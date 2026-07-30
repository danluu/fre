use fre_kernel_ir::{
    AbiVersion, AggregateOperation, AggregateOutput, AnchorFlags, BlockOp, ByteClass, Count,
    DataBlob, ExactAggregateProgram, MAX_EXACT_AGGREGATE_LITERAL_BYTES, Operation, OutputKind,
    SelectedEnd, SemanticsVersion, SpanSum, ValidatedProgram,
};
use memchr::arch::all::packedpair::Pair;

use crate::{
    ArithmeticSite, AuditedNativeImage, BackendVersion, BranchKind, CodeLabel, Condition,
    ConfirmationKind, CpuFeatures, DataSymbol, EmitError, ImageLayout, ImageStats, LabelKind,
    NativeAggregateImage, NativeImage, Relocation, RelocationKind, RelocationTarget, ResourceKind,
    SelectedEndRegisterBackendV2, TargetSpec, UnsupportedReason,
    image::{
        AggregateManifest, DataSymbolKind, SearchCallAbi, SearchManifest, SearchShape, aot_size,
    },
    selected_end_v2::{
        AuditedSelectedEndRegisterImageV2, SELECTED_END_REGISTER_ARTIFACT_IDENTITY_DOMAIN_V2,
    },
};

const CODE_ALIGNMENT: usize = 16;
const DATA_ALIGNMENT: usize = 16;
const EXACT_CODE_RESERVE: usize = 1_024;
const CLASS_CODE_RESERVE: usize = 1_600;
const EXACT_LABEL_RESERVE: usize = 32;
const CLASS_LABEL_RESERVE: usize = 48;
const EXACT_RELOCATION_RESERVE: usize = 64;
const V7_EXACT_CODE_RESERVE: usize = 1_536;
const V7_EXACT_LABEL_RESERVE: usize = 48;
const V7_EXACT_RELOCATION_RESERVE: usize = 96;
const SVE16_EXACT_CODE_RESERVE: usize = 1_536;
const SVE16_EXACT_LABEL_RESERVE: usize = 48;
const SVE16_EXACT_RELOCATION_RESERVE: usize = 96;
const V8_EXACT_CODE_RESERVE: usize = 2_304;
const V8_EXACT_LABEL_RESERVE: usize = 64;
const V8_EXACT_RELOCATION_RESERVE: usize = 128;
const CLASS_RELOCATION_RESERVE: usize = 96;
const AGGREGATE_CODE_RESERVE: usize = 1_600;
const AGGREGATE_LABEL_RESERVE: usize = 48;
const AGGREGATE_RELOCATION_RESERVE: usize = 96;
const SEARCH_CANDIDATE_POLICY_NONE: u16 = 0;
const SEARCH_CANDIDATE_POLICY_V1: u16 = 1;
const SEARCH_CANDIDATE_POLICY_V2: u16 = 2;
const SEARCH_CANDIDATE_POLICY_V3: u16 = 3;
const SEARCH_CANDIDATE_POLICY_V4: u16 = 4;
const SEARCH_CANDIDATE_POLICY_SVE16_V1: u16 = 5;
const SEARCH_CANDIDATE_POLICY_SVE2_16_V1: u16 = 6;
const SEARCH_CANDIDATE_POLICY_SVE2_FIXED16_V2: u16 = 8;
const SEARCH_CANDIDATE_POLICY_V5: u16 = 9;
const SEARCH_CANDIDATE_POLICY_V6: u16 = 10;
const SEARCH_CANDIDATE_POLICY_V7: u16 = 11;
const SEARCH_CANDIDATE_BLOCK_WIDTH: u16 = 16;
const SEARCH_CANDIDATE_OFFSET_NONE: u16 = u16::MAX;
const SVE2_CLASS_TABLE_DATA_ID: u32 = 2;
const SVE2_CLASS_TABLE_BYTES: usize = 16;

/// Largest confirmation payload admitted when a search can confirm at more
/// than one candidate position.
///
/// This converts the naive confirmation factor into an implementation
/// constant. Longer unanchored patterns require a proved-linear Two-Way or
/// automaton fallback in a higher-level planner. Single-candidate start/end
/// anchored literals and start-anchored class runs do not need this cap.
pub const MAX_REPEATED_CONFIRM_BYTES: usize = 32;

/// Explicit implementation policy for one search image.
///
/// The default is Advanced SIMD Search V8. Qualification remains a separate
/// facade concern: selecting a backend here stamps its exact machine-code
/// contract but does not authorize production execution.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SearchBackendPolicy {
    /// Legacy Advanced SIMD Search V7.
    AsimdV7,
    /// Advanced SIMD Search V8, including its authenticated AOT contract.
    #[default]
    AsimdV8,
    /// Search V9 candidate: V8 plus an exact first-candidate fast path.
    AsimdV9,
    /// Search V10 candidate: V9 plus a terminal-aware fifth ASIMD filter.
    AsimdV10,
    /// Search V11 candidate: V9 plus five ASIMD columns that reserve both
    /// literal endpoints before frequency-ranked columns.
    AsimdV11,
    /// SVE screening with exactly sixteen active byte lanes.
    Sve16,
    /// SVE2 `MATCH` screening with exactly sixteen active byte lanes,
    /// including canonical ASCII classes with at most sixteen members.
    Sve2Fixed16,
    /// Candidate V8 screening with fixed-lane SVE confirmation.
    Sve16V6,
    /// Candidate paired-ASIMD screening with fixed-lane SVE2 recovery.
    Sve2Fixed16V2,
}

impl SearchBackendPolicy {
    /// Current source-final policy measured by the V8 qualification bridge.
    pub const CURRENT: Self = Self::AsimdV8;

    /// Authenticated backend version selected by this policy.
    #[must_use]
    pub const fn backend_version(self) -> BackendVersion {
        match self {
            Self::AsimdV7 => BackendVersion::SEARCH_V7,
            Self::AsimdV8 => BackendVersion::SEARCH_V8,
            Self::AsimdV9 => BackendVersion::SEARCH_V9,
            Self::AsimdV10 => BackendVersion::SEARCH_V10,
            Self::AsimdV11 => BackendVersion::SEARCH_V11,
            Self::Sve16 => BackendVersion::SEARCH_SVE16_V1,
            Self::Sve2Fixed16 => BackendVersion::SEARCH_SVE2_16_V1,
            Self::Sve16V6 => BackendVersion::SEARCH_SVE16_V6,
            Self::Sve2Fixed16V2 => BackendVersion::SEARCH_SVE2_FIXED16_V2,
        }
    }
}

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

/// Explicit resource limits for one bounded emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmitLimits {
    pub max_code_bytes: u64,
    pub max_data_bytes: u64,
    pub max_relocations: u64,
    pub max_labels: u64,
    pub max_emission_work: u64,
    pub max_scratch_bytes: u64,
}

impl Default for EmitLimits {
    fn default() -> Self {
        Self {
            max_code_bytes: 64 << 10,
            max_data_bytes: 1 << 20,
            max_relocations: 256,
            max_labels: 128,
            max_emission_work: 4 << 20,
            max_scratch_bytes: 64 << 10,
        }
    }
}

/// Emit a pattern-specialized `AArch64` image from already validated Kernel IR.
///
/// The result is position independent only when code and rodata retain the
/// exact relative placement in [`ImageLayout`]. No executable mapping or raw
/// function pointer is created here.
pub fn emit<O: Operation>(
    program: &ValidatedProgram<O>,
    limits: EmitLimits,
) -> Result<NativeImage, EmitError> {
    emit_with_backend(program, SearchBackendPolicy::CURRENT, limits)
}

/// Emit one search image under an explicit backend policy.
///
/// The policy-selected backend version, feature envelope, machine code, and
/// AOT magic all participate in the resulting artifact identity.
pub fn emit_with_backend<O: Operation>(
    program: &ValidatedProgram<O>,
    backend: SearchBackendPolicy,
    limits: EmitLimits,
) -> Result<NativeImage, EmitError> {
    emit_search_version(program, limits, backend.backend_version())
}

/// Emit and retain the successful final whole-image audit as immutable
/// typestate.
///
/// This is the trusted counterpart to [`emit_with_backend`] for a publisher
/// that accepts [`AuditedNativeImage`]. Converting the result back to a plain
/// image deliberately discards that publication capability.
pub fn emit_audited_with_backend<O: Operation>(
    program: &ValidatedProgram<O>,
    backend: SearchBackendPolicy,
    limits: EmitLimits,
) -> Result<AuditedNativeImage, EmitError> {
    emit_search_version_audited(program, limits, backend.backend_version())
}

/// Emit a sealed non-empty exact-literal `SelectedEnd` image for the
/// windowed register-return ABI2.
///
/// This is a distinct publication type. Search-v1 publishers accept neither
/// its wrapper nor its ABI-tagged underlying image.
pub fn emit_selected_end_register_v2(
    program: &ValidatedProgram<SelectedEnd>,
    backend: SelectedEndRegisterBackendV2,
    limits: EmitLimits,
) -> Result<AuditedSelectedEndRegisterImageV2, EmitError> {
    let image = emit_search_image(
        program,
        limits,
        backend.backend_version(),
        SearchCallAbi::SelectedEndRegisterV2,
    )?;
    finalize_selected_end_register_image_v2(image, limits)
}

/// Emit the opt-in SVE search backend with exactly sixteen active byte lanes.
///
/// The physical architectural vector length may be larger; emitted code uses
/// `PTRUE ..., VL16` and never changes thread vector-length state. This
/// backend admits non-empty unanchored exact literals and the proved
/// non-start-anchored singleton-class suffix family. Other shapes fail
/// explicitly. [`emit`] remains the deterministic Search V8 default.
pub fn emit_sve16<O: Operation>(
    program: &ValidatedProgram<O>,
    limits: EmitLimits,
) -> Result<NativeImage, EmitError> {
    emit_with_backend(program, SearchBackendPolicy::Sve16, limits)
}

/// Emit the opt-in SVE2 backend with exactly sixteen active byte lanes.
///
/// Candidate comparison uses the SVE2-only `MATCH` instruction, so the image
/// carries an explicit SVE2 feature requirement. In addition to the shapes
/// admitted by [`emit_sve16`], this admits non-start-anchored class suffixes
/// whose canonical ASCII class contains two through sixteen members.
pub fn emit_sve2_16<O: Operation>(
    program: &ValidatedProgram<O>,
    limits: EmitLimits,
) -> Result<NativeImage, EmitError> {
    emit_with_backend(program, SearchBackendPolicy::Sve2Fixed16, limits)
}

/// Emit the candidate V8-screening backend with fixed-lane SVE confirmation.
///
/// This policy admits only unanchored non-empty exact literals of at least
/// sixteen bytes. It uses `PTRUE ..., VL16` and is not selected by [`emit`].
pub fn emit_sve16_v6<O: Operation>(
    program: &ValidatedProgram<O>,
    limits: EmitLimits,
) -> Result<NativeImage, EmitError> {
    emit_with_backend(program, SearchBackendPolicy::Sve16V6, limits)
}

/// Emit the candidate paired-ASIMD/fixed-lane-SVE2 exact-16 backend.
///
/// This is an explicit candidate policy and never changes [`emit`] or
/// [`SearchBackendPolicy::CURRENT`]. It admits only unanchored exact literals
/// of exactly sixteen bytes and stamps the unique search tag 21 wire contract.
pub fn emit_sve2_fixed16_v2<O: Operation>(
    program: &ValidatedProgram<O>,
    limits: EmitLimits,
) -> Result<NativeImage, EmitError> {
    emit_with_backend(program, SearchBackendPolicy::Sve2Fixed16V2, limits)
}

#[cfg(test)]
pub(crate) fn emit_search_version_for_test<O: Operation>(
    program: &ValidatedProgram<O>,
    limits: EmitLimits,
    backend_version: BackendVersion,
) -> Result<NativeImage, EmitError> {
    emit_search_version(program, limits, backend_version)
}

fn emit_search_version<O: Operation>(
    program: &ValidatedProgram<O>,
    limits: EmitLimits,
    backend_version: BackendVersion,
) -> Result<NativeImage, EmitError> {
    emit_search_version_audited(program, limits, backend_version)
        .map(AuditedNativeImage::into_image)
}

#[allow(
    clippy::too_many_lines,
    reason = "the versioned search construction keeps one transaction from validation through authenticated image finalization"
)]
fn emit_search_version_audited<O: Operation>(
    program: &ValidatedProgram<O>,
    limits: EmitLimits,
    backend_version: BackendVersion,
) -> Result<AuditedNativeImage, EmitError> {
    let image = emit_search_image(program, limits, backend_version, SearchCallAbi::OutSlotV1)?;
    finalize_image(image, limits)
}

#[allow(
    clippy::too_many_lines,
    reason = "the versioned search construction keeps one transaction from validation through immutable image construction"
)]
fn emit_search_image<O: Operation>(
    program: &ValidatedProgram<O>,
    limits: EmitLimits,
    backend_version: BackendVersion,
    search_call_abi: SearchCallAbi,
) -> Result<NativeImage, EmitError> {
    if !matches!(
        backend_version,
        BackendVersion::SEARCH_V1
            | BackendVersion::SEARCH_V2
            | BackendVersion::SEARCH_V3
            | BackendVersion::SEARCH_V4
            | BackendVersion::SEARCH_V5
            | BackendVersion::SEARCH_V6
            | BackendVersion::SEARCH_V7
            | BackendVersion::SEARCH_V8
            | BackendVersion::SEARCH_V9
            | BackendVersion::SEARCH_V10
            | BackendVersion::SEARCH_V11
            | BackendVersion::SEARCH_SVE16_V1
            | BackendVersion::SEARCH_SVE2_16_V1
            | BackendVersion::SEARCH_SVE16_V6
            | BackendVersion::SEARCH_SVE2_FIXED16_V2
    ) {
        return Err(EmitError::InternalInvariant);
    }
    if program.raw().abi != AbiVersion::CURRENT {
        return Err(EmitError::Unsupported {
            reason: UnsupportedReason::AbiVersion,
        });
    }
    if program.raw().semantics != SemanticsVersion::CURRENT {
        return Err(EmitError::Unsupported {
            reason: UnsupportedReason::SemanticsVersion,
        });
    }
    if program.raw().output != O::KIND {
        return Err(EmitError::Unsupported {
            reason: UnsupportedReason::OutputContract,
        });
    }
    if search_call_abi == SearchCallAbi::SelectedEndRegisterV2
        && program.raw().output != OutputKind::SelectedEnd
    {
        return Err(EmitError::Unsupported {
            reason: UnsupportedReason::OutputContract,
        });
    }
    let plan = Plan::recognize(program)?;
    if search_call_abi == SearchCallAbi::SelectedEndRegisterV2
        && !matches!(plan, Plan::Exact { literal, .. } if !literal.is_empty())
    {
        return Err(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        });
    }
    if matches!(
        backend_version,
        BackendVersion::SEARCH_SVE16_V1 | BackendVersion::SEARCH_SVE2_16_V1
    ) && !plan.is_fixed16_policy_shape(backend_version)
    {
        return Err(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        });
    }
    if backend_version == BackendVersion::SEARCH_SVE16_V6 && !plan.is_sve16_v6_policy_shape() {
        return Err(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        });
    }
    if backend_version == BackendVersion::SEARCH_SVE2_FIXED16_V2
        && !plan.is_sve2_fixed16_v2_policy_shape()
    {
        return Err(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        });
    }
    if matches!(
        backend_version,
        BackendVersion::SEARCH_V9 | BackendVersion::SEARCH_V10 | BackendVersion::SEARCH_V11
    ) && !plan.is_v9_policy_shape()
    {
        return Err(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        });
    }
    let sve_confirmation_features = if plan.uses_asimd_confirmation() {
        CpuFeatures::ASIMD
    } else {
        CpuFeatures::NONE
    };
    let mut meter = WorkMeter::new(limits.max_emission_work);
    let v7_policy_scan_admission = plan.admit_v7_policy_scans(backend_version, &mut meter)?;
    let search_manifest = plan.search_manifest(
        program.raw().output,
        program.cache_identity(),
        backend_version,
        v7_policy_scan_admission,
    )?;
    let capacities = plan.capacities(backend_version);
    let scratch = scratch_bytes(capacities)?;
    enforce_u64(
        ResourceKind::ScratchBytes,
        scratch,
        limits.max_scratch_bytes,
    )?;
    let sve2_class_table = match plan {
        Plan::ClassSuffix { class, .. } if backend_version == BackendVersion::SEARCH_SVE2_16_V1 => {
            sve2_fixed16_ascii_class_table(class)
        }
        _ => None,
    };
    let data = build_rodata(
        program.raw().data.as_slice(),
        sve2_class_table,
        limits.max_data_bytes,
        &mut meter,
    )?;
    let mut assembler = Assembler::new(limits, capacities, meter)?;
    let entry = assembler.new_label(LabelKind::Entry)?;
    let found = assembler.new_label(LabelKind::ReturnFound)?;
    let none = assembler.new_label(LabelKind::ReturnNone)?;
    assembler.bind(entry)?;
    emit_preamble(&mut assembler, none)?;
    emit_plan(
        &mut assembler,
        &data,
        plan,
        search_manifest,
        backend_version,
        found,
        none,
    )?;
    match search_call_abi {
        SearchCallAbi::OutSlotV1 => {
            emit_returns(&mut assembler, program.raw().output, found, none)?;
        }
        SearchCallAbi::SelectedEndRegisterV2 => {
            emit_selected_end_register_returns_v2(&mut assembler, found, none)?;
        }
    }
    let finalized = assembler.finalize(data.bytes.len())?;
    let code_len = finalized.code.len();
    let rodata_offset = align_up(code_len, DATA_ALIGNMENT, ArithmeticSite::ImageLayout)?;
    let total =
        rodata_offset
            .checked_add(data.bytes.len())
            .ok_or(EmitError::ArithmeticOverflow {
                site: ArithmeticSite::ImageLayout,
            })?;
    let layout = ImageLayout {
        code_alignment: u32::try_from(CODE_ALIGNMENT).expect("small constant"),
        rodata_alignment: u32::try_from(DATA_ALIGNMENT).expect("small constant"),
        rodata_from_code_start: to_u32(rodata_offset, ArithmeticSite::ImageLayout)?,
        total_mapped_bytes: to_u32(total, ArithmeticSite::ImageLayout)?,
    };
    let stats = ImageStats {
        code_bytes: to_u32(code_len, ArithmeticSite::CodeOffset)?,
        data_bytes: to_u32(data.bytes.len(), ArithmeticSite::DataOffset)?,
        relocations: to_u32(finalized.relocations.len(), ArithmeticSite::CodeOffset)?,
        labels: to_u32(finalized.labels.len(), ArithmeticSite::CodeOffset)?,
        emission_work: finalized.work,
        scratch_bytes: scratch,
        vector_instructions: finalized.vector_instructions,
    };
    let image = NativeImage {
        backend_version,
        target: TargetSpec {
            features: match backend_version {
                BackendVersion::SEARCH_SVE16_V1 => {
                    CpuFeatures::SVE.union(sve_confirmation_features)
                }
                BackendVersion::SEARCH_SVE2_16_V1 => CpuFeatures::SVE
                    .union(CpuFeatures::SVE2)
                    .union(sve_confirmation_features),
                BackendVersion::SEARCH_SVE16_V6 => CpuFeatures::SVE.union(CpuFeatures::ASIMD),
                BackendVersion::SEARCH_SVE2_FIXED16_V2 => CpuFeatures::ASIMD
                    .union(CpuFeatures::SVE)
                    .union(CpuFeatures::SVE2),
                _ if finalized.vector_instructions == 0 => CpuFeatures::NONE,
                _ => CpuFeatures::ASIMD,
            },
            ..TargetSpec::AARCH64_AAPCS64
        },
        output: program.raw().output,
        source_identity: program.cache_identity(),
        layout,
        code: finalized.code,
        rodata: data.bytes,
        labels: finalized.labels,
        symbols: data.symbols,
        relocations: finalized.relocations,
        stats,
        artifact_identity: crate::ArtifactIdentity::ZERO,
        search_call_abi,
        search: matches!(
            backend_version,
            BackendVersion::SEARCH_V3
                | BackendVersion::SEARCH_V4
                | BackendVersion::SEARCH_V5
                | BackendVersion::SEARCH_V6
                | BackendVersion::SEARCH_V7
                | BackendVersion::SEARCH_V8
                | BackendVersion::SEARCH_V9
                | BackendVersion::SEARCH_V10
                | BackendVersion::SEARCH_V11
                | BackendVersion::SEARCH_SVE16_V1
                | BackendVersion::SEARCH_SVE2_16_V1
                | BackendVersion::SEARCH_SVE16_V6
                | BackendVersion::SEARCH_SVE2_FIXED16_V2
        )
        .then_some(search_manifest),
        aggregate: None,
    };
    Ok(image)
}

/// Emit one whole-haystack non-overlapping exact-literal aggregate entry.
///
/// This uses the distinct three-argument aggregate ABI and never widens or
/// changes the existing five-argument search ABI. The literal-width cap is a
/// semantic complexity bound: every admitted confirmation has constant work.
pub fn emit_exact_aggregate<A: AggregateOperation>(
    program: &ExactAggregateProgram<A>,
    limits: EmitLimits,
) -> Result<NativeAggregateImage, EmitError> {
    emit_exact_aggregate_backend(program, limits, AggregateBackend::Current)
}

/// Emit the experimental fixed-16-lane SVE2 backend for a one-byte Count.
///
/// This is an explicit experiment: [`emit_exact_aggregate`] and
/// [`BackendVersion::AGGREGATE_CURRENT`] remain unchanged. The generated loop
/// uses `MATCH`, an SVE2-only instruction, and the image requires OS-usable
/// SVE and SVE2 at publication time.
pub fn emit_exact_aggregate_sve2_fixed16_count_experimental(
    program: &ExactAggregateProgram<Count>,
    limits: EmitLimits,
) -> Result<NativeAggregateImage, EmitError> {
    emit_exact_aggregate_backend(
        program,
        limits,
        AggregateBackend::Sve2Fixed16CountExperimental,
    )
}

/// Emit the experimental fixed-16-lane SVE2 backend for a two-byte Count.
///
/// The vector loop forms an exact predicate for adjacent literal-byte pairs.
/// It counts that predicate directly when the two bytes differ, because such
/// matches cannot overlap. Equal-byte literals use the predicate as a screen
/// and recover matches in ascending order to preserve non-overlap semantics.
/// This remains an explicit experiment and does not change
/// [`emit_exact_aggregate`] or [`BackendVersion::AGGREGATE_CURRENT`].
pub fn emit_exact_aggregate_sve2_fixed16_pair_count_experimental(
    program: &ExactAggregateProgram<Count>,
    limits: EmitLimits,
) -> Result<NativeAggregateImage, EmitError> {
    emit_exact_aggregate_backend(
        program,
        limits,
        AggregateBackend::Sve2Fixed16PairCountExperimental,
    )
}

/// Emit the experimental fixed-16-lane SVE2 backend for unequal-pair `SpanSum`.
///
/// Unequal adjacent bytes cannot overlap, so the backend reuses the exact
/// fixed-16 pair-count loop and checks a final multiplication by the literal
/// width. Equal-byte pairs are deliberately outside this direct-count shape.
/// This remains explicit and does not change [`emit_exact_aggregate`] or
/// [`BackendVersion::AGGREGATE_CURRENT`].
pub fn emit_exact_aggregate_sve2_fixed16_pair_span_sum_experimental(
    program: &ExactAggregateProgram<SpanSum>,
    limits: EmitLimits,
) -> Result<NativeAggregateImage, EmitError> {
    if matches!(program.literal(), [left, right] if left == right) {
        return Err(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        });
    }
    emit_exact_aggregate_backend(
        program,
        limits,
        AggregateBackend::Sve2Fixed16PairSpanSumExperimental,
    )
}

/// Emit the experimental fixed-16-lane SVE2 backend for one-byte `SpanSum`.
///
/// Every admitted match has width one, so predicate population is exactly the
/// matched-byte sum. The backend remains explicit and separately versioned.
pub fn emit_exact_aggregate_sve2_fixed16_span_sum_experimental(
    program: &ExactAggregateProgram<SpanSum>,
    limits: EmitLimits,
) -> Result<NativeAggregateImage, EmitError> {
    emit_exact_aggregate_backend(
        program,
        limits,
        AggregateBackend::Sve2Fixed16SpanSumExperimental,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AggregateBackend {
    Current,
    Sve2Fixed16CountExperimental,
    Sve2Fixed16PairCountExperimental,
    Sve2Fixed16PairSpanSumExperimental,
    Sve2Fixed16SpanSumExperimental,
}

impl AggregateBackend {
    const fn version(self) -> BackendVersion {
        match self {
            Self::Current => BackendVersion::AGGREGATE_CURRENT,
            Self::Sve2Fixed16CountExperimental => {
                BackendVersion::AGGREGATE_SVE2_FIXED16_COUNT_EXPERIMENTAL_V1
            }
            Self::Sve2Fixed16PairCountExperimental => {
                BackendVersion::AGGREGATE_SVE2_FIXED16_PAIR_COUNT_EXPERIMENTAL_V1
            }
            Self::Sve2Fixed16PairSpanSumExperimental => {
                BackendVersion::AGGREGATE_SVE2_FIXED16_PAIR_SPAN_SUM_EXPERIMENTAL_V1
            }
            Self::Sve2Fixed16SpanSumExperimental => {
                BackendVersion::AGGREGATE_SVE2_FIXED16_SPAN_SUM_EXPERIMENTAL_V1
            }
        }
    }

    const fn features(self, vector_instructions: u32) -> CpuFeatures {
        match self {
            Self::Current if vector_instructions == 0 => CpuFeatures::NONE,
            Self::Current => CpuFeatures::ASIMD,
            Self::Sve2Fixed16CountExperimental
            | Self::Sve2Fixed16PairCountExperimental
            | Self::Sve2Fixed16PairSpanSumExperimental
            | Self::Sve2Fixed16SpanSumExperimental => CpuFeatures::SVE.union(CpuFeatures::SVE2),
        }
    }
}

fn emit_exact_aggregate_backend<A: AggregateOperation>(
    program: &ExactAggregateProgram<A>,
    limits: EmitLimits,
    backend: AggregateBackend,
) -> Result<NativeAggregateImage, EmitError> {
    let literal = program.literal();
    if literal.len() > MAX_EXACT_AGGREGATE_LITERAL_BYTES {
        return Err(EmitError::ConfirmationLengthLimit {
            kind: ConfirmationKind::ExactLiteral,
            limit: MAX_EXACT_AGGREGATE_LITERAL_BYTES,
            required: literal.len(),
        });
    }
    match backend {
        AggregateBackend::Current => {}
        AggregateBackend::Sve2Fixed16CountExperimental
            if literal.len() == 1 && A::OUTPUT == AggregateOutput::Count => {}
        AggregateBackend::Sve2Fixed16PairCountExperimental
            if literal.len() == 2 && A::OUTPUT == AggregateOutput::Count => {}
        AggregateBackend::Sve2Fixed16PairSpanSumExperimental
            if literal.len() == 2
                && literal[0] != literal[1]
                && A::OUTPUT == AggregateOutput::SpanSum => {}
        AggregateBackend::Sve2Fixed16SpanSumExperimental
            if literal.len() == 1 && A::OUTPUT == AggregateOutput::SpanSum => {}
        _ => {
            return Err(EmitError::Unsupported {
                reason: UnsupportedReason::KernelShape,
            });
        }
    }
    let capacities = Capacities {
        code: AGGREGATE_CODE_RESERVE,
        labels: AGGREGATE_LABEL_RESERVE,
        relocations: AGGREGATE_RELOCATION_RESERVE,
    };
    let scratch = scratch_bytes(capacities)?;
    enforce_u64(
        ResourceKind::ScratchBytes,
        scratch,
        limits.max_scratch_bytes,
    )?;
    let mut meter = WorkMeter::new(limits.max_emission_work);
    let data = build_literal_rodata(literal, limits.max_data_bytes, &mut meter)?;
    let mut assembler = Assembler::new(limits, capacities, meter)?;
    let entry = assembler.new_label(LabelKind::Entry)?;
    let done = assembler.new_label(LabelKind::ReturnFound)?;
    let overflow = if literal.is_empty() && A::OUTPUT == AggregateOutput::SpanSum {
        done
    } else {
        assembler.new_label(LabelKind::ReturnNone)?
    };
    assembler.bind(entry)?;
    emit_aggregate_exact(
        &mut assembler,
        literal,
        A::OUTPUT,
        backend,
        done,
        overflow,
        &data,
    )?;
    emit_aggregate_returns(&mut assembler, done, overflow, backend)?;
    let finalized = assembler.finalize(data.bytes.len())?;
    let image = build_aggregate_image(program, finalized, data, scratch, backend)?;
    finalize_aggregate_image(image, limits)
}

fn build_aggregate_image<A: AggregateOperation>(
    program: &ExactAggregateProgram<A>,
    finalized: Finalized,
    data: Rodata,
    scratch: u64,
    backend: AggregateBackend,
) -> Result<NativeImage, EmitError> {
    let code_len = finalized.code.len();
    let rodata_offset = align_up(code_len, DATA_ALIGNMENT, ArithmeticSite::ImageLayout)?;
    let total =
        rodata_offset
            .checked_add(data.bytes.len())
            .ok_or(EmitError::ArithmeticOverflow {
                site: ArithmeticSite::ImageLayout,
            })?;
    let layout = ImageLayout {
        code_alignment: u32::try_from(CODE_ALIGNMENT).expect("small constant"),
        rodata_alignment: u32::try_from(DATA_ALIGNMENT).expect("small constant"),
        rodata_from_code_start: to_u32(rodata_offset, ArithmeticSite::ImageLayout)?,
        total_mapped_bytes: to_u32(total, ArithmeticSite::ImageLayout)?,
    };
    let stats = ImageStats {
        code_bytes: to_u32(code_len, ArithmeticSite::CodeOffset)?,
        data_bytes: to_u32(data.bytes.len(), ArithmeticSite::DataOffset)?,
        relocations: to_u32(finalized.relocations.len(), ArithmeticSite::CodeOffset)?,
        labels: to_u32(finalized.labels.len(), ArithmeticSite::CodeOffset)?,
        emission_work: finalized.work,
        scratch_bytes: scratch,
        vector_instructions: finalized.vector_instructions,
    };
    Ok(NativeImage {
        backend_version: backend.version(),
        target: TargetSpec {
            features: backend.features(finalized.vector_instructions),
            ..TargetSpec::AARCH64_AAPCS64
        },
        // This field belongs to the search-image wire layout and is ignored
        // for the separately tagged aggregate container. Keeping it valid
        // permits shared section/layout code without conflating public types.
        output: OutputKind::Span,
        source_identity: program.search_cache_identity(),
        layout,
        code: finalized.code,
        rodata: data.bytes,
        labels: finalized.labels,
        symbols: data.symbols,
        relocations: finalized.relocations,
        stats,
        artifact_identity: crate::ArtifactIdentity::ZERO,
        search_call_abi: SearchCallAbi::OutSlotV1,
        search: None,
        aggregate: Some(AggregateManifest {
            output: A::OUTPUT,
            source_identity: program.cache_identity(),
            literal_bytes: to_u32(program.literal().len(), ArithmeticSite::DataOffset)?,
        }),
    })
}

fn emit_aggregate_exact(
    assembler: &mut Assembler,
    literal: &[u8],
    output: AggregateOutput,
    backend: AggregateBackend,
    done: Label,
    overflow: Label,
    data: &Rodata,
) -> Result<(), EmitError> {
    assembler.mov_imm64(X13, 0)?;
    if literal.is_empty() {
        if output == AggregateOutput::SpanSum {
            return assembler.branch(done);
        }
        // A safe Rust slice cannot have u64::MAX bytes on this target, but the
        // native entry still fails closed if invoked outside that contract.
        assembler.mov_imm64(X10, u64::MAX)?;
        assembler.cmp_reg64(X1, X10)?;
        assembler.branch_cond(Condition::Equal, overflow)?;
        assembler.add_imm(X13, X1, 1)?;
        return assembler.branch(done);
    }

    assembler.adr(X8, data.symbol_offset(0)?)?;
    assembler.mov_imm64(
        X12,
        u64::try_from(literal.len()).map_err(|_| EmitError::ArithmeticOverflow {
            site: ArithmeticSite::DataOffset,
        })?,
    )?;
    if literal.len() == 1 {
        match backend {
            AggregateBackend::Current => emit_aggregate_single_byte(assembler, done, overflow),
            AggregateBackend::Sve2Fixed16CountExperimental
            | AggregateBackend::Sve2Fixed16SpanSumExperimental => {
                emit_aggregate_single_byte_sve2_fixed16_count(assembler, done, overflow)
            }
            AggregateBackend::Sve2Fixed16PairCountExperimental
            | AggregateBackend::Sve2Fixed16PairSpanSumExperimental => {
                Err(EmitError::InternalInvariant)
            }
        }
    } else if literal.len() == 2
        && matches!(
            backend,
            AggregateBackend::Sve2Fixed16PairCountExperimental
                | AggregateBackend::Sve2Fixed16PairSpanSumExperimental
        )
    {
        if backend == AggregateBackend::Sve2Fixed16PairSpanSumExperimental {
            emit_aggregate_non_self_overlapping_pair_sve2_fixed16_count(assembler, done, overflow)
        } else {
            emit_aggregate_two_byte_sve2_fixed16_count(assembler, literal, done, overflow)
        }
    } else {
        if backend != AggregateBackend::Current {
            return Err(EmitError::InternalInvariant);
        }
        emit_aggregate_multi_byte(assembler, literal, output, done, overflow)
    }
}

fn emit_aggregate_two_byte_sve2_fixed16_count(
    assembler: &mut Assembler,
    literal: &[u8],
    done: Label,
    overflow: Label,
) -> Result<(), EmitError> {
    if literal.len() != 2 {
        return Err(EmitError::InternalInvariant);
    }
    if literal[0] == literal[1] {
        emit_aggregate_equal_pair_sve2_fixed16_count(assembler, done, overflow)
    } else {
        emit_aggregate_non_self_overlapping_pair_sve2_fixed16_count(assembler, done, overflow)
    }
}

fn emit_aggregate_pair_sve2_fixed16_setup(
    assembler: &mut Assembler,
    done: Label,
) -> Result<(), EmitError> {
    assembler.cmp_reg64(X1, X12)?;
    assembler.branch_cond(Condition::CarryClear, done)?;
    // X6 is the final valid start. A sixteen-start vector iteration is
    // admitted only when X6 - X5 >= 15, which proves that the second load's
    // final active byte (start + 16) is at most haystack_len - 1.
    assembler.sub_reg(X6, X1, X12)?;
    assembler.load_byte(X11, X8, 0)?;
    assembler.sve_ptrue_bytes_vl16(0)?;
    assembler.sve_duplicate_byte(1, X11)?;
    assembler.load_byte(X11, X8, 1)?;
    assembler.sve_duplicate_byte(3, X11)?;
    assembler.mov_imm64(X5, 0)
}

fn emit_aggregate_pair_sve2_fixed16_predicate(assembler: &mut Assembler) -> Result<(), EmitError> {
    assembler.add_reg(X15, X0, X5)?;
    assembler.sve_load_bytes(0, 0, X15)?;
    assembler.add_imm(X10, X15, 1)?;
    assembler.sve_load_bytes(2, 0, X10)?;
    assembler.sve2_match_bytes(1, 0, 0, 1)?;
    assembler.sve2_match_bytes(2, 0, 2, 3)?;
    assembler.sve_and_predicate_bytes(1, 0, 1, 2)
}

fn emit_aggregate_pair_scalar_candidate(
    assembler: &mut Assembler,
    candidate_miss: Label,
    overflow: Label,
) -> Result<(), EmitError> {
    assembler.load_byte_reg(X10, X0, X5)?;
    assembler.load_byte(X11, X8, 0)?;
    assembler.cmp_reg32(X10, X11)?;
    assembler.branch_cond(Condition::NotEqual, candidate_miss)?;
    assembler.add_reg(X15, X0, X5)?;
    assembler.load_byte(X10, X15, 1)?;
    assembler.load_byte(X11, X8, 1)?;
    assembler.cmp_reg32(X10, X11)?;
    assembler.branch_cond(Condition::NotEqual, candidate_miss)?;
    emit_aggregate_add_immediate(assembler, 1, overflow)
}

fn emit_aggregate_non_self_overlapping_pair_sve2_fixed16_count(
    assembler: &mut Assembler,
    done: Label,
    overflow: Label,
) -> Result<(), EmitError> {
    let vector = assembler.new_label(LabelKind::Loop)?;
    let tail = assembler.new_label(LabelKind::SlowPath)?;
    let tail_miss = assembler.new_label(LabelKind::Internal)?;
    emit_aggregate_pair_sve2_fixed16_setup(assembler, done)?;

    assembler.bind(vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, done)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, tail)?;
    emit_aggregate_pair_sve2_fixed16_predicate(assembler)?;
    assembler.sve_count_predicate_bytes(X10, 0, 1)?;
    emit_aggregate_add_register(assembler, X10, overflow)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.branch(vector)?;

    assembler.bind(tail)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, done)?;
    emit_aggregate_pair_scalar_candidate(assembler, tail_miss, overflow)?;
    assembler.add_imm(X5, X5, 2)?;
    assembler.branch(tail)?;
    assembler.bind(tail_miss)?;
    assembler.add_imm(X5, X5, 1)?;
    assembler.branch(tail)
}

fn emit_aggregate_equal_pair_sve2_fixed16_count(
    assembler: &mut Assembler,
    done: Label,
    overflow: Label,
) -> Result<(), EmitError> {
    let vector = assembler.new_label(LabelKind::Loop)?;
    let scalar_block = assembler.new_label(LabelKind::SlowPath)?;
    let scalar_tail = assembler.new_label(LabelKind::SlowPath)?;
    let scalar_scan = assembler.new_label(LabelKind::Loop)?;
    let candidate_miss = assembler.new_label(LabelKind::Internal)?;
    let advance_block = assembler.new_label(LabelKind::Internal)?;
    emit_aggregate_pair_sve2_fixed16_setup(assembler, done)?;

    assembler.bind(vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, done)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, scalar_tail)?;
    emit_aggregate_pair_sve2_fixed16_predicate(assembler)?;
    assembler.sve_test_predicate_bytes(0, 1)?;
    assembler.branch_cond(Condition::NotEqual, scalar_block)?;
    assembler.bind(advance_block)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.branch(vector)?;

    assembler.bind(scalar_block)?;
    assembler.add_imm(X7, X5, 15)?;
    assembler.branch(scalar_scan)?;
    assembler.bind(scalar_tail)?;
    assembler.mov_reg(X7, X6)?;
    assembler.bind(scalar_scan)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::Higher, vector)?;
    emit_aggregate_pair_scalar_candidate(assembler, candidate_miss, overflow)?;
    assembler.add_imm(X5, X5, 2)?;
    assembler.branch(scalar_scan)?;
    assembler.bind(candidate_miss)?;
    assembler.add_imm(X5, X5, 1)?;
    assembler.branch(scalar_scan)
}

fn emit_aggregate_single_byte(
    assembler: &mut Assembler,
    done: Label,
    overflow: Label,
) -> Result<(), EmitError> {
    let vector = assembler.new_label(LabelKind::Loop)?;
    let tail = assembler.new_label(LabelKind::SlowPath)?;
    let tail_miss = assembler.new_label(LabelKind::Internal)?;
    assembler.load_byte(X11, X8, 0)?;
    assembler.dup_byte16(1, X11)?;
    assembler.mov_imm64(X5, 0)?;
    assembler.bind(vector)?;
    assembler.cmp_reg64(X5, X1)?;
    assembler.branch_cond(Condition::CarrySet, done)?;
    assembler.sub_reg(X10, X1, X5)?;
    assembler.cmp_imm64(X10, 16)?;
    assembler.branch_cond(Condition::CarryClear, tail)?;
    assembler.add_reg(X15, X0, X5)?;
    assembler.load_vector128(0, X15, 0)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    // Each matching lane is 0xff. ADDV therefore produces (-matches) mod
    // 256; subtracting from 256 and retaining eight bits recovers 0..=16.
    assembler.add_across_bytes16(0, 0)?;
    assembler.move_vector_byte_to32(X10, 0)?;
    assembler.mov_imm64(X11, 256)?;
    assembler.sub_reg(X10, X11, X10)?;
    assembler.and_low_bits(X10, X10, 8)?;
    emit_aggregate_add_register(assembler, X10, overflow)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.branch(vector)?;

    assembler.bind(tail)?;
    assembler.cmp_reg64(X5, X1)?;
    assembler.branch_cond(Condition::CarrySet, done)?;
    assembler.load_byte_reg(X10, X0, X5)?;
    assembler.load_byte(X11, X8, 0)?;
    assembler.cmp_reg32(X10, X11)?;
    assembler.branch_cond(Condition::NotEqual, tail_miss)?;
    emit_aggregate_add_immediate(assembler, 1, overflow)?;
    assembler.bind(tail_miss)?;
    assembler.add_imm(X5, X5, 1)?;
    assembler.branch(tail)
}

fn emit_aggregate_single_byte_sve2_fixed16_count(
    assembler: &mut Assembler,
    done: Label,
    overflow: Label,
) -> Result<(), EmitError> {
    let vector = assembler.new_label(LabelKind::Loop)?;
    let tail = assembler.new_label(LabelKind::SlowPath)?;
    let tail_miss = assembler.new_label(LabelKind::Internal)?;
    assembler.load_byte(X11, X8, 0)?;
    // P0 permanently selects the first sixteen byte lanes, independent of a
    // larger physical VL. MATCH is intentionally used to make this backend
    // genuinely SVE2-specific rather than a relabeled SVE sequence.
    assembler.sve_ptrue_bytes_vl16(0)?;
    assembler.sve_duplicate_byte(1, X11)?;
    assembler.mov_imm64(X5, 0)?;
    assembler.bind(vector)?;
    assembler.cmp_reg64(X5, X1)?;
    assembler.branch_cond(Condition::CarrySet, done)?;
    assembler.sub_reg(X10, X1, X5)?;
    assembler.cmp_imm64(X10, 16)?;
    assembler.branch_cond(Condition::CarryClear, tail)?;
    assembler.add_reg(X15, X0, X5)?;
    assembler.sve_load_bytes(0, 0, X15)?;
    assembler.sve2_match_bytes(1, 0, 0, 1)?;
    assembler.sve_count_predicate_bytes(X10, 0, 1)?;
    emit_aggregate_add_register(assembler, X10, overflow)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.branch(vector)?;

    assembler.bind(tail)?;
    assembler.cmp_reg64(X5, X1)?;
    assembler.branch_cond(Condition::CarrySet, done)?;
    assembler.load_byte_reg(X10, X0, X5)?;
    assembler.load_byte(X11, X8, 0)?;
    assembler.cmp_reg32(X10, X11)?;
    assembler.branch_cond(Condition::NotEqual, tail_miss)?;
    emit_aggregate_add_immediate(assembler, 1, overflow)?;
    assembler.bind(tail_miss)?;
    assembler.add_imm(X5, X5, 1)?;
    assembler.branch(tail)
}

fn emit_aggregate_multi_byte(
    assembler: &mut Assembler,
    literal: &[u8],
    output: AggregateOutput,
    done: Label,
    overflow: Label,
) -> Result<(), EmitError> {
    let vector = assembler.new_label(LabelKind::Loop)?;
    let scalar_block = assembler.new_label(LabelKind::SlowPath)?;
    let scalar_tail = assembler.new_label(LabelKind::SlowPath)?;
    let scalar_scan = assembler.new_label(LabelKind::Loop)?;
    let candidate_miss = assembler.new_label(LabelKind::Internal)?;
    let advance_block = assembler.new_label(LabelKind::Internal)?;
    let literal_len = u16::try_from(literal.len()).map_err(|_| EmitError::ArithmeticOverflow {
        site: ArithmeticSite::DataOffset,
    })?;
    let last_offset = literal_len
        .checked_sub(1)
        .ok_or(EmitError::InternalInvariant)?;
    assembler.cmp_reg64(X1, X12)?;
    assembler.branch_cond(Condition::CarryClear, done)?;
    assembler.sub_reg(X6, X1, X12)?;
    assembler.mov_imm64(X5, 0)?;
    assembler.load_byte(X11, X8, 0)?;
    assembler.dup_byte16(1, X11)?;
    assembler.load_byte(X11, X8, last_offset)?;
    assembler.dup_byte16(3, X11)?;

    assembler.bind(vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, done)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, scalar_tail)?;
    assembler.add_reg(X15, X0, X5)?;
    assembler.load_vector128(0, X15, 0)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    assembler.add_imm(X10, X15, last_offset)?;
    assembler.load_vector128(2, X10, 0)?;
    assembler.compare_equal_bytes16(2, 2, 3)?;
    assembler.and_bytes16(0, 0, 2)?;
    assembler.unsigned_max_bytes16(0, 0)?;
    assembler.move_vector_byte_to32(X10, 0)?;
    assembler.compare_branch_zero(X10, true, scalar_block)?;
    assembler.bind(advance_block)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.branch(vector)?;

    assembler.bind(scalar_block)?;
    assembler.add_imm(X7, X5, 15)?;
    assembler.branch(scalar_scan)?;
    assembler.bind(scalar_tail)?;
    assembler.mov_reg(X7, X6)?;
    assembler.bind(scalar_scan)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::Higher, vector)?;
    assembler.load_byte_reg(X10, X0, X5)?;
    assembler.load_byte(X11, X8, 0)?;
    assembler.cmp_reg32(X10, X11)?;
    assembler.branch_cond(Condition::NotEqual, candidate_miss)?;
    assembler.add_reg(X15, X0, X5)?;
    assembler.load_byte(X10, X15, last_offset)?;
    assembler.load_byte(X11, X8, last_offset)?;
    assembler.cmp_reg32(X10, X11)?;
    assembler.branch_cond(Condition::NotEqual, candidate_miss)?;
    if literal.len() > 2 {
        emit_literal_equality_with_vectors(
            assembler,
            X15,
            X8,
            literal.len(),
            candidate_miss,
            4,
            5,
            X11,
        )?;
    }
    let delta = match output {
        AggregateOutput::Count => 1,
        AggregateOutput::SpanSum => literal_len,
    };
    emit_aggregate_add_immediate(assembler, delta, overflow)?;
    // This is the semantic non-overlap transition. Continue at exactly end,
    // retaining that boundary while discarding every intervening start.
    assembler.add_imm(X5, X5, literal_len)?;
    assembler.branch(scalar_scan)?;
    assembler.bind(candidate_miss)?;
    assembler.add_imm(X5, X5, 1)?;
    assembler.branch(scalar_scan)
}

fn emit_aggregate_add_register(
    assembler: &mut Assembler,
    delta: u8,
    overflow: Label,
) -> Result<(), EmitError> {
    assembler.mov_reg(X14, X13)?;
    assembler.add_reg(X13, X13, delta)?;
    assembler.cmp_reg64(X13, X14)?;
    assembler.branch_cond(Condition::CarryClear, overflow)
}

fn emit_aggregate_add_immediate(
    assembler: &mut Assembler,
    delta: u16,
    overflow: Label,
) -> Result<(), EmitError> {
    assembler.mov_reg(X14, X13)?;
    assembler.add_imm(X13, X13, delta)?;
    assembler.cmp_reg64(X13, X14)?;
    assembler.branch_cond(Condition::CarryClear, overflow)
}

fn emit_aggregate_returns(
    assembler: &mut Assembler,
    done: Label,
    overflow: Label,
    backend: AggregateBackend,
) -> Result<(), EmitError> {
    assembler.bind(done)?;
    if backend == AggregateBackend::Sve2Fixed16PairSpanSumExperimental {
        emit_aggregate_add_register(assembler, X13, overflow)?;
    }
    assembler.store64(X13, X2, 0)?;
    assembler.mov_imm64(X0, 0)?;
    assembler.ret()?;
    if overflow != done {
        assembler.bind(overflow)?;
        assembler.mov_imm64(X0, 1)?;
        assembler.ret()?;
    }
    Ok(())
}

fn emit_plan(
    assembler: &mut Assembler,
    data: &Rodata,
    plan: Plan<'_>,
    manifest: SearchManifest,
    backend_version: BackendVersion,
    found: Label,
    none: Label,
) -> Result<(), EmitError> {
    let candidate_offsets = (manifest.candidate_policy_version != SEARCH_CANDIDATE_POLICY_NONE)
        .then_some(CandidateOffsets {
            primary: manifest.primary_offset,
            secondary: (manifest.secondary_offset != SEARCH_CANDIDATE_OFFSET_NONE)
                .then_some(manifest.secondary_offset),
            verification: (manifest.verification_offset != SEARCH_CANDIDATE_OFFSET_NONE)
                .then_some(manifest.verification_offset),
            quaternary: (manifest.quaternary_offset != SEARCH_CANDIDATE_OFFSET_NONE)
                .then_some(manifest.quaternary_offset),
            quinary: (manifest.quinary_offset != SEARCH_CANDIDATE_OFFSET_NONE)
                .then_some(manifest.quinary_offset),
        });
    match plan {
        Plan::Exact { literal, anchors } => {
            assembler.adr(X8, data.symbol_offset(0)?)?;
            emit_exact(
                assembler,
                literal,
                anchors,
                candidate_offsets,
                backend_version,
                found,
                none,
            )
        }
        Plan::ClassSuffix {
            class,
            suffix,
            anchors,
        } => {
            assembler.adr(X8, data.symbol_offset(0)?)?;
            assembler.adr(X7, data.symbol_offset(1)?)?;
            let suffix_first_class = (!anchors.start)
                .then(|| suffix_first_class(class, backend_version))
                .flatten();
            if let Some(suffix_first_class) = suffix_first_class {
                if suffix_first_class == SuffixFirstClass::Sve2Table {
                    assembler.adr(X16, data.symbol_offset(SVE2_CLASS_TABLE_DATA_ID)?)?;
                }
                emit_suffix_first_class(
                    assembler,
                    suffix_first_class,
                    suffix,
                    manifest,
                    found,
                    none,
                )
            } else {
                emit_class_suffix(assembler, class, suffix, anchors, found, none)
            }
        }
    }
}

fn finalize_image(
    mut image: NativeImage,
    limits: EmitLimits,
) -> Result<AuditedNativeImage, EmitError> {
    charge_image_identity(&mut image, limits)?;
    crate::audit(&image).map_err(|_| EmitError::InternalInvariant)?;
    Ok(AuditedNativeImage::from_emitter_audit(image))
}

fn finalize_selected_end_register_image_v2(
    mut image: NativeImage,
    limits: EmitLimits,
) -> Result<AuditedSelectedEndRegisterImageV2, EmitError> {
    charge_image_identity(&mut image, limits)?;
    let image = AuditedSelectedEndRegisterImageV2::from_emitter_candidate(image)?;
    crate::audit_selected_end_register_v2(&image).map_err(|_| EmitError::InternalInvariant)?;
    Ok(image)
}

fn finalize_aggregate_image(
    mut image: NativeImage,
    limits: EmitLimits,
) -> Result<NativeAggregateImage, EmitError> {
    charge_image_identity(&mut image, limits)?;
    let image = NativeAggregateImage::try_new(image)?;
    crate::audit_aggregate(&image).map_err(|_| EmitError::InternalInvariant)?;
    Ok(image)
}

fn charge_image_identity(image: &mut NativeImage, limits: EmitLimits) -> Result<(), EmitError> {
    let identity_domain_bytes = match image.search_call_abi() {
        SearchCallAbi::OutSlotV1 => 0,
        SearchCallAbi::SelectedEndRegisterV2 => {
            SELECTED_END_REGISTER_ARTIFACT_IDENTITY_DOMAIN_V2.len()
        }
    };
    let identity_bytes = aot_size(image)?.checked_add(identity_domain_bytes).ok_or(
        EmitError::ArithmeticOverflow {
            site: ArithmeticSite::AotSize,
        },
    )?;
    let identity_work =
        u64::try_from(identity_bytes).map_err(|_| EmitError::ArithmeticOverflow {
            site: ArithmeticSite::AotSize,
        })?;
    image.stats.emission_work = image.stats.emission_work.checked_add(identity_work).ok_or(
        EmitError::ArithmeticOverflow {
            site: ArithmeticSite::EmissionWork,
        },
    )?;
    enforce_u64(
        ResourceKind::EmissionWork,
        image.stats.emission_work,
        limits.max_emission_work,
    )?;
    let identity_scratch = u64::try_from(core::mem::size_of::<sha2::Sha256>()).map_err(|_| {
        EmitError::ArithmeticOverflow {
            site: ArithmeticSite::ScratchBytes,
        }
    })?;
    image.stats.scratch_bytes = image.stats.scratch_bytes.max(identity_scratch);
    enforce_u64(
        ResourceKind::ScratchBytes,
        image.stats.scratch_bytes,
        limits.max_scratch_bytes,
    )?;
    image.artifact_identity = image.compute_artifact_identity()?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Plan<'a> {
    Exact {
        literal: &'a [u8],
        anchors: AnchorFlags,
    },
    ClassSuffix {
        class: ByteClass,
        suffix: &'a [u8],
        anchors: AnchorFlags,
    },
}

#[derive(Clone, Copy)]
struct CandidateOffsets {
    primary: u16,
    secondary: Option<u16>,
    verification: Option<u16>,
    quaternary: Option<u16>,
    quinary: Option<u16>,
}

mod v7_policy_scan_admission {
    use super::{
        ArithmeticSite, CandidateOffsets, EmitError, WorkMeter, candidate_byte_pair,
        candidate_ranked_verification_offsets, candidate_ranked_verification_offsets_v2,
        candidate_ranked_verification_offsets_v3,
    };

    /// Move-only proof that both complete V7 policy scans were admitted.
    ///
    /// The literal is held inside the unforgeable token so selecting offsets
    /// cannot be redirected to bytes whose scan work was not admitted.
    pub(super) struct Admission<'a> {
        literal: &'a [u8],
    }

    impl<'a> Admission<'a> {
        pub(super) fn charge(literal: &'a [u8], meter: &mut WorkMeter) -> Result<Self, EmitError> {
            let scan_work = u64::try_from(literal.len())
                .map_err(|_| EmitError::ArithmeticOverflow {
                    site: ArithmeticSite::EmissionWork,
                })?
                .checked_mul(2)
                .ok_or(EmitError::ArithmeticOverflow {
                    site: ArithmeticSite::EmissionWork,
                })?;
            meter.charge(scan_work)?;
            Ok(Self { literal })
        }

        pub(super) fn select_offsets(self) -> CandidateOffsets {
            let (primary, secondary) = candidate_byte_pair(self.literal);
            let (verification, quaternary) =
                candidate_ranked_verification_offsets(self.literal, primary, secondary);
            CandidateOffsets {
                primary,
                secondary,
                verification,
                quaternary,
                quinary: None,
            }
        }

        pub(super) fn select_offsets_v2(self) -> CandidateOffsets {
            let (primary, secondary) = candidate_byte_pair(self.literal);
            let (verification, quaternary, quinary) =
                candidate_ranked_verification_offsets_v2(self.literal, primary, secondary);
            CandidateOffsets {
                primary,
                secondary,
                verification,
                quaternary,
                quinary,
            }
        }

        pub(super) fn select_offsets_v3(self) -> CandidateOffsets {
            let (primary, secondary) = candidate_byte_pair(self.literal);
            let (verification, quaternary, quinary) =
                candidate_ranked_verification_offsets_v3(self.literal, primary, secondary);
            CandidateOffsets {
                primary,
                secondary,
                verification,
                quaternary,
                quinary,
            }
        }
    }
}

use v7_policy_scan_admission::Admission as V7PolicyScanAdmission;

impl<'a> Plan<'a> {
    const fn is_v9_policy_shape(self) -> bool {
        matches!(
            self,
            Self::Exact {
                literal: [_, ..],
                anchors: AnchorFlags {
                    start: false,
                    end: false,
                },
            }
        )
    }

    const fn is_sve2_fixed16_v2_policy_shape(self) -> bool {
        matches!(
            self,
            Self::Exact {
                literal,
                anchors:
                    AnchorFlags {
                        start: false,
                        end: false,
                    },
            } if literal.len() == 16
        )
    }

    const fn is_sve16_v6_policy_shape(self) -> bool {
        matches!(
            self,
            Self::Exact {
                literal,
                anchors:
                    AnchorFlags {
                        start: false,
                        end: false,
                    },
            } if literal.len() >= 16
        )
    }

    fn is_fixed16_policy_shape(self, backend_version: BackendVersion) -> bool {
        match self {
            Self::Exact {
                literal: [_, ..],
                anchors:
                    AnchorFlags {
                        start: false,
                        end: false,
                    },
            } => true,
            Self::ClassSuffix {
                class,
                suffix: [_, ..],
                anchors: AnchorFlags { start: false, .. },
            } => {
                singleton_byte(class).is_some()
                    || (backend_version == BackendVersion::SEARCH_SVE2_16_V1
                        && sve2_fixed16_ascii_class_table(class).is_some())
            }
            _ => false,
        }
    }

    const fn uses_asimd_confirmation(self) -> bool {
        matches!(
            self,
            Self::Exact {
                literal,
                ..
            } | Self::ClassSuffix {
                suffix: literal,
                ..
            } if literal.len() >= 16
        )
    }

    fn recognize<O: Operation>(program: &'a ValidatedProgram<O>) -> Result<Self, EmitError> {
        let raw = program.raw();
        let mut literal = None;
        let mut class_scan = None;
        let mut suffix = None;
        for block in &raw.blocks {
            match block.op {
                BlockOp::ScanLiteral {
                    needle, anchors, ..
                } => literal = Some((needle, anchors)),
                BlockOp::ScanClassStart { class, .. } => class_scan = Some(class),
                BlockOp::ConfirmSuffix {
                    suffix: data,
                    anchored_end,
                    ..
                } => suffix = Some((data, anchored_end)),
                _ => {}
            }
        }
        if let Some((id, anchors)) = literal {
            let bytes = data_bytes(raw.data.get(to_usize(id.0)?))?;
            if !anchors.start && !anchors.end {
                enforce_confirmation_length(ConfirmationKind::ExactLiteral, bytes.len())?;
            }
            return Ok(Self::Exact {
                literal: bytes,
                anchors,
            });
        }
        let class_id = class_scan.ok_or(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        })?;
        let (suffix_id, anchored_end) = suffix.ok_or(EmitError::Unsupported {
            reason: UnsupportedReason::KernelShape,
        })?;
        let class = data_class(raw.data.get(to_usize(class_id.0)?))?;
        let suffix = data_bytes(raw.data.get(to_usize(suffix_id.0)?))?;
        let anchored_start = raw.blocks.iter().find_map(|block| match block.op {
            BlockOp::ScanClassStart { anchored_start, .. } => Some(anchored_start),
            _ => None,
        });
        let anchors = AnchorFlags {
            start: anchored_start.ok_or(EmitError::Unsupported {
                reason: UnsupportedReason::KernelShape,
            })?,
            end: anchored_end,
        };
        if !anchors.start {
            enforce_confirmation_length(ConfirmationKind::ClassSuffix, suffix.len())?;
        }
        Ok(Self::ClassSuffix {
            class,
            suffix,
            anchors,
        })
    }

    const fn capacities(self, backend_version: BackendVersion) -> Capacities {
        match self {
            Self::Exact { .. } if backend_version.0 == BackendVersion::SEARCH_V7.0 => Capacities {
                code: V7_EXACT_CODE_RESERVE,
                labels: V7_EXACT_LABEL_RESERVE,
                relocations: V7_EXACT_RELOCATION_RESERVE,
            },
            Self::Exact { .. }
                if matches!(
                    backend_version,
                    BackendVersion::SEARCH_V8
                        | BackendVersion::SEARCH_V9
                        | BackendVersion::SEARCH_V10
                        | BackendVersion::SEARCH_V11
                        | BackendVersion::SEARCH_SVE16_V6
                        | BackendVersion::SEARCH_SVE2_FIXED16_V2
                ) =>
            {
                Capacities {
                    code: V8_EXACT_CODE_RESERVE,
                    labels: V8_EXACT_LABEL_RESERVE,
                    relocations: V8_EXACT_RELOCATION_RESERVE,
                }
            }
            Self::Exact { .. }
                if matches!(
                    backend_version,
                    BackendVersion::SEARCH_SVE16_V1 | BackendVersion::SEARCH_SVE2_16_V1
                ) =>
            {
                Capacities {
                    code: SVE16_EXACT_CODE_RESERVE,
                    labels: SVE16_EXACT_LABEL_RESERVE,
                    relocations: SVE16_EXACT_RELOCATION_RESERVE,
                }
            }
            Self::Exact { .. } => Capacities {
                code: EXACT_CODE_RESERVE,
                labels: EXACT_LABEL_RESERVE,
                relocations: EXACT_RELOCATION_RESERVE,
            },
            Self::ClassSuffix { .. } => Capacities {
                code: CLASS_CODE_RESERVE,
                labels: CLASS_LABEL_RESERVE,
                relocations: CLASS_RELOCATION_RESERVE,
            },
        }
    }

    fn admit_v7_policy_scans(
        self,
        backend_version: BackendVersion,
        meter: &mut WorkMeter,
    ) -> Result<Option<V7PolicyScanAdmission<'a>>, EmitError> {
        let Self::Exact { literal, anchors } = self else {
            return Ok(None);
        };
        if !matches!(
            backend_version,
            BackendVersion::SEARCH_V7
                | BackendVersion::SEARCH_V8
                | BackendVersion::SEARCH_V9
                | BackendVersion::SEARCH_V10
                | BackendVersion::SEARCH_V11
                | BackendVersion::SEARCH_SVE16_V1
                | BackendVersion::SEARCH_SVE2_16_V1
                | BackendVersion::SEARCH_SVE16_V6
                | BackendVersion::SEARCH_SVE2_FIXED16_V2
        ) || anchors.start
            || anchors.end
            || literal.is_empty()
        {
            return Ok(None);
        }

        // The move-only token is minted by one combined charge and is the only
        // route to both ranked scans. Older backends retain their historical
        // receipts and adjacent emission charge.
        V7PolicyScanAdmission::charge(literal, meter).map(Some)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the versioned manifest construction keeps every historical and current policy field explicit"
    )]
    fn search_manifest(
        self,
        output: OutputKind,
        source_identity: fre_kernel_ir::CacheIdentity,
        backend_version: BackendVersion,
        v7_policy_scan_admission: Option<V7PolicyScanAdmission<'a>>,
    ) -> Result<SearchManifest, EmitError> {
        let (shape, anchors, literal, candidate_policy) = match self {
            Self::Exact { literal, anchors } => {
                let policy_enabled = !anchors.start && !anchors.end && !literal.is_empty();
                let candidate_policy = if !policy_enabled {
                    if v7_policy_scan_admission.is_some() {
                        return Err(EmitError::InternalInvariant);
                    }
                    None
                } else if matches!(
                    backend_version,
                    BackendVersion::SEARCH_V7
                        | BackendVersion::SEARCH_V8
                        | BackendVersion::SEARCH_V9
                        | BackendVersion::SEARCH_V10
                        | BackendVersion::SEARCH_V11
                        | BackendVersion::SEARCH_SVE16_V1
                        | BackendVersion::SEARCH_SVE2_16_V1
                        | BackendVersion::SEARCH_SVE16_V6
                        | BackendVersion::SEARCH_SVE2_FIXED16_V2
                ) {
                    let admission = v7_policy_scan_admission.ok_or(EmitError::InternalInvariant)?;
                    Some(if backend_version == BackendVersion::SEARCH_V11 {
                        admission.select_offsets_v3()
                    } else if matches!(
                        backend_version,
                        BackendVersion::SEARCH_SVE2_FIXED16_V2 | BackendVersion::SEARCH_V10
                    ) {
                        admission.select_offsets_v2()
                    } else {
                        admission.select_offsets()
                    })
                } else {
                    if v7_policy_scan_admission.is_some() {
                        return Err(EmitError::InternalInvariant);
                    }
                    let (primary, secondary) = candidate_byte_pair(literal);
                    let verification = matches!(
                        backend_version,
                        BackendVersion::SEARCH_V5 | BackendVersion::SEARCH_V6
                    )
                    .then(|| candidate_verification_offset(literal, primary, secondary))
                    .flatten();
                    Some(CandidateOffsets {
                        primary,
                        secondary,
                        verification,
                        quaternary: None,
                        quinary: None,
                    })
                };
                (
                    SearchShape::ExactLiteral,
                    anchors,
                    literal,
                    candidate_policy,
                )
            }
            Self::ClassSuffix {
                class,
                suffix,
                anchors,
            } => {
                if v7_policy_scan_admission.is_some() {
                    return Err(EmitError::InternalInvariant);
                }
                let candidate_policy = (!anchors.start
                    && !suffix.is_empty()
                    && (singleton_byte(class).is_some()
                        || (backend_version == BackendVersion::SEARCH_SVE2_16_V1
                            && sve2_fixed16_ascii_class_table(class).is_some())))
                .then(|| CandidateOffsets {
                    primary: 0,
                    secondary: (suffix.len() > 1).then(|| {
                        u16::try_from(
                            suffix
                                .len()
                                .checked_sub(1)
                                .expect("non-empty singleton suffix"),
                        )
                        .expect("bounded class suffix offset fits u16")
                    }),
                    verification: None,
                    quaternary: None,
                    quinary: None,
                });
                (SearchShape::ClassSuffix, anchors, suffix, candidate_policy)
            }
        };
        let (
            candidate_policy_version,
            candidate_block_width,
            primary_offset,
            secondary_offset,
            verification_offset,
            quaternary_offset,
            quinary_offset,
        ) = candidate_policy.map_or(
            (
                SEARCH_CANDIDATE_POLICY_NONE,
                0,
                SEARCH_CANDIDATE_OFFSET_NONE,
                SEARCH_CANDIDATE_OFFSET_NONE,
                SEARCH_CANDIDATE_OFFSET_NONE,
                SEARCH_CANDIDATE_OFFSET_NONE,
                SEARCH_CANDIDATE_OFFSET_NONE,
            ),
            |offsets| {
                (
                    if backend_version == BackendVersion::SEARCH_SVE2_FIXED16_V2
                        && shape == SearchShape::ExactLiteral
                    {
                        SEARCH_CANDIDATE_POLICY_SVE2_FIXED16_V2
                    } else if backend_version == BackendVersion::SEARCH_V10
                        && shape == SearchShape::ExactLiteral
                    {
                        SEARCH_CANDIDATE_POLICY_V6
                    } else if backend_version == BackendVersion::SEARCH_V11
                        && shape == SearchShape::ExactLiteral
                    {
                        SEARCH_CANDIDATE_POLICY_V7
                    } else if backend_version == BackendVersion::SEARCH_V9
                        && shape == SearchShape::ExactLiteral
                    {
                        SEARCH_CANDIDATE_POLICY_V5
                    } else if backend_version == BackendVersion::SEARCH_V8
                        && shape == SearchShape::ExactLiteral
                    {
                        SEARCH_CANDIDATE_POLICY_V4
                    } else if backend_version == BackendVersion::SEARCH_SVE2_16_V1
                        && matches!(shape, SearchShape::ExactLiteral | SearchShape::ClassSuffix)
                    {
                        SEARCH_CANDIDATE_POLICY_SVE2_16_V1
                    } else if matches!(
                        backend_version,
                        BackendVersion::SEARCH_SVE16_V1 | BackendVersion::SEARCH_SVE16_V6
                    ) && matches!(
                        shape,
                        SearchShape::ExactLiteral | SearchShape::ClassSuffix
                    ) {
                        SEARCH_CANDIDATE_POLICY_SVE16_V1
                    } else if backend_version == BackendVersion::SEARCH_V7
                        && shape == SearchShape::ExactLiteral
                    {
                        SEARCH_CANDIDATE_POLICY_V3
                    } else if matches!(
                        backend_version,
                        BackendVersion::SEARCH_V5 | BackendVersion::SEARCH_V6
                    ) && shape == SearchShape::ExactLiteral
                    {
                        SEARCH_CANDIDATE_POLICY_V2
                    } else {
                        SEARCH_CANDIDATE_POLICY_V1
                    },
                    SEARCH_CANDIDATE_BLOCK_WIDTH,
                    offsets.primary,
                    offsets.secondary.unwrap_or(SEARCH_CANDIDATE_OFFSET_NONE),
                    offsets.verification.unwrap_or(SEARCH_CANDIDATE_OFFSET_NONE),
                    offsets.quaternary.unwrap_or(SEARCH_CANDIDATE_OFFSET_NONE),
                    offsets.quinary.unwrap_or(SEARCH_CANDIDATE_OFFSET_NONE),
                )
            },
        );
        Ok(SearchManifest {
            backend_version,
            shape,
            output,
            anchors,
            source_identity,
            literal_bytes: to_u32(literal.len(), ArithmeticSite::DataOffset)?,
            candidate_policy_version,
            candidate_block_width,
            primary_offset,
            secondary_offset,
            verification_offset,
            quaternary_offset,
            quinary_offset,
        })
    }
}

fn enforce_confirmation_length(kind: ConfirmationKind, required: usize) -> Result<(), EmitError> {
    if required > MAX_REPEATED_CONFIRM_BYTES {
        return Err(EmitError::ConfirmationLengthLimit {
            kind,
            limit: MAX_REPEATED_CONFIRM_BYTES,
            required,
        });
    }
    Ok(())
}

fn data_bytes(blob: Option<&DataBlob>) -> Result<&[u8], EmitError> {
    match blob {
        Some(DataBlob::Bytes(bytes)) => Ok(bytes),
        _ => Err(EmitError::Unsupported {
            reason: UnsupportedReason::DataLayout,
        }),
    }
}

fn data_class(blob: Option<&DataBlob>) -> Result<ByteClass, EmitError> {
    match blob {
        Some(DataBlob::ByteClass(class)) => Ok(*class),
        _ => Err(EmitError::Unsupported {
            reason: UnsupportedReason::DataLayout,
        }),
    }
}

fn emit_preamble(assembler: &mut Assembler, none: Label) -> Result<(), EmitError> {
    assembler.mov_reg(X9, X0)?;
    assembler.cmp_reg64(X2, X3)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.cmp_reg64(X3, X1)?;
    assembler.branch_cond(Condition::Higher, none)
}

#[allow(
    clippy::too_many_lines,
    reason = "explicit version dispatch keeps every authenticated search backend visible"
)]
fn emit_exact(
    assembler: &mut Assembler,
    literal: &[u8],
    anchors: AnchorFlags,
    candidate_offsets: Option<CandidateOffsets>,
    backend_version: BackendVersion,
    found: Label,
    none: Label,
) -> Result<(), EmitError> {
    if literal.is_empty() {
        return emit_empty_literal(assembler, anchors, found, none);
    }
    let length = u64::try_from(literal.len()).map_err(|_| EmitError::ArithmeticOverflow {
        site: ArithmeticSite::DataOffset,
    })?;
    assembler.mov_imm64(X12, length)?;
    if anchors.start {
        assembler.cmp_imm64(X2, 0)?;
        assembler.branch_cond(Condition::NotEqual, none)?;
        assembler.cmp_reg64(X3, X12)?;
        assembler.branch_cond(Condition::CarryClear, none)?;
        if anchors.end {
            assembler.cmp_reg64(X1, X12)?;
            assembler.branch_cond(Condition::NotEqual, none)?;
        }
        assembler.mov_imm64(X13, 0)?;
        assembler.mov_reg(X15, X9)?;
        emit_literal_equality(assembler, X15, X8, literal.len(), none)?;
        assembler.mov_reg(X14, X12)?;
        return assembler.branch(found);
    }
    if anchors.end {
        assembler.cmp_reg64(X1, X12)?;
        assembler.branch_cond(Condition::CarryClear, none)?;
        assembler.sub_reg(X13, X1, X12)?;
        assembler.cmp_reg64(X13, X2)?;
        assembler.branch_cond(Condition::CarryClear, none)?;
        assembler.cmp_reg64(X3, X1)?;
        assembler.branch_cond(Condition::NotEqual, none)?;
        assembler.add_reg(X15, X9, X13)?;
        emit_literal_equality(assembler, X15, X8, literal.len(), none)?;
        assembler.mov_reg(X14, X1)?;
        return assembler.branch(found);
    }
    assembler.sub_reg(X10, X3, X2)?;
    assembler.cmp_reg64(X10, X12)?;
    assembler.branch_cond(Condition::CarryClear, none)?;
    assembler.sub_reg(X6, X3, X12)?;
    assembler.mov_reg(X5, X2)?;
    let CandidateOffsets {
        primary: primary_offset,
        secondary: secondary_offset,
        verification: verification_offset,
        quaternary: quaternary_offset,
        quinary: quinary_offset,
    } = candidate_offsets.ok_or(EmitError::InternalInvariant)?;
    match backend_version {
        BackendVersion::SEARCH_V1 => {
            emit_vector_candidate_skip_v1(assembler, literal, none, found)?;
        }
        BackendVersion::SEARCH_V2 => {
            emit_vector_candidate_skip_v2(
                assembler,
                literal,
                primary_offset,
                secondary_offset,
                none,
                found,
            )?;
        }
        BackendVersion::SEARCH_V3 => {
            emit_vector_candidate_skip_v3(
                assembler,
                literal,
                primary_offset,
                secondary_offset,
                none,
                found,
            )?;
        }
        BackendVersion::SEARCH_V4 => {
            emit_vector_candidate_skip_v4(
                assembler,
                literal,
                primary_offset,
                secondary_offset,
                none,
                found,
            )?;
        }
        BackendVersion::SEARCH_V5 => {
            emit_vector_candidate_skip_v5(
                assembler,
                literal,
                primary_offset,
                secondary_offset,
                verification_offset,
                none,
                found,
            )?;
        }
        BackendVersion::SEARCH_V6 => {
            emit_vector_candidate_skip_v6(
                assembler,
                literal,
                primary_offset,
                secondary_offset,
                verification_offset,
                none,
                found,
            )?;
        }
        BackendVersion::SEARCH_V7 => {
            emit_vector_candidate_skip_v7(
                assembler,
                literal,
                primary_offset,
                secondary_offset,
                verification_offset,
                quaternary_offset,
                none,
                found,
            )?;
        }
        BackendVersion::SEARCH_SVE16_V1 | BackendVersion::SEARCH_SVE2_16_V1 => {
            emit_vector_candidate_skip_sve16(
                assembler,
                literal,
                primary_offset,
                secondary_offset,
                verification_offset,
                quaternary_offset,
                backend_version,
                none,
                found,
            )?;
        }
        BackendVersion::SEARCH_V8 | BackendVersion::SEARCH_SVE16_V6 => {
            emit_vector_candidate_skip_v8(
                assembler,
                literal,
                primary_offset,
                secondary_offset,
                verification_offset,
                quaternary_offset,
                None,
                backend_version,
                none,
                found,
            )?;
        }
        BackendVersion::SEARCH_V10 => {
            emit_vector_candidate_skip_v10(
                assembler,
                literal,
                primary_offset,
                secondary_offset,
                verification_offset,
                quaternary_offset,
                quinary_offset,
                none,
                found,
            )?;
        }
        BackendVersion::SEARCH_V11 => {
            emit_vector_candidate_skip_v10(
                assembler,
                literal,
                primary_offset,
                secondary_offset,
                verification_offset,
                quaternary_offset,
                quinary_offset,
                none,
                found,
            )?;
        }
        BackendVersion::SEARCH_V9 => {
            emit_vector_candidate_skip_v9(
                assembler,
                literal,
                primary_offset,
                secondary_offset,
                verification_offset,
                quaternary_offset,
                none,
                found,
            )?;
        }
        BackendVersion::SEARCH_SVE2_FIXED16_V2 => {
            emit_vector_candidate_skip_sve2_fixed16_v2(
                assembler,
                literal,
                primary_offset,
                secondary_offset,
                verification_offset,
                quaternary_offset,
                quinary_offset,
                none,
                found,
            )?;
        }
        _ => return Err(EmitError::InternalInvariant),
    }
    Ok(())
}

fn emit_empty_literal(
    assembler: &mut Assembler,
    anchors: AnchorFlags,
    found: Label,
    none: Label,
) -> Result<(), EmitError> {
    if anchors.start {
        assembler.cmp_imm64(X2, 0)?;
        assembler.branch_cond(Condition::NotEqual, none)?;
        if anchors.end {
            assembler.cmp_imm64(X1, 0)?;
            assembler.branch_cond(Condition::NotEqual, none)?;
        }
        assembler.mov_imm64(X13, 0)?;
        assembler.mov_imm64(X14, 0)?;
    } else if anchors.end {
        assembler.cmp_reg64(X3, X1)?;
        assembler.branch_cond(Condition::NotEqual, none)?;
        assembler.mov_reg(X13, X1)?;
        assembler.mov_reg(X14, X1)?;
    } else {
        assembler.mov_reg(X13, X2)?;
        assembler.mov_reg(X14, X2)?;
    }
    assembler.branch(found)
}

fn emit_vector_candidate_skip_v1(
    assembler: &mut Assembler,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    let vector = assembler.new_label(LabelKind::Loop)?;
    let scalar = assembler.new_label(LabelKind::SlowPath)?;
    let advance = assembler.new_label(LabelKind::Internal)?;
    let second_filter = if literal.len() > 1 {
        Some(assembler.new_label(LabelKind::SlowPath)?)
    } else {
        None
    };
    assembler.load_byte(X11, X8, 0)?;
    assembler.dup_byte16(1, X11)?;
    let secondary_offset = u16::try_from(literal.len().saturating_sub(1)).map_err(|_| {
        EmitError::ArithmeticOverflow {
            site: ArithmeticSite::DataOffset,
        }
    })?;
    if second_filter.is_some() {
        assembler.load_byte(X11, X8, secondary_offset)?;
        assembler.dup_byte16(3, X11)?;
    }
    assembler.bind(vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, scalar)?;
    assembler.add_reg(X15, X9, X5)?;
    assembler.load_vector128(0, X15, 0)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    if let Some(second_filter) = second_filter {
        assembler.unsigned_max_bytes16(2, 0)?;
        assembler.move_vector_byte_to32(X10, 2)?;
        assembler.compare_branch_zero(X10, true, second_filter)?;
    } else {
        assembler.unsigned_max_bytes16(0, 0)?;
        assembler.move_vector_byte_to32(X10, 0)?;
        assembler.compare_branch_zero(X10, true, scalar)?;
    }
    assembler.bind(advance)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.branch(vector)?;
    if let Some(second_filter) = second_filter {
        assembler.bind(second_filter)?;
        assembler.add_imm(X10, X15, secondary_offset)?;
        assembler.load_vector128(2, X10, 0)?;
        assembler.compare_equal_bytes16(2, 2, 3)?;
        assembler.and_bytes16(0, 0, 2)?;
        assembler.unsigned_max_bytes16(0, 0)?;
        assembler.move_vector_byte_to32(X10, 0)?;
        assembler.compare_branch_zero(X10, true, scalar)?;
        assembler.branch(advance)?;
    }
    assembler.bind(scalar)?;
    emit_scalar_candidates_legacy(assembler, literal, false, none, found)
}

fn emit_vector_candidate_skip_v2(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    let vector = assembler.new_label(LabelKind::Loop)?;
    let scalar = assembler.new_label(LabelKind::SlowPath)?;
    let advance = assembler.new_label(LabelKind::Internal)?;
    let second_filter = if secondary_offset.is_some() {
        Some(assembler.new_label(LabelKind::SlowPath)?)
    } else {
        None
    };
    assembler.load_byte(X11, X8, primary_offset)?;
    assembler.dup_byte16(1, X11)?;
    if let Some(secondary_offset) = secondary_offset {
        assembler.load_byte(X11, X8, secondary_offset)?;
        assembler.dup_byte16(3, X11)?;
    }
    assembler.add_reg(X15, X9, X5)?;
    if primary_offset != 0 {
        assembler.add_imm(X15, X15, primary_offset)?;
    }
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, scalar)?;
    assembler.sub_imm(X7, X6, 15)?;
    assembler.bind(vector)?;
    assembler.load_vector128(0, X15, 0)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    if let Some(second_filter) = second_filter {
        assembler.unsigned_max_pairwise_bytes16(2, 0, 0)?;
        assembler.move_vector_double_to64(X10, 2)?;
        assembler.compare_branch_zero(X10, true, second_filter)?;
    } else {
        assembler.unsigned_max_pairwise_bytes16(0, 0, 0)?;
        assembler.move_vector_double_to64(X10, 0)?;
        assembler.compare_branch_zero(X10, true, scalar)?;
    }
    assembler.bind(advance)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.add_imm(X15, X15, 16)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(scalar)?;
    if let Some(second_filter) = second_filter {
        let secondary_offset = secondary_offset.ok_or(EmitError::InternalInvariant)?;
        let delta = secondary_offset.abs_diff(primary_offset);
        assembler.bind(second_filter)?;
        if secondary_offset > primary_offset {
            assembler.add_imm(X10, X15, delta)?;
        } else {
            assembler.sub_imm(X10, X15, delta)?;
        }
        assembler.load_vector128(2, X10, 0)?;
        assembler.compare_equal_bytes16(2, 2, 3)?;
        assembler.and_bytes16(0, 0, 2)?;
        assembler.unsigned_max_pairwise_bytes16(0, 0, 0)?;
        assembler.move_vector_double_to64(X10, 0)?;
        assembler.compare_branch_zero(X10, true, scalar)?;
        assembler.branch(advance)?;
    }
    assembler.bind(scalar)?;
    emit_scalar_candidates_legacy(assembler, literal, true, none, found)
}

fn emit_scalar_candidates_legacy(
    assembler: &mut Assembler,
    literal: &[u8],
    fixed_16: bool,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    let scan = assembler.new_label(LabelKind::Loop)?;
    let advance = assembler.new_label(LabelKind::Internal)?;
    assembler.bind(scan)?;
    assembler.load_byte_reg(X10, X9, X5)?;
    assembler.load_byte(X11, X8, 0)?;
    assembler.cmp_reg32(X10, X11)?;
    assembler.branch_cond(Condition::NotEqual, advance)?;
    assembler.add_reg(X15, X9, X5)?;
    if fixed_16 && literal.len() == 16 {
        emit_literal_equality_16(assembler, X15, X8, advance)?;
    } else {
        emit_literal_equality(assembler, X15, X8, literal.len(), advance)?;
    }
    assembler.mov_reg(X13, X5)?;
    assembler.add_reg(X14, X5, X12)?;
    assembler.branch(found)?;
    assembler.bind(advance)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::CarrySet, none)?;
    assembler.add_imm(X5, X5, 1)?;
    assembler.branch(scan)
}

fn emit_vector_candidate_skip_v3(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    // These vector loads examine two 16-byte columns of candidate positions,
    // not one candidate. X6 is the last start at which the complete literal
    // fits. The remaining-start check proves X5..=X5+15 are valid starts; for
    // either selected byte column at offset P it therefore also proves
    // X5+P..=X5+P+15 lies inside the search window because P < length.
    let vector = assembler.new_label(LabelKind::Loop)?;
    let scalar = assembler.new_label(LabelKind::SlowPath)?;
    let advance = assembler.new_label(LabelKind::Internal)?;
    let block_setup = assembler.new_label(LabelKind::SlowPath)?;
    let tail_setup = assembler.new_label(LabelKind::SlowPath)?;
    let second_filter = if literal.len() > 1 {
        Some(assembler.new_label(LabelKind::SlowPath)?)
    } else {
        None
    };
    assembler.meter.charge_usize(literal.len())?;
    assembler.load_byte(X11, X8, primary_offset)?;
    assembler.dup_byte16(1, X11)?;
    if let Some(secondary_offset) = secondary_offset {
        assembler.load_byte(X11, X8, secondary_offset)?;
        assembler.dup_byte16(3, X11)?;
    }
    assembler.add_reg(X15, X9, X5)?;
    if primary_offset != 0 {
        assembler.add_imm(X15, X15, primary_offset)?;
    }
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, tail_setup)?;
    assembler.sub_imm(X7, X6, 15)?;
    assembler.bind(vector)?;
    assembler.load_vector128(0, X15, 0)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    if let Some(second_filter) = second_filter {
        // Preserve the first-byte lane mask in v0 while reducing a copy. Most
        // blocks contain no first-byte candidate and fall through at exactly
        // the original one-vector steady-state branch behavior.
        assembler.unsigned_max_pairwise_bytes16(2, 0, 0)?;
        assembler.move_vector_double_to64(X10, 2)?;
        assembler.compare_branch_zero(X10, true, second_filter)?;
    } else {
        assembler.unsigned_max_pairwise_bytes16(0, 0, 0)?;
        assembler.move_vector_double_to64(X10, 0)?;
        assembler.compare_branch_zero(X10, true, block_setup)?;
    }
    assembler.bind(advance)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.add_imm(X15, X15, 16)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)?;
    if let Some(second_filter) = second_filter {
        let secondary_offset = secondary_offset.expect("multi-byte literal has a byte pair");
        let secondary_delta = secondary_offset.abs_diff(primary_offset);
        assembler.bind(second_filter)?;
        if secondary_offset > primary_offset {
            assembler.add_imm(X10, X15, secondary_delta)?;
        } else {
            assembler.sub_imm(X10, X15, secondary_delta)?;
        }
        assembler.load_vector128(2, X10, 0)?;
        assembler.compare_equal_bytes16(2, 2, 3)?;
        assembler.and_bytes16(0, 0, 2)?;
        assembler.unsigned_max_pairwise_bytes16(0, 0, 0)?;
        assembler.move_vector_double_to64(X10, 0)?;
        assembler.compare_branch_zero(X10, true, block_setup)?;
        assembler.branch(advance)?;
    }
    // A vector hit proves only that at least one candidate in this block has
    // the selected byte pair. Bound scalar confirmation to those 16
    // candidates, then resume vector filtering after a false-positive block.
    // X13 is otherwise only the eventual output start, so it can carry this
    // internal block/tail mode until a match is found.
    assembler.bind(block_setup)?;
    assembler.mov_imm64(X13, 1)?;
    assembler.add_imm(X7, X5, 15)?;
    assembler.branch(scalar)?;
    assembler.bind(tail_setup)?;
    assembler.mov_imm64(X13, 0)?;
    assembler.mov_reg(X7, X6)?;
    assembler.bind(scalar)?;
    emit_scalar_candidates(
        assembler,
        literal,
        primary_offset,
        secondary_offset,
        vector,
        tail_setup,
        none,
        found,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete mask-guided recovery graph keeps every bound and resume edge visible"
)]
fn emit_vector_candidate_skip_v4(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    emit_vector_candidate_skip_mask(
        assembler,
        literal,
        primary_offset,
        secondary_offset,
        None,
        none,
        found,
    )
}

fn emit_vector_candidate_skip_v5(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    verification_offset: Option<u16>,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    emit_vector_candidate_skip_mask(
        assembler,
        literal,
        primary_offset,
        secondary_offset,
        verification_offset,
        none,
        found,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete sparse per-lane recovery graph keeps mask construction, lane order, bounds, and resume edges reviewable"
)]
fn emit_vector_candidate_skip_v6(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    verification_offset: Option<u16>,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    // The intersected v0 bytes are exactly 0xff or 0x00. SHRN #4 packs each
    // adjacent byte pair into one output byte: the low and high nibbles
    // represent the even and odd candidate lanes. Masking the low 64 bits with
    // 0x1111... retains one bit at positions 4*lane for all 16 lanes. RBIT/CLZ
    // then selects the lowest surviving lane, and X0 & (X0 - 1) clears exactly
    // that lane after a false confirmation.
    let vector = assembler.new_label(LabelKind::Loop)?;
    let advance = assembler.new_label(LabelKind::Internal)?;
    let recover = assembler.new_label(LabelKind::SlowPath)?;
    let lane_loop = assembler.new_label(LabelKind::Loop)?;
    let candidate_miss = assembler.new_label(LabelKind::Internal)?;
    let block_resume = assembler.new_label(LabelKind::Internal)?;
    let tail_setup = assembler.new_label(LabelKind::SlowPath)?;
    let second_filter = if literal.len() > 1 {
        Some(assembler.new_label(LabelKind::SlowPath)?)
    } else {
        None
    };
    assembler.meter.charge_usize(literal.len())?;
    assembler.load_byte(X11, X8, primary_offset)?;
    assembler.dup_byte16(1, X11)?;
    if let Some(secondary_offset) = secondary_offset {
        assembler.load_byte(X11, X8, secondary_offset)?;
        assembler.dup_byte16(3, X11)?;
    }
    if let Some(verification_offset) = verification_offset {
        assembler.load_byte(X11, X8, verification_offset)?;
        assembler.dup_byte16(5, X11)?;
    }
    assembler.add_reg(X15, X9, X5)?;
    if primary_offset != 0 {
        assembler.add_imm(X15, X15, primary_offset)?;
    }
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, tail_setup)?;
    assembler.sub_imm(X7, X6, 15)?;
    assembler.bind(vector)?;
    assembler.load_vector128(0, X15, 0)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    if let Some(second_filter) = second_filter {
        assembler.unsigned_max_pairwise_bytes16(2, 0, 0)?;
        assembler.move_vector_double_to64(X10, 2)?;
        assembler.compare_branch_zero(X10, true, second_filter)?;
    } else {
        emit_sparse_lane_mask(assembler)?;
        assembler.compare_branch_zero(X0, true, recover)?;
    }
    assembler.bind(advance)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.add_imm(X15, X15, 16)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)?;
    if let Some(second_filter) = second_filter {
        let secondary_offset = secondary_offset.expect("multi-byte literal has a byte pair");
        let secondary_delta = secondary_offset.abs_diff(primary_offset);
        assembler.bind(second_filter)?;
        if secondary_offset > primary_offset {
            assembler.add_imm(X10, X15, secondary_delta)?;
        } else {
            assembler.sub_imm(X10, X15, secondary_delta)?;
        }
        assembler.load_vector128(2, X10, 0)?;
        assembler.compare_equal_bytes16(2, 2, 3)?;
        assembler.and_bytes16(0, 0, 2)?;
        if let Some(verification_offset) = verification_offset {
            let verification_delta = verification_offset.abs_diff(primary_offset);
            if verification_offset > primary_offset {
                assembler.add_imm(X10, X15, verification_delta)?;
            } else {
                assembler.sub_imm(X10, X15, verification_delta)?;
            }
            assembler.load_vector128(4, X10, 0)?;
            assembler.compare_equal_bytes16(4, 4, 5)?;
            assembler.and_bytes16(0, 0, 4)?;
        }
        emit_sparse_lane_mask(assembler)?;
        assembler.compare_branch_zero(X0, true, recover)?;
        assembler.branch(advance)?;
    }

    assembler.bind(recover)?;
    assembler.mov_reg(X7, X5)?;
    assembler.bind(lane_loop)?;
    assembler.rbit(X10, X0)?;
    assembler.clz(X10, X10)?;
    assembler.lsr_imm(X10, X10, 2)?;
    assembler.add_reg(X5, X7, X10)?;
    assembler.load_byte_reg(X10, X9, X5)?;
    assembler.load_byte(X11, X8, 0)?;
    assembler.cmp_reg32(X10, X11)?;
    assembler.branch_cond(Condition::NotEqual, candidate_miss)?;
    assembler.add_reg(X15, X9, X5)?;
    if literal.len() == 16 {
        emit_literal_equality_16(assembler, X15, X8, candidate_miss)?;
    } else {
        emit_literal_equality(assembler, X15, X8, literal.len(), candidate_miss)?;
    }
    assembler.mov_reg(X13, X5)?;
    assembler.add_reg(X14, X5, X12)?;
    assembler.branch(found)?;

    assembler.bind(candidate_miss)?;
    assembler.sub_imm(X10, X0, 1)?;
    assembler.and_reg(X0, X0, X10)?;
    assembler.compare_branch_zero(X0, true, lane_loop)?;
    assembler.bind(block_resume)?;
    assembler.add_imm(X5, X7, 16)?;
    // Confirmation clobbers v0/v1. Restore every sealed filter constant before
    // re-entering the vector loop; this keeps later groups independent.
    assembler.load_byte(X11, X8, primary_offset)?;
    assembler.dup_byte16(1, X11)?;
    if let Some(secondary_offset) = secondary_offset {
        assembler.load_byte(X11, X8, secondary_offset)?;
        assembler.dup_byte16(3, X11)?;
    }
    if let Some(verification_offset) = verification_offset {
        assembler.load_byte(X11, X8, verification_offset)?;
        assembler.dup_byte16(5, X11)?;
    }
    assembler.add_reg(X15, X9, X5)?;
    if primary_offset != 0 {
        assembler.add_imm(X15, X15, primary_offset)?;
    }
    assembler.sub_imm(X7, X6, 15)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)?;

    assembler.bind(tail_setup)?;
    emit_scalar_candidates_legacy(assembler, literal, true, none, found)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the complete staged sparse-lane graph keeps survivor tests, ranked columns, lane order, and resume bounds explicit"
)]
fn emit_vector_candidate_skip_v7(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    verification_offset: Option<u16>,
    quaternary_offset: Option<u16>,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    let vector = assembler.new_label(LabelKind::Loop)?;
    let advance = assembler.new_label(LabelKind::Internal)?;
    let recover = assembler.new_label(LabelKind::SlowPath)?;
    let lane_loop = assembler.new_label(LabelKind::Loop)?;
    let candidate_miss = assembler.new_label(LabelKind::Internal)?;
    let tail_setup = assembler.new_label(LabelKind::SlowPath)?;
    let second_filter = secondary_offset
        .map(|_| assembler.new_label(LabelKind::SlowPath))
        .transpose()?;
    let third_filter = verification_offset
        .map(|_| assembler.new_label(LabelKind::SlowPath))
        .transpose()?;
    let fourth_filter = quaternary_offset
        .map(|_| assembler.new_label(LabelKind::SlowPath))
        .transpose()?;
    let filters_cover_zero = primary_offset == 0
        || secondary_offset == Some(0)
        || verification_offset == Some(0)
        || quaternary_offset == Some(0);

    assembler.load_byte(X11, X8, primary_offset)?;
    assembler.dup_byte16(1, X11)?;
    if let Some(offset) = secondary_offset {
        assembler.load_byte(X11, X8, offset)?;
        assembler.dup_byte16(3, X11)?;
    }
    if let Some(offset) = verification_offset {
        assembler.load_byte(X11, X8, offset)?;
        assembler.dup_byte16(5, X11)?;
    }
    if let Some(offset) = quaternary_offset {
        assembler.load_byte(X11, X8, offset)?;
        assembler.dup_byte16(7, X11)?;
    }
    // X14 is otherwise dead until the found return. Full confirmation uses
    // v16/v17, so this scalar mask and all four vector constants survive every
    // rejected lane and every later vector block.
    assembler.mov_imm64(X14, 0x1111_1111_1111_1111)?;
    assembler.add_reg(X15, X9, X5)?;
    if primary_offset != 0 {
        assembler.add_imm(X15, X15, primary_offset)?;
    }
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, tail_setup)?;
    assembler.sub_imm(X7, X6, 15)?;

    assembler.bind(vector)?;
    assembler.load_vector128(0, X15, 0)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    if let Some(second_filter) = second_filter {
        assembler.unsigned_max_pairwise_bytes16(2, 0, 0)?;
        assembler.move_vector_double_to64(X10, 2)?;
        assembler.compare_branch_zero(X10, true, second_filter)?;
    } else {
        emit_sparse_lane_mask_v7(assembler)?;
        assembler.compare_branch_zero(X0, true, recover)?;
    }

    assembler.bind(advance)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.add_imm(X15, X15, 16)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)?;

    if let Some(second_filter) = second_filter {
        let offset = secondary_offset.expect("second-filter label requires an offset");
        let delta = offset.abs_diff(primary_offset);
        assembler.bind(second_filter)?;
        if offset > primary_offset {
            assembler.add_imm(X10, X15, delta)?;
        } else {
            assembler.sub_imm(X10, X15, delta)?;
        }
        assembler.load_vector128(2, X10, 0)?;
        assembler.compare_equal_bytes16(2, 2, 3)?;
        assembler.and_bytes16(0, 0, 2)?;
        emit_sparse_lane_mask_v7(assembler)?;
        assembler.compare_branch_zero(X0, false, advance)?;
        if let Some(third_filter) = third_filter {
            emit_branch_if_mask_has_multiple(assembler, X0, X10, third_filter)?;
        }
        assembler.branch(recover)?;
    }

    if let Some(third_filter) = third_filter {
        let offset = verification_offset.expect("third-filter label requires an offset");
        let delta = offset.abs_diff(primary_offset);
        assembler.bind(third_filter)?;
        if offset > primary_offset {
            assembler.add_imm(X10, X15, delta)?;
        } else {
            assembler.sub_imm(X10, X15, delta)?;
        }
        assembler.load_vector128(4, X10, 0)?;
        assembler.compare_equal_bytes16(4, 4, 5)?;
        assembler.and_bytes16(0, 0, 4)?;
        emit_sparse_lane_mask_v7(assembler)?;
        assembler.compare_branch_zero(X0, false, advance)?;
        if let Some(fourth_filter) = fourth_filter {
            emit_branch_if_mask_has_multiple(assembler, X0, X10, fourth_filter)?;
        }
        assembler.branch(recover)?;
    }

    if let Some(fourth_filter) = fourth_filter {
        let offset = quaternary_offset.expect("fourth-filter label requires an offset");
        let delta = offset.abs_diff(primary_offset);
        assembler.bind(fourth_filter)?;
        if offset > primary_offset {
            assembler.add_imm(X10, X15, delta)?;
        } else {
            assembler.sub_imm(X10, X15, delta)?;
        }
        assembler.load_vector128(6, X10, 0)?;
        assembler.compare_equal_bytes16(6, 6, 7)?;
        assembler.and_bytes16(0, 0, 6)?;
        emit_sparse_lane_mask_v7(assembler)?;
        assembler.compare_branch_zero(X0, true, recover)?;
        assembler.branch(advance)?;
    }

    assembler.bind(recover)?;
    assembler.mov_reg(X7, X5)?;
    assembler.bind(lane_loop)?;
    assembler.rbit(X10, X0)?;
    assembler.clz(X10, X10)?;
    assembler.lsr_imm(X10, X10, 2)?;
    assembler.add_reg(X5, X7, X10)?;
    if !filters_cover_zero {
        assembler.load_byte_reg(X10, X9, X5)?;
        assembler.load_byte(X11, X8, 0)?;
        assembler.cmp_reg32(X10, X11)?;
        assembler.branch_cond(Condition::NotEqual, candidate_miss)?;
    }
    assembler.add_reg(X15, X9, X5)?;
    if literal.len() == 16 {
        emit_literal_equality_16_with_vectors(assembler, X15, X8, candidate_miss, 16, 17)?;
    } else {
        emit_literal_equality_with_vectors(
            assembler,
            X15,
            X8,
            literal.len(),
            candidate_miss,
            16,
            17,
            X11,
        )?;
    }
    assembler.mov_reg(X13, X5)?;
    assembler.add_reg(X14, X5, X12)?;
    assembler.branch(found)?;

    assembler.bind(candidate_miss)?;
    assembler.sub_imm(X10, X0, 1)?;
    assembler.and_reg(X0, X0, X10)?;
    assembler.compare_branch_zero(X0, true, lane_loop)?;
    assembler.add_imm(X5, X7, 16)?;
    assembler.add_reg(X15, X9, X5)?;
    if primary_offset != 0 {
        assembler.add_imm(X15, X15, primary_offset)?;
    }
    assembler.sub_imm(X7, X6, 15)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)?;

    assembler.bind(tail_setup)?;
    emit_scalar_candidates_legacy(assembler, literal, true, none, found)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the authenticated ranked offsets and differentiated backend tag are explicit inputs to the fixed-lane SVE graph"
)]
fn emit_vector_candidate_skip_sve16(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    verification_offset: Option<u16>,
    quaternary_offset: Option<u16>,
    backend_version: BackendVersion,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    let vector = assembler.new_label(LabelKind::Loop)?;
    let advance = assembler.new_label(LabelKind::Internal)?;
    let candidate_miss = assembler.new_label(LabelKind::Internal)?;
    let tail = assembler.new_label(LabelKind::SlowPath)?;
    let offsets = [
        Some(primary_offset),
        secondary_offset,
        verification_offset,
        quaternary_offset,
    ];

    // P0 is deliberately limited to sixteen byte lanes. This contract is
    // independent of the thread's physical architectural VL and does not
    // mutate any process or thread vector-length state.
    assembler.sve_ptrue_bytes_vl16(0)?;
    for (index, offset) in offsets.into_iter().enumerate() {
        let Some(offset) = offset else {
            continue;
        };
        let constant = u8::try_from(
            index
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
                .ok_or(EmitError::InternalInvariant)?,
        )
        .map_err(|_| EmitError::InternalInvariant)?;
        assembler.load_byte(X11, X8, offset)?;
        assembler.sve_duplicate_byte(constant, X11)?;
    }

    assembler.bind(vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, tail)?;
    assembler.add_reg(X15, X9, X5)?;

    for (index, offset) in offsets.into_iter().enumerate() {
        let Some(offset) = offset else {
            continue;
        };
        let loaded = u8::try_from(index.checked_mul(2).ok_or(EmitError::InternalInvariant)?)
            .map_err(|_| EmitError::InternalInvariant)?;
        let constant = loaded.checked_add(1).ok_or(EmitError::InternalInvariant)?;
        let result_predicate = if index == 0 { 1 } else { 2 };
        let base = if offset == 0 {
            X15
        } else {
            assembler.add_imm(X10, X15, offset)?;
            X10
        };
        assembler.sve_load_bytes(loaded, 0, base)?;
        if backend_version == BackendVersion::SEARCH_SVE2_16_V1 {
            assembler.sve2_match_bytes(result_predicate, 0, loaded, constant)?;
        } else {
            assembler.sve_compare_equal_bytes(result_predicate, 0, loaded, constant)?;
        }
        if index != 0 {
            assembler.sve_and_predicate_bytes(1, 0, 1, result_predicate)?;
        }
        assembler.sve_test_predicate_bytes(0, 1)?;
        assembler.branch_cond(Condition::Equal, advance)?;
    }

    // P3 contains exactly the active lanes preceding the first candidate.
    // CNTP therefore materializes that candidate's zero-based lane index
    // without assuming anything about inactive lanes above VL16.
    assembler.sve_break_before_bytes(3, 0, 1)?;
    assembler.sve_count_predicate_bytes(X10, 0, 3)?;
    assembler.add_reg(X13, X5, X10)?;
    assembler.add_reg(X15, X9, X13)?;
    emit_literal_equality_with_vectors(
        assembler,
        X15,
        X8,
        literal.len(),
        candidate_miss,
        0,
        2,
        X11,
    )?;
    assembler.add_reg(X14, X13, X12)?;
    assembler.branch(found)?;

    assembler.bind(candidate_miss)?;
    assembler.add_imm(X5, X13, 1)?;
    assembler.branch(vector)?;

    assembler.bind(advance)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.branch(vector)?;

    assembler.bind(tail)?;
    emit_scalar_candidates_legacy(assembler, literal, true, none, found)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the V9 prefix is deliberately explicit before entering the unchanged V8 graph"
)]
fn emit_vector_candidate_skip_v9(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    verification_offset: Option<u16>,
    quaternary_offset: Option<u16>,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    let first_candidate_miss = assembler.new_label(LabelKind::Internal)?;
    let selected = literal
        .get(usize::from(primary_offset))
        .copied()
        .ok_or(EmitError::InternalInvariant)?;

    // The caller has already proved that X5 is one legal candidate start.
    // Rejecting on the ranked byte avoids full equality on the common miss.
    assembler.add_reg(X15, X9, X5)?;
    assembler.load_byte(X10, X15, primary_offset)?;
    assembler.cmp_imm32(X10, u16::from(selected))?;
    assembler.branch_cond(Condition::NotEqual, first_candidate_miss)?;
    if literal.len() > 1 {
        emit_literal_equality(assembler, X15, X8, literal.len(), first_candidate_miss)?;
    }
    assembler.mov_reg(X13, X5)?;
    assembler.add_reg(X14, X5, X12)?;
    assembler.branch(found)?;

    // Advance exactly one candidate. V8's own initial X5 > X6 gate handles
    // the single-candidate window without reading beyond its checked extent.
    assembler.bind(first_candidate_miss)?;
    assembler.add_imm(X5, X5, 1)?;
    emit_vector_candidate_skip_v8(
        assembler,
        literal,
        primary_offset,
        secondary_offset,
        verification_offset,
        quaternary_offset,
        None,
        BackendVersion::SEARCH_V8,
        none,
        found,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the V10 prefix is explicit before entering its terminal-filter extension of V8"
)]
fn emit_vector_candidate_skip_v10(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    verification_offset: Option<u16>,
    quaternary_offset: Option<u16>,
    quinary_offset: Option<u16>,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    let first_candidate_miss = assembler.new_label(LabelKind::Internal)?;
    let selected = literal
        .get(usize::from(primary_offset))
        .copied()
        .ok_or(EmitError::InternalInvariant)?;

    assembler.add_reg(X15, X9, X5)?;
    assembler.load_byte(X10, X15, primary_offset)?;
    assembler.cmp_imm32(X10, u16::from(selected))?;
    assembler.branch_cond(Condition::NotEqual, first_candidate_miss)?;
    if literal.len() > 1 {
        emit_literal_equality(assembler, X15, X8, literal.len(), first_candidate_miss)?;
    }
    assembler.mov_reg(X13, X5)?;
    assembler.add_reg(X14, X5, X12)?;
    assembler.branch(found)?;

    assembler.bind(first_candidate_miss)?;
    assembler.add_imm(X5, X5, 1)?;
    emit_vector_candidate_skip_v8(
        assembler,
        literal,
        primary_offset,
        secondary_offset,
        verification_offset,
        quaternary_offset,
        quinary_offset,
        BackendVersion::SEARCH_V10,
        none,
        found,
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the versioned v8 graph keeps its paired 64-candidate screen and authenticated staged recovery explicit"
)]
fn emit_vector_candidate_skip_v8(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    verification_offset: Option<u16>,
    quaternary_offset: Option<u16>,
    quinary_offset: Option<u16>,
    backend_version: BackendVersion,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    let wide = assembler.new_label(LabelKind::Loop)?;
    let wide_advance = assembler.new_label(LabelKind::Internal)?;
    let secondary_only = secondary_offset
        .map(|_| assembler.new_label(LabelKind::Loop))
        .transpose()?;
    let secondary_only_advance = secondary_offset
        .map(|_| assembler.new_label(LabelKind::Internal))
        .transpose()?;
    let narrow_setup = assembler.new_label(LabelKind::Internal)?;
    let narrow = assembler.new_label(LabelKind::Loop)?;
    let advance = assembler.new_label(LabelKind::Internal)?;
    let recover = assembler.new_label(LabelKind::SlowPath)?;
    let lane_loop = assembler.new_label(LabelKind::Loop)?;
    let candidate_miss = assembler.new_label(LabelKind::Internal)?;
    let tail_setup = assembler.new_label(LabelKind::SlowPath)?;
    let wide_second_filter = secondary_offset
        .map(|_| assembler.new_label(LabelKind::SlowPath))
        .transpose()?;
    let second_filter = secondary_offset
        .map(|_| assembler.new_label(LabelKind::SlowPath))
        .transpose()?;
    let third_filter = verification_offset
        .map(|_| assembler.new_label(LabelKind::SlowPath))
        .transpose()?;
    let fourth_filter = quaternary_offset
        .map(|_| assembler.new_label(LabelKind::SlowPath))
        .transpose()?;
    let fifth_filter = quinary_offset
        .map(|_| assembler.new_label(LabelKind::SlowPath))
        .transpose()?;
    let filters_cover_zero = primary_offset == 0
        || secondary_offset == Some(0)
        || verification_offset == Some(0)
        || quaternary_offset == Some(0)
        || quinary_offset == Some(0);
    let sve_confirmation =
        backend_version == BackendVersion::SEARCH_SVE16_V6 && literal.len() >= 16;

    assembler.load_byte(X11, X8, primary_offset)?;
    assembler.dup_byte16(1, X11)?;
    if let Some(offset) = secondary_offset {
        assembler.load_byte(X11, X8, offset)?;
        assembler.dup_byte16(3, X11)?;
    }
    if let Some(offset) = verification_offset {
        assembler.load_byte(X11, X8, offset)?;
        assembler.dup_byte16(5, X11)?;
    }
    if let Some(offset) = quaternary_offset {
        assembler.load_byte(X11, X8, offset)?;
        assembler.dup_byte16(7, X11)?;
    }
    if let Some(offset) = quinary_offset {
        assembler.load_byte(X11, X8, offset)?;
        assembler.dup_byte16(23, X11)?;
    }
    if sve_confirmation {
        // Establish the fixed predicate and immutable literal once per call.
        // Neither the ASIMD screen nor recovery confirmation clobbers P0/Z31.
        assembler.sve_ptrue_bytes_vl16(0)?;
        assembler.sve_load_bytes(31, 0, X8)?;
    }
    if !filters_cover_zero {
        // X11 remains live across the staged screen. Candidate confirmation
        // uses X13 for its scalar needle byte so this compile-time literal
        // byte is not reloaded from rodata for every recovered lane.
        assembler.mov_imm64(X11, u64::from(literal[0]))?;
    }
    // X14 remains dead until a successful return. The narrow recovery keeps
    // the historical sparse-mask representation and v16/v17 confirmation
    // temporaries. V8's wide screen uses only caller-saved v16-v21.
    assembler.mov_imm64(X14, 0x1111_1111_1111_1111)?;
    assembler.add_reg(X15, X9, X5)?;
    if primary_offset != 0 {
        assembler.add_imm(X15, X15, primary_offset)?;
    }
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, tail_setup)?;
    assembler.cmp_imm64(X10, 63)?;
    assembler.branch_cond(Condition::CarryClear, narrow_setup)?;
    assembler.sub_imm(X7, X6, 63)?;

    // Test four primary columns before loading any secondary data. Paired Q
    // loads halve the load-instruction footprint without changing the exact
    // authenticated 64-byte range. A primary miss proves all 64 candidate
    // starts impossible. A pair hit permanently enters the unchanged 16-wide
    // staged recovery graph so pair-heavy inputs pay this wide probe only once.
    assembler.bind(wide)?;
    assembler.load_vector_pair128(0, 2, X15, 0)?;
    assembler.load_vector_pair128(4, 6, X15, 32)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    assembler.compare_equal_bytes16(2, 2, 1)?;
    assembler.compare_equal_bytes16(4, 4, 1)?;
    assembler.compare_equal_bytes16(6, 6, 1)?;
    emit_four_block_presence_v8(assembler)?;
    if let Some(wide_second_filter) = wide_second_filter {
        assembler.compare_branch_zero(X10, true, wide_second_filter)?;
    } else {
        assembler.compare_branch_zero(X10, true, narrow_setup)?;
    }

    assembler.bind(wide_advance)?;
    assembler.add_imm(X5, X5, 64)?;
    assembler.add_imm(X15, X15, 64)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, wide)?;
    assembler.branch(narrow_setup)?;

    if let Some(wide_second_filter) = wide_second_filter {
        let offset = secondary_offset.expect("wide second-filter label requires an offset");
        let delta = offset.abs_diff(primary_offset);
        assembler.bind(wide_second_filter)?;
        if offset > primary_offset {
            assembler.add_imm(X10, X15, delta)?;
        } else {
            assembler.sub_imm(X10, X15, delta)?;
        }
        assembler.load_vector_pair128(18, 19, X10, 0)?;
        assembler.load_vector_pair128(20, 21, X10, 32)?;
        assembler.compare_equal_bytes16(18, 18, 3)?;
        assembler.and_bytes16(0, 0, 18)?;
        assembler.compare_equal_bytes16(19, 19, 3)?;
        assembler.and_bytes16(2, 2, 19)?;
        assembler.compare_equal_bytes16(20, 20, 3)?;
        assembler.and_bytes16(4, 4, 20)?;
        assembler.compare_equal_bytes16(21, 21, 3)?;
        assembler.and_bytes16(6, 6, 21)?;
        emit_four_block_presence_v8(assembler)?;
        assembler.compare_branch_zero(X10, true, narrow_setup)?;
    }

    // One primary-present/pair-empty group is enough to establish that the
    // primary-only screen is the wrong discriminator for this haystack. Every
    // match still requires the sealed secondary byte, so later groups first
    // screen that column alone. A secondary hit lazily reloads the four
    // primary columns and falls back permanently only when their intersection
    // contains a real pair; a pair-empty recheck switches the next group back
    // to primary-first screening.
    if let (Some(secondary_only), Some(secondary_only_advance), Some(offset)) =
        (secondary_only, secondary_only_advance, secondary_offset)
    {
        assembler.bind(secondary_only_advance)?;
        assembler.add_imm(X5, X5, 64)?;
        assembler.add_imm(X15, X15, 64)?;
        assembler.cmp_reg64(X5, X7)?;
        assembler.branch_cond(Condition::LowerOrSame, secondary_only)?;
        assembler.branch(narrow_setup)?;

        assembler.bind(secondary_only)?;
        let delta = offset.abs_diff(primary_offset);
        if offset > primary_offset {
            assembler.add_imm(X10, X15, delta)?;
        } else {
            assembler.sub_imm(X10, X15, delta)?;
        }
        assembler.load_vector_pair128(0, 2, X10, 0)?;
        assembler.load_vector_pair128(4, 6, X10, 32)?;
        assembler.compare_equal_bytes16(0, 0, 3)?;
        assembler.compare_equal_bytes16(2, 2, 3)?;
        assembler.compare_equal_bytes16(4, 4, 3)?;
        assembler.compare_equal_bytes16(6, 6, 3)?;
        emit_four_block_presence_v8(assembler)?;
        assembler.compare_branch_zero(X10, false, secondary_only_advance)?;
        assembler.load_vector_pair128(18, 19, X15, 0)?;
        assembler.load_vector_pair128(20, 21, X15, 32)?;
        assembler.compare_equal_bytes16(18, 18, 1)?;
        assembler.and_bytes16(0, 0, 18)?;
        assembler.compare_equal_bytes16(19, 19, 1)?;
        assembler.and_bytes16(2, 2, 19)?;
        assembler.compare_equal_bytes16(20, 20, 1)?;
        assembler.and_bytes16(4, 4, 20)?;
        assembler.compare_equal_bytes16(21, 21, 1)?;
        assembler.and_bytes16(6, 6, 21)?;
        emit_four_block_presence_v8(assembler)?;
        assembler.compare_branch_zero(X10, false, wide_advance)?;
    }

    assembler.bind(narrow_setup)?;
    assembler.sub_imm(X7, X6, 15)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, narrow)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)?;

    assembler.bind(narrow)?;
    assembler.load_vector128(0, X15, 0)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    if let Some(second_filter) = second_filter {
        assembler.unsigned_max_pairwise_bytes16(2, 0, 0)?;
        assembler.move_vector_double_to64(X10, 2)?;
        assembler.compare_branch_zero(X10, true, second_filter)?;
    } else {
        emit_sparse_lane_mask_v7(assembler)?;
        assembler.compare_branch_zero(X0, true, recover)?;
    }

    assembler.bind(advance)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.add_imm(X15, X15, 16)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, narrow)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)?;

    if let Some(second_filter) = second_filter {
        let offset = secondary_offset.expect("second-filter label requires an offset");
        let delta = offset.abs_diff(primary_offset);
        assembler.bind(second_filter)?;
        if offset > primary_offset {
            assembler.add_imm(X10, X15, delta)?;
        } else {
            assembler.sub_imm(X10, X15, delta)?;
        }
        assembler.load_vector128(2, X10, 0)?;
        assembler.compare_equal_bytes16(2, 2, 3)?;
        assembler.and_bytes16(0, 0, 2)?;
        emit_sparse_lane_mask_v7(assembler)?;
        assembler.compare_branch_zero(X0, false, advance)?;
        if let Some(third_filter) = third_filter {
            emit_branch_if_mask_has_multiple(assembler, X0, X10, third_filter)?;
        }
        assembler.branch(fifth_filter.unwrap_or(recover))?;
    }

    if let Some(third_filter) = third_filter {
        let offset = verification_offset.expect("third-filter label requires an offset");
        let delta = offset.abs_diff(primary_offset);
        assembler.bind(third_filter)?;
        if offset > primary_offset {
            assembler.add_imm(X10, X15, delta)?;
        } else {
            assembler.sub_imm(X10, X15, delta)?;
        }
        assembler.load_vector128(4, X10, 0)?;
        assembler.compare_equal_bytes16(4, 4, 5)?;
        assembler.and_bytes16(0, 0, 4)?;
        emit_sparse_lane_mask_v7(assembler)?;
        assembler.compare_branch_zero(X0, false, advance)?;
        if let Some(fourth_filter) = fourth_filter {
            emit_branch_if_mask_has_multiple(assembler, X0, X10, fourth_filter)?;
        }
        assembler.branch(fifth_filter.unwrap_or(recover))?;
    }

    if let Some(fourth_filter) = fourth_filter {
        let offset = quaternary_offset.expect("fourth-filter label requires an offset");
        let delta = offset.abs_diff(primary_offset);
        assembler.bind(fourth_filter)?;
        if offset > primary_offset {
            assembler.add_imm(X10, X15, delta)?;
        } else {
            assembler.sub_imm(X10, X15, delta)?;
        }
        assembler.load_vector128(6, X10, 0)?;
        assembler.compare_equal_bytes16(6, 6, 7)?;
        assembler.and_bytes16(0, 0, 6)?;
        emit_sparse_lane_mask_v7(assembler)?;
        assembler.compare_branch_zero(X0, true, fifth_filter.unwrap_or(recover))?;
        assembler.branch(advance)?;
    }

    if let Some(fifth_filter) = fifth_filter {
        let offset = quinary_offset.expect("fifth-filter label requires an offset");
        let delta = offset.abs_diff(primary_offset);
        assembler.bind(fifth_filter)?;
        if offset > primary_offset {
            assembler.add_imm(X10, X15, delta)?;
        } else {
            assembler.sub_imm(X10, X15, delta)?;
        }
        assembler.load_vector128(22, X10, 0)?;
        assembler.compare_equal_bytes16(22, 22, 23)?;
        assembler.and_bytes16(0, 0, 22)?;
        emit_sparse_lane_mask_v7(assembler)?;
        assembler.compare_branch_zero(X0, true, recover)?;
        assembler.branch(advance)?;
    }

    assembler.bind(recover)?;
    assembler.mov_reg(X7, X5)?;
    assembler.bind(lane_loop)?;
    assembler.rbit(X10, X0)?;
    assembler.clz(X10, X10)?;
    assembler.lsr_imm(X10, X10, 2)?;
    assembler.add_reg(X5, X7, X10)?;
    if !filters_cover_zero {
        assembler.load_byte_reg(X10, X9, X5)?;
        assembler.cmp_reg32(X10, X11)?;
        assembler.branch_cond(Condition::NotEqual, candidate_miss)?;
    }
    assembler.add_reg(X15, X9, X5)?;
    if sve_confirmation {
        assembler.sve_load_bytes(16, 0, X15)?;
        assembler.sve_compare_equal_bytes(1, 0, 16, 31)?;
        assembler.sve_bit_clear_predicate_bytes_set_flags(2, 0, 0, 1)?;
        assembler.branch_cond(Condition::NotEqual, candidate_miss)?;
        if literal.len() > 16 {
            let remaining = literal
                .len()
                .checked_sub(16)
                .ok_or(EmitError::InternalInvariant)?;
            assembler.add_imm(X15, X15, 16)?;
            assembler.add_imm(X16, X8, 16)?;
            emit_literal_equality_with_vectors(
                assembler,
                X15,
                X16,
                remaining,
                candidate_miss,
                16,
                17,
                X13,
            )?;
        }
    } else if literal.len() == 16 {
        emit_literal_equality_16_with_vectors(assembler, X15, X8, candidate_miss, 16, 17)?;
    } else {
        emit_literal_equality_with_vectors(
            assembler,
            X15,
            X8,
            literal.len(),
            candidate_miss,
            16,
            17,
            X13,
        )?;
    }
    assembler.mov_reg(X13, X5)?;
    assembler.add_reg(X14, X5, X12)?;
    assembler.branch(found)?;

    assembler.bind(candidate_miss)?;
    assembler.sub_imm(X10, X0, 1)?;
    assembler.and_reg(X0, X0, X10)?;
    assembler.compare_branch_zero(X0, true, lane_loop)?;
    assembler.add_imm(X5, X7, 16)?;
    assembler.add_reg(X15, X9, X5)?;
    if primary_offset != 0 {
        assembler.add_imm(X15, X15, primary_offset)?;
    }
    assembler.sub_imm(X7, X6, 15)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, narrow)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)?;

    if backend_version == BackendVersion::SEARCH_SVE16_V6 && literal.len() == 16 {
        // Every reachable predecessor branches directly to `tail_setup`.
        // Keep the fixed-16 cold-tail address byte-identical to V8.
        assembler.mov_reg(X10, X10)?;
    }
    assembler.bind(tail_setup)?;
    emit_scalar_candidates_legacy(assembler, literal, true, none, found)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the tag21 graph keeps paired wide screening, adaptive state, five authenticated columns, and retained-predicate recovery in one reviewable unit"
)]
fn emit_vector_candidate_skip_sve2_fixed16_v2(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    verification_offset: Option<u16>,
    quaternary_offset: Option<u16>,
    quinary_offset: Option<u16>,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    if literal.len() != 16 {
        return Err(EmitError::InternalInvariant);
    }
    let offsets = [
        primary_offset,
        secondary_offset.ok_or(EmitError::InternalInvariant)?,
        verification_offset.ok_or(EmitError::InternalInvariant)?,
        quaternary_offset.ok_or(EmitError::InternalInvariant)?,
        quinary_offset.ok_or(EmitError::InternalInvariant)?,
    ];
    let filters_cover_zero = offsets.contains(&0);
    // Z8-Z15 are callee-saved. Keep every filter in the low caller-saved bank
    // or the high caller-saved bank, outside V8's z16-z21 reducer temporaries.
    let constants = [1_u8, 3, 5, 7, 22];
    let wide = assembler.new_label(LabelKind::Loop)?;
    let wide_advance = assembler.new_label(LabelKind::Internal)?;
    let secondary_only = assembler.new_label(LabelKind::Loop)?;
    let secondary_only_advance = assembler.new_label(LabelKind::Internal)?;
    let wide_second_filter = assembler.new_label(LabelKind::SlowPath)?;
    let wide_remaining_filters = assembler.new_label(LabelKind::SlowPath)?;
    let wide_next_mask = assembler.new_label(LabelKind::Loop)?;
    let wide_candidate = assembler.new_label(LabelKind::Loop)?;
    let wide_candidate_miss = assembler.new_label(LabelKind::Internal)?;
    let narrow_setup = assembler.new_label(LabelKind::Internal)?;
    let narrow = assembler.new_label(LabelKind::Loop)?;
    let advance = assembler.new_label(LabelKind::Internal)?;
    let candidate = assembler.new_label(LabelKind::Loop)?;
    let candidate_miss = assembler.new_label(LabelKind::Internal)?;
    let tail_setup = assembler.new_label(LabelKind::SlowPath)?;

    // The runtime admits this candidate only when the observed architectural
    // vector length is sixteen bytes. P0 still seals the active-lane contract
    // in the instruction stream and no vector-length state is mutated.
    assembler.sve_ptrue_bytes_vl16(0)?;
    for (&offset, &constant) in offsets.iter().zip(constants.iter()) {
        let byte = literal
            .get(usize::from(offset))
            .copied()
            .ok_or(EmitError::InternalInvariant)?;
        assembler.mov_imm64(X11, u64::from(byte))?;
        assembler.sve_duplicate_byte(constant, X11)?;
    }
    // Exact confirmation never relies on MATCH membership semantics.
    assembler.sve_load_bytes(31, 0, X8)?;
    if !filters_cover_zero {
        // Keep literal[0] live in X11 so dense false-positive streams can be
        // rejected with one scalar load before paying for SVE confirmation.
        assembler.mov_imm64(X11, u64::from(literal[0]))?;
    }

    assembler.add_reg(X15, X9, X5)?;
    if primary_offset != 0 {
        assembler.add_imm(X15, X15, primary_offset)?;
    }
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, tail_setup)?;
    assembler.cmp_imm64(X10, 63)?;
    assembler.branch_cond(Condition::CarryClear, narrow_setup)?;
    assembler.sub_imm(X7, X6, 63)?;

    // Match V8's paired-Q front end while reading exactly the same
    // authenticated 64-byte columns.
    assembler.bind(wide)?;
    assembler.load_vector_pair128(0, 2, X15, 0)?;
    assembler.load_vector_pair128(4, 6, X15, 32)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    assembler.compare_equal_bytes16(2, 2, 1)?;
    assembler.compare_equal_bytes16(4, 4, 1)?;
    assembler.compare_equal_bytes16(6, 6, 1)?;
    emit_four_block_presence_v8(assembler)?;
    assembler.compare_branch_zero(X10, true, wide_second_filter)?;

    assembler.bind(wide_advance)?;
    assembler.add_imm(X5, X5, 64)?;
    assembler.add_imm(X15, X15, 64)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, wide)?;
    assembler.branch(narrow_setup)?;

    let secondary_delta = offsets[1].abs_diff(primary_offset);
    assembler.bind(wide_second_filter)?;
    if offsets[1] > primary_offset {
        assembler.add_imm(X10, X15, secondary_delta)?;
    } else {
        assembler.sub_imm(X10, X15, secondary_delta)?;
    }
    assembler.load_vector_pair128(18, 19, X10, 0)?;
    assembler.load_vector_pair128(20, 21, X10, 32)?;
    assembler.compare_equal_bytes16(18, 18, 3)?;
    assembler.and_bytes16(0, 0, 18)?;
    assembler.compare_equal_bytes16(19, 19, 3)?;
    assembler.and_bytes16(2, 2, 19)?;
    assembler.compare_equal_bytes16(20, 20, 3)?;
    assembler.and_bytes16(4, 4, 20)?;
    assembler.compare_equal_bytes16(21, 21, 3)?;
    assembler.and_bytes16(6, 6, 21)?;
    emit_four_block_presence_v8(assembler)?;
    assembler.compare_branch_zero(X10, false, secondary_only_advance)?;
    assembler.branch(wide_remaining_filters)?;

    // Retain V8's adaptive secondary-first state for primary-dense groups
    // whose selected secondary column rejects every lane.
    assembler.bind(secondary_only_advance)?;
    assembler.add_imm(X5, X5, 64)?;
    assembler.add_imm(X15, X15, 64)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, secondary_only)?;
    assembler.branch(narrow_setup)?;

    assembler.bind(secondary_only)?;
    if offsets[1] > primary_offset {
        assembler.add_imm(X10, X15, secondary_delta)?;
    } else {
        assembler.sub_imm(X10, X15, secondary_delta)?;
    }
    assembler.load_vector_pair128(0, 2, X10, 0)?;
    assembler.load_vector_pair128(4, 6, X10, 32)?;
    assembler.compare_equal_bytes16(0, 0, 3)?;
    assembler.compare_equal_bytes16(2, 2, 3)?;
    assembler.compare_equal_bytes16(4, 4, 3)?;
    assembler.compare_equal_bytes16(6, 6, 3)?;
    emit_four_block_presence_v8(assembler)?;
    assembler.compare_branch_zero(X10, false, secondary_only_advance)?;
    assembler.load_vector_pair128(18, 19, X15, 0)?;
    assembler.load_vector_pair128(20, 21, X15, 32)?;
    assembler.compare_equal_bytes16(18, 18, 1)?;
    assembler.and_bytes16(0, 0, 18)?;
    assembler.compare_equal_bytes16(19, 19, 1)?;
    assembler.and_bytes16(2, 2, 19)?;
    assembler.compare_equal_bytes16(20, 20, 1)?;
    assembler.and_bytes16(4, 4, 20)?;
    assembler.compare_equal_bytes16(21, 21, 1)?;
    assembler.and_bytes16(6, 6, 21)?;
    emit_four_block_presence_v8(assembler)?;
    assembler.compare_branch_zero(X10, false, wide_advance)?;

    // Do not discard an authenticated 64-lane primary/secondary mask. Screen
    // the remaining three columns in place, then recover candidates from all
    // four 16-lane quarters in source order.
    assembler.bind(wide_remaining_filters)?;
    for index in 2..offsets.len() {
        let delta = offsets[index].abs_diff(primary_offset);
        if offsets[index] > primary_offset {
            assembler.add_imm(X10, X15, delta)?;
        } else {
            assembler.sub_imm(X10, X15, delta)?;
        }
        assembler.load_vector_pair128(18, 19, X10, 0)?;
        assembler.load_vector_pair128(20, 21, X10, 32)?;
        assembler.compare_equal_bytes16(18, 18, constants[index])?;
        assembler.and_bytes16(0, 0, 18)?;
        assembler.compare_equal_bytes16(19, 19, constants[index])?;
        assembler.and_bytes16(2, 2, 19)?;
        assembler.compare_equal_bytes16(20, 20, constants[index])?;
        assembler.and_bytes16(4, 4, 20)?;
        assembler.compare_equal_bytes16(21, 21, constants[index])?;
        assembler.and_bytes16(6, 6, 21)?;
        emit_four_block_presence_v8(assembler)?;
        assembler.compare_branch_zero(X10, false, wide_advance)?;
    }

    // The wide recovery keeps one sparse 16-lane mask in each of x0-x3.
    // Materialize its scalar lane selector only after every wide filter has
    // retained a survivor. X14 is otherwise dead until a successful return.
    assembler.shift_right_narrow_halfwords_to_bytes8(16, 0)?;
    assembler.move_vector_double_to64(X0, 16)?;
    assembler.mov_imm64(X14, 0x1111_1111_1111_1111)?;
    assembler.and_reg(X0, X0, X14)?;
    for (destination, source) in [(X1, 2_u8), (X2, 4), (X3, 6)] {
        assembler.shift_right_narrow_halfwords_to_bytes8(16, source)?;
        assembler.move_vector_double_to64(destination, 16)?;
        assembler.and_reg(destination, destination, X14)?;
    }
    assembler.mov_reg(X17, X5)?;
    assembler.add_imm(X16, X5, 64)?;
    assembler.bind(wide_next_mask)?;
    assembler.compare_branch_zero(X0, true, wide_candidate)?;
    assembler.add_imm(X17, X17, 16)?;
    assembler.cmp_reg64(X17, X16)?;
    assembler.branch_cond(Condition::CarrySet, wide_advance)?;
    assembler.mov_reg(X0, X1)?;
    assembler.mov_reg(X1, X2)?;
    assembler.mov_reg(X2, X3)?;
    assembler.branch(wide_next_mask)?;

    assembler.bind(wide_candidate)?;
    assembler.rbit(X10, X0)?;
    assembler.clz(X10, X10)?;
    assembler.lsr_imm(X10, X10, 2)?;
    assembler.add_reg(X13, X17, X10)?;
    if !filters_cover_zero {
        assembler.load_byte_reg(X10, X9, X13)?;
        assembler.cmp_reg32(X10, X11)?;
        assembler.branch_cond(Condition::NotEqual, wide_candidate_miss)?;
    }
    assembler.add_reg(X10, X9, X13)?;
    assembler.sve_load_bytes(30, 0, X10)?;
    assembler.sve_compare_equal_bytes(2, 0, 30, 31)?;
    assembler.sve_bit_clear_predicate_bytes_set_flags(2, 0, 0, 2)?;
    assembler.branch_cond(Condition::NotEqual, wide_candidate_miss)?;
    assembler.add_reg(X14, X13, X12)?;
    assembler.branch(found)?;

    assembler.bind(wide_candidate_miss)?;
    assembler.sub_imm(X10, X0, 1)?;
    assembler.and_reg(X0, X0, X10)?;
    assembler.compare_branch_zero(X0, true, wide_candidate)?;
    assembler.branch(wide_next_mask)?;

    assembler.bind(narrow_setup)?;
    assembler.sub_imm(X7, X6, 15)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, narrow)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)?;

    assembler.bind(narrow)?;
    assembler.sve_load_bytes(0, 0, X15)?;
    assembler.sve2_match_bytes(1, 0, 0, constants[0])?;
    assembler.sve_test_predicate_bytes(0, 1)?;
    assembler.branch_cond(Condition::Equal, advance)?;
    for index in 1..offsets.len() {
        let delta = offsets[index].abs_diff(primary_offset);
        if offsets[index] > primary_offset {
            assembler.add_imm(X10, X15, delta)?;
        } else {
            assembler.sub_imm(X10, X15, delta)?;
        }
        assembler.sve_load_bytes(0, 0, X10)?;
        assembler.sve2_match_bytes(2, 0, 0, constants[index])?;
        assembler.sve_and_predicate_bytes_set_flags(1, 0, 1, 2)?;
        assembler.branch_cond(Condition::Equal, advance)?;
        if index < offsets.len().saturating_sub(1) {
            assembler.sve_count_predicate_bytes(X10, 0, 1)?;
            assembler.cmp_imm64(X10, 1)?;
            assembler.branch_cond(Condition::LowerOrSame, candidate)?;
        }
    }
    assembler.branch(candidate)?;

    assembler.bind(candidate)?;
    assembler.sve_break_before_bytes(3, 0, 1)?;
    assembler.sve_count_predicate_bytes(X10, 0, 3)?;
    assembler.add_reg(X13, X5, X10)?;
    if !filters_cover_zero {
        assembler.load_byte_reg(X10, X9, X13)?;
        assembler.cmp_reg32(X10, X11)?;
        assembler.branch_cond(Condition::NotEqual, candidate_miss)?;
    }
    assembler.add_reg(X10, X9, X13)?;
    assembler.sve_load_bytes(30, 0, X10)?;
    assembler.sve_compare_equal_bytes(2, 0, 30, 31)?;
    assembler.sve_bit_clear_predicate_bytes_set_flags(2, 0, 0, 2)?;
    assembler.branch_cond(Condition::NotEqual, candidate_miss)?;
    assembler.add_reg(X14, X13, X12)?;
    assembler.branch(found)?;

    // Remove the rejected leftmost lane while retaining every later survivor.
    // No column is reloaded and the fifth constant remains live in z22.
    assembler.bind(candidate_miss)?;
    assembler.sve_break_after_bytes(3, 0, 1)?;
    assembler.sve_bit_clear_predicate_bytes_set_flags(1, 0, 1, 3)?;
    assembler.branch_cond(Condition::NotEqual, candidate)?;

    assembler.bind(advance)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.add_imm(X15, X15, 16)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, narrow)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)?;

    assembler.bind(tail_setup)?;
    emit_scalar_candidates_legacy(assembler, literal, true, none, found)
}

fn emit_four_block_presence_v8(assembler: &mut Assembler) -> Result<(), EmitError> {
    assembler.unsigned_max_pairwise_bytes16(16, 0, 2)?;
    assembler.unsigned_max_pairwise_bytes16(17, 4, 6)?;
    assembler.unsigned_max_pairwise_bytes16(16, 16, 17)?;
    assembler.unsigned_max_pairwise_bytes16(16, 16, 16)?;
    assembler.move_vector_double_to64(X10, 16)
}

fn emit_branch_if_mask_has_multiple(
    assembler: &mut Assembler,
    mask: u8,
    scratch: u8,
    target: Label,
) -> Result<(), EmitError> {
    assembler.sub_imm(scratch, mask, 1)?;
    assembler.and_reg(scratch, mask, scratch)?;
    assembler.compare_branch_zero(scratch, true, target)
}

fn emit_sparse_lane_mask_v7(assembler: &mut Assembler) -> Result<(), EmitError> {
    assembler.shift_right_narrow_halfwords_to_bytes8(2, 0)?;
    assembler.move_vector_double_to64(X0, 2)?;
    assembler.and_reg(X0, X0, X14)
}

fn emit_sparse_lane_mask(assembler: &mut Assembler) -> Result<(), EmitError> {
    assembler.shift_right_narrow_halfwords_to_bytes8(2, 0)?;
    assembler.move_vector_double_to64(X0, 2)?;
    assembler.mov_imm64(X11, 0x1111_1111_1111_1111)?;
    assembler.and_reg(X0, X0, X11)
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete mask-guided recovery graph keeps every bound and resume edge visible"
)]
fn emit_vector_candidate_skip_mask(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    verification_offset: Option<u16>,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    // UMAXP reduces the 16 candidate lanes into eight adjacent-lane bytes.
    // The following FMOV therefore carries a compact pair mask in X10. Keep
    // that mask and confirm only the two candidate starts represented by each
    // nonzero byte instead of rescanning all 16 starts in every hit block.
    let vector = assembler.new_label(LabelKind::Loop)?;
    let advance = assembler.new_label(LabelKind::Internal)?;
    let block_setup = assembler.new_label(LabelKind::SlowPath)?;
    let block_pairs = assembler.new_label(LabelKind::Loop)?;
    let pair_confirm = assembler.new_label(LabelKind::SlowPath)?;
    let scalar = assembler.new_label(LabelKind::Loop)?;
    let scalar_advance = assembler.new_label(LabelKind::Internal)?;
    let pair_exhausted = assembler.new_label(LabelKind::Internal)?;
    let block_resume = assembler.new_label(LabelKind::Internal)?;
    let tail_setup = assembler.new_label(LabelKind::SlowPath)?;
    let second_filter = if literal.len() > 1 {
        Some(assembler.new_label(LabelKind::SlowPath)?)
    } else {
        None
    };
    assembler.meter.charge_usize(literal.len())?;
    assembler.load_byte(X11, X8, primary_offset)?;
    assembler.dup_byte16(1, X11)?;
    if let Some(secondary_offset) = secondary_offset {
        assembler.load_byte(X11, X8, secondary_offset)?;
        assembler.dup_byte16(3, X11)?;
    }
    if let Some(verification_offset) = verification_offset {
        assembler.load_byte(X11, X8, verification_offset)?;
        assembler.dup_byte16(5, X11)?;
    }
    assembler.add_reg(X15, X9, X5)?;
    if primary_offset != 0 {
        assembler.add_imm(X15, X15, primary_offset)?;
    }
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, tail_setup)?;
    assembler.sub_imm(X7, X6, 15)?;
    assembler.bind(vector)?;
    assembler.load_vector128(0, X15, 0)?;
    assembler.compare_equal_bytes16(0, 0, 1)?;
    if let Some(second_filter) = second_filter {
        assembler.unsigned_max_pairwise_bytes16(2, 0, 0)?;
        assembler.move_vector_double_to64(X10, 2)?;
        assembler.compare_branch_zero(X10, true, second_filter)?;
    } else {
        assembler.unsigned_max_pairwise_bytes16(0, 0, 0)?;
        assembler.move_vector_double_to64(X10, 0)?;
        assembler.compare_branch_zero(X10, true, block_setup)?;
    }
    assembler.bind(advance)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.add_imm(X15, X15, 16)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)?;
    if let Some(second_filter) = second_filter {
        let secondary_offset = secondary_offset.expect("multi-byte literal has a byte pair");
        let secondary_delta = secondary_offset.abs_diff(primary_offset);
        assembler.bind(second_filter)?;
        if secondary_offset > primary_offset {
            assembler.add_imm(X10, X15, secondary_delta)?;
        } else {
            assembler.sub_imm(X10, X15, secondary_delta)?;
        }
        assembler.load_vector128(2, X10, 0)?;
        assembler.compare_equal_bytes16(2, 2, 3)?;
        assembler.and_bytes16(0, 0, 2)?;
        if let Some(verification_offset) = verification_offset {
            let verification_delta = verification_offset.abs_diff(primary_offset);
            if verification_offset > primary_offset {
                assembler.add_imm(X10, X15, verification_delta)?;
            } else {
                assembler.sub_imm(X10, X15, verification_delta)?;
            }
            assembler.load_vector128(4, X10, 0)?;
            assembler.compare_equal_bytes16(4, 4, 5)?;
            assembler.and_bytes16(0, 0, 4)?;
        }
        assembler.unsigned_max_pairwise_bytes16(0, 0, 0)?;
        assembler.move_vector_double_to64(X10, 0)?;
        assembler.compare_branch_zero(X10, true, block_setup)?;
        assembler.branch(advance)?;
    }

    assembler.bind(block_setup)?;
    assembler.mov_reg(X0, X10)?;
    assembler.add_imm(X7, X5, 15)?;
    assembler.bind(block_pairs)?;
    assembler.and_low_bits(X10, X0, 8)?;
    assembler.lsr_imm(X0, X0, 8)?;
    assembler.compare_branch_zero(X10, true, pair_confirm)?;
    assembler.add_imm(X5, X5, 2)?;
    assembler.compare_branch_zero(X0, true, block_pairs)?;
    assembler.branch(block_resume)?;

    assembler.bind(pair_confirm)?;
    assembler.add_imm(X2, X5, 1)?;
    assembler.bind(scalar)?;
    assembler.load_byte_reg(X10, X9, X5)?;
    assembler.load_byte(X11, X8, 0)?;
    assembler.cmp_reg32(X10, X11)?;
    assembler.branch_cond(Condition::NotEqual, scalar_advance)?;
    assembler.add_reg(X15, X9, X5)?;
    if literal.len() == 16 {
        emit_literal_equality_16(assembler, X15, X8, scalar_advance)?;
    } else {
        emit_literal_equality(assembler, X15, X8, literal.len(), scalar_advance)?;
    }
    assembler.mov_reg(X13, X5)?;
    assembler.add_reg(X14, X5, X12)?;
    assembler.branch(found)?;
    assembler.bind(scalar_advance)?;
    assembler.cmp_reg64(X5, X2)?;
    assembler.branch_cond(Condition::CarrySet, pair_exhausted)?;
    assembler.add_imm(X5, X5, 1)?;
    assembler.branch(scalar)?;
    assembler.bind(pair_exhausted)?;
    assembler.add_imm(X5, X5, 1)?;
    assembler.compare_branch_zero(X0, true, block_pairs)?;

    assembler.bind(block_resume)?;
    assembler.add_imm(X5, X7, 1)?;
    // Confirmation may clobber v0/v1, so restore the filter constants once
    // after every flagged pair in the block has been exhausted.
    assembler.load_byte(X11, X8, primary_offset)?;
    assembler.dup_byte16(1, X11)?;
    if let Some(secondary_offset) = secondary_offset {
        assembler.load_byte(X11, X8, secondary_offset)?;
        assembler.dup_byte16(3, X11)?;
    }
    assembler.add_reg(X15, X9, X5)?;
    if primary_offset != 0 {
        assembler.add_imm(X15, X15, primary_offset)?;
    }
    assembler.sub_imm(X7, X6, 15)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)?;

    assembler.bind(tail_setup)?;
    emit_scalar_candidates_legacy(assembler, literal, true, none, found)
}

fn candidate_byte_pair(literal: &[u8]) -> (u16, Option<u16>) {
    let Some(pair) = Pair::new(literal) else {
        return (0, None);
    };
    (u16::from(pair.index1()), Some(u16::from(pair.index2())))
}

fn candidate_verification_offset(
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
) -> Option<u16> {
    let primary_byte = *literal.get(usize::from(primary_offset))?;
    let secondary_byte = secondary_offset
        .and_then(|offset| literal.get(usize::from(offset)))
        .copied();
    literal
        .iter()
        .position(|&byte| byte != primary_byte && Some(byte) != secondary_byte)
        .map(|offset| u16::try_from(offset).expect("bounded repeated-confirmation offset fits u16"))
}

fn candidate_ranked_verification_offsets(
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
) -> (Option<u16>, Option<u16>) {
    let mut selected = [None; 2];
    for (offset, &byte) in literal.iter().enumerate() {
        let offset = u16::try_from(offset).expect("bounded repeated-confirmation offset fits u16");
        if offset == primary_offset || Some(offset) == secondary_offset {
            continue;
        }
        let key = (V7_BYTE_FREQUENCY_RANK[usize::from(byte)], offset);
        if selected[0].is_none_or(|current| {
            let current_byte = literal[usize::from(current)];
            key < (V7_BYTE_FREQUENCY_RANK[usize::from(current_byte)], current)
        }) {
            selected[1] = selected[0];
            selected[0] = Some(offset);
        } else if selected[1].is_none_or(|current| {
            let current_byte = literal[usize::from(current)];
            key < (V7_BYTE_FREQUENCY_RANK[usize::from(current_byte)], current)
        }) {
            selected[1] = Some(offset);
        }
    }
    (selected[0], selected[1])
}

fn candidate_ranked_verification_offsets_v2(
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
) -> (Option<u16>, Option<u16>, Option<u16>) {
    // Exact-16 prefix near-misses agree through byte fourteen. Reserve the
    // fifth authenticated column for byte fifteen unless the packed pair
    // already covers it; that case retains all three ranked columns.
    let terminal_offset = literal
        .len()
        .checked_sub(1)
        .and_then(|offset| u16::try_from(offset).ok());
    let force_terminal = terminal_offset
        .is_some_and(|offset| offset != primary_offset && Some(offset) != secondary_offset);
    let mut selected = [None; 3];
    for (offset, &byte) in literal.iter().enumerate() {
        let offset = u16::try_from(offset).expect("bounded repeated-confirmation offset fits u16");
        if offset == primary_offset
            || Some(offset) == secondary_offset
            || (force_terminal && Some(offset) == terminal_offset)
        {
            continue;
        }
        let key = (V7_BYTE_FREQUENCY_RANK[usize::from(byte)], offset);
        if selected[0].is_none_or(|current| {
            let current_byte = literal[usize::from(current)];
            key < (V7_BYTE_FREQUENCY_RANK[usize::from(current_byte)], current)
        }) {
            selected[2] = selected[1];
            selected[1] = selected[0];
            selected[0] = Some(offset);
        } else if selected[1].is_none_or(|current| {
            let current_byte = literal[usize::from(current)];
            key < (V7_BYTE_FREQUENCY_RANK[usize::from(current_byte)], current)
        }) {
            selected[2] = selected[1];
            selected[1] = Some(offset);
        } else if selected[2].is_none_or(|current| {
            let current_byte = literal[usize::from(current)];
            key < (V7_BYTE_FREQUENCY_RANK[usize::from(current_byte)], current)
        }) {
            selected[2] = Some(offset);
        }
    }
    (
        selected[0],
        selected[1],
        if force_terminal {
            terminal_offset
        } else {
            selected[2]
        },
    )
}

fn candidate_ranked_verification_offsets_v3(
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
) -> (Option<u16>, Option<u16>, Option<u16>) {
    // Keep the five-column schema frozen: the packed pair owns the first two
    // columns. Any endpoint absent from that pair is reserved in the remaining
    // three columns, with byte zero before the terminal byte, and all earlier
    // columns retain the frozen frequency rank. Thus no favorable ranked
    // selection can omit either endpoint.
    let head_offset = (!literal.is_empty()).then_some(0_u16);
    let terminal_offset = literal
        .len()
        .checked_sub(1)
        .and_then(|offset| u16::try_from(offset).ok());
    let force_head = head_offset
        .is_some_and(|offset| offset != primary_offset && Some(offset) != secondary_offset);
    let force_terminal = terminal_offset.is_some_and(|offset| {
        Some(offset) != head_offset && offset != primary_offset && Some(offset) != secondary_offset
    });
    let reserved = usize::from(force_head) + usize::from(force_terminal);
    let ranked_slots = 3_usize
        .checked_sub(reserved)
        .expect("at most two distinct endpoints");
    let mut ranked = [None; 3];
    for (offset, &byte) in literal.iter().enumerate() {
        let offset = u16::try_from(offset).expect("bounded repeated-confirmation offset fits u16");
        if offset == primary_offset
            || Some(offset) == secondary_offset
            || (force_head && Some(offset) == head_offset)
            || (force_terminal && Some(offset) == terminal_offset)
        {
            continue;
        }
        let key = (V7_BYTE_FREQUENCY_RANK[usize::from(byte)], offset);
        if ranked[0].is_none_or(|current| {
            let current_byte = literal[usize::from(current)];
            key < (V7_BYTE_FREQUENCY_RANK[usize::from(current_byte)], current)
        }) {
            ranked[2] = ranked[1];
            ranked[1] = ranked[0];
            ranked[0] = Some(offset);
        } else if ranked[1].is_none_or(|current| {
            let current_byte = literal[usize::from(current)];
            key < (V7_BYTE_FREQUENCY_RANK[usize::from(current_byte)], current)
        }) {
            ranked[2] = ranked[1];
            ranked[1] = Some(offset);
        } else if ranked[2].is_none_or(|current| {
            let current_byte = literal[usize::from(current)];
            key < (V7_BYTE_FREQUENCY_RANK[usize::from(current_byte)], current)
        }) {
            ranked[2] = Some(offset);
        }
    }

    let mut selected = [None; 3];
    selected[..ranked_slots].copy_from_slice(&ranked[..ranked_slots]);
    let mut next = ranked_slots;
    if force_head {
        selected[next] = head_offset;
        next += 1;
    }
    if force_terminal {
        selected[next] = terminal_offset;
    }
    (selected[0], selected[1], selected[2])
}

// Frozen memchr 2.8.3 packed-pair frequency order. V7 uses the same ranking
// after excluding the already-selected primary and secondary columns.
const V7_BYTE_FREQUENCY_RANK: [u8; 256] = [
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

#[allow(
    clippy::too_many_arguments,
    reason = "the recovery inputs keep every authenticated label and selected-byte offset explicit"
)]
fn emit_scalar_candidates(
    assembler: &mut Assembler,
    literal: &[u8],
    primary_offset: u16,
    secondary_offset: Option<u16>,
    vector: Label,
    tail_setup: Label,
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    let scan = assembler.new_label(LabelKind::Loop)?;
    let advance = assembler.new_label(LabelKind::Internal)?;
    let exhausted = assembler.new_label(LabelKind::Internal)?;
    let block_resume = assembler.new_label(LabelKind::Internal)?;
    assembler.bind(scan)?;
    assembler.load_byte_reg(X10, X9, X5)?;
    assembler.load_byte(X11, X8, 0)?;
    assembler.cmp_reg32(X10, X11)?;
    assembler.branch_cond(Condition::NotEqual, advance)?;
    assembler.add_reg(X15, X9, X5)?;
    if literal.len() == 16 {
        emit_literal_equality_16(assembler, X15, X8, advance)?;
    } else {
        emit_literal_equality(assembler, X15, X8, literal.len(), advance)?;
    }
    assembler.mov_reg(X13, X5)?;
    assembler.add_reg(X14, X5, X12)?;
    assembler.branch(found)?;
    assembler.bind(advance)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::CarrySet, exhausted)?;
    assembler.add_imm(X5, X5, 1)?;
    assembler.branch(scan)?;
    assembler.bind(exhausted)?;
    assembler.compare_branch_zero(X13, true, block_resume)?;
    assembler.branch(none)?;
    assembler.bind(block_resume)?;
    // Scalar confirmation uses v0/v1, so a false candidate can clobber the
    // duplicated primary filter. Restore both filter constants before
    // returning to the vector loop.
    assembler.load_byte(X11, X8, primary_offset)?;
    assembler.dup_byte16(1, X11)?;
    if let Some(secondary_offset) = secondary_offset {
        assembler.load_byte(X11, X8, secondary_offset)?;
        assembler.dup_byte16(3, X11)?;
    }
    assembler.add_imm(X5, X5, 1)?;
    assembler.add_reg(X15, X9, X5)?;
    if primary_offset != 0 {
        assembler.add_imm(X15, X15, primary_offset)?;
    }
    assembler.sub_imm(X7, X6, 15)?;
    assembler.cmp_reg64(X5, X7)?;
    assembler.branch_cond(Condition::LowerOrSame, vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.branch(tail_setup)
}

fn emit_literal_equality_16(
    assembler: &mut Assembler,
    hay_pointer: u8,
    needle_pointer: u8,
    mismatch: Label,
) -> Result<(), EmitError> {
    emit_literal_equality_16_with_vectors(assembler, hay_pointer, needle_pointer, mismatch, 0, 1)
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit vector temporaries let V7 retain every staged filter constant"
)]
fn emit_literal_equality_16_with_vectors(
    assembler: &mut Assembler,
    hay_pointer: u8,
    needle_pointer: u8,
    mismatch: Label,
    left_vector: u8,
    right_vector: u8,
) -> Result<(), EmitError> {
    assembler.load_vector128(left_vector, hay_pointer, 0)?;
    assembler.load_vector128(right_vector, needle_pointer, 0)?;
    assembler.compare_equal_bytes16(left_vector, left_vector, right_vector)?;
    assembler.unsigned_min_bytes16(left_vector, left_vector)?;
    assembler.move_vector_byte_to32(X10, left_vector)?;
    assembler.cmp_imm32(X10, 255)?;
    assembler.branch_cond(Condition::NotEqual, mismatch)
}

fn emit_class_suffix(
    assembler: &mut Assembler,
    _class: ByteClass,
    suffix: &[u8],
    anchors: AnchorFlags,
    found: Label,
    none: Label,
) -> Result<(), EmitError> {
    let suffix_length = u64::try_from(suffix.len()).map_err(|_| EmitError::ArithmeticOverflow {
        site: ArithmeticSite::DataOffset,
    })?;
    assembler.mov_imm64(X12, suffix_length)?;
    let extend = assembler.new_label(LabelKind::Loop)?;
    let confirm = assembler.new_label(LabelKind::Internal)?;
    let reject = assembler.new_label(LabelKind::SlowPath)?;
    let scan = if anchors.start {
        assembler.cmp_imm64(X2, 0)?;
        assembler.branch_cond(Condition::NotEqual, none)?;
        assembler.cmp_imm64(X3, 0)?;
        assembler.branch_cond(Condition::Equal, none)?;
        assembler.load_byte(X10, X9, 0)?;
        emit_class_membership(assembler, none)?;
        assembler.mov_imm64(X13, 0)?;
        assembler.mov_imm64(X14, 1)?;
        assembler.branch(extend)?;
        None
    } else {
        let scan = assembler.new_label(LabelKind::Loop)?;
        let scan_miss = assembler.new_label(LabelKind::Internal)?;
        assembler.mov_reg(X5, X2)?;
        assembler.bind(scan)?;
        assembler.cmp_reg64(X5, X3)?;
        assembler.branch_cond(Condition::CarrySet, none)?;
        assembler.load_byte_reg(X10, X9, X5)?;
        emit_class_membership(assembler, scan_miss)?;
        assembler.mov_reg(X13, X5)?;
        assembler.add_imm(X14, X5, 1)?;
        assembler.branch(extend)?;
        assembler.bind(scan_miss)?;
        assembler.add_imm(X5, X5, 1)?;
        assembler.branch(scan)?;
        Some(scan)
    };
    assembler.bind(extend)?;
    assembler.cmp_reg64(X14, X3)?;
    assembler.branch_cond(Condition::CarrySet, confirm)?;
    assembler.load_byte_reg(X10, X9, X14)?;
    emit_class_membership(assembler, confirm)?;
    assembler.add_imm(X14, X14, 1)?;
    assembler.branch(extend)?;
    assembler.bind(confirm)?;
    assembler.mov_reg(X6, X14)?;
    assembler.sub_reg(X10, X3, X14)?;
    assembler.cmp_reg64(X10, X12)?;
    assembler.branch_cond(Condition::CarryClear, reject)?;
    assembler.add_reg(X15, X9, X14)?;
    emit_literal_equality(assembler, X15, X7, suffix.len(), reject)?;
    assembler.add_reg(X14, X14, X12)?;
    if anchors.end {
        assembler.cmp_reg64(X14, X1)?;
        assembler.branch_cond(Condition::NotEqual, reject)?;
    }
    assembler.branch(found)?;
    assembler.bind(reject)?;
    if anchors.start {
        assembler.branch(none)
    } else {
        assembler.mov_reg(X5, X6)?;
        assembler.branch(scan.ok_or(EmitError::InternalInvariant)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SuffixFirstClass {
    Singleton(u8),
    Sve2Table,
}

fn suffix_first_class(
    class: ByteClass,
    backend_version: BackendVersion,
) -> Option<SuffixFirstClass> {
    singleton_byte(class)
        .map(SuffixFirstClass::Singleton)
        .or_else(|| {
            (backend_version == BackendVersion::SEARCH_SVE2_16_V1
                && sve2_fixed16_ascii_class_table(class).is_some())
            .then_some(SuffixFirstClass::Sve2Table)
        })
}

/// Emit a suffix-first search for the mechanically admitted class family
/// proved in `research/jit/bakeoff/class-suffix-theorem.md`.
#[allow(
    clippy::too_many_lines,
    reason = "keeping the complete monotonic candidate and backward-confirmation CFG together makes its range proof auditable"
)]
fn emit_suffix_first_class(
    assembler: &mut Assembler,
    class: SuffixFirstClass,
    suffix: &[u8],
    manifest: SearchManifest,
    found: Label,
    none: Label,
) -> Result<(), EmitError> {
    let anchors = manifest.anchors;
    let backend_version = manifest.backend_version;
    debug_assert!(!anchors.start);
    debug_assert!(!suffix.is_empty());
    debug_assert!(suffix.len() <= MAX_REPEATED_CONFIRM_BYTES);
    if let SuffixFirstClass::Singleton(class_byte) = class {
        debug_assert_ne!(suffix[0], class_byte);
    }

    let suffix_length = u64::try_from(suffix.len()).map_err(|_| EmitError::ArithmeticOverflow {
        site: ArithmeticSite::DataOffset,
    })?;
    let primary_offset = manifest.primary_offset;
    let secondary_offset = (manifest.secondary_offset != SEARCH_CANDIDATE_OFFSET_NONE)
        .then_some(manifest.secondary_offset);
    if primary_offset != 0
        || secondary_offset
            != (suffix.len() > 1).then(|| {
                u16::try_from(
                    suffix
                        .len()
                        .checked_sub(1)
                        .expect("non-empty singleton suffix"),
                )
                .expect("bounded class suffix offset fits u16")
            })
    {
        return Err(EmitError::InternalInvariant);
    }
    let last_offset = secondary_offset.unwrap_or(0);
    let sve = matches!(
        backend_version,
        BackendVersion::SEARCH_SVE16_V1 | BackendVersion::SEARCH_SVE2_16_V1
    );
    if class == SuffixFirstClass::Sve2Table && backend_version != BackendVersion::SEARCH_SVE2_16_V1
    {
        return Err(EmitError::InternalInvariant);
    }
    assembler.mov_imm64(X12, suffix_length)?;
    // A match needs at least one class byte followed by the complete suffix.
    assembler.sub_reg(X10, X3, X2)?;
    assembler.cmp_reg64(X10, X12)?;
    assembler.branch_cond(Condition::LowerOrSame, none)?;
    assembler.sub_reg(X6, X3, X12)?;
    assembler.add_imm(X5, X2, 1)?;

    // The fixed-lane policies retain their constants in odd-numbered Z
    // registers while full confirmation uses even-numbered V registers.
    // P0 is exactly VL16, independent of the thread's physical SVE length.
    if sve {
        assembler.sve_ptrue_bytes_vl16(0)?;
        assembler.load_byte(X11, X7, 0)?;
        assembler.sve_duplicate_byte(1, X11)?;
        if suffix.len() > 1 {
            assembler.load_byte(X11, X7, last_offset)?;
            assembler.sve_duplicate_byte(3, X11)?;
        }
        match class {
            SuffixFirstClass::Singleton(class_byte) => {
                assembler.mov_imm64(X11, u64::from(class_byte))?;
                assembler.sve_duplicate_byte(5, X11)?;
            }
            SuffixFirstClass::Sve2Table => assembler.sve_load_bytes(5, 0, X16)?,
        }
    } else {
        let SuffixFirstClass::Singleton(class_byte) = class else {
            return Err(EmitError::InternalInvariant);
        };
        // v4/v5 retain the suffix pair across full confirmation in v0/v1.
        // v6 retains the class byte for the backward vector scan.
        assembler.load_byte(X11, X7, 0)?;
        assembler.dup_byte16(4, X11)?;
        if suffix.len() > 1 {
            assembler.load_byte(X11, X7, last_offset)?;
            assembler.dup_byte16(5, X11)?;
        }
        assembler.mov_imm64(X11, u64::from(class_byte))?;
        assembler.dup_byte16(6, X11)?;
    }

    let vector = assembler.new_label(LabelKind::Loop)?;
    let advance_vector = assembler.new_label(LabelKind::Internal)?;
    let second_filter = if suffix.len() > 1 {
        Some(assembler.new_label(LabelKind::SlowPath)?)
    } else {
        None
    };
    let block_scalar = assembler.new_label(LabelKind::SlowPath)?;
    let tail_scalar = assembler.new_label(LabelKind::SlowPath)?;
    let scalar_scan = assembler.new_label(LabelKind::Loop)?;
    let candidate_reject = assembler.new_label(LabelKind::Internal)?;
    let backward_vector = assembler.new_label(LabelKind::Loop)?;
    let backward_scalar = assembler.new_label(LabelKind::SlowPath)?;
    let backward_done = assembler.new_label(LabelKind::Internal)?;

    assembler.bind(vector)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::Higher, none)?;
    assembler.sub_reg(X10, X6, X5)?;
    assembler.cmp_imm64(X10, 15)?;
    assembler.branch_cond(Condition::CarryClear, tail_scalar)?;
    assembler.add_reg(X15, X9, X5)?;
    if sve {
        assembler.sve_load_bytes(0, 0, X15)?;
        if backend_version == BackendVersion::SEARCH_SVE2_16_V1 {
            assembler.sve2_match_bytes(1, 0, 0, 1)?;
        } else {
            assembler.sve_compare_equal_bytes(1, 0, 0, 1)?;
        }
        assembler.sve_test_predicate_bytes(0, 1)?;
        assembler.branch_cond(Condition::NotEqual, second_filter.unwrap_or(block_scalar))?;
    } else {
        assembler.load_vector128(2, X15, 0)?;
        assembler.compare_equal_bytes16(2, 2, 4)?;
        if let Some(second_filter) = second_filter {
            // Reduce into v7 so the first-byte lane mask in v2 remains
            // available for exact lane-wise intersection on the uncommon
            // path.
            assembler.unsigned_max_bytes16(7, 2)?;
            assembler.move_vector_byte_to32(X10, 7)?;
            assembler.compare_branch_zero(X10, true, second_filter)?;
        } else {
            assembler.unsigned_max_bytes16(2, 2)?;
            assembler.move_vector_byte_to32(X10, 2)?;
            assembler.compare_branch_zero(X10, true, block_scalar)?;
        }
    }
    assembler.bind(advance_vector)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.branch(vector)?;

    if let Some(second_filter) = second_filter {
        assembler.bind(second_filter)?;
        assembler.add_imm(X10, X15, last_offset)?;
        if sve {
            assembler.sve_load_bytes(2, 0, X10)?;
            if backend_version == BackendVersion::SEARCH_SVE2_16_V1 {
                assembler.sve2_match_bytes(2, 0, 2, 3)?;
            } else {
                assembler.sve_compare_equal_bytes(2, 0, 2, 3)?;
            }
            assembler.sve_and_predicate_bytes(1, 0, 1, 2)?;
            assembler.sve_test_predicate_bytes(0, 1)?;
            assembler.branch_cond(Condition::NotEqual, block_scalar)?;
        } else {
            assembler.load_vector128(3, X10, 0)?;
            assembler.compare_equal_bytes16(3, 3, 5)?;
            assembler.and_bytes16(2, 2, 3)?;
            assembler.unsigned_max_bytes16(2, 2)?;
            assembler.move_vector_byte_to32(X10, 2)?;
            assembler.compare_branch_zero(X10, true, block_scalar)?;
        }
        assembler.branch(advance_vector)?;
    }

    // A pair hit scans only this proved-in-range group of 16 starts before
    // returning to the vector loop. The final tail uses last_start + 1.
    assembler.bind(block_scalar)?;
    assembler.add_imm(X0, X5, 16)?;
    assembler.branch(scalar_scan)?;
    assembler.bind(tail_scalar)?;
    assembler.add_imm(X0, X6, 1)?;
    assembler.branch(scalar_scan)?;

    assembler.bind(scalar_scan)?;
    assembler.cmp_reg64(X5, X0)?;
    assembler.branch_cond(Condition::Equal, vector)?;
    assembler.add_reg(X15, X9, X5)?;
    assembler.load_byte(X10, X15, 0)?;
    assembler.load_byte(X11, X7, 0)?;
    assembler.cmp_reg32(X10, X11)?;
    assembler.branch_cond(Condition::NotEqual, candidate_reject)?;
    if suffix.len() > 1 {
        assembler.load_byte(X10, X15, last_offset)?;
        assembler.load_byte(X11, X7, last_offset)?;
        assembler.cmp_reg32(X10, X11)?;
        assembler.branch_cond(Condition::NotEqual, candidate_reject)?;
    }
    if sve {
        emit_literal_equality_with_vectors(
            assembler,
            X15,
            X7,
            suffix.len(),
            candidate_reject,
            0,
            2,
            X11,
        )?;
    } else {
        emit_literal_equality(assembler, X15, X7, suffix.len(), candidate_reject)?;
    }
    assembler.add_reg(X14, X5, X12)?;
    if anchors.end {
        assembler.cmp_reg64(X14, X1)?;
        assembler.branch_cond(Condition::NotEqual, candidate_reject)?;
    }
    // X5 starts at window_start + 1, so this predecessor is in-range.
    assembler.sub_imm(X10, X5, 1)?;
    match class {
        SuffixFirstClass::Singleton(class_byte) => {
            assembler.load_byte_reg(X15, X9, X10)?;
            assembler.mov_imm64(X11, u64::from(class_byte))?;
            assembler.cmp_reg32(X15, X11)?;
            assembler.branch_cond(Condition::NotEqual, candidate_reject)?;
        }
        SuffixFirstClass::Sve2Table => {
            assembler.load_byte_reg(X10, X9, X10)?;
            emit_class_membership(assembler, candidate_reject)?;
        }
    }

    // Scan the maximal admitted-class run backward. Every vector load covers
    // [X13-16, X13), admitted only when at least 16 window bytes remain.
    assembler.mov_reg(X13, X5)?;
    assembler.bind(backward_vector)?;
    assembler.sub_reg(X10, X13, X2)?;
    assembler.cmp_imm64(X10, 16)?;
    assembler.branch_cond(Condition::CarryClear, backward_scalar)?;
    assembler.add_reg(X15, X9, X13)?;
    assembler.sub_imm(X15, X15, 16)?;
    if sve {
        assembler.sve_load_bytes(4, 0, X15)?;
        if backend_version == BackendVersion::SEARCH_SVE2_16_V1 {
            assembler.sve2_match_bytes(1, 0, 4, 5)?;
        } else {
            assembler.sve_compare_equal_bytes(1, 0, 4, 5)?;
        }
        assembler.sve_count_predicate_bytes(X10, 0, 1)?;
        assembler.cmp_imm64(X10, 16)?;
    } else {
        assembler.load_vector128(2, X15, 0)?;
        assembler.compare_equal_bytes16(2, 2, 6)?;
        assembler.unsigned_min_bytes16(2, 2)?;
        assembler.move_vector_byte_to32(X10, 2)?;
        assembler.cmp_imm32(X10, 255)?;
    }
    assembler.branch_cond(Condition::NotEqual, backward_scalar)?;
    assembler.sub_imm(X13, X13, 16)?;
    assembler.branch(backward_vector)?;

    assembler.bind(backward_scalar)?;
    assembler.cmp_reg64(X13, X2)?;
    assembler.branch_cond(Condition::Equal, backward_done)?;
    match class {
        SuffixFirstClass::Singleton(_) => {
            assembler.sub_imm(X10, X13, 1)?;
            assembler.load_byte_reg(X15, X9, X10)?;
            assembler.cmp_reg32(X15, X11)?;
            assembler.branch_cond(Condition::NotEqual, backward_done)?;
            assembler.mov_reg(X13, X10)?;
        }
        SuffixFirstClass::Sve2Table => {
            assembler.sub_imm(X6, X13, 1)?;
            assembler.load_byte_reg(X10, X9, X6)?;
            emit_class_membership(assembler, backward_done)?;
            assembler.mov_reg(X13, X6)?;
        }
    }
    assembler.branch(backward_scalar)?;
    assembler.bind(backward_done)?;
    assembler.branch(found)?;

    assembler.bind(candidate_reject)?;
    assembler.add_imm(X5, X5, 1)?;
    assembler.branch(scalar_scan)
}

pub(crate) fn singleton_byte(class: ByteClass) -> Option<u8> {
    let lanes = class.lanes();
    if lanes
        .iter()
        .try_fold(0_u32, |total, lane| total.checked_add(lane.count_ones()))?
        != 1
    {
        return None;
    }
    for (word_index, word) in lanes.into_iter().enumerate() {
        if word == 0 {
            continue;
        }
        let base = word_index.checked_mul(64)?;
        let bit = usize::try_from(word.trailing_zeros()).ok()?;
        return u8::try_from(base.checked_add(bit)?).ok();
    }
    None
}

fn sve2_fixed16_ascii_class_table(class: ByteClass) -> Option<[u8; SVE2_CLASS_TABLE_BYTES]> {
    let lanes = class.lanes();
    if lanes[2] != 0 || lanes[3] != 0 {
        return None;
    }
    let member_count = lanes[..2].iter().try_fold(0_usize, |total, lane| {
        total.checked_add(usize::try_from(lane.count_ones()).ok()?)
    })?;
    if !(2..=SVE2_CLASS_TABLE_BYTES).contains(&member_count) {
        return None;
    }
    let mut members = [0_u8; SVE2_CLASS_TABLE_BYTES];
    let mut member_index = 0_usize;
    for (word_index, mut word) in lanes[..2].iter().copied().enumerate() {
        while word != 0 {
            let bit = usize::try_from(word.trailing_zeros()).ok()?;
            members[member_index] =
                u8::try_from(word_index.checked_mul(64)?.checked_add(bit)?).ok()?;
            member_index = member_index.checked_add(1)?;
            word &= word.checked_sub(1)?;
        }
    }
    debug_assert_eq!(member_index, member_count);
    // MATCH compares against every byte in its 128-bit segment. Repeat the
    // ascending canonical members so no padding byte becomes a false member.
    let mut table = [0_u8; SVE2_CLASS_TABLE_BYTES];
    for (byte, member) in table
        .iter_mut()
        .zip(members[..member_count].iter().copied().cycle())
    {
        *byte = member;
    }
    Some(table)
}

fn emit_class_membership(assembler: &mut Assembler, not_member: Label) -> Result<(), EmitError> {
    assembler.lsr_imm(X11, X10, 6)?;
    assembler.and_low_bits(X17, X10, 6)?;
    assembler.load64_reg_scaled(X15, X8, X11)?;
    assembler.lsrv(X15, X15, X17)?;
    assembler.and_low_bits(X15, X15, 1)?;
    assembler.compare_branch_zero(X15, false, not_member)
}

fn emit_literal_equality(
    assembler: &mut Assembler,
    hay_pointer: u8,
    needle_pointer: u8,
    length: usize,
    mismatch: Label,
) -> Result<(), EmitError> {
    emit_literal_equality_with_vectors(
        assembler,
        hay_pointer,
        needle_pointer,
        length,
        mismatch,
        0,
        1,
        X11,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit vector and scalar temporaries make enclosing filter liveness auditable"
)]
fn emit_literal_equality_with_vectors(
    assembler: &mut Assembler,
    hay_pointer: u8,
    needle_pointer: u8,
    length: usize,
    mismatch: Label,
    left_vector: u8,
    right_vector: u8,
    scalar_needle_byte: u8,
) -> Result<(), EmitError> {
    let scalar = assembler.new_label(LabelKind::Internal)?;
    let scalar_loop = assembler.new_label(LabelKind::Loop)?;
    let equal = assembler.new_label(LabelKind::Internal)?;
    assembler.mov_reg(X15, hay_pointer)?;
    assembler.mov_reg(X16, needle_pointer)?;
    assembler.mov_imm64(
        X17,
        u64::try_from(length).map_err(|_| EmitError::ArithmeticOverflow {
            site: ArithmeticSite::DataOffset,
        })?,
    )?;
    if length >= 16 {
        let vector_loop = assembler.new_label(LabelKind::Loop)?;
        assembler.bind(vector_loop)?;
        assembler.cmp_imm64(X17, 16)?;
        assembler.branch_cond(Condition::CarryClear, scalar)?;
        assembler.load_vector128(left_vector, X15, 0)?;
        assembler.load_vector128(right_vector, X16, 0)?;
        assembler.compare_equal_bytes16(left_vector, left_vector, right_vector)?;
        assembler.unsigned_min_bytes16(left_vector, left_vector)?;
        assembler.move_vector_byte_to32(X10, left_vector)?;
        assembler.cmp_imm32(X10, 255)?;
        assembler.branch_cond(Condition::NotEqual, mismatch)?;
        assembler.add_imm(X15, X15, 16)?;
        assembler.add_imm(X16, X16, 16)?;
        assembler.sub_imm(X17, X17, 16)?;
        assembler.branch(vector_loop)?;
    } else {
        assembler.branch(scalar)?;
    }
    assembler.bind(scalar)?;
    assembler.compare_branch_zero(X17, false, equal)?;
    assembler.bind(scalar_loop)?;
    assembler.load_byte(X10, X15, 0)?;
    assembler.load_byte(scalar_needle_byte, X16, 0)?;
    assembler.cmp_reg32(X10, scalar_needle_byte)?;
    assembler.branch_cond(Condition::NotEqual, mismatch)?;
    assembler.add_imm(X15, X15, 1)?;
    assembler.add_imm(X16, X16, 1)?;
    assembler.sub_imm(X17, X17, 1)?;
    assembler.compare_branch_zero(X17, true, scalar_loop)?;
    assembler.bind(equal)
}

fn emit_returns(
    assembler: &mut Assembler,
    output: OutputKind,
    found: Label,
    none: Label,
) -> Result<(), EmitError> {
    assembler.bind(found)?;
    match output {
        OutputKind::Exists => {}
        OutputKind::SelectedEnd => assembler.store64(X14, X4, 8)?,
        OutputKind::Span => {
            assembler.store64(X13, X4, 0)?;
            assembler.store64(X14, X4, 8)?;
        }
    }
    assembler.mov_imm64(X0, 1)?;
    assembler.ret()?;
    assembler.bind(none)?;
    assembler.mov_imm64(X0, 0)?;
    assembler.ret()
}

fn emit_selected_end_register_returns_v2(
    assembler: &mut Assembler,
    found: Label,
    none: Label,
) -> Result<(), EmitError> {
    assembler.bind(found)?;
    assembler.mov_reg(X0, X14)?;
    assembler.ret()?;
    assembler.bind(none)?;
    assembler.mov_imm64(X0, 0)?;
    assembler.ret()
}

#[derive(Clone, Copy)]
struct Capacities {
    code: usize,
    labels: usize,
    relocations: usize,
}

fn scratch_bytes(capacities: Capacities) -> Result<u64, EmitError> {
    let labels = capacities
        .labels
        .checked_mul(core::mem::size_of::<LabelRecord>())
        .ok_or(EmitError::ArithmeticOverflow {
            site: ArithmeticSite::ScratchBytes,
        })?;
    let fixups = capacities
        .relocations
        .checked_mul(core::mem::size_of::<Fixup>())
        .ok_or(EmitError::ArithmeticOverflow {
            site: ArithmeticSite::ScratchBytes,
        })?;
    let total = labels
        .checked_add(fixups)
        .ok_or(EmitError::ArithmeticOverflow {
            site: ArithmeticSite::ScratchBytes,
        })?;
    u64::try_from(total).map_err(|_| EmitError::ArithmeticOverflow {
        site: ArithmeticSite::ScratchBytes,
    })
}

struct Rodata {
    bytes: Box<[u8]>,
    symbols: Box<[DataSymbol]>,
}

impl Rodata {
    fn symbol_offset(&self, id: u32) -> Result<u32, EmitError> {
        self.symbols
            .iter()
            .find(|symbol| symbol.ir_data_id == id)
            .map(|symbol| symbol.offset)
            .ok_or(EmitError::Unsupported {
                reason: UnsupportedReason::DataLayout,
            })
    }
}

fn build_literal_rodata(
    literal: &[u8],
    max_bytes: u64,
    meter: &mut WorkMeter,
) -> Result<Rodata, EmitError> {
    enforce(ResourceKind::DataBytes, literal.len(), max_bytes)?;
    meter.charge_usize(literal.len())?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(literal.len())
        .map_err(|_| EmitError::AllocationFailed {
            resource: ResourceKind::DataBytes,
        })?;
    bytes.extend_from_slice(literal);
    let symbol = DataSymbol {
        ir_data_id: 0,
        offset: 0,
        length: to_u32(literal.len(), ArithmeticSite::DataOffset)?,
        alignment: u8::try_from(DATA_ALIGNMENT).expect("small constant"),
        kind: DataSymbolKind::Bytes,
    };
    Ok(Rodata {
        bytes: bytes.into_boxed_slice(),
        symbols: Box::new([symbol]),
    })
}

fn build_rodata(
    blobs: &[DataBlob],
    sve2_class_table: Option<[u8; SVE2_CLASS_TABLE_BYTES]>,
    max_bytes: u64,
    meter: &mut WorkMeter,
) -> Result<Rodata, EmitError> {
    let mut required = 0_usize;
    for blob in blobs {
        required = align_up(required, DATA_ALIGNMENT, ArithmeticSite::DataOffset)?;
        required =
            required
                .checked_add(blob_length(blob))
                .ok_or(EmitError::ArithmeticOverflow {
                    site: ArithmeticSite::DataOffset,
                })?;
    }
    if sve2_class_table.is_some() {
        required = align_up(required, DATA_ALIGNMENT, ArithmeticSite::DataOffset)?;
        required =
            required
                .checked_add(SVE2_CLASS_TABLE_BYTES)
                .ok_or(EmitError::ArithmeticOverflow {
                    site: ArithmeticSite::DataOffset,
                })?;
    }
    enforce(ResourceKind::DataBytes, required, max_bytes)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(required)
        .map_err(|_| EmitError::AllocationFailed {
            resource: ResourceKind::DataBytes,
        })?;
    let mut symbols = Vec::new();
    let symbol_count = blobs
        .len()
        .checked_add(usize::from(sve2_class_table.is_some()))
        .ok_or(EmitError::ArithmeticOverflow {
            site: ArithmeticSite::DataOffset,
        })?;
    symbols
        .try_reserve_exact(symbol_count)
        .map_err(|_| EmitError::AllocationFailed {
            resource: ResourceKind::DataBytes,
        })?;
    for (index, blob) in blobs.iter().enumerate() {
        while bytes.len() % DATA_ALIGNMENT != 0 {
            meter.charge(1)?;
            bytes.push(0);
        }
        let offset = to_u32(bytes.len(), ArithmeticSite::DataOffset)?;
        let (length, kind) = match blob {
            DataBlob::Bytes(value) => {
                meter.charge_usize(value.len())?;
                bytes.extend_from_slice(value);
                (value.len(), DataSymbolKind::Bytes)
            }
            DataBlob::ByteClass(class) => {
                meter.charge(32)?;
                for lane in class.lanes() {
                    bytes.extend_from_slice(&lane.to_le_bytes());
                }
                (32, DataSymbolKind::ByteClass)
            }
        };
        symbols.push(DataSymbol {
            ir_data_id: to_u32(index, ArithmeticSite::DataOffset)?,
            offset,
            length: to_u32(length, ArithmeticSite::DataOffset)?,
            alignment: u8::try_from(DATA_ALIGNMENT).expect("small constant"),
            kind,
        });
    }
    if let Some(table) = sve2_class_table {
        while bytes.len() % DATA_ALIGNMENT != 0 {
            meter.charge(1)?;
            bytes.push(0);
        }
        let offset = to_u32(bytes.len(), ArithmeticSite::DataOffset)?;
        meter.charge(u64::try_from(SVE2_CLASS_TABLE_BYTES).expect("small constant"))?;
        bytes.extend_from_slice(&table);
        symbols.push(DataSymbol {
            ir_data_id: SVE2_CLASS_TABLE_DATA_ID,
            offset,
            length: u32::try_from(SVE2_CLASS_TABLE_BYTES).expect("small constant"),
            alignment: u8::try_from(DATA_ALIGNMENT).expect("small constant"),
            kind: DataSymbolKind::Bytes,
        });
    }
    debug_assert_eq!(bytes.len(), required);
    Ok(Rodata {
        bytes: bytes.into_boxed_slice(),
        symbols: symbols.into_boxed_slice(),
    })
}

const fn blob_length(blob: &DataBlob) -> usize {
    match blob {
        DataBlob::Bytes(bytes) => bytes.len(),
        DataBlob::ByteClass(_) => 32,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Label(u32);

#[derive(Clone, Copy)]
struct LabelRecord {
    offset: Option<u32>,
    kind: LabelKind,
}

#[derive(Clone, Copy)]
enum FixupTarget {
    Label(Label),
    Rodata(u32),
}

#[derive(Clone, Copy)]
struct Fixup {
    at: u32,
    kind: RelocationKind,
    target: FixupTarget,
}

struct Assembler {
    code: Vec<u8>,
    labels: Vec<LabelRecord>,
    fixups: Vec<Fixup>,
    limits: EmitLimits,
    meter: WorkMeter,
    vector_instructions: u32,
}

impl Assembler {
    fn new(
        limits: EmitLimits,
        capacities: Capacities,
        meter: WorkMeter,
    ) -> Result<Self, EmitError> {
        let code_reserve = capacities.code.min(to_usize_limit(limits.max_code_bytes));
        let label_reserve = capacities.labels.min(to_usize_limit(limits.max_labels));
        let relocation_reserve = capacities
            .relocations
            .min(to_usize_limit(limits.max_relocations));
        let mut code = Vec::new();
        code.try_reserve_exact(code_reserve)
            .map_err(|_| EmitError::AllocationFailed {
                resource: ResourceKind::CodeBytes,
            })?;
        let mut labels = Vec::new();
        labels
            .try_reserve_exact(label_reserve)
            .map_err(|_| EmitError::AllocationFailed {
                resource: ResourceKind::Labels,
            })?;
        let mut fixups = Vec::new();
        fixups
            .try_reserve_exact(relocation_reserve)
            .map_err(|_| EmitError::AllocationFailed {
                resource: ResourceKind::Relocations,
            })?;
        Ok(Self {
            code,
            labels,
            fixups,
            limits,
            meter,
            vector_instructions: 0,
        })
    }

    fn new_label(&mut self, kind: LabelKind) -> Result<Label, EmitError> {
        let required = self
            .labels
            .len()
            .checked_add(1)
            .ok_or(EmitError::ArithmeticOverflow {
                site: ArithmeticSite::CodeOffset,
            })?;
        enforce(ResourceKind::Labels, required, self.limits.max_labels)?;
        self.meter.charge(1)?;
        let id = to_u32(self.labels.len(), ArithmeticSite::CodeOffset)?;
        self.labels.push(LabelRecord { offset: None, kind });
        Ok(Label(id))
    }

    fn bind(&mut self, label: Label) -> Result<(), EmitError> {
        self.meter.charge(1)?;
        let offset = to_u32(self.code.len(), ArithmeticSite::CodeOffset)?;
        let index = to_usize(label.0)?;
        let record = self
            .labels
            .get_mut(index)
            .ok_or(EmitError::InternalInvariant)?;
        if record.offset.replace(offset).is_some() {
            return Err(EmitError::InternalInvariant);
        }
        Ok(())
    }

    fn emit_word(&mut self, word: u32, vector: bool) -> Result<(), EmitError> {
        let required = self
            .code
            .len()
            .checked_add(4)
            .ok_or(EmitError::ArithmeticOverflow {
                site: ArithmeticSite::CodeOffset,
            })?;
        enforce(
            ResourceKind::CodeBytes,
            required,
            self.limits.max_code_bytes,
        )?;
        self.meter.charge(1)?;
        self.code.extend_from_slice(&word.to_le_bytes());
        if vector {
            self.vector_instructions =
                self.vector_instructions
                    .checked_add(1)
                    .ok_or(EmitError::ArithmeticOverflow {
                        site: ArithmeticSite::CodeOffset,
                    })?;
        }
        Ok(())
    }

    fn add_fixup(
        &mut self,
        kind: RelocationKind,
        target: FixupTarget,
        placeholder: u32,
    ) -> Result<(), EmitError> {
        let required = self
            .fixups
            .len()
            .checked_add(1)
            .ok_or(EmitError::ArithmeticOverflow {
                site: ArithmeticSite::CodeOffset,
            })?;
        enforce(
            ResourceKind::Relocations,
            required,
            self.limits.max_relocations,
        )?;
        let at = to_u32(self.code.len(), ArithmeticSite::CodeOffset)?;
        self.emit_word(placeholder, false)?;
        self.fixups.push(Fixup { at, kind, target });
        Ok(())
    }

    fn mov_reg(&mut self, destination: u8, source: u8) -> Result<(), EmitError> {
        self.emit_word(
            0xaa00_03e0 | reg_field(source, 16) | reg_field(destination, 0),
            false,
        )
    }

    fn mov_imm64(&mut self, destination: u8, value: u64) -> Result<(), EmitError> {
        let mut emitted = false;
        for halfword in 0_u8..4 {
            let shift = u32::from(halfword) * 16;
            let immediate = u16::try_from((value >> shift) & 0xffff).expect("masked to u16");
            if immediate != 0 || !emitted {
                let base = if emitted { 0xf280_0000 } else { 0xd280_0000 };
                self.emit_word(
                    base | (u32::from(halfword) << 21)
                        | (u32::from(immediate) << 5)
                        | u32::from(destination),
                    false,
                )?;
                emitted = true;
            }
        }
        Ok(())
    }

    fn cmp_reg64(&mut self, left: u8, right: u8) -> Result<(), EmitError> {
        self.emit_word(
            0xeb00_001f | reg_field(right, 16) | reg_field(left, 5),
            false,
        )
    }

    fn cmp_reg32(&mut self, left: u8, right: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x6b00_001f | reg_field(right, 16) | reg_field(left, 5),
            false,
        )
    }

    fn cmp_imm64(&mut self, register: u8, immediate: u16) -> Result<(), EmitError> {
        debug_assert!(immediate <= 0xfff);
        self.emit_word(
            0xf100_001f | (u32::from(immediate) << 10) | reg_field(register, 5),
            false,
        )
    }

    fn cmp_imm32(&mut self, register: u8, immediate: u16) -> Result<(), EmitError> {
        debug_assert!(immediate <= 0xfff);
        self.emit_word(
            0x7100_001f | (u32::from(immediate) << 10) | reg_field(register, 5),
            false,
        )
    }

    fn add_reg(&mut self, destination: u8, left: u8, right: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x8b00_0000 | reg_field(right, 16) | reg_field(left, 5) | u32::from(destination),
            false,
        )
    }

    fn sub_reg(&mut self, destination: u8, left: u8, right: u8) -> Result<(), EmitError> {
        self.emit_word(
            0xcb00_0000 | reg_field(right, 16) | reg_field(left, 5) | u32::from(destination),
            false,
        )
    }

    fn add_imm(&mut self, destination: u8, source: u8, immediate: u16) -> Result<(), EmitError> {
        debug_assert!(immediate <= 0xfff);
        self.emit_word(
            0x9100_0000
                | (u32::from(immediate) << 10)
                | reg_field(source, 5)
                | u32::from(destination),
            false,
        )
    }

    fn sub_imm(&mut self, destination: u8, source: u8, immediate: u16) -> Result<(), EmitError> {
        debug_assert!(immediate <= 0xfff);
        self.emit_word(
            0xd100_0000
                | (u32::from(immediate) << 10)
                | reg_field(source, 5)
                | u32::from(destination),
            false,
        )
    }

    fn and_reg(&mut self, destination: u8, left: u8, right: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x8a00_0000 | reg_field(right, 16) | reg_field(left, 5) | u32::from(destination),
            false,
        )
    }

    fn and_low_bits(&mut self, destination: u8, source: u8, bits: u8) -> Result<(), EmitError> {
        debug_assert!((1..=63).contains(&bits));
        let immediate_mask = u32::from(bits.checked_sub(1).expect("bits are nonzero")) << 10;
        self.emit_word(
            0x9240_0000 | immediate_mask | reg_field(source, 5) | u32::from(destination),
            false,
        )
    }

    fn lsr_imm(&mut self, destination: u8, source: u8, shift: u8) -> Result<(), EmitError> {
        self.emit_word(
            0xd340_0000
                | (u32::from(shift) << 16)
                | (63 << 10)
                | reg_field(source, 5)
                | u32::from(destination),
            false,
        )
    }

    fn lsrv(&mut self, destination: u8, source: u8, shift: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x9ac0_2400 | reg_field(shift, 16) | reg_field(source, 5) | u32::from(destination),
            false,
        )
    }

    fn load_byte(&mut self, destination: u8, base: u8, offset: u16) -> Result<(), EmitError> {
        debug_assert!(offset <= 0xfff);
        self.emit_word(
            0x3940_0000 | (u32::from(offset) << 10) | reg_field(base, 5) | u32::from(destination),
            false,
        )
    }

    fn load_byte_reg(&mut self, destination: u8, base: u8, index: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x3860_6800 | reg_field(index, 16) | reg_field(base, 5) | u32::from(destination),
            false,
        )
    }

    fn load64_reg_scaled(&mut self, destination: u8, base: u8, index: u8) -> Result<(), EmitError> {
        self.emit_word(
            0xf860_7800 | reg_field(index, 16) | reg_field(base, 5) | u32::from(destination),
            false,
        )
    }

    fn store64(&mut self, source: u8, base: u8, offset: u16) -> Result<(), EmitError> {
        debug_assert!(offset.is_multiple_of(8) && offset / 8 <= 0xfff);
        self.emit_word(
            0xf900_0000 | (u32::from(offset / 8) << 10) | reg_field(base, 5) | u32::from(source),
            false,
        )
    }

    fn load_vector128(&mut self, destination: u8, base: u8, offset: u16) -> Result<(), EmitError> {
        debug_assert!(offset.is_multiple_of(16) && offset / 16 <= 0xfff);
        self.emit_word(
            0x3dc0_0000
                | (u32::from(offset / 16) << 10)
                | reg_field(base, 5)
                | u32::from(destination),
            true,
        )
    }

    fn load_vector_pair128(
        &mut self,
        first_destination: u8,
        second_destination: u8,
        base: u8,
        offset: u16,
    ) -> Result<(), EmitError> {
        debug_assert!(
            first_destination != second_destination
                && offset.is_multiple_of(16)
                && offset / 16 < 64
        );
        self.emit_word(
            0xad40_0000
                | (u32::from(offset / 16) << 15)
                | reg_field(second_destination, 10)
                | reg_field(base, 5)
                | u32::from(first_destination),
            true,
        )
    }

    fn dup_byte16(&mut self, destination: u8, source: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x4e01_0c00 | reg_field(source, 5) | u32::from(destination),
            true,
        )
    }

    fn sve_ptrue_bytes_vl16(&mut self, destination: u8) -> Result<(), EmitError> {
        debug_assert!(destination <= 15);
        self.emit_word(0x2518_e120 | u32::from(destination), true)
    }

    fn sve_duplicate_byte(&mut self, destination: u8, source: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x0520_3800 | reg_field(source, 5) | u32::from(destination),
            true,
        )
    }

    fn sve_load_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        base: u8,
    ) -> Result<(), EmitError> {
        debug_assert!(predicate <= 7);
        self.emit_word(
            0xa400_a000
                | (u32::from(predicate) << 10)
                | reg_field(base, 5)
                | u32::from(destination),
            true,
        )
    }

    fn sve_compare_equal_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    ) -> Result<(), EmitError> {
        debug_assert!(destination <= 15 && predicate <= 7);
        self.emit_word(
            0x2400_a000
                | reg_field(right, 16)
                | (u32::from(predicate) << 10)
                | reg_field(left, 5)
                | u32::from(destination),
            true,
        )
    }

    fn sve_bit_clear_predicate_bytes_set_flags(
        &mut self,
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    ) -> Result<(), EmitError> {
        debug_assert!(destination <= 15 && predicate <= 7 && left <= 15 && right <= 15);
        self.emit_word(
            0x2540_4010
                | (u32::from(right) << 16)
                | (u32::from(predicate) << 10)
                | (u32::from(left) << 5)
                | u32::from(destination),
            true,
        )
    }

    fn sve2_match_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    ) -> Result<(), EmitError> {
        debug_assert!(destination <= 15 && predicate <= 7);
        self.emit_word(
            0x4520_8000
                | reg_field(right, 16)
                | (u32::from(predicate) << 10)
                | reg_field(left, 5)
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
    ) -> Result<(), EmitError> {
        debug_assert!(destination <= 15 && predicate <= 7 && left <= 15 && right <= 15);
        self.emit_word(
            0x2500_4000
                | (u32::from(right) << 16)
                | (u32::from(predicate) << 10)
                | (u32::from(left) << 5)
                | u32::from(destination),
            true,
        )
    }

    fn sve_and_predicate_bytes_set_flags(
        &mut self,
        destination: u8,
        predicate: u8,
        left: u8,
        right: u8,
    ) -> Result<(), EmitError> {
        debug_assert!(destination <= 15 && predicate <= 7 && left <= 15 && right <= 15);
        self.emit_word(
            0x2540_4000
                | (u32::from(right) << 16)
                | (u32::from(predicate) << 10)
                | (u32::from(left) << 5)
                | u32::from(destination),
            true,
        )
    }

    fn sve_test_predicate_bytes(&mut self, predicate: u8, tested: u8) -> Result<(), EmitError> {
        debug_assert!(predicate <= 7 && tested <= 15);
        self.emit_word(
            0x2550_c000 | (u32::from(predicate) << 10) | (u32::from(tested) << 5),
            true,
        )
    }

    fn sve_break_before_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        source: u8,
    ) -> Result<(), EmitError> {
        debug_assert!(destination <= 15 && predicate <= 7 && source <= 15);
        self.emit_word(
            0x2590_4000
                | (u32::from(predicate) << 10)
                | (u32::from(source) << 5)
                | u32::from(destination),
            true,
        )
    }

    fn sve_break_after_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        source: u8,
    ) -> Result<(), EmitError> {
        debug_assert!(destination <= 15 && predicate <= 7 && source <= 15);
        self.emit_word(
            0x2510_4000
                | (u32::from(predicate) << 10)
                | (u32::from(source) << 5)
                | u32::from(destination),
            true,
        )
    }

    fn sve_count_predicate_bytes(
        &mut self,
        destination: u8,
        predicate: u8,
        source: u8,
    ) -> Result<(), EmitError> {
        debug_assert!(predicate <= 7 && source <= 15);
        self.emit_word(
            0x2520_8000
                | (u32::from(predicate) << 10)
                | (u32::from(source) << 5)
                | u32::from(destination),
            true,
        )
    }

    fn compare_equal_bytes16(
        &mut self,
        destination: u8,
        left: u8,
        right: u8,
    ) -> Result<(), EmitError> {
        self.emit_word(
            0x6e20_8c00 | reg_field(right, 16) | reg_field(left, 5) | u32::from(destination),
            true,
        )
    }

    fn and_bytes16(&mut self, destination: u8, left: u8, right: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x4e20_1c00 | reg_field(right, 16) | reg_field(left, 5) | u32::from(destination),
            true,
        )
    }

    fn shift_right_narrow_halfwords_to_bytes8(
        &mut self,
        destination: u8,
        source: u8,
    ) -> Result<(), EmitError> {
        self.emit_word(
            0x0f0c_8400 | reg_field(source, 5) | u32::from(destination),
            true,
        )
    }

    fn unsigned_min_bytes16(&mut self, destination: u8, source: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x6e31_a800 | reg_field(source, 5) | u32::from(destination),
            true,
        )
    }

    fn unsigned_max_bytes16(&mut self, destination: u8, source: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x6e30_a800 | reg_field(source, 5) | u32::from(destination),
            true,
        )
    }

    fn unsigned_max_pairwise_bytes16(
        &mut self,
        destination: u8,
        left: u8,
        right: u8,
    ) -> Result<(), EmitError> {
        self.emit_word(
            0x6e20_a400 | reg_field(right, 16) | reg_field(left, 5) | u32::from(destination),
            true,
        )
    }

    fn add_across_bytes16(&mut self, destination: u8, source: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x4e31_b800 | reg_field(source, 5) | u32::from(destination),
            true,
        )
    }

    fn move_vector_byte_to32(&mut self, destination: u8, source: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x0e01_3c00 | reg_field(source, 5) | u32::from(destination),
            true,
        )
    }

    fn move_vector_double_to64(&mut self, destination: u8, source: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x9e66_0000 | reg_field(source, 5) | u32::from(destination),
            true,
        )
    }

    fn rbit(&mut self, destination: u8, source: u8) -> Result<(), EmitError> {
        self.emit_word(
            0xdac0_0000 | reg_field(source, 5) | u32::from(destination),
            false,
        )
    }

    fn clz(&mut self, destination: u8, source: u8) -> Result<(), EmitError> {
        self.emit_word(
            0xdac0_1000 | reg_field(source, 5) | u32::from(destination),
            false,
        )
    }

    fn adr(&mut self, destination: u8, rodata_offset: u32) -> Result<(), EmitError> {
        self.add_fixup(
            RelocationKind::Address21,
            FixupTarget::Rodata(rodata_offset),
            0x1000_0000 | u32::from(destination),
        )
    }

    fn branch(&mut self, target: Label) -> Result<(), EmitError> {
        self.add_fixup(
            RelocationKind::Branch26,
            FixupTarget::Label(target),
            0x1400_0000,
        )
    }

    fn branch_cond(&mut self, condition: Condition, target: Label) -> Result<(), EmitError> {
        self.add_fixup(
            RelocationKind::ConditionalBranch19,
            FixupTarget::Label(target),
            0x5400_0000 | condition_code(condition),
        )
    }

    fn compare_branch_zero(
        &mut self,
        register: u8,
        nonzero: bool,
        target: Label,
    ) -> Result<(), EmitError> {
        let base = if nonzero { 0xb500_0000 } else { 0xb400_0000 };
        self.add_fixup(
            RelocationKind::CompareBranch19,
            FixupTarget::Label(target),
            base | u32::from(register),
        )
    }

    fn ret(&mut self) -> Result<(), EmitError> {
        self.emit_word(0xd65f_03c0, false)
    }

    fn finalize(mut self, data_bytes: usize) -> Result<Finalized, EmitError> {
        let code_bytes = self.code.len();
        let rodata_base = align_up(code_bytes, DATA_ALIGNMENT, ArithmeticSite::ImageLayout)?;
        let total = rodata_base
            .checked_add(data_bytes)
            .ok_or(EmitError::ArithmeticOverflow {
                site: ArithmeticSite::ImageLayout,
            })?;
        let _ = to_u32(total, ArithmeticSite::ImageLayout)?;
        let mut relocations = Vec::new();
        relocations
            .try_reserve_exact(self.fixups.len())
            .map_err(|_| EmitError::AllocationFailed {
                resource: ResourceKind::Relocations,
            })?;
        for fixup in &self.fixups {
            self.meter.charge(1)?;
            let (target_absolute, target) = match fixup.target {
                FixupTarget::Label(label) => {
                    let record = self
                        .labels
                        .get(to_usize(label.0)?)
                        .ok_or(EmitError::InternalInvariant)?;
                    let offset = record.offset.ok_or(EmitError::InternalInvariant)?;
                    (
                        usize::try_from(offset).expect("u32 fits usize"),
                        RelocationTarget::CodeOffset(offset),
                    )
                }
                FixupTarget::Rodata(offset) => {
                    let offset_usize = usize::try_from(offset).expect("u32 fits usize");
                    if offset_usize >= data_bytes && data_bytes != 0 {
                        return Err(EmitError::InternalInvariant);
                    }
                    let absolute = rodata_base.checked_add(offset_usize).ok_or(
                        EmitError::ArithmeticOverflow {
                            site: ArithmeticSite::RelocationDisplacement,
                        },
                    )?;
                    (absolute, RelocationTarget::RodataOffset(offset))
                }
            };
            let word = read_word(&self.code, fixup.at)?;
            let resolved = resolve_word(word, fixup.kind, fixup.at, target_absolute)?;
            write_word(&mut self.code, fixup.at, resolved)?;
            relocations.push(Relocation {
                code_offset: fixup.at,
                kind: fixup.kind,
                target,
                addend: 0,
                resolved_word: resolved,
            });
        }
        let mut labels = Vec::new();
        labels
            .try_reserve_exact(self.labels.len())
            .map_err(|_| EmitError::AllocationFailed {
                resource: ResourceKind::Labels,
            })?;
        for record in self.labels {
            labels.push(CodeLabel {
                offset: record.offset.ok_or(EmitError::InternalInvariant)?,
                kind: record.kind,
            });
        }
        labels.sort_unstable();
        Ok(Finalized {
            code: self.code.into_boxed_slice(),
            labels: labels.into_boxed_slice(),
            relocations: relocations.into_boxed_slice(),
            work: self.meter.consumed,
            vector_instructions: self.vector_instructions,
        })
    }
}

struct Finalized {
    code: Box<[u8]>,
    labels: Box<[CodeLabel]>,
    relocations: Box<[Relocation]>,
    work: u64,
    vector_instructions: u32,
}

#[derive(Clone, Copy)]
struct WorkMeter {
    limit: u64,
    consumed: u64,
}

impl WorkMeter {
    const fn new(limit: u64) -> Self {
        Self { limit, consumed: 0 }
    }

    fn charge(&mut self, amount: u64) -> Result<(), EmitError> {
        let required = self
            .consumed
            .checked_add(amount)
            .ok_or(EmitError::ArithmeticOverflow {
                site: ArithmeticSite::EmissionWork,
            })?;
        if required > self.limit {
            return Err(EmitError::ResourceLimit {
                resource: ResourceKind::EmissionWork,
                limit: self.limit,
                required,
            });
        }
        self.consumed = required;
        Ok(())
    }

    fn charge_usize(&mut self, amount: usize) -> Result<(), EmitError> {
        self.charge(
            u64::try_from(amount).map_err(|_| EmitError::ArithmeticOverflow {
                site: ArithmeticSite::EmissionWork,
            })?,
        )
    }
}

fn resolve_word(
    word: u32,
    kind: RelocationKind,
    from: u32,
    target: usize,
) -> Result<u32, EmitError> {
    let from_i64 = i64::from(from);
    let target_u64 = u64::try_from(target).map_err(|_| EmitError::ArithmeticOverflow {
        site: ArithmeticSite::RelocationDisplacement,
    })?;
    let target_signed = i64::try_from(target_u64).map_err(|_| EmitError::ArithmeticOverflow {
        site: ArithmeticSite::RelocationDisplacement,
    })?;
    let displacement =
        target_signed
            .checked_sub(from_i64)
            .ok_or(EmitError::ArithmeticOverflow {
                site: ArithmeticSite::RelocationDisplacement,
            })?;
    match kind {
        RelocationKind::Branch26 => encode_scaled_displacement(
            word,
            displacement,
            26,
            0,
            BranchKind::Unconditional26,
            from,
            target_u64,
        ),
        RelocationKind::ConditionalBranch19 | RelocationKind::CompareBranch19 => {
            encode_scaled_displacement(
                word,
                displacement,
                19,
                5,
                if kind == RelocationKind::ConditionalBranch19 {
                    BranchKind::Conditional19
                } else {
                    BranchKind::Compare19
                },
                from,
                target_u64,
            )
        }
        RelocationKind::Address21 => encode_adr(word, displacement, from, target_u64),
    }
}

fn encode_scaled_displacement(
    word: u32,
    displacement: i64,
    bits: u8,
    shift: u8,
    kind: BranchKind,
    from: u32,
    target: u64,
) -> Result<u32, EmitError> {
    if displacement % 4 != 0 {
        return Err(EmitError::InternalInvariant);
    }
    let scaled = displacement / 4;
    let (minimum, maximum) = signed_range(bits);
    if scaled < minimum || scaled > maximum {
        return Err(EmitError::BranchOutOfRange {
            kind,
            from: u64::from(from),
            to: target,
            minimum: minimum.checked_mul(4).expect("signed instruction range"),
            maximum: maximum.checked_mul(4).expect("signed instruction range"),
        });
    }
    let mask = 1_u32
        .checked_shl(u32::from(bits))
        .and_then(|value| value.checked_sub(1))
        .expect("relocation widths are below 32");
    let encoded = u32::try_from(scaled & i64::from(mask)).expect("masked displacement");
    Ok(word | (encoded << u32::from(shift)))
}

fn encode_adr(word: u32, displacement: i64, from: u32, target: u64) -> Result<u32, EmitError> {
    let (minimum, maximum) = signed_range(21);
    if displacement < minimum || displacement > maximum {
        return Err(EmitError::BranchOutOfRange {
            kind: BranchKind::Address21,
            from: u64::from(from),
            to: target,
            minimum,
            maximum,
        });
    }
    let encoded = u32::try_from(displacement & 0x1f_ffff).expect("21-bit displacement");
    let low = encoded & 3;
    let high = encoded >> 2;
    Ok(word | (low << 29) | (high << 5))
}

fn signed_range(bits: u8) -> (i64, i64) {
    let shift = bits.checked_sub(1).expect("signed field is nonempty");
    let magnitude = 1_i64
        .checked_shl(u32::from(shift))
        .expect("instruction fields fit i64");
    (
        magnitude.checked_neg().expect("positive magnitude"),
        magnitude.checked_sub(1).expect("positive magnitude"),
    )
}

fn read_word(code: &[u8], offset: u32) -> Result<u32, EmitError> {
    let offset = to_usize(offset)?;
    let end = offset.checked_add(4).ok_or(EmitError::ArithmeticOverflow {
        site: ArithmeticSite::CodeOffset,
    })?;
    let bytes = code.get(offset..end).ok_or(EmitError::InternalInvariant)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_word(code: &mut [u8], offset: u32, word: u32) -> Result<(), EmitError> {
    let offset = to_usize(offset)?;
    let end = offset.checked_add(4).ok_or(EmitError::ArithmeticOverflow {
        site: ArithmeticSite::CodeOffset,
    })?;
    let destination = code
        .get_mut(offset..end)
        .ok_or(EmitError::InternalInvariant)?;
    destination.copy_from_slice(&word.to_le_bytes());
    Ok(())
}

fn align_up(value: usize, alignment: usize, site: ArithmeticSite) -> Result<usize, EmitError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(EmitError::InternalInvariant)?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(EmitError::ArithmeticOverflow { site })
}

fn enforce(resource: ResourceKind, required: usize, limit: u64) -> Result<(), EmitError> {
    let required = u64::try_from(required).map_err(|_| EmitError::ResourceLimit {
        resource,
        limit,
        required: u64::MAX,
    })?;
    enforce_u64(resource, required, limit)
}

const fn enforce_u64(resource: ResourceKind, required: u64, limit: u64) -> Result<(), EmitError> {
    if required > limit {
        return Err(EmitError::ResourceLimit {
            resource,
            limit,
            required,
        });
    }
    Ok(())
}

fn to_u32(value: usize, site: ArithmeticSite) -> Result<u32, EmitError> {
    u32::try_from(value).map_err(|_| EmitError::ArithmeticOverflow { site })
}

fn to_usize(value: u32) -> Result<usize, EmitError> {
    usize::try_from(value).map_err(|_| EmitError::ArithmeticOverflow {
        site: ArithmeticSite::CodeOffset,
    })
}

fn to_usize_limit(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn reg_field(register: u8, shift: u8) -> u32 {
    u32::from(register) << shift
}

const fn condition_code(condition: Condition) -> u32 {
    match condition {
        Condition::Equal => 0,
        Condition::NotEqual => 1,
        Condition::CarrySet => 2,
        Condition::CarryClear => 3,
        Condition::Higher => 8,
        Condition::LowerOrSame => 9,
        Condition::Always => 14,
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::{
        BranchKind, EmitError, MAX_REPEATED_CONFIRM_BYTES, RelocationKind, candidate_byte_pair,
        candidate_ranked_verification_offsets, candidate_ranked_verification_offsets_v2,
        candidate_ranked_verification_offsets_v3, candidate_verification_offset, resolve_word,
        signed_range,
    };

    #[test]
    fn candidate_byte_pair_matches_the_pinned_frequency_ranker() {
        assert_eq!(candidate_byte_pair(b""), (0, None));
        assert_eq!(candidate_byte_pair(b"a"), (0, None));
        assert_eq!(candidate_byte_pair(b"0123456789abcdef"), (7, Some(6)));
        assert_eq!(candidate_byte_pair(b"Sherlock Holmes"), (9, Some(7)));

        let repeated = [b'a'; MAX_REPEATED_CONFIRM_BYTES];
        assert_eq!(candidate_byte_pair(&repeated), (0, Some(1)));
        assert_eq!(
            candidate_verification_offset(b"0123456789abcdef", 7, Some(6)),
            Some(0)
        );
        assert_eq!(candidate_verification_offset(b"7a e", 0, Some(1)), Some(2));
        assert_eq!(candidate_verification_offset(b"abab", 0, Some(1)), None);
        assert_eq!(
            candidate_ranked_verification_offsets(b"0123456789abcdef", 7, Some(6)),
            (Some(8), Some(5))
        );
        assert_eq!(
            candidate_ranked_verification_offsets_v2(b"0123456789abcdef", 7, Some(6)),
            (Some(8), Some(5), Some(15))
        );
        assert_eq!(
            candidate_ranked_verification_offsets_v3(b"0123456789abcdef", 7, Some(6)),
            (Some(8), Some(0), Some(15))
        );
        let mut terminal_pair = [b'e'; 16];
        terminal_pair[15] = 0x1f;
        terminal_pair[4] = 0x1e;
        assert_eq!(candidate_byte_pair(&terminal_pair), (15, Some(4)));
        assert_eq!(
            candidate_ranked_verification_offsets_v2(&terminal_pair, 15, Some(4)),
            (Some(0), Some(1), Some(2))
        );
        assert_eq!(
            candidate_ranked_verification_offsets_v3(&terminal_pair, 15, Some(4)),
            (Some(1), Some(2), Some(0))
        );
        assert_eq!(
            candidate_ranked_verification_offsets_v3(&[b'e'; 16], 0, Some(1)),
            (Some(2), Some(3), Some(15))
        );
        let mut subtract = [b'e'; 16];
        subtract[8] = 0x1f;
        subtract[4] = 0x1e;
        subtract[2] = 0x1d;
        subtract[1] = 0x1c;
        assert_eq!(candidate_byte_pair(&subtract), (8, Some(4)));
        assert_eq!(
            candidate_ranked_verification_offsets(&subtract, 8, Some(4)),
            (Some(2), Some(1))
        );
    }

    #[test]
    fn signed_ranges_are_exact() {
        assert_eq!(signed_range(19), (-262_144, 262_143));
        assert_eq!(signed_range(21), (-1_048_576, 1_048_575));
        assert_eq!(signed_range(26), (-33_554_432, 33_554_431));
    }

    #[test]
    fn every_pc_relative_range_accepts_edges_and_refuses_first_outside() {
        check_scaled_range(
            0x1400_0000,
            RelocationKind::Branch26,
            BranchKind::Unconditional26,
            26,
        );
        check_scaled_range(
            0x5400_0000,
            RelocationKind::ConditionalBranch19,
            BranchKind::Conditional19,
            19,
        );
        check_scaled_range(
            0xb400_0000,
            RelocationKind::CompareBranch19,
            BranchKind::Compare19,
            19,
        );
        let (minimum, maximum) = signed_range(21);
        let maximum = usize::try_from(maximum).expect("positive ADR range");
        assert!(resolve_word(0x1000_0000, RelocationKind::Address21, 0, maximum).is_ok());
        assert_range_error(
            resolve_word(
                0x1000_0000,
                RelocationKind::Address21,
                0,
                maximum.checked_add(1).expect("small range"),
            ),
            BranchKind::Address21,
        );
        let magnitude =
            usize::try_from(minimum.checked_neg().expect("negative minimum")).expect("small range");
        assert!(
            resolve_word(
                0x1000_0000,
                RelocationKind::Address21,
                u32::try_from(magnitude).expect("fits u32"),
                0,
            )
            .is_ok()
        );
        assert_range_error(
            resolve_word(
                0x1000_0000,
                RelocationKind::Address21,
                u32::try_from(magnitude.checked_add(1).expect("small range")).expect("fits u32"),
                0,
            ),
            BranchKind::Address21,
        );
    }

    fn check_scaled_range(word: u32, relocation: RelocationKind, branch: BranchKind, bits: u8) {
        let (minimum, maximum) = signed_range(bits);
        let maximum = usize::try_from(maximum.checked_mul(4).expect("instruction range"))
            .expect("positive range");
        assert!(resolve_word(word, relocation, 0, maximum).is_ok());
        assert_range_error(
            resolve_word(
                word,
                relocation,
                0,
                maximum.checked_add(4).expect("small range"),
            ),
            branch,
        );
        let magnitude = usize::try_from(
            minimum
                .checked_mul(4)
                .and_then(i64::checked_neg)
                .expect("negative minimum"),
        )
        .expect("small range");
        assert!(
            resolve_word(
                word,
                relocation,
                u32::try_from(magnitude).expect("range fits u32"),
                0,
            )
            .is_ok()
        );
        assert_range_error(
            resolve_word(
                word,
                relocation,
                u32::try_from(magnitude.checked_add(4).expect("small range"))
                    .expect("range fits u32"),
                0,
            ),
            branch,
        );
    }

    fn assert_range_error(result: Result<u32, EmitError>, expected: BranchKind) {
        let error = result.expect_err("first displacement outside the field must fail");
        assert!(matches!(
            error,
            EmitError::BranchOutOfRange { kind, .. } if kind == expected
        ));
    }
}
