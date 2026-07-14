use fre_kernel_ir::{
    AbiVersion, AggregateOperation, AggregateOutput, AnchorFlags, BlockOp, ByteClass, DataBlob,
    ExactAggregateProgram, MAX_EXACT_AGGREGATE_LITERAL_BYTES, Operation, OutputKind,
    SemanticsVersion, ValidatedProgram,
};

use crate::{
    ArithmeticSite, BackendVersion, BranchKind, CodeLabel, Condition, ConfirmationKind,
    CpuFeatures, DataSymbol, EmitError, ImageLayout, ImageStats, LabelKind, NativeAggregateImage,
    NativeImage, Relocation, RelocationKind, RelocationTarget, ResourceKind, TargetSpec,
    UnsupportedReason,
    image::{AggregateManifest, DataSymbolKind, aot_size},
};

const CODE_ALIGNMENT: usize = 16;
const DATA_ALIGNMENT: usize = 16;
const EXACT_CODE_RESERVE: usize = 1_024;
const CLASS_CODE_RESERVE: usize = 1_600;
const EXACT_LABEL_RESERVE: usize = 32;
const CLASS_LABEL_RESERVE: usize = 48;
const EXACT_RELOCATION_RESERVE: usize = 64;
const CLASS_RELOCATION_RESERVE: usize = 96;
const AGGREGATE_CODE_RESERVE: usize = 1_600;
const AGGREGATE_LABEL_RESERVE: usize = 48;
const AGGREGATE_RELOCATION_RESERVE: usize = 96;

/// Largest confirmation payload admitted when a search can confirm at more
/// than one candidate position.
///
/// This converts the naive confirmation factor into an implementation
/// constant. Longer unanchored patterns require a proved-linear Two-Way or
/// automaton fallback in a higher-level planner. Single-candidate start/end
/// anchored literals and start-anchored class runs do not need this cap.
pub const MAX_REPEATED_CONFIRM_BYTES: usize = 32;

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
    let plan = Plan::recognize(program)?;
    let capacities = plan.capacities();
    let scratch = scratch_bytes(capacities)?;
    enforce_u64(
        ResourceKind::ScratchBytes,
        scratch,
        limits.max_scratch_bytes,
    )?;
    let mut meter = WorkMeter::new(limits.max_emission_work);
    let data = build_rodata(
        program.raw().data.as_slice(),
        limits.max_data_bytes,
        &mut meter,
    )?;
    let mut assembler = Assembler::new(limits, capacities, meter)?;
    let entry = assembler.new_label(LabelKind::Entry)?;
    let found = assembler.new_label(LabelKind::ReturnFound)?;
    let none = assembler.new_label(LabelKind::ReturnNone)?;
    assembler.bind(entry)?;
    emit_preamble(&mut assembler, none)?;
    emit_plan(&mut assembler, &data, plan, found, none)?;
    emit_returns(&mut assembler, program.raw().output, found, none)?;
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
        backend_version: BackendVersion::CURRENT,
        target: TargetSpec {
            features: if finalized.vector_instructions == 0 {
                CpuFeatures::NONE
            } else {
                CpuFeatures::ASIMD
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
        aggregate: None,
    };
    finalize_image(image, limits)
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
    let literal = program.literal();
    if literal.len() > MAX_EXACT_AGGREGATE_LITERAL_BYTES {
        return Err(EmitError::ConfirmationLengthLimit {
            kind: ConfirmationKind::ExactLiteral,
            limit: MAX_EXACT_AGGREGATE_LITERAL_BYTES,
            required: literal.len(),
        });
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
    emit_aggregate_exact(&mut assembler, literal, A::OUTPUT, done, overflow, &data)?;
    emit_aggregate_returns(&mut assembler, done, overflow)?;
    let finalized = assembler.finalize(data.bytes.len())?;
    let image = build_aggregate_image(program, finalized, data, scratch)?;
    finalize_aggregate_image(image, limits)
}

fn build_aggregate_image<A: AggregateOperation>(
    program: &ExactAggregateProgram<A>,
    finalized: Finalized,
    data: Rodata,
    scratch: u64,
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
        backend_version: BackendVersion::CURRENT,
        target: TargetSpec {
            features: if finalized.vector_instructions == 0 {
                CpuFeatures::NONE
            } else {
                CpuFeatures::ASIMD
            },
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
        emit_aggregate_single_byte(assembler, done, overflow)
    } else {
        emit_aggregate_multi_byte(assembler, literal, output, done, overflow)
    }
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
) -> Result<(), EmitError> {
    assembler.bind(done)?;
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
    found: Label,
    none: Label,
) -> Result<(), EmitError> {
    match plan {
        Plan::Exact { literal, anchors } => {
            assembler.adr(X8, data.symbol_offset(0)?)?;
            emit_exact(assembler, literal, anchors, found, none)
        }
        Plan::ClassSuffix {
            class,
            suffix,
            anchors,
        } => {
            assembler.adr(X8, data.symbol_offset(0)?)?;
            assembler.adr(X7, data.symbol_offset(1)?)?;
            if let Some(class_byte) = (!anchors.start).then(|| singleton_byte(class)).flatten() {
                emit_singleton_class_suffix_first(
                    assembler, class_byte, suffix, anchors, found, none,
                )
            } else {
                emit_class_suffix(assembler, class, suffix, anchors, found, none)
            }
        }
    }
}

fn finalize_image(mut image: NativeImage, limits: EmitLimits) -> Result<NativeImage, EmitError> {
    charge_image_identity(&mut image, limits)?;
    crate::audit(&image).map_err(|_| EmitError::InternalInvariant)?;
    Ok(image)
}

fn finalize_aggregate_image(
    mut image: NativeImage,
    limits: EmitLimits,
) -> Result<NativeAggregateImage, EmitError> {
    charge_image_identity(&mut image, limits)?;
    let image = NativeAggregateImage::new(image);
    crate::audit_aggregate(&image).map_err(|_| EmitError::InternalInvariant)?;
    Ok(image)
}

fn charge_image_identity(image: &mut NativeImage, limits: EmitLimits) -> Result<(), EmitError> {
    let identity_work =
        u64::try_from(aot_size(image)?).map_err(|_| EmitError::ArithmeticOverflow {
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

impl<'a> Plan<'a> {
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

    const fn capacities(self) -> Capacities {
        match self {
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

fn emit_exact(
    assembler: &mut Assembler,
    literal: &[u8],
    anchors: AnchorFlags,
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
    emit_vector_candidate_skip(assembler, literal, none, found)?;
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

fn emit_vector_candidate_skip(
    assembler: &mut Assembler,
    literal: &[u8],
    none: Label,
    found: Label,
) -> Result<(), EmitError> {
    // These vector loads examine two 16-byte columns of candidate positions,
    // not one candidate. X6 is the last start at which the complete literal
    // fits. The remaining-start check proves X5..=X5+15 are valid starts; for
    // the optional last-byte column it therefore also proves
    // X5+(length-1)..=X5+(length-1)+15 lies inside the search window.
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
    let last_offset = u16::try_from(literal.len().saturating_sub(1)).map_err(|_| {
        EmitError::ArithmeticOverflow {
            site: ArithmeticSite::DataOffset,
        }
    })?;
    if literal.len() > 1 {
        assembler.load_byte(X11, X8, last_offset)?;
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
        // Preserve the first-byte lane mask in v0 while reducing a copy. Most
        // blocks contain no first-byte candidate and fall through at exactly
        // the original one-vector steady-state branch behavior.
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
        assembler.add_imm(X10, X15, last_offset)?;
        assembler.load_vector128(2, X10, 0)?;
        assembler.compare_equal_bytes16(2, 2, 3)?;
        assembler.and_bytes16(0, 0, 2)?;
        assembler.unsigned_max_bytes16(0, 0)?;
        assembler.move_vector_byte_to32(X10, 0)?;
        assembler.compare_branch_zero(X10, true, scalar)?;
        assembler.branch(advance)?;
    }
    assembler.bind(scalar)?;
    emit_scalar_candidates(assembler, literal, none, found)
}

fn emit_scalar_candidates(
    assembler: &mut Assembler,
    literal: &[u8],
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
    emit_literal_equality(assembler, X15, X8, literal.len(), advance)?;
    assembler.mov_reg(X13, X5)?;
    assembler.add_reg(X14, X5, X12)?;
    assembler.branch(found)?;
    assembler.bind(advance)?;
    assembler.cmp_reg64(X5, X6)?;
    assembler.branch_cond(Condition::CarrySet, none)?;
    assembler.add_imm(X5, X5, 1)?;
    assembler.branch(scan)
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

/// Emit a suffix-first search for the mechanically admitted singleton-class
/// family proved in `research/jit/bakeoff/class-suffix-theorem.md`.
#[allow(
    clippy::too_many_lines,
    reason = "keeping the complete monotonic candidate and backward-confirmation CFG together makes its range proof auditable"
)]
fn emit_singleton_class_suffix_first(
    assembler: &mut Assembler,
    class_byte: u8,
    suffix: &[u8],
    anchors: AnchorFlags,
    found: Label,
    none: Label,
) -> Result<(), EmitError> {
    debug_assert!(!anchors.start);
    debug_assert!(!suffix.is_empty());
    debug_assert!(suffix.len() <= MAX_REPEATED_CONFIRM_BYTES);
    debug_assert_ne!(suffix[0], class_byte);

    let suffix_length = u64::try_from(suffix.len()).map_err(|_| EmitError::ArithmeticOverflow {
        site: ArithmeticSite::DataOffset,
    })?;
    let last_offset = u16::try_from(suffix.len().saturating_sub(1)).map_err(|_| {
        EmitError::ArithmeticOverflow {
            site: ArithmeticSite::DataOffset,
        }
    })?;
    assembler.mov_imm64(X12, suffix_length)?;
    // A match needs at least one class byte followed by the complete suffix.
    assembler.sub_reg(X10, X3, X2)?;
    assembler.cmp_reg64(X10, X12)?;
    assembler.branch_cond(Condition::LowerOrSame, none)?;
    assembler.sub_reg(X6, X3, X12)?;
    assembler.add_imm(X5, X2, 1)?;

    // v4/v5 retain the suffix pair across full confirmation in v0/v1. v6
    // retains the singleton class byte for the backward vector scan.
    assembler.load_byte(X11, X7, 0)?;
    assembler.dup_byte16(4, X11)?;
    if suffix.len() > 1 {
        assembler.load_byte(X11, X7, last_offset)?;
        assembler.dup_byte16(5, X11)?;
    }
    assembler.mov_imm64(X11, u64::from(class_byte))?;
    assembler.dup_byte16(6, X11)?;

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
    assembler.load_vector128(2, X15, 0)?;
    assembler.compare_equal_bytes16(2, 2, 4)?;
    if let Some(second_filter) = second_filter {
        // Reduce into v7 so the first-byte lane mask in v2 remains available
        // for exact lane-wise intersection on the uncommon path.
        assembler.unsigned_max_bytes16(7, 2)?;
        assembler.move_vector_byte_to32(X10, 7)?;
        assembler.compare_branch_zero(X10, true, second_filter)?;
    } else {
        assembler.unsigned_max_bytes16(2, 2)?;
        assembler.move_vector_byte_to32(X10, 2)?;
        assembler.compare_branch_zero(X10, true, block_scalar)?;
    }
    assembler.bind(advance_vector)?;
    assembler.add_imm(X5, X5, 16)?;
    assembler.branch(vector)?;

    if let Some(second_filter) = second_filter {
        assembler.bind(second_filter)?;
        assembler.add_imm(X10, X15, last_offset)?;
        assembler.load_vector128(3, X10, 0)?;
        assembler.compare_equal_bytes16(3, 3, 5)?;
        assembler.and_bytes16(2, 2, 3)?;
        assembler.unsigned_max_bytes16(2, 2)?;
        assembler.move_vector_byte_to32(X10, 2)?;
        assembler.compare_branch_zero(X10, true, block_scalar)?;
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
    emit_literal_equality(assembler, X15, X7, suffix.len(), candidate_reject)?;
    assembler.add_reg(X14, X5, X12)?;
    if anchors.end {
        assembler.cmp_reg64(X14, X1)?;
        assembler.branch_cond(Condition::NotEqual, candidate_reject)?;
    }
    // X5 starts at window_start + 1, so this predecessor is in-range.
    assembler.sub_imm(X10, X5, 1)?;
    assembler.load_byte_reg(X15, X9, X10)?;
    assembler.mov_imm64(X11, u64::from(class_byte))?;
    assembler.cmp_reg32(X15, X11)?;
    assembler.branch_cond(Condition::NotEqual, candidate_reject)?;

    // Scan the maximal singleton-class run backward. Every vector load covers
    // [X13-16, X13), admitted only when at least 16 window bytes remain.
    assembler.mov_reg(X13, X5)?;
    assembler.bind(backward_vector)?;
    assembler.sub_reg(X10, X13, X2)?;
    assembler.cmp_imm64(X10, 16)?;
    assembler.branch_cond(Condition::CarryClear, backward_scalar)?;
    assembler.add_reg(X15, X9, X13)?;
    assembler.sub_imm(X15, X15, 16)?;
    assembler.load_vector128(2, X15, 0)?;
    assembler.compare_equal_bytes16(2, 2, 6)?;
    assembler.unsigned_min_bytes16(2, 2)?;
    assembler.move_vector_byte_to32(X10, 2)?;
    assembler.cmp_imm32(X10, 255)?;
    assembler.branch_cond(Condition::NotEqual, backward_scalar)?;
    assembler.sub_imm(X13, X13, 16)?;
    assembler.branch(backward_vector)?;

    assembler.bind(backward_scalar)?;
    assembler.cmp_reg64(X13, X2)?;
    assembler.branch_cond(Condition::Equal, backward_done)?;
    assembler.sub_imm(X10, X13, 1)?;
    assembler.load_byte_reg(X15, X9, X10)?;
    assembler.cmp_reg32(X15, X11)?;
    assembler.branch_cond(Condition::NotEqual, backward_done)?;
    assembler.mov_reg(X13, X10)?;
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
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "explicit vector temporaries make enclosing filter liveness auditable"
)]
fn emit_literal_equality_with_vectors(
    assembler: &mut Assembler,
    hay_pointer: u8,
    needle_pointer: u8,
    length: usize,
    mismatch: Label,
    left_vector: u8,
    right_vector: u8,
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
    assembler.load_byte(X11, X16, 0)?;
    assembler.cmp_reg32(X10, X11)?;
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
    enforce(ResourceKind::DataBytes, required, max_bytes)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(required)
        .map_err(|_| EmitError::AllocationFailed {
            resource: ResourceKind::DataBytes,
        })?;
    let mut symbols = Vec::new();
    symbols
        .try_reserve_exact(blobs.len())
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

    fn dup_byte16(&mut self, destination: u8, source: u8) -> Result<(), EmitError> {
        self.emit_word(
            0x4e01_0c00 | reg_field(source, 5) | u32::from(destination),
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
    use super::{BranchKind, EmitError, RelocationKind, resolve_word, signed_range};

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
