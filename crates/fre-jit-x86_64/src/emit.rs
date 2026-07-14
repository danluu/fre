use core::mem::size_of;

use fre_kernel_ir::{
    AnchorFlags, BlockOp, ByteClass, DataBlob, Operation, RawProgram, ValidateLimits,
    ValidatedProgram,
};

use crate::{
    AuditLimits, CallingConvention, EmitError, EmitResource, FeatureTier, ImageStats, KernelShape,
    NativeImage, Relocation, RelocationKind, Section, TargetStamp, UnsupportedKernel,
    UnsupportedTarget, X86AbiStamp, audit_image,
};

const HARD_CODE_BYTES: usize = 4_096;
const HARD_LABELS: usize = 64;
const HARD_BRANCHES: usize = 128;
const HARD_RELOCATIONS: usize = 8;
const EMIT_SCRATCH_BYTES: usize = HARD_CODE_BYTES
    + HARD_LABELS * size_of::<Option<usize>>()
    + HARD_BRANCHES * size_of::<BranchFixup>()
    + HARD_RELOCATIONS * size_of::<DataFixup>();

/// All resource limits consulted while constructing one native image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmitLimits {
    pub max_code_bytes: u64,
    pub max_data_bytes: u64,
    pub max_image_bytes: u64,
    pub max_relocations: u64,
    pub max_internal_branches: u64,
    pub max_branch_displacement: u64,
    pub max_relocation_displacement: u64,
    pub max_emit_work: u64,
    pub max_emit_scratch_bytes: u64,
    pub max_runtime_work_factor: u64,
    pub max_runtime_scratch_bytes: u64,
}

impl Default for EmitLimits {
    fn default() -> Self {
        Self {
            max_code_bytes: u64::try_from(HARD_CODE_BYTES).expect("small constant"),
            max_data_bytes: 1 << 20,
            max_image_bytes: (1 << 20) + 8_192,
            max_relocations: u64::try_from(HARD_RELOCATIONS).expect("small constant"),
            max_internal_branches: u64::try_from(HARD_BRANCHES).expect("small constant"),
            max_branch_displacement: i32::MAX.unsigned_abs().into(),
            max_relocation_displacement: i32::MAX.unsigned_abs().into(),
            max_emit_work: 4 << 20,
            max_emit_scratch_bytes: u64::try_from(EMIT_SCRATCH_BYTES).expect("small constant"),
            max_runtime_work_factor: (1 << 20) + 16,
            max_runtime_scratch_bytes: 0,
        }
    }
}

/// Target, feature and resource policy for one deterministic compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmitConfig {
    pub target: TargetStamp,
    pub feature_tier: FeatureTier,
    pub limits: EmitLimits,
    pub audit_limits: AuditLimits,
}

impl Default for EmitConfig {
    fn default() -> Self {
        Self {
            target: TargetStamp::system_v_amd64_v1(),
            feature_tier: FeatureTier::Scalar,
            limits: EmitLimits::default(),
            audit_limits: AuditLimits::default(),
        }
    }
}

/// Validate an untrusted Kernel IR program and then emit it.
pub fn emit_raw<O: Operation>(
    raw: RawProgram,
    validate_limits: ValidateLimits,
    config: EmitConfig,
) -> Result<NativeImage, EmitError> {
    let validated = raw.validate::<O>(validate_limits)?;
    emit(&validated, config)
}

/// Emit a deterministic native image from validated Kernel IR.
pub fn emit<O: Operation>(
    program: &ValidatedProgram<O>,
    config: EmitConfig,
) -> Result<NativeImage, EmitError> {
    check_target(config.target)?;
    enforce(
        EmitResource::EmitScratchBytes,
        EMIT_SCRATCH_BYTES,
        config.limits.max_emit_scratch_bytes,
    )?;
    enforce(
        EmitResource::RuntimeScratchBytes,
        0_usize,
        config.limits.max_runtime_scratch_bytes,
    )?;
    let runtime_work_factor = program.stats().work_factor();
    enforce_u64(
        EmitResource::RuntimeWorkFactor,
        runtime_work_factor,
        config.limits.max_runtime_work_factor,
    )?;

    let plan = Plan::extract(program)?;
    let used_tier = effective_tier(config.feature_tier, plan.confirmation_length());
    let mut meter = WorkMeter::new(config.limits.max_emit_work);
    let (data, constants) = build_constants(&plan, &config.limits, &mut meter)?;
    let mut assembler = Assembler::new(config.limits, &mut meter);
    match plan {
        Plan::Exact { literal, anchors } => {
            emit_exact(
                &mut assembler,
                literal,
                anchors,
                constants.pattern,
                used_tier,
            )?;
        }
        Plan::ClassSuffix {
            class,
            suffix,
            anchors,
        } => emit_class_suffix(&mut assembler, class, suffix, anchors, constants, used_tier)?,
    }
    let shape = plan.shape()?;
    let raw = program.raw();
    let image = assembler.finish(FinishInput {
        data: &data,
        data_alignment: used_tier.vector_width().max(8),
        shape,
        output: raw.output,
        kernel_identity: program.cache_identity(),
        stamp: X86AbiStamp {
            target: config.target,
            requested_tier: config.feature_tier,
            used_tier,
            kernel_abi_version: raw.abi.0,
            kernel_semantics_version: raw.semantics.0,
        },
        runtime_work_factor,
    })?;
    audit_image(&image, config.audit_limits)?;
    Ok(image)
}

fn check_target(target: TargetStamp) -> Result<(), EmitError> {
    let supported = TargetStamp::system_v_amd64_v1();
    if target != supported {
        return Err(EmitError::UnsupportedTarget(UnsupportedTarget {
            target,
            supported_calling_convention: CallingConvention::SystemVAMD64V1,
        }));
    }
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
    fn extract<O: Operation>(program: &'a ValidatedProgram<O>) -> Result<Self, EmitError> {
        let raw = program.raw();
        let mut literal = None;
        let mut class = None;
        let mut suffix = None;
        let mut class_start_anchor = None;
        let mut suffix_end_anchor = None;
        for block in &raw.blocks {
            match block.op {
                BlockOp::ScanLiteral {
                    needle, anchors, ..
                } => literal = Some((needle, anchors)),
                BlockOp::ScanClassStart {
                    class: id,
                    anchored_start,
                    ..
                } => {
                    class = Some(id);
                    class_start_anchor = Some(anchored_start);
                }
                BlockOp::ConfirmSuffix {
                    suffix: id,
                    anchored_end,
                    ..
                } => {
                    suffix = Some(id);
                    suffix_end_anchor = Some(anchored_end);
                }
                _ => {}
            }
        }
        if let Some((id, anchors)) = literal {
            let bytes = data_bytes(raw, id.0)?;
            require_u32_length(bytes.len())?;
            return Ok(Self::Exact {
                literal: bytes,
                anchors,
            });
        }
        let class = data_class(
            raw,
            class.ok_or(UnsupportedKernel::MissingCanonicalOperation)?.0,
        )?;
        let suffix = data_bytes(
            raw,
            suffix
                .ok_or(UnsupportedKernel::MissingCanonicalOperation)?
                .0,
        )?;
        require_u32_length(suffix.len())?;
        Ok(Self::ClassSuffix {
            class,
            suffix,
            anchors: AnchorFlags {
                start: class_start_anchor.ok_or(UnsupportedKernel::MissingCanonicalOperation)?,
                end: suffix_end_anchor.ok_or(UnsupportedKernel::MissingCanonicalOperation)?,
            },
        })
    }

    const fn confirmation_length(self) -> usize {
        match self {
            Self::Exact { literal, .. } => literal.len(),
            Self::ClassSuffix { suffix, .. } => suffix.len(),
        }
    }

    fn shape(self) -> Result<KernelShape, EmitError> {
        Ok(match self {
            Self::Exact { literal, anchors } => KernelShape::ExactLiteral {
                literal_len: u32::try_from(literal.len())
                    .map_err(|_| UnsupportedKernel::LiteralTooLarge)?,
                anchors,
            },
            Self::ClassSuffix {
                class,
                suffix,
                anchors,
            } => KernelShape::DisjointClassSuffix {
                class_population: class_population(class),
                suffix_len: u32::try_from(suffix.len())
                    .map_err(|_| UnsupportedKernel::LiteralTooLarge)?,
                anchors,
            },
        })
    }
}

fn data_bytes(raw: &RawProgram, id: u32) -> Result<&[u8], EmitError> {
    let index = usize::try_from(id).map_err(|_| UnsupportedKernel::MissingData)?;
    match raw.data.get(index) {
        Some(DataBlob::Bytes(bytes)) => Ok(bytes),
        Some(DataBlob::ByteClass(_)) => Err(UnsupportedKernel::WrongDataKind.into()),
        None => Err(UnsupportedKernel::MissingData.into()),
    }
}

fn data_class(raw: &RawProgram, id: u32) -> Result<ByteClass, EmitError> {
    let index = usize::try_from(id).map_err(|_| UnsupportedKernel::MissingData)?;
    match raw.data.get(index) {
        Some(DataBlob::ByteClass(class)) => Ok(*class),
        Some(DataBlob::Bytes(_)) => Err(UnsupportedKernel::WrongDataKind.into()),
        None => Err(UnsupportedKernel::MissingData.into()),
    }
}

impl From<UnsupportedKernel> for EmitError {
    fn from(value: UnsupportedKernel) -> Self {
        Self::UnsupportedKernel(value)
    }
}

fn require_u32_length(length: usize) -> Result<(), EmitError> {
    u32::try_from(length)
        .map(|_| ())
        .map_err(|_| UnsupportedKernel::LiteralTooLarge.into())
}

const fn effective_tier(requested: FeatureTier, length: usize) -> FeatureTier {
    match requested {
        FeatureTier::Avx2 if length >= 32 => FeatureTier::Avx2,
        FeatureTier::Avx2 | FeatureTier::Sse2 if length > 16 => FeatureTier::Sse2,
        FeatureTier::Scalar | FeatureTier::Sse2 | FeatureTier::Avx2 => FeatureTier::Scalar,
    }
}

#[derive(Clone, Copy, Default)]
struct ConstantLayout {
    class_table: Option<u32>,
    pattern: Option<u32>,
}

fn build_constants(
    plan: &Plan<'_>,
    limits: &EmitLimits,
    meter: &mut WorkMeter,
) -> Result<(Vec<u8>, ConstantLayout), EmitError> {
    let (required, dense_class, long_pattern) = match *plan {
        Plan::Exact { literal, .. } => {
            let long = literal.len() > 16;
            (if long { literal.len() } else { 0 }, false, long)
        }
        Plan::ClassSuffix { class, suffix, .. } => {
            let dense = class_population(class) > 4;
            let class_bytes: usize = if dense { 256 } else { 0 };
            let suffix_bytes = if suffix.len() > 16 { suffix.len() } else { 0 };
            (
                class_bytes
                    .checked_add(suffix_bytes)
                    .ok_or(EmitError::ArithmeticOverflow)?,
                dense,
                suffix.len() > 16,
            )
        }
    };
    enforce(EmitResource::DataBytes, required, limits.max_data_bytes)?;
    let mut data = Vec::new();
    data.try_reserve_exact(required)
        .map_err(|_| EmitError::AllocationFailed {
            resource: EmitResource::DataBytes,
        })?;
    let mut layout = ConstantLayout::default();
    if dense_class {
        layout.class_table = Some(offset_u32(data.len())?);
        let Plan::ClassSuffix { class, .. } = *plan else {
            return Err(EmitError::InternalInvariant);
        };
        for byte in u8::MIN..=u8::MAX {
            meter.charge(1)?;
            data.push(u8::from(class.contains(byte)));
        }
    }
    if long_pattern {
        layout.pattern = Some(offset_u32(data.len())?);
        let pattern = match *plan {
            Plan::Exact { literal, .. } => literal,
            Plan::ClassSuffix { suffix, .. } => suffix,
        };
        meter.charge(usize_u64(pattern.len())?)?;
        data.extend_from_slice(pattern);
    }
    if data.len() != required {
        return Err(EmitError::InternalInvariant);
    }
    Ok((data, layout))
}

fn class_population(class: ByteClass) -> u16 {
    let population: u32 = class.lanes().iter().map(|lane| lane.count_ones()).sum();
    u16::try_from(population).expect("a byte class contains at most 256 bytes")
}

fn class_members(class: ByteClass) -> [u8; 4] {
    let mut members = [0_u8; 4];
    let mut length = 0_usize;
    for byte in u8::MIN..=u8::MAX {
        if class.contains(byte) && length < members.len() {
            members[length] = byte;
            length = length.checked_add(1).expect("four-slot array is guarded");
        }
    }
    members
}

#[derive(Clone, Copy, Default)]
struct BranchFixup {
    displacement_offset: usize,
    label: usize,
}

#[derive(Clone, Copy, Default)]
struct DataFixup {
    displacement_offset: usize,
    target_offset: u32,
}

#[derive(Clone, Copy)]
struct Label(usize);

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
            .ok_or(EmitError::ArithmeticOverflow)?;
        if required > self.limit {
            return Err(EmitError::ResourceLimit {
                resource: EmitResource::EmitWork,
                limit: self.limit,
                required,
            });
        }
        self.consumed = required;
        Ok(())
    }
}

struct Assembler<'a> {
    code: [u8; HARD_CODE_BYTES],
    code_len: usize,
    labels: [Option<usize>; HARD_LABELS],
    label_count: usize,
    branches: [BranchFixup; HARD_BRANCHES],
    branch_count: usize,
    data_fixups: [DataFixup; HARD_RELOCATIONS],
    relocation_count: usize,
    limits: EmitLimits,
    meter: &'a mut WorkMeter,
}

impl<'a> Assembler<'a> {
    const fn new(limits: EmitLimits, meter: &'a mut WorkMeter) -> Self {
        Self {
            code: [0; HARD_CODE_BYTES],
            code_len: 0,
            labels: [None; HARD_LABELS],
            label_count: 0,
            branches: [BranchFixup {
                displacement_offset: 0,
                label: 0,
            }; HARD_BRANCHES],
            branch_count: 0,
            data_fixups: [DataFixup {
                displacement_offset: 0,
                target_offset: 0,
            }; HARD_RELOCATIONS],
            relocation_count: 0,
            limits,
            meter,
        }
    }

    fn label(&mut self) -> Result<Label, EmitError> {
        if self.label_count == HARD_LABELS {
            return Err(EmitError::InternalInvariant);
        }
        let label = Label(self.label_count);
        self.label_count = self
            .label_count
            .checked_add(1)
            .ok_or(EmitError::ArithmeticOverflow)?;
        Ok(label)
    }

    fn bind(&mut self, label: Label) -> Result<(), EmitError> {
        let slot = self
            .labels
            .get_mut(label.0)
            .ok_or(EmitError::InternalInvariant)?;
        if slot.replace(self.code_len).is_some() {
            return Err(EmitError::DuplicateLabel);
        }
        Ok(())
    }

    fn bytes(&mut self, bytes: &[u8]) -> Result<(), EmitError> {
        self.meter.charge(usize_u64(bytes.len())?)?;
        let end = self
            .code_len
            .checked_add(bytes.len())
            .ok_or(EmitError::ArithmeticOverflow)?;
        if end > HARD_CODE_BYTES {
            return Err(EmitError::ResourceLimit {
                resource: EmitResource::CodeBytes,
                limit: u64::try_from(HARD_CODE_BYTES).expect("small constant"),
                required: usize_u64(end)?,
            });
        }
        self.code[self.code_len..end].copy_from_slice(bytes);
        self.code_len = end;
        Ok(())
    }

    fn u32(&mut self, value: u32) -> Result<(), EmitError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), EmitError> {
        self.bytes(&value.to_le_bytes())
    }

    fn branch(&mut self, opcode: &[u8], label: Label) -> Result<(), EmitError> {
        let required = self
            .branch_count
            .checked_add(1)
            .ok_or(EmitError::ArithmeticOverflow)?;
        enforce(
            EmitResource::InternalBranches,
            required,
            self.limits.max_internal_branches,
        )?;
        if required > HARD_BRANCHES {
            return Err(EmitError::InternalInvariant);
        }
        self.bytes(opcode)?;
        let displacement_offset = self.code_len;
        self.u32(0)?;
        self.branches[self.branch_count] = BranchFixup {
            displacement_offset,
            label: label.0,
        };
        self.branch_count = required;
        Ok(())
    }

    fn jmp(&mut self, label: Label) -> Result<(), EmitError> {
        self.branch(&[0xE9], label)
    }

    fn je(&mut self, label: Label) -> Result<(), EmitError> {
        self.branch(&[0x0F, 0x84], label)
    }

    fn jne(&mut self, label: Label) -> Result<(), EmitError> {
        self.branch(&[0x0F, 0x85], label)
    }

    fn ja(&mut self, label: Label) -> Result<(), EmitError> {
        self.branch(&[0x0F, 0x87], label)
    }

    fn jae(&mut self, label: Label) -> Result<(), EmitError> {
        self.branch(&[0x0F, 0x83], label)
    }

    fn jb(&mut self, label: Label) -> Result<(), EmitError> {
        self.branch(&[0x0F, 0x82], label)
    }

    fn jbe(&mut self, label: Label) -> Result<(), EmitError> {
        self.branch(&[0x0F, 0x86], label)
    }

    fn lea_rip(&mut self, prefix: &[u8], target_offset: u32) -> Result<(), EmitError> {
        let required = self
            .relocation_count
            .checked_add(1)
            .ok_or(EmitError::ArithmeticOverflow)?;
        enforce(
            EmitResource::Relocations,
            required,
            self.limits.max_relocations,
        )?;
        if required > HARD_RELOCATIONS {
            return Err(EmitError::InternalInvariant);
        }
        self.bytes(prefix)?;
        let displacement_offset = self.code_len;
        self.u32(0)?;
        self.data_fixups[self.relocation_count] = DataFixup {
            displacement_offset,
            target_offset,
        };
        self.relocation_count = required;
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "branch and relocation resolution form one auditable finalization transaction"
    )]
    fn finish(mut self, input: FinishInput<'_>) -> Result<NativeImage, EmitError> {
        enforce(
            EmitResource::CodeBytes,
            self.code_len,
            self.limits.max_code_bytes,
        )?;
        enforce(
            EmitResource::DataBytes,
            input.data.len(),
            self.limits.max_data_bytes,
        )?;
        let data_offset = align_up(self.code_len, input.data_alignment)?;
        let image_len = data_offset
            .checked_add(input.data.len())
            .ok_or(EmitError::ArithmeticOverflow)?;
        enforce(
            EmitResource::ImageBytes,
            image_len,
            self.limits.max_image_bytes,
        )?;
        let mut maximum_branch_displacement = 0_u64;
        for index in 0..self.branch_count {
            self.meter.charge(1)?;
            let fixup = self.branches[index];
            let target = self
                .labels
                .get(fixup.label)
                .copied()
                .flatten()
                .ok_or(EmitError::UnboundLabel)?;
            let next = fixup
                .displacement_offset
                .checked_add(4)
                .ok_or(EmitError::ArithmeticOverflow)?;
            let (displacement, magnitude) =
                relative_i32(target, next, EmitResource::BranchDisplacement)?;
            enforce_u64(
                EmitResource::BranchDisplacement,
                magnitude,
                self.limits.max_branch_displacement,
            )?;
            maximum_branch_displacement = maximum_branch_displacement.max(magnitude);
            patch_i32(&mut self.code, fixup.displacement_offset, displacement)?;
        }
        for label in self.labels.iter().take(self.label_count) {
            if label.is_none() {
                return Err(EmitError::UnboundLabel);
            }
        }
        let mut relocations = Vec::new();
        relocations
            .try_reserve_exact(self.relocation_count)
            .map_err(|_| EmitError::AllocationFailed {
                resource: EmitResource::Relocations,
            })?;
        let mut maximum_relocation_displacement = 0_u64;
        for index in 0..self.relocation_count {
            self.meter.charge(1)?;
            let fixup = self.data_fixups[index];
            let target = data_offset
                .checked_add(
                    usize::try_from(fixup.target_offset)
                        .map_err(|_| EmitError::ArithmeticOverflow)?,
                )
                .ok_or(EmitError::ArithmeticOverflow)?;
            let next = fixup
                .displacement_offset
                .checked_add(4)
                .ok_or(EmitError::ArithmeticOverflow)?;
            let (displacement, magnitude) =
                relative_i32(target, next, EmitResource::RelocationDisplacement)?;
            enforce_u64(
                EmitResource::RelocationDisplacement,
                magnitude,
                self.limits.max_relocation_displacement,
            )?;
            maximum_relocation_displacement = maximum_relocation_displacement.max(magnitude);
            patch_i32(&mut self.code, fixup.displacement_offset, displacement)?;
            relocations.push(Relocation {
                kind: RelocationKind::RipRelativeI32,
                source_section: Section::Code,
                displacement_offset: offset_u32(fixup.displacement_offset)?,
                target_section: Section::Data,
                target_offset: fixup.target_offset,
            });
        }
        let mut image = Vec::new();
        image
            .try_reserve_exact(image_len)
            .map_err(|_| EmitError::AllocationFailed {
                resource: EmitResource::ImageBytes,
            })?;
        self.meter.charge(usize_u64(image_len)?)?;
        image.extend_from_slice(&self.code[..self.code_len]);
        image.resize(data_offset, 0x90);
        image.extend_from_slice(input.data);
        let emit_work = self.meter.consumed;
        let stats = ImageStats {
            code_bytes: self.code_len,
            data_bytes: input.data.len(),
            image_bytes: image_len,
            padding_bytes: data_offset
                .checked_sub(self.code_len)
                .ok_or(EmitError::InternalInvariant)?,
            relocations: self.relocation_count,
            internal_branches: self.branch_count,
            maximum_branch_displacement,
            maximum_relocation_displacement,
            emit_work,
            emit_scratch_bytes: EMIT_SCRATCH_BYTES,
            runtime_work_factor: input.runtime_work_factor,
            runtime_scratch_bytes: 0,
        };
        Ok(NativeImage {
            stamp: input.stamp,
            output: input.output,
            shape: input.shape,
            kernel_identity: input.kernel_identity,
            entry_offset: 0,
            code_len: offset_u32(self.code_len)?,
            data_offset: offset_u32(data_offset)?,
            image: image.into_boxed_slice(),
            relocations: relocations.into_boxed_slice(),
            stats,
        })
    }
}

#[derive(Clone, Copy)]
struct FinishInput<'a> {
    data: &'a [u8],
    data_alignment: usize,
    shape: KernelShape,
    output: fre_kernel_ir::OutputKind,
    kernel_identity: fre_kernel_ir::CacheIdentity,
    stamp: X86AbiStamp,
    runtime_work_factor: u64,
}

fn emit_prologue(assembler: &mut Assembler<'_>, invalid: Label) -> Result<(), EmitError> {
    // cmp rdx,rcx; ja invalid; cmp rcx,rsi; ja invalid
    assembler.bytes(&[0x48, 0x39, 0xCA])?;
    assembler.ja(invalid)?;
    assembler.bytes(&[0x48, 0x39, 0xF1])?;
    assembler.ja(invalid)
}

fn emit_exact(
    assembler: &mut Assembler<'_>,
    literal: &[u8],
    anchors: AnchorFlags,
    pattern_offset: Option<u32>,
    tier: FeatureTier,
) -> Result<(), EmitError> {
    let invalid = assembler.label()?;
    let none = assembler.label()?;
    let found = assembler.label()?;
    let compare = assembler.label()?;
    let reject = assembler.label()?;
    emit_prologue(assembler, invalid)?;
    emit_mov_r11_u64(assembler, usize_u64(literal.len())?)?;
    if anchors.start {
        // test rdx,rdx; jne none
        assembler.bytes(&[0x48, 0x85, 0xD2])?;
        assembler.jne(none)?;
        // width = window_end - window_start; require width >= literal length.
        assembler.bytes(&[0x49, 0x89, 0xCA])?; // mov r10,rcx
        assembler.bytes(&[0x49, 0x29, 0xD2])?; // sub r10,rdx
        assembler.bytes(&[0x4D, 0x39, 0xDA])?; // cmp r10,r11
        assembler.jb(none)?;
        if anchors.end {
            assembler.bytes(&[0x4C, 0x39, 0xDE])?; // cmp rsi,r11
            assembler.jne(none)?;
        }
        assembler.bytes(&[0x45, 0x31, 0xC9])?; // xor r9d,r9d
    } else if anchors.end {
        assembler.bytes(&[0x48, 0x39, 0xF1])?; // cmp rcx,rsi
        assembler.jne(none)?;
        assembler.bytes(&[0x49, 0x89, 0xCA])?; // mov r10,rcx
        assembler.bytes(&[0x49, 0x29, 0xD2])?; // sub r10,rdx
        assembler.bytes(&[0x4D, 0x39, 0xDA])?; // cmp r10,r11
        assembler.jb(none)?;
        assembler.bytes(&[0x49, 0x89, 0xF1])?; // mov r9,rsi
        assembler.bytes(&[0x4D, 0x29, 0xD9])?; // sub r9,r11
    } else {
        assembler.bytes(&[0x49, 0x89, 0xCA])?; // mov r10,rcx
        assembler.bytes(&[0x49, 0x29, 0xD2])?; // sub r10,rdx
        assembler.bytes(&[0x4D, 0x39, 0xDA])?; // cmp r10,r11
        assembler.jb(none)?;
        assembler.bytes(&[0x49, 0x89, 0xCA])?; // mov r10,rcx
        assembler.bytes(&[0x4D, 0x29, 0xDA])?; // sub r10,r11
        assembler.bytes(&[0x49, 0x89, 0xD1])?; // mov r9,rdx
    }
    assembler.bind(compare)?;
    emit_exact_confirmation(assembler, literal, pattern_offset, tier, reject)?;
    assembler.jmp(found)?;
    assembler.bind(reject)?;
    if anchors.start || anchors.end {
        assembler.jmp(none)?;
    } else {
        assembler.bytes(&[0x49, 0xFF, 0xC1])?; // inc r9
        assembler.bytes(&[0x4D, 0x39, 0xD1])?; // cmp r9,r10
        assembler.jbe(compare)?;
        assembler.jmp(none)?;
    }
    assembler.bind(found)?;
    assembler.bytes(&[0x4D, 0x89, 0x08])?; // mov [r8],r9
    assembler.bytes(&[0x4C, 0x89, 0xC9])?; // mov rcx,r9
    emit_mov_r11_u64(assembler, usize_u64(literal.len())?)?;
    assembler.bytes(&[0x4C, 0x01, 0xD9])?; // add rcx,r11
    assembler.bytes(&[0x49, 0x89, 0x48, 0x08])?; // mov [r8+8],rcx
    emit_status_return(assembler, 1, tier)?;
    assembler.bind(none)?;
    emit_zero_return(assembler, 0, tier)?;
    assembler.bind(invalid)?;
    emit_zero_return(assembler, 2, tier)
}

fn emit_class_suffix(
    assembler: &mut Assembler<'_>,
    class: ByteClass,
    suffix: &[u8],
    anchors: AnchorFlags,
    constants: ConstantLayout,
    tier: FeatureTier,
) -> Result<(), EmitError> {
    let invalid = assembler.label()?;
    let none = assembler.label()?;
    let scan = assembler.label()?;
    let member = assembler.label()?;
    let extend = assembler.label()?;
    let extend_member = assembler.label()?;
    let confirm = assembler.label()?;
    let reject = assembler.label()?;
    let found = assembler.label()?;
    emit_prologue(assembler, invalid)?;
    assembler.bytes(&[0x49, 0x89, 0xD1])?; // mov r9,rdx
    assembler.bind(scan)?;
    if anchors.start {
        assembler.bytes(&[0x4D, 0x85, 0xC9])?; // test r9,r9
        assembler.jne(none)?;
    }
    assembler.bytes(&[0x49, 0x39, 0xC9])?; // cmp r9,rcx
    assembler.jae(none)?;
    emit_class_test(
        assembler,
        class,
        constants.class_table,
        IndexRegister::R9,
        member,
    )?;
    if anchors.start {
        assembler.jmp(none)?;
    } else {
        assembler.bytes(&[0x49, 0xFF, 0xC1])?; // inc r9
        assembler.jmp(scan)?;
    }
    assembler.bind(member)?;
    assembler.bytes(&[0x4D, 0x89, 0xCA])?; // mov r10,r9
    assembler.bytes(&[0x4D, 0x8D, 0x59, 0x01])?; // lea r11,[r9+1]
    assembler.bind(extend)?;
    assembler.bytes(&[0x49, 0x39, 0xCB])?; // cmp r11,rcx
    assembler.jae(confirm)?;
    emit_class_test(
        assembler,
        class,
        constants.class_table,
        IndexRegister::R11,
        extend_member,
    )?;
    assembler.jmp(confirm)?;
    assembler.bind(extend_member)?;
    assembler.bytes(&[0x49, 0xFF, 0xC3])?; // inc r11
    assembler.jmp(extend)?;
    assembler.bind(confirm)?;
    assembler.bytes(&[0x48, 0x89, 0xC8])?; // mov rax,rcx
    assembler.bytes(&[0x4C, 0x29, 0xD8])?; // sub rax,r11
    emit_mov_rdx_u64(assembler, usize_u64(suffix.len())?)?;
    assembler.bytes(&[0x48, 0x39, 0xD0])?; // cmp rax,rdx
    assembler.jb(reject)?;
    if anchors.end {
        assembler.bytes(&[0x4C, 0x89, 0xD8])?; // mov rax,r11
        assembler.bytes(&[0x48, 0x01, 0xD0])?; // add rax,rdx
        assembler.bytes(&[0x48, 0x39, 0xF0])?; // cmp rax,rsi
        assembler.jne(reject)?;
    }
    emit_class_confirmation(assembler, suffix, constants.pattern, tier, reject)?;
    assembler.jmp(found)?;
    assembler.bind(reject)?;
    assembler.bytes(&[0x4D, 0x89, 0xD9])?; // mov r9,r11
    assembler.jmp(scan)?;
    assembler.bind(found)?;
    assembler.bytes(&[0x4D, 0x89, 0x10])?; // mov [r8],r10
    assembler.bytes(&[0x4C, 0x89, 0xD8])?; // mov rax,r11
    emit_mov_rdx_u64(assembler, usize_u64(suffix.len())?)?;
    assembler.bytes(&[0x48, 0x01, 0xD0])?; // add rax,rdx
    assembler.bytes(&[0x49, 0x89, 0x40, 0x08])?; // mov [r8+8],rax
    emit_status_return(assembler, 1, tier)?;
    assembler.bind(none)?;
    emit_zero_return(assembler, 0, tier)?;
    assembler.bind(invalid)?;
    emit_zero_return(assembler, 2, tier)
}

#[derive(Clone, Copy)]
enum IndexRegister {
    R9,
    R11,
}

fn emit_class_test(
    assembler: &mut Assembler<'_>,
    class: ByteClass,
    table: Option<u32>,
    index: IndexRegister,
    member: Label,
) -> Result<(), EmitError> {
    let load = match index {
        IndexRegister::R9 => &[0x42, 0x0F, 0xB6, 0x04, 0x0F][..],
        IndexRegister::R11 => &[0x42, 0x0F, 0xB6, 0x04, 0x1F][..],
    };
    assembler.bytes(load)?; // movzx eax,[rdi+index]
    if let Some(offset) = table {
        assembler.lea_rip(&[0x48, 0x8D, 0x15], offset)?; // lea rdx,[rip+table]
        assembler.bytes(&[0x80, 0x3C, 0x02, 0x00])?; // cmp byte [rdx+rax],0
        assembler.jne(member)?;
        return Ok(());
    }
    let members = class_members(class);
    let population = usize::from(class_population(class));
    if population > members.len() {
        return Err(EmitError::InternalInvariant);
    }
    for byte in members.into_iter().take(population) {
        assembler.bytes(&[0x3C, byte])?; // cmp al,imm8
        assembler.je(member)?;
    }
    Ok(())
}

fn emit_exact_confirmation(
    assembler: &mut Assembler<'_>,
    literal: &[u8],
    pattern_offset: Option<u32>,
    tier: FeatureTier,
    reject: Label,
) -> Result<(), EmitError> {
    if literal.len() <= 16 {
        return emit_inline_confirmation(assembler, literal, CandidateIndex::R9, reject);
    }
    let offset = pattern_offset.ok_or(EmitError::InternalInvariant)?;
    assembler.bytes(&[0x4A, 0x8D, 0x04, 0x0F])?; // lea rax,[rdi+r9]
    // R10 remains the last legal candidate across a rejected confirmation.
    assembler.lea_rip(&[0x48, 0x8D, 0x15], offset)?; // lea rdx,[rip+pattern]
    match tier {
        FeatureTier::Scalar => emit_scalar_exact_loop(assembler, literal.len(), reject),
        FeatureTier::Sse2 => emit_sse_exact_loop(assembler, literal.len(), reject),
        FeatureTier::Avx2 => emit_avx_exact_loop(assembler, literal.len(), reject),
    }
}

fn emit_class_confirmation(
    assembler: &mut Assembler<'_>,
    suffix: &[u8],
    pattern_offset: Option<u32>,
    tier: FeatureTier,
    reject: Label,
) -> Result<(), EmitError> {
    if suffix.len() <= 16 {
        return emit_inline_confirmation(assembler, suffix, CandidateIndex::R11, reject);
    }
    let offset = pattern_offset.ok_or(EmitError::InternalInvariant)?;
    assembler.bytes(&[0x4A, 0x8D, 0x04, 0x1F])?; // lea rax,[rdi+r11]
    assembler.lea_rip(&[0x48, 0x8D, 0x15], offset)?; // lea rdx,[rip+pattern]
    match tier {
        FeatureTier::Scalar => emit_scalar_class_loop(assembler, suffix.len(), reject),
        FeatureTier::Sse2 => emit_sse_class_loop(assembler, suffix.len(), reject),
        FeatureTier::Avx2 => emit_avx_class_loop(assembler, suffix.len(), reject),
    }
}

#[derive(Clone, Copy)]
enum CandidateIndex {
    R9,
    R11,
}

fn emit_inline_confirmation(
    assembler: &mut Assembler<'_>,
    bytes: &[u8],
    index: CandidateIndex,
    reject: Label,
) -> Result<(), EmitError> {
    match bytes.len() {
        0 => Ok(()),
        1 => emit_inline_piece(assembler, bytes, 0, 1, index, reject),
        2 => emit_inline_piece(assembler, bytes, 0, 2, index, reject),
        3 => {
            emit_inline_piece(assembler, bytes, 0, 2, index, reject)?;
            emit_inline_piece(assembler, bytes, 2, 1, index, reject)
        }
        4 => emit_inline_piece(assembler, bytes, 0, 4, index, reject),
        5..=7 => {
            emit_inline_piece(assembler, bytes, 0, 4, index, reject)?;
            let offset = bytes
                .len()
                .checked_sub(4)
                .ok_or(EmitError::InternalInvariant)?;
            emit_inline_piece(assembler, bytes, offset, 4, index, reject)
        }
        8 => emit_inline_piece(assembler, bytes, 0, 8, index, reject),
        9..=15 => {
            emit_inline_piece(assembler, bytes, 0, 8, index, reject)?;
            let offset = bytes
                .len()
                .checked_sub(8)
                .ok_or(EmitError::InternalInvariant)?;
            emit_inline_piece(assembler, bytes, offset, 8, index, reject)
        }
        16 => {
            emit_inline_piece(assembler, bytes, 0, 8, index, reject)?;
            emit_inline_piece(assembler, bytes, 8, 8, index, reject)
        }
        _ => Err(EmitError::InternalInvariant),
    }
}

fn emit_inline_piece(
    assembler: &mut Assembler<'_>,
    bytes: &[u8],
    offset: usize,
    width: usize,
    index: CandidateIndex,
    reject: Label,
) -> Result<(), EmitError> {
    let end = offset
        .checked_add(width)
        .ok_or(EmitError::ArithmeticOverflow)?;
    let piece = bytes.get(offset..end).ok_or(EmitError::InternalInvariant)?;
    if width == 8 {
        let value = u64::from_le_bytes(piece.try_into().map_err(|_| EmitError::InternalInvariant)?);
        match index {
            CandidateIndex::R9 => emit_mov_r11_u64(assembler, value)?,
            CandidateIndex::R11 => {
                assembler.bytes(&[0x49, 0xB9])?; // mov r9,imm64; preserves run end
                assembler.u64(value)?;
            }
        }
    } else {
        let mut value = [0_u8; 4];
        value[..width].copy_from_slice(piece);
        assembler.bytes(match index {
            CandidateIndex::R9 => &[0x41, 0xBB],  // mov r11d,imm32
            CandidateIndex::R11 => &[0x41, 0xB9], // mov r9d,imm32
        })?;
        assembler.u32(u32::from_le_bytes(value))?;
    }
    let displacement = u8::try_from(offset).map_err(|_| EmitError::InternalInvariant)?;
    let sib = match index {
        CandidateIndex::R9 => 0x0F,
        CandidateIndex::R11 => 0x1F,
    };
    let (plain_modrm, displaced_modrm) = match index {
        CandidateIndex::R9 => (0x1C, 0x5C),  // compare against r11
        CandidateIndex::R11 => (0x0C, 0x4C), // compare against r9
    };
    match (width, offset) {
        (1, 0) => assembler.bytes(&[0x46, 0x38, plain_modrm, sib])?,
        (2, 0) => assembler.bytes(&[0x66, 0x46, 0x39, plain_modrm, sib])?,
        (4, 0) => assembler.bytes(&[0x46, 0x39, plain_modrm, sib])?,
        (8, 0) => assembler.bytes(&[0x4E, 0x39, plain_modrm, sib])?,
        (1, _) => assembler.bytes(&[0x46, 0x38, displaced_modrm, sib, displacement])?,
        (2, _) => assembler.bytes(&[0x66, 0x46, 0x39, displaced_modrm, sib, displacement])?,
        (4, _) => assembler.bytes(&[0x46, 0x39, displaced_modrm, sib, displacement])?,
        (8, _) => assembler.bytes(&[0x4E, 0x39, displaced_modrm, sib, displacement])?,
        _ => return Err(EmitError::InternalInvariant),
    }
    assembler.jne(reject)
}

fn emit_scalar_exact_loop(
    assembler: &mut Assembler<'_>,
    length: usize,
    reject: Label,
) -> Result<(), EmitError> {
    let loop_label = assembler.label()?;
    emit_mov_rcx_u64(assembler, usize_u64(length)?)?;
    assembler.bind(loop_label)?;
    assembler.bytes(&[0x0F, 0xB6, 0x32])?; // movzx esi,[rdx]
    assembler.bytes(&[0x40, 0x38, 0x30])?; // cmp [rax],sil
    assembler.jne(reject)?;
    assembler.bytes(&[0x48, 0xFF, 0xC0])?; // inc rax
    assembler.bytes(&[0x48, 0xFF, 0xC2])?; // inc rdx
    assembler.bytes(&[0x48, 0xFF, 0xC9])?; // dec rcx
    assembler.jne(loop_label)
}

fn emit_sse_exact_loop(
    assembler: &mut Assembler<'_>,
    length: usize,
    reject: Label,
) -> Result<(), EmitError> {
    let chunks = length / 16;
    let tail = length % 16;
    let loop_label = assembler.label()?;
    emit_mov_rcx_u64(assembler, usize_u64(chunks)?)?;
    assembler.bind(loop_label)?;
    emit_sse_compare_exact(assembler, reject)?;
    assembler.bytes(&[0x48, 0x83, 0xC0, 0x10])?; // add rax,16
    assembler.bytes(&[0x48, 0x83, 0xC2, 0x10])?; // add rdx,16
    assembler.bytes(&[0x48, 0xFF, 0xC9])?; // dec rcx
    assembler.jne(loop_label)?;
    emit_scalar_exact_tail(assembler, tail, reject)
}

fn emit_avx_exact_loop(
    assembler: &mut Assembler<'_>,
    length: usize,
    reject: Label,
) -> Result<(), EmitError> {
    let chunks = length / 32;
    let tail = length % 32;
    let loop_label = assembler.label()?;
    emit_mov_rcx_u64(assembler, usize_u64(chunks)?)?;
    assembler.bind(loop_label)?;
    emit_avx_compare_exact(assembler, reject)?;
    assembler.bytes(&[0x48, 0x83, 0xC0, 0x20])?;
    assembler.bytes(&[0x48, 0x83, 0xC2, 0x20])?;
    assembler.bytes(&[0x48, 0xFF, 0xC9])?;
    assembler.jne(loop_label)?;
    emit_scalar_exact_tail(assembler, tail, reject)
}

fn emit_scalar_exact_tail(
    assembler: &mut Assembler<'_>,
    tail: usize,
    reject: Label,
) -> Result<(), EmitError> {
    if tail == 0 {
        return Ok(());
    }
    let loop_label = assembler.label()?;
    emit_mov_rcx_u64(assembler, usize_u64(tail)?)?;
    assembler.bind(loop_label)?;
    assembler.bytes(&[0x0F, 0xB6, 0x32])?;
    assembler.bytes(&[0x40, 0x38, 0x30])?;
    assembler.jne(reject)?;
    assembler.bytes(&[0x48, 0xFF, 0xC0])?;
    assembler.bytes(&[0x48, 0xFF, 0xC2])?;
    assembler.bytes(&[0x48, 0xFF, 0xC9])?;
    assembler.jne(loop_label)
}

fn emit_sse_compare_exact(assembler: &mut Assembler<'_>, reject: Label) -> Result<(), EmitError> {
    assembler.bytes(&[0xF3, 0x0F, 0x6F, 0x00])?; // movdqu xmm0,[rax]
    assembler.bytes(&[0xF3, 0x0F, 0x6F, 0x0A])?; // movdqu xmm1,[rdx]
    assembler.bytes(&[0x66, 0x0F, 0x74, 0xC1])?; // pcmpeqb xmm0,xmm1
    assembler.bytes(&[0x66, 0x0F, 0xD7, 0xF0])?; // pmovmskb esi,xmm0
    assembler.bytes(&[0x81, 0xFE, 0xFF, 0xFF, 0x00, 0x00])?;
    assembler.jne(reject)
}

fn emit_avx_compare_exact(assembler: &mut Assembler<'_>, reject: Label) -> Result<(), EmitError> {
    assembler.bytes(&[0xC5, 0xFE, 0x6F, 0x00])?; // vmovdqu ymm0,[rax]
    assembler.bytes(&[0xC5, 0xFD, 0x74, 0x02])?; // vpcmpeqb ymm0,ymm0,[rdx]
    assembler.bytes(&[0xC5, 0xFD, 0xD7, 0xF0])?; // vpmovmskb esi,ymm0
    assembler.bytes(&[0x83, 0xFE, 0xFF])?; // cmp esi,-1
    assembler.jne(reject)
}

fn emit_scalar_class_loop(
    assembler: &mut Assembler<'_>,
    length: usize,
    reject: Label,
) -> Result<(), EmitError> {
    let loop_label = assembler.label()?;
    assembler.bytes(&[0x49, 0x89, 0xC1])?; // mov r9,rax (candidate pointer)
    emit_mov_rax_u64(assembler, usize_u64(length)?)?;
    assembler.bind(loop_label)?;
    assembler.bytes(&[0x0F, 0xB6, 0x32])?; // movzx esi,[rdx]
    assembler.bytes(&[0x41, 0x38, 0x31])?; // cmp [r9],sil
    assembler.jne(reject)?;
    assembler.bytes(&[0x49, 0xFF, 0xC1])?;
    assembler.bytes(&[0x48, 0xFF, 0xC2])?;
    assembler.bytes(&[0x48, 0xFF, 0xC8])?;
    assembler.jne(loop_label)
}

fn emit_sse_class_loop(
    assembler: &mut Assembler<'_>,
    length: usize,
    reject: Label,
) -> Result<(), EmitError> {
    let chunks = length / 16;
    let tail = length % 16;
    let loop_label = assembler.label()?;
    assembler.bytes(&[0x49, 0x89, 0xC1])?; // mov r9,rax
    emit_mov_rax_u64(assembler, usize_u64(chunks)?)?;
    assembler.bind(loop_label)?;
    emit_sse_compare_class(assembler, reject)?;
    assembler.bytes(&[0x49, 0x83, 0xC1, 0x10])?;
    assembler.bytes(&[0x48, 0x83, 0xC2, 0x10])?;
    assembler.bytes(&[0x48, 0xFF, 0xC8])?;
    assembler.jne(loop_label)?;
    emit_scalar_class_tail(assembler, tail, reject)
}

fn emit_avx_class_loop(
    assembler: &mut Assembler<'_>,
    length: usize,
    reject: Label,
) -> Result<(), EmitError> {
    let chunks = length / 32;
    let tail = length % 32;
    let loop_label = assembler.label()?;
    assembler.bytes(&[0x49, 0x89, 0xC1])?;
    emit_mov_rax_u64(assembler, usize_u64(chunks)?)?;
    assembler.bind(loop_label)?;
    emit_avx_compare_class(assembler, reject)?;
    assembler.bytes(&[0x49, 0x83, 0xC1, 0x20])?;
    assembler.bytes(&[0x48, 0x83, 0xC2, 0x20])?;
    assembler.bytes(&[0x48, 0xFF, 0xC8])?;
    assembler.jne(loop_label)?;
    emit_scalar_class_tail(assembler, tail, reject)
}

fn emit_scalar_class_tail(
    assembler: &mut Assembler<'_>,
    tail: usize,
    reject: Label,
) -> Result<(), EmitError> {
    if tail == 0 {
        return Ok(());
    }
    let loop_label = assembler.label()?;
    emit_mov_rax_u64(assembler, usize_u64(tail)?)?;
    assembler.bind(loop_label)?;
    assembler.bytes(&[0x0F, 0xB6, 0x32])?;
    assembler.bytes(&[0x41, 0x38, 0x31])?;
    assembler.jne(reject)?;
    assembler.bytes(&[0x49, 0xFF, 0xC1])?;
    assembler.bytes(&[0x48, 0xFF, 0xC2])?;
    assembler.bytes(&[0x48, 0xFF, 0xC8])?;
    assembler.jne(loop_label)
}

fn emit_sse_compare_class(assembler: &mut Assembler<'_>, reject: Label) -> Result<(), EmitError> {
    assembler.bytes(&[0xF3, 0x41, 0x0F, 0x6F, 0x01])?; // movdqu xmm0,[r9]
    assembler.bytes(&[0xF3, 0x0F, 0x6F, 0x0A])?; // movdqu xmm1,[rdx]
    assembler.bytes(&[0x66, 0x0F, 0x74, 0xC1])?;
    assembler.bytes(&[0x66, 0x0F, 0xD7, 0xF0])?; // pmovmskb esi,xmm0
    assembler.bytes(&[0x81, 0xFE, 0xFF, 0xFF, 0x00, 0x00])?;
    assembler.jne(reject)
}

fn emit_avx_compare_class(assembler: &mut Assembler<'_>, reject: Label) -> Result<(), EmitError> {
    assembler.bytes(&[0xC4, 0xC1, 0x7E, 0x6F, 0x01])?; // vmovdqu ymm0,[r9]
    assembler.bytes(&[0xC5, 0xFD, 0x74, 0x02])?; // vpcmpeqb ymm0,ymm0,[rdx]
    assembler.bytes(&[0xC5, 0xFD, 0xD7, 0xF0])?; // vpmovmskb esi,ymm0
    assembler.bytes(&[0x83, 0xFE, 0xFF])?;
    assembler.jne(reject)
}

fn emit_status_return(
    assembler: &mut Assembler<'_>,
    status: u32,
    tier: FeatureTier,
) -> Result<(), EmitError> {
    assembler.bytes(&[0xB8])?;
    assembler.u32(status)?;
    emit_cleanup(assembler, tier)?;
    assembler.bytes(&[0xC3])
}

fn emit_zero_return(
    assembler: &mut Assembler<'_>,
    status: u32,
    tier: FeatureTier,
) -> Result<(), EmitError> {
    assembler.bytes(&[0x31, 0xC0])?; // xor eax,eax
    assembler.bytes(&[0x49, 0x89, 0x00])?; // mov [r8],rax
    assembler.bytes(&[0x49, 0x89, 0x40, 0x08])?; // mov [r8+8],rax
    if status != 0 {
        assembler.bytes(&[0xB8])?;
        assembler.u32(status)?;
    }
    emit_cleanup(assembler, tier)?;
    assembler.bytes(&[0xC3])
}

fn emit_cleanup(assembler: &mut Assembler<'_>, tier: FeatureTier) -> Result<(), EmitError> {
    if tier == FeatureTier::Avx2 {
        assembler.bytes(&[0xC5, 0xF8, 0x77])?; // vzeroupper
    }
    Ok(())
}

fn emit_mov_r11_u64(assembler: &mut Assembler<'_>, value: u64) -> Result<(), EmitError> {
    assembler.bytes(&[0x49, 0xBB])?;
    assembler.u64(value)
}

fn emit_mov_rcx_u64(assembler: &mut Assembler<'_>, value: u64) -> Result<(), EmitError> {
    assembler.bytes(&[0x48, 0xB9])?;
    assembler.u64(value)
}

fn emit_mov_rdx_u64(assembler: &mut Assembler<'_>, value: u64) -> Result<(), EmitError> {
    assembler.bytes(&[0x48, 0xBA])?;
    assembler.u64(value)
}

fn emit_mov_rax_u64(assembler: &mut Assembler<'_>, value: u64) -> Result<(), EmitError> {
    assembler.bytes(&[0x48, 0xB8])?;
    assembler.u64(value)
}

fn relative_i32(
    target: usize,
    next: usize,
    resource: EmitResource,
) -> Result<(i32, u64), EmitError> {
    let target = i128::try_from(target).map_err(|_| EmitError::ArithmeticOverflow)?;
    let next = i128::try_from(next).map_err(|_| EmitError::ArithmeticOverflow)?;
    let displacement = target
        .checked_sub(next)
        .ok_or(EmitError::ArithmeticOverflow)?;
    let magnitude =
        u64::try_from(displacement.unsigned_abs()).map_err(|_| EmitError::ArithmeticOverflow)?;
    let displacement = i32::try_from(displacement).map_err(|_| EmitError::ResourceLimit {
        resource,
        limit: i32::MAX.unsigned_abs().into(),
        required: magnitude,
    })?;
    Ok((displacement, magnitude))
}

fn patch_i32(code: &mut [u8; HARD_CODE_BYTES], offset: usize, value: i32) -> Result<(), EmitError> {
    let end = offset.checked_add(4).ok_or(EmitError::ArithmeticOverflow)?;
    let destination = code
        .get_mut(offset..end)
        .ok_or(EmitError::InternalInvariant)?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn align_up(value: usize, alignment: usize) -> Result<usize, EmitError> {
    if !alignment.is_power_of_two() {
        return Err(EmitError::InternalInvariant);
    }
    let mask = alignment
        .checked_sub(1)
        .ok_or(EmitError::InternalInvariant)?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(EmitError::ArithmeticOverflow)
}

fn offset_u32(value: usize) -> Result<u32, EmitError> {
    u32::try_from(value).map_err(|_| EmitError::ArithmeticOverflow)
}

fn usize_u64(value: usize) -> Result<u64, EmitError> {
    u64::try_from(value).map_err(|_| EmitError::ArithmeticOverflow)
}

fn enforce(resource: EmitResource, required: usize, limit: u64) -> Result<(), EmitError> {
    enforce_u64(resource, usize_u64(required)?, limit)
}

const fn enforce_u64(resource: EmitResource, required: u64, limit: u64) -> Result<(), EmitError> {
    if required > limit {
        return Err(EmitError::ResourceLimit {
            resource,
            limit,
            required,
        });
    }
    Ok(())
}
