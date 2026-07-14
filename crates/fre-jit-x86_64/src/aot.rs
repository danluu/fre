use fre_kernel_ir::{AnchorFlags, OutputKind};

use crate::{
    AotError, Architecture, CallingConvention, EmitResource, FeatureTier, KernelShape, NativeImage,
    RelocationKind, Section, TargetStamp, X86AbiStamp,
};

const MAGIC: &[u8; 8] = b"FREX64\0\x01";
const FORMAT_VERSION: u16 = 1;
const HEADER_BYTES: usize = 82;
const RELOCATION_BYTES: usize = 12;
const AOT_SCRATCH_BYTES: usize = 128;

/// Bounds for deterministic AOT-container construction and inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotLimits {
    pub max_bytes: u64,
    pub max_work: u64,
    pub max_scratch_bytes: u64,
}

impl Default for AotLimits {
    fn default() -> Self {
        Self {
            max_bytes: (1 << 20) + 16_384,
            max_work: 4 << 20,
            max_scratch_bytes: u64::try_from(AOT_SCRATCH_BYTES).expect("small constant"),
        }
    }
}

/// Parsed, endian-stable header of a FRE x86-64 AOT image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotHeader {
    pub format_version: u16,
    pub stamp: X86AbiStamp,
    pub output: OutputKind,
    pub entry_offset: u32,
    pub code_len: u32,
    pub data_offset: u32,
    pub image_len: u32,
    pub relocation_count: u32,
    pub kernel_identity: [u8; 32],
    pub kernel_shape: KernelShape,
}

/// Deterministic cache/AOT container. It is not an ELF, Mach-O or COFF file.
/// OS object wrappers must preserve the contained image layout and manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AotArtifact {
    bytes: Box<[u8]>,
    header: AotHeader,
}

impl AotArtifact {
    /// Serialize an already-audited native image without executable memory.
    pub fn from_image(image: &NativeImage, limits: AotLimits) -> Result<Self, AotError> {
        enforce_scratch(limits.max_scratch_bytes)?;
        let relocation_bytes = image
            .relocations()
            .len()
            .checked_mul(RELOCATION_BYTES)
            .ok_or(AotError::ArithmeticOverflow)?;
        let required = HEADER_BYTES
            .checked_add(relocation_bytes)
            .and_then(|size| size.checked_add(image.image_bytes().len()))
            .ok_or(AotError::ArithmeticOverflow)?;
        enforce(
            EmitResource::AotBytes,
            usize_u64(required)?,
            limits.max_bytes,
        )?;
        // One charge for each output byte plus each relocation validation.
        let work = usize_u64(required)?
            .checked_add(usize_u64(image.relocations().len())?)
            .ok_or(AotError::ArithmeticOverflow)?;
        enforce(EmitResource::AotWork, work, limits.max_work)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(required)
            .map_err(|_| AotError::AllocationFailed)?;
        let header = header_from_image(image)?;
        put_header(&mut bytes, header);
        for relocation in image.relocations() {
            bytes.push(relocation_tag(relocation.kind));
            bytes.push(section_tag(relocation.source_section));
            bytes.push(section_tag(relocation.target_section));
            bytes.push(0);
            bytes.extend_from_slice(&relocation.displacement_offset.to_le_bytes());
            bytes.extend_from_slice(&relocation.target_offset.to_le_bytes());
        }
        bytes.extend_from_slice(image.image_bytes());
        if bytes.len() != required {
            return Err(AotError::ArithmeticOverflow);
        }
        Ok(Self {
            bytes: bytes.into_boxed_slice(),
            header,
        })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn header(&self) -> AotHeader {
        self.header
    }
}

/// Inspect and length-check an AOT container without publishing it.
#[expect(
    clippy::too_many_lines,
    reason = "the fixed endian-stable header is decoded linearly so every field remains visible"
)]
pub fn inspect_aot(bytes: &[u8], limits: AotLimits) -> Result<AotHeader, AotError> {
    enforce_scratch(limits.max_scratch_bytes)?;
    enforce(
        EmitResource::AotBytes,
        usize_u64(bytes.len())?,
        limits.max_bytes,
    )?;
    enforce(
        EmitResource::AotWork,
        usize_u64(bytes.len())?,
        limits.max_work,
    )?;
    if bytes.len() < HEADER_BYTES {
        return Err(AotError::Truncated);
    }
    if bytes.get(..8) != Some(MAGIC) {
        return Err(AotError::InvalidMagic);
    }
    let version = read_u16(bytes, 8)?;
    if version != FORMAT_VERSION {
        return Err(AotError::UnsupportedVersion { actual: version });
    }
    let architecture = match byte(bytes, 10)? {
        1 => Architecture::X86_64,
        _ => return Err(AotError::InvalidField),
    };
    let calling_convention = match byte(bytes, 11)? {
        1 => CallingConvention::SystemVAMD64V1,
        2 => CallingConvention::WindowsX64V1,
        _ => return Err(AotError::InvalidField),
    };
    let pointer_width = byte(bytes, 12)?;
    let little_endian = match byte(bytes, 13)? {
        1 => true,
        0 => false,
        _ => return Err(AotError::InvalidField),
    };
    let requested_tier = tier(byte(bytes, 14)?)?;
    let used_tier = tier(byte(bytes, 15)?)?;
    let output = output(byte(bytes, 16)?)?;
    if byte(bytes, 17)? != 0 {
        return Err(AotError::InvalidField);
    }
    let kernel_abi_version = read_u16(bytes, 18)?;
    let kernel_semantics_version = read_u16(bytes, 20)?;
    let entry_offset = read_u32(bytes, 22)?;
    let code_len = read_u32(bytes, 26)?;
    let data_offset = read_u32(bytes, 30)?;
    let image_len = read_u32(bytes, 34)?;
    let relocation_count = read_u32(bytes, 38)?;
    let mut identity = [0_u8; 32];
    identity.copy_from_slice(bytes.get(42..74).ok_or(AotError::Truncated)?);
    let shape_tag = byte(bytes, 74)?;
    let anchor_bits = byte(bytes, 75)?;
    if anchor_bits & !3 != 0 {
        return Err(AotError::InvalidField);
    }
    let population = read_u16(bytes, 76)?;
    let pattern_len = read_u32(bytes, 78)?;
    let anchors = AnchorFlags {
        start: anchor_bits & 1 != 0,
        end: anchor_bits & 2 != 0,
    };
    let kernel_shape = match shape_tag {
        1 if population == 0 => KernelShape::ExactLiteral {
            literal_len: pattern_len,
            anchors,
        },
        2 if (1..=255).contains(&population) && pattern_len != 0 => {
            KernelShape::DisjointClassSuffix {
                class_population: population,
                suffix_len: pattern_len,
                anchors,
            }
        }
        _ => return Err(AotError::InvalidField),
    };
    let relocation_count_usize =
        usize::try_from(relocation_count).map_err(|_| AotError::InvalidField)?;
    let relocation_bytes = relocation_count_usize
        .checked_mul(RELOCATION_BYTES)
        .ok_or(AotError::ArithmeticOverflow)?;
    let image_start = HEADER_BYTES
        .checked_add(relocation_bytes)
        .ok_or(AotError::ArithmeticOverflow)?;
    let expected = image_start
        .checked_add(usize::try_from(image_len).map_err(|_| AotError::InvalidField)?)
        .ok_or(AotError::ArithmeticOverflow)?;
    if expected != bytes.len()
        || entry_offset >= code_len
        || code_len > data_offset
        || data_offset > image_len
    {
        return Err(AotError::InvalidField);
    }
    for index in 0..relocation_count_usize {
        let offset = HEADER_BYTES
            .checked_add(
                index
                    .checked_mul(RELOCATION_BYTES)
                    .ok_or(AotError::ArithmeticOverflow)?,
            )
            .ok_or(AotError::ArithmeticOverflow)?;
        let source_offset = checked_offset(offset, 1)?;
        let target_section_offset = checked_offset(offset, 2)?;
        let reserved_offset = checked_offset(offset, 3)?;
        let displacement_field = checked_offset(offset, 4)?;
        let target_field = checked_offset(offset, 8)?;
        if byte(bytes, offset)? != relocation_tag(RelocationKind::RipRelativeI32)
            || byte(bytes, source_offset)? != section_tag(Section::Code)
            || byte(bytes, target_section_offset)? != section_tag(Section::Data)
            || byte(bytes, reserved_offset)? != 0
        {
            return Err(AotError::InvalidField);
        }
        let displacement_offset = read_u32(bytes, displacement_field)?;
        let target_offset = read_u32(bytes, target_field)?;
        if displacement_offset
            .checked_add(4)
            .ok_or(AotError::ArithmeticOverflow)?
            > code_len
            || target_offset
                >= image_len
                    .checked_sub(data_offset)
                    .ok_or(AotError::InvalidField)?
        {
            return Err(AotError::InvalidField);
        }
    }
    Ok(AotHeader {
        format_version: version,
        stamp: X86AbiStamp {
            target: TargetStamp {
                architecture,
                calling_convention,
                pointer_width,
                little_endian,
            },
            requested_tier,
            used_tier,
            kernel_abi_version,
            kernel_semantics_version,
        },
        output,
        entry_offset,
        code_len,
        data_offset,
        image_len,
        relocation_count,
        kernel_identity: identity,
        kernel_shape,
    })
}

fn header_from_image(image: &NativeImage) -> Result<AotHeader, AotError> {
    let mut identity = [0_u8; 32];
    identity.copy_from_slice(image.kernel_identity().as_bytes());
    Ok(AotHeader {
        format_version: FORMAT_VERSION,
        stamp: image.stamp(),
        output: image.output_kind(),
        entry_offset: image.entry_offset(),
        code_len: u32::try_from(image.code().len()).map_err(|_| AotError::ArithmeticOverflow)?,
        data_offset: image.data_offset(),
        image_len: u32::try_from(image.image_bytes().len())
            .map_err(|_| AotError::ArithmeticOverflow)?,
        relocation_count: u32::try_from(image.relocations().len())
            .map_err(|_| AotError::ArithmeticOverflow)?,
        kernel_identity: identity,
        kernel_shape: image.kernel_shape(),
    })
}

fn put_header(bytes: &mut Vec<u8>, header: AotHeader) {
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&header.format_version.to_le_bytes());
    bytes.push(architecture_tag(header.stamp.target.architecture));
    bytes.push(calling_convention_tag(
        header.stamp.target.calling_convention,
    ));
    bytes.push(header.stamp.target.pointer_width);
    bytes.push(u8::from(header.stamp.target.little_endian));
    bytes.push(tier_tag(header.stamp.requested_tier));
    bytes.push(tier_tag(header.stamp.used_tier));
    bytes.push(output_tag(header.output));
    bytes.push(0);
    bytes.extend_from_slice(&header.stamp.kernel_abi_version.to_le_bytes());
    bytes.extend_from_slice(&header.stamp.kernel_semantics_version.to_le_bytes());
    bytes.extend_from_slice(&header.entry_offset.to_le_bytes());
    bytes.extend_from_slice(&header.code_len.to_le_bytes());
    bytes.extend_from_slice(&header.data_offset.to_le_bytes());
    bytes.extend_from_slice(&header.image_len.to_le_bytes());
    bytes.extend_from_slice(&header.relocation_count.to_le_bytes());
    bytes.extend_from_slice(&header.kernel_identity);
    let (tag, population, length, anchors) = match header.kernel_shape {
        KernelShape::ExactLiteral {
            literal_len,
            anchors,
        } => (1, 0, literal_len, anchors),
        KernelShape::DisjointClassSuffix {
            class_population,
            suffix_len,
            anchors,
        } => (2, class_population, suffix_len, anchors),
    };
    bytes.push(tag);
    bytes.push(u8::from(anchors.start) | (u8::from(anchors.end) << 1));
    bytes.extend_from_slice(&population.to_le_bytes());
    bytes.extend_from_slice(&length.to_le_bytes());
}

const fn output_tag(output: OutputKind) -> u8 {
    match output {
        OutputKind::Exists => 1,
        OutputKind::SelectedEnd => 2,
        OutputKind::Span => 3,
    }
}

fn output(value: u8) -> Result<OutputKind, AotError> {
    match value {
        1 => Ok(OutputKind::Exists),
        2 => Ok(OutputKind::SelectedEnd),
        3 => Ok(OutputKind::Span),
        _ => Err(AotError::InvalidField),
    }
}

fn tier(value: u8) -> Result<FeatureTier, AotError> {
    match value {
        0 => Ok(FeatureTier::Scalar),
        1 => Ok(FeatureTier::Sse2),
        2 => Ok(FeatureTier::Avx2),
        _ => Err(AotError::InvalidField),
    }
}

fn byte(bytes: &[u8], offset: usize) -> Result<u8, AotError> {
    bytes.get(offset).copied().ok_or(AotError::Truncated)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AotError> {
    let end = offset.checked_add(2).ok_or(AotError::ArithmeticOverflow)?;
    let value = bytes.get(offset..end).ok_or(AotError::Truncated)?;
    Ok(u16::from_le_bytes(
        value.try_into().map_err(|_| AotError::Truncated)?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AotError> {
    let end = offset.checked_add(4).ok_or(AotError::ArithmeticOverflow)?;
    let value = bytes.get(offset..end).ok_or(AotError::Truncated)?;
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| AotError::Truncated)?,
    ))
}

fn enforce_scratch(limit: u64) -> Result<(), AotError> {
    enforce(
        EmitResource::AotScratchBytes,
        u64::try_from(AOT_SCRATCH_BYTES).expect("small constant"),
        limit,
    )
}

const fn enforce(resource: EmitResource, required: u64, limit: u64) -> Result<(), AotError> {
    if required > limit {
        return Err(AotError::ResourceLimit {
            resource,
            limit,
            required,
        });
    }
    Ok(())
}

fn usize_u64(value: usize) -> Result<u64, AotError> {
    u64::try_from(value).map_err(|_| AotError::ArithmeticOverflow)
}

const fn architecture_tag(architecture: Architecture) -> u8 {
    match architecture {
        Architecture::X86_64 => 1,
    }
}

const fn calling_convention_tag(calling_convention: CallingConvention) -> u8 {
    match calling_convention {
        CallingConvention::SystemVAMD64V1 => 1,
        CallingConvention::WindowsX64V1 => 2,
    }
}

const fn tier_tag(tier: FeatureTier) -> u8 {
    match tier {
        FeatureTier::Scalar => 0,
        FeatureTier::Sse2 => 1,
        FeatureTier::Avx2 => 2,
    }
}

const fn relocation_tag(kind: RelocationKind) -> u8 {
    match kind {
        RelocationKind::RipRelativeI32 => 1,
    }
}

const fn section_tag(section: Section) -> u8 {
    match section {
        Section::Code => 1,
        Section::Data => 2,
    }
}

fn checked_offset(offset: usize, delta: usize) -> Result<usize, AotError> {
    offset
        .checked_add(delta)
        .ok_or(AotError::ArithmeticOverflow)
}
