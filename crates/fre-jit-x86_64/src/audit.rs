use core::mem::size_of;

use crate::{AuditError, EmitResource, FeatureTier, NativeImage, RelocationKind, Section};

const HARD_AUDIT_CODE_BYTES: usize = 4_096;
const AUDIT_SCRATCH_BYTES: usize = HARD_AUDIT_CODE_BYTES + 1 + size_of::<usize>();

/// Bounds for the decoder/authenticity pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditLimits {
    pub max_instructions: u64,
    pub max_work: u64,
    pub max_scratch_bytes: u64,
}

impl Default for AuditLimits {
    fn default() -> Self {
        Self {
            max_instructions: 4_096,
            max_work: 64 << 10,
            max_scratch_bytes: u64::try_from(AUDIT_SCRATCH_BYTES).expect("small constant"),
        }
    }
}

/// Independently decoded instruction-shape evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InstructionShape {
    pub instructions: usize,
    pub scalar_comparisons: usize,
    pub sse2_comparisons: usize,
    pub avx2_comparisons: usize,
    pub vector_loads: usize,
    pub direct_branches: usize,
    pub returns: usize,
    pub data_references: usize,
    pub avx_cleanups: usize,
}

/// Result of a complete authenticity pass over one image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditReport {
    pub shape: InstructionShape,
    pub decoded_bytes: usize,
    pub work: u64,
    pub scratch_bytes: usize,
    pub highest_feature_tier: FeatureTier,
}

/// Decode every code byte and verify all direct-control-flow and data targets.
///
/// The decoder is intentionally independent of the emitter's instruction
/// helpers. It accepts only the small v1 whitelist, which excludes calls,
/// indirect jumps, stack adjustment and writes to callee-saved registers.
#[expect(
    clippy::too_many_lines,
    reason = "keeping both audit passes adjacent makes the authenticity invariant reviewable"
)]
pub fn audit_image(image: &NativeImage, limits: AuditLimits) -> Result<AuditReport, AuditError> {
    enforce(
        EmitResource::AuditScratchBytes,
        AUDIT_SCRATCH_BYTES,
        limits.max_scratch_bytes,
    )?;
    let code = image.code();
    if code.len() > HARD_AUDIT_CODE_BYTES {
        return Err(AuditError::ResourceLimit {
            resource: EmitResource::AuditScratchBytes,
            limit: u64::try_from(HARD_AUDIT_CODE_BYTES).expect("small constant"),
            required: usize_u64(code.len())?,
        });
    }
    if image.entry_offset() != 0
        || usize::try_from(image.data_offset()).map_err(|_| AuditError::ImageLayout)? < code.len()
        || image.image_bytes().len()
            != usize::try_from(image.data_offset())
                .map_err(|_| AuditError::ImageLayout)?
                .checked_add(image.data().len())
                .ok_or(AuditError::ArithmeticOverflow)?
    {
        return Err(AuditError::ImageLayout);
    }

    let mut boundaries = [false; HARD_AUDIT_CODE_BYTES + 1];
    let mut meter = AuditMeter::new(limits.max_work);
    let mut offset = 0_usize;
    let mut shape = InstructionShape::default();
    let mut highest = FeatureTier::Scalar;
    while offset < code.len() {
        boundaries[offset] = true;
        let decoded = decode_one(code, offset)?;
        meter.charge(
            usize_u64(decoded.len)?
                .checked_add(1)
                .ok_or(AuditError::ArithmeticOverflow)?,
        )?;
        shape.instructions = shape
            .instructions
            .checked_add(1)
            .ok_or(AuditError::ArithmeticOverflow)?;
        enforce(
            EmitResource::AuditInstructions,
            shape.instructions,
            limits.max_instructions,
        )?;
        account(decoded.kind, &mut shape, &mut highest)?;
        if decoded.kind == Kind::Return && image.stamp().used_tier == FeatureTier::Avx2 {
            let cleanup_start = offset.checked_sub(3);
            if cleanup_start.and_then(|start| code.get(start..offset)) != Some(&[0xC5, 0xF8, 0x77])
            {
                return Err(AuditError::MissingAvxCleanup { offset });
            }
        }
        offset = offset
            .checked_add(decoded.len)
            .ok_or(AuditError::ArithmeticOverflow)?;
    }
    boundaries[code.len()] = true;
    if offset != code.len() {
        return Err(AuditError::ImageLayout);
    }

    let mut relocation_count = 0_usize;
    offset = 0;
    while offset < code.len() {
        let decoded = decode_one(code, offset)?;
        meter.charge(1)?;
        if let Some(displacement_offset) = decoded.branch_displacement {
            let displacement = read_i32(code, displacement_offset)?;
            let next = displacement_offset
                .checked_add(4)
                .ok_or(AuditError::ArithmeticOverflow)?;
            let target = add_signed(next, displacement)
                .ok_or(AuditError::BranchTargetOutOfRange { offset })?;
            if target >= code.len() {
                return Err(AuditError::BranchTargetOutOfRange { offset });
            }
            if !boundaries[target] {
                return Err(AuditError::BranchTargetNotInstruction { offset, target });
            }
        }
        if let Some(displacement_offset) = decoded.data_displacement {
            validate_data_reference(image, displacement_offset)?;
            relocation_count = relocation_count
                .checked_add(1)
                .ok_or(AuditError::ArithmeticOverflow)?;
        }
        offset = offset
            .checked_add(decoded.len)
            .ok_or(AuditError::ArithmeticOverflow)?;
    }
    if relocation_count != image.relocations().len() {
        return Err(AuditError::RelocationManifestMismatch { offset: code.len() });
    }
    if highest != image.stamp().used_tier {
        return Err(AuditError::TierMismatch { offset: 0 });
    }
    Ok(AuditReport {
        shape,
        decoded_bytes: code.len(),
        work: meter.consumed,
        scratch_bytes: AUDIT_SCRATCH_BYTES,
        highest_feature_tier: highest,
    })
}

fn validate_data_reference(
    image: &NativeImage,
    displacement_offset: usize,
) -> Result<(), AuditError> {
    let relocation = image
        .relocations()
        .iter()
        .find(|relocation| {
            usize::try_from(relocation.displacement_offset).ok() == Some(displacement_offset)
        })
        .ok_or(AuditError::RelocationManifestMismatch {
            offset: displacement_offset,
        })?;
    if relocation.kind != RelocationKind::RipRelativeI32
        || relocation.source_section != Section::Code
        || relocation.target_section != Section::Data
    {
        return Err(AuditError::RelocationManifestMismatch {
            offset: displacement_offset,
        });
    }
    let target_offset = usize::try_from(relocation.target_offset).map_err(|_| {
        AuditError::DataTargetOutOfRange {
            offset: displacement_offset,
        }
    })?;
    if target_offset >= image.data().len() {
        return Err(AuditError::DataTargetOutOfRange {
            offset: displacement_offset,
        });
    }
    let displacement = read_i32(image.code(), displacement_offset)?;
    let next = displacement_offset
        .checked_add(4)
        .ok_or(AuditError::ArithmeticOverflow)?;
    let actual = add_signed(next, displacement).ok_or(AuditError::DataTargetOutOfRange {
        offset: displacement_offset,
    })?;
    let expected = usize::try_from(image.data_offset())
        .map_err(|_| AuditError::ArithmeticOverflow)?
        .checked_add(target_offset)
        .ok_or(AuditError::ArithmeticOverflow)?;
    if actual != expected {
        return Err(AuditError::RelocationManifestMismatch {
            offset: displacement_offset,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Plain,
    ScalarCompare,
    SseCompare,
    AvxCompare,
    SseLoad,
    AvxLoad,
    DirectBranch,
    DataReference,
    AvxCleanup,
    Return,
}

#[derive(Clone, Copy)]
struct Decoded {
    len: usize,
    kind: Kind,
    branch_displacement: Option<usize>,
    data_displacement: Option<usize>,
}

impl Decoded {
    const fn plain(len: usize) -> Self {
        Self {
            len,
            kind: Kind::Plain,
            branch_displacement: None,
            data_displacement: None,
        }
    }

    const fn kind(len: usize, kind: Kind) -> Self {
        Self {
            len,
            kind,
            branch_displacement: None,
            data_displacement: None,
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "a single explicit whitelist is easier to audit than distributed x86 decoder state"
)]
fn decode_one(code: &[u8], offset: usize) -> Result<Decoded, AuditError> {
    let rest = code
        .get(offset..)
        .ok_or(AuditError::TruncatedInstruction { offset })?;
    if rest.starts_with(&[0xE9]) {
        require_len(rest, 5, offset)?;
        return Ok(Decoded {
            len: 5,
            kind: Kind::DirectBranch,
            branch_displacement: Some(checked_offset(offset, 1)?),
            data_displacement: None,
        });
    }
    if rest.starts_with(&[0x0F]) {
        require_len(rest, 2, offset)?;
        if matches!(rest[1], 0x82..=0x87) {
            require_len(rest, 6, offset)?;
            return Ok(Decoded {
                len: 6,
                kind: Kind::DirectBranch,
                branch_displacement: Some(checked_offset(offset, 2)?),
                data_displacement: None,
            });
        }
    }
    if rest.starts_with(&[0x48, 0x8D, 0x15]) || rest.starts_with(&[0x4C, 0x8D, 0x15]) {
        require_len(rest, 7, offset)?;
        return Ok(Decoded {
            len: 7,
            kind: Kind::DataReference,
            branch_displacement: None,
            data_displacement: Some(checked_offset(offset, 3)?),
        });
    }
    if rest.starts_with(&[0xC5, 0xF8, 0x77]) {
        return Ok(Decoded::kind(3, Kind::AvxCleanup));
    }
    if rest.starts_with(&[0xC4, 0xC1, 0x7D, 0x74, 0x02])
        || rest.starts_with(&[0xC5, 0xFD, 0x74, 0x02])
    {
        return Ok(Decoded::kind(
            if rest[0] == 0xC4 { 5 } else { 4 },
            Kind::AvxCompare,
        ));
    }
    if rest.starts_with(&[0xC5, 0xFE, 0x6F, 0x00])
        || rest.starts_with(&[0xC4, 0xC1, 0x7E, 0x6F, 0x01])
        || rest.starts_with(&[0xC5, 0xFD, 0xD7, 0xD0])
        || rest.starts_with(&[0xC5, 0xFD, 0xD7, 0xF0])
    {
        return Ok(Decoded::kind(
            if rest.starts_with(&[0xC4]) { 5 } else { 4 },
            Kind::AvxLoad,
        ));
    }
    if rest.starts_with(&[0x66, 0x0F, 0x74, 0xC1]) {
        return Ok(Decoded::kind(4, Kind::SseCompare));
    }
    if starts_any(
        rest,
        &[
            &[0xF3, 0x0F, 0x6F, 0x00],
            &[0xF3, 0x41, 0x0F, 0x6F, 0x0A],
            &[0x66, 0x0F, 0xD7, 0xD0],
            &[0xF3, 0x41, 0x0F, 0x6F, 0x01],
            &[0xF3, 0x0F, 0x6F, 0x0A],
            &[0x66, 0x0F, 0xD7, 0xF0],
        ],
    ) {
        let len = if rest.starts_with(&[0xF3, 0x41]) {
            5
        } else {
            4
        };
        return Ok(Decoded::kind(len, Kind::SseLoad));
    }
    if rest.starts_with(&[0xC3]) {
        return Ok(Decoded::kind(1, Kind::Return));
    }
    if let Some(decoded) = decode_inline_compare(rest) {
        return Ok(decoded);
    }
    if starts_any(
        rest,
        &[
            &[0x38, 0x10],
            &[0x40, 0x38, 0x30],
            &[0x41, 0x38, 0x31],
            &[0x80, 0x3C, 0x02, 0x00],
        ],
    ) {
        let len = if rest[0] == 0x80 {
            4
        } else if matches!(rest[0], 0x40 | 0x41) {
            3
        } else {
            2
        };
        return Ok(Decoded::kind(len, Kind::ScalarCompare));
    }
    if let Some(length) = immediate_length(rest) {
        require_len(rest, length, offset)?;
        return Ok(Decoded::plain(length));
    }
    if let Some(length) = plain_static_length(rest) {
        return Ok(Decoded::plain(length));
    }
    if matches!(rest.first(), Some(0xE8 | 0xFF)) {
        return Err(AuditError::ForbiddenControlFlow { offset });
    }
    if looks_truncated(rest) {
        return Err(AuditError::TruncatedInstruction { offset });
    }
    Err(AuditError::UnknownInstruction { offset })
}

fn decode_inline_compare(rest: &[u8]) -> Option<Decoded> {
    let scalar = |len| Some(Decoded::kind(len, Kind::ScalarCompare));
    match rest {
        [0x46, 0x38 | 0x39, 0x1C, 0x0F, ..]
        | [0x4E, 0x39, 0x1C, 0x0F, ..]
        | [0x46, 0x38 | 0x39, 0x0C, 0x1F, ..]
        | [0x4E, 0x39, 0x0C, 0x1F, ..] => scalar(4),
        [0x66, 0x46, 0x39, 0x1C, 0x0F, ..]
        | [0x66, 0x46, 0x39, 0x0C, 0x1F, ..]
        | [0x46, 0x38 | 0x39, 0x5C, 0x0F, _, ..]
        | [0x4E, 0x39, 0x5C, 0x0F, _, ..]
        | [0x46, 0x38 | 0x39, 0x4C, 0x1F, _, ..]
        | [0x4E, 0x39, 0x4C, 0x1F, _, ..] => scalar(5),
        [0x66, 0x46, 0x39, 0x5C, 0x0F, _, ..] | [0x66, 0x46, 0x39, 0x4C, 0x1F, _, ..] => scalar(6),
        _ => None,
    }
}

fn immediate_length(rest: &[u8]) -> Option<usize> {
    match rest {
        [0x49, 0xBB | 0xB9, ..] | [0x48, 0xB8..=0xBA, ..] => Some(10),
        [0x41, 0xBB | 0xB9, ..] | [0x81, 0xFA | 0xFE, ..] => Some(6),
        [0xB8, ..] => Some(5),
        [0x83, 0xFA | 0xFE, ..] => Some(3),
        [0x3C, ..] => Some(2),
        _ => None,
    }
}

fn plain_static_length(rest: &[u8]) -> Option<usize> {
    const THREE: &[&[u8]] = &[
        &[0x48, 0x39, 0xCA],
        &[0x48, 0x39, 0xF1],
        &[0x48, 0x85, 0xD2],
        &[0x49, 0x89, 0xCA],
        &[0x49, 0x29, 0xD2],
        &[0x4D, 0x39, 0xDA],
        &[0x4C, 0x39, 0xDE],
        &[0x49, 0x89, 0xF1],
        &[0x4D, 0x29, 0xD9],
        &[0x4D, 0x29, 0xDA],
        &[0x49, 0x89, 0xD1],
        &[0x49, 0xFF, 0xC1],
        &[0x4D, 0x39, 0xD1],
        &[0x4D, 0x89, 0x08],
        &[0x4C, 0x89, 0xC9],
        &[0x4C, 0x01, 0xD9],
        &[0x49, 0x89, 0x00],
        &[0x4D, 0x85, 0xC9],
        &[0x49, 0x39, 0xC9],
        &[0x4D, 0x89, 0xCA],
        &[0x49, 0x39, 0xCB],
        &[0x49, 0xFF, 0xC3],
        &[0x48, 0x89, 0xC8],
        &[0x4C, 0x29, 0xD8],
        &[0x48, 0x39, 0xD0],
        &[0x4C, 0x89, 0xD8],
        &[0x48, 0x01, 0xD0],
        &[0x48, 0x39, 0xF0],
        &[0x4D, 0x89, 0xD9],
        &[0x4D, 0x89, 0x10],
        &[0x49, 0x89, 0xC1],
        &[0x49, 0xFF, 0xC1],
        &[0x48, 0xFF, 0xC2],
        &[0x48, 0xFF, 0xC8],
        &[0x48, 0xFF, 0xC0],
        &[0x49, 0xFF, 0xC2],
        &[0x48, 0xFF, 0xC9],
    ];
    const FOUR: &[&[u8]] = &[
        &[0x45, 0x31, 0xC9, 0x00], // special-cased by first three below
        &[0x49, 0x89, 0x48, 0x08],
        &[0x49, 0x89, 0x40, 0x08],
        &[0x4D, 0x8D, 0x59, 0x01],
        &[0x49, 0x83, 0xC1, 0x10],
        &[0x49, 0x83, 0xC1, 0x20],
        &[0x48, 0x83, 0xC2, 0x10],
        &[0x48, 0x83, 0xC2, 0x20],
        &[0x48, 0x83, 0xC0, 0x10],
        &[0x48, 0x83, 0xC0, 0x20],
        &[0x49, 0x83, 0xC2, 0x10],
        &[0x49, 0x83, 0xC2, 0x20],
        &[0x4A, 0x8D, 0x04, 0x0F],
        &[0x4A, 0x8D, 0x04, 0x1F],
    ];
    if rest.starts_with(&[0x31, 0xC0]) {
        return Some(2);
    }
    if rest.starts_with(&[0x45, 0x31, 0xC9])
        || rest.starts_with(&[0x0F, 0xB6, 0x32])
        || rest.starts_with(&[0x41, 0x0F, 0xB6, 0x12])
    {
        return Some(if rest.starts_with(&[0x41, 0x0F]) {
            4
        } else {
            3
        });
    }
    if rest.starts_with(&[0x42, 0x0F, 0xB6, 0x04, 0x0F])
        || rest.starts_with(&[0x42, 0x0F, 0xB6, 0x04, 0x1F])
    {
        return Some(5);
    }
    if THREE.iter().any(|bytes| rest.starts_with(bytes)) {
        return Some(3);
    }
    if FOUR.iter().any(|bytes| rest.starts_with(bytes)) {
        return Some(4);
    }
    None
}

fn account(
    kind: Kind,
    shape: &mut InstructionShape,
    highest: &mut FeatureTier,
) -> Result<(), AuditError> {
    let field = match kind {
        Kind::ScalarCompare => Some(&mut shape.scalar_comparisons),
        Kind::SseCompare => {
            *highest = (*highest).max(FeatureTier::Sse2);
            Some(&mut shape.sse2_comparisons)
        }
        Kind::AvxCompare => {
            *highest = FeatureTier::Avx2;
            Some(&mut shape.avx2_comparisons)
        }
        Kind::SseLoad => {
            *highest = (*highest).max(FeatureTier::Sse2);
            Some(&mut shape.vector_loads)
        }
        Kind::AvxLoad => {
            *highest = FeatureTier::Avx2;
            Some(&mut shape.vector_loads)
        }
        Kind::DirectBranch => Some(&mut shape.direct_branches),
        Kind::DataReference => Some(&mut shape.data_references),
        Kind::AvxCleanup => Some(&mut shape.avx_cleanups),
        Kind::Return => Some(&mut shape.returns),
        Kind::Plain => None,
    };
    if let Some(field) = field {
        *field = field.checked_add(1).ok_or(AuditError::ArithmeticOverflow)?;
    }
    Ok(())
}

fn read_i32(code: &[u8], offset: usize) -> Result<i32, AuditError> {
    let end = offset
        .checked_add(4)
        .ok_or(AuditError::ArithmeticOverflow)?;
    let bytes: [u8; 4] = code
        .get(offset..end)
        .ok_or(AuditError::TruncatedInstruction { offset })?
        .try_into()
        .map_err(|_| AuditError::TruncatedInstruction { offset })?;
    Ok(i32::from_le_bytes(bytes))
}

fn add_signed(base: usize, displacement: i32) -> Option<usize> {
    if displacement >= 0 {
        base.checked_add(usize::try_from(displacement).ok()?)
    } else {
        base.checked_sub(usize::try_from(displacement.unsigned_abs()).ok()?)
    }
}

fn require_len(rest: &[u8], length: usize, offset: usize) -> Result<(), AuditError> {
    if rest.len() < length {
        return Err(AuditError::TruncatedInstruction { offset });
    }
    Ok(())
}

fn starts_any(rest: &[u8], choices: &[&[u8]]) -> bool {
    choices.iter().any(|choice| rest.starts_with(choice))
}

fn looks_truncated(rest: &[u8]) -> bool {
    matches!(
        rest.first(),
        Some(0x0F | 0x41..=0x4F | 0x66 | 0x80 | 0x81 | 0x83 | 0xC4 | 0xC5 | 0xE9 | 0xF3)
    ) && rest.len() < 10
}

struct AuditMeter {
    limit: u64,
    consumed: u64,
}

impl AuditMeter {
    const fn new(limit: u64) -> Self {
        Self { limit, consumed: 0 }
    }

    fn charge(&mut self, amount: u64) -> Result<(), AuditError> {
        let required = self
            .consumed
            .checked_add(amount)
            .ok_or(AuditError::ArithmeticOverflow)?;
        if required > self.limit {
            return Err(AuditError::ResourceLimit {
                resource: EmitResource::AuditWork,
                limit: self.limit,
                required,
            });
        }
        self.consumed = required;
        Ok(())
    }
}

fn enforce(resource: EmitResource, required: usize, limit: u64) -> Result<(), AuditError> {
    let required = usize_u64(required)?;
    if required > limit {
        return Err(AuditError::ResourceLimit {
            resource,
            limit,
            required,
        });
    }
    Ok(())
}

fn usize_u64(value: usize) -> Result<u64, AuditError> {
    u64::try_from(value).map_err(|_| AuditError::ArithmeticOverflow)
}

fn checked_offset(offset: usize, delta: usize) -> Result<usize, AuditError> {
    offset
        .checked_add(delta)
        .ok_or(AuditError::ArithmeticOverflow)
}
