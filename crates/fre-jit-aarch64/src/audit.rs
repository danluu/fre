use core::fmt;

use fre_kernel_ir::{
    AggregateOutput, Count, MAX_EXACT_AGGREGATE_LITERAL_BYTES, SpanSum, ValidateLimits,
    build_exact_aggregate,
};

use crate::{
    CpuFeatures, DataSymbolKind, DecodeError, DecodedInstruction, LabelKind, NativeAggregateImage,
    NativeImage, RelocationKind, RelocationTarget,
    decode::{canonical_word, decode_one},
};

/// Independent post-emission authenticity failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditError {
    Decode(DecodeError),
    InvalidImageContract,
    InvalidLayout,
    InvalidLabel {
        offset: u32,
    },
    InvalidDataSymbol {
        id: u32,
    },
    OverlappingDataSymbols {
        first: u32,
        second: u32,
    },
    InvalidRelocation {
        offset: u32,
    },
    OverlappingRelocations {
        offset: u32,
    },
    MissingRelocation {
        offset: u32,
    },
    UnexpectedRelocation {
        offset: u32,
    },
    RelocationKindMismatch {
        offset: u32,
    },
    RelocationWordMismatch {
        offset: u32,
    },
    NonCanonicalInstruction {
        offset: u32,
    },
    BranchTargetNotLabel {
        offset: u32,
        target: i64,
    },
    AddressTargetNotData {
        offset: u32,
        target: i64,
    },
    ForbiddenStore {
        offset: u32,
        base: u8,
        displacement: u16,
    },
    ResultPointerClobber {
        offset: u32,
        register: u8,
    },
    InvalidAggregateManifest,
    ForbiddenAggregateRegister {
        offset: u32,
        register: u8,
    },
    ForbiddenAggregateVectorRegister {
        offset: u32,
        register: u8,
    },
    InvalidAggregateStatus {
        offset: u32,
        status: u16,
    },
    InvalidAggregateControlFlow {
        offset: u32,
    },
    InvalidAggregateLoad {
        offset: u32,
    },
    InvalidAggregateStoreContract,
    FeatureMismatch,
    ArithmeticOverflow,
}

impl From<DecodeError> for AuditError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

impl fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AArch64 image audit failed: {self:?}")
    }
}

impl std::error::Error for AuditError {}

/// Instruction-shape and manifest evidence produced by a successful audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditReport {
    pub instructions: u32,
    pub direct_branches: u32,
    pub data_addresses: u32,
    pub vector_instructions: u32,
    pub stores: u32,
    pub returns: u32,
}

/// Re-decode and authenticate a finalized image.
///
/// This pass shares no encoding helpers with the emitter. It proves that each
/// direct target is a declared label, each data address names immutable image
/// data, relocations are complete/non-overlapping, result stores follow the
/// fixed ABI, and no unknown or indirect instruction is present.
#[allow(
    clippy::too_many_lines,
    reason = "keeping the independent linear audit in one pass makes relocation completeness auditable"
)]
pub fn audit(image: &NativeImage) -> Result<AuditReport, AuditError> {
    if image.aggregate_manifest().is_some() {
        return Err(AuditError::InvalidImageContract);
    }
    audit_impl(image, StoreContract::Search)
}

/// Independently re-decode a whole-haystack aggregate image.
pub fn audit_aggregate(image: &NativeAggregateImage) -> Result<AuditReport, AuditError> {
    audit_aggregate_shape(image.inner())?;
    let report = audit_impl(image.inner(), StoreContract::Aggregate)?;
    audit_aggregate_contract(image.inner())?;
    Ok(report)
}

#[derive(Clone, Copy)]
enum StoreContract {
    Search,
    Aggregate,
}

#[allow(
    clippy::too_many_lines,
    reason = "keeping the independent linear audit in one pass makes relocation completeness auditable"
)]
fn audit_impl(
    image: &NativeImage,
    store_contract: StoreContract,
) -> Result<AuditReport, AuditError> {
    validate_layout(image)?;
    validate_labels(image)?;
    validate_symbols(image)?;
    validate_relocation_order(image)?;
    let mut report = AuditReport {
        instructions: 0,
        direct_branches: 0,
        data_addresses: 0,
        vector_instructions: 0,
        stores: 0,
        returns: 0,
    };
    let mut relocation_index = 0_usize;
    for (index, bytes) in image.code.chunks_exact(4).enumerate() {
        let offset = u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(4))
            .ok_or(AuditError::ArithmeticOverflow)?;
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let instruction = decode_one(word, offset)?;
        if canonical_word(instruction) != Some(word) {
            return Err(AuditError::NonCanonicalInstruction { offset });
        }
        report.instructions = report
            .instructions
            .checked_add(1)
            .ok_or(AuditError::ArithmeticOverflow)?;
        if instruction.is_vector() {
            report.vector_instructions = report
                .vector_instructions
                .checked_add(1)
                .ok_or(AuditError::ArithmeticOverflow)?;
        }
        let result_pointer = match store_contract {
            StoreContract::Search => 4,
            StoreContract::Aggregate => 2,
        };
        if instruction.written_gpr() == Some(result_pointer) {
            return Err(AuditError::ResultPointerClobber {
                offset,
                register: result_pointer,
            });
        }
        let relocation = image
            .relocations
            .get(relocation_index)
            .filter(|relocation| relocation.code_offset == offset);
        match instruction {
            DecodedInstruction::Branch { displacement }
            | DecodedInstruction::BranchCondition { displacement, .. }
            | DecodedInstruction::CompareBranchZero64 { displacement, .. } => {
                report.direct_branches = report
                    .direct_branches
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
                let relocation = relocation.ok_or(AuditError::MissingRelocation { offset })?;
                let expected_kind = match instruction {
                    DecodedInstruction::Branch { .. } => RelocationKind::Branch26,
                    DecodedInstruction::BranchCondition { .. } => {
                        RelocationKind::ConditionalBranch19
                    }
                    DecodedInstruction::CompareBranchZero64 { .. } => {
                        RelocationKind::CompareBranch19
                    }
                    _ => unreachable!("outer match fixes the instruction kind"),
                };
                if relocation.kind != expected_kind {
                    return Err(AuditError::RelocationKindMismatch { offset });
                }
                let target = i64::from(offset)
                    .checked_add(i64::from(displacement))
                    .ok_or(AuditError::ArithmeticOverflow)?;
                let target_u32 = u32::try_from(target)
                    .map_err(|_| AuditError::BranchTargetNotLabel { offset, target })?;
                if !image.labels.iter().any(|label| label.offset == target_u32) {
                    return Err(AuditError::BranchTargetNotLabel { offset, target });
                }
                if relocation.target != RelocationTarget::CodeOffset(target_u32)
                    || relocation.addend != 0
                {
                    return Err(AuditError::InvalidRelocation { offset });
                }
                validate_word(relocation.resolved_word, word, offset)?;
                relocation_index = relocation_index
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
            }
            DecodedInstruction::Address {
                displacement,
                destination: _,
            } => {
                report.data_addresses = report
                    .data_addresses
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
                let relocation = relocation.ok_or(AuditError::MissingRelocation { offset })?;
                if relocation.kind != RelocationKind::Address21 {
                    return Err(AuditError::RelocationKindMismatch { offset });
                }
                let target = i64::from(offset)
                    .checked_add(i64::from(displacement))
                    .ok_or(AuditError::ArithmeticOverflow)?;
                let rodata_base = i64::from(image.layout.rodata_from_code_start);
                let relative = target
                    .checked_sub(rodata_base)
                    .ok_or(AuditError::ArithmeticOverflow)?;
                let relative_u32 = u32::try_from(relative)
                    .map_err(|_| AuditError::AddressTargetNotData { offset, target })?;
                if !image
                    .symbols
                    .iter()
                    .any(|symbol| symbol.offset == relative_u32)
                {
                    return Err(AuditError::AddressTargetNotData { offset, target });
                }
                if relocation.target != RelocationTarget::RodataOffset(relative_u32)
                    || relocation.addend != 0
                {
                    return Err(AuditError::InvalidRelocation { offset });
                }
                validate_word(relocation.resolved_word, word, offset)?;
                relocation_index = relocation_index
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
            }
            DecodedInstruction::Store64 {
                base,
                offset: store_offset,
                ..
            } => {
                report.stores = report
                    .stores
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
                let permitted = match store_contract {
                    StoreContract::Search => base == 4 && matches!(store_offset, 0 | 8),
                    StoreContract::Aggregate => base == 2 && store_offset == 0,
                };
                if !permitted {
                    return Err(AuditError::ForbiddenStore {
                        offset,
                        base,
                        displacement: store_offset,
                    });
                }
                if relocation.is_some() {
                    return Err(AuditError::UnexpectedRelocation { offset });
                }
            }
            DecodedInstruction::Return => {
                report.returns = report
                    .returns
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
                if relocation.is_some() {
                    return Err(AuditError::UnexpectedRelocation { offset });
                }
            }
            _ => {
                if relocation.is_some() {
                    return Err(AuditError::UnexpectedRelocation { offset });
                }
            }
        }
    }
    if relocation_index != image.relocations.len() {
        let offset = image
            .relocations
            .get(relocation_index)
            .map_or(u32::MAX, |relocation| relocation.code_offset);
        return Err(AuditError::UnexpectedRelocation { offset });
    }
    let needs_vector = report.vector_instructions != 0;
    if image.target.features.contains(CpuFeatures::ASIMD) != needs_vector
        || report.vector_instructions != image.stats.vector_instructions
    {
        return Err(AuditError::FeatureMismatch);
    }
    Ok(report)
}

#[allow(
    clippy::too_many_lines,
    reason = "the aggregate-only decoded contract is intentionally kept as one auditable gate"
)]
fn audit_aggregate_contract(image: &NativeImage) -> Result<(), AuditError> {
    let literal_len = audit_aggregate_shape(image)?;
    let manifest = image
        .aggregate_manifest()
        .ok_or(AuditError::InvalidAggregateManifest)?;
    let symbol = image.symbols[0];
    if symbol.ir_data_id != 0
        || symbol.offset != 0
        || usize::try_from(symbol.length).ok() != Some(literal_len)
        || symbol.alignment != 16
        || symbol.kind != DataSymbolKind::Bytes
    {
        return Err(AuditError::InvalidAggregateManifest);
    }
    let (expected_identity, expected_search_identity) = match manifest.output {
        AggregateOutput::Count => {
            let program = build_exact_aggregate::<Count>(&image.rodata, ValidateLimits::default())
                .map_err(|_| AuditError::InvalidAggregateManifest)?;
            (program.cache_identity(), program.search_cache_identity())
        }
        AggregateOutput::SpanSum => {
            let program =
                build_exact_aggregate::<SpanSum>(&image.rodata, ValidateLimits::default())
                    .map_err(|_| AuditError::InvalidAggregateManifest)?;
            (program.cache_identity(), program.search_cache_identity())
        }
    };
    if manifest.source_identity != expected_identity
        || image.source_identity != expected_search_identity
    {
        return Err(AuditError::InvalidAggregateManifest);
    }

    let instructions = crate::decode(image.code())?;
    let mut stores = Vec::new();
    let mut status_zero = None;
    let mut status_one = None;
    let mut address_count = 0_usize;
    for (index, &instruction) in instructions.iter().enumerate() {
        let offset = instruction_offset(index)?;
        if let Some(register) = first_forbidden_aggregate_register(instruction) {
            return Err(AuditError::ForbiddenAggregateRegister { offset, register });
        }
        if let Some(register) = first_forbidden_aggregate_vector_register(instruction) {
            return Err(AuditError::ForbiddenAggregateVectorRegister { offset, register });
        }
        validate_aggregate_critical_write(&instructions, index, literal_len, manifest.output)?;
        match instruction {
            DecodedInstruction::Address { destination: 8, .. } => {
                address_count = address_count
                    .checked_add(1)
                    .ok_or(AuditError::ArithmeticOverflow)?;
            }
            DecodedInstruction::Address { .. } => {
                return Err(AuditError::InvalidAggregateControlFlow { offset });
            }
            DecodedInstruction::LoadByte { .. }
            | DecodedInstruction::LoadByteRegister { .. }
            | DecodedInstruction::Load64RegisterScaled { .. }
            | DecodedInstruction::LoadVector128 { .. } => {
                if !valid_aggregate_load(&instructions, index, literal_len) {
                    return Err(AuditError::InvalidAggregateLoad { offset });
                }
            }
            DecodedInstruction::Store64 { source: 13, .. } => stores.push(index),
            DecodedInstruction::Store64 { .. } => {
                return Err(AuditError::InvalidAggregateStoreContract);
            }
            DecodedInstruction::Return => {
                let status_index = index
                    .checked_sub(1)
                    .ok_or(AuditError::InvalidAggregateControlFlow { offset })?;
                match instructions[status_index] {
                    DecodedInstruction::MoveZero64 {
                        destination: 0,
                        immediate: 0,
                        shift: 0,
                    } => {
                        if status_zero.replace((status_index, index)).is_some() {
                            return Err(AuditError::InvalidAggregateStoreContract);
                        }
                    }
                    DecodedInstruction::MoveZero64 {
                        destination: 0,
                        immediate: 1,
                        shift: 0,
                    } => {
                        if status_one.replace((status_index, index)).is_some() {
                            return Err(AuditError::InvalidAggregateStoreContract);
                        }
                    }
                    DecodedInstruction::MoveZero64 {
                        destination: 0,
                        immediate,
                        ..
                    } => {
                        return Err(AuditError::InvalidAggregateStatus {
                            offset: instruction_offset(status_index)?,
                            status: immediate,
                        });
                    }
                    _ => return Err(AuditError::InvalidAggregateControlFlow { offset }),
                }
            }
            _ => {}
        }
    }
    if address_count != usize::from(literal_len != 0) || stores.len() != 1 {
        return Err(AuditError::InvalidAggregateStoreContract);
    }
    let (success_status, success_return) =
        status_zero.ok_or(AuditError::InvalidAggregateStoreContract)?;
    let fault = status_one;
    let fault_required = literal_len != 0 || manifest.output == AggregateOutput::Count;
    if fault.is_some() != fault_required {
        return Err(AuditError::InvalidAggregateStoreContract);
    }
    let success_store = success_status
        .checked_sub(1)
        .ok_or(AuditError::InvalidAggregateStoreContract)?;
    if stores[0] != success_store
        || !matches!(
            instructions[success_store],
            DecodedInstruction::Store64 {
                source: 13,
                base: 2,
                offset: 0
            }
        )
    {
        return Err(AuditError::InvalidAggregateStoreContract);
    }

    let mut protected = vec![success_status, success_return];
    if let Some((_fault_status, fault_return)) = fault {
        protected.push(fault_return);
    }
    validate_aggregate_branches(&instructions, &protected, literal_len)?;
    validate_aggregate_definite_initialization(&instructions)?;
    validate_aggregate_reachability(&instructions)?;
    Ok(())
}

fn audit_aggregate_shape(image: &NativeImage) -> Result<usize, AuditError> {
    let manifest = image
        .aggregate_manifest()
        .ok_or(AuditError::InvalidAggregateManifest)?;
    let literal_len = usize::try_from(manifest.literal_bytes)
        .map_err(|_| AuditError::InvalidAggregateManifest)?;
    if literal_len > MAX_EXACT_AGGREGATE_LITERAL_BYTES
        || image.rodata.len() != literal_len
        || image.symbols.len() != 1
    {
        return Err(AuditError::InvalidAggregateManifest);
    }
    Ok(literal_len)
}

fn instruction_offset(index: usize) -> Result<u32, AuditError> {
    u32::try_from(index)
        .ok()
        .and_then(|value| value.checked_mul(4))
        .ok_or(AuditError::ArithmeticOverflow)
}

fn instruction_after(
    instructions: &[DecodedInstruction],
    index: usize,
    distance: usize,
) -> Option<&DecodedInstruction> {
    index
        .checked_add(distance)
        .and_then(|next| instructions.get(next))
}

#[allow(
    clippy::match_same_arms,
    reason = "operand arities remain grouped by decoded ISA form for security review"
)]
fn first_forbidden_aggregate_register(instruction: DecodedInstruction) -> Option<u8> {
    fn forbidden(registers: &[u8]) -> Option<u8> {
        registers.iter().copied().find(|&register| register >= 18)
    }
    match instruction {
        DecodedInstruction::MoveRegister64 {
            destination,
            source,
        } => forbidden(&[destination, source]),
        DecodedInstruction::MoveZero64 { destination, .. }
        | DecodedInstruction::MoveKeep64 { destination, .. }
        | DecodedInstruction::CompareImmediate64 {
            register: destination,
            ..
        }
        | DecodedInstruction::CompareImmediate32 {
            register: destination,
            ..
        }
        | DecodedInstruction::MoveVectorByteTo32 { destination, .. }
        | DecodedInstruction::Address { destination, .. }
        | DecodedInstruction::CompareBranchZero64 {
            register: destination,
            ..
        } => forbidden(&[destination]),
        DecodedInstruction::CompareRegister64 { left, right }
        | DecodedInstruction::CompareRegister32 { left, right } => forbidden(&[left, right]),
        DecodedInstruction::AddRegister64 {
            destination,
            left,
            right,
        }
        | DecodedInstruction::SubtractRegister64 {
            destination,
            left,
            right,
        } => forbidden(&[destination, left, right]),
        DecodedInstruction::AddImmediate64 {
            destination,
            source,
            ..
        }
        | DecodedInstruction::SubtractImmediate64 {
            destination,
            source,
            ..
        }
        | DecodedInstruction::AndLowBits64 {
            destination,
            source,
            ..
        }
        | DecodedInstruction::LogicalShiftRightImmediate64 {
            destination,
            source,
            ..
        }
        | DecodedInstruction::LogicalShiftLeftImmediate64 {
            destination,
            source,
            ..
        } => forbidden(&[destination, source]),
        DecodedInstruction::LoadByte {
            destination, base, ..
        } => forbidden(&[destination, base]),
        DecodedInstruction::LoadVector128 { base, .. } => forbidden(&[base]),
        DecodedInstruction::LoadByteRegister {
            destination,
            base,
            index,
        }
        | DecodedInstruction::Load64RegisterScaled {
            destination,
            base,
            index,
        } => forbidden(&[destination, base, index]),
        DecodedInstruction::Store64 { source, base, .. } => forbidden(&[source, base]),
        DecodedInstruction::DuplicateByte16 { source, .. } => forbidden(&[source]),
        DecodedInstruction::LogicalShiftRightVariable64 {
            destination,
            source,
            shift,
        } => forbidden(&[destination, source, shift]),
        DecodedInstruction::CompareEqualBytes16 { .. }
        | DecodedInstruction::AndBytes16 { .. }
        | DecodedInstruction::UnsignedMinBytes16 { .. }
        | DecodedInstruction::UnsignedMaxBytes16 { .. }
        | DecodedInstruction::AddAcrossBytes16 { .. }
        | DecodedInstruction::Branch { .. }
        | DecodedInstruction::BranchCondition { .. }
        | DecodedInstruction::Return => None,
    }
}

fn first_forbidden_aggregate_vector_register(instruction: DecodedInstruction) -> Option<u8> {
    fn forbidden(registers: &[u8]) -> Option<u8> {
        registers.iter().copied().find(|&register| register > 5)
    }
    match instruction {
        DecodedInstruction::LoadVector128 { destination, .. }
        | DecodedInstruction::DuplicateByte16 { destination, .. } => forbidden(&[destination]),
        DecodedInstruction::CompareEqualBytes16 {
            destination,
            left,
            right,
        }
        | DecodedInstruction::AndBytes16 {
            destination,
            left,
            right,
        } => forbidden(&[destination, left, right]),
        DecodedInstruction::UnsignedMinBytes16 {
            destination,
            source,
        }
        | DecodedInstruction::UnsignedMaxBytes16 {
            destination,
            source,
        }
        | DecodedInstruction::AddAcrossBytes16 {
            destination,
            source,
        } => forbidden(&[destination, source]),
        DecodedInstruction::MoveVectorByteTo32 { source, .. } => forbidden(&[source]),
        _ => None,
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "critical-register producer forms are intentionally reviewed in one exhaustive gate"
)]
fn validate_aggregate_critical_write(
    instructions: &[DecodedInstruction],
    index: usize,
    literal_len: usize,
    output: AggregateOutput,
) -> Result<(), AuditError> {
    let instruction = instructions[index];
    let Some(destination) = instruction.written_gpr() else {
        return Ok(());
    };
    let valid = match destination {
        0 => {
            matches!(
                instruction,
                DecodedInstruction::MoveZero64 {
                    destination: 0,
                    immediate: _,
                    shift: 0
                }
            ) && matches!(
                instruction_after(instructions, index, 1),
                Some(DecodedInstruction::Return)
            )
        }
        5 => {
            matches!(
                instruction,
                DecodedInstruction::MoveZero64 {
                    destination: 5,
                    immediate: 0,
                    shift: 0
                } | DecodedInstruction::AddImmediate64 {
                    destination: 5,
                    source: 5,
                    immediate: 1 | 16,
                }
            ) || matches!(
                instruction,
                DecodedInstruction::AddImmediate64 {
                    destination: 5,
                    source: 5,
                    immediate,
                } if usize::from(immediate) == literal_len
            )
        }
        6 => matches!(
            instruction,
            DecodedInstruction::SubtractRegister64 {
                destination: 6,
                left: 1,
                right: 12
            }
        ),
        7 => matches!(
            instruction,
            DecodedInstruction::AddImmediate64 {
                destination: 7,
                source: 5,
                immediate: 15
            } | DecodedInstruction::MoveRegister64 {
                destination: 7,
                source: 6
            }
        ),
        8 => matches!(
            instruction,
            DecodedInstruction::Address { destination: 8, .. }
        ),
        12 => matches!(
            instruction,
            DecodedInstruction::MoveZero64 {
                destination: 12,
                immediate,
                shift: 0
            } if usize::from(immediate) == literal_len
        ),
        13 => valid_aggregate_accumulator_write(instructions, index, literal_len, output),
        14 => matches!(
            instruction,
            DecodedInstruction::MoveRegister64 {
                destination: 14,
                source: 13
            }
        ),
        10 => valid_aggregate_x10_write(instructions, index, literal_len),
        11 => valid_aggregate_x11_write(instructions, index, literal_len),
        15 => matches!(
            instruction,
            DecodedInstruction::AddRegister64 {
                destination: 15,
                left: 0,
                right: 5
            } | DecodedInstruction::MoveRegister64 {
                destination: 15,
                source: 15
            } | DecodedInstruction::AddImmediate64 {
                destination: 15,
                source: 15,
                immediate: 1 | 16
            }
        ),
        16 => matches!(
            instruction,
            DecodedInstruction::MoveRegister64 {
                destination: 16,
                source: 8
            } | DecodedInstruction::AddImmediate64 {
                destination: 16,
                source: 16,
                immediate: 1 | 16
            }
        ),
        17 => {
            matches!(
                instruction,
                DecodedInstruction::MoveZero64 {
                    destination: 17,
                    immediate,
                    shift: 0
                } if usize::from(immediate) == literal_len
            ) || matches!(
                instruction,
                DecodedInstruction::SubtractImmediate64 {
                    destination: 17,
                    source: 17,
                    immediate: 1 | 16
                }
            )
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(AuditError::InvalidAggregateControlFlow {
            offset: instruction_offset(index)?,
        })
    }
}

fn valid_aggregate_x10_write(
    instructions: &[DecodedInstruction],
    index: usize,
    literal_len: usize,
) -> bool {
    let instruction = instructions[index];
    if matches!(
        instruction,
        DecodedInstruction::LoadByte {
            destination: 10,
            ..
        } | DecodedInstruction::LoadByteRegister {
            destination: 10,
            ..
        }
    ) {
        return valid_aggregate_load(instructions, index, literal_len);
    }
    if literal_len == 0
        && matches!(
            instruction,
            DecodedInstruction::MoveZero64 {
                destination: 10,
                immediate: u16::MAX,
                shift: 0
            } | DecodedInstruction::MoveKeep64 {
                destination: 10,
                immediate: u16::MAX,
                shift: 16 | 32 | 48
            }
        )
    {
        return true;
    }
    let last = literal_len
        .checked_sub(1)
        .and_then(|value| u16::try_from(value).ok());
    matches!(
        instruction,
        DecodedInstruction::SubtractRegister64 {
            destination: 10,
            left: 1 | 6,
            right: 5
        } | DecodedInstruction::SubtractRegister64 {
            destination: 10,
            left: 11,
            right: 10
        } | DecodedInstruction::AndLowBits64 {
            destination: 10,
            source: 10,
            bits: 8
        } | DecodedInstruction::MoveVectorByteTo32 {
            destination: 10,
            source: 0 | 4
        }
    ) || matches!(
        instruction,
        DecodedInstruction::AddImmediate64 {
            destination: 10,
            source: 15,
            immediate,
        } if Some(immediate) == last
            && matches!(
                instruction_after(instructions, index, 1),
                Some(DecodedInstruction::LoadVector128 {
                    base: 10,
                    offset: 0,
                    ..
                })
            )
    )
}

fn valid_aggregate_x11_write(
    instructions: &[DecodedInstruction],
    index: usize,
    literal_len: usize,
) -> bool {
    matches!(
        instructions[index],
        DecodedInstruction::MoveZero64 {
            destination: 11,
            immediate: 256,
            shift: 0
        }
    ) || (matches!(
        instructions[index],
        DecodedInstruction::LoadByte {
            destination: 11,
            ..
        }
    ) && valid_aggregate_load(instructions, index, literal_len))
}

fn valid_aggregate_accumulator_write(
    instructions: &[DecodedInstruction],
    index: usize,
    literal_len: usize,
    output: AggregateOutput,
) -> bool {
    let instruction = instructions[index];
    if index == 0
        && matches!(
            instruction,
            DecodedInstruction::MoveZero64 {
                destination: 13,
                immediate: 0,
                shift: 0
            }
        )
    {
        return true;
    }
    if literal_len == 0
        && output == AggregateOutput::Count
        && matches!(
            instruction,
            DecodedInstruction::AddImmediate64 {
                destination: 13,
                source: 1,
                immediate: 1
            }
        )
    {
        return true;
    }
    let expected_delta = match output {
        AggregateOutput::Count => 1,
        AggregateOutput::SpanSum => literal_len,
    };
    let is_accumulation = (literal_len == 1
        && matches!(
            instruction,
            DecodedInstruction::AddRegister64 {
                destination: 13,
                left: 13,
                right: 10
            }
        ))
        || matches!(
            instruction,
            DecodedInstruction::AddImmediate64 {
                destination: 13,
                source: 13,
                immediate,
            } if usize::from(immediate) == expected_delta
        );
    is_accumulation
        && matches!(
            index
                .checked_sub(1)
                .and_then(|prior| instructions.get(prior)),
            Some(DecodedInstruction::MoveRegister64 {
                destination: 14,
                source: 13
            })
        )
        && matches!(
            instruction_after(instructions, index, 1),
            Some(DecodedInstruction::CompareRegister64 {
                left: 13,
                right: 14
            })
        )
        && matches!(
            instruction_after(instructions, index, 2),
            Some(DecodedInstruction::BranchCondition {
                condition: crate::Condition::CarryClear,
                ..
            })
        )
}

fn valid_aggregate_load(
    instructions: &[DecodedInstruction],
    index: usize,
    literal_len: usize,
) -> bool {
    if literal_len == 0 {
        return false;
    }
    let last = literal_len
        .checked_sub(1)
        .and_then(|value| u16::try_from(value).ok())
        .expect("nonempty aggregate literal cap fits u16");
    match instructions[index] {
        DecodedInstruction::LoadByte {
            base: 8 | 15,
            offset: 0,
            ..
        }
        | DecodedInstruction::LoadByte {
            base: 16,
            offset: 0,
            ..
        }
        | DecodedInstruction::LoadByteRegister {
            base: 0, index: 5, ..
        }
        | DecodedInstruction::LoadVector128 {
            base: 15 | 16,
            offset: 0,
            ..
        } => true,
        DecodedInstruction::LoadByte {
            base: 8 | 15,
            offset,
            ..
        } if offset == last => valid_aggregate_last_byte_filter_load(instructions, index, last),
        DecodedInstruction::LoadVector128 {
            base: 10,
            offset: 0,
            ..
        } => matches!(
            index.checked_sub(1).and_then(|prior| instructions.get(prior)),
            Some(DecodedInstruction::AddImmediate64 {
                destination: 10,
                source: 15,
                immediate,
            }) if *immediate == last
        ),
        DecodedInstruction::LoadByte { .. }
        | DecodedInstruction::LoadByteRegister { .. }
        | DecodedInstruction::Load64RegisterScaled { .. }
        | DecodedInstruction::LoadVector128 { .. } => false,
        _ => true,
    }
}

fn valid_aggregate_last_byte_filter_load(
    instructions: &[DecodedInstruction],
    index: usize,
    last: u16,
) -> bool {
    match instructions[index] {
        DecodedInstruction::LoadByte {
            destination: 10,
            base: 15,
            offset,
        } if offset == last => {
            matches!(
                index
                    .checked_sub(1)
                    .and_then(|prior| instructions.get(prior)),
                Some(DecodedInstruction::AddRegister64 {
                    destination: 15,
                    left: 0,
                    right: 5
                })
            ) && matches!(
                instruction_after(instructions, index, 1),
                Some(DecodedInstruction::LoadByte {
                    destination: 11,
                    base: 8,
                    offset
                }) if *offset == last
            ) && matches!(
                instruction_after(instructions, index, 2),
                Some(DecodedInstruction::CompareRegister32 {
                    left: 10,
                    right: 11
                })
            )
        }
        DecodedInstruction::LoadByte {
            destination: 11,
            base: 8,
            offset,
        } if offset == last => {
            let initial_filter = matches!(
                index
                    .checked_sub(2)
                    .and_then(|prior| instructions.get(prior)),
                Some(DecodedInstruction::LoadByte {
                    destination: 11,
                    base: 8,
                    offset: 0
                })
            ) && matches!(
                index
                    .checked_sub(1)
                    .and_then(|prior| instructions.get(prior)),
                Some(DecodedInstruction::DuplicateByte16 {
                    destination: 1,
                    source: 11
                })
            ) && matches!(
                instruction_after(instructions, index, 1),
                Some(DecodedInstruction::DuplicateByte16 {
                    destination: 3,
                    source: 11
                })
            );
            let scalar_filter = matches!(
                index.checked_sub(1).and_then(|prior| instructions.get(prior)),
                Some(DecodedInstruction::LoadByte {
                    destination: 10,
                    base: 15,
                    offset
                }) if *offset == last
            ) && matches!(
                instruction_after(instructions, index, 1),
                Some(DecodedInstruction::CompareRegister32 {
                    left: 10,
                    right: 11
                })
            );
            initial_filter || scalar_filter
        }
        _ => false,
    }
}

fn validate_aggregate_branches(
    instructions: &[DecodedInstruction],
    protected_targets: &[usize],
    literal_len: usize,
) -> Result<(), AuditError> {
    let vector_cursor_guard = unique_vector_cursor_guard(instructions);
    for (index, &instruction) in instructions.iter().enumerate() {
        let (DecodedInstruction::Branch { displacement }
        | DecodedInstruction::BranchCondition { displacement, .. }
        | DecodedInstruction::CompareBranchZero64 { displacement, .. }) = instruction
        else {
            continue;
        };
        let target = aggregate_branch_target(index, displacement, instructions.len())?;
        if protected_targets.contains(&target) {
            return Err(AuditError::InvalidAggregateControlFlow {
                offset: instruction_offset(index)?,
            });
        }
        let valid_edge = match target.cmp(&index) {
            core::cmp::Ordering::Less => {
                valid_aggregate_back_edge(instructions, index, target, vector_cursor_guard)
            }
            core::cmp::Ordering::Greater => {
                valid_aggregate_forward_edge(instructions, index, target, literal_len)
            }
            core::cmp::Ordering::Equal => false,
        };
        if !valid_edge {
            return Err(AuditError::InvalidAggregateControlFlow {
                offset: instruction_offset(index)?,
            });
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete aggregate forward-edge template belongs in one auditable allowlist"
)]
fn valid_aggregate_forward_edge(
    instructions: &[DecodedInstruction],
    index: usize,
    target: usize,
    literal_len: usize,
) -> bool {
    let prior = index
        .checked_sub(1)
        .and_then(|value| instructions.get(value));
    let target_instruction = instructions.get(target);
    match instructions[index] {
        DecodedInstruction::Branch { .. } => {
            let finish = matches!(
                prior,
                Some(
                    DecodedInstruction::MoveZero64 {
                        destination: 13,
                        immediate: 0,
                        shift: 0
                    } | DecodedInstruction::AddImmediate64 {
                        destination: 13,
                        source: 1,
                        immediate: 1
                    }
                )
            ) && matches!(
                target_instruction,
                Some(DecodedInstruction::Store64 {
                    source: 13,
                    base: 2,
                    offset: 0
                })
            );
            let enter_scalar_envelope = matches!(
                prior,
                Some(DecodedInstruction::AddImmediate64 {
                    destination: 7,
                    source: 5,
                    immediate: 15
                })
            ) && matches!(
                target_instruction,
                Some(DecodedInstruction::CompareRegister64 { left: 5, right: 7 })
            );
            let enter_confirmation = matches!(
                prior,
                Some(DecodedInstruction::MoveZero64 {
                    destination: 17,
                    immediate,
                    shift: 0
                }) if usize::from(*immediate) == literal_len
            ) && matches!(
                target_instruction,
                Some(DecodedInstruction::CompareBranchZero64 {
                    register: 17,
                    nonzero: false,
                    ..
                })
            );
            finish || enter_scalar_envelope || enter_confirmation
        }
        DecodedInstruction::BranchCondition { condition, .. } => match (prior, condition) {
            (
                Some(DecodedInstruction::CompareRegister64 { left: 1, right: 12 }),
                crate::Condition::CarryClear,
            )
            | (
                Some(DecodedInstruction::CompareRegister64 { left: 5, right: 6 }),
                crate::Condition::Higher,
            )
            | (
                Some(DecodedInstruction::CompareRegister64 { left: 5, right: 1 }),
                crate::Condition::CarrySet,
            ) => matches!(
                target_instruction,
                Some(DecodedInstruction::Store64 {
                    source: 13,
                    base: 2,
                    offset: 0
                })
            ),
            (
                Some(DecodedInstruction::CompareImmediate64 {
                    register: 10,
                    immediate: 16,
                }),
                crate::Condition::CarryClear,
            ) => matches!(
                target_instruction,
                Some(DecodedInstruction::CompareRegister64 { left: 5, right: 1 })
            ),
            (
                Some(DecodedInstruction::CompareImmediate64 {
                    register: 10,
                    immediate: 15,
                }),
                crate::Condition::CarryClear,
            ) => matches!(
                target_instruction,
                Some(DecodedInstruction::MoveRegister64 {
                    destination: 7,
                    source: 6
                })
            ),
            (
                Some(
                    DecodedInstruction::CompareRegister32 {
                        left: 10,
                        right: 11,
                    }
                    | DecodedInstruction::CompareImmediate32 {
                        register: 10,
                        immediate: 255,
                    },
                ),
                crate::Condition::NotEqual,
            ) => matches!(
                target_instruction,
                Some(DecodedInstruction::AddImmediate64 {
                    destination: 5,
                    source: 5,
                    immediate: 1
                })
            ),
            (
                Some(DecodedInstruction::CompareRegister64 {
                    left: 13,
                    right: 14,
                }),
                crate::Condition::CarryClear,
            )
            | (
                Some(DecodedInstruction::CompareRegister64 { left: 1, right: 10 }),
                crate::Condition::Equal,
            ) => matches!(
                target_instruction,
                Some(DecodedInstruction::MoveZero64 {
                    destination: 0,
                    immediate: 1,
                    shift: 0
                })
            ),
            (
                Some(DecodedInstruction::CompareImmediate64 {
                    register: 17,
                    immediate: 16,
                }),
                crate::Condition::CarryClear,
            ) => matches!(
                target_instruction,
                Some(DecodedInstruction::CompareBranchZero64 {
                    register: 17,
                    nonzero: false,
                    ..
                })
            ),
            _ => false,
        },
        DecodedInstruction::CompareBranchZero64 {
            register: 10,
            nonzero: true,
            ..
        } => matches!(
            target_instruction,
            Some(DecodedInstruction::AddImmediate64 {
                destination: 7,
                source: 5,
                immediate: 15
            })
        ),
        DecodedInstruction::CompareBranchZero64 {
            register: 17,
            nonzero: false,
            ..
        } => matches!(
            target_instruction,
            Some(DecodedInstruction::MoveRegister64 {
                destination: 14,
                source: 13
            })
        ),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InitializedState {
    gpr: u32,
    vector: u32,
}

fn validate_aggregate_definite_initialization(
    instructions: &[DecodedInstruction],
) -> Result<(), AuditError> {
    let mut states = vec![None; instructions.len()];
    let initial = InitializedState {
        gpr: register_mask(&[0, 1, 2]),
        vector: 0,
    };
    states[0] = Some(initial);
    let mut pending = vec![0_usize];
    while let Some(index) = pending.pop() {
        let state = states[index].ok_or(AuditError::InvalidAggregateControlFlow {
            offset: instruction_offset(index)?,
        })?;
        let instruction = instructions[index];
        let required_gpr = aggregate_gpr_reads(instruction);
        let required_vector = aggregate_vector_reads(instruction);
        if state.gpr & required_gpr != required_gpr
            || state.vector & required_vector != required_vector
        {
            return Err(AuditError::InvalidAggregateControlFlow {
                offset: instruction_offset(index)?,
            });
        }
        let mut output = state;
        if let Some(destination) = instruction.written_gpr() {
            output.gpr |= register_mask(&[destination]);
        }
        if let Some(destination) = aggregate_vector_write(instruction) {
            output.vector |= register_mask(&[destination]);
        }
        let successors = aggregate_successors(instructions, index)?;
        for successor in successors.into_iter().flatten() {
            match states[successor] {
                None => {
                    states[successor] = Some(output);
                    pending.push(successor);
                }
                Some(existing) => {
                    let intersection = InitializedState {
                        gpr: existing.gpr & output.gpr,
                        vector: existing.vector & output.vector,
                    };
                    if intersection != existing {
                        states[successor] = Some(intersection);
                        pending.push(successor);
                    }
                }
            }
        }
    }
    Ok(())
}

fn register_mask(registers: &[u8]) -> u32 {
    registers.iter().fold(0_u32, |mask, &register| {
        mask | 1_u32.checked_shl(u32::from(register)).unwrap_or(0)
    })
}

#[allow(
    clippy::match_same_arms,
    clippy::too_many_lines,
    reason = "exhaustive source-register classification is the security boundary; parallel arms preserve decoded operand roles"
)]
fn aggregate_gpr_reads(instruction: DecodedInstruction) -> u32 {
    match instruction {
        DecodedInstruction::MoveRegister64 { source, .. } => register_mask(&[source]),
        DecodedInstruction::MoveKeep64 { destination, .. } => register_mask(&[destination]),
        DecodedInstruction::CompareRegister64 { left, right }
        | DecodedInstruction::CompareRegister32 { left, right } => register_mask(&[left, right]),
        DecodedInstruction::CompareImmediate64 { register, .. }
        | DecodedInstruction::CompareImmediate32 { register, .. }
        | DecodedInstruction::CompareBranchZero64 { register, .. } => register_mask(&[register]),
        DecodedInstruction::AddRegister64 { left, right, .. }
        | DecodedInstruction::SubtractRegister64 { left, right, .. } => {
            register_mask(&[left, right])
        }
        DecodedInstruction::AddImmediate64 { source, .. }
        | DecodedInstruction::SubtractImmediate64 { source, .. }
        | DecodedInstruction::AndLowBits64 { source, .. }
        | DecodedInstruction::LogicalShiftRightImmediate64 { source, .. }
        | DecodedInstruction::LogicalShiftLeftImmediate64 { source, .. } => {
            register_mask(&[source])
        }
        DecodedInstruction::LoadByte { base, .. }
        | DecodedInstruction::LoadVector128 { base, .. } => register_mask(&[base]),
        DecodedInstruction::LoadByteRegister { base, index, .. }
        | DecodedInstruction::Load64RegisterScaled { base, index, .. } => {
            register_mask(&[base, index])
        }
        DecodedInstruction::Store64 { source, base, .. } => register_mask(&[source, base]),
        DecodedInstruction::DuplicateByte16 { source, .. } => register_mask(&[source]),
        DecodedInstruction::LogicalShiftRightVariable64 { source, shift, .. } => {
            register_mask(&[source, shift])
        }
        DecodedInstruction::MoveZero64 { .. }
        | DecodedInstruction::MoveVectorByteTo32 { .. }
        | DecodedInstruction::CompareEqualBytes16 { .. }
        | DecodedInstruction::AndBytes16 { .. }
        | DecodedInstruction::UnsignedMinBytes16 { .. }
        | DecodedInstruction::UnsignedMaxBytes16 { .. }
        | DecodedInstruction::AddAcrossBytes16 { .. }
        | DecodedInstruction::Address { .. }
        | DecodedInstruction::Branch { .. }
        | DecodedInstruction::BranchCondition { .. }
        | DecodedInstruction::Return => 0,
    }
}

fn aggregate_vector_reads(instruction: DecodedInstruction) -> u32 {
    match instruction {
        DecodedInstruction::CompareEqualBytes16 { left, right, .. }
        | DecodedInstruction::AndBytes16 { left, right, .. } => register_mask(&[left, right]),
        DecodedInstruction::UnsignedMinBytes16 { source, .. }
        | DecodedInstruction::UnsignedMaxBytes16 { source, .. }
        | DecodedInstruction::AddAcrossBytes16 { source, .. }
        | DecodedInstruction::MoveVectorByteTo32 { source, .. } => register_mask(&[source]),
        _ => 0,
    }
}

const fn aggregate_vector_write(instruction: DecodedInstruction) -> Option<u8> {
    match instruction {
        DecodedInstruction::LoadVector128 { destination, .. }
        | DecodedInstruction::DuplicateByte16 { destination, .. }
        | DecodedInstruction::CompareEqualBytes16 { destination, .. }
        | DecodedInstruction::AndBytes16 { destination, .. }
        | DecodedInstruction::UnsignedMinBytes16 { destination, .. }
        | DecodedInstruction::UnsignedMaxBytes16 { destination, .. }
        | DecodedInstruction::AddAcrossBytes16 { destination, .. } => Some(destination),
        _ => None,
    }
}

fn aggregate_successors(
    instructions: &[DecodedInstruction],
    index: usize,
) -> Result<[Option<usize>; 2], AuditError> {
    let next = index.checked_add(1).ok_or(AuditError::ArithmeticOverflow)?;
    match instructions[index] {
        DecodedInstruction::Branch { displacement } => Ok([
            Some(aggregate_branch_target(
                index,
                displacement,
                instructions.len(),
            )?),
            None,
        ]),
        DecodedInstruction::BranchCondition { displacement, .. }
        | DecodedInstruction::CompareBranchZero64 { displacement, .. } => {
            if next >= instructions.len() {
                return Err(AuditError::InvalidAggregateControlFlow {
                    offset: instruction_offset(index)?,
                });
            }
            Ok([
                Some(next),
                Some(aggregate_branch_target(
                    index,
                    displacement,
                    instructions.len(),
                )?),
            ])
        }
        DecodedInstruction::Return => Ok([None, None]),
        _ => {
            if next >= instructions.len() {
                return Err(AuditError::InvalidAggregateControlFlow {
                    offset: instruction_offset(index)?,
                });
            }
            Ok([Some(next), None])
        }
    }
}

fn valid_aggregate_back_edge(
    instructions: &[DecodedInstruction],
    index: usize,
    target: usize,
    vector_cursor_guard: Option<usize>,
) -> bool {
    let prior = index
        .checked_sub(1)
        .and_then(|value| instructions.get(value));
    match instructions[index] {
        DecodedInstruction::Branch { .. } => {
            let cursor_progress = matches!(
                prior,
                Some(DecodedInstruction::AddImmediate64 {
                    destination: 5,
                    source: 5,
                    immediate: 1..=32
                })
            ) && guarded_cursor_loop(instructions, target);
            let confirmation_progress = matches!(
                prior,
                Some(DecodedInstruction::SubtractImmediate64 {
                    destination: 17,
                    source: 17,
                    immediate: 16
                })
            ) && matches!(
                instructions.get(target),
                Some(DecodedInstruction::CompareImmediate64 {
                    register: 17,
                    immediate: 16
                })
            );
            cursor_progress || confirmation_progress
        }
        DecodedInstruction::BranchCondition {
            condition: crate::Condition::Higher,
            ..
        } => {
            matches!(
                prior,
                Some(DecodedInstruction::CompareRegister64 { left: 5, right: 7 })
            ) && vector_cursor_guard == Some(target)
        }
        DecodedInstruction::CompareBranchZero64 {
            register: 17,
            nonzero: true,
            ..
        } => matches!(
            prior,
            Some(DecodedInstruction::SubtractImmediate64 {
                destination: 17,
                source: 17,
                immediate: 1
            })
        ),
        _ => false,
    }
}

fn unique_vector_cursor_guard(instructions: &[DecodedInstruction]) -> Option<usize> {
    let mut guards = instructions
        .iter()
        .enumerate()
        .filter_map(|(index, instruction)| {
            (matches!(
                instruction,
                DecodedInstruction::CompareRegister64 { left: 5, right: 6 }
            ) && matches!(
                instruction_after(instructions, index, 1),
                Some(DecodedInstruction::BranchCondition {
                    condition: crate::Condition::Higher,
                    ..
                })
            ))
            .then_some(index)
        });
    let guard = guards.next()?;
    guards.next().is_none().then_some(guard)
}

fn guarded_cursor_loop(instructions: &[DecodedInstruction], target: usize) -> bool {
    matches!(
        instructions.get(target),
        Some(DecodedInstruction::CompareRegister64 {
            left: 5,
            right: 1 | 6 | 7
        })
    ) && matches!(
        instruction_after(instructions, target, 1),
        Some(DecodedInstruction::BranchCondition {
            condition: crate::Condition::CarrySet | crate::Condition::Higher,
            ..
        })
    )
}

fn aggregate_branch_target(
    index: usize,
    displacement: i32,
    instruction_count: usize,
) -> Result<usize, AuditError> {
    let offset = i64::from(instruction_offset(index)?);
    let target = offset
        .checked_add(i64::from(displacement))
        .ok_or(AuditError::ArithmeticOverflow)?;
    if target < 0 || target % 4 != 0 {
        return Err(AuditError::InvalidAggregateControlFlow {
            offset: instruction_offset(index)?,
        });
    }
    let target = usize::try_from(target / 4).map_err(|_| AuditError::ArithmeticOverflow)?;
    if target >= instruction_count {
        return Err(AuditError::InvalidAggregateControlFlow {
            offset: instruction_offset(index)?,
        });
    }
    Ok(target)
}

fn validate_aggregate_reachability(instructions: &[DecodedInstruction]) -> Result<(), AuditError> {
    let mut reachable = vec![false; instructions.len()];
    let mut pending = vec![0_usize];
    while let Some(index) = pending.pop() {
        if *reachable
            .get(index)
            .ok_or(AuditError::InvalidAggregateControlFlow { offset: u32::MAX })?
        {
            continue;
        }
        reachable[index] = true;
        let mut add_successor = |successor: usize| -> Result<(), AuditError> {
            if successor >= instructions.len() {
                return Err(AuditError::InvalidAggregateControlFlow {
                    offset: instruction_offset(index)?,
                });
            }
            pending.push(successor);
            Ok(())
        };
        match instructions[index] {
            DecodedInstruction::Branch { displacement } => {
                add_successor(aggregate_branch_target(
                    index,
                    displacement,
                    instructions.len(),
                )?)?;
            }
            DecodedInstruction::BranchCondition { displacement, .. }
            | DecodedInstruction::CompareBranchZero64 { displacement, .. } => {
                add_successor(index.checked_add(1).ok_or(AuditError::ArithmeticOverflow)?)?;
                add_successor(aggregate_branch_target(
                    index,
                    displacement,
                    instructions.len(),
                )?)?;
            }
            DecodedInstruction::Return => {}
            _ => add_successor(index.checked_add(1).ok_or(AuditError::ArithmeticOverflow)?)?,
        }
    }
    if let Some(index) = reachable.iter().position(|&value| !value) {
        return Err(AuditError::InvalidAggregateControlFlow {
            offset: instruction_offset(index)?,
        });
    }
    Ok(())
}

fn validate_layout(image: &NativeImage) -> Result<(), AuditError> {
    if image.code.is_empty()
        || !image.code.len().is_multiple_of(4)
        || image.layout.code_alignment != 16
        || image.layout.rodata_alignment != 16
        || !image.layout.rodata_from_code_start.is_multiple_of(16)
    {
        return Err(AuditError::InvalidLayout);
    }
    let code_len = u32::try_from(image.code.len()).map_err(|_| AuditError::InvalidLayout)?;
    if image.layout.rodata_from_code_start < code_len {
        return Err(AuditError::InvalidLayout);
    }
    let data_len = u32::try_from(image.rodata.len()).map_err(|_| AuditError::InvalidLayout)?;
    let total = image
        .layout
        .rodata_from_code_start
        .checked_add(data_len)
        .ok_or(AuditError::ArithmeticOverflow)?;
    if total != image.layout.total_mapped_bytes
        || image.stats.code_bytes != code_len
        || image.stats.data_bytes != data_len
        || usize::try_from(image.stats.relocations).ok() != Some(image.relocations.len())
        || usize::try_from(image.stats.labels).ok() != Some(image.labels.len())
    {
        return Err(AuditError::InvalidLayout);
    }
    Ok(())
}

fn validate_labels(image: &NativeImage) -> Result<(), AuditError> {
    let code_len = u32::try_from(image.code.len()).map_err(|_| AuditError::InvalidLayout)?;
    let mut prior = None;
    let mut entries = 0_u8;
    for label in &image.labels {
        if label.offset >= code_len || label.offset % 4 != 0 {
            return Err(AuditError::InvalidLabel {
                offset: label.offset,
            });
        }
        if prior.is_some_and(|offset| offset > label.offset) {
            return Err(AuditError::InvalidLabel {
                offset: label.offset,
            });
        }
        if label.kind == LabelKind::Entry {
            entries = entries
                .checked_add(1)
                .ok_or(AuditError::ArithmeticOverflow)?;
            if label.offset != 0 {
                return Err(AuditError::InvalidLabel {
                    offset: label.offset,
                });
            }
        }
        prior = Some(label.offset);
    }
    if entries != 1 {
        return Err(AuditError::InvalidLabel { offset: 0 });
    }
    Ok(())
}

fn validate_symbols(image: &NativeImage) -> Result<(), AuditError> {
    let data_len = u32::try_from(image.rodata.len()).map_err(|_| AuditError::InvalidLayout)?;
    for (index, symbol) in image.symbols.iter().enumerate() {
        if symbol.alignment == 0
            || !symbol.alignment.is_power_of_two()
            || !symbol.offset.is_multiple_of(u32::from(symbol.alignment))
            || symbol
                .offset
                .checked_add(symbol.length)
                .is_none_or(|end| end > data_len)
        {
            return Err(AuditError::InvalidDataSymbol {
                id: symbol.ir_data_id,
            });
        }
        for prior in &image.symbols[..index] {
            let prior_end = prior
                .offset
                .checked_add(prior.length)
                .ok_or(AuditError::ArithmeticOverflow)?;
            if symbol.length != 0 && prior.length != 0 && symbol.offset < prior_end {
                return Err(AuditError::OverlappingDataSymbols {
                    first: prior.ir_data_id,
                    second: symbol.ir_data_id,
                });
            }
        }
    }
    Ok(())
}

fn validate_relocation_order(image: &NativeImage) -> Result<(), AuditError> {
    let code_len = u32::try_from(image.code.len()).map_err(|_| AuditError::InvalidLayout)?;
    let mut prior = None;
    for relocation in &image.relocations {
        if relocation.code_offset % 4 != 0
            || relocation
                .code_offset
                .checked_add(4)
                .is_none_or(|end| end > code_len)
        {
            return Err(AuditError::InvalidRelocation {
                offset: relocation.code_offset,
            });
        }
        if prior == Some(relocation.code_offset) {
            return Err(AuditError::OverlappingRelocations {
                offset: relocation.code_offset,
            });
        }
        if prior.is_some_and(|offset| offset > relocation.code_offset) {
            return Err(AuditError::InvalidRelocation {
                offset: relocation.code_offset,
            });
        }
        prior = Some(relocation.code_offset);
    }
    Ok(())
}

const fn validate_word(expected: u32, actual: u32, offset: u32) -> Result<(), AuditError> {
    if expected != actual {
        return Err(AuditError::RelocationWordMismatch { offset });
    }
    Ok(())
}
