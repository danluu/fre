#![allow(
    clippy::arithmetic_side_effects,
    reason = "fixed-width instruction bitfields are masked before bounded shifts and scaling"
)]

use core::fmt;

/// `AArch64` condition code used by the emitter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Condition {
    Equal = 0,
    NotEqual = 1,
    CarrySet = 2,
    CarryClear = 3,
    Higher = 8,
    LowerOrSame = 9,
    Always = 14,
}

impl Condition {
    const fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(Self::Equal),
            1 => Some(Self::NotEqual),
            2 => Some(Self::CarrySet),
            3 => Some(Self::CarryClear),
            8 => Some(Self::Higher),
            9 => Some(Self::LowerOrSame),
            14 => Some(Self::Always),
            _ => None,
        }
    }
}

/// Independently decoded instruction admitted by the current backend policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedInstruction {
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
    LogicalShiftRightImmediate64 {
        destination: u8,
        source: u8,
        shift: u8,
    },
    LogicalShiftLeftImmediate64 {
        destination: u8,
        source: u8,
        shift: u8,
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
    LoadVectorPair128 {
        first_destination: u8,
        second_destination: u8,
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
    AndBytes16 {
        destination: u8,
        left: u8,
        right: u8,
    },
    ShiftRightNarrowHalfwordsToBytes8 {
        destination: u8,
        source: u8,
    },
    UnsignedMinBytes16 {
        destination: u8,
        source: u8,
    },
    UnsignedMaxBytes16 {
        destination: u8,
        source: u8,
    },
    UnsignedMaxPairwiseBytes16 {
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
    MoveVectorDoubleTo64 {
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
    SveAndPredicateBytesSetFlags {
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
    SveBitClearPredicateBytes {
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
    LogicalShiftRightVariable64 {
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
    Address {
        destination: u8,
        displacement: i32,
    },
    Branch {
        displacement: i32,
    },
    BranchCondition {
        condition: Condition,
        displacement: i32,
    },
    CompareBranchZero64 {
        register: u8,
        nonzero: bool,
        displacement: i32,
    },
    Return,
}

impl DecodedInstruction {
    /// Whether this instruction uses any Advanced SIMD or SVE vector state.
    #[must_use]
    pub const fn is_vector(self) -> bool {
        matches!(
            self,
            Self::LoadVector128 { .. }
                | Self::LoadVectorPair128 { .. }
                | Self::DuplicateByte16 { .. }
                | Self::CompareEqualBytes16 { .. }
                | Self::AndBytes16 { .. }
                | Self::ShiftRightNarrowHalfwordsToBytes8 { .. }
                | Self::UnsignedMinBytes16 { .. }
                | Self::UnsignedMaxBytes16 { .. }
                | Self::UnsignedMaxPairwiseBytes16 { .. }
                | Self::AddAcrossBytes16 { .. }
                | Self::MoveVectorByteTo32 { .. }
                | Self::MoveVectorDoubleTo64 { .. }
                | Self::SvePtrueBytesVl16 { .. }
                | Self::SveDuplicateByte { .. }
                | Self::SveLoadBytes { .. }
                | Self::SveCompareEqualBytes { .. }
                | Self::Sve2MatchBytes { .. }
                | Self::SveAndPredicateBytes { .. }
                | Self::SveAndPredicateBytesSetFlags { .. }
                | Self::SveBitClearPredicateBytesSetFlags { .. }
                | Self::SveBitClearPredicateBytes { .. }
                | Self::SveTestPredicateBytes { .. }
                | Self::SveBreakBeforeBytes { .. }
                | Self::SveBreakAfterBytes { .. }
                | Self::SveCountPredicateBytes { .. }
        )
    }

    /// Whether this instruction specifically requires baseline Advanced SIMD.
    #[must_use]
    pub const fn is_asimd(self) -> bool {
        matches!(
            self,
            Self::LoadVector128 { .. }
                | Self::LoadVectorPair128 { .. }
                | Self::DuplicateByte16 { .. }
                | Self::CompareEqualBytes16 { .. }
                | Self::AndBytes16 { .. }
                | Self::ShiftRightNarrowHalfwordsToBytes8 { .. }
                | Self::UnsignedMinBytes16 { .. }
                | Self::UnsignedMaxBytes16 { .. }
                | Self::UnsignedMaxPairwiseBytes16 { .. }
                | Self::AddAcrossBytes16 { .. }
                | Self::MoveVectorByteTo32 { .. }
                | Self::MoveVectorDoubleTo64 { .. }
        )
    }

    /// Whether this instruction requires SVE (including SVE2 instructions).
    #[must_use]
    pub const fn is_sve(self) -> bool {
        matches!(
            self,
            Self::SvePtrueBytesVl16 { .. }
                | Self::SveDuplicateByte { .. }
                | Self::SveLoadBytes { .. }
                | Self::SveCompareEqualBytes { .. }
                | Self::Sve2MatchBytes { .. }
                | Self::SveAndPredicateBytes { .. }
                | Self::SveAndPredicateBytesSetFlags { .. }
                | Self::SveBitClearPredicateBytesSetFlags { .. }
                | Self::SveBitClearPredicateBytes { .. }
                | Self::SveTestPredicateBytes { .. }
                | Self::SveBreakBeforeBytes { .. }
                | Self::SveBreakAfterBytes { .. }
                | Self::SveCountPredicateBytes { .. }
        )
    }

    /// Whether this instruction requires an SVE2-only encoding.
    #[must_use]
    pub const fn is_sve2(self) -> bool {
        matches!(self, Self::Sve2MatchBytes { .. })
    }

    /// Direct PC-relative target displacement, if any.
    #[must_use]
    pub const fn direct_displacement(self) -> Option<i32> {
        match self {
            Self::Address { displacement, .. }
            | Self::Branch { displacement }
            | Self::BranchCondition { displacement, .. }
            | Self::CompareBranchZero64 { displacement, .. } => Some(displacement),
            _ => None,
        }
    }

    /// General-purpose register overwritten by this instruction, if any.
    ///
    /// Vector-only destinations are intentionally excluded. The independent
    /// auditor uses this to prove that an ABI result-pointer register remains
    /// unchanged from entry through every permitted result store.
    #[must_use]
    pub const fn written_gpr(self) -> Option<u8> {
        match self {
            Self::MoveRegister64 { destination, .. }
            | Self::MoveZero64 { destination, .. }
            | Self::MoveKeep64 { destination, .. }
            | Self::AddRegister64 { destination, .. }
            | Self::AddImmediate64 { destination, .. }
            | Self::SubtractRegister64 { destination, .. }
            | Self::SubtractImmediate64 { destination, .. }
            | Self::AndRegister64 { destination, .. }
            | Self::AndLowBits64 { destination, .. }
            | Self::LogicalShiftRightImmediate64 { destination, .. }
            | Self::LogicalShiftLeftImmediate64 { destination, .. }
            | Self::LoadByte { destination, .. }
            | Self::LoadByteRegister { destination, .. }
            | Self::Load64RegisterScaled { destination, .. }
            | Self::MoveVectorByteTo32 { destination, .. }
            | Self::MoveVectorDoubleTo64 { destination, .. }
            | Self::SveCountPredicateBytes { destination, .. }
            | Self::LogicalShiftRightVariable64 { destination, .. }
            | Self::ReverseBits64 { destination, .. }
            | Self::CountLeadingZeros64 { destination, .. }
            | Self::Address { destination, .. } => Some(destination),
            Self::CompareRegister64 { .. }
            | Self::CompareRegister32 { .. }
            | Self::CompareImmediate64 { .. }
            | Self::CompareImmediate32 { .. }
            | Self::Store64 { .. }
            | Self::LoadVector128 { .. }
            | Self::LoadVectorPair128 { .. }
            | Self::DuplicateByte16 { .. }
            | Self::CompareEqualBytes16 { .. }
            | Self::AndBytes16 { .. }
            | Self::ShiftRightNarrowHalfwordsToBytes8 { .. }
            | Self::UnsignedMinBytes16 { .. }
            | Self::UnsignedMaxBytes16 { .. }
            | Self::UnsignedMaxPairwiseBytes16 { .. }
            | Self::AddAcrossBytes16 { .. }
            | Self::SvePtrueBytesVl16 { .. }
            | Self::SveDuplicateByte { .. }
            | Self::SveLoadBytes { .. }
            | Self::SveCompareEqualBytes { .. }
            | Self::Sve2MatchBytes { .. }
            | Self::SveAndPredicateBytes { .. }
            | Self::SveAndPredicateBytesSetFlags { .. }
            | Self::SveBitClearPredicateBytesSetFlags { .. }
            | Self::SveBitClearPredicateBytes { .. }
            | Self::SveTestPredicateBytes { .. }
            | Self::SveBreakBeforeBytes { .. }
            | Self::SveBreakAfterBytes { .. }
            | Self::Branch { .. }
            | Self::BranchCondition { .. }
            | Self::CompareBranchZero64 { .. }
            | Self::Return => None,
        }
    }

    /// Whether this instruction explicitly names one general-purpose
    /// register.
    ///
    /// Implicit architectural operands such as `RET`'s link register and all
    /// vector or predicate register numbers are excluded. The register-return
    /// Search-v2 auditor uses this complete operand projection to prove that
    /// the removed Search-v1 result-pointer register `x4` is neither read nor
    /// written.
    #[allow(
        clippy::match_same_arms,
        clippy::too_many_lines,
        reason = "operand arities remain grouped by decoded ISA form for security review"
    )]
    pub(crate) fn uses_gpr(self, register: u8) -> bool {
        match self {
            Self::MoveRegister64 {
                destination,
                source,
            } => [destination, source].contains(&register),
            Self::MoveZero64 { destination, .. }
            | Self::MoveKeep64 { destination, .. }
            | Self::CompareImmediate64 {
                register: destination,
                ..
            }
            | Self::CompareImmediate32 {
                register: destination,
                ..
            }
            | Self::MoveVectorByteTo32 { destination, .. }
            | Self::MoveVectorDoubleTo64 { destination, .. }
            | Self::SveCountPredicateBytes { destination, .. }
            | Self::Address { destination, .. }
            | Self::CompareBranchZero64 {
                register: destination,
                ..
            } => destination == register,
            Self::CompareRegister64 { left, right } | Self::CompareRegister32 { left, right } => {
                [left, right].contains(&register)
            }
            Self::AddRegister64 {
                destination,
                left,
                right,
            }
            | Self::SubtractRegister64 {
                destination,
                left,
                right,
            }
            | Self::AndRegister64 {
                destination,
                left,
                right,
            } => [destination, left, right].contains(&register),
            Self::AddImmediate64 {
                destination,
                source,
                ..
            }
            | Self::SubtractImmediate64 {
                destination,
                source,
                ..
            }
            | Self::AndLowBits64 {
                destination,
                source,
                ..
            }
            | Self::LogicalShiftRightImmediate64 {
                destination,
                source,
                ..
            }
            | Self::LogicalShiftLeftImmediate64 {
                destination,
                source,
                ..
            }
            | Self::ReverseBits64 {
                destination,
                source,
            }
            | Self::CountLeadingZeros64 {
                destination,
                source,
            } => [destination, source].contains(&register),
            Self::LoadByte {
                destination, base, ..
            } => [destination, base].contains(&register),
            Self::LoadVector128 { base, .. }
            | Self::LoadVectorPair128 { base, .. }
            | Self::SveLoadBytes { base, .. } => base == register,
            Self::LoadByteRegister {
                destination,
                base,
                index,
            }
            | Self::Load64RegisterScaled {
                destination,
                base,
                index,
            } => [destination, base, index].contains(&register),
            Self::Store64 { source, base, .. } => [source, base].contains(&register),
            Self::DuplicateByte16 { source, .. } | Self::SveDuplicateByte { source, .. } => {
                source == register
            }
            Self::LogicalShiftRightVariable64 {
                destination,
                source,
                shift,
            } => [destination, source, shift].contains(&register),
            Self::CompareEqualBytes16 { .. }
            | Self::AndBytes16 { .. }
            | Self::ShiftRightNarrowHalfwordsToBytes8 { .. }
            | Self::UnsignedMinBytes16 { .. }
            | Self::UnsignedMaxBytes16 { .. }
            | Self::UnsignedMaxPairwiseBytes16 { .. }
            | Self::AddAcrossBytes16 { .. }
            | Self::SvePtrueBytesVl16 { .. }
            | Self::SveCompareEqualBytes { .. }
            | Self::Sve2MatchBytes { .. }
            | Self::SveAndPredicateBytes { .. }
            | Self::SveAndPredicateBytesSetFlags { .. }
            | Self::SveBitClearPredicateBytesSetFlags { .. }
            | Self::SveBitClearPredicateBytes { .. }
            | Self::SveTestPredicateBytes { .. }
            | Self::SveBreakBeforeBytes { .. }
            | Self::SveBreakAfterBytes { .. }
            | Self::Branch { .. }
            | Self::BranchCondition { .. }
            | Self::Return => false,
        }
    }
}

/// Failure from the small policy decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    UnalignedCodeLength { length: usize },
    UnknownInstruction { offset: u32, word: u32 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AArch64 decode failed: {self:?}")
    }
}

impl std::error::Error for DecodeError {}

/// Decode an entire little-endian code section using the independent policy
/// decoder. Unknown or forbidden instructions are rejected.
pub fn decode(code: &[u8]) -> Result<Vec<DecodedInstruction>, DecodeError> {
    if !code.len().is_multiple_of(4) {
        return Err(DecodeError::UnalignedCodeLength { length: code.len() });
    }
    let mut decoded = Vec::with_capacity(code.len() / 4);
    for (index, bytes) in code.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let offset = u32::try_from(index)
            .ok()
            .and_then(|value| value.checked_mul(4))
            .unwrap_or(u32::MAX);
        decoded.push(decode_one(word, offset)?);
    }
    Ok(decoded)
}

/// Decode one little-endian instruction word at a byte offset.
#[allow(
    clippy::too_many_lines,
    reason = "a single ordered mask table keeps the authenticity decoder easy to inspect"
)]
pub fn decode_one(word: u32, offset: u32) -> Result<DecodedInstruction, DecodeError> {
    let rd = reg(word);
    let rn = reg(word >> 5);
    let rm = reg(word >> 16);
    let instruction = if word & 0xffe0_ffe0 == 0xaa00_03e0 {
        DecodedInstruction::MoveRegister64 {
            destination: rd,
            source: rm,
        }
    } else if word & 0xff80_0000 == 0xd280_0000 {
        DecodedInstruction::MoveZero64 {
            destination: rd,
            immediate: imm16(word),
            shift: halfword_shift(word),
        }
    } else if word & 0xff80_0000 == 0xf280_0000 {
        DecodedInstruction::MoveKeep64 {
            destination: rd,
            immediate: imm16(word),
            shift: halfword_shift(word),
        }
    } else if word & 0xffe0_fc1f == 0xeb00_001f {
        DecodedInstruction::CompareRegister64 {
            left: rn,
            right: rm,
        }
    } else if word & 0xffe0_fc1f == 0x6b00_001f {
        DecodedInstruction::CompareRegister32 {
            left: rn,
            right: rm,
        }
    } else if word & 0xffc0_001f == 0xf100_001f {
        DecodedInstruction::CompareImmediate64 {
            register: rn,
            immediate: imm12(word),
        }
    } else if word & 0xffc0_001f == 0x7100_001f {
        DecodedInstruction::CompareImmediate32 {
            register: rn,
            immediate: imm12(word),
        }
    } else if word & 0xffe0_fc00 == 0x8b00_0000 {
        DecodedInstruction::AddRegister64 {
            destination: rd,
            left: rn,
            right: rm,
        }
    } else if word & 0xffc0_0000 == 0x9100_0000 {
        DecodedInstruction::AddImmediate64 {
            destination: rd,
            source: rn,
            immediate: imm12(word),
        }
    } else if word & 0xffe0_fc00 == 0xcb00_0000 {
        DecodedInstruction::SubtractRegister64 {
            destination: rd,
            left: rn,
            right: rm,
        }
    } else if word & 0xffc0_0000 == 0xd100_0000 {
        DecodedInstruction::SubtractImmediate64 {
            destination: rd,
            source: rn,
            immediate: imm12(word),
        }
    } else if word & 0xffe0_fc00 == 0x8a00_0000 {
        DecodedInstruction::AndRegister64 {
            destination: rd,
            left: rn,
            right: rm,
        }
    } else if word & 0xffc0_0000 == 0x9240_0000 && (word >> 16).trailing_zeros() >= 6 {
        DecodedInstruction::AndLowBits64 {
            destination: rd,
            source: rn,
            bits: u8::try_from(((word >> 10) & 0x3f).checked_add(1).expect("six-bit field"))
                .expect("at most 64"),
        }
    } else if word & 0xffc0_0000 == 0xd340_0000 {
        decode_bitfield(word, offset)?
    } else if word & 0xffc0_0000 == 0x3940_0000 {
        DecodedInstruction::LoadByte {
            destination: rd,
            base: rn,
            offset: imm12(word),
        }
    } else if word & 0xffe0_fc00 == 0x3860_6800 {
        DecodedInstruction::LoadByteRegister {
            destination: rd,
            base: rn,
            index: rm,
        }
    } else if word & 0xffe0_fc00 == 0xf860_7800 {
        DecodedInstruction::Load64RegisterScaled {
            destination: rd,
            base: rn,
            index: rm,
        }
    } else if word & 0xffc0_0000 == 0xf900_0000 {
        DecodedInstruction::Store64 {
            source: rd,
            base: rn,
            offset: imm12(word).checked_mul(8).expect("scaled imm12 fits u16"),
        }
    } else if word & 0xffc0_0000 == 0x3dc0_0000 {
        DecodedInstruction::LoadVector128 {
            destination: rd,
            base: rn,
            offset: imm12(word)
                .checked_mul(16)
                .expect("scaled vector imm12 fits u16"),
        }
    } else if word & 0xffe0_0000 == 0xad40_0000 {
        // LDP Q has a signed imm7. Pinning bit 21 to zero admits only its
        // nonnegative half while leaving the low six immediate bits available.
        DecodedInstruction::LoadVectorPair128 {
            first_destination: rd,
            second_destination: reg(word >> 10),
            base: rn,
            offset: u16::try_from((word >> 15) & 0x3f)
                .expect("six-bit pair offset")
                .checked_mul(16)
                .expect("scaled vector-pair offset fits u16"),
        }
    } else if word & 0xffff_fc00 == 0x4e01_0c00 {
        DecodedInstruction::DuplicateByte16 {
            destination: rd,
            source: rn,
        }
    } else if word & 0xffe0_fc00 == 0x6e20_8c00 {
        DecodedInstruction::CompareEqualBytes16 {
            destination: rd,
            left: rn,
            right: rm,
        }
    } else if word & 0xffe0_fc00 == 0x4e20_1c00 {
        DecodedInstruction::AndBytes16 {
            destination: rd,
            left: rn,
            right: rm,
        }
    } else if word & 0xffff_fc00 == 0x0f0c_8400 {
        DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
            destination: rd,
            source: rn,
        }
    } else if word & 0xffff_fc00 == 0x6e31_a800 {
        DecodedInstruction::UnsignedMinBytes16 {
            destination: rd,
            source: rn,
        }
    } else if word & 0xffff_fc00 == 0x6e30_a800 {
        DecodedInstruction::UnsignedMaxBytes16 {
            destination: rd,
            source: rn,
        }
    } else if word & 0xffe0_fc00 == 0x6e20_a400 {
        DecodedInstruction::UnsignedMaxPairwiseBytes16 {
            destination: rd,
            left: rn,
            right: rm,
        }
    } else if word & 0xffff_fc00 == 0x4e31_b800 {
        DecodedInstruction::AddAcrossBytes16 {
            destination: rd,
            source: rn,
        }
    } else if word & 0xffff_fc00 == 0x0e01_3c00 {
        DecodedInstruction::MoveVectorByteTo32 {
            destination: rd,
            source: rn,
        }
    } else if word & 0xffff_fc00 == 0x9e66_0000 {
        DecodedInstruction::MoveVectorDoubleTo64 {
            destination: rd,
            source: rn,
        }
    } else if word & 0xffff_fff0 == 0x2518_e120 {
        DecodedInstruction::SvePtrueBytesVl16 {
            destination: predicate(word),
        }
    } else if word & 0xffff_fc00 == 0x0520_3800 {
        DecodedInstruction::SveDuplicateByte {
            destination: rd,
            source: rn,
        }
    } else if word & 0xffff_e000 == 0xa400_a000 {
        DecodedInstruction::SveLoadBytes {
            destination: rd,
            predicate: governing_predicate(word),
            base: rn,
        }
    } else if word & 0xffe0_e010 == 0x2400_a000 {
        DecodedInstruction::SveCompareEqualBytes {
            destination: predicate(word),
            predicate: governing_predicate(word),
            left: rn,
            right: rm,
        }
    } else if word & 0xffe0_e010 == 0x4520_8000 {
        DecodedInstruction::Sve2MatchBytes {
            destination: predicate(word),
            predicate: governing_predicate(word),
            left: rn,
            right: rm,
        }
    } else if word & 0xfff0_e210 == 0x2540_4000 {
        DecodedInstruction::SveAndPredicateBytesSetFlags {
            destination: predicate(word),
            predicate: governing_predicate(word),
            left: predicate(word >> 5),
            right: predicate(word >> 16),
        }
    } else if word & 0xfff0_e210 == 0x2500_4000 {
        DecodedInstruction::SveAndPredicateBytes {
            destination: predicate(word),
            predicate: governing_predicate(word),
            left: predicate(word >> 5),
            right: predicate(word >> 16),
        }
    } else if word & 0xfff0_e210 == 0x2540_4010 {
        DecodedInstruction::SveBitClearPredicateBytesSetFlags {
            destination: predicate(word),
            predicate: governing_predicate(word),
            left: predicate(word >> 5),
            right: predicate(word >> 16),
        }
    } else if word & 0xfff0_e210 == 0x2500_4010 {
        DecodedInstruction::SveBitClearPredicateBytes {
            destination: predicate(word),
            predicate: governing_predicate(word),
            left: predicate(word >> 5),
            right: predicate(word >> 16),
        }
    } else if word & 0xffff_e21f == 0x2550_c000 {
        DecodedInstruction::SveTestPredicateBytes {
            predicate: governing_predicate(word),
            tested: predicate(word >> 5),
        }
    } else if word & 0xffff_e210 == 0x2590_4000 {
        DecodedInstruction::SveBreakBeforeBytes {
            destination: predicate(word),
            predicate: governing_predicate(word),
            source: predicate(word >> 5),
        }
    } else if word & 0xffff_e210 == 0x2510_4000 {
        DecodedInstruction::SveBreakAfterBytes {
            destination: predicate(word),
            predicate: governing_predicate(word),
            source: predicate(word >> 5),
        }
    } else if word & 0xffff_e200 == 0x2520_8000 {
        DecodedInstruction::SveCountPredicateBytes {
            destination: rd,
            predicate: governing_predicate(word),
            source: predicate(word >> 5),
        }
    } else if word & 0xffe0_fc00 == 0x9ac0_2400 {
        DecodedInstruction::LogicalShiftRightVariable64 {
            destination: rd,
            source: rn,
            shift: rm,
        }
    } else if word & 0xffff_fc00 == 0xdac0_0000 {
        DecodedInstruction::ReverseBits64 {
            destination: rd,
            source: rn,
        }
    } else if word & 0xffff_fc00 == 0xdac0_1000 {
        DecodedInstruction::CountLeadingZeros64 {
            destination: rd,
            source: rn,
        }
    } else if word & 0x9f00_0000 == 0x1000_0000 {
        DecodedInstruction::Address {
            destination: rd,
            displacement: decode_adr_displacement(word),
        }
    } else if word & 0xfc00_0000 == 0x1400_0000 {
        DecodedInstruction::Branch {
            displacement: sign_extend(word & 0x03ff_ffff, 26) << 2,
        }
    } else if word & 0xff00_0010 == 0x5400_0000 {
        let condition = Condition::from_bits(u8::try_from(word & 0xf).expect("four-bit field"))
            .ok_or(DecodeError::UnknownInstruction { offset, word })?;
        DecodedInstruction::BranchCondition {
            condition,
            displacement: sign_extend((word >> 5) & 0x7_ffff, 19) << 2,
        }
    } else if word & 0xff00_0000 == 0xb400_0000 || word & 0xff00_0000 == 0xb500_0000 {
        DecodedInstruction::CompareBranchZero64 {
            register: rd,
            nonzero: word & 0x0100_0000 != 0,
            displacement: sign_extend((word >> 5) & 0x7_ffff, 19) << 2,
        }
    } else if word == 0xd65f_03c0 {
        DecodedInstruction::Return
    } else {
        return Err(DecodeError::UnknownInstruction { offset, word });
    };
    Ok(instruction)
}

/// Independent canonical re-encoding used only to authenticate decoder round
/// trips. This is intentionally separate from the lowering assembler.
#[allow(
    clippy::too_many_lines,
    reason = "one exhaustive match makes missing instruction round trips a compile error"
)]
pub(crate) fn canonical_word(instruction: DecodedInstruction) -> Option<u32> {
    let word = match instruction {
        DecodedInstruction::MoveRegister64 {
            destination,
            source,
        } => 0xaa00_03e0 | field(source, 16)? | field(destination, 0)?,
        DecodedInstruction::MoveZero64 {
            destination,
            immediate,
            shift,
        } => {
            0xd280_0000
                | halfword_field(shift)?
                | (u32::from(immediate) << 5)
                | field(destination, 0)?
        }
        DecodedInstruction::MoveKeep64 {
            destination,
            immediate,
            shift,
        } => {
            0xf280_0000
                | halfword_field(shift)?
                | (u32::from(immediate) << 5)
                | field(destination, 0)?
        }
        DecodedInstruction::CompareRegister64 { left, right } => {
            0xeb00_001f | field(right, 16)? | field(left, 5)?
        }
        DecodedInstruction::CompareRegister32 { left, right } => {
            0x6b00_001f | field(right, 16)? | field(left, 5)?
        }
        DecodedInstruction::CompareImmediate64 {
            register,
            immediate,
        } => 0xf100_001f | immediate_field(immediate, 12, 10)? | field(register, 5)?,
        DecodedInstruction::CompareImmediate32 {
            register,
            immediate,
        } => 0x7100_001f | immediate_field(immediate, 12, 10)? | field(register, 5)?,
        DecodedInstruction::AddRegister64 {
            destination,
            left,
            right,
        } => 0x8b00_0000 | field(right, 16)? | field(left, 5)? | field(destination, 0)?,
        DecodedInstruction::AddImmediate64 {
            destination,
            source,
            immediate,
        } => {
            0x9100_0000
                | immediate_field(immediate, 12, 10)?
                | field(source, 5)?
                | field(destination, 0)?
        }
        DecodedInstruction::SubtractRegister64 {
            destination,
            left,
            right,
        } => 0xcb00_0000 | field(right, 16)? | field(left, 5)? | field(destination, 0)?,
        DecodedInstruction::SubtractImmediate64 {
            destination,
            source,
            immediate,
        } => {
            0xd100_0000
                | immediate_field(immediate, 12, 10)?
                | field(source, 5)?
                | field(destination, 0)?
        }
        DecodedInstruction::AndRegister64 {
            destination,
            left,
            right,
        } => 0x8a00_0000 | field(right, 16)? | field(left, 5)? | field(destination, 0)?,
        DecodedInstruction::AndLowBits64 {
            destination,
            source,
            bits,
        } => {
            let mask = bits.checked_sub(1)?;
            0x9240_0000 | (u32::from(mask) << 10) | field(source, 5)? | field(destination, 0)?
        }
        DecodedInstruction::LogicalShiftRightImmediate64 {
            destination,
            source,
            shift,
        } => {
            0xd340_0000
                | (u32::from(shift) << 16)
                | (63 << 10)
                | field(source, 5)?
                | field(destination, 0)?
        }
        DecodedInstruction::LogicalShiftLeftImmediate64 {
            destination,
            source,
            shift,
        } => {
            let rotate = 64_u8.checked_sub(shift)?;
            let mask = 63_u8.checked_sub(shift)?;
            0xd340_0000
                | (u32::from(rotate) << 16)
                | (u32::from(mask) << 10)
                | field(source, 5)?
                | field(destination, 0)?
        }
        DecodedInstruction::LoadByte {
            destination,
            base,
            offset,
        } => {
            0x3940_0000
                | immediate_field(offset, 12, 10)?
                | field(base, 5)?
                | field(destination, 0)?
        }
        DecodedInstruction::LoadByteRegister {
            destination,
            base,
            index,
        } => 0x3860_6800 | field(index, 16)? | field(base, 5)? | field(destination, 0)?,
        DecodedInstruction::Load64RegisterScaled {
            destination,
            base,
            index,
        } => 0xf860_7800 | field(index, 16)? | field(base, 5)? | field(destination, 0)?,
        DecodedInstruction::Store64 {
            source,
            base,
            offset,
        } => {
            if !offset.is_multiple_of(8) {
                return None;
            }
            0xf900_0000 | immediate_field(offset / 8, 12, 10)? | field(base, 5)? | field(source, 0)?
        }
        DecodedInstruction::LoadVector128 {
            destination,
            base,
            offset,
        } => {
            if !offset.is_multiple_of(16) {
                return None;
            }
            0x3dc0_0000
                | immediate_field(offset / 16, 12, 10)?
                | field(base, 5)?
                | field(destination, 0)?
        }
        DecodedInstruction::LoadVectorPair128 {
            first_destination,
            second_destination,
            base,
            offset,
        } => {
            if first_destination == second_destination
                || !offset.is_multiple_of(16)
                || offset / 16 >= 64
            {
                return None;
            }
            0xad40_0000
                | (u32::from(offset / 16) << 15)
                | field(second_destination, 10)?
                | field(base, 5)?
                | field(first_destination, 0)?
        }
        DecodedInstruction::DuplicateByte16 {
            destination,
            source,
        } => 0x4e01_0c00 | field(source, 5)? | field(destination, 0)?,
        DecodedInstruction::CompareEqualBytes16 {
            destination,
            left,
            right,
        } => 0x6e20_8c00 | field(right, 16)? | field(left, 5)? | field(destination, 0)?,
        DecodedInstruction::AndBytes16 {
            destination,
            left,
            right,
        } => 0x4e20_1c00 | field(right, 16)? | field(left, 5)? | field(destination, 0)?,
        DecodedInstruction::ShiftRightNarrowHalfwordsToBytes8 {
            destination,
            source,
        } => 0x0f0c_8400 | field(source, 5)? | field(destination, 0)?,
        DecodedInstruction::UnsignedMinBytes16 {
            destination,
            source,
        } => 0x6e31_a800 | field(source, 5)? | field(destination, 0)?,
        DecodedInstruction::UnsignedMaxBytes16 {
            destination,
            source,
        } => 0x6e30_a800 | field(source, 5)? | field(destination, 0)?,
        DecodedInstruction::UnsignedMaxPairwiseBytes16 {
            destination,
            left,
            right,
        } => 0x6e20_a400 | field(right, 16)? | field(left, 5)? | field(destination, 0)?,
        DecodedInstruction::AddAcrossBytes16 {
            destination,
            source,
        } => 0x4e31_b800 | field(source, 5)? | field(destination, 0)?,
        DecodedInstruction::MoveVectorByteTo32 {
            destination,
            source,
        } => 0x0e01_3c00 | field(source, 5)? | field(destination, 0)?,
        DecodedInstruction::MoveVectorDoubleTo64 {
            destination,
            source,
        } => 0x9e66_0000 | field(source, 5)? | field(destination, 0)?,
        DecodedInstruction::SvePtrueBytesVl16 { destination } => {
            0x2518_e120 | predicate_field(destination, 0)?
        }
        DecodedInstruction::SveDuplicateByte {
            destination,
            source,
        } => 0x0520_3800 | field(source, 5)? | field(destination, 0)?,
        DecodedInstruction::SveLoadBytes {
            destination,
            predicate,
            base,
        } => {
            0xa400_a000
                | governing_predicate_field(predicate)?
                | field(base, 5)?
                | field(destination, 0)?
        }
        DecodedInstruction::SveCompareEqualBytes {
            destination,
            predicate,
            left,
            right,
        } => {
            0x2400_a000
                | field(right, 16)?
                | governing_predicate_field(predicate)?
                | field(left, 5)?
                | predicate_field(destination, 0)?
        }
        DecodedInstruction::Sve2MatchBytes {
            destination,
            predicate,
            left,
            right,
        } => {
            0x4520_8000
                | field(right, 16)?
                | governing_predicate_field(predicate)?
                | field(left, 5)?
                | predicate_field(destination, 0)?
        }
        DecodedInstruction::SveAndPredicateBytes {
            destination,
            predicate,
            left,
            right,
        } => {
            0x2500_4000
                | predicate_field(right, 16)?
                | governing_predicate_field(predicate)?
                | predicate_field(left, 5)?
                | predicate_field(destination, 0)?
        }
        DecodedInstruction::SveAndPredicateBytesSetFlags {
            destination,
            predicate,
            left,
            right,
        } => {
            0x2540_4000
                | predicate_field(right, 16)?
                | governing_predicate_field(predicate)?
                | predicate_field(left, 5)?
                | predicate_field(destination, 0)?
        }
        DecodedInstruction::SveBitClearPredicateBytesSetFlags {
            destination,
            predicate,
            left,
            right,
        } => {
            0x2540_4010
                | predicate_field(right, 16)?
                | governing_predicate_field(predicate)?
                | predicate_field(left, 5)?
                | predicate_field(destination, 0)?
        }
        DecodedInstruction::SveBitClearPredicateBytes {
            destination,
            predicate,
            left,
            right,
        } => {
            0x2500_4010
                | predicate_field(right, 16)?
                | governing_predicate_field(predicate)?
                | predicate_field(left, 5)?
                | predicate_field(destination, 0)?
        }
        DecodedInstruction::SveTestPredicateBytes { predicate, tested } => {
            0x2550_c000 | governing_predicate_field(predicate)? | predicate_field(tested, 5)?
        }
        DecodedInstruction::SveBreakBeforeBytes {
            destination,
            predicate,
            source,
        } => {
            0x2590_4000
                | governing_predicate_field(predicate)?
                | predicate_field(source, 5)?
                | predicate_field(destination, 0)?
        }
        DecodedInstruction::SveBreakAfterBytes {
            destination,
            predicate,
            source,
        } => {
            0x2510_4000
                | governing_predicate_field(predicate)?
                | predicate_field(source, 5)?
                | predicate_field(destination, 0)?
        }
        DecodedInstruction::SveCountPredicateBytes {
            destination,
            predicate,
            source,
        } => {
            0x2520_8000
                | governing_predicate_field(predicate)?
                | predicate_field(source, 5)?
                | field(destination, 0)?
        }
        DecodedInstruction::LogicalShiftRightVariable64 {
            destination,
            source,
            shift,
        } => 0x9ac0_2400 | field(shift, 16)? | field(source, 5)? | field(destination, 0)?,
        DecodedInstruction::ReverseBits64 {
            destination,
            source,
        } => 0xdac0_0000 | field(source, 5)? | field(destination, 0)?,
        DecodedInstruction::CountLeadingZeros64 {
            destination,
            source,
        } => 0xdac0_1000 | field(source, 5)? | field(destination, 0)?,
        DecodedInstruction::Address {
            destination,
            displacement,
        } => {
            if !(-1_048_576..=1_048_575).contains(&displacement) {
                return None;
            }
            let encoded = displacement.cast_unsigned() & 0x1f_ffff;
            0x1000_0000 | ((encoded & 3) << 29) | ((encoded >> 2) << 5) | field(destination, 0)?
        }
        DecodedInstruction::Branch { displacement } => {
            0x1400_0000 | displacement_field(displacement, 26, 0)?
        }
        DecodedInstruction::BranchCondition {
            condition,
            displacement,
        } => 0x5400_0000 | displacement_field(displacement, 19, 5)? | condition_bits(condition),
        DecodedInstruction::CompareBranchZero64 {
            register,
            nonzero,
            displacement,
        } => {
            let base = if nonzero { 0xb500_0000 } else { 0xb400_0000 };
            base | displacement_field(displacement, 19, 5)? | field(register, 0)?
        }
        DecodedInstruction::Return => 0xd65f_03c0,
    };
    Some(word)
}

fn field(value: u8, shift: u8) -> Option<u32> {
    (value < 32).then(|| u32::from(value) << shift)
}

fn predicate_field(value: u8, shift: u8) -> Option<u32> {
    (value < 16).then(|| u32::from(value) << shift)
}

fn governing_predicate_field(value: u8) -> Option<u32> {
    (value < 8).then(|| u32::from(value) << 10)
}

fn immediate_field(value: u16, bits: u8, shift: u8) -> Option<u32> {
    let limit = 1_u32.checked_shl(u32::from(bits))?;
    (u32::from(value) < limit).then(|| u32::from(value) << shift)
}

fn halfword_field(shift: u8) -> Option<u32> {
    if !shift.is_multiple_of(16) || shift > 48 {
        return None;
    }
    Some(u32::from(shift / 16) << 21)
}

fn displacement_field(displacement: i32, bits: u8, shift: u8) -> Option<u32> {
    if displacement.checked_rem(4) != Some(0) {
        return None;
    }
    let scaled = displacement / 4;
    let magnitude = 1_i32.checked_shl(u32::from(bits.checked_sub(1)?))?;
    if scaled < magnitude.checked_neg()? || scaled >= magnitude {
        return None;
    }
    let mask = 1_u32.checked_shl(u32::from(bits))?.checked_sub(1)?;
    Some((scaled.cast_unsigned() & mask) << shift)
}

const fn condition_bits(condition: Condition) -> u32 {
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

fn decode_bitfield(word: u32, offset: u32) -> Result<DecodedInstruction, DecodeError> {
    let destination = reg(word);
    let source = reg(word >> 5);
    let rotate = u8::try_from((word >> 16) & 0x3f).expect("six-bit field");
    let mask = u8::try_from((word >> 10) & 0x3f).expect("six-bit field");
    if mask == 63 {
        return Ok(DecodedInstruction::LogicalShiftRightImmediate64 {
            destination,
            source,
            shift: rotate,
        });
    }
    if mask.wrapping_add(1) == rotate {
        return Ok(DecodedInstruction::LogicalShiftLeftImmediate64 {
            destination,
            source,
            shift: 64_u8.wrapping_sub(rotate),
        });
    }
    Err(DecodeError::UnknownInstruction { offset, word })
}

fn reg(word: u32) -> u8 {
    u8::try_from(word & 0x1f).expect("five-bit field")
}

fn predicate(word: u32) -> u8 {
    u8::try_from(word & 0xf).expect("four-bit predicate field")
}

fn governing_predicate(word: u32) -> u8 {
    u8::try_from((word >> 10) & 7).expect("three-bit governing predicate field")
}

fn imm12(word: u32) -> u16 {
    u16::try_from((word >> 10) & 0xfff).expect("12-bit field")
}

fn imm16(word: u32) -> u16 {
    u16::try_from((word >> 5) & 0xffff).expect("16-bit field")
}

fn halfword_shift(word: u32) -> u8 {
    u8::try_from(((word >> 21) & 3).checked_mul(16).expect("two-bit field")).expect("at most 48")
}

fn decode_adr_displacement(word: u32) -> i32 {
    let low = (word >> 29) & 3;
    let high = (word >> 5) & 0x7_ffff;
    sign_extend((high << 2) | low, 21)
}

fn sign_extend(value: u32, bits: u8) -> i32 {
    let shift = 32_u32
        .checked_sub(u32::from(bits))
        .expect("field no wider than u32");
    (value << shift).cast_signed() >> shift
}
