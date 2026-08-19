//! AArch64 target code for the prepared table-driven Ordered-TNFA iterator.
//!
//! This backend deliberately remains separate from the x86-64 emitter so the
//! independently frozen first-ISA source stays byte-identical while parity is
//! audited. Both entries consume the same immutable object image and V15
//! prepared scratch ABI.

use super::{
    aarch64_add_w_reg, aarch64_add_x_imm, aarch64_add_x_lsl, aarch64_add_x_reg, aarch64_add_x_uxtw,
    aarch64_and_low_w, aarch64_and_w, aarch64_cmp_w, aarch64_cmp_w_imm, aarch64_cmp_x,
    aarch64_load_byte_reg, aarch64_load_pair_x, aarch64_load_u32_constant,
    aarch64_load_u64_constant, aarch64_load_w_imm, aarch64_load_w_uxtw, aarch64_load_x_imm,
    aarch64_load_x_lsl3, aarch64_lsr_w_imm, aarch64_mov_x, aarch64_orr_w, aarch64_store_pair_x,
    aarch64_lsr_x_imm,
    aarch64_store_w, aarch64_store_x, aarch64_sub_w_imm, aarch64_sub_x_imm,
    aarch64_sub_x_reg, Aarch64Assembler,
    ModuleRelocation, ObjectError, RelocationKind, AARCH64_EQ, AARCH64_HI, AARCH64_HS, AARCH64_LO,
    AARCH64_LS, AARCH64_NE, PARTIAL_TABLE_SYMBOL, PREPARED_FALLBACK_RUNTIME_SYMBOL, TEXT_SECTION,
};
use crate::{
    ordered_nfa_native::{
        NativeOrderedNfaObjectImage, NativeOrderedNfaObjectLayout,
        NativeOrderedNfaStartPrefixPlan,
        ORDERED_NFA_EDGE_DISPATCH_V1_ADMITTED_ROWS_FIELD,
        ORDERED_NFA_EDGE_DISPATCH_V1_BYTE_MAP_OFFSET_FIELD,
        ORDERED_NFA_EDGE_DISPATCH_V1_CONTROL_FIELD,
        ORDERED_NFA_EDGE_DISPATCH_V1_METADATA_COUNT_FIELD,
        ORDERED_NFA_EDGE_DISPATCH_V1_METADATA_OFFSET_FIELD,
        ORDERED_NFA_EDGE_DISPATCH_V1_ROWS_OFFSET_FIELD,
        ORDERED_NFA_EDGE_DISPATCH_V1_TRANSITION_COUNT_FIELD,
        ORDERED_NFA_EDGE_DISPATCH_V1_TRANSITIONS_OFFSET_FIELD,
        FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION,
        FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION_COMPLEMENT_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_ARTIFACT_IDENTITY_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_BYTES, FROZEN_ORDERED_NFA_SCRATCH_V1_BYTES_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_CACHE_IDENTITY_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_ADDRESS_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET, FROZEN_ORDERED_NFA_SCRATCH_V1_MAGIC,
        FROZEN_ORDERED_NFA_SCRATCH_V1_MAGIC_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_END_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_START_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_READY_SEAL, FROZEN_ORDERED_NFA_SCRATCH_V1_READY_SEAL_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_ADDRESS_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_ROOT_CAPACITY_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_SEEN_ADDRESS_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_ADDRESS_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_CAPACITY_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET,
        FROZEN_ORDERED_NFA_SCRATCH_V1_STATE_CAPACITY_OFFSET, ORDERED_NFA_OBJECT_V1_ABI_VERSION,
        ORDERED_NFA_OBJECT_V1_ASSERTION_KINDS_FIELD, ORDERED_NFA_OBJECT_V1_ASSERTION_MASK,
        ORDERED_NFA_OBJECT_V1_BYTE_ENDS_OFFSET_FIELD,
        ORDERED_NFA_OBJECT_V1_BYTE_STARTS_OFFSET_FIELD, ORDERED_NFA_OBJECT_V1_CLOSURE_SLOTS_FIELD,
        ORDERED_NFA_OBJECT_V1_EDGE_COUNT_FIELD, ORDERED_NFA_OBJECT_V1_EDGE_KINDS_OFFSET_FIELD,
        ORDERED_NFA_OBJECT_V1_EDGE_OFFSETS_OFFSET_FIELD,
        ORDERED_NFA_OBJECT_V1_EDGE_TARGETS_OFFSET_FIELD, ORDERED_NFA_OBJECT_V1_FLAG_UNICODE,
        ORDERED_NFA_OBJECT_V1_IDENTITY_OFFSET, ORDERED_NFA_OBJECT_V1_KNOWN_FLAGS,
        ORDERED_NFA_OBJECT_V1_LINE_TERMINATOR_FIELD, ORDERED_NFA_OBJECT_V1_MAGIC,
        ORDERED_NFA_OBJECT_V1_READY_SEAL, ORDERED_NFA_OBJECT_V1_ROLES_OFFSET_FIELD,
        ORDERED_NFA_OBJECT_V1_START_STATE_FIELD, ORDERED_NFA_OBJECT_V1_STATE_COUNT_FIELD,
        ORDERED_NFA_OBJECT_V1_UNICODE_ASSERTION_MASK,
        ORDERED_NFA_OBJECT_V1_UNICODE_RANGES_OFFSET_FIELD,
        ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_COUNT_FIELD,
        ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_STRIDE,
        ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_STRIDE_FIELD,
        ORDERED_NFA_OBJECT_V1_ZERO_WIDTH_EDGE_COUNT_FIELD,
        ORDERED_NFA_OBJECT_V2_ABI_VERSION, ORDERED_NFA_OBJECT_V2_FLAG_ORDERED_EDGE_DISPATCH,
        ORDERED_NFA_OBJECT_V2_KNOWN_FLAGS, ORDERED_NFA_OBJECT_V2_MAGIC,
        ORDERED_NFA_OBJECT_V2_READY_SEAL, ORDERED_NFA_OBJECT_V3_ABI_VERSION,
        ORDERED_NFA_OBJECT_V3_FLAG_TERMINAL_RANGE, ORDERED_NFA_OBJECT_V3_KNOWN_FLAGS,
        ORDERED_NFA_OBJECT_V3_MAGIC, ORDERED_NFA_OBJECT_V3_READY_SEAL,
    },
    program::{
        FROZEN_COMPACT_LOOP_PLAN_V1_SCANNER_ADDRESS_OFFSET,
        FROZEN_DYNAMIC_ROWS_V3_CACHE_IDENTITY_OFFSET, FROZEN_DYNAMIC_ROWS_V3_CLASS_COUNT_OFFSET,
        FROZEN_DYNAMIC_ROWS_V3_FORMAT_VERSION_OFFSET, FROZEN_DYNAMIC_ROWS_V3_INITIAL_STATE_OFFSET,
        FROZEN_DYNAMIC_ROWS_V3_LOOP_COUNT_OFFSET, FROZEN_DYNAMIC_ROWS_V3_LOOP_STATES_OFFSET,
        FROZEN_DYNAMIC_ROWS_V3_READY_SEAL_OFFSET, FROZEN_DYNAMIC_ROWS_V3_ROWS_ADDRESS_OFFSET,
        FROZEN_DYNAMIC_ROWS_V3_ROW_SHIFT_OFFSET, FROZEN_DYNAMIC_ROWS_V3_STATE_COUNT_OFFSET,
        FROZEN_DYNAMIC_ROWS_V6_LOOP_INDEX_ADDRESS_OFFSET,
        FROZEN_DYNAMIC_ROWS_V6_LOOP_INDEX_LENGTH_OFFSET, FROZEN_DYNAMIC_ROWS_V6_LOOP_PLANS_OFFSET,
        FROZEN_DYNAMIC_ROWS_V6_LOOP_PLAN_COUNT_OFFSET, FROZEN_DYNAMIC_ROWS_V6_RESERVED_OFFSET,
        FROZEN_ORDERED_NFA_V15_FORMAT_VERSION, FROZEN_PREPARED_HEADER_V15_BYTES,
        FROZEN_PREPARED_HEADER_V15_DYNAMIC_ROWS_OFFSET, FROZEN_PREPARED_HEADER_V15_READY_SEAL,
        FROZEN_PREPARED_HEADER_V1_ABI_VERSION, FROZEN_PREPARED_HEADER_V1_ABI_VERSION_OFFSET,
        FROZEN_PREPARED_HEADER_V1_ACCEPT_MASK_OFFSET, FROZEN_PREPARED_HEADER_V1_ACTIVE_SEAL,
        FROZEN_PREPARED_HEADER_V1_ACTIVE_SEAL_OFFSET,
        FROZEN_PREPARED_HEADER_V1_ARTIFACT_IDENTITY_OFFSET,
        FROZEN_PREPARED_HEADER_V1_CACHE_IDENTITY_OFFSET,
        FROZEN_PREPARED_HEADER_V1_CLASS_MAP_OFFSET, FROZEN_PREPARED_HEADER_V1_FLAGS_OFFSET,
        FROZEN_PREPARED_HEADER_V1_FLAG_ORDERED_NFA_V15,
        FROZEN_PREPARED_HEADER_V1_FORWARD_INITIAL_ROW_OFFSET,
        FROZEN_PREPARED_HEADER_V1_FORWARD_LIVE_CELLS_OFFSET,
        FROZEN_PREPARED_HEADER_V1_FORWARD_ROWS_ADDRESS_OFFSET,
        FROZEN_PREPARED_HEADER_V1_HEADER_BYTES_OFFSET, FROZEN_PREPARED_HEADER_V1_MAGIC,
        FROZEN_PREPARED_HEADER_V1_MAGIC_OFFSET,
        FROZEN_PREPARED_HEADER_V1_NEXT_ROW_TOKEN_MASK_OFFSET,
        FROZEN_PREPARED_HEADER_V1_REVERSE_INITIAL_ROW_OFFSET,
        FROZEN_PREPARED_HEADER_V1_REVERSE_LIVE_CELLS_OFFSET,
        FROZEN_PREPARED_HEADER_V1_REVERSE_ROWS_ADDRESS_OFFSET,
        FROZEN_PREPARED_HEADER_V1_ROW_STRIDE_OFFSET,
        FROZEN_PREPARED_HEADER_V1_UNFILLED_CELL_OFFSET,
    },
};
use fre_automata::{NativeEpsilonClosureAction, NativeEpsilonClosureProgramView};

const STATUS_NO_MATCH: u32 = 0;
const STATUS_MATCH: u32 = 1;
const STATUS_INVALID_ARGUMENT: u32 = 2;
const STATUS_RUNTIME_FAILURE: u32 = 3;
const STATUS_INVALID_HANDLE: u32 = 5;

const ROLE_SPLIT: u8 = 0;
const ROLE_CONSUMING: u8 = 1;
const ROLE_ACCEPT: u8 = 2;
const EDGE_EPSILON: u8 = 0;
const EDGE_BYTE_RANGE: u8 = 1;
const EDGE_START_TEXT: u8 = 2;
const EDGE_END_TEXT: u8 = 3;
const EDGE_START_LINE: u8 = 4;
const EDGE_END_LINE: u8 = 5;
const EDGE_START_LINE_CRLF: u8 = 6;
const EDGE_END_LINE_CRLF: u8 = 7;
const EDGE_WORD_ASCII: u8 = 8;
const EDGE_NOT_WORD_ASCII: u8 = 9;
const EDGE_WORD_START_ASCII: u8 = 10;
const EDGE_WORD_END_ASCII: u8 = 11;
const EDGE_WORD_START_HALF_ASCII: u8 = 12;
const EDGE_WORD_END_HALF_ASCII: u8 = 13;
const EDGE_WORD_UNICODE: u8 = 14;
const EDGE_NOT_WORD_UNICODE: u8 = 15;
const EDGE_WORD_START_UNICODE: u8 = 16;
const EDGE_WORD_END_UNICODE: u8 = 17;
const EDGE_WORD_START_HALF_UNICODE: u8 = 18;
const EDGE_WORD_END_HALF_UNICODE: u8 = 19;

const FRAME_BYTES: u16 = 256;
const SAVE_BYTES: u16 = 96;
const STACK_BYTES: u16 = FRAME_BYTES + SAVE_BYTES;
const L_HEADER: u16 = 0;
const L_HAY: u16 = 8;
const L_LEN: u16 = 16;
const L_POSITION: u16 = 24;
const L_END: u16 = 32;
const L_RESULT: u16 = 40;
const L_TABLE: u16 = 48;
const L_SCRATCH: u16 = 56;
const L_SEEN: u16 = 64;
const L_CURRENT: u16 = 72;
const L_ROOTS: u16 = 80;
const L_STACK: u16 = 88;
const L_CACHE: u16 = 96;
const L_ROOT_COUNT: u16 = 104;
const L_ROOT_INDEX: u16 = 112;
const L_THREAD_STATE: u16 = 120;
const L_THREAD_START: u16 = 128;
const L_EDGE_INDEX: u16 = 136;
const L_EDGE_END: u16 = 144;
const L_CURRENT_INDEX: u16 = 152;
const L_ROOT_MODE: u16 = 160;
const L_BYTE: u16 = 168;
const L_ASSERT_KIND: u16 = 176;
const L_ASSERT_LEFT: u16 = 184;
const L_ASSERT_POSITION: u16 = 192;
const L_ASSERT_RETURN: u16 = 200;
const L_CLASS_RETURN: u16 = 208;
const L_ASSERT_CACHE_KNOWN: u16 = 216;
const L_ASSERT_CACHE_ENABLED: u16 = 224;
const L_ASSERT_CACHE_BIT: u16 = 232;

const _: () = assert!(FRAME_BYTES.is_multiple_of(16));
const _: () = assert!(STACK_BYTES.is_multiple_of(16));
const _: () = assert!(L_ASSERT_CACHE_BIT + 8 <= FRAME_BYTES);

/// One complete AArch64 public/private Ordered-NFA text fragment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Aarch64OrderedNfaNativeEntry {
    pub(super) code: Vec<u8>,
    pub(super) relocations: Vec<ModuleRelocation>,
    pub(super) private_entry_offset: usize,
    /// Handle-only, source-free classifier for one whole prepared operation.
    pub(super) bulk_gate_entry_offset: usize,
}

fn scratch_bytes(layout: NativeOrderedNfaObjectLayout) -> Result<usize, ObjectError> {
    if FROZEN_ORDERED_NFA_SCRATCH_V1_BYTES != 176 {
        return Err(ObjectError::InvalidModule("Ordered-NFA scratch ABI drift"));
    }
    let seen = layout
        .state_count
        .checked_mul(8)
        .ok_or(ObjectError::ArithmeticOverflow("Ordered-NFA seen bytes"))?;
    let current = layout
        .state_count
        .checked_mul(16)
        .ok_or(ObjectError::ArithmeticOverflow("Ordered-NFA current bytes"))?;
    let roots = layout
        .edge_count
        .checked_mul(16)
        .ok_or(ObjectError::ArithmeticOverflow("Ordered-NFA roots bytes"))?;
    let stack = layout
        .closure_slots
        .checked_mul(16)
        .ok_or(ObjectError::ArithmeticOverflow("Ordered-NFA stack bytes"))?;
    FROZEN_ORDERED_NFA_SCRATCH_V1_BYTES
        .checked_add(seen)
        .and_then(|bytes| bytes.checked_add(current))
        .and_then(|bytes| bytes.checked_add(roots))
        .and_then(|bytes| bytes.checked_add(stack))
        .ok_or(ObjectError::ArithmeticOverflow("Ordered-NFA scratch bytes"))
}

struct A<'a> {
    asm: &'a mut Aarch64Assembler,
}

impl A<'_> {
    fn i(&mut self, instruction: Result<u32, ObjectError>) -> Result<(), ObjectError> {
        self.asm.instruction(instruction?)?;
        Ok(())
    }

    fn raw(&mut self, instruction: u32) -> Result<usize, ObjectError> {
        self.asm.instruction(instruction)
    }

    fn mov_x(&mut self, destination: u8, source: u8) -> Result<(), ObjectError> {
        self.i(aarch64_mov_x(destination, source))
    }

    fn mov_w(&mut self, destination: u8, source: u8) -> Result<(), ObjectError> {
        self.i(Ok(0x2a00_03e0
            | (u32::from(source) << 16)
            | u32::from(destination)))
    }

    fn constant32(&mut self, destination: u8, value: u32) -> Result<(), ObjectError> {
        aarch64_load_u32_constant(self.asm, destination, value)
    }

    fn constant64(&mut self, destination: u8, value: u64) -> Result<(), ObjectError> {
        aarch64_load_u64_constant(self.asm, destination, value)
    }

    fn load_x(&mut self, destination: u8, base: u8, offset: usize) -> Result<(), ObjectError> {
        let offset = u16::try_from(offset)
            .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 LDR X offset"))?;
        self.i(aarch64_load_x_imm(destination, base, offset))
    }

    fn load_w(&mut self, destination: u8, base: u8, offset: usize) -> Result<(), ObjectError> {
        let offset = u16::try_from(offset)
            .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 LDR W offset"))?;
        self.i(aarch64_load_w_imm(destination, base, offset))
    }

    fn store_x(&mut self, source: u8, base: u8, offset: usize) -> Result<(), ObjectError> {
        let offset = u16::try_from(offset)
            .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 STR X offset"))?;
        self.i(aarch64_store_x(source, base, offset))
    }

    fn store_w(&mut self, source: u8, base: u8, offset: usize) -> Result<(), ObjectError> {
        let offset = u16::try_from(offset)
            .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 STR W offset"))?;
        self.i(aarch64_store_w(source, base, offset))
    }

    fn cmp_x(&mut self, left: u8, right: u8) -> Result<(), ObjectError> {
        self.i(aarch64_cmp_x(left, right))
    }

    fn cmp_w(&mut self, left: u8, right: u8) -> Result<(), ObjectError> {
        self.i(aarch64_cmp_w(left, right))
    }

    fn cmp_w_imm(&mut self, register: u8, value: u16) -> Result<(), ObjectError> {
        self.i(aarch64_cmp_w_imm(register, value))
    }

    fn add_x(&mut self, destination: u8, left: u8, right: u8) -> Result<(), ObjectError> {
        self.i(aarch64_add_x_reg(destination, left, right))
    }

    fn add_x_imm(&mut self, destination: u8, source: u8, value: u16) -> Result<(), ObjectError> {
        self.i(aarch64_add_x_imm(destination, source, value))
    }

    fn add_w_imm(&mut self, destination: u8, source: u8, value: u16) -> Result<(), ObjectError> {
        if value > 0x0fff {
            return Err(ObjectError::InvalidModule("AArch64 ADD W immediate"));
        }
        self.raw(
            0x1100_0000
                | (u32::from(value) << 10)
                | (u32::from(source) << 5)
                | u32::from(destination),
        )?;
        Ok(())
    }

    fn sub_x(&mut self, destination: u8, left: u8, right: u8) -> Result<(), ObjectError> {
        self.i(aarch64_sub_x_reg(destination, left, right))
    }

    fn sub_x_imm(&mut self, destination: u8, source: u8, value: u16) -> Result<(), ObjectError> {
        self.i(aarch64_sub_x_imm(destination, source, value))
    }

    fn sub_w_imm(&mut self, destination: u8, source: u8, value: u16) -> Result<(), ObjectError> {
        self.i(aarch64_sub_w_imm(destination, source, value))
    }

    fn and_w(&mut self, destination: u8, left: u8, right: u8) -> Result<(), ObjectError> {
        self.i(aarch64_and_w(destination, left, right))
    }

    fn orr_w(&mut self, destination: u8, left: u8, right: u8) -> Result<(), ObjectError> {
        self.i(aarch64_orr_w(destination, left, right))
    }

    fn lsl_w_imm(&mut self, destination: u8, source: u8, shift: u8) -> Result<(), ObjectError> {
        if shift == 0 {
            return self.mov_w(destination, source);
        }
        if shift > 31 {
            return Err(ObjectError::InvalidModule("AArch64 LSL W immediate"));
        }
        let immr = 32_u8 - shift;
        let imms = 31_u8 - shift;
        self.raw(
            0x5300_0000
                | (u32::from(immr) << 16)
                | (u32::from(imms) << 10)
                | (u32::from(source) << 5)
                | u32::from(destination),
        )?;
        Ok(())
    }

    fn lsl_w(&mut self, destination: u8, source: u8, shift: u8) -> Result<(), ObjectError> {
        if destination > 31 || source > 31 || shift > 31 {
            return Err(ObjectError::InvalidModule("AArch64 LSLV W register"));
        }
        self.raw(
            0x1ac0_2000
                | (u32::from(shift) << 16)
                | (u32::from(source) << 5)
                | u32::from(destination),
        )?;
        Ok(())
    }

    fn branch(&mut self, label: usize) -> Result<(), ObjectError> {
        self.asm.branch(label)
    }

    fn branch_cond(&mut self, condition: u8, label: usize) -> Result<(), ObjectError> {
        self.asm.branch_cond(condition, label)
    }

    fn cbz_x(&mut self, register: u8, label: usize) -> Result<(), ObjectError> {
        self.asm.branch_zero_x(register, label)
    }

    fn cbnz_x(&mut self, register: u8, label: usize) -> Result<(), ObjectError> {
        self.asm.branch_nonzero_x(register, label)
    }

    fn cbz_w(&mut self, register: u8, label: usize) -> Result<(), ObjectError> {
        self.asm.branch_zero_w(register, label)
    }

    fn cbnz_w(&mut self, register: u8, label: usize) -> Result<(), ObjectError> {
        self.asm.branch_nonzero_w(register, label)
    }

    fn call(&mut self, label: usize) -> Result<(), ObjectError> {
        self.asm.call(label)
    }

    fn tbnz_w(&mut self, register: u8, bit: u8, label: usize) -> Result<(), ObjectError> {
        self.asm.branch_bit_set_w(register, bit, label)
    }

    fn tbnz_x(&mut self, register: u8, bit: u8, label: usize) -> Result<(), ObjectError> {
        self.asm.branch_bit_set_x(register, bit, label)
    }
}

fn emit_epilogue(a: &mut A<'_>) -> Result<(), ObjectError> {
    a.i(aarch64_load_pair_x(
        19,
        20,
        31,
        i16::try_from(FRAME_BYTES).unwrap(),
    ))?;
    a.i(aarch64_load_pair_x(
        21,
        22,
        31,
        i16::try_from(FRAME_BYTES + 16).unwrap(),
    ))?;
    a.i(aarch64_load_pair_x(
        23,
        24,
        31,
        i16::try_from(FRAME_BYTES + 32).unwrap(),
    ))?;
    a.i(aarch64_load_pair_x(
        25,
        26,
        31,
        i16::try_from(FRAME_BYTES + 48).unwrap(),
    ))?;
    a.i(aarch64_load_pair_x(
        27,
        28,
        31,
        i16::try_from(FRAME_BYTES + 64).unwrap(),
    ))?;
    a.i(aarch64_load_pair_x(
        29,
        30,
        31,
        i16::try_from(FRAME_BYTES + 80).unwrap(),
    ))?;
    a.add_x_imm(31, 31, STACK_BYTES)?;
    Ok(())
}

fn emit_return(a: &mut A<'_>, status: u32) -> Result<(), ObjectError> {
    a.constant32(0, status)?;
    emit_epilogue(a)?;
    a.raw(0xd65f_03c0)?;
    Ok(())
}

fn emit_prologue_and_raw_checks(
    asm: &mut Aarch64Assembler,
    invalid_argument: usize,
    invalid_handle: usize,
) -> Result<[usize; 2], ObjectError> {
    let mut a = A { asm };
    a.sub_x_imm(31, 31, STACK_BYTES)?;
    a.i(aarch64_store_pair_x(
        19,
        20,
        31,
        i16::try_from(FRAME_BYTES).unwrap(),
    ))?;
    a.i(aarch64_store_pair_x(
        21,
        22,
        31,
        i16::try_from(FRAME_BYTES + 16).unwrap(),
    ))?;
    a.i(aarch64_store_pair_x(
        23,
        24,
        31,
        i16::try_from(FRAME_BYTES + 32).unwrap(),
    ))?;
    a.i(aarch64_store_pair_x(
        25,
        26,
        31,
        i16::try_from(FRAME_BYTES + 48).unwrap(),
    ))?;
    a.i(aarch64_store_pair_x(
        27,
        28,
        31,
        i16::try_from(FRAME_BYTES + 64).unwrap(),
    ))?;
    a.i(aarch64_store_pair_x(
        29,
        30,
        31,
        i16::try_from(FRAME_BYTES + 80).unwrap(),
    ))?;
    a.mov_x(29, 31)?;

    for (register, local) in [
        (0, L_HEADER),
        (1, L_HAY),
        (2, L_LEN),
        (3, L_POSITION),
        (4, L_END),
        (5, L_RESULT),
    ] {
        a.store_x(register, 31, usize::from(local))?;
    }
    a.mov_x(19, 0)?;
    a.mov_x(20, 1)?;
    a.mov_x(21, 2)?;
    a.mov_x(22, 4)?;
    a.mov_x(23, 5)?;
    let page = a.raw(0x9000_0018)?;
    let page_offset = a.raw(aarch64_add_x_imm(24, 24, 0)?)?;
    a.store_x(24, 31, usize::from(L_TABLE))?;

    a.cbz_x(19, invalid_handle)?;
    a.cbz_x(20, invalid_argument)?;
    a.cbz_x(23, invalid_argument)?;
    for bit in 0..3 {
        a.tbnz_x(23, bit, invalid_argument)?;
    }
    a.load_x(8, 31, usize::from(L_POSITION))?;
    a.cmp_x(8, 22)?;
    a.branch_cond(AARCH64_HI, invalid_argument)?;
    a.cmp_x(22, 21)?;
    a.branch_cond(AARCH64_HI, invalid_argument)?;
    a.tbnz_x(21, 63, invalid_argument)?;
    Ok([page, page_offset])
}

fn emit_bulk_gate_prologue(
    asm: &mut Aarch64Assembler,
    invalid_handle: usize,
) -> Result<[usize; 2], ObjectError> {
    let mut a = A { asm };
    // Retain the complete search-entry save geometry so shared exact-auth
    // emitters and the common epilogue have one invariant frame layout.
    a.sub_x_imm(31, 31, STACK_BYTES)?;
    for (left, right, offset) in [
        (19, 20, FRAME_BYTES),
        (21, 22, FRAME_BYTES + 16),
        (23, 24, FRAME_BYTES + 32),
        (25, 26, FRAME_BYTES + 48),
        (27, 28, FRAME_BYTES + 64),
        (29, 30, FRAME_BYTES + 80),
    ] {
        a.i(aarch64_store_pair_x(
            left,
            right,
            31,
            i16::try_from(offset).unwrap(),
        ))?;
    }
    a.mov_x(29, 31)?;
    a.store_x(0, 31, usize::from(L_HEADER))?;
    a.mov_x(19, 0)?;
    let page = a.raw(0x9000_0018)?;
    let page_offset = a.raw(aarch64_add_x_imm(24, 24, 0)?)?;
    a.store_x(24, 31, usize::from(L_TABLE))?;
    a.cbz_x(19, invalid_handle)?;
    Ok([page, page_offset])
}

fn emit_v15_claim_classifier(
    a: &mut A<'_>,
    claimed: usize,
    legacy: usize,
) -> Result<(), ObjectError> {
    let flag = FROZEN_PREPARED_HEADER_V1_FLAG_ORDERED_NFA_V15;
    if !flag.is_power_of_two() {
        return Err(ObjectError::InvalidModule(
            "Ordered-NFA V15 flag is not a single bit",
        ));
    }
    a.load_w(8, 19, FROZEN_PREPARED_HEADER_V1_FLAGS_OFFSET)?;
    a.tbnz_w(8, u8::try_from(flag.trailing_zeros()).unwrap(), claimed)?;
    a.load_x(
        8,
        19,
        FROZEN_PREPARED_HEADER_V15_DYNAMIC_ROWS_OFFSET + FROZEN_DYNAMIC_ROWS_V3_READY_SEAL_OFFSET,
    )?;
    a.constant64(9, FROZEN_PREPARED_HEADER_V15_READY_SEAL)?;
    a.cmp_x(8, 9)?;
    a.branch_cond(AARCH64_EQ, claimed)?;
    a.load_w(
        8,
        19,
        FROZEN_PREPARED_HEADER_V15_DYNAMIC_ROWS_OFFSET
            + FROZEN_DYNAMIC_ROWS_V3_FORMAT_VERSION_OFFSET,
    )?;
    a.constant32(9, FROZEN_ORDERED_NFA_V15_FORMAT_VERSION)?;
    a.cmp_w(8, 9)?;
    a.branch_cond(AARCH64_EQ, claimed)?;
    a.branch(legacy)
}

fn cmp_mem_x_const(
    a: &mut A<'_>,
    base: u8,
    offset: usize,
    value: u64,
    invalid: usize,
) -> Result<(), ObjectError> {
    a.load_x(8, base, offset)?;
    a.constant64(9, value)?;
    a.cmp_x(8, 9)?;
    a.branch_cond(AARCH64_NE, invalid)
}

fn cmp_mem_w_const(
    a: &mut A<'_>,
    base: u8,
    offset: usize,
    value: u32,
    invalid: usize,
) -> Result<(), ObjectError> {
    a.load_w(8, base, offset)?;
    a.constant32(9, value)?;
    a.cmp_w(8, 9)?;
    a.branch_cond(AARCH64_NE, invalid)
}

fn require_mem_x_zero(
    a: &mut A<'_>,
    base: u8,
    offset: usize,
    invalid: usize,
) -> Result<(), ObjectError> {
    a.load_x(8, base, offset)?;
    a.cbnz_x(8, invalid)
}

fn require_mem_w_zero(
    a: &mut A<'_>,
    base: u8,
    offset: usize,
    invalid: usize,
) -> Result<(), ObjectError> {
    a.load_w(8, base, offset)?;
    a.cbnz_w(8, invalid)
}

fn compare_identity(
    a: &mut A<'_>,
    left: u8,
    left_offset: usize,
    right: u8,
    right_offset: usize,
    invalid: usize,
) -> Result<(), ObjectError> {
    for offset in (0..32).step_by(8) {
        a.load_x(8, left, left_offset + offset)?;
        a.load_x(9, right, right_offset + offset)?;
        a.cmp_x(8, 9)?;
        a.branch_cond(AARCH64_NE, invalid)?;
    }
    Ok(())
}

fn emit_exact_object_auth(
    a: &mut A<'_>,
    layout: NativeOrderedNfaObjectLayout,
    invalid: usize,
) -> Result<(), ObjectError> {
    let flags = (if layout.unicode_ranges_offset.is_some() {
        ORDERED_NFA_OBJECT_V1_FLAG_UNICODE
    } else {
        0
    }) | if layout.ordered_edge_dispatch.is_some() {
        ORDERED_NFA_OBJECT_V2_FLAG_ORDERED_EDGE_DISPATCH
    } else {
        0
    } | if layout.terminal_range.is_some() {
        ORDERED_NFA_OBJECT_V3_FLAG_TERMINAL_RANGE
    } else {
        0
    };
    let (ready_seal, magic, abi_version, known_flags) =
        if layout.terminal_range.is_some() {
            (
                ORDERED_NFA_OBJECT_V3_READY_SEAL,
                ORDERED_NFA_OBJECT_V3_MAGIC,
                ORDERED_NFA_OBJECT_V3_ABI_VERSION,
                ORDERED_NFA_OBJECT_V3_KNOWN_FLAGS,
            )
        } else if layout.ordered_edge_dispatch.is_some() {
            (
                ORDERED_NFA_OBJECT_V2_READY_SEAL,
                ORDERED_NFA_OBJECT_V2_MAGIC,
                ORDERED_NFA_OBJECT_V2_ABI_VERSION,
                ORDERED_NFA_OBJECT_V2_KNOWN_FLAGS,
            )
        } else {
            (
                ORDERED_NFA_OBJECT_V1_READY_SEAL,
                ORDERED_NFA_OBJECT_V1_MAGIC,
                ORDERED_NFA_OBJECT_V1_ABI_VERSION,
                ORDERED_NFA_OBJECT_V1_KNOWN_FLAGS,
            )
        };
    cmp_mem_x_const(a, 24, 0, ready_seal, invalid)?;
    cmp_mem_x_const(a, 24, 8, magic, invalid)?;
    cmp_mem_w_const(a, 24, 16, abi_version, invalid)?;
    cmp_mem_w_const(a, 24, 20, !abi_version, invalid)?;
    cmp_mem_w_const(
        a,
        24,
        24,
        u32::try_from(layout.object_bytes)
            .map_err(|_| ObjectError::ArithmeticOverflow("Ordered-NFA object bytes"))?,
        invalid,
    )?;
    cmp_mem_w_const(a, 24, 28, flags, invalid)?;
    for (field, value) in [
        (
            ORDERED_NFA_OBJECT_V1_ROLES_OFFSET_FIELD,
            layout.roles_offset,
        ),
        (
            ORDERED_NFA_OBJECT_V1_EDGE_OFFSETS_OFFSET_FIELD,
            layout.edge_offsets_offset,
        ),
        (
            ORDERED_NFA_OBJECT_V1_EDGE_TARGETS_OFFSET_FIELD,
            layout.edge_targets_offset,
        ),
        (
            ORDERED_NFA_OBJECT_V1_EDGE_KINDS_OFFSET_FIELD,
            layout.edge_kinds_offset,
        ),
        (
            ORDERED_NFA_OBJECT_V1_BYTE_STARTS_OFFSET_FIELD,
            layout.byte_starts_offset,
        ),
        (
            ORDERED_NFA_OBJECT_V1_BYTE_ENDS_OFFSET_FIELD,
            layout.byte_ends_offset,
        ),
        (
            ORDERED_NFA_OBJECT_V1_UNICODE_RANGES_OFFSET_FIELD,
            layout.unicode_ranges_offset.unwrap_or(0),
        ),
        (
            ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_COUNT_FIELD,
            layout.unicode_range_count,
        ),
        (ORDERED_NFA_OBJECT_V1_STATE_COUNT_FIELD, layout.state_count),
        (ORDERED_NFA_OBJECT_V1_EDGE_COUNT_FIELD, layout.edge_count),
        (
            ORDERED_NFA_OBJECT_V1_ZERO_WIDTH_EDGE_COUNT_FIELD,
            layout.zero_width_edge_count,
        ),
        (
            ORDERED_NFA_OBJECT_V1_CLOSURE_SLOTS_FIELD,
            layout.closure_slots,
        ),
    ] {
        cmp_mem_w_const(
            a,
            24,
            field,
            u32::try_from(value)
                .map_err(|_| ObjectError::ArithmeticOverflow("Ordered-NFA object geometry"))?,
            invalid,
        )?;
    }
    cmp_mem_w_const(
        a,
        24,
        ORDERED_NFA_OBJECT_V1_START_STATE_FIELD,
        layout.start_state,
        invalid,
    )?;
    cmp_mem_w_const(
        a,
        24,
        ORDERED_NFA_OBJECT_V1_ASSERTION_KINDS_FIELD,
        layout.assertion_kinds,
        invalid,
    )?;
    cmp_mem_w_const(
        a,
        24,
        ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_STRIDE_FIELD,
        if layout.unicode_ranges_offset.is_some() {
            ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_STRIDE
        } else {
            0
        },
        invalid,
    )?;
    let terminal_word = layout.terminal_range.map_or(
        u32::from(layout.line_terminator),
        |range| {
            u32::from_le_bytes([
                layout.line_terminator,
                range.start,
                range.end,
                range.reverse_depth,
            ])
        },
    );
    cmp_mem_w_const(
        a,
        24,
        ORDERED_NFA_OBJECT_V1_LINE_TERMINATOR_FIELD,
        terminal_word,
        invalid,
    )?;
    if layout.assertion_kinds & !ORDERED_NFA_OBJECT_V1_ASSERTION_MASK != 0
        || layout.unicode_ranges_offset.is_some()
            != (layout.assertion_kinds & ORDERED_NFA_OBJECT_V1_UNICODE_ASSERTION_MASK != 0)
        || layout
            .terminal_range
            .is_some_and(|range| range.start > range.end || range.reverse_depth != 0)
        || flags & !known_flags != 0
    {
        return Err(ObjectError::InvalidModule(
            "Ordered-NFA object layout has inconsistent assertion flags",
        ));
    }
    if let Some(dispatch) = layout.ordered_edge_dispatch {
        materialize_table_base(a, 16, dispatch.descriptor_offset)?;
        for (field, value) in [
            (ORDERED_NFA_EDGE_DISPATCH_V1_ROWS_OFFSET_FIELD, dispatch.rows_offset),
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_BYTE_MAP_OFFSET_FIELD,
                dispatch.byte_map_offset,
            ),
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_METADATA_OFFSET_FIELD,
                dispatch.metadata_offset,
            ),
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_TRANSITIONS_OFFSET_FIELD,
                dispatch.transitions_offset,
            ),
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_ADMITTED_ROWS_FIELD,
                dispatch.admitted_rows,
            ),
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_METADATA_COUNT_FIELD,
                dispatch.metadata_count,
            ),
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_TRANSITION_COUNT_FIELD,
                dispatch.transition_count,
            ),
        ] {
            cmp_mem_w_const(
                a,
                16,
                field,
                u32::try_from(value).map_err(|_| {
                    ObjectError::ArithmeticOverflow("Ordered-edge dispatch object geometry")
                })?,
                invalid,
            )?;
        }
        cmp_mem_w_const(
            a,
            16,
            ORDERED_NFA_EDGE_DISPATCH_V1_CONTROL_FIELD,
            dispatch.encoding.control(),
            invalid,
        )?;
    }
    Ok(())
}

fn emit_common_header_identity_auth(a: &mut A<'_>, invalid: usize) -> Result<(), ObjectError> {
    cmp_mem_x_const(
        a,
        19,
        FROZEN_PREPARED_HEADER_V1_MAGIC_OFFSET,
        FROZEN_PREPARED_HEADER_V1_MAGIC,
        invalid,
    )?;
    cmp_mem_w_const(
        a,
        19,
        FROZEN_PREPARED_HEADER_V1_ABI_VERSION_OFFSET,
        FROZEN_PREPARED_HEADER_V1_ABI_VERSION,
        invalid,
    )?;
    compare_identity(
        a,
        19,
        FROZEN_PREPARED_HEADER_V1_ARTIFACT_IDENTITY_OFFSET,
        24,
        ORDERED_NFA_OBJECT_V1_IDENTITY_OFFSET,
        invalid,
    )
}

fn emit_exact_header_auth(
    a: &mut A<'_>,
    layout: NativeOrderedNfaObjectLayout,
    expected_scratch_bytes: usize,
    invalid: usize,
) -> Result<(), ObjectError> {
    for (offset, value) in [
        (
            FROZEN_PREPARED_HEADER_V1_ACTIVE_SEAL_OFFSET,
            FROZEN_PREPARED_HEADER_V1_ACTIVE_SEAL,
        ),
        (
            FROZEN_PREPARED_HEADER_V1_MAGIC_OFFSET,
            FROZEN_PREPARED_HEADER_V1_MAGIC,
        ),
    ] {
        cmp_mem_x_const(a, 19, offset, value, invalid)?;
    }
    for (offset, value) in [
        (
            FROZEN_PREPARED_HEADER_V1_ABI_VERSION_OFFSET,
            FROZEN_PREPARED_HEADER_V1_ABI_VERSION,
        ),
        (
            FROZEN_PREPARED_HEADER_V1_FLAGS_OFFSET,
            FROZEN_PREPARED_HEADER_V1_FLAG_ORDERED_NFA_V15,
        ),
    ] {
        cmp_mem_w_const(a, 19, offset, value, invalid)?;
    }
    cmp_mem_x_const(
        a,
        19,
        FROZEN_PREPARED_HEADER_V1_HEADER_BYTES_OFFSET,
        u64::try_from(FROZEN_PREPARED_HEADER_V15_BYTES).unwrap(),
        invalid,
    )?;
    compare_identity(
        a,
        19,
        FROZEN_PREPARED_HEADER_V1_ARTIFACT_IDENTITY_OFFSET,
        24,
        ORDERED_NFA_OBJECT_V1_IDENTITY_OFFSET,
        invalid,
    )?;
    a.load_x(8, 19, FROZEN_PREPARED_HEADER_V1_FORWARD_ROWS_ADDRESS_OFFSET)?;
    a.cbz_x(8, invalid)?;
    require_mem_x_zero(
        a,
        19,
        FROZEN_PREPARED_HEADER_V1_REVERSE_ROWS_ADDRESS_OFFSET,
        invalid,
    )?;
    cmp_mem_x_const(
        a,
        19,
        FROZEN_PREPARED_HEADER_V1_FORWARD_LIVE_CELLS_OFFSET,
        u64::try_from(expected_scratch_bytes).unwrap(),
        invalid,
    )?;
    require_mem_x_zero(
        a,
        19,
        FROZEN_PREPARED_HEADER_V1_REVERSE_LIVE_CELLS_OFFSET,
        invalid,
    )?;
    a.load_x(8, 19, FROZEN_PREPARED_HEADER_V1_CACHE_IDENTITY_OFFSET)?;
    a.cbz_x(8, invalid)?;
    a.store_x(8, 31, usize::from(L_CACHE))?;
    for (offset, value) in [
        (
            FROZEN_PREPARED_HEADER_V1_ROW_STRIDE_OFFSET,
            layout.state_count,
        ),
        (
            FROZEN_PREPARED_HEADER_V1_FORWARD_INITIAL_ROW_OFFSET,
            layout.edge_count,
        ),
        (
            FROZEN_PREPARED_HEADER_V1_REVERSE_INITIAL_ROW_OFFSET,
            layout.closure_slots,
        ),
    ] {
        cmp_mem_w_const(a, 19, offset, u32::try_from(value).unwrap(), invalid)?;
    }
    for (offset, value) in [
        (
            FROZEN_PREPARED_HEADER_V1_UNFILLED_CELL_OFFSET,
            !u32::try_from(layout.state_count).unwrap(),
        ),
        (
            FROZEN_PREPARED_HEADER_V1_ACCEPT_MASK_OFFSET,
            !u32::try_from(layout.edge_count).unwrap(),
        ),
        (
            FROZEN_PREPARED_HEADER_V1_NEXT_ROW_TOKEN_MASK_OFFSET,
            !u32::try_from(layout.closure_slots).unwrap(),
        ),
    ] {
        cmp_mem_w_const(a, 19, offset, value, invalid)?;
    }
    for offset in (0..256).step_by(8) {
        require_mem_x_zero(
            a,
            19,
            FROZEN_PREPARED_HEADER_V1_CLASS_MAP_OFFSET + offset,
            invalid,
        )?;
    }
    let tail = FROZEN_PREPARED_HEADER_V15_DYNAMIC_ROWS_OFFSET;
    cmp_mem_x_const(
        a,
        19,
        tail + FROZEN_DYNAMIC_ROWS_V3_READY_SEAL_OFFSET,
        FROZEN_PREPARED_HEADER_V15_READY_SEAL,
        invalid,
    )?;
    a.load_x(8, 19, FROZEN_PREPARED_HEADER_V1_FORWARD_ROWS_ADDRESS_OFFSET)?;
    a.load_x(9, 19, tail + FROZEN_DYNAMIC_ROWS_V3_ROWS_ADDRESS_OFFSET)?;
    a.cmp_x(8, 9)?;
    a.branch_cond(AARCH64_NE, invalid)?;
    a.load_x(8, 31, usize::from(L_CACHE))?;
    a.load_x(9, 19, tail + FROZEN_DYNAMIC_ROWS_V3_CACHE_IDENTITY_OFFSET)?;
    a.cmp_x(8, 9)?;
    a.branch_cond(AARCH64_NE, invalid)?;
    for (offset, value) in [
        (
            FROZEN_DYNAMIC_ROWS_V3_STATE_COUNT_OFFSET,
            layout.state_count,
        ),
        (FROZEN_DYNAMIC_ROWS_V3_CLASS_COUNT_OFFSET, layout.edge_count),
        (
            FROZEN_DYNAMIC_ROWS_V3_ROW_SHIFT_OFFSET,
            layout.zero_width_edge_count,
        ),
        (
            FROZEN_DYNAMIC_ROWS_V3_INITIAL_STATE_OFFSET,
            layout.closure_slots,
        ),
    ] {
        cmp_mem_w_const(a, 19, tail + offset, u32::try_from(value).unwrap(), invalid)?;
    }
    require_mem_w_zero(
        a,
        19,
        tail + FROZEN_DYNAMIC_ROWS_V3_LOOP_COUNT_OFFSET,
        invalid,
    )?;
    for index in 0..4 {
        cmp_mem_w_const(
            a,
            19,
            tail + FROZEN_DYNAMIC_ROWS_V3_LOOP_STATES_OFFSET + index * 4,
            u32::MAX,
            invalid,
        )?;
    }
    cmp_mem_w_const(
        a,
        19,
        tail + FROZEN_DYNAMIC_ROWS_V3_FORMAT_VERSION_OFFSET,
        FROZEN_ORDERED_NFA_V15_FORMAT_VERSION,
        invalid,
    )?;
    require_mem_w_zero(
        a,
        19,
        tail + FROZEN_DYNAMIC_ROWS_V6_LOOP_PLAN_COUNT_OFFSET,
        invalid,
    )?;
    require_mem_w_zero(
        a,
        19,
        tail + FROZEN_DYNAMIC_ROWS_V6_RESERVED_OFFSET,
        invalid,
    )?;
    require_mem_x_zero(
        a,
        19,
        tail + FROZEN_DYNAMIC_ROWS_V6_LOOP_INDEX_ADDRESS_OFFSET,
        invalid,
    )?;
    require_mem_x_zero(
        a,
        19,
        tail + FROZEN_DYNAMIC_ROWS_V6_LOOP_INDEX_LENGTH_OFFSET,
        invalid,
    )?;
    for plan in 0..4 {
        let base = tail + FROZEN_DYNAMIC_ROWS_V6_LOOP_PLANS_OFFSET + plan * 48;
        cmp_mem_x_const(a, 19, base, u64::MAX, invalid)?;
        for offset in [8, 16, 24, 32] {
            require_mem_x_zero(a, 19, base + offset, invalid)?;
        }
        a.load_x(
            8,
            19,
            base + FROZEN_COMPACT_LOOP_PLAN_V1_SCANNER_ADDRESS_OFFSET,
        )?;
        a.cbz_x(8, invalid)?;
        for bit in 0..3 {
            a.tbnz_x(8, bit, invalid)?;
        }
    }
    Ok(())
}

fn emit_exact_scratch_auth(
    a: &mut A<'_>,
    layout: NativeOrderedNfaObjectLayout,
    expected_scratch_bytes: usize,
    invalid: usize,
) -> Result<(), ObjectError> {
    for (offset, value) in [
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_READY_SEAL_OFFSET,
            FROZEN_ORDERED_NFA_SCRATCH_V1_READY_SEAL,
        ),
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_MAGIC_OFFSET,
            FROZEN_ORDERED_NFA_SCRATCH_V1_MAGIC,
        ),
    ] {
        cmp_mem_x_const(a, 19, offset, value, invalid)?;
    }
    for (offset, value) in [
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION_OFFSET,
            FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION,
        ),
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION_COMPLEMENT_OFFSET,
            !FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION,
        ),
    ] {
        cmp_mem_w_const(a, 19, offset, value, invalid)?;
    }
    cmp_mem_x_const(
        a,
        19,
        FROZEN_ORDERED_NFA_SCRATCH_V1_BYTES_OFFSET,
        u64::try_from(expected_scratch_bytes).unwrap(),
        invalid,
    )?;
    compare_identity(
        a,
        19,
        FROZEN_ORDERED_NFA_SCRATCH_V1_ARTIFACT_IDENTITY_OFFSET,
        24,
        ORDERED_NFA_OBJECT_V1_IDENTITY_OFFSET,
        invalid,
    )?;
    a.load_x(8, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_CACHE_IDENTITY_OFFSET)?;
    a.load_x(9, 31, usize::from(L_CACHE))?;
    a.cmp_x(8, 9)?;
    a.branch_cond(AARCH64_NE, invalid)?;
    let header = [
        FROZEN_PREPARED_HEADER_V15_DYNAMIC_ROWS_OFFSET
            + FROZEN_DYNAMIC_ROWS_V6_LOOP_PLANS_OFFSET
            + FROZEN_COMPACT_LOOP_PLAN_V1_SCANNER_ADDRESS_OFFSET,
        FROZEN_PREPARED_HEADER_V15_DYNAMIC_ROWS_OFFSET
            + FROZEN_DYNAMIC_ROWS_V6_LOOP_PLANS_OFFSET
            + 48
            + FROZEN_COMPACT_LOOP_PLAN_V1_SCANNER_ADDRESS_OFFSET,
        FROZEN_PREPARED_HEADER_V15_DYNAMIC_ROWS_OFFSET
            + FROZEN_DYNAMIC_ROWS_V6_LOOP_PLANS_OFFSET
            + 96
            + FROZEN_COMPACT_LOOP_PLAN_V1_SCANNER_ADDRESS_OFFSET,
        FROZEN_PREPARED_HEADER_V15_DYNAMIC_ROWS_OFFSET
            + FROZEN_DYNAMIC_ROWS_V6_LOOP_PLANS_OFFSET
            + 144
            + FROZEN_COMPACT_LOOP_PLAN_V1_SCANNER_ADDRESS_OFFSET,
    ];
    for (((offset, local), register), header_offset) in [
        (FROZEN_ORDERED_NFA_SCRATCH_V1_SEEN_ADDRESS_OFFSET, L_SEEN),
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_ADDRESS_OFFSET,
            L_CURRENT,
        ),
        (FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_ADDRESS_OFFSET, L_ROOTS),
        (FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_ADDRESS_OFFSET, L_STACK),
    ]
    .into_iter()
    .zip([25, 26, 27, 28])
    .zip(header)
    {
        a.load_x(8, 19, offset)?;
        a.cbz_x(8, invalid)?;
        for bit in 0..3 {
            a.tbnz_x(8, bit, invalid)?;
        }
        a.load_x(9, 31, usize::from(L_HEADER))?;
        a.load_x(10, 9, header_offset)?;
        a.cmp_x(8, 10)?;
        a.branch_cond(AARCH64_NE, invalid)?;
        a.store_x(8, 31, usize::from(local))?;
        a.mov_x(register, 8)?;
    }
    for (offset, value) in [
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_STATE_CAPACITY_OFFSET,
            layout.state_count,
        ),
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_ROOT_CAPACITY_OFFSET,
            layout.edge_count,
        ),
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_CAPACITY_OFFSET,
            layout.closure_slots,
        ),
    ] {
        cmp_mem_w_const(a, 19, offset, u32::try_from(value).unwrap(), invalid)?;
    }
    require_mem_w_zero(
        a,
        19,
        FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_CAPACITY_OFFSET + 4,
        invalid,
    )?;
    for (offset, capacity) in [
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
            layout.state_count,
        ),
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET,
            layout.edge_count,
        ),
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET,
            layout.closure_slots,
        ),
    ] {
        a.load_x(8, 19, offset)?;
        a.constant64(9, u64::try_from(capacity).unwrap())?;
        a.cmp_x(8, 9)?;
        a.branch_cond(AARCH64_HI, invalid)?;
    }
    a.load_w(8, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET)?;
    a.cmp_w_imm(8, 1)?;
    a.branch_cond(AARCH64_HI, invalid)?;
    require_mem_w_zero(
        a,
        19,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET + 4,
        invalid,
    )?;
    Ok(())
}

fn cmp_w_value(a: &mut A<'_>, register: u8, value: u32) -> Result<(), ObjectError> {
    if value <= 0x0fff {
        return a.cmp_w_imm(register, u16::try_from(value).unwrap());
    }
    a.constant32(17, value)?;
    a.cmp_w(register, 17)
}

fn materialize_table_base(
    a: &mut A<'_>,
    destination: u8,
    offset: usize,
) -> Result<(), ObjectError> {
    a.constant64(
        17,
        u64::try_from(offset)
            .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 Ordered-NFA table offset"))?,
    )?;
    a.add_x(destination, 24, 17)
}

fn emit_ascii_word_classification(
    asm: &mut Aarch64Assembler,
    byte: u8,
    output: u8,
) -> Result<(), ObjectError> {
    let word = asm.label()?;
    let done = asm.label()?;
    let mut a = A { asm };
    a.constant32(output, 0)?;
    cmp_w_value(&mut a, byte, u32::from(b'_'))?;
    a.branch_cond(AARCH64_EQ, word)?;
    cmp_w_value(&mut a, byte, u32::from(b'0'))?;
    a.branch_cond(AARCH64_LO, done)?;
    cmp_w_value(&mut a, byte, u32::from(b'9'))?;
    a.branch_cond(AARCH64_LS, word)?;
    cmp_w_value(&mut a, byte, u32::from(b'A'))?;
    a.branch_cond(AARCH64_LO, done)?;
    cmp_w_value(&mut a, byte, u32::from(b'Z'))?;
    a.branch_cond(AARCH64_LS, word)?;
    cmp_w_value(&mut a, byte, u32::from(b'a'))?;
    a.branch_cond(AARCH64_LO, done)?;
    cmp_w_value(&mut a, byte, u32::from(b'z'))?;
    a.branch_cond(AARCH64_HI, done)?;
    a.asm.bind(word)?;
    a.constant32(output, 1)?;
    a.asm.bind(done)
}

/// Leaf UTF-8 decoder. Input is x0=position, x1=permitted end and w2=exact-end
/// flag. Output is w0=scalar and w1=valid. It reads only the full authenticated
/// haystack retained in x20.
fn emit_decode_scalar(asm: &mut Aarch64Assembler, label: usize) -> Result<(), ObjectError> {
    let invalid = asm.label()?;
    let len2 = asm.label()?;
    let len3 = asm.label()?;
    let len4 = asm.label()?;
    let extent = asm.label()?;
    let not_exact = asm.label()?;
    let decode2 = asm.label()?;
    let decode3 = asm.label()?;
    let decode4 = asm.label()?;
    let below_surrogate = asm.label()?;
    let ascii_valid = asm.label()?;
    let valid = asm.label()?;
    asm.bind(label)?;
    let mut a = A { asm };
    a.i(aarch64_load_byte_reg(3, 20, 0))?;
    cmp_w_value(&mut a, 3, 0x7f)?;
    a.branch_cond(AARCH64_LS, ascii_valid)?;
    cmp_w_value(&mut a, 3, 0xc2)?;
    a.branch_cond(AARCH64_LO, invalid)?;
    cmp_w_value(&mut a, 3, 0xdf)?;
    a.branch_cond(AARCH64_LS, len2)?;
    cmp_w_value(&mut a, 3, 0xef)?;
    a.branch_cond(AARCH64_LS, len3)?;
    cmp_w_value(&mut a, 3, 0xf4)?;
    a.branch_cond(AARCH64_LS, len4)?;
    a.branch(invalid)?;
    a.asm.bind(len2)?;
    a.constant32(4, 2)?;
    a.branch(extent)?;
    a.asm.bind(len3)?;
    a.constant32(4, 3)?;
    a.branch(extent)?;
    a.asm.bind(len4)?;
    a.constant32(4, 4)?;
    a.asm.bind(extent)?;
    a.add_x(5, 0, 4)?;
    a.cmp_x(5, 1)?;
    a.branch_cond(AARCH64_HI, invalid)?;
    a.cbz_w(2, not_exact)?;
    a.cmp_x(5, 1)?;
    a.branch_cond(AARCH64_NE, invalid)?;
    a.asm.bind(not_exact)?;
    a.cmp_w_imm(4, 2)?;
    a.branch_cond(AARCH64_EQ, decode2)?;
    a.cmp_w_imm(4, 3)?;
    a.branch_cond(AARCH64_EQ, decode3)?;
    a.branch(decode4)?;

    a.asm.bind(decode2)?;
    a.add_x_imm(5, 0, 1)?;
    a.i(aarch64_load_byte_reg(6, 20, 5))?;
    a.constant32(7, 0xc0)?;
    a.and_w(7, 6, 7)?;
    a.cmp_w_imm(7, 0x80)?;
    a.branch_cond(AARCH64_NE, invalid)?;
    a.i(aarch64_and_low_w(0, 3, 5))?;
    a.lsl_w_imm(0, 0, 6)?;
    a.i(aarch64_and_low_w(6, 6, 6))?;
    a.orr_w(0, 0, 6)?;
    a.branch(valid)?;

    a.asm.bind(decode3)?;
    a.add_x_imm(5, 0, 1)?;
    a.i(aarch64_load_byte_reg(6, 20, 5))?;
    a.add_x_imm(5, 0, 2)?;
    a.i(aarch64_load_byte_reg(7, 20, 5))?;
    for register in [6, 7] {
        a.constant32(8, 0xc0)?;
        a.and_w(8, register, 8)?;
        a.cmp_w_imm(8, 0x80)?;
        a.branch_cond(AARCH64_NE, invalid)?;
    }
    a.i(aarch64_and_low_w(0, 3, 4))?;
    a.lsl_w_imm(0, 0, 12)?;
    a.i(aarch64_and_low_w(6, 6, 6))?;
    a.lsl_w_imm(6, 6, 6)?;
    a.orr_w(0, 0, 6)?;
    a.i(aarch64_and_low_w(7, 7, 6))?;
    a.orr_w(0, 0, 7)?;
    cmp_w_value(&mut a, 0, 0x800)?;
    a.branch_cond(AARCH64_LO, invalid)?;
    cmp_w_value(&mut a, 0, 0xd800)?;
    a.branch_cond(AARCH64_LO, below_surrogate)?;
    cmp_w_value(&mut a, 0, 0xdfff)?;
    a.branch_cond(AARCH64_LS, invalid)?;
    a.asm.bind(below_surrogate)?;
    a.branch(valid)?;

    a.asm.bind(decode4)?;
    a.add_x_imm(5, 0, 1)?;
    a.i(aarch64_load_byte_reg(6, 20, 5))?;
    a.add_x_imm(5, 0, 2)?;
    a.i(aarch64_load_byte_reg(7, 20, 5))?;
    a.add_x_imm(5, 0, 3)?;
    a.i(aarch64_load_byte_reg(8, 20, 5))?;
    for register in [6, 7, 8] {
        a.constant32(9, 0xc0)?;
        a.and_w(9, register, 9)?;
        a.cmp_w_imm(9, 0x80)?;
        a.branch_cond(AARCH64_NE, invalid)?;
    }
    a.i(aarch64_and_low_w(0, 3, 3))?;
    a.lsl_w_imm(0, 0, 18)?;
    a.i(aarch64_and_low_w(6, 6, 6))?;
    a.lsl_w_imm(6, 6, 12)?;
    a.orr_w(0, 0, 6)?;
    a.i(aarch64_and_low_w(7, 7, 6))?;
    a.lsl_w_imm(7, 7, 6)?;
    a.orr_w(0, 0, 7)?;
    a.i(aarch64_and_low_w(8, 8, 6))?;
    a.orr_w(0, 0, 8)?;
    cmp_w_value(&mut a, 0, 0x1_0000)?;
    a.branch_cond(AARCH64_LO, invalid)?;
    cmp_w_value(&mut a, 0, 0x10_ffff)?;
    a.branch_cond(AARCH64_HI, invalid)?;
    a.branch(valid)?;

    a.asm.bind(ascii_valid)?;
    a.mov_w(0, 3)?;
    a.asm.bind(valid)?;
    a.constant32(1, 1)?;
    a.raw(0xd65f_03c0)?;
    a.asm.bind(invalid)?;
    a.constant32(0, 0)?;
    a.constant32(1, 0)?;
    a.raw(0xd65f_03c0)?;
    Ok(())
}

/// Leaf binary search in the exact object-local Unicode Perl-word ranges.
fn emit_unicode_member(
    asm: &mut Aarch64Assembler,
    label: usize,
    layout: NativeOrderedNfaObjectLayout,
) -> Result<(), ObjectError> {
    let unicode_offset = layout
        .unicode_ranges_offset
        .ok_or(ObjectError::InvalidModule(
            "Unicode membership emitted without object table",
        ))?;
    let loop_label = asm.label()?;
    let lower = asm.label()?;
    let upper = asm.label()?;
    let found = asm.label()?;
    let absent = asm.label()?;
    asm.bind(label)?;
    let mut a = A { asm };
    a.mov_w(6, 0)?;
    a.constant32(1, 0)?;
    a.constant32(2, u32::try_from(layout.unicode_range_count).unwrap())?;
    materialize_table_base(&mut a, 5, unicode_offset)?;
    a.asm.bind(loop_label)?;
    a.cmp_w(1, 2)?;
    a.branch_cond(AARCH64_HS, absent)?;
    a.i(aarch64_add_w_reg(3, 1, 2))?;
    a.i(aarch64_lsr_w_imm(3, 3, 1))?;
    a.i(aarch64_add_x_uxtw(4, 5, 3, 3))?;
    a.load_w(7, 4, 0)?;
    a.cmp_w(6, 7)?;
    a.branch_cond(AARCH64_LO, lower)?;
    a.load_w(7, 4, 4)?;
    a.cmp_w(6, 7)?;
    a.branch_cond(AARCH64_HI, upper)?;
    a.branch(found)?;
    a.asm.bind(lower)?;
    a.mov_w(2, 3)?;
    a.branch(loop_label)?;
    a.asm.bind(upper)?;
    a.add_w_imm(1, 3, 1)?;
    a.branch(loop_label)?;
    a.asm.bind(found)?;
    a.constant32(0, 1)?;
    a.raw(0xd65f_03c0)?;
    a.asm.bind(absent)?;
    a.constant32(0, 0)?;
    a.raw(0xd65f_03c0)?;
    Ok(())
}

fn emit_helper_return(a: &mut A<'_>, return_local: u16) -> Result<(), ObjectError> {
    a.load_x(30, 31, usize::from(return_local))?;
    a.raw(0xd65f_03c0)?;
    Ok(())
}

fn emit_unicode_classifiers(
    asm: &mut Aarch64Assembler,
    left_label: usize,
    right_label: usize,
    decode_label: usize,
    member_label: usize,
) -> Result<(), ObjectError> {
    let left_nonword = asm.label()?;
    let left_invalid = asm.label()?;
    let left_find = asm.label()?;
    let left_found = asm.label()?;
    let left_ascii = asm.label()?;
    let left_done = asm.label()?;
    asm.bind(left_label)?;
    let mut a = A { asm };
    a.store_x(30, 31, usize::from(L_CLASS_RETURN))?;
    a.cbz_x(0, left_nonword)?;
    a.mov_x(1, 0)?;
    a.sub_x_imm(0, 0, 1)?;
    a.constant32(3, 0)?;
    a.asm.bind(left_find)?;
    a.i(aarch64_load_byte_reg(4, 20, 0))?;
    cmp_w_value(&mut a, 4, 0x80)?;
    a.branch_cond(AARCH64_LO, left_found)?;
    cmp_w_value(&mut a, 4, 0xbf)?;
    a.branch_cond(AARCH64_HI, left_found)?;
    a.cmp_w_imm(3, 3)?;
    a.branch_cond(AARCH64_HS, left_invalid)?;
    a.cbz_x(0, left_invalid)?;
    a.sub_x_imm(0, 0, 1)?;
    a.add_w_imm(3, 3, 1)?;
    a.branch(left_find)?;
    a.asm.bind(left_found)?;
    cmp_w_value(&mut a, 4, 0x7f)?;
    a.branch_cond(AARCH64_LS, left_ascii)?;
    a.constant32(2, 1)?;
    a.call(decode_label)?;
    a.cbz_w(1, left_invalid)?;
    a.call(member_label)?;
    a.add_w_imm(0, 0, 1)?;
    a.branch(left_done)?;
    a.asm.bind(left_ascii)?;
    emit_ascii_word_classification(a.asm, 4, 9)?;
    a.mov_w(0, 9)?;
    a.add_w_imm(0, 0, 1)?;
    a.branch(left_done)?;
    a.asm.bind(left_nonword)?;
    a.constant32(0, 1)?;
    a.branch(left_done)?;
    a.asm.bind(left_invalid)?;
    a.constant32(0, 0)?;
    a.asm.bind(left_done)?;
    emit_helper_return(&mut a, L_CLASS_RETURN)?;

    let right_nonword = a.asm.label()?;
    let right_invalid = a.asm.label()?;
    let right_ascii = a.asm.label()?;
    let right_done = a.asm.label()?;
    a.asm.bind(right_label)?;
    a.store_x(30, 31, usize::from(L_CLASS_RETURN))?;
    a.cmp_x(0, 21)?;
    a.branch_cond(AARCH64_EQ, right_nonword)?;
    a.i(aarch64_load_byte_reg(4, 20, 0))?;
    cmp_w_value(&mut a, 4, 0x7f)?;
    a.branch_cond(AARCH64_LS, right_ascii)?;
    a.mov_x(1, 21)?;
    a.constant32(2, 0)?;
    a.call(decode_label)?;
    a.cbz_w(1, right_invalid)?;
    a.call(member_label)?;
    a.add_w_imm(0, 0, 1)?;
    a.branch(right_done)?;
    a.asm.bind(right_ascii)?;
    emit_ascii_word_classification(a.asm, 4, 9)?;
    a.mov_w(0, 9)?;
    a.add_w_imm(0, 0, 1)?;
    a.branch(right_done)?;
    a.asm.bind(right_nonword)?;
    a.constant32(0, 1)?;
    a.branch(right_done)?;
    a.asm.bind(right_invalid)?;
    a.constant32(0, 0)?;
    a.asm.bind(right_done)?;
    emit_helper_return(&mut a, L_CLASS_RETURN)
}

fn emit_assertion_result(a: &mut A<'_>, value: bool, failed: bool) -> Result<(), ObjectError> {
    a.constant32(0, u32::from(value))?;
    a.constant32(1, u32::from(failed))?;
    emit_helper_return(a, L_ASSERT_RETURN)
}

fn emit_assertion(
    asm: &mut Aarch64Assembler,
    label: usize,
    layout: NativeOrderedNfaObjectLayout,
    unicode_left: Option<usize>,
    unicode_right: Option<usize>,
) -> Result<(), ObjectError> {
    let true_result = asm.label()?;
    let false_result = asm.label()?;
    let failure = asm.label()?;
    let load_context = asm.label()?;
    let ascii = asm.label()?;
    let unicode = asm.label()?;
    asm.bind(label)?;
    let mut a = A { asm };
    a.store_x(30, 31, usize::from(L_ASSERT_RETURN))?;
    a.store_w(0, 31, usize::from(L_ASSERT_KIND))?;
    a.store_x(1, 31, usize::from(L_ASSERT_POSITION))?;
    a.cmp_w_imm(0, EDGE_WORD_END_HALF_UNICODE.into())?;
    a.branch_cond(AARCH64_HI, failure)?;
    a.cmp_w_imm(0, EDGE_EPSILON.into())?;
    a.branch_cond(AARCH64_EQ, true_result)?;
    a.cmp_w_imm(0, EDGE_START_TEXT.into())?;
    let not_absolute_start = a.asm.label()?;
    a.branch_cond(AARCH64_NE, not_absolute_start)?;
    a.cbz_x(1, true_result)?;
    a.branch(false_result)?;
    a.asm.bind(not_absolute_start)?;
    a.cmp_w_imm(0, EDGE_END_TEXT.into())?;
    a.branch_cond(AARCH64_NE, load_context)?;
    a.cmp_x(1, 21)?;
    a.branch_cond(AARCH64_EQ, true_result)?;
    a.branch(false_result)?;

    a.asm.bind(load_context)?;
    a.constant32(8, 256)?;
    a.constant32(9, 256)?;
    let no_before = a.asm.label()?;
    a.cbz_x(1, no_before)?;
    a.sub_x_imm(10, 1, 1)?;
    a.i(aarch64_load_byte_reg(8, 20, 10))?;
    a.asm.bind(no_before)?;
    let no_after = a.asm.label()?;
    a.cmp_x(1, 21)?;
    a.branch_cond(AARCH64_EQ, no_after)?;
    a.i(aarch64_load_byte_reg(9, 20, 1))?;
    a.asm.bind(no_after)?;

    for kind in EDGE_START_LINE..=EDGE_END_LINE_CRLF {
        let next = a.asm.label()?;
        a.load_w(10, 31, usize::from(L_ASSERT_KIND))?;
        a.cmp_w_imm(10, kind.into())?;
        a.branch_cond(AARCH64_NE, next)?;
        match kind {
            EDGE_START_LINE => {
                a.load_x(10, 31, usize::from(L_ASSERT_POSITION))?;
                a.cbz_x(10, true_result)?;
                cmp_w_value(&mut a, 8, u32::from(layout.line_terminator))?;
                a.branch_cond(AARCH64_EQ, true_result)?;
            }
            EDGE_END_LINE => {
                a.load_x(10, 31, usize::from(L_ASSERT_POSITION))?;
                a.cmp_x(10, 21)?;
                a.branch_cond(AARCH64_EQ, true_result)?;
                cmp_w_value(&mut a, 9, u32::from(layout.line_terminator))?;
                a.branch_cond(AARCH64_EQ, true_result)?;
            }
            EDGE_START_LINE_CRLF => {
                a.load_x(10, 31, usize::from(L_ASSERT_POSITION))?;
                a.cbz_x(10, true_result)?;
                cmp_w_value(&mut a, 8, u32::from(b'\n'))?;
                a.branch_cond(AARCH64_EQ, true_result)?;
                cmp_w_value(&mut a, 8, u32::from(b'\r'))?;
                a.branch_cond(AARCH64_NE, false_result)?;
                cmp_w_value(&mut a, 9, u32::from(b'\n'))?;
                a.branch_cond(AARCH64_NE, true_result)?;
            }
            EDGE_END_LINE_CRLF => {
                a.load_x(10, 31, usize::from(L_ASSERT_POSITION))?;
                a.cmp_x(10, 21)?;
                a.branch_cond(AARCH64_EQ, true_result)?;
                cmp_w_value(&mut a, 9, u32::from(b'\r'))?;
                a.branch_cond(AARCH64_EQ, true_result)?;
                cmp_w_value(&mut a, 9, u32::from(b'\n'))?;
                a.branch_cond(AARCH64_NE, false_result)?;
                cmp_w_value(&mut a, 8, u32::from(b'\r'))?;
                a.branch_cond(AARCH64_NE, true_result)?;
            }
            _ => unreachable!(),
        }
        a.branch(false_result)?;
        a.asm.bind(next)?;
    }
    a.load_w(10, 31, usize::from(L_ASSERT_KIND))?;
    a.cmp_w_imm(10, EDGE_WORD_UNICODE.into())?;
    a.branch_cond(AARCH64_HS, unicode)?;
    a.branch(ascii)?;

    a.asm.bind(ascii)?;
    emit_ascii_word_classification(a.asm, 8, 10)?;
    emit_ascii_word_classification(a.asm, 9, 11)?;
    for kind in EDGE_WORD_ASCII..=EDGE_WORD_END_HALF_ASCII {
        let next = a.asm.label()?;
        a.load_w(12, 31, usize::from(L_ASSERT_KIND))?;
        a.cmp_w_imm(12, kind.into())?;
        a.branch_cond(AARCH64_NE, next)?;
        match kind {
            EDGE_WORD_ASCII => {
                a.cmp_w(10, 11)?;
                a.branch_cond(AARCH64_NE, true_result)?;
            }
            EDGE_NOT_WORD_ASCII => {
                a.cmp_w(10, 11)?;
                a.branch_cond(AARCH64_EQ, true_result)?;
            }
            EDGE_WORD_START_ASCII => {
                a.cbnz_w(10, false_result)?;
                a.cbnz_w(11, true_result)?;
            }
            EDGE_WORD_END_ASCII => {
                a.cbz_w(10, false_result)?;
                a.cbz_w(11, true_result)?;
            }
            EDGE_WORD_START_HALF_ASCII => {
                a.cbz_w(10, true_result)?;
            }
            EDGE_WORD_END_HALF_ASCII => {
                a.cbz_w(11, true_result)?;
            }
            _ => unreachable!(),
        }
        a.branch(false_result)?;
        a.asm.bind(next)?;
    }
    a.branch(failure)?;

    a.asm.bind(unicode)?;
    let Some((left, right)) = unicode_left.zip(unicode_right) else {
        a.branch(failure)?;
        a.asm.bind(true_result)?;
        emit_assertion_result(&mut a, true, false)?;
        a.asm.bind(false_result)?;
        emit_assertion_result(&mut a, false, false)?;
        a.asm.bind(failure)?;
        return emit_assertion_result(&mut a, false, true);
    };
    a.load_x(0, 31, usize::from(L_ASSERT_POSITION))?;
    a.call(left)?;
    a.store_w(0, 31, usize::from(L_ASSERT_LEFT))?;
    a.load_x(0, 31, usize::from(L_ASSERT_POSITION))?;
    a.call(right)?;
    a.mov_w(10, 0)?;
    a.load_w(9, 31, usize::from(L_ASSERT_LEFT))?;
    for kind in EDGE_WORD_UNICODE..=EDGE_WORD_END_HALF_UNICODE {
        let next = a.asm.label()?;
        a.load_w(11, 31, usize::from(L_ASSERT_KIND))?;
        a.cmp_w_imm(11, kind.into())?;
        a.branch_cond(AARCH64_NE, next)?;
        match kind {
            EDGE_WORD_UNICODE => {
                cmp_w_value(&mut a, 9, 2)?;
                let left_not_word = a.asm.label()?;
                let compare = a.asm.label()?;
                a.branch_cond(AARCH64_NE, left_not_word)?;
                cmp_w_value(&mut a, 10, 2)?;
                a.branch_cond(AARCH64_NE, true_result)?;
                a.branch(false_result)?;
                a.asm.bind(left_not_word)?;
                cmp_w_value(&mut a, 10, 2)?;
                a.branch_cond(AARCH64_NE, compare)?;
                a.branch(true_result)?;
                a.asm.bind(compare)?;
            }
            EDGE_NOT_WORD_UNICODE => {
                a.cbz_w(9, false_result)?;
                a.cbz_w(10, false_result)?;
                cmp_w_value(&mut a, 9, 2)?;
                let left_not_word = a.asm.label()?;
                a.branch_cond(AARCH64_NE, left_not_word)?;
                cmp_w_value(&mut a, 10, 2)?;
                a.branch_cond(AARCH64_EQ, true_result)?;
                a.branch(false_result)?;
                a.asm.bind(left_not_word)?;
                cmp_w_value(&mut a, 10, 2)?;
                a.branch_cond(AARCH64_NE, true_result)?;
            }
            EDGE_WORD_START_UNICODE => {
                cmp_w_value(&mut a, 9, 2)?;
                a.branch_cond(AARCH64_EQ, false_result)?;
                cmp_w_value(&mut a, 10, 2)?;
                a.branch_cond(AARCH64_EQ, true_result)?;
            }
            EDGE_WORD_END_UNICODE => {
                cmp_w_value(&mut a, 9, 2)?;
                a.branch_cond(AARCH64_NE, false_result)?;
                cmp_w_value(&mut a, 10, 2)?;
                a.branch_cond(AARCH64_NE, true_result)?;
            }
            EDGE_WORD_START_HALF_UNICODE => {
                cmp_w_value(&mut a, 9, 1)?;
                a.branch_cond(AARCH64_EQ, true_result)?;
            }
            EDGE_WORD_END_HALF_UNICODE => {
                cmp_w_value(&mut a, 10, 1)?;
                a.branch_cond(AARCH64_EQ, true_result)?;
            }
            _ => unreachable!(),
        }
        a.branch(false_result)?;
        a.asm.bind(next)?;
    }
    a.branch(failure)?;

    a.asm.bind(true_result)?;
    emit_assertion_result(&mut a, true, false)?;
    a.asm.bind(false_result)?;
    emit_assertion_result(&mut a, false, false)?;
    a.asm.bind(failure)?;
    emit_assertion_result(&mut a, false, true)
}

fn load_table_byte(
    a: &mut A<'_>,
    destination: u8,
    index: u8,
    offset: usize,
) -> Result<(), ObjectError> {
    materialize_table_base(a, 16, offset)?;
    a.i(aarch64_load_byte_reg(destination, 16, index))
}

fn load_table_word(
    a: &mut A<'_>,
    destination: u8,
    index: u8,
    offset: usize,
) -> Result<(), ObjectError> {
    materialize_table_base(a, 16, offset)?;
    a.i(aarch64_load_w_uxtw(destination, 16, index))
}

fn thread_address(a: &mut A<'_>, destination: u8, base: u8, index: u8) -> Result<(), ObjectError> {
    a.i(aarch64_add_x_lsl(destination, base, index, 4))
}

fn store_thread(a: &mut A<'_>, address: u8, state: u8, start: u8) -> Result<(), ObjectError> {
    a.store_w(state, address, 0)?;
    a.store_w(31, address, 4)?;
    a.store_x(start, address, 8)
}

fn compare_x_usize(a: &mut A<'_>, register: u8, value: usize) -> Result<(), ObjectError> {
    a.constant64(
        17,
        u64::try_from(value)
            .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 Ordered-NFA bound"))?,
    )?;
    a.cmp_x(register, 17)
}

fn selected_start_closure_program<'a>(
    image: &NativeOrderedNfaObjectImage<'a>,
) -> Result<Option<NativeEpsilonClosureProgramView<'a>>, ObjectError> {
    match (
        image.start_closure_program,
        image.layout.start_closure_dispatch,
    ) {
        (None, None) => Ok(None),
        (Some(program), Some(receipt))
            if program.len() == receipt.instruction_count
                && program.is_guarded() == receipt.guarded
                && (!receipt.guarded || image.layout.cache_boundary_assertions) =>
        {
            let first = program.instruction(0).ok_or(ObjectError::InvalidModule(
                "AArch64 Ordered-NFA start closure first instruction",
            ))?;
            if first.state() != image.layout.start_state
                || first.subtree_end() != program.len()
                || first.guard() != 0
            {
                return Err(ObjectError::InvalidModule(
                    "AArch64 Ordered-NFA start closure root",
                ));
            }
            Ok(Some(program))
        }
        _ => Err(ObjectError::InvalidModule(
            "AArch64 Ordered-NFA start closure receipt",
        )),
    }
}

/// Branch to `matched` exactly when `byte` is in the compiler-proved
/// first-byte cover. Validate the compiler-only range receipt before baking
/// its comparisons into target text.
fn emit_start_prefix_membership(
    a: &mut A<'_>,
    plan: NativeOrderedNfaStartPrefixPlan,
    byte: u8,
    matched: usize,
    missed: usize,
) -> Result<(), ObjectError> {
    let mut previous_end = None;
    if plan.ranges().is_empty() {
        return Err(ObjectError::InvalidModule(
            "AArch64 Ordered-NFA empty start-prefix cover",
        ));
    }
    for range in plan.ranges() {
        if range.start > range.end
            || previous_end.is_some_and(|end| end >= range.start)
        {
            return Err(ObjectError::InvalidModule(
                "AArch64 Ordered-NFA start-prefix range order",
            ));
        }
        previous_end = Some(range.end);
        let next_range = a.asm.label()?;
        a.cmp_w_imm(byte, u16::from(range.start))?;
        a.branch_cond(AARCH64_LO, next_range)?;
        a.cmp_w_imm(byte, u16::from(range.end))?;
        a.branch_cond(AARCH64_LS, matched)?;
        a.asm.bind(next_range)?;
    }
    a.branch(missed)
}

fn start_closure_labels(
    asm: &mut Aarch64Assembler,
    program: NativeEpsilonClosureProgramView<'_>,
) -> Result<Vec<usize>, ObjectError> {
    let count = program
        .len()
        .checked_add(1)
        .ok_or(ObjectError::ArithmeticOverflow(
            "AArch64 Ordered-NFA start closure label count",
        ))?;
    let mut labels = Vec::new();
    labels
        .try_reserve_exact(count)
        .map_err(|_| ObjectError::Allocation("AArch64 Ordered-NFA start closure labels"))?;
    for _ in 0..count {
        labels.push(asm.label()?);
    }
    Ok(labels)
}

fn start_closure_label(labels: &[usize], index: usize) -> Result<usize, ObjectError> {
    labels.get(index).copied().ok_or(ObjectError::InvalidModule(
        "AArch64 Ordered-NFA start closure label",
    ))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "validated assertion-kind bounds make the compiler-emitted cache bit total"
)]
fn emit_static_guarded_split_assertions(
    a: &mut A<'_>,
    kinds: &[u8],
    assertion_kinds: u32,
    assertion: usize,
    runtime_failure: usize,
) -> Result<(), ObjectError> {
    for &kind in kinds.iter().rev() {
        if kind == EDGE_EPSILON {
            continue;
        }
        if !(EDGE_START_TEXT..=EDGE_WORD_END_HALF_UNICODE).contains(&kind) {
            return Err(ObjectError::InvalidModule(
                "AArch64 Ordered-NFA guarded start closure Split edge",
            ));
        }
        let bit = 1_u32 << u32::from(kind - EDGE_START_TEXT);
        if assertion_kinds & bit == 0 {
            return Err(ObjectError::InvalidModule(
                "AArch64 Ordered-NFA guarded start closure assertion kind",
            ));
        }
        let known = a.asm.label()?;
        a.constant32(9, bit)?;
        a.load_w(10, 31, usize::from(L_ASSERT_CACHE_KNOWN))?;
        a.and_w(11, 10, 9)?;
        a.cbnz_w(11, known)?;
        a.constant32(0, u32::from(kind))?;
        a.load_x(1, 31, usize::from(L_POSITION))?;
        a.call(assertion)?;
        a.cbnz_w(1, runtime_failure)?;
        a.constant32(9, bit)?;
        a.load_w(10, 31, usize::from(L_ASSERT_CACHE_KNOWN))?;
        a.orr_w(10, 10, 9)?;
        a.store_w(10, 31, usize::from(L_ASSERT_CACHE_KNOWN))?;
        a.cbz_w(0, known)?;
        a.load_w(10, 31, usize::from(L_ASSERT_CACHE_ENABLED))?;
        a.orr_w(10, 10, 9)?;
        a.store_w(10, 31, usize::from(L_ASSERT_CACHE_ENABLED))?;
        a.asm.bind(known)?;
    }
    Ok(())
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_arguments,
    reason = "validated guards make cache-bit construction total while the static closure shares the authenticated image and semantic exits"
)]
fn emit_static_start_closure(
    a: &mut A<'_>,
    image: &NativeOrderedNfaObjectImage<'_>,
    program: NativeEpsilonClosureProgramView<'_>,
    labels: &[usize],
    assertion: usize,
    after_roots: usize,
    runtime_failure: usize,
) -> Result<(), ObjectError> {
    let layout = image.layout;
    a.asm.bind(start_closure_label(labels, 0)?)?;
    a.store_x(31, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
    for instruction_index in 0..program.len() {
        if instruction_index != 0 {
            a.asm
                .bind(start_closure_label(labels, instruction_index)?)?;
        }
        let instruction = program.instruction(instruction_index).ok_or(
            ObjectError::InvalidModule("AArch64 Ordered-NFA start closure instruction"),
        )?;
        let state = instruction.state();
        if usize::try_from(state)
            .ok()
            .is_none_or(|state| state >= layout.state_count)
        {
            return Err(ObjectError::InvalidModule(
                "AArch64 Ordered-NFA start closure state",
            ));
        }
        let subtree_end = instruction.subtree_end();
        if subtree_end <= instruction_index || subtree_end > program.len() {
            return Err(ObjectError::InvalidModule(
                "AArch64 Ordered-NFA start closure subtree",
            ));
        }
        let subtree_end = start_closure_label(labels, subtree_end)?;

        let guard = instruction.guard();
        if guard != 0 {
            if !program.is_guarded() || guard > 18 {
                return Err(ObjectError::InvalidModule(
                    "AArch64 Ordered-NFA start closure guard",
                ));
            }
            let bit = 1_u32 << guard.saturating_sub(1);
            if layout.assertion_kinds & bit == 0 {
                return Err(ObjectError::InvalidModule(
                    "AArch64 Ordered-NFA start closure guard kind",
                ));
            }
            a.constant32(9, bit)?;
            a.load_w(10, 31, usize::from(L_ASSERT_CACHE_KNOWN))?;
            a.and_w(11, 10, 9)?;
            a.cbz_w(11, runtime_failure)?;
            a.load_w(10, 31, usize::from(L_ASSERT_CACHE_ENABLED))?;
            a.and_w(11, 10, 9)?;
            a.cbz_w(11, subtree_end)?;
        }

        a.constant32(8, state)?;
        a.i(aarch64_load_x_lsl3(9, 25, 8))?;
        a.load_x(10, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET)?;
        a.cmp_x(9, 10)?;
        a.branch_cond(AARCH64_EQ, subtree_end)?;
        a.i(aarch64_add_x_lsl(9, 25, 8, 3))?;
        a.store_x(10, 9, 0)?;

        match instruction.action() {
            NativeEpsilonClosureAction::Accept => {
                a.load_x(10, 31, usize::from(L_THREAD_START))?;
                a.store_x(10, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_START_OFFSET)?;
                a.load_x(10, 31, usize::from(L_POSITION))?;
                a.store_x(10, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_END_OFFSET)?;
                a.constant32(10, 1)?;
                a.store_w(10, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET)?;
                a.branch(after_roots)?;
            }
            NativeEpsilonClosureAction::Consume => {
                a.load_x(9, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET)?;
                compare_x_usize(a, 9, layout.state_count)?;
                a.branch_cond(AARCH64_HS, runtime_failure)?;
                thread_address(a, 10, 26, 9)?;
                a.constant32(11, state)?;
                a.load_x(12, 31, usize::from(L_THREAD_START))?;
                store_thread(a, 10, 11, 12)?;
                a.add_x_imm(9, 9, 1)?;
                a.store_x(9, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET)?;
            }
            NativeEpsilonClosureAction::Split => {
                if program.is_guarded() {
                    let kinds = image.encoded_edge_kinds_for_state(state).ok_or(
                        ObjectError::InvalidModule(
                            "AArch64 Ordered-NFA guarded start closure Split row",
                        ),
                    )?;
                    emit_static_guarded_split_assertions(
                        a,
                        kinds,
                        layout.assertion_kinds,
                        assertion,
                        runtime_failure,
                    )?;
                }
            }
            NativeEpsilonClosureAction::SeenBackedge => a.branch(runtime_failure)?,
        }
    }
    a.asm
        .bind(start_closure_label(labels, program.len())?)?;
    a.branch(after_roots)
}

fn emit_semantic_body(
    asm: &mut Aarch64Assembler,
    image: &NativeOrderedNfaObjectImage<'_>,
    assertion: usize,
    no_match: usize,
    matched: usize,
    runtime_failure: usize,
) -> Result<(), ObjectError> {
    let layout = image.layout;
    let start_program = selected_start_closure_program(image)?;
    let start_labels = start_program
        .map(|program| start_closure_labels(asm, program))
        .transpose()?;
    let boundary = asm.label()?;
    let next_old_root = asm.label()?;
    let old_roots_done = asm.label()?;
    let expand_start = asm.label()?;
    let expand_loop = asm.label()?;
    let split_edges = asm.label()?;
    let split_next = asm.label()?;
    let split_assertion_passed = asm.label()?;
    let cached_assertion_miss = asm.label()?;
    let cached_assertion_false = asm.label()?;
    let expand_pop = asm.label()?;
    let root_complete = asm.label()?;
    let after_roots = asm.label()?;
    let has_current = asm.label()?;
    let consume_start = asm.label()?;
    let consume_thread = asm.label()?;
    let consume_next_thread = asm.label()?;
    let consume_edge = asm.label()?;
    let consume_next_edge = asm.label()?;
    let consumed_boundary = asm.label()?;
    let finish = asm.label()?;
    let not_accept = asm.label()?;

    let mut a = A { asm };
    a.branch(boundary)?;

    a.asm.bind(boundary)?;
    a.store_x(31, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET)?;
    a.load_x(8, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET)?;
    a.add_x_imm(8, 8, 1)?;
    a.store_x(8, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET)?;
    a.load_x(8, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET)?;
    a.store_x(8, 31, usize::from(L_ROOT_COUNT))?;
    a.store_x(31, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET)?;
    a.store_x(31, 31, usize::from(L_ROOT_INDEX))?;
    a.store_x(31, 31, usize::from(L_ROOT_MODE))?;
    if layout.cache_boundary_assertions {
        a.store_w(31, 31, usize::from(L_ASSERT_CACHE_KNOWN))?;
        a.store_w(31, 31, usize::from(L_ASSERT_CACHE_ENABLED))?;
    }

    a.asm.bind(next_old_root)?;
    a.load_x(8, 31, usize::from(L_ROOT_INDEX))?;
    a.load_x(9, 31, usize::from(L_ROOT_COUNT))?;
    a.cmp_x(8, 9)?;
    a.branch_cond(AARCH64_HS, old_roots_done)?;
    thread_address(&mut a, 10, 27, 8)?;
    a.load_w(11, 10, 0)?;
    a.store_x(11, 31, usize::from(L_THREAD_STATE))?;
    a.load_w(11, 10, 4)?;
    a.cbnz_w(11, runtime_failure)?;
    a.load_x(11, 10, 8)?;
    a.store_x(11, 31, usize::from(L_THREAD_START))?;
    a.add_x_imm(8, 8, 1)?;
    a.store_x(8, 31, usize::from(L_ROOT_INDEX))?;
    a.branch(expand_start)?;

    a.asm.bind(old_roots_done)?;
    a.load_w(8, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET)?;
    a.cbnz_w(8, after_roots)?;
    if let Some(prefix) = layout.start_prefix {
        let start_admitted = a.asm.label()?;
        a.load_x(8, 31, usize::from(L_POSITION))?;
        a.cmp_x(8, 22)?;
        a.branch_cond(AARCH64_HS, after_roots)?;
        a.i(aarch64_load_byte_reg(9, 20, 8))?;
        emit_start_prefix_membership(
            &mut a,
            prefix,
            9,
            start_admitted,
            after_roots,
        )?;
        a.asm.bind(start_admitted)?;
    }
    a.constant32(8, layout.start_state)?;
    a.store_x(8, 31, usize::from(L_THREAD_STATE))?;
    a.load_x(8, 31, usize::from(L_POSITION))?;
    a.store_x(8, 31, usize::from(L_THREAD_START))?;
    a.constant32(8, 1)?;
    a.store_x(8, 31, usize::from(L_ROOT_MODE))?;
    if let Some(labels) = start_labels.as_deref() {
        a.branch(start_closure_label(labels, 0)?)?;
    }

    a.asm.bind(expand_start)?;
    a.store_x(31, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
    a.branch(expand_loop)?;

    a.asm.bind(expand_loop)?;
    a.load_x(8, 31, usize::from(L_THREAD_STATE))?;
    compare_x_usize(&mut a, 8, layout.state_count)?;
    a.branch_cond(AARCH64_HS, runtime_failure)?;
    a.i(aarch64_load_x_lsl3(9, 25, 8))?;
    a.load_x(10, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET)?;
    a.cmp_x(9, 10)?;
    a.branch_cond(AARCH64_EQ, expand_pop)?;
    a.i(aarch64_add_x_lsl(9, 25, 8, 3))?;
    a.store_x(10, 9, 0)?;
    load_table_byte(&mut a, 9, 8, layout.roles_offset)?;
    a.cmp_w_imm(9, ROLE_ACCEPT.into())?;
    a.branch_cond(AARCH64_NE, not_accept)?;
    a.load_x(10, 31, usize::from(L_THREAD_START))?;
    a.store_x(10, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_START_OFFSET)?;
    a.load_x(10, 31, usize::from(L_POSITION))?;
    a.store_x(10, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_END_OFFSET)?;
    a.constant32(10, 1)?;
    a.store_w(10, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET)?;
    a.branch(after_roots)?;

    a.asm.bind(not_accept)?;
    a.cmp_w_imm(9, ROLE_CONSUMING.into())?;
    a.branch_cond(AARCH64_NE, split_edges)?;
    a.load_x(9, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET)?;
    compare_x_usize(&mut a, 9, layout.state_count)?;
    a.branch_cond(AARCH64_HS, runtime_failure)?;
    thread_address(&mut a, 10, 26, 9)?;
    a.load_x(11, 31, usize::from(L_THREAD_STATE))?;
    a.load_x(12, 31, usize::from(L_THREAD_START))?;
    store_thread(&mut a, 10, 11, 12)?;
    a.add_x_imm(9, 9, 1)?;
    a.store_x(9, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET)?;
    a.branch(expand_pop)?;

    a.asm.bind(split_edges)?;
    a.cmp_w_imm(9, ROLE_SPLIT.into())?;
    a.branch_cond(AARCH64_NE, runtime_failure)?;
    a.load_w(8, 31, usize::from(L_THREAD_STATE))?;
    load_table_word(&mut a, 9, 8, layout.edge_offsets_offset)?;
    a.add_w_imm(10, 8, 1)?;
    load_table_word(&mut a, 10, 10, layout.edge_offsets_offset)?;
    a.cmp_w(9, 10)?;
    a.branch_cond(AARCH64_HI, runtime_failure)?;
    cmp_w_value(&mut a, 10, u32::try_from(layout.edge_count).unwrap())?;
    a.branch_cond(AARCH64_HI, runtime_failure)?;
    a.store_x(9, 31, usize::from(L_EDGE_END))?;
    a.store_x(10, 31, usize::from(L_EDGE_INDEX))?;

    a.asm.bind(split_next)?;
    a.load_x(8, 31, usize::from(L_EDGE_INDEX))?;
    a.load_x(9, 31, usize::from(L_EDGE_END))?;
    a.cmp_x(8, 9)?;
    a.branch_cond(AARCH64_EQ, expand_pop)?;
    a.sub_x_imm(8, 8, 1)?;
    a.store_x(8, 31, usize::from(L_EDGE_INDEX))?;
    load_table_byte(&mut a, 0, 8, layout.edge_kinds_offset)?;
    a.cbz_w(0, split_assertion_passed)?;
    if layout.cache_boundary_assertions {
        a.cmp_w_imm(0, u16::from(EDGE_START_TEXT))?;
        a.branch_cond(AARCH64_LO, runtime_failure)?;
        a.cmp_w_imm(0, u16::from(EDGE_WORD_END_HALF_UNICODE))?;
        a.branch_cond(AARCH64_HI, runtime_failure)?;
        a.sub_w_imm(8, 0, u16::from(EDGE_START_TEXT))?;
        a.constant32(9, 1)?;
        a.lsl_w(9, 9, 8)?;
        a.constant32(10, layout.assertion_kinds)?;
        a.and_w(11, 10, 9)?;
        a.cbz_w(11, runtime_failure)?;
        a.store_w(9, 31, usize::from(L_ASSERT_CACHE_BIT))?;
        a.load_w(10, 31, usize::from(L_ASSERT_CACHE_KNOWN))?;
        a.and_w(11, 10, 9)?;
        a.cbz_w(11, cached_assertion_miss)?;
        a.load_w(10, 31, usize::from(L_ASSERT_CACHE_ENABLED))?;
        a.and_w(10, 10, 9)?;
        a.cbz_w(10, split_next)?;
        a.branch(split_assertion_passed)?;
    }
    a.asm.bind(cached_assertion_miss)?;
    a.load_x(1, 31, usize::from(L_POSITION))?;
    a.call(assertion)?;
    a.cbnz_w(1, runtime_failure)?;
    if layout.cache_boundary_assertions {
        a.load_w(9, 31, usize::from(L_ASSERT_CACHE_BIT))?;
        a.load_w(10, 31, usize::from(L_ASSERT_CACHE_KNOWN))?;
        a.orr_w(10, 10, 9)?;
        a.store_w(10, 31, usize::from(L_ASSERT_CACHE_KNOWN))?;
        a.cbz_w(0, cached_assertion_false)?;
        a.load_w(10, 31, usize::from(L_ASSERT_CACHE_ENABLED))?;
        a.orr_w(10, 10, 9)?;
        a.store_w(10, 31, usize::from(L_ASSERT_CACHE_ENABLED))?;
        a.branch(split_assertion_passed)?;
    }
    a.asm.bind(cached_assertion_false)?;
    a.cbz_w(0, split_next)?;
    a.asm.bind(split_assertion_passed)?;
    a.load_w(8, 31, usize::from(L_EDGE_INDEX))?;
    load_table_word(&mut a, 9, 8, layout.edge_targets_offset)?;
    cmp_w_value(&mut a, 9, u32::try_from(layout.state_count).unwrap())?;
    a.branch_cond(AARCH64_HS, runtime_failure)?;
    a.load_x(10, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
    compare_x_usize(&mut a, 10, layout.closure_slots)?;
    a.branch_cond(AARCH64_HS, runtime_failure)?;
    thread_address(&mut a, 11, 28, 10)?;
    a.load_x(12, 31, usize::from(L_THREAD_START))?;
    store_thread(&mut a, 11, 9, 12)?;
    a.add_x_imm(10, 10, 1)?;
    a.store_x(10, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
    a.branch(split_next)?;

    a.asm.bind(expand_pop)?;
    a.load_x(8, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
    a.cbz_x(8, root_complete)?;
    a.sub_x_imm(8, 8, 1)?;
    a.store_x(8, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
    thread_address(&mut a, 9, 28, 8)?;
    a.load_w(10, 9, 0)?;
    a.store_x(10, 31, usize::from(L_THREAD_STATE))?;
    a.load_w(10, 9, 4)?;
    a.cbnz_w(10, runtime_failure)?;
    a.load_x(10, 9, 8)?;
    a.store_x(10, 31, usize::from(L_THREAD_START))?;
    a.branch(expand_loop)?;

    a.asm.bind(root_complete)?;
    a.load_x(8, 31, usize::from(L_ROOT_MODE))?;
    a.cbnz_x(8, after_roots)?;
    a.branch(next_old_root)?;

    if let (Some(program), Some(labels)) = (start_program, start_labels.as_deref()) {
        emit_static_start_closure(
            &mut a,
            image,
            program,
            labels,
            assertion,
            after_roots,
            runtime_failure,
        )?;
    }

    a.asm.bind(after_roots)?;
    a.load_x(8, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET)?;
    a.cbnz_x(8, has_current)?;
    a.load_w(9, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET)?;
    a.cbnz_w(9, finish)?;
    a.load_x(9, 31, usize::from(L_POSITION))?;
    a.cmp_x(9, 22)?;
    a.branch_cond(
        if layout.start_prefix.is_some() {
            AARCH64_HS
        } else {
            AARCH64_EQ
        },
        finish,
    )?;
    if let Some(prefix) = layout.start_prefix {
        let scan_next = a.asm.label()?;
        let scan_hit = a.asm.label()?;
        a.asm.bind(scan_next)?;
        a.add_x_imm(9, 9, 1)?;
        a.cmp_x(9, 22)?;
        a.branch_cond(AARCH64_HS, finish)?;
        a.i(aarch64_load_byte_reg(8, 20, 9))?;
        emit_start_prefix_membership(&mut a, prefix, 8, scan_hit, scan_next)?;
        a.asm.bind(scan_hit)?;
        a.store_x(9, 31, usize::from(L_POSITION))?;
        a.branch(boundary)?;
    }
    a.asm.bind(has_current)?;
    a.load_x(9, 31, usize::from(L_POSITION))?;
    a.cmp_x(9, 22)?;
    a.branch_cond(
        if layout.start_prefix.is_some() {
            AARCH64_HS
        } else {
            AARCH64_EQ
        },
        finish,
    )?;
    a.branch(consume_start)?;

    a.asm.bind(consume_start)?;
    a.load_x(8, 31, usize::from(L_POSITION))?;
    a.i(aarch64_load_byte_reg(9, 20, 8))?;
    a.store_x(9, 31, usize::from(L_BYTE))?;
    a.store_x(31, 31, usize::from(L_CURRENT_INDEX))?;

    a.asm.bind(consume_thread)?;
    a.load_x(8, 31, usize::from(L_CURRENT_INDEX))?;
    a.load_x(9, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET)?;
    a.cmp_x(8, 9)?;
    a.branch_cond(AARCH64_HS, consumed_boundary)?;
    thread_address(&mut a, 10, 26, 8)?;
    a.load_w(11, 10, 0)?;
    a.store_x(11, 31, usize::from(L_THREAD_STATE))?;
    a.load_w(11, 10, 4)?;
    a.cbnz_w(11, runtime_failure)?;
    a.load_x(11, 10, 8)?;
    a.store_x(11, 31, usize::from(L_THREAD_START))?;
    a.load_w(8, 31, usize::from(L_THREAD_STATE))?;
    cmp_w_value(&mut a, 8, u32::try_from(layout.state_count).unwrap())?;
    a.branch_cond(AARCH64_HS, runtime_failure)?;
    if let Some(dispatch) = layout.ordered_edge_dispatch {
        let scalar_setup = a.asm.label()?;
        let nonfinal_segment = a.asm.label()?;
        let final_nonlast_row = a.asm.label()?;
        let have_end = a.asm.label()?;
        let transition_loop = a.asm.label()?;
        let transition_done = a.asm.label()?;

        // Load the packed row pair with one scaled state lookup. Only the
        // exact absent sentinel selects the incumbent scalar row scan.
        materialize_table_base(&mut a, 16, dispatch.rows_offset)?;
        a.i(aarch64_load_x_lsl3(9, 16, 8))?;
        cmp_w_value(&mut a, 9, u32::MAX)?;
        a.branch_cond(AARCH64_EQ, scalar_setup)?;
        a.i(aarch64_lsr_x_imm(10, 9, 32))?;
        a.i(aarch64_and_low_w(9, 9, 24))?;
        a.cbz_w(9, runtime_failure)?;
        a.i(aarch64_and_low_w(11, 10, 24))?;
        cmp_w_value(
            &mut a,
            11,
            u32::try_from(dispatch.admitted_rows).unwrap(),
        )?;
        a.branch_cond(AARCH64_HS, runtime_failure)?;
        a.i(aarch64_lsr_w_imm(12, 10, 24))?;

        // row*256 + byte selects the exact local segment.
        a.mov_w(13, 11)?;
        a.lsl_w_imm(14, 11, 8)?;
        a.load_w(15, 31, usize::from(L_BYTE))?;
        a.add_x(14, 14, 15)?;
        materialize_table_base(&mut a, 16, dispatch.byte_map_offset)?;
        a.i(aarch64_load_byte_reg(15, 16, 14))?;
        a.cmp_w(15, 12)?;
        a.branch_cond(AARCH64_HI, runtime_failure)?;
        a.add_x(9, 9, 15)?;
        compare_x_usize(&mut a, 9, dispatch.metadata_count)?;
        a.branch_cond(AARCH64_HS, runtime_failure)?;
        load_table_word(&mut a, 8, 9, dispatch.metadata_offset)?;
        a.cmp_w(15, 12)?;
        a.branch_cond(AARCH64_LO, nonfinal_segment)?;
        a.add_w_imm(13, 13, 1)?;
        cmp_w_value(
            &mut a,
            13,
            u32::try_from(dispatch.admitted_rows).unwrap(),
        )?;
        a.branch_cond(AARCH64_LO, final_nonlast_row)?;
        a.constant32(10, u32::try_from(dispatch.transition_count).unwrap())?;
        a.branch(have_end)?;

        a.asm.bind(nonfinal_segment)?;
        a.add_x_imm(9, 9, 1)?;
        compare_x_usize(&mut a, 9, dispatch.metadata_count)?;
        a.branch_cond(AARCH64_HS, runtime_failure)?;
        load_table_word(&mut a, 10, 9, dispatch.metadata_offset)?;
        a.branch(have_end)?;

        a.asm.bind(final_nonlast_row)?;
        a.add_x_imm(9, 9, 2)?;
        compare_x_usize(&mut a, 9, dispatch.metadata_count)?;
        a.branch_cond(AARCH64_HS, runtime_failure)?;
        load_table_word(&mut a, 10, 9, dispatch.metadata_offset)?;

        a.asm.bind(have_end)?;
        a.cmp_w(8, 10)?;
        a.branch_cond(AARCH64_HI, runtime_failure)?;
        cmp_w_value(
            &mut a,
            10,
            u32::try_from(dispatch.transition_count).unwrap(),
        )?;
        a.branch_cond(AARCH64_HI, runtime_failure)?;
        a.cmp_w(8, 10)?;
        a.branch_cond(AARCH64_EQ, consume_next_thread)?;
        a.load_x(11, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET)?;
        a.sub_x(9, 10, 8)?;
        a.add_x(9, 9, 11)?;
        compare_x_usize(&mut a, 9, layout.edge_count)?;
        a.branch_cond(AARCH64_HI, runtime_failure)?;
        materialize_table_base(&mut a, 15, dispatch.transitions_offset)?;

        a.asm.bind(transition_loop)?;
        a.cmp_x(8, 10)?;
        a.branch_cond(AARCH64_HS, transition_done)?;
        match dispatch.encoding {
            crate::ordered_nfa_native::NativeOrderedEdgeEncoding::Direct32 { target_bits } => {
                a.i(aarch64_load_w_uxtw(12, 15, 8))?;
                if target_bits == 0 {
                    a.constant32(12, 0)?;
                } else {
                    a.i(aarch64_and_low_w(
                        12,
                        12,
                        u8::try_from(target_bits).unwrap(),
                    ))?;
                }
            }
            crate::ordered_nfa_native::NativeOrderedEdgeEncoding::Direct64 => {
                a.i(aarch64_load_x_lsl3(12, 15, 8))?;
            }
            crate::ordered_nfa_native::NativeOrderedEdgeEncoding::Legacy => {
                a.i(aarch64_load_w_uxtw(12, 15, 8))?;
                cmp_w_value(&mut a, 12, u32::try_from(layout.edge_count).unwrap())?;
                a.branch_cond(AARCH64_HS, runtime_failure)?;
                load_table_word(&mut a, 12, 12, layout.edge_targets_offset)?;
            }
        }
        cmp_w_value(&mut a, 12, u32::try_from(layout.state_count).unwrap())?;
        a.branch_cond(AARCH64_HS, runtime_failure)?;
        thread_address(&mut a, 13, 27, 11)?;
        a.load_x(14, 31, usize::from(L_THREAD_START))?;
        store_thread(&mut a, 13, 12, 14)?;
        a.add_x_imm(11, 11, 1)?;
        a.add_x_imm(8, 8, 1)?;
        a.branch(transition_loop)?;

        a.asm.bind(transition_done)?;
        a.store_x(11, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET)?;
        a.branch(consume_next_thread)?;
        a.asm.bind(scalar_setup)?;
    }
    load_table_word(&mut a, 9, 8, layout.edge_offsets_offset)?;
    a.add_w_imm(10, 8, 1)?;
    load_table_word(&mut a, 10, 10, layout.edge_offsets_offset)?;
    a.cmp_w(9, 10)?;
    a.branch_cond(AARCH64_HI, runtime_failure)?;
    cmp_w_value(&mut a, 10, u32::try_from(layout.edge_count).unwrap())?;
    a.branch_cond(AARCH64_HI, runtime_failure)?;
    a.store_x(9, 31, usize::from(L_EDGE_INDEX))?;
    a.store_x(10, 31, usize::from(L_EDGE_END))?;

    a.asm.bind(consume_edge)?;
    a.load_x(8, 31, usize::from(L_EDGE_INDEX))?;
    a.load_x(9, 31, usize::from(L_EDGE_END))?;
    a.cmp_x(8, 9)?;
    a.branch_cond(AARCH64_HS, consume_next_thread)?;
    load_table_byte(&mut a, 9, 8, layout.edge_kinds_offset)?;
    a.cmp_w_imm(9, EDGE_BYTE_RANGE.into())?;
    a.branch_cond(AARCH64_NE, runtime_failure)?;
    a.load_w(9, 31, usize::from(L_BYTE))?;
    load_table_byte(&mut a, 10, 8, layout.byte_starts_offset)?;
    a.cmp_w(9, 10)?;
    a.branch_cond(AARCH64_LO, consume_next_edge)?;
    load_table_byte(&mut a, 10, 8, layout.byte_ends_offset)?;
    a.cmp_w(9, 10)?;
    a.branch_cond(AARCH64_HI, consume_next_edge)?;
    load_table_word(&mut a, 9, 8, layout.edge_targets_offset)?;
    cmp_w_value(&mut a, 9, u32::try_from(layout.state_count).unwrap())?;
    a.branch_cond(AARCH64_HS, runtime_failure)?;
    a.load_x(10, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET)?;
    compare_x_usize(&mut a, 10, layout.edge_count)?;
    a.branch_cond(AARCH64_HS, runtime_failure)?;
    thread_address(&mut a, 11, 27, 10)?;
    a.load_x(12, 31, usize::from(L_THREAD_START))?;
    store_thread(&mut a, 11, 9, 12)?;
    a.add_x_imm(10, 10, 1)?;
    a.store_x(10, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET)?;

    a.asm.bind(consume_next_edge)?;
    a.load_x(8, 31, usize::from(L_EDGE_INDEX))?;
    a.add_x_imm(8, 8, 1)?;
    a.store_x(8, 31, usize::from(L_EDGE_INDEX))?;
    a.branch(consume_edge)?;

    a.asm.bind(consume_next_thread)?;
    a.load_x(8, 31, usize::from(L_CURRENT_INDEX))?;
    a.add_x_imm(8, 8, 1)?;
    a.store_x(8, 31, usize::from(L_CURRENT_INDEX))?;
    a.branch(consume_thread)?;

    a.asm.bind(consumed_boundary)?;
    a.load_x(8, 31, usize::from(L_POSITION))?;
    a.add_x_imm(8, 8, 1)?;
    a.store_x(8, 31, usize::from(L_POSITION))?;
    a.branch(boundary)?;

    a.asm.bind(finish)?;
    a.load_w(8, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET)?;
    a.cbz_w(8, no_match)?;
    a.load_x(8, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_START_OFFSET)?;
    a.store_x(8, 23, 0)?;
    a.load_x(8, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_END_OFFSET)?;
    a.store_x(8, 23, 8)?;
    a.branch(matched)
}

/// Emit the AArch64 AAPCS64 private/public V15 one-Span search entry.
pub(super) fn lower_aarch64(
    image: &NativeOrderedNfaObjectImage<'_>,
) -> Result<Aarch64OrderedNfaNativeEntry, ObjectError> {
    let layout = image.layout;
    let expected_scratch_bytes = scratch_bytes(layout)?;
    let mut asm = Aarch64Assembler::new();
    let invalid_argument = asm.label()?;
    let invalid_handle = asm.label()?;
    let runtime_failure = asm.label()?;
    let no_match = asm.label()?;
    let matched = asm.label()?;
    let shared_auth = asm.label()?;
    let public_fallback = asm.label()?;
    let private_entry = asm.label()?;
    let bulk_gate_entry = asm.label()?;
    let bulk_gate_claimed = asm.label()?;
    let bulk_gate_legacy = asm.label()?;
    let clear_generation = asm.label()?;
    let clear_generation_loop = asm.label()?;
    let clear_generation_store = asm.label()?;
    let after_generation_clear = asm.label()?;
    let search_entry = asm.label()?;
    let terminal_scan = if layout.terminal_range.is_some() {
        Some(asm.label()?)
    } else {
        None
    };
    let assertion = asm.label()?;
    let unicode_helpers = if layout.unicode_ranges_offset.is_some() {
        Some((asm.label()?, asm.label()?, asm.label()?, asm.label()?))
    } else {
        None
    };

    let public_table = emit_prologue_and_raw_checks(&mut asm, invalid_argument, invalid_handle)?;
    {
        let mut a = A { asm: &mut asm };
        emit_exact_object_auth(&mut a, layout, runtime_failure)?;
        emit_common_header_identity_auth(&mut a, runtime_failure)?;
        emit_v15_claim_classifier(&mut a, shared_auth, public_fallback)?;
    }

    asm.bind(private_entry)?;
    let private_table = emit_prologue_and_raw_checks(&mut asm, invalid_argument, invalid_handle)?;
    {
        let mut a = A { asm: &mut asm };
        a.branch(shared_auth)?;
    }

    asm.bind(bulk_gate_entry)?;
    let bulk_gate_table = emit_bulk_gate_prologue(&mut asm, invalid_handle)?;
    {
        let mut a = A { asm: &mut asm };
        emit_exact_object_auth(&mut a, layout, runtime_failure)?;
        emit_common_header_identity_auth(&mut a, runtime_failure)?;
        emit_v15_claim_classifier(&mut a, bulk_gate_claimed, bulk_gate_legacy)?;
    }
    asm.bind(bulk_gate_claimed)?;
    {
        let mut a = A { asm: &mut asm };
        emit_exact_header_auth(&mut a, layout, expected_scratch_bytes, runtime_failure)?;
        a.load_x(8, 19, FROZEN_PREPARED_HEADER_V1_FORWARD_ROWS_ADDRESS_OFFSET)?;
        a.mov_x(19, 8)?;
        a.store_x(19, 31, usize::from(L_SCRATCH))?;
        emit_exact_scratch_auth(&mut a, layout, expected_scratch_bytes, runtime_failure)?;
        a.branch(matched)?;
    }
    asm.bind(bulk_gate_legacy)?;
    {
        let mut a = A { asm: &mut asm };
        emit_return(&mut a, STATUS_NO_MATCH)?;
    }

    asm.bind(shared_auth)?;
    {
        let mut a = A { asm: &mut asm };
        emit_exact_object_auth(&mut a, layout, runtime_failure)?;
        emit_exact_header_auth(&mut a, layout, expected_scratch_bytes, runtime_failure)?;
        a.load_x(8, 19, FROZEN_PREPARED_HEADER_V1_FORWARD_ROWS_ADDRESS_OFFSET)?;
        a.mov_x(19, 8)?;
        a.store_x(19, 31, usize::from(L_SCRATCH))?;
        emit_exact_scratch_auth(&mut a, layout, expected_scratch_bytes, runtime_failure)?;

        // Prove that every generation increment for this invocation fits
        // before reading source or mutating scratch. Overflow is repaired by
        // clearing the authenticated seen generation vector and storing zero.
        a.load_x(8, 31, usize::from(L_POSITION))?;
        a.sub_x(9, 22, 8)?;
        a.add_x_imm(9, 9, 1)?;
        a.constant64(10, u64::MAX)?;
        a.sub_x(10, 10, 9)?;
        a.load_x(11, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET)?;
        a.cmp_x(11, 10)?;
        a.branch_cond(AARCH64_HI, clear_generation)?;
        a.branch(after_generation_clear)?;
    }

    asm.bind(public_fallback)?;
    let fallback_branch = {
        let mut a = A { asm: &mut asm };
        for (register, local) in [
            (0, L_HEADER),
            (1, L_HAY),
            (2, L_LEN),
            (3, L_POSITION),
            (4, L_END),
            (5, L_RESULT),
        ] {
            a.load_x(register, 31, usize::from(local))?;
        }
        emit_epilogue(&mut a)?;
        a.raw(0x1400_0000)?
    };

    asm.bind(clear_generation)?;
    {
        let mut a = A { asm: &mut asm };
        a.constant32(8, 0)?;
    }
    asm.bind(clear_generation_loop)?;
    {
        let mut a = A { asm: &mut asm };
        compare_x_usize(&mut a, 8, layout.state_count)?;
        a.branch_cond(AARCH64_HS, clear_generation_store)?;
        a.i(aarch64_add_x_lsl(9, 25, 8, 3))?;
        a.store_x(31, 9, 0)?;
        a.add_x_imm(8, 8, 1)?;
        a.branch(clear_generation_loop)?;
    }
    asm.bind(clear_generation_store)?;
    {
        let mut a = A { asm: &mut asm };
        a.store_x(31, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET)?;
        a.branch(after_generation_clear)?;
    }
    asm.bind(after_generation_clear)?;
    {
        let mut a = A { asm: &mut asm };
        for offset in [
            FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
            FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET,
            FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET,
            FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_START_OFFSET,
            FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_END_OFFSET,
        ] {
            a.store_x(31, 19, offset)?;
        }
        a.store_w(31, 19, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET)?;
        if let Some(scan) = terminal_scan {
            a.mov_x(8, 22)?;
            a.branch(scan)?;
        } else {
            a.branch(search_entry)?;
        }
    }

    if let (Some(scan), Some(range)) = (terminal_scan, layout.terminal_range) {
        asm.bind(scan)?;
        let mut a = A { asm: &mut asm };
        a.load_x(9, 31, usize::from(L_POSITION))?;
        a.cmp_x(8, 9)?;
        a.branch_cond(AARCH64_LS, no_match)?;
        a.sub_x_imm(8, 8, 1)?;
        a.i(aarch64_load_byte_reg(10, 20, 8))?;
        a.cmp_w_imm(10, u16::from(range.start))?;
        a.branch_cond(AARCH64_LO, scan)?;
        a.cmp_w_imm(10, u16::from(range.end))?;
        a.branch_cond(AARCH64_HI, scan)?;
        a.add_x_imm(22, 8, 1)?;
        a.branch(search_entry)?;
    }

    asm.bind(search_entry)?;
    emit_semantic_body(
        &mut asm,
        image,
        assertion,
        no_match,
        matched,
        runtime_failure,
    )?;
    asm.bind(no_match)?;
    {
        let mut a = A { asm: &mut asm };
        a.store_x(31, 23, 0)?;
        a.store_x(31, 23, 8)?;
        emit_return(&mut a, STATUS_NO_MATCH)?;
    }
    asm.bind(matched)?;
    {
        let mut a = A { asm: &mut asm };
        emit_return(&mut a, STATUS_MATCH)?;
    }
    asm.bind(invalid_argument)?;
    {
        let mut a = A { asm: &mut asm };
        emit_return(&mut a, STATUS_INVALID_ARGUMENT)?;
    }
    asm.bind(invalid_handle)?;
    {
        let mut a = A { asm: &mut asm };
        emit_return(&mut a, STATUS_INVALID_HANDLE)?;
    }
    asm.bind(runtime_failure)?;
    {
        let mut a = A { asm: &mut asm };
        emit_return(&mut a, STATUS_RUNTIME_FAILURE)?;
    }
    let (unicode_left, unicode_right) = unicode_helpers
        .map(|(_, _, left, right)| (Some(left), Some(right)))
        .unwrap_or((None, None));
    emit_assertion(&mut asm, assertion, layout, unicode_left, unicode_right)?;
    if let Some((decode, member, left, right)) = unicode_helpers {
        emit_unicode_classifiers(&mut asm, left, right, decode, member)?;
        emit_decode_scalar(&mut asm, decode)?;
        emit_unicode_member(&mut asm, member, layout)?;
    }

    let private_offset =
        asm.labels
            .get(private_entry)
            .copied()
            .flatten()
            .ok_or(ObjectError::InvalidModule(
                "AArch64 Ordered-NFA private entry is unbound",
            ))?;
    let bulk_gate_offset =
        asm.labels
            .get(bulk_gate_entry)
            .copied()
            .flatten()
            .ok_or(ObjectError::InvalidModule(
                "AArch64 Ordered-NFA bulk gate entry is unbound",
            ))?;
    let mut offsets = [
        public_table[0],
        public_table[1],
        private_table[0],
        private_table[1],
        bulk_gate_table[0],
        bulk_gate_table[1],
        fallback_branch,
        private_offset,
        bulk_gate_offset,
    ];
    let code = asm.finish_with_offsets(&mut offsets)?;
    let [public_page, public_page_offset, private_page, private_page_offset, bulk_gate_page, bulk_gate_page_offset, fallback, private_entry_offset, bulk_gate_entry_offset] =
        offsets;
    let relocation = |offset: usize,
                      kind: RelocationKind,
                      symbol: usize,
                      context: &'static str|
     -> Result<ModuleRelocation, ObjectError> {
        Ok(ModuleRelocation {
            section: TEXT_SECTION,
            offset: u64::try_from(offset).map_err(|_| ObjectError::ArithmeticOverflow(context))?,
            kind,
            symbol,
            addend: 0,
        })
    };
    Ok(Aarch64OrderedNfaNativeEntry {
        code,
        relocations: vec![
            relocation(
                public_page,
                RelocationKind::Aarch64Page21,
                PARTIAL_TABLE_SYMBOL,
                "AArch64 Ordered-NFA public table ADRP",
            )?,
            relocation(
                public_page_offset,
                RelocationKind::Aarch64PageOff12,
                PARTIAL_TABLE_SYMBOL,
                "AArch64 Ordered-NFA public table ADD",
            )?,
            relocation(
                private_page,
                RelocationKind::Aarch64Page21,
                PARTIAL_TABLE_SYMBOL,
                "AArch64 Ordered-NFA private table ADRP",
            )?,
            relocation(
                private_page_offset,
                RelocationKind::Aarch64PageOff12,
                PARTIAL_TABLE_SYMBOL,
                "AArch64 Ordered-NFA private table ADD",
            )?,
            relocation(
                bulk_gate_page,
                RelocationKind::Aarch64Page21,
                PARTIAL_TABLE_SYMBOL,
                "AArch64 Ordered-NFA bulk-gate table ADRP",
            )?,
            relocation(
                bulk_gate_page_offset,
                RelocationKind::Aarch64PageOff12,
                PARTIAL_TABLE_SYMBOL,
                "AArch64 Ordered-NFA bulk-gate table ADD",
            )?,
            relocation(
                fallback,
                RelocationKind::Aarch64Branch26,
                PREPARED_FALLBACK_RUNTIME_SYMBOL,
                "AArch64 Ordered-NFA fallback branch",
            )?,
        ],
        private_entry_offset,
        bulk_gate_entry_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn optimizing_ordered_nfa(pattern: &str) -> crate::CompiledProgram {
        let parsed = fre_syntax::parse(fre_syntax::ParseRequest::rust(
            pattern.to_owned(),
            fre_syntax::CompatibilityProfile::RustBytes(fre_syntax::RustProfile::default()),
        ))
        .unwrap();
        let fre_syntax::CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("Rust request returned a non-Rust pattern");
        };
        let raw = fre_lower::lower_raw(
            &parsed,
            fre_lower::OperationSemantics::CaptureFree,
            fre_lower::LowerLimits::default(),
        )
        .unwrap()
        .into_plan();
        let automaton = fre_automata::Automaton::from_raw(
            raw.clone(),
            fre_automata::CompileLimits::default(),
        )
        .unwrap();
        crate::CompiledProgram::build(
            raw,
            automaton,
            crate::OutputContract::Span,
            crate::CompileMode::Optimizing,
            crate::DeterminizeLimits {
                max_states: 0,
                ..crate::DeterminizeLimits::default()
            },
            usize::MAX,
        )
        .unwrap()
    }

    fn minimal_image() -> NativeOrderedNfaObjectImage<'static> {
        NativeOrderedNfaObjectImage {
            bytes: vec![0; 144],
            layout: NativeOrderedNfaObjectLayout {
                object_bytes: 144,
                roles_offset: 128,
                edge_offsets_offset: 132,
                edge_targets_offset: 140,
                edge_kinds_offset: 140,
                byte_starts_offset: 140,
                byte_ends_offset: 140,
                unicode_ranges_offset: None,
                unicode_range_count: 0,
                state_count: 1,
                edge_count: 0,
                zero_width_edge_count: 0,
                closure_slots: 1,
                start_state: 0,
                assertion_kinds: 0,
                cache_boundary_assertions: false,
                start_closure_dispatch: None,
                start_prefix: None,
                line_terminator: b'\n',
                ordered_edge_dispatch: None,
                terminal_range: None,
            },
            start_closure_program: None,
        }
    }

    fn terminal_range_image() -> NativeOrderedNfaObjectImage<'static> {
        let mut image = minimal_image();
        image.layout.terminal_range = Some(
            crate::ordered_nfa_native::NativeOrderedNfaTerminalRangeV1 {
                start: 0x80,
                end: 0xff,
                reverse_depth: 0,
            },
        );
        image
    }

    fn cached_assertion_image() -> NativeOrderedNfaObjectImage<'static> {
        let mut image = minimal_image();
        image.layout.assertion_kinds =
            (1 << (EDGE_END_TEXT - EDGE_START_TEXT)) | (1 << (EDGE_WORD_ASCII - EDGE_START_TEXT));
        image.layout.cache_boundary_assertions = true;
        image
    }

    fn instruction(code: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(code[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn ordered_nfa_aarch64_unrolls_only_the_selected_start_closure() {
        let program = optimizing_ordered_nfa(r"(?:a?|bc)");
        let view = program.native_ordered_nfa_view().unwrap();
        let selected = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        let receipt = selected.layout.start_closure_dispatch.unwrap();
        assert!(!receipt.guarded);
        assert!(receipt.instruction_count > 1);
        let scalar = NativeOrderedNfaObjectImage::try_build(
            crate::ordered_nfa_native::NativeOrderedNfaProgramView {
                start_closure_dispatch: None,
                ..view
            },
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.bytes, scalar.bytes);
        let selected_entry = lower_aarch64(&selected).unwrap();
        let scalar_entry = lower_aarch64(&scalar).unwrap();
        assert!(selected_entry.code.len() > scalar_entry.code.len());
        assert_eq!(selected_entry.relocations, scalar_entry.relocations);
    }

    #[test]
    fn ordered_nfa_aarch64_emits_only_the_selected_start_prefix_fast_forward() {
        let program = optimizing_ordered_nfa(r"a?b?c?d?e?f?g?h?[a-z]x");
        let view = program.native_ordered_nfa_view().unwrap();
        let selected = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        let prefix = selected.layout.start_prefix.unwrap();
        assert_eq!(
            prefix
                .ranges()
                .iter()
                .map(|range| (range.start, range.end))
                .collect::<Vec<_>>(),
            [(b'a', b'z')]
        );
        let scalar = NativeOrderedNfaObjectImage::try_build(
            crate::ordered_nfa_native::NativeOrderedNfaProgramView {
                start_prefix_first_set: None,
                ..view
            },
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        assert!(scalar.layout.start_prefix.is_none());
        assert_eq!(selected.bytes, scalar.bytes);
        let selected_entry = lower_aarch64(&selected).unwrap();
        let scalar_entry = lower_aarch64(&scalar).unwrap();
        assert!(selected_entry.code.len() > scalar_entry.code.len());
        assert_eq!(selected_entry.relocations, scalar_entry.relocations);

        let position_load =
            aarch64_load_x_imm(9, 31, L_POSITION).expect("position load encoding");
        let position_cmp = aarch64_cmp_x(9, 22).expect("position compare encoding");
        let end_conditions = |code: &[u8]| {
            let words = code
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            words
                .windows(3)
                .filter_map(|words| {
                    let branch = words[2];
                    if words[0] != position_load
                        || words[1] != position_cmp
                        || branch & 0xff00_0010 != 0x5400_0000
                    {
                        return None;
                    }
                    u8::try_from(branch & 0xf).ok()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(end_conditions(&scalar_entry.code), [AARCH64_EQ, AARCH64_EQ]);
        assert_eq!(end_conditions(&selected_entry.code), [AARCH64_HS, AARCH64_HS]);
    }

    #[test]
    fn ordered_nfa_aarch64_start_prefix_membership_has_hit_and_miss_edges() {
        let program = optimizing_ordered_nfa(r"a?b?c?d?e?f?g?h?[a-z]x");
        let image = NativeOrderedNfaObjectImage::try_build(
            program.native_ordered_nfa_view().unwrap(),
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        let prefix = image.layout.start_prefix.unwrap();
        let mut asm = Aarch64Assembler::new();
        let matched = asm.label().unwrap();
        let missed = asm.label().unwrap();
        emit_start_prefix_membership(&mut A { asm: &mut asm }, prefix, 8, matched, missed)
            .unwrap();

        assert_eq!(asm.fixups.len(), 3);
        assert_eq!(asm.fixups[1].label, matched);
        assert_eq!(asm.fixups[2].label, missed);
        assert_eq!(
            instruction(&asm.code, 0),
            aarch64_cmp_w_imm(8, u16::from(b'a')).unwrap()
        );
        assert_eq!(
            instruction(&asm.code, 8),
            aarch64_cmp_w_imm(8, u16::from(b'z')).unwrap()
        );

        asm.bind(matched).unwrap();
        asm.instruction(0xd65f_03c0).unwrap();
        asm.bind(missed).unwrap();
        asm.instruction(0xd65f_03c0).unwrap();
        assert!(!asm.finish().unwrap().is_empty());
    }

    #[test]
    fn ordered_nfa_aarch64_guarded_split_assertions_are_emitted_in_reverse_row_order() {
        let mut asm = Aarch64Assembler::new();
        let assertion = asm.label().unwrap();
        let failure = asm.label().unwrap();
        emit_static_guarded_split_assertions(
            &mut A { asm: &mut asm },
            &[2, 0, 4, 3],
            0b111,
            assertion,
            failure,
        )
        .unwrap();
        let kinds = asm
            .code
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .filter_map(|word| {
                [2_u32, 3, 4]
                    .into_iter()
                    .find(|kind| word == 0xd280_0000 | (kind << 5))
            })
            .collect::<Vec<_>>();
        assert_eq!(kinds, [3, 4, 2]);
    }

    #[test]
    fn ordered_nfa_aarch64_entry_has_exact_relocation_shape() {
        let entry = lower_aarch64(&minimal_image()).unwrap();
        assert!(!entry.code.is_empty());
        assert!(entry.code.len().is_multiple_of(4));
        assert!(entry.private_entry_offset > 0);
        assert!(entry.private_entry_offset < entry.code.len());
        assert!(entry.private_entry_offset.is_multiple_of(4));
        assert!(entry.bulk_gate_entry_offset > entry.private_entry_offset);
        assert!(entry.bulk_gate_entry_offset < entry.code.len());
        assert!(entry.bulk_gate_entry_offset.is_multiple_of(4));
        let prologue = aarch64_sub_x_imm(31, 31, STACK_BYTES).unwrap();
        assert_eq!(instruction(&entry.code, 0), prologue);
        assert_eq!(
            instruction(&entry.code, entry.private_entry_offset),
            prologue
        );
        assert_eq!(
            instruction(&entry.code, entry.bulk_gate_entry_offset),
            prologue
        );
        assert_eq!(entry.relocations.len(), 7);
        assert_eq!(
            entry
                .relocations
                .iter()
                .map(|relocation| (relocation.kind, relocation.symbol, relocation.addend))
                .collect::<Vec<_>>(),
            vec![
                (RelocationKind::Aarch64Page21, PARTIAL_TABLE_SYMBOL, 0),
                (RelocationKind::Aarch64PageOff12, PARTIAL_TABLE_SYMBOL, 0,),
                (RelocationKind::Aarch64Page21, PARTIAL_TABLE_SYMBOL, 0),
                (RelocationKind::Aarch64PageOff12, PARTIAL_TABLE_SYMBOL, 0,),
                (RelocationKind::Aarch64Page21, PARTIAL_TABLE_SYMBOL, 0),
                (RelocationKind::Aarch64PageOff12, PARTIAL_TABLE_SYMBOL, 0,),
                (
                    RelocationKind::Aarch64Branch26,
                    PREPARED_FALLBACK_RUNTIME_SYMBOL,
                    0,
                ),
            ]
        );
        for relocation in &entry.relocations {
            let offset = usize::try_from(relocation.offset).unwrap();
            assert!(offset.is_multiple_of(4));
            assert!(offset + 4 <= entry.code.len());
            let word = instruction(&entry.code, offset);
            match relocation.kind {
                RelocationKind::Aarch64Page21 => assert_eq!(word, 0x9000_0018),
                RelocationKind::Aarch64PageOff12 => {
                    assert_eq!(word, aarch64_add_x_imm(24, 24, 0).unwrap());
                }
                RelocationKind::Aarch64Branch26 => assert_eq!(word, 0x1400_0000),
                _ => panic!("unexpected Ordered-NFA relocation"),
            }
        }
    }

    #[test]
    fn ordered_nfa_aarch64_caches_repeated_assertions_once_per_boundary() {
        let scalar = lower_aarch64(&minimal_image()).unwrap();
        let cached = lower_aarch64(&cached_assertion_image()).unwrap();
        assert!(cached.code.len() > scalar.code.len());
        let instructions = cached
            .code
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        let reset_known = aarch64_store_w(31, 31, L_ASSERT_CACHE_KNOWN).unwrap();
        let reset_enabled = aarch64_store_w(31, 31, L_ASSERT_CACHE_ENABLED).unwrap();
        let shift_bit = 0x1ac0_2000 | (u32::from(8_u8) << 16) | (u32::from(9_u8) << 5) | 9;
        assert!(instructions.contains(&reset_known));
        assert!(instructions.contains(&reset_enabled));
        assert!(instructions.contains(&shift_bit));
        assert!(instructions.contains(&aarch64_store_w(9, 31, L_ASSERT_CACHE_BIT).unwrap()));
        assert_eq!(cached.relocations, scalar.relocations);
    }

    #[test]
    fn ordered_nfa_aarch64_terminal_range_emits_authenticated_reverse_scan() {
        let scalar = lower_aarch64(&minimal_image()).unwrap();
        let filtered = lower_aarch64(&terminal_range_image()).unwrap();
        assert!(filtered.code.len() > scalar.code.len());
        assert!(filtered
            .code
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
            .any(|word| word == aarch64_load_byte_reg(10, 20, 8).unwrap()));
        for immediate in [0x80_u16, 0xff] {
            let compare = aarch64_cmp_w_imm(10, immediate).unwrap();
            assert!(filtered
                .code
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
                .any(|word| word == compare));
        }
        assert_eq!(
            filtered
                .relocations
                .iter()
                .map(|relocation| (relocation.kind, relocation.symbol, relocation.addend))
                .collect::<Vec<_>>(),
            scalar
                .relocations
                .iter()
                .map(|relocation| (relocation.kind, relocation.symbol, relocation.addend))
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn aarch64_call26_survives_control_flow_optimization_as_bl() {
        let mut asm = Aarch64Assembler::new();
        let callee = asm.label().unwrap();
        let done = asm.label().unwrap();
        let call = asm.code.len();
        asm.call(callee).unwrap();
        asm.branch(done).unwrap();
        asm.bind(callee).unwrap();
        asm.instruction(0xd65f_03c0).unwrap();
        asm.bind(done).unwrap();
        asm.instruction(0xd503_201f).unwrap();
        let mut offsets = [call];
        let code = asm.finish_with_offsets(&mut offsets).unwrap();
        assert_eq!(instruction(&code, offsets[0]) & 0xfc00_0000, 0x9400_0000);
    }

    #[test]
    fn ordered_nfa_aarch64_epsilon_edges_bypass_the_assertion_call() {
        let entry = lower_aarch64(&minimal_image()).unwrap();
        let words = entry
            .code
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        let position_load = aarch64_load_x_imm(1, 31, L_POSITION).unwrap();
        let matches = words
            .windows(5)
            .enumerate()
            .filter_map(|(index, window)| {
                ((window[0] & 0xff00_001f == 0x3400_0000)
                    && window[1] == position_load
                    && (window[2] & 0xfc00_0000 == 0x9400_0000)
                    && (window[3] & 0xff00_001f == 0x3500_0001)
                    && (window[4] & 0xff00_001f == 0x3400_0000))
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "epsilon bypass must be unique");
        let index = matches[0];
        let immediate = (words[index] >> 5) & 0x7ffff;
        let displacement = if immediate & (1 << 18) == 0 {
            isize::try_from(immediate).unwrap()
        } else {
            isize::try_from(immediate).unwrap() - (1 << 19)
        };
        assert_eq!(index.checked_add_signed(displacement).unwrap(), index + 5);
    }
}
