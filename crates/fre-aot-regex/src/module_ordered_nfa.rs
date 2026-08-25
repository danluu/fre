//! Target code for the prepared table-driven Ordered-TNFA iterator.
//!
//! The public and private entry share one exact prepared-search ABI. Every
//! capability, descriptor, pointer, and bound is authenticated before the
//! first haystack byte is read. The generated interpreter then uses only the
//! object-local canonical SoA graph and the exclusive V15 Pike scratch.

use super::{
    push_bytes, ModuleRelocation, ObjectError, RelocationKind, X86Assembler, PARTIAL_TABLE_SYMBOL,
    PREPARED_FALLBACK_RUNTIME_SYMBOL, TEXT_SECTION,
};
use crate::{
    ordered_nfa_native::{
        NativeOrderedNfaObjectImage, NativeOrderedNfaObjectLayout,
        NativeOrderedNfaStartPrefixPlan, WholeWindowWidthBounds,
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
const ROLE_CONSUME: u8 = 1;
const ROLE_ACCEPT: u8 = 2;
const EDGE_EPSILON: u8 = 0;
const EDGE_BYTE_RANGE: u8 = 1;

#[derive(Debug)]
pub(super) struct OrderedNfaNativeEntry {
    pub(super) code: Vec<u8>,
    pub(super) relocations: Vec<ModuleRelocation>,
    pub(super) private_entry_offset: usize,
    /// Handle-only classifier used once by whole-operation wrappers. It
    /// returns 0 for an authenticated legacy handle, 1 for an exact V15
    /// owner, 3 for a claimed malformed owner, and 5 for a null handle. It
    /// never reads source or mutates scratch/output state.
    pub(super) bulk_gate_entry_offset: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OrderedNfaEntrySurface {
    Compatibility,
    OperationOnly,
    #[cfg(test)]
    OperationOnlyReauthenticate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum R {
    Ax = 0,
    Cx = 1,
    Dx = 2,
    Bx = 3,
    Sp = 4,
    Bp = 5,
    Si = 6,
    Di = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl R {
    const fn lo(self) -> u8 {
        self as u8 & 7
    }

    const fn hi(self) -> bool {
        self as u8 >= 8
    }
}

struct X<'a> {
    asm: &'a mut X86Assembler,
}

impl X<'_> {
    fn op(&mut self, bytes: &[u8]) -> Result<(), ObjectError> {
        self.asm.instruction(bytes)?;
        Ok(())
    }

    fn rex(bytes: &mut Vec<u8>, w: bool, r: bool, x: bool, b: bool) {
        let rex = 0x40 | u8::from(w) << 3 | u8::from(r) << 2 | u8::from(x) << 1 | u8::from(b);
        if rex != 0x40 {
            bytes.push(rex);
        }
    }

    fn modrm(bytes: &mut Vec<u8>, mode: u8, reg: u8, rm: u8) {
        bytes.push(mode << 6 | (reg & 7) << 3 | (rm & 7));
    }

    fn mem(bytes: &mut Vec<u8>, reg: R, base: R, disp: i32, w: bool, opcode: &[u8]) {
        Self::rex(bytes, w, reg.hi(), false, base.hi());
        bytes.extend_from_slice(opcode);
        Self::modrm(bytes, 2, reg.lo(), base.lo());
        if base.lo() == R::Sp.lo() {
            bytes.push(0x24);
        }
        bytes.extend_from_slice(&disp.to_le_bytes());
    }

    fn mem_group(bytes: &mut Vec<u8>, group: u8, base: R, disp: i32, w: bool, opcode: u8) {
        Self::rex(bytes, w, false, false, base.hi());
        bytes.push(opcode);
        Self::modrm(bytes, 2, group, base.lo());
        if base.lo() == R::Sp.lo() {
            bytes.push(0x24);
        }
        bytes.extend_from_slice(&disp.to_le_bytes());
    }

    fn indexed(
        bytes: &mut Vec<u8>,
        reg: R,
        base: R,
        index: R,
        scale_log2: u8,
        disp: i32,
        w: bool,
        opcode: &[u8],
    ) {
        Self::rex(bytes, w, reg.hi(), index.hi(), base.hi());
        bytes.extend_from_slice(opcode);
        Self::modrm(bytes, 2, reg.lo(), 4);
        bytes.push((scale_log2 & 3) << 6 | index.lo() << 3 | base.lo());
        bytes.extend_from_slice(&disp.to_le_bytes());
    }

    fn rr(&mut self, opcode: u8, dst: R, src: R, w: bool) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(3);
        Self::rex(&mut bytes, w, src.hi(), false, dst.hi());
        bytes.push(opcode);
        Self::modrm(&mut bytes, 3, src.lo(), dst.lo());
        self.op(&bytes)
    }

    fn mov64(&mut self, dst: R, src: R) -> Result<(), ObjectError> {
        self.rr(0x89, dst, src, true)
    }

    fn mov32(&mut self, dst: R, src: R) -> Result<(), ObjectError> {
        self.rr(0x89, dst, src, false)
    }

    fn xor32(&mut self, dst: R, src: R) -> Result<(), ObjectError> {
        self.rr(0x31, dst, src, false)
    }

    fn cmp64(&mut self, left: R, right: R) -> Result<(), ObjectError> {
        self.rr(0x39, left, right, true)
    }

    fn cmp32(&mut self, left: R, right: R) -> Result<(), ObjectError> {
        self.rr(0x39, left, right, false)
    }

    fn test64(&mut self, left: R, right: R) -> Result<(), ObjectError> {
        self.rr(0x85, left, right, true)
    }

    fn test32(&mut self, left: R, right: R) -> Result<(), ObjectError> {
        self.rr(0x85, left, right, false)
    }

    fn load64(&mut self, dst: R, base: R, disp: usize) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(8);
        Self::mem(&mut bytes, dst, base, i32_disp(disp)?, true, &[0x8b]);
        self.op(&bytes)
    }

    fn load32(&mut self, dst: R, base: R, disp: usize) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(8);
        Self::mem(&mut bytes, dst, base, i32_disp(disp)?, false, &[0x8b]);
        self.op(&bytes)
    }

    fn load8(&mut self, dst: R, base: R, disp: usize) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(9);
        Self::mem(&mut bytes, dst, base, i32_disp(disp)?, false, &[0x0f, 0xb6]);
        self.op(&bytes)
    }

    fn load64_index(
        &mut self,
        dst: R,
        base: R,
        index: R,
        scale: u8,
        disp: usize,
    ) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(9);
        Self::indexed(
            &mut bytes,
            dst,
            base,
            index,
            scale,
            i32_disp(disp)?,
            true,
            &[0x8b],
        );
        self.op(&bytes)
    }

    fn load32_index(
        &mut self,
        dst: R,
        base: R,
        index: R,
        scale: u8,
        disp: usize,
    ) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(9);
        Self::indexed(
            &mut bytes,
            dst,
            base,
            index,
            scale,
            i32_disp(disp)?,
            false,
            &[0x8b],
        );
        self.op(&bytes)
    }

    fn load8_index(&mut self, dst: R, base: R, index: R, disp: usize) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(10);
        Self::indexed(
            &mut bytes,
            dst,
            base,
            index,
            0,
            i32_disp(disp)?,
            false,
            &[0x0f, 0xb6],
        );
        self.op(&bytes)
    }

    fn store64(&mut self, base: R, disp: usize, src: R) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(8);
        Self::mem(&mut bytes, src, base, i32_disp(disp)?, true, &[0x89]);
        self.op(&bytes)
    }

    fn store32(&mut self, base: R, disp: usize, src: R) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(8);
        Self::mem(&mut bytes, src, base, i32_disp(disp)?, false, &[0x89]);
        self.op(&bytes)
    }

    fn store64_index(
        &mut self,
        base: R,
        index: R,
        scale: u8,
        disp: usize,
        src: R,
    ) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(9);
        Self::indexed(
            &mut bytes,
            src,
            base,
            index,
            scale,
            i32_disp(disp)?,
            true,
            &[0x89],
        );
        self.op(&bytes)
    }

    fn store32_index(
        &mut self,
        base: R,
        index: R,
        scale: u8,
        disp: usize,
        src: R,
    ) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(9);
        Self::indexed(
            &mut bytes,
            src,
            base,
            index,
            scale,
            i32_disp(disp)?,
            false,
            &[0x89],
        );
        self.op(&bytes)
    }

    fn imm64(&mut self, dst: R, value: u64) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(10);
        Self::rex(&mut bytes, true, false, false, dst.hi());
        bytes.push(0xb8 + dst.lo());
        bytes.extend_from_slice(&value.to_le_bytes());
        self.op(&bytes)
    }

    fn imm32(&mut self, dst: R, value: u32) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(6);
        Self::rex(&mut bytes, false, false, false, dst.hi());
        bytes.push(0xb8 + dst.lo());
        bytes.extend_from_slice(&value.to_le_bytes());
        self.op(&bytes)
    }

    fn cmp_mem64_value(&mut self, base: R, disp: usize, value: u64) -> Result<(), ObjectError> {
        self.imm64(R::Ax, value)?;
        let mut bytes = Vec::with_capacity(8);
        Self::mem(&mut bytes, R::Ax, base, i32_disp(disp)?, true, &[0x39]);
        self.op(&bytes)
    }

    fn cmp_mem32_value(&mut self, base: R, disp: usize, value: u32) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(11);
        Self::mem_group(&mut bytes, 7, base, i32_disp(disp)?, false, 0x81);
        bytes.extend_from_slice(&value.to_le_bytes());
        self.op(&bytes)
    }

    fn cmp_mem64_zero(&mut self, base: R, disp: usize) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(9);
        Self::mem_group(&mut bytes, 7, base, i32_disp(disp)?, true, 0x83);
        bytes.push(0);
        self.op(&bytes)
    }

    fn cmp_mem32_zero(&mut self, base: R, disp: usize) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(8);
        Self::mem_group(&mut bytes, 7, base, i32_disp(disp)?, false, 0x83);
        bytes.push(0);
        self.op(&bytes)
    }

    fn store_mem64_zero(&mut self, base: R, disp: usize) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(12);
        Self::mem_group(&mut bytes, 0, base, i32_disp(disp)?, true, 0xc7);
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        self.op(&bytes)
    }

    fn store_mem32_value(&mut self, base: R, disp: usize, value: u32) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(12);
        Self::mem_group(&mut bytes, 0, base, i32_disp(disp)?, false, 0xc7);
        bytes.extend_from_slice(&value.to_le_bytes());
        self.op(&bytes)
    }

    fn add64(&mut self, dst: R, src: R) -> Result<(), ObjectError> {
        self.rr(0x01, dst, src, true)
    }

    fn add32(&mut self, dst: R, src: R) -> Result<(), ObjectError> {
        self.rr(0x01, dst, src, false)
    }

    fn sub64(&mut self, dst: R, src: R) -> Result<(), ObjectError> {
        self.rr(0x29, dst, src, true)
    }

    fn inc64(&mut self, reg: R) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(4);
        Self::rex(&mut bytes, true, false, false, reg.hi());
        bytes.push(0xff);
        Self::modrm(&mut bytes, 3, 0, reg.lo());
        self.op(&bytes)
    }

    fn dec64(&mut self, reg: R) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(4);
        Self::rex(&mut bytes, true, false, false, reg.hi());
        bytes.push(0xff);
        Self::modrm(&mut bytes, 3, 1, reg.lo());
        self.op(&bytes)
    }

    fn cmp64_imm(&mut self, reg: R, value: u32) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(8);
        Self::rex(&mut bytes, true, false, false, reg.hi());
        bytes.push(0x81);
        Self::modrm(&mut bytes, 3, 7, reg.lo());
        bytes.extend_from_slice(&value.to_le_bytes());
        self.op(&bytes)
    }

    fn cmp32_imm(&mut self, reg: R, value: u32) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(8);
        Self::rex(&mut bytes, false, false, false, reg.hi());
        bytes.push(0x81);
        Self::modrm(&mut bytes, 3, 7, reg.lo());
        bytes.extend_from_slice(&value.to_le_bytes());
        self.op(&bytes)
    }

    fn shl32_imm(&mut self, reg: R, count: u8) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(5);
        Self::rex(&mut bytes, false, false, false, reg.hi());
        bytes.push(0xc1);
        Self::modrm(&mut bytes, 3, 4, reg.lo());
        bytes.push(count);
        self.op(&bytes)
    }

    fn shl32_cl(&mut self, reg: R) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(3);
        Self::rex(&mut bytes, false, false, false, reg.hi());
        bytes.push(0xd3);
        Self::modrm(&mut bytes, 3, 4, reg.lo());
        self.op(&bytes)
    }

    fn shl64_imm(&mut self, reg: R, count: u8) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(5);
        Self::rex(&mut bytes, true, false, false, reg.hi());
        bytes.push(0xc1);
        Self::modrm(&mut bytes, 3, 4, reg.lo());
        bytes.push(count);
        self.op(&bytes)
    }

    fn shr32_imm(&mut self, reg: R, count: u8) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(5);
        Self::rex(&mut bytes, false, false, false, reg.hi());
        bytes.push(0xc1);
        Self::modrm(&mut bytes, 3, 5, reg.lo());
        bytes.push(count);
        self.op(&bytes)
    }

    fn and32_imm(&mut self, reg: R, value: u32) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(8);
        Self::rex(&mut bytes, false, false, false, reg.hi());
        bytes.push(0x81);
        Self::modrm(&mut bytes, 3, 4, reg.lo());
        bytes.extend_from_slice(&value.to_le_bytes());
        self.op(&bytes)
    }

    fn or32(&mut self, dst: R, src: R) -> Result<(), ObjectError> {
        self.rr(0x09, dst, src, false)
    }

    fn setcc32(&mut self, reg: R, condition: u8) -> Result<(), ObjectError> {
        let mut bytes = Vec::with_capacity(5);
        // A REX prefix is mandatory for r8b..r15b and for spl/bpl/sil/dil.
        let needs_rex = reg.hi() || reg.lo() >= 4;
        if needs_rex {
            bytes.push(0x40 | u8::from(reg.hi()));
        }
        bytes.extend_from_slice(&[0x0f, 0x90 | (condition & 0x0f)]);
        Self::modrm(&mut bytes, 3, 0, reg.lo());
        if needs_rex {
            bytes.push(0x40 | u8::from(reg.hi()) << 2 | u8::from(reg.hi()));
        }
        bytes.extend_from_slice(&[0x0f, 0xb6]);
        Self::modrm(&mut bytes, 3, reg.lo(), reg.lo());
        self.op(&bytes)
    }

    fn branch(&mut self, condition: u8, label: usize) -> Result<(), ObjectError> {
        self.asm.branch(&[0x0f, condition], label)
    }

    fn jump(&mut self, label: usize) -> Result<(), ObjectError> {
        self.asm.branch(&[0xe9], label)
    }

    fn call(&mut self, label: usize) -> Result<(), ObjectError> {
        self.asm.branch(&[0xe8], label)
    }
}

fn i32_disp(offset: usize) -> Result<i32, ObjectError> {
    i32::try_from(offset)
        .map_err(|_| ObjectError::ArithmeticOverflow("x86 Ordered-NFA displacement"))
}

fn scratch_bytes(layout: NativeOrderedNfaObjectLayout) -> Result<usize, ObjectError> {
    FROZEN_ORDERED_NFA_SCRATCH_V1_BYTES
        .checked_add(
            layout
                .state_count
                .checked_mul(24)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "Ordered-NFA state scratch bytes",
                ))?,
        )
        .and_then(|bytes| bytes.checked_add(layout.edge_count.checked_mul(16)?))
        .and_then(|bytes| bytes.checked_add(layout.closure_slots.checked_mul(16)?))
        .ok_or(ObjectError::ArithmeticOverflow("Ordered-NFA scratch bytes"))
}

fn branch_not_equal(x: &mut X<'_>, invalid: usize) -> Result<(), ObjectError> {
    x.branch(0x85, invalid)
}

fn compare_identity(
    x: &mut X<'_>,
    left: R,
    left_offset: usize,
    right: R,
    right_offset: usize,
    invalid: usize,
) -> Result<(), ObjectError> {
    for offset in (0..32).step_by(8) {
        x.load64(R::Ax, right, right_offset + offset)?;
        let mut bytes = Vec::with_capacity(8);
        X::mem(
            &mut bytes,
            R::Ax,
            left,
            i32_disp(left_offset + offset)?,
            true,
            &[0x39],
        );
        x.op(&bytes)?;
        branch_not_equal(x, invalid)?;
    }
    Ok(())
}

const L_POSITION: usize = 0;
const L_SEEN: usize = 8;
const L_CURRENT: usize = 16;
const L_ROOTS: usize = 24;
const L_STACK: usize = 32;
const L_CACHE_IDENTITY: usize = 40;
const L_ROOT_COUNT: usize = 48;
const L_ROOT_INDEX: usize = 56;
const L_THREAD_STATE: usize = 64;
const L_THREAD_START: usize = 72;
const L_EDGE_INDEX: usize = 80;
const L_EDGE_END: usize = 88;
const L_CURRENT_INDEX: usize = 96;
const L_ROOT_MODE: usize = 104;
const L_HEADER: usize = 112;
const L_BYTE: usize = 120;
const L_ASSERT_LEFT_CLASS: usize = 128;
const L_ASSERTION_KNOWN_MASK: usize = 136;
const L_ASSERTION_ENABLED_MASK: usize = 144;
const L_ASSERTION_BIT: usize = 152;
const _: () = assert!(L_ASSERTION_BIT + 8 <= 0xa8);

fn emit_epilogue(x: &mut X<'_>) -> Result<(), ObjectError> {
    x.op(&[0x48, 0x81, 0xc4, 0xa8, 0, 0, 0])?;
    x.op(&[0x41, 0x5f])?;
    x.op(&[0x41, 0x5e])?;
    x.op(&[0x41, 0x5d])?;
    x.op(&[0x41, 0x5c])?;
    x.op(&[0x5b])?;
    x.op(&[0x5d])
}

fn emit_return(x: &mut X<'_>) -> Result<(), ObjectError> {
    emit_epilogue(x)?;
    x.op(&[0xc3])
}

fn emit_prologue_and_raw_checks(
    asm: &mut X86Assembler,
    table_displacement: usize,
    invalid_argument: usize,
    invalid_handle: usize,
) -> Result<(), ObjectError> {
    let mut x = X { asm };
    x.op(&[0x55])?;
    x.op(&[0x53])?;
    x.op(&[0x41, 0x54])?;
    x.op(&[0x41, 0x55])?;
    x.op(&[0x41, 0x56])?;
    x.op(&[0x41, 0x57])?;
    x.op(&[0x48, 0x81, 0xec, 0xa8, 0, 0, 0])?;
    x.mov64(R::Bx, R::Di)?;
    x.store64(R::Sp, L_HEADER, R::Di)?;
    x.mov64(R::R12, R::Si)?;
    x.mov64(R::R13, R::Dx)?;
    x.store64(R::Sp, L_POSITION, R::Cx)?;
    x.mov64(R::R14, R::R8)?;
    x.mov64(R::R15, R::R9)?;
    x.op(&[0x48, 0x8d, 0x2d])?;
    x.asm.bind(table_displacement)?;
    push_bytes(&mut x.asm.code, &[0; 4])?;

    x.test64(R::Bx, R::Bx)?;
    x.branch(0x84, invalid_handle)?;
    x.test64(R::R15, R::R15)?;
    x.branch(0x84, invalid_argument)?;
    x.load64(R::Ax, R::Sp, L_POSITION)?;
    x.cmp64(R::Ax, R::R14)?;
    x.branch(0x87, invalid_argument)?;
    x.cmp64(R::R14, R::R13)?;
    x.branch(0x87, invalid_argument)?;
    x.test64(R::R12, R::R12)?;
    x.branch(0x84, invalid_argument)?;
    x.imm64(R::Ax, i64::MAX as u64)?;
    x.cmp64(R::R13, R::Ax)?;
    x.branch(0x87, invalid_argument)?;
    x.imm64(R::Ax, 7)?;
    x.test64(R::R15, R::Ax)?;
    x.branch(0x85, invalid_argument)
}

fn emit_bulk_gate_prologue(
    asm: &mut X86Assembler,
    table_displacement: usize,
    invalid_handle: usize,
) -> Result<(), ObjectError> {
    let mut x = X { asm };
    // Match the complete search-entry frame so the shared epilogue and exact
    // authentication emitters have identical, independently bounded locals.
    x.op(&[0x55])?;
    x.op(&[0x53])?;
    x.op(&[0x41, 0x54])?;
    x.op(&[0x41, 0x55])?;
    x.op(&[0x41, 0x56])?;
    x.op(&[0x41, 0x57])?;
    x.op(&[0x48, 0x81, 0xec, 0xa8, 0, 0, 0])?;
    x.mov64(R::Bx, R::Di)?;
    x.store64(R::Sp, L_HEADER, R::Di)?;
    x.op(&[0x48, 0x8d, 0x2d])?;
    x.asm.bind(table_displacement)?;
    push_bytes(&mut x.asm.code, &[0; 4])?;
    x.test64(R::Bx, R::Bx)?;
    x.branch(0x84, invalid_handle)
}

fn emit_v15_claim_classifier(
    x: &mut X<'_>,
    claimed: usize,
    legacy: usize,
) -> Result<(), ObjectError> {
    x.load32(R::Ax, R::Bx, FROZEN_PREPARED_HEADER_V1_FLAGS_OFFSET)?;
    x.and32_imm(R::Ax, FROZEN_PREPARED_HEADER_V1_FLAG_ORDERED_NFA_V15)?;
    x.test64(R::Ax, R::Ax)?;
    x.branch(0x85, claimed)?;
    x.load64(
        R::Ax,
        R::Bx,
        FROZEN_PREPARED_HEADER_V15_DYNAMIC_ROWS_OFFSET + FROZEN_DYNAMIC_ROWS_V3_READY_SEAL_OFFSET,
    )?;
    x.imm64(R::Cx, FROZEN_PREPARED_HEADER_V15_READY_SEAL)?;
    x.cmp64(R::Ax, R::Cx)?;
    x.branch(0x84, claimed)?;
    x.load32(
        R::Ax,
        R::Bx,
        FROZEN_PREPARED_HEADER_V15_DYNAMIC_ROWS_OFFSET
            + FROZEN_DYNAMIC_ROWS_V3_FORMAT_VERSION_OFFSET,
    )?;
    x.cmp32_imm(R::Ax, FROZEN_ORDERED_NFA_V15_FORMAT_VERSION)?;
    x.branch(0x84, claimed)?;
    x.jump(legacy)
}

/// Reject an impossible absolute whole-window width after exact handle and
/// scratch authentication, but before source reads or scratch mutation. The
/// independently proved absolute cuts also reject every partial window.
fn emit_whole_window_width_gate(
    x: &mut X<'_>,
    bounds: WholeWindowWidthBounds,
    no_match: usize,
) -> Result<(), ObjectError> {
    let minimum = u64::try_from(bounds.minimum)
        .map_err(|_| ObjectError::ArithmeticOverflow("x86 Ordered-NFA minimum width"))?;
    let maximum = u64::try_from(bounds.maximum)
        .map_err(|_| ObjectError::ArithmeticOverflow("x86 Ordered-NFA maximum width"))?;
    x.load64(R::Ax, R::Sp, L_POSITION)?;
    x.test64(R::Ax, R::Ax)?;
    x.branch(0x85, no_match)?;
    x.cmp64(R::R14, R::R13)?;
    x.branch(0x85, no_match)?;
    x.imm64(R::Ax, minimum)?;
    x.cmp64(R::R13, R::Ax)?;
    x.branch(0x82, no_match)?;
    x.imm64(R::Ax, maximum)?;
    x.cmp64(R::R13, R::Ax)?;
    x.branch(0x87, no_match)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "authenticated sidecar offsets were checked while constructing the object layout"
)]
fn emit_exact_object_auth(
    x: &mut X<'_>,
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
    x.cmp_mem64_value(R::Bp, 0, ready_seal)?;
    branch_not_equal(x, invalid)?;
    x.cmp_mem64_value(R::Bp, 8, magic)?;
    branch_not_equal(x, invalid)?;
    x.cmp_mem32_value(R::Bp, 16, abi_version)?;
    branch_not_equal(x, invalid)?;
    x.cmp_mem32_value(R::Bp, 20, !abi_version)?;
    branch_not_equal(x, invalid)?;
    x.cmp_mem32_value(
        R::Bp,
        24,
        u32::try_from(layout.object_bytes)
            .map_err(|_| ObjectError::ArithmeticOverflow("Ordered-NFA object bytes"))?,
    )?;
    branch_not_equal(x, invalid)?;
    x.cmp_mem32_value(R::Bp, 28, flags)?;
    branch_not_equal(x, invalid)?;
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
        x.cmp_mem32_value(
            R::Bp,
            field,
            u32::try_from(value)
                .map_err(|_| ObjectError::ArithmeticOverflow("Ordered-NFA object geometry"))?,
        )?;
        branch_not_equal(x, invalid)?;
    }
    x.cmp_mem32_value(
        R::Bp,
        ORDERED_NFA_OBJECT_V1_START_STATE_FIELD,
        layout.start_state,
    )?;
    branch_not_equal(x, invalid)?;
    x.cmp_mem32_value(
        R::Bp,
        ORDERED_NFA_OBJECT_V1_ASSERTION_KINDS_FIELD,
        layout.assertion_kinds,
    )?;
    branch_not_equal(x, invalid)?;
    x.cmp_mem32_value(
        R::Bp,
        ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_STRIDE_FIELD,
        if layout.unicode_ranges_offset.is_some() {
            ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_STRIDE
        } else {
            0
        },
    )?;
    branch_not_equal(x, invalid)?;
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
    x.load32(R::Ax, R::Bp, ORDERED_NFA_OBJECT_V1_LINE_TERMINATOR_FIELD)?;
    x.cmp32_imm(R::Ax, terminal_word)?;
    branch_not_equal(x, invalid)?;
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
            x.cmp_mem32_value(
                R::Bp,
                dispatch.descriptor_offset + field,
                u32::try_from(value).map_err(|_| {
                    ObjectError::ArithmeticOverflow("Ordered-edge dispatch object geometry")
                })?,
            )?;
            branch_not_equal(x, invalid)?;
        }
        x.cmp_mem32_value(
            R::Bp,
            dispatch.descriptor_offset + ORDERED_NFA_EDGE_DISPATCH_V1_CONTROL_FIELD,
            dispatch.encoding.control(),
        )?;
        branch_not_equal(x, invalid)?;
    }
    Ok(())
}

fn emit_exact_header_auth(
    x: &mut X<'_>,
    layout: NativeOrderedNfaObjectLayout,
    scratch_bytes: usize,
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
        x.cmp_mem64_value(R::Bx, offset, value)?;
        branch_not_equal(x, invalid)?;
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
        x.cmp_mem32_value(R::Bx, offset, value)?;
        branch_not_equal(x, invalid)?;
    }
    x.cmp_mem64_value(
        R::Bx,
        FROZEN_PREPARED_HEADER_V1_HEADER_BYTES_OFFSET,
        u64::try_from(FROZEN_PREPARED_HEADER_V15_BYTES).unwrap(),
    )?;
    branch_not_equal(x, invalid)?;
    compare_identity(
        x,
        R::Bx,
        FROZEN_PREPARED_HEADER_V1_ARTIFACT_IDENTITY_OFFSET,
        R::Bp,
        ORDERED_NFA_OBJECT_V1_IDENTITY_OFFSET,
        invalid,
    )?;
    x.cmp_mem64_zero(R::Bx, FROZEN_PREPARED_HEADER_V1_FORWARD_ROWS_ADDRESS_OFFSET)?;
    x.branch(0x84, invalid)?;
    for offset in [
        FROZEN_PREPARED_HEADER_V1_REVERSE_ROWS_ADDRESS_OFFSET,
        FROZEN_PREPARED_HEADER_V1_REVERSE_LIVE_CELLS_OFFSET,
    ] {
        x.cmp_mem64_zero(R::Bx, offset)?;
        branch_not_equal(x, invalid)?;
    }
    x.cmp_mem64_value(
        R::Bx,
        FROZEN_PREPARED_HEADER_V1_FORWARD_LIVE_CELLS_OFFSET,
        u64::try_from(scratch_bytes).unwrap(),
    )?;
    branch_not_equal(x, invalid)?;
    x.cmp_mem64_zero(R::Bx, FROZEN_PREPARED_HEADER_V1_CACHE_IDENTITY_OFFSET)?;
    x.branch(0x84, invalid)?;
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
        x.cmp_mem32_value(R::Bx, offset, u32::try_from(value).unwrap())?;
        branch_not_equal(x, invalid)?;
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
        x.cmp_mem32_value(R::Bx, offset, value)?;
        branch_not_equal(x, invalid)?;
    }
    for offset in (0..256).step_by(8) {
        x.cmp_mem64_zero(R::Bx, FROZEN_PREPARED_HEADER_V1_CLASS_MAP_OFFSET + offset)?;
        branch_not_equal(x, invalid)?;
    }
    let tail = FROZEN_PREPARED_HEADER_V15_DYNAMIC_ROWS_OFFSET;
    x.cmp_mem64_value(
        R::Bx,
        tail + FROZEN_DYNAMIC_ROWS_V3_READY_SEAL_OFFSET,
        FROZEN_PREPARED_HEADER_V15_READY_SEAL,
    )?;
    branch_not_equal(x, invalid)?;
    x.load64(
        R::Ax,
        R::Bx,
        FROZEN_PREPARED_HEADER_V1_FORWARD_ROWS_ADDRESS_OFFSET,
    )?;
    let mut bytes = Vec::new();
    X::mem(
        &mut bytes,
        R::Ax,
        R::Bx,
        i32_disp(tail + FROZEN_DYNAMIC_ROWS_V3_ROWS_ADDRESS_OFFSET)?,
        true,
        &[0x39],
    );
    x.op(&bytes)?;
    branch_not_equal(x, invalid)?;
    x.load64(
        R::Ax,
        R::Bx,
        FROZEN_PREPARED_HEADER_V1_CACHE_IDENTITY_OFFSET,
    )?;
    x.store64(R::Sp, L_CACHE_IDENTITY, R::Ax)?;
    let mut bytes = Vec::new();
    X::mem(
        &mut bytes,
        R::Ax,
        R::Bx,
        i32_disp(tail + FROZEN_DYNAMIC_ROWS_V3_CACHE_IDENTITY_OFFSET)?,
        true,
        &[0x39],
    );
    x.op(&bytes)?;
    branch_not_equal(x, invalid)?;
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
        x.cmp_mem32_value(R::Bx, tail + offset, u32::try_from(value).unwrap())?;
        branch_not_equal(x, invalid)?;
    }
    x.cmp_mem32_zero(R::Bx, tail + FROZEN_DYNAMIC_ROWS_V3_LOOP_COUNT_OFFSET)?;
    branch_not_equal(x, invalid)?;
    for index in 0..4 {
        x.cmp_mem32_value(
            R::Bx,
            tail + FROZEN_DYNAMIC_ROWS_V3_LOOP_STATES_OFFSET + index * 4,
            u32::MAX,
        )?;
        branch_not_equal(x, invalid)?;
    }
    x.cmp_mem32_value(
        R::Bx,
        tail + FROZEN_DYNAMIC_ROWS_V3_FORMAT_VERSION_OFFSET,
        FROZEN_ORDERED_NFA_V15_FORMAT_VERSION,
    )?;
    branch_not_equal(x, invalid)?;
    for offset in [
        FROZEN_DYNAMIC_ROWS_V6_LOOP_PLAN_COUNT_OFFSET,
        FROZEN_DYNAMIC_ROWS_V6_RESERVED_OFFSET,
    ] {
        x.cmp_mem32_zero(R::Bx, tail + offset)?;
        branch_not_equal(x, invalid)?;
    }
    for offset in [
        FROZEN_DYNAMIC_ROWS_V6_LOOP_INDEX_ADDRESS_OFFSET,
        FROZEN_DYNAMIC_ROWS_V6_LOOP_INDEX_LENGTH_OFFSET,
    ] {
        x.cmp_mem64_zero(R::Bx, tail + offset)?;
        branch_not_equal(x, invalid)?;
    }
    for plan in 0..4 {
        let base = tail + FROZEN_DYNAMIC_ROWS_V6_LOOP_PLANS_OFFSET + plan * 48;
        x.cmp_mem64_value(R::Bx, base, u64::MAX)?;
        branch_not_equal(x, invalid)?;
        for offset in [8, 16, 24, 32] {
            x.cmp_mem64_zero(R::Bx, base + offset)?;
            branch_not_equal(x, invalid)?;
        }
        x.load64(
            R::Ax,
            R::Bx,
            base + FROZEN_COMPACT_LOOP_PLAN_V1_SCANNER_ADDRESS_OFFSET,
        )?;
        x.test64(R::Ax, R::Ax)?;
        x.branch(0x84, invalid)?;
        x.imm64(R::Cx, 7)?;
        x.test64(R::Ax, R::Cx)?;
        x.branch(0x85, invalid)?;
    }
    Ok(())
}

fn emit_common_header_identity_auth(x: &mut X<'_>, invalid: usize) -> Result<(), ObjectError> {
    x.cmp_mem64_value(
        R::Bx,
        FROZEN_PREPARED_HEADER_V1_MAGIC_OFFSET,
        FROZEN_PREPARED_HEADER_V1_MAGIC,
    )?;
    branch_not_equal(x, invalid)?;
    x.cmp_mem32_value(
        R::Bx,
        FROZEN_PREPARED_HEADER_V1_ABI_VERSION_OFFSET,
        FROZEN_PREPARED_HEADER_V1_ABI_VERSION,
    )?;
    branch_not_equal(x, invalid)?;
    compare_identity(
        x,
        R::Bx,
        FROZEN_PREPARED_HEADER_V1_ARTIFACT_IDENTITY_OFFSET,
        R::Bp,
        ORDERED_NFA_OBJECT_V1_IDENTITY_OFFSET,
        invalid,
    )
}

fn emit_exact_scratch_auth(
    x: &mut X<'_>,
    layout: NativeOrderedNfaObjectLayout,
    scratch_bytes: usize,
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
        x.cmp_mem64_value(R::Bx, offset, value)?;
        branch_not_equal(x, invalid)?;
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
        x.cmp_mem32_value(R::Bx, offset, value)?;
        branch_not_equal(x, invalid)?;
    }
    x.cmp_mem64_value(
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_BYTES_OFFSET,
        u64::try_from(scratch_bytes).unwrap(),
    )?;
    branch_not_equal(x, invalid)?;
    compare_identity(
        x,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_ARTIFACT_IDENTITY_OFFSET,
        R::Bp,
        ORDERED_NFA_OBJECT_V1_IDENTITY_OFFSET,
        invalid,
    )?;
    x.load64(R::Ax, R::Sp, L_CACHE_IDENTITY)?;
    let mut bytes = Vec::new();
    X::mem(
        &mut bytes,
        R::Ax,
        R::Bx,
        i32_disp(FROZEN_ORDERED_NFA_SCRATCH_V1_CACHE_IDENTITY_OFFSET)?,
        true,
        &[0x39],
    );
    x.op(&bytes)?;
    branch_not_equal(x, invalid)?;
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
    for ((offset, local), header_offset) in [
        (FROZEN_ORDERED_NFA_SCRATCH_V1_SEEN_ADDRESS_OFFSET, L_SEEN),
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_ADDRESS_OFFSET,
            L_CURRENT,
        ),
        (FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_ADDRESS_OFFSET, L_ROOTS),
        (FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_ADDRESS_OFFSET, L_STACK),
    ]
    .into_iter()
    .zip(header)
    {
        x.load64(R::Ax, R::Bx, offset)?;
        x.test64(R::Ax, R::Ax)?;
        x.branch(0x84, invalid)?;
        x.load64(R::Cx, R::Sp, L_HEADER)?;
        x.load64(R::Dx, R::Cx, header_offset)?;
        x.cmp64(R::Ax, R::Dx)?;
        branch_not_equal(x, invalid)?;
        x.store64(R::Sp, local, R::Ax)?;
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
        x.cmp_mem32_value(R::Bx, offset, u32::try_from(value).unwrap())?;
        branch_not_equal(x, invalid)?;
    }
    // The reserved word follows stack_capacity and the control-reserved word
    // follows pending_valid in this exact 176-byte C layout.
    x.cmp_mem32_zero(
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_CAPACITY_OFFSET + 4,
    )?;
    branch_not_equal(x, invalid)?;
    x.load64(
        R::Ax,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
    )?;
    x.cmp64_imm(R::Ax, u32::try_from(layout.state_count).unwrap())?;
    x.branch(0x87, invalid)?;
    x.load64(R::Ax, R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET)?;
    x.cmp64_imm(R::Ax, u32::try_from(layout.edge_count).unwrap())?;
    x.branch(0x87, invalid)?;
    x.load64(R::Ax, R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
    x.cmp64_imm(R::Ax, u32::try_from(layout.closure_slots).unwrap())?;
    x.branch(0x87, invalid)?;
    x.load32(
        R::Ax,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET,
    )?;
    x.cmp32_imm(R::Ax, 1)?;
    x.branch(0x87, invalid)?;
    x.cmp_mem32_zero(
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET + 4,
    )?;
    branch_not_equal(x, invalid)?;
    Ok(())
}

/// Rehydrate the per-invocation register/local view from a capability already
/// authenticated by the enclosing aggregate wrapper's one-shot bulk gate.
///
/// This entry is never published and the wrapper makes no external calls
/// between the gate and its local search loop. The exclusive prepared-handle
/// contract therefore keeps these write-once addresses stable for the whole
/// reduction while ordinary/private search continues to authenticate them on
/// every independent invocation.
fn emit_trusted_aggregate_scratch_setup(x: &mut X<'_>) -> Result<(), ObjectError> {
    x.load64(
        R::Ax,
        R::Bx,
        FROZEN_PREPARED_HEADER_V1_FORWARD_ROWS_ADDRESS_OFFSET,
    )?;
    x.mov64(R::Bx, R::Ax)?;
    for (offset, local) in [
        (FROZEN_ORDERED_NFA_SCRATCH_V1_SEEN_ADDRESS_OFFSET, L_SEEN),
        (
            FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_ADDRESS_OFFSET,
            L_CURRENT,
        ),
        (FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_ADDRESS_OFFSET, L_ROOTS),
        (FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_ADDRESS_OFFSET, L_STACK),
    ] {
        x.load64(R::Ax, R::Bx, offset)?;
        x.store64(R::Sp, local, R::Ax)?;
    }
    Ok(())
}

fn emit_bool_return(x: &mut X<'_>, value: bool) -> Result<(), ObjectError> {
    x.imm32(R::Ax, u32::from(value))?;
    x.xor32(R::Dx, R::Dx)?;
    x.op(&[0xc3])
}

fn emit_unicode_member(
    asm: &mut X86Assembler,
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
    let mut x = X { asm };
    x.mov32(R::Di, R::Ax)?;
    x.xor32(R::Cx, R::Cx)?;
    x.imm32(R::Dx, u32::try_from(layout.unicode_range_count).unwrap())?;
    x.asm.bind(loop_label)?;
    x.cmp32(R::Cx, R::Dx)?;
    x.branch(0x83, absent)?;
    x.mov32(R::R8, R::Cx)?;
    x.add32(R::R8, R::Dx)?;
    x.shr32_imm(R::R8, 1)?;
    x.load32_index(R::R9, R::Bp, R::R8, 3, unicode_offset)?;
    x.cmp32(R::Di, R::R9)?;
    x.branch(0x82, lower)?;
    x.load32_index(R::R10, R::Bp, R::R8, 3, unicode_offset + 4)?;
    x.cmp32(R::Di, R::R10)?;
    x.branch(0x87, upper)?;
    x.jump(found)?;
    x.asm.bind(lower)?;
    x.mov32(R::Dx, R::R8)?;
    x.jump(loop_label)?;
    x.asm.bind(upper)?;
    x.mov32(R::Cx, R::R8)?;
    x.inc64(R::Cx)?;
    x.jump(loop_label)?;
    x.asm.bind(found)?;
    x.imm32(R::Ax, 1)?;
    x.op(&[0xc3])?;
    x.asm.bind(absent)?;
    x.xor32(R::Ax, R::Ax)?;
    x.op(&[0xc3])
}

/// Decode one scalar at `haystack + rcx`. `rdx` is the permitted byte end and
/// `r11d != 0` requires the scalar to end exactly there. Returns `edi=1` and
/// the scalar in eax, or `edi=0` for malformed/truncated UTF-8.
fn emit_decode_scalar(asm: &mut X86Assembler, label: usize) -> Result<(), ObjectError> {
    let invalid = asm.label()?;
    let len2 = asm.label()?;
    let len3 = asm.label()?;
    let len4 = asm.label()?;
    let extent = asm.label()?;
    let decode2 = asm.label()?;
    let decode3 = asm.label()?;
    let decode4 = asm.label()?;
    let valid = asm.label()?;
    asm.bind(label)?;
    let mut x = X { asm };
    x.load8_index(R::Ax, R::R12, R::Cx, 0)?;
    x.cmp32_imm(R::Ax, 0x7f)?;
    x.branch(0x86, valid)?;
    x.cmp32_imm(R::Ax, 0xc2)?;
    x.branch(0x82, invalid)?;
    x.cmp32_imm(R::Ax, 0xdf)?;
    x.branch(0x86, len2)?;
    x.cmp32_imm(R::Ax, 0xef)?;
    x.branch(0x86, len3)?;
    x.cmp32_imm(R::Ax, 0xf4)?;
    x.branch(0x86, len4)?;
    x.jump(invalid)?;
    x.asm.bind(len2)?;
    x.imm32(R::R8, 2)?;
    x.jump(extent)?;
    x.asm.bind(len3)?;
    x.imm32(R::R8, 3)?;
    x.jump(extent)?;
    x.asm.bind(len4)?;
    x.imm32(R::R8, 4)?;
    x.asm.bind(extent)?;
    x.mov64(R::R9, R::Cx)?;
    x.add64(R::R9, R::R8)?;
    x.cmp64(R::R9, R::Dx)?;
    x.branch(0x87, invalid)?;
    x.test64(R::R11, R::R11)?;
    let not_exact = x.asm.label()?;
    x.branch(0x84, not_exact)?;
    x.cmp64(R::R9, R::Dx)?;
    x.branch(0x85, invalid)?;
    x.asm.bind(not_exact)?;
    x.cmp32_imm(R::R8, 2)?;
    x.branch(0x84, decode2)?;
    x.cmp32_imm(R::R8, 3)?;
    x.branch(0x84, decode3)?;
    x.jump(decode4)?;

    x.asm.bind(decode2)?;
    x.load8_index(R::Di, R::R12, R::Cx, 1)?;
    x.mov32(R::R9, R::Di)?;
    x.and32_imm(R::R9, 0xc0)?;
    x.cmp32_imm(R::R9, 0x80)?;
    x.branch(0x85, invalid)?;
    x.and32_imm(R::Ax, 0x1f)?;
    x.shl32_imm(R::Ax, 6)?;
    x.and32_imm(R::Di, 0x3f)?;
    x.or32(R::Ax, R::Di)?;
    x.jump(valid)?;

    x.asm.bind(decode3)?;
    x.load8_index(R::Di, R::R12, R::Cx, 1)?;
    x.load8_index(R::R9, R::R12, R::Cx, 2)?;
    for reg in [R::Di, R::R9] {
        x.mov32(R::R10, reg)?;
        x.and32_imm(R::R10, 0xc0)?;
        x.cmp32_imm(R::R10, 0x80)?;
        x.branch(0x85, invalid)?;
    }
    x.and32_imm(R::Ax, 0x0f)?;
    x.shl32_imm(R::Ax, 12)?;
    x.and32_imm(R::Di, 0x3f)?;
    x.shl32_imm(R::Di, 6)?;
    x.or32(R::Ax, R::Di)?;
    x.and32_imm(R::R9, 0x3f)?;
    x.or32(R::Ax, R::R9)?;
    x.cmp32_imm(R::Ax, 0x800)?;
    x.branch(0x82, invalid)?;
    x.cmp32_imm(R::Ax, 0xd800)?;
    let below_surrogate = x.asm.label()?;
    x.branch(0x82, below_surrogate)?;
    x.cmp32_imm(R::Ax, 0xdfff)?;
    x.branch(0x86, invalid)?;
    x.asm.bind(below_surrogate)?;
    x.jump(valid)?;

    x.asm.bind(decode4)?;
    x.load8_index(R::Di, R::R12, R::Cx, 1)?;
    x.load8_index(R::R9, R::R12, R::Cx, 2)?;
    x.load8_index(R::R10, R::R12, R::Cx, 3)?;
    for reg in [R::Di, R::R9, R::R10] {
        x.mov32(R::R8, reg)?;
        x.and32_imm(R::R8, 0xc0)?;
        x.cmp32_imm(R::R8, 0x80)?;
        x.branch(0x85, invalid)?;
    }
    x.and32_imm(R::Ax, 0x07)?;
    x.shl32_imm(R::Ax, 18)?;
    x.and32_imm(R::Di, 0x3f)?;
    x.shl32_imm(R::Di, 12)?;
    x.or32(R::Ax, R::Di)?;
    x.and32_imm(R::R9, 0x3f)?;
    x.shl32_imm(R::R9, 6)?;
    x.or32(R::Ax, R::R9)?;
    x.and32_imm(R::R10, 0x3f)?;
    x.or32(R::Ax, R::R10)?;
    x.cmp32_imm(R::Ax, 0x1_0000)?;
    x.branch(0x82, invalid)?;
    x.cmp32_imm(R::Ax, 0x10_ffff)?;
    x.branch(0x87, invalid)?;
    x.jump(valid)?;

    x.asm.bind(valid)?;
    x.imm32(R::Di, 1)?;
    x.op(&[0xc3])?;
    x.asm.bind(invalid)?;
    x.xor32(R::Di, R::Di)?;
    x.op(&[0xc3])
}

fn emit_ascii_word_classification(x: &mut X<'_>, byte: R, output: R) -> Result<(), ObjectError> {
    let word = x.asm.label()?;
    let done = x.asm.label()?;
    x.xor32(output, output)?;
    x.cmp32_imm(byte, u32::from(b'_'))?;
    x.branch(0x84, word)?;
    x.cmp32_imm(byte, u32::from(b'0'))?;
    x.branch(0x82, done)?;
    x.cmp32_imm(byte, u32::from(b'9'))?;
    x.branch(0x86, word)?;
    x.cmp32_imm(byte, u32::from(b'A'))?;
    x.branch(0x82, done)?;
    x.cmp32_imm(byte, u32::from(b'Z'))?;
    x.branch(0x86, word)?;
    x.cmp32_imm(byte, u32::from(b'a'))?;
    x.branch(0x82, done)?;
    x.cmp32_imm(byte, u32::from(b'z'))?;
    x.branch(0x87, done)?;
    x.asm.bind(word)?;
    x.imm32(output, 1)?;
    x.asm.bind(done)?;
    Ok(())
}

fn emit_unicode_classifiers(
    asm: &mut X86Assembler,
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
    let left_member_done = asm.label()?;
    asm.bind(left_label)?;
    let mut x = X { asm };
    x.test64(R::Cx, R::Cx)?;
    x.branch(0x84, left_nonword)?;
    x.mov64(R::R10, R::Cx)?;
    x.dec64(R::Cx)?;
    x.xor32(R::R8, R::R8)?;
    x.asm.bind(left_find)?;
    x.load8_index(R::Ax, R::R12, R::Cx, 0)?;
    x.cmp32_imm(R::Ax, 0x80)?;
    x.branch(0x82, left_found)?;
    x.cmp32_imm(R::Ax, 0xbf)?;
    x.branch(0x87, left_found)?;
    x.cmp32_imm(R::R8, 3)?;
    x.branch(0x83, left_invalid)?;
    x.test64(R::Cx, R::Cx)?;
    x.branch(0x84, left_invalid)?;
    x.dec64(R::Cx)?;
    x.inc64(R::R8)?;
    x.jump(left_find)?;
    x.asm.bind(left_found)?;
    x.cmp32_imm(R::Ax, 0x7f)?;
    x.branch(0x86, left_ascii)?;
    x.mov64(R::Dx, R::R10)?;
    x.imm32(R::R11, 1)?;
    x.call(decode_label)?;
    x.test64(R::Di, R::Di)?;
    x.branch(0x84, left_invalid)?;
    x.call(member_label)?;
    x.inc64(R::Ax)?;
    x.jump(left_member_done)?;
    x.asm.bind(left_ascii)?;
    emit_ascii_word_classification(&mut x, R::Ax, R::R9)?;
    x.mov32(R::Ax, R::R9)?;
    x.inc64(R::Ax)?;
    x.jump(left_member_done)?;
    x.asm.bind(left_nonword)?;
    x.imm32(R::Ax, 1)?;
    x.jump(left_member_done)?;
    x.asm.bind(left_invalid)?;
    x.xor32(R::Ax, R::Ax)?;
    x.asm.bind(left_member_done)?;
    x.op(&[0xc3])?;

    let right_nonword = x.asm.label()?;
    let right_invalid = x.asm.label()?;
    let right_ascii = x.asm.label()?;
    let right_done = x.asm.label()?;
    x.asm.bind(right_label)?;
    x.cmp64(R::Cx, R::R13)?;
    x.branch(0x84, right_nonword)?;
    x.load8_index(R::Ax, R::R12, R::Cx, 0)?;
    x.cmp32_imm(R::Ax, 0x7f)?;
    x.branch(0x86, right_ascii)?;
    x.mov64(R::Dx, R::R13)?;
    x.xor32(R::R11, R::R11)?;
    x.call(decode_label)?;
    x.test64(R::Di, R::Di)?;
    x.branch(0x84, right_invalid)?;
    x.call(member_label)?;
    x.inc64(R::Ax)?;
    x.jump(right_done)?;
    x.asm.bind(right_ascii)?;
    emit_ascii_word_classification(&mut x, R::Ax, R::R9)?;
    x.mov32(R::Ax, R::R9)?;
    x.inc64(R::Ax)?;
    x.jump(right_done)?;
    x.asm.bind(right_nonword)?;
    x.imm32(R::Ax, 1)?;
    x.jump(right_done)?;
    x.asm.bind(right_invalid)?;
    x.xor32(R::Ax, R::Ax)?;
    x.asm.bind(right_done)?;
    x.op(&[0xc3])
}

fn emit_assertion(
    asm: &mut X86Assembler,
    label: usize,
    layout: NativeOrderedNfaObjectLayout,
    unicode_left: Option<usize>,
    unicode_right: Option<usize>,
) -> Result<(), ObjectError> {
    let true_result = asm.label()?;
    let false_result = asm.label()?;
    let failure = asm.label()?;
    let load_context = asm.label()?;
    let dispatch_context = asm.label()?;
    let ascii = asm.label()?;
    let unicode = asm.label()?;
    asm.bind(label)?;
    let mut x = X { asm };
    x.mov32(R::Si, R::Ax)?;
    x.cmp32_imm(R::Si, 19)?;
    x.branch(0x87, failure)?;
    x.cmp32_imm(R::Si, EDGE_EPSILON.into())?;
    x.branch(0x84, true_result)?;
    x.cmp32_imm(R::Si, 2)?;
    let not_absolute_start = x.asm.label()?;
    x.branch(0x85, not_absolute_start)?;
    x.test64(R::Cx, R::Cx)?;
    x.branch(0x84, true_result)?;
    x.jump(false_result)?;
    x.asm.bind(not_absolute_start)?;
    x.cmp32_imm(R::Si, 3)?;
    x.branch(0x85, load_context)?;
    x.cmp64(R::Cx, R::R13)?;
    x.branch(0x84, true_result)?;
    x.jump(false_result)?;

    x.asm.bind(load_context)?;
    x.imm32(R::R8, 256)?;
    x.imm32(R::R9, 256)?;
    x.test64(R::Cx, R::Cx)?;
    let no_before = x.asm.label()?;
    x.branch(0x84, no_before)?;
    x.mov64(R::Di, R::Cx)?;
    x.dec64(R::Di)?;
    x.load8_index(R::R8, R::R12, R::Di, 0)?;
    x.asm.bind(no_before)?;
    x.cmp64(R::Cx, R::R13)?;
    let no_after = x.asm.label()?;
    x.branch(0x84, no_after)?;
    x.load8_index(R::R9, R::R12, R::Cx, 0)?;
    x.asm.bind(no_after)?;
    x.asm.bind(dispatch_context)?;

    // Configured LF-style and CRLF-style assertions.
    for kind in 4_u32..=7 {
        let next = x.asm.label()?;
        x.cmp32_imm(R::Si, kind)?;
        x.branch(0x85, next)?;
        match kind {
            4 => {
                x.test64(R::Cx, R::Cx)?;
                x.branch(0x84, true_result)?;
                x.cmp32_imm(R::R8, u32::from(layout.line_terminator))?;
                x.branch(0x84, true_result)?;
            }
            5 => {
                x.cmp64(R::Cx, R::R13)?;
                x.branch(0x84, true_result)?;
                x.cmp32_imm(R::R9, u32::from(layout.line_terminator))?;
                x.branch(0x84, true_result)?;
            }
            6 => {
                x.test64(R::Cx, R::Cx)?;
                x.branch(0x84, true_result)?;
                x.cmp32_imm(R::R8, u32::from(b'\n'))?;
                x.branch(0x84, true_result)?;
                x.cmp32_imm(R::R8, u32::from(b'\r'))?;
                x.branch(0x85, false_result)?;
                x.cmp32_imm(R::R9, u32::from(b'\n'))?;
                x.branch(0x85, true_result)?;
            }
            7 => {
                x.cmp64(R::Cx, R::R13)?;
                x.branch(0x84, true_result)?;
                x.cmp32_imm(R::R9, u32::from(b'\r'))?;
                x.branch(0x84, true_result)?;
                x.cmp32_imm(R::R9, u32::from(b'\n'))?;
                x.branch(0x85, false_result)?;
                x.cmp32_imm(R::R8, u32::from(b'\r'))?;
                x.branch(0x85, true_result)?;
            }
            _ => unreachable!(),
        }
        x.jump(false_result)?;
        x.asm.bind(next)?;
    }
    x.cmp32_imm(R::Si, 14)?;
    x.branch(0x83, unicode)?;
    x.jump(ascii)?;

    x.asm.bind(ascii)?;
    emit_ascii_word_classification(&mut x, R::R8, R::R10)?;
    emit_ascii_word_classification(&mut x, R::R9, R::R11)?;
    // kinds 8..13: boundary, negate, start, end, start-half, end-half.
    let ascii_kind9 = x.asm.label()?;
    x.cmp32_imm(R::Si, 8)?;
    x.branch(0x85, ascii_kind9)?;
    x.cmp32(R::R10, R::R11)?;
    x.branch(0x85, true_result)?;
    x.jump(false_result)?;
    x.asm.bind(ascii_kind9)?;
    let ascii_kind10 = x.asm.label()?;
    x.cmp32_imm(R::Si, 9)?;
    x.branch(0x85, ascii_kind10)?;
    x.cmp32(R::R10, R::R11)?;
    x.branch(0x84, true_result)?;
    x.jump(false_result)?;
    x.asm.bind(ascii_kind10)?;
    let ascii_kind11 = x.asm.label()?;
    x.cmp32_imm(R::Si, 10)?;
    x.branch(0x85, ascii_kind11)?;
    x.test64(R::R10, R::R10)?;
    x.branch(0x85, false_result)?;
    x.test64(R::R11, R::R11)?;
    x.branch(0x85, true_result)?;
    x.jump(false_result)?;
    x.asm.bind(ascii_kind11)?;
    let ascii_kind12 = x.asm.label()?;
    x.cmp32_imm(R::Si, 11)?;
    x.branch(0x85, ascii_kind12)?;
    x.test64(R::R10, R::R10)?;
    x.branch(0x84, false_result)?;
    x.test64(R::R11, R::R11)?;
    x.branch(0x84, true_result)?;
    x.jump(false_result)?;
    x.asm.bind(ascii_kind12)?;
    let ascii_kind13 = x.asm.label()?;
    x.cmp32_imm(R::Si, 12)?;
    x.branch(0x85, ascii_kind13)?;
    x.test64(R::R10, R::R10)?;
    x.branch(0x84, true_result)?;
    x.jump(false_result)?;
    x.asm.bind(ascii_kind13)?;
    x.cmp32_imm(R::Si, 13)?;
    x.branch(0x85, failure)?;
    x.test64(R::R11, R::R11)?;
    x.branch(0x84, true_result)?;
    x.jump(false_result)?;

    x.asm.bind(unicode)?;
    let Some((left, right)) = unicode_left.zip(unicode_right) else {
        x.jump(failure)?;
        x.asm.bind(true_result)?;
        emit_bool_return(&mut x, true)?;
        x.asm.bind(false_result)?;
        emit_bool_return(&mut x, false)?;
        x.asm.bind(failure)?;
        x.xor32(R::Ax, R::Ax)?;
        x.imm32(R::Dx, 1)?;
        return x.op(&[0xc3]);
    };
    x.load64(R::Cx, R::Sp, 8 + L_POSITION)?;
    x.call(left)?;
    x.store64(R::Sp, 8 + L_ASSERT_LEFT_CLASS, R::Ax)?;
    // Classifiers clobber rcx. The assertion frame is one return address below
    // the fixed main frame, so reload the authenticated boundary explicitly.
    x.load64(R::Cx, R::Sp, 8 + L_POSITION)?;
    x.call(right)?;
    x.mov32(R::R11, R::Ax)?;
    x.load64(R::R10, R::Sp, 8 + L_ASSERT_LEFT_CLASS)?;
    x.load64(R::Cx, R::Sp, 8 + L_POSITION)?;
    // class 0 invalid, 1 valid non-word, 2 valid word.
    let unicode15 = x.asm.label()?;
    x.cmp32_imm(R::Si, 14)?;
    x.branch(0x85, unicode15)?;
    x.cmp32_imm(R::R10, 2)?;
    x.setcc32(R::R8, 4)?;
    x.cmp32_imm(R::R11, 2)?;
    x.setcc32(R::R9, 4)?;
    x.cmp32(R::R8, R::R9)?;
    x.branch(0x85, true_result)?;
    x.jump(false_result)?;
    x.asm.bind(unicode15)?;
    let unicode16 = x.asm.label()?;
    x.cmp32_imm(R::Si, 15)?;
    x.branch(0x85, unicode16)?;
    x.test64(R::R10, R::R10)?;
    x.branch(0x84, false_result)?;
    x.test64(R::R11, R::R11)?;
    x.branch(0x84, false_result)?;
    x.cmp32_imm(R::R10, 2)?;
    x.setcc32(R::R8, 4)?;
    x.cmp32_imm(R::R11, 2)?;
    x.setcc32(R::R9, 4)?;
    x.cmp32(R::R8, R::R9)?;
    x.branch(0x84, true_result)?;
    x.jump(false_result)?;
    x.asm.bind(unicode16)?;
    let unicode17 = x.asm.label()?;
    x.cmp32_imm(R::Si, 16)?;
    x.branch(0x85, unicode17)?;
    x.cmp32_imm(R::R10, 2)?;
    x.branch(0x84, false_result)?;
    x.cmp32_imm(R::R11, 2)?;
    x.branch(0x84, true_result)?;
    x.jump(false_result)?;
    x.asm.bind(unicode17)?;
    let unicode18 = x.asm.label()?;
    x.cmp32_imm(R::Si, 17)?;
    x.branch(0x85, unicode18)?;
    x.cmp32_imm(R::R10, 2)?;
    x.branch(0x85, false_result)?;
    x.cmp32_imm(R::R11, 2)?;
    x.branch(0x85, true_result)?;
    x.jump(false_result)?;
    x.asm.bind(unicode18)?;
    let unicode19 = x.asm.label()?;
    x.cmp32_imm(R::Si, 18)?;
    x.branch(0x85, unicode19)?;
    x.cmp32_imm(R::R10, 1)?;
    x.branch(0x84, true_result)?;
    x.jump(false_result)?;
    x.asm.bind(unicode19)?;
    x.cmp32_imm(R::Si, 19)?;
    x.branch(0x85, failure)?;
    x.cmp32_imm(R::R11, 1)?;
    x.branch(0x84, true_result)?;
    x.jump(false_result)?;

    x.asm.bind(true_result)?;
    emit_bool_return(&mut x, true)?;
    x.asm.bind(false_result)?;
    emit_bool_return(&mut x, false)?;
    x.asm.bind(failure)?;
    x.xor32(R::Ax, R::Ax)?;
    x.imm32(R::Dx, 1)?;
    x.op(&[0xc3])
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
                "x86 Ordered-NFA start closure first instruction",
            ))?;
            if first.state() != image.layout.start_state
                || first.subtree_end() != program.len()
                || first.guard() != 0
            {
                return Err(ObjectError::InvalidModule(
                    "x86 Ordered-NFA start closure root",
                ));
            }
            Ok(Some(program))
        }
        _ => Err(ObjectError::InvalidModule(
            "x86 Ordered-NFA start closure receipt",
        )),
    }
}

/// Branch to `matched` exactly when `byte` is in the compiler-proved
/// first-byte cover. The ranges are compiler-only metadata, so validate their
/// canonical ordering before baking them into target text.
fn emit_start_prefix_membership(
    x: &mut X<'_>,
    plan: NativeOrderedNfaStartPrefixPlan,
    byte: R,
    matched: usize,
    missed: usize,
) -> Result<(), ObjectError> {
    let mut previous_end = None;
    if plan.ranges().is_empty() {
        return Err(ObjectError::InvalidModule(
            "x86 Ordered-NFA empty start-prefix cover",
        ));
    }
    for range in plan.ranges() {
        if range.start > range.end
            || previous_end.is_some_and(|end| end >= range.start)
        {
            return Err(ObjectError::InvalidModule(
                "x86 Ordered-NFA start-prefix range order",
            ));
        }
        previous_end = Some(range.end);
        let next_range = x.asm.label()?;
        x.cmp32_imm(byte, u32::from(range.start))?;
        x.branch(0x82, next_range)?;
        x.cmp32_imm(byte, u32::from(range.end))?;
        x.branch(0x86, matched)?;
        x.asm.bind(next_range)?;
    }
    x.jump(missed)
}

fn start_closure_labels(
    asm: &mut X86Assembler,
    program: NativeEpsilonClosureProgramView<'_>,
) -> Result<Vec<usize>, ObjectError> {
    let count = program
        .len()
        .checked_add(1)
        .ok_or(ObjectError::ArithmeticOverflow(
            "x86 Ordered-NFA start closure label count",
        ))?;
    let mut labels = Vec::new();
    labels
        .try_reserve_exact(count)
        .map_err(|_| ObjectError::Allocation("x86 Ordered-NFA start closure labels"))?;
    for _ in 0..count {
        labels.push(asm.label()?);
    }
    Ok(labels)
}

fn start_closure_label(labels: &[usize], index: usize) -> Result<usize, ObjectError> {
    labels.get(index).copied().ok_or(ObjectError::InvalidModule(
        "x86 Ordered-NFA start closure label",
    ))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "validated assertion-kind bounds make the compiler-emitted cache bit total"
)]
fn emit_static_guarded_split_assertions(
    x: &mut X<'_>,
    kinds: &[u8],
    assertion_kinds: u32,
    assertion: usize,
    runtime_failure: usize,
) -> Result<(), ObjectError> {
    for &kind in kinds.iter().rev() {
        if kind == EDGE_EPSILON {
            continue;
        }
        if !(2..=19).contains(&kind) {
            return Err(ObjectError::InvalidModule(
                "x86 Ordered-NFA guarded start closure Split edge",
            ));
        }
        let bit = 1_u32 << u32::from(kind - 2);
        if assertion_kinds & bit == 0 {
            return Err(ObjectError::InvalidModule(
                "x86 Ordered-NFA guarded start closure assertion kind",
            ));
        }
        let known = x.asm.label()?;
        x.imm32(R::R8, bit)?;
        x.load32(R::R9, R::Sp, L_ASSERTION_KNOWN_MASK)?;
        x.test32(R::R9, R::R8)?;
        x.branch(0x85, known)?;
        x.imm32(R::Ax, u32::from(kind))?;
        x.load64(R::Cx, R::Sp, L_POSITION)?;
        x.call(assertion)?;
        x.test64(R::Dx, R::Dx)?;
        x.branch(0x85, runtime_failure)?;
        x.imm32(R::R8, bit)?;
        x.load32(R::R9, R::Sp, L_ASSERTION_KNOWN_MASK)?;
        x.or32(R::R9, R::R8)?;
        x.store32(R::Sp, L_ASSERTION_KNOWN_MASK, R::R9)?;
        x.test64(R::Ax, R::Ax)?;
        x.branch(0x84, known)?;
        x.load32(R::R9, R::Sp, L_ASSERTION_ENABLED_MASK)?;
        x.or32(R::R9, R::R8)?;
        x.store32(R::Sp, L_ASSERTION_ENABLED_MASK, R::R9)?;
        x.asm.bind(known)?;
    }
    Ok(())
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "validated guards make cache-bit construction total while the static closure shares the authenticated image and semantic exits"
)]
fn emit_static_start_closure(
    x: &mut X<'_>,
    image: &NativeOrderedNfaObjectImage<'_>,
    program: NativeEpsilonClosureProgramView<'_>,
    labels: &[usize],
    assertion: usize,
    after_roots: usize,
    runtime_failure: usize,
) -> Result<(), ObjectError> {
    let layout = image.layout;
    x.asm.bind(start_closure_label(labels, 0)?)?;
    x.store_mem64_zero(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
    for instruction_index in 0..program.len() {
        if instruction_index != 0 {
            x.asm
                .bind(start_closure_label(labels, instruction_index)?)?;
        }
        let instruction = program.instruction(instruction_index).ok_or(
            ObjectError::InvalidModule("x86 Ordered-NFA start closure instruction"),
        )?;
        let state = instruction.state();
        if usize::try_from(state)
            .ok()
            .is_none_or(|state| state >= layout.state_count)
        {
            return Err(ObjectError::InvalidModule(
                "x86 Ordered-NFA start closure state",
            ));
        }
        let subtree_end = instruction.subtree_end();
        if subtree_end <= instruction_index || subtree_end > program.len() {
            return Err(ObjectError::InvalidModule(
                "x86 Ordered-NFA start closure subtree",
            ));
        }
        let subtree_end = start_closure_label(labels, subtree_end)?;

        let guard = instruction.guard();
        if guard != 0 {
            if !program.is_guarded() || guard > 18 {
                return Err(ObjectError::InvalidModule(
                    "x86 Ordered-NFA start closure guard",
                ));
            }
            let bit = 1_u32 << guard.saturating_sub(1);
            if layout.assertion_kinds & bit == 0 {
                return Err(ObjectError::InvalidModule(
                    "x86 Ordered-NFA start closure guard kind",
                ));
            }
            x.imm32(R::R8, bit)?;
            x.load32(R::R9, R::Sp, L_ASSERTION_KNOWN_MASK)?;
            x.test32(R::R9, R::R8)?;
            x.branch(0x84, runtime_failure)?;
            x.load32(R::R9, R::Sp, L_ASSERTION_ENABLED_MASK)?;
            x.test32(R::R9, R::R8)?;
            x.branch(0x84, subtree_end)?;
        } else if !program.is_guarded() && instruction.guard() != 0 {
            return Err(ObjectError::InvalidModule(
                "plain x86 Ordered-NFA start closure guard",
            ));
        }

        x.imm32(R::Cx, state)?;
        x.load64(R::Ax, R::Sp, L_SEEN)?;
        x.load64_index(R::Dx, R::Ax, R::Cx, 3, 0)?;
        x.load64(
            R::R8,
            R::Bx,
            FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET,
        )?;
        x.cmp64(R::Dx, R::R8)?;
        x.branch(0x84, subtree_end)?;
        x.store64_index(R::Ax, R::Cx, 3, 0, R::R8)?;

        match instruction.action() {
            NativeEpsilonClosureAction::Accept => {
                x.load64(R::Dx, R::Sp, L_THREAD_START)?;
                x.store64(
                    R::Bx,
                    FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_START_OFFSET,
                    R::Dx,
                )?;
                x.load64(R::Dx, R::Sp, L_POSITION)?;
                x.store64(
                    R::Bx,
                    FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_END_OFFSET,
                    R::Dx,
                )?;
                x.store_mem32_value(
                    R::Bx,
                    FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET,
                    1,
                )?;
                x.jump(after_roots)?;
            }
            NativeEpsilonClosureAction::Consume => {
                x.load64(
                    R::Cx,
                    R::Bx,
                    FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
                )?;
                x.cmp64_imm(R::Cx, u32::try_from(layout.state_count).unwrap())?;
                x.branch(0x83, runtime_failure)?;
                x.load64(R::Ax, R::Sp, L_CURRENT)?;
                x.shl64_imm(R::Cx, 4)?;
                x.add64(R::Ax, R::Cx)?;
                x.imm32(R::Dx, state)?;
                x.store32(R::Ax, 0, R::Dx)?;
                x.store_mem32_value(R::Ax, 4, 0)?;
                x.load64(R::Dx, R::Sp, L_THREAD_START)?;
                x.store64(R::Ax, 8, R::Dx)?;
                x.load64(
                    R::Cx,
                    R::Bx,
                    FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
                )?;
                x.inc64(R::Cx)?;
                x.store64(
                    R::Bx,
                    FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
                    R::Cx,
                )?;
            }
            NativeEpsilonClosureAction::Split => {
                if program.is_guarded() {
                    let kinds = image.encoded_edge_kinds_for_state(state).ok_or(
                        ObjectError::InvalidModule(
                            "x86 Ordered-NFA guarded start closure Split row",
                        ),
                    )?;
                    emit_static_guarded_split_assertions(
                        x,
                        kinds,
                        layout.assertion_kinds,
                        assertion,
                        runtime_failure,
                    )?;
                }
            }
            NativeEpsilonClosureAction::SeenBackedge => x.jump(runtime_failure)?,
        }
    }
    x.asm
        .bind(start_closure_label(labels, program.len())?)?;
    x.jump(after_roots)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "authenticated dispatch geometry and target widths make emitted sidecar offsets and masks total"
)]
fn emit_semantic_body(
    asm: &mut X86Assembler,
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
    let expand_pop = asm.label()?;
    let root_complete = asm.label()?;
    let after_roots = asm.label()?;
    let consume_start = asm.label()?;
    let consume_thread = asm.label()?;
    let consume_next_thread = asm.label()?;
    let consume_edge = asm.label()?;
    let consume_next_edge = asm.label()?;
    let finish = asm.label()?;

    let states = u32::try_from(layout.state_count).unwrap();
    let edges = u32::try_from(layout.edge_count).unwrap();
    let closure = u32::try_from(layout.closure_slots).unwrap();
    let mut x = X { asm };
    x.jump(boundary)?;

    x.asm.bind(boundary)?;
    if layout.cache_boundary_assertions {
        x.store_mem32_value(R::Sp, L_ASSERTION_KNOWN_MASK, 0)?;
        x.store_mem32_value(R::Sp, L_ASSERTION_ENABLED_MASK, 0)?;
    }
    x.store_mem64_zero(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET)?;
    x.load64(
        R::Ax,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET,
    )?;
    x.inc64(R::Ax)?;
    x.store64(
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET,
        R::Ax,
    )?;
    x.load64(R::Ax, R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET)?;
    x.store64(R::Sp, L_ROOT_COUNT, R::Ax)?;
    x.store_mem64_zero(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET)?;
    x.store_mem64_zero(R::Sp, L_ROOT_INDEX)?;
    x.store_mem64_zero(R::Sp, L_ROOT_MODE)?;

    x.asm.bind(next_old_root)?;
    x.load64(R::Cx, R::Sp, L_ROOT_INDEX)?;
    x.load64(R::Dx, R::Sp, L_ROOT_COUNT)?;
    x.cmp64(R::Cx, R::Dx)?;
    x.branch(0x83, old_roots_done)?;
    x.load64(R::Ax, R::Sp, L_ROOTS)?;
    x.shl64_imm(R::Cx, 4)?;
    x.add64(R::Ax, R::Cx)?;
    x.load32(R::Dx, R::Ax, 0)?;
    x.store64(R::Sp, L_THREAD_STATE, R::Dx)?;
    x.load32(R::Dx, R::Ax, 4)?;
    x.test64(R::Dx, R::Dx)?;
    x.branch(0x85, runtime_failure)?;
    x.load64(R::Dx, R::Ax, 8)?;
    x.store64(R::Sp, L_THREAD_START, R::Dx)?;
    x.load64(R::Cx, R::Sp, L_ROOT_INDEX)?;
    x.inc64(R::Cx)?;
    x.store64(R::Sp, L_ROOT_INDEX, R::Cx)?;
    x.jump(expand_start)?;

    x.asm.bind(old_roots_done)?;
    x.load32(
        R::Ax,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET,
    )?;
    x.test64(R::Ax, R::Ax)?;
    x.branch(0x85, after_roots)?;
    if let Some(prefix) = layout.start_prefix {
        let start_admitted = x.asm.label()?;
        x.load64(R::Dx, R::Sp, L_POSITION)?;
        x.cmp64(R::Dx, R::R14)?;
        x.branch(0x83, after_roots)?;
        x.load8_index(R::Ax, R::R12, R::Dx, 0)?;
        emit_start_prefix_membership(
            &mut x,
            prefix,
            R::Ax,
            start_admitted,
            after_roots,
        )?;
        x.asm.bind(start_admitted)?;
    }
    x.imm32(R::Ax, layout.start_state)?;
    x.store64(R::Sp, L_THREAD_STATE, R::Ax)?;
    x.load64(R::Ax, R::Sp, L_POSITION)?;
    x.store64(R::Sp, L_THREAD_START, R::Ax)?;
    x.imm32(R::Ax, 1)?;
    x.store64(R::Sp, L_ROOT_MODE, R::Ax)?;
    if let Some(labels) = start_labels.as_deref() {
        x.jump(start_closure_label(labels, 0)?)?;
    }

    x.asm.bind(expand_start)?;
    x.store_mem64_zero(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
    x.jump(expand_loop)?;

    x.asm.bind(expand_loop)?;
    x.load64(R::Cx, R::Sp, L_THREAD_STATE)?;
    x.cmp64_imm(R::Cx, states)?;
    x.branch(0x83, runtime_failure)?;
    x.load64(R::Ax, R::Sp, L_SEEN)?;
    x.load64_index(R::Dx, R::Ax, R::Cx, 3, 0)?;
    x.load64(
        R::R8,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET,
    )?;
    x.cmp64(R::Dx, R::R8)?;
    x.branch(0x84, expand_pop)?;
    x.store64_index(R::Ax, R::Cx, 3, 0, R::R8)?;
    x.load8_index(R::Ax, R::Bp, R::Cx, layout.roles_offset)?;
    x.cmp32_imm(R::Ax, ROLE_ACCEPT.into())?;
    let not_accept = x.asm.label()?;
    x.branch(0x85, not_accept)?;
    x.load64(R::Dx, R::Sp, L_THREAD_START)?;
    x.store64(
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_START_OFFSET,
        R::Dx,
    )?;
    x.load64(R::Dx, R::Sp, L_POSITION)?;
    x.store64(
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_END_OFFSET,
        R::Dx,
    )?;
    x.store_mem32_value(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET, 1)?;
    x.jump(after_roots)?;
    x.asm.bind(not_accept)?;
    x.cmp32_imm(R::Ax, ROLE_CONSUME.into())?;
    x.branch(0x85, split_edges)?;
    x.load64(
        R::Cx,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
    )?;
    x.cmp64_imm(R::Cx, states)?;
    x.branch(0x83, runtime_failure)?;
    x.load64(R::Ax, R::Sp, L_CURRENT)?;
    x.shl64_imm(R::Cx, 4)?;
    x.add64(R::Ax, R::Cx)?;
    x.load64(R::Dx, R::Sp, L_THREAD_STATE)?;
    x.store32(R::Ax, 0, R::Dx)?;
    x.store_mem32_value(R::Ax, 4, 0)?;
    x.load64(R::Dx, R::Sp, L_THREAD_START)?;
    x.store64(R::Ax, 8, R::Dx)?;
    x.load64(
        R::Cx,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
    )?;
    x.inc64(R::Cx)?;
    x.store64(
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
        R::Cx,
    )?;
    x.jump(expand_pop)?;

    x.asm.bind(split_edges)?;
    x.cmp32_imm(R::Ax, ROLE_SPLIT.into())?;
    x.branch(0x85, runtime_failure)?;
    x.load64(R::Cx, R::Sp, L_THREAD_STATE)?;
    x.load32_index(R::Ax, R::Bp, R::Cx, 2, layout.edge_offsets_offset)?;
    x.load32_index(R::Dx, R::Bp, R::Cx, 2, layout.edge_offsets_offset + 4)?;
    x.cmp32(R::Ax, R::Dx)?;
    x.branch(0x87, runtime_failure)?;
    x.cmp32_imm(R::Dx, edges)?;
    x.branch(0x87, runtime_failure)?;
    x.store64(R::Sp, L_EDGE_END, R::Ax)?;
    x.store64(R::Sp, L_EDGE_INDEX, R::Dx)?;

    x.asm.bind(split_next)?;
    x.load64(R::Cx, R::Sp, L_EDGE_INDEX)?;
    x.load64(R::Dx, R::Sp, L_EDGE_END)?;
    x.cmp64(R::Cx, R::Dx)?;
    x.branch(0x84, expand_pop)?;
    x.dec64(R::Cx)?;
    x.store64(R::Sp, L_EDGE_INDEX, R::Cx)?;
    x.load8_index(R::Ax, R::Bp, R::Cx, layout.edge_kinds_offset)?;
    x.cmp32_imm(R::Ax, EDGE_EPSILON.into())?;
    x.branch(0x84, split_assertion_passed)?;
    if layout.cache_boundary_assertions {
        let cache_miss = x.asm.label()?;
        x.cmp32_imm(R::Ax, 2)?;
        x.branch(0x82, runtime_failure)?;
        x.cmp32_imm(R::Ax, 19)?;
        x.branch(0x87, runtime_failure)?;
        x.mov32(R::Cx, R::Ax)?;
        x.dec64(R::Cx)?;
        x.dec64(R::Cx)?;
        x.imm32(R::R8, 1)?;
        x.shl32_cl(R::R8)?;
        x.imm32(R::R9, layout.assertion_kinds)?;
        x.test32(R::R9, R::R8)?;
        x.branch(0x84, runtime_failure)?;
        x.load32(R::R9, R::Sp, L_ASSERTION_KNOWN_MASK)?;
        x.test32(R::R9, R::R8)?;
        x.branch(0x84, cache_miss)?;
        x.load32(R::R9, R::Sp, L_ASSERTION_ENABLED_MASK)?;
        x.test32(R::R9, R::R8)?;
        x.branch(0x84, split_next)?;
        x.jump(split_assertion_passed)?;

        x.asm.bind(cache_miss)?;
        // The helper owns all caller-saved registers, so preserve the
        // validated bit in the final free frame slot across the cold call.
        x.store32(R::Sp, L_ASSERTION_BIT, R::R8)?;
        x.load64(R::Cx, R::Sp, L_POSITION)?;
        x.call(assertion)?;
        x.test64(R::Dx, R::Dx)?;
        x.branch(0x85, runtime_failure)?;
        x.load32(R::R8, R::Sp, L_ASSERTION_BIT)?;
        x.load32(R::R9, R::Sp, L_ASSERTION_KNOWN_MASK)?;
        x.or32(R::R9, R::R8)?;
        x.store32(R::Sp, L_ASSERTION_KNOWN_MASK, R::R9)?;
        x.test64(R::Ax, R::Ax)?;
        x.branch(0x84, split_next)?;
        x.load32(R::R9, R::Sp, L_ASSERTION_ENABLED_MASK)?;
        x.or32(R::R9, R::R8)?;
        x.store32(R::Sp, L_ASSERTION_ENABLED_MASK, R::R9)?;
        x.jump(split_assertion_passed)?;
    } else {
        x.load64(R::Cx, R::Sp, L_POSITION)?;
        x.call(assertion)?;
        x.test64(R::Dx, R::Dx)?;
        x.branch(0x85, runtime_failure)?;
        x.test64(R::Ax, R::Ax)?;
        x.branch(0x84, split_next)?;
    }
    x.asm.bind(split_assertion_passed)?;
    x.load64(R::Cx, R::Sp, L_EDGE_INDEX)?;
    x.load32_index(R::Dx, R::Bp, R::Cx, 2, layout.edge_targets_offset)?;
    x.cmp32_imm(R::Dx, states)?;
    x.branch(0x83, runtime_failure)?;
    x.load64(R::Cx, R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
    x.cmp64_imm(R::Cx, closure)?;
    x.branch(0x83, runtime_failure)?;
    x.load64(R::Ax, R::Sp, L_STACK)?;
    x.shl64_imm(R::Cx, 4)?;
    x.add64(R::Ax, R::Cx)?;
    x.store32(R::Ax, 0, R::Dx)?;
    x.store_mem32_value(R::Ax, 4, 0)?;
    x.load64(R::Dx, R::Sp, L_THREAD_START)?;
    x.store64(R::Ax, 8, R::Dx)?;
    x.load64(R::Cx, R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
    x.inc64(R::Cx)?;
    x.store64(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET, R::Cx)?;
    x.jump(split_next)?;

    x.asm.bind(expand_pop)?;
    x.load64(R::Cx, R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
    x.test64(R::Cx, R::Cx)?;
    x.branch(0x84, root_complete)?;
    x.dec64(R::Cx)?;
    x.store64(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET, R::Cx)?;
    x.load64(R::Ax, R::Sp, L_STACK)?;
    x.shl64_imm(R::Cx, 4)?;
    x.add64(R::Ax, R::Cx)?;
    x.load32(R::Dx, R::Ax, 0)?;
    x.store64(R::Sp, L_THREAD_STATE, R::Dx)?;
    x.load32(R::Dx, R::Ax, 4)?;
    x.test64(R::Dx, R::Dx)?;
    x.branch(0x85, runtime_failure)?;
    x.load64(R::Dx, R::Ax, 8)?;
    x.store64(R::Sp, L_THREAD_START, R::Dx)?;
    x.jump(expand_loop)?;

    x.asm.bind(root_complete)?;
    x.load64(R::Ax, R::Sp, L_ROOT_MODE)?;
    x.test64(R::Ax, R::Ax)?;
    x.branch(0x85, after_roots)?;
    x.jump(next_old_root)?;

    if let (Some(program), Some(labels)) = (start_program, start_labels.as_deref()) {
        emit_static_start_closure(
            &mut x,
            image,
            program,
            labels,
            assertion,
            after_roots,
            runtime_failure,
        )?;
    }

    x.asm.bind(after_roots)?;
    x.load64(
        R::Ax,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
    )?;
    x.test64(R::Ax, R::Ax)?;
    let has_current = x.asm.label()?;
    x.branch(0x85, has_current)?;
    x.load32(
        R::Dx,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET,
    )?;
    x.test64(R::Dx, R::Dx)?;
    x.branch(0x85, finish)?;
    x.load64(R::Dx, R::Sp, L_POSITION)?;
    x.cmp64(R::Dx, R::R14)?;
    x.branch(
        if layout.start_prefix.is_some() {
            0x83
        } else {
            0x84
        },
        finish,
    )?;
    if let Some(prefix) = layout.start_prefix {
        let scan_next = x.asm.label()?;
        let scan_hit = x.asm.label()?;
        x.asm.bind(scan_next)?;
        x.inc64(R::Dx)?;
        x.cmp64(R::Dx, R::R14)?;
        x.branch(0x83, finish)?;
        x.load8_index(R::Ax, R::R12, R::Dx, 0)?;
        emit_start_prefix_membership(&mut x, prefix, R::Ax, scan_hit, scan_next)?;
        x.asm.bind(scan_hit)?;
        x.store64(R::Sp, L_POSITION, R::Dx)?;
        x.jump(boundary)?;
    }
    x.asm.bind(has_current)?;
    x.load64(R::Dx, R::Sp, L_POSITION)?;
    x.cmp64(R::Dx, R::R14)?;
    x.branch(
        if layout.start_prefix.is_some() {
            0x83
        } else {
            0x84
        },
        finish,
    )?;
    x.jump(consume_start)?;

    x.asm.bind(consume_start)?;
    x.load64(R::Cx, R::Sp, L_POSITION)?;
    x.load8_index(R::Ax, R::R12, R::Cx, 0)?;
    x.store64(R::Sp, L_BYTE, R::Ax)?;
    x.store_mem64_zero(R::Sp, L_CURRENT_INDEX)?;

    x.asm.bind(consume_thread)?;
    x.load64(R::Cx, R::Sp, L_CURRENT_INDEX)?;
    x.load64(
        R::Dx,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
    )?;
    x.cmp64(R::Cx, R::Dx)?;
    let consumed_boundary = x.asm.label()?;
    x.branch(0x83, consumed_boundary)?;
    x.load64(R::Ax, R::Sp, L_CURRENT)?;
    x.shl64_imm(R::Cx, 4)?;
    x.add64(R::Ax, R::Cx)?;
    x.load32(R::Dx, R::Ax, 0)?;
    x.store64(R::Sp, L_THREAD_STATE, R::Dx)?;
    x.load32(R::Dx, R::Ax, 4)?;
    x.test64(R::Dx, R::Dx)?;
    x.branch(0x85, runtime_failure)?;
    x.load64(R::Dx, R::Ax, 8)?;
    x.store64(R::Sp, L_THREAD_START, R::Dx)?;
    x.load64(R::Cx, R::Sp, L_THREAD_STATE)?;
    x.cmp64_imm(R::Cx, states)?;
    x.branch(0x83, runtime_failure)?;
    if let Some(dispatch) = layout.ordered_edge_dispatch {
        let scalar_setup = x.asm.label()?;
        let nonfinal_segment = x.asm.label()?;
        let final_nonlast_row = x.asm.label()?;
        let have_end = x.asm.label()?;
        let transition_loop = x.asm.label()?;
        let transition_done = x.asm.label()?;

        // Load the exact packed row words. Only the all-ones sentinel may
        // select the incumbent scalar scan; every malformed present row is a
        // runtime failure.
        x.load32_index(R::Ax, R::Bp, R::Cx, 3, dispatch.rows_offset)?;
        x.cmp32_imm(R::Ax, u32::MAX)?;
        x.branch(0x84, scalar_setup)?;
        x.load32_index(R::Dx, R::Bp, R::Cx, 3, dispatch.rows_offset + 4)?;
        x.and32_imm(R::Ax, 0x00ff_ffff)?;
        x.test64(R::Ax, R::Ax)?;
        x.branch(0x84, runtime_failure)?;
        x.mov32(R::R8, R::Dx)?;
        x.and32_imm(R::R8, 0x00ff_ffff)?;
        x.cmp32_imm(R::R8, u32::try_from(dispatch.admitted_rows).unwrap())?;
        x.branch(0x83, runtime_failure)?;
        x.shr32_imm(R::Dx, 24)?;

        // Map this byte to the row-local segment.
        x.mov64(R::R11, R::R8)?;
        x.shl64_imm(R::R8, 8)?;
        x.load64(R::R9, R::Sp, L_BYTE)?;
        x.add64(R::R8, R::R9)?;
        x.load8_index(R::R10, R::Bp, R::R8, dispatch.byte_map_offset)?;
        x.cmp32(R::R10, R::Dx)?;
        x.branch(0x87, runtime_failure)?;
        x.add64(R::Ax, R::R10)?;
        x.cmp64_imm(R::Ax, u32::try_from(dispatch.metadata_count).unwrap())?;
        x.branch(0x83, runtime_failure)?;
        x.load32_index(R::R9, R::Bp, R::Ax, 2, dispatch.metadata_offset)?;
        x.cmp32(R::R10, R::Dx)?;
        x.branch(0x82, nonfinal_segment)?;
        x.inc64(R::R11)?;
        x.cmp64_imm(R::R11, u32::try_from(dispatch.admitted_rows).unwrap())?;
        x.branch(0x82, final_nonlast_row)?;
        x.imm32(R::R10, u32::try_from(dispatch.transition_count).unwrap())?;
        x.jump(have_end)?;

        x.asm.bind(nonfinal_segment)?;
        x.inc64(R::Ax)?;
        x.cmp64_imm(R::Ax, u32::try_from(dispatch.metadata_count).unwrap())?;
        x.branch(0x83, runtime_failure)?;
        x.load32_index(R::R10, R::Bp, R::Ax, 2, dispatch.metadata_offset)?;
        x.jump(have_end)?;

        x.asm.bind(final_nonlast_row)?;
        x.inc64(R::Ax)?;
        x.inc64(R::Ax)?;
        x.cmp64_imm(R::Ax, u32::try_from(dispatch.metadata_count).unwrap())?;
        x.branch(0x83, runtime_failure)?;
        x.load32_index(R::R10, R::Bp, R::Ax, 2, dispatch.metadata_offset)?;

        x.asm.bind(have_end)?;
        x.cmp32(R::R9, R::R10)?;
        x.branch(0x87, runtime_failure)?;
        x.cmp32_imm(R::R10, u32::try_from(dispatch.transition_count).unwrap())?;
        x.branch(0x87, runtime_failure)?;
        x.cmp32(R::R9, R::R10)?;
        x.branch(0x84, consume_next_thread)?;
        x.load64(
            R::R11,
            R::Bx,
            FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET,
        )?;
        x.mov64(R::R8, R::R10)?;
        x.sub64(R::R8, R::R9)?;
        x.add64(R::R8, R::R11)?;
        x.cmp64_imm(R::R8, edges)?;
        x.branch(0x87, runtime_failure)?;

        x.asm.bind(transition_loop)?;
        x.cmp64(R::R9, R::R10)?;
        x.branch(0x83, transition_done)?;
        match dispatch.encoding {
            crate::ordered_nfa_native::NativeOrderedEdgeEncoding::Direct32 { target_bits } => {
                x.load32_index(
                    R::Dx,
                    R::Bp,
                    R::R9,
                    2,
                    dispatch.transitions_offset,
                )?;
                let mask = if target_bits == 0 {
                    0
                } else {
                    (1_u32 << target_bits) - 1
                };
                x.and32_imm(R::Dx, mask)?;
            }
            crate::ordered_nfa_native::NativeOrderedEdgeEncoding::Direct64 => {
                x.load64_index(
                    R::Dx,
                    R::Bp,
                    R::R9,
                    3,
                    dispatch.transitions_offset,
                )?;
            }
            crate::ordered_nfa_native::NativeOrderedEdgeEncoding::Legacy => {
                x.load32_index(
                    R::Dx,
                    R::Bp,
                    R::R9,
                    2,
                    dispatch.transitions_offset,
                )?;
                x.cmp32_imm(R::Dx, edges)?;
                x.branch(0x83, runtime_failure)?;
                x.load32_index(
                    R::Dx,
                    R::Bp,
                    R::Dx,
                    2,
                    layout.edge_targets_offset,
                )?;
            }
        }
        x.cmp32_imm(R::Dx, states)?;
        x.branch(0x83, runtime_failure)?;
        x.load64(R::Ax, R::Sp, L_ROOTS)?;
        x.mov64(R::Cx, R::R11)?;
        x.shl64_imm(R::Cx, 4)?;
        x.add64(R::Ax, R::Cx)?;
        x.store32(R::Ax, 0, R::Dx)?;
        x.store_mem32_value(R::Ax, 4, 0)?;
        x.load64(R::Dx, R::Sp, L_THREAD_START)?;
        x.store64(R::Ax, 8, R::Dx)?;
        x.inc64(R::R11)?;
        x.inc64(R::R9)?;
        x.jump(transition_loop)?;

        x.asm.bind(transition_done)?;
        x.store64(
            R::Bx,
            FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET,
            R::R11,
        )?;
        x.jump(consume_next_thread)?;
        x.asm.bind(scalar_setup)?;
    }
    x.load32_index(R::Ax, R::Bp, R::Cx, 2, layout.edge_offsets_offset)?;
    x.load32_index(R::Dx, R::Bp, R::Cx, 2, layout.edge_offsets_offset + 4)?;
    x.cmp32(R::Ax, R::Dx)?;
    x.branch(0x87, runtime_failure)?;
    x.cmp32_imm(R::Dx, edges)?;
    x.branch(0x87, runtime_failure)?;
    x.store64(R::Sp, L_EDGE_INDEX, R::Ax)?;
    x.store64(R::Sp, L_EDGE_END, R::Dx)?;

    x.asm.bind(consume_edge)?;
    x.load64(R::Cx, R::Sp, L_EDGE_INDEX)?;
    x.load64(R::Dx, R::Sp, L_EDGE_END)?;
    x.cmp64(R::Cx, R::Dx)?;
    x.branch(0x83, consume_next_thread)?;
    x.load8_index(R::Ax, R::Bp, R::Cx, layout.edge_kinds_offset)?;
    x.cmp32_imm(R::Ax, EDGE_BYTE_RANGE.into())?;
    x.branch(0x85, runtime_failure)?;
    x.load64(R::Ax, R::Sp, L_BYTE)?;
    x.load8_index(R::R8, R::Bp, R::Cx, layout.byte_starts_offset)?;
    x.cmp32(R::Ax, R::R8)?;
    x.branch(0x82, consume_next_edge)?;
    x.load8_index(R::R8, R::Bp, R::Cx, layout.byte_ends_offset)?;
    x.cmp32(R::Ax, R::R8)?;
    x.branch(0x87, consume_next_edge)?;
    x.load32_index(R::Dx, R::Bp, R::Cx, 2, layout.edge_targets_offset)?;
    x.cmp32_imm(R::Dx, states)?;
    x.branch(0x83, runtime_failure)?;
    x.load64(R::Cx, R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET)?;
    x.cmp64_imm(R::Cx, edges)?;
    x.branch(0x83, runtime_failure)?;
    x.load64(R::Ax, R::Sp, L_ROOTS)?;
    x.shl64_imm(R::Cx, 4)?;
    x.add64(R::Ax, R::Cx)?;
    x.store32(R::Ax, 0, R::Dx)?;
    x.store_mem32_value(R::Ax, 4, 0)?;
    x.load64(R::Dx, R::Sp, L_THREAD_START)?;
    x.store64(R::Ax, 8, R::Dx)?;
    x.load64(R::Cx, R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET)?;
    x.inc64(R::Cx)?;
    x.store64(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET, R::Cx)?;

    x.asm.bind(consume_next_edge)?;
    x.load64(R::Cx, R::Sp, L_EDGE_INDEX)?;
    x.inc64(R::Cx)?;
    x.store64(R::Sp, L_EDGE_INDEX, R::Cx)?;
    x.jump(consume_edge)?;

    x.asm.bind(consume_next_thread)?;
    x.load64(R::Cx, R::Sp, L_CURRENT_INDEX)?;
    x.inc64(R::Cx)?;
    x.store64(R::Sp, L_CURRENT_INDEX, R::Cx)?;
    x.jump(consume_thread)?;

    x.asm.bind(consumed_boundary)?;
    x.load64(R::Ax, R::Sp, L_POSITION)?;
    x.inc64(R::Ax)?;
    x.store64(R::Sp, L_POSITION, R::Ax)?;
    x.jump(boundary)?;

    x.asm.bind(finish)?;
    x.load32(
        R::Ax,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET,
    )?;
    x.test64(R::Ax, R::Ax)?;
    x.branch(0x84, no_match)?;
    x.load64(
        R::Ax,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_START_OFFSET,
    )?;
    x.store64(R::R15, 0, R::Ax)?;
    x.load64(
        R::Ax,
        R::Bx,
        FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_END_OFFSET,
    )?;
    x.store64(R::R15, 8, R::Ax)?;
    x.jump(matched)
}

/// Emit the x86-64 SysV private/public V15 one-Span search entry.
pub(super) fn lower_x86_64(
    image: &NativeOrderedNfaObjectImage<'_>,
) -> Result<OrderedNfaNativeEntry, ObjectError> {
    lower_x86_64_with_surface(image, OrderedNfaEntrySurface::Compatibility)
}

/// Emit only the private V15 search and its source-free capability gate.
///
/// Unlike [`lower_x86_64`], this fragment has no ordinary public adapter and
/// no compatibility fallback relocation. It is therefore suitable for a
/// whole-operation object whose sole global function is an enclosing reducer.
pub(super) fn lower_x86_64_operation_only(
    image: &NativeOrderedNfaObjectImage<'_>,
) -> Result<OrderedNfaNativeEntry, ObjectError> {
    lower_x86_64_with_surface(image, OrderedNfaEntrySurface::OperationOnly)
}

fn lower_x86_64_with_surface(
    image: &NativeOrderedNfaObjectImage<'_>,
    surface: OrderedNfaEntrySurface,
) -> Result<OrderedNfaNativeEntry, ObjectError> {
    // The fragmented terminal proof is aggregate-only. Revalidate it here so
    // a forged compiler-only receipt still fails closed, but do not let it
    // change the shared/public/private one-Span entry.
    let _ = image.terminal_exact_set_plan()?;
    let layout = image.layout;
    let expected_scratch_bytes = scratch_bytes(layout)?;
    let mut asm = X86Assembler::new();
    let invalid_argument = asm.label()?;
    let invalid_handle = asm.label()?;
    let runtime_failure = asm.label()?;
    let no_match = asm.label()?;
    let matched = asm.label()?;
    let after_generation_clear = asm.label()?;
    let clear_generation = asm.label()?;
    let clear_generation_loop = asm.label()?;
    let clear_generation_store = asm.label()?;
    let search_entry = asm.label()?;
    let terminal_scan = if layout.terminal_range.is_some() {
        Some(asm.label()?)
    } else {
        None
    };
    let shared_auth = asm.label()?;
    let public_fallback = asm.label()?;
    let public_fallback_displacement = asm.label()?;
    let public_table_displacement = asm.label()?;
    let private_entry = asm.label()?;
    let private_table_displacement = asm.label()?;
    let bulk_gate_entry = asm.label()?;
    let bulk_gate_table_displacement = asm.label()?;
    let bulk_gate_claimed = asm.label()?;
    let bulk_gate_legacy = asm.label()?;
    let assertion = asm.label()?;
    let authenticated_search = asm.label()?;
    let unicode_helpers = if image.layout.unicode_ranges_offset.is_some() {
        Some((asm.label()?, asm.label()?, asm.label()?, asm.label()?))
    } else {
        None
    };

    if surface == OrderedNfaEntrySurface::Compatibility {
        emit_prologue_and_raw_checks(
            &mut asm,
            public_table_displacement,
            invalid_argument,
            invalid_handle,
        )?;
        {
            let mut x = X { asm: &mut asm };
            emit_exact_object_auth(&mut x, layout, runtime_failure)?;
            emit_common_header_identity_auth(&mut x, runtime_failure)?;
            // A V15 claim is sticky: any one of the flag, ready seal, or
            // format discriminator commits the call to exact native
            // authentication. A revoked or malformed claimant returns status
            // 3 and never deopts.
            emit_v15_claim_classifier(&mut x, shared_auth, public_fallback)?;
        }
    }

    asm.bind(private_entry)?;
    emit_prologue_and_raw_checks(
        &mut asm,
        private_table_displacement,
        invalid_argument,
        invalid_handle,
    )?;
    {
        let mut x = X { asm: &mut asm };
        if surface == OrderedNfaEntrySurface::OperationOnly {
            emit_trusted_aggregate_scratch_setup(&mut x)?;
            x.jump(authenticated_search)?;
        } else {
            x.jump(shared_auth)?;
        }
    }

    asm.bind(bulk_gate_entry)?;
    emit_bulk_gate_prologue(&mut asm, bulk_gate_table_displacement, invalid_handle)?;
    {
        let mut x = X { asm: &mut asm };
        emit_exact_object_auth(&mut x, layout, runtime_failure)?;
        emit_common_header_identity_auth(&mut x, runtime_failure)?;
        emit_v15_claim_classifier(&mut x, bulk_gate_claimed, bulk_gate_legacy)?;
    }
    asm.bind(bulk_gate_claimed)?;
    {
        let mut x = X { asm: &mut asm };
        emit_exact_header_auth(&mut x, layout, expected_scratch_bytes, runtime_failure)?;
        x.load64(
            R::Ax,
            R::Bx,
            FROZEN_PREPARED_HEADER_V1_FORWARD_ROWS_ADDRESS_OFFSET,
        )?;
        x.mov64(R::Bx, R::Ax)?;
        emit_exact_scratch_auth(&mut x, layout, expected_scratch_bytes, runtime_failure)?;
        x.jump(matched)?;
    }
    asm.bind(bulk_gate_legacy)?;
    {
        let mut x = X { asm: &mut asm };
        x.imm32(R::Ax, STATUS_NO_MATCH)?;
        emit_return(&mut x)?;
    }

    asm.bind(shared_auth)?;
    {
        let mut x = X { asm: &mut asm };
        emit_exact_object_auth(&mut x, layout, runtime_failure)?;
        emit_exact_header_auth(&mut x, layout, expected_scratch_bytes, runtime_failure)?;
        x.load64(
            R::Ax,
            R::Bx,
            FROZEN_PREPARED_HEADER_V1_FORWARD_ROWS_ADDRESS_OFFSET,
        )?;
        x.mov64(R::Bx, R::Ax)?;
        emit_exact_scratch_auth(&mut x, layout, expected_scratch_bytes, runtime_failure)?;
    }
    asm.bind(authenticated_search)?;
    {
        let mut x = X { asm: &mut asm };
        if let Some(bounds) = layout.whole_window_width_bounds {
            emit_whole_window_width_gate(&mut x, bounds, no_match)?;
        }

        // Complete generation-overflow preflight before any source byte read.
        x.mov64(R::Ax, R::R14)?;
        x.load64(R::Cx, R::Sp, L_POSITION)?;
        x.sub64(R::Ax, R::Cx)?;
        x.inc64(R::Ax)?;
        x.imm64(R::Dx, u64::MAX)?;
        x.sub64(R::Dx, R::Ax)?;
        x.load64(
            R::Cx,
            R::Bx,
            FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET,
        )?;
        x.cmp64(R::Cx, R::Dx)?;
        x.branch(0x87, clear_generation)?;
        x.jump(after_generation_clear)?;
    }

    if surface == OrderedNfaEntrySurface::Compatibility {
        asm.bind(public_fallback)?;
        {
            let mut x = X { asm: &mut asm };
            x.load64(R::Di, R::Sp, L_HEADER)?;
            x.mov64(R::Si, R::R12)?;
            x.mov64(R::Dx, R::R13)?;
            x.load64(R::Cx, R::Sp, L_POSITION)?;
            x.mov64(R::R8, R::R14)?;
            x.mov64(R::R9, R::R15)?;
            emit_epilogue(&mut x)?;
            x.op(&[0xe9])?;
            x.asm.bind(public_fallback_displacement)?;
            push_bytes(&mut x.asm.code, &[0; 4])?;
        }
    }
    asm.bind(clear_generation)?;
    {
        let mut x = X { asm: &mut asm };
        x.xor32(R::Cx, R::Cx)?;
    }
    asm.bind(clear_generation_loop)?;
    {
        let mut x = X { asm: &mut asm };
        x.cmp64_imm(R::Cx, u32::try_from(layout.state_count).unwrap())?;
        x.branch(0x83, clear_generation_store)?;
        x.load64(R::Ax, R::Sp, L_SEEN)?;
        x.xor32(R::Dx, R::Dx)?;
        x.store64_index(R::Ax, R::Cx, 3, 0, R::Dx)?;
        x.inc64(R::Cx)?;
        x.jump(clear_generation_loop)?;
    }
    asm.bind(clear_generation_store)?;
    {
        let mut x = X { asm: &mut asm };
        x.store_mem64_zero(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET)?;
        x.jump(after_generation_clear)?;
    }
    asm.bind(after_generation_clear)?;
    {
        let mut x = X { asm: &mut asm };
        // Reset invocation-local logical lengths and pending result.
        x.store_mem64_zero(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET)?;
        x.store_mem64_zero(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET)?;
        x.store_mem64_zero(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET)?;
        x.store_mem64_zero(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_START_OFFSET)?;
        x.store_mem64_zero(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_END_OFFSET)?;
        x.store_mem32_value(R::Bx, FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET, 0)?;
        if let Some(scan) = terminal_scan {
            x.mov64(R::Cx, R::R14)?;
            x.jump(scan)?;
        } else {
            x.jump(search_entry)?;
        }
    }

    if let (Some(scan), Some(range)) = (terminal_scan, layout.terminal_range) {
        asm.bind(scan)?;
        let mut x = X { asm: &mut asm };
        x.load64(R::Dx, R::Sp, L_POSITION)?;
        x.cmp64(R::Cx, R::Dx)?;
        x.branch(0x86, no_match)?;
        x.dec64(R::Cx)?;
        x.load8_index(R::Ax, R::R12, R::Cx, 0)?;
        x.cmp32_imm(R::Ax, u32::from(range.start))?;
        x.branch(0x82, scan)?;
        x.cmp32_imm(R::Ax, u32::from(range.end))?;
        x.branch(0x87, scan)?;
        x.inc64(R::Cx)?;
        x.mov64(R::R14, R::Cx)?;
        x.jump(search_entry)?;
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
        let mut x = X { asm: &mut asm };
        x.store_mem64_zero(R::R15, 0)?;
        x.store_mem64_zero(R::R15, 8)?;
        x.imm32(R::Ax, STATUS_NO_MATCH)?;
        emit_return(&mut x)?;
    }
    asm.bind(matched)?;
    {
        let mut x = X { asm: &mut asm };
        x.imm32(R::Ax, STATUS_MATCH)?;
        emit_return(&mut x)?;
    }
    asm.bind(invalid_argument)?;
    {
        let mut x = X { asm: &mut asm };
        x.imm32(R::Ax, STATUS_INVALID_ARGUMENT)?;
        emit_return(&mut x)?;
    }
    asm.bind(invalid_handle)?;
    {
        let mut x = X { asm: &mut asm };
        x.imm32(R::Ax, STATUS_INVALID_HANDLE)?;
        emit_return(&mut x)?;
    }
    asm.bind(runtime_failure)?;
    {
        let mut x = X { asm: &mut asm };
        x.imm32(R::Ax, STATUS_RUNTIME_FAILURE)?;
        emit_return(&mut x)?;
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
    let finished = asm.finish_with_label_offsets()?;
    let public_table_displacement = (surface == OrderedNfaEntrySurface::Compatibility)
        .then(|| finished.label_offset(public_table_displacement))
        .transpose()?;
    let private_table_displacement = finished.label_offset(private_table_displacement)?;
    let bulk_gate_table_displacement = finished.label_offset(bulk_gate_table_displacement)?;
    let public_fallback_displacement = (surface == OrderedNfaEntrySurface::Compatibility)
        .then(|| finished.label_offset(public_fallback_displacement))
        .transpose()?;
    let private_entry_offset = finished.label_offset(private_entry)?;
    let bulk_gate_entry_offset = finished.label_offset(bulk_gate_entry)?;
    let mut relocations = Vec::with_capacity(if surface == OrderedNfaEntrySurface::Compatibility {
        4
    } else {
        2
    });
    if let Some(public_table_displacement) = public_table_displacement {
        relocations.push(ModuleRelocation {
            section: TEXT_SECTION,
            offset: u64::try_from(public_table_displacement).map_err(|_| {
                ObjectError::ArithmeticOverflow("x86 Ordered-NFA public table relocation")
            })?,
            kind: RelocationKind::X86PcRelative32,
            symbol: PARTIAL_TABLE_SYMBOL,
            addend: -4,
        });
    }
    relocations.push(ModuleRelocation {
        section: TEXT_SECTION,
        offset: u64::try_from(private_table_displacement).map_err(|_| {
            ObjectError::ArithmeticOverflow("x86 Ordered-NFA private table relocation")
        })?,
        kind: RelocationKind::X86PcRelative32,
        symbol: PARTIAL_TABLE_SYMBOL,
        addend: -4,
    });
    relocations.push(ModuleRelocation {
        section: TEXT_SECTION,
        offset: u64::try_from(bulk_gate_table_displacement).map_err(|_| {
            ObjectError::ArithmeticOverflow("x86 Ordered-NFA bulk-gate table relocation")
        })?,
        kind: RelocationKind::X86PcRelative32,
        symbol: PARTIAL_TABLE_SYMBOL,
        addend: -4,
    });
    if let Some(public_fallback_displacement) = public_fallback_displacement {
        relocations.push(ModuleRelocation {
            section: TEXT_SECTION,
            offset: u64::try_from(public_fallback_displacement).map_err(|_| {
                ObjectError::ArithmeticOverflow("x86 Ordered-NFA fallback relocation")
            })?,
            kind: RelocationKind::X86PltRelative32,
            symbol: PREPARED_FALLBACK_RUNTIME_SYMBOL,
            addend: -4,
        });
    }
    Ok(OrderedNfaNativeEntry {
        code: finished.code,
        relocations,
        private_entry_offset,
        bulk_gate_entry_offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;

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
                whole_window_width_bounds: None,
                line_terminator: b'\n',
                ordered_edge_dispatch: None,
                terminal_range: None,
            },
            terminal_exact_set_words: None,
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

    fn boundary_assertion_cache_image() -> NativeOrderedNfaObjectImage<'static> {
        let mut image = minimal_image();
        image.layout.assertion_kinds = 1 << 6;
        image.layout.cache_boundary_assertions = true;
        image
    }

    #[test]
    fn ordered_nfa_x86_unrolls_only_the_selected_start_closure() {
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
        let selected_entry = lower_x86_64(&selected).unwrap();
        let scalar_entry = lower_x86_64(&scalar).unwrap();
        assert!(selected_entry.code.len() > scalar_entry.code.len());
        assert_eq!(selected_entry.relocations, scalar_entry.relocations);
    }

    #[test]
    fn ordered_nfa_x86_emits_only_the_selected_start_prefix_fast_forward() {
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
        let selected_entry = lower_x86_64(&selected).unwrap();
        let scalar_entry = lower_x86_64(&scalar).unwrap();
        assert!(selected_entry.code.len() > scalar_entry.code.len());
        assert_eq!(selected_entry.relocations, scalar_entry.relocations);

        let mut signature_assembler = X86Assembler::new();
        {
            let mut signature = X {
                asm: &mut signature_assembler,
            };
            signature.load64(R::Dx, R::Sp, L_POSITION).unwrap();
            signature.cmp64(R::Dx, R::R14).unwrap();
        }
        let signature = signature_assembler.code;
        let end_conditions = |code: &[u8]| {
            code.windows(signature.len() + 2)
                .filter_map(|bytes| {
                    if !bytes.starts_with(&signature) {
                        return None;
                    }
                    match &bytes[signature.len()..] {
                        [0x74, _] | [0x0f, 0x84] => Some(0x84),
                        [0x73, _] | [0x0f, 0x83] => Some(0x83),
                        _ => None,
                    }
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(end_conditions(&scalar_entry.code), [0x84, 0x84]);
        assert_eq!(end_conditions(&selected_entry.code), [0x83, 0x83, 0x83]);
    }

    #[test]
    fn ordered_nfa_x86_emits_only_the_selected_whole_window_width_gate() {
        let program = optimizing_ordered_nfa(r"^.{249}$");
        let view = program.native_ordered_nfa_view().unwrap();
        let selected = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(
            selected.layout.whole_window_width_bounds,
            Some(WholeWindowWidthBounds {
                minimum: 249,
                maximum: 996,
            }),
        );
        let without = NativeOrderedNfaObjectImage::try_build(
            crate::ordered_nfa_native::NativeOrderedNfaProgramView {
                whole_window_width_bounds: None,
                ..view
            },
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.bytes, without.bytes);
        let selected_entry = lower_x86_64(&selected).unwrap();
        let without_entry = lower_x86_64(&without).unwrap();
        assert!(selected_entry.code.len() > without_entry.code.len());
        let relocation_semantics = |entry: &OrderedNfaNativeEntry| {
            entry
                .relocations
                .iter()
                .map(|relocation| {
                    (
                        relocation.section,
                        relocation.kind,
                        relocation.symbol,
                        relocation.addend,
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            relocation_semantics(&selected_entry),
            relocation_semantics(&without_entry),
        );

        let mut asm = X86Assembler::new();
        let no_match = asm.label().unwrap();
        emit_whole_window_width_gate(
            &mut X { asm: &mut asm },
            selected.layout.whole_window_width_bounds.unwrap(),
            no_match,
        )
        .unwrap();
        assert_eq!(asm.fixups.len(), 4);
        assert!(asm.fixups.iter().all(|fixup| fixup.label == no_match));
        assert!(asm
            .code
            .windows(8)
            .any(|bytes| bytes == 249_u64.to_le_bytes()));
        assert!(asm
            .code
            .windows(8)
            .any(|bytes| bytes == 996_u64.to_le_bytes()));
    }

    #[test]
    fn ordered_nfa_x86_start_prefix_membership_has_hit_and_miss_edges() {
        let program = optimizing_ordered_nfa(r"a?b?c?d?e?f?g?h?[a-z]x");
        let image = NativeOrderedNfaObjectImage::try_build(
            program.native_ordered_nfa_view().unwrap(),
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        let prefix = image.layout.start_prefix.unwrap();
        let mut asm = X86Assembler::new();
        let matched = asm.label().unwrap();
        let missed = asm.label().unwrap();
        emit_start_prefix_membership(&mut X { asm: &mut asm }, prefix, R::Ax, matched, missed)
            .unwrap();

        assert_eq!(asm.fixups.len(), 3);
        assert_eq!(asm.fixups[1].label, matched);
        assert_eq!(asm.fixups[2].label, missed);
        assert!(asm
            .code
            .windows(6)
            .any(|bytes| bytes == [0x81, 0xf8, b'a', 0, 0, 0]));
        assert!(asm
            .code
            .windows(6)
            .any(|bytes| bytes == [0x81, 0xf8, b'z', 0, 0, 0]));

        asm.bind(matched).unwrap();
        asm.instruction(&[0xc3]).unwrap();
        asm.bind(missed).unwrap();
        asm.instruction(&[0xc3]).unwrap();
        assert!(!asm.finish().unwrap().is_empty());
    }

    #[test]
    fn ordered_nfa_x86_guarded_split_assertions_are_emitted_in_reverse_row_order() {
        let mut asm = X86Assembler::new();
        let assertion = asm.label().unwrap();
        let failure = asm.label().unwrap();
        emit_static_guarded_split_assertions(
            &mut X { asm: &mut asm },
            &[2, 0, 4, 3],
            0b111,
            assertion,
            failure,
        )
        .unwrap();
        let kinds = asm
            .code
            .windows(5)
            .enumerate()
            .filter(|(offset, window)| {
                window[0] == 0xb8
                    && offset.checked_sub(1).is_none_or(|i| asm.code[i] != 0x41)
            })
            .map(|(_, window)| u32::from_le_bytes(window[1..5].try_into().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(kinds, [3, 4, 2]);
    }

    #[test]
    fn ordered_nfa_x86_entry_has_public_private_gate_and_fallback_relocations() {
        let entry = lower_x86_64(&minimal_image()).unwrap();
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(&entry.code)),
            "8cdf9553af134536984f1e998684714d3980bdd827346adccdb9a9fa8ae647b6",
            "compatibility text must remain byte-identical to 979fc26e8",
        );
        assert!(!entry.code.is_empty());
        assert!(entry.private_entry_offset > 0);
        assert!(entry.private_entry_offset < entry.code.len());
        assert!(entry.bulk_gate_entry_offset > entry.private_entry_offset);
        assert!(entry.bulk_gate_entry_offset < entry.code.len());
        let prologue = [0x55, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57];
        assert_eq!(&entry.code[..prologue.len()], &prologue);
        assert_eq!(
            &entry.code[entry.private_entry_offset..entry.private_entry_offset + prologue.len()],
            &prologue,
        );
        assert_eq!(
            &entry.code
                [entry.bulk_gate_entry_offset..entry.bulk_gate_entry_offset + prologue.len()],
            &prologue,
        );
        assert_eq!(entry.relocations.len(), 4);
        assert_eq!(
            entry
                .relocations
                .iter()
                .map(|relocation| (relocation.kind, relocation.symbol, relocation.addend))
                .collect::<Vec<_>>(),
            vec![
                (RelocationKind::X86PcRelative32, PARTIAL_TABLE_SYMBOL, -4),
                (RelocationKind::X86PcRelative32, PARTIAL_TABLE_SYMBOL, -4),
                (RelocationKind::X86PcRelative32, PARTIAL_TABLE_SYMBOL, -4),
                (
                    RelocationKind::X86PltRelative32,
                    PREPARED_FALLBACK_RUNTIME_SYMBOL,
                    -4,
                ),
            ],
        );
        for relocation in &entry.relocations[..3] {
            let offset = usize::try_from(relocation.offset).unwrap();
            assert!(offset >= 3);
            assert_eq!(&entry.code[offset - 3..offset], &[0x48, 0x8d, 0x2d]);
            assert_eq!(&entry.code[offset..offset + 4], &[0; 4]);
        }
        let fallback = usize::try_from(entry.relocations[3].offset).unwrap();
        assert!(fallback >= 1);
        assert_eq!(entry.code[fallback - 1], 0xe9);
        assert_eq!(&entry.code[fallback..fallback + 4], &[0; 4]);
    }

    #[test]
    fn ordered_nfa_x86_operation_only_entry_has_closed_local_relocations() {
        let compatibility = lower_x86_64(&minimal_image()).unwrap();
        let operation = lower_x86_64_operation_only(&minimal_image()).unwrap();
        let reauthenticated = lower_x86_64_with_surface(
            &minimal_image(),
            OrderedNfaEntrySurface::OperationOnlyReauthenticate,
        )
        .unwrap();

        assert!(!operation.code.is_empty());
        assert!(operation.code.len() < compatibility.code.len());
        assert_eq!(operation.private_entry_offset, 0);
        assert!(operation.bulk_gate_entry_offset > operation.private_entry_offset);
        assert!(operation.bulk_gate_entry_offset < operation.code.len());
        assert_eq!(operation.relocations.len(), 2);
        assert!(operation.relocations.iter().all(|relocation| {
            relocation.section == TEXT_SECTION
                && relocation.kind == RelocationKind::X86PcRelative32
                && relocation.symbol == PARTIAL_TABLE_SYMBOL
                && relocation.addend == -4
        }));
        assert!(operation
            .relocations
            .iter()
            .all(|relocation| relocation.symbol != PREPARED_FALLBACK_RUNTIME_SYMBOL));
        assert_ne!(operation.code, reauthenticated.code);
        assert!(operation.bulk_gate_entry_offset > reauthenticated.bulk_gate_entry_offset);
        assert_ne!(operation.code.len(), reauthenticated.code.len());
        assert_eq!(operation.relocations.len(), reauthenticated.relocations.len());
        assert_eq!(
            operation
                .relocations
                .iter()
                .map(|relocation| (relocation.kind, relocation.symbol, relocation.addend))
                .collect::<Vec<_>>(),
            reauthenticated
                .relocations
                .iter()
                .map(|relocation| (relocation.kind, relocation.symbol, relocation.addend))
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn ordered_nfa_x86_terminal_range_emits_authenticated_reverse_scan() {
        let scalar = lower_x86_64(&minimal_image()).unwrap();
        let filtered = lower_x86_64(&terminal_range_image()).unwrap();
        assert!(filtered.code.len() > scalar.code.len());
        for immediate in [0x80_u32, 0xff] {
            let immediate = immediate.to_le_bytes();
            let needle = [0x81, 0xf8, immediate[0], immediate[1], immediate[2], immediate[3]];
            assert!(
                filtered.code.windows(needle.len()).any(|window| window == needle),
                "missing terminal-range comparison",
            );
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
    fn ordered_nfa_x86_terminal_exact_set_is_shared_entry_inert_but_validated() {
        let repeated = r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}";
        let pattern = format!(r"{repeated}[0-24-6]");
        let program = optimizing_ordered_nfa(&pattern);
        let view = program.native_ordered_nfa_view().unwrap();
        let selected = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        assert!(
            selected.terminal_exact_set_plan().unwrap().is_some(),
            "fragmented final column must retain its validated aggregate receipt",
        );
        assert!(selected.layout.terminal_range.is_none());

        let without = NativeOrderedNfaObjectImage::try_build(
            crate::ordered_nfa_native::NativeOrderedNfaProgramView {
                terminal_exact_set: None,
                ..view
            },
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.bytes, without.bytes);

        let selected_entry = lower_x86_64(&selected).unwrap();
        let without_entry = lower_x86_64(&without).unwrap();
        assert_eq!(selected_entry.code, without_entry.code);
        assert_eq!(selected_entry.relocations, without_entry.relocations);
        assert_eq!(
            selected_entry.private_entry_offset,
            without_entry.private_entry_offset,
        );
        assert_eq!(
            selected_entry.bulk_gate_entry_offset,
            without_entry.bulk_gate_entry_offset,
        );

        let mut overlap = selected.clone();
        overlap.layout.terminal_range =
            Some(crate::ordered_nfa_native::NativeOrderedNfaTerminalRangeV1 {
                start: b'a',
                end: b'z',
                reverse_depth: 0,
            });
        assert!(matches!(
            lower_x86_64(&overlap),
            Err(ObjectError::InvalidModule(
                "ordered-NFA terminal exact-set overlaps terminal range"
            ))
        ));

        let mut invalid = selected;
        invalid.terminal_exact_set_words = Some([0; 4]);
        assert!(matches!(
            lower_x86_64(&invalid),
            Err(ObjectError::InvalidModule(
                "ordered-NFA terminal exact-set proof"
            ))
        ));
    }

    #[test]
    fn ordered_nfa_x86_epsilon_edges_bypass_the_assertion_call() {
        let entry = lower_x86_64(&minimal_image()).unwrap();
        let prefix = [0x81, 0xf8, 0, 0, 0, 0];
        let reload_edge_index = [0x48, 0x8b, 0x8c, 0x24, 0x50, 0, 0, 0];
        let matches = entry
            .code
            .windows(prefix.len())
            .enumerate()
            .filter_map(|(offset, bytes)| {
                if bytes != prefix {
                    return None;
                }
                let branch = offset.checked_add(prefix.len())?;
                let (branch_end, displacement) = match entry.code.get(branch) {
                    Some(0x74) => (
                        branch.checked_add(2)?,
                        isize::from(i8::from_le_bytes([*entry.code.get(branch + 1)?])),
                    ),
                    Some(0x0f) if entry.code.get(branch + 1) == Some(&0x84) => (
                        branch.checked_add(6)?,
                        isize::try_from(i32::from_le_bytes(
                            entry.code.get(branch + 2..branch + 6)?.try_into().ok()?,
                        ))
                        .ok()?,
                    ),
                    _ => return None,
                };
                let target = branch_end.checked_add_signed(displacement)?;
                let target_end = target.checked_add(reload_edge_index.len())?;
                (target > branch_end
                    && entry.code.get(branch_end..target)?.contains(&0xe8)
                    && entry.code.get(target..target_end)? == reload_edge_index)
                    .then_some((branch_end, target))
            })
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "epsilon bypass must be unique");
        let (branch_end, target) = matches[0];
        assert!(entry.code[branch_end..target].contains(&0xe8));
        assert_eq!(&entry.code[target..target + 8], &reload_edge_index);
    }

    #[test]
    fn ordered_nfa_x86_boundary_assertion_cache_is_lazy_and_boundary_scoped() {
        let scalar = lower_x86_64(&minimal_image()).unwrap();
        let cached = lower_x86_64(&boundary_assertion_cache_image()).unwrap();
        assert!(cached.code.len() > scalar.code.len());

        let known_reset = [0xc7, 0x84, 0x24, 0x88, 0, 0, 0, 0, 0, 0, 0];
        let enabled_reset = [0xc7, 0x84, 0x24, 0x90, 0, 0, 0, 0, 0, 0, 0];
        for reset in [&known_reset[..], &enabled_reset[..]] {
            assert_eq!(
                cached
                    .code
                    .windows(reset.len())
                    .filter(|window| *window == reset)
                    .count(),
                1,
            );
            assert!(!scalar
                .code
                .windows(reset.len())
                .any(|window| window == reset));
        }

        // `shl r8d, cl` constructs the validated kind bit once; the miss path
        // spills and reloads it around the assertion helper call.
        let variable_kind_shift = [0x41, 0xd3, 0xe0];
        assert_eq!(
            cached
                .code
                .windows(variable_kind_shift.len())
                .filter(|window| *window == variable_kind_shift)
                .count(),
            1,
        );
        assert!(!scalar
            .code
            .windows(variable_kind_shift.len())
            .any(|window| window == variable_kind_shift));

        let asserted_kind_mask = [0x41, 0xb9, 0x40, 0, 0, 0, 0x45, 0x85, 0xc1];
        assert_eq!(
            cached
                .code
                .windows(asserted_kind_mask.len())
                .filter(|window| *window == asserted_kind_mask)
                .count(),
            1,
        );
        assert!(!scalar
            .code
            .windows(asserted_kind_mask.len())
            .any(|window| window == asserted_kind_mask));

        let bit_spill = [0x44, 0x89, 0x84, 0x24, 0x98, 0, 0, 0];
        let bit_reload = [0x44, 0x8b, 0x84, 0x24, 0x98, 0, 0, 0];
        for access in [&bit_spill[..], &bit_reload[..]] {
            assert_eq!(
                cached
                    .code
                    .windows(access.len())
                    .filter(|window| *window == access)
                    .count(),
                1,
            );
            assert!(!scalar
                .code
                .windows(access.len())
                .any(|window| window == access));
        }

        let known_update = [0x44, 0x89, 0x8c, 0x24, 0x88, 0, 0, 0];
        let enabled_update = [0x44, 0x89, 0x8c, 0x24, 0x90, 0, 0, 0];
        for update in [&known_update[..], &enabled_update[..]] {
            assert_eq!(
                cached
                    .code
                    .windows(update.len())
                    .filter(|window| *window == update)
                    .count(),
                1,
            );
            assert!(!scalar
                .code
                .windows(update.len())
                .any(|window| window == update));
        }
    }
}
