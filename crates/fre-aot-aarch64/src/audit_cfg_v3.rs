//! Independent decoded control-flow safety proof for Count-v3 images.
//!
//! The exact-template audit proves that decoded instructions equal a reviewed
//! policy. This module proves a different property: every reachable haystack
//! load is dominated by a non-wrapping cursor bound, and every decoded
//! backedge decreases a well-founded cursor or candidate-set measure. It does
//! not regenerate an emitter schedule.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all decoded offsets use checked arithmetic or bounded Count-v3 fields"
)]
#![allow(
    clippy::struct_excessive_bools,
    reason = "the verifier keeps independent one-bit provenance facts explicit for conservative joins"
)]

use core::mem::size_of;

use fre_exact_alloc::{CopyError, ExactVec};

use crate::{
    CodeLabelV3, ConditionV3, CountAotArithmeticSite, CountAotError, CountAotResource,
    DecodedInstructionV3,
};

const X0: u8 = 0;
const X1: u8 = 1;
const X3: u8 = 3;
const X4: u8 = 4;
const X5: u8 = 5;
const X6: u8 = 6;
const X7: u8 = 7;
const X8: u8 = 8;
const X9: u8 = 9;
const X15: u8 = 15;
const X16: u8 = 16;
const X17: u8 = 17;

const MAX_LITERAL_BYTES_V3: usize = 32;
const SVE_VL_BYTES_V3: u16 = 16;
const NO_PENDING_V3: usize = usize::MAX;
const TRACKED_GPRS_V3: [u8; 8] = [X5, X6, X7, X8, X9, X15, X16, X17];
const PREDICATE_REGISTERS_V3: usize = 16;
// A value cell can independently lose two candidate flags and then collapse
// to Unknown. Predicate cells have the same height. Compare, two bounds, and
// seven boolean facts and the active-loop cell each lose precision at most
// once. The extra one is first reachability. Joins never strengthen a stored
// cell, so this is a complete per-instruction enqueue bound rather than a
// heuristic iteration cap.
const VALUE_CELL_DEGRADES_V3: usize = 3;
const SCALAR_FACT_DEGRADES_V3: usize = 1 + 2 + 7 + 1;
const ABSTRACT_STATE_CHANGE_BUDGET_V3: usize = 1
    + TRACKED_GPRS_V3.len() * VALUE_CELL_DEGRADES_V3
    + PREDICATE_REGISTERS_V3 * VALUE_CELL_DEGRADES_V3
    + SCALAR_FACT_DEGRADES_V3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AbstractValueV3 {
    Unknown,
    HaystackBase,
    Length,
    Cursor,
    MaxStart,
    CursorOffset { minimum: u16, maximum: u16 },
    HaystackAddress { minimum: u16, maximum: u16 },
    RemainingToMax,
    RemainingToLength,
    PackedCandidateBits,
    CandidateMask { nonempty: bool, reduced: bool },
    ReversedCandidateMask,
    CandidateBitIndex,
    CandidateMaskMinusOne,
}

impl AbstractValueV3 {
    fn join(self, incoming: Self) -> Self {
        if self == incoming {
            return self;
        }
        match (self, incoming) {
            (
                Self::CandidateMask {
                    nonempty: left_nonempty,
                    reduced: left_reduced,
                },
                Self::CandidateMask {
                    nonempty: right_nonempty,
                    reduced: right_reduced,
                },
            ) => Self::CandidateMask {
                nonempty: left_nonempty && right_nonempty,
                reduced: left_reduced && right_reduced,
            },
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PredicateValueV3 {
    Unknown,
    AllVl16,
    Candidate { nonempty: bool, reduced: bool },
    PrefixBeforeFirst,
    PrefixThroughFirst,
}

impl PredicateValueV3 {
    fn join(self, incoming: Self) -> Self {
        if self == incoming {
            return self;
        }
        match (self, incoming) {
            (
                Self::Candidate {
                    nonempty: left_nonempty,
                    reduced: left_reduced,
                },
                Self::Candidate {
                    nonempty: right_nonempty,
                    reduced: right_reduced,
                },
            ) => Self::Candidate {
                nonempty: left_nonempty && right_nonempty,
                reduced: left_reduced && right_reduced,
            },
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompareFactV3 {
    None,
    LengthAgainstWidth,
    CursorAgainstMax,
    CursorAgainstLength,
    RemainingMax { minimum: u16 },
    RemainingLength { minimum: u16 },
    CandidateMaskAgainstZero { register: u8 },
    PredicateAgainstEmpty { predicate: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AbstractStateV3 {
    values: [AbstractValueV3; TRACKED_GPRS_V3.len()],
    predicates: [PredicateValueV3; PREDICATE_REGISTERS_V3],
    compare: CompareFactV3,
    max_slack: Option<u16>,
    length_remaining: Option<u16>,
    x0_is_haystack: bool,
    x1_is_length: bool,
    x3_is_cursor: bool,
    x4_is_max_start: bool,
    length_at_least_width: bool,
    cursor_advanced: bool,
    outer_loop_advanced: bool,
    active_loop_header: usize,
}

impl AbstractStateV3 {
    const fn entry() -> Self {
        Self {
            values: [AbstractValueV3::Unknown; TRACKED_GPRS_V3.len()],
            predicates: [PredicateValueV3::Unknown; PREDICATE_REGISTERS_V3],
            compare: CompareFactV3::None,
            max_slack: None,
            length_remaining: None,
            x0_is_haystack: true,
            x1_is_length: true,
            x3_is_cursor: false,
            x4_is_max_start: false,
            length_at_least_width: false,
            cursor_advanced: false,
            outer_loop_advanced: false,
            active_loop_header: NO_PENDING_V3,
        }
    }

    fn value(self, register: u8) -> AbstractValueV3 {
        match register {
            X0 if self.x0_is_haystack => AbstractValueV3::HaystackBase,
            X1 if self.x1_is_length => AbstractValueV3::Length,
            X3 if self.x3_is_cursor => AbstractValueV3::Cursor,
            X4 if self.x4_is_max_start => AbstractValueV3::MaxStart,
            _ => tracked_index_v3(register)
                .map_or(AbstractValueV3::Unknown, |index| self.values[index]),
        }
    }

    fn predicate(self, register: u8) -> PredicateValueV3 {
        self.predicates
            .get(usize::from(register))
            .copied()
            .unwrap_or(PredicateValueV3::Unknown)
    }

    fn set_predicate(&mut self, register: u8, value: PredicateValueV3) {
        if let Some(predicate) = self.predicates.get_mut(usize::from(register)) {
            *predicate = value;
        }
    }

    fn clobber_gpr(&mut self, register: u8) {
        match register {
            X0 => self.x0_is_haystack = false,
            X1 => {
                self.x1_is_length = false;
                self.length_remaining = None;
                self.length_at_least_width = false;
            }
            X3 => {
                self.x3_is_cursor = false;
                self.max_slack = None;
                self.length_remaining = None;
                self.cursor_advanced = false;
                self.invalidate_cursor_relative_values();
            }
            X4 => {
                self.x4_is_max_start = false;
                self.max_slack = None;
            }
            _ => {}
        }
        if let Some(index) = tracked_index_v3(register) {
            self.values[index] = AbstractValueV3::Unknown;
        }
    }

    fn write_value(&mut self, register: u8, value: AbstractValueV3) {
        self.clobber_gpr(register);
        if let Some(index) = tracked_index_v3(register) {
            self.values[index] = value;
        }
    }

    fn set_cursor_zero(&mut self) {
        self.clobber_gpr(X3);
        self.x3_is_cursor = true;
        self.max_slack = self.x4_is_max_start.then_some(0);
        self.length_remaining = self.x1_is_length.then_some(0);
        self.cursor_advanced = false;
    }

    fn set_max_start(&mut self) {
        self.clobber_gpr(X4);
        self.x4_is_max_start = true;
        self.max_slack = None;
    }

    fn invalidate_cursor_relative_values(&mut self) {
        for value in &mut self.values {
            if matches!(
                value,
                AbstractValueV3::CursorOffset { .. } | AbstractValueV3::HaystackAddress { .. }
            ) {
                *value = AbstractValueV3::Unknown;
            }
        }
    }

    fn advance_cursor(
        &mut self,
        source: AbstractValueV3,
        immediate: u16,
    ) -> Result<(), CountAotError> {
        let (minimum, maximum) = match source {
            AbstractValueV3::Cursor => (immediate, immediate),
            AbstractValueV3::CursorOffset { minimum, maximum } => (
                minimum
                    .checked_add(immediate)
                    .ok_or_else(audit_arithmetic_v3)?,
                maximum
                    .checked_add(immediate)
                    .ok_or_else(audit_arithmetic_v3)?,
            ),
            _ => {
                self.clobber_gpr(X3);
                return Ok(());
            }
        };
        self.max_slack = subtract_bound_v3(self.max_slack, maximum);
        self.length_remaining = subtract_bound_v3(self.length_remaining, maximum);
        self.invalidate_cursor_relative_values();
        self.x3_is_cursor = true;
        self.cursor_advanced |= minimum != 0;
        Ok(())
    }

    fn reset_loop_progress(&mut self) {
        self.cursor_advanced = false;
        for value in &mut self.values {
            if let AbstractValueV3::CandidateMask {
                nonempty,
                reduced: _,
            } = *value
            {
                *value = AbstractValueV3::CandidateMask {
                    nonempty,
                    reduced: false,
                };
            }
        }
        for predicate in &mut self.predicates {
            if let PredicateValueV3::Candidate {
                nonempty,
                reduced: _,
            } = *predicate
            {
                *predicate = PredicateValueV3::Candidate {
                    nonempty,
                    reduced: false,
                };
            }
        }
    }

    fn has_local_progress(self) -> bool {
        self.cursor_advanced
            || self
                .values
                .iter()
                .any(|value| matches!(value, AbstractValueV3::CandidateMask { reduced: true, .. }))
            || self.predicates.iter().any(|predicate| {
                matches!(predicate, PredicateValueV3::Candidate { reduced: true, .. })
            })
    }

    fn has_backedge_progress(self, target: usize) -> bool {
        self.has_local_progress() || (self.active_loop_header != target && self.outer_loop_advanced)
    }

    fn prepare_loop_entry(&mut self, source: usize, target: usize) {
        if self.active_loop_header == target {
            self.reset_loop_progress();
            return;
        }
        if target > source {
            self.outer_loop_advanced |= self.has_local_progress();
        } else {
            // A backward edge to a different header exits the current inner
            // scan mode. The edge check consumed the combined local/outer
            // measure; begin a fresh outer-loop iteration.
            self.outer_loop_advanced = false;
        }
        self.reset_loop_progress();
        self.active_loop_header = target;
    }

    fn join(&mut self, incoming: Self) -> bool {
        let before = *self;
        for (value, incoming) in self.values.iter_mut().zip(incoming.values) {
            *value = value.join(incoming);
        }
        for (predicate, incoming) in self.predicates.iter_mut().zip(incoming.predicates) {
            *predicate = predicate.join(incoming);
        }
        self.compare = if self.compare == incoming.compare {
            self.compare
        } else {
            CompareFactV3::None
        };
        self.max_slack = join_lower_bound_v3(self.max_slack, incoming.max_slack);
        self.length_remaining =
            join_lower_bound_v3(self.length_remaining, incoming.length_remaining);
        self.x0_is_haystack &= incoming.x0_is_haystack;
        self.x1_is_length &= incoming.x1_is_length;
        self.x3_is_cursor &= incoming.x3_is_cursor;
        self.x4_is_max_start &= incoming.x4_is_max_start;
        self.length_at_least_width &= incoming.length_at_least_width;
        self.cursor_advanced &= incoming.cursor_advanced;
        self.outer_loop_advanced &= incoming.outer_loop_advanced;
        self.active_loop_header = if self.active_loop_header == incoming.active_loop_header {
            self.active_loop_header
        } else {
            NO_PENDING_V3
        };
        *self != before
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SafetySlotV3 {
    state: AbstractStateV3,
    reachable: bool,
    loop_header: bool,
    queued: bool,
    next_pending: usize,
}

impl Default for SafetySlotV3 {
    fn default() -> Self {
        Self {
            state: AbstractStateV3::entry(),
            reachable: false,
            loop_header: false,
            queued: false,
            next_pending: NO_PENDING_V3,
        }
    }
}

type DecodedCfgInlineStateV3 = (
    AbstractStateV3,
    AbstractStateV3,
    SafetySlotV3,
    [usize; 8],
    [u64; 4],
    CountAotError,
);

/// Additional peak scratch required by the independent decoded-CFG proof.
pub(crate) fn decoded_cfg_safety_scratch_bytes_v3(
    instruction_count: usize,
) -> Result<u64, CountAotError> {
    let slots = instruction_count
        .checked_mul(size_of::<SafetySlotV3>())
        .ok_or_else(audit_arithmetic_v3)?;
    let total = slots
        .checked_add(size_of::<DecodedCfgInlineStateV3>())
        .ok_or_else(audit_arithmetic_v3)?;
    u64::try_from(total).map_err(|_| audit_arithmetic_v3())
}

/// Conservative source-dimension work bound for the decoded-CFG proof.
pub(crate) fn decoded_cfg_safety_work_upper_bound_v3(
    instruction_count: usize,
    label_count: usize,
) -> Result<u64, CountAotError> {
    let instructions = u64::try_from(instruction_count).map_err(|_| audit_arithmetic_v3())?;
    let labels = u64::try_from(label_count).map_err(|_| audit_arithmetic_v3())?;
    instructions
        .checked_mul(
            u64::try_from(ABSTRACT_STATE_CHANGE_BUDGET_V3)
                .map_err(|_| audit_arithmetic_v3())?
                .checked_add(labels)
                .and_then(|work| work.checked_add(16))
                .ok_or_else(audit_arithmetic_v3)?,
        )
        .and_then(|work| work.checked_add(labels.checked_mul(2)?))
        .and_then(|work| work.checked_add(32))
        .ok_or_else(audit_arithmetic_v3)
}

/// Prove decoded Count-v3 cursor/load bounds and loop progress without
/// regenerating the emitter's instruction schedule.
pub(crate) fn audit_decoded_cfg_safety_v3(
    decoded: &[DecodedInstructionV3],
    labels: &[CodeLabelV3],
    literal_width: usize,
) -> Result<(), CountAotError> {
    if decoded.is_empty() || literal_width > MAX_LITERAL_BYTES_V3 {
        return Err(invalid_v3("v3 decoded CFG dimensions"));
    }
    let mut slots = ExactVec::try_with_capacity(decoded.len()).map_err(map_scratch_error_v3)?;
    for _ in decoded {
        slots
            .try_push(SafetySlotV3::default())
            .map_err(|_| invalid_v3("v3 decoded CFG slot capacity"))?;
    }

    for (index, instruction) in decoded.iter().copied().enumerate() {
        if let Some(displacement) = direct_displacement_v3(instruction) {
            let target = branch_target_v3(index, displacement, decoded.len())?;
            let target_offset =
                u32::try_from(target.checked_mul(4).ok_or_else(audit_arithmetic_v3)?)
                    .map_err(|_| audit_arithmetic_v3())?;
            if labels.iter().all(|label| label.offset != target_offset) {
                return Err(invalid_v3("v3 decoded CFG target label"));
            }
            if target <= index {
                slots[target].loop_header = true;
            }
        }
    }

    slots[0].reachable = true;
    slots[0].state = AbstractStateV3::entry();
    if slots[0].loop_header {
        slots[0].state.prepare_loop_entry(0, 0);
    }

    let maximum_steps = decoded
        .len()
        .checked_mul(ABSTRACT_STATE_CHANGE_BUDGET_V3)
        .and_then(|work| work.checked_add(decoded.len()))
        .ok_or_else(audit_arithmetic_v3)?;
    let mut pending = NO_PENDING_V3;
    enqueue_v3(&mut slots, 0, &mut pending);
    let mut steps = 0_usize;
    while pending != NO_PENDING_V3 {
        steps = steps.checked_add(1).ok_or_else(audit_arithmetic_v3)?;
        if steps > maximum_steps {
            return Err(invalid_v3("v3 decoded CFG state-change bound"));
        }
        let index = pending;
        pending = slots[index].next_pending;
        slots[index].queued = false;
        slots[index].next_pending = NO_PENDING_V3;
        let state = slots[index].state;
        match decoded[index] {
            DecodedInstructionV3::Branch { displacement } => {
                let target = branch_target_v3(index, displacement, decoded.len())?;
                if target <= index && !state.has_backedge_progress(target) {
                    return Err(invalid_v3("v3 decoded CFG non-progressing backedge"));
                }
                propagate_v3(&mut slots, index, target, state, &mut pending);
            }
            DecodedInstructionV3::BranchCondition {
                condition,
                displacement,
            } => {
                let target = branch_target_v3(index, displacement, decoded.len())?;
                let (mut taken, mut fallthrough) = split_condition_v3(state, condition);
                taken.compare = CompareFactV3::None;
                fallthrough.compare = CompareFactV3::None;
                if target <= index && !taken.has_backedge_progress(target) {
                    return Err(invalid_v3("v3 decoded CFG non-progressing backedge"));
                }
                propagate_v3(&mut slots, index, target, taken, &mut pending);
                let next = index
                    .checked_add(1)
                    .filter(|next| *next < decoded.len())
                    .ok_or(invalid_v3("v3 decoded CFG conditional fallthrough"))?;
                propagate_v3(&mut slots, index, next, fallthrough, &mut pending);
            }
            DecodedInstructionV3::Return => {}
            instruction => {
                let mut next_state = state;
                execute_v3(&mut next_state, instruction, literal_width)?;
                let next = index
                    .checked_add(1)
                    .filter(|next| *next < decoded.len())
                    .ok_or(invalid_v3("v3 decoded CFG unterminated path"))?;
                propagate_v3(&mut slots, index, next, next_state, &mut pending);
            }
        }
    }
    for (instruction, slot) in decoded.iter().zip(slots.iter()) {
        if is_haystack_load_v3(*instruction) && !slot.reachable {
            return Err(invalid_v3("v3 decoded CFG unreachable load"));
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed decoded-ISA transfer keeps every provenance rule explicit and auditable"
)]
fn execute_v3(
    state: &mut AbstractStateV3,
    instruction: DecodedInstructionV3,
    literal_width: usize,
) -> Result<(), CountAotError> {
    state.compare = CompareFactV3::None;
    match instruction {
        DecodedInstructionV3::MoveZero64 {
            destination,
            immediate,
            ..
        } => {
            if destination == X3 && immediate == 0 {
                state.set_cursor_zero();
            } else {
                state.clobber_gpr(destination);
            }
        }
        DecodedInstructionV3::MoveKeep64 { destination, .. } => {
            state.clobber_gpr(destination);
        }
        DecodedInstructionV3::AddRegister64 {
            destination,
            left,
            right,
        } => {
            let left_value = state.value(left);
            let right_value = state.value(right);
            let result = add_values_v3(left_value, right_value);
            state.write_value(destination, result);
        }
        DecodedInstructionV3::AddImmediate64 {
            destination,
            source,
            immediate,
        } => {
            let source_value = state.value(source);
            if destination == X3 {
                state.advance_cursor(source_value, immediate)?;
            } else {
                let result = add_immediate_value_v3(source_value, immediate)?;
                state.write_value(destination, result);
            }
        }
        DecodedInstructionV3::SubtractRegister64 {
            destination,
            left,
            right,
        } => {
            let left_value = state.value(left);
            let right_value = state.value(right);
            let result = match (left_value, right_value) {
                (AbstractValueV3::MaxStart, AbstractValueV3::Cursor)
                    if state.max_slack.is_some() =>
                {
                    AbstractValueV3::RemainingToMax
                }
                (AbstractValueV3::Length, AbstractValueV3::Cursor)
                    if state.length_remaining.is_some() =>
                {
                    AbstractValueV3::RemainingToLength
                }
                _ => AbstractValueV3::Unknown,
            };
            state.write_value(destination, result);
        }
        DecodedInstructionV3::SubtractImmediate64 {
            destination,
            source,
            immediate,
        } => {
            let source_value = state.value(source);
            if destination == X4
                && source_value == AbstractValueV3::Length
                && usize::from(immediate) == literal_width
                && state.length_at_least_width
            {
                state.set_max_start();
            } else {
                let result = if destination == X16
                    && immediate == 1
                    && matches!(source_value, AbstractValueV3::CandidateMask { .. })
                {
                    AbstractValueV3::CandidateMaskMinusOne
                } else {
                    AbstractValueV3::Unknown
                };
                state.write_value(destination, result);
            }
        }
        DecodedInstructionV3::AndRegister64 {
            destination,
            left,
            right,
        } => {
            let left_value = state.value(left);
            let right_value = state.value(right);
            let result = match (destination, left, right, left_value, right_value) {
                (
                    X6,
                    X6,
                    X16,
                    AbstractValueV3::CandidateMask { nonempty: true, .. },
                    AbstractValueV3::CandidateMaskMinusOne,
                ) => AbstractValueV3::CandidateMask {
                    nonempty: false,
                    reduced: true,
                },
                (X6, X6, X17, AbstractValueV3::PackedCandidateBits, _) => {
                    AbstractValueV3::CandidateMask {
                        nonempty: false,
                        reduced: false,
                    }
                }
                _ => AbstractValueV3::Unknown,
            };
            state.write_value(destination, result);
        }
        DecodedInstructionV3::AndLowBits64 { destination, .. } => {
            state.clobber_gpr(destination);
        }
        DecodedInstructionV3::LogicalShiftRight64 {
            destination,
            source,
            shift,
        } => {
            let result = if destination == X7
                && source == X7
                && shift == 2
                && state.value(source) == AbstractValueV3::CandidateBitIndex
            {
                AbstractValueV3::CursorOffset {
                    minimum: 0,
                    maximum: 15,
                }
            } else {
                AbstractValueV3::Unknown
            };
            state.write_value(destination, result);
        }
        DecodedInstructionV3::ReverseBits64 {
            destination,
            source,
        } => {
            let result = match state.value(source) {
                AbstractValueV3::CandidateMask { nonempty: true, .. } => {
                    AbstractValueV3::ReversedCandidateMask
                }
                _ => AbstractValueV3::Unknown,
            };
            state.write_value(destination, result);
        }
        DecodedInstructionV3::CountLeadingZeros64 {
            destination,
            source,
        } => {
            let result = if state.value(source) == AbstractValueV3::ReversedCandidateMask {
                AbstractValueV3::CandidateBitIndex
            } else {
                AbstractValueV3::Unknown
            };
            state.write_value(destination, result);
        }
        DecodedInstructionV3::CompareRegister64 { left, right } => {
            state.compare = match (state.value(left), state.value(right)) {
                (AbstractValueV3::Cursor, AbstractValueV3::MaxStart) => {
                    CompareFactV3::CursorAgainstMax
                }
                (AbstractValueV3::Cursor, AbstractValueV3::Length) => {
                    CompareFactV3::CursorAgainstLength
                }
                _ => CompareFactV3::None,
            };
        }
        DecodedInstructionV3::CompareImmediate64 {
            register,
            immediate,
        } => {
            state.compare = match state.value(register) {
                AbstractValueV3::Length if usize::from(immediate) == literal_width => {
                    CompareFactV3::LengthAgainstWidth
                }
                AbstractValueV3::RemainingToMax => {
                    CompareFactV3::RemainingMax { minimum: immediate }
                }
                AbstractValueV3::RemainingToLength => {
                    CompareFactV3::RemainingLength { minimum: immediate }
                }
                AbstractValueV3::CandidateMask { .. } if immediate == 0 => {
                    CompareFactV3::CandidateMaskAgainstZero { register }
                }
                _ => CompareFactV3::None,
            };
        }
        DecodedInstructionV3::CompareRegister32 { .. }
        | DecodedInstructionV3::CompareImmediate32 { .. } => {}
        DecodedInstructionV3::LoadByte {
            destination,
            base,
            offset,
        } => {
            prove_load_v3(state, state.value(base), offset, 1, literal_width)?;
            state.clobber_gpr(destination);
        }
        DecodedInstructionV3::LoadByteRegister {
            destination,
            base,
            index,
        } => {
            let address = add_values_v3(state.value(base), state.value(index));
            prove_load_v3(state, address, 0, 1, literal_width)?;
            state.clobber_gpr(destination);
        }
        DecodedInstructionV3::LoadVector128 { base, offset, .. } => {
            prove_load_v3(state, state.value(base), offset, 16, literal_width)?;
        }
        DecodedInstructionV3::LoadVectorDouble { base, offset, .. } => {
            prove_load_v3(state, state.value(base), offset, 8, literal_width)?;
        }
        DecodedInstructionV3::MoveVectorByteTo32 { destination, .. } => {
            state.clobber_gpr(destination);
        }
        DecodedInstructionV3::MoveVectorDoubleTo64 { destination, .. } => {
            state.write_value(destination, AbstractValueV3::PackedCandidateBits);
        }
        DecodedInstructionV3::SvePtrueBytesVl16 { destination } => {
            state.set_predicate(destination, PredicateValueV3::AllVl16);
        }
        DecodedInstructionV3::SveDuplicateByte { .. } => {}
        DecodedInstructionV3::SveLoadBytes { base, .. } => {
            prove_load_v3(state, state.value(base), 0, SVE_VL_BYTES_V3, literal_width)?;
        }
        DecodedInstructionV3::SveLoadBytesMulVl {
            base,
            vector_offset,
            ..
        } => {
            let scaled_offset = signed_mul_vl_offset_v3(vector_offset)?;
            prove_load_v3(
                state,
                state.value(base),
                scaled_offset,
                SVE_VL_BYTES_V3,
                literal_width,
            )?;
        }
        DecodedInstructionV3::SveCompareEqualBytes { destination, .. }
        | DecodedInstructionV3::Sve2MatchBytes { destination, .. } => {
            state.set_predicate(
                destination,
                PredicateValueV3::Candidate {
                    nonempty: false,
                    reduced: false,
                },
            );
        }
        DecodedInstructionV3::SveAndPredicateBytes { destination, .. } => {
            state.set_predicate(
                destination,
                PredicateValueV3::Candidate {
                    nonempty: false,
                    reduced: false,
                },
            );
        }
        DecodedInstructionV3::SveOrPredicateBytes {
            destination,
            predicate,
            left,
            right,
        } => {
            let value = match (
                state.predicate(predicate),
                state.predicate(left),
                state.predicate(right),
            ) {
                (
                    PredicateValueV3::AllVl16,
                    PredicateValueV3::Candidate {
                        nonempty: left_nonempty,
                        ..
                    },
                    PredicateValueV3::Candidate {
                        nonempty: right_nonempty,
                        ..
                    },
                ) => PredicateValueV3::Candidate {
                    nonempty: left_nonempty || right_nonempty,
                    reduced: false,
                },
                _ => PredicateValueV3::Unknown,
            };
            state.set_predicate(destination, value);
        }
        DecodedInstructionV3::SveTestPredicateBytes { tested, .. } => {
            state.compare = CompareFactV3::PredicateAgainstEmpty { predicate: tested };
        }
        DecodedInstructionV3::SveBreakBeforeBytes {
            destination,
            predicate,
            source,
        } => {
            let value = match (state.predicate(predicate), state.predicate(source)) {
                (PredicateValueV3::AllVl16, PredicateValueV3::Candidate { nonempty: true, .. }) => {
                    PredicateValueV3::PrefixBeforeFirst
                }
                _ => PredicateValueV3::Unknown,
            };
            state.set_predicate(destination, value);
        }
        DecodedInstructionV3::SveBreakAfterBytes {
            destination,
            predicate,
            source,
        } => {
            let value = match (state.predicate(predicate), state.predicate(source)) {
                (PredicateValueV3::AllVl16, PredicateValueV3::Candidate { nonempty: true, .. }) => {
                    PredicateValueV3::PrefixThroughFirst
                }
                _ => PredicateValueV3::Unknown,
            };
            state.set_predicate(destination, value);
        }
        DecodedInstructionV3::SveBitClearPredicateBytesSetFlags {
            destination,
            predicate,
            left,
            right,
        } => {
            let value = match (
                state.predicate(predicate),
                state.predicate(left),
                state.predicate(right),
            ) {
                (
                    PredicateValueV3::AllVl16,
                    PredicateValueV3::Candidate { nonempty: true, .. },
                    PredicateValueV3::PrefixThroughFirst,
                ) => PredicateValueV3::Candidate {
                    nonempty: false,
                    reduced: true,
                },
                _ => PredicateValueV3::Unknown,
            };
            state.set_predicate(destination, value);
            state.compare = CompareFactV3::PredicateAgainstEmpty {
                predicate: destination,
            };
        }
        DecodedInstructionV3::SveCountPredicateBytes {
            destination,
            predicate,
            source,
        } => {
            let result = if destination == X7
                && state.predicate(predicate) == PredicateValueV3::AllVl16
                && state.predicate(source) == PredicateValueV3::PrefixBeforeFirst
            {
                AbstractValueV3::CursorOffset {
                    minimum: 0,
                    maximum: 15,
                }
            } else {
                AbstractValueV3::Unknown
            };
            state.write_value(destination, result);
        }
        DecodedInstructionV3::Store64 { .. }
        | DecodedInstructionV3::DuplicateByte16 { .. }
        | DecodedInstructionV3::CompareEqualBytes16 { .. }
        | DecodedInstructionV3::CompareEqualBytes8 { .. }
        | DecodedInstructionV3::AndBytes16 { .. }
        | DecodedInstructionV3::AddBytes16 { .. }
        | DecodedInstructionV3::OrBytes16 { .. }
        | DecodedInstructionV3::ShrinkNarrowBytesFromHalfwords { .. }
        | DecodedInstructionV3::AddAcrossBytes16 { .. }
        | DecodedInstructionV3::UnsignedMaxAcrossBytes16 { .. }
        | DecodedInstructionV3::UnsignedMinAcrossBytes8 { .. }
        | DecodedInstructionV3::UnsignedMinAcrossBytes16 { .. }
        | DecodedInstructionV3::Move64ToVectorDouble { .. }
        | DecodedInstructionV3::Insert64ToVectorDoubleLane1 { .. } => {}
        DecodedInstructionV3::Branch { .. }
        | DecodedInstructionV3::BranchCondition { .. }
        | DecodedInstructionV3::Return => {
            return Err(invalid_v3("v3 decoded CFG transfer"));
        }
    }
    Ok(())
}

fn split_condition_v3(
    state: AbstractStateV3,
    condition: ConditionV3,
) -> (AbstractStateV3, AbstractStateV3) {
    let mut taken = state;
    let mut fallthrough = state;
    match (state.compare, condition) {
        (CompareFactV3::LengthAgainstWidth, ConditionV3::CarryClear) => {
            fallthrough.length_at_least_width = true;
        }
        (CompareFactV3::CursorAgainstMax, ConditionV3::Higher) => {
            taken.max_slack = None;
            strengthen_bound_v3(&mut fallthrough.max_slack, 0);
        }
        (CompareFactV3::CursorAgainstLength, ConditionV3::CarrySet) => {
            taken.length_remaining = None;
            strengthen_bound_v3(&mut fallthrough.length_remaining, 1);
        }
        (CompareFactV3::RemainingMax { minimum }, ConditionV3::CarryClear) => {
            strengthen_bound_v3(&mut fallthrough.max_slack, minimum);
        }
        (CompareFactV3::RemainingLength { minimum }, ConditionV3::CarryClear) => {
            strengthen_bound_v3(&mut fallthrough.length_remaining, minimum);
        }
        (CompareFactV3::CandidateMaskAgainstZero { register }, ConditionV3::Equal) => {
            mark_candidate_nonempty_v3(&mut fallthrough, register);
        }
        (CompareFactV3::CandidateMaskAgainstZero { register }, ConditionV3::NotEqual) => {
            mark_candidate_nonempty_v3(&mut taken, register);
        }
        (CompareFactV3::PredicateAgainstEmpty { predicate }, ConditionV3::Equal) => {
            mark_predicate_nonempty_v3(&mut fallthrough, predicate);
        }
        (CompareFactV3::PredicateAgainstEmpty { predicate }, ConditionV3::NotEqual) => {
            mark_predicate_nonempty_v3(&mut taken, predicate);
        }
        _ => {}
    }
    (taken, fallthrough)
}

fn mark_candidate_nonempty_v3(state: &mut AbstractStateV3, register: u8) {
    if let AbstractValueV3::CandidateMask { reduced, .. } = state.value(register) {
        state.write_value(
            register,
            AbstractValueV3::CandidateMask {
                nonempty: true,
                reduced,
            },
        );
    }
}

fn mark_predicate_nonempty_v3(state: &mut AbstractStateV3, register: u8) {
    if let PredicateValueV3::Candidate { reduced, .. } = state.predicate(register) {
        state.set_predicate(
            register,
            PredicateValueV3::Candidate {
                nonempty: true,
                reduced,
            },
        );
    }
}

fn add_values_v3(left: AbstractValueV3, right: AbstractValueV3) -> AbstractValueV3 {
    match (left, right) {
        (AbstractValueV3::HaystackBase, AbstractValueV3::Cursor)
        | (AbstractValueV3::Cursor, AbstractValueV3::HaystackBase) => {
            AbstractValueV3::HaystackAddress {
                minimum: 0,
                maximum: 0,
            }
        }
        (AbstractValueV3::HaystackBase, AbstractValueV3::CursorOffset { minimum, maximum })
        | (AbstractValueV3::CursorOffset { minimum, maximum }, AbstractValueV3::HaystackBase) => {
            AbstractValueV3::HaystackAddress { minimum, maximum }
        }
        (AbstractValueV3::Cursor, AbstractValueV3::CursorOffset { minimum, maximum })
        | (AbstractValueV3::CursorOffset { minimum, maximum }, AbstractValueV3::Cursor) => {
            AbstractValueV3::CursorOffset { minimum, maximum }
        }
        _ => AbstractValueV3::Unknown,
    }
}

fn add_immediate_value_v3(
    source: AbstractValueV3,
    immediate: u16,
) -> Result<AbstractValueV3, CountAotError> {
    match source {
        AbstractValueV3::HaystackAddress { minimum, maximum } => {
            Ok(AbstractValueV3::HaystackAddress {
                minimum: minimum
                    .checked_add(immediate)
                    .ok_or_else(audit_arithmetic_v3)?,
                maximum: maximum
                    .checked_add(immediate)
                    .ok_or_else(audit_arithmetic_v3)?,
            })
        }
        AbstractValueV3::CursorOffset { minimum, maximum } => Ok(AbstractValueV3::CursorOffset {
            minimum: minimum
                .checked_add(immediate)
                .ok_or_else(audit_arithmetic_v3)?,
            maximum: maximum
                .checked_add(immediate)
                .ok_or_else(audit_arithmetic_v3)?,
        }),
        _ => Ok(AbstractValueV3::Unknown),
    }
}

fn prove_load_v3(
    state: &AbstractStateV3,
    base: AbstractValueV3,
    instruction_offset: u16,
    load_bytes: u16,
    literal_width: usize,
) -> Result<(), CountAotError> {
    let AbstractValueV3::HaystackAddress { maximum, .. } = base else {
        return Err(invalid_v3("v3 decoded CFG unproven load base"));
    };
    if load_bytes == 0 || literal_width == 0 {
        return Err(invalid_v3("v3 decoded CFG invalid load width"));
    }
    let maximum = u32::from(maximum)
        .checked_add(u32::from(instruction_offset))
        .ok_or_else(audit_arithmetic_v3)?;
    let inclusive_end = maximum
        .checked_add(u32::from(load_bytes) - 1)
        .ok_or_else(audit_arithmetic_v3)?;
    let max_start_proof = state.max_slack.is_some_and(|slack| {
        let allowed =
            u32::from(slack).checked_add(u32::try_from(literal_width - 1).unwrap_or(u32::MAX));
        allowed.is_some_and(|allowed| inclusive_end <= allowed)
    });
    let length_proof = state.length_remaining.is_some_and(|remaining| {
        maximum
            .checked_add(u32::from(load_bytes))
            .is_some_and(|exclusive_end| exclusive_end <= u32::from(remaining))
    });
    if max_start_proof || length_proof {
        Ok(())
    } else {
        Err(invalid_v3("v3 decoded CFG load interval"))
    }
}

fn signed_mul_vl_offset_v3(vector_offset: i8) -> Result<u16, CountAotError> {
    let scaled = i16::from(vector_offset)
        .checked_mul(i16::try_from(SVE_VL_BYTES_V3).map_err(|_| audit_arithmetic_v3())?)
        .ok_or_else(audit_arithmetic_v3)?;
    // The current decoded address domain is relative to a nonnegative
    // candidate cursor. Reject negative MUL-VL offsets instead of silently
    // losing the lower-bound obligation. Reviewed Count-v3 schedules emit
    // exactly 0..=7 here.
    u16::try_from(scaled).map_err(|_| invalid_v3("v3 decoded CFG negative MUL VL load"))
}

fn propagate_v3(
    slots: &mut [SafetySlotV3],
    source: usize,
    target: usize,
    mut state: AbstractStateV3,
    pending: &mut usize,
) {
    if slots[target].loop_header {
        state.prepare_loop_entry(source, target);
    }
    let slot = &mut slots[target];
    let changed = if !slot.reachable {
        slot.reachable = true;
        slot.state = state;
        true
    } else {
        slot.state.join(state)
    };
    if changed {
        enqueue_v3(slots, target, pending);
    }
}

fn enqueue_v3(slots: &mut [SafetySlotV3], target: usize, pending: &mut usize) {
    if slots[target].queued {
        return;
    }
    slots[target].queued = true;
    slots[target].next_pending = *pending;
    *pending = target;
}

fn branch_target_v3(
    instruction_index: usize,
    displacement: i32,
    instruction_count: usize,
) -> Result<usize, CountAotError> {
    let source = i64::try_from(
        instruction_index
            .checked_mul(4)
            .ok_or_else(audit_arithmetic_v3)?,
    )
    .map_err(|_| audit_arithmetic_v3())?;
    let target = source
        .checked_add(i64::from(displacement))
        .ok_or_else(audit_arithmetic_v3)?;
    if target < 0 || target % 4 != 0 {
        return Err(invalid_v3("v3 decoded CFG branch target"));
    }
    let target = usize::try_from(target / 4).map_err(|_| audit_arithmetic_v3())?;
    if target >= instruction_count {
        return Err(invalid_v3("v3 decoded CFG branch range"));
    }
    Ok(target)
}

const fn direct_displacement_v3(instruction: DecodedInstructionV3) -> Option<i32> {
    match instruction {
        DecodedInstructionV3::Branch { displacement }
        | DecodedInstructionV3::BranchCondition { displacement, .. } => Some(displacement),
        _ => None,
    }
}

const fn is_haystack_load_v3(instruction: DecodedInstructionV3) -> bool {
    matches!(
        instruction,
        DecodedInstructionV3::LoadByte { .. }
            | DecodedInstructionV3::LoadByteRegister { .. }
            | DecodedInstructionV3::LoadVector128 { .. }
            | DecodedInstructionV3::LoadVectorDouble { .. }
            | DecodedInstructionV3::SveLoadBytes { .. }
            | DecodedInstructionV3::SveLoadBytesMulVl { .. }
    )
}

fn tracked_index_v3(register: u8) -> Option<usize> {
    TRACKED_GPRS_V3
        .iter()
        .position(|candidate| *candidate == register)
}

fn subtract_bound_v3(bound: Option<u16>, amount: u16) -> Option<u16> {
    bound.and_then(|bound| bound.checked_sub(amount))
}

fn strengthen_bound_v3(bound: &mut Option<u16>, candidate: u16) {
    *bound = Some(bound.map_or(candidate, |bound| bound.max(candidate)));
}

fn join_lower_bound_v3(left: Option<u16>, right: Option<u16>) -> Option<u16> {
    (left == right).then_some(left).flatten()
}

const fn invalid_v3(at: &'static str) -> CountAotError {
    CountAotError::InvalidImage { at }
}

const fn audit_arithmetic_v3() -> CountAotError {
    CountAotError::ArithmeticOverflow {
        site: CountAotArithmeticSite::Audit,
    }
}

fn map_scratch_error_v3(error: CopyError) -> CountAotError {
    match error {
        CopyError::LayoutOverflow => audit_arithmetic_v3(),
        CopyError::AllocationFailed => CountAotError::AllocationFailed {
            resource: CountAotResource::ScratchBytes,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LabelKindV3;

    fn branch_condition(from: usize, to: usize, condition: ConditionV3) -> DecodedInstructionV3 {
        DecodedInstructionV3::BranchCondition {
            condition,
            displacement: i32::try_from(
                i64::try_from(to).unwrap() * 4 - i64::try_from(from).unwrap() * 4,
            )
            .unwrap(),
        }
    }

    fn branch(from: usize, to: usize) -> DecodedInstructionV3 {
        DecodedInstructionV3::Branch {
            displacement: i32::try_from(
                i64::try_from(to).unwrap() * 4 - i64::try_from(from).unwrap() * 4,
            )
            .unwrap(),
        }
    }

    #[test]
    fn prior_direct_mask_wrap_fixture_is_rejected() {
        // This is the old unsafe shape: after an exact 16-start iteration,
        // X3==X4+1. The next X4-X3 wraps and falsely passes the remaining-work
        // comparison because no explicit X3<=X4 guard dominates it.
        let decoded = [
            DecodedInstructionV3::CompareImmediate64 {
                register: X1,
                immediate: 3,
            },
            branch_condition(1, 11, ConditionV3::CarryClear),
            DecodedInstructionV3::SubtractImmediate64 {
                destination: X4,
                source: X1,
                immediate: 3,
            },
            DecodedInstructionV3::MoveZero64 {
                destination: X3,
                immediate: 0,
                shift: 0,
            },
            DecodedInstructionV3::SubtractRegister64 {
                destination: X6,
                left: X4,
                right: X3,
            },
            DecodedInstructionV3::CompareImmediate64 {
                register: X6,
                immediate: 15,
            },
            branch_condition(6, 11, ConditionV3::CarryClear),
            DecodedInstructionV3::AddRegister64 {
                destination: X15,
                left: X0,
                right: X3,
            },
            DecodedInstructionV3::LoadVector128 {
                destination: 0,
                base: X15,
                offset: 0,
            },
            DecodedInstructionV3::AddImmediate64 {
                destination: X3,
                source: X3,
                immediate: 16,
            },
            branch(10, 4),
            DecodedInstructionV3::Return,
        ];
        let labels = [
            CodeLabelV3 {
                offset: 16,
                kind: LabelKindV3::VectorLoop,
            },
            CodeLabelV3 {
                offset: 44,
                kind: LabelKindV3::Success,
            },
        ];
        assert_eq!(
            audit_decoded_cfg_safety_v3(&decoded, &labels, 3),
            Err(invalid_v3("v3 decoded CFG load interval"))
        );
    }

    #[test]
    fn explicit_cursor_guard_proves_the_exact_boundary() {
        let decoded = [
            DecodedInstructionV3::CompareImmediate64 {
                register: X1,
                immediate: 3,
            },
            branch_condition(1, 13, ConditionV3::CarryClear),
            DecodedInstructionV3::SubtractImmediate64 {
                destination: X4,
                source: X1,
                immediate: 3,
            },
            DecodedInstructionV3::MoveZero64 {
                destination: X3,
                immediate: 0,
                shift: 0,
            },
            DecodedInstructionV3::CompareRegister64 {
                left: X3,
                right: X4,
            },
            branch_condition(5, 13, ConditionV3::Higher),
            DecodedInstructionV3::SubtractRegister64 {
                destination: X6,
                left: X4,
                right: X3,
            },
            DecodedInstructionV3::CompareImmediate64 {
                register: X6,
                immediate: 15,
            },
            branch_condition(8, 13, ConditionV3::CarryClear),
            DecodedInstructionV3::AddRegister64 {
                destination: X15,
                left: X0,
                right: X3,
            },
            DecodedInstructionV3::LoadVector128 {
                destination: 0,
                base: X15,
                offset: 0,
            },
            DecodedInstructionV3::AddImmediate64 {
                destination: X3,
                source: X3,
                immediate: 16,
            },
            branch(12, 4),
            DecodedInstructionV3::Return,
        ];
        let labels = [
            CodeLabelV3 {
                offset: 16,
                kind: LabelKindV3::VectorLoop,
            },
            CodeLabelV3 {
                offset: 52,
                kind: LabelKindV3::Success,
            },
        ];
        audit_decoded_cfg_safety_v3(&decoded, &labels, 3).unwrap();
    }

    #[test]
    fn load_interval_accepts_last_byte_and_rejects_one_past_it() {
        let mut state = AbstractStateV3::entry();
        state.x3_is_cursor = true;
        state.x4_is_max_start = true;
        state.max_slack = Some(15);
        let base = AbstractValueV3::HaystackAddress {
            minimum: 0,
            maximum: 15,
        };
        prove_load_v3(&state, base, 31, 1, 32).unwrap();
        assert_eq!(
            prove_load_v3(&state, base, 32, 1, 32),
            Err(invalid_v3("v3 decoded CFG load interval"))
        );
    }

    #[test]
    fn cursor_free_self_loop_is_rejected() {
        let decoded = [branch(0, 0)];
        let labels = [CodeLabelV3 {
            offset: 0,
            kind: LabelKindV3::VectorLoop,
        }];
        assert_eq!(
            audit_decoded_cfg_safety_v3(&decoded, &labels, 1),
            Err(invalid_v3("v3 decoded CFG non-progressing backedge"))
        );
    }

    #[test]
    fn zero_or_unknown_candidate_clear_is_not_progress() {
        let decoded = [
            DecodedInstructionV3::MoveVectorDoubleTo64 {
                destination: X6,
                source: 0,
            },
            DecodedInstructionV3::AndRegister64 {
                destination: X6,
                left: X6,
                right: X17,
            },
            DecodedInstructionV3::SubtractImmediate64 {
                destination: X16,
                source: X6,
                immediate: 1,
            },
            DecodedInstructionV3::AndRegister64 {
                destination: X6,
                left: X6,
                right: X16,
            },
            branch(4, 0),
        ];
        let labels = [CodeLabelV3 {
            offset: 0,
            kind: LabelKindV3::CandidateLoop,
        }];
        assert_eq!(
            audit_decoded_cfg_safety_v3(&decoded, &labels, 2),
            Err(invalid_v3("v3 decoded CFG non-progressing backedge"))
        );
    }

    #[test]
    fn all_sve_predicates_survive_or_reduction_and_ptest() {
        let mut state = AbstractStateV3::entry();
        state.set_predicate(0, PredicateValueV3::AllVl16);
        state.set_predicate(
            4,
            PredicateValueV3::Candidate {
                nonempty: true,
                reduced: false,
            },
        );
        state.set_predicate(
            11,
            PredicateValueV3::Candidate {
                nonempty: false,
                reduced: false,
            },
        );
        execute_v3(
            &mut state,
            DecodedInstructionV3::SveOrPredicateBytes {
                destination: 15,
                predicate: 0,
                left: 4,
                right: 11,
            },
            32,
        )
        .unwrap();
        assert_eq!(
            state.predicate(15),
            PredicateValueV3::Candidate {
                nonempty: true,
                reduced: false,
            }
        );
        execute_v3(
            &mut state,
            DecodedInstructionV3::SveTestPredicateBytes {
                predicate: 0,
                tested: 15,
            },
            32,
        )
        .unwrap();
        let (taken, _) = split_condition_v3(state, ConditionV3::NotEqual);
        assert!(matches!(
            taken.predicate(15),
            PredicateValueV3::Candidate { nonempty: true, .. }
        ));
    }

    #[test]
    fn mul_vl_offsets_are_exact_and_negative_offsets_refuse() {
        assert_eq!(signed_mul_vl_offset_v3(0).unwrap(), 0);
        assert_eq!(signed_mul_vl_offset_v3(7).unwrap(), 112);
        assert_eq!(
            signed_mul_vl_offset_v3(-1),
            Err(invalid_v3("v3 decoded CFG negative MUL VL load"))
        );
    }
}
