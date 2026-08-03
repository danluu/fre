//! Target-neutral packed data layout for native contextual-DFA lowering.
//!
//! The contextual graph uses a 16-bit boundary key. Native initial-state
//! dispatch can therefore be a complete direct-index table rather than a
//! target-specific hash or comparison chain. Initial and reverse words retain
//! explicit validity/event bits and a 30-bit `state + 1` payload. Complete
//! forward rows instead carry the successor's three state flags beside the
//! event and a 28-bit nonzero payload, eliminating a dependent flag-table load
//! from the native forward loop.

#![allow(
    dead_code,
    reason = "the packed contextual layout is staged immediately ahead of native instruction lowering"
)]

use crate::{
    CompileResource, ObjectError,
    context_dfa::{
        NativeContextAnchoredForwardView, NativeContextDfaView, NativeContextForwardState,
    },
    program::{NativeContextProgramView, OutputContract},
};

/// Number of entries in a complete 16-bit contextual dispatch table.
pub(crate) const CONTEXT_DISPATCH_ENTRIES: usize = 1 << 16;
/// Bit marking an initialized transition or initial-dispatch entry.
pub(crate) const CONTEXT_CELL_VALID: u32 = 1 << 30;
/// Acceptance for forward cells and `reaches_start` for reverse cells.
pub(crate) const CONTEXT_CELL_EVENT: u32 = 1 << 31;
/// Low-bit payload mask. Zero means no state; nonzero is `state + 1`.
pub(crate) const CONTEXT_CELL_STATE_MASK: u32 = CONTEXT_CELL_VALID - 1;
/// Low-bit `state + 1` payload in complete forward transition rows.
pub(crate) const CONTEXT_FORWARD_CELL_STATE_MASK: u32 = (1 << 28) - 1;
/// Shift of packed successor state flags in complete forward rows.
pub(crate) const CONTEXT_FORWARD_CELL_FLAGS_SHIFT: u8 = 28;
/// Packed successor state-flag field in complete forward rows.
pub(crate) const CONTEXT_FORWARD_CELL_FLAGS_MASK: u32 = 0x7000_0000;
/// Explicit invalid/unpopulated direct-dispatch entry.
pub(crate) const CONTEXT_INVALID_CELL: u32 = 0;
/// Maximum representable number of states (last index is one less).
pub(crate) const MAX_PACKED_CONTEXT_STATES: usize = 0x3fff_ffff;
/// Maximum state count representable by a complete packed forward row.
///
/// A table approaching this limit already exceeds the native data ceiling by
/// orders of magnitude because every state has at least two four-byte cells.
pub(crate) const MAX_PACKED_CONTEXT_FORWARD_STATES: usize = 0x0fff_ffff;
/// Addressable native data ceiling shared by current x86-64/AArch64 lowering.
pub(crate) const MAX_CONTEXT_NATIVE_DATA_BYTES: usize = 0x7fff_ffff;

/// Packed bits attached to one forward state.
pub(crate) const CONTEXT_STATE_PENDING: u8 = 1 << 0;
/// `pending` with an empty ordered frontier: native execution may stop.
pub(crate) const CONTEXT_STATE_TERMINAL: u8 = 1 << 1;
/// No consuming path is active at the state's current boundary.
///
/// This bit is a lowering-internal graph fact, not part of serialized
/// [`crate::program::CompiledProgram`] bytes. Native table images are rebuilt
/// by the optimizing compiler, so defining this formerly reserved bit does
/// not change the portable program format.
pub(crate) const CONTEXT_STATE_EMPTY: u8 = 1 << 2;

/// Private source-identical A/B switch for raw-byte-pair initial dispatch.
///
/// The optimized representation is selected only when every retained state
/// fits its checked 14-bit payload. Larger machines keep the original
/// semantic-context table without changing native behavior.
const ENABLE_CONTEXT_RAW_PAIR_INITIAL_DISPATCH: bool = true;
/// Private source-identical A/B switch for raw-byte-pair reverse dispatch.
///
/// This is deliberately independent from the forward switch so the matching
/// contribution of each direction can be measured without changing table or
/// lowering semantics in the other direction.
const ENABLE_CONTEXT_RAW_PAIR_REVERSE_INITIAL_DISPATCH: bool = true;
/// Private source-identical A/B switch for bounded raw-byte transition rows.
///
/// Direct rows remove byte-class lookup and variable-width row arithmetic
/// from native loops. Selection remains structural and independently falls
/// back to compact class rows in either direction.
const ENABLE_CONTEXT_DIRECT_BYTE_TRANSITIONS: bool = true;
pub(crate) const CONTEXT_RAW_FORWARD_STATE_MASK: u16 = 0x3fff;
pub(crate) const CONTEXT_RAW_FORWARD_VALID: u16 = 1 << 14;
pub(crate) const CONTEXT_RAW_FORWARD_EMPTY: u16 = 1 << 15;
pub(crate) const CONTEXT_RAW_REVERSE_STATE_MASK: u16 = 0x3fff;
pub(crate) const CONTEXT_RAW_REVERSE_VALID: u16 = 1 << 14;
pub(crate) const CONTEXT_RAW_REVERSE_EVENT: u16 = 1 << 15;
const CONTEXT_RAW_PAIR_BYTES: usize = CONTEXT_DISPATCH_ENTRIES * core::mem::size_of::<u16>();
const CONTEXT_RAW_BOUNDARY_ENTRIES: usize = 257;
const CONTEXT_RAW_START_BYTES: usize = CONTEXT_RAW_BOUNDARY_ENTRIES * core::mem::size_of::<u16>();
const CONTEXT_RAW_END_BYTES: usize = 256 * core::mem::size_of::<u16>();
pub(crate) const CONTEXT_DIRECT_BYTE_ROW_CELLS: usize = 256;
pub(crate) const CONTEXT_DIRECT_BYTE_ROW_BYTES: usize =
    CONTEXT_DIRECT_BYTE_ROW_CELLS * core::mem::size_of::<u32>();
const CONTEXT_DIRECT_BYTE_MAX_STATES: usize = 512;
const CONTEXT_DIRECT_BYTE_MAX_COMBINED_BYTES: usize = 1 << 20;
const CONTEXT_ANCHORED_DIRECT_BYTE_MAX_BYTES: usize = 256 * 1024;
const CONTEXT_ANCHORED_MAX_ADDED_BYTES: usize = 1 << 20;

fn raw_forward_initial_state_payload_fits(states: usize) -> bool {
    states <= usize::from(CONTEXT_RAW_FORWARD_STATE_MASK)
}

fn raw_reverse_initial_state_payload_fits(states: usize) -> bool {
    states <= usize::from(CONTEXT_RAW_REVERSE_STATE_MASK)
}

/// Caller-controlled resource ceiling for the owned packed data image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContextNativeLimits {
    pub(crate) max_data_bytes: usize,
}

impl Default for ContextNativeLimits {
    fn default() -> Self {
        Self {
            max_data_bytes: MAX_CONTEXT_NATIVE_DATA_BYTES,
        }
    }
}

/// Deterministic, little-endian table image and target-independent offsets.
///
/// `byte_classes` and `class_properties` are fixed 256-byte tables. Forward
/// and retained reverse transitions have `row_width` packed `u32` cells per
/// state. Initial dispatch is either the complete semantic-key table or a
/// cost-gated raw adjacent-byte table plus bounded absolute-edge tables.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContextNativeLayout {
    pub(crate) output: OutputContract,
    pub(crate) class_count: u16,
    pub(crate) row_width: u16,
    pub(crate) forward_states: u32,
    pub(crate) reverse_states: u32,
    pub(crate) exact_match_width: Option<u64>,
    pub(crate) max_match_width: Option<u64>,
    pub(crate) byte_classes_offset: u32,
    pub(crate) class_properties_offset: u32,
    pub(crate) forward_state_flags_offset: u32,
    pub(crate) forward_cells_offset: u32,
    /// Separate per-state absolute-boundary cells for DirectByte forward rows.
    pub(crate) forward_byte_sentinel_offset: Option<u32>,
    pub(crate) reverse_cells_offset: Option<u32>,
    /// Separate per-state absolute-boundary cells for DirectByte reverse rows.
    pub(crate) reverse_byte_sentinel_offset: Option<u32>,
    pub(crate) forward_initial_offset: u32,
    pub(crate) reverse_initial_offset: Option<u32>,
    pub(crate) raw_pair_initial: Option<ContextRawPairInitialLayout>,
    pub(crate) raw_pair_reverse_initial: Option<ContextRawPairReverseInitialLayout>,
    pub(crate) anchored_forward: Option<ContextAnchoredForwardLayout>,
    pub(crate) data: Vec<u8>,
}

/// Packed optional exact-start forward verifier.
///
/// The main forward initial dispatch yields a search-DFA state. The checked
/// map translates that state to this sidecar, avoiding a second 16-bit
/// boundary table. Transition rows use the same packed cell format as the
/// complete forward machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContextAnchoredForwardLayout {
    pub(crate) states: u32,
    pub(crate) main_initial_to_anchored_offset: u32,
    pub(crate) state_flags_offset: u32,
    pub(crate) cells_offset: u32,
    pub(crate) byte_sentinel_offset: Option<u32>,
    pub(crate) max_resolution_steps: Option<u32>,
}

/// Offsets for the 16-bit raw-byte-pair initial-dispatch representation.
///
/// Interior boundaries use `previous | (current << 8)`. Absolute start and
/// end are kept in separate, small tables because those facts are properties
/// of the complete haystack, not of a search-window edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContextRawPairInitialLayout {
    pub(crate) forward_start_offset: u32,
    pub(crate) forward_end_offset: u32,
}

/// Absolute-edge offsets for the 16-bit raw reverse initial dispatch.
///
/// Its pair table uses the same `previous | (current << 8)` index as forward
/// dispatch. Bit 15 of each valid cell records `reaches_start` instead of the
/// forward empty-frontier fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContextRawPairReverseInitialLayout {
    pub(crate) reverse_start_offset: u32,
    pub(crate) reverse_end_offset: u32,
}

/// Status values published by the native five-argument search ABI.
///
/// These values and the two result words are independent of instruction set
/// and object format, so the same control-flow contract applies to x86-64 and
/// `AArch64` on both Linux and macOS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum ContextNativeExecutionStatus {
    NoMatch = 0,
    Matched = 1,
    Invalid = 2,
}

/// Architecture-neutral result of the packed contextual lowering model.
///
/// No-match results contain two zero words. `Exists` matches also leave both
/// words zero; `SelectedEnd` publishes `{end, end}` and `Span` publishes
/// `{start, end}`. A target emitter can therefore map this model directly to
/// the existing native entry ABI without target-specific semantic choices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContextNativeExecutionResult {
    pub(crate) status: ContextNativeExecutionStatus,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl ContextNativeExecutionResult {
    const fn no_match() -> Self {
        Self {
            status: ContextNativeExecutionStatus::NoMatch,
            start: 0,
            end: 0,
        }
    }

    const fn invalid() -> Self {
        Self {
            status: ContextNativeExecutionStatus::Invalid,
            start: 0,
            end: 0,
        }
    }

    const fn exists() -> Self {
        Self {
            status: ContextNativeExecutionStatus::Matched,
            start: 0,
            end: 0,
        }
    }

    const fn selected_end(end: usize) -> Self {
        Self {
            status: ContextNativeExecutionStatus::Matched,
            start: end,
            end,
        }
    }

    const fn span(start: usize, end: usize) -> Self {
        Self {
            status: ContextNativeExecutionStatus::Matched,
            start,
            end,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedContextCell {
    next: Option<u32>,
    event: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedForwardCell {
    next: u32,
    event: bool,
    flags: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextForwardSelection {
    end: Option<usize>,
    initial_pending: bool,
}

const CLASS_TABLE_BYTES: usize = 256;
const CONTEXT_DISPATCH_BYTES: usize = CONTEXT_DISPATCH_ENTRIES * core::mem::size_of::<u32>();
const VIEW_NO_STATE: u32 = u32::MAX;

const CONTEXT_CLASS_MASK: u32 = 0x01ff;
const CONTEXT_PROPERTIES_MASK: u8 = 0x0f;
const CONTEXT_PROPERTIES_SHIFT: u8 = 9;
const CONTEXT_PRESENT_BIT: u32 = 1 << 13;
const CONTEXT_ABSOLUTE_START_BIT: u32 = 1 << 14;
const CONTEXT_ABSOLUTE_END_BIT: u32 = 1 << 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextLayoutPlan {
    byte_classes: usize,
    class_properties: usize,
    forward_state_flags: usize,
    forward_cells: usize,
    forward_byte_sentinel: Option<usize>,
    reverse_cells: Option<usize>,
    reverse_byte_sentinel: Option<usize>,
    forward_initial: usize,
    reverse_initial: Option<usize>,
    raw_pair_initial: Option<ContextRawPairInitialPlan>,
    raw_pair_reverse_initial: Option<ContextRawPairReverseInitialPlan>,
    total: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextRawPairInitialPlan {
    forward_start: usize,
    forward_end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextRawPairReverseInitialPlan {
    reverse_start: usize,
    reverse_end: usize,
}

impl ContextNativeLayout {
    /// Return the exact deterministic data image consumed by native lowering.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Pack one forward initial-boundary key.
    ///
    /// The caller must derive `properties` from the byte before the boundary
    /// in the original haystack. `class` is the byte at the boundary, or
    /// `class_count` when the boundary is the absolute haystack end.
    pub(crate) fn pack_context(
        &self,
        class: u16,
        properties: u8,
        present: bool,
        absolute_start: bool,
        absolute_end: bool,
    ) -> Option<u16> {
        if class > self.class_count || properties & !CONTEXT_PROPERTIES_MASK != 0 {
            return None;
        }
        let packed = u32::from(class)
            | (u32::from(properties) << CONTEXT_PROPERTIES_SHIFT)
            | if present { CONTEXT_PRESENT_BIT } else { 0 }
            | if absolute_start {
                CONTEXT_ABSOLUTE_START_BIT
            } else {
                0
            }
            | if absolute_end {
                CONTEXT_ABSOLUTE_END_BIT
            } else {
                0
            };
        u16::try_from(packed).ok()
    }

    /// Derive a forward key from an original-haystack boundary.
    ///
    /// `position` is allowed to be a search-window edge, but `haystack` must
    /// remain the complete original C-ABI haystack. In particular, bytes just
    /// outside the search window still determine line/word assertions.
    pub(crate) fn forward_context_at(&self, haystack: &[u8], position: usize) -> Option<u16> {
        if position > haystack.len() {
            return None;
        }
        let before = position
            .checked_sub(1)
            .and_then(|index| haystack.get(index));
        let current = haystack.get(position);
        let properties = before.map_or(0, |&byte| self.properties_for_byte(byte));
        let class = current.map_or(self.class_count, |&byte| {
            u16::from(self.class_for_byte(byte))
        });
        self.pack_context(
            class,
            properties,
            before.is_some(),
            position == 0,
            position == haystack.len(),
        )
    }

    /// Derive a reverse initial key from an original-haystack boundary.
    ///
    /// Reverse keys swap the class/property roles: the low bits classify the
    /// byte before the boundary and the property bits describe the current
    /// byte. The same full-haystack rule as [`Self::forward_context_at`]
    /// applies.
    pub(crate) fn reverse_context_at(&self, haystack: &[u8], position: usize) -> Option<u16> {
        if position > haystack.len() {
            return None;
        }
        let before = position
            .checked_sub(1)
            .and_then(|index| haystack.get(index));
        let current = haystack.get(position);
        let class = before.map_or(self.class_count, |&byte| {
            u16::from(self.class_for_byte(byte))
        });
        let properties = current.map_or(0, |&byte| self.properties_for_byte(byte));
        self.pack_context(
            class,
            properties,
            current.is_some(),
            position == 0,
            position == haystack.len(),
        )
    }

    pub(crate) fn class_for_byte(&self, byte: u8) -> u8 {
        let index = offset(self.byte_classes_offset)
            .checked_add(usize::from(byte))
            .expect("validated context class-table index");
        self.data[index]
    }

    pub(crate) fn properties_for_byte(&self, byte: u8) -> u8 {
        let class = usize::from(self.class_for_byte(byte));
        let index = offset(self.class_properties_offset)
            .checked_add(class)
            .expect("validated context property-table index");
        self.data[index]
    }

    pub(crate) fn forward_initial_cell(&self, context: u16) -> u32 {
        if let Some(raw) = self.raw_pair_initial {
            return self
                .raw_forward_initial_halfword(context, raw)
                .map_or(CONTEXT_INVALID_CELL, expand_raw_forward_initial);
        }
        table_word(
            &self.data,
            offset(self.forward_initial_offset),
            usize::from(context),
        )
    }

    pub(crate) fn reverse_initial_cell(&self, context: u16) -> Option<u32> {
        if let Some(raw) = self.raw_pair_reverse_initial {
            return Some(
                self.raw_reverse_initial_halfword(context, raw)
                    .map_or(CONTEXT_INVALID_CELL, expand_raw_reverse_initial),
            );
        }
        self.reverse_initial_offset
            .map(|table| table_word(&self.data, offset(table), usize::from(context)))
    }

    fn raw_byte_for_class(&self, class: u16) -> Option<u8> {
        (0_u16..=255).find_map(|byte| {
            let byte = u8::try_from(byte).ok()?;
            (u16::from(self.class_for_byte(byte)) == class).then_some(byte)
        })
    }

    fn raw_byte_for_properties(&self, properties: u8) -> Option<u8> {
        (0_u16..=255).find_map(|byte| {
            let byte = u8::try_from(byte).ok()?;
            (self.properties_for_byte(byte) == properties).then_some(byte)
        })
    }

    fn raw_forward_initial_halfword(
        &self,
        context: u16,
        raw: ContextRawPairInitialLayout,
    ) -> Option<u16> {
        let context = u32::from(context);
        let class = u16::try_from(context & CONTEXT_CLASS_MASK).ok()?;
        let properties = u8::try_from(
            (context >> CONTEXT_PROPERTIES_SHIFT) & u32::from(CONTEXT_PROPERTIES_MASK),
        )
        .ok()?;
        let present = context & CONTEXT_PRESENT_BIT != 0;
        let absolute_start = context & CONTEXT_ABSOLUTE_START_BIT != 0;
        let absolute_end = context & CONTEXT_ABSOLUTE_END_BIT != 0;
        let (table, index, reconstructed) = if absolute_start {
            let current = if absolute_end {
                None
            } else {
                Some(self.raw_byte_for_class(class)?)
            };
            let index = current.map_or(256, usize::from);
            (
                raw.forward_start_offset,
                index,
                self.pack_context(
                    current.map_or(self.class_count, |byte| {
                        u16::from(self.class_for_byte(byte))
                    }),
                    0,
                    false,
                    true,
                    current.is_none(),
                )?,
            )
        } else if absolute_end {
            let previous = self.raw_byte_for_properties(properties)?;
            (
                raw.forward_end_offset,
                usize::from(previous),
                self.pack_context(
                    self.class_count,
                    self.properties_for_byte(previous),
                    true,
                    false,
                    true,
                )?,
            )
        } else if present {
            let previous = self.raw_byte_for_properties(properties)?;
            let current = self.raw_byte_for_class(class)?;
            let index = usize::from(previous) | (usize::from(current) << 8);
            (
                self.forward_initial_offset,
                index,
                self.pack_context(
                    u16::from(self.class_for_byte(current)),
                    self.properties_for_byte(previous),
                    true,
                    false,
                    false,
                )?,
            )
        } else {
            return None;
        };
        if reconstructed != u16::try_from(context).ok()? {
            return None;
        }
        Some(table_halfword(&self.data, offset(table), index))
    }

    fn raw_reverse_initial_halfword(
        &self,
        context: u16,
        raw: ContextRawPairReverseInitialLayout,
    ) -> Option<u16> {
        let context = u32::from(context);
        let class = u16::try_from(context & CONTEXT_CLASS_MASK).ok()?;
        let properties = u8::try_from(
            (context >> CONTEXT_PROPERTIES_SHIFT) & u32::from(CONTEXT_PROPERTIES_MASK),
        )
        .ok()?;
        let present = context & CONTEXT_PRESENT_BIT != 0;
        let absolute_start = context & CONTEXT_ABSOLUTE_START_BIT != 0;
        let absolute_end = context & CONTEXT_ABSOLUTE_END_BIT != 0;
        let (table, index, reconstructed) = if absolute_start {
            let current = if present {
                Some(self.raw_byte_for_properties(properties)?)
            } else {
                None
            };
            let index = current.map_or(256, usize::from);
            (
                raw.reverse_start_offset,
                index,
                self.pack_context(
                    self.class_count,
                    current.map_or(0, |byte| self.properties_for_byte(byte)),
                    current.is_some(),
                    true,
                    current.is_none(),
                )?,
            )
        } else if absolute_end {
            let previous = self.raw_byte_for_class(class)?;
            (
                raw.reverse_end_offset,
                usize::from(previous),
                self.pack_context(
                    u16::from(self.class_for_byte(previous)),
                    0,
                    false,
                    false,
                    true,
                )?,
            )
        } else if present {
            let previous = self.raw_byte_for_class(class)?;
            let current = self.raw_byte_for_properties(properties)?;
            let index = usize::from(previous) | (usize::from(current) << 8);
            (
                self.reverse_initial_offset?,
                index,
                self.pack_context(
                    u16::from(self.class_for_byte(previous)),
                    self.properties_for_byte(current),
                    true,
                    false,
                    false,
                )?,
            )
        } else {
            return None;
        };
        if reconstructed != u16::try_from(context).ok()? {
            return None;
        }
        Some(table_halfword(&self.data, offset(table), index))
    }

    pub(crate) fn forward_cell(&self, state: u32, symbol: u16) -> Option<u32> {
        if let Some(sentinel) = self.forward_byte_sentinel_offset {
            if symbol == self.class_count {
                return direct_byte_sentinel_cell(&self.data, sentinel, self.forward_states, state);
            }
            let byte = self.raw_byte_for_class(symbol)?;
            return direct_byte_table_cell(
                &self.data,
                self.forward_cells_offset,
                self.forward_states,
                state,
                byte,
            );
        }
        packed_table_cell(
            &self.data,
            self.forward_cells_offset,
            self.forward_states,
            self.row_width,
            state,
            symbol,
        )
    }

    pub(crate) fn reverse_cell(&self, state: u32, symbol: u16) -> Option<u32> {
        if let Some(sentinel) = self.reverse_byte_sentinel_offset {
            if symbol == self.class_count {
                return direct_byte_sentinel_cell(&self.data, sentinel, self.reverse_states, state);
            }
            let byte = self.raw_byte_for_class(symbol)?;
            return direct_byte_table_cell(
                &self.data,
                self.reverse_cells_offset?,
                self.reverse_states,
                state,
                byte,
            );
        }
        packed_table_cell(
            &self.data,
            self.reverse_cells_offset?,
            self.reverse_states,
            self.row_width,
            state,
            symbol,
        )
    }

    pub(crate) const fn forward_direct_bytes(&self) -> bool {
        self.forward_byte_sentinel_offset.is_some()
    }

    pub(crate) const fn reverse_direct_bytes(&self) -> bool {
        self.reverse_byte_sentinel_offset.is_some()
    }

    pub(crate) fn anchored_initial_state(&self, main_state: u32) -> Option<u32> {
        let anchored = self.anchored_forward?;
        if main_state >= self.forward_states {
            return None;
        }
        let mapped = table_word(
            &self.data,
            offset(anchored.main_initial_to_anchored_offset),
            usize::try_from(main_state).ok()?,
        );
        (mapped != VIEW_NO_STATE && mapped < anchored.states).then_some(mapped)
    }

    pub(crate) fn anchored_state_flags(&self, state: u32) -> Option<u8> {
        let anchored = self.anchored_forward?;
        if state >= anchored.states {
            return None;
        }
        let index =
            offset(anchored.state_flags_offset).checked_add(usize::try_from(state).ok()?)?;
        self.data.get(index).copied()
    }

    pub(crate) fn anchored_cell_for_byte(&self, state: u32, byte: Option<u8>) -> Option<u32> {
        let anchored = self.anchored_forward?;
        if let Some(sentinel) = anchored.byte_sentinel_offset {
            return match byte {
                Some(byte) => direct_byte_table_cell(
                    &self.data,
                    anchored.cells_offset,
                    anchored.states,
                    state,
                    byte,
                ),
                None => direct_byte_sentinel_cell(&self.data, sentinel, anchored.states, state),
            };
        }
        let symbol = byte.map_or(self.class_count, |byte| {
            u16::from(self.class_for_byte(byte))
        });
        packed_table_cell(
            &self.data,
            anchored.cells_offset,
            anchored.states,
            self.row_width,
            state,
            symbol,
        )
    }

    fn forward_cell_for_byte(&self, state: u32, byte: Option<u8>) -> Option<u32> {
        if let Some(sentinel) = self.forward_byte_sentinel_offset {
            return match byte {
                Some(byte) => direct_byte_table_cell(
                    &self.data,
                    self.forward_cells_offset,
                    self.forward_states,
                    state,
                    byte,
                ),
                None => direct_byte_sentinel_cell(&self.data, sentinel, self.forward_states, state),
            };
        }
        let symbol = byte.map_or(self.class_count, |byte| {
            u16::from(self.class_for_byte(byte))
        });
        self.forward_cell(state, symbol)
    }

    fn reverse_cell_for_byte(&self, state: u32, byte: Option<u8>) -> Option<u32> {
        if let Some(sentinel) = self.reverse_byte_sentinel_offset {
            return match byte {
                Some(byte) => direct_byte_table_cell(
                    &self.data,
                    self.reverse_cells_offset?,
                    self.reverse_states,
                    state,
                    byte,
                ),
                None => direct_byte_sentinel_cell(&self.data, sentinel, self.reverse_states, state),
            };
        }
        let symbol = byte.map_or(self.class_count, |byte| {
            u16::from(self.class_for_byte(byte))
        });
        self.reverse_cell(state, symbol)
    }

    pub(crate) fn forward_state_flags(&self, state: u32) -> Option<u8> {
        if state >= self.forward_states {
            return None;
        }
        let index =
            offset(self.forward_state_flags_offset).checked_add(usize::try_from(state).ok()?)?;
        self.data.get(index).copied()
    }

    /// Execute the architecture-neutral control-flow model over the exact
    /// packed bytes that native code consumes.
    ///
    /// This is an executable lowering specification, not a fallback matching
    /// engine. Target emitters can map its checked dispatch, forward loop,
    /// output specialization, and optional reverse loop to their assembler
    /// interfaces. Boundary classification always receives the complete
    /// original haystack: `window_start` and `window_end` limit consumption,
    /// but bytes immediately outside the window still decide line and word
    /// assertions.
    pub(crate) fn execute_lowering_model(
        &self,
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
    ) -> ContextNativeExecutionResult {
        if window_start > window_end || window_end > haystack.len() {
            return ContextNativeExecutionResult::invalid();
        }
        let Some(selection) = self.forward_selection(haystack, window_start, window_end) else {
            return ContextNativeExecutionResult::invalid();
        };
        let Some(selected_end) = selection.end else {
            return ContextNativeExecutionResult::no_match();
        };
        match self.output {
            OutputContract::Exists => ContextNativeExecutionResult::exists(),
            OutputContract::SelectedEnd => ContextNativeExecutionResult::selected_end(selected_end),
            OutputContract::Span if selection.initial_pending => {
                ContextNativeExecutionResult::span(window_start, selected_end)
            }
            OutputContract::Span => {
                let start = if let Some(width) = self.exact_match_width {
                    let Some(width) = usize::try_from(width).ok() else {
                        return ContextNativeExecutionResult::invalid();
                    };
                    let Some(start) = selected_end.checked_sub(width) else {
                        return ContextNativeExecutionResult::invalid();
                    };
                    if start < window_start {
                        return ContextNativeExecutionResult::invalid();
                    }
                    start
                } else {
                    let Some(start) = self.reverse_start(haystack, window_start, selected_end)
                    else {
                        return ContextNativeExecutionResult::invalid();
                    };
                    start
                };
                ContextNativeExecutionResult::span(start, selected_end)
            }
        }
    }

    fn forward_selection(
        &self,
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
    ) -> Option<ContextForwardSelection> {
        let context = self.forward_context_at(haystack, window_start)?;
        let (initial, initial_flags) = self.forward_initial_with_flags(context)?;
        if initial.event {
            return None;
        }
        let mut state = initial.next?;
        let mut state_flags = initial_flags;
        let initial_pending = initial_flags & CONTEXT_STATE_PENDING != 0;
        let mut pending_end = initial_pending.then_some(window_start);
        if initial_pending
            && (self.output == OutputContract::Exists
                || initial_flags & CONTEXT_STATE_TERMINAL != 0)
        {
            return Some(ContextForwardSelection {
                end: pending_end,
                initial_pending,
            });
        }

        let mut position = window_start;
        while position < window_end {
            if state_flags & CONTEXT_STATE_TERMINAL != 0 {
                break;
            }
            let destination = position.checked_add(1)?;
            let byte = haystack.get(destination).copied();
            let cell = decode_forward_transition_cell(self.forward_cell_for_byte(state, byte)?)?;
            state = cell.next;
            state_flags = cell.flags;
            position = destination;
            if cell.event {
                pending_end = Some(position);
                if self.output == OutputContract::Exists {
                    break;
                }
            }
        }
        Some(ContextForwardSelection {
            end: pending_end,
            initial_pending,
        })
    }

    fn forward_initial_with_flags(&self, context: u16) -> Option<(DecodedContextCell, u8)> {
        if let Some(raw) = self.raw_pair_initial {
            let word = self.raw_forward_initial_halfword(context, raw)?;
            let initial = decode_context_cell(expand_raw_forward_initial(word))?;
            let flags = self.checked_forward_state_flags(initial.next?)?;
            return Some((initial, flags));
        }
        let initial = decode_context_cell(self.forward_initial_cell(context))?;
        let flags = self.checked_forward_state_flags(initial.next?)?;
        Some((initial, flags))
    }

    fn checked_forward_state_flags(&self, state: u32) -> Option<u8> {
        let flags = self.forward_state_flags(state)?;
        validate_forward_state_flags(flags)
    }

    fn reverse_start(
        &self,
        haystack: &[u8],
        window_start: usize,
        selected_end: usize,
    ) -> Option<usize> {
        let context = self.reverse_context_at(haystack, selected_end)?;
        let initial = decode_context_cell(self.reverse_initial_cell(context)?)?;
        let mut candidate = initial.event.then_some(selected_end);
        let mut state = initial.next;
        let mut cursor = selected_end;
        while cursor > window_start {
            let Some(current_state) = state else {
                break;
            };
            let source = cursor.checked_sub(1)?;
            let byte = source
                .checked_sub(1)
                .and_then(|index| haystack.get(index))
                .copied();
            let cell = decode_context_cell(self.reverse_cell_for_byte(current_state, byte)?)?;
            cursor = source;
            if cell.event {
                candidate = Some(cursor);
            }
            state = cell.next;
        }
        candidate
    }
}

fn validate_forward_state_flags(flags: u8) -> Option<u8> {
    let pending = flags & CONTEXT_STATE_PENDING != 0;
    let terminal = flags & CONTEXT_STATE_TERMINAL != 0;
    let empty = flags & CONTEXT_STATE_EMPTY != 0;
    if flags & !(CONTEXT_STATE_PENDING | CONTEXT_STATE_TERMINAL | CONTEXT_STATE_EMPTY) != 0
        || terminal != (pending && empty)
    {
        return None;
    }
    Some(flags)
}

fn decode_context_cell(word: u32) -> Option<DecodedContextCell> {
    if word & CONTEXT_CELL_VALID == 0 {
        return None;
    }
    let payload = word & CONTEXT_CELL_STATE_MASK;
    Some(DecodedContextCell {
        next: if payload == 0 {
            None
        } else {
            payload.checked_sub(1)
        },
        event: word & CONTEXT_CELL_EVENT != 0,
    })
}

fn decode_forward_transition_cell(word: u32) -> Option<DecodedForwardCell> {
    let payload = word & CONTEXT_FORWARD_CELL_STATE_MASK;
    if payload == 0 {
        return None;
    }
    let flags =
        u8::try_from((word & CONTEXT_FORWARD_CELL_FLAGS_MASK) >> CONTEXT_FORWARD_CELL_FLAGS_SHIFT)
            .ok()
            .and_then(validate_forward_state_flags)?;
    Some(DecodedForwardCell {
        next: payload.checked_sub(1)?,
        event: word & CONTEXT_CELL_EVENT != 0,
        flags,
    })
}

fn context_forward_flags(state: NativeContextForwardState) -> Result<u8, ObjectError> {
    let flags = if state.pending {
        CONTEXT_STATE_PENDING
    } else {
        0
    } | if state.empty { CONTEXT_STATE_EMPTY } else { 0 }
        | if state.terminal {
            CONTEXT_STATE_TERMINAL
        } else {
            0
        };
    validate_forward_state_flags(flags).ok_or(ObjectError::InvalidModule(
        "context forward state flags are incoherent",
    ))
}

/// Build an owned, deterministic contextual table image.
///
/// Exists/selected-end programs and fixed-width span programs normally omit
/// all reverse data. Other span programs retain both reverse rows and a second
/// complete 16-bit initial dispatch. Compile/link time is outside the matching
/// fast path, so the direct tables intentionally trade object size for one
/// indexed load at each initial boundary.
pub(crate) fn build_context_native_layout(
    view: NativeContextProgramView<'_>,
    limits: ContextNativeLimits,
) -> Result<ContextNativeLayout, ObjectError> {
    build_context_native_layout_with_reverse_mode(
        view,
        limits,
        false,
        ENABLE_CONTEXT_DIRECT_BYTE_TRANSITIONS,
        false,
    )
}

/// Build the contextual image while optionally retaining reverse tables for
/// a graph-selected suffix verifier. The ordinary Exists/SelectedEnd layout
/// stays compact; callers opt in only after a reverse-search profitability
/// proof.
#[allow(
    clippy::too_many_lines,
    reason = "validation, exact allocation, packing, and publication form one transaction"
)]
pub(crate) fn build_context_native_layout_with_reverse(
    view: NativeContextProgramView<'_>,
    limits: ContextNativeLimits,
    retain_reverse_for_suffix: bool,
) -> Result<ContextNativeLayout, ObjectError> {
    build_context_native_layout_with_reverse_mode(
        view,
        limits,
        retain_reverse_for_suffix,
        ENABLE_CONTEXT_DIRECT_BYTE_TRANSITIONS,
        false,
    )
}

/// Build a contextual image with explicitly selected optional native
/// accelerators. The anchored verifier is appended only when its graph and
/// profitability plan will actually be emitted.
pub(crate) fn build_context_native_layout_with_accelerators(
    view: NativeContextProgramView<'_>,
    limits: ContextNativeLimits,
    retain_reverse_for_suffix: bool,
    retain_anchored_forward: bool,
) -> Result<ContextNativeLayout, ObjectError> {
    build_context_native_layout_with_reverse_mode(
        view,
        limits,
        retain_reverse_for_suffix,
        ENABLE_CONTEXT_DIRECT_BYTE_TRANSITIONS,
        retain_anchored_forward,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "validation, exact allocation, packing, and publication form one transaction"
)]
fn build_context_native_layout_with_reverse_mode(
    view: NativeContextProgramView<'_>,
    limits: ContextNativeLimits,
    retain_reverse_for_suffix: bool,
    enable_direct_bytes: bool,
    retain_anchored_forward: bool,
) -> Result<ContextNativeLayout, ObjectError> {
    validate_native_view(view.dfa)?;
    let dfa = view.dfa;
    let class_count = usize::try_from(dfa.initial_dispatch.class_count)
        .map_err(|_| ObjectError::ArithmeticOverflow("context class count"))?;
    let row_width = usize::try_from(dfa.initial_dispatch.row_width)
        .map_err(|_| ObjectError::ArithmeticOverflow("context row width"))?;
    let forward_states = dfa.forward_states.len();
    let reverse_states =
        dfa.reverse_row_offsets
            .len()
            .checked_sub(1)
            .ok_or(ObjectError::InvalidModule(
                "context reverse row offsets are empty",
            ))?;
    check_state_count(forward_states)?;
    check_state_count(reverse_states)?;

    let exact_match_width = view
        .exact_match_width
        .map(|width| {
            u64::try_from(width)
                .map_err(|_| ObjectError::ArithmeticOverflow("context exact match width"))
        })
        .transpose()?;
    let max_match_width = view
        .max_match_width
        .map(|width| {
            u64::try_from(width)
                .map_err(|_| ObjectError::ArithmeticOverflow("context maximum match width"))
        })
        .transpose()?;
    let retain_reverse = (view.output == OutputContract::Span && exact_match_width.is_none())
        || (view.output == OutputContract::Exists && retain_reverse_for_suffix)
        || (view.output == OutputContract::SelectedEnd
            && exact_match_width.is_none()
            && retain_reverse_for_suffix);
    let raw_pair_initial = ENABLE_CONTEXT_RAW_PAIR_INITIAL_DISPATCH
        && raw_forward_initial_state_payload_fits(forward_states);
    let raw_pair_reverse_initial = retain_reverse
        && ENABLE_CONTEXT_RAW_PAIR_REVERSE_INITIAL_DISPATCH
        && raw_reverse_initial_state_payload_fits(reverse_states);
    let effective_limit = limits.max_data_bytes.min(MAX_CONTEXT_NATIVE_DATA_BYTES);
    let (mut direct_forward, mut direct_reverse) = select_direct_byte_directions(
        forward_states,
        reverse_states,
        retain_reverse,
        enable_direct_bytes,
    )?;
    let plan = loop {
        match plan_context_layout(
            forward_states,
            reverse_states,
            row_width,
            retain_reverse,
            raw_pair_initial,
            raw_pair_reverse_initial,
            direct_forward,
            direct_reverse,
            effective_limit,
        ) {
            Err(ObjectError::Resource {
                resource: CompileResource::ProgramBytes,
                ..
            }) if direct_reverse => direct_reverse = false,
            Err(ObjectError::Resource {
                resource: CompileResource::ProgramBytes,
                ..
            }) if direct_forward => direct_forward = false,
            result => break result?,
        }
    };

    let mut data = Vec::new();
    data.try_reserve_exact(plan.total)
        .map_err(|_| ObjectError::InvalidModule("context native allocation failed"))?;
    data.resize(plan.total, 0);
    let classes_end = plan
        .byte_classes
        .checked_add(CLASS_TABLE_BYTES)
        .ok_or(ObjectError::ArithmeticOverflow("context class table end"))?;
    data[plan.byte_classes..classes_end].copy_from_slice(dfa.byte_classes);
    let properties_end =
        plan.class_properties
            .checked_add(class_count)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context property table end",
            ))?;
    data[plan.class_properties..properties_end].copy_from_slice(dfa.class_properties);

    for (index, state) in dfa.forward_states.iter().enumerate() {
        let destination =
            plan.forward_state_flags
                .checked_add(index)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "context forward flag offset",
                ))?;
        data[destination] = context_forward_flags(*state)?;
    }
    populate_forward_transition_cells(
        &mut data,
        plan.forward_cells,
        plan.forward_byte_sentinel,
        dfa,
        forward_states,
        row_width,
    )?;
    if let Some(reverse_cells) = plan.reverse_cells {
        populate_reverse_transition_cells(
            &mut data,
            reverse_cells,
            plan.reverse_byte_sentinel,
            dfa,
            reverse_states,
            row_width,
        )?;
    }
    if let Some(raw) = plan.raw_pair_initial {
        populate_raw_pair_initial(&mut data, plan.forward_initial, raw, dfa)?;
    } else {
        populate_forward_initial(
            &mut data,
            plan.forward_initial,
            dfa.forward_initial,
            forward_states,
        )?;
    }
    if let Some(reverse_initial) = plan.reverse_initial {
        if let Some(raw) = plan.raw_pair_reverse_initial {
            populate_raw_reverse_initial(&mut data, reverse_initial, raw, dfa)?;
        } else {
            populate_reverse_initial(
                &mut data,
                reverse_initial,
                dfa.reverse_initial,
                reverse_states,
            )?;
        }
    }

    let raw_pair_initial = plan
        .raw_pair_initial
        .map(|raw| {
            Ok(ContextRawPairInitialLayout {
                forward_start_offset: checked_offset(
                    raw.forward_start,
                    "context raw forward start dispatch",
                )?,
                forward_end_offset: checked_offset(
                    raw.forward_end,
                    "context raw forward end dispatch",
                )?,
            })
        })
        .transpose()?;
    let raw_pair_reverse_initial = plan
        .raw_pair_reverse_initial
        .map(|raw| {
            Ok(ContextRawPairReverseInitialLayout {
                reverse_start_offset: checked_offset(
                    raw.reverse_start,
                    "context raw reverse start dispatch",
                )?,
                reverse_end_offset: checked_offset(
                    raw.reverse_end,
                    "context raw reverse end dispatch",
                )?,
            })
        })
        .transpose()?;
    let anchored_forward = if retain_anchored_forward
        && matches!(
            view.output,
            OutputContract::Span | OutputContract::SelectedEnd
        )
        && exact_match_width.is_none()
    {
        append_anchored_forward_layout(&mut data, dfa, effective_limit)?
    } else {
        None
    };

    Ok(ContextNativeLayout {
        output: view.output,
        class_count: u16::try_from(class_count)
            .map_err(|_| ObjectError::ArithmeticOverflow("context class count"))?,
        row_width: u16::try_from(row_width)
            .map_err(|_| ObjectError::ArithmeticOverflow("context row width"))?,
        forward_states: u32::try_from(forward_states)
            .map_err(|_| ObjectError::ArithmeticOverflow("context forward states"))?,
        reverse_states: if retain_reverse {
            u32::try_from(reverse_states)
                .map_err(|_| ObjectError::ArithmeticOverflow("context reverse states"))?
        } else {
            0
        },
        exact_match_width,
        max_match_width,
        byte_classes_offset: checked_offset(plan.byte_classes, "context byte classes")?,
        class_properties_offset: checked_offset(plan.class_properties, "context class properties")?,
        forward_state_flags_offset: checked_offset(
            plan.forward_state_flags,
            "context forward flags",
        )?,
        forward_cells_offset: checked_offset(plan.forward_cells, "context forward cells")?,
        forward_byte_sentinel_offset: plan
            .forward_byte_sentinel
            .map(|value| checked_offset(value, "context forward byte sentinel cells"))
            .transpose()?,
        reverse_cells_offset: plan
            .reverse_cells
            .map(|value| checked_offset(value, "context reverse cells"))
            .transpose()?,
        reverse_byte_sentinel_offset: plan
            .reverse_byte_sentinel
            .map(|value| checked_offset(value, "context reverse byte sentinel cells"))
            .transpose()?,
        forward_initial_offset: checked_offset(plan.forward_initial, "context forward dispatch")?,
        reverse_initial_offset: plan
            .reverse_initial
            .map(|value| checked_offset(value, "context reverse dispatch"))
            .transpose()?,
        raw_pair_initial,
        raw_pair_reverse_initial,
        anchored_forward,
        data,
    })
}

/// Append the optional exact-start verifier without changing mandatory layout
/// failure semantics. Any size or allocation ceiling simply omits the
/// sidecar; malformed target-neutral data remains a hard compiler error.
fn append_anchored_forward_layout(
    data: &mut Vec<u8>,
    dfa: NativeContextDfaView<'_>,
    effective_limit: usize,
) -> Result<Option<ContextAnchoredForwardLayout>, ObjectError> {
    if let Some(layout) = append_anchored_forward_layout_mode(data, dfa, effective_limit, true)? {
        return Ok(Some(layout));
    }
    append_anchored_forward_layout_mode(data, dfa, effective_limit, false)
}

fn append_anchored_forward_layout_mode(
    data: &mut Vec<u8>,
    dfa: NativeContextDfaView<'_>,
    effective_limit: usize,
    enable_direct_bytes: bool,
) -> Result<Option<ContextAnchoredForwardLayout>, ObjectError> {
    let Some(anchored) = dfa.anchored_forward else {
        return Ok(None);
    };
    let states = anchored.states.len();
    check_state_count(states)?;
    let row_width = usize::try_from(dfa.initial_dispatch.row_width)
        .map_err(|_| ObjectError::ArithmeticOverflow("context anchored row width"))?;
    let start = data.len();
    let Some(mut cursor) = align_up(
        start,
        core::mem::align_of::<u32>(),
        "context anchored map alignment",
    )
    .ok() else {
        return Ok(None);
    };
    let main_initial_to_anchored = cursor;
    let Some(map_bytes) = anchored
        .main_initial_to_anchored
        .len()
        .checked_mul(core::mem::size_of::<u32>())
    else {
        return Ok(None);
    };
    let Some(after_map) = cursor.checked_add(map_bytes) else {
        return Ok(None);
    };
    cursor = after_map;
    let state_flags = cursor;
    let Some(after_flags) = cursor.checked_add(states) else {
        return Ok(None);
    };
    let Some(aligned_cells) = align_up(
        after_flags,
        core::mem::align_of::<u32>(),
        "context anchored cell alignment",
    )
    .ok() else {
        return Ok(None);
    };
    cursor = aligned_cells;
    let cells = cursor;
    let direct_bytes = direct_byte_transition_bytes(states).ok();
    let direct = enable_direct_bytes
        && direct_bytes.is_some_and(|bytes| bytes <= CONTEXT_ANCHORED_DIRECT_BYTE_MAX_BYTES);
    let cell_bytes = if direct {
        let Some(bytes) = states.checked_mul(CONTEXT_DIRECT_BYTE_ROW_BYTES) else {
            return Ok(None);
        };
        bytes
    } else {
        let Some(bytes) = anchored
            .cells
            .len()
            .checked_mul(core::mem::size_of::<u32>())
        else {
            return Ok(None);
        };
        bytes
    };
    let Some(after_cells) = cursor.checked_add(cell_bytes) else {
        return Ok(None);
    };
    cursor = after_cells;
    let byte_sentinel = if direct {
        let offset = cursor;
        let Some(bytes) = states.checked_mul(core::mem::size_of::<u32>()) else {
            return Ok(None);
        };
        let Some(after_sentinel) = cursor.checked_add(bytes) else {
            return Ok(None);
        };
        cursor = after_sentinel;
        Some(offset)
    } else {
        None
    };
    let Some(added) = cursor.checked_sub(start) else {
        return Ok(None);
    };
    if added > CONTEXT_ANCHORED_MAX_ADDED_BYTES
        || cursor > effective_limit
        || cursor > MAX_CONTEXT_NATIVE_DATA_BYTES
    {
        return Ok(None);
    }
    if data.try_reserve_exact(added).is_err() {
        return Ok(None);
    }
    data.resize(cursor, 0);

    for (index, &mapped) in anchored.main_initial_to_anchored.iter().enumerate() {
        put_table_word(data, main_initial_to_anchored, index, mapped)?;
    }
    for (index, &state) in anchored.states.iter().enumerate() {
        let destination = state_flags
            .checked_add(index)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context anchored state flag",
            ))?;
        data[destination] = context_forward_flags(state)?;
    }
    populate_anchored_forward_cells(data, cells, byte_sentinel, dfa, anchored, states, row_width)?;

    Ok(Some(ContextAnchoredForwardLayout {
        states: u32::try_from(states)
            .map_err(|_| ObjectError::ArithmeticOverflow("context anchored states"))?,
        main_initial_to_anchored_offset: checked_offset(
            main_initial_to_anchored,
            "context anchored initial map",
        )?,
        state_flags_offset: checked_offset(state_flags, "context anchored state flags")?,
        cells_offset: checked_offset(cells, "context anchored cells")?,
        byte_sentinel_offset: byte_sentinel
            .map(|offset| checked_offset(offset, "context anchored sentinel cells"))
            .transpose()?,
        max_resolution_steps: anchored.max_resolution_steps,
    }))
}

fn populate_anchored_forward_cells(
    data: &mut [u8],
    table: usize,
    byte_sentinel: Option<usize>,
    dfa: NativeContextDfaView<'_>,
    anchored: NativeContextAnchoredForwardView<'_>,
    states: usize,
    row_width: usize,
) -> Result<(), ObjectError> {
    let Some(byte_sentinel) = byte_sentinel else {
        for (index, cell) in anchored.cells.iter().enumerate() {
            let successor =
                anchored
                    .states
                    .get(usize::try_from(cell.next).map_err(|_| {
                        ObjectError::ArithmeticOverflow("context anchored successor")
                    })?)
                    .copied()
                    .ok_or(ObjectError::InvalidModule(
                        "context anchored successor is out of range",
                    ))?;
            let packed = pack_forward_transition_cell(
                cell.next,
                cell.accepted,
                context_forward_flags(successor)?,
                states,
            )?;
            put_table_word(data, table, index, packed)?;
        }
        return Ok(());
    };
    let sentinel = usize::try_from(dfa.initial_dispatch.sentinel_class)
        .map_err(|_| ObjectError::ArithmeticOverflow("context anchored sentinel class"))?;
    for state in 0..states {
        let source_row = state
            .checked_mul(row_width)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context anchored direct-byte source row",
            ))?;
        let destination_row = state.checked_mul(CONTEXT_DIRECT_BYTE_ROW_CELLS).ok_or(
            ObjectError::ArithmeticOverflow("context anchored direct-byte destination row"),
        )?;
        for byte in u8::MIN..=u8::MAX {
            let class = usize::from(dfa.byte_classes[usize::from(byte)]);
            let cell = anchored.cells[source_row + class];
            let successor =
                anchored
                    .states
                    .get(usize::try_from(cell.next).map_err(|_| {
                        ObjectError::ArithmeticOverflow("context anchored successor")
                    })?)
                    .copied()
                    .ok_or(ObjectError::InvalidModule(
                        "context anchored successor is out of range",
                    ))?;
            let packed = pack_forward_transition_cell(
                cell.next,
                cell.accepted,
                context_forward_flags(successor)?,
                states,
            )?;
            put_table_word(data, table, destination_row + usize::from(byte), packed)?;
        }
        let cell = anchored.cells[source_row + sentinel];
        let successor = anchored
            .states
            .get(
                usize::try_from(cell.next)
                    .map_err(|_| ObjectError::ArithmeticOverflow("context anchored successor"))?,
            )
            .copied()
            .ok_or(ObjectError::InvalidModule(
                "context anchored successor is out of range",
            ))?;
        let packed = pack_forward_transition_cell(
            cell.next,
            cell.accepted,
            context_forward_flags(successor)?,
            states,
        )?;
        put_table_word(data, byte_sentinel, state, packed)?;
    }
    Ok(())
}

fn expand_raw_forward_initial(word: u16) -> u32 {
    let payload = word & CONTEXT_RAW_FORWARD_STATE_MASK;
    if word & CONTEXT_RAW_FORWARD_VALID == 0 || payload == 0 {
        return CONTEXT_INVALID_CELL;
    }
    CONTEXT_CELL_VALID | u32::from(payload)
}

fn expand_raw_reverse_initial(word: u16) -> u32 {
    if word & CONTEXT_RAW_REVERSE_VALID == 0 {
        return CONTEXT_INVALID_CELL;
    }
    CONTEXT_CELL_VALID
        | u32::from(word & CONTEXT_RAW_REVERSE_STATE_MASK)
        | if word & CONTEXT_RAW_REVERSE_EVENT != 0 {
            CONTEXT_CELL_EVENT
        } else {
            0
        }
}

#[allow(
    clippy::too_many_lines,
    reason = "all cross-slice native-view invariants are audited together before allocation"
)]
fn validate_native_view(dfa: NativeContextDfaView<'_>) -> Result<(), ObjectError> {
    let dispatch = dfa.initial_dispatch;
    let class_count = usize::try_from(dispatch.class_count)
        .map_err(|_| ObjectError::ArithmeticOverflow("context class count"))?;
    if class_count == 0
        || class_count > CLASS_TABLE_BYTES
        || dispatch.sentinel_class != dispatch.class_count
        || dispatch.row_width
            != dispatch
                .class_count
                .checked_add(1)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "context dispatch row width",
                ))?
        || dispatch.class_mask != CONTEXT_CLASS_MASK
        || dispatch.properties_mask != CONTEXT_PROPERTIES_MASK
        || dispatch.properties_shift != CONTEXT_PROPERTIES_SHIFT
        || dispatch.present_bit != CONTEXT_PRESENT_BIT
        || dispatch.absolute_start_bit != CONTEXT_ABSOLUTE_START_BIT
        || dispatch.absolute_end_bit != CONTEXT_ABSOLUTE_END_BIT
    {
        return Err(ObjectError::InvalidModule(
            "invalid contextual dispatch metadata",
        ));
    }
    if dfa.class_representatives.len() != class_count
        || dfa.class_properties.len() != class_count
        || dfa
            .byte_classes
            .iter()
            .any(|&class| usize::from(class) >= class_count)
        || dfa
            .class_properties
            .iter()
            .any(|properties| properties & !CONTEXT_PROPERTIES_MASK != 0)
    {
        return Err(ObjectError::InvalidModule(
            "invalid contextual alphabet tables",
        ));
    }
    for (class, &representative) in dfa.class_representatives.iter().enumerate() {
        if usize::from(dfa.byte_classes[usize::from(representative)]) != class {
            return Err(ObjectError::InvalidModule(
                "context representative has the wrong class",
            ));
        }
    }
    if dfa.forward_states.is_empty() {
        return Err(ObjectError::InvalidModule(
            "context forward machine has no states",
        ));
    }
    if dfa
        .forward_states
        .iter()
        .any(|state| state.terminal != (state.pending && state.empty))
    {
        return Err(ObjectError::InvalidModule(
            "context terminal state flags are incoherent",
        ));
    }
    let row_width = usize::try_from(dispatch.row_width)
        .map_err(|_| ObjectError::ArithmeticOverflow("context row width"))?;
    validate_fixed_rows(
        dfa.forward_row_offsets,
        dfa.forward_states.len(),
        row_width,
        dfa.forward_cells.len(),
        "invalid contextual forward row geometry",
    )?;
    let reverse_states =
        dfa.reverse_row_offsets
            .len()
            .checked_sub(1)
            .ok_or(ObjectError::InvalidModule(
                "context reverse row offsets are empty",
            ))?;
    validate_fixed_rows(
        dfa.reverse_row_offsets,
        reverse_states,
        row_width,
        dfa.reverse_cells.len(),
        "invalid contextual reverse row geometry",
    )?;
    validate_initial_contexts(dfa.forward_initial.iter().map(|entry| entry.context))?;
    validate_initial_contexts(dfa.reverse_initial.iter().map(|entry| entry.context))?;
    for entry in dfa.forward_initial {
        validate_state(entry.state, dfa.forward_states.len())?;
    }
    for cell in dfa.forward_cells {
        validate_state(cell.next, dfa.forward_states.len())?;
    }
    for entry in dfa.reverse_initial {
        if entry.state != VIEW_NO_STATE {
            validate_state(entry.state, reverse_states)?;
        }
    }
    for cell in dfa.reverse_cells {
        if cell.next != VIEW_NO_STATE {
            validate_state(cell.next, reverse_states)?;
        }
    }
    if let Some(anchored) = dfa.anchored_forward {
        validate_anchored_forward_view(dfa, anchored, row_width)?;
    }
    Ok(())
}

fn validate_anchored_forward_view(
    dfa: NativeContextDfaView<'_>,
    anchored: NativeContextAnchoredForwardView<'_>,
    row_width: usize,
) -> Result<(), ObjectError> {
    if anchored.states.is_empty()
        || anchored.main_initial_to_anchored.len() != dfa.forward_states.len()
        || anchored
            .states
            .iter()
            .any(|state| state.terminal != (state.pending && state.empty))
    {
        return Err(ObjectError::InvalidModule(
            "invalid contextual anchored-forward dimensions or flags",
        ));
    }
    validate_fixed_rows(
        anchored.row_offsets,
        anchored.states.len(),
        row_width,
        anchored.cells.len(),
        "invalid contextual anchored-forward row geometry",
    )?;
    for (main, &mapped) in anchored.main_initial_to_anchored.iter().enumerate() {
        let is_initial = dfa
            .forward_initial
            .iter()
            .any(|entry| usize::try_from(entry.state).ok() == Some(main));
        if (mapped != VIEW_NO_STATE) != is_initial {
            return Err(ObjectError::InvalidModule(
                "context anchored map domain differs from main initial states",
            ));
        }
        if mapped != VIEW_NO_STATE {
            validate_state(mapped, anchored.states.len())?;
        }
    }
    for cell in anchored.cells {
        validate_state(cell.next, anchored.states.len())?;
    }
    let mut mapped_initials = 0_usize;
    for initial in dfa.forward_initial {
        let main = usize::try_from(initial.state)
            .map_err(|_| ObjectError::ArithmeticOverflow("context anchored main initial"))?;
        let mapped = *anchored
            .main_initial_to_anchored
            .get(main)
            .filter(|&&state| state != VIEW_NO_STATE)
            .ok_or(ObjectError::InvalidModule(
                "context anchored main initial is not mapped",
            ))?;
        let mapped_index = usize::try_from(mapped)
            .map_err(|_| ObjectError::ArithmeticOverflow("context anchored initial"))?;
        let main_flags = dfa
            .forward_states
            .get(main)
            .ok_or(ObjectError::InvalidModule(
                "context anchored main initial state is absent",
            ))?;
        let anchored_flags =
            anchored
                .states
                .get(mapped_index)
                .ok_or(ObjectError::InvalidModule(
                    "context anchored initial state is absent",
                ))?;
        if main_flags != anchored_flags {
            return Err(ObjectError::InvalidModule(
                "context anchored initial flags differ from the main state",
            ));
        }
        mapped_initials = mapped_initials
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context anchored mapped initial count",
            ))?;
    }
    if mapped_initials == 0 {
        return Err(ObjectError::InvalidModule(
            "context anchored forward has no mapped initial states",
        ));
    }
    Ok(())
}

fn validate_fixed_rows(
    offsets: &[u32],
    states: usize,
    row_width: usize,
    cells: usize,
    message: &'static str,
) -> Result<(), ObjectError> {
    let offset_count = states
        .checked_add(1)
        .ok_or(ObjectError::ArithmeticOverflow("context row offset count"))?;
    let expected_cells = states
        .checked_mul(row_width)
        .ok_or(ObjectError::ArithmeticOverflow("context fixed row cells"))?;
    if offsets.len() != offset_count || cells != expected_cells {
        return Err(ObjectError::InvalidModule(message));
    }
    for (state, &actual) in offsets.iter().enumerate() {
        let expected = state
            .checked_mul(row_width)
            .ok_or(ObjectError::ArithmeticOverflow("context row offset"))?;
        if usize::try_from(actual).ok() != Some(expected) {
            return Err(ObjectError::InvalidModule(message));
        }
    }
    Ok(())
}

fn validate_initial_contexts(contexts: impl Iterator<Item = u32>) -> Result<(), ObjectError> {
    let mut previous = None;
    for context in contexts {
        if u16::try_from(context).is_err() || previous.is_some_and(|value| value >= context) {
            return Err(ObjectError::InvalidModule(
                "context initial dispatch is not canonical",
            ));
        }
        previous = Some(context);
    }
    Ok(())
}

fn validate_state(state: u32, states: usize) -> Result<(), ObjectError> {
    let state = usize::try_from(state)
        .map_err(|_| ObjectError::ArithmeticOverflow("context state index"))?;
    if state >= states {
        return Err(ObjectError::InvalidModule(
            "context state is outside its table",
        ));
    }
    Ok(())
}

fn check_state_count(states: usize) -> Result<(), ObjectError> {
    if states > MAX_PACKED_CONTEXT_STATES {
        return Err(ObjectError::Resource {
            resource: CompileResource::DfaStates,
            limit: MAX_PACKED_CONTEXT_STATES,
            required: states,
        });
    }
    Ok(())
}

fn direct_byte_transition_bytes(states: usize) -> Result<usize, ObjectError> {
    states
        .checked_mul(
            CONTEXT_DIRECT_BYTE_ROW_BYTES
                .checked_add(core::mem::size_of::<u32>())
                .ok_or(ObjectError::ArithmeticOverflow(
                    "context direct-byte row and sentinel bytes",
                ))?,
        )
        .ok_or(ObjectError::ArithmeticOverflow(
            "context direct-byte transition bytes",
        ))
}

fn select_direct_byte_directions(
    forward_states: usize,
    reverse_states: usize,
    retain_reverse: bool,
    enabled: bool,
) -> Result<(bool, bool), ObjectError> {
    if !enabled {
        return Ok((false, false));
    }
    let direct_forward = forward_states != 0 && forward_states <= CONTEXT_DIRECT_BYTE_MAX_STATES;
    let forward_bytes = if direct_forward {
        direct_byte_transition_bytes(forward_states)?
    } else {
        0
    };
    let reverse_eligible =
        retain_reverse && reverse_states != 0 && reverse_states <= CONTEXT_DIRECT_BYTE_MAX_STATES;
    let reverse_bytes = if reverse_eligible {
        direct_byte_transition_bytes(reverse_states)?
    } else {
        0
    };
    let direct_reverse = reverse_eligible
        && forward_bytes
            .checked_add(reverse_bytes)
            .is_some_and(|bytes| bytes <= CONTEXT_DIRECT_BYTE_MAX_COMBINED_BYTES);
    Ok((direct_forward, direct_reverse))
}

#[allow(
    clippy::too_many_lines,
    reason = "all table sections and exact resource accounting form one auditable layout transaction"
)]
fn plan_context_layout(
    forward_states: usize,
    reverse_states: usize,
    row_width: usize,
    retain_reverse: bool,
    raw_pair_initial: bool,
    raw_pair_reverse_initial: bool,
    direct_forward: bool,
    direct_reverse: bool,
    limit: usize,
) -> Result<ContextLayoutPlan, ObjectError> {
    check_state_count(forward_states)?;
    check_state_count(reverse_states)?;
    if direct_reverse && !retain_reverse {
        return Err(ObjectError::InvalidModule(
            "direct-byte reverse cells require retained reverse rows",
        ));
    }
    let row_bytes = row_width
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(ObjectError::ArithmeticOverflow("context row bytes"))?;
    let mut cursor = 0;
    let byte_classes = reserve_section(&mut cursor, CLASS_TABLE_BYTES, "context class map")?;
    let class_properties = reserve_section(&mut cursor, CLASS_TABLE_BYTES, "context property map")?;
    let forward_state_flags =
        reserve_section(&mut cursor, forward_states, "context forward state flags")?;
    cursor = align_up(
        cursor,
        core::mem::align_of::<u32>(),
        "context cell alignment",
    )?;
    let forward_cell_bytes = if direct_forward {
        forward_states
            .checked_mul(CONTEXT_DIRECT_BYTE_ROW_BYTES)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context direct-byte forward cell bytes",
            ))?
    } else {
        forward_states
            .checked_mul(row_bytes)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context forward cell bytes",
            ))?
    };
    let forward_cells = reserve_section(&mut cursor, forward_cell_bytes, "context forward cells")?;
    let forward_byte_sentinel = if direct_forward {
        Some(reserve_section(
            &mut cursor,
            forward_states
                .checked_mul(core::mem::size_of::<u32>())
                .ok_or(ObjectError::ArithmeticOverflow(
                    "context direct-byte forward sentinel bytes",
                ))?,
            "context direct-byte forward sentinel cells",
        )?)
    } else {
        None
    };
    let reverse_cells = if retain_reverse {
        let reverse_cell_bytes = if direct_reverse {
            reverse_states
                .checked_mul(CONTEXT_DIRECT_BYTE_ROW_BYTES)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "context direct-byte reverse cell bytes",
                ))?
        } else {
            reverse_states
                .checked_mul(row_bytes)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "context reverse cell bytes",
                ))?
        };
        Some(reserve_section(
            &mut cursor,
            reverse_cell_bytes,
            "context reverse cells",
        )?)
    } else {
        None
    };
    let reverse_byte_sentinel = if direct_reverse {
        Some(reserve_section(
            &mut cursor,
            reverse_states
                .checked_mul(core::mem::size_of::<u32>())
                .ok_or(ObjectError::ArithmeticOverflow(
                    "context direct-byte reverse sentinel bytes",
                ))?,
            "context direct-byte reverse sentinel cells",
        )?)
    } else {
        None
    };
    let forward_initial_bytes = if raw_pair_initial {
        CONTEXT_RAW_PAIR_BYTES
    } else {
        CONTEXT_DISPATCH_BYTES
    };
    let forward_initial = reserve_section(
        &mut cursor,
        forward_initial_bytes,
        "context forward initial dispatch",
    )?;
    let reverse_initial = if retain_reverse {
        let reverse_initial_bytes = if raw_pair_reverse_initial {
            CONTEXT_RAW_PAIR_BYTES
        } else {
            CONTEXT_DISPATCH_BYTES
        };
        Some(reserve_section(
            &mut cursor,
            reverse_initial_bytes,
            "context reverse initial dispatch",
        )?)
    } else {
        None
    };
    let raw_pair_initial = if raw_pair_initial {
        let forward_start = reserve_section(
            &mut cursor,
            CONTEXT_RAW_START_BYTES,
            "context raw forward start dispatch",
        )?;
        let forward_end = reserve_section(
            &mut cursor,
            CONTEXT_RAW_END_BYTES,
            "context raw forward end dispatch",
        )?;
        Some(ContextRawPairInitialPlan {
            forward_start,
            forward_end,
        })
    } else {
        None
    };
    let raw_pair_reverse_initial = if raw_pair_reverse_initial {
        if !retain_reverse {
            return Err(ObjectError::InvalidModule(
                "raw reverse dispatch requires retained reverse rows",
            ));
        }
        let reverse_start = reserve_section(
            &mut cursor,
            CONTEXT_RAW_START_BYTES,
            "context raw reverse start dispatch",
        )?;
        let reverse_end = reserve_section(
            &mut cursor,
            CONTEXT_RAW_END_BYTES,
            "context raw reverse end dispatch",
        )?;
        Some(ContextRawPairReverseInitialPlan {
            reverse_start,
            reverse_end,
        })
    } else {
        None
    };
    if cursor > limit {
        return Err(ObjectError::Resource {
            resource: CompileResource::ProgramBytes,
            limit,
            required: cursor,
        });
    }
    Ok(ContextLayoutPlan {
        byte_classes,
        class_properties,
        forward_state_flags,
        forward_cells,
        forward_byte_sentinel,
        reverse_cells,
        reverse_byte_sentinel,
        forward_initial,
        reverse_initial,
        raw_pair_initial,
        raw_pair_reverse_initial,
        total: cursor,
    })
}

fn reserve_section(
    cursor: &mut usize,
    bytes: usize,
    site: &'static str,
) -> Result<usize, ObjectError> {
    let begin = *cursor;
    *cursor = cursor
        .checked_add(bytes)
        .ok_or(ObjectError::ArithmeticOverflow(site))?;
    Ok(begin)
}

fn align_up(value: usize, alignment: usize, site: &'static str) -> Result<usize, ObjectError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(ObjectError::ArithmeticOverflow(site))?;
    if !alignment.is_power_of_two() {
        return Err(ObjectError::InvalidModule(
            "context table alignment is not a power of two",
        ));
    }
    value
        .checked_add(mask)
        .map(|aligned| aligned & !mask)
        .ok_or(ObjectError::ArithmeticOverflow(site))
}

fn pack_context_cell(next: Option<u32>, event: bool, states: usize) -> Result<u32, ObjectError> {
    check_state_count(states)?;
    let payload = match next {
        None => 0,
        Some(next) => {
            validate_state(next, states)?;
            next.checked_add(1)
                .filter(|&encoded| encoded <= CONTEXT_CELL_STATE_MASK)
                .ok_or(ObjectError::InvalidModule(
                    "context state exceeds packed cell payload",
                ))?
        }
    };
    Ok(CONTEXT_CELL_VALID | if event { CONTEXT_CELL_EVENT } else { 0 } | payload)
}

fn pack_forward_transition_cell(
    next: u32,
    event: bool,
    flags: u8,
    states: usize,
) -> Result<u32, ObjectError> {
    check_state_count(states)?;
    if states > MAX_PACKED_CONTEXT_FORWARD_STATES {
        return Err(ObjectError::InvalidModule(
            "context forward states exceed packed transition payload",
        ));
    }
    validate_state(next, states)?;
    let flags = validate_forward_state_flags(flags).ok_or(ObjectError::InvalidModule(
        "invalid contextual forward successor flags",
    ))?;
    let payload = next
        .checked_add(1)
        .filter(|&encoded| encoded <= CONTEXT_FORWARD_CELL_STATE_MASK)
        .ok_or(ObjectError::InvalidModule(
            "context state exceeds packed forward transition payload",
        ))?;
    Ok(if event { CONTEXT_CELL_EVENT } else { 0 }
        | (u32::from(flags) << CONTEXT_FORWARD_CELL_FLAGS_SHIFT)
        | payload)
}

fn populate_forward_transition_cells(
    data: &mut [u8],
    table: usize,
    byte_sentinel: Option<usize>,
    dfa: NativeContextDfaView<'_>,
    states: usize,
    row_width: usize,
) -> Result<(), ObjectError> {
    let Some(byte_sentinel) = byte_sentinel else {
        for (index, cell) in dfa.forward_cells.iter().enumerate() {
            let successor =
                dfa.forward_states
                    .get(usize::try_from(cell.next).map_err(|_| {
                        ObjectError::ArithmeticOverflow("context forward successor")
                    })?)
                    .copied()
                    .ok_or(ObjectError::InvalidModule(
                        "context forward successor is out of range",
                    ))?;
            let packed = pack_forward_transition_cell(
                cell.next,
                cell.accepted,
                context_forward_flags(successor)?,
                states,
            )?;
            put_table_word(data, table, index, packed)?;
        }
        return Ok(());
    };
    let sentinel = usize::try_from(dfa.initial_dispatch.sentinel_class)
        .map_err(|_| ObjectError::ArithmeticOverflow("context sentinel class"))?;
    for state in 0..states {
        let source_row = state
            .checked_mul(row_width)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context direct-byte forward source row",
            ))?;
        let destination_row = state.checked_mul(CONTEXT_DIRECT_BYTE_ROW_CELLS).ok_or(
            ObjectError::ArithmeticOverflow("context direct-byte forward destination row"),
        )?;
        for byte in u8::MIN..=u8::MAX {
            let class = usize::from(dfa.byte_classes[usize::from(byte)]);
            let cell = dfa.forward_cells[source_row + class];
            let successor =
                dfa.forward_states
                    .get(usize::try_from(cell.next).map_err(|_| {
                        ObjectError::ArithmeticOverflow("context forward successor")
                    })?)
                    .copied()
                    .ok_or(ObjectError::InvalidModule(
                        "context forward successor is out of range",
                    ))?;
            let packed = pack_forward_transition_cell(
                cell.next,
                cell.accepted,
                context_forward_flags(successor)?,
                states,
            )?;
            put_table_word(data, table, destination_row + usize::from(byte), packed)?;
        }
        let cell = dfa.forward_cells[source_row + sentinel];
        let successor = dfa
            .forward_states
            .get(
                usize::try_from(cell.next)
                    .map_err(|_| ObjectError::ArithmeticOverflow("context forward successor"))?,
            )
            .copied()
            .ok_or(ObjectError::InvalidModule(
                "context forward successor is out of range",
            ))?;
        let packed = pack_forward_transition_cell(
            cell.next,
            cell.accepted,
            context_forward_flags(successor)?,
            states,
        )?;
        put_table_word(data, byte_sentinel, state, packed)?;
    }
    Ok(())
}

fn populate_reverse_transition_cells(
    data: &mut [u8],
    table: usize,
    byte_sentinel: Option<usize>,
    dfa: NativeContextDfaView<'_>,
    states: usize,
    row_width: usize,
) -> Result<(), ObjectError> {
    let pack = |cell: crate::context_dfa::NativeContextReverseCell| {
        let next = (cell.next != VIEW_NO_STATE).then_some(cell.next);
        pack_context_cell(next, cell.reaches_start, states)
    };
    let Some(byte_sentinel) = byte_sentinel else {
        for (index, &cell) in dfa.reverse_cells.iter().enumerate() {
            put_table_word(data, table, index, pack(cell)?)?;
        }
        return Ok(());
    };
    let sentinel = usize::try_from(dfa.initial_dispatch.sentinel_class)
        .map_err(|_| ObjectError::ArithmeticOverflow("context sentinel class"))?;
    for state in 0..states {
        let source_row = state
            .checked_mul(row_width)
            .ok_or(ObjectError::ArithmeticOverflow(
                "context direct-byte reverse source row",
            ))?;
        let destination_row = state.checked_mul(CONTEXT_DIRECT_BYTE_ROW_CELLS).ok_or(
            ObjectError::ArithmeticOverflow("context direct-byte reverse destination row"),
        )?;
        for byte in u8::MIN..=u8::MAX {
            let class = usize::from(dfa.byte_classes[usize::from(byte)]);
            put_table_word(
                data,
                table,
                destination_row + usize::from(byte),
                pack(dfa.reverse_cells[source_row + class])?,
            )?;
        }
        put_table_word(
            data,
            byte_sentinel,
            state,
            pack(dfa.reverse_cells[source_row + sentinel])?,
        )?;
    }
    Ok(())
}

fn populate_forward_initial(
    data: &mut [u8],
    table: usize,
    entries: &[crate::context_dfa::NativeContextForwardInitial],
    states: usize,
) -> Result<(), ObjectError> {
    for entry in entries {
        let context = usize::try_from(entry.context)
            .map_err(|_| ObjectError::ArithmeticOverflow("context forward key"))?;
        if context >= CONTEXT_DISPATCH_ENTRIES {
            return Err(ObjectError::InvalidModule(
                "context forward key exceeds 16 bits",
            ));
        }
        if table_word(data, table, context) != CONTEXT_INVALID_CELL {
            return Err(ObjectError::InvalidModule(
                "duplicate context forward initial key",
            ));
        }
        let packed = pack_context_cell(Some(entry.state), false, states)?;
        put_table_word(data, table, context, packed)?;
    }
    Ok(())
}

fn populate_reverse_initial(
    data: &mut [u8],
    table: usize,
    entries: &[crate::context_dfa::NativeContextReverseInitial],
    states: usize,
) -> Result<(), ObjectError> {
    for entry in entries {
        let context = usize::try_from(entry.context)
            .map_err(|_| ObjectError::ArithmeticOverflow("context reverse key"))?;
        if context >= CONTEXT_DISPATCH_ENTRIES {
            return Err(ObjectError::InvalidModule(
                "context reverse key exceeds 16 bits",
            ));
        }
        if table_word(data, table, context) != CONTEXT_INVALID_CELL {
            return Err(ObjectError::InvalidModule(
                "duplicate context reverse initial key",
            ));
        }
        let next = (entry.state != VIEW_NO_STATE).then_some(entry.state);
        let packed = pack_context_cell(next, entry.reaches_start, states)?;
        put_table_word(data, table, context, packed)?;
    }
    Ok(())
}

fn forward_initial_entry(
    entries: &[crate::context_dfa::NativeContextForwardInitial],
    context: u32,
) -> Option<crate::context_dfa::NativeContextForwardInitial> {
    entries
        .binary_search_by_key(&context, |entry| entry.context)
        .ok()
        .and_then(|index| entries.get(index))
        .copied()
}

fn reverse_initial_entry(
    entries: &[crate::context_dfa::NativeContextReverseInitial],
    context: u32,
) -> Option<crate::context_dfa::NativeContextReverseInitial> {
    entries
        .binary_search_by_key(&context, |entry| entry.context)
        .ok()
        .and_then(|index| entries.get(index))
        .copied()
}

fn pack_raw_forward_initial(
    dfa: NativeContextDfaView<'_>,
    context: u32,
) -> Result<u16, ObjectError> {
    let Some(entry) = forward_initial_entry(dfa.forward_initial, context) else {
        return Ok(0);
    };
    validate_state(entry.state, dfa.forward_states.len())?;
    let state_index = usize::try_from(entry.state)
        .map_err(|_| ObjectError::ArithmeticOverflow("context raw forward state"))?;
    let state = dfa
        .forward_states
        .get(state_index)
        .ok_or(ObjectError::InvalidModule(
            "context raw forward state is absent",
        ))?;
    let payload = entry
        .state
        .checked_add(1)
        .and_then(|state| u16::try_from(state).ok())
        .filter(|&state| state <= CONTEXT_RAW_FORWARD_STATE_MASK)
        .ok_or(ObjectError::InvalidModule(
            "context raw forward state exceeds its payload",
        ))?;
    Ok(CONTEXT_RAW_FORWARD_VALID
        | payload
        | if state.empty {
            CONTEXT_RAW_FORWARD_EMPTY
        } else {
            0
        })
}

fn pack_raw_reverse_initial(
    dfa: NativeContextDfaView<'_>,
    context: u32,
) -> Result<u16, ObjectError> {
    let Some(entry) = reverse_initial_entry(dfa.reverse_initial, context) else {
        return Ok(0);
    };
    let payload = if entry.state == VIEW_NO_STATE {
        0
    } else {
        validate_state(entry.state, dfa.reverse_row_offsets.len().saturating_sub(1))?;
        entry
            .state
            .checked_add(1)
            .and_then(|state| u16::try_from(state).ok())
            .filter(|&state| state <= CONTEXT_RAW_REVERSE_STATE_MASK)
            .ok_or(ObjectError::InvalidModule(
                "context raw reverse state exceeds 14 bits",
            ))?
    };
    Ok(CONTEXT_RAW_REVERSE_VALID
        | payload
        | if entry.reaches_start {
            CONTEXT_RAW_REVERSE_EVENT
        } else {
            0
        })
}

fn context_class(dfa: NativeContextDfaView<'_>, byte: u8) -> u32 {
    u32::from(dfa.byte_classes[usize::from(byte)])
}

fn context_properties(dfa: NativeContextDfaView<'_>, byte: u8) -> u8 {
    let class = usize::from(dfa.byte_classes[usize::from(byte)]);
    dfa.class_properties[class]
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "raw-pair indexes are exhaustively bounded by the 16-bit table domain"
)]
fn populate_raw_pair_initial(
    data: &mut [u8],
    forward_pairs: usize,
    plan: ContextRawPairInitialPlan,
    dfa: NativeContextDfaView<'_>,
) -> Result<(), ObjectError> {
    for pair in 0..CONTEXT_DISPATCH_ENTRIES {
        let previous = u8::try_from(pair & 0xff)
            .map_err(|_| ObjectError::ArithmeticOverflow("context raw previous byte"))?;
        let current = u8::try_from(pair >> 8)
            .map_err(|_| ObjectError::ArithmeticOverflow("context raw current byte"))?;
        let forward_context = dfa
            .initial_dispatch
            .pack(
                context_class(dfa, current),
                context_properties(dfa, previous),
                true,
                false,
                false,
            )
            .ok_or(ObjectError::InvalidModule(
                "context raw forward pair does not pack",
            ))?;
        put_table_halfword(
            data,
            forward_pairs,
            pair,
            pack_raw_forward_initial(dfa, forward_context)?,
        )?;
    }

    let sentinel = dfa.initial_dispatch.sentinel_class;
    for byte in 0_u16..=256 {
        let current = (byte < 256).then(|| u8::try_from(byte).expect("bounded byte"));
        let forward_context = dfa
            .initial_dispatch
            .pack(
                current.map_or(sentinel, |value| context_class(dfa, value)),
                0,
                false,
                true,
                current.is_none(),
            )
            .ok_or(ObjectError::InvalidModule(
                "context raw forward start does not pack",
            ))?;
        put_table_halfword(
            data,
            plan.forward_start,
            usize::from(byte),
            pack_raw_forward_initial(dfa, forward_context)?,
        )?;
    }
    for byte in 0_u16..256 {
        let byte = u8::try_from(byte).expect("bounded byte");
        let forward_context = dfa
            .initial_dispatch
            .pack(sentinel, context_properties(dfa, byte), true, false, true)
            .ok_or(ObjectError::InvalidModule(
                "context raw forward end does not pack",
            ))?;
        put_table_halfword(
            data,
            plan.forward_end,
            usize::from(byte),
            pack_raw_forward_initial(dfa, forward_context)?,
        )?;
    }
    Ok(())
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "raw-pair indexes are exhaustively bounded by the 16-bit table domain"
)]
fn populate_raw_reverse_initial(
    data: &mut [u8],
    reverse_pairs: usize,
    plan: ContextRawPairReverseInitialPlan,
    dfa: NativeContextDfaView<'_>,
) -> Result<(), ObjectError> {
    for pair in 0..CONTEXT_DISPATCH_ENTRIES {
        let previous = u8::try_from(pair & 0xff)
            .map_err(|_| ObjectError::ArithmeticOverflow("context raw previous byte"))?;
        let current = u8::try_from(pair >> 8)
            .map_err(|_| ObjectError::ArithmeticOverflow("context raw current byte"))?;
        let reverse_context = dfa
            .initial_dispatch
            .pack(
                context_class(dfa, previous),
                context_properties(dfa, current),
                true,
                false,
                false,
            )
            .ok_or(ObjectError::InvalidModule(
                "context raw reverse pair does not pack",
            ))?;
        put_table_halfword(
            data,
            reverse_pairs,
            pair,
            pack_raw_reverse_initial(dfa, reverse_context)?,
        )?;
    }

    let sentinel = dfa.initial_dispatch.sentinel_class;
    for byte in 0_u16..=256 {
        let current = (byte < 256).then(|| u8::try_from(byte).expect("bounded byte"));
        let reverse_context = dfa
            .initial_dispatch
            .pack(
                sentinel,
                current.map_or(0, |value| context_properties(dfa, value)),
                current.is_some(),
                true,
                current.is_none(),
            )
            .ok_or(ObjectError::InvalidModule(
                "context raw reverse start does not pack",
            ))?;
        put_table_halfword(
            data,
            plan.reverse_start,
            usize::from(byte),
            pack_raw_reverse_initial(dfa, reverse_context)?,
        )?;
    }
    for byte in 0_u16..256 {
        let byte = u8::try_from(byte).expect("bounded byte");
        let reverse_context = dfa
            .initial_dispatch
            .pack(context_class(dfa, byte), 0, false, false, true)
            .ok_or(ObjectError::InvalidModule(
                "context raw reverse end does not pack",
            ))?;
        put_table_halfword(
            data,
            plan.reverse_end,
            usize::from(byte),
            pack_raw_reverse_initial(dfa, reverse_context)?,
        )?;
    }
    Ok(())
}

fn checked_offset(value: usize, site: &'static str) -> Result<u32, ObjectError> {
    u32::try_from(value).map_err(|_| ObjectError::ArithmeticOverflow(site))
}

fn offset(value: u32) -> usize {
    usize::try_from(value).expect("u32 context offset fits the host address space")
}

fn put_table_word(
    data: &mut [u8],
    table: usize,
    index: usize,
    word: u32,
) -> Result<(), ObjectError> {
    let begin = index
        .checked_mul(core::mem::size_of::<u32>())
        .and_then(|relative| table.checked_add(relative))
        .ok_or(ObjectError::ArithmeticOverflow("context table word offset"))?;
    let end = begin
        .checked_add(core::mem::size_of::<u32>())
        .ok_or(ObjectError::ArithmeticOverflow("context table word end"))?;
    let destination = data
        .get_mut(begin..end)
        .ok_or(ObjectError::InvalidModule("context table word is absent"))?;
    destination.copy_from_slice(&word.to_le_bytes());
    Ok(())
}

fn put_table_halfword(
    data: &mut [u8],
    table: usize,
    index: usize,
    word: u16,
) -> Result<(), ObjectError> {
    let begin = index
        .checked_mul(core::mem::size_of::<u16>())
        .and_then(|relative| table.checked_add(relative))
        .ok_or(ObjectError::ArithmeticOverflow(
            "context table halfword offset",
        ))?;
    let end =
        begin
            .checked_add(core::mem::size_of::<u16>())
            .ok_or(ObjectError::ArithmeticOverflow(
                "context table halfword end",
            ))?;
    let destination = data.get_mut(begin..end).ok_or(ObjectError::InvalidModule(
        "context table halfword is absent",
    ))?;
    destination.copy_from_slice(&word.to_le_bytes());
    Ok(())
}

fn table_halfword(data: &[u8], table: usize, index: usize) -> u16 {
    let relative = index
        .checked_mul(core::mem::size_of::<u16>())
        .expect("validated contextual halfword relative offset");
    let begin = table
        .checked_add(relative)
        .expect("validated contextual halfword absolute offset");
    let end = begin
        .checked_add(core::mem::size_of::<u16>())
        .expect("validated contextual halfword end");
    u16::from_le_bytes(
        data[begin..end]
            .try_into()
            .expect("validated contextual table halfword"),
    )
}

fn table_word(data: &[u8], table: usize, index: usize) -> u32 {
    let relative = index
        .checked_mul(core::mem::size_of::<u32>())
        .expect("validated contextual table relative offset");
    let begin = table
        .checked_add(relative)
        .expect("validated contextual table absolute offset");
    let end = begin
        .checked_add(core::mem::size_of::<u32>())
        .expect("validated contextual table word end");
    u32::from_le_bytes(
        data[begin..end]
            .try_into()
            .expect("validated contextual table word"),
    )
}

fn packed_table_cell(
    data: &[u8],
    table: u32,
    states: u32,
    row_width: u16,
    state: u32,
    symbol: u16,
) -> Option<u32> {
    if state >= states || symbol >= row_width {
        return None;
    }
    let index = usize::try_from(state)
        .ok()?
        .checked_mul(usize::from(row_width))?
        .checked_add(usize::from(symbol))?;
    Some(table_word(data, offset(table), index))
}

fn direct_byte_table_cell(
    data: &[u8],
    table: u32,
    states: u32,
    state: u32,
    byte: u8,
) -> Option<u32> {
    if state >= states {
        return None;
    }
    let index = usize::try_from(state)
        .ok()?
        .checked_mul(CONTEXT_DIRECT_BYTE_ROW_CELLS)?
        .checked_add(usize::from(byte))?;
    Some(table_word(data, offset(table), index))
}

fn direct_byte_sentinel_cell(data: &[u8], table: u32, states: u32, state: u32) -> Option<u32> {
    if state >= states {
        return None;
    }
    Some(table_word(
        data,
        offset(table),
        usize::try_from(state).ok()?,
    ))
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "test indexes are bounded by the validated row and 16-bit dispatch dimensions"
)]
mod tests {
    use fre_automata::{Automaton, CompileLimits as AutomatonLimits};
    use fre_lower::{LowerLimits, OperationSemantics};
    use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

    use super::*;
    use crate::{
        CompileMode,
        dfa::DeterminizeLimits,
        program::{CompiledProgram, MatchResult, SearchWindow},
    };

    fn contextual_program(
        pattern: &str,
        line_terminator: u8,
        output: OutputContract,
    ) -> CompiledProgram {
        let mut profile = RustProfile::default();
        profile.options.line_terminator = line_terminator;
        let parsed = fre_syntax::parse(ParseRequest::rust(
            pattern.to_owned(),
            CompatibilityProfile::RustBytes(profile),
        ))
        .unwrap_or_else(|error| panic!("parse {pattern:?}: {error}"));
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("Rust parse returned a non-Rust pattern");
        };
        let raw = fre_lower::lower_raw_general(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("lower {pattern:?}: {error}"))
        .into_plan();
        let automaton = Automaton::from_raw(raw.clone(), AutomatonLimits::default())
            .unwrap_or_else(|error| panic!("validate {pattern:?}: {error}"))
            .with_line_terminator(line_terminator);
        let program = CompiledProgram::build(
            raw,
            automaton,
            output,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
            usize::MAX,
        )
        .unwrap_or_else(|error| panic!("compile {pattern:?}: {error}"));
        assert!(
            program.native_context_program_view().is_some(),
            "contextual optimizer declined {pattern:?}"
        );
        program
    }

    fn expected_execution(result: MatchResult) -> ContextNativeExecutionResult {
        match result {
            MatchResult::Exists(false)
            | MatchResult::SelectedEnd(None)
            | MatchResult::Span(None) => ContextNativeExecutionResult::no_match(),
            MatchResult::Exists(true) => ContextNativeExecutionResult::exists(),
            MatchResult::SelectedEnd(Some(end)) => ContextNativeExecutionResult::selected_end(end),
            MatchResult::Span(Some((start, end))) => ContextNativeExecutionResult::span(start, end),
        }
    }

    fn for_each_context_haystack(mut visit: impl FnMut(&[u8])) {
        const ALPHABET: &[u8] = &[b'a', b'b', b'_', b'-', b'\n', b'\r', b';', 0x80, 0xff];
        for length in 0_u32..=2 {
            let total = ALPHABET.len().pow(length);
            for mut encoded in 0..total {
                let mut haystack = vec![0_u8; usize::try_from(length).expect("small length")];
                for byte in &mut haystack {
                    *byte = ALPHABET[encoded % ALPHABET.len()];
                    encoded /= ALPHABET.len();
                }
                visit(&haystack);
            }
        }
    }

    fn assert_lowering_model_matches_program(
        pattern: &str,
        line_terminator: u8,
        output: OutputContract,
    ) {
        let program = contextual_program(pattern, line_terminator, output);
        let layout = build_context_native_layout(
            program
                .native_context_program_view()
                .expect("contextual native view"),
            ContextNativeLimits::default(),
        )
        .expect("contextual packed layout");
        let mut workspace = program.prepare_workspace().expect("program workspace");
        for_each_context_haystack(|haystack| {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = program
                        .search_with_workspace(
                            haystack,
                            SearchWindow::new(start, end),
                            &mut workspace,
                        )
                        .map(expected_execution)
                        .expect("valid exhaustive window");
                    let actual = layout.execute_lowering_model(haystack, start, end);
                    assert_eq!(
                        actual, expected,
                        "packed lowering mismatch: pattern={pattern:?} line={line_terminator:#04x} output={output:?} haystack={haystack:02x?} window={start}..{end}"
                    );
                }
            }
        });
        assert_eq!(
            layout.execute_lowering_model(b"", 1, 0).status,
            ContextNativeExecutionStatus::Invalid
        );
        assert_eq!(
            layout.execute_lowering_model(b"", 0, 1).status,
            ContextNativeExecutionStatus::Invalid
        );
    }

    fn source_forward_context(
        dfa: NativeContextDfaView<'_>,
        haystack: &[u8],
        position: usize,
    ) -> u16 {
        let before = position
            .checked_sub(1)
            .and_then(|index| haystack.get(index));
        let current = haystack.get(position);
        let properties = before.map_or(0, |&byte| {
            let class = usize::from(dfa.byte_classes[usize::from(byte)]);
            dfa.class_properties[class]
        });
        let class = current.map_or(dfa.initial_dispatch.sentinel_class, |&byte| {
            u32::from(dfa.byte_classes[usize::from(byte)])
        });
        u16::try_from(
            dfa.initial_dispatch
                .pack(
                    class,
                    properties,
                    before.is_some(),
                    position == 0,
                    position == haystack.len(),
                )
                .expect("feasible forward context"),
        )
        .expect("context is 16 bits")
    }

    fn source_reverse_context(
        dfa: NativeContextDfaView<'_>,
        haystack: &[u8],
        position: usize,
    ) -> u16 {
        let before = position
            .checked_sub(1)
            .and_then(|index| haystack.get(index));
        let current = haystack.get(position);
        let class = before.map_or(dfa.initial_dispatch.sentinel_class, |&byte| {
            u32::from(dfa.byte_classes[usize::from(byte)])
        });
        let properties = current.map_or(0, |&byte| {
            let class = usize::from(dfa.byte_classes[usize::from(byte)]);
            dfa.class_properties[class]
        });
        u16::try_from(
            dfa.initial_dispatch
                .pack(
                    class,
                    properties,
                    current.is_some(),
                    position == 0,
                    position == haystack.len(),
                )
                .expect("feasible reverse context"),
        )
        .expect("context is 16 bits")
    }

    fn expected_initial_tables(dfa: NativeContextDfaView<'_>) -> (Vec<u32>, Vec<u32>) {
        let mut forward = vec![CONTEXT_INVALID_CELL; CONTEXT_DISPATCH_ENTRIES];
        for entry in dfa.forward_initial {
            forward[usize::try_from(entry.context).unwrap()] =
                pack_context_cell(Some(entry.state), false, dfa.forward_states.len()).unwrap();
        }
        let mut reverse = vec![CONTEXT_INVALID_CELL; CONTEXT_DISPATCH_ENTRIES];
        let reverse_states = dfa.reverse_row_offsets.len() - 1;
        for entry in dfa.reverse_initial {
            let next = (entry.state != VIEW_NO_STATE).then_some(entry.state);
            reverse[usize::try_from(entry.context).unwrap()] =
                pack_context_cell(next, entry.reaches_start, reverse_states).unwrap();
        }
        (forward, reverse)
    }

    fn expected_forward_flags(dfa: NativeContextDfaView<'_>, state: u32) -> u8 {
        let state = &dfa.forward_states[usize::try_from(state).unwrap()];
        (if state.pending {
            CONTEXT_STATE_PENDING
        } else {
            0
        }) | if state.terminal {
            CONTEXT_STATE_TERMINAL
        } else {
            0
        } | if state.empty { CONTEXT_STATE_EMPTY } else { 0 }
    }

    fn assert_raw_forward_word(
        dfa: NativeContextDfaView<'_>,
        word: u16,
        expected: u32,
        location: &str,
    ) {
        assert_eq!(
            expand_raw_forward_initial(word),
            expected,
            "raw forward semantic mismatch: {location}"
        );
        let Some(initial) = decode_context_cell(expected) else {
            assert_eq!(word, 0, "invalid raw forward cell is not zero: {location}");
            return;
        };
        let state = initial
            .next
            .expect("forward initial cells have live states");
        let payload = u16::try_from(state + 1).unwrap();
        let flags = expected_forward_flags(dfa, state);
        assert_ne!(word & CONTEXT_RAW_FORWARD_VALID, 0);
        assert_eq!(word & CONTEXT_RAW_FORWARD_STATE_MASK, payload);
        assert_eq!(
            word & CONTEXT_RAW_FORWARD_EMPTY != 0,
            flags & CONTEXT_STATE_EMPTY != 0
        );
    }

    fn assert_raw_forward_physical_tables(
        layout: &ContextNativeLayout,
        dfa: NativeContextDfaView<'_>,
        expected: &[u32],
    ) {
        let raw = layout
            .raw_pair_initial
            .expect("test graph must select raw forward dispatch");
        let pairs = offset(layout.forward_initial_offset);
        for pair in 0..CONTEXT_DISPATCH_ENTRIES {
            let previous = u8::try_from(pair & 0xff).unwrap();
            let current = u8::try_from(pair >> 8).unwrap();
            let context = dfa
                .initial_dispatch
                .pack(
                    context_class(dfa, current),
                    context_properties(dfa, previous),
                    true,
                    false,
                    false,
                )
                .unwrap();
            assert_raw_forward_word(
                dfa,
                table_halfword(&layout.data, pairs, pair),
                expected[usize::try_from(context).unwrap()],
                "interior pair",
            );
        }

        let sentinel = dfa.initial_dispatch.sentinel_class;
        for index in 0_u16..=256 {
            let current = (index < 256).then(|| u8::try_from(index).unwrap());
            let context = dfa
                .initial_dispatch
                .pack(
                    current.map_or(sentinel, |byte| context_class(dfa, byte)),
                    0,
                    false,
                    true,
                    current.is_none(),
                )
                .unwrap();
            assert_raw_forward_word(
                dfa,
                table_halfword(
                    &layout.data,
                    offset(raw.forward_start_offset),
                    usize::from(index),
                ),
                expected[usize::try_from(context).unwrap()],
                "absolute start",
            );
        }
        for index in 0_u16..256 {
            let previous = u8::try_from(index).unwrap();
            let context = dfa
                .initial_dispatch
                .pack(
                    sentinel,
                    context_properties(dfa, previous),
                    true,
                    false,
                    true,
                )
                .unwrap();
            assert_raw_forward_word(
                dfa,
                table_halfword(
                    &layout.data,
                    offset(raw.forward_end_offset),
                    usize::from(index),
                ),
                expected[usize::try_from(context).unwrap()],
                "absolute end",
            );
        }
    }

    fn assert_raw_reverse_physical_tables(
        layout: &ContextNativeLayout,
        dfa: NativeContextDfaView<'_>,
        expected: &[u32],
    ) {
        let raw = layout
            .raw_pair_reverse_initial
            .expect("test graph must select raw reverse dispatch");
        let pairs = offset(
            layout
                .reverse_initial_offset
                .expect("retained reverse pair table"),
        );
        for pair in 0..CONTEXT_DISPATCH_ENTRIES {
            let previous = u8::try_from(pair & 0xff).unwrap();
            let current = u8::try_from(pair >> 8).unwrap();
            let context = dfa
                .initial_dispatch
                .pack(
                    context_class(dfa, previous),
                    context_properties(dfa, current),
                    true,
                    false,
                    false,
                )
                .unwrap();
            assert_eq!(
                expand_raw_reverse_initial(table_halfword(&layout.data, pairs, pair)),
                expected[usize::try_from(context).unwrap()],
                "raw reverse pair mismatch: previous={previous:#04x} current={current:#04x}"
            );
        }

        let sentinel = dfa.initial_dispatch.sentinel_class;
        for index in 0_u16..=256 {
            let current = (index < 256).then(|| u8::try_from(index).unwrap());
            let context = dfa
                .initial_dispatch
                .pack(
                    sentinel,
                    current.map_or(0, |byte| context_properties(dfa, byte)),
                    current.is_some(),
                    true,
                    current.is_none(),
                )
                .unwrap();
            assert_eq!(
                expand_raw_reverse_initial(table_halfword(
                    &layout.data,
                    offset(raw.reverse_start_offset),
                    usize::from(index),
                )),
                expected[usize::try_from(context).unwrap()],
                "raw reverse absolute-start mismatch: index={index}"
            );
        }
        for index in 0_u16..256 {
            let previous = u8::try_from(index).unwrap();
            let context = dfa
                .initial_dispatch
                .pack(context_class(dfa, previous), 0, false, false, true)
                .unwrap();
            assert_eq!(
                expand_raw_reverse_initial(table_halfword(
                    &layout.data,
                    offset(raw.reverse_end_offset),
                    usize::from(index),
                )),
                expected[usize::try_from(context).unwrap()],
                "raw reverse absolute-end mismatch: previous={previous:#04x}"
            );
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the table-by-table proof intentionally checks every emitted representation in one pass"
    )]
    fn assert_layout_matches_view(pattern: &str) {
        let program = contextual_program(pattern, b';', OutputContract::Span);
        let view = program.native_context_program_view().unwrap();
        assert!(view.exact_match_width.is_none(), "test must retain reverse");
        let first = build_context_native_layout(view, ContextNativeLimits::default()).unwrap();
        let second = build_context_native_layout(view, ContextNativeLimits::default()).unwrap();
        assert_eq!(first, second, "identity bytes changed for {pattern:?}");
        assert_eq!(first.bytes(), second.bytes());
        assert!(first.reverse_cells_offset.is_some());
        assert!(first.reverse_initial_offset.is_some());
        assert!(first.forward_direct_bytes());
        assert!(first.reverse_direct_bytes());
        assert_eq!(
            offset(first.forward_byte_sentinel_offset.unwrap()),
            offset(first.forward_cells_offset)
                + usize::try_from(first.forward_states).unwrap() * CONTEXT_DIRECT_BYTE_ROW_BYTES
        );
        assert_eq!(
            offset(first.reverse_byte_sentinel_offset.unwrap()),
            offset(first.reverse_cells_offset.unwrap())
                + usize::try_from(first.reverse_states).unwrap() * CONTEXT_DIRECT_BYTE_ROW_BYTES
        );

        for byte in u8::MIN..=u8::MAX {
            assert_eq!(first.class_for_byte(byte), dfa_class(view.dfa, byte));
            let class = usize::from(dfa_class(view.dfa, byte));
            assert_eq!(
                first.properties_for_byte(byte),
                view.dfa.class_properties[class]
            );
        }
        let property_padding =
            offset(first.class_properties_offset) + usize::from(first.class_count);
        assert!(
            first.data[property_padding
                ..property_padding + CLASS_TABLE_BYTES - usize::from(first.class_count)]
                .iter()
                .all(|&byte| byte == 0)
        );

        let width = usize::from(first.row_width);
        for (state, source) in view.dfa.forward_states.iter().enumerate() {
            let expected_flags = if source.pending {
                CONTEXT_STATE_PENDING
            } else {
                0
            } | if source.empty { CONTEXT_STATE_EMPTY } else { 0 }
                | if source.terminal {
                    CONTEXT_STATE_TERMINAL
                } else {
                    0
                };
            assert_eq!(
                first.forward_state_flags(u32::try_from(state).unwrap()),
                Some(expected_flags)
            );
            for symbol in 0..width {
                let index = state * width + symbol;
                let source = view.dfa.forward_cells[index];
                let successor = view.dfa.forward_states[usize::try_from(source.next).unwrap()];
                assert_eq!(
                    first.forward_cell(
                        u32::try_from(state).unwrap(),
                        u16::try_from(symbol).unwrap()
                    ),
                    Some(
                        pack_forward_transition_cell(
                            source.next,
                            source.accepted,
                            context_forward_flags(successor).unwrap(),
                            view.dfa.forward_states.len(),
                        )
                        .unwrap()
                    )
                );
            }
            for byte in u8::MIN..=u8::MAX {
                let class = usize::from(view.dfa.byte_classes[usize::from(byte)]);
                let source = view.dfa.forward_cells[state * width + class];
                let successor = view.dfa.forward_states[usize::try_from(source.next).unwrap()];
                assert_eq!(
                    direct_byte_table_cell(
                        &first.data,
                        first.forward_cells_offset,
                        first.forward_states,
                        u32::try_from(state).unwrap(),
                        byte,
                    ),
                    Some(
                        pack_forward_transition_cell(
                            source.next,
                            source.accepted,
                            context_forward_flags(successor).unwrap(),
                            view.dfa.forward_states.len(),
                        )
                        .unwrap()
                    ),
                    "physical forward DirectByte mismatch: state={state} byte={byte:#04x}"
                );
            }
            let sentinel = usize::try_from(view.dfa.initial_dispatch.sentinel_class).unwrap();
            let source = view.dfa.forward_cells[state * width + sentinel];
            let successor = view.dfa.forward_states[usize::try_from(source.next).unwrap()];
            assert_eq!(
                direct_byte_sentinel_cell(
                    &first.data,
                    first.forward_byte_sentinel_offset.unwrap(),
                    first.forward_states,
                    u32::try_from(state).unwrap(),
                ),
                Some(
                    pack_forward_transition_cell(
                        source.next,
                        source.accepted,
                        context_forward_flags(successor).unwrap(),
                        view.dfa.forward_states.len(),
                    )
                    .unwrap()
                ),
                "physical forward DirectByte sentinel mismatch: state={state}"
            );
        }
        let reverse_states = view.dfa.reverse_row_offsets.len() - 1;
        for state in 0..reverse_states {
            for symbol in 0..width {
                let source = view.dfa.reverse_cells[state * width + symbol];
                let next = (source.next != VIEW_NO_STATE).then_some(source.next);
                assert_eq!(
                    first.reverse_cell(
                        u32::try_from(state).unwrap(),
                        u16::try_from(symbol).unwrap()
                    ),
                    Some(pack_context_cell(next, source.reaches_start, reverse_states).unwrap())
                );
            }
            for byte in u8::MIN..=u8::MAX {
                let class = usize::from(view.dfa.byte_classes[usize::from(byte)]);
                let source = view.dfa.reverse_cells[state * width + class];
                let next = (source.next != VIEW_NO_STATE).then_some(source.next);
                assert_eq!(
                    direct_byte_table_cell(
                        &first.data,
                        first.reverse_cells_offset.unwrap(),
                        first.reverse_states,
                        u32::try_from(state).unwrap(),
                        byte,
                    ),
                    Some(pack_context_cell(next, source.reaches_start, reverse_states).unwrap()),
                    "physical reverse DirectByte mismatch: state={state} byte={byte:#04x}"
                );
            }
            let sentinel = usize::try_from(view.dfa.initial_dispatch.sentinel_class).unwrap();
            let source = view.dfa.reverse_cells[state * width + sentinel];
            let next = (source.next != VIEW_NO_STATE).then_some(source.next);
            assert_eq!(
                direct_byte_sentinel_cell(
                    &first.data,
                    first.reverse_byte_sentinel_offset.unwrap(),
                    first.reverse_states,
                    u32::try_from(state).unwrap(),
                ),
                Some(pack_context_cell(next, source.reaches_start, reverse_states).unwrap()),
                "physical reverse DirectByte sentinel mismatch: state={state}"
            );
        }

        let (expected_forward, expected_reverse) = expected_initial_tables(view.dfa);
        for context in u16::MIN..=u16::MAX {
            assert_eq!(
                first.forward_initial_cell(context),
                expected_forward[usize::from(context)]
            );
            assert_eq!(
                first.reverse_initial_cell(context),
                Some(expected_reverse[usize::from(context)])
            );
        }
        assert_raw_forward_physical_tables(&first, view.dfa, &expected_forward);
        assert_raw_reverse_physical_tables(&first, view.dfa, &expected_reverse);

        // Every realizable boundary is generated from all byte pairs. This
        // proves that full-haystack classification reaches every canonical
        // initial fact, including empty/start/interior/end contexts.
        let mut seen_forward = vec![false; CONTEXT_DISPATCH_ENTRIES];
        let mut seen_reverse = vec![false; CONTEXT_DISPATCH_ENTRIES];
        assert_boundary(
            &first,
            view.dfa,
            b"",
            0,
            &mut seen_forward,
            &mut seen_reverse,
        );
        for left in u8::MIN..=u8::MAX {
            for right in u8::MIN..=u8::MAX {
                let haystack = [left, right];
                for position in 0..=haystack.len() {
                    assert_boundary(
                        &first,
                        view.dfa,
                        &haystack,
                        position,
                        &mut seen_forward,
                        &mut seen_reverse,
                    );
                }
            }
        }
        for entry in view.dfa.forward_initial {
            assert!(seen_forward[usize::try_from(entry.context).unwrap()]);
        }
        for entry in view.dfa.reverse_initial {
            assert!(seen_reverse[usize::try_from(entry.context).unwrap()]);
        }
    }

    fn dfa_class(dfa: NativeContextDfaView<'_>, byte: u8) -> u8 {
        dfa.byte_classes[usize::from(byte)]
    }

    fn assert_boundary(
        layout: &ContextNativeLayout,
        dfa: NativeContextDfaView<'_>,
        haystack: &[u8],
        position: usize,
        seen_forward: &mut [bool],
        seen_reverse: &mut [bool],
    ) {
        let forward = layout.forward_context_at(haystack, position).unwrap();
        let reverse = layout.reverse_context_at(haystack, position).unwrap();
        assert_eq!(forward, source_forward_context(dfa, haystack, position));
        assert_eq!(reverse, source_reverse_context(dfa, haystack, position));
        assert_ne!(layout.forward_initial_cell(forward), CONTEXT_INVALID_CELL);
        assert_ne!(
            layout.reverse_initial_cell(reverse),
            Some(CONTEXT_INVALID_CELL)
        );
        seen_forward[usize::from(forward)] = true;
        seen_reverse[usize::from(reverse)] = true;
    }

    #[test]
    fn generated_ascii_assertion_layouts_match_every_view_cell_and_context() {
        let assertions = [
            r"\A",
            r"\z",
            r"(?m:^)",
            r"(?m:$)",
            r"(?mR:^)",
            r"(?mR:$)",
            r"(?-u:\b)",
            r"(?-u:\B)",
            r"(?-u:\b{start})",
            r"(?-u:\b{end})",
            r"(?-u:\b{start-half})",
            r"(?-u:\b{end-half})",
        ];
        for assertion in assertions {
            let pattern = format!("(?:a{assertion}|{assertion}a|ab)+?");
            assert_layout_matches_view(&pattern);
        }
    }

    #[test]
    fn lowering_model_matches_all_contracts_windows_and_ascii_assertions() {
        let assertions = [
            r"\A",
            r"\z",
            r"(?m:^)",
            r"(?m:$)",
            r"(?mR:^)",
            r"(?mR:$)",
            r"(?-u:\b)",
            r"(?-u:\B)",
            r"(?-u:\b{start})",
            r"(?-u:\b{end})",
            r"(?-u:\b{start-half})",
            r"(?-u:\b{end-half})",
        ];
        for line_terminator in [b'\n', b';'] {
            for assertion in assertions {
                let pattern = format!("(?:a{assertion}|{assertion}a|ab)+?");
                for output in [
                    OutputContract::Exists,
                    OutputContract::SelectedEnd,
                    OutputContract::Span,
                ] {
                    assert_lowering_model_matches_program(&pattern, line_terminator, output);
                }
            }
        }
    }

    #[test]
    fn forced_direct_byte_and_narrow_models_are_equivalent() {
        let patterns = [r"(?:(?-u:\b)a|ab)+?", r"(?:a(?m:$)|(?m:^)b|ab)+?"];
        for pattern in patterns {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let program = contextual_program(pattern, b'\n', output);
                let view = program.native_context_program_view().unwrap();
                let direct = build_context_native_layout_with_reverse_mode(
                    view,
                    ContextNativeLimits::default(),
                    false,
                    true,
                    false,
                )
                .unwrap();
                let narrow = build_context_native_layout_with_reverse_mode(
                    view,
                    ContextNativeLimits::default(),
                    false,
                    false,
                    false,
                )
                .unwrap();
                assert!(direct.forward_direct_bytes());
                assert!(!narrow.forward_direct_bytes());
                assert!(!narrow.reverse_direct_bytes());
                assert_eq!(
                    direct.reverse_direct_bytes(),
                    output == OutputContract::Span && direct.exact_match_width.is_none()
                );
                for_each_context_haystack(|haystack| {
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            assert_eq!(
                                direct.execute_lowering_model(haystack, start, end),
                                narrow.execute_lowering_model(haystack, start, end),
                                "DirectByte/narrow mismatch: pattern={pattern:?} output={output:?} haystack={haystack:02x?} window={start}..{end}"
                            );
                        }
                    }
                });
            }
        }
    }

    #[test]
    fn anchored_forward_layout_is_optional_exact_and_physically_equivalent() {
        let program = contextual_program(r"(?-u:\b)(?:ab|a)+(?-u:\b)", b'\n', OutputContract::Span);
        let view = program.native_context_program_view().unwrap();
        let native = view
            .dfa
            .anchored_forward
            .expect("test graph has an anchored sidecar");
        let mandatory = build_context_native_layout(view, ContextNativeLimits::default()).unwrap();
        assert!(mandatory.anchored_forward.is_none());
        let accelerated = build_context_native_layout_with_accelerators(
            view,
            ContextNativeLimits::default(),
            false,
            true,
        )
        .unwrap();
        let layout = accelerated
            .anchored_forward
            .expect("anchored layout was retained");
        assert!(layout.byte_sentinel_offset.is_some());
        assert_eq!(usize::try_from(layout.states).unwrap(), native.states.len());
        assert_eq!(layout.max_resolution_steps, native.max_resolution_steps);
        let mut compact = mandatory.clone();
        compact.anchored_forward = append_anchored_forward_layout_mode(
            &mut compact.data,
            view.dfa,
            MAX_CONTEXT_NATIVE_DATA_BYTES,
            false,
        )
        .unwrap();
        assert!(
            compact
                .anchored_forward
                .expect("compact anchored layout")
                .byte_sentinel_offset
                .is_none()
        );
        for physical in [&accelerated, &compact] {
            for (main, &expected) in native.main_initial_to_anchored.iter().enumerate() {
                assert_eq!(
                    physical.anchored_initial_state(u32::try_from(main).unwrap()),
                    (expected != u32::MAX).then_some(expected)
                );
            }
            let row_width = usize::from(physical.row_width);
            for (state, expected_flags) in native.states.iter().copied().enumerate() {
                assert_eq!(
                    physical.anchored_state_flags(u32::try_from(state).unwrap()),
                    Some(context_forward_flags(expected_flags).unwrap())
                );
                let row = state * row_width;
                for byte in u8::MIN..=u8::MAX {
                    let class = usize::from(view.dfa.byte_classes[usize::from(byte)]);
                    let expected = native.cells[row + class];
                    assert_eq!(
                        decode_forward_transition_cell(
                            physical
                                .anchored_cell_for_byte(u32::try_from(state).unwrap(), Some(byte),)
                                .unwrap()
                        ),
                        Some(DecodedForwardCell {
                            next: expected.next,
                            event: expected.accepted,
                            flags: context_forward_flags(
                                native.states[usize::try_from(expected.next).unwrap()]
                            )
                            .unwrap(),
                        })
                    );
                }
                let expected = native.cells[row + usize::from(physical.class_count)];
                assert_eq!(
                    decode_forward_transition_cell(
                        physical
                            .anchored_cell_for_byte(u32::try_from(state).unwrap(), None)
                            .unwrap()
                    ),
                    Some(DecodedForwardCell {
                        next: expected.next,
                        event: expected.accepted,
                        flags: context_forward_flags(
                            native.states[usize::try_from(expected.next).unwrap()]
                        )
                        .unwrap(),
                    })
                );
            }
        }

        let exact = build_context_native_layout_with_accelerators(
            view,
            ContextNativeLimits {
                max_data_bytes: accelerated.data.len(),
            },
            false,
            true,
        )
        .unwrap();
        assert_eq!(exact, accelerated);
        let compact_fallback = build_context_native_layout_with_accelerators(
            view,
            ContextNativeLimits {
                max_data_bytes: accelerated.data.len() - 1,
            },
            false,
            true,
        )
        .unwrap();
        assert_eq!(compact_fallback, compact);
        let compact_exact = build_context_native_layout_with_accelerators(
            view,
            ContextNativeLimits {
                max_data_bytes: compact.data.len(),
            },
            false,
            true,
        )
        .unwrap();
        assert_eq!(compact_exact, compact);
        let omitted = build_context_native_layout_with_accelerators(
            view,
            ContextNativeLimits {
                max_data_bytes: compact.data.len() - 1,
            },
            false,
            true,
        )
        .unwrap();
        assert_eq!(omitted, mandatory);
    }

    #[test]
    fn anchored_forward_layout_is_retained_for_variable_selected_end() {
        let variable = r"(?-u:\b)(?:ab|a)+(?-u:\b)";
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let program = contextual_program(variable, b'\n', output);
            let view = program.native_context_program_view().unwrap();
            let layout = build_context_native_layout_with_accelerators(
                view,
                ContextNativeLimits::default(),
                false,
                true,
            )
            .unwrap();
            assert_eq!(
                layout.anchored_forward.is_some(),
                matches!(output, OutputContract::SelectedEnd | OutputContract::Span),
                "output={output:?}"
            );
        }

        let fixed = contextual_program(r"(?-u:\b)a", b'\n', OutputContract::SelectedEnd);
        let layout = build_context_native_layout_with_accelerators(
            fixed.native_context_program_view().unwrap(),
            ContextNativeLimits::default(),
            false,
            true,
        )
        .unwrap();
        assert_eq!(layout.exact_match_width, Some(1));
        assert!(layout.anchored_forward.is_none());
    }

    #[test]
    fn selected_end_reverse_layout_is_retained_only_for_a_selected_suffix_verifier() {
        let pattern = r"(?-u:\b(?:woua|qiaia)\b)";
        let program = contextual_program(pattern, b'\n', OutputContract::SelectedEnd);
        let view = program.native_context_program_view().unwrap();
        assert!(view.exact_match_width.is_none());

        let compact = build_context_native_layout_with_reverse(
            view,
            ContextNativeLimits::default(),
            false,
        )
        .unwrap();
        assert_eq!(compact.reverse_states, 0);
        assert!(compact.reverse_cells_offset.is_none());
        assert!(compact.reverse_initial_offset.is_none());

        let suffix = build_context_native_layout_with_reverse(
            view,
            ContextNativeLimits::default(),
            true,
        )
        .unwrap();
        assert!(suffix.reverse_states > 0);
        assert!(suffix.reverse_cells_offset.is_some());
        assert!(suffix.reverse_initial_offset.is_some());

        let fixed = contextual_program(r"(?-u:\b)fpez", b'\n', OutputContract::SelectedEnd);
        let fixed_layout = build_context_native_layout_with_reverse(
            fixed.native_context_program_view().unwrap(),
            ContextNativeLimits::default(),
            true,
        )
        .unwrap();
        assert_eq!(fixed_layout.exact_match_width, Some(4));
        assert_eq!(fixed_layout.reverse_states, 0);
        assert!(fixed_layout.reverse_cells_offset.is_none());
    }

    #[test]
    fn lowering_model_covers_fixed_width_nullable_and_reverse_span_routes() {
        let patterns = [
            r"(?-u:\b)a",
            r"(?m:^)a",
            r"a(?m:$)",
            r"(?mR:^)a",
            r"(?mR:$)",
            r"(?-u:\b)",
            r"(?-u:\B)",
            r"(?:(?-u:\b)a|ab)+?",
        ];
        for pattern in patterns {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                assert_lowering_model_matches_program(pattern, b'\n', output);
            }
        }
    }

    #[test]
    fn lowering_model_reads_assertion_context_outside_window() {
        let cases: [(&str, &[u8], usize, usize, bool); 5] = [
            (r"(?m:^)a", b"\na", 1, 2, true),
            (r"a(?m:$)", b"a\n", 0, 1, true),
            (r"a(?-u:\b)", b"a_", 0, 1, false),
            (r"(?-u:\b)a", b"-a", 1, 2, true),
            (r"\Aa", b"-a", 1, 2, false),
        ];
        for (pattern, haystack, start, end, matched) in cases {
            let program = contextual_program(pattern, b'\n', OutputContract::Span);
            let layout = build_context_native_layout(
                program
                    .native_context_program_view()
                    .expect("contextual native view"),
                ContextNativeLimits::default(),
            )
            .expect("contextual packed layout");
            let actual = layout.execute_lowering_model(haystack, start, end);
            assert_eq!(
                actual.status == ContextNativeExecutionStatus::Matched,
                matched,
                "outside-window assertion context: pattern={pattern:?}"
            );
            assert_eq!(
                actual,
                expected_execution(
                    program
                        .search(haystack, SearchWindow::new(start, end))
                        .expect("valid explicit window")
                )
            );
        }
    }

    #[test]
    fn reverse_tables_are_retained_only_when_span_recovery_needs_them() {
        let variable = r"(?:(?-u:\b)a|ab)+?";
        let span_program = contextual_program(variable, b'\n', OutputContract::Span);
        let span = build_context_native_layout(
            span_program.native_context_program_view().unwrap(),
            ContextNativeLimits::default(),
        )
        .unwrap();
        assert!(span.exact_match_width.is_none());
        assert!(span.reverse_cells_offset.is_some());
        assert!(span.reverse_initial_offset.is_some());
        assert!(span.raw_pair_reverse_initial.is_some());
        assert_ne!(span.reverse_states, 0);

        for output in [OutputContract::Exists, OutputContract::SelectedEnd] {
            let program = contextual_program(variable, b'\n', output);
            let layout = build_context_native_layout(
                program.native_context_program_view().unwrap(),
                ContextNativeLimits::default(),
            )
            .unwrap();
            assert!(layout.reverse_cells_offset.is_none());
            assert!(layout.reverse_initial_offset.is_none());
            assert!(layout.raw_pair_reverse_initial.is_none());
            assert_eq!(layout.reverse_states, 0);
        }

        let fixed_program = contextual_program(r"(?-u:\b)a", b'\n', OutputContract::Span);
        let fixed = build_context_native_layout(
            fixed_program.native_context_program_view().unwrap(),
            ContextNativeLimits::default(),
        )
        .unwrap();
        assert_eq!(fixed.exact_match_width, Some(1));
        assert!(fixed.reverse_cells_offset.is_none());
        assert!(fixed.reverse_initial_offset.is_none());
        assert!(fixed.raw_pair_reverse_initial.is_none());
    }

    #[test]
    fn every_compiler_populated_transition_is_well_formed_and_forward_successors_are_live() {
        let program = contextual_program(r"(?-u:\b)(?:ab|a)+(?-u:\b)", b'\n', OutputContract::Span);
        let view = program.native_context_program_view().unwrap();
        for direct_bytes in [false, true] {
            let layout = build_context_native_layout_with_reverse_mode(
                view,
                ContextNativeLimits::default(),
                false,
                direct_bytes,
                true,
            )
            .unwrap();
            let anchored = layout
                .anchored_forward
                .expect("test graph must retain its anchored sidecar");

            let assert_live_forward = |word: u32, states: u32, location: &str| {
                assert_ne!(
                    word & CONTEXT_FORWARD_CELL_STATE_MASK,
                    0,
                    "dead {location} successor"
                );
                let decoded = decode_forward_transition_cell(word)
                    .expect("populated forward transition has a live successor");
                let successor = decoded.next;
                assert!(successor < states, "out-of-range {location} successor");
                decoded
            };

            for state in 0..layout.forward_states {
                for byte in u8::MIN..=u8::MAX {
                    let decoded = assert_live_forward(
                        layout
                            .forward_cell_for_byte(state, Some(byte))
                            .expect("main byte transition"),
                        layout.forward_states,
                        "main byte",
                    );
                    assert_eq!(
                        Some(decoded.flags),
                        layout.forward_state_flags(decoded.next),
                        "main byte successor flags"
                    );
                }
                let decoded = assert_live_forward(
                    layout
                        .forward_cell_for_byte(state, None)
                        .expect("main sentinel transition"),
                    layout.forward_states,
                    "main sentinel",
                );
                assert_eq!(
                    Some(decoded.flags),
                    layout.forward_state_flags(decoded.next),
                    "main sentinel successor flags"
                );
            }

            for state in 0..anchored.states {
                for byte in u8::MIN..=u8::MAX {
                    let decoded = assert_live_forward(
                        layout
                            .anchored_cell_for_byte(state, Some(byte))
                            .expect("anchored byte transition"),
                        anchored.states,
                        "anchored byte",
                    );
                    assert_eq!(
                        Some(decoded.flags),
                        layout.anchored_state_flags(decoded.next),
                        "anchored byte successor flags"
                    );
                }
                let decoded = assert_live_forward(
                    layout
                        .anchored_cell_for_byte(state, None)
                        .expect("anchored sentinel transition"),
                    anchored.states,
                    "anchored sentinel",
                );
                assert_eq!(
                    Some(decoded.flags),
                    layout.anchored_state_flags(decoded.next),
                    "anchored sentinel successor flags"
                );
            }

            let mut saw_reverse_dead = false;
            for state in 0..layout.reverse_states {
                for byte in u8::MIN..=u8::MAX {
                    let word = layout
                        .reverse_cell_for_byte(state, Some(byte))
                        .expect("reverse byte transition");
                    assert_ne!(word & CONTEXT_CELL_VALID, 0);
                    let decoded = decode_context_cell(word).expect("valid reverse byte cell");
                    saw_reverse_dead |= decoded.next.is_none();
                    assert!(decoded.next.is_none_or(|next| next < layout.reverse_states));
                }
                let word = layout
                    .reverse_cell_for_byte(state, None)
                    .expect("reverse sentinel transition");
                assert_ne!(word & CONTEXT_CELL_VALID, 0);
                let decoded = decode_context_cell(word).expect("valid reverse sentinel cell");
                saw_reverse_dead |= decoded.next.is_none();
                assert!(decoded.next.is_none_or(|next| next < layout.reverse_states));
            }
            assert!(
                saw_reverse_dead,
                "reverse rows must exercise the valid zero-payload dead frontier"
            );
        }
    }

    #[test]
    fn packed_cell_sentinels_and_state_boundary_do_not_collide() {
        assert_eq!(CONTEXT_INVALID_CELL, 0);
        assert!(raw_forward_initial_state_payload_fits(usize::from(
            CONTEXT_RAW_FORWARD_STATE_MASK
        )));
        assert!(!raw_forward_initial_state_payload_fits(
            usize::from(CONTEXT_RAW_FORWARD_STATE_MASK) + 1
        ));
        assert!(raw_reverse_initial_state_payload_fits(usize::from(
            CONTEXT_RAW_REVERSE_STATE_MASK
        )));
        assert!(!raw_reverse_initial_state_payload_fits(
            usize::from(CONTEXT_RAW_REVERSE_STATE_MASK) + 1
        ));
        let dead = pack_context_cell(None, false, 0).unwrap();
        let reached = pack_context_cell(None, true, 0).unwrap();
        assert_eq!(dead, CONTEXT_CELL_VALID);
        assert_eq!(reached, CONTEXT_CELL_VALID | CONTEXT_CELL_EVENT);
        assert_ne!(dead, CONTEXT_INVALID_CELL);
        assert_eq!(dead & CONTEXT_CELL_STATE_MASK, 0);
        assert_eq!(reached & CONTEXT_CELL_STATE_MASK, 0);
        assert_eq!(
            expand_raw_reverse_initial(CONTEXT_RAW_REVERSE_VALID | CONTEXT_RAW_REVERSE_EVENT),
            CONTEXT_CELL_VALID | CONTEXT_CELL_EVENT,
            "a raw reaches-start event with no live reverse state must survive decoding"
        );

        let last = u32::try_from(MAX_PACKED_CONTEXT_STATES - 1).unwrap();
        let packed = pack_context_cell(Some(last), true, MAX_PACKED_CONTEXT_STATES).unwrap();
        assert_eq!(packed & CONTEXT_CELL_STATE_MASK, CONTEXT_CELL_STATE_MASK);
        assert_eq!(packed & CONTEXT_CELL_VALID, CONTEXT_CELL_VALID);
        assert_eq!(packed & CONTEXT_CELL_EVENT, CONTEXT_CELL_EVENT);
        assert!(matches!(
            pack_context_cell(Some(1), false, 1),
            Err(ObjectError::InvalidModule(_))
        ));
        assert!(matches!(
            check_state_count(MAX_PACKED_CONTEXT_STATES + 1),
            Err(ObjectError::Resource {
                resource: CompileResource::DfaStates,
                limit: MAX_PACKED_CONTEXT_STATES,
                required,
            }) if required == MAX_PACKED_CONTEXT_STATES + 1
        ));

        let last_forward = u32::try_from(MAX_PACKED_CONTEXT_FORWARD_STATES - 1).unwrap();
        for event in [false, true] {
            for flags in [
                0,
                CONTEXT_STATE_EMPTY,
                CONTEXT_STATE_PENDING,
                CONTEXT_STATE_PENDING | CONTEXT_STATE_EMPTY | CONTEXT_STATE_TERMINAL,
            ] {
                let packed = pack_forward_transition_cell(
                    last_forward,
                    event,
                    flags,
                    MAX_PACKED_CONTEXT_FORWARD_STATES,
                )
                .unwrap();
                assert_eq!(packed & CONTEXT_FORWARD_CELL_STATE_MASK, last_forward + 1);
                assert_eq!(packed & CONTEXT_CELL_EVENT != 0, event);
                assert_eq!(
                    decode_forward_transition_cell(packed),
                    Some(DecodedForwardCell {
                        next: last_forward,
                        event,
                        flags,
                    })
                );
            }
        }
        assert!(matches!(
            pack_forward_transition_cell(0, false, CONTEXT_STATE_TERMINAL, 1,),
            Err(ObjectError::InvalidModule(_))
        ));
        assert!(matches!(
            pack_forward_transition_cell(0, false, 0, MAX_PACKED_CONTEXT_FORWARD_STATES + 1,),
            Err(ObjectError::InvalidModule(_))
        ));
    }

    #[test]
    fn empty_frontier_flag_encoding_rejects_reserved_and_incoherent_bits() {
        let program = contextual_program("(?-u:\\bcat\\b)", b'\n', OutputContract::Span);
        let view = program.native_context_program_view().unwrap();
        let mut layout = build_context_native_layout(view, ContextNativeLimits::default()).unwrap();
        let index = offset(layout.forward_state_flags_offset);
        for flags in [
            0,
            CONTEXT_STATE_EMPTY,
            CONTEXT_STATE_PENDING,
            CONTEXT_STATE_PENDING | CONTEXT_STATE_EMPTY | CONTEXT_STATE_TERMINAL,
        ] {
            layout.data[index] = flags;
            assert_eq!(layout.checked_forward_state_flags(0), Some(flags));
        }
        for flags in [
            CONTEXT_STATE_TERMINAL,
            CONTEXT_STATE_PENDING | CONTEXT_STATE_EMPTY,
            1 << 3,
        ] {
            layout.data[index] = flags;
            assert_eq!(layout.checked_forward_state_flags(0), None);
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "all layout byte-accounting boundaries stay in one audit"
    )]
    fn layout_accounting_limits_and_arithmetic_are_exact() {
        let with_reverse =
            plan_context_layout(3, 4, 5, true, false, false, false, false, usize::MAX).unwrap();
        assert_eq!(with_reverse.byte_classes, 0);
        assert_eq!(with_reverse.class_properties, 256);
        assert_eq!(with_reverse.forward_state_flags, 512);
        assert_eq!(with_reverse.forward_cells, 516);
        assert_eq!(with_reverse.reverse_cells, Some(576));
        assert_eq!(with_reverse.forward_initial, 656);
        assert_eq!(with_reverse.reverse_initial, Some(262_800));
        assert_eq!(with_reverse.total, 524_944);
        assert_eq!(
            plan_context_layout(
                3,
                4,
                5,
                true,
                false,
                false,
                false,
                false,
                with_reverse.total,
            )
            .unwrap(),
            with_reverse
        );
        assert!(matches!(
            plan_context_layout(
                3,
                4,
                5,
                true,
                false,
                false,
                false,
                false,
                with_reverse.total - 1,
            ),
            Err(ObjectError::Resource {
                resource: CompileResource::ProgramBytes,
                limit,
                required,
            }) if limit == with_reverse.total - 1 && required == with_reverse.total
        ));

        let forward_only =
            plan_context_layout(3, 4, 5, false, false, false, false, false, usize::MAX).unwrap();
        assert_eq!(forward_only.reverse_cells, None);
        assert_eq!(forward_only.forward_initial, 576);
        assert_eq!(forward_only.reverse_initial, None);
        assert_eq!(forward_only.total, 262_720);

        let raw_forward_with_reverse =
            plan_context_layout(3, 4, 5, true, true, false, false, false, usize::MAX).unwrap();
        assert_eq!(raw_forward_with_reverse.forward_initial, 656);
        assert_eq!(raw_forward_with_reverse.reverse_initial, Some(131_728));
        assert_eq!(
            raw_forward_with_reverse.raw_pair_initial,
            Some(ContextRawPairInitialPlan {
                forward_start: 393_872,
                forward_end: 394_386,
            })
        );
        assert_eq!(raw_forward_with_reverse.total, 394_898);
        assert!(raw_forward_with_reverse.total < with_reverse.total);

        let raw_with_reverse =
            plan_context_layout(3, 4, 5, true, true, true, false, false, usize::MAX).unwrap();
        assert_eq!(raw_with_reverse.forward_initial, 656);
        assert_eq!(raw_with_reverse.reverse_initial, Some(131_728));
        assert_eq!(
            raw_with_reverse.raw_pair_initial,
            Some(ContextRawPairInitialPlan {
                forward_start: 262_800,
                forward_end: 263_314,
            })
        );
        assert_eq!(
            raw_with_reverse.raw_pair_reverse_initial,
            Some(ContextRawPairReverseInitialPlan {
                reverse_start: 263_826,
                reverse_end: 264_340,
            })
        );
        assert_eq!(raw_with_reverse.total, 264_852);
        assert!(raw_with_reverse.total < with_reverse.total);

        let raw_forward_only =
            plan_context_layout(3, 4, 5, false, true, false, false, false, usize::MAX).unwrap();
        assert_eq!(raw_forward_only.forward_initial, 576);
        assert_eq!(raw_forward_only.reverse_initial, None);
        assert_eq!(raw_forward_only.total, 132_674);
        assert!(raw_forward_only.total < forward_only.total);

        let mut cursor = usize::MAX;
        assert!(matches!(
            reserve_section(&mut cursor, 1, "test overflow"),
            Err(ObjectError::ArithmeticOverflow("test overflow"))
        ));
        assert!(matches!(
            align_up(usize::MAX, 4, "test alignment overflow"),
            Err(ObjectError::ArithmeticOverflow("test alignment overflow"))
        ));
        assert!(matches!(
            align_up(1, 3, "unused"),
            Err(ObjectError::InvalidModule(_))
        ));
    }

    #[test]
    fn direct_byte_direction_gates_and_program_caps_are_exact() {
        assert_eq!(
            select_direct_byte_directions(512, 508, true, true).unwrap(),
            (true, true),
            "1020 maximum-sized rows consume exactly 1,048,560 bytes"
        );
        assert_eq!(
            direct_byte_transition_bytes(512).unwrap() + direct_byte_transition_bytes(508).unwrap(),
            1_048_560
        );
        assert_eq!(
            select_direct_byte_directions(512, 509, true, true).unwrap(),
            (true, false),
            "reverse DirectByte must independently decline above the combined cap"
        );
        assert_eq!(
            select_direct_byte_directions(513, 512, true, true).unwrap(),
            (false, true),
            "an oversized forward machine must not disable an eligible reverse machine"
        );
        assert_eq!(
            select_direct_byte_directions(512, 512, false, true).unwrap(),
            (true, false)
        );
        assert_eq!(
            select_direct_byte_directions(1, 1, true, false).unwrap(),
            (false, false)
        );

        let direct =
            plan_context_layout(3, 4, 5, true, false, false, true, true, usize::MAX).unwrap();
        assert_eq!(
            direct.forward_byte_sentinel,
            Some(direct.forward_cells + 3 * CONTEXT_DIRECT_BYTE_ROW_BYTES)
        );
        assert_eq!(
            direct.reverse_cells,
            Some(direct.forward_byte_sentinel.unwrap() + 3 * core::mem::size_of::<u32>())
        );
        assert_eq!(
            direct.reverse_byte_sentinel,
            Some(direct.reverse_cells.unwrap() + 4 * CONTEXT_DIRECT_BYTE_ROW_BYTES)
        );
        assert_eq!(
            direct.forward_initial,
            direct.reverse_byte_sentinel.unwrap() + 4 * core::mem::size_of::<u32>()
        );

        let program = contextual_program(r"(?:(?-u:\b)a|ab)+?", b'\n', OutputContract::Span);
        let view = program.native_context_program_view().unwrap();
        let narrow = build_context_native_layout_with_reverse_mode(
            view,
            ContextNativeLimits::default(),
            false,
            false,
            false,
        )
        .unwrap();
        let expanded = build_context_native_layout_with_reverse_mode(
            view,
            ContextNativeLimits::default(),
            false,
            true,
            false,
        )
        .unwrap();
        assert!(expanded.forward_direct_bytes());
        assert!(expanded.reverse_direct_bytes());
        assert!(expanded.data.len() > narrow.data.len());
        let capped = build_context_native_layout_with_reverse_mode(
            view,
            ContextNativeLimits {
                max_data_bytes: narrow.data.len(),
            },
            false,
            true,
            false,
        )
        .unwrap();
        assert_eq!(capped, narrow, "program cap must fall back to narrow rows");
        assert!(matches!(
            build_context_native_layout_with_reverse_mode(
                view,
                ContextNativeLimits {
                    max_data_bytes: narrow.data.len() - 1,
                },
                false,
                true,
                false,
            ),
            Err(ObjectError::Resource {
                resource: CompileResource::ProgramBytes,
                limit,
                required,
            }) if limit == narrow.data.len() - 1 && required == narrow.data.len()
        ));
    }

    #[test]
    fn full_haystack_context_does_not_treat_window_edges_as_absolute() {
        let program =
            contextual_program(r"(?:(?-u:\b)a|a(?m:$)|ab)+?", b'\n', OutputContract::Span);
        let layout = build_context_native_layout(
            program.native_context_program_view().unwrap(),
            ContextNativeLimits::default(),
        )
        .unwrap();
        let haystack = b"-a\nz";
        let full_start = layout.forward_context_at(haystack, 1).unwrap();
        let sliced_start = layout.forward_context_at(&haystack[1..2], 0).unwrap();
        let full_end = layout.reverse_context_at(haystack, 2).unwrap();
        let sliced_end = layout.reverse_context_at(&haystack[1..2], 1).unwrap();
        assert_ne!(full_start, sliced_start);
        assert_ne!(full_end, sliced_end);
        assert_ne!(
            layout.forward_initial_cell(full_start),
            CONTEXT_INVALID_CELL
        );
        assert_ne!(
            layout.reverse_initial_cell(full_end),
            Some(CONTEXT_INVALID_CELL)
        );
        assert_eq!(
            layout.forward_context_at(haystack, haystack.len() + 1),
            None
        );
        assert_eq!(
            layout.reverse_context_at(haystack, haystack.len() + 1),
            None
        );
    }
}
