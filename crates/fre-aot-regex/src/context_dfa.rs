//! Complete ordered determinization for byte-local context assertions.
//!
//! This is deliberately target neutral.  Assertions are evaluated while an
//! ordered Thompson closure is formed at a boundary, and the boundary class is
//! part of the deterministic graph key.  No source position, haystack byte,
//! source spelling, or source hash participates in construction.

#![allow(
    dead_code,
    reason = "checked contextual model helpers are retained alongside the production native view"
)]

use core::{
    cmp::Ordering,
    hash::{BuildHasherDefault, Hash, Hasher},
};
use std::collections::HashMap;

use fre_automata::{EdgeKind, RawPlan, StateRole};

use crate::{
    error::CompileError,
    program::{MatchResult, OutputContract, SearchWindow},
};

const PROPERTY_CONFIGURED_LINE: u8 = 1 << 0;
const PROPERTY_CR: u8 = 1 << 1;
const PROPERTY_LF: u8 = 1 << 2;
const PROPERTY_ASCII_WORD: u8 = 1 << 3;
const NATIVE_CONTEXT_CLASS_MASK: u32 = 0x01ff;
const NATIVE_CONTEXT_PROPERTIES_MASK: u8 = 0x0f;
const NATIVE_CONTEXT_PROPERTIES_SHIFT: u8 = 9;
const NATIVE_CONTEXT_PRESENT_BIT: u32 = 1 << 13;
const NATIVE_CONTEXT_ABSOLUTE_START_BIT: u32 = 1 << 14;
const NATIVE_CONTEXT_ABSOLUTE_END_BIT: u32 = 1 << 15;

type StableMap<K, V> = HashMap<K, V, BuildHasherDefault<StableFnvHasher>>;

/// Hard limits shared by the forward and reverse contextual machines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the max prefix makes every independently enforced construction ceiling explicit"
)]
pub(crate) struct ContextDfaLimits {
    pub(crate) max_states: usize,
    pub(crate) max_transitions: usize,
    pub(crate) max_work: u64,
}

impl Default for ContextDfaLimits {
    fn default() -> Self {
        Self {
            max_states: 65_536,
            max_transitions: 16_777_216,
            max_work: 500_000_000,
        }
    }
}

/// Independent ceilings for the optional single-start forward sidecar.
///
/// Reaching one of these limits omits only the sidecar. The complete search
/// forward and reverse machines have already been built transactionally under
/// [`ContextDfaLimits`] and remain available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the max prefix makes every independently enforced sidecar ceiling explicit"
)]
pub(crate) struct AnchoredForwardLimits {
    pub(crate) max_states: usize,
    pub(crate) max_transitions: usize,
    pub(crate) max_work: u64,
}

impl Default for AnchoredForwardLimits {
    fn default() -> Self {
        Self {
            max_states: 4_096,
            max_transitions: 1_048_576,
            max_work: 16_777_216,
        }
    }
}

impl From<AnchoredForwardLimits> for ContextDfaLimits {
    fn from(limits: AnchoredForwardLimits) -> Self {
        Self {
            max_states: limits.max_states,
            max_transitions: limits.max_transitions,
            max_work: limits.max_work,
        }
    }
}

/// Structural reason that complete contextual determinization was declined.
///
/// This is exposed through the fresh-compilation receipt. It is deliberately
/// not part of the stable semantic-program wire format: deserializing an
/// ordered-NFA artifact cannot recreate an omitted contextual sidecar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextDfaResource {
    /// The graph contains an assertion outside the byte-local contextual
    /// optimizer's supported vocabulary.
    UnsupportedAssertion(EdgeKind),
    /// Aggregate forward/reverse state construction reached its ceiling.
    States { limit: usize, required: usize },
    /// Aggregate forward/reverse transition construction reached its ceiling.
    Transitions { limit: usize, required: usize },
    /// Deterministic construction work reached its ceiling.
    Work { limit: u64, required: u64 },
    /// A bounded fallible reservation failed.
    Allocation {
        requested_elements: usize,
        element_size: usize,
    },
    /// Mandatory state minimization merged initial states whose independently
    /// minimized exact-start residuals are not equivalent. The optional
    /// sidecar is omitted; the mandatory machines remain complete.
    IncompatibleAnchoredQuotient {
        main_state: u32,
        first_anchored_state: u32,
        second_anchored_state: u32,
    },
}

/// Exact bounded construction progress at a structural decline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextDfaDecline {
    /// Exact structural resource that stopped construction.
    pub resource: ContextDfaResource,
    /// Charged deterministic work completed before the decline.
    pub work_completed: u64,
    /// Aggregate forward/reverse states reserved before the decline.
    pub states_completed: usize,
    /// Aggregate forward/reverse transitions reserved before the decline.
    pub transitions_completed: usize,
}

/// Structural dimensions of one completed contextual machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextDfaStats {
    /// Graph- and assertion-property-equivalent byte classes.
    pub alphabet_classes: usize,
    /// Transition cells per state, including the end-of-window symbol.
    pub row_width: usize,
    /// Canonical forward initial boundary-context dispatch entries.
    pub forward_initial_contexts: usize,
    /// Complete forward contextual states.
    pub forward_states: usize,
    /// Complete flattened forward transition cells.
    pub forward_transitions: usize,
    /// Canonical reverse initial boundary-context dispatch entries.
    pub reverse_initial_contexts: usize,
    /// Complete reverse contextual states.
    pub reverse_states: usize,
    /// Complete flattened reverse transition cells.
    pub reverse_transitions: usize,
    /// Whether the optional exact-start forward sidecar was published.
    pub anchored_forward_present: bool,
    /// Canonical exact-start initial boundary-context dispatch entries.
    ///
    /// This is zero when the optional sidecar was omitted.
    pub anchored_forward_initial_contexts: usize,
    /// Complete exact-start forward states, or zero when omitted.
    pub anchored_forward_states: usize,
    /// Complete flattened exact-start transition cells, or zero when omitted.
    pub anchored_forward_transitions: usize,
    /// Exact pre-quotient states constructed under [`AnchoredForwardLimits`].
    ///
    /// This is the replayable state ceiling for a successful sidecar build;
    /// `anchored_forward_states` describes the optimized published machine.
    pub anchored_forward_construction_states: usize,
    /// Exact pre-quotient transition cells constructed under
    /// [`AnchoredForwardLimits`].
    ///
    /// This is the replayable transition ceiling for a successful sidecar
    /// build; `anchored_forward_transitions` describes the optimized machine.
    pub anchored_forward_construction_transitions: usize,
    /// Maximum transitions before every exact-start path resolves.
    ///
    /// This is `None` when the sidecar was omitted or its reachable live graph
    /// contains a cycle. [`ContextDfaStats::anchored_forward_present`]
    /// distinguishes those cases.
    pub anchored_forward_max_resolution_steps: Option<u32>,
    /// Deterministic work completed by the optional sidecar attempt.
    ///
    /// Failed transactional attempts are included, even though no partial
    /// sidecar is published.
    pub anchored_forward_build_work: u64,
    /// Exact resource decline when the optional sidecar was omitted.
    pub anchored_forward_decline: Option<ContextDfaDecline>,
    /// Total deterministic construction work for the mandatory forward and
    /// reverse machines plus the complete or declined sidecar attempt.
    pub build_work: u64,
}

/// Result of an optional contextual determinization attempt.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "keeping the completed machine inline avoids an unaccounted infallible allocation"
)]
pub(crate) enum ContextDfaOutcome {
    Complete(ContextDfa),
    Declined(ContextDfaDecline),
}

/// An explicit classification of one original-haystack boundary.
///
/// Byte classes are graph-derived equivalence classes. `None` on the left or
/// right means that the boundary is at the corresponding original-haystack
/// edge; the absolute flags are retained independently so the model does not
/// silently equate a search-window edge with a haystack edge.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct BoundaryContext {
    pub(crate) before_byte_class: Option<u8>,
    pub(crate) current_byte_class: Option<u8>,
    pub(crate) absolute_start: bool,
    pub(crate) absolute_end: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ContextNeeds {
    property_mask: u8,
}

impl ContextNeeds {
    fn inspect(raw: &RawPlan) -> Result<Self, EdgeKind> {
        let mut property_mask = 0_u8;
        for &kind in &raw.edge_kinds {
            match kind {
                EdgeKind::Epsilon
                | EdgeKind::ByteRange
                | EdgeKind::AssertHaystackStart
                | EdgeKind::AssertHaystackEnd => {}
                EdgeKind::AssertLineStartLf | EdgeKind::AssertLineEndLf => {
                    property_mask |= PROPERTY_CONFIGURED_LINE;
                }
                EdgeKind::AssertLineStartCrlf | EdgeKind::AssertLineEndCrlf => {
                    property_mask |= PROPERTY_CR | PROPERTY_LF;
                }
                EdgeKind::AssertWordAscii
                | EdgeKind::AssertWordAsciiNegate
                | EdgeKind::AssertWordStartAscii
                | EdgeKind::AssertWordEndAscii
                | EdgeKind::AssertWordStartHalfAscii
                | EdgeKind::AssertWordEndHalfAscii => {
                    property_mask |= PROPERTY_ASCII_WORD;
                }
                _ => return Err(kind),
            }
        }
        Ok(Self { property_mask })
    }
}

#[derive(Clone, Debug)]
struct Alphabet {
    byte_to_class: [u8; 256],
    representatives: Vec<u8>,
    properties: Vec<u8>,
}

impl Alphabet {
    fn build(
        raw: &RawPlan,
        line_terminator: u8,
        needs: ContextNeeds,
        budget: &mut BuildBudget,
    ) -> Result<Option<Self>, CompileError> {
        let Some(mut representatives) = reserve_vec(256, budget)? else {
            return Ok(None);
        };
        let Some(mut properties) = reserve_vec(256, budget)? else {
            return Ok(None);
        };
        let mut byte_to_class = [0_u8; 256];
        for byte in u8::MIN..=u8::MAX {
            if !budget.charge(1) {
                return Ok(None);
            }
            let byte_properties = byte_properties(byte, line_terminator) & needs.property_mask;
            let mut found = None;
            for (class, &representative) in representatives.iter().enumerate() {
                if !budget.charge(1) {
                    return Ok(None);
                }
                if properties[class] == byte_properties
                    && bytes_are_graph_equivalent(raw, byte, representative, budget)?
                {
                    if budget.declined.is_some() {
                        return Ok(None);
                    }
                    found = Some(class);
                    break;
                }
                if budget.declined.is_some() {
                    return Ok(None);
                }
            }
            let class = if let Some(class) = found {
                class
            } else {
                let class = representatives.len();
                representatives.push(byte);
                properties.push(byte_properties);
                class
            };
            byte_to_class[usize::from(byte)] = u8::try_from(class).map_err(|_| {
                CompileError::InternalInvariant("contextual alphabet exceeded 256 classes")
            })?;
        }
        Ok(Some(Self {
            byte_to_class,
            representatives,
            properties,
        }))
    }

    fn class(&self, byte: u8) -> u8 {
        self.byte_to_class[usize::from(byte)]
    }

    fn representative(&self, class: u8) -> Result<u8, CompileError> {
        self.representatives.get(usize::from(class)).copied().ok_or(
            CompileError::InternalInvariant("contextual byte class has no representative"),
        )
    }

    fn properties(&self, class: u8) -> Result<u8, CompileError> {
        self.properties
            .get(usize::from(class))
            .copied()
            .ok_or(CompileError::InternalInvariant(
                "contextual byte class has no property record",
            ))
    }

    const fn classes(&self) -> usize {
        self.representatives.len()
    }

    fn observe(&self, haystack: &[u8], position: usize) -> Result<BoundaryContext, CompileError> {
        if position > haystack.len() {
            return Err(CompileError::InternalInvariant(
                "context boundary exceeded the original haystack",
            ));
        }
        let before_byte_class = position
            .checked_sub(1)
            .and_then(|index| haystack.get(index))
            .copied()
            .map(|byte| self.class(byte));
        let current_byte_class = haystack.get(position).copied().map(|byte| self.class(byte));
        Ok(BoundaryContext {
            before_byte_class,
            current_byte_class,
            absolute_start: position == 0,
            absolute_end: position == haystack.len(),
        })
    }
}

fn bytes_are_graph_equivalent(
    raw: &RawPlan,
    left: u8,
    right: u8,
    budget: &mut BuildBudget,
) -> Result<bool, CompileError> {
    for edge in 0..raw.edge_kinds.len() {
        if !budget.charge(1) {
            return Ok(false);
        }
        if raw.edge_kinds[edge] != EdgeKind::ByteRange {
            continue;
        }
        let start = *raw
            .byte_starts
            .get(edge)
            .ok_or(CompileError::InternalInvariant(
                "contextual alphabet byte start is absent",
            ))?;
        let end = *raw
            .byte_ends
            .get(edge)
            .ok_or(CompileError::InternalInvariant(
                "contextual alphabet byte end is absent",
            ))?;
        if (start <= left && left <= end) != (start <= right && right <= end) {
            return Ok(false);
        }
    }
    Ok(true)
}

const fn byte_properties(byte: u8, line_terminator: u8) -> u8 {
    let mut properties = 0_u8;
    if byte == line_terminator {
        properties |= PROPERTY_CONFIGURED_LINE;
    }
    if byte == b'\r' {
        properties |= PROPERTY_CR;
    }
    if byte == b'\n' {
        properties |= PROPERTY_LF;
    }
    if byte == b'_' || byte.is_ascii_alphanumeric() {
        properties |= PROPERTY_ASCII_WORD;
    }
    properties
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum CurrentClass {
    Byte(u8),
    HaystackEnd,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ForwardBoundary {
    before_present: bool,
    before_properties: u8,
    current: CurrentClass,
    absolute_start: bool,
    absolute_end: bool,
}

impl ForwardBoundary {
    fn from_observation(
        observation: BoundaryContext,
        alphabet: &Alphabet,
    ) -> Result<Self, CompileError> {
        let before_properties = observation
            .before_byte_class
            .map(|class| alphabet.properties(class))
            .transpose()?
            .unwrap_or(0);
        Ok(Self {
            before_present: observation.before_byte_class.is_some(),
            before_properties,
            current: observation
                .current_byte_class
                .map_or(CurrentClass::HaystackEnd, CurrentClass::Byte),
            absolute_start: observation.absolute_start,
            absolute_end: observation.absolute_end,
        })
    }

    fn assertion_context(self, alphabet: &Alphabet) -> Result<AssertionContext, CompileError> {
        let (current_present, current_properties) = match self.current {
            CurrentClass::Byte(class) => (true, alphabet.properties(class)?),
            CurrentClass::HaystackEnd => (false, 0),
        };
        Ok(AssertionContext {
            before_present: self.before_present,
            before_properties: self.before_properties,
            current_present,
            current_properties,
            absolute_start: self.absolute_start,
            absolute_end: self.absolute_end,
        })
    }

    fn native_context(self, class_count: usize) -> Result<u32, CompileError> {
        let current = match self.current {
            CurrentClass::Byte(class) => u32::from(class),
            CurrentClass::HaystackEnd => u32::try_from(class_count).map_err(|_| {
                CompileError::InternalInvariant("contextual class count exceeded u32")
            })?,
        };
        if current > 256 || self.before_properties > 0x0f {
            return Err(CompileError::InternalInvariant(
                "forward native context field exceeded its packed width",
            ));
        }
        Ok(current
            | (u32::from(self.before_properties) << NATIVE_CONTEXT_PROPERTIES_SHIFT)
            | if self.before_present {
                NATIVE_CONTEXT_PRESENT_BIT
            } else {
                0
            }
            | if self.absolute_start {
                NATIVE_CONTEXT_ABSOLUTE_START_BIT
            } else {
                0
            }
            | if self.absolute_end {
                NATIVE_CONTEXT_ABSOLUTE_END_BIT
            } else {
                0
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ReverseBoundary {
    before: Option<u8>,
    current_present: bool,
    current_properties: u8,
    absolute_start: bool,
    absolute_end: bool,
}

impl ReverseBoundary {
    fn from_observation(
        observation: BoundaryContext,
        alphabet: &Alphabet,
    ) -> Result<Self, CompileError> {
        let current_properties = observation
            .current_byte_class
            .map(|class| alphabet.properties(class))
            .transpose()?
            .unwrap_or(0);
        Ok(Self {
            before: observation.before_byte_class,
            current_present: observation.current_byte_class.is_some(),
            current_properties,
            absolute_start: observation.absolute_start,
            absolute_end: observation.absolute_end,
        })
    }

    fn assertion_context(self, alphabet: &Alphabet) -> Result<AssertionContext, CompileError> {
        let before_properties = match self.before {
            Some(class) => match alphabet.properties.get(usize::from(class)) {
                Some(properties) => *properties,
                None => {
                    return Err(CompileError::InternalInvariant(
                        "reverse boundary before class is absent",
                    ));
                }
            },
            None => 0,
        };
        Ok(AssertionContext {
            before_present: self.before.is_some(),
            before_properties,
            current_present: self.current_present,
            current_properties: self.current_properties,
            absolute_start: self.absolute_start,
            absolute_end: self.absolute_end,
        })
    }

    fn native_context(self, class_count: usize) -> Result<u32, CompileError> {
        let before = self.before.map_or_else(
            || {
                u32::try_from(class_count).map_err(|_| {
                    CompileError::InternalInvariant("contextual class count exceeded u32")
                })
            },
            |class| Ok(u32::from(class)),
        )?;
        if before > 256 || self.current_properties > 0x0f {
            return Err(CompileError::InternalInvariant(
                "reverse native context field exceeded its packed width",
            ));
        }
        Ok(before
            | (u32::from(self.current_properties) << NATIVE_CONTEXT_PROPERTIES_SHIFT)
            | if self.current_present {
                NATIVE_CONTEXT_PRESENT_BIT
            } else {
                0
            }
            | if self.absolute_start {
                NATIVE_CONTEXT_ABSOLUTE_START_BIT
            } else {
                0
            }
            | if self.absolute_end {
                NATIVE_CONTEXT_ABSOLUTE_END_BIT
            } else {
                0
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "presence and absolute-haystack edges are independent boundary facts"
)]
struct AssertionContext {
    before_present: bool,
    before_properties: u8,
    current_present: bool,
    current_properties: u8,
    absolute_start: bool,
    absolute_end: bool,
}

impl AssertionContext {
    fn enabled(self, kind: EdgeKind) -> Result<bool, CompileError> {
        let before_line =
            self.before_present && self.before_properties & PROPERTY_CONFIGURED_LINE != 0;
        let current_line =
            self.current_present && self.current_properties & PROPERTY_CONFIGURED_LINE != 0;
        let before_cr = self.before_present && self.before_properties & PROPERTY_CR != 0;
        let before_lf = self.before_present && self.before_properties & PROPERTY_LF != 0;
        let current_cr = self.current_present && self.current_properties & PROPERTY_CR != 0;
        let current_lf = self.current_present && self.current_properties & PROPERTY_LF != 0;
        let before_word = self.before_present && self.before_properties & PROPERTY_ASCII_WORD != 0;
        let current_word =
            self.current_present && self.current_properties & PROPERTY_ASCII_WORD != 0;
        match kind {
            EdgeKind::Epsilon => Ok(true),
            EdgeKind::AssertHaystackStart => Ok(self.absolute_start),
            EdgeKind::AssertHaystackEnd => Ok(self.absolute_end),
            EdgeKind::AssertLineStartLf => Ok(self.absolute_start || before_line),
            EdgeKind::AssertLineEndLf => Ok(self.absolute_end || current_line),
            EdgeKind::AssertLineStartCrlf => {
                Ok(self.absolute_start || before_lf || before_cr && !current_lf)
            }
            EdgeKind::AssertLineEndCrlf => {
                Ok(self.absolute_end || current_cr || current_lf && !before_cr)
            }
            EdgeKind::AssertWordAscii => Ok(before_word != current_word),
            EdgeKind::AssertWordAsciiNegate => Ok(before_word == current_word),
            EdgeKind::AssertWordStartAscii => Ok(!before_word && current_word),
            EdgeKind::AssertWordEndAscii => Ok(before_word && !current_word),
            EdgeKind::AssertWordStartHalfAscii => Ok(!before_word),
            EdgeKind::AssertWordEndHalfAscii => Ok(!current_word),
            EdgeKind::ByteRange
            | EdgeKind::AssertWordUnicode
            | EdgeKind::AssertWordUnicodeNegate
            | EdgeKind::AssertWordStartUnicode
            | EdgeKind::AssertWordEndUnicode
            | EdgeKind::AssertWordStartHalfUnicode
            | EdgeKind::AssertWordEndHalfUnicode => Err(CompileError::InternalInvariant(
                "unsupported edge reached contextual assertion evaluation",
            )),
            _ => Err(CompileError::InternalInvariant(
                "unknown edge reached contextual assertion evaluation",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ForwardKey {
    items: Vec<u32>,
    pending: bool,
    boundary: ForwardBoundary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ForwardCell {
    next: u32,
    accepted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForwardMode {
    /// Inject a fresh graph start after the current ordered frontier, producing
    /// the complete unanchored search machine.
    Search,
    /// Retain only paths that originated at the exact initial candidate.
    Anchored,
}

/// Canonically ordered initial-context dispatch fact for the forward machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeContextForwardInitial {
    /// Packed boundary facts, ordered numerically and independent of hash-map
    /// layout. Bits 0..=8 are current class (`class_count` means haystack
    /// end), 9..=12 are previous-byte properties, and bits 13..=15 are
    /// previous-present, absolute-start, and absolute-end.
    pub(crate) context: u32,
    pub(crate) state: u32,
}

/// One flattened forward contextual transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeContextForwardCell {
    pub(crate) next: u32,
    pub(crate) accepted: bool,
}

/// Per-forward-state control facts required by native ordered execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeContextForwardState {
    /// An ordered acceptance has been observed but can still be superseded by
    /// a higher-priority consuming path.
    pub(crate) pending: bool,
    /// No consuming path is active at this boundary. When `pending` is also
    /// false, native search may discard the current byte and restart from the
    /// graph-derived anchored-prefix scanner without losing a match start.
    pub(crate) empty: bool,
    /// Exact portable early-stop condition: `pending && items.is_empty()`.
    pub(crate) terminal: bool,
}

#[derive(Clone, Debug)]
struct ForwardDfa {
    initial: StableMap<ForwardBoundary, u32>,
    canonical_initial: Vec<NativeContextForwardInitial>,
    states: Vec<ForwardKey>,
    native_states: Vec<NativeContextForwardState>,
    row_offsets: Vec<u32>,
    cells: Vec<NativeContextForwardCell>,
}

/// Optional deterministic forward machine whose frontier contains only paths
/// born at one exact candidate start.
///
/// Its initial keys are byte-for-byte equal to the corresponding search-DFA
/// initial keys. `main_initial_to_anchored` lets native lowering reuse the
/// search machine's exact raw/semantic boundary dispatch instead of publishing
/// a second complete initial table.
#[derive(Clone, Debug)]
struct AnchoredForwardDfa {
    forward: ForwardDfa,
    main_initial_to_anchored: Vec<u32>,
    /// Maximum transitions before every graph path resolves, when the live
    /// reachable graph is acyclic. `None` means a live cycle exists.
    max_resolution_steps: Option<u32>,
}

/// Transactional result of the independently bounded optional sidecar build.
struct AnchoredForwardBuild {
    machine: Option<AnchoredForwardDfa>,
    build_work: u64,
    construction_states: usize,
    construction_transitions: usize,
    decline: Option<ContextDfaDecline>,
}

impl AnchoredForwardBuild {
    fn completed(machine: AnchoredForwardDfa, budget: BuildBudget) -> Self {
        Self {
            machine: Some(machine),
            build_work: budget.work,
            construction_states: budget.states,
            construction_transitions: budget.transitions,
            decline: None,
        }
    }

    fn declined(budget: BuildBudget) -> Result<Self, CompileError> {
        let build_work = budget.work;
        Ok(Self {
            machine: None,
            build_work,
            construction_states: 0,
            construction_transitions: 0,
            decline: Some(budget.finish_decline()?),
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReverseKey {
    items: Vec<u32>,
    boundary: ReverseBoundary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReverseCell {
    next: Option<u32>,
    reaches_start: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReverseInitial {
    state: Option<u32>,
    reaches_start: bool,
}

/// Canonically ordered initial-context dispatch fact for span recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeContextReverseInitial {
    /// Packed boundary facts, ordered numerically. Bits 0..=8 are the previous
    /// byte class (`class_count` means absent), 9..=12 are current-byte
    /// properties, and bits 13..=15 are current-present, absolute-start, and
    /// absolute-end.
    pub(crate) context: u32,
    /// `u32::MAX` denotes an empty reverse frontier.
    pub(crate) state: u32,
    pub(crate) reaches_start: bool,
}

/// One flattened reverse contextual transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeContextReverseCell {
    /// `u32::MAX` denotes an empty reverse frontier.
    pub(crate) next: u32,
    pub(crate) reaches_start: bool,
}

/// Exact packed-key and fixed-row contract shared by both initial dispatches.
///
/// Forward keys pack the current byte class (or `sentinel_class` at haystack
/// end), previous-byte properties, previous-byte presence, and the two
/// absolute flags. Reverse keys pack the previous byte class (or
/// `sentinel_class` when absent), current-byte properties, current-byte
/// presence, and the same absolute flags. Initial fact slices are strictly
/// sorted by this exact key and require equality lookup; no hash layout is
/// part of the native contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeContextInitialDispatch {
    pub(crate) class_count: u32,
    pub(crate) sentinel_class: u32,
    pub(crate) row_width: u32,
    pub(crate) class_mask: u32,
    pub(crate) properties_mask: u8,
    pub(crate) properties_shift: u8,
    pub(crate) present_bit: u32,
    pub(crate) absolute_start_bit: u32,
    pub(crate) absolute_end_bit: u32,
}

impl NativeContextInitialDispatch {
    fn new(class_count: usize) -> Result<Self, CompileError> {
        let class_count = u32::try_from(class_count)
            .map_err(|_| CompileError::InternalInvariant("contextual class count exceeded u32"))?;
        if class_count > 256 {
            return Err(CompileError::InternalInvariant(
                "contextual class count exceeded packed dispatch width",
            ));
        }
        let row_width = class_count
            .checked_add(1)
            .ok_or(CompileError::InternalInvariant(
                "contextual native row width overflowed",
            ))?;
        Ok(Self {
            class_count,
            sentinel_class: class_count,
            row_width,
            class_mask: NATIVE_CONTEXT_CLASS_MASK,
            properties_mask: NATIVE_CONTEXT_PROPERTIES_MASK,
            properties_shift: NATIVE_CONTEXT_PROPERTIES_SHIFT,
            present_bit: NATIVE_CONTEXT_PRESENT_BIT,
            absolute_start_bit: NATIVE_CONTEXT_ABSOLUTE_START_BIT,
            absolute_end_bit: NATIVE_CONTEXT_ABSOLUTE_END_BIT,
        })
    }

    pub(crate) fn pack(
        self,
        class: u32,
        properties: u8,
        present: bool,
        absolute_start: bool,
        absolute_end: bool,
    ) -> Option<u32> {
        if class > self.sentinel_class || properties & !self.properties_mask != 0 {
            return None;
        }
        Some(
            class
                | (u32::from(properties) << self.properties_shift)
                | if present { self.present_bit } else { 0 }
                | if absolute_start {
                    self.absolute_start_bit
                } else {
                    0
                }
                | if absolute_end {
                    self.absolute_end_bit
                } else {
                    0
                },
        )
    }
}

#[derive(Clone, Debug)]
struct ReverseDfa {
    initial: StableMap<ReverseBoundary, ReverseInitial>,
    canonical_initial: Vec<NativeContextReverseInitial>,
    states: Vec<ReverseKey>,
    row_offsets: Vec<u32>,
    cells: Vec<NativeContextReverseCell>,
}

/// Independent ceiling for the optional late semantic quotient.
///
/// The mandatory determinization and optional anchored sidecar have already
/// completed before this pass starts. Exhaustion therefore keeps those exact
/// machines instead of turning a successful compilation into a decline.
const LATE_CONTEXT_QUOTIENT_MAX_WORK: u64 = 1_000_000_000;
const LATE_CONTEXT_QUOTIENT_MAX_STATES: usize = 65_536;
const LATE_CONTEXT_QUOTIENT_MAX_TRANSITIONS: usize = 16_777_216;
const LATE_ANCHORED_QUOTIENT_MAX_STATES: usize = 4_096;
const LATE_ANCHORED_QUOTIENT_MAX_TRANSITIONS: usize = 1_048_576;

struct LateQuotientBudget {
    work: u64,
    max_work: u64,
    exhausted: bool,
}

impl LateQuotientBudget {
    const fn new(max_work: u64) -> Self {
        Self {
            work: 0,
            max_work,
            exhausted: false,
        }
    }

    fn charge(&mut self, amount: usize) -> bool {
        let Ok(amount) = u64::try_from(amount) else {
            self.exhausted = true;
            return false;
        };
        let Some(required) = self.work.checked_add(amount) else {
            self.exhausted = true;
            return false;
        };
        if required > self.max_work {
            self.exhausted = true;
            return false;
        }
        self.work = required;
        true
    }

    fn charge_product(&mut self, left: usize, right: usize) -> bool {
        let Some(amount) = left.checked_mul(right) else {
            self.exhausted = true;
            return false;
        };
        self.charge(amount)
    }

    fn reserve_vec<T>(&mut self, capacity: usize) -> Option<Vec<T>> {
        let mut values = Vec::new();
        if values.try_reserve_exact(capacity).is_err() {
            self.exhausted = true;
            return None;
        }
        Some(values)
    }

    fn reserve_map<K: Eq + Hash, V>(&mut self, capacity: usize) -> Option<StableMap<K, V>> {
        let mut values = StableMap::default();
        if values.try_reserve(capacity).is_err() {
            self.exhausted = true;
            return None;
        }
        Some(values)
    }
}

#[derive(Clone, Copy)]
struct SignatureFingerprint {
    first: u64,
    second: u64,
    state: usize,
}

struct StatePartition {
    old_to_new: Vec<u32>,
    representatives: Vec<usize>,
}

struct ContextDfaQuotient {
    forward: Option<ForwardDfa>,
    reverse: Option<ReverseDfa>,
    anchored_update: AnchoredQuotientUpdate,
    semantic_quotient: bool,
}

enum AnchoredQuotientUpdate {
    Preserve,
    Remap(Vec<u32>),
    Replace(AnchoredForwardDfa),
    Omit(ContextDfaResource),
}

enum AnchoredMappingRemap {
    Complete(Vec<u32>),
    Conflict {
        main_state: u32,
        first_anchored_state: u32,
        second_anchored_state: u32,
    },
}

const fn quotient_mix(mut hash: u64, value: u64) -> u64 {
    hash ^= value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    hash = hash.wrapping_mul(0x1000_0000_01b3);
    hash ^ (hash >> 29)
}

const fn quotient_sort_units(length: usize) -> usize {
    if length < 2 {
        return length;
    }
    let bits = usize::BITS - (length - 1).leading_zeros();
    length.saturating_mul(bits as usize)
}

fn validate_forward_quotient_input(forward: &ForwardDfa, width: usize) -> Result<(), CompileError> {
    let state_count = forward.states.len();
    if forward.native_states.len() != state_count
        || forward.row_offsets.len() != state_count.saturating_add(1)
        || forward.cells.len() != state_count.saturating_mul(width)
    {
        return Err(CompileError::InternalInvariant(
            "contextual forward quotient input has inconsistent dimensions",
        ));
    }
    for (state, &offset) in forward.row_offsets.iter().enumerate() {
        let expected = state
            .checked_mul(width)
            .ok_or(CompileError::InternalInvariant(
                "contextual forward quotient row offset overflowed",
            ))?;
        if usize::try_from(offset).ok() != Some(expected) {
            return Err(CompileError::InternalInvariant(
                "contextual forward quotient input has a noncanonical row offset",
            ));
        }
    }
    if forward.cells.iter().any(|cell| {
        usize::try_from(cell.next).map_or(true, |destination| destination >= state_count)
    }) {
        return Err(CompileError::InternalInvariant(
            "contextual forward quotient destination is absent",
        ));
    }
    Ok(())
}

fn validate_reverse_quotient_input(reverse: &ReverseDfa, width: usize) -> Result<(), CompileError> {
    let state_count = reverse.states.len();
    if reverse.row_offsets.len() != state_count.saturating_add(1)
        || reverse.cells.len() != state_count.saturating_mul(width)
    {
        return Err(CompileError::InternalInvariant(
            "contextual reverse quotient input has inconsistent dimensions",
        ));
    }
    for (state, &offset) in reverse.row_offsets.iter().enumerate() {
        let expected = state
            .checked_mul(width)
            .ok_or(CompileError::InternalInvariant(
                "contextual reverse quotient row offset overflowed",
            ))?;
        if usize::try_from(offset).ok() != Some(expected) {
            return Err(CompileError::InternalInvariant(
                "contextual reverse quotient input has a noncanonical row offset",
            ));
        }
    }
    if reverse.cells.iter().any(|cell| {
        cell.next != u32::MAX
            && usize::try_from(cell.next).map_or(true, |destination| destination >= state_count)
    }) {
        return Err(CompileError::InternalInvariant(
            "contextual reverse quotient destination is absent",
        ));
    }
    Ok(())
}

fn forward_signature_hash(
    forward: &ForwardDfa,
    state: usize,
    width: usize,
    partition: &[u32],
    external: &[u32],
    seed: u64,
) -> u64 {
    let native = forward.native_states[state];
    let key = &forward.states[state];
    let mut hash = quotient_mix(seed, u64::from(partition[state]));
    hash = quotient_mix(hash, u64::from(native.pending));
    hash = quotient_mix(hash, u64::from(native.empty));
    hash = quotient_mix(hash, u64::from(native.terminal));
    hash = quotient_mix(
        hash,
        u64::from(key.boundary.current != CurrentClass::HaystackEnd),
    );
    hash = quotient_mix(hash, u64::from(external[state]));
    let begin = state * width;
    for cell in &forward.cells[begin..begin + width] {
        hash = quotient_mix(hash, u64::from(cell.accepted));
        hash = quotient_mix(hash, u64::from(partition[cell.next as usize]));
    }
    hash
}

fn forward_signature_cmp(
    forward: &ForwardDfa,
    left: usize,
    right: usize,
    width: usize,
    partition: &[u32],
    external: &[u32],
) -> Ordering {
    let left_native = forward.native_states[left];
    let right_native = forward.native_states[right];
    let left_consumable = forward.states[left].boundary.current != CurrentClass::HaystackEnd;
    let right_consumable = forward.states[right].boundary.current != CurrentClass::HaystackEnd;
    partition[left]
        .cmp(&partition[right])
        .then_with(|| left_native.pending.cmp(&right_native.pending))
        .then_with(|| left_native.empty.cmp(&right_native.empty))
        .then_with(|| left_native.terminal.cmp(&right_native.terminal))
        .then_with(|| left_consumable.cmp(&right_consumable))
        .then_with(|| external[left].cmp(&external[right]))
        .then_with(|| {
            let left_begin = left * width;
            let right_begin = right * width;
            forward.cells[left_begin..left_begin + width]
                .iter()
                .zip(&forward.cells[right_begin..right_begin + width])
                .find_map(|(left_cell, right_cell)| {
                    let ordering = left_cell.accepted.cmp(&right_cell.accepted).then_with(|| {
                        partition[left_cell.next as usize].cmp(&partition[right_cell.next as usize])
                    });
                    (ordering != Ordering::Equal).then_some(ordering)
                })
                .unwrap_or(Ordering::Equal)
        })
}

fn reverse_signature_hash(
    reverse: &ReverseDfa,
    state: usize,
    width: usize,
    partition: &[u32],
    seed: u64,
) -> u64 {
    let mut hash = quotient_mix(seed, u64::from(partition[state]));
    let begin = state * width;
    for cell in &reverse.cells[begin..begin + width] {
        hash = quotient_mix(hash, u64::from(cell.reaches_start));
        let destination = if cell.next == u32::MAX {
            u64::MAX
        } else {
            u64::from(partition[cell.next as usize])
        };
        hash = quotient_mix(hash, destination);
    }
    hash
}

fn reverse_signature_cmp(
    reverse: &ReverseDfa,
    left: usize,
    right: usize,
    width: usize,
    partition: &[u32],
) -> Ordering {
    partition[left].cmp(&partition[right]).then_with(|| {
        let left_begin = left * width;
        let right_begin = right * width;
        reverse.cells[left_begin..left_begin + width]
            .iter()
            .zip(&reverse.cells[right_begin..right_begin + width])
            .find_map(|(left_cell, right_cell)| {
                let left_destination =
                    (left_cell.next != u32::MAX).then(|| partition[left_cell.next as usize]);
                let right_destination =
                    (right_cell.next != u32::MAX).then(|| partition[right_cell.next as usize]);
                let ordering = left_cell
                    .reaches_start
                    .cmp(&right_cell.reaches_start)
                    .then_with(|| left_destination.cmp(&right_destination));
                (ordering != Ordering::Equal).then_some(ordering)
            })
            .unwrap_or(Ordering::Equal)
    })
}

fn refine_state_partition<HashSignature, CompareSignature>(
    state_count: usize,
    signature_units: usize,
    budget: &mut LateQuotientBudget,
    mut hash_signature: HashSignature,
    mut compare_signature: CompareSignature,
) -> Option<StatePartition>
where
    HashSignature: FnMut(usize, &[u32], u64) -> u64,
    CompareSignature: FnMut(usize, usize, &[u32]) -> Ordering,
{
    let mut partition = budget.reserve_vec(state_count)?;
    partition.resize(state_count, 0_u32);
    let mut next_partition = budget.reserve_vec(state_count)?;
    next_partition.resize(state_count, u32::MAX);
    let mut fingerprints = budget.reserve_vec(state_count)?;
    if state_count == 0 {
        return Some(StatePartition {
            old_to_new: partition,
            representatives: Vec::new(),
        });
    }

    let mut partition_count = 1_usize;
    loop {
        fingerprints.clear();
        if !budget.charge_product(state_count, signature_units) {
            return None;
        }
        for state in 0..state_count {
            fingerprints.push(SignatureFingerprint {
                first: hash_signature(state, &partition, 0xcbf2_9ce4_8422_2325),
                second: hash_signature(state, &partition, 0x6a09_e667_f3bc_c909),
                state,
            });
        }
        if !budget.charge(quotient_sort_units(state_count)) {
            return None;
        }
        fingerprints.sort_unstable_by_key(|entry| (entry.first, entry.second));
        next_partition.fill(u32::MAX);
        if !budget.charge(state_count) {
            return None;
        }

        let mut next_count = 0_usize;
        let mut cursor = 0_usize;
        while cursor < fingerprints.len() {
            let fingerprint = (fingerprints[cursor].first, fingerprints[cursor].second);
            let mut end = cursor + 1;
            while end < fingerprints.len()
                && (fingerprints[end].first, fingerprints[end].second) == fingerprint
            {
                end += 1;
            }
            let bucket_len = end - cursor;
            if !budget.charge_product(bucket_len.saturating_sub(1), signature_units) {
                return None;
            }
            let first_state = fingerprints[cursor].state;
            let all_equal = fingerprints[cursor + 1..end].iter().all(|entry| {
                compare_signature(first_state, entry.state, &partition) == Ordering::Equal
            });
            if all_equal {
                let next = u32::try_from(next_count).ok()?;
                for entry in &fingerprints[cursor..end] {
                    next_partition[entry.state] = next;
                }
                next_count += 1;
            } else {
                if !budget.charge_product(quotient_sort_units(bucket_len), signature_units) {
                    return None;
                }
                fingerprints[cursor..end].sort_unstable_by(|left, right| {
                    compare_signature(left.state, right.state, &partition)
                });
                if !budget.charge_product(bucket_len.saturating_sub(1), signature_units) {
                    return None;
                }
                let mut previous = None;
                for entry in &fingerprints[cursor..end] {
                    if previous.is_none_or(|state| {
                        compare_signature(state, entry.state, &partition) != Ordering::Equal
                    }) {
                        next_count += 1;
                    }
                    next_partition[entry.state] = u32::try_from(next_count - 1).ok()?;
                    previous = Some(entry.state);
                }
            }
            cursor = end;
        }
        if next_count == partition_count {
            core::mem::swap(&mut partition, &mut next_partition);
            partition_count = next_count;
            break;
        }
        core::mem::swap(&mut partition, &mut next_partition);
        partition_count = next_count;
    }

    let mut representatives = budget.reserve_vec(partition_count)?;
    representatives.resize(partition_count, usize::MAX);
    if !budget.charge(state_count) {
        return None;
    }
    for (state, &class) in partition.iter().enumerate() {
        let representative = representatives.get_mut(class as usize)?;
        *representative = (*representative).min(state);
    }
    if representatives.contains(&usize::MAX) {
        return None;
    }
    Some(StatePartition {
        old_to_new: partition,
        representatives,
    })
}

fn forward_partition(
    forward: &ForwardDfa,
    width: usize,
    external: &[u32],
    budget: &mut LateQuotientBudget,
) -> Result<Option<StatePartition>, CompileError> {
    validate_forward_quotient_input(forward, width)?;
    if external.len() != forward.states.len() {
        return Err(CompileError::InternalInvariant(
            "contextual forward quotient external colors have the wrong length",
        ));
    }
    let signature_units = width
        .checked_mul(2)
        .and_then(|units| units.checked_add(6))
        .ok_or(CompileError::InternalInvariant(
            "contextual forward quotient signature width overflowed",
        ))?;
    Ok(refine_state_partition(
        forward.states.len(),
        signature_units,
        budget,
        |state, partition, seed| {
            forward_signature_hash(forward, state, width, partition, external, seed)
        },
        |left, right, partition| {
            forward_signature_cmp(forward, left, right, width, partition, external)
        },
    ))
}

fn reverse_partition(
    reverse: &ReverseDfa,
    width: usize,
    budget: &mut LateQuotientBudget,
) -> Result<Option<StatePartition>, CompileError> {
    validate_reverse_quotient_input(reverse, width)?;
    let signature_units = width
        .checked_mul(2)
        .and_then(|units| units.checked_add(1))
        .ok_or(CompileError::InternalInvariant(
            "contextual reverse quotient signature width overflowed",
        ))?;
    Ok(refine_state_partition(
        reverse.states.len(),
        signature_units,
        budget,
        |state, partition, seed| reverse_signature_hash(reverse, state, width, partition, seed),
        |left, right, partition| reverse_signature_cmp(reverse, left, right, width, partition),
    ))
}

fn quotient_clone_forward_key(
    key: &ForwardKey,
    budget: &mut LateQuotientBudget,
) -> Option<ForwardKey> {
    if !budget.charge(key.items.len()) {
        return None;
    }
    let mut items = budget.reserve_vec(key.items.len())?;
    items.extend_from_slice(&key.items);
    Some(ForwardKey {
        items,
        pending: key.pending,
        boundary: key.boundary,
    })
}

fn quotient_clone_reverse_key(
    key: &ReverseKey,
    budget: &mut LateQuotientBudget,
) -> Option<ReverseKey> {
    if !budget.charge(key.items.len()) {
        return None;
    }
    let mut items = budget.reserve_vec(key.items.len())?;
    items.extend_from_slice(&key.items);
    Some(ReverseKey {
        items,
        boundary: key.boundary,
    })
}

fn build_forward_quotient(
    source: &ForwardDfa,
    partition: &StatePartition,
    width: usize,
    budget: &mut LateQuotientBudget,
) -> Result<Option<ForwardDfa>, CompileError> {
    if partition.old_to_new.len() != source.states.len() {
        return Err(CompileError::InternalInvariant(
            "contextual forward quotient map has the wrong length",
        ));
    }
    let state_count = partition.representatives.len();
    let cell_count = state_count
        .checked_mul(width)
        .ok_or(CompileError::InternalInvariant(
            "contextual forward quotient cell count overflowed",
        ))?;
    let Some(mut initial) = budget.reserve_map(source.initial.len()) else {
        return Ok(None);
    };
    if !budget.charge(source.initial.len()) {
        return Ok(None);
    }
    for (&boundary, &state) in &source.initial {
        let state =
            *partition
                .old_to_new
                .get(state as usize)
                .ok_or(CompileError::InternalInvariant(
                    "contextual forward quotient initial state is absent",
                ))?;
        if initial.insert(boundary, state).is_some() {
            return Err(CompileError::InternalInvariant(
                "contextual forward quotient duplicated an initial boundary",
            ));
        }
    }

    let Some(mut canonical_initial) = budget.reserve_vec(source.canonical_initial.len()) else {
        return Ok(None);
    };
    if !budget.charge(source.canonical_initial.len()) {
        return Ok(None);
    }
    for &entry in &source.canonical_initial {
        canonical_initial.push(NativeContextForwardInitial {
            context: entry.context,
            state: *partition.old_to_new.get(entry.state as usize).ok_or(
                CompileError::InternalInvariant(
                    "canonical forward quotient initial state is absent",
                ),
            )?,
        });
    }

    let Some(mut states) = budget.reserve_vec(state_count) else {
        return Ok(None);
    };
    let Some(mut native_states) = budget.reserve_vec(state_count) else {
        return Ok(None);
    };
    let Some(mut row_offsets) = budget.reserve_vec(state_count.saturating_add(1)) else {
        return Ok(None);
    };
    let Some(mut cells) = budget.reserve_vec(cell_count) else {
        return Ok(None);
    };
    for &representative in &partition.representatives {
        if !budget.charge(width.saturating_add(1)) {
            return Ok(None);
        }
        let key = source
            .states
            .get(representative)
            .ok_or(CompileError::InternalInvariant(
                "contextual forward quotient representative is absent",
            ))?;
        let Some(key) = quotient_clone_forward_key(key, budget) else {
            return Ok(None);
        };
        states.push(key);
        native_states.push(*source.native_states.get(representative).ok_or(
            CompileError::InternalInvariant(
                "contextual forward quotient native representative is absent",
            ),
        )?);
        row_offsets.push(u32::try_from(cells.len()).map_err(|_| {
            CompileError::InternalInvariant("contextual forward quotient row offset exceeded u32")
        })?);
        let begin = representative
            .checked_mul(width)
            .ok_or(CompileError::InternalInvariant(
                "contextual forward quotient source row overflowed",
            ))?;
        for cell in
            source
                .cells
                .get(begin..begin + width)
                .ok_or(CompileError::InternalInvariant(
                    "contextual forward quotient source row is absent",
                ))?
        {
            cells.push(NativeContextForwardCell {
                next: *partition.old_to_new.get(cell.next as usize).ok_or(
                    CompileError::InternalInvariant(
                        "contextual forward quotient destination is absent",
                    ),
                )?,
                accepted: cell.accepted,
            });
        }
    }
    row_offsets.push(u32::try_from(cells.len()).map_err(|_| {
        CompileError::InternalInvariant("contextual forward quotient final offset exceeded u32")
    })?);
    Ok(Some(ForwardDfa {
        initial,
        canonical_initial,
        states,
        native_states,
        row_offsets,
        cells,
    }))
}

fn build_reverse_quotient(
    source: &ReverseDfa,
    partition: &StatePartition,
    width: usize,
    budget: &mut LateQuotientBudget,
) -> Result<Option<ReverseDfa>, CompileError> {
    if partition.old_to_new.len() != source.states.len() {
        return Err(CompileError::InternalInvariant(
            "contextual reverse quotient map has the wrong length",
        ));
    }
    let state_count = partition.representatives.len();
    let cell_count = state_count
        .checked_mul(width)
        .ok_or(CompileError::InternalInvariant(
            "contextual reverse quotient cell count overflowed",
        ))?;
    let Some(mut initial) = budget.reserve_map(source.initial.len()) else {
        return Ok(None);
    };
    if !budget.charge(source.initial.len()) {
        return Ok(None);
    }
    for (&boundary, &entry) in &source.initial {
        let state = match entry.state {
            Some(state) => Some(*partition.old_to_new.get(state as usize).ok_or(
                CompileError::InternalInvariant(
                    "contextual reverse quotient initial state is absent",
                ),
            )?),
            None => None,
        };
        if initial
            .insert(
                boundary,
                ReverseInitial {
                    state,
                    reaches_start: entry.reaches_start,
                },
            )
            .is_some()
        {
            return Err(CompileError::InternalInvariant(
                "contextual reverse quotient duplicated an initial boundary",
            ));
        }
    }

    let Some(mut canonical_initial) = budget.reserve_vec(source.canonical_initial.len()) else {
        return Ok(None);
    };
    if !budget.charge(source.canonical_initial.len()) {
        return Ok(None);
    }
    for &entry in &source.canonical_initial {
        let state = if entry.state == u32::MAX {
            u32::MAX
        } else {
            *partition.old_to_new.get(entry.state as usize).ok_or(
                CompileError::InternalInvariant(
                    "canonical reverse quotient initial state is absent",
                ),
            )?
        };
        canonical_initial.push(NativeContextReverseInitial {
            context: entry.context,
            state,
            reaches_start: entry.reaches_start,
        });
    }

    let Some(mut states) = budget.reserve_vec(state_count) else {
        return Ok(None);
    };
    let Some(mut row_offsets) = budget.reserve_vec(state_count.saturating_add(1)) else {
        return Ok(None);
    };
    let Some(mut cells) = budget.reserve_vec(cell_count) else {
        return Ok(None);
    };
    for &representative in &partition.representatives {
        if !budget.charge(width.saturating_add(1)) {
            return Ok(None);
        }
        let key = source
            .states
            .get(representative)
            .ok_or(CompileError::InternalInvariant(
                "contextual reverse quotient representative is absent",
            ))?;
        let Some(key) = quotient_clone_reverse_key(key, budget) else {
            return Ok(None);
        };
        states.push(key);
        row_offsets.push(u32::try_from(cells.len()).map_err(|_| {
            CompileError::InternalInvariant("contextual reverse quotient row offset exceeded u32")
        })?);
        let begin = representative
            .checked_mul(width)
            .ok_or(CompileError::InternalInvariant(
                "contextual reverse quotient source row overflowed",
            ))?;
        for cell in
            source
                .cells
                .get(begin..begin + width)
                .ok_or(CompileError::InternalInvariant(
                    "contextual reverse quotient source row is absent",
                ))?
        {
            cells.push(NativeContextReverseCell {
                next: if cell.next == u32::MAX {
                    u32::MAX
                } else {
                    *partition.old_to_new.get(cell.next as usize).ok_or(
                        CompileError::InternalInvariant(
                            "contextual reverse quotient destination is absent",
                        ),
                    )?
                },
                reaches_start: cell.reaches_start,
            });
        }
    }
    row_offsets.push(u32::try_from(cells.len()).map_err(|_| {
        CompileError::InternalInvariant("contextual reverse quotient final offset exceeded u32")
    })?);
    Ok(Some(ReverseDfa {
        initial,
        canonical_initial,
        states,
        row_offsets,
        cells,
    }))
}

fn remap_anchored_initial_states(
    source: &[u32],
    main_partition: Option<&StatePartition>,
    anchored_partition: Option<&StatePartition>,
    budget: &mut LateQuotientBudget,
) -> Result<Option<AnchoredMappingRemap>, CompileError> {
    if main_partition.is_some_and(|partition| source.len() != partition.old_to_new.len()) {
        return Err(CompileError::InternalInvariant(
            "contextual anchored quotient mapping has the wrong source length",
        ));
    }
    let main_states =
        main_partition.map_or(source.len(), |partition| partition.representatives.len());
    let Some(mut remapped) = budget.reserve_vec(main_states) else {
        return Ok(None);
    };
    remapped.resize(main_states, u32::MAX);
    if !budget.charge(source.len()) {
        return Ok(None);
    }
    for (main_state, &anchored_state) in source.iter().enumerate() {
        if anchored_state == u32::MAX {
            continue;
        }
        let main_state = main_partition.map_or_else(
            || {
                u32::try_from(main_state).map_err(|_| {
                    CompileError::InternalInvariant(
                        "contextual quotient main mapping state exceeded u32",
                    )
                })
            },
            |partition| {
                partition.old_to_new.get(main_state).copied().ok_or(
                    CompileError::InternalInvariant(
                        "contextual quotient main mapping state is absent",
                    ),
                )
            },
        )?;
        let anchored_state = anchored_partition.map_or_else(
            || Ok(anchored_state),
            |partition| {
                partition
                    .old_to_new
                    .get(anchored_state as usize)
                    .copied()
                    .ok_or(CompileError::InternalInvariant(
                        "contextual quotient anchored mapping state is absent",
                    ))
            },
        )?;
        let slot = remapped
            .get_mut(main_state as usize)
            .ok_or(CompileError::InternalInvariant(
                "contextual quotient remapped main state is absent",
            ))?;
        if *slot != u32::MAX && *slot != anchored_state {
            return Ok(Some(AnchoredMappingRemap::Conflict {
                main_state,
                first_anchored_state: *slot,
                second_anchored_state: anchored_state,
            }));
        }
        *slot = anchored_state;
    }
    Ok(Some(AnchoredMappingRemap::Complete(remapped)))
}

fn late_context_quotient_with_work_limit(
    forward: &ForwardDfa,
    reverse: &ReverseDfa,
    anchored_forward: Option<&AnchoredForwardDfa>,
    width: usize,
    max_work: u64,
) -> Result<Option<ContextDfaQuotient>, CompileError> {
    let Some(total_states) = forward.states.len().checked_add(reverse.states.len()) else {
        return Ok(None);
    };
    let Some(total_transitions) = forward.cells.len().checked_add(reverse.cells.len()) else {
        return Ok(None);
    };
    if total_states > LATE_CONTEXT_QUOTIENT_MAX_STATES
        || total_transitions > LATE_CONTEXT_QUOTIENT_MAX_TRANSITIONS
    {
        return Ok(None);
    }

    let mut budget = LateQuotientBudget::new(max_work);
    let Some(mut no_external) = budget.reserve_vec(forward.states.len()) else {
        return Ok(None);
    };
    no_external.resize(forward.states.len(), 0_u32);
    let Some(main_partition) = forward_partition(forward, width, &no_external, &mut budget)? else {
        return Ok(None);
    };
    let Some(reverse_partition) = reverse_partition(reverse, width, &mut budget)? else {
        return Ok(None);
    };
    let forward_reduced = main_partition.representatives.len() < forward.states.len();
    let reverse_reduced = reverse_partition.representatives.len() < reverse.states.len();
    let forward = if forward_reduced {
        let Some(machine) = build_forward_quotient(forward, &main_partition, width, &mut budget)?
        else {
            return Ok(None);
        };
        Some(machine)
    } else {
        None
    };
    let reverse = if reverse_reduced {
        let Some(machine) =
            build_reverse_quotient(reverse, &reverse_partition, width, &mut budget)?
        else {
            return Ok(None);
        };
        Some(machine)
    } else {
        None
    };

    // The optional sidecar gets an independent budget and never participates
    // in mandatory partition refinement. If mandatory initial states merge,
    // its remapped state-index function must remain single-valued.
    let mut anchored_reduced = false;
    let anchored_update = if let Some(source) = anchored_forward {
        let mut anchored_budget = LateQuotientBudget::new(max_work);
        let anchored_partition = if source.forward.states.len() <= LATE_ANCHORED_QUOTIENT_MAX_STATES
            && source.forward.cells.len() <= LATE_ANCHORED_QUOTIENT_MAX_TRANSITIONS
        {
            let partition = if let Some(mut no_external) =
                anchored_budget.reserve_vec(source.forward.states.len())
            {
                no_external.resize(source.forward.states.len(), 0_u32);
                forward_partition(&source.forward, width, &no_external, &mut anchored_budget)?
            } else {
                None
            };
            partition
        } else {
            None
        };
        let mut replacement_forward = None;
        let selected_anchored_partition = if let Some(partition) = anchored_partition.as_ref() {
            if partition.representatives.len() < source.forward.states.len() {
                if let Some(machine) =
                    build_forward_quotient(&source.forward, partition, width, &mut anchored_budget)?
                {
                    replacement_forward = Some(machine);
                    Some(partition)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        // Mapping is linear in the already-bounded mandatory state arena. A
        // fresh fixed ceiling makes `None` below an allocation failure rather
        // than an ambiguous carry-over from optional refinement work.
        let mut mapping_budget = LateQuotientBudget::new(LATE_CONTEXT_QUOTIENT_MAX_WORK);
        let remapped = remap_anchored_initial_states(
            &source.main_initial_to_anchored,
            forward_reduced.then_some(&main_partition),
            selected_anchored_partition,
            &mut mapping_budget,
        )?;
        match remapped {
            Some(AnchoredMappingRemap::Complete(main_initial_to_anchored)) => {
                if let Some(forward_machine) = replacement_forward {
                    anchored_reduced = true;
                    AnchoredQuotientUpdate::Replace(AnchoredForwardDfa {
                        forward: forward_machine,
                        main_initial_to_anchored,
                        max_resolution_steps: source.max_resolution_steps,
                    })
                } else if forward_reduced {
                    AnchoredQuotientUpdate::Remap(main_initial_to_anchored)
                } else {
                    AnchoredQuotientUpdate::Preserve
                }
            }
            Some(AnchoredMappingRemap::Conflict {
                main_state,
                first_anchored_state,
                second_anchored_state,
            }) => AnchoredQuotientUpdate::Omit(ContextDfaResource::IncompatibleAnchoredQuotient {
                main_state,
                first_anchored_state,
                second_anchored_state,
            }),
            None if forward_reduced => {
                AnchoredQuotientUpdate::Omit(ContextDfaResource::Allocation {
                    requested_elements: main_partition.representatives.len(),
                    element_size: core::mem::size_of::<u32>(),
                })
            }
            None => AnchoredQuotientUpdate::Preserve,
        }
    } else {
        AnchoredQuotientUpdate::Preserve
    };
    if !forward_reduced && !reverse_reduced && !anchored_reduced {
        return Ok(None);
    }
    Ok(Some(ContextDfaQuotient {
        forward,
        reverse,
        anchored_update,
        semantic_quotient: forward_reduced || reverse_reduced || anchored_reduced,
    }))
}

fn late_context_quotient(
    forward: &ForwardDfa,
    reverse: &ReverseDfa,
    anchored_forward: Option<&AnchoredForwardDfa>,
    width: usize,
) -> Result<Option<ContextDfaQuotient>, CompileError> {
    late_context_quotient_with_work_limit(
        forward,
        reverse,
        anchored_forward,
        width,
        LATE_CONTEXT_QUOTIENT_MAX_WORK,
    )
}

/// Compact deterministic handoff consumed by contextual native lowering.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeContextDfaView<'a> {
    pub(crate) initial_dispatch: NativeContextInitialDispatch,
    pub(crate) byte_classes: &'a [u8; 256],
    pub(crate) class_representatives: &'a [u8],
    pub(crate) class_properties: &'a [u8],
    pub(crate) forward_initial: &'a [NativeContextForwardInitial],
    pub(crate) forward_states: &'a [NativeContextForwardState],
    pub(crate) forward_row_offsets: &'a [u32],
    pub(crate) forward_cells: &'a [NativeContextForwardCell],
    pub(crate) reverse_initial: &'a [NativeContextReverseInitial],
    pub(crate) reverse_row_offsets: &'a [u32],
    pub(crate) reverse_cells: &'a [NativeContextReverseCell],
    pub(crate) anchored_forward: Option<NativeContextAnchoredForwardView<'a>>,
}

/// Compact target-neutral handoff for the optional exact-start verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeContextAnchoredForwardView<'a> {
    /// Search-forward state to anchored-forward state. `u32::MAX` denotes a
    /// search state that is not an initial boundary state.
    pub(crate) main_initial_to_anchored: &'a [u32],
    pub(crate) states: &'a [NativeContextForwardState],
    pub(crate) row_offsets: &'a [u32],
    pub(crate) cells: &'a [NativeContextForwardCell],
    pub(crate) max_resolution_steps: Option<u32>,
}

/// A complete graph-derived contextual machine.
#[derive(Clone, Debug)]
pub(crate) struct ContextDfa {
    alphabet: Alphabet,
    initial_dispatch: NativeContextInitialDispatch,
    forward: ForwardDfa,
    reverse: ReverseDfa,
    anchored_forward: Option<AnchoredForwardDfa>,
    /// Representatives of a late semantic quotient need not retain the exact
    /// byte-boundary key of every merged state. Native flags and transition
    /// observations remain exact; this only disables portable debug checks
    /// that compare a representative's incidental key to the current byte.
    semantic_quotient: bool,
    stats: ContextDfaStats,
}

impl ForwardDfa {
    fn cell(&self, state: u32, symbol: usize) -> Option<NativeContextForwardCell> {
        let state = usize::try_from(state).ok()?;
        let begin = usize::try_from(*self.row_offsets.get(state)?).ok()?;
        let end = usize::try_from(*self.row_offsets.get(state.checked_add(1)?)?).ok()?;
        self.cells.get(begin..end)?.get(symbol).copied()
    }
}

impl ReverseDfa {
    fn cell(&self, state: u32, symbol: usize) -> Option<NativeContextReverseCell> {
        let state = usize::try_from(state).ok()?;
        let begin = usize::try_from(*self.row_offsets.get(state)?).ok()?;
        let end = usize::try_from(*self.row_offsets.get(state.checked_add(1)?)?).ok()?;
        self.cells.get(begin..end)?.get(symbol).copied()
    }
}

impl ContextDfa {
    pub(crate) const fn stats(&self) -> ContextDfaStats {
        self.stats
    }

    pub(crate) fn native_view(&self) -> NativeContextDfaView<'_> {
        NativeContextDfaView {
            initial_dispatch: self.initial_dispatch,
            byte_classes: &self.alphabet.byte_to_class,
            class_representatives: &self.alphabet.representatives,
            class_properties: &self.alphabet.properties,
            forward_initial: &self.forward.canonical_initial,
            forward_states: &self.forward.native_states,
            forward_row_offsets: &self.forward.row_offsets,
            forward_cells: &self.forward.cells,
            reverse_initial: &self.reverse.canonical_initial,
            reverse_row_offsets: &self.reverse.row_offsets,
            reverse_cells: &self.reverse.cells,
            anchored_forward: self.anchored_forward.as_ref().map(|anchored| {
                NativeContextAnchoredForwardView {
                    main_initial_to_anchored: &anchored.main_initial_to_anchored,
                    states: &anchored.forward.native_states,
                    row_offsets: &anchored.forward.row_offsets,
                    cells: &anchored.forward.cells,
                    max_resolution_steps: anchored.max_resolution_steps,
                }
            }),
        }
    }

    /// Execute one output contract while assertions inspect the original
    /// haystack rather than a window slice.
    pub(crate) fn search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        output: OutputContract,
    ) -> Result<MatchResult, CompileError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(CompileError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let earliest = output == OutputContract::Exists;
        let selected = self.selected_end(haystack, window, earliest)?;
        match output {
            OutputContract::Exists => Ok(MatchResult::Exists(selected.end.is_some())),
            OutputContract::SelectedEnd => Ok(MatchResult::SelectedEnd(selected.end)),
            OutputContract::Span => {
                let span = match selected.end {
                    None => None,
                    Some(end) if selected.initial_pending => Some((window.start(), end)),
                    Some(end) => Some((
                        self.recover_start(haystack, window.start(), end)?.ok_or(
                            CompileError::InternalInvariant(
                                "contextual reverse DFA could not recover a selected match",
                            ),
                        )?,
                        end,
                    )),
                };
                Ok(MatchResult::Span(span))
            }
        }
    }

    fn selected_end(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        earliest: bool,
    ) -> Result<ForwardSelection, CompileError> {
        let observation = self.alphabet.observe(haystack, window.start())?;
        let boundary = ForwardBoundary::from_observation(observation, &self.alphabet)?;
        let mut state =
            *self
                .forward
                .initial
                .get(&boundary)
                .ok_or(CompileError::InternalInvariant(
                    "contextual forward initial boundary is absent",
                ))?;
        let initial = self.forward_state(state)?;
        let initial_pending = initial.pending;
        let mut pending_end = initial_pending.then_some(window.start());
        if initial_pending && (earliest || initial.items.is_empty()) {
            return Ok(ForwardSelection {
                end: pending_end,
                initial_pending,
            });
        }

        let mut position = window.start();
        while position < window.end() {
            let key = self.forward_state(state)?;
            if key.pending && key.items.is_empty() {
                break;
            }
            let current = *haystack
                .get(position)
                .ok_or(CompileError::InternalInvariant(
                    "contextual forward source exceeded the validated window",
                ))?;
            if !self.semantic_quotient
                && key.boundary.current != CurrentClass::Byte(self.alphabet.class(current))
            {
                return Err(CompileError::InternalInvariant(
                    "contextual forward state has the wrong current byte class",
                ));
            }
            let destination = position
                .checked_add(1)
                .ok_or(CompileError::InternalInvariant(
                    "contextual forward position overflowed",
                ))?;
            let symbol = haystack
                .get(destination)
                .copied()
                .map_or(self.alphabet.classes(), |byte| {
                    usize::from(self.alphabet.class(byte))
                });
            let cell = self
                .forward
                .cell(state, symbol)
                .ok_or(CompileError::InternalInvariant(
                    "contextual forward transition is absent",
                ))?;
            position = destination;
            if cell.accepted {
                pending_end = Some(position);
                if earliest {
                    return Ok(ForwardSelection {
                        end: pending_end,
                        initial_pending,
                    });
                }
            }
            state = cell.next;
        }
        Ok(ForwardSelection {
            end: pending_end,
            initial_pending,
        })
    }

    /// Select the exact ordered end for a match required to start at
    /// `candidate`. No later graph start is injected while this model runs.
    ///
    /// This is retained for semantic and native-lowering validation. Runtime
    /// code may bound an attempt and fall back to the complete search DFA, but
    /// every completed sidecar result has these exact semantics.
    fn anchored_selected_end(
        &self,
        haystack: &[u8],
        candidate: usize,
        window_end: usize,
    ) -> Result<Option<usize>, CompileError> {
        if candidate > window_end || window_end > haystack.len() {
            return Err(CompileError::InvalidWindow {
                start: candidate,
                end: window_end,
                haystack_len: haystack.len(),
            });
        }
        let anchored = self
            .anchored_forward
            .as_ref()
            .ok_or(CompileError::InternalInvariant(
                "contextual anchored forward sidecar is absent",
            ))?;
        let observation = self.alphabet.observe(haystack, candidate)?;
        let boundary = ForwardBoundary::from_observation(observation, &self.alphabet)?;
        let main_state =
            *self
                .forward
                .initial
                .get(&boundary)
                .ok_or(CompileError::InternalInvariant(
                    "contextual search initial boundary is absent",
                ))?;
        let main_index = usize::try_from(main_state).map_err(|_| {
            CompileError::InternalInvariant("contextual search initial state exceeded usize")
        })?;
        let mut state = *anchored
            .main_initial_to_anchored
            .get(main_index)
            .filter(|&&state| state != u32::MAX)
            .ok_or(CompileError::InternalInvariant(
                "contextual anchored initial-state mapping is absent",
            ))?;
        if anchored.forward.initial.get(&boundary) != Some(&state) {
            return Err(CompileError::InternalInvariant(
                "contextual anchored initial-state mapping disagrees with its boundary",
            ));
        }

        let initial = anchored
            .forward
            .states
            .get(usize::try_from(state).map_err(|_| {
                CompileError::InternalInvariant("contextual anchored state exceeded usize")
            })?)
            .ok_or(CompileError::InternalInvariant(
                "contextual anchored initial state is absent",
            ))?;
        let mut pending_end = initial.pending.then_some(candidate);
        if initial.pending && initial.items.is_empty() {
            return Ok(pending_end);
        }

        let mut position = candidate;
        while position < window_end {
            let key = anchored
                .forward
                .states
                .get(usize::try_from(state).map_err(|_| {
                    CompileError::InternalInvariant("contextual anchored state exceeded usize")
                })?)
                .ok_or(CompileError::InternalInvariant(
                    "contextual anchored state is absent",
                ))?;
            if key.items.is_empty() {
                break;
            }
            let current = *haystack
                .get(position)
                .ok_or(CompileError::InternalInvariant(
                    "contextual anchored source exceeded the validated window",
                ))?;
            if !self.semantic_quotient
                && key.boundary.current != CurrentClass::Byte(self.alphabet.class(current))
            {
                return Err(CompileError::InternalInvariant(
                    "contextual anchored state has the wrong current byte class",
                ));
            }
            let destination = position
                .checked_add(1)
                .ok_or(CompileError::InternalInvariant(
                    "contextual anchored position overflowed",
                ))?;
            let symbol = haystack
                .get(destination)
                .copied()
                .map_or(self.alphabet.classes(), |byte| {
                    usize::from(self.alphabet.class(byte))
                });
            let cell =
                anchored
                    .forward
                    .cell(state, symbol)
                    .ok_or(CompileError::InternalInvariant(
                        "contextual anchored transition is absent",
                    ))?;
            position = destination;
            if cell.accepted {
                pending_end = Some(position);
            }
            state = cell.next;
        }
        Ok(pending_end)
    }

    fn recover_start(
        &self,
        haystack: &[u8],
        window_start: usize,
        selected_end: usize,
    ) -> Result<Option<usize>, CompileError> {
        let observation = self.alphabet.observe(haystack, selected_end)?;
        let boundary = ReverseBoundary::from_observation(observation, &self.alphabet)?;
        let initial =
            *self
                .reverse
                .initial
                .get(&boundary)
                .ok_or(CompileError::InternalInvariant(
                    "contextual reverse initial boundary is absent",
                ))?;
        let mut candidate = initial.reaches_start.then_some(selected_end);
        let mut state = initial.state;
        let mut cursor = selected_end;
        while cursor > window_start {
            let Some(current_state) = state else {
                break;
            };
            let source = cursor
                .checked_sub(1)
                .ok_or(CompileError::InternalInvariant(
                    "contextual reverse cursor underflowed",
                ))?;
            let key = self.reverse_state(current_state)?;
            let byte = *haystack.get(source).ok_or(CompileError::InternalInvariant(
                "contextual reverse source exceeded the haystack",
            ))?;
            if !self.semantic_quotient && key.boundary.before != Some(self.alphabet.class(byte)) {
                return Err(CompileError::InternalInvariant(
                    "contextual reverse state has the wrong preceding byte class",
                ));
            }
            let source_boundary = self.alphabet.observe(haystack, source)?;
            let symbol = source_boundary
                .before_byte_class
                .map_or(self.alphabet.classes(), usize::from);
            let cell =
                self.reverse
                    .cell(current_state, symbol)
                    .ok_or(CompileError::InternalInvariant(
                        "contextual reverse transition is absent",
                    ))?;
            cursor = source;
            if cell.reaches_start {
                candidate = Some(cursor);
            }
            state = (cell.next != u32::MAX).then_some(cell.next);
        }
        Ok(candidate)
    }

    fn forward_state(&self, state: u32) -> Result<&ForwardKey, CompileError> {
        self.forward
            .states
            .get(usize::try_from(state).map_err(|_| {
                CompileError::InternalInvariant("contextual forward state exceeded usize")
            })?)
            .ok_or(CompileError::InternalInvariant(
                "contextual forward state is absent",
            ))
    }

    fn reverse_state(&self, state: u32) -> Result<&ReverseKey, CompileError> {
        self.reverse
            .states
            .get(usize::try_from(state).map_err(|_| {
                CompileError::InternalInvariant("contextual reverse state exceeded usize")
            })?)
            .ok_or(CompileError::InternalInvariant(
                "contextual reverse state is absent",
            ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ForwardSelection {
    end: Option<usize>,
    initial_pending: bool,
}

/// Eagerly construct both contextual directions under one explicit budget.
pub(crate) fn determinize(
    raw: &RawPlan,
    line_terminator: u8,
    limits: ContextDfaLimits,
) -> Result<ContextDfaOutcome, CompileError> {
    determinize_with_anchored_limits(
        raw,
        line_terminator,
        limits,
        AnchoredForwardLimits::default(),
    )
}

fn determinize_with_anchored_limits(
    raw: &RawPlan,
    line_terminator: u8,
    limits: ContextDfaLimits,
    anchored_limits: AnchoredForwardLimits,
) -> Result<ContextDfaOutcome, CompileError> {
    let needs = match ContextNeeds::inspect(raw) {
        Ok(needs) => needs,
        Err(kind) => {
            return Ok(ContextDfaOutcome::Declined(ContextDfaDecline {
                resource: ContextDfaResource::UnsupportedAssertion(kind),
                work_completed: 0,
                states_completed: 0,
                transitions_completed: 0,
            }));
        }
    };
    let mut budget = BuildBudget::new(limits);
    let Some(alphabet) = Alphabet::build(raw, line_terminator, needs, &mut budget)? else {
        return Ok(ContextDfaOutcome::Declined(budget.finish_decline()?));
    };
    let Some(mut forward) = build_forward(raw, &alphabet, &mut budget)? else {
        return Ok(ContextDfaOutcome::Declined(budget.finish_decline()?));
    };
    let Some(mut reverse) = build_reverse(raw, &alphabet, &mut budget)? else {
        return Ok(ContextDfaOutcome::Declined(budget.finish_decline()?));
    };
    let initial_dispatch = NativeContextInitialDispatch::new(alphabet.classes())?;
    let mut anchored = build_anchored_forward(raw, &alphabet, &forward, anchored_limits)?;
    let row_width = alphabet
        .classes()
        .checked_add(1)
        .ok_or(CompileError::InternalInvariant(
            "contextual quotient row width overflowed",
        ))?;
    let mut semantic_quotient = false;
    if let Some(quotient) =
        late_context_quotient(&forward, &reverse, anchored.machine.as_ref(), row_width)?
    {
        if let Some(machine) = quotient.forward {
            forward = machine;
        }
        if let Some(machine) = quotient.reverse {
            reverse = machine;
        }
        match quotient.anchored_update {
            AnchoredQuotientUpdate::Preserve => {}
            AnchoredQuotientUpdate::Remap(mapping) => {
                let machine = anchored
                    .machine
                    .as_mut()
                    .ok_or(CompileError::InternalInvariant(
                        "contextual anchored remap has no source machine",
                    ))?;
                machine.main_initial_to_anchored = mapping;
            }
            AnchoredQuotientUpdate::Replace(machine) => anchored.machine = Some(machine),
            AnchoredQuotientUpdate::Omit(resource) => {
                anchored.machine = None;
                anchored.decline = Some(ContextDfaDecline {
                    resource,
                    work_completed: anchored.build_work,
                    states_completed: anchored.construction_states,
                    transitions_completed: anchored.construction_transitions,
                });
            }
        }
        semantic_quotient = quotient.semantic_quotient;
        if let Some(machine) = anchored.machine.as_ref() {
            validate_anchored_initial_mapping(
                &forward,
                &machine.forward,
                &machine.main_initial_to_anchored,
                false,
            )?;
        }
    }
    let (
        anchored_forward_present,
        anchored_forward_initial_contexts,
        anchored_forward_states,
        anchored_forward_transitions,
        anchored_forward_max_resolution_steps,
    ) = anchored
        .machine
        .as_ref()
        .map_or((false, 0, 0, 0, None), |machine| {
            (
                true,
                machine.forward.canonical_initial.len(),
                machine.forward.states.len(),
                machine.forward.cells.len(),
                machine.max_resolution_steps,
            )
        });
    let build_work =
        budget
            .work
            .checked_add(anchored.build_work)
            .ok_or(CompileError::InternalInvariant(
                "contextual aggregate build work overflowed",
            ))?;
    let stats = ContextDfaStats {
        alphabet_classes: alphabet.classes(),
        row_width: alphabet
            .classes()
            .checked_add(1)
            .ok_or(CompileError::InternalInvariant(
                "contextual stats row width overflowed",
            ))?,
        forward_initial_contexts: forward.canonical_initial.len(),
        forward_states: forward.states.len(),
        forward_transitions: forward.cells.len(),
        reverse_initial_contexts: reverse.canonical_initial.len(),
        reverse_states: reverse.states.len(),
        reverse_transitions: reverse.cells.len(),
        anchored_forward_present,
        anchored_forward_initial_contexts,
        anchored_forward_states,
        anchored_forward_transitions,
        anchored_forward_construction_states: anchored.construction_states,
        anchored_forward_construction_transitions: anchored.construction_transitions,
        anchored_forward_max_resolution_steps,
        anchored_forward_build_work: anchored.build_work,
        anchored_forward_decline: anchored.decline,
        build_work,
    };
    Ok(ContextDfaOutcome::Complete(ContextDfa {
        alphabet,
        initial_dispatch,
        forward,
        reverse,
        anchored_forward: anchored.machine,
        semantic_quotient,
        stats,
    }))
}

struct ForwardClosure {
    seen: Vec<bool>,
    stack: Vec<u32>,
    items: Vec<u32>,
}

impl ForwardClosure {
    fn new(raw: &RawPlan, budget: &mut BuildBudget) -> Result<Option<Self>, CompileError> {
        let Some(mut seen) = reserve_vec(raw.roles.len(), budget)? else {
            return Ok(None);
        };
        seen.resize(raw.roles.len(), false);
        let stack_capacity =
            raw.edge_targets
                .len()
                .checked_add(1)
                .ok_or(CompileError::InternalInvariant(
                    "contextual forward stack capacity overflowed",
                ))?;
        let Some(stack) = reserve_vec(stack_capacity, budget)? else {
            return Ok(None);
        };
        let Some(items) = reserve_vec(raw.roles.len(), budget)? else {
            return Ok(None);
        };
        Ok(Some(Self { seen, stack, items }))
    }

    fn begin(&mut self) {
        self.seen.fill(false);
        self.stack.clear();
        self.items.clear();
    }

    fn expand(
        &mut self,
        raw: &RawPlan,
        root: u32,
        context: AssertionContext,
        budget: &mut BuildBudget,
    ) -> Result<bool, CompileError> {
        self.stack.clear();
        self.stack.push(root);
        while let Some(state) = self.stack.pop() {
            if !budget.charge(1) {
                return Ok(false);
            }
            let index = plan_index(state, raw.roles.len(), "contextual forward closure")?;
            if self.seen[index] {
                continue;
            }
            self.seen[index] = true;
            match raw.roles[index] {
                StateRole::Accept => return Ok(true),
                StateRole::Consume => self.items.push(state),
                StateRole::Split => {
                    for edge in state_edges(raw, state)?.rev() {
                        if !budget.charge(1) {
                            return Ok(false);
                        }
                        if context.enabled(raw.edge_kinds[edge])? {
                            self.stack.push(raw.edge_targets[edge]);
                        }
                    }
                }
                _ => {
                    return Err(CompileError::InternalInvariant(
                        "contextual forward closure reached an unknown state role",
                    ));
                }
            }
        }
        Ok(false)
    }

    fn copy_items(&self, budget: &mut BuildBudget) -> Result<Option<Vec<u32>>, CompileError> {
        clone_u32s(&self.items, budget)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "seeding and completing the deterministic forward worklist remain one audited transaction"
)]
fn build_forward(
    raw: &RawPlan,
    alphabet: &Alphabet,
    budget: &mut BuildBudget,
) -> Result<Option<ForwardDfa>, CompileError> {
    let Some(mut closure) = ForwardClosure::new(raw, budget)? else {
        return Ok(None);
    };
    let Some(mut states) = reserve_vec(1, budget)? else {
        return Ok(None);
    };
    let Some(mut rows) = reserve_vec(1, budget)? else {
        return Ok(None);
    };
    let Some(mut interned) = reserve_map(1, budget)? else {
        return Ok(None);
    };
    let Some(mut initial) = reserve_map(1, budget)? else {
        return Ok(None);
    };

    let mut property_seen = [false; 16];
    let Some(mut property_classes) = reserve_vec(16, budget)? else {
        return Ok(None);
    };
    for &properties in &alphabet.properties {
        let index = usize::from(properties);
        if !property_seen[index] {
            property_seen[index] = true;
            property_classes.push(properties);
        }
    }

    let empty = ForwardBoundary {
        before_present: false,
        before_properties: 0,
        current: CurrentClass::HaystackEnd,
        absolute_start: true,
        absolute_end: true,
    };
    if seed_forward_initial(
        raw,
        alphabet,
        empty,
        &mut closure,
        &mut states,
        &mut rows,
        &mut interned,
        &mut initial,
        budget,
    )?
    .is_none()
    {
        return Ok(None);
    }
    for class in 0..alphabet.classes() {
        let class = u8::try_from(class)
            .map_err(|_| CompileError::InternalInvariant("contextual forward class exceeded u8"))?;
        let start = ForwardBoundary {
            before_present: false,
            before_properties: 0,
            current: CurrentClass::Byte(class),
            absolute_start: true,
            absolute_end: false,
        };
        if seed_forward_initial(
            raw,
            alphabet,
            start,
            &mut closure,
            &mut states,
            &mut rows,
            &mut interned,
            &mut initial,
            budget,
        )?
        .is_none()
        {
            return Ok(None);
        }
    }
    for &before_properties in &property_classes {
        for class in 0..alphabet.classes() {
            let class = u8::try_from(class).map_err(|_| {
                CompileError::InternalInvariant("contextual forward class exceeded u8")
            })?;
            let interior = ForwardBoundary {
                before_present: true,
                before_properties,
                current: CurrentClass::Byte(class),
                absolute_start: false,
                absolute_end: false,
            };
            if seed_forward_initial(
                raw,
                alphabet,
                interior,
                &mut closure,
                &mut states,
                &mut rows,
                &mut interned,
                &mut initial,
                budget,
            )?
            .is_none()
            {
                return Ok(None);
            }
        }
        let end = ForwardBoundary {
            before_present: true,
            before_properties,
            current: CurrentClass::HaystackEnd,
            absolute_start: false,
            absolute_end: true,
        };
        if seed_forward_initial(
            raw,
            alphabet,
            end,
            &mut closure,
            &mut states,
            &mut rows,
            &mut interned,
            &mut initial,
            budget,
        )?
        .is_none()
        {
            return Ok(None);
        }
    }

    let width = alphabet
        .classes()
        .checked_add(1)
        .ok_or(CompileError::InternalInvariant(
            "contextual forward row width overflowed",
        ))?;
    let mut cursor = 0_usize;
    while cursor < states.len() {
        let Some(key) = clone_forward_key(&states[cursor], budget)? else {
            return Ok(None);
        };
        if key.items.is_empty() && key.pending || key.boundary.current == CurrentClass::HaystackEnd
        {
            cursor = cursor
                .checked_add(1)
                .ok_or(CompileError::InternalInvariant(
                    "contextual forward worklist overflowed",
                ))?;
            continue;
        }
        if !budget.reserve_transitions(width) {
            return Ok(None);
        }
        let Some(mut row) = reserve_vec(width, budget)? else {
            return Ok(None);
        };
        let CurrentClass::Byte(current_class) = key.boundary.current else {
            return Err(CompileError::InternalInvariant(
                "contextual forward row has no current byte",
            ));
        };
        let byte = alphabet.representative(current_class)?;
        let before_properties = alphabet.properties(current_class)?;
        for symbol in 0..width {
            let current = if symbol == alphabet.classes() {
                CurrentClass::HaystackEnd
            } else {
                CurrentClass::Byte(u8::try_from(symbol).map_err(|_| {
                    CompileError::InternalInvariant("contextual forward symbol exceeded u8")
                })?)
            };
            let boundary = ForwardBoundary {
                before_present: true,
                before_properties,
                current,
                absolute_start: false,
                absolute_end: current == CurrentClass::HaystackEnd,
            };
            let Some(cell) = build_forward_cell(
                raw,
                alphabet,
                ForwardMode::Search,
                &key,
                byte,
                boundary,
                &mut closure,
                &mut states,
                &mut rows,
                &mut interned,
                budget,
            )?
            else {
                return Ok(None);
            };
            row.push(cell);
        }
        *rows.get_mut(cursor).ok_or(CompileError::InternalInvariant(
            "contextual forward worklist row is absent",
        ))? = row;
        cursor = cursor
            .checked_add(1)
            .ok_or(CompileError::InternalInvariant(
                "contextual forward worklist overflowed",
            ))?;
    }
    let Some((canonical_initial, native_states, row_offsets, cells)) =
        finalize_forward_tables(&initial, &states, &rows, alphabet.classes(), budget)?
    else {
        return Ok(None);
    };
    Ok(Some(ForwardDfa {
        initial,
        canonical_initial,
        states,
        native_states,
        row_offsets,
        cells,
    }))
}

/// Build the optional exact-start machine under a budget wholly independent
/// of the complete contextual search machine.
///
/// Limit and allocation failures are transactional: no partial table is
/// published and the already-complete search/reverse pair remains valid.
fn build_anchored_forward(
    raw: &RawPlan,
    alphabet: &Alphabet,
    main: &ForwardDfa,
    limits: AnchoredForwardLimits,
) -> Result<AnchoredForwardBuild, CompileError> {
    let mut budget = BuildBudget::new(limits.into());
    let built = build_anchored_forward_with_budget(raw, alphabet, main, &mut budget)?;
    match built {
        Some(machine) => Ok(AnchoredForwardBuild::completed(machine, budget)),
        None => AnchoredForwardBuild::declined(budget),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "exact initial-key cloning and restart-free worklist completion form one transactional sidecar build"
)]
fn build_anchored_forward_with_budget(
    raw: &RawPlan,
    alphabet: &Alphabet,
    main: &ForwardDfa,
    budget: &mut BuildBudget,
) -> Result<Option<AnchoredForwardDfa>, CompileError> {
    let Some(mut closure) = ForwardClosure::new(raw, budget)? else {
        return Ok(None);
    };
    let Some(mut states) = reserve_vec(1, budget)? else {
        return Ok(None);
    };
    let Some(mut rows) = reserve_vec(1, budget)? else {
        return Ok(None);
    };
    let Some(mut interned) = reserve_map(1, budget)? else {
        return Ok(None);
    };
    let Some(mut initial) = reserve_map(main.initial.len(), budget)? else {
        return Ok(None);
    };
    let Some(mut ordered_initial) = reserve_vec(main.initial.len(), budget)? else {
        return Ok(None);
    };
    for (&boundary, &state) in &main.initial {
        if !budget.charge(1) {
            return Ok(None);
        }
        ordered_initial.push((
            boundary.native_context(alphabet.classes())?,
            boundary,
            state,
        ));
    }
    ordered_initial.sort_unstable_by_key(|&(context, _, _)| context);
    if ordered_initial
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0)
    {
        return Err(CompileError::InternalInvariant(
            "contextual anchored initial contexts are not unique",
        ));
    }

    let Some(mut main_initial_to_anchored) = reserve_vec(main.states.len(), budget)? else {
        return Ok(None);
    };
    main_initial_to_anchored.resize(main.states.len(), u32::MAX);
    for (_, boundary, main_state) in ordered_initial {
        let main_index = usize::try_from(main_state).map_err(|_| {
            CompileError::InternalInvariant("contextual search initial state exceeded usize")
        })?;
        let main_key = main
            .states
            .get(main_index)
            .ok_or(CompileError::InternalInvariant(
                "contextual search initial state is absent",
            ))?;
        if main_key.boundary != boundary {
            return Err(CompileError::InternalInvariant(
                "contextual search initial state has the wrong boundary",
            ));
        }
        let Some(key) = clone_forward_key(main_key, budget)? else {
            return Ok(None);
        };
        let Some(anchored_state) =
            intern_forward(key, &mut states, &mut rows, &mut interned, budget)?
        else {
            return Ok(None);
        };
        let mapped =
            main_initial_to_anchored
                .get_mut(main_index)
                .ok_or(CompileError::InternalInvariant(
                    "contextual anchored mapping index is absent",
                ))?;
        if *mapped != u32::MAX {
            return Err(CompileError::InternalInvariant(
                "contextual search initial state has multiple boundaries",
            ));
        }
        *mapped = anchored_state;
        if initial.try_reserve(1).is_err() {
            budget.allocation::<(ForwardBoundary, u32)>(initial.len().saturating_add(1));
            return Ok(None);
        }
        if initial.insert(boundary, anchored_state).is_some() {
            return Err(CompileError::InternalInvariant(
                "duplicate contextual anchored initial boundary",
            ));
        }
    }

    let width = alphabet
        .classes()
        .checked_add(1)
        .ok_or(CompileError::InternalInvariant(
            "contextual anchored row width overflowed",
        ))?;
    let mut cursor = 0_usize;
    while cursor < states.len() {
        let Some(key) = clone_forward_key(&states[cursor], budget)? else {
            return Ok(None);
        };
        if key.items.is_empty() || key.boundary.current == CurrentClass::HaystackEnd {
            cursor = cursor
                .checked_add(1)
                .ok_or(CompileError::InternalInvariant(
                    "contextual anchored worklist overflowed",
                ))?;
            continue;
        }
        if !budget.reserve_transitions(width) {
            return Ok(None);
        }
        let Some(mut row) = reserve_vec(width, budget)? else {
            return Ok(None);
        };
        let CurrentClass::Byte(current_class) = key.boundary.current else {
            return Err(CompileError::InternalInvariant(
                "contextual anchored row has no current byte",
            ));
        };
        let byte = alphabet.representative(current_class)?;
        let before_properties = alphabet.properties(current_class)?;
        for symbol in 0..width {
            let current = if symbol == alphabet.classes() {
                CurrentClass::HaystackEnd
            } else {
                CurrentClass::Byte(u8::try_from(symbol).map_err(|_| {
                    CompileError::InternalInvariant("contextual anchored symbol exceeded u8")
                })?)
            };
            let boundary = ForwardBoundary {
                before_present: true,
                before_properties,
                current,
                absolute_start: false,
                absolute_end: current == CurrentClass::HaystackEnd,
            };
            let Some(cell) = build_forward_cell(
                raw,
                alphabet,
                ForwardMode::Anchored,
                &key,
                byte,
                boundary,
                &mut closure,
                &mut states,
                &mut rows,
                &mut interned,
                budget,
            )?
            else {
                return Ok(None);
            };
            row.push(cell);
        }
        *rows.get_mut(cursor).ok_or(CompileError::InternalInvariant(
            "contextual anchored worklist row is absent",
        ))? = row;
        cursor = cursor
            .checked_add(1)
            .ok_or(CompileError::InternalInvariant(
                "contextual anchored worklist overflowed",
            ))?;
    }

    let Some((canonical_initial, native_states, row_offsets, cells)) =
        finalize_forward_tables(&initial, &states, &rows, alphabet.classes(), budget)?
    else {
        return Ok(None);
    };
    let forward = ForwardDfa {
        initial,
        canonical_initial,
        states,
        native_states,
        row_offsets,
        cells,
    };
    validate_anchored_initial_mapping(main, &forward, &main_initial_to_anchored, true)?;
    let max_resolution_steps =
        match anchored_resolution_horizon(&forward, alphabet.classes(), budget)? {
            AnchoredHorizonOutcome::Complete(steps) => steps,
            AnchoredHorizonOutcome::Declined => return Ok(None),
        };
    Ok(Some(AnchoredForwardDfa {
        forward,
        main_initial_to_anchored,
        max_resolution_steps,
    }))
}

fn validate_anchored_initial_mapping(
    main: &ForwardDfa,
    anchored: &ForwardDfa,
    mapping: &[u32],
    require_equal_keys: bool,
) -> Result<(), CompileError> {
    if mapping.len() != main.states.len() || anchored.initial.len() != main.initial.len() {
        return Err(CompileError::InternalInvariant(
            "contextual anchored initial mapping has the wrong dimensions",
        ));
    }
    for (&boundary, &main_state) in &main.initial {
        let main_index = usize::try_from(main_state).map_err(|_| {
            CompileError::InternalInvariant("contextual search initial state exceeded usize")
        })?;
        let anchored_state = *mapping
            .get(main_index)
            .filter(|&&state| state != u32::MAX)
            .ok_or(CompileError::InternalInvariant(
                "contextual anchored initial mapping is absent",
            ))?;
        if anchored.initial.get(&boundary) != Some(&anchored_state) {
            return Err(CompileError::InternalInvariant(
                "contextual anchored initial dispatch disagrees with its mapping",
            ));
        }
        let main_key = main
            .states
            .get(main_index)
            .ok_or(CompileError::InternalInvariant(
                "contextual search initial state is absent",
            ))?;
        let anchored_key = anchored
            .states
            .get(usize::try_from(anchored_state).map_err(|_| {
                CompileError::InternalInvariant("contextual anchored state exceeded usize")
            })?)
            .ok_or(CompileError::InternalInvariant(
                "contextual anchored initial state is absent",
            ))?;
        if require_equal_keys && main_key != anchored_key {
            return Err(CompileError::InternalInvariant(
                "contextual anchored initial key differs from search initial key",
            ));
        }
    }
    Ok(())
}

enum AnchoredHorizonOutcome {
    Complete(Option<u32>),
    Declined,
}

/// Return the maximum number of byte transitions until every reachable path
/// resolves, or `None` when a live cycle exists. Resolved padded self-loops are
/// deliberately excluded from the graph.
///
/// Every scratch reservation, initialization, state scan, and transition scan
/// is charged to the optional sidecar budget. Exhaustion returns `Declined` so
/// the caller transactionally omits the whole sidecar instead of publishing a
/// machine with an analysis that escaped its construction ceiling.
fn anchored_resolution_horizon(
    forward: &ForwardDfa,
    class_count: usize,
    budget: &mut BuildBudget,
) -> Result<AnchoredHorizonOutcome, CompileError> {
    let state_count = forward.states.len();
    let width = class_count
        .checked_add(1)
        .ok_or(CompileError::InternalInvariant(
            "contextual anchored horizon row width overflowed",
        ))?;
    let Some(mut reachable) = reserve_horizon_vec(state_count, budget)? else {
        return Ok(AnchoredHorizonOutcome::Declined);
    };
    if !budget.charge_usize(state_count) {
        return Ok(AnchoredHorizonOutcome::Declined);
    }
    reachable.resize(state_count, false);
    let Some(mut stack) = reserve_horizon_vec(state_count, budget)? else {
        return Ok(AnchoredHorizonOutcome::Declined);
    };
    if !budget.charge_usize(forward.initial.len()) {
        return Ok(AnchoredHorizonOutcome::Declined);
    }
    for &state in forward.initial.values() {
        let index = usize::try_from(state).map_err(|_| {
            CompileError::InternalInvariant("contextual anchored initial state exceeded usize")
        })?;
        let key = forward
            .states
            .get(index)
            .ok_or(CompileError::InternalInvariant(
                "contextual anchored initial state is absent",
            ))?;
        if is_live_anchored_state(key) && !reachable[index] {
            reachable[index] = true;
            stack.push(index);
        }
    }
    while let Some(state) = stack.pop() {
        if !budget.charge(1) {
            return Ok(AnchoredHorizonOutcome::Declined);
        }
        let row = anchored_row(forward, state, width)?;
        if !budget.charge_usize(row.len()) {
            return Ok(AnchoredHorizonOutcome::Declined);
        }
        for cell in row {
            let destination = usize::try_from(cell.next).map_err(|_| {
                CompileError::InternalInvariant("contextual anchored destination exceeded usize")
            })?;
            let key = forward
                .states
                .get(destination)
                .ok_or(CompileError::InternalInvariant(
                    "contextual anchored destination is absent",
                ))?;
            if is_live_anchored_state(key) && !reachable[destination] {
                reachable[destination] = true;
                stack.push(destination);
            }
        }
    }

    let Some(mut indegree) = reserve_horizon_vec(state_count, budget)? else {
        return Ok(AnchoredHorizonOutcome::Declined);
    };
    if !budget.charge_usize(state_count) {
        return Ok(AnchoredHorizonOutcome::Declined);
    }
    indegree.resize(state_count, 0_usize);
    if !budget.charge_usize(state_count) {
        return Ok(AnchoredHorizonOutcome::Declined);
    }
    let reachable_count = reachable.iter().filter(|&&value| value).count();
    if !budget.charge_usize(state_count) {
        return Ok(AnchoredHorizonOutcome::Declined);
    }
    for state in 0..state_count {
        if !reachable[state] {
            continue;
        }
        let row = anchored_row(forward, state, width)?;
        if !budget.charge_usize(row.len()) {
            return Ok(AnchoredHorizonOutcome::Declined);
        }
        for cell in row {
            let destination = usize::try_from(cell.next).map_err(|_| {
                CompileError::InternalInvariant("contextual anchored destination exceeded usize")
            })?;
            if *reachable
                .get(destination)
                .ok_or(CompileError::InternalInvariant(
                    "contextual anchored destination is absent",
                ))?
            {
                indegree[destination] =
                    indegree[destination]
                        .checked_add(1)
                        .ok_or(CompileError::InternalInvariant(
                            "contextual anchored indegree overflowed",
                        ))?;
            }
        }
    }

    let Some(mut order) = reserve_horizon_vec(reachable_count, budget)? else {
        return Ok(AnchoredHorizonOutcome::Declined);
    };
    stack.clear();
    if !budget.charge_usize(state_count) {
        return Ok(AnchoredHorizonOutcome::Declined);
    }
    for state in 0..state_count {
        if reachable[state] && indegree[state] == 0 {
            stack.push(state);
        }
    }
    while let Some(state) = stack.pop() {
        if !budget.charge(1) {
            return Ok(AnchoredHorizonOutcome::Declined);
        }
        order.push(state);
        let row = anchored_row(forward, state, width)?;
        if !budget.charge_usize(row.len()) {
            return Ok(AnchoredHorizonOutcome::Declined);
        }
        for cell in row {
            let destination = usize::try_from(cell.next).map_err(|_| {
                CompileError::InternalInvariant("contextual anchored destination exceeded usize")
            })?;
            if !reachable[destination] {
                continue;
            }
            indegree[destination] =
                indegree[destination]
                    .checked_sub(1)
                    .ok_or(CompileError::InternalInvariant(
                        "contextual anchored indegree underflowed",
                    ))?;
            if indegree[destination] == 0 {
                stack.push(destination);
            }
        }
    }
    if order.len() != reachable_count {
        return Ok(AnchoredHorizonOutcome::Complete(None));
    }

    let Some(mut horizons) = reserve_horizon_vec(state_count, budget)? else {
        return Ok(AnchoredHorizonOutcome::Declined);
    };
    if !budget.charge_usize(state_count) {
        return Ok(AnchoredHorizonOutcome::Declined);
    }
    horizons.resize(state_count, 0_u32);
    if !budget.charge_usize(order.len()) {
        return Ok(AnchoredHorizonOutcome::Declined);
    }
    for &state in order.iter().rev() {
        let mut horizon = 0_u32;
        let row = anchored_row(forward, state, width)?;
        if !budget.charge_usize(row.len()) {
            return Ok(AnchoredHorizonOutcome::Declined);
        }
        for cell in row {
            let destination = usize::try_from(cell.next).map_err(|_| {
                CompileError::InternalInvariant("contextual anchored destination exceeded usize")
            })?;
            let suffix = if reachable[destination] {
                horizons[destination]
            } else {
                0
            };
            horizon = horizon.max(
                suffix
                    .checked_add(1)
                    .ok_or(CompileError::InternalInvariant(
                        "contextual anchored horizon exceeded u32",
                    ))?,
            );
        }
        horizons[state] = horizon;
    }
    let mut maximum = 0_u32;
    if !budget.charge_usize(forward.initial.len()) {
        return Ok(AnchoredHorizonOutcome::Declined);
    }
    for &state in forward.initial.values() {
        let index = usize::try_from(state).map_err(|_| {
            CompileError::InternalInvariant("contextual anchored initial state exceeded usize")
        })?;
        if reachable[index] {
            maximum = maximum.max(horizons[index]);
        }
    }
    Ok(AnchoredHorizonOutcome::Complete(Some(maximum)))
}

fn anchored_row(
    forward: &ForwardDfa,
    state: usize,
    width: usize,
) -> Result<&[NativeContextForwardCell], CompileError> {
    let begin = usize::try_from(*forward.row_offsets.get(state).ok_or(
        CompileError::InternalInvariant("contextual anchored row offset is absent"),
    )?)
    .map_err(|_| {
        CompileError::InternalInvariant("contextual anchored row offset exceeded usize")
    })?;
    let end = usize::try_from(
        *forward
            .row_offsets
            .get(state.checked_add(1).ok_or(CompileError::InternalInvariant(
                "contextual anchored state offset overflowed",
            ))?)
            .ok_or(CompileError::InternalInvariant(
                "contextual anchored row end is absent",
            ))?,
    )
    .map_err(|_| CompileError::InternalInvariant("contextual anchored row end exceeded usize"))?;
    if end.checked_sub(begin) != Some(width) {
        return Err(CompileError::InternalInvariant(
            "contextual anchored horizon row has the wrong width",
        ));
    }
    forward
        .cells
        .get(begin..end)
        .ok_or(CompileError::InternalInvariant(
            "contextual anchored horizon row is absent",
        ))
}

const fn is_live_anchored_state(key: &ForwardKey) -> bool {
    !key.items.is_empty() && !matches!(key.boundary.current, CurrentClass::HaystackEnd)
}

fn reserve_horizon_vec<T>(
    capacity: usize,
    budget: &mut BuildBudget,
) -> Result<Option<Vec<T>>, CompileError> {
    if !budget.charge_usize(capacity) {
        return Ok(None);
    }
    reserve_vec(capacity, budget)
}

type FinalForwardTables = (
    Vec<NativeContextForwardInitial>,
    Vec<NativeContextForwardState>,
    Vec<u32>,
    Vec<NativeContextForwardCell>,
);

#[allow(
    clippy::too_many_lines,
    reason = "canonical initial facts, state flags, padded rows, and budget accounting publish atomically"
)]
fn finalize_forward_tables(
    initial: &StableMap<ForwardBoundary, u32>,
    states: &[ForwardKey],
    rows: &[Vec<ForwardCell>],
    class_count: usize,
    budget: &mut BuildBudget,
) -> Result<Option<FinalForwardTables>, CompileError> {
    if states.len() != rows.len() {
        return Err(CompileError::InternalInvariant(
            "contextual forward state and row counts differ",
        ));
    }
    let Some(mut canonical_initial) = reserve_vec(initial.len(), budget)? else {
        return Ok(None);
    };
    for (&boundary, &state) in initial {
        if !budget.charge(1) {
            return Ok(None);
        }
        canonical_initial.push(NativeContextForwardInitial {
            context: boundary.native_context(class_count)?,
            state,
        });
    }
    canonical_initial.sort_unstable_by_key(|entry| entry.context);
    if canonical_initial
        .windows(2)
        .any(|pair| pair[0].context == pair[1].context)
    {
        return Err(CompileError::InternalInvariant(
            "canonical forward initial contexts are not unique",
        ));
    }

    let width = class_count
        .checked_add(1)
        .ok_or(CompileError::InternalInvariant(
            "flattened forward row width overflowed",
        ))?;
    let cell_count = rows
        .len()
        .checked_mul(width)
        .ok_or(CompileError::InternalInvariant(
            "flattened forward transition count overflowed",
        ))?;
    let padding = rows.iter().try_fold(0_usize, |total, row| {
        if row.is_empty() {
            total.checked_add(width)
        } else if row.len() == width {
            Some(total)
        } else {
            None
        }
    });
    let Some(padding) = padding else {
        return Err(CompileError::InternalInvariant(
            "contextual forward row has a partial width",
        ));
    };
    if !budget.reserve_transitions(padding) {
        return Ok(None);
    }
    let offset_count = rows
        .len()
        .checked_add(1)
        .ok_or(CompileError::InternalInvariant(
            "forward row-offset count overflowed",
        ))?;
    let Some(mut row_offsets) = reserve_vec(offset_count, budget)? else {
        return Ok(None);
    };
    let Some(mut native_states) = reserve_vec(states.len(), budget)? else {
        return Ok(None);
    };
    let Some(mut cells) = reserve_vec(cell_count, budget)? else {
        return Ok(None);
    };
    for (state_index, (state, row)) in states.iter().zip(rows).enumerate() {
        if !budget.charge(1) {
            return Ok(None);
        }
        let empty = state.items.is_empty();
        let terminal = state.pending && empty;
        native_states.push(NativeContextForwardState {
            pending: state.pending,
            empty,
            terminal,
        });
        row_offsets.push(
            u32::try_from(cells.len())
                .map_err(|_| CompileError::InternalInvariant("forward row offset exceeded u32"))?,
        );
        if row.is_empty() {
            let state = u32::try_from(state_index).map_err(|_| {
                CompileError::InternalInvariant("forward padding state exceeded u32")
            })?;
            for _ in 0..width {
                if !budget.charge(1) {
                    return Ok(None);
                }
                cells.push(NativeContextForwardCell {
                    next: state,
                    accepted: false,
                });
            }
        } else {
            for &cell in row {
                if !budget.charge(1) {
                    return Ok(None);
                }
                cells.push(NativeContextForwardCell {
                    next: cell.next,
                    accepted: cell.accepted,
                });
            }
        }
    }
    row_offsets.push(
        u32::try_from(cells.len()).map_err(|_| {
            CompileError::InternalInvariant("forward final row offset exceeded u32")
        })?,
    );
    Ok(Some((canonical_initial, native_states, row_offsets, cells)))
}

#[allow(
    clippy::too_many_arguments,
    reason = "initial-state publication updates the closure, graph arenas, indexes, and shared budget atomically"
)]
fn seed_forward_initial(
    raw: &RawPlan,
    alphabet: &Alphabet,
    boundary: ForwardBoundary,
    closure: &mut ForwardClosure,
    states: &mut Vec<ForwardKey>,
    rows: &mut Vec<Vec<ForwardCell>>,
    interned: &mut StableMap<ForwardKey, u32>,
    initial: &mut StableMap<ForwardBoundary, u32>,
    budget: &mut BuildBudget,
) -> Result<Option<()>, CompileError> {
    closure.begin();
    let accepted = closure.expand(
        raw,
        raw.start,
        boundary.assertion_context(alphabet)?,
        budget,
    )?;
    if budget.declined.is_some() {
        return Ok(None);
    }
    let Some(items) = closure.copy_items(budget)? else {
        return Ok(None);
    };
    let key = ForwardKey {
        items,
        pending: accepted,
        boundary,
    };
    let Some(state) = intern_forward(key, states, rows, interned, budget)? else {
        return Ok(None);
    };
    if initial.try_reserve(1).is_err() {
        budget.allocation::<(ForwardBoundary, u32)>(initial.len().saturating_add(1));
        return Ok(None);
    }
    if initial.insert(boundary, state).is_some() {
        return Err(CompileError::InternalInvariant(
            "duplicate contextual forward initial boundary",
        ));
    }
    Ok(Some(()))
}

#[allow(
    clippy::too_many_arguments,
    reason = "one transition atomically owns closure, interning, table, and budget state"
)]
fn build_forward_cell(
    raw: &RawPlan,
    alphabet: &Alphabet,
    mode: ForwardMode,
    key: &ForwardKey,
    byte: u8,
    boundary: ForwardBoundary,
    closure: &mut ForwardClosure,
    states: &mut Vec<ForwardKey>,
    rows: &mut Vec<Vec<ForwardCell>>,
    interned: &mut StableMap<ForwardKey, u32>,
    budget: &mut BuildBudget,
) -> Result<Option<ForwardCell>, CompileError> {
    closure.begin();
    let context = boundary.assertion_context(alphabet)?;
    let mut accepted = false;
    'items: for &consuming in &key.items {
        if !budget.charge(1) {
            return Ok(None);
        }
        for edge in state_edges(raw, consuming)? {
            if !budget.charge(1) {
                return Ok(None);
            }
            if raw.edge_kinds[edge] != EdgeKind::ByteRange {
                return Err(CompileError::InternalInvariant(
                    "contextual consuming state has a zero-width edge",
                ));
            }
            if raw.byte_starts[edge] <= byte
                && byte <= raw.byte_ends[edge]
                && closure.expand(raw, raw.edge_targets[edge], context, budget)?
            {
                accepted = true;
                break 'items;
            }
            if budget.declined.is_some() {
                return Ok(None);
            }
        }
    }
    if mode == ForwardMode::Search && !accepted && !key.pending {
        accepted = closure.expand(raw, raw.start, context, budget)?;
        if budget.declined.is_some() {
            return Ok(None);
        }
    }
    let Some(items) = closure.copy_items(budget)? else {
        return Ok(None);
    };
    let next_key = ForwardKey {
        items,
        pending: key.pending || accepted,
        boundary,
    };
    let Some(next) = intern_forward(next_key, states, rows, interned, budget)? else {
        return Ok(None);
    };
    Ok(Some(ForwardCell { next, accepted }))
}

fn intern_forward(
    key: ForwardKey,
    states: &mut Vec<ForwardKey>,
    rows: &mut Vec<Vec<ForwardCell>>,
    interned: &mut StableMap<ForwardKey, u32>,
    budget: &mut BuildBudget,
) -> Result<Option<u32>, CompileError> {
    if let Some(&known) = interned.get(&key) {
        return Ok(Some(known));
    }
    if !budget.reserve_state() {
        return Ok(None);
    }
    let Some(stored) = clone_forward_key(&key, budget)? else {
        return Ok(None);
    };
    if states.try_reserve(1).is_err() || rows.try_reserve(1).is_err() {
        budget.allocation::<ForwardKey>(states.len().saturating_add(1));
        return Ok(None);
    }
    if interned.try_reserve(1).is_err() {
        budget.allocation::<(ForwardKey, u32)>(interned.len().saturating_add(1));
        return Ok(None);
    }
    let id = u32::try_from(states.len()).map_err(|_| {
        CompileError::InternalInvariant("contextual forward state count exceeded u32")
    })?;
    states.push(stored);
    rows.push(Vec::new());
    interned.insert(key, id);
    Ok(Some(id))
}

struct Incoming {
    sources: Vec<u32>,
    by_target: Vec<Vec<u32>>,
}

impl Incoming {
    fn build(raw: &RawPlan, budget: &mut BuildBudget) -> Result<Option<Self>, CompileError> {
        let Some(mut sources) = reserve_vec(raw.edge_targets.len(), budget)? else {
            return Ok(None);
        };
        sources.resize(raw.edge_targets.len(), 0);
        let Some(mut by_target) = reserve_vec(raw.roles.len(), budget)? else {
            return Ok(None);
        };
        by_target.resize_with(raw.roles.len(), Vec::new);
        let Some(mut degrees) = reserve_vec(raw.roles.len(), budget)? else {
            return Ok(None);
        };
        degrees.resize(raw.roles.len(), 0_usize);
        for source in 0..raw.roles.len() {
            let source_u32 = u32::try_from(source).map_err(|_| {
                CompileError::InternalInvariant("contextual reverse source exceeded u32")
            })?;
            for edge in state_edges(raw, source_u32)? {
                if !budget.charge(1) {
                    return Ok(None);
                }
                sources[edge] = source_u32;
                let target = plan_index(
                    raw.edge_targets[edge],
                    raw.roles.len(),
                    "contextual reverse target",
                )?;
                degrees[target] =
                    degrees[target]
                        .checked_add(1)
                        .ok_or(CompileError::InternalInvariant(
                            "contextual reverse degree overflowed",
                        ))?;
            }
        }
        for (row, &degree) in by_target.iter_mut().zip(&degrees) {
            if row.try_reserve_exact(degree).is_err() {
                budget.allocation::<u32>(degree);
                return Ok(None);
            }
        }
        for (edge, &target) in raw.edge_targets.iter().enumerate() {
            let target = plan_index(target, raw.roles.len(), "contextual reverse target")?;
            by_target[target].push(u32::try_from(edge).map_err(|_| {
                CompileError::InternalInvariant("contextual reverse edge exceeded u32")
            })?);
        }
        Ok(Some(Self { sources, by_target }))
    }
}

struct ReverseClosure {
    seen: Vec<bool>,
    stack: Vec<u32>,
    items: Vec<u32>,
}

impl ReverseClosure {
    fn new(raw: &RawPlan, budget: &mut BuildBudget) -> Result<Option<Self>, CompileError> {
        let Some(mut seen) = reserve_vec(raw.roles.len(), budget)? else {
            return Ok(None);
        };
        seen.resize(raw.roles.len(), false);
        let capacity =
            raw.edge_targets
                .len()
                .checked_add(1)
                .ok_or(CompileError::InternalInvariant(
                    "contextual reverse stack capacity overflowed",
                ))?;
        let Some(stack) = reserve_vec(capacity, budget)? else {
            return Ok(None);
        };
        let Some(items) = reserve_vec(raw.edge_targets.len(), budget)? else {
            return Ok(None);
        };
        Ok(Some(Self { seen, stack, items }))
    }

    fn begin(&mut self) {
        self.seen.fill(false);
        self.stack.clear();
        self.items.clear();
    }

    fn expand(
        &mut self,
        raw: &RawPlan,
        incoming: &Incoming,
        root: u32,
        context: AssertionContext,
        budget: &mut BuildBudget,
    ) -> Result<bool, CompileError> {
        self.stack.push(root);
        let mut reaches_start = false;
        while let Some(state) = self.stack.pop() {
            if !budget.charge(1) {
                return Ok(false);
            }
            let index = plan_index(state, raw.roles.len(), "contextual reverse closure")?;
            if self.seen[index] {
                continue;
            }
            self.seen[index] = true;
            reaches_start |= state == raw.start;
            for &edge in &incoming.by_target[index] {
                if !budget.charge(1) {
                    return Ok(false);
                }
                let edge_index = usize::try_from(edge).map_err(|_| {
                    CompileError::InternalInvariant("contextual reverse edge exceeded usize")
                })?;
                let source = incoming.sources[edge_index];
                let source_index = plan_index(
                    source,
                    raw.roles.len(),
                    "contextual reverse incoming source",
                )?;
                match raw.roles[source_index] {
                    StateRole::Split => {
                        if context.enabled(raw.edge_kinds[edge_index])? {
                            self.stack.push(source);
                        }
                    }
                    StateRole::Consume => {}
                    StateRole::Accept => {
                        return Err(CompileError::InternalInvariant(
                            "contextual reverse graph has an outgoing Accept edge",
                        ));
                    }
                    _ => {
                        return Err(CompileError::InternalInvariant(
                            "contextual reverse closure reached an unknown state role",
                        ));
                    }
                }
            }
        }
        Ok(reaches_start)
    }

    fn collect_frontier(
        &mut self,
        raw: &RawPlan,
        incoming: &Incoming,
        budget: &mut BuildBudget,
    ) -> Result<bool, CompileError> {
        for target in 0..raw.roles.len() {
            if !budget.charge(1) {
                return Ok(false);
            }
            if !self.seen[target] {
                continue;
            }
            for &edge in &incoming.by_target[target] {
                if !budget.charge(1) {
                    return Ok(false);
                }
                let edge_index = usize::try_from(edge).map_err(|_| {
                    CompileError::InternalInvariant("contextual reverse edge exceeded usize")
                })?;
                let source = plan_index(
                    incoming.sources[edge_index],
                    raw.roles.len(),
                    "contextual reverse frontier source",
                )?;
                if raw.roles[source] == StateRole::Consume {
                    self.items.push(edge);
                }
            }
        }
        Ok(true)
    }

    fn copy_items(&self, budget: &mut BuildBudget) -> Result<Option<Vec<u32>>, CompileError> {
        clone_u32s(&self.items, budget)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "seeding and completing the deterministic reverse worklist remain one audited transaction"
)]
fn build_reverse(
    raw: &RawPlan,
    alphabet: &Alphabet,
    budget: &mut BuildBudget,
) -> Result<Option<ReverseDfa>, CompileError> {
    let Some(incoming) = Incoming::build(raw, budget)? else {
        return Ok(None);
    };
    let Some(mut closure) = ReverseClosure::new(raw, budget)? else {
        return Ok(None);
    };
    let Some(mut states) = reserve_vec(1, budget)? else {
        return Ok(None);
    };
    let Some(mut rows) = reserve_vec(1, budget)? else {
        return Ok(None);
    };
    let Some(mut interned) = reserve_map(1, budget)? else {
        return Ok(None);
    };
    let Some(mut initial) = reserve_map(1, budget)? else {
        return Ok(None);
    };

    let mut property_seen = [false; 16];
    let Some(mut property_classes) = reserve_vec(16, budget)? else {
        return Ok(None);
    };
    for &properties in &alphabet.properties {
        let index = usize::from(properties);
        if !property_seen[index] {
            property_seen[index] = true;
            property_classes.push(properties);
        }
    }

    let empty = ReverseBoundary {
        before: None,
        current_present: false,
        current_properties: 0,
        absolute_start: true,
        absolute_end: true,
    };
    if seed_reverse_initial(
        raw,
        alphabet,
        &incoming,
        empty,
        &mut closure,
        &mut states,
        &mut rows,
        &mut interned,
        &mut initial,
        budget,
    )?
    .is_none()
    {
        return Ok(None);
    }
    for &current_properties in &property_classes {
        let start = ReverseBoundary {
            before: None,
            current_present: true,
            current_properties,
            absolute_start: true,
            absolute_end: false,
        };
        if seed_reverse_initial(
            raw,
            alphabet,
            &incoming,
            start,
            &mut closure,
            &mut states,
            &mut rows,
            &mut interned,
            &mut initial,
            budget,
        )?
        .is_none()
        {
            return Ok(None);
        }
    }
    for before in 0..alphabet.classes() {
        let before = u8::try_from(before)
            .map_err(|_| CompileError::InternalInvariant("contextual reverse class exceeded u8"))?;
        for &current_properties in &property_classes {
            let interior = ReverseBoundary {
                before: Some(before),
                current_present: true,
                current_properties,
                absolute_start: false,
                absolute_end: false,
            };
            if seed_reverse_initial(
                raw,
                alphabet,
                &incoming,
                interior,
                &mut closure,
                &mut states,
                &mut rows,
                &mut interned,
                &mut initial,
                budget,
            )?
            .is_none()
            {
                return Ok(None);
            }
        }
        let end = ReverseBoundary {
            before: Some(before),
            current_present: false,
            current_properties: 0,
            absolute_start: false,
            absolute_end: true,
        };
        if seed_reverse_initial(
            raw,
            alphabet,
            &incoming,
            end,
            &mut closure,
            &mut states,
            &mut rows,
            &mut interned,
            &mut initial,
            budget,
        )?
        .is_none()
        {
            return Ok(None);
        }
    }

    let width = alphabet
        .classes()
        .checked_add(1)
        .ok_or(CompileError::InternalInvariant(
            "contextual reverse row width overflowed",
        ))?;
    let mut cursor = 0_usize;
    while cursor < states.len() {
        let Some(key) = clone_reverse_key(&states[cursor], budget)? else {
            return Ok(None);
        };
        let Some(current_class) = key.boundary.before else {
            cursor = cursor
                .checked_add(1)
                .ok_or(CompileError::InternalInvariant(
                    "contextual reverse worklist overflowed",
                ))?;
            continue;
        };
        if !budget.reserve_transitions(width) {
            return Ok(None);
        }
        let Some(mut row) = reserve_vec(width, budget)? else {
            return Ok(None);
        };
        let byte = alphabet.representative(current_class)?;
        let current_properties = alphabet.properties(current_class)?;
        for symbol in 0..width {
            let before = if symbol == alphabet.classes() {
                None
            } else {
                Some(u8::try_from(symbol).map_err(|_| {
                    CompileError::InternalInvariant("contextual reverse symbol exceeded u8")
                })?)
            };
            let boundary = ReverseBoundary {
                before,
                current_present: true,
                current_properties,
                absolute_start: before.is_none(),
                absolute_end: false,
            };
            let Some(cell) = build_reverse_cell(
                raw,
                alphabet,
                &incoming,
                &key,
                byte,
                boundary,
                &mut closure,
                &mut states,
                &mut rows,
                &mut interned,
                budget,
            )?
            else {
                return Ok(None);
            };
            row.push(cell);
        }
        *rows.get_mut(cursor).ok_or(CompileError::InternalInvariant(
            "contextual reverse worklist row is absent",
        ))? = row;
        cursor = cursor
            .checked_add(1)
            .ok_or(CompileError::InternalInvariant(
                "contextual reverse worklist overflowed",
            ))?;
    }
    let Some((canonical_initial, row_offsets, cells)) =
        finalize_reverse_tables(&initial, &rows, alphabet.classes(), budget)?
    else {
        return Ok(None);
    };
    Ok(Some(ReverseDfa {
        initial,
        canonical_initial,
        states,
        row_offsets,
        cells,
    }))
}

type FinalReverseTables = (
    Vec<NativeContextReverseInitial>,
    Vec<u32>,
    Vec<NativeContextReverseCell>,
);

fn finalize_reverse_tables(
    initial: &StableMap<ReverseBoundary, ReverseInitial>,
    rows: &[Vec<ReverseCell>],
    class_count: usize,
    budget: &mut BuildBudget,
) -> Result<Option<FinalReverseTables>, CompileError> {
    let Some(mut canonical_initial) = reserve_vec(initial.len(), budget)? else {
        return Ok(None);
    };
    for (&boundary, &entry) in initial {
        if !budget.charge(1) {
            return Ok(None);
        }
        canonical_initial.push(NativeContextReverseInitial {
            context: boundary.native_context(class_count)?,
            state: entry.state.unwrap_or(u32::MAX),
            reaches_start: entry.reaches_start,
        });
    }
    canonical_initial.sort_unstable_by_key(|entry| entry.context);
    if canonical_initial
        .windows(2)
        .any(|pair| pair[0].context == pair[1].context)
    {
        return Err(CompileError::InternalInvariant(
            "canonical reverse initial contexts are not unique",
        ));
    }

    let width = class_count
        .checked_add(1)
        .ok_or(CompileError::InternalInvariant(
            "flattened reverse row width overflowed",
        ))?;
    let cell_count = rows
        .len()
        .checked_mul(width)
        .ok_or(CompileError::InternalInvariant(
            "flattened reverse transition count overflowed",
        ))?;
    let padding = rows.iter().try_fold(0_usize, |total, row| {
        if row.is_empty() {
            total.checked_add(width)
        } else if row.len() == width {
            Some(total)
        } else {
            None
        }
    });
    let Some(padding) = padding else {
        return Err(CompileError::InternalInvariant(
            "contextual reverse row has a partial width",
        ));
    };
    if !budget.reserve_transitions(padding) {
        return Ok(None);
    }
    let offset_count = rows
        .len()
        .checked_add(1)
        .ok_or(CompileError::InternalInvariant(
            "reverse row-offset count overflowed",
        ))?;
    let Some(mut row_offsets) = reserve_vec(offset_count, budget)? else {
        return Ok(None);
    };
    let Some(mut cells) = reserve_vec(cell_count, budget)? else {
        return Ok(None);
    };
    for row in rows {
        if !budget.charge(1) {
            return Ok(None);
        }
        row_offsets.push(
            u32::try_from(cells.len())
                .map_err(|_| CompileError::InternalInvariant("reverse row offset exceeded u32"))?,
        );
        if row.is_empty() {
            for _ in 0..width {
                if !budget.charge(1) {
                    return Ok(None);
                }
                cells.push(NativeContextReverseCell {
                    next: u32::MAX,
                    reaches_start: false,
                });
            }
        } else {
            for &cell in row {
                if !budget.charge(1) {
                    return Ok(None);
                }
                cells.push(NativeContextReverseCell {
                    next: cell.next.unwrap_or(u32::MAX),
                    reaches_start: cell.reaches_start,
                });
            }
        }
    }
    row_offsets.push(
        u32::try_from(cells.len()).map_err(|_| {
            CompileError::InternalInvariant("reverse final row offset exceeded u32")
        })?,
    );
    Ok(Some((canonical_initial, row_offsets, cells)))
}

#[allow(
    clippy::too_many_arguments,
    reason = "reverse initialization updates closure, graph arenas, indexes, and shared budget atomically"
)]
fn seed_reverse_initial(
    raw: &RawPlan,
    alphabet: &Alphabet,
    incoming: &Incoming,
    boundary: ReverseBoundary,
    closure: &mut ReverseClosure,
    states: &mut Vec<ReverseKey>,
    rows: &mut Vec<Vec<ReverseCell>>,
    interned: &mut StableMap<ReverseKey, u32>,
    initial: &mut StableMap<ReverseBoundary, ReverseInitial>,
    budget: &mut BuildBudget,
) -> Result<Option<()>, CompileError> {
    closure.begin();
    let context = boundary.assertion_context(alphabet)?;
    let mut reaches_start = false;
    for state in 0..raw.roles.len() {
        if !budget.charge(1) {
            return Ok(None);
        }
        if raw.roles[state] == StateRole::Accept {
            reaches_start |= closure.expand(
                raw,
                incoming,
                u32::try_from(state).map_err(|_| {
                    CompileError::InternalInvariant("contextual reverse Accept state exceeded u32")
                })?,
                context,
                budget,
            )?;
            if budget.declined.is_some() {
                return Ok(None);
            }
        }
    }
    if !closure.collect_frontier(raw, incoming, budget)? {
        return Ok(None);
    }
    let Some(items) = closure.copy_items(budget)? else {
        return Ok(None);
    };
    let state = intern_reverse(
        ReverseKey { items, boundary },
        states,
        rows,
        interned,
        budget,
    )?;
    if budget.declined.is_some() {
        return Ok(None);
    }
    if initial.try_reserve(1).is_err() {
        budget.allocation::<(ReverseBoundary, ReverseInitial)>(initial.len().saturating_add(1));
        return Ok(None);
    }
    if initial
        .insert(
            boundary,
            ReverseInitial {
                state,
                reaches_start,
            },
        )
        .is_some()
    {
        return Err(CompileError::InternalInvariant(
            "duplicate contextual reverse initial boundary",
        ));
    }
    Ok(Some(()))
}

#[allow(
    clippy::too_many_arguments,
    reason = "one reverse transition atomically owns closure, interning, table, and budget state"
)]
fn build_reverse_cell(
    raw: &RawPlan,
    alphabet: &Alphabet,
    incoming: &Incoming,
    key: &ReverseKey,
    byte: u8,
    boundary: ReverseBoundary,
    closure: &mut ReverseClosure,
    states: &mut Vec<ReverseKey>,
    rows: &mut Vec<Vec<ReverseCell>>,
    interned: &mut StableMap<ReverseKey, u32>,
    budget: &mut BuildBudget,
) -> Result<Option<ReverseCell>, CompileError> {
    closure.begin();
    let context = boundary.assertion_context(alphabet)?;
    let mut reaches_start = false;
    for &incoming_edge in &key.items {
        if !budget.charge(1) {
            return Ok(None);
        }
        let edge = usize::try_from(incoming_edge).map_err(|_| {
            CompileError::InternalInvariant("contextual reverse incoming edge exceeded usize")
        })?;
        if raw.byte_starts[edge] <= byte && byte <= raw.byte_ends[edge] {
            reaches_start |=
                closure.expand(raw, incoming, incoming.sources[edge], context, budget)?;
            if budget.declined.is_some() {
                return Ok(None);
            }
        }
    }
    if !closure.collect_frontier(raw, incoming, budget)? {
        return Ok(None);
    }
    let Some(items) = closure.copy_items(budget)? else {
        return Ok(None);
    };
    let next = intern_reverse(
        ReverseKey { items, boundary },
        states,
        rows,
        interned,
        budget,
    )?;
    if budget.declined.is_some() {
        return Ok(None);
    }
    Ok(Some(ReverseCell {
        next,
        reaches_start,
    }))
}

fn intern_reverse(
    key: ReverseKey,
    states: &mut Vec<ReverseKey>,
    rows: &mut Vec<Vec<ReverseCell>>,
    interned: &mut StableMap<ReverseKey, u32>,
    budget: &mut BuildBudget,
) -> Result<Option<u32>, CompileError> {
    if key.items.is_empty() {
        return Ok(None);
    }
    if let Some(&known) = interned.get(&key) {
        return Ok(Some(known));
    }
    if !budget.reserve_state() {
        return Ok(None);
    }
    let Some(stored) = clone_reverse_key(&key, budget)? else {
        return Ok(None);
    };
    if states.try_reserve(1).is_err() || rows.try_reserve(1).is_err() {
        budget.allocation::<ReverseKey>(states.len().saturating_add(1));
        return Ok(None);
    }
    if interned.try_reserve(1).is_err() {
        budget.allocation::<(ReverseKey, u32)>(interned.len().saturating_add(1));
        return Ok(None);
    }
    let id = u32::try_from(states.len()).map_err(|_| {
        CompileError::InternalInvariant("contextual reverse state count exceeded u32")
    })?;
    states.push(stored);
    rows.push(Vec::new());
    interned.insert(key, id);
    Ok(Some(id))
}

struct BuildBudget {
    limits: ContextDfaLimits,
    work: u64,
    states: usize,
    transitions: usize,
    declined: Option<ContextDfaResource>,
}

impl BuildBudget {
    const fn new(limits: ContextDfaLimits) -> Self {
        Self {
            limits,
            work: 0,
            states: 0,
            transitions: 0,
            declined: None,
        }
    }

    fn charge(&mut self, amount: u64) -> bool {
        let Some(required) = self.work.checked_add(amount) else {
            self.decline(ContextDfaResource::Work {
                limit: self.limits.max_work,
                required: u64::MAX,
            });
            return false;
        };
        if required > self.limits.max_work {
            self.decline(ContextDfaResource::Work {
                limit: self.limits.max_work,
                required,
            });
            return false;
        }
        self.work = required;
        true
    }

    fn charge_usize(&mut self, amount: usize) -> bool {
        let Ok(amount) = u64::try_from(amount) else {
            self.decline(ContextDfaResource::Work {
                limit: self.limits.max_work,
                required: u64::MAX,
            });
            return false;
        };
        self.charge(amount)
    }

    fn reserve_state(&mut self) -> bool {
        let Some(required) = self.states.checked_add(1) else {
            self.decline(ContextDfaResource::States {
                limit: self.limits.max_states,
                required: usize::MAX,
            });
            return false;
        };
        if required > self.limits.max_states {
            self.decline(ContextDfaResource::States {
                limit: self.limits.max_states,
                required,
            });
            return false;
        }
        if !self.charge(1) {
            return false;
        }
        self.states = required;
        true
    }

    fn reserve_transitions(&mut self, amount: usize) -> bool {
        let Some(required) = self.transitions.checked_add(amount) else {
            self.decline(ContextDfaResource::Transitions {
                limit: self.limits.max_transitions,
                required: usize::MAX,
            });
            return false;
        };
        if required > self.limits.max_transitions {
            self.decline(ContextDfaResource::Transitions {
                limit: self.limits.max_transitions,
                required,
            });
            return false;
        }
        let Ok(work) = u64::try_from(amount) else {
            self.decline(ContextDfaResource::Work {
                limit: self.limits.max_work,
                required: u64::MAX,
            });
            return false;
        };
        if !self.charge(work) {
            return false;
        }
        self.transitions = required;
        true
    }

    fn allocation<T>(&mut self, requested_elements: usize) {
        self.decline(ContextDfaResource::Allocation {
            requested_elements,
            element_size: core::mem::size_of::<T>(),
        });
    }

    fn decline(&mut self, resource: ContextDfaResource) {
        if self.declined.is_none() {
            self.declined = Some(resource);
        }
    }

    fn finish_decline(self) -> Result<ContextDfaDecline, CompileError> {
        Ok(ContextDfaDecline {
            resource: self.declined.ok_or(CompileError::InternalInvariant(
                "contextual determinization stopped without a decline",
            ))?,
            work_completed: self.work,
            states_completed: self.states,
            transitions_completed: self.transitions,
        })
    }
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the Result shape composes uniformly with checked builder helpers and future size validation"
)]
fn reserve_vec<T>(
    capacity: usize,
    budget: &mut BuildBudget,
) -> Result<Option<Vec<T>>, CompileError> {
    let mut values = Vec::new();
    if values.try_reserve_exact(capacity).is_err() {
        budget.allocation::<T>(capacity);
        return Ok(None);
    }
    Ok(Some(values))
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the Result shape composes uniformly with checked builder helpers and future size validation"
)]
fn reserve_map<K: Eq + Hash, V>(
    capacity: usize,
    budget: &mut BuildBudget,
) -> Result<Option<StableMap<K, V>>, CompileError> {
    let mut values = StableMap::default();
    if values.try_reserve(capacity).is_err() {
        budget.allocation::<(K, V)>(capacity);
        return Ok(None);
    }
    Ok(Some(values))
}

fn clone_u32s(values: &[u32], budget: &mut BuildBudget) -> Result<Option<Vec<u32>>, CompileError> {
    let Some(mut cloned) = reserve_vec(values.len(), budget)? else {
        return Ok(None);
    };
    cloned.extend_from_slice(values);
    Ok(Some(cloned))
}

fn clone_forward_key(
    key: &ForwardKey,
    budget: &mut BuildBudget,
) -> Result<Option<ForwardKey>, CompileError> {
    Ok(clone_u32s(&key.items, budget)?.map(|items| ForwardKey {
        items,
        pending: key.pending,
        boundary: key.boundary,
    }))
}

fn clone_reverse_key(
    key: &ReverseKey,
    budget: &mut BuildBudget,
) -> Result<Option<ReverseKey>, CompileError> {
    Ok(clone_u32s(&key.items, budget)?.map(|items| ReverseKey {
        items,
        boundary: key.boundary,
    }))
}

fn plan_index(state: u32, states: usize, site: &'static str) -> Result<usize, CompileError> {
    let index = usize::try_from(state)
        .map_err(|_| CompileError::InternalInvariant("contextual state exceeded usize"))?;
    if index >= states {
        return Err(CompileError::InternalInvariant(site));
    }
    Ok(index)
}

fn state_edges(raw: &RawPlan, state: u32) -> Result<core::ops::Range<usize>, CompileError> {
    let state = plan_index(
        state,
        raw.roles.len(),
        "contextual state is outside the graph",
    )?;
    let next = state.checked_add(1).ok_or(CompileError::InternalInvariant(
        "contextual state offset overflowed",
    ))?;
    let begin = usize::try_from(*raw.edge_offsets.get(state).ok_or(
        CompileError::InternalInvariant("contextual state offset is absent"),
    )?)
    .map_err(|_| CompileError::InternalInvariant("contextual edge offset exceeded usize"))?;
    let end = usize::try_from(*raw.edge_offsets.get(next).ok_or(
        CompileError::InternalInvariant("contextual state end offset is absent"),
    )?)
    .map_err(|_| CompileError::InternalInvariant("contextual edge end exceeded usize"))?;
    if end > raw.edge_targets.len() || begin > end {
        return Err(CompileError::InternalInvariant(
            "contextual edge range is invalid",
        ));
    }
    Ok(begin..end)
}

#[derive(Default)]
struct StableFnvHasher(u64);

impl Hasher for StableFnvHasher {
    fn write(&mut self, bytes: &[u8]) {
        let mut hash = if self.0 == 0 {
            0xcbf2_9ce4_8422_2325
        } else {
            self.0
        };
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.0 = hash;
    }

    fn finish(&self) -> u64 {
        if self.0 == 0 {
            0xcbf2_9ce4_8422_2325
        } else {
            self.0
        }
    }
}

#[cfg(test)]
mod tests {
    use fre_automata::{Automaton, CompileLimits};
    use fre_lower::{LowerLimits, OperationSemantics};
    use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

    use super::*;
    use crate::{
        CompileMode,
        dfa::DeterminizeLimits,
        program::{CompiledProgram, EngineKind},
    };

    fn raw_plan(pattern: &str, line_terminator: u8) -> RawPlan {
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
        fre_lower::lower_raw_general(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .unwrap_or_else(|error| panic!("lower {pattern:?}: {error}"))
        .into_plan()
    }

    fn complete(outcome: ContextDfaOutcome) -> ContextDfa {
        match outcome {
            ContextDfaOutcome::Complete(machine) => machine,
            ContextDfaOutcome::Declined(decline) => {
                panic!("contextual determinization declined: {decline:?}")
            }
        }
    }

    fn main_build_work(stats: ContextDfaStats) -> u64 {
        stats
            .build_work
            .checked_sub(stats.anchored_forward_build_work)
            .expect("sidecar work is included in aggregate contextual work")
    }

    fn assert_mandatory_stats_eq(actual: ContextDfaStats, expected: ContextDfaStats) {
        assert_eq!(actual.alphabet_classes, expected.alphabet_classes);
        assert_eq!(actual.row_width, expected.row_width);
        assert_eq!(
            actual.forward_initial_contexts,
            expected.forward_initial_contexts
        );
        assert_eq!(actual.forward_states, expected.forward_states);
        assert_eq!(actual.forward_transitions, expected.forward_transitions);
        assert_eq!(
            actual.reverse_initial_contexts,
            expected.reverse_initial_contexts
        );
        assert_eq!(actual.reverse_states, expected.reverse_states);
        assert_eq!(actual.reverse_transitions, expected.reverse_transitions);
        assert_eq!(main_build_work(actual), main_build_work(expected));
    }

    fn programs(pattern: &str, line_terminator: u8) -> (ContextDfa, CompiledProgram) {
        let raw = raw_plan(pattern, line_terminator);
        let automaton = Automaton::from_raw(raw.clone(), CompileLimits::default())
            .unwrap_or_else(|error| panic!("validate {pattern:?}: {error}"))
            .with_line_terminator(line_terminator);
        let machine = complete(
            determinize(&raw, line_terminator, ContextDfaLimits::default())
                .unwrap_or_else(|error| panic!("determinize {pattern:?}: {error}")),
        );
        let reference = CompiledProgram::build(
            raw,
            automaton,
            OutputContract::Span,
            CompileMode::Fast,
            DeterminizeLimits::default(),
            usize::MAX,
        )
        .unwrap_or_else(|error| panic!("reference {pattern:?}: {error}"));
        (machine, reference)
    }

    fn generated_haystacks(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        fn extend(
            result: &mut Vec<Vec<u8>>,
            prefix: &mut Vec<u8>,
            alphabet: &[u8],
            max_len: usize,
        ) {
            result.push(prefix.clone());
            if prefix.len() == max_len {
                return;
            }
            for &byte in alphabet {
                prefix.push(byte);
                extend(result, prefix, alphabet, max_len);
                prefix.pop();
            }
        }
        let mut result = Vec::new();
        extend(&mut result, &mut Vec::new(), alphabet, max_len);
        result
    }

    fn assert_every_window(pattern: &str, line_terminator: u8, haystacks: &[Vec<u8>]) {
        let (machine, reference) = programs(pattern, line_terminator);
        let mut workspace = reference.prepare_workspace().expect("reference workspace");
        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let expected = reference
                        .search_with_workspace(haystack, window, &mut workspace)
                        .unwrap_or_else(|error| {
                            panic!(
                                "reference search {pattern:?}/{line_terminator:#04x}/{haystack:?}/{start}..{end}: {error}"
                            )
                        });
                    let MatchResult::Span(expected_span) = expected else {
                        panic!("Span reference returned another contract");
                    };
                    for output in [
                        OutputContract::Exists,
                        OutputContract::SelectedEnd,
                        OutputContract::Span,
                    ] {
                        let actual = machine.search(haystack, window, output).unwrap_or_else(|error| {
                            panic!(
                                "context search {pattern:?}/{line_terminator:#04x}/{haystack:?}/{start}..{end}/{output:?}: {error}"
                            )
                        });
                        let projected = match output {
                            OutputContract::Exists => MatchResult::Exists(expected_span.is_some()),
                            OutputContract::SelectedEnd => {
                                MatchResult::SelectedEnd(expected_span.map(|(_, end)| end))
                            }
                            OutputContract::Span => MatchResult::Span(expected_span),
                        };
                        assert_eq!(
                            actual, projected,
                            "pattern={pattern:?}, terminator={line_terminator:#04x}, haystack={haystack:?}, window={start}..{end}, output={output:?}"
                        );
                    }
                }
            }
        }
    }

    fn assert_anchored_every_window(pattern: &str, line_terminator: u8, haystacks: &[Vec<u8>]) {
        let (machine, reference) = programs(pattern, line_terminator);
        assert!(
            machine.anchored_forward.is_some(),
            "anchored sidecar unexpectedly omitted for {pattern:?}"
        );
        let mut workspace = reference.prepare_workspace().expect("reference workspace");
        for haystack in haystacks {
            for candidate in 0..=haystack.len() {
                for window_end in candidate..=haystack.len() {
                    let window = SearchWindow::new(candidate, window_end);
                    let MatchResult::Span(reference_span) = reference
                        .search_with_workspace(haystack, window, &mut workspace)
                        .unwrap_or_else(|error| {
                            panic!(
                                "reference anchored oracle {pattern:?}/{line_terminator:#04x}/{haystack:?}/{candidate}..{window_end}: {error}"
                            )
                        })
                    else {
                        panic!("Span reference returned another contract");
                    };
                    let expected =
                        reference_span.and_then(|(start, end)| (start == candidate).then_some(end));
                    let actual = machine
                        .anchored_selected_end(haystack, candidate, window_end)
                        .unwrap_or_else(|error| {
                            panic!(
                                "anchored sidecar {pattern:?}/{line_terminator:#04x}/{haystack:?}/{candidate}..{window_end}: {error}"
                            )
                        });
                    assert_eq!(
                        actual, expected,
                        "pattern={pattern:?}, terminator={line_terminator:#04x}, haystack={haystack:?}, candidate={candidate}, window_end={window_end}"
                    );
                }
            }
        }
    }

    #[test]
    fn generated_assertion_graphs_match_tnfa_for_every_window() {
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
            let mut alphabet = vec![b'a', b'_', b'-', b'\r', b'\n'];
            if !alphabet.contains(&line_terminator) {
                alphabet.push(line_terminator);
            }
            let haystacks = generated_haystacks(&alphabet, 3);
            for assertion in assertions {
                let patterns = [
                    assertion.to_owned(),
                    format!("{assertion}a"),
                    format!("a{assertion}"),
                    format!("(?:a{assertion}|{assertion}a)"),
                    format!("(?:{assertion}a|ab)*?"),
                ];
                for pattern in patterns {
                    assert_every_window(&pattern, line_terminator, &haystacks);
                }
            }
        }
    }

    #[test]
    fn mixed_context_pending_priority_matches_tnfa_for_every_window() {
        let patterns = [
            r"(?:(?m:^)|(?-u:\b))a+?",
            r"(?:a(?m:$)|a(?-u:\b{end})|ab)",
            r"(?:(?mR:^)[a_]+(?mR:$)|b*)",
            r"(?:(?-u:\b{start-half})a|a(?-u:\b{end-half}))+?",
            r"(?:\A|(?m:^))?(?:a|aa)*?(?:\z|(?m:$))",
        ];
        let haystacks = generated_haystacks(b"ab_-\r\n", 4);
        for pattern in patterns {
            assert_every_window(pattern, b'\n', &haystacks);
        }
    }

    #[test]
    fn anchored_sidecar_matches_exact_start_oracle_for_every_window() {
        let patterns = [
            r"a",
            r"(?:ab|a)",
            r"(?:a|ab)",
            r"a+",
            r"a+?",
            r"(?:a|aa)*?",
            r"\A(?:ab|a)+?\z",
            r"(?m:^)(?:ab|a)+?(?m:$)",
            r"(?mR:^)(?:a|aa)*(?mR:$)",
            r"(?-u:\b)(?:foo|f+?)(?-u:\b)",
            r"(?-u:\b{start-half})(?:a|ab)+(?-u:\b{end-half})",
        ];
        for line_terminator in [b'\n', b';'] {
            let mut alphabet = vec![b'a', b'b', b'f', b'o', b'_', b'-', b'\r', b'\n'];
            if !alphabet.contains(&line_terminator) {
                alphabet.push(line_terminator);
            }
            let haystacks = generated_haystacks(&alphabet, 3);
            for pattern in patterns {
                assert_anchored_every_window(pattern, line_terminator, &haystacks);
            }
        }
    }

    #[test]
    fn anchored_sidecar_never_restarts_at_a_later_candidate() {
        let (machine, _) = programs(r"(?-u:\b)ab(?-u:\b)", b'\n');
        let haystack = b"x ab ";
        assert_eq!(
            machine
                .search(
                    haystack,
                    SearchWindow::new(0, haystack.len()),
                    OutputContract::Span,
                )
                .expect("complete contextual search"),
            MatchResult::Span(Some((2, 4)))
        );
        assert_eq!(
            machine
                .anchored_selected_end(haystack, 0, haystack.len())
                .expect("anchored rejection"),
            None
        );
        assert_eq!(
            machine
                .anchored_selected_end(haystack, 2, haystack.len())
                .expect("anchored match"),
            Some(4)
        );
    }

    #[test]
    fn anchored_limits_omit_only_the_optional_sidecar() {
        let raw = raw_plan(r"(?m:^)(?:a|b)+?(?m:$)", b'\n');
        let baseline = complete(
            determinize_with_anchored_limits(
                &raw,
                b'\n',
                ContextDfaLimits::default(),
                AnchoredForwardLimits::default(),
            )
            .expect("baseline contextual determinization"),
        );
        assert!(baseline.anchored_forward.is_some());
        let baseline_stats = baseline.stats();
        assert!(baseline_stats.anchored_forward_present);
        assert!(baseline_stats.anchored_forward_decline.is_none());
        for (limits, expected_resource) in [
            (
                AnchoredForwardLimits {
                    max_states: 0,
                    ..AnchoredForwardLimits::default()
                },
                ContextDfaResource::States {
                    limit: 0,
                    required: 1,
                },
            ),
            (
                AnchoredForwardLimits {
                    max_transitions: 0,
                    ..AnchoredForwardLimits::default()
                },
                ContextDfaResource::Transitions {
                    limit: 0,
                    required: baseline_stats.row_width,
                },
            ),
            (
                AnchoredForwardLimits {
                    max_work: 0,
                    ..AnchoredForwardLimits::default()
                },
                ContextDfaResource::Work {
                    limit: 0,
                    required: 1,
                },
            ),
        ] {
            let bounded = complete(
                determinize_with_anchored_limits(&raw, b'\n', ContextDfaLimits::default(), limits)
                    .expect("bounded anchored determinization"),
            );
            assert!(bounded.anchored_forward.is_none());
            let bounded_stats = bounded.stats();
            assert_mandatory_stats_eq(bounded_stats, baseline_stats);
            assert!(!bounded_stats.anchored_forward_present);
            assert_eq!(bounded_stats.anchored_forward_initial_contexts, 0);
            assert_eq!(bounded_stats.anchored_forward_states, 0);
            assert_eq!(bounded_stats.anchored_forward_transitions, 0);
            assert_eq!(bounded_stats.anchored_forward_construction_states, 0);
            assert_eq!(bounded_stats.anchored_forward_construction_transitions, 0);
            assert_eq!(bounded_stats.anchored_forward_max_resolution_steps, None);
            let decline = bounded_stats
                .anchored_forward_decline
                .expect("bounded sidecar decline receipt");
            assert_eq!(decline.resource, expected_resource);
            assert_eq!(
                bounded_stats.anchored_forward_build_work,
                decline.work_completed
            );
            assert_eq!(
                bounded_stats.build_work,
                main_build_work(baseline_stats)
                    .checked_add(bounded_stats.anchored_forward_build_work)
                    .unwrap()
            );
            let baseline_view = baseline.native_view();
            let bounded_view = bounded.native_view();
            assert_eq!(bounded_view.forward_initial, baseline_view.forward_initial);
            assert_eq!(bounded_view.forward_states, baseline_view.forward_states);
            assert_eq!(
                bounded_view.forward_row_offsets,
                baseline_view.forward_row_offsets
            );
            assert_eq!(bounded_view.forward_cells, baseline_view.forward_cells);
            assert_eq!(bounded_view.reverse_initial, baseline_view.reverse_initial);
            assert_eq!(
                bounded_view.reverse_row_offsets,
                baseline_view.reverse_row_offsets
            );
            assert_eq!(bounded_view.reverse_cells, baseline_view.reverse_cells);
        }
    }

    #[test]
    fn anchored_sidecar_exact_limits_and_stats_are_receipt_closed() {
        let raw = raw_plan(r"(?m:^)(?:ab|a)+?(?m:$)", b'\n');
        let build = |limits| {
            complete(
                determinize_with_anchored_limits(&raw, b'\n', ContextDfaLimits::default(), limits)
                    .expect("bounded anchored determinization"),
            )
        };
        let baseline = build(AnchoredForwardLimits::default());
        let baseline_stats = baseline.stats();
        let anchored = baseline
            .anchored_forward
            .as_ref()
            .expect("baseline anchored sidecar");
        assert!(baseline_stats.anchored_forward_present);
        assert_eq!(
            baseline_stats.anchored_forward_initial_contexts,
            anchored.forward.canonical_initial.len()
        );
        assert_eq!(
            baseline_stats.anchored_forward_states,
            anchored.forward.states.len()
        );
        assert_eq!(
            baseline_stats.anchored_forward_transitions,
            anchored.forward.cells.len()
        );
        assert!(
            baseline_stats.anchored_forward_construction_states
                >= baseline_stats.anchored_forward_states
        );
        assert!(
            baseline_stats.anchored_forward_construction_transitions
                >= baseline_stats.anchored_forward_transitions
        );
        assert_eq!(
            baseline_stats.anchored_forward_max_resolution_steps,
            anchored.max_resolution_steps
        );
        assert!(baseline_stats.anchored_forward_build_work > 0);
        assert!(baseline_stats.anchored_forward_decline.is_none());
        assert_eq!(
            baseline_stats.build_work,
            main_build_work(baseline_stats)
                .checked_add(baseline_stats.anchored_forward_build_work)
                .unwrap()
        );

        let exact_states = build(AnchoredForwardLimits {
            max_states: baseline_stats.anchored_forward_construction_states,
            ..AnchoredForwardLimits::default()
        });
        assert!(exact_states.stats().anchored_forward_present);
        let state_limit = baseline_stats
            .anchored_forward_construction_states
            .checked_sub(1)
            .expect("anchored sidecar has states");
        let state_limited = build(AnchoredForwardLimits {
            max_states: state_limit,
            ..AnchoredForwardLimits::default()
        });
        assert!(state_limited.anchored_forward.is_none());
        assert_eq!(
            state_limited
                .stats()
                .anchored_forward_decline
                .expect("state decline")
                .resource,
            ContextDfaResource::States {
                limit: state_limit,
                required: baseline_stats.anchored_forward_construction_states,
            }
        );

        let exact_transitions = build(AnchoredForwardLimits {
            max_transitions: baseline_stats.anchored_forward_construction_transitions,
            ..AnchoredForwardLimits::default()
        });
        assert!(exact_transitions.stats().anchored_forward_present);
        let transition_limit = baseline_stats
            .anchored_forward_construction_transitions
            .checked_sub(1)
            .expect("anchored sidecar has transitions");
        let transition_limited = build(AnchoredForwardLimits {
            max_transitions: transition_limit,
            ..AnchoredForwardLimits::default()
        });
        assert!(transition_limited.anchored_forward.is_none());
        assert_eq!(
            transition_limited
                .stats()
                .anchored_forward_decline
                .expect("transition decline")
                .resource,
            ContextDfaResource::Transitions {
                limit: transition_limit,
                required: baseline_stats.anchored_forward_construction_transitions,
            }
        );

        let exact_work = build(AnchoredForwardLimits {
            max_work: baseline_stats.anchored_forward_build_work,
            ..AnchoredForwardLimits::default()
        });
        assert!(exact_work.stats().anchored_forward_present);
        assert_eq!(
            exact_work.stats().anchored_forward_build_work,
            baseline_stats.anchored_forward_build_work
        );
        let work_limit = baseline_stats
            .anchored_forward_build_work
            .checked_sub(1)
            .expect("anchored sidecar performs work");
        let work_limited = build(AnchoredForwardLimits {
            max_work: work_limit,
            ..AnchoredForwardLimits::default()
        });
        assert!(work_limited.anchored_forward.is_none());
        let decline = work_limited
            .stats()
            .anchored_forward_decline
            .expect("work decline");
        assert_eq!(
            decline.resource,
            ContextDfaResource::Work {
                limit: work_limit,
                required: baseline_stats.anchored_forward_build_work,
            }
        );
        assert_eq!(
            work_limited.stats().anchored_forward_build_work,
            decline.work_completed
        );
        assert_mandatory_stats_eq(work_limited.stats(), baseline_stats);
    }

    #[test]
    fn anchored_mapping_requires_a_single_equivalent_target_per_main_quotient() {
        let main_partition = StatePartition {
            old_to_new: vec![0, 0],
            representatives: vec![0],
        };
        let distinct_anchored = StatePartition {
            old_to_new: vec![0, 1],
            representatives: vec![0, 1],
        };
        let mut budget = LateQuotientBudget::new(u64::MAX);
        let conflict = remap_anchored_initial_states(
            &[0, 1],
            Some(&main_partition),
            Some(&distinct_anchored),
            &mut budget,
        )
        .expect("checked incompatible remap")
        .expect("remap allocation");
        assert!(matches!(
            conflict,
            AnchoredMappingRemap::Conflict {
                main_state: 0,
                first_anchored_state: 0,
                second_anchored_state: 1,
            }
        ));

        let equivalent_anchored = StatePartition {
            old_to_new: vec![0, 0],
            representatives: vec![0],
        };
        let mut budget = LateQuotientBudget::new(u64::MAX);
        let compatible = remap_anchored_initial_states(
            &[0, 1],
            Some(&main_partition),
            Some(&equivalent_anchored),
            &mut budget,
        )
        .expect("checked compatible remap")
        .expect("remap allocation");
        let AnchoredMappingRemap::Complete(mapping) = compatible else {
            panic!("equivalent anchored targets were rejected");
        };
        assert_eq!(mapping, vec![0]);
    }

    #[test]
    fn anchored_horizon_scratch_and_scans_obey_an_exact_work_limit() {
        let (machine, _) = programs(r"(?-u:\b)abc(?-u:\b)", b'\n');
        let anchored = machine
            .anchored_forward
            .as_ref()
            .expect("finite anchored sidecar");
        let limits = ContextDfaLimits {
            max_states: usize::MAX,
            max_transitions: usize::MAX,
            max_work: u64::MAX,
        };
        let mut measured = BuildBudget::new(limits);
        assert!(matches!(
            anchored_resolution_horizon(
                &anchored.forward,
                machine.alphabet.classes(),
                &mut measured,
            )
            .expect("measure bounded horizon"),
            AnchoredHorizonOutcome::Complete(Some(3))
        ));
        let exact_work = measured.work;
        assert!(exact_work > 0);

        let mut exact = BuildBudget::new(ContextDfaLimits {
            max_work: exact_work,
            ..limits
        });
        assert!(matches!(
            anchored_resolution_horizon(&anchored.forward, machine.alphabet.classes(), &mut exact,)
                .expect("exact bounded horizon"),
            AnchoredHorizonOutcome::Complete(Some(3))
        ));
        assert_eq!(exact.work, exact_work);

        let work_limit = exact_work.checked_sub(1).unwrap();
        let mut limited = BuildBudget::new(ContextDfaLimits {
            max_work: work_limit,
            ..limits
        });
        assert!(matches!(
            anchored_resolution_horizon(
                &anchored.forward,
                machine.alphabet.classes(),
                &mut limited,
            )
            .expect("one-below bounded horizon"),
            AnchoredHorizonOutcome::Declined
        ));
        assert_eq!(
            limited.finish_decline().expect("horizon work decline"),
            ContextDfaDecline {
                resource: ContextDfaResource::Work {
                    limit: work_limit,
                    required: exact_work,
                },
                work_completed: exact_work
                    .checked_sub(
                        u64::try_from(anchored.forward.initial.len())
                            .expect("initial context count fits u64")
                    )
                    .unwrap(),
                states_completed: 0,
                transitions_completed: 0,
            }
        );
    }

    #[test]
    fn anchored_resolution_horizon_is_graph_derived() {
        let (finite, _) = programs(r"(?-u:\b)abc(?-u:\b)", b'\n');
        assert_eq!(
            finite
                .native_view()
                .anchored_forward
                .expect("finite anchored sidecar")
                .max_resolution_steps,
            Some(3)
        );

        let (cyclic, _) = programs(r"(?-u:\b)a+", b'\n');
        assert_eq!(
            cyclic
                .native_view()
                .anchored_forward
                .expect("cyclic anchored sidecar")
                .max_resolution_steps,
            None
        );
    }

    #[test]
    fn configured_line_classification_covers_every_byte_value() {
        for line_terminator in u8::MIN..=u8::MAX {
            for byte in u8::MIN..=u8::MAX {
                let properties = byte_properties(byte, line_terminator);
                assert_eq!(
                    properties & PROPERTY_CONFIGURED_LINE != 0,
                    byte == line_terminator
                );
                assert_eq!(properties & PROPERTY_CR != 0, byte == b'\r');
                assert_eq!(properties & PROPERTY_LF != 0, byte == b'\n');
                assert_eq!(
                    properties & PROPERTY_ASCII_WORD != 0,
                    byte == b'_' || byte.is_ascii_alphanumeric()
                );
            }
        }
    }

    #[test]
    fn unicode_assertions_are_a_typed_structural_decline() {
        let mut profile = RustProfile::default();
        profile.options.unicode = true;
        let parsed = fre_syntax::parse(ParseRequest::rust(
            r"\b".to_owned(),
            CompatibilityProfile::RustBytes(profile),
        ))
        .expect("parse Unicode boundary");
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("Rust parse returned a non-Rust pattern");
        };
        let raw = fre_lower::lower_raw_general(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .expect("lower Unicode boundary")
        .into_plan();
        let outcome = determinize(&raw, b'\n', ContextDfaLimits::default())
            .expect("Unicode assertion must decline, not error");
        assert!(matches!(
            outcome,
            ContextDfaOutcome::Declined(ContextDfaDecline {
                resource: ContextDfaResource::UnsupportedAssertion(EdgeKind::AssertWordUnicode),
                ..
            })
        ));

        // Contextual compilation is an optional optimization. A structural
        // decline leaves the same validated graph eligible for the universal
        // engine; it is never a source-pattern rejection.
        let automaton = Automaton::from_raw(raw.clone(), CompileLimits::default())
            .expect("validate Unicode fallback")
            .with_line_terminator(b'\n');
        let fallback = CompiledProgram::build(
            raw,
            automaton,
            OutputContract::Span,
            CompileMode::Fast,
            DeterminizeLimits::default(),
            usize::MAX,
        )
        .expect("contextual decline must preserve universal compiler eligibility");
        assert_eq!(fallback.engine_kind(), EngineKind::OrderedNfa);
    }

    #[test]
    fn construction_limits_decline_without_partial_machine() {
        let (machine, _) = programs(r"(?m:^)(?:a|b)+$", b'\n');
        assert!(!machine.forward.states.is_empty());

        let mut profile = RustProfile::default();
        profile.options.line_terminator = b'\n';
        let parsed = fre_syntax::parse(ParseRequest::rust(
            r"(?m:^)(?:a|b)+$".to_owned(),
            CompatibilityProfile::RustBytes(profile),
        ))
        .expect("parse bounded graph");
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("Rust parse returned a non-Rust pattern");
        };
        let raw = fre_lower::lower_raw_general(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .expect("lower bounded graph")
        .into_plan();
        for limits in [
            ContextDfaLimits {
                max_states: 0,
                ..ContextDfaLimits::default()
            },
            ContextDfaLimits {
                max_transitions: 0,
                ..ContextDfaLimits::default()
            },
            ContextDfaLimits {
                max_work: 0,
                ..ContextDfaLimits::default()
            },
        ] {
            assert!(matches!(
                determinize(&raw, b'\n', limits).expect("bounded construction"),
                ContextDfaOutcome::Declined(_)
            ));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "canonical dispatch completeness, fixed rows, state flags, and clone identity form one native-view proof"
    )]
    fn native_view_is_flat_canonical_and_clone_exact() {
        let pattern = r"(?:(?mR:^)(?:ab|a)+?b(?mR:$)|(?-u:\bfoo\b))";
        let (first, _) = programs(pattern, b';');
        let (second, _) = programs(pattern, b';');
        let cloned = first.clone();
        let expected = first.native_view();
        for actual in [second.native_view(), cloned.native_view()] {
            assert_eq!(actual.initial_dispatch, expected.initial_dispatch);
            assert_eq!(actual.byte_classes, expected.byte_classes);
            assert_eq!(actual.class_representatives, expected.class_representatives);
            assert_eq!(actual.class_properties, expected.class_properties);
            assert_eq!(actual.forward_initial, expected.forward_initial);
            assert_eq!(actual.forward_states, expected.forward_states);
            assert_eq!(actual.forward_row_offsets, expected.forward_row_offsets);
            assert_eq!(actual.forward_cells, expected.forward_cells);
            assert_eq!(actual.reverse_initial, expected.reverse_initial);
            assert_eq!(actual.reverse_row_offsets, expected.reverse_row_offsets);
            assert_eq!(actual.reverse_cells, expected.reverse_cells);
            assert_eq!(actual.anchored_forward, expected.anchored_forward);
        }
        assert!(
            expected
                .forward_initial
                .windows(2)
                .all(|pair| pair[0].context < pair[1].context)
        );
        assert!(
            expected
                .reverse_initial
                .windows(2)
                .all(|pair| pair[0].context < pair[1].context)
        );
        let dispatch = expected.initial_dispatch;
        assert_eq!(dispatch.class_count, dispatch.sentinel_class);
        assert_eq!(
            dispatch.row_width,
            dispatch.class_count.checked_add(1).unwrap()
        );
        assert_eq!(dispatch.class_mask, 0x01ff);
        assert_eq!(dispatch.properties_mask, 0x0f);
        assert_eq!(dispatch.properties_shift, 9);
        assert_eq!(dispatch.present_bit, 1 << 13);
        assert_eq!(dispatch.absolute_start_bit, 1 << 14);
        assert_eq!(dispatch.absolute_end_bit, 1 << 15);
        assert!(
            expected
                .byte_classes
                .iter()
                .all(|&class| u32::from(class) < dispatch.class_count)
        );

        let width = usize::try_from(dispatch.row_width).unwrap();
        assert_eq!(first.stats().row_width, width);
        assert_eq!(expected.forward_states.len(), first.stats().forward_states);
        assert_eq!(
            expected.forward_cells.len(),
            expected.forward_states.len().checked_mul(width).unwrap()
        );
        assert_eq!(
            expected.reverse_cells.len(),
            first.stats().reverse_states.checked_mul(width).unwrap()
        );
        assert!(
            expected
                .forward_row_offsets
                .windows(2)
                .all(|pair| { pair[1].checked_sub(pair[0]) == Some(dispatch.row_width) })
        );
        assert!(
            expected
                .reverse_row_offsets
                .windows(2)
                .all(|pair| { pair[1].checked_sub(pair[0]) == Some(dispatch.row_width) })
        );
        assert_eq!(
            expected.forward_row_offsets.last().copied(),
            Some(u32::try_from(expected.forward_cells.len()).unwrap())
        );
        assert_eq!(
            expected.reverse_row_offsets.last().copied(),
            Some(u32::try_from(expected.reverse_cells.len()).unwrap())
        );

        let anchored = first
            .anchored_forward
            .as_ref()
            .expect("anchored forward sidecar");
        let native_anchored = expected
            .anchored_forward
            .expect("native anchored forward sidecar");
        assert_eq!(
            native_anchored.main_initial_to_anchored.len(),
            expected.forward_states.len()
        );
        assert_eq!(native_anchored.states, anchored.forward.native_states);
        assert_eq!(
            native_anchored.cells.len(),
            native_anchored.states.len().checked_mul(width).unwrap()
        );
        assert!(
            native_anchored
                .row_offsets
                .windows(2)
                .all(|pair| pair[1].checked_sub(pair[0]) == Some(dispatch.row_width))
        );
        assert_eq!(
            native_anchored.row_offsets.last().copied(),
            Some(u32::try_from(native_anchored.cells.len()).unwrap())
        );
        let mut unique_main_initials = first.forward.initial.values().copied().collect::<Vec<_>>();
        unique_main_initials.sort_unstable();
        unique_main_initials.dedup();
        assert_eq!(
            native_anchored
                .main_initial_to_anchored
                .iter()
                .filter(|&&state| state != u32::MAX)
                .count(),
            unique_main_initials.len()
        );
        for (&boundary, &main_state) in &first.forward.initial {
            let main_index = usize::try_from(main_state).unwrap();
            let anchored_state = native_anchored.main_initial_to_anchored[main_index];
            assert_ne!(anchored_state, u32::MAX);
            assert_eq!(
                anchored.forward.initial.get(&boundary),
                Some(&anchored_state)
            );
            assert_eq!(
                first.forward.native_states[main_index],
                anchored.forward.native_states[usize::try_from(anchored_state).unwrap()]
            );
        }

        for (state, (key, native)) in first
            .forward
            .states
            .iter()
            .zip(expected.forward_states)
            .enumerate()
        {
            assert_eq!(native.pending, key.pending);
            assert_eq!(native.empty, key.items.is_empty());
            assert_eq!(native.terminal, key.pending && key.items.is_empty());
            if native.terminal {
                let begin = state.checked_mul(width).unwrap();
                let end = begin.checked_add(width).unwrap();
                let state = u32::try_from(state).unwrap();
                assert!(
                    expected.forward_cells[begin..end]
                        .iter()
                        .all(|cell| cell.next == state && !cell.accepted)
                );
            }
        }
        assert!(expected.forward_initial.iter().all(|entry| {
            usize::try_from(entry.state).is_ok_and(|state| state < expected.forward_states.len())
        }));
        assert!(expected.reverse_initial.iter().all(|entry| {
            entry.state == u32::MAX
                || usize::try_from(entry.state)
                    .is_ok_and(|state| state < first.stats().reverse_states)
        }));

        let mut properties = expected.class_properties.to_vec();
        properties.sort_unstable();
        properties.dedup();
        let mut forward_contexts = Vec::new();
        forward_contexts.push(
            dispatch
                .pack(dispatch.sentinel_class, 0, false, true, true)
                .unwrap(),
        );
        for class in 0..dispatch.class_count {
            forward_contexts.push(dispatch.pack(class, 0, false, true, false).unwrap());
        }
        for &before_properties in &properties {
            for class in 0..dispatch.class_count {
                forward_contexts.push(
                    dispatch
                        .pack(class, before_properties, true, false, false)
                        .unwrap(),
                );
            }
            forward_contexts.push(
                dispatch
                    .pack(
                        dispatch.sentinel_class,
                        before_properties,
                        true,
                        false,
                        true,
                    )
                    .unwrap(),
            );
        }
        forward_contexts.sort_unstable();
        assert_eq!(
            forward_contexts,
            expected
                .forward_initial
                .iter()
                .map(|entry| entry.context)
                .collect::<Vec<_>>()
        );

        let mut reverse_contexts = Vec::new();
        reverse_contexts.push(
            dispatch
                .pack(dispatch.sentinel_class, 0, false, true, true)
                .unwrap(),
        );
        for &current_properties in &properties {
            reverse_contexts.push(
                dispatch
                    .pack(
                        dispatch.sentinel_class,
                        current_properties,
                        true,
                        true,
                        false,
                    )
                    .unwrap(),
            );
        }
        for before in 0..dispatch.class_count {
            for &current_properties in &properties {
                reverse_contexts.push(
                    dispatch
                        .pack(before, current_properties, true, false, false)
                        .unwrap(),
                );
            }
            reverse_contexts.push(dispatch.pack(before, 0, false, false, true).unwrap());
        }
        reverse_contexts.sort_unstable();
        assert_eq!(
            reverse_contexts,
            expected
                .reverse_initial
                .iter()
                .map(|entry| entry.context)
                .collect::<Vec<_>>()
        );
        assert_eq!(first.stats(), second.stats());
        assert_eq!(first.stats(), cloned.stats());
    }
}
