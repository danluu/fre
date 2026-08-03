use core::{fmt, mem::size_of};

use fre_simd_kernels::{
    classify_byte_delta_16, AsciiByteSet, AsciiByteSetClassifier, ByteSet256, ByteSetClassifier,
    ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, BYTE_SET_BLOCK_BYTES,
};
use memchr::{memchr, memchr2, memchr3};

use crate::{
    k0_root_corridor::{
        inspect_root_run_accounted, member_prefix_length, qualifying_start_mask,
        root_corridor_member_window, root_run_inspection_work, take_first_qualified_start,
        RootRunDescriptor, ROOT_CORRIDOR_MASK_MAXIMUM_MINIMUM,
    },
    plan::{
        BoundaryContextClassifier, ByteSet, StartAsciiClassifier, StartByteSetClassifier,
        StartFilterProof, StartFilterProofCell, StartFilterPublication, StartPositionClass,
        StartPositionFilter, StartPositionScanner, StartScanner,
        BYTE_START_ASCII_CLASSIFIER_SELECTION_WORK, BYTE_START_BITMAP_POPULATION_WORK,
        BYTE_START_MEMBER_EXTRACTION_WORK, BYTE_START_RANGE_DETECTION_WORK,
        BYTE_START_SET_CLASSIFIER_BUILD_WORK, BYTE_START_SMALL_MAX_MEMBERS,
        START_FILTER_GUARD_MAX_CARDINALITY, START_FILTER_GUARD_SELECTION_WORK,
        START_FILTER_POSITION_COUNT, START_FILTER_PROBE_SELECTION_WORK,
        START_FILTER_SCANNER_SELECTION_WORK,
    },
    Automaton, EdgeKind, MatchSpan, OutputContract, ResourceKind, SearchAccounting, SearchError,
    SearchLimits, SearchWindow, SetupAccounting, StateRole, UnicodeLookMatcher,
};

const INVOCATION_RESET_WORK: u64 = 3;
// A contextual bidirectional invocation consumes at most three generations
// per source byte plus the fixed boundary and cold start-proof closures. Use
// that universal ceiling while the retained generation is comfortably below
// rollover, avoiding mode-dependent bound reconstruction on ordinary inputs.
const GENERATION_FAST_WINDOW_MAX: usize = 4_294_967_295;
const _: () = assert!(START_FILTER_POSITION_COUNT == 16);
const GENERATION_FAST_RESERVE: u64 = 3 * 4_294_967_295 + 16 + 3;
const START_FILTER_OWNER_ALLOCATION_WORK: u64 = 1;
const ROOT_RUN_WINDOW_BYTES: usize = 64;
const ROOT_RUN_SCANNER_SHAPE_MAX_WORK: usize =
    BYTE_START_BITMAP_POPULATION_WORK + BYTE_START_RANGE_DETECTION_WORK;
const ORDINARY_START_FILTER_PROOF: StartFilterProof = StartFilterProof {
    scanner: None,
    filter: None,
    force_haystack_start: false,
    // Conservatively decline contextual acceleration when an allocation
    // failure permanently disables the optional retained proof.
    relaxed_nullable: true,
};
const BYTE_ALPHABET: usize = 256;
const DIRECT_ROW_STRIDE: u32 = 256;
const _: () = assert!(BYTE_ALPHABET == 1 << 8);
// Prepared compiled searches are deliberately allowed a larger bounded
// determinization frontier than the original L1-sized cache. A direct row is
// still only touched for the current state, while retaining more identities
// avoids falling back to an ordered closure on every subsequent byte once a
// moderately branching unbounded expression crosses 64 subsets.
const LAZY_MAX_STATES: usize = 256;
const _: () = assert!(LAZY_MAX_STATES <= usize::MAX / BYTE_ALPHABET);
const LAZY_MAX_ITEMS: usize = 16_384;
const EXACT_LAZY_CAPACITY_MAX_ITEMS: usize = 3;
const LAZY_CELL_ACCEPT: u32 = 1 << 31;
const LAZY_CELL_RESTART: u32 = 1 << 30;
// Direct non-context cells use the two bits below as a three-way provenance
// action. Contextual cells retain `LAZY_CELL_RESTART` with its existing
// meaning and leave `LAZY_CELL_START_PROPAGATE` clear; reverse cells leave
// both clear. Even after reserving the extra bit, the encoded direct-row
// ceiling is orders of magnitude below the remaining state field.
const LAZY_CELL_START_PROPAGATE: u32 = 1 << 29;
const LAZY_CELL_STATE_MASK: u32 = LAZY_CELL_START_PROPAGATE - 1;
const LAZY_CELL_UNFILLED: u32 = u32::MAX;
const LAZY_NO_STATE: u32 = u32::MAX;
#[cfg(test)]
const ASSERTION_KIND_COUNT: usize = 18;
const CONTEXT_SYMBOL_BYTE_BITS: u32 = 9;
const CONTEXT_INITIAL_BYTE: u32 = 256;
const CONTEXT_TRANSITION_WAYS: usize = 4;
const CONTEXT_TRANSITION_MAX_SLOTS: usize = LAZY_MAX_STATES * BYTE_ALPHABET;
const CONTEXT_TRANSITION_MAX_BUCKETS: usize =
    CONTEXT_TRANSITION_MAX_SLOTS / CONTEXT_TRANSITION_WAYS;
const CONTEXT_EMPTY_SOURCE: u32 = u32::MAX;
const CONTEXT_INITIAL_SOURCE: u32 = u32::MAX - 1;

/// Index one direct byte row after its source state has been authenticated.
///
/// Every direct lazy arena is constructed with at most `LAZY_MAX_STATES`
/// rows, and state publication never exceeds that fixed capacity. The const
/// assertion above therefore proves this multiply/add cannot overflow. Keeping
/// that shape proof outside the warmed transition loop removes the remaining
/// fallible arithmetic branch from every warmed input byte; the final slice
/// lookup still diagnoses a broken physical layout.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the fixed lazy-state ceiling and byte alphabet prove the row index fits usize"
)]
fn direct_row_cell_index(state: usize, byte: u8) -> usize {
    debug_assert!(state < LAZY_MAX_STATES);
    state * BYTE_ALPHABET + usize::from(byte)
}

/// Authenticate one direct-row source once, before entering a warmed loop.
///
/// Direct transition cells retain `row_offset + 1` rather than `state + 1`.
/// The zero value therefore remains the dead transition while a warmed edge
/// can feed its decoded value directly to [`LazyWorkspace::direct_cell`] or
/// [`ReverseWorkspace::direct_cell`] without rebuilding `state * 256`.
fn direct_row_offset(state: u32) -> Result<u32, SearchError> {
    let state = usize::try_from(state).map_err(|_| SearchError::InternalInvariant {
        detail: "direct lazy state does not fit usize",
    })?;
    if state >= LAZY_MAX_STATES {
        return Err(SearchError::InternalInvariant {
            detail: "direct lazy state is outside the cache ceiling",
        });
    }
    u32::try_from(direct_row_cell_index(state, 0)).map_err(|_| SearchError::InternalInvariant {
        detail: "direct lazy row offset does not fit u32",
    })
}

fn direct_row_encoded_state(state: u32) -> Result<u32, SearchError> {
    direct_row_offset(state)?
        .checked_add(1)
        .filter(|encoded| *encoded <= LAZY_CELL_STATE_MASK)
        .ok_or(SearchError::InternalInvariant {
            detail: "direct lazy row encoding exceeds its cell field",
        })
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "authenticated direct row offsets are exact multiples of the fixed stride"
)]
fn direct_row_state(row_offset: u32) -> u32 {
    debug_assert_eq!(row_offset % DIRECT_ROW_STRIDE, 0);
    row_offset / DIRECT_ROW_STRIDE
}

#[cfg(test)]
const ASSERTION_KINDS: [EdgeKind; ASSERTION_KIND_COUNT] = [
    EdgeKind::AssertHaystackStart,
    EdgeKind::AssertHaystackEnd,
    EdgeKind::AssertLineStartLf,
    EdgeKind::AssertLineEndLf,
    EdgeKind::AssertLineStartCrlf,
    EdgeKind::AssertLineEndCrlf,
    EdgeKind::AssertWordAscii,
    EdgeKind::AssertWordAsciiNegate,
    EdgeKind::AssertWordStartAscii,
    EdgeKind::AssertWordEndAscii,
    EdgeKind::AssertWordStartHalfAscii,
    EdgeKind::AssertWordEndHalfAscii,
    EdgeKind::AssertWordUnicode,
    EdgeKind::AssertWordUnicodeNegate,
    EdgeKind::AssertWordStartUnicode,
    EdgeKind::AssertWordEndUnicode,
    EdgeKind::AssertWordStartHalfUnicode,
    EdgeKind::AssertWordEndHalfUnicode,
];

const ABSOLUTE_ENABLED_BY_CLASS: [u32; 4] = [0, 1 << 0, 1 << 1, (1 << 0) | (1 << 1)];
const CONFIGURED_LINE_ENABLED_BY_CLASS: [u32; 4] = [0, 1 << 2, 1 << 3, (1 << 2) | (1 << 3)];
const CRLF_LINE_ENABLED_BY_CLASS: [u32; 4] = [0, 1 << 4, 1 << 5, (1 << 4) | (1 << 5)];
const ASCII_WORD_ENABLED_BY_CLASS: [u32; 4] = [
    (1 << 7) | (1 << 10) | (1 << 11),
    (1 << 6) | (1 << 9) | (1 << 11),
    (1 << 6) | (1 << 8) | (1 << 10),
    1 << 7,
];
const UNICODE_WORD_ENABLED_BY_CLASS: [u32; 9] = [
    0,
    1 << 16,
    (1 << 12) | (1 << 15),
    1 << 17,
    (1 << 13) | (1 << 16) | (1 << 17),
    (1 << 12) | (1 << 15) | (1 << 17),
    (1 << 12) | (1 << 14),
    (1 << 12) | (1 << 14) | (1 << 16),
    1 << 13,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContextTransitionSlot {
    source: u32,
    symbol: u32,
    value: u32,
}

impl ContextTransitionSlot {
    const EMPTY: Self = Self {
        source: CONTEXT_EMPTY_SOURCE,
        symbol: 0,
        value: 0,
    };

    const fn populated(source: u32, symbol: u32, value: u32) -> Self {
        Self {
            source,
            symbol,
            value,
        }
    }
}

struct ContextTransitionStore {
    slots: Vec<ContextTransitionSlot>,
    bucket_mask: usize,
}

impl fmt::Debug for ContextTransitionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let buckets = if self.slots.is_empty() {
            0
        } else {
            self.bucket_mask.saturating_add(1)
        };
        formatter
            .debug_struct("ContextTransitionStore")
            .field("slots", &self.slots.len())
            .field("buckets", &buckets)
            .field("occupied", &self.occupied_slots())
            .finish()
    }
}

impl ContextTransitionStore {
    fn new(slot_count: usize, total_bytes: usize) -> Result<Self, SearchError> {
        let bucket_mask = contextual_transition_bucket_mask(slot_count)?;
        Ok(Self {
            slots: allocate_slots(slot_count, ContextTransitionSlot::EMPTY, total_bytes)?,
            bucket_mask,
        })
    }

    const fn disabled() -> Self {
        Self {
            slots: Vec::new(),
            bucket_mask: 0,
        }
    }

    fn is_allocated(&self) -> bool {
        !self.slots.is_empty()
    }

    fn occupied_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.source != CONTEXT_EMPTY_SOURCE)
            .count()
    }

    fn retained_bytes(&self) -> Result<usize, SearchError> {
        capacity_bytes::<ContextTransitionSlot>(&self.slots, "contextual transition cache bytes")
    }

    fn lookup(
        &self,
        source: u32,
        symbol: u32,
        meter: &mut WorkMeter,
        position: usize,
    ) -> Result<(Option<u32>, Option<usize>), SearchError> {
        let expected_slots = self
            .bucket_mask
            .checked_add(1)
            .and_then(|buckets| buckets.checked_mul(CONTEXT_TRANSITION_WAYS))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "contextual transition store shape",
            })?;
        if self.slots.is_empty()
            || self.slots.len() != expected_slots
            || self.slots.len() > CONTEXT_TRANSITION_MAX_SLOTS
        {
            return Err(SearchError::InternalInvariant {
                detail: "contextual transition store has an invalid bucket shape",
            });
        }
        meter.charge(1, position)?;
        let bucket = contextual_transition_hash(source, symbol) & self.bucket_mask;
        let begin =
            bucket
                .checked_mul(CONTEXT_TRANSITION_WAYS)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "contextual transition bucket",
                })?;
        let mut empty = None;
        for way in 0..CONTEXT_TRANSITION_WAYS {
            meter.charge(1, position)?;
            let index = begin
                .checked_add(way)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "contextual transition way",
                })?;
            let slot = *self
                .slots
                .get(index)
                .ok_or(SearchError::InternalInvariant {
                    detail: "contextual transition way is outside the fixed store",
                })?;
            if slot.source == source && slot.symbol == symbol {
                return Ok((Some(slot.value), None));
            }
            if slot.source == CONTEXT_EMPTY_SOURCE {
                empty = Some(index);
                break;
            }
        }
        Ok((None, empty))
    }

    fn publish(
        &mut self,
        index: Option<usize>,
        record: ContextTransitionSlot,
        meter: &mut WorkMeter,
        core_reserve: u64,
        position: usize,
    ) -> Result<(), SearchError> {
        let Some(index) = index else {
            return Ok(());
        };
        if meter.remaining() <= core_reserve {
            return Ok(());
        }
        meter.charge(1, position)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(SearchError::InternalInvariant {
                detail: "contextual transition publication is outside the fixed store",
            })?;
        if slot.source == CONTEXT_EMPTY_SOURCE {
            *slot = record;
        }
        Ok(())
    }
}

// Reserve one byte transition per exact potential lazy state, then round the
// four-way bucket domain up for masking. The proof depends only on immutable
// graph shape; a full bucket still executes through the bounded inline path.
fn contextual_transition_slots(state_capacity: usize) -> Result<usize, SearchError> {
    if state_capacity == 0 {
        return Ok(0);
    }
    let bounded_states = state_capacity.min(LAZY_MAX_STATES);
    let desired_slots =
        bounded_states
            .checked_mul(BYTE_ALPHABET)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "contextual transition desired slots",
            })?;
    let desired_buckets = desired_slots.div_ceil(CONTEXT_TRANSITION_WAYS);
    let bucket_count = desired_buckets
        .checked_next_power_of_two()
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "contextual transition bucket rounding",
        })?
        .min(CONTEXT_TRANSITION_MAX_BUCKETS);
    bucket_count
        .checked_mul(CONTEXT_TRANSITION_WAYS)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "contextual transition slots",
        })
}

fn contextual_transition_bucket_mask(slot_count: usize) -> Result<usize, SearchError> {
    if slot_count == 0 {
        return Ok(0);
    }
    if slot_count > CONTEXT_TRANSITION_MAX_SLOTS || slot_count % CONTEXT_TRANSITION_WAYS != 0 {
        return Err(SearchError::InternalInvariant {
            detail: "contextual transition store has an invalid slot count",
        });
    }
    let bucket_count = slot_count / CONTEXT_TRANSITION_WAYS;
    if !bucket_count.is_power_of_two() {
        return Err(SearchError::InternalInvariant {
            detail: "contextual transition store bucket count is not a power of two",
        });
    }
    bucket_count
        .checked_sub(1)
        .ok_or(SearchError::InternalInvariant {
            detail: "contextual transition store has no buckets",
        })
}

fn contextual_transition_hash(source: u32, symbol: u32) -> usize {
    let key = u64::from(symbol) ^ (u64::from(source) << 32);
    let mixed = key.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let folded = (mixed ^ (mixed >> 32)) & u64::from(u32::MAX);
    usize::try_from(folded).expect("folded context hash fits usize")
}

const fn contextual_symbol(byte: u32, assertions: u32) -> u32 {
    byte | (assertions << CONTEXT_SYMBOL_BYTE_BITS)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceMode {
    Pike,
    Endpoints,
    Bidirectional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SpanCursorBinding {
    automaton_identity: u64,
    limits: SearchLimits,
}

// The cursor may borrow only the automaton-owned proof or the static decline.
// A proof whose optional owner was resource-refused remains unprepared, so the
// next search repeats and charges derivation instead of retaining hidden work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum SpanCursorStartProof {
    #[default]
    Unprepared,
    AutomatonOwned,
    Ordinary,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LazyCapabilities {
    lazy: bool,
    reverse: bool,
    contextual: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct EffectiveLazyMode {
    lazy: bool,
    reverse: bool,
}

// A zero-sized proof that the direct lazy initial row is ready for this
// invocation. Only leftmost-first reducers retain this proof across the
// preparation/loop boundary; first-accept reducers use the ordinary
// preparation entry so they do not carry a readiness mode through their short
// path.
#[derive(Clone, Copy, Debug)]
struct DirectLazyReady;

// One ordinary execution loop may revisit a complete classifier block after
// a guard or DFA restart rejects its first member. Retain only the unconsumed
// lanes from that already charged block. This cursor is deliberately created
// by the loop itself: it never crosses a search call, fallback, source, or
// workspace boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RetainedStartMaskCursor {
    base: usize,
    width: u8,
    members: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetainedStartCandidate {
    Unavailable,
    Candidate(usize),
    ResumeAt(usize),
}

impl RetainedStartMaskCursor {
    const fn clear(&mut self) {
        self.base = 0;
        self.width = 0;
        self.members = 0;
    }

    fn take(&mut self, position: usize, end: usize) -> Result<RetainedStartCandidate, SearchError> {
        if self.width == 0 {
            return Ok(RetainedStartCandidate::Unavailable);
        }
        let width = usize::from(self.width);
        let block_end = self
            .base
            .checked_add(width)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "retained start-mask block end",
            })?;
        if position < self.base || position >= block_end {
            self.clear();
            return Ok(RetainedStartCandidate::Unavailable);
        }
        if block_end > end {
            return Err(SearchError::InternalInvariant {
                detail: "retained start-mask block exceeded the validated search window",
            });
        }

        let relative = position
            .checked_sub(self.base)
            .ok_or(SearchError::InternalInvariant {
                detail: "retained start-mask position preceded its block",
            })?;
        self.members &= u64::MAX
            .checked_shl(u32::try_from(relative).expect("classifier lane fits u32"))
            .unwrap_or(0);
        if self.members == 0 {
            self.clear();
            return Ok(RetainedStartCandidate::ResumeAt(block_end));
        }

        let lane = usize::try_from(self.members.trailing_zeros())
            .expect("a retained classifier lane fits usize");
        if lane >= width {
            return Err(SearchError::InternalInvariant {
                detail: "retained start-mask member exceeded its complete block",
            });
        }
        let candidate = self
            .base
            .checked_add(lane)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "retained start-mask candidate",
            })?;
        if candidate < position || candidate >= end {
            return Err(SearchError::InternalInvariant {
                detail: "retained start-mask candidate escaped its monotone search window",
            });
        }
        self.members &= self
            .members
            .checked_sub(1)
            .expect("a selected retained start-mask member is nonzero");
        Ok(RetainedStartCandidate::Candidate(candidate))
    }

    fn retain_complete_block(
        &mut self,
        base: usize,
        width: usize,
        members: u64,
        end: usize,
    ) -> Result<usize, SearchError> {
        let maximum_width = usize::try_from(u64::BITS).expect("u64 bit width fits usize");
        if width == 0 || width > maximum_width || members == 0 {
            return Err(SearchError::InternalInvariant {
                detail: "invalid complete start-mask block was retained",
            });
        }
        let block_end = base
            .checked_add(width)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "retained complete start-mask block end",
            })?;
        if block_end > end {
            return Err(SearchError::InternalInvariant {
                detail: "incomplete start-mask classifier block was retained",
            });
        }
        let unused = u64::BITS
            .checked_sub(u32::try_from(width).expect("classifier width fits u32"))
            .ok_or(SearchError::InternalInvariant {
                detail: "retained start-mask width exceeded its mask",
            })?;
        let valid = u64::MAX.checked_shr(unused).unwrap_or(u64::MAX);
        if members & !valid != 0 {
            return Err(SearchError::InternalInvariant {
                detail: "retained start-mask contained a lane outside its classifier block",
            });
        }
        self.base = base;
        self.width = u8::try_from(width).expect("classifier width fits u8");
        self.members = members;
        match self.take(base, end)? {
            RetainedStartCandidate::Candidate(candidate) => Ok(candidate),
            RetainedStartCandidate::Unavailable | RetainedStartCandidate::ResumeAt(_) => {
                Err(SearchError::InternalInvariant {
                    detail: "nonempty retained start-mask block had no first candidate",
                })
            }
        }
    }
}

// Source-independent facts that are invariant across suffix searches using
// one workspace. Haystack bytes, the changing start, and the effective
// forward/reverse mode remain call-local. In particular, preparing a direct
// nullable initial row can prove the next span's start and remove the need for
// reverse recovery without invalidating this cache.
#[derive(Clone, Copy, Debug, Default)]
struct SpanCursorCache {
    binding: Option<SpanCursorBinding>,
    start_proof: SpanCursorStartProof,
    capabilities: LazyCapabilities,
}

#[derive(Clone, Copy, Debug, Default)]
struct Thread {
    state: u32,
    start: usize,
}

pub(crate) struct UntypedReport {
    pub(crate) found: Option<MatchSpan>,
    pub(crate) accounting: SearchAccounting,
}

// Source-derived masks may cross only calls made by one iterator that owns
// this exact immutable borrow. Keeping them out of `K0SearchSession` avoids a
// pointer/length identity check (and its ABA hole) when a reusable session is
// later paired with another haystack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootRunBlockCursor {
    automaton_identity: u64,
    base: usize,
    members: u64,
    valid_bytes: u8,
    qualified_starts: u32,
    activation_at: usize,
}

impl Default for RootRunBlockCursor {
    fn default() -> Self {
        Self {
            automaton_identity: 0,
            base: 0,
            members: 0,
            valid_bytes: 0,
            qualified_starts: 0,
            activation_at: usize::MAX,
        }
    }
}

impl RootRunBlockCursor {
    const fn clear(&mut self) {
        *self = Self::empty();
    }

    const fn clear_members(&mut self) {
        self.base = 0;
        self.members = 0;
        self.valid_bytes = 0;
        self.qualified_starts = 0;
    }

    const fn empty() -> Self {
        Self {
            automaton_identity: 0,
            base: 0,
            members: 0,
            valid_bytes: 0,
            qualified_starts: 0,
            activation_at: usize::MAX,
        }
    }

    const fn arm(&mut self, automaton_identity: u64, position: usize) {
        self.clear_members();
        self.automaton_identity = automaton_identity;
        self.activation_at = position;
    }
}

/// Lifetime-bound source state for repeated span searches by one iterator.
///
/// The cursor owns the immutable haystack borrow so source-derived masks
/// cannot accidentally survive a change of source in a reusable K0 session.
/// It is intentionally opaque outside this crate.
#[derive(Debug)]
pub struct K0SpanSourceCursor<'h> {
    haystack: &'h [u8],
    root_run: RootRunBlockCursor,
}

impl<'h> K0SpanSourceCursor<'h> {
    /// Bind an empty cursor to one exact immutable haystack.
    #[doc(hidden)]
    #[must_use]
    pub const fn new(haystack: &'h [u8]) -> Self {
        Self {
            haystack,
            root_run: RootRunBlockCursor::empty(),
        }
    }

    /// The exact source borrow authenticated by this cursor.
    #[doc(hidden)]
    #[must_use]
    pub const fn haystack(&self) -> &'h [u8] {
        self.haystack
    }
}

/// Fixed logical dimensions needed by the K0 executor for one automaton shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceLayout {
    states: usize,
    edges: usize,
    zero_width_edges: usize,
    closure_slots: usize,
    lazy_state_capacity: usize,
    lazy_item_capacity: usize,
    lazy_context_slots: usize,
    reverse_state_capacity: usize,
    reverse_item_capacity: usize,
    reverse_context_slots: usize,
    logical_bytes: usize,
    initialized_bytes: usize,
    construction_work: u64,
}

impl WorkspaceLayout {
    pub(crate) fn for_automaton(automaton: &Automaton) -> Result<Self, SearchError> {
        Self::for_automaton_mode(automaton, WorkspaceMode::Pike)
    }

    pub(crate) fn for_accelerated_automaton(automaton: &Automaton) -> Result<Self, SearchError> {
        Self::for_automaton_mode(automaton, WorkspaceMode::Endpoints)
    }

    pub(crate) fn for_bidirectional_automaton(automaton: &Automaton) -> Result<Self, SearchError> {
        Self::for_automaton_mode(automaton, WorkspaceMode::Bidirectional)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one source-free transaction authenticates all three nested workspace layouts"
    )]
    fn for_automaton_mode(automaton: &Automaton, mode: WorkspaceMode) -> Result<Self, SearchError> {
        let states = automaton.stats().states();
        let edges = automaton.stats().edges();
        let zero_width_edges = automaton.stats().zero_width_edges();
        let closure_slots =
            zero_width_edges
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "closure stack capacity",
                })?;
        let (lazy_state_capacity, lazy_item_capacity) = if mode == WorkspaceMode::Pike {
            (0, 0)
        } else {
            lazy_capacities(automaton)?
        };
        let lazy_context_slots =
            if lazy_state_capacity != 0 && automaton.stats().assertion_edges() != 0 {
                contextual_transition_slots(lazy_state_capacity)?
            } else {
                0
            };
        let (reverse_state_capacity, reverse_item_capacity) =
            if mode == WorkspaceMode::Bidirectional && lazy_state_capacity != 0 {
                reverse_capacities(automaton)?
            } else {
                (0, 0)
            };
        let reverse_context_slots =
            if reverse_state_capacity != 0 && automaton.stats().assertion_edges() != 0 {
                contextual_transition_slots(reverse_state_capacity)?
            } else {
                0
            };
        let pike_bytes = scratch_bytes(states, edges, closure_slots)?;
        let lazy_bytes = lazy_scratch_bytes(
            states,
            lazy_state_capacity,
            lazy_item_capacity,
            lazy_context_slots,
        )?;
        let reverse_bytes = reverse_scratch_bytes(
            states,
            edges,
            reverse_state_capacity,
            reverse_item_capacity,
            reverse_context_slots,
        )?;
        let logical_bytes = pike_bytes
            .checked_add(lazy_bytes)
            .and_then(|value| value.checked_add(reverse_bytes))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "workspace logical bytes",
            })?;
        let reverse_rewrite_bytes = if reverse_state_capacity == 0 {
            0
        } else {
            let state_rewrite_bytes = size_of::<u64>()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(size_of::<u32>()))
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "reverse CSR state rewrite bytes",
                })?;
            let edge_rewrite_bytes = size_of::<u64>()
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(size_of::<u32>()))
                .and_then(|bytes| bytes.checked_add(2))
                .and_then(|bytes| {
                    if reverse_context_slots == 0 {
                        Some(bytes)
                    } else {
                        bytes.checked_add(size_of::<EdgeKind>())
                    }
                })
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "reverse CSR edge rewrite bytes",
                })?;
            states
                .checked_mul(state_rewrite_bytes)
                .and_then(|bytes| {
                    edges
                        .checked_mul(edge_rewrite_bytes)
                        .and_then(|edges| bytes.checked_add(edges))
                })
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "reverse CSR rewrite bytes",
                })?
        };
        let initialized_bytes = logical_bytes.checked_add(reverse_rewrite_bytes).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "workspace initialized bytes",
            },
        )?;
        let pike_initialized_slots = states
            .checked_add(states)
            .and_then(|value| value.checked_add(edges))
            .and_then(|value| value.checked_add(closure_slots))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "workspace initialized slots",
            })?;
        let lazy_initialized_slots = lazy_initialized_slots(
            states,
            lazy_state_capacity,
            lazy_item_capacity,
            lazy_context_slots,
        )?;
        let reverse_initialized_slots = reverse_initialized_slots(
            states,
            edges,
            reverse_state_capacity,
            reverse_item_capacity,
            reverse_context_slots,
        )?;
        let initialized_slots = pike_initialized_slots
            .checked_add(lazy_initialized_slots)
            .and_then(|value| value.checked_add(reverse_initialized_slots))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "workspace initialized slots",
            })?;
        let pike_allocations = usize::from(states != 0)
            .checked_add(usize::from(states != 0))
            .and_then(|value| value.checked_add(usize::from(edges != 0)))
            .and_then(|value| value.checked_add(usize::from(closure_slots != 0)))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "workspace allocation count",
            })?;
        let lazy_allocations = if lazy_state_capacity == 0 {
            0
        } else {
            // The contextual store replaces the direct-row allocation.
            7usize
                .checked_add(usize::from(lazy_item_capacity != 0))
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "lazy workspace allocation count",
                })?
        };
        let reverse_allocations = if reverse_state_capacity == 0 {
            0
        } else {
            // Context replaces rows and additionally retains incoming kinds.
            11usize
                .checked_add(usize::from(reverse_context_slots != 0))
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "reverse workspace allocation count",
                })?
        };
        let non_empty_allocations = pike_allocations
            .checked_add(lazy_allocations)
            .and_then(|value| value.checked_add(reverse_allocations))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "workspace allocation count",
            })?;
        let reverse_build_work = if reverse_state_capacity == 0 {
            0
        } else {
            states
                .checked_mul(3)
                .and_then(|value| {
                    edges
                        .checked_mul(2)
                        .and_then(|edges| value.checked_add(edges))
                })
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "reverse CSR construction work",
                })?
        };
        let construction_operations = initialized_slots
            .checked_add(non_empty_allocations)
            .and_then(|value| value.checked_add(reverse_build_work))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "workspace construction work",
            })?;
        let construction_work = u64::try_from(construction_operations).map_err(|_| {
            SearchError::ArithmeticOverflow {
                computation: "workspace construction work conversion",
            }
        })?;
        Ok(Self {
            states,
            edges,
            zero_width_edges,
            closure_slots,
            lazy_state_capacity,
            lazy_item_capacity,
            lazy_context_slots,
            reverse_state_capacity,
            reverse_item_capacity,
            reverse_context_slots,
            logical_bytes,
            initialized_bytes,
            construction_work,
        })
    }

    /// Number of automaton states for which generation/current slots exist.
    #[must_use]
    pub const fn states(self) -> usize {
        self.states
    }

    /// Number of next-boundary root slots.
    #[must_use]
    pub const fn edges(self) -> usize {
        self.edges
    }

    /// Number of zero-width edges in the compatible automaton shape.
    #[must_use]
    pub const fn zero_width_edges(self) -> usize {
        self.zero_width_edges
    }

    /// Number of fixed closure-stack slots.
    #[must_use]
    pub const fn closure_slots(self) -> usize {
        self.closure_slots
    }

    /// Required heap payload before allocator capacity rounding.
    #[must_use]
    pub const fn logical_bytes(self) -> usize {
        self.logical_bytes
    }

    /// Exact logical constructor charge for this layout.
    #[must_use]
    pub const fn construction_work(self) -> u64 {
        self.construction_work
    }
}

/// Hard limits applied while explicitly constructing reusable K0 workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceLimits {
    /// Maximum logical operations allowed during workspace construction.
    pub max_setup_work: u64,
    /// Maximum retained heap payload bytes.
    pub max_scratch_bytes: usize,
}

impl WorkspaceLimits {
    /// Limits that accept every representable workspace layout.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_setup_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }
}

impl Default for WorkspaceLimits {
    fn default() -> Self {
        Self {
            max_setup_work: 2_000_000,
            max_scratch_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LazyInterned {
    State(u32),
    BudgetDeclined,
    CapacityFull,
}

fn validate_lazy_capacity_full(
    item_universe: usize,
    detail: &'static str,
) -> Result<(), SearchError> {
    // Through three distinct consuming items, every ordered subset, pending
    // mode, and reachable empty identity fits below LAZY_MAX_STATES. The
    // corresponding aggregate item arena is exact as well. CapacityFull in
    // that regime therefore proves a broken layout or cache invariant rather
    // than ordinary bounded-cache saturation.
    if item_universe <= EXACT_LAZY_CAPACITY_MAX_ITEMS {
        return Err(SearchError::InternalInvariant { detail });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LazyTransition {
    Ready(u32),
    Inline { accepted: bool, pending: bool },
}

/// Source-independent effect of one non-context direct transition on a
/// runtime proof that every active thread has the same match start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LazyStartAction {
    /// Source and injected-root provenance coexist, or no live provenance is
    /// available. A scalar start cannot be authenticated.
    Drop,
    /// Every retained thread and any acceptance came from the source
    /// frontier, so an authenticated scalar remains exact.
    Propagate,
    /// The source frontier became empty before the unanchored root was
    /// injected. Every retained thread starts at the new boundary.
    Reset,
}

impl LazyStartAction {
    const fn cell_bits(self) -> u32 {
        match self {
            Self::Drop => 0,
            Self::Propagate => LAZY_CELL_START_PROPAGATE,
            Self::Reset => LAZY_CELL_RESTART,
        }
    }

    const fn from_direct_cell(cell: u32) -> Self {
        match cell & (LAZY_CELL_START_PROPAGATE | LAZY_CELL_RESTART) {
            LAZY_CELL_START_PROPAGATE => Self::Propagate,
            LAZY_CELL_RESTART => Self::Reset,
            _ => Self::Drop,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LazyState {
    Cached(u32),
    Inline { pending: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContextLazyTransition {
    Ready(u32),
    Inline {
        accepted: bool,
        pending: bool,
        restartable: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReverseTransition {
    Ready(u32),
    Inline { reaches_start: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReverseState {
    Cached(u32),
    Inline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LazyInitialKind {
    Uninitialized,
    Positive,
    PositiveSingle,
    NullablePrefix,
    NullableTerminal,
}

/// Fixed ordered-subset rows owned by one exact immutable automaton session.
///
/// `modes` makes the pending selected-end bit part of state identity. The
/// transition graph is consequently contract-neutral: existence and
/// earliest-end stop on a cell's acceptance bit, while selected-end follows
/// the same row until the higher-priority retained prefix dies. Full-span
/// recovery is deliberately outside this first forward-only slice.
#[derive(Debug)]
struct LazyWorkspace {
    automaton_identity: u64,
    scratch: Vec<u32>,
    scratch_len: usize,
    frontier: Vec<u32>,
    frontier_len: usize,
    rows: Vec<u32>,
    context: ContextTransitionStore,
    offsets: Vec<usize>,
    lengths: Vec<u32>,
    modes: Vec<u8>,
    hashes: Vec<u64>,
    items: Vec<u32>,
    state_len: usize,
    item_len: usize,
    initial: u32,
    initial_kind: LazyInitialKind,
    inline_start_action: LazyStartAction,
    initialized: bool,
    declined: bool,
    saturated: bool,
}

impl LazyWorkspace {
    fn new(
        automaton: &Automaton,
        layout: WorkspaceLayout,
        total_bytes: usize,
    ) -> Result<Self, SearchError> {
        let state_capacity = layout.lazy_state_capacity;
        let item_capacity = layout.lazy_item_capacity;
        if state_capacity == 0 {
            return Ok(Self::disabled());
        }
        let row_cells = if layout.lazy_context_slots == 0 {
            state_capacity
                .checked_mul(BYTE_ALPHABET)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "lazy DFA row cells",
                })?
        } else {
            0
        };
        Ok(Self {
            automaton_identity: automaton.identity(),
            scratch: allocate_slots(layout.states, 0_u32, total_bytes)?,
            scratch_len: 0,
            frontier: allocate_slots(layout.states, 0_u32, total_bytes)?,
            frontier_len: 0,
            rows: allocate_slots(row_cells, LAZY_CELL_UNFILLED, total_bytes)?,
            context: ContextTransitionStore::new(layout.lazy_context_slots, total_bytes)?,
            offsets: allocate_slots(state_capacity, 0_usize, total_bytes)?,
            lengths: allocate_slots(state_capacity, 0_u32, total_bytes)?,
            modes: allocate_slots(state_capacity, 0_u8, total_bytes)?,
            hashes: allocate_slots(state_capacity, 0_u64, total_bytes)?,
            items: allocate_slots(item_capacity, 0_u32, total_bytes)?,
            state_len: 0,
            item_len: 0,
            initial: LAZY_NO_STATE,
            initial_kind: LazyInitialKind::Uninitialized,
            inline_start_action: LazyStartAction::Drop,
            initialized: false,
            declined: false,
            saturated: false,
        })
    }

    const fn disabled() -> Self {
        Self {
            automaton_identity: 0,
            scratch: Vec::new(),
            scratch_len: 0,
            frontier: Vec::new(),
            frontier_len: 0,
            rows: Vec::new(),
            context: ContextTransitionStore::disabled(),
            offsets: Vec::new(),
            lengths: Vec::new(),
            modes: Vec::new(),
            hashes: Vec::new(),
            items: Vec::new(),
            state_len: 0,
            item_len: 0,
            initial: LAZY_NO_STATE,
            initial_kind: LazyInitialKind::Uninitialized,
            inline_start_action: LazyStartAction::Drop,
            initialized: false,
            declined: true,
            saturated: false,
        }
    }

    fn is_allocated(&self) -> bool {
        !self.rows.is_empty() || self.context.is_allocated()
    }

    fn is_bound_to(&self, automaton: &Automaton) -> bool {
        self.automaton_identity == automaton.identity()
    }

    fn retained_bytes(&self) -> Result<usize, SearchError> {
        let scratch = capacity_bytes::<u32>(&self.scratch, "lazy DFA scratch bytes")?;
        let frontier = capacity_bytes::<u32>(&self.frontier, "lazy DFA frontier bytes")?;
        let rows = capacity_bytes::<u32>(&self.rows, "lazy DFA row bytes")?;
        let context = self.context.retained_bytes()?;
        let offsets = capacity_bytes::<usize>(&self.offsets, "lazy DFA offset bytes")?;
        let lengths = capacity_bytes::<u32>(&self.lengths, "lazy DFA length bytes")?;
        let modes = capacity_bytes::<u8>(&self.modes, "lazy DFA mode bytes")?;
        let hashes = capacity_bytes::<u64>(&self.hashes, "lazy DFA hash bytes")?;
        let items = capacity_bytes::<u32>(&self.items, "lazy DFA item bytes")?;
        scratch
            .checked_add(frontier)
            .and_then(|value| value.checked_add(rows))
            .and_then(|value| value.checked_add(context))
            .and_then(|value| value.checked_add(offsets))
            .and_then(|value| value.checked_add(lengths))
            .and_then(|value| value.checked_add(modes))
            .and_then(|value| value.checked_add(hashes))
            .and_then(|value| value.checked_add(items))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "retained lazy DFA bytes",
            })
    }

    fn state_bounds(&self, state: u32) -> Result<(usize, usize, bool), SearchError> {
        let state = usize::try_from(state).map_err(|_| SearchError::InternalInvariant {
            detail: "lazy DFA state does not fit usize",
        })?;
        if state >= self.state_len {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA state is outside the retained cache",
            });
        }
        let offset = *self
            .offsets
            .get(state)
            .ok_or(SearchError::InternalInvariant {
                detail: "lazy DFA state offset is outside metadata",
            })?;
        let length = usize::try_from(*self.lengths.get(state).ok_or(
            SearchError::InternalInvariant {
                detail: "lazy DFA state length is outside metadata",
            },
        )?)
        .map_err(|_| SearchError::InternalInvariant {
            detail: "lazy DFA state length does not fit usize",
        })?;
        let end = offset
            .checked_add(length)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA state item end",
            })?;
        if end > self.item_len || end > self.items.len() {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA state items are outside the retained arena",
            });
        }
        let pending = *self
            .modes
            .get(state)
            .ok_or(SearchError::InternalInvariant {
                detail: "lazy DFA state mode is outside metadata",
            })?
            != 0;
        Ok((offset, length, pending))
    }

    fn item(&self, state: u32, ordinal: usize) -> Result<u32, SearchError> {
        let (offset, length, _) = self.state_bounds(state)?;
        if ordinal >= length {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA item ordinal is outside its state",
            });
        }
        let item = offset
            .checked_add(ordinal)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA item index",
            })?;
        self.items
            .get(item)
            .copied()
            .ok_or(SearchError::InternalInvariant {
                detail: "lazy DFA item is outside the retained arena",
            })
    }

    fn cell(&self, state: u32, byte: u8) -> Result<u32, SearchError> {
        let state = usize::try_from(state).map_err(|_| SearchError::InternalInvariant {
            detail: "lazy DFA transition state does not fit usize",
        })?;
        if state >= self.state_len {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA transition state is outside the cache",
            });
        }
        debug_assert!(self.state_len <= LAZY_MAX_STATES);
        let cell_index = direct_row_cell_index(state, byte);
        self.rows
            .get(cell_index)
            .copied()
            .ok_or(SearchError::InternalInvariant {
                detail: "lazy DFA transition cell is outside the direct table",
            })
    }

    /// Read a warmed direct transition using an already-authenticated row.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "direct row offsets are bounded by the fixed lazy-state ceiling"
    )]
    fn direct_cell(&self, row_offset: u32, byte: u8) -> Result<u32, SearchError> {
        let row_offset =
            usize::try_from(row_offset).map_err(|_| SearchError::InternalInvariant {
                detail: "lazy DFA direct row offset does not fit usize",
            })?;
        debug_assert_eq!(row_offset % BYTE_ALPHABET, 0);
        debug_assert!(row_offset / BYTE_ALPHABET < self.state_len);
        self.rows
            .get(row_offset + usize::from(byte))
            .copied()
            .ok_or(SearchError::InternalInvariant {
                detail: "lazy DFA transition cell is outside the direct table",
            })
    }

    fn set_cell(&mut self, state: u32, byte: u8, cell: u32) -> Result<(), SearchError> {
        let state = usize::try_from(state).map_err(|_| SearchError::InternalInvariant {
            detail: "lazy DFA transition state does not fit usize",
        })?;
        if state >= self.state_len {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA transition source is outside the cache",
            });
        }
        debug_assert!(self.state_len <= LAZY_MAX_STATES);
        let cell_index = direct_row_cell_index(state, byte);
        *self
            .rows
            .get_mut(cell_index)
            .ok_or(SearchError::InternalInvariant {
                detail: "lazy DFA transition cell is outside the direct table",
            })? = cell;
        Ok(())
    }

    fn intern_initial(
        &mut self,
        pending: bool,
        meter: &mut WorkMeter,
        position: usize,
    ) -> Result<u32, SearchError> {
        let item_count = self.scratch_len;
        if (item_count == 0 && !pending) || self.state_len != 0 || self.item_len != 0 {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA initial state has an invalid cache shape",
            });
        }
        if self.offsets.is_empty() || item_count > self.items.len() {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA initial state exceeds its fixed arena",
            });
        }
        let item_work = u64::try_from(item_count).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "lazy DFA initial item work",
        })?;
        meter.charge(item_work, position)?;
        let hash = lazy_hash(&self.scratch[..item_count], pending);
        meter.charge(item_work, position)?;
        self.items[..item_count].copy_from_slice(&self.scratch[..item_count]);
        self.offsets[0] = 0;
        self.lengths[0] =
            u32::try_from(item_count).map_err(|_| SearchError::InternalInvariant {
                detail: "lazy DFA initial length does not fit u32",
            })?;
        self.modes[0] = u8::from(pending);
        self.hashes[0] = hash;
        self.state_len = 1;
        self.item_len = item_count;
        self.scratch_len = 0;
        Ok(0)
    }

    fn intern_speculative(
        &mut self,
        pending: bool,
        meter: &mut WorkMeter,
        core_reserve: u64,
        position: usize,
    ) -> Result<LazyInterned, SearchError> {
        let item_count = self.scratch_len;
        let item_end =
            self.item_len
                .checked_add(item_count)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "lazy DFA speculative item end",
                })?;
        let can_publish = self.state_len < self.offsets.len() && item_end <= self.items.len();
        let publication_work = if can_publish { item_count.max(1) } else { 0 };

        // Learning is optional. Require the complete worst-case comparison and
        // publication allowance before doing any of it; otherwise continue
        // from the already-advanced frontier inline.
        let comparison = self
            .state_len
            .checked_mul(
                item_count
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "lazy DFA comparison work",
                    })?,
            )
            .and_then(|work| work.checked_add(item_count))
            .and_then(|work| work.checked_add(publication_work))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA learning work",
            })?;
        let comparison =
            u64::try_from(comparison).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "lazy DFA learning work conversion",
            })?;
        let remaining = meter.remaining();
        let Some(optional) = remaining.checked_sub(core_reserve) else {
            return Ok(LazyInterned::BudgetDeclined);
        };
        if comparison > optional {
            return Ok(LazyInterned::BudgetDeclined);
        }

        let item_work = u64::try_from(item_count).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "lazy DFA item work",
        })?;
        meter.charge(item_work, position)?;
        let hash = lazy_hash(&self.scratch[..item_count], pending);
        for state in 0..self.state_len {
            meter.charge(1, position)?;
            if self.modes[state] != u8::from(pending)
                || self.hashes[state] != hash
                || usize::try_from(self.lengths[state]).map_err(|_| {
                    SearchError::InternalInvariant {
                        detail: "lazy DFA retained length does not fit usize",
                    }
                })? != item_count
            {
                continue;
            }
            let offset = self.offsets[state];
            let end = offset
                .checked_add(item_count)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "lazy DFA candidate state end",
                })?;
            meter.charge(item_work, position)?;
            if self.items.get(offset..end) == Some(&self.scratch[..item_count]) {
                self.scratch_len = 0;
                return Ok(LazyInterned::State(u32::try_from(state).map_err(|_| {
                    SearchError::InternalInvariant {
                        detail: "lazy DFA state does not fit u32",
                    }
                })?));
            }
        }

        if !can_publish {
            return Ok(LazyInterned::CapacityFull);
        }
        meter.charge(
            u64::try_from(publication_work).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "lazy DFA publication work conversion",
            })?,
            position,
        )?;
        self.items[self.item_len..item_end].copy_from_slice(&self.scratch[..item_count]);
        let state = self.state_len;
        self.offsets[state] = self.item_len;
        self.lengths[state] =
            u32::try_from(item_count).map_err(|_| SearchError::InternalInvariant {
                detail: "lazy DFA item count does not fit u32",
            })?;
        self.modes[state] = u8::from(pending);
        self.hashes[state] = hash;
        self.item_len = item_end;
        self.state_len = self
            .state_len
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA state count",
            })?;
        self.scratch_len = 0;
        Ok(LazyInterned::State(u32::try_from(state).map_err(|_| {
            SearchError::InternalInvariant {
                detail: "lazy DFA state does not fit u32",
            }
        })?))
    }

    fn retain_scratch_as_frontier(&mut self) -> Result<(), SearchError> {
        if self.scratch_len > self.frontier.len() || self.scratch.len() != self.frontier.len() {
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA inline frontier exceeds its fixed arena",
            });
        }
        core::mem::swap(&mut self.scratch, &mut self.frontier);
        self.frontier_len = self.scratch_len;
        self.scratch_len = 0;
        Ok(())
    }
}

/// Incoming-edge CSR and unordered reverse-subset rows for exact span starts.
///
/// Reverse state items are incoming consuming-edge indices, not only source
/// states. This preserves arbitrary validated `Consume` states whose ranges
/// can lead to different continuations. Items are canonicalized in CSR order,
/// so state identity needs no priority or pending-match mode.
#[derive(Debug)]
struct ReverseWorkspace {
    automaton_identity: u64,
    incoming_offsets: Vec<u32>,
    incoming_sources: Vec<u32>,
    incoming_starts: Vec<u8>,
    incoming_ends: Vec<u8>,
    incoming_kinds: Vec<EdgeKind>,
    scratch: Vec<u32>,
    scratch_len: usize,
    frontier: Vec<u32>,
    frontier_len: usize,
    rows: Vec<u32>,
    context: ContextTransitionStore,
    offsets: Vec<usize>,
    lengths: Vec<u32>,
    hashes: Vec<u64>,
    items: Vec<u32>,
    state_len: usize,
    item_len: usize,
    initial: u32,
    initialized: bool,
    declined: bool,
    saturated: bool,
}

impl ReverseWorkspace {
    fn new(
        automaton: &Automaton,
        layout: WorkspaceLayout,
        total_bytes: usize,
        seen_at: &mut [u64],
    ) -> Result<Self, SearchError> {
        let state_capacity = layout.reverse_state_capacity;
        if state_capacity == 0 {
            return Ok(Self::disabled());
        }
        let row_cells = if layout.reverse_context_slots == 0 {
            state_capacity
                .checked_mul(BYTE_ALPHABET)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "reverse lazy DFA row cells",
                })?
        } else {
            0
        };
        let offset_slots = layout
            .states
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse CSR offset slots",
            })?;
        let mut reverse = Self {
            automaton_identity: automaton.identity(),
            incoming_offsets: allocate_slots(offset_slots, 0_u32, total_bytes)?,
            incoming_sources: allocate_slots(layout.edges, 0_u32, total_bytes)?,
            incoming_starts: allocate_slots(layout.edges, 0_u8, total_bytes)?,
            incoming_ends: allocate_slots(layout.edges, 0_u8, total_bytes)?,
            incoming_kinds: if layout.reverse_context_slots == 0 {
                Vec::new()
            } else {
                allocate_slots(layout.edges, EdgeKind::Epsilon, total_bytes)?
            },
            scratch: allocate_slots(layout.edges, 0_u32, total_bytes)?,
            scratch_len: 0,
            frontier: allocate_slots(layout.edges, 0_u32, total_bytes)?,
            frontier_len: 0,
            rows: allocate_slots(row_cells, LAZY_CELL_UNFILLED, total_bytes)?,
            context: ContextTransitionStore::new(layout.reverse_context_slots, total_bytes)?,
            offsets: allocate_slots(state_capacity, 0_usize, total_bytes)?,
            lengths: allocate_slots(state_capacity, 0_u32, total_bytes)?,
            hashes: allocate_slots(state_capacity, 0_u64, total_bytes)?,
            items: allocate_slots(layout.reverse_item_capacity, 0_u32, total_bytes)?,
            state_len: 0,
            item_len: 0,
            initial: LAZY_NO_STATE,
            initialized: false,
            declined: false,
            saturated: false,
        };
        reverse.build_csr(automaton, seen_at)?;
        Ok(reverse)
    }

    const fn disabled() -> Self {
        Self {
            automaton_identity: 0,
            incoming_offsets: Vec::new(),
            incoming_sources: Vec::new(),
            incoming_starts: Vec::new(),
            incoming_ends: Vec::new(),
            incoming_kinds: Vec::new(),
            scratch: Vec::new(),
            scratch_len: 0,
            frontier: Vec::new(),
            frontier_len: 0,
            rows: Vec::new(),
            context: ContextTransitionStore::disabled(),
            offsets: Vec::new(),
            lengths: Vec::new(),
            hashes: Vec::new(),
            items: Vec::new(),
            state_len: 0,
            item_len: 0,
            initial: LAZY_NO_STATE,
            initialized: false,
            declined: true,
            saturated: false,
        }
    }

    fn build_csr(&mut self, automaton: &Automaton, seen_at: &mut [u64]) -> Result<(), SearchError> {
        if seen_at.len() != automaton.stats().states() {
            return Err(SearchError::InternalInvariant {
                detail: "reverse CSR cursor shape does not match the automaton",
            });
        }
        for &target in &automaton.edge_targets {
            let target = crate::plan::plan_index(target);
            seen_at[target] =
                seen_at[target]
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "reverse CSR incoming count",
                    })?;
        }
        let mut prefix = 0usize;
        for (state, &count) in seen_at.iter().enumerate() {
            prefix = prefix
                .checked_add(usize::try_from(count).map_err(|_| {
                    SearchError::ArithmeticOverflow {
                        computation: "reverse CSR incoming count conversion",
                    }
                })?)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "reverse CSR prefix",
                })?;
            let next = state
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "reverse CSR next offset slot",
                })?;
            self.incoming_offsets[next] =
                u32::try_from(prefix).map_err(|_| SearchError::InternalInvariant {
                    detail: "validated reverse CSR prefix does not fit u32",
                })?;
        }
        if prefix != automaton.stats().edges() {
            return Err(SearchError::InternalInvariant {
                detail: "reverse CSR prefix does not cover every edge",
            });
        }
        for (state, cursor) in seen_at.iter_mut().enumerate() {
            *cursor = u64::from(self.incoming_offsets[state]);
        }
        for source in 0..automaton.stats().states() {
            let source_u32 = u32::try_from(source).map_err(|_| SearchError::InternalInvariant {
                detail: "validated reverse CSR source does not fit u32",
            })?;
            for edge in automaton.state_edges(source_u32) {
                let target = crate::plan::plan_index(automaton.edge_targets[edge]);
                let slot = usize::try_from(seen_at[target]).map_err(|_| {
                    SearchError::ArithmeticOverflow {
                        computation: "reverse CSR cursor conversion",
                    }
                })?;
                seen_at[target] =
                    seen_at[target]
                        .checked_add(1)
                        .ok_or(SearchError::ArithmeticOverflow {
                            computation: "reverse CSR cursor",
                        })?;
                *self
                    .incoming_sources
                    .get_mut(slot)
                    .ok_or(SearchError::InternalInvariant {
                        detail: "reverse CSR cursor exceeded source storage",
                    })? = source_u32;
                self.incoming_starts[slot] = automaton.byte_starts[edge];
                self.incoming_ends[slot] = automaton.byte_ends[edge];
                if !self.incoming_kinds.is_empty() {
                    self.incoming_kinds[slot] = automaton.edge_kinds[edge];
                }
            }
        }
        seen_at.fill(0);
        Ok(())
    }

    fn is_allocated(&self) -> bool {
        !self.rows.is_empty() || self.context.is_allocated()
    }

    fn is_bound_to(&self, automaton: &Automaton) -> bool {
        self.automaton_identity == automaton.identity()
    }

    fn retained_bytes(&self) -> Result<usize, SearchError> {
        let mut total = 0usize;
        for bytes in [
            capacity_bytes::<u32>(&self.incoming_offsets, "reverse CSR offset bytes")?,
            capacity_bytes::<u32>(&self.incoming_sources, "reverse CSR source bytes")?,
            capacity_bytes::<u8>(&self.incoming_starts, "reverse CSR start bytes")?,
            capacity_bytes::<u8>(&self.incoming_ends, "reverse CSR end bytes")?,
            capacity_bytes::<EdgeKind>(&self.incoming_kinds, "reverse CSR kind bytes")?,
            capacity_bytes::<u32>(&self.scratch, "reverse DFA scratch bytes")?,
            capacity_bytes::<u32>(&self.frontier, "reverse DFA frontier bytes")?,
            capacity_bytes::<u32>(&self.rows, "reverse DFA row bytes")?,
            self.context.retained_bytes()?,
            capacity_bytes::<usize>(&self.offsets, "reverse DFA offset bytes")?,
            capacity_bytes::<u32>(&self.lengths, "reverse DFA length bytes")?,
            capacity_bytes::<u64>(&self.hashes, "reverse DFA hash bytes")?,
            capacity_bytes::<u32>(&self.items, "reverse DFA item bytes")?,
        ] {
            total = total
                .checked_add(bytes)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "retained reverse DFA bytes",
                })?;
        }
        Ok(total)
    }

    fn incoming_range(&self, target: u32) -> Result<core::ops::Range<usize>, SearchError> {
        let target = usize::try_from(target).map_err(|_| SearchError::InternalInvariant {
            detail: "reverse closure target does not fit usize",
        })?;
        let next = target
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse CSR next target",
            })?;
        let begin = usize::try_from(*self.incoming_offsets.get(target).ok_or(
            SearchError::InternalInvariant {
                detail: "reverse CSR target is outside offsets",
            },
        )?)
        .map_err(|_| SearchError::InternalInvariant {
            detail: "validated reverse CSR offset does not fit usize",
        })?;
        let end = usize::try_from(*self.incoming_offsets.get(next).ok_or(
            SearchError::InternalInvariant {
                detail: "reverse CSR next target is outside offsets",
            },
        )?)
        .map_err(|_| SearchError::InternalInvariant {
            detail: "validated reverse CSR offset does not fit usize",
        })?;
        Ok(begin..end)
    }

    fn state_bounds(&self, state: u32) -> Result<(usize, usize), SearchError> {
        let state = usize::try_from(state).map_err(|_| SearchError::InternalInvariant {
            detail: "reverse DFA state does not fit usize",
        })?;
        if state >= self.state_len {
            return Err(SearchError::InternalInvariant {
                detail: "reverse DFA state is outside the retained cache",
            });
        }
        let offset = self.offsets[state];
        let length =
            usize::try_from(self.lengths[state]).map_err(|_| SearchError::InternalInvariant {
                detail: "reverse DFA state length does not fit usize",
            })?;
        let end = offset
            .checked_add(length)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse DFA state item end",
            })?;
        if end > self.item_len || end > self.items.len() {
            return Err(SearchError::InternalInvariant {
                detail: "reverse DFA state items are outside the arena",
            });
        }
        Ok((offset, length))
    }

    fn item(&self, state: u32, ordinal: usize) -> Result<u32, SearchError> {
        let (offset, length) = self.state_bounds(state)?;
        if ordinal >= length {
            return Err(SearchError::InternalInvariant {
                detail: "reverse DFA item ordinal is outside its state",
            });
        }
        let item = offset
            .checked_add(ordinal)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse DFA item index",
            })?;
        self.items
            .get(item)
            .copied()
            .ok_or(SearchError::InternalInvariant {
                detail: "reverse DFA item is outside the retained arena",
            })
    }

    fn cell(&self, state: u32, byte: u8) -> Result<u32, SearchError> {
        let state = usize::try_from(state).map_err(|_| SearchError::InternalInvariant {
            detail: "reverse DFA transition state does not fit usize",
        })?;
        if state >= self.state_len {
            return Err(SearchError::InternalInvariant {
                detail: "reverse DFA transition state is outside the cache",
            });
        }
        debug_assert!(self.state_len <= LAZY_MAX_STATES);
        let cell = direct_row_cell_index(state, byte);
        self.rows
            .get(cell)
            .copied()
            .ok_or(SearchError::InternalInvariant {
                detail: "reverse DFA transition cell is outside the direct table",
            })
    }

    /// Read a warmed direct transition using an already-authenticated row.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "direct row offsets are bounded by the fixed lazy-state ceiling"
    )]
    fn direct_cell(&self, row_offset: u32, byte: u8) -> Result<u32, SearchError> {
        let row_offset =
            usize::try_from(row_offset).map_err(|_| SearchError::InternalInvariant {
                detail: "reverse DFA direct row offset does not fit usize",
            })?;
        debug_assert_eq!(row_offset % BYTE_ALPHABET, 0);
        debug_assert!(row_offset / BYTE_ALPHABET < self.state_len);
        self.rows
            .get(row_offset + usize::from(byte))
            .copied()
            .ok_or(SearchError::InternalInvariant {
                detail: "reverse DFA transition cell is outside the direct table",
            })
    }

    fn set_cell(&mut self, state: u32, byte: u8, value: u32) -> Result<(), SearchError> {
        let state = usize::try_from(state).map_err(|_| SearchError::InternalInvariant {
            detail: "reverse DFA transition state does not fit usize",
        })?;
        if state >= self.state_len {
            return Err(SearchError::InternalInvariant {
                detail: "reverse DFA transition source is outside the cache",
            });
        }
        debug_assert!(self.state_len <= LAZY_MAX_STATES);
        let cell = direct_row_cell_index(state, byte);
        *self
            .rows
            .get_mut(cell)
            .ok_or(SearchError::InternalInvariant {
                detail: "reverse DFA transition cell is outside the direct table",
            })? = value;
        Ok(())
    }

    fn intern_initial(
        &mut self,
        meter: &mut WorkMeter,
        position: usize,
    ) -> Result<u32, SearchError> {
        let item_count = self.scratch_len;
        if item_count == 0 || self.state_len != 0 || self.item_len != 0 {
            return Err(SearchError::InternalInvariant {
                detail: "reverse DFA initial state has an invalid cache shape",
            });
        }
        if self.offsets.is_empty() || item_count > self.items.len() {
            return Err(SearchError::InternalInvariant {
                detail: "reverse DFA initial state exceeds its fixed arena",
            });
        }
        let work = u64::try_from(item_count).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "reverse DFA initial item work",
        })?;
        meter.charge(work, position)?;
        let hash = lazy_hash(&self.scratch[..item_count], false);
        meter.charge(work, position)?;
        self.items[..item_count].copy_from_slice(&self.scratch[..item_count]);
        self.offsets[0] = 0;
        self.lengths[0] =
            u32::try_from(item_count).map_err(|_| SearchError::InternalInvariant {
                detail: "reverse DFA initial length does not fit u32",
            })?;
        self.hashes[0] = hash;
        self.state_len = 1;
        self.item_len = item_count;
        self.scratch_len = 0;
        Ok(0)
    }

    fn intern_speculative(
        &mut self,
        meter: &mut WorkMeter,
        core_reserve: u64,
        position: usize,
    ) -> Result<LazyInterned, SearchError> {
        let item_count = self.scratch_len;
        let item_end =
            self.item_len
                .checked_add(item_count)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "reverse DFA speculative item end",
                })?;
        let can_publish = self.state_len < self.offsets.len() && item_end <= self.items.len();
        let publication_work = if can_publish { item_count.max(1) } else { 0 };
        let comparison = self
            .state_len
            .checked_mul(
                item_count
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "reverse DFA comparison work",
                    })?,
            )
            .and_then(|work| work.checked_add(item_count))
            .and_then(|work| work.checked_add(publication_work))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse DFA learning work",
            })?;
        let comparison =
            u64::try_from(comparison).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "reverse DFA learning work conversion",
            })?;
        let Some(optional) = meter.remaining().checked_sub(core_reserve) else {
            return Ok(LazyInterned::BudgetDeclined);
        };
        if comparison > optional {
            return Ok(LazyInterned::BudgetDeclined);
        }

        let item_work = u64::try_from(item_count).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "reverse DFA item work",
        })?;
        meter.charge(item_work, position)?;
        let hash = lazy_hash(&self.scratch[..item_count], false);
        for state in 0..self.state_len {
            meter.charge(1, position)?;
            if self.hashes[state] != hash
                || usize::try_from(self.lengths[state]).map_err(|_| {
                    SearchError::InternalInvariant {
                        detail: "reverse DFA retained length does not fit usize",
                    }
                })? != item_count
            {
                continue;
            }
            let offset = self.offsets[state];
            let end = offset
                .checked_add(item_count)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "reverse DFA candidate state end",
                })?;
            meter.charge(item_work, position)?;
            if self.items.get(offset..end) == Some(&self.scratch[..item_count]) {
                self.scratch_len = 0;
                return Ok(LazyInterned::State(u32::try_from(state).map_err(|_| {
                    SearchError::InternalInvariant {
                        detail: "reverse DFA state does not fit u32",
                    }
                })?));
            }
        }
        if !can_publish {
            return Ok(LazyInterned::CapacityFull);
        }
        meter.charge(
            u64::try_from(publication_work).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "reverse DFA publication work conversion",
            })?,
            position,
        )?;
        self.items[self.item_len..item_end].copy_from_slice(&self.scratch[..item_count]);
        let state = self.state_len;
        self.offsets[state] = self.item_len;
        self.lengths[state] =
            u32::try_from(item_count).map_err(|_| SearchError::InternalInvariant {
                detail: "reverse DFA item count does not fit u32",
            })?;
        self.hashes[state] = hash;
        self.item_len = item_end;
        self.state_len = self
            .state_len
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse DFA state count",
            })?;
        self.scratch_len = 0;
        Ok(LazyInterned::State(u32::try_from(state).map_err(|_| {
            SearchError::InternalInvariant {
                detail: "reverse DFA state does not fit u32",
            }
        })?))
    }

    fn retain_scratch_as_frontier(&mut self) -> Result<(), SearchError> {
        if self.scratch_len > self.frontier.len() || self.scratch.len() != self.frontier.len() {
            return Err(SearchError::InternalInvariant {
                detail: "reverse DFA inline frontier exceeds its fixed arena",
            });
        }
        core::mem::swap(&mut self.scratch, &mut self.frontier);
        self.frontier_len = self.scratch_len;
        self.scratch_len = 0;
        Ok(())
    }
}

/// Graph-bound ordered consuming frontiers admitted for exact K0 continuation.
///
/// A frontier is the complete ordered list at one byte boundary after epsilon
/// closure has stopped at the first accepting path, plus the selected-end
/// pending bit. The list order is semantic: earlier entries have higher
/// priority. Construction validates graph binding, consuming roles, bounds,
/// uniqueness, and the declared flat shape. Reachability from a particular
/// prefix is deliberately a producer proof; the AOT producer authenticates
/// that proof by canonically regenerating its partial table before this set is
/// constructed.
///
/// Cached lazy-state IDs are only hints. Every hint is content-checked against
/// the paired workspace before reuse, so moving a set between compatible
/// workspaces cannot cross an unauthenticated state identity.
#[derive(Debug)]
pub struct K0ResumeSet {
    automaton_identity: u64,
    offsets: Vec<usize>,
    lengths: Vec<u32>,
    modes: Vec<u8>,
    items: Vec<u32>,
    cached_states: Vec<u32>,
    retained_bytes: usize,
}

impl K0ResumeSet {
    /// Copy a canonical collection of ordered frontiers and bind it to one
    /// immutable automaton instance.
    ///
    /// `state_count` and `total_items` make the allocation and iteration shape
    /// explicit before any input is copied. Every yielded slice must be
    /// non-empty and contain distinct consuming-state indices in priority
    /// order. The boolean is the frontier's pending selected-end mode.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::InvalidResumeState`] for an invalid shape or
    /// graph item, or [`SearchError::ScratchAllocationFailed`] if the fixed
    /// retained payload cannot be allocated.
    #[doc(hidden)]
    #[allow(
        clippy::too_many_lines,
        reason = "the one-time graph binding validates and publishes the complete flat resume shape"
    )]
    pub fn new<'a, I>(
        automaton: &Automaton,
        state_count: usize,
        total_items: usize,
        frontiers: I,
    ) -> Result<Self, SearchError>
    where
        I: IntoIterator<Item = (&'a [u32], bool)>,
    {
        if automaton.stats().assertion_edges() != 0 {
            return Err(SearchError::InvalidResumeState {
                detail: "ordered-frontier continuation requires an assertion-free automaton",
            });
        }
        if state_count == 0 || total_items == 0 {
            return Err(SearchError::InvalidResumeState {
                detail: "resume set has no non-empty frontier",
            });
        }
        let retained_bytes = state_count
            .checked_mul(size_of::<usize>())
            .and_then(|bytes| {
                state_count
                    .checked_mul(size_of::<u32>())
                    .and_then(|more| bytes.checked_add(more))
            })
            .and_then(|bytes| bytes.checked_add(state_count))
            .and_then(|bytes| {
                state_count
                    .checked_mul(size_of::<u32>())
                    .and_then(|more| bytes.checked_add(more))
            })
            .and_then(|bytes| {
                total_items
                    .checked_mul(size_of::<u32>())
                    .and_then(|more| bytes.checked_add(more))
            })
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "ordered-frontier resume storage bytes",
            })?;
        let mut offsets = allocate_slots(state_count, 0_usize, retained_bytes)?;
        let mut lengths = allocate_slots(state_count, 0_u32, retained_bytes)?;
        let mut modes = allocate_slots(state_count, 0_u8, retained_bytes)?;
        let mut items = allocate_slots(total_items, 0_u32, retained_bytes)?;
        let cached_states = allocate_slots(state_count, LAZY_NO_STATE, retained_bytes)?;

        let mut frontiers = frontiers.into_iter();
        let mut item_cursor = 0usize;
        for state in 0..state_count {
            let (frontier, pending) = frontiers.next().ok_or(
                SearchError::InvalidResumeState {
                    detail: "resume iterator ended before its declared state count",
                },
            )?;
            if frontier.is_empty() {
                return Err(SearchError::InvalidResumeState {
                    detail: "resume frontier is empty",
                });
            }
            let length = u32::try_from(frontier.len()).map_err(|_| {
                SearchError::InvalidResumeState {
                    detail: "resume frontier length exceeds u32",
                }
            })?;
            let item_end = item_cursor.checked_add(frontier.len()).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "ordered-frontier resume item end",
                },
            )?;
            if item_end > items.len() {
                return Err(SearchError::InvalidResumeState {
                    detail: "resume frontiers exceed their declared total item count",
                });
            }
            for (ordinal, &item) in frontier.iter().enumerate() {
                let item_index = usize::try_from(item).map_err(|_| {
                    SearchError::InvalidResumeState {
                        detail: "resume item does not fit the host index space",
                    }
                })?;
                if automaton.roles.get(item_index) != Some(&StateRole::Consume) {
                    return Err(SearchError::InvalidResumeState {
                        detail: "resume item is not a consuming automaton state",
                    });
                }
                if frontier[..ordinal].contains(&item) {
                    return Err(SearchError::InvalidResumeState {
                        detail: "resume frontier contains a duplicate state",
                    });
                }
            }
            items[item_cursor..item_end].copy_from_slice(frontier);
            offsets[state] = item_cursor;
            lengths[state] = length;
            modes[state] = u8::from(pending);
            item_cursor = item_end;
        }
        if frontiers.next().is_some() {
            return Err(SearchError::InvalidResumeState {
                detail: "resume iterator exceeds its declared state count",
            });
        }
        if item_cursor != total_items {
            return Err(SearchError::InvalidResumeState {
                detail: "resume frontiers do not fill their declared item count",
            });
        }

        let retained_bytes = offsets
            .capacity()
            .checked_mul(size_of::<usize>())
            .and_then(|bytes| {
                lengths
                    .capacity()
                    .checked_mul(size_of::<u32>())
                    .and_then(|more| bytes.checked_add(more))
            })
            .and_then(|bytes| bytes.checked_add(modes.capacity()))
            .and_then(|bytes| {
                cached_states
                    .capacity()
                    .checked_mul(size_of::<u32>())
                    .and_then(|more| bytes.checked_add(more))
            })
            .and_then(|bytes| {
                items
                    .capacity()
                    .checked_mul(size_of::<u32>())
                    .and_then(|more| bytes.checked_add(more))
            })
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "retained ordered-frontier resume storage bytes",
            })?;

        Ok(Self {
            automaton_identity: automaton.identity(),
            offsets,
            lengths,
            modes,
            items,
            cached_states,
            retained_bytes,
        })
    }

    /// Allocator-retained payload owned by this continuation set.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Whether this continuation set was authenticated against `automaton`.
    #[doc(hidden)]
    #[must_use]
    pub const fn is_bound_to(&self, automaton: &Automaton) -> bool {
        self.automaton_identity == automaton.identity()
    }

    fn frontier(&self, state: usize) -> Result<(&[u32], bool), SearchError> {
        let offset = *self
            .offsets
            .get(state)
            .ok_or(SearchError::InvalidResumeState {
                detail: "resume state index is outside the authenticated set",
            })?;
        let length = usize::try_from(*self.lengths.get(state).ok_or(
            SearchError::InternalInvariant {
                detail: "resume state length is outside its metadata",
            },
        )?)
        .map_err(|_| SearchError::InternalInvariant {
            detail: "resume state length does not fit usize",
        })?;
        let end = offset
            .checked_add(length)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "ordered-frontier resume state end",
            })?;
        let items = self
            .items
            .get(offset..end)
            .ok_or(SearchError::InternalInvariant {
                detail: "resume state items are outside their retained arena",
            })?;
        let pending = *self
            .modes
            .get(state)
            .ok_or(SearchError::InternalInvariant {
                detail: "resume pending mode is outside its metadata",
            })?
            != 0;
        Ok((items, pending))
    }
}

/// Caller-owned fixed-capacity storage for allocation-free repeated K0 calls.
///
/// All backing vectors retain their full initialized length. Separate logical
/// lengths control which thread slots are live, so execution cannot trigger a
/// reserve or resize. A workspace is compatible with every validated automaton
/// having the exact layout returned by [`Self::layout`].
#[derive(Debug)]
pub struct K0Workspace {
    bound_automaton_identity: u64,
    bound_capabilities: LazyCapabilities,
    layout: WorkspaceLayout,
    seen_at: Vec<u64>,
    generation: u64,
    current: Vec<Thread>,
    current_len: usize,
    roots: Vec<Thread>,
    roots_len: usize,
    stack: Vec<Thread>,
    stack_len: usize,
    lazy: LazyWorkspace,
    reverse: ReverseWorkspace,
    span_cursor: SpanCursorCache,
    retained_bytes: usize,
    construction: SetupAccounting,
}

/// Reusable K0 storage bound to one exact immutable automaton.
///
/// Unlike [`K0Workspace`], this owner cannot be paired with another automaton
/// after construction. Searches can therefore reuse the authenticated graph
/// shape and cursor capabilities while retaining all per-invocation window,
/// work, scratch, reset, and accounting checks.
#[derive(Debug)]
pub struct K0SearchSession<'a> {
    automaton: &'a Automaton,
    workspace: K0Workspace,
    capabilities: LazyCapabilities,
    span_start_proof: SpanCursorStartProof,
    root_run: Option<RootRunDescriptor>,
}

impl K0Workspace {
    /// Allocate and fully initialize fixed-capacity workspace for `automaton`.
    ///
    /// Both the logical payload and allocator-reported retained capacity are
    /// checked against `limits`. The returned object never grows implicitly.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] on arithmetic overflow, a setup/scratch limit,
    /// or a fallible allocation failure.
    pub fn new(automaton: &Automaton, limits: WorkspaceLimits) -> Result<Self, SearchError> {
        Self::new_mode(automaton, limits, WorkspaceMode::Pike)
    }

    /// Allocate reusable K0 storage plus a bounded ordered lazy-DFA cache.
    ///
    /// Structurally ineligible automata retain exactly the ordinary Pike
    /// workspace. Assertion-free byte automata add fixed-capacity direct rows;
    /// assertion-bearing byte automata instead key a bounded transition store
    /// by the exact enabled-assertion mask at each boundary. Neither store
    /// grows during a search. Assertion-free nullable graphs retain their
    /// ordered higher-priority consuming prefix plus the initial empty match;
    /// contextual nullable and empty-language graphs remain on Pike. Span
    /// operations use Pike unless an empty result needs no reverse recovery.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] on arithmetic overflow, a setup/scratch limit,
    /// or a fallible allocation failure.
    pub fn new_accelerated(
        automaton: &Automaton,
        limits: WorkspaceLimits,
    ) -> Result<Self, SearchError> {
        Self::new_mode(automaton, limits, WorkspaceMode::Endpoints)
    }

    /// Allocate reusable endpoint rows plus a bounded reverse lazy-DFA cache
    /// that recovers exact starts for full-span operations.
    ///
    /// Structurally ineligible graphs retain the ordinary Pike layout. The
    /// reverse incoming-edge CSR and direct or assertion-contextual cache are
    /// fixed and fully initialized before this method returns; searches never
    /// grow them.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] on arithmetic overflow, a setup/scratch limit,
    /// or a fallible allocation failure.
    pub fn new_bidirectional(
        automaton: &Automaton,
        limits: WorkspaceLimits,
    ) -> Result<Self, SearchError> {
        Self::new_mode(automaton, limits, WorkspaceMode::Bidirectional)
    }

    fn new_mode(
        automaton: &Automaton,
        limits: WorkspaceLimits,
        mode: WorkspaceMode,
    ) -> Result<Self, SearchError> {
        let layout = WorkspaceLayout::for_automaton_mode(automaton, mode)?;
        Self::new_with_layout(automaton, limits, layout)
    }

    fn new_with_layout(
        automaton: &Automaton,
        limits: WorkspaceLimits,
        layout: WorkspaceLayout,
    ) -> Result<Self, SearchError> {
        if layout.construction_work > limits.max_setup_work {
            return Err(SearchError::WorkspaceSetupWorkLimitExceeded {
                limit: limits.max_setup_work,
                needed: layout.construction_work,
            });
        }
        if layout.logical_bytes > limits.max_scratch_bytes {
            return Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed: layout.logical_bytes,
                limit: limits.max_scratch_bytes,
            });
        }

        let mut seen_at = allocate_slots(layout.states, 0_u64, layout.logical_bytes)?;
        let current = allocate_slots(layout.states, Thread::default(), layout.logical_bytes)?;
        let roots = allocate_slots(layout.edges, Thread::default(), layout.logical_bytes)?;
        let stack = allocate_slots(
            layout.closure_slots,
            Thread::default(),
            layout.logical_bytes,
        )?;
        let lazy = LazyWorkspace::new(automaton, layout, layout.logical_bytes)?;
        let reverse = ReverseWorkspace::new(automaton, layout, layout.logical_bytes, &mut seen_at)?;
        let bound_capabilities = LazyCapabilities {
            lazy: lazy.is_allocated(),
            reverse: reverse.is_allocated(),
            contextual: automaton.stats().assertion_edges() != 0,
        };
        let retained_bytes = retained_bytes(&seen_at, &current, &roots, &stack, &lazy, &reverse)?;
        if retained_bytes > limits.max_scratch_bytes {
            return Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed: retained_bytes,
                limit: limits.max_scratch_bytes,
            });
        }

        let construction = SetupAccounting {
            work: layout.construction_work,
            allocated_bytes: retained_bytes,
            initialized_bytes: layout.initialized_bytes,
            retained_bytes,
            reused: false,
        };
        Ok(Self {
            bound_automaton_identity: automaton.identity(),
            bound_capabilities,
            layout,
            seen_at,
            generation: 0,
            current,
            current_len: 0,
            roots,
            roots_len: 0,
            stack,
            stack_len: 0,
            lazy,
            reverse,
            span_cursor: SpanCursorCache::default(),
            retained_bytes,
            construction,
        })
    }

    /// Fixed logical shape accepted by this workspace.
    #[must_use]
    pub const fn layout(&self) -> WorkspaceLayout {
        self.layout
    }

    /// Actual vector-capacity payload retained after construction.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// Constructor allocation and initialization charges.
    #[must_use]
    pub const fn construction_accounting(&self) -> SetupAccounting {
        self.construction
    }

    fn begin_invocation(
        &mut self,
        required_generations: u64,
        meter: &mut WorkMeter,
        setup: &mut SetupAccounting,
        position: usize,
    ) -> Result<(), SearchError> {
        meter.charge(INVOCATION_RESET_WORK, position)?;
        setup.work = setup.work.checked_add(INVOCATION_RESET_WORK).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "search setup work",
            },
        )?;
        self.current_len = 0;
        self.roots_len = 0;
        self.stack_len = 0;
        self.lazy.frontier_len = 0;

        if self.generation > u64::MAX.saturating_sub(required_generations) {
            let clear_work =
                u64::try_from(self.seen_at.len()).map_err(|_| SearchError::ArithmeticOverflow {
                    computation: "generation reset work conversion",
                })?;
            meter.charge(clear_work, position)?;
            setup.work =
                setup
                    .work
                    .checked_add(clear_work)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "generation reset setup work",
                    })?;
            let clear_bytes = self.seen_at.len().checked_mul(size_of::<u64>()).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "generation reset initialized bytes",
                },
            )?;
            setup.initialized_bytes = setup.initialized_bytes.checked_add(clear_bytes).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "search setup initialized bytes",
                },
            )?;
            self.seen_at.fill(0);
            self.generation = 0;
        }
        Ok(())
    }

    fn begin_boundary(
        &mut self,
        meter: &mut WorkMeter,
        position: usize,
    ) -> Result<(), SearchError> {
        meter.charge(1, position)?;
        self.current_len = 0;
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(SearchError::InternalInvariant {
                detail: "preflighted seen-table generation overflowed",
            })?;
        Ok(())
    }

    fn push_current(&mut self, thread: Thread) -> Result<(), SearchError> {
        let slot =
            self.current
                .get_mut(self.current_len)
                .ok_or(SearchError::InternalInvariant {
                    detail: "ordered current-state set exceeded state count",
                })?;
        *slot = thread;
        self.current_len =
            self.current_len
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "current-state logical length",
                })?;
        Ok(())
    }

    fn push_root(&mut self, thread: Thread) -> Result<(), SearchError> {
        let slot = self
            .roots
            .get_mut(self.roots_len)
            .ok_or(SearchError::InternalInvariant {
                detail: "next-boundary roots exceeded consuming edge count",
            })?;
        *slot = thread;
        self.roots_len = self
            .roots_len
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "next-boundary root logical length",
            })?;
        Ok(())
    }

    fn push_stack(&mut self, thread: Thread) -> Result<(), SearchError> {
        let slot = self
            .stack
            .get_mut(self.stack_len)
            .ok_or(SearchError::InternalInvariant {
                detail: "epsilon closure stack exceeded zero-width edge bound",
            })?;
        *slot = thread;
        self.stack_len = self
            .stack_len
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "closure stack logical length",
            })?;
        Ok(())
    }

    fn pop_stack(&mut self) -> Option<Thread> {
        self.stack_len = self.stack_len.checked_sub(1)?;
        self.stack.get(self.stack_len).copied()
    }
}

impl<'a> K0SearchSession<'a> {
    /// Select and construct the best admitted reusable workspace tier.
    ///
    /// This is an internal facade bridge. `endpoint_eligible` and
    /// `bidirectional` are source-independent planner facts. Optional cache
    /// tiers that do not fit fall back to the next smaller tier; the ordinary
    /// Pike tier remains mandatory and reports its setup refusal. After one
    /// workspace tier is selected, the root-run descriptor is admitted from
    /// the remaining setup-work budget independently. Descriptor refusal keeps
    /// the already admitted workspace instead of forcing a smaller tier.
    #[doc(hidden)]
    pub fn new_selected(
        automaton: &'a Automaton,
        limits: WorkspaceLimits,
        endpoint_eligible: bool,
        bidirectional: bool,
    ) -> Result<Self, SearchError> {
        let fits = |layout: WorkspaceLayout| {
            layout.construction_work <= limits.max_setup_work
                && layout.logical_bytes <= limits.max_scratch_bytes
        };
        let layout = if endpoint_eligible && bidirectional {
            WorkspaceLayout::for_bidirectional_automaton(automaton)
                .ok()
                .filter(|layout| fits(*layout))
        } else {
            None
        }
        .or_else(|| {
            endpoint_eligible
                .then(|| WorkspaceLayout::for_accelerated_automaton(automaton).ok())
                .flatten()
                .filter(|layout| fits(*layout))
        })
        .map_or_else(
            || WorkspaceLayout::for_automaton(automaton),
            Result::<_, SearchError>::Ok,
        )?;
        let mut workspace = K0Workspace::new_with_layout(automaton, limits, layout)?;
        let capabilities = LazyCapabilities {
            lazy: workspace.lazy.is_allocated(),
            reverse: workspace.reverse.is_allocated(),
            contextual: automaton.stats().assertion_edges() != 0,
        };
        // This is an optional, source-free session specialization. Reserve
        // its complete graph-table inspection and scanner-shape charges before
        // touching the graph, and decline without hidden setup work when the
        // caller's constructor budget cannot admit them.
        let root_run = if endpoint_eligible && bidirectional {
            let scanner_shape_envelope = u64::try_from(ROOT_RUN_SCANNER_SHAPE_MAX_WORK)
                .expect("root-run scanner-shape work fits u64");
            let admitted = root_run_inspection_work(automaton)
                .and_then(|envelope| envelope.checked_add(scanner_shape_envelope))
                .is_some_and(|envelope| {
                    workspace
                        .construction
                        .work
                        .checked_add(envelope)
                        .is_some_and(|work| work <= limits.max_setup_work)
                });
            if admitted {
                let inspection = inspect_root_run_accounted(automaton);
                workspace.construction.work = workspace
                    .construction
                    .work
                    .checked_add(inspection.work())
                    .expect("admitted root-run inspection fits its prospective envelope");
                let descriptor = inspection.descriptor().filter(|descriptor| {
                    descriptor.minimum() <= ROOT_CORRIDOR_MASK_MAXIMUM_MINIMUM
                });
                descriptor.filter(|descriptor| {
                    let (eligible, selection_work) =
                        root_run_descriptor_has_ascii_scanner(*descriptor);
                    workspace.construction.work = workspace
                        .construction
                        .work
                        .checked_add(selection_work)
                        .expect("admitted scanner-shape selection fits its prospective envelope");
                    eligible
                })
            } else {
                None
            }
        } else {
            None
        };
        Ok(Self {
            automaton,
            workspace,
            capabilities,
            span_start_proof: retained_span_cursor_start_proof(automaton),
            root_run,
        })
    }

    /// Constructor allocation and initialization charges.
    #[must_use]
    pub const fn construction_accounting(&self) -> SetupAccounting {
        self.workspace.construction_accounting()
    }

    pub(crate) fn search_window_untyped(
        &mut self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        contract: OutputContract,
    ) -> Result<UntypedReport, SearchError> {
        execute_bound(
            self.automaton,
            haystack,
            window,
            &mut self.workspace,
            limits,
            contract,
            self.capabilities,
        )
    }

    pub(crate) fn search_span_at_untyped(
        &mut self,
        source: &mut K0SpanSourceCursor<'_>,
        start: usize,
        limits: SearchLimits,
    ) -> Result<UntypedReport, SearchError> {
        let haystack = source.haystack;
        if let Some(descriptor) = self.root_run {
            if self.automaton.start_filter_proof.get().is_some() {
                return search_span_with_root_run_cursor(
                    self.automaton,
                    haystack,
                    start,
                    &mut self.workspace,
                    limits,
                    self.capabilities,
                    descriptor,
                    &mut source.root_run,
                );
            }
        }
        search_span_with_bound_cursor(
            self.automaton,
            haystack,
            start,
            &mut self.workspace,
            limits,
            self.capabilities,
            &mut self.span_start_proof,
        )
    }
}

struct WorkMeter {
    limit: u64,
    consumed: u64,
}

impl WorkMeter {
    const fn new(limit: u64, consumed: u64) -> Self {
        Self { limit, consumed }
    }

    fn charge(&mut self, requested: u64, position: usize) -> Result<(), SearchError> {
        let next = self
            .consumed
            .checked_add(requested)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "search work counter",
            })?;
        if next > self.limit {
            return Err(SearchError::WorkLimitExceeded {
                limit: self.limit,
                consumed: self.consumed,
                requested,
                position,
            });
        }
        self.consumed = next;
        Ok(())
    }

    const fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.consumed)
    }

    fn try_charge_optional(&mut self, requested: u64, completion_reserve: u64) -> bool {
        let Some(optional) = self.remaining().checked_sub(completion_reserve) else {
            return false;
        };
        if requested > optional {
            return false;
        }
        self.charge_admitted(requested);
        true
    }

    fn charge_admitted(&mut self, requested: u64) {
        debug_assert!(requested <= self.remaining());
        // The caller proved `consumed + requested <= limit`, and `limit`
        // itself is representable. Saturation is therefore unreachable and
        // keeps this post-success accounting update infallible.
        self.consumed = self.consumed.saturating_add(requested);
    }
}

pub(crate) fn search(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    limits: SearchLimits,
    contract: OutputContract,
) -> Result<UntypedReport, SearchError> {
    validate_window(haystack, window)?;
    let layout = WorkspaceLayout::for_automaton(automaton)?;
    let cold_setup_work = layout
        .construction_work
        .checked_add(INVOCATION_RESET_WORK)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "one-shot setup work",
        })?;
    if cold_setup_work > limits.max_work {
        return Err(SearchError::WorkLimitExceeded {
            limit: limits.max_work,
            consumed: 0,
            requested: cold_setup_work,
            position: window.start(),
        });
    }
    let mut workspace = K0Workspace::new(
        automaton,
        WorkspaceLimits {
            max_setup_work: layout.construction_work,
            max_scratch_bytes: limits.max_scratch_bytes,
        },
    )?;
    let setup = workspace.construction_accounting();
    execute(
        automaton,
        haystack,
        window,
        &mut workspace,
        limits,
        setup,
        contract,
        false,
    )
}

pub(crate) fn search_with_workspace(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    contract: OutputContract,
) -> Result<UntypedReport, SearchError> {
    execute(
        automaton,
        haystack,
        window,
        workspace,
        limits,
        SetupAccounting::empty(workspace.retained_bytes, true),
        contract,
        true,
    )
}

pub(crate) fn search_with_authenticated_workspace(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    contract: OutputContract,
) -> Result<UntypedReport, SearchError> {
    validate_window(haystack, window)?;
    if workspace.bound_automaton_identity != automaton.identity() {
        // A facade may accept a workspace from an independently constructed
        // but semantically identical program. Preserve the ordinary public
        // workspace contract in that case: validate the complete shape and
        // decline identity-bound lazy/reverse caches. Only the exact immutable
        // automaton that allocated this workspace may take the abbreviated
        // authenticated path below.
        return search_with_workspace(automaton, haystack, window, workspace, limits, contract);
    }
    execute_bound_prevalidated(
        automaton,
        haystack,
        window,
        workspace,
        limits,
        contract,
        workspace.bound_capabilities,
    )
}

pub(crate) fn search_prevalidated_window_with_authenticated_workspace(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    contract: OutputContract,
) -> Result<UntypedReport, SearchError> {
    if workspace.bound_automaton_identity != automaton.identity() {
        // A semantic clone does not share the facade's exact-automaton proof.
        // Re-enter the complete public workspace path, including range and
        // layout validation, before touching its workspace.
        return search_with_workspace(automaton, haystack, window, workspace, limits, contract);
    }
    debug_assert!(validate_window(haystack, window).is_ok());
    execute_bound_prevalidated(
        automaton,
        haystack,
        window,
        workspace,
        limits,
        contract,
        workspace.bound_capabilities,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the continuation entry keeps its authenticated frontier and original window explicit"
)]
pub(crate) fn search_from_resume_with_workspace(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    resume_set: &mut K0ResumeSet,
    resume_state: usize,
    resume_position: usize,
    pending_end: Option<usize>,
    limits: SearchLimits,
    contract: OutputContract,
) -> Result<UntypedReport, SearchError> {
    validate_window(haystack, window)?;
    if resume_position < window.start() || resume_position > window.end() {
        return Err(SearchError::InvalidResumeState {
            detail: "resume position is outside the original search window",
        });
    }
    if resume_set.automaton_identity != automaton.identity() {
        return Err(SearchError::InvalidResumeState {
            detail: "resume set belongs to a different immutable automaton",
        });
    }
    if !workspace.lazy.is_allocated() || !workspace.lazy.is_bound_to(automaton) {
        return Err(SearchError::InvalidResumeState {
            detail: "resume requires an accelerated workspace bound to the same automaton",
        });
    }
    let (_, resume_pending) = resume_set.frontier(resume_state)?;
    if resume_pending != pending_end.is_some() {
        return Err(SearchError::InvalidResumeState {
            detail: "resume pending mode disagrees with the selected endpoint",
        });
    }
    if pending_end.is_some_and(|end| end < window.start() || end > resume_position) {
        return Err(SearchError::InvalidResumeState {
            detail: "resume selected endpoint is outside the consumed prefix",
        });
    }
    if !matches!(
        contract,
        OutputContract::Exists
            | OutputContract::EarliestEnd
            | OutputContract::SelectedEnd
            | OutputContract::Span
    ) {
        return Err(SearchError::InvalidResumeState {
            detail: "resume output contract is unsupported",
        });
    }
    execute_from_resume(
        automaton,
        haystack,
        window,
        workspace,
        resume_set,
        resume_state,
        resume_position,
        pending_end,
        limits,
        contract,
    )
}

fn lazy_capabilities(
    automaton: &Automaton,
    workspace: &K0Workspace,
    allow_lazy: bool,
    wants_span: bool,
) -> LazyCapabilities {
    let lazy = allow_lazy && workspace.lazy.is_allocated();
    LazyCapabilities {
        lazy,
        reverse: lazy
            && wants_span
            && workspace.reverse.is_allocated()
            && workspace.reverse.is_bound_to(automaton),
        contextual: automaton.stats().assertion_edges() != 0,
    }
}

fn effective_lazy_mode(
    automaton: &Automaton,
    workspace: &K0Workspace,
    wants_span: bool,
    capabilities: LazyCapabilities,
) -> Result<EffectiveLazyMode, SearchError> {
    let cached_start_known = capabilities.lazy
        && wants_span
        && !capabilities.contextual
        && workspace.lazy.is_bound_to(automaton)
        && workspace.lazy.initialized
        && lazy_initial_has_pending(workspace)?;
    let reverse = capabilities.reverse && wants_span && !cached_start_known;

    // A direct nullable initial state proves every retained consuming path
    // belongs to the invocation's window start. Before that row is prepared,
    // a direct endpoint workspace may attempt forward execution and
    // authenticate its pending bit; a direct nonnullable endpoint workspace
    // will decline the span acceleration and use Pike.
    let may_prove_start_without_reverse = wants_span && !capabilities.contextual;
    let lazy = capabilities.lazy && (!wants_span || reverse || may_prove_start_without_reverse);
    Ok(EffectiveLazyMode { lazy, reverse })
}

fn effective_bound_lazy_mode(
    workspace: &K0Workspace,
    wants_span: bool,
    capabilities: LazyCapabilities,
) -> Result<EffectiveLazyMode, SearchError> {
    let cached_start_known = capabilities.lazy
        && wants_span
        && !capabilities.contextual
        && workspace.lazy.initialized
        && lazy_initial_has_pending(workspace)?;
    let reverse = capabilities.reverse && wants_span && !cached_start_known;
    let may_prove_start_without_reverse = wants_span && !capabilities.contextual;
    let lazy = capabilities.lazy && (!wants_span || reverse || may_prove_start_without_reverse);
    Ok(EffectiveLazyMode { lazy, reverse })
}

pub(crate) fn search_span_with_workspace_cursor(
    automaton: &Automaton,
    haystack: &[u8],
    start: usize,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
) -> Result<UntypedReport, SearchError> {
    let window = SearchWindow::new(start, haystack.len());
    validate_window(haystack, window)?;
    let cursor = prepare_span_cursor(automaton, workspace, limits)?;
    let mode = effective_lazy_mode(automaton, workspace, true, cursor.capabilities)?;
    let mut setup = SetupAccounting::empty(workspace.retained_bytes, true);
    let (mut meter, setup_work) = prepare_prevalidated_invocation(
        automaton,
        workspace,
        window,
        limits,
        &mut setup,
        mode.lazy,
        mode.reverse,
    )?;
    let start_proof = match cursor.start_proof {
        SpanCursorStartProof::AutomatonOwned => {
            let proof =
                automaton
                    .start_filter_proof
                    .get()
                    .ok_or(SearchError::InternalInvariant {
                        detail: "cursor lost its automaton-owned start-filter proof",
                    })?;
            InvocationStartProof::Published(proof)
        }
        SpanCursorStartProof::Ordinary => {
            InvocationStartProof::Published(&ORDINARY_START_FILTER_PROOF)
        }
        SpanCursorStartProof::Unprepared => prepare_start_filter(
            automaton,
            workspace,
            &mut meter,
            window.start(),
            window.end(),
        )?,
    };
    let report = execute_prepared(
        automaton,
        haystack,
        window,
        workspace,
        limits,
        setup,
        OutputContract::Span,
        mode.lazy,
        mode.reverse,
        cursor.capabilities.contextual,
        meter,
        setup_work,
        start_proof.borrowed(),
    )?;
    workspace.span_cursor.start_proof = retained_span_cursor_start_proof(automaton);
    Ok(report)
}

fn search_span_with_bound_cursor(
    automaton: &Automaton,
    haystack: &[u8],
    start: usize,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    capabilities: LazyCapabilities,
    retained_start_proof: &mut SpanCursorStartProof,
) -> Result<UntypedReport, SearchError> {
    let window = SearchWindow::new(start, haystack.len());
    validate_window(haystack, window)?;
    let mode = effective_bound_lazy_mode(workspace, true, capabilities)?;
    let mut setup = SetupAccounting::empty(workspace.retained_bytes, true);
    let (mut meter, setup_work) = prepare_bound_invocation(
        automaton,
        workspace,
        window,
        limits,
        &mut setup,
        mode.lazy,
        mode.reverse,
    )?;
    let start_proof = match *retained_start_proof {
        SpanCursorStartProof::AutomatonOwned => {
            let proof =
                automaton
                    .start_filter_proof
                    .get()
                    .ok_or(SearchError::InternalInvariant {
                        detail: "bound cursor lost its automaton-owned start-filter proof",
                    })?;
            InvocationStartProof::Published(proof)
        }
        SpanCursorStartProof::Ordinary => {
            InvocationStartProof::Published(&ORDINARY_START_FILTER_PROOF)
        }
        SpanCursorStartProof::Unprepared => prepare_start_filter(
            automaton,
            workspace,
            &mut meter,
            window.start(),
            window.end(),
        )?,
    };
    let report = execute_prepared(
        automaton,
        haystack,
        window,
        workspace,
        limits,
        setup,
        OutputContract::Span,
        mode.lazy,
        mode.reverse,
        capabilities.contextual,
        meter,
        setup_work,
        start_proof.borrowed(),
    )?;
    *retained_start_proof = retained_span_cursor_start_proof(automaton);
    Ok(report)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the specialized span entry keeps source-bound root-run state explicit"
)]
#[inline(never)]
fn search_span_with_root_run_cursor(
    automaton: &Automaton,
    haystack: &[u8],
    start: usize,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    capabilities: LazyCapabilities,
    descriptor: RootRunDescriptor,
    cursor: &mut RootRunBlockCursor,
) -> Result<UntypedReport, SearchError> {
    let window = SearchWindow::new(start, haystack.len());
    validate_window(haystack, window)?;
    let mode = effective_bound_lazy_mode(workspace, true, capabilities)?;
    let mut setup = SetupAccounting::empty(workspace.retained_bytes, true);
    let (mut meter, setup_work) = prepare_bound_invocation(
        automaton,
        workspace,
        window,
        limits,
        &mut setup,
        mode.lazy,
        mode.reverse,
    )?;
    let proof = automaton
        .start_filter_proof
        .get()
        .ok_or(SearchError::InternalInvariant {
            detail: "root-run corridor lost its published start-filter proof",
        })?;
    let (scanner, classifier) =
        root_run_ascii_scanner(descriptor, proof).ok_or(SearchError::InternalInvariant {
            detail: "root-run descriptor disagreed with its published start scanner",
        })?;

    // Source-derived residuals are transactional: a hard-limit or internal
    // failure leaves the caller-owned iterator cursor byte-for-byte unchanged,
    // so an exact retry is well defined.
    let mut transactional_cursor = *cursor;
    let (pending, boundaries) = execute_root_run_corridor(
        automaton,
        descriptor,
        scanner,
        classifier,
        haystack,
        window,
        &mut transactional_cursor,
        &mut meter,
    )?;
    let transition_work =
        meter
            .consumed
            .checked_sub(setup_work)
            .ok_or(SearchError::InternalInvariant {
                detail: "setup work exceeded total root-run search work",
            })?;
    let report = UntypedReport {
        found: pending,
        accounting: SearchAccounting::new(
            meter.consumed,
            setup,
            transition_work,
            workspace.retained_bytes,
            boundaries,
        ),
    };
    *cursor = transactional_cursor;
    Ok(report)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the forward loop keeps endpoint commitment and cache handoff together"
)]
fn execute_lazy_loop(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    contract: OutputContract,
    core_reserve: u64,
    scanner: Option<&StartPositionScanner>,
    guard: Option<&StartPositionClass>,
    probe: Option<&StartPositionClass>,
    adaptive_probe: &mut AdaptiveStartProbe,
    _ready: DirectLazyReady,
) -> Result<Option<(Option<MatchSpan>, usize)>, SearchError> {
    debug_assert!(matches!(
        contract,
        OutputContract::Exists
            | OutputContract::EarliestEnd
            | OutputContract::SelectedEnd
            | OutputContract::Span
    ));
    debug_assert!(workspace.lazy.is_allocated());
    debug_assert!(workspace.lazy.is_bound_to(automaton));
    debug_assert!(workspace.lazy.initialized);
    debug_assert!(!workspace.lazy.declined);

    let haystack = haystack
        .get(..window.end())
        .ok_or(SearchError::InternalInvariant {
            detail: "lazy DFA window exceeds the validated haystack",
        })?;

    let (initial_pending, initial_terminal) = match workspace.lazy.initial_kind {
        LazyInitialKind::Positive | LazyInitialKind::PositiveSingle => (false, false),
        LazyInitialKind::NullablePrefix => (true, false),
        LazyInitialKind::NullableTerminal => (true, true),
        LazyInitialKind::Uninitialized => {
            return Err(SearchError::InternalInvariant {
                detail: "initialized lazy DFA has no cached initial kind",
            });
        }
    };
    let earliest = matches!(
        contract,
        OutputContract::Exists | OutputContract::EarliestEnd
    );
    let initial = workspace.lazy.initial;
    if initial == LAZY_NO_STATE {
        return Err(SearchError::InternalInvariant {
            detail: "initialized lazy DFA has no initial state",
        });
    }
    if initial_pending && (earliest || initial_terminal) {
        return Ok(Some((
            Some(MatchSpan::new(window.start(), window.start())),
            1,
        )));
    }
    let initial_row = direct_row_offset(initial)?;
    let mut state = LazyState::Cached(initial_row);
    let mut position = window.start();
    let mut boundaries = 0usize;
    let mut pending_end = initial_pending.then_some(window.start());
    let mut entered = false;
    let mut retained_start_mask = RetainedStartMaskCursor::default();
    let mut engine_candidate = None;

    loop {
        if pending_end.is_none() && state == LazyState::Cached(initial_row) {
            if let Some(scanner) = scanner {
                if position < window.end() {
                    if let (Some(probe), Some(candidate)) = (probe, engine_candidate.take()) {
                        adaptive_probe.observe_restartable_rejection(
                            probe,
                            haystack,
                            candidate,
                            window.end(),
                            meter,
                        )?;
                    }
                } else {
                    engine_candidate = None;
                }
                position = next_start_candidate_adaptive(
                    scanner,
                    haystack,
                    position,
                    window.end(),
                    guard,
                    probe,
                    meter,
                    &mut retained_start_mask,
                    adaptive_probe,
                )?;
                if position == window.end() {
                    return Ok(Some((None, boundaries)));
                }
                if probe.is_some() && adaptive_probe.samples_rejections() {
                    engine_candidate = Some(position);
                }
            }
        }
        if !entered {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "the validated window proves the initial boundary increment fits"
            )]
            {
                boundaries += 1;
            }
            entered = true;
        }
        if position >= haystack.len() {
            if position == haystack.len() {
                return Ok(Some((
                    pending_end.map(|end| MatchSpan::new(window.start(), end)),
                    boundaries,
                )));
            }
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA source position exceeded the validated window",
            });
        }

        meter.charge(1, position)?;
        #[allow(
            clippy::indexing_slicing,
            reason = "the immediately dominating window-ceiling check proves this source index"
        )]
        let byte = haystack[position];
        let transition = match state {
            LazyState::Cached(cached) => {
                let cell = workspace.lazy.direct_cell(cached, byte)?;
                if cell == LAZY_CELL_UNFILLED {
                    build_lazy_cached_transition(
                        automaton,
                        direct_row_state(cached),
                        byte,
                        workspace,
                        meter,
                        core_reserve,
                        position,
                    )?
                } else {
                    LazyTransition::Ready(cell)
                }
            }
            LazyState::Inline { pending } => {
                build_lazy_inline_transition(automaton, byte, pending, workspace, meter, position)?
            }
        };
        debug_assert!(position < window.end());
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "the validated window proves hot-loop position and boundary increments fit"
        )]
        {
            position += 1;
            boundaries += 1;
        }

        let (accepted, next) = match transition {
            LazyTransition::Ready(cell) => {
                let encoded = cell & LAZY_CELL_STATE_MASK;
                (
                    cell & LAZY_CELL_ACCEPT != 0,
                    if encoded == 0 {
                        None
                    } else {
                        Some(LazyState::Cached(encoded.checked_sub(1).ok_or(
                            SearchError::InternalInvariant {
                                detail: "lazy DFA encoded state underflowed",
                            },
                        )?))
                    },
                )
            }
            LazyTransition::Inline { accepted, pending } => {
                (accepted, Some(LazyState::Inline { pending }))
            }
        };
        if accepted {
            pending_end = Some(position);
            if earliest {
                return Ok(Some((
                    Some(MatchSpan::new(window.start(), position)),
                    boundaries,
                )));
            }
        }
        let Some(next) = next else {
            return Ok(Some((
                pending_end.map(|end| MatchSpan::new(window.start(), end)),
                boundaries,
            )));
        };
        state = next;
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the shared Pike/lazy entry authenticates one complete invocation"
)]
fn execute(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    setup: SetupAccounting,
    contract: OutputContract,
    allow_lazy: bool,
) -> Result<UntypedReport, SearchError> {
    validate_window(haystack, window)?;
    let wants_span = matches!(contract, OutputContract::Span);
    let contextual = automaton.stats().assertion_edges() != 0;
    let mode = if wants_span {
        effective_lazy_mode(
            automaton,
            workspace,
            true,
            lazy_capabilities(automaton, workspace, allow_lazy, true),
        )?
    } else {
        // Endpoint contracts never recover a start, so reverse capability,
        // binding, and nullable-start proof checks cannot affect their mode.
        EffectiveLazyMode {
            lazy: allow_lazy && workspace.lazy.is_allocated(),
            reverse: false,
        }
    };
    let mut setup = setup;
    let (mut meter, setup_work) = prepare_invocation(
        automaton,
        workspace,
        window,
        limits,
        &mut setup,
        mode.lazy,
        mode.reverse,
    )?;
    let start_proof = prepare_start_filter(
        automaton,
        workspace,
        &mut meter,
        window.start(),
        window.end(),
    )?;
    execute_prepared(
        automaton,
        haystack,
        window,
        workspace,
        limits,
        setup,
        contract,
        mode.lazy,
        mode.reverse,
        contextual,
        meter,
        setup_work,
        start_proof.borrowed(),
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the bound Pike/lazy entry authenticates one complete invocation"
)]
fn execute_bound(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    contract: OutputContract,
    capabilities: LazyCapabilities,
) -> Result<UntypedReport, SearchError> {
    validate_window(haystack, window)?;
    execute_bound_prevalidated(
        automaton,
        haystack,
        window,
        workspace,
        limits,
        contract,
        capabilities,
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the prevalidated bound entry carries one authenticated invocation"
)]
fn execute_bound_prevalidated(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    contract: OutputContract,
    capabilities: LazyCapabilities,
) -> Result<UntypedReport, SearchError> {
    let wants_span = matches!(contract, OutputContract::Span);
    let mode = if wants_span {
        effective_bound_lazy_mode(workspace, true, capabilities)?
    } else {
        EffectiveLazyMode {
            lazy: capabilities.lazy,
            reverse: false,
        }
    };
    let mut setup = SetupAccounting::empty(workspace.retained_bytes, true);
    let (meter, setup_work) = prepare_bound_invocation(
        automaton,
        workspace,
        window,
        limits,
        &mut setup,
        mode.lazy,
        mode.reverse,
    )?;
    let start_proof = if let Some(proof) = automaton.start_filter_proof.get() {
        ExecutionStartProof::Published(proof)
    } else if automaton.start_filter_proof.allocation_failed() {
        ExecutionStartProof::Published(&ORDINARY_START_FILTER_PROOF)
    } else {
        return execute_bound_with_unprepared_start_filter(
            automaton,
            haystack,
            window,
            workspace,
            limits,
            setup,
            contract,
            mode,
            capabilities.contextual,
            meter,
            setup_work,
        );
    };
    execute_prepared(
        automaton,
        haystack,
        window,
        workspace,
        limits,
        setup,
        contract,
        mode.lazy,
        mode.reverse,
        capabilities.contextual,
        meter,
        setup_work,
        start_proof,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the cold proof path preserves the complete prepared invocation transaction"
)]
#[inline(never)]
fn execute_bound_with_unprepared_start_filter(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    setup: SetupAccounting,
    contract: OutputContract,
    mode: EffectiveLazyMode,
    contextual: bool,
    mut meter: WorkMeter,
    setup_work: u64,
) -> Result<UntypedReport, SearchError> {
    let start_proof = prepare_start_filter(
        automaton,
        workspace,
        &mut meter,
        window.start(),
        window.end(),
    )?;
    execute_prepared(
        automaton,
        haystack,
        window,
        workspace,
        limits,
        setup,
        contract,
        mode.lazy,
        mode.reverse,
        contextual,
        meter,
        setup_work,
        start_proof.borrowed(),
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the shared Pike/lazy entry authenticates one complete invocation"
)]
fn execute_prepared(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
    mut setup: SetupAccounting,
    contract: OutputContract,
    may_use_lazy: bool,
    may_use_reverse: bool,
    contextual: bool,
    mut meter: WorkMeter,
    mut setup_work: u64,
    start_proof: ExecutionStartProof<'_>,
) -> Result<UntypedReport, SearchError> {
    let wants_span = matches!(contract, OutputContract::Span);
    let supported_contract = matches!(
        contract,
        OutputContract::Exists
            | OutputContract::EarliestEnd
            | OutputContract::SelectedEnd
            | OutputContract::Span
    );
    let retains_priority_prefix =
        matches!(contract, OutputContract::SelectedEnd | OutputContract::Span);
    let mut direct_ready = (retains_priority_prefix
        && may_use_lazy
        && !contextual
        && workspace.lazy.is_bound_to(automaton)
        && workspace.lazy.initialized
        && !workspace.lazy.declined)
        .then_some(DirectLazyReady);
    // Cache learning is optional work. Preserve the ordinary reusable-work
    // certificate by reserving its complete transition allowance before any
    // initial-state publication or speculative interning. Unlimited callers
    // need no finite reserve.
    let window_bytes =
        window
            .end()
            .checked_sub(window.start())
            .ok_or(SearchError::InternalInvariant {
                detail: "validated search window has a descending range",
            })?;
    let ordinary_core_reserve = if may_use_lazy && limits.max_work != u64::MAX {
        automaton
            .conservative_transition_work_bound(window_bytes)
            .unwrap_or(u64::MAX)
    } else {
        0
    };
    let reverse_core_reserve = if may_use_reverse && limits.max_work != u64::MAX {
        conservative_reverse_work_bound(automaton, window_bytes).unwrap_or(u64::MAX)
    } else {
        0
    };
    let lazy_core_reserve = if may_use_reverse && limits.max_work != u64::MAX {
        ordinary_core_reserve.saturating_add(reverse_core_reserve)
    } else {
        ordinary_core_reserve
    };
    // Unlike direct byte rows, a contextual hit still evaluates the assertion
    // symbol and probes a bounded associative store. Admit that fixed work
    // source-free before reading the haystack or mutating contextual state.
    // A finite call retains that complete bound as its learning reserve.
    // Exact-bound calls therefore execute inline or hit existing records,
    // while callers with surplus work may publish without consuming the
    // source-free completion allowance.
    let contextual_bound = if contextual && limits.max_work != u64::MAX {
        contextual_execution_work_upper(automaton, window_bytes, wants_span).ok()
    } else {
        None
    };
    let contextual_admitted = !contextual
        || limits.max_work == u64::MAX
        || contextual_bound.is_some_and(|bound| bound <= meter.remaining());
    let contextual_learning_reserve = if contextual && limits.max_work != u64::MAX {
        contextual_bound.unwrap_or(u64::MAX)
    } else {
        lazy_core_reserve
    };
    let bidirectional_ready = if contextual {
        contextual_admitted
            && !start_proof.proof().relaxed_nullable
            && (!wants_span || (may_use_reverse && workspace.reverse.context.is_allocated()))
    } else if wants_span && may_use_lazy {
        let start_known = if workspace.lazy.initialized {
            lazy_initial_has_pending(workspace)?
        } else {
            false
        };
        if !may_use_reverse && !start_known && !start_proof.proof().relaxed_nullable {
            false
        } else {
            let forward_preparation = if workspace.lazy.initialized {
                0
            } else {
                lazy_initial_work_upper(automaton).unwrap_or(u64::MAX)
            };
            let reverse_preparation =
                if !may_use_reverse || start_known || workspace.reverse.initialized {
                    0
                } else {
                    reverse_initial_work_upper(automaton).unwrap_or(u64::MAX)
                };
            let combined_preparation = forward_preparation.saturating_add(reverse_preparation);
            let admitted = combined_preparation == 0
                || meter
                    .remaining()
                    .checked_sub(lazy_core_reserve)
                    .is_some_and(|optional| combined_preparation <= optional);
            if !admitted {
                false
            } else if direct_ready.is_some()
                || prepare_lazy(
                    automaton,
                    workspace,
                    &mut meter,
                    lazy_core_reserve,
                    window.start(),
                )?
            {
                direct_ready = Some(DirectLazyReady);
                lazy_initial_has_pending(workspace)?
                    || (may_use_reverse
                        && prepare_reverse_lazy(
                            automaton,
                            workspace,
                            &mut meter,
                            lazy_core_reserve,
                            window.start(),
                        )?)
            } else {
                false
            }
        }
    } else {
        true
    };
    let earliest = matches!(
        contract,
        OutputContract::Exists | OutputContract::EarliestEnd
    );
    // This state is deliberately shared across lazy execution and its Pike
    // fallback, but dies with this one invocation.
    let mut adaptive_probe = AdaptiveStartProbe::default();
    let lazy = if may_use_lazy && bidirectional_ready && supported_contract {
        if contextual {
            execute_context_lazy_loop(
                automaton,
                haystack,
                window,
                workspace,
                &mut meter,
                contract,
                contextual_learning_reserve,
                start_proof.proof().scanner.as_ref(),
                start_proof.proof().guard(),
                start_proof.proof().probe(),
                start_proof.proof().force_haystack_start,
                start_proof.proof().relaxed_nullable,
                &mut adaptive_probe,
            )?
            .map(|(found, boundaries)| (found, boundaries, false))
        } else {
            let ready = if let Some(ready) = direct_ready {
                Some(ready)
            } else {
                prepare_lazy(
                    automaton,
                    workspace,
                    &mut meter,
                    lazy_core_reserve,
                    window.start(),
                )?
                .then_some(DirectLazyReady)
            };
            if let Some(ready) = ready {
                if wants_span {
                    execute_lazy_span_loop::<true>(
                        automaton,
                        haystack,
                        window,
                        workspace,
                        &mut meter,
                        contract,
                        lazy_core_reserve,
                        start_proof.proof().scanner.as_ref(),
                        start_proof.proof().guard(),
                        start_proof.proof().probe(),
                        &mut adaptive_probe,
                        ready,
                    )?
                } else {
                    execute_lazy_loop(
                        automaton,
                        haystack,
                        window,
                        workspace,
                        &mut meter,
                        contract,
                        lazy_core_reserve,
                        start_proof.proof().scanner.as_ref(),
                        start_proof.proof().guard(),
                        start_proof.proof().probe(),
                        &mut adaptive_probe,
                        ready,
                    )?
                    .map(|(found, boundaries)| (found, boundaries, false))
                }
            } else {
                None
            }
        }
    } else {
        None
    };
    let used_lazy = lazy.is_some();
    let (mut pending, mut boundaries, direct_start_known) = if let Some(result) = lazy {
        result
    } else if let Some(scanner) = start_proof.proof().scanner.as_ref() {
        let (found, boundaries) = execute_filtered_loop(
            automaton,
            haystack,
            window,
            workspace,
            &mut meter,
            earliest,
            scanner,
            start_proof.proof().guard(),
            start_proof.proof().probe(),
            start_proof.proof().force_haystack_start,
            &mut adaptive_probe,
        )?;
        (found, boundaries, false)
    } else {
        // Keep the common nullable/all-byte decline path free of scanner and
        // secondary-filter option tests at every examined boundary.
        debug_assert!(start_proof.proof().filter.is_none());
        debug_assert!(!start_proof.proof().force_haystack_start);
        let (found, boundaries) =
            execute_unfiltered_loop(automaton, haystack, window, workspace, &mut meter, earliest)?;
        (found, boundaries, false)
    };
    if wants_span && used_lazy {
        if let Some(selected) = pending {
            if !direct_start_known {
                let end = selected.end();
                let (start, reverse_boundaries) = if contextual {
                    execute_context_reverse_lazy_loop(
                        automaton,
                        haystack,
                        window.start(),
                        end,
                        workspace,
                        &mut meter,
                        contextual_learning_reserve,
                    )?
                } else {
                    execute_reverse_lazy_loop(
                        automaton,
                        haystack,
                        window.start(),
                        end,
                        workspace,
                        &mut meter,
                        reverse_core_reserve,
                    )?
                };
                let start = start.ok_or(SearchError::InternalInvariant {
                    detail: "reverse DFA could not recover the forward-selected span",
                })?;
                pending = Some(MatchSpan::new(start, end));
                boundaries = boundaries.checked_add(reverse_boundaries).ok_or(
                    SearchError::ArithmeticOverflow {
                        computation: "bidirectional examined boundary count",
                    },
                )?;
            }
        }
    }

    let published_proof_bytes = start_proof.publish(
        automaton,
        workspace.retained_bytes,
        limits.max_scratch_bytes,
        &mut meter,
        &mut setup,
        &mut setup_work,
    );
    let scratch_bytes = workspace
        .retained_bytes
        .checked_add(published_proof_bytes)
        .expect("published start-filter payload was preflighted");
    let transition_work =
        meter
            .consumed
            .checked_sub(setup_work)
            .ok_or(SearchError::InternalInvariant {
                detail: "setup work exceeded total search work",
            })?;
    Ok(UntypedReport {
        found: pending,
        accounting: SearchAccounting::new(
            meter.consumed,
            setup,
            transition_work,
            scratch_bytes,
            boundaries,
        ),
    })
}

// Retained-frontier continuation is a separately selected engine entry. Give
// it private setup and transition helpers so it cannot turn the
// ordinary K0 helpers into multi-caller outlining candidates under ThinLTO.
fn prepare_resume_invocation(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    window: SearchWindow,
    limits: SearchLimits,
    setup: &mut SetupAccounting,
    may_use_lazy: bool,
    may_use_reverse: bool,
) -> Result<(WorkMeter, u64), SearchError> {
    let required_layout = WorkspaceLayout::for_automaton(automaton)?;
    if required_layout.states != workspace.layout.states
        || required_layout.edges != workspace.layout.edges
        || required_layout.zero_width_edges != workspace.layout.zero_width_edges
        || required_layout.closure_slots != workspace.layout.closure_slots
    {
        return Err(SearchError::WorkspaceLayoutMismatch {
            required_states: required_layout.states,
            actual_states: workspace.layout.states,
            required_edges: required_layout.edges,
            actual_edges: workspace.layout.edges,
            required_zero_width_edges: required_layout.zero_width_edges,
            actual_zero_width_edges: workspace.layout.zero_width_edges,
        });
    }
    if setup.retained_bytes > limits.max_scratch_bytes {
        return Err(SearchError::ResourceLimit {
            resource: ResourceKind::ScratchBytes,
            needed: setup.retained_bytes,
            limit: limits.max_scratch_bytes,
        });
    }

    prepare_bound_invocation(
        automaton,
        workspace,
        window,
        limits,
        setup,
        may_use_lazy,
        may_use_reverse,
    )
}

#[allow(
    clippy::inline_always,
    reason = "the private resume clone must not become an outlined second caller"
)]
#[inline(always)]
fn resume_lazy_state_bounds(
    lazy: &LazyWorkspace,
    state: u32,
) -> Result<(usize, usize, bool), SearchError> {
    let state = usize::try_from(state).map_err(|_| SearchError::InternalInvariant {
        detail: "lazy DFA state does not fit usize",
    })?;
    if state >= lazy.state_len {
        return Err(SearchError::InternalInvariant {
            detail: "lazy DFA state is outside the retained cache",
        });
    }
    let offset = *lazy
        .offsets
        .get(state)
        .ok_or(SearchError::InternalInvariant {
            detail: "lazy DFA state offset is outside metadata",
        })?;
    let length = usize::try_from(*lazy.lengths.get(state).ok_or(
        SearchError::InternalInvariant {
            detail: "lazy DFA state length is outside metadata",
        },
    )?)
    .map_err(|_| SearchError::InternalInvariant {
        detail: "lazy DFA state length does not fit usize",
    })?;
    let end = offset
        .checked_add(length)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "lazy DFA state item end",
        })?;
    if end > lazy.item_len || end > lazy.items.len() {
        return Err(SearchError::InternalInvariant {
            detail: "lazy DFA state items are outside the retained arena",
        });
    }
    let pending = *lazy
        .modes
        .get(state)
        .ok_or(SearchError::InternalInvariant {
            detail: "lazy DFA state mode is outside metadata",
        })?
        != 0;
    Ok((offset, length, pending))
}

const fn resume_lazy_start_action(
    source_len: usize,
    final_len: usize,
    injected_root: bool,
) -> LazyStartAction {
    if !injected_root {
        return LazyStartAction::Propagate;
    }
    if source_len == 0 {
        return if final_len == 0 {
            LazyStartAction::Drop
        } else {
            LazyStartAction::Reset
        };
    }
    if final_len == source_len {
        LazyStartAction::Propagate
    } else {
        LazyStartAction::Drop
    }
}

#[allow(
    clippy::inline_always,
    clippy::too_many_arguments,
    reason = "the private resume publication must not alter the ordinary helper call graph"
)]
#[inline(always)]
fn finish_resume_lazy_cached_transition(
    automaton: &Automaton,
    state: u32,
    byte: u8,
    accepted: bool,
    pending: bool,
    start_action: LazyStartAction,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<LazyTransition, SearchError> {
    let next_pending = pending || accepted;
    let encoded = if workspace.lazy.scratch_len == 0 {
        0
    } else {
        match workspace
            .lazy
            .intern_speculative(next_pending, meter, core_reserve, position)?
        {
            LazyInterned::State(next) => direct_row_encoded_state(next)?,
            LazyInterned::BudgetDeclined => {
                workspace.lazy.retain_scratch_as_frontier()?;
                workspace.lazy.inline_start_action = start_action;
                return Ok(LazyTransition::Inline {
                    accepted,
                    pending: next_pending,
                });
            }
            LazyInterned::CapacityFull => {
                validate_lazy_capacity_full(
                    automaton.stats().consuming_states(),
                    "exact small lazy DFA exhausted its proven capacity",
                )?;
                workspace.lazy.saturated = true;
                workspace.lazy.retain_scratch_as_frontier()?;
                workspace.lazy.inline_start_action = start_action;
                return Ok(LazyTransition::Inline {
                    accepted,
                    pending: next_pending,
                });
            }
        }
    };
    let cell = encoded | if accepted { LAZY_CELL_ACCEPT } else { 0 } | start_action.cell_bits();
    workspace.lazy.set_cell(state, byte, cell)?;
    Ok(LazyTransition::Ready(cell))
}

#[allow(
    clippy::inline_always,
    clippy::too_many_arguments,
    reason = "the private resumed miss must stay isolated from the ordinary helper call graph"
)]
#[inline(always)]
fn build_resume_lazy_cached_transition(
    automaton: &Automaton,
    state: u32,
    byte: u8,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<LazyTransition, SearchError> {
    let cached = workspace.lazy.cell(state, byte)?;
    if cached != LAZY_CELL_UNFILLED {
        return Ok(LazyTransition::Ready(cached));
    }

    let (offset, length, pending) = resume_lazy_state_bounds(&workspace.lazy, state)?;
    begin_lazy_closure(workspace, meter, position)?;
    let mut accepted = false;
    'frontier: for ordinal in 0..length {
        let item = offset
            .checked_add(ordinal)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA item index",
            })?;
        let consuming =
            *workspace
                .lazy
                .items
                .get(item)
                .ok_or(SearchError::InternalInvariant {
                    detail: "lazy DFA item is outside the retained arena",
                })?;
        for edge in automaton.state_edges(consuming) {
            meter.charge(1, position)?;
            if automaton.byte_starts[edge] <= byte
                && byte <= automaton.byte_ends[edge]
                && expand_lazy_root(
                    automaton,
                    automaton.edge_targets[edge],
                    workspace,
                    meter,
                    position,
                )?
            {
                accepted = true;
                break 'frontier;
            }
        }
    }
    let source_len = workspace.lazy.scratch_len;
    let mut injected_root = false;
    if !accepted && !pending {
        injected_root = true;
        if expand_lazy_root(automaton, automaton.start, workspace, meter, position)? {
            return Err(SearchError::InternalInvariant {
                detail: "nonnullable lazy DFA accepted an injected empty match",
            });
        }
    }
    let start_action =
        resume_lazy_start_action(source_len, workspace.lazy.scratch_len, injected_root);
    finish_resume_lazy_cached_transition(
        automaton,
        state,
        byte,
        accepted,
        pending,
        start_action,
        workspace,
        meter,
        core_reserve,
        position,
    )
}

#[allow(
    clippy::inline_always,
    reason = "the private resumed miss must stay isolated from the ordinary helper call graph"
)]
#[inline(always)]
fn build_resume_lazy_inline_transition(
    automaton: &Automaton,
    byte: u8,
    pending: bool,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<LazyTransition, SearchError> {
    let length = workspace.lazy.frontier_len;
    begin_lazy_closure(workspace, meter, position)?;
    let mut accepted = false;
    'frontier: for ordinal in 0..length {
        let consuming =
            *workspace
                .lazy
                .frontier
                .get(ordinal)
                .ok_or(SearchError::InternalInvariant {
                    detail: "lazy DFA inline frontier item is outside its arena",
                })?;
        for edge in automaton.state_edges(consuming) {
            meter.charge(1, position)?;
            if automaton.byte_starts[edge] <= byte
                && byte <= automaton.byte_ends[edge]
                && expand_lazy_root(
                    automaton,
                    automaton.edge_targets[edge],
                    workspace,
                    meter,
                    position,
                )?
            {
                accepted = true;
                break 'frontier;
            }
        }
    }
    let source_len = workspace.lazy.scratch_len;
    let mut injected_root = false;
    if !accepted && !pending {
        injected_root = true;
        if expand_lazy_root(automaton, automaton.start, workspace, meter, position)? {
            return Err(SearchError::InternalInvariant {
                detail: "nonnullable inline lazy DFA accepted an injected empty match",
            });
        }
    }
    let start_action =
        resume_lazy_start_action(source_len, workspace.lazy.scratch_len, injected_root);
    let next_pending = pending || accepted;
    if workspace.lazy.scratch_len == 0 {
        workspace.lazy.frontier_len = 0;
        let accepted_bit = if accepted { LAZY_CELL_ACCEPT } else { 0 };
        return Ok(LazyTransition::Ready(
            accepted_bit | start_action.cell_bits(),
        ));
    }
    workspace.lazy.retain_scratch_as_frontier()?;
    workspace.lazy.inline_start_action = start_action;
    Ok(LazyTransition::Inline {
        accepted,
        pending: next_pending,
    })
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the resume transaction keeps forward commitment, optional reverse recovery, and accounting adjacent"
)]
#[inline(never)]
fn execute_from_resume(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    resume_set: &mut K0ResumeSet,
    resume_state: usize,
    resume_position: usize,
    pending_end: Option<usize>,
    limits: SearchLimits,
    contract: OutputContract,
) -> Result<UntypedReport, SearchError> {
    let wants_span = contract == OutputContract::Span;
    if wants_span
        && (!workspace.reverse.is_allocated() || !workspace.reverse.is_bound_to(automaton))
    {
        return Err(SearchError::InvalidResumeState {
            detail: "span resume requires a bidirectional workspace",
        });
    }

    let scratch_bytes = workspace
        .retained_bytes
        .checked_add(resume_set.retained_bytes)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "resume invocation retained scratch bytes",
        })?;
    let mut setup = SetupAccounting::empty(scratch_bytes, true);
    let (mut meter, setup_work) = prepare_resume_invocation(
        automaton,
        workspace,
        window,
        limits,
        &mut setup,
        true,
        wants_span,
    )?;
    let remaining_bytes = window
        .end()
        .checked_sub(resume_position)
        .ok_or(SearchError::InvalidResumeState {
            detail: "resume position follows the original window end",
        })?;
    let window_bytes = window
        .end()
        .checked_sub(window.start())
        .ok_or(SearchError::InternalInvariant {
            detail: "validated resume window descends",
        })?;
    let forward_reserve = if limits.max_work == u64::MAX {
        0
    } else {
        automaton
            .conservative_transition_work_bound(remaining_bytes)
            .unwrap_or(u64::MAX)
    };
    let reverse_reserve = if wants_span && limits.max_work != u64::MAX {
        conservative_reverse_work_bound(automaton, window_bytes).unwrap_or(u64::MAX)
    } else {
        0
    };
    let completion_reserve = forward_reserve.saturating_add(reverse_reserve);
    let reverse_initial_reserve = if wants_span
        && limits.max_work != u64::MAX
        && !workspace.reverse.initialized
    {
        reverse_initial_work_upper(automaton).unwrap_or(u64::MAX)
    } else {
        0
    };
    let post_seed_reserve = completion_reserve.saturating_add(reverse_initial_reserve);
    let seed_reserve = if limits.max_work == u64::MAX {
        0
    } else {
        resume_seed_work_upper(resume_set, resume_state)?
    };
    let pre_seed_reserve = post_seed_reserve.saturating_add(seed_reserve);

    // Preparing the ordinary initial row is optional for semantics, but lets
    // the resumed frontier intern into the same persistent cache and reuse its
    // future rows. If finite work cannot admit that setup, continuation stays
    // exact from an inline frontier.
    let may_intern = prepare_lazy(
        automaton,
        workspace,
        &mut meter,
        pre_seed_reserve,
        resume_position,
    )?;
    let state = seed_lazy_resume_state(
        automaton,
        workspace,
        resume_set,
        resume_state,
        &mut meter,
        post_seed_reserve,
        resume_position,
        may_intern,
    )?;
    let (mut pending, mut boundaries) = execute_lazy_resume_loop(
        automaton,
        haystack,
        window,
        workspace,
        &mut meter,
        contract,
        post_seed_reserve,
        state,
        resume_position,
        pending_end,
    )?;

    if wants_span {
        if let Some(selected) = pending {
            let end = selected.end();
            if !prepare_reverse_lazy(
                automaton,
                workspace,
                &mut meter,
                reverse_reserve,
                end,
            )? {
                if workspace.reverse.declined {
                    return Err(SearchError::InternalInvariant {
                        detail: "selected resume endpoint has no reverse start frontier",
                    });
                }
                return Err(SearchError::WorkLimitExceeded {
                    limit: limits.max_work,
                    consumed: meter.consumed,
                    requested: reverse_initial_work_upper(automaton)?,
                    position: end,
                });
            }
            let (start, reverse_boundaries) = execute_resume_reverse_lazy_loop(
                automaton,
                haystack,
                window.start(),
                end,
                workspace,
                &mut meter,
                reverse_reserve,
            )?;
            let start = start.ok_or(SearchError::InternalInvariant {
                detail: "reverse DFA could not recover the resume-selected span",
            })?;
            pending = Some(MatchSpan::new(start, end));
            boundaries = boundaries.checked_add(reverse_boundaries).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "resume bidirectional examined boundary count",
                },
            )?;
        }
    }

    let transition_work = meter
        .consumed
        .checked_sub(setup_work)
        .ok_or(SearchError::InternalInvariant {
            detail: "resume setup work exceeded total search work",
        })?;
    Ok(UntypedReport {
        found: pending,
        accounting: SearchAccounting::new(
            meter.consumed,
            setup,
            transition_work,
            scratch_bytes,
            boundaries,
        ),
    })
}

/// Mandatory work needed to authenticate a retained frontier and copy it
/// into inline scratch. A valid cached hint may first compare every item plus
/// its pending-mode bit and then miss, so the exact worst case is `2n + 1`.
fn resume_seed_work_upper(
    resume_set: &K0ResumeSet,
    resume_state: usize,
) -> Result<u64, SearchError> {
    let length = u64::from(*resume_set.lengths.get(resume_state).ok_or(
        SearchError::InvalidResumeState {
            detail: "resume state index is outside the authenticated set",
        },
    )?);
    length
        .checked_mul(2)
        .and_then(|work| work.checked_add(1))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "resume seed work bound",
        })
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the seed publication checks both external and workspace state identities"
)]
#[inline(never)]
fn seed_lazy_resume_state(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    resume_set: &mut K0ResumeSet,
    resume_state: usize,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
    may_intern: bool,
) -> Result<LazyState, SearchError> {
    let (offset, length, pending) = {
        let offset = *resume_set
            .offsets
            .get(resume_state)
            .ok_or(SearchError::InvalidResumeState {
                detail: "resume state index is outside the authenticated set",
            })?;
        let length = usize::try_from(*resume_set.lengths.get(resume_state).ok_or(
            SearchError::InternalInvariant {
                detail: "resume state length is outside its metadata",
            },
        )?)
        .map_err(|_| SearchError::InternalInvariant {
            detail: "resume state length does not fit usize",
        })?;
        let pending = *resume_set
            .modes
            .get(resume_state)
            .ok_or(SearchError::InternalInvariant {
                detail: "resume state mode is outside its metadata",
            })?
            != 0;
        (offset, length, pending)
    };
    let end = offset
        .checked_add(length)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "ordered-frontier resume seed end",
        })?;
    let seed = resume_set
        .items
        .get(offset..end)
        .ok_or(SearchError::InternalInvariant {
            detail: "resume seed items are outside their retained arena",
        })?;

    let cached_hint = *resume_set
        .cached_states
        .get(resume_state)
        .ok_or(SearchError::InternalInvariant {
            detail: "resume cached-state hint is outside its metadata",
        })?;
    if cached_hint != LAZY_NO_STATE
        && usize::try_from(cached_hint)
            .ok()
            .is_some_and(|state| state < workspace.lazy.state_len)
    {
        let comparison_work = u64::try_from(length.saturating_add(1)).map_err(|_| {
            SearchError::ArithmeticOverflow {
                computation: "resume cached-state comparison work",
            }
        })?;
        meter.charge(comparison_work, position)?;
        let (cached_offset, cached_length, cached_pending) =
            resume_lazy_state_bounds(&workspace.lazy, cached_hint)?;
        let cached_end = cached_offset.checked_add(cached_length).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "resume cached-state item end",
            },
        )?;
        if cached_pending == pending
            && workspace.lazy.items.get(cached_offset..cached_end) == Some(seed)
        {
            return Ok(LazyState::Cached(direct_row_offset(cached_hint)?));
        }
    }
    resume_set.cached_states[resume_state] = LAZY_NO_STATE;

    let copy_work = u64::try_from(length).map_err(|_| SearchError::ArithmeticOverflow {
        computation: "resume frontier copy work",
    })?;
    meter.charge(copy_work, position)?;
    if length > workspace.lazy.scratch.len() || length > workspace.lazy.frontier.len() {
        return Err(SearchError::InvalidResumeState {
            detail: "resume frontier exceeds the automaton workspace arena",
        });
    }
    if may_intern && workspace.lazy.initialized && !workspace.lazy.declined {
        workspace.lazy.scratch[..length].copy_from_slice(seed);
        workspace.lazy.scratch_len = length;
        match workspace
            .lazy
            .intern_speculative(pending, meter, core_reserve, position)?
        {
            LazyInterned::State(state) => {
                resume_set.cached_states[resume_state] = state;
                return Ok(LazyState::Cached(direct_row_offset(state)?));
            }
            LazyInterned::BudgetDeclined => {
                workspace.lazy.retain_scratch_as_frontier()?;
                return Ok(LazyState::Inline { pending });
            }
            LazyInterned::CapacityFull => {
                validate_lazy_capacity_full(
                    automaton.stats().consuming_states(),
                    "exact small resume frontier exhausted its proven cache capacity",
                )?;
                workspace.lazy.saturated = true;
                workspace.lazy.retain_scratch_as_frontier()?;
                return Ok(LazyState::Inline { pending });
            }
        }
    }

    workspace.lazy.frontier[..length].copy_from_slice(seed);
    workspace.lazy.frontier_len = length;
    Ok(LazyState::Inline { pending })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the exact resume loop keeps its committed endpoint and frontier together"
)]
#[inline(never)]
fn execute_lazy_resume_loop(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    contract: OutputContract,
    core_reserve: u64,
    mut state: LazyState,
    mut position: usize,
    mut pending_end: Option<usize>,
) -> Result<(Option<MatchSpan>, usize), SearchError> {
    let earliest = matches!(
        contract,
        OutputContract::Exists | OutputContract::EarliestEnd
    );
    if earliest && pending_end.is_some() {
        return Ok((
            pending_end.map(|end| MatchSpan::new(window.start(), end)),
            1,
        ));
    }
    let mut boundaries = 1usize;
    loop {
        if position == window.end() {
            return Ok((
                pending_end.map(|end| MatchSpan::new(window.start(), end)),
                boundaries,
            ));
        }
        meter.charge(1, position)?;
        let byte = *haystack
            .get(position)
            .ok_or(SearchError::InternalInvariant {
                detail: "resume source position exceeded the validated window",
            })?;
        let transition = match state {
            LazyState::Cached(cached) => {
                let cell = workspace.lazy.direct_cell(cached, byte)?;
                if cell == LAZY_CELL_UNFILLED {
                    build_resume_lazy_cached_transition(
                        automaton,
                        direct_row_state(cached),
                        byte,
                        workspace,
                        meter,
                        core_reserve,
                        position,
                    )?
                } else {
                    LazyTransition::Ready(cell)
                }
            }
            LazyState::Inline { pending } => {
                build_resume_lazy_inline_transition(
                    automaton, byte, pending, workspace, meter, position,
                )?
            }
        };
        position = position
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "resume input position",
            })?;
        boundaries = boundaries
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "resume examined boundary count",
            })?;

        let (accepted, next) = match transition {
            LazyTransition::Ready(cell) => {
                let encoded = cell & LAZY_CELL_STATE_MASK;
                (
                    cell & LAZY_CELL_ACCEPT != 0,
                    if encoded == 0 {
                        None
                    } else {
                        Some(LazyState::Cached(encoded.checked_sub(1).ok_or(
                            SearchError::InternalInvariant {
                                detail: "resume encoded state underflowed",
                            },
                        )?))
                    },
                )
            }
            LazyTransition::Inline { accepted, pending } => {
                (accepted, Some(LazyState::Inline { pending }))
            }
        };
        if accepted {
            pending_end = Some(position);
            if earliest {
                return Ok((
                    Some(MatchSpan::new(window.start(), position)),
                    boundaries,
                ));
            }
        }
        let Some(next) = next else {
            return Ok((
                pending_end.map(|end| MatchSpan::new(window.start(), end)),
                boundaries,
            ));
        };
        state = next;
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the forward loop keeps endpoint commitment and cache handoff together"
)]
fn execute_lazy_span_loop<const TRACK_START: bool>(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    contract: OutputContract,
    core_reserve: u64,
    scanner: Option<&StartPositionScanner>,
    guard: Option<&StartPositionClass>,
    probe: Option<&StartPositionClass>,
    adaptive_probe: &mut AdaptiveStartProbe,
    _ready: DirectLazyReady,
) -> Result<Option<(Option<MatchSpan>, usize, bool)>, SearchError> {
    debug_assert!(matches!(
        contract,
        OutputContract::Exists
            | OutputContract::EarliestEnd
            | OutputContract::SelectedEnd
            | OutputContract::Span
    ));
    debug_assert!(workspace.lazy.is_allocated());
    debug_assert!(workspace.lazy.is_bound_to(automaton));
    debug_assert!(workspace.lazy.initialized);
    debug_assert!(!workspace.lazy.declined);

    // Bind the direct executor to the already-validated window ceiling once.
    // Subsequent source positions are monotone and tested against that same
    // ceiling before indexing, so release code can share the loop-end and
    // slice-bounds proof instead of retaining the full-haystack bound as a
    // second per-byte comparison.
    let haystack = haystack
        .get(..window.end())
        .ok_or(SearchError::InternalInvariant {
            detail: "lazy DFA window exceeds the validated haystack",
        })?;

    let (initial_pending, initial_terminal) = match workspace.lazy.initial_kind {
        LazyInitialKind::Positive | LazyInitialKind::PositiveSingle => (false, false),
        LazyInitialKind::NullablePrefix => (true, false),
        LazyInitialKind::NullableTerminal => (true, true),
        LazyInitialKind::Uninitialized => {
            return Err(SearchError::InternalInvariant {
                detail: "initialized lazy DFA has no cached initial kind",
            });
        }
    };
    let earliest = matches!(
        contract,
        OutputContract::Exists | OutputContract::EarliestEnd
    );
    let initial = workspace.lazy.initial;
    if initial == LAZY_NO_STATE {
        return Err(SearchError::InternalInvariant {
            detail: "initialized lazy DFA has no initial state",
        });
    }
    if initial_pending && (earliest || initial_terminal) {
        return Ok(Some((
            Some(MatchSpan::new(window.start(), window.start())),
            1,
            TRACK_START,
        )));
    }
    // Even a physically full cache retains useful prefix rows. Start from the
    // cached initial state and hand off only when an unfilled edge is reached.
    let initial_row = direct_row_offset(initial)?;
    let mut state = LazyState::Cached(initial_row);
    let mut position = window.start();
    let mut boundaries = 0usize;
    let mut pending_end = initial_pending.then_some(window.start());
    // One root expansion creates every positive initial-frontier item at the
    // same source boundary. Cardinality does not affect that provenance.
    let mut active_start = (TRACK_START
        && (initial_pending
            || matches!(
                workspace.lazy.initial_kind,
                LazyInitialKind::Positive | LazyInitialKind::PositiveSingle
            )))
    .then_some(window.start());
    let mut pending_start = (TRACK_START && initial_pending).then_some(window.start());
    let mut entered = false;
    let mut retained_start_mask = RetainedStartMaskCursor::default();
    let mut engine_candidate = None;

    loop {
        if pending_end.is_none() && state == LazyState::Cached(initial_row) {
            if let Some(scanner) = scanner {
                if position < window.end() {
                    if let (Some(probe), Some(candidate)) = (probe, engine_candidate.take()) {
                        adaptive_probe.observe_restartable_rejection(
                            probe,
                            haystack,
                            candidate,
                            window.end(),
                            meter,
                        )?;
                    }
                } else {
                    // Reaching the terminal boundary is not a restartable
                    // rejection and therefore has no postmortem sample.
                    engine_candidate = None;
                }
                position = next_start_candidate_adaptive(
                    scanner,
                    haystack,
                    position,
                    window.end(),
                    guard,
                    probe,
                    meter,
                    &mut retained_start_mask,
                    adaptive_probe,
                )?;
                if position == window.end() {
                    return Ok(Some((None, boundaries, false)));
                }
                if TRACK_START {
                    // One root expansion creates every positive initial
                    // frontier item at this exact candidate boundary.
                    active_start = matches!(
                        workspace.lazy.initial_kind,
                        LazyInitialKind::Positive | LazyInitialKind::PositiveSingle
                    )
                    .then_some(position);
                }
                if probe.is_some() && adaptive_probe.samples_rejections() {
                    engine_candidate = Some(position);
                }
            }
        }
        if !entered {
            // A Rust slice is no longer than `isize::MAX`, and this counter is
            // at most the validated window length plus its initial boundary.
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "the validated window proves the initial boundary increment fits"
            )]
            {
                boundaries += 1;
            }
            entered = true;
        }
        if position >= haystack.len() {
            if position == haystack.len() {
                let start_known = TRACK_START && pending_end.is_some() && pending_start.is_some();
                return Ok(Some((
                    pending_end
                        .map(|end| MatchSpan::new(pending_start.unwrap_or(window.start()), end)),
                    boundaries,
                    start_known,
                )));
            }
            return Err(SearchError::InternalInvariant {
                detail: "lazy DFA source position exceeded the validated window",
            });
        }

        // Charge the source step before indexing the validated window. A
        // warmed transition therefore costs one unit and performs one direct
        // row lookup; a cold transition additionally charges its closure and
        // optional learning work.
        meter.charge(1, position)?;
        #[allow(
            clippy::indexing_slicing,
            reason = "the immediately dominating window-ceiling check proves this source index"
        )]
        let byte = haystack[position];
        let transition = match state {
            LazyState::Cached(cached) => {
                let cell = workspace.lazy.direct_cell(cached, byte)?;
                if cell == LAZY_CELL_UNFILLED {
                    build_lazy_cached_transition(
                        automaton,
                        direct_row_state(cached),
                        byte,
                        workspace,
                        meter,
                        core_reserve,
                        position,
                    )?
                } else {
                    LazyTransition::Ready(cell)
                }
            }
            LazyState::Inline { pending } => {
                build_lazy_inline_transition(automaton, byte, pending, workspace, meter, position)?
            }
        };
        // `position < window.end() <= haystack.len() <= isize::MAX` at this
        // point. Carry that already-authenticated range proof directly rather
        // than repeating fallible arithmetic on every warmed transition.
        debug_assert!(position < window.end());
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "the validated window proves hot-loop position and boundary increments fit"
        )]
        {
            position += 1;
            boundaries += 1;
        }

        let (accepted, next, start_action) = match transition {
            LazyTransition::Ready(cell) => {
                let encoded = cell & LAZY_CELL_STATE_MASK;
                (
                    cell & LAZY_CELL_ACCEPT != 0,
                    if encoded == 0 {
                        None
                    } else {
                        Some(LazyState::Cached(encoded.checked_sub(1).ok_or(
                            SearchError::InternalInvariant {
                                detail: "lazy DFA encoded state underflowed",
                            },
                        )?))
                    },
                    if TRACK_START {
                        LazyStartAction::from_direct_cell(cell)
                    } else {
                        LazyStartAction::Drop
                    },
                )
            }
            LazyTransition::Inline { accepted, pending } => (
                accepted,
                Some(LazyState::Inline { pending }),
                if TRACK_START {
                    workspace.lazy.inline_start_action
                } else {
                    LazyStartAction::Drop
                },
            ),
        };
        let next_start = if TRACK_START {
            match start_action {
                LazyStartAction::Drop => None,
                LazyStartAction::Propagate => active_start,
                LazyStartAction::Reset => Some(position),
            }
        } else {
            None
        };
        if accepted {
            pending_end = Some(position);
            pending_start = next_start;
            if earliest {
                return Ok(Some((
                    Some(MatchSpan::new(
                        pending_start.unwrap_or(window.start()),
                        position,
                    )),
                    boundaries,
                    TRACK_START && pending_start.is_some(),
                )));
            }
        }
        let Some(next) = next else {
            let start_known = TRACK_START && pending_end.is_some() && pending_start.is_some();
            return Ok(Some((
                pending_end.map(|end| MatchSpan::new(pending_start.unwrap_or(window.start()), end)),
                boundaries,
                start_known,
            )));
        };
        state = next;
        active_start = next_start;
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "contextual endpoint execution keeps scanner restart and semantic cache keys together"
)]
fn execute_context_lazy_loop(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    contract: OutputContract,
    core_reserve: u64,
    scanner: Option<&StartPositionScanner>,
    guard: Option<&StartPositionClass>,
    probe: Option<&StartPositionClass>,
    force_haystack_start: bool,
    relaxed_nullable: bool,
    adaptive_probe: &mut AdaptiveStartProbe,
) -> Result<Option<(Option<MatchSpan>, usize)>, SearchError> {
    if !matches!(
        contract,
        OutputContract::Exists
            | OutputContract::EarliestEnd
            | OutputContract::SelectedEnd
            | OutputContract::Span
    ) || !workspace.lazy.context.is_allocated()
        || !workspace.lazy.is_bound_to(automaton)
        || workspace.lazy.declined
    {
        return Ok(None);
    }
    if relaxed_nullable {
        workspace.lazy.declined = true;
        return Ok(None);
    }

    let earliest = matches!(
        contract,
        OutputContract::Exists | OutputContract::EarliestEnd
    );
    let mut position = window.start();
    let mut boundaries = 0usize;
    let mut initial_candidate_scanned = false;
    let mut retained_start_mask = RetainedStartMaskCursor::default();
    let mut engine_candidate = None;
    if let Some(scanner) = scanner {
        // An absolute-start branch may contribute only at original haystack
        // boundary zero. Otherwise the proven scanner can establish the first
        // viable root before contextual initialization, avoiding construction
        // of an initial state that would be discarded immediately.
        if !(force_haystack_start && position == 0) {
            position = next_start_candidate_adaptive(
                scanner,
                haystack,
                position,
                window.end(),
                guard,
                probe,
                meter,
                &mut retained_start_mask,
                adaptive_probe,
            )?;
            if position == window.end() {
                return Ok(Some((None, boundaries)));
            }
            if probe.is_some() && adaptive_probe.samples_rejections() {
                engine_candidate = Some(position);
            }
            initial_candidate_scanned = true;
        }
    }
    let initial_mask = enabled_assertion_mask(automaton, haystack, position, meter)?;
    let Some((mut state, mut restartable)) = context_lazy_initial(
        automaton,
        initial_mask,
        workspace,
        meter,
        core_reserve,
        position,
    )?
    else {
        return Ok(None);
    };
    workspace.lazy.initialized = true;

    let mut pending_end = None;
    let mut entered = false;

    loop {
        if (!initial_candidate_scanned || entered)
            && pending_end.is_none()
            && restartable
            && !(force_haystack_start && position == 0)
        {
            let candidate = if let Some(scanner) = scanner {
                if position < window.end() {
                    if let (Some(probe), Some(candidate)) = (probe, engine_candidate.take()) {
                        adaptive_probe.observe_restartable_rejection(
                            probe,
                            haystack,
                            candidate,
                            window.end(),
                            meter,
                        )?;
                    }
                } else {
                    engine_candidate = None;
                }
                next_start_candidate_adaptive(
                    scanner,
                    haystack,
                    position,
                    window.end(),
                    guard,
                    probe,
                    meter,
                    &mut retained_start_mask,
                    adaptive_probe,
                )?
            } else {
                position
            };
            if candidate == window.end() {
                return Ok(Some((None, boundaries)));
            }
            if probe.is_some() && adaptive_probe.samples_rejections() {
                engine_candidate = Some(candidate);
            }
            if candidate != position {
                position = candidate;
                let mask = enabled_assertion_mask(automaton, haystack, position, meter)?;
                let Some(initial) = context_lazy_initial(
                    automaton,
                    mask,
                    workspace,
                    meter,
                    core_reserve,
                    position,
                )?
                else {
                    return Ok(None);
                };
                state = initial.0;
            }
        }
        if !entered {
            boundaries = boundaries
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "contextual lazy DFA examined boundary count",
                })?;
            entered = true;
        }
        if position == window.end() {
            return Ok(Some((
                pending_end.map(|end| MatchSpan::new(window.start(), end)),
                boundaries,
            )));
        }

        meter.charge(1, position)?;
        let byte = *haystack
            .get(position)
            .ok_or(SearchError::InternalInvariant {
                detail: "contextual lazy DFA source exceeded the validated window",
            })?;
        let destination = position
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "contextual lazy DFA destination",
            })?;
        let assertions = enabled_assertion_mask(automaton, haystack, destination, meter)?;
        let symbol = contextual_symbol(u32::from(byte), assertions);
        let transition = match state {
            LazyState::Cached(cached) => build_context_lazy_cached_transition(
                automaton,
                cached,
                byte,
                symbol,
                assertions,
                workspace,
                meter,
                core_reserve,
                destination,
            )?,
            LazyState::Inline { pending } => build_context_lazy_inline_transition(
                automaton,
                byte,
                assertions,
                pending,
                workspace,
                meter,
                destination,
            )?,
        };
        position = destination;
        boundaries = boundaries
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "contextual lazy DFA examined boundary count",
            })?;

        let (accepted, next_pending, next_restartable, next) = match transition {
            ContextLazyTransition::Ready(cell) => {
                let encoded = cell & LAZY_CELL_STATE_MASK;
                (
                    cell & LAZY_CELL_ACCEPT != 0,
                    false,
                    cell & LAZY_CELL_RESTART != 0,
                    if encoded == 0 {
                        None
                    } else {
                        Some(LazyState::Cached(encoded.checked_sub(1).ok_or(
                            SearchError::InternalInvariant {
                                detail: "contextual lazy DFA encoded state underflowed",
                            },
                        )?))
                    },
                )
            }
            ContextLazyTransition::Inline {
                accepted,
                pending,
                restartable,
            } => (
                accepted,
                pending,
                restartable,
                Some(LazyState::Inline { pending }),
            ),
        };
        if accepted {
            pending_end = Some(position);
            if earliest {
                return Ok(Some((
                    Some(MatchSpan::new(window.start(), position)),
                    boundaries,
                )));
            }
        }
        let Some(next) = next else {
            return Ok(Some((
                pending_end.map(|end| MatchSpan::new(window.start(), end)),
                boundaries,
            )));
        };
        state = match next {
            LazyState::Cached(state) => LazyState::Cached(state),
            LazyState::Inline { .. } => LazyState::Inline {
                pending: next_pending,
            },
        };
        restartable = next_restartable;
    }
}

fn context_lazy_initial(
    automaton: &Automaton,
    assertions: u32,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<Option<(LazyState, bool)>, SearchError> {
    let symbol = contextual_symbol(CONTEXT_INITIAL_BYTE, assertions);
    let (cached, slot) =
        workspace
            .lazy
            .context
            .lookup(CONTEXT_INITIAL_SOURCE, symbol, meter, position)?;
    if let Some(cell) = cached {
        let encoded = cell & LAZY_CELL_STATE_MASK;
        if encoded == 0 || cell & (LAZY_CELL_ACCEPT | LAZY_CELL_RESTART) != LAZY_CELL_RESTART {
            return Err(SearchError::InternalInvariant {
                detail: "contextual lazy DFA initial cache cell is invalid",
            });
        }
        return Ok(Some((
            LazyState::Cached(
                encoded
                    .checked_sub(1)
                    .ok_or(SearchError::InternalInvariant {
                        detail: "contextual lazy DFA initial state underflowed",
                    })?,
            ),
            true,
        )));
    }

    begin_lazy_closure(workspace, meter, position)?;
    if expand_context_lazy_root(
        automaton,
        automaton.start,
        assertions,
        workspace,
        meter,
        position,
    )? {
        workspace.lazy.scratch_len = 0;
        workspace.lazy.declined = true;
        return Ok(None);
    }
    let (state, encoded) =
        retain_context_lazy_scratch(automaton, false, workspace, meter, core_reserve, position)?;
    if let Some(encoded) = encoded {
        let cell = encoded | LAZY_CELL_RESTART;
        workspace.lazy.context.publish(
            slot,
            ContextTransitionSlot::populated(CONTEXT_INITIAL_SOURCE, symbol, cell),
            meter,
            core_reserve,
            position,
        )?;
    }
    Ok(Some((state, true)))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the contextual transition key and closure context must remain adjacent"
)]
fn build_context_lazy_cached_transition(
    automaton: &Automaton,
    state: u32,
    byte: u8,
    symbol: u32,
    assertions: u32,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<ContextLazyTransition, SearchError> {
    let (cached, slot) = workspace
        .lazy
        .context
        .lookup(state, symbol, meter, position)?;
    if let Some(cell) = cached {
        return Ok(ContextLazyTransition::Ready(cell));
    }

    let (_, length, pending) = workspace.lazy.state_bounds(state)?;
    begin_lazy_closure(workspace, meter, position)?;
    let mut accepted = false;
    'frontier: for ordinal in 0..length {
        let consuming = workspace.lazy.item(state, ordinal)?;
        for edge in automaton.state_edges(consuming) {
            meter.charge(1, position)?;
            if automaton.byte_starts[edge] <= byte
                && byte <= automaton.byte_ends[edge]
                && expand_context_lazy_root(
                    automaton,
                    automaton.edge_targets[edge],
                    assertions,
                    workspace,
                    meter,
                    position,
                )?
            {
                accepted = true;
                break 'frontier;
            }
        }
    }
    let mut restartable = false;
    if !accepted && !pending {
        restartable = workspace.lazy.scratch_len == 0;
        if expand_context_lazy_root(
            automaton,
            automaton.start,
            assertions,
            workspace,
            meter,
            position,
        )? {
            return Err(SearchError::InternalInvariant {
                detail: "relaxed-nonnullable contextual DFA accepted an injected empty match",
            });
        }
    }
    let next_pending = pending || accepted;
    if workspace.lazy.scratch_len == 0 && next_pending {
        let cell = if accepted { LAZY_CELL_ACCEPT } else { 0 };
        workspace.lazy.context.publish(
            slot,
            ContextTransitionSlot::populated(state, symbol, cell),
            meter,
            core_reserve,
            position,
        )?;
        return Ok(ContextLazyTransition::Ready(cell));
    }

    let (next, encoded) = retain_context_lazy_scratch(
        automaton,
        next_pending,
        workspace,
        meter,
        core_reserve,
        position,
    )?;
    let accepted_bit = if accepted { LAZY_CELL_ACCEPT } else { 0 };
    let restart_bit = if restartable { LAZY_CELL_RESTART } else { 0 };
    if let Some(encoded) = encoded {
        let cell = encoded | accepted_bit | restart_bit;
        workspace.lazy.context.publish(
            slot,
            ContextTransitionSlot::populated(state, symbol, cell),
            meter,
            core_reserve,
            position,
        )?;
        Ok(ContextLazyTransition::Ready(cell))
    } else {
        let LazyState::Inline { pending } = next else {
            return Err(SearchError::InternalInvariant {
                detail: "uncached contextual transition retained a cached state",
            });
        };
        Ok(ContextLazyTransition::Inline {
            accepted,
            pending,
            restartable,
        })
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "inline contextual execution mirrors one complete cached transition"
)]
fn build_context_lazy_inline_transition(
    automaton: &Automaton,
    byte: u8,
    assertions: u32,
    pending: bool,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<ContextLazyTransition, SearchError> {
    let length = workspace.lazy.frontier_len;
    begin_lazy_closure(workspace, meter, position)?;
    let mut accepted = false;
    'frontier: for ordinal in 0..length {
        let consuming =
            *workspace
                .lazy
                .frontier
                .get(ordinal)
                .ok_or(SearchError::InternalInvariant {
                    detail: "contextual inline frontier item is outside its arena",
                })?;
        for edge in automaton.state_edges(consuming) {
            meter.charge(1, position)?;
            if automaton.byte_starts[edge] <= byte
                && byte <= automaton.byte_ends[edge]
                && expand_context_lazy_root(
                    automaton,
                    automaton.edge_targets[edge],
                    assertions,
                    workspace,
                    meter,
                    position,
                )?
            {
                accepted = true;
                break 'frontier;
            }
        }
    }
    let mut restartable = false;
    if !accepted && !pending {
        restartable = workspace.lazy.scratch_len == 0;
        if expand_context_lazy_root(
            automaton,
            automaton.start,
            assertions,
            workspace,
            meter,
            position,
        )? {
            return Err(SearchError::InternalInvariant {
                detail: "relaxed-nonnullable contextual inline DFA accepted an empty match",
            });
        }
    }
    let next_pending = pending || accepted;
    if workspace.lazy.scratch_len == 0 {
        workspace.lazy.frontier_len = 0;
        if next_pending {
            return Ok(ContextLazyTransition::Ready(if accepted {
                LAZY_CELL_ACCEPT
            } else {
                0
            }));
        }
        return Ok(ContextLazyTransition::Inline {
            accepted,
            pending: false,
            restartable,
        });
    }
    workspace.lazy.retain_scratch_as_frontier()?;
    Ok(ContextLazyTransition::Inline {
        accepted,
        pending: next_pending,
        restartable,
    })
}

fn retain_context_lazy_scratch(
    automaton: &Automaton,
    pending: bool,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<(LazyState, Option<u32>), SearchError> {
    match workspace
        .lazy
        .intern_speculative(pending, meter, core_reserve, position)?
    {
        LazyInterned::State(state) => {
            let encoded = state.checked_add(1).ok_or(SearchError::InternalInvariant {
                detail: "contextual lazy DFA encoded state overflowed",
            })?;
            if encoded > LAZY_CELL_STATE_MASK {
                return Err(SearchError::InternalInvariant {
                    detail: "contextual lazy DFA state exceeds its cell field",
                });
            }
            Ok((LazyState::Cached(state), Some(encoded)))
        }
        LazyInterned::BudgetDeclined => {
            workspace.lazy.retain_scratch_as_frontier()?;
            Ok((LazyState::Inline { pending }, None))
        }
        LazyInterned::CapacityFull => {
            validate_lazy_capacity_full(
                automaton.stats().consuming_states(),
                "exact small contextual lazy DFA exhausted its proven capacity",
            )?;
            workspace.lazy.saturated = true;
            workspace.lazy.retain_scratch_as_frontier()?;
            Ok((LazyState::Inline { pending }, None))
        }
    }
}

fn expand_context_lazy_root(
    automaton: &Automaton,
    root: u32,
    assertions: u32,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<bool, SearchError> {
    workspace.stack_len = 0;
    workspace.push_stack(Thread {
        state: root,
        start: 0,
    })?;
    while let Some(thread) = workspace.pop_stack() {
        meter.charge(1, position)?;
        let state = crate::plan::plan_index(thread.state);
        if workspace.seen_at[state] == workspace.generation {
            continue;
        }
        workspace.seen_at[state] = workspace.generation;
        match automaton.roles[state] {
            StateRole::Accept => return Ok(true),
            StateRole::Consume => push_lazy_scratch(workspace, thread.state)?,
            StateRole::Split => {
                for edge in automaton.state_edges(thread.state).rev() {
                    meter.charge(1, position)?;
                    if assertion_enabled(automaton.edge_kinds[edge], assertions)? {
                        workspace.push_stack(Thread {
                            state: automaton.edge_targets[edge],
                            start: 0,
                        })?;
                    }
                }
            }
        }
    }
    Ok(false)
}

fn lazy_initial_work_upper(automaton: &Automaton) -> Result<u64, SearchError> {
    let states =
        u64::try_from(automaton.stats().states()).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "lazy DFA initial state count",
        })?;
    let epsilon_edges = u64::try_from(automaton.stats().zero_width_edges()).map_err(|_| {
        SearchError::ArithmeticOverflow {
            computation: "lazy DFA initial epsilon-edge count",
        }
    })?;
    states
        .checked_mul(2)
        .and_then(|work| {
            epsilon_edges
                .checked_mul(2)
                .and_then(|edges| work.checked_add(edges))
        })
        .and_then(|work| work.checked_add(2))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "lazy DFA initial preparation work",
        })
}

fn prepare_lazy(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<bool, SearchError> {
    if !workspace.lazy.is_allocated()
        || !workspace.lazy.is_bound_to(automaton)
        || workspace.lazy.declined
    {
        return Ok(false);
    }
    if workspace.lazy.initialized {
        return Ok(true);
    }

    let initial_upper = lazy_initial_work_upper(automaton)?;
    let remaining = meter.remaining();
    let Some(optional) = remaining.checked_sub(core_reserve) else {
        return Ok(false);
    };
    if initial_upper > optional {
        return Ok(false);
    }

    begin_lazy_closure(workspace, meter, position)?;
    let accepted = expand_lazy_root(automaton, automaton.start, workspace, meter, position)?;
    if !accepted && workspace.lazy.scratch_len == 0 {
        // Empty-language graphs remain on Pike. This decision is immutable
        // for the exact bound automaton and is therefore sticky.
        workspace.lazy.scratch_len = 0;
        workspace.lazy.declined = true;
        return Ok(false);
    }
    // Ordered closure stops at the first Accept. Any consuming states already
    // retained are precisely the higher-priority alternatives that may still
    // replace this initial empty match. The existing pending mode therefore
    // represents nullable execution without pattern-specific cases.
    let initial_kind = match (accepted, workspace.lazy.scratch_len == 0) {
        (false, false) if workspace.lazy.scratch_len == 1 => LazyInitialKind::PositiveSingle,
        (false, false) => LazyInitialKind::Positive,
        (true, false) => LazyInitialKind::NullablePrefix,
        (true, true) => LazyInitialKind::NullableTerminal,
        (false, true) => {
            return Err(SearchError::InternalInvariant {
                detail: "nonnullable lazy DFA initial state has no consuming items",
            });
        }
    };
    let initial = workspace.lazy.intern_initial(accepted, meter, position)?;
    workspace.lazy.initial = initial;
    workspace.lazy.initial_kind = initial_kind;
    workspace.lazy.initialized = true;
    Ok(true)
}

#[cfg(test)]
fn lazy_initial_is_terminal(workspace: &K0Workspace) -> Result<bool, SearchError> {
    let initial = workspace.lazy.initial;
    if initial == LAZY_NO_STATE {
        return Err(SearchError::InternalInvariant {
            detail: "initialized lazy DFA has no initial state",
        });
    }
    Ok(workspace.lazy.initial_kind == LazyInitialKind::NullableTerminal)
}

fn lazy_initial_has_pending(workspace: &K0Workspace) -> Result<bool, SearchError> {
    let initial = workspace.lazy.initial;
    if initial == LAZY_NO_STATE {
        return Err(SearchError::InternalInvariant {
            detail: "initialized lazy DFA has no initial state",
        });
    }
    Ok(matches!(
        workspace.lazy.initial_kind,
        LazyInitialKind::NullablePrefix | LazyInitialKind::NullableTerminal
    ))
}

fn begin_lazy_closure(
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<(), SearchError> {
    meter.charge(1, position)?;
    workspace.lazy.scratch_len = 0;
    workspace.stack_len = 0;
    workspace.generation =
        workspace
            .generation
            .checked_add(1)
            .ok_or(SearchError::InternalInvariant {
                detail: "preflighted lazy DFA generation overflowed",
            })?;
    Ok(())
}

fn push_lazy_scratch(workspace: &mut K0Workspace, state: u32) -> Result<(), SearchError> {
    *workspace
        .lazy
        .scratch
        .get_mut(workspace.lazy.scratch_len)
        .ok_or(SearchError::InternalInvariant {
            detail: "lazy DFA closure output exceeded automaton states",
        })? = state;
    workspace.lazy.scratch_len =
        workspace
            .lazy
            .scratch_len
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA closure output length",
            })?;
    Ok(())
}

fn expand_lazy_root(
    automaton: &Automaton,
    root: u32,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<bool, SearchError> {
    workspace.stack_len = 0;
    workspace.push_stack(Thread {
        state: root,
        start: 0,
    })?;
    while let Some(thread) = workspace.pop_stack() {
        meter.charge(1, position)?;
        let state = crate::plan::plan_index(thread.state);
        if workspace.seen_at[state] == workspace.generation {
            continue;
        }
        workspace.seen_at[state] = workspace.generation;
        match automaton.roles[state] {
            StateRole::Accept => return Ok(true),
            StateRole::Consume => push_lazy_scratch(workspace, thread.state)?,
            StateRole::Split => {
                for edge in automaton.state_edges(thread.state).rev() {
                    meter.charge(1, position)?;
                    if automaton.edge_kinds[edge] != EdgeKind::Epsilon {
                        return Err(SearchError::InternalInvariant {
                            detail: "lazy DFA reached a non-epsilon split edge",
                        });
                    }
                    workspace.push_stack(Thread {
                        state: automaton.edge_targets[edge],
                        start: 0,
                    })?;
                }
            }
        }
    }
    Ok(false)
}

const fn lazy_start_action(
    source_len: usize,
    final_len: usize,
    injected_root: bool,
) -> LazyStartAction {
    if !injected_root {
        return LazyStartAction::Propagate;
    }
    if source_len == 0 {
        return if final_len == 0 {
            LazyStartAction::Drop
        } else {
            LazyStartAction::Reset
        };
    }
    if final_len == source_len {
        // The root closure added no thread. Any graph states it revisited were
        // already owned by the earlier, higher-priority source frontier.
        LazyStartAction::Propagate
    } else {
        LazyStartAction::Drop
    }
}

fn build_lazy_cached_transition(
    automaton: &Automaton,
    state: u32,
    byte: u8,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<LazyTransition, SearchError> {
    let cached = workspace.lazy.cell(state, byte)?;
    if cached != LAZY_CELL_UNFILLED {
        return Ok(LazyTransition::Ready(cached));
    }

    let (_, length, pending) = workspace.lazy.state_bounds(state)?;
    begin_lazy_closure(workspace, meter, position)?;
    let mut accepted = false;
    'frontier: for ordinal in 0..length {
        let consuming = workspace.lazy.item(state, ordinal)?;
        for edge in automaton.state_edges(consuming) {
            meter.charge(1, position)?;
            if automaton.byte_starts[edge] <= byte
                && byte <= automaton.byte_ends[edge]
                && expand_lazy_root(
                    automaton,
                    automaton.edge_targets[edge],
                    workspace,
                    meter,
                    position,
                )?
            {
                accepted = true;
                break 'frontier;
            }
        }
    }
    let source_len = workspace.lazy.scratch_len;
    let mut injected_root = false;
    if !accepted && !pending {
        injected_root = true;
        if expand_lazy_root(automaton, automaton.start, workspace, meter, position)? {
            return Err(SearchError::InternalInvariant {
                detail: "nonnullable lazy DFA accepted an injected empty match",
            });
        }
    }
    let start_action = lazy_start_action(source_len, workspace.lazy.scratch_len, injected_root);
    finish_lazy_cached_transition(
        automaton,
        state,
        byte,
        accepted,
        pending,
        start_action,
        workspace,
        meter,
        core_reserve,
        position,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "cache publication authenticates one complete transition and its work reserve"
)]
fn finish_lazy_cached_transition(
    automaton: &Automaton,
    state: u32,
    byte: u8,
    accepted: bool,
    pending: bool,
    start_action: LazyStartAction,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<LazyTransition, SearchError> {
    let next_pending = pending || accepted;
    let encoded = if workspace.lazy.scratch_len == 0 {
        0
    } else {
        match workspace
            .lazy
            .intern_speculative(next_pending, meter, core_reserve, position)?
        {
            LazyInterned::State(next) => direct_row_encoded_state(next)?,
            LazyInterned::BudgetDeclined => {
                workspace.lazy.retain_scratch_as_frontier()?;
                workspace.lazy.inline_start_action = start_action;
                return Ok(LazyTransition::Inline {
                    accepted,
                    pending: next_pending,
                });
            }
            LazyInterned::CapacityFull => {
                validate_lazy_capacity_full(
                    automaton.stats().consuming_states(),
                    "exact small lazy DFA exhausted its proven capacity",
                )?;
                workspace.lazy.saturated = true;
                workspace.lazy.retain_scratch_as_frontier()?;
                workspace.lazy.inline_start_action = start_action;
                return Ok(LazyTransition::Inline {
                    accepted,
                    pending: next_pending,
                });
            }
        }
    };
    let cell = encoded | if accepted { LAZY_CELL_ACCEPT } else { 0 } | start_action.cell_bits();
    workspace.lazy.set_cell(state, byte, cell)?;
    Ok(LazyTransition::Ready(cell))
}

fn build_lazy_inline_transition(
    automaton: &Automaton,
    byte: u8,
    pending: bool,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<LazyTransition, SearchError> {
    let length = workspace.lazy.frontier_len;
    begin_lazy_closure(workspace, meter, position)?;
    let mut accepted = false;
    'frontier: for ordinal in 0..length {
        let consuming =
            *workspace
                .lazy
                .frontier
                .get(ordinal)
                .ok_or(SearchError::InternalInvariant {
                    detail: "lazy DFA inline frontier item is outside its arena",
                })?;
        for edge in automaton.state_edges(consuming) {
            meter.charge(1, position)?;
            if automaton.byte_starts[edge] <= byte
                && byte <= automaton.byte_ends[edge]
                && expand_lazy_root(
                    automaton,
                    automaton.edge_targets[edge],
                    workspace,
                    meter,
                    position,
                )?
            {
                accepted = true;
                break 'frontier;
            }
        }
    }
    let source_len = workspace.lazy.scratch_len;
    let mut injected_root = false;
    if !accepted && !pending {
        injected_root = true;
        if expand_lazy_root(automaton, automaton.start, workspace, meter, position)? {
            return Err(SearchError::InternalInvariant {
                detail: "nonnullable inline lazy DFA accepted an injected empty match",
            });
        }
    }
    let start_action = lazy_start_action(source_len, workspace.lazy.scratch_len, injected_root);
    let next_pending = pending || accepted;
    if workspace.lazy.scratch_len == 0 {
        workspace.lazy.frontier_len = 0;
        let accepted_bit = if accepted { LAZY_CELL_ACCEPT } else { 0 };
        return Ok(LazyTransition::Ready(
            accepted_bit | start_action.cell_bits(),
        ));
    }
    workspace.lazy.retain_scratch_as_frontier()?;
    workspace.lazy.inline_start_action = start_action;
    Ok(LazyTransition::Inline {
        accepted,
        pending: next_pending,
    })
}

fn reverse_initial_work_upper(automaton: &Automaton) -> Result<u64, SearchError> {
    let states =
        u64::try_from(automaton.stats().states()).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "reverse DFA initial state count",
        })?;
    let edges =
        u64::try_from(automaton.stats().edges()).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "reverse DFA initial edge count",
        })?;
    let consuming = u64::try_from(automaton.stats().consuming_edges()).map_err(|_| {
        SearchError::ArithmeticOverflow {
            computation: "reverse DFA initial consuming-edge count",
        }
    })?;
    states
        .checked_mul(3)
        .and_then(|work| {
            edges
                .checked_mul(3)
                .and_then(|edges| work.checked_add(edges))
        })
        .and_then(|work| {
            consuming
                .checked_mul(2)
                .and_then(|items| work.checked_add(items))
        })
        .and_then(|work| work.checked_add(1))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "reverse DFA initial preparation work",
        })
}

fn conservative_reverse_work_bound(
    automaton: &Automaton,
    input_bytes: usize,
) -> Result<u64, SearchError> {
    let input = u64::try_from(input_bytes).map_err(|_| SearchError::ArithmeticOverflow {
        computation: "reverse DFA input length conversion",
    })?;
    let states =
        u64::try_from(automaton.stats().states()).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "reverse DFA state count conversion",
        })?;
    let edges =
        u64::try_from(automaton.stats().edges()).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "reverse DFA edge count conversion",
        })?;
    let consuming = u64::try_from(automaton.stats().consuming_edges()).map_err(|_| {
        SearchError::ArithmeticOverflow {
            computation: "reverse DFA consuming-edge count conversion",
        }
    })?;
    let per_byte = states
        .checked_add(
            edges
                .checked_mul(3)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "reverse DFA per-byte edge work bound",
                })?,
        )
        .and_then(|work| {
            consuming
                .checked_mul(2)
                .and_then(|items| work.checked_add(items))
        })
        .and_then(|work| work.checked_add(2))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "reverse DFA per-byte work bound",
        })?;
    input
        .checked_mul(per_byte)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "reverse DFA work bound",
        })
}

fn contextual_execution_work_upper(
    automaton: &Automaton,
    input_bytes: usize,
    wants_span: bool,
) -> Result<u64, SearchError> {
    let input = u64::try_from(input_bytes).map_err(|_| SearchError::ArithmeticOverflow {
        computation: "contextual DFA input length conversion",
    })?;
    let assertion_checks = u64::from(automaton.stats().assertion_kinds().count_ones());
    let lookup = u64::try_from(CONTEXT_TRANSITION_WAYS)
        .map_err(|_| SearchError::ArithmeticOverflow {
            computation: "contextual transition way conversion",
        })?
        .checked_add(1)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "contextual transition lookup work",
        })?;
    let symbol_work =
        assertion_checks
            .checked_add(lookup)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "contextual assertion-symbol work",
            })?;

    // Reserve one initial symbol for every candidate-bearing execution, even
    // though a scanner miss returns before evaluating one. Every later symbol
    // is either a consumed transition or an initial-state rebuild after a
    // scanner jump. A rebuild skips at least one byte, so those disjoint
    // progress counts sum to at most the input length.
    let forward_symbols = input
        .checked_add(1)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "contextual forward symbol count",
        })?;
    let forward_overhead =
        forward_symbols
            .checked_mul(symbol_work)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "contextual forward symbol work",
            })?;
    let forward = automaton.conservative_transition_work_bound(input_bytes)?;
    // Keep a separate initial allowance in case the source-specific closure
    // proves nullable and contextual execution declines to the ordinary loop.
    let forward_initial = lazy_initial_work_upper(automaton)?;
    let mut work = forward
        .checked_add(forward_initial)
        .and_then(|bound| bound.checked_add(forward_overhead))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "contextual forward work bound",
        })?;

    if wants_span {
        // Reverse execution evaluates one Accept-seeded initial symbol and at
        // most one source-boundary symbol per byte. Its initial closure is
        // source dependent, so retain the complete direct-initial upper bound
        // in addition to the per-byte reverse execution certificate.
        let reverse_symbols = input
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "contextual reverse symbol count",
            })?;
        let reverse_overhead =
            reverse_symbols
                .checked_mul(symbol_work)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "contextual reverse symbol work",
                })?;
        let reverse = conservative_reverse_work_bound(automaton, input_bytes)?;
        let reverse_initial = reverse_initial_work_upper(automaton)?;
        work = work
            .checked_add(reverse)
            .and_then(|bound| bound.checked_add(reverse_initial))
            .and_then(|bound| bound.checked_add(reverse_overhead))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "contextual bidirectional work bound",
            })?;
    }
    Ok(work)
}

fn prepare_reverse_lazy(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<bool, SearchError> {
    if !workspace.reverse.is_allocated()
        || !workspace.reverse.is_bound_to(automaton)
        || workspace.reverse.declined
    {
        return Ok(false);
    }
    if workspace.reverse.initialized {
        return Ok(true);
    }
    let initial_upper = reverse_initial_work_upper(automaton)?;
    let Some(optional) = meter.remaining().checked_sub(core_reserve) else {
        return Ok(false);
    };
    if initial_upper > optional {
        return Ok(false);
    }

    begin_reverse_closure(workspace, meter, position)?;
    for state in 0..automaton.stats().states() {
        meter.charge(1, position)?;
        if automaton.roles[state] == StateRole::Accept {
            let _ = expand_reverse_root(
                automaton,
                u32::try_from(state).map_err(|_| SearchError::InternalInvariant {
                    detail: "validated reverse Accept state does not fit u32",
                })?,
                workspace,
                meter,
                position,
            )?;
        }
    }
    collect_reverse_frontier(automaton, workspace, meter, position)?;
    if workspace.reverse.scratch_len == 0 {
        workspace.reverse.scratch_len = 0;
        workspace.reverse.declined = true;
        return Ok(false);
    }
    // A nullable graph reaches the forward start without consuming at the
    // selected-end boundary. Positive forward selections suppress that
    // later-start empty match, while terminal initial empties skip reverse
    // preparation entirely. Retain only the consuming reverse frontier here.
    let initial = workspace.reverse.intern_initial(meter, position)?;
    workspace.reverse.initial = initial;
    workspace.reverse.initialized = true;
    Ok(true)
}

fn begin_reverse_closure(
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<(), SearchError> {
    meter.charge(1, position)?;
    workspace.reverse.scratch_len = 0;
    workspace.stack_len = 0;
    workspace.generation =
        workspace
            .generation
            .checked_add(1)
            .ok_or(SearchError::InternalInvariant {
                detail: "preflighted reverse DFA generation overflowed",
            })?;
    Ok(())
}

fn expand_reverse_root(
    automaton: &Automaton,
    root: u32,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<bool, SearchError> {
    workspace.push_stack(Thread {
        state: root,
        start: 0,
    })?;
    let mut reaches_start = false;
    while let Some(thread) = workspace.pop_stack() {
        meter.charge(1, position)?;
        let state = crate::plan::plan_index(thread.state);
        if workspace.seen_at[state] == workspace.generation {
            continue;
        }
        workspace.seen_at[state] = workspace.generation;
        reaches_start |= thread.state == automaton.start;
        let incoming = workspace.reverse.incoming_range(thread.state)?;
        for edge in incoming {
            meter.charge(1, position)?;
            let source = workspace.reverse.incoming_sources[edge];
            match automaton.roles[crate::plan::plan_index(source)] {
                StateRole::Split => {
                    if workspace.reverse.incoming_starts[edge] != 0
                        || workspace.reverse.incoming_ends[edge] != 0
                    {
                        return Err(SearchError::InternalInvariant {
                            detail: "reverse epsilon edge has noncanonical byte bounds",
                        });
                    }
                    workspace.push_stack(Thread {
                        state: source,
                        start: 0,
                    })?;
                }
                StateRole::Consume => {}
                StateRole::Accept => {
                    return Err(SearchError::InternalInvariant {
                        detail: "reverse CSR contains an outgoing Accept edge",
                    });
                }
            }
        }
    }
    Ok(reaches_start)
}

fn collect_reverse_frontier(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<(), SearchError> {
    for target in 0..automaton.stats().states() {
        meter.charge(1, position)?;
        if workspace.seen_at[target] != workspace.generation {
            continue;
        }
        let target = u32::try_from(target).map_err(|_| SearchError::InternalInvariant {
            detail: "validated reverse target does not fit u32",
        })?;
        for incoming in workspace.reverse.incoming_range(target)? {
            meter.charge(1, position)?;
            let source = workspace.reverse.incoming_sources[incoming];
            if automaton.roles[crate::plan::plan_index(source)] != StateRole::Consume {
                continue;
            }
            *workspace
                .reverse
                .scratch
                .get_mut(workspace.reverse.scratch_len)
                .ok_or(SearchError::InternalInvariant {
                    detail: "reverse DFA closure output exceeded edge storage",
                })? = u32::try_from(incoming).map_err(|_| SearchError::InternalInvariant {
                detail: "validated reverse incoming edge does not fit u32",
            })?;
            workspace.reverse.scratch_len = workspace.reverse.scratch_len.checked_add(1).ok_or(
                SearchError::ArithmeticOverflow {
                    computation: "reverse DFA closure output length",
                },
            )?;
        }
    }
    Ok(())
}

fn build_reverse_cached_transition(
    automaton: &Automaton,
    state: u32,
    byte: u8,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<ReverseTransition, SearchError> {
    let cached = workspace.reverse.cell(state, byte)?;
    if cached != LAZY_CELL_UNFILLED {
        return Ok(ReverseTransition::Ready(cached));
    }
    let (_, length) = workspace.reverse.state_bounds(state)?;
    begin_reverse_closure(workspace, meter, position)?;
    let mut reaches_start = false;
    for ordinal in 0..length {
        let incoming = usize::try_from(workspace.reverse.item(state, ordinal)?).map_err(|_| {
            SearchError::InternalInvariant {
                detail: "reverse DFA incoming item does not fit usize",
            }
        })?;
        meter.charge(1, position)?;
        let start = workspace.reverse.incoming_starts[incoming];
        let end = workspace.reverse.incoming_ends[incoming];
        if start <= byte && byte <= end {
            reaches_start |= expand_reverse_root(
                automaton,
                workspace.reverse.incoming_sources[incoming],
                workspace,
                meter,
                position,
            )?;
        }
    }
    collect_reverse_frontier(automaton, workspace, meter, position)?;
    finish_reverse_cached_transition(
        automaton,
        state,
        byte,
        reaches_start,
        workspace,
        meter,
        core_reserve,
        position,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "reverse cache publication authenticates one complete transition"
)]
fn finish_reverse_cached_transition(
    automaton: &Automaton,
    state: u32,
    byte: u8,
    reaches_start: bool,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<ReverseTransition, SearchError> {
    let encoded = if workspace.reverse.scratch_len == 0 {
        0
    } else {
        match workspace
            .reverse
            .intern_speculative(meter, core_reserve, position)?
        {
            LazyInterned::State(next) => direct_row_encoded_state(next)?,
            LazyInterned::BudgetDeclined => {
                workspace.reverse.retain_scratch_as_frontier()?;
                return Ok(ReverseTransition::Inline { reaches_start });
            }
            LazyInterned::CapacityFull => {
                validate_lazy_capacity_full(
                    automaton.stats().consuming_edges(),
                    "exact small reverse DFA exhausted its proven capacity",
                )?;
                workspace.reverse.saturated = true;
                workspace.reverse.retain_scratch_as_frontier()?;
                return Ok(ReverseTransition::Inline { reaches_start });
            }
        }
    };
    let cell = encoded | if reaches_start { LAZY_CELL_ACCEPT } else { 0 };
    workspace.reverse.set_cell(state, byte, cell)?;
    Ok(ReverseTransition::Ready(cell))
}

fn build_reverse_inline_transition(
    automaton: &Automaton,
    byte: u8,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<ReverseTransition, SearchError> {
    let length = workspace.reverse.frontier_len;
    begin_reverse_closure(workspace, meter, position)?;
    let mut reaches_start = false;
    for ordinal in 0..length {
        let incoming = usize::try_from(workspace.reverse.frontier[ordinal]).map_err(|_| {
            SearchError::InternalInvariant {
                detail: "reverse DFA inline item does not fit usize",
            }
        })?;
        meter.charge(1, position)?;
        let start = workspace.reverse.incoming_starts[incoming];
        let end = workspace.reverse.incoming_ends[incoming];
        if start <= byte && byte <= end {
            reaches_start |= expand_reverse_root(
                automaton,
                workspace.reverse.incoming_sources[incoming],
                workspace,
                meter,
                position,
            )?;
        }
    }
    collect_reverse_frontier(automaton, workspace, meter, position)?;
    if workspace.reverse.scratch_len == 0 {
        workspace.reverse.frontier_len = 0;
        return Ok(ReverseTransition::Ready(if reaches_start {
            LAZY_CELL_ACCEPT
        } else {
            0
        }));
    }
    workspace.reverse.retain_scratch_as_frontier()?;
    Ok(ReverseTransition::Inline { reaches_start })
}

fn execute_reverse_lazy_loop(
    automaton: &Automaton,
    haystack: &[u8],
    window_start: usize,
    selected_end: usize,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
) -> Result<(Option<usize>, usize), SearchError> {
    if !workspace.reverse.initialized {
        return Err(SearchError::InternalInvariant {
            detail: "reverse DFA executed without an initialized state",
        });
    }
    let initial = workspace.reverse.initial;
    if initial == LAZY_NO_STATE {
        return Err(SearchError::InternalInvariant {
            detail: "initialized reverse DFA has no initial state",
        });
    }
    let mut state = ReverseState::Cached(direct_row_offset(initial)?);
    let mut cursor = selected_end;
    let mut candidate = None;
    // The Accept-seeded state is the reverse automaton's selected-end
    // boundary; every consumed byte adds one earlier boundary.
    let mut boundaries = 1usize;
    while cursor > window_start {
        let source = cursor
            .checked_sub(1)
            .ok_or(SearchError::InternalInvariant {
                detail: "reverse DFA cursor underflowed",
            })?;
        meter.charge(1, source)?;
        let byte = *haystack.get(source).ok_or(SearchError::InternalInvariant {
            detail: "reverse DFA source position exceeded the validated window",
        })?;
        let transition = match state {
            ReverseState::Cached(cached) => {
                let cell = workspace.reverse.direct_cell(cached, byte)?;
                if cell == LAZY_CELL_UNFILLED {
                    build_reverse_cached_transition(
                        automaton,
                        direct_row_state(cached),
                        byte,
                        workspace,
                        meter,
                        core_reserve,
                        source,
                    )?
                } else {
                    ReverseTransition::Ready(cell)
                }
            }
            ReverseState::Inline => {
                build_reverse_inline_transition(automaton, byte, workspace, meter, source)?
            }
        };
        cursor = source;
        boundaries = boundaries
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse DFA examined boundary count",
            })?;
        let (reaches_start, next) = match transition {
            ReverseTransition::Ready(cell) => {
                let encoded = cell & LAZY_CELL_STATE_MASK;
                (
                    cell & LAZY_CELL_ACCEPT != 0,
                    if encoded == 0 {
                        None
                    } else {
                        Some(ReverseState::Cached(encoded.checked_sub(1).ok_or(
                            SearchError::InternalInvariant {
                                detail: "reverse DFA encoded state underflowed",
                            },
                        )?))
                    },
                )
            }
            ReverseTransition::Inline { reaches_start } => {
                (reaches_start, Some(ReverseState::Inline))
            }
        };
        if reaches_start {
            candidate = Some(cursor);
        }
        let Some(next) = next else {
            break;
        };
        state = next;
    }
    Ok((candidate, boundaries))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the retained-resume copy preserves the ordinary reverse loop's single-caller codegen"
)]
fn execute_resume_reverse_lazy_loop(
    automaton: &Automaton,
    haystack: &[u8],
    window_start: usize,
    selected_end: usize,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
) -> Result<(Option<usize>, usize), SearchError> {
    if !workspace.reverse.initialized {
        return Err(SearchError::InternalInvariant {
            detail: "reverse DFA executed without an initialized state",
        });
    }
    let initial = workspace.reverse.initial;
    if initial == LAZY_NO_STATE {
        return Err(SearchError::InternalInvariant {
            detail: "initialized reverse DFA has no initial state",
        });
    }
    let mut state = ReverseState::Cached(direct_row_offset(initial)?);
    let mut cursor = selected_end;
    let mut candidate = None;
    // The Accept-seeded state is the reverse automaton's selected-end
    // boundary; every consumed byte adds one earlier boundary.
    let mut boundaries = 1usize;
    while cursor > window_start {
        let source = cursor
            .checked_sub(1)
            .ok_or(SearchError::InternalInvariant {
                detail: "reverse DFA cursor underflowed",
            })?;
        meter.charge(1, source)?;
        let byte = *haystack.get(source).ok_or(SearchError::InternalInvariant {
            detail: "reverse DFA source position exceeded the validated window",
        })?;
        let transition = match state {
            ReverseState::Cached(cached) => {
                let cell = workspace.reverse.direct_cell(cached, byte)?;
                if cell == LAZY_CELL_UNFILLED {
                    build_resume_reverse_cached_transition(
                        automaton,
                        direct_row_state(cached),
                        byte,
                        workspace,
                        meter,
                        core_reserve,
                        source,
                    )?
                } else {
                    ReverseTransition::Ready(cell)
                }
            }
            ReverseState::Inline => {
                build_resume_reverse_inline_transition(automaton, byte, workspace, meter, source)?
            }
        };
        cursor = source;
        boundaries = boundaries
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse DFA examined boundary count",
            })?;
        let (reaches_start, next) = match transition {
            ReverseTransition::Ready(cell) => {
                let encoded = cell & LAZY_CELL_STATE_MASK;
                (
                    cell & LAZY_CELL_ACCEPT != 0,
                    if encoded == 0 {
                        None
                    } else {
                        Some(ReverseState::Cached(encoded.checked_sub(1).ok_or(
                            SearchError::InternalInvariant {
                                detail: "reverse DFA encoded state underflowed",
                            },
                        )?))
                    },
                )
            }
            ReverseTransition::Inline { reaches_start } => {
                (reaches_start, Some(ReverseState::Inline))
            }
        };
        if reaches_start {
            candidate = Some(cursor);
        }
        let Some(next) = next else {
            break;
        };
        state = next;
    }
    Ok((candidate, boundaries))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the retained-resume copy preserves the ordinary reverse builder's single-caller codegen"
)]
fn build_resume_reverse_cached_transition(
    automaton: &Automaton,
    state: u32,
    byte: u8,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<ReverseTransition, SearchError> {
    let cached = workspace.reverse.cell(state, byte)?;
    if cached != LAZY_CELL_UNFILLED {
        return Ok(ReverseTransition::Ready(cached));
    }
    let (_, length) = workspace.reverse.state_bounds(state)?;
    begin_reverse_closure(workspace, meter, position)?;
    let mut reaches_start = false;
    for ordinal in 0..length {
        let incoming = usize::try_from(workspace.reverse.item(state, ordinal)?).map_err(|_| {
            SearchError::InternalInvariant {
                detail: "reverse DFA incoming item does not fit usize",
            }
        })?;
        meter.charge(1, position)?;
        let start = workspace.reverse.incoming_starts[incoming];
        let end = workspace.reverse.incoming_ends[incoming];
        if start <= byte && byte <= end {
            reaches_start |= expand_reverse_root(
                automaton,
                workspace.reverse.incoming_sources[incoming],
                workspace,
                meter,
                position,
            )?;
        }
    }
    collect_reverse_frontier(automaton, workspace, meter, position)?;
    finish_reverse_cached_transition(
        automaton,
        state,
        byte,
        reaches_start,
        workspace,
        meter,
        core_reserve,
        position,
    )
}

fn build_resume_reverse_inline_transition(
    automaton: &Automaton,
    byte: u8,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<ReverseTransition, SearchError> {
    let length = workspace.reverse.frontier_len;
    begin_reverse_closure(workspace, meter, position)?;
    let mut reaches_start = false;
    for ordinal in 0..length {
        let incoming = usize::try_from(workspace.reverse.frontier[ordinal]).map_err(|_| {
            SearchError::InternalInvariant {
                detail: "reverse DFA inline item does not fit usize",
            }
        })?;
        meter.charge(1, position)?;
        let start = workspace.reverse.incoming_starts[incoming];
        let end = workspace.reverse.incoming_ends[incoming];
        if start <= byte && byte <= end {
            reaches_start |= expand_reverse_root(
                automaton,
                workspace.reverse.incoming_sources[incoming],
                workspace,
                meter,
                position,
            )?;
        }
    }
    collect_reverse_frontier(automaton, workspace, meter, position)?;
    if workspace.reverse.scratch_len == 0 {
        workspace.reverse.frontier_len = 0;
        return Ok(ReverseTransition::Ready(if reaches_start {
            LAZY_CELL_ACCEPT
        } else {
            0
        }));
    }
    workspace.reverse.retain_scratch_as_frontier()?;
    Ok(ReverseTransition::Inline { reaches_start })
}

fn execute_context_reverse_lazy_loop(
    automaton: &Automaton,
    haystack: &[u8],
    window_start: usize,
    selected_end: usize,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
) -> Result<(Option<usize>, usize), SearchError> {
    let assertions = enabled_assertion_mask(automaton, haystack, selected_end, meter)?;
    let Some(mut state) = context_reverse_initial(
        automaton,
        assertions,
        workspace,
        meter,
        core_reserve,
        selected_end,
    )?
    else {
        return Err(SearchError::InternalInvariant {
            detail: "contextual reverse DFA declined a forward-selected positive match",
        });
    };
    workspace.reverse.initialized = true;

    let mut cursor = selected_end;
    let mut candidate = None;
    let mut boundaries = 1usize;
    while cursor > window_start {
        let source = cursor
            .checked_sub(1)
            .ok_or(SearchError::InternalInvariant {
                detail: "contextual reverse DFA cursor underflowed",
            })?;
        meter.charge(1, source)?;
        let byte = *haystack.get(source).ok_or(SearchError::InternalInvariant {
            detail: "contextual reverse DFA source exceeded the validated window",
        })?;
        let assertions = enabled_assertion_mask(automaton, haystack, source, meter)?;
        let symbol = contextual_symbol(u32::from(byte), assertions);
        let transition = match state {
            ReverseState::Cached(cached) => build_context_reverse_cached_transition(
                automaton,
                cached,
                byte,
                symbol,
                assertions,
                workspace,
                meter,
                core_reserve,
                source,
            )?,
            ReverseState::Inline => build_context_reverse_inline_transition(
                automaton, byte, assertions, workspace, meter, source,
            )?,
        };
        cursor = source;
        boundaries = boundaries
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "contextual reverse DFA examined boundary count",
            })?;
        let (reaches_start, next) = match transition {
            ReverseTransition::Ready(cell) => {
                let encoded = cell & LAZY_CELL_STATE_MASK;
                (
                    cell & LAZY_CELL_ACCEPT != 0,
                    if encoded == 0 {
                        None
                    } else {
                        Some(ReverseState::Cached(encoded.checked_sub(1).ok_or(
                            SearchError::InternalInvariant {
                                detail: "contextual reverse DFA state underflowed",
                            },
                        )?))
                    },
                )
            }
            ReverseTransition::Inline { reaches_start } => {
                (reaches_start, Some(ReverseState::Inline))
            }
        };
        if reaches_start {
            candidate = Some(cursor);
        }
        let Some(next) = next else {
            break;
        };
        state = next;
    }
    Ok((candidate, boundaries))
}

fn context_reverse_initial(
    automaton: &Automaton,
    assertions: u32,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<Option<ReverseState>, SearchError> {
    if !workspace.reverse.context.is_allocated()
        || !workspace.reverse.is_bound_to(automaton)
        || workspace.reverse.declined
    {
        return Ok(None);
    }
    let symbol = contextual_symbol(CONTEXT_INITIAL_BYTE, assertions);
    let (cached, slot) =
        workspace
            .reverse
            .context
            .lookup(CONTEXT_INITIAL_SOURCE, symbol, meter, position)?;
    if let Some(cell) = cached {
        let encoded = cell & LAZY_CELL_STATE_MASK;
        if encoded == 0 || cell & (LAZY_CELL_ACCEPT | LAZY_CELL_RESTART) != 0 {
            return Err(SearchError::InternalInvariant {
                detail: "contextual reverse initial cache cell is invalid",
            });
        }
        return Ok(Some(ReverseState::Cached(encoded.checked_sub(1).ok_or(
            SearchError::InternalInvariant {
                detail: "contextual reverse initial state underflowed",
            },
        )?)));
    }

    begin_reverse_closure(workspace, meter, position)?;
    let mut reaches_start = false;
    for state in 0..automaton.stats().states() {
        meter.charge(1, position)?;
        if automaton.roles[state] == StateRole::Accept {
            reaches_start |= expand_context_reverse_root(
                automaton,
                u32::try_from(state).map_err(|_| SearchError::InternalInvariant {
                    detail: "validated contextual reverse Accept state does not fit u32",
                })?,
                assertions,
                workspace,
                meter,
                position,
            )?;
        }
    }
    collect_reverse_frontier(automaton, workspace, meter, position)?;
    if reaches_start {
        workspace.reverse.scratch_len = 0;
        workspace.reverse.declined = true;
        return Ok(None);
    }
    let (state, encoded) =
        retain_context_reverse_scratch(automaton, workspace, meter, core_reserve, position)?;
    if let Some(encoded) = encoded {
        workspace.reverse.context.publish(
            slot,
            ContextTransitionSlot::populated(CONTEXT_INITIAL_SOURCE, symbol, encoded),
            meter,
            core_reserve,
            position,
        )?;
    }
    Ok(Some(state))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the reverse contextual key and source-boundary closure remain adjacent"
)]
fn build_context_reverse_cached_transition(
    automaton: &Automaton,
    state: u32,
    byte: u8,
    symbol: u32,
    assertions: u32,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<ReverseTransition, SearchError> {
    let (cached, slot) = workspace
        .reverse
        .context
        .lookup(state, symbol, meter, position)?;
    if let Some(cell) = cached {
        return Ok(ReverseTransition::Ready(cell));
    }
    let (_, length) = workspace.reverse.state_bounds(state)?;
    begin_reverse_closure(workspace, meter, position)?;
    let mut reaches_start = false;
    for ordinal in 0..length {
        let incoming = usize::try_from(workspace.reverse.item(state, ordinal)?).map_err(|_| {
            SearchError::InternalInvariant {
                detail: "contextual reverse incoming item does not fit usize",
            }
        })?;
        meter.charge(1, position)?;
        let start = workspace.reverse.incoming_starts[incoming];
        let end = workspace.reverse.incoming_ends[incoming];
        if start <= byte && byte <= end {
            reaches_start |= expand_context_reverse_root(
                automaton,
                workspace.reverse.incoming_sources[incoming],
                assertions,
                workspace,
                meter,
                position,
            )?;
        }
    }
    collect_reverse_frontier(automaton, workspace, meter, position)?;
    if workspace.reverse.scratch_len == 0 {
        let cell = if reaches_start { LAZY_CELL_ACCEPT } else { 0 };
        workspace.reverse.context.publish(
            slot,
            ContextTransitionSlot::populated(state, symbol, cell),
            meter,
            core_reserve,
            position,
        )?;
        return Ok(ReverseTransition::Ready(cell));
    }
    let (_next, encoded) =
        retain_context_reverse_scratch(automaton, workspace, meter, core_reserve, position)?;
    if let Some(encoded) = encoded {
        let cell = encoded | if reaches_start { LAZY_CELL_ACCEPT } else { 0 };
        workspace.reverse.context.publish(
            slot,
            ContextTransitionSlot::populated(state, symbol, cell),
            meter,
            core_reserve,
            position,
        )?;
        Ok(ReverseTransition::Ready(cell))
    } else {
        Ok(ReverseTransition::Inline { reaches_start })
    }
}

fn build_context_reverse_inline_transition(
    automaton: &Automaton,
    byte: u8,
    assertions: u32,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<ReverseTransition, SearchError> {
    let length = workspace.reverse.frontier_len;
    begin_reverse_closure(workspace, meter, position)?;
    let mut reaches_start = false;
    for ordinal in 0..length {
        let incoming = usize::try_from(workspace.reverse.frontier[ordinal]).map_err(|_| {
            SearchError::InternalInvariant {
                detail: "contextual reverse inline item does not fit usize",
            }
        })?;
        meter.charge(1, position)?;
        let start = workspace.reverse.incoming_starts[incoming];
        let end = workspace.reverse.incoming_ends[incoming];
        if start <= byte && byte <= end {
            reaches_start |= expand_context_reverse_root(
                automaton,
                workspace.reverse.incoming_sources[incoming],
                assertions,
                workspace,
                meter,
                position,
            )?;
        }
    }
    collect_reverse_frontier(automaton, workspace, meter, position)?;
    if workspace.reverse.scratch_len == 0 {
        workspace.reverse.frontier_len = 0;
        return Ok(ReverseTransition::Ready(if reaches_start {
            LAZY_CELL_ACCEPT
        } else {
            0
        }));
    }
    workspace.reverse.retain_scratch_as_frontier()?;
    Ok(ReverseTransition::Inline { reaches_start })
}

fn retain_context_reverse_scratch(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    core_reserve: u64,
    position: usize,
) -> Result<(ReverseState, Option<u32>), SearchError> {
    match workspace
        .reverse
        .intern_speculative(meter, core_reserve, position)?
    {
        LazyInterned::State(state) => {
            let encoded = state.checked_add(1).ok_or(SearchError::InternalInvariant {
                detail: "contextual reverse encoded state overflowed",
            })?;
            if encoded > LAZY_CELL_STATE_MASK {
                return Err(SearchError::InternalInvariant {
                    detail: "contextual reverse state exceeds its cell field",
                });
            }
            Ok((ReverseState::Cached(state), Some(encoded)))
        }
        LazyInterned::BudgetDeclined => {
            workspace.reverse.retain_scratch_as_frontier()?;
            Ok((ReverseState::Inline, None))
        }
        LazyInterned::CapacityFull => {
            validate_lazy_capacity_full(
                automaton.stats().consuming_edges(),
                "exact small contextual reverse DFA exhausted its proven capacity",
            )?;
            workspace.reverse.saturated = true;
            workspace.reverse.retain_scratch_as_frontier()?;
            Ok((ReverseState::Inline, None))
        }
    }
}

fn expand_context_reverse_root(
    automaton: &Automaton,
    root: u32,
    assertions: u32,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<bool, SearchError> {
    workspace.push_stack(Thread {
        state: root,
        start: 0,
    })?;
    let mut reaches_start = false;
    while let Some(thread) = workspace.pop_stack() {
        meter.charge(1, position)?;
        let state = crate::plan::plan_index(thread.state);
        if workspace.seen_at[state] == workspace.generation {
            continue;
        }
        workspace.seen_at[state] = workspace.generation;
        reaches_start |= thread.state == automaton.start;
        let incoming = workspace.reverse.incoming_range(thread.state)?;
        for edge in incoming {
            meter.charge(1, position)?;
            let source = workspace.reverse.incoming_sources[edge];
            match automaton.roles[crate::plan::plan_index(source)] {
                StateRole::Split => {
                    let kind = *workspace.reverse.incoming_kinds.get(edge).ok_or(
                        SearchError::InternalInvariant {
                            detail: "contextual reverse CSR kind is outside storage",
                        },
                    )?;
                    if assertion_enabled(kind, assertions)? {
                        workspace.push_stack(Thread {
                            state: source,
                            start: 0,
                        })?;
                    }
                }
                StateRole::Consume => {}
                StateRole::Accept => {
                    return Err(SearchError::InternalInvariant {
                        detail: "contextual reverse CSR contains an outgoing Accept edge",
                    });
                }
            }
        }
    }
    Ok(reaches_start)
}

fn execute_unfiltered_loop(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    earliest: bool,
) -> Result<(Option<MatchSpan>, usize), SearchError> {
    let mut position = window.start();
    let mut boundaries = 0usize;
    let mut pending = None;

    loop {
        boundaries = boundaries
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "examined boundary count",
            })?;
        workspace.begin_boundary(meter, position)?;
        expand_boundary_roots(
            automaton,
            haystack,
            position,
            workspace,
            meter,
            &mut pending,
        )?;

        if earliest && pending.is_some() {
            break;
        }

        // All live states are higher priority than `pending`. If none remain,
        // the pending match is irrevocably selected.
        if workspace.current_len == 0 && (pending.is_some() || position == window.end()) {
            break;
        }
        if position == window.end() {
            break;
        }

        consume_current(automaton, haystack[position], position, workspace, meter)?;
        position = position
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "input position",
            })?;
    }

    Ok((pending, boundaries))
}

#[allow(clippy::too_many_arguments)]
fn execute_filtered_loop(
    automaton: &Automaton,
    haystack: &[u8],
    window: SearchWindow,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    earliest: bool,
    scanner: &StartPositionScanner,
    guard: Option<&StartPositionClass>,
    probe: Option<&StartPositionClass>,
    force_haystack_start: bool,
    adaptive_probe: &mut AdaptiveStartProbe,
) -> Result<(Option<MatchSpan>, usize), SearchError> {
    let mut position = window.start();
    let mut boundaries = 0usize;
    let mut pending = None;
    let mut retained_start_mask = RetainedStartMaskCursor::default();
    let mut engine_candidate = None;

    loop {
        if pending.is_none()
            && workspace.roots_len == 0
            // An absolute-start branch may contribute a match only at
            // original haystack boundary zero. Evaluate the full root there
            // once; the scanner is a proof for later boundaries.
            && !(force_haystack_start && position == 0)
        {
            if position < window.end() {
                if let (Some(probe), Some(candidate)) = (probe, engine_candidate.take()) {
                    adaptive_probe.observe_restartable_rejection(
                        probe,
                        haystack,
                        candidate,
                        window.end(),
                        meter,
                    )?;
                }
            } else {
                engine_candidate = None;
            }
            position = next_start_candidate_adaptive(
                scanner,
                haystack,
                position,
                window.end(),
                guard,
                probe,
                meter,
                &mut retained_start_mask,
                adaptive_probe,
            )?;
            if position == window.end() {
                break;
            }
            if probe.is_some() && adaptive_probe.samples_rejections() {
                engine_candidate = Some(position);
            }
        }
        boundaries = boundaries
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "examined boundary count",
            })?;
        workspace.begin_boundary(meter, position)?;
        expand_boundary_roots(
            automaton,
            haystack,
            position,
            workspace,
            meter,
            &mut pending,
        )?;

        if earliest && pending.is_some() {
            break;
        }

        // All live states are higher priority than `pending`. If none remain,
        // the pending match is irrevocably selected.
        if workspace.current_len == 0 && (pending.is_some() || position == window.end()) {
            break;
        }
        if position == window.end() {
            break;
        }

        consume_current(automaton, haystack[position], position, workspace, meter)?;
        position = position
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "input position",
            })?;
    }

    Ok((pending, boundaries))
}

#[derive(Clone, Copy, Debug)]
struct StartPositionProof {
    sets: [ByteSet; START_FILTER_POSITION_COUNT],
    length: usize,
    force_haystack_start: bool,
}

impl StartPositionProof {
    const fn disabled() -> Self {
        Self {
            sets: [ByteSet::EMPTY; START_FILTER_POSITION_COUNT],
            length: 0,
            force_haystack_start: false,
        }
    }
}

fn derive_start_position_classes(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<StartPositionProof, SearchError> {
    let result = derive_start_position_classes_inner(automaton, workspace, meter, position);
    // The proof borrows the invocation's fixed workspace, but none of its
    // temporary logical entries may become live K0 execution state.
    workspace.current_len = 0;
    workspace.roots_len = 0;
    workspace.stack_len = 0;
    result
}

fn derive_start_position_classes_inner(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<StartPositionProof, SearchError> {
    let mut sets = [ByteSet::EMPTY; START_FILTER_POSITION_COUNT];
    let mut force_haystack_start = false;
    workspace.current_len = 0;
    workspace.roots_len = 0;
    workspace.stack_len = 0;

    for depth in 0..START_FILTER_POSITION_COUNT {
        begin_start_proof_depth(workspace)?;
        let frontier_len = if depth == 0 { 1 } else { workspace.roots_len };
        let mut reached_accept = false;
        let mut words = [0_u64; 4];

        for frontier_index in 0..frontier_len {
            workspace.stack_len = 0;
            let state = if depth == 0 {
                automaton.start
            } else {
                workspace.roots[frontier_index].state
            };
            workspace.push_stack(Thread { state, start: 0 })?;

            while let Some(thread) = workspace.pop_stack() {
                meter.charge(1, position)?;
                let state = thread.state;
                let state_index = crate::plan::plan_index(state);
                if workspace.seen_at[state_index] == workspace.generation {
                    continue;
                }
                workspace.seen_at[state_index] = workspace.generation;

                match automaton.roles[state_index] {
                    StateRole::Accept => {
                        reached_accept = true;
                        break;
                    }
                    StateRole::Consume => {
                        workspace.push_current(thread)?;
                        for edge in automaton.state_edges(state) {
                            meter.charge(1, position)?;
                            insert_byte_range(
                                &mut words,
                                automaton.byte_starts[edge],
                                automaton.byte_ends[edge],
                            );
                        }
                    }
                    StateRole::Split => {
                        for edge in automaton.state_edges(state).rev() {
                            meter.charge(1, position)?;
                            if automaton.edge_kinds[edge] == EdgeKind::AssertHaystackStart {
                                // Boundary zero is evaluated without filtering;
                                // every scanner-selected boundary is nonzero.
                                if depth == 0 {
                                    force_haystack_start = true;
                                }
                                continue;
                            }
                            // Every other assertion is conservatively relaxed
                            // to epsilon. This only enlarges the byte class.
                            workspace.push_stack(Thread {
                                state: automaton.edge_targets[edge],
                                start: 0,
                            })?;
                        }
                    }
                }
            }
            if reached_accept {
                break;
            }
        }

        // If a path can accept after exactly `depth` consumed bytes, no byte
        // at this or any later offset is required by every match.
        if reached_accept {
            return Ok(StartPositionProof {
                sets,
                length: depth,
                force_haystack_start,
            });
        }

        let set = ByteSet::from_words(words);
        sets[depth] = set;
        if set == ByteSet::EMPTY {
            // No nonzero-start path can consume the next required byte, so no
            // such path can ever accept.
            sets[0] = ByteSet::EMPTY;
            return Ok(StartPositionProof {
                sets,
                length: 1,
                force_haystack_start,
            });
        }
        let next_depth = depth
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter next proof depth",
            })?;
        if next_depth == START_FILTER_POSITION_COUNT {
            return Ok(StartPositionProof {
                sets,
                length: START_FILTER_POSITION_COUNT,
                force_haystack_start,
            });
        }

        // Build the exact consumed-depth frontier for the next class. Revisit
        // and charge every consuming edge before retaining its target.
        retain_next_start_frontier(automaton, workspace, meter, position)?;
    }

    Ok(StartPositionProof::disabled())
}

fn begin_start_proof_depth(workspace: &mut K0Workspace) -> Result<(), SearchError> {
    workspace.generation =
        workspace
            .generation
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter proof generation",
            })?;
    workspace.current_len = 0;
    Ok(())
}

fn retain_next_start_frontier(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<(), SearchError> {
    workspace.roots_len = 0;
    for current_index in 0..workspace.current_len {
        let state = workspace.current[current_index].state;
        for edge in automaton.state_edges(state) {
            meter.charge(1, position)?;
            workspace.push_root(Thread {
                state: automaton.edge_targets[edge],
                start: 0,
            })?;
        }
    }
    Ok(())
}

// Keep the pending proof inline until the complete search succeeds. Publication
// then uses the fallible, exactly accounted cold owner; the warm variant remains
// one borrowed pointer resolved before the execution loop.
#[allow(clippy::large_enum_variant)]
enum InvocationStartProof<'a> {
    Published(&'a StartFilterProof),
    Pending {
        proof: StartFilterProof,
        publish: bool,
    },
}

impl InvocationStartProof<'_> {
    #[cfg(test)]
    const fn proof(&self) -> &StartFilterProof {
        match self {
            Self::Published(proof) => proof,
            Self::Pending { proof, .. } => proof,
        }
    }

    const fn borrowed(&self) -> ExecutionStartProof<'_> {
        match self {
            Self::Published(proof) => ExecutionStartProof::Published(proof),
            Self::Pending { proof, publish } => ExecutionStartProof::Pending {
                proof,
                publish: *publish,
            },
        }
    }
}

#[derive(Clone, Copy)]
enum ExecutionStartProof<'a> {
    Published(&'a StartFilterProof),
    Pending {
        proof: &'a StartFilterProof,
        publish: bool,
    },
}

impl<'a> ExecutionStartProof<'a> {
    const fn proof(self) -> &'a StartFilterProof {
        match self {
            Self::Published(proof) | Self::Pending { proof, .. } => proof,
        }
    }

    fn publish(
        self,
        automaton: &Automaton,
        workspace_bytes: usize,
        scratch_limit: usize,
        meter: &mut WorkMeter,
        setup: &mut SetupAccounting,
        setup_work: &mut u64,
    ) -> usize {
        let Self::Pending {
            proof,
            publish: true,
        } = self
        else {
            return 0;
        };
        if automaton.start_filter_proof.is_initialized() {
            return 0;
        }

        let proof_bytes = StartFilterProofCell::PAYLOAD_BYTES;
        let Some(scratch_bytes) = workspace_bytes.checked_add(proof_bytes) else {
            return 0;
        };
        if scratch_bytes > scratch_limit || meter.remaining() < START_FILTER_OWNER_ALLOCATION_WORK {
            // Optional specialization ownership never turns an otherwise
            // admitted ordinary K0 result into a resource error. Unlike an
            // allocator failure, a resource refusal remains retryable.
            return 0;
        }
        let Some(next_setup_work) = setup.work.checked_add(START_FILTER_OWNER_ALLOCATION_WORK)
        else {
            return 0;
        };
        let Some(next_reported_setup_work) =
            setup_work.checked_add(START_FILTER_OWNER_ALLOCATION_WORK)
        else {
            return 0;
        };
        let Some(next_allocated_bytes) = setup.allocated_bytes.checked_add(proof_bytes) else {
            return 0;
        };
        let Some(next_initialized_bytes) = setup.initialized_bytes.checked_add(proof_bytes) else {
            return 0;
        };

        match automaton.start_filter_proof.publish(proof) {
            StartFilterPublication::AlreadyInitialized => 0,
            StartFilterPublication::AllocationFailed => {
                meter.charge_admitted(START_FILTER_OWNER_ALLOCATION_WORK);
                setup.work = next_setup_work;
                *setup_work = next_reported_setup_work;
                0
            }
            StartFilterPublication::Published => {
                meter.charge_admitted(START_FILTER_OWNER_ALLOCATION_WORK);
                setup.work = next_setup_work;
                setup.allocated_bytes = next_allocated_bytes;
                setup.initialized_bytes = next_initialized_bytes;
                *setup_work = next_reported_setup_work;
                proof_bytes
            }
        }
    }
}

fn prepare_start_filter<'a>(
    automaton: &'a Automaton,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    position: usize,
    end: usize,
) -> Result<InvocationStartProof<'a>, SearchError> {
    if let Some(proof) = automaton.start_filter_proof.get() {
        return Ok(InvocationStartProof::Published(proof));
    }
    if automaton.start_filter_proof.allocation_failed() {
        return Ok(InvocationStartProof::Published(
            &ORDINARY_START_FILTER_PROOF,
        ));
    }

    let position_proof = derive_start_position_classes(automaton, workspace, meter, position)?;
    let (scanner, filter, publish) = if position_proof.length == 0 {
        (None, None, true)
    } else {
        let selection = select_start_classes(
            &position_proof.sets[..position_proof.length],
            meter,
            position,
        )?;
        if selection.scanner.set == ByteSet::ALL
            && selection.guard.is_none()
            && selection.probe.is_none()
        {
            (None, None, true)
        } else {
            let scanner = build_byte_start_scanner(
                selection.scanner.set,
                selection.scanner_cardinality,
                meter,
                position,
            )?;
            let (filter, publish) = if let Some(guard) = selection.guard {
                (Some(StartPositionFilter::Guard(guard)), true)
            } else if let Some(probe) = selection.probe {
                let work = u64::try_from(START_FILTER_PROBE_SELECTION_WORK)
                    .expect("Probe selection work fits u64");
                // A finite caller may be exactly admitted for ordinary K0.
                // Probe retention can spend only surplus above a complete
                // source-independent execution allowance and the optional
                // proof-owner unit, just like optional lazy-cache learning.
                // This makes the one-unit shortfall a successful scanner-only
                // call instead of stealing completion or publication work.
                let completion_reserve = if meter.limit == u64::MAX {
                    0
                } else {
                    end.checked_sub(position).map_or(u64::MAX, |bytes| {
                        start_probe_completion_reserve(automaton, bytes)
                    })
                };
                if meter.try_charge_optional(work, completion_reserve) {
                    (Some(StartPositionFilter::Probe(probe)), true)
                } else {
                    // A constrained caller may use the already-built scanner,
                    // but must not permanently publish a resource-dependent
                    // degraded proof and poison later richer invocations.
                    (None, false)
                }
            } else {
                (None, true)
            };
            (
                Some(StartPositionScanner {
                    offset: selection.scanner.offset,
                    scanner,
                }),
                filter,
                publish,
            )
        }
    };

    let proof = StartFilterProof {
        // The forced boundary matters only when skipping is enabled.
        force_haystack_start: scanner.is_some() && position_proof.force_haystack_start,
        scanner,
        filter,
        relaxed_nullable: position_proof.length == 0,
    };
    // Publish only after the entire search succeeds. A racing successful
    // caller may win first; both values come from the same immutable graph.
    Ok(InvocationStartProof::Pending { proof, publish })
}

fn start_probe_completion_reserve(automaton: &Automaton, input_bytes: usize) -> u64 {
    automaton
        .conservative_post_start_filter_work_bound(input_bytes)
        .ok()
        .and_then(|work| work.checked_add(START_FILTER_OWNER_ALLOCATION_WORK))
        .unwrap_or(u64::MAX)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StartClassSelection {
    scanner: StartPositionClass,
    scanner_cardinality: u32,
    guard: Option<StartPositionClass>,
    probe: Option<StartPositionClass>,
}

// The original proof considered positions zero through seven. Preserve its
// equal-cardinality choices exactly: byte-set cardinality does not predict
// source frequency, so a newly proved deeper class must be strictly smaller
// before it displaces an established scanner or guard.
const START_FILTER_STABLE_TIE_POSITION_COUNT: u8 = 8;

const fn scanner_tie_rank(offset: u8) -> (bool, u8) {
    // Root first avoids hot-path rewind. Among later positions, deeper scans a
    // shorter suffix and rejects truncated windows earlier.
    (offset == 0, offset)
}

fn select_start_classes(
    sets: &[ByteSet],
    meter: &mut WorkMeter,
    position: usize,
) -> Result<StartClassSelection, SearchError> {
    debug_assert!(!sets.is_empty());
    debug_assert!(sets.len() <= START_FILTER_POSITION_COUNT);
    let mut cardinalities = [0_u32; START_FILTER_POSITION_COUNT];
    let mut scanner: Option<(u32, StartPositionClass)> = None;

    for (offset, &set) in sets.iter().enumerate() {
        meter.charge(
            u64::try_from(BYTE_START_BITMAP_POPULATION_WORK)
                .expect("byte bitmap population work fits u64"),
            position,
        )?;
        let cardinality = set.cardinality();
        cardinalities[offset] = cardinality;
        meter.charge(
            u64::try_from(START_FILTER_SCANNER_SELECTION_WORK)
                .expect("scanner selection work fits u64"),
            position,
        )?;
        let class = StartPositionClass {
            offset: u8::try_from(offset).expect("bounded start-filter offset fits u8"),
            set,
        };
        let replace = match scanner {
            None => true,
            Some((best_cardinality, best_class)) => {
                cardinality < best_cardinality
                    || (cardinality == best_cardinality
                        && class.offset < START_FILTER_STABLE_TIE_POSITION_COUNT
                        && scanner_tie_rank(class.offset) > scanner_tie_rank(best_class.offset))
            }
        };
        if replace {
            scanner = Some((cardinality, class));
        }
    }

    let (scanner_cardinality, scanner) =
        scanner.expect("a nonempty exact-position proof selects a scanner");
    let mut guard: Option<(u32, StartPositionClass)> = None;
    let mut probe: Option<(u32, StartPositionClass)> = None;
    for (offset, &set) in sets.iter().enumerate() {
        if offset == usize::from(scanner.offset) {
            continue;
        }
        meter.charge(
            u64::try_from(START_FILTER_GUARD_SELECTION_WORK)
                .expect("secondary-filter comparison work fits u64"),
            position,
        )?;
        let cardinality = cardinalities[offset];
        let class = StartPositionClass {
            offset: u8::try_from(offset).expect("bounded start-filter offset fits u8"),
            set,
        };
        let retained = if cardinality <= START_FILTER_GUARD_MAX_CARDINALITY {
            &mut guard
        } else if cardinality < u32::from(u8::MAX) + 1 {
            &mut probe
        } else {
            continue;
        };
        let replace = match *retained {
            None => true,
            Some((best_cardinality, best_class)) => {
                cardinality < best_cardinality
                    || (cardinality == best_cardinality
                        && class.offset < START_FILTER_STABLE_TIE_POSITION_COUNT
                        && class.offset > best_class.offset)
            }
        };
        if replace {
            *retained = Some((cardinality, class));
        }
    }

    Ok(StartClassSelection {
        scanner,
        scanner_cardinality,
        guard: guard.map(|(_, class)| class),
        probe: probe.map(|(_, class)| class),
    })
}

#[cfg(test)]
fn byte_start_scanner(
    set: ByteSet,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<StartScanner, SearchError> {
    meter.charge(
        u64::try_from(BYTE_START_BITMAP_POPULATION_WORK)
            .expect("byte bitmap population work fits u64"),
        position,
    )?;
    let cardinality = set.cardinality();
    build_byte_start_scanner(set, cardinality, meter, position)
}

fn build_byte_start_scanner(
    set: ByteSet,
    cardinality: u32,
    meter: &mut WorkMeter,
    position: usize,
) -> Result<StartScanner, SearchError> {
    debug_assert_eq!(set.cardinality(), cardinality);
    if cardinality == 0 {
        return Ok(StartScanner::Empty);
    }
    if usize::try_from(cardinality).expect("byte cardinality fits usize")
        <= BYTE_START_SMALL_MAX_MEMBERS
    {
        let extraction_work = usize::try_from(cardinality)
            .ok()
            .and_then(|members| members.checked_mul(BYTE_START_MEMBER_EXTRACTION_WORK))
            .and_then(|work| u64::try_from(work).ok())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "small byte start-scanner extraction work",
            })?;
        meter.charge(extraction_work, position)?;
        let mut bytes = [0_u8; BYTE_START_SMALL_MAX_MEMBERS];
        let mut length = 0usize;
        for (word_index, mut word) in set.words().into_iter().enumerate() {
            while word != 0 {
                let bit = word.trailing_zeros();
                let byte = word_index
                    .checked_mul(64)
                    .and_then(|offset| u8::try_from(offset).ok())
                    .expect("byte word offset fits u8")
                    .checked_add(u8::try_from(bit).expect("byte word bit fits u8"))
                    .expect("byte bitmap member fits u8");
                *bytes
                    .get_mut(length)
                    .expect("small byte scanner retains at most three bytes") = byte;
                length = length
                    .checked_add(1)
                    .expect("small byte scanner cardinality fits usize");
                word &= word
                    .checked_sub(1)
                    .expect("the small byte scanner word is nonzero");
            }
        }
        return Ok(match bytes[..length] {
            [byte] => StartScanner::One(byte),
            [first, second] => StartScanner::Two(first, second),
            [first, second, third] => StartScanner::Three(first, second, third),
            _ => unreachable!("one-to-three-byte set has matching scanner cardinality"),
        });
    }

    meter.charge(
        u64::try_from(BYTE_START_RANGE_DETECTION_WORK).expect("range detection work fits u64"),
        position,
    )?;
    if let Some((start, end)) = inclusive_byte_range(set, cardinality) {
        return Ok(StartScanner::Range { start, end });
    }

    if let Some(ascii) = ascii_start_set(set) {
        meter.charge(
            u64::try_from(BYTE_START_ASCII_CLASSIFIER_SELECTION_WORK)
                .expect("ASCII classifier construction work fits u64"),
            position,
        )?;
        return Ok(StartScanner::AsciiSet {
            set,
            classifier: StartAsciiClassifier::new(ascii),
        });
    }

    meter.charge(
        u64::try_from(BYTE_START_SET_CLASSIFIER_BUILD_WORK)
            .expect("full-byte classifier construction work fits u64"),
        position,
    )?;
    Ok(StartScanner::Set(build_full_byte_start_classifier(set)))
}

fn inclusive_byte_range(set: ByteSet, cardinality: u32) -> Option<(u8, u8)> {
    debug_assert_eq!(set.cardinality(), cardinality);
    let words = set.words();
    let mut first_word = None;
    let mut last_word = None;
    for (index, word) in words.into_iter().enumerate() {
        if word != 0 {
            first_word.get_or_insert(index);
            last_word = Some(index);
        }
    }
    let first_word = first_word?;
    let last_word = last_word?;
    let word_bits = usize::try_from(u64::BITS).ok()?;
    let first_bit = usize::try_from(words[first_word].trailing_zeros()).ok()?;
    let last_bit = u64::BITS
        .checked_sub(1)?
        .checked_sub(words[last_word].leading_zeros())
        .and_then(|bit| usize::try_from(bit).ok())?;
    let start = first_word.checked_mul(word_bits)?.checked_add(first_bit)?;
    let end = last_word.checked_mul(word_bits)?.checked_add(last_bit)?;
    let span = end.checked_sub(start)?.checked_add(1)?;
    if u32::try_from(span).ok()? != cardinality {
        return None;
    }
    Some((u8::try_from(start).ok()?, u8::try_from(end).ok()?))
}

fn ascii_start_set(set: ByteSet) -> Option<AsciiByteSet> {
    let [low, high, upper_low, upper_high] = set.words();
    (upper_low == 0 && upper_high == 0).then_some(AsciiByteSet::from_words([low, high]))
}

fn build_full_byte_start_classifier(set: ByteSet) -> StartByteSetClassifier {
    StartByteSetClassifier::new(ByteSetClassifier::new(ByteSet256::from_words(set.words())))
}

#[cold]
#[inline(never)]
pub(crate) fn insert_byte_range(words: &mut [u64; 4], start: u8, end: u8) {
    let start_word = usize::from(start / 64);
    let end_word = usize::from(end / 64);
    let start_bit = u32::from(start % 64);
    let end_bit = u32::from(end % 64);
    let end_shift = 63_u32
        .checked_sub(end_bit)
        .expect("a byte-range bit index is at most 63");
    if start_word == end_word {
        words[start_word] |= (u64::MAX << start_bit) & (u64::MAX >> end_shift);
        return;
    }
    words[start_word] |= u64::MAX << start_bit;
    for word in &mut words[start_word + 1..end_word] {
        *word = u64::MAX;
    }
    words[end_word] |= u64::MAX >> end_shift;
}

fn next_start_candidate(
    scanner: &StartPositionScanner,
    haystack: &[u8],
    position: usize,
    end: usize,
    guard: Option<&StartPositionClass>,
    meter: &mut WorkMeter,
) -> Result<usize, SearchError> {
    next_start_candidate_inner(scanner, haystack, position, end, guard, meter, None)
}

fn next_start_candidate_retained(
    scanner: &StartPositionScanner,
    haystack: &[u8],
    position: usize,
    end: usize,
    guard: Option<&StartPositionClass>,
    meter: &mut WorkMeter,
    cursor: &mut RetainedStartMaskCursor,
) -> Result<usize, SearchError> {
    next_start_candidate_inner(scanner, haystack, position, end, guard, meter, Some(cursor))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum AdaptiveProbePhase {
    #[default]
    Inactive,
    Active,
    Disabled,
}

/// Invocation-local evidence for one broad exact-position Probe.
///
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AdaptiveStartProbe {
    phase: AdaptiveProbePhase,
    consecutive_rejections: u8,
}

impl AdaptiveStartProbe {
    const fn samples_rejections(self) -> bool {
        matches!(self.phase, AdaptiveProbePhase::Inactive)
    }

    fn observe_restartable_rejection(
        &mut self,
        probe: &StartPositionClass,
        haystack: &[u8],
        candidate: usize,
        end: usize,
        meter: &mut WorkMeter,
    ) -> Result<(), SearchError> {
        debug_assert_eq!(self.phase, AdaptiveProbePhase::Inactive);

        // Preserve failure atomicity for the invocation-local state: charge
        // before the source read and before changing the rejection streak.
        meter.charge(1, candidate)?;
        let probe_position = candidate.checked_add(usize::from(probe.offset)).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "adaptive start-probe position",
            },
        )?;
        let passed = probe_position < end && probe.set.contains(haystack[probe_position]);
        if passed {
            self.consecutive_rejections = 0;
        } else {
            self.consecutive_rejections = self.consecutive_rejections.saturating_add(1).min(2);
            if self.consecutive_rejections == 2 {
                self.phase = AdaptiveProbePhase::Active;
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn next_start_candidate_adaptive(
    scanner: &StartPositionScanner,
    haystack: &[u8],
    mut position: usize,
    end: usize,
    guard: Option<&StartPositionClass>,
    probe: Option<&StartPositionClass>,
    meter: &mut WorkMeter,
    cursor: &mut RetainedStartMaskCursor,
    state: &mut AdaptiveStartProbe,
) -> Result<usize, SearchError> {
    debug_assert!(guard.is_none() || probe.is_none());
    let Some(probe) = probe else {
        return next_start_candidate_retained(
            scanner, haystack, position, end, guard, meter, cursor,
        );
    };

    loop {
        let candidate =
            next_start_candidate_retained(scanner, haystack, position, end, None, meter, cursor)?;
        if candidate == end {
            return Ok(end);
        }
        if state.phase != AdaptiveProbePhase::Active {
            return Ok(candidate);
        }

        // An active Probe is a real start-filter operation. Charge before its
        // source read; a truncated exact position is a charged rejection.
        meter.charge(1, candidate)?;
        let probe_position = candidate.checked_add(usize::from(probe.offset)).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "adaptive start-probe position",
            },
        )?;
        if probe_position < end && probe.set.contains(haystack[probe_position]) {
            state.phase = AdaptiveProbePhase::Disabled;
            return Ok(candidate);
        }

        position = candidate
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "adaptive start-probe next candidate",
            })?;
    }
}

fn next_start_candidate_inner(
    scanner: &StartPositionScanner,
    haystack: &[u8],
    position: usize,
    end: usize,
    guard: Option<&StartPositionClass>,
    meter: &mut WorkMeter,
    mut cursor: Option<&mut RetainedStartMaskCursor>,
) -> Result<usize, SearchError> {
    let mut search = position;
    let scanner_offset = usize::from(scanner.offset);
    loop {
        let scan_start =
            search
                .checked_add(scanner_offset)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "start-filter scanner position",
                })?;
        if scan_start >= end {
            if let Some(cursor) = cursor.as_deref_mut() {
                cursor.clear();
            }
            return Ok(end);
        }
        let scan_position = next_scanner_candidate(
            &scanner.scanner,
            haystack,
            scan_start,
            end,
            meter,
            cursor.as_deref_mut(),
        )?;
        if scan_position == end {
            if let Some(cursor) = cursor.as_deref_mut() {
                cursor.clear();
            }
            return Ok(end);
        }
        let candidate =
            scan_position
                .checked_sub(scanner_offset)
                .ok_or(SearchError::InternalInvariant {
                    detail: "start-filter scanner matched before its exact offset",
                })?;
        let Some(guard) = guard else {
            return Ok(candidate);
        };
        let guard_position = candidate.checked_add(usize::from(guard.offset)).ok_or(
            SearchError::ArithmeticOverflow {
                computation: "start-filter guard position",
            },
        )?;
        meter.charge(1, candidate)?;
        if guard_position >= end {
            if let Some(cursor) = cursor.as_deref_mut() {
                cursor.clear();
            }
            return Ok(end);
        }
        if guard.set.contains(haystack[guard_position]) {
            return Ok(candidate);
        }
        search = candidate
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter next candidate",
            })?;
    }
}

fn next_scanner_candidate(
    scanner: &StartScanner,
    haystack: &[u8],
    position: usize,
    end: usize,
    meter: &mut WorkMeter,
    cursor: Option<&mut RetainedStartMaskCursor>,
) -> Result<usize, SearchError> {
    match scanner {
        StartScanner::Empty => Ok(end),
        StartScanner::One(byte) => {
            next_small_start_candidate(haystack, position, end, meter, |source| {
                memchr(*byte, source)
            })
        }
        StartScanner::Two(first, second) => {
            next_small_start_candidate(haystack, position, end, meter, |source| {
                memchr2(*first, *second, source)
            })
        }
        StartScanner::Three(first, second, third) => {
            next_small_start_candidate(haystack, position, end, meter, |source| {
                memchr3(*first, *second, *third, source)
            })
        }
        StartScanner::Range {
            start,
            end: range_end,
        } => next_range_start_candidate(*start, *range_end, haystack, position, end, meter, cursor),
        StartScanner::AsciiSet { classifier, .. } => next_ascii_start_candidate(
            classifier.classifier(),
            haystack,
            position,
            end,
            meter,
            cursor,
        ),
        StartScanner::Set(classifier) => {
            next_set_start_candidate(classifier, haystack, position, end, meter, cursor)
        }
    }
}

fn next_small_start_candidate(
    haystack: &[u8],
    position: usize,
    end: usize,
    meter: &mut WorkMeter,
    find: impl FnOnce(&[u8]) -> Option<usize>,
) -> Result<usize, SearchError> {
    let remaining = haystack
        .get(position..end)
        .ok_or(SearchError::InternalInvariant {
            detail: "start scanner range exceeded the validated search window",
        })?;
    let available = meter.limit.saturating_sub(meter.consumed);
    let admitted = usize::try_from(available)
        .unwrap_or(usize::MAX)
        .min(remaining.len());
    let relative = find(&remaining[..admitted]);
    let scanned = relative
        .map(|offset| {
            offset
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "small start-scanner matched extent",
                })
        })
        .transpose()?
        .unwrap_or(admitted);
    let scanned_work = u64::try_from(scanned).map_err(|_| SearchError::ArithmeticOverflow {
        computation: "small start-scanner work",
    })?;
    meter.charge_admitted(scanned_work);

    if let Some(relative) = relative {
        return position
            .checked_add(relative)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "small start-scanner candidate",
            });
    }
    if admitted == remaining.len() {
        return Ok(end);
    }

    let refused_position =
        position
            .checked_add(admitted)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "small start-scanner refusal position",
            })?;
    meter.charge(1, refused_position)?;
    Err(SearchError::InternalInvariant {
        detail: "start scanner admitted progress beyond the work limit",
    })
}

fn next_range_start_candidate(
    start: u8,
    range_end: u8,
    haystack: &[u8],
    mut position: usize,
    end: usize,
    meter: &mut WorkMeter,
    mut cursor: Option<&mut RetainedStartMaskCursor>,
) -> Result<usize, SearchError> {
    debug_assert!(start <= range_end);
    let width = range_end.wrapping_sub(start);

    if let Some(cursor) = cursor.as_deref_mut() {
        match cursor.take(position, end)? {
            RetainedStartCandidate::Unavailable => {}
            RetainedStartCandidate::Candidate(candidate) => return Ok(candidate),
            RetainedStartCandidate::ResumeAt(resume) => position = resume,
        }
    }

    // Nearby candidates are cheaper as direct comparisons, and a guard that
    // rejects one candidate can re-enter at the following byte without
    // repeatedly classifying an overlapping fixed-width block.
    let scalar_prefix_end = position.saturating_add(BYTE_SET_BLOCK_BYTES).min(end);
    let prefix_candidate =
        next_small_start_candidate(haystack, position, scalar_prefix_end, meter, |source| {
            source
                .iter()
                .position(|&byte| byte.wrapping_sub(start) <= width)
        })?;
    if prefix_candidate < scalar_prefix_end {
        return Ok(prefix_candidate);
    }
    position = scalar_prefix_end;

    // Charge a complete logical block before its first source read. A match
    // in any lane therefore has the same hard-limit threshold as the broad
    // full-byte classifier it replaces.
    let block_work = u64::try_from(BYTE_SET_BLOCK_BYTES).expect("range block width fits in u64");
    while end.saturating_sub(position) >= BYTE_SET_BLOCK_BYTES && meter.remaining() >= block_work {
        meter.charge_admitted(block_work);
        let block_end =
            position
                .checked_add(BYTE_SET_BLOCK_BYTES)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "start-range block end",
                })?;
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = haystack
            .get(position..block_end)
            .ok_or(SearchError::InternalInvariant {
                detail: "start-range scanner exceeded the validated search window",
            })?
            .try_into()
            .expect("checked start-range block extent");
        let members =
            classify_byte_delta_16(start, range_end.wrapping_sub(start), block).member_mask();
        if members != 0 {
            if let Some(cursor) = cursor.as_deref_mut() {
                return cursor.retain_complete_block(
                    position,
                    BYTE_SET_BLOCK_BYTES,
                    u64::from(members),
                    end,
                );
            }
            let offset = usize::try_from(members.trailing_zeros())
                .expect("a start-range lane fits in usize");
            return position
                .checked_add(offset)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "start-range candidate",
                });
        }
        position = block_end;
    }

    next_small_start_candidate(haystack, position, end, meter, |source| {
        source
            .iter()
            .position(|&byte| byte.wrapping_sub(start) <= width)
    })
}

fn next_set_start_candidate(
    classifier: &StartByteSetClassifier,
    haystack: &[u8],
    mut position: usize,
    end: usize,
    meter: &mut WorkMeter,
    mut cursor: Option<&mut RetainedStartMaskCursor>,
) -> Result<usize, SearchError> {
    // A table classifier has a higher fixed cost than one bitmap lookup. Keep
    // the first complete classifier-width block scalar so short searches and
    // repeated nearby candidates retain the low-latency path; vector work is
    // reserved for the long no-candidate spans that can amortize it.
    let set = classifier.set();
    if let Some(cursor) = cursor.as_deref_mut() {
        match cursor.take(position, end)? {
            RetainedStartCandidate::Unavailable => {}
            RetainedStartCandidate::Candidate(candidate) => return Ok(candidate),
            RetainedStartCandidate::ResumeAt(resume) => position = resume,
        }
    }
    let scalar_prefix_end = position.saturating_add(BYTE_SET_BLOCK_BYTES).min(end);
    let prefix_candidate =
        next_small_start_candidate(haystack, position, scalar_prefix_end, meter, |source| {
            source.iter().position(|&byte| set.contains(byte))
        })?;
    if prefix_candidate < scalar_prefix_end {
        return Ok(prefix_candidate);
    }
    position = scalar_prefix_end;

    // Start-filter work counts each logically examined source byte once. This
    // preserves the scalar scanner's hard-limit threshold and monotonicity.
    let block_work =
        u64::try_from(BYTE_SET_BLOCK_BYTES).expect("classifier block width fits in u64");
    while end.saturating_sub(position) >= BYTE_SET_BLOCK_BYTES && meter.remaining() >= block_work {
        meter.charge_admitted(block_work);
        let block_end =
            position
                .checked_add(BYTE_SET_BLOCK_BYTES)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "full-byte start-classifier block end",
                })?;
        let source = haystack
            .get(position..block_end)
            .ok_or(SearchError::InternalInvariant {
                detail: "full-byte start classifier exceeded the validated search window",
            })?;
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = source
            .try_into()
            .expect("checked full-byte classifier extent");
        let members = classifier.classifier().classify_16(block).member_mask();
        if members != 0 {
            if let Some(cursor) = cursor.as_deref_mut() {
                return cursor.retain_complete_block(
                    position,
                    BYTE_SET_BLOCK_BYTES,
                    u64::from(members),
                    end,
                );
            }
            let offset = usize::try_from(members.trailing_zeros())
                .expect("a classified full-byte lane fits in usize");
            return position
                .checked_add(offset)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "full-byte start-classifier candidate",
                });
        }
        position = block_end;
    }

    next_small_start_candidate(haystack, position, end, meter, |source| {
        source.iter().position(|&byte| set.contains(byte))
    })
}

fn next_ascii_start_candidate(
    classifier: &AsciiByteSetClassifier,
    haystack: &[u8],
    mut position: usize,
    end: usize,
    meter: &mut WorkMeter,
    mut cursor: Option<&mut RetainedStartMaskCursor>,
) -> Result<usize, SearchError> {
    if let Some(cursor) = cursor.as_deref_mut() {
        match cursor.take(position, end)? {
            RetainedStartCandidate::Unavailable => {}
            RetainedStartCandidate::Candidate(candidate) => return Ok(candidate),
            RetainedStartCandidate::ResumeAt(resume) => position = resume,
        }
    }
    while end.saturating_sub(position) >= ASCII_WIDE_BYTES
        && meter.remaining() >= u64::try_from(ASCII_WIDE_BYTES).expect("classifier width fits u64")
    {
        meter.charge_admitted(u64::try_from(ASCII_WIDE_BYTES).expect("classifier width fits u64"));
        let block_end =
            position
                .checked_add(ASCII_WIDE_BYTES)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "wide start-classifier block end",
                })?;
        let block: &[u8; ASCII_WIDE_BYTES] = haystack[position..block_end]
            .try_into()
            .expect("checked wide classifier extent");
        let members = classifier.classify_32(block).member_mask();
        if members != 0 {
            if let Some(cursor) = cursor.as_deref_mut() {
                return cursor.retain_complete_block(
                    position,
                    ASCII_WIDE_BYTES,
                    u64::from(members),
                    end,
                );
            }
            let offset =
                usize::try_from(members.trailing_zeros()).expect("wide classifier lane fits usize");
            return position
                .checked_add(offset)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "wide start-classifier candidate",
                });
        }
        position = block_end;
    }
    if end.saturating_sub(position) >= ASCII_NARROW_BYTES
        && meter.remaining()
            >= u64::try_from(ASCII_NARROW_BYTES).expect("classifier width fits u64")
    {
        meter
            .charge_admitted(u64::try_from(ASCII_NARROW_BYTES).expect("classifier width fits u64"));
        let block_end =
            position
                .checked_add(ASCII_NARROW_BYTES)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "narrow start-classifier block end",
                })?;
        let block: &[u8; ASCII_NARROW_BYTES] = haystack[position..block_end]
            .try_into()
            .expect("checked narrow classifier extent");
        let members = classifier.classify_16(block).member_mask();
        if members != 0 {
            if let Some(cursor) = cursor {
                return cursor.retain_complete_block(
                    position,
                    ASCII_NARROW_BYTES,
                    u64::from(members),
                    end,
                );
            }
            let offset = usize::try_from(members.trailing_zeros())
                .expect("narrow classifier lane fits usize");
            return position
                .checked_add(offset)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "narrow start-classifier candidate",
                });
        }
        position = block_end;
    }
    next_small_start_candidate(haystack, position, end, meter, |source| {
        source
            .iter()
            .position(|&byte| classifier.set().contains(byte))
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootRunCachedCandidate {
    Candidate(usize),
    Exhausted,
    ResumeAt(usize),
}

fn classify_root_run_members(
    classifier: &AsciiByteSetClassifier,
    haystack: &[u8],
    position: usize,
    length: usize,
    meter: &mut WorkMeter,
) -> Result<u64, SearchError> {
    debug_assert!(length <= ROOT_RUN_WINDOW_BYTES);
    let work = u64::try_from(length).map_err(|_| SearchError::ArithmeticOverflow {
        computation: "root-run classified byte count",
    })?;
    meter.charge(work, position)?;
    let end = position
        .checked_add(length)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "root-run classified block end",
        })?;
    let source = haystack
        .get(position..end)
        .ok_or(SearchError::InternalInvariant {
            detail: "root-run classifier exceeded the validated haystack",
        })?;

    let mut members = 0_u64;
    let mut consumed = 0usize;
    while source.len().saturating_sub(consumed) >= ASCII_WIDE_BYTES {
        let block_end =
            consumed
                .checked_add(ASCII_WIDE_BYTES)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "root-run wide block end",
                })?;
        let block: &[u8; ASCII_WIDE_BYTES] = source[consumed..block_end]
            .try_into()
            .expect("checked root-run wide classifier extent");
        members |= u64::from(classifier.classify_32(block).member_mask())
            .checked_shl(u32::try_from(consumed).expect("root-run offset fits u32"))
            .unwrap_or(0);
        consumed = block_end;
    }
    if source.len().saturating_sub(consumed) >= ASCII_NARROW_BYTES {
        let block_end =
            consumed
                .checked_add(ASCII_NARROW_BYTES)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "root-run narrow block end",
                })?;
        let block: &[u8; ASCII_NARROW_BYTES] = source[consumed..block_end]
            .try_into()
            .expect("checked root-run narrow classifier extent");
        members |= u64::from(classifier.classify_16(block).member_mask())
            .checked_shl(u32::try_from(consumed).expect("root-run offset fits u32"))
            .unwrap_or(0);
        consumed = block_end;
    }
    for (lane, &byte) in source[consumed..].iter().enumerate() {
        if classifier.set().contains(byte) {
            let bit = consumed
                .checked_add(lane)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "root-run scalar lane",
                })?;
            members |= 1_u64
                .checked_shl(u32::try_from(bit).expect("root-run bit fits u32"))
                .unwrap_or(0);
        }
    }
    Ok(members)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the cursor transaction keeps source, proof, window, and meter capabilities explicit"
)]
fn try_initialize_root_run_block(
    cursor: &mut RootRunBlockCursor,
    automaton_identity: u64,
    descriptor: RootRunDescriptor,
    classifier: &AsciiByteSetClassifier,
    haystack: &[u8],
    base: usize,
    end: usize,
    meter: &mut WorkMeter,
) -> Result<bool, SearchError> {
    let available = end.saturating_sub(base).min(ROOT_RUN_WINDOW_BYTES);
    let work = u64::try_from(available).map_err(|_| SearchError::ArithmeticOverflow {
        computation: "root-run initial block work",
    })?;
    if available == 0 || meter.remaining() < work {
        return Ok(false);
    }
    let membership = classify_root_run_members(classifier, haystack, base, available, meter)?;
    let current = u32::try_from(membership & u64::from(u32::MAX))
        .expect("the current root-run half is explicitly masked");
    let lookahead = u32::try_from(membership >> 32).expect("the root-run lookahead half fits u32");
    let members = root_corridor_member_window(current, lookahead);
    *cursor = RootRunBlockCursor {
        automaton_identity,
        base,
        members,
        valid_bytes: u8::try_from(available).expect("root-run block has at most 64 bytes"),
        qualified_starts: qualifying_start_mask(members, descriptor.minimum()),
        activation_at: usize::MAX,
    };
    Ok(true)
}

fn try_advance_root_run_block(
    cursor: &mut RootRunBlockCursor,
    descriptor: RootRunDescriptor,
    classifier: &AsciiByteSetClassifier,
    haystack: &[u8],
    end: usize,
    meter: &mut WorkMeter,
) -> Result<bool, SearchError> {
    debug_assert_ne!(cursor.automaton_identity, 0);
    let old_base = cursor.base;
    let new_base =
        old_base
            .checked_add(ASCII_WIDE_BYTES)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "root-run residual block base",
            })?;
    let retained = usize::from(cursor.valid_bytes).saturating_sub(ASCII_WIDE_BYTES);
    let available = end.saturating_sub(new_base).min(ROOT_RUN_WINDOW_BYTES);
    if available == 0 {
        cursor.clear();
        return Ok(true);
    }
    let new_bytes = available.saturating_sub(retained);
    let work = u64::try_from(new_bytes).map_err(|_| SearchError::ArithmeticOverflow {
        computation: "root-run residual refill work",
    })?;
    if meter.remaining() < work {
        return Ok(false);
    }
    let refill_position =
        new_base
            .checked_add(retained)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "root-run residual refill position",
            })?;
    let refill =
        classify_root_run_members(classifier, haystack, refill_position, new_bytes, meter)?;
    let shift = u32::try_from(retained).expect("root-run retained width fits u32");
    let members = (cursor.members >> ASCII_WIDE_BYTES) | refill.checked_shl(shift).unwrap_or(0);
    cursor.base = new_base;
    cursor.members = members;
    cursor.valid_bytes =
        u8::try_from(available).expect("root-run residual block has at most 64 bytes");
    cursor.qualified_starts = qualifying_start_mask(members, descriptor.minimum());
    Ok(true)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the cursor transaction keeps source, proof, window, and meter capabilities explicit"
)]
fn next_root_run_cached_candidate(
    cursor: &mut RootRunBlockCursor,
    automaton_identity: u64,
    descriptor: RootRunDescriptor,
    classifier: &AsciiByteSetClassifier,
    haystack: &[u8],
    start: usize,
    end: usize,
    meter: &mut WorkMeter,
) -> Result<RootRunCachedCandidate, SearchError> {
    if cursor.automaton_identity != automaton_identity || cursor.valid_bytes == 0 {
        if cursor.automaton_identity != automaton_identity {
            cursor.clear();
        }
        return Ok(RootRunCachedCandidate::ResumeAt(start));
    }
    if start < cursor.base {
        cursor.clear();
        return Ok(RootRunCachedCandidate::ResumeAt(start));
    }

    loop {
        let block_end =
            cursor
                .base
                .checked_add(ASCII_WIDE_BYTES)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "root-run residual candidate block end",
                })?;
        if start > block_end {
            cursor.clear_members();
            return Ok(RootRunCachedCandidate::ResumeAt(start));
        }
        if start < block_end {
            let offset = start.saturating_sub(cursor.base);
            let allowed = if offset == 0 {
                u32::MAX
            } else {
                u32::MAX
                    .checked_shl(u32::try_from(offset).expect("root-run offset fits u32"))
                    .unwrap_or(0)
            };
            let minimum = usize::try_from(descriptor.minimum())
                .expect("the admitted root-run minimum fits usize");
            let qualified_end = end
                .checked_sub(minimum)
                .and_then(|last| last.checked_add(1))
                .unwrap_or(0);
            let end_lanes = qualified_end
                .saturating_sub(cursor.base)
                .min(ASCII_WIDE_BYTES);
            let within_end = if end_lanes == ASCII_WIDE_BYTES {
                u32::MAX
            } else {
                1_u32
                    .checked_shl(u32::try_from(end_lanes).expect("root-run lane count fits u32"))
                    .unwrap_or(0)
                    .wrapping_sub(1)
            };
            let mut candidates = cursor.qualified_starts & allowed & within_end;
            if candidates != 0 {
                let lane = take_first_qualified_start(&mut candidates)
                    .expect("a nonempty root-run residual has a first lane");
                let lane = usize::try_from(lane).expect("root-run candidate lane fits usize");
                return cursor
                    .base
                    .checked_add(lane)
                    .map(RootRunCachedCandidate::Candidate)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "root-run residual candidate",
                    });
            }
        }

        let resume = block_end.max(start);
        if resume >= end {
            cursor.clear();
            return Ok(RootRunCachedCandidate::Exhausted);
        }
        if !try_advance_root_run_block(cursor, descriptor, classifier, haystack, end, meter)? {
            cursor.clear_members();
            return Ok(RootRunCachedCandidate::ResumeAt(resume));
        }
        if cursor.valid_bytes == 0 {
            return Ok(RootRunCachedCandidate::Exhausted);
        }
    }
}

fn root_run_cached_member(
    cursor: &RootRunBlockCursor,
    automaton_identity: u64,
    position: usize,
) -> Option<bool> {
    if cursor.automaton_identity != automaton_identity || position < cursor.base {
        return None;
    }
    let lane = position.checked_sub(cursor.base)?;
    if lane >= usize::from(cursor.valid_bytes) {
        return None;
    }
    let lane = u32::try_from(lane).ok()?;
    Some(cursor.members & (1_u64 << lane) != 0)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the cursor transaction keeps source, proof, window, and meter capabilities explicit"
)]
fn extend_root_run_greedy(
    descriptor: RootRunDescriptor,
    classifier: &AsciiByteSetClassifier,
    automaton_identity: u64,
    cursor: &RootRunBlockCursor,
    haystack: &[u8],
    end: usize,
    start: usize,
    meter: &mut WorkMeter,
) -> Result<usize, SearchError> {
    let minimum =
        usize::try_from(descriptor.minimum()).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "root-run minimum conversion",
        })?;
    let mut position = start
        .checked_add(minimum)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "root-run minimum endpoint",
        })?;
    if !descriptor.greedy() {
        return Ok(position);
    }
    let limit = descriptor
        .maximum()
        .map(|maximum| {
            start
                .checked_add(usize::try_from(maximum).map_err(|_| {
                    SearchError::ArithmeticOverflow {
                        computation: "root-run maximum conversion",
                    }
                })?)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "root-run maximum endpoint",
                })
        })
        .transpose()?
        .unwrap_or(end)
        .min(end);

    while position < limit {
        if let Some(member) = root_run_cached_member(cursor, automaton_identity, position) {
            if !member {
                return Ok(position);
            }
            let lane = position
                .checked_sub(cursor.base)
                .ok_or(SearchError::InternalInvariant {
                    detail: "root-run cached member preceded its block",
                })?;
            let available = usize::from(cursor.valid_bytes)
                .saturating_sub(lane)
                .min(limit.saturating_sub(position));
            let lane = u32::try_from(lane).expect("root-run cached lane fits u32");
            let consecutive = usize::try_from(member_prefix_length(
                cursor.members,
                lane,
                u32::try_from(available).expect("root-run available width fits u32"),
            ))
            .expect("root-run consecutive width fits usize")
            .min(available);
            position =
                position
                    .checked_add(consecutive)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "root-run cached greedy endpoint",
                    })?;
            if consecutive < available {
                return Ok(position);
            }
            continue;
        }
        break;
    }

    let block_work = u64::try_from(ASCII_WIDE_BYTES).expect("root-run classifier width fits u64");
    while limit.saturating_sub(position) >= ASCII_WIDE_BYTES {
        meter.charge(block_work, position)?;
        let block_end =
            position
                .checked_add(ASCII_WIDE_BYTES)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "root-run greedy wide block end",
                })?;
        let block: &[u8; ASCII_WIDE_BYTES] = haystack[position..block_end]
            .try_into()
            .expect("checked root-run greedy classifier extent");
        let members = classifier.classify_32(block).member_mask();
        if members != u32::MAX {
            return position
                .checked_add(
                    usize::try_from(members.trailing_ones())
                        .expect("root-run greedy lane fits usize"),
                )
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "root-run greedy endpoint",
                });
        }
        position = block_end;
    }
    while position < limit {
        meter.charge(1, position)?;
        if !descriptor.set().contains(haystack[position]) {
            break;
        }
        position = position
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "root-run scalar greedy endpoint",
            })?;
    }
    Ok(position)
}

fn root_run_ascii_scanner(
    descriptor: RootRunDescriptor,
    proof: &StartFilterProof,
) -> Option<(&StartPositionScanner, &AsciiByteSetClassifier)> {
    if proof.force_haystack_start || proof.relaxed_nullable {
        return None;
    }
    let scanner = proof.scanner.as_ref()?;
    if scanner.offset != 0 {
        return None;
    }
    let StartScanner::AsciiSet { set, classifier } = &scanner.scanner else {
        return None;
    };
    let [low, high] = descriptor.set().words();
    (*set == ByteSet::from_words([low, high, 0, 0])).then_some((scanner, classifier.classifier()))
}

#[cold]
#[inline(never)]
fn root_run_descriptor_has_ascii_scanner(descriptor: RootRunDescriptor) -> (bool, u64) {
    let [low, high] = descriptor.set().words();
    let bits = u128::from(low) | (u128::from(high) << u64::BITS);
    if usize::try_from(bits.count_ones()).expect("byte cardinality fits usize")
        <= BYTE_START_SMALL_MAX_MEMBERS
    {
        return (
            false,
            u64::try_from(BYTE_START_BITMAP_POPULATION_WORK)
                .expect("byte population work fits u64"),
        );
    }

    // For nonzero `bits`, adding its lowest member bit carries through exactly
    // the lowest contiguous run. Any overlap with the original bitmap
    // therefore proves that another, disjoint run remains.
    let after_lowest_run = bits.wrapping_add(bits & bits.wrapping_neg());
    (
        bits & after_lowest_run != 0,
        u64::try_from(ROOT_RUN_SCANNER_SHAPE_MAX_WORK)
            .expect("root-run scanner-shape work fits u64"),
    )
}

fn root_run_cursor_can_resume(
    cursor: &RootRunBlockCursor,
    automaton_identity: u64,
    position: usize,
) -> bool {
    cursor.automaton_identity == automaton_identity
        && cursor.valid_bytes != 0
        && position >= cursor.base
        && position <= cursor.base.saturating_add(ASCII_WIDE_BYTES)
}

#[inline(never)]
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "one non-inlined executor keeps the authenticated corridor transaction together"
)]
fn execute_root_run_corridor(
    automaton: &Automaton,
    descriptor: RootRunDescriptor,
    scanner: &StartPositionScanner,
    classifier: &AsciiByteSetClassifier,
    haystack: &[u8],
    window: SearchWindow,
    cursor: &mut RootRunBlockCursor,
    meter: &mut WorkMeter,
) -> Result<(Option<MatchSpan>, usize), SearchError> {
    debug_assert_eq!(scanner.offset, 0);
    debug_assert!(descriptor.minimum() > 0);
    debug_assert!(descriptor.minimum() <= ROOT_CORRIDOR_MASK_MAXIMUM_MINIMUM);
    let automaton_identity = automaton.identity();
    if cursor.automaton_identity != automaton_identity {
        cursor.clear();
    }

    let minimum =
        usize::try_from(descriptor.minimum()).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "root-run minimum conversion",
        })?;
    let mut search = window.start();
    let mut boundaries = 0usize;
    loop {
        let cached = next_root_run_cached_candidate(
            cursor,
            automaton_identity,
            descriptor,
            classifier,
            haystack,
            search,
            window.end(),
            meter,
        )?;
        let (candidate, qualified) = match cached {
            RootRunCachedCandidate::Candidate(candidate) => (candidate, true),
            RootRunCachedCandidate::Exhausted => return Ok((None, boundaries)),
            RootRunCachedCandidate::ResumeAt(resume) => {
                search = resume;
                // Keep the mature 32-byte ASCII absence path unchanged. A
                // source enters the corridor classifier only after this exact
                // scanner has produced a real member candidate.
                let candidate =
                    next_start_candidate(scanner, haystack, search, window.end(), None, meter)?;
                if candidate == window.end() {
                    cursor.clear();
                    return Ok((None, boundaries));
                }
                let activate = cursor.automaton_identity == automaton_identity
                    && cursor.activation_at == candidate;
                cursor.activation_at = usize::MAX;
                if activate
                    && try_initialize_root_run_block(
                        cursor,
                        automaton_identity,
                        descriptor,
                        classifier,
                        haystack,
                        candidate,
                        window.end(),
                        meter,
                    )?
                {
                    search = candidate;
                    continue;
                }
                (candidate, false)
            }
        };
        boundaries = boundaries
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "root-run candidate boundary count",
            })?;

        if !qualified {
            let required_end =
                candidate
                    .checked_add(minimum)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "root-run required endpoint",
                    })?;
            if required_end > window.end() {
                return Ok((None, boundaries));
            }
            let mut position = candidate
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "root-run scalar validation position",
                })?;
            let mut rejected_at = None;
            while position < required_end {
                meter.charge(1, position)?;
                if !descriptor.set().contains(haystack[position]) {
                    rejected_at = Some(position);
                    break;
                }
                position = position
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "root-run scalar validation position",
                    })?;
            }
            if let Some(rejected_at) = rejected_at {
                search = rejected_at
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "root-run rejected-candidate resume",
                    })?;
                // Do not probe an isolated sparse path. Arm one exact
                // position; only a later candidate already confirmed by the
                // mature scanner may activate broad corridor classification.
                cursor.arm(automaton_identity, search);
                continue;
            }
        }

        let endpoint = extend_root_run_greedy(
            descriptor,
            classifier,
            automaton_identity,
            cursor,
            haystack,
            window.end(),
            candidate,
            meter,
        )?;

        // Defer dense iteration activation until the next call's mature
        // scanner has independently confirmed that the exact non-overlapping
        // endpoint is a member. Isolated matches add no speculative read.
        if endpoint < window.end()
            && !root_run_cursor_can_resume(cursor, automaton_identity, endpoint)
        {
            cursor.arm(automaton_identity, endpoint);
        }
        return Ok((Some(MatchSpan::new(candidate, endpoint)), boundaries));
    }
}

fn prepare_invocation(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    window: SearchWindow,
    limits: SearchLimits,
    setup: &mut SetupAccounting,
    may_use_lazy: bool,
    may_use_reverse: bool,
) -> Result<(WorkMeter, u64), SearchError> {
    let required_layout = WorkspaceLayout::for_automaton(automaton)?;
    if required_layout.states != workspace.layout.states
        || required_layout.edges != workspace.layout.edges
        || required_layout.zero_width_edges != workspace.layout.zero_width_edges
        || required_layout.closure_slots != workspace.layout.closure_slots
    {
        return Err(SearchError::WorkspaceLayoutMismatch {
            required_states: required_layout.states,
            actual_states: workspace.layout.states,
            required_edges: required_layout.edges,
            actual_edges: workspace.layout.edges,
            required_zero_width_edges: required_layout.zero_width_edges,
            actual_zero_width_edges: workspace.layout.zero_width_edges,
        });
    }

    prepare_bound_invocation(
        automaton,
        workspace,
        window,
        limits,
        setup,
        may_use_lazy,
        may_use_reverse,
    )
}

fn prepare_bound_invocation(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    window: SearchWindow,
    limits: SearchLimits,
    setup: &mut SetupAccounting,
    may_use_lazy: bool,
    may_use_reverse: bool,
) -> Result<(WorkMeter, u64), SearchError> {
    if workspace.retained_bytes > limits.max_scratch_bytes {
        return Err(SearchError::ResourceLimit {
            resource: ResourceKind::ScratchBytes,
            needed: workspace.retained_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if setup.work > limits.max_work {
        return Err(SearchError::WorkLimitExceeded {
            limit: limits.max_work,
            consumed: 0,
            requested: setup.work,
            position: window.start(),
        });
    }
    prepare_prevalidated_invocation(
        automaton,
        workspace,
        window,
        limits,
        setup,
        may_use_lazy,
        may_use_reverse,
    )
}

fn prepare_span_cursor(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    limits: SearchLimits,
) -> Result<SpanCursorCache, SearchError> {
    let binding = SpanCursorBinding {
        automaton_identity: automaton.identity(),
        limits,
    };
    if workspace.span_cursor.binding == Some(binding) {
        if workspace.span_cursor.start_proof == SpanCursorStartProof::Unprepared {
            workspace.span_cursor.start_proof = retained_span_cursor_start_proof(automaton);
        }
        return Ok(workspace.span_cursor);
    }

    let required_layout = WorkspaceLayout::for_automaton(automaton)?;
    if required_layout.states != workspace.layout.states
        || required_layout.edges != workspace.layout.edges
        || required_layout.zero_width_edges != workspace.layout.zero_width_edges
        || required_layout.closure_slots != workspace.layout.closure_slots
    {
        return Err(SearchError::WorkspaceLayoutMismatch {
            required_states: required_layout.states,
            actual_states: workspace.layout.states,
            required_edges: required_layout.edges,
            actual_edges: workspace.layout.edges,
            required_zero_width_edges: required_layout.zero_width_edges,
            actual_zero_width_edges: workspace.layout.zero_width_edges,
        });
    }
    if workspace.retained_bytes > limits.max_scratch_bytes {
        return Err(SearchError::ResourceLimit {
            resource: ResourceKind::ScratchBytes,
            needed: workspace.retained_bytes,
            limit: limits.max_scratch_bytes,
        });
    }

    let cursor = SpanCursorCache {
        binding: Some(binding),
        start_proof: retained_span_cursor_start_proof(automaton),
        capabilities: lazy_capabilities(automaton, workspace, true, true),
    };
    workspace.span_cursor = cursor;
    Ok(cursor)
}

fn retained_span_cursor_start_proof(automaton: &Automaton) -> SpanCursorStartProof {
    if automaton.start_filter_proof.get().is_some() {
        SpanCursorStartProof::AutomatonOwned
    } else if automaton.start_filter_proof.allocation_failed() {
        SpanCursorStartProof::Ordinary
    } else {
        SpanCursorStartProof::Unprepared
    }
}

fn prepare_prevalidated_invocation(
    automaton: &Automaton,
    workspace: &mut K0Workspace,
    window: SearchWindow,
    limits: SearchLimits,
    setup: &mut SetupAccounting,
    may_use_lazy: bool,
    may_use_reverse: bool,
) -> Result<(WorkMeter, u64), SearchError> {
    let window_bytes = window.end().saturating_sub(window.start());
    let required_generations = if window_bytes <= GENERATION_FAST_WINDOW_MAX
        && workspace.generation <= u64::MAX - GENERATION_FAST_RESERVE
    {
        GENERATION_FAST_RESERVE
    } else {
        required_generation_count(automaton, window, may_use_lazy, may_use_reverse)?
    };
    let mut meter = WorkMeter::new(limits.max_work, setup.work);
    workspace.begin_invocation(required_generations, &mut meter, setup, window.start())?;
    let setup_work = meter.consumed;
    Ok((meter, setup_work))
}

fn required_generation_count(
    automaton: &Automaton,
    window: SearchWindow,
    may_use_lazy: bool,
    may_use_reverse: bool,
) -> Result<u64, SearchError> {
    let bytes =
        window
            .end()
            .checked_sub(window.start())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "required boundary generations",
            })?;

    // Base execution has one closure at the initial boundary and at most one
    // after each admitted byte. Cold start-filter derivation can precede it
    // with one generation for each exact proof position.
    let mut required = bytes
        .checked_add(1)
        .and_then(|count| count.checked_add(START_FILTER_POSITION_COUNT))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "required boundary generations",
        })?;

    if may_use_lazy {
        // Direct lazy execution adds only its immutable initial closure; its
        // per-byte transition closures are already covered by `bytes` above.
        // Contextual execution may additionally rebuild an initial closure
        // after every scanner-selected candidate, for at most bytes + 1
        // source boundaries.
        let forward_initials = if automaton.stats().assertion_edges() == 0 {
            1
        } else {
            bytes
                .checked_add(1)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "required boundary generations",
                })?
        };
        required =
            required
                .checked_add(forward_initials)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: "required boundary generations",
                })?;
    }

    if may_use_reverse {
        // Reverse recovery has one Accept-seeded initial closure and at most
        // one closure per source byte. A cold direct nullable call may reserve
        // this and then discover a pending forward initial state; a warm call
        // derives `may_use_reverse = false` and omits the reserve.
        required = required
            .checked_add(
                bytes
                    .checked_add(1)
                    .ok_or(SearchError::ArithmeticOverflow {
                        computation: "required boundary generations",
                    })?,
            )
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "required boundary generations",
            })?;
    }

    u64::try_from(required).map_err(|_| SearchError::ArithmeticOverflow {
        computation: "required boundary generation conversion",
    })
}

fn expand_boundary_roots(
    automaton: &Automaton,
    haystack: &[u8],
    position: usize,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
    pending: &mut Option<MatchSpan>,
) -> Result<(), SearchError> {
    let root_count = workspace.roots_len;
    let mut root_index = 0usize;
    while root_index < root_count {
        let root = workspace.roots[root_index];
        if let Some(found) = expand_root(automaton, haystack, position, root, workspace, meter)? {
            *pending = Some(found);
            break;
        }
        root_index = root_index
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "next-boundary root index",
            })?;
    }
    workspace.roots_len = 0;

    // A new start is lower priority than every still-live earlier start. Once
    // any match is pending, later starts can never win.
    if pending.is_none() {
        *pending = expand_root(
            automaton,
            haystack,
            position,
            Thread {
                state: automaton.start,
                start: position,
            },
            workspace,
            meter,
        )?;
    }
    Ok(())
}

fn consume_current(
    automaton: &Automaton,
    byte: u8,
    position: usize,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
) -> Result<(), SearchError> {
    meter.charge(1, position)?;
    let current_len = workspace.current_len;
    for index in 0..current_len {
        let thread = workspace.current[index];
        for edge in automaton.state_edges(thread.state) {
            meter.charge(1, position)?;
            debug_assert_eq!(automaton.edge_kinds[edge], EdgeKind::ByteRange);
            if automaton.byte_starts[edge] <= byte && byte <= automaton.byte_ends[edge] {
                workspace.push_root(Thread {
                    state: automaton.edge_targets[edge],
                    start: thread.start,
                })?;
            }
        }
    }
    Ok(())
}

fn validate_window(haystack: &[u8], window: SearchWindow) -> Result<(), SearchError> {
    if window.start() > window.end() || window.end() > haystack.len() {
        return Err(SearchError::InvalidWindow {
            start: window.start(),
            end: window.end(),
            haystack_len: haystack.len(),
        });
    }
    Ok(())
}

fn expand_root(
    automaton: &Automaton,
    haystack: &[u8],
    position: usize,
    root: Thread,
    workspace: &mut K0Workspace,
    meter: &mut WorkMeter,
) -> Result<Option<MatchSpan>, SearchError> {
    if position > haystack.len() {
        return Err(SearchError::InternalInvariant {
            detail: "assertion position exceeded original haystack",
        });
    }
    workspace.stack_len = 0;
    workspace.push_stack(root)?;

    while let Some(thread) = workspace.pop_stack() {
        meter.charge(1, position)?;
        let state = crate::plan::plan_index(thread.state);
        if workspace.seen_at[state] == workspace.generation {
            continue;
        }
        workspace.seen_at[state] = workspace.generation;

        match automaton.roles[state] {
            StateRole::Accept => return Ok(Some(MatchSpan::new(thread.start, position))),
            StateRole::Consume => workspace.push_current(thread)?,
            StateRole::Split => {
                // Reverse push produces forward edge order under a LIFO stack.
                for edge in automaton.state_edges(thread.state).rev() {
                    meter.charge(1, position)?;
                    let enabled = zero_width_edge_enabled(
                        automaton,
                        automaton.edge_kinds[edge],
                        haystack,
                        position,
                    )?;
                    if enabled {
                        workspace.push_stack(Thread {
                            state: automaton.edge_targets[edge],
                            start: thread.start,
                        })?;
                    }
                }
            }
        }
    }
    Ok(None)
}

pub(crate) fn zero_width_edge_enabled(
    automaton: &Automaton,
    kind: EdgeKind,
    haystack: &[u8],
    position: usize,
) -> Result<bool, SearchError> {
    zero_width_edge_enabled_with_line_terminator(
        automaton.line_terminator(),
        kind,
        haystack,
        position,
    )
}

fn enabled_assertion_mask(
    automaton: &Automaton,
    haystack: &[u8],
    position: usize,
    meter: &mut WorkMeter,
) -> Result<u32, SearchError> {
    enabled_assertion_mask_with_classifier(
        automaton.boundary_context_classifier(),
        automaton.line_terminator(),
        haystack,
        position,
        meter,
    )
}

fn enabled_assertion_mask_with_classifier(
    classifier: BoundaryContextClassifier,
    line_terminator: u8,
    haystack: &[u8],
    position: usize,
    meter: &mut WorkMeter,
) -> Result<u32, SearchError> {
    debug_assert!(position <= haystack.len());
    let checks = u64::from(classifier.assertions().count_ones());
    if checks <= meter.remaining() {
        meter.charge_admitted(checks);
    } else {
        // Preserve the canonical evaluator's one-unit failure report and the
        // exact amount consumed before a finite limit rejects this boundary.
        for _ in 0..checks {
            meter.charge(1, position)?;
        }
    }

    let mut enabled = 0_u32;
    let absolute = classifier.absolute();
    if absolute != 0 {
        let class = binary_boundary_class(position == 0, position == haystack.len());
        enabled |= ABSOLUTE_ENABLED_BY_CLASS[class] & absolute;
    }

    let configured_line = classifier.configured_line();
    let crlf_line = classifier.crlf_line();
    let ascii_word = classifier.ascii_word();
    let byte_context_used = configured_line | crlf_line | ascii_word != 0;
    let (before, after) = if byte_context_used {
        (
            position
                .checked_sub(1)
                .and_then(|index| haystack.get(index))
                .copied(),
            haystack.get(position).copied(),
        )
    } else {
        (None, None)
    };

    if configured_line != 0 {
        let class = binary_boundary_class(
            position == 0 || before == Some(line_terminator),
            position == haystack.len() || after == Some(line_terminator),
        );
        enabled |= CONFIGURED_LINE_ENABLED_BY_CLASS[class] & configured_line;
    }
    if crlf_line != 0 {
        let class = binary_boundary_class(
            position == 0 || before == Some(b'\n') || before == Some(b'\r') && after != Some(b'\n'),
            position == haystack.len()
                || after == Some(b'\r')
                || after == Some(b'\n') && before != Some(b'\r'),
        );
        enabled |= CRLF_LINE_ENABLED_BY_CLASS[class] & crlf_line;
    }
    if ascii_word != 0 {
        let class = binary_boundary_class(
            before.is_some_and(is_ascii_word),
            after.is_some_and(is_ascii_word),
        );
        enabled |= ASCII_WORD_ENABLED_BY_CLASS[class] & ascii_word;
    }

    let unicode_word = classifier.unicode_word();
    if unicode_word != 0 {
        let class = UnicodeLookMatcher::classify_prevalidated(haystack, position).class();
        enabled |= UNICODE_WORD_ENABLED_BY_CLASS[class] & unicode_word;
    }
    Ok(enabled)
}

const fn binary_boundary_class(left: bool, right: bool) -> usize {
    let left = if left { 1 } else { 0 };
    let right = if right { 1 } else { 0 };
    left | (right << 1)
}

fn assertion_enabled(kind: EdgeKind, enabled: u32) -> Result<bool, SearchError> {
    if kind == EdgeKind::Epsilon {
        return Ok(true);
    }
    let bit = kind.assertion_bit().ok_or(SearchError::InternalInvariant {
        detail: "contextual closure reached a consuming split edge",
    })?;
    Ok(enabled & bit != 0)
}

pub(crate) fn zero_width_edge_enabled_with_line_terminator(
    line_terminator: u8,
    kind: EdgeKind,
    haystack: &[u8],
    position: usize,
) -> Result<bool, SearchError> {
    match kind {
        EdgeKind::Epsilon => Ok(true),
        EdgeKind::AssertHaystackStart => Ok(position == 0),
        EdgeKind::AssertHaystackEnd => Ok(position == haystack.len()),
        EdgeKind::AssertLineStartLf => Ok(position == 0
            || position
                .checked_sub(1)
                .and_then(|index| haystack.get(index))
                .is_some_and(|&byte| byte == line_terminator)),
        EdgeKind::AssertLineEndLf => {
            Ok(position == haystack.len() || haystack.get(position) == Some(&line_terminator))
        }
        EdgeKind::AssertLineStartCrlf => {
            let before = position
                .checked_sub(1)
                .and_then(|index| haystack.get(index));
            let after = haystack.get(position);
            Ok(position == 0
                || before == Some(&b'\n')
                || (before == Some(&b'\r') && after != Some(&b'\n')))
        }
        EdgeKind::AssertLineEndCrlf => {
            let before = position
                .checked_sub(1)
                .and_then(|index| haystack.get(index));
            let after = haystack.get(position);
            Ok(position == haystack.len()
                || after == Some(&b'\r')
                || (after == Some(&b'\n') && before != Some(&b'\r')))
        }
        EdgeKind::AssertWordAscii
        | EdgeKind::AssertWordAsciiNegate
        | EdgeKind::AssertWordStartAscii
        | EdgeKind::AssertWordEndAscii
        | EdgeKind::AssertWordStartHalfAscii
        | EdgeKind::AssertWordEndHalfAscii => {
            let word_before = position
                .checked_sub(1)
                .and_then(|index| haystack.get(index))
                .is_some_and(|&byte| is_ascii_word(byte));
            let word_after = haystack
                .get(position)
                .is_some_and(|&byte| is_ascii_word(byte));
            Ok(match kind {
                EdgeKind::AssertWordAscii => word_before != word_after,
                EdgeKind::AssertWordAsciiNegate => word_before == word_after,
                EdgeKind::AssertWordStartAscii => !word_before && word_after,
                EdgeKind::AssertWordEndAscii => word_before && !word_after,
                EdgeKind::AssertWordStartHalfAscii => !word_before,
                EdgeKind::AssertWordEndHalfAscii => !word_after,
                _ => {
                    return Err(SearchError::InternalInvariant {
                        detail: "word assertion dispatch changed variants",
                    });
                }
            })
        }
        kind @ (EdgeKind::AssertWordUnicode
        | EdgeKind::AssertWordUnicodeNegate
        | EdgeKind::AssertWordStartUnicode
        | EdgeKind::AssertWordEndUnicode
        | EdgeKind::AssertWordStartHalfUnicode
        | EdgeKind::AssertWordEndHalfUnicode) => {
            unicode_assertion_matches(kind, haystack, position)
        }
        EdgeKind::ByteRange => Err(SearchError::InternalInvariant {
            detail: "split state contained a consuming edge",
        }),
    }
}

fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn unicode_assertion_matches(
    kind: EdgeKind,
    haystack: &[u8],
    position: usize,
) -> Result<bool, SearchError> {
    let look = match kind {
        EdgeKind::AssertWordUnicode => regex_syntax::hir::Look::WordUnicode,
        EdgeKind::AssertWordUnicodeNegate => regex_syntax::hir::Look::WordUnicodeNegate,
        EdgeKind::AssertWordStartUnicode => regex_syntax::hir::Look::WordStartUnicode,
        EdgeKind::AssertWordEndUnicode => regex_syntax::hir::Look::WordEndUnicode,
        EdgeKind::AssertWordStartHalfUnicode => regex_syntax::hir::Look::WordStartHalfUnicode,
        EdgeKind::AssertWordEndHalfUnicode => regex_syntax::hir::Look::WordEndHalfUnicode,
        _ => {
            return Err(SearchError::InternalInvariant {
                detail: "non-Unicode edge in Unicode assertion dispatch",
            });
        }
    };
    Ok(UnicodeLookMatcher::matches_prevalidated(
        look, haystack, position,
    ))
}

fn lazy_capacities(automaton: &Automaton) -> Result<(usize, usize), SearchError> {
    let states = automaton.stats().states();
    if states == 0 || states > LAZY_MAX_ITEMS {
        return Ok((0, 0));
    }
    let consuming = automaton.stats().consuming_states();
    let state_capacity = forward_lazy_state_capacity(consuming);
    let item_capacity = ordered_partial_permutation_item_capacity(
        consuming,
        2,
        state_capacity,
        "lazy DFA item capacity",
    )?;
    Ok((state_capacity, item_capacity))
}

fn reverse_capacities(automaton: &Automaton) -> Result<(usize, usize), SearchError> {
    let consuming = automaton.stats().consuming_edges();
    if consuming == 0 || consuming > LAZY_MAX_ITEMS {
        return Ok((0, 0));
    }
    let state_capacity =
        reverse_lazy_state_capacity(consuming, automaton.stats().assertion_edges() != 0);
    let item_capacity = ordered_partial_permutation_item_capacity(
        consuming,
        1,
        state_capacity,
        "reverse lazy DFA item capacity",
    )?;
    Ok((state_capacity, item_capacity))
}

/// Count distinct ordered nonempty subsets, capped at the retained row limit.
///
/// A closure generation admits each item at most once, but forward priority
/// makes different orders distinct cache states. `modes` accounts for state
/// identity outside the item sequence, while `empty_modes` admits only the
/// semantically reachable empty identities.
fn capped_ordered_partial_permutations(items: usize, modes: usize, empty_modes: usize) -> usize {
    let mut total = empty_modes.min(LAZY_MAX_STATES);
    let mut permutations = 1usize;
    let mut length = 1usize;
    while length <= items && total < LAZY_MAX_STATES {
        let prior = length.saturating_sub(1);
        let remaining = items.saturating_sub(prior);
        permutations = permutations.saturating_mul(remaining).min(LAZY_MAX_STATES);
        total = total
            .saturating_add(permutations.saturating_mul(modes))
            .min(LAZY_MAX_STATES);
        length = length.saturating_add(1);
    }
    total
}

fn forward_lazy_state_capacity(consuming_states: usize) -> usize {
    // Nonempty ordered subsets exist in both pending modes. Exactly one empty
    // identity is retainable: the pending nullable initial state in a direct
    // graph, or the nonpending restart state in a contextual graph.
    capped_ordered_partial_permutations(consuming_states, 2, 1)
}

fn reverse_lazy_state_capacity(consuming_edges: usize, contextual: bool) -> usize {
    if consuming_edges == 0 {
        return 0;
    }
    // Reverse state identity is only its consuming-edge sequence. Contextual
    // initialization can additionally retain one empty sequence when the
    // current assertion mask disconnects every consuming predecessor.
    capped_ordered_partial_permutations(consuming_edges, 1, usize::from(contextual))
}

/// Maximum aggregate item length of any retained set of distinct identities.
///
/// Enumerate each length exactly, retaining the longest identities first.
/// Products are capped at the bounded state domain: once a layer supplies all
/// remaining identities, larger factorial values cannot affect the arena.
fn ordered_partial_permutation_item_capacity(
    items: usize,
    modes: usize,
    state_capacity: usize,
    structure: &'static str,
) -> Result<usize, SearchError> {
    let mut remaining_states = state_capacity;
    let mut item_capacity = 0usize;
    let mut length = items;
    while length != 0 && remaining_states != 0 {
        let mut permutations = 1usize;
        for ordinal in 0..length {
            let factor = items
                .checked_sub(ordinal)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: structure,
                })?;
            permutations = permutations.saturating_mul(factor).min(state_capacity);
        }
        let identities = permutations.saturating_mul(modes).min(state_capacity);
        let selected = identities.min(remaining_states);
        item_capacity = selected
            .checked_mul(length)
            .and_then(|items| item_capacity.checked_add(items))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: structure,
            })?;
        remaining_states =
            remaining_states
                .checked_sub(selected)
                .ok_or(SearchError::ArithmeticOverflow {
                    computation: structure,
                })?;
        length = length
            .checked_sub(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: structure,
            })?;
    }
    Ok(item_capacity.min(LAZY_MAX_ITEMS))
}

fn lazy_initialized_slots(
    states: usize,
    state_capacity: usize,
    item_capacity: usize,
    context_slots: usize,
) -> Result<usize, SearchError> {
    if state_capacity == 0 {
        return Ok(0);
    }
    let rows = if context_slots == 0 {
        state_capacity
            .checked_mul(BYTE_ALPHABET)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA initialized row slots",
            })?
    } else {
        0
    };
    states
        .checked_mul(2)
        .and_then(|slots| slots.checked_add(rows))
        .and_then(|slots| slots.checked_add(context_slots))
        .and_then(|slots| slots.checked_add(state_capacity))
        .and_then(|slots| slots.checked_add(state_capacity))
        .and_then(|slots| slots.checked_add(state_capacity))
        .and_then(|slots| slots.checked_add(state_capacity))
        .and_then(|slots| slots.checked_add(item_capacity))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "lazy DFA initialized slots",
        })
}

fn lazy_scratch_bytes(
    states: usize,
    state_capacity: usize,
    item_capacity: usize,
    context_slots: usize,
) -> Result<usize, SearchError> {
    if state_capacity == 0 {
        return Ok(0);
    }
    let rows = if context_slots == 0 {
        state_capacity
            .checked_mul(BYTE_ALPHABET)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA row cells",
            })?
    } else {
        0
    };
    let state_u32s = states
        .checked_mul(2)
        .and_then(|slots| slots.checked_add(rows))
        .and_then(|slots| slots.checked_add(state_capacity))
        .and_then(|slots| slots.checked_add(item_capacity))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "lazy DFA u32 slots",
        })?;
    let u32_bytes =
        state_u32s
            .checked_mul(size_of::<u32>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA u32 bytes",
            })?;
    let offsets =
        state_capacity
            .checked_mul(size_of::<usize>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA offset bytes",
            })?;
    let modes = state_capacity;
    let hashes =
        state_capacity
            .checked_mul(size_of::<u64>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "lazy DFA hash bytes",
            })?;
    let context_bytes = context_slots
        .checked_mul(size_of::<ContextTransitionSlot>())
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "lazy DFA contextual transition bytes",
        })?;
    u32_bytes
        .checked_add(offsets)
        .and_then(|bytes| bytes.checked_add(modes))
        .and_then(|bytes| bytes.checked_add(hashes))
        .and_then(|bytes| bytes.checked_add(context_bytes))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "lazy DFA scratch bytes",
        })
}

fn reverse_initialized_slots(
    states: usize,
    edges: usize,
    state_capacity: usize,
    item_capacity: usize,
    context_slots: usize,
) -> Result<usize, SearchError> {
    if state_capacity == 0 {
        return Ok(0);
    }
    let rows = if context_slots == 0 {
        state_capacity
            .checked_mul(BYTE_ALPHABET)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse lazy DFA initialized row slots",
            })?
    } else {
        0
    };
    states
        .checked_add(1)
        .and_then(|slots| {
            edges
                .checked_mul(3)
                .and_then(|edges| slots.checked_add(edges))
        })
        .and_then(|slots| {
            edges
                .checked_mul(2)
                .and_then(|edges| slots.checked_add(edges))
        })
        .and_then(|slots| slots.checked_add(if context_slots == 0 { 0 } else { edges }))
        .and_then(|slots| slots.checked_add(rows))
        .and_then(|slots| slots.checked_add(context_slots))
        .and_then(|slots| {
            state_capacity
                .checked_mul(3)
                .and_then(|meta| slots.checked_add(meta))
        })
        .and_then(|slots| slots.checked_add(item_capacity))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "reverse lazy DFA initialized slots",
        })
}

fn reverse_scratch_bytes(
    states: usize,
    edges: usize,
    state_capacity: usize,
    item_capacity: usize,
    context_slots: usize,
) -> Result<usize, SearchError> {
    if state_capacity == 0 {
        return Ok(0);
    }
    let rows = if context_slots == 0 {
        state_capacity
            .checked_mul(BYTE_ALPHABET)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse lazy DFA row cells",
            })?
    } else {
        0
    };
    let u32_slots = states
        .checked_add(1)
        .and_then(|slots| slots.checked_add(edges))
        .and_then(|slots| {
            edges
                .checked_mul(2)
                .and_then(|edges| slots.checked_add(edges))
        })
        .and_then(|slots| slots.checked_add(rows))
        .and_then(|slots| slots.checked_add(state_capacity))
        .and_then(|slots| slots.checked_add(item_capacity))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "reverse lazy DFA u32 slots",
        })?;
    let u32_bytes =
        u32_slots
            .checked_mul(size_of::<u32>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse lazy DFA u32 bytes",
            })?;
    let range_bytes = edges
        .checked_mul(2)
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "reverse CSR range bytes",
        })?;
    let kind_bytes = if context_slots == 0 {
        0
    } else {
        edges
            .checked_mul(size_of::<EdgeKind>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse CSR kind bytes",
            })?
    };
    let offsets =
        state_capacity
            .checked_mul(size_of::<usize>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse lazy DFA offset bytes",
            })?;
    let hashes =
        state_capacity
            .checked_mul(size_of::<u64>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "reverse lazy DFA hash bytes",
            })?;
    let context_bytes = context_slots
        .checked_mul(size_of::<ContextTransitionSlot>())
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "reverse contextual transition bytes",
        })?;
    u32_bytes
        .checked_add(range_bytes)
        .and_then(|bytes| bytes.checked_add(kind_bytes))
        .and_then(|bytes| bytes.checked_add(offsets))
        .and_then(|bytes| bytes.checked_add(hashes))
        .and_then(|bytes| bytes.checked_add(context_bytes))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "reverse lazy DFA scratch bytes",
        })
}

fn lazy_hash(items: &[u32], pending: bool) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ u64::from(pending);
    for &item in items {
        hash ^= u64::from(item);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn scratch_bytes(states: usize, edges: usize, stack: usize) -> Result<usize, SearchError> {
    let seen = states
        .checked_mul(size_of::<u64>())
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "seen scratch bytes",
        })?;
    let current =
        states
            .checked_mul(size_of::<Thread>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "current-thread scratch bytes",
            })?;
    let roots = edges
        .checked_mul(size_of::<Thread>())
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "root scratch bytes",
        })?;
    let closure =
        stack
            .checked_mul(size_of::<Thread>())
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "closure-stack scratch bytes",
            })?;
    seen.checked_add(current)
        .and_then(|value| value.checked_add(roots))
        .and_then(|value| value.checked_add(closure))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "total scratch bytes",
        })
}

fn allocate_slots<T: Copy>(
    length: usize,
    value: T,
    total_bytes: usize,
) -> Result<Vec<T>, SearchError> {
    let mut vector = Vec::new();
    vector
        .try_reserve_exact(length)
        .map_err(|_| SearchError::ScratchAllocationFailed {
            requested: total_bytes,
        })?;
    vector.resize(length, value);
    Ok(vector)
}

fn retained_bytes(
    seen_at: &Vec<u64>,
    current: &Vec<Thread>,
    roots: &Vec<Thread>,
    stack: &Vec<Thread>,
    lazy: &LazyWorkspace,
    reverse: &ReverseWorkspace,
) -> Result<usize, SearchError> {
    let seen = seen_at.capacity().checked_mul(size_of::<u64>()).ok_or(
        SearchError::ArithmeticOverflow {
            computation: "retained seen scratch bytes",
        },
    )?;
    let current = current.capacity().checked_mul(size_of::<Thread>()).ok_or(
        SearchError::ArithmeticOverflow {
            computation: "retained current scratch bytes",
        },
    )?;
    let roots = roots.capacity().checked_mul(size_of::<Thread>()).ok_or(
        SearchError::ArithmeticOverflow {
            computation: "retained root scratch bytes",
        },
    )?;
    let stack = stack.capacity().checked_mul(size_of::<Thread>()).ok_or(
        SearchError::ArithmeticOverflow {
            computation: "retained closure scratch bytes",
        },
    )?;
    let lazy = lazy.retained_bytes()?;
    let reverse = reverse.retained_bytes()?;
    seen.checked_add(current)
        .and_then(|value| value.checked_add(roots))
        .and_then(|value| value.checked_add(stack))
        .and_then(|value| value.checked_add(lazy))
        .and_then(|value| value.checked_add(reverse))
        .ok_or(SearchError::ArithmeticOverflow {
            computation: "total retained scratch bytes",
        })
}

fn capacity_bytes<T>(vector: &Vec<T>, computation: &'static str) -> Result<usize, SearchError> {
    vector
        .capacity()
        .checked_mul(size_of::<T>())
        .ok_or(SearchError::ArithmeticOverflow { computation })
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::{
        classify_byte_delta_16, scratch_bytes, ContextTransitionSlot, WorkMeter,
        ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, BYTE_SET_BLOCK_BYTES, CONTEXT_INITIAL_SOURCE,
        INVOCATION_RESET_WORK, ROOT_RUN_SCANNER_SHAPE_MAX_WORK,
    };
    use crate::{
        plan::{
            ByteSet, StartFilterProof, StartFilterProofCell, StartPositionClass,
            StartPositionFilter, StartPositionScanner, StartScanner,
            BYTE_START_ASCII_CLASSIFIER_SELECTION_WORK, BYTE_START_BITMAP_POPULATION_WORK,
            BYTE_START_MEMBER_EXTRACTION_WORK, BYTE_START_RANGE_DETECTION_WORK,
            BYTE_START_SET_CLASSIFIER_BUILD_WORK, BYTE_START_SMALL_MAX_MEMBERS,
            START_FILTER_GUARD_SELECTION_WORK, START_FILTER_MAX_OFFSET,
            START_FILTER_MAX_SELECTION_WORK, START_FILTER_POSITION_COUNT,
            START_FILTER_PROBE_SELECTION_WORK, START_FILTER_SCANNER_SELECTION_WORK,
        },
        Automaton, CompileLimits, EarliestEnd, EdgeKind, Exists, K0ResumeSet, K0SearchSession,
        K0SpanSourceCursor, K0Workspace, MatchSpan, OutputContract, RawPlan, ResourceKind,
        SearchError, SearchLimits, SearchWindow, SelectedEnd, Span, StateRole, WorkspaceLimits,
    };

    fn ascii_literal(byte: u8) -> Automaton {
        ascii_root_bytes(&[byte])
    }

    fn one_below_owner_free(work: u64) -> u64 {
        work.checked_sub(super::START_FILTER_OWNER_ALLOCATION_WORK)
            .and_then(|owner_free| owner_free.checked_sub(1))
            .unwrap()
    }

    fn ascii_root_bytes(bytes: &[u8]) -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![
                    0,
                    u32::try_from(bytes.len()).expect("test root fits u32"),
                    u32::try_from(bytes.len()).expect("test root fits u32"),
                ],
                edge_targets: vec![1; bytes.len()],
                edge_kinds: vec![EdgeKind::ByteRange; bytes.len()],
                byte_starts: bytes.to_vec(),
                byte_ends: bytes.to_vec(),
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    const ROOT_RUN_TEST_SET: [u8; 4] = [b'a', b'c', b'e', b'g'];

    fn push_root_run_test_class(
        target: u32,
        edge_targets: &mut Vec<u32>,
        edge_kinds: &mut Vec<EdgeKind>,
        byte_starts: &mut Vec<u8>,
        byte_ends: &mut Vec<u8>,
    ) {
        for byte in ROOT_RUN_TEST_SET {
            edge_targets.push(target);
            edge_kinds.push(EdgeKind::ByteRange);
            byte_starts.push(byte);
            byte_ends.push(byte);
        }
    }

    fn root_run_exact(minimum: usize) -> Automaton {
        assert!(minimum > 0);
        let mut edge_targets = Vec::new();
        let mut edge_kinds = Vec::new();
        let mut byte_starts = Vec::new();
        let mut byte_ends = Vec::new();
        let mut edge_offsets = vec![0_u32];
        for state in 0..minimum {
            push_root_run_test_class(
                u32::try_from(state.checked_add(1).unwrap()).unwrap(),
                &mut edge_targets,
                &mut edge_kinds,
                &mut byte_starts,
                &mut byte_ends,
            );
            edge_offsets.push(u32::try_from(edge_targets.len()).unwrap());
        }
        edge_offsets.push(u32::try_from(edge_targets.len()).unwrap());
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: (0..minimum)
                    .map(|_| StateRole::Consume)
                    .chain(core::iter::once(StateRole::Accept))
                    .collect(),
                edge_offsets,
                edge_targets,
                edge_kinds,
                byte_starts,
                byte_ends,
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn root_run_exact_two() -> Automaton {
        root_run_exact(2)
    }

    fn root_run_finite_two_four(greedy: bool) -> Automaton {
        let mut edge_targets = Vec::new();
        let mut edge_kinds = Vec::new();
        let mut byte_starts = Vec::new();
        let mut byte_ends = Vec::new();
        let mut edge_offsets = vec![0_u32];
        for (role, class_target, split_targets) in [
            (StateRole::Consume, Some(1), None),
            (StateRole::Consume, Some(2), None),
            (
                StateRole::Split,
                None,
                Some(if greedy { [3, 4] } else { [4, 3] }),
            ),
            (StateRole::Consume, Some(4), None),
            (
                StateRole::Split,
                None,
                Some(if greedy { [5, 6] } else { [6, 5] }),
            ),
            (StateRole::Consume, Some(6), None),
            (StateRole::Accept, None, None),
        ] {
            if role == StateRole::Consume {
                push_root_run_test_class(
                    class_target.expect("consume target"),
                    &mut edge_targets,
                    &mut edge_kinds,
                    &mut byte_starts,
                    &mut byte_ends,
                );
            } else if let Some(targets) = split_targets {
                for target in targets {
                    edge_targets.push(target);
                    edge_kinds.push(EdgeKind::Epsilon);
                    byte_starts.push(0);
                    byte_ends.push(0);
                }
            }
            edge_offsets.push(u32::try_from(edge_targets.len()).expect("test graph fits u32"));
        }
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets,
                edge_targets,
                edge_kinds,
                byte_starts,
                byte_ends,
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn root_run_unbounded_two(greedy: bool) -> Automaton {
        let mut edge_targets = Vec::new();
        let mut edge_kinds = Vec::new();
        let mut byte_starts = Vec::new();
        let mut byte_ends = Vec::new();
        push_root_run_test_class(
            1,
            &mut edge_targets,
            &mut edge_kinds,
            &mut byte_starts,
            &mut byte_ends,
        );
        push_root_run_test_class(
            2,
            &mut edge_targets,
            &mut edge_kinds,
            &mut byte_starts,
            &mut byte_ends,
        );
        for target in if greedy { [1, 3] } else { [3, 1] } {
            edge_targets.push(target);
            edge_kinds.push(EdgeKind::Epsilon);
            byte_starts.push(0);
            byte_ends.push(0);
        }
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 4, 8, 10, 10],
                edge_targets,
                edge_kinds,
                byte_starts,
                byte_ends,
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn byte_chain(ranges: &[(u8, u8)]) -> Automaton {
        assert!(!ranges.is_empty());
        let edge_offset_slots = ranges
            .len()
            .checked_add(2)
            .expect("test chain offset count fits usize");
        let mut edge_offsets = Vec::with_capacity(edge_offset_slots);
        for offset in 0..=ranges.len() {
            edge_offsets.push(u32::try_from(offset).expect("test chain fits u32"));
        }
        edge_offsets.push(u32::try_from(ranges.len()).expect("test chain fits u32"));
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: (0..ranges.len())
                    .map(|_| StateRole::Consume)
                    .chain(core::iter::once(StateRole::Accept))
                    .collect(),
                edge_offsets,
                edge_targets: (1..=ranges.len())
                    .map(|target| u32::try_from(target).expect("test chain fits u32"))
                    .collect(),
                edge_kinds: vec![EdgeKind::ByteRange; ranges.len()],
                byte_starts: ranges.iter().map(|&(start, _)| start).collect(),
                byte_ends: ranges.iter().map(|&(_, end)| end).collect(),
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn byte_class_then_range(
        bytes: &[u8],
        suffix: (u8, u8),
        assertion: Option<EdgeKind>,
    ) -> Automaton {
        assert!(!bytes.is_empty());
        assert!(suffix.0 <= suffix.1);
        let class_edges = u32::try_from(bytes.len()).expect("test byte class fits u32");
        let class_edges_plus_one = class_edges.checked_add(1).unwrap();
        let class_edges_plus_two = class_edges.checked_add(2).unwrap();
        let (start, roles, edge_offsets, root_target, suffix_target) = if assertion.is_some() {
            (
                0,
                vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                vec![
                    0,
                    1,
                    class_edges_plus_one,
                    class_edges_plus_two,
                    class_edges_plus_two,
                ],
                2,
                3,
            )
        } else {
            (
                0,
                vec![StateRole::Consume, StateRole::Consume, StateRole::Accept],
                vec![0, class_edges, class_edges_plus_one, class_edges_plus_one],
                1,
                2,
            )
        };
        let capacity = bytes
            .len()
            .checked_add(usize::from(assertion.is_some()))
            .and_then(|value| value.checked_add(1))
            .unwrap();
        let mut edge_targets = Vec::with_capacity(capacity);
        let mut edge_kinds = Vec::with_capacity(edge_targets.capacity());
        let mut byte_starts = Vec::with_capacity(edge_targets.capacity());
        let mut byte_ends = Vec::with_capacity(edge_targets.capacity());
        if let Some(assertion) = assertion {
            edge_targets.push(1);
            edge_kinds.push(assertion);
            byte_starts.push(0);
            byte_ends.push(0);
        }
        for &byte in bytes {
            edge_targets.push(root_target);
            edge_kinds.push(EdgeKind::ByteRange);
            byte_starts.push(byte);
            byte_ends.push(byte);
        }
        edge_targets.push(suffix_target);
        edge_kinds.push(EdgeKind::ByteRange);
        byte_starts.push(suffix.0);
        byte_ends.push(suffix.1);

        Automaton::from_raw(
            RawPlan {
                start,
                roles,
                edge_offsets,
                edge_targets,
                edge_kinds,
                byte_starts,
                byte_ends,
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn zero_edge_consume() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 0, 0],
                edge_targets: vec![],
                edge_kinds: vec![],
                byte_starts: vec![],
                byte_ends: vec![],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_byte_or_eight_byte_chain(absolute: u8, ranges: &[(u8, u8); 8]) -> Automaton {
        let mut byte_starts = vec![0, 0, absolute];
        byte_starts.extend(ranges.iter().map(|&(start, _)| start));
        let mut byte_ends = vec![0, 0, absolute];
        byte_ends.extend(ranges.iter().map(|&(_, end)| end));
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                ],
                edge_offsets: vec![0, 2, 3, 3, 4, 5, 6, 7, 8, 9, 10, 11],
                edge_targets: vec![1, 3, 2, 4, 5, 6, 7, 8, 9, 10, 2],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts,
                byte_ends,
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn factored_q_ab_z() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 1, 3, 4, 4],
                edge_targets: vec![1, 2, 2, 3],
                edge_kinds: vec![EdgeKind::ByteRange; 4],
                byte_starts: vec![b'Q', b'a', b'b', b'Z'],
                byte_ends: vec![b'Q', b'a', b'b', b'Z'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn expanded_q_ab_z() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 5, 6, 7, 8, 8],
                edge_targets: vec![1, 4, 2, 3, 7, 5, 6, 7],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'Q', b'a', b'Z', b'Q', b'b', b'Z'],
                byte_ends: vec![0, 0, b'Q', b'a', b'Z', b'Q', b'b', b'Z'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_foo() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 1, 2, 3, 4, 4],
                edge_targets: vec![1, 2, 3, 4],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, b'f', b'o', b'o'],
                byte_ends: vec![0, b'f', b'o', b'o'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_or_colon_foo() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 5, 6, 6],
                edge_targets: vec![2, 1, 2, 3, 4, 5],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b':', b'f', b'o', b'o'],
                byte_ends: vec![0, 0, b':', b'f', b'o', b'o'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_high_byte_or_colon_a() -> Automaton {
        // (?:\A\xff|:a)
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 5, 5],
                edge_targets: vec![1, 2, 4, 3, 4],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, 0xff, b':', b'a'],
                byte_ends: vec![0, 0, 0xff, b':', b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn assertion_or_colon(assertion: EdgeKind) -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 4],
                edge_targets: vec![1, 2, 3, 3],
                edge_kinds: vec![
                    assertion,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'a', b':'],
                byte_ends: vec![0, 0, b'a', b':'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn every_assertion() -> Automaton {
        let edges = u32::try_from(super::ASSERTION_KINDS.len()).unwrap();
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Split, StateRole::Accept],
                edge_offsets: vec![0, edges, edges],
                edge_targets: vec![1; super::ASSERTION_KINDS.len()],
                edge_kinds: super::ASSERTION_KINDS.to_vec(),
                byte_starts: vec![0; super::ASSERTION_KINDS.len()],
                byte_ends: vec![0; super::ASSERTION_KINDS.len()],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn trailing_assertion_or_bang(assertion: EdgeKind) -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 1, 3, 4, 4],
                edge_targets: vec![1, 3, 2, 3],
                edge_kinds: vec![
                    EdgeKind::ByteRange,
                    assertion,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![b'a', 0, 0, b'!'],
                byte_ends: vec![b'a', 0, 0, b'!'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn asserted_line_a() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 2, 2],
                edge_targets: vec![1, 2],
                edge_kinds: vec![EdgeKind::AssertLineStartLf, EdgeKind::ByteRange],
                byte_starts: vec![0, b'a'],
                byte_ends: vec![0, b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn digit_slash_then_line_end_or_bang() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 1, 2, 4, 5, 5],
                edge_targets: vec![1, 2, 4, 3, 4],
                edge_kinds: vec![
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::AssertLineEndLf,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![b'0', b'/', 0, 0, b'!'],
                byte_ends: vec![b'9', b'/', 0, 0, b'!'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn asserted_line_three_classes() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 1, 2, 3, 4, 4],
                edge_targets: vec![1, 2, 3, 4],
                edge_kinds: vec![
                    EdgeKind::AssertLineStartLf,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, b'a', b'c', b'e'],
                byte_ends: vec![0, b'b', b'd', b'f'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_nullable_or_colon() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 2, 3, 3],
                edge_targets: vec![2, 1, 2],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b':'],
                byte_ends: vec![0, 0, b':'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_or_colon_or_unasserted_empty() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 3, 4, 4],
                edge_targets: vec![2, 1, 2, 2],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, 0, b':'],
                byte_ends: vec![0, 0, 0, b':'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn absolute_or_colon_with_ordered_suffixes() -> Automaton {
        // (?:\A|:)ab(?:cd|c)(?:\z|!)
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 13],
                edge_targets: vec![2, 1, 2, 3, 4, 5, 7, 6, 8, 8, 10, 9, 10],
                edge_kinds: vec![
                    EdgeKind::AssertHaystackStart,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::AssertHaystackEnd,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b':', b'a', b'b', 0, 0, b'c', b'd', b'c', 0, 0, b'!'],
                byte_ends: vec![0, 0, b':', b'a', b'b', 0, 0, b'c', b'd', b'c', 0, 0, b'!'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn greedy_a_plus_or_a() -> Automaton {
        // (?:a+|a), with the greedy repetition first in priority order.
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 5, 6, 6],
                edge_targets: vec![1, 3, 2, 1, 4, 4],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'a', 0, 0, b'a'],
                byte_ends: vec![0, 0, b'a', 0, 0, b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn ordered_ab_or_ac() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 4, 5, 6, 6],
                edge_targets: vec![1, 4, 2, 3, 5, 6],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'a', b'b', b'a', b'c'],
                byte_ends: vec![0, 0, b'a', b'b', b'a', b'c'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn a_plus(greedy: bool) -> Automaton {
        let split_targets = if greedy { [0, 2] } else { [2, 0] };
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Split, StateRole::Accept],
                edge_offsets: vec![0, 1, 3, 3],
                edge_targets: vec![1, split_targets[0], split_targets[1]],
                edge_kinds: vec![EdgeKind::ByteRange, EdgeKind::Epsilon, EdgeKind::Epsilon],
                byte_starts: vec![b'a', 0, 0],
                byte_ends: vec![b'a', 0, 0],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn a_star(greedy: bool) -> Automaton {
        let split_targets = if greedy { [1, 2] } else { [2, 1] };
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 2, 3, 3],
                edge_targets: vec![split_targets[0], split_targets[1], 0],
                edge_kinds: vec![EdgeKind::Epsilon, EdgeKind::Epsilon, EdgeKind::ByteRange],
                byte_starts: vec![0, 0, b'a'],
                byte_ends: vec![0, 0, b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn greedy_a_star_b() -> Automaton {
        // a*b: globally positive with a nullable repeated prefix.
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 4],
                edge_targets: vec![1, 2, 0, 3],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'a', b'b'],
                byte_ends: vec![0, 0, b'a', b'b'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn a_question(greedy: bool) -> Automaton {
        let split_targets = if greedy { [1, 2] } else { [2, 1] };
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 2, 3, 3],
                edge_targets: vec![split_targets[0], split_targets[1], 2],
                edge_kinds: vec![EdgeKind::Epsilon, EdgeKind::Epsilon, EdgeKind::ByteRange],
                byte_starts: vec![0, 0, b'a'],
                byte_ends: vec![0, 0, b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn empty_or_a_plus(empty_first: bool, greedy_plus: bool) -> Automaton {
        let root_targets = if empty_first { [3, 1] } else { [1, 3] };
        let plus_targets = if greedy_plus { [1, 3] } else { [3, 1] };
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 5, 5],
                edge_targets: vec![
                    root_targets[0],
                    root_targets[1],
                    2,
                    plus_targets[0],
                    plus_targets[1],
                ],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                ],
                byte_starts: vec![0, 0, b'a', 0, 0],
                byte_ends: vec![0, 0, b'a', 0, 0],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn empty_or_ab(empty_first: bool) -> Automaton {
        let root_targets = if empty_first { [3, 1] } else { [1, 3] };
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 4],
                edge_targets: vec![root_targets[0], root_targets[1], 2, 3],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'a', b'b'],
                byte_ends: vec![0, 0, b'a', b'b'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn ordered_a_or_ab(long_first: bool) -> Automaton {
        let (first, second) = if long_first { (1_u32, 4_u32) } else { (4, 1) };
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Accept,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 4, 5, 5],
                edge_targets: vec![first, second, 2, 3, 5],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, b'a', b'b', b'a'],
                byte_ends: vec![0, 0, b'a', b'b', b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn multi_target_consume_a_or_bc() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Consume,
                    StateRole::Accept,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 2, 3, 3],
                edge_targets: vec![1, 2, 3],
                edge_kinds: vec![EdgeKind::ByteRange; 3],
                byte_starts: vec![b'a', b'b', b'c'],
                byte_ends: vec![b'a', b'b', b'c'],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    fn greedy_binary_pair_plus_then_80() -> Automaton {
        Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Consume,
                    StateRole::Split,
                    StateRole::Consume,
                    StateRole::Accept,
                ],
                edge_offsets: vec![0, 2, 3, 4, 6, 7, 7],
                edge_targets: vec![1, 2, 3, 3, 0, 4, 5],
                edge_kinds: vec![
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                    EdgeKind::ByteRange,
                    EdgeKind::Epsilon,
                    EdgeKind::Epsilon,
                    EdgeKind::ByteRange,
                ],
                byte_starts: vec![0, 0, 0x00, 0xff, 0, 0, 0x80],
                byte_ends: vec![0, 0, 0x00, 0xff, 0, 0, 0x80],
            },
            CompileLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn contextual_transition_slots_round_exact_state_domains_to_buckets() {
        let cases = [
            (0, 0),
            (1, 256),
            (2, 512),
            (3, 1_024),
            (4, 1_024),
            (5, 2_048),
            (8, 2_048),
            (9, 4_096),
            (16, 4_096),
            (17, 8_192),
            (32, 8_192),
            (33, 16_384),
            (64, 16_384),
            (65, 32_768),
            (128, 32_768),
            (129, super::CONTEXT_TRANSITION_MAX_SLOTS),
            (super::LAZY_MAX_STATES, super::CONTEXT_TRANSITION_MAX_SLOTS),
            (
                super::LAZY_MAX_STATES + 1,
                super::CONTEXT_TRANSITION_MAX_SLOTS,
            ),
            (usize::MAX, super::CONTEXT_TRANSITION_MAX_SLOTS),
        ];
        for (state_capacity, expected_slots) in cases {
            let slots = super::contextual_transition_slots(state_capacity).unwrap();
            assert_eq!(slots, expected_slots, "state capacity {state_capacity}");
            if slots != 0 {
                let buckets = slots / super::CONTEXT_TRANSITION_WAYS;
                assert!(buckets.is_power_of_two());
                assert!(buckets <= super::CONTEXT_TRANSITION_MAX_BUCKETS);
                assert_eq!(
                    super::contextual_transition_bucket_mask(slots).unwrap(),
                    buckets - 1
                );
            }
        }
        assert_eq!(super::contextual_transition_bucket_mask(0).unwrap(), 0);
        for slots in [
            1,
            super::CONTEXT_TRANSITION_WAYS + 1,
            super::CONTEXT_TRANSITION_WAYS * 3,
            super::CONTEXT_TRANSITION_MAX_SLOTS + super::CONTEXT_TRANSITION_WAYS,
        ] {
            assert!(matches!(
                super::contextual_transition_bucket_mask(slots),
                Err(SearchError::InternalInvariant { .. })
            ));
        }
    }

    #[test]
    fn ordered_partial_permutation_caps_match_exhaustive_state_identities() {
        fn enumerate_nonempty_orders(used: &mut [bool], length: usize, lengths: &mut Vec<usize>) {
            for item in 0..used.len() {
                if used[item] {
                    continue;
                }
                used[item] = true;
                let next_length = length.checked_add(1).unwrap();
                lengths.push(next_length);
                enumerate_nonempty_orders(used, next_length, lengths);
                used[item] = false;
            }
        }

        let mut forward = Vec::new();
        let mut forward_items = Vec::new();
        let mut direct_reverse = Vec::new();
        let mut reverse_items = Vec::new();
        let mut contextual_reverse = Vec::new();
        for items in 0..=6 {
            let mut lengths = Vec::new();
            enumerate_nonempty_orders(&mut vec![false; items], 0, &mut lengths);
            let nonempty = lengths.len();
            let expected_forward = nonempty
                .checked_mul(2)
                .and_then(|states| states.checked_add(1))
                .unwrap()
                .min(super::LAZY_MAX_STATES);
            let expected_direct_reverse = if items == 0 {
                0
            } else {
                nonempty.min(super::LAZY_MAX_STATES)
            };
            let expected_contextual_reverse = if items == 0 {
                0
            } else {
                nonempty.checked_add(1).unwrap().min(super::LAZY_MAX_STATES)
            };
            let got_forward = super::forward_lazy_state_capacity(items);
            let got_direct_reverse = super::reverse_lazy_state_capacity(items, false);
            let got_contextual_reverse = super::reverse_lazy_state_capacity(items, true);
            let mut forward_lengths = lengths.clone();
            forward_lengths.extend_from_slice(&lengths);
            forward_lengths.push(0);
            forward_lengths.sort_unstable_by(|left, right| right.cmp(left));
            let expected_forward_items = forward_lengths
                .iter()
                .take(expected_forward)
                .copied()
                .sum::<usize>()
                .min(super::LAZY_MAX_ITEMS);
            let mut direct_reverse_lengths = lengths.clone();
            direct_reverse_lengths.sort_unstable_by(|left, right| right.cmp(left));
            let expected_direct_reverse_items = direct_reverse_lengths
                .iter()
                .take(expected_direct_reverse)
                .copied()
                .sum::<usize>()
                .min(super::LAZY_MAX_ITEMS);
            let mut contextual_reverse_lengths = lengths;
            contextual_reverse_lengths.push(0);
            contextual_reverse_lengths.sort_unstable_by(|left, right| right.cmp(left));
            let expected_contextual_reverse_items = contextual_reverse_lengths
                .iter()
                .take(expected_contextual_reverse)
                .copied()
                .sum::<usize>()
                .min(super::LAZY_MAX_ITEMS);
            let got_forward_items = super::ordered_partial_permutation_item_capacity(
                items,
                2,
                got_forward,
                "test forward items",
            )
            .unwrap();
            let got_direct_reverse_items = super::ordered_partial_permutation_item_capacity(
                items,
                1,
                got_direct_reverse,
                "test direct reverse items",
            )
            .unwrap();
            let got_contextual_reverse_items = super::ordered_partial_permutation_item_capacity(
                items,
                1,
                got_contextual_reverse,
                "test contextual reverse items",
            )
            .unwrap();
            assert_eq!(got_forward, expected_forward, "forward items={items}");
            assert_eq!(
                got_forward_items, expected_forward_items,
                "forward arena items={items}"
            );
            assert_eq!(
                got_direct_reverse, expected_direct_reverse,
                "direct reverse items={items}"
            );
            assert_eq!(
                got_contextual_reverse, expected_contextual_reverse,
                "contextual reverse items={items}"
            );
            assert_eq!(
                got_direct_reverse_items, expected_direct_reverse_items,
                "direct reverse arena items={items}"
            );
            assert_eq!(
                got_contextual_reverse_items, expected_contextual_reverse_items,
                "contextual reverse arena items={items}"
            );
            forward.push(got_forward);
            forward_items.push(got_forward_items);
            direct_reverse.push(got_direct_reverse);
            reverse_items.push(got_direct_reverse_items);
            contextual_reverse.push(got_contextual_reverse);
        }
        assert_eq!(forward, [1, 3, 9, 31, 129, 256, 256]);
        assert_eq!(forward_items, [0, 2, 12, 66, 392, 1_264, 1_536]);
        assert_eq!(direct_reverse, [0, 1, 4, 15, 64, 256, 256]);
        assert_eq!(reverse_items, [0, 1, 6, 33, 196, 1_128, 1_536]);
        assert_eq!(contextual_reverse, [0, 2, 5, 16, 65, 256, 256]);
        assert_eq!(
            super::forward_lazy_state_capacity(usize::MAX),
            super::LAZY_MAX_STATES
        );
        assert_eq!(
            super::reverse_lazy_state_capacity(usize::MAX, false),
            super::LAZY_MAX_STATES
        );
        assert_eq!(
            super::reverse_lazy_state_capacity(usize::MAX, true),
            super::LAZY_MAX_STATES
        );
        assert_eq!(
            super::ordered_partial_permutation_item_capacity(
                super::LAZY_MAX_ITEMS,
                2,
                super::LAZY_MAX_STATES,
                "test saturated forward items",
            )
            .unwrap(),
            super::LAZY_MAX_ITEMS
        );
        for (items, expected) in [
            (63, 63 * super::LAZY_MAX_STATES),
            (64, super::LAZY_MAX_ITEMS),
            (65, super::LAZY_MAX_ITEMS),
        ] {
            assert_eq!(
                super::ordered_partial_permutation_item_capacity(
                    items,
                    2,
                    super::LAZY_MAX_STATES,
                    "test forward item cap transition",
                )
                .unwrap(),
                expected,
                "forward cap transition items={items}"
            );
            assert_eq!(
                super::ordered_partial_permutation_item_capacity(
                    items,
                    1,
                    super::LAZY_MAX_STATES,
                    "test reverse item cap transition",
                )
                .unwrap(),
                expected,
                "reverse cap transition items={items}"
            );
        }
        assert_eq!(
            super::ordered_partial_permutation_item_capacity(
                super::LAZY_MAX_ITEMS,
                1,
                super::LAZY_MAX_STATES,
                "test saturated reverse items",
            )
            .unwrap(),
            super::LAZY_MAX_ITEMS
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the census, state proof, item arena, direct rows, contextual slots, and resource edges share one layout matrix"
    )]
    fn consuming_census_tightly_sizes_every_lazy_workspace_component() {
        let terminal = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Accept],
                edge_offsets: vec![0, 0],
                edge_targets: vec![],
                edge_kinds: vec![],
                byte_starts: vec![],
                byte_ends: vec![],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let cases = [
            ("terminal", terminal, 0, 0, 1, 0, 0, 0),
            ("zero-edge-consume", zero_edge_consume(), 1, 0, 3, 2, 0, 0),
            ("one", byte_chain(&[(b'a', b'a')]), 1, 1, 3, 2, 1, 1),
            (
                "two",
                byte_chain(&[(b'a', b'a'), (b'b', b'b')]),
                2,
                2,
                9,
                12,
                4,
                6,
            ),
            (
                "three",
                byte_chain(&[(b'a', b'a'), (b'b', b'b'), (b'c', b'c')]),
                3,
                3,
                31,
                66,
                15,
                33,
            ),
            (
                "four",
                byte_chain(&[(b'a', b'a'), (b'b', b'b'), (b'c', b'c'), (b'd', b'd')]),
                4,
                4,
                129,
                392,
                64,
                196,
            ),
        ];

        for (
            name,
            plan,
            consuming_states,
            consuming_edges,
            forward_states,
            forward_items,
            reverse_states,
            reverse_items,
        ) in cases
        {
            assert_eq!(
                plan.stats().consuming_states(),
                consuming_states,
                "{name}: authenticated consuming-state census"
            );
            assert_eq!(
                plan.stats().consuming_edges(),
                consuming_edges,
                "{name}: consuming-edge census"
            );

            let endpoint = plan.accelerated_workspace_layout().unwrap();
            let ordinary = plan.workspace_layout().unwrap();
            assert_eq!(
                endpoint.lazy_state_capacity, forward_states,
                "{name}: forward states"
            );
            assert_eq!(
                endpoint.lazy_item_capacity, forward_items,
                "{name}: forward items"
            );
            assert_eq!(endpoint.lazy_context_slots, 0, "{name}: direct forward");
            let expected_lazy_bytes = super::lazy_scratch_bytes(
                endpoint.states,
                forward_states,
                endpoint.lazy_item_capacity,
                0,
            )
            .unwrap();
            assert_eq!(
                endpoint
                    .logical_bytes()
                    .checked_sub(ordinary.logical_bytes())
                    .unwrap(),
                expected_lazy_bytes,
                "{name}: exact additional logical bytes"
            );
            let expected_lazy_work = super::lazy_initialized_slots(
                endpoint.states,
                forward_states,
                endpoint.lazy_item_capacity,
                0,
            )
            .unwrap()
            .checked_add(7)
            .and_then(|work| work.checked_add(usize::from(endpoint.lazy_item_capacity != 0)))
            .and_then(|work| u64::try_from(work).ok())
            .unwrap();
            assert_eq!(
                endpoint
                    .construction_work()
                    .checked_sub(ordinary.construction_work())
                    .unwrap(),
                expected_lazy_work,
                "{name}: exact initialization and allocation work"
            );
            let exact_endpoint = K0Workspace::new_accelerated(
                &plan,
                WorkspaceLimits {
                    max_setup_work: endpoint.construction_work(),
                    max_scratch_bytes: endpoint.logical_bytes(),
                },
            )
            .unwrap();
            assert_eq!(
                exact_endpoint.lazy.rows.len(),
                forward_states.checked_mul(super::BYTE_ALPHABET).unwrap(),
                "{name}: forward row cells"
            );
            assert_eq!(
                exact_endpoint.lazy.items.len(),
                forward_items,
                "{name}: forward item storage"
            );
            assert_eq!(
                exact_endpoint.construction_accounting().work(),
                endpoint.construction_work(),
                "{name}: exact construction accounting"
            );
            assert!(matches!(
                K0Workspace::new_accelerated(
                    &plan,
                    WorkspaceLimits {
                        max_setup_work: endpoint.construction_work() - 1,
                        max_scratch_bytes: usize::MAX,
                    },
                ),
                Err(SearchError::WorkspaceSetupWorkLimitExceeded { limit, needed })
                    if limit == endpoint.construction_work() - 1
                        && needed == endpoint.construction_work()
            ));
            assert!(matches!(
                K0Workspace::new_accelerated(
                    &plan,
                    WorkspaceLimits {
                        max_setup_work: u64::MAX,
                        max_scratch_bytes: endpoint.logical_bytes() - 1,
                    },
                ),
                Err(SearchError::ResourceLimit {
                    resource: ResourceKind::ScratchBytes,
                    needed,
                    limit,
                }) if needed == endpoint.logical_bytes()
                    && limit == endpoint.logical_bytes() - 1
            ));

            let full = plan.bidirectional_workspace_layout().unwrap();
            assert_eq!(
                full.reverse_state_capacity, reverse_states,
                "{name}: reverse states"
            );
            assert_eq!(
                full.reverse_item_capacity, reverse_items,
                "{name}: reverse items"
            );
            let exact_full =
                K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
            assert_eq!(
                exact_full.reverse.rows.len(),
                reverse_states.checked_mul(super::BYTE_ALPHABET).unwrap(),
                "{name}: reverse row cells"
            );
            assert_eq!(
                exact_full.reverse.items.len(),
                reverse_items,
                "{name}: reverse item storage"
            );
            if reverse_states == 0 {
                assert_eq!(full, endpoint, "{name}: no reverse frontier");
            } else {
                assert!(
                    full.logical_bytes() > endpoint.logical_bytes(),
                    "{name}: reverse storage"
                );
            }
        }

        let contextual = asserted_line_a();
        assert_eq!(contextual.stats().consuming_states(), 1);
        let endpoint = contextual.accelerated_workspace_layout().unwrap();
        let full = contextual.bidirectional_workspace_layout().unwrap();
        assert_eq!(endpoint.lazy_state_capacity, 3);
        assert_eq!(endpoint.lazy_item_capacity, 2);
        assert_eq!(endpoint.lazy_context_slots, 1_024);
        assert_eq!(full.reverse_state_capacity, 2);
        assert_eq!(full.reverse_item_capacity, 1);
        assert_eq!(full.reverse_context_slots, 512);
        let workspace =
            K0Workspace::new_bidirectional(&contextual, WorkspaceLimits::unlimited()).unwrap();
        assert!(workspace.lazy.rows.is_empty());
        assert!(workspace.reverse.rows.is_empty());
        assert_eq!(workspace.lazy.context.slots.len(), 1_024);
        assert_eq!(workspace.reverse.context.slots.len(), 512);
        assert_eq!(
            workspace.lazy.context.retained_bytes().unwrap(),
            1_024 * size_of::<ContextTransitionSlot>()
        );
        assert_eq!(
            workspace.reverse.context.retained_bytes().unwrap(),
            512 * size_of::<ContextTransitionSlot>()
        );
        assert_eq!(workspace.retained_bytes(), full.logical_bytes());
        assert_eq!(
            workspace.construction_accounting().allocated_bytes(),
            full.logical_bytes()
        );

        let three_classes = asserted_line_three_classes();
        assert_eq!(three_classes.stats().consuming_states(), 3);
        assert_eq!(three_classes.stats().consuming_edges(), 3);
        let endpoint = three_classes.accelerated_workspace_layout().unwrap();
        let full = three_classes.bidirectional_workspace_layout().unwrap();
        assert_eq!(endpoint.lazy_state_capacity, 31);
        assert_eq!(endpoint.lazy_context_slots, 8_192);
        assert_eq!(full.reverse_state_capacity, 16);
        assert_eq!(full.reverse_context_slots, 4_096);
        let workspace =
            K0Workspace::new_bidirectional(&three_classes, WorkspaceLimits::unlimited()).unwrap();
        assert_eq!(workspace.lazy.context.slots.len(), 8_192);
        assert_eq!(workspace.reverse.context.slots.len(), 4_096);
        assert_eq!(workspace.retained_bytes(), full.logical_bytes());
        assert_eq!(
            workspace.construction_accounting().allocated_bytes(),
            full.logical_bytes()
        );
    }

    #[test]
    fn zero_edge_consume_census_preserves_semantics_accounting_and_cache_capacity() {
        let plan = zero_edge_consume();
        let endpoint = plan.accelerated_workspace_layout().unwrap();
        assert_eq!(plan.stats().consuming_states(), 1);
        assert_eq!(plan.stats().consuming_edges(), 0);
        assert_eq!(endpoint.lazy_state_capacity, 3);
        assert_eq!(endpoint.lazy_item_capacity, 2);
        assert_eq!(endpoint.reverse_state_capacity, 0);

        let mut pike = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut accelerated =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let haystacks = [b"".as_slice(), b"a", b"\0\xff", b"dead"];
        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let want = plan
                        .prepare::<Exists>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut pike,
                            SearchLimits::unlimited(),
                        )
                        .unwrap();
                    let got = plan
                        .prepare::<Exists>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut accelerated,
                            SearchLimits::unlimited(),
                        )
                        .unwrap();
                    assert_eq!(got.output(), want.output());
                    assert_eq!(
                        got.accounting().boundaries(),
                        want.accounting().boundaries()
                    );

                    let want = plan
                        .prepare::<EarliestEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut pike,
                            SearchLimits::unlimited(),
                        )
                        .unwrap();
                    let got = plan
                        .prepare::<EarliestEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut accelerated,
                            SearchLimits::unlimited(),
                        )
                        .unwrap();
                    assert_eq!(got.output(), want.output());
                    assert_eq!(
                        got.accounting().boundaries(),
                        want.accounting().boundaries()
                    );

                    let want = plan
                        .prepare::<SelectedEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut pike,
                            SearchLimits::unlimited(),
                        )
                        .unwrap();
                    let got = plan
                        .prepare::<SelectedEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut accelerated,
                            SearchLimits::unlimited(),
                        )
                        .unwrap();
                    assert_eq!(got.output(), want.output());
                    assert_eq!(
                        got.accounting().boundaries(),
                        want.accounting().boundaries()
                    );

                    let want = plan
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut pike,
                            SearchLimits::unlimited(),
                        )
                        .unwrap();
                    let got = plan
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut accelerated,
                            SearchLimits::unlimited(),
                        )
                        .unwrap();
                    assert_eq!(got.output(), want.output());
                    assert_eq!(
                        got.accounting().boundaries(),
                        want.accounting().boundaries()
                    );
                }
            }
        }
        assert!(accelerated.lazy.initialized);
        assert!(!accelerated.lazy.declined);
        assert!(!accelerated.lazy.saturated);
        assert!(accelerated.lazy.state_len <= endpoint.lazy_state_capacity);
        assert!(accelerated.lazy.item_len <= endpoint.lazy_item_capacity);
    }

    #[test]
    fn existence_stops_at_first_accepting_boundary() {
        let automaton = greedy_a_plus_or_a();
        let haystack = b"aaaaaaaa";

        let exists = automaton
            .prepare::<Exists>()
            .search(haystack, SearchLimits::unlimited())
            .unwrap();
        let selected = automaton
            .prepare::<Span>()
            .search(haystack, SearchLimits::unlimited())
            .unwrap();

        assert_eq!(exists.output(), &true);
        assert_eq!(
            selected.output(),
            &Some(crate::MatchSpan::new(0, haystack.len()))
        );
        assert_eq!(exists.accounting().boundaries(), 2);
        assert_eq!(selected.accounting().boundaries(), 9);
        assert!(exists.accounting().work() < selected.accounting().work());
    }

    fn pin_without_start_filter(automaton: &Automaton) {
        automaton
            .start_filter_proof
            .set(&StartFilterProof {
                scanner: None,
                filter: None,
                force_haystack_start: false,
                relaxed_nullable: false,
            })
            .expect("fresh reference automaton");
    }

    fn bounded_words(alphabet: &[u8], maximum_len: usize) -> Vec<Vec<u8>> {
        let mut words = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..maximum_len {
            let mut next = Vec::with_capacity(frontier.len().saturating_mul(alphabet.len()));
            for prefix in &frontier {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    words.push(word.clone());
                    next.push(word);
                }
            }
            frontier = next;
        }
        words
    }

    fn assert_all_windows_match_unspecialized(
        name: &str,
        specialized: &Automaton,
        reference: &Automaton,
        haystacks: &[Vec<u8>],
    ) {
        pin_without_start_filter(reference);
        let mut specialized_workspace =
            K0Workspace::new(specialized, WorkspaceLimits::unlimited()).unwrap();
        let mut reference_workspace =
            K0Workspace::new(reference, WorkspaceLimits::unlimited()).unwrap();

        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let actual = specialized
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut specialized_workspace,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let expected = reference
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut reference_workspace,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    assert_eq!(
                        actual, expected,
                        "{name}: span mismatch for {haystack:?} in {start}..{end}"
                    );

                    let actual = specialized
                        .prepare::<EarliestEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut specialized_workspace,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let expected = reference
                        .prepare::<EarliestEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut reference_workspace,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    assert_eq!(
                        actual, expected,
                        "{name}: earliest-end mismatch for {haystack:?} in {start}..{end}"
                    );
                }
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one differential helper checks all four contracts over the same window matrix"
    )]
    fn assert_contextual_all_contracts(plan: &Automaton, haystacks: &[Vec<u8>]) {
        let mut pike = K0Workspace::new(plan, WorkspaceLimits::unlimited()).unwrap();
        let mut endpoint =
            K0Workspace::new_accelerated(plan, WorkspaceLimits::unlimited()).unwrap();
        let mut bidirectional =
            K0Workspace::new_bidirectional(plan, WorkspaceLimits::unlimited()).unwrap();
        assert!(endpoint.lazy.context.is_allocated());
        assert!(bidirectional.lazy.context.is_allocated());
        assert!(bidirectional.reverse.context.is_allocated());

        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let want_exists = plan
                        .prepare::<Exists>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut pike,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let got_exists = plan
                        .prepare::<Exists>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut endpoint,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    assert_eq!(
                        got_exists, want_exists,
                        "contextual Exists mismatch plan={plan:?} source={haystack:?} window={window:?}"
                    );

                    let want_earliest = plan
                        .prepare::<EarliestEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut pike,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let got_earliest = plan
                        .prepare::<EarliestEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut endpoint,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    assert_eq!(
                        got_earliest, want_earliest,
                        "contextual EarliestEnd mismatch plan={plan:?} source={haystack:?} window={window:?}"
                    );

                    let want_selected = plan
                        .prepare::<SelectedEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut pike,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let got_selected = plan
                        .prepare::<SelectedEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut endpoint,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    assert_eq!(
                        got_selected, want_selected,
                        "contextual SelectedEnd mismatch plan={plan:?} source={haystack:?} window={window:?}"
                    );

                    let want_span = plan
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut pike,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let got_span = plan
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut bidirectional,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    assert_eq!(
                        got_span, want_span,
                        "contextual Span mismatch plan={plan:?} source={haystack:?} window={window:?}"
                    );
                }
            }
        }
        assert!(endpoint.lazy.initialized);
        assert!(!endpoint.lazy.declined);
        assert!(bidirectional.lazy.initialized);
        assert!(bidirectional.reverse.initialized);
        assert!(!bidirectional.reverse.declined);
    }

    fn assert_chain_filter_matches_unspecialized(
        name: &str,
        ranges: &[(u8, u8)],
        expected: StartFilterProof,
        haystacks: &[Vec<u8>],
    ) -> Automaton {
        let specialized = byte_chain(ranges);
        let reference = byte_chain(ranges);
        assert_all_windows_match_unspecialized(name, &specialized, &reference, haystacks);
        assert_eq!(
            specialized
                .start_filter_proof
                .get()
                .expect("exhaustive search publishes proof"),
            &expected
        );
        specialized
    }

    fn byte_set(bytes: &[u8]) -> ByteSet {
        let mut words = [0_u64; 4];
        for &byte in bytes {
            super::insert_byte_range(&mut words, byte, byte);
        }
        ByteSet::from_words(words)
    }

    fn byte_range_set(start: u8, end: u8) -> ByteSet {
        let mut words = [0_u64; 4];
        super::insert_byte_range(&mut words, start, end);
        ByteSet::from_words(words)
    }

    fn next_random_word(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn scanner_for(bytes: &[u8]) -> StartScanner {
        let mut meter = WorkMeter::new(u64::MAX, 0);
        let scanner = super::byte_start_scanner(byte_set(bytes), &mut meter, 0).unwrap();
        assert_eq!(meter.consumed, expected_scanner_selection_work(bytes));
        scanner
    }

    fn scanner_for_set(set: ByteSet) -> StartScanner {
        let mut meter = WorkMeter::new(u64::MAX, 0);
        super::byte_start_scanner(set, &mut meter, 0).unwrap()
    }

    fn scanner_contains(scanner: &StartScanner, byte: u8) -> bool {
        match scanner {
            StartScanner::Empty => false,
            StartScanner::One(member) => byte == *member,
            StartScanner::Two(first, second) => byte == *first || byte == *second,
            StartScanner::Three(first, second, third) => {
                byte == *first || byte == *second || byte == *third
            }
            StartScanner::Range { start, end } => (*start..=*end).contains(&byte),
            StartScanner::AsciiSet { set, .. } => set.contains(byte),
            StartScanner::Set(classifier) => classifier.set().contains(byte),
        }
    }

    fn retained_candidate_sequence(
        scanner: &StartPositionScanner,
        guard: Option<&StartPositionClass>,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> (Vec<usize>, u64) {
        let mut cursor = super::RetainedStartMaskCursor::default();
        let mut meter = WorkMeter::new(u64::MAX, 0);
        let mut search = start;
        let mut candidates = Vec::new();
        loop {
            let candidate = super::next_start_candidate_retained(
                scanner,
                haystack,
                search,
                end,
                guard,
                &mut meter,
                &mut cursor,
            )
            .unwrap();
            if candidate == end {
                break;
            }
            assert!(candidate >= search);
            candidates.push(candidate);
            search = candidate.checked_add(1).unwrap();
        }
        (candidates, meter.consumed)
    }

    const fn positioned_scanner(offset: u8, scanner: StartScanner) -> StartPositionScanner {
        StartPositionScanner { offset, scanner }
    }

    const fn root_scanner(scanner: StartScanner) -> StartPositionScanner {
        positioned_scanner(0, scanner)
    }

    fn expected_scanner_construction_work(bytes: &[u8]) -> u64 {
        let set = byte_set(bytes);
        let cardinality = usize::try_from(set.cardinality()).unwrap();
        let construction = if cardinality <= BYTE_START_SMALL_MAX_MEMBERS {
            cardinality
                .checked_mul(BYTE_START_MEMBER_EXTRACTION_WORK)
                .unwrap()
        } else {
            let fallback = if super::inclusive_byte_range(set, u32::try_from(cardinality).unwrap())
                .is_some()
            {
                0
            } else if bytes.iter().all(u8::is_ascii) {
                BYTE_START_ASCII_CLASSIFIER_SELECTION_WORK
            } else {
                BYTE_START_SET_CLASSIFIER_BUILD_WORK
            };
            BYTE_START_RANGE_DETECTION_WORK
                .checked_add(fallback)
                .unwrap()
        };
        u64::try_from(construction).unwrap()
    }

    fn expected_scanner_selection_work(bytes: &[u8]) -> u64 {
        u64::try_from(BYTE_START_BITMAP_POPULATION_WORK)
            .unwrap()
            .checked_add(expected_scanner_construction_work(bytes))
            .unwrap()
    }

    fn expected_start_class_selection_work(positions: usize) -> u64 {
        u64::try_from(
            positions
                .checked_mul(
                    BYTE_START_BITMAP_POPULATION_WORK
                        .checked_add(START_FILTER_SCANNER_SELECTION_WORK)
                        .unwrap(),
                )
                .and_then(|work| {
                    positions
                        .saturating_sub(1)
                        .checked_mul(START_FILTER_GUARD_SELECTION_WORK)
                        .and_then(|guard| work.checked_add(guard))
                })
                .unwrap(),
        )
        .unwrap()
    }

    fn expected_filter_selection_work(positions: usize, scanner_bytes: &[u8]) -> u64 {
        expected_start_class_selection_work(positions)
            .checked_add(expected_scanner_construction_work(scanner_bytes))
            .unwrap()
    }

    fn expected_ascii_scanner_work(start: usize, end: usize, expected: usize) -> u64 {
        let mut position = start;
        let mut work = 0_usize;
        while end.saturating_sub(position) >= ASCII_WIDE_BYTES {
            work = work.checked_add(ASCII_WIDE_BYTES).unwrap();
            let block_end = position.checked_add(ASCII_WIDE_BYTES).unwrap();
            if expected < block_end {
                return u64::try_from(work).unwrap();
            }
            position = block_end;
        }
        if end.saturating_sub(position) >= ASCII_NARROW_BYTES {
            work = work.checked_add(ASCII_NARROW_BYTES).unwrap();
            let block_end = position.checked_add(ASCII_NARROW_BYTES).unwrap();
            if expected < block_end {
                return u64::try_from(work).unwrap();
            }
            position = block_end;
        }
        let tail = if expected == end {
            end.saturating_sub(position)
        } else {
            expected
                .checked_sub(position)
                .and_then(|distance| distance.checked_add(1))
                .unwrap()
        };
        u64::try_from(work.checked_add(tail).unwrap()).unwrap()
    }

    fn expected_full_byte_scanner_work(start: usize, end: usize, expected: usize) -> u64 {
        let mut position = start;
        let mut work = 0_usize;
        let scalar_prefix_end = start
            .saturating_add(fre_simd_kernels::BYTE_SET_BLOCK_BYTES)
            .min(end);
        while position < scalar_prefix_end {
            work = work.checked_add(1).unwrap();
            if position == expected {
                return u64::try_from(work).unwrap();
            }
            position = position.checked_add(1).unwrap();
        }
        while end.saturating_sub(position) >= fre_simd_kernels::BYTE_SET_BLOCK_BYTES {
            work = work
                .checked_add(fre_simd_kernels::BYTE_SET_BLOCK_BYTES)
                .unwrap();
            let block_end = position
                .checked_add(fre_simd_kernels::BYTE_SET_BLOCK_BYTES)
                .unwrap();
            if expected < block_end {
                return u64::try_from(work).unwrap();
            }
            position = block_end;
        }
        let tail = if expected == end {
            end.saturating_sub(position)
        } else {
            expected
                .checked_sub(position)
                .and_then(|distance| distance.checked_add(1))
                .unwrap()
        };
        u64::try_from(work.checked_add(tail).unwrap()).unwrap()
    }

    #[test]
    fn refused_work_is_never_charged() {
        let mut meter = WorkMeter::new(3, 0);
        meter.charge(2, 7).unwrap();
        let error = meter.charge(2, 8).unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit: 3,
                consumed: 2,
                requested: 2,
                position: 8
            }
        ));
        assert_eq!(meter.consumed, 2);
    }

    #[test]
    fn start_filter_depth_layout_and_selection_bound_cover_one_simd_block() {
        assert_eq!(START_FILTER_POSITION_COUNT, ASCII_NARROW_BYTES);
        assert_eq!(START_FILTER_POSITION_COUNT, 16);
        assert_eq!(START_FILTER_MAX_OFFSET, 15);

        let expected_selection_work = START_FILTER_POSITION_COUNT
            .checked_mul(
                BYTE_START_BITMAP_POPULATION_WORK
                    .checked_add(START_FILTER_SCANNER_SELECTION_WORK)
                    .unwrap(),
            )
            .and_then(|work| {
                START_FILTER_MAX_OFFSET
                    .checked_mul(START_FILTER_GUARD_SELECTION_WORK)
                    .and_then(|guards| work.checked_add(guards))
            })
            .and_then(|work| work.checked_add(BYTE_START_RANGE_DETECTION_WORK))
            .and_then(|work| work.checked_add(BYTE_START_SET_CLASSIFIER_BUILD_WORK))
            .and_then(|work| work.checked_add(START_FILTER_PROBE_SELECTION_WORK))
            .unwrap();
        assert_eq!(START_FILTER_MAX_SELECTION_WORK, expected_selection_work);
        assert_eq!(START_FILTER_MAX_SELECTION_WORK, 357);

        // All exact-position sets remain a transient cold stack value. The
        // immutable owner still retains only its selected scanner and guard.
        let expected_transient_bytes = START_FILTER_POSITION_COUNT
            .checked_mul(size_of::<ByteSet>())
            .and_then(|bytes| bytes.checked_add(size_of::<usize>() * 2))
            .unwrap();
        assert_eq!(
            size_of::<super::StartPositionProof>(),
            expected_transient_bytes
        );
    }

    #[test]
    fn start_proof_stops_at_the_exact_work_limit() {
        let automaton = ascii_root_bytes(b"abcdef");
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let mut meter = WorkMeter::new(1, 0);
        let error =
            super::derive_start_position_classes(&automaton, &mut workspace, &mut meter, 23)
                .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit: 1,
                consumed: 1,
                requested: 1,
                position: 23
            }
        ));
        assert_eq!(meter.consumed, 1);
    }

    #[test]
    fn scratch_charge_grows_monotonically() {
        let small = scratch_bytes(2, 1, 1).unwrap();
        let more_states = scratch_bytes(3, 1, 1).unwrap();
        let more_edges = scratch_bytes(2, 2, 1).unwrap();
        let deeper_closure = scratch_bytes(2, 1, 2).unwrap();
        assert!(more_states > small);
        assert!(more_edges > small);
        assert!(deeper_closure > small);
    }

    #[test]
    fn start_scanner_selection_work_is_exact_and_precedes_construction() {
        let scanner_sets: &[&[u8]] =
            &[&[], b"a", b"ab", b"abc", b"abcd", &[0x80, 0x81, 0x82, 0x83]];
        for &bytes in scanner_sets {
            let expected = expected_scanner_selection_work(bytes);

            let mut population_refusal = WorkMeter::new(
                u64::try_from(BYTE_START_BITMAP_POPULATION_WORK.checked_sub(1).unwrap()).unwrap(),
                0,
            );
            let error = super::byte_start_scanner(byte_set(bytes), &mut population_refusal, 17)
                .unwrap_err();
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    consumed: 0,
                    requested,
                    position: 17,
                    ..
                } if requested
                    == u64::try_from(BYTE_START_BITMAP_POPULATION_WORK).unwrap()
            ));

            let mut exact = WorkMeter::new(expected, 0);
            super::byte_start_scanner(byte_set(bytes), &mut exact, 17).unwrap();
            assert_eq!(exact.consumed, expected);

            let mut one_below = WorkMeter::new(expected.checked_sub(1).unwrap(), 0);
            let error = super::byte_start_scanner(byte_set(bytes), &mut one_below, 17).unwrap_err();
            let set = byte_set(bytes);
            let cardinality = usize::try_from(set.cardinality()).unwrap();
            let range = (cardinality > BYTE_START_SMALL_MAX_MEMBERS)
                .then(|| super::inclusive_byte_range(set, u32::try_from(cardinality).unwrap()))
                .flatten();
            let expected_tail = if cardinality == 0 {
                u64::try_from(BYTE_START_BITMAP_POPULATION_WORK).unwrap()
            } else if cardinality <= BYTE_START_SMALL_MAX_MEMBERS {
                u64::try_from(
                    cardinality
                        .checked_mul(BYTE_START_MEMBER_EXTRACTION_WORK)
                        .unwrap(),
                )
                .unwrap()
            } else if range.is_some() {
                u64::try_from(BYTE_START_RANGE_DETECTION_WORK).unwrap()
            } else if bytes.iter().all(u8::is_ascii) {
                u64::try_from(BYTE_START_ASCII_CLASSIFIER_SELECTION_WORK).unwrap()
            } else {
                u64::try_from(BYTE_START_SET_CLASSIFIER_BUILD_WORK).unwrap()
            };
            let expected_consumed = if cardinality == 0 {
                0
            } else if cardinality > BYTE_START_SMALL_MAX_MEMBERS && range.is_none() {
                u64::try_from(BYTE_START_BITMAP_POPULATION_WORK + BYTE_START_RANGE_DETECTION_WORK)
                    .unwrap()
            } else {
                u64::try_from(BYTE_START_BITMAP_POPULATION_WORK).unwrap()
            };
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    consumed,
                    requested,
                    position: 17,
                    ..
                } if consumed == expected_consumed && requested == expected_tail
            ));
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the candidate-first differential keeps the proven scanner inputs explicit"
    )]
    fn assert_context_candidate_first_case(
        name: &str,
        plan: &Automaton,
        haystack: &[u8],
        window: SearchWindow,
        scanner: &StartPositionScanner,
        guard: Option<&StartPositionClass>,
        force_haystack_start: bool,
    ) {
        let mut reference = K0Workspace::new(plan, WorkspaceLimits::unlimited()).unwrap();
        let expected = plan
            .prepare::<EarliestEnd>()
            .search_window_with_workspace(
                haystack,
                window,
                &mut reference,
                SearchLimits::unlimited(),
            )
            .unwrap()
            .into_output();

        for limits in [SearchLimits::default(), SearchLimits::unlimited()] {
            let mut accelerated =
                K0Workspace::new_accelerated(plan, WorkspaceLimits::unlimited()).unwrap();
            let actual = plan
                .prepare::<EarliestEnd>()
                .search_window_with_workspace(haystack, window, &mut accelerated, limits)
                .unwrap()
                .into_output();
            assert_eq!(
                actual, expected,
                "{name}: public contextual result source={haystack:?} window={window:?}"
            );
        }

        let run = |limit| {
            let mut workspace =
                K0Workspace::new_accelerated(plan, WorkspaceLimits::unlimited()).unwrap();
            let mut meter = WorkMeter::new(limit, 0);
            let mut adaptive_probe = super::AdaptiveStartProbe::default();
            let result = super::execute_context_lazy_loop(
                plan,
                haystack,
                window,
                &mut workspace,
                &mut meter,
                OutputContract::EarliestEnd,
                0,
                Some(scanner),
                guard,
                None,
                force_haystack_start,
                false,
                &mut adaptive_probe,
            );
            (result, meter.consumed, workspace.lazy.initialized)
        };

        let expected_initialized = if force_haystack_start && window.start() == 0 {
            true
        } else {
            let mut meter = WorkMeter::new(u64::MAX, 0);
            super::next_start_candidate(
                scanner,
                haystack,
                window.start(),
                window.end(),
                guard,
                &mut meter,
            )
            .unwrap()
                != window.end()
        };
        let (unlimited, unlimited_work, initialized) = run(u64::MAX);
        let unlimited = unlimited
            .unwrap()
            .expect("the allocated contextual executor must accept the plan");
        assert_eq!(
            unlimited.0.map(MatchSpan::end),
            expected,
            "{name}: direct unlimited result source={haystack:?} window={window:?}"
        );
        assert_eq!(
            initialized, expected_initialized,
            "{name}: a scanner miss must return before contextual initialization"
        );
        assert!(
            unlimited_work > 0,
            "{name}: the scanner must charge actual work"
        );

        // Unlimited execution may spend optional work publishing reusable
        // states. Find the exact finite allowance for the same result so the
        // boundary below tests mandatory work rather than optional learning.
        let exact_work = (0..=unlimited_work)
            .find(|&limit| {
                matches!(
                    run(limit).0,
                    Ok(Some(result)) if result == unlimited
                )
            })
            .expect("unlimited actual work must admit an equivalent finite execution");
        let (exact, consumed, exact_initialized) = run(exact_work);
        assert_eq!(
            exact.unwrap(),
            Some(unlimited),
            "{name}: exact-work execution changed its result"
        );
        assert_eq!(consumed, exact_work, "{name}: exact work was not consumed");
        assert_eq!(exact_initialized, initialized);

        let one_below = exact_work.checked_sub(1).unwrap();
        let (error, consumed, _) = run(one_below);
        let SearchError::WorkLimitExceeded {
            limit,
            consumed: reported,
            requested,
            position,
        } = error.expect_err("one-below work must fail")
        else {
            panic!("{name}: one-below returned the wrong error");
        };
        assert_eq!(limit, one_below);
        assert_eq!(reported, consumed);
        assert!(reported.checked_add(requested).unwrap() > limit);
        assert!(
            (window.start()..=window.end()).contains(&position),
            "{name}: failure position escaped the search window"
        );
    }

    #[test]
    fn contextual_candidate_first_is_differential_for_line_modes_bytes_and_windows() {
        let mut haystacks = bounded_words(&[b'a', b'x', b'!', b'\r', b'\n', 0x80, 0xff], 3);
        haystacks.extend([
            b"a\n".to_vec(),
            b"xxa\n".to_vec(),
            b"a\r\n".to_vec(),
            b"xxa\r\n".to_vec(),
            vec![0xf0, 0x28, 0x8c, 0xbc, b'a', b'\n', 0xff],
            vec![0xff, b'x', b'a', b'\r', b'\n', 0x80],
        ]);
        for kind in [EdgeKind::AssertLineEndLf, EdgeKind::AssertLineEndCrlf] {
            let plan = trailing_assertion_or_bang(kind);
            assert_contextual_all_contracts(&plan, &haystacks);
            let proof = plan
                .start_filter_proof
                .get()
                .expect("exhaustive contextual search publishes its start proof");
            assert!(!proof.force_haystack_start);
            assert!(proof.guard().is_none());
            assert!(matches!(
                proof.scanner,
                Some(StartPositionScanner {
                    offset: 0,
                    scanner: StartScanner::One(b'a'),
                })
            ));
        }
    }

    #[test]
    fn contextual_candidate_first_work_limits_are_exact() {
        let scanner = StartPositionScanner {
            offset: 0,
            scanner: StartScanner::One(b'a'),
        };
        let cases: &[(&str, EdgeKind, &[u8], SearchWindow)] = &[
            (
                "lf-candidate-zero",
                EdgeKind::AssertLineEndLf,
                b"a\n",
                SearchWindow::new(0, 2),
            ),
            (
                "lf-candidate-interior",
                EdgeKind::AssertLineEndLf,
                b"xxa\n",
                SearchWindow::new(0, 4),
            ),
            (
                "lf-no-candidate",
                EdgeKind::AssertLineEndLf,
                b"xxxx",
                SearchWindow::new(0, 4),
            ),
            (
                "lf-nonzero-window",
                EdgeKind::AssertLineEndLf,
                b"za\nx",
                SearchWindow::new(1, 3),
            ),
            (
                "crlf-candidate-zero",
                EdgeKind::AssertLineEndCrlf,
                b"a\r\n",
                SearchWindow::new(0, 3),
            ),
            (
                "crlf-candidate-interior",
                EdgeKind::AssertLineEndCrlf,
                b"xxa\r\n",
                SearchWindow::new(0, 5),
            ),
            (
                "invalid-utf8-window",
                EdgeKind::AssertLineEndLf,
                &[0xf0, 0x28, 0x8c, 0xbc, b'a', b'\n', 0xff],
                SearchWindow::new(1, 6),
            ),
            (
                "high-byte-window",
                EdgeKind::AssertLineEndCrlf,
                &[0xff, b'x', b'a', b'\r', b'\n', 0x80],
                SearchWindow::new(1, 5),
            ),
        ];
        for &(name, kind, haystack, window) in cases {
            let plan = trailing_assertion_or_bang(kind);
            assert_context_candidate_first_case(
                name, &plan, haystack, window, &scanner, None, false,
            );
        }
    }

    #[test]
    fn contextual_candidate_first_preserves_absolute_start_priority() {
        let scanner = StartPositionScanner {
            offset: 0,
            scanner: StartScanner::One(b':'),
        };
        let guard = StartPositionClass {
            offset: 1,
            set: byte_set(b"a"),
        };
        let cases: &[(&str, &[u8], SearchWindow)] = &[
            (
                "absolute-high-byte-at-zero",
                b"\xff:a",
                SearchWindow::new(0, 3),
            ),
            (
                "absolute-high-byte-nonzero-window",
                b"x\xff:a",
                SearchWindow::new(1, 4),
            ),
            (
                "absolute-sibling-interior",
                b"xx:a",
                SearchWindow::new(1, 4),
            ),
            ("absolute-no-sibling", b"x\xffxx", SearchWindow::new(1, 4)),
        ];
        for &(name, haystack, window) in cases {
            let plan = absolute_high_byte_or_colon_a();
            assert_context_candidate_first_case(
                name,
                &plan,
                haystack,
                window,
                &scanner,
                Some(&guard),
                true,
            );
        }
    }

    #[test]
    fn contextual_candidate_first_misses_preserve_work_boundaries_and_cache_state() {
        let plan = trailing_assertion_or_bang(EdgeKind::AssertLineEndLf);
        let scanner = StartPositionScanner {
            offset: 0,
            scanner: StartScanner::One(b'a'),
        };
        let run = |workspace: &mut K0Workspace, haystack: &[u8]| {
            let mut meter = WorkMeter::new(u64::MAX, 0);
            let mut adaptive_probe = super::AdaptiveStartProbe::default();
            let result = super::execute_context_lazy_loop(
                &plan,
                haystack,
                SearchWindow::full(haystack),
                workspace,
                &mut meter,
                OutputContract::EarliestEnd,
                0,
                Some(&scanner),
                None,
                None,
                false,
                false,
                &mut adaptive_probe,
            )
            .unwrap()
            .unwrap();
            (result, meter.consumed)
        };

        let mut cold_miss =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        assert_eq!(run(&mut cold_miss, b"xxxx"), ((None, 0), 4));
        assert!(!cold_miss.lazy.initialized);
        assert_eq!(cold_miss.lazy.state_len, 0);
        assert_eq!(cold_miss.lazy.item_len, 0);
        assert_eq!(cold_miss.lazy.context.occupied_slots(), 0);

        let mut warm = K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let (cold_result, cold_work) = run(&mut warm, b"a\n");
        assert_eq!(cold_result, (Some(MatchSpan::new(0, 1)), 2));
        assert!(warm.lazy.initialized);
        assert!(warm.lazy.state_len > 0);
        assert!(warm.lazy.item_len > 0);
        let warm_state_len = warm.lazy.state_len;
        let warm_item_len = warm.lazy.item_len;
        let warm_slots = warm.lazy.context.occupied_slots();
        assert!(warm_slots > 0);

        let (cached_result, cached_work) = run(&mut warm, b"a\n");
        assert_eq!(cached_result, cold_result);
        assert!(
            cached_work < cold_work,
            "the second contextual execution must use its retained cache"
        );
        assert_eq!(warm.lazy.state_len, warm_state_len);
        assert_eq!(warm.lazy.item_len, warm_item_len);
        assert_eq!(warm.lazy.context.occupied_slots(), warm_slots);

        assert_eq!(run(&mut warm, b"xxxx"), ((None, 0), 4));
        assert_eq!(warm.lazy.state_len, warm_state_len);
        assert_eq!(warm.lazy.item_len, warm_item_len);
        assert_eq!(warm.lazy.context.occupied_slots(), warm_slots);

        let no_scanner = asserted_line_a();
        let mut no_scanner_workspace =
            K0Workspace::new_accelerated(&no_scanner, WorkspaceLimits::unlimited()).unwrap();
        let mut no_scanner_meter = WorkMeter::new(u64::MAX, 0);
        let mut no_scanner_probe = super::AdaptiveStartProbe::default();
        let empty = super::execute_context_lazy_loop(
            &no_scanner,
            b"",
            SearchWindow::new(0, 0),
            &mut no_scanner_workspace,
            &mut no_scanner_meter,
            OutputContract::EarliestEnd,
            0,
            None,
            None,
            None,
            false,
            false,
            &mut no_scanner_probe,
        )
        .unwrap();
        assert_eq!(empty, Some((None, 0)));
        assert!(no_scanner_workspace.lazy.initialized);
        assert!(no_scanner_meter.consumed > 0);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "offset clipping and both public contracts share one proof and window matrix"
    )]
    fn contextual_candidate_first_handles_offset_scanners_clipped_windows_and_span_contracts() {
        let plan = digit_slash_then_line_end_or_bang();
        let haystack = &[0xff, b'x', b'5', b'/', b'\n', 0x80];
        let mut proof_workspace = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
        plan.prepare::<Span>()
            .search_with_workspace(haystack, &mut proof_workspace, SearchLimits::unlimited())
            .unwrap();
        let proof = plan
            .start_filter_proof
            .get()
            .expect("successful search publishes the offset scanner");
        assert_eq!(
            proof,
            &StartFilterProof {
                scanner: Some(positioned_scanner(1, StartScanner::One(b'/'))),
                filter: Some(StartPositionFilter::Guard(StartPositionClass {
                    offset: 0,
                    set: byte_range_set(b'0', b'9'),
                })),
                force_haystack_start: false,
                relaxed_nullable: false,
            }
        );
        let scanner = proof.scanner.as_ref().unwrap();
        let guard = proof.guard();

        let windows = [
            SearchWindow::full(haystack),
            SearchWindow::new(1, 5),
            // The assertion at byte boundary 4 observes the original newline
            // even though the search window ends immediately before it.
            SearchWindow::new(2, 4),
            SearchWindow::new(2, 3),
            SearchWindow::new(3, 5),
        ];
        for window in windows {
            let mut ordinary = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
            let expected_end = plan
                .prepare::<SelectedEnd>()
                .search_window_with_workspace(
                    haystack,
                    window,
                    &mut ordinary,
                    SearchLimits::unlimited(),
                )
                .unwrap();
            let mut ordinary_span = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
            let expected_span = plan
                .prepare::<Span>()
                .search_window_with_workspace(
                    haystack,
                    window,
                    &mut ordinary_span,
                    SearchLimits::unlimited(),
                )
                .unwrap();

            for limits in [SearchLimits::default(), SearchLimits::unlimited()] {
                let mut endpoint =
                    K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
                let actual_end = plan
                    .prepare::<SelectedEnd>()
                    .search_window_with_workspace(haystack, window, &mut endpoint, limits)
                    .unwrap();
                assert_eq!(actual_end.output(), expected_end.output());
                assert_eq!(
                    actual_end.accounting().boundaries(),
                    expected_end.accounting().boundaries(),
                    "SelectedEnd boundary mismatch window={window:?} limits={limits:?}"
                );

                let mut bidirectional =
                    K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
                let actual_span = plan
                    .prepare::<Span>()
                    .search_window_with_workspace(haystack, window, &mut bidirectional, limits)
                    .unwrap();
                assert_eq!(actual_span.output(), expected_span.output());
                if actual_span.output().is_none() {
                    assert_eq!(actual_span.accounting().boundaries(), 0);
                }
            }
        }

        assert_context_candidate_first_case(
            "offset-scanner-original-context",
            &plan,
            haystack,
            SearchWindow::new(2, 4),
            scanner,
            guard,
            false,
        );

        let mut clipped =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut clipped_meter = WorkMeter::new(u64::MAX, 0);
        let mut clipped_probe = super::AdaptiveStartProbe::default();
        let clipped_result = super::execute_context_lazy_loop(
            &plan,
            haystack,
            SearchWindow::new(2, 3),
            &mut clipped,
            &mut clipped_meter,
            OutputContract::SelectedEnd,
            0,
            Some(scanner),
            guard,
            None,
            false,
            false,
            &mut clipped_probe,
        )
        .unwrap();
        assert_eq!(clipped_result, Some((None, 0)));
        assert_eq!(clipped_meter.consumed, 0);
        assert!(!clipped.lazy.initialized);
        assert_eq!(clipped.lazy.context.occupied_slots(), 0);
    }

    #[test]
    fn byte_range_bitmap_matches_every_scalar_bound_pair() {
        for start in 0_u8..=u8::MAX {
            for end in start..=u8::MAX {
                let mut words = [0_u64; 4];
                super::insert_byte_range(&mut words, start, end);
                let set = ByteSet::from_words(words);
                for byte in 0_u8..=u8::MAX {
                    assert_eq!(
                        set.contains(byte),
                        (start..=end).contains(&byte),
                        "bitmap mismatch for {start:#04x}..={end:#04x} at {byte:#04x}"
                    );
                }
            }
        }
    }

    #[test]
    fn class_selection_is_exact_bounded_and_prefers_root_then_deepest_ties() {
        let sets = [
            byte_set(b"Q"),
            byte_set(b"ab"),
            ByteSet::ALL,
            byte_set(b"Z"),
        ];
        let expected = expected_start_class_selection_work(sets.len());

        let mut exact = WorkMeter::new(expected, 0);
        let selected = super::select_start_classes(&sets, &mut exact, 19).unwrap();
        assert_eq!(
            selected.scanner,
            StartPositionClass {
                offset: 0,
                set: byte_set(b"Q"),
            }
        );
        assert_eq!(selected.scanner_cardinality, 1);
        assert_eq!(
            selected.guard,
            Some(StartPositionClass {
                offset: 3,
                set: byte_set(b"Z"),
            })
        );
        assert_eq!(exact.consumed, expected);

        let mut one_below = WorkMeter::new(expected - 1, 0);
        let error = super::select_start_classes(&sets, &mut one_below, 19).unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit,
                consumed: 22,
                requested: 1,
                position: 19,
            } if limit == expected - 1
        ));

        let mut population_refusal = WorkMeter::new(3, 0);
        let error = super::select_start_classes(&sets, &mut population_refusal, 23).unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit: 3,
                consumed: 0,
                requested: 4,
                position: 23,
            }
        ));

        let tied = [byte_set(b"Q"), byte_set(b"a"), ByteSet::ALL, byte_set(b"Z")];
        let mut tied_meter = WorkMeter::new(u64::MAX, 0);
        let tied = super::select_start_classes(&tied, &mut tied_meter, 0).unwrap();
        assert_eq!(tied.scanner.offset, 0);
        assert_eq!(
            tied.guard.expect("two selective non-scanner classes"),
            StartPositionClass {
                offset: 3,
                set: byte_set(b"Z"),
            }
        );

        let shallow_is_smaller = [
            byte_set(b"Q"),
            byte_set(b"a"),
            ByteSet::ALL,
            byte_set(b"YZ"),
        ];
        let mut shallow_meter = WorkMeter::new(u64::MAX, 0);
        let shallow =
            super::select_start_classes(&shallow_is_smaller, &mut shallow_meter, 0).unwrap();
        assert_eq!(shallow.scanner.offset, 0);
        assert_eq!(
            shallow.guard.expect("two selective non-scanner classes"),
            StartPositionClass {
                offset: 1,
                set: byte_set(b"a"),
            }
        );

        let all_later = [byte_set(b"Q"), ByteSet::ALL, ByteSet::ALL, ByteSet::ALL];
        let mut all_meter = WorkMeter::new(u64::MAX, 0);
        let selected = super::select_start_classes(&all_later, &mut all_meter, 0).unwrap();
        assert_eq!(selected.scanner.offset, 0);
        assert_eq!(selected.guard, None);
        assert_eq!(all_meter.consumed, expected);

        let no_root_tie = [
            byte_set(b"ab"),
            byte_set(b"Z"),
            ByteSet::ALL,
            byte_set(b"Y"),
        ];
        let mut no_root_meter = WorkMeter::new(u64::MAX, 0);
        let selected = super::select_start_classes(&no_root_tie, &mut no_root_meter, 0).unwrap();
        assert_eq!(
            selected.scanner,
            StartPositionClass {
                offset: 3,
                set: byte_set(b"Y"),
            },
            "the deepest equal class wins only when offset zero is not tied"
        );

        let mut extended_scanner_tie = [ByteSet::ALL; START_FILTER_POSITION_COUNT];
        extended_scanner_tie[5] = byte_set(b"Y");
        extended_scanner_tie[15] = byte_set(b"Z");
        let mut extended_scanner_meter = WorkMeter::new(u64::MAX, 0);
        let selected =
            super::select_start_classes(&extended_scanner_tie, &mut extended_scanner_meter, 0)
                .unwrap();
        assert_eq!(
            selected.scanner,
            StartPositionClass {
                offset: 5,
                set: byte_set(b"Y"),
            },
            "extended equal-cardinality positions must not displace the stable scanner"
        );

        let mut extended_guard_tie = [ByteSet::ALL; START_FILTER_POSITION_COUNT];
        extended_guard_tie[0] = byte_set(b"Q");
        extended_guard_tie[5] = byte_set(b"Y");
        extended_guard_tie[15] = byte_set(b"Z");
        let mut extended_guard_meter = WorkMeter::new(u64::MAX, 0);
        let selected =
            super::select_start_classes(&extended_guard_tie, &mut extended_guard_meter, 0).unwrap();
        assert_eq!(selected.scanner.offset, 0);
        assert_eq!(
            selected.guard,
            Some(StartPositionClass {
                offset: 5,
                set: byte_set(b"Y"),
            }),
            "extended equal-cardinality positions must not displace the stable guard"
        );

        let mut strict_extended_improvement = [ByteSet::ALL; START_FILTER_POSITION_COUNT];
        strict_extended_improvement[0] = byte_set(b"QR");
        strict_extended_improvement[5] = byte_set(b"YZ");
        strict_extended_improvement[15] = byte_set(b"!");
        let mut strict_improvement_meter = WorkMeter::new(u64::MAX, 0);
        let selected = super::select_start_classes(
            &strict_extended_improvement,
            &mut strict_improvement_meter,
            0,
        )
        .unwrap();
        assert_eq!(
            selected.scanner,
            StartPositionClass {
                offset: 15,
                set: byte_set(b"!"),
            },
            "a strictly smaller extended class remains eligible"
        );
    }

    #[test]
    fn secondary_filter_boundaries_distinguish_guard_probe_and_all_decline() {
        for cardinality in [63_u8, 64] {
            let maximum_eligible = byte_range_set(0, cardinality - 1);
            let mut maximum_meter = WorkMeter::new(u64::MAX, 0);
            let selected = super::select_start_classes(
                &[byte_set(b"Q"), maximum_eligible],
                &mut maximum_meter,
                0,
            )
            .unwrap();
            assert_eq!(selected.scanner.offset, 0);
            assert_eq!(
                selected.guard,
                Some(StartPositionClass {
                    offset: 1,
                    set: maximum_eligible,
                })
            );
            assert_eq!(selected.probe, None);
            assert_eq!(
                maximum_meter.consumed,
                expected_start_class_selection_work(2)
            );
        }

        for cardinality in [65_u8, 66, 96, 128, 192, 255] {
            let broad = byte_range_set(0, cardinality - 1);
            let mut broad_meter = WorkMeter::new(u64::MAX, 0);
            let selected =
                super::select_start_classes(&[byte_set(b"Q"), broad], &mut broad_meter, 0).unwrap();
            assert_eq!(selected.scanner.offset, 0);
            assert_eq!(selected.guard, None);
            assert_eq!(
                selected.probe,
                Some(StartPositionClass {
                    offset: 1,
                    set: broad,
                })
            );
            assert_eq!(broad_meter.consumed, expected_start_class_selection_work(2));
        }

        let mut all_meter = WorkMeter::new(u64::MAX, 0);
        let all = super::select_start_classes(&[byte_set(b"Q"), ByteSet::ALL], &mut all_meter, 0)
            .unwrap();
        assert_eq!(all.guard, None);
        assert_eq!(all.probe, None);
        assert_eq!(all_meter.consumed, expected_start_class_selection_work(2));

        let broad_then_tied_eligible = [
            byte_set(b"Q"),
            byte_range_set(0, 64),
            byte_set(b"Z"),
            byte_set(b"Y"),
        ];
        let mut eligible_meter = WorkMeter::new(u64::MAX, 0);
        let selected =
            super::select_start_classes(&broad_then_tied_eligible, &mut eligible_meter, 0).unwrap();
        assert_eq!(selected.scanner.offset, 0);
        assert_eq!(
            selected.guard,
            Some(StartPositionClass {
                offset: 3,
                set: byte_set(b"Y"),
            })
        );
        assert_eq!(
            selected.probe,
            Some(StartPositionClass {
                offset: 1,
                set: byte_range_set(0, 64),
            })
        );
        assert_eq!(
            eligible_meter.consumed,
            expected_start_class_selection_work(broad_then_tied_eligible.len())
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the exact state-machine trace keeps every transition and N/N-1 charge adjacent"
    )]
    fn adaptive_probe_state_machine_is_exact_charged_and_failure_atomic() {
        let scanner = root_scanner(StartScanner::One(b'Q'));
        let probe = StartPositionClass {
            offset: 1,
            set: byte_range_set(0x80, 0xc0),
        };
        let source = [b'Q', 0, b'Q', 0, b'Q', 0, b'Q', 0x80, b'Q', 0];
        let mut meter = WorkMeter::new(u64::MAX, 0);
        let mut cursor = super::RetainedStartMaskCursor::default();
        let mut state = super::AdaptiveStartProbe::default();

        let first = super::next_start_candidate_adaptive(
            &scanner,
            &source,
            0,
            source.len(),
            None,
            Some(&probe),
            &mut meter,
            &mut cursor,
            &mut state,
        )
        .unwrap();
        assert_eq!((first, meter.consumed), (0, 1));
        state
            .observe_restartable_rejection(&probe, &source, first, source.len(), &mut meter)
            .unwrap();
        assert_eq!(state.phase, super::AdaptiveProbePhase::Inactive);
        assert_eq!(state.consecutive_rejections, 1);
        assert_eq!(meter.consumed, 2);

        let second = super::next_start_candidate_adaptive(
            &scanner,
            &source,
            1,
            source.len(),
            None,
            Some(&probe),
            &mut meter,
            &mut cursor,
            &mut state,
        )
        .unwrap();
        assert_eq!((second, meter.consumed), (2, 4));
        state
            .observe_restartable_rejection(&probe, &source, second, source.len(), &mut meter)
            .unwrap();
        assert_eq!(state.phase, super::AdaptiveProbePhase::Active);
        assert_eq!(state.consecutive_rejections, 2);
        assert_eq!(meter.consumed, 5);

        // The first active candidate misses and is filtered. The second
        // passes, enters the engine, and disables the Probe permanently.
        let passing = super::next_start_candidate_adaptive(
            &scanner,
            &source,
            3,
            source.len(),
            None,
            Some(&probe),
            &mut meter,
            &mut cursor,
            &mut state,
        )
        .unwrap();
        assert_eq!((passing, meter.consumed), (6, 11));
        assert_eq!(state.phase, super::AdaptiveProbePhase::Disabled);
        assert_eq!(state.consecutive_rejections, 2);

        // Disabled means no checks and no reactivation, even when the next
        // engine candidate misses the broad secondary predicate.
        let disabled = super::next_start_candidate_adaptive(
            &scanner,
            &source,
            7,
            source.len(),
            None,
            Some(&probe),
            &mut meter,
            &mut cursor,
            &mut state,
        )
        .unwrap();
        assert_eq!((disabled, meter.consumed), (8, 13));
        assert_eq!(state.phase, super::AdaptiveProbePhase::Disabled);

        let mut reset_by_pass = super::AdaptiveStartProbe {
            phase: super::AdaptiveProbePhase::Inactive,
            consecutive_rejections: 1,
        };
        let mut pass_meter = WorkMeter::new(1, 0);
        reset_by_pass
            .observe_restartable_rejection(&probe, &source, passing, source.len(), &mut pass_meter)
            .unwrap();
        assert_eq!(reset_by_pass, super::AdaptiveStartProbe::default());

        let mut active = super::AdaptiveStartProbe {
            phase: super::AdaptiveProbePhase::Active,
            consecutive_rejections: 2,
        };
        let before = active;
        let mut refused_meter = WorkMeter::new(1, 0);
        let mut refused_cursor = super::RetainedStartMaskCursor::default();
        let error = super::next_start_candidate_adaptive(
            &scanner,
            b"Q",
            0,
            1,
            None,
            Some(&probe),
            &mut refused_meter,
            &mut refused_cursor,
            &mut active,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit: 1,
                consumed: 1,
                requested: 1,
                position: 0,
            }
        ));
        assert_eq!(
            active, before,
            "a refused active check must not mutate state"
        );

        let mut exact = before;
        let mut exact_meter = WorkMeter::new(2, 0);
        let mut exact_cursor = super::RetainedStartMaskCursor::default();
        assert_eq!(
            super::next_start_candidate_adaptive(
                &scanner,
                b"Q",
                0,
                1,
                None,
                Some(&probe),
                &mut exact_meter,
                &mut exact_cursor,
                &mut exact,
            )
            .unwrap(),
            1
        );
        assert_eq!(exact_meter.consumed, 2);
        assert_eq!(exact, before, "an out-of-window Probe position is a miss");

        let mut postmortem = super::AdaptiveStartProbe {
            phase: super::AdaptiveProbePhase::Inactive,
            consecutive_rejections: 1,
        };
        let postmortem_before = postmortem;
        let mut no_work = WorkMeter::new(0, 0);
        assert!(matches!(
            postmortem.observe_restartable_rejection(&probe, b"Q\0", 0, 2, &mut no_work),
            Err(SearchError::WorkLimitExceeded {
                limit: 0,
                consumed: 0,
                requested: 1,
                position: 0,
            })
        ));
        assert_eq!(postmortem, postmortem_before);
    }

    #[test]
    fn optional_probe_selection_declines_ephemerally_and_retries_without_poisoning() {
        let ranges = [(b'Q', b'Q'), (0, 64)];
        let oracle = byte_chain(&ranges);
        let mut oracle_workspace = K0Workspace::new(&oracle, WorkspaceLimits::unlimited()).unwrap();
        let mut derivation_meter = WorkMeter::new(u64::MAX, 0);
        let derived = super::derive_start_position_classes(
            &oracle,
            &mut oracle_workspace,
            &mut derivation_meter,
            0,
        )
        .unwrap();
        assert_eq!(derived.length, 2);
        let before_optional = derivation_meter
            .consumed
            .checked_add(expected_start_class_selection_work(2))
            .and_then(|work| work.checked_add(expected_scanner_construction_work(b"Q")))
            .unwrap();
        let optional_work = u64::try_from(START_FILTER_PROBE_SELECTION_WORK).unwrap();
        assert_eq!(optional_work, 1);

        let constrained = byte_chain(&ranges);
        let mut constrained_workspace =
            K0Workspace::new(&constrained, WorkspaceLimits::unlimited()).unwrap();
        let mut constrained_meter = WorkMeter::new(before_optional, 0);
        let constrained_proof = super::prepare_start_filter(
            &constrained,
            &mut constrained_workspace,
            &mut constrained_meter,
            0,
            0,
        )
        .unwrap();
        assert_eq!(constrained_meter.consumed, before_optional);
        match constrained_proof {
            super::InvocationStartProof::Pending { proof, publish } => {
                assert!(
                    !publish,
                    "a resource-dependent degraded proof must be ephemeral"
                );
                assert!(matches!(
                    proof.scanner,
                    Some(StartPositionScanner {
                        offset: 0,
                        scanner: StartScanner::One(b'Q'),
                    })
                ));
                assert_eq!(proof.filter, None);
            }
            super::InvocationStartProof::Published(_) => {
                panic!("a cold constrained invocation unexpectedly borrowed a proof")
            }
        }
        assert!(constrained.start_filter_proof.get().is_none());

        let exact = byte_chain(&ranges);
        let mut exact_workspace = K0Workspace::new(&exact, WorkspaceLimits::unlimited()).unwrap();
        let mut exact_meter = WorkMeter::new(u64::MAX, 0);
        let exact_proof =
            super::prepare_start_filter(&exact, &mut exact_workspace, &mut exact_meter, 0, 0)
                .unwrap();
        assert_eq!(exact_meter.consumed, before_optional + optional_work);
        match exact_proof {
            super::InvocationStartProof::Pending { proof, publish } => {
                assert!(publish);
                assert!(matches!(
                    proof.probe(),
                    Some(StartPositionClass { offset: 1, set })
                        if *set == byte_range_set(0, 64)
                ));
            }
            super::InvocationStartProof::Published(_) => {
                panic!("a cold exact invocation unexpectedly borrowed a proof")
            }
        }

        // A finite public call reserves a complete ordinary-K0 allowance.
        // One unit below Probe admission must therefore succeed with the
        // scanner-only ephemeral proof and leave later publication retryable.
        let source = b"Q\xffQ\xffQ\x20";
        let expected_output = Some(MatchSpan::new(4, 6));
        let public_constrained = byte_chain(&ranges);
        let mut public_constrained_workspace =
            K0Workspace::new(&public_constrained, WorkspaceLimits::unlimited()).unwrap();
        let runtime_reserve = public_constrained
            .conservative_post_start_filter_work_bound(source.len())
            .unwrap();
        let completion_reserve =
            super::start_probe_completion_reserve(&public_constrained, source.len());
        assert_eq!(
            completion_reserve,
            runtime_reserve
                .checked_add(super::START_FILTER_OWNER_ALLOCATION_WORK)
                .unwrap(),
            "finite Probe selection must preserve both execution and owner publication"
        );
        let one_below_limit = INVOCATION_RESET_WORK
            .checked_add(before_optional)
            .and_then(|work| work.checked_add(completion_reserve))
            .unwrap();
        let one_below = public_constrained
            .prepare::<Span>()
            .search_with_workspace(
                source,
                &mut public_constrained_workspace,
                SearchLimits {
                    max_work: one_below_limit,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap();
        assert_eq!(one_below.accounting().setup().allocated_bytes(), 0);
        assert_eq!(one_below.into_output(), expected_output);
        assert!(
            public_constrained.start_filter_proof.get().is_none(),
            "a scanner-only finite success must not poison immutable publication"
        );

        let public_exact = byte_chain(&ranges);
        let mut public_exact_workspace =
            K0Workspace::new(&public_exact, WorkspaceLimits::unlimited()).unwrap();
        let exact_limit = one_below_limit.checked_add(optional_work).unwrap();
        let exact_report = public_exact
            .prepare::<Span>()
            .search_with_workspace(
                source,
                &mut public_exact_workspace,
                SearchLimits {
                    max_work: exact_limit,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap();
        assert_eq!(
            exact_report.accounting().setup().allocated_bytes(),
            StartFilterProofCell::PAYLOAD_BYTES,
            "the exact finite selection allowance must publish its owner"
        );
        assert_eq!(exact_report.into_output(), expected_output);
        assert!(matches!(
            public_exact
                .start_filter_proof
                .get()
                .expect("the exact selection allowance publishes the complete proof")
                .probe(),
            Some(StartPositionClass { offset: 1, set })
                if *set == byte_range_set(0, 64)
        ));

        // Once the proof is warm, its exact reported runtime limit remains a
        // hard boundary: N succeeds identically and N-1 is the incumbent
        // typed work error. The failed invocation cannot leak adaptive state.
        let warm = public_exact
            .prepare::<Span>()
            .search_with_workspace(
                source,
                &mut public_exact_workspace,
                SearchLimits::unlimited(),
            )
            .unwrap();
        let warm_work = warm.accounting().work();
        let exact_warm = public_exact
            .prepare::<Span>()
            .search_with_workspace(
                source,
                &mut public_exact_workspace,
                SearchLimits {
                    max_work: warm_work,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap();
        assert_eq!(exact_warm.output(), warm.output());
        assert_eq!(exact_warm.accounting(), warm.accounting());
        let one_below_runtime = public_exact
            .prepare::<Span>()
            .search_with_workspace(
                source,
                &mut public_exact_workspace,
                SearchLimits {
                    max_work: warm_work.checked_sub(1).unwrap(),
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(
            one_below_runtime,
            SearchError::WorkLimitExceeded { .. }
        ));
        let runtime_recovery = public_exact
            .prepare::<Span>()
            .search_with_workspace(
                source,
                &mut public_exact_workspace,
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(runtime_recovery.output(), warm.output());
        assert_eq!(runtime_recovery.accounting(), warm.accounting());

        // Unlimited recovery after the ephemeral success must be identical to
        // a fresh unlimited call and publish the complete Probe.
        let retry = public_constrained
            .prepare::<Span>()
            .search_with_workspace(
                source,
                &mut public_constrained_workspace,
                SearchLimits::unlimited(),
            )
            .unwrap();
        let fresh = byte_chain(&ranges);
        let mut fresh_workspace = K0Workspace::new(&fresh, WorkspaceLimits::unlimited()).unwrap();
        let fresh_report = fresh
            .prepare::<Span>()
            .search_with_workspace(source, &mut fresh_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(retry.output(), fresh_report.output());
        assert_eq!(retry.accounting(), fresh_report.accounting());
        let published = public_constrained
            .start_filter_proof
            .get()
            .expect("the richer retry must publish the complete proof");
        assert!(matches!(
            published.probe(),
            Some(StartPositionClass { offset: 1, set })
                if *set == byte_range_set(0, 64)
        ));
    }

    #[test]
    fn guarded_scanner_honors_window_end_and_exact_incremental_work() {
        let scanner = root_scanner(StartScanner::One(b'a'));
        let guard = StartPositionClass {
            offset: 1,
            set: byte_set(b"b"),
        };
        let haystack = b"_aaab_";

        let mut exact = WorkMeter::new(6, 0);
        assert_eq!(
            super::next_start_candidate(&scanner, haystack, 1, 5, Some(&guard), &mut exact,)
                .unwrap(),
            3
        );
        assert_eq!(exact.consumed, 6);

        let mut one_below = WorkMeter::new(5, 0);
        let error =
            super::next_start_candidate(&scanner, haystack, 1, 5, Some(&guard), &mut one_below)
                .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit: 5,
                consumed: 5,
                requested: 1,
                position: 3,
            }
        ));

        let mut clipped = WorkMeter::new(6, 0);
        assert_eq!(
            super::next_start_candidate(&scanner, haystack, 1, 4, Some(&guard), &mut clipped,)
                .unwrap(),
            4
        );
        assert_eq!(clipped.consumed, 6);

        let high_and_nul = StartPositionClass {
            offset: 2,
            set: byte_set(&[0, 0xff]),
        };
        let mut high_meter = WorkMeter::new(u64::MAX, 0);
        assert_eq!(
            super::next_start_candidate(
                &root_scanner(scanner_for(&[0x80, 0xfe])),
                &[0x80, b'x', 0xff, 0xfe, b'x', 0],
                0,
                6,
                Some(&high_and_nul),
                &mut high_meter,
            )
            .unwrap(),
            0
        );
        assert_eq!(high_meter.consumed, 2);
    }

    #[test]
    fn contiguous_start_ranges_are_selected_without_displacing_small_scanners() {
        for (start, end) in [
            (0_u8, 3_u8),
            (62, 65),
            (0x7e, 0x81),
            (0x80, 0x9f),
            (0xfc, 0xff),
            (0, 0xfe),
        ] {
            let set = byte_range_set(start, end);
            let mut meter = WorkMeter::new(u64::MAX, 0);
            let scanner = super::byte_start_scanner(set, &mut meter, 0).unwrap();
            assert_eq!(scanner, StartScanner::Range { start, end });
            assert_eq!(
                meter.consumed,
                u64::try_from(BYTE_START_BITMAP_POPULATION_WORK + BYTE_START_RANGE_DETECTION_WORK)
                    .unwrap()
            );
        }

        for (bytes, expected) in [
            (&[0x80][..], StartScanner::One(0x80)),
            (&[0x80, 0x81][..], StartScanner::Two(0x80, 0x81)),
            (
                &[0x80, 0x81, 0x82][..],
                StartScanner::Three(0x80, 0x81, 0x82),
            ),
        ] {
            assert_eq!(scanner_for(bytes), expected);
        }

        let ascii_hole = scanner_for(&[0, 1, 3, 4]);
        assert!(matches!(ascii_hole, StartScanner::AsciiSet { .. }));
        let full_byte_hole = scanner_for(&[0x7f, 0x80, 0x82, 0x83]);
        assert!(matches!(full_byte_hole, StartScanner::Set(_)));
    }

    #[test]
    fn start_range_mask_is_exact_for_all_interval_boundaries_and_lanes() {
        for start in 0_u8..=u8::MAX {
            for end in [start, start.saturating_add(1), u8::MAX] {
                let block: [u8; fre_simd_kernels::BYTE_SET_BLOCK_BYTES] =
                    core::array::from_fn(|lane| {
                        u8::try_from(
                            lane.wrapping_mul(197)
                                .wrapping_add(usize::from(start))
                                .wrapping_add(usize::from(end))
                                & 255,
                        )
                        .unwrap()
                    });
                let actual =
                    classify_byte_delta_16(start, end.wrapping_sub(start), &block).member_mask();
                let expected = block.iter().enumerate().fold(0_u16, |mask, (lane, &byte)| {
                    mask | (u16::from((start..=end).contains(&byte)) << lane)
                });
                assert_eq!(
                    actual, expected,
                    "range {start:#04x}..={end:#04x} block={block:?}"
                );
            }
        }
    }

    #[test]
    fn byte_start_scanners_match_scalar_reference_for_every_window() {
        let scanner_sets: &[&[u8]] = &[
            &[],
            b"\0",
            b"a",
            b"ac",
            b"ac\x7f",
            b"\x80\xff",
            b"\0a\xff",
            b"\0\x01\x02\x03",
            b"abcd",
            b"\x7e\x7f\x80\x81",
            b"\xfc\xfd\xfe\xff",
            b"\x3f\x40AB",
            b"\x80\x81\x8f\x90",
            b"\0\x1f\x40\x7f\x80\xbf\xc0\xff",
        ];
        let mut haystacks = bounded_words(
            &[
                b'?', b'@', b'A', b'B', b'a', b'b', b'c', b'd', b'x', 0x7f, 0x80, 0xff,
            ],
            3,
        );
        let mut long = vec![0x80; 65];
        for (position, byte) in [
            (1, b'a'),
            (15, b'b'),
            (16, b'c'),
            (31, b'd'),
            (32, 0x7f),
            (63, b'a'),
        ] {
            long[position] = byte;
        }
        haystacks.push(long);

        for &bytes in scanner_sets {
            let scanner = root_scanner(scanner_for(bytes));
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let expected = (start..end)
                            .find(|&position| bytes.contains(&haystack[position]))
                            .unwrap_or(end);
                        let mut meter = WorkMeter::new(u64::MAX, 0);
                        let actual = super::next_start_candidate(
                            &scanner, haystack, start, end, None, &mut meter,
                        )
                        .unwrap();
                        assert_eq!(
                            actual, expected,
                            "scanner {bytes:?} disagreed in {start}..{end} of {haystack:?}"
                        );

                        let expected_work = match scanner.scanner {
                            StartScanner::AsciiSet { .. } => {
                                expected_ascii_scanner_work(start, end, expected)
                            }
                            StartScanner::Set(_) | StartScanner::Range { .. } => {
                                expected_full_byte_scanner_work(start, end, expected)
                            }
                            StartScanner::Empty => 0,
                            StartScanner::One(_)
                            | StartScanner::Two(_, _)
                            | StartScanner::Three(_, _, _) => {
                                if expected == end {
                                    u64::try_from(end - start).unwrap()
                                } else {
                                    u64::try_from(expected - start + 1).unwrap()
                                }
                            }
                        };
                        assert_eq!(
                            meter.consumed, expected_work,
                            "scanner {bytes:?} charged unexpected physical work in {start}..{end}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn retained_start_masks_match_scalar_sequences_for_all_eligible_scanners_and_windows() {
        let cases: [(&str, StartScanner, &[u8]); 3] = [
            (
                "range",
                scanner_for_set(byte_range_set(0x20, 0x7f)),
                &[0x20, 0x41, 0x7f],
            ),
            ("ascii-set", scanner_for_set(byte_set(b"aceg")), b"aceg"),
            (
                "full-set",
                scanner_for_set(byte_set(&[0x80, 0x82, 0xfe, 0xff])),
                &[0x80, 0x82, 0xfe, 0xff],
            ),
        ];
        assert!(matches!(cases[0].1, StartScanner::Range { .. }));
        assert!(matches!(cases[1].1, StartScanner::AsciiSet { .. }));
        assert!(matches!(cases[2].1, StartScanner::Set(_)));

        for (name, scanner, members) in cases {
            let nonmember = (0_u8..=u8::MAX)
                .find(|&byte| !scanner_contains(&scanner, byte))
                .unwrap();
            let mut haystack = vec![nonmember; 70];
            for (position, byte) in haystack.iter_mut().enumerate() {
                if position % 5 != 1 {
                    *byte = members[position % members.len()];
                }
            }
            let scanner = positioned_scanner(3, scanner);
            let accepting = StartPositionClass {
                offset: 0,
                set: byte_set(&[members[0], members[members.len() - 1]]),
            };
            let rejecting = StartPositionClass {
                offset: 0,
                set: byte_set(&[nonmember.wrapping_add(1)]),
            };

            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    for guard in [None, Some(&accepting), Some(&rejecting)] {
                        let expected = (start..end)
                            .filter(|&candidate| {
                                let Some(scan_position) = candidate.checked_add(3) else {
                                    return false;
                                };
                                if scan_position >= end
                                    || !scanner_contains(&scanner.scanner, haystack[scan_position])
                                {
                                    return false;
                                }
                                guard.is_none_or(|guard| {
                                    let guard_position =
                                        candidate.checked_add(usize::from(guard.offset)).unwrap();
                                    guard_position < end
                                        && guard.set.contains(haystack[guard_position])
                                })
                            })
                            .collect::<Vec<_>>();
                        let (actual, _) =
                            retained_candidate_sequence(&scanner, guard, &haystack, start, end);
                        assert_eq!(
                            actual, expected,
                            "{name} retained sequence disagreed for {start}..{end} guard={guard:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one accounting matrix covers each eligible classifier and every uncached edge"
    )]
    fn retained_start_masks_charge_complete_blocks_once_and_keep_scalar_edges_uncached() {
        let ascii = root_scanner(scanner_for_set(byte_set(b"aceg")));
        assert!(matches!(&ascii.scanner, StartScanner::AsciiSet { .. }));
        let dense = [b'a'; ASCII_WIDE_BYTES];

        let mut legacy = WorkMeter::new(u64::MAX, 0);
        assert_eq!(
            super::next_start_candidate(&ascii, &dense, 0, dense.len(), None, &mut legacy).unwrap(),
            0
        );
        assert_eq!(legacy.consumed, u64::try_from(ASCII_WIDE_BYTES).unwrap());

        let mut cursor = super::RetainedStartMaskCursor::default();
        let mut meter = WorkMeter::new(u64::MAX, 0);
        let mut previous_work = 0;
        for position in 0..dense.len() {
            assert_eq!(
                super::next_start_candidate_retained(
                    &ascii,
                    &dense,
                    position,
                    dense.len(),
                    None,
                    &mut meter,
                    &mut cursor,
                )
                .unwrap(),
                position
            );
            assert!(meter.consumed >= previous_work);
            assert_eq!(meter.consumed, u64::try_from(ASCII_WIDE_BYTES).unwrap());
            previous_work = meter.consumed;
        }
        assert_eq!(
            super::next_start_candidate_retained(
                &ascii,
                &dense,
                dense.len(),
                dense.len(),
                None,
                &mut meter,
                &mut cursor,
            )
            .unwrap(),
            dense.len()
        );
        assert_eq!(cursor, super::RetainedStartMaskCursor::default());

        for (name, scanner) in [
            (
                "range",
                root_scanner(scanner_for_set(byte_range_set(0x20, 0x7f))),
            ),
            (
                "full-set",
                root_scanner(scanner_for_set(byte_set(&[0x80, 0x82, 0xfe, 0xff]))),
            ),
        ] {
            let member = if name == "range" { 0x41 } else { 0x82 };
            let nonmember = if name == "range" { 0xff } else { 0x00 };

            let mut classified = vec![nonmember; BYTE_SET_BLOCK_BYTES * 2];
            classified[BYTE_SET_BLOCK_BYTES..].fill(member);
            let mut classified_cursor = super::RetainedStartMaskCursor::default();
            let mut classified_meter = WorkMeter::new(u64::MAX, 0);
            assert_eq!(
                super::next_start_candidate_retained(
                    &scanner,
                    &classified,
                    0,
                    classified.len(),
                    None,
                    &mut classified_meter,
                    &mut classified_cursor,
                )
                .unwrap(),
                BYTE_SET_BLOCK_BYTES,
                "{name} first classified member"
            );
            assert_eq!(
                classified_meter.consumed,
                u64::try_from(BYTE_SET_BLOCK_BYTES * 2).unwrap()
            );
            assert_eq!(
                usize::from(classified_cursor.width),
                BYTE_SET_BLOCK_BYTES,
                "{name} complete classifier width"
            );
            let before = classified_meter.consumed;
            assert_eq!(
                super::next_start_candidate_retained(
                    &scanner,
                    &classified,
                    BYTE_SET_BLOCK_BYTES + 1,
                    classified.len(),
                    None,
                    &mut classified_meter,
                    &mut classified_cursor,
                )
                .unwrap(),
                BYTE_SET_BLOCK_BYTES + 1
            );
            assert_eq!(classified_meter.consumed, before);

            let mut incomplete = vec![nonmember; BYTE_SET_BLOCK_BYTES * 2 - 1];
            *incomplete.last_mut().unwrap() = member;
            let mut incomplete_cursor = super::RetainedStartMaskCursor::default();
            let mut incomplete_meter = WorkMeter::new(u64::MAX, 0);
            assert_eq!(
                super::next_start_candidate_retained(
                    &scanner,
                    &incomplete,
                    0,
                    incomplete.len(),
                    None,
                    &mut incomplete_meter,
                    &mut incomplete_cursor,
                )
                .unwrap(),
                incomplete.len() - 1
            );
            assert_eq!(
                incomplete_cursor,
                super::RetainedStartMaskCursor::default(),
                "{name} scalar tail must not be retained"
            );
        }

        for length in [15_usize, 16, 17, 31, 32, 33] {
            let source = vec![b'a'; length];
            let mut cursor = super::RetainedStartMaskCursor::default();
            let mut meter = WorkMeter::new(u64::MAX, 0);
            let _ = super::next_start_candidate_retained(
                &ascii,
                &source,
                0,
                length,
                None,
                &mut meter,
                &mut cursor,
            )
            .unwrap();
            assert_eq!(
                usize::from(cursor.width),
                if length >= ASCII_WIDE_BYTES {
                    ASCII_WIDE_BYTES
                } else if length >= ASCII_NARROW_BYTES {
                    ASCII_NARROW_BYTES
                } else {
                    0
                },
                "ASCII retained width at length {length}"
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one exact-limit transaction covers classification and guard rejection together"
    )]
    fn retained_start_mask_classification_and_guard_limits_are_exact() {
        let scanner = root_scanner(scanner_for_set(byte_set(b"aceg")));
        let mut last_lane = [0x80; ASCII_WIDE_BYTES];
        last_lane[ASCII_WIDE_BYTES - 1] = b'a';

        let exact_work = u64::try_from(ASCII_WIDE_BYTES).unwrap();
        let mut exact_cursor = super::RetainedStartMaskCursor::default();
        let mut exact = WorkMeter::new(exact_work, 0);
        assert_eq!(
            super::next_start_candidate_retained(
                &scanner,
                &last_lane,
                0,
                last_lane.len(),
                None,
                &mut exact,
                &mut exact_cursor,
            )
            .unwrap(),
            last_lane.len() - 1
        );
        assert_eq!(exact.consumed, exact_work);

        let mut refused_cursor = super::RetainedStartMaskCursor::default();
        let mut refused = WorkMeter::new(exact_work - 1, 0);
        assert!(matches!(
            super::next_start_candidate_retained(
                &scanner,
                &last_lane,
                0,
                last_lane.len(),
                None,
                &mut refused,
                &mut refused_cursor,
            ),
            Err(SearchError::WorkLimitExceeded {
                limit,
                consumed,
                requested: 1,
                position,
            }) if limit == exact_work - 1
                && consumed == exact_work - 1
                && position == ASCII_WIDE_BYTES - 1
        ));

        let dense = [b'a'; ASCII_WIDE_BYTES];
        let accepting_first_guard = StartPositionClass {
            offset: 1,
            set: byte_set(b"a"),
        };
        let mut accepting_first_cursor = super::RetainedStartMaskCursor::default();
        let mut accepting_first = WorkMeter::new(u64::MAX, 0);
        assert_eq!(
            super::next_start_candidate_retained(
                &scanner,
                &dense,
                0,
                dense.len(),
                Some(&accepting_first_guard),
                &mut accepting_first,
                &mut accepting_first_cursor,
            )
            .unwrap(),
            0
        );
        assert_eq!(accepting_first.consumed, exact_work.checked_add(1).unwrap());

        let rejecting_guard = StartPositionClass {
            offset: 1,
            set: byte_set(b"z"),
        };
        let guarded_work = exact_work.checked_mul(2).unwrap();
        let mut guarded_cursor = super::RetainedStartMaskCursor::default();
        let mut guarded = WorkMeter::new(guarded_work, 0);
        assert_eq!(
            super::next_start_candidate_retained(
                &scanner,
                &dense,
                0,
                dense.len(),
                Some(&rejecting_guard),
                &mut guarded,
                &mut guarded_cursor,
            )
            .unwrap(),
            dense.len()
        );
        assert_eq!(guarded.consumed, guarded_work);

        let mut guarded_refused_cursor = super::RetainedStartMaskCursor::default();
        let mut guarded_refused = WorkMeter::new(guarded_work - 1, 0);
        assert!(matches!(
            super::next_start_candidate_retained(
                &scanner,
                &dense,
                0,
                dense.len(),
                Some(&rejecting_guard),
                &mut guarded_refused,
                &mut guarded_refused_cursor,
            ),
            Err(SearchError::WorkLimitExceeded {
                limit,
                consumed,
                requested: 1,
                position,
            }) if limit == guarded_work - 1
                && consumed == guarded_work - 1
                && position == ASCII_WIDE_BYTES - 1
        ));

        let mut accepts_after_three = dense;
        accepts_after_three[4] = b'z';
        let accepting_guard = StartPositionClass {
            offset: 1,
            set: byte_set(b"z"),
        };
        let mut accepting_cursor = super::RetainedStartMaskCursor::default();
        let mut accepting = WorkMeter::new(u64::MAX, 0);
        assert_eq!(
            super::next_start_candidate_retained(
                &scanner,
                &accepts_after_three,
                0,
                accepts_after_three.len(),
                Some(&accepting_guard),
                &mut accepting,
                &mut accepting_cursor,
            )
            .unwrap(),
            3
        );
        assert_eq!(accepting.consumed, exact_work + 4);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one route differential keeps every cursor-owning K0 loop on the same boundary matrix"
    )]
    fn broad_probe_matches_unfiltered_k0_across_loops_contracts_sessions_and_calls() {
        let range = (0x20_u8..=0x7f).collect::<Vec<_>>();
        let cases: [(&str, Vec<u8>, u8, Option<EdgeKind>); 4] = [
            ("range", range, 0x60, None),
            ("ascii-set", b"aceg".to_vec(), b'a', None),
            ("full-set", vec![0x80, 0x82, 0xfe, 0xff], 0x80, None),
            (
                "context-ascii-set",
                b"aceg".to_vec(),
                b'a',
                Some(EdgeKind::AssertLineStartLf),
            ),
        ];

        for (name, bytes, root_member, assertion) in cases {
            let specialized = byte_class_then_range(&bytes, (0, 64), assertion);
            let reference = byte_class_then_range(&bytes, (0, 64), assertion);
            pin_without_start_filter(&reference);
            let mut reference_workspace =
                K0Workspace::new(&reference, WorkspaceLimits::unlimited()).unwrap();
            let mut filtered =
                K0Workspace::new(&specialized, WorkspaceLimits::unlimited()).unwrap();
            let mut endpoint =
                K0Workspace::new_accelerated(&specialized, WorkspaceLimits::unlimited()).unwrap();
            let mut full =
                K0Workspace::new_bidirectional(&specialized, WorkspaceLimits::unlimited()).unwrap();
            let filtered_bytes = filtered.retained_bytes();
            let endpoint_bytes = endpoint.retained_bytes();
            let full_bytes = full.retained_bytes();

            let mut sources = Vec::new();
            for length in [15_usize, 16, 17, 31, 32, 33, 65] {
                let mut source = vec![0xff; length];
                if assertion.is_some() {
                    for chunk in (0..length).step_by(3) {
                        source[chunk] = b'\n';
                        if chunk + 1 < length {
                            source[chunk + 1] = root_member;
                        }
                    }
                    if length >= 3 {
                        let chunk = ((length - 3) / 3) * 3;
                        source[chunk] = b'\n';
                        source[chunk + 1] = root_member;
                        source[chunk + 2] = 0x20;
                    }
                } else {
                    for position in (0..length).step_by(2) {
                        source[position] = root_member;
                    }
                    if length >= 2 {
                        let candidate = ((length / 2).min(length - 2)) & !1;
                        source[candidate] = root_member;
                        source[candidate + 1] = 0x20;
                    }
                }
                sources.push(source);
            }

            for source in &sources {
                let mut points = vec![0, source.len()];
                points.extend(
                    [1_usize, 2, 14, 15, 16, 17, 30, 31, 32, 33, 64]
                        .into_iter()
                        .filter(|&point| point <= source.len()),
                );
                points.sort_unstable();
                points.dedup();

                for (start_index, &start) in points.iter().enumerate() {
                    for &end in &points[start_index..] {
                        let window = SearchWindow::new(start, end);
                        macro_rules! compare_contract {
                            ($contract:ty) => {{
                                let expected = reference
                                    .prepare::<$contract>()
                                    .search_window_with_workspace(
                                        source,
                                        window,
                                        &mut reference_workspace,
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap()
                                    .into_output();
                                let filtered_output = specialized
                                    .prepare::<$contract>()
                                    .search_window_with_workspace(
                                        source,
                                        window,
                                        &mut filtered,
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap()
                                    .into_output();
                                let endpoint_output = specialized
                                    .prepare::<$contract>()
                                    .search_window_with_workspace(
                                        source,
                                        window,
                                        &mut endpoint,
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap()
                                    .into_output();
                                let full_output = specialized
                                    .prepare::<$contract>()
                                    .search_window_with_workspace(
                                        source,
                                        window,
                                        &mut full,
                                        SearchLimits::unlimited(),
                                    )
                                    .unwrap()
                                    .into_output();
                                assert_eq!(
                                    filtered_output,
                                    expected,
                                    "{name} filtered {} source={source:?} window={window:?}",
                                    stringify!($contract)
                                );
                                assert_eq!(
                                    endpoint_output,
                                    expected,
                                    "{name} endpoint {} source={source:?} window={window:?}",
                                    stringify!($contract)
                                );
                                assert_eq!(
                                    full_output,
                                    expected,
                                    "{name} full {} source={source:?} window={window:?}",
                                    stringify!($contract)
                                );
                            }};
                        }
                        compare_contract!(Exists);
                        compare_contract!(EarliestEnd);
                        compare_contract!(SelectedEnd);
                        compare_contract!(Span);
                    }
                }

                macro_rules! compare_direct {
                    ($contract:ty) => {{
                        let expected = reference
                            .prepare::<$contract>()
                            .search_with_workspace(
                                source,
                                &mut reference_workspace,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        let actual = specialized
                            .prepare::<$contract>()
                            .search(source, SearchLimits::unlimited())
                            .unwrap()
                            .into_output();
                        assert_eq!(
                            actual,
                            expected,
                            "{name} direct {} source={source:?}",
                            stringify!($contract)
                        );
                    }};
                }
                compare_direct!(Exists);
                compare_direct!(EarliestEnd);
                compare_direct!(SelectedEnd);
                compare_direct!(Span);
            }

            assert_eq!(filtered.retained_bytes(), filtered_bytes);
            assert_eq!(endpoint.retained_bytes(), endpoint_bytes);
            assert_eq!(full.retained_bytes(), full_bytes);
            let proof = specialized
                .start_filter_proof
                .get()
                .expect("route differential publishes its start proof");
            match name {
                "range" => {
                    assert!(matches!(
                        proof.scanner,
                        Some(StartPositionScanner {
                            offset: 1,
                            scanner: StartScanner::Range { .. },
                        })
                    ));
                    assert!(matches!(
                        proof.probe(),
                        Some(StartPositionClass { offset: 0, set })
                            if *set == byte_range_set(0x20, 0x7f)
                    ));
                }
                "ascii-set" | "context-ascii-set" => {
                    assert!(matches!(
                        proof.scanner,
                        Some(StartPositionScanner {
                            offset: 0,
                            scanner: StartScanner::AsciiSet { .. },
                        })
                    ));
                    assert!(matches!(
                        proof.probe(),
                        Some(StartPositionClass { offset: 1, set })
                            if *set == byte_range_set(0, 64)
                    ));
                }
                "full-set" => {
                    assert!(matches!(
                        proof.scanner,
                        Some(StartPositionScanner {
                            offset: 0,
                            scanner: StartScanner::Set(_),
                        })
                    ));
                    assert!(matches!(
                        proof.probe(),
                        Some(StartPositionClass { offset: 1, set })
                            if *set == byte_range_set(0, 64)
                    ));
                }
                _ => unreachable!(),
            }

            let source = sources.last().unwrap();
            let mut session = K0SearchSession::new_selected(
                &specialized,
                WorkspaceLimits::unlimited(),
                true,
                true,
            )
            .unwrap();
            assert!(session.root_run.is_none(), "{name} must use ordinary K0");
            let retained = session.construction_accounting().retained_bytes();
            let expected = reference
                .prepare::<Span>()
                .search_with_workspace(source, &mut reference_workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output();
            let first = session
                .search::<Span>(source, SearchLimits::unlimited())
                .unwrap();
            let warm = session
                .search::<Span>(source, SearchLimits::unlimited())
                .unwrap();
            let repeated = session
                .search::<Span>(source, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(first.output(), &expected, "{name} first session call");
            assert_eq!(warm.output(), &expected, "{name} warm session call");
            assert_eq!(repeated.output(), &expected, "{name} repeated session call");
            assert_eq!(warm.accounting().work(), repeated.accounting().work());
            assert_eq!(warm.accounting().scratch_bytes(), retained);
            assert_eq!(repeated.accounting().scratch_bytes(), retained);

            let other = &sources[sources.len() - 2];
            let other_expected = reference
                .prepare::<Span>()
                .search_with_workspace(other, &mut reference_workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output();
            assert_eq!(
                session
                    .search::<Span>(other, SearchLimits::unlimited())
                    .unwrap()
                    .into_output(),
                other_expected,
                "{name} changed-source session call"
            );
            assert_eq!(
                session
                    .search::<Span>(source, SearchLimits::unlimited())
                    .unwrap()
                    .into_output(),
                expected,
                "{name} cursor must not survive a changed-source call"
            );
        }
    }

    #[test]
    fn broad_probe_phase_change_is_differential_and_resets_per_invocation() {
        const CANDIDATE_STRIDE: usize = 20;
        const CANDIDATE_COUNT: usize = 6;

        // The exact suffix lies just outside the bounded 16-position proof.
        // It can therefore disprove a candidate after an active Probe passes,
        // demonstrating that the Probe disables instead of becoming a hidden
        // always-on guard tailored to this pattern.
        let mut ranges = vec![(b'Q', b'Q'), (0, 64)];
        ranges.extend(core::iter::repeat_n((0, 0xff), 14));
        ranges.push((b'Z', b'Z'));
        assert_eq!(ranges.len(), START_FILTER_POSITION_COUNT + 1);

        let specialized = byte_chain(&ranges);
        let reference = byte_chain(&ranges);
        pin_without_start_filter(&reference);

        let mut source = vec![0xff; (CANDIDATE_COUNT - 1) * CANDIDATE_STRIDE + ranges.len()];
        for candidate in 0..CANDIDATE_COUNT {
            source[candidate * CANDIDATE_STRIDE] = b'Q';
        }
        // Candidates zero and one establish two misses. Candidate two is
        // filtered. Candidate three passes the active Probe but fails at the
        // out-of-proof suffix and permanently disables probing. Candidate
        // four must then enter unchecked; candidate five is the real match.
        source[3 * CANDIDATE_STRIDE + 1] = 0x20;
        source[5 * CANDIDATE_STRIDE + 1] = 0x20;
        source[5 * CANDIDATE_STRIDE + START_FILTER_POSITION_COUNT] = b'Z';
        let expected = Some(MatchSpan::new(
            5 * CANDIDATE_STRIDE,
            5 * CANDIDATE_STRIDE + ranges.len(),
        ));

        // Publish once so every workspace below measures the same immutable
        // proof while retaining invocation-local adaptive state.
        assert_eq!(
            specialized
                .prepare::<Span>()
                .search(&source, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            expected
        );
        let proof = specialized
            .start_filter_proof
            .get()
            .expect("phase-change search publishes a proof");
        assert!(matches!(
            proof.scanner,
            Some(StartPositionScanner {
                offset: 0,
                scanner: StartScanner::One(b'Q'),
            })
        ));
        assert!(matches!(
            proof.probe(),
            Some(StartPositionClass { offset: 1, set })
                if *set == byte_range_set(0, 64)
        ));

        let mut reference_workspace =
            K0Workspace::new(&reference, WorkspaceLimits::unlimited()).unwrap();
        let reference_output = reference
            .prepare::<Span>()
            .search_with_workspace(&source, &mut reference_workspace, SearchLimits::unlimited())
            .unwrap()
            .into_output();
        assert_eq!(reference_output, expected);

        let mut pike = K0Workspace::new(&specialized, WorkspaceLimits::unlimited()).unwrap();
        let mut endpoint =
            K0Workspace::new_accelerated(&specialized, WorkspaceLimits::unlimited()).unwrap();
        let mut full =
            K0Workspace::new_bidirectional(&specialized, WorkspaceLimits::unlimited()).unwrap();
        for (name, workspace) in [
            ("pike", &mut pike),
            ("lazy", &mut endpoint),
            ("span", &mut full),
        ] {
            let first = specialized
                .prepare::<Span>()
                .search_with_workspace(&source, workspace, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(first.output(), &reference_output, "{name} first call");
            let second = specialized
                .prepare::<Span>()
                .search_with_workspace(&source, workspace, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(second.output(), &reference_output, "{name} second call");
        }

        // Pike has no transition-learning delta. Equal repeated reports prove
        // that Active/Disabled state does not leak between invocations.
        let pike_first = specialized
            .prepare::<Span>()
            .search_with_workspace(&source, &mut pike, SearchLimits::unlimited())
            .unwrap();
        let pike_second = specialized
            .prepare::<Span>()
            .search_with_workspace(&source, &mut pike, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(pike_first.output(), pike_second.output());
        assert_eq!(pike_first.accounting(), pike_second.accounting());
    }

    #[test]
    fn singleton_exact_positions_never_select_a_broad_probe() {
        for length in 1..=START_FILTER_POSITION_COUNT {
            let sets = vec![byte_set(b"Q"); length];
            let mut meter = WorkMeter::new(u64::MAX, 0);
            let selection = super::select_start_classes(&sets, &mut meter, 0).unwrap();
            assert_eq!(selection.probe, None, "singleton run length {length}");
            assert_eq!(
                selection.guard.is_some(),
                length > 1,
                "singleton run length {length}"
            );
        }
    }

    #[test]
    fn concurrent_broad_probe_first_use_has_one_immutable_owner() {
        let automaton = Arc::new(byte_chain(&[(b'Q', b'Q'), (0, 64)]));
        let source = Arc::<[u8]>::from(&b"Q\xffQ\xffQ\x20"[..]);
        let thread_count = 8;
        let barrier = Arc::new(Barrier::new(thread_count));
        let mut handles = Vec::with_capacity(thread_count);
        for _ in 0..thread_count {
            let automaton = Arc::clone(&automaton);
            let source = Arc::clone(&source);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut workspace =
                    K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
                barrier.wait();
                let report = automaton
                    .prepare::<Span>()
                    .search_with_workspace(&source, &mut workspace, SearchLimits::unlimited())
                    .unwrap();
                (
                    report.into_output(),
                    report.accounting().setup().allocated_bytes(),
                )
            }));
        }
        let reports = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert!(reports
            .iter()
            .all(|(output, _)| output == &Some(MatchSpan::new(4, 6))));
        assert_eq!(
            reports
                .iter()
                .filter(|(_, allocated)| *allocated == StartFilterProofCell::PAYLOAD_BYTES)
                .count(),
            1
        );
        assert!(reports
            .iter()
            .all(|(_, allocated)| *allocated == 0
                || *allocated == StartFilterProofCell::PAYLOAD_BYTES));
        let proof = automaton
            .start_filter_proof
            .get()
            .expect("one racing caller publishes the Probe proof");
        assert!(matches!(
            proof.probe(),
            Some(StartPositionClass { offset: 1, set })
                if *set == byte_range_set(0, 64)
        ));
    }

    #[test]
    fn retained_start_mask_dfa_restart_work_is_exact_and_call_local() {
        let plan = byte_class_then_range(b"aceg", (0, 64), None);
        let mut workspace = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
        let retained = workspace.retained_bytes();
        let mut haystack = [0xff; 65];
        for position in (0..haystack.len()).step_by(2) {
            haystack[position] = b'a';
        }
        haystack[62] = b'a';
        haystack[63] = 0x20;

        let _ = plan
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let measured = plan
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let work = measured.accounting().work();
        let expected = *measured.output();
        assert_eq!(expected, Some(MatchSpan::new(62, 64)));

        let exact = SearchLimits {
            max_work: work,
            max_scratch_bytes: retained,
        };
        assert_eq!(
            plan.prepare::<Span>()
                .search_with_workspace(&haystack, &mut workspace, exact)
                .unwrap()
                .into_output(),
            expected
        );
        assert!(matches!(
            plan.prepare::<Span>().search_with_workspace(
                &haystack,
                &mut workspace,
                SearchLimits {
                    max_work: work - 1,
                    max_scratch_bytes: retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == work - 1
        ));
        assert_eq!(workspace.retained_bytes(), retained);
        assert_eq!(
            plan.prepare::<Span>()
                .search_with_workspace(b"\xff\xffa\x20", &mut workspace, SearchLimits::unlimited(),)
                .unwrap()
                .into_output(),
            Some(MatchSpan::new(2, 4))
        );
        assert_eq!(
            plan.prepare::<Span>()
                .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited(),)
                .unwrap()
                .into_output(),
            expected,
            "a failed limit and changed source must not retain an invocation cursor"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one source-derived ledger keeps retained-mask and adaptive-Probe charges exact"
    )]
    fn accelerated_range_restarts_have_a_source_derived_exact_retained_mask_ledger() {
        const RESTARTS: [usize; 4] = [16, 20, 24, 28];
        const TRANSITION_POSITIONS: [usize; 8] = [16, 17, 20, 21, 24, 25, 28, 29];

        let range = (0x20_u8..=0x60).collect::<Vec<_>>();
        assert_eq!(range.len(), 65, "the root class must exceed the guard cap");
        let plan = byte_class_then_range(&range, (0x80, 0xff), None);
        let mut haystack = [0_u8; 32];
        for &candidate in &RESTARTS {
            haystack[candidate] = 0x40;
        }
        haystack[29] = 0x80;

        let layout = plan.accelerated_workspace_layout().unwrap();
        assert!(layout.lazy_state_capacity > 0);
        assert!(layout.lazy_item_capacity > 0);
        let mut accelerated =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        assert_eq!(accelerated.layout(), layout);
        assert!(accelerated.lazy.is_allocated());
        assert!(!accelerated.lazy.initialized);
        assert!(!accelerated.lazy.declined);
        let retained_bytes = accelerated.retained_bytes();

        let cold = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(&haystack, &mut accelerated, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(cold.output(), &Some(30));
        assert!(accelerated.lazy.initialized);
        assert!(!accelerated.lazy.declined);
        assert!(accelerated.lazy.state_len > 0);

        let bidirectional_layout = plan.bidirectional_workspace_layout().unwrap();
        assert!(bidirectional_layout.lazy_state_capacity > 0);
        assert!(bidirectional_layout.lazy_item_capacity > 0);
        assert!(bidirectional_layout.reverse_state_capacity > 0);
        assert!(bidirectional_layout.reverse_item_capacity > 0);
        let mut bidirectional =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        assert_eq!(bidirectional.layout(), bidirectional_layout);
        assert!(bidirectional.lazy.is_allocated());
        assert!(bidirectional.reverse.is_allocated());
        assert!(!bidirectional.lazy.initialized);
        assert!(!bidirectional.reverse.initialized);
        let cold_span = plan
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut bidirectional, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(cold_span.output(), &Some(MatchSpan::new(28, 30)));
        assert!(bidirectional.lazy.initialized);
        assert!(bidirectional.reverse.initialized);
        assert!(!bidirectional.lazy.declined);
        assert!(!bidirectional.reverse.declined);
        assert!(bidirectional.lazy.state_len > 0);
        assert!(bidirectional.reverse.state_len > 0);
        assert_eq!(
            plan.prepare::<Span>()
                .search_with_workspace(&haystack, &mut bidirectional, SearchLimits::unlimited(),)
                .unwrap()
                .into_output(),
            Some(MatchSpan::new(28, 30))
        );
        let proof = plan
            .start_filter_proof
            .get()
            .expect("the cold run publishes its exact start proof");
        assert!(matches!(
            proof.scanner,
            Some(StartPositionScanner {
                offset: 0,
                scanner: StartScanner::Range {
                    start: 0x20,
                    end: 0x60,
                },
            })
        ));
        assert_eq!(proof.guard(), None);
        assert!(matches!(
            proof.probe(),
            Some(StartPositionClass { offset: 1, set })
                if *set == byte_range_set(0x80, 0xff)
        ));

        // This ledger is derived from the fixed source and the warmed loop,
        // not copied from a candidate report: reset costs three, the first
        // Range call scans a 16-byte scalar prefix plus one complete 16-byte
        // classifier block, and three failed/accepted two-byte DFA attempts
        // visit six positions. The third candidate is removed by the active
        // Probe; two postmortem and two active checks are each charged once.
        // Retained candidates add no second classifier charge.
        let reset_work = INVOCATION_RESET_WORK;
        let first_classifier_work = u64::try_from(BYTE_SET_BLOCK_BYTES)
            .unwrap()
            .checked_mul(2)
            .unwrap();
        let parent_transition_work = u64::try_from(TRANSITION_POSITIONS.len()).unwrap();
        let candidate_transition_work = parent_transition_work.checked_sub(2).unwrap();
        let probe_work = 4_u64;
        let revised_work = reset_work
            .checked_add(first_classifier_work)
            .and_then(|work| work.checked_add(candidate_transition_work))
            .and_then(|work| work.checked_add(probe_work))
            .unwrap();
        assert_eq!(revised_work, 45);

        // The non-retaining entry is the exact-parent scanner algorithm. It
        // must re-scan three bytes after each of the first three DFA failures:
        // 18..=20, 22..=24, and 26..=28. This independently closes the parent
        // scanner ledger at 41 and its complete warmed search at 52.
        let scanner = proof.scanner.as_ref().unwrap();
        let mut parent_scanner = WorkMeter::new(u64::MAX, 0);
        for (&restart, &expected) in [0_usize, 18, 22, 26].iter().zip(&RESTARTS) {
            assert_eq!(
                super::next_start_candidate(
                    scanner,
                    &haystack,
                    restart,
                    haystack.len(),
                    None,
                    &mut parent_scanner,
                )
                .unwrap(),
                expected
            );
        }
        let parent_scanner_work = first_classifier_work
            .checked_add(u64::try_from((RESTARTS.len() - 1) * 3).unwrap())
            .unwrap();
        assert_eq!(parent_scanner.consumed, parent_scanner_work);
        assert_eq!(parent_scanner_work, 41);
        let exact_parent_work = reset_work
            .checked_add(parent_scanner_work)
            .and_then(|work| work.checked_add(parent_transition_work))
            .unwrap();
        assert_eq!(exact_parent_work, 52);
        assert_eq!(exact_parent_work - revised_work, 7);

        let mut retained_scanner = WorkMeter::new(u64::MAX, 0);
        let mut cursor = super::RetainedStartMaskCursor::default();
        for (&restart, &expected) in [0_usize, 18, 22, 26].iter().zip(&RESTARTS) {
            assert_eq!(
                super::next_start_candidate_retained(
                    scanner,
                    &haystack,
                    restart,
                    haystack.len(),
                    None,
                    &mut retained_scanner,
                    &mut cursor,
                )
                .unwrap(),
                expected
            );
        }
        assert_eq!(retained_scanner.consumed, first_classifier_work);

        let measured = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(&haystack, &mut accelerated, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(measured.output(), &Some(30));
        assert_eq!(measured.accounting().setup().work(), reset_work);
        assert_eq!(measured.accounting().transition_work(), 42);
        assert_eq!(measured.accounting().work(), revised_work);
        assert_eq!(measured.accounting().scratch_bytes(), retained_bytes);

        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(
                    &haystack,
                    &mut accelerated,
                    SearchLimits {
                        max_work: revised_work,
                        max_scratch_bytes: retained_bytes,
                    },
                )
                .unwrap()
                .into_output(),
            Some(30)
        );
        assert!(matches!(
            plan.prepare::<SelectedEnd>().search_with_workspace(
                &haystack,
                &mut accelerated,
                SearchLimits {
                    max_work: revised_work - 1,
                    max_scratch_bytes: retained_bytes,
                },
            ),
            Err(SearchError::WorkLimitExceeded {
                limit,
                consumed,
                requested: 1,
                position: 29,
            }) if limit == revised_work - 1 && consumed == revised_work - 1
        ));
        assert_eq!(accelerated.retained_bytes(), retained_bytes);

        let oracle = byte_class_then_range(&range, (0x80, 0xff), None);
        pin_without_start_filter(&oracle);
        let mut oracle_workspace = K0Workspace::new(&oracle, WorkspaceLimits::unlimited()).unwrap();
        assert!(!oracle_workspace.lazy.is_allocated());
        assert_eq!(
            oracle
                .prepare::<SelectedEnd>()
                .search_with_workspace(&haystack, &mut oracle_workspace, SearchLimits::unlimited(),)
                .unwrap()
                .into_output(),
            Some(30)
        );
    }

    #[test]
    fn broad_full_byte_scanners_match_every_window_and_vector_threshold() {
        let mut sets = vec![
            byte_set(&[0x80, 0x81, 0x8e, 0x8f]),
            byte_set(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
            byte_set(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xff]),
            ByteSet::from_words([
                0xaaaa_aaaa_aaaa_aaaa,
                0x5555_5555_5555_5555,
                0x0123_4567_89ab_cdef,
                0xfedc_ba98_7654_3210,
            ]),
        ];
        let explicit_sets = sets.len();
        let mut random = 0xd1b5_4a32_d192_ed03_u64;
        for _ in 0..24 {
            let mut words = core::array::from_fn(|_| next_random_word(&mut random));
            // Keep this matrix on the full-byte path even for an adversarial
            // random draw with an empty upper half.
            words[2] |= 1_u64 << (random & 63);
            sets.push(ByteSet::from_words(words));
        }

        let threshold_lengths = [
            0_usize, 1, 2, 3, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65,
        ];
        for (set_index, set) in sets.into_iter().enumerate() {
            let scanner = root_scanner(scanner_for_set(set));
            let StartScanner::Set(classifier) = &scanner.scanner else {
                panic!("broad non-ASCII set {set_index} did not retain a full-byte classifier");
            };
            assert_eq!(
                classifier.classifier().set().words(),
                set.words(),
                "set {set_index} retained the wrong exact full-byte bitmap"
            );

            for &length in &threshold_lengths {
                let haystack = (0..length)
                    .map(|index| {
                        u8::try_from(
                            (index
                                .wrapping_mul(197)
                                .wrapping_add(set_index.wrapping_mul(61))
                                .wrapping_add(length.wrapping_mul(17)))
                                & 255,
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>();
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let expected = (start..end)
                            .find(|&position| set.contains(haystack[position]))
                            .unwrap_or(end);
                        let mut meter = WorkMeter::new(u64::MAX, 0);
                        let actual = super::next_start_candidate(
                            &scanner, &haystack, start, end, None, &mut meter,
                        )
                        .unwrap();
                        assert_eq!(
                            actual, expected,
                            "full-byte set {set_index} disagreed for {start}..{end} at length {length}"
                        );
                        assert_eq!(
                            meter.consumed,
                            expected_full_byte_scanner_work(start, end, expected),
                            "full-byte set {set_index} charged the wrong work for {start}..{end} at length {length}"
                        );
                    }
                }
            }

            // A complete byte permutation plus every subwindow checks all
            // high-byte values and every possible unaligned vector boundary.
            if set_index < explicit_sets {
                let haystack = (0..=u8::MAX)
                    .map(|byte| {
                        byte.wrapping_mul(197)
                            .wrapping_add(u8::try_from(set_index * 29).unwrap())
                    })
                    .collect::<Vec<_>>();
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let expected = (start..end)
                            .find(|&position| set.contains(haystack[position]))
                            .unwrap_or(end);
                        let mut meter = WorkMeter::new(u64::MAX, 0);
                        let actual = super::next_start_candidate(
                            &scanner, &haystack, start, end, None, &mut meter,
                        )
                        .unwrap();
                        assert_eq!(
                            actual, expected,
                            "full-domain set {set_index} disagreed for {start}..{end}"
                        );
                        assert_eq!(
                            meter.consumed,
                            expected_full_byte_scanner_work(start, end, expected)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn broad_full_byte_scanner_preserves_exact_hard_work_limits() {
        for set in [
            byte_range_set(0x80, 0xff),
            ByteSet::from_words([
                0xaaaa_aaaa_aaaa_aaaa,
                0x5555_5555_5555_5555,
                0x0123_4567_89ab_cdef,
                0xfedc_ba98_7654_3210,
            ]),
        ] {
            let scanner = root_scanner(scanner_for_set(set));
            let nonmember = (0_u8..=u8::MAX)
                .find(|&byte| !set.contains(byte))
                .expect("the test sets leave at least one nonmember");
            for length in [1_usize, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
                let start = 3_usize;
                let end = start.checked_add(length).unwrap();
                let haystack = vec![nonmember; end + 2];
                for limit in 0..=u64::try_from(length).unwrap() {
                    let mut meter = WorkMeter::new(limit, 0);
                    let result = super::next_start_candidate(
                        &scanner, &haystack, start, end, None, &mut meter,
                    );
                    if limit == u64::try_from(length).unwrap() {
                        assert_eq!(result.unwrap(), end);
                        assert_eq!(meter.consumed, limit);
                    } else {
                        let error = result.unwrap_err();
                        assert!(matches!(
                            error,
                            SearchError::WorkLimitExceeded {
                                consumed,
                                requested: 1,
                                position,
                                ..
                            } if consumed == limit
                                && position == start + usize::try_from(limit).unwrap()
                        ));
                        assert_eq!(meter.consumed, limit);
                    }
                }
            }
        }
    }

    #[test]
    fn full_byte_scalar_extents_preserve_exact_and_one_below_work() {
        let range = root_scanner(scanner_for_set(byte_range_set(0x40, 0x7f)));
        assert!(matches!(&range.scanner, StartScanner::Range { .. }));
        let set = root_scanner(scanner_for_set(byte_set(&[0x80, 0x82, 0x84, 0x86])));
        assert!(matches!(&set.scanner, StartScanner::Set(_)));

        let start = 3_usize;
        let length = BYTE_SET_BLOCK_BYTES
            .checked_mul(3)
            .and_then(|extent| extent.checked_sub(1))
            .unwrap();
        let end = start.checked_add(length).unwrap();
        let first_tail = BYTE_SET_BLOCK_BYTES.checked_mul(2).unwrap();
        let initial_work = 7_u64;

        for (name, scanner, member) in [("range", range, 0x55), ("set", set, 0x84)] {
            for candidate_offset in (0..BYTE_SET_BLOCK_BYTES).chain(first_tail..length) {
                let mut haystack = vec![0x20; end.checked_add(2).unwrap()];
                haystack[start.checked_add(candidate_offset).unwrap()] = member;
                let required = u64::try_from(candidate_offset.checked_add(1).unwrap()).unwrap();
                let exact_limit = initial_work.checked_add(required).unwrap();

                let mut exact = WorkMeter::new(exact_limit, initial_work);
                assert_eq!(
                    super::next_start_candidate(&scanner, &haystack, start, end, None, &mut exact,)
                        .unwrap(),
                    start.checked_add(candidate_offset).unwrap(),
                    "{name} scalar candidate at offset {candidate_offset}"
                );
                assert_eq!(exact.consumed, exact_limit);

                let one_below_limit = exact_limit.checked_sub(1).unwrap();
                let mut one_below = WorkMeter::new(one_below_limit, initial_work);
                let error = super::next_start_candidate(
                    &scanner,
                    &haystack,
                    start,
                    end,
                    None,
                    &mut one_below,
                )
                .unwrap_err();
                assert!(matches!(
                    error,
                    SearchError::WorkLimitExceeded {
                        limit,
                        consumed,
                        requested: 1,
                        position,
                    } if limit == one_below_limit
                        && consumed == one_below_limit
                        && position == start + candidate_offset
                ));
                assert_eq!(one_below.consumed, one_below_limit);
            }
        }
    }

    #[test]
    fn ascii_scalar_tail_preserves_exact_and_one_below_work() {
        let scanner = root_scanner(scanner_for_set(byte_set(&[0, 1, 3, 4])));
        assert!(matches!(&scanner.scanner, StartScanner::AsciiSet { .. }));

        let start = 3_usize;
        let vector_extent = ASCII_WIDE_BYTES
            .checked_mul(2)
            .and_then(|extent| extent.checked_add(ASCII_NARROW_BYTES))
            .unwrap();
        let length = vector_extent
            .checked_add(ASCII_NARROW_BYTES)
            .and_then(|extent| extent.checked_sub(1))
            .unwrap();
        let end = start.checked_add(length).unwrap();
        let initial_work = 7_u64;

        for candidate_offset in vector_extent..length {
            let mut haystack = vec![0x80; end.checked_add(2).unwrap()];
            haystack[start.checked_add(candidate_offset).unwrap()] = 3;
            let required = u64::try_from(candidate_offset.checked_add(1).unwrap()).unwrap();
            let exact_limit = initial_work.checked_add(required).unwrap();

            let mut exact = WorkMeter::new(exact_limit, initial_work);
            assert_eq!(
                super::next_start_candidate(&scanner, &haystack, start, end, None, &mut exact,)
                    .unwrap(),
                start.checked_add(candidate_offset).unwrap()
            );
            assert_eq!(exact.consumed, exact_limit);

            let one_below_limit = exact_limit.checked_sub(1).unwrap();
            let mut one_below = WorkMeter::new(one_below_limit, initial_work);
            let error =
                super::next_start_candidate(&scanner, &haystack, start, end, None, &mut one_below)
                    .unwrap_err();
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    limit,
                    consumed,
                    requested: 1,
                    position,
                } if limit == one_below_limit
                    && consumed == one_below_limit
                    && position == start + candidate_offset
            ));
            assert_eq!(one_below.consumed, one_below_limit);
        }
    }

    #[test]
    fn exact_position_scanners_zero_through_fifteen_match_every_window() {
        let markers = [
            0, 0xff, b'Z', 0x80, b'!', 0x7f, b'/', 0xfe, b'@', 0x81, b'#', 0x7e, b'_', 0x82, b'%',
            0xfd,
        ];

        for scanner_offset in 0..START_FILTER_POSITION_COUNT {
            let marker = markers[scanner_offset];
            let mut ranges = [(0, 0xff); START_FILTER_POSITION_COUNT];
            if scanner_offset == 0 {
                ranges[0] = (marker, marker);
            } else {
                ranges[0] = (b'A', b'B');
                ranges[scanner_offset] = (marker, marker);
            }

            let valid = ranges
                .iter()
                .enumerate()
                .map(|(offset, &(start, _))| {
                    if offset == scanner_offset {
                        return start;
                    }
                    match offset % 4 {
                        0 => start,
                        1 => 0,
                        2 => 0xff,
                        _ => 0x80,
                    }
                })
                .collect::<Vec<_>>();
            let mut haystacks = (0..=START_FILTER_POSITION_COUNT + 2)
                .map(|length| vec![b'x'; length])
                .collect::<Vec<_>>();
            haystacks.extend([
                valid.clone(),
                {
                    let mut source = vec![0xff, 0, 0x80];
                    source.extend_from_slice(&valid);
                    source.extend_from_slice(&[0, 0xff]);
                    source
                },
                {
                    let mut source = vec![marker; 19];
                    source[3..3 + valid.len()].copy_from_slice(&valid);
                    source
                },
                vec![0, 0xff, marker, 0x80, marker, 0x7f, 0xfe, marker],
            ]);

            let specialized = byte_chain(&ranges);
            let reference = byte_chain(&ranges);
            assert_all_windows_match_unspecialized(
                &format!("exact-position-scanner-{scanner_offset}"),
                &specialized,
                &reference,
                &haystacks,
            );

            let proof = specialized
                .start_filter_proof
                .get()
                .expect("all-window comparison publishes the exact-position proof");
            assert_eq!(
                proof.scanner,
                Some(positioned_scanner(
                    u8::try_from(scanner_offset).unwrap(),
                    StartScanner::One(marker),
                ))
            );
            assert_eq!(
                proof.guard().copied(),
                (scanner_offset != 0).then_some(StartPositionClass {
                    offset: 0,
                    set: byte_set(b"AB"),
                })
            );

            let mut workspace =
                K0Workspace::new(&specialized, WorkspaceLimits::unlimited()).unwrap();
            for clipped_end in 0..=scanner_offset {
                let clipped = specialized
                    .prepare::<Span>()
                    .search_window_with_workspace(
                        &valid,
                        SearchWindow::new(0, clipped_end),
                        &mut workspace,
                        SearchLimits::unlimited(),
                    )
                    .unwrap();
                assert!(clipped.output().is_none());
                assert_eq!(
                    clipped.accounting().boundaries(),
                    0,
                    "offset {scanner_offset} admitted a start without its scanner byte"
                );
            }
            let published = specialized
                .start_filter_proof
                .get()
                .expect("proof remains published");
            assert!(
                core::ptr::eq(proof, published),
                "a warm call must borrow the original immutable proof"
            );
        }
    }

    #[test]
    fn exact_position_depth_thresholds_are_exact_and_correct() {
        let proof_work = u64::try_from(
            START_FILTER_POSITION_COUNT
                .checked_mul(3)
                .and_then(|work| work.checked_sub(1))
                .unwrap(),
        )
        .unwrap();
        let selection_work = expected_start_class_selection_work(START_FILTER_POSITION_COUNT);
        let marker = 0xfe;

        for scanner_offset in [7, 8, 15, 16] {
            let eligible = scanner_offset <= START_FILTER_MAX_OFFSET;
            let mut ranges = vec![(0, 0xff); START_FILTER_POSITION_COUNT + 1];
            ranges[scanner_offset] = (marker, marker);
            let mut valid = vec![b'x'; ranges.len()];
            valid[scanner_offset] = marker;
            let mut shifted = vec![b'?'; 3];
            shifted.extend_from_slice(&valid);
            shifted.extend_from_slice(b"tail");
            let haystacks = vec![vec![], valid[..valid.len() - 1].to_vec(), valid, shifted];
            let expected = StartFilterProof {
                scanner: eligible.then_some(positioned_scanner(
                    u8::try_from(scanner_offset).unwrap(),
                    StartScanner::One(marker),
                )),
                filter: None,
                force_haystack_start: false,
                relaxed_nullable: false,
            };
            assert_chain_filter_matches_unspecialized(
                &format!("exact-position-threshold-{scanner_offset}"),
                &ranges,
                expected,
                &haystacks,
            );

            let measured = byte_chain(&ranges);
            let mut workspace = K0Workspace::new(&measured, WorkspaceLimits::unlimited()).unwrap();
            let mut meter = WorkMeter::new(u64::MAX, 0);
            let pending =
                super::prepare_start_filter(&measured, &mut workspace, &mut meter, 37, 37).unwrap();
            assert_eq!(pending.proof(), &expected);
            let expected_work = proof_work
                .checked_add(selection_work)
                .and_then(|work| {
                    work.checked_add(if eligible {
                        expected_scanner_construction_work(&[marker])
                    } else {
                        0
                    })
                })
                .unwrap();
            assert_eq!(
                meter.consumed, expected_work,
                "offset {scanner_offset} used unexpected proof work"
            );

            let refused = byte_chain(&ranges);
            let mut refused_workspace =
                K0Workspace::new(&refused, WorkspaceLimits::unlimited()).unwrap();
            let one_below = expected_work.checked_sub(1).unwrap();
            let mut refused_meter = WorkMeter::new(one_below, 0);
            let Err(error) = super::prepare_start_filter(
                &refused,
                &mut refused_workspace,
                &mut refused_meter,
                37,
                37,
            ) else {
                panic!("one-below proof work unexpectedly succeeded");
            };
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    limit,
                    consumed,
                    requested: 1,
                    position: 37,
                } if limit == one_below && consumed == one_below
            ));
        }
    }

    #[test]
    fn offset_seven_scanner_preserves_absolute_start_and_work_bounds() {
        let ranges = [
            (b'A', b'B'),
            (0, 0xff),
            (0, 0xff),
            (0, 0xff),
            (0, 0xff),
            (0, 0xff),
            (0, 0xff),
            (b'Z', b'Z'),
        ];
        let valid = [b'A', 0, 0xff, 0x80, b'x', 0, 0xfe, b'Z'];
        let mut later = vec![b'x'; 17];
        later.extend_from_slice(&valid);
        let haystacks = vec![
            vec![],
            vec![0xfe],
            vec![0xfe, b'x', b'x'],
            valid.to_vec(),
            later.clone(),
            vec![0xfe, b'A', 0, 0xff, 0x80, b'x', 0, 0xfe],
        ];

        let specialized = absolute_byte_or_eight_byte_chain(0xfe, &ranges);
        let reference = absolute_byte_or_eight_byte_chain(0xfe, &ranges);
        assert_all_windows_match_unspecialized(
            "absolute-or-offset-seven",
            &specialized,
            &reference,
            &haystacks,
        );
        assert_eq!(
            specialized
                .start_filter_proof
                .get()
                .expect("absolute-start comparison publishes proof"),
            &StartFilterProof {
                scanner: Some(positioned_scanner(7, StartScanner::One(b'Z'))),
                filter: Some(StartPositionFilter::Guard(StartPositionClass {
                    offset: 0,
                    set: byte_set(b"AB"),
                })),
                force_haystack_start: true,
                relaxed_nullable: false,
            }
        );

        let mut workspace = K0Workspace::new(&specialized, WorkspaceLimits::unlimited()).unwrap();
        let at_zero = specialized
            .prepare::<Span>()
            .search_with_workspace(b"\xfexxxxxxxZ", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(at_zero.output(), &Some(crate::MatchSpan::new(0, 1)));

        let bound = specialized
            .conservative_reused_work_bound(later.len())
            .unwrap();
        let warm = specialized
            .prepare::<Span>()
            .search_with_workspace(&later, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(warm.output(), &Some(crate::MatchSpan::new(17, 25)));
        assert!(warm.accounting().work() <= bound);

        let metered = absolute_byte_or_eight_byte_chain(0xfe, &ranges);
        let mut metered_workspace =
            K0Workspace::new(&metered, WorkspaceLimits::unlimited()).unwrap();
        let cold_bound = metered.conservative_reused_work_bound(later.len()).unwrap();
        let cold = metered
            .prepare::<Span>()
            .search_with_workspace(&later, &mut metered_workspace, SearchLimits::unlimited())
            .unwrap();
        let warm = metered
            .prepare::<Span>()
            .search_with_workspace(&later, &mut metered_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(cold.output(), warm.output());
        assert!(cold.accounting().work() <= cold_bound);
        assert!(
            cold.accounting().transition_work() > warm.accounting().transition_work(),
            "the cold offset-seven proof must be fully charged before publication"
        );
    }

    #[test]
    fn declined_filters_use_the_exact_scanner_free_accounting_path() {
        fn nullable() -> Automaton {
            Automaton::from_raw(
                RawPlan {
                    start: 0,
                    roles: vec![StateRole::Accept],
                    edge_offsets: vec![0, 0],
                    edge_targets: vec![],
                    edge_kinds: vec![],
                    byte_starts: vec![],
                    byte_ends: vec![],
                },
                CompileLimits::default(),
            )
            .unwrap()
        }

        for (name, specialized, reference, haystack, window) in [
            (
                "all-byte",
                byte_chain(&[(0, 0xff)]),
                byte_chain(&[(0, 0xff)]),
                vec![0, 0xff, b'x'],
                SearchWindow::new(1, 3),
            ),
            (
                "nullable",
                nullable(),
                nullable(),
                vec![0, 0xff, b'x'],
                SearchWindow::new(1, 3),
            ),
        ] {
            pin_without_start_filter(&reference);
            let mut specialized_workspace =
                K0Workspace::new(&specialized, WorkspaceLimits::unlimited()).unwrap();
            let mut reference_workspace =
                K0Workspace::new(&reference, WorkspaceLimits::unlimited()).unwrap();
            specialized
                .prepare::<Span>()
                .search_window_with_workspace(
                    &haystack,
                    window,
                    &mut specialized_workspace,
                    SearchLimits::unlimited(),
                )
                .unwrap();
            let warm = specialized
                .prepare::<Span>()
                .search_window_with_workspace(
                    &haystack,
                    window,
                    &mut specialized_workspace,
                    SearchLimits::unlimited(),
                )
                .unwrap();
            let unfiltered = reference
                .prepare::<Span>()
                .search_window_with_workspace(
                    &haystack,
                    window,
                    &mut reference_workspace,
                    SearchLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(warm.output(), unfiltered.output(), "{name} output");
            assert_eq!(
                warm.accounting(),
                unfiltered.accounting(),
                "{name} scanner-free accounting"
            );
            assert!(specialized
                .start_filter_proof
                .get()
                .expect("successful cold call publishes decline")
                .scanner
                .is_none());
        }
    }

    #[test]
    fn full_byte_root_declines_start_filtering() {
        let automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 1],
                edge_targets: vec![1],
                edge_kinds: vec![EdgeKind::ByteRange],
                byte_starts: vec![0],
                byte_ends: vec![0xff],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        automaton
            .prepare::<Span>()
            .search_with_workspace(b"\xffA", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let proof = automaton
            .start_filter_proof
            .get()
            .expect("successful search publishes the declined proof");
        assert!(proof.scanner.is_none());
        assert!(!proof.force_haystack_start);
    }

    #[test]
    fn full_byte_root_uses_a_more_selective_broad_later_class() {
        let automaton = byte_chain(&[(0, 0xff), (0, 64)]);
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let source = vec![0_u8; 257];
        let report = automaton
            .prepare::<Span>()
            .search_with_workspace(&source, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(report.output(), &Some(crate::MatchSpan::new(0, 2)));
        assert!(report.accounting().boundaries() > 0);
        let proof = automaton
            .start_filter_proof
            .get()
            .expect("successful search publishes later-position filter");
        assert!(matches!(
            proof.scanner,
            Some(StartPositionScanner {
                offset: 1,
                scanner: StartScanner::Range { start: 0, end: 64 },
            })
        ));
        assert_eq!(proof.guard(), None);
        assert!(!proof.force_haystack_start);
        assert!(!proof.relaxed_nullable);
    }

    #[test]
    fn bounded_position_guards_match_unspecialized_search_on_dense_and_binary_inputs() {
        let mut haystacks = bounded_words(&[0, b'Q', b'Z', b'x', 0x7f, 0x80, 0xfe, 0xff], 3);
        haystacks.extend([
            vec![b'Q'; 129],
            vec![0xff; 129],
            {
                let mut source = vec![b'Q'; 129];
                source[64] = b'Z';
                source
            },
            {
                let mut source = vec![0xff; 129];
                source[63] = 0;
                source
            },
            vec![0, 0x80, 0, 0xff, b'Q', 0, b'Z'],
        ]);

        let q_any_z = assert_chain_filter_matches_unspecialized(
            "selective-root-dense-middle",
            &[(b'Q', b'Q'), (0, 0xff), (b'Z', b'Z')],
            StartFilterProof {
                scanner: Some(root_scanner(StartScanner::One(b'Q'))),
                filter: Some(StartPositionFilter::Guard(StartPositionClass {
                    offset: 2,
                    set: byte_set(b"Z"),
                })),
                force_haystack_start: false,
                relaxed_nullable: false,
            },
            &haystacks,
        );

        let all_then_z = assert_chain_filter_matches_unspecialized(
            "all-byte-root-with-selective-guard",
            &[(0, 0xff), (b'Z', b'Z')],
            StartFilterProof {
                scanner: Some(positioned_scanner(1, StartScanner::One(b'Z'))),
                filter: None,
                force_haystack_start: false,
                relaxed_nullable: false,
            },
            &haystacks,
        );

        let high_then_nul = assert_chain_filter_matches_unspecialized(
            "high-byte-root-with-nul-guard",
            &[(0x80, 0xff), (0, 0), (0xfe, 0xff)],
            StartFilterProof {
                scanner: Some(positioned_scanner(1, StartScanner::One(0))),
                filter: Some(StartPositionFilter::Guard(StartPositionClass {
                    offset: 2,
                    set: byte_set(&[0xfe, 0xff]),
                })),
                force_haystack_start: false,
                relaxed_nullable: false,
            },
            &haystacks,
        );

        for (name, automaton, source) in [
            ("all-Q", &q_any_z, vec![b'Q'; 129]),
            ("all-high", &high_then_nul, vec![0xff; 129]),
            ("all-byte-root", &all_then_z, vec![b'x'; 129]),
        ] {
            let mut workspace = K0Workspace::new(automaton, WorkspaceLimits::unlimited()).unwrap();
            let report = automaton
                .prepare::<Span>()
                .search_with_workspace(&source, &mut workspace, SearchLimits::unlimited())
                .unwrap();
            assert!(report.output().is_none(), "{name} unexpectedly matched");
            assert_eq!(
                report.accounting().boundaries(),
                0,
                "{name} should be rejected by the root-plus-guard filter"
            );
            assert!(
                report.accounting().work()
                    <= automaton
                        .conservative_reused_work_bound(source.len())
                        .unwrap(),
                "{name} exceeded its conservative work certificate"
            );
        }
    }

    #[test]
    fn passing_guard_candidates_respect_cold_and_warm_work_bounds() {
        let automaton = byte_chain(&[(b'Q', b'Q'), (0, 0xff), (b'Z', b'Z'), (b'A', b'Z')]);
        let source = b"QxZx".repeat(64);
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let bound = automaton
            .conservative_reused_work_bound(source.len())
            .unwrap();

        let cold = automaton
            .prepare::<Span>()
            .search_with_workspace(&source, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert!(cold.output().is_none());
        assert!(cold.accounting().boundaries() > 0);
        assert!(cold.accounting().work() <= bound);

        let warm = automaton
            .prepare::<Span>()
            .search_with_workspace(&source, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(warm.output(), cold.output());
        assert!(warm.accounting().boundaries() > 0);
        assert!(warm.accounting().work() <= bound);
        assert!(warm.accounting().work() < cold.accounting().work());
    }

    #[test]
    fn an_accepting_shorter_branch_prevents_an_unsound_later_guard() {
        fn q_or_qxz() -> Automaton {
            Automaton::from_raw(
                RawPlan {
                    start: 0,
                    roles: vec![
                        StateRole::Split,
                        StateRole::Consume,
                        StateRole::Accept,
                        StateRole::Consume,
                        StateRole::Consume,
                        StateRole::Consume,
                    ],
                    edge_offsets: vec![0, 2, 3, 3, 4, 5, 6],
                    edge_targets: vec![1, 3, 2, 4, 5, 2],
                    edge_kinds: vec![
                        EdgeKind::Epsilon,
                        EdgeKind::Epsilon,
                        EdgeKind::ByteRange,
                        EdgeKind::ByteRange,
                        EdgeKind::ByteRange,
                        EdgeKind::ByteRange,
                    ],
                    byte_starts: vec![0, 0, b'Q', b'Q', b'x', b'Z'],
                    byte_ends: vec![0, 0, b'Q', b'Q', b'x', b'Z'],
                },
                CompileLimits::default(),
            )
            .unwrap()
        }

        let specialized = q_or_qxz();
        let reference = q_or_qxz();
        let mut haystacks = bounded_words(&[b'Q', b'x', b'Z', 0xff], 3);
        haystacks.push(b"xxxxQxxxx".to_vec());
        assert_all_windows_match_unspecialized(
            "accept-truncates-position-proof",
            &specialized,
            &reference,
            &haystacks,
        );
        assert_eq!(
            specialized
                .start_filter_proof
                .get()
                .expect("exhaustive search publishes proof"),
            &StartFilterProof {
                scanner: Some(root_scanner(StartScanner::One(b'Q'))),
                filter: None,
                force_haystack_start: false,
                relaxed_nullable: false,
            }
        );
    }

    #[test]
    fn equivalent_factored_and_expanded_topologies_retain_the_same_filter() {
        let mut haystacks = bounded_words(&[0, b'Q', b'a', b'b', b'Z', 0xff], 3);
        haystacks.extend([
            b"QQQQQQQQQQQQ".to_vec(),
            b"xxQaZxxQbZ".to_vec(),
            vec![0xff, b'Q', b'a', b'Z', 0, b'Q', b'b', b'Z'],
        ]);

        let factored = factored_q_ab_z();
        let factored_reference = factored_q_ab_z();
        assert_all_windows_match_unspecialized(
            "factored-position-classes",
            &factored,
            &factored_reference,
            &haystacks,
        );
        let expanded = expanded_q_ab_z();
        let expanded_reference = expanded_q_ab_z();
        assert_all_windows_match_unspecialized(
            "expanded-position-classes",
            &expanded,
            &expanded_reference,
            &haystacks,
        );

        let expected = StartFilterProof {
            scanner: Some(root_scanner(StartScanner::One(b'Q'))),
            filter: Some(StartPositionFilter::Guard(StartPositionClass {
                offset: 2,
                set: byte_set(b"Z"),
            })),
            force_haystack_start: false,
            relaxed_nullable: false,
        };
        assert_eq!(factored.start_filter_proof.get(), Some(&expected));
        assert_eq!(expanded.start_filter_proof.get(), Some(&expected));

        let mut factored_workspace =
            K0Workspace::new(&factored, WorkspaceLimits::unlimited()).unwrap();
        let mut expanded_workspace =
            K0Workspace::new(&expanded, WorkspaceLimits::unlimited()).unwrap();
        for haystack in &haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let factored_output = factored
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut factored_workspace,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let expanded_output = expanded
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut expanded_workspace,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    assert_eq!(
                        factored_output, expanded_output,
                        "equivalent topology mismatch for {haystack:?} in {start}..{end}"
                    );
                }
            }
        }
    }

    #[test]
    fn start_scanners_honor_exact_admitted_work() {
        let scanners = [
            root_scanner(scanner_for(b"a")),
            root_scanner(scanner_for(b"ab")),
            root_scanner(scanner_for(b"abc")),
            root_scanner(scanner_for(b"abcd")),
        ];
        for scanner in &scanners {
            let mut exact = WorkMeter::new(10, 7);
            assert_eq!(
                super::next_start_candidate(scanner, b"_xxa_", 1, 4, None, &mut exact).unwrap(),
                3
            );
            assert_eq!(exact.consumed, 10);

            let mut before_candidate = WorkMeter::new(9, 7);
            let error =
                super::next_start_candidate(scanner, b"_xxa_", 1, 4, None, &mut before_candidate)
                    .unwrap_err();
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    limit: 9,
                    consumed: 9,
                    requested: 1,
                    position: 3,
                }
            ));

            let mut full_miss = WorkMeter::new(10, 7);
            assert_eq!(
                super::next_start_candidate(scanner, b"_xxx_", 1, 4, None, &mut full_miss).unwrap(),
                4
            );
            assert_eq!(full_miss.consumed, 10);

            let mut partial_miss = WorkMeter::new(9, 7);
            let error =
                super::next_start_candidate(scanner, b"_xxx_", 1, 4, None, &mut partial_miss)
                    .unwrap_err();
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    limit: 9,
                    consumed: 9,
                    requested: 1,
                    position: 3,
                }
            ));

            let mut exhausted = WorkMeter::new(7, 7);
            let error = super::next_start_candidate(scanner, b"_xxx_", 1, 4, None, &mut exhausted)
                .unwrap_err();
            assert!(matches!(
                error,
                SearchError::WorkLimitExceeded {
                    limit: 7,
                    consumed: 7,
                    requested: 1,
                    position: 1,
                }
            ));
        }

        let mut empty_meter = WorkMeter::new(7, 7);
        assert_eq!(
            super::next_start_candidate(
                &root_scanner(StartScanner::Empty),
                b"_xxx_",
                1,
                4,
                None,
                &mut empty_meter,
            )
            .unwrap(),
            4
        );
        assert_eq!(empty_meter.consumed, 7);

        let absolute = absolute_foo();
        let mut workspace = K0Workspace::new(&absolute, WorkspaceLimits::unlimited()).unwrap();
        absolute
            .prepare::<Span>()
            .search_with_workspace(b"x", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let proof = absolute
            .start_filter_proof
            .get()
            .expect("successful absolute search publishes its proof");
        assert!(proof.force_haystack_start);
        assert!(matches!(
            proof.scanner,
            Some(StartPositionScanner {
                offset: 0,
                scanner: StartScanner::Empty,
            })
        ));
    }

    #[test]
    fn start_scanner_cardinality_is_cached_without_copying() {
        let cases: &[&[u8]] = &[&[], b"a", b"ab", b"abc", b"abcd"];

        for &bytes in cases {
            let automaton = ascii_root_bytes(bytes);
            let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
            let cold = automaton
                .prepare::<Span>()
                .search_with_workspace(b"z", &mut workspace, SearchLimits::unlimited())
                .unwrap();
            let warm = automaton
                .prepare::<Span>()
                .search_with_workspace(b"z", &mut workspace, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(cold.output(), warm.output());
            let graph_work = if bytes.is_empty() {
                1
            } else {
                2_u64
                    .checked_add(u64::try_from(bytes.len()).unwrap().checked_mul(2).unwrap())
                    .unwrap()
            };
            let proof_work = graph_work
                .checked_add(expected_filter_selection_work(1, bytes))
                .unwrap();
            assert_eq!(
                cold.accounting()
                    .transition_work()
                    .checked_sub(warm.accounting().transition_work()),
                Some(proof_work)
            );

            let proof = automaton
                .start_filter_proof
                .get()
                .expect("successful search publishes the start scanner");
            let scanner = proof
                .scanner
                .as_ref()
                .expect("a selective byte root enables start scanning");
            assert_eq!(scanner.offset, 0);
            assert!(matches!(
                (bytes, &scanner.scanner),
                (b"", StartScanner::Empty)
                    | (b"a", StartScanner::One(b'a'))
                    | (b"ab", StartScanner::Two(b'a', b'b'))
                    | (b"abc", StartScanner::Three(b'a', b'b', b'c'))
                    | (
                        b"abcd",
                        StartScanner::Range {
                            start: b'a',
                            end: b'd'
                        }
                    )
            ));

            let mut meter = WorkMeter::new(u64::MAX, 0);
            let invocation =
                super::prepare_start_filter(&automaton, &mut workspace, &mut meter, 0, 0).unwrap();
            match invocation {
                super::InvocationStartProof::Published(borrowed) => {
                    assert!(core::ptr::eq(borrowed, proof));
                }
                super::InvocationStartProof::Pending { .. } => {
                    panic!("cached scanner was unexpectedly rebuilt");
                }
            }
            assert_eq!(meter.consumed, 0);
        }
    }

    #[test]
    fn byte_start_specialization_is_once_per_automaton_and_clone() {
        let automaton = ascii_literal(b'a');
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let cold = automaton
            .prepare::<Span>()
            .search_with_workspace(b"zzza", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let warm = automaton
            .prepare::<Span>()
            .search_with_workspace(b"zzza", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(cold.output(), warm.output());
        let specialization_work = 4_u64
            .checked_add(expected_filter_selection_work(1, b"a"))
            .unwrap();
        let proof_bytes = StartFilterProofCell::PAYLOAD_BYTES;
        assert_eq!(
            cold.accounting()
                .transition_work()
                .checked_sub(warm.accounting().transition_work()),
            Some(specialization_work)
        );
        assert_eq!(cold.accounting().setup().allocated_bytes(), proof_bytes);
        assert_eq!(cold.accounting().setup().initialized_bytes(), proof_bytes);
        assert_eq!(
            cold.accounting().scratch_bytes(),
            workspace.retained_bytes().checked_add(proof_bytes).unwrap()
        );
        assert_eq!(warm.accounting().setup().allocated_bytes(), 0);
        assert_eq!(warm.accounting().setup().initialized_bytes(), 0);
        assert_eq!(
            warm.accounting().scratch_bytes(),
            workspace.retained_bytes()
        );
        assert_eq!(
            cold.accounting().setup_work(),
            warm.accounting()
                .setup_work()
                .checked_add(super::START_FILTER_OWNER_ALLOCATION_WORK)
                .unwrap()
        );
        let published = automaton
            .start_filter_proof
            .get()
            .expect("successful cold search publishes the proof");
        let mut cache_meter = WorkMeter::new(u64::MAX, 0);
        let cached =
            super::prepare_start_filter(&automaton, &mut workspace, &mut cache_meter, 0, 0)
                .unwrap();
        match cached {
            super::InvocationStartProof::Published(borrowed) => {
                assert!(
                    core::ptr::eq(borrowed, published),
                    "warm invocation must borrow the cached start scanner"
                );
            }
            super::InvocationStartProof::Pending { .. } => {
                panic!("warm invocation unexpectedly rebuilt the proof");
            }
        }
        assert_eq!(cache_meter.consumed, 0);

        let cloned = automaton.clone();
        assert!(
            cloned.start_filter_proof.get().is_none(),
            "cloning must not copy uncharged first-use specialization"
        );
        let mut clone_workspace = K0Workspace::new(&cloned, WorkspaceLimits::unlimited()).unwrap();
        let clone_cold = cloned
            .prepare::<Span>()
            .search_with_workspace(b"zzza", &mut clone_workspace, SearchLimits::unlimited())
            .unwrap();
        let clone_warm = cloned
            .prepare::<Span>()
            .search_with_workspace(b"zzza", &mut clone_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            clone_cold
                .accounting()
                .transition_work()
                .checked_sub(clone_warm.accounting().transition_work()),
            Some(specialization_work)
        );
        assert_eq!(
            clone_cold.accounting().setup().allocated_bytes(),
            proof_bytes
        );
        assert_eq!(clone_warm.accounting().setup().allocated_bytes(), 0);
    }

    #[test]
    fn start_filter_owner_layout_is_pointer_isolated() {
        assert_eq!(
            size_of::<Option<StartPositionFilter>>(),
            size_of::<Option<StartPositionClass>>(),
            "the Guard/Probe tag must reuse the incumbent optional-class discriminant"
        );
        assert_eq!(
            StartFilterProofCell::PAYLOAD_BYTES,
            size_of::<StartFilterProof>()
        );
        #[cfg(target_pointer_width = "64")]
        {
            assert!(size_of::<StartFilterProofCell>() <= 16);
            assert!(size_of::<Automaton>() <= 192);
        }
        #[cfg(all(
            target_pointer_width = "64",
            target_arch = "aarch64",
            target_os = "macos"
        ))]
        {
            assert_eq!(size_of::<StartFilterProofCell>(), 16);
            assert_eq!(size_of::<Automaton>(), 192);
            #[cfg(feature = "static-dispatch")]
            assert_eq!(size_of::<StartFilterProof>(), 136);
            #[cfg(not(feature = "static-dispatch"))]
            assert_eq!(size_of::<StartFilterProof>(), 480);
        }
    }

    #[test]
    fn owner_limit_refusal_preserves_k0_and_remains_retryable() {
        let proof_bytes = StartFilterProofCell::PAYLOAD_BYTES;
        let scratch_refused = ascii_literal(b'a');
        let mut scratch_workspace =
            K0Workspace::new(&scratch_refused, WorkspaceLimits::unlimited()).unwrap();
        let retained = scratch_workspace.retained_bytes();
        let refused = scratch_refused
            .prepare::<Span>()
            .search_with_workspace(
                b"zzza",
                &mut scratch_workspace,
                SearchLimits {
                    max_work: u64::MAX,
                    max_scratch_bytes: retained,
                },
            )
            .unwrap();
        assert_eq!(
            refused.output(),
            &Some(crate::MatchSpan::new(3, 4)),
            "owner refusal must not refuse ordinary K0"
        );
        assert_eq!(refused.accounting().setup().allocated_bytes(), 0);
        assert_eq!(refused.accounting().setup().initialized_bytes(), 0);
        assert_eq!(refused.accounting().scratch_bytes(), retained);
        assert!(
            scratch_refused.start_filter_proof.get().is_none(),
            "scratch refusal must leave publication retryable"
        );

        let published = scratch_refused
            .prepare::<Span>()
            .search_with_workspace(b"zzza", &mut scratch_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            published.accounting().setup().allocated_bytes(),
            proof_bytes
        );
        assert_eq!(
            published.accounting().scratch_bytes(),
            retained.checked_add(proof_bytes).unwrap()
        );
        assert!(scratch_refused.start_filter_proof.get().is_some());

        let warm = scratch_refused
            .prepare::<Span>()
            .search_with_workspace(
                b"zzza",
                &mut scratch_workspace,
                SearchLimits {
                    max_work: u64::MAX,
                    max_scratch_bytes: retained,
                },
            )
            .unwrap();
        assert_eq!(warm.output(), refused.output());
        assert_eq!(warm.accounting().setup().allocated_bytes(), 0);
        assert_eq!(warm.accounting().scratch_bytes(), retained);

        let work_refused = ascii_literal(b'a');
        let mut work_workspace =
            K0Workspace::new(&work_refused, WorkspaceLimits::unlimited()).unwrap();
        let exact_without_owner = refused.accounting().work();
        let exact = work_refused
            .prepare::<Span>()
            .search_with_workspace(
                b"zzza",
                &mut work_workspace,
                SearchLimits {
                    max_work: exact_without_owner,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap();
        assert_eq!(exact.output(), refused.output());
        assert_eq!(exact.accounting().work(), exact_without_owner);
        assert_eq!(exact.accounting().setup().allocated_bytes(), 0);
        assert!(
            work_refused.start_filter_proof.get().is_none(),
            "work refusal must leave publication retryable"
        );
        let retry = work_refused
            .prepare::<Span>()
            .search_with_workspace(b"zzza", &mut work_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(retry.accounting().setup().allocated_bytes(), proof_bytes);
        assert!(work_refused.start_filter_proof.get().is_some());
    }

    #[test]
    fn owner_allocation_failure_permanently_uses_ordinary_k0() {
        let automaton = ascii_literal(b'a');
        automaton
            .start_filter_proof
            .mark_allocation_failed()
            .unwrap();
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let mut meter = WorkMeter::new(u64::MAX, 0);
        let proof =
            super::prepare_start_filter(&automaton, &mut workspace, &mut meter, 0, 0).unwrap();
        match proof {
            super::InvocationStartProof::Published(proof) => {
                assert_eq!(proof, &super::ORDINARY_START_FILTER_PROOF);
            }
            super::InvocationStartProof::Pending { .. } => {
                panic!("allocation failure retried optional proof construction");
            }
        }
        assert_eq!(meter.consumed, 0);

        let retained = workspace.retained_bytes();
        let report = automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"zzza",
                &mut workspace,
                SearchLimits {
                    max_work: u64::MAX,
                    max_scratch_bytes: retained,
                },
            )
            .unwrap();
        assert_eq!(report.output(), &Some(crate::MatchSpan::new(3, 4)));
        assert_eq!(report.accounting().setup().allocated_bytes(), 0);
        assert_eq!(report.accounting().scratch_bytes(), retained);
        assert!(automaton.start_filter_proof.get().is_none());
    }

    #[test]
    fn refused_scanner_selection_does_not_publish_unpaid_specialization() {
        let root = [b'a', b'b', b'c', b'd'];
        let automaton = ascii_root_bytes(&root);
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        // The root proof visits its state and consuming edges, retains the
        // next frontier with a second edge pass, then observes accept.
        let proof_work = 2_u64
            .checked_add(u64::try_from(root.len()).unwrap().checked_mul(2).unwrap())
            .unwrap();
        let admitted = INVOCATION_RESET_WORK.checked_add(proof_work).unwrap();
        let population_work = u64::try_from(BYTE_START_BITMAP_POPULATION_WORK).unwrap();
        let error = automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"za",
                &mut workspace,
                SearchLimits {
                    max_work: admitted,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                consumed,
                requested,
                ..
            } if consumed == admitted
                && requested == population_work
        ));
        assert!(automaton.start_filter_proof.get().is_none());

        // Once all bitmap words are admitted and counted, choosing this
        // position is the next indivisible selection charge.
        let population_admitted = admitted.checked_add(population_work).unwrap();
        let error = automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"za",
                &mut workspace,
                SearchLimits {
                    max_work: population_admitted,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                consumed,
                requested,
                ..
            } if consumed == population_admitted
                && requested == u64::try_from(START_FILTER_SCANNER_SELECTION_WORK).unwrap()
        ));
        assert!(automaton.start_filter_proof.get().is_none());

        // A small scanner charges its member extraction after population and
        // exact-position selection, and likewise cannot publish on refusal.
        let small = ascii_literal(b'a');
        let mut small_workspace = K0Workspace::new(&small, WorkspaceLimits::unlimited()).unwrap();
        let small_proof_work = 4_u64;
        let small_extraction_limit = INVOCATION_RESET_WORK
            .checked_add(small_proof_work)
            .and_then(|work| work.checked_add(population_work))
            .and_then(|work| {
                work.checked_add(u64::try_from(START_FILTER_SCANNER_SELECTION_WORK).unwrap())
            })
            .unwrap();
        let error = small
            .prepare::<Span>()
            .search_with_workspace(
                b"za",
                &mut small_workspace,
                SearchLimits {
                    max_work: small_extraction_limit,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                consumed,
                requested,
                ..
            } if consumed == small_extraction_limit
                && requested
                    == u64::try_from(BYTE_START_MEMBER_EXTRACTION_WORK).unwrap()
        ));
        assert!(small.start_filter_proof.get().is_none());
    }

    #[test]
    fn refused_class_selection_does_not_publish_unpaid_specialization() {
        let ranges = [(b'Q', b'Q'), (0, 0xff), (b'Z', b'Z')];
        let measured = byte_chain(&ranges);
        let mut measured_workspace =
            K0Workspace::new(&measured, WorkspaceLimits::unlimited()).unwrap();
        let mut proof_meter = WorkMeter::new(u64::MAX, 0);
        let proof = super::derive_start_position_classes(
            &measured,
            &mut measured_workspace,
            &mut proof_meter,
            0,
        )
        .unwrap();
        assert_eq!(proof.length, 3);

        let selection_work = expected_start_class_selection_work(proof.length);
        let one_below_selection = INVOCATION_RESET_WORK
            .checked_add(proof_meter.consumed)
            .and_then(|work| work.checked_add(selection_work))
            .and_then(|work| work.checked_sub(1))
            .unwrap();
        let automaton = byte_chain(&ranges);
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let error = automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"QxZ",
                &mut workspace,
                SearchLimits {
                    max_work: one_below_selection,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SearchError::WorkLimitExceeded {
                limit,
                consumed,
                requested: 1,
                position: 0,
            } if limit == one_below_selection && consumed == one_below_selection
        ));
        assert!(
            automaton.start_filter_proof.get().is_none(),
            "a refused class comparison must not publish a partial proof"
        );

        automaton
            .prepare::<Span>()
            .search_with_workspace(b"QxZ", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            automaton
                .start_filter_proof
                .get()
                .expect("successful retry publishes complete proof")
                .guard()
                .copied(),
            Some(StartPositionClass {
                offset: 2,
                set: byte_set(b"Z"),
            })
        );
    }

    #[test]
    fn failed_first_use_does_not_publish_unpaid_specialization() {
        let root = [b'a', b'b', b'c', b'd'];
        let automaton = ascii_root_bytes(&root);
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let proof_work = 2_u64
            .checked_add(u64::try_from(root.len()).unwrap().checked_mul(2).unwrap())
            .unwrap();
        let specialization_admitted = INVOCATION_RESET_WORK
            .checked_add(proof_work)
            .and_then(|work| work.checked_add(expected_filter_selection_work(1, &root)))
            .unwrap();
        let probe = ascii_root_bytes(&root);
        let mut probe_workspace = K0Workspace::new(&probe, WorkspaceLimits::unlimited()).unwrap();
        let full_cold_work = probe
            .prepare::<Span>()
            .search_with_workspace(b"za", &mut probe_workspace, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        // Owner publication is optional: one below the complete cold report
        // now admits the search itself and merely declines retention. Refuse
        // one unit below the owner-free execution instead.
        let late_limit = one_below_owner_free(full_cold_work);
        let late_error = automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"za",
                &mut workspace,
                SearchLimits {
                    max_work: late_limit,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(
            late_error,
            SearchError::WorkLimitExceeded { consumed, .. }
                if consumed > specialization_admitted
        ));
        assert!(
            automaton.start_filter_proof.get().is_none(),
            "a search that pays specialization but later fails must not publish it"
        );

        let cold = automaton
            .prepare::<Span>()
            .search_with_workspace(b"za", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert!(automaton.start_filter_proof.get().is_some());
        let warm = automaton
            .prepare::<Span>()
            .search_with_workspace(b"za", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let specialization_work = proof_work
            .checked_add(expected_filter_selection_work(1, &root))
            .unwrap();
        assert_eq!(
            cold.accounting()
                .transition_work()
                .checked_sub(warm.accounting().transition_work()),
            Some(specialization_work)
        );
        automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"za",
                &mut workspace,
                SearchLimits {
                    max_work: warm.accounting().work(),
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap();

        let cloned = automaton.clone();
        let mut clone_workspace = K0Workspace::new(&cloned, WorkspaceLimits::unlimited()).unwrap();
        let clone_error = cloned
            .prepare::<Span>()
            .search_with_workspace(
                b"za",
                &mut clone_workspace,
                SearchLimits {
                    max_work: warm.accounting().work(),
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(clone_error, SearchError::WorkLimitExceeded { .. }));
        assert!(cloned.start_filter_proof.get().is_none());
    }

    #[test]
    fn concurrent_first_use_is_correct_and_fully_charged() {
        let reference = ascii_literal(b'a');
        let mut reference_workspace =
            K0Workspace::new(&reference, WorkspaceLimits::unlimited()).unwrap();
        let cold_work = reference
            .prepare::<Span>()
            .search_with_workspace(
                b"zzzzzzza",
                &mut reference_workspace,
                SearchLimits::unlimited(),
            )
            .unwrap()
            .accounting()
            .transition_work();
        let warm_work = reference
            .prepare::<Span>()
            .search_with_workspace(
                b"zzzzzzza",
                &mut reference_workspace,
                SearchLimits::unlimited(),
            )
            .unwrap()
            .accounting()
            .transition_work();
        assert!(cold_work > warm_work);

        let automaton = Arc::new(ascii_literal(b'a'));
        let thread_count = 8;
        let barrier = Arc::new(Barrier::new(thread_count));
        let mut handles = Vec::new();
        for _ in 0..thread_count {
            let automaton = Arc::clone(&automaton);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut workspace =
                    K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
                barrier.wait();
                let report = automaton
                    .prepare::<Span>()
                    .search_with_workspace(b"zzzzzzza", &mut workspace, SearchLimits::unlimited())
                    .unwrap();
                let accounting = report.accounting();
                (
                    report.into_output(),
                    accounting.transition_work(),
                    accounting.setup(),
                    accounting.scratch_bytes(),
                    workspace.retained_bytes(),
                )
            }));
        }

        let reports: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert!(reports.iter().all(|(found, _, _, _, _)| {
            found.as_ref().map(|span| (span.start(), span.end())) == Some((7, 8))
        }));
        assert!(
            reports
                .iter()
                .all(|(_, work, _, _, _)| *work == cold_work || *work == warm_work),
            "a racing caller must either derive and fully charge or use the published proof"
        );
        assert!(reports.iter().any(|(_, work, _, _, _)| *work == cold_work));
        let proof_bytes = StartFilterProofCell::PAYLOAD_BYTES;
        let publishers: Vec<_> = reports
            .iter()
            .filter(|(_, _, setup, _, _)| setup.allocated_bytes() != 0)
            .collect();
        assert_eq!(
            publishers.len(),
            1,
            "the lock must serialize the only fallible owner allocation"
        );
        let (_, _, setup, scratch_bytes, retained_bytes) = publishers[0];
        assert_eq!(setup.allocated_bytes(), proof_bytes);
        assert_eq!(setup.initialized_bytes(), proof_bytes);
        assert_eq!(
            *scratch_bytes,
            retained_bytes.checked_add(proof_bytes).unwrap()
        );
        assert!(reports.iter().all(|(_, _, setup, scratch, retained)| {
            setup.allocated_bytes() == proof_bytes || *scratch == *retained
        }));
        assert!(automaton.start_filter_proof.get().is_some());
    }

    #[test]
    fn every_non_absolute_start_assertion_is_conservatively_relaxed() {
        let absolute = assertion_or_colon(EdgeKind::AssertHaystackStart);
        let mut absolute_workspace =
            K0Workspace::new(&absolute, WorkspaceLimits::unlimited()).unwrap();
        let mut absolute_meter = WorkMeter::new(u64::MAX, 0);
        let proof = super::derive_start_position_classes(
            &absolute,
            &mut absolute_workspace,
            &mut absolute_meter,
            0,
        )
        .unwrap();
        assert!(proof.force_haystack_start);
        assert_eq!(proof.sets[0].words(), [1_u64 << u32::from(b':'), 0, 0, 0]);

        let relaxed = [
            EdgeKind::AssertHaystackEnd,
            EdgeKind::AssertLineStartLf,
            EdgeKind::AssertLineEndLf,
            EdgeKind::AssertLineStartCrlf,
            EdgeKind::AssertLineEndCrlf,
            EdgeKind::AssertWordAscii,
            EdgeKind::AssertWordAsciiNegate,
            EdgeKind::AssertWordStartAscii,
            EdgeKind::AssertWordEndAscii,
            EdgeKind::AssertWordStartHalfAscii,
            EdgeKind::AssertWordEndHalfAscii,
            EdgeKind::AssertWordUnicode,
            EdgeKind::AssertWordUnicodeNegate,
            EdgeKind::AssertWordStartUnicode,
            EdgeKind::AssertWordEndUnicode,
            EdgeKind::AssertWordStartHalfUnicode,
            EdgeKind::AssertWordEndHalfUnicode,
        ];
        for assertion in relaxed {
            let automaton = assertion_or_colon(assertion);
            let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
            let mut meter = WorkMeter::new(u64::MAX, 0);
            let proof =
                super::derive_start_position_classes(&automaton, &mut workspace, &mut meter, 0)
                    .unwrap();
            assert_eq!(
                proof.sets[0],
                byte_set(b"a:"),
                "{} did not conservatively retain both roots",
                assertion.name()
            );
            assert_eq!(proof.length, 1);
            assert!(
                !proof.force_haystack_start,
                "{} unexpectedly retained an absolute-start exception",
                assertion.name()
            );
        }
    }

    #[test]
    fn absolute_high_byte_branch_and_ascii_sibling_match_every_window() {
        let mut haystacks = bounded_words(&[b'x', b':', b'a', 0xff], 5);
        let mut late = vec![b'x'; 65];
        late.extend_from_slice(&[0xff, b':', b'a']);
        haystacks.push(late);

        let specialized = absolute_high_byte_or_colon_a();
        let reference = absolute_high_byte_or_colon_a();
        assert_all_windows_match_unspecialized(
            "absolute-high-byte-or-colon",
            &specialized,
            &reference,
            &haystacks,
        );

        let proof = specialized
            .start_filter_proof
            .get()
            .expect("exhaustive successful search publishes the proof");
        assert!(proof.force_haystack_start);
        assert!(matches!(
            proof.scanner,
            Some(StartPositionScanner {
                offset: 0,
                scanner: StartScanner::One(b':'),
            })
        ));
        assert_eq!(
            proof.guard().copied(),
            Some(StartPositionClass {
                offset: 1,
                set: byte_set(b"a"),
            })
        );

        let mut workspace = K0Workspace::new(&specialized, WorkspaceLimits::unlimited()).unwrap();
        let at_zero = specialized
            .prepare::<Span>()
            .search_with_workspace(b"\xff:a", &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .into_output()
            .expect("the absolute high-byte branch matches at zero");
        assert_eq!((at_zero.start(), at_zero.end()), (0, 1));

        let later = specialized
            .prepare::<Span>()
            .search_window_with_workspace(
                b"x\xff:a",
                SearchWindow::new(1, 4),
                &mut workspace,
                SearchLimits::unlimited(),
            )
            .unwrap()
            .into_output()
            .expect("the ASCII sibling remains discoverable after a nonzero high byte");
        assert_eq!((later.start(), later.end()), (2, 4));
    }

    #[test]
    fn absolute_start_root_proof_matches_unspecialized_search_exhaustively() {
        type AutomatonFactory = fn() -> Automaton;

        let mut haystacks = bounded_words(b"x:fo", 5);
        let mut late_colon = vec![b'x'; 65];
        late_colon.extend_from_slice(b":foo");
        haystacks.push(late_colon);
        let mut dense_colons = vec![b':'; 33];
        dense_colons.extend_from_slice(b"foo");
        haystacks.push(dense_colons);

        let cases: &[(&str, AutomatonFactory)] = &[
            ("absolute-foo", absolute_foo),
            ("absolute-or-colon-foo", absolute_or_colon_foo),
            ("absolute-nullable-or-colon", absolute_nullable_or_colon),
            (
                "unasserted-nullable-sibling",
                absolute_or_colon_or_unasserted_empty,
            ),
        ];
        for &(name, build) in cases {
            let specialized = build();
            let reference = build();
            assert_all_windows_match_unspecialized(name, &specialized, &reference, &haystacks);
        }
    }

    #[test]
    fn factored_absolute_start_pattern_matches_unspecialized_search() {
        let haystacks = [
            b"".as_slice(),
            b"abc".as_slice(),
            b"abcd".as_slice(),
            b"abc!".as_slice(),
            b":abc".as_slice(),
            b":abcd".as_slice(),
            b":abc!".as_slice(),
            b"x:abc!".as_slice(),
            b":::x:abcd".as_slice(),
            b"abcdx:abc!".as_slice(),
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:abcd".as_slice(),
            b":::::::::::::::::::::::::::::::::abc!".as_slice(),
        ]
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
        let specialized = absolute_or_colon_with_ordered_suffixes();
        let reference = absolute_or_colon_with_ordered_suffixes();
        assert_all_windows_match_unspecialized(
            "factored-absolute-start",
            &specialized,
            &reference,
            &haystacks,
        );
        assert_contextual_all_contracts(&specialized, &haystacks);
    }

    #[test]
    fn absolute_start_root_proof_is_transactional_and_exactly_metered() {
        let automaton = absolute_or_colon_foo();
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let mut haystack = vec![b'x'; 64];
        haystack.extend_from_slice(b":foo");

        let cold = automaton
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let proof = automaton
            .start_filter_proof
            .get()
            .expect("successful search publishes the proof");
        assert!(proof.force_haystack_start);
        assert!(matches!(
            proof.scanner,
            Some(StartPositionScanner {
                offset: 0,
                scanner: StartScanner::One(b':'),
            })
        ));
        assert_eq!(
            proof.guard().copied(),
            Some(StartPositionClass {
                offset: 3,
                set: byte_set(b"o"),
            })
        );

        let warm = automaton
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let specialization_work = 16_u64
            .checked_add(expected_filter_selection_work(4, b":"))
            .unwrap();
        assert_eq!(
            cold.accounting()
                .transition_work()
                .checked_sub(warm.accounting().transition_work()),
            Some(specialization_work)
        );
        assert_eq!(cold.output(), warm.output());
        assert_eq!(warm.output(), &Some(crate::MatchSpan::new(64, 68)));
        assert_eq!(warm.accounting().boundaries(), 6);
        assert_eq!(
            warm.accounting().work(),
            warm.accounting().setup_work() + warm.accounting().transition_work()
        );
        assert_eq!(
            warm.accounting().scratch_bytes(),
            workspace.retained_bytes()
        );
        assert!(warm.accounting().setup().reused());

        let exact = automaton
            .prepare::<Span>()
            .search_with_workspace(
                &haystack,
                &mut workspace,
                SearchLimits {
                    max_work: warm.accounting().work(),
                    max_scratch_bytes: warm.accounting().scratch_bytes(),
                },
            )
            .unwrap();
        assert_eq!(exact.output(), warm.output());
        assert_eq!(exact.accounting(), warm.accounting());

        let refused = automaton
            .prepare::<Span>()
            .search_with_workspace(
                &haystack,
                &mut workspace,
                SearchLimits {
                    max_work: warm.accounting().work() - 1,
                    max_scratch_bytes: warm.accounting().scratch_bytes(),
                },
            )
            .unwrap_err();
        assert!(matches!(refused, SearchError::WorkLimitExceeded { .. }));

        let unpublished = absolute_or_colon_foo();
        let mut unpublished_workspace =
            K0Workspace::new(&unpublished, WorkspaceLimits::unlimited()).unwrap();
        let cold_work = cold.accounting().work();
        let failed_search_limit = one_below_owner_free(cold_work);
        let refused = unpublished
            .prepare::<Span>()
            .search_with_workspace(
                &haystack,
                &mut unpublished_workspace,
                SearchLimits {
                    max_work: failed_search_limit,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(refused, SearchError::WorkLimitExceeded { .. }));
        assert!(
            unpublished.start_filter_proof.get().is_none(),
            "a failed cold search must not publish the absolute-start proof"
        );
    }

    #[test]
    fn generation_rollover_is_preflighted_and_accounted_as_setup() {
        let required_generations = u64::try_from(
            1_usize
                .checked_add(START_FILTER_POSITION_COUNT)
                .and_then(|count| count.checked_add(1))
                .unwrap(),
        )
        .unwrap();
        let no_reset = ascii_literal(b'a');
        pin_without_start_filter(&no_reset);
        let mut no_reset_workspace =
            K0Workspace::new(&no_reset, WorkspaceLimits::unlimited()).unwrap();
        no_reset_workspace.generation = u64::MAX.checked_sub(required_generations).unwrap();
        let no_reset_report = no_reset
            .prepare::<Span>()
            .search_with_workspace(b"a", &mut no_reset_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(no_reset_report.accounting().setup_work(), 3);
        assert_eq!(no_reset_report.accounting().setup().initialized_bytes(), 0);

        let automaton = ascii_literal(b'a');
        pin_without_start_filter(&automaton);
        let mut workspace =
            super::K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).expect("workspace");
        workspace.generation = u64::MAX
            .checked_sub(required_generations.checked_sub(1).unwrap())
            .unwrap();
        let before_reset = workspace.generation;

        let reset_work = 3_u64
            .checked_add(u64::try_from(automaton.stats().states()).unwrap())
            .unwrap();
        let error = automaton
            .prepare::<Span>()
            .search_with_workspace(
                b"a",
                &mut workspace,
                SearchLimits {
                    max_work: reset_work - 1,
                    max_scratch_bytes: usize::MAX,
                },
            )
            .unwrap_err();
        assert!(matches!(error, SearchError::WorkLimitExceeded { .. }));
        assert_eq!(workspace.generation, before_reset);

        let report = automaton
            .prepare::<Span>()
            .search_with_workspace(b"a", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(report.accounting().setup_work(), reset_work);
        assert_eq!(
            report.accounting().setup().initialized_bytes(),
            automaton.stats().states() * size_of::<u64>()
        );
        assert_eq!(report.into_output().unwrap().end(), 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "cold and warm ordinary/prevalidated/cursor modes share one rollover proof"
    )]
    fn nullable_generation_preflight_tracks_live_mode_and_cursor_parity() {
        let plan = empty_or_ab(false);
        plan.start_filter_proof
            .set(&StartFilterProof {
                scanner: None,
                filter: None,
                force_haystack_start: false,
                relaxed_nullable: true,
            })
            .expect("fresh nullable automaton");
        let limits = SearchLimits::unlimited();
        let cold_haystack = b"abxx";
        let cold_window = SearchWindow::new(0, cold_haystack.len());

        let mut ordinary_preflight =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut prepared_preflight =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let capabilities = super::lazy_capabilities(&plan, &ordinary_preflight, true, true);
        let mode =
            super::effective_lazy_mode(&plan, &ordinary_preflight, true, capabilities).unwrap();
        assert_eq!(
            mode,
            super::EffectiveLazyMode {
                lazy: true,
                reverse: false,
            }
        );
        let endpoint_required =
            super::required_generation_count(&plan, cold_window, mode.lazy, mode.reverse).unwrap();
        assert_eq!(
            endpoint_required,
            u64::try_from(cold_haystack.len() + 1 + START_FILTER_POSITION_COUNT + 1,).unwrap()
        );
        ordinary_preflight.generation = u64::MAX - endpoint_required;
        prepared_preflight.generation = u64::MAX - endpoint_required;
        let mut ordinary_setup =
            crate::SetupAccounting::empty(ordinary_preflight.retained_bytes, true);
        let mut prepared_setup =
            crate::SetupAccounting::empty(prepared_preflight.retained_bytes, true);
        let ordinary_prepared = super::prepare_invocation(
            &plan,
            &mut ordinary_preflight,
            cold_window,
            limits,
            &mut ordinary_setup,
            mode.lazy,
            mode.reverse,
        )
        .unwrap();
        let prevalidated = super::prepare_prevalidated_invocation(
            &plan,
            &mut prepared_preflight,
            cold_window,
            limits,
            &mut prepared_setup,
            mode.lazy,
            mode.reverse,
        )
        .unwrap();
        assert_eq!(ordinary_prepared.0.consumed, prevalidated.0.consumed);
        assert_eq!(ordinary_prepared.1, prevalidated.1);
        assert_eq!(ordinary_setup, prepared_setup);
        assert_eq!(ordinary_preflight.generation, prepared_preflight.generation);

        let mut endpoint_ordinary =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut endpoint_cursor =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        endpoint_ordinary.generation = u64::MAX - endpoint_required;
        endpoint_cursor.generation = u64::MAX - endpoint_required;
        let ordinary_report = plan
            .prepare::<Span>()
            .search_window_with_workspace(
                cold_haystack,
                cold_window,
                &mut endpoint_ordinary,
                limits,
            )
            .unwrap();
        let cursor_report = super::search_span_with_workspace_cursor(
            &plan,
            cold_haystack,
            0,
            &mut endpoint_cursor,
            limits,
        )
        .unwrap();
        assert_eq!(ordinary_report.output(), &cursor_report.found);
        assert_eq!(ordinary_report.accounting(), cursor_report.accounting);
        assert_eq!(endpoint_ordinary.generation, endpoint_cursor.generation);
        assert_eq!(ordinary_report.accounting().setup().initialized_bytes(), 0);

        let mut full_ordinary =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut full_cursor =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let cold_full_mode = super::effective_lazy_mode(
            &plan,
            &full_ordinary,
            true,
            super::lazy_capabilities(&plan, &full_ordinary, true, true),
        )
        .unwrap();
        assert_eq!(
            cold_full_mode,
            super::EffectiveLazyMode {
                lazy: true,
                reverse: true,
            }
        );
        let cold_full_required = super::required_generation_count(
            &plan,
            cold_window,
            cold_full_mode.lazy,
            cold_full_mode.reverse,
        )
        .unwrap();
        assert_eq!(
            cold_full_required,
            endpoint_required + u64::try_from(cold_haystack.len() + 1).unwrap()
        );
        full_ordinary.generation = u64::MAX - cold_full_required;
        full_cursor.generation = u64::MAX - cold_full_required;
        let ordinary_cold = plan
            .prepare::<Span>()
            .search_window_with_workspace(cold_haystack, cold_window, &mut full_ordinary, limits)
            .unwrap();
        let cursor_cold = super::search_span_with_workspace_cursor(
            &plan,
            cold_haystack,
            0,
            &mut full_cursor,
            limits,
        )
        .unwrap();
        assert_eq!(ordinary_cold.output(), &cursor_cold.found);
        assert_eq!(ordinary_cold.accounting(), cursor_cold.accounting);
        assert_eq!(full_ordinary.generation, full_cursor.generation);
        assert!(!full_ordinary.reverse.initialized);
        assert!(!full_cursor.reverse.initialized);

        let warm_haystack = b"xxab";
        let warm_window = SearchWindow::new(2, warm_haystack.len());
        let warm_ordinary_mode = super::effective_lazy_mode(
            &plan,
            &full_ordinary,
            true,
            super::lazy_capabilities(&plan, &full_ordinary, true, true),
        )
        .unwrap();
        let warm_cursor_cache =
            super::prepare_span_cursor(&plan, &mut full_cursor, limits).unwrap();
        let warm_cursor_mode =
            super::effective_lazy_mode(&plan, &full_cursor, true, warm_cursor_cache.capabilities)
                .unwrap();
        assert_eq!(warm_ordinary_mode, warm_cursor_mode);
        assert_eq!(
            warm_ordinary_mode,
            super::EffectiveLazyMode {
                lazy: true,
                reverse: false,
            }
        );
        let warm_required = super::required_generation_count(
            &plan,
            warm_window,
            warm_ordinary_mode.lazy,
            warm_ordinary_mode.reverse,
        )
        .unwrap();
        full_ordinary.seen_at.fill(0);
        full_cursor.seen_at.fill(0);
        full_ordinary.generation = u64::MAX - warm_required;
        full_cursor.generation = u64::MAX - warm_required;
        let ordinary_warm = plan
            .prepare::<Span>()
            .search_window_with_workspace(warm_haystack, warm_window, &mut full_ordinary, limits)
            .unwrap();
        let cursor_warm = super::search_span_with_workspace_cursor(
            &plan,
            warm_haystack,
            warm_window.start(),
            &mut full_cursor,
            limits,
        )
        .unwrap();
        assert_eq!(ordinary_warm.output(), &cursor_warm.found);
        assert_eq!(ordinary_warm.accounting(), cursor_warm.accounting);
        assert_eq!(full_ordinary.generation, full_cursor.generation);
        assert_eq!(ordinary_warm.accounting().setup().initialized_bytes(), 0);
    }

    #[test]
    fn sparse_ascii_root_skips_impossible_starts_and_preserves_the_span() {
        let automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 2, 2],
                edge_targets: vec![1, 2],
                edge_kinds: vec![EdgeKind::ByteRange, EdgeKind::ByteRange],
                byte_starts: vec![b'0', b'/'],
                byte_ends: vec![b'9', b'/'],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();

        let mut haystack = vec![b'x'; 96];
        haystack.extend_from_slice(b"5/");
        automaton
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let miss = automaton
            .prepare::<Span>()
            .search_with_workspace(b"xxxx", &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(miss.accounting().boundaries(), 0);
        assert!(miss.into_output().is_none());
        let report = automaton
            .prepare::<Span>()
            .search_with_workspace(&haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        let accounting = report.accounting();
        let found = report.into_output().unwrap();
        assert_eq!((found.start(), found.end()), (96, 98));
        assert_eq!(
            automaton
                .start_filter_proof
                .get()
                .expect("start proof should be initialized"),
            &StartFilterProof {
                scanner: Some(positioned_scanner(1, StartScanner::One(b'/'))),
                filter: Some(StartPositionFilter::Guard(StartPositionClass {
                    offset: 0,
                    set: byte_range_set(b'0', b'9'),
                })),
                force_haystack_start: false,
                relaxed_nullable: false,
            }
        );
        assert_eq!(accounting.boundaries(), 3);
        assert!(accounting.transition_work() < 120);
    }

    #[test]
    fn ranged_sparse_root_keeps_original_offsets() {
        let automaton = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 1],
                edge_targets: vec![1],
                edge_kinds: vec![EdgeKind::ByteRange],
                byte_starts: vec![b'a'],
                byte_ends: vec![b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut workspace = K0Workspace::new(&automaton, WorkspaceLimits::unlimited()).unwrap();
        let haystack = b"a...............................a";
        let report = automaton
            .prepare::<Span>()
            .search_window_with_workspace(
                haystack,
                SearchWindow::new(1, haystack.len()),
                &mut workspace,
                SearchLimits::unlimited(),
            )
            .unwrap();
        let found = report.into_output().unwrap();
        assert_eq!((found.start(), found.end()), (32, 33));
    }

    #[test]
    fn nullable_declines_while_asserted_and_high_byte_roots_filter() {
        let nullable = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Accept],
                edge_offsets: vec![0, 0],
                edge_targets: vec![],
                edge_kinds: vec![],
                byte_starts: vec![],
                byte_ends: vec![],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut nullable_workspace =
            K0Workspace::new(&nullable, WorkspaceLimits::unlimited()).unwrap();
        let nullable_cold = nullable
            .prepare::<Span>()
            .search_with_workspace(b"", &mut nullable_workspace, SearchLimits::unlimited())
            .unwrap();
        let nullable_warm = nullable
            .prepare::<Span>()
            .search_with_workspace(b"", &mut nullable_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            nullable_cold
                .accounting()
                .transition_work()
                .checked_sub(nullable_warm.accounting().transition_work()),
            Some(1)
        );
        assert!(nullable
            .start_filter_proof
            .get()
            .expect("nullable proof should be initialized")
            .scanner
            .is_none());

        let asserted = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 2, 2],
                edge_targets: vec![1, 2],
                edge_kinds: vec![EdgeKind::AssertLineStartLf, EdgeKind::ByteRange],
                byte_starts: vec![0, b'a'],
                byte_ends: vec![0, b'a'],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut asserted_workspace =
            K0Workspace::new(&asserted, WorkspaceLimits::unlimited()).unwrap();
        asserted
            .prepare::<Span>()
            .search_with_workspace(b"a", &mut asserted_workspace, SearchLimits::unlimited())
            .unwrap();
        assert!(matches!(
            asserted
                .start_filter_proof
                .get()
                .expect("asserted proof should be initialized")
                .scanner,
            Some(StartPositionScanner {
                offset: 0,
                scanner: StartScanner::One(b'a'),
            })
        ));

        let high = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Consume, StateRole::Accept],
                edge_offsets: vec![0, 1, 1],
                edge_targets: vec![1],
                edge_kinds: vec![EdgeKind::ByteRange],
                byte_starts: vec![0x80],
                byte_ends: vec![0xff],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut high_workspace = K0Workspace::new(&high, WorkspaceLimits::unlimited()).unwrap();
        high.prepare::<Span>()
            .search_with_workspace(&[0x80], &mut high_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            high.start_filter_proof
                .get()
                .expect("high-byte proof should be initialized")
                .scanner,
            Some(StartPositionScanner {
                offset: 0,
                scanner: scanner_for_set(ByteSet::from_words([0, 0, u64::MAX, u64::MAX,])),
            })
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "all four typed contracts share one exhaustive window matrix"
    )]
    fn ordered_lazy_dfa_is_exhaustively_differential_for_every_contract_and_window() {
        let plans = [
            a_plus(true),
            a_plus(false),
            ordered_a_or_ab(true),
            ordered_a_or_ab(false),
            greedy_a_plus_or_a(),
            greedy_binary_pair_plus_then_80(),
            multi_target_consume_a_or_bc(),
            byte_chain(&[(0x00, 0xff), (b'Z', b'Z')]),
        ];
        let haystacks = bounded_words(&[0x00, b'a', b'b', 0x80, 0xff], 4);
        let mut checked = 0usize;

        for plan in &plans {
            let mut pike = K0Workspace::new(plan, WorkspaceLimits::unlimited()).unwrap();
            let mut accelerated =
                K0Workspace::new_accelerated(plan, WorkspaceLimits::unlimited()).unwrap();
            let mut bidirectional =
                K0Workspace::new_bidirectional(plan, WorkspaceLimits::unlimited()).unwrap();
            assert!(accelerated.retained_bytes() > pike.retained_bytes());
            assert!(bidirectional.retained_bytes() > accelerated.retained_bytes());

            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let want_exists = plan
                            .prepare::<Exists>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        let got_exists = plan
                            .prepare::<Exists>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut accelerated,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        assert_eq!(
                            got_exists, want_exists,
                            "exists mismatch plan={plan:?}, source={haystack:?}, window={window:?}"
                        );

                        let want_earliest = plan
                            .prepare::<EarliestEnd>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        let got_earliest = plan
                            .prepare::<EarliestEnd>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut bidirectional,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        assert_eq!(
                            got_earliest, want_earliest,
                            "earliest mismatch plan={plan:?}, source={haystack:?}, window={window:?}"
                        );

                        let want_selected = plan
                            .prepare::<SelectedEnd>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        let got_selected = plan
                            .prepare::<SelectedEnd>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut accelerated,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        assert_eq!(
                            got_selected, want_selected,
                            "selected mismatch plan={plan:?}, source={haystack:?}, window={window:?}"
                        );

                        let want_span = plan
                            .prepare::<Span>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        let got_span = plan
                            .prepare::<Span>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut bidirectional,
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .into_output();
                        assert_eq!(
                            got_span, want_span,
                            "span mismatch plan={plan:?}, source={haystack:?}, window={window:?}"
                        );
                        checked = checked.checked_add(1).unwrap();
                    }
                }
            }
            assert!(accelerated.lazy.initialized);
            assert!(!accelerated.lazy.declined);
            assert!(bidirectional.lazy.initialized);
            assert!(bidirectional.reverse.initialized);
            assert!(!bidirectional.reverse.declined);
        }
        assert!(checked > 10_000);
    }

    #[test]
    fn direct_cells_certify_source_propagation_root_reset_and_mixed_drop() {
        let propagated = a_plus(true);
        pin_without_start_filter(&propagated);
        let mut propagated_workspace =
            K0Workspace::new_accelerated(&propagated, WorkspaceLimits::unlimited()).unwrap();
        propagated
            .prepare::<SelectedEnd>()
            .search_with_workspace(b"ba", &mut propagated_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            propagated_workspace.lazy.initial_kind,
            super::LazyInitialKind::PositiveSingle
        );
        let initial = propagated_workspace.lazy.initial;
        assert_eq!(
            super::LazyStartAction::from_direct_cell(
                propagated_workspace.lazy.cell(initial, b'a').unwrap()
            ),
            super::LazyStartAction::Propagate
        );
        assert_eq!(
            super::LazyStartAction::from_direct_cell(
                propagated_workspace.lazy.cell(initial, b'b').unwrap()
            ),
            super::LazyStartAction::Reset
        );

        let mixed = byte_chain(&[(b'a', b'a'), (b'b', b'b')]);
        pin_without_start_filter(&mixed);
        let mut mixed_workspace =
            K0Workspace::new_accelerated(&mixed, WorkspaceLimits::unlimited()).unwrap();
        mixed
            .prepare::<SelectedEnd>()
            .search_with_workspace(b"a", &mut mixed_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            mixed_workspace.lazy.initial_kind,
            super::LazyInitialKind::PositiveSingle
        );
        assert_eq!(
            super::LazyStartAction::from_direct_cell(
                mixed_workspace
                    .lazy
                    .cell(mixed_workspace.lazy.initial, b'a')
                    .unwrap()
            ),
            super::LazyStartAction::Drop,
            "the continuing `b` thread and newly injected `a` root have distinct starts"
        );

        let uniform_multi = greedy_a_plus_or_a();
        pin_without_start_filter(&uniform_multi);
        let mut uniform_multi_workspace =
            K0Workspace::new_accelerated(&uniform_multi, WorkspaceLimits::unlimited()).unwrap();
        uniform_multi
            .prepare::<SelectedEnd>()
            .search_with_workspace(
                b"ba",
                &mut uniform_multi_workspace,
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(
            uniform_multi_workspace.lazy.initial_kind,
            super::LazyInitialKind::Positive
        );
        let uniform_multi_initial = uniform_multi_workspace.lazy.initial;
        assert_eq!(
            super::LazyStartAction::from_direct_cell(
                uniform_multi_workspace
                    .lazy
                    .cell(uniform_multi_initial, b'a')
                    .unwrap()
            ),
            super::LazyStartAction::Propagate
        );
        assert_eq!(
            super::LazyStartAction::from_direct_cell(
                uniform_multi_workspace
                    .lazy
                    .cell(uniform_multi_initial, b'b')
                    .unwrap()
            ),
            super::LazyStartAction::Reset
        );

        let mixed_multi = ordered_ab_or_ac();
        pin_without_start_filter(&mixed_multi);
        let mut mixed_multi_workspace =
            K0Workspace::new_accelerated(&mixed_multi, WorkspaceLimits::unlimited()).unwrap();
        mixed_multi
            .prepare::<SelectedEnd>()
            .search_with_workspace(b"a", &mut mixed_multi_workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            mixed_multi_workspace.lazy.initial_kind,
            super::LazyInitialKind::Positive
        );
        assert_eq!(
            super::LazyStartAction::from_direct_cell(
                mixed_multi_workspace
                    .lazy
                    .cell(mixed_multi_workspace.lazy.initial, b'a')
                    .unwrap()
            ),
            super::LazyStartAction::Drop,
            "two continuing source threads and a newly injected root have distinct starts"
        );
    }

    #[test]
    fn singleton_start_certificate_is_exhaustive_and_never_reads_reverse_rows() {
        let plans = [
            ("one-byte", byte_chain(&[(b'a', b'a')])),
            ("greedy-plus", a_plus(true)),
            ("lazy-plus", a_plus(false)),
        ];
        let haystacks = bounded_words(&[b'a', b'b', 0xff], 4);
        let mut checked = 0usize;

        for (name, plan) in &plans {
            pin_without_start_filter(plan);
            let mut pike = K0Workspace::new(plan, WorkspaceLimits::unlimited()).unwrap();
            let mut direct =
                K0Workspace::new_bidirectional(plan, WorkspaceLimits::unlimited()).unwrap();
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let want = plan
                            .prepare::<Span>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        let got = plan
                            .prepare::<Span>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut direct,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        assert_eq!(
                            got.output(),
                            want.output(),
                            "{name}: source={haystack:?} window={window:?}"
                        );
                        checked = checked.checked_add(1).unwrap();
                    }
                }
            }
            assert_eq!(
                direct.lazy.initial_kind,
                super::LazyInitialKind::PositiveSingle,
                "{name}"
            );
            assert!(direct.reverse.initialized, "{name}");
            assert!(
                direct
                    .reverse
                    .rows
                    .iter()
                    .all(|&cell| cell == super::LAZY_CELL_UNFILLED),
                "{name}: a certified span must not execute reverse recovery"
            );
        }
        assert!(checked > 1_000);
    }

    #[test]
    fn uniform_multi_item_start_certificate_is_exhaustive_and_drops_on_mixed_provenance() {
        let plans = [
            ("greedy-plus-or-a", greedy_a_plus_or_a(), true),
            ("long-a-or-ab", ordered_a_or_ab(true), true),
            ("ab-or-ac", ordered_ab_or_ac(), false),
        ];
        let haystacks = bounded_words(&[b'a', b'b', b'c', 0xff], 4);
        let mut checked = 0usize;

        for (name, plan, remains_uniform) in &plans {
            pin_without_start_filter(plan);
            let mut pike = K0Workspace::new(plan, WorkspaceLimits::unlimited()).unwrap();
            let mut direct =
                K0Workspace::new_bidirectional(plan, WorkspaceLimits::unlimited()).unwrap();
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let want = plan
                            .prepare::<Span>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        let got = plan
                            .prepare::<Span>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut direct,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        assert_eq!(
                            got.output(),
                            want.output(),
                            "{name}: source={haystack:?} window={window:?}"
                        );
                        checked = checked.checked_add(1).unwrap();
                    }
                }
            }
            assert_eq!(
                direct.lazy.initial_kind,
                super::LazyInitialKind::Positive,
                "{name}: the initial closure must contain multiple consuming items"
            );
            assert!(direct.reverse.initialized, "{name}");
            let reverse_untouched = direct
                .reverse
                .rows
                .iter()
                .all(|&cell| cell == super::LAZY_CELL_UNFILLED);
            assert_eq!(
                reverse_untouched, *remains_uniform,
                "{name}: reverse execution must follow the provenance certificate"
            );
        }
        assert!(checked > 10_000);
    }

    #[test]
    fn certified_span_preserves_exact_finite_work_and_boundary_accounting() {
        let plan = a_plus(true);
        pin_without_start_filter(&plan);
        let haystack = b"baaaa";
        let mut workspace =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let retained = workspace.retained_bytes();

        let span = plan
            .prepare::<Span>()
            .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(span.output(), &Some(MatchSpan::new(1, haystack.len())));
        assert!(workspace
            .reverse
            .rows
            .iter()
            .all(|&cell| cell == super::LAZY_CELL_UNFILLED));
        let selected = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(
            span.accounting().boundaries(),
            selected.accounting().boundaries()
        );

        let measured = plan
            .prepare::<Span>()
            .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        assert_eq!(
            plan.prepare::<Span>()
                .search_with_workspace(
                    haystack,
                    &mut workspace,
                    SearchLimits {
                        max_work: measured,
                        max_scratch_bytes: retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(MatchSpan::new(1, haystack.len()))
        );
        assert!(matches!(
            plan.prepare::<Span>().search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: measured - 1,
                    max_scratch_bytes: retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == measured - 1
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "nullable priority needs all four contracts over the same exhaustive windows"
    )]
    fn nullable_ordered_lazy_dfa_matches_pike_for_every_contract_and_window() {
        let plans = [
            ("greedy-star", a_star(true), false),
            ("lazy-star", a_star(false), true),
            ("greedy-question", a_question(true), false),
            ("lazy-question", a_question(false), true),
            ("empty-first-greedy-plus", empty_or_a_plus(true, true), true),
            ("empty-first-lazy-plus", empty_or_a_plus(true, false), true),
            (
                "positive-first-greedy-plus",
                empty_or_a_plus(false, true),
                false,
            ),
            (
                "positive-first-lazy-plus",
                empty_or_a_plus(false, false),
                false,
            ),
            ("empty-first-ab", empty_or_ab(true), true),
            ("positive-first-ab", empty_or_ab(false), false),
        ];
        let haystacks = bounded_words(&[0x00, b'a', b'b', 0x80, 0xff], 3);
        let mut checked = 0usize;
        let mut positive_spans = 0usize;

        for (name, plan, _terminal_initial) in &plans {
            pin_without_start_filter(plan);
            let mut pike = K0Workspace::new(plan, WorkspaceLimits::unlimited()).unwrap();
            let mut endpoint =
                K0Workspace::new_accelerated(plan, WorkspaceLimits::unlimited()).unwrap();
            let mut bidirectional =
                K0Workspace::new_bidirectional(plan, WorkspaceLimits::unlimited()).unwrap();

            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let want_exists = plan
                            .prepare::<Exists>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        let got_exists = plan
                            .prepare::<Exists>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut endpoint,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        assert_eq!(
                            got_exists.output(),
                            want_exists.output(),
                            "{name}: Exists source={haystack:?} window={window:?}"
                        );
                        assert_eq!(
                            got_exists.accounting().boundaries(),
                            want_exists.accounting().boundaries(),
                            "{name}: Exists boundary accounting"
                        );

                        let want_earliest = plan
                            .prepare::<EarliestEnd>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        let got_earliest = plan
                            .prepare::<EarliestEnd>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut endpoint,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        assert_eq!(
                            got_earliest.output(),
                            want_earliest.output(),
                            "{name}: EarliestEnd source={haystack:?} window={window:?}"
                        );
                        assert_eq!(
                            got_earliest.accounting().boundaries(),
                            want_earliest.accounting().boundaries(),
                            "{name}: EarliestEnd boundary accounting"
                        );

                        let want_selected = plan
                            .prepare::<SelectedEnd>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        let got_selected = plan
                            .prepare::<SelectedEnd>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut endpoint,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        assert_eq!(
                            got_selected.output(),
                            want_selected.output(),
                            "{name}: SelectedEnd source={haystack:?} window={window:?}"
                        );
                        assert_eq!(
                            got_selected.accounting().boundaries(),
                            want_selected.accounting().boundaries(),
                            "{name}: SelectedEnd boundary accounting"
                        );

                        let want_span = plan
                            .prepare::<Span>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut pike,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        let got_span = plan
                            .prepare::<Span>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut endpoint,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        let got_full_span = plan
                            .prepare::<Span>()
                            .search_window_with_workspace(
                                haystack,
                                window,
                                &mut bidirectional,
                                SearchLimits::unlimited(),
                            )
                            .unwrap();
                        assert_eq!(
                            got_span.output(),
                            want_span.output(),
                            "{name}: endpoint Span source={haystack:?} window={window:?}"
                        );
                        assert_eq!(
                            got_full_span.output(),
                            want_span.output(),
                            "{name}: full Span source={haystack:?} window={window:?}"
                        );
                        assert_eq!(
                            got_span.accounting().boundaries(),
                            want_span.accounting().boundaries(),
                            "{name}: start-known endpoint Span boundary accounting"
                        );
                        assert_eq!(
                            got_full_span.accounting().boundaries(),
                            want_span.accounting().boundaries(),
                            "{name}: start-known full Span boundary accounting"
                        );
                        if let Some(selected) = want_span.output() {
                            assert_eq!(
                                selected.start(),
                                window.start(),
                                "{name}: nullable selected start proof"
                            );
                            if selected.end() > selected.start() {
                                positive_spans = positive_spans.checked_add(1).unwrap();
                            }
                        }
                        checked = checked.checked_add(1).unwrap();
                    }
                }
            }

            assert!(endpoint.lazy.initialized, "{name}: endpoint initialized");
            assert!(!endpoint.lazy.declined, "{name}: endpoint accepted");
            assert!(
                !endpoint.lazy.saturated,
                "{name}: exhaustive nullable identities fit their proven capacity"
            );
            assert!(endpoint.lazy.state_len <= endpoint.layout.lazy_state_capacity);
            assert!(endpoint.lazy.item_len <= endpoint.layout.lazy_item_capacity);
            assert!(bidirectional.lazy.initialized, "{name}: span initialized");
            assert!(
                !bidirectional.reverse.initialized,
                "{name}: start-known span must not prepare reverse"
            );
            assert!(
                !bidirectional.lazy.declined,
                "{name}: span forward accepted"
            );
            assert!(
                !bidirectional.lazy.saturated,
                "{name}: full-session forward identities fit their proven capacity"
            );
            assert!(bidirectional.lazy.state_len <= bidirectional.layout.lazy_state_capacity);
            assert!(bidirectional.lazy.item_len <= bidirectional.layout.lazy_item_capacity);
        }
        assert!(checked > 10_000);
        assert!(positive_spans > 100);
    }

    #[test]
    fn contextual_assertion_masks_match_the_canonical_edge_evaluator() {
        let mut haystacks = bounded_words(&[0, b'\r', b'\n', b';', b'a', b'_', 0x80], 3);
        haystacks.extend([
            "é".as_bytes().to_vec(),
            "α_".as_bytes().to_vec(),
            vec![0xf0, 0x9f, 0x92, 0xa9],
            vec![0xf0, 0x28, 0x8c, 0xbc],
            vec![0xc3],
            vec![0x80, b'a'],
        ]);
        for kind in super::ASSERTION_KINDS {
            let plan = assertion_or_colon(kind).with_line_terminator(b';');
            let bit = kind.assertion_bit().unwrap();
            assert_eq!(plan.stats().assertion_kinds(), bit);
            for haystack in &haystacks {
                for position in 0..=haystack.len() {
                    let mut meter = WorkMeter::new(u64::MAX, 0);
                    let mask = super::enabled_assertion_mask(&plan, haystack, position, &mut meter)
                        .unwrap();
                    let expected =
                        super::zero_width_edge_enabled(&plan, kind, haystack, position).unwrap();
                    assert_eq!(
                        mask & bit != 0,
                        expected,
                        "mask mismatch kind={kind:?} source={haystack:?} position={position}"
                    );
                    assert_eq!(mask & !bit, 0);
                    assert_eq!(meter.consumed, 1);
                }
            }
        }
    }

    #[test]
    fn compiled_context_classifier_matches_every_canonical_assertion_together() {
        fn check(plan: &Automaton, haystack: &[u8], position: usize) {
            let expected = super::ASSERTION_KINDS
                .into_iter()
                .filter(|&kind| {
                    super::zero_width_edge_enabled(plan, kind, haystack, position).unwrap()
                })
                .fold(0_u32, |mask, kind| mask | kind.assertion_bit().unwrap());
            let mut meter = WorkMeter::new(u64::MAX, 0);
            let got = super::enabled_assertion_mask(plan, haystack, position, &mut meter).unwrap();
            assert_eq!(
                got,
                expected,
                "source={haystack:?} position={position} terminator={}",
                plan.line_terminator()
            );
            assert_eq!(
                meter.consumed,
                u64::try_from(super::ASSERTION_KIND_COUNT).unwrap()
            );
        }

        for line_terminator in u8::MIN..=u8::MAX {
            let plan = every_assertion().with_line_terminator(line_terminator);
            let haystacks = [
                vec![],
                vec![line_terminator],
                vec![b'\r', line_terminator, b'\n'],
                vec![line_terminator, b'\r', b'\n', line_terminator],
            ];
            for haystack in haystacks {
                for position in 0..=haystack.len() {
                    check(&plan, &haystack, position);
                }
            }
        }

        let plan = every_assertion().with_line_terminator(b';');
        check(&plan, &[], 0);
        for byte in u8::MIN..=u8::MAX {
            check(&plan, &[byte], 0);
            check(&plan, &[byte], 1);
        }
        for left in u8::MIN..=u8::MAX {
            for right in u8::MIN..=u8::MAX {
                check(&plan, &[left, right], 1);
            }
        }

        let mut haystacks = bounded_words(&[0, b'\r', b'\n', b';', b'a', b'_', 0x80], 3);
        haystacks.extend([
            "é".as_bytes().to_vec(),
            "α_".as_bytes().to_vec(),
            " aβ\u{200C}!".as_bytes().to_vec(),
            vec![0xf0, 0x9f, 0x92, 0xa9],
            vec![0xf0, 0x28, 0x8c, 0xbc],
            vec![0xc3],
            vec![0x80, b'a'],
            vec![b'a', 0xed, 0xa0, 0x80, b'_'],
            vec![0xf4, 0x90, 0x80, 0x80],
        ]);
        for haystack in haystacks {
            for position in 0..=haystack.len() {
                check(&plan, &haystack, position);
            }
        }
    }

    #[test]
    fn compiled_context_classifier_preserves_finite_work_failure_timing() {
        let plan = every_assertion();
        let haystack = b"a_b";
        let checks = u64::try_from(super::ASSERTION_KIND_COUNT).unwrap();
        for limit in 0..checks {
            let mut meter = WorkMeter::new(limit, 0);
            assert_eq!(
                super::enabled_assertion_mask(&plan, haystack, 1, &mut meter),
                Err(SearchError::WorkLimitExceeded {
                    limit,
                    consumed: limit,
                    requested: 1,
                    position: 1,
                })
            );
            assert_eq!(meter.consumed, limit);
        }
        let mut meter = WorkMeter::new(checks, 0);
        super::enabled_assertion_mask(&plan, haystack, 1, &mut meter).unwrap();
        assert_eq!(meter.consumed, checks);
    }

    #[test]
    fn contextual_cache_keys_distinguish_the_same_state_and_byte_by_mask() {
        let kind = EdgeKind::AssertLineEndLf;
        let plan = trailing_assertion_or_bang(kind);
        let mut workspace =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut meter = WorkMeter::new(u64::MAX, 0);
        let (state, _) = super::context_lazy_initial(&plan, 0, &mut workspace, &mut meter, 0, 0)
            .unwrap()
            .unwrap();
        let super::LazyState::Cached(source) = state else {
            panic!("unlimited initial state must be retained");
        };
        let bit = kind.assertion_bit().unwrap();
        let disabled_symbol = super::contextual_symbol(u32::from(b'a'), 0);
        let enabled_symbol = super::contextual_symbol(u32::from(b'a'), bit);
        let disabled = super::build_context_lazy_cached_transition(
            &plan,
            source,
            b'a',
            disabled_symbol,
            0,
            &mut workspace,
            &mut meter,
            0,
            1,
        )
        .unwrap();
        let enabled = super::build_context_lazy_cached_transition(
            &plan,
            source,
            b'a',
            enabled_symbol,
            bit,
            &mut workspace,
            &mut meter,
            0,
            1,
        )
        .unwrap();
        let super::ContextLazyTransition::Ready(disabled) = disabled else {
            panic!("unlimited transition must be retained");
        };
        let super::ContextLazyTransition::Ready(enabled) = enabled else {
            panic!("unlimited transition must be retained");
        };
        assert_eq!(disabled & super::LAZY_CELL_ACCEPT, 0);
        assert_ne!(enabled & super::LAZY_CELL_ACCEPT, 0);
        assert!(workspace.lazy.context.slots.iter().any(|slot| {
            slot.source == source && slot.symbol == disabled_symbol && slot.value == disabled
        }));
        assert!(workspace.lazy.context.slots.iter().any(|slot| {
            slot.source == source && slot.symbol == enabled_symbol && slot.value == enabled
        }));
    }

    #[test]
    fn contextual_lazy_dfa_is_differential_for_every_assertion_contract_and_window() {
        let haystacks = vec![
            Vec::new(),
            b":".to_vec(),
            b"a".to_vec(),
            b"a!".to_vec(),
            b"x:a!".to_vec(),
            b"\na\n".to_vec(),
            b"\r\na!\r\n".to_vec(),
            b";a!;".to_vec(),
            b"_a! x:a".to_vec(),
            "éa! α:a".as_bytes().to_vec(),
            vec![0x80, b'a', b'!', 0xc3, b':'],
            vec![b'x', 0xf0, 0x28, 0x8c, 0xbc, b'a', b'!'],
        ];
        for kind in super::ASSERTION_KINDS {
            let leading = assertion_or_colon(kind).with_line_terminator(b';');
            assert_contextual_all_contracts(&leading, &haystacks);
            let trailing = trailing_assertion_or_bang(kind).with_line_terminator(b';');
            assert_contextual_all_contracts(&trailing, &haystacks);
        }
    }

    #[test]
    fn contextual_empty_initial_state_can_activate_at_a_later_boundary() {
        let plan = asserted_line_a();
        pin_without_start_filter(&plan);
        let haystacks = vec![b"xx\na".to_vec(), b"x\nxa\n".to_vec(), b"\r\nx\na".to_vec()];
        assert_contextual_all_contracts(&plan, &haystacks);

        let mut pike = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut contextual =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let window = SearchWindow::new(1, 4);
        let want = plan
            .prepare::<Span>()
            .search_window_with_workspace(b"xx\na", window, &mut pike, SearchLimits::unlimited())
            .unwrap()
            .into_output();
        let got = plan
            .prepare::<Span>()
            .search_window_with_workspace(
                b"xx\na",
                window,
                &mut contextual,
                SearchLimits::unlimited(),
            )
            .unwrap()
            .into_output();
        assert_eq!(got, want);
        assert_eq!(got, Some(MatchSpan::new(3, 4)));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "contextual endpoint and bidirectional setup plus admission share one boundary matrix"
    )]
    fn contextual_layout_and_finite_admission_boundaries_are_exact() {
        let plan = asserted_line_a();
        pin_without_start_filter(&plan);
        let ordinary = plan.workspace_layout().unwrap();
        let endpoint = plan.accelerated_workspace_layout().unwrap();
        let full = plan.bidirectional_workspace_layout().unwrap();
        assert!(endpoint.logical_bytes() > ordinary.logical_bytes());
        assert!(endpoint.construction_work() > ordinary.construction_work());
        assert!(full.logical_bytes() > endpoint.logical_bytes());
        assert!(full.construction_work() > endpoint.construction_work());
        let reverse_initialized = super::reverse_initialized_slots(
            full.states,
            full.edges,
            full.reverse_state_capacity,
            full.reverse_item_capacity,
            full.reverse_context_slots,
        )
        .unwrap();
        let reverse_build = full
            .states
            .checked_mul(3)
            .and_then(|work| {
                full.edges
                    .checked_mul(2)
                    .and_then(|edges| work.checked_add(edges))
            })
            .unwrap();
        let expected_reverse_work = reverse_initialized
            .checked_add(12)
            .and_then(|work| work.checked_add(reverse_build))
            .and_then(|work| u64::try_from(work).ok())
            .unwrap();
        assert_eq!(
            full.construction_work()
                .checked_sub(endpoint.construction_work())
                .unwrap(),
            expected_reverse_work
        );

        K0Workspace::new_accelerated(
            &plan,
            WorkspaceLimits {
                max_setup_work: endpoint.construction_work(),
                max_scratch_bytes: endpoint.logical_bytes(),
            },
        )
        .unwrap();
        assert!(matches!(
            K0Workspace::new_accelerated(
                &plan,
                WorkspaceLimits {
                    max_setup_work: endpoint.construction_work() - 1,
                    max_scratch_bytes: usize::MAX,
                },
            ),
            Err(SearchError::WorkspaceSetupWorkLimitExceeded { limit, needed })
                if limit == endpoint.construction_work() - 1
                    && needed == endpoint.construction_work()
        ));
        assert!(matches!(
            K0Workspace::new_accelerated(
                &plan,
                WorkspaceLimits {
                    max_setup_work: u64::MAX,
                    max_scratch_bytes: endpoint.logical_bytes() - 1,
                },
            ),
            Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed,
                limit,
            }) if needed == endpoint.logical_bytes() && limit == endpoint.logical_bytes() - 1
        ));

        let full_workspace = K0Workspace::new_bidirectional(
            &plan,
            WorkspaceLimits {
                max_setup_work: full.construction_work(),
                max_scratch_bytes: full.logical_bytes(),
            },
        )
        .unwrap();
        assert!(
            full_workspace.construction_accounting().initialized_bytes() > full.logical_bytes(),
            "contextual reverse CSR rewrites must be included in initialization accounting"
        );
        assert!(matches!(
            K0Workspace::new_bidirectional(
                &plan,
                WorkspaceLimits {
                    max_setup_work: full.construction_work() - 1,
                    max_scratch_bytes: usize::MAX,
                },
            ),
            Err(SearchError::WorkspaceSetupWorkLimitExceeded { limit, needed })
                if limit == full.construction_work() - 1
                    && needed == full.construction_work()
        ));
        assert!(matches!(
            K0Workspace::new_bidirectional(
                &plan,
                WorkspaceLimits {
                    max_setup_work: u64::MAX,
                    max_scratch_bytes: full.logical_bytes() - 1,
                },
            ),
            Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed,
                limit,
            }) if needed == full.logical_bytes() && limit == full.logical_bytes() - 1
        ));

        let haystack = b"x\na";
        let endpoint_upper =
            super::contextual_execution_work_upper(&plan, haystack.len(), false).unwrap();
        let endpoint_limit = INVOCATION_RESET_WORK.checked_add(endpoint_upper).unwrap();
        let mut admitted =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let admitted_retained = admitted.retained_bytes();
        let report = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(
                haystack,
                &mut admitted,
                SearchLimits {
                    max_work: endpoint_limit,
                    max_scratch_bytes: admitted_retained,
                },
            )
            .unwrap();
        assert_eq!(report.output(), &Some(haystack.len()));
        assert!(report.accounting().work() <= endpoint_limit);
        assert!(admitted.lazy.initialized);
        assert_eq!(admitted.lazy.state_len, 0);
        assert_eq!(admitted.lazy.context.occupied_slots(), 0);

        let learning_limit = endpoint_limit.checked_add(10_000).unwrap();
        let mut learning =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let learning_retained = learning.retained_bytes();
        let cold = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(
                haystack,
                &mut learning,
                SearchLimits {
                    max_work: learning_limit,
                    max_scratch_bytes: learning_retained,
                },
            )
            .unwrap();
        assert_eq!(cold.output(), &Some(haystack.len()));
        assert!(learning.lazy.state_len > 0);
        assert!(learning.lazy.context.occupied_slots() > 0);
        let occupied = learning.lazy.context.occupied_slots();
        let warm = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(
                haystack,
                &mut learning,
                SearchLimits {
                    max_work: learning_limit,
                    max_scratch_bytes: learning_retained,
                },
            )
            .unwrap();
        assert_eq!(warm.output(), cold.output());
        assert!(
            warm.accounting().transition_work() < cold.accounting().transition_work(),
            "finite surplus must retain reusable contextual hits"
        );
        assert_eq!(learning.lazy.context.occupied_slots(), occupied);

        let mut refused =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let refused_retained = refused.retained_bytes();
        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(
                    haystack,
                    &mut refused,
                    SearchLimits {
                        max_work: endpoint_limit - 1,
                        max_scratch_bytes: refused_retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(haystack.len())
        );
        assert!(!refused.lazy.initialized);
        assert_eq!(refused.lazy.context.occupied_slots(), 0);

        let ordinary_certificate = plan.conservative_reused_work_bound(haystack.len()).unwrap();
        let mut certified =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let certified_retained = certified.retained_bytes();
        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(
                    haystack,
                    &mut certified,
                    SearchLimits {
                        max_work: ordinary_certificate,
                        max_scratch_bytes: certified_retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(haystack.len())
        );
        assert!(!certified.lazy.initialized);
        assert_eq!(certified.lazy.context.occupied_slots(), 0);

        let span_upper =
            super::contextual_execution_work_upper(&plan, haystack.len(), true).unwrap();
        let span_limit = INVOCATION_RESET_WORK.checked_add(span_upper).unwrap();
        let mut span = K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let span_retained = span.retained_bytes();
        let report = plan
            .prepare::<Span>()
            .search_with_workspace(
                haystack,
                &mut span,
                SearchLimits {
                    max_work: span_limit,
                    max_scratch_bytes: span_retained,
                },
            )
            .unwrap();
        assert_eq!(report.output(), &Some(MatchSpan::new(2, 3)));
        assert!(report.accounting().work() <= span_limit);
        assert!(span.lazy.initialized);
        assert!(span.reverse.initialized);
        assert_eq!(span.lazy.state_len, 0);
        assert_eq!(span.reverse.state_len, 0);
        assert_eq!(span.lazy.context.occupied_slots(), 0);
        assert_eq!(span.reverse.context.occupied_slots(), 0);

        let mut span_refused =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let span_refused_retained = span_refused.retained_bytes();
        assert_eq!(
            plan.prepare::<Span>()
                .search_with_workspace(
                    haystack,
                    &mut span_refused,
                    SearchLimits {
                        max_work: span_limit - 1,
                        max_scratch_bytes: span_refused_retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(MatchSpan::new(2, 3))
        );
        assert!(!span_refused.lazy.initialized);
        assert!(!span_refused.reverse.initialized);
        assert_eq!(span_refused.lazy.context.occupied_slots(), 0);
        assert_eq!(span_refused.reverse.context.occupied_slots(), 0);
    }

    #[test]
    fn conditionally_nullable_assertions_have_an_exact_context_decline_allowance() {
        let plan = absolute_nullable_or_colon();
        let haystack = b":";
        let mut warm = K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(haystack, &mut warm, SearchLimits::unlimited(),)
                .unwrap()
                .into_output(),
            Some(0)
        );
        assert!(!warm.lazy.initialized);
        assert!(warm.lazy.declined);
        assert_eq!(warm.lazy.context.occupied_slots(), 0);

        let upper = super::contextual_execution_work_upper(&plan, haystack.len(), false).unwrap();
        let exact = INVOCATION_RESET_WORK.checked_add(upper).unwrap();
        for (max_work, context_declined) in [(exact, true), (exact - 1, false)] {
            let mut workspace =
                K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
            let retained = workspace.retained_bytes();
            assert_eq!(
                plan.prepare::<SelectedEnd>()
                    .search_with_workspace(
                        haystack,
                        &mut workspace,
                        SearchLimits {
                            max_work,
                            max_scratch_bytes: retained,
                        },
                    )
                    .unwrap()
                    .into_output(),
                Some(0)
            );
            assert!(!workspace.lazy.initialized);
            assert_eq!(workspace.lazy.declined, context_declined);
            assert_eq!(workspace.lazy.context.occupied_slots(), 0);
        }
    }

    #[test]
    fn full_context_buckets_continue_inline_without_changing_results() {
        let plan = assertion_or_colon(EdgeKind::AssertWordAscii);
        let mut pike = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut contextual =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let forward_slots = contextual.lazy.context.slots.len();
        let reverse_slots = contextual.reverse.context.slots.len();
        for slot in &mut contextual.lazy.context.slots {
            *slot = ContextTransitionSlot {
                source: CONTEXT_INITIAL_SOURCE - 1,
                symbol: 0,
                value: 0,
            };
        }
        for slot in &mut contextual.reverse.context.slots {
            *slot = ContextTransitionSlot {
                source: CONTEXT_INITIAL_SOURCE - 1,
                symbol: 0,
                value: 0,
            };
        }

        let haystacks = [
            b"".as_slice(),
            b":",
            b"a",
            b"x:a",
            b"_a :",
            &[0x80, b':', b'a'],
        ];
        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let want_end = plan
                        .prepare::<SelectedEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut pike,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let got_end = plan
                        .prepare::<SelectedEnd>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut contextual,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    assert_eq!(got_end, want_end, "endpoint {haystack:?}/{window:?}");

                    let want_span = plan
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut pike,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let got_span = plan
                        .prepare::<Span>()
                        .search_window_with_workspace(
                            haystack,
                            window,
                            &mut contextual,
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    assert_eq!(got_span, want_span, "span {haystack:?}/{window:?}");
                }
            }
        }
        assert_eq!(contextual.lazy.context.occupied_slots(), forward_slots);
        assert_eq!(contextual.reverse.context.occupied_slots(), reverse_slots);
    }

    #[test]
    fn empty_context_states_require_one_unit_of_publication_budget() {
        let plan = asserted_line_a();
        let mut forward =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        assert_eq!(forward.lazy.scratch_len, 0);
        let mut zero = WorkMeter::new(0, 0);
        assert_eq!(
            forward
                .lazy
                .intern_speculative(false, &mut zero, 0, 0)
                .unwrap(),
            super::LazyInterned::BudgetDeclined
        );
        assert_eq!(zero.consumed, 0);
        assert_eq!(forward.lazy.state_len, 0);

        let mut exact = WorkMeter::new(1, 0);
        assert_eq!(
            forward
                .lazy
                .intern_speculative(false, &mut exact, 0, 0)
                .unwrap(),
            super::LazyInterned::State(0)
        );
        assert_eq!(exact.consumed, 1);
        assert_eq!(forward.lazy.state_len, 1);
        forward.lazy.scratch[0] = 0;
        forward.lazy.scratch_len = 1;
        let mut fill = WorkMeter::new(u64::MAX, 0);
        assert_eq!(
            forward
                .lazy
                .intern_speculative(false, &mut fill, 0, 0)
                .unwrap(),
            super::LazyInterned::State(1)
        );
        forward.lazy.scratch[0] = 0;
        forward.lazy.scratch_len = 1;
        assert_eq!(
            forward
                .lazy
                .intern_speculative(true, &mut fill, 0, 0)
                .unwrap(),
            super::LazyInterned::State(2)
        );
        assert_eq!(forward.lazy.state_len, 3);
        assert_eq!(forward.lazy.item_len, 2);
        assert_eq!(forward.lazy.offsets.len(), 3);
        assert_eq!(forward.lazy.items.len(), 2);
        assert!(!forward.lazy.saturated);

        let mut reverse =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        assert_eq!(reverse.reverse.scratch_len, 0);
        let mut zero = WorkMeter::new(0, 0);
        assert_eq!(
            reverse.reverse.intern_speculative(&mut zero, 0, 0).unwrap(),
            super::LazyInterned::BudgetDeclined
        );
        assert_eq!(zero.consumed, 0);
        assert_eq!(reverse.reverse.state_len, 0);

        let mut exact = WorkMeter::new(1, 0);
        assert_eq!(
            reverse
                .reverse
                .intern_speculative(&mut exact, 0, 0)
                .unwrap(),
            super::LazyInterned::State(0)
        );
        assert_eq!(exact.consumed, 1);
        assert_eq!(reverse.reverse.state_len, 1);
        reverse.reverse.scratch[0] = 0;
        reverse.reverse.scratch_len = 1;
        let mut fill = WorkMeter::new(u64::MAX, 0);
        assert_eq!(
            reverse.reverse.intern_speculative(&mut fill, 0, 0).unwrap(),
            super::LazyInterned::State(1)
        );
        assert_eq!(reverse.reverse.state_len, 2);
        assert_eq!(reverse.reverse.item_len, 1);
        assert_eq!(reverse.reverse.offsets.len(), 2);
        assert_eq!(reverse.reverse.items.len(), 1);
        assert!(!reverse.reverse.saturated);
    }

    #[test]
    fn exact_small_contextual_capacity_exhaustion_is_an_invariant_failure() {
        let plan = asserted_line_a();
        assert!(plan.stats().consuming_states() <= super::EXACT_LAZY_CAPACITY_MAX_ITEMS);
        assert!(plan.stats().consuming_edges() <= super::EXACT_LAZY_CAPACITY_MAX_ITEMS);

        let mut forward =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        forward.lazy.offsets.truncate(0);
        forward.lazy.scratch[0] = 1;
        forward.lazy.scratch_len = 1;
        let mut forward_meter = WorkMeter::new(u64::MAX, 0);
        assert!(matches!(
            super::retain_context_lazy_scratch(
                &plan,
                false,
                &mut forward,
                &mut forward_meter,
                0,
                0,
            ),
            Err(SearchError::InternalInvariant {
                detail: "exact small contextual lazy DFA exhausted its proven capacity",
            })
        ));
        assert!(!forward.lazy.saturated);

        let mut reverse =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        reverse.reverse.offsets.truncate(0);
        reverse.reverse.scratch[0] = 0;
        reverse.reverse.scratch_len = 1;
        let mut reverse_meter = WorkMeter::new(u64::MAX, 0);
        assert!(matches!(
            super::retain_context_reverse_scratch(&plan, &mut reverse, &mut reverse_meter, 0, 0,),
            Err(SearchError::InternalInvariant {
                detail: "exact small contextual reverse DFA exhausted its proven capacity",
            })
        ));
        assert!(!reverse.reverse.saturated);
    }

    #[test]
    fn span_is_a_typed_pike_fallback_and_contextual_graphs_get_bounded_storage() {
        let eligible = a_plus(true);
        let ordinary = eligible.workspace_layout().unwrap();
        let accelerated = eligible.accelerated_workspace_layout().unwrap();
        assert!(accelerated.logical_bytes() > ordinary.logical_bytes());
        assert!(accelerated.construction_work() > ordinary.construction_work());

        let mut workspace =
            K0Workspace::new_accelerated(&eligible, WorkspaceLimits::unlimited()).unwrap();
        let span = eligible
            .prepare::<Span>()
            .search_with_workspace(b"baaa", &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .into_output();
        assert_eq!(span, Some(MatchSpan::new(1, 4)));
        assert!(!workspace.lazy.initialized);
        assert!(!workspace.lazy.declined);

        let selected = eligible
            .prepare::<SelectedEnd>()
            .search_with_workspace(b"baaa", &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .into_output();
        assert_eq!(selected, Some(4));
        assert!(workspace.lazy.initialized);

        let asserted = assertion_or_colon(EdgeKind::AssertLineStartLf);
        assert!(
            asserted
                .accelerated_workspace_layout()
                .unwrap()
                .logical_bytes()
                > asserted.workspace_layout().unwrap().logical_bytes()
        );
        let ordinary_asserted = K0Workspace::new(&asserted, WorkspaceLimits::unlimited()).unwrap();
        let mut accelerated_asserted =
            K0Workspace::new_accelerated(&asserted, WorkspaceLimits::unlimited()).unwrap();
        assert!(accelerated_asserted.retained_bytes() > ordinary_asserted.retained_bytes());
        assert!(accelerated_asserted.lazy.context.is_allocated());
        assert!(asserted
            .prepare::<SelectedEnd>()
            .search_with_workspace(b":a", &mut accelerated_asserted, SearchLimits::unlimited(),)
            .unwrap()
            .into_output()
            .is_some());
        assert!(accelerated_asserted.lazy.initialized);

        let nullable = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Accept],
                edge_offsets: vec![0, 0],
                edge_targets: vec![],
                edge_kinds: vec![],
                byte_starts: vec![],
                byte_ends: vec![],
            },
            CompileLimits::default(),
        )
        .unwrap();
        let mut nullable_workspace =
            K0Workspace::new_accelerated(&nullable, WorkspaceLimits::unlimited()).unwrap();
        assert_eq!(
            nullable
                .prepare::<SelectedEnd>()
                .search_with_workspace(b"abc", &mut nullable_workspace, SearchLimits::unlimited(),)
                .unwrap()
                .into_output(),
            Some(0)
        );
        assert!(!nullable_workspace.lazy.declined);
        assert!(nullable_workspace.lazy.initialized);
        assert!(super::lazy_initial_is_terminal(&nullable_workspace).unwrap());

        let mut nullable_span =
            K0Workspace::new_bidirectional(&nullable, WorkspaceLimits::unlimited()).unwrap();
        assert!(!nullable_span.reverse.is_allocated());
        let report = nullable
            .prepare::<Span>()
            .search_with_workspace(b"abc", &mut nullable_span, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(report.output(), &Some(MatchSpan::new(0, 0)));
        assert_eq!(report.accounting().boundaries(), 1);
        assert!(nullable_span.lazy.initialized);
        assert!(!nullable_span.reverse.initialized);
    }

    #[test]
    fn cached_lazy_initial_kind_matches_immutable_state_metadata() {
        let terminal = Automaton::from_raw(
            RawPlan {
                start: 0,
                roles: vec![StateRole::Accept],
                edge_offsets: vec![0, 0],
                edge_targets: vec![],
                edge_kinds: vec![],
                byte_starts: vec![],
                byte_ends: vec![],
            },
            CompileLimits::default(),
        )
        .unwrap();

        for (plan, haystack, expected_pending, expected_terminal) in [
            (a_plus(true), b"a".as_slice(), false, false),
            (greedy_a_star_b(), b"aaab".as_slice(), false, false),
            (a_star(true), b"a".as_slice(), true, false),
            (terminal, b"".as_slice(), true, true),
        ] {
            let mut workspace =
                K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
            let _ = plan
                .prepare::<SelectedEnd>()
                .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
                .unwrap();
            let initial = workspace.lazy.initial;
            let (_, length, pending) = workspace.lazy.state_bounds(initial).unwrap();
            assert_eq!(
                matches!(
                    workspace.lazy.initial_kind,
                    super::LazyInitialKind::NullablePrefix
                        | super::LazyInitialKind::NullableTerminal
                ),
                pending
            );
            assert_eq!(
                workspace.lazy.initial_kind == super::LazyInitialKind::NullableTerminal,
                pending && length == 0
            );
            assert_eq!(pending, expected_pending);
            assert_eq!(
                workspace.lazy.initial_kind == super::LazyInitialKind::NullableTerminal,
                expected_terminal
            );

            let cached = workspace.lazy.initial_kind;
            let _ = plan
                .prepare::<SelectedEnd>()
                .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(workspace.lazy.initial_kind, cached);
        }
    }

    #[test]
    fn endpoint_capabilities_skip_reverse_probe() {
        let plan = a_plus(true);
        let workspace =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let endpoint = super::lazy_capabilities(&plan, &workspace, true, false);
        let span = super::lazy_capabilities(&plan, &workspace, true, true);
        assert!(endpoint.lazy);
        assert!(!endpoint.reverse);
        assert!(span.lazy);
        assert!(span.reverse);
        assert_eq!(endpoint.contextual, span.contextual);
    }

    #[test]
    fn bidirectional_span_layout_and_warm_limits_are_exact() {
        let plan = a_plus(true);
        let endpoint = plan.accelerated_workspace_layout().unwrap();
        let full = plan.bidirectional_workspace_layout().unwrap();
        assert!(full.logical_bytes() > endpoint.logical_bytes());
        assert!(full.construction_work() > endpoint.construction_work());

        assert!(matches!(
            K0Workspace::new_bidirectional(
                &plan,
                WorkspaceLimits {
                    max_setup_work: full.construction_work() - 1,
                    max_scratch_bytes: usize::MAX,
                },
            ),
            Err(SearchError::WorkspaceSetupWorkLimitExceeded { limit, needed })
                if limit == full.construction_work() - 1
                    && needed == full.construction_work()
        ));
        assert!(matches!(
            K0Workspace::new_bidirectional(
                &plan,
                WorkspaceLimits {
                    max_setup_work: u64::MAX,
                    max_scratch_bytes: full.logical_bytes() - 1,
                },
            ),
            Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed,
                limit,
            }) if needed == full.logical_bytes() && limit == full.logical_bytes() - 1
        ));

        let haystack = b"baaaaa";
        let mut workspace = K0Workspace::new_bidirectional(
            &plan,
            WorkspaceLimits {
                max_setup_work: full.construction_work(),
                max_scratch_bytes: full.logical_bytes(),
            },
        )
        .unwrap();
        assert!(
            workspace.construction_accounting().initialized_bytes() > full.logical_bytes(),
            "CSR construction rewrites must be included in initialization accounting"
        );
        assert_eq!(
            plan.prepare::<Span>()
                .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(MatchSpan::new(1, haystack.len()))
        );
        let measured = plan
            .prepare::<Span>()
            .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        let retained = workspace.retained_bytes();
        assert_eq!(
            plan.prepare::<Span>()
                .search_with_workspace(
                    haystack,
                    &mut workspace,
                    SearchLimits {
                        max_work: measured,
                        max_scratch_bytes: retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(MatchSpan::new(1, haystack.len()))
        );
        assert!(matches!(
            plan.prepare::<Span>().search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: measured - 1,
                    max_scratch_bytes: retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == measured - 1
        ));
        assert!(matches!(
            plan.prepare::<Span>().search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: u64::MAX,
                    max_scratch_bytes: retained - 1,
                },
            ),
            Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed,
                limit,
            }) if needed == retained && limit == retained - 1
        ));
    }

    #[test]
    fn reverse_budget_and_capacity_handoffs_preserve_retry_and_correctness() {
        let plan = a_plus(true);
        let mut workspace =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut initialization = WorkMeter::new(u64::MAX, 0);
        assert!(
            super::prepare_reverse_lazy(&plan, &mut workspace, &mut initialization, 0, 0,).unwrap()
        );
        let state = workspace.reverse.initial;
        assert_eq!(
            workspace.reverse.cell(state, b'a').unwrap(),
            super::LAZY_CELL_UNFILLED
        );

        let mut declined = WorkMeter::new(u64::MAX, 0);
        assert!(matches!(
            super::build_reverse_cached_transition(
                &plan,
                state,
                b'a',
                &mut workspace,
                &mut declined,
                u64::MAX,
                0,
            )
            .unwrap(),
            super::ReverseTransition::Inline { .. }
        ));
        assert!(!workspace.reverse.saturated);
        assert_eq!(
            workspace.reverse.cell(state, b'a').unwrap(),
            super::LAZY_CELL_UNFILLED
        );
        let mut retry = WorkMeter::new(u64::MAX, 0);
        assert!(matches!(
            super::build_reverse_cached_transition(
                &plan,
                state,
                b'a',
                &mut workspace,
                &mut retry,
                0,
                0,
            )
            .unwrap(),
            super::ReverseTransition::Ready(_)
        ));
        assert_ne!(
            workspace.reverse.cell(state, b'a').unwrap(),
            super::LAZY_CELL_UNFILLED
        );

        let capacity_plan = byte_chain(&[(b'a', b'a'), (b'b', b'b')]);
        let mut saturated =
            K0Workspace::new_bidirectional(&capacity_plan, WorkspaceLimits::unlimited()).unwrap();
        saturated.reverse.offsets.truncate(1);
        saturated.reverse.lengths.truncate(1);
        saturated.reverse.hashes.truncate(1);
        assert!(matches!(
            capacity_plan.prepare::<Span>().search_with_workspace(
                b"zabx",
                &mut saturated,
                SearchLimits::unlimited(),
            ),
            Err(SearchError::InternalInvariant {
                detail: "exact small reverse DFA exhausted its proven capacity",
            })
        ));
        assert!(!saturated.reverse.saturated);

        let large_plan = byte_chain(&[(b'a', b'a'), (b'b', b'b'), (b'c', b'c'), (b'd', b'd')]);
        let mut pike = K0Workspace::new(&large_plan, WorkspaceLimits::unlimited()).unwrap();
        let mut large_saturated =
            K0Workspace::new_bidirectional(&large_plan, WorkspaceLimits::unlimited()).unwrap();
        large_saturated.reverse.offsets.truncate(1);
        large_saturated.reverse.lengths.truncate(1);
        large_saturated.reverse.hashes.truncate(1);
        for haystack in [b"zabcdx".as_slice(), b"abcdabcd", b"xxabcd"] {
            let want = large_plan
                .prepare::<Span>()
                .search_with_workspace(haystack, &mut pike, SearchLimits::unlimited())
                .unwrap()
                .into_output();
            let got = large_plan
                .prepare::<Span>()
                .search_with_workspace(haystack, &mut large_saturated, SearchLimits::unlimited())
                .unwrap()
                .into_output();
            assert_eq!(got, want, "large saturated reverse source={haystack:?}");
        }
        assert!(large_saturated.reverse.saturated);
    }

    #[test]
    fn reverse_cache_is_bound_to_the_exact_immutable_automaton() {
        let first = byte_chain(&[(b'a', b'a'), (b'b', b'b')]);
        let second = byte_chain(&[(b'a', b'a'), (b'c', b'c')]);
        assert_eq!(
            first.bidirectional_workspace_layout().unwrap(),
            second.bidirectional_workspace_layout().unwrap()
        );
        let mut workspace =
            K0Workspace::new_bidirectional(&first, WorkspaceLimits::unlimited()).unwrap();
        assert_eq!(
            second
                .prepare::<Span>()
                .search_with_workspace(b"zac", &mut workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(MatchSpan::new(1, 3))
        );
        assert!(!workspace.reverse.initialized);
        assert_eq!(
            first
                .prepare::<Span>()
                .search_with_workspace(b"zab", &mut workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(MatchSpan::new(1, 3))
        );
        assert!(workspace.reverse.initialized);
    }

    #[test]
    fn saturated_lazy_cache_continues_inline_without_replaying_and_stays_correct() {
        let plan = byte_chain(&[(b'a', b'a'), (b'b', b'b'), (b'c', b'c'), (b'd', b'd')]);
        let mut pike = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut accelerated =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();

        // Retain only the mandatory initial state. The first transition that
        // has a live successor must hand its just-computed frontier to inline
        // execution.
        accelerated.lazy.offsets.truncate(1);
        accelerated.lazy.lengths.truncate(1);
        accelerated.lazy.modes.truncate(1);
        accelerated.lazy.hashes.truncate(1);

        for haystack in [b"zabcdx".as_slice(), b"abcdabcd", b"xabcdx", b"\xffabcdx"] {
            let want = plan
                .prepare::<SelectedEnd>()
                .search_with_workspace(haystack, &mut pike, SearchLimits::unlimited())
                .unwrap()
                .into_output();
            let got = plan
                .prepare::<SelectedEnd>()
                .search_with_workspace(haystack, &mut accelerated, SearchLimits::unlimited())
                .unwrap()
                .into_output();
            assert_eq!(got, want, "saturated source={haystack:?}");
        }
        assert!(accelerated.lazy.saturated);
        assert!(accelerated.lazy.initialized);
    }

    #[test]
    fn nullable_lazy_cache_budget_and_capacity_handoffs_preserve_priority() {
        let plan = empty_or_ab(false);
        pin_without_start_filter(&plan);
        let mut saturated =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        saturated.lazy.offsets.truncate(1);
        saturated.lazy.lengths.truncate(1);
        saturated.lazy.modes.truncate(1);
        saturated.lazy.hashes.truncate(1);

        assert!(matches!(
            plan.prepare::<SelectedEnd>().search_with_workspace(
                b"ab",
                &mut saturated,
                SearchLimits::unlimited(),
            ),
            Err(SearchError::InternalInvariant {
                detail: "exact small lazy DFA exhausted its proven capacity",
            })
        ));
        assert!(!saturated.lazy.saturated);
        assert!(saturated.lazy.initialized);

        let mut retryable =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let _ = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(b"", &mut retryable, SearchLimits::unlimited())
            .unwrap();
        let initial = retryable.lazy.initial;
        assert_eq!(
            retryable.lazy.cell(initial, b'a').unwrap(),
            super::LAZY_CELL_UNFILLED
        );
        let mut refused = WorkMeter::new(u64::MAX, 0);
        assert!(matches!(
            super::build_lazy_cached_transition(
                &plan,
                initial,
                b'a',
                &mut retryable,
                &mut refused,
                u64::MAX,
                0,
            )
            .unwrap(),
            super::LazyTransition::Inline {
                accepted: false,
                pending: true,
                ..
            }
        ));
        assert!(!retryable.lazy.saturated);
        assert_eq!(
            retryable.lazy.cell(initial, b'a').unwrap(),
            super::LAZY_CELL_UNFILLED
        );
        let mut retry = WorkMeter::new(u64::MAX, 0);
        assert!(matches!(
            super::build_lazy_cached_transition(
                &plan,
                initial,
                b'a',
                &mut retryable,
                &mut retry,
                0,
                0,
            )
            .unwrap(),
            super::LazyTransition::Ready(_)
        ));
        assert_ne!(
            retryable.lazy.cell(initial, b'a').unwrap(),
            super::LAZY_CELL_UNFILLED
        );
    }

    #[test]
    fn nullable_positive_spans_do_not_touch_reverse_capacity() {
        let plan = empty_or_ab(false);
        pin_without_start_filter(&plan);
        let mut pike = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut saturated =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        saturated.reverse.offsets.truncate(1);
        saturated.reverse.lengths.truncate(1);
        saturated.reverse.hashes.truncate(1);

        for haystack in [b"ab".as_slice(), b"\xffab", b"aba", b"a\xffb", b""] {
            for start in 0..=haystack.len() {
                let window = SearchWindow::new(start, haystack.len());
                let want = plan
                    .prepare::<Span>()
                    .search_window_with_workspace(
                        haystack,
                        window,
                        &mut pike,
                        SearchLimits::unlimited(),
                    )
                    .unwrap()
                    .into_output();
                let got = plan
                    .prepare::<Span>()
                    .search_window_with_workspace(
                        haystack,
                        window,
                        &mut saturated,
                        SearchLimits::unlimited(),
                    )
                    .unwrap()
                    .into_output();
                assert_eq!(got, want, "nullable reverse source={haystack:?}/{window:?}");
            }
        }
        assert!(saturated.lazy.initialized);
        assert!(!saturated.reverse.initialized);
        assert!(!saturated.reverse.saturated);
    }

    #[test]
    fn span_cursor_recomputes_nullable_start_known_mode_after_initialization() {
        let plan = empty_or_ab(false);
        plan.start_filter_proof
            .set(&StartFilterProof {
                scanner: None,
                filter: None,
                force_haystack_start: false,
                relaxed_nullable: true,
            })
            .expect("fresh nullable automaton");
        let limits = SearchLimits::unlimited();

        let mut endpoint =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let endpoint_cursor = super::prepare_span_cursor(&plan, &mut endpoint, limits).unwrap();
        assert!(endpoint_cursor.capabilities.lazy);
        assert!(!endpoint_cursor.capabilities.reverse);
        assert_eq!(
            super::effective_lazy_mode(&plan, &endpoint, true, endpoint_cursor.capabilities,)
                .unwrap(),
            super::EffectiveLazyMode {
                lazy: true,
                reverse: false,
            }
        );
        let endpoint_report =
            super::search_span_with_workspace_cursor(&plan, b"abxx", 0, &mut endpoint, limits)
                .unwrap();
        assert_eq!(endpoint_report.found, Some(MatchSpan::new(0, 2)));
        assert!(endpoint.lazy.initialized);
        assert!(super::lazy_initial_has_pending(&endpoint).unwrap());

        let mut full = K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let cold_cursor = super::prepare_span_cursor(&plan, &mut full, limits).unwrap();
        assert!(cold_cursor.capabilities.lazy);
        assert!(cold_cursor.capabilities.reverse);
        assert_eq!(
            super::effective_lazy_mode(&plan, &full, true, cold_cursor.capabilities).unwrap(),
            super::EffectiveLazyMode {
                lazy: true,
                reverse: true,
            }
        );
        let full_report =
            super::search_span_with_workspace_cursor(&plan, b"abxx", 0, &mut full, limits).unwrap();
        assert_eq!(full_report.found, Some(MatchSpan::new(0, 2)));
        assert!(full.lazy.initialized);
        assert!(!full.reverse.initialized);

        let warm_cursor = super::prepare_span_cursor(&plan, &mut full, limits).unwrap();
        assert_eq!(warm_cursor.capabilities, cold_cursor.capabilities);
        assert_eq!(
            super::effective_lazy_mode(&plan, &full, true, warm_cursor.capabilities).unwrap(),
            super::EffectiveLazyMode {
                lazy: true,
                reverse: false,
            }
        );
        let warm_report =
            super::search_span_with_workspace_cursor(&plan, b"xxab", 2, &mut full, limits).unwrap();
        assert_eq!(warm_report.found, Some(MatchSpan::new(2, 4)));
        assert!(!full.reverse.initialized);
    }

    #[test]
    fn transient_learning_budget_refusal_preserves_cached_rows_and_can_retry() {
        let plan = a_plus(true);
        let certified = plan.conservative_reused_work_bound(2).unwrap();
        let mut fresh = K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let fresh_retained = fresh.retained_bytes();
        let certified_report = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(
                b"aa",
                &mut fresh,
                SearchLimits {
                    max_work: certified,
                    max_scratch_bytes: fresh_retained,
                },
            )
            .unwrap();
        assert_eq!(certified_report.output(), &Some(2));
        assert!(certified_report.accounting().work() <= certified);
        assert!(
            !fresh.lazy.initialized,
            "a fresh cache must leave the ordinary certificate reserved"
        );

        let mut workspace =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();

        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(b"a", &mut workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(1)
        );
        let initial = workspace.lazy.initial;
        let pending = workspace.lazy.cell(initial, b'a').unwrap() & super::LAZY_CELL_STATE_MASK;
        let pending = super::direct_row_state(pending.checked_sub(1).unwrap());
        assert_eq!(
            workspace.lazy.cell(pending, b'a').unwrap(),
            super::LAZY_CELL_UNFILLED
        );

        let retained = workspace.retained_bytes();
        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(
                    b"aa",
                    &mut workspace,
                    SearchLimits {
                        max_work: certified,
                        max_scratch_bytes: retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(2)
        );
        assert!(!workspace.lazy.saturated);
        assert_eq!(
            workspace.lazy.cell(pending, b'a').unwrap(),
            super::LAZY_CELL_UNFILLED,
            "a bound-certified call must decline optional learning"
        );

        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(b"aa", &mut workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(2)
        );
        assert_ne!(
            workspace.lazy.cell(pending, b'a').unwrap(),
            super::LAZY_CELL_UNFILLED,
            "a later call with surplus work must retry and publish the row"
        );
    }

    #[test]
    fn warmed_lazy_rows_remove_repeated_dense_pike_closure_work() {
        let plan = a_plus(true);
        let haystack = vec![b'a'; 4_096];
        let mut pike = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut accelerated =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();

        let _ = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(&haystack, &mut accelerated, SearchLimits::unlimited())
            .unwrap();
        let pike = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(&haystack, &mut pike, SearchLimits::unlimited())
            .unwrap();
        let accelerated = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(&haystack, &mut accelerated, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(accelerated.output(), pike.output());
        assert!(
            accelerated.accounting().transition_work() * 2 < pike.accounting().transition_work(),
            "warmed rows should replace repeated ordered closure"
        );
    }

    #[test]
    fn authenticated_direct_row_offsets_keep_physical_bounds_checked() {
        let plan = a_plus(true);
        let mut forward =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        plan.prepare::<SelectedEnd>()
            .search_with_workspace(b"aa", &mut forward, SearchLimits::unlimited())
            .unwrap();
        let forward_initial = forward.lazy.initial;
        assert!(forward.lazy.state_len > 0);
        let forward_outside = u32::try_from(forward.lazy.state_len).unwrap();
        assert_eq!(
            forward.lazy.cell(forward_outside, b'a').unwrap_err(),
            SearchError::InternalInvariant {
                detail: "lazy DFA transition state is outside the cache",
            }
        );
        let forward_row = super::direct_row_offset(forward_initial).unwrap();
        forward.lazy.rows.clear();
        assert_eq!(
            forward.lazy.direct_cell(forward_row, b'a').unwrap_err(),
            SearchError::InternalInvariant {
                detail: "lazy DFA transition cell is outside the direct table",
            }
        );

        let mut reverse =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        plan.prepare::<Span>()
            .search_with_workspace(b"aa", &mut reverse, SearchLimits::unlimited())
            .unwrap();
        let reverse_initial = reverse.reverse.initial;
        assert!(reverse.reverse.state_len > 0);
        let reverse_outside = u32::try_from(reverse.reverse.state_len).unwrap();
        assert_eq!(
            reverse.reverse.cell(reverse_outside, b'a').unwrap_err(),
            SearchError::InternalInvariant {
                detail: "reverse DFA transition state is outside the cache",
            }
        );
        let reverse_row = super::direct_row_offset(reverse_initial).unwrap();
        reverse.reverse.rows.clear();
        assert_eq!(
            reverse.reverse.direct_cell(reverse_row, b'a').unwrap_err(),
            SearchError::InternalInvariant {
                detail: "reverse DFA transition cell is outside the direct table",
            }
        );
    }

    #[test]
    fn accelerated_workspace_limits_and_optional_preparation_are_pre_source_exact() {
        let plan = a_plus(true);
        let layout = plan.accelerated_workspace_layout().unwrap();
        let setup_error = K0Workspace::new_accelerated(
            &plan,
            WorkspaceLimits {
                max_setup_work: layout.construction_work() - 1,
                max_scratch_bytes: usize::MAX,
            },
        )
        .unwrap_err();
        assert_eq!(
            setup_error,
            SearchError::WorkspaceSetupWorkLimitExceeded {
                limit: layout.construction_work() - 1,
                needed: layout.construction_work(),
            }
        );
        let scratch_error = K0Workspace::new_accelerated(
            &plan,
            WorkspaceLimits {
                max_setup_work: u64::MAX,
                max_scratch_bytes: layout.logical_bytes() - 1,
            },
        )
        .unwrap_err();
        assert!(matches!(
            scratch_error,
            SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed,
                limit,
            } if needed == layout.logical_bytes() && limit == layout.logical_bytes() - 1
        ));

        let mut workspace =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        pin_without_start_filter(&plan);
        let states = u64::try_from(plan.stats().states()).unwrap();
        let epsilon = u64::try_from(plan.stats().zero_width_edges()).unwrap();
        let initial_upper = states * 2 + epsilon * 2 + 2;
        let limits = SearchLimits {
            max_work: INVOCATION_RESET_WORK + initial_upper - 1,
            max_scratch_bytes: workspace.retained_bytes(),
        };
        let mut setup = crate::SetupAccounting::empty(workspace.retained_bytes(), true);
        let (mut meter, _) = super::prepare_invocation(
            &plan,
            &mut workspace,
            SearchWindow::new(0, 4),
            limits,
            &mut setup,
            true,
            false,
        )
        .unwrap();
        assert!(!super::prepare_lazy(&plan, &mut workspace, &mut meter, 0, 0).unwrap());
        assert_eq!(meter.consumed, INVOCATION_RESET_WORK);
        assert!(!workspace.lazy.initialized);
        assert!(!workspace.lazy.declined);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "all accelerated endpoint contracts share the same exact-limit matrix"
    )]
    fn warmed_lazy_contracts_enforce_exact_and_one_below_work_limits() {
        let plan = a_plus(true);
        let haystack = b"baaaaa";
        let mut workspace =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let retained = workspace.retained_bytes();

        let _ = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap();

        let exists_work = plan
            .prepare::<Exists>()
            .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        assert!(plan
            .prepare::<Exists>()
            .search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: exists_work,
                    max_scratch_bytes: retained,
                },
            )
            .unwrap()
            .into_output());
        assert!(matches!(
            plan.prepare::<Exists>().search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: exists_work - 1,
                    max_scratch_bytes: retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == exists_work - 1
        ));

        let earliest_work = plan
            .prepare::<EarliestEnd>()
            .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        assert_eq!(
            plan.prepare::<EarliestEnd>()
                .search_with_workspace(
                    haystack,
                    &mut workspace,
                    SearchLimits {
                        max_work: earliest_work,
                        max_scratch_bytes: retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(2)
        );
        assert!(matches!(
            plan.prepare::<EarliestEnd>().search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: earliest_work - 1,
                    max_scratch_bytes: retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == earliest_work - 1
        ));

        let selected_work = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(haystack, &mut workspace, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(
                    haystack,
                    &mut workspace,
                    SearchLimits {
                        max_work: selected_work,
                        max_scratch_bytes: retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(haystack.len())
        );
        assert!(matches!(
            plan.prepare::<SelectedEnd>().search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: selected_work - 1,
                    max_scratch_bytes: retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == selected_work - 1
        ));

        assert!(matches!(
            plan.prepare::<SelectedEnd>().search_with_workspace(
                haystack,
                &mut workspace,
                SearchLimits {
                    max_work: u64::MAX,
                    max_scratch_bytes: retained - 1,
                },
            ),
            Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed,
                limit,
            }) if needed == retained && limit == retained - 1
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "all four nullable contracts need independent exact and one-below ledgers"
    )]
    fn warmed_nullable_lazy_contracts_enforce_exact_limits_and_pike_fallback_accounting() {
        let plan = a_star(true);
        pin_without_start_filter(&plan);
        let haystack = b"aaaa";
        let mut endpoint =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let mut span = K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let endpoint_retained = endpoint.retained_bytes();
        let span_retained = span.retained_bytes();

        let _ = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(haystack, &mut endpoint, SearchLimits::unlimited())
            .unwrap();
        let _ = plan
            .prepare::<Span>()
            .search_with_workspace(haystack, &mut span, SearchLimits::unlimited())
            .unwrap();

        let exists_work = plan
            .prepare::<Exists>()
            .search_with_workspace(haystack, &mut endpoint, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        assert!(plan
            .prepare::<Exists>()
            .search_with_workspace(
                haystack,
                &mut endpoint,
                SearchLimits {
                    max_work: exists_work,
                    max_scratch_bytes: endpoint_retained,
                },
            )
            .unwrap()
            .into_output());
        assert!(matches!(
            plan.prepare::<Exists>().search_with_workspace(
                haystack,
                &mut endpoint,
                SearchLimits {
                    max_work: exists_work - 1,
                    max_scratch_bytes: endpoint_retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == exists_work - 1
        ));

        let earliest_work = plan
            .prepare::<EarliestEnd>()
            .search_with_workspace(haystack, &mut endpoint, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        assert_eq!(
            plan.prepare::<EarliestEnd>()
                .search_with_workspace(
                    haystack,
                    &mut endpoint,
                    SearchLimits {
                        max_work: earliest_work,
                        max_scratch_bytes: endpoint_retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(0)
        );
        assert!(matches!(
            plan.prepare::<EarliestEnd>().search_with_workspace(
                haystack,
                &mut endpoint,
                SearchLimits {
                    max_work: earliest_work - 1,
                    max_scratch_bytes: endpoint_retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == earliest_work - 1
        ));

        let selected_work = plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(haystack, &mut endpoint, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_with_workspace(
                    haystack,
                    &mut endpoint,
                    SearchLimits {
                        max_work: selected_work,
                        max_scratch_bytes: endpoint_retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(haystack.len())
        );
        assert!(matches!(
            plan.prepare::<SelectedEnd>().search_with_workspace(
                haystack,
                &mut endpoint,
                SearchLimits {
                    max_work: selected_work - 1,
                    max_scratch_bytes: endpoint_retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == selected_work - 1
        ));

        let span_work = plan
            .prepare::<Span>()
            .search_with_workspace(haystack, &mut span, SearchLimits::unlimited())
            .unwrap()
            .accounting()
            .work();
        assert_eq!(
            plan.prepare::<Span>()
                .search_with_workspace(
                    haystack,
                    &mut span,
                    SearchLimits {
                        max_work: span_work,
                        max_scratch_bytes: span_retained,
                    },
                )
                .unwrap()
                .into_output(),
            Some(MatchSpan::new(0, haystack.len()))
        );
        assert!(matches!(
            plan.prepare::<Span>().search_with_workspace(
                haystack,
                &mut span,
                SearchLimits {
                    max_work: span_work - 1,
                    max_scratch_bytes: span_retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == span_work - 1
        ));
        assert!(matches!(
            plan.prepare::<Span>().search_with_workspace(
                haystack,
                &mut span,
                SearchLimits {
                    max_work: u64::MAX,
                    max_scratch_bytes: span_retained - 1,
                },
            ),
            Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed,
                limit,
            }) if needed == span_retained && limit == span_retained - 1
        ));

        let fallback_plan = empty_or_ab(false);
        pin_without_start_filter(&fallback_plan);
        let fallback_haystack = b"ab";
        let mut pike = K0Workspace::new(&fallback_plan, WorkspaceLimits::unlimited()).unwrap();
        let pike_report = fallback_plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(fallback_haystack, &mut pike, SearchLimits::unlimited())
            .unwrap();
        let certificate = fallback_plan
            .conservative_reused_work_bound(fallback_haystack.len())
            .unwrap();
        let mut fresh =
            K0Workspace::new_accelerated(&fallback_plan, WorkspaceLimits::unlimited()).unwrap();
        let fresh_retained = fresh.retained_bytes();
        let fallback = fallback_plan
            .prepare::<SelectedEnd>()
            .search_with_workspace(
                fallback_haystack,
                &mut fresh,
                SearchLimits {
                    max_work: certificate,
                    max_scratch_bytes: fresh_retained,
                },
            )
            .unwrap();
        assert_eq!(fallback.output(), pike_report.output());
        assert_eq!(
            fallback.accounting().transition_work(),
            pike_report.accounting().transition_work()
        );
        assert_eq!(
            fallback.accounting().boundaries(),
            pike_report.accounting().boundaries()
        );
        assert!(!fresh.lazy.initialized);
        assert!(!fresh.lazy.declined);

        let terminal = a_star(false);
        pin_without_start_filter(&terminal);
        let mut terminal_span =
            K0Workspace::new_bidirectional(&terminal, WorkspaceLimits::unlimited()).unwrap();
        let _ = terminal
            .prepare::<Span>()
            .search_with_workspace(haystack, &mut terminal_span, SearchLimits::unlimited())
            .unwrap();
        let warm = terminal
            .prepare::<Span>()
            .search_with_workspace(haystack, &mut terminal_span, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(warm.output(), &Some(MatchSpan::new(0, 0)));
        assert_eq!(warm.accounting().boundaries(), 1);
        assert!(!terminal_span.reverse.initialized);
        let terminal_retained = terminal_span.retained_bytes();
        let exact = terminal
            .prepare::<Span>()
            .search_with_workspace(
                haystack,
                &mut terminal_span,
                SearchLimits {
                    max_work: warm.accounting().work(),
                    max_scratch_bytes: terminal_retained,
                },
            )
            .unwrap();
        assert_eq!(exact.output(), warm.output());
        assert!(matches!(
            terminal.prepare::<Span>().search_with_workspace(
                haystack,
                &mut terminal_span,
                SearchLimits {
                    max_work: warm.accounting().work() - 1,
                    max_scratch_bytes: terminal_retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { .. })
        ));
    }

    #[test]
    fn lazy_cache_is_bound_to_the_exact_immutable_automaton() {
        let first = byte_chain(&[(b'a', b'a'), (b'b', b'b')]);
        let second = byte_chain(&[(b'a', b'a'), (b'c', b'c')]);
        assert_eq!(first.workspace_layout(), second.workspace_layout());
        let mut workspace =
            K0Workspace::new_accelerated(&first, WorkspaceLimits::unlimited()).unwrap();

        assert_eq!(
            second
                .prepare::<SelectedEnd>()
                .search_with_workspace(b"zac", &mut workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(3)
        );
        assert!(!workspace.lazy.initialized);
        assert!(workspace.lazy.is_bound_to(&first));

        assert_eq!(
            first
                .prepare::<SelectedEnd>()
                .search_with_workspace(b"zab", &mut workspace, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(3)
        );
        assert!(workspace.lazy.initialized);
    }

    #[test]
    fn root_run_session_retains_only_ascii_set_scanner_shapes() {
        let assert_selection = |bytes: &[u8], expected_retained: bool| {
            let plan = ascii_root_bytes(bytes);
            let session =
                K0SearchSession::new_selected(&plan, WorkspaceLimits::unlimited(), true, true)
                    .unwrap();
            assert_eq!(
                session.root_run.is_some(),
                expected_retained,
                "unexpected scanner shape for {bytes:?}"
            );

            let base = K0Workspace::new_with_layout(
                &plan,
                WorkspaceLimits::unlimited(),
                session.workspace.layout,
            )
            .unwrap();
            let inspection = super::inspect_root_run_accounted(&plan);
            let scanner_work = if bytes.len() <= BYTE_START_SMALL_MAX_MEMBERS {
                BYTE_START_BITMAP_POPULATION_WORK
            } else {
                ROOT_RUN_SCANNER_SHAPE_MAX_WORK
            };
            let expected_work = base
                .construction_accounting()
                .work()
                .checked_add(inspection.work())
                .and_then(|work| {
                    work.checked_add(u64::try_from(scanner_work).expect("test work fits u64"))
                })
                .unwrap();
            assert_eq!(session.construction_accounting().work(), expected_work);
        };

        for bytes in [
            &[b'a'][..],
            &[b'a', b'b'][..],
            &[b'a', b'b', b'c'][..],
            &[b'a', b'b', b'c', b'd'][..],
            &[61, 62, 63, 64][..],
            &[62, 63, 64, 65][..],
            &[124, 125, 126, 127][..],
        ] {
            assert_selection(bytes, false);
        }

        for bytes in [
            &ROOT_RUN_TEST_SET[..],
            &[0, 1, 2, 127][..],
            &[61, 62, 64, 65][..],
        ] {
            assert_selection(bytes, true);
        }
    }

    #[test]
    fn selected_session_admission_separates_root_run_descriptor_and_workspace_tiers() {
        let plan = root_run_exact_two();
        let full =
            K0SearchSession::new_selected(&plan, WorkspaceLimits::unlimited(), true, true).unwrap();
        assert!(full.root_run.is_some());
        assert!(full.capabilities.reverse);
        let full_setup = full.construction_accounting();

        // One unit below the fully observed setup cannot admit the prospective
        // descriptor envelope, but the already selected bidirectional layout
        // remains the best workspace admitted by the caller.
        let layout_only_full = K0SearchSession::new_selected(
            &plan,
            WorkspaceLimits {
                max_setup_work: full_setup.work() - 1,
                max_scratch_bytes: usize::MAX,
            },
            true,
            true,
        )
        .unwrap();
        assert!(layout_only_full.root_run.is_none());
        assert!(layout_only_full.capabilities.reverse);
        assert_eq!(layout_only_full.workspace.layout, full.workspace.layout);
        let layout_only_full_setup = layout_only_full.construction_accounting();
        assert!(layout_only_full_setup.work() < full_setup.work());
        assert_eq!(
            layout_only_full_setup.allocated_bytes(),
            full_setup.allocated_bytes()
        );
        assert_eq!(
            layout_only_full_setup.initialized_bytes(),
            full_setup.initialized_bytes()
        );
        assert_eq!(
            layout_only_full_setup.retained_bytes(),
            full_setup.retained_bytes()
        );

        let endpoint =
            K0SearchSession::new_selected(&plan, WorkspaceLimits::unlimited(), true, false)
                .unwrap();
        assert!(endpoint.root_run.is_none());
        assert!(!endpoint.capabilities.reverse);
        let endpoint_setup = endpoint.construction_accounting();
        assert!(endpoint_setup.work() < layout_only_full_setup.work());
        let exact_endpoint = K0SearchSession::new_selected(
            &plan,
            WorkspaceLimits {
                max_setup_work: endpoint_setup.work(),
                max_scratch_bytes: usize::MAX,
            },
            true,
            true,
        )
        .unwrap();
        assert!(exact_endpoint.root_run.is_none());
        assert!(!exact_endpoint.capabilities.reverse);
        assert_eq!(exact_endpoint.workspace.layout, endpoint.workspace.layout);
        assert_eq!(exact_endpoint.construction_accounting(), endpoint_setup);

        let pike = K0Workspace::new(&plan, WorkspaceLimits::unlimited()).unwrap();
        let pike_setup = pike.construction_accounting();
        assert!(pike_setup.work() < endpoint_setup.work());
        let exact_pike = K0SearchSession::new_selected(
            &plan,
            WorkspaceLimits {
                max_setup_work: pike_setup.work(),
                max_scratch_bytes: usize::MAX,
            },
            true,
            true,
        )
        .unwrap();
        assert!(exact_pike.root_run.is_none());
        assert!(!exact_pike.capabilities.lazy);
        assert!(!exact_pike.capabilities.reverse);
        assert_eq!(exact_pike.workspace.layout, pike.layout);
        assert_eq!(exact_pike.construction_accounting(), pike_setup);
        assert!(matches!(
            K0SearchSession::new_selected(
                &plan,
                WorkspaceLimits {
                    max_setup_work: pike_setup.work() - 1,
                    max_scratch_bytes: usize::MAX,
                },
                true,
                true,
            ),
            Err(SearchError::WorkspaceSetupWorkLimitExceeded { limit, needed })
                if limit == pike_setup.work() - 1 && needed == pike_setup.work()
        ));
    }

    #[test]
    fn root_run_corridor_matches_ordinary_k0_for_exact_finite_and_unbounded_runs() {
        let plans = [
            root_run_exact_two(),
            root_run_exact(31),
            root_run_exact(32),
            root_run_finite_two_four(false),
            root_run_finite_two_four(true),
            root_run_unbounded_two(false),
            root_run_unbounded_two(true),
        ];
        let haystacks: [&[u8]; 6] = [
            b"",
            b"zzzzzzzz",
            b"azazazazazaz",
            b"zzacegzz",
            b"acegacegaceg",
            b"zzaacceeggzzacegacz",
        ];

        for plan in &plans {
            let mut session =
                K0SearchSession::new_selected(plan, WorkspaceLimits::unlimited(), true, true)
                    .unwrap();
            assert!(
                session.root_run.is_some(),
                "strict test graph should own a root-run descriptor"
            );
            for &haystack in &haystacks {
                for start in 0..=haystack.len() {
                    let expected = session
                        .search_window::<Span>(
                            haystack,
                            SearchWindow::new(start, haystack.len()),
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let mut source = K0SpanSourceCursor::new(haystack);
                    let actual = session
                        .search_span_at_source_cursor(&mut source, start, SearchLimits::unlimited())
                        .unwrap()
                        .into_output();
                    assert_eq!(
                        actual, expected,
                        "roles={:?}, haystack={haystack:?}, start={start}",
                        plan.roles
                    );
                }
            }
        }
    }

    #[test]
    fn root_run_corridor_sequential_cursor_matches_ordinary_k0_exhaustively_and_at_block_tails() {
        let plans = [
            root_run_exact_two(),
            root_run_exact(31),
            root_run_exact(32),
            root_run_finite_two_four(false),
            root_run_finite_two_four(true),
            root_run_unbounded_two(false),
            root_run_unbounded_two(true),
        ];

        for plan in &plans {
            let mut session =
                K0SearchSession::new_selected(plan, WorkspaceLimits::unlimited(), true, true)
                    .unwrap();
            assert!(session.root_run.is_some());

            let mut check = |haystack: &[u8]| {
                let mut source = K0SpanSourceCursor::new(haystack);
                let mut start = 0usize;
                loop {
                    let expected = session
                        .search_window::<Span>(
                            haystack,
                            SearchWindow::new(start, haystack.len()),
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let actual = session
                        .search_span_at_source_cursor(&mut source, start, SearchLimits::unlimited())
                        .unwrap()
                        .into_output();
                    assert_eq!(
                        actual, expected,
                        "roles={:?}, haystack={haystack:?}, start={start}",
                        plan.roles
                    );
                    let Some(matched) = actual else {
                        break;
                    };
                    assert!(matched.end() > start);
                    start = matched.end();
                }
            };

            // Every member/nonmember source through eight bytes exercises
            // repeated cursor publication and invalidation without depending
            // on a benchmark-shaped density.
            for length in 0..=8usize {
                for bits in 0..(1usize << length) {
                    let haystack: Vec<u8> = (0..length)
                        .map(|lane| {
                            if bits & (1usize << lane) == 0 {
                                b'z'
                            } else {
                                b'a'
                            }
                        })
                        .collect();
                    check(&haystack);
                }
            }

            // The physical classifier window is 32 bytes. Exercise one byte
            // below, at, and above both the first and refill boundaries.
            for length in [31usize, 32, 33, 63, 64, 65] {
                let dense = vec![b'a'; length];
                check(&dense);

                let alternating: Vec<u8> = (0..length)
                    .map(|lane| if lane % 2 == 0 { b'a' } else { b'z' })
                    .collect();
                check(&alternating);

                let mixed: Vec<u8> = (0..length).map(|lane| b"acegzz"[lane % 6]).collect();
                check(&mixed);
            }
        }
    }

    #[test]
    fn root_run_corridor_clamps_cached_qualification_and_greedy_extension_to_window_end() {
        let plans = [
            root_run_exact_two(),
            root_run_finite_two_four(false),
            root_run_finite_two_four(true),
            root_run_unbounded_two(false),
            root_run_unbounded_two(true),
        ];
        let haystack = b"zzacegacegacegacegacegacegacegacegacegacegacegacegacegacegacegzz";

        for plan in &plans {
            let mut session =
                K0SearchSession::new_selected(plan, WorkspaceLimits::unlimited(), true, true)
                    .unwrap();
            let _ = session
                .search::<Span>(haystack, SearchLimits::unlimited())
                .unwrap();
            let descriptor = session.root_run.expect("strict root-run descriptor");

            for end in 28..=38 {
                for start in 26..=end {
                    let expected = session
                        .search_window::<Span>(
                            haystack,
                            SearchWindow::new(start, end),
                            SearchLimits::unlimited(),
                        )
                        .unwrap()
                        .into_output();
                    let proof = plan
                        .start_filter_proof
                        .get()
                        .expect("warm start-filter proof");
                    let (scanner, classifier) = super::root_run_ascii_scanner(descriptor, proof)
                        .expect("test set owns an ASCII classifier");
                    let mut cursor = super::RootRunBlockCursor::default();
                    let mut meter = WorkMeter::new(u64::MAX, 0);
                    let actual = super::execute_root_run_corridor(
                        plan,
                        descriptor,
                        scanner,
                        classifier,
                        haystack,
                        SearchWindow::new(start, end),
                        &mut cursor,
                        &mut meter,
                    )
                    .unwrap()
                    .0;
                    assert_eq!(
                        actual, expected,
                        "roles={:?}, start={start}, end={end}",
                        plan.roles
                    );
                    assert!(
                        actual.is_none_or(|matched| matched.end() <= end),
                        "corridor crossed the authenticated window end"
                    );
                }
            }
        }

        // A cursor populated under a longer window must still fail closed if
        // an internal caller later presents a shorter one.
        let plan = root_run_exact_two();
        let mut session =
            K0SearchSession::new_selected(&plan, WorkspaceLimits::unlimited(), true, true).unwrap();
        let _ = session
            .search::<Span>(haystack, SearchLimits::unlimited())
            .unwrap();
        let descriptor = session.root_run.unwrap();
        let proof = plan.start_filter_proof.get().unwrap();
        let (scanner, classifier) = super::root_run_ascii_scanner(descriptor, proof).unwrap();
        let mut cursor = super::RootRunBlockCursor::default();
        let mut meter = WorkMeter::new(u64::MAX, 0);
        let _ = super::execute_root_run_corridor(
            &plan,
            descriptor,
            scanner,
            classifier,
            haystack,
            SearchWindow::full(haystack),
            &mut cursor,
            &mut meter,
        )
        .unwrap();
        let mut retry_meter = WorkMeter::new(u64::MAX, 0);
        assert_eq!(
            super::execute_root_run_corridor(
                &plan,
                descriptor,
                scanner,
                classifier,
                haystack,
                SearchWindow::new(30, 31),
                &mut cursor,
                &mut retry_meter,
            )
            .unwrap()
            .0,
            None
        );
    }

    #[test]
    fn root_run_corridor_retains_dense_iterator_masks_transactionally() {
        let plan = root_run_exact_two();
        let mut session =
            K0SearchSession::new_selected(&plan, WorkspaceLimits::unlimited(), true, true).unwrap();
        let haystack = b"acegacegacegacegacegacegacegacegacegacegacegacegacegacegacegaceg";

        // Publish the ordinary start proof before measuring the source-bound
        // iterator cursor itself.
        let _ = session
            .search::<Span>(haystack, SearchLimits::unlimited())
            .unwrap();
        let mut source = K0SpanSourceCursor::new(haystack);
        let first = session
            .search_span_at_source_cursor(&mut source, 0, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(first.output(), &Some(MatchSpan::new(0, 2)));
        assert_ne!(source.root_run.automaton_identity, 0);
        assert_eq!(source.root_run.activation_at, 2);
        assert_eq!(source.root_run.qualified_starts, 0);

        let second = session
            .search_span_at_source_cursor(&mut source, 2, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(second.output(), &Some(MatchSpan::new(2, 4)));
        assert!(source.root_run.qualified_starts != 0);
        let repeated = session
            .search_span_at_source_cursor(&mut source, 2, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(repeated.output(), &Some(MatchSpan::new(2, 4)));
        let third = session
            .search_span_at_source_cursor(&mut source, 4, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(third.output(), &Some(MatchSpan::new(4, 6)));
        assert_eq!(third.accounting().transition_work(), 0);

        let before_refusal = source.root_run;
        let exact = third.accounting().work();
        assert_eq!(exact, INVOCATION_RESET_WORK);
        assert!(matches!(
            session.search_span_at_source_cursor(
                &mut source,
                6,
                SearchLimits {
                    max_work: exact.checked_sub(1).unwrap(),
                    max_scratch_bytes: usize::MAX,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. })
                if limit == exact.checked_sub(1).unwrap()
        ));
        assert_eq!(source.root_run, before_refusal);
        assert_eq!(
            session
                .search_span_at_source_cursor(&mut source, 6, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(MatchSpan::new(6, 8))
        );
    }

    #[test]
    fn root_run_corridor_preserves_absent_scanner_and_batches_alternating_rejection() {
        let plan = root_run_exact_two();
        let mut session =
            K0SearchSession::new_selected(&plan, WorkspaceLimits::unlimited(), true, true).unwrap();
        let _ = session
            .search::<Span>(b"zzzz", SearchLimits::unlimited())
            .unwrap();

        let absent = [b'z'; 256];
        let mut absent_source = K0SpanSourceCursor::new(&absent);
        let absent_report = session
            .search_span_at_source_cursor(&mut absent_source, 0, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(absent_report.output(), &None);
        assert_eq!(absent_report.accounting().boundaries(), 0);
        assert_eq!(absent_source.root_run, super::RootRunBlockCursor::default());

        let alternating = [b'a', b'z'].repeat(128);
        let mut alternating_source = K0SpanSourceCursor::new(&alternating);
        let alternating_report = session
            .search_span_at_source_cursor(&mut alternating_source, 0, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(alternating_report.output(), &None);
        assert!(
            alternating_report.accounting().transition_work()
                <= u64::try_from(alternating.len().checked_mul(2).unwrap()).unwrap(),
            "bit-parallel rejection must not walk every member/nonmember run"
        );
    }

    #[test]
    fn exact_bound_session_matches_validating_workspace_and_cursor() {
        let plan = byte_chain(&[(b'a', b'a'), (b'b', b'b')]);
        let mut session =
            K0SearchSession::new_selected(&plan, WorkspaceLimits::unlimited(), true, true).unwrap();
        assert_eq!(session.automaton.identity(), plan.identity());
        assert!(session.capabilities.lazy);
        assert!(session.capabilities.reverse);
        let retained = session.construction_accounting().retained_bytes();
        let haystack = b"zzabzzab";

        let _ = session
            .search::<Span>(haystack, SearchLimits::unlimited())
            .unwrap();
        let warm = session
            .search::<Span>(haystack, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(warm.into_output(), Some(MatchSpan::new(2, 4)));
        assert!(warm.accounting().setup().reused());
        assert_eq!(warm.accounting().setup().retained_bytes(), retained);
        assert_eq!(warm.accounting().scratch_bytes(), retained);

        let mut validating =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let _ = plan
            .prepare::<Span>()
            .search_with_workspace(haystack, &mut validating, SearchLimits::unlimited())
            .unwrap();
        let validating_warm = plan
            .prepare::<Span>()
            .search_with_workspace(haystack, &mut validating, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(validating_warm.output(), warm.output());
        assert_eq!(
            validating_warm.accounting().transition_work(),
            warm.accounting().transition_work()
        );
        assert_eq!(
            validating_warm.accounting().boundaries(),
            warm.accounting().boundaries()
        );
        assert_eq!(
            session
                .search_span_at_cursor(haystack, 4, SearchLimits::unlimited())
                .unwrap()
                .into_output(),
            Some(MatchSpan::new(6, 8))
        );
    }

    #[test]
    fn exact_bound_session_preserves_per_call_limits_and_recovers() {
        let plan = byte_chain(&[(b'a', b'a'), (b'b', b'b')]);
        let mut session =
            K0SearchSession::new_selected(&plan, WorkspaceLimits::unlimited(), true, true).unwrap();
        let retained = session.construction_accounting().retained_bytes();
        let haystack = b"zzabzzab";
        let _ = session
            .search::<Span>(haystack, SearchLimits::unlimited())
            .unwrap();
        let warm = session
            .search::<Span>(haystack, SearchLimits::unlimited())
            .unwrap();
        let exact = SearchLimits {
            max_work: warm.accounting().work(),
            max_scratch_bytes: retained,
        };
        assert_eq!(
            session.search::<Span>(haystack, exact).unwrap().output(),
            warm.output()
        );
        assert!(matches!(
            session.search::<Span>(
                haystack,
                SearchLimits {
                    max_work: exact.max_work - 1,
                    max_scratch_bytes: retained,
                },
            ),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == exact.max_work - 1
        ));
        assert!(matches!(
            session.search::<Span>(
                haystack,
                SearchLimits {
                    max_work: u64::MAX,
                    max_scratch_bytes: retained - 1,
                },
            ),
            Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed,
                limit,
            }) if needed == retained && limit == retained - 1
        ));
        assert!(matches!(
            session.search_window::<Span>(
                haystack,
                SearchWindow::new(3, haystack.len() + 1),
                SearchLimits::unlimited(),
            ),
            Err(SearchError::InvalidWindow {
                start: 3,
                end,
                haystack_len,
            }) if end == haystack.len() + 1 && haystack_len == haystack.len()
        ));
        assert_eq!(
            session
                .search::<Span>(haystack, SearchLimits::unlimited())
                .unwrap()
                .output(),
            warm.output()
        );
    }

    #[test]
    fn caller_owned_workspace_still_rejects_a_wrong_shape() {
        let plan = byte_chain(&[(b'a', b'a'), (b'b', b'b')]);
        let wrong_plan = ascii_literal(b'a');
        let mut wrong_workspace =
            K0Workspace::new(&wrong_plan, WorkspaceLimits::unlimited()).unwrap();
        assert!(matches!(
            plan.prepare::<Span>().search_with_workspace(
                b"zzabzzab",
                &mut wrong_workspace,
                SearchLimits::unlimited(),
            ),
            Err(SearchError::WorkspaceLayoutMismatch { .. })
        ));
    }

    #[test]
    fn authenticated_workspace_reuses_shape_facts_and_safely_falls_back_for_another_automaton() {
        let plan = ascii_literal(b'a');
        let other = ascii_literal(b'b');
        assert_eq!(
            plan.workspace_layout().unwrap(),
            other.workspace_layout().unwrap()
        );
        let mut workspace =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let report = plan
            .prepare::<SelectedEnd>()
            .search_window_with_authenticated_workspace(
                b"za",
                SearchWindow::new(0, 2),
                &mut workspace,
                SearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(report.into_output(), Some(2));
        assert_eq!(
            other
                .prepare::<SelectedEnd>()
                .search_window_with_authenticated_workspace(
                    b"zb",
                    SearchWindow::new(0, 2),
                    &mut workspace,
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .into_output(),
            Some(2)
        );
        assert!(workspace.lazy.is_bound_to(&plan));
    }

    #[test]
    fn ordered_frontier_resume_is_graph_bound_and_recovers_exact_span() {
        let plan = byte_chain(&[(b'a', b'a'), (b'b', b'b')]);
        let frontier = [1_u32];
        let mut resume = K0ResumeSet::new(&plan, 1, 1, [(&frontier[..], false)]).unwrap();
        let mut workspace =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let haystack = b"zzabzzab";
        let window = SearchWindow::full(haystack);

        let selected = plan
            .prepare::<SelectedEnd>()
            .search_window_from_ordered_resume(
                haystack,
                window,
                &mut workspace,
                &mut resume,
                0,
                3,
                None,
                SearchLimits::unlimited(),
            )
            .unwrap()
            .into_output();
        assert_eq!(selected, Some(4));

        let span = plan
            .prepare::<Span>()
            .search_window_from_ordered_resume(
                haystack,
                window,
                &mut workspace,
                &mut resume,
                0,
                3,
                None,
                SearchLimits::unlimited(),
            )
            .unwrap()
            .into_output();
        assert_eq!(span, Some(MatchSpan::new(2, 4)));

        assert!(matches!(
            plan.prepare::<SelectedEnd>()
                .search_window_from_ordered_resume(
                    haystack,
                    window,
                    &mut workspace,
                    &mut resume,
                    0,
                    3,
                    Some(2),
                    SearchLimits::unlimited(),
                ),
            Err(SearchError::InvalidResumeState { .. })
        ));

        let cloned = plan.clone();
        let mut cloned_workspace =
            K0Workspace::new_accelerated(&cloned, WorkspaceLimits::unlimited()).unwrap();
        assert!(matches!(
            cloned
                .prepare::<SelectedEnd>()
                .search_window_from_ordered_resume(
                    haystack,
                    window,
                    &mut cloned_workspace,
                    &mut resume,
                    0,
                    3,
                    None,
                    SearchLimits::unlimited(),
                ),
            Err(SearchError::InvalidResumeState { .. })
        ));
    }

    #[test]
    fn ordered_frontier_resume_reserves_seed_reverse_and_exact_scratch() {
        let plan = byte_chain(&[(b'a', b'a'), (b'b', b'b')]);
        let haystack = b"zzabzzab";
        let window = SearchWindow::full(haystack);
        let frontier = [1_u32];

        // A finite cold Span continuation must preserve all mandatory work
        // before considering ordinary lazy-initial publication: frontier
        // authentication, forward completion, reverse initialization, and
        // reverse completion.
        let mut cold_resume = K0ResumeSet::new(&plan, 1, 1, [(&frontier[..], false)]).unwrap();
        let mut cold_workspace =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        let cold_scratch = cold_workspace
            .retained_bytes()
            .checked_add(cold_resume.retained_bytes())
            .unwrap();
        let forward = plan
            .conservative_transition_work_bound(window.end() - 3)
            .unwrap();
        let reverse =
            super::conservative_reverse_work_bound(&plan, window.end() - window.start()).unwrap();
        let reverse_initial = super::reverse_initial_work_upper(&plan).unwrap();
        let seed = super::resume_seed_work_upper(&cold_resume, 0).unwrap();
        let cold_exact = INVOCATION_RESET_WORK
            .checked_add(forward)
            .and_then(|work| work.checked_add(reverse))
            .and_then(|work| work.checked_add(reverse_initial))
            .and_then(|work| work.checked_add(seed))
            .unwrap();
        let cold = plan
            .prepare::<Span>()
            .search_window_from_ordered_resume(
                haystack,
                window,
                &mut cold_workspace,
                &mut cold_resume,
                0,
                3,
                None,
                SearchLimits {
                    max_work: cold_exact,
                    max_scratch_bytes: cold_scratch,
                },
            )
            .unwrap();
        assert_eq!(cold.into_output(), Some(MatchSpan::new(2, 4)));
        assert_eq!(cold.accounting().scratch_bytes(), cold_scratch);
        assert_eq!(cold.accounting().setup().retained_bytes(), cold_scratch);
        assert!(!cold_workspace.lazy.initialized);

        let mut refused_resume = K0ResumeSet::new(&plan, 1, 1, [(&frontier[..], false)]).unwrap();
        let mut refused_workspace =
            K0Workspace::new_bidirectional(&plan, WorkspaceLimits::unlimited()).unwrap();
        assert!(matches!(
            plan.prepare::<Span>().search_window_from_ordered_resume(
                haystack,
                window,
                &mut refused_workspace,
                &mut refused_resume,
                0,
                3,
                None,
                SearchLimits {
                    max_work: u64::MAX,
                    max_scratch_bytes: cold_scratch - 1,
                },
            ),
            Err(SearchError::ResourceLimit {
                resource: ResourceKind::ScratchBytes,
                needed,
                limit,
            }) if needed == cold_scratch && limit == cold_scratch - 1
        ));

        // This SelectedEnd limit is deliberately enough for the old
        // completion-only reserve to publish the optional lazy initial row,
        // but not enough for the corrected completion+seed reserve to do so.
        // The exact continuation therefore succeeds inline without letting
        // optional setup steal the frontier-authentication allowance.
        let mut endpoint_resume =
            K0ResumeSet::new(&plan, 1, 1, [(&frontier[..], false)]).unwrap();
        let mut endpoint_workspace =
            K0Workspace::new_accelerated(&plan, WorkspaceLimits::unlimited()).unwrap();
        let endpoint_scratch = endpoint_workspace
            .retained_bytes()
            .checked_add(endpoint_resume.retained_bytes())
            .unwrap();
        let lazy_initial = super::lazy_initial_work_upper(&plan).unwrap();
        let endpoint_limit = INVOCATION_RESET_WORK
            .checked_add(forward)
            .and_then(|work| work.checked_add(lazy_initial))
            .unwrap();
        let old_optional = endpoint_limit - INVOCATION_RESET_WORK - forward;
        let new_optional = old_optional.checked_sub(seed).unwrap();
        assert!(lazy_initial <= old_optional);
        assert!(lazy_initial > new_optional);
        assert_eq!(
            plan.prepare::<SelectedEnd>()
                .search_window_from_ordered_resume(
                    haystack,
                    window,
                    &mut endpoint_workspace,
                    &mut endpoint_resume,
                    0,
                    3,
                    None,
                    SearchLimits {
                        max_work: endpoint_limit,
                        max_scratch_bytes: endpoint_scratch,
                    },
                )
                .unwrap()
                .into_output(),
            Some(4)
        );
        assert!(!endpoint_workspace.lazy.initialized);

        // Once both caches and the resume-set hint are warm, actual work is
        // the exact finite boundary and one less is a hard refusal.
        fn warm_span(
            plan: &Automaton,
            haystack: &[u8],
            max_work: u64,
        ) -> Result<(Option<MatchSpan>, u64, bool), SearchError> {
            let frontier = [1_u32];
            let mut resume = K0ResumeSet::new(plan, 1, 1, [(&frontier[..], false)]).unwrap();
            let mut workspace =
                K0Workspace::new_bidirectional(plan, WorkspaceLimits::unlimited()).unwrap();
            let scratch = workspace
                .retained_bytes()
                .checked_add(resume.retained_bytes())
                .unwrap();
            plan.prepare::<Span>().search_window_from_ordered_resume(
                haystack,
                SearchWindow::full(haystack),
                &mut workspace,
                &mut resume,
                0,
                3,
                None,
                SearchLimits::unlimited(),
            )?;
            let cached = resume.cached_states[0] != super::LAZY_NO_STATE;
            let report = plan.prepare::<Span>().search_window_from_ordered_resume(
                haystack,
                SearchWindow::full(haystack),
                &mut workspace,
                &mut resume,
                0,
                3,
                None,
                SearchLimits {
                    max_work,
                    max_scratch_bytes: scratch,
                },
            )?;
            Ok((report.into_output(), report.accounting().work(), cached))
        }
        let (warm_expected, warm_exact, cached) = warm_span(&plan, haystack, u64::MAX).unwrap();
        assert!(cached);
        assert_eq!(warm_expected, Some(MatchSpan::new(2, 4)));
        assert_eq!(
            warm_span(&plan, haystack, warm_exact).unwrap().0,
            warm_expected
        );
        assert!(matches!(
            warm_span(&plan, haystack, warm_exact - 1),
            Err(SearchError::WorkLimitExceeded { limit, .. }) if limit == warm_exact - 1
        ));
    }

    #[test]
    fn ordered_frontier_resume_rejects_nonconsuming_and_duplicate_items() {
        let plan = byte_chain(&[(b'a', b'a'), (b'b', b'b')]);
        let accept = [2_u32];
        assert!(matches!(
            K0ResumeSet::new(&plan, 1, 1, [(&accept[..], false)]),
            Err(SearchError::InvalidResumeState { .. })
        ));
        let duplicate = [1_u32, 1_u32];
        assert!(matches!(
            K0ResumeSet::new(&plan, 1, 2, [(&duplicate[..], false)]),
            Err(SearchError::InvalidResumeState { .. })
        ));
    }
}
