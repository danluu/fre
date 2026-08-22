//! Fixed-layout prepared Ordered-TNFA data and its target-neutral authority.
//!
//! This module deliberately contains no object publication or target code.
//! It freezes one validated `RawPlan` into explicit C-layout descriptors and
//! bounded pointer-stable storage, then interprets those same encoded tables
//! with the ordered Pike rules used by K0. Native backends consume only this
//! source-independent audited contract.

use std::sync::atomic::{AtomicU64, Ordering};

use fre_automata::{
    EdgeKind, NativeEpsilonClosureAction, NativeEpsilonClosureProgramView,
    NativeOrderedEdgeDispatchView, NativeOrderedEdgeTransitions, RawPlan, StateRole,
    UnicodeLookMatcher, WorkspaceShape,
};
use fre_exact_alloc::try_box_preserve;

use crate::{ObjectError, byte_frequency::estimated_byte_frequency_units, program::OutputContract};

/// Stable descriptor magic for a prepared ordered TNFA.
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_DESCRIPTOR_V1_MAGIC: u64 = u64::from_le_bytes(*b"FREONF1\0");
/// Exact descriptor ABI consumed by generated private entries.
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ABI_VERSION: u32 = 1;
/// Published only after all immutable tables and scratch pointers authenticate.
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_DESCRIPTOR_V1_READY_SEAL: u64 = 0x4ec7_35a9_d861_b20f;
/// Stable scratch-descriptor magic.
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_SCRATCH_V1_MAGIC: u64 = u64::from_le_bytes(*b"FREONS1\0");
/// Exact mutable scratch ABI.
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION: u32 = 1;
/// Setup-complete scratch seal. Exclusive execution mutates only control words
/// and payload cells, never this seal or any pointer/capacity field.
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_SCRATCH_V1_READY_SEAL: u64 = 0x93b6_e4c1_75da_280f;

/// Structural ceiling for the graph descriptor and its six SoA tables emitted
/// into authenticated object rodata. This is independent of the smaller
/// mutable-handle budget: increasing it admits larger immutable graphs without
/// increasing the maximum prepared scratch allocation.
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_V1_MAX_DESCRIPTOR_BYTES: usize = 4 * 1024 * 1024;
/// Structural ceiling for the four exact Pike scratch payloads retained by a
/// prepared handle.
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_V1_MAX_SCRATCH_BYTES: usize = 8 * 1024 * 1024;
/// Structural ceiling for exact Pike scratch construction work.
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_V1_MAX_SETUP_WORK: u64 = 2_000_000;
/// Suggested additive V3 handle cap. It is never consulted implicitly; the
/// preparation caller must place an explicit cap in [`FrozenOrderedNfaLimitsV1`].
#[doc(hidden)]
pub const DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES: usize = 8 * 1024 * 1024;

const ROLE_SPLIT: u8 = 0;
const ROLE_CONSUME: u8 = 1;
const ROLE_ACCEPT: u8 = 2;

const EDGE_EPSILON: u8 = 0;
const EDGE_BYTE_RANGE: u8 = 1;
const EDGE_ASSERT_HAYSTACK_START: u8 = 2;
const EDGE_ASSERT_HAYSTACK_END: u8 = 3;
const EDGE_ASSERT_LINE_START_LF: u8 = 4;
const EDGE_ASSERT_LINE_END_LF: u8 = 5;
const EDGE_ASSERT_LINE_START_CRLF: u8 = 6;
const EDGE_ASSERT_LINE_END_CRLF: u8 = 7;
const EDGE_ASSERT_WORD_ASCII: u8 = 8;
const EDGE_ASSERT_WORD_ASCII_NEGATE: u8 = 9;
const EDGE_ASSERT_WORD_START_ASCII: u8 = 10;
const EDGE_ASSERT_WORD_END_ASCII: u8 = 11;
const EDGE_ASSERT_WORD_START_HALF_ASCII: u8 = 12;
const EDGE_ASSERT_WORD_END_HALF_ASCII: u8 = 13;
const EDGE_ASSERT_WORD_UNICODE: u8 = 14;
const EDGE_ASSERT_WORD_UNICODE_NEGATE: u8 = 15;
const EDGE_ASSERT_WORD_START_UNICODE: u8 = 16;
const EDGE_ASSERT_WORD_END_UNICODE: u8 = 17;
const EDGE_ASSERT_WORD_START_HALF_UNICODE: u8 = 18;
const EDGE_ASSERT_WORD_END_HALF_UNICODE: u8 = 19;

static NEXT_FROZEN_ORDERED_NFA_CACHE_IDENTITY: AtomicU64 = AtomicU64::new(1);

fn next_cache_identity() -> Option<u64> {
    NEXT_FROZEN_ORDERED_NFA_CACHE_IDENTITY
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
            identity.checked_add(1)
        })
        .ok()
}

/// Explicit source-independent construction limits.
///
/// A refusal is soft: callers retain the incumbent prepared runtime route.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrozenOrderedNfaLimitsV1 {
    pub max_states: usize,
    pub max_edges: usize,
    pub max_descriptor_bytes: usize,
    pub max_scratch_bytes: usize,
    pub max_setup_work: u64,
    /// Maximum retained scratch-descriptor and Pike payload bytes. Immutable
    /// graph data is separately charged to object/native-data limits. This
    /// value must come from an additive preparation ABI or a containing
    /// operation-set handle cap; V2's reserved words are never reinterpreted.
    pub max_handle_bytes: usize,
}

impl FrozenOrderedNfaLimitsV1 {
    /// Construct explicit limits for one additive prepared-handle budget.
    #[must_use]
    pub const fn new(max_handle_bytes: usize) -> Self {
        Self {
            max_states: 262_144,
            max_edges: 1_048_576,
            max_descriptor_bytes: FROZEN_ORDERED_NFA_V1_MAX_DESCRIPTOR_BYTES,
            max_scratch_bytes: FROZEN_ORDERED_NFA_V1_MAX_SCRATCH_BYTES,
            max_setup_work: FROZEN_ORDERED_NFA_V1_MAX_SETUP_WORK,
            max_handle_bytes,
        }
    }
}

/// Exact object-data, setup-work, and prepared-handle accounting.
///
/// Graph tables are compiler-side model storage only and become authenticated
/// object rodata; they are never duplicated into the prepared handle. The
/// handle charge is therefore exactly the mutable scratch descriptor and its
/// four bounded payloads. Prospective and retained handle values are measured
/// independently and must agree before publication.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrozenOrderedNfaAccountingV1 {
    descriptor_bytes: usize,
    scratch_bytes: usize,
    setup_work: u64,
    prospective_handle_bytes: usize,
    retained_handle_bytes: usize,
}

impl FrozenOrderedNfaAccountingV1 {
    #[must_use]
    pub const fn descriptor_bytes(self) -> usize {
        self.descriptor_bytes
    }

    #[must_use]
    pub const fn scratch_bytes(self) -> usize {
        self.scratch_bytes
    }

    #[must_use]
    pub const fn setup_work(self) -> u64 {
        self.setup_work
    }

    #[must_use]
    pub const fn prospective_handle_bytes(self) -> usize {
        self.prospective_handle_bytes
    }

    #[must_use]
    pub const fn retained_handle_bytes(self) -> usize {
        self.retained_handle_bytes
    }
}

/// Compiler-only graph-proved byte bounds for an absolute whole-window match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WholeWindowWidthBounds {
    pub(crate) minimum: usize,
    pub(crate) maximum: usize,
}

/// Target-neutral view of one exact ordered-NFA Span program.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeOrderedNfaProgramView<'a> {
    pub(crate) output: OutputContract,
    pub(crate) raw: &'a RawPlan,
    /// Compiler-only consumed-byte bounds for graphs whose accepting paths
    /// independently cross absolute start and absolute end assertion cuts.
    /// This is intentionally absent from every frozen object descriptor.
    pub(crate) whole_window_width_bounds: Option<WholeWindowWidthBounds>,
    /// Exact compiler-only first-byte proof for a nonempty anchored prefix.
    /// This is intentionally absent from every frozen object descriptor.
    pub(crate) start_prefix_first_set: Option<[u64; 4]>,
    pub(crate) ordered_edge_dispatch: Option<NativeOrderedEdgeDispatchView<'a>>,
    pub(crate) start_closure_dispatch: Option<NativeEpsilonClosureProgramView<'a>>,
    /// Exact compiler-only bitmap for a fragmented final-byte suffix column.
    /// Reverse depth is fixed at zero by this field's contract. The four
    /// canonical ascending-byte-index words never enter the frozen object
    /// image.
    pub(crate) terminal_exact_set: Option<[u64; 4]>,
    pub(crate) terminal_range: Option<NativeOrderedNfaTerminalRangeV1>,
    pub(crate) line_terminator: u8,
    pub(crate) artifact_identity: [u8; 32],
}

/// One graph-proved necessary range for the final consumed match byte.
///
/// V1 deliberately admits only reverse depth zero. Keeping the depth explicit
/// lets a later ABI add deeper suffix columns without silently changing the
/// byte constrained by this proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeOrderedNfaTerminalRangeV1 {
    pub(crate) start: u8,
    pub(crate) end: u8,
    pub(crate) reverse_depth: u8,
}

/// Below this structural size, an extra full-window range scan is more likely
/// to duplicate cheap Pike work than amortize it.
pub(crate) const MIN_NATIVE_ORDERED_NFA_TERMINAL_RANGE_EDGES: usize = 64;
/// Exact fragmented sets broader than this are insufficiently selective to
/// justify an exhaustive reverse trim on match-dense aggregate routes.
pub(crate) const MAX_NATIVE_ORDERED_NFA_TERMINAL_EXACT_SET_CARDINALITY: u16 = 64;

/// A start-only text specialization remains deliberately smaller than the
/// universal retained sidecar. These fixed ceilings cover the two motivating
/// Rebar graphs while bounding compiler work and target-code growth before an
/// assembler allocates the candidate entry.
pub(crate) const MAX_NATIVE_ORDERED_NFA_START_CLOSURE_INSTRUCTIONS: usize =
    fre_automata::COMPILER_PRIVATE_EPSILON_CLOSURE_START_MAX_INSTRUCTIONS;
pub(crate) const MAX_NATIVE_ORDERED_NFA_START_CLOSURE_SPLIT_EDGE_VISITS: usize =
    fre_automata::COMPILER_PRIVATE_EPSILON_CLOSURE_START_MAX_SPLIT_EDGE_VISITS;

/// Bound code growth and false-positive scanning for the compiler-only
/// first-byte restart filter. The cover may contain gaps, but never omits a
/// byte proved possible by the anchored prefix.
pub(crate) const MAX_NATIVE_ORDERED_NFA_START_PREFIX_RANGES: usize = 4;
pub(crate) const MAX_NATIVE_ORDERED_NFA_START_PREFIX_CANDIDATE_BYTES: usize = 96;
/// Require enough authenticated idle-root closure work to amortize the
/// compiler-only membership test. A raw Consume root has no retained closure
/// receipt and deliberately keeps the incumbent byte-by-byte loop.
pub(crate) const MIN_NATIVE_ORDERED_NFA_START_PREFIX_CLOSURE_INSTRUCTIONS: usize = 16;

// A distinct single-assertion guarded start may amortize the same prefix text
// in its wide consuming row instead of a retained epsilon closure. Keep this
// narrow policy private to source admission: the ordinary 96-byte cap, emitted
// plan, and frozen object ABI remain unchanged.
const MIN_NATIVE_ORDERED_NFA_GUARDED_UNICODE_PREFIX_CONSUME_EDGES: usize = 32;
const MIN_NATIVE_ORDERED_NFA_GUARDED_UNICODE_PREFIX_EXACT_BYTES: u32 = 97;
const MAX_NATIVE_ORDERED_NFA_GUARDED_UNICODE_PREFIX_EXACT_BYTES: u32 = 128;
const MAX_NATIVE_ORDERED_NFA_GUARDED_UNICODE_PREFIX_CANDIDATE_BYTES: usize = 128;

/// Exact immutable object-wire descriptor extent. All table locations are
/// descriptor-relative little-endian `u32` offsets, so the image contains no
/// data relocations and remains position independent.
pub(crate) const ORDERED_NFA_OBJECT_V1_DESCRIPTOR_BYTES: usize = 128;
pub(crate) const ORDERED_NFA_OBJECT_V1_ALIGNMENT: usize = 16;
pub(crate) const ORDERED_NFA_OBJECT_V1_READY_SEAL: u64 = 0x6d2c_8fa1_b437_50e9;
pub(crate) const ORDERED_NFA_OBJECT_V1_MAGIC: u64 = u64::from_le_bytes(*b"FREONR1\0");
pub(crate) const ORDERED_NFA_OBJECT_V1_ABI_VERSION: u32 = 1;
pub(crate) const ORDERED_NFA_OBJECT_V1_FLAG_UNICODE: u32 = 1;
pub(crate) const ORDERED_NFA_OBJECT_V1_KNOWN_FLAGS: u32 = ORDERED_NFA_OBJECT_V1_FLAG_UNICODE;
pub(crate) const ORDERED_NFA_OBJECT_V1_IDENTITY_OFFSET: usize = 32;
pub(crate) const ORDERED_NFA_OBJECT_V1_ROLES_OFFSET_FIELD: usize = 64;
pub(crate) const ORDERED_NFA_OBJECT_V1_EDGE_OFFSETS_OFFSET_FIELD: usize = 68;
pub(crate) const ORDERED_NFA_OBJECT_V1_EDGE_TARGETS_OFFSET_FIELD: usize = 72;
pub(crate) const ORDERED_NFA_OBJECT_V1_EDGE_KINDS_OFFSET_FIELD: usize = 76;
pub(crate) const ORDERED_NFA_OBJECT_V1_BYTE_STARTS_OFFSET_FIELD: usize = 80;
pub(crate) const ORDERED_NFA_OBJECT_V1_BYTE_ENDS_OFFSET_FIELD: usize = 84;
pub(crate) const ORDERED_NFA_OBJECT_V1_UNICODE_RANGES_OFFSET_FIELD: usize = 88;
pub(crate) const ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_COUNT_FIELD: usize = 92;
pub(crate) const ORDERED_NFA_OBJECT_V1_STATE_COUNT_FIELD: usize = 96;
pub(crate) const ORDERED_NFA_OBJECT_V1_EDGE_COUNT_FIELD: usize = 100;
pub(crate) const ORDERED_NFA_OBJECT_V1_ZERO_WIDTH_EDGE_COUNT_FIELD: usize = 104;
pub(crate) const ORDERED_NFA_OBJECT_V1_CLOSURE_SLOTS_FIELD: usize = 108;
pub(crate) const ORDERED_NFA_OBJECT_V1_START_STATE_FIELD: usize = 112;
pub(crate) const ORDERED_NFA_OBJECT_V1_ASSERTION_KINDS_FIELD: usize = 116;
pub(crate) const ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_STRIDE_FIELD: usize = 120;
pub(crate) const ORDERED_NFA_OBJECT_V1_LINE_TERMINATOR_FIELD: usize = 124;
pub(crate) const ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_STRIDE: u32 = 8;
pub(crate) const ORDERED_NFA_OBJECT_V1_ASSERTION_MASK: u32 = (1 << 18) - 1;
pub(crate) const ORDERED_NFA_OBJECT_V1_UNICODE_ASSERTION_MASK: u32 = 0x3f000;
pub(crate) const ORDERED_NFA_OBJECT_V2_READY_SEAL: u64 = 0xe0f1_8ec9_d9d2_dbc5;
pub(crate) const ORDERED_NFA_OBJECT_V2_MAGIC: u64 = u64::from_le_bytes(*b"FREONR2\0");
pub(crate) const ORDERED_NFA_OBJECT_V2_ABI_VERSION: u32 = 2;
pub(crate) const ORDERED_NFA_OBJECT_V2_FLAG_ORDERED_EDGE_DISPATCH: u32 = 1 << 1;
pub(crate) const ORDERED_NFA_OBJECT_V2_KNOWN_FLAGS: u32 =
    ORDERED_NFA_OBJECT_V1_FLAG_UNICODE | ORDERED_NFA_OBJECT_V2_FLAG_ORDERED_EDGE_DISPATCH;
/// Domain-separated as the little-endian first 64 bits of SHA-256 over
/// `fre-aot-regex ordered-nfa object v3 terminal-range ready seal`.
pub(crate) const ORDERED_NFA_OBJECT_V3_READY_SEAL: u64 = 0x1714_b2b6_1371_1a7f;
pub(crate) const ORDERED_NFA_OBJECT_V3_MAGIC: u64 = u64::from_le_bytes(*b"FREONR3\0");
pub(crate) const ORDERED_NFA_OBJECT_V3_ABI_VERSION: u32 = 3;
pub(crate) const ORDERED_NFA_OBJECT_V3_FLAG_TERMINAL_RANGE: u32 = 1 << 2;
pub(crate) const ORDERED_NFA_OBJECT_V3_KNOWN_FLAGS: u32 = ORDERED_NFA_OBJECT_V1_FLAG_UNICODE
    | ORDERED_NFA_OBJECT_V2_FLAG_ORDERED_EDGE_DISPATCH
    | ORDERED_NFA_OBJECT_V3_FLAG_TERMINAL_RANGE;
pub(crate) const ORDERED_NFA_OBJECT_V3_TERMINAL_RANGE_START_FIELD: usize = 125;
pub(crate) const ORDERED_NFA_OBJECT_V3_TERMINAL_RANGE_END_FIELD: usize = 126;
pub(crate) const ORDERED_NFA_OBJECT_V3_TERMINAL_RANGE_REVERSE_DEPTH_FIELD: usize = 127;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_DESCRIPTOR_BYTES: usize = 32;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_ROWS_OFFSET_FIELD: usize = 0;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_BYTE_MAP_OFFSET_FIELD: usize = 4;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_METADATA_OFFSET_FIELD: usize = 8;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_TRANSITIONS_OFFSET_FIELD: usize = 12;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_ADMITTED_ROWS_FIELD: usize = 16;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_METADATA_COUNT_FIELD: usize = 20;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_TRANSITION_COUNT_FIELD: usize = 24;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_CONTROL_FIELD: usize = 28;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_FORMAT: u32 = 1;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_ENCODING_DIRECT32: u32 = 1;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_ENCODING_DIRECT64: u32 = 2;
pub(crate) const ORDERED_NFA_EDGE_DISPATCH_V1_ENCODING_LEGACY: u32 = 3;

const fn ordered_nfa_object_flags(
    has_unicode: bool,
    has_dispatch: bool,
    has_terminal_range: bool,
) -> u32 {
    (if has_unicode {
        ORDERED_NFA_OBJECT_V1_FLAG_UNICODE
    } else {
        0
    }) | if has_dispatch {
        ORDERED_NFA_OBJECT_V2_FLAG_ORDERED_EDGE_DISPATCH
    } else {
        0
    } | if has_terminal_range {
        ORDERED_NFA_OBJECT_V3_FLAG_TERMINAL_RANGE
    } else {
        0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeOrderedEdgeEncoding {
    Direct32 { target_bits: u32 },
    Direct64,
    Legacy,
}

impl NativeOrderedEdgeEncoding {
    const fn tag(self) -> u32 {
        match self {
            Self::Direct32 { .. } => ORDERED_NFA_EDGE_DISPATCH_V1_ENCODING_DIRECT32,
            Self::Direct64 => ORDERED_NFA_EDGE_DISPATCH_V1_ENCODING_DIRECT64,
            Self::Legacy => ORDERED_NFA_EDGE_DISPATCH_V1_ENCODING_LEGACY,
        }
    }

    pub(crate) const fn target_bits(self) -> u32 {
        match self {
            Self::Direct32 { target_bits } => target_bits,
            Self::Direct64 | Self::Legacy => 0,
        }
    }

    pub(crate) const fn entry_bytes(self) -> usize {
        match self {
            Self::Direct64 => 8,
            Self::Direct32 { .. } | Self::Legacy => 4,
        }
    }

    pub(crate) const fn control(self) -> u32 {
        ORDERED_NFA_EDGE_DISPATCH_V1_FORMAT
            | (self.tag() << 8)
            | (self.target_bits() << 16)
            | (match self {
                Self::Direct64 => 8,
                Self::Direct32 { .. } | Self::Legacy => 4,
            } << 24)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeOrderedEdgeDispatchLayout {
    pub(crate) descriptor_offset: usize,
    pub(crate) rows_offset: usize,
    pub(crate) byte_map_offset: usize,
    pub(crate) metadata_offset: usize,
    pub(crate) transitions_offset: usize,
    pub(crate) admitted_rows: usize,
    pub(crate) metadata_count: usize,
    pub(crate) transition_count: usize,
    pub(crate) encoding: NativeOrderedEdgeEncoding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeOrderedNfaObjectLayout {
    pub(crate) object_bytes: usize,
    pub(crate) roles_offset: usize,
    pub(crate) edge_offsets_offset: usize,
    pub(crate) edge_targets_offset: usize,
    pub(crate) edge_kinds_offset: usize,
    pub(crate) byte_starts_offset: usize,
    pub(crate) byte_ends_offset: usize,
    pub(crate) unicode_ranges_offset: Option<usize>,
    pub(crate) unicode_range_count: usize,
    pub(crate) state_count: usize,
    pub(crate) edge_count: usize,
    pub(crate) zero_width_edge_count: usize,
    pub(crate) closure_slots: usize,
    pub(crate) start_state: u32,
    pub(crate) assertion_kinds: u32,
    /// Whether the canonical graph has enough duplicate assertion edges to
    /// justify lazy boundary-local truth caching in native code. This is a
    /// compiler-only decision and does not change the frozen object ABI.
    pub(crate) cache_boundary_assertions: bool,
    /// Compiler-only receipt for an admitted start-root text specialization.
    /// No field or payload is added to the frozen object image.
    pub(crate) start_closure_dispatch: Option<NativeOrderedNfaStartClosureLayout>,
    /// Compiler-only first-byte admission and idle-forward plan. This changes
    /// generated text only and adds no field or payload to the object image.
    pub(crate) start_prefix: Option<NativeOrderedNfaStartPrefixPlan>,
    /// Compiler-only absolute whole-window width proof. This changes neither
    /// the frozen object descriptor nor any following table offset or extent.
    pub(crate) whole_window_width_bounds: Option<WholeWindowWidthBounds>,
    pub(crate) line_terminator: u8,
    pub(crate) ordered_edge_dispatch: Option<NativeOrderedEdgeDispatchLayout>,
    pub(crate) terminal_range: Option<NativeOrderedNfaTerminalRangeV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeOrderedNfaStartClosureLayout {
    pub(crate) guarded: bool,
    pub(crate) instruction_count: usize,
    pub(crate) split_edge_visits: usize,
}

const EMPTY_NATIVE_ORDERED_NFA_BYTE_RANGE: NativeOrderedNfaByteRange =
    NativeOrderedNfaByteRange { start: 0, end: 0 };

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeOrderedNfaByteRange {
    pub(crate) start: u8,
    pub(crate) end: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeOrderedNfaStartPrefixPlan {
    ranges: [NativeOrderedNfaByteRange; MAX_NATIVE_ORDERED_NFA_START_PREFIX_RANGES],
    range_count: u8,
}

impl NativeOrderedNfaStartPrefixPlan {
    pub(crate) fn ranges(&self) -> &[NativeOrderedNfaByteRange] {
        &self.ranges[..usize::from(self.range_count)]
    }
}

/// Validated compiler-only receipt for an aggregate terminal-set trim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeOrderedNfaTerminalExactSetPlan {
    words: [u64; 4],
}

impl NativeOrderedNfaTerminalExactSetPlan {
    pub(crate) const fn words(self) -> [u64; 4] {
        self.words
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeOrderedNfaObjectImage<'a> {
    pub(crate) bytes: Vec<u8>,
    pub(crate) layout: NativeOrderedNfaObjectLayout,
    /// Compiler-only fragmented final-byte bitmap retained through target
    /// lowering. This never enters the frozen object image.
    pub(crate) terminal_exact_set_words: Option<[u64; 4]>,
    /// Borrowed compiler IR consumed only while target text is emitted.
    pub(crate) start_closure_program: Option<NativeEpsilonClosureProgramView<'a>>,
}

/// Failure-atomic result of sizing and constructing one native Ordered-NFA
/// object image. The reported path distinguishes a structural refusal from an
/// exact caller byte ceiling before any image allocation is attempted.
pub(crate) enum NativeOrderedNfaObjectImageBuild<'a> {
    Built(NativeOrderedNfaObjectImage<'a>),
    Unsupported,
    DataLimit { required: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeOrderedEdgeDispatchShape {
    admitted_rows: usize,
    metadata_count: usize,
    transition_count: usize,
    encoding: NativeOrderedEdgeEncoding,
}

fn boundary_assertion_cache_is_profitable(assertion_edges: usize, assertion_kinds: u32) -> bool {
    const MIN_ASSERTION_EDGES: usize = 4;
    const MIN_DUPLICATE_EDGES: usize = 2;

    let distinct_kinds = usize::try_from(assertion_kinds.count_ones())
        .expect("at most 18 ordered-NFA assertion kinds fit usize");
    assertion_edges >= MIN_ASSERTION_EDGES
        && assertion_edges.saturating_sub(distinct_kinds) >= MIN_DUPLICATE_EDGES
}

fn validate_native_ordered_nfa_terminal_range(
    range: NativeOrderedNfaTerminalRangeV1,
    edge_count: usize,
) -> Result<NativeOrderedNfaTerminalRangeV1, ObjectError> {
    if edge_count < MIN_NATIVE_ORDERED_NFA_TERMINAL_RANGE_EDGES
        || range.start > range.end
        || (range.start == u8::MIN && range.end == u8::MAX)
        || range.reverse_depth != 0
    {
        return Err(ObjectError::InvalidModule(
            "ordered-NFA terminal-range proof",
        ));
    }
    Ok(range)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "a u8 byte indexes one of four complete u64 bitmap words"
)]
fn native_ordered_nfa_terminal_exact_set_contains(exact: [u64; 4], byte: u8) -> bool {
    let index = usize::from(byte);
    exact[index / 64] & (1_u64 << (index % 64)) != 0
}

/// Validate the compiler-only exact terminal bitmap. Empty, universal, and
/// contiguous columns are not members of this plan: the latter remain owned
/// by the V3 range path.
fn validate_native_ordered_nfa_terminal_exact_set(
    exact: [u64; 4],
    edge_count: usize,
) -> Result<NativeOrderedNfaTerminalExactSetPlan, ObjectError> {
    let cardinality = exact.iter().map(|word| word.count_ones()).sum::<u32>();
    if edge_count < MIN_NATIVE_ORDERED_NFA_TERMINAL_RANGE_EDGES
        || cardinality == 0
        || cardinality > u32::from(MAX_NATIVE_ORDERED_NFA_TERMINAL_EXACT_SET_CARDINALITY)
    {
        return Err(ObjectError::InvalidModule(
            "ordered-NFA terminal exact-set proof",
        ));
    }
    let start = (u8::MIN..=u8::MAX)
        .find(|&byte| native_ordered_nfa_terminal_exact_set_contains(exact, byte))
        .ok_or(ObjectError::InvalidModule(
            "ordered-NFA terminal exact-set first byte",
        ))?;
    let end = (u8::MIN..=u8::MAX)
        .rev()
        .find(|&byte| native_ordered_nfa_terminal_exact_set_contains(exact, byte))
        .ok_or(ObjectError::InvalidModule(
            "ordered-NFA terminal exact-set last byte",
        ))?;
    let inclusive_width = u32::from(end)
        .checked_sub(u32::from(start))
        .and_then(|width| width.checked_add(1))
        .ok_or(ObjectError::InvalidModule(
            "ordered-NFA terminal exact-set width",
        ))?;
    if inclusive_width == cardinality {
        return Err(ObjectError::InvalidModule(
            "ordered-NFA terminal exact set is contiguous",
        ));
    }
    Ok(NativeOrderedNfaTerminalExactSetPlan { words: exact })
}

fn native_ordered_nfa_start_prefix_contains(
    plan: NativeOrderedNfaStartPrefixPlan,
    byte: u8,
) -> bool {
    plan.ranges()
        .iter()
        .any(|range| (range.start..=range.end).contains(&byte))
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "fixed four-word membership and the complete byte loop bound every index and shift"
)]
fn validate_native_ordered_nfa_start_prefix_with_candidate_cap(
    plan: NativeOrderedNfaStartPrefixPlan,
    exact: [u64; 4],
    max_candidate_bytes: usize,
) -> Result<NativeOrderedNfaStartPrefixPlan, ObjectError> {
    if max_candidate_bytes == 0
        || max_candidate_bytes > MAX_NATIVE_ORDERED_NFA_GUARDED_UNICODE_PREFIX_CANDIDATE_BYTES
    {
        return Err(ObjectError::InvalidModule(
            "ordered-NFA start-prefix planner candidate-byte cap",
        ));
    }
    let ranges = plan.ranges();
    if ranges.is_empty() || ranges.len() > MAX_NATIVE_ORDERED_NFA_START_PREFIX_RANGES {
        return Err(ObjectError::InvalidModule(
            "ordered-NFA start-prefix range count",
        ));
    }
    let mut candidate_bytes = 0_usize;
    let mut previous_end = None;
    for range in ranges {
        if range.start > range.end || previous_end.is_some_and(|end| end >= range.start) {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA start-prefix range order",
            ));
        }
        let width = usize::from(range.end)
            .checked_sub(usize::from(range.start))
            .and_then(|width| width.checked_add(1))
            .ok_or(ObjectError::InvalidModule(
                "ordered-NFA start-prefix range width",
            ))?;
        candidate_bytes =
            candidate_bytes
                .checked_add(width)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "ordered-NFA start-prefix candidate bytes",
                ))?;
        previous_end = Some(range.end);
    }
    if candidate_bytes == 0 || candidate_bytes > max_candidate_bytes {
        return Err(ObjectError::InvalidModule(
            "ordered-NFA start-prefix candidate-byte cap",
        ));
    }
    for byte in u8::MIN..=u8::MAX {
        let index = usize::from(byte);
        if exact[index / 64] & (1_u64 << (index % 64)) != 0
            && !native_ordered_nfa_start_prefix_contains(plan, byte)
        {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA start-prefix cover omits an exact byte",
            ));
        }
    }
    Ok(plan)
}

/// Cover the exact first-byte proof by at most four deterministic inclusive
/// ranges. Merging the least-frequent intervening gaps can add candidates,
/// but the returned filter remains a superset of the semantic proof.
#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "the exact cardinality, deterministic gap merging, and fixed range capacity form one bounded planner transaction"
)]
fn derive_native_ordered_nfa_start_prefix(
    exact: [u64; 4],
) -> Result<Option<NativeOrderedNfaStartPrefixPlan>, ObjectError> {
    derive_native_ordered_nfa_start_prefix_with_candidate_cap(
        exact,
        MAX_NATIVE_ORDERED_NFA_START_PREFIX_CANDIDATE_BYTES,
    )
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "the exact cardinality, deterministic gap merging, and fixed range capacity form one bounded planner transaction"
)]
fn derive_native_ordered_nfa_start_prefix_with_candidate_cap(
    exact: [u64; 4],
    max_candidate_bytes: usize,
) -> Result<Option<NativeOrderedNfaStartPrefixPlan>, ObjectError> {
    const MAX_EXACT_RANGES: usize = MAX_NATIVE_ORDERED_NFA_GUARDED_UNICODE_PREFIX_CANDIDATE_BYTES;

    if max_candidate_bytes == 0 || max_candidate_bytes > MAX_EXACT_RANGES {
        return Err(ObjectError::InvalidModule(
            "ordered-NFA start-prefix derivation candidate-byte cap",
        ));
    }

    let exact_candidate_bytes: usize = exact
        .iter()
        .map(|word| {
            usize::try_from(word.count_ones())
                .expect("a u64 population count fits every supported usize")
        })
        .sum();
    if exact_candidate_bytes == 0 || exact_candidate_bytes > max_candidate_bytes {
        return Ok(None);
    }

    let mut ranges = [EMPTY_NATIVE_ORDERED_NFA_BYTE_RANGE; MAX_EXACT_RANGES];
    let mut range_count = 0_usize;
    for byte in u8::MIN..=u8::MAX {
        let index = usize::from(byte);
        if exact[index / 64] & (1_u64 << (index % 64)) == 0 {
            continue;
        }
        if let Some(last) = range_count
            .checked_sub(1)
            .and_then(|index| ranges.get_mut(index))
            && last.end.checked_add(1) == Some(byte)
        {
            last.end = byte;
            continue;
        }
        let slot = ranges
            .get_mut(range_count)
            .ok_or(ObjectError::InvalidModule(
                "ordered-NFA start-prefix exact range capacity",
            ))?;
        *slot = NativeOrderedNfaByteRange {
            start: byte,
            end: byte,
        };
        range_count = range_count
            .checked_add(1)
            .ok_or(ObjectError::ArithmeticOverflow(
                "ordered-NFA start-prefix exact range count",
            ))?;
    }

    while range_count > MAX_NATIVE_ORDERED_NFA_START_PREFIX_RANGES {
        let mut selected_gap = None;
        for gap_index in 0..range_count.saturating_sub(1) {
            let left = ranges[gap_index];
            let right = ranges[gap_index + 1];
            let gap_start = u16::from(left.end) + 1;
            let gap_end = u16::from(right.start).saturating_sub(1);
            let gap_bytes = gap_end
                .checked_sub(gap_start)
                .and_then(|width| width.checked_add(1))
                .ok_or(ObjectError::InvalidModule(
                    "ordered-NFA start-prefix ranges overlap",
                ))?;
            let mut frequency_units = 0_u16;
            for byte in gap_start..=gap_end {
                frequency_units = frequency_units.saturating_add(estimated_byte_frequency_units(
                    u8::try_from(byte).map_err(|_| {
                        ObjectError::ArithmeticOverflow("ordered-NFA start-prefix gap byte")
                    })?,
                ));
            }
            let key = (frequency_units, gap_bytes, gap_index);
            if selected_gap.is_none_or(|(_, current_key)| key < current_key) {
                selected_gap = Some((gap_index, key));
            }
        }
        let (gap_index, _) = selected_gap.ok_or(ObjectError::InvalidModule(
            "ordered-NFA start-prefix has no mergeable gap",
        ))?;
        ranges[gap_index].end = ranges[gap_index + 1].end;
        ranges.copy_within(gap_index + 2..range_count, gap_index + 1);
        range_count -= 1;
    }

    let candidate_bytes = ranges[..range_count]
        .iter()
        .try_fold(0_usize, |sum, range| {
            let width = usize::from(range.end)
                .checked_sub(usize::from(range.start))
                .and_then(|width| width.checked_add(1))
                .ok_or(ObjectError::InvalidModule(
                    "ordered-NFA start-prefix coalesced range width",
                ))?;
            sum.checked_add(width)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "ordered-NFA start-prefix coalesced candidate bytes",
                ))
        })?;
    if candidate_bytes > max_candidate_bytes {
        return Ok(None);
    }

    let mut compact =
        [EMPTY_NATIVE_ORDERED_NFA_BYTE_RANGE; MAX_NATIVE_ORDERED_NFA_START_PREFIX_RANGES];
    compact[..range_count].copy_from_slice(&ranges[..range_count]);
    let plan = NativeOrderedNfaStartPrefixPlan {
        ranges: compact,
        range_count: u8::try_from(range_count).map_err(|_| {
            ObjectError::ArithmeticOverflow("ordered-NFA start-prefix compact range count")
        })?,
    };
    Ok(Some(
        validate_native_ordered_nfa_start_prefix_with_candidate_cap(
            plan,
            exact,
            max_candidate_bytes,
        )?,
    ))
}

fn native_ordered_nfa_state_edge_bounds(
    raw: &RawPlan,
    state: usize,
) -> Result<(usize, usize), ObjectError> {
    let successor = state.checked_add(1).ok_or(ObjectError::InvalidModule(
        "ordered-NFA guarded Unicode prefix state successor",
    ))?;
    let begin = raw
        .edge_offsets
        .get(state)
        .copied()
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(ObjectError::InvalidModule(
            "ordered-NFA guarded Unicode prefix edge begin",
        ))?;
    let end = raw
        .edge_offsets
        .get(successor)
        .copied()
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(ObjectError::InvalidModule(
            "ordered-NFA guarded Unicode prefix edge end",
        ))?;
    if begin > end || end > raw.edge_targets.len() {
        return Err(ObjectError::InvalidModule(
            "ordered-NFA guarded Unicode prefix edge bounds",
        ));
    }
    Ok((begin, end))
}

fn native_ordered_nfa_start_prefix_intersects_utf8_continuation(
    plan: NativeOrderedNfaStartPrefixPlan,
) -> bool {
    plan.ranges()
        .iter()
        .any(|range| range.start <= 0xbf && range.end >= 0x80)
}

/// Admit the one audited cheap-closure exception without weakening the
/// ordinary start-prefix policy. The scalar start closure deliberately has no
/// retained sidecar for this one-edge shape, so the canonical graph must
/// describe exactly `AssertWordUnicode -> Consume`; the consuming row then
/// reconstructs the authenticated first-byte bitmap before the wider cover is
/// considered.
#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "the complete fail-closed graph, bitmap, and range validation transaction bounds every index and shift"
)]
fn derive_native_ordered_nfa_guarded_unicode_start_prefix(
    raw: &RawPlan,
    exact: [u64; 4],
) -> Result<Option<NativeOrderedNfaStartPrefixPlan>, ObjectError> {
    let root_state = usize::try_from(raw.start)
        .map_err(|_| ObjectError::InvalidModule("ordered-NFA guarded Unicode prefix root state"))?;
    let root_role = raw.roles.get(root_state).ok_or(ObjectError::InvalidModule(
        "ordered-NFA guarded Unicode prefix root bounds",
    ))?;
    if *root_role != StateRole::Split {
        return Ok(None);
    }

    let (root_begin, root_end) = native_ordered_nfa_state_edge_bounds(raw, root_state)?;
    for edge in root_begin..root_end {
        let kind = *raw.edge_kinds.get(edge).ok_or(ObjectError::InvalidModule(
            "ordered-NFA guarded Unicode prefix root edge kind",
        ))?;
        if kind == EdgeKind::ByteRange || encode_edge_kind(kind).is_none() {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA guarded Unicode prefix root edge role",
            ));
        }
        if raw.byte_starts.get(edge) != Some(&0) || raw.byte_ends.get(edge) != Some(&0) {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA guarded Unicode prefix assertion payload",
            ));
        }
        let target = raw
            .edge_targets
            .get(edge)
            .copied()
            .and_then(|target| usize::try_from(target).ok())
            .ok_or(ObjectError::InvalidModule(
                "ordered-NFA guarded Unicode prefix root target",
            ))?;
        if target >= raw.roles.len() {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA guarded Unicode prefix root target bounds",
            ));
        }
    }
    if root_end.checked_sub(root_begin) != Some(1) {
        return Ok(None);
    }
    let root_kind = raw
        .edge_kinds
        .get(root_begin)
        .ok_or(ObjectError::InvalidModule(
            "ordered-NFA guarded Unicode prefix root edge kind",
        ))?;
    if *root_kind != EdgeKind::AssertWordUnicode {
        return Ok(None);
    }
    let consume_state = *raw
        .edge_targets
        .get(root_begin)
        .ok_or(ObjectError::InvalidModule(
            "ordered-NFA guarded Unicode prefix root target",
        ))?;
    let consume_index = usize::try_from(consume_state).map_err(|_| {
        ObjectError::InvalidModule("ordered-NFA guarded Unicode prefix consume state")
    })?;
    let consume_role = raw
        .roles
        .get(consume_index)
        .ok_or(ObjectError::InvalidModule(
            "ordered-NFA guarded Unicode prefix consume bounds",
        ))?;
    if *consume_role != StateRole::Consume {
        return Ok(None);
    }

    let (consume_begin, consume_end) = native_ordered_nfa_state_edge_bounds(raw, consume_index)?;
    let consume_degree =
        consume_end
            .checked_sub(consume_begin)
            .ok_or(ObjectError::InvalidModule(
                "ordered-NFA guarded Unicode prefix consuming degree",
            ))?;

    let mut reconstructed = [0_u64; 4];
    for edge in consume_begin..consume_end {
        if raw.edge_kinds.get(edge) != Some(&EdgeKind::ByteRange) {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA guarded Unicode prefix consuming edge kind",
            ));
        }
        let target = raw
            .edge_targets
            .get(edge)
            .copied()
            .and_then(|target| usize::try_from(target).ok())
            .ok_or(ObjectError::InvalidModule(
                "ordered-NFA guarded Unicode prefix consuming target",
            ))?;
        if target >= raw.roles.len() {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA guarded Unicode prefix consuming target bounds",
            ));
        }
        let start = *raw.byte_starts.get(edge).ok_or(ObjectError::InvalidModule(
            "ordered-NFA guarded Unicode prefix range start",
        ))?;
        let end = *raw.byte_ends.get(edge).ok_or(ObjectError::InvalidModule(
            "ordered-NFA guarded Unicode prefix range end",
        ))?;
        if start > end {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA guarded Unicode prefix range order",
            ));
        }
        for byte in start..=end {
            let index = usize::from(byte);
            reconstructed[index / 64] |= 1_u64 << (index % 64);
        }
    }

    let exact_bytes = reconstructed
        .iter()
        .map(|word| word.count_ones())
        .sum::<u32>();
    if reconstructed != exact {
        return Err(ObjectError::InvalidModule(
            "ordered-NFA guarded Unicode prefix exact-set proof",
        ));
    }
    if consume_degree < MIN_NATIVE_ORDERED_NFA_GUARDED_UNICODE_PREFIX_CONSUME_EDGES
        || !(MIN_NATIVE_ORDERED_NFA_GUARDED_UNICODE_PREFIX_EXACT_BYTES
            ..=MAX_NATIVE_ORDERED_NFA_GUARDED_UNICODE_PREFIX_EXACT_BYTES)
            .contains(&exact_bytes)
        || exact[2] != 0
    {
        return Ok(None);
    }
    let Some(plan) = derive_native_ordered_nfa_start_prefix_with_candidate_cap(
        exact,
        MAX_NATIVE_ORDERED_NFA_GUARDED_UNICODE_PREFIX_CANDIDATE_BYTES,
    )?
    else {
        return Ok(None);
    };
    if native_ordered_nfa_start_prefix_intersects_utf8_continuation(plan) {
        return Ok(None);
    }
    Ok(Some(plan))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "instruction and edge indices are checked against the authenticated program and graph extents"
)]
fn validate_native_ordered_nfa_start_closure(
    program: NativeEpsilonClosureProgramView<'_>,
    raw: &RawPlan,
    assertion_kinds: u32,
) -> Result<Option<NativeOrderedNfaStartClosureLayout>, ObjectError> {
    let instruction_count = program.len();
    if instruction_count == 0 {
        return Err(ObjectError::InvalidModule(
            "ordered-NFA start closure is empty",
        ));
    }
    if instruction_count > MAX_NATIVE_ORDERED_NFA_START_CLOSURE_INSTRUCTIONS {
        return Ok(None);
    }
    let first = program.instruction(0).ok_or(ObjectError::InvalidModule(
        "ordered-NFA start closure first instruction",
    ))?;
    if first.state() != raw.start || first.subtree_end() != instruction_count || first.guard() != 0
    {
        return Err(ObjectError::InvalidModule("ordered-NFA start closure root"));
    }

    let edges = raw.edge_targets.len();
    let guarded = program.is_guarded();
    let mut split_edge_visits = 0_usize;
    for instruction_index in 0..instruction_count {
        let instruction =
            program
                .instruction(instruction_index)
                .ok_or(ObjectError::InvalidModule(
                    "ordered-NFA start closure instruction extent",
                ))?;
        let subtree_end = instruction.subtree_end();
        if subtree_end <= instruction_index || subtree_end > instruction_count {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA start closure subtree",
            ));
        }
        let state = usize::try_from(instruction.state())
            .map_err(|_| ObjectError::InvalidModule("ordered-NFA start closure state encoding"))?;
        let role = raw
            .roles
            .get(state)
            .copied()
            .ok_or(ObjectError::InvalidModule(
                "ordered-NFA start closure state bounds",
            ))?;
        let edge_begin = raw
            .edge_offsets
            .get(state)
            .copied()
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(ObjectError::InvalidModule(
                "ordered-NFA start closure edge begin",
            ))?;
        let edge_end = raw
            .edge_offsets
            .get(state.checked_add(1).ok_or(ObjectError::ArithmeticOverflow(
                "ordered-NFA start closure state successor",
            ))?)
            .copied()
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(ObjectError::InvalidModule(
                "ordered-NFA start closure edge end",
            ))?;
        if edge_begin > edge_end || edge_end > edges {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA start closure edge bounds",
            ));
        }
        let degree = edge_end - edge_begin;

        if guarded {
            let guard = instruction.guard();
            if guard > 18
                || (guard != 0 && assertion_kinds & (1_u32 << guard.saturating_sub(1)) == 0)
            {
                return Err(ObjectError::InvalidModule(
                    "ordered-NFA start closure guard",
                ));
            }
        } else if instruction.guard() != 0 {
            return Err(ObjectError::InvalidModule(
                "plain ordered-NFA start closure has a guard",
            ));
        }

        match instruction.action() {
            NativeEpsilonClosureAction::Split => {
                if role != StateRole::Split {
                    return Err(ObjectError::InvalidModule(
                        "ordered-NFA start closure Split role",
                    ));
                }
                split_edge_visits = split_edge_visits.checked_add(degree).ok_or(
                    ObjectError::ArithmeticOverflow("ordered-NFA start closure Split-edge visits"),
                )?;
                if split_edge_visits > MAX_NATIVE_ORDERED_NFA_START_CLOSURE_SPLIT_EDGE_VISITS {
                    return Ok(None);
                }
                if guarded {
                    if raw.edge_kinds[edge_begin..edge_end].contains(&EdgeKind::ByteRange) {
                        return Err(ObjectError::InvalidModule(
                            "guarded ordered-NFA start closure consuming Split edge",
                        ));
                    }
                } else if instruction.edge_work()
                    != u32::try_from(degree).map_err(|_| {
                        ObjectError::InvalidModule(
                            "plain ordered-NFA start closure edge-work encoding",
                        )
                    })?
                    || raw.edge_kinds[edge_begin..edge_end]
                        .iter()
                        .any(|&kind| kind != EdgeKind::Epsilon)
                {
                    return Err(ObjectError::InvalidModule(
                        "plain ordered-NFA start closure Split row",
                    ));
                }
            }
            NativeEpsilonClosureAction::Consume => {
                if role != StateRole::Consume
                    || instruction.edge_work() != 0
                    || subtree_end != instruction_index + 1
                {
                    return Err(ObjectError::InvalidModule(
                        "ordered-NFA start closure Consume instruction",
                    ));
                }
            }
            NativeEpsilonClosureAction::Accept => {
                if role != StateRole::Accept
                    || instruction.edge_work() != 0
                    || subtree_end != instruction_index + 1
                {
                    return Err(ObjectError::InvalidModule(
                        "ordered-NFA start closure Accept instruction",
                    ));
                }
            }
            NativeEpsilonClosureAction::SeenBackedge => {
                if role != StateRole::Split
                    || instruction.edge_work() != 0
                    || subtree_end != instruction_index + 1
                {
                    return Err(ObjectError::InvalidModule(
                        "ordered-NFA start closure backedge instruction",
                    ));
                }
            }
        }
    }
    if split_edge_visits.checked_add(1) != Some(instruction_count) {
        return Err(ObjectError::InvalidModule(
            "ordered-NFA start closure edge/instruction receipt",
        ));
    }
    Ok(Some(NativeOrderedNfaStartClosureLayout {
        guarded,
        instruction_count,
        split_edge_visits,
    }))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "canonical dispatch validation keeps its dependent bounds and encoding invariants in one fail-closed transaction"
)]
fn validate_native_ordered_edge_dispatch(
    view: NativeOrderedEdgeDispatchView<'_>,
    raw: &RawPlan,
    states: usize,
    edges: usize,
) -> Result<NativeOrderedEdgeDispatchShape, ObjectError> {
    if view.state_count() != states {
        return Err(ObjectError::InvalidModule(
            "ordered-edge dispatch state count",
        ));
    }
    let byte_map = view.segment_by_byte();
    if byte_map.is_empty() || !byte_map.len().is_multiple_of(256) {
        return Err(ObjectError::InvalidModule(
            "ordered-edge dispatch byte-map extent",
        ));
    }
    let admitted_rows = byte_map.len() / 256;
    if view.admitted_rows() != admitted_rows {
        return Err(ObjectError::InvalidModule(
            "ordered-edge dispatch admitted-row count",
        ));
    }
    let metadata = view.segment_metadata();
    let transitions = view.transitions();
    let (encoding, target_mask) = match transitions {
        NativeOrderedEdgeTransitions::Direct32 { target_bits, .. } => {
            if target_bits > 31 {
                return Err(ObjectError::InvalidModule(
                    "ordered-edge dispatch direct32 target width",
                ));
            }
            let target_mask = if target_bits == 0 {
                0
            } else {
                (1_u32 << target_bits) - 1
            };
            (
                NativeOrderedEdgeEncoding::Direct32 { target_bits },
                target_mask,
            )
        }
        NativeOrderedEdgeTransitions::Direct64(_) => {
            (NativeOrderedEdgeEncoding::Direct64, u32::MAX)
        }
        NativeOrderedEdgeTransitions::Legacy(_) => (NativeOrderedEdgeEncoding::Legacy, u32::MAX),
    };
    let transition_count = transitions.len();
    if transition_count == 0 || metadata.is_empty() {
        return Err(ObjectError::InvalidModule(
            "ordered-edge dispatch empty canonical payload",
        ));
    }
    let copied_payload_bytes = states
        .checked_mul(8)
        .and_then(|bytes| bytes.checked_add(byte_map.len()))
        .and_then(|bytes| {
            metadata
                .len()
                .checked_mul(4)
                .and_then(|metadata_bytes| bytes.checked_add(metadata_bytes))
        })
        .and_then(|bytes| {
            transition_count
                .checked_mul(encoding.entry_bytes())
                .and_then(|transition_bytes| bytes.checked_add(transition_bytes))
        })
        .ok_or(ObjectError::ArithmeticOverflow(
            "ordered-edge dispatch copied payload receipt",
        ))?;
    if copied_payload_bytes > view.retained_bytes() {
        return Err(ObjectError::InvalidModule(
            "ordered-edge dispatch retained-byte receipt",
        ));
    }

    let mut present_rows = 0_usize;
    let mut expected_degree_index = 0_usize;
    let mut expected_transition = 0_usize;
    for state in 0..states {
        let Some(row) = view.row(state) else {
            continue;
        };
        if present_rows >= admitted_rows
            || raw.roles[state] != StateRole::Consume
            || usize::try_from(row.row_ordinal()).ok() != Some(present_rows)
            || usize::try_from(row.segment_base()).ok() != expected_degree_index.checked_add(1)
            || row.last_segment() >= 256
            || row.target_bits() != encoding.target_bits()
        {
            return Err(ObjectError::InvalidModule(
                "ordered-edge dispatch row descriptor",
            ));
        }
        let row_ordinal = present_rows;
        let segment_base = usize::try_from(row.segment_base()).unwrap();
        let segment_count = usize::try_from(row.last_segment()).unwrap() + 1;
        let segment_end =
            segment_base
                .checked_add(segment_count)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "ordered-edge dispatch segment extent",
                ))?;
        if segment_end > metadata.len() {
            return Err(ObjectError::InvalidModule(
                "ordered-edge dispatch segment metadata bounds",
            ));
        }
        let edge_start = usize::try_from(raw.edge_offsets[state]).unwrap();
        let edge_end = usize::try_from(raw.edge_offsets[state + 1]).unwrap();
        let degree = edge_end
            .checked_sub(edge_start)
            .ok_or(ObjectError::InvalidModule(
                "ordered-edge dispatch source row order",
            ))?;
        if metadata
            .get(expected_degree_index)
            .and_then(|&value| usize::try_from(value).ok())
            != Some(degree)
        {
            return Err(ObjectError::InvalidModule(
                "ordered-edge dispatch row degree",
            ));
        }
        let map_start = row_ordinal
            .checked_mul(256)
            .ok_or(ObjectError::ArithmeticOverflow(
                "ordered-edge dispatch byte-map row",
            ))?;
        let map_end = map_start
            .checked_add(256)
            .ok_or(ObjectError::ArithmeticOverflow(
                "ordered-edge dispatch byte-map extent",
            ))?;
        let Some(map) = byte_map.get(map_start..map_end) else {
            return Err(ObjectError::InvalidModule(
                "ordered-edge dispatch byte-map bounds",
            ));
        };
        if map.first().copied() != Some(0)
            || map
                .windows(2)
                .any(|pair| pair[1] < pair[0] || pair[1] > pair[0].saturating_add(1))
            || map
                .last()
                .is_none_or(|&segment| u32::from(segment) != row.last_segment())
        {
            return Err(ObjectError::InvalidModule(
                "ordered-edge dispatch byte-map segment",
            ));
        }
        for local_segment in 0..segment_count {
            let segment_index = segment_base + local_segment;
            let begin = usize::try_from(metadata[segment_index]).unwrap();
            let end = if local_segment + 1 < segment_count {
                usize::try_from(metadata[segment_index + 1]).unwrap()
            } else if row_ordinal + 1 < admitted_rows {
                let next_row_first =
                    segment_index
                        .checked_add(2)
                        .ok_or(ObjectError::ArithmeticOverflow(
                            "ordered-edge dispatch next-row segment",
                        ))?;
                let Some(&next) = metadata.get(next_row_first) else {
                    return Err(ObjectError::InvalidModule(
                        "ordered-edge dispatch next-row metadata",
                    ));
                };
                usize::try_from(next).unwrap()
            } else {
                transition_count
            };
            if begin != expected_transition || begin > end || end > transition_count {
                return Err(ObjectError::InvalidModule(
                    "ordered-edge dispatch transition interval",
                ));
            }
            expected_transition = end;
        }
        expected_degree_index = segment_end;
        present_rows += 1;
    }
    if present_rows != admitted_rows
        || expected_degree_index != metadata.len()
        || expected_transition != transition_count
    {
        return Err(ObjectError::InvalidModule(
            "ordered-edge dispatch canonical coverage",
        ));
    }
    match transitions {
        NativeOrderedEdgeTransitions::Direct32 { transitions, .. } => {
            for &transition in transitions {
                let encoded = transition.compiler_private_encoded();
                let target = encoded & target_mask;
                let work = encoded >> encoding.target_bits();
                if usize::try_from(target)
                    .ok()
                    .is_none_or(|target| target >= states)
                    || work == 0
                {
                    return Err(ObjectError::InvalidModule(
                        "ordered-edge dispatch direct32 transition",
                    ));
                }
            }
        }
        NativeOrderedEdgeTransitions::Direct64(transitions) => {
            for &transition in transitions {
                let encoded = transition.compiler_private_encoded();
                let target = u32::try_from(encoded & u64::from(u32::MAX)).unwrap();
                let work = u32::try_from(encoded >> 32).unwrap();
                if usize::try_from(target)
                    .ok()
                    .is_none_or(|target| target >= states)
                    || work == 0
                {
                    return Err(ObjectError::InvalidModule(
                        "ordered-edge dispatch direct64 transition",
                    ));
                }
            }
        }
        NativeOrderedEdgeTransitions::Legacy(edge_ordinals) => {
            for &edge in edge_ordinals {
                let Some(&target) = usize::try_from(edge)
                    .ok()
                    .and_then(|edge| raw.edge_targets.get(edge))
                else {
                    return Err(ObjectError::InvalidModule(
                        "ordered-edge dispatch legacy transition",
                    ));
                };
                if usize::try_from(target)
                    .ok()
                    .is_none_or(|target| target >= states)
                    || usize::try_from(edge).ok().is_none_or(|edge| edge >= edges)
                {
                    return Err(ObjectError::InvalidModule(
                        "ordered-edge dispatch legacy target",
                    ));
                }
            }
        }
    }
    Ok(NativeOrderedEdgeDispatchShape {
        admitted_rows,
        metadata_count: metadata.len(),
        transition_count,
        encoding,
    })
}

impl<'a> NativeOrderedNfaObjectImage<'a> {
    /// Revalidate the separately retained compiler-only terminal bitmap during
    /// backend lowering. The ordinary entry deliberately ignores valid words,
    /// while the module receipt may later supply them to aggregate wrappers;
    /// malformed words and a forged overlap with V3 still fail closed.
    pub(crate) fn terminal_exact_set_plan(
        &self,
    ) -> Result<Option<NativeOrderedNfaTerminalExactSetPlan>, ObjectError> {
        let Some(exact) = self.terminal_exact_set_words else {
            return Ok(None);
        };
        if self.layout.terminal_range.is_some() {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA terminal exact-set overlaps terminal range",
            ));
        }
        validate_native_ordered_nfa_terminal_exact_set(exact, self.layout.edge_count).map(Some)
    }

    /// Borrow one state's already-encoded canonical edge-kind row from the
    /// object image. This is a compiler-only convenience for guarded start
    /// specialization and does not expose source storage to target code.
    pub(crate) fn encoded_edge_kinds_for_state(&self, state: u32) -> Option<&[u8]> {
        let state = usize::try_from(state).ok()?;
        if state >= self.layout.state_count {
            return None;
        }
        let read_offset = |index: usize| {
            let begin = self
                .layout
                .edge_offsets_offset
                .checked_add(index.checked_mul(4)?)?;
            let end = begin.checked_add(4)?;
            self.bytes
                .get(begin..end)?
                .try_into()
                .ok()
                .map(u32::from_le_bytes)
                .and_then(|value| usize::try_from(value).ok())
        };
        let begin = read_offset(state)?;
        let end = read_offset(state.checked_add(1)?)?;
        if begin > end || end > self.layout.edge_count {
            return None;
        }
        let kinds_begin = self.layout.edge_kinds_offset.checked_add(begin)?;
        let kinds_end = self.layout.edge_kinds_offset.checked_add(end)?;
        self.bytes.get(kinds_begin..kinds_end)
    }

    /// Build one canonical, relocation-free graph image. Numeric/structural or
    /// caller-cap refusal is soft; host allocation failure remains explicit.
    #[allow(
        dead_code,
        reason = "compatibility wrapper retained for existing internal and test callers"
    )]
    pub(crate) fn try_build(
        view: NativeOrderedNfaProgramView<'a>,
        max_object_bytes: usize,
    ) -> Result<Option<Self>, ObjectError> {
        Ok(match Self::try_build_reported(view, max_object_bytes)? {
            NativeOrderedNfaObjectImageBuild::Built(image) => Some(image),
            NativeOrderedNfaObjectImageBuild::Unsupported
            | NativeOrderedNfaObjectImageBuild::DataLimit { .. } => None,
        })
    }

    /// Report the exact numeric image ceiling separately from structural
    /// ineligibility while preserving allocation and malformed-input errors.
    pub(crate) fn try_build_reported(
        view: NativeOrderedNfaProgramView<'a>,
        max_object_bytes: usize,
    ) -> Result<NativeOrderedNfaObjectImageBuild<'a>, ObjectError> {
        let mut limits =
            FrozenOrderedNfaLimitsV1::new(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES);
        limits.max_descriptor_bytes = FROZEN_ORDERED_NFA_V1_MAX_DESCRIPTOR_BYTES;
        let Some(shape) = validate_ordered_nfa_shape(view, limits) else {
            return Ok(NativeOrderedNfaObjectImageBuild::Unsupported);
        };
        let raw = view.raw;
        let states = shape.states;
        let edges = shape.edges;
        let mut assertion_kinds = 0_u32;
        let mut assertion_edges = 0_usize;
        for &kind in raw.edge_kinds.iter() {
            if kind != EdgeKind::Epsilon && kind != EdgeKind::ByteRange {
                assertion_edges =
                    assertion_edges
                        .checked_add(1)
                        .ok_or(ObjectError::ArithmeticOverflow(
                            "ordered-NFA assertion edge count",
                        ))?;
                assertion_kinds |= assertion_bit(kind)
                    .ok_or(ObjectError::InvalidModule("ordered-NFA assertion encoding"))?;
            }
        }
        if assertion_kinds & !ORDERED_NFA_OBJECT_V1_ASSERTION_MASK != 0 {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA assertion mask exceeds object ABI",
            ));
        }
        let start_closure_dispatch = match view.start_closure_dispatch {
            Some(program) => {
                validate_native_ordered_nfa_start_closure(program, raw, assertion_kinds)?
            }
            None => None,
        };
        let start_closure_program = start_closure_dispatch.and(view.start_closure_dispatch);
        let start_prefix = match (
            view.start_closure_dispatch,
            start_closure_dispatch,
            view.start_prefix_first_set,
        ) {
            (Some(_), Some(receipt), Some(exact))
                if receipt.instruction_count
                    >= MIN_NATIVE_ORDERED_NFA_START_PREFIX_CLOSURE_INSTRUCTIONS =>
            {
                derive_native_ordered_nfa_start_prefix(exact)?
            }
            (None, None, Some(exact)) => {
                derive_native_ordered_nfa_guarded_unicode_start_prefix(raw, exact)?
            }
            _ => None,
        };
        let whole_window_width_bounds = match view.whole_window_width_bounds {
            Some(bounds) if bounds.minimum <= bounds.maximum => Some(bounds),
            Some(_) => {
                return Err(ObjectError::InvalidModule(
                    "ordered-NFA whole-window width bounds are inverted",
                ));
            }
            None => None,
        };
        let cache_boundary_assertions =
            boundary_assertion_cache_is_profitable(assertion_edges, assertion_kinds)
                || start_closure_dispatch.is_some_and(|layout| layout.guarded);
        let terminal_exact_set_words = match view.terminal_exact_set {
            Some(exact) => {
                validate_native_ordered_nfa_terminal_exact_set(exact, edges)?;
                Some(exact)
            }
            None => None,
        };
        let terminal_range = view
            .terminal_range
            .map(|range| validate_native_ordered_nfa_terminal_range(range, edges))
            .transpose()?;
        if terminal_exact_set_words.is_some() && terminal_range.is_some() {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA terminal exact-set overlaps terminal range",
            ));
        }
        let has_unicode = assertion_kinds & ORDERED_NFA_OBJECT_V1_UNICODE_ASSERTION_MASK != 0;
        let align4 =
            |value: usize| {
                value.checked_add(3).map(|rounded| rounded & !3).ok_or(
                    ObjectError::ArithmeticOverflow("ordered-NFA object alignment"),
                )
            };
        let roles_offset = ORDERED_NFA_OBJECT_V1_DESCRIPTOR_BYTES;
        let edge_offsets_offset = align4(
            roles_offset
                .checked_add(states)
                .ok_or(ObjectError::ArithmeticOverflow("ordered-NFA roles extent"))?,
        )?;
        let edge_targets_offset = edge_offsets_offset
            .checked_add(
                states
                    .checked_add(1)
                    .and_then(|count| count.checked_mul(4))
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "ordered-NFA edge-offset extent",
                    ))?,
            )
            .ok_or(ObjectError::ArithmeticOverflow(
                "ordered-NFA edge-target offset",
            ))?;
        let edge_kinds_offset = edge_targets_offset
            .checked_add(edges.checked_mul(4).ok_or(ObjectError::ArithmeticOverflow(
                "ordered-NFA edge-target extent",
            ))?)
            .ok_or(ObjectError::ArithmeticOverflow(
                "ordered-NFA edge-kind offset",
            ))?;
        let byte_starts_offset =
            edge_kinds_offset
                .checked_add(edges)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "ordered-NFA byte-start offset",
                ))?;
        let byte_ends_offset =
            byte_starts_offset
                .checked_add(edges)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "ordered-NFA byte-end offset",
                ))?;
        let graph_end = byte_ends_offset
            .checked_add(edges)
            .ok_or(ObjectError::ArithmeticOverflow("ordered-NFA graph extent"))?;
        let ranges = UnicodeLookMatcher::perl_word_ranges_v16();
        let (unicode_ranges_offset, unicode_range_count, base_object_bytes) = if has_unicode {
            let offset = align4(graph_end)?;
            let bytes = ranges
                .len()
                .checked_mul(usize::try_from(ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_STRIDE).unwrap())
                .and_then(|bytes| offset.checked_add(bytes))
                .ok_or(ObjectError::ArithmeticOverflow(
                    "ordered-NFA Unicode range extent",
                ))?;
            (Some(offset), ranges.len(), bytes)
        } else {
            (None, 0, graph_end)
        };
        if base_object_bytes > FROZEN_ORDERED_NFA_V1_MAX_DESCRIPTOR_BYTES {
            return Ok(NativeOrderedNfaObjectImageBuild::Unsupported);
        }
        let dispatch_shape = view
            .ordered_edge_dispatch
            .map(|dispatch| validate_native_ordered_edge_dispatch(dispatch, raw, states, edges))
            .transpose()?;
        let mut ordered_edge_dispatch =
            if let Some(shape) = dispatch_shape {
                let align8 = |value: usize| {
                    value.checked_add(7).map(|rounded| rounded & !7).ok_or(
                        ObjectError::ArithmeticOverflow("ordered-edge dispatch alignment"),
                    )
                };
                let descriptor_offset = align8(base_object_bytes)?;
                let rows_offset = descriptor_offset
                    .checked_add(ORDERED_NFA_EDGE_DISPATCH_V1_DESCRIPTOR_BYTES)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "ordered-edge dispatch row offset",
                    ))?;
                let byte_map_offset =
                    rows_offset
                        .checked_add(states.checked_mul(8).ok_or(
                            ObjectError::ArithmeticOverflow("ordered-edge dispatch row extent"),
                        )?)
                        .ok_or(ObjectError::ArithmeticOverflow(
                            "ordered-edge dispatch byte-map offset",
                        ))?;
                let metadata_offset = byte_map_offset
                    .checked_add(shape.admitted_rows.checked_mul(256).ok_or(
                        ObjectError::ArithmeticOverflow("ordered-edge dispatch byte-map extent"),
                    )?)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "ordered-edge dispatch metadata offset",
                    ))?;
                let transition_unaligned = metadata_offset
                    .checked_add(shape.metadata_count.checked_mul(4).ok_or(
                        ObjectError::ArithmeticOverflow("ordered-edge dispatch metadata extent"),
                    )?)
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "ordered-edge dispatch transition offset",
                    ))?;
                let transitions_offset = if shape.encoding.entry_bytes() == 8 {
                    align8(transition_unaligned)?
                } else {
                    align4(transition_unaligned)?
                };
                let object_bytes = transitions_offset
                    .checked_add(
                        shape
                            .transition_count
                            .checked_mul(shape.encoding.entry_bytes())
                            .ok_or(ObjectError::ArithmeticOverflow(
                                "ordered-edge dispatch transition extent",
                            ))?,
                    )
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "ordered-edge dispatch object extent",
                    ))?;
                Some((
                    NativeOrderedEdgeDispatchLayout {
                        descriptor_offset,
                        rows_offset,
                        byte_map_offset,
                        metadata_offset,
                        transitions_offset,
                        admitted_rows: shape.admitted_rows,
                        metadata_count: shape.metadata_count,
                        transition_count: shape.transition_count,
                        encoding: shape.encoding,
                    },
                    object_bytes,
                ))
            } else {
                None
            };
        if ordered_edge_dispatch.is_some_and(|(_, extended_bytes)| {
            extended_bytes > max_object_bytes || u32::try_from(extended_bytes).is_err()
        }) {
            // The sidecar is an optional native accelerator. Omitting it is
            // all-or-nothing and preserves the exact scalar graph extent;
            // an independent descriptor-tail terminal proof may still select
            // V3 under a cap between the two extents.
            ordered_edge_dispatch = None;
        }
        let object_bytes = ordered_edge_dispatch.map_or(base_object_bytes, |(_, bytes)| bytes);
        if object_bytes > max_object_bytes {
            return Ok(NativeOrderedNfaObjectImageBuild::DataLimit {
                required: object_bytes,
            });
        }
        if u32::try_from(object_bytes).is_err()
            || u32::try_from(states).is_err()
            || u32::try_from(edges).is_err()
            || u32::try_from(shape.closure_slots).is_err()
            || u32::try_from(shape.zero_width_edges).is_err()
            || u32::try_from(unicode_range_count).is_err()
        {
            return Ok(NativeOrderedNfaObjectImageBuild::Unsupported);
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(object_bytes)
            .map_err(|_| ObjectError::Allocation("ordered-NFA object image"))?;
        bytes.resize(object_bytes, 0);
        let put_u32 = |image: &mut [u8], offset: usize, value: u32| {
            image
                .get_mut(offset..offset + 4)
                .ok_or(ObjectError::InvalidModule("ordered-NFA u32 object field"))?
                .copy_from_slice(&value.to_le_bytes());
            Ok::<(), ObjectError>(())
        };
        let put_u64 = |image: &mut [u8], offset: usize, value: u64| {
            image
                .get_mut(offset..offset + 8)
                .ok_or(ObjectError::InvalidModule("ordered-NFA u64 object field"))?
                .copy_from_slice(&value.to_le_bytes());
            Ok::<(), ObjectError>(())
        };
        let (ready_seal, magic, abi_version, known_flags) = if terminal_range.is_some() {
            (
                ORDERED_NFA_OBJECT_V3_READY_SEAL,
                ORDERED_NFA_OBJECT_V3_MAGIC,
                ORDERED_NFA_OBJECT_V3_ABI_VERSION,
                ORDERED_NFA_OBJECT_V3_KNOWN_FLAGS,
            )
        } else if ordered_edge_dispatch.is_some() {
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
        put_u64(&mut bytes, 8, magic)?;
        put_u32(&mut bytes, 16, abi_version)?;
        put_u32(&mut bytes, 20, !abi_version)?;
        put_u32(&mut bytes, 24, u32::try_from(object_bytes).unwrap())?;
        put_u32(
            &mut bytes,
            28,
            ordered_nfa_object_flags(
                has_unicode,
                ordered_edge_dispatch.is_some(),
                terminal_range.is_some(),
            ),
        )?;
        bytes[ORDERED_NFA_OBJECT_V1_IDENTITY_OFFSET..ORDERED_NFA_OBJECT_V1_IDENTITY_OFFSET + 32]
            .copy_from_slice(&view.artifact_identity);
        for (field, value) in [
            (ORDERED_NFA_OBJECT_V1_ROLES_OFFSET_FIELD, roles_offset),
            (
                ORDERED_NFA_OBJECT_V1_EDGE_OFFSETS_OFFSET_FIELD,
                edge_offsets_offset,
            ),
            (
                ORDERED_NFA_OBJECT_V1_EDGE_TARGETS_OFFSET_FIELD,
                edge_targets_offset,
            ),
            (
                ORDERED_NFA_OBJECT_V1_EDGE_KINDS_OFFSET_FIELD,
                edge_kinds_offset,
            ),
            (
                ORDERED_NFA_OBJECT_V1_BYTE_STARTS_OFFSET_FIELD,
                byte_starts_offset,
            ),
            (
                ORDERED_NFA_OBJECT_V1_BYTE_ENDS_OFFSET_FIELD,
                byte_ends_offset,
            ),
            (
                ORDERED_NFA_OBJECT_V1_UNICODE_RANGES_OFFSET_FIELD,
                unicode_ranges_offset.unwrap_or(0),
            ),
        ] {
            put_u32(&mut bytes, field, u32::try_from(value).unwrap())?;
        }
        put_u32(
            &mut bytes,
            ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_COUNT_FIELD,
            u32::try_from(unicode_range_count).unwrap(),
        )?;
        put_u32(
            &mut bytes,
            ORDERED_NFA_OBJECT_V1_STATE_COUNT_FIELD,
            u32::try_from(states).unwrap(),
        )?;
        put_u32(
            &mut bytes,
            ORDERED_NFA_OBJECT_V1_EDGE_COUNT_FIELD,
            u32::try_from(edges).unwrap(),
        )?;
        put_u32(
            &mut bytes,
            ORDERED_NFA_OBJECT_V1_ZERO_WIDTH_EDGE_COUNT_FIELD,
            u32::try_from(shape.zero_width_edges).unwrap(),
        )?;
        put_u32(
            &mut bytes,
            ORDERED_NFA_OBJECT_V1_CLOSURE_SLOTS_FIELD,
            u32::try_from(shape.closure_slots).unwrap(),
        )?;
        put_u32(
            &mut bytes,
            ORDERED_NFA_OBJECT_V1_START_STATE_FIELD,
            raw.start,
        )?;
        put_u32(
            &mut bytes,
            ORDERED_NFA_OBJECT_V1_ASSERTION_KINDS_FIELD,
            assertion_kinds,
        )?;
        put_u32(
            &mut bytes,
            ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_STRIDE_FIELD,
            if has_unicode {
                ORDERED_NFA_OBJECT_V1_UNICODE_RANGE_STRIDE
            } else {
                0
            },
        )?;
        bytes[ORDERED_NFA_OBJECT_V1_LINE_TERMINATOR_FIELD] = view.line_terminator;
        if let Some(range) = terminal_range {
            bytes[ORDERED_NFA_OBJECT_V3_TERMINAL_RANGE_START_FIELD] = range.start;
            bytes[ORDERED_NFA_OBJECT_V3_TERMINAL_RANGE_END_FIELD] = range.end;
            bytes[ORDERED_NFA_OBJECT_V3_TERMINAL_RANGE_REVERSE_DEPTH_FIELD] = range.reverse_depth;
        }

        for (index, &role) in raw.roles.iter().enumerate() {
            bytes[roles_offset + index] = encode_role(role).ok_or(ObjectError::InvalidModule(
                "ordered-NFA object role encoding",
            ))?;
        }
        for (index, &value) in raw.edge_offsets.iter().enumerate() {
            put_u32(&mut bytes, edge_offsets_offset + index * 4, value)?;
        }
        for (index, &value) in raw.edge_targets.iter().enumerate() {
            put_u32(&mut bytes, edge_targets_offset + index * 4, value)?;
        }
        for (index, &kind) in raw.edge_kinds.iter().enumerate() {
            bytes[edge_kinds_offset + index] = encode_edge_kind(kind).ok_or(
                ObjectError::InvalidModule("ordered-NFA object edge encoding"),
            )?;
        }
        bytes[byte_starts_offset..byte_starts_offset + edges].copy_from_slice(&raw.byte_starts);
        bytes[byte_ends_offset..byte_ends_offset + edges].copy_from_slice(&raw.byte_ends);
        if let Some(offset) = unicode_ranges_offset {
            for (index, &(start, end)) in ranges.iter().enumerate() {
                let range = offset + index * 8;
                put_u32(&mut bytes, range, u32::from(start))?;
                put_u32(&mut bytes, range + 4, u32::from(end))?;
            }
        }
        #[allow(
            clippy::arithmetic_side_effects,
            reason = "V2 sidecar offsets and extents were checked while constructing the selected layout"
        )]
        let ordered_edge_dispatch = if let Some((layout, _)) = ordered_edge_dispatch {
            let dispatch = view
                .ordered_edge_dispatch
                .ok_or(ObjectError::InvalidModule(
                    "ordered-edge dispatch layout without source view",
                ))?;
            for (field, value) in [
                (
                    ORDERED_NFA_EDGE_DISPATCH_V1_ROWS_OFFSET_FIELD,
                    layout.rows_offset,
                ),
                (
                    ORDERED_NFA_EDGE_DISPATCH_V1_BYTE_MAP_OFFSET_FIELD,
                    layout.byte_map_offset,
                ),
                (
                    ORDERED_NFA_EDGE_DISPATCH_V1_METADATA_OFFSET_FIELD,
                    layout.metadata_offset,
                ),
                (
                    ORDERED_NFA_EDGE_DISPATCH_V1_TRANSITIONS_OFFSET_FIELD,
                    layout.transitions_offset,
                ),
                (
                    ORDERED_NFA_EDGE_DISPATCH_V1_ADMITTED_ROWS_FIELD,
                    layout.admitted_rows,
                ),
                (
                    ORDERED_NFA_EDGE_DISPATCH_V1_METADATA_COUNT_FIELD,
                    layout.metadata_count,
                ),
                (
                    ORDERED_NFA_EDGE_DISPATCH_V1_TRANSITION_COUNT_FIELD,
                    layout.transition_count,
                ),
            ] {
                put_u32(
                    &mut bytes,
                    layout.descriptor_offset + field,
                    u32::try_from(value).unwrap(),
                )?;
            }
            put_u32(
                &mut bytes,
                layout.descriptor_offset + ORDERED_NFA_EDGE_DISPATCH_V1_CONTROL_FIELD,
                layout.encoding.control(),
            )?;
            for state in 0..states {
                let words = dispatch.row(state).map_or(
                    [u32::MAX, 0],
                    fre_automata::NativeOrderedEdgeRowDescriptor::compiler_private_encoded,
                );
                put_u32(&mut bytes, layout.rows_offset + state * 8, words[0])?;
                put_u32(&mut bytes, layout.rows_offset + state * 8 + 4, words[1])?;
            }
            let byte_map = dispatch.segment_by_byte();
            bytes[layout.byte_map_offset..layout.byte_map_offset + byte_map.len()]
                .copy_from_slice(byte_map);
            for (index, &value) in dispatch.segment_metadata().iter().enumerate() {
                put_u32(&mut bytes, layout.metadata_offset + index * 4, value)?;
            }
            match dispatch.transitions() {
                NativeOrderedEdgeTransitions::Direct32 { transitions, .. } => {
                    for (index, &transition) in transitions.iter().enumerate() {
                        put_u32(
                            &mut bytes,
                            layout.transitions_offset + index * 4,
                            transition.compiler_private_encoded(),
                        )?;
                    }
                }
                NativeOrderedEdgeTransitions::Direct64(transitions) => {
                    for (index, &transition) in transitions.iter().enumerate() {
                        put_u64(
                            &mut bytes,
                            layout.transitions_offset + index * 8,
                            transition.compiler_private_encoded(),
                        )?;
                    }
                }
                NativeOrderedEdgeTransitions::Legacy(edges) => {
                    for (index, &edge) in edges.iter().enumerate() {
                        put_u32(&mut bytes, layout.transitions_offset + index * 4, edge)?;
                    }
                }
            }
            Some(layout)
        } else {
            None
        };
        if ordered_nfa_object_flags(
            has_unicode,
            ordered_edge_dispatch.is_some(),
            terminal_range.is_some(),
        ) & !known_flags
            != 0
        {
            return Err(ObjectError::InvalidModule(
                "ordered-NFA object flags exceed selected ABI",
            ));
        }
        put_u64(&mut bytes, 0, ready_seal)?;
        let layout = NativeOrderedNfaObjectLayout {
            object_bytes,
            roles_offset,
            edge_offsets_offset,
            edge_targets_offset,
            edge_kinds_offset,
            byte_starts_offset,
            byte_ends_offset,
            unicode_ranges_offset,
            unicode_range_count,
            state_count: states,
            edge_count: edges,
            zero_width_edge_count: shape.zero_width_edges,
            closure_slots: shape.closure_slots,
            start_state: raw.start,
            assertion_kinds,
            cache_boundary_assertions,
            start_closure_dispatch,
            start_prefix,
            whole_window_width_bounds,
            line_terminator: view.line_terminator,
            ordered_edge_dispatch,
            terminal_range,
        };
        Ok(NativeOrderedNfaObjectImageBuild::Built(Self {
            bytes,
            layout,
            terminal_exact_set_words,
            start_closure_program,
        }))
    }
}

/// One fixed-layout Pike thread. `start` preserves match provenance through
/// closure and byte consumption.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub struct FrozenOrderedNfaThreadV1 {
    state: u32,
    reserved: u32,
    start: usize,
}

/// Immutable authenticated graph descriptor. Generated code may read only
/// this record and its explicitly addressed SoA payloads, never Rust object
/// layout.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FrozenOrderedNfaDescriptorV1 {
    ready_seal: u64,
    magic: u64,
    abi_version: u32,
    abi_version_complement: u32,
    descriptor_bytes: usize,
    artifact_identity: [u8; 32],
    roles_address: usize,
    edge_offsets_address: usize,
    edge_targets_address: usize,
    edge_kinds_address: usize,
    byte_starts_address: usize,
    byte_ends_address: usize,
    state_count: u32,
    edge_count: u32,
    zero_width_edge_count: u32,
    closure_slots: u32,
    start_state: u32,
    assertion_kinds: u32,
    line_terminator: u8,
    reserved: [u8; 7],
}

/// Fixed-layout mutable workspace descriptor. Addresses and capacities are
/// write-once; only the final generation and logical lengths change during an
/// exclusive invocation.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FrozenOrderedNfaScratchV1 {
    ready_seal: u64,
    magic: u64,
    abi_version: u32,
    abi_version_complement: u32,
    scratch_bytes: usize,
    artifact_identity: [u8; 32],
    cache_identity: u64,
    seen_address: usize,
    current_address: usize,
    roots_address: usize,
    stack_address: usize,
    state_capacity: u32,
    root_capacity: u32,
    stack_capacity: u32,
    reserved: u32,
    generation: u64,
    current_len: usize,
    roots_len: usize,
    stack_len: usize,
    pending_start: usize,
    pending_end: usize,
    pending_valid: u32,
    control_reserved: u32,
}

/// Exact byte extent of [`FrozenOrderedNfaDescriptorV1`].
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_DESCRIPTOR_V1_BYTES: usize =
    std::mem::size_of::<FrozenOrderedNfaDescriptorV1>();
/// Exact byte extent of [`FrozenOrderedNfaScratchV1`].
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_SCRATCH_V1_BYTES: usize =
    std::mem::size_of::<FrozenOrderedNfaScratchV1>();
/// Exact byte extent of [`FrozenOrderedNfaThreadV1`].
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_THREAD_V1_BYTES: usize =
    std::mem::size_of::<FrozenOrderedNfaThreadV1>();

macro_rules! descriptor_offset {
    ($name:ident, $field:ident) => {
        #[doc(hidden)]
        pub const $name: usize = std::mem::offset_of!(FrozenOrderedNfaDescriptorV1, $field);
    };
}

descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_READY_SEAL_OFFSET,
    ready_seal
);
descriptor_offset!(FROZEN_ORDERED_NFA_DESCRIPTOR_V1_MAGIC_OFFSET, magic);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ABI_VERSION_OFFSET,
    abi_version
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ABI_VERSION_COMPLEMENT_OFFSET,
    abi_version_complement
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_BYTES_OFFSET,
    descriptor_bytes
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ARTIFACT_IDENTITY_OFFSET,
    artifact_identity
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ROLES_ADDRESS_OFFSET,
    roles_address
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_EDGE_OFFSETS_ADDRESS_OFFSET,
    edge_offsets_address
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_EDGE_TARGETS_ADDRESS_OFFSET,
    edge_targets_address
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_EDGE_KINDS_ADDRESS_OFFSET,
    edge_kinds_address
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_BYTE_STARTS_ADDRESS_OFFSET,
    byte_starts_address
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_BYTE_ENDS_ADDRESS_OFFSET,
    byte_ends_address
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_STATE_COUNT_OFFSET,
    state_count
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_EDGE_COUNT_OFFSET,
    edge_count
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ZERO_WIDTH_EDGE_COUNT_OFFSET,
    zero_width_edge_count
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_CLOSURE_SLOTS_OFFSET,
    closure_slots
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_START_STATE_OFFSET,
    start_state
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ASSERTION_KINDS_OFFSET,
    assertion_kinds
);
descriptor_offset!(
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_LINE_TERMINATOR_OFFSET,
    line_terminator
);

macro_rules! scratch_offset {
    ($name:ident, $field:ident) => {
        #[doc(hidden)]
        pub const $name: usize = std::mem::offset_of!(FrozenOrderedNfaScratchV1, $field);
    };
}

scratch_offset!(FROZEN_ORDERED_NFA_SCRATCH_V1_READY_SEAL_OFFSET, ready_seal);
scratch_offset!(FROZEN_ORDERED_NFA_SCRATCH_V1_MAGIC_OFFSET, magic);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION_OFFSET,
    abi_version
);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION_COMPLEMENT_OFFSET,
    abi_version_complement
);
scratch_offset!(FROZEN_ORDERED_NFA_SCRATCH_V1_BYTES_OFFSET, scratch_bytes);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_ARTIFACT_IDENTITY_OFFSET,
    artifact_identity
);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_CACHE_IDENTITY_OFFSET,
    cache_identity
);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_SEEN_ADDRESS_OFFSET,
    seen_address
);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_ADDRESS_OFFSET,
    current_address
);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_ADDRESS_OFFSET,
    roots_address
);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_ADDRESS_OFFSET,
    stack_address
);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_STATE_CAPACITY_OFFSET,
    state_capacity
);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_ROOT_CAPACITY_OFFSET,
    root_capacity
);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_CAPACITY_OFFSET,
    stack_capacity
);
scratch_offset!(FROZEN_ORDERED_NFA_SCRATCH_V1_GENERATION_OFFSET, generation);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_CURRENT_LEN_OFFSET,
    current_len
);
scratch_offset!(FROZEN_ORDERED_NFA_SCRATCH_V1_ROOTS_LEN_OFFSET, roots_len);
scratch_offset!(FROZEN_ORDERED_NFA_SCRATCH_V1_STACK_LEN_OFFSET, stack_len);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_START_OFFSET,
    pending_start
);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_END_OFFSET,
    pending_end
);
scratch_offset!(
    FROZEN_ORDERED_NFA_SCRATCH_V1_PENDING_VALID_OFFSET,
    pending_valid
);

/// Byte offsets inside one fixed-layout thread.
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_THREAD_V1_STATE_OFFSET: usize =
    std::mem::offset_of!(FrozenOrderedNfaThreadV1, state);
#[doc(hidden)]
pub const FROZEN_ORDERED_NFA_THREAD_V1_START_OFFSET: usize =
    std::mem::offset_of!(FrozenOrderedNfaThreadV1, start);

#[derive(Debug)]
struct FrozenOrderedNfaScratchStorageV1 {
    seen: Box<[u64]>,
    current: Box<[FrozenOrderedNfaThreadV1]>,
    roots: Box<[FrozenOrderedNfaThreadV1]>,
    stack: Box<[FrozenOrderedNfaThreadV1]>,
    descriptor: Box<FrozenOrderedNfaScratchV1>,
}

/// Pointer-stable mutable Pike workspace retained by an exclusive prepared
/// handle. The immutable graph is deliberately absent: generated code reads
/// its separately authenticated object-local descriptor and SoA tables.
///
/// Phase-one [`FrozenOrderedNfaStorageV1`] remains the compiler/test reference
/// owner. This is the only owner type that may be installed in a runtime
/// handle, so the handle receipt cannot accidentally omit retained graph
/// copies.
#[doc(hidden)]
#[derive(Debug)]
pub struct FrozenOrderedNfaPreparedScratchV1 {
    scratch: FrozenOrderedNfaScratchStorageV1,
    expected_artifact_identity: [u8; 32],
    expected_cache_identity: u64,
    accounting: FrozenOrderedNfaAccountingV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedOrderedNfaShapeV1 {
    states: usize,
    edges: usize,
    zero_width_edges: usize,
    closure_slots: usize,
    descriptor_bytes: usize,
    scratch_bytes: usize,
    setup_work: u64,
}

/// Pointer-stable ownership for one immutable graph and its exclusive bounded
/// Pike workspace.
#[doc(hidden)]
#[derive(Debug)]
pub struct FrozenOrderedNfaStorageV1 {
    roles: Box<[u8]>,
    edge_offsets: Box<[u32]>,
    edge_targets: Box<[u32]>,
    edge_kinds: Box<[u8]>,
    byte_starts: Box<[u8]>,
    byte_ends: Box<[u8]>,
    scratch: FrozenOrderedNfaScratchStorageV1,
    descriptor: Box<FrozenOrderedNfaDescriptorV1>,
    expected_cache_identity: u64,
    accounting: FrozenOrderedNfaAccountingV1,
}

#[derive(Clone, Copy)]
struct FrozenOrderedNfaGraph<'a> {
    roles: &'a [u8],
    edge_offsets: &'a [u32],
    edge_targets: &'a [u32],
    edge_kinds: &'a [u8],
    byte_starts: &'a [u8],
    byte_ends: &'a [u8],
    start: u32,
    line_terminator: u8,
}

impl FrozenOrderedNfaStorageV1 {
    pub(crate) fn try_new(
        view: NativeOrderedNfaProgramView<'_>,
        limits: FrozenOrderedNfaLimitsV1,
    ) -> Option<Self> {
        if view.output != OutputContract::Span {
            return None;
        }
        let raw = view.raw;
        let states = raw.roles.len();
        let edges = raw.edge_targets.len();
        if states == 0
            || states > limits.max_states
            || edges > limits.max_edges
            || raw.edge_offsets.len() != states.checked_add(1)?
            || raw.edge_kinds.len() != edges
            || raw.byte_starts.len() != edges
            || raw.byte_ends.len() != edges
            || usize::try_from(raw.start).ok()? >= states
            || raw.edge_offsets.first().copied() != Some(0)
        {
            return None;
        }

        let mut zero_width_edges = 0usize;
        let mut assertion_kinds = 0_u32;
        let mut has_accept = false;
        for state in 0..states {
            let begin = usize::try_from(*raw.edge_offsets.get(state)?).ok()?;
            let end = usize::try_from(*raw.edge_offsets.get(state + 1)?).ok()?;
            if begin > end || end > edges {
                return None;
            }
            let role = *raw.roles.get(state)?;
            let _ = encode_role(role)?;
            has_accept |= role == StateRole::Accept;
            if role == StateRole::Accept && begin != end {
                return None;
            }
            for edge in begin..end {
                let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
                if target >= states {
                    return None;
                }
                let kind = *raw.edge_kinds.get(edge)?;
                if (role == StateRole::Consume) != (kind == EdgeKind::ByteRange)
                    || role == StateRole::Accept
                {
                    return None;
                }
                if kind == EdgeKind::ByteRange {
                    if raw.byte_starts[edge] > raw.byte_ends[edge] {
                        return None;
                    }
                } else {
                    if raw.byte_starts[edge] != 0 || raw.byte_ends[edge] != 0 {
                        return None;
                    }
                    zero_width_edges = zero_width_edges.checked_add(1)?;
                    if kind != EdgeKind::Epsilon {
                        assertion_kinds |= assertion_bit(kind)?;
                    }
                }
                let _ = encode_edge_kind(kind)?;
            }
        }
        if !has_accept || usize::try_from(*raw.edge_offsets.last()?).ok()? != edges {
            return None;
        }

        let layout = WorkspaceShape::new(states, edges, zero_width_edges)?
            .workspace_layout()
            .ok()?;
        let closure_slots = layout.closure_slots();
        let setup_work = layout.construction_work();
        let descriptor_bytes = descriptor_payload_bytes(states, edges)?;
        let scratch_bytes = scratch_payload_bytes(states, edges, closure_slots)?;
        let prospective_handle_bytes = scratch_bytes;
        if descriptor_bytes > limits.max_descriptor_bytes
            || scratch_bytes > limits.max_scratch_bytes
            || setup_work > limits.max_setup_work
            || prospective_handle_bytes > limits.max_handle_bytes
        {
            return None;
        }

        let mut encoded_roles = try_zeroed_vec(states)?;
        for (encoded, &role) in encoded_roles.iter_mut().zip(&raw.roles) {
            *encoded = encode_role(role)?;
        }
        let mut encoded_kinds = try_zeroed_vec(edges)?;
        for (encoded, &kind) in encoded_kinds.iter_mut().zip(&raw.edge_kinds) {
            *encoded = encode_edge_kind(kind)?;
        }
        let roles = encoded_roles.into_boxed_slice();
        let edge_offsets = try_copy_box(&raw.edge_offsets)?;
        let edge_targets = try_copy_box(&raw.edge_targets)?;
        let edge_kinds = encoded_kinds.into_boxed_slice();
        let byte_starts = try_copy_box(&raw.byte_starts)?;
        let byte_ends = try_copy_box(&raw.byte_ends)?;
        let seen = try_filled_box(states, 0_u64)?;
        let current = try_filled_box(states, FrozenOrderedNfaThreadV1::default())?;
        let roots = try_filled_box(edges, FrozenOrderedNfaThreadV1::default())?;
        let stack = try_filled_box(closure_slots, FrozenOrderedNfaThreadV1::default())?;
        let cache_identity = next_cache_identity()?;

        let scratch_descriptor = try_box_preserve(FrozenOrderedNfaScratchV1 {
            ready_seal: 0,
            magic: FROZEN_ORDERED_NFA_SCRATCH_V1_MAGIC,
            abi_version: FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION,
            abi_version_complement: !FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION,
            scratch_bytes,
            artifact_identity: view.artifact_identity,
            cache_identity,
            seen_address: seen.as_ptr().expose_provenance(),
            current_address: current.as_ptr().expose_provenance(),
            roots_address: roots.as_ptr().expose_provenance(),
            stack_address: stack.as_ptr().expose_provenance(),
            state_capacity: u32::try_from(states).ok()?,
            root_capacity: u32::try_from(edges).ok()?,
            stack_capacity: u32::try_from(closure_slots).ok()?,
            reserved: 0,
            generation: 0,
            current_len: 0,
            roots_len: 0,
            stack_len: 0,
            pending_start: 0,
            pending_end: 0,
            pending_valid: 0,
            control_reserved: 0,
        })
        .ok()?;
        let mut scratch = FrozenOrderedNfaScratchStorageV1 {
            descriptor: scratch_descriptor,
            seen,
            current,
            roots,
            stack,
        };
        scratch.descriptor.ready_seal = FROZEN_ORDERED_NFA_SCRATCH_V1_READY_SEAL;

        let mut descriptor = try_box_preserve(FrozenOrderedNfaDescriptorV1 {
            ready_seal: 0,
            magic: FROZEN_ORDERED_NFA_DESCRIPTOR_V1_MAGIC,
            abi_version: FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ABI_VERSION,
            abi_version_complement: !FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ABI_VERSION,
            descriptor_bytes,
            artifact_identity: view.artifact_identity,
            roles_address: roles.as_ptr().expose_provenance(),
            edge_offsets_address: edge_offsets.as_ptr().expose_provenance(),
            edge_targets_address: edge_targets.as_ptr().expose_provenance(),
            edge_kinds_address: edge_kinds.as_ptr().expose_provenance(),
            byte_starts_address: byte_starts.as_ptr().expose_provenance(),
            byte_ends_address: byte_ends.as_ptr().expose_provenance(),
            state_count: u32::try_from(states).ok()?,
            edge_count: u32::try_from(edges).ok()?,
            zero_width_edge_count: u32::try_from(zero_width_edges).ok()?,
            closure_slots: u32::try_from(closure_slots).ok()?,
            start_state: raw.start,
            assertion_kinds,
            line_terminator: view.line_terminator,
            reserved: [0; 7],
        })
        .ok()?;
        descriptor.ready_seal = FROZEN_ORDERED_NFA_DESCRIPTOR_V1_READY_SEAL;
        // A boxed slice's allocation extent is exactly its length. Recompute
        // every owner independently instead of assuming related arrays share
        // the canonical dimensions used for the prospective receipt.
        let retained_descriptor_bytes = descriptor_payload_bytes_from_lengths(
            roles.len(),
            edge_offsets.len(),
            edge_targets.len(),
            edge_kinds.len(),
            byte_starts.len(),
            byte_ends.len(),
        )?;
        let retained_scratch_bytes = scratch_payload_bytes_from_lengths(
            scratch.seen.len(),
            scratch.current.len(),
            scratch.roots.len(),
            scratch.stack.len(),
        )?;
        let retained_handle_bytes = retained_scratch_bytes;
        if retained_descriptor_bytes != descriptor_bytes
            || retained_scratch_bytes != scratch_bytes
            || retained_descriptor_bytes > limits.max_descriptor_bytes
            || retained_scratch_bytes > limits.max_scratch_bytes
            || retained_handle_bytes > limits.max_handle_bytes
            || retained_handle_bytes != prospective_handle_bytes
        {
            return None;
        }
        let accounting = FrozenOrderedNfaAccountingV1 {
            descriptor_bytes,
            scratch_bytes,
            setup_work,
            prospective_handle_bytes,
            retained_handle_bytes,
        };
        let storage = Self {
            roles,
            edge_offsets,
            edge_targets,
            edge_kinds,
            byte_starts,
            byte_ends,
            scratch,
            descriptor,
            expected_cache_identity: cache_identity,
            accounting,
        };
        storage.authenticate_graph(view.artifact_identity)?;
        storage.authenticate_scratch(view.artifact_identity)?;
        Some(storage)
    }

    /// Address of the immutable fixed-layout descriptor.
    #[doc(hidden)]
    #[must_use]
    pub fn descriptor_address(&self) -> usize {
        (&*self.descriptor as *const FrozenOrderedNfaDescriptorV1).expose_provenance()
    }

    /// Exact artifact identity copied into the authenticated descriptor.
    #[doc(hidden)]
    #[must_use]
    pub const fn artifact_identity(&self) -> [u8; 32] {
        self.descriptor.artifact_identity
    }

    /// Setup-minted graph/scratch binding nonce.
    #[doc(hidden)]
    #[must_use]
    pub const fn cache_identity(&self) -> u64 {
        self.expected_cache_identity
    }

    /// Exact setup accounting remeasured after all payload owners exist.
    #[doc(hidden)]
    #[must_use]
    pub const fn accounting(&self) -> FrozenOrderedNfaAccountingV1 {
        self.accounting
    }

    fn authenticate_graph(
        &self,
        expected_artifact_identity: [u8; 32],
    ) -> Option<FrozenOrderedNfaGraph<'_>> {
        let descriptor = &self.descriptor;
        let states = usize::try_from(descriptor.state_count).ok()?;
        let edges = usize::try_from(descriptor.edge_count).ok()?;
        if descriptor.ready_seal != FROZEN_ORDERED_NFA_DESCRIPTOR_V1_READY_SEAL
            || descriptor.magic != FROZEN_ORDERED_NFA_DESCRIPTOR_V1_MAGIC
            || descriptor.abi_version != FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ABI_VERSION
            || descriptor.abi_version_complement != !FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ABI_VERSION
            || descriptor.descriptor_bytes != descriptor_payload_bytes(states, edges)?
            || descriptor.artifact_identity != expected_artifact_identity
            || descriptor.roles_address != self.roles.as_ptr().expose_provenance()
            || descriptor.edge_offsets_address != self.edge_offsets.as_ptr().expose_provenance()
            || descriptor.edge_targets_address != self.edge_targets.as_ptr().expose_provenance()
            || descriptor.edge_kinds_address != self.edge_kinds.as_ptr().expose_provenance()
            || descriptor.byte_starts_address != self.byte_starts.as_ptr().expose_provenance()
            || descriptor.byte_ends_address != self.byte_ends.as_ptr().expose_provenance()
            || self.roles.len() != states
            || self.edge_offsets.len() != states.checked_add(1)?
            || self.edge_targets.len() != edges
            || self.edge_kinds.len() != edges
            || self.byte_starts.len() != edges
            || self.byte_ends.len() != edges
            || usize::try_from(descriptor.start_state).ok()? >= states
            || descriptor.reserved != [0; 7]
            || self.accounting.descriptor_bytes != descriptor.descriptor_bytes
            || self.accounting.prospective_handle_bytes != self.accounting.scratch_bytes
            || self.accounting.retained_handle_bytes != self.accounting.scratch_bytes
        {
            return None;
        }
        let (zero_width_edges, assertion_kinds) = validate_encoded_graph(
            &self.roles,
            &self.edge_offsets,
            &self.edge_targets,
            &self.edge_kinds,
            &self.byte_starts,
            &self.byte_ends,
        )?;
        let layout = WorkspaceShape::new(states, edges, zero_width_edges)?
            .workspace_layout()
            .ok()?;
        if usize::try_from(descriptor.zero_width_edge_count).ok()? != zero_width_edges
            || usize::try_from(descriptor.closure_slots).ok()? != layout.closure_slots()
            || descriptor.assertion_kinds != assertion_kinds
            || self.accounting.setup_work != layout.construction_work()
            || self.accounting.descriptor_bytes
                != descriptor_payload_bytes_from_lengths(
                    self.roles.len(),
                    self.edge_offsets.len(),
                    self.edge_targets.len(),
                    self.edge_kinds.len(),
                    self.byte_starts.len(),
                    self.byte_ends.len(),
                )?
        {
            return None;
        }
        Some(FrozenOrderedNfaGraph {
            roles: &self.roles,
            edge_offsets: &self.edge_offsets,
            edge_targets: &self.edge_targets,
            edge_kinds: &self.edge_kinds,
            byte_starts: &self.byte_starts,
            byte_ends: &self.byte_ends,
            start: descriptor.start_state,
            line_terminator: descriptor.line_terminator,
        })
    }

    fn authenticate_scratch(&self, expected_artifact_identity: [u8; 32]) -> Option<()> {
        let descriptor = &self.scratch.descriptor;
        let states = self.roles.len();
        let edges = self.edge_targets.len();
        let closure_slots = usize::try_from(self.descriptor.closure_slots).ok()?;
        if descriptor.ready_seal != FROZEN_ORDERED_NFA_SCRATCH_V1_READY_SEAL
            || descriptor.magic != FROZEN_ORDERED_NFA_SCRATCH_V1_MAGIC
            || descriptor.abi_version != FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION
            || descriptor.abi_version_complement != !FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION
            || descriptor.scratch_bytes != scratch_payload_bytes(states, edges, closure_slots)?
            || descriptor.artifact_identity != expected_artifact_identity
            || descriptor.artifact_identity != self.descriptor.artifact_identity
            || self.expected_cache_identity == 0
            || descriptor.cache_identity != self.expected_cache_identity
            || descriptor.seen_address != self.scratch.seen.as_ptr().expose_provenance()
            || descriptor.current_address != self.scratch.current.as_ptr().expose_provenance()
            || descriptor.roots_address != self.scratch.roots.as_ptr().expose_provenance()
            || descriptor.stack_address != self.scratch.stack.as_ptr().expose_provenance()
            || usize::try_from(descriptor.state_capacity).ok()? != states
            || usize::try_from(descriptor.root_capacity).ok()? != edges
            || usize::try_from(descriptor.stack_capacity).ok()? != closure_slots
            || self.scratch.seen.len() != states
            || self.scratch.current.len() != states
            || self.scratch.roots.len() != edges
            || self.scratch.stack.len() != closure_slots
            || descriptor.reserved != 0
            || descriptor.control_reserved != 0
            || descriptor.current_len > states
            || descriptor.roots_len > edges
            || descriptor.stack_len > closure_slots
            || descriptor.pending_valid > 1
            || self.accounting.scratch_bytes
                != scratch_payload_bytes_from_lengths(
                    self.scratch.seen.len(),
                    self.scratch.current.len(),
                    self.scratch.roots.len(),
                    self.scratch.stack.len(),
                )?
        {
            return None;
        }
        Some(())
    }

    /// Target-neutral execution of the exact frozen tables.
    ///
    /// The outer `None` is a fail-closed descriptor/window refusal. The inner
    /// option is the ordered Span result. Authentication and the complete
    /// generation-overflow preflight happen before indexing `haystack`.
    #[cfg(test)]
    pub(crate) fn search_for_test(
        &mut self,
        expected_artifact_identity: [u8; 32],
        haystack: &[u8],
        window_start: usize,
        window_end: usize,
    ) -> Option<Option<(usize, usize)>> {
        if window_start > window_end || window_end > haystack.len() {
            return None;
        }
        self.authenticate_graph(expected_artifact_identity)?;
        self.authenticate_scratch(expected_artifact_identity)?;
        let boundaries = window_end.checked_sub(window_start)?.checked_add(1)?;
        let boundary_generations = u64::try_from(boundaries).ok()?;
        if self.scratch.descriptor.generation > u64::MAX.checked_sub(boundary_generations)? {
            self.scratch.seen.fill(0);
            self.scratch.descriptor.generation = 0;
        }
        self.scratch.descriptor.current_len = 0;
        self.scratch.descriptor.roots_len = 0;
        self.scratch.descriptor.stack_len = 0;
        self.scratch.descriptor.pending_start = 0;
        self.scratch.descriptor.pending_end = 0;
        self.scratch.descriptor.pending_valid = 0;

        let graph = FrozenOrderedNfaGraph {
            roles: &self.roles,
            edge_offsets: &self.edge_offsets,
            edge_targets: &self.edge_targets,
            edge_kinds: &self.edge_kinds,
            byte_starts: &self.byte_starts,
            byte_ends: &self.byte_ends,
            start: self.descriptor.start_state,
            line_terminator: self.descriptor.line_terminator,
        };
        execute_ordered_span(graph, &mut self.scratch, haystack, window_start, window_end)
    }
}

impl FrozenOrderedNfaPreparedScratchV1 {
    /// Build only the bounded mutable workspace for an authenticated ordered
    /// NFA. Canonical graph structure is validated directly; no graph table is
    /// copied or retained by this preparation transaction.
    pub(crate) fn try_new(
        view: NativeOrderedNfaProgramView<'_>,
        limits: FrozenOrderedNfaLimitsV1,
    ) -> Option<Self> {
        let shape = validate_ordered_nfa_shape(view, limits)?;
        let seen = try_filled_box(shape.states, 0_u64)?;
        let current = try_filled_box(shape.states, FrozenOrderedNfaThreadV1::default())?;
        let roots = try_filled_box(shape.edges, FrozenOrderedNfaThreadV1::default())?;
        let stack = try_filled_box(shape.closure_slots, FrozenOrderedNfaThreadV1::default())?;
        let expected_cache_identity = next_cache_identity()?;
        let descriptor = try_box_preserve(FrozenOrderedNfaScratchV1 {
            ready_seal: 0,
            magic: FROZEN_ORDERED_NFA_SCRATCH_V1_MAGIC,
            abi_version: FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION,
            abi_version_complement: !FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION,
            scratch_bytes: shape.scratch_bytes,
            artifact_identity: view.artifact_identity,
            cache_identity: expected_cache_identity,
            seen_address: seen.as_ptr().expose_provenance(),
            current_address: current.as_ptr().expose_provenance(),
            roots_address: roots.as_ptr().expose_provenance(),
            stack_address: stack.as_ptr().expose_provenance(),
            state_capacity: u32::try_from(shape.states).ok()?,
            root_capacity: u32::try_from(shape.edges).ok()?,
            stack_capacity: u32::try_from(shape.closure_slots).ok()?,
            reserved: 0,
            generation: 0,
            current_len: 0,
            roots_len: 0,
            stack_len: 0,
            pending_start: 0,
            pending_end: 0,
            pending_valid: 0,
            control_reserved: 0,
        })
        .ok()?;
        let mut scratch = FrozenOrderedNfaScratchStorageV1 {
            seen,
            current,
            roots,
            stack,
            descriptor,
        };
        let retained_scratch_bytes = scratch_payload_bytes_from_lengths(
            scratch.seen.len(),
            scratch.current.len(),
            scratch.roots.len(),
            scratch.stack.len(),
        )?;
        if retained_scratch_bytes != shape.scratch_bytes
            || retained_scratch_bytes > limits.max_scratch_bytes
            || retained_scratch_bytes > limits.max_handle_bytes
        {
            return None;
        }
        scratch.descriptor.ready_seal = FROZEN_ORDERED_NFA_SCRATCH_V1_READY_SEAL;
        let accounting = FrozenOrderedNfaAccountingV1 {
            descriptor_bytes: shape.descriptor_bytes,
            scratch_bytes: shape.scratch_bytes,
            setup_work: shape.setup_work,
            prospective_handle_bytes: shape.scratch_bytes,
            retained_handle_bytes: retained_scratch_bytes,
        };
        let owner = Self {
            scratch,
            expected_artifact_identity: view.artifact_identity,
            expected_cache_identity,
            accounting,
        };
        owner.authenticate()?;
        Some(owner)
    }

    pub(crate) fn authenticate(&self) -> Option<()> {
        let descriptor = &self.scratch.descriptor;
        let states = usize::try_from(descriptor.state_capacity).ok()?;
        let edges = usize::try_from(descriptor.root_capacity).ok()?;
        let closure_slots = usize::try_from(descriptor.stack_capacity).ok()?;
        if descriptor.ready_seal != FROZEN_ORDERED_NFA_SCRATCH_V1_READY_SEAL
            || descriptor.magic != FROZEN_ORDERED_NFA_SCRATCH_V1_MAGIC
            || descriptor.abi_version != FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION
            || descriptor.abi_version_complement != !FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION
            || descriptor.scratch_bytes != scratch_payload_bytes(states, edges, closure_slots)?
            || descriptor.artifact_identity != self.expected_artifact_identity
            || self.expected_cache_identity == 0
            || descriptor.cache_identity != self.expected_cache_identity
            || descriptor.seen_address != self.scratch.seen.as_ptr().expose_provenance()
            || descriptor.current_address != self.scratch.current.as_ptr().expose_provenance()
            || descriptor.roots_address != self.scratch.roots.as_ptr().expose_provenance()
            || descriptor.stack_address != self.scratch.stack.as_ptr().expose_provenance()
            || self.scratch.seen.len() != states
            || self.scratch.current.len() != states
            || self.scratch.roots.len() != edges
            || self.scratch.stack.len() != closure_slots
            || descriptor.reserved != 0
            || descriptor.control_reserved != 0
            || descriptor.current_len > states
            || descriptor.roots_len > edges
            || descriptor.stack_len > closure_slots
            || descriptor.pending_valid > 1
            || self.accounting.scratch_bytes
                != scratch_payload_bytes_from_lengths(
                    self.scratch.seen.len(),
                    self.scratch.current.len(),
                    self.scratch.roots.len(),
                    self.scratch.stack.len(),
                )?
            || self.accounting.prospective_handle_bytes != self.accounting.scratch_bytes
            || self.accounting.retained_handle_bytes != self.accounting.scratch_bytes
        {
            return None;
        }
        Some(())
    }

    /// Address of the exact C-layout scratch descriptor.
    #[must_use]
    pub fn descriptor_address(&self) -> usize {
        (&*self.scratch.descriptor as *const FrozenOrderedNfaScratchV1).expose_provenance()
    }

    /// Semantic artifact identity bound at setup.
    #[must_use]
    pub const fn artifact_identity(&self) -> [u8; 32] {
        self.expected_artifact_identity
    }

    /// Process-private nonce binding the header and scratch descriptor.
    #[must_use]
    pub const fn cache_identity(&self) -> u64 {
        self.expected_cache_identity
    }

    /// Exact retained scratch receipt.
    #[must_use]
    pub const fn accounting(&self) -> FrozenOrderedNfaAccountingV1 {
        self.accounting
    }

    /// Exact prepared geometry mirrored into the additive header.
    #[must_use]
    pub const fn capacities(&self) -> (u32, u32, u32) {
        (
            self.scratch.descriptor.state_capacity,
            self.scratch.descriptor.root_capacity,
            self.scratch.descriptor.stack_capacity,
        )
    }

    /// Exact payload addresses mirrored independently by the V15 header.
    #[must_use]
    pub fn payload_addresses(&self) -> [usize; 4] {
        [
            self.scratch.seen.as_ptr().expose_provenance(),
            self.scratch.current.as_ptr().expose_provenance(),
            self.scratch.roots.as_ptr().expose_provenance(),
            self.scratch.stack.as_ptr().expose_provenance(),
        ]
    }

    /// Return whether the complete scratch descriptor and every payload owner
    /// still authenticate against their setup-minted identity and nonce.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.authenticate().is_some()
    }

    /// Permanently revoke this scratch capability before any fallback may
    /// mutate or release its payloads.
    pub fn revoke(&mut self) {
        self.scratch.descriptor.ready_seal = 0;
    }
}

fn execute_ordered_span(
    graph: FrozenOrderedNfaGraph<'_>,
    scratch: &mut FrozenOrderedNfaScratchStorageV1,
    haystack: &[u8],
    window_start: usize,
    window_end: usize,
) -> Option<Option<(usize, usize)>> {
    let mut position = window_start;
    loop {
        scratch.descriptor.current_len = 0;
        scratch.descriptor.generation = scratch.descriptor.generation.checked_add(1)?;
        expand_boundary_roots(graph, scratch, haystack, position)?;

        if scratch.descriptor.current_len == 0
            && (scratch.descriptor.pending_valid != 0 || position == window_end)
        {
            break;
        }
        if position == window_end {
            break;
        }
        consume_current(graph, scratch, haystack[position])?;
        position = position.checked_add(1)?;
    }
    Some((scratch.descriptor.pending_valid != 0).then_some((
        scratch.descriptor.pending_start,
        scratch.descriptor.pending_end,
    )))
}

fn expand_boundary_roots(
    graph: FrozenOrderedNfaGraph<'_>,
    scratch: &mut FrozenOrderedNfaScratchStorageV1,
    haystack: &[u8],
    position: usize,
) -> Option<()> {
    let root_count = scratch.descriptor.roots_len;
    let mut root_index = 0usize;
    while root_index < root_count {
        let root = *scratch.roots.get(root_index)?;
        if let Some((start, end)) = expand_root(graph, scratch, haystack, position, root)? {
            scratch.descriptor.pending_start = start;
            scratch.descriptor.pending_end = end;
            scratch.descriptor.pending_valid = 1;
            break;
        }
        root_index = root_index.checked_add(1)?;
    }
    scratch.descriptor.roots_len = 0;
    if scratch.descriptor.pending_valid == 0 {
        let root = FrozenOrderedNfaThreadV1 {
            state: graph.start,
            reserved: 0,
            start: position,
        };
        if let Some((start, end)) = expand_root(graph, scratch, haystack, position, root)? {
            scratch.descriptor.pending_start = start;
            scratch.descriptor.pending_end = end;
            scratch.descriptor.pending_valid = 1;
        }
    }
    Some(())
}

fn expand_root(
    graph: FrozenOrderedNfaGraph<'_>,
    scratch: &mut FrozenOrderedNfaScratchStorageV1,
    haystack: &[u8],
    position: usize,
    root: FrozenOrderedNfaThreadV1,
) -> Option<Option<(usize, usize)>> {
    scratch.descriptor.stack_len = 0;
    let mut thread = root;
    loop {
        if thread.reserved != 0 {
            return None;
        }
        let state = usize::try_from(thread.state).ok()?;
        let seen = scratch.seen.get_mut(state)?;
        if *seen != scratch.descriptor.generation {
            *seen = scratch.descriptor.generation;
            match *graph.roles.get(state)? {
                ROLE_ACCEPT => return Some(Some((thread.start, position))),
                ROLE_CONSUME => push_current(scratch, thread)?,
                ROLE_SPLIT => {
                    let begin = usize::try_from(*graph.edge_offsets.get(state)?).ok()?;
                    let end =
                        usize::try_from(*graph.edge_offsets.get(state.checked_add(1)?)?).ok()?;
                    for edge in (begin..end).rev() {
                        let kind = *graph.edge_kinds.get(edge)?;
                        if zero_width_enabled(graph.line_terminator, kind, haystack, position)? {
                            push_stack(
                                scratch,
                                FrozenOrderedNfaThreadV1 {
                                    state: *graph.edge_targets.get(edge)?,
                                    reserved: 0,
                                    start: thread.start,
                                },
                            )?;
                        }
                    }
                }
                _ => return None,
            }
        }
        let Some(next) = pop_stack(scratch)? else {
            return Some(None);
        };
        thread = next;
    }
}

fn consume_current(
    graph: FrozenOrderedNfaGraph<'_>,
    scratch: &mut FrozenOrderedNfaScratchStorageV1,
    byte: u8,
) -> Option<()> {
    let current_len = scratch.descriptor.current_len;
    for index in 0..current_len {
        let thread = *scratch.current.get(index)?;
        let state = usize::try_from(thread.state).ok()?;
        let begin = usize::try_from(*graph.edge_offsets.get(state)?).ok()?;
        let end = usize::try_from(*graph.edge_offsets.get(state.checked_add(1)?)?).ok()?;
        for edge in begin..end {
            if *graph.edge_kinds.get(edge)? != EDGE_BYTE_RANGE {
                return None;
            }
            if *graph.byte_starts.get(edge)? <= byte && byte <= *graph.byte_ends.get(edge)? {
                push_root(
                    scratch,
                    FrozenOrderedNfaThreadV1 {
                        state: *graph.edge_targets.get(edge)?,
                        reserved: 0,
                        start: thread.start,
                    },
                )?;
            }
        }
    }
    Some(())
}

fn push_current(
    scratch: &mut FrozenOrderedNfaScratchStorageV1,
    thread: FrozenOrderedNfaThreadV1,
) -> Option<()> {
    let slot = scratch.current.get_mut(scratch.descriptor.current_len)?;
    *slot = thread;
    scratch.descriptor.current_len = scratch.descriptor.current_len.checked_add(1)?;
    Some(())
}

fn push_root(
    scratch: &mut FrozenOrderedNfaScratchStorageV1,
    thread: FrozenOrderedNfaThreadV1,
) -> Option<()> {
    let slot = scratch.roots.get_mut(scratch.descriptor.roots_len)?;
    *slot = thread;
    scratch.descriptor.roots_len = scratch.descriptor.roots_len.checked_add(1)?;
    Some(())
}

fn push_stack(
    scratch: &mut FrozenOrderedNfaScratchStorageV1,
    thread: FrozenOrderedNfaThreadV1,
) -> Option<()> {
    let slot = scratch.stack.get_mut(scratch.descriptor.stack_len)?;
    *slot = thread;
    scratch.descriptor.stack_len = scratch.descriptor.stack_len.checked_add(1)?;
    Some(())
}

fn pop_stack(
    scratch: &mut FrozenOrderedNfaScratchStorageV1,
) -> Option<Option<FrozenOrderedNfaThreadV1>> {
    if scratch.descriptor.stack_len == 0 {
        return Some(None);
    }
    scratch.descriptor.stack_len = scratch.descriptor.stack_len.checked_sub(1)?;
    Some(Some(*scratch.stack.get(scratch.descriptor.stack_len)?))
}

fn zero_width_enabled(
    line_terminator: u8,
    kind: u8,
    haystack: &[u8],
    position: usize,
) -> Option<bool> {
    if position > haystack.len() {
        return None;
    }
    let before = position
        .checked_sub(1)
        .and_then(|index| haystack.get(index))
        .copied();
    let after = haystack.get(position).copied();
    Some(match kind {
        EDGE_EPSILON => true,
        EDGE_ASSERT_HAYSTACK_START => position == 0,
        EDGE_ASSERT_HAYSTACK_END => position == haystack.len(),
        EDGE_ASSERT_LINE_START_LF => position == 0 || before == Some(line_terminator),
        EDGE_ASSERT_LINE_END_LF => position == haystack.len() || after == Some(line_terminator),
        EDGE_ASSERT_LINE_START_CRLF => {
            position == 0 || before == Some(b'\n') || before == Some(b'\r') && after != Some(b'\n')
        }
        EDGE_ASSERT_LINE_END_CRLF => {
            position == haystack.len()
                || after == Some(b'\r')
                || after == Some(b'\n') && before != Some(b'\r')
        }
        EDGE_ASSERT_WORD_ASCII
        | EDGE_ASSERT_WORD_ASCII_NEGATE
        | EDGE_ASSERT_WORD_START_ASCII
        | EDGE_ASSERT_WORD_END_ASCII
        | EDGE_ASSERT_WORD_START_HALF_ASCII
        | EDGE_ASSERT_WORD_END_HALF_ASCII => {
            let left = before.is_some_and(is_ascii_word);
            let right = after.is_some_and(is_ascii_word);
            match kind {
                EDGE_ASSERT_WORD_ASCII => left != right,
                EDGE_ASSERT_WORD_ASCII_NEGATE => left == right,
                EDGE_ASSERT_WORD_START_ASCII => !left && right,
                EDGE_ASSERT_WORD_END_ASCII => left && !right,
                EDGE_ASSERT_WORD_START_HALF_ASCII => !left,
                EDGE_ASSERT_WORD_END_HALF_ASCII => !right,
                _ => return None,
            }
        }
        EDGE_ASSERT_WORD_UNICODE
        | EDGE_ASSERT_WORD_UNICODE_NEGATE
        | EDGE_ASSERT_WORD_START_UNICODE
        | EDGE_ASSERT_WORD_END_UNICODE
        | EDGE_ASSERT_WORD_START_HALF_UNICODE
        | EDGE_ASSERT_WORD_END_HALF_UNICODE => UnicodeLookMatcher::matches_edge_kind_prevalidated(
            decode_edge_kind(kind)?,
            haystack,
            position,
        )?,
        _ => return None,
    })
}

const fn is_ascii_word(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn descriptor_payload_bytes(states: usize, edges: usize) -> Option<usize> {
    descriptor_payload_bytes_from_lengths(
        states,
        states.checked_add(1)?,
        edges,
        edges,
        edges,
        edges,
    )
}

fn descriptor_payload_bytes_from_lengths(
    roles: usize,
    edge_offsets: usize,
    edge_targets: usize,
    edge_kinds: usize,
    byte_starts: usize,
    byte_ends: usize,
) -> Option<usize> {
    FROZEN_ORDERED_NFA_DESCRIPTOR_V1_BYTES
        .checked_add(roles.checked_mul(std::mem::size_of::<u8>())?)?
        .checked_add(edge_offsets.checked_mul(std::mem::size_of::<u32>())?)?
        .checked_add(edge_targets.checked_mul(std::mem::size_of::<u32>())?)?
        .checked_add(edge_kinds.checked_mul(std::mem::size_of::<u8>())?)?
        .checked_add(byte_starts.checked_mul(std::mem::size_of::<u8>())?)?
        .checked_add(byte_ends.checked_mul(std::mem::size_of::<u8>())?)
}

fn scratch_payload_bytes(states: usize, edges: usize, closure_slots: usize) -> Option<usize> {
    scratch_payload_bytes_from_lengths(states, states, edges, closure_slots)
}

fn scratch_payload_bytes_from_lengths(
    seen: usize,
    current: usize,
    roots: usize,
    stack: usize,
) -> Option<usize> {
    FROZEN_ORDERED_NFA_SCRATCH_V1_BYTES
        .checked_add(seen.checked_mul(std::mem::size_of::<u64>())?)?
        .checked_add(current.checked_mul(FROZEN_ORDERED_NFA_THREAD_V1_BYTES)?)?
        .checked_add(roots.checked_mul(FROZEN_ORDERED_NFA_THREAD_V1_BYTES)?)?
        .checked_add(stack.checked_mul(FROZEN_ORDERED_NFA_THREAD_V1_BYTES)?)
}

fn validate_ordered_nfa_shape(
    view: NativeOrderedNfaProgramView<'_>,
    limits: FrozenOrderedNfaLimitsV1,
) -> Option<ValidatedOrderedNfaShapeV1> {
    if view.output != OutputContract::Span {
        return None;
    }
    let raw = view.raw;
    let states = raw.roles.len();
    let edges = raw.edge_targets.len();
    if states == 0
        || states > limits.max_states
        || edges > limits.max_edges
        || raw.edge_offsets.len() != states.checked_add(1)?
        || raw.edge_kinds.len() != edges
        || raw.byte_starts.len() != edges
        || raw.byte_ends.len() != edges
        || usize::try_from(raw.start).ok()? >= states
        || raw.edge_offsets.first().copied() != Some(0)
    {
        return None;
    }

    let mut zero_width_edges = 0usize;
    let mut has_accept = false;
    for state in 0..states {
        let begin = usize::try_from(*raw.edge_offsets.get(state)?).ok()?;
        let end = usize::try_from(*raw.edge_offsets.get(state + 1)?).ok()?;
        if begin > end || end > edges {
            return None;
        }
        let role = *raw.roles.get(state)?;
        let _ = encode_role(role)?;
        has_accept |= role == StateRole::Accept;
        if role == StateRole::Accept && begin != end {
            return None;
        }
        for edge in begin..end {
            if usize::try_from(*raw.edge_targets.get(edge)?).ok()? >= states {
                return None;
            }
            let kind = *raw.edge_kinds.get(edge)?;
            if (role == StateRole::Consume) != (kind == EdgeKind::ByteRange)
                || role == StateRole::Accept
            {
                return None;
            }
            if kind == EdgeKind::ByteRange {
                if raw.byte_starts[edge] > raw.byte_ends[edge] {
                    return None;
                }
            } else {
                if raw.byte_starts[edge] != 0 || raw.byte_ends[edge] != 0 {
                    return None;
                }
                zero_width_edges = zero_width_edges.checked_add(1)?;
                if kind != EdgeKind::Epsilon {
                    let _ = assertion_bit(kind)?;
                }
            }
            let _ = encode_edge_kind(kind)?;
        }
    }
    if !has_accept || usize::try_from(*raw.edge_offsets.last()?).ok()? != edges {
        return None;
    }

    let layout = WorkspaceShape::new(states, edges, zero_width_edges)?
        .workspace_layout()
        .ok()?;
    let closure_slots = layout.closure_slots();
    let descriptor_bytes = descriptor_payload_bytes(states, edges)?;
    let scratch_bytes = scratch_payload_bytes(states, edges, closure_slots)?;
    let setup_work = layout.construction_work();
    if descriptor_bytes > limits.max_descriptor_bytes
        || scratch_bytes > limits.max_scratch_bytes
        || scratch_bytes > limits.max_handle_bytes
        || setup_work > limits.max_setup_work
    {
        return None;
    }
    Some(ValidatedOrderedNfaShapeV1 {
        states,
        edges,
        zero_width_edges,
        closure_slots,
        descriptor_bytes,
        scratch_bytes,
        setup_work,
    })
}

fn validate_encoded_graph(
    roles: &[u8],
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kinds: &[u8],
    byte_starts: &[u8],
    byte_ends: &[u8],
) -> Option<(usize, u32)> {
    let states = roles.len();
    let edges = edge_targets.len();
    if states == 0
        || edge_offsets.len() != states.checked_add(1)?
        || edge_kinds.len() != edges
        || byte_starts.len() != edges
        || byte_ends.len() != edges
        || edge_offsets.first().copied() != Some(0)
    {
        return None;
    }
    let mut zero_width_edges = 0usize;
    let mut assertion_kinds = 0_u32;
    let mut has_accept = false;
    for (state, &role) in roles.iter().enumerate() {
        if !matches!(role, ROLE_SPLIT | ROLE_CONSUME | ROLE_ACCEPT) {
            return None;
        }
        let begin = usize::try_from(*edge_offsets.get(state)?).ok()?;
        let end = usize::try_from(*edge_offsets.get(state.checked_add(1)?)?).ok()?;
        if begin > end || end > edges || role == ROLE_ACCEPT && begin != end {
            return None;
        }
        has_accept |= role == ROLE_ACCEPT;
        for edge in begin..end {
            if usize::try_from(*edge_targets.get(edge)?).ok()? >= states {
                return None;
            }
            let kind = *edge_kinds.get(edge)?;
            let decoded = decode_edge_kind(kind)?;
            if (role == ROLE_CONSUME) != (kind == EDGE_BYTE_RANGE) || role == ROLE_ACCEPT {
                return None;
            }
            if kind == EDGE_BYTE_RANGE {
                if byte_starts[edge] > byte_ends[edge] {
                    return None;
                }
            } else {
                if byte_starts[edge] != 0 || byte_ends[edge] != 0 {
                    return None;
                }
                zero_width_edges = zero_width_edges.checked_add(1)?;
                if kind != EDGE_EPSILON {
                    assertion_kinds |= assertion_bit(decoded)?;
                }
            }
        }
    }
    if !has_accept || usize::try_from(*edge_offsets.last()?).ok()? != edges {
        return None;
    }
    Some((zero_width_edges, assertion_kinds))
}

fn try_zeroed_vec(length: usize) -> Option<Vec<u8>> {
    let mut values = Vec::new();
    values.try_reserve_exact(length).ok()?;
    values.resize(length, 0);
    Some(values)
}

fn try_copy_box<T: Copy>(source: &[T]) -> Option<Box<[T]>> {
    let mut values = Vec::new();
    values.try_reserve_exact(source.len()).ok()?;
    values.extend_from_slice(source);
    Some(values.into_boxed_slice())
}

fn try_filled_box<T: Copy>(length: usize, value: T) -> Option<Box<[T]>> {
    let mut values = Vec::new();
    values.try_reserve_exact(length).ok()?;
    values.resize(length, value);
    Some(values.into_boxed_slice())
}

fn encode_role(role: StateRole) -> Option<u8> {
    Some(match role {
        StateRole::Split => ROLE_SPLIT,
        StateRole::Consume => ROLE_CONSUME,
        StateRole::Accept => ROLE_ACCEPT,
        _ => return None,
    })
}

pub(crate) fn encode_edge_kind(kind: EdgeKind) -> Option<u8> {
    Some(match kind {
        EdgeKind::Epsilon => EDGE_EPSILON,
        EdgeKind::ByteRange => EDGE_BYTE_RANGE,
        EdgeKind::AssertHaystackStart => EDGE_ASSERT_HAYSTACK_START,
        EdgeKind::AssertHaystackEnd => EDGE_ASSERT_HAYSTACK_END,
        EdgeKind::AssertLineStartLf => EDGE_ASSERT_LINE_START_LF,
        EdgeKind::AssertLineEndLf => EDGE_ASSERT_LINE_END_LF,
        EdgeKind::AssertLineStartCrlf => EDGE_ASSERT_LINE_START_CRLF,
        EdgeKind::AssertLineEndCrlf => EDGE_ASSERT_LINE_END_CRLF,
        EdgeKind::AssertWordAscii => EDGE_ASSERT_WORD_ASCII,
        EdgeKind::AssertWordAsciiNegate => EDGE_ASSERT_WORD_ASCII_NEGATE,
        EdgeKind::AssertWordStartAscii => EDGE_ASSERT_WORD_START_ASCII,
        EdgeKind::AssertWordEndAscii => EDGE_ASSERT_WORD_END_ASCII,
        EdgeKind::AssertWordStartHalfAscii => EDGE_ASSERT_WORD_START_HALF_ASCII,
        EdgeKind::AssertWordEndHalfAscii => EDGE_ASSERT_WORD_END_HALF_ASCII,
        EdgeKind::AssertWordUnicode => EDGE_ASSERT_WORD_UNICODE,
        EdgeKind::AssertWordUnicodeNegate => EDGE_ASSERT_WORD_UNICODE_NEGATE,
        EdgeKind::AssertWordStartUnicode => EDGE_ASSERT_WORD_START_UNICODE,
        EdgeKind::AssertWordEndUnicode => EDGE_ASSERT_WORD_END_UNICODE,
        EdgeKind::AssertWordStartHalfUnicode => EDGE_ASSERT_WORD_START_HALF_UNICODE,
        EdgeKind::AssertWordEndHalfUnicode => EDGE_ASSERT_WORD_END_HALF_UNICODE,
        _ => return None,
    })
}

fn decode_edge_kind(kind: u8) -> Option<EdgeKind> {
    Some(match kind {
        EDGE_EPSILON => EdgeKind::Epsilon,
        EDGE_BYTE_RANGE => EdgeKind::ByteRange,
        EDGE_ASSERT_HAYSTACK_START => EdgeKind::AssertHaystackStart,
        EDGE_ASSERT_HAYSTACK_END => EdgeKind::AssertHaystackEnd,
        EDGE_ASSERT_LINE_START_LF => EdgeKind::AssertLineStartLf,
        EDGE_ASSERT_LINE_END_LF => EdgeKind::AssertLineEndLf,
        EDGE_ASSERT_LINE_START_CRLF => EdgeKind::AssertLineStartCrlf,
        EDGE_ASSERT_LINE_END_CRLF => EdgeKind::AssertLineEndCrlf,
        EDGE_ASSERT_WORD_ASCII => EdgeKind::AssertWordAscii,
        EDGE_ASSERT_WORD_ASCII_NEGATE => EdgeKind::AssertWordAsciiNegate,
        EDGE_ASSERT_WORD_START_ASCII => EdgeKind::AssertWordStartAscii,
        EDGE_ASSERT_WORD_END_ASCII => EdgeKind::AssertWordEndAscii,
        EDGE_ASSERT_WORD_START_HALF_ASCII => EdgeKind::AssertWordStartHalfAscii,
        EDGE_ASSERT_WORD_END_HALF_ASCII => EdgeKind::AssertWordEndHalfAscii,
        EDGE_ASSERT_WORD_UNICODE => EdgeKind::AssertWordUnicode,
        EDGE_ASSERT_WORD_UNICODE_NEGATE => EdgeKind::AssertWordUnicodeNegate,
        EDGE_ASSERT_WORD_START_UNICODE => EdgeKind::AssertWordStartUnicode,
        EDGE_ASSERT_WORD_END_UNICODE => EdgeKind::AssertWordEndUnicode,
        EDGE_ASSERT_WORD_START_HALF_UNICODE => EdgeKind::AssertWordStartHalfUnicode,
        EDGE_ASSERT_WORD_END_HALF_UNICODE => EdgeKind::AssertWordEndHalfUnicode,
        _ => return None,
    })
}

fn assertion_bit(kind: EdgeKind) -> Option<u32> {
    let encoded = encode_edge_kind(kind)?;
    let ordinal = encoded.checked_sub(EDGE_ASSERT_HAYSTACK_START)?;
    Some(1_u32.checked_shl(u32::from(ordinal))?)
}

const _: () = {
    assert!(core::mem::size_of::<NativeOrderedNfaObjectLayout>() <= 256);
    assert!(FROZEN_ORDERED_NFA_DESCRIPTOR_V1_READY_SEAL_OFFSET == 0);
    assert!(FROZEN_ORDERED_NFA_SCRATCH_V1_READY_SEAL_OFFSET == 0);
    assert!(FROZEN_ORDERED_NFA_THREAD_V1_STATE_OFFSET == 0);
    assert!(FROZEN_ORDERED_NFA_THREAD_V1_START_OFFSET == 8);
    assert!(FROZEN_ORDERED_NFA_THREAD_V1_BYTES == 16);
    assert!(
        FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ABI_VERSION_COMPLEMENT_OFFSET
            == FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ABI_VERSION_OFFSET + 4
    );
    assert!(
        FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION_COMPLEMENT_OFFSET
            == FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION_OFFSET + 4
    );
};

#[cfg(test)]
mod tests {
    use fre_automata::{Automaton, CompileLimits};
    use fre_lower::{LowerLimits, OperationSemantics};
    use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

    use super::*;
    use crate::{CompileMode, DeterminizeLimits, MatchResult, SearchWindow};

    fn limits(max_handle_bytes: usize) -> FrozenOrderedNfaLimitsV1 {
        FrozenOrderedNfaLimitsV1::new(max_handle_bytes)
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "u8 membership bounds every four-word test index and shift"
    )]
    fn membership_words(bytes: impl IntoIterator<Item = u8>) -> [u64; 4] {
        let mut words = [0_u64; 4];
        for byte in bytes {
            let index = usize::from(byte);
            words[index / 64] |= 1_u64 << (index % 64);
        }
        words
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "validated inclusive byte ranges have bounded width"
    )]
    fn prefix_candidate_bytes(plan: NativeOrderedNfaStartPrefixPlan) -> usize {
        plan.ranges()
            .iter()
            .map(|range| usize::from(range.end) - usize::from(range.start) + 1)
            .sum()
    }

    fn ranges_with_degree(mut ranges: Vec<(u8, u8)>, degree: usize) -> Vec<(u8, u8)> {
        assert!(!ranges.is_empty());
        assert!(ranges.len() <= degree);
        let duplicate = ranges[0].0;
        while ranges.len() < degree {
            ranges.push((duplicate, duplicate));
        }
        ranges
    }

    fn guarded_prefix_cardinality_ranges(cardinality: u16, degree: usize) -> Vec<(u8, u8)> {
        assert!((1..=192).contains(&cardinality));
        let ranges = if cardinality <= 128 {
            vec![(
                0,
                u8::try_from(cardinality.checked_sub(1).unwrap()).unwrap(),
            )]
        } else {
            vec![
                (0, 127),
                (
                    192,
                    u8::try_from(
                        191_u16
                            .checked_add(cardinality.checked_sub(128).unwrap())
                            .unwrap(),
                    )
                    .unwrap(),
                ),
            ]
        };
        ranges_with_degree(ranges, degree)
    }

    fn guarded_prefix_program(assertion: EdgeKind, ranges: &[(u8, u8)]) -> crate::CompiledProgram {
        let consume_end = ranges
            .len()
            .checked_add(1)
            .and_then(|end| u32::try_from(end).ok())
            .expect("focused guarded-prefix edge count fits u32");
        let mut edge_targets = vec![1];
        edge_targets.extend(std::iter::repeat_n(2, ranges.len()));
        let mut edge_kinds = vec![assertion];
        edge_kinds.extend(std::iter::repeat_n(EdgeKind::ByteRange, ranges.len()));
        let mut byte_starts = vec![0];
        byte_starts.extend(ranges.iter().map(|&(start, _)| start));
        let mut byte_ends = vec![0];
        byte_ends.extend(ranges.iter().map(|&(_, end)| end));
        let raw = RawPlan {
            start: 0,
            roles: vec![StateRole::Split, StateRole::Consume, StateRole::Accept],
            edge_offsets: vec![0, 1, consume_end, consume_end],
            edge_targets,
            edge_kinds,
            byte_starts,
            byte_ends,
        };
        let automaton = Automaton::from_raw(raw.clone(), CompileLimits::default())
            .expect("validate focused guarded-prefix graph");
        crate::CompiledProgram::build(
            raw,
            automaton,
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
            usize::MAX,
        )
        .expect("compile focused guarded-prefix graph")
    }

    fn selected_start_prefix(
        program: &crate::CompiledProgram,
    ) -> Option<NativeOrderedNfaStartPrefixPlan> {
        let view = program
            .native_ordered_nfa_view()
            .expect("focused program exposes an ordered-NFA view");
        NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap()
            .layout
            .start_prefix
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "u8 membership bounds every four-word test index and shift"
    )]
    fn start_prefix_plan_admits_nosey_shape_as_four_range_superset() {
        let exact = membership_words(
            [b'$', b'-']
                .into_iter()
                .chain(b'0'..=b'9')
                .chain(b'A'..=b'Z')
                .chain(b'a'..=b'z'),
        );
        let plan = derive_native_ordered_nfa_start_prefix(exact)
            .unwrap()
            .expect("Nosey first set remains below the prefix-text cap");
        assert_eq!(
            plan.ranges(),
            &[
                NativeOrderedNfaByteRange {
                    start: b'$',
                    end: b'$',
                },
                NativeOrderedNfaByteRange {
                    start: b'-',
                    end: b'9',
                },
                NativeOrderedNfaByteRange {
                    start: b'A',
                    end: b'Z',
                },
                NativeOrderedNfaByteRange {
                    start: b'a',
                    end: b'z',
                },
            ]
        );
        assert_eq!(prefix_candidate_bytes(plan), 66);
        assert!(native_ordered_nfa_start_prefix_contains(plan, b'.'));
        assert!(native_ordered_nfa_start_prefix_contains(plan, b'/'));
        for byte in u8::MIN..=u8::MAX {
            let index = usize::from(byte);
            if exact[index / 64] & (1_u64 << (index % 64)) != 0 {
                assert!(native_ordered_nfa_start_prefix_contains(plan, byte));
            }
        }
    }

    #[test]
    fn start_prefix_plan_enforces_candidate_and_range_caps() {
        let admitted_96 = membership_words(u8::MIN..=95);
        let plan = derive_native_ordered_nfa_start_prefix(admitted_96)
            .unwrap()
            .expect("96 contiguous candidates fit exactly");
        assert_eq!(prefix_candidate_bytes(plan), 96);
        assert!(
            derive_native_ordered_nfa_start_prefix(membership_words(u8::MIN..=96))
                .unwrap()
                .is_none()
        );

        let exact_four = membership_words([1, 3, 5, 7]);
        let four = derive_native_ordered_nfa_start_prefix(exact_four)
            .unwrap()
            .expect("four exact ranges fit without coalescing");
        assert_eq!(four.ranges().len(), 4);
        assert_eq!(prefix_candidate_bytes(four), 4);

        let exact_five = membership_words([1, 3, 5, 7, 9]);
        let five = derive_native_ordered_nfa_start_prefix(exact_five)
            .unwrap()
            .expect("five tiny ranges coalesce safely");
        assert_eq!(five.ranges().len(), 4);
        assert_eq!(prefix_candidate_bytes(five), 6);
        for byte in [1, 3, 5, 7, 9] {
            assert!(native_ordered_nfa_start_prefix_contains(five, byte));
        }

        let costly_cover = membership_words((0_u8..=188).step_by(4));
        assert!(
            derive_native_ordered_nfa_start_prefix(costly_cover)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn guarded_unicode_word_wide_row_admits_a_wider_compiler_only_prefix() {
        let ranges = guarded_prefix_cardinality_ranges(110, 39);
        let program = guarded_prefix_program(EdgeKind::AssertWordUnicode, &ranges);
        let view = program
            .native_ordered_nfa_view()
            .expect("guarded fixture exposes an ordered-NFA view");
        let exact = view
            .start_prefix_first_set
            .expect("guarded fixture has an authenticated first-byte set");
        assert_eq!(exact.iter().map(|word| word.count_ones()).sum::<u32>(), 110);
        assert_eq!(exact[2], 0);
        assert!(
            derive_native_ordered_nfa_start_prefix(exact)
                .unwrap()
                .is_none()
        );

        assert!(view.start_closure_dispatch.is_none());

        let plan = derive_native_ordered_nfa_guarded_unicode_start_prefix(view.raw, exact)
            .unwrap()
            .expect("audited guarded shape admits the wider cover");
        assert_eq!(prefix_candidate_bytes(plan), 110);
        assert!(prefix_candidate_bytes(plan) > MAX_NATIVE_ORDERED_NFA_START_PREFIX_CANDIDATE_BYTES);
        assert!(!native_ordered_nfa_start_prefix_intersects_utf8_continuation(plan));
        for byte in u8::MIN..=u8::MAX {
            let index = usize::from(byte);
            if exact[index / 64] & (1_u64 << (index % 64)) != 0 {
                assert!(native_ordered_nfa_start_prefix_contains(plan, byte));
            }
        }

        let selected = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(selected.layout.start_prefix, Some(plan));
        let without = NativeOrderedNfaObjectImage::try_build(
            NativeOrderedNfaProgramView {
                start_prefix_first_set: None,
                ..view
            },
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        assert!(without.layout.start_prefix.is_none());
        assert!(selected.layout.start_closure_dispatch.is_none());
        assert!(selected.start_closure_program.is_none());
        assert!(without.layout.start_closure_dispatch.is_none());
        assert!(without.start_closure_program.is_none());
        assert_eq!(selected.bytes, without.bytes);
        assert_eq!(selected.layout.object_bytes, without.layout.object_bytes);
    }

    #[test]
    fn guarded_unicode_word_prefix_requires_the_source_receipt_to_be_absent() {
        let ranges = guarded_prefix_cardinality_ranges(110, 39);
        let program = guarded_prefix_program(EdgeKind::AssertWordUnicode, &ranges);
        let view = program.native_ordered_nfa_view().unwrap();
        assert!(view.start_closure_dispatch.is_none());
        assert!(selected_start_prefix(&program).is_some());

        let oversized =
            unary_split_chain_program(MAX_NATIVE_ORDERED_NFA_START_CLOSURE_INSTRUCTIONS);
        let oversized_program = oversized
            .native_ordered_nfa_view()
            .unwrap()
            .start_closure_dispatch
            .expect("oversized fixture still exposes its source receipt");
        assert!(oversized_program.len() > MAX_NATIVE_ORDERED_NFA_START_CLOSURE_INSTRUCTIONS);

        let omitted = NativeOrderedNfaObjectImage::try_build(
            NativeOrderedNfaProgramView {
                start_closure_dispatch: Some(oversized_program),
                ..view
            },
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        assert!(omitted.layout.start_closure_dispatch.is_none());
        assert!(omitted.start_closure_program.is_none());
        assert!(omitted.layout.start_prefix.is_none());
    }

    #[test]
    fn guarded_unicode_word_prefix_requires_the_exact_raw_shape_and_bitmap() {
        let ranges = guarded_prefix_cardinality_ranges(110, 39);
        let unicode = guarded_prefix_program(EdgeKind::AssertWordUnicode, &ranges);
        let unicode_view = unicode.native_ordered_nfa_view().unwrap();
        let exact = unicode_view.start_prefix_first_set.unwrap();
        assert!(unicode_view.start_closure_dispatch.is_none());

        let absolute = guarded_prefix_program(EdgeKind::AssertHaystackStart, &ranges);
        let absolute_view = absolute.native_ordered_nfa_view().unwrap();
        assert_eq!(absolute_view.start_prefix_first_set, Some(exact));
        assert_eq!(
            absolute_view.raw.edge_kinds[0],
            EdgeKind::AssertHaystackStart
        );
        assert!(absolute_view.start_closure_dispatch.is_none());
        assert!(selected_start_prefix(&absolute).is_none());

        let mut alternative = unicode_view.raw.clone();
        alternative.roles[0] = StateRole::Consume;
        assert!(
            derive_native_ordered_nfa_guarded_unicode_start_prefix(&alternative, exact)
                .unwrap()
                .is_none()
        );

        let mut mismatched = exact;
        mismatched[0] &= !1;
        assert!(matches!(
            derive_native_ordered_nfa_guarded_unicode_start_prefix(unicode_view.raw, mismatched,),
            Err(ObjectError::InvalidModule(_))
        ));

        let mut malformed = unicode_view.raw.clone();
        malformed.byte_starts[0] = 1;
        assert!(matches!(
            derive_native_ordered_nfa_guarded_unicode_start_prefix(&malformed, exact),
            Err(ObjectError::InvalidModule(_))
        ));
        alternative = unicode_view.raw.clone();
        alternative.edge_targets.insert(1, 1);
        alternative
            .edge_kinds
            .insert(1, EdgeKind::AssertWordUnicode);
        alternative.byte_starts.insert(1, 0);
        alternative.byte_ends.insert(1, 0);
        for offset in &mut alternative.edge_offsets[1..] {
            *offset = offset.checked_add(1).unwrap();
        }
        assert!(
            derive_native_ordered_nfa_guarded_unicode_start_prefix(&alternative, exact)
                .unwrap()
                .is_none()
        );
        alternative = unicode_view.raw.clone();
        alternative.edge_targets[0] = 2;
        assert!(
            derive_native_ordered_nfa_guarded_unicode_start_prefix(&alternative, exact)
                .unwrap()
                .is_none()
        );
        malformed = unicode_view.raw.clone();
        malformed.edge_kinds[1] = EdgeKind::Epsilon;
        assert!(matches!(
            derive_native_ordered_nfa_guarded_unicode_start_prefix(&malformed, exact),
            Err(ObjectError::InvalidModule(_))
        ));

        malformed = unicode_view.raw.clone();
        malformed.edge_targets[1] = u32::MAX;
        assert!(matches!(
            derive_native_ordered_nfa_guarded_unicode_start_prefix(&malformed, exact),
            Err(ObjectError::InvalidModule(_))
        ));
    }

    #[test]
    fn guarded_unicode_word_prefix_explicitly_rejects_continuation_cover_ranges() {
        let plan = NativeOrderedNfaStartPrefixPlan {
            ranges: [
                NativeOrderedNfaByteRange {
                    start: 0x70,
                    end: 0x80,
                },
                EMPTY_NATIVE_ORDERED_NFA_BYTE_RANGE,
                EMPTY_NATIVE_ORDERED_NFA_BYTE_RANGE,
                EMPTY_NATIVE_ORDERED_NFA_BYTE_RANGE,
            ],
            range_count: 1,
        };
        assert!(native_ordered_nfa_start_prefix_intersects_utf8_continuation(plan));

        let lead = NativeOrderedNfaStartPrefixPlan {
            ranges: [
                NativeOrderedNfaByteRange {
                    start: 0xc0,
                    end: 0xff,
                },
                EMPTY_NATIVE_ORDERED_NFA_BYTE_RANGE,
                EMPTY_NATIVE_ORDERED_NFA_BYTE_RANGE,
                EMPTY_NATIVE_ORDERED_NFA_BYTE_RANGE,
            ],
            range_count: 1,
        };
        assert!(!native_ordered_nfa_start_prefix_intersects_utf8_continuation(lead));
    }

    #[test]
    fn guarded_unicode_word_prefix_enforces_degree_cardinality_and_utf8_lead_bounds() {
        for (cardinality, expected) in [
            (96_u16, false),
            (97, true),
            (128, true),
            (129, false),
            (178, false),
        ] {
            let ranges = guarded_prefix_cardinality_ranges(cardinality, 32);
            let program = guarded_prefix_program(EdgeKind::AssertWordUnicode, &ranges);
            let view = program.native_ordered_nfa_view().unwrap();
            let exact = view.start_prefix_first_set.unwrap();
            assert_eq!(
                exact.iter().map(|word| word.count_ones()).sum::<u32>(),
                u32::from(cardinality),
            );
            assert_eq!(exact[2], 0);
            assert_eq!(selected_start_prefix(&program).is_some(), expected);
        }

        let degree_31 = guarded_prefix_program(
            EdgeKind::AssertWordUnicode,
            &guarded_prefix_cardinality_ranges(97, 31),
        );
        assert!(selected_start_prefix(&degree_31).is_none());

        for continuation_byte in [0x80, 0xbf] {
            let continuation =
                ranges_with_degree(vec![(0, 108), (continuation_byte, continuation_byte)], 32);
            let continuation = guarded_prefix_program(EdgeKind::AssertWordUnicode, &continuation);
            let continuation_view = continuation.native_ordered_nfa_view().unwrap();
            let continuation_exact = continuation_view.start_prefix_first_set.unwrap();
            assert_eq!(
                continuation_exact
                    .iter()
                    .map(|word| word.count_ones())
                    .sum::<u32>(),
                110,
            );
            assert_ne!(continuation_exact[2], 0);
            assert!(continuation_view.start_closure_dispatch.is_none());
            assert!(selected_start_prefix(&continuation).is_none());
        }
    }

    #[test]
    fn guarded_unicode_word_prefix_enforces_exact_128_byte_cover_cap() {
        let five_ranges = |last_end| {
            ranges_with_degree(
                vec![(0, 24), (26, 50), (52, 76), (78, 102), (192, last_end)],
                32,
            )
        };

        let admitted = guarded_prefix_program(EdgeKind::AssertWordUnicode, &five_ranges(218));
        let admitted_view = admitted.native_ordered_nfa_view().unwrap();
        let admitted_exact = admitted_view.start_prefix_first_set.unwrap();
        assert_eq!(
            admitted_exact
                .iter()
                .map(|word| word.count_ones())
                .sum::<u32>(),
            127,
        );
        let admitted_plan = selected_start_prefix(&admitted)
            .expect("the deterministic one-byte merge reaches the exact cover cap");
        assert_eq!(prefix_candidate_bytes(admitted_plan), 128);
        assert_eq!(
            admitted_plan.ranges(),
            &[
                NativeOrderedNfaByteRange { start: 0, end: 50 },
                NativeOrderedNfaByteRange { start: 52, end: 76 },
                NativeOrderedNfaByteRange {
                    start: 78,
                    end: 102,
                },
                NativeOrderedNfaByteRange {
                    start: 192,
                    end: 218,
                },
            ],
        );

        let declined = guarded_prefix_program(EdgeKind::AssertWordUnicode, &five_ranges(219));
        let declined_view = declined.native_ordered_nfa_view().unwrap();
        let declined_exact = declined_view.start_prefix_first_set.unwrap();
        assert_eq!(
            declined_exact
                .iter()
                .map(|word| word.count_ones())
                .sum::<u32>(),
            128,
        );
        let coalesced_129 = NativeOrderedNfaStartPrefixPlan {
            ranges: [
                NativeOrderedNfaByteRange { start: 0, end: 50 },
                NativeOrderedNfaByteRange { start: 52, end: 76 },
                NativeOrderedNfaByteRange {
                    start: 78,
                    end: 102,
                },
                NativeOrderedNfaByteRange {
                    start: 192,
                    end: 219,
                },
            ],
            range_count: 4,
        };
        assert_eq!(prefix_candidate_bytes(coalesced_129), 129);
        for byte in u8::MIN..=u8::MAX {
            let index = usize::from(byte);
            if declined_exact[index / 64] & (1_u64 << (index % 64)) != 0 {
                assert!(native_ordered_nfa_start_prefix_contains(
                    coalesced_129,
                    byte,
                ));
            }
        }
        assert!(selected_start_prefix(&declined).is_none());
    }

    #[test]
    fn guarded_unicode_word_prefix_rejects_a_cover_over_128_bytes() {
        let ranges: Vec<_> = (0_u8..=126)
            .step_by(2)
            .chain((192_u8..=254).step_by(2))
            .chain([255])
            .map(|byte| (byte, byte))
            .collect();
        assert_eq!(ranges.len(), 97);
        let program = guarded_prefix_program(EdgeKind::AssertWordUnicode, &ranges);
        let view = program.native_ordered_nfa_view().unwrap();
        let exact = view.start_prefix_first_set.unwrap();
        assert_eq!(exact.iter().map(|word| word.count_ones()).sum::<u32>(), 97);
        assert_eq!(exact[2], 0);
        assert!(
            derive_native_ordered_nfa_start_prefix_with_candidate_cap(
                exact,
                MAX_NATIVE_ORDERED_NFA_GUARDED_UNICODE_PREFIX_CANDIDATE_BYTES,
            )
            .unwrap()
            .is_none()
        );
        assert!(selected_start_prefix(&program).is_none());
    }

    #[test]
    fn go33484_unicode_dot_exact_178_start_set_remains_unselected() {
        let program = span_program_with_mode(
            r"^.{249}$",
            b'\n',
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let view = program.native_ordered_nfa_view().unwrap();
        let exact = view.start_prefix_first_set.unwrap();
        assert_eq!(exact.iter().map(|word| word.count_ones()).sum::<u32>(), 178);
        assert_eq!(view.raw.edge_kinds[0], EdgeKind::AssertHaystackStart);
        assert!(view.start_closure_dispatch.is_none());
        assert!(selected_start_prefix(&program).is_none());
    }

    #[test]
    fn start_prefix_selection_is_compiler_only_and_deterministic() {
        let program = span_program_with_mode(
            r"a?b?c?d?e?f?g?h?[a-z]+Z",
            b'\n',
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let view = program.native_ordered_nfa_view().unwrap();
        assert!(view.start_prefix_first_set.is_some());
        let first = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        let second = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.layout.start_prefix.unwrap().ranges(),
            &[NativeOrderedNfaByteRange {
                start: b'a',
                end: b'z',
            }]
        );

        let without = NativeOrderedNfaObjectImage::try_build(
            NativeOrderedNfaProgramView {
                start_prefix_first_set: None,
                ..view
            },
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        assert_eq!(first.bytes, without.bytes);
        assert!(without.layout.start_prefix.is_none());
    }

    #[test]
    fn whole_window_width_bounds_are_deterministic_and_do_not_change_object_data() {
        let program = span_program_with_mode(
            r"^.{2,4}$",
            b'\n',
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let view = program.native_ordered_nfa_view().unwrap();
        let expected = WholeWindowWidthBounds {
            minimum: 2,
            maximum: 16,
        };
        assert_eq!(view.whole_window_width_bounds, Some(expected));

        let first = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        let second = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.layout.whole_window_width_bounds, Some(expected));

        let without = NativeOrderedNfaObjectImage::try_build(
            NativeOrderedNfaProgramView {
                whole_window_width_bounds: None,
                ..view
            },
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        assert_eq!(first.bytes, without.bytes);
        assert_eq!(first.layout.object_bytes, without.layout.object_bytes);
        assert!(without.layout.whole_window_width_bounds.is_none());

        let serialized = program.serialize().unwrap();
        let restored = crate::CompiledProgram::deserialize(&serialized).unwrap();
        let restored_view = restored.native_ordered_nfa_view().unwrap();
        assert_eq!(restored_view.whole_window_width_bounds, Some(expected));
        let restored_image = NativeOrderedNfaObjectImage::try_build(restored_view, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(restored_image.bytes, first.bytes);
        assert_eq!(
            restored_image.layout.whole_window_width_bounds,
            Some(expected)
        );
    }

    #[test]
    fn terminal_exact_set_selection_is_deterministic_and_object_byte_inert() {
        let repeated = r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}";
        let program = span_program_with_mode(
            &format!(r"{repeated}[0-24-6]"),
            b'\n',
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let view = program.native_ordered_nfa_view().unwrap();
        let exact = view
            .terminal_exact_set
            .expect("fragmented depth-zero suffix selects exact terminal bitmap");
        assert!(view.terminal_range.is_none());

        let first = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        let second = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(first, second);
        let plan = first
            .terminal_exact_set_plan()
            .unwrap()
            .expect("validated fragmented bitmap is selected");
        assert_eq!(first.terminal_exact_set_words, Some(exact));
        assert_eq!(plan.words(), exact);

        let without = NativeOrderedNfaObjectImage::try_build(
            NativeOrderedNfaProgramView {
                terminal_exact_set: None,
                ..view
            },
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        assert_eq!(first.bytes, without.bytes);
        assert_eq!(first.layout.object_bytes, without.layout.object_bytes);
        assert_eq!(
            first.layout.ordered_edge_dispatch,
            without.layout.ordered_edge_dispatch
        );
        assert!(without.terminal_exact_set_words.is_none());
        assert!(without.terminal_exact_set_plan().unwrap().is_none());

        let serialized = program.serialize().unwrap();
        let restored = crate::CompiledProgram::deserialize(&serialized).unwrap();
        let restored_view = restored.native_ordered_nfa_view().unwrap();
        assert_eq!(restored_view.terminal_exact_set, Some(exact));
        let restored_image = NativeOrderedNfaObjectImage::try_build(restored_view, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(restored_image.bytes, first.bytes);
        assert_eq!(restored_image.terminal_exact_set_words, Some(exact));
        assert_eq!(
            restored_image.terminal_exact_set_plan().unwrap(),
            Some(plan)
        );
    }

    #[test]
    fn terminal_exact_set_validation_rejects_noncanonical_or_overlapping_plans() {
        let repeated = r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}";
        let fragmented = span_program_with_mode(
            &format!(r"{repeated}[0-24-6]"),
            b'\n',
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let fragmented_view = fragmented.native_ordered_nfa_view().unwrap();
        for invalid in [[0_u64; 4], [u64::MAX; 4], membership_words(b'a'..=b'z')] {
            assert!(matches!(
                NativeOrderedNfaObjectImage::try_build(
                    NativeOrderedNfaProgramView {
                        terminal_exact_set: Some(invalid),
                        ..fragmented_view
                    },
                    usize::MAX,
                ),
                Err(ObjectError::InvalidModule(_))
            ));
        }
        let broad_fragmented = membership_words((0_u8..64).chain([65_u8]));
        assert_eq!(
            broad_fragmented
                .iter()
                .map(|word| word.count_ones())
                .sum::<u32>(),
            u32::from(MAX_NATIVE_ORDERED_NFA_TERMINAL_EXACT_SET_CARDINALITY)
                .checked_add(1)
                .expect("terminal exact-set cardinality cap has a successor"),
        );
        assert!(matches!(
            NativeOrderedNfaObjectImage::try_build(
                NativeOrderedNfaProgramView {
                    terminal_exact_set: Some(broad_fragmented),
                    ..fragmented_view
                },
                usize::MAX,
            ),
            Err(ObjectError::InvalidModule(_))
        ));

        let tiny = span_program_with_mode(
            r"[0-24-6]",
            b'\n',
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let tiny_view = tiny.native_ordered_nfa_view().unwrap();
        assert!(tiny_view.raw.edge_kinds.len() < MIN_NATIVE_ORDERED_NFA_TERMINAL_RANGE_EDGES);
        assert!(matches!(
            NativeOrderedNfaObjectImage::try_build(
                NativeOrderedNfaProgramView {
                    terminal_exact_set: Some(membership_words([
                        b'0', b'1', b'2', b'4', b'5', b'6',
                    ])),
                    ..tiny_view
                },
                usize::MAX,
            ),
            Err(ObjectError::InvalidModule(_))
        ));

        let contiguous = span_program_with_mode(
            &format!(r"{repeated}[a-z]"),
            b'\n',
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let contiguous_view = contiguous.native_ordered_nfa_view().unwrap();
        assert!(contiguous_view.terminal_range.is_some());
        assert!(matches!(
            NativeOrderedNfaObjectImage::try_build(
                NativeOrderedNfaProgramView {
                    terminal_exact_set: fragmented_view.terminal_exact_set,
                    ..contiguous_view
                },
                usize::MAX,
            ),
            Err(ObjectError::InvalidModule(_))
        ));
    }

    #[test]
    fn boundary_assertion_cache_requires_dense_exact_kind_reuse() {
        let first = 1_u32;
        let second = 1_u32 << 1;
        assert!(!boundary_assertion_cache_is_profitable(0, 0));
        assert!(!boundary_assertion_cache_is_profitable(3, first));
        assert!(boundary_assertion_cache_is_profitable(4, first));
        assert!(!boundary_assertion_cache_is_profitable(
            4,
            first | second | (1 << 2)
        ));
        assert!(boundary_assertion_cache_is_profitable(4, first | second));
        assert!(boundary_assertion_cache_is_profitable(59, 0x42));
    }

    #[test]
    fn boundary_assertion_cache_selection_is_compiler_only_and_deterministic() {
        let program = span_program(r"(?-u:(?:\ba|b\bcc|dd\beee|ffff\bggggg|h\z))", b'\n');
        let view = program.native_ordered_nfa_view().unwrap();
        let first = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        let second = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        assert!(first.layout.cache_boundary_assertions);
        assert_eq!(first, second);
        assert_eq!(first.layout.assertion_kinds, 0x42);
    }

    #[test]
    fn start_closure_selection_is_deterministic_and_does_not_change_object_bytes() {
        let program = span_program_with_mode(
            r"(?:a?|bc)",
            b'\n',
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let view = program
            .native_ordered_nfa_view()
            .expect("optimizing fallback exposes ordered TNFA");
        let program_view = view
            .start_closure_dispatch
            .expect("branching start retains canonical closure bytecode");
        assert!(!program_view.is_guarded());
        assert!(program_view.len() > 1);

        let first = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        let second = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(first, second);
        let receipt = first
            .layout
            .start_closure_dispatch
            .expect("bounded canonical start closure is selected");
        assert_eq!(receipt.guarded, program_view.is_guarded());
        assert_eq!(receipt.instruction_count, program_view.len());
        assert_eq!(
            receipt.split_edge_visits.checked_add(1),
            Some(program_view.len())
        );
        assert_eq!(first.start_closure_program, Some(program_view));

        let without_view = NativeOrderedNfaProgramView {
            start_closure_dispatch: None,
            ..view
        };
        let without = NativeOrderedNfaObjectImage::try_build(without_view, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(first.bytes, without.bytes);
        assert!(without.layout.start_closure_dispatch.is_none());
        assert!(without.start_closure_program.is_none());
    }

    #[test]
    fn guarded_start_closure_forces_cache_without_changing_object_bytes() {
        let program = span_program_with_mode(
            r"(?-u:(?:\ba|b\bcc|dd\beee|ffff\bggggg|h\z))",
            b'\n',
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let view = program
            .native_ordered_nfa_view()
            .expect("guarded optimizing fallback exposes ordered TNFA");
        let program_view = view
            .start_closure_dispatch
            .expect("assertion-bearing start retains guarded bytecode");
        assert!(program_view.is_guarded());

        let selected = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        let receipt = selected
            .layout
            .start_closure_dispatch
            .expect("bounded guarded start closure is selected");
        assert!(receipt.guarded);
        assert!(selected.layout.cache_boundary_assertions);
        assert_eq!(
            receipt.split_edge_visits.checked_add(1),
            Some(receipt.instruction_count)
        );

        let without = NativeOrderedNfaObjectImage::try_build(
            NativeOrderedNfaProgramView {
                start_closure_dispatch: None,
                ..view
            },
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        assert_eq!(selected.bytes, without.bytes);
        assert!(without.layout.start_closure_dispatch.is_none());
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the synthetic unary split graph uses small bounded test indices"
    )]
    fn unary_split_chain_program(split_count: usize) -> crate::CompiledProgram {
        let mut roles = vec![StateRole::Split; split_count];
        roles.extend([StateRole::Consume, StateRole::Accept]);
        let mut edge_offsets = Vec::with_capacity(roles.len() + 1);
        let mut edge_targets = Vec::with_capacity(split_count + 1);
        let mut edge_kinds = Vec::with_capacity(split_count + 1);
        let mut byte_starts = Vec::with_capacity(split_count + 1);
        let mut byte_ends = Vec::with_capacity(split_count + 1);
        edge_offsets.push(0);
        for index in 0..split_count {
            edge_targets.push(u32::try_from(index + 1).unwrap());
            edge_kinds.push(EdgeKind::Epsilon);
            byte_starts.push(0);
            byte_ends.push(0);
            edge_offsets.push(u32::try_from(edge_targets.len()).unwrap());
        }
        edge_targets.push(u32::try_from(split_count + 1).unwrap());
        edge_kinds.push(EdgeKind::ByteRange);
        byte_starts.push(b'z');
        byte_ends.push(b'z');
        edge_offsets.push(u32::try_from(edge_targets.len()).unwrap());
        edge_offsets.push(u32::try_from(edge_targets.len()).unwrap());
        let raw = RawPlan {
            start: 0,
            roles,
            edge_offsets,
            edge_targets,
            edge_kinds,
            byte_starts,
            byte_ends,
        };
        let automaton = Automaton::from_raw(raw.clone(), CompileLimits::default()).unwrap();
        crate::CompiledProgram::build(
            raw,
            automaton,
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
            usize::MAX,
        )
        .unwrap()
    }

    #[test]
    fn start_prefix_requires_sixteen_authenticated_closure_instructions() {
        let below_program = unary_split_chain_program(14);
        let below_view = below_program
            .native_ordered_nfa_view()
            .expect("15-instruction closure exposes an ordered-NFA view");
        assert_eq!(
            below_view
                .start_closure_dispatch
                .expect("unary split chain retains a closure")
                .len(),
            MIN_NATIVE_ORDERED_NFA_START_PREFIX_CLOSURE_INSTRUCTIONS - 1,
        );
        assert!(below_view.start_prefix_first_set.is_some());
        let below = NativeOrderedNfaObjectImage::try_build(below_view, usize::MAX)
            .unwrap()
            .unwrap();
        assert!(below.layout.start_prefix.is_none());

        let exact_program = unary_split_chain_program(15);
        let exact_view = exact_program
            .native_ordered_nfa_view()
            .expect("16-instruction closure exposes an ordered-NFA view");
        assert_eq!(
            exact_view
                .start_closure_dispatch
                .expect("unary split chain retains a closure")
                .len(),
            MIN_NATIVE_ORDERED_NFA_START_PREFIX_CLOSURE_INSTRUCTIONS,
        );
        let exact = NativeOrderedNfaObjectImage::try_build(exact_view, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(
            exact.layout.start_prefix.unwrap().ranges(),
            &[NativeOrderedNfaByteRange {
                start: b'z',
                end: b'z',
            }],
        );

        let no_closure = NativeOrderedNfaObjectImage::try_build(
            NativeOrderedNfaProgramView {
                start_closure_dispatch: None,
                ..exact_view
            },
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        assert!(no_closure.layout.start_prefix.is_none());
        assert_eq!(exact.bytes, no_closure.bytes);
    }

    #[test]
    fn oversized_start_closure_is_softly_omitted_without_object_changes() {
        let program = unary_split_chain_program(MAX_NATIVE_ORDERED_NFA_START_CLOSURE_INSTRUCTIONS);
        let view = program
            .native_ordered_nfa_view()
            .expect("optimizing fallback exposes ordered TNFA");
        let program_view = view
            .start_closure_dispatch
            .expect("optional chain retains canonical start closure bytecode");
        assert!(
            program_view.len() > MAX_NATIVE_ORDERED_NFA_START_CLOSURE_INSTRUCTIONS,
            "fixture must exercise the compiler text cap"
        );

        let omitted = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        assert!(omitted.layout.start_closure_dispatch.is_none());
        assert!(omitted.start_closure_program.is_none());
        let without = NativeOrderedNfaObjectImage::try_build(
            NativeOrderedNfaProgramView {
                start_closure_dispatch: None,
                ..view
            },
            usize::MAX,
        )
        .unwrap()
        .unwrap();
        assert_eq!(omitted.bytes, without.bytes);
    }

    fn span_program(pattern: &str, line_terminator: u8) -> crate::CompiledProgram {
        span_program_with_mode(
            pattern,
            line_terminator,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        )
    }

    fn span_program_with_mode(
        pattern: &str,
        line_terminator: u8,
        mode: CompileMode,
        determinize_limits: DeterminizeLimits,
    ) -> crate::CompiledProgram {
        let mut profile = RustProfile::default();
        profile.options.line_terminator = line_terminator;
        let parsed = fre_syntax::parse(ParseRequest::rust(
            pattern.to_owned(),
            CompatibilityProfile::RustBytes(profile),
        ))
        .expect("parse target-neutral TNFA test pattern");
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("Rust request returned a non-Rust pattern");
        };
        let raw = fre_lower::lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .expect("lower target-neutral TNFA test pattern")
        .into_plan();
        let automaton = Automaton::from_raw(raw.clone(), CompileLimits::default())
            .expect("validate target-neutral TNFA test graph")
            .with_line_terminator(line_terminator);
        crate::CompiledProgram::build(
            raw,
            automaton,
            OutputContract::Span,
            mode,
            determinize_limits,
            usize::MAX,
        )
        .expect("compile target-neutral TNFA test program")
    }

    fn assert_differential(pattern: &str, line_terminator: u8, haystacks: &[&[u8]]) {
        let program = span_program(pattern, line_terminator);
        let view = program
            .native_ordered_nfa_view()
            .expect("fast Span program exposes ordered TNFA");
        let expected_artifact_identity = view.artifact_identity;
        let mut frozen = FrozenOrderedNfaStorageV1::try_new(
            view,
            limits(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES),
        )
        .expect("freeze ordered TNFA");
        let mut workspace = program.prepare_workspace().expect("prepare K0 workspace");
        for &haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let MatchResult::Span(expected) = program
                        .search_with_workspace(haystack, window, &mut workspace)
                        .expect("portable K0 search")
                    else {
                        panic!("Span program returned a different contract");
                    };
                    let actual = frozen
                        .search_for_test(
                            expected_artifact_identity,
                            haystack,
                            window.start(),
                            window.end(),
                        )
                        .expect("authenticated frozen-table search");
                    assert_eq!(
                        expected, actual,
                        "pattern={pattern:?} haystack={haystack:?} window={window:?}"
                    );
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum AuthCorruption {
        CallerArtifactIdentity,
        ExpectedCacheIdentity,
        GraphReadySeal,
        GraphMagic,
        GraphAbiVersion,
        GraphAbiVersionComplement,
        GraphBytes,
        GraphArtifactIdentity,
        GraphRolesAddress,
        GraphEdgeOffsetsAddress,
        GraphEdgeTargetsAddress,
        GraphEdgeKindsAddress,
        GraphByteStartsAddress,
        GraphByteEndsAddress,
        GraphStateCount,
        GraphEdgeCount,
        GraphZeroWidthEdgeCount,
        GraphClosureSlots,
        GraphStartState,
        GraphAssertionKinds,
        GraphReserved,
        GraphRolesTable,
        GraphEdgeOffsetsTable,
        GraphEdgeTargetsTable,
        GraphEdgeKindsTable,
        GraphByteStartsTable,
        GraphByteEndsTable,
        GraphRolesLength,
        GraphEdgeOffsetsLength,
        GraphEdgeTargetsLength,
        GraphEdgeKindsLength,
        GraphByteStartsLength,
        GraphByteEndsLength,
        ScratchReadySeal,
        ScratchMagic,
        ScratchAbiVersion,
        ScratchAbiVersionComplement,
        ScratchBytes,
        ScratchArtifactIdentity,
        ScratchCacheIdentity,
        ScratchSeenAddress,
        ScratchCurrentAddress,
        ScratchRootsAddress,
        ScratchStackAddress,
        ScratchStateCapacity,
        ScratchRootCapacity,
        ScratchStackCapacity,
        ScratchReserved,
        ScratchCurrentLen,
        ScratchRootsLen,
        ScratchStackLen,
        ScratchPendingValid,
        ScratchControlReserved,
        ScratchSeenLength,
        ScratchCurrentLength,
        ScratchRootsLength,
        ScratchStackLength,
        AccountingDescriptorBytes,
        AccountingScratchBytes,
        AccountingSetupWork,
        AccountingProspectiveHandleBytes,
        AccountingRetainedHandleBytes,
    }

    const AUTH_CORRUPTIONS: &[AuthCorruption] = &[
        AuthCorruption::CallerArtifactIdentity,
        AuthCorruption::ExpectedCacheIdentity,
        AuthCorruption::GraphReadySeal,
        AuthCorruption::GraphMagic,
        AuthCorruption::GraphAbiVersion,
        AuthCorruption::GraphAbiVersionComplement,
        AuthCorruption::GraphBytes,
        AuthCorruption::GraphArtifactIdentity,
        AuthCorruption::GraphRolesAddress,
        AuthCorruption::GraphEdgeOffsetsAddress,
        AuthCorruption::GraphEdgeTargetsAddress,
        AuthCorruption::GraphEdgeKindsAddress,
        AuthCorruption::GraphByteStartsAddress,
        AuthCorruption::GraphByteEndsAddress,
        AuthCorruption::GraphStateCount,
        AuthCorruption::GraphEdgeCount,
        AuthCorruption::GraphZeroWidthEdgeCount,
        AuthCorruption::GraphClosureSlots,
        AuthCorruption::GraphStartState,
        AuthCorruption::GraphAssertionKinds,
        AuthCorruption::GraphReserved,
        AuthCorruption::GraphRolesTable,
        AuthCorruption::GraphEdgeOffsetsTable,
        AuthCorruption::GraphEdgeTargetsTable,
        AuthCorruption::GraphEdgeKindsTable,
        AuthCorruption::GraphByteStartsTable,
        AuthCorruption::GraphByteEndsTable,
        AuthCorruption::GraphRolesLength,
        AuthCorruption::GraphEdgeOffsetsLength,
        AuthCorruption::GraphEdgeTargetsLength,
        AuthCorruption::GraphEdgeKindsLength,
        AuthCorruption::GraphByteStartsLength,
        AuthCorruption::GraphByteEndsLength,
        AuthCorruption::ScratchReadySeal,
        AuthCorruption::ScratchMagic,
        AuthCorruption::ScratchAbiVersion,
        AuthCorruption::ScratchAbiVersionComplement,
        AuthCorruption::ScratchBytes,
        AuthCorruption::ScratchArtifactIdentity,
        AuthCorruption::ScratchCacheIdentity,
        AuthCorruption::ScratchSeenAddress,
        AuthCorruption::ScratchCurrentAddress,
        AuthCorruption::ScratchRootsAddress,
        AuthCorruption::ScratchStackAddress,
        AuthCorruption::ScratchStateCapacity,
        AuthCorruption::ScratchRootCapacity,
        AuthCorruption::ScratchStackCapacity,
        AuthCorruption::ScratchReserved,
        AuthCorruption::ScratchCurrentLen,
        AuthCorruption::ScratchRootsLen,
        AuthCorruption::ScratchStackLen,
        AuthCorruption::ScratchPendingValid,
        AuthCorruption::ScratchControlReserved,
        AuthCorruption::ScratchSeenLength,
        AuthCorruption::ScratchCurrentLength,
        AuthCorruption::ScratchRootsLength,
        AuthCorruption::ScratchStackLength,
        AuthCorruption::AccountingDescriptorBytes,
        AuthCorruption::AccountingScratchBytes,
        AuthCorruption::AccountingSetupWork,
        AuthCorruption::AccountingProspectiveHandleBytes,
        AuthCorruption::AccountingRetainedHandleBytes,
    ];

    fn different_nonzero(value: u64) -> u64 {
        let changed = value.wrapping_add(1);
        if changed == 0 { 1 } else { changed }
    }

    fn consuming_edge(frozen: &FrozenOrderedNfaStorageV1) -> usize {
        frozen
            .edge_kinds
            .iter()
            .position(|&kind| kind == EDGE_BYTE_RANGE)
            .expect("corruption fixture has a consuming edge")
    }

    fn apply_auth_corruption(
        corruption: AuthCorruption,
        frozen: &mut FrozenOrderedNfaStorageV1,
        expected_artifact_identity: &mut [u8; 32],
    ) {
        match corruption {
            AuthCorruption::CallerArtifactIdentity => expected_artifact_identity[0] ^= 1,
            AuthCorruption::ExpectedCacheIdentity => {
                frozen.expected_cache_identity = different_nonzero(frozen.expected_cache_identity);
            }
            AuthCorruption::GraphReadySeal => frozen.descriptor.ready_seal ^= 1,
            AuthCorruption::GraphMagic => frozen.descriptor.magic ^= 1,
            AuthCorruption::GraphAbiVersion => frozen.descriptor.abi_version ^= 1,
            AuthCorruption::GraphAbiVersionComplement => {
                frozen.descriptor.abi_version_complement ^= 1;
            }
            AuthCorruption::GraphBytes => frozen.descriptor.descriptor_bytes ^= 1,
            AuthCorruption::GraphArtifactIdentity => frozen.descriptor.artifact_identity[0] ^= 1,
            AuthCorruption::GraphRolesAddress => frozen.descriptor.roles_address ^= 1,
            AuthCorruption::GraphEdgeOffsetsAddress => frozen.descriptor.edge_offsets_address ^= 1,
            AuthCorruption::GraphEdgeTargetsAddress => frozen.descriptor.edge_targets_address ^= 1,
            AuthCorruption::GraphEdgeKindsAddress => frozen.descriptor.edge_kinds_address ^= 1,
            AuthCorruption::GraphByteStartsAddress => frozen.descriptor.byte_starts_address ^= 1,
            AuthCorruption::GraphByteEndsAddress => frozen.descriptor.byte_ends_address ^= 1,
            AuthCorruption::GraphStateCount => frozen.descriptor.state_count ^= 1,
            AuthCorruption::GraphEdgeCount => frozen.descriptor.edge_count ^= 1,
            AuthCorruption::GraphZeroWidthEdgeCount => {
                frozen.descriptor.zero_width_edge_count ^= 1;
            }
            AuthCorruption::GraphClosureSlots => frozen.descriptor.closure_slots ^= 1,
            AuthCorruption::GraphStartState => {
                frozen.descriptor.start_state = frozen.descriptor.state_count;
            }
            AuthCorruption::GraphAssertionKinds => frozen.descriptor.assertion_kinds ^= 1 << 31,
            AuthCorruption::GraphReserved => frozen.descriptor.reserved[0] = 1,
            AuthCorruption::GraphRolesTable => frozen.roles[0] = u8::MAX,
            AuthCorruption::GraphEdgeOffsetsTable => frozen.edge_offsets[0] = 1,
            AuthCorruption::GraphEdgeTargetsTable => {
                frozen.edge_targets[0] = frozen.descriptor.state_count;
            }
            AuthCorruption::GraphEdgeKindsTable => {
                let edge = consuming_edge(frozen);
                frozen.edge_kinds[edge] = u8::MAX;
            }
            AuthCorruption::GraphByteStartsTable => {
                let edge = consuming_edge(frozen);
                frozen.byte_starts[edge] = frozen.byte_ends[edge].checked_add(1).unwrap();
            }
            AuthCorruption::GraphByteEndsTable => {
                let edge = consuming_edge(frozen);
                frozen.byte_ends[edge] = frozen.byte_starts[edge].checked_sub(1).unwrap();
            }
            AuthCorruption::GraphRolesLength => {
                frozen.roles = frozen.roles[..frozen.roles.len() - 1]
                    .to_vec()
                    .into_boxed_slice();
                frozen.descriptor.roles_address = frozen.roles.as_ptr().expose_provenance();
            }
            AuthCorruption::GraphEdgeOffsetsLength => {
                frozen.edge_offsets = frozen.edge_offsets[..frozen.edge_offsets.len() - 1]
                    .to_vec()
                    .into_boxed_slice();
                frozen.descriptor.edge_offsets_address =
                    frozen.edge_offsets.as_ptr().expose_provenance();
            }
            AuthCorruption::GraphEdgeTargetsLength => {
                frozen.edge_targets = frozen.edge_targets[..frozen.edge_targets.len() - 1]
                    .to_vec()
                    .into_boxed_slice();
                frozen.descriptor.edge_targets_address =
                    frozen.edge_targets.as_ptr().expose_provenance();
            }
            AuthCorruption::GraphEdgeKindsLength => {
                frozen.edge_kinds = frozen.edge_kinds[..frozen.edge_kinds.len() - 1]
                    .to_vec()
                    .into_boxed_slice();
                frozen.descriptor.edge_kinds_address =
                    frozen.edge_kinds.as_ptr().expose_provenance();
            }
            AuthCorruption::GraphByteStartsLength => {
                frozen.byte_starts = frozen.byte_starts[..frozen.byte_starts.len() - 1]
                    .to_vec()
                    .into_boxed_slice();
                frozen.descriptor.byte_starts_address =
                    frozen.byte_starts.as_ptr().expose_provenance();
            }
            AuthCorruption::GraphByteEndsLength => {
                frozen.byte_ends = frozen.byte_ends[..frozen.byte_ends.len() - 1]
                    .to_vec()
                    .into_boxed_slice();
                frozen.descriptor.byte_ends_address = frozen.byte_ends.as_ptr().expose_provenance();
            }
            AuthCorruption::ScratchReadySeal => frozen.scratch.descriptor.ready_seal ^= 1,
            AuthCorruption::ScratchMagic => frozen.scratch.descriptor.magic ^= 1,
            AuthCorruption::ScratchAbiVersion => frozen.scratch.descriptor.abi_version ^= 1,
            AuthCorruption::ScratchAbiVersionComplement => {
                frozen.scratch.descriptor.abi_version_complement ^= 1;
            }
            AuthCorruption::ScratchBytes => frozen.scratch.descriptor.scratch_bytes ^= 1,
            AuthCorruption::ScratchArtifactIdentity => {
                frozen.scratch.descriptor.artifact_identity[0] ^= 1;
            }
            AuthCorruption::ScratchCacheIdentity => {
                frozen.scratch.descriptor.cache_identity =
                    different_nonzero(frozen.scratch.descriptor.cache_identity);
            }
            AuthCorruption::ScratchSeenAddress => frozen.scratch.descriptor.seen_address ^= 1,
            AuthCorruption::ScratchCurrentAddress => frozen.scratch.descriptor.current_address ^= 1,
            AuthCorruption::ScratchRootsAddress => frozen.scratch.descriptor.roots_address ^= 1,
            AuthCorruption::ScratchStackAddress => frozen.scratch.descriptor.stack_address ^= 1,
            AuthCorruption::ScratchStateCapacity => frozen.scratch.descriptor.state_capacity ^= 1,
            AuthCorruption::ScratchRootCapacity => frozen.scratch.descriptor.root_capacity ^= 1,
            AuthCorruption::ScratchStackCapacity => frozen.scratch.descriptor.stack_capacity ^= 1,
            AuthCorruption::ScratchReserved => frozen.scratch.descriptor.reserved = 1,
            AuthCorruption::ScratchCurrentLen => {
                frozen.scratch.descriptor.current_len = frozen.scratch.seen.len() + 1;
            }
            AuthCorruption::ScratchRootsLen => {
                frozen.scratch.descriptor.roots_len = frozen.scratch.roots.len() + 1;
            }
            AuthCorruption::ScratchStackLen => {
                frozen.scratch.descriptor.stack_len = frozen.scratch.stack.len() + 1;
            }
            AuthCorruption::ScratchPendingValid => frozen.scratch.descriptor.pending_valid = 2,
            AuthCorruption::ScratchControlReserved => {
                frozen.scratch.descriptor.control_reserved = 1;
            }
            AuthCorruption::ScratchSeenLength => {
                frozen.scratch.seen = frozen.scratch.seen[..frozen.scratch.seen.len() - 1]
                    .to_vec()
                    .into_boxed_slice();
                frozen.scratch.descriptor.seen_address =
                    frozen.scratch.seen.as_ptr().expose_provenance();
            }
            AuthCorruption::ScratchCurrentLength => {
                frozen.scratch.current = frozen.scratch.current[..frozen.scratch.current.len() - 1]
                    .to_vec()
                    .into_boxed_slice();
                frozen.scratch.descriptor.current_address =
                    frozen.scratch.current.as_ptr().expose_provenance();
            }
            AuthCorruption::ScratchRootsLength => {
                frozen.scratch.roots = frozen.scratch.roots[..frozen.scratch.roots.len() - 1]
                    .to_vec()
                    .into_boxed_slice();
                frozen.scratch.descriptor.roots_address =
                    frozen.scratch.roots.as_ptr().expose_provenance();
            }
            AuthCorruption::ScratchStackLength => {
                frozen.scratch.stack = frozen.scratch.stack[..frozen.scratch.stack.len() - 1]
                    .to_vec()
                    .into_boxed_slice();
                frozen.scratch.descriptor.stack_address =
                    frozen.scratch.stack.as_ptr().expose_provenance();
            }
            AuthCorruption::AccountingDescriptorBytes => frozen.accounting.descriptor_bytes ^= 1,
            AuthCorruption::AccountingScratchBytes => frozen.accounting.scratch_bytes ^= 1,
            AuthCorruption::AccountingSetupWork => frozen.accounting.setup_work ^= 1,
            AuthCorruption::AccountingProspectiveHandleBytes => {
                frozen.accounting.prospective_handle_bytes ^= 1;
            }
            AuthCorruption::AccountingRetainedHandleBytes => {
                frozen.accounting.retained_handle_bytes ^= 1;
            }
        }
    }

    #[test]
    fn edge_encoding_and_every_word_assertion_variant_are_exact() {
        let kinds = [
            EdgeKind::Epsilon,
            EdgeKind::ByteRange,
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
        for (encoded, kind) in kinds.into_iter().enumerate() {
            let encoded = u8::try_from(encoded).unwrap();
            assert_eq!(encode_edge_kind(kind), Some(encoded));
            assert_eq!(decode_edge_kind(encoded), Some(kind));
        }
        assert_eq!(decode_edge_kind(20), None);
        assert_eq!(decode_edge_kind(u8::MAX), None);

        let ascii_kinds = [
            EDGE_ASSERT_WORD_ASCII,
            EDGE_ASSERT_WORD_ASCII_NEGATE,
            EDGE_ASSERT_WORD_START_ASCII,
            EDGE_ASSERT_WORD_END_ASCII,
            EDGE_ASSERT_WORD_START_HALF_ASCII,
            EDGE_ASSERT_WORD_END_HALF_ASCII,
        ];
        let ascii_contexts: &[(&[u8], usize, [bool; 6])] = &[
            (b"  ", 1, [false, true, false, false, true, true]),
            (b" a", 1, [true, false, true, false, true, false]),
            (b"a ", 1, [true, false, false, true, false, true]),
            (b"aa", 1, [false, true, false, false, false, false]),
        ];
        for &(haystack, position, expected) in ascii_contexts {
            for (kind, expected) in ascii_kinds.into_iter().zip(expected) {
                assert_eq!(
                    zero_width_enabled(b'\n', kind, haystack, position),
                    Some(expected),
                    "ASCII kind={kind} haystack={haystack:?} position={position}"
                );
            }
        }

        let unicode_kinds = [
            EDGE_ASSERT_WORD_UNICODE,
            EDGE_ASSERT_WORD_UNICODE_NEGATE,
            EDGE_ASSERT_WORD_START_UNICODE,
            EDGE_ASSERT_WORD_END_UNICODE,
            EDGE_ASSERT_WORD_START_HALF_UNICODE,
            EDGE_ASSERT_WORD_END_HALF_UNICODE,
        ];
        let unicode_contexts: &[(&[u8], usize, [bool; 6])] = &[
            (b"  ", 1, [false, true, false, false, true, true]),
            (" α".as_bytes(), 1, [true, false, true, false, true, false]),
            ("α ".as_bytes(), 2, [true, false, false, true, false, true]),
            (
                "αβ".as_bytes(),
                2,
                [false, true, false, false, false, false],
            ),
            (&[0xFF, b'a'], 1, [true, false, true, false, false, false]),
            (&[b'a', 0xFF], 1, [true, false, false, true, false, false]),
            (&[0xFF, b' '], 1, [false, false, false, false, false, true]),
            (&[b' ', 0xFF], 1, [false, false, false, false, true, false]),
            (&[0xFF, 0xFE], 1, [false, false, false, false, false, false]),
        ];
        for &(haystack, position, expected) in unicode_contexts {
            for (kind, expected) in unicode_kinds.into_iter().zip(expected) {
                assert_eq!(
                    zero_width_enabled(b'\n', kind, haystack, position),
                    Some(expected),
                    "Unicode kind={kind} haystack={haystack:?} position={position}"
                );
            }
        }
    }

    #[test]
    fn fixed_layout_is_explicit_and_target_native() {
        assert_eq!(FROZEN_ORDERED_NFA_THREAD_V1_BYTES, 16);
        assert_eq!(FROZEN_ORDERED_NFA_THREAD_V1_STATE_OFFSET, 0);
        assert_eq!(FROZEN_ORDERED_NFA_THREAD_V1_START_OFFSET, 8);
        assert_eq!(FROZEN_ORDERED_NFA_DESCRIPTOR_V1_READY_SEAL_OFFSET, 0);
        assert_eq!(FROZEN_ORDERED_NFA_SCRATCH_V1_READY_SEAL_OFFSET, 0);
        assert_eq!(
            FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ABI_VERSION_COMPLEMENT_OFFSET,
            FROZEN_ORDERED_NFA_DESCRIPTOR_V1_ABI_VERSION_OFFSET + 4
        );
        assert_eq!(
            FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION_COMPLEMENT_OFFSET,
            FROZEN_ORDERED_NFA_SCRATCH_V1_ABI_VERSION_OFFSET + 4
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "V2 canonical copying and the exact V1 cap fallback form one boundary test"
    )]
    fn ordered_edge_dispatch_v2_copies_canonical_tables_and_cap_falls_back_to_v1() {
        let program = span_program_with_mode(
            r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}(?-u:[\x80-\xFF])\b",
            b'\n',
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let view = NativeOrderedNfaProgramView {
            terminal_range: None,
            ..program.native_ordered_nfa_view().unwrap()
        };
        let dispatch = view
            .ordered_edge_dispatch
            .expect("wide consuming rows retain their canonical dispatch");
        let image = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        let layout = image
            .layout
            .ordered_edge_dispatch
            .expect("the exact sidecar fits the V2 object");
        let read_u32 =
            |offset: usize| u32::from_le_bytes(image.bytes[offset..offset + 4].try_into().unwrap());
        let read_u64 =
            |offset: usize| u64::from_le_bytes(image.bytes[offset..offset + 8].try_into().unwrap());
        assert_eq!(read_u64(0), ORDERED_NFA_OBJECT_V2_READY_SEAL);
        assert_eq!(read_u64(8), ORDERED_NFA_OBJECT_V2_MAGIC);
        assert_eq!(read_u32(16), ORDERED_NFA_OBJECT_V2_ABI_VERSION);
        assert_eq!(read_u32(20), !ORDERED_NFA_OBJECT_V2_ABI_VERSION);
        assert_eq!(
            read_u32(28),
            ORDERED_NFA_OBJECT_V1_FLAG_UNICODE | ORDERED_NFA_OBJECT_V2_FLAG_ORDERED_EDGE_DISPATCH
        );
        assert_eq!(
            &image.bytes
                [ORDERED_NFA_OBJECT_V1_IDENTITY_OFFSET..ORDERED_NFA_OBJECT_V1_IDENTITY_OFFSET + 32],
            &view.artifact_identity
        );
        for (field, expected) in [
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_ROWS_OFFSET_FIELD,
                layout.rows_offset,
            ),
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_BYTE_MAP_OFFSET_FIELD,
                layout.byte_map_offset,
            ),
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_METADATA_OFFSET_FIELD,
                layout.metadata_offset,
            ),
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_TRANSITIONS_OFFSET_FIELD,
                layout.transitions_offset,
            ),
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_ADMITTED_ROWS_FIELD,
                layout.admitted_rows,
            ),
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_METADATA_COUNT_FIELD,
                layout.metadata_count,
            ),
            (
                ORDERED_NFA_EDGE_DISPATCH_V1_TRANSITION_COUNT_FIELD,
                layout.transition_count,
            ),
        ] {
            assert_eq!(
                read_u32(layout.descriptor_offset + field),
                u32::try_from(expected).unwrap()
            );
        }
        assert_eq!(
            read_u32(layout.descriptor_offset + ORDERED_NFA_EDGE_DISPATCH_V1_CONTROL_FIELD),
            layout.encoding.control()
        );
        for state in 0..dispatch.state_count() {
            let expected = dispatch.row(state).map_or(
                [u32::MAX, 0],
                fre_automata::NativeOrderedEdgeRowDescriptor::compiler_private_encoded,
            );
            assert_eq!(read_u32(layout.rows_offset + state * 8), expected[0]);
            assert_eq!(read_u32(layout.rows_offset + state * 8 + 4), expected[1]);
        }
        assert_eq!(
            &image.bytes
                [layout.byte_map_offset..layout.byte_map_offset + dispatch.segment_by_byte().len()],
            dispatch.segment_by_byte()
        );
        for (index, &expected) in dispatch.segment_metadata().iter().enumerate() {
            assert_eq!(read_u32(layout.metadata_offset + index * 4), expected);
        }
        let NativeOrderedEdgeTransitions::Direct32 {
            transitions,
            target_bits,
        } = dispatch.transitions()
        else {
            panic!("repeated sparse rows should use direct32 transitions");
        };
        assert_eq!(
            layout.encoding,
            NativeOrderedEdgeEncoding::Direct32 { target_bits }
        );
        for (index, &transition) in transitions.iter().enumerate() {
            assert_eq!(
                read_u32(layout.transitions_offset + index * 4),
                transition.compiler_private_encoded()
            );
        }
        assert_eq!(
            NativeOrderedNfaObjectImage::try_build(view, image.bytes.len())
                .unwrap()
                .unwrap(),
            image,
        );

        let scalar_view = NativeOrderedNfaProgramView {
            ordered_edge_dispatch: None,
            ..view
        };
        let scalar = NativeOrderedNfaObjectImage::try_build(scalar_view, usize::MAX)
            .unwrap()
            .unwrap();
        assert!(scalar.layout.ordered_edge_dispatch.is_none());
        assert_eq!(
            u64::from_le_bytes(scalar.bytes[0..8].try_into().unwrap()),
            ORDERED_NFA_OBJECT_V1_READY_SEAL
        );
        let capped = NativeOrderedNfaObjectImage::try_build(view, image.bytes.len() - 1)
            .unwrap()
            .unwrap();
        assert_eq!(capped, scalar);
        assert_eq!(
            NativeOrderedNfaObjectImage::try_build(view, scalar.bytes.len())
                .unwrap()
                .unwrap(),
            scalar
        );
        assert!(
            NativeOrderedNfaObjectImage::try_build(view, scalar.bytes.len() - 1)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "V3 composition and exact V1/V2 preservation share one wire boundary"
    )]
    fn terminal_range_v3_uses_descriptor_tail_and_preserves_v1_v2_payloads() {
        let program = span_program_with_mode(
            r"[0-24-68-9A-CE-GI-KM-OQ-SU-WY-Za-ce-gi-km-oq-su-wy-z]{100,}(?-u:[\x80-\xFF])\b",
            b'\n',
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let view = program.native_ordered_nfa_view().unwrap();
        let terminal_range = NativeOrderedNfaTerminalRangeV1 {
            start: 0x80,
            end: 0xff,
            reverse_depth: 0,
        };
        assert_eq!(view.terminal_range, Some(terminal_range));
        assert!(view.ordered_edge_dispatch.is_some());

        let v3 = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .unwrap();
        let read_u32 =
            |offset: usize| u32::from_le_bytes(v3.bytes[offset..offset + 4].try_into().unwrap());
        let read_u64 =
            |offset: usize| u64::from_le_bytes(v3.bytes[offset..offset + 8].try_into().unwrap());
        assert_eq!(read_u64(0), ORDERED_NFA_OBJECT_V3_READY_SEAL);
        assert_eq!(read_u64(8), ORDERED_NFA_OBJECT_V3_MAGIC);
        assert_eq!(read_u32(16), ORDERED_NFA_OBJECT_V3_ABI_VERSION);
        assert_eq!(read_u32(20), !ORDERED_NFA_OBJECT_V3_ABI_VERSION);
        assert_eq!(
            read_u32(28),
            ORDERED_NFA_OBJECT_V1_FLAG_UNICODE
                | ORDERED_NFA_OBJECT_V2_FLAG_ORDERED_EDGE_DISPATCH
                | ORDERED_NFA_OBJECT_V3_FLAG_TERMINAL_RANGE
        );
        assert_eq!(
            v3.bytes[ORDERED_NFA_OBJECT_V3_TERMINAL_RANGE_START_FIELD],
            terminal_range.start
        );
        assert_eq!(
            v3.bytes[ORDERED_NFA_OBJECT_V3_TERMINAL_RANGE_END_FIELD],
            terminal_range.end
        );
        assert_eq!(
            v3.bytes[ORDERED_NFA_OBJECT_V3_TERMINAL_RANGE_REVERSE_DEPTH_FIELD],
            terminal_range.reverse_depth
        );
        assert_eq!(v3.layout.terminal_range, Some(terminal_range));

        let v2_view = NativeOrderedNfaProgramView {
            terminal_range: None,
            ..view
        };
        let v2 = NativeOrderedNfaObjectImage::try_build(v2_view, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(v3.bytes.len(), v2.bytes.len());
        assert_eq!(
            v3.layout.ordered_edge_dispatch,
            v2.layout.ordered_edge_dispatch
        );
        assert_eq!(&v3.bytes[32..125], &v2.bytes[32..125]);
        assert_eq!(&v3.bytes[128..], &v2.bytes[128..]);
        assert_eq!(
            u64::from_le_bytes(v2.bytes[0..8].try_into().unwrap()),
            ORDERED_NFA_OBJECT_V2_READY_SEAL
        );
        assert_eq!(&v2.bytes[125..128], &[0, 0, 0]);

        let v3_scalar_view = NativeOrderedNfaProgramView {
            ordered_edge_dispatch: None,
            ..view
        };
        let v3_scalar = NativeOrderedNfaObjectImage::try_build(v3_scalar_view, usize::MAX)
            .unwrap()
            .unwrap();
        let v1_view = NativeOrderedNfaProgramView {
            terminal_range: None,
            ..v3_scalar_view
        };
        let v1 = NativeOrderedNfaObjectImage::try_build(v1_view, usize::MAX)
            .unwrap()
            .unwrap();
        assert_eq!(v3_scalar.bytes.len(), v1.bytes.len());
        assert_eq!(&v3_scalar.bytes[32..125], &v1.bytes[32..125]);
        assert_eq!(&v3_scalar.bytes[128..], &v1.bytes[128..]);
        assert_eq!(
            u64::from_le_bytes(v1.bytes[0..8].try_into().unwrap()),
            ORDERED_NFA_OBJECT_V1_READY_SEAL
        );
        assert_eq!(&v1.bytes[125..128], &[0, 0, 0]);
        assert_eq!(
            NativeOrderedNfaObjectImage::try_build(view, v3_scalar.bytes.len())
                .unwrap()
                .unwrap(),
            v3_scalar
        );

        for invalid in [
            NativeOrderedNfaTerminalRangeV1 {
                start: 2,
                end: 1,
                reverse_depth: 0,
            },
            NativeOrderedNfaTerminalRangeV1 {
                start: u8::MIN,
                end: u8::MAX,
                reverse_depth: 0,
            },
            NativeOrderedNfaTerminalRangeV1 {
                start: b'a',
                end: b'z',
                reverse_depth: 1,
            },
        ] {
            let invalid_view = NativeOrderedNfaProgramView {
                terminal_range: Some(invalid),
                ..v1_view
            };
            assert!(matches!(
                NativeOrderedNfaObjectImage::try_build(invalid_view, usize::MAX),
                Err(ObjectError::InvalidModule(_))
            ));
        }
    }

    #[test]
    fn construction_receipts_and_one_below_total_cap_are_exact() {
        let program = span_program(r"(?:ab|a)b?", b'\n');
        let view = program.native_ordered_nfa_view().unwrap();
        let frozen = FrozenOrderedNfaStorageV1::try_new(
            view,
            limits(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES),
        )
        .unwrap();
        let accounting = frozen.accounting();
        assert_eq!(
            accounting.prospective_handle_bytes(),
            accounting.retained_handle_bytes()
        );
        assert_eq!(
            accounting.retained_handle_bytes(),
            accounting.scratch_bytes()
        );
        assert!(accounting.setup_work() > 0);
        assert!(
            FrozenOrderedNfaStorageV1::try_new(
                view,
                limits(accounting.prospective_handle_bytes() - 1),
            )
            .is_none()
        );
        assert!(FrozenOrderedNfaStorageV1::try_new(
            view,
            limits(accounting.prospective_handle_bytes()),
        )
        .is_some());
    }

    #[test]
    fn prepared_scratch_owner_has_exact_independent_caps_and_no_graph_owner() {
        let program = span_program(r"(?:ab|a)b?", b'\n');
        let view = program.native_ordered_nfa_view().unwrap();
        let reference = FrozenOrderedNfaStorageV1::try_new(
            view,
            limits(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES),
        )
        .unwrap();
        let expected = reference.accounting();
        drop(reference);

        let exact = FrozenOrderedNfaPreparedScratchV1::try_new(
            view,
            limits(expected.retained_handle_bytes()),
        )
        .unwrap();
        assert_eq!(exact.accounting(), expected);
        assert_eq!(exact.artifact_identity(), view.artifact_identity);
        assert_ne!(exact.cache_identity(), 0);
        assert!(exact.authenticate().is_some());

        let mut constrained = limits(expected.retained_handle_bytes() - 1);
        assert!(FrozenOrderedNfaPreparedScratchV1::try_new(view, constrained).is_none());
        constrained = limits(expected.retained_handle_bytes());
        constrained.max_scratch_bytes = expected.scratch_bytes() - 1;
        assert!(FrozenOrderedNfaPreparedScratchV1::try_new(view, constrained).is_none());
        constrained = limits(expected.retained_handle_bytes());
        constrained.max_setup_work = expected.setup_work() - 1;
        assert!(FrozenOrderedNfaPreparedScratchV1::try_new(view, constrained).is_none());
    }

    #[test]
    fn construction_softly_refuses_each_component_cap() {
        let program = span_program(r"(?:ab|a)b?", b'\n');
        let view = program.native_ordered_nfa_view().unwrap();
        let mut constrained = limits(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES);
        constrained.max_descriptor_bytes = 0;
        assert!(FrozenOrderedNfaStorageV1::try_new(view, constrained).is_none());
        let mut constrained = limits(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES);
        constrained.max_scratch_bytes = 0;
        assert!(FrozenOrderedNfaStorageV1::try_new(view, constrained).is_none());
        let exact = FrozenOrderedNfaStorageV1::try_new(
            view,
            limits(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES),
        )
        .unwrap()
        .accounting();
        let mut constrained = limits(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES);
        constrained.max_setup_work = exact.setup_work() - 1;
        assert!(FrozenOrderedNfaStorageV1::try_new(view, constrained).is_none());
        constrained.max_setup_work = exact.setup_work();
        assert!(FrozenOrderedNfaStorageV1::try_new(view, constrained).is_some());
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the synthetic chain has fixed dimensions below every u32 and structural ceiling"
    )]
    fn immutable_descriptor_cap_admits_large_graph_without_expanding_scratch_cap() {
        const EDGES: usize = 180_000;
        const OLD_DESCRIPTOR_CAP: usize = 2 * 1024 * 1024;

        let mut roles = vec![StateRole::Consume; EDGES];
        roles.push(StateRole::Accept);
        let mut edge_offsets = (0..=EDGES)
            .map(|offset| u32::try_from(offset).unwrap())
            .collect::<Vec<_>>();
        edge_offsets.push(u32::try_from(EDGES).unwrap());
        let raw = RawPlan {
            start: 0,
            roles,
            edge_offsets,
            edge_targets: (1..=EDGES)
                .map(|target| u32::try_from(target).unwrap())
                .collect(),
            edge_kinds: vec![EdgeKind::ByteRange; EDGES],
            byte_starts: vec![b'a'; EDGES],
            byte_ends: vec![b'a'; EDGES],
        };
        let view = NativeOrderedNfaProgramView {
            output: OutputContract::Span,
            raw: &raw,
            whole_window_width_bounds: None,
            start_prefix_first_set: None,
            ordered_edge_dispatch: None,
            start_closure_dispatch: None,
            terminal_exact_set: None,
            terminal_range: None,
            line_terminator: b'\n',
            artifact_identity: [7; 32],
        };
        let image = NativeOrderedNfaObjectImage::try_build(view, usize::MAX)
            .unwrap()
            .expect("four-MiB immutable descriptor envelope");
        assert!(image.bytes.len() > OLD_DESCRIPTOR_CAP);
        assert!(image.bytes.len() <= FROZEN_ORDERED_NFA_V1_MAX_DESCRIPTOR_BYTES);
        drop(image);

        let owner = FrozenOrderedNfaPreparedScratchV1::try_new(
            view,
            limits(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES),
        )
        .expect("large immutable graph still fits the unchanged scratch envelope");
        assert!(owner.accounting().descriptor_bytes() > OLD_DESCRIPTOR_CAP);
        assert!(owner.accounting().scratch_bytes() <= FROZEN_ORDERED_NFA_V1_MAX_SCRATCH_BYTES);
        drop(owner);

        let mut old = limits(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES);
        old.max_descriptor_bytes = OLD_DESCRIPTOR_CAP;
        assert!(FrozenOrderedNfaPreparedScratchV1::try_new(view, old).is_none());
    }

    #[test]
    fn construction_softly_refuses_non_span_view_variant() {
        let program = span_program(r"a+", b'\n');
        let span = program.native_ordered_nfa_view().unwrap();
        let count = NativeOrderedNfaProgramView {
            output: OutputContract::Exists,
            ..span
        };
        assert!(
            FrozenOrderedNfaStorageV1::try_new(
                count,
                limits(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES),
            )
            .is_none()
        );
    }

    #[test]
    fn descriptor_authentication_precedes_source_and_scratch_mutation() {
        let program = span_program(r"a+", b'\n');
        let mut frozen = FrozenOrderedNfaStorageV1::try_new(
            program.native_ordered_nfa_view().unwrap(),
            limits(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES),
        )
        .unwrap();
        let expected_artifact_identity = frozen.artifact_identity();
        frozen.descriptor.magic ^= 1;
        let before = *frozen.scratch.descriptor;
        assert_eq!(
            frozen.search_for_test(expected_artifact_identity, b"aaaa", 0, 4),
            None
        );
        assert_eq!(*frozen.scratch.descriptor, before);
    }

    #[test]
    fn every_authenticated_corruption_refuses_without_mutating_scratch() {
        let program = span_program(r"(?:a+|(?-u:\b))", b'\n');
        let view = program.native_ordered_nfa_view().unwrap();
        for &corruption in AUTH_CORRUPTIONS {
            let mut expected_artifact_identity = view.artifact_identity;
            let mut frozen = FrozenOrderedNfaStorageV1::try_new(
                view,
                limits(DEFAULT_FROZEN_ORDERED_NFA_V1_MAX_HANDLE_BYTES),
            )
            .unwrap();
            apply_auth_corruption(corruption, &mut frozen, &mut expected_artifact_identity);
            let descriptor_before = *frozen.scratch.descriptor;
            let seen_before = frozen.scratch.seen.clone();
            let current_before = frozen.scratch.current.clone();
            let roots_before = frozen.scratch.roots.clone();
            let stack_before = frozen.scratch.stack.clone();
            assert_eq!(
                frozen.search_for_test(expected_artifact_identity, b"aaaa", 0, 4),
                None,
                "accepted {corruption:?}"
            );
            assert_eq!(
                *frozen.scratch.descriptor, descriptor_before,
                "mutated scratch control after {corruption:?}"
            );
            assert_eq!(
                frozen.scratch.seen, seen_before,
                "mutated seen after {corruption:?}"
            );
            assert_eq!(
                frozen.scratch.current, current_before,
                "mutated current after {corruption:?}"
            );
            assert_eq!(
                frozen.scratch.roots, roots_before,
                "mutated roots after {corruption:?}"
            );
            assert_eq!(
                frozen.scratch.stack, stack_before,
                "mutated stack after {corruption:?}"
            );
        }
    }

    #[test]
    fn frozen_tables_match_k0_priority_nullable_and_pending() {
        assert_differential(
            r"(?:a.*?b|a.*b|(?:ab|a)b?)",
            b'\n',
            &[b"", b"a", b"ab", b"axxbxxb", b"zzabzz", b"aaab"],
        );
        assert_differential(r"(?:a*?|b)", b'\n', &[b"", b"b", b"aaa", b"zaaa", b"bbb"]);
    }

    #[test]
    fn frozen_tables_match_every_byte_local_assertion_family() {
        assert_differential(
            r"(?:\Aab\z|(?m:^ab$)|(?mR:^ab$)|(?-u:\bab\b))",
            b'\n',
            &[
                b"ab",
                b"x ab y",
                b"ab\nxx",
                b"xx\nab\n",
                b"xx\r\nab\r\n",
                b"_ab_",
            ],
        );
        assert_differential(
            r"(?m:^ab$)",
            b';',
            &[b"ab", b"xx;ab;yy", b"xx\nab\nyy", b";ab;"],
        );
    }

    #[test]
    fn frozen_tables_match_unicode_assertions_on_arbitrary_bytes() {
        assert_differential(
            r"\b(?:\w+?)\b",
            b'\n',
            &[
                b"",
                b"abc",
                "αβ x".as_bytes(),
                &[0xFF, b'a', b' ', b'z'],
                &[0xC0, 0x80, b'a'],
                &[0xED, 0xA0, 0x80, b'a'],
                &[0xF0, 0x9F, 0x92],
                &[b'a', 0x80, b'b'],
            ],
        );
    }
}
