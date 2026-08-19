use core::{marker::PhantomData, mem::size_of, ops::Deref};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, OnceLock,
};

use fre_simd_kernels::{
    AsciiByteSet, AsciiByteSetClassifier, AsciiByteSetNonMemberScanner,
    AsciiSelection, ByteSetClassifier, ASCII_CLASSIFIER_BUILD_WORK,
    ASCII_NONMEMBER_RUN_SCANNER_BUILD_WORK,
};
#[cfg(any(
    test,
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
))]
use fre_simd_kernels::{AsciiByteSetRunScanner, ASCII_RUN_SCANNER_BUILD_WORK};

use crate::{
    CompileError, MalformedPlan, Operation, ResourceKind, SearchError, TypedPlan,
    WorkspaceLayout, WorkspaceLimits,
};
use crate::K0Workspace;
use crate::{
    EpsilonClosureDispatchAllocationError,
    OrderedEdgeDispatchAllocationError, ordered_edge_dispatch::OrderedEdgeDispatch,
};
use crate::epsilon_closure_dispatch::{
    EpsilonClosureDispatch, EpsilonClosureStartProgram,
};

static NEXT_AUTOMATON_IDENTITY: AtomicU64 = AtomicU64::new(1);

const BYTE_CLASS_DOMAIN_SIZE: usize = 256;
// One bounded pass records the at-most-two boundary effects of every edge,
// including the kind check for zero-width edges.
const BYTE_CLASS_BOUNDARY_WORK_PER_EDGE: usize = 1;
// One bounded pass emits the class of every byte.
const BYTE_CLASS_EMISSION_WORK: usize = BYTE_CLASS_DOMAIN_SIZE;

fn next_automaton_identity() -> u64 {
    NEXT_AUTOMATON_IDENTITY
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
            identity.checked_add(1)
        })
        .unwrap_or_else(|_| panic!("automaton identity space exhausted"))
}

/// Number of exact consumed-byte positions in the primary bounded start-filter
/// tier. Any of offsets zero through thirty-one may supply the primary scanner
/// and at most one other primary-tier position may supply a Guard or Probe.
pub(crate) const START_FILTER_POSITION_COUNT: usize = 32;
/// Largest consumed-byte offset inspected by the bounded start filter.
pub(crate) const START_FILTER_MAX_OFFSET: usize = START_FILTER_POSITION_COUNT - 1;
/// Number of exact consumed-byte positions in the optional second proof tier.
///
/// Giving each tier the same width is a source-independent geometric policy:
/// the first tier keeps all existing choices stable, while the second tier may
/// retain one additional post-Guard Probe without privileging any one offset.
pub(crate) const START_FILTER_DEEP_POSITION_COUNT: usize = START_FILTER_POSITION_COUNT;
/// Total exact-position capacity of both bounded proof tiers.
pub(crate) const START_FILTER_PROOF_POSITION_COUNT: usize =
    START_FILTER_POSITION_COUNT + START_FILTER_DEEP_POSITION_COUNT;
/// Largest consumed-byte offset represented by either bounded proof tier.
pub(crate) const START_FILTER_PROOF_MAX_OFFSET: usize =
    START_FILTER_PROOF_POSITION_COUNT - 1;
/// Maximum secondary exact-position filters retained by one immutable proof.
pub(crate) const START_FILTER_MAX_GUARDS: usize = 2;
/// Maximum charged secondary classifications of one source position. A
/// block-local Guard intersection may classify a lane once in its complete
/// SIMD block and conservatively recheck a retained survivor as a scalar
/// candidate on a later engine restart; an independently retained deep Probe
/// may then classify that Guard survivor once more.
const START_FILTER_MAX_SECONDARY_CHECKS_PER_POSITION: usize =
    START_FILTER_MAX_GUARDS.saturating_add(1);
/// Exact abstract work to count the members in all four byte-bitmap words.
pub(crate) const BYTE_START_BITMAP_POPULATION_WORK: usize = 4;
/// Exact abstract work to extract one small-scanner member from the bitmap.
pub(crate) const BYTE_START_MEMBER_EXTRACTION_WORK: usize = 1;
/// Largest cardinality represented by direct `memchr` scanners.
pub(crate) const BYTE_START_SMALL_MAX_MEMBERS: usize = 3;
/// Exact abstract work to inspect all four bitmap words for one inclusive
/// range after the member cardinality is known.
pub(crate) const BYTE_START_RANGE_DETECTION_WORK: usize = 4;
/// Exact abstract work to compile a broad full-byte bitmap classifier.
///
/// Construction visits the complete 256-byte domain once while populating two
/// exact 16-byte nibble tables. Targets with the wide full-byte execution path
/// also compile its ASCII nonmember-run scanner. Host capture and immutable
/// leaf selection happen once after those fixed passes.
#[cfg(any(
    test,
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
))]
pub(crate) const BYTE_START_SET_CLASSIFIER_BUILD_WORK: usize =
    fre_simd_kernels::BYTE_SET_CLASSIFIER_BUILD_WORK + ASCII_RUN_SCANNER_BUILD_WORK;
#[cfg(not(any(
    test,
    target_arch = "x86_64",
    all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
)))]
pub(crate) const BYTE_START_SET_CLASSIFIER_BUILD_WORK: usize =
    fre_simd_kernels::BYTE_SET_CLASSIFIER_BUILD_WORK;
/// Exact abstract work to compile a broad all-ASCII bitmap scanner.
pub(crate) const BYTE_START_ASCII_CLASSIFIER_SELECTION_WORK: usize =
    ASCII_CLASSIFIER_BUILD_WORK + ASCII_NONMEMBER_RUN_SCANNER_BUILD_WORK;
/// Exact abstract work to compare one position with the incumbent scanner.
pub(crate) const START_FILTER_SCANNER_SELECTION_WORK: usize = 1;
/// Exact abstract work to compare one non-scanner position with the incumbent
/// secondary filter.
pub(crate) const START_FILTER_GUARD_SELECTION_WORK: usize = 1;
/// Exact abstract work to compare one optional second-tier position with the
/// incumbent deep Probe. Cardinality is charged independently as one complete
/// four-word bitmap population.
pub(crate) const START_FILTER_DEEP_PROBE_SELECTION_WORK: usize = 1;
/// Optional work to retain one already-compared broad exact-position class as
/// an adaptive Probe after the primary scanner has been fully constructed.
pub(crate) const START_FILTER_PROBE_RETENTION_WORK: usize = 1;
/// Maximum work to retain one deep Probe and materialize its compact
/// one-to-three-member scan leaf in padding already owned by the exact class.
pub(crate) const START_FILTER_DEEP_PROBE_MAX_BUILD_WORK: usize =
    START_FILTER_PROBE_RETENTION_WORK
        + BYTE_START_SMALL_MAX_MEMBERS * BYTE_START_MEMBER_EXTRACTION_WORK;
/// Maximum optional Probe work, including exact contiguous-range detection
/// when the primary scanner can retain a classified block intersection.
pub(crate) const START_FILTER_PROBE_SELECTION_WORK: usize =
    START_FILTER_PROBE_RETENTION_WORK + BYTE_START_RANGE_DETECTION_WORK;
/// Largest non-scanner byte class selective enough to retain as a guard.
/// Sixty-four members are one quarter of the complete 256-byte domain.
pub(crate) const START_FILTER_GUARD_MAX_CARDINALITY: u32 = 64;
/// Conservative selection bound: count and compare every exact-position set,
/// compare every non-scanner set for the optional secondary filter, compile
/// the costliest retained scanner, then retain a broad Probe when eligible.
pub(crate) const START_FILTER_MAX_SELECTION_WORK: usize = START_FILTER_POSITION_COUNT
    * (BYTE_START_BITMAP_POPULATION_WORK + START_FILTER_SCANNER_SELECTION_WORK)
    + START_FILTER_MAX_OFFSET * START_FILTER_GUARD_SELECTION_WORK
    + START_FILTER_DEEP_POSITION_COUNT
        * (BYTE_START_BITMAP_POPULATION_WORK + START_FILTER_DEEP_PROBE_SELECTION_WORK)
    + BYTE_START_RANGE_DETECTION_WORK
    + BYTE_START_SET_CLASSIFIER_BUILD_WORK
    + START_FILTER_PROBE_SELECTION_WORK
    + START_FILTER_DEEP_PROBE_MAX_BUILD_WORK;

/// The structural role of a Thompson state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StateRole {
    /// Ordered zero-width branching. All outgoing edges must be zero-width.
    Split,
    /// Ordered consuming branching. All outgoing edges must consume one byte.
    Consume,
    /// A successful match. Accept states have no outgoing edges.
    Accept,
}

impl StateRole {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Split => "split",
            Self::Consume => "consume",
            Self::Accept => "accept",
        }
    }
}

/// The kind of one graph edge. Payload byte bounds live in separate arrays.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EdgeKind {
    /// Unconditional zero-width transition.
    Epsilon,
    /// Consume one byte in the inclusive range stored alongside this edge.
    ByteRange,
    /// Zero-width assertion at the beginning of the original haystack.
    AssertHaystackStart,
    /// Zero-width assertion at the end of the original haystack.
    AssertHaystackEnd,
    /// Zero-width assertion at original-haystack start or after the configured
    /// line-terminator byte. The variant name mirrors regex-syntax's
    /// historical `StartLF` name; LF is the default, not a hard-coded value.
    AssertLineStartLf,
    /// Zero-width assertion at original-haystack end or before the configured
    /// line-terminator byte. The variant name mirrors regex-syntax's
    /// historical `EndLF` name; LF is the default, not a hard-coded value.
    AssertLineEndLf,
    /// Zero-width CRLF-aware line start without splitting a CRLF pair.
    AssertLineStartCrlf,
    /// Zero-width CRLF-aware line end without splitting a CRLF pair.
    AssertLineEndCrlf,
    /// Zero-width ASCII word boundary; only `[A-Za-z0-9_]` are word bytes.
    AssertWordAscii,
    /// Zero-width negated ASCII word boundary assertion.
    AssertWordAsciiNegate,
    /// Zero-width start-of-ASCII-word assertion.
    AssertWordStartAscii,
    /// Zero-width end-of-ASCII-word assertion.
    AssertWordEndAscii,
    /// Zero-width left half of an ASCII word-start assertion.
    AssertWordStartHalfAscii,
    /// Zero-width right half of an ASCII word-end assertion.
    AssertWordEndHalfAscii,
    /// Zero-width positive Unicode word boundary using the UTS#18 `\w` set.
    AssertWordUnicode,
    /// Zero-width negated Unicode word boundary.
    AssertWordUnicodeNegate,
    /// Zero-width start-of-Unicode-word assertion.
    AssertWordStartUnicode,
    /// Zero-width end-of-Unicode-word assertion.
    AssertWordEndUnicode,
    /// Zero-width left half of a Unicode word-start assertion.
    AssertWordStartHalfUnicode,
    /// Zero-width right half of a Unicode word-end assertion.
    AssertWordEndHalfUnicode,
}

impl EdgeKind {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Epsilon => "epsilon",
            Self::ByteRange => "byte-range",
            Self::AssertHaystackStart => "start-assertion",
            Self::AssertHaystackEnd => "end-assertion",
            Self::AssertLineStartLf => "configured-line-start-assertion",
            Self::AssertLineEndLf => "configured-line-end-assertion",
            Self::AssertLineStartCrlf => "CRLF-line-start-assertion",
            Self::AssertLineEndCrlf => "CRLF-line-end-assertion",
            Self::AssertWordAscii => "ASCII-word-boundary-assertion",
            Self::AssertWordAsciiNegate => "ASCII-not-word-boundary-assertion",
            Self::AssertWordStartAscii => "ASCII-word-start-assertion",
            Self::AssertWordEndAscii => "ASCII-word-end-assertion",
            Self::AssertWordStartHalfAscii => "ASCII-word-start-half-assertion",
            Self::AssertWordEndHalfAscii => "ASCII-word-end-half-assertion",
            Self::AssertWordUnicode => "Unicode-word-boundary-assertion",
            Self::AssertWordUnicodeNegate => "Unicode-not-word-boundary-assertion",
            Self::AssertWordStartUnicode => "Unicode-word-start-assertion",
            Self::AssertWordEndUnicode => "Unicode-word-end-assertion",
            Self::AssertWordStartHalfUnicode => "Unicode-word-start-half-assertion",
            Self::AssertWordEndHalfUnicode => "Unicode-word-end-half-assertion",
        }
    }

    pub(crate) const fn is_zero_width(self) -> bool {
        !matches!(self, Self::ByteRange)
    }

    pub(crate) const fn assertion_bit(self) -> Option<u32> {
        let ordinal = match self {
            Self::Epsilon | Self::ByteRange => return None,
            Self::AssertHaystackStart => 0,
            Self::AssertHaystackEnd => 1,
            Self::AssertLineStartLf => 2,
            Self::AssertLineEndLf => 3,
            Self::AssertLineStartCrlf => 4,
            Self::AssertLineEndCrlf => 5,
            Self::AssertWordAscii => 6,
            Self::AssertWordAsciiNegate => 7,
            Self::AssertWordStartAscii => 8,
            Self::AssertWordEndAscii => 9,
            Self::AssertWordStartHalfAscii => 10,
            Self::AssertWordEndHalfAscii => 11,
            Self::AssertWordUnicode => 12,
            Self::AssertWordUnicodeNegate => 13,
            Self::AssertWordStartUnicode => 14,
            Self::AssertWordEndUnicode => 15,
            Self::AssertWordStartHalfUnicode => 16,
            Self::AssertWordEndHalfUnicode => 17,
        };
        Some(1_u32 << ordinal)
    }
}

/// Mutable interchange form accepted from a future lowering layer.
///
/// `edge_offsets` is a CSR offset table and must contain `roles.len() + 1`
/// entries. Edge `i` has target `edge_targets[i]`, kind `edge_kinds[i]`, and
/// inclusive byte bounds `byte_starts[i]..=byte_ends[i]`. Bounds for
/// zero-width edges must both be zero, avoiding ignored non-canonical payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawPlan {
    pub start: u32,
    pub roles: Vec<StateRole>,
    pub edge_offsets: Vec<u32>,
    pub edge_targets: Vec<u32>,
    pub edge_kinds: Vec<EdgeKind>,
    pub byte_starts: Vec<u8>,
    pub byte_ends: Vec<u8>,
}

/// Hard construction limits for this standalone automata layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileLimits {
    pub max_states: usize,
    pub max_edges: usize,
    pub max_storage_bytes: usize,
    pub max_validation_work: usize,
}

impl Default for CompileLimits {
    fn default() -> Self {
        Self {
            max_states: 262_144,
            max_edges: 1_048_576,
            max_storage_bytes: 128 * 1024 * 1024,
            max_validation_work: 4_000_000,
        }
    }
}

/// Immutable dimensions and construction charges for a validated plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlanStats {
    states: usize,
    edges: usize,
    zero_width_edges: usize,
    assertion_edges: usize,
    assertion_kinds: u32,
    consuming_states: u32,
    consuming_edges: usize,
    storage_bytes: usize,
    validation_work: usize,
}

/// Immutable conservative byte equivalence classes for transition caching.
///
/// Class IDs follow increasing boundary intervals. The partition need not
/// merge disjoint intervals with identical edge membership, but every
/// validated byte range is exactly a union of complete classes. One fixed
/// inline map makes construction allocation-free and retains all 256
/// singleton classes when every byte is independently delimited. A class
/// representative is recovered by a bounded cold scan instead of retaining a
/// second 256-byte table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ByteClasses {
    class_by_byte: [u8; BYTE_CLASS_DOMAIN_SIZE],
    count: u16,
}

impl ByteClasses {
    fn from_validated_ranges(raw: &RawPlan) -> Self {
        let mut starts_class = [false; BYTE_CLASS_DOMAIN_SIZE];
        starts_class[0] = true;
        for edge in 0..raw.edge_kinds.len() {
            if raw.edge_kinds[edge] != EdgeKind::ByteRange {
                continue;
            }
            let start = usize::from(raw.byte_starts[edge]);
            let end = raw.byte_ends[edge];
            starts_class[start] = true;
            if end != u8::MAX {
                starts_class[usize::from(end) + 1] = true;
            }
        }

        let mut class_by_byte = [0_u8; BYTE_CLASS_DOMAIN_SIZE];
        let mut count = 0usize;
        for byte in 0..BYTE_CLASS_DOMAIN_SIZE {
            if starts_class[byte] {
                count += 1;
            }
            class_by_byte[byte] = u8::try_from(count - 1)
                .expect("at most 256 byte classes have IDs fitting u8");
        }
        Self {
            class_by_byte,
            count: u16::try_from(count).expect("the byte-class count fits u16"),
        }
    }

    pub(crate) fn class_of(&self, byte: u8) -> u8 {
        self.class_by_byte[usize::from(byte)]
    }

    pub(crate) fn representative(&self, class: u8) -> Option<u8> {
        if usize::from(class) >= self.count() {
            return None;
        }
        self.class_by_byte
            .iter()
            .position(|&candidate| candidate == class)
            .and_then(|byte| u8::try_from(byte).ok())
    }

    pub(crate) fn count(&self) -> usize {
        usize::from(self.count)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BoundaryContextClassifier {
    assertions: u32,
}

impl BoundaryContextClassifier {
    const ABSOLUTE: u32 = (1 << 0) | (1 << 1);
    const CONFIGURED_LINE: u32 = (1 << 2) | (1 << 3);
    const CRLF_LINE: u32 = (1 << 4) | (1 << 5);
    const ASCII_WORD: u32 = (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11);
    const UNICODE_WORD: u32 = (1 << 12) | (1 << 13) | (1 << 14) | (1 << 15) | (1 << 16) | (1 << 17);

    pub(crate) const fn new(assertions: u32) -> Self {
        Self { assertions }
    }

    pub(crate) const fn assertions(self) -> u32 {
        self.assertions
    }

    pub(crate) const fn absolute(self) -> u32 {
        self.assertions & Self::ABSOLUTE
    }

    pub(crate) const fn configured_line(self) -> u32 {
        self.assertions & Self::CONFIGURED_LINE
    }

    pub(crate) const fn crlf_line(self) -> u32 {
        self.assertions & Self::CRLF_LINE
    }

    pub(crate) const fn ascii_word(self) -> u32 {
        self.assertions & Self::ASCII_WORD
    }

    pub(crate) const fn unicode_word(self) -> u32 {
        self.assertions & Self::UNICODE_WORD
    }
}

impl PlanStats {
    #[must_use]
    pub const fn states(self) -> usize {
        self.states
    }

    #[must_use]
    pub const fn edges(self) -> usize {
        self.edges
    }

    #[must_use]
    pub const fn zero_width_edges(self) -> usize {
        self.zero_width_edges
    }

    /// Whether this graph contains any context-sensitive assertion edge.
    ///
    /// Assertion-free nullable graphs can retain a start-known ordered lazy
    /// state, while nullable graphs whose emptiness depends on context cannot.
    #[must_use]
    pub const fn has_assertions(self) -> bool {
        self.assertion_edges != 0
    }

    pub(crate) const fn assertion_edges(self) -> usize {
        self.assertion_edges
    }

    pub(crate) const fn assertion_kinds(self) -> u32 {
        self.assertion_kinds
    }

    /// Number of states authenticated with the consuming role.
    #[must_use]
    pub fn consuming_states(self) -> usize {
        usize::try_from(self.consuming_states)
            .expect("validated u32 consuming-state count fits usize")
    }

    #[must_use]
    pub const fn consuming_edges(self) -> usize {
        self.consuming_edges
    }

    /// Payload bytes in the immutable structure-of-arrays tables.
    #[must_use]
    pub const fn storage_bytes(self) -> usize {
        self.storage_bytes
    }

    #[must_use]
    pub const fn validation_work(self) -> usize {
        self.validation_work
    }
}

/// A half-open search range. Assertions retain original-haystack context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchWindow {
    start: usize,
    end: usize,
}

impl SearchWindow {
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub const fn full(haystack: &[u8]) -> Self {
        Self {
            start: 0,
            end: haystack.len(),
        }
    }

    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }
}

/// Per-invocation hard limits. Both are checked; neither is a deadline.
///
/// `max_work` covers setup plus transitions. A one-shot call therefore charges
/// cold workspace construction, while a reusable call charges only logical
/// reset (and, extremely rarely, generation-table clearing) before transitions.
/// Unless an operation-aware prepared facade has already settled the policy,
/// the first successful search on an immutable [`Automaton`] also charges its
/// bounded full-byte start-filter proof and scanner/secondary-filter
/// selection. The automaton fallibly retains that result in one cold heap
/// owner, so later calls do not repeat or charge that work. Search-time owner
/// publication requires one additional work unit and enough scratch allowance
/// for its exact payload; refusal preserves ordinary K0 and leaves publication
/// retryable. Source-free preparation may instead use its explicit setup-work
/// cap to permanently select ordinary K0 before any source call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchLimits {
    pub max_work: u64,
    pub max_scratch_bytes: usize,
}

impl SearchLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: u64::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }
}

impl Default for SearchLimits {
    fn default() -> Self {
        Self {
            max_work: 100_000_000,
            max_scratch_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Fixed full-byte bitmap retained by the portable start filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ByteSet([u64; 4]);

impl ByteSet {
    pub(crate) const EMPTY: Self = Self([0; 4]);
    pub(crate) const ALL: Self = Self([u64::MAX; 4]);

    pub(crate) const fn from_words(words: [u64; 4]) -> Self {
        Self(words)
    }

    pub(crate) const fn words(self) -> [u64; 4] {
        self.0
    }

    pub(crate) fn contains(self, byte: u8) -> bool {
        let word = usize::from(byte / 64);
        let bit = u32::from(byte % 64);
        self.0[word] & (1_u64 << bit) != 0
    }

    pub(crate) fn cardinality(self) -> u32 {
        self.0
            .into_iter()
            .map(u64::count_ones)
            .fold(0_u32, u32::saturating_add)
    }
}

/// Immutable SIMD classifier retained for one broad all-ASCII byte set.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StartAsciiClassifier {
    inner: AsciiByteSetClassifier,
    nonmembers: AsciiByteSetNonMemberScanner,
}

impl StartAsciiClassifier {
    pub(crate) fn new(set: AsciiByteSet) -> Self {
        Self {
            inner: AsciiByteSetClassifier::new(set),
            // High bytes are exact nonmembers of an all-ASCII start set, so
            // retain a whole-slice scanner that advances across them instead
            // of ending the run at every non-ASCII byte.
            nonmembers: AsciiByteSetNonMemberScanner::new(set),
        }
    }

    pub(crate) const fn classifier(&self) -> &AsciiByteSetClassifier {
        &self.inner
    }

    pub(crate) const fn nonmember_scanner(&self) -> &AsciiByteSetNonMemberScanner {
        &self.nonmembers
    }

    const fn set(&self) -> AsciiByteSet {
        self.inner.set()
    }

    const fn selection(&self) -> AsciiSelection {
        self.inner.selection()
    }

    const fn nonmember_selection(&self) -> fre_simd_kernels::SelectionReceipt {
        self.nonmembers.selection()
    }
}

impl PartialEq for StartAsciiClassifier {
    fn eq(&self, other: &Self) -> bool {
        self.set() == other.set()
            && self.selection() == other.selection()
            && self.nonmembers.set() == other.nonmembers.set()
            && self.nonmember_selection() == other.nonmember_selection()
    }
}

impl Eq for StartAsciiClassifier {}

/// Immutable full-byte classifier retained for one non-ASCII start set.
///
/// This is the compact one-column specialization of the reusable byte-bucket
/// classifier: two 16-byte tables represent all sixteen high nibbles in one
/// fixed-width invocation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StartByteSetClassifier {
    inner: ByteSetClassifier,
    #[cfg(any(
        test,
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
    ))]
    ascii_nonmembers: AsciiByteSetRunScanner,
}

impl StartByteSetClassifier {
    pub(crate) fn new(inner: ByteSetClassifier) -> Self {
        #[cfg(any(
            test,
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
        ))]
        let words = inner.set().words();
        Self {
            inner,
            // The run contains only ASCII bytes absent from the exact
            // 256-byte set. Every high byte terminates it and is rechecked by
            // the full classifier, whether that byte is a member or not.
            #[cfg(any(
                test,
                target_arch = "x86_64",
                all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
            ))]
            ascii_nonmembers: AsciiByteSetRunScanner::new(AsciiByteSet::from_words([
                !words[0], !words[1],
            ])),
        }
    }

    pub(crate) const fn set(&self) -> ByteSet {
        ByteSet::from_words(self.inner.set().words())
    }

    pub(crate) const fn classifier(&self) -> &ByteSetClassifier {
        &self.inner
    }

    #[cfg(any(
        test,
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
    ))]
    pub(crate) const fn ascii_nonmember_scanner(&self) -> &AsciiByteSetRunScanner {
        &self.ascii_nonmembers
    }
}

impl PartialEq for StartByteSetClassifier {
    fn eq(&self, other: &Self) -> bool {
        let inner_equal = self.inner.set() == other.inner.set()
            && self.inner.selection() == other.inner.selection()
            && self.inner.wide_selection() == other.inner.wide_selection();
        #[cfg(any(
            test,
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
        ))]
        {
            inner_equal
                && self.ascii_nonmembers.set() == other.ascii_nonmembers.set()
                && self.ascii_nonmembers.selection() == other.ascii_nonmembers.selection()
        }
        #[cfg(not(any(
            test,
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_os = "linux", target_endian = "little")
        )))]
        {
            inner_equal
        }
    }
}

impl Eq for StartByteSetClassifier {}

/// Immutable scanner selected from one proved exact-position byte set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartScanner {
    Empty,
    One(u8),
    Two(u8, u8),
    Three(u8, u8, u8),
    Range {
        start: u8,
        end: u8,
    },
    AsciiSet {
        set: ByteSet,
        classifier: StartAsciiClassifier,
    },
    Set(StartByteSetClassifier),
}

/// One sound byte class at an exact consumed-byte offset after match start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartPositionClassPolicy {
    Ordinary,
    AdaptiveProbe,
    AdaptiveEarlyProbe,
    GuardPair,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartPositionClass {
    pub(crate) offset: u8,
    range_start: u8,
    range_end: u8,
    policy: StartPositionClassPolicy,
    compact_probe_len: u8,
    compact_probe_members: [u8; BYTE_START_SMALL_MAX_MEMBERS],
    pub(crate) set: ByteSet,
}

impl StartPositionClass {
    pub(crate) const fn new(offset: u8, set: ByteSet) -> Self {
        Self {
            offset,
            range_start: 1,
            range_end: 0,
            policy: StartPositionClassPolicy::Ordinary,
            compact_probe_len: 0,
            compact_probe_members: [0; BYTE_START_SMALL_MAX_MEMBERS],
            set,
        }
    }

    const fn with_probe_policy(
        mut self,
        range: Option<(u8, u8)>,
        policy: StartPositionClassPolicy,
    ) -> Self {
        (self.range_start, self.range_end) = match range {
            Some((start, end)) => (start, end),
            None => (1, 0),
        };
        self.policy = policy;
        self
    }

    const fn with_compact_probe_members(
        mut self,
        members: [u8; BYTE_START_SMALL_MAX_MEMBERS],
        length: u8,
    ) -> Self {
        self.compact_probe_len = length;
        self.compact_probe_members = members;
        self
    }
}

/// Broad exact-position class used as an adaptive secondary scanner.
///
/// A contiguous range can be intersected with the primary scanner a complete
/// candidate block at a time without constructing another runtime classifier.
/// Compact deep classes normally activate after primary-candidate rejection;
/// an immutable proof may separately mark one for a bounded source-witnessed
/// trial before the first engine restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct StartPositionProbe {
    class: StartPositionClass,
}

impl StartPositionProbe {
    pub(crate) const fn new(class: StartPositionClass, range: Option<(u8, u8)>) -> Self {
        Self {
            class: class.with_probe_policy(range, StartPositionClassPolicy::AdaptiveProbe),
        }
    }

    pub(crate) fn new_compact(
        class: StartPositionClass,
        members: [u8; BYTE_START_SMALL_MAX_MEMBERS],
        length: u8,
    ) -> Option<Self> {
        let member_count = usize::from(length);
        if !(1..=BYTE_START_SMALL_MAX_MEMBERS).contains(&member_count) {
            return None;
        }
        let mut words = [0_u64; 4];
        for &member in &members[..member_count] {
            let word = usize::from(member / 64);
            let bit = u32::from(member % 64);
            if words[word] & (1_u64 << bit) != 0 {
                return None;
            }
            words[word] |= 1_u64 << bit;
        }
        if ByteSet::from_words(words) != class.set {
            return None;
        }
        Some(Self {
            class: class
                .with_probe_policy(None, StartPositionClassPolicy::AdaptiveProbe)
                .with_compact_probe_members(members, length),
        })
    }

    pub(crate) const fn with_early_trial(mut self) -> Self {
        debug_assert!(self.class.compact_probe_len != 0);
        self.class.policy = StartPositionClassPolicy::AdaptiveEarlyProbe;
        self
    }

    pub(crate) const fn new_guard_pair(
        class: StartPositionClass,
        range: (u8, u8),
    ) -> Self {
        Self {
            class: class.with_probe_policy(Some(range), StartPositionClassPolicy::GuardPair),
        }
    }

    pub(crate) const fn range(&self) -> Option<(u8, u8)> {
        if self.class.range_start <= self.class.range_end {
            Some((self.class.range_start, self.class.range_end))
        } else {
            None
        }
    }

    pub(crate) const fn is_guard_pair(&self) -> bool {
        matches!(self.class.policy, StartPositionClassPolicy::GuardPair)
    }

    pub(crate) const fn trials_early(&self) -> bool {
        matches!(
            self.class.policy,
            StartPositionClassPolicy::AdaptiveEarlyProbe
        )
    }

    pub(crate) const fn class(&self) -> &StartPositionClass {
        &self.class
    }

    pub(crate) const fn compact_members(
        &self,
    ) -> (u8, &[u8; BYTE_START_SMALL_MAX_MEMBERS]) {
        (
            self.class.compact_probe_len,
            &self.class.compact_probe_members,
        )
    }
}

impl Deref for StartPositionProbe {
    type Target = StartPositionClass;

    fn deref(&self) -> &Self::Target {
        &self.class
    }
}

/// Execution policy for the one retained non-scanner exact-position class.
///
/// A guard is checked for every primary candidate. A Guard pair retains a paid
/// exact range for invocation-local block intersection after source-derived
/// admission succeeds. A broad probe normally starts inactive and is enabled
/// by invocation-local engine rejections; a compact deep probe may instead
/// carry immutable eligibility for one bounded source-witnessed early trial.
/// Keeping the policy in the immutable proof makes every route auditable
/// without retaining any source-dependent state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartPositionFilter {
    position: StartPositionProbe,
    late_probe: Option<StartPositionProbe>,
}

impl StartPositionFilter {
    pub(crate) const fn new_guard(class: StartPositionClass) -> Self {
        Self {
            position: StartPositionProbe { class },
            late_probe: None,
        }
    }

    pub(crate) const fn new_probe(probe: StartPositionProbe) -> Self {
        Self {
            position: probe,
            late_probe: None,
        }
    }

    pub(crate) const fn with_late_probe(mut self, probe: StartPositionProbe) -> Self {
        self.late_probe = Some(probe);
        self
    }

    pub(crate) const fn guard(&self) -> Option<&StartPositionClass> {
        match self.position.class.policy {
            StartPositionClassPolicy::Ordinary => Some(self.position.class()),
            StartPositionClassPolicy::AdaptiveProbe
            | StartPositionClassPolicy::AdaptiveEarlyProbe
            | StartPositionClassPolicy::GuardPair => None,
        }
    }

    pub(crate) const fn guard_pair(&self) -> Option<&StartPositionProbe> {
        if self.position.is_guard_pair() {
            Some(&self.position)
        } else {
            None
        }
    }

    pub(crate) const fn probe(&self) -> Option<&StartPositionProbe> {
        if let Some(probe) = &self.late_probe {
            return Some(probe);
        }
        match self.position.class.policy {
            StartPositionClassPolicy::Ordinary => None,
            StartPositionClassPolicy::AdaptiveProbe
            | StartPositionClassPolicy::AdaptiveEarlyProbe
            | StartPositionClassPolicy::GuardPair => {
                Some(&self.position)
            }
        }
    }
}

/// Scanner and exact consumed-byte offset used to recover candidate starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartPositionScanner {
    pub(crate) offset: u8,
    pub(crate) scanner: StartScanner,
}

/// Immutable bounded start-filter proof published after a successful search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StartFilterProof {
    pub(crate) scanner: Option<StartPositionScanner>,
    pub(crate) filter: Option<StartPositionFilter>,
    pub(crate) force_haystack_start: bool,
    pub(crate) relaxed_nullable: bool,
}

impl StartFilterProof {
    pub(crate) const fn guard(&self) -> Option<&StartPositionClass> {
        match &self.filter {
            Some(filter) => filter.guard(),
            None => None,
        }
    }

    pub(crate) const fn probe(&self) -> Option<&StartPositionProbe> {
        match &self.filter {
            Some(filter) => filter.probe(),
            None => None,
        }
    }

    #[cfg(test)]
    pub(crate) const fn guard_pair(&self) -> Option<&StartPositionProbe> {
        match &self.filter {
            Some(filter) => filter.guard_pair(),
            None => None,
        }
    }

    pub(crate) const fn scalar_guard_parts(&self) -> Option<(u8, &ByteSet)> {
        match &self.filter {
            Some(filter) => match (filter.guard(), filter.guard_pair()) {
                (Some(guard), _) => Some((guard.offset, &guard.set)),
                (None, Some(pair)) => {
                    let class = pair.class();
                    Some((class.offset, &class.set))
                }
                (None, None) => None,
            },
            None => None,
        }
    }
}

/// Cold, fallibly allocated owner for one published start-filter proof.
///
/// `None` inside the lock is the permanent ordinary-K0 policy, selected either
/// by source-free preparation under an insufficient proof-work cap or by a
/// fallible owner-allocation failure. A source-bearing search's ordinary
/// scratch/work refusal does not initialize the lock, so a later invocation
/// with more allowance may retry. `get_or_init` serializes the fallible owner
/// decision: concurrent successful first users may each derive the same
/// immutable proof, but exactly one of them attempts to allocate its owner.
#[derive(Debug, Default)]
pub(crate) struct StartFilterProofCell {
    inner: OnceLock<Option<Box<[StartFilterProof; 1]>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartFilterPublication {
    AlreadyInitialized,
    AllocationFailed,
    Published,
}

impl StartFilterProofCell {
    pub(crate) const PAYLOAD_BYTES: usize = size_of::<StartFilterProof>();

    pub(crate) const fn new() -> Self {
        Self {
            inner: OnceLock::new(),
        }
    }

    pub(crate) fn get(&self) -> Option<&StartFilterProof> {
        self.inner
            .get()
            .and_then(Option::as_ref)
            .map(|owner| &owner[0])
    }

    pub(crate) fn is_initialized(&self) -> bool {
        self.inner.get().is_some()
    }

    pub(crate) fn is_permanently_ordinary(&self) -> bool {
        matches!(self.inner.get(), Some(None))
    }

    pub(crate) fn publish(&self, proof: &StartFilterProof) -> StartFilterPublication {
        let mut attempted = false;
        let retained = self.inner.get_or_init(|| {
            attempted = true;
            try_start_filter_proof_owner(proof)
        });
        if !attempted {
            StartFilterPublication::AlreadyInitialized
        } else if retained.is_some() {
            StartFilterPublication::Published
        } else {
            StartFilterPublication::AllocationFailed
        }
    }

    /// Permanently retain the ordinary no-filter policy after an optional
    /// source-free preparation attempt declines. This uses the same `None`
    /// sentinel as an owner-allocation failure, so later source-bearing calls
    /// cannot repeat proof derivation or attempt an allocation.
    pub(crate) fn decline(&self) {
        let _ = self.inner.get_or_init(|| None);
    }

    #[cfg(test)]
    pub(crate) fn set(&self, proof: &StartFilterProof) -> Result<(), ()> {
        let owner = try_start_filter_proof_owner(proof).ok_or(())?;
        self.inner.set(Some(owner)).map_err(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn mark_allocation_failed(&self) -> Result<(), ()> {
        self.inner.set(None).map_err(|_| ())
    }
}

fn try_start_filter_proof_owner(proof: &StartFilterProof) -> Option<Box<[StartFilterProof; 1]>> {
    let mut slot = Vec::new();
    slot.try_reserve_exact(1).ok()?;
    // `into_boxed_slice` is allocation-free only when length equals
    // capacity. An allocator may legally grant more than was requested; in
    // that unusual case, decline publication instead of invoking an
    // infallible shrinking allocation.
    if slot.capacity() != 1 {
        return None;
    }
    slot.push(*proof);
    let owner: Box<[StartFilterProof]> = slot.into_boxed_slice();
    owner.try_into().ok()
}

/// Immutable structure-of-arrays prioritized Thompson graph.
#[derive(Debug)]
pub struct Automaton {
    identity: u64,
    // Value-only ordinary searches may retain one reusable workspace here.
    // Diagnostic/accounting searches never use it. A short mutex protects
    // checkout/return only; K0 execution happens outside the lock.
    pub(crate) pooled_workspace: OnceLock<Box<Mutex<Option<K0Workspace>>>>,
    pub(crate) start: u32,
    pub(crate) roles: Box<[StateRole]>,
    pub(crate) edge_offsets: Box<[u32]>,
    pub(crate) edge_targets: Box<[u32]>,
    pub(crate) edge_kinds: Box<[EdgeKind]>,
    pub(crate) byte_starts: Box<[u8]>,
    pub(crate) byte_ends: Box<[u8]>,
    byte_classes: ByteClasses,
    pub(crate) epsilon_closure_dispatch: Option<EpsilonClosureDispatch>,
    epsilon_closure_start_program: Option<EpsilonClosureStartProgram>,
    pub(crate) ordered_edge_dispatch: Option<OrderedEdgeDispatch>,
    pub(crate) start_filter_proof: StartFilterProofCell,
    line_terminator: u8,
    stats: PlanStats,
}

impl Clone for Automaton {
    fn clone(&self) -> Self {
        Self {
            identity: next_automaton_identity(),
            pooled_workspace: OnceLock::new(),
            start: self.start,
            roles: self.roles.clone(),
            edge_offsets: self.edge_offsets.clone(),
            edge_targets: self.edge_targets.clone(),
            edge_kinds: self.edge_kinds.clone(),
            byte_starts: self.byte_starts.clone(),
            byte_ends: self.byte_ends.clone(),
            byte_classes: self.byte_classes,
            epsilon_closure_dispatch: self.epsilon_closure_dispatch.clone(),
            epsilon_closure_start_program: self.epsilon_closure_start_program.clone(),
            ordered_edge_dispatch: self.ordered_edge_dispatch.clone(),
            // A clone is a new immutable plan construction. Do not silently
            // copy first-use specialization that this instance has not paid
            // to derive.
            start_filter_proof: StartFilterProofCell::new(),
            line_terminator: self.line_terminator,
            stats: self.stats,
        }
    }
}

impl Automaton {
    /// Retained inline bytes added by the exact full-byte class map.
    pub const BYTE_CLASS_MAP_RETAINED_BYTES: usize = size_of::<ByteClasses>();

    /// Exact additional validation work for the byte-class boundary and
    /// emission passes over a graph with `edges` edges.
    #[must_use]
    pub fn byte_class_map_validation_work(edges: usize) -> Option<usize> {
        edges
            .checked_mul(BYTE_CLASS_BOUNDARY_WORK_PER_EDGE)
            .and_then(|work| work.checked_add(BYTE_CLASS_EMISSION_WORK))
    }

    const POOLED_WORKSPACE_OWNER_PUBLICATION_WORK: u64 = 1;

    const fn pooled_workspace_owner_bytes() -> usize {
        size_of::<Mutex<Option<K0Workspace>>>()
    }

    fn pooled_workspace_payload_limits(limits: WorkspaceLimits) -> Option<WorkspaceLimits> {
        Some(WorkspaceLimits {
            max_setup_work: limits
                .max_setup_work
                .checked_sub(Self::POOLED_WORKSPACE_OWNER_PUBLICATION_WORK)?,
            max_scratch_bytes: limits
                .max_scratch_bytes
                .checked_sub(Self::pooled_workspace_owner_bytes())?,
        })
    }

    fn pooled_workspace_fits(workspace: &K0Workspace, limits: WorkspaceLimits) -> bool {
        let Some(payload_limits) = Self::pooled_workspace_payload_limits(limits) else {
            return false;
        };
        workspace.construction_accounting().work() <= payload_limits.max_setup_work
            && workspace.retained_bytes() <= payload_limits.max_scratch_bytes
    }

    fn try_checkout_pooled_workspace_with<A>(
        &self,
        limits: WorkspaceLimits,
        endpoint_eligible: bool,
        bidirectional: bool,
        allocate_owner: A,
    ) -> Option<K0Workspace>
    where
        A: FnOnce(
            Mutex<Option<K0Workspace>>,
        ) -> Result<
            Box<Mutex<Option<K0Workspace>>>,
            (fre_exact_alloc::CopyError, Mutex<Option<K0Workspace>>),
        >,
    {
        let payload_limits = Self::pooled_workspace_payload_limits(limits)?;
        if let Some(owner) = self.pooled_workspace.get() {
            let mut slot = owner.lock().ok()?;
            if let Some(workspace) = slot.take() {
                if Self::pooled_workspace_fits(&workspace, limits) {
                    return Some(workspace);
                }
                *slot = Some(workspace);
                return None;
            }
            drop(slot);
            return K0Workspace::new_selected(
                self,
                payload_limits,
                endpoint_eligible,
                bidirectional,
            )
            .ok();
        }

        // Construct the complete selected workspace before allocating or
        // publishing its owner. A layout/resource/allocation refusal therefore
        // leaves no empty retained cache behind and the facade can run its
        // canonical one-shot path with the original envelope.
        let workspace =
            K0Workspace::new_selected(self, payload_limits, endpoint_eligible, bidirectional)
                .ok()?;
        let owner = match allocate_owner(Mutex::new(None)) {
            Ok(owner) => owner,
            Err((_error, owner)) => {
                drop(owner);
                drop(workspace);
                return None;
            }
        };
        // Publish an empty slot while returning the fully constructed
        // workspace to this invocation. Concurrent first users keep their own
        // bounded workspace; only a successful search later wins the slot.
        match self.pooled_workspace.set(owner) {
            Ok(()) => Some(workspace),
            Err(owner) => {
                drop(owner);
                Some(workspace)
            }
        }
    }

    /// Check out or fallibly create the optional scratch used only by an
    /// ordinary value-only facade search.
    ///
    /// The mutex is held only while moving the workspace out of its slot.
    /// Concurrent searches therefore create independent bounded workspaces
    /// instead of serializing execution. Allocation failure or a poisoned
    /// owner declines this optional acceleration so the facade can use its
    /// canonical one-shot path.
    pub(crate) fn try_checkout_pooled_workspace(
        &self,
        limits: WorkspaceLimits,
        endpoint_eligible: bool,
        bidirectional: bool,
    ) -> Option<K0Workspace> {
        self.try_checkout_pooled_workspace_with(
            limits,
            endpoint_eligible,
            bidirectional,
            fre_exact_alloc::try_box_preserve,
        )
    }

    /// Return a successfully used value-only scratch workspace when its slot
    /// is empty. A concurrent winner keeps the slot; the excess workspace is
    /// dropped. A poisoned owner is never reused.
    pub(crate) fn return_pooled_workspace(&self, workspace: K0Workspace) {
        let Some(owner) = self.pooled_workspace.get() else {
            return;
        };
        if let Ok(mut slot) = owner.lock() {
            if slot.is_none() {
                *slot = Some(workspace);
            }
        }
    }

    /// Validate all dimensions, resource limits, roles, edge payloads, and
    /// targets before freezing the supplied vectors.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError::Malformed`] for any inconsistent graph table,
    /// [`CompileError::ResourceLimit`] when a declared hard limit is too low,
    /// or [`CompileError::ArithmeticOverflow`] when a charge cannot be
    /// represented. No partially validated automaton is returned.
    pub fn from_raw(raw: RawPlan, limits: CompileLimits) -> Result<Self, CompileError> {
        let (stats, byte_classes) = validate_raw(&raw, limits)?;
        Ok(Self {
            identity: next_automaton_identity(),
            pooled_workspace: OnceLock::new(),
            start: raw.start,
            roles: raw.roles.into_boxed_slice(),
            edge_offsets: raw.edge_offsets.into_boxed_slice(),
            edge_targets: raw.edge_targets.into_boxed_slice(),
            edge_kinds: raw.edge_kinds.into_boxed_slice(),
            byte_starts: raw.byte_starts.into_boxed_slice(),
            byte_ends: raw.byte_ends.into_boxed_slice(),
            byte_classes,
            epsilon_closure_dispatch: None,
            epsilon_closure_start_program: None,
            ordered_edge_dispatch: None,
            start_filter_proof: StartFilterProofCell::new(),
            line_terminator: b'\n',
            stats,
        })
    }

    /// Bind the byte observed by line-start and line-end assertion edges.
    ///
    /// The byte is immutable after publication and adds no heap storage. Raw
    /// standalone automata default to LF; profile-aware facades call this
    /// before exposing the validated plan. A retained start-filter proof cannot
    /// depend on this byte: context assertions are relaxed while proving byte
    /// classes, while an absolute haystack-start edge is handled separately.
    #[must_use]
    pub fn with_line_terminator(mut self, line_terminator: u8) -> Self {
        // Changing assertion semantics creates a new immutable plan identity.
        // This also makes every previously constructed external workspace fail
        // authentication and prevents an automaton-owned value cache from
        // surviving the consuming configuration mutation.
        self.identity = next_automaton_identity();
        self.pooled_workspace = OnceLock::new();
        self.line_terminator = line_terminator;
        self
    }

    /// Byte observed by line-start and line-end assertion edges.
    #[must_use]
    pub const fn line_terminator(&self) -> u8 {
        self.line_terminator
    }

    #[must_use]
    pub const fn stats(&self) -> PlanStats {
        self.stats
    }

    /// Exact bounded alphabet partition derived from validated byte ranges.
    pub(crate) const fn byte_classes(&self) -> &ByteClasses {
        &self.byte_classes
    }

    /// Derive canonical priority-DFS programs for profitable assertion-free
    /// boundary closures.
    ///
    /// Qualification depends only on the validated graph and fixed compiler
    /// ceilings. `Ok(false)` means no closure qualified (or a fixed ceiling
    /// was reached). Allocation begins only after exact dimensions have been
    /// derived, and the sidecar is canonically reconstructible from the graph.
    ///
    /// # Errors
    ///
    /// Returns the exact bounded allocation extent when a qualifying sidecar
    /// could not be retained.
    pub fn try_enable_epsilon_closure_dispatch(
        &mut self,
    ) -> Result<bool, EpsilonClosureDispatchAllocationError> {
        if self.epsilon_closure_dispatch.is_some() {
            return Ok(true);
        }
        let dispatch = EpsilonClosureDispatch::derive(self)?;
        if dispatch.is_some() {
            // Full is strictly stronger and is the portable K0 authority.
            // Never retain two copies if this hidden source-only API was used
            // before the ordinary all-root attempt.
            self.epsilon_closure_start_program = None;
        }
        self.epsilon_closure_dispatch = dispatch;
        Ok(self.epsilon_closure_dispatch.is_some())
    }

    /// Whether this immutable graph owns canonical Pike closure programs.
    #[must_use]
    pub const fn has_epsilon_closure_dispatch(&self) -> bool {
        self.epsilon_closure_dispatch.is_some()
    }

    /// Retained immutable bytes in the optional Pike closure programs.
    #[must_use]
    pub fn epsilon_closure_dispatch_retained_bytes(&self) -> usize {
        self.epsilon_closure_dispatch
            .as_ref()
            .map_or(0, EpsilonClosureDispatch::retained_bytes)
    }

    /// Derive a bounded start-root closure program solely for native text
    /// specialization.
    ///
    /// Unlike [`Self::try_enable_epsilon_closure_dispatch`], this does not
    /// enable portable K0 dispatch and is deliberately absent from stable
    /// serialization. Source builders may call it only after the canonical
    /// all-root attempt declines. `Ok(true)` means the distinct private owner
    /// is present.
    ///
    /// # Errors
    ///
    /// Returns the exact bounded allocation extent when a qualifying start
    /// program could not be retained.
    #[doc(hidden)]
    pub fn try_enable_epsilon_closure_start_program(
        &mut self,
    ) -> Result<bool, EpsilonClosureDispatchAllocationError> {
        if self.epsilon_closure_start_program.is_some() {
            return Ok(true);
        }
        if self.epsilon_closure_dispatch.is_some() {
            return Ok(false);
        }
        self.epsilon_closure_start_program = EpsilonClosureStartProgram::derive(self)?;
        Ok(self.epsilon_closure_start_program.is_some())
    }

    /// Whether the distinct compiler-private start-only owner is present.
    ///
    /// This intentionally excludes an all-root dispatch even when that
    /// dispatch contains a start program. It is suitable for rejecting a
    /// source-only sidecar on build and serialization paths where it is not
    /// eligible.
    #[doc(hidden)]
    #[must_use]
    pub const fn compiler_private_has_epsilon_closure_start_program(&self) -> bool {
        self.epsilon_closure_start_program.is_some()
    }

    /// Exact retained bytes in the distinct compiler-private start-only
    /// owner. The portable all-root dispatch is accounted separately.
    #[doc(hidden)]
    #[must_use]
    pub fn compiler_private_epsilon_closure_start_program_retained_bytes(&self) -> usize {
        self.epsilon_closure_start_program
            .as_ref()
            .map_or(0, EpsilonClosureStartProgram::retained_bytes)
    }

    /// Borrow only the canonical start-root closure program for native text
    /// specialization.
    ///
    /// This compiler-private view is decoded and address-free. It deliberately
    /// does not expose the all-state root table or either complete instruction
    /// arena, and it returns `None` for a scalar or direct-leaf start root.
    #[doc(hidden)]
    #[must_use]
    pub fn compiler_private_epsilon_closure_start_program_view(
        &self,
    ) -> Option<crate::NativeEpsilonClosureProgramView<'_>> {
        self.epsilon_closure_dispatch
            .as_ref()
            .and_then(|dispatch| dispatch.native_start_program(self.start))
            .or_else(|| {
                self.epsilon_closure_start_program
                    .as_ref()
                    .and_then(|program| program.native_start_program(self.start))
            })
    }

    /// Derive the canonical priority-preserving dispatch for profitable wide
    /// consuming rows.
    ///
    /// Qualification depends only on the validated graph and fixed compiler
    /// ceilings. `Ok(false)` means no row qualified (or the fixed derivation
    /// ceiling was reached). Allocation begins only after exact dimensions
    /// have been derived; an allocation failure is returned explicitly so an
    /// optimizing artifact never changes identity based on allocator state.
    ///
    /// # Errors
    ///
    /// Returns the exact bounded allocation extent when a qualifying sidecar
    /// could not be retained.
    pub fn try_enable_ordered_edge_dispatch(
        &mut self,
    ) -> Result<bool, OrderedEdgeDispatchAllocationError> {
        if self.ordered_edge_dispatch.is_some() {
            return Ok(true);
        }
        self.ordered_edge_dispatch = OrderedEdgeDispatch::derive(self)?;
        Ok(self.ordered_edge_dispatch.is_some())
    }

    /// Whether this immutable graph owns a canonical ordered-edge dispatch.
    #[must_use]
    pub const fn has_ordered_edge_dispatch(&self) -> bool {
        self.ordered_edge_dispatch.is_some()
    }

    /// Retained immutable bytes in the optional ordered-edge dispatch.
    #[must_use]
    pub fn ordered_edge_dispatch_retained_bytes(&self) -> usize {
        self.ordered_edge_dispatch
            .as_ref()
            .map_or(0, OrderedEdgeDispatch::retained_bytes)
    }

    /// Borrow the exact canonical ordered-edge sidecar for native lowering.
    ///
    /// The view is compiler-private and address-free: consumers may copy its
    /// immutable arrays, but must not re-run row admission analysis.
    #[doc(hidden)]
    #[must_use]
    pub fn compiler_private_ordered_edge_dispatch_view(
        &self,
    ) -> Option<crate::NativeOrderedEdgeDispatchView<'_>> {
        self.ordered_edge_dispatch
            .as_ref()
            .map(OrderedEdgeDispatch::native_view)
    }

    /// Retained heap payload of the optional immutable start-filter proof.
    ///
    /// Stable prepared-runtime owners use this after source-free settlement
    /// to recheck their complete retained-byte envelope before publication.
    /// A permanently ordinary policy and an unsettled policy both retain no
    /// proof payload.
    #[doc(hidden)]
    #[must_use]
    pub fn compiler_private_start_filter_proof_retained_bytes(&self) -> usize {
        self.start_filter_proof
            .get()
            .map_or(0, |_| StartFilterProofCell::PAYLOAD_BYTES)
    }

    /// Process-local identity of this exact immutable automaton instance.
    ///
    /// This is exposed only so sibling facade proofs can bind separately
    /// retained auxiliary plans to the one authoritative automaton they were
    /// derived from. It is not a structural hash and must not be persisted.
    #[doc(hidden)]
    #[must_use]
    pub const fn identity(&self) -> u64 {
        self.identity
    }

    pub(crate) const fn boundary_context_classifier(&self) -> BoundaryContextClassifier {
        BoundaryContextClassifier::new(self.stats.assertion_kinds)
    }

    /// Compute the fixed K0 workspace shape without allocating it.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::ArithmeticOverflow`] if its byte or work charge
    /// cannot be represented.
    pub fn workspace_layout(&self) -> Result<WorkspaceLayout, SearchError> {
        WorkspaceLayout::for_automaton(self)
    }

    /// Compute the fixed reusable-workspace shape including the bounded
    /// ordered lazy-DFA accelerator when this graph is structurally eligible.
    ///
    /// Ineligible graphs return the same layout as [`Self::workspace_layout`].
    /// Span searches do not use the accelerator; callers preparing a
    /// span-only workspace should retain the ordinary layout.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::ArithmeticOverflow`] if its byte or work charge
    /// cannot be represented.
    pub fn accelerated_workspace_layout(&self) -> Result<WorkspaceLayout, SearchError> {
        WorkspaceLayout::for_accelerated_automaton(self)
    }

    /// Compute the fixed reusable-workspace shape for endpoint acceleration
    /// plus reverse full-span recovery.
    ///
    /// Ineligible graphs return the ordinary Pike layout. Callers that only
    /// need existence or endpoint projections should use
    /// [`Self::accelerated_workspace_layout`] to avoid reverse storage.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::ArithmeticOverflow`] if its byte or work charge
    /// cannot be represented.
    pub fn bidirectional_workspace_layout(&self) -> Result<WorkspaceLayout, SearchError> {
        WorkspaceLayout::for_bidirectional_automaton(self)
    }

    /// Bind this graph to an output contract without adding a runtime mode flag
    /// to the K0 loop.
    #[must_use]
    pub const fn prepare<O: Operation>(&self) -> TypedPlan<'_, O> {
        TypedPlan {
            automaton: self,
            operation: PhantomData,
        }
    }

    /// Derive and retain the immutable K0 start-filter proof without reading
    /// caller source.
    ///
    /// This setup-only bridge is intended for prepared facades. It requires a
    /// workspace bound to this exact automaton instance, performs the same
    /// complete graph proof as a cold unlimited search without beginning an
    /// empty invocation, and either publishes its fallibly allocated owner or
    /// permanently selects ordinary K0. After success, a later search cannot
    /// derive or allocate the start-filter proof on its first source call.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for an incompatible workspace or an invariant
    /// failure while traversing the already validated graph. Optional owner
    /// allocation failure is a successful semantic decline.
    #[doc(hidden)]
    pub fn prepare_start_filter_with_workspace(
        &self,
        workspace: &mut K0Workspace,
    ) -> Result<crate::K0StartFilterPreparationReceipt, SearchError> {
        crate::k0::prepare_start_filter_with_workspace(self, workspace)
    }

    /// Work-capped counterpart of [`Self::prepare_start_filter_with_workspace`].
    ///
    /// A cap below the complete graph-only proof bound permanently selects
    /// ordinary K0 without attempting finite or window-dependent derivation.
    #[doc(hidden)]
    pub fn prepare_start_filter_with_workspace_limit(
        &self,
        workspace: &mut K0Workspace,
        max_setup_work: u64,
    ) -> Result<crate::K0StartFilterPreparationReceipt, SearchError> {
        crate::k0::prepare_start_filter_with_workspace_limit(
            self,
            workspace,
            max_setup_work,
        )
    }

    /// Conservative graph-only work for the strongest immutable start-filter
    /// proof plus one fallible owner-publication attempt.
    ///
    /// This is zero once either the proof or permanent ordinary K0 has been
    /// settled. An arithmetic failure means no finite setup cap can admit the
    /// optional proof and callers should select ordinary K0.
    #[doc(hidden)]
    pub fn start_filter_preparation_setup_work_bound(&self) -> Result<u64, SearchError> {
        if self.start_filter_proof.is_initialized() {
            return Ok(0);
        }
        self.conservative_start_filter_proof_work_bound()?
            .checked_add(crate::k0::START_FILTER_OWNER_ALLOCATION_WORK)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter preparation work bound",
            })
    }

    /// A conservative certificate for transition work over `input_bytes`.
    ///
    /// The bound covers one initial boundary, one boundary per byte, all
    /// possible consuming-edge inspections, all zero-width closure attempts,
    /// duplicate roots, and per-boundary/per-byte bookkeeping. It excludes
    /// workspace construction and invocation setup. Early match commitment
    /// normally uses much less.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::ArithmeticOverflow`] if the conservative bound
    /// cannot fit in a `u64`.
    pub fn conservative_transition_work_bound(
        &self,
        input_bytes: usize,
    ) -> Result<u64, SearchError> {
        let input = u64::try_from(input_bytes).map_err(|_| SearchError::ArithmeticOverflow {
            computation: "input length conversion",
        })?;
        let edges =
            u64::try_from(self.stats.edges).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "edge count conversion",
            })?;
        let boundaries = input
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "work-bound boundary count",
            })?;
        let closure = edges
            .checked_mul(2)
            .and_then(|value| value.checked_add(2))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "work-bound closure charge",
            })?;
        let consume = edges
            .checked_add(1)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "work-bound consume charge",
            })?;
        let automaton = boundaries
            .checked_mul(closure)
            .and_then(|value| {
                input
                    .checked_mul(consume)
                    .and_then(|tail| value.checked_add(tail))
            })
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "conservative transition work bound",
            })?;
        // The first successful invocation on an immutable automaton derives
        // up to sixty-four exact-position byte classes in two equal tiers and
        // selects a scanner plus bounded secondary filters. Each depth may
        // inspect a state twice
        // and a consuming edge twice while building the next frontier, in
        // addition to the ordinary edge inspection. Later invocations read
        // the automaton-owned result.
        let start_proof = self.conservative_start_filter_proof_work_bound()?;
        // A retained Guard or adaptive Probe normally adds one membership
        // check per candidate/source position. A block-local Guard survivor
        // may be conservatively rechecked after SIMD classification and then
        // checked by one additional deep Probe, so reserve three checks.
        let secondary_filter = input
            .checked_mul(u64::try_from(START_FILTER_MAX_SECONDARY_CHECKS_PER_POSITION).map_err(
                |_| SearchError::ArithmeticOverflow {
                    computation: "start-filter secondary-check count conversion",
                },
            )?)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter guard work bound",
            })?;
        automaton
            .checked_add(start_proof)
            .and_then(|work| work.checked_add(secondary_filter))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "transition work with start-filter proof",
            })
    }

    fn conservative_start_filter_proof_work_bound(&self) -> Result<u64, SearchError> {
        let per_position = self.conservative_start_filter_position_work_bound()?;
        per_position
            .checked_mul(u64::try_from(START_FILTER_PROOF_POSITION_COUNT).map_err(|_| {
                SearchError::ArithmeticOverflow {
                    computation: "start-filter position count conversion",
                }
            })?)
            .and_then(|work| {
                u64::try_from(START_FILTER_MAX_SELECTION_WORK)
                    .ok()
                    .and_then(|selection| work.checked_add(selection))
            })
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter proof work bound",
            })
    }

    pub(crate) fn conservative_start_filter_tail_work_bound(&self) -> Result<u64, SearchError> {
        let per_position = self.conservative_start_filter_position_work_bound()?;
        let selection = START_FILTER_DEEP_POSITION_COUNT
            .checked_mul(
                BYTE_START_BITMAP_POPULATION_WORK + START_FILTER_DEEP_PROBE_SELECTION_WORK,
            )
            .and_then(|work| work.checked_add(START_FILTER_DEEP_PROBE_MAX_BUILD_WORK))
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "deep start-filter selection work bound",
            })?;
        per_position
            .checked_mul(u64::try_from(START_FILTER_DEEP_POSITION_COUNT).map_err(|_| {
                SearchError::ArithmeticOverflow {
                    computation: "deep start-filter position count conversion",
                }
            })?)
            .and_then(|work| {
                u64::try_from(selection)
                    .ok()
                    .and_then(|selection| work.checked_add(selection))
            })
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "deep start-filter proof work bound",
            })
    }

    fn conservative_start_filter_position_work_bound(&self) -> Result<u64, SearchError> {
        u64::try_from(self.stats.states)
            .ok()
            .and_then(|states| states.checked_mul(2))
            .and_then(|states| {
                u64::try_from(self.stats.edges)
                    .ok()
                    .and_then(|edges| edges.checked_mul(3))
                    .and_then(|edges| states.checked_add(edges))
            })
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "start-filter per-position proof work bound",
            })
    }

    /// Conservative completion allowance after cold start-filter derivation
    /// and selection have already been charged.
    pub(crate) fn conservative_post_start_filter_work_bound(
        &self,
        input_bytes: usize,
    ) -> Result<u64, SearchError> {
        let full = self.conservative_transition_work_bound(input_bytes)?;
        let proof = self.conservative_start_filter_proof_work_bound()?;
        full.checked_sub(proof)
            .ok_or(SearchError::InternalInvariant {
                detail: "post-start-filter work bound underflowed",
            })
    }

    /// A conservative total-work certificate for a one-shot K0 call.
    ///
    /// This adds exact cold workspace construction and invocation reset to
    /// [`Self::conservative_transition_work_bound`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::ArithmeticOverflow`] if the conservative bound
    /// cannot fit in a `u64`.
    pub fn conservative_work_bound(&self, input_bytes: usize) -> Result<u64, SearchError> {
        let transition = self.conservative_transition_work_bound(input_bytes)?;
        let setup = WorkspaceLayout::for_automaton(self)?
            .construction_work()
            .checked_add(3)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "conservative one-shot setup work bound",
            })?;
        transition
            .checked_add(setup)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "conservative total search work bound",
            })
    }

    /// A conservative total-work certificate for a reusable-workspace call.
    ///
    /// The setup term includes invocation reset and the rare worst case where
    /// the entire generation table must be cleared before `u64` rollover.
    /// Normal warm calls charge only three setup operations.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::ArithmeticOverflow`] if the conservative bound
    /// cannot fit in a `u64`.
    pub fn conservative_reused_work_bound(&self, input_bytes: usize) -> Result<u64, SearchError> {
        let transition = self.conservative_transition_work_bound(input_bytes)?;
        let states =
            u64::try_from(self.stats.states).map_err(|_| SearchError::ArithmeticOverflow {
                computation: "generation reset state count conversion",
            })?;
        let setup = states
            .checked_add(3)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "conservative reused setup work bound",
            })?;
        transition
            .checked_add(setup)
            .ok_or(SearchError::ArithmeticOverflow {
                computation: "conservative reused total work bound",
            })
    }

    pub(crate) fn state_edges(&self, state: u32) -> core::ops::Range<usize> {
        let state = plan_index(state);
        let next = state.saturating_add(1);
        plan_index(self.edge_offsets[state])..plan_index(self.edge_offsets[next])
    }
}

/// Convert a plan index after construction has proved it fits the host's
/// address space. All supported Rust targets have at least 32-bit `usize`, but
/// keeping the conversion explicit also makes the validation boundary clear.
pub(crate) fn plan_index(value: u32) -> usize {
    usize::try_from(value).expect("validated u32 plan index fits usize")
}

#[derive(Clone, Copy)]
struct Shape {
    states: usize,
    edges: usize,
    storage_bytes: usize,
    validation_work: usize,
}

fn validate_raw(
    raw: &RawPlan,
    limits: CompileLimits,
) -> Result<(PlanStats, ByteClasses), CompileError> {
    let shape = validate_shape(raw, limits)?;
    validate_offsets(&raw.edge_offsets, shape.edges)?;
    let (zero_width_edges, assertion_edges, assertion_kinds, consuming_states, consuming_edges) =
        validate_graph(raw, shape.states)?;
    let byte_classes = ByteClasses::from_validated_ranges(raw);
    Ok((
        PlanStats {
            states: shape.states,
            edges: shape.edges,
            zero_width_edges,
            assertion_edges,
            assertion_kinds,
            consuming_states,
            consuming_edges,
            storage_bytes: shape.storage_bytes,
            validation_work: shape.validation_work,
        },
        byte_classes,
    ))
}

/// Validate a borrowed raw plan without freezing or retaining any graph
/// storage.
///
/// Priority-side graph composition uses this seam to authenticate each
/// independent source before rebasing its indices. Keeping the canonical
/// validator here prevents the composite builder from acquiring a second,
/// drifting definition of a valid Thompson graph.
pub(crate) fn validate_borrowed_raw_plan(
    raw: &RawPlan,
    limits: CompileLimits,
) -> Result<PlanStats, CompileError> {
    validate_raw(raw, limits).map(|(stats, _)| stats)
}

fn validate_shape(raw: &RawPlan, limits: CompileLimits) -> Result<Shape, CompileError> {
    let states = raw.roles.len();
    let edges = raw.edge_targets.len();
    if states == 0 {
        return Err(MalformedPlan::EmptyStateTable.into());
    }
    check_index_space(ResourceKind::States, states)?;
    check_index_space(ResourceKind::Edges, edges)?;
    check_limit(ResourceKind::States, states, limits.max_states)?;
    check_limit(ResourceKind::Edges, edges, limits.max_edges)?;
    if usize::try_from(raw.start).map_or(true, |start| start >= states) {
        return Err(MalformedPlan::StartOutOfBounds {
            start: raw.start,
            states,
        }
        .into());
    }

    let expected_offsets = states
        .checked_add(1)
        .ok_or(CompileError::ArithmeticOverflow {
            computation: "state offset count",
        })?;
    if raw.edge_offsets.len() != expected_offsets {
        return Err(MalformedPlan::OffsetCount {
            expected: expected_offsets,
            actual: raw.edge_offsets.len(),
        }
        .into());
    }
    validate_edge_array_lengths(raw, edges)?;

    let (storage_bytes, validation_work) = raw_plan_resource_requirements(states, edges)?;
    check_limit(
        ResourceKind::ValidationWork,
        validation_work,
        limits.max_validation_work,
    )?;
    check_limit(
        ResourceKind::StorageBytes,
        storage_bytes,
        limits.max_storage_bytes,
    )?;
    Ok(Shape {
        states,
        edges,
        storage_bytes,
        validation_work,
    })
}

/// Canonical allocation-free storage and validation-work prospective for raw
/// graph dimensions.
pub(crate) fn raw_plan_resource_requirements(
    states: usize,
    edges: usize,
) -> Result<(usize, usize), CompileError> {
    check_index_space(ResourceKind::States, states)?;
    check_index_space(ResourceKind::Edges, edges)?;
    let byte_class_work = Automaton::byte_class_map_validation_work(edges).ok_or(
        CompileError::ArithmeticOverflow {
            computation: "byte-class validation work",
        },
    )?;
    let validation_work = states
        .checked_mul(2)
        .and_then(|value| {
            edges
                .checked_mul(2)
                .and_then(|edge_work| value.checked_add(edge_work))
        })
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(byte_class_work))
        .ok_or(CompileError::ArithmeticOverflow {
            computation: "validation work",
        })?;
    let storage_bytes = storage_bytes(states, edges)?;
    Ok((storage_bytes, validation_work))
}

fn check_index_space(resource: ResourceKind, count: usize) -> Result<(), CompileError> {
    if u32::try_from(count).is_err() {
        return Err(MalformedPlan::IndexSpaceExceeded { resource, count }.into());
    }
    Ok(())
}

fn validate_edge_array_lengths(raw: &RawPlan, edges: usize) -> Result<(), CompileError> {
    for (name, actual) in [
        ("edge_kinds", raw.edge_kinds.len()),
        ("byte_starts", raw.byte_starts.len()),
        ("byte_ends", raw.byte_ends.len()),
    ] {
        if actual != edges {
            return Err(MalformedPlan::EdgeArrayLength {
                array: name,
                expected: edges,
                actual,
            }
            .into());
        }
    }
    Ok(())
}

fn validate_graph(
    raw: &RawPlan,
    states: usize,
) -> Result<(usize, usize, u32, u32, usize), CompileError> {
    let mut zero_width_edges = 0usize;
    let mut assertion_edges = 0usize;
    let mut assertion_kinds = 0_u32;
    let mut consuming_states = 0_u32;
    let mut consuming_edges = 0usize;
    let mut has_accept = false;
    for state in 0..states {
        let next_state = state.saturating_add(1);
        let begin = plan_index(raw.edge_offsets[state]);
        let end = plan_index(raw.edge_offsets[next_state]);
        let role = raw.roles[state];
        if role == StateRole::Consume {
            consuming_states =
                consuming_states
                    .checked_add(1)
                    .ok_or(CompileError::ArithmeticOverflow {
                        computation: "consuming state count",
                    })?;
        }
        if role == StateRole::Accept {
            has_accept = true;
            if begin != end {
                return Err(MalformedPlan::AcceptHasEdges {
                    state,
                    edges: end.saturating_sub(begin),
                }
                .into());
            }
            continue;
        }
        for edge in begin..end {
            if validate_edge(raw, states, state, edge, role)? {
                consuming_edges = checked_edge_increment(consuming_edges, "consuming edge count")?;
            } else {
                zero_width_edges =
                    checked_edge_increment(zero_width_edges, "zero-width edge count")?;
                if raw.edge_kinds[edge] != EdgeKind::Epsilon {
                    assertion_edges =
                        checked_edge_increment(assertion_edges, "assertion edge count")?;
                    assertion_kinds |= raw.edge_kinds[edge]
                        .assertion_bit()
                        .expect("validated non-epsilon zero-width edge is an assertion");
                }
            }
        }
    }
    if !has_accept {
        return Err(MalformedPlan::MissingAcceptState.into());
    }
    Ok((
        zero_width_edges,
        assertion_edges,
        assertion_kinds,
        consuming_states,
        consuming_edges,
    ))
}

/// Returns true for a consuming edge and false for a zero-width edge.
fn validate_edge(
    raw: &RawPlan,
    states: usize,
    state: usize,
    edge: usize,
    role: StateRole,
) -> Result<bool, CompileError> {
    let target = raw.edge_targets[edge];
    if usize::try_from(target).map_or(true, |target| target >= states) {
        return Err(MalformedPlan::TargetOutOfBounds {
            edge,
            target,
            states,
        }
        .into());
    }
    let kind = raw.edge_kinds[edge];
    let role_accepts_kind = match role {
        StateRole::Split => kind.is_zero_width(),
        StateRole::Consume => kind == EdgeKind::ByteRange,
        StateRole::Accept => false,
    };
    if !role_accepts_kind {
        return Err(MalformedPlan::EdgeKindForState {
            state,
            edge,
            role: role.name(),
            kind: kind.name(),
        }
        .into());
    }
    if kind == EdgeKind::ByteRange {
        if raw.byte_starts[edge] > raw.byte_ends[edge] {
            return Err(MalformedPlan::InvalidByteRange {
                edge,
                start: raw.byte_starts[edge],
                end: raw.byte_ends[edge],
            }
            .into());
        }
        return Ok(true);
    }
    if raw.byte_starts[edge] != 0 || raw.byte_ends[edge] != 0 {
        return Err(MalformedPlan::NonCanonicalByteBounds {
            edge,
            start: raw.byte_starts[edge],
            end: raw.byte_ends[edge],
        }
        .into());
    }
    Ok(false)
}

fn checked_edge_increment(value: usize, computation: &'static str) -> Result<usize, CompileError> {
    value
        .checked_add(1)
        .ok_or(CompileError::ArithmeticOverflow { computation })
}

fn check_limit(resource: ResourceKind, needed: usize, limit: usize) -> Result<(), CompileError> {
    if needed > limit {
        return Err(CompileError::ResourceLimit {
            resource,
            needed,
            limit,
        });
    }
    Ok(())
}

fn storage_bytes(states: usize, edges: usize) -> Result<usize, CompileError> {
    let offsets = states
        .checked_add(1)
        .and_then(|count| count.checked_mul(size_of::<u32>()))
        .ok_or(CompileError::ArithmeticOverflow {
            computation: "offset table bytes",
        })?;
    let state_bytes =
        states
            .checked_mul(size_of::<StateRole>())
            .ok_or(CompileError::ArithmeticOverflow {
                computation: "state role bytes",
            })?;
    let per_edge = size_of::<u32>()
        .checked_add(size_of::<EdgeKind>())
        .and_then(|value| {
            size_of::<u8>()
                .checked_mul(2)
                .and_then(|bytes| value.checked_add(bytes))
        })
        .ok_or(CompileError::ArithmeticOverflow {
            computation: "edge record bytes",
        })?;
    let edge_bytes = edges
        .checked_mul(per_edge)
        .ok_or(CompileError::ArithmeticOverflow {
            computation: "edge table bytes",
        })?;
    offsets
        .checked_add(state_bytes)
        .and_then(|value| value.checked_add(edge_bytes))
        .and_then(|value| value.checked_add(Automaton::BYTE_CLASS_MAP_RETAINED_BYTES))
        .ok_or(CompileError::ArithmeticOverflow {
            computation: "automaton storage bytes",
        })
}

fn validate_offsets(offsets: &[u32], edges: usize) -> Result<(), CompileError> {
    if offsets[0] != 0 {
        return Err(MalformedPlan::FirstOffsetNotZero { actual: offsets[0] }.into());
    }
    let mut previous = 0u32;
    for (state, &offset) in offsets.iter().enumerate() {
        if offset < previous {
            return Err(MalformedPlan::OffsetDecreases {
                state: state.saturating_sub(1),
                from: previous,
                to: offset,
            }
            .into());
        }
        if usize::try_from(offset).map_or(true, |offset| offset > edges) {
            return Err(MalformedPlan::OffsetOutOfBounds {
                state: state.saturating_sub(1),
                offset,
                edges,
            }
            .into());
        }
        previous = offset;
    }
    if usize::try_from(previous) != Ok(edges) {
        return Err(MalformedPlan::FinalOffsetMismatch {
            final_offset: previous,
            edges,
        }
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;
    use crate::{Exists, SearchLimits, SearchWindow};

    fn raw_ranges(ranges: &[(u8, u8)]) -> RawPlan {
        let edges = u32::try_from(ranges.len()).expect("focused edge count fits u32");
        RawPlan {
            start: 0,
            roles: vec![StateRole::Consume, StateRole::Accept],
            edge_offsets: vec![0, edges, edges],
            edge_targets: vec![1; ranges.len()],
            edge_kinds: vec![EdgeKind::ByteRange; ranges.len()],
            byte_starts: ranges.iter().map(|&(start, _)| start).collect(),
            byte_ends: ranges.iter().map(|&(_, end)| end).collect(),
        }
    }

    fn compile_ranges(ranges: &[(u8, u8)]) -> Automaton {
        Automaton::from_raw(raw_ranges(ranges), CompileLimits::default())
            .expect("focused byte ranges form a valid automaton")
    }

    #[test]
    fn compiler_private_start_filter_proof_charge_tracks_all_three_states() {
        let unsettled = compile_ranges(&[(b'a', b'a')]);
        assert!(!unsettled.start_filter_proof.is_initialized());
        assert_eq!(
            unsettled.compiler_private_start_filter_proof_retained_bytes(),
            0
        );

        let ordinary = compile_ranges(&[(b'a', b'a')]);
        ordinary.start_filter_proof.mark_allocation_failed().unwrap();
        assert!(ordinary.start_filter_proof.is_permanently_ordinary());
        assert_eq!(
            ordinary.compiler_private_start_filter_proof_retained_bytes(),
            0
        );

        let published = compile_ranges(&[(b'a', b'a')]);
        published
            .start_filter_proof
            .set(&StartFilterProof {
                scanner: None,
                filter: None,
                force_haystack_start: false,
                relaxed_nullable: false,
            })
            .unwrap();
        assert!(published.start_filter_proof.get().is_some());
        assert_eq!(
            published.compiler_private_start_filter_proof_retained_bytes(),
            StartFilterProofCell::PAYLOAD_BYTES
        );
    }

    #[test]
    fn byte_classes_cover_overlapping_disjoint_full_and_high_ranges() {
        let overlapping = compile_ranges(&[(1, 5), (3, 7)]);
        let classes = overlapping.byte_classes();
        assert_eq!(classes.count(), 5);
        for (byte, class) in [
            (0, 0),
            (1, 1),
            (2, 1),
            (3, 2),
            (5, 2),
            (6, 3),
            (7, 3),
            (8, 4),
            (255, 4),
        ] {
            assert_eq!(classes.class_of(byte), class, "byte={byte}");
        }
        for (class, representative) in [(0, 0), (1, 1), (2, 3), (3, 6), (4, 8)] {
            assert_eq!(classes.representative(class), Some(representative));
        }
        assert_eq!(classes.representative(5), None);

        let disjoint = compile_ranges(&[(10, 20), (30, 40)]);
        let classes = disjoint.byte_classes();
        assert_eq!(classes.count(), 5);
        for (class, representative) in [(0, 0), (1, 10), (2, 21), (3, 30), (4, 41)] {
            assert_eq!(classes.representative(class), Some(representative));
        }

        let full = compile_ranges(&[(0, u8::MAX)]);
        let classes = full.byte_classes();
        assert_eq!(classes.count(), 1);
        assert_eq!(classes.representative(0), Some(0));
        assert!((u8::MIN..=u8::MAX).all(|byte| classes.class_of(byte) == 0));

        let high = compile_ranges(&[(254, 255), (255, 255)]);
        let classes = high.byte_classes();
        assert_eq!(classes.count(), 3);
        assert_eq!(classes.representative(0), Some(0));
        assert_eq!(classes.representative(1), Some(254));
        assert_eq!(classes.representative(2), Some(255));
    }

    #[test]
    fn byte_classes_support_all_singletons_and_clone_preserves_the_map() {
        let ranges: Vec<_> = (u8::MIN..=u8::MAX).map(|byte| (byte, byte)).collect();
        let automaton = compile_ranges(&ranges);
        let classes = automaton.byte_classes();
        assert_eq!(classes.count(), BYTE_CLASS_DOMAIN_SIZE);
        for byte in u8::MIN..=u8::MAX {
            assert_eq!(classes.class_of(byte), byte);
            assert_eq!(classes.representative(byte), Some(byte));
        }
        assert_eq!(
            Automaton::BYTE_CLASS_MAP_RETAINED_BYTES,
            BYTE_CLASS_DOMAIN_SIZE + size_of::<u16>()
        );

        let expected_validation_work = 2 * 2
            + ranges.len() * 2
            + 1
            + Automaton::byte_class_map_validation_work(ranges.len()).unwrap();
        assert_eq!(automaton.stats().validation_work(), expected_validation_work);
        let expected_storage_bytes = 3 * size_of::<u32>()
            + 2 * size_of::<StateRole>()
            + ranges.len()
                * (size_of::<u32>() + size_of::<EdgeKind>() + 2 * size_of::<u8>())
            + Automaton::BYTE_CLASS_MAP_RETAINED_BYTES;
        assert_eq!(automaton.stats().storage_bytes(), expected_storage_bytes);

        let identity = automaton.identity();
        let cloned = automaton.clone();
        assert_ne!(cloned.identity(), identity);
        assert_eq!(cloned.byte_classes(), automaton.byte_classes());
        assert_eq!(cloned.stats(), automaton.stats());
    }

    #[test]
    fn byte_classes_refine_every_validated_edge_exhaustively() {
        let ranges = [
            (0, 0),
            (0, 255),
            (1, 17),
            (5, 9),
            (9, 200),
            (64, 127),
            (128, 254),
            (200, 255),
            (255, 255),
        ];
        let automaton = compile_ranges(&ranges);
        let classes = automaton.byte_classes();
        for class in 0..classes.count() {
            let class = u8::try_from(class).expect("class ID fits u8");
            let representative = classes
                .representative(class)
                .expect("each retained class has a representative");
            assert_eq!(classes.class_of(representative), class);
            for &(start, end) in &ranges {
                let representative_is_member = start <= representative && representative <= end;
                for byte in u8::MIN..=u8::MAX {
                    if classes.class_of(byte) == class {
                        assert_eq!(
                            start <= byte && byte <= end,
                            representative_is_member,
                            "class={class} byte={byte} range={start}..={end}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn byte_classes_preserve_malformed_and_exact_limit_boundaries() {
        let malformed = raw_ranges(&[(9, 8)]);
        assert_eq!(
            Automaton::from_raw(malformed, CompileLimits::default()).unwrap_err(),
            CompileError::Malformed(MalformedPlan::InvalidByteRange {
                edge: 0,
                start: 9,
                end: 8,
            })
        );

        let raw = raw_ranges(&[(0, 7), (3, 11), (250, 255)]);
        let baseline = Automaton::from_raw(raw.clone(), CompileLimits::default())
            .expect("baseline limits admit byte classes");
        let storage_bytes = baseline.stats().storage_bytes();
        let validation_work = baseline.stats().validation_work();
        assert_eq!(
            Automaton::from_raw(
                raw.clone(),
                CompileLimits {
                    max_storage_bytes: storage_bytes - 1,
                    ..CompileLimits::default()
                },
            )
            .unwrap_err(),
            CompileError::ResourceLimit {
                resource: ResourceKind::StorageBytes,
                needed: storage_bytes,
                limit: storage_bytes - 1,
            }
        );
        assert_eq!(
            Automaton::from_raw(
                raw,
                CompileLimits {
                    max_validation_work: validation_work - 1,
                    ..CompileLimits::default()
                },
            )
            .unwrap_err(),
            CompileError::ResourceLimit {
                resource: ResourceKind::ValidationWork,
                needed: validation_work,
                limit: validation_work - 1,
            }
        );
    }

    #[test]
    fn pooled_workspace_owner_is_one_resource_transaction() {
        let exact = compile_ranges(&[(b'a', b'a')]);
        let payload = K0Workspace::new_selected(&exact, WorkspaceLimits::unlimited(), false, false)
            .expect("focused selected workspace constructs");
        let limits = WorkspaceLimits {
            max_setup_work: payload
                .construction_accounting()
                .work()
                .checked_add(Automaton::POOLED_WORKSPACE_OWNER_PUBLICATION_WORK)
                .unwrap(),
            max_scratch_bytes: payload
                .retained_bytes()
                .checked_add(Automaton::pooled_workspace_owner_bytes())
                .unwrap(),
        };
        drop(payload);

        let one_below_owner = compile_ranges(&[(b'a', b'a')]);
        assert!(
            one_below_owner
                .try_checkout_pooled_workspace(
                    WorkspaceLimits {
                        max_scratch_bytes: limits.max_scratch_bytes - 1,
                        ..limits
                    },
                    false,
                    false,
                )
                .is_none()
        );
        assert!(
            one_below_owner.pooled_workspace.get().is_none(),
            "resource refusal must not retain an empty owner",
        );
        assert_eq!(
            one_below_owner
                .prepare::<Exists>()
                .search_window(b"za", SearchWindow::full(b"za"), SearchLimits::unlimited(),)
                .unwrap()
                .into_output(),
            true,
            "canonical one-shot remains independently available",
        );

        let admitted = exact
            .try_checkout_pooled_workspace(limits, false, false)
            .expect("exact aggregate owner and payload limits admit");
        assert!(exact.pooled_workspace.get().is_some());
        exact.return_pooled_workspace(admitted);
        assert!(
            exact
                .pooled_workspace
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn pooled_workspace_owner_failure_poison_and_plan_mutation_fail_closed() {
        let allocation_failed = compile_ranges(&[(b'a', b'a')]);
        assert!(
            allocation_failed
                .try_checkout_pooled_workspace_with(
                    WorkspaceLimits::unlimited(),
                    true,
                    true,
                    |owner| Err((fre_exact_alloc::CopyError::AllocationFailed, owner)),
                )
                .is_none()
        );
        assert!(allocation_failed.pooled_workspace.get().is_none());

        let poisoned = compile_ranges(&[(b'a', b'a')]);
        let workspace = poisoned
            .try_checkout_pooled_workspace(WorkspaceLimits::unlimited(), true, true)
            .expect("focused workspace constructs");
        poisoned.return_pooled_workspace(workspace);
        let owner = poisoned.pooled_workspace.get().unwrap();
        let poisoned_result = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = owner.lock().unwrap();
                    panic!("poison focused pool owner");
                })
                .join()
        });
        assert!(poisoned_result.is_err());
        assert!(
            poisoned
                .try_checkout_pooled_workspace(WorkspaceLimits::unlimited(), true, true)
                .is_none(),
            "a poisoned optional owner declines to canonical execution",
        );
        assert_eq!(
            poisoned
                .prepare::<Exists>()
                .search_window(b"za", SearchWindow::full(b"za"), SearchLimits::unlimited(),)
                .unwrap()
                .into_output(),
            true,
        );

        let mutable = compile_ranges(&[(b'a', b'a')]);
        let old_identity = mutable.identity();
        let workspace = mutable
            .try_checkout_pooled_workspace(WorkspaceLimits::unlimited(), true, true)
            .expect("focused workspace constructs");
        mutable.return_pooled_workspace(workspace);
        let changed = mutable.with_line_terminator(b';');
        assert_ne!(changed.identity(), old_identity);
        assert!(
            changed.pooled_workspace.get().is_none(),
            "a language-configuration mutation gets a fresh pool",
        );
    }
}
