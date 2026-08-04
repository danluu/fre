use core::{marker::PhantomData, mem::size_of};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};

use fre_simd_kernels::{
    AsciiByteSet, AsciiByteSetClassifier, AsciiByteSetRunScanner, AsciiSelection,
    ByteSetClassifier, ASCII_CLASSIFIER_BUILD_WORK, ASCII_RUN_SCANNER_BUILD_WORK,
};

use crate::{CompileError, MalformedPlan, Operation, ResourceKind, TypedPlan, WorkspaceLayout};

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

/// Number of exact consumed-byte positions retained by the bounded start
/// filter. Any of offsets zero through fifteen may supply the primary
/// scanner; at most one other position may supply a secondary Guard or Probe.
pub(crate) const START_FILTER_POSITION_COUNT: usize = 16;
/// Largest consumed-byte offset inspected by the bounded start filter.
pub(crate) const START_FILTER_MAX_OFFSET: usize = START_FILTER_POSITION_COUNT - 1;
/// Maximum secondary exact-position filters retained by one immutable proof.
pub(crate) const START_FILTER_MAX_GUARDS: usize = 1;
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
    ASCII_CLASSIFIER_BUILD_WORK + ASCII_RUN_SCANNER_BUILD_WORK;
/// Exact abstract work to compare one position with the incumbent scanner.
pub(crate) const START_FILTER_SCANNER_SELECTION_WORK: usize = 1;
/// Exact abstract work to compare one non-scanner position with the incumbent
/// secondary filter.
pub(crate) const START_FILTER_GUARD_SELECTION_WORK: usize = 1;
/// Optional work to retain one already-compared broad exact-position class as
/// an adaptive Probe after the primary scanner has been fully constructed.
pub(crate) const START_FILTER_PROBE_SELECTION_WORK: usize = 1;
/// Largest non-scanner byte class selective enough to retain as a guard.
/// Sixty-four members are one quarter of the complete 256-byte domain.
pub(crate) const START_FILTER_GUARD_MAX_CARDINALITY: u32 = 64;
/// Conservative selection bound: count and compare every exact-position set,
/// compare every non-scanner set for the optional secondary filter, compile
/// the costliest retained scanner, then retain a broad Probe when eligible.
pub(crate) const START_FILTER_MAX_SELECTION_WORK: usize = START_FILTER_POSITION_COUNT
    * (BYTE_START_BITMAP_POPULATION_WORK + START_FILTER_SCANNER_SELECTION_WORK)
    + START_FILTER_MAX_OFFSET * START_FILTER_GUARD_SELECTION_WORK
    + BYTE_START_RANGE_DETECTION_WORK
    + BYTE_START_SET_CLASSIFIER_BUILD_WORK
    + START_FILTER_PROBE_SELECTION_WORK;

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
/// The first successful search on an immutable [`Automaton`] also charges its
/// bounded full-byte start-filter proof and scanner/secondary-filter
/// selection. The automaton fallibly retains that result in one cold heap
/// owner, so later calls do not repeat or charge that work. Owner publication
/// requires one additional work unit and enough scratch allowance for its
/// exact payload; refusal preserves ordinary K0 and leaves publication
/// retryable.
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
    nonmembers: AsciiByteSetRunScanner,
}

impl StartAsciiClassifier {
    pub(crate) fn new(set: AsciiByteSet) -> Self {
        let words = set.words();
        Self {
            inner: AsciiByteSetClassifier::new(set),
            // This scanner advances only across ASCII bytes outside the exact
            // start set. A high byte deliberately ends the run so the caller
            // can fall back to the full fixed-block membership path.
            nonmembers: AsciiByteSetRunScanner::new(AsciiByteSet::from_words([
                !words[0], !words[1],
            ])),
        }
    }

    pub(crate) const fn classifier(&self) -> &AsciiByteSetClassifier {
        &self.inner
    }

    pub(crate) const fn nonmember_scanner(&self) -> &AsciiByteSetRunScanner {
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
pub(crate) struct StartPositionClass {
    pub(crate) offset: u8,
    pub(crate) set: ByteSet,
}

/// Execution policy for the one retained non-scanner exact-position class.
///
/// A guard is checked for every primary candidate. A probe starts inactive
/// and is enabled only by invocation-local evidence from rejected primary
/// candidates. Keeping the policy in the immutable proof makes the two routes
/// auditable without retaining any source-dependent state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartPositionFilter {
    Guard(StartPositionClass),
    Probe(StartPositionClass),
}

impl StartPositionFilter {
    pub(crate) const fn guard(&self) -> Option<&StartPositionClass> {
        match self {
            Self::Guard(class) => Some(class),
            Self::Probe(_) => None,
        }
    }

    pub(crate) const fn probe(&self) -> Option<&StartPositionClass> {
        match self {
            Self::Guard(_) => None,
            Self::Probe(class) => Some(class),
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

    pub(crate) const fn probe(&self) -> Option<&StartPositionClass> {
        match &self.filter {
            Some(filter) => filter.probe(),
            None => None,
        }
    }
}

/// Cold, fallibly allocated owner for one published start-filter proof.
///
/// `None` inside the lock is a permanent allocation-failure sentinel. Resource
/// refusal does not initialize the lock, so a later invocation with more
/// scratch allowance may retry. `get_or_init` serializes the fallible
/// allocation itself: concurrent successful first users may each derive the
/// same immutable proof, but exactly one of them attempts to allocate its
/// retained owner.
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

    pub(crate) fn allocation_failed(&self) -> bool {
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
    pub(crate) start: u32,
    pub(crate) roles: Box<[StateRole]>,
    pub(crate) edge_offsets: Box<[u32]>,
    pub(crate) edge_targets: Box<[u32]>,
    pub(crate) edge_kinds: Box<[EdgeKind]>,
    pub(crate) byte_starts: Box<[u8]>,
    pub(crate) byte_ends: Box<[u8]>,
    byte_classes: ByteClasses,
    pub(crate) start_filter_proof: StartFilterProofCell,
    line_terminator: u8,
    stats: PlanStats,
}

impl Clone for Automaton {
    fn clone(&self) -> Self {
        Self {
            identity: next_automaton_identity(),
            start: self.start,
            roles: self.roles.clone(),
            edge_offsets: self.edge_offsets.clone(),
            edge_targets: self.edge_targets.clone(),
            edge_kinds: self.edge_kinds.clone(),
            byte_starts: self.byte_starts.clone(),
            byte_ends: self.byte_ends.clone(),
            byte_classes: self.byte_classes,
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
            start: raw.start,
            roles: raw.roles.into_boxed_slice(),
            edge_offsets: raw.edge_offsets.into_boxed_slice(),
            edge_targets: raw.edge_targets.into_boxed_slice(),
            edge_kinds: raw.edge_kinds.into_boxed_slice(),
            byte_starts: raw.byte_starts.into_boxed_slice(),
            byte_ends: raw.byte_ends.into_boxed_slice(),
            byte_classes,
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
    pub const fn with_line_terminator(mut self, line_terminator: u8) -> Self {
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

    pub(crate) const fn identity(&self) -> u64 {
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
        // up to sixteen exact-position byte classes and selects a scanner plus
        // one secondary Guard or Probe. Each depth may inspect a state twice
        // and a consuming edge twice while building the next frontier, in
        // addition to the ordinary edge inspection. Later invocations read
        // the automaton-owned result.
        let start_proof = self.conservative_start_filter_proof_work_bound()?;
        // The mutually exclusive retained Guard or adaptive Probe can add at
        // most one membership check per candidate/source position on top of
        // the full all-boundaries automaton bound.
        let secondary_filter = input
            .checked_mul(u64::try_from(START_FILTER_MAX_GUARDS).map_err(|_| {
                SearchError::ArithmeticOverflow {
                    computation: "start-filter guard count conversion",
                }
            })?)
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
        let per_position = u64::try_from(self.stats.states)
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
            })?;
        per_position
            .checked_mul(u64::try_from(START_FILTER_POSITION_COUNT).map_err(|_| {
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
    check_limit(
        ResourceKind::ValidationWork,
        validation_work,
        limits.max_validation_work,
    )?;
    let storage_bytes = storage_bytes(states, edges)?;
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

use crate::SearchError;

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

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
}
