use fre_automata::{
    Automaton, CompileLimits as AutomatonCompileLimits, EdgeKind, Exists, K0ResumeSet, K0Workspace,
    RawPlan, SearchLimits, SearchWindow as K0SearchWindow, SelectedEnd, Span, StateRole,
    WorkspaceLimits,
};
use fre_simd_kernels::{
    ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, AsciiByteSet, AsciiByteSetClassifier,
    BYTE_SET_BLOCK_BYTES, BYTE_SET_WIDE_BLOCK_BYTES, ByteSet256, ByteSetClassifier,
};
use memchr::{memchr, memchr2, memchr3};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::{
    CompileMode,
    context_dfa::{
        self, ContextDfa, ContextDfaDecline, ContextDfaLimits, ContextDfaOutcome, ContextDfaStats,
        NativeContextDfaView,
    },
    dfa::{
        self, DeterminizationReport, DeterminizeLimits, DeterminizeOutcome, DfaStats,
        NativeDfaView, OrderedDfa, PartialDfa, PartialDfaPrefixPlan, PartialDfaResult,
        PartialDfaResume,
    },
    error::CompileError,
    required_literals::{self, RequiredLiterals},
    seeded_reverse::{
        SeededReverseBuild, SeededReverseDfa, SeededReverseLimits, SeededReverseSeed,
        build_seeded_reverse_exact,
    },
};

const PROGRAM_MAGIC: &[u8; 8] = b"FREGAOT\0";
const PROGRAM_FORMAT_VERSION_V1: u32 = 1;
const PROGRAM_FORMAT_VERSION_V2: u32 = 2;
const PROGRAM_FORMAT_VERSION_V3: u32 = 3;
const PROGRAM_FORMAT_VERSION_V4: u32 = 4;
const PROGRAM_FORMAT_VERSION: u32 = PROGRAM_FORMAT_VERSION_V4;
const PROGRAM_FLAG_NFA_MANDATORY_SUFFIX: u8 = 1 << 0;
const PROGRAM_FLAG_NFA_MANDATORY_CUT: u8 = 1 << 1;
const PROGRAM_FLAG_NFA_EXACT_PRODUCT: u8 = 1 << 2;
const PROGRAM_FLAG_NFA_PARTIAL_DFA: u8 = 1 << 3;
const PROGRAM_V3_KNOWN_FLAGS: u8 = PROGRAM_FLAG_NFA_MANDATORY_SUFFIX
    | PROGRAM_FLAG_NFA_MANDATORY_CUT
    | PROGRAM_FLAG_NFA_EXACT_PRODUCT;
const PROGRAM_KNOWN_FLAGS: u8 = PROGRAM_FLAG_NFA_MANDATORY_SUFFIX
    | PROGRAM_FLAG_NFA_MANDATORY_CUT
    | PROGRAM_FLAG_NFA_EXACT_PRODUCT
    | PROGRAM_FLAG_NFA_PARTIAL_DFA;
const DEFAULT_LINE_TERMINATOR: u8 = b'\n';
/// Number of bytes that a runtime must read before it can discover the exact
/// serialized artifact extent.
pub const PROGRAM_HEADER_LEN: usize = 24;
/// Hard ceiling accepted by the stable deserializer and runtime boundary.
///
/// This matches the default compiler program budget. It bounds the only raw
/// pointer extent that the runtime discovers from the artifact itself.
pub const MAX_SERIALIZED_PROGRAM_BYTES: usize = 256 * 1024 * 1024;
const MIN_SERIALIZED_PROGRAM_BYTES: usize = PROGRAM_HEADER_LEN + 52 + 8;
/// Maximum fixed byte depth inspected by the source-independent anchored
/// prefix analysis.
pub const MAX_ANCHORED_PREFIX_BYTES: usize = 16;
/// Maximum fixed byte depth inspected by the source-independent anchored
/// suffix analysis. Index zero is the final consumed byte.
pub(crate) const MAX_ANCHORED_SUFFIX_BYTES: usize = 8;
/// Hard work ceiling for anchored-prefix derivation.
///
/// Work charges state visits, edge visits, and bytes inserted into a set. A
/// graph that reaches this ceiling simply receives no prefix optimization; it
/// remains fully executable through the same semantic program.
const MAX_ANCHORED_PREFIX_WORK: u64 = 1_000_000;
/// Hard work ceiling for anchored-suffix derivation.
const MAX_ANCHORED_SUFFIX_WORK: u64 = 1_000_000;
/// Hard work ceiling for the optional graph-wide exact-width proof.
const MAX_EXACT_WIDTH_WORK: u64 = 1_000_000;
/// Hard work ceiling for the optional graph-wide maximum-width proof.
const MAX_MATCH_WIDTH_WORK: u64 = 1_000_000;
/// Maximum conservative false-candidate work admitted for the portable NFA
/// mandatory-suffix accelerator. The product is the proved maximum match
/// width times the primary suffix-column cardinality.
const MAX_NFA_SUFFIX_CANDIDATE_WORK: usize = 64;
const MAX_NFA_SUFFIX_REVERSE_STATES: usize = 4_096;
const MAX_NFA_SUFFIX_REVERSE_CELLS: usize = 262_144;
const MAX_NFA_SUFFIX_REVERSE_WORK: u64 = 8_000_000;
const MAX_NFA_SUFFIX_REVERSE_MEMORY_BYTES: usize = 16 * 1024 * 1024;
/// Permit a short burst before measuring suffix-filter density. Thereafter the
/// scanner admits four times the uniform expected hit rate for its one-to-
/// three-byte primary set and falls back to the ordinary ordered NFA when the
/// observed input is denser.
const NFA_SUFFIX_PRIMARY_HIT_CREDIT: usize = 8;
const NFA_SUFFIX_PRIMARY_HIT_DENOMINATOR: usize = 64;
/// Bound cumulative reverse verification for mandatory suffixes whose match
/// width is unbounded (or whose width proof exhausted its resource envelope).
/// One late sparse candidate may inspect the complete preceding window, but
/// repeated false candidates may not turn the accelerator into a quadratic
/// scan. The credit keeps short windows and a small burst of candidates out of
/// the ordinary executor without weakening the asymptotic bound.
const NFA_SUFFIX_SCAN_ONLY_REVERSE_WORK_CREDIT: usize = 1_024;
const NFA_SUFFIX_SCAN_ONLY_REVERSE_WORK_MULTIPLIER: usize = 2;
/// A graph-wide byte cut must be substantially selective before its probe is
/// placed in front of the ordinary ordered-NFA executor. For a uniformly
/// distributed source, 64 members imply one hit every four bytes; broader
/// sets cannot amortize even their short scalar admission probe. Real sources
/// can still benefit from any narrower class that is absent from a window.
const MAX_NFA_MANDATORY_CUT_CARDINALITY: u16 = 64;
/// An ordinary mandatory cut always names a real Thompson state. This reserved
/// value lets the mutually exclusive cut slot retain a complete exact-product
/// scanner without changing the scanner enum or compiled-program layout.
const NFA_EXACT_PRODUCT_ROOT_SENTINEL: u32 = u32::MAX;
/// Because the cut is an extra pass, it must halve the strongest existing
/// forward column's uniform expected hit rate. This prevents a marginally
/// narrower interior class from displacing K0's already-vectorized filter.
const NFA_MANDATORY_CUT_MIN_SELECTIVITY_GAIN: u16 = 2;
/// Keep a common positive search out of vector setup. A miss through this
/// short prefix earns the target-dispatched block classifier for the rest of
/// the window.
const NFA_MANDATORY_CUT_SCALAR_PREFIX_BYTES: usize = 8;

/// Checked failure while reconstructing a stable AOT semantic program.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProgramFormatError {
    /// A fixed field, tag, count, table shape, or trailing extent is invalid.
    Malformed(&'static str),
    /// The embedded Thompson graph failed the canonical automaton validator.
    Automaton(fre_automata::CompileError),
    /// A bounded reconstruction allocation could not be reserved.
    Allocation(&'static str),
}

impl fmt::Display for ProgramFormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(detail) => write!(formatter, "malformed AOT program: {detail}"),
            Self::Automaton(error) => write!(formatter, "invalid AOT automaton: {error}"),
            Self::Allocation(table) => {
                write!(formatter, "could not allocate bounded AOT {table} table")
            }
        }
    }
}

impl std::error::Error for ProgramFormatError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Automaton(error) => Some(error),
            Self::Malformed(_) | Self::Allocation(_) => None,
        }
    }
}

impl From<fre_automata::CompileError> for ProgramFormatError {
    fn from(value: fre_automata::CompileError) -> Self {
        Self::Automaton(value)
    }
}

/// Capture-free result promised by one compiled entry point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputContract {
    Exists,
    SelectedEnd,
    Span,
}

impl OutputContract {
    const fn tag(self) -> u8 {
        match self {
            Self::Exists => 0,
            Self::SelectedEnd => 1,
            Self::Span => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ProgramFormatError> {
        match tag {
            0 => Ok(Self::Exists),
            1 => Ok(Self::SelectedEnd),
            2 => Ok(Self::Span),
            _ => Err(ProgramFormatError::Malformed("unknown output-contract tag")),
        }
    }
}

/// Result of executing a program with its statically selected contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchResult {
    Exists(bool),
    SelectedEnd(Option<usize>),
    Span(Option<(usize, usize)>),
}

impl MatchResult {
    #[must_use]
    pub const fn is_match(self) -> bool {
        match self {
            Self::Exists(found) => found,
            Self::SelectedEnd(found) => found.is_some(),
            Self::Span(found) => found.is_some(),
        }
    }
}

/// Half-open byte range searched by a compiled program.
///
/// Construction is cheap and validation happens transactionally at
/// [`CompiledProgram::search`], before either engine reads the haystack.
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

/// Structurally selected target-neutral execution engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineKind {
    /// Universal prioritized Thompson-NFA execution.
    OrderedNfa,
    /// Complete byte-local ordered-DFA execution.
    OrderedDfa,
    /// Complete ordered DFA whose state keys include byte-local assertion
    /// context.
    ///
    /// This variant is observable only on a fresh optimizing compilation.
    /// Stable program serialization deliberately stores its universal
    /// ordered-NFA representation, so deserializing those bytes reports
    /// [`Self::OrderedNfa`] and has no contextual sidecar.
    OrderedContextDfa,
}

/// Structural reason that one target-neutral execution engine was selected.
///
/// No source spelling, pattern identity, or benchmark identity participates in
/// this decision. [`CompiledProgram::determinization_report`] and
/// [`CompiledProgram::context_determinization_report`] preserve the exact
/// resource and completed work behind their respective fallbacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineSelectionReason {
    /// The caller explicitly selected the fast universal ordered-NFA route.
    FastMode,
    /// Optimizing mode completed ordered determinization.
    CompleteDfa,
    /// Optimizing mode completed contextual ordered determinization. The
    /// fresh program and emitted object use the self-contained contextual DFA.
    CompleteContextDfa,
    /// Context assertions were present, but contextual determinization was
    /// structurally unsupported or declined under its resource limits. The
    /// universal ordered-NFA representation remains executable; inspect
    /// [`CompiledProgram::context_determinization_report`] for exact details.
    ContextAssertions,
    /// Complete determinization was structurally declined under its limits;
    /// inspect [`CompiledProgram::determinization_report`] for exact details.
    DeterminizationResourceLimit,
}

impl EngineKind {
    const fn tag(self) -> u8 {
        match self {
            // Contextual sidecars are intentionally absent from the stable
            // wire format. Their semantic artifact is the ordered NFA.
            Self::OrderedNfa | Self::OrderedContextDfa => 0,
            Self::OrderedDfa => 1,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ProgramFormatError> {
        match tag {
            0 => Ok(Self::OrderedNfa),
            1 => Ok(Self::OrderedDfa),
            _ => Err(ProgramFormatError::Malformed("unknown engine tag")),
        }
    }
}

/// Immutable dimensions of one compiled semantic program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramStats {
    pub engine: EngineKind,
    /// Compile-time selection provenance, if retained by this value.
    pub engine_selection_reason: Option<EngineSelectionReason>,
    pub thompson_states: usize,
    pub thompson_edges: usize,
    pub serialized_bytes: usize,
    pub dfa: Option<DfaStats>,
    /// Fresh contextual-determinization outcome. This is `None` for
    /// assertion-free programs, Fast mode, and deserialized artifacts.
    pub context_determinization: Option<ContextDeterminizationReport>,
    /// Compile-time determinization provenance, if retained by this value.
    pub determinization: Option<DeterminizationReport>,
    /// Structural fixed prefix available to native candidate filtering.
    pub anchored_prefix: AnchoredPrefixStats,
    /// Proven maximum consumed byte width, or `None` when the graph is
    /// structurally unbounded or the optional bounded proof declined.
    pub max_match_width: Option<usize>,
}

/// Fresh-compilation provenance for optional contextual determinization.
///
/// Exactly one of `stats` and `decline` is present. The report is intentionally
/// omitted from the stable semantic-program wire format together with the
/// contextual DFA sidecar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextDeterminizationReport {
    /// Limits supplied by the caller.
    pub requested_limits: DeterminizeLimits,
    /// Limits after clamping to the stable artifact construction ceilings.
    pub effective_limits: DeterminizeLimits,
    /// Complete contextual machine dimensions, when construction succeeded.
    pub stats: Option<ContextDfaStats>,
    /// Exact construction decline, when no contextual machine was retained.
    pub decline: Option<ContextDfaDecline>,
}

impl ContextDeterminizationReport {
    fn complete(requested_limits: DeterminizeLimits, stats: ContextDfaStats) -> Self {
        Self {
            requested_limits,
            effective_limits: requested_limits.effective_for_stable_artifact(),
            stats: Some(stats),
            decline: None,
        }
    }

    fn declined(requested_limits: DeterminizeLimits, decline: ContextDfaDecline) -> Self {
        Self {
            requested_limits,
            effective_limits: requested_limits.effective_for_stable_artifact(),
            stats: None,
            decline: Some(decline),
        }
    }
}

/// Result of the bounded, graph-only anchored-prefix analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchoredPrefixStats {
    /// Number of leading bytes every accepting path must consume.
    ///
    /// This is capped at [`MAX_ANCHORED_PREFIX_BYTES`]. A value at the cap is
    /// still a lower bound: an accepting path may require more bytes.
    pub guaranteed_bytes: usize,
    /// Positions whose conservative byte set excludes at least one byte.
    pub selective_positions: usize,
    /// Deterministic derivation work charged before completion or decline.
    pub derivation_work: u64,
    /// Whether the fixed work ceiling declined this optional analysis.
    pub resource_limited: bool,
    /// Whether the analysis conservatively traversed context assertions.
    pub context_assertions: bool,
}

/// Internal result of the bounded, graph-only anchored-suffix analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "internal suffix receipt is staged for native code-generation policy"
)]
pub(crate) struct AnchoredSuffixStats {
    /// Number of trailing bytes every accepting path must consume.
    pub(crate) guaranteed_bytes: usize,
    /// Positions whose conservative byte set excludes at least one byte.
    pub(crate) selective_positions: usize,
    /// Deterministic derivation work charged before completion or decline.
    pub(crate) derivation_work: u64,
    /// Whether the fixed work or allocation ceiling declined the analysis.
    pub(crate) resource_limited: bool,
    /// Whether the analysis conservatively traversed context assertions.
    pub(crate) context_assertions: bool,
}

/// Internal receipt for the bounded maximum-match-width proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MaxMatchWidthStats {
    pub(crate) width: Option<usize>,
    pub(crate) derivation_work: u64,
    pub(crate) resource_limited: bool,
    pub(crate) unbounded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AnchoredByteSet {
    words: [u64; 4],
}

impl AnchoredByteSet {
    const EMPTY: Self = Self { words: [0; 4] };

    /// Construct one graph-neutral byte column from its four 64-bit words.
    #[must_use]
    #[allow(
        dead_code,
        reason = "native interior-literal lowering consumes this construction seam"
    )]
    pub(crate) const fn from_words(words: [u64; 4]) -> Self {
        Self { words }
    }

    fn insert_range(&mut self, start: u8, end: u8, work: &mut AnchoredWork) -> bool {
        for byte in start..=end {
            if !work.charge(1) {
                return false;
            }
            let index = usize::from(byte);
            self.words[index / 64] |= 1_u64 << (index % 64);
        }
        true
    }

    pub(crate) const fn words(self) -> [u64; 4] {
        self.words
    }

    pub(crate) fn contains(self, byte: u8) -> bool {
        let index = usize::from(byte);
        self.words[index / 64] & (1_u64 << (index % 64)) != 0
    }

    pub(crate) fn cardinality(self) -> u16 {
        self.words
            .iter()
            .map(|word| u16::try_from(word.count_ones()).unwrap_or(u16::MAX))
            .sum()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AnchoredPrefix {
    sets: [AnchoredByteSet; MAX_ANCHORED_PREFIX_BYTES],
    len: u8,
    derivation_work: u64,
    resource_limited: bool,
    context_assertions: bool,
}

impl AnchoredPrefix {
    const EMPTY: Self = Self {
        sets: [AnchoredByteSet::EMPTY; MAX_ANCHORED_PREFIX_BYTES],
        len: 0,
        derivation_work: 0,
        resource_limited: false,
        context_assertions: false,
    };

    #[allow(
        dead_code,
        reason = "suffix sets are exposed through NativeProgramView for the next native lowering"
    )]
    pub(crate) fn sets(&self) -> &[AnchoredByteSet] {
        &self.sets[..usize::from(self.len)]
    }

    fn stats(self) -> AnchoredPrefixStats {
        AnchoredPrefixStats {
            guaranteed_bytes: usize::from(self.len),
            selective_positions: self
                .sets()
                .iter()
                .filter(|set| set.cardinality() < 256)
                .count(),
            derivation_work: self.derivation_work,
            resource_limited: self.resource_limited,
            context_assertions: self.context_assertions,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AnchoredSuffix {
    /// `sets[0]` classifies the final consumed byte, `sets[1]` the preceding
    /// byte, and so on.
    sets: [AnchoredByteSet; MAX_ANCHORED_SUFFIX_BYTES],
    len: u8,
    derivation_work: u64,
    resource_limited: bool,
    context_assertions: bool,
}

impl AnchoredSuffix {
    const EMPTY: Self = Self {
        sets: [AnchoredByteSet::EMPTY; MAX_ANCHORED_SUFFIX_BYTES],
        len: 0,
        derivation_work: 0,
        resource_limited: false,
        context_assertions: false,
    };

    pub(crate) fn sets(&self) -> &[AnchoredByteSet] {
        &self.sets[..usize::from(self.len)]
    }

    #[allow(
        dead_code,
        reason = "internal suffix receipt is staged for native code-generation policy"
    )]
    fn stats(self) -> AnchoredSuffixStats {
        AnchoredSuffixStats {
            guaranteed_bytes: usize::from(self.len),
            selective_positions: self
                .sets()
                .iter()
                .filter(|set| set.cardinality() < 256)
                .count(),
            derivation_work: self.derivation_work,
            resource_limited: self.resource_limited,
            context_assertions: self.context_assertions,
        }
    }
}

/// Optional portable accelerator for ordered-NFA programs with a graph-proved
/// non-empty terminal suffix.
///
/// The suffix column is only a necessary filter. Every hit is verified by an
/// independently determinized reverse machine seeded from all Accept states.
/// For endpoint-sensitive contracts, reverse verification is used only to
/// discover the globally earliest viable start when maximum width is finite;
/// the ordinary ordered NFA is then replayed from that start through its
/// complete proved width. That final replay, rather than the unordered reverse
/// subset, selects alternation and greedy/lazy priority. Without an admitted
/// finite width, exhausting the suffix scanner still proves no match for every
/// output. Sparse candidates are reverse-verified within a linear work
/// envelope. `Exists` may return directly from that exact proof, while an
/// endpoint-sensitive proved match is handed back to the ordinary ordered NFA
/// so the accelerator never double-walks an unbounded match to recover
/// priority.
#[derive(Clone, Debug)]
struct NfaMandatorySuffix {
    primary_bytes: [u8; 3],
    primary_count: u8,
    primary_depth: u8,
    minimum_width: u8,
    maximum_width: Option<usize>,
    reverse: SeededReverseDfa,
}

/// Complete scanner for an exact fixed-width Cartesian byte product.
///
/// This sidecar is admitted only when a graph walk proves that every
/// consuming edge in a byte layer reaches the same next Thompson state. The
/// continuation is therefore independent of which member of that layer's
/// byte set was consumed, so the anchored columns describe the complete
/// language rather than merely necessary conditions. Scanning one selective
/// column and checking the remaining columns can then replace ordered-NFA
/// execution without losing alternation or greediness semantics.
#[derive(Clone, Copy, Debug)]
struct NfaExactProduct {
    primary_bytes: [u8; 3],
    primary_count: u8,
    primary_offset: u8,
    width: u8,
}

impl NfaExactProduct {
    fn derive(
        raw: &RawPlan,
        prefix: &AnchoredPrefix,
        exact_width: Option<usize>,
        engine: &ProgramEngine,
    ) -> Option<Self> {
        if !matches!(engine, ProgramEngine::OrderedNfa) || prefix.context_assertions {
            return None;
        }
        let width = exact_width?;
        if width == 0 || width != prefix.sets().len() || width > MAX_ANCHORED_PREFIX_BYTES {
            return None;
        }
        if !nfa_prefix_is_exact_product(raw, prefix.sets()) {
            return None;
        }

        let (primary_offset, primary) = prefix
            .sets()
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, set)| (1..=3).contains(&usize::from(set.cardinality())))
            .min_by_key(|(offset, set)| (set.cardinality(), *offset != 0, *offset))?;
        let primary_count = usize::from(primary.cardinality());
        let mut primary_bytes = [0_u8; 3];
        let mut count = 0usize;
        for byte in u8::MIN..=u8::MAX {
            if !primary.contains(byte) {
                continue;
            }
            *primary_bytes.get_mut(count)? = byte;
            count = count.checked_add(1)?;
        }
        if count != primary_count {
            return None;
        }
        Some(Self {
            primary_bytes,
            primary_count: u8::try_from(primary_count).ok()?,
            primary_offset: u8::try_from(primary_offset).ok()?,
            width: u8::try_from(width).ok()?,
        })
    }

    fn find_primary(&self, haystack: &[u8]) -> Option<usize> {
        match self.primary_count {
            1 => memchr(self.primary_bytes[0], haystack),
            2 => memchr2(self.primary_bytes[0], self.primary_bytes[1], haystack),
            3 => memchr3(
                self.primary_bytes[0],
                self.primary_bytes[1],
                self.primary_bytes[2],
                haystack,
            ),
            _ => None,
        }
    }

    #[inline(never)]
    fn search(
        &self,
        prefix: &AnchoredPrefix,
        haystack: &[u8],
        window: SearchWindow,
        output: OutputContract,
    ) -> MatchResult {
        let width = usize::from(self.width);
        let offset = usize::from(self.primary_offset);
        let no_match = || match output {
            OutputContract::Exists => MatchResult::Exists(false),
            OutputContract::SelectedEnd => MatchResult::SelectedEnd(None),
            OutputContract::Span => MatchResult::Span(None),
        };
        let Some(last_start) = window.end.checked_sub(width) else {
            return no_match();
        };
        if last_start < window.start {
            return no_match();
        }
        let Some(mut scan) = window.start.checked_add(offset) else {
            return no_match();
        };
        let Some(scan_end) = last_start
            .checked_add(offset)
            .and_then(|last| last.checked_add(1))
        else {
            return no_match();
        };

        while scan < scan_end {
            let Some(source) = haystack.get(scan..scan_end) else {
                return no_match();
            };
            let Some(relative) = self.find_primary(source) else {
                return no_match();
            };
            let Some(hit) = scan.checked_add(relative) else {
                return no_match();
            };
            let Some(start) = hit.checked_sub(offset) else {
                return no_match();
            };
            let exact = prefix
                .sets()
                .iter()
                .copied()
                .enumerate()
                .all(|(depth, set)| {
                    start
                        .checked_add(depth)
                        .and_then(|position| haystack.get(position))
                        .is_some_and(|&byte| set.contains(byte))
                });
            if exact {
                let end = start
                    .checked_add(width)
                    .expect("validated exact-product candidate width");
                return match output {
                    OutputContract::Exists => MatchResult::Exists(true),
                    OutputContract::SelectedEnd => MatchResult::SelectedEnd(Some(end)),
                    OutputContract::Span => MatchResult::Span(Some((start, end))),
                };
            }
            let Some(next) = hit.checked_add(1) else {
                return no_match();
            };
            scan = next;
        }
        no_match()
    }
}

/// Sufficient graph proof that every anchored byte column has a
/// byte-independent continuation.
///
/// The Thompson closure at each depth may contain several consuming states
/// and ranges, but all of their consuming edges must converge on one exact
/// target. Consequently every member of the unioned anchored set reaches the
/// same next closure. Repeating that proof through the exact width makes the
/// per-column Cartesian product complete. More general correlated graphs
/// simply decline this optional sidecar.
#[allow(
    clippy::too_many_lines,
    reason = "the bounded product proof keeps graph validation and convergence together"
)]
fn nfa_prefix_is_exact_product(raw: &RawPlan, sets: &[AnchoredByteSet]) -> bool {
    let states = raw.roles.len();
    let Ok(mut current) = usize::try_from(raw.start) else {
        return false;
    };
    if current >= states || raw.edge_offsets.len() != states.saturating_add(1) {
        return false;
    }
    let mut seen = Vec::new();
    if seen.try_reserve_exact(states).is_err() {
        return false;
    }
    seen.resize(states, false);
    let mut stack = Vec::new();
    let mut consuming = Vec::new();
    let Some(stack_capacity) = raw.edge_targets.len().checked_add(1) else {
        return false;
    };
    if stack.try_reserve_exact(stack_capacity).is_err()
        || consuming.try_reserve_exact(states).is_err()
    {
        return false;
    }

    for expected in sets {
        seen.fill(false);
        stack.clear();
        consuming.clear();
        stack.push(current);
        while let Some(state) = stack.pop() {
            let Some(mark) = seen.get_mut(state) else {
                return false;
            };
            if *mark {
                continue;
            }
            *mark = true;
            match raw.roles.get(state) {
                Some(StateRole::Split) => {
                    let Some(&begin) = raw.edge_offsets.get(state) else {
                        return false;
                    };
                    let Some(&end) = raw.edge_offsets.get(state.saturating_add(1)) else {
                        return false;
                    };
                    let (Ok(begin), Ok(end)) = (usize::try_from(begin), usize::try_from(end))
                    else {
                        return false;
                    };
                    if begin > end || end > raw.edge_kinds.len() {
                        return false;
                    }
                    for edge in begin..end {
                        if raw.edge_kinds.get(edge) != Some(&EdgeKind::Epsilon) {
                            return false;
                        }
                        let Some(&target) = raw.edge_targets.get(edge) else {
                            return false;
                        };
                        let Ok(target) = usize::try_from(target) else {
                            return false;
                        };
                        if target >= states {
                            return false;
                        }
                        stack.push(target);
                    }
                }
                Some(StateRole::Consume) => consuming.push(state),
                _ => return false,
            }
        }
        if consuming.is_empty() {
            return false;
        }

        let mut words = [0_u64; 4];
        let mut common_target = None;
        for &state in &consuming {
            let Some(&begin) = raw.edge_offsets.get(state) else {
                return false;
            };
            let Some(&end) = raw.edge_offsets.get(state.saturating_add(1)) else {
                return false;
            };
            let (Ok(begin), Ok(end)) = (usize::try_from(begin), usize::try_from(end)) else {
                return false;
            };
            if begin >= end || end > raw.edge_kinds.len() {
                return false;
            }
            for edge in begin..end {
                if raw.edge_kinds.get(edge) != Some(&EdgeKind::ByteRange) {
                    return false;
                }
                let (Some(&start), Some(&end), Some(&target)) = (
                    raw.byte_starts.get(edge),
                    raw.byte_ends.get(edge),
                    raw.edge_targets.get(edge),
                ) else {
                    return false;
                };
                let Ok(target) = usize::try_from(target) else {
                    return false;
                };
                if start > end || target >= states {
                    return false;
                }
                if common_target.is_some_and(|common| common != target) {
                    return false;
                }
                common_target = Some(target);
                for byte in start..=end {
                    let index = usize::from(byte);
                    words[index / 64] |= 1_u64 << (index % 64);
                }
            }
        }
        if words != expected.words() {
            return false;
        }
        let Some(target) = common_target else {
            return false;
        };
        current = target;
    }

    // Every product member reaches this same closure. At least one Accept in
    // it proves membership; the independent exact-width analysis rules out an
    // accepting continuation at any other byte depth.
    seen.fill(false);
    stack.clear();
    stack.push(current);
    while let Some(state) = stack.pop() {
        let Some(mark) = seen.get_mut(state) else {
            return false;
        };
        if *mark {
            continue;
        }
        *mark = true;
        match raw.roles.get(state) {
            Some(StateRole::Accept) => return true,
            Some(StateRole::Split) => {
                let Some(&begin) = raw.edge_offsets.get(state) else {
                    return false;
                };
                let Some(&end) = raw.edge_offsets.get(state.saturating_add(1)) else {
                    return false;
                };
                let (Ok(begin), Ok(end)) = (usize::try_from(begin), usize::try_from(end)) else {
                    return false;
                };
                if begin > end || end > raw.edge_kinds.len() {
                    return false;
                }
                for edge in begin..end {
                    if raw.edge_kinds.get(edge) != Some(&EdgeKind::Epsilon) {
                        return false;
                    }
                    let Some(&target) = raw.edge_targets.get(edge) else {
                        return false;
                    };
                    let Ok(target) = usize::try_from(target) else {
                        return false;
                    };
                    if target >= states {
                        return false;
                    }
                    stack.push(target);
                }
            }
            Some(StateRole::Consume) => {}
            Some(_) | None => return false,
        }
    }
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NfaMandatorySuffixScan {
    Candidate(usize),
    Exhausted,
    Fallback,
}

impl NfaMandatorySuffix {
    fn derive(
        raw: &RawPlan,
        prefix: &AnchoredPrefix,
        suffix: &AnchoredSuffix,
        maximum_width: Option<usize>,
    ) -> Option<Self> {
        let minimum_width = suffix.sets().len();
        if minimum_width == 0
            || maximum_width.is_some_and(|maximum_width| maximum_width < minimum_width)
        {
            return None;
        }

        let (primary_depth, primary) = suffix
            .sets()
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, set)| (1..=3).contains(&usize::from(set.cardinality())))
            .min_by_key(|(depth, set)| (set.cardinality(), *depth))?;
        let primary_count = usize::from(primary.cardinality());
        let best_forward_count = prefix
            .sets()
            .iter()
            .copied()
            .map(AnchoredByteSet::cardinality)
            .min()
            .map_or(256, usize::from);
        // The ordinary K0 executor already scans the strongest guaranteed
        // forward column. A reverse sidecar only earns its extra verification
        // and replay work when its endpoint column is strictly more selective.
        if primary_count >= best_forward_count {
            return None;
        }
        // A small finite bound admits earliest-start recovery and ordered
        // replay. Wider finite graphs still retain the scan-only/no-match
        // proof and the adaptively bounded reverse verifier; treating them
        // like an unbounded graph avoids discarding a generally useful
        // accelerator solely because bounded endpoint replay is unavailable.
        let maximum_width = maximum_width.filter(|maximum_width| {
            maximum_width
                .checked_mul(primary_count)
                .is_some_and(|work| work <= MAX_NFA_SUFFIX_CANDIDATE_WORK)
        });

        let mut primary_bytes = [0_u8; 3];
        let mut count = 0usize;
        for byte in 0..=u8::MAX {
            if primary.contains(byte) {
                *primary_bytes.get_mut(count)? = byte;
                count = count.checked_add(1)?;
            }
        }
        if count != primary_count {
            return None;
        }

        let reverse_limits = SeededReverseLimits {
            max_states: MAX_NFA_SUFFIX_REVERSE_STATES,
            max_cells: MAX_NFA_SUFFIX_REVERSE_CELLS,
            max_work: MAX_NFA_SUFFIX_REVERSE_WORK,
            max_memory_bytes: MAX_NFA_SUFFIX_REVERSE_MEMORY_BYTES,
            max_addressable_bytes: MAX_NFA_SUFFIX_REVERSE_MEMORY_BYTES,
        };
        let SeededReverseBuild::Complete(reverse) =
            build_seeded_reverse_exact(raw, SeededReverseSeed::AcceptStates, reverse_limits)
        else {
            return None;
        };
        // A non-empty anchored suffix proves every match consumes at least one
        // byte. Refuse a contradictory reverse artifact instead of allowing a
        // zero-width event to bypass the suffix filter.
        if reverse.initial_reaches_start() {
            return None;
        }

        Some(Self {
            primary_bytes,
            primary_count: u8::try_from(primary_count).ok()?,
            primary_depth: u8::try_from(primary_depth).ok()?,
            minimum_width: u8::try_from(minimum_width).ok()?,
            maximum_width,
            reverse,
        })
    }

    fn find_primary(&self, haystack: &[u8]) -> Option<usize> {
        match self.primary_count {
            1 => memchr(self.primary_bytes[0], haystack),
            2 => memchr2(self.primary_bytes[0], self.primary_bytes[1], haystack),
            3 => memchr3(
                self.primary_bytes[0],
                self.primary_bytes[1],
                self.primary_bytes[2],
                haystack,
            ),
            _ => None,
        }
    }

    fn primary_hits_are_dense(
        &self,
        window_start: usize,
        endpoint: usize,
        primary_hits: usize,
    ) -> bool {
        let scanned = endpoint.saturating_sub(window_start);
        let proportional = scanned.saturating_mul(usize::from(self.primary_count))
            / NFA_SUFFIX_PRIMARY_HIT_DENOMINATOR;
        primary_hits > NFA_SUFFIX_PRIMARY_HIT_CREDIT.saturating_add(proportional)
    }

    /// Admit another scan-only reverse verification while cumulative charged
    /// work remains linear in the portion of the window reached so far.
    fn next_scan_only_reverse_work(
        reverse_work: usize,
        window_start: usize,
        endpoint: usize,
    ) -> Option<usize> {
        let candidate_work = endpoint.checked_sub(window_start)?;
        let next_reverse_work = reverse_work.checked_add(candidate_work)?;
        let permitted_work = candidate_work
            .saturating_mul(NFA_SUFFIX_SCAN_ONLY_REVERSE_WORK_MULTIPLIER)
            .saturating_add(NFA_SUFFIX_SCAN_ONLY_REVERSE_WORK_CREDIT);
        (next_reverse_work <= permitted_work).then_some(next_reverse_work)
    }

    /// Return the next endpoint whose complete graph-proved suffix columns
    /// match. `maximum_endpoint` is inclusive and never exceeds the semantic
    /// search window end.
    fn next_candidate_endpoint(
        &self,
        suffix: &AnchoredSuffix,
        haystack: &[u8],
        window_start: usize,
        maximum_endpoint: usize,
        from_endpoint: usize,
        primary_hits: &mut usize,
    ) -> NfaMandatorySuffixScan {
        let Some(minimum_endpoint) = window_start.checked_add(usize::from(self.minimum_width))
        else {
            return NfaMandatorySuffixScan::Fallback;
        };
        let endpoint = from_endpoint.max(minimum_endpoint);
        if endpoint > maximum_endpoint {
            return NfaMandatorySuffixScan::Exhausted;
        }
        let depth = usize::from(self.primary_depth);
        let Some(primary_offset) = depth.checked_add(1) else {
            return NfaMandatorySuffixScan::Fallback;
        };
        let Some(mut scan) = endpoint.checked_sub(primary_offset) else {
            return NfaMandatorySuffixScan::Fallback;
        };
        let Some(scan_limit) = maximum_endpoint.checked_sub(depth) else {
            return NfaMandatorySuffixScan::Fallback;
        };

        while scan < scan_limit {
            let Some(bytes) = haystack.get(scan..scan_limit) else {
                return NfaMandatorySuffixScan::Fallback;
            };
            let Some(relative) = self.find_primary(bytes) else {
                return NfaMandatorySuffixScan::Exhausted;
            };
            let Some(hit) = scan.checked_add(relative) else {
                return NfaMandatorySuffixScan::Fallback;
            };
            let Some(candidate) = hit
                .checked_add(depth)
                .and_then(|endpoint| endpoint.checked_add(1))
            else {
                return NfaMandatorySuffixScan::Fallback;
            };
            let Some(next_primary_hits) = primary_hits.checked_add(1) else {
                return NfaMandatorySuffixScan::Fallback;
            };
            *primary_hits = next_primary_hits;
            let aligned = suffix
                .sets()
                .iter()
                .copied()
                .enumerate()
                .all(|(depth, set)| {
                    candidate
                        .checked_sub(depth.saturating_add(1))
                        .filter(|&position| position >= window_start)
                        .and_then(|position| haystack.get(position))
                        .is_some_and(|&byte| set.contains(byte))
                });
            if aligned {
                return NfaMandatorySuffixScan::Candidate(candidate);
            }
            if self.primary_hits_are_dense(window_start, candidate, *primary_hits) {
                return NfaMandatorySuffixScan::Fallback;
            }
            let Some(next_scan) = hit.checked_add(1) else {
                return NfaMandatorySuffixScan::Fallback;
            };
            scan = next_scan;
        }
        NfaMandatorySuffixScan::Exhausted
    }
}

/// Optional whole-window rejection filter proved by one mandatory consuming
/// dominator in the productive Thompson graph.
///
/// Every Start-to-Accept graph path visits `root_state`. Its productive
/// outgoing byte ranges therefore form a necessary set for every match. The
/// retained required-literal layer is correlated and complete, so taking the
/// first byte of every alternative reconstructs that necessary set even when
/// later paths branch or cycle. Absence of every set member from a semantic
/// search window is a complete no-match proof for every output contract. A
/// hit proves nothing and immediately hands the original window to K0.
#[derive(Clone, Debug)]
struct NfaMandatoryCut {
    root_state: u32,
    cardinality: u16,
    scanner: NfaMandatoryCutScanner,
}

#[derive(Clone, Debug)]
enum NfaMandatoryCutScanner {
    Small {
        bytes: [u8; 3],
        count: u8,
    },
    Ascii {
        set: AsciiByteSet,
        classifier: AsciiByteSetClassifier,
    },
    Full {
        set: ByteSet256,
        classifier: ByteSetClassifier,
    },
}

impl NfaMandatoryCut {
    const fn from_exact_product(product: NfaExactProduct) -> Self {
        Self {
            root_state: NFA_EXACT_PRODUCT_ROOT_SENTINEL,
            cardinality: u16::from_le_bytes([product.width, product.primary_offset]),
            scanner: NfaMandatoryCutScanner::Small {
                bytes: product.primary_bytes,
                count: product.primary_count,
            },
        }
    }

    const fn exact_product(&self) -> Option<NfaExactProduct> {
        if self.root_state != NFA_EXACT_PRODUCT_ROOT_SENTINEL {
            return None;
        }
        let [width, primary_offset] = self.cardinality.to_le_bytes();
        let NfaMandatoryCutScanner::Small { bytes, count } = &self.scanner else {
            return None;
        };
        if width == 0 || primary_offset >= width || *count == 0 || *count > 3 {
            return None;
        }
        Some(NfaExactProduct {
            primary_bytes: *bytes,
            primary_count: *count,
            primary_offset,
            width,
        })
    }

    fn from_candidate(candidate: &required_literals::RequiredInteriorCandidate) -> Option<Self> {
        if candidate.depth() == 0 || candidate.literals().is_empty() {
            return None;
        }
        let mut words = [0_u64; 4];
        for literal in candidate.literals() {
            let &byte = literal.as_bytes().first()?;
            let index = usize::from(byte);
            words[index / 64] |= 1_u64 << (index % 64);
        }
        let cardinality = words.iter().try_fold(0_u16, |total, word| {
            total.checked_add(u16::try_from(word.count_ones()).ok()?)
        })?;
        if cardinality == 0 || cardinality > MAX_NFA_MANDATORY_CUT_CARDINALITY {
            return None;
        }

        let scanner = if cardinality <= 3 {
            let mut bytes = [0_u8; 3];
            let mut count = 0usize;
            for byte in 0_u16..=u16::from(u8::MAX) {
                let byte = u8::try_from(byte).ok()?;
                let index = usize::from(byte);
                if words[index / 64] & (1_u64 << (index % 64)) == 0 {
                    continue;
                }
                *bytes.get_mut(count)? = byte;
                count = count.checked_add(1)?;
            }
            if count != usize::from(cardinality) {
                return None;
            }
            NfaMandatoryCutScanner::Small {
                bytes,
                count: u8::try_from(count).ok()?,
            }
        } else if words[2] == 0 && words[3] == 0 {
            let set = AsciiByteSet::from_words([words[0], words[1]]);
            NfaMandatoryCutScanner::Ascii {
                set,
                classifier: AsciiByteSetClassifier::new(set),
            }
        } else {
            let set = ByteSet256::from_words(words);
            NfaMandatoryCutScanner::Full {
                set,
                classifier: ByteSetClassifier::new(set),
            }
        };
        let root_state = candidate.root_state();
        if root_state == NFA_EXACT_PRODUCT_ROOT_SENTINEL {
            return None;
        }
        Some(Self {
            root_state,
            cardinality,
            scanner,
        })
    }

    /// Stable target-neutral cost order. Smaller necessary sets dominate;
    /// equal-cardinality sets prefer the lower-overhead scanner, then the
    /// canonical state number and bitmap. No observed haystack or pattern
    /// identity participates in this choice.
    fn cost_key(&self) -> (u16, u8, u32, [u64; 4]) {
        let (tier, words) = match &self.scanner {
            NfaMandatoryCutScanner::Small { bytes, count } => {
                let mut words = [0_u64; 4];
                for &byte in &bytes[..usize::from(*count)] {
                    let index = usize::from(byte);
                    words[index / 64] |= 1_u64 << (index % 64);
                }
                (0, words)
            }
            NfaMandatoryCutScanner::Ascii { set, .. } => {
                let ascii = set.words();
                (1, [ascii[0], ascii[1], 0, 0])
            }
            NfaMandatoryCutScanner::Full { set, .. } => (2, set.words()),
        };
        (self.cardinality, tier, self.root_state, words)
    }

    fn has_member(&self, haystack: &[u8]) -> bool {
        match &self.scanner {
            NfaMandatoryCutScanner::Small { bytes, count: 1 } => {
                memchr(bytes[0], haystack).is_some()
            }
            NfaMandatoryCutScanner::Small { bytes, count: 2 } => {
                memchr2(bytes[0], bytes[1], haystack).is_some()
            }
            NfaMandatoryCutScanner::Small { bytes, count: 3 } => {
                memchr3(bytes[0], bytes[1], bytes[2], haystack).is_some()
            }
            // A malformed internal count must fail open to the ordered NFA.
            NfaMandatoryCutScanner::Small { .. } => true,
            NfaMandatoryCutScanner::Ascii { set, classifier } => {
                scan_ascii_cut(*set, classifier, haystack)
            }
            NfaMandatoryCutScanner::Full { set, classifier } => {
                scan_full_cut(*set, classifier, haystack)
            }
        }
    }
}

fn scan_ascii_cut(set: AsciiByteSet, classifier: &AsciiByteSetClassifier, haystack: &[u8]) -> bool {
    let prefix_end = haystack.len().min(NFA_MANDATORY_CUT_SCALAR_PREFIX_BYTES);
    if haystack[..prefix_end]
        .iter()
        .copied()
        .any(|byte| set.contains(byte))
    {
        return true;
    }
    let mut position = prefix_end;
    while haystack.len().saturating_sub(position) >= ASCII_WIDE_BYTES {
        let end = position
            .checked_add(ASCII_WIDE_BYTES)
            .expect("remaining source proves the wide ASCII cut extent");
        let block: &[u8; ASCII_WIDE_BYTES] = haystack[position..end]
            .try_into()
            .expect("checked ASCII cut block width");
        if classifier.classify_32(block).member_mask() != 0 {
            return true;
        }
        position = end;
    }
    if haystack.len().saturating_sub(position) >= ASCII_NARROW_BYTES {
        let end = position
            .checked_add(ASCII_NARROW_BYTES)
            .expect("remaining source proves the narrow ASCII cut extent");
        let block: &[u8; ASCII_NARROW_BYTES] = haystack[position..end]
            .try_into()
            .expect("checked narrow ASCII cut block width");
        if classifier.classify_16(block).member_mask() != 0 {
            return true;
        }
        position = end;
    }
    haystack[position..]
        .iter()
        .copied()
        .any(|byte| set.contains(byte))
}

fn scan_full_cut(set: ByteSet256, classifier: &ByteSetClassifier, haystack: &[u8]) -> bool {
    let prefix_end = haystack.len().min(NFA_MANDATORY_CUT_SCALAR_PREFIX_BYTES);
    if haystack[..prefix_end]
        .iter()
        .copied()
        .any(|byte| set.contains(byte))
    {
        return true;
    }
    let mut position = prefix_end;
    while haystack.len().saturating_sub(position) >= BYTE_SET_WIDE_BLOCK_BYTES {
        let end = position
            .checked_add(BYTE_SET_WIDE_BLOCK_BYTES)
            .expect("remaining source proves the wide full-byte cut extent");
        let block: &[u8; BYTE_SET_WIDE_BLOCK_BYTES] = haystack[position..end]
            .try_into()
            .expect("checked full-byte cut block width");
        if classifier.classify_32(block).member_mask() != 0 {
            return true;
        }
        position = end;
    }
    if haystack.len().saturating_sub(position) >= BYTE_SET_BLOCK_BYTES {
        let end = position
            .checked_add(BYTE_SET_BLOCK_BYTES)
            .expect("remaining source proves the narrow full-byte cut extent");
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = haystack[position..end]
            .try_into()
            .expect("checked narrow full-byte cut block width");
        if classifier.classify_16(block).member_mask() != 0 {
            return true;
        }
        position = end;
    }
    haystack[position..]
        .iter()
        .copied()
        .any(|byte| set.contains(byte))
}

#[derive(Clone, Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "keeping the graph inline avoids an infallible allocation while constructing a program"
)]
enum ProgramEngine {
    OrderedNfa,
    OrderedNfaWithPartial(Box<PartialDfa>),
    OrderedDfa(OrderedDfa),
}

impl ProgramEngine {
    const fn is_ordered_nfa(&self) -> bool {
        matches!(self, Self::OrderedNfa | Self::OrderedNfaWithPartial(_))
    }

    const fn partial_dfa(&self) -> Option<&PartialDfa> {
        match self {
            Self::OrderedNfaWithPartial(partial) => Some(partial),
            Self::OrderedNfa | Self::OrderedDfa(_) => None,
        }
    }
}

fn derive_nfa_suffix(
    raw: &RawPlan,
    prefix: &AnchoredPrefix,
    suffix: &AnchoredSuffix,
    maximum_width: MaxMatchWidthStats,
    engine: &ProgramEngine,
    enabled: bool,
) -> Option<NfaMandatorySuffix> {
    if !enabled
        || !engine.is_ordered_nfa()
        || raw
            .edge_kinds
            .iter()
            .any(|kind| !matches!(kind, EdgeKind::Epsilon | EdgeKind::ByteRange))
    {
        return None;
    }
    NfaMandatorySuffix::derive(raw, prefix, suffix, maximum_width.width)
}

fn derive_nfa_mandatory_cut(
    prefix: &AnchoredPrefix,
    required_literals: &RequiredLiterals,
    engine: &ProgramEngine,
    mandatory_suffix_present: bool,
    enabled: bool,
) -> Option<NfaMandatoryCut> {
    if !enabled || mandatory_suffix_present || !engine.is_ordered_nfa() {
        return None;
    }

    // K0 already scans its strongest graph-proved forward column. The
    // whole-window cut is admitted only when it is strictly more selective,
    // so positive/dense sources do not pay for a redundant pre-pass. A
    // mandatory suffix is an effective existing reverse filter and excludes
    // this sidecar above; an unmaterialized suffix is not treated as free.
    let best_forward_cardinality = prefix
        .sets()
        .iter()
        .copied()
        .map(AnchoredByteSet::cardinality)
        .min()
        .unwrap_or(256);

    required_literals
        .interior()
        .candidates()
        .iter()
        .filter_map(NfaMandatoryCut::from_candidate)
        .filter(|candidate| {
            candidate
                .cardinality
                .saturating_mul(NFA_MANDATORY_CUT_MIN_SELECTIVITY_GAIN)
                <= best_forward_cardinality
        })
        .min_by_key(NfaMandatoryCut::cost_key)
}

/// General capture-free AOT semantic program.
///
/// The validated automaton is deliberately retained for every route. In fast
/// mode and when complete determinization is declined, it is the executable
/// universal representation. In optimizing mode, no source-pattern identity
/// participates in selecting the DFA.
#[derive(Clone, Debug)]
pub struct CompiledProgram {
    raw: RawPlan,
    automaton: Automaton,
    identity: [u8; 32],
    line_terminator: u8,
    output: OutputContract,
    engine: ProgramEngine,
    engine_selection_reason: Option<EngineSelectionReason>,
    determinization_report: Option<DeterminizationReport>,
    /// Optional in-memory assertion optimizer. Stable serialization keeps
    /// the universal ordered-NFA engine and deliberately omits this sidecar.
    context_dfa: Option<ContextDfa>,
    /// Fresh contextual construction provenance. This is omitted from the
    /// stable wire format together with `context_dfa`.
    context_determinization_report: Option<ContextDeterminizationReport>,
    anchored_prefix: AnchoredPrefix,
    anchored_suffix: AnchoredSuffix,
    required_literals: RequiredLiterals,
    exact_match_width: Option<usize>,
    max_match_width: MaxMatchWidthStats,
    nfa_mandatory_suffix: Option<NfaMandatorySuffix>,
    nfa_mandatory_cut: Option<NfaMandatoryCut>,
}

/// Reusable, allocation-free execution storage for one semantic program.
///
/// Construct this with [`CompiledProgram::prepare_workspace`] and pass it to
/// [`CompiledProgram::search_with_workspace`]. A semantic identity check
/// prevents accidentally pairing storage with another program.
#[derive(Debug)]
pub struct ProgramWorkspace {
    identity: [u8; 32],
    nfa: Option<K0Workspace>,
    partial: Option<Box<PartialDfaWorkspace>>,
}

/// Scratch used only by an ordered-NFA program with retained subset rows.
/// Keeping the route in one optional owner leaves ordinary NFA workspaces
/// unchanged apart from one cold pointer-sized niche.
#[derive(Debug)]
struct PartialDfaWorkspace {
    resume: Option<K0ResumeSet>,
    state: PartialDfaRuntimeState,
}

/// Per-prepared-workspace admission state for a retained partial table.
///
/// Missing forward rows normally resume K0 directly and count as complete
/// partial executions. The fallback guard remains for holes more cheaply
/// decided by another complete accelerator, a foreign compatible workspace,
/// and variable-width positive spans that still need ordinary start recovery.
#[derive(Clone, Copy, Debug, Default)]
struct PartialDfaRuntimeState {
    consecutive_fallbacks: u8,
    bypass_remaining: u16,
    prefix_plan: Option<PartialDfaPrefixPlan>,
    prefix_supported: bool,
    #[cfg(test)]
    resumed: usize,
}

impl PartialDfaRuntimeState {
    fn new(prefix: &[AnchoredByteSet]) -> Self {
        let (prefix_plan, prefix_supported) = PartialDfaPrefixPlan::derive(prefix);
        Self {
            prefix_plan,
            prefix_supported,
            ..Self::default()
        }
    }

    fn admit(&mut self) -> bool {
        if !self.prefix_supported {
            false
        } else if self.bypass_remaining == 0 {
            true
        } else {
            self.bypass_remaining = self.bypass_remaining.saturating_sub(1);
            false
        }
    }

    fn observe_complete(&mut self) {
        self.consecutive_fallbacks = 0;
        self.bypass_remaining = 0;
    }

    fn observe_resume(&mut self) {
        #[cfg(test)]
        {
            self.resumed = self.resumed.saturating_add(1);
        }
        self.observe_complete();
    }

    fn observe_fallback(&mut self, consumed: usize, input_bytes: usize) {
        self.consecutive_fallbacks = self.consecutive_fallbacks.saturating_add(1);
        if self.consecutive_fallbacks < 2 {
            return;
        }
        let early = consumed <= 16 || consumed <= input_bytes / 8;
        let base_shift = if early { 4_u32 } else { 0_u32 };
        let maximum_shift = if early { 10_u32 } else { 3_u32 };
        let fallback_exponent = u32::from(self.consecutive_fallbacks.saturating_sub(2));
        let shift = base_shift
            .saturating_add(fallback_exponent)
            .min(maximum_shift);
        self.bypass_remaining = 1_u16 << shift;
    }
}

#[allow(dead_code, reason = "structural handoff for native code generation")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeProgramView<'a> {
    pub(crate) output: OutputContract,
    /// Validated Thompson graph retained for bounded graph-only native
    /// analyses whose facts are deliberately not part of the stable wire
    /// format.
    pub(crate) raw: &'a RawPlan,
    pub(crate) dfa: NativeDfaView<'a>,
    pub(crate) anchored_prefix: &'a AnchoredPrefix,
    pub(crate) anchored_suffix: &'a AnchoredSuffix,
    pub(crate) required_literals: &'a RequiredLiterals,
    pub(crate) exact_match_width: Option<usize>,
    pub(crate) max_match_width: Option<usize>,
}

#[allow(
    dead_code,
    reason = "structural handoff for contextual native lowering"
)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeContextProgramView<'a> {
    pub(crate) output: OutputContract,
    pub(crate) dfa: NativeContextDfaView<'a>,
    pub(crate) anchored_prefix: &'a AnchoredPrefix,
    pub(crate) anchored_suffix: &'a AnchoredSuffix,
    pub(crate) required_literals: &'a RequiredLiterals,
    pub(crate) exact_match_width: Option<usize>,
    pub(crate) max_match_width: Option<usize>,
}

const fn contextual_limits(requested: DeterminizeLimits) -> ContextDfaLimits {
    let effective = requested.effective_for_stable_artifact();
    ContextDfaLimits {
        max_states: effective.max_states,
        max_transitions: effective.max_transitions,
        max_work: effective.max_work,
    }
}

impl CompiledProgram {
    #[allow(
        clippy::too_many_lines,
        reason = "engine selection and optional graph-sidecar publication are transactional"
    )]
    pub(crate) fn build(
        raw: RawPlan,
        automaton: Automaton,
        output: OutputContract,
        mode: CompileMode,
        limits: DeterminizeLimits,
    ) -> Result<Self, CompileError> {
        let line_terminator = automaton.line_terminator();
        let exact_match_width = derive_exact_match_width(&raw);
        let needs_reverse_span = output == OutputContract::Span && exact_match_width.is_none();
        let contains_context_assertions = raw
            .edge_kinds
            .iter()
            .any(|kind| !matches!(kind, EdgeKind::Epsilon | EdgeKind::ByteRange));
        let (
            engine,
            engine_selection_reason,
            determinization_report,
            context_dfa,
            context_determinization_report,
            partial_dfa,
        ) = match mode {
            CompileMode::Fast => (
                ProgramEngine::OrderedNfa,
                EngineSelectionReason::FastMode,
                DeterminizationReport::not_attempted(limits),
                None,
                None,
                None,
            ),
            CompileMode::Optimizing if contains_context_assertions => {
                let (contextual, reason, contextual_report) = match context_dfa::determinize(
                    &raw,
                    line_terminator,
                    contextual_limits(limits),
                )? {
                    ContextDfaOutcome::Complete(machine) => {
                        let report =
                            ContextDeterminizationReport::complete(limits, machine.stats());
                        (
                            Some(machine),
                            EngineSelectionReason::CompleteContextDfa,
                            report,
                        )
                    }
                    ContextDfaOutcome::Declined(decline) => (
                        None,
                        EngineSelectionReason::ContextAssertions,
                        ContextDeterminizationReport::declined(limits, decline),
                    ),
                };
                (
                    ProgramEngine::OrderedNfa,
                    reason,
                    DeterminizationReport::not_attempted(limits),
                    contextual,
                    Some(contextual_report),
                    None,
                )
            }
            CompileMode::Optimizing => match dfa::determinize(&raw, needs_reverse_span, limits)? {
                DeterminizeOutcome::Complete { machine, report } => (
                    ProgramEngine::OrderedDfa(machine),
                    EngineSelectionReason::CompleteDfa,
                    report,
                    None,
                    None,
                    None,
                ),
                DeterminizeOutcome::Declined { report, partial } => (
                    ProgramEngine::OrderedNfa,
                    EngineSelectionReason::DeterminizationResourceLimit,
                    report,
                    None,
                    None,
                    partial,
                ),
            },
        };
        let identity = automaton_digest(&raw, line_terminator);
        let anchored_prefix = derive_anchored_prefix(&raw);
        let anchored_suffix = derive_anchored_suffix(&raw);
        let required_literals = if mode == CompileMode::Optimizing {
            required_literals::derive(&raw)
        } else {
            RequiredLiterals::unavailable()
        };
        let max_match_width = derive_max_match_width(&raw);
        let nfa_exact_product = (mode == CompileMode::Optimizing)
            .then(|| NfaExactProduct::derive(&raw, &anchored_prefix, exact_match_width, &engine))
            .flatten();
        let nfa_mandatory_suffix = (nfa_exact_product.is_none())
            .then(|| {
                derive_nfa_suffix(
                    &raw,
                    &anchored_prefix,
                    &anchored_suffix,
                    max_match_width,
                    &engine,
                    mode == CompileMode::Optimizing,
                )
            })
            .flatten();
        let nfa_mandatory_cut = nfa_exact_product
            .map(NfaMandatoryCut::from_exact_product)
            .or_else(|| {
                derive_nfa_mandatory_cut(
                    &anchored_prefix,
                    &required_literals,
                    &engine,
                    nfa_mandatory_suffix.is_some(),
                    mode == CompileMode::Optimizing && context_dfa.is_none(),
                )
            });
        let engine = match (engine, partial_dfa.filter(|_| nfa_exact_product.is_none())) {
            (ProgramEngine::OrderedNfa, Some(partial)) => {
                ProgramEngine::OrderedNfaWithPartial(Box::new(partial))
            }
            (engine, None) => engine,
            (ProgramEngine::OrderedNfaWithPartial(_), Some(_))
            | (ProgramEngine::OrderedDfa(_), Some(_)) => {
                return Err(CompileError::InternalInvariant(
                    "partial DFA was paired with a non-fallback engine",
                ));
            }
        };
        Ok(Self {
            raw,
            automaton,
            identity,
            line_terminator,
            output,
            engine,
            engine_selection_reason: Some(engine_selection_reason),
            determinization_report: Some(determinization_report),
            context_dfa,
            context_determinization_report,
            anchored_prefix,
            anchored_suffix,
            required_literals,
            exact_match_width,
            max_match_width,
            nfa_mandatory_suffix,
            nfa_mandatory_cut,
        })
    }

    #[must_use]
    pub const fn output_contract(&self) -> OutputContract {
        self.output
    }

    /// Byte recognized by configured multiline assertions and dot semantics.
    #[must_use]
    pub const fn line_terminator(&self) -> u8 {
        self.line_terminator
    }

    #[must_use]
    pub const fn engine_kind(&self) -> EngineKind {
        if self.context_dfa.is_some() {
            return EngineKind::OrderedContextDfa;
        }
        match self.engine {
            ProgramEngine::OrderedNfa | ProgramEngine::OrderedNfaWithPartial(_) => {
                EngineKind::OrderedNfa
            }
            ProgramEngine::OrderedDfa(_) => EngineKind::OrderedDfa,
        }
    }

    const fn program_flags(&self) -> u8 {
        let mut flags = 0;
        if self.nfa_mandatory_suffix.is_some() {
            flags |= PROGRAM_FLAG_NFA_MANDATORY_SUFFIX;
        }
        if let Some(sidecar) = &self.nfa_mandatory_cut {
            if sidecar.exact_product().is_some() {
                flags |= PROGRAM_FLAG_NFA_EXACT_PRODUCT;
            } else {
                flags |= PROGRAM_FLAG_NFA_MANDATORY_CUT;
            }
        }
        if matches!(self.engine, ProgramEngine::OrderedNfaWithPartial(_)) {
            flags |= PROGRAM_FLAG_NFA_PARTIAL_DFA;
        }
        flags
    }

    /// Return the structural reason for the selected engine when provenance is
    /// available.
    ///
    /// Compilation always retains this value. The stable program wire format
    /// predates selection receipts and does not encode the requested mode, so
    /// a deserialized ordered-NFA program returns `None`. A serialized DFA is
    /// unambiguously the result of complete determinization.
    #[must_use]
    pub const fn engine_selection_reason(&self) -> Option<EngineSelectionReason> {
        self.engine_selection_reason
    }

    #[must_use]
    pub const fn dfa_stats(&self) -> Option<DfaStats> {
        match &self.engine {
            ProgramEngine::OrderedNfa | ProgramEngine::OrderedNfaWithPartial(_) => None,
            ProgramEngine::OrderedDfa(machine) => Some(machine.stats()),
        }
    }

    fn partial_dfa(&self) -> Option<&PartialDfa> {
        self.engine.partial_dfa()
    }

    /// Return dimensions of the optional in-memory contextual optimizer.
    ///
    /// Stable serialized programs intentionally return `None`: their wire
    /// payload remains the universal ordered-NFA representation.
    #[must_use]
    pub const fn context_dfa_stats(&self) -> Option<ContextDfaStats> {
        match &self.context_dfa {
            Some(machine) => Some(machine.stats()),
            None => None,
        }
    }

    /// Return fresh contextual-determinization provenance, when contextual
    /// construction was attempted.
    ///
    /// The report records either complete machine dimensions or the exact
    /// unsupported assertion/resource decline. It is not serialized, so a
    /// reconstructed stable program returns `None`.
    #[must_use]
    pub const fn context_determinization_report(&self) -> Option<&ContextDeterminizationReport> {
        self.context_determinization_report.as_ref()
    }

    #[allow(
        dead_code,
        reason = "standalone contextual view is retained for structural validation"
    )]
    pub(crate) fn native_context_dfa_view(&self) -> Option<NativeContextDfaView<'_>> {
        self.context_dfa.as_ref().map(ContextDfa::native_view)
    }

    #[allow(
        dead_code,
        reason = "structural handoff for contextual native lowering"
    )]
    pub(crate) fn native_context_program_view(&self) -> Option<NativeContextProgramView<'_>> {
        self.context_dfa
            .as_ref()
            .map(|machine| NativeContextProgramView {
                output: self.output,
                dfa: machine.native_view(),
                anchored_prefix: &self.anchored_prefix,
                anchored_suffix: &self.anchored_suffix,
                required_literals: &self.required_literals,
                exact_match_width: self.exact_match_width,
                max_match_width: self.max_match_width(),
            })
    }

    /// Return the exact compile-time determinization route, when provenance is
    /// retained by this value.
    ///
    /// Stable serialized programs intentionally do not encode caller limits,
    /// so deserialized programs return `None`.
    #[must_use]
    pub const fn determinization_report(&self) -> Option<&DeterminizationReport> {
        self.determinization_report.as_ref()
    }

    /// Return the bounded graph-derived fixed-prefix facts.
    ///
    /// The analysis uses only the validated Thompson graph. It does not inspect
    /// source spelling, hashes, benchmark identities, or target identity.
    #[must_use]
    pub fn anchored_prefix_stats(&self) -> AnchoredPrefixStats {
        self.anchored_prefix.stats()
    }

    /// Return graph-derived trailing-byte facts for native code generation.
    #[must_use]
    #[allow(
        dead_code,
        reason = "internal suffix receipt is staged for native code-generation policy"
    )]
    pub(crate) fn anchored_suffix_stats(&self) -> AnchoredSuffixStats {
        self.anchored_suffix.stats()
    }

    /// Return the consumed byte width shared by every accepting graph path.
    ///
    /// This proof is derived from the validated automaton alone. `None` means
    /// only that the bounded analysis did not prove one width; it does not
    /// change compiler eligibility or matching semantics.
    #[must_use]
    pub const fn exact_match_width(&self) -> Option<usize> {
        self.exact_match_width
    }

    /// Return a proven maximum consumed byte width for bounded graphs.
    ///
    /// `None` conservatively covers both structurally unbounded graphs and a
    /// bounded optional analysis decline.
    #[must_use]
    pub const fn max_match_width(&self) -> Option<usize> {
        self.max_match_width.width
    }

    #[must_use]
    #[allow(
        dead_code,
        reason = "internal width receipt is staged for native code-generation policy"
    )]
    pub(crate) const fn max_match_width_stats(&self) -> MaxMatchWidthStats {
        self.max_match_width
    }

    /// Program dimensions, including the exact stable serialized size.
    ///
    /// # Errors
    ///
    /// Returns an invariant error only if a serialized length cannot be
    /// represented by the host `usize`.
    pub fn stats(&self) -> Result<ProgramStats, CompileError> {
        let graph = self.automaton.stats();
        Ok(ProgramStats {
            engine: self.engine_kind(),
            engine_selection_reason: self.engine_selection_reason(),
            thompson_states: graph.states(),
            thompson_edges: graph.edges(),
            serialized_bytes: self.serialized_len()?,
            dfa: self.dfa_stats(),
            context_determinization: self.context_determinization_report.clone(),
            determinization: self.determinization_report.clone(),
            anchored_prefix: self.anchored_prefix_stats(),
            max_match_width: self.max_match_width(),
        })
    }

    #[allow(dead_code, reason = "structural handoff for native code generation")]
    pub(crate) fn native_dfa_view(&self) -> Option<NativeProgramView<'_>> {
        match &self.engine {
            ProgramEngine::OrderedNfa | ProgramEngine::OrderedNfaWithPartial(_) => None,
            ProgramEngine::OrderedDfa(machine) => Some(NativeProgramView {
                output: self.output,
                raw: &self.raw,
                dfa: machine.native_view(),
                anchored_prefix: &self.anchored_prefix,
                anchored_suffix: &self.anchored_suffix,
                required_literals: &self.required_literals,
                exact_match_width: self.exact_match_width,
                max_match_width: self.max_match_width(),
            }),
        }
    }

    /// Execute the complete target-neutral semantic program.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid-window error before reading the haystack, or a
    /// portable executor error if the universal NFA cannot prepare its
    /// unlimited workspace.
    pub fn search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<MatchResult, CompileError> {
        if window.start > window.end || window.end > haystack.len() {
            return Err(CompileError::InvalidWindow {
                start: window.start,
                end: window.end,
                haystack_len: haystack.len(),
            });
        }
        let mut workspace = self.prepare_workspace()?;
        self.search_with_workspace(haystack, window, &mut workspace)
    }

    /// Allocate and initialize reusable storage for this exact program.
    ///
    /// Ordered-DFA programs require no scratch allocation. Ordered-NFA
    /// programs retain a fully initialized fixed-capacity K0 workspace unless
    /// a complete graph-proved sidecar makes the ordered executor unreachable.
    /// The workspace includes the bounded endpoint cache for existence/end
    /// contracts and bidirectional start recovery for spans, so repeated calls
    /// can reuse learned rows without allocating.
    ///
    /// # Errors
    ///
    /// Returns a portable executor error if the NFA workspace cannot be
    /// prepared.
    pub fn prepare_workspace(&self) -> Result<ProgramWorkspace, CompileError> {
        let exact_product = self
            .nfa_mandatory_cut
            .as_ref()
            .and_then(NfaMandatoryCut::exact_product)
            .is_some();
        let nfa = if self.engine.is_ordered_nfa() && !exact_product {
            Some(match self.output {
                OutputContract::Exists | OutputContract::SelectedEnd => {
                    K0Workspace::new_accelerated(&self.automaton, WorkspaceLimits::unlimited())?
                }
                OutputContract::Span if self.exact_match_width.is_some() => {
                    K0Workspace::new_accelerated(&self.automaton, WorkspaceLimits::unlimited())?
                }
                OutputContract::Span => {
                    K0Workspace::new_bidirectional(&self.automaton, WorkspaceLimits::unlimited())?
                }
            })
        } else {
            None
        };
        let partial = self
            .partial_dfa()
            .map(|partial| {
                let resume = (partial.resume_frontier_count() != 0)
                    .then(|| {
                        K0ResumeSet::new(
                            &self.automaton,
                            partial.resume_frontier_count(),
                            partial.resume_item_count()?,
                            partial.resume_frontiers(),
                        )
                        .map_err(CompileError::from)
                    })
                    .transpose()?;
                Ok::<_, CompileError>(Box::new(PartialDfaWorkspace {
                    resume,
                    state: PartialDfaRuntimeState::new(self.anchored_prefix.sets()),
                }))
            })
            .transpose()?;
        Ok(ProgramWorkspace {
            identity: self.identity,
            nfa,
            partial,
        })
    }

    /// Execute with caller-owned storage prepared for this semantic program.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid-window error before reading the haystack, a
    /// portable executor error, or an invariant error if `workspace` belongs
    /// to a different program.
    pub fn search_with_workspace(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut ProgramWorkspace,
    ) -> Result<MatchResult, CompileError> {
        if window.start > window.end || window.end > haystack.len() {
            return Err(CompileError::InvalidWindow {
                start: window.start,
                end: window.end,
                haystack_len: haystack.len(),
            });
        }
        if workspace.identity != self.identity {
            return Err(CompileError::InternalInvariant(
                "program workspace belongs to a different semantic program",
            ));
        }
        if let Some(machine) = &self.context_dfa {
            return machine.search(haystack, window, self.output);
        }
        match &self.engine {
            ProgramEngine::OrderedNfa => {
                if let Some(nfa) = workspace.nfa.as_mut() {
                    return self.search_nfa(haystack, window, nfa);
                }
                let product = self
                    .nfa_mandatory_cut
                    .as_ref()
                    .and_then(NfaMandatoryCut::exact_product)
                    .ok_or(CompileError::InternalInvariant(
                        "ordered-NFA program workspace has no executable storage",
                    ))?;
                Ok(product.search(&self.anchored_prefix, haystack, window, self.output))
            }
            ProgramEngine::OrderedNfaWithPartial(partial) => {
                let nfa = workspace
                    .nfa
                    .as_mut()
                    .ok_or(CompileError::InternalInvariant(
                        "partial-DFA program workspace has no K0 storage",
                    ))?;
                let Some(partial_workspace) = workspace.partial.as_deref_mut() else {
                    // A workspace prepared by the structurally identical fast
                    // program remains compatible. It simply takes the
                    // ordinary K0 route selected for that prepared session.
                    return self.search_nfa(haystack, window, nfa);
                };
                if let Some(found) = self.search_nfa_with_partial_dfa(
                    partial,
                    haystack,
                    window,
                    nfa,
                    &mut partial_workspace.resume,
                    &mut partial_workspace.state,
                )? {
                    return Ok(found);
                }
                self.search_nfa(haystack, window, nfa)
            }
            ProgramEngine::OrderedDfa(machine) => {
                match self.output {
                    OutputContract::Exists => Ok(MatchResult::Exists(machine.exists(
                        haystack,
                        window.start,
                        window.end,
                    )?)),
                    OutputContract::SelectedEnd => Ok(MatchResult::SelectedEnd(
                        machine.selected_end(haystack, window.start, window.end)?,
                    )),
                    OutputContract::Span => {
                        let found = if let Some(width) = self.exact_match_width {
                            machine
                                .selected_end(haystack, window.start, window.end)?
                                .map(|end| {
                                    end.checked_sub(width).map(|start| (start, end)).ok_or(
                                        CompileError::InternalInvariant(
                                            "fixed-width match end preceded its proved width",
                                        ),
                                    )
                                })
                                .transpose()?
                        } else {
                            machine
                                .span(haystack, window.start, window.end)?
                                .map(|span| (span.start, span.end))
                        };
                        Ok(MatchResult::Span(found))
                    }
                }
            }
        }
    }

    fn search_nfa(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
    ) -> Result<MatchResult, CompileError> {
        if let Some(found) = self.search_nfa_with_mandatory_suffix(haystack, window, workspace)? {
            return Ok(found);
        }
        if let Some(found) = self.search_nfa_with_mandatory_cut(haystack, window) {
            return Ok(found);
        }
        self.search_nfa_unaccelerated(haystack, window, workspace)
    }

    /// Try the mutually exclusive graph-proved forward sidecar. An exact
    /// product returns a complete result; an ordinary mandatory-cut member is
    /// deliberately inconclusive and leaves the window to the ordered NFA.
    fn search_nfa_with_mandatory_cut(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Option<MatchResult> {
        let accelerator = self.nfa_mandatory_cut.as_ref()?;
        if let Some(product) = accelerator.exact_product() {
            return Some(product.search(&self.anchored_prefix, haystack, window, self.output));
        }
        let source = haystack.get(window.start..window.end)?;
        if accelerator.has_member(source) {
            return None;
        }
        Some(match self.output {
            OutputContract::Exists => MatchResult::Exists(false),
            OutputContract::SelectedEnd => MatchResult::SelectedEnd(None),
            OutputContract::Span => MatchResult::Span(None),
        })
    }

    /// Execute retained, canonical subset rows until they either decide the
    /// complete result or reach a state whose row was not completed under the
    /// caller's determinization budget. A side exit carries the exact ordered
    /// subset and pending endpoint into K0 at the first unconsumed byte; the
    /// original prefix is never replayed.
    fn search_nfa_with_partial_dfa(
        &self,
        partial: &PartialDfa,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut Option<K0ResumeSet>,
        state: &mut PartialDfaRuntimeState,
    ) -> Result<Option<MatchResult>, CompileError> {
        if !state.admit() {
            return Ok(None);
        }
        let input_bytes = window.end.saturating_sub(window.start);
        match self.output {
            OutputContract::Exists => match partial.exists(
                haystack,
                window.start,
                window.end,
                self.anchored_prefix.sets(),
                state.prefix_plan,
            )? {
                PartialDfaResult::Complete(found) => {
                    state.observe_complete();
                    Ok(Some(MatchResult::Exists(found)))
                }
                PartialDfaResult::Resume(resume) => self
                    .resolve_partial_hole(haystack, window, workspace, resume_set, state, resume),
            },
            OutputContract::SelectedEnd => {
                match partial.selected_end(
                    haystack,
                    window.start,
                    window.end,
                    self.anchored_prefix.sets(),
                    state.prefix_plan,
                )? {
                    PartialDfaResult::Complete(found) => {
                        state.observe_complete();
                        Ok(Some(MatchResult::SelectedEnd(found)))
                    }
                    PartialDfaResult::Resume(resume) => self.resolve_partial_hole(
                        haystack, window, workspace, resume_set, state, resume,
                    ),
                }
            }
            OutputContract::Span => {
                match partial.selected_end(
                    haystack,
                    window.start,
                    window.end,
                    self.anchored_prefix.sets(),
                    state.prefix_plan,
                )? {
                    PartialDfaResult::Resume(resume) => self.resolve_partial_hole(
                        haystack, window, workspace, resume_set, state, resume,
                    ),
                    PartialDfaResult::Complete(None) => {
                        state.observe_complete();
                        Ok(Some(MatchResult::Span(None)))
                    }
                    PartialDfaResult::Complete(Some(end)) => {
                        let Some(width) = self.exact_match_width else {
                            // The retained forward rows prove the selected end,
                            // but variable-width start recovery requires an
                            // exact reverse machine. Until partial reverse rows
                            // are retained, let bidirectional K0 recover it.
                            state.observe_fallback(input_bytes, input_bytes);
                            return Ok(None);
                        };
                        let start =
                            end.checked_sub(width)
                                .ok_or(CompileError::InternalInvariant(
                                    "partial fixed-width match end preceded its proved width",
                                ))?;
                        state.observe_complete();
                        Ok(Some(MatchResult::Span(Some((start, end)))))
                    }
                }
            }
        }
    }

    fn resolve_partial_hole(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut Option<K0ResumeSet>,
        state: &mut PartialDfaRuntimeState,
        resume: PartialDfaResume,
    ) -> Result<Option<MatchResult>, CompileError> {
        let input_bytes = window.end.saturating_sub(window.start);
        let consumed = resume.position.saturating_sub(window.start);
        if let Some(found) = self.search_nfa_with_mandatory_suffix(haystack, window, workspace)? {
            state.observe_fallback(consumed, input_bytes);
            return Ok(Some(found));
        }
        if let Some(found) = self.search_nfa_with_mandatory_cut(haystack, window) {
            state.observe_fallback(consumed, input_bytes);
            return Ok(Some(found));
        }
        if resume_set
            .as_ref()
            .is_none_or(|set| !set.is_bound_to(&self.automaton))
        {
            state.observe_fallback(consumed, input_bytes);
            return Ok(None);
        }
        let found =
            self.search_nfa_from_partial_resume(haystack, window, workspace, resume_set, resume)?;
        state.observe_resume();
        Ok(Some(found))
    }

    fn search_nfa_from_partial_resume(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
        resume_set: &mut Option<K0ResumeSet>,
        resume: PartialDfaResume,
    ) -> Result<MatchResult, CompileError> {
        let resume_set = resume_set.as_mut().ok_or(CompileError::InternalInvariant(
            "partial DFA hole has no authenticated K0 resume set",
        ))?;
        let k0_window = K0SearchWindow::new(window.start, window.end);
        let limits = SearchLimits::unlimited();
        match self.output {
            OutputContract::Exists => {
                let found = self
                    .automaton
                    .prepare::<Exists>()
                    .search_window_from_ordered_resume(
                        haystack,
                        k0_window,
                        workspace,
                        resume_set,
                        resume.state,
                        resume.position,
                        resume.pending_end,
                        limits,
                    )?
                    .into_output();
                Ok(MatchResult::Exists(found))
            }
            OutputContract::SelectedEnd => {
                let found = self
                    .automaton
                    .prepare::<SelectedEnd>()
                    .search_window_from_ordered_resume(
                        haystack,
                        k0_window,
                        workspace,
                        resume_set,
                        resume.state,
                        resume.position,
                        resume.pending_end,
                        limits,
                    )?
                    .into_output();
                Ok(MatchResult::SelectedEnd(found))
            }
            OutputContract::Span => {
                let found = if let Some(width) = self.exact_match_width {
                    self.automaton
                        .prepare::<SelectedEnd>()
                        .search_window_from_ordered_resume(
                            haystack,
                            k0_window,
                            workspace,
                            resume_set,
                            resume.state,
                            resume.position,
                            resume.pending_end,
                            limits,
                        )?
                        .into_output()
                        .map(|end| {
                            end.checked_sub(width).map(|start| (start, end)).ok_or(
                                CompileError::InternalInvariant(
                                    "resumed fixed-width match end preceded its proved width",
                                ),
                            )
                        })
                        .transpose()?
                } else {
                    self.automaton
                        .prepare::<Span>()
                        .search_window_from_ordered_resume(
                            haystack,
                            k0_window,
                            workspace,
                            resume_set,
                            resume.state,
                            resume.position,
                            resume.pending_end,
                            limits,
                        )?
                        .into_output()
                        .map(|span| (span.start(), span.end()))
                };
                Ok(MatchResult::Span(found))
            }
        }
    }

    /// Try the graph-derived mandatory-suffix route. `None` means this program
    /// has no eligible sidecar; every eligible execution returns a complete
    /// semantic result, including a proved no-match.
    fn search_nfa_with_mandatory_suffix(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
    ) -> Result<Option<MatchResult>, CompileError> {
        let Some(accelerator) = &self.nfa_mandatory_suffix else {
            return Ok(None);
        };

        let Some(maximum_width) = accelerator.maximum_width else {
            return self.search_nfa_with_scan_only_mandatory_suffix(haystack, window);
        };

        let mut from_endpoint = window
            .start
            .checked_add(usize::from(accelerator.minimum_width))
            .ok_or(CompileError::InternalInvariant(
                "mandatory-suffix minimum endpoint overflowed",
            ))?;
        let mut earliest_start: Option<usize> = None;
        let mut primary_hits = 0usize;

        loop {
            // Once a start `s` is known, an endpoint at or beyond `s + M`
            // cannot prove a start before `s`: every match consumes at most M
            // bytes. The ordered replay below considers the equality endpoint
            // as part of the complete decision range for `s`.
            let maximum_endpoint = match earliest_start {
                Some(start) => start
                    .checked_add(maximum_width)
                    .and_then(|endpoint| endpoint.checked_sub(1))
                    .map_or(window.end, |endpoint| endpoint.min(window.end)),
                None => window.end,
            };
            let endpoint = match accelerator.next_candidate_endpoint(
                &self.anchored_suffix,
                haystack,
                window.start,
                maximum_endpoint,
                from_endpoint,
                &mut primary_hits,
            ) {
                NfaMandatorySuffixScan::Candidate(endpoint) => endpoint,
                NfaMandatorySuffixScan::Exhausted => break,
                NfaMandatorySuffixScan::Fallback => return Ok(None),
            };
            if endpoint
                == window
                    .start
                    .saturating_add(usize::from(accelerator.minimum_width))
            {
                // A suffix hit at the first possible endpoint is cheaper to
                // resolve directly: ordered replay is already bounded by M,
                // while reverse verification would duplicate that short walk.
                return Ok(None);
            }
            let reverse_start = endpoint.saturating_sub(maximum_width).max(window.start);
            let candidate_start = accelerator
                .reverse
                .trace(haystack, reverse_start, endpoint)
                .map_err(|_| {
                    CompileError::InternalInvariant(
                        "mandatory-suffix reverse verifier received an invalid window",
                    )
                })?
                .last();
            if let Some(start) = candidate_start {
                if self.output == OutputContract::Exists {
                    return Ok(Some(MatchResult::Exists(true)));
                }
                earliest_start = Some(earliest_start.map_or(start, |current| current.min(start)));
            }
            if accelerator.primary_hits_are_dense(window.start, endpoint, primary_hits) {
                return Ok(None);
            }
            let Some(next_endpoint) = endpoint.checked_add(1) else {
                break;
            };
            from_endpoint = next_endpoint;
        }

        let Some(earliest_start) = earliest_start else {
            return Ok(Some(match self.output {
                OutputContract::Exists => MatchResult::Exists(false),
                OutputContract::SelectedEnd => MatchResult::SelectedEnd(None),
                OutputContract::Span => MatchResult::Span(None),
            }));
        };
        let replay_end = earliest_start
            .checked_add(maximum_width)
            .map_or(window.end, |end| end.min(window.end));
        self.search_nfa_unaccelerated(
            haystack,
            SearchWindow::new(earliest_start, replay_end),
            workspace,
        )
        .map(Some)
    }

    /// Search a mandatory suffix without an admitted finite replay width.
    /// This includes genuinely unbounded graphs, exhausted width proofs, and
    /// finite widths whose worst-case replay cost exceeded the accelerator's
    /// bounded-replay envelope.
    ///
    /// Exhausting the graph-proved suffix scanner is a complete no-match
    /// proof for every output contract. An independently determinized reverse
    /// machine rejects sparse false candidates and proves matches directly for
    /// `Exists`. A proved endpoint-sensitive match falls back immediately to
    /// the ordinary ordered NFA, avoiding a reverse walk followed by an
    /// unbounded ordered replay. Cumulative reverse work is conservatively
    /// bounded before each verification, preventing adversarial sparse
    /// candidates from inducing quadratic execution.
    fn search_nfa_with_scan_only_mandatory_suffix(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<Option<MatchResult>, CompileError> {
        let accelerator =
            self.nfa_mandatory_suffix
                .as_ref()
                .ok_or(CompileError::InternalInvariant(
                    "scan-only mandatory-suffix search has no sidecar",
                ))?;
        if accelerator.maximum_width.is_some() {
            return Err(CompileError::InternalInvariant(
                "scan-only mandatory-suffix search received a bounded-replay sidecar",
            ));
        }

        let mut from_endpoint = window
            .start
            .checked_add(usize::from(accelerator.minimum_width))
            .ok_or(CompileError::InternalInvariant(
                "mandatory-suffix minimum endpoint overflowed",
            ))?;
        let mut primary_hits = 0usize;
        let mut reverse_work = 0usize;
        loop {
            let endpoint = match accelerator.next_candidate_endpoint(
                &self.anchored_suffix,
                haystack,
                window.start,
                window.end,
                from_endpoint,
                &mut primary_hits,
            ) {
                NfaMandatorySuffixScan::Candidate(endpoint) => endpoint,
                NfaMandatorySuffixScan::Exhausted => {
                    break;
                }
                NfaMandatorySuffixScan::Fallback => return Ok(None),
            };

            let Some(next_reverse_work) = NfaMandatorySuffix::next_scan_only_reverse_work(
                reverse_work,
                window.start,
                endpoint,
            ) else {
                return Ok(None);
            };
            reverse_work = next_reverse_work;
            let proves_match = accelerator
                .reverse
                .trace(haystack, window.start, endpoint)
                .map_err(|_| {
                    CompileError::InternalInvariant(
                        "mandatory-suffix reverse verifier received an invalid window",
                    )
                })?
                .next()
                .is_some();
            if proves_match {
                if self.output == OutputContract::Exists {
                    return Ok(Some(MatchResult::Exists(true)));
                }
                return Ok(None);
            }
            if accelerator.primary_hits_are_dense(window.start, endpoint, primary_hits) {
                return Ok(None);
            }
            let Some(next_endpoint) = endpoint.checked_add(1) else {
                break;
            };
            from_endpoint = next_endpoint;
        }
        Ok(Some(match self.output {
            OutputContract::Exists => MatchResult::Exists(false),
            OutputContract::SelectedEnd => MatchResult::SelectedEnd(None),
            OutputContract::Span => MatchResult::Span(None),
        }))
    }

    fn search_nfa_unaccelerated(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        workspace: &mut K0Workspace,
    ) -> Result<MatchResult, CompileError> {
        let window = K0SearchWindow::new(window.start, window.end);
        let limits = SearchLimits::unlimited();
        match self.output {
            OutputContract::Exists => {
                let found = self
                    .automaton
                    .prepare::<Exists>()
                    .search_prevalidated_window_with_authenticated_workspace(
                        haystack, window, workspace, limits,
                    )?
                    .into_output();
                Ok(MatchResult::Exists(found))
            }
            OutputContract::SelectedEnd => {
                let found = self
                    .automaton
                    .prepare::<SelectedEnd>()
                    .search_prevalidated_window_with_authenticated_workspace(
                        haystack, window, workspace, limits,
                    )?
                    .into_output();
                Ok(MatchResult::SelectedEnd(found))
            }
            OutputContract::Span => {
                let found = if let Some(width) = self.exact_match_width {
                    self.automaton
                        .prepare::<SelectedEnd>()
                        .search_prevalidated_window_with_authenticated_workspace(
                            haystack, window, workspace, limits,
                        )?
                        .into_output()
                        .map(|end| {
                            end.checked_sub(width).map(|start| (start, end)).ok_or(
                                CompileError::InternalInvariant(
                                    "fixed-width NFA match end preceded its proved width",
                                ),
                            )
                        })
                        .transpose()?
                } else {
                    self.automaton
                        .prepare::<Span>()
                        .search_prevalidated_window_with_authenticated_workspace(
                            haystack, window, workspace, limits,
                        )?
                        .into_output()
                        .map(|span| (span.start(), span.end()))
                };
                Ok(MatchResult::Span(found))
            }
        }
    }

    /// Exact byte length of [`Self::serialize`].
    ///
    /// # Errors
    ///
    /// Returns an invariant error when a length arithmetic operation
    /// overflows.
    pub fn serialized_len(&self) -> Result<usize, CompileError> {
        let raw = raw_serialized_len(&self.raw)?;
        let dfa = match &self.engine {
            ProgramEngine::OrderedNfa => 0,
            ProgramEngine::OrderedNfaWithPartial(partial) => partial.serialized_len()?,
            ProgramEngine::OrderedDfa(machine) => machine.serialized_len()?,
        };
        PROGRAM_HEADER_LEN
            .checked_add(raw)
            .and_then(|value| value.checked_add(8))
            .and_then(|value| value.checked_add(dfa))
            .ok_or(CompileError::InternalInvariant(
                "program serialization length overflowed",
            ))
    }

    /// Serialize this program in the stable, self-delimiting little-endian
    /// runtime format.
    ///
    /// # Errors
    ///
    /// Returns an invariant error if a dimension cannot be represented or the
    /// bounded output allocation cannot be reserved.
    pub fn serialize(&self) -> Result<Vec<u8>, CompileError> {
        let expected = self.serialized_len()?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(expected).map_err(|_| {
            CompileError::InternalInvariant("program serialization allocation failed")
        })?;
        bytes.extend_from_slice(PROGRAM_MAGIC);
        put_u32(&mut bytes, PROGRAM_FORMAT_VERSION);
        bytes.push(self.engine_kind().tag());
        bytes.push(self.output.tag());
        bytes.extend_from_slice(&[self.line_terminator, self.program_flags()]);
        put_u64(
            &mut bytes,
            u64::try_from(expected).map_err(|_| {
                CompileError::InternalInvariant("program serialization length exceeded u64")
            })?,
        );
        serialize_raw(&self.raw, &mut bytes);
        let dfa_len = match &self.engine {
            ProgramEngine::OrderedNfa => 0,
            ProgramEngine::OrderedNfaWithPartial(partial) => partial.serialized_len()?,
            ProgramEngine::OrderedDfa(machine) => machine.serialized_len()?,
        };
        put_u64(
            &mut bytes,
            u64::try_from(dfa_len).map_err(|_| {
                CompileError::InternalInvariant("DFA serialization length exceeded u64")
            })?,
        );
        match &self.engine {
            ProgramEngine::OrderedNfa => {}
            ProgramEngine::OrderedNfaWithPartial(partial) => partial.serialize_into(&mut bytes),
            ProgramEngine::OrderedDfa(machine) => machine.serialize_into(&mut bytes),
        }
        if bytes.len() != expected {
            return Err(CompileError::InternalInvariant(
                "program serializer emitted an unexpected byte count",
            ));
        }
        Ok(bytes)
    }

    /// SHA-256 of the exact bytes returned by [`Self::serialize`].
    ///
    /// # Errors
    ///
    /// Returns the same bounded serialization failures as [`Self::serialize`].
    pub fn serialized_sha256(&self) -> Result<[u8; 32], CompileError> {
        Ok(Sha256::digest(self.serialize()?).into())
    }

    /// Read and validate the declared total extent from a fixed program
    /// header.
    ///
    /// Runtimes use this before constructing a slice over an embedded object
    /// section. `header` must contain exactly [`PROGRAM_HEADER_LEN`] bytes; the
    /// returned extent is always within [`MAX_SERIALIZED_PROGRAM_BYTES`].
    ///
    /// # Errors
    ///
    /// Rejects an incomplete header, bad magic or version, unknown tags,
    /// non-zero reserved bytes, and an out-of-range total extent.
    pub fn serialized_len_from_header(header: &[u8]) -> Result<usize, ProgramFormatError> {
        if header.len() != PROGRAM_HEADER_LEN {
            return Err(ProgramFormatError::Malformed(
                "fixed header has the wrong length",
            ));
        }
        if header.get(..8) != Some(PROGRAM_MAGIC.as_slice()) {
            return Err(ProgramFormatError::Malformed("bad program magic"));
        }
        let version = read_u32_at(header, 8)?;
        EngineKind::from_tag(header[12])?;
        OutputContract::from_tag(header[13])?;
        header_line_terminator(header, version)?;
        header_program_flags(header, version)?;
        let total = usize_from_u64(read_u64_at(header, 16)?, "program total length")?;
        if !(MIN_SERIALIZED_PROGRAM_BYTES..=MAX_SERIALIZED_PROGRAM_BYTES).contains(&total) {
            return Err(ProgramFormatError::Malformed(
                "program total length exceeds the stable bounds",
            ));
        }
        Ok(total)
    }

    /// Strictly reconstruct a complete semantic program from its stable
    /// serialized form.
    ///
    /// This validates the fixed header and exact total extent, every raw-plan
    /// count and tag, the complete graph through [`Automaton::from_raw`], all
    /// ordered-DFA table shapes and cell state bounds, output-specific reverse
    /// requirements, reserved bytes, and the absence of trailing data.
    ///
    /// # Errors
    ///
    /// Returns [`ProgramFormatError`] for any malformed or unsupported input.
    #[allow(
        clippy::too_many_lines,
        reason = "stable wire validation and optional sidecar reconstruction are transactional"
    )]
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProgramFormatError> {
        let header = bytes
            .get(..PROGRAM_HEADER_LEN)
            .ok_or(ProgramFormatError::Malformed("program header is truncated"))?;
        let declared = Self::serialized_len_from_header(header)?;
        if declared != bytes.len() {
            return Err(ProgramFormatError::Malformed(
                "declared program length does not match the supplied extent",
            ));
        }

        let engine_kind = EngineKind::from_tag(header[12])?;
        let output = OutputContract::from_tag(header[13])?;
        let version = read_u32_at(header, 8)?;
        let line_terminator = header_line_terminator(header, version)?;
        let program_flags = header_program_flags(header, version)?;
        let mandatory_suffix_enabled = program_flags & PROGRAM_FLAG_NFA_MANDATORY_SUFFIX != 0;
        let mandatory_cut_enabled = program_flags & PROGRAM_FLAG_NFA_MANDATORY_CUT != 0;
        let exact_product_enabled = program_flags & PROGRAM_FLAG_NFA_EXACT_PRODUCT != 0;
        if (mandatory_suffix_enabled || mandatory_cut_enabled || exact_product_enabled)
            && engine_kind != EngineKind::OrderedNfa
        {
            return Err(ProgramFormatError::Malformed(
                "mandatory NFA sidecar flag requires an ordered-NFA engine",
            ));
        }
        if (mandatory_suffix_enabled && mandatory_cut_enabled)
            || (mandatory_suffix_enabled && exact_product_enabled)
            || (mandatory_cut_enabled && exact_product_enabled)
        {
            return Err(ProgramFormatError::Malformed(
                "ordered-NFA sidecar flags are mutually exclusive",
            ));
        }
        if program_flags & PROGRAM_FLAG_NFA_PARTIAL_DFA != 0
            && engine_kind != EngineKind::OrderedNfa
        {
            return Err(ProgramFormatError::Malformed(
                "partial-DFA flag requires an ordered-NFA engine",
            ));
        }
        let mut reader = ProgramReader::new(
            bytes
                .get(PROGRAM_HEADER_LEN..)
                .ok_or(ProgramFormatError::Malformed("program body is truncated"))?,
        );
        let raw = deserialize_raw(&mut reader)?;
        let automaton = deserialize_automaton(&raw, line_terminator)?;
        let exact_match_width = derive_exact_match_width(&raw);

        let dfa_len = reader.usize_u64("DFA byte length")?;
        let dfa_bytes = reader.take(dfa_len, "DFA body is truncated")?;
        let (engine, partial_dfa) = match engine_kind {
            EngineKind::OrderedNfa | EngineKind::OrderedContextDfa => {
                let partial = if program_flags & PROGRAM_FLAG_NFA_PARTIAL_DFA != 0 {
                    if dfa_len == 0 {
                        return Err(ProgramFormatError::Malformed(
                            "partial-DFA program has no partial payload",
                        ));
                    }
                    if raw
                        .edge_kinds
                        .iter()
                        .any(|kind| !matches!(kind, EdgeKind::Epsilon | EdgeKind::ByteRange))
                    {
                        return Err(ProgramFormatError::Malformed(
                            "partial-DFA graph contains a context assertion",
                        ));
                    }
                    let alphabet_shape = dfa_alphabet_shape(&raw)?;
                    let partial = PartialDfa::deserialize(
                        dfa_bytes,
                        alphabet_shape.construction_classes(),
                        &alphabet_shape.boundary_starts,
                        &raw.roles,
                    )?;
                    partial.validate_canonical(
                        &raw,
                        output == OutputContract::Span && exact_match_width.is_none(),
                    )?;
                    Some(Box::new(partial))
                } else {
                    if dfa_len != 0 {
                        return Err(ProgramFormatError::Malformed(
                            "ordered-NFA program contains an unflagged DFA payload",
                        ));
                    }
                    None
                };
                (ProgramEngine::OrderedNfa, partial)
            }
            EngineKind::OrderedDfa => {
                if dfa_len == 0 {
                    return Err(ProgramFormatError::Malformed(
                        "ordered-DFA program has no DFA payload",
                    ));
                }
                if raw
                    .edge_kinds
                    .iter()
                    .any(|kind| !matches!(kind, EdgeKind::Epsilon | EdgeKind::ByteRange))
                {
                    return Err(ProgramFormatError::Malformed(
                        "ordered-DFA graph contains a context assertion",
                    ));
                }
                let alphabet_shape = dfa_alphabet_shape(&raw)?;
                let machine = OrderedDfa::deserialize(
                    dfa_bytes,
                    output,
                    exact_match_width,
                    alphabet_shape.construction_classes(),
                    &alphabet_shape.boundary_starts,
                )?;
                machine.validate_canonical(&raw)?;
                (ProgramEngine::OrderedDfa(machine), None)
            }
        };
        reader.finish()?;
        let engine_selection_reason = match engine_kind {
            EngineKind::OrderedNfa | EngineKind::OrderedContextDfa => None,
            EngineKind::OrderedDfa => Some(EngineSelectionReason::CompleteDfa),
        };
        let identity = automaton_digest(&raw, line_terminator);
        let anchored_prefix = derive_anchored_prefix(&raw);
        let anchored_suffix = derive_anchored_suffix(&raw);
        let required_literals = if engine_kind == EngineKind::OrderedDfa
            || mandatory_cut_enabled
            || program_flags & PROGRAM_FLAG_NFA_PARTIAL_DFA != 0
        {
            required_literals::derive(&raw)
        } else {
            RequiredLiterals::unavailable()
        };
        let max_match_width = derive_max_match_width(&raw);
        let nfa_exact_product = exact_product_enabled
            .then(|| NfaExactProduct::derive(&raw, &anchored_prefix, exact_match_width, &engine))
            .flatten();
        if exact_product_enabled != nfa_exact_product.is_some() {
            return Err(ProgramFormatError::Malformed(
                "exact-product flag is incompatible with the embedded graph",
            ));
        }
        let nfa_mandatory_suffix = derive_nfa_suffix(
            &raw,
            &anchored_prefix,
            &anchored_suffix,
            max_match_width,
            &engine,
            mandatory_suffix_enabled,
        );
        if mandatory_suffix_enabled != nfa_mandatory_suffix.is_some() {
            return Err(ProgramFormatError::Malformed(
                "mandatory-suffix flag is incompatible with the embedded graph",
            ));
        }
        let ordinary_mandatory_cut = derive_nfa_mandatory_cut(
            &anchored_prefix,
            &required_literals,
            &engine,
            nfa_mandatory_suffix.is_some(),
            mandatory_cut_enabled && nfa_exact_product.is_none(),
        );
        if mandatory_cut_enabled != ordinary_mandatory_cut.is_some() {
            return Err(ProgramFormatError::Malformed(
                "mandatory-cut flag is incompatible with the embedded graph",
            ));
        }
        let nfa_mandatory_cut = nfa_exact_product
            .map(NfaMandatoryCut::from_exact_product)
            .or(ordinary_mandatory_cut);
        if nfa_exact_product.is_some() && partial_dfa.is_some() {
            return Err(ProgramFormatError::Malformed(
                "exact-product and partial-DFA sidecars are mutually exclusive",
            ));
        }
        let engine = match (engine, partial_dfa) {
            (ProgramEngine::OrderedNfa, Some(partial)) => {
                ProgramEngine::OrderedNfaWithPartial(partial)
            }
            (engine, None) => engine,
            (ProgramEngine::OrderedNfaWithPartial(_), Some(_))
            | (ProgramEngine::OrderedDfa(_), Some(_)) => {
                return Err(ProgramFormatError::Malformed(
                    "partial DFA was paired with a non-fallback engine",
                ));
            }
        };
        let program = Self {
            raw,
            automaton,
            identity,
            line_terminator,
            output,
            engine,
            engine_selection_reason,
            determinization_report: None,
            context_dfa: None,
            context_determinization_report: None,
            anchored_prefix,
            anchored_suffix,
            required_literals,
            exact_match_width,
            max_match_width,
            nfa_mandatory_suffix,
            nfa_mandatory_cut,
        };
        if program
            .serialized_len()
            .map_err(|_| ProgramFormatError::Malformed("reconstructed program length overflowed"))?
            != bytes.len()
        {
            return Err(ProgramFormatError::Malformed(
                "reconstructed program has a non-canonical extent",
            ));
        }
        Ok(program)
    }
}

#[derive(Clone, Copy, Debug)]
struct AnchoredWork {
    limit: u64,
    used: u64,
    declined: bool,
    context_assertions: bool,
}

impl AnchoredWork {
    const fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            declined: false,
            context_assertions: false,
        }
    }

    fn charge(&mut self, amount: u64) -> bool {
        let Some(next) = self.used.checked_add(amount) else {
            self.declined = true;
            return false;
        };
        if next > self.limit {
            self.declined = true;
            return false;
        }
        self.used = next;
        true
    }
}

fn declined_anchored_prefix(work: AnchoredWork) -> AnchoredPrefix {
    AnchoredPrefix {
        derivation_work: work.used,
        resource_limited: true,
        context_assertions: work.context_assertions,
        ..AnchoredPrefix::EMPTY
    }
}

const fn anchored_prefix_assertion(kind: EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::AssertHaystackStart
            | EdgeKind::AssertHaystackEnd
            | EdgeKind::AssertLineStartLf
            | EdgeKind::AssertLineEndLf
            | EdgeKind::AssertLineStartCrlf
            | EdgeKind::AssertLineEndCrlf
            | EdgeKind::AssertWordAscii
            | EdgeKind::AssertWordAsciiNegate
            | EdgeKind::AssertWordStartAscii
            | EdgeKind::AssertWordEndAscii
            | EdgeKind::AssertWordStartHalfAscii
            | EdgeKind::AssertWordEndHalfAscii
            | EdgeKind::AssertWordUnicode
            | EdgeKind::AssertWordUnicodeNegate
            | EdgeKind::AssertWordStartUnicode
            | EdgeKind::AssertWordEndUnicode
            | EdgeKind::AssertWordStartHalfUnicode
            | EdgeKind::AssertWordEndHalfUnicode
    )
}

fn prefix_push(states: &mut Vec<u32>, state: u32) -> bool {
    if states.try_reserve(1).is_err() {
        return false;
    }
    states.push(state);
    true
}

/// Derive a conservative fixed-byte prefix directly from the Thompson graph.
///
/// Each layer computes a fresh zero-width closure with a per-layer seen set.
/// Assertions are traversed without deciding whether they hold: their target
/// bytes remain necessary whenever that asserted path accepts, while paths
/// whose assertions fail only add harmless false positives. Reaching accept
/// before another byte, an invalid graph relation, or exhausting bounded work
/// stops/declines the optional optimization. Unioning every consuming edge can
/// therefore never reject an accepting path.
#[allow(
    clippy::too_many_lines,
    reason = "bounded graph-layer closure and its conservative exits stay in one auditable analysis"
)]
fn derive_anchored_prefix(raw: &RawPlan) -> AnchoredPrefix {
    let mut work = AnchoredWork::new(MAX_ANCHORED_PREFIX_WORK);
    for kind in &raw.edge_kinds {
        if !work.charge(1) {
            return declined_anchored_prefix(work);
        }
        if anchored_prefix_assertion(*kind) {
            work.context_assertions = true;
        } else if !matches!(kind, EdgeKind::Epsilon | EdgeKind::ByteRange) {
            return AnchoredPrefix {
                derivation_work: work.used,
                context_assertions: true,
                ..AnchoredPrefix::EMPTY
            };
        }
    }
    let states = raw.roles.len();
    let Ok(start) = usize::try_from(raw.start) else {
        return AnchoredPrefix::EMPTY;
    };
    if start >= states || raw.edge_offsets.len() != states.saturating_add(1) {
        return AnchoredPrefix::EMPTY;
    }
    let Ok(state_initialization_work) = u64::try_from(states) else {
        return declined_anchored_prefix(work);
    };
    if !work.charge(state_initialization_work) {
        return declined_anchored_prefix(work);
    }

    let mut seen = Vec::new();
    if seen.try_reserve_exact(states).is_err() {
        return declined_anchored_prefix(work);
    }
    seen.resize(states, 0_u8);
    let mut current = Vec::new();
    if current.try_reserve_exact(1).is_err() {
        return declined_anchored_prefix(work);
    }
    current.push(raw.start);
    let mut stack = Vec::new();
    let mut consuming = Vec::new();
    let mut next = Vec::new();
    let mut prefix = AnchoredPrefix {
        context_assertions: work.context_assertions,
        ..AnchoredPrefix::EMPTY
    };

    for depth in 0..MAX_ANCHORED_PREFIX_BYTES {
        let layer = depth.saturating_add(1);
        let generation = u8::try_from(layer).unwrap_or(u8::MAX);
        stack.clear();
        consuming.clear();
        next.clear();
        if !prefix_push(&mut stack, current[0]) {
            return declined_anchored_prefix(work);
        }
        for &state in current.iter().skip(1) {
            if !prefix_push(&mut stack, state) {
                return declined_anchored_prefix(work);
            }
        }

        while let Some(state) = stack.pop() {
            if !work.charge(1) {
                return declined_anchored_prefix(work);
            }
            let Ok(state_index) = usize::try_from(state) else {
                return AnchoredPrefix::EMPTY;
            };
            let Some(mark) = seen.get_mut(state_index) else {
                return AnchoredPrefix::EMPTY;
            };
            if *mark == generation {
                continue;
            }
            *mark = generation;
            match raw.roles.get(state_index) {
                Some(StateRole::Accept) => {
                    prefix.derivation_work = work.used;
                    return prefix;
                }
                Some(StateRole::Consume) => {
                    if !prefix_push(&mut consuming, state) {
                        return declined_anchored_prefix(work);
                    }
                }
                Some(StateRole::Split) => {
                    let Some(&begin) = raw.edge_offsets.get(state_index) else {
                        return AnchoredPrefix::EMPTY;
                    };
                    let Some(next_state) = state_index.checked_add(1) else {
                        return AnchoredPrefix::EMPTY;
                    };
                    let Some(&end) = raw.edge_offsets.get(next_state) else {
                        return AnchoredPrefix::EMPTY;
                    };
                    let (Ok(begin), Ok(end)) = (usize::try_from(begin), usize::try_from(end))
                    else {
                        return AnchoredPrefix::EMPTY;
                    };
                    if begin > end || end > raw.edge_kinds.len() {
                        return AnchoredPrefix::EMPTY;
                    }
                    for edge in begin..end {
                        if !work.charge(1) {
                            return declined_anchored_prefix(work);
                        }
                        let Some(&kind) = raw.edge_kinds.get(edge) else {
                            return AnchoredPrefix::EMPTY;
                        };
                        if kind != EdgeKind::Epsilon && !anchored_prefix_assertion(kind) {
                            return AnchoredPrefix::EMPTY;
                        }
                        let Some(&target) = raw.edge_targets.get(edge) else {
                            return AnchoredPrefix::EMPTY;
                        };
                        if !prefix_push(&mut stack, target) {
                            return declined_anchored_prefix(work);
                        }
                    }
                }
                Some(_) | None => return AnchoredPrefix::EMPTY,
            }
        }

        let mut set = AnchoredByteSet::EMPTY;
        for &state in &consuming {
            let Ok(state_index) = usize::try_from(state) else {
                return AnchoredPrefix::EMPTY;
            };
            let Some(&begin) = raw.edge_offsets.get(state_index) else {
                return AnchoredPrefix::EMPTY;
            };
            let Some(next_state) = state_index.checked_add(1) else {
                return AnchoredPrefix::EMPTY;
            };
            let Some(&end) = raw.edge_offsets.get(next_state) else {
                return AnchoredPrefix::EMPTY;
            };
            let (Ok(begin), Ok(end)) = (usize::try_from(begin), usize::try_from(end)) else {
                return AnchoredPrefix::EMPTY;
            };
            if begin > end || end > raw.edge_kinds.len() {
                return AnchoredPrefix::EMPTY;
            }
            for edge in begin..end {
                if !work.charge(1) {
                    return declined_anchored_prefix(work);
                }
                if raw.edge_kinds.get(edge) != Some(&EdgeKind::ByteRange) {
                    return AnchoredPrefix::EMPTY;
                }
                let (Some(&start), Some(&end), Some(&target)) = (
                    raw.byte_starts.get(edge),
                    raw.byte_ends.get(edge),
                    raw.edge_targets.get(edge),
                ) else {
                    return AnchoredPrefix::EMPTY;
                };
                if start > end || !set.insert_range(start, end, &mut work) {
                    return declined_anchored_prefix(work);
                }
                if !prefix_push(&mut next, target) {
                    return declined_anchored_prefix(work);
                }
            }
        }
        if set.cardinality() == 0 {
            prefix.derivation_work = work.used;
            return prefix;
        }
        prefix.sets[depth] = set;
        prefix.len = u8::try_from(layer).unwrap_or(u8::MAX);
        if layer == MAX_ANCHORED_PREFIX_BYTES {
            prefix.derivation_work = work.used;
            return prefix;
        }
        if next.is_empty() {
            prefix.derivation_work = work.used;
            return prefix;
        }
        current.clear();
        if current.try_reserve(next.len()).is_err() {
            return declined_anchored_prefix(work);
        }
        current.extend_from_slice(&next);
    }
    prefix.derivation_work = work.used;
    prefix
}

#[derive(Clone, Copy, Debug)]
struct AnalysisIncomingEdge {
    source: u32,
    edge: u32,
}

struct AnalysisIncoming {
    by_target: Vec<Vec<AnalysisIncomingEdge>>,
}

impl AnalysisIncoming {
    fn build(raw: &RawPlan, work: &mut AnchoredWork) -> Option<Self> {
        let states = raw.roles.len();
        let mut by_target = Vec::new();
        if by_target.try_reserve_exact(states).is_err() {
            work.declined = true;
            return None;
        }
        by_target.resize_with(states, Vec::new);
        for source in 0..states {
            if !work.charge(1) {
                return None;
            }
            let source_u32 = u32::try_from(source).ok()?;
            let edges = analysis_state_edges(raw, source)?;
            for edge in edges {
                if !work.charge(1) {
                    return None;
                }
                let target = usize::try_from(*raw.edge_targets.get(edge)?).ok()?;
                let row = by_target.get_mut(target)?;
                if row.try_reserve(1).is_err() {
                    work.declined = true;
                    return None;
                }
                row.push(AnalysisIncomingEdge {
                    source: source_u32,
                    edge: u32::try_from(edge).ok()?,
                });
            }
        }
        Some(Self { by_target })
    }
}

fn analysis_state_edges(raw: &RawPlan, state: usize) -> Option<core::ops::Range<usize>> {
    let begin = usize::try_from(*raw.edge_offsets.get(state)?).ok()?;
    let end = usize::try_from(*raw.edge_offsets.get(state.checked_add(1)?)?).ok()?;
    (begin <= end && end <= raw.edge_targets.len()).then_some(begin..end)
}

fn anchored_push<T>(values: &mut Vec<T>, value: T, work: &mut AnchoredWork) -> bool {
    if values.try_reserve(1).is_err() {
        work.declined = true;
        return false;
    }
    values.push(value);
    true
}

fn stopped_anchored_suffix(work: AnchoredWork) -> AnchoredSuffix {
    AnchoredSuffix {
        derivation_work: work.used,
        context_assertions: work.context_assertions,
        ..AnchoredSuffix::EMPTY
    }
}

fn declined_anchored_suffix(work: AnchoredWork) -> AnchoredSuffix {
    AnchoredSuffix {
        derivation_work: work.used,
        resource_limited: true,
        context_assertions: work.context_assertions,
        ..AnchoredSuffix::EMPTY
    }
}

/// Derive conservative trailing byte sets by walking the Thompson graph
/// backwards from every accept state. Assertions are traversed as zero-width
/// necessary conditions. Ignoring whether they hold can only add byte values
/// or shorten the proved suffix, never exclude an accepting path.
fn derive_anchored_suffix(raw: &RawPlan) -> AnchoredSuffix {
    derive_anchored_suffix_with_limit(raw, MAX_ANCHORED_SUFFIX_WORK)
}

#[allow(
    clippy::too_many_lines,
    reason = "reverse closure, incoming-edge validation, and bounded publication form one proof"
)]
fn derive_anchored_suffix_with_limit(raw: &RawPlan, max_work: u64) -> AnchoredSuffix {
    let mut work = AnchoredWork::new(max_work);
    for &kind in &raw.edge_kinds {
        if !work.charge(1) {
            return declined_anchored_suffix(work);
        }
        if anchored_prefix_assertion(kind) {
            work.context_assertions = true;
        } else if !matches!(kind, EdgeKind::Epsilon | EdgeKind::ByteRange) {
            work.context_assertions = true;
            return stopped_anchored_suffix(work);
        }
    }

    let states = raw.roles.len();
    let Ok(start) = usize::try_from(raw.start) else {
        return stopped_anchored_suffix(work);
    };
    if start >= states || raw.edge_offsets.len() != states.saturating_add(1) {
        return stopped_anchored_suffix(work);
    }
    let Ok(initialization_work) = u64::try_from(states) else {
        return declined_anchored_suffix(work);
    };
    if !work.charge(initialization_work) {
        return declined_anchored_suffix(work);
    }
    let Some(incoming) = AnalysisIncoming::build(raw, &mut work) else {
        return if work.declined {
            declined_anchored_suffix(work)
        } else {
            stopped_anchored_suffix(work)
        };
    };

    let mut seen = Vec::new();
    if seen.try_reserve_exact(states).is_err() {
        work.declined = true;
        return declined_anchored_suffix(work);
    }
    seen.resize(states, 0_u8);
    let mut current = Vec::new();
    for (state, role) in raw.roles.iter().enumerate() {
        if !work.charge(1) {
            return declined_anchored_suffix(work);
        }
        if *role == StateRole::Accept
            && !anchored_push(
                &mut current,
                u32::try_from(state).unwrap_or(u32::MAX),
                &mut work,
            )
        {
            return declined_anchored_suffix(work);
        }
    }
    if current.is_empty() || current.contains(&u32::MAX) {
        return stopped_anchored_suffix(work);
    }

    let mut stack = Vec::new();
    let mut consuming = Vec::new();
    let mut next = Vec::new();
    let mut suffix = AnchoredSuffix {
        context_assertions: work.context_assertions,
        ..AnchoredSuffix::EMPTY
    };

    for depth in 0..MAX_ANCHORED_SUFFIX_BYTES {
        let layer = depth.saturating_add(1);
        let generation = u8::try_from(layer).unwrap_or(u8::MAX);
        stack.clear();
        consuming.clear();
        next.clear();
        for &state in &current {
            if !anchored_push(&mut stack, state, &mut work) {
                return declined_anchored_suffix(work);
            }
        }

        while let Some(state) = stack.pop() {
            if !work.charge(1) {
                return declined_anchored_suffix(work);
            }
            let Ok(state_index) = usize::try_from(state) else {
                return stopped_anchored_suffix(work);
            };
            let Some(mark) = seen.get_mut(state_index) else {
                return stopped_anchored_suffix(work);
            };
            if *mark == generation {
                continue;
            }
            *mark = generation;
            if state_index == start {
                suffix.derivation_work = work.used;
                return suffix;
            }
            let Some(row) = incoming.by_target.get(state_index) else {
                return stopped_anchored_suffix(work);
            };
            for &incoming_edge in row {
                if !work.charge(1) {
                    return declined_anchored_suffix(work);
                }
                let Ok(source) = usize::try_from(incoming_edge.source) else {
                    return stopped_anchored_suffix(work);
                };
                let Ok(edge) = usize::try_from(incoming_edge.edge) else {
                    return stopped_anchored_suffix(work);
                };
                let Some(&kind) = raw.edge_kinds.get(edge) else {
                    return stopped_anchored_suffix(work);
                };
                match raw.roles.get(source) {
                    Some(StateRole::Split)
                        if kind == EdgeKind::Epsilon || anchored_prefix_assertion(kind) =>
                    {
                        if !anchored_push(&mut stack, incoming_edge.source, &mut work) {
                            return declined_anchored_suffix(work);
                        }
                    }
                    Some(StateRole::Consume) if kind == EdgeKind::ByteRange => {
                        if !anchored_push(&mut consuming, incoming_edge, &mut work) {
                            return declined_anchored_suffix(work);
                        }
                    }
                    Some(_) | None => return stopped_anchored_suffix(work),
                }
            }
        }

        let mut set = AnchoredByteSet::EMPTY;
        for incoming_edge in &consuming {
            let Ok(edge) = usize::try_from(incoming_edge.edge) else {
                return stopped_anchored_suffix(work);
            };
            let (Some(&start_byte), Some(&end_byte)) =
                (raw.byte_starts.get(edge), raw.byte_ends.get(edge))
            else {
                return stopped_anchored_suffix(work);
            };
            if start_byte > end_byte || !set.insert_range(start_byte, end_byte, &mut work) {
                return declined_anchored_suffix(work);
            }
            if !anchored_push(&mut next, incoming_edge.source, &mut work) {
                return declined_anchored_suffix(work);
            }
        }
        if set.cardinality() == 0 {
            suffix.derivation_work = work.used;
            return suffix;
        }
        suffix.sets[depth] = set;
        suffix.len = u8::try_from(layer).unwrap_or(u8::MAX);
        if layer == MAX_ANCHORED_SUFFIX_BYTES {
            suffix.derivation_work = work.used;
            return suffix;
        }
        if next.is_empty() {
            suffix.derivation_work = work.used;
            return suffix;
        }
        current.clear();
        if current.try_reserve(next.len()).is_err() {
            work.declined = true;
            return declined_anchored_suffix(work);
        }
        current.extend_from_slice(&next);
    }
    suffix.derivation_work = work.used;
    suffix
}

/// Prove that every graph path from the Thompson start to an accept consumes
/// exactly the same number of bytes.
///
/// A consistent integer potential is assigned to every reachable state. A
/// byte-range edge adds one and every zero-width edge adds zero. Reconverging
/// paths with different potentials, consuming cycles, arithmetic overflow,
/// malformed relations, allocation failure, or the fixed work ceiling all
/// conservatively return `None`. The proof therefore depends only on graph
/// structure and never on source spelling or a pattern catalogue.
fn derive_exact_match_width(raw: &RawPlan) -> Option<usize> {
    let states = raw.roles.len();
    if states == 0 || raw.edge_offsets.len() != states.checked_add(1)? {
        return None;
    }
    let start = usize::try_from(raw.start).ok()?;
    if start >= states {
        return None;
    }

    let mut distances = Vec::new();
    distances.try_reserve_exact(states).ok()?;
    distances.resize(states, None);
    distances[start] = Some(0_usize);

    let mut stack = Vec::new();
    stack.try_reserve_exact(states).ok()?;
    stack.push(raw.start);
    let mut accepted_width = None;
    let mut work = 0_u64;

    while let Some(state) = stack.pop() {
        work = work.checked_add(1)?;
        if work > MAX_EXACT_WIDTH_WORK {
            return None;
        }
        let state_index = usize::try_from(state).ok()?;
        let distance = distances.get(state_index).copied().flatten()?;
        match raw.roles.get(state_index)? {
            StateRole::Accept => {
                if accepted_width.is_some_and(|known| known != distance) {
                    return None;
                }
                accepted_width = Some(distance);
            }
            StateRole::Split | StateRole::Consume => {}
            _ => return None,
        }

        let next_state = state_index.checked_add(1)?;
        let begin = usize::try_from(*raw.edge_offsets.get(state_index)?).ok()?;
        let end = usize::try_from(*raw.edge_offsets.get(next_state)?).ok()?;
        if begin > end
            || end > raw.edge_kinds.len()
            || end > raw.edge_targets.len()
            || end > raw.byte_starts.len()
            || end > raw.byte_ends.len()
        {
            return None;
        }
        for edge in begin..end {
            work = work.checked_add(1)?;
            if work > MAX_EXACT_WIDTH_WORK {
                return None;
            }
            let increment = usize::from(raw.edge_kinds[edge] == EdgeKind::ByteRange);
            let target_distance = distance.checked_add(increment)?;
            let target = usize::try_from(raw.edge_targets[edge]).ok()?;
            let slot = distances.get_mut(target)?;
            match *slot {
                Some(known) if known != target_distance => return None,
                Some(_) => {}
                None => {
                    *slot = Some(target_distance);
                    stack.push(raw.edge_targets[edge]);
                }
            }
        }
    }
    accepted_width
}

fn incomplete_max_match_width(work: AnchoredWork) -> MaxMatchWidthStats {
    MaxMatchWidthStats {
        width: None,
        derivation_work: work.used,
        resource_limited: work.declined,
        unbounded: false,
    }
}

fn unbounded_max_match_width(work: AnchoredWork) -> MaxMatchWidthStats {
    MaxMatchWidthStats {
        width: None,
        derivation_work: work.used,
        resource_limited: false,
        unbounded: true,
    }
}

fn analysis_filled<T: Clone>(length: usize, value: T, work: &mut AnchoredWork) -> Option<Vec<T>> {
    let mut values = Vec::new();
    if values.try_reserve_exact(length).is_err() {
        work.declined = true;
        return None;
    }
    values.resize(length, value);
    Some(values)
}

fn analysis_capacity<T>(capacity: usize, work: &mut AnchoredWork) -> Option<Vec<T>> {
    let mut values = Vec::new();
    if values.try_reserve_exact(capacity).is_err() {
        work.declined = true;
        return None;
    }
    Some(values)
}

fn analysis_edge_weight(kind: EdgeKind) -> Option<usize> {
    if kind == EdgeKind::ByteRange {
        Some(1)
    } else if kind == EdgeKind::Epsilon || anchored_prefix_assertion(kind) {
        Some(0)
    } else {
        None
    }
}

#[derive(Clone, Copy)]
struct WidthDfsFrame {
    state: usize,
    next_edge: usize,
    end_edge: usize,
}

#[derive(Clone, Copy)]
struct WidthComponentEdge {
    target: usize,
    weight: usize,
}

/// Prove the maximum number of bytes consumed by any structurally accepting
/// path. Context assertions are zero-width edges. Kosaraju condensation makes
/// the proof linear in graph size: a byte edge internal to a relevant SCC is
/// an unbounded positive cycle; otherwise longest-path dynamic programming on
/// the condensation DAG yields the exact structural maximum.
fn derive_max_match_width(raw: &RawPlan) -> MaxMatchWidthStats {
    derive_max_match_width_with_limit(raw, MAX_MATCH_WIDTH_WORK)
}

#[allow(
    clippy::too_many_lines,
    reason = "bounded reachability, SCC construction, cycle proof, and longest-path publication are one audit unit"
)]
fn derive_max_match_width_with_limit(raw: &RawPlan, max_work: u64) -> MaxMatchWidthStats {
    let mut work = AnchoredWork::new(max_work);
    let states = raw.roles.len();
    let edges = raw.edge_targets.len();
    if states == 0
        || raw.edge_offsets.len() != states.saturating_add(1)
        || raw.edge_kinds.len() != edges
        || raw.byte_starts.len() != edges
        || raw.byte_ends.len() != edges
    {
        return incomplete_max_match_width(work);
    }
    let Ok(start) = usize::try_from(raw.start) else {
        return incomplete_max_match_width(work);
    };
    if start >= states {
        return incomplete_max_match_width(work);
    }
    for &kind in &raw.edge_kinds {
        if !work.charge(1) {
            return incomplete_max_match_width(work);
        }
        if analysis_edge_weight(kind).is_none() {
            return incomplete_max_match_width(work);
        }
    }
    let Some(incoming) = AnalysisIncoming::build(raw, &mut work) else {
        return incomplete_max_match_width(work);
    };

    // First remove graph regions that cannot participate in an accepting
    // path. A positive cycle is relevant only when it is both reachable from
    // the start and can still reach an accept state.
    let Some(mut can_accept) = analysis_filled(states, false, &mut work) else {
        return incomplete_max_match_width(work);
    };
    let Some(mut stack) = analysis_capacity(states, &mut work) else {
        return incomplete_max_match_width(work);
    };
    for (state, role) in raw.roles.iter().enumerate() {
        if !work.charge(1) {
            return incomplete_max_match_width(work);
        }
        if *role == StateRole::Accept {
            can_accept[state] = true;
            stack.push(state);
        }
    }
    while let Some(state) = stack.pop() {
        if !work.charge(1) {
            return incomplete_max_match_width(work);
        }
        let Some(row) = incoming.by_target.get(state) else {
            return incomplete_max_match_width(work);
        };
        for incoming_edge in row {
            if !work.charge(1) {
                return incomplete_max_match_width(work);
            }
            let Ok(source) = usize::try_from(incoming_edge.source) else {
                return incomplete_max_match_width(work);
            };
            let Some(mark) = can_accept.get_mut(source) else {
                return incomplete_max_match_width(work);
            };
            if !*mark {
                *mark = true;
                stack.push(source);
            }
        }
    }
    if !can_accept[start] {
        return incomplete_max_match_width(work);
    }

    let Some(mut reachable) = analysis_filled(states, false, &mut work) else {
        return incomplete_max_match_width(work);
    };
    reachable[start] = true;
    stack.push(start);
    while let Some(state) = stack.pop() {
        if !work.charge(1) {
            return incomplete_max_match_width(work);
        }
        let Some(state_edges) = analysis_state_edges(raw, state) else {
            return incomplete_max_match_width(work);
        };
        for edge in state_edges {
            if !work.charge(1) {
                return incomplete_max_match_width(work);
            }
            let Ok(target) = usize::try_from(raw.edge_targets[edge]) else {
                return incomplete_max_match_width(work);
            };
            if !can_accept.get(target).copied().unwrap_or(false) {
                continue;
            }
            let Some(mark) = reachable.get_mut(target) else {
                return incomplete_max_match_width(work);
            };
            if !*mark {
                *mark = true;
                stack.push(target);
            }
        }
    }

    // Forward finishing order over the relevant subgraph.
    let Some(mut seen) = analysis_filled(states, false, &mut work) else {
        return incomplete_max_match_width(work);
    };
    let Some(mut order) = analysis_capacity(states, &mut work) else {
        return incomplete_max_match_width(work);
    };
    let Some(mut frames) = analysis_capacity(states, &mut work) else {
        return incomplete_max_match_width(work);
    };
    for root in 0..states {
        if !work.charge(1) {
            return incomplete_max_match_width(work);
        }
        if !reachable[root] || seen[root] {
            continue;
        }
        let Some(root_edges) = analysis_state_edges(raw, root) else {
            return incomplete_max_match_width(work);
        };
        seen[root] = true;
        frames.push(WidthDfsFrame {
            state: root,
            next_edge: root_edges.start,
            end_edge: root_edges.end,
        });
        while !frames.is_empty() {
            if !work.charge(1) {
                return incomplete_max_match_width(work);
            }
            let edge = {
                let Some(frame) = frames.last_mut() else {
                    return incomplete_max_match_width(work);
                };
                if frame.next_edge < frame.end_edge {
                    let edge = frame.next_edge;
                    frame.next_edge = frame.next_edge.saturating_add(1);
                    Some(edge)
                } else {
                    None
                }
            };
            if let Some(edge) = edge {
                if !work.charge(1) {
                    return incomplete_max_match_width(work);
                }
                let Ok(target) = usize::try_from(raw.edge_targets[edge]) else {
                    return incomplete_max_match_width(work);
                };
                if !reachable.get(target).copied().unwrap_or(false) || seen[target] {
                    continue;
                }
                let Some(target_edges) = analysis_state_edges(raw, target) else {
                    return incomplete_max_match_width(work);
                };
                seen[target] = true;
                frames.push(WidthDfsFrame {
                    state: target,
                    next_edge: target_edges.start,
                    end_edge: target_edges.end,
                });
            } else {
                let Some(frame) = frames.pop() else {
                    return incomplete_max_match_width(work);
                };
                order.push(frame.state);
            }
        }
    }

    // Transpose traversal in reverse finishing order assigns SCCs.
    let Some(mut component) = analysis_filled(states, usize::MAX, &mut work) else {
        return incomplete_max_match_width(work);
    };
    let mut component_count = 0_usize;
    for &root in order.iter().rev() {
        if component[root] != usize::MAX {
            continue;
        }
        component[root] = component_count;
        stack.push(root);
        while let Some(state) = stack.pop() {
            if !work.charge(1) {
                return incomplete_max_match_width(work);
            }
            let Some(row) = incoming.by_target.get(state) else {
                return incomplete_max_match_width(work);
            };
            for incoming_edge in row {
                if !work.charge(1) {
                    return incomplete_max_match_width(work);
                }
                let Ok(source) = usize::try_from(incoming_edge.source) else {
                    return incomplete_max_match_width(work);
                };
                if !reachable.get(source).copied().unwrap_or(false)
                    || component[source] != usize::MAX
                {
                    continue;
                }
                component[source] = component_count;
                stack.push(source);
            }
        }
        let Some(next_count) = component_count.checked_add(1) else {
            return incomplete_max_match_width(work);
        };
        component_count = next_count;
    }
    if component_count == 0 {
        return incomplete_max_match_width(work);
    }

    let mut component_edges = Vec::new();
    if component_edges.try_reserve_exact(component_count).is_err() {
        work.declined = true;
        return incomplete_max_match_width(work);
    }
    component_edges.resize_with(component_count, Vec::new);
    let Some(mut indegree) = analysis_filled(component_count, 0_usize, &mut work) else {
        return incomplete_max_match_width(work);
    };
    for source in 0..states {
        if !reachable[source] {
            continue;
        }
        let source_component = component[source];
        let Some(source_edges) = analysis_state_edges(raw, source) else {
            return incomplete_max_match_width(work);
        };
        for edge in source_edges {
            if !work.charge(1) {
                return incomplete_max_match_width(work);
            }
            let Ok(target) = usize::try_from(raw.edge_targets[edge]) else {
                return incomplete_max_match_width(work);
            };
            if !reachable.get(target).copied().unwrap_or(false) {
                continue;
            }
            let target_component = component[target];
            let Some(weight) = analysis_edge_weight(raw.edge_kinds[edge]) else {
                return incomplete_max_match_width(work);
            };
            if source_component == target_component {
                if weight != 0 {
                    return unbounded_max_match_width(work);
                }
                continue;
            }
            let Some(row) = component_edges.get_mut(source_component) else {
                return incomplete_max_match_width(work);
            };
            if row.try_reserve(1).is_err() {
                work.declined = true;
                return incomplete_max_match_width(work);
            }
            row.push(WidthComponentEdge {
                target: target_component,
                weight,
            });
            let Some(target_indegree) = indegree.get_mut(target_component) else {
                return incomplete_max_match_width(work);
            };
            let Some(next_indegree) = target_indegree.checked_add(1) else {
                return incomplete_max_match_width(work);
            };
            *target_indegree = next_indegree;
        }
    }

    let Some(mut queue) = analysis_capacity(component_count, &mut work) else {
        return incomplete_max_match_width(work);
    };
    for (id, &degree) in indegree.iter().enumerate() {
        if degree == 0 {
            queue.push(id);
        }
    }
    let Some(mut distances) = analysis_filled(component_count, None, &mut work) else {
        return incomplete_max_match_width(work);
    };
    let start_component = component[start];
    distances[start_component] = Some(0_usize);
    let mut cursor = 0_usize;
    while cursor < queue.len() {
        if !work.charge(1) {
            return incomplete_max_match_width(work);
        }
        let source = queue[cursor];
        cursor = cursor.saturating_add(1);
        let source_distance = distances[source];
        let Some(row) = component_edges.get(source) else {
            return incomplete_max_match_width(work);
        };
        for edge in row {
            if !work.charge(1) {
                return incomplete_max_match_width(work);
            }
            if let Some(distance) = source_distance {
                let Some(candidate) = distance.checked_add(edge.weight) else {
                    return incomplete_max_match_width(work);
                };
                let Some(target_distance) = distances.get_mut(edge.target) else {
                    return incomplete_max_match_width(work);
                };
                if target_distance.is_none_or(|known| candidate > known) {
                    *target_distance = Some(candidate);
                }
            }
            let Some(target_indegree) = indegree.get_mut(edge.target) else {
                return incomplete_max_match_width(work);
            };
            let Some(next_indegree) = target_indegree.checked_sub(1) else {
                return incomplete_max_match_width(work);
            };
            *target_indegree = next_indegree;
            if next_indegree == 0 {
                queue.push(edge.target);
            }
        }
    }
    if queue.len() != component_count {
        return incomplete_max_match_width(work);
    }

    let mut width = None;
    for (state, role) in raw.roles.iter().enumerate() {
        if *role != StateRole::Accept || !reachable[state] {
            continue;
        }
        let Some(distance) = distances[component[state]] else {
            return incomplete_max_match_width(work);
        };
        width = Some(width.map_or(distance, |known: usize| known.max(distance)));
    }
    MaxMatchWidthStats {
        width,
        derivation_work: work.used,
        resource_limited: false,
        unbounded: false,
    }
}

fn deserialize_automaton(
    raw: &RawPlan,
    line_terminator: u8,
) -> Result<Automaton, ProgramFormatError> {
    let validation_work = raw
        .roles
        .len()
        .checked_mul(2)
        .and_then(|states| {
            raw.edge_targets
                .len()
                .checked_mul(2)
                .and_then(|edges| states.checked_add(edges))
        })
        .and_then(|work| work.checked_add(1))
        .ok_or(ProgramFormatError::Malformed(
            "automaton validation work overflowed",
        ))?;
    Ok(Automaton::from_raw(
        clone_raw_fallible(raw)?,
        AutomatonCompileLimits {
            max_states: raw.roles.len(),
            max_edges: raw.edge_targets.len(),
            max_storage_bytes: MAX_SERIALIZED_PROGRAM_BYTES,
            max_validation_work: validation_work,
        },
    )?
    .with_line_terminator(line_terminator))
}

struct ProgramReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> ProgramReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(
        &mut self,
        length: usize,
        truncated: &'static str,
    ) -> Result<&'a [u8], ProgramFormatError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(ProgramFormatError::Malformed("program offset overflowed"))?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ProgramFormatError::Malformed(truncated))?;
        self.cursor = end;
        Ok(value)
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, ProgramFormatError> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| ProgramFormatError::Malformed(field))?,
        ))
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, ProgramFormatError> {
        let bytes = self.take(8, field)?;
        Ok(u64::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| ProgramFormatError::Malformed(field))?,
        ))
    }

    fn usize_u64(&mut self, field: &'static str) -> Result<usize, ProgramFormatError> {
        usize_from_u64(self.u64(field)?, field)
    }

    fn finish(&self) -> Result<(), ProgramFormatError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(ProgramFormatError::Malformed(
                "trailing bytes follow the program",
            ))
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the stable raw-plan wire order is kept in one auditable decoder"
)]
fn deserialize_raw(reader: &mut ProgramReader<'_>) -> Result<RawPlan, ProgramFormatError> {
    let start = reader.u32("raw start state is truncated")?;
    let roles_len = reader.usize_u64("raw role count is truncated")?;
    let offsets_len = reader.usize_u64("raw edge-offset count is truncated")?;
    let targets_len = reader.usize_u64("raw edge-target count is truncated")?;
    let kinds_len = reader.usize_u64("raw edge-kind count is truncated")?;
    let starts_len = reader.usize_u64("raw byte-start count is truncated")?;
    let ends_len = reader.usize_u64("raw byte-end count is truncated")?;

    let raw_payload = roles_len
        .checked_add(
            offsets_len
                .checked_mul(4)
                .ok_or(ProgramFormatError::Malformed(
                    "raw edge-offset byte count overflowed",
                ))?,
        )
        .and_then(|length| {
            targets_len
                .checked_mul(4)
                .and_then(|targets| length.checked_add(targets))
        })
        .and_then(|length| length.checked_add(kinds_len))
        .and_then(|length| length.checked_add(starts_len))
        .and_then(|length| length.checked_add(ends_len))
        .ok_or(ProgramFormatError::Malformed(
            "raw-plan payload length overflowed",
        ))?;
    if raw_payload > reader.bytes.len().saturating_sub(reader.cursor) {
        return Err(ProgramFormatError::Malformed(
            "raw-plan arrays exceed the program extent",
        ));
    }

    let role_bytes = reader.take(roles_len, "raw role table is truncated")?;
    let mut roles = reserve_vec(roles_len, "role")?;
    for &tag in role_bytes {
        roles.push(state_role_from_tag(tag)?);
    }

    let mut edge_offsets = reserve_vec(offsets_len, "edge-offset")?;
    for _ in 0..offsets_len {
        edge_offsets.push(reader.u32("raw edge-offset table is truncated")?);
    }
    let mut edge_targets = reserve_vec(targets_len, "edge-target")?;
    for _ in 0..targets_len {
        edge_targets.push(reader.u32("raw edge-target table is truncated")?);
    }

    let kind_bytes = reader.take(kinds_len, "raw edge-kind table is truncated")?;
    let mut edge_kinds = reserve_vec(kinds_len, "edge-kind")?;
    for &tag in kind_bytes {
        edge_kinds.push(edge_kind_from_tag(tag)?);
    }
    let byte_starts = clone_slice_fallible(
        reader.take(starts_len, "raw byte-start table is truncated")?,
        "byte-start",
    )?;
    let byte_ends = clone_slice_fallible(
        reader.take(ends_len, "raw byte-end table is truncated")?,
        "byte-end",
    )?;

    Ok(RawPlan {
        start,
        roles,
        edge_offsets,
        edge_targets,
        edge_kinds,
        byte_starts,
        byte_ends,
    })
}

fn reserve_vec<T>(capacity: usize, table: &'static str) -> Result<Vec<T>, ProgramFormatError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(capacity)
        .map_err(|_| ProgramFormatError::Allocation(table))?;
    Ok(values)
}

fn clone_slice_fallible<T: Copy>(
    values: &[T],
    table: &'static str,
) -> Result<Vec<T>, ProgramFormatError> {
    let mut copy = reserve_vec(values.len(), table)?;
    copy.extend_from_slice(values);
    Ok(copy)
}

fn clone_raw_fallible(raw: &RawPlan) -> Result<RawPlan, ProgramFormatError> {
    Ok(RawPlan {
        start: raw.start,
        roles: clone_slice_fallible(&raw.roles, "validated role")?,
        edge_offsets: clone_slice_fallible(&raw.edge_offsets, "validated edge-offset")?,
        edge_targets: clone_slice_fallible(&raw.edge_targets, "validated edge-target")?,
        edge_kinds: clone_slice_fallible(&raw.edge_kinds, "validated edge-kind")?,
        byte_starts: clone_slice_fallible(&raw.byte_starts, "validated byte-start")?,
        byte_ends: clone_slice_fallible(&raw.byte_ends, "validated byte-end")?,
    })
}

struct DfaAlphabetShape {
    boundary_classes: usize,
    graph_classes: usize,
    boundary_starts: [bool; 256],
}

impl DfaAlphabetShape {
    const fn construction_classes(&self) -> (usize, usize) {
        (self.boundary_classes, self.graph_classes)
    }
}

fn dfa_alphabet_shape(raw: &RawPlan) -> Result<DfaAlphabetShape, ProgramFormatError> {
    let mut boundary_starts = [false; 256];
    boundary_starts[0] = true;
    for (edge, &kind) in raw.edge_kinds.iter().enumerate() {
        if kind == EdgeKind::ByteRange {
            boundary_starts[usize::from(raw.byte_starts[edge])] = true;
            if let Some(after) = raw.byte_ends[edge].checked_add(1) {
                boundary_starts[usize::from(after)] = true;
            }
        }
    }
    let boundary_classes = boundary_starts.iter().filter(|&&start| start).count();
    if boundary_classes == 0 {
        return Err(ProgramFormatError::Malformed(
            "DFA alphabet has no boundary classes",
        ));
    }
    let graph_classes = crate::dfa::graph_alphabet_class_count(raw, &boundary_starts)?;
    Ok(DfaAlphabetShape {
        boundary_classes,
        graph_classes,
        boundary_starts,
    })
}

fn state_role_from_tag(tag: u8) -> Result<StateRole, ProgramFormatError> {
    match tag {
        0 => Ok(StateRole::Split),
        1 => Ok(StateRole::Consume),
        2 => Ok(StateRole::Accept),
        _ => Err(ProgramFormatError::Malformed("unknown state-role tag")),
    }
}

fn edge_kind_from_tag(tag: u8) -> Result<EdgeKind, ProgramFormatError> {
    match tag {
        0 => Ok(EdgeKind::Epsilon),
        1 => Ok(EdgeKind::ByteRange),
        2 => Ok(EdgeKind::AssertHaystackStart),
        3 => Ok(EdgeKind::AssertHaystackEnd),
        4 => Ok(EdgeKind::AssertLineStartLf),
        5 => Ok(EdgeKind::AssertLineEndLf),
        6 => Ok(EdgeKind::AssertLineStartCrlf),
        7 => Ok(EdgeKind::AssertLineEndCrlf),
        8 => Ok(EdgeKind::AssertWordAscii),
        9 => Ok(EdgeKind::AssertWordAsciiNegate),
        10 => Ok(EdgeKind::AssertWordStartAscii),
        11 => Ok(EdgeKind::AssertWordEndAscii),
        12 => Ok(EdgeKind::AssertWordStartHalfAscii),
        13 => Ok(EdgeKind::AssertWordEndHalfAscii),
        14 => Ok(EdgeKind::AssertWordUnicode),
        15 => Ok(EdgeKind::AssertWordUnicodeNegate),
        16 => Ok(EdgeKind::AssertWordStartUnicode),
        17 => Ok(EdgeKind::AssertWordEndUnicode),
        18 => Ok(EdgeKind::AssertWordStartHalfUnicode),
        19 => Ok(EdgeKind::AssertWordEndHalfUnicode),
        _ => Err(ProgramFormatError::Malformed("unknown edge-kind tag")),
    }
}

fn usize_from_u64(value: u64, field: &'static str) -> Result<usize, ProgramFormatError> {
    usize::try_from(value).map_err(|_| ProgramFormatError::Malformed(field))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, ProgramFormatError> {
    let end = offset
        .checked_add(4)
        .ok_or(ProgramFormatError::Malformed("header offset overflowed"))?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(ProgramFormatError::Malformed("header field is truncated"))?
            .try_into()
            .map_err(|_| ProgramFormatError::Malformed("header field has the wrong width"))?,
    ))
}

fn read_u64_at(bytes: &[u8], offset: usize) -> Result<u64, ProgramFormatError> {
    let end = offset
        .checked_add(8)
        .ok_or(ProgramFormatError::Malformed("header offset overflowed"))?;
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(ProgramFormatError::Malformed("header field is truncated"))?
            .try_into()
            .map_err(|_| ProgramFormatError::Malformed("header field has the wrong width"))?,
    ))
}

fn header_line_terminator(header: &[u8], version: u32) -> Result<u8, ProgramFormatError> {
    match version {
        PROGRAM_FORMAT_VERSION_V1 => {
            if header[14..16] != [0, 0] {
                return Err(ProgramFormatError::Malformed(
                    "V1 program header reserved bytes are non-zero",
                ));
            }
            Ok(DEFAULT_LINE_TERMINATOR)
        }
        PROGRAM_FORMAT_VERSION_V2 => {
            if header[15] != 0 {
                return Err(ProgramFormatError::Malformed(
                    "V2 program header reserved byte is non-zero",
                ));
            }
            Ok(header[14])
        }
        PROGRAM_FORMAT_VERSION_V3 | PROGRAM_FORMAT_VERSION_V4 => Ok(header[14]),
        _ => Err(ProgramFormatError::Malformed(
            "unsupported program format version",
        )),
    }
}

fn header_program_flags(header: &[u8], version: u32) -> Result<u8, ProgramFormatError> {
    match version {
        PROGRAM_FORMAT_VERSION_V1 | PROGRAM_FORMAT_VERSION_V2 => Ok(0),
        PROGRAM_FORMAT_VERSION_V3 => {
            let flags = header[15];
            if flags & !PROGRAM_V3_KNOWN_FLAGS != 0 {
                return Err(ProgramFormatError::Malformed(
                    "V3 program header contains unknown flags",
                ));
            }
            Ok(flags)
        }
        PROGRAM_FORMAT_VERSION_V4 => {
            let flags = header[15];
            if flags & !PROGRAM_KNOWN_FLAGS != 0 {
                return Err(ProgramFormatError::Malformed(
                    "V4 program header contains unknown flags",
                ));
            }
            Ok(flags)
        }
        _ => Err(ProgramFormatError::Malformed(
            "unsupported program format version",
        )),
    }
}

/// Stable SHA-256 identity of a canonical lowered graph and its line semantics.
#[must_use]
pub(crate) fn automaton_digest(raw: &RawPlan, line_terminator: u8) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"FRE-AOT-AUTOMATON-V2\0");
    hash.update([line_terminator]);
    digest_u32(&mut hash, raw.start);
    digest_u64(&mut hash, raw.roles.len());
    for &role in &raw.roles {
        hash.update([role_tag(role)]);
    }
    digest_u64(&mut hash, raw.edge_offsets.len());
    for &offset in &raw.edge_offsets {
        digest_u32(&mut hash, offset);
    }
    digest_u64(&mut hash, raw.edge_targets.len());
    for &target in &raw.edge_targets {
        digest_u32(&mut hash, target);
    }
    digest_u64(&mut hash, raw.edge_kinds.len());
    for &kind in &raw.edge_kinds {
        hash.update([edge_kind_tag(kind)]);
    }
    digest_u64(&mut hash, raw.byte_starts.len());
    hash.update(&raw.byte_starts);
    digest_u64(&mut hash, raw.byte_ends.len());
    hash.update(&raw.byte_ends);
    hash.finalize().into()
}

fn raw_serialized_len(raw: &RawPlan) -> Result<usize, CompileError> {
    let roles = raw.roles.len();
    let offsets = raw
        .edge_offsets
        .len()
        .checked_mul(4)
        .ok_or(CompileError::InternalInvariant(
            "raw edge-offset serialization length overflowed",
        ))?;
    let targets = raw
        .edge_targets
        .len()
        .checked_mul(4)
        .ok_or(CompileError::InternalInvariant(
            "raw edge-target serialization length overflowed",
        ))?;
    let kinds = raw.edge_kinds.len();
    let starts = raw.byte_starts.len();
    let ends = raw.byte_ends.len();
    52_usize
        .checked_add(roles)
        .and_then(|value| value.checked_add(offsets))
        .and_then(|value| value.checked_add(targets))
        .and_then(|value| value.checked_add(kinds))
        .and_then(|value| value.checked_add(starts))
        .and_then(|value| value.checked_add(ends))
        .ok_or(CompileError::InternalInvariant(
            "raw-plan serialization length overflowed",
        ))
}

fn serialize_raw(raw: &RawPlan, bytes: &mut Vec<u8>) {
    put_u32(bytes, raw.start);
    put_u64(bytes, usize_u64(raw.roles.len()));
    put_u64(bytes, usize_u64(raw.edge_offsets.len()));
    put_u64(bytes, usize_u64(raw.edge_targets.len()));
    put_u64(bytes, usize_u64(raw.edge_kinds.len()));
    put_u64(bytes, usize_u64(raw.byte_starts.len()));
    put_u64(bytes, usize_u64(raw.byte_ends.len()));
    bytes.extend(raw.roles.iter().copied().map(role_tag));
    for &offset in &raw.edge_offsets {
        put_u32(bytes, offset);
    }
    for &target in &raw.edge_targets {
        put_u32(bytes, target);
    }
    bytes.extend(raw.edge_kinds.iter().copied().map(edge_kind_tag));
    bytes.extend_from_slice(&raw.byte_starts);
    bytes.extend_from_slice(&raw.byte_ends);
}

const fn role_tag(role: StateRole) -> u8 {
    match role {
        StateRole::Split => 0,
        StateRole::Consume => 1,
        StateRole::Accept => 2,
        _ => u8::MAX,
    }
}

const fn edge_kind_tag(kind: EdgeKind) -> u8 {
    match kind {
        EdgeKind::Epsilon => 0,
        EdgeKind::ByteRange => 1,
        EdgeKind::AssertHaystackStart => 2,
        EdgeKind::AssertHaystackEnd => 3,
        EdgeKind::AssertLineStartLf => 4,
        EdgeKind::AssertLineEndLf => 5,
        EdgeKind::AssertLineStartCrlf => 6,
        EdgeKind::AssertLineEndCrlf => 7,
        EdgeKind::AssertWordAscii => 8,
        EdgeKind::AssertWordAsciiNegate => 9,
        EdgeKind::AssertWordStartAscii => 10,
        EdgeKind::AssertWordEndAscii => 11,
        EdgeKind::AssertWordStartHalfAscii => 12,
        EdgeKind::AssertWordEndHalfAscii => 13,
        EdgeKind::AssertWordUnicode => 14,
        EdgeKind::AssertWordUnicodeNegate => 15,
        EdgeKind::AssertWordStartUnicode => 16,
        EdgeKind::AssertWordEndUnicode => 17,
        EdgeKind::AssertWordStartHalfUnicode => 18,
        EdgeKind::AssertWordEndHalfUnicode => 19,
        _ => u8::MAX,
    }
}

fn digest_u32(hash: &mut Sha256, value: u32) {
    hash.update(value.to_le_bytes());
}

fn digest_u64(hash: &mut Sha256, value: usize) {
    hash.update(usize_u64(value).to_le_bytes());
}

fn usize_u64(value: usize) -> u64 {
    u64::try_from(value).expect("supported targets have at most 64-bit usize")
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use crate::dfa::{DeterminizationResource, DeterminizationStage};
    use fre_automata::{Automaton, CompileLimits};
    use fre_lower::{LowerLimits, OperationSemantics};
    use fre_syntax::{CanonicalPattern, CompatibilityProfile, ParseRequest, RustProfile};

    use super::*;

    fn program(
        pattern: &str,
        output: OutputContract,
        mode: CompileMode,
        determinize: DeterminizeLimits,
    ) -> CompiledProgram {
        program_with_line_terminator(pattern, b'\n', output, mode, determinize)
    }

    fn program_with_line_terminator(
        pattern: &str,
        line_terminator: u8,
        output: OutputContract,
        mode: CompileMode,
        determinize: DeterminizeLimits,
    ) -> CompiledProgram {
        let mut profile = RustProfile::default();
        profile.options.line_terminator = line_terminator;
        let parsed = fre_syntax::parse(ParseRequest::rust(
            pattern.to_owned(),
            CompatibilityProfile::RustBytes(profile),
        ))
        .expect("parse");
        let CanonicalPattern::Rust(parsed) = parsed.pattern else {
            panic!("Rust request returned non-Rust pattern");
        };
        let raw = fre_lower::lower_raw(
            &parsed,
            OperationSemantics::CaptureFree,
            LowerLimits::default(),
        )
        .expect("lower")
        .into_plan();
        let automaton = Automaton::from_raw(raw.clone(), CompileLimits::default())
            .expect("validate")
            .with_line_terminator(line_terminator);
        CompiledProgram::build(raw, automaton, output, mode, determinize).expect("compile")
    }

    fn generated_byte_strings(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        fn extend(
            strings: &mut Vec<Vec<u8>>,
            current: &mut Vec<u8>,
            alphabet: &[u8],
            max_len: usize,
        ) {
            strings.push(current.clone());
            if current.len() == max_len {
                return;
            }
            for &byte in alphabet {
                current.push(byte);
                extend(strings, current, alphabet, max_len);
                current.pop();
            }
        }

        let mut strings = Vec::new();
        extend(&mut strings, &mut Vec::new(), alphabet, max_len);
        strings
    }

    #[test]
    fn resource_fallback_exact_product_is_graph_proved_complete_and_round_trips() {
        let fallback_limits = DeterminizeLimits {
            max_states: 0,
            ..DeterminizeLimits::default()
        };
        let haystacks = generated_byte_strings(b"aZ012x", 4);
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let accelerated = program("a[0-2]Z", output, CompileMode::Optimizing, fallback_limits);
            assert!(
                accelerated
                    .nfa_mandatory_cut
                    .as_ref()
                    .and_then(NfaMandatoryCut::exact_product)
                    .is_some()
            );
            assert!(accelerated.nfa_mandatory_suffix.is_none());
            let serialized = accelerated
                .serialize()
                .expect("serialize exact-product sidecar");
            assert_eq!(serialized[15], PROGRAM_FLAG_NFA_EXACT_PRODUCT);
            let restored =
                CompiledProgram::deserialize(&serialized).expect("restore exact-product sidecar");
            assert!(
                restored
                    .nfa_mandatory_cut
                    .as_ref()
                    .and_then(NfaMandatoryCut::exact_product)
                    .is_some()
            );

            let reference = program(
                "a[0-2]Z",
                output,
                CompileMode::Fast,
                DeterminizeLimits::default(),
            );
            assert!(
                reference
                    .nfa_mandatory_cut
                    .as_ref()
                    .and_then(NfaMandatoryCut::exact_product)
                    .is_none()
            );
            let mut accelerated_workspace = accelerated.prepare_workspace().unwrap();
            assert!(accelerated_workspace.nfa.is_none());
            let mut restored_workspace = restored.prepare_workspace().unwrap();
            assert!(restored_workspace.nfa.is_none());
            let mut reference_workspace = reference.prepare_workspace().unwrap();
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let expected = reference
                            .search_with_workspace(haystack, window, &mut reference_workspace)
                            .unwrap();
                        assert_eq!(
                            accelerated
                                .search_with_workspace(
                                    haystack,
                                    window,
                                    &mut accelerated_workspace,
                                )
                                .unwrap(),
                            expected,
                            "accelerated {output:?}/{haystack:?}/{start}..{end}"
                        );
                        assert_eq!(
                            restored
                                .search_with_workspace(haystack, window, &mut restored_workspace)
                                .unwrap(),
                            expected,
                            "restored {output:?}/{haystack:?}/{start}..{end}"
                        );
                    }
                }
            }
        }

        // Exercise selective columns after the first byte. Candidate starts
        // must remain ordered and window-relative when the primary hit is
        // translated back by a nonzero offset.
        for (pattern, alphabet, max_len, primary_offset) in [
            ("[ab]x", b"abxy".as_slice(), 3, 1_u8),
            ("[ab][01]Z", b"ab01Zx".as_slice(), 3, 2_u8),
        ] {
            let haystacks = generated_byte_strings(alphabet, max_len);
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let accelerated =
                    program(pattern, output, CompileMode::Optimizing, fallback_limits);
                assert_eq!(
                    accelerated
                        .nfa_mandatory_cut
                        .as_ref()
                        .and_then(NfaMandatoryCut::exact_product)
                        .expect("nonzero-offset exact product")
                        .primary_offset,
                    primary_offset
                );
                let reference = program(
                    pattern,
                    output,
                    CompileMode::Fast,
                    DeterminizeLimits::default(),
                );
                let mut accelerated_workspace = accelerated.prepare_workspace().unwrap();
                let mut reference_workspace = reference.prepare_workspace().unwrap();
                for haystack in &haystacks {
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = SearchWindow::new(start, end);
                            assert_eq!(
                                accelerated
                                    .search_with_workspace(
                                        haystack,
                                        window,
                                        &mut accelerated_workspace,
                                    )
                                    .unwrap(),
                                reference
                                    .search_with_workspace(
                                        haystack,
                                        window,
                                        &mut reference_workspace,
                                    )
                                    .unwrap(),
                                "{pattern}/{output:?}/{haystack:?}/{start}..{end}"
                            );
                        }
                    }
                }
            }
        }

        for (pattern, eligible) in [
            ("a", true),
            ("abcdefghijklmnop", true),
            ("abcdefghijklmnopq", false),
            (r"(?-u:[\x00-\xFF])", false),
        ] {
            let compiled = program(
                pattern,
                OutputContract::Span,
                CompileMode::Optimizing,
                fallback_limits,
            );
            assert_eq!(
                compiled
                    .nfa_mandatory_cut
                    .as_ref()
                    .and_then(NfaMandatoryCut::exact_product)
                    .is_some(),
                eligible,
                "{pattern}"
            );
        }

        let correlated = program(
            "(?:ab|cd)",
            OutputContract::Span,
            CompileMode::Optimizing,
            fallback_limits,
        );
        assert!(
            correlated
                .nfa_mandatory_cut
                .as_ref()
                .and_then(NfaMandatoryCut::exact_product)
                .is_none()
        );
        let variable = program(
            "a[0-2]+Z",
            OutputContract::Span,
            CompileMode::Optimizing,
            fallback_limits,
        );
        assert!(
            variable
                .nfa_mandatory_cut
                .as_ref()
                .and_then(NfaMandatoryCut::exact_product)
                .is_none()
        );
    }

    #[test]
    fn ordered_alternation_and_repetition_match_nfa() {
        let cases = [
            ("a|ab", b"zab".as_slice(), Some((1, 2))),
            ("ab|a", b"zab".as_slice(), Some((1, 3))),
            ("a+", b"zaaa".as_slice(), Some((1, 4))),
            ("a+?", b"zaaa".as_slice(), Some((1, 2))),
            ("(?:ab|a)+", b"zababa".as_slice(), Some((1, 6))),
            ("[a-z]+Z", b"12abcZ34".as_slice(), Some((2, 6))),
        ];
        for (pattern, haystack, expected) in cases {
            let dfa = program(
                pattern,
                OutputContract::Span,
                CompileMode::Optimizing,
                DeterminizeLimits::default(),
            );
            let nfa = program(
                pattern,
                OutputContract::Span,
                CompileMode::Fast,
                DeterminizeLimits::default(),
            );
            assert_eq!(dfa.engine_kind(), EngineKind::OrderedDfa, "{pattern}");
            let window = SearchWindow::full(haystack);
            assert_eq!(
                dfa.search(haystack, window).unwrap(),
                MatchResult::Span(expected),
                "{pattern}"
            );
            assert_eq!(
                dfa.search(haystack, window).unwrap(),
                nfa.search(haystack, window).unwrap(),
                "{pattern}"
            );
        }
    }

    #[test]
    fn anchored_prefix_is_bounded_and_derived_only_from_graph_layers() {
        let byte_members = |program: &CompiledProgram, depth: usize, byte: u8| {
            let set = program
                .anchored_prefix
                .sets()
                .get(depth)
                .copied()
                .expect("prefix depth");
            let words = set.words();
            words[usize::from(byte) / 64] & (1_u64 << (usize::from(byte) % 64)) != 0
        };

        let literal_bytes = b"abcdefghijklmnopq";
        let literal = program(
            core::str::from_utf8(literal_bytes).expect("ASCII fixture"),
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(
            literal.anchored_prefix_stats(),
            AnchoredPrefixStats {
                guaranteed_bytes: MAX_ANCHORED_PREFIX_BYTES,
                selective_positions: MAX_ANCHORED_PREFIX_BYTES,
                derivation_work: literal.anchored_prefix_stats().derivation_work,
                resource_limited: false,
                context_assertions: false,
            }
        );
        for (depth, &byte) in literal_bytes[..MAX_ANCHORED_PREFIX_BYTES]
            .iter()
            .enumerate()
        {
            assert!(byte_members(&literal, depth, byte));
            assert!(!byte_members(&literal, depth, byte.wrapping_add(1)));
        }

        let alternation = program(
            "(?:ab|ac)d",
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(alternation.anchored_prefix_stats().guaranteed_bytes, 3);
        assert!(byte_members(&alternation, 0, b'a'));
        assert!(byte_members(&alternation, 1, b'b'));
        assert!(byte_members(&alternation, 1, b'c'));
        assert!(byte_members(&alternation, 2, b'd'));

        // A shorter path makes every later fixed offset unsafe. The first
        // layer remains a conservative union over both paths.
        for pattern in ["a?b", "a*b", "(?:|a)b", "a|bc"] {
            let variable = program(
                pattern,
                OutputContract::SelectedEnd,
                CompileMode::Optimizing,
                DeterminizeLimits::default(),
            );
            assert_eq!(
                variable.anchored_prefix_stats().guaranteed_bytes,
                1,
                "{pattern}"
            );
        }

        let nullable = program(
            "",
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(nullable.anchored_prefix_stats().guaranteed_bytes, 0);

        let asserted = program(
            "^ab",
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        let asserted_stats = asserted.anchored_prefix_stats();
        assert_eq!(asserted_stats.guaranteed_bytes, 2);
        assert_eq!(asserted_stats.selective_positions, 2);
        assert!(byte_members(&asserted, 0, b'a'));
        assert!(byte_members(&asserted, 1, b'b'));
        assert!(asserted_stats.derivation_work > 0);
        assert!(!asserted_stats.resource_limited);
        assert!(asserted_stats.context_assertions);

        let unicode_asserted = program(
            r"\bfoo",
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        let unicode_stats = unicode_asserted.anchored_prefix_stats();
        assert_eq!(unicode_stats.guaranteed_bytes, 3);
        assert_eq!(unicode_stats.selective_positions, 3);
        assert!(unicode_stats.context_assertions);
        assert!(unicode_asserted.context_dfa_stats().is_none());
        for (depth, &byte) in b"foo".iter().enumerate() {
            assert!(byte_members(&unicode_asserted, depth, byte));
        }

        let assertion_only = program(
            r"\A",
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(assertion_only.anchored_prefix_stats().guaranteed_bytes, 0);
        assert!(assertion_only.anchored_prefix_stats().context_assertions);
    }

    #[test]
    fn anchored_suffix_is_bounded_reverse_graph_analysis() {
        let byte_members = |program: &CompiledProgram, depth: usize, byte: u8| {
            program
                .anchored_suffix
                .sets()
                .get(depth)
                .copied()
                .is_some_and(|set| set.contains(byte))
        };

        let literal = program(
            "abcdefghijk",
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(
            literal.anchored_suffix_stats(),
            AnchoredSuffixStats {
                guaranteed_bytes: MAX_ANCHORED_SUFFIX_BYTES,
                selective_positions: MAX_ANCHORED_SUFFIX_BYTES,
                derivation_work: literal.anchored_suffix_stats().derivation_work,
                resource_limited: false,
                context_assertions: false,
            }
        );
        for (depth, &byte) in b"kjihgfed".iter().enumerate() {
            assert!(byte_members(&literal, depth, byte));
            assert!(!byte_members(&literal, depth, byte.wrapping_add(1)));
        }

        let alternation = program(
            "d(?:ab|cb)",
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(alternation.anchored_suffix_stats().guaranteed_bytes, 3);
        assert!(byte_members(&alternation, 0, b'b'));
        assert!(byte_members(&alternation, 1, b'a'));
        assert!(byte_members(&alternation, 1, b'c'));
        assert!(byte_members(&alternation, 2, b'd'));

        let classes = program(
            "[ab][xy]",
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(classes.anchored_suffix_stats().guaranteed_bytes, 2);
        for byte in b"xy" {
            assert!(byte_members(&classes, 0, *byte));
        }
        for byte in b"ab" {
            assert!(byte_members(&classes, 1, *byte));
        }

        let optional = program(
            "ab?c",
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(optional.anchored_suffix_stats().guaranteed_bytes, 2);
        assert!(byte_members(&optional, 0, b'c'));
        assert!(byte_members(&optional, 1, b'a'));
        assert!(byte_members(&optional, 1, b'b'));

        for (pattern, guaranteed) in [("(?:|a)b", 1), ("a{2,4}b", 3), ("", 0), ("a*", 0)] {
            let compiled = program(
                pattern,
                OutputContract::SelectedEnd,
                CompileMode::Optimizing,
                DeterminizeLimits::default(),
            );
            assert_eq!(
                compiled.anchored_suffix_stats().guaranteed_bytes,
                guaranteed,
                "{pattern:?}"
            );
        }

        for pattern in [r"\Aab\z", r"(?m:^ab$)", r"(?-u:\bab\b)", r"\bab\b"] {
            let asserted = program(
                pattern,
                OutputContract::SelectedEnd,
                CompileMode::Optimizing,
                DeterminizeLimits::default(),
            );
            let stats = asserted.anchored_suffix_stats();
            assert_eq!(stats.guaranteed_bytes, 2, "{pattern:?}");
            assert!(stats.context_assertions, "{pattern:?}");
            assert!(byte_members(&asserted, 0, b'b'));
            assert!(byte_members(&asserted, 1, b'a'));
        }

        let native = literal.native_dfa_view().expect("literal native view");
        assert_eq!(
            native.anchored_suffix.sets(),
            literal.anchored_suffix.sets()
        );

        let limited = derive_anchored_suffix_with_limit(&literal.raw, 0);
        assert!(limited.sets().is_empty());
        assert!(limited.stats().resource_limited);
    }

    #[test]
    fn maximum_match_width_proves_bounded_graphs_and_positive_cycles() {
        let bounded = [
            ("", Some(0)),
            ("abc", Some(3)),
            ("a|bc", Some(2)),
            ("a?b?", Some(2)),
            ("a{2,4}", Some(4)),
            ("(?:ab){0,3}", Some(6)),
            (r"\Aab\z", Some(2)),
            (r"(?-u:\bfoo\b)", Some(3)),
            (r"\bfoo\b", Some(3)),
        ];
        for (pattern, expected) in bounded {
            let compiled = program(
                pattern,
                OutputContract::Span,
                CompileMode::Optimizing,
                DeterminizeLimits::default(),
            );
            assert_eq!(compiled.max_match_width(), expected, "{pattern:?}");
            let stats = compiled.max_match_width_stats();
            assert_eq!(stats.width, expected, "{pattern:?}");
            assert!(!stats.resource_limited, "{pattern:?}");
            assert!(!stats.unbounded, "{pattern:?}");
            assert!(stats.derivation_work > 0, "{pattern:?}");
            if let Some(exact) = compiled.exact_match_width() {
                assert_eq!(expected, Some(exact), "{pattern:?}");
            }
            let bytes = compiled.serialize().unwrap();
            let restored = CompiledProgram::deserialize(&bytes).unwrap();
            assert_eq!(restored.max_match_width(), expected, "{pattern:?}");
        }

        for pattern in ["a*", "a+", "(?:ab)*", "(?:a|b)+"] {
            let compiled = program(
                pattern,
                OutputContract::Span,
                CompileMode::Optimizing,
                DeterminizeLimits::default(),
            );
            assert_eq!(compiled.max_match_width(), None, "{pattern:?}");
            let stats = compiled.max_match_width_stats();
            assert!(stats.unbounded, "{pattern:?}");
            assert!(!stats.resource_limited, "{pattern:?}");
        }

        let native = program(
            "a{2,4}",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(
            native
                .native_dfa_view()
                .expect("native view")
                .max_match_width,
            Some(4)
        );
        assert_eq!(native.stats().unwrap().max_match_width, Some(4));

        let limited = derive_max_match_width_with_limit(&native.raw, 0);
        assert_eq!(limited.width, None);
        assert!(limited.resource_limited);
        assert!(!limited.unbounded);
    }

    #[test]
    fn exact_match_width_is_a_graph_proof_and_survives_round_trip() {
        let cases = [
            ("", Some(0)),
            ("abc", Some(3)),
            ("(?:ab|cd)", Some(2)),
            ("[a-z]{4}", Some(4)),
            ("(?:a|b)c", Some(2)),
            (r"\Aab\z", Some(2)),
            (r"(?-u:\bfoo\b)", Some(3)),
            ("Δ", Some(2)),
            ("a{2,4}", None),
            ("a+", None),
            ("(?:ab)*", None),
            ("(?:|a)", None),
            ("a?b?", None),
        ];
        for (pattern, expected) in cases {
            let compiled = program(
                pattern,
                OutputContract::Span,
                CompileMode::Optimizing,
                DeterminizeLimits::default(),
            );
            assert_eq!(compiled.exact_match_width(), expected, "{pattern:?}");
            let restored = CompiledProgram::deserialize(&compiled.serialize().unwrap()).unwrap();
            assert_eq!(restored.exact_match_width(), expected, "{pattern:?}");
        }
    }

    #[test]
    fn generated_accepting_paths_never_escape_the_anchored_prefix_sets() {
        let patterns = [
            "abcd",
            "ab|ac",
            "a?bc",
            "a+b",
            "ab(?:|c)d",
            "(?:ab|a)c",
            "a{2,4}b",
            "(?:ab|cd){1,3}d",
            r"\Aab\z",
            r"(?m:^ab$)",
            r"(?-u:\bab\b)",
            r"\bab\b",
        ];
        let alphabet = [b'a', b'b', b'c', b'd', b'X'];
        let mut haystacks = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..5 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &byte in &alphabet {
                    let mut haystack = prefix.clone();
                    haystack.push(byte);
                    next.push(haystack.clone());
                    haystacks.push(haystack);
                }
            }
            frontier = next;
        }

        for pattern in patterns {
            let compiled = program(
                pattern,
                OutputContract::Span,
                CompileMode::Optimizing,
                DeterminizeLimits::default(),
            );
            for haystack in &haystacks {
                let MatchResult::Span(found) = compiled
                    .search(haystack, SearchWindow::full(haystack))
                    .unwrap()
                else {
                    panic!("span contract changed");
                };
                let Some((0, end)) = found else {
                    continue;
                };
                assert!(
                    compiled.anchored_prefix.sets().len() <= end,
                    "{pattern:?} {haystack:?}"
                );
                for (position, set) in compiled.anchored_prefix.sets().iter().enumerate() {
                    assert!(
                        set.contains(haystack[position]),
                        "{pattern:?} {haystack:?} at {position}"
                    );
                }
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "suffix membership, width bounds, NFA differential, and every search window form one exhaustive proof"
    )]
    fn generated_matches_obey_suffix_sets_and_maximum_width_for_every_window() {
        let patterns = [
            "",
            "ab",
            "a|bc",
            "a?bc",
            "a{2,3}b",
            "(?:ab|c){1,2}",
            "a*",
            r"\Aab\z",
            r"(?m:^ab$)",
            r"(?mR:^ab$)",
            r"(?-u:\bab\b)",
            r"\bab\b",
        ];
        let alphabet = [b'a', b'b', b'c', b'X', b'-', b'\r', b'\n'];
        let mut haystacks = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..3 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &byte in &alphabet {
                    let mut haystack = prefix.clone();
                    haystack.push(byte);
                    next.push(haystack.clone());
                    haystacks.push(haystack);
                }
            }
            frontier = next;
        }

        for pattern in patterns {
            let compiled = program(
                pattern,
                OutputContract::Span,
                CompileMode::Optimizing,
                DeterminizeLimits::default(),
            );
            let reference = program(
                pattern,
                OutputContract::Span,
                CompileMode::Fast,
                DeterminizeLimits::default(),
            );
            let suffix = compiled.anchored_suffix.sets();
            let maximum = compiled.max_match_width();
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let actual = compiled.search(haystack, window).unwrap();
                        let expected = reference.search(haystack, window).unwrap();
                        assert_eq!(
                            actual, expected,
                            "differential {pattern:?}/{haystack:?}/{start}..{end}"
                        );
                        let MatchResult::Span(found) = actual else {
                            panic!("span contract changed");
                        };
                        let Some((match_start, match_end)) = found else {
                            continue;
                        };
                        let width = match_end.checked_sub(match_start).expect("ordered span");
                        if let Some(maximum) = maximum {
                            assert!(
                                width <= maximum,
                                "maximum {pattern:?}/{haystack:?}/{start}..{end}: {width}>{maximum}"
                            );
                        }
                        assert!(
                            suffix.len() <= width,
                            "suffix depth {pattern:?}/{haystack:?}/{start}..{end}"
                        );
                        for (depth, set) in suffix.iter().enumerate() {
                            let position = match_end
                                .checked_sub(depth.saturating_add(1))
                                .expect("proved suffix byte");
                            assert!(
                                set.contains(haystack[position]),
                                "suffix {pattern:?}/{haystack:?}/{start}..{end} at reverse depth {depth}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn all_contracts_and_windows_agree_with_universal_nfa() {
        let patterns = [
            "",
            "a",
            "a|ab",
            "ab|a",
            "a*",
            "a*?",
            "(?:ab|ba){1,3}",
            "[^x]+x",
        ];
        let haystacks: &[&[u8]] = &[b"", b"a", b"zab", b"baaa", b"xxabax", b"nomatch"];
        for pattern in patterns {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let dfa = program(
                    pattern,
                    output,
                    CompileMode::Optimizing,
                    DeterminizeLimits::default(),
                );
                let nfa = program(
                    pattern,
                    output,
                    CompileMode::Fast,
                    DeterminizeLimits::default(),
                );
                for &haystack in haystacks {
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = SearchWindow::new(start, end);
                            assert_eq!(
                                dfa.search(haystack, window).unwrap(),
                                nfa.search(haystack, window).unwrap(),
                                "{pattern:?} {output:?} {haystack:?} {start}..{end}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn assertions_use_context_dfa_while_ordinary_limits_fall_back_to_general_nfa() {
        let asserted = program(
            "(?m:^a)",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(asserted.engine_kind(), EngineKind::OrderedContextDfa);
        assert_eq!(
            asserted.engine_selection_reason(),
            Some(EngineSelectionReason::CompleteContextDfa)
        );
        assert!(asserted.context_dfa_stats().is_some());
        let contextual = asserted
            .context_determinization_report()
            .expect("fresh contextual receipt");
        assert_eq!(contextual.stats, asserted.context_dfa_stats());
        assert_eq!(contextual.decline, None);
        assert_eq!(
            asserted.search(b"\na", SearchWindow::new(1, 2)).unwrap(),
            MatchResult::Span(Some((1, 2)))
        );

        let limited = program(
            "(?:ab|ac|ad)+z",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        assert_eq!(limited.engine_kind(), EngineKind::OrderedNfa);
        assert_eq!(
            limited
                .search(b"xxabacadz", SearchWindow::full(b"xxabacadz"))
                .unwrap(),
            MatchResult::Span(Some((2, 9)))
        );
    }

    #[test]
    fn resource_fallback_mandatory_suffix_is_structural_and_round_trips() {
        let fallback_limits = DeterminizeLimits {
            max_states: 0,
            ..DeterminizeLimits::default()
        };
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let compiled = program(
                "(?:a|bb)q[xz]",
                output,
                CompileMode::Optimizing,
                fallback_limits,
            );
            assert_eq!(compiled.engine_kind(), EngineKind::OrderedNfa);
            assert_eq!(
                compiled.engine_selection_reason(),
                Some(EngineSelectionReason::DeterminizationResourceLimit)
            );
            let accelerator = compiled
                .nfa_mandatory_suffix
                .as_ref()
                .expect("finite selective suffix should construct the sidecar");
            assert_eq!(accelerator.primary_depth, 1);
            assert_eq!(accelerator.primary_bytes[0], b'q');
            assert_eq!(accelerator.maximum_width, Some(4));

            let bytes = compiled.serialize().expect("serialize fallback");
            assert_eq!(
                u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
                PROGRAM_FORMAT_VERSION_V4
            );
            assert_eq!(bytes[15], PROGRAM_FLAG_NFA_MANDATORY_SUFFIX);
            let restored = CompiledProgram::deserialize(&bytes).expect("restore fallback");
            assert_eq!(restored.engine_kind(), EngineKind::OrderedNfa);
            assert!(restored.nfa_mandatory_suffix.is_some());
            assert_eq!(restored.serialize().unwrap(), bytes);

            let fast = program(
                "(?:a|bb)q[xz]",
                output,
                CompileMode::Fast,
                DeterminizeLimits::default(),
            );
            assert_eq!(fast.engine_kind(), EngineKind::OrderedNfa);
            assert!(fast.nfa_mandatory_suffix.is_none());
            let fast_bytes = fast.serialize().expect("serialize fast fallback");
            assert_eq!(fast_bytes[15], 0);
            let restored_fast =
                CompiledProgram::deserialize(&fast_bytes).expect("restore fast fallback");
            assert!(restored_fast.nfa_mandatory_suffix.is_none());
            assert_eq!(restored_fast.serialize().unwrap(), fast_bytes);
        }

        let ineligible = [
            ("", CompileMode::Fast),
            ("a*z", CompileMode::Fast),
            (".{1,64}z", CompileMode::Fast),
            ("[a-z]{1,2}", CompileMode::Fast),
            ("ab", CompileMode::Fast),
            (r"a\bz", CompileMode::Fast),
        ];
        for (pattern, mode) in ineligible {
            let compiled = program(
                pattern,
                OutputContract::Span,
                mode,
                DeterminizeLimits::default(),
            );
            assert_eq!(
                compiled.engine_kind(),
                EngineKind::OrderedNfa,
                "{pattern:?}"
            );
            assert!(
                compiled.nfa_mandatory_suffix.is_none(),
                "ineligible graph unexpectedly admitted: {pattern:?}"
            );
        }

        let dense = program(
            "[^z]{1,7}z",
            OutputContract::Span,
            CompileMode::Optimizing,
            fallback_limits,
        );
        let accelerator = dense.nfa_mandatory_suffix.as_ref().unwrap();
        let haystack = vec![b'z'; 64];
        let mut primary_hits = 0;
        assert_eq!(
            accelerator.next_candidate_endpoint(
                &dense.anchored_suffix,
                &haystack,
                0,
                haystack.len(),
                usize::from(accelerator.minimum_width),
                &mut primary_hits,
            ),
            NfaMandatorySuffixScan::Fallback
        );
        assert!(primary_hits > NFA_SUFFIX_PRIMARY_HIT_CREDIT);
        let mut reference = dense.clone();
        reference.nfa_mandatory_suffix = None;
        assert_eq!(
            dense
                .search(&haystack, SearchWindow::full(&haystack))
                .unwrap(),
            reference
                .search(&haystack, SearchWindow::full(&haystack))
                .unwrap()
        );
    }

    #[test]
    fn resource_fallback_mandatory_cut_is_structural_and_round_trips() {
        let fallback_limits = DeterminizeLimits {
            max_states: 0,
            ..DeterminizeLimits::default()
        };
        let pattern = "(?:x|yz)7[A-Za-z]+";
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let compiled = program(pattern, output, CompileMode::Optimizing, fallback_limits);
            assert_eq!(compiled.engine_kind(), EngineKind::OrderedNfa);
            assert!(compiled.nfa_mandatory_suffix.is_none());
            let cut = compiled
                .nfa_mandatory_cut
                .as_ref()
                .expect("selective mandatory interior root should construct a cut");
            assert_eq!(cut.cardinality, 1);
            assert!(cut.has_member(b"no 7 here"));
            assert!(!cut.has_member(b"cut-free window"));

            let bytes = compiled.serialize().expect("serialize cut fallback");
            assert_eq!(bytes[15], PROGRAM_FLAG_NFA_MANDATORY_CUT);
            let restored = CompiledProgram::deserialize(&bytes).expect("restore cut fallback");
            assert!(restored.nfa_mandatory_suffix.is_none());
            assert!(restored.nfa_mandatory_cut.is_some());
            assert_eq!(restored.serialize().unwrap(), bytes);

            let fast = program(
                pattern,
                output,
                CompileMode::Fast,
                DeterminizeLimits::default(),
            );
            assert!(fast.nfa_mandatory_cut.is_none());
            assert_eq!(fast.serialize().unwrap()[15], 0);
        }

        let nullable = program(
            "(?:|(?:x|yz)7[A-Za-z]+)",
            OutputContract::Span,
            CompileMode::Optimizing,
            fallback_limits,
        );
        assert!(nullable.nfa_mandatory_cut.is_none());

        let marginal = program(
            "[ABC]+[QR][0-9]+",
            OutputContract::Span,
            CompileMode::Optimizing,
            fallback_limits,
        );
        assert!(
            marginal.nfa_mandatory_cut.is_none(),
            "an extra pass requires at least a twofold selectivity gain"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "small generated sources, every window, all contracts, wire reconstruction, cycles, assertions, and scanner tiers form one differential proof"
    )]
    fn mandatory_cut_matches_ordered_nfa_for_every_generated_window() {
        let ordinary_fallback = DeterminizeLimits {
            max_states: 0,
            ..DeterminizeLimits::default()
        };
        let context_fallback = DeterminizeLimits {
            max_states: 0,
            ..DeterminizeLimits::default()
        };
        let cases: &[(&str, &[u8], DeterminizeLimits, u16)] = &[
            ("[A-Za-z]+7[0-9]+", b"Aa70!", ordinary_fallback, 1),
            ("[A-Za-z]+[QWER][0-9]+", b"AaQW0!", ordinary_fallback, 4),
            (
                r"(?-u:[A-Za-z]+[\x80-\x83][0-9]+)",
                &[b'A', b'a', 0x80, 0x83, b'0', b'!'],
                ordinary_fallback,
                4,
            ),
            ("(?:x|yz)7[A-Za-z]+", b"xyz7A!", ordinary_fallback, 1),
            ("[ab]*(?:x|yz)7[A-Za-z]+", b"abxyz7A", ordinary_fallback, 1),
            (
                "(?:[A-Z]|[a-z][0-9])[QWER][0-9]+",
                b"Aa0QW9!",
                ordinary_fallback,
                4,
            ),
            (
                r"(?-u:(?:[A-Z]|[a-z][0-9])[\x80-\x83][0-9]+)",
                &[b'A', b'a', b'0', 0x80, 0x83, b'9', 0xff],
                ordinary_fallback,
                4,
            ),
            (
                r"(?m:(?:^[A-Z]|[a-z][0-9]))7[A-Za-z]+",
                b"Aa07Z\n!",
                context_fallback,
                1,
            ),
        ];

        for &(pattern, alphabet, limits, expected_cardinality) in cases {
            let haystacks = generated_byte_strings(alphabet, 3);
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let accelerated = program(pattern, output, CompileMode::Optimizing, limits);
                assert_eq!(
                    accelerated.engine_kind(),
                    EngineKind::OrderedNfa,
                    "{pattern:?}"
                );
                assert!(accelerated.nfa_mandatory_suffix.is_none(), "{pattern:?}");
                assert_eq!(
                    accelerated
                        .nfa_mandatory_cut
                        .as_ref()
                        .unwrap_or_else(|| panic!("missing cut for {pattern:?}"))
                        .cardinality,
                    expected_cardinality,
                    "{pattern:?}"
                );
                let restored = CompiledProgram::deserialize(
                    &accelerated.serialize().expect("serialize generated cut"),
                )
                .expect("restore generated cut");
                let mut reference = accelerated.clone();
                reference.nfa_mandatory_cut = None;
                let mut accelerated_workspace = accelerated.prepare_workspace().unwrap();
                let mut restored_workspace = restored.prepare_workspace().unwrap();
                let mut reference_workspace = reference.prepare_workspace().unwrap();

                for haystack in &haystacks {
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = SearchWindow::new(start, end);
                            let expected = reference
                                .search_with_workspace(haystack, window, &mut reference_workspace)
                                .unwrap();
                            assert_eq!(
                                accelerated
                                    .search_with_workspace(
                                        haystack,
                                        window,
                                        &mut accelerated_workspace,
                                    )
                                    .unwrap(),
                                expected,
                                "fresh {pattern:?}/{output:?}/{haystack:?}/{start}..{end}"
                            );
                            assert_eq!(
                                restored
                                    .search_with_workspace(
                                        haystack,
                                        window,
                                        &mut restored_workspace,
                                    )
                                    .unwrap(),
                                expected,
                                "wire {pattern:?}/{output:?}/{haystack:?}/{start}..{end}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the explicit adversarial graph and every-window differential form one proof"
    )]
    fn mandatory_cut_handles_consuming_cycles_and_multiple_accepts() {
        type TestEdge = (u32, EdgeKind, u8, u8);
        let epsilon = |target| (target, EdgeKind::Epsilon, 0, 0);
        let byte = |target, start, end| (target, EdgeKind::ByteRange, start, end);
        let rows: Vec<Vec<TestEdge>> = vec![
            vec![epsilon(1), epsilon(2), epsilon(7)],
            vec![byte(4, b'x', b'x')],
            vec![byte(3, b'y', b'y')],
            vec![byte(4, b'z', b'z')],
            vec![byte(5, b'7', b'7')],
            vec![
                byte(5, b'A', b'Z'),
                byte(6, b'A', b'Z'),
                byte(5, b'a', b'z'),
                byte(8, b'a', b'z'),
            ],
            vec![],
            vec![byte(0, b'p', b'p')],
            vec![],
        ];
        let roles = vec![
            StateRole::Split,
            StateRole::Consume,
            StateRole::Consume,
            StateRole::Consume,
            StateRole::Consume,
            StateRole::Consume,
            StateRole::Accept,
            StateRole::Consume,
            StateRole::Accept,
        ];
        let mut edge_offsets = Vec::with_capacity(rows.len().saturating_add(1));
        let mut edge_targets = Vec::new();
        let mut edge_kinds = Vec::new();
        let mut byte_starts = Vec::new();
        let mut byte_ends = Vec::new();
        edge_offsets.push(0);
        for row in rows {
            for (target, kind, start, end) in row {
                edge_targets.push(target);
                edge_kinds.push(kind);
                byte_starts.push(start);
                byte_ends.push(end);
            }
            edge_offsets.push(u32::try_from(edge_targets.len()).expect("test edge count"));
        }
        let raw = RawPlan {
            start: 0,
            roles,
            edge_offsets,
            edge_targets,
            edge_kinds,
            byte_starts,
            byte_ends,
        };
        let automaton = Automaton::from_raw(raw.clone(), CompileLimits::default())
            .expect("cyclic multi-accept graph validates");
        let accelerated = CompiledProgram::build(
            raw,
            automaton,
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        )
        .expect("compile cyclic multi-accept fallback");
        assert!(accelerated.nfa_mandatory_suffix.is_none());
        assert_eq!(
            accelerated
                .nfa_mandatory_cut
                .as_ref()
                .expect("common consuming dominator")
                .cardinality,
            1
        );
        let restored = CompiledProgram::deserialize(&accelerated.serialize().unwrap()).unwrap();
        let mut reference = accelerated.clone();
        reference.nfa_mandatory_cut = None;
        let mut accelerated_workspace = accelerated.prepare_workspace().unwrap();
        let mut restored_workspace = restored.prepare_workspace().unwrap();
        let mut reference_workspace = reference.prepare_workspace().unwrap();
        for haystack in generated_byte_strings(b"pxyz7Aa", 4) {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    let expected = reference
                        .search_with_workspace(&haystack, window, &mut reference_workspace)
                        .unwrap();
                    assert_eq!(
                        accelerated
                            .search_with_workspace(&haystack, window, &mut accelerated_workspace,)
                            .unwrap(),
                        expected
                    );
                    assert_eq!(
                        restored
                            .search_with_workspace(&haystack, window, &mut restored_workspace)
                            .unwrap(),
                        expected
                    );
                }
            }
        }
    }

    #[test]
    fn mandatory_cut_classifiers_cover_every_block_boundary() {
        let limits = DeterminizeLimits {
            max_states: 0,
            ..DeterminizeLimits::default()
        };
        for (pattern, member, ascii) in [
            ("(?:[A-Z]|[a-z][0-9])[QWER][0-9]+", b'Q', true),
            (r"(?-u:(?:[A-Z]|[a-z][0-9])[\x80-\x83][0-9]+)", 0x80, false),
        ] {
            let compiled = program(
                pattern,
                OutputContract::Exists,
                CompileMode::Optimizing,
                limits,
            );
            let cut = compiled.nfa_mandatory_cut.as_ref().unwrap();
            assert_eq!(
                matches!(cut.scanner, NfaMandatoryCutScanner::Ascii { .. }),
                ascii
            );
            assert_eq!(
                matches!(cut.scanner, NfaMandatoryCutScanner::Full { .. }),
                !ascii
            );
            for length in 0..=96 {
                let miss = vec![b'!'; length];
                assert!(!cut.has_member(&miss), "{pattern:?}/{length}");
                for position in 0..length {
                    let mut hit = miss.clone();
                    hit[position] = member;
                    assert!(
                        cut.has_member(&hit),
                        "{pattern:?}/{length}/hit-at-{position}"
                    );
                }
            }
        }
    }

    #[test]
    fn mandatory_suffix_acceleration_matches_ordered_nfa_for_every_small_window() {
        fn extend_haystacks(
            haystacks: &mut Vec<Vec<u8>>,
            prefix: &mut Vec<u8>,
            alphabet: &[u8],
            remaining: usize,
        ) {
            haystacks.push(prefix.clone());
            if remaining == 0 {
                return;
            }
            for &byte in alphabet {
                prefix.push(byte);
                extend_haystacks(haystacks, prefix, alphabet, remaining - 1);
                prefix.pop();
            }
        }

        let patterns = [
            "(?:a|bb)z",
            "(?:bb|a)z",
            "(?:a|bc)z",
            "..z|.z",
            ".z|..z",
            ".{1,3}z",
            ".{1,3}?z",
            "[ab]{1,3}z",
            "[ab]{1,3}?z",
            "(?:ab|ba){1,2}z",
            "(?:a|ba){1,2}z",
            "(?:a|bb)q[xz]",
        ];
        let fallback_limits = DeterminizeLimits {
            max_states: 0,
            ..DeterminizeLimits::default()
        };
        let mut haystacks = Vec::new();
        extend_haystacks(&mut haystacks, &mut Vec::new(), b"abzx", 4);
        haystacks.extend([
            b"xaaabz".to_vec(),
            b"xababz".to_vec(),
            b"zzabbbzx".to_vec(),
            b"xabxzbbz".to_vec(),
            b"xaqzbbqx".to_vec(),
        ]);

        for pattern in patterns {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let accelerated =
                    program(pattern, output, CompileMode::Optimizing, fallback_limits);
                assert_eq!(
                    accelerated.engine_kind(),
                    EngineKind::OrderedNfa,
                    "{pattern:?}"
                );
                assert!(
                    accelerated.nfa_mandatory_suffix.is_some(),
                    "eligible fixture was declined: {pattern:?}"
                );
                let mut reference = accelerated.clone();
                reference.nfa_mandatory_suffix = None;
                let mut accelerated_workspace = accelerated.prepare_workspace().unwrap();
                let mut reference_workspace = reference.prepare_workspace().unwrap();

                for haystack in &haystacks {
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = SearchWindow::new(start, end);
                            let expected = reference
                                .search_with_workspace(haystack, window, &mut reference_workspace)
                                .unwrap();
                            let actual = accelerated
                                .search_with_workspace(haystack, window, &mut accelerated_workspace)
                                .unwrap();
                            assert_eq!(
                                actual, expected,
                                "{pattern:?}/{output:?}/{haystack:?}/{start}..{end}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn scan_only_mandatory_suffix_is_structural_and_round_trips() {
        let fallback_limits = DeterminizeLimits {
            max_states: 0,
            ..DeterminizeLimits::default()
        };
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let compiled = program(
                "(?:ab|c)*q[xz]",
                output,
                CompileMode::Optimizing,
                fallback_limits,
            );
            assert_eq!(compiled.engine_kind(), EngineKind::OrderedNfa);
            assert!(compiled.max_match_width.width.is_none());
            assert!(compiled.max_match_width.unbounded);
            let accelerator = compiled
                .nfa_mandatory_suffix
                .as_ref()
                .expect("unbounded selective suffix should construct the sidecar");
            assert_eq!(accelerator.primary_depth, 1);
            assert_eq!(accelerator.primary_bytes[0], b'q');
            assert_eq!(accelerator.maximum_width, None);

            let bytes = compiled.serialize().expect("serialize fallback");
            assert_eq!(bytes[15], PROGRAM_FLAG_NFA_MANDATORY_SUFFIX);
            let restored = CompiledProgram::deserialize(&bytes).expect("restore fallback");
            assert!(restored.nfa_mandatory_suffix.is_some());
            assert_eq!(
                restored
                    .nfa_mandatory_suffix
                    .as_ref()
                    .and_then(|sidecar| sidecar.maximum_width),
                None
            );
            assert_eq!(restored.serialize().unwrap(), bytes);
        }

        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let wide = program(".{1,65}z", output, CompileMode::Optimizing, fallback_limits);
            assert!(
                wide.max_match_width
                    .width
                    .is_some_and(|width| width > MAX_NFA_SUFFIX_CANDIDATE_WORK)
            );
            assert_eq!(
                wide.nfa_mandatory_suffix
                    .as_ref()
                    .expect("wide finite suffix should retain the scan-only sidecar")
                    .maximum_width,
                None
            );
            let bytes = wide.serialize().unwrap();
            assert_eq!(bytes[15], PROGRAM_FLAG_NFA_MANDATORY_SUFFIX);
            let restored = CompiledProgram::deserialize(&bytes).unwrap();
            assert_eq!(restored.serialize().unwrap(), bytes);
            for haystack in [
                b"xxxxxxxxxxxxxxxx".as_slice(),
                b"xxxxxxxxxxxxxxxz",
                b"zxxxxxxxxxxxxxxx",
                b"\n\n\n\n\n\n\n\n",
            ] {
                let mut reference = wide.clone();
                reference.nfa_mandatory_suffix = None;
                assert_eq!(
                    wide.search(haystack, SearchWindow::full(haystack)).unwrap(),
                    reference
                        .search(haystack, SearchWindow::full(haystack))
                        .unwrap(),
                    "{output:?}/{haystack:?}"
                );
            }
        }
    }

    #[test]
    fn scan_only_mandatory_suffix_matches_ordered_nfa_for_every_small_window() {
        fn extend_haystacks(
            haystacks: &mut Vec<Vec<u8>>,
            prefix: &mut Vec<u8>,
            alphabet: &[u8],
            remaining: usize,
        ) {
            haystacks.push(prefix.clone());
            if remaining == 0 {
                return;
            }
            for &byte in alphabet {
                prefix.push(byte);
                extend_haystacks(haystacks, prefix, alphabet, remaining - 1);
                prefix.pop();
            }
        }

        let patterns = [
            "a*z",
            "a*?z",
            "(?:ab)*z",
            "(?:ab)*?z",
            "(?:ab|c)*q[xz]",
            "(?:ab|c)*?q[xz]",
            "(?:a|bc)*qz",
            "(?:a|bc)*?qz",
        ];
        let fallback_limits = DeterminizeLimits {
            max_states: 0,
            ..DeterminizeLimits::default()
        };
        let mut haystacks = Vec::new();
        extend_haystacks(&mut haystacks, &mut Vec::new(), b"abqzx", 4);
        haystacks.extend([
            b"aaaaaaaaaz".to_vec(),
            b"ababababqz".to_vec(),
            b"ccccccqz".to_vec(),
            b"zqzxqz".to_vec(),
            b"xxxxxxxx".to_vec(),
        ]);

        for pattern in patterns {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let accelerated =
                    program(pattern, output, CompileMode::Optimizing, fallback_limits);
                assert_eq!(
                    accelerated.engine_kind(),
                    EngineKind::OrderedNfa,
                    "{pattern:?}"
                );
                assert!(
                    accelerated.nfa_mandatory_suffix.is_some(),
                    "eligible unbounded fixture was declined: {pattern:?}"
                );
                assert_eq!(
                    accelerated
                        .nfa_mandatory_suffix
                        .as_ref()
                        .and_then(|sidecar| sidecar.maximum_width),
                    None,
                    "{pattern:?}"
                );
                let restored = CompiledProgram::deserialize(
                    &accelerated
                        .serialize()
                        .expect("serialize scan-only sidecar"),
                )
                .expect("restore scan-only sidecar");
                assert!(restored.nfa_mandatory_suffix.is_some());
                let reference = program(
                    pattern,
                    output,
                    CompileMode::Fast,
                    DeterminizeLimits::default(),
                );
                assert!(reference.nfa_mandatory_suffix.is_none());
                let mut accelerated_workspace = accelerated.prepare_workspace().unwrap();
                let mut restored_workspace = restored.prepare_workspace().unwrap();
                let mut reference_workspace = reference.prepare_workspace().unwrap();

                for haystack in &haystacks {
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = SearchWindow::new(start, end);
                            let expected = reference
                                .search_with_workspace(haystack, window, &mut reference_workspace)
                                .unwrap();
                            let actual = accelerated
                                .search_with_workspace(haystack, window, &mut accelerated_workspace)
                                .unwrap();
                            let restored_actual = restored
                                .search_with_workspace(haystack, window, &mut restored_workspace)
                                .unwrap();
                            assert_eq!(
                                actual, expected,
                                "{pattern:?}/{output:?}/{haystack:?}/{start}..{end}"
                            );
                            assert_eq!(
                                restored_actual, expected,
                                "round trip {pattern:?}/{output:?}/{haystack:?}/{start}..{end}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn scan_only_mandatory_suffix_escapes_adversarial_candidates() {
        let endpoints = [1_025, 2_049, 3_073, 4_097];
        let mut reverse_work = 0;
        for &endpoint in &endpoints[..3] {
            reverse_work =
                NfaMandatorySuffix::next_scan_only_reverse_work(reverse_work, 0, endpoint)
                    .expect("sparse prefix remains inside the linear reverse-work envelope");
        }
        assert!(
            NfaMandatorySuffix::next_scan_only_reverse_work(reverse_work, 0, endpoints[3],)
                .is_none()
        );

        let fallback_limits = DeterminizeLimits {
            max_states: 0,
            ..DeterminizeLimits::default()
        };
        let mut sparse_false_candidates = vec![b'x'; 5_000];
        for endpoint in endpoints {
            sparse_false_candidates[endpoint - 1] = b'z';
        }
        let dense_candidates = vec![b'z'; 4_096];

        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            for (pattern, haystack) in [
                ("[ab]+z", sparse_false_candidates.as_slice()),
                ("[ab]*z", dense_candidates.as_slice()),
            ] {
                let accelerated =
                    program(pattern, output, CompileMode::Optimizing, fallback_limits);
                assert_eq!(
                    accelerated
                        .nfa_mandatory_suffix
                        .as_ref()
                        .and_then(|sidecar| sidecar.maximum_width),
                    None,
                    "{pattern:?}"
                );
                assert!(accelerated.nfa_mandatory_suffix.is_some(), "{pattern:?}");
                let reference = program(
                    pattern,
                    output,
                    CompileMode::Fast,
                    DeterminizeLimits::default(),
                );
                assert_eq!(
                    accelerated
                        .search(haystack, SearchWindow::full(haystack))
                        .unwrap(),
                    reference
                        .search(haystack, SearchWindow::full(haystack))
                        .unwrap(),
                    "{pattern:?}/{output:?}"
                );
            }
        }
    }

    #[test]
    fn ordered_nfa_workspace_uses_the_output_specific_persistent_cache() {
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let program = program(
                "(?:ab|ac|ad)+z",
                output,
                CompileMode::Fast,
                DeterminizeLimits::default(),
            );
            let workspace = program.prepare_workspace().expect("prepare NFA workspace");
            let actual = workspace
                .nfa
                .as_ref()
                .expect("ordered NFA retains K0 storage")
                .layout();
            let expected = match output {
                OutputContract::Exists | OutputContract::SelectedEnd => program
                    .automaton
                    .accelerated_workspace_layout()
                    .expect("endpoint workspace layout"),
                OutputContract::Span => program
                    .automaton
                    .bidirectional_workspace_layout()
                    .expect("bidirectional workspace layout"),
            };
            assert_eq!(actual, expected, "{output:?}");
        }

        let fixed_span = program(
            "(?:ab|cd)",
            OutputContract::Span,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        );
        assert_eq!(fixed_span.exact_match_width, Some(2));
        let workspace = fixed_span
            .prepare_workspace()
            .expect("prepare fixed-width span workspace");
        assert_eq!(
            workspace
                .nfa
                .as_ref()
                .expect("ordered NFA retains K0 storage")
                .layout(),
            fixed_span
                .automaton
                .accelerated_workspace_layout()
                .expect("fixed-width span endpoint layout")
        );
        assert_eq!(
            fixed_span
                .search(b"xxcdyy", SearchWindow::full(b"xxcdyy"))
                .expect("fixed-width fallback search"),
            MatchResult::Span(Some((2, 4)))
        );
    }

    #[test]
    fn ordered_nfa_workspace_remains_usable_by_a_semantically_identical_clone() {
        let original = program(
            "(?:ab|ac|ad)+z",
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        assert_eq!(original.engine_kind(), EngineKind::OrderedNfa);
        let cloned = original.clone();
        let mut workspace = original.prepare_workspace().expect("prepare NFA workspace");
        let haystack = b"xxacadz";
        assert_eq!(
            cloned
                .search_with_workspace(haystack, SearchWindow::full(haystack), &mut workspace)
                .expect("search cloned semantic program"),
            MatchResult::SelectedEnd(Some(haystack.len()))
        );
    }

    #[test]
    fn exact_width_span_omits_reverse_dfa_and_accepts_legacy_redundancy() {
        let optimized = program(
            "abc",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        let stats = optimized.dfa_stats().expect("complete exact-width DFA");
        assert_eq!(optimized.exact_match_width, Some(3));
        assert_eq!(stats.reverse_states, 0);
        assert!(
            !optimized
                .determinization_report()
                .expect("fresh determinization receipt")
                .attempted_stages
                .contains(&DeterminizationStage::ReverseSubsetConstruction)
        );
        assert_eq!(
            optimized
                .search(b"xxabcxx", SearchWindow::full(b"xxabcxx"))
                .expect("exact-width direct search"),
            MatchResult::Span(Some((2, 5)))
        );

        // V2 artifacts emitted before this optimization redundantly retained
        // reverse start recovery for every nonnullable Span. Their presence
        // remains canonical under the old construction choice and must stay
        // readable even though new exact-width artifacts omit it.
        let mut legacy = program(
            "abc",
            OutputContract::Span,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        );
        let legacy_machine = match dfa::determinize(&legacy.raw, true, DeterminizeLimits::default())
            .expect("legacy reverse determinization")
        {
            DeterminizeOutcome::Complete { machine, .. } => machine,
            DeterminizeOutcome::Declined { report, .. } => {
                panic!("legacy reverse determinization declined: {report:?}")
            }
        };
        assert!(legacy_machine.stats().reverse_states > 0);
        legacy.engine = ProgramEngine::OrderedDfa(legacy_machine);
        legacy.engine_selection_reason = Some(EngineSelectionReason::CompleteDfa);
        let restored = CompiledProgram::deserialize(
            &legacy
                .serialize()
                .expect("serialize legacy exact-width DFA"),
        )
        .expect("deserialize legacy exact-width DFA");
        assert!(restored.dfa_stats().unwrap().reverse_states > 0);
        assert_eq!(
            restored
                .search(b"xxabcxx", SearchWindow::full(b"xxabcxx"))
                .expect("legacy exact-width direct search"),
            MatchResult::Span(Some((2, 5)))
        );
    }

    #[test]
    fn default_budget_admits_ordered_subset_permutations_before_minimization() {
        // The overlapping first two classes keep differently ordered search
        // starts alive through the bounded repetition. Complete construction
        // has 131,072 ordered subsets, but graph minimization proves that only
        // 19 forward states are observably distinct. This is a structural
        // regression for the optimizing budget, not a source-identity route.
        let pattern = r"[b-c][a-b]{1,16}z";
        let optimized = program(
            pattern,
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(optimized.engine_kind(), EngineKind::OrderedDfa);
        assert_eq!(
            optimized.engine_selection_reason(),
            Some(EngineSelectionReason::CompleteDfa)
        );
        let stats = optimized.dfa_stats().expect("complete default DFA");
        assert_eq!(stats.forward_states_before_minimization, 131_072);
        assert_eq!(stats.forward_states, 19);
        assert_eq!(stats.reverse_states, 18);
        let report = optimized
            .determinization_report()
            .expect("fresh determinization receipt");
        assert_eq!(report.effective_limits.max_states, 262_144);
        assert_eq!(report.decline, None);

        let limited = program(
            pattern,
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 65_536,
                ..DeterminizeLimits::default()
            },
        );
        assert_eq!(limited.engine_kind(), EngineKind::OrderedNfa);
        assert_eq!(
            limited.engine_selection_reason(),
            Some(EngineSelectionReason::DeterminizationResourceLimit)
        );
        let decline = limited
            .determinization_report()
            .and_then(|report| report.decline)
            .expect("explicit lower state limit must decline");
        assert_eq!(
            decline.stage,
            dfa::DeterminizationStage::ForwardSubsetConstruction
        );
        assert_eq!(
            decline.resource,
            dfa::DeterminizationResource::States {
                limit: 65_536,
                required: 65_537,
            }
        );
        assert_eq!(decline.states_completed, 65_536);
    }

    #[test]
    fn resource_decline_retains_canonical_partial_rows_for_every_contract() {
        // The disjoint terminal alternatives deliberately leave no suffix
        // sidecar eligible, so every missing retained row exercises the
        // authenticated K0 continuation rather than another accelerator.
        let pattern = r"a+Q|[b-c][a-b]{1,5}(?:x+|y+)";
        let limits = DeterminizeLimits {
            max_states: 32,
            ..DeterminizeLimits::default()
        };
        let mut haystacks = generated_byte_strings(&[0, b'a', b'b', b'c', b'x', b'z', 255], 5);
        haystacks.extend([
            b"xxcbbbbxyy".to_vec(),
            b"bbbbbbbbbbbb".to_vec(),
            b"xxbaaaayyy".to_vec(),
            b"aaaQ".to_vec(),
            vec![b'a'; 257],
            {
                let mut value = vec![b'x'; 255];
                value.extend_from_slice(b"cbbbbx");
                value
            },
        ]);
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let partial = program(pattern, output, CompileMode::Optimizing, limits);
            assert_eq!(partial.engine_kind(), EngineKind::OrderedNfa);
            let retained = partial
                .partial_dfa()
                .unwrap_or_else(|| panic!("missing retained rows for {output:?}"));
            let (complete_rows, discovered_states) = retained.retained_dimensions();
            assert!(complete_rows > 0);
            assert!(complete_rows < discovered_states);
            let report = partial.determinization_report().unwrap();
            assert!(report.decline.is_some(), "{output:?}");
            assert!(partial.nfa_mandatory_suffix.is_none(), "{output:?}");

            let bytes = partial.serialize().expect("serialize partial DFA");
            assert_eq!(
                u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
                PROGRAM_FORMAT_VERSION_V4
            );
            assert_ne!(bytes[15] & PROGRAM_FLAG_NFA_PARTIAL_DFA, 0);
            let restored = CompiledProgram::deserialize(&bytes).expect("restore partial DFA");
            assert!(restored.partial_dfa().is_some());
            assert_eq!(restored.serialize().unwrap(), bytes);

            let reference = program(
                pattern,
                output,
                CompileMode::Fast,
                DeterminizeLimits::default(),
            );
            let mut partial_workspace = partial.prepare_workspace().unwrap();
            let mut restored_workspace = restored.prepare_workspace().unwrap();
            let mut reference_workspace = reference.prepare_workspace().unwrap();
            for haystack in &haystacks {
                let haystack = haystack.as_slice();
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        let expected = reference
                            .search_with_workspace(haystack, window, &mut reference_workspace)
                            .unwrap();
                        assert_eq!(
                            partial
                                .search_with_workspace(haystack, window, &mut partial_workspace)
                                .unwrap(),
                            expected,
                            "fresh {output:?} {haystack:?} {start}..{end}"
                        );
                        assert_eq!(
                            restored
                                .search_with_workspace(haystack, window, &mut restored_workspace)
                                .unwrap(),
                            expected,
                            "restored {output:?} {haystack:?} {start}..{end}"
                        );
                    }
                }
            }
            assert!(
                partial_workspace.partial.as_deref().unwrap().state.resumed > 0,
                "fresh {output:?} never exercised stateful K0 resume"
            );
            assert!(
                restored_workspace.partial.as_deref().unwrap().state.resumed > 0,
                "restored {output:?} never exercised stateful K0 resume"
            );
        }
    }

    #[test]
    fn partial_hole_uses_complete_suffix_proof_and_adapts_away_from_redundant_probe() {
        let pattern = r"[b-c][a-b]{1,10}z";
        let limited = program(
            pattern,
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 32,
                ..DeterminizeLimits::default()
            },
        );
        let partial = limited.partial_dfa().expect("retained rows");
        assert!(limited.nfa_mandatory_suffix.is_some());
        let (prefix_plan, supported) = PartialDfaPrefixPlan::derive(limited.anchored_prefix.sets());
        assert!(supported);
        let haystack = b"cbbbbbbbbbbz";
        let resume = match partial
            .selected_end(
                haystack,
                0,
                haystack.len(),
                limited.anchored_prefix.sets(),
                prefix_plan,
            )
            .expect("partial probe")
        {
            PartialDfaResult::Resume(resume) => resume,
            PartialDfaResult::Complete(found) => {
                panic!("test input did not reach a retained hole: {found:?}")
            }
        };
        assert!(resume.position > 0);
        assert!(resume.position < haystack.len());

        let reference = program(
            pattern,
            OutputContract::SelectedEnd,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        );
        let expected = reference
            .search(haystack, SearchWindow::full(haystack))
            .expect("reference search");
        let mut workspace = limited.prepare_workspace().expect("workspace");
        for attempt in 0..2 {
            assert_eq!(
                limited
                    .search_with_workspace(haystack, SearchWindow::full(haystack), &mut workspace,)
                    .expect("accelerated search"),
                expected,
                "attempt {attempt}"
            );
        }
        let state = &workspace.partial.as_deref().unwrap().state;
        assert_eq!(state.resumed, 0);
        assert_eq!(state.consecutive_fallbacks, 2);
        assert!(state.bypass_remaining > 0);
    }

    #[test]
    fn partial_hole_uses_complete_mandatory_cut_proof_and_round_trips() {
        let pattern = r"[b-c][a-b]{1,10}7[A-Za-z]+";
        let limited = program(
            pattern,
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 32,
                ..DeterminizeLimits::default()
            },
        );
        let partial = limited.partial_dfa().expect("retained rows");
        assert!(limited.nfa_mandatory_suffix.is_none());
        assert!(limited.nfa_mandatory_cut.is_some());
        let bytes = limited.serialize().expect("serialize combined sidecars");
        assert_eq!(
            bytes[15],
            PROGRAM_FLAG_NFA_MANDATORY_CUT | PROGRAM_FLAG_NFA_PARTIAL_DFA
        );
        let restored = CompiledProgram::deserialize(&bytes).expect("restore combined sidecars");
        assert!(restored.partial_dfa().is_some());
        assert!(restored.nfa_mandatory_cut.is_some());
        assert_eq!(restored.serialize().unwrap(), bytes);

        let (prefix_plan, supported) = PartialDfaPrefixPlan::derive(limited.anchored_prefix.sets());
        assert!(supported);
        let haystack = b"cbbbbbbbbbbbb";
        let resume = match partial
            .selected_end(
                haystack,
                0,
                haystack.len(),
                limited.anchored_prefix.sets(),
                prefix_plan,
            )
            .expect("partial probe")
        {
            PartialDfaResult::Resume(resume) => resume,
            PartialDfaResult::Complete(found) => {
                panic!("test input did not reach a retained hole: {found:?}")
            }
        };
        assert!(resume.position > 0);

        let reference = program(
            pattern,
            OutputContract::SelectedEnd,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        );
        let expected = reference
            .search(haystack, SearchWindow::full(haystack))
            .expect("reference search");
        let mut workspace = limited.prepare_workspace().expect("workspace");
        for attempt in 0..2 {
            assert_eq!(
                limited
                    .search_with_workspace(haystack, SearchWindow::full(haystack), &mut workspace,)
                    .expect("accelerated search"),
                expected,
                "attempt {attempt}"
            );
        }
        let state = &workspace.partial.as_deref().unwrap().state;
        assert_eq!(state.resumed, 0);
        assert_eq!(state.consecutive_fallbacks, 2);
        assert!(state.bypass_remaining > 0);
    }

    #[test]
    fn partial_cold_payloads_are_indirect_and_absent_without_retained_rows() {
        assert_eq!(
            core::mem::size_of::<Box<PartialDfa>>(),
            core::mem::size_of::<usize>()
        );
        assert_eq!(
            core::mem::size_of::<Option<Box<PartialDfaWorkspace>>>(),
            core::mem::size_of::<usize>()
        );

        let limited = program(
            r"[b-c][a-b]{1,10}7[A-Za-z]+",
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        assert!(limited.partial_dfa().is_none());
        assert!(matches!(limited.engine, ProgramEngine::OrderedNfa));
        let workspace = limited.prepare_workspace().expect("workspace");
        assert!(workspace.partial.is_none());
    }

    #[test]
    fn partial_resume_with_a_foreign_semantic_workspace_falls_back_exactly() {
        let pattern = r"a+Q|[b-c][a-b]{1,10}(?:x+|y+)";
        let limited = program(
            pattern,
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 32,
                ..DeterminizeLimits::default()
            },
        );
        assert!(limited.nfa_mandatory_suffix.is_none());
        let partial = limited.partial_dfa().expect("retained rows");
        let (prefix_plan, supported) = PartialDfaPrefixPlan::derive(limited.anchored_prefix.sets());
        assert!(supported);
        let haystack = b"cbbbbbbbbbbx";
        assert!(matches!(
            partial
                .selected_end(
                    haystack,
                    0,
                    haystack.len(),
                    limited.anchored_prefix.sets(),
                    prefix_plan,
                )
                .expect("partial probe"),
            PartialDfaResult::Resume(_)
        ));

        let reference = program(
            pattern,
            OutputContract::SelectedEnd,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        );
        let expected = reference
            .search(haystack, SearchWindow::full(haystack))
            .expect("reference search");
        let mut foreign_workspace = reference.prepare_workspace().expect("foreign workspace");
        assert!(foreign_workspace.partial.is_none());
        assert_eq!(
            limited
                .search_with_workspace(
                    haystack,
                    SearchWindow::full(haystack),
                    &mut foreign_workspace,
                )
                .expect("exact compatibility fallback"),
            expected
        );
        assert!(foreign_workspace.partial.is_none());
    }

    #[test]
    fn late_partial_hole_resumes_after_the_retained_prefix() {
        let pattern = r"a+Z|[b-c][a-b]{1,16}(?:x+|y+)";
        let limited = program(
            pattern,
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 256,
                ..DeterminizeLimits::default()
            },
        );
        assert!(limited.nfa_mandatory_suffix.is_none());
        let mut haystack = vec![b'a'; 4_096];
        haystack.extend(std::iter::repeat_n(b'b', 24));
        let partial = limited.partial_dfa().expect("retained rows");
        let (prefix_plan, supported) = PartialDfaPrefixPlan::derive(limited.anchored_prefix.sets());
        assert!(supported);
        let resume = match partial
            .selected_end(
                &haystack,
                0,
                haystack.len(),
                limited.anchored_prefix.sets(),
                prefix_plan,
            )
            .expect("partial probe")
        {
            PartialDfaResult::Resume(resume) => resume,
            PartialDfaResult::Complete(found) => {
                panic!("test input did not reach a retained hole: {found:?}")
            }
        };
        assert!(resume.position > 4_096);
        assert_eq!(resume.pending_end, None);

        let reference = program(
            pattern,
            OutputContract::SelectedEnd,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        );
        let expected = reference
            .search(&haystack, SearchWindow::full(&haystack))
            .expect("reference search");
        let mut workspace = limited.prepare_workspace().expect("workspace");
        assert_eq!(
            limited
                .search_with_workspace(&haystack, SearchWindow::full(&haystack), &mut workspace,)
                .expect("resumed search"),
            expected
        );
        assert_eq!(workspace.partial.as_deref().unwrap().state.resumed, 1);
    }

    #[test]
    fn stateful_partial_resume_preserves_pending_priority_for_every_small_window() {
        let patterns = [
            r"(?:a+Q|[b-c][a-b]{1,10}(?:za|z))",
            r"(?:a+Q|[b-c][a-b]{1,10}(?:z[a-b]+|z))",
            r"(?:a+Q|[b-c][a-b]{1,10}(?:z[a-b]+?|z))",
        ];
        let limits = DeterminizeLimits {
            max_states: 32,
            ..DeterminizeLimits::default()
        };
        let mut haystacks = generated_byte_strings(&[b'a', b'b', b'c', b'z'], 5);
        haystacks.extend([
            b"xxcbbbbzxx".to_vec(),
            b"xxcbbbbzayy".to_vec(),
            b"cbbbbzabbx".to_vec(),
            b"cbbbbbbbbbbbb".to_vec(),
            b"xxbaaaaazyy".to_vec(),
            b"aaaQ".to_vec(),
        ]);
        for pattern in patterns {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let partial = program(pattern, output, CompileMode::Optimizing, limits);
                let retained = partial
                    .partial_dfa()
                    .unwrap_or_else(|| panic!("missing partial table for {pattern:?}/{output:?}"));
                let (complete, discovered) = retained.retained_dimensions();
                assert!(complete < discovered, "{pattern:?}/{output:?}");
                assert_eq!(
                    retained.resume_frontier_count(),
                    discovered - complete,
                    "{pattern:?}/{output:?}"
                );
                assert!(
                    partial.nfa_mandatory_suffix.is_none(),
                    "{pattern:?}/{output:?}"
                );
                let reference = program(
                    pattern,
                    output,
                    CompileMode::Fast,
                    DeterminizeLimits::default(),
                );
                let mut partial_workspace = partial.prepare_workspace().unwrap();
                let mut reference_workspace = reference.prepare_workspace().unwrap();
                for haystack in &haystacks {
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = SearchWindow::new(start, end);
                            let expected = reference
                                .search_with_workspace(haystack, window, &mut reference_workspace)
                                .unwrap();
                            assert_eq!(
                                partial
                                    .search_with_workspace(
                                        haystack,
                                        window,
                                        &mut partial_workspace,
                                    )
                                    .unwrap(),
                                expected,
                                "{pattern:?}/{output:?} {haystack:?} {start}..{end}"
                            );
                        }
                    }
                }
                assert!(
                    partial_workspace.partial.as_deref().unwrap().state.resumed > 0,
                    "{pattern:?}/{output:?} never reached a retained hole"
                );
            }
        }
    }

    #[test]
    fn repeated_early_partial_holes_back_off_and_complete_probe_resets() {
        let mut state = PartialDfaRuntimeState {
            prefix_supported: true,
            ..PartialDfaRuntimeState::default()
        };
        assert!(state.admit());
        state.observe_fallback(1, 1_024);
        assert!(state.admit());
        state.observe_fallback(1, 1_024);
        assert_eq!(state.bypass_remaining, 16);
        for _ in 0..16 {
            assert!(!state.admit(), "early-hole bypass interval");
        }
        assert!(state.admit(), "the guard periodically re-probes");
        state.observe_fallback(1, 1_024);
        assert_eq!(state.bypass_remaining, 32);
        for _ in 0..32 {
            assert!(!state.admit());
        }
        assert!(state.admit());
        state.observe_complete();
        assert!(state.admit());
        assert_eq!(state.consecutive_fallbacks, 0);
        assert_eq!(state.bypass_remaining, 0);
    }

    #[test]
    fn partial_dfa_wire_requires_strict_flag_and_canonical_limit_provenance() {
        let compiled = program(
            r"[b-c][a-b]{1,5}z",
            OutputContract::SelectedEnd,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 32,
                ..DeterminizeLimits::default()
            },
        );
        assert!(compiled.partial_dfa().is_some());
        let bytes = compiled.serialize().unwrap();
        assert_ne!(bytes[15] & PROGRAM_FLAG_NFA_PARTIAL_DFA, 0);

        let mut unflagged = bytes.clone();
        unflagged[15] &= !PROGRAM_FLAG_NFA_PARTIAL_DFA;
        assert!(CompiledProgram::deserialize(&unflagged).is_err());

        let mut legacy_flag = bytes.clone();
        legacy_flag[8..12].copy_from_slice(&PROGRAM_FORMAT_VERSION_V3.to_le_bytes());
        assert!(CompiledProgram::deserialize(&legacy_flag).is_err());

        let payload = PROGRAM_HEADER_LEN
            .checked_add(raw_serialized_len(&compiled.raw).unwrap())
            .and_then(|offset| offset.checked_add(8))
            .unwrap();
        let class_count = usize::try_from(u32::from_le_bytes(
            bytes[payload + 24..payload + 28].try_into().unwrap(),
        ))
        .unwrap();
        let state_counts = payload + 284 + class_count;
        let discovered = usize::try_from(u32::from_le_bytes(
            bytes[state_counts..state_counts + 4].try_into().unwrap(),
        ))
        .unwrap();
        let complete = usize::try_from(u32::from_le_bytes(
            bytes[state_counts + 4..state_counts + 8]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        let cell_count = usize::try_from(u64::from_le_bytes(
            bytes[state_counts + 8..state_counts + 16]
                .try_into()
                .unwrap(),
        ))
        .unwrap();
        let resume_count_offset = state_counts + 24;
        let resume_descriptors = resume_count_offset + 8 + cell_count * 8;
        assert!(discovered > complete);

        let mut changed_limit = bytes.clone();
        changed_limit[payload..payload + 8].copy_from_slice(&0_u64.to_le_bytes());
        assert!(CompiledProgram::deserialize(&changed_limit).is_err());

        let mut changed_resume_count = bytes.clone();
        changed_resume_count[resume_count_offset..resume_count_offset + 8]
            .copy_from_slice(&0_u64.to_le_bytes());
        assert!(CompiledProgram::deserialize(&changed_resume_count).is_err());

        let mut changed_pending = bytes.clone();
        let first_descriptor = u32::from_le_bytes(
            changed_pending[resume_descriptors..resume_descriptors + 4]
                .try_into()
                .unwrap(),
        );
        assert_ne!(first_descriptor & 0x7fff_ffff, 0);
        changed_pending[resume_descriptors..resume_descriptors + 4]
            .copy_from_slice(&(first_descriptor ^ (1 << 31)).to_le_bytes());
        assert!(CompiledProgram::deserialize(&changed_pending).is_err());

        let accept = compiled
            .raw
            .roles
            .iter()
            .position(|&role| role == StateRole::Accept)
            .and_then(|state| u32::try_from(state).ok())
            .unwrap();
        let mut changed_item_role = bytes.clone();
        changed_item_role[resume_descriptors + 4..resume_descriptors + 8]
            .copy_from_slice(&accept.to_le_bytes());
        assert!(CompiledProgram::deserialize(&changed_item_role).is_err());

        let mut descriptor = resume_descriptors;
        let mut swappable = None;
        for _ in complete..discovered {
            let encoded = u32::from_le_bytes(bytes[descriptor..descriptor + 4].try_into().unwrap());
            let length = usize::try_from(encoded & 0x7fff_ffff).unwrap();
            if length >= 2 {
                swappable = Some(descriptor + 4);
                break;
            }
            descriptor += 4 + length * 4;
        }
        let first_item = swappable.expect("partial resume payload has a multi-item frontier");
        let mut reordered = bytes;
        let left = reordered[first_item..first_item + 4].to_vec();
        let right = reordered[first_item + 4..first_item + 8].to_vec();
        reordered[first_item..first_item + 4].copy_from_slice(&right);
        reordered[first_item + 4..first_item + 8].copy_from_slice(&left);
        assert!(CompiledProgram::deserialize(&reordered).is_err());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the sidecar, stable-wire, clone, and every-window invariants form one round-trip proof"
    )]
    fn contextual_sidecar_round_trip_retains_wire_fallback_for_all_windows() {
        let patterns = [
            r"(?m:^(?:ab|a)+?b$)",
            r"(?mR:^(?:ab|a)+?b$)",
            r"(?-u:\b(?:foo|fo)+?\b)",
            r"(?:\Aab|(?-u:\bfoo\b))\z",
        ];
        let haystacks: &[&[u8]] = &[
            b"",
            b"ab",
            b"aab",
            b"x\naab\ny",
            b"x\r\naab\r\ny",
            b"foo",
            b"-foo-",
            b"xxab",
        ];
        for pattern in patterns {
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                let optimized = program(
                    pattern,
                    output,
                    CompileMode::Optimizing,
                    DeterminizeLimits::default(),
                );
                let fallback = program(
                    pattern,
                    output,
                    CompileMode::Fast,
                    DeterminizeLimits::default(),
                );
                assert_eq!(
                    optimized.engine_kind(),
                    EngineKind::OrderedContextDfa,
                    "{pattern}"
                );
                assert_eq!(
                    optimized.engine_selection_reason(),
                    Some(EngineSelectionReason::CompleteContextDfa),
                    "{pattern}"
                );
                let stats = optimized
                    .context_dfa_stats()
                    .unwrap_or_else(|| panic!("missing contextual sidecar for {pattern:?}"));
                assert!(stats.alphabet_classes > 0);
                assert!(stats.forward_initial_contexts > 0);
                assert!(stats.forward_states > 0);
                assert!(stats.reverse_initial_contexts > 0);
                assert!(stats.build_work > 0);

                let program_view = optimized
                    .native_context_program_view()
                    .expect("completed sidecar has a contextual program view");
                assert_eq!(program_view.output, output);
                assert_eq!(
                    program_view.anchored_prefix.sets(),
                    optimized.anchored_prefix.sets()
                );
                assert_eq!(
                    program_view.anchored_suffix.sets(),
                    optimized.anchored_suffix.sets()
                );
                assert_eq!(
                    program_view.exact_match_width,
                    optimized.exact_match_width()
                );
                assert_eq!(program_view.max_match_width, optimized.max_match_width());
                let view = optimized
                    .native_context_dfa_view()
                    .expect("completed sidecar has a native view");
                assert_eq!(program_view.dfa.initial_dispatch, view.initial_dispatch);
                assert_eq!(view.class_representatives.len(), stats.alphabet_classes);
                assert_eq!(view.class_properties.len(), stats.alphabet_classes);
                assert_eq!(view.byte_classes.len(), 256);
                assert_eq!(view.forward_initial.len(), stats.forward_initial_contexts);
                assert_eq!(view.forward_states.len(), stats.forward_states);
                assert_eq!(view.forward_cells.len(), stats.forward_transitions);
                assert_eq!(view.reverse_initial.len(), stats.reverse_initial_contexts);
                assert_eq!(view.reverse_cells.len(), stats.reverse_transitions);
                assert_eq!(view.forward_row_offsets.len(), stats.forward_states + 1);
                assert_eq!(view.reverse_row_offsets.len(), stats.reverse_states + 1);
                assert_eq!(
                    usize::try_from(view.initial_dispatch.row_width).unwrap(),
                    stats.row_width
                );
                assert!(view.forward_row_offsets.windows(2).all(|pair| {
                    pair[1].checked_sub(pair[0]) == Some(view.initial_dispatch.row_width)
                }));
                assert!(view.reverse_row_offsets.windows(2).all(|pair| {
                    pair[1].checked_sub(pair[0]) == Some(view.initial_dispatch.row_width)
                }));
                assert!(
                    view.forward_initial
                        .windows(2)
                        .all(|pair| pair[0].context < pair[1].context)
                );
                assert!(
                    view.reverse_initial
                        .windows(2)
                        .all(|pair| pair[0].context < pair[1].context)
                );
                assert_eq!(
                    view.forward_row_offsets.last().copied().map(u64::from),
                    Some(u64::try_from(view.forward_cells.len()).unwrap())
                );
                assert_eq!(
                    view.reverse_row_offsets.last().copied().map(u64::from),
                    Some(u64::try_from(view.reverse_cells.len()).unwrap())
                );

                let bytes = optimized.serialize().unwrap();
                assert_eq!(bytes, fallback.serialize().unwrap(), "{pattern}");
                let restored = CompiledProgram::deserialize(&bytes).unwrap();
                assert_eq!(restored.engine_kind(), EngineKind::OrderedNfa);
                assert_eq!(restored.context_dfa_stats(), None);
                assert_eq!(restored.context_determinization_report(), None);
                assert_eq!(restored.serialize().unwrap(), bytes);

                let cloned = optimized.clone();
                assert_eq!(cloned.context_dfa_stats(), Some(stats));
                for &haystack in haystacks {
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = SearchWindow::new(start, end);
                            let expected = fallback.search(haystack, window).unwrap();
                            assert_eq!(
                                optimized.search(haystack, window).unwrap(),
                                expected,
                                "optimized {pattern:?}/{output:?}/{haystack:?}/{start}..{end}"
                            );
                            assert_eq!(
                                cloned.search(haystack, window).unwrap(),
                                expected,
                                "clone {pattern:?}/{output:?}/{haystack:?}/{start}..{end}"
                            );
                            assert_eq!(
                                restored.search(haystack, window).unwrap(),
                                expected,
                                "restored {pattern:?}/{output:?}/{haystack:?}/{start}..{end}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn contextual_unicode_and_resource_declines_preserve_compiler_eligibility() {
        let cases = [
            (
                r"\b(?:foo|bar)\b",
                DeterminizeLimits::default(),
                "Unicode assertion",
            ),
            (
                r"(?-u:\b(?:foo|bar)\b)",
                DeterminizeLimits {
                    max_states: 0,
                    ..DeterminizeLimits::default()
                },
                "state limit",
            ),
            (
                r"(?m:^(?:foo|bar)$)",
                DeterminizeLimits {
                    max_work: 0,
                    ..DeterminizeLimits::default()
                },
                "work limit",
            ),
            (
                r"(?-u:\b(?:foo|bar)\b)",
                DeterminizeLimits {
                    max_transitions: 0,
                    ..DeterminizeLimits::default()
                },
                "transition limit",
            ),
        ];
        let haystacks: &[&[u8]] = &[b"", b"foo", b"-foo-", b"x\nbar\ny", b"foobar"];
        for (pattern, limits, reason) in cases {
            let optimized = program(
                pattern,
                OutputContract::Span,
                CompileMode::Optimizing,
                limits,
            );
            let fallback = program(
                pattern,
                OutputContract::Span,
                CompileMode::Fast,
                DeterminizeLimits::default(),
            );
            assert_eq!(optimized.engine_kind(), EngineKind::OrderedNfa, "{reason}");
            assert_eq!(
                optimized.engine_selection_reason(),
                Some(EngineSelectionReason::ContextAssertions),
                "{reason}"
            );
            assert_eq!(optimized.context_dfa_stats(), None, "{reason}");
            let contextual = optimized
                .context_determinization_report()
                .unwrap_or_else(|| panic!("missing contextual decline for {reason}"));
            assert_eq!(contextual.stats, None, "{reason}");
            assert!(contextual.decline.is_some(), "{reason}");
            for &haystack in haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        assert_eq!(
                            optimized.search(haystack, window).unwrap(),
                            fallback.search(haystack, window).unwrap(),
                            "{reason}: {pattern:?}/{haystack:?}/{start}..{end}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn equivalent_disjoint_alphabet_columns_are_coalesced() {
        let compiled = program(
            "[a-cx-z]+",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        let stats = compiled.dfa_stats().expect("complete DFA");
        assert!(
            stats.graph_classes < stats.boundary_classes,
            "full edge signatures should merge recurring nonmatching intervals before construction"
        );
        assert!(
            stats.alphabet_classes < stats.graph_classes,
            "whole-machine equivalence should additionally merge matching intervals with distinct edges"
        );

        let reference = program(
            "[a-cx-z]+",
            OutputContract::Span,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        );
        for haystack in [b"".as_slice(), b"---abc---", b"wwwxyz123", b"pqrxayzb"] {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    assert_eq!(
                        compiled.search(haystack, window).unwrap(),
                        reference.search(haystack, window).unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn graph_alphabet_transition_budget_is_exact_and_avoids_boundary_width_fallback() {
        let pattern = "(?:[a-z]|mX)+(?:[D-Z]q|!)?";
        let unrestricted = program(
            pattern,
            OutputContract::Exists,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        let stats = unrestricted.dfa_stats().expect("complete DFA");
        assert!(stats.graph_classes < stats.boundary_classes);
        assert_eq!(stats.reverse_states_before_minimization, 0);
        let construction_states = stats.forward_states_before_minimization;
        let graph_transitions = construction_states
            .checked_mul(stats.graph_classes)
            .expect("small graph transition count");
        let boundary_transitions = construction_states
            .checked_mul(stats.boundary_classes)
            .expect("small boundary transition count");
        assert!(graph_transitions < boundary_transitions);

        let exact_limits = DeterminizeLimits {
            max_transitions: graph_transitions,
            ..DeterminizeLimits::default()
        };
        let exact = program(
            pattern,
            OutputContract::Exists,
            CompileMode::Optimizing,
            exact_limits,
        );
        assert_eq!(exact.engine_kind(), EngineKind::OrderedDfa);
        assert_eq!(exact.dfa_stats(), Some(stats));
        let exact_report = exact
            .determinization_report()
            .expect("fresh determinization report");
        assert_eq!(exact_report.decline, None);
        assert_eq!(exact_report.transitions_completed, graph_transitions);
        let repeated = program(
            pattern,
            OutputContract::Exists,
            CompileMode::Optimizing,
            exact_limits,
        );
        assert_eq!(
            repeated.determinization_report(),
            exact.determinization_report()
        );
        assert_eq!(repeated.serialize().unwrap(), exact.serialize().unwrap());

        let serialized = exact.serialize().unwrap();
        let restored = CompiledProgram::deserialize(&serialized).expect("canonical replay");
        assert_eq!(restored.dfa_stats(), Some(stats));
        assert_eq!(restored.serialize().unwrap(), serialized);

        let below = program(
            pattern,
            OutputContract::Exists,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_transitions: graph_transitions - 1,
                ..DeterminizeLimits::default()
            },
        );
        assert_eq!(below.engine_kind(), EngineKind::OrderedNfa);
        assert_eq!(
            below.engine_selection_reason(),
            Some(EngineSelectionReason::DeterminizationResourceLimit)
        );
        let decline = below
            .determinization_report()
            .and_then(|report| report.decline)
            .expect("transition decline");
        assert_eq!(
            decline.stage,
            DeterminizationStage::ForwardSubsetConstruction
        );
        assert_eq!(
            decline.resource,
            DeterminizationResource::Transitions {
                limit: graph_transitions - 1,
                required: graph_transitions,
            }
        );
        assert_eq!(
            decline.transitions_completed,
            graph_transitions - stats.graph_classes
        );
    }

    #[test]
    fn graph_precoalescing_matches_ordered_nfa_on_generated_windows() {
        let pattern = "(?:[a-z]|mX)+(?:[D-Z]q|!)?";
        let haystacks =
            generated_byte_strings(&[0, b'!', b'A', b'D', b'X', b'Z', b'm', b'n', 255], 3);
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let optimized = program(
                pattern,
                output,
                CompileMode::Optimizing,
                DeterminizeLimits::default(),
            );
            let reference = program(
                pattern,
                output,
                CompileMode::Fast,
                DeterminizeLimits::default(),
            );
            let stats = optimized.dfa_stats().expect("complete DFA");
            assert!(stats.graph_classes < stats.boundary_classes);
            for haystack in &haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = SearchWindow::new(start, end);
                        assert_eq!(
                            optimized.search(haystack, window).unwrap(),
                            reference.search(haystack, window).unwrap(),
                            "{output:?}/{haystack:?}/{start}..{end}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn equivalent_subset_states_are_minimized_without_pattern_recipes() {
        let compiled = program(
            "(?:ab|cb)",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        let stats = compiled.dfa_stats().expect("complete DFA");
        assert!(
            stats.forward_states < stats.forward_states_before_minimization,
            "structurally equivalent continuation states should share one quotient state"
        );

        let reference = program(
            "(?:ab|cb)",
            OutputContract::Span,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        );
        for haystack in [b"".as_slice(), b"ab", b"cb", b"xxcbab", b"ac"] {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    assert_eq!(
                        compiled.search(haystack, window).unwrap(),
                        reference.search(haystack, window).unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn serialization_and_digest_are_stable_and_shape_sensitive() {
        let first = program(
            "(?:ab|ac)+",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        let second = program(
            "(?:ab|ac)+",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(first.serialize().unwrap(), second.serialize().unwrap());
        assert_eq!(
            first.serialized_len().unwrap(),
            first.serialize().unwrap().len()
        );
        let serialized = first.serialize().unwrap();
        let restored = CompiledProgram::deserialize(&serialized).unwrap();
        assert_eq!(restored.serialize().unwrap(), serialized);
        assert_eq!(restored.output_contract(), first.output_contract());
        assert_eq!(restored.engine_kind(), first.engine_kind());
        for haystack in [b"".as_slice(), b"zzabac", b"nomatch"] {
            let window = SearchWindow::full(haystack);
            assert_eq!(
                restored.search(haystack, window).unwrap(),
                first.search(haystack, window).unwrap()
            );
        }
        assert_eq!(
            automaton_digest(&first.raw, first.line_terminator),
            automaton_digest(&second.raw, second.line_terminator)
        );

        let other = program(
            "(?:ab|ad)+",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_ne!(
            automaton_digest(&first.raw, first.line_terminator),
            automaton_digest(&other.raw, other.line_terminator)
        );

        let alternate_terminator = program_with_line_terminator(
            "(?:ab|ac)+",
            b';',
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_ne!(
            automaton_digest(&first.raw, first.line_terminator),
            automaton_digest(
                &alternate_terminator.raw,
                alternate_terminator.line_terminator
            )
        );
    }

    #[test]
    fn assertion_nfa_round_trips_for_every_output_contract() {
        let haystack = b"x\nalpha beta";
        for output in [
            OutputContract::Exists,
            OutputContract::SelectedEnd,
            OutputContract::Span,
        ] {
            let original = program(
                r"(?m:^alpha\b)",
                output,
                CompileMode::Fast,
                DeterminizeLimits::default(),
            );
            assert_eq!(original.engine_kind(), EngineKind::OrderedNfa);
            let bytes = original.serialize().unwrap();
            assert_eq!(
                u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
                PROGRAM_FORMAT_VERSION_V4
            );
            assert_eq!(bytes[14], b'\n');
            assert_eq!(bytes[15], 0);
            assert_eq!(
                CompiledProgram::serialized_len_from_header(&bytes[..PROGRAM_HEADER_LEN]).unwrap(),
                bytes.len()
            );
            let restored = CompiledProgram::deserialize(&bytes).unwrap();
            assert_eq!(restored.serialize().unwrap(), bytes);
            assert_eq!(
                restored
                    .search(haystack, SearchWindow::full(haystack))
                    .unwrap(),
                original
                    .search(haystack, SearchWindow::full(haystack))
                    .unwrap()
            );
        }
    }

    #[test]
    fn v4_nfa_sidecar_flags_are_strict_versioned_and_engine_scoped() {
        let fallback = program(
            "(?:a|bb)q[xz]",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let bytes = fallback.serialize().unwrap();
        assert_eq!(bytes[15], PROGRAM_FLAG_NFA_MANDATORY_SUFFIX);

        let mut unknown = bytes.clone();
        unknown[15] |= 1 << 7;
        assert!(CompiledProgram::deserialize(&unknown).is_err());

        let cut = program(
            "(?:x|yz)7[A-Za-z]+",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let cut_bytes = cut.serialize().unwrap();
        assert_eq!(cut_bytes[15], PROGRAM_FLAG_NFA_MANDATORY_CUT);
        assert!(CompiledProgram::deserialize(&cut_bytes).is_ok());

        let mut contradictory = cut_bytes.clone();
        contradictory[15] = PROGRAM_FLAG_NFA_MANDATORY_SUFFIX | PROGRAM_FLAG_NFA_MANDATORY_CUT;
        assert!(CompiledProgram::deserialize(&contradictory).is_err());
        contradictory[15] = PROGRAM_FLAG_NFA_MANDATORY_SUFFIX | PROGRAM_FLAG_NFA_EXACT_PRODUCT;
        assert!(CompiledProgram::deserialize(&contradictory).is_err());
        contradictory[15] = PROGRAM_FLAG_NFA_MANDATORY_CUT | PROGRAM_FLAG_NFA_EXACT_PRODUCT;
        assert!(CompiledProgram::deserialize(&contradictory).is_err());

        let mut incompatible = program(
            "a*",
            OutputContract::Span,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        )
        .serialize()
        .unwrap();
        incompatible[15] = PROGRAM_FLAG_NFA_MANDATORY_CUT;
        assert!(CompiledProgram::deserialize(&incompatible).is_err());
        incompatible[15] = PROGRAM_FLAG_NFA_EXACT_PRODUCT;
        assert!(CompiledProgram::deserialize(&incompatible).is_err());

        let unbounded = program(
            "(?:ab|c)*q[xz]",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
        );
        let unbounded_bytes = unbounded.serialize().unwrap();
        assert_eq!(unbounded_bytes[15], PROGRAM_FLAG_NFA_MANDATORY_SUFFIX);
        assert!(CompiledProgram::deserialize(&unbounded_bytes).is_ok());

        let mut legacy_v3_partial = bytes;
        legacy_v3_partial[8..12].copy_from_slice(&PROGRAM_FORMAT_VERSION_V3.to_le_bytes());
        legacy_v3_partial[15] |= PROGRAM_FLAG_NFA_PARTIAL_DFA;
        assert!(CompiledProgram::deserialize(&legacy_v3_partial).is_err());

        let dfa = program(
            "(?:ab|ac)+",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(dfa.engine_kind(), EngineKind::OrderedDfa);
        let mut wrong_engine = dfa.serialize().unwrap();
        wrong_engine[15] = PROGRAM_FLAG_NFA_MANDATORY_SUFFIX;
        assert!(CompiledProgram::deserialize(&wrong_engine).is_err());
        wrong_engine[15] = PROGRAM_FLAG_NFA_MANDATORY_CUT;
        assert!(CompiledProgram::deserialize(&wrong_engine).is_err());
        wrong_engine[15] = PROGRAM_FLAG_NFA_EXACT_PRODUCT;
        assert!(CompiledProgram::deserialize(&wrong_engine).is_err());
    }

    #[test]
    fn line_terminator_is_bound_to_v4_header_identity_and_execution() {
        let original = program_with_line_terminator(
            r"(?m:^a$)",
            b';',
            OutputContract::Span,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        );
        let bytes = original.serialize().unwrap();
        assert_eq!(original.line_terminator(), b';');
        assert_eq!(bytes[14], b';');
        assert_eq!(bytes[15], 0);

        let restored = CompiledProgram::deserialize(&bytes).unwrap();
        assert_eq!(restored.line_terminator(), b';');
        assert_eq!(restored.serialize().unwrap(), bytes);
        assert_eq!(
            restored.search(b";a;", SearchWindow::full(b";a;")).unwrap(),
            MatchResult::Span(Some((1, 2)))
        );

        let mut changed_header = bytes;
        changed_header[14] = b'\n';
        let changed = CompiledProgram::deserialize(&changed_header).unwrap();
        assert_eq!(changed.line_terminator(), b'\n');
        assert_eq!(changed.serialize().unwrap(), changed_header);
        assert_eq!(
            changed.search(b";a;", SearchWindow::full(b";a;")).unwrap(),
            MatchResult::Span(None)
        );

        let mut original_workspace = original.prepare_workspace().unwrap();
        assert!(matches!(
            changed.search_with_workspace(
                b";a;",
                SearchWindow::full(b";a;"),
                &mut original_workspace
            ),
            Err(CompileError::InternalInvariant(
                "program workspace belongs to a different semantic program"
            ))
        ));
    }

    #[test]
    fn strict_v1_programs_decode_as_lf_and_reserialize_as_v4() {
        let original = program(
            r"(?m:^a$)",
            OutputContract::Span,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        );
        let mut v1 = original.serialize().unwrap();
        v1[8..12].copy_from_slice(&PROGRAM_FORMAT_VERSION_V1.to_le_bytes());
        v1[14] = 0;
        v1[15] = 0;

        assert_eq!(
            CompiledProgram::serialized_len_from_header(&v1[..PROGRAM_HEADER_LEN]).unwrap(),
            v1.len()
        );
        let restored = CompiledProgram::deserialize(&v1).unwrap();
        assert_eq!(restored.line_terminator(), b'\n');
        assert_eq!(
            restored
                .search(b"\na\n", SearchWindow::full(b"\na\n"))
                .unwrap(),
            MatchResult::Span(Some((1, 2)))
        );

        let v4 = restored.serialize().unwrap();
        assert_eq!(
            u32::from_le_bytes(v4[8..12].try_into().unwrap()),
            PROGRAM_FORMAT_VERSION_V4
        );
        assert_eq!(v4[14], b'\n');
        assert_eq!(v4[15], 0);

        let mut noncanonical_v1 = v1.clone();
        noncanonical_v1[14] = b'\n';
        assert!(CompiledProgram::deserialize(&noncanonical_v1).is_err());
        noncanonical_v1 = v1;
        noncanonical_v1[15] = 1;
        assert!(CompiledProgram::deserialize(&noncanonical_v1).is_err());
    }

    #[test]
    fn strict_v1_ordered_dfa_canonical_upgrades_to_v4_with_identical_semantics() {
        let original = program(
            "(?:ab|a)+?b",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        assert_eq!(original.engine_kind(), EngineKind::OrderedDfa);
        let canonical_v4 = original.serialize().unwrap();
        let mut v1 = canonical_v4.clone();
        v1[8..12].copy_from_slice(&PROGRAM_FORMAT_VERSION_V1.to_le_bytes());
        v1[14] = 0;
        v1[15] = 0;

        let restored = CompiledProgram::deserialize(&v1).unwrap();
        assert_eq!(restored.engine_kind(), EngineKind::OrderedDfa);
        assert_eq!(
            restored.engine_selection_reason(),
            Some(EngineSelectionReason::CompleteDfa)
        );
        assert_eq!(restored.line_terminator(), DEFAULT_LINE_TERMINATOR);
        assert_eq!(restored.dfa_stats(), original.dfa_stats());
        assert_eq!(restored.serialize().unwrap(), canonical_v4);

        for haystack in [
            b"".as_slice(),
            b"a",
            b"ab",
            b"xxaaab",
            b"ababbx",
            b"nomatch",
        ] {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = SearchWindow::new(start, end);
                    assert_eq!(
                        restored.search(haystack, window).unwrap(),
                        original.search(haystack, window).unwrap(),
                        "haystack={haystack:?}, window={start}..{end}"
                    );
                }
            }
        }
    }

    #[test]
    fn deserializer_rejects_headers_counts_tags_graphs_and_trailing_bytes() {
        let nfa = program(
            "(?m:^a)",
            OutputContract::Span,
            CompileMode::Fast,
            DeterminizeLimits::default(),
        );
        let valid = nfa.serialize().unwrap();
        for end in 0..valid.len() {
            assert!(
                CompiledProgram::deserialize(&valid[..end]).is_err(),
                "truncation at {end} was accepted"
            );
        }

        let mut malformed = valid.clone();
        malformed[0] ^= 1;
        assert!(CompiledProgram::deserialize(&malformed).is_err());
        malformed = valid.clone();
        malformed[8..12].copy_from_slice(&5_u32.to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());
        malformed = valid.clone();
        malformed[12] = 9;
        assert!(CompiledProgram::deserialize(&malformed).is_err());
        malformed = valid.clone();
        malformed[13] = 9;
        assert!(CompiledProgram::deserialize(&malformed).is_err());
        malformed = valid.clone();
        malformed[15] = 1 << 7;
        assert!(CompiledProgram::deserialize(&malformed).is_err());
        malformed = valid.clone();
        malformed[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());
        malformed = valid.clone();
        // RawPlan.start is the first body field.
        malformed[PROGRAM_HEADER_LEN..PROGRAM_HEADER_LEN + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            CompiledProgram::deserialize(&malformed),
            Err(ProgramFormatError::Automaton(_))
        ));
        malformed = valid.clone();
        // The six RawPlan counts follow start; an impossible role count must
        // be rejected before any allocation.
        malformed[PROGRAM_HEADER_LEN + 4..PROGRAM_HEADER_LEN + 12]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());
        malformed = valid.clone();
        // Raw tags begin after start plus six u64 counts.
        malformed[PROGRAM_HEADER_LEN + 52] = u8::MAX;
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(CompiledProgram::deserialize(&trailing).is_err());
    }

    #[test]
    fn deserializer_rejects_malformed_dfa_tables() {
        let original = program(
            "(?:ab|ac)+",
            OutputContract::Span,
            CompileMode::Optimizing,
            DeterminizeLimits::default(),
        );
        let valid = original.serialize().unwrap();
        let dfa_start = PROGRAM_HEADER_LEN + raw_serialized_len(&original.raw).unwrap() + 8;
        let class_start = dfa_start + 8;
        let class_count =
            usize::try_from(read_u32_at(&valid, class_start).unwrap()).expect("class count");

        let mut malformed = valid.clone();
        malformed[dfa_start..dfa_start + 8].copy_from_slice(&0_u64.to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        malformed = valid.clone();
        malformed[dfa_start..dfa_start + 8]
            .copy_from_slice(&(crate::dfa::MAX_STABLE_DFA_BUILD_WORK + 1).to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        let canonical_work = read_u64_at(&valid, dfa_start).unwrap();
        assert!(canonical_work < crate::dfa::MAX_STABLE_DFA_BUILD_WORK);
        malformed = valid.clone();
        malformed[dfa_start..dfa_start + 8].copy_from_slice(&(canonical_work + 1).to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        malformed = valid.clone();
        malformed[class_start..class_start + 4].copy_from_slice(&0_u32.to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        malformed = valid.clone();
        malformed[class_start + 4] = u8::MAX;
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        let forward_start = class_start + 4 + 256 + class_count;
        let forward_states =
            usize::try_from(read_u32_at(&valid, forward_start).unwrap()).expect("forward states");
        malformed = valid.clone();
        malformed[forward_start + 4..forward_start + 12].copy_from_slice(&0_u64.to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        malformed = valid.clone();
        malformed[forward_start + 14] = 1;
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        let forward_pre_minimization_states = forward_start + 16;
        malformed = valid.clone();
        malformed[forward_pre_minimization_states..forward_pre_minimization_states + 4]
            .copy_from_slice(&0_u32.to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        let canonical_forward_states =
            read_u32_at(&valid, forward_pre_minimization_states).unwrap();
        malformed = valid.clone();
        malformed[forward_pre_minimization_states..forward_pre_minimization_states + 4]
            .copy_from_slice(&(canonical_forward_states + 1).to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        malformed = valid.clone();
        malformed[forward_pre_minimization_states..forward_pre_minimization_states + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        let first_forward_cell = forward_start + 20;
        malformed = valid.clone();
        malformed[first_forward_cell..first_forward_cell + 4].copy_from_slice(
            &u32::try_from(forward_states)
                .expect("state count")
                .to_le_bytes(),
        );
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        // This mutation preserves every table shape and cell bound. Canonical
        // regeneration must still reject its changed transition semantics.
        malformed = valid.clone();
        malformed[first_forward_cell + 4] ^= 1;
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        // Tiny artifacts with self-consistent enormous dimensions must fail
        // their wire-extent preflight before attempting table allocation.
        let enormous_states = u32::MAX;
        let enormous_cells =
            u64::from(enormous_states) * u64::try_from(class_count).expect("class count fits u64");
        malformed = valid.clone();
        malformed[forward_start..forward_start + 4].copy_from_slice(&enormous_states.to_le_bytes());
        malformed[forward_start + 4..forward_start + 12]
            .copy_from_slice(&enormous_cells.to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        let original_forward_cells =
            usize::try_from(read_u64_at(&valid, forward_start + 4).unwrap())
                .expect("forward cell count");
        let reverse_start = forward_start + 20 + original_forward_cells * 8;
        malformed = valid.clone();
        malformed[reverse_start..reverse_start + 4].copy_from_slice(&enormous_states.to_le_bytes());
        malformed[reverse_start + 4..reverse_start + 12]
            .copy_from_slice(&enormous_cells.to_le_bytes());
        malformed[reverse_start + 12] = 1;
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        malformed = valid.clone();
        malformed[reverse_start + 16..reverse_start + 20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());

        malformed = valid.clone();
        malformed[forward_start + 4..forward_start + 12].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(CompiledProgram::deserialize(&malformed).is_err());
    }

    #[test]
    fn malformed_byte_fuzz_never_bypasses_canonical_round_trip() {
        let seeds = [
            program(
                "(?m:^a)",
                OutputContract::Span,
                CompileMode::Fast,
                DeterminizeLimits::default(),
            )
            .serialize()
            .unwrap(),
            program(
                "(?:ab|ac)+",
                OutputContract::Span,
                CompileMode::Optimizing,
                DeterminizeLimits::default(),
            )
            .serialize()
            .unwrap(),
        ];
        for seed in seeds {
            for index in 0..seed.len() {
                let mut candidate = seed.clone();
                candidate[index] ^= 1_u8 << (index % 8);
                if let Ok(decoded) = CompiledProgram::deserialize(&candidate) {
                    let canonical = decoded.serialize().unwrap();
                    let reparsed = CompiledProgram::deserialize(&canonical).unwrap();
                    assert_eq!(reparsed.serialize().unwrap(), canonical);
                }
            }
        }

        let mut state = 0x6a09_e667_f3bc_c909_u64;
        for length in 0..512 {
            let mut candidate = Vec::with_capacity(length);
            for _ in 0..length {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                candidate.push(state.to_le_bytes()[0]);
            }
            if let Ok(decoded) = CompiledProgram::deserialize(&candidate) {
                let canonical = decoded.serialize().unwrap();
                let reparsed = CompiledProgram::deserialize(&canonical).unwrap();
                assert_eq!(reparsed.serialize().unwrap(), canonical);
            }
        }
    }

    #[test]
    fn invalid_window_is_rejected_before_engine_execution() {
        for mode in [CompileMode::Fast, CompileMode::Optimizing] {
            let compiled = program(
                "a+",
                OutputContract::Span,
                mode,
                DeterminizeLimits::default(),
            );
            assert!(matches!(
                compiled.search(b"abc", SearchWindow::new(3, 2)),
                Err(CompileError::InvalidWindow { .. })
            ));
            assert!(matches!(
                compiled.search(b"abc", SearchWindow::new(0, 4)),
                Err(CompileError::InvalidWindow { .. })
            ));
        }
    }
}
