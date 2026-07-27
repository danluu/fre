//! Complete bounded candidate streams for one or more non-empty byte literals.
//!
//! A single unbordered literal uses `memchr`'s reusable worst-case-linear
//! Two-Way finder. Bordered and multi-literal languages use an owned sparse
//! trie restarted at each byte start. The latter is Aho-Corasick-equivalent
//! as a complete fixed-program candidate source while keeping every
//! allocation and comparison visible to this crate's accounting.

use core::{fmt, mem};

use fre_exact_alloc::{CopyError, ExactVec};
use memchr::memmem::{Finder, FinderBuilder, Prefilter};

use crate::{
    Window,
    literal_anchor::{CandidateEmissionOrder, LiteralCandidate},
};

/// Stable identity of these syntax-independent byte candidate primitives.
pub const PLAN_ID: &str = "literal-candidate-stream.byte.v2";

const NONE: usize = usize::MAX;
const CANDIDATE_WORK: usize = 2;
// memchr 2.8.3 dispatches widths 2..=32 to its packed-pair engine. Above that
// threshold with `Prefilter::None`, its documented scalar Two-Way path makes
// two maximal-suffix passes, one byte-set pass, and bounded period/pair/hash
// passes. These deliberately loose charges dominate those finite passes.
const TWOWAY_MIN_WIDTH: usize = 33;
const TWOWAY_PATTERN_READS_PER_BYTE: usize = 16;
const TWOWAY_BUILD_WORK_PER_BYTE: usize = 32;
const TWOWAY_BUILD_FIXED_WORK: usize = 64;
// Scalar Two-Way uses at most two comparison reads plus one byte-set probe
// per consumed haystack byte; four leaves one full linear term of slack.
const TWOWAY_SCAN_READS_PER_BYTE: usize = 4;

/// Structurally selected complete candidate algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// One unbordered literal searched by a reusable Two-Way finder.
    TwoWay,
    /// Exact-allocation sparse trie restarted at each byte start.
    SparseTrie,
}

/// Why this primitive requires the integrating dense semantic executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenseFallbackReason {
    /// No required literal was supplied.
    EmptyLanguage,
    /// Empty literals require operation-specific empty-match progress.
    EmptyLiteral { pattern_index: usize },
}

/// Source-independent terminal fallback disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenseFallback {
    reason: DenseFallbackReason,
    accounting: BuildAccounting,
}

impl DenseFallback {
    /// Exact structural reason for the disposition.
    #[must_use]
    pub const fn reason(self) -> DenseFallbackReason {
        self.reason
    }

    /// Prospective construction envelope; fallback performs no allocation.
    #[must_use]
    pub const fn build_accounting(self) -> BuildAccounting {
        self.accounting
    }
}

/// Construction either admits one immutable stream or selects dense fallback.
#[derive(Debug)]
pub enum BuildAttempt {
    /// A bounded candidate stream was constructed.
    Admitted(ByteCandidatePlan),
    /// Candidate semantics belong to the later dense executor.
    DenseFallback(DenseFallback),
}

/// Construction-resource dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildResource {
    Patterns,
    PatternBytes,
    PatternByteReads,
    States,
    Transitions,
    Outputs,
    Work,
    PersistentBytes,
    PeakBytes,
    Allocations,
}

/// Caller-selected construction limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_patterns: usize,
    pub max_pattern_bytes: usize,
    pub max_pattern_byte_reads: usize,
    pub max_states: usize,
    pub max_transitions: usize,
    pub max_outputs: usize,
    pub max_work: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
    pub max_allocations: usize,
}

impl BuildLimits {
    /// Disable caller-selected limits; arithmetic remains checked.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_patterns: usize::MAX,
            max_pattern_bytes: usize::MAX,
            max_pattern_byte_reads: usize::MAX,
            max_states: usize::MAX,
            max_transitions: usize::MAX,
            max_outputs: usize::MAX,
            max_work: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
            max_allocations: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_patterns: 4_096,
            max_pattern_bytes: 32 << 20,
            max_pattern_byte_reads: 256 << 20,
            max_states: 32 << 20,
            max_transitions: 32 << 20,
            max_outputs: 4_096,
            max_work: 512 << 20,
            max_persistent_bytes: 512 << 20,
            max_peak_bytes: 512 << 20,
            max_allocations: 3,
        }
    }
}

/// Prospective envelopes and completed construction counters.
///
/// Persistent-byte fields count the inline plan plus exact retained heap
/// capacities. For an unbordered singleton, the prospective fields
/// conservatively cover either structural outcome because every limit is
/// published before the border proof reads a pattern byte. Dependency-owned
/// Two-Way preprocessing is represented by a conservative fixed per-byte
/// charge; sparse-trie work is observed operation by operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub algorithm: Algorithm,
    pub patterns: usize,
    pub pattern_bytes: usize,
    pub pattern_byte_reads_upper_bound: usize,
    pub states_upper_bound: usize,
    pub transitions_upper_bound: usize,
    pub outputs_upper_bound: usize,
    pub max_pattern_bytes: usize,
    pub work_upper_bound: usize,
    pub persistent_bytes_upper_bound: usize,
    pub peak_bytes_upper_bound: usize,
    pub allocations_upper_bound: usize,
    pub pattern_byte_reads: usize,
    pub states: usize,
    pub transitions: usize,
    pub outputs: usize,
    pub work: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
    pub allocations: usize,
}

/// Typed candidate construction failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    Resource {
        resource: BuildResource,
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AllocationFailed {
        structure: &'static str,
        items: usize,
    },
    Invariant {
        detail: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "byte candidate construction failed: {self:?}")
    }
}

impl std::error::Error for BuildError {}

/// Runtime-resource dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanResource {
    InputBytes,
    CandidateStarts,
    SourceByteReads,
    TransitionProbes,
    CandidateEvents,
    Work,
    ScratchBytes,
}

/// Complete source-independent envelope for one scan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanUpperBounds {
    pub input_bytes: usize,
    pub candidate_starts: usize,
    pub source_byte_reads: usize,
    pub transition_probes: usize,
    pub candidate_events: usize,
    pub work: usize,
    pub scratch_bytes: usize,
}

/// Actual structural counters committed by one scan.
///
/// The dependency-owned Two-Way loop exposes occurrences but not individual
/// byte inspections. Its successful receipt therefore charges a conservative
/// four source-read units per input byte as actual work. The route is pinned
/// to scalar Two-Way by admitting only widths above the dependency's packed
/// threshold and disabling its prefilter. Sparse-trie counters are observed
/// directly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanActual {
    pub input_bytes: usize,
    pub candidate_starts: usize,
    pub source_byte_reads: usize,
    pub transition_probes: usize,
    pub candidate_events: usize,
    pub work: usize,
    pub scratch_bytes: usize,
}

/// Successful full-scan receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanReceipt {
    pub upper: ScanUpperBounds,
    pub actual: ScanActual,
}

/// Caller-selected scan limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanLimits {
    pub max_input_bytes: usize,
    pub max_candidate_starts: usize,
    pub max_source_byte_reads: usize,
    pub max_transition_probes: usize,
    pub max_candidate_events: usize,
    pub max_work: usize,
    pub max_scratch_bytes: usize,
}

impl ScanLimits {
    /// Disable caller-selected limits.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_candidate_starts: usize::MAX,
            max_source_byte_reads: usize::MAX,
            max_transition_probes: usize::MAX,
            max_candidate_events: usize::MAX,
            max_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
        }
    }
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 128 << 20,
            max_candidate_starts: 128 << 20,
            max_source_byte_reads: 1 << 30,
            max_transition_probes: 1 << 30,
            max_candidate_events: 512 << 20,
            max_work: 2 << 30,
            max_scratch_bytes: 0,
        }
    }
}

/// Checked preflight or internal scan failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScanError {
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    Resource {
        resource: ScanResource,
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    Invariant {
        detail: &'static str,
    },
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "byte candidate scan failed: {self:?}")
    }
}

impl std::error::Error for ScanError {}

/// Failure receipt. Limit failures occur before source access and therefore
/// carry zero actual counters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanAttemptError {
    pub source: ScanError,
    pub actual: ScanActual,
}

impl fmt::Display for ScanAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, formatter)
    }
}

impl std::error::Error for ScanAttemptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Node {
    first_edge: usize,
    first_output: usize,
    last_output: usize,
}

impl Node {
    const EMPTY: Self = Self {
        first_edge: NONE,
        first_output: NONE,
        last_output: NONE,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Edge {
    byte: u8,
    target: usize,
    next: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Output {
    pattern_index: usize,
    width: usize,
    next: usize,
}

#[derive(Debug)]
struct SparseTrie {
    nodes: ExactVec<Node>,
    edges: ExactVec<Edge>,
    outputs: ExactVec<Output>,
}

#[derive(Debug)]
enum Engine {
    TwoWay {
        finder: Finder<'static>,
        width: usize,
    },
    SparseTrie(SparseTrie),
}

/// Immutable complete byte-literal candidate stream.
#[derive(Debug)]
pub struct ByteCandidatePlan {
    engine: Engine,
    build: BuildAccounting,
}

impl ByteCandidatePlan {
    /// Structurally select and construct a complete candidate stream.
    ///
    /// Inputs are concrete byte slices: no syntax parser, metadata, source
    /// fixture, expected value, hash, or timing signal is visible here.
    /// Every limit is enforced before a pattern byte is inspected or a
    /// persistent allocation is attempted.
    ///
    /// # Errors
    ///
    /// Returns checked construction-resource, arithmetic, allocation, or
    /// internal-invariant failures.
    pub fn build(patterns: &[&[u8]], limits: BuildLimits) -> Result<BuildAttempt, BuildError> {
        let fallback = if patterns.is_empty() {
            Some(DenseFallbackReason::EmptyLanguage)
        } else {
            patterns
                .iter()
                .enumerate()
                .find(|(_, pattern)| pattern.is_empty())
                .map(|(pattern_index, _)| DenseFallbackReason::EmptyLiteral { pattern_index })
        };
        let prospective = preflight_from_lengths(patterns)?;
        enforce_build_limits(prospective, limits)?;
        if let Some(reason) = fallback {
            return Ok(BuildAttempt::DenseFallback(DenseFallback {
                reason,
                accounting: prospective,
            }));
        }

        let mut pattern_byte_reads = 0_usize;
        let mut classification_work = 0_usize;
        let use_two_way = patterns.len() == 1
            && patterns[0].len() >= TWOWAY_MIN_WIDTH
            && is_unbordered(
                patterns[0],
                &mut pattern_byte_reads,
                &mut classification_work,
            )?;

        let (engine, mut actual) = if use_two_way {
            build_two_way(
                patterns[0],
                prospective,
                pattern_byte_reads,
                classification_work,
            )?
        } else {
            build_sparse_trie(
                patterns,
                prospective,
                pattern_byte_reads,
                classification_work,
            )?
        };
        actual.algorithm = if use_two_way {
            Algorithm::TwoWay
        } else {
            Algorithm::SparseTrie
        };
        if !build_actual_within(actual) {
            return Err(BuildError::Invariant {
                detail: "byte candidate construction actual exceeded prospective",
            });
        }
        Ok(BuildAttempt::Admitted(Self {
            engine,
            build: actual,
        }))
    }

    /// Selected implementation.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.build.algorithm
    }

    /// Increasing start, then end, then source pattern index.
    #[must_use]
    pub const fn emission_order(&self) -> CandidateEmissionOrder {
        CandidateEmissionOrder::StartEndPattern
    }

    /// Construction certificate.
    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    /// Derive the complete scan envelope from a byte length only.
    ///
    /// # Errors
    ///
    /// Returns a checked arithmetic error.
    pub fn scan_upper_bounds(&self, input_bytes: usize) -> Result<ScanUpperBounds, ScanError> {
        let candidate_events = match &self.engine {
            Engine::TwoWay { width, .. } => occurrence_ceiling(input_bytes, *width)?,
            Engine::SparseTrie(trie) => {
                trie.outputs.iter().try_fold(0_usize, |total, output| {
                    total
                        .checked_add(occurrence_ceiling(input_bytes, output.width)?)
                        .ok_or(ScanError::ArithmeticOverflow {
                            computation: "sparse-trie candidate events",
                        })
                })?
            }
        };
        let candidate_starts = input_bytes;
        let (source_byte_reads, transition_probes) = match &self.engine {
            Engine::TwoWay { .. } => (
                checked_scan_mul(
                    input_bytes,
                    TWOWAY_SCAN_READS_PER_BYTE,
                    "Two-Way charged source reads",
                )?,
                0,
            ),
            Engine::SparseTrie(_) => {
                let reads = checked_scan_mul(
                    candidate_starts,
                    self.build.max_pattern_bytes,
                    "sparse-trie source byte reads",
                )?;
                let probes = checked_scan_mul(
                    reads,
                    self.build.transitions,
                    "sparse-trie transition probes",
                )?;
                (reads, probes)
            }
        };
        let event_work =
            checked_scan_mul(candidate_events, CANDIDATE_WORK, "candidate event work")?;
        let work = candidate_starts
            .checked_add(source_byte_reads)
            .and_then(|sum| sum.checked_add(transition_probes))
            .and_then(|sum| sum.checked_add(event_work))
            .ok_or(ScanError::ArithmeticOverflow {
                computation: "byte candidate scan work",
            })?;
        Ok(ScanUpperBounds {
            input_bytes,
            candidate_starts,
            source_byte_reads,
            transition_probes,
            candidate_events,
            work,
            scratch_bytes: 0,
        })
    }

    /// Emit every candidate wholly inside `window`.
    ///
    /// All limits are checked before the searched slice is formed. Once
    /// admitted, this method completes the selected stream and never changes
    /// algorithm or asks a caller to restart on a fallback.
    ///
    /// # Errors
    ///
    /// Returns a checked range/resource receipt before source access, or an
    /// internal checked-accounting receipt if an invariant fails.
    pub fn scan_window<F>(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ScanLimits,
        mut emit: F,
    ) -> Result<ScanReceipt, ScanAttemptError>
    where
        F: FnMut(LiteralCandidate),
    {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(ScanAttemptError {
                source: ScanError::InvalidWindow {
                    start: window.start(),
                    end: window.end(),
                    haystack_len: haystack.len(),
                },
                actual: ScanActual::default(),
            });
        }
        let input_bytes =
            window
                .end()
                .checked_sub(window.start())
                .ok_or_else(|| ScanAttemptError {
                    source: ScanError::ArithmeticOverflow {
                        computation: "candidate window length",
                    },
                    actual: ScanActual::default(),
                })?;
        let upper = self
            .scan_upper_bounds(input_bytes)
            .map_err(|source| ScanAttemptError {
                source,
                actual: ScanActual::default(),
            })?;
        enforce_scan_limits(upper, limits).map_err(|source| ScanAttemptError {
            source,
            actual: ScanActual::default(),
        })?;

        scan_source_probe::record();
        let source = &haystack[window.start()..window.end()];
        let mut actual = execute_scan(
            &self.engine,
            self.build.max_pattern_bytes,
            source,
            window.start(),
            upper,
            &mut emit,
        )?;
        let event_work = actual
            .candidate_events
            .checked_mul(CANDIDATE_WORK)
            .ok_or_else(|| attempt_overflow(upper, actual, "actual candidate event work"))?;
        actual.work = actual
            .candidate_starts
            .checked_add(actual.source_byte_reads)
            .and_then(|sum| sum.checked_add(actual.transition_probes))
            .and_then(|sum| sum.checked_add(event_work))
            .ok_or_else(|| attempt_overflow(upper, actual, "actual candidate scan work"))?;
        if !scan_actual_within(actual, upper) {
            return Err(ScanAttemptError {
                source: ScanError::Invariant {
                    detail: "byte candidate scan actual exceeded prospective",
                },
                actual,
            });
        }
        Ok(ScanReceipt { upper, actual })
    }

    /// Emit every candidate in the complete haystack.
    ///
    /// # Errors
    ///
    /// Returns the same checked receipts as [`Self::scan_window`].
    pub fn scan<F>(
        &self,
        haystack: &[u8],
        limits: ScanLimits,
        emit: F,
    ) -> Result<ScanReceipt, ScanAttemptError>
    where
        F: FnMut(LiteralCandidate),
    {
        self.scan_window(haystack, Window::full(haystack), limits, emit)
    }
}

fn execute_scan<F>(
    engine: &Engine,
    max_pattern_bytes: usize,
    source: &[u8],
    absolute_base: usize,
    upper: ScanUpperBounds,
    emit: &mut F,
) -> Result<ScanActual, ScanAttemptError>
where
    F: FnMut(LiteralCandidate),
{
    let mut actual = ScanActual {
        input_bytes: source.len(),
        ..ScanActual::default()
    };
    match engine {
        Engine::TwoWay { finder, width } => {
            actual.candidate_starts = upper.candidate_starts;
            actual.source_byte_reads = upper.source_byte_reads;
            for relative_start in finder.find_iter(source) {
                let start = absolute_base
                    .checked_add(relative_start)
                    .ok_or_else(|| attempt_overflow(upper, actual, "Two-Way candidate start"))?;
                let end = start
                    .checked_add(*width)
                    .ok_or_else(|| attempt_overflow(upper, actual, "Two-Way candidate end"))?;
                account_candidate(&mut actual, upper)?;
                emit(LiteralCandidate::new(0, start, end));
            }
        }
        Engine::SparseTrie(trie) => scan_sparse_trie(
            trie,
            max_pattern_bytes,
            source,
            absolute_base,
            upper,
            &mut actual,
            emit,
        )?,
    }
    Ok(actual)
}

fn scan_sparse_trie<F>(
    trie: &SparseTrie,
    max_pattern_bytes: usize,
    source: &[u8],
    absolute_base: usize,
    upper: ScanUpperBounds,
    actual: &mut ScanActual,
    emit: &mut F,
) -> Result<(), ScanAttemptError>
where
    F: FnMut(LiteralCandidate),
{
    let mut relative_start = 0_usize;
    while relative_start < source.len() {
        actual.candidate_starts = checked_actual_add(
            actual.candidate_starts,
            1,
            upper,
            *actual,
            "sparse-trie candidate starts",
        )?;
        let mut state = 0_usize;
        let mut cursor = relative_start;
        let mut depth = 0_usize;
        while cursor < source.len() && depth < max_pattern_bytes {
            actual.source_byte_reads = checked_actual_add(
                actual.source_byte_reads,
                1,
                upper,
                *actual,
                "sparse-trie source byte reads",
            )?;
            let byte = source[cursor];
            let Some(next) =
                transition_with_actual(&trie.nodes, &trie.edges, state, byte, actual, upper)?
            else {
                break;
            };
            state = next;
            cursor = cursor
                .checked_add(1)
                .ok_or_else(|| attempt_overflow(upper, *actual, "sparse-trie cursor"))?;
            depth = depth
                .checked_add(1)
                .ok_or_else(|| attempt_overflow(upper, *actual, "sparse-trie depth"))?;
            emit_sparse_outputs(
                trie,
                state,
                absolute_base,
                (relative_start, cursor),
                upper,
                actual,
                emit,
            )?;
        }
        relative_start = relative_start
            .checked_add(1)
            .ok_or_else(|| attempt_overflow(upper, *actual, "next sparse-trie candidate start"))?;
    }
    Ok(())
}

fn emit_sparse_outputs<F>(
    trie: &SparseTrie,
    state: usize,
    absolute_base: usize,
    relative_span: (usize, usize),
    upper: ScanUpperBounds,
    actual: &mut ScanActual,
    emit: &mut F,
) -> Result<(), ScanAttemptError>
where
    F: FnMut(LiteralCandidate),
{
    let start = absolute_base
        .checked_add(relative_span.0)
        .ok_or_else(|| attempt_overflow(upper, *actual, "sparse-trie candidate start"))?;
    let end = absolute_base
        .checked_add(relative_span.1)
        .ok_or_else(|| attempt_overflow(upper, *actual, "sparse-trie candidate end"))?;
    let mut output = trie.nodes[state].first_output;
    while output != NONE {
        let terminal = trie.outputs[output];
        account_candidate(actual, upper)?;
        emit(LiteralCandidate::new(terminal.pattern_index, start, end));
        output = terminal.next;
    }
    Ok(())
}

fn preflight_from_lengths(patterns: &[&[u8]]) -> Result<BuildAccounting, BuildError> {
    let (pattern_bytes, max_pattern_bytes) = pattern_census(patterns)?;
    let states_upper_bound =
        pattern_bytes
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "sparse-trie states",
            })?;
    let transitions_upper_bound = pattern_bytes;
    let outputs_upper_bound = patterns.len();
    let trie_bytes = exact_trie_bytes(
        states_upper_bound,
        transitions_upper_bound,
        outputs_upper_bound,
    )?;
    let two_way_eligible_by_width = patterns.len() == 1 && pattern_bytes >= TWOWAY_MIN_WIDTH;
    let classification = if two_way_eligible_by_width {
        triangular(pattern_bytes)?
    } else {
        0
    };
    let classification_reads =
        checked_build_mul(classification, 2, "border classification byte reads")?;
    let two_way_pattern_reads = checked_build_mul(
        pattern_bytes,
        TWOWAY_PATTERN_READS_PER_BYTE,
        "Two-Way construction pattern reads",
    )?
    .checked_add(TWOWAY_BUILD_FIXED_WORK)
    .ok_or(BuildError::ArithmeticOverflow {
        computation: "Two-Way construction pattern reads",
    })?;
    let route_pattern_reads = if two_way_eligible_by_width {
        pattern_bytes.max(two_way_pattern_reads)
    } else {
        pattern_bytes
    };
    let pattern_byte_reads_upper_bound = classification_reads
        .checked_add(route_pattern_reads)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "construction pattern byte reads",
        })?;
    let trie_probe_work =
        checked_build_mul(pattern_bytes, pattern_bytes, "sparse-trie edge probes")?;
    let trie_work = trie_probe_work
        .checked_add(pattern_bytes)
        .and_then(|work| work.checked_add(states_upper_bound))
        .and_then(|work| work.checked_add(transitions_upper_bound))
        .and_then(|work| work.checked_add(outputs_upper_bound))
        .and_then(|work| work.checked_add(patterns.len()))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "sparse-trie construction work",
        })?;
    let two_way_work = checked_build_mul(
        pattern_bytes,
        TWOWAY_BUILD_WORK_PER_BYTE,
        "Two-Way charged construction work",
    )?
    .checked_add(TWOWAY_BUILD_FIXED_WORK)
    .ok_or(BuildError::ArithmeticOverflow {
        computation: "Two-Way construction work",
    })?;
    let work_upper_bound = classification
        .checked_add(trie_work.max(two_way_work))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "candidate construction work",
        })?;
    let retained_heap_upper_bound = trie_bytes.max(pattern_bytes);
    let persistent_bytes_upper_bound = mem::size_of::<ByteCandidatePlan>()
        .checked_add(retained_heap_upper_bound)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "candidate retained plan bytes",
        })?;
    Ok(BuildAccounting {
        algorithm: Algorithm::SparseTrie,
        patterns: patterns.len(),
        pattern_bytes,
        pattern_byte_reads_upper_bound,
        states_upper_bound,
        transitions_upper_bound,
        outputs_upper_bound,
        max_pattern_bytes,
        work_upper_bound,
        persistent_bytes_upper_bound,
        peak_bytes_upper_bound: persistent_bytes_upper_bound,
        allocations_upper_bound: 3,
        pattern_byte_reads: 0,
        states: 0,
        transitions: 0,
        outputs: 0,
        work: 0,
        persistent_bytes: 0,
        peak_bytes: 0,
        allocations: 0,
    })
}

fn pattern_census(patterns: &[&[u8]]) -> Result<(usize, usize), BuildError> {
    let mut pattern_bytes = 0_usize;
    let mut max_pattern_bytes = 0_usize;
    for pattern in patterns {
        pattern_bytes =
            pattern_bytes
                .checked_add(pattern.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "literal candidate pattern bytes",
                })?;
        max_pattern_bytes = max_pattern_bytes.max(pattern.len());
    }
    Ok((pattern_bytes, max_pattern_bytes))
}

fn build_two_way(
    pattern: &[u8],
    prospective: BuildAccounting,
    pattern_byte_reads: usize,
    classification_work: usize,
) -> Result<(Engine, BuildAccounting), BuildError> {
    build_probe::record_allocation_attempt();
    let needle = fre_exact_alloc::copy_exact(pattern)
        .map_err(|error| map_copy_error(error, "Two-Way needle", pattern.len()))?;
    let dependency_reads = checked_build_mul(
        pattern.len(),
        TWOWAY_PATTERN_READS_PER_BYTE,
        "Two-Way charged pattern reads",
    )?
    .checked_add(TWOWAY_BUILD_FIXED_WORK)
    .ok_or(BuildError::ArithmeticOverflow {
        computation: "Two-Way charged pattern reads",
    })?;
    let copied_reads =
        pattern_byte_reads
            .checked_add(dependency_reads)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "Two-Way actual pattern byte reads",
            })?;
    let charged = checked_build_mul(
        pattern.len(),
        TWOWAY_BUILD_WORK_PER_BYTE,
        "Two-Way actual charged work",
    )?
    .checked_add(TWOWAY_BUILD_FIXED_WORK)
    .and_then(|work| work.checked_add(classification_work))
    .ok_or(BuildError::ArithmeticOverflow {
        computation: "Two-Way actual construction work",
    })?;
    let mut actual = prospective;
    actual.pattern_byte_reads = copied_reads;
    actual.work = charged;
    actual.persistent_bytes = mem::size_of::<ByteCandidatePlan>()
        .checked_add(needle.len())
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "Two-Way retained plan bytes",
        })?;
    actual.peak_bytes = actual.persistent_bytes;
    actual.allocations = usize::from(!needle.is_empty());
    let mut builder = FinderBuilder::new();
    builder.prefilter(Prefilter::None);
    Ok((
        Engine::TwoWay {
            finder: builder.build_forward_owned(needle),
            width: pattern.len(),
        },
        actual,
    ))
}

fn build_sparse_trie(
    patterns: &[&[u8]],
    prospective: BuildAccounting,
    pattern_byte_reads: usize,
    classification_work: usize,
) -> Result<(Engine, BuildAccounting), BuildError> {
    let mut trie = allocate_sparse_trie(prospective)?;

    let mut work = classification_work;
    push_exact(&mut trie.nodes, Node::EMPTY, "sparse-trie root state")?;
    work = checked_build_add(work, 1, "sparse-trie root work")?;
    let mut observed_pattern_reads = pattern_byte_reads;
    let mut transition_probes = 0_usize;
    for (pattern_index, pattern) in patterns.iter().enumerate() {
        work = checked_build_add(work, 1, "sparse-trie pattern work")?;
        let mut state = 0_usize;
        for &byte in *pattern {
            build_probe::record_source_reads(1);
            observed_pattern_reads =
                checked_build_add(observed_pattern_reads, 1, "actual pattern byte reads")?;
            work = checked_build_add(work, 1, "sparse-trie byte-read work")?;
            let (next, probes) = transition(&trie.nodes, &trie.edges, state, byte);
            transition_probes =
                checked_build_add(transition_probes, probes, "build transition probes")?;
            work = checked_build_add(work, probes, "sparse-trie probe work")?;
            state = if let Some(existing) = next {
                existing
            } else {
                let next_state = trie.nodes.len();
                push_exact(&mut trie.nodes, Node::EMPTY, "sparse-trie state")?;
                work = checked_build_add(work, 1, "sparse-trie state work")?;
                let edge_index = trie.edges.len();
                let next_edge = trie.nodes[state].first_edge;
                push_exact(
                    &mut trie.edges,
                    Edge {
                        byte,
                        target: next_state,
                        next: next_edge,
                    },
                    "sparse-trie transition",
                )?;
                trie.nodes[state].first_edge = edge_index;
                work = checked_build_add(work, 1, "sparse-trie edge work")?;
                next_state
            };
        }
        append_output(
            &mut trie.nodes,
            &mut trie.outputs,
            state,
            pattern_index,
            pattern.len(),
        )?;
        work = checked_build_add(work, 1, "sparse-trie output work")?;
    }
    let heap_bytes = exact_trie_bytes(
        trie.nodes.capacity(),
        trie.edges.capacity(),
        trie.outputs.capacity(),
    )?;
    let persistent_bytes = mem::size_of::<ByteCandidatePlan>()
        .checked_add(heap_bytes)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "sparse-trie retained plan bytes",
        })?;
    let allocations = usize::from(trie.nodes.capacity() != 0)
        .checked_add(usize::from(trie.edges.capacity() != 0))
        .and_then(|count| count.checked_add(usize::from(trie.outputs.capacity() != 0)))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "sparse-trie allocation count",
        })?;
    let mut actual = prospective;
    actual.pattern_byte_reads = observed_pattern_reads;
    actual.states = trie.nodes.len();
    actual.transitions = trie.edges.len();
    actual.outputs = trie.outputs.len();
    actual.work = work;
    actual.persistent_bytes = persistent_bytes;
    actual.peak_bytes = persistent_bytes;
    actual.allocations = allocations;
    let _ = transition_probes;
    Ok((Engine::SparseTrie(trie), actual))
}

fn allocate_sparse_trie(prospective: BuildAccounting) -> Result<SparseTrie, BuildError> {
    build_probe::record_allocation_attempt();
    let nodes = ExactVec::try_with_capacity(prospective.states_upper_bound).map_err(|error| {
        map_copy_error(error, "sparse-trie states", prospective.states_upper_bound)
    })?;
    build_probe::record_allocation_attempt();
    let edges =
        ExactVec::try_with_capacity(prospective.transitions_upper_bound).map_err(|error| {
            map_copy_error(
                error,
                "sparse-trie transitions",
                prospective.transitions_upper_bound,
            )
        })?;
    build_probe::record_allocation_attempt();
    let outputs =
        ExactVec::try_with_capacity(prospective.outputs_upper_bound).map_err(|error| {
            map_copy_error(
                error,
                "sparse-trie outputs",
                prospective.outputs_upper_bound,
            )
        })?;
    Ok(SparseTrie {
        nodes,
        edges,
        outputs,
    })
}

fn is_unbordered(
    pattern: &[u8],
    pattern_byte_reads: &mut usize,
    work: &mut usize,
) -> Result<bool, BuildError> {
    let mut border = 1_usize;
    while border < pattern.len() {
        let suffix_start =
            pattern
                .len()
                .checked_sub(border)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "literal border suffix",
                })?;
        let mut index = 0_usize;
        let mut equal = true;
        while index < border {
            build_probe::record_source_reads(2);
            *pattern_byte_reads =
                checked_build_add(*pattern_byte_reads, 2, "border pattern byte reads")?;
            *work = checked_build_add(*work, 1, "border comparison work")?;
            let suffix_index =
                suffix_start
                    .checked_add(index)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "literal border suffix index",
                    })?;
            if pattern[index] != pattern[suffix_index] {
                equal = false;
                break;
            }
            index = index.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
                computation: "literal border index",
            })?;
        }
        if equal {
            return Ok(false);
        }
        border = border
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "literal border width",
            })?;
    }
    Ok(true)
}

fn exact_trie_bytes(
    states: usize,
    transitions: usize,
    outputs: usize,
) -> Result<usize, BuildError> {
    checked_build_mul(states, mem::size_of::<Node>(), "sparse-trie state bytes")?
        .checked_add(checked_build_mul(
            transitions,
            mem::size_of::<Edge>(),
            "sparse-trie transition bytes",
        )?)
        .and_then(|bytes| {
            checked_build_mul(
                outputs,
                mem::size_of::<Output>(),
                "sparse-trie output bytes",
            )
            .ok()
            .and_then(|output_bytes| bytes.checked_add(output_bytes))
        })
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "sparse-trie persistent bytes",
        })
}

fn triangular(width: usize) -> Result<usize, BuildError> {
    let prior = width.saturating_sub(1);
    if width & 1 == 0 {
        width
            .checked_div(2)
            .and_then(|half| half.checked_mul(prior))
    } else {
        prior
            .checked_div(2)
            .and_then(|half| width.checked_mul(half))
    }
    .ok_or(BuildError::ArithmeticOverflow {
        computation: "literal border comparisons",
    })
}

fn append_output(
    nodes: &mut [Node],
    outputs: &mut ExactVec<Output>,
    state: usize,
    pattern_index: usize,
    width: usize,
) -> Result<(), BuildError> {
    let output_index = outputs.len();
    push_exact(
        outputs,
        Output {
            pattern_index,
            width,
            next: NONE,
        },
        "sparse-trie output",
    )?;
    let last = nodes[state].last_output;
    if last == NONE {
        nodes[state].first_output = output_index;
    } else {
        outputs[last].next = output_index;
    }
    nodes[state].last_output = output_index;
    Ok(())
}

fn transition(nodes: &[Node], edges: &[Edge], state: usize, byte: u8) -> (Option<usize>, usize) {
    let mut edge = nodes[state].first_edge;
    let mut probes = 0_usize;
    while edge != NONE {
        probes = probes.saturating_add(1);
        let candidate = edges[edge];
        if candidate.byte == byte {
            return (Some(candidate.target), probes);
        }
        edge = candidate.next;
    }
    (None, probes)
}

fn transition_with_actual(
    nodes: &[Node],
    edges: &[Edge],
    state: usize,
    byte: u8,
    actual: &mut ScanActual,
    upper: ScanUpperBounds,
) -> Result<Option<usize>, ScanAttemptError> {
    let mut edge = nodes[state].first_edge;
    while edge != NONE {
        actual.transition_probes = checked_actual_add(
            actual.transition_probes,
            1,
            upper,
            *actual,
            "actual sparse-trie transition probes",
        )?;
        let candidate = edges[edge];
        if candidate.byte == byte {
            return Ok(Some(candidate.target));
        }
        edge = candidate.next;
    }
    Ok(None)
}

fn push_exact<T>(
    values: &mut ExactVec<T>,
    value: T,
    detail: &'static str,
) -> Result<(), BuildError> {
    values
        .try_push(value)
        .map_err(|_| BuildError::Invariant { detail })
}

fn occurrence_ceiling(input_bytes: usize, width: usize) -> Result<usize, ScanError> {
    if input_bytes < width {
        return Ok(0);
    }
    input_bytes
        .checked_sub(width)
        .and_then(|remaining| remaining.checked_add(1))
        .ok_or(ScanError::ArithmeticOverflow {
            computation: "literal occurrence ceiling",
        })
}

fn enforce_build_limits(
    accounting: BuildAccounting,
    limits: BuildLimits,
) -> Result<(), BuildError> {
    for (needed, limit, resource) in [
        (
            accounting.patterns,
            limits.max_patterns,
            BuildResource::Patterns,
        ),
        (
            accounting.pattern_bytes,
            limits.max_pattern_bytes,
            BuildResource::PatternBytes,
        ),
        (
            accounting.pattern_byte_reads_upper_bound,
            limits.max_pattern_byte_reads,
            BuildResource::PatternByteReads,
        ),
        (
            accounting.states_upper_bound,
            limits.max_states,
            BuildResource::States,
        ),
        (
            accounting.transitions_upper_bound,
            limits.max_transitions,
            BuildResource::Transitions,
        ),
        (
            accounting.outputs_upper_bound,
            limits.max_outputs,
            BuildResource::Outputs,
        ),
        (
            accounting.work_upper_bound,
            limits.max_work,
            BuildResource::Work,
        ),
        (
            accounting.persistent_bytes_upper_bound,
            limits.max_persistent_bytes,
            BuildResource::PersistentBytes,
        ),
        (
            accounting.peak_bytes_upper_bound,
            limits.max_peak_bytes,
            BuildResource::PeakBytes,
        ),
        (
            accounting.allocations_upper_bound,
            limits.max_allocations,
            BuildResource::Allocations,
        ),
    ] {
        if needed > limit {
            return Err(BuildError::Resource {
                resource,
                needed,
                limit,
            });
        }
    }
    Ok(())
}

fn enforce_scan_limits(upper: ScanUpperBounds, limits: ScanLimits) -> Result<(), ScanError> {
    for (needed, limit, resource) in [
        (
            upper.input_bytes,
            limits.max_input_bytes,
            ScanResource::InputBytes,
        ),
        (
            upper.candidate_starts,
            limits.max_candidate_starts,
            ScanResource::CandidateStarts,
        ),
        (
            upper.source_byte_reads,
            limits.max_source_byte_reads,
            ScanResource::SourceByteReads,
        ),
        (
            upper.transition_probes,
            limits.max_transition_probes,
            ScanResource::TransitionProbes,
        ),
        (
            upper.candidate_events,
            limits.max_candidate_events,
            ScanResource::CandidateEvents,
        ),
        (upper.work, limits.max_work, ScanResource::Work),
        (
            upper.scratch_bytes,
            limits.max_scratch_bytes,
            ScanResource::ScratchBytes,
        ),
    ] {
        if needed > limit {
            return Err(ScanError::Resource {
                resource,
                needed,
                limit,
            });
        }
    }
    Ok(())
}

fn account_candidate(
    actual: &mut ScanActual,
    upper: ScanUpperBounds,
) -> Result<(), ScanAttemptError> {
    actual.candidate_events = checked_actual_add(
        actual.candidate_events,
        1,
        upper,
        *actual,
        "actual byte candidate events",
    )?;
    Ok(())
}

const fn build_actual_within(actual: BuildAccounting) -> bool {
    actual.pattern_byte_reads <= actual.pattern_byte_reads_upper_bound
        && actual.states <= actual.states_upper_bound
        && actual.transitions <= actual.transitions_upper_bound
        && actual.outputs <= actual.outputs_upper_bound
        && actual.work <= actual.work_upper_bound
        && actual.persistent_bytes <= actual.persistent_bytes_upper_bound
        && actual.peak_bytes <= actual.peak_bytes_upper_bound
        && actual.allocations <= actual.allocations_upper_bound
}

const fn scan_actual_within(actual: ScanActual, upper: ScanUpperBounds) -> bool {
    actual.input_bytes <= upper.input_bytes
        && actual.candidate_starts <= upper.candidate_starts
        && actual.source_byte_reads <= upper.source_byte_reads
        && actual.transition_probes <= upper.transition_probes
        && actual.candidate_events <= upper.candidate_events
        && actual.work <= upper.work
        && actual.scratch_bytes <= upper.scratch_bytes
}

fn checked_actual_add(
    left: usize,
    right: usize,
    upper: ScanUpperBounds,
    actual: ScanActual,
    computation: &'static str,
) -> Result<usize, ScanAttemptError> {
    left.checked_add(right)
        .ok_or_else(|| attempt_overflow(upper, actual, computation))
}

fn attempt_overflow(
    _upper: ScanUpperBounds,
    actual: ScanActual,
    computation: &'static str,
) -> ScanAttemptError {
    ScanAttemptError {
        source: ScanError::ArithmeticOverflow { computation },
        actual,
    }
}

fn checked_build_add(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, BuildError> {
    left.checked_add(right)
        .ok_or(BuildError::ArithmeticOverflow { computation })
}

fn checked_build_mul(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, BuildError> {
    left.checked_mul(right)
        .ok_or(BuildError::ArithmeticOverflow { computation })
}

fn checked_scan_mul(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, ScanError> {
    left.checked_mul(right)
        .ok_or(ScanError::ArithmeticOverflow { computation })
}

fn map_copy_error(error: CopyError, structure: &'static str, items: usize) -> BuildError {
    match error {
        CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
            computation: "candidate exact allocation layout",
        },
        CopyError::AllocationFailed => BuildError::AllocationFailed { structure, items },
    }
}

#[cfg(not(test))]
mod build_probe {
    pub(super) const fn record_source_reads(_: usize) {}
    pub(super) const fn record_allocation_attempt() {}
}

#[cfg(test)]
mod build_probe {
    use std::cell::Cell;

    std::thread_local! {
        static SOURCE_READS: Cell<usize> = const { Cell::new(0) };
        static ALLOCATION_ATTEMPTS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record_source_reads(reads: usize) {
        SOURCE_READS.set(
            SOURCE_READS
                .get()
                .checked_add(reads)
                .expect("source-read probe overflow"),
        );
    }

    pub(super) fn record_allocation_attempt() {
        ALLOCATION_ATTEMPTS.set(
            ALLOCATION_ATTEMPTS
                .get()
                .checked_add(1)
                .expect("allocation probe overflow"),
        );
    }

    pub(super) fn reset() {
        SOURCE_READS.set(0);
        ALLOCATION_ATTEMPTS.set(0);
    }

    pub(super) fn source_reads() -> usize {
        SOURCE_READS.get()
    }

    pub(super) fn allocation_attempts() -> usize {
        ALLOCATION_ATTEMPTS.get()
    }
}

#[cfg(not(test))]
mod scan_source_probe {
    pub(super) const fn record() {}
}

#[cfg(test)]
mod scan_source_probe {
    use std::cell::Cell;

    std::thread_local! {
        static ACCESSES: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record() {
        ACCESSES.set(
            ACCESSES
                .get()
                .checked_add(1)
                .expect("scan source probe overflow"),
        );
    }

    pub(super) fn reset() {
        ACCESSES.set(0);
    }

    pub(super) fn accesses() -> usize {
        ACCESSES.get()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Algorithm, BuildAccounting, BuildAttempt, BuildError, BuildLimits, BuildResource,
        ByteCandidatePlan, DenseFallbackReason, ScanActual, ScanError, ScanLimits, ScanResource,
        build_probe, scan_source_probe,
    };
    use crate::{LiteralCandidate, Window};

    const LONG_UNBORDERED: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

    fn admitted(patterns: &[&[u8]]) -> ByteCandidatePlan {
        match ByteCandidatePlan::build(patterns, BuildLimits::default()).unwrap() {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("unexpected fallback: {fallback:?}")
            }
        }
    }

    fn collect(plan: &ByteCandidatePlan, haystack: &[u8]) -> Vec<LiteralCandidate> {
        let mut candidates = Vec::new();
        plan.scan(haystack, ScanLimits::unlimited(), |candidate| {
            candidates.push(candidate);
        })
        .unwrap();
        candidates
    }

    fn assert_build_actual_within(accounting: BuildAccounting) {
        assert!(accounting.pattern_byte_reads <= accounting.pattern_byte_reads_upper_bound);
        assert!(accounting.states <= accounting.states_upper_bound);
        assert!(accounting.transitions <= accounting.transitions_upper_bound);
        assert!(accounting.outputs <= accounting.outputs_upper_bound);
        assert!(accounting.work <= accounting.work_upper_bound);
        assert!(accounting.persistent_bytes <= accounting.persistent_bytes_upper_bound);
        assert!(accounting.peak_bytes <= accounting.peak_bytes_upper_bound);
        assert!(accounting.allocations <= accounting.allocations_upper_bound);
    }

    #[test]
    fn structural_selection_and_empty_fallback_are_exact() {
        assert_eq!(admitted(&[LONG_UNBORDERED]).algorithm(), Algorithm::TwoWay);
        assert_eq!(admitted(&[b"needle"]).algorithm(), Algorithm::SparseTrie);
        assert_eq!(admitted(&[b"aaa"]).algorithm(), Algorithm::SparseTrie);
        assert_eq!(admitted(&[b"a", b"b"]).algorithm(), Algorithm::SparseTrie);
        let BuildAttempt::DenseFallback(empty) =
            ByteCandidatePlan::build(&[], BuildLimits::default()).unwrap()
        else {
            panic!("empty language must fall back");
        };
        assert_eq!(empty.reason(), DenseFallbackReason::EmptyLanguage);
        let BuildAttempt::DenseFallback(empty_literal) =
            ByteCandidatePlan::build(&[b"a", b""], BuildLimits::default()).unwrap()
        else {
            panic!("empty literal must fall back");
        };
        assert_eq!(
            empty_literal.reason(),
            DenseFallbackReason::EmptyLiteral { pattern_index: 1 }
        );
    }

    #[test]
    fn overlaps_duplicates_windows_offsets_and_order_are_complete() {
        let plan = admitted(&[b"aa", b"a", b"aa"]);
        let mut candidates = Vec::new();
        let receipt = plan
            .scan_window(
                b"xxaaa!",
                Window::new(2, 5),
                ScanLimits::unlimited(),
                |candidate| candidates.push(candidate),
            )
            .unwrap();
        let actual = candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.pattern_index(),
                    candidate.start(),
                    candidate.end(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            [
                (1, 2, 3),
                (0, 2, 4),
                (2, 2, 4),
                (1, 3, 4),
                (0, 3, 5),
                (2, 3, 5),
                (1, 4, 5),
            ]
        );
        assert_eq!(receipt.actual.candidate_events, actual.len());
        assert!(receipt.actual.candidate_events <= receipt.upper.candidate_events);
    }

    #[test]
    fn same_end_priority_is_governed_by_start_then_source_order() {
        let plan = admitted(&[b"a", b"ba", b"a"]);
        let actual = collect(&plan, b"ba")
            .into_iter()
            .map(|candidate| {
                (
                    candidate.pattern_index(),
                    candidate.start(),
                    candidate.end(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, [(1, 0, 2), (0, 1, 2), (2, 1, 2)]);
    }

    #[test]
    fn exhaustive_small_alphabet_matches_naive_ordered_stream() {
        let patterns: &[&[u8]] = &[b"a", b"aa", b"ba", b"a"];
        let plan = admitted(patterns);
        for len in 0..=6 {
            let variants = 1_usize.checked_shl(len).unwrap();
            for bits in 0..variants {
                let haystack = (0..len)
                    .map(|index| {
                        let mask = 1_usize.checked_shl(index).unwrap();
                        if bits & mask == 0 { b'a' } else { b'b' }
                    })
                    .collect::<Vec<_>>();
                let mut expected = Vec::new();
                for start in 0..haystack.len() {
                    let mut at_start = Vec::new();
                    for (pattern_index, pattern) in patterns.iter().enumerate() {
                        let Some(end) = start.checked_add(pattern.len()) else {
                            continue;
                        };
                        if end <= haystack.len() && haystack[start..end] == **pattern {
                            at_start.push((pattern_index, start, end));
                        }
                    }
                    at_start.sort_unstable_by_key(|&(pattern_index, _, end)| (end, pattern_index));
                    expected.extend(at_start);
                }
                let actual = collect(&plan, &haystack)
                    .into_iter()
                    .map(|candidate| {
                        (
                            candidate.pattern_index(),
                            candidate.start(),
                            candidate.end(),
                        )
                    })
                    .collect::<Vec<_>>();
                assert_eq!(actual, expected, "haystack={haystack:?}");
            }
        }
    }

    fn exact_build_limits(accounting: BuildAccounting) -> BuildLimits {
        BuildLimits {
            max_patterns: accounting.patterns,
            max_pattern_bytes: accounting.pattern_bytes,
            max_pattern_byte_reads: accounting.pattern_byte_reads_upper_bound,
            max_states: accounting.states_upper_bound,
            max_transitions: accounting.transitions_upper_bound,
            max_outputs: accounting.outputs_upper_bound,
            max_work: accounting.work_upper_bound,
            max_persistent_bytes: accounting.persistent_bytes_upper_bound,
            max_peak_bytes: accounting.peak_bytes_upper_bound,
            max_allocations: accounting.allocations_upper_bound,
        }
    }

    fn verify_build_boundaries(patterns: &[&[u8]]) {
        let accounting = admitted(patterns).build_accounting();
        assert_build_actual_within(accounting);
        assert!(matches!(
            ByteCandidatePlan::build(patterns, exact_build_limits(accounting)).unwrap(),
            BuildAttempt::Admitted(_)
        ));
        let exact = exact_build_limits(accounting);
        let cases = [
            (
                BuildResource::Patterns,
                BuildLimits {
                    max_patterns: accounting.patterns.checked_sub(1).unwrap(),
                    ..exact
                },
            ),
            (
                BuildResource::PatternBytes,
                BuildLimits {
                    max_pattern_bytes: accounting.pattern_bytes.checked_sub(1).unwrap(),
                    ..exact
                },
            ),
            (
                BuildResource::PatternByteReads,
                BuildLimits {
                    max_pattern_byte_reads: accounting
                        .pattern_byte_reads_upper_bound
                        .checked_sub(1)
                        .unwrap(),
                    ..exact
                },
            ),
            (
                BuildResource::States,
                BuildLimits {
                    max_states: accounting.states_upper_bound.checked_sub(1).unwrap(),
                    ..exact
                },
            ),
            (
                BuildResource::Transitions,
                BuildLimits {
                    max_transitions: accounting.transitions_upper_bound.checked_sub(1).unwrap(),
                    ..exact
                },
            ),
            (
                BuildResource::Outputs,
                BuildLimits {
                    max_outputs: accounting.outputs_upper_bound.checked_sub(1).unwrap(),
                    ..exact
                },
            ),
            (
                BuildResource::Work,
                BuildLimits {
                    max_work: accounting.work_upper_bound.checked_sub(1).unwrap(),
                    ..exact
                },
            ),
            (
                BuildResource::PersistentBytes,
                BuildLimits {
                    max_persistent_bytes: accounting
                        .persistent_bytes_upper_bound
                        .checked_sub(1)
                        .unwrap(),
                    ..exact
                },
            ),
            (
                BuildResource::PeakBytes,
                BuildLimits {
                    max_peak_bytes: accounting.peak_bytes_upper_bound.checked_sub(1).unwrap(),
                    ..exact
                },
            ),
            (
                BuildResource::Allocations,
                BuildLimits {
                    max_allocations: accounting.allocations_upper_bound.checked_sub(1).unwrap(),
                    ..exact
                },
            ),
        ];
        for (resource, limits) in cases {
            build_probe::reset();
            assert!(matches!(
                ByteCandidatePlan::build(patterns, limits),
                Err(BuildError::Resource {
                    resource: observed,
                    ..
                }) if observed == resource
            ));
            assert_eq!(build_probe::source_reads(), 0);
            assert_eq!(build_probe::allocation_attempts(), 0);
        }
    }

    #[test]
    fn exact_and_every_positive_one_below_build_limit_precede_source_and_allocation() {
        verify_build_boundaries(&[LONG_UNBORDERED]);
        verify_build_boundaries(&[b"aba", b"bab"]);
    }

    fn exact_scan_limits(upper: super::ScanUpperBounds) -> ScanLimits {
        ScanLimits {
            max_input_bytes: upper.input_bytes,
            max_candidate_starts: upper.candidate_starts,
            max_source_byte_reads: upper.source_byte_reads,
            max_transition_probes: upper.transition_probes,
            max_candidate_events: upper.candidate_events,
            max_work: upper.work,
            max_scratch_bytes: upper.scratch_bytes,
        }
    }

    #[test]
    fn exact_and_every_positive_one_below_scan_limit_precede_source() {
        for plan in [admitted(&[LONG_UNBORDERED]), admitted(&[b"aa", b"a"])] {
            let haystack =
                b"abcdefghijklmnopqrstuvwxyz0123456789 aaaa abcdefghijklmnopqrstuvwxyz0123456789";
            let upper = plan.scan_upper_bounds(haystack.len()).unwrap();
            scan_source_probe::reset();
            let exact_receipt = plan
                .scan(haystack, exact_scan_limits(upper), |_| {})
                .unwrap();
            assert!(super::scan_actual_within(exact_receipt.actual, upper));
            assert_eq!(scan_source_probe::accesses(), 1);
            let exact = exact_scan_limits(upper);
            let mut cases = vec![
                (
                    ScanResource::InputBytes,
                    ScanLimits {
                        max_input_bytes: upper.input_bytes.checked_sub(1).unwrap(),
                        ..exact
                    },
                ),
                (
                    ScanResource::CandidateStarts,
                    ScanLimits {
                        max_candidate_starts: upper.candidate_starts.checked_sub(1).unwrap(),
                        ..exact
                    },
                ),
                (
                    ScanResource::SourceByteReads,
                    ScanLimits {
                        max_source_byte_reads: upper.source_byte_reads.checked_sub(1).unwrap(),
                        ..exact
                    },
                ),
                (
                    ScanResource::CandidateEvents,
                    ScanLimits {
                        max_candidate_events: upper.candidate_events.checked_sub(1).unwrap(),
                        ..exact
                    },
                ),
                (
                    ScanResource::Work,
                    ScanLimits {
                        max_work: upper.work.checked_sub(1).unwrap(),
                        ..exact
                    },
                ),
            ];
            if upper.transition_probes > 0 {
                cases.push((
                    ScanResource::TransitionProbes,
                    ScanLimits {
                        max_transition_probes: upper.transition_probes.checked_sub(1).unwrap(),
                        ..exact
                    },
                ));
            }
            for (resource, limits) in cases {
                scan_source_probe::reset();
                let mut emissions = 0_usize;
                let error = plan
                    .scan(haystack, limits, |_| {
                        emissions = emissions.checked_add(1).unwrap();
                    })
                    .unwrap_err();
                assert!(matches!(
                    error.source,
                    ScanError::Resource {
                        resource: observed,
                        ..
                    } if observed == resource
                ));
                assert_eq!(error.actual, ScanActual::default());
                assert_eq!(emissions, 0);
                assert_eq!(scan_source_probe::accesses(), 0);
            }
        }
    }

    #[test]
    fn fixed_program_doubling_envelopes_remain_linear() {
        let plan = admitted(&[b"aba", b"bab"]);
        let first = plan.scan_upper_bounds(1_024).unwrap();
        let second = plan.scan_upper_bounds(2_048).unwrap();
        let fourth = plan.scan_upper_bounds(4_096).unwrap();
        assert_eq!(
            second.source_byte_reads,
            first.source_byte_reads.checked_mul(2).unwrap()
        );
        assert_eq!(
            fourth.source_byte_reads,
            second.source_byte_reads.checked_mul(2).unwrap()
        );
        assert!(
            second.work
                <= first
                    .work
                    .checked_mul(2)
                    .and_then(|work| work.checked_add(8))
                    .unwrap()
        );
        assert!(
            fourth.work
                <= second
                    .work
                    .checked_mul(2)
                    .and_then(|work| work.checked_add(8))
                    .unwrap()
        );
    }

    #[test]
    fn prospective_overflow_is_typed_without_source_access() {
        for plan in [admitted(&[LONG_UNBORDERED]), admitted(&[b"aba", b"bab"])] {
            scan_source_probe::reset();
            assert!(matches!(
                plan.scan_upper_bounds(usize::MAX),
                Err(ScanError::ArithmeticOverflow { .. })
            ));
            assert_eq!(scan_source_probe::accesses(), 0);
        }
        assert!(matches!(
            super::triangular(usize::MAX),
            Err(BuildError::ArithmeticOverflow { .. })
        ));
    }
}
