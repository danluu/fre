//! Bounded sparse trie for caller-canonicalized Unicode simple-fold literals.
//!
//! This module deliberately does not parse syntax or own a Unicode table.
//! The later HIR integration supplies sorted scalar equivalence classes from
//! its pinned canonical simple-fold facts. Classes must be pairwise identical
//! or disjoint. The retained trie matches those classes directly against
//! strict UTF-8 and reports original byte offsets. Invalid UTF-8 never matches
//! and advances one byte.

use core::{fmt, marker::PhantomData, mem};

use fre_exact_alloc::{CopyError, ExactVec};
use fre_simd_kernels::{
    BYTE_BUCKET_BLOCK_BYTES, BYTE_BUCKET_MAX_COLUMNS, BYTE_SET_WIDE_BLOCK_BYTES,
    ByteBucketClassifier, ByteBucketTables, DispatchPolicy, SelectionReceipt, SimdDispatchContext,
    classify_byte_set1_32, classify_byte_set2_32, classify_byte_set3_32,
};
use memchr::{memchr, memchr_iter, memchr2, memchr2_iter, memchr3, memchr3_iter};

use crate::{
    Window,
    literal_anchor::{CandidateEmissionOrder, LiteralCandidate},
    packed_ordered_literal_aggregate::byte_frequency_rank,
};

/// Stable identity of the canonical folded-scalar trie primitive.
pub const PLAN_ID: &str = "literal-candidate-stream.unicode-folded-trie.v7";

const NONE: usize = usize::MAX;
const CANDIDATE_WORK: usize = 2;
const MAX_UTF8_WIDTH: usize = 4;
const MEMCHR_ROOT_PREFILTER_NEEDLES: usize = 3;
const ROOT_PREFILTER_BYTE_VALUES: usize = 256;
const ROOT_PREFILTER_BYTE_WORDS: usize = 4;
const ROOT_PREFILTER_WORD_BITS: usize = 64;
const ROOT_PREFILTER_BUCKETS: usize = 8;
const ROOT_PREFILTER_CLASSIFIER_HIGH_WORK: usize = 16;
// Matches the authenticated byte-bucket construction charge used by the
// packed multi-literal owner. Host capture and Auto selection happen once.
const ROOT_PREFILTER_CLASSIFIER_SELECTION_WORK: usize = 256;
const ROOT_PREFILTER_FINGERPRINT_GAIN: u64 = 2;
const ROOT_PREFILTER_FINGERPRINT_MAX_WORK: usize = 1 << 20;
const ROOT_PREFILTER_FINGERPRINT_SCORE_WORK: usize =
    2 * BYTE_BUCKET_MAX_COLUMNS * BYTE_BUCKET_MAX_COLUMNS * ROOT_PREFILTER_BYTE_VALUES
        * ROOT_PREFILTER_BUCKETS;
const ROOT_PREFILTER_FINGERPRINT_LAYOUT_WORK: usize =
    ROOT_PREFILTER_BYTE_VALUES + ROOT_PREFILTER_BUCKETS * 16;
const ROOT_PREFILTER_OFFSET_WORK: usize = 2;
const ROOT_PREFILTER_EDGE_WORK: usize = 7;
const ROOT_PREFILTER_NEEDLE_WORK: usize = 2;

/// One sorted canonical simple-fold equivalence class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FoldedScalarClass<'a> {
    equivalents: &'a [char],
}

impl<'a> FoldedScalarClass<'a> {
    /// Wrap caller-derived canonical equivalents.
    #[must_use]
    pub const fn new(equivalents: &'a [char]) -> Self {
        Self { equivalents }
    }

    /// Strictly sorted canonical equivalents.
    #[must_use]
    pub const fn equivalents(self) -> &'a [char] {
        self.equivalents
    }
}

/// One folded literal represented as a sequence of scalar classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FoldedLiteral<'a> {
    classes: &'a [FoldedScalarClass<'a>],
}

impl<'a> FoldedLiteral<'a> {
    /// Construct a caller-canonicalized folded literal source.
    #[must_use]
    pub const fn new(classes: &'a [FoldedScalarClass<'a>]) -> Self {
        Self { classes }
    }

    /// Scalar-position classes in source order.
    #[must_use]
    pub const fn classes(self) -> &'a [FoldedScalarClass<'a>] {
        self.classes
    }
}

/// Structural reason to use the integrating dense semantic executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenseFallbackReason {
    EmptyLanguage,
    EmptyLiteral {
        pattern_index: usize,
    },
    EmptyClass {
        pattern_index: usize,
        scalar_index: usize,
    },
    NonCanonicalClass {
        pattern_index: usize,
        scalar_index: usize,
    },
    OverlappingClasses {
        first_pattern: usize,
        first_scalar: usize,
        second_pattern: usize,
        second_scalar: usize,
    },
}

/// Source-independent terminal fallback disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DenseFallback {
    reason: DenseFallbackReason,
    accounting: BuildAccounting,
}

impl DenseFallback {
    /// Exact canonicalization/empty-match reason.
    #[must_use]
    pub const fn reason(self) -> DenseFallbackReason {
        self.reason
    }

    /// Prospective envelope and validation work completed before fallback.
    #[must_use]
    pub const fn build_accounting(self) -> BuildAccounting {
        self.accounting
    }
}

/// Folded construction outcome.
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "the admitted plan retains an allocation-free compiled byte classifier; boxing it would add an unaccounted construction allocation and steady indirection"
)]
pub enum BuildAttempt {
    Admitted(FoldedLiteralTriePlan),
    DenseFallback(DenseFallback),
}

/// Construction-resource dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildResource {
    Patterns,
    ScalarPositions,
    EquivalentScalars,
    States,
    Transitions,
    Work,
    PersistentBytes,
    PeakBytes,
    Allocations,
}

/// Caller-selected folded-trie construction limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_patterns: usize,
    pub max_scalar_positions: usize,
    pub max_equivalent_scalars: usize,
    pub max_states: usize,
    pub max_transitions: usize,
    pub max_work: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
    pub max_allocations: usize,
}

impl BuildLimits {
    /// Disable caller-selected limits.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_patterns: usize::MAX,
            max_scalar_positions: usize::MAX,
            max_equivalent_scalars: usize::MAX,
            max_states: usize::MAX,
            max_transitions: usize::MAX,
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
            max_scalar_positions: 1 << 20,
            max_equivalent_scalars: 4 << 20,
            max_states: (1 << 20) + 1,
            max_transitions: 4 << 20,
            max_work: 256 << 20,
            max_persistent_bytes: 256 << 20,
            max_peak_bytes: 256 << 20,
            max_allocations: 3,
        }
    }
}

/// Prospective envelope and completed construction census.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub patterns: usize,
    pub scalar_positions: usize,
    pub equivalent_scalars: usize,
    pub states_upper_bound: usize,
    pub transitions_upper_bound: usize,
    pub max_pattern_scalars: usize,
    pub max_state_fanout_upper_bound: usize,
    pub canonical_comparisons_upper_bound: usize,
    pub insertion_probes_upper_bound: usize,
    pub root_prefilter_work_upper_bound: usize,
    pub work_upper_bound: usize,
    pub persistent_bytes_upper_bound: usize,
    pub peak_bytes_upper_bound: usize,
    pub allocations_upper_bound: usize,
    pub canonical_comparisons: usize,
    pub insertion_probes: usize,
    /// Exact maximum number of outgoing trie edges inspected by one scalar
    /// transition. This is a retained topology certificate, not the total
    /// transition count across unrelated states.
    pub max_state_fanout: usize,
    pub root_prefilter_work: usize,
    pub root_prefilter_needles: usize,
    pub root_prefilter_offset: Option<usize>,
    pub root_prefilter_guard_needles: usize,
    pub root_prefilter_guard_offset: Option<usize>,
    pub root_prefilter_classifier_selection: Option<SelectionReceipt>,
    pub work: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
    pub states: usize,
    pub transitions: usize,
    pub outputs: usize,
    pub allocations: usize,
}

/// Checked construction failure.
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
        write!(
            formatter,
            "folded literal trie construction failed: {self:?}"
        )
    }
}

impl std::error::Error for BuildError {}

/// Runtime-resource dimension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanResource {
    InputBytes,
    CandidateStarts,
    ScalarDecodes,
    DecodedScalars,
    InvalidBytes,
    SourceByteReads,
    TransitionProbes,
    CandidateEvents,
    Work,
    ScratchBytes,
}

/// Complete source-independent folded scan envelope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanUpperBounds {
    pub input_bytes: usize,
    pub candidate_starts: usize,
    pub scalar_decodes: usize,
    pub decoded_scalars: usize,
    pub invalid_bytes: usize,
    pub source_byte_reads: usize,
    pub transition_probes: usize,
    pub candidate_events: usize,
    pub work: usize,
    pub scratch_bytes: usize,
}

/// Actual committed folded scan counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanActual {
    pub input_bytes: usize,
    /// Scalar-start attempts on the complete path, or byte-anchor hits on the
    /// prefiltered path. Both are bounded by `input_bytes`.
    pub candidate_starts: usize,
    pub scalar_decodes: usize,
    pub decoded_scalars: usize,
    pub invalid_bytes: usize,
    pub source_byte_reads: usize,
    pub transition_probes: usize,
    pub candidate_events: usize,
    pub work: usize,
    pub scratch_bytes: usize,
}

/// Completed full folded scan receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanReceipt {
    pub upper: ScanUpperBounds,
    pub actual: ScanActual,
}

/// Terminal disposition of a density-aware leftmost search.
///
/// `DenseFallback` certifies that every candidate start before
/// `resume_start` was checked and did not match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the exact-block owner supersedes this retained one-candidate fallback"
)]
pub(crate) enum AdaptiveFindOutcome {
    Match(LiteralCandidate),
    NoMatch,
    DenseFallback { resume_start: usize },
}

/// Density-aware leftmost-search result with exact work already committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the exact-block owner supersedes this retained one-candidate fallback"
)]
pub(crate) struct AdaptiveFindResult {
    pub outcome: AdaptiveFindOutcome,
    pub receipt: ScanReceipt,
}

/// Terminal disposition of one ordered necessary-candidate search.
///
/// A candidate is only a source-derived necessary fixed-column hit. The
/// caller must still settle it with an authoritative matcher. `NoCandidate`
/// proves that the complete window contains no possible folded start, while a
/// a dense fixed-column guard rejection leaves an exact continuation at
/// `resume_start`. A union-successor rejection is already a cheap necessary
/// sentinel result and continues the ordered scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootCandidateOutcome {
    Candidate { start: usize },
    NoCandidate,
    DenseFallback { resume_start: usize },
}

/// One checked necessary-candidate result with exact committed work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootCandidateResult {
    pub outcome: RootCandidateOutcome,
    pub receipt: ScanReceipt,
}

/// Caller-selected folded scan limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanLimits {
    pub max_input_bytes: usize,
    pub max_candidate_starts: usize,
    pub max_scalar_decodes: usize,
    pub max_decoded_scalars: usize,
    pub max_invalid_bytes: usize,
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
            max_scalar_decodes: usize::MAX,
            max_decoded_scalars: usize::MAX,
            max_invalid_bytes: usize::MAX,
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
            max_scalar_decodes: 512 << 20,
            max_decoded_scalars: 512 << 20,
            max_invalid_bytes: 128 << 20,
            max_source_byte_reads: 2 << 30,
            max_transition_probes: 2 << 30,
            max_candidate_events: 512 << 20,
            max_work: 1 << 30,
            max_scratch_bytes: 0,
        }
    }
}

/// Checked folded scan failure.
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
        write!(formatter, "folded literal trie scan failed: {self:?}")
    }
}

impl std::error::Error for ScanError {}

/// Failure receipt. Preflight failures carry zero actual source effects.
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
    scalar: char,
    target: usize,
    next: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Output {
    pattern_index: usize,
    next: usize,
}

#[derive(Clone, Debug)]
struct RootPrefilter {
    needles: [u8; MEMCHR_ROOT_PREFILTER_NEEDLES],
    needle_count: u16,
    byte_set: [u64; ROOT_PREFILTER_BYTE_WORDS],
    classifier: Option<ByteBucketClassifier>,
    offset: u8,
    guard_byte_set: [u64; ROOT_PREFILTER_BYTE_WORDS],
    guard_needle_count: u16,
    guard_offset: u8,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RootPrefilterScanProgress {
    primary_reads: usize,
    correlated_reads: usize,
}

impl RootPrefilterScanProgress {
    fn source_byte_reads(self) -> Option<usize> {
        self.primary_reads.checked_add(self.correlated_reads)
    }
}

impl RootPrefilter {
    const fn has_guard(&self) -> bool {
        self.guard_needle_count != 0
    }

    fn primary_matches(&self, byte: u8) -> bool {
        byte_set_contains(self.byte_set, byte)
    }

    fn guard_matches(&self, byte: u8) -> bool {
        byte_set_contains(self.guard_byte_set, byte)
    }

    fn classifier_columns(&self) -> usize {
        self.classifier
            .as_ref()
            .map_or(1, |classifier| classifier.tables().columns())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the three memchr widths and retained full-byte classifier share one checked callback/error contract"
    )]
    #[inline(never)]
    fn scan<S>(
        &self,
        source: &[u8],
        invalid_actual: ScanActual,
        hit: &mut RootPrefilterHitState<'_, '_, '_, '_, S>,
    ) -> Result<RootPrefilterScanProgress, ScanAttemptError>
    where
        S: LiteralCandidateSink + ?Sized,
    {
        if usize::from(self.guard_needle_count) > ROOT_PREFILTER_BYTE_VALUES {
            return Err(ScanAttemptError {
                source: ScanError::Invariant {
                    detail: "folded root prefilter retained an invalid guard needle count",
                },
                actual: invalid_actual,
            });
        }
        match self.needle_count {
            1 => {
                for position in memchr_iter(self.needles[0], source) {
                    let scanned_through = position.checked_add(1).ok_or(ScanAttemptError {
                        source: ScanError::ArithmeticOverflow {
                            computation: "folded root prefilter scanned prefix",
                        },
                        actual: invalid_actual,
                    })?;
                    let progress = RootPrefilterScanProgress {
                        primary_reads: scanned_through,
                        correlated_reads: 0,
                    };
                    if !hit.on_hit(position, progress)? {
                        return Ok(progress);
                    }
                }
            }
            2 => {
                for position in memchr2_iter(self.needles[0], self.needles[1], source) {
                    let scanned_through = position.checked_add(1).ok_or(ScanAttemptError {
                        source: ScanError::ArithmeticOverflow {
                            computation: "folded root prefilter scanned prefix",
                        },
                        actual: invalid_actual,
                    })?;
                    let progress = RootPrefilterScanProgress {
                        primary_reads: scanned_through,
                        correlated_reads: 0,
                    };
                    if !hit.on_hit(position, progress)? {
                        return Ok(progress);
                    }
                }
            }
            3 => {
                for position in
                    memchr3_iter(self.needles[0], self.needles[1], self.needles[2], source)
                {
                    let scanned_through = position.checked_add(1).ok_or(ScanAttemptError {
                        source: ScanError::ArithmeticOverflow {
                            computation: "folded root prefilter scanned prefix",
                        },
                        actual: invalid_actual,
                    })?;
                    let progress = RootPrefilterScanProgress {
                        primary_reads: scanned_through,
                        correlated_reads: 0,
                    };
                    if !hit.on_hit(position, progress)? {
                        return Ok(progress);
                    }
                }
            }
            4..=256 => {
                let Some(classifier) = self.classifier else {
                    return Err(ScanAttemptError {
                        source: ScanError::Invariant {
                            detail: "wide folded root prefilter is missing its classifier",
                        },
                        actual: invalid_actual,
                    });
                };
                let columns = classifier.tables().columns();
                let mut block_start = 0_usize;
                let mut correlated_reads = 0_usize;
                if columns == 1 {
                    // Keep the optional-width decision and the full-width
                    // extent check out of the established one-column fallback
                    // loop. Empty screens also skip lane iteration entirely.
                    while let Some(masks) =
                        classifier.classify_first_16(&source[block_start..])
                    {
                        let scanned_through =
                            block_start.checked_add(16).ok_or(ScanAttemptError {
                                source: ScanError::ArithmeticOverflow {
                                    computation: "wide folded root prefilter scanned prefix",
                                },
                                actual: invalid_actual,
                            })?;
                        if masks.chunks() == [0, 0] {
                            block_start = scanned_through;
                            continue;
                        }
                        let progress = RootPrefilterScanProgress {
                            primary_reads: scanned_through,
                            correlated_reads: 0,
                        };
                        for (chunk_index, mut chunk) in masks.chunks().into_iter().enumerate() {
                            while chunk != 0 {
                                let lane = usize::try_from(chunk.trailing_zeros() / u8::BITS)
                                    .expect("a classified narrow lane fits in usize");
                                let position = chunk_index
                                    .checked_mul(8)
                                    .and_then(|offset| offset.checked_add(lane))
                                    .and_then(|offset| block_start.checked_add(offset))
                                    .ok_or(ScanAttemptError {
                                        source: ScanError::ArithmeticOverflow {
                                            computation: "wide folded root prefilter hit",
                                        },
                                        actual: invalid_actual,
                                    })?;
                                if !hit.on_hit(position, progress)? {
                                    return Ok(progress);
                                }
                                let shift = lane.checked_mul(8).ok_or(ScanAttemptError {
                                    source: ScanError::ArithmeticOverflow {
                                        computation: "wide folded root prefilter lane shift",
                                    },
                                    actual: invalid_actual,
                                })?;
                                let lane_mask = u64::from(u8::MAX)
                                    .checked_shl(u32::try_from(shift).map_err(|_| {
                                        ScanAttemptError {
                                            source: ScanError::ArithmeticOverflow {
                                                computation: "wide folded root prefilter lane shift",
                                            },
                                            actual: invalid_actual,
                                        }
                                    })?)
                                    .ok_or(ScanAttemptError {
                                        source: ScanError::ArithmeticOverflow {
                                            computation: "wide folded root prefilter lane mask",
                                        },
                                        actual: invalid_actual,
                                    })?;
                                chunk &= !lane_mask;
                            }
                        }
                        block_start = block_start.checked_add(16).ok_or(ScanAttemptError {
                            source: ScanError::ArithmeticOverflow {
                                computation: "wide folded root prefilter block start",
                            },
                            actual: invalid_actual,
                        })?;
                    }
                } else {
                    let required_input_bytes = classifier.tables().required_input_bytes();
                    while source
                        .len()
                        .checked_sub(block_start)
                        .is_some_and(|remaining| remaining >= required_input_bytes)
                    {
                        let scanned_through =
                            block_start.checked_add(16).ok_or(ScanAttemptError {
                                source: ScanError::ArithmeticOverflow {
                                    computation: "wide folded root prefilter scanned prefix",
                                },
                                actual: invalid_actual,
                            })?;
                        let screening = classifier
                            .classify_first_16(&source[block_start..])
                            .ok_or(ScanAttemptError {
                                source: ScanError::Invariant {
                                    detail: "wide folded root screen lost its block extent",
                                },
                                actual: invalid_actual,
                            })?;
                        if screening.chunks() == [0, 0] {
                            block_start = scanned_through;
                            continue;
                        }
                        let masks = classifier
                            .classify_16(&source[block_start..])
                            .ok_or(ScanAttemptError {
                                source: ScanError::Invariant {
                                    detail: "wide folded root classifier lost its correlated extent",
                                },
                                actual: invalid_actual,
                            })?;
                        let block_reads = BYTE_BUCKET_BLOCK_BYTES
                            .checked_mul(columns)
                            .ok_or(ScanAttemptError {
                                source: ScanError::ArithmeticOverflow {
                                    computation: "wide folded root correlated block reads",
                                },
                                actual: invalid_actual,
                            })?;
                        correlated_reads = correlated_reads.checked_add(block_reads).ok_or(
                            ScanAttemptError {
                                source: ScanError::ArithmeticOverflow {
                                    computation: "wide folded root correlated source reads",
                                },
                                actual: invalid_actual,
                            },
                        )?;
                        let progress = RootPrefilterScanProgress {
                            primary_reads: scanned_through,
                            correlated_reads,
                        };
                        for (chunk_index, mut chunk) in masks.chunks().into_iter().enumerate() {
                            while chunk != 0 {
                                let lane = usize::try_from(chunk.trailing_zeros() / u8::BITS)
                                    .expect("a classified narrow lane fits in usize");
                                let position = chunk_index
                                    .checked_mul(8)
                                    .and_then(|offset| offset.checked_add(lane))
                                    .and_then(|offset| block_start.checked_add(offset))
                                    .ok_or(ScanAttemptError {
                                        source: ScanError::ArithmeticOverflow {
                                            computation: "wide folded root prefilter hit",
                                        },
                                        actual: invalid_actual,
                                    })?;
                                if !hit.on_hit(position, progress)? {
                                    return Ok(progress);
                                }
                                let shift = lane.checked_mul(8).ok_or(ScanAttemptError {
                                    source: ScanError::ArithmeticOverflow {
                                        computation: "wide folded root prefilter lane shift",
                                    },
                                    actual: invalid_actual,
                                })?;
                                let lane_mask = u64::from(u8::MAX)
                                    .checked_shl(u32::try_from(shift).map_err(|_| {
                                        ScanAttemptError {
                                            source: ScanError::ArithmeticOverflow {
                                                computation: "wide folded root prefilter lane shift",
                                            },
                                            actual: invalid_actual,
                                        }
                                    })?)
                                    .ok_or(ScanAttemptError {
                                        source: ScanError::ArithmeticOverflow {
                                            computation: "wide folded root prefilter lane mask",
                                        },
                                        actual: invalid_actual,
                                    })?;
                                chunk &= !lane_mask;
                            }
                        }
                        block_start = block_start.checked_add(16).ok_or(ScanAttemptError {
                            source: ScanError::ArithmeticOverflow {
                                computation: "wide folded root prefilter block start",
                            },
                            actual: invalid_actual,
                        })?;
                    }
                }
                for (tail_offset, &byte) in source[block_start..].iter().enumerate() {
                    let primary_reads = block_start
                        .checked_add(tail_offset)
                        .and_then(|position| position.checked_add(1))
                        .ok_or(ScanAttemptError {
                            source: ScanError::ArithmeticOverflow {
                                computation: "wide folded root tail reads",
                            },
                            actual: invalid_actual,
                        })?;
                    if byte_set_contains(self.byte_set, byte) {
                        let position =
                            block_start
                                .checked_add(tail_offset)
                                .ok_or(ScanAttemptError {
                                    source: ScanError::ArithmeticOverflow {
                                        computation: "wide folded root prefilter tail hit",
                                    },
                                    actual: invalid_actual,
                                })?;
                        let progress = RootPrefilterScanProgress {
                            primary_reads,
                            correlated_reads,
                        };
                        if !hit.on_hit(position, progress)? {
                            return Ok(progress);
                        }
                    }
                }
                return Ok(RootPrefilterScanProgress {
                    primary_reads: source.len(),
                    correlated_reads,
                });
            }
            _ => {
                return Err(ScanAttemptError {
                    source: ScanError::Invariant {
                        detail: "folded root prefilter retained an invalid needle count",
                    },
                    actual: invalid_actual,
                });
            }
        }
        Ok(RootPrefilterScanProgress {
            primary_reads: source.len(),
            correlated_reads: 0,
        })
    }

    #[inline(never)]
    fn scan_value(&self, source: &[u8], hit: &mut ValueHitState<'_, '_>) {
        let first = match self.needle_count {
            1 => memchr(self.needles[0], source),
            2 => memchr2(self.needles[0], self.needles[1], source),
            3 => memchr3(self.needles[0], self.needles[1], self.needles[2], source),
            _ => unreachable!("value folded scan only admits memchr-width prefilters"),
        };
        let Some(first) = first else {
            return;
        };
        if !hit.on_hit(first) {
            return;
        }
        let Some(mut block_start) = first.checked_add(1) else {
            hit.declined = true;
            return;
        };
        let remaining = source.len().saturating_sub(block_start);
        let complete_bytes = remaining.saturating_sub(remaining % BYTE_SET_WIDE_BLOCK_BYTES);
        let Some(block_limit) = block_start.checked_add(complete_bytes) else {
            hit.declined = true;
            return;
        };
        while block_start < block_limit {
            let Some(block_end) = block_start.checked_add(BYTE_SET_WIDE_BLOCK_BYTES) else {
                hit.declined = true;
                return;
            };
            let Ok(block) =
                <&[u8; BYTE_SET_WIDE_BLOCK_BYTES]>::try_from(&source[block_start..block_end])
            else {
                hit.declined = true;
                return;
            };
            let mut members = match self.needle_count {
                1 => classify_byte_set1_32(self.needles[0], block).member_mask(),
                2 => classify_byte_set2_32([self.needles[0], self.needles[1]], block).member_mask(),
                3 => classify_byte_set3_32(
                    [self.needles[0], self.needles[1], self.needles[2]],
                    block,
                )
                .member_mask(),
                _ => unreachable!("value folded scan only admits memchr-width prefilters"),
            };
            while members != 0 {
                let lane = usize::try_from(members.trailing_zeros())
                    .expect("a 32-byte classifier lane fits usize");
                let Some(position) = block_start.checked_add(lane) else {
                    hit.declined = true;
                    return;
                };
                if !hit.on_hit(position) {
                    return;
                }
                members &= members.saturating_sub(1);
            }
            block_start = block_end;
        }
        for (tail_offset, &byte) in source[block_limit..].iter().enumerate() {
            if !self.primary_matches(byte) {
                continue;
            }
            let Some(position) = block_limit.checked_add(tail_offset) else {
                hit.declined = true;
                return;
            };
            if !hit.on_hit(position) {
                return;
            }
        }
    }
}

trait LiteralCandidateSink {
    fn emit_candidate(&mut self, candidate: LiteralCandidate);
}

impl<F> LiteralCandidateSink for F
where
    F: FnMut(LiteralCandidate),
{
    fn emit_candidate(&mut self, candidate: LiteralCandidate) {
        self(candidate);
    }
}

struct LeftmostFirstSink<'a> {
    selected: &'a mut Option<LiteralCandidate>,
    multiple_starts: &'a mut bool,
}

impl LiteralCandidateSink for LeftmostFirstSink<'_> {
    fn emit_candidate(&mut self, candidate: LiteralCandidate) {
        match *self.selected {
            None => *self.selected = Some(candidate),
            Some(best) if candidate.start() == best.start() => {
                if candidate.pattern_index() < best.pattern_index() {
                    *self.selected = Some(candidate);
                }
            }
            Some(_) => *self.multiple_starts = true,
        }
    }
}

/// Immutable exact-allocation sparse folded-scalar trie.
#[derive(Clone, Debug)]
pub struct FoldedLiteralTriePlan {
    nodes: ExactVec<Node>,
    edges: ExactVec<Edge>,
    outputs: ExactVec<Output>,
    root_prefilter: Option<RootPrefilter>,
    build: BuildAccounting,
}

impl FoldedLiteralTriePlan {
    /// Validate caller-canonicalized fold classes and construct one trie.
    ///
    /// Canonical classes must be non-empty, strictly scalar-sorted, and
    /// pairwise identical or disjoint. This validates representation only;
    /// the caller deriving HIR facts remains responsible for binding classes
    /// to the pinned Unicode simple-fold table.
    ///
    /// # Errors
    ///
    /// Returns checked resource/allocation/invariant errors. All resource
    /// limits are enforced before exact persistent allocation.
    #[cold]
    #[inline(never)]
    pub fn build(
        patterns: &[FoldedLiteral<'_>],
        limits: BuildLimits,
    ) -> Result<BuildAttempt, BuildError> {
        Self::build_with_dispatch(SimdDispatchContext::capture(), patterns, limits)
    }

    /// Construct one trie from a capability snapshot captured before the
    /// caller enters its bounded construction transaction.
    ///
    /// # Errors
    ///
    /// Returns checked resource/allocation/invariant errors. All resource
    /// limits are enforced before exact persistent allocation.
    #[allow(
        clippy::too_many_lines,
        reason = "bounded allocation, exact topology census, and receipt publication stay in one auditable transaction"
    )]
    #[cold]
    #[inline(never)]
    pub fn build_with_dispatch(
        dispatch: SimdDispatchContext,
        patterns: &[FoldedLiteral<'_>],
        limits: BuildLimits,
    ) -> Result<BuildAttempt, BuildError> {
        let mut prospective = preflight_from_lengths(patterns)?;
        enforce_build_limits(&prospective, limits)?;
        let (fallback, canonical_comparisons) = fallback_reason(patterns)?;
        if let Some(reason) = fallback {
            let mut accounting = prospective;
            accounting.canonical_comparisons = canonical_comparisons;
            accounting.work = canonical_comparisons;
            return Ok(BuildAttempt::DenseFallback(DenseFallback {
                reason,
                accounting,
            }));
        }
        // Base column selection and the one-column classifier are covered by
        // the already-enforced prospective. Charge either optional successor
        // derivation only after selection, then enforce it before successor
        // source work or allocation.
        let (root_prefilter_columns, root_prefilter_base_work) =
            select_root_prefilter_columns(patterns)?;
        let fingerprint_admitted = if root_prefilter_columns[0].is_some_and(|primary| {
            usize::from(primary.needle_count) > MEMCHR_ROOT_PREFILTER_NEEDLES
        }) {
            admit_root_prefilter_fingerprint(&mut prospective, limits.max_work)?
        } else {
            false
        };
        if root_prefilter_columns[0].is_some_and(|primary| {
            usize::from(primary.needle_count) <= MEMCHR_ROOT_PREFILTER_NEEDLES
        }) {
            admit_root_prefilter_successor(&mut prospective)?;
            enforce_build_limits(&prospective, limits)?;
        } else if fingerprint_admitted {
            enforce_build_limits(&prospective, limits)?;
        }
        let (root_prefilter, root_prefilter_work) = materialize_root_prefilter(
            dispatch,
            patterns,
            root_prefilter_columns,
            root_prefilter_base_work,
            fingerprint_admitted,
        )?;
        build_probe::record_allocation_attempt();
        let mut nodes =
            ExactVec::try_with_capacity(prospective.states_upper_bound).map_err(|error| {
                map_copy_error(error, "folded trie states", prospective.states_upper_bound)
            })?;
        build_probe::record_allocation_attempt();
        let mut edges =
            ExactVec::try_with_capacity(prospective.transitions_upper_bound).map_err(|error| {
                map_copy_error(
                    error,
                    "folded trie transitions",
                    prospective.transitions_upper_bound,
                )
            })?;
        build_probe::record_allocation_attempt();
        let mut outputs = ExactVec::try_with_capacity(prospective.patterns)
            .map_err(|error| map_copy_error(error, "folded trie outputs", prospective.patterns))?;
        let mut work = canonical_comparisons;
        let mut insertion_probes = 0_usize;
        let mut max_state_fanout = 0_usize;
        push_exact(&mut nodes, Node::EMPTY, "folded root state")?;
        work = checked_build_add(work, 1, "folded root work")?;
        for (pattern_index, pattern) in patterns.iter().enumerate() {
            work = checked_build_add(work, 1, "folded pattern work")?;
            let mut state = 0_usize;
            for class in pattern.classes {
                work = checked_build_add(work, 1, "folded scalar-position work")?;
                state = insert_class(
                    &mut nodes,
                    &mut edges,
                    state,
                    class.equivalents,
                    &mut insertion_probes,
                    &mut max_state_fanout,
                    &mut work,
                )?;
            }
            append_output(&mut nodes, &mut outputs, state, pattern_index)?;
            work = checked_build_add(work, 1, "folded output work")?;
        }
        let mut build = prospective;
        build.canonical_comparisons = canonical_comparisons;
        build.insertion_probes = insertion_probes;
        build.max_state_fanout = max_state_fanout;
        build.work = work;
        build.states = nodes.len();
        build.transitions = edges.len();
        build.outputs = outputs.len();
        build.allocations = usize::from(nodes.capacity() != 0)
            .checked_add(usize::from(edges.capacity() != 0))
            .and_then(|count| count.checked_add(usize::from(outputs.capacity() != 0)))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded trie allocation count",
            })?;
        build.persistent_bytes =
            exact_retained_bytes(nodes.capacity(), edges.capacity(), outputs.capacity())?;
        build.peak_bytes = build.persistent_bytes;
        work = checked_build_add(
            work,
            root_prefilter_work,
            "folded root prefilter selection work",
        )?;
        build.root_prefilter_work = root_prefilter_work;
        build.root_prefilter_needles = root_prefilter
            .as_ref()
            .map_or(0, |prefilter| usize::from(prefilter.needle_count));
        build.root_prefilter_offset = root_prefilter
            .as_ref()
            .map(|prefilter| usize::from(prefilter.offset));
        build.root_prefilter_guard_needles = root_prefilter
            .as_ref()
            .map_or(0, |prefilter| usize::from(prefilter.guard_needle_count));
        build.root_prefilter_guard_offset = root_prefilter
            .as_ref()
            .filter(|prefilter| prefilter.has_guard())
            .map(|prefilter| usize::from(prefilter.guard_offset));
        build.root_prefilter_classifier_selection = root_prefilter
            .as_ref()
            .and_then(|prefilter| prefilter.classifier.as_ref())
            .map(ByteBucketClassifier::selection);
        build.work = work;
        if !build_actual_within(&build) {
            return Err(BuildError::Invariant {
                detail: "folded construction actual exceeded prospective",
            });
        }
        Ok(BuildAttempt::Admitted(Self {
            nodes,
            edges,
            outputs,
            root_prefilter,
            build,
        }))
    }

    /// Stable emission order.
    #[must_use]
    pub const fn emission_order(&self) -> CandidateEmissionOrder {
        CandidateEmissionOrder::StartEndPattern
    }

    /// Exact construction certificate.
    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[cfg(test)]
    fn root_prefilter_classifier_columns(&self) -> usize {
        self.root_prefilter
            .as_ref()
            .and_then(|prefilter| prefilter.classifier.as_ref())
            .map_or(0, |classifier| classifier.tables().columns())
    }

    /// Authenticate that the retained root columns are necessary for every
    /// exact byte pattern owned by an attaching authoritative matcher.
    pub(crate) fn root_prefilter_is_necessary_for(
        &self,
        patterns: &[Vec<u8>],
    ) -> bool {
        let Some(prefilter) = self.root_prefilter.as_ref() else {
            return false;
        };
        !patterns.is_empty()
            && patterns.iter().all(|pattern| {
                let bytes = pattern.as_slice();
                bytes
                    .get(usize::from(prefilter.offset))
                    .is_some_and(|&byte| byte_set_contains(prefilter.byte_set, byte))
                    && prefilter.classifier.as_ref().is_none_or(|classifier| {
                        bytes
                            .get(usize::from(prefilter.offset)..)
                            .and_then(|prefix| classifier.classify_prefix(prefix))
                            .is_some_and(|buckets| buckets != 0)
                    })
                    && (!prefilter.has_guard()
                        || bytes
                            .get(usize::from(prefilter.guard_offset))
                            .is_some_and(|&byte| {
                                byte_set_contains(prefilter.guard_byte_set, byte)
                            }))
            })
    }

    /// Derive the exact linear envelope for one necessary-root pass.
    ///
    /// A correlated classifier first screens column zero, then reads all
    /// retained columns only for a screen-positive block. A retained guard
    /// reads at most one byte for each primary position. The fixed columns at
    /// the first exact start may also be read once before the classifier. The
    /// attaching matcher has already authenticated that every retained fixed
    /// column is necessary and lies within `max_pattern_bytes`.
    pub(crate) fn root_candidate_single_pass_upper_bounds(
        &self,
        input_bytes: usize,
        max_pattern_bytes: usize,
    ) -> Result<ScanUpperBounds, ScanError> {
        let Some(prefilter) = self.root_prefilter.as_ref() else {
            return Err(ScanError::Invariant {
                detail: "folded root-candidate envelope requires a retained root prefilter",
            });
        };
        let classifier_columns = prefilter.classifier_columns();
        if max_pattern_bytes == 0
            || usize::from(prefilter.offset)
                .checked_add(classifier_columns)
                .is_none_or(|end| end > max_pattern_bytes)
            || (prefilter.has_guard()
                && usize::from(prefilter.guard_offset) >= max_pattern_bytes)
        {
            return Err(ScanError::Invariant {
                detail: "folded root-candidate columns escaped the exact pattern width",
            });
        }
        let source_passes = classifier_columns
            .checked_add(usize::from(classifier_columns > 1))
            .and_then(|passes| passes.checked_add(usize::from(prefilter.has_guard())))
            .ok_or(ScanError::ArithmeticOverflow {
                computation: "folded root-candidate source passes",
            })?;
        let root_start_probe_reads = classifier_columns
            .checked_add(usize::from(prefilter.has_guard()))
            .ok_or(ScanError::ArithmeticOverflow {
                computation: "folded root-candidate start-probe reads",
            })?;
        let source_byte_reads = input_bytes
            .checked_mul(source_passes)
            .and_then(|reads| reads.checked_add(root_start_probe_reads))
            .ok_or(ScanError::ArithmeticOverflow {
                computation: "folded root-candidate source byte reads",
            })?;
        let candidate_starts = input_bytes;
        let work = candidate_starts.checked_add(source_byte_reads).ok_or(
            ScanError::ArithmeticOverflow {
                computation: "folded root-candidate work",
            },
        )?;
        Ok(ScanUpperBounds {
            input_bytes,
            candidate_starts,
            source_byte_reads,
            work,
            ..ScanUpperBounds::default()
        })
    }

    /// Derive a complete fixed-program linear envelope from input length only.
    ///
    /// Every successfully decoded scalar performs at most one transition
    /// lookup. A lookup follows only the current state's singly linked edge
    /// list, whose authenticated maximum length is `max_state_fanout`.
    /// Invalid decodes perform no lookup, so `scalar_decodes *
    /// max_state_fanout` also bounds their mixed valid/invalid execution.
    ///
    /// # Errors
    ///
    /// Returns checked arithmetic failures.
    pub fn scan_upper_bounds(&self, input_bytes: usize) -> Result<ScanUpperBounds, ScanError> {
        let candidate_starts = input_bytes;
        let scalar_decodes = checked_scan_mul(
            candidate_starts,
            self.build.max_pattern_scalars,
            "folded scalar decodes",
        )?;
        let decoded_scalars = scalar_decodes;
        let invalid_bytes = candidate_starts;
        let scalar_source_byte_reads = checked_scan_mul(
            scalar_decodes,
            MAX_UTF8_WIDTH,
            "folded scalar source byte reads",
        )?;
        let source_byte_reads = if self.root_prefilter.is_some() {
            let prefilter = self
                .root_prefilter
                .as_ref()
                .expect("the checked folded root prefilter remains present");
            let classifier_columns = prefilter.classifier_columns();
            let prefilter_passes = classifier_columns
                .checked_add(usize::from(classifier_columns > 1))
                .and_then(|passes| passes.checked_add(usize::from(prefilter.has_guard())))
                .ok_or(ScanError::ArithmeticOverflow {
                    computation: "folded root-prefilter pass count",
                })?;
            let prefilter_reads =
                input_bytes
                    .checked_mul(prefilter_passes)
                    .ok_or(ScanError::ArithmeticOverflow {
                        computation: "folded root-prefilter source byte reads",
                    })?;
            scalar_source_byte_reads
                .checked_add(prefilter_reads)
                .ok_or(ScanError::ArithmeticOverflow {
                    computation: "folded root-prefilter and scalar source byte reads",
                })?
        } else {
            scalar_source_byte_reads
        };
        let transition_probes = checked_scan_mul(
            scalar_decodes,
            self.build.max_state_fanout,
            "folded transition probes",
        )?;
        let candidate_events = checked_scan_mul(
            candidate_starts,
            self.build.patterns,
            "folded candidate events",
        )?;
        let event_work = checked_scan_mul(
            candidate_events,
            CANDIDATE_WORK,
            "folded candidate event work",
        )?;
        let work = candidate_starts
            .checked_add(source_byte_reads)
            .and_then(|sum| sum.checked_add(transition_probes))
            .and_then(|sum| sum.checked_add(event_work))
            .ok_or(ScanError::ArithmeticOverflow {
                computation: "folded scan work",
            })?;
        Ok(ScanUpperBounds {
            input_bytes,
            candidate_starts,
            scalar_decodes,
            decoded_scalars,
            invalid_bytes,
            source_byte_reads,
            transition_probes,
            candidate_events,
            work,
            scratch_bytes: 0,
        })
    }

    /// Emit every folded candidate wholly within `window`.
    ///
    /// The complete envelope and every caller limit are checked before the
    /// searched slice is formed. Invalid UTF-8 consumes one candidate-start
    /// byte and never traverses a trie edge.
    ///
    /// # Errors
    ///
    /// Returns a pre-source checked range/resource receipt or a checked
    /// internal-accounting receipt.
    pub fn scan_window<F>(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ScanLimits,
        emit: F,
    ) -> Result<ScanReceipt, ScanAttemptError>
    where
        F: FnMut(LiteralCandidate),
    {
        self.scan_window_mode(haystack, window, limits, ScanStop::Never, emit)
    }

    /// Return the leftmost candidate, breaking equal-start ties by source
    /// pattern order.
    ///
    /// The complete source-independent envelope and every caller limit are
    /// checked before source access. Execution stops after fully traversing
    /// the first candidate-bearing scalar start, so ordered alternatives at
    /// that start remain leftmost-first without scanning later starts.
    ///
    /// # Errors
    ///
    /// Returns the same checked range, resource and accounting failures as
    /// [`Self::scan_window`].
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ScanLimits,
    ) -> Result<(Option<LiteralCandidate>, ScanReceipt), ScanAttemptError> {
        let mut selected = None::<LiteralCandidate>;
        let mut order_violation = false;
        let receipt = self.scan_window_mode(
            haystack,
            window,
            limits,
            ScanStop::AfterMatchingStart,
            LeftmostFirstSink {
                selected: &mut selected,
                multiple_starts: &mut order_violation,
            },
        )?;
        if order_violation {
            return Err(ScanAttemptError {
                source: ScanError::Invariant {
                    detail: "first folded candidate group contained multiple starts",
                },
                actual: receipt.actual,
            });
        }
        Ok((selected, receipt))
    }

    /// Return the leftmost candidate without retaining successful execution
    /// accounting.
    ///
    /// Admitted memchr-width plans preserve the reporting path's complete
    /// pre-source envelope and refusal order, then verify candidate starts
    /// without updating diagnostic counters. Structurally unsupported plans
    /// and impossible value arithmetic decline to the reporting implementation
    /// so its exact partial-error receipt remains authoritative.
    ///
    /// # Errors
    ///
    /// Returns the same checked range, resource and accounting failures as
    /// [`Self::find_window`].
    #[inline]
    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ScanLimits,
    ) -> Result<Option<LiteralCandidate>, ScanAttemptError> {
        match self.scan_window_prefiltered_value(
            haystack,
            window,
            limits,
            ScanStop::AfterMatchingStart,
        )? {
            ValueScanAttempt::Complete(selected) => Ok(selected),
            ValueScanAttempt::Declined => self
                .find_window(haystack, window, limits)
                .map(|(selected, _)| selected),
        }
    }

    /// Find the leftmost candidate while bounding false-candidate density.
    ///
    /// The retained fixed-column prefilter visits candidate starts in byte
    /// order. When exact verification costs more than the byte distance since
    /// the previous candidate, this returns a certified continuation for an
    /// exact byte matcher. The decision has no corpus-selected threshold.
    #[cold]
    #[inline(never)]
    #[allow(
        dead_code,
        reason = "the exact-block owner supersedes this retained one-candidate fallback"
    )]
    pub(crate) fn find_window_adaptive_precharged(
        &self,
        haystack: &[u8],
        window: Window,
        upper: ScanUpperBounds,
    ) -> Result<AdaptiveFindResult, ScanAttemptError> {
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
        if upper.input_bytes != window.end().saturating_sub(window.start()) {
            return Err(ScanAttemptError {
                source: ScanError::Invariant {
                    detail: "adaptive folded precharge does not match its window",
                },
                actual: ScanActual::default(),
            });
        }

        scan_source_probe::record();
        let source = &haystack[window.start()..window.end()];
        let (outcome, mut actual) = execute_adaptive_find(self, source, window.start(), upper)?;
        let event_work = actual
            .candidate_events
            .checked_mul(CANDIDATE_WORK)
            .ok_or_else(|| attempt_overflow(upper, actual, "adaptive folded event work"))?;
        actual.work = actual
            .candidate_starts
            .checked_add(actual.source_byte_reads)
            .and_then(|sum| sum.checked_add(actual.transition_probes))
            .and_then(|sum| sum.checked_add(event_work))
            .ok_or_else(|| attempt_overflow(upper, actual, "adaptive folded work"))?;
        if !actual_within(actual, upper) {
            return Err(ScanAttemptError {
                source: ScanError::Invariant {
                    detail: "adaptive folded trie actual exceeded prospective",
                },
                actual,
            });
        }
        Ok(AdaptiveFindResult {
            outcome,
            receipt: ScanReceipt { upper, actual },
        })
    }

    /// Find the first guard-qualified necessary root candidate.
    ///
    /// This is a source-selection primitive, not a match operation. The
    /// caller supplies an exact precharge for this window and must settle a
    /// reported start with an authoritative matcher before returning it.
    #[cold]
    #[inline(never)]
    pub(crate) fn find_root_candidate_precharged(
        &self,
        haystack: &[u8],
        window: Window,
        upper: ScanUpperBounds,
    ) -> Result<RootCandidateResult, ScanAttemptError> {
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
        if upper.input_bytes < window.end().saturating_sub(window.start()) {
            return Err(ScanAttemptError {
                source: ScanError::Invariant {
                    detail: "folded root-candidate precharge does not cover its window",
                },
                actual: ScanActual::default(),
            });
        }

        #[cfg(test)]
        root_candidate_dispatch_probe::record();
        scan_source_probe::record();
        let source = &haystack[window.start()..window.end()];
        let (outcome, mut actual) =
            execute_root_candidate_find(self, source, window.start(), upper)?;
        actual.work = actual
            .candidate_starts
            .checked_add(actual.source_byte_reads)
            .ok_or_else(|| attempt_overflow(upper, actual, "folded root-candidate work"))?;
        if !actual_within(actual, upper) {
            return Err(ScanAttemptError {
                source: ScanError::Invariant {
                    detail: "folded root-candidate actual exceeded prospective",
                },
                actual,
            });
        }
        Ok(RootCandidateResult {
            outcome,
            receipt: ScanReceipt { upper, actual },
        })
    }

    /// Return whether any folded candidate exists, stopping on the first
    /// emitted candidate.
    ///
    /// # Errors
    ///
    /// Returns the same checked range, resource and accounting failures as
    /// [`Self::scan_window`].
    pub fn is_match_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ScanLimits,
    ) -> Result<(bool, ScanReceipt), ScanAttemptError> {
        let mut selected = None;
        let mut multiple_starts = false;
        let receipt = self.scan_window_mode(
            haystack,
            window,
            limits,
            ScanStop::AfterFirstEvent,
            LeftmostFirstSink {
                selected: &mut selected,
                multiple_starts: &mut multiple_starts,
            },
        )?;
        Ok((selected.is_some(), receipt))
    }

    /// Return whether any folded candidate exists without retaining
    /// successful execution accounting.
    ///
    /// # Errors
    ///
    /// Returns the same checked range, resource and accounting failures as
    /// [`Self::is_match_window`].
    #[inline]
    pub fn is_match_window_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ScanLimits,
    ) -> Result<bool, ScanAttemptError> {
        match self.scan_window_prefiltered_value(
            haystack,
            window,
            limits,
            ScanStop::AfterFirstEvent,
        )? {
            ValueScanAttempt::Complete(selected) => Ok(selected.is_some()),
            ValueScanAttempt::Declined => self
                .is_match_window(haystack, window, limits)
                .map(|(matched, _)| matched),
        }
    }

    fn scan_window_prefiltered_value(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ScanLimits,
        stop: ScanStop,
    ) -> Result<ValueScanAttempt, ScanAttemptError> {
        let Some(prefilter) = self.root_prefilter.as_ref() else {
            return Ok(ValueScanAttempt::Declined);
        };
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
                        computation: "folded window length",
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
        if !matches!(prefilter.needle_count, 1..=3)
            || usize::from(prefilter.guard_needle_count) > ROOT_PREFILTER_BYTE_VALUES
        {
            return Ok(ValueScanAttempt::Declined);
        }

        scan_source_probe::record();
        let source = &haystack[window.start()..window.end()];
        let mut state = ValueHitState {
            plan: self,
            source,
            absolute_base: window.start(),
            offset: usize::from(prefilter.offset),
            prefilter,
            stop,
            selected: None,
            declined: false,
        };
        prefilter.scan_value(source, &mut state);
        if state.declined {
            return Ok(ValueScanAttempt::Declined);
        }
        Ok(ValueScanAttempt::Complete(state.selected))
    }

    fn scan_window_mode<F>(
        &self,
        haystack: &[u8],
        window: Window,
        limits: ScanLimits,
        stop: ScanStop,
        mut emit: F,
    ) -> Result<ScanReceipt, ScanAttemptError>
    where
        F: LiteralCandidateSink,
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
                        computation: "folded window length",
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
        let mut actual = execute_folded_scan(self, source, window.start(), upper, stop, &mut emit)?;
        let event_work = actual
            .candidate_events
            .checked_mul(CANDIDATE_WORK)
            .ok_or_else(|| attempt_overflow(upper, actual, "actual folded event work"))?;
        actual.work = actual
            .candidate_starts
            .checked_add(actual.source_byte_reads)
            .and_then(|sum| sum.checked_add(actual.transition_probes))
            .and_then(|sum| sum.checked_add(event_work))
            .ok_or_else(|| attempt_overflow(upper, actual, "actual folded work"))?;
        if !actual_within(actual, upper) {
            return Err(ScanAttemptError {
                source: ScanError::Invariant {
                    detail: "folded trie actual exceeded prospective",
                },
                actual,
            });
        }
        Ok(ScanReceipt { upper, actual })
    }

    /// Emit every folded candidate in the complete haystack.
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

fn execute_folded_scan<F>(
    plan: &FoldedLiteralTriePlan,
    source: &[u8],
    absolute_base: usize,
    upper: ScanUpperBounds,
    stop: ScanStop,
    emit: &mut F,
) -> Result<ScanActual, ScanAttemptError>
where
    F: LiteralCandidateSink + ?Sized,
{
    execute_folded_scan_impl(
        plan,
        source,
        absolute_base,
        upper,
        plan.root_prefilter.as_ref(),
        stop,
        emit,
    )
}

struct AdaptiveHitState<'plan, 'source> {
    plan: &'plan FoldedLiteralTriePlan,
    source: &'source [u8],
    absolute_base: usize,
    upper: ScanUpperBounds,
    offset: usize,
    prefilter: &'plan RootPrefilter,
    actual: ScanActual,
    prefilter_source_reads: usize,
    previous_candidate_scanned_through: usize,
    outcome: AdaptiveFindOutcome,
}

impl AdaptiveHitState<'_, '_> {
    #[allow(
        clippy::too_many_lines,
        reason = "the outlined adaptive transaction preserves every accounting and fallback branch"
    )]
    #[inline(never)]
    fn on_hit(
        &mut self,
        hit: usize,
        progress: RootPrefilterScanProgress,
    ) -> Result<bool, ScanAttemptError> {
        let source_reads_through = progress.source_byte_reads().ok_or(ScanAttemptError {
            source: ScanError::ArithmeticOverflow {
                computation: "adaptive folded prefilter cumulative source reads",
            },
            actual: self.actual,
        })?;
        let additional_reads = source_reads_through
            .checked_sub(self.prefilter_source_reads)
            .ok_or(ScanAttemptError {
                source: ScanError::Invariant {
                    detail: "adaptive folded prefilter prefix moved backwards",
                },
                actual: self.actual,
            })?;
        self.actual.source_byte_reads = checked_actual_add(
            self.actual.source_byte_reads,
            additional_reads,
            self.upper,
            self.actual,
            "adaptive folded prefilter source reads",
        )?;
        self.prefilter_source_reads = source_reads_through;
        let Some(relative_start) = hit.checked_sub(self.offset) else {
            return Ok(true);
        };

        let verification_source_reads_before = self.actual.source_byte_reads;
        let verification_transition_probes_before = self.actual.transition_probes;
        let verification_candidate_starts_before = self.actual.candidate_starts;
        if self.prefilter.has_guard() {
            let Some(guard_position) =
                relative_start.checked_add(usize::from(self.prefilter.guard_offset))
            else {
                return Ok(true);
            };
            let Some(&guard_byte) = self.source.get(guard_position) else {
                return Ok(true);
            };
            self.actual.source_byte_reads = checked_actual_add(
                self.actual.source_byte_reads,
                1,
                self.upper,
                self.actual,
                "adaptive folded prefilter guard reads",
            )?;
            if !self.prefilter.guard_matches(guard_byte) {
                let guard_work = self
                    .actual
                    .source_byte_reads
                    .checked_sub(verification_source_reads_before)
                    .ok_or_else(|| {
                        attempt_overflow(
                            self.upper,
                            self.actual,
                            "adaptive guard verification work",
                        )
                    })?;
                let local_span = progress
                    .primary_reads
                    .checked_sub(self.previous_candidate_scanned_through)
                    .ok_or_else(|| {
                        attempt_overflow(self.upper, self.actual, "adaptive guard byte distance")
                    })?;
                self.previous_candidate_scanned_through = progress.primary_reads;
                if guard_work > local_span {
                    let resume_start = self
                        .absolute_base
                        .checked_add(relative_start)
                        .and_then(|start| start.checked_add(1))
                        .ok_or_else(|| {
                            attempt_overflow(
                                self.upper,
                                self.actual,
                                "adaptive guard DFA continuation",
                            )
                        })?;
                    self.outcome = AdaptiveFindOutcome::DenseFallback { resume_start };
                    return Ok(false);
                }
                return Ok(true);
            }
        }
        self.actual.candidate_starts = checked_actual_add(
            self.actual.candidate_starts,
            1,
            self.upper,
            self.actual,
            "adaptive folded candidate starts",
        )?;
        let mut selected = None::<LiteralCandidate>;
        let mut multiple_starts = false;
        let mut sink = LeftmostFirstSink {
            selected: &mut selected,
            multiple_starts: &mut multiple_starts,
        };
        let _ = scan_folded_start(
            self.plan,
            self.source,
            self.absolute_base,
            relative_start,
            self.upper,
            &mut self.actual,
            false,
            &mut sink,
        )?;
        if let Some(candidate) = selected {
            self.outcome = AdaptiveFindOutcome::Match(candidate);
            return Ok(false);
        }

        let verification_source_reads = self
            .actual
            .source_byte_reads
            .checked_sub(verification_source_reads_before)
            .ok_or_else(|| {
                attempt_overflow(
                    self.upper,
                    self.actual,
                    "adaptive verification source reads",
                )
            })?;
        let verification_transition_probes = self
            .actual
            .transition_probes
            .checked_sub(verification_transition_probes_before)
            .ok_or_else(|| {
                attempt_overflow(
                    self.upper,
                    self.actual,
                    "adaptive verification transition probes",
                )
            })?;
        let verification_candidate_starts = self
            .actual
            .candidate_starts
            .checked_sub(verification_candidate_starts_before)
            .ok_or_else(|| {
                attempt_overflow(
                    self.upper,
                    self.actual,
                    "adaptive verification candidate starts",
                )
            })?;
        let verification_work = verification_source_reads
            .checked_add(verification_transition_probes)
            .and_then(|work| work.checked_add(verification_candidate_starts))
            .ok_or_else(|| {
                attempt_overflow(self.upper, self.actual, "adaptive verification work")
            })?;
        let local_span = progress
            .primary_reads
            .checked_sub(self.previous_candidate_scanned_through)
            .ok_or_else(|| {
                attempt_overflow(self.upper, self.actual, "adaptive candidate byte distance")
            })?;
        self.previous_candidate_scanned_through = progress.primary_reads;
        if verification_work > local_span {
            let resume_start = self
                .absolute_base
                .checked_add(relative_start)
                .and_then(|start| start.checked_add(1))
                .ok_or_else(|| {
                    attempt_overflow(self.upper, self.actual, "adaptive DFA continuation")
                })?;
            self.outcome = AdaptiveFindOutcome::DenseFallback { resume_start };
            return Ok(false);
        }
        Ok(true)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "ordered prefilter traversal retains exact continuation and work accounting"
)]
#[cold]
#[inline(never)]
#[allow(
    dead_code,
    reason = "the exact-block owner supersedes this retained one-candidate fallback"
)]
fn execute_adaptive_find(
    plan: &FoldedLiteralTriePlan,
    source: &[u8],
    absolute_base: usize,
    upper: ScanUpperBounds,
) -> Result<(AdaptiveFindOutcome, ScanActual), ScanAttemptError> {
    let Some(prefilter) = plan.root_prefilter.as_ref() else {
        return Err(ScanAttemptError {
            source: ScanError::Invariant {
                detail: "adaptive folded scan requires a retained root prefilter",
            },
            actual: ScanActual::default(),
        });
    };
    let actual = ScanActual {
        input_bytes: source.len(),
        ..ScanActual::default()
    };
    let offset = usize::from(prefilter.offset);
    let invalid_actual = actual;
    let mut state = AdaptiveHitState {
        plan,
        source,
        absolute_base,
        upper,
        offset,
        prefilter,
        actual,
        prefilter_source_reads: 0,
        previous_candidate_scanned_through: 0,
        outcome: AdaptiveFindOutcome::NoMatch,
    };
    let completed_progress = {
        let mut hit_state: RootPrefilterHitState<'_, '_, '_, '_, LeftmostFirstSink<'_>> =
            RootPrefilterHitState::Adaptive(&mut state, PhantomData);
        prefilter.scan(source, invalid_actual, &mut hit_state)?
    };
    let completed_source_reads = completed_progress.source_byte_reads().ok_or(
        ScanAttemptError {
            source: ScanError::ArithmeticOverflow {
                computation: "adaptive folded prefilter completion cumulative reads",
            },
            actual: state.actual,
        },
    )?;
    let remaining_prefilter_reads = completed_source_reads
        .checked_sub(state.prefilter_source_reads)
        .ok_or(ScanAttemptError {
            source: ScanError::Invariant {
                detail: "adaptive folded prefilter completion moved backwards",
            },
            actual: state.actual,
        })?;
    state.actual.source_byte_reads = checked_actual_add(
        state.actual.source_byte_reads,
        remaining_prefilter_reads,
        upper,
        state.actual,
        "adaptive folded prefilter completion source reads",
    )?;
    Ok((state.outcome, state.actual))
}

struct RootCandidateHitState<'plan, 'source> {
    source: &'source [u8],
    absolute_base: usize,
    upper: ScanUpperBounds,
    offset: usize,
    prefilter: &'plan RootPrefilter,
    actual: ScanActual,
    prefilter_source_reads: usize,
    previous_candidate_scanned_through: usize,
    outcome: RootCandidateOutcome,
}

impl RootCandidateHitState<'_, '_> {
    #[inline(never)]
    fn on_hit(
        &mut self,
        hit: usize,
        progress: RootPrefilterScanProgress,
    ) -> Result<bool, ScanAttemptError> {
        let source_reads_through = progress.source_byte_reads().ok_or(ScanAttemptError {
            source: ScanError::ArithmeticOverflow {
                computation: "folded root-candidate cumulative source reads",
            },
            actual: self.actual,
        })?;
        let additional_reads = source_reads_through
            .checked_sub(self.prefilter_source_reads)
            .ok_or(ScanAttemptError {
                source: ScanError::Invariant {
                    detail: "folded root-candidate prefix moved backwards",
                },
                actual: self.actual,
            })?;
        self.actual.source_byte_reads = checked_actual_add(
            self.actual.source_byte_reads,
            additional_reads,
            self.upper,
            self.actual,
            "folded root-candidate prefilter source reads",
        )?;
        self.prefilter_source_reads = source_reads_through;
        let Some(relative_start) = hit.checked_sub(self.offset) else {
            return Ok(true);
        };

        let verification_source_reads_before = self.actual.source_byte_reads;
        if self.prefilter.has_guard() {
            let Some(guard_position) =
                relative_start.checked_add(usize::from(self.prefilter.guard_offset))
            else {
                return Ok(true);
            };
            let Some(&guard_byte) = self.source.get(guard_position) else {
                return Ok(true);
            };
            self.actual.source_byte_reads = checked_actual_add(
                self.actual.source_byte_reads,
                1,
                self.upper,
                self.actual,
                "folded root-candidate guard reads",
            )?;
            if !self.prefilter.guard_matches(guard_byte) {
                let guard_work = self
                    .actual
                    .source_byte_reads
                    .checked_sub(verification_source_reads_before)
                    .ok_or_else(|| {
                        attempt_overflow(
                            self.upper,
                            self.actual,
                            "folded root-candidate guard work",
                        )
                    })?;
                let local_span = progress
                    .primary_reads
                    .checked_sub(self.previous_candidate_scanned_through)
                    .ok_or_else(|| {
                        attempt_overflow(
                            self.upper,
                            self.actual,
                            "folded root-candidate guard byte distance",
                        )
                    })?;
                self.previous_candidate_scanned_through = progress.primary_reads;
                if guard_work > local_span {
                    let resume_start = self
                        .absolute_base
                        .checked_add(relative_start)
                        .and_then(|start| start.checked_add(1))
                        .ok_or_else(|| {
                            attempt_overflow(
                                self.upper,
                                self.actual,
                                "folded root-candidate guard continuation",
                            )
                        })?;
                    self.outcome = RootCandidateOutcome::DenseFallback { resume_start };
                    return Ok(false);
                }
                return Ok(true);
            }
        }
        self.actual.candidate_starts = checked_actual_add(
            self.actual.candidate_starts,
            1,
            self.upper,
            self.actual,
            "folded root-candidate starts",
        )?;
        let start = self
            .absolute_base
            .checked_add(relative_start)
            .ok_or_else(|| {
                attempt_overflow(
                    self.upper,
                    self.actual,
                    "folded root-candidate absolute start",
                )
            })?;
        self.outcome = RootCandidateOutcome::Candidate { start };
        Ok(false)
    }
}

fn execute_root_candidate_find(
    plan: &FoldedLiteralTriePlan,
    source: &[u8],
    absolute_base: usize,
    upper: ScanUpperBounds,
) -> Result<(RootCandidateOutcome, ScanActual), ScanAttemptError> {
    let Some(prefilter) = plan.root_prefilter.as_ref() else {
        return Err(ScanAttemptError {
            source: ScanError::Invariant {
                detail: "folded root-candidate search requires a retained root prefilter",
            },
            actual: ScanActual::default(),
        });
    };
    let mut actual = ScanActual {
        input_bytes: source.len(),
        ..ScanActual::default()
    };
    // The wide classifier reports even lane zero only after classifying its
    // complete first block. Settle that exact start from the retained
    // necessary columns. A rejection deliberately leaves the original source
    // and its alignment unchanged for the existing full-window scanner.
    let primary_offset = usize::from(prefilter.offset);
    if let Some(&primary_byte) = source.get(primary_offset) {
        let mut qualified = if let Some(classifier) = prefilter.classifier.as_ref()
            && classifier.tables().columns() > 1
            && source.len().saturating_sub(primary_offset) >= classifier.tables().columns()
        {
            actual.source_byte_reads = classifier.tables().columns();
            classifier
                .classify_prefix(&source[primary_offset..])
                .is_some_and(|buckets| buckets != 0)
        } else {
            actual.source_byte_reads = 1;
            prefilter.primary_matches(primary_byte)
        };
        if qualified && prefilter.has_guard() {
            qualified = false;
            if let Some(&guard_byte) = source.get(usize::from(prefilter.guard_offset)) {
                actual.source_byte_reads = actual.source_byte_reads.checked_add(1).ok_or(
                    ScanAttemptError {
                        source: ScanError::ArithmeticOverflow {
                            computation: "folded root-candidate start guard reads",
                        },
                        actual,
                    },
                )?;
                qualified = prefilter.guard_matches(guard_byte);
            }
        }
        if qualified {
            actual.candidate_starts = 1;
            return Ok((
                RootCandidateOutcome::Candidate {
                    start: absolute_base,
                },
                actual,
            ));
        }
    }
    let invalid_actual = actual;
    let mut state = RootCandidateHitState {
        source,
        absolute_base,
        upper,
        offset: usize::from(prefilter.offset),
        prefilter,
        actual,
        prefilter_source_reads: 0,
        previous_candidate_scanned_through: 0,
        outcome: RootCandidateOutcome::NoCandidate,
    };
    let completed_progress = {
        let mut hit_state: RootPrefilterHitState<'_, '_, '_, '_, LeftmostFirstSink<'_>> =
            RootPrefilterHitState::RootCandidate(&mut state, PhantomData);
        prefilter.scan(source, invalid_actual, &mut hit_state)?
    };
    let completed_source_reads = completed_progress.source_byte_reads().ok_or(
        ScanAttemptError {
            source: ScanError::ArithmeticOverflow {
                computation: "folded root-candidate completion cumulative reads",
            },
            actual: state.actual,
        },
    )?;
    let remaining_prefilter_reads = completed_source_reads
        .checked_sub(state.prefilter_source_reads)
        .ok_or(ScanAttemptError {
            source: ScanError::Invariant {
                detail: "folded root-candidate completion moved backwards",
            },
            actual: state.actual,
        })?;
    state.actual.source_byte_reads = checked_actual_add(
        state.actual.source_byte_reads,
        remaining_prefilter_reads,
        upper,
        state.actual,
        "folded root-candidate completion source reads",
    )?;
    Ok((state.outcome, state.actual))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanStop {
    Never,
    AfterMatchingStart,
    AfterFirstEvent,
}

enum ValueScanAttempt {
    Complete(Option<LiteralCandidate>),
    Declined,
}

impl ScanStop {
    const fn after_matching_start(self) -> bool {
        !matches!(self, Self::Never)
    }

    const fn after_first_event(self) -> bool {
        matches!(self, Self::AfterFirstEvent)
    }
}

struct IncumbentHitState<'plan, 'source, 'emit, S>
where
    S: LiteralCandidateSink + ?Sized,
{
    plan: &'plan FoldedLiteralTriePlan,
    source: &'source [u8],
    absolute_base: usize,
    upper: ScanUpperBounds,
    offset: usize,
    prefilter: &'plan RootPrefilter,
    actual: ScanActual,
    prefilter_source_reads: usize,
    stop: ScanStop,
    emit: &'emit mut S,
}

impl<S> IncumbentHitState<'_, '_, '_, S>
where
    S: LiteralCandidateSink + ?Sized,
{
    #[allow(
        clippy::inline_always,
        reason = "built-in operations share one static prefilter instantiation and avoid a call per hit"
    )]
    #[inline(always)]
    fn on_hit(
        &mut self,
        hit: usize,
        progress: RootPrefilterScanProgress,
    ) -> Result<bool, ScanAttemptError> {
        let source_reads_through = progress.source_byte_reads().ok_or(ScanAttemptError {
            source: ScanError::ArithmeticOverflow {
                computation: "folded root prefilter cumulative source reads",
            },
            actual: self.actual,
        })?;
        let additional_reads = source_reads_through
            .checked_sub(self.prefilter_source_reads)
            .ok_or(ScanAttemptError {
                source: ScanError::Invariant {
                    detail: "folded root prefilter scanned prefix moved backwards",
                },
                actual: self.actual,
            })?;
        self.actual.source_byte_reads = checked_actual_add(
            self.actual.source_byte_reads,
            additional_reads,
            self.upper,
            self.actual,
            "folded root-prefilter source reads",
        )?;
        self.prefilter_source_reads = source_reads_through;
        let Some(relative_start) = hit.checked_sub(self.offset) else {
            return Ok(true);
        };
        if self.prefilter.has_guard() {
            let Some(guard_position) =
                relative_start.checked_add(usize::from(self.prefilter.guard_offset))
            else {
                return Ok(true);
            };
            let Some(&guard_byte) = self.source.get(guard_position) else {
                return Ok(true);
            };
            self.actual.source_byte_reads = checked_actual_add(
                self.actual.source_byte_reads,
                1,
                self.upper,
                self.actual,
                "folded root-prefilter guard reads",
            )?;
            if !self.prefilter.guard_matches(guard_byte) {
                return Ok(true);
            }
        }
        self.actual.candidate_starts = checked_actual_add(
            self.actual.candidate_starts,
            1,
            self.upper,
            self.actual,
            "folded root-prefilter candidate starts",
        )?;
        let events_before = self.actual.candidate_events;
        let _ = scan_folded_start(
            self.plan,
            self.source,
            self.absolute_base,
            relative_start,
            self.upper,
            &mut self.actual,
            self.stop.after_first_event(),
            self.emit,
        )?;
        Ok(!self.stop.after_matching_start() || self.actual.candidate_events == events_before)
    }
}

struct ValueHitState<'plan, 'source> {
    plan: &'plan FoldedLiteralTriePlan,
    source: &'source [u8],
    absolute_base: usize,
    offset: usize,
    prefilter: &'plan RootPrefilter,
    stop: ScanStop,
    selected: Option<LiteralCandidate>,
    declined: bool,
}

impl ValueHitState<'_, '_> {
    #[inline(always)]
    fn on_hit(&mut self, hit: usize) -> bool {
        let Some(relative_start) = hit.checked_sub(self.offset) else {
            return true;
        };
        if self.prefilter.has_guard() {
            let Some(guard_position) =
                relative_start.checked_add(usize::from(self.prefilter.guard_offset))
            else {
                self.declined = true;
                return false;
            };
            let Some(&guard_byte) = self.source.get(guard_position) else {
                return true;
            };
            if !self.prefilter.guard_matches(guard_byte) {
                return true;
            }
        }
        let Some(selected) = scan_folded_start_value(
            self.plan,
            self.source,
            self.absolute_base,
            relative_start,
            self.stop.after_first_event(),
        ) else {
            self.declined = true;
            return false;
        };
        if let Some(selected) = selected {
            self.selected = Some(selected);
            return false;
        }
        true
    }
}

#[allow(
    dead_code,
    reason = "the enum retains the superseded adaptive verifier alongside exact blocks"
)]
enum RootPrefilterHitState<'state, 'plan, 'source, 'emit, S>
where
    S: LiteralCandidateSink + ?Sized,
{
    Incumbent(&'state mut IncumbentHitState<'plan, 'source, 'emit, S>),
    Adaptive(
        &'state mut AdaptiveHitState<'plan, 'source>,
        PhantomData<&'emit mut S>,
    ),
    RootCandidate(
        &'state mut RootCandidateHitState<'plan, 'source>,
        PhantomData<&'emit mut S>,
    ),
}

impl<S> RootPrefilterHitState<'_, '_, '_, '_, S>
where
    S: LiteralCandidateSink + ?Sized,
{
    #[inline(always)]
    fn on_hit(
        &mut self,
        hit: usize,
        progress: RootPrefilterScanProgress,
    ) -> Result<bool, ScanAttemptError> {
        match self {
            Self::Incumbent(state) => state.on_hit(hit, progress),
            Self::Adaptive(state, _) => state.on_hit(hit, progress),
            Self::RootCandidate(state, _) => state.on_hit(hit, progress),
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the scalar and prefetched paths share one exact early-stop accounting transaction"
)]
fn execute_folded_scan_impl<F>(
    plan: &FoldedLiteralTriePlan,
    source: &[u8],
    absolute_base: usize,
    upper: ScanUpperBounds,
    root_prefilter: Option<&RootPrefilter>,
    stop: ScanStop,
    emit: &mut F,
) -> Result<ScanActual, ScanAttemptError>
where
    F: LiteralCandidateSink + ?Sized,
{
    let mut actual = ScanActual {
        input_bytes: source.len(),
        ..ScanActual::default()
    };
    if let Some(prefilter) = root_prefilter {
        let invalid_actual = actual;
        let mut state = IncumbentHitState {
            plan,
            source,
            absolute_base,
            upper,
            offset: usize::from(prefilter.offset),
            prefilter,
            actual,
            prefilter_source_reads: 0,
            stop,
            emit,
        };
        let completed_progress = {
            let mut hit_state = RootPrefilterHitState::Incumbent(&mut state);
            prefilter.scan(source, invalid_actual, &mut hit_state)?
        };
        let completed_source_reads = completed_progress.source_byte_reads().ok_or(
            ScanAttemptError {
                source: ScanError::ArithmeticOverflow {
                    computation: "folded root-prefilter completion cumulative reads",
                },
                actual: state.actual,
            },
        )?;
        let remaining_prefilter_reads = completed_source_reads
            .checked_sub(state.prefilter_source_reads)
            .ok_or(ScanAttemptError {
                source: ScanError::Invariant {
                    detail: "folded root prefilter completion moved backwards",
                },
                actual: state.actual,
            })?;
        state.actual.source_byte_reads = checked_actual_add(
            state.actual.source_byte_reads,
            remaining_prefilter_reads,
            upper,
            state.actual,
            "folded root-prefilter completion source reads",
        )?;
        return Ok(state.actual);
    }
    let mut relative_start = 0_usize;
    while relative_start < source.len() {
        actual.candidate_starts = checked_actual_add(
            actual.candidate_starts,
            1,
            upper,
            actual,
            "folded candidate starts",
        )?;
        let events_before = actual.candidate_events;
        let advance = scan_folded_start(
            plan,
            source,
            absolute_base,
            relative_start,
            upper,
            &mut actual,
            stop.after_first_event(),
            emit,
        )?;
        if stop.after_matching_start() && actual.candidate_events != events_before {
            break;
        }
        relative_start = relative_start
            .checked_add(advance)
            .ok_or_else(|| attempt_overflow(upper, actual, "next folded candidate start"))?;
    }
    Ok(actual)
}

#[derive(Clone, Copy)]
struct PrefilterColumn {
    needles: [u8; MEMCHR_ROOT_PREFILTER_NEEDLES],
    needle_count: u16,
    byte_set: [u64; ROOT_PREFILTER_BYTE_WORDS],
    high_nibbles: u16,
    offset: u8,
    scalar_index: usize,
    local_offset: u8,
    structural_leads: usize,
    frequency_score: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootGuardCandidate {
    byte_set: [u64; ROOT_PREFILTER_BYTE_WORDS],
    needle_count: u16,
    offset: u8,
    structural_leads: usize,
    frequency_score: u64,
}

impl RootGuardCandidate {
    const fn fixed(column: PrefilterColumn) -> Self {
        Self {
            byte_set: column.byte_set,
            needle_count: column.needle_count,
            offset: column.offset,
            structural_leads: column.structural_leads,
            frequency_score: column.frequency_score,
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one allocation-free traversal keeps base fixed-column derivation, ranking and exact work accounting visibly coupled"
)]
#[cold]
#[inline(never)]
fn select_root_prefilter_columns(
    patterns: &[FoldedLiteral<'_>],
) -> Result<([Option<PrefilterColumn>; 2], usize), BuildError> {
    if patterns.is_empty() {
        return Err(BuildError::Invariant {
            detail: "folded prefilter language is empty",
        });
    }
    let mut selected = [None::<PrefilterColumn>; 2];
    let mut work = 0_usize;
    let mut absolute_offset = 0_usize;
    let mut scalar_index = 0_usize;
    'positions: loop {
        for pattern in patterns {
            if pattern.classes.get(scalar_index).is_none() {
                break 'positions;
            }
        }
        let mut fixed_width = None;
        for local_offset in 0..MAX_UTF8_WIDTH {
            work = checked_build_add(
                work,
                ROOT_PREFILTER_OFFSET_WORK,
                "folded root prefilter offset work",
            )?;
            let mut needles = [0_u8; MEMCHR_ROOT_PREFILTER_NEEDLES];
            let mut needle_count = 0_usize;
            let mut byte_set = [0_u64; ROOT_PREFILTER_BYTE_WORDS];
            let mut high_nibbles = 0_u16;
            let mut eligible = true;
            for pattern in patterns {
                let class = pattern
                    .classes
                    .get(scalar_index)
                    .ok_or(BuildError::Invariant {
                        detail: "folded prefilter position disappeared",
                    })?;
                for &scalar in class.equivalents {
                    work = checked_build_add(
                        work,
                        ROOT_PREFILTER_EDGE_WORK,
                        "folded root prefilter edge work",
                    )?;
                    let mut encoded = [0_u8; MAX_UTF8_WIDTH];
                    let bytes = scalar.encode_utf8(&mut encoded).as_bytes();
                    if local_offset == 0 {
                        if fixed_width.is_some_and(|width| width != bytes.len()) {
                            fixed_width = Some(0);
                        } else if fixed_width.is_none() {
                            fixed_width = Some(bytes.len());
                        }
                    }
                    let Some(&needle) = bytes.get(local_offset) else {
                        eligible = false;
                        continue;
                    };
                    if !byte_set_contains(byte_set, needle) {
                        byte_set_insert(&mut byte_set, needle);
                        high_nibbles |= 1_u16 << (needle >> 4);
                        if needle_count < MEMCHR_ROOT_PREFILTER_NEEDLES {
                            needles[needle_count] = needle;
                        }
                        needle_count =
                            needle_count
                                .checked_add(1)
                                .ok_or(BuildError::ArithmeticOverflow {
                                    computation: "folded root prefilter needle count",
                                })?;
                    }
                }
            }
            if !eligible || needle_count == 0 {
                continue;
            }
            if needle_count > MEMCHR_ROOT_PREFILTER_NEEDLES
                && high_nibbles.count_ones()
                    > u32::try_from(ROOT_PREFILTER_BUCKETS)
                        .expect("the fixed bucket count fits in u32")
            {
                continue;
            }
            let Some(offset) = absolute_offset.checked_add(local_offset) else {
                return Err(BuildError::ArithmeticOverflow {
                    computation: "folded root prefilter absolute offset",
                });
            };
            let Ok(offset) = u8::try_from(offset) else {
                continue;
            };
            let mut structural_leads = 0_usize;
            let mut frequency_score = 0_u64;
            for (word_index, mut word) in byte_set.into_iter().enumerate() {
                while word != 0 {
                    let bit = usize::try_from(word.trailing_zeros())
                        .expect("a byte-set bit position fits in usize");
                    let needle_index = word_index
                        .checked_mul(ROOT_PREFILTER_WORD_BITS)
                        .and_then(|base| base.checked_add(bit))
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "folded root prefilter byte-set member",
                        })?;
                    let needle = u8::try_from(needle_index).expect("a byte-set member fits in u8");
                    word &= word.checked_sub(1).expect("the byte-set word is nonzero");
                    work = checked_build_add(
                        work,
                        ROOT_PREFILTER_NEEDLE_WORK,
                        "folded root prefilter needle work",
                    )?;
                    structural_leads = structural_leads
                        .checked_add(usize::from(matches!(needle, 0xC2..=0xF4)))
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "folded root prefilter structural leads",
                        })?;
                    frequency_score = frequency_score
                        .checked_add(u64::from(byte_frequency_rank(needle)).saturating_add(1))
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "folded root prefilter frequency score",
                        })?;
                }
            }
            if structural_leads == needle_count {
                continue;
            }
            record_prefilter_column(
                &mut selected,
                PrefilterColumn {
                    needles,
                    needle_count: u16::try_from(needle_count).map_err(|_| {
                        BuildError::Invariant {
                            detail: "folded root prefilter needle count does not fit u16",
                        }
                    })?,
                    byte_set,
                    high_nibbles,
                    offset,
                    scalar_index,
                    local_offset: u8::try_from(local_offset)
                        .expect("a UTF-8 byte offset fits in u8"),
                    structural_leads,
                    frequency_score,
                },
            );
        }
        if fixed_width == Some(0) {
            break;
        }
        let Some(width) = fixed_width else {
            return Err(BuildError::Invariant {
                detail: "folded root prefilter class has no width",
            });
        };
        absolute_offset =
            absolute_offset
                .checked_add(width)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "folded root prefilter prefix width",
                })?;
        scalar_index = scalar_index
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded root prefilter scalar index",
            })?;
    }
    Ok((selected, work))
}

#[cold]
#[inline(never)]
fn materialize_root_prefilter(
    dispatch: SimdDispatchContext,
    patterns: &[FoldedLiteral<'_>],
    selected: [Option<PrefilterColumn>; 2],
    mut work: usize,
    fingerprint_admitted: bool,
) -> Result<(Option<RootPrefilter>, usize), BuildError> {
    let root_prefilter = if let Some(primary) = selected[0] {
        let mut guard = selected[1].map(RootGuardCandidate::fixed);
        // Scalar successor checks amortize naturally over memchr's ordered
        // hits. A wide root already owns a block classifier; retaining a
        // scalar successor there would turn rejected lanes back into callback
        // traffic. That shape belongs in a fused multi-column classifier.
        if usize::from(primary.needle_count) <= MEMCHR_ROOT_PREFILTER_NEEDLES {
            if let Some(successor) = derive_union_successor_guard(patterns, primary, &mut work)? {
                if guard.is_none_or(|fixed| {
                    successor_guard_is_better(successor, fixed, primary.offset)
                }) {
                    guard = Some(successor);
                }
            }
        }
        let classifier = if usize::from(primary.needle_count) > MEMCHR_ROOT_PREFILTER_NEEDLES {
            let (classifier, retained_guard, classifier_work) = root_prefilter_classifier(
                dispatch,
                patterns,
                primary,
                guard,
                fingerprint_admitted,
            )?;
            guard = retained_guard;
            work = checked_build_add(
                work,
                classifier_work,
                "folded root prefilter classifier work",
            )?;
            Some(classifier)
        } else {
            None
        };
        Some(RootPrefilter {
            needles: primary.needles,
            needle_count: primary.needle_count,
            byte_set: primary.byte_set,
            classifier,
            offset: primary.offset,
            guard_byte_set: guard.map_or([0; ROOT_PREFILTER_BYTE_WORDS], |guard| guard.byte_set),
            guard_needle_count: guard.map_or(0, |guard| guard.needle_count),
            guard_offset: guard.map_or(0, |guard| guard.offset),
        })
    } else {
        None
    };
    Ok((root_prefilter, work))
}

fn record_prefilter_column(
    selected: &mut [Option<PrefilterColumn>; 2],
    candidate: PrefilterColumn,
) {
    if selected[0].is_none_or(|best| prefilter_column_is_better(candidate, best)) {
        selected[1] = selected[0];
        selected[0] = Some(candidate);
    } else if selected[1].is_none_or(|best| prefilter_column_is_better(candidate, best)) {
        selected[1] = Some(candidate);
    }
}

fn prefilter_column_is_better(candidate: PrefilterColumn, incumbent: PrefilterColumn) -> bool {
    (
        candidate.structural_leads,
        candidate.frequency_score,
        core::cmp::Reverse(candidate.offset),
    ) < (
        incumbent.structural_leads,
        incumbent.frequency_score,
        core::cmp::Reverse(incumbent.offset),
    )
}

fn successor_guard_is_better(
    candidate: RootGuardCandidate,
    incumbent: RootGuardCandidate,
    primary_offset: u8,
) -> bool {
    let candidate_score = (candidate.structural_leads, candidate.frequency_score);
    let incumbent_score = (incumbent.structural_leads, incumbent.frequency_score);
    candidate_score < incumbent_score
        || (candidate_score == incumbent_score
            && candidate.offset.abs_diff(primary_offset)
                < incumbent.offset.abs_diff(primary_offset))
}

/// Derive one unconditional necessary byte column after the selected primary.
///
/// Each retained set is the union at one byte distance over every folded
/// expansion of every pattern. Keeping the columns independent deliberately
/// admits their cross-product: it can create false positives, but cannot
/// reject a real folded expansion. Only the best selective column is retained,
/// so runtime still reads at most one guard byte per primary hit.
fn derive_union_successor_guard(
    patterns: &[FoldedLiteral<'_>],
    primary: PrefilterColumn,
    work: &mut usize,
) -> Result<Option<RootGuardCandidate>, BuildError> {
    #[cfg(test)]
    build_probe::record_successor_attempt();
    let mut selected = None::<RootGuardCandidate>;
    for distance in 1..=MAX_UTF8_WIDTH {
        *work = checked_build_add(
            *work,
            ROOT_PREFILTER_OFFSET_WORK,
            "folded root successor offset work",
        )?;
        let Some(offset) = usize::from(primary.offset).checked_add(distance) else {
            return Err(BuildError::ArithmeticOverflow {
                computation: "folded root successor absolute offset",
            });
        };
        let Ok(offset) = u8::try_from(offset) else {
            continue;
        };
        let mut byte_set = [0_u64; ROOT_PREFILTER_BYTE_WORDS];
        let mut necessary = true;
        for pattern in patterns {
            if !collect_union_successor_bytes(
                *pattern,
                primary.scalar_index,
                usize::from(primary.local_offset),
                distance,
                &mut byte_set,
                work,
            )? {
                necessary = false;
                break;
            }
        }
        if !necessary {
            continue;
        }
        let Some(candidate) = union_successor_guard_candidate(byte_set, offset, work)? else {
            continue;
        };
        if selected.is_none_or(|best| {
            successor_guard_is_better(candidate, best, primary.offset)
        }) {
            selected = Some(candidate);
        }
    }
    Ok(selected)
}

fn collect_union_successor_bytes(
    pattern: FoldedLiteral<'_>,
    primary_scalar_index: usize,
    primary_local_offset: usize,
    distance: usize,
    byte_set: &mut [u64; ROOT_PREFILTER_BYTE_WORDS],
    work: &mut usize,
) -> Result<bool, BuildError> {
    let primary_class = pattern
        .classes
        .get(primary_scalar_index)
        .ok_or(BuildError::Invariant {
            detail: "folded root successor primary position disappeared",
        })?;
    let target_offset = primary_local_offset
        .checked_add(distance)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root successor target offset",
        })?;
    let mut remaining_offsets = 0_u8;
    for &scalar in primary_class.equivalents {
        *work = checked_build_add(
            *work,
            ROOT_PREFILTER_EDGE_WORK,
            "folded root successor primary edge work",
        )?;
        let mut encoded = [0_u8; MAX_UTF8_WIDTH];
        let bytes = scalar.encode_utf8(&mut encoded).as_bytes();
        if let Some(&byte) = bytes.get(target_offset) {
            byte_set_insert(byte_set, byte);
            continue;
        }
        let remaining = target_offset
            .checked_sub(bytes.len())
            .ok_or(BuildError::Invariant {
                detail: "folded root successor target moved before its primary scalar",
            })?;
        if remaining >= MAX_UTF8_WIDTH {
            return Err(BuildError::Invariant {
                detail: "folded root successor frontier escaped its bounded distance",
            });
        }
        remaining_offsets |= 1_u8 << remaining;
    }

    let mut scalar_index = primary_scalar_index
        .checked_add(1)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root successor scalar index",
        })?;
    while remaining_offsets != 0 {
        let Some(class) = pattern.classes.get(scalar_index) else {
            return Ok(false);
        };
        let mut next_offsets = 0_u8;
        let mut offsets = remaining_offsets;
        while offsets != 0 {
            let remaining = usize::try_from(offsets.trailing_zeros())
                .expect("a bounded successor offset fits in usize");
            offsets &= offsets.wrapping_sub(1);
            for &scalar in class.equivalents {
                *work = checked_build_add(
                    *work,
                    ROOT_PREFILTER_EDGE_WORK,
                    "folded root successor frontier edge work",
                )?;
                let mut encoded = [0_u8; MAX_UTF8_WIDTH];
                let bytes = scalar.encode_utf8(&mut encoded).as_bytes();
                if let Some(&byte) = bytes.get(remaining) {
                    byte_set_insert(byte_set, byte);
                    continue;
                }
                let next = remaining
                    .checked_sub(bytes.len())
                    .ok_or(BuildError::Invariant {
                        detail: "folded root successor frontier moved backwards",
                    })?;
                if next >= MAX_UTF8_WIDTH {
                    return Err(BuildError::Invariant {
                        detail: "folded root successor frontier exceeded its bounded distance",
                    });
                }
                next_offsets |= 1_u8 << next;
            }
        }
        remaining_offsets = next_offsets;
        scalar_index = scalar_index
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded root successor following scalar index",
            })?;
    }
    Ok(true)
}

fn union_successor_guard_candidate(
    byte_set: [u64; ROOT_PREFILTER_BYTE_WORDS],
    offset: u8,
    work: &mut usize,
) -> Result<Option<RootGuardCandidate>, BuildError> {
    let mut needle_count = 0_usize;
    let mut structural_leads = 0_usize;
    let mut frequency_score = 0_u64;
    let mut high_nibbles = 0_u16;
    for needle in byte_set_members(byte_set) {
        *work = checked_build_add(
            *work,
            ROOT_PREFILTER_NEEDLE_WORK,
            "folded root successor needle work",
        )?;
        needle_count = needle_count
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded root successor needle count",
            })?;
        structural_leads = structural_leads
            .checked_add(usize::from(matches!(needle, 0xC2..=0xF4)))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded root successor structural leads",
            })?;
        frequency_score = frequency_score
            .checked_add(u64::from(byte_frequency_rank(needle)).saturating_add(1))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded root successor frequency score",
            })?;
        high_nibbles |= 1_u16 << (needle >> 4);
    }
    if needle_count == 0
        || needle_count == ROOT_PREFILTER_BYTE_VALUES
        || needle_count > ROOT_PREFILTER_BUCKETS
        || structural_leads == needle_count
        || (needle_count > MEMCHR_ROOT_PREFILTER_NEEDLES
            && high_nibbles.count_ones()
                > u32::try_from(ROOT_PREFILTER_BUCKETS)
                    .expect("the fixed bucket count fits in u32"))
    {
        return Ok(None);
    }
    Ok(Some(RootGuardCandidate {
        byte_set,
        needle_count: u16::try_from(needle_count).map_err(|_| BuildError::Invariant {
            detail: "folded root successor needle count does not fit u16",
        })?,
        offset,
        structural_leads,
        frequency_score,
    }))
}

fn byte_set_insert(set: &mut [u64; ROOT_PREFILTER_BYTE_WORDS], byte: u8) {
    let index = usize::from(byte >> 6);
    let bit = usize::from(byte & 0x3F);
    set[index] |= 1_u64 << bit;
}

fn byte_set_contains(set: [u64; ROOT_PREFILTER_BYTE_WORDS], byte: u8) -> bool {
    let index = usize::from(byte >> 6);
    let bit = usize::from(byte & 0x3F);
    set[index] & (1_u64 << bit) != 0
}

struct ByteSetMembers {
    words: [u64; ROOT_PREFILTER_BYTE_WORDS],
    word_index: usize,
}

impl Iterator for ByteSetMembers {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        while self.word_index < self.words.len() {
            let word = self.words[self.word_index];
            if word == 0 {
                self.word_index = self.word_index.saturating_add(1);
                continue;
            }
            let bit = usize::try_from(word.trailing_zeros())
                .expect("a byte-set bit position fits in usize");
            self.words[self.word_index] &= word.wrapping_sub(1);
            let byte = self
                .word_index
                .saturating_mul(ROOT_PREFILTER_WORD_BITS)
                .saturating_add(bit);
            return Some(u8::try_from(byte).expect("a byte-set member fits in u8"));
        }
        None
    }
}

fn byte_set_members(set: [u64; ROOT_PREFILTER_BYTE_WORDS]) -> ByteSetMembers {
    ByteSetMembers {
        words: set,
        word_index: 0,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootClassifierBucketLayout {
    high_bucket_masks: [u8; 16],
}

impl RootClassifierBucketLayout {
    fn next_bucket(
        self,
        byte: u8,
        ordinals: &mut [usize; 16],
    ) -> Result<u8, BuildError> {
        let high_nibble = usize::from(byte >> 4);
        let mut buckets = self.high_bucket_masks[high_nibble];
        let bucket_count = usize::try_from(buckets.count_ones())
            .expect("the fixed bucket count fits in usize");
        if bucket_count == 0 {
            return Err(BuildError::Invariant {
                detail: "folded root classifier atom lost its high-nibble bucket",
            });
        }
        let selected = ordinals[high_nibble] % bucket_count;
        ordinals[high_nibble] = ordinals[high_nibble].checked_add(1).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "folded root classifier atom ordinal",
            },
        )?;
        for _ in 0..selected {
            buckets &= buckets.wrapping_sub(1);
        }
        Ok(1_u8 << buckets.trailing_zeros())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootClassifierVolume {
    numerator: u64,
    dimensions: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootClassifierConfig {
    columns: usize,
    guard: Option<RootGuardCandidate>,
    volume: RootClassifierVolume,
}

fn root_prefilter_classifier(
    dispatch: SimdDispatchContext,
    patterns: &[FoldedLiteral<'_>],
    primary: PrefilterColumn,
    guard: Option<RootGuardCandidate>,
    fingerprint_admitted: bool,
) -> Result<(ByteBucketClassifier, Option<RootGuardCandidate>, usize), BuildError> {
    let (single_column, members) = root_prefilter_one_column_tables(
        primary.byte_set,
        primary.high_nibbles,
    )?;
    let base_work = ROOT_PREFILTER_CLASSIFIER_HIGH_WORK
        .checked_add(members)
        .and_then(|work| work.checked_add(ROOT_PREFILTER_CLASSIFIER_SELECTION_WORK))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root prefilter classifier work",
        })?;
    let mut fingerprint_work = 0_usize;
    let (tables, guard) = if fingerprint_admitted {
        correlated_root_prefilter_tables(
            patterns,
            primary,
            guard,
            &mut fingerprint_work,
        )?
        .map_or((single_column, guard), |(tables, guard)| (tables, guard))
    } else {
        (single_column, guard)
    };
    let work = base_work
        .checked_add(fingerprint_work)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded correlated root classifier work",
        })?;
    let classifier = dispatch
        .byte_bucket_classifier(tables, DispatchPolicy::Auto)
        .expect("automatic byte-bucket dispatch retains a scalar fallback");
    Ok((classifier, guard, work))
}

fn root_prefilter_one_column_tables(
    set: [u64; ROOT_PREFILTER_BYTE_WORDS],
    high_nibbles: u16,
) -> Result<(ByteBucketTables, usize), BuildError> {
    let mut low = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
    let mut high = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
    let mut high_buckets = [0_u8; 16];
    let mut next_bucket = 0_u32;
    for high_nibble in 0_u8..16 {
        if high_nibbles & (1_u16 << high_nibble) == 0 {
            continue;
        }
        let bucket = 1_u8.checked_shl(next_bucket).ok_or(BuildError::Invariant {
            detail: "folded root prefilter exceeded byte buckets",
        })?;
        next_bucket = next_bucket
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded root prefilter bucket count",
            })?;
        let index = usize::from(high_nibble);
        high_buckets[index] = bucket;
        high[0][index] = bucket;
    }
    if next_bucket
        > u32::try_from(ROOT_PREFILTER_BUCKETS)
            .expect("the fixed root-prefilter bucket count fits in u32")
    {
        return Err(BuildError::Invariant {
            detail: "folded root prefilter exceeded byte buckets",
        });
    }
    let mut members = 0_usize;
    for byte in byte_set_members(set) {
        let high_nibble = usize::from(byte >> 4);
        let low_nibble = usize::from(byte & 0x0F);
        low[0][low_nibble] |= high_buckets[high_nibble];
        members = members
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded root prefilter classifier members",
            })?;
    }
    let tables = ByteBucketTables::new(1, low, high).map_err(|_| BuildError::Invariant {
        detail: "folded root prefilter retained invalid classifier tables",
    })?;
    Ok((tables, members))
}

#[allow(
    clippy::too_many_lines,
    reason = "fixed bucket allocation and bounded correlated-column materialization share one source-derived transaction"
)]
fn correlated_root_prefilter_tables(
    patterns: &[FoldedLiteral<'_>],
    primary: PrefilterColumn,
    guard: Option<RootGuardCandidate>,
    work: &mut usize,
) -> Result<Option<(ByteBucketTables, Option<RootGuardCandidate>)>, BuildError> {
    #[cfg(test)]
    build_probe::record_fingerprint_attempt();
    let layout = root_classifier_bucket_layout(patterns, primary, work)?;
    let mut low = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
    let mut high = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
    let mut ordinals = [0_usize; 16];
    for pattern in patterns {
        let class = pattern
            .classes
            .get(primary.scalar_index)
            .ok_or(BuildError::Invariant {
                detail: "folded root classifier primary position disappeared",
            })?;
        for &scalar in class.equivalents {
            *work = checked_build_add(
                *work,
                ROOT_PREFILTER_EDGE_WORK,
                "folded root classifier primary table work",
            )?;
            let mut encoded = [0_u8; MAX_UTF8_WIDTH];
            let bytes = scalar.encode_utf8(&mut encoded).as_bytes();
            let byte = *bytes
                .get(usize::from(primary.local_offset))
                .ok_or(BuildError::Invariant {
                    detail: "folded root classifier primary byte disappeared",
                })?;
            let bucket = layout.next_bucket(byte, &mut ordinals)?;
            classifier_table_insert(&mut low[0], &mut high[0], byte, bucket);
        }
    }

    let mut max_columns = 1_usize;
    for distance in 1..BYTE_BUCKET_MAX_COLUMNS {
        *work = checked_build_add(
            *work,
            ROOT_PREFILTER_OFFSET_WORK,
            "folded correlated root offset work",
        )?;
        let mut column_ordinals = [0_usize; 16];
        let mut necessary = true;
        for pattern in patterns {
            if !collect_bucketed_successor_column(
                *pattern,
                primary,
                distance,
                layout,
                &mut column_ordinals,
                &mut low[distance],
                &mut high[distance],
                work,
            )? {
                necessary = false;
                break;
            }
        }
        if !necessary {
            break;
        }
        max_columns = distance.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "folded correlated root column count",
        })?;
    }
    if max_columns == 1 {
        return Ok(None);
    }
    *work = checked_build_add(
        *work,
        ROOT_PREFILTER_FINGERPRINT_SCORE_WORK,
        "folded root fingerprint score work",
    )?;
    let baseline = root_classifier_baseline_volume(primary, guard)?;
    let mut selected = None::<RootClassifierConfig>;
    for columns in 2..=max_columns {
        let without_guard = root_classifier_volume(low, high, columns, primary, None)?;
        let candidate = if let Some(guard) = guard {
            let with_guard = root_classifier_volume(low, high, columns, primary, Some(guard))?;
            if volume_gain_at_least(
                with_guard,
                without_guard,
                ROOT_PREFILTER_FINGERPRINT_GAIN,
            )? {
                RootClassifierConfig {
                    columns,
                    guard: Some(guard),
                    volume: with_guard,
                }
            } else {
                RootClassifierConfig {
                    columns,
                    guard: None,
                    volume: without_guard,
                }
            }
        } else {
            RootClassifierConfig {
                columns,
                guard: None,
                volume: without_guard,
            }
        };
        // A primary behind an unchecked prefix gives the verifier an earlier,
        // cheaper rejection point. One forward byte cannot amortize a second
        // block classification, so leave that C2 shape on the established
        // one-column route. Wider fingerprints must additionally prove that
        // bucket identity rejects at least one tuple beyond the same columns
        // treated as independent unions. The direct `(columns + 1)` density
        // test below remains the runtime break-even gate.
        if primary.offset != 0 {
            if columns == 2 {
                continue;
            }
            let independent = root_classifier_independent_volume(
                low,
                high,
                columns,
                primary,
                candidate.guard,
            )?;
            if !volume_density_is_strictly_lower(candidate.volume, independent)? {
                continue;
            }
        }
        let direct_gain = u64::try_from(columns.checked_add(1).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "folded root fingerprint runtime passes",
            },
        )?)
        .map_err(|_| BuildError::ArithmeticOverflow {
            computation: "folded root fingerprint runtime gain",
        })?;
        if !volume_gain_at_least(candidate.volume, baseline, direct_gain)? {
            continue;
        }
        let replaces = if let Some(incumbent) = selected {
            volume_gain_at_least(
                candidate.volume,
                incumbent.volume,
                ROOT_PREFILTER_FINGERPRINT_GAIN,
            )?
        } else {
            true
        };
        if replaces {
            selected = Some(candidate);
        }
    }
    let Some(selected) = selected else {
        return Ok(None);
    };
    let tables = ByteBucketTables::new(selected.columns, low, high).map_err(|_| {
        BuildError::Invariant {
            detail: "folded root fingerprint retained invalid classifier tables",
        }
    })?;
    Ok(Some((tables, selected.guard)))
}

fn root_classifier_bucket_layout(
    patterns: &[FoldedLiteral<'_>],
    primary: PrefilterColumn,
    work: &mut usize,
) -> Result<RootClassifierBucketLayout, BuildError> {
    let mut atom_counts = [0_usize; 16];
    for pattern in patterns {
        let class = pattern
            .classes
            .get(primary.scalar_index)
            .ok_or(BuildError::Invariant {
                detail: "folded root classifier bucket position disappeared",
            })?;
        for &scalar in class.equivalents {
            *work = checked_build_add(
                *work,
                ROOT_PREFILTER_EDGE_WORK,
                "folded root classifier bucket atom work",
            )?;
            let mut encoded = [0_u8; MAX_UTF8_WIDTH];
            let bytes = scalar.encode_utf8(&mut encoded).as_bytes();
            let byte = *bytes
                .get(usize::from(primary.local_offset))
                .ok_or(BuildError::Invariant {
                    detail: "folded root classifier bucket byte disappeared",
                })?;
            let high_nibble = usize::from(byte >> 4);
            atom_counts[high_nibble] = atom_counts[high_nibble].checked_add(1).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "folded root classifier bucket atoms",
                },
            )?;
        }
    }
    *work = checked_build_add(
        *work,
        ROOT_PREFILTER_FINGERPRINT_LAYOUT_WORK,
        "folded root fingerprint layout work",
    )?;
    let mut bucket_counts = [0_u8; 16];
    let mut assigned = 0_usize;
    for (high_nibble, &atoms) in atom_counts.iter().enumerate() {
        if atoms != 0 {
            bucket_counts[high_nibble] = 1;
            assigned = assigned.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
                computation: "folded root classifier assigned buckets",
            })?;
        }
    }
    if assigned == 0 || assigned > ROOT_PREFILTER_BUCKETS {
        return Err(BuildError::Invariant {
            detail: "folded root classifier bucket layout escaped its fixed capacity",
        });
    }
    while assigned < ROOT_PREFILTER_BUCKETS {
        let mut best = None::<(usize, usize)>;
        for high_nibble in 0..16 {
            let slots = usize::from(bucket_counts[high_nibble]);
            if slots == 0 || slots >= atom_counts[high_nibble] {
                continue;
            }
            let pressure = atom_counts[high_nibble]
                .checked_add(slots.saturating_sub(1))
                .and_then(|atoms| atoms.checked_div(slots))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "folded root classifier bucket pressure",
                })?;
            if best.is_none_or(|(best_pressure, _)| pressure > best_pressure) {
                best = Some((pressure, high_nibble));
            }
        }
        let Some((_, high_nibble)) = best else {
            break;
        };
        bucket_counts[high_nibble] = bucket_counts[high_nibble].checked_add(1).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "folded root classifier high-nibble buckets",
            },
        )?;
        assigned = assigned.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root classifier assigned buckets",
        })?;
    }
    let mut high_bucket_masks = [0_u8; 16];
    let mut next_bucket = 0_u32;
    for high_nibble in 0..16 {
        for _ in 0..bucket_counts[high_nibble] {
            let bucket = 1_u8.checked_shl(next_bucket).ok_or(BuildError::Invariant {
                detail: "folded root classifier bucket assignment overflowed",
            })?;
            high_bucket_masks[high_nibble] |= bucket;
            next_bucket = next_bucket.checked_add(1).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "folded root classifier next bucket",
                },
            )?;
        }
    }
    Ok(RootClassifierBucketLayout { high_bucket_masks })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the bounded UTF-8 frontier keeps its source position, bucket identity and fixed output tables explicit"
)]
fn collect_bucketed_successor_column(
    pattern: FoldedLiteral<'_>,
    primary: PrefilterColumn,
    distance: usize,
    layout: RootClassifierBucketLayout,
    ordinals: &mut [usize; 16],
    low: &mut [u8; 16],
    high: &mut [u8; 16],
    work: &mut usize,
) -> Result<bool, BuildError> {
    let primary_class = pattern
        .classes
        .get(primary.scalar_index)
        .ok_or(BuildError::Invariant {
            detail: "folded root fingerprint primary position disappeared",
        })?;
    let target_offset = usize::from(primary.local_offset)
        .checked_add(distance)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root fingerprint target offset",
        })?;
    let mut frontier = [0_u8; MAX_UTF8_WIDTH];
    for &scalar in primary_class.equivalents {
        *work = checked_build_add(
            *work,
            ROOT_PREFILTER_EDGE_WORK,
            "folded root fingerprint primary edge work",
        )?;
        let mut encoded = [0_u8; MAX_UTF8_WIDTH];
        let bytes = scalar.encode_utf8(&mut encoded).as_bytes();
        let primary_byte = *bytes
            .get(usize::from(primary.local_offset))
            .ok_or(BuildError::Invariant {
                detail: "folded root fingerprint primary byte disappeared",
            })?;
        let bucket = layout.next_bucket(primary_byte, ordinals)?;
        if let Some(&byte) = bytes.get(target_offset) {
            classifier_table_insert(low, high, byte, bucket);
            continue;
        }
        let remaining = target_offset.checked_sub(bytes.len()).ok_or(
            BuildError::Invariant {
                detail: "folded root fingerprint target moved before its scalar",
            },
        )?;
        let entry = frontier.get_mut(remaining).ok_or(BuildError::Invariant {
            detail: "folded root fingerprint frontier escaped its fixed width",
        })?;
        *entry |= bucket;
    }

    let mut scalar_index = primary
        .scalar_index
        .checked_add(1)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root fingerprint scalar index",
        })?;
    while frontier.iter().any(|&buckets| buckets != 0) {
        let Some(class) = pattern.classes.get(scalar_index) else {
            return Ok(false);
        };
        let mut next_frontier = [0_u8; MAX_UTF8_WIDTH];
        for (remaining, &buckets) in frontier.iter().enumerate() {
            if buckets == 0 {
                continue;
            }
            for &scalar in class.equivalents {
                *work = checked_build_add(
                    *work,
                    ROOT_PREFILTER_EDGE_WORK,
                    "folded root fingerprint frontier edge work",
                )?;
                let mut encoded = [0_u8; MAX_UTF8_WIDTH];
                let bytes = scalar.encode_utf8(&mut encoded).as_bytes();
                if let Some(&byte) = bytes.get(remaining) {
                    classifier_table_insert(low, high, byte, buckets);
                    continue;
                }
                let next = remaining.checked_sub(bytes.len()).ok_or(
                    BuildError::Invariant {
                        detail: "folded root fingerprint frontier moved backwards",
                    },
                )?;
                let entry = next_frontier.get_mut(next).ok_or(BuildError::Invariant {
                    detail: "folded root fingerprint next frontier escaped its fixed width",
                })?;
                *entry |= buckets;
            }
        }
        frontier = next_frontier;
        scalar_index = scalar_index.checked_add(1).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "folded root fingerprint following scalar index",
            },
        )?;
    }
    Ok(true)
}

fn classifier_table_insert(
    low: &mut [u8; 16],
    high: &mut [u8; 16],
    byte: u8,
    buckets: u8,
) {
    low[usize::from(byte & 0x0F)] |= buckets;
    high[usize::from(byte >> 4)] |= buckets;
}

fn root_classifier_baseline_volume(
    primary: PrefilterColumn,
    guard: Option<RootGuardCandidate>,
) -> Result<RootClassifierVolume, BuildError> {
    let primary_members = u64::from(primary.needle_count);
    let Some(guard) = guard else {
        return Ok(RootClassifierVolume {
            numerator: primary_members,
            dimensions: 1,
        });
    };
    if guard.offset == primary.offset {
        let intersection = byte_set_members(primary.byte_set)
            .filter(|&byte| byte_set_contains(guard.byte_set, byte))
            .count();
        return Ok(RootClassifierVolume {
            numerator: u64::try_from(intersection).map_err(|_| BuildError::ArithmeticOverflow {
                computation: "folded root classifier baseline intersection",
            })?,
            dimensions: 1,
        });
    }
    let numerator = primary_members
        .checked_mul(u64::from(guard.needle_count))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root classifier baseline volume",
        })?;
    Ok(RootClassifierVolume {
        numerator,
        dimensions: 2,
    })
}

fn root_classifier_volume(
    low: [[u8; 16]; BYTE_BUCKET_MAX_COLUMNS],
    high: [[u8; 16]; BYTE_BUCKET_MAX_COLUMNS],
    columns: usize,
    primary: PrefilterColumn,
    guard: Option<RootGuardCandidate>,
) -> Result<RootClassifierVolume, BuildError> {
    let guard_column = guard.and_then(|guard| {
        usize::from(guard.offset)
            .checked_sub(usize::from(primary.offset))
            .filter(|&column| column < columns)
    });
    let mut numerator = 0_u64;
    for bucket in 0..ROOT_PREFILTER_BUCKETS {
        let bucket = 1_u8 << bucket;
        let mut bucket_volume = 1_u64;
        for column in 0..columns {
            let mut members = 0_u64;
            for byte in u8::MIN..=u8::MAX {
                let admitted = low[column][usize::from(byte & 0x0F)]
                    & high[column][usize::from(byte >> 4)]
                    & bucket
                    != 0;
                let guard_admitted = guard_column != Some(column)
                    || guard.is_some_and(|guard| byte_set_contains(guard.byte_set, byte));
                members = members
                    .checked_add(if admitted && guard_admitted { 1 } else { 0 })
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "folded root classifier column volume",
                    })?;
            }
            bucket_volume = bucket_volume.checked_mul(members).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "folded root classifier bucket volume",
                },
            )?;
        }
        numerator = numerator.checked_add(bucket_volume).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "folded root classifier tuple volume",
            },
        )?;
    }
    let mut dimensions = columns;
    if let Some(guard) = guard
        && guard_column.is_none()
    {
        numerator = numerator
            .checked_mul(u64::from(guard.needle_count))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded root classifier outside-guard volume",
            })?;
        dimensions = dimensions.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root classifier volume dimensions",
        })?;
    }
    Ok(RootClassifierVolume {
        numerator,
        dimensions,
    })
}

fn root_classifier_independent_volume(
    low: [[u8; 16]; BYTE_BUCKET_MAX_COLUMNS],
    high: [[u8; 16]; BYTE_BUCKET_MAX_COLUMNS],
    columns: usize,
    primary: PrefilterColumn,
    guard: Option<RootGuardCandidate>,
) -> Result<RootClassifierVolume, BuildError> {
    let guard_column = guard.and_then(|guard| {
        usize::from(guard.offset)
            .checked_sub(usize::from(primary.offset))
            .filter(|&column| column < columns)
    });
    let mut numerator = 1_u64;
    for column in 0..columns {
        let mut members = 0_u64;
        for byte in u8::MIN..=u8::MAX {
            let admitted = low[column][usize::from(byte & 0x0F)]
                & high[column][usize::from(byte >> 4)]
                != 0;
            let guard_admitted = guard_column != Some(column)
                || guard.is_some_and(|guard| byte_set_contains(guard.byte_set, byte));
            members = members
                .checked_add(if admitted && guard_admitted { 1 } else { 0 })
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "folded independent classifier column volume",
                })?;
        }
        numerator = numerator
            .checked_mul(members)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded independent classifier tuple volume",
            })?;
    }
    let mut dimensions = columns;
    if let Some(guard) = guard
        && guard_column.is_none()
    {
        numerator = numerator
            .checked_mul(u64::from(guard.needle_count))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded independent classifier outside-guard volume",
            })?;
        dimensions = dimensions.checked_add(1).ok_or(BuildError::ArithmeticOverflow {
            computation: "folded independent classifier volume dimensions",
        })?;
    }
    Ok(RootClassifierVolume {
        numerator,
        dimensions,
    })
}

fn volume_density_is_strictly_lower(
    candidate: RootClassifierVolume,
    baseline: RootClassifierVolume,
) -> Result<bool, BuildError> {
    let candidate_scaled = scale_classifier_volume(
        u128::from(candidate.numerator),
        baseline.dimensions,
    )
    .ok_or(BuildError::ArithmeticOverflow {
        computation: "folded root classifier strict candidate density",
    })?;
    let baseline_scaled = scale_classifier_volume(
        u128::from(baseline.numerator),
        candidate.dimensions,
    )
    .ok_or(BuildError::ArithmeticOverflow {
        computation: "folded root classifier strict baseline density",
    })?;
    Ok(candidate_scaled < baseline_scaled)
}

fn volume_gain_at_least(
    candidate: RootClassifierVolume,
    baseline: RootClassifierVolume,
    gain: u64,
) -> Result<bool, BuildError> {
    let candidate_scaled = u128::from(candidate.numerator)
        .checked_mul(u128::from(gain))
        .and_then(|volume| scale_classifier_volume(volume, baseline.dimensions))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root classifier candidate density",
        })?;
    let baseline_scaled = scale_classifier_volume(
        u128::from(baseline.numerator),
        candidate.dimensions,
    )
    .ok_or(BuildError::ArithmeticOverflow {
        computation: "folded root classifier baseline density",
    })?;
    Ok(candidate_scaled <= baseline_scaled)
}

fn scale_classifier_volume(mut volume: u128, dimensions: usize) -> Option<u128> {
    let byte_values = u128::try_from(ROOT_PREFILTER_BYTE_VALUES).ok()?;
    for _ in 0..dimensions {
        volume = volume.checked_mul(byte_values)?;
    }
    Some(volume)
}

fn scan_folded_start_value(
    plan: &FoldedLiteralTriePlan,
    source: &[u8],
    absolute_base: usize,
    relative_start: usize,
    stop_after_first_event: bool,
) -> Option<Option<LiteralCandidate>> {
    let start = absolute_base.checked_add(relative_start)?;
    let mut selected = None::<LiteralCandidate>;
    let mut state = 0_usize;
    let mut cursor = relative_start;
    let mut depth = 0_usize;
    while cursor < source.len() && depth < plan.build.max_pattern_scalars {
        let decoded = decode_scalar(&source[cursor..]);
        let Some(scalar) = decoded.scalar else {
            break;
        };
        let Some(next) = transition_value(&plan.nodes, &plan.edges, state, scalar) else {
            break;
        };
        state = next;
        cursor = cursor.checked_add(decoded.width)?;
        depth = depth.checked_add(1)?;
        let end = absolute_base.checked_add(cursor)?;
        let mut output = plan.nodes[state].first_output;
        while output != NONE {
            let terminal = plan.outputs[output];
            let candidate = LiteralCandidate::new(terminal.pattern_index, start, end);
            if selected.is_none_or(|best| candidate.pattern_index() < best.pattern_index()) {
                selected = Some(candidate);
            }
            if stop_after_first_event {
                return Some(selected);
            }
            output = terminal.next;
        }
    }
    Some(selected)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the early-stop bit joins the established explicit scan-accounting boundary"
)]
fn scan_folded_start<S>(
    plan: &FoldedLiteralTriePlan,
    source: &[u8],
    absolute_base: usize,
    relative_start: usize,
    upper: ScanUpperBounds,
    actual: &mut ScanActual,
    stop_after_first_event: bool,
    emit: &mut S,
) -> Result<usize, ScanAttemptError>
where
    S: LiteralCandidateSink + ?Sized,
{
    let mut state = 0_usize;
    let mut cursor = relative_start;
    let mut depth = 0_usize;
    let mut next_start_advance = 1_usize;
    while cursor < source.len() && depth < plan.build.max_pattern_scalars {
        actual.scalar_decodes = checked_actual_add(
            actual.scalar_decodes,
            1,
            upper,
            *actual,
            "folded scalar decodes",
        )?;
        let decoded = decode_scalar(&source[cursor..]);
        actual.source_byte_reads = checked_actual_add(
            actual.source_byte_reads,
            decoded.byte_checks,
            upper,
            *actual,
            "folded source reads",
        )?;
        let Some(scalar) = decoded.scalar else {
            actual.invalid_bytes = checked_actual_add(
                actual.invalid_bytes,
                1,
                upper,
                *actual,
                "invalid UTF-8 bytes",
            )?;
            break;
        };
        if depth == 0 {
            next_start_advance = decoded.width;
        }
        actual.decoded_scalars =
            checked_actual_add(actual.decoded_scalars, 1, upper, *actual, "decoded scalars")?;
        let Some(next) =
            transition_with_actual(&plan.nodes, &plan.edges, state, scalar, actual, upper)?
        else {
            break;
        };
        state = next;
        cursor = cursor
            .checked_add(decoded.width)
            .ok_or_else(|| attempt_overflow(upper, *actual, "folded cursor"))?;
        depth = depth
            .checked_add(1)
            .ok_or_else(|| attempt_overflow(upper, *actual, "folded depth"))?;
        if emit_folded_outputs(
            plan,
            state,
            absolute_base,
            (relative_start, cursor),
            upper,
            actual,
            stop_after_first_event,
            emit,
        )? {
            break;
        }
    }
    Ok(next_start_advance)
}

#[allow(
    clippy::too_many_arguments,
    reason = "output emission retains explicit span, envelope, actual and early-stop state"
)]
fn emit_folded_outputs<S>(
    plan: &FoldedLiteralTriePlan,
    state: usize,
    absolute_base: usize,
    relative_span: (usize, usize),
    upper: ScanUpperBounds,
    actual: &mut ScanActual,
    stop_after_first_event: bool,
    emit: &mut S,
) -> Result<bool, ScanAttemptError>
where
    S: LiteralCandidateSink + ?Sized,
{
    let start = absolute_base
        .checked_add(relative_span.0)
        .ok_or_else(|| attempt_overflow(upper, *actual, "folded candidate start"))?;
    let end = absolute_base
        .checked_add(relative_span.1)
        .ok_or_else(|| attempt_overflow(upper, *actual, "folded candidate end"))?;
    let mut output = plan.nodes[state].first_output;
    while output != NONE {
        let terminal = plan.outputs[output];
        actual.candidate_events = checked_actual_add(
            actual.candidate_events,
            1,
            upper,
            *actual,
            "folded candidate events",
        )?;
        emit.emit_candidate(LiteralCandidate::new(terminal.pattern_index, start, end));
        if stop_after_first_event {
            return Ok(true);
        }
        output = terminal.next;
    }
    Ok(false)
}

#[cold]
#[inline(never)]
fn fallback_reason(
    patterns: &[FoldedLiteral<'_>],
) -> Result<(Option<DenseFallbackReason>, usize), BuildError> {
    let mut comparisons = 0_usize;
    if patterns.is_empty() {
        return Ok((Some(DenseFallbackReason::EmptyLanguage), comparisons));
    }
    for (pattern_index, pattern) in patterns.iter().enumerate() {
        if pattern.classes.is_empty() {
            return Ok((
                Some(DenseFallbackReason::EmptyLiteral { pattern_index }),
                comparisons,
            ));
        }
        for (scalar_index, class) in pattern.classes.iter().enumerate() {
            if class.equivalents.is_empty() {
                return Ok((
                    Some(DenseFallbackReason::EmptyClass {
                        pattern_index,
                        scalar_index,
                    }),
                    comparisons,
                ));
            }
            if !strictly_sorted(class.equivalents, &mut comparisons)? {
                return Ok((
                    Some(DenseFallbackReason::NonCanonicalClass {
                        pattern_index,
                        scalar_index,
                    }),
                    comparisons,
                ));
            }
        }
    }
    for (first_pattern, first) in patterns.iter().enumerate() {
        for (first_scalar, first_class) in first.classes.iter().enumerate() {
            for (second_pattern, second) in patterns.iter().enumerate().skip(first_pattern) {
                let scalar_start = if second_pattern == first_pattern {
                    first_scalar.saturating_add(1)
                } else {
                    0
                };
                for (second_scalar, second_class) in
                    second.classes.iter().enumerate().skip(scalar_start)
                {
                    if class_relation(
                        first_class.equivalents,
                        second_class.equivalents,
                        &mut comparisons,
                    )? == ClassRelation::PartialOverlap
                    {
                        return Ok((
                            Some(DenseFallbackReason::OverlappingClasses {
                                first_pattern,
                                first_scalar,
                                second_pattern,
                                second_scalar,
                            }),
                            comparisons,
                        ));
                    }
                }
            }
        }
    }
    Ok((None, comparisons))
}

#[cold]
#[inline(never)]
fn preflight_from_lengths(patterns: &[FoldedLiteral<'_>]) -> Result<BuildAccounting, BuildError> {
    let mut scalar_positions = 0_usize;
    let mut equivalent_scalars = 0_usize;
    let mut max_pattern_scalars = 0_usize;
    for pattern in patterns {
        scalar_positions = scalar_positions.checked_add(pattern.classes.len()).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "folded scalar positions",
            },
        )?;
        max_pattern_scalars = max_pattern_scalars.max(pattern.classes.len());
        for class in pattern.classes {
            equivalent_scalars = equivalent_scalars
                .checked_add(class.equivalents.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "folded equivalent scalars",
                })?;
        }
    }
    let states_upper_bound =
        scalar_positions
            .checked_add(1)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded trie states",
            })?;
    let transitions_upper_bound = equivalent_scalars;
    let persistent_bytes_upper_bound =
        exact_retained_bytes(states_upper_bound, transitions_upper_bound, patterns.len())?;
    let pairwise_comparisons = checked_build_mul(
        equivalent_scalars,
        equivalent_scalars,
        "folded canonical comparison work",
    )?;
    let canonical_comparisons_upper_bound = pairwise_comparisons
        .checked_add(equivalent_scalars)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded canonical comparisons",
        })?;
    let insertion_probes_upper_bound = pairwise_comparisons;
    let root_prefilter_work_upper_bound =
        preflight_root_prefilter_work_upper_bound(scalar_positions, equivalent_scalars)?;
    let insertion_work =
        insertion_probes_upper_bound
            .checked_add(equivalent_scalars.checked_mul(3).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "folded insertion scalar work",
                },
            )?)
            .and_then(|work| work.checked_add(scalar_positions))
            .and_then(|work| work.checked_add(states_upper_bound))
            .and_then(|work| work.checked_add(patterns.len()))
            .and_then(|work| work.checked_add(patterns.len()))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "folded insertion work",
            })?;
    let work_upper_bound = canonical_comparisons_upper_bound
        .checked_add(insertion_work)
        .and_then(|work| work.checked_add(scalar_positions))
        .and_then(|work| work.checked_add(root_prefilter_work_upper_bound))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded construction work",
        })?;
    Ok(BuildAccounting {
        patterns: patterns.len(),
        scalar_positions,
        equivalent_scalars,
        states_upper_bound,
        transitions_upper_bound,
        max_pattern_scalars,
        max_state_fanout_upper_bound: transitions_upper_bound,
        canonical_comparisons_upper_bound,
        insertion_probes_upper_bound,
        root_prefilter_work_upper_bound,
        work_upper_bound,
        persistent_bytes_upper_bound,
        peak_bytes_upper_bound: persistent_bytes_upper_bound,
        allocations_upper_bound: 3,
        canonical_comparisons: 0,
        insertion_probes: 0,
        max_state_fanout: 0,
        root_prefilter_work: 0,
        root_prefilter_needles: 0,
        root_prefilter_offset: None,
        root_prefilter_guard_needles: 0,
        root_prefilter_guard_offset: None,
        root_prefilter_classifier_selection: None,
        work: 0,
        persistent_bytes: 0,
        peak_bytes: 0,
        states: 0,
        transitions: 0,
        outputs: 0,
        allocations: 0,
    })
}

// This is the v5 base-column/classifier envelope. Successor work is admitted
// separately only after source-derived selection proves the primary is narrow.
fn preflight_root_prefilter_work_upper_bound(
    scalar_positions: usize,
    equivalent_scalars: usize,
) -> Result<usize, BuildError> {
    let columns = checked_build_mul(
        scalar_positions,
        MAX_UTF8_WIDTH,
        "folded root prefilter column upper bound",
    )?;
    let needle_work_per_column = checked_build_mul(
        ROOT_PREFILTER_BYTE_VALUES,
        ROOT_PREFILTER_NEEDLE_WORK,
        "folded root prefilter needle upper work",
    )?;
    let needle_work = checked_build_mul(
        columns,
        needle_work_per_column,
        "folded root prefilter all-needle upper work",
    )?;
    let offset_work = checked_build_mul(
        columns,
        ROOT_PREFILTER_OFFSET_WORK,
        "folded root prefilter offset upper work",
    )?;
    let edge_work = checked_build_mul(
        equivalent_scalars,
        ROOT_PREFILTER_EDGE_WORK,
        "folded root prefilter edge upper work",
    )?
    .checked_mul(MAX_UTF8_WIDTH)
    .ok_or(BuildError::ArithmeticOverflow {
        computation: "folded root prefilter all-edge upper work",
    })?;
    offset_work
        .checked_add(edge_work)
        .and_then(|work| work.checked_add(needle_work))
        .and_then(|work| work.checked_add(ROOT_PREFILTER_CLASSIFIER_HIGH_WORK))
        .and_then(|work| work.checked_add(ROOT_PREFILTER_BYTE_VALUES))
        .and_then(|work| work.checked_add(ROOT_PREFILTER_CLASSIFIER_SELECTION_WORK))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root prefilter upper work",
        })
}

fn root_prefilter_fingerprint_work_upper_bound(
    equivalent_scalars: usize,
) -> Result<usize, BuildError> {
    // Two complete primary-atom passes build the bucket layout and column
    // zero. At each of three successor distances, one primary pass plus at
    // most four merged remaining-offset frontiers can visit every equivalent
    // scalar. Bucket identities are bitsets on those four frontier slots, so
    // this bound does not multiply by the number of root alternatives.
    let successor_passes = BYTE_BUCKET_MAX_COLUMNS
        .saturating_sub(1)
        .checked_mul(MAX_UTF8_WIDTH.saturating_add(1))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root fingerprint successor passes",
        })?;
    let edge_passes = successor_passes.checked_add(2).ok_or(
        BuildError::ArithmeticOverflow {
            computation: "folded root fingerprint edge passes",
        },
    )?;
    let edge_work = equivalent_scalars
        .checked_mul(edge_passes)
        .and_then(|work| work.checked_mul(ROOT_PREFILTER_EDGE_WORK))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root fingerprint edge work",
        })?;
    let offset_work = BYTE_BUCKET_MAX_COLUMNS
        .saturating_sub(1)
        .checked_mul(ROOT_PREFILTER_OFFSET_WORK)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root fingerprint offset work",
        })?;
    edge_work
        .checked_add(offset_work)
        .and_then(|work| work.checked_add(ROOT_PREFILTER_FINGERPRINT_LAYOUT_WORK))
        .and_then(|work| work.checked_add(ROOT_PREFILTER_FINGERPRINT_SCORE_WORK))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root fingerprint upper work",
        })
}

fn admit_root_prefilter_fingerprint(
    accounting: &mut BuildAccounting,
    max_work: usize,
) -> Result<bool, BuildError> {
    let fingerprint_work =
        root_prefilter_fingerprint_work_upper_bound(accounting.equivalent_scalars)?;
    if fingerprint_work > ROOT_PREFILTER_FINGERPRINT_MAX_WORK {
        return Ok(false);
    }
    let mut fingerprint = *accounting;
    fingerprint.root_prefilter_work_upper_bound = fingerprint
        .root_prefilter_work_upper_bound
        .checked_add(fingerprint_work)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root fingerprint prefilter upper work",
        })?;
    fingerprint.work_upper_bound = fingerprint
        .work_upper_bound
        .checked_add(fingerprint_work)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root fingerprint construction work",
        })?;
    if fingerprint.work_upper_bound > max_work {
        return Ok(false);
    }
    *accounting = fingerprint;
    Ok(true)
}

fn root_prefilter_successor_work_upper_bound(
    equivalent_scalars: usize,
) -> Result<usize, BuildError> {
    let offset_work = checked_build_mul(
        MAX_UTF8_WIDTH,
        ROOT_PREFILTER_OFFSET_WORK,
        "folded root successor offset upper work",
    )?;
    let edge_work = checked_build_mul(
        equivalent_scalars,
        ROOT_PREFILTER_EDGE_WORK,
        "folded root successor edge upper work",
    )?
    .checked_mul(MAX_UTF8_WIDTH)
    .and_then(|work| work.checked_mul(MAX_UTF8_WIDTH))
    .ok_or(BuildError::ArithmeticOverflow {
        computation: "folded root successor frontier upper work",
    })?;
    let needle_work = checked_build_mul(
        MAX_UTF8_WIDTH,
        ROOT_PREFILTER_BYTE_VALUES,
        "folded root successor byte upper bound",
    )?
    .checked_mul(ROOT_PREFILTER_NEEDLE_WORK)
    .ok_or(BuildError::ArithmeticOverflow {
        computation: "folded root successor needle upper work",
    })?;
    offset_work
        .checked_add(edge_work)
        .and_then(|work| work.checked_add(needle_work))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root successor upper work",
        })
}

fn admit_root_prefilter_successor(accounting: &mut BuildAccounting) -> Result<(), BuildError> {
    let successor_work =
        root_prefilter_successor_work_upper_bound(accounting.equivalent_scalars)?;
    accounting.root_prefilter_work_upper_bound = accounting
        .root_prefilter_work_upper_bound
        .checked_add(successor_work)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root successor prefilter upper work",
        })?;
    accounting.work_upper_bound = accounting
        .work_upper_bound
        .checked_add(successor_work)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root successor construction work",
        })?;
    Ok(())
}

#[cold]
#[inline(never)]
fn enforce_build_limits(
    accounting: &BuildAccounting,
    limits: BuildLimits,
) -> Result<(), BuildError> {
    for (needed, limit, resource) in [
        (
            accounting.patterns,
            limits.max_patterns,
            BuildResource::Patterns,
        ),
        (
            accounting.scalar_positions,
            limits.max_scalar_positions,
            BuildResource::ScalarPositions,
        ),
        (
            accounting.equivalent_scalars,
            limits.max_equivalent_scalars,
            BuildResource::EquivalentScalars,
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

fn strictly_sorted(scalars: &[char], comparisons: &mut usize) -> Result<bool, BuildError> {
    for pair in scalars.windows(2) {
        build_probe::record_scalar_reads(2);
        *comparisons = checked_build_add(*comparisons, 1, "folded sorting comparisons")?;
        if pair[0] >= pair[1] {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClassRelation {
    Identical,
    Disjoint,
    PartialOverlap,
}

fn class_relation(
    left: &[char],
    right: &[char],
    comparisons: &mut usize,
) -> Result<ClassRelation, BuildError> {
    let mut left_index = 0_usize;
    let mut right_index = 0_usize;
    let mut identical = left.len() == right.len();
    let mut overlap = false;
    while left_index < left.len() && right_index < right.len() {
        build_probe::record_scalar_reads(2);
        *comparisons = checked_build_add(*comparisons, 1, "folded class comparisons")?;
        match left[left_index].cmp(&right[right_index]) {
            core::cmp::Ordering::Less => {
                identical = false;
                left_index = left_index.saturating_add(1);
            }
            core::cmp::Ordering::Greater => {
                identical = false;
                right_index = right_index.saturating_add(1);
            }
            core::cmp::Ordering::Equal => {
                overlap = true;
                left_index = left_index.saturating_add(1);
                right_index = right_index.saturating_add(1);
            }
        }
    }
    if left_index != left.len() || right_index != right.len() {
        identical = false;
    }
    Ok(if identical {
        ClassRelation::Identical
    } else if overlap {
        ClassRelation::PartialOverlap
    } else {
        ClassRelation::Disjoint
    })
}

#[cold]
#[inline(never)]
fn insert_class(
    nodes: &mut ExactVec<Node>,
    edges: &mut ExactVec<Edge>,
    state: usize,
    equivalents: &[char],
    insertion_probes: &mut usize,
    max_state_fanout: &mut usize,
    work: &mut usize,
) -> Result<usize, BuildError> {
    let mut target = None;
    let mut missing = false;
    let mut missing_state_edges = None;
    for &scalar in equivalents {
        build_probe::record_scalar_reads(1);
        *work = checked_build_add(*work, 1, "folded equivalent-scalar work")?;
        let (observed, probes) = transition(nodes, edges, state, scalar);
        *insertion_probes =
            checked_build_add(*insertion_probes, probes, "folded insertion probes")?;
        *work = checked_build_add(*work, probes, "folded insertion probe work")?;
        if let Some(observed) = observed {
            if target.is_some_and(|expected| expected != observed) {
                return Err(BuildError::Invariant {
                    detail: "canonical class reached multiple trie states",
                });
            }
            target = Some(observed);
        } else {
            missing = true;
            if missing_state_edges.is_some_and(|expected| expected != probes) {
                return Err(BuildError::Invariant {
                    detail: "folded trie miss observed an unstable state degree",
                });
            }
            missing_state_edges = Some(probes);
        }
    }
    if let Some(existing) = target {
        if missing {
            return Err(BuildError::Invariant {
                detail: "canonical class partially overlapped a trie edge",
            });
        }
        return Ok(existing);
    }
    let state_edges = missing_state_edges
        .ok_or(BuildError::Invariant {
            detail: "nonempty folded class had neither an existing nor a missing transition",
        })?
        .checked_add(equivalents.len())
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded trie state degree",
        })?;
    *work = checked_build_add(*work, 1, "folded trie state-degree certificate work")?;
    *max_state_fanout = (*max_state_fanout).max(state_edges);
    let next_state = nodes.len();
    push_exact(nodes, Node::EMPTY, "folded trie state")?;
    *work = checked_build_add(*work, 1, "folded trie state work")?;
    for &scalar in equivalents {
        build_probe::record_scalar_reads(1);
        *work = checked_build_add(*work, 1, "folded retained scalar work")?;
        let edge_index = edges.len();
        let next = nodes[state].first_edge;
        push_exact(
            edges,
            Edge {
                scalar,
                target: next_state,
                next,
            },
            "folded trie transition",
        )?;
        nodes[state].first_edge = edge_index;
        *work = checked_build_add(*work, 1, "folded trie transition work")?;
    }
    Ok(next_state)
}

fn append_output(
    nodes: &mut [Node],
    outputs: &mut ExactVec<Output>,
    state: usize,
    pattern_index: usize,
) -> Result<(), BuildError> {
    let output_index = outputs.len();
    push_exact(
        outputs,
        Output {
            pattern_index,
            next: NONE,
        },
        "folded trie output",
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

fn transition(
    nodes: &[Node],
    edges: &[Edge],
    state: usize,
    scalar: char,
) -> (Option<usize>, usize) {
    let mut edge = nodes[state].first_edge;
    let mut probes = 0_usize;
    while edge != NONE {
        probes = probes.saturating_add(1);
        let candidate = edges[edge];
        if candidate.scalar == scalar {
            return (Some(candidate.target), probes);
        }
        edge = candidate.next;
    }
    (None, probes)
}

fn transition_value(nodes: &[Node], edges: &[Edge], state: usize, scalar: u32) -> Option<usize> {
    let mut edge = nodes[state].first_edge;
    while edge != NONE {
        let candidate = edges[edge];
        if u32::from(candidate.scalar) == scalar {
            return Some(candidate.target);
        }
        edge = candidate.next;
    }
    None
}

fn transition_with_actual(
    nodes: &[Node],
    edges: &[Edge],
    state: usize,
    scalar: u32,
    actual: &mut ScanActual,
    upper: ScanUpperBounds,
) -> Result<Option<usize>, ScanAttemptError> {
    let mut edge = nodes[state].first_edge;
    while edge != NONE {
        actual.transition_probes = actual
            .transition_probes
            .checked_add(1)
            .ok_or_else(|| attempt_overflow(upper, *actual, "folded transition probes"))?;
        let candidate = edges[edge];
        if u32::from(candidate.scalar) == scalar {
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
            upper.scalar_decodes,
            limits.max_scalar_decodes,
            ScanResource::ScalarDecodes,
        ),
        (
            upper.decoded_scalars,
            limits.max_decoded_scalars,
            ScanResource::DecodedScalars,
        ),
        (
            upper.invalid_bytes,
            limits.max_invalid_bytes,
            ScanResource::InvalidBytes,
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

const fn actual_within(actual: ScanActual, upper: ScanUpperBounds) -> bool {
    actual.input_bytes <= upper.input_bytes
        && actual.candidate_starts <= upper.candidate_starts
        && actual.scalar_decodes <= upper.scalar_decodes
        && actual.decoded_scalars <= upper.decoded_scalars
        && actual.invalid_bytes <= upper.invalid_bytes
        && actual.source_byte_reads <= upper.source_byte_reads
        && actual.transition_probes <= upper.transition_probes
        && actual.candidate_events <= upper.candidate_events
        && actual.work <= upper.work
        && actual.scratch_bytes <= upper.scratch_bytes
}

const fn build_actual_within(actual: &BuildAccounting) -> bool {
    actual.canonical_comparisons <= actual.canonical_comparisons_upper_bound
        && actual.insertion_probes <= actual.insertion_probes_upper_bound
        && actual.max_state_fanout <= actual.max_state_fanout_upper_bound
        && actual.max_state_fanout <= actual.transitions
        && actual.root_prefilter_work <= actual.root_prefilter_work_upper_bound
        && actual.work <= actual.work_upper_bound
        && actual.persistent_bytes <= actual.persistent_bytes_upper_bound
        && actual.peak_bytes <= actual.peak_bytes_upper_bound
        && actual.states <= actual.states_upper_bound
        && actual.transitions <= actual.transitions_upper_bound
        && actual.outputs <= actual.patterns
        && actual.allocations <= actual.allocations_upper_bound
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

fn exact_retained_bytes(
    states: usize,
    transitions: usize,
    outputs: usize,
) -> Result<usize, BuildError> {
    let state_bytes = checked_build_mul(states, mem::size_of::<Node>(), "folded state bytes")?;
    let transition_bytes = checked_build_mul(
        transitions,
        mem::size_of::<Edge>(),
        "folded transition bytes",
    )?;
    let output_bytes = checked_build_mul(outputs, mem::size_of::<Output>(), "folded output bytes")?;
    mem::size_of::<FoldedLiteralTriePlan>()
        .checked_add(state_bytes)
        .and_then(|bytes| bytes.checked_add(transition_bytes))
        .and_then(|bytes| bytes.checked_add(output_bytes))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded retained plan bytes",
        })
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

#[cfg(not(test))]
mod build_probe {
    pub(super) const fn record_scalar_reads(_: usize) {}
    pub(super) const fn record_allocation_attempt() {}
}

#[cfg(not(test))]
mod scan_source_probe {
    pub(super) const fn record() {}
}

#[cfg(test)]
pub(crate) mod root_candidate_dispatch_probe {
    use std::cell::Cell;

    std::thread_local! {
        static DISPATCHES: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record() {
        DISPATCHES.set(
            DISPATCHES
                .get()
                .checked_add(1)
                .expect("folded root-candidate dispatch probe overflow"),
        );
    }

    pub(crate) fn reset() {
        DISPATCHES.set(0);
    }

    pub(crate) fn dispatches() -> usize {
        DISPATCHES.get()
    }
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
                .expect("folded source-access probe overflow"),
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
mod build_probe {
    use std::cell::Cell;

    std::thread_local! {
        static SCALAR_READS: Cell<usize> = const { Cell::new(0) };
        static ALLOCATION_ATTEMPTS: Cell<usize> = const { Cell::new(0) };
        static SUCCESSOR_ATTEMPTS: Cell<usize> = const { Cell::new(0) };
        static FINGERPRINT_ATTEMPTS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record_scalar_reads(reads: usize) {
        SCALAR_READS.set(
            SCALAR_READS
                .get()
                .checked_add(reads)
                .expect("folded scalar-read probe overflow"),
        );
    }

    pub(super) fn record_allocation_attempt() {
        ALLOCATION_ATTEMPTS.set(
            ALLOCATION_ATTEMPTS
                .get()
                .checked_add(1)
                .expect("folded allocation probe overflow"),
        );
    }

    pub(super) fn record_successor_attempt() {
        SUCCESSOR_ATTEMPTS.set(
            SUCCESSOR_ATTEMPTS
                .get()
                .checked_add(1)
                .expect("folded successor probe overflow"),
        );
    }

    pub(super) fn record_fingerprint_attempt() {
        FINGERPRINT_ATTEMPTS.set(
            FINGERPRINT_ATTEMPTS
                .get()
                .checked_add(1)
                .expect("folded fingerprint probe overflow"),
        );
    }

    pub(super) fn reset() {
        SCALAR_READS.set(0);
        ALLOCATION_ATTEMPTS.set(0);
        SUCCESSOR_ATTEMPTS.set(0);
        FINGERPRINT_ATTEMPTS.set(0);
    }

    pub(super) fn scalar_reads() -> usize {
        SCALAR_READS.get()
    }

    pub(super) fn allocation_attempts() -> usize {
        ALLOCATION_ATTEMPTS.get()
    }

    pub(super) fn successor_attempts() -> usize {
        SUCCESSOR_ATTEMPTS.get()
    }

    pub(super) fn fingerprint_attempts() -> usize {
        FINGERPRINT_ATTEMPTS.get()
    }
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
            computation: "folded exact allocation layout",
        },
        CopyError::AllocationFailed => BuildError::AllocationFailed { structure, items },
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedScalar {
    scalar: Option<u32>,
    width: usize,
    byte_checks: usize,
}

fn decode_scalar(bytes: &[u8]) -> DecodedScalar {
    let Some(&first) = bytes.first() else {
        return invalid(0);
    };
    if first <= 0x7F {
        return DecodedScalar {
            scalar: Some(u32::from(first)),
            width: 1,
            byte_checks: 1,
        };
    }
    if (0xC2..=0xDF).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid(bytes.len().min(2));
        };
        if !is_continuation(second) {
            return invalid(2);
        }
        return DecodedScalar {
            scalar: Some((u32::from(first & 0x1F) << 6) | u32::from(second & 0x3F)),
            width: 2,
            byte_checks: 2,
        };
    }
    if (0xE0..=0xEF).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid(bytes.len().min(3));
        };
        let second_ok = match first {
            0xE0 => (0xA0..=0xBF).contains(&second),
            0xED => (0x80..=0x9F).contains(&second),
            _ => is_continuation(second),
        };
        if !second_ok {
            return invalid(2);
        }
        let Some(&third) = bytes.get(2) else {
            return invalid(bytes.len().min(3));
        };
        if !is_continuation(third) {
            return invalid(3);
        }
        return DecodedScalar {
            scalar: Some(
                (u32::from(first & 0x0F) << 12)
                    | (u32::from(second & 0x3F) << 6)
                    | u32::from(third & 0x3F),
            ),
            width: 3,
            byte_checks: 3,
        };
    }
    if (0xF0..=0xF4).contains(&first) {
        let Some(&second) = bytes.get(1) else {
            return invalid(bytes.len().min(4));
        };
        let second_ok = match first {
            0xF0 => (0x90..=0xBF).contains(&second),
            0xF4 => (0x80..=0x8F).contains(&second),
            _ => is_continuation(second),
        };
        if !second_ok {
            return invalid(2);
        }
        let Some(&third) = bytes.get(2) else {
            return invalid(bytes.len().min(4));
        };
        if !is_continuation(third) {
            return invalid(3);
        }
        let Some(&fourth) = bytes.get(3) else {
            return invalid(bytes.len().min(4));
        };
        if !is_continuation(fourth) {
            return invalid(4);
        }
        return DecodedScalar {
            scalar: Some(
                (u32::from(first & 0x07) << 18)
                    | (u32::from(second & 0x3F) << 12)
                    | (u32::from(third & 0x3F) << 6)
                    | u32::from(fourth & 0x3F),
            ),
            width: 4,
            byte_checks: 4,
        };
    }
    invalid(1)
}

const fn invalid(byte_checks: usize) -> DecodedScalar {
    DecodedScalar {
        scalar: None,
        width: 1,
        byte_checks,
    }
}

const fn is_continuation(byte: u8) -> bool {
    byte & 0xC0 == 0x80
}

#[cfg(test)]
mod tests {
    use super::{
        BuildAccounting, BuildAttempt, BuildError, BuildLimits, BuildResource, DenseFallbackReason,
        FoldedLiteral, FoldedLiteralTriePlan, FoldedScalarClass, PrefilterColumn,
        RootCandidateOutcome, RootGuardCandidate, ScanActual, ScanError, ScanLimits, ScanResource,
        ScanStop, ScanUpperBounds, build_probe, byte_set_insert,
        byte_set_members, classifier_table_insert, collect_union_successor_bytes,
        correlated_root_prefilter_tables, derive_union_successor_guard,
        execute_folded_scan_impl, root_classifier_independent_volume, root_classifier_volume,
        root_prefilter_fingerprint_work_upper_bound, scan_source_probe, successor_guard_is_better,
        union_successor_guard_candidate, volume_density_is_strictly_lower, volume_gain_at_least,
        RootClassifierVolume,
    };
    use crate::{LiteralCandidate, Window};
    use fre_simd_kernels::{
        BYTE_BUCKET_BLOCK_BYTES, BYTE_BUCKET_MAX_COLUMNS, BYTE_SET_WIDE_BLOCK_BYTES,
        ByteBucketClassifier, ByteBucketTables, DispatchPolicy, SimdDispatchContext,
    };

    const KELVIN: [char; 3] = ['K', 'k', '\u{212A}'];
    const SIGMA: [char; 3] = ['Σ', 'ς', 'σ'];
    const CYRILLIC_ES: [char; 3] = ['С', 'с', 'ᲃ'];
    const CYRILLIC_SHA: [char; 2] = ['Ш', 'ш'];
    const CYRILLIC_IE: [char; 2] = ['Е', 'е'];

    fn admitted(patterns: &[FoldedLiteral<'_>]) -> FoldedLiteralTriePlan {
        match FoldedLiteralTriePlan::build(patterns, BuildLimits::default()).unwrap() {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("unexpected fallback: {fallback:?}")
            }
        }
    }

    fn one_class(class: &[char]) -> [FoldedScalarClass<'_>; 1] {
        [FoldedScalarClass::new(class)]
    }

    fn collect(plan: &FoldedLiteralTriePlan, haystack: &[u8]) -> Vec<LiteralCandidate> {
        let mut candidates = Vec::new();
        plan.scan(haystack, ScanLimits::unlimited(), |candidate| {
            candidates.push(candidate);
        })
        .unwrap();
        candidates
    }

    fn exact_build_limits(accounting: &BuildAccounting) -> BuildLimits {
        BuildLimits {
            max_patterns: accounting.patterns,
            max_scalar_positions: accounting.scalar_positions,
            max_equivalent_scalars: accounting.equivalent_scalars,
            max_states: accounting.states_upper_bound,
            max_transitions: accounting.transitions_upper_bound,
            max_work: accounting.work_upper_bound,
            max_persistent_bytes: accounting.persistent_bytes_upper_bound,
            max_peak_bytes: accounting.peak_bytes_upper_bound,
            max_allocations: accounting.allocations_upper_bound,
        }
    }

    fn exact_scan_limits(upper: ScanUpperBounds) -> ScanLimits {
        ScanLimits {
            max_input_bytes: upper.input_bytes,
            max_candidate_starts: upper.candidate_starts,
            max_scalar_decodes: upper.scalar_decodes,
            max_decoded_scalars: upper.decoded_scalars,
            max_invalid_bytes: upper.invalid_bytes,
            max_source_byte_reads: upper.source_byte_reads,
            max_transition_probes: upper.transition_probes,
            max_candidate_events: upper.candidate_events,
            max_work: upper.work,
            max_scratch_bytes: upper.scratch_bytes,
        }
    }

    fn assert_value_projection_parity(
        plan: &FoldedLiteralTriePlan,
        haystack: &[u8],
        window: Window,
        limits: ScanLimits,
        expected_recorded_source_accesses: usize,
        expected_value_source_accesses: usize,
    ) -> (
        Result<Option<LiteralCandidate>, super::ScanAttemptError>,
        Result<bool, super::ScanAttemptError>,
    ) {
        scan_source_probe::reset();
        let recorded_find = plan
            .find_window(haystack, window, limits)
            .map(|(candidate, _receipt)| candidate);
        let recorded_find_accesses = scan_source_probe::accesses();

        scan_source_probe::reset();
        let value_find = plan.find_window_value(haystack, window, limits);
        let value_find_accesses = scan_source_probe::accesses();
        assert_eq!(value_find, recorded_find);
        assert_eq!(
            recorded_find_accesses,
            expected_recorded_source_accesses
        );
        assert_eq!(value_find_accesses, expected_value_source_accesses);

        scan_source_probe::reset();
        let recorded_is_match = plan
            .is_match_window(haystack, window, limits)
            .map(|(matched, _receipt)| matched);
        let recorded_is_match_accesses = scan_source_probe::accesses();

        scan_source_probe::reset();
        let value_is_match = plan.is_match_window_value(haystack, window, limits);
        let value_is_match_accesses = scan_source_probe::accesses();
        assert_eq!(value_is_match, recorded_is_match);
        assert_eq!(
            recorded_is_match_accesses,
            expected_recorded_source_accesses
        );
        assert_eq!(value_is_match_accesses, expected_value_source_accesses);

        (recorded_find, recorded_is_match)
    }

    fn synthetic_primary(
        byte: u8,
        offset: u8,
        scalar_index: usize,
        local_offset: u8,
    ) -> PrefilterColumn {
        let mut byte_set = [0_u64; 4];
        byte_set_insert(&mut byte_set, byte);
        PrefilterColumn {
            needles: [byte, 0, 0],
            needle_count: 1,
            byte_set,
            high_nibbles: 1_u16 << (byte >> 4),
            offset,
            scalar_index,
            local_offset,
            structural_leads: usize::from(matches!(byte, 0xC2..=0xF4)),
            frequency_score: u64::from(super::byte_frequency_rank(byte)).saturating_add(1),
        }
    }

    fn synthetic_wide_primary(bytes: &[u8]) -> PrefilterColumn {
        let mut byte_set = [0_u64; 4];
        let mut high_nibbles = 0_u16;
        let mut frequency_score = 0_u64;
        for &byte in bytes {
            byte_set_insert(&mut byte_set, byte);
            high_nibbles |= 1_u16 << (byte >> 4);
            frequency_score = frequency_score
                .checked_add(u64::from(super::byte_frequency_rank(byte)).saturating_add(1))
                .unwrap();
        }
        PrefilterColumn {
            needles: [0; 3],
            needle_count: u16::try_from(bytes.len()).unwrap(),
            byte_set,
            high_nibbles,
            offset: 0,
            scalar_index: 0,
            local_offset: 0,
            structural_leads: bytes
                .iter()
                .filter(|&&byte| matches!(byte, 0xC2..=0xF4))
                .count(),
            frequency_score,
        }
    }

    fn correlated_ascii_plan() -> FoldedLiteralTriePlan {
        const ROOT_1: [char; 1] = ['\u{1}'];
        const ROOT_2: [char; 1] = ['\u{2}'];
        const ROOT_3: [char; 1] = ['\u{3}'];
        const ROOT_4: [char; 1] = ['\u{4}'];
        const A_D: [char; 4] = ['a', 'b', 'c', 'd'];
        const E_H: [char; 4] = ['e', 'f', 'g', 'h'];
        const I_L: [char; 4] = ['i', 'j', 'k', 'l'];
        const M_P: [char; 4] = ['m', 'n', 'o', 'p'];
        let first = [
            FoldedScalarClass::new(&ROOT_1),
            FoldedScalarClass::new(&A_D),
        ];
        let second = [
            FoldedScalarClass::new(&ROOT_2),
            FoldedScalarClass::new(&E_H),
        ];
        let third = [
            FoldedScalarClass::new(&ROOT_3),
            FoldedScalarClass::new(&I_L),
        ];
        let fourth = [
            FoldedScalarClass::new(&ROOT_4),
            FoldedScalarClass::new(&M_P),
        ];
        admitted(&[
            FoldedLiteral::new(&first),
            FoldedLiteral::new(&second),
            FoldedLiteral::new(&third),
            FoldedLiteral::new(&fourth),
        ])
    }

    fn correlated_variable_width_plan(
        columns: usize,
    ) -> (FoldedLiteralTriePlan, [Vec<u8>; 4]) {
        const ROOT_1: [char; 1] = ['\u{442}'];
        const ROOT_2: [char; 1] = ['\u{7ff}'];
        const ROOT_3: [char; 1] = ['\u{800}'];
        const ROOT_4: [char; 1] = ['\u{1000}'];
        const TAIL_1: [[char; 1]; 3] = [['a'], ['b'], ['c']];
        const TAIL_2: [[char; 1]; 3] = [['e'], ['f'], ['g']];
        const TAIL_3: [[char; 1]; 3] = [['i'], ['j'], ['k']];
        const TAIL_4: [[char; 1]; 3] = [['m'], ['n'], ['o']];

        assert!((2..=BYTE_BUCKET_MAX_COLUMNS).contains(&columns));
        let tails = columns - 1;
        let make_classes = |root: &'static [char], suffixes: &'static [[char; 1]; 3]| {
            core::iter::once(FoldedScalarClass::new(root))
                .chain(
                    suffixes[..tails]
                        .iter()
                        .map(|class| FoldedScalarClass::new(class)),
                )
                .collect::<Vec<_>>()
        };
        let first = make_classes(&ROOT_1, &TAIL_1);
        let second = make_classes(&ROOT_2, &TAIL_2);
        let third = make_classes(&ROOT_3, &TAIL_3);
        let fourth = make_classes(&ROOT_4, &TAIL_4);
        let patterns = [
            FoldedLiteral::new(&first),
            FoldedLiteral::new(&second),
            FoldedLiteral::new(&third),
            FoldedLiteral::new(&fourth),
        ];
        let exact = patterns.map(|pattern| {
            pattern
                .classes()
                .iter()
                .flat_map(|class| {
                    let mut encoded = [0_u8; 4];
                    class.equivalents()[0]
                        .encode_utf8(&mut encoded)
                        .as_bytes()
                        .to_vec()
                })
                .collect::<Vec<_>>()
        });
        (admitted(&patterns), exact)
    }

    fn assert_prefilter_matches_scalar(
        plan: &FoldedLiteralTriePlan,
        haystack: &[u8],
        window: Window,
        stop: ScanStop,
    ) {
        let source = &haystack[window.start()..window.end()];
        let upper = plan.scan_upper_bounds(source.len()).unwrap();
        let mut scalar = Vec::new();
        let scalar_actual = execute_folded_scan_impl(
            plan,
            source,
            window.start(),
            upper,
            None,
            stop,
            &mut |candidate| scalar.push(candidate),
        )
        .unwrap();
        let mut prefetched = Vec::new();
        let prefetched_actual = execute_folded_scan_impl(
            plan,
            source,
            window.start(),
            upper,
            plan.root_prefilter.as_ref(),
            stop,
            &mut |candidate| prefetched.push(candidate),
        )
        .unwrap();
        assert_eq!(prefetched, scalar);
        assert!(super::actual_within(scalar_actual, upper));
        assert!(super::actual_within(prefetched_actual, upper));
    }

    fn union_successor_members(
        patterns: &[FoldedLiteral<'_>],
        primary: PrefilterColumn,
        distance: usize,
    ) -> Option<Vec<u8>> {
        let mut byte_set = [0_u64; 4];
        let mut work = 0;
        for pattern in patterns {
            if !collect_union_successor_bytes(
                *pattern,
                primary.scalar_index,
                usize::from(primary.local_offset),
                distance,
                &mut byte_set,
                &mut work,
            )
            .unwrap()
            {
                return None;
            }
        }
        Some(byte_set_members(byte_set).collect())
    }

    #[test]
    fn kelvin_sigma_russian_and_duplicates_keep_original_byte_offsets() {
        let kelvin = FoldedScalarClass::new(&KELVIN);
        let sigma = FoldedScalarClass::new(&SIGMA);
        let phrase_classes = [kelvin, sigma];
        let russian_classes = one_class(&CYRILLIC_ES);
        let patterns = [
            FoldedLiteral::new(&phrase_classes),
            FoldedLiteral::new(&russian_classes),
            FoldedLiteral::new(&phrase_classes),
        ];
        let plan = admitted(&patterns);
        let haystack = "x\u{212A}ς Kσ kΣ Ссᲃ".as_bytes();
        let candidates = collect(&plan, haystack);
        let phrase_spans = ["\u{212A}ς", "Kσ", "kΣ"]
            .into_iter()
            .flat_map(|text| {
                let start = core::str::from_utf8(haystack).unwrap().find(text).unwrap();
                [
                    (0, start, start + text.len()),
                    (2, start, start + text.len()),
                ]
            })
            .collect::<Vec<_>>();
        let russian_spans = ["С", "с", "ᲃ"]
            .into_iter()
            .map(|text| {
                let start = core::str::from_utf8(haystack).unwrap().find(text).unwrap();
                (1, start, start + text.len())
            })
            .collect::<Vec<_>>();
        let mut expected = phrase_spans
            .into_iter()
            .chain(russian_spans)
            .collect::<Vec<_>>();
        let mut actual = candidates
            .into_iter()
            .map(|candidate| {
                (
                    candidate.pattern_index(),
                    candidate.start(),
                    candidate.end(),
                )
            })
            .collect::<Vec<_>>();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected);
    }

    #[test]
    fn union_successor_frontier_covers_variable_widths_and_safe_cross_products() {
        const A: [char; 1] = ['A'];
        const B: [char; 1] = ['B'];
        const C: [char; 1] = ['C'];
        const D: [char; 1] = ['D'];
        const P: [char; 1] = ['p'];
        let left = [
            FoldedScalarClass::new(&P),
            FoldedScalarClass::new(&A),
            FoldedScalarClass::new(&B),
        ];
        let right = [
            FoldedScalarClass::new(&P),
            FoldedScalarClass::new(&C),
            FoldedScalarClass::new(&D),
        ];
        let alternatives = [FoldedLiteral::new(&left), FoldedLiteral::new(&right)];
        let primary = synthetic_primary(b'p', 0, 0, 0);
        assert_eq!(
            union_successor_members(&alternatives, primary, 1).unwrap(),
            [b'A', b'C']
        );
        assert_eq!(
            union_successor_members(&alternatives, primary, 2).unwrap(),
            [b'B', b'D']
        );
        let first = union_successor_members(&alternatives, primary, 1).unwrap();
        let second = union_successor_members(&alternatives, primary, 2).unwrap();
        for crossed in [b"pAD", b"pCB"] {
            assert!(first.contains(&crossed[1]));
            assert!(second.contains(&crossed[2]));
        }

        const X: [char; 1] = ['x'];
        const Y: [char; 1] = ['y'];
        const Z: [char; 1] = ['z'];
        const Q: [char; 1] = ['q'];
        let variable_width = [
            FoldedScalarClass::new(&KELVIN),
            FoldedScalarClass::new(&X),
            FoldedScalarClass::new(&Y),
            FoldedScalarClass::new(&Z),
            FoldedScalarClass::new(&Q),
        ];
        let variable_width = [FoldedLiteral::new(&variable_width)];
        let primary = synthetic_primary(b'K', 0, 0, 0);
        assert_eq!(
            union_successor_members(&variable_width, primary, 1).unwrap(),
            [b'x', 0x84]
        );
        assert_eq!(
            union_successor_members(&variable_width, primary, 2).unwrap(),
            [b'y', 0xAA]
        );
        assert_eq!(
            union_successor_members(&variable_width, primary, 3).unwrap(),
            [b'x', b'z']
        );
        assert_eq!(
            union_successor_members(&variable_width, primary, 4).unwrap(),
            [b'q', b'y']
        );

        let terminal = [FoldedScalarClass::new(&KELVIN)];
        let terminal = [FoldedLiteral::new(&terminal)];
        assert!(union_successor_members(&terminal, primary, 1).is_none());
        let mut work = 0;
        assert_eq!(
            derive_union_successor_guard(&terminal, primary, &mut work).unwrap(),
            None
        );
    }

    #[test]
    fn correlated_fingerprint_carries_buckets_across_variable_width_utf8_frontiers() {
        const UPPER_K: [char; 1] = ['K'];
        const LOWER_K: [char; 1] = ['k'];
        const KELVIN_ONLY: [char; 1] = ['\u{212A}'];
        const Q: [char; 1] = ['Q'];
        const A: [char; 1] = ['a'];
        const B: [char; 1] = ['b'];
        const C: [char; 1] = ['c'];
        const D: [char; 1] = ['d'];
        const E: [char; 1] = ['e'];
        const F: [char; 1] = ['f'];
        const G: [char; 1] = ['g'];
        const H: [char; 1] = ['h'];
        const I: [char; 1] = ['i'];
        const J: [char; 1] = ['j'];
        const L: [char; 1] = ['l'];
        const M: [char; 1] = ['m'];
        const N: [char; 1] = ['n'];
        const O: [char; 1] = ['o'];
        const P: [char; 1] = ['p'];
        let upper = [
            FoldedScalarClass::new(&UPPER_K),
            FoldedScalarClass::new(&A),
            FoldedScalarClass::new(&B),
            FoldedScalarClass::new(&C),
            FoldedScalarClass::new(&D),
        ];
        let lower = [
            FoldedScalarClass::new(&LOWER_K),
            FoldedScalarClass::new(&E),
            FoldedScalarClass::new(&F),
            FoldedScalarClass::new(&G),
            FoldedScalarClass::new(&H),
        ];
        let kelvin = [
            FoldedScalarClass::new(&KELVIN_ONLY),
            FoldedScalarClass::new(&I),
            FoldedScalarClass::new(&J),
            FoldedScalarClass::new(&L),
            FoldedScalarClass::new(&P),
        ];
        let q = [
            FoldedScalarClass::new(&Q),
            FoldedScalarClass::new(&M),
            FoldedScalarClass::new(&N),
            FoldedScalarClass::new(&O),
            FoldedScalarClass::new(&P),
        ];
        let patterns = [
            FoldedLiteral::new(&upper),
            FoldedLiteral::new(&lower),
            FoldedLiteral::new(&kelvin),
            FoldedLiteral::new(&q),
        ];
        let primary = synthetic_wide_primary(&[b'K', b'k', 0xE2, b'Q']);
        let mut work = 0_usize;
        let (tables, guard) = correlated_root_prefilter_tables(
            &patterns,
            primary,
            None,
            &mut work,
        )
        .unwrap()
        .expect("four source-distinct prefixes justify a correlated fingerprint");
        assert_eq!(tables.columns(), BYTE_BUCKET_MAX_COLUMNS);
        assert_eq!(guard, None);
        let classifier = ByteBucketClassifier::new(tables);
        for prefix in [
            b"Kabc".as_slice(),
            b"kefg".as_slice(),
            "\u{212A}i".as_bytes(),
            b"Qmno".as_slice(),
        ] {
            assert_ne!(classifier.classify_prefix(prefix), Some(0));
        }
        assert_eq!(classifier.classify_prefix(b"Kebc"), Some(0));
        let equivalent_scalars = patterns
            .iter()
            .flat_map(|pattern| pattern.classes())
            .map(|class| class.equivalents().len())
            .sum();
        assert!(
            work <= root_prefilter_fingerprint_work_upper_bound(equivalent_scalars).unwrap()
        );
    }

    #[test]
    fn correlated_volume_normalizes_dimensions_thresholds_and_guard_positions() {
        let equal_one_column = RootClassifierVolume {
            numerator: 1,
            dimensions: 1,
        };
        let equal_two_columns = RootClassifierVolume {
            numerator: 256,
            dimensions: 2,
        };
        assert!(volume_gain_at_least(equal_one_column, equal_two_columns, 1).unwrap());
        assert!(volume_gain_at_least(equal_two_columns, equal_one_column, 1).unwrap());
        assert!(!volume_gain_at_least(equal_two_columns, equal_one_column, 2).unwrap());
        assert!(!volume_density_is_strictly_lower(equal_one_column, equal_two_columns).unwrap());
        assert!(!volume_density_is_strictly_lower(equal_two_columns, equal_one_column).unwrap());

        let strict_but_less_than_twofold = RootClassifierVolume {
            numerator: 3,
            dimensions: 2,
        };
        let strict_baseline = RootClassifierVolume {
            numerator: 4,
            dimensions: 2,
        };
        assert!(
            volume_density_is_strictly_lower(strict_but_less_than_twofold, strict_baseline)
                .unwrap()
        );
        assert!(
            !volume_gain_at_least(strict_but_less_than_twofold, strict_baseline, 2).unwrap()
        );

        let threshold_baseline = RootClassifierVolume {
            numerator: 3,
            dimensions: 1,
        };
        assert!(
            volume_gain_at_least(equal_two_columns, threshold_baseline, 3).unwrap()
        );
        assert!(
            !volume_gain_at_least(equal_two_columns, threshold_baseline, 4).unwrap()
        );

        let primary = synthetic_wide_primary(&[1, 2, 3, 4]);
        let mut low = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
        let mut high = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
        for root in 1_u8..=4 {
            classifier_table_insert(&mut low[0], &mut high[0], root, 1);
        }
        for suffix in [b'a', b'b'] {
            classifier_table_insert(&mut low[1], &mut high[1], suffix, 1);
        }
        let without_guard = root_classifier_volume(low, high, 2, primary, None).unwrap();
        assert_eq!(
            without_guard,
            RootClassifierVolume {
                numerator: 8,
                dimensions: 2,
            }
        );
        let independent =
            root_classifier_independent_volume(low, high, 2, primary, None).unwrap();
        assert_eq!(independent, without_guard);
        assert!(!volume_density_is_strictly_lower(without_guard, independent).unwrap());

        let mut correlated_low = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
        let mut correlated_high = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
        for (bucket, root, suffix) in [
            (1_u8, 1_u8, b'a'),
            (2_u8, 2_u8, b'b'),
            (4_u8, 3_u8, b'c'),
            (8_u8, 4_u8, b'd'),
        ] {
            classifier_table_insert(
                &mut correlated_low[0],
                &mut correlated_high[0],
                root,
                bucket,
            );
            classifier_table_insert(
                &mut correlated_low[1],
                &mut correlated_high[1],
                suffix,
                bucket,
            );
        }
        let correlated = root_classifier_volume(
            correlated_low,
            correlated_high,
            2,
            primary,
            None,
        )
        .unwrap();
        assert_eq!(
            correlated,
            RootClassifierVolume {
                numerator: 4,
                dimensions: 2,
            }
        );
        let independent = root_classifier_independent_volume(
            correlated_low,
            correlated_high,
            2,
            primary,
            None,
        )
        .unwrap();
        assert_eq!(
            independent,
            RootClassifierVolume {
                numerator: 16,
                dimensions: 2,
            }
        );
        assert!(volume_density_is_strictly_lower(correlated, independent).unwrap());

        let mut same_byte_set = [0_u64; 4];
        byte_set_insert(&mut same_byte_set, 1);
        byte_set_insert(&mut same_byte_set, 2);
        let same_column = RootGuardCandidate {
            byte_set: same_byte_set,
            needle_count: 2,
            offset: 0,
            structural_leads: 0,
            frequency_score: 0,
        };
        let same_volume =
            root_classifier_volume(low, high, 2, primary, Some(same_column)).unwrap();
        assert_eq!(
            same_volume,
            RootClassifierVolume {
                numerator: 4,
                dimensions: 2,
            }
        );
        assert!(volume_gain_at_least(same_volume, without_guard, 2).unwrap());

        let outside_selective = RootGuardCandidate {
            offset: 3,
            ..same_column
        };
        let outside_volume =
            root_classifier_volume(low, high, 2, primary, Some(outside_selective)).unwrap();
        assert_eq!(
            outside_volume,
            RootClassifierVolume {
                numerator: 16,
                dimensions: 3,
            }
        );
        assert!(volume_gain_at_least(outside_volume, without_guard, 2).unwrap());

        let outside_unselective = RootGuardCandidate {
            byte_set: [u64::MAX; 4],
            needle_count: 256,
            offset: 3,
            structural_leads: 0,
            frequency_score: 0,
        };
        let unselective_volume =
            root_classifier_volume(low, high, 2, primary, Some(outside_unselective)).unwrap();
        assert_eq!(
            unselective_volume,
            RootClassifierVolume {
                numerator: 2_048,
                dimensions: 3,
            }
        );
        assert!(
            !volume_gain_at_least(unselective_volume, without_guard, 2).unwrap()
        );
    }

    #[test]
    fn admitted_correlated_root_publishes_columns_and_screens_absent_blocks_once() {
        build_probe::reset();
        let plan = correlated_ascii_plan();
        assert_eq!(plan.build.root_prefilter_offset, Some(0));
        assert_eq!(plan.build.root_prefilter_needles, 4);
        assert_eq!(plan.root_prefilter_classifier_columns(), 2);
        assert_eq!(plan.build.root_prefilter_guard_needles, 0);
        assert_eq!(build_probe::fingerprint_attempts(), 1);

        let absent = vec![b'q'; 64];
        let upper = plan.scan_upper_bounds(absent.len()).unwrap();
        let mut absent_candidates = Vec::new();
        let absent_actual = execute_folded_scan_impl(
            &plan,
            &absent,
            0,
            upper,
            plan.root_prefilter.as_ref(),
            ScanStop::Never,
            &mut |candidate| absent_candidates.push(candidate),
        )
        .unwrap();
        assert!(absent_candidates.is_empty());
        assert_eq!(absent_actual.source_byte_reads, absent.len());
        assert!(super::actual_within(absent_actual, upper));

        let mut false_root = absent.clone();
        false_root[0] = 1;
        false_root[1] = b'z';
        let upper = plan.scan_upper_bounds(false_root.len()).unwrap();
        let mut false_candidates = Vec::new();
        let false_actual = execute_folded_scan_impl(
            &plan,
            &false_root,
            0,
            upper,
            plan.root_prefilter.as_ref(),
            ScanStop::Never,
            &mut |candidate| false_candidates.push(candidate),
        )
        .unwrap();
        assert!(false_candidates.is_empty());
        assert_eq!(
            false_actual.source_byte_reads,
            false_root.len() + 2 * super::BYTE_BUCKET_BLOCK_BYTES
        );
        assert!(super::actual_within(false_actual, upper));

        let mut early = vec![b'q'; 64];
        early[0] = 1;
        early[1] = b'a';
        let upper = plan.scan_upper_bounds(early.len()).unwrap();
        let mut early_candidates = Vec::new();
        let early_actual = execute_folded_scan_impl(
            &plan,
            &early,
            0,
            upper,
            plan.root_prefilter.as_ref(),
            ScanStop::AfterMatchingStart,
            &mut |candidate| early_candidates.push(candidate),
        )
        .unwrap();
        assert_eq!(early_candidates, [LiteralCandidate::new(0, 0, 2)]);
        assert_eq!(
            early_actual.source_byte_reads,
            3 * super::BYTE_BUCKET_BLOCK_BYTES + 2
        );
        assert!(super::actual_within(early_actual, upper));

        let mut valid = absent;
        valid[0] = 1;
        valid[1] = b'a';
        let upper = plan
            .root_candidate_single_pass_upper_bounds(valid.len(), 2)
            .unwrap();
        let found = plan
            .find_root_candidate_precharged(&valid, Window::full(&valid), upper)
            .unwrap();
        assert_eq!(found.outcome, RootCandidateOutcome::Candidate { start: 0 });
        assert_eq!(found.receipt.actual.source_byte_reads, 2);
        assert!(super::actual_within(found.receipt.actual, upper));

        let mut tail = vec![b'q'; 18];
        tail[16] = 1;
        tail[17] = b'a';
        let upper = plan.scan_upper_bounds(tail.len()).unwrap();
        let mut scalar = Vec::new();
        execute_folded_scan_impl(
            &plan,
            &tail,
            0,
            upper,
            None,
            ScanStop::Never,
            &mut |candidate| scalar.push(candidate),
        )
        .unwrap();
        let mut prefetched = Vec::new();
        let actual = execute_folded_scan_impl(
            &plan,
            &tail,
            0,
            upper,
            plan.root_prefilter.as_ref(),
            ScanStop::Never,
            &mut |candidate| prefetched.push(candidate),
        )
        .unwrap();
        assert_eq!(prefetched, scalar);
        assert_eq!(prefetched, [LiteralCandidate::new(0, 16, 18)]);
        assert!(super::actual_within(actual, upper));
    }

    #[test]
    fn correlated_variable_width_nonzero_offset_matches_scalar_across_extents() {
        for columns in 2..=BYTE_BUCKET_MAX_COLUMNS {
            let (plan, exact) = correlated_variable_width_plan(columns);
            assert_eq!(plan.build.root_prefilter_offset, Some(1));
            assert_eq!(plan.build.root_prefilter_guard_needles, 0);
            assert_eq!(
                plan.root_prefilter_classifier_columns(),
                if columns == 2 { 1 } else { columns },
                "nonzero-offset correlation needs two forward bytes and bucket discrimination"
            );
            assert!(plan.root_prefilter_is_necessary_for(&exact));

            for len in 0..=18 {
                let mut source = vec![b'!'; len];
                let pattern = &exact[len % exact.len()];
                if pattern.len() <= source.len() {
                    let start = source.len().saturating_sub(pattern.len()) / 2;
                    source[start..start + pattern.len()].copy_from_slice(pattern);
                }
                let window = Window::full(&source);
                assert_prefilter_matches_scalar(&plan, &source, window, ScanStop::Never);
                assert_prefilter_matches_scalar(
                    &plan,
                    &source,
                    window,
                    ScanStop::AfterMatchingStart,
                );
            }

            for residue in 0..BYTE_BUCKET_BLOCK_BYTES {
                let inner_len = 2 * BYTE_BUCKET_BLOCK_BYTES + residue;
                let window_start = 3;
                let window_end = window_start + inner_len;
                let mut framed = vec![b'#'; window_end + 5];
                framed[window_start..window_end].fill(b'!');
                let first = &exact[residue % exact.len()];
                let second = &exact[(residue + 1) % exact.len()];
                let boundary_start = window_start + BYTE_BUCKET_BLOCK_BYTES - 1;
                framed[boundary_start..boundary_start + first.len()].copy_from_slice(first);
                let tail_start = window_end - second.len();
                framed[tail_start..window_end].copy_from_slice(second);
                let window = Window::new(window_start, window_end);
                assert_prefilter_matches_scalar(&plan, &framed, window, ScanStop::Never);
                assert_prefilter_matches_scalar(
                    &plan,
                    &framed,
                    window,
                    ScanStop::AfterMatchingStart,
                );
            }
        }
    }

    #[test]
    fn attachment_authenticates_correlated_bucket_identity_extent_and_offset() {
        let mut plan = correlated_ascii_plan();
        let exact = [
            (1_u8, b"abcd".as_slice()),
            (2_u8, b"efgh".as_slice()),
            (3_u8, b"ijkl".as_slice()),
            (4_u8, b"mnop".as_slice()),
        ]
        .into_iter()
        .flat_map(|(root, suffixes)| {
            suffixes
                .iter()
                .map(move |&suffix| vec![root, suffix])
        })
        .collect::<Vec<_>>();
        assert!(plan.root_prefilter_is_necessary_for(&exact));

        let mut low = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
        let mut high = [[0_u8; 16]; BYTE_BUCKET_MAX_COLUMNS];
        for (bucket, (root, suffixes)) in [
            (1_u8, (1_u8, b"abcd".as_slice())),
            (2_u8, (2_u8, b"efgh".as_slice())),
            (4_u8, (3_u8, b"ijkl".as_slice())),
            (8_u8, (4_u8, b"mnop".as_slice())),
        ] {
            classifier_table_insert(&mut low[0], &mut high[0], root, bucket);
            for &suffix in suffixes {
                if root != 1 {
                    classifier_table_insert(&mut low[1], &mut high[1], suffix, bucket);
                }
            }
        }
        let corrupted = ByteBucketTables::new(2, low, high).unwrap();
        plan.root_prefilter.as_mut().unwrap().classifier =
            Some(ByteBucketClassifier::new(corrupted));
        assert!(
            exact.iter().all(|pattern| {
                plan.root_prefilter
                    .as_ref()
                    .unwrap()
                    .primary_matches(pattern[0])
            }),
            "all independent primary checks still pass"
        );
        assert!(!plan.root_prefilter_is_necessary_for(&exact));
        assert!(matches!(
            plan.root_candidate_single_pass_upper_bounds(64, 1),
            Err(ScanError::Invariant { .. })
        ));

        let mut plan = correlated_ascii_plan();
        plan.root_prefilter.as_mut().unwrap().offset = 1;
        assert!(!plan.root_prefilter_is_necessary_for(&exact));
    }

    #[test]
    fn union_successor_guard_is_authenticated_and_rejections_keep_scanning() {
        const A: [char; 1] = ['a'];
        const B: [char; 1] = ['b'];
        let classes = [
            FoldedScalarClass::new(&KELVIN),
            FoldedScalarClass::new(&A),
            FoldedScalarClass::new(&B),
        ];
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        let prefilter = plan.root_prefilter.as_ref().unwrap();
        assert_eq!(prefilter.offset, 0);
        assert!(prefilter.has_guard());
        assert!((1..=4).contains(&prefilter.guard_offset));

        let exact = [
            b"Kab".to_vec(),
            b"kab".to_vec(),
            "\u{212A}ab".as_bytes().to_vec(),
        ];
        assert!(plan.root_prefilter_is_necessary_for(&exact));
        let mut corrupted = exact.clone();
        corrupted[0][usize::from(prefilter.guard_offset)] = 0xFF;
        assert!(!plan.root_prefilter_is_necessary_for(&corrupted));

        let false_roots = b"KxKxKxKxKxKxKxKx";
        let upper = plan
            .root_candidate_single_pass_upper_bounds(false_roots.len(), 5)
            .unwrap();
        let rejected = plan
            .find_root_candidate_precharged(false_roots, Window::full(false_roots), upper)
            .unwrap();
        assert_eq!(rejected.outcome, RootCandidateOutcome::NoCandidate);
        assert_eq!(rejected.receipt.actual.candidate_starts, 0);

        let valid = b"xxKab";
        let upper = plan
            .root_candidate_single_pass_upper_bounds(valid.len(), 5)
            .unwrap();
        assert_eq!(
            plan.find_root_candidate_precharged(valid, Window::full(valid), upper)
                .unwrap()
                .outcome,
            RootCandidateOutcome::Candidate { start: 2 }
        );
    }

    #[test]
    fn one_column_empty_blocks_preserve_progress_and_early_stop_accounting() {
        const FOUR: [char; 4] = ['A', 'B', 'C', 'D'];
        let classes = one_class(&FOUR);
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        assert_eq!(plan.root_prefilter_classifier_columns(), 1);

        for len in [15, 16, 17, 32] {
            let source = vec![b'!'; len];
            let upper = plan.scan_upper_bounds(source.len()).unwrap();
            let mut candidates = Vec::new();
            let actual = execute_folded_scan_impl(
                &plan,
                &source,
                0,
                upper,
                plan.root_prefilter.as_ref(),
                ScanStop::AfterMatchingStart,
                &mut |candidate| candidates.push(candidate),
            )
            .unwrap();
            assert!(candidates.is_empty());
            assert_eq!(actual.source_byte_reads, source.len());
            assert!(super::actual_within(actual, upper));
        }

        let mut source = vec![b'!'; 48];
        source[32] = b'A';
        let upper = plan.scan_upper_bounds(source.len()).unwrap();
        let mut candidates = Vec::new();
        let actual = execute_folded_scan_impl(
            &plan,
            &source,
            0,
            upper,
            plan.root_prefilter.as_ref(),
            ScanStop::AfterMatchingStart,
            &mut |candidate| candidates.push(candidate),
        )
        .unwrap();
        assert_eq!(candidates, [LiteralCandidate::new(0, 32, 33)]);
        assert_eq!(actual.source_byte_reads, 49);
        assert_eq!(actual.candidate_starts, 1);
        assert!(super::actual_within(actual, upper));
    }

    #[test]
    fn wide_root_fingerprint_is_optional_under_the_baseline_work_limit() {
        const FOUR: [char; 4] = ['A', 'B', 'C', 'D'];
        let classes = one_class(&FOUR);
        let patterns = [FoldedLiteral::new(&classes)];
        let baseline = super::preflight_from_lengths(&patterns).unwrap();
        assert_eq!(baseline.root_prefilter_work_upper_bound, 2_696);
        assert_eq!(baseline.work_upper_bound, 2_750);

        build_probe::reset();
        let baseline_plan = match FoldedLiteralTriePlan::build(
            &patterns,
            exact_build_limits(&baseline),
        )
        .unwrap()
        {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("unexpected fallback: {fallback:?}")
            }
        };
        assert_eq!(baseline_plan.root_prefilter_classifier_columns(), 1);
        assert_eq!(baseline_plan.build.work_upper_bound, baseline.work_upper_bound);
        assert_eq!(build_probe::fingerprint_attempts(), 0);
        assert_eq!(build_probe::successor_attempts(), 0);
        assert_eq!(build_probe::allocation_attempts(), 3);

        let plan = admitted(&patterns);
        let accounting = plan.build_accounting();
        assert_eq!(accounting.root_prefilter_needles, 4);
        assert_eq!(accounting.root_prefilter_guard_needles, 0);
        assert_eq!(plan.root_prefilter_classifier_columns(), 1);
        assert_eq!(accounting.root_prefilter_work_upper_bound, 69_098);
        assert_eq!(accounting.work_upper_bound, 69_152);

        build_probe::reset();
        assert!(matches!(
            FoldedLiteralTriePlan::build(&patterns, exact_build_limits(&accounting)).unwrap(),
            BuildAttempt::Admitted(_)
        ));
        assert_eq!(build_probe::fingerprint_attempts(), 1);
        assert_eq!(build_probe::successor_attempts(), 0);
    }

    #[test]
    fn narrow_successor_upper_is_enforced_before_derivation_or_allocation() {
        const A: [char; 1] = ['a'];
        const B: [char; 1] = ['b'];
        let classes = [
            FoldedScalarClass::new(&KELVIN),
            FoldedScalarClass::new(&A),
            FoldedScalarClass::new(&B),
        ];
        let patterns = [FoldedLiteral::new(&classes)];
        let base = super::preflight_from_lengths(&patterns).unwrap();
        let successor = super::root_prefilter_successor_work_upper_bound(
            base.equivalent_scalars,
        )
        .unwrap();
        assert_eq!(base.root_prefilter_work_upper_bound, 6_836);
        assert_eq!(base.work_upper_bound, 6_918);
        assert_eq!(successor, 2_616);

        let accounting = admitted(&patterns).build_accounting();
        assert_eq!(accounting.root_prefilter_needles, 3);
        assert_ne!(accounting.root_prefilter_guard_needles, 0);
        assert_eq!(
            accounting.root_prefilter_work_upper_bound,
            base.root_prefilter_work_upper_bound + successor
        );
        assert_eq!(accounting.root_prefilter_work_upper_bound, 9_452);
        assert_eq!(accounting.work_upper_bound, 9_534);

        build_probe::reset();
        assert!(matches!(
            FoldedLiteralTriePlan::build(&patterns, exact_build_limits(&accounting)).unwrap(),
            BuildAttempt::Admitted(_)
        ));
        assert_eq!(build_probe::successor_attempts(), 1);

        build_probe::reset();
        assert!(matches!(
            FoldedLiteralTriePlan::build(
                &patterns,
                BuildLimits {
                    max_work: accounting.work_upper_bound - 1,
                    ..BuildLimits::unlimited()
                }
            ),
            Err(BuildError::Resource {
                resource: BuildResource::Work,
                needed: 9_534,
                limit: 9_533,
            })
        ));
        assert_ne!(build_probe::scalar_reads(), 0);
        assert_eq!(build_probe::successor_attempts(), 0);
        assert_eq!(build_probe::allocation_attempts(), 0);
    }

    #[test]
    fn successor_replacement_requires_better_score_or_an_equal_closer_column() {
        let candidate = |offset, structural_leads, frequency_score| RootGuardCandidate {
            byte_set: [0; 4],
            needle_count: 1,
            offset,
            structural_leads,
            frequency_score,
        };
        let primary_offset = 5;
        let fixed = candidate(10, 0, 20);
        let closer = candidate(6, 0, 20);
        let equal_farther = candidate(11, 0, 20);
        let better_farther = candidate(11, 0, 19);
        let worse_closer = candidate(6, 0, 21);
        assert!(successor_guard_is_better(closer, fixed, primary_offset));
        assert!(!successor_guard_is_better(
            equal_farther,
            fixed,
            primary_offset
        ));
        assert!(successor_guard_is_better(
            better_farther,
            fixed,
            primary_offset
        ));
        assert!(!successor_guard_is_better(
            worse_closer,
            fixed,
            primary_offset
        ));

        let mut broad = [0_u64; 4];
        for byte in b'a'..=b'i' {
            byte_set_insert(&mut broad, byte);
        }
        let mut work = 0;
        assert_eq!(
            union_successor_guard_candidate(broad, 1, &mut work).unwrap(),
            None,
            "a broad successor cannot justify a scalar load at every primary hit"
        );
    }

    #[test]
    fn malformed_utf8_never_matches_and_advances_one_byte() {
        let classes = one_class(&KELVIN);
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        let mut haystack = vec![0xFF, 0xC0, 0xAF, 0xED, 0xA0, 0x80, 0xF4, 0x90, 0x80, 0x80];
        let valid_start = haystack.len();
        haystack.extend_from_slice("\u{212A}".as_bytes());
        haystack.extend_from_slice(&[0xE2, 0x84]);
        let candidates = collect(&plan, &haystack);
        assert_eq!(
            candidates,
            [LiteralCandidate::new(
                0,
                valid_start,
                valid_start + "\u{212A}".len()
            )]
        );
    }

    #[test]
    fn prefix_lengths_duplicates_and_pattern_priority_have_stable_order() {
        let kelvin = FoldedScalarClass::new(&KELVIN);
        let one = [kelvin];
        let two = [kelvin, kelvin];
        let patterns = [
            FoldedLiteral::new(&two),
            FoldedLiteral::new(&one),
            FoldedLiteral::new(&two),
            FoldedLiteral::new(&one),
        ];
        let plan = admitted(&patterns);
        assert_eq!(
            collect(&plan, b"KK"),
            [
                LiteralCandidate::new(1, 0, 1),
                LiteralCandidate::new(3, 0, 1),
                LiteralCandidate::new(0, 0, 2),
                LiteralCandidate::new(2, 0, 2),
                LiteralCandidate::new(1, 1, 2),
                LiteralCandidate::new(3, 1, 2),
            ]
        );
    }

    #[test]
    fn first_candidate_projection_stops_after_one_start_and_keeps_pattern_priority() {
        let kelvin = FoldedScalarClass::new(&KELVIN);
        let one = [kelvin];
        let two = [kelvin, kelvin];
        let patterns = [
            FoldedLiteral::new(&two),
            FoldedLiteral::new(&one),
            FoldedLiteral::new(&two),
            FoldedLiteral::new(&one),
        ];
        let plan = admitted(&patterns);
        let (candidate, receipt) = plan
            .find_window(b"xKKKK", Window::new(1, 5), ScanLimits::unlimited())
            .unwrap();
        assert_eq!(candidate, Some(LiteralCandidate::new(0, 1, 3)));
        assert_eq!(receipt.actual.candidate_starts, 1);
        assert_eq!(receipt.actual.candidate_events, 4);
        assert!(receipt.actual.work < receipt.upper.work);
        assert!(receipt.actual.source_byte_reads < receipt.upper.source_byte_reads);

        let (matched, exists_receipt) = plan
            .is_match_window(b"xKKKK", Window::new(1, 5), ScanLimits::unlimited())
            .unwrap();
        assert!(matched);
        assert_eq!(exists_receipt.actual.candidate_starts, 1);
        assert_eq!(exists_receipt.actual.candidate_events, 1);
        assert!(exists_receipt.actual.work < receipt.actual.work);

        let reversed = [FoldedLiteral::new(&one), FoldedLiteral::new(&two)];
        let reversed = admitted(&reversed);
        assert_eq!(
            reversed
                .find_window(b"KK", Window::full(b"KK"), ScanLimits::unlimited())
                .unwrap()
                .0,
            Some(LiteralCandidate::new(0, 0, 1))
        );
    }

    #[test]
    fn value_projections_match_recorded_prefilter_forms_and_edge_cases() {
        let kelvin = FoldedScalarClass::new(&KELVIN);
        let one = [kelvin];
        let two = [kelvin, kelvin];
        let patterns = [
            FoldedLiteral::new(&two),
            FoldedLiteral::new(&one),
            FoldedLiteral::new(&two),
            FoldedLiteral::new(&one),
        ];
        let narrow = admitted(&patterns);
        let narrow_prefilter = narrow.root_prefilter.as_ref().unwrap();
        assert_eq!(narrow_prefilter.needle_count, 3);
        assert!(narrow_prefilter.classifier.is_none());
        let (found, matched) = assert_value_projection_parity(
            &narrow,
            b"xKKKK",
            Window::new(1, 5),
            ScanLimits::unlimited(),
            1,
            1,
        );
        assert_eq!(found.unwrap(), Some(LiteralCandidate::new(0, 1, 3)));
        assert!(matched.unwrap());

        let mut malformed = vec![0xFF, 0xC0, 0xAF, 0xED, 0xA0, 0x80];
        let valid_start = malformed.len();
        malformed.extend_from_slice("\u{212A}".as_bytes());
        malformed.extend_from_slice(&[0xE2, 0x84]);
        let (found, matched) = assert_value_projection_parity(
            &narrow,
            &malformed,
            Window::full(&malformed),
            ScanLimits::unlimited(),
            1,
            1,
        );
        assert_eq!(
            found.unwrap(),
            Some(LiteralCandidate::new(
                1,
                valid_start,
                valid_start + "\u{212A}".len()
            ))
        );
        assert!(matched.unwrap());

        let split = "\u{212A}".as_bytes();
        for window in [Window::new(0, 2), Window::new(1, 3)] {
            let (found, matched) = assert_value_projection_parity(
                &narrow,
                split,
                window,
                ScanLimits::unlimited(),
                1,
                1,
            );
            assert_eq!(found.unwrap(), None);
            assert!(!matched.unwrap());
        }

        let russian_classes = [
            FoldedScalarClass::new(&CYRILLIC_SHA),
            FoldedScalarClass::new(&CYRILLIC_IE),
        ];
        let russian_patterns = [FoldedLiteral::new(&russian_classes)];
        let guarded = admitted(&russian_patterns);
        let guarded_prefilter = guarded.root_prefilter.as_ref().unwrap();
        assert_eq!(guarded_prefilter.needle_count, 2);
        assert_ne!(guarded_prefilter.guard_needle_count, 0);
        let framed = "xxШЕшеШЕyy".as_bytes();
        let (found, matched) = assert_value_projection_parity(
            &guarded,
            framed,
            Window::new(2, framed.len() - 2),
            ScanLimits::unlimited(),
            1,
            1,
        );
        assert_eq!(found.unwrap(), Some(LiteralCandidate::new(0, 2, 6)));
        assert!(matched.unwrap());

        const FOUR: [char; 4] = ['A', 'B', 'C', 'D'];
        let wide_classes = one_class(&FOUR);
        let wide_patterns = [FoldedLiteral::new(&wide_classes)];
        let wide = admitted(&wide_patterns);
        assert_eq!(wide.build.root_prefilter_needles, 4);
        assert_eq!(wide.root_prefilter_classifier_columns(), 1);
        let (found, matched) = assert_value_projection_parity(
            &wide,
            b"xxqD!",
            Window::new(2, 5),
            ScanLimits::unlimited(),
            1,
            1,
        );
        assert_eq!(found.unwrap(), Some(LiteralCandidate::new(0, 3, 4)));
        assert!(matched.unwrap());

        let correlated = correlated_ascii_plan();
        assert_eq!(correlated.root_prefilter_classifier_columns(), 2);
        let (found, matched) = assert_value_projection_parity(
            &correlated,
            b"xxq\x01az",
            Window::new(2, 6),
            ScanLimits::unlimited(),
            1,
            1,
        );
        assert_eq!(found.unwrap(), Some(LiteralCandidate::new(0, 3, 5)));
        assert!(matched.unwrap());
    }

    #[test]
    fn value_projections_continue_after_rejected_root_hits() {
        let check = |plan: &FoldedLiteralTriePlan, literal: &[u8], needle_count| {
            let prefilter = plan.root_prefilter.as_ref().unwrap();
            assert_eq!(prefilter.needle_count, needle_count);
            assert!(prefilter.classifier.is_none());

            let mut haystack = vec![b'!'; 2 * BYTE_SET_WIDE_BLOCK_BYTES + 11];
            haystack[usize::from(prefilter.offset)] = prefilter.needles[0];
            let (found, matched) = assert_value_projection_parity(
                plan,
                &haystack,
                Window::full(&haystack),
                ScanLimits::unlimited(),
                1,
                1,
            );
            assert_eq!(found.unwrap(), None);
            assert!(!matched.unwrap());

            let expected_start = haystack.len();
            haystack.extend_from_slice(literal);
            let (found, matched) = assert_value_projection_parity(
                plan,
                &haystack,
                Window::full(&haystack),
                ScanLimits::unlimited(),
                1,
                1,
            );
            assert_eq!(
                found.unwrap(),
                Some(LiteralCandidate::new(
                    0,
                    expected_start,
                    expected_start + literal.len()
                ))
            );
            assert!(matched.unwrap());
        };

        const ASCII_Q: [char; 1] = ['Q'];
        const ASCII_Z: [char; 1] = ['Z'];
        let ascii_classes = [
            FoldedScalarClass::new(&ASCII_Q),
            FoldedScalarClass::new(&ASCII_Z),
        ];
        check(&admitted(&[FoldedLiteral::new(&ascii_classes)]), b"QZ", 1);

        let russian_classes = [
            FoldedScalarClass::new(&CYRILLIC_SHA),
            FoldedScalarClass::new(&CYRILLIC_IE),
        ];
        check(
            &admitted(&[FoldedLiteral::new(&russian_classes)]),
            "ШЕ".as_bytes(),
            2,
        );

        let kelvin = FoldedScalarClass::new(&KELVIN);
        let kelvin_classes = [kelvin, kelvin];
        check(&admitted(&[FoldedLiteral::new(&kelvin_classes)]), b"KK", 3);
    }

    #[test]
    fn value_projections_keep_exact_preflight_failures() {
        let classes = one_class(&KELVIN);
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        let haystack = "Kk\u{212A}".as_bytes();
        let upper = plan.scan_upper_bounds(haystack.len()).unwrap();

        let (found, matched) = assert_value_projection_parity(
            &plan,
            haystack,
            Window::full(haystack),
            exact_scan_limits(upper),
            1,
            1,
        );
        assert_eq!(found.unwrap(), Some(LiteralCandidate::new(0, 0, 1)));
        assert!(matched.unwrap());

        for window in [
            Window::new(2, 1),
            Window::new(0, haystack.len().checked_add(1).unwrap()),
        ] {
            let expected = super::ScanAttemptError {
                source: ScanError::InvalidWindow {
                    start: window.start(),
                    end: window.end(),
                    haystack_len: haystack.len(),
                },
                actual: ScanActual::default(),
            };
            let (found, matched) =
                assert_value_projection_parity(
                    &plan,
                    haystack,
                    window,
                    ScanLimits::unlimited(),
                    0,
                    0,
                );
            assert_eq!(found.unwrap_err(), expected);
            assert_eq!(matched.unwrap_err(), expected);
        }

        let cases = [
            (
                ScanResource::InputBytes,
                upper.input_bytes,
                ScanLimits {
                    max_input_bytes: upper.input_bytes.saturating_sub(1),
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::CandidateStarts,
                upper.candidate_starts,
                ScanLimits {
                    max_candidate_starts: upper.candidate_starts.saturating_sub(1),
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::ScalarDecodes,
                upper.scalar_decodes,
                ScanLimits {
                    max_scalar_decodes: upper.scalar_decodes.saturating_sub(1),
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::DecodedScalars,
                upper.decoded_scalars,
                ScanLimits {
                    max_decoded_scalars: upper.decoded_scalars.saturating_sub(1),
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::InvalidBytes,
                upper.invalid_bytes,
                ScanLimits {
                    max_invalid_bytes: upper.invalid_bytes.saturating_sub(1),
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::SourceByteReads,
                upper.source_byte_reads,
                ScanLimits {
                    max_source_byte_reads: upper.source_byte_reads.saturating_sub(1),
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::TransitionProbes,
                upper.transition_probes,
                ScanLimits {
                    max_transition_probes: upper.transition_probes.saturating_sub(1),
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::CandidateEvents,
                upper.candidate_events,
                ScanLimits {
                    max_candidate_events: upper.candidate_events.saturating_sub(1),
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::Work,
                upper.work,
                ScanLimits {
                    max_work: upper.work.saturating_sub(1),
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::ScratchBytes,
                upper.scratch_bytes,
                ScanLimits {
                    max_scratch_bytes: upper.scratch_bytes.saturating_sub(1),
                    ..ScanLimits::unlimited()
                },
            ),
        ];
        let mut checked = 0;
        for (resource, needed, limits) in cases {
            if needed == 0 {
                assert_eq!(resource, ScanResource::ScratchBytes);
                continue;
            }
            let expected = super::ScanAttemptError {
                source: ScanError::Resource {
                    resource,
                    needed,
                    limit: needed - 1,
                },
                actual: ScanActual::default(),
            };
            let (found, matched) =
                assert_value_projection_parity(
                    &plan,
                    haystack,
                    Window::full(haystack),
                    limits,
                    0,
                    0,
                );
            assert_eq!(found.unwrap_err(), expected);
            assert_eq!(matched.unwrap_err(), expected);
            checked += 1;
        }
        assert_eq!(checked, 9);
    }

    #[test]
    fn value_projections_match_direct_kernel_without_a_retained_prefilter() {
        let classes = one_class(&KELVIN);
        let patterns = [FoldedLiteral::new(&classes)];
        let mut plan = admitted(&patterns);
        assert!(plan.root_prefilter.is_some());
        plan.root_prefilter = None;

        let haystack = [0xFF, b'x', b'K', 0xE2, 0x84];
        let (found, matched) = assert_value_projection_parity(
            &plan,
            &haystack,
            Window::full(&haystack),
            ScanLimits::unlimited(),
            1,
            1,
        );
        assert_eq!(found.unwrap(), Some(LiteralCandidate::new(0, 2, 3)));
        assert!(matched.unwrap());
    }

    #[test]
    fn windows_and_ascii_fold_differential_are_exact() {
        const ASCII_A: [char; 2] = ['A', 'a'];
        let first = FoldedScalarClass::new(&ASCII_A);
        let classes = [first, first];
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        for len in 0..=5 {
            let variants = 3_usize.pow(u32::try_from(len).unwrap());
            for mut code in 0..variants {
                let mut haystack = Vec::new();
                for _ in 0..len {
                    haystack.push(match code % 3 {
                        0 => b'A',
                        1 => b'a',
                        _ => b'b',
                    });
                    code /= 3;
                }
                let expected = (0..haystack.len())
                    .filter_map(|start| {
                        let end = start.checked_add(2)?;
                        (end <= haystack.len()
                            && haystack[start..end]
                                .iter()
                                .all(|byte| matches!(byte, b'A' | b'a')))
                        .then_some(LiteralCandidate::new(0, start, end))
                    })
                    .collect::<Vec<_>>();
                assert_eq!(collect(&plan, &haystack), expected);
            }
        }

        let mut candidates = Vec::new();
        plan.scan_window(
            b"xxAa!",
            Window::new(2, 4),
            ScanLimits::unlimited(),
            |candidate| candidates.push(candidate),
        )
        .unwrap();
        assert_eq!(candidates, [LiteralCandidate::new(0, 2, 4)]);
    }

    #[test]
    fn russian_root_uses_rare_common_continuation_offset() {
        let classes = [
            FoldedScalarClass::new(&CYRILLIC_SHA),
            FoldedScalarClass::new(&CYRILLIC_IE),
        ];
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        let prefilter = plan
            .root_prefilter
            .as_ref()
            .expect("two Russian fold variants have a common-offset prefilter");
        assert_eq!(prefilter.offset, 1);
        assert_eq!(prefilter.needle_count, 2);
        let mut needles = prefilter.needles[..usize::from(prefilter.needle_count)].to_vec();
        needles.sort_unstable();
        assert_eq!(needles, [0x88, 0xA8]);
        assert_eq!(plan.build.root_prefilter_offset, Some(1));
        assert_eq!(plan.build.root_prefilter_needles, 2);
        assert_eq!(plan.build.root_prefilter_classifier_selection, None);
        assert_eq!(prefilter.guard_offset, 3);
        assert_eq!(prefilter.guard_needle_count, 2);
        let mut guard_needles = byte_set_members(prefilter.guard_byte_set).collect::<Vec<_>>();
        guard_needles.sort_unstable();
        assert_eq!(guard_needles, [0x95, 0xB5]);
        assert_eq!(plan.build.root_prefilter_guard_offset, Some(3));
        assert_eq!(plan.build.root_prefilter_guard_needles, 2);
    }

    #[test]
    fn lead_only_root_uses_wide_continuation_classifier() {
        const DENSE_CYRILLIC_ROOT: [char; 4] = ['А', 'Р', 'р', 'ё'];
        let classes = one_class(&DENSE_CYRILLIC_ROOT);
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = match FoldedLiteralTriePlan::build_with_dispatch(
            SimdDispatchContext::capture(),
            &patterns,
            BuildLimits::default(),
        )
        .unwrap()
        {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("unexpected fallback: {fallback:?}")
            }
        };
        assert_eq!(plan.build.root_prefilter_offset, Some(1));
        assert_eq!(plan.build.root_prefilter_needles, 4);
        let selection = plan
            .build
            .root_prefilter_classifier_selection
            .expect("the wide prefilter publishes its retained classifier selection");
        let retained_selection = plan
            .root_prefilter
            .as_ref()
            .and_then(|prefilter| prefilter.classifier.as_ref())
            .map(ByteBucketClassifier::selection)
            .expect("the wide prefilter retains its published classifier");
        assert_eq!(selection, retained_selection);
        assert_eq!(selection.policy, DispatchPolicy::Auto);
        assert_eq!(
            collect(&plan, "xАРрё".as_bytes()),
            [
                LiteralCandidate::new(0, 1, 3),
                LiteralCandidate::new(0, 3, 5),
                LiteralCandidate::new(0, 5, 7),
                LiteralCandidate::new(0, 7, 9),
            ]
        );
    }

    #[test]
    fn four_byte_root_exercises_later_common_offset() {
        const DESERET_LONG_I: [char; 2] = ['\u{10400}', '\u{10428}'];
        let classes = one_class(&DESERET_LONG_I);
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        let prefilter = plan
            .root_prefilter
            .as_ref()
            .expect("Deseret fold variants retain a later-byte prefilter");
        assert_eq!(prefilter.offset, 2);
        assert_eq!(prefilter.needle_count, 1);
        assert_eq!(prefilter.needles[0], 0x90);
        assert_eq!(
            collect(&plan, "x\u{10400}\u{10428}".as_bytes()),
            [
                LiteralCandidate::new(0, 1, 5),
                LiteralCandidate::new(0, 5, 9),
            ]
        );
    }

    #[test]
    fn four_distinct_root_bytes_use_wide_classifier() {
        const FOUR: [char; 4] = ['A', 'B', 'C', 'D'];
        let classes = one_class(&FOUR);
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        assert_eq!(plan.build.root_prefilter_offset, Some(0));
        assert_eq!(plan.build.root_prefilter_needles, 4);
        assert!(plan.build.root_prefilter_classifier_selection.is_some());
        assert_eq!(
            collect(&plan, b"xABCD"),
            [
                LiteralCandidate::new(0, 1, 2),
                LiteralCandidate::new(0, 2, 3),
                LiteralCandidate::new(0, 3, 4),
                LiteralCandidate::new(0, 4, 5),
            ]
        );
    }

    #[test]
    fn wide_classifier_matches_complete_scan_across_blocks_and_tail() {
        const FOUR: [char; 4] = ['A', 'B', 'C', 'D'];
        let classes = one_class(&FOUR);
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        let mut source = (u8::MIN..=u8::MAX).collect::<Vec<_>>();
        source.extend_from_slice(b"tail-ABCD-\xff");
        let upper = plan.scan_upper_bounds(source.len()).unwrap();
        let mut scalar = Vec::new();
        let scalar_actual = execute_folded_scan_impl(
            &plan,
            &source,
            0,
            upper,
            None,
            ScanStop::Never,
            &mut |candidate| {
                scalar.push(candidate);
            },
        )
        .unwrap();
        let mut prefetched = Vec::new();
        let prefetched_actual = execute_folded_scan_impl(
            &plan,
            &source,
            0,
            upper,
            plan.root_prefilter.as_ref(),
            ScanStop::Never,
            &mut |candidate| prefetched.push(candidate),
        )
        .unwrap();
        assert_eq!(prefetched, scalar);
        assert!(super::actual_within(scalar_actual, upper));
        assert!(super::actual_within(prefetched_actual, upper));

        for residue in 0..32 {
            let len = 48_usize.checked_add(residue).unwrap();
            let mut framed = vec![b'x'; len.checked_add(8).unwrap()];
            for (position, byte) in [
                (0, b'A'),
                (1, b'B'),
                (2, b'C'),
                (3, b'D'),
                (7, b'A'),
                (8, b'B'),
                (15, b'C'),
                (16, b'D'),
                (len.saturating_sub(1), b'A'),
            ] {
                framed[position.checked_add(4).unwrap()] = byte;
            }
            framed[6] = 0xFF;
            for window_start in 1_usize..=4 {
                let window_end = window_start.checked_add(len).unwrap();
                let window = &framed[window_start..window_end];
                let upper = plan.scan_upper_bounds(window.len()).unwrap();
                let mut scalar = Vec::new();
                execute_folded_scan_impl(
                    &plan,
                    window,
                    window_start,
                    upper,
                    None,
                    ScanStop::Never,
                    &mut |candidate| scalar.push(candidate),
                )
                .unwrap();
                let mut prefetched = Vec::new();
                execute_folded_scan_impl(
                    &plan,
                    window,
                    window_start,
                    upper,
                    plan.root_prefilter.as_ref(),
                    ScanStop::Never,
                    &mut |candidate| prefetched.push(candidate),
                )
                .unwrap();
                assert_eq!(
                    prefetched, scalar,
                    "residue {residue}, nonzero window {window_start}"
                );
            }
        }
    }

    #[test]
    fn common_offset_prefilter_matches_scalar_reference_on_all_short_byte_strings_and_windows() {
        let classes = [
            FoldedScalarClass::new(&CYRILLIC_SHA),
            FoldedScalarClass::new(&CYRILLIC_IE),
        ];
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        let alphabet = [0x00, 0x88, 0xA8, 0xD0, 0xD1, 0xFF, b' ', b'x'];
        for len in 0..=5 {
            let variants = alphabet.len().pow(u32::try_from(len).unwrap());
            for mut code in 0..variants {
                let mut haystack = Vec::with_capacity(len);
                for _ in 0..len {
                    haystack.push(alphabet[code % alphabet.len()]);
                    code /= alphabet.len();
                }
                for start in 0..=len {
                    for end in start..=len {
                        let source = &haystack[start..end];
                        let upper = plan.scan_upper_bounds(source.len()).unwrap();
                        let mut scalar = Vec::new();
                        let scalar_actual = execute_folded_scan_impl(
                            &plan,
                            source,
                            start,
                            upper,
                            None,
                            ScanStop::Never,
                            &mut |candidate| scalar.push(candidate),
                        )
                        .unwrap();
                        let mut prefetched = Vec::new();
                        let prefetched_actual = execute_folded_scan_impl(
                            &plan,
                            source,
                            start,
                            upper,
                            plan.root_prefilter.as_ref(),
                            ScanStop::Never,
                            &mut |candidate| prefetched.push(candidate),
                        )
                        .unwrap();
                        assert_eq!(prefetched, scalar);
                        assert!(super::actual_within(scalar_actual, upper));
                        assert!(super::actual_within(prefetched_actual, upper));
                    }
                }
            }
        }

        let multi_hit = "ШЕшеШЕ".as_bytes();
        let upper = plan.scan_upper_bounds(multi_hit.len()).unwrap();
        let mut scalar = Vec::new();
        execute_folded_scan_impl(
            &plan,
            multi_hit,
            0,
            upper,
            None,
            ScanStop::Never,
            &mut |candidate| {
                scalar.push(candidate);
            },
        )
        .unwrap();
        let mut prefetched = Vec::new();
        execute_folded_scan_impl(
            &plan,
            multi_hit,
            0,
            upper,
            plan.root_prefilter.as_ref(),
            ScanStop::Never,
            &mut |candidate| {
                prefetched.push(candidate);
            },
        )
        .unwrap();
        assert_eq!(prefetched, scalar);
        assert_eq!(
            prefetched,
            [
                LiteralCandidate::new(0, 0, 4),
                LiteralCandidate::new(0, 4, 8),
                LiteralCandidate::new(0, 8, 12),
            ]
        );
    }

    #[test]
    fn empty_unsorted_and_overlapping_classes_return_typed_fallback() {
        let BuildAttempt::DenseFallback(empty) =
            FoldedLiteralTriePlan::build(&[], BuildLimits::default()).unwrap()
        else {
            panic!("empty language must fall back");
        };
        assert_eq!(empty.reason(), DenseFallbackReason::EmptyLanguage);

        let no_classes = [FoldedLiteral::new(&[])];
        let BuildAttempt::DenseFallback(empty_literal) =
            FoldedLiteralTriePlan::build(&no_classes, BuildLimits::default()).unwrap()
        else {
            panic!("empty literal must fall back");
        };
        assert!(matches!(
            empty_literal.reason(),
            DenseFallbackReason::EmptyLiteral { pattern_index: 0 }
        ));

        let empty_values = [];
        let empty_classes = [FoldedScalarClass::new(&empty_values)];
        let empty_class_pattern = [FoldedLiteral::new(&empty_classes)];
        let BuildAttempt::DenseFallback(empty_class) =
            FoldedLiteralTriePlan::build(&empty_class_pattern, BuildLimits::default()).unwrap()
        else {
            panic!("empty class must fall back");
        };
        assert!(matches!(
            empty_class.reason(),
            DenseFallbackReason::EmptyClass {
                pattern_index: 0,
                scalar_index: 0
            }
        ));

        let unsorted_values = ['a', 'A'];
        let unsorted_classes = [FoldedScalarClass::new(&unsorted_values)];
        let unsorted_pattern = [FoldedLiteral::new(&unsorted_classes)];
        let BuildAttempt::DenseFallback(unsorted) =
            FoldedLiteralTriePlan::build(&unsorted_pattern, BuildLimits::default()).unwrap()
        else {
            panic!("unsorted class must fall back");
        };
        assert!(matches!(
            unsorted.reason(),
            DenseFallbackReason::NonCanonicalClass { .. }
        ));

        let first_values = ['A', 'a'];
        let second_values = ['A', 'b'];
        let first_classes = [FoldedScalarClass::new(&first_values)];
        let second_classes = [FoldedScalarClass::new(&second_values)];
        let overlap_patterns = [
            FoldedLiteral::new(&first_classes),
            FoldedLiteral::new(&second_classes),
        ];
        let BuildAttempt::DenseFallback(overlap) =
            FoldedLiteralTriePlan::build(&overlap_patterns, BuildLimits::default()).unwrap()
        else {
            panic!("partially overlapping classes must fall back");
        };
        assert!(matches!(
            overlap.reason(),
            DenseFallbackReason::OverlappingClasses { .. }
        ));
    }

    #[test]
    fn a_window_split_inside_multibyte_scalar_cannot_match_across_boundary() {
        let classes = one_class(&KELVIN);
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        let source = "\u{212A}".as_bytes();
        for window in [Window::new(0, 2), Window::new(1, 3)] {
            let mut candidates = Vec::new();
            plan.scan_window(source, window, ScanLimits::unlimited(), |candidate| {
                candidates.push(candidate);
            })
            .unwrap();
            assert!(candidates.is_empty());
        }
    }

    #[test]
    fn every_build_dimension_has_an_exact_one_below_gate() {
        let kelvin_classes = one_class(&KELVIN);
        let sigma_classes = one_class(&SIGMA);
        let patterns = [
            FoldedLiteral::new(&kelvin_classes),
            FoldedLiteral::new(&sigma_classes),
        ];
        let mandatory = super::preflight_from_lengths(&patterns).unwrap();
        let accounting = admitted(&patterns).build_accounting();
        assert!(accounting.canonical_comparisons <= accounting.canonical_comparisons_upper_bound);
        assert!(accounting.insertion_probes <= accounting.insertion_probes_upper_bound);
        assert!(accounting.max_state_fanout <= accounting.max_state_fanout_upper_bound);
        assert!(accounting.work <= accounting.work_upper_bound);
        assert!(accounting.persistent_bytes <= accounting.persistent_bytes_upper_bound);
        assert!(accounting.peak_bytes <= accounting.peak_bytes_upper_bound);
        assert!(matches!(
            FoldedLiteralTriePlan::build(&patterns, exact_build_limits(&accounting)).unwrap(),
            BuildAttempt::Admitted(_)
        ));
        for (resource, limits) in [
            (
                BuildResource::Patterns,
                BuildLimits {
                    max_patterns: accounting.patterns - 1,
                    ..BuildLimits::unlimited()
                },
            ),
            (
                BuildResource::ScalarPositions,
                BuildLimits {
                    max_scalar_positions: accounting.scalar_positions - 1,
                    ..BuildLimits::unlimited()
                },
            ),
            (
                BuildResource::EquivalentScalars,
                BuildLimits {
                    max_equivalent_scalars: accounting.equivalent_scalars - 1,
                    ..BuildLimits::unlimited()
                },
            ),
            (
                BuildResource::States,
                BuildLimits {
                    max_states: accounting.states_upper_bound - 1,
                    ..BuildLimits::unlimited()
                },
            ),
            (
                BuildResource::Transitions,
                BuildLimits {
                    max_transitions: accounting.transitions_upper_bound - 1,
                    ..BuildLimits::unlimited()
                },
            ),
            (
                BuildResource::Work,
                BuildLimits {
                    max_work: mandatory.work_upper_bound - 1,
                    ..BuildLimits::unlimited()
                },
            ),
            (
                BuildResource::PersistentBytes,
                BuildLimits {
                    max_persistent_bytes: accounting.persistent_bytes_upper_bound - 1,
                    ..BuildLimits::unlimited()
                },
            ),
            (
                BuildResource::PeakBytes,
                BuildLimits {
                    max_peak_bytes: accounting.peak_bytes_upper_bound - 1,
                    ..BuildLimits::unlimited()
                },
            ),
            (
                BuildResource::Allocations,
                BuildLimits {
                    max_allocations: accounting.allocations_upper_bound - 1,
                    ..BuildLimits::unlimited()
                },
            ),
        ] {
            build_probe::reset();
            assert!(matches!(
                FoldedLiteralTriePlan::build(&patterns, limits),
                Err(BuildError::Resource {
                    resource: observed,
                    ..
                }) if observed == resource
            ));
            assert_eq!(build_probe::scalar_reads(), 0);
            assert_eq!(build_probe::allocation_attempts(), 0);
        }
    }

    #[test]
    fn every_positive_scan_dimension_refuses_before_emission() {
        let classes = one_class(&KELVIN);
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        let haystack = "Kk\u{212A}".as_bytes();
        let upper = plan.scan_upper_bounds(haystack.len()).unwrap();
        scan_source_probe::reset();
        let receipt = plan
            .scan(haystack, exact_scan_limits(upper), |_| {})
            .unwrap();
        assert!(super::actual_within(receipt.actual, upper));
        assert_eq!(scan_source_probe::accesses(), 1);
        for (resource, limits) in [
            (
                ScanResource::InputBytes,
                ScanLimits {
                    max_input_bytes: upper.input_bytes - 1,
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::DecodedScalars,
                ScanLimits {
                    max_decoded_scalars: upper.decoded_scalars - 1,
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::InvalidBytes,
                ScanLimits {
                    max_invalid_bytes: upper.invalid_bytes - 1,
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::CandidateStarts,
                ScanLimits {
                    max_candidate_starts: upper.candidate_starts - 1,
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::ScalarDecodes,
                ScanLimits {
                    max_scalar_decodes: upper.scalar_decodes - 1,
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::SourceByteReads,
                ScanLimits {
                    max_source_byte_reads: upper.source_byte_reads - 1,
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::TransitionProbes,
                ScanLimits {
                    max_transition_probes: upper.transition_probes - 1,
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::CandidateEvents,
                ScanLimits {
                    max_candidate_events: upper.candidate_events - 1,
                    ..ScanLimits::unlimited()
                },
            ),
            (
                ScanResource::Work,
                ScanLimits {
                    max_work: upper.work - 1,
                    ..ScanLimits::unlimited()
                },
            ),
        ] {
            scan_source_probe::reset();
            let mut emissions = 0;
            let error = plan.scan(haystack, limits, |_| emissions += 1).unwrap_err();
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

    #[test]
    fn maximum_state_fanout_bounds_linked_transition_probes() {
        const A: [char; 2] = ['A', 'a'];
        const B: [char; 2] = ['B', 'b'];
        const C: [char; 2] = ['C', 'c'];
        const D: [char; 2] = ['D', 'd'];
        const X: [char; 2] = ['X', 'x'];
        const Y: [char; 2] = ['Y', 'y'];
        let ab = [FoldedScalarClass::new(&A), FoldedScalarClass::new(&B)];
        let ac = [FoldedScalarClass::new(&A), FoldedScalarClass::new(&C)];
        let ad = [FoldedScalarClass::new(&A), FoldedScalarClass::new(&D)];
        let xy = [FoldedScalarClass::new(&X), FoldedScalarClass::new(&Y)];
        let patterns = [
            FoldedLiteral::new(&ab),
            FoldedLiteral::new(&ac),
            FoldedLiteral::new(&ad),
            FoldedLiteral::new(&xy),
        ];
        let plan = admitted(&patterns);
        let build = plan.build_accounting();
        assert_eq!(build.transitions, 12);
        assert_eq!(build.max_state_fanout, 6);
        assert!(build.max_state_fanout <= build.max_state_fanout_upper_bound);

        let source = b"Ae".repeat(32);
        let upper = plan.scan_upper_bounds(source.len()).unwrap();
        assert_eq!(
            upper.transition_probes,
            upper.scalar_decodes * build.max_state_fanout
        );
        assert!(
            upper.transition_probes < upper.scalar_decodes * build.transitions,
            "the envelope must use maximum state fanout, not total transitions"
        );

        scan_source_probe::reset();
        plan.scan(&source, exact_scan_limits(upper), |_| {})
            .unwrap();
        assert_eq!(scan_source_probe::accesses(), 1);

        scan_source_probe::reset();
        let mut emissions = 0;
        let error = plan
            .scan(
                &source,
                ScanLimits {
                    max_transition_probes: upper.transition_probes - 1,
                    ..exact_scan_limits(upper)
                },
                |_| emissions += 1,
            )
            .unwrap_err();
        assert!(matches!(
            error.source,
            ScanError::Resource {
                resource: ScanResource::TransitionProbes,
                needed,
                limit,
            } if needed == upper.transition_probes && limit == upper.transition_probes - 1
        ));
        assert_eq!(error.actual, ScanActual::default());
        assert_eq!(emissions, 0);
        assert_eq!(scan_source_probe::accesses(), 0);

        let actual =
            execute_folded_scan_impl(&plan, &source, 0, upper, None, ScanStop::Never, &mut |_| {})
                .unwrap();
        assert_eq!(actual.transition_probes, 32 * 14);
        assert!(super::actual_within(actual, upper));
    }

    #[test]
    fn fixed_trie_doubling_counters_are_linear() {
        let classes = one_class(&KELVIN);
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        assert_eq!(plan.build.max_state_fanout, KELVIN.len());
        let first = plan.scan_upper_bounds(1_024).unwrap();
        let second = plan.scan_upper_bounds(2_048).unwrap();
        let fourth = plan.scan_upper_bounds(4_096).unwrap();
        assert_eq!(
            first.transition_probes,
            first.scalar_decodes * plan.build.max_state_fanout
        );
        assert_eq!(second.scalar_decodes, first.scalar_decodes * 2);
        assert_eq!(fourth.scalar_decodes, second.scalar_decodes * 2);
        assert_eq!(second.transition_probes, first.transition_probes * 2);
        assert_eq!(fourth.transition_probes, second.transition_probes * 2);
        assert_eq!(second.work, first.work * 2);
        assert_eq!(fourth.work, second.work * 2);
    }

    #[test]
    fn prospective_overflow_is_typed_without_source_access() {
        let classes = one_class(&KELVIN);
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        scan_source_probe::reset();
        assert!(matches!(
            plan.scan_upper_bounds(usize::MAX),
            Err(ScanError::ArithmeticOverflow { .. })
        ));
        assert_eq!(scan_source_probe::accesses(), 0);
    }
}
