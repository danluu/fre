//! Bounded sparse trie for caller-canonicalized Unicode simple-fold literals.
//!
//! This module deliberately does not parse syntax or own a Unicode table.
//! The later HIR integration supplies sorted scalar equivalence classes from
//! its pinned canonical simple-fold facts. Classes must be pairwise identical
//! or disjoint. The retained trie matches those classes directly against
//! strict UTF-8 and reports original byte offsets. Invalid UTF-8 never matches
//! and advances one byte.

use core::{fmt, mem};

use fre_exact_alloc::{CopyError, ExactVec};
use fre_simd_kernels::{
    BYTE_BUCKET_MAX_COLUMNS, ByteBucketClassifier, ByteBucketTables, DispatchPolicy,
    SelectionReceipt, SimdDispatchContext,
};
use memchr::{memchr_iter, memchr2_iter, memchr3_iter};

use crate::{
    Window,
    literal_anchor::{CandidateEmissionOrder, LiteralCandidate},
    packed_ordered_literal_aggregate::byte_frequency_rank,
};

/// Stable identity of the canonical folded-scalar trie primitive.
pub const PLAN_ID: &str = "literal-candidate-stream.unicode-folded-trie.v4";

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
    pub canonical_comparisons_upper_bound: usize,
    pub insertion_probes_upper_bound: usize,
    pub root_prefilter_work_upper_bound: usize,
    pub work_upper_bound: usize,
    pub persistent_bytes_upper_bound: usize,
    pub peak_bytes_upper_bound: usize,
    pub allocations_upper_bound: usize,
    pub canonical_comparisons: usize,
    pub insertion_probes: usize,
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

#[derive(Debug)]
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

impl RootPrefilter {
    const fn has_guard(&self) -> bool {
        self.guard_needle_count != 0
    }

    fn guard_matches(&self, byte: u8) -> bool {
        byte_set_contains(self.guard_byte_set, byte)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the three memchr widths and retained full-byte classifier share one checked callback/error contract"
    )]
    fn scan<F>(
        &self,
        source: &[u8],
        invalid_actual: ScanActual,
        mut hit: F,
    ) -> Result<(), ScanAttemptError>
    where
        F: FnMut(usize) -> Result<(), ScanAttemptError>,
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
                    hit(position)?;
                }
            }
            2 => {
                for position in memchr2_iter(self.needles[0], self.needles[1], source) {
                    hit(position)?;
                }
            }
            3 => {
                for position in
                    memchr3_iter(self.needles[0], self.needles[1], self.needles[2], source)
                {
                    hit(position)?;
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
                let mut block_start = 0_usize;
                while let Some(masks) = classifier.classify_16(&source[block_start..]) {
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
                            hit(position)?;
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
                for (tail_offset, &byte) in source[block_start..].iter().enumerate() {
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
                        hit(position)?;
                    }
                }
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
        Ok(())
    }
}

/// Immutable exact-allocation sparse folded-scalar trie.
#[derive(Debug)]
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
    pub fn build(
        patterns: &[FoldedLiteral<'_>],
        limits: BuildLimits,
    ) -> Result<BuildAttempt, BuildError> {
        let prospective = preflight_from_lengths(patterns)?;
        enforce_build_limits(prospective, limits)?;
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
                    &mut work,
                )?;
            }
            append_output(&mut nodes, &mut outputs, state, pattern_index)?;
            work = checked_build_add(work, 1, "folded output work")?;
        }
        let mut build = prospective;
        build.canonical_comparisons = canonical_comparisons;
        build.insertion_probes = insertion_probes;
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
        let (root_prefilter, root_prefilter_work) = select_root_prefilter(patterns)?;
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
        if !build_actual_within(build) {
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

    /// Derive a complete fixed-program linear envelope from input length only.
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
            let prefilter_passes = usize::from(
                self.root_prefilter
                    .as_ref()
                    .is_some_and(RootPrefilter::has_guard),
            )
            .checked_add(1)
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
            self.build.transitions,
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
        let mut actual = execute_folded_scan(self, source, window.start(), upper, &mut emit)?;
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
    emit: &mut F,
) -> Result<ScanActual, ScanAttemptError>
where
    F: FnMut(LiteralCandidate),
{
    execute_folded_scan_impl(
        plan,
        source,
        absolute_base,
        upper,
        plan.root_prefilter.as_ref(),
        emit,
    )
}

fn execute_folded_scan_impl<F>(
    plan: &FoldedLiteralTriePlan,
    source: &[u8],
    absolute_base: usize,
    upper: ScanUpperBounds,
    root_prefilter: Option<&RootPrefilter>,
    emit: &mut F,
) -> Result<ScanActual, ScanAttemptError>
where
    F: FnMut(LiteralCandidate),
{
    let mut actual = ScanActual {
        input_bytes: source.len(),
        ..ScanActual::default()
    };
    if let Some(prefilter) = root_prefilter {
        actual.source_byte_reads = checked_actual_add(
            actual.source_byte_reads,
            source.len(),
            upper,
            actual,
            "folded root-prefilter source reads",
        )?;
        let offset = usize::from(prefilter.offset);
        let invalid_actual = actual;
        prefilter.scan(source, invalid_actual, |hit| {
            let Some(relative_start) = hit.checked_sub(offset) else {
                return Ok(());
            };
            if prefilter.has_guard() {
                let Some(guard_position) =
                    relative_start.checked_add(usize::from(prefilter.guard_offset))
                else {
                    return Ok(());
                };
                let Some(&guard_byte) = source.get(guard_position) else {
                    return Ok(());
                };
                actual.source_byte_reads = checked_actual_add(
                    actual.source_byte_reads,
                    1,
                    upper,
                    actual,
                    "folded root-prefilter guard reads",
                )?;
                if !prefilter.guard_matches(guard_byte) {
                    return Ok(());
                }
            }
            actual.candidate_starts = checked_actual_add(
                actual.candidate_starts,
                1,
                upper,
                actual,
                "folded root-prefilter candidate starts",
            )?;
            let _ = scan_folded_start(
                plan,
                source,
                absolute_base,
                relative_start,
                upper,
                &mut actual,
                emit,
            )?;
            Ok(())
        })?;
        return Ok(actual);
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
        let advance = scan_folded_start(
            plan,
            source,
            absolute_base,
            relative_start,
            upper,
            &mut actual,
            emit,
        )?;
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
    structural_leads: usize,
    frequency_score: u64,
}

#[allow(
    clippy::too_many_lines,
    reason = "one allocation-free traversal keeps fixed-column derivation, ranking and exact work accounting visibly coupled"
)]
fn select_root_prefilter(
    patterns: &[FoldedLiteral<'_>],
) -> Result<(Option<RootPrefilter>, usize), BuildError> {
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
    let selected = if let Some(primary) = selected[0] {
        let guard = selected[1];
        let classifier = if usize::from(primary.needle_count) > MEMCHR_ROOT_PREFILTER_NEEDLES {
            let (classifier, classifier_work) =
                root_prefilter_classifier(primary.byte_set, primary.high_nibbles)?;
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
    Ok((selected, work))
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

fn root_prefilter_classifier(
    set: [u64; ROOT_PREFILTER_BYTE_WORDS],
    high_nibbles: u16,
) -> Result<(ByteBucketClassifier, usize), BuildError> {
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
    let work = ROOT_PREFILTER_CLASSIFIER_HIGH_WORK
        .checked_add(members)
        .and_then(|work| work.checked_add(ROOT_PREFILTER_CLASSIFIER_SELECTION_WORK))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "folded root prefilter classifier work",
        })?;
    let classifier = SimdDispatchContext::capture()
        .byte_bucket_classifier(tables, DispatchPolicy::Auto)
        .expect("automatic byte-bucket dispatch retains a scalar fallback");
    Ok((classifier, work))
}

fn scan_folded_start<F>(
    plan: &FoldedLiteralTriePlan,
    source: &[u8],
    absolute_base: usize,
    relative_start: usize,
    upper: ScanUpperBounds,
    actual: &mut ScanActual,
    emit: &mut F,
) -> Result<usize, ScanAttemptError>
where
    F: FnMut(LiteralCandidate),
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
        emit_folded_outputs(
            plan,
            state,
            absolute_base,
            (relative_start, cursor),
            upper,
            actual,
            emit,
        )?;
    }
    Ok(next_start_advance)
}

fn emit_folded_outputs<F>(
    plan: &FoldedLiteralTriePlan,
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
        emit(LiteralCandidate::new(terminal.pattern_index, start, end));
        output = terminal.next;
    }
    Ok(())
}

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
        canonical_comparisons_upper_bound,
        insertion_probes_upper_bound,
        root_prefilter_work_upper_bound,
        work_upper_bound,
        persistent_bytes_upper_bound,
        peak_bytes_upper_bound: persistent_bytes_upper_bound,
        allocations_upper_bound: 3,
        canonical_comparisons: 0,
        insertion_probes: 0,
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

fn insert_class(
    nodes: &mut ExactVec<Node>,
    edges: &mut ExactVec<Edge>,
    state: usize,
    equivalents: &[char],
    insertion_probes: &mut usize,
    work: &mut usize,
) -> Result<usize, BuildError> {
    let mut target = None;
    let mut missing = false;
    for &scalar in equivalents {
        build_probe::record_scalar_reads(1);
        *work = checked_build_add(*work, 1, "folded equivalent-scalar work")?;
        let (observed, probes) = transition(nodes, edges, state, scalar);
        *insertion_probes =
            checked_build_add(*insertion_probes, probes, "folded insertion probes")?;
        *work = checked_build_add(*work, probes, "folded insertion probe work")?;
        match observed {
            Some(observed) => {
                if target.is_some_and(|expected| expected != observed) {
                    return Err(BuildError::Invariant {
                        detail: "canonical class reached multiple trie states",
                    });
                }
                target = Some(observed);
            }
            None => missing = true,
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

const fn build_actual_within(actual: BuildAccounting) -> bool {
    actual.canonical_comparisons <= actual.canonical_comparisons_upper_bound
        && actual.insertion_probes <= actual.insertion_probes_upper_bound
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

    pub(super) fn reset() {
        SCALAR_READS.set(0);
        ALLOCATION_ATTEMPTS.set(0);
    }

    pub(super) fn scalar_reads() -> usize {
        SCALAR_READS.get()
    }

    pub(super) fn allocation_attempts() -> usize {
        ALLOCATION_ATTEMPTS.get()
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
        FoldedLiteral, FoldedLiteralTriePlan, FoldedScalarClass, ScanActual, ScanError, ScanLimits,
        ScanResource, ScanUpperBounds, build_probe, byte_set_members, execute_folded_scan_impl,
        scan_source_probe,
    };
    use crate::{LiteralCandidate, Window};

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

    fn exact_build_limits(accounting: BuildAccounting) -> BuildLimits {
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
        let plan = admitted(&patterns);
        assert_eq!(plan.build.root_prefilter_offset, Some(1));
        assert_eq!(plan.build.root_prefilter_needles, 4);
        let selection = plan
            .build
            .root_prefilter_classifier_selection
            .expect("the wide prefilter publishes its retained classifier selection");
        assert!(!selection.variant_id.is_empty());
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
        let scalar_actual =
            execute_folded_scan_impl(&plan, &source, 0, upper, None, &mut |candidate| {
                scalar.push(candidate);
            })
            .unwrap();
        let mut prefetched = Vec::new();
        let prefetched_actual = execute_folded_scan_impl(
            &plan,
            &source,
            0,
            upper,
            plan.root_prefilter.as_ref(),
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
        execute_folded_scan_impl(&plan, multi_hit, 0, upper, None, &mut |candidate| {
            scalar.push(candidate);
        })
        .unwrap();
        let mut prefetched = Vec::new();
        execute_folded_scan_impl(
            &plan,
            multi_hit,
            0,
            upper,
            plan.root_prefilter.as_ref(),
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
        let accounting = admitted(&patterns).build_accounting();
        assert!(accounting.canonical_comparisons <= accounting.canonical_comparisons_upper_bound);
        assert!(accounting.insertion_probes <= accounting.insertion_probes_upper_bound);
        assert!(accounting.work <= accounting.work_upper_bound);
        assert!(accounting.persistent_bytes <= accounting.persistent_bytes_upper_bound);
        assert!(accounting.peak_bytes <= accounting.peak_bytes_upper_bound);
        assert!(matches!(
            FoldedLiteralTriePlan::build(&patterns, exact_build_limits(accounting)).unwrap(),
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
                    max_work: accounting.work_upper_bound - 1,
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
    fn fixed_trie_doubling_counters_are_linear() {
        let classes = one_class(&KELVIN);
        let patterns = [FoldedLiteral::new(&classes)];
        let plan = admitted(&patterns);
        let first = plan.scan_upper_bounds(1_024).unwrap();
        let second = plan.scan_upper_bounds(2_048).unwrap();
        let fourth = plan.scan_upper_bounds(4_096).unwrap();
        assert_eq!(second.scalar_decodes, first.scalar_decodes * 2);
        assert_eq!(fourth.scalar_decodes, second.scalar_decodes * 2);
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
