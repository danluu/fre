//! Literal-anchored whole-operation reduction for `W+ S+ L S+ W+` and
//! complete-span visitation for its terminal `W+ S+ L` form.
//!
//! Admission proves byte-mode complete ASCII word and whitespace classes,
//! greedy nonempty repetitions, and one nonempty all-word literal. The reducer
//! owns a preprocessed sparse finder for the proved literal, uses it on inputs
//! large enough to amortize candidate iteration, then verifies the adjacent
//! maximal token runs. Short full-phrase inputs retain the fixed block-mask
//! classifier and maximal-token DFA. Terminal phrases always use literal
//! anchors because a match may end in the middle of a maximal word run.
//!
//! A completed right word resets the DFA instead of reusing that word as the
//! next left token. This preserves non-overlapping restart semantics for
//! `a Holmes b Holmes c` while retaining leftmost-first greedy spans.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all resource and index arithmetic is checked before it affects execution"
)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::CopyError;
use fre_simd_kernels::{
    ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, AsciiWordSpaceClassifier, DispatchPolicy,
};
use memchr::memmem::{Finder, FinderBuilder};

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError};

pub const PLAN_ID: &str = "token-phrase.literal-anchor-maximal-ascii-stream.v5";
pub const COUNT_OPERATION_ID: &str = "token-phrase.count.unicode-off.v5";
pub const SPAN_SUM_OPERATION_ID: &str = "token-phrase.span-sum.unicode-off.v5";
/// Stable identity of allocation-free complete-span visitation.
pub const SPAN_VISIT_OPERATION_ID: &str = "token-phrase.span-visit.unicode-off.v1";

const FIXED_BUILD_WORK: usize = 8;
const LITERAL_VALIDATION_WORK_PER_BYTE: usize = 1;
const LITERAL_COPY_WORK_PER_BYTE: usize = 1;
// Covers the pinned memchr 2.8.3 rank, Rabin-Karp and Two-Way preprocessing
// passes. The owned builder consumes the already-accounted exact Box and
// performs no second payload allocation.
const FINDER_BUILD_WORK_PER_BYTE: usize = 12;
const SIMD_CLASSIFIER_BUILD_WORK: usize = 128 + 2 + 2;
const FIXED_REDUCE_WORK: usize = 8;
const CLASSIFICATION_WORK: usize = 2;
const LITERAL_COMPARISON_WORK: usize = 1;
const TOKEN_EVENT_WORK: usize = 3;
const MATCH_WORK: usize = 4;
const FULL_MINIMUM_NON_LITERAL_BYTES: usize = 4;
const TERMINAL_MINIMUM_NON_LITERAL_BYTES: usize = 2;
// Four full classifier blocks amortize iteration through the retained finder.
// Finder preprocessing is paid once during plan construction.
const CANDIDATE_MIN_INPUT_BYTES: usize = ASCII_WIDE_BYTES * 4;
// A conservative logical source-read and work charge for the pinned memchr
// 2.8.3 forward finder. It covers vector-window overlap, candidate
// confirmation, and scalar linear fallback without claiming hardware-load
// exactness from an opaque dependency.
const FINDER_SCAN_CHARGE_PER_BYTE: usize = 16;
const FINDER_CALL_WORK: usize = 2;
const ANCHOR_CANDIDATE_WORK: usize = 4;
const VERIFICATION_READ_WORK: usize = 1;
// Non-overlapping literal candidates partition the gaps between anchors.
// Each verifier can walk only the adjacent word/space runs in those gaps.
// Four whole-input passes plus eight endpoint reads per candidate is therefore
// a conservative bound for all explicit verifier byte examinations.
const VERIFICATION_PASSES: usize = 4;
const VERIFICATION_ENDPOINT_READS_PER_CANDIDATE: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Topology {
    WordSpaceLiteralSpaceWord,
    WordSpaceLiteral,
}

/// Physical reduction route selected from public plan and input lengths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// The complete phrase cannot fit, so execution observes no source bytes.
    ImpossibleWidth,
    /// Short inputs use the incumbent fixed-block classifier and token DFA.
    BlockMasks,
    /// Long inputs use the retained literal finder and adjacent-run verifier.
    LiteralAnchors,
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "the cache identity records independent proved semantic invariants explicitly"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub literal_bytes: usize,
    pub topology: Topology,
    pub outer_word_assertions: bool,
    pub unicode: bool,
    pub greedy: bool,
    pub maximal_tokens: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_literal_bytes: usize,
    pub max_build_work: usize,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_literal_bytes: usize::MAX,
            max_build_work: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_literal_bytes: 4 * 1024 * 1024,
            max_build_work: 64 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_persistent_bytes: 16 * 1024 * 1024,
            max_peak_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub literal_bytes: usize,
    pub work_upper_bound: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_input_bytes: usize,
    pub max_source_reads: usize,
    pub max_work: usize,
    pub max_classifications: usize,
    pub max_literal_comparisons: usize,
    pub max_token_events: usize,
    pub max_finder_scan_bytes: usize,
    pub max_finder_calls: usize,
    pub max_anchor_candidates: usize,
    pub max_verification_reads: usize,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_source_reads: usize::MAX,
            max_work: usize::MAX,
            max_classifications: usize::MAX,
            max_literal_comparisons: usize::MAX,
            max_token_events: usize::MAX,
            max_finder_scan_bytes: usize::MAX,
            max_finder_calls: usize::MAX,
            max_anchor_candidates: usize::MAX,
            max_verification_reads: usize::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 512 * 1024 * 1024,
            max_source_reads: 512 * 1024 * 1024,
            max_work: 8 * 1024 * 1024 * 1024,
            max_classifications: 512 * 1024 * 1024,
            max_literal_comparisons: 512 * 1024 * 1024,
            max_token_events: 512 * 1024 * 1024,
            max_finder_scan_bytes: 512 * 1024 * 1024,
            max_finder_calls: 512 * 1024 * 1024,
            max_anchor_candidates: 512 * 1024 * 1024,
            max_verification_reads: 8 * 1024 * 1024 * 1024,
            max_match_events: 64 * 1024 * 1024,
            max_count: 64 * 1024 * 1024,
            max_span_sum: u64::MAX,
            max_scratch_bytes: 0,
            max_persistent_bytes: 16 * 1024 * 1024,
            max_peak_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub route: Route,
    pub input_bytes: usize,
    /// Route-specific conservative logical source-read charge.
    ///
    /// The block route charges its one classification load per byte. The
    /// anchor route charges the pinned finder at
    /// `FINDER_SCAN_CHARGE_PER_BYTE` plus every explicit verifier read.
    /// This is intentionally not presented as a hardware load count.
    pub source_reads: usize,
    pub work: usize,
    /// Block classifications or explicit anchor-verifier predicates.
    pub classifications: usize,
    /// Block-route literal comparisons. Anchor search is metered separately.
    pub literal_comparisons: usize,
    /// Block-route maximal-token events.
    pub token_events: usize,
    /// Bytes in the complete window passed to the retained finder.
    pub finder_scan_bytes: usize,
    /// Finder iterator calls, including final exhaustion.
    pub finder_calls: usize,
    /// Non-overlapping literal occurrences yielded by the finder.
    pub anchor_candidates: usize,
    /// Explicit byte examinations in adjacent-run verification.
    pub verification_reads: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub route: Route,
    /// Route-specific logical source-read charge using the same definitions as
    /// [`ReduceUpperBounds::source_reads`].
    pub source_reads: usize,
    pub work: usize,
    /// Exact block classifications or anchor-verifier predicates.
    pub classifications: usize,
    /// Exact block-route comparisons while a literal token was expected.
    pub literal_comparisons: usize,
    /// Exact maximal tokens consumed by the block-route DFA.
    pub tokens: usize,
    /// Exact complete-window finder scan charge (zero or the input length).
    pub finder_scan_bytes: usize,
    /// Exact iterator calls, including final exhaustion.
    pub finder_calls: usize,
    /// Exact non-overlapping literal occurrences yielded.
    pub anchor_candidates: usize,
    /// Exact explicit byte examinations made by adjacent-run verification.
    pub verification_reads: usize,
    pub matches: usize,
    pub count: u64,
    pub span_sum: u64,
    pub scratch_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult {
    pub count: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult {
    pub span_sum: u64,
    pub accounting: ReduceAccounting,
}

/// One complete non-overlapping match emitted by the token-phrase reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteSpan {
    pub start: usize,
    pub end: usize,
}

/// Summary of one allocation-free complete-span traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanVisitResult {
    pub matches: usize,
    pub span_sum: u64,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyLiteral,
    NonWordLiteral { byte: u8 },
    LiteralBytesLimit { needed: usize, limit: usize },
    WorkLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    AllocationFailed { bytes: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "token-phrase construction failed: {self:?}")
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InputBytesLimit {
        needed: usize,
        limit: usize,
    },
    SourceReadsLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    ClassificationsLimit {
        needed: usize,
        limit: usize,
    },
    LiteralComparisonsLimit {
        needed: usize,
        limit: usize,
    },
    TokenEventsLimit {
        needed: usize,
        limit: usize,
    },
    FinderScanBytesLimit {
        needed: usize,
        limit: usize,
    },
    FinderCallsLimit {
        needed: usize,
        limit: usize,
    },
    AnchorCandidatesLimit {
        needed: usize,
        limit: usize,
    },
    VerificationReadsLimit {
        needed: usize,
        limit: usize,
    },
    MatchEventsLimit {
        needed: usize,
        limit: usize,
    },
    CountLimit {
        needed: u64,
        limit: u64,
    },
    SpanSumLimit {
        needed: u64,
        limit: u64,
    },
    ScratchLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
    AccountingInvariant {
        resource: &'static str,
        actual: u64,
        upper: u64,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "token-phrase reduction failed: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Debug)]
pub struct TokenPhrasePlan {
    finder: Finder<'static>,
    classifier: AsciiWordSpaceClassifier,
    topology: Topology,
    outer_word_assertions: bool,
    build: BuildAccounting,
}

impl TokenPhrasePlan {
    pub fn build(
        literal: &[u8],
        outer_word_assertions: bool,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_attempt(literal, outer_word_assertions, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build one proved token-phrase topology.
    pub fn build_topology(
        literal: &[u8],
        topology: Topology,
        outer_word_assertions: bool,
        limits: BuildLimits,
    ) -> Result<Self, BuildError> {
        Self::build_topology_attempt(literal, topology, outer_word_assertions, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build while retaining exact successful or partial terminal effects.
    #[allow(
        clippy::too_many_lines,
        reason = "the construction transaction keeps literal validation, exact allocation, classifier construction, and partial effects in one auditable boundary"
    )]
    pub fn build_attempt(
        literal: &[u8],
        outer_word_assertions: bool,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        Self::build_topology_attempt(
            literal,
            Topology::WordSpaceLiteralSpaceWord,
            outer_word_assertions,
            limits,
        )
    }

    /// Build one proved topology while retaining exact successful or partial
    /// terminal effects.
    #[allow(
        clippy::too_many_lines,
        reason = "the construction transaction keeps literal validation, exact allocation, classifier construction, and partial effects in one auditable boundary"
    )]
    pub fn build_topology_attempt(
        literal: &[u8],
        topology: Topology,
        outer_word_assertions: bool,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>> {
        let mut actual = DirectBuildAttemptActual::default();
        let result = (|| {
            if literal.is_empty() {
                return Err(BuildError::EmptyLiteral);
            }
            enforce_build(
                literal.len(),
                limits.max_literal_bytes,
                BuildResource::LiteralBytes,
            )?;
            let literal_build_work_per_byte = LITERAL_VALIDATION_WORK_PER_BYTE
                .checked_add(LITERAL_COPY_WORK_PER_BYTE)
                .and_then(|work| work.checked_add(FINDER_BUILD_WORK_PER_BYTE))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "literal build work per byte",
                })?;
            let work_upper_bound = literal
                .len()
                .checked_mul(literal_build_work_per_byte)
                .and_then(|work| work.checked_add(FIXED_BUILD_WORK))
                .and_then(|work| work.checked_add(SIMD_CLASSIFIER_BUILD_WORK))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "complete literal build work",
                })?;
            enforce_build(work_upper_bound, limits.max_build_work, BuildResource::Work)?;
            let scratch_bytes = 0;
            let persistent_bytes = size_of::<Self>().checked_add(literal.len()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "persistent bytes",
                },
            )?;
            let peak_bytes = persistent_bytes;
            enforce_build(
                scratch_bytes,
                limits.max_scratch_bytes,
                BuildResource::Scratch,
            )?;
            enforce_build(
                persistent_bytes,
                limits.max_persistent_bytes,
                BuildResource::Persistent,
            )?;
            enforce_build(peak_bytes, limits.max_peak_bytes, BuildResource::Peak)?;

            actual.work =
                u64::try_from(FIXED_BUILD_WORK).map_err(|_| BuildError::ArithmeticOverflow {
                    computation: "fixed build work conversion",
                })?;
            for &byte in literal {
                actual.work =
                    actual
                        .work
                        .checked_add(u64::try_from(LITERAL_VALIDATION_WORK_PER_BYTE).map_err(
                            |_| BuildError::ArithmeticOverflow {
                                computation: "literal validation work conversion",
                            },
                        )?)
                        .ok_or(BuildError::ArithmeticOverflow {
                            computation: "literal validation work",
                        })?;
                if !is_ascii_word(byte) {
                    return Err(BuildError::NonWordLiteral { byte });
                }
            }

            let literal = fre_exact_alloc::copy_exact(literal)
                .map(Vec::into_boxed_slice)
                .map_err(|error| match error {
                    CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
                        computation: "exact literal allocation layout",
                    },
                    CopyError::AllocationFailed => BuildError::AllocationFailed {
                        bytes: literal.len(),
                    },
                })?;
            actual.allocations = 1;
            actual.allocated_bytes = literal.len();
            actual.copied_bytes = literal.len();
            actual.work = actual
                .work
                .checked_add(
                    u64::try_from(
                        literal
                            .len()
                            .checked_mul(LITERAL_COPY_WORK_PER_BYTE)
                            .ok_or(BuildError::ArithmeticOverflow {
                                computation: "literal copy work",
                            })?,
                    )
                    .map_err(|_| BuildError::ArithmeticOverflow {
                        computation: "literal copy work conversion",
                    })?,
                )
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "complete literal copy work",
                })?;
            let finder = FinderBuilder::new().build_forward_owned(literal);
            actual.work = actual
                .work
                .checked_add(
                    u64::try_from(
                        finder
                            .needle()
                            .len()
                            .checked_mul(FINDER_BUILD_WORK_PER_BYTE)
                            .ok_or(BuildError::ArithmeticOverflow {
                                computation: "finder preprocessing work",
                            })?,
                    )
                    .map_err(|_| BuildError::ArithmeticOverflow {
                        computation: "finder preprocessing work conversion",
                    })?,
                )
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "complete finder preprocessing work",
                })?;
            let classifier = AsciiWordSpaceClassifier::with_policy(DispatchPolicy::Auto)
                .expect("automatic word/space classification always has a scalar fallback");
            actual.work = actual
                .work
                .checked_add(u64::try_from(SIMD_CLASSIFIER_BUILD_WORK).map_err(|_| {
                    BuildError::ArithmeticOverflow {
                        computation: "classifier build work conversion",
                    }
                })?)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "complete actual build work",
                })?;
            debug_assert_eq!(usize::try_from(actual.work), Ok(work_upper_bound));
            actual.initialized_bytes = persistent_bytes;
            actual.live_persistent_bytes = persistent_bytes;
            actual.peak_bytes = persistent_bytes;
            Ok(Self {
                finder,
                classifier,
                topology,
                outer_word_assertions,
                build: BuildAccounting {
                    literal_bytes: persistent_bytes - size_of::<Self>(),
                    work_upper_bound,
                    scratch_bytes,
                    persistent_bytes,
                    peak_bytes,
                },
            })
        })();
        match result {
            Ok(plan) => Ok(DirectBuildAttempt::new(plan, actual)),
            Err(source) => {
                actual.live_persistent_bytes = 0;
                Err(DirectBuildAttemptError::new(source, actual))
            }
        }
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.build
    }

    #[must_use]
    pub const fn count_identity(&self) -> OperationIdentity {
        self.identity(COUNT_OPERATION_ID)
    }

    #[must_use]
    pub const fn span_sum_identity(&self) -> OperationIdentity {
        self.identity(SPAN_SUM_OPERATION_ID)
    }

    #[must_use]
    pub const fn span_visit_identity(&self) -> OperationIdentity {
        self.identity(SPAN_VISIT_OPERATION_ID)
    }

    const fn identity(&self, operation_id: &'static str) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id,
            literal_bytes: self.build.literal_bytes,
            topology: self.topology,
            outer_word_assertions: self.outer_word_assertions,
            unicode: false,
            greedy: true,
            maximal_tokens: true,
            non_overlapping: true,
        }
    }

    fn literal(&self) -> &[u8] {
        self.finder.needle()
    }

    const fn minimum_non_literal_bytes(&self) -> usize {
        match self.topology {
            Topology::WordSpaceLiteralSpaceWord => FULL_MINIMUM_NON_LITERAL_BYTES,
            Topology::WordSpaceLiteral => TERMINAL_MINIMUM_NON_LITERAL_BYTES,
        }
    }

    const fn uses_short_block_route(&self, input_bytes: usize) -> bool {
        matches!(self.topology, Topology::WordSpaceLiteralSpaceWord)
            && input_bytes < CANDIDATE_MIN_INPUT_BYTES
    }

    #[inline]
    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
        if self.uses_short_block_route(haystack.len()) {
            let upper = self.preflight_short_input(haystack.len(), Operation::Count, limits)?;
            let actual = self.scan(haystack, Operation::Count, upper)?;
            return Ok(CountResult {
                count: actual.count,
                accounting: ReduceAccounting {
                    identity: self.count_identity(),
                    upper_bounds: upper,
                    actual,
                },
            });
        }
        let upper = self.preflight(haystack.len(), Operation::Count, limits)?;
        let actual = self.scan(haystack, Operation::Count, upper)?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    #[inline]
    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
        if self.uses_short_block_route(haystack.len()) {
            let upper = self.preflight_short_input(haystack.len(), Operation::SpanSum, limits)?;
            let actual = self.scan(haystack, Operation::SpanSum, upper)?;
            return Ok(SpanSumResult {
                span_sum: actual.span_sum,
                accounting: ReduceAccounting {
                    identity: self.span_sum_identity(),
                    upper_bounds: upper,
                    actual,
                },
            });
        }
        let upper = self.preflight(haystack.len(), Operation::SpanSum, limits)?;
        let actual = self.scan(haystack, Operation::SpanSum, upper)?;
        Ok(SpanSumResult {
            span_sum: actual.span_sum,
            accounting: ReduceAccounting {
                identity: self.span_sum_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    /// Visit every complete non-overlapping match in one allocation-free
    /// traversal. Prospective limits are checked before source access or the
    /// first callback.
    #[inline]
    pub fn visit_spans<F>(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
        mut visitor: F,
    ) -> Result<SpanVisitResult, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let upper = if self.uses_short_block_route(haystack.len()) {
            self.preflight_short_input(haystack.len(), Operation::SpanVisit, limits)?
        } else {
            self.preflight(haystack.len(), Operation::SpanVisit, limits)?
        };
        let actual = self.scan_with_visitor(haystack, Operation::SpanVisit, upper, &mut visitor)?;
        Ok(SpanVisitResult {
            matches: actual.matches,
            span_sum: actual.span_sum,
            accounting: ReduceAccounting {
                identity: self.span_visit_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    #[inline]
    fn preflight_short_input(
        &self,
        input_bytes: usize,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        debug_assert!(input_bytes < CANDIDATE_MIN_INPUT_BYTES);
        let upper = self.derive_short_input_upper_bounds(input_bytes, operation)?;
        enforce_upper_bounds(upper, limits)?;
        Ok(upper)
    }

    fn derive_short_input_upper_bounds(
        &self,
        input_bytes: usize,
        operation: Operation,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let minimum_match_bytes = self
            .literal()
            .len()
            .checked_add(self.minimum_non_literal_bytes())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "minimum token-phrase match width",
            })?;
        let route = if input_bytes < minimum_match_bytes {
            Route::ImpossibleWidth
        } else {
            Route::BlockMasks
        };
        let match_events = if route == Route::ImpossibleWidth {
            0
        } else {
            input_bytes
                .checked_div(minimum_match_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "match-event bound divisor",
                })?
        };
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "match-event bound as count",
        })?;
        let span_sum = match operation {
            Operation::Count => 0,
            Operation::SpanSum | Operation::SpanVisit if route == Route::ImpossibleWidth => 0,
            Operation::SpanSum | Operation::SpanVisit => {
                u64::try_from(input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "input bytes as span-sum bound",
                })?
            }
        };
        let (source_reads, work, classifications, literal_comparisons, token_events) =
            if route == Route::ImpossibleWidth {
                (0, FIXED_REDUCE_WORK, 0, 0, 0)
            } else {
                let classifications = input_bytes;
                let literal_comparisons = input_bytes;
                let token_events = input_bytes;
                let work = classifications
                    .checked_mul(CLASSIFICATION_WORK)
                    .and_then(|value| {
                        literal_comparisons
                            .checked_mul(LITERAL_COMPARISON_WORK)
                            .and_then(|comparisons| value.checked_add(comparisons))
                    })
                    .and_then(|value| {
                        token_events
                            .checked_mul(TOKEN_EVENT_WORK)
                            .and_then(|tokens| value.checked_add(tokens))
                    })
                    .and_then(|value| {
                        match_events
                            .checked_mul(MATCH_WORK)
                            .and_then(|matches| value.checked_add(matches))
                    })
                    .and_then(|value| value.checked_add(FIXED_REDUCE_WORK))
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "complete short-input block-mask reduction work bound",
                    })?;
                (
                    input_bytes,
                    work,
                    classifications,
                    literal_comparisons,
                    token_events,
                )
            };
        let persistent_bytes = self.build.persistent_bytes;
        Ok(ReduceUpperBounds {
            route,
            input_bytes,
            source_reads,
            work,
            classifications,
            literal_comparisons,
            token_events,
            finder_scan_bytes: 0,
            finder_calls: 0,
            anchor_candidates: 0,
            verification_reads: 0,
            match_events,
            count,
            span_sum,
            scratch_bytes: 0,
            persistent_bytes,
            peak_bytes: persistent_bytes,
        })
    }

    fn preflight(
        &self,
        input_bytes: usize,
        operation: Operation,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let upper = self.derive_upper_bounds(input_bytes, operation)?;
        enforce_upper_bounds(upper, limits)?;
        Ok(upper)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the route discriminator and every route-specific prospective counter stay in one source-free admission certificate"
    )]
    fn derive_upper_bounds(
        &self,
        input_bytes: usize,
        operation: Operation,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let minimum_match_bytes = self
            .literal()
            .len()
            .checked_add(self.minimum_non_literal_bytes())
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "minimum token-phrase match width",
            })?;
        let route = if input_bytes < minimum_match_bytes {
            Route::ImpossibleWidth
        } else if self.uses_short_block_route(input_bytes) {
            Route::BlockMasks
        } else {
            Route::LiteralAnchors
        };
        let match_events = if route == Route::ImpossibleWidth {
            0
        } else {
            input_bytes
                .checked_div(minimum_match_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "match-event bound divisor",
                })?
        };
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "match-event bound as count",
        })?;
        let span_sum = match operation {
            Operation::Count => 0,
            Operation::SpanSum | Operation::SpanVisit if route == Route::ImpossibleWidth => 0,
            Operation::SpanSum | Operation::SpanVisit => {
                u64::try_from(input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "input bytes as span-sum bound",
                })?
            }
        };
        let (
            source_reads,
            work,
            classifications,
            literal_comparisons,
            token_events,
            finder_scan_bytes,
            finder_calls,
            anchor_candidates,
            verification_reads,
        ) = match route {
            Route::ImpossibleWidth => (0, FIXED_REDUCE_WORK, 0, 0, 0, 0, 0, 0, 0),
            Route::BlockMasks => {
                let classifications = input_bytes;
                let literal_comparisons = input_bytes;
                let token_events = input_bytes;
                let work = classifications
                    .checked_mul(CLASSIFICATION_WORK)
                    .and_then(|value| {
                        literal_comparisons
                            .checked_mul(LITERAL_COMPARISON_WORK)
                            .and_then(|comparisons| value.checked_add(comparisons))
                    })
                    .and_then(|value| {
                        token_events
                            .checked_mul(TOKEN_EVENT_WORK)
                            .and_then(|tokens| value.checked_add(tokens))
                    })
                    .and_then(|value| {
                        match_events
                            .checked_mul(MATCH_WORK)
                            .and_then(|matches| value.checked_add(matches))
                    })
                    .and_then(|value| value.checked_add(FIXED_REDUCE_WORK))
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "complete block-mask reduction work bound",
                    })?;
                (
                    input_bytes,
                    work,
                    classifications,
                    literal_comparisons,
                    token_events,
                    0,
                    0,
                    0,
                    0,
                )
            }
            Route::LiteralAnchors => {
                let finder_scan_bytes = input_bytes;
                let anchor_candidates = input_bytes.checked_div(self.literal().len()).ok_or(
                    ReduceError::ArithmeticOverflow {
                        computation: "anchor-candidate bound divisor",
                    },
                )?;
                let finder_calls =
                    anchor_candidates
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "finder-call bound",
                        })?;
                let verification_reads = input_bytes
                    .checked_mul(VERIFICATION_PASSES)
                    .and_then(|reads| {
                        anchor_candidates
                            .checked_mul(VERIFICATION_ENDPOINT_READS_PER_CANDIDATE)
                            .and_then(|endpoints| reads.checked_add(endpoints))
                    })
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "anchor-verification read bound",
                    })?;
                let source_reads = finder_scan_bytes
                    .checked_mul(FINDER_SCAN_CHARGE_PER_BYTE)
                    .and_then(|reads| reads.checked_add(verification_reads))
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "literal-anchor source-read bound",
                    })?;
                let classifications = verification_reads;
                let work = finder_scan_bytes
                    .checked_mul(FINDER_SCAN_CHARGE_PER_BYTE)
                    .and_then(|value| {
                        finder_calls
                            .checked_mul(FINDER_CALL_WORK)
                            .and_then(|calls| value.checked_add(calls))
                    })
                    .and_then(|value| {
                        anchor_candidates
                            .checked_mul(ANCHOR_CANDIDATE_WORK)
                            .and_then(|candidates| value.checked_add(candidates))
                    })
                    .and_then(|value| {
                        verification_reads
                            .checked_mul(VERIFICATION_READ_WORK)
                            .and_then(|verification| value.checked_add(verification))
                    })
                    .and_then(|value| {
                        match_events
                            .checked_mul(MATCH_WORK)
                            .and_then(|matches| value.checked_add(matches))
                    })
                    .and_then(|value| value.checked_add(FIXED_REDUCE_WORK))
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "complete literal-anchor reduction work bound",
                    })?;
                (
                    source_reads,
                    work,
                    classifications,
                    0,
                    0,
                    finder_scan_bytes,
                    finder_calls,
                    anchor_candidates,
                    verification_reads,
                )
            }
        };
        let scratch_bytes = 0;
        let persistent_bytes = self.build.persistent_bytes;
        let peak_bytes = persistent_bytes;
        Ok(ReduceUpperBounds {
            route,
            input_bytes,
            source_reads,
            work,
            classifications,
            literal_comparisons,
            token_events,
            finder_scan_bytes,
            finder_calls,
            anchor_candidates,
            verification_reads,
            match_events,
            count,
            span_sum,
            scratch_bytes,
            persistent_bytes,
            peak_bytes,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the one-pass fixed 32/16/tail schedule and exact final accounting remain together for source-read review"
    )]
    fn scan(
        &self,
        haystack: &[u8],
        operation: Operation,
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        self.scan_with_visitor(haystack, operation, upper, &mut |_| {})
    }

    fn scan_with_visitor<F>(
        &self,
        haystack: &[u8],
        operation: Operation,
        upper: ReduceUpperBounds,
        visitor: &mut F,
    ) -> Result<ReduceActualCounters, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        match upper.route {
            Route::ImpossibleWidth => {
                let actual = ReduceActualCounters {
                    route: Route::ImpossibleWidth,
                    source_reads: 0,
                    work: FIXED_REDUCE_WORK,
                    classifications: 0,
                    literal_comparisons: 0,
                    tokens: 0,
                    finder_scan_bytes: 0,
                    finder_calls: 0,
                    anchor_candidates: 0,
                    verification_reads: 0,
                    matches: 0,
                    count: 0,
                    span_sum: 0,
                    scratch_bytes: 0,
                };
                verify_actual(actual, upper)?;
                Ok(actual)
            }
            Route::BlockMasks => self.scan_block_masks(haystack, operation, upper, visitor),
            Route::LiteralAnchors => self.scan_literal_anchors(haystack, operation, upper, visitor),
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the one-pass fixed 32/16/tail schedule and exact final accounting remain together for source-read review"
    )]
    fn scan_block_masks<F>(
        &self,
        haystack: &[u8],
        operation: Operation,
        upper: ReduceUpperBounds,
        visitor: &mut F,
    ) -> Result<ReduceActualCounters, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let mut actual = ReduceActualCounters {
            route: Route::BlockMasks,
            source_reads: haystack.len(),
            work: FIXED_REDUCE_WORK,
            classifications: haystack.len(),
            literal_comparisons: 0,
            tokens: 0,
            finder_scan_bytes: 0,
            finder_calls: 0,
            anchor_candidates: 0,
            verification_reads: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            scratch_bytes: 0,
        };
        let mut stream = TokenStreamState::new();
        let mut position = 0_usize;

        while haystack.len() - position >= ASCII_WIDE_BYTES {
            let end = position + ASCII_WIDE_BYTES;
            let block: [u8; ASCII_WIDE_BYTES] = haystack[position..end]
                .try_into()
                .expect("the exact wide source extent was checked");
            let masks = self.classifier.classify_32(&block);
            self.consume_classified_block(
                &block,
                position,
                masks.word_mask(),
                masks.space_mask(),
                operation,
                &mut stream,
                &mut actual,
                visitor,
            )?;
            position = end;
        }

        if haystack.len() - position >= ASCII_NARROW_BYTES {
            let end = position + ASCII_NARROW_BYTES;
            let block: [u8; ASCII_NARROW_BYTES] = haystack[position..end]
                .try_into()
                .expect("the exact narrow source extent was checked");
            let masks = self.classifier.classify_16(&block);
            self.consume_classified_block(
                &block,
                position,
                u32::from(masks.word_mask()),
                u32::from(masks.space_mask()),
                operation,
                &mut stream,
                &mut actual,
                visitor,
            )?;
            position = end;
        }

        if position < haystack.len() {
            let tail_len = haystack.len() - position;
            let mut tail = [0_u8; ASCII_NARROW_BYTES];
            let mut words = 0_u32;
            let mut spaces = 0_u32;
            for lane in 0..tail_len {
                let byte = haystack[position + lane];
                tail[lane] = byte;
                let bit = 1_u32 << lane;
                if is_ascii_word(byte) {
                    words |= bit;
                } else if is_ascii_space(byte) {
                    spaces |= bit;
                }
            }
            self.consume_classified_block(
                &tail[..tail_len],
                position,
                words,
                spaces,
                operation,
                &mut stream,
                &mut actual,
                visitor,
            )?;
        }

        if let Some(kind) = stream.token_kind {
            self.consume_token(
                Token {
                    kind,
                    start: stream.token_start,
                    end: haystack.len(),
                    literal_equal: stream.literal_equal,
                },
                operation,
                &mut stream.phrase,
                &mut actual,
                visitor,
            )?;
        }

        actual.work = actual
            .classifications
            .checked_mul(CLASSIFICATION_WORK)
            .and_then(|work| {
                actual
                    .literal_comparisons
                    .checked_mul(LITERAL_COMPARISON_WORK)
                    .and_then(|comparisons| work.checked_add(comparisons))
            })
            .and_then(|work| {
                actual
                    .tokens
                    .checked_mul(TOKEN_EVENT_WORK)
                    .and_then(|tokens| work.checked_add(tokens))
            })
            .and_then(|work| {
                actual
                    .matches
                    .checked_mul(MATCH_WORK)
                    .and_then(|matches| work.checked_add(matches))
            })
            .and_then(|work| work.checked_add(FIXED_REDUCE_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual reduction work",
            })?;
        verify_actual(actual, upper)?;
        Ok(actual)
    }

    fn scan_literal_anchors<F>(
        &self,
        haystack: &[u8],
        operation: Operation,
        upper: ReduceUpperBounds,
        visitor: &mut F,
    ) -> Result<ReduceActualCounters, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let mut actual = ReduceActualCounters {
            route: Route::LiteralAnchors,
            source_reads: 0,
            work: FIXED_REDUCE_WORK,
            classifications: 0,
            literal_comparisons: 0,
            tokens: 0,
            finder_scan_bytes: haystack.len(),
            finder_calls: 0,
            anchor_candidates: 0,
            verification_reads: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            scratch_bytes: 0,
        };
        let mut consumed_through = 0_usize;
        // `find_iter` deliberately skips overlapping literal occurrences. That
        // is complete for this grammar: the byte immediately before any
        // skipped overlap lies inside the earlier all-word literal, while a
        // qualifying middle literal must have ASCII space immediately before
        // it.
        for literal_start in self.finder.find_iter(haystack) {
            actual.anchor_candidates = checked_add(
                actual.anchor_candidates,
                1,
                "literal-anchor candidate events",
            )?;
            if literal_start < consumed_through {
                continue;
            }
            let Some((match_start, match_end)) =
                self.literal_anchor_match_span(haystack, literal_start, &mut actual)?
            else {
                continue;
            };
            if match_start < consumed_through {
                continue;
            }
            record_match(&mut actual, operation, match_start, match_end, visitor)?;
            consumed_through = match_end;
        }
        actual.finder_calls =
            actual
                .anchor_candidates
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual finder calls",
                })?;
        actual.classifications = actual.verification_reads;
        actual.source_reads = actual
            .finder_scan_bytes
            .checked_mul(FINDER_SCAN_CHARGE_PER_BYTE)
            .and_then(|reads| reads.checked_add(actual.verification_reads))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual literal-anchor source-read charge",
            })?;
        actual.work = actual
            .finder_scan_bytes
            .checked_mul(FINDER_SCAN_CHARGE_PER_BYTE)
            .and_then(|work| {
                actual
                    .finder_calls
                    .checked_mul(FINDER_CALL_WORK)
                    .and_then(|calls| work.checked_add(calls))
            })
            .and_then(|work| {
                actual
                    .anchor_candidates
                    .checked_mul(ANCHOR_CANDIDATE_WORK)
                    .and_then(|candidates| work.checked_add(candidates))
            })
            .and_then(|work| {
                actual
                    .verification_reads
                    .checked_mul(VERIFICATION_READ_WORK)
                    .and_then(|verification| work.checked_add(verification))
            })
            .and_then(|work| {
                actual
                    .matches
                    .checked_mul(MATCH_WORK)
                    .and_then(|matches| work.checked_add(matches))
            })
            .and_then(|work| work.checked_add(FIXED_REDUCE_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual literal-anchor reduction work",
            })?;
        verify_actual(actual, upper)?;
        Ok(actual)
    }

    fn literal_anchor_match_span(
        &self,
        haystack: &[u8],
        literal_start: usize,
        actual: &mut ReduceActualCounters,
    ) -> Result<Option<(usize, usize)>, ReduceError> {
        let literal_end = literal_start.checked_add(self.literal().len()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "literal anchor end",
            },
        )?;
        if literal_start == 0 || literal_end > haystack.len() {
            return Ok(None);
        }
        if !read_is_ascii_space(haystack, literal_start - 1, actual)? {
            return Ok(None);
        }

        let mut left_space_start = literal_start;
        while left_space_start > 0 && read_is_ascii_space(haystack, left_space_start - 1, actual)? {
            left_space_start -= 1;
        }
        if left_space_start == 0 || !read_is_ascii_word(haystack, left_space_start - 1, actual)? {
            return Ok(None);
        }
        let mut match_start = left_space_start;
        while match_start > 0 && read_is_ascii_word(haystack, match_start - 1, actual)? {
            match_start -= 1;
        }

        if self.topology == Topology::WordSpaceLiteral {
            if self.outer_word_assertions
                && literal_end < haystack.len()
                && read_is_ascii_word(haystack, literal_end, actual)?
            {
                return Ok(None);
            }
            return Ok(Some((match_start, literal_end)));
        }

        if literal_end == haystack.len() || !read_is_ascii_space(haystack, literal_end, actual)? {
            return Ok(None);
        }

        let mut right_word_start = literal_end;
        while right_word_start < haystack.len()
            && read_is_ascii_space(haystack, right_word_start, actual)?
        {
            right_word_start += 1;
        }
        if right_word_start == haystack.len()
            || !read_is_ascii_word(haystack, right_word_start, actual)?
        {
            return Ok(None);
        }
        let mut match_end = right_word_start;
        while match_end < haystack.len() && read_is_ascii_word(haystack, match_end, actual)? {
            match_end += 1;
        }
        Ok(Some((match_start, match_end)))
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the fixed-block boundary keeps its local bytes, disjoint masks, absolute offset, DFA, and accounting visibly coupled"
    )]
    fn consume_classified_block<F>(
        &self,
        bytes: &[u8],
        block_start: usize,
        words: u32,
        spaces: u32,
        operation: Operation,
        stream: &mut TokenStreamState,
        actual: &mut ReduceActualCounters,
        visitor: &mut F,
    ) -> Result<(), ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        debug_assert!(bytes.len() <= ASCII_WIDE_BYTES);
        let valid = low_mask(bytes.len());
        if words & spaces != 0 || (words | spaces) & !valid != 0 {
            return Err(ReduceError::AccountingInvariant {
                resource: "block class masks",
                actual: u64::from((words | spaces) & !valid),
                upper: 0,
            });
        }

        let others = valid & !(words | spaces);
        let mut lane = 0_usize;
        while lane < bytes.len() {
            let bit = 1_u32 << lane;
            let (kind, mask) = if words & bit != 0 {
                (TokenKind::Word, words)
            } else if spaces & bit != 0 {
                (TokenKind::Space, spaces)
            } else {
                (TokenKind::Other, others)
            };
            let run_len = usize::try_from((mask >> lane).trailing_ones())
                .expect("a u32 mask run length fits usize")
                .min(bytes.len() - lane);
            debug_assert_ne!(run_len, 0);
            let token_position = block_start + lane;

            if stream.token_kind.is_some_and(|current| current != kind) {
                let current = stream.token_kind.ok_or(ReduceError::ArithmeticOverflow {
                    computation: "current token kind",
                })?;
                self.consume_token(
                    Token {
                        kind: current,
                        start: stream.token_start,
                        end: token_position,
                        literal_equal: stream.literal_equal,
                    },
                    operation,
                    &mut stream.phrase,
                    actual,
                    visitor,
                )?;
                stream.begin_token(kind, token_position);
            } else if stream.token_kind.is_none() {
                stream.begin_token(kind, token_position);
            }

            if kind == TokenKind::Word && stream.compare_literal {
                let run_end = lane + run_len;
                self.compare_literal_segment(&bytes[lane..run_end], stream, actual)?;
            }
            lane += run_len;
        }
        Ok(())
    }

    fn compare_literal_segment(
        &self,
        bytes: &[u8],
        stream: &mut TokenStreamState,
        actual: &mut ReduceActualCounters,
    ) -> Result<(), ReduceError> {
        let segment_start = stream.literal_offset;
        stream.literal_offset = stream.literal_offset.checked_add(bytes.len()).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "literal candidate token width",
            },
        )?;
        if !stream.literal_equal {
            return Ok(());
        }

        let available = self.literal().len().saturating_sub(segment_start);
        let comparison_bytes = bytes.len().min(available);
        for (relative, &byte) in bytes[..comparison_bytes].iter().enumerate() {
            actual.literal_comparisons += 1;
            if self.literal()[segment_start + relative] != byte {
                stream.literal_equal = false;
                return Ok(());
            }
        }
        if comparison_bytes != bytes.len() {
            stream.literal_equal = false;
        }
        Ok(())
    }

    fn consume_token<F>(
        &self,
        token: Token,
        operation: Operation,
        state: &mut PhraseState,
        actual: &mut ReduceActualCounters,
        visitor: &mut F,
    ) -> Result<(), ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        actual.tokens = checked_add(actual.tokens, 1, "token events")?;
        let exact_literal = token.literal_equal
            && token
                .end
                .checked_sub(token.start)
                .is_some_and(|width| width == self.literal().len());
        *state = match (*state, token.kind) {
            (PhraseState::NeedLeftSpace { start }, TokenKind::Space) => {
                PhraseState::NeedLiteral { start }
            }
            (PhraseState::NeedLiteral { start }, TokenKind::Word) if exact_literal => {
                PhraseState::NeedRightSpace { start }
            }
            (PhraseState::SeekingWord | PhraseState::NeedLiteral { .. }, TokenKind::Word) => {
                PhraseState::NeedLeftSpace { start: token.start }
            }
            (PhraseState::NeedRightSpace { start }, TokenKind::Space) => {
                PhraseState::NeedFinalWord { start }
            }
            (PhraseState::NeedFinalWord { start }, TokenKind::Word) => {
                record_match(actual, operation, start, token.end, visitor)?;
                PhraseState::SeekingWord
            }
            (_, TokenKind::Word) => PhraseState::NeedLeftSpace { start: token.start },
            _ => PhraseState::SeekingWord,
        };
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Count,
    SpanSum,
    SpanVisit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokenKind {
    Word,
    Space,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Token {
    kind: TokenKind,
    start: usize,
    end: usize,
    literal_equal: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhraseState {
    SeekingWord,
    NeedLeftSpace { start: usize },
    NeedLiteral { start: usize },
    NeedRightSpace { start: usize },
    NeedFinalWord { start: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TokenStreamState {
    phrase: PhraseState,
    token_kind: Option<TokenKind>,
    token_start: usize,
    literal_offset: usize,
    literal_equal: bool,
    compare_literal: bool,
}

impl TokenStreamState {
    const fn new() -> Self {
        Self {
            phrase: PhraseState::SeekingWord,
            token_kind: None,
            token_start: 0,
            literal_offset: 0,
            literal_equal: false,
            compare_literal: false,
        }
    }

    fn begin_token(&mut self, kind: TokenKind, start: usize) {
        self.token_kind = Some(kind);
        self.token_start = start;
        self.literal_offset = 0;
        self.compare_literal =
            kind == TokenKind::Word && matches!(self.phrase, PhraseState::NeedLiteral { .. });
        self.literal_equal = self.compare_literal;
    }
}

const fn is_ascii_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

const fn is_ascii_space(byte: u8) -> bool {
    matches!(byte, b'\t'..=b'\r' | b' ')
}

fn read_is_ascii_word(
    haystack: &[u8],
    index: usize,
    actual: &mut ReduceActualCounters,
) -> Result<bool, ReduceError> {
    actual.verification_reads = checked_add(
        actual.verification_reads,
        1,
        "anchor-verification byte reads",
    )?;
    Ok(is_ascii_word(haystack[index]))
}

fn read_is_ascii_space(
    haystack: &[u8],
    index: usize,
    actual: &mut ReduceActualCounters,
) -> Result<bool, ReduceError> {
    actual.verification_reads = checked_add(
        actual.verification_reads,
        1,
        "anchor-verification byte reads",
    )?;
    Ok(is_ascii_space(haystack[index]))
}

const fn low_mask(bits: usize) -> u32 {
    if bits == ASCII_WIDE_BYTES {
        u32::MAX
    } else {
        (1_u32 << bits) - 1
    }
}

fn record_match<F>(
    actual: &mut ReduceActualCounters,
    operation: Operation,
    start: usize,
    end: usize,
    visitor: &mut F,
) -> Result<(), ReduceError>
where
    F: FnMut(CompleteSpan),
{
    actual.matches = checked_add(actual.matches, 1, "match events")?;
    actual.count = actual
        .count
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "actual count",
        })?;
    if matches!(operation, Operation::SpanSum | Operation::SpanVisit) {
        let width = end
            .checked_sub(start)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "matched span width",
            })?;
        actual.span_sum = actual
            .span_sum
            .checked_add(
                u64::try_from(width).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "matched span width as u64",
                })?,
            )
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual span sum",
            })?;
    }
    actual.work = checked_add(actual.work, MATCH_WORK, "match work")?;
    if operation == Operation::SpanVisit {
        visitor(CompleteSpan { start, end });
    }
    Ok(())
}

fn checked_add(left: usize, right: usize, computation: &'static str) -> Result<usize, ReduceError> {
    left.checked_add(right)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
}

fn verify_actual(
    actual: ReduceActualCounters,
    upper: ReduceUpperBounds,
) -> Result<(), ReduceError> {
    if actual.route != upper.route {
        return Err(ReduceError::AccountingInvariant {
            resource: "route",
            actual: 1,
            upper: 0,
        });
    }
    verify("source reads", actual.source_reads, upper.source_reads)?;
    verify("work", actual.work, upper.work)?;
    verify(
        "classifications",
        actual.classifications,
        upper.classifications,
    )?;
    verify(
        "literal comparisons",
        actual.literal_comparisons,
        upper.literal_comparisons,
    )?;
    verify("token events", actual.tokens, upper.token_events)?;
    verify(
        "finder scan bytes",
        actual.finder_scan_bytes,
        upper.finder_scan_bytes,
    )?;
    verify("finder calls", actual.finder_calls, upper.finder_calls)?;
    verify(
        "anchor candidates",
        actual.anchor_candidates,
        upper.anchor_candidates,
    )?;
    verify(
        "verification reads",
        actual.verification_reads,
        upper.verification_reads,
    )?;
    verify("matches", actual.matches, upper.match_events)?;
    verify("count", actual.count, upper.count)?;
    verify("span sum", actual.span_sum, upper.span_sum)?;
    verify("scratch bytes", actual.scratch_bytes, upper.scratch_bytes)
}

fn verify(
    resource: &'static str,
    actual: impl TryInto<u64>,
    upper: impl TryInto<u64>,
) -> Result<(), ReduceError> {
    let actual = actual
        .try_into()
        .map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "actual counter as u64",
        })?;
    let upper = upper
        .try_into()
        .map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "upper bound as u64",
        })?;
    if actual > upper {
        return Err(ReduceError::AccountingInvariant {
            resource,
            actual,
            upper,
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum BuildResource {
    LiteralBytes,
    Work,
    Scratch,
    Persistent,
    Peak,
}

fn enforce_build(needed: usize, limit: usize, resource: BuildResource) -> Result<(), BuildError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        BuildResource::LiteralBytes => BuildError::LiteralBytesLimit { needed, limit },
        BuildResource::Work => BuildError::WorkLimit { needed, limit },
        BuildResource::Scratch => BuildError::ScratchLimit { needed, limit },
        BuildResource::Persistent => BuildError::PersistentLimit { needed, limit },
        BuildResource::Peak => BuildError::PeakLimit { needed, limit },
    })
}

#[derive(Clone, Copy)]
enum ReduceResource {
    InputBytes,
    SourceReads,
    Work,
    Classifications,
    LiteralComparisons,
    TokenEvents,
    FinderScanBytes,
    FinderCalls,
    AnchorCandidates,
    VerificationReads,
    MatchEvents,
    Scratch,
    Persistent,
    Peak,
}

fn enforce_upper_bounds(upper: ReduceUpperBounds, limits: ReduceLimits) -> Result<(), ReduceError> {
    for (needed, limit, resource) in [
        (
            upper.input_bytes,
            limits.max_input_bytes,
            ReduceResource::InputBytes,
        ),
        (
            upper.source_reads,
            limits.max_source_reads,
            ReduceResource::SourceReads,
        ),
        (upper.work, limits.max_work, ReduceResource::Work),
        (
            upper.classifications,
            limits.max_classifications,
            ReduceResource::Classifications,
        ),
        (
            upper.literal_comparisons,
            limits.max_literal_comparisons,
            ReduceResource::LiteralComparisons,
        ),
        (
            upper.token_events,
            limits.max_token_events,
            ReduceResource::TokenEvents,
        ),
        (
            upper.finder_scan_bytes,
            limits.max_finder_scan_bytes,
            ReduceResource::FinderScanBytes,
        ),
        (
            upper.finder_calls,
            limits.max_finder_calls,
            ReduceResource::FinderCalls,
        ),
        (
            upper.anchor_candidates,
            limits.max_anchor_candidates,
            ReduceResource::AnchorCandidates,
        ),
        (
            upper.verification_reads,
            limits.max_verification_reads,
            ReduceResource::VerificationReads,
        ),
        (
            upper.match_events,
            limits.max_match_events,
            ReduceResource::MatchEvents,
        ),
        (
            upper.scratch_bytes,
            limits.max_scratch_bytes,
            ReduceResource::Scratch,
        ),
        (
            upper.persistent_bytes,
            limits.max_persistent_bytes,
            ReduceResource::Persistent,
        ),
        (
            upper.peak_bytes,
            limits.max_peak_bytes,
            ReduceResource::Peak,
        ),
    ] {
        enforce_reduce(needed, limit, resource)?;
    }
    if upper.count > limits.max_count {
        return Err(ReduceError::CountLimit {
            needed: upper.count,
            limit: limits.max_count,
        });
    }
    if upper.span_sum > limits.max_span_sum {
        return Err(ReduceError::SpanSumLimit {
            needed: upper.span_sum,
            limit: limits.max_span_sum,
        });
    }
    Ok(())
}

fn enforce_reduce(
    needed: usize,
    limit: usize,
    resource: ReduceResource,
) -> Result<(), ReduceError> {
    if needed <= limit {
        return Ok(());
    }
    Err(match resource {
        ReduceResource::InputBytes => ReduceError::InputBytesLimit { needed, limit },
        ReduceResource::SourceReads => ReduceError::SourceReadsLimit { needed, limit },
        ReduceResource::Work => ReduceError::WorkLimit { needed, limit },
        ReduceResource::Classifications => ReduceError::ClassificationsLimit { needed, limit },
        ReduceResource::LiteralComparisons => {
            ReduceError::LiteralComparisonsLimit { needed, limit }
        }
        ReduceResource::TokenEvents => ReduceError::TokenEventsLimit { needed, limit },
        ReduceResource::FinderScanBytes => ReduceError::FinderScanBytesLimit { needed, limit },
        ReduceResource::FinderCalls => ReduceError::FinderCallsLimit { needed, limit },
        ReduceResource::AnchorCandidates => ReduceError::AnchorCandidatesLimit { needed, limit },
        ReduceResource::VerificationReads => ReduceError::VerificationReadsLimit { needed, limit },
        ReduceResource::MatchEvents => ReduceError::MatchEventsLimit { needed, limit },
        ReduceResource::Scratch => ReduceError::ScratchLimit { needed, limit },
        ReduceResource::Persistent => ReduceError::PersistentLimit { needed, limit },
        ReduceResource::Peak => ReduceError::PeakLimit { needed, limit },
    })
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;

    use super::*;

    fn plan(literal: &[u8], outer_word_assertions: bool) -> TokenPhrasePlan {
        TokenPhrasePlan::build(literal, outer_word_assertions, BuildLimits::default()).unwrap()
    }

    fn terminal_plan(literal: &[u8], outer_word_assertions: bool) -> TokenPhrasePlan {
        TokenPhrasePlan::build_topology(
            literal,
            Topology::WordSpaceLiteral,
            outer_word_assertions,
            BuildLimits::default(),
        )
        .unwrap()
    }

    fn oracle(literal: &str, asserted: bool, haystack: &[u8]) -> (u64, u64) {
        let pattern = if asserted {
            format!(r"\b\w+\s+{literal}\s+\w+\b")
        } else {
            format!(r"\w+\s+{literal}\s+\w+")
        };
        RegexBuilder::new(&pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .fold((0_u64, 0_u64), |sum, matched| {
                (
                    sum.0.checked_add(1).unwrap(),
                    sum.1
                        .checked_add(u64::try_from(matched.len()).unwrap())
                        .unwrap(),
                )
            })
    }

    fn oracle_spans(literal: &str, asserted: bool, haystack: &[u8]) -> Vec<CompleteSpan> {
        let pattern = if asserted {
            format!(r"\b\w+\s+{literal}\s+\w+\b")
        } else {
            format!(r"\w+\s+{literal}\s+\w+")
        };
        RegexBuilder::new(&pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| CompleteSpan {
                start: matched.start(),
                end: matched.end(),
            })
            .collect()
    }

    fn terminal_oracle_spans(literal: &str, asserted: bool, haystack: &[u8]) -> Vec<CompleteSpan> {
        let pattern = if asserted {
            format!(r"\b\w+\s+{literal}\b")
        } else {
            format!(r"\w+\s+{literal}")
        };
        RegexBuilder::new(&pattern)
            .unicode(false)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| CompleteSpan {
                start: matched.start(),
                end: matched.end(),
            })
            .collect()
    }

    fn generate(alphabet: &[u8], maximum: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        for _ in 0..maximum {
            let prior = all.clone();
            for prefix in prior {
                for &byte in alphabet {
                    let mut value = prefix.clone();
                    value.push(byte);
                    all.push(value);
                }
            }
        }
        all.sort();
        all.dedup();
        all
    }

    #[test]
    fn maximal_tokens_preserve_restart_greediness_and_nonoverlap() {
        for asserted in [false, true] {
            let plan = plan(b"Holmes", asserted);
            for haystack in [
                b"Sherlock Holmes wat".as_slice(),
                b"a Holmes b Holmes c",
                b"A  Holmes \t B--C Holmes D",
                b"A X Holmes Y",
                b"A Holm B Holmes C",
                b"A Holmes X Holmes Y",
                b"A Holmes X B Holmes Y",
                b"_ Holmes z9\nq Holmes r_",
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa                    Holmes\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                b"\xffSherlock Holmes wat\x80",
                b"notHolmes x Holmes y",
            ] {
                let expected = oracle("Holmes", asserted, haystack);
                assert_eq!(
                    plan.count(haystack, ReduceLimits::default()).unwrap().count,
                    expected.0,
                    "asserted={asserted}, haystack={haystack:?}"
                );
                assert_eq!(
                    plan.span_sum(haystack, ReduceLimits::default())
                        .unwrap()
                        .span_sum,
                    expected.1,
                    "asserted={asserted}, haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn span_visit_matches_pinned_endpoints_on_both_physical_routes() {
        for asserted in [false, true] {
            let plan = plan(b"Holmes", asserted);
            for haystack in [
                b"--left Holmes right--a Holmes b Holmes c--".as_slice(),
                b"--left Holmes right--a Holmes b Holmes c--xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            ] {
                let expected = oracle_spans("Holmes", asserted, haystack);
                let mut actual = Vec::new();
                let visited = plan
                    .visit_spans(haystack, ReduceLimits::unlimited(), |span| {
                        actual.push(span);
                    })
                    .expect("complete span visit");
                assert_eq!(actual, expected);
                assert_eq!(visited.matches, expected.len());
                assert_eq!(
                    visited.span_sum,
                    expected.iter().fold(0_u64, |sum, span| {
                        sum.checked_add(u64::try_from(span.end - span.start).unwrap())
                            .unwrap()
                    })
                );
                assert_eq!(
                    visited.accounting.identity,
                    plan.span_visit_identity()
                );
                assert_eq!(visited.accounting.actual.scratch_bytes, 0);
            }
        }
    }

    #[test]
    fn span_visit_refusal_precedes_source_and_callback() {
        let plan = plan(b"Holmes", true);
        let haystack = b"left Holmes right";
        let mut callbacks = 0_usize;
        let error = plan
            .visit_spans(
                haystack,
                ReduceLimits {
                    max_span_sum: u64::try_from(haystack.len() - 1).unwrap(),
                    ..ReduceLimits::unlimited()
                },
                |_| callbacks += 1,
            )
            .expect_err("prospective span-sum refusal");
        assert!(matches!(error, ReduceError::SpanSumLimit { .. }));
        assert_eq!(callbacks, 0);
    }

    #[test]
    fn terminal_span_visit_matches_oracle_and_keeps_full_identity_stable() {
        let full = plan(b"Holmes", false);
        assert_eq!(
            full.span_visit_identity().topology,
            Topology::WordSpaceLiteralSpaceWord
        );

        for asserted in [false, true] {
            let plan = terminal_plan(b"Holmes", asserted);
            assert_eq!(
                plan.span_visit_identity().topology,
                Topology::WordSpaceLiteral
            );
            for haystack in [
                b"a Holmes b Holmes".as_slice(),
                b"--left  Holmes--right HolmesX--tail Holmes",
                b"Holmes--left Holmes--",
                b"x\xffleft\tHolmes\x80q Holmes_more",
                b"--left Holmes--xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            ] {
                let expected = terminal_oracle_spans("Holmes", asserted, haystack);
                let mut actual = Vec::new();
                let visited = plan
                    .visit_spans(haystack, ReduceLimits::unlimited(), |span| {
                        actual.push(span);
                    })
                    .expect("terminal complete-span visit");
                assert_eq!(
                    actual, expected,
                    "asserted={asserted}, haystack={haystack:?}"
                );
                assert_eq!(visited.matches, expected.len());
                assert_eq!(visited.accounting.actual.route, Route::LiteralAnchors);
            }
        }
    }

    #[test]
    fn terminal_span_visit_matches_exhaustive_small_byte_oracle() {
        for asserted in [false, true] {
            let plan = terminal_plan(b"h", asserted);
            for haystack in generate(&[b'a', b'h', b' ', b'\t', b'-', 0xff], 5) {
                let expected = terminal_oracle_spans("h", asserted, &haystack);
                let mut actual = Vec::new();
                plan.visit_spans(&haystack, ReduceLimits::unlimited(), |span| {
                    actual.push(span);
                })
                .expect("exhaustive terminal complete-span visit");
                assert_eq!(
                    actual, expected,
                    "asserted={asserted}, haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    fn terminal_span_visit_refuses_before_callback() {
        let plan = terminal_plan(b"Holmes", false);
        let haystack = b"left Holmes";
        let mut callbacks = 0_usize;
        let error = plan
            .visit_spans(
                haystack,
                ReduceLimits {
                    max_span_sum: u64::try_from(haystack.len() - 1).unwrap(),
                    ..ReduceLimits::unlimited()
                },
                |_| callbacks += 1,
            )
            .expect_err("prospective terminal span-sum refusal");
        assert!(matches!(error, ReduceError::SpanSumLimit { .. }));
        assert_eq!(callbacks, 0);
    }

    #[test]
    fn dense_bordered_literal_occurrences_do_not_hide_exact_token_candidates() {
        let mut haystack = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-".to_vec();
        haystack.extend_from_slice(b"left aaa right");
        haystack.extend_from_slice(b"-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-");
        haystack.extend_from_slice(b"x aaa y aaa z");
        haystack.extend_from_slice(b"-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(haystack.len() >= CANDIDATE_MIN_INPUT_BYTES);
        for asserted in [false, true] {
            let plan = plan(b"aaa", asserted);
            let expected = oracle("aaa", asserted, &haystack);
            let count = plan
                .count(&haystack, ReduceLimits::unlimited())
                .expect("bordered count");
            let spans = plan
                .span_sum(&haystack, ReduceLimits::unlimited())
                .expect("bordered spans");
            assert_eq!((count.count, spans.span_sum), expected);
            let actual = count.accounting.actual;
            assert_eq!(actual.route, Route::LiteralAnchors);
            assert_eq!(actual.tokens, 0);
            assert_eq!(actual.finder_scan_bytes, haystack.len());
            assert_eq!(actual.finder_calls, actual.anchor_candidates + 1);
            assert!(
                actual.anchor_candidates
                    > usize::try_from(count.count).expect("test count fits usize")
            );
            assert!(actual.verification_reads <= count.accounting.upper_bounds.verification_reads);
        }
    }

    #[test]
    fn block_boundaries_preserve_maximal_runs_literal_gating_and_restart() {
        for asserted in [false, true] {
            let plan = plan(b"Holmes", asserted);
            for alignment in 0..ASCII_WIDE_BYTES * 2 {
                for run_len in [1, 15, 16, 17, 31, 32, 33] {
                    let mut haystack = vec![b'-'; alignment];
                    haystack.extend(core::iter::repeat_n(b'a', run_len));
                    haystack.extend(core::iter::repeat_n(b' ', run_len));
                    haystack.extend_from_slice(b"Holmes");
                    haystack.extend(core::iter::repeat_n(b'\t', run_len));
                    haystack.extend(core::iter::repeat_n(b'b', run_len));
                    haystack.extend_from_slice(b"--a Holmes b Holmes c--");

                    let expected = oracle("Holmes", asserted, &haystack);
                    let count = plan
                        .count(&haystack, ReduceLimits::unlimited())
                        .expect("block-boundary count");
                    let spans = plan
                        .span_sum(&haystack, ReduceLimits::unlimited())
                        .expect("block-boundary span sum");
                    assert_eq!(
                        (count.count, spans.span_sum),
                        expected,
                        "asserted={asserted}, alignment={alignment}, run_len={run_len}"
                    );
                    let actual = count.accounting.actual;
                    match actual.route {
                        Route::BlockMasks => {
                            assert_eq!(actual.source_reads, haystack.len());
                            assert_eq!(actual.classifications, haystack.len());
                        }
                        Route::LiteralAnchors => {
                            assert_eq!(actual.finder_scan_bytes, haystack.len());
                            assert_eq!(actual.finder_calls, actual.anchor_candidates + 1);
                            assert_eq!(actual.classifications, actual.verification_reads);
                            assert!(actual.source_reads > haystack.len());
                        }
                        Route::ImpossibleWidth => {
                            panic!("a complete phrase was present in an impossible-width route");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn exhaustive_small_byte_semantics_match_pinned_regex() {
        for (literal, maximum) in [("h", 6), ("aa", 6)] {
            for asserted in [false, true] {
                let plan = plan(literal.as_bytes(), asserted);
                let pattern = if asserted {
                    format!(r"\b\w+\s+{literal}\s+\w+\b")
                } else {
                    format!(r"\w+\s+{literal}\s+\w+")
                };
                let regex = RegexBuilder::new(&pattern).unicode(false).build().unwrap();
                for haystack in generate(&[b'a', b'h', b' ', b'\t', b'-', 0xff], maximum) {
                    let expected =
                        regex
                            .find_iter(&haystack)
                            .fold((0_u64, 0_u64), |sum, matched| {
                                (
                                    sum.0.checked_add(1).unwrap(),
                                    sum.1
                                        .checked_add(u64::try_from(matched.len()).unwrap())
                                        .unwrap(),
                                )
                            });
                    assert_eq!(
                        plan.count(&haystack, ReduceLimits::unlimited())
                            .unwrap()
                            .count,
                        expected.0,
                        "literal={literal:?}, asserted={asserted}, haystack={haystack:?}"
                    );
                    assert_eq!(
                        plan.span_sum(&haystack, ReduceLimits::unlimited())
                            .unwrap()
                            .span_sum,
                        expected.1,
                        "literal={literal:?}, asserted={asserted}, haystack={haystack:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn route_threshold_127_128_129_preserves_exact_semantics() {
        for length in [
            CANDIDATE_MIN_INPUT_BYTES - 1,
            CANDIDATE_MIN_INPUT_BYTES,
            CANDIDATE_MIN_INPUT_BYTES + 1,
        ] {
            let mut haystack = b"--left Holmes right--".to_vec();
            haystack.resize(length, b'-');
            let expected_route = if length < CANDIDATE_MIN_INPUT_BYTES {
                Route::BlockMasks
            } else {
                Route::LiteralAnchors
            };
            for asserted in [false, true] {
                let plan = plan(b"Holmes", asserted);
                let expected = oracle("Holmes", asserted, &haystack);
                let count = plan
                    .count(&haystack, ReduceLimits::unlimited())
                    .expect("threshold count");
                let spans = plan
                    .span_sum(&haystack, ReduceLimits::unlimited())
                    .expect("threshold span sum");
                assert_eq!((count.count, spans.span_sum), expected);
                assert_eq!(count.accounting.actual.route, expected_route);
                assert_eq!(spans.accounting.actual.route, expected_route);
            }
        }
    }

    #[test]
    fn short_route_has_no_anchor_admission_dependency() {
        let plan = plan(b"Holmes", true);
        let haystack = b"left Holmes right---------------";
        assert!(haystack.len() < CANDIDATE_MIN_INPUT_BYTES);
        let limits = ReduceLimits {
            max_finder_scan_bytes: 0,
            max_finder_calls: 0,
            max_anchor_candidates: 0,
            max_verification_reads: 0,
            ..ReduceLimits::unlimited()
        };
        let count = plan.count(haystack, limits).expect("short count");
        let span_sum = plan.span_sum(haystack, limits).expect("short span sum");
        assert_eq!(count.accounting.upper_bounds.route, Route::BlockMasks);
        assert_eq!(span_sum.accounting.upper_bounds.route, Route::BlockMasks);
        assert_eq!(count.accounting.actual.route, Route::BlockMasks);
        assert_eq!(span_sum.accounting.actual.route, Route::BlockMasks);
        assert_eq!(
            (
                count.accounting.upper_bounds.finder_scan_bytes,
                count.accounting.upper_bounds.finder_calls,
                count.accounting.upper_bounds.anchor_candidates,
                count.accounting.upper_bounds.verification_reads,
            ),
            (0, 0, 0, 0)
        );
        assert_eq!((count.count, span_sum.span_sum), (1, 17));
    }

    #[test]
    fn anchor_route_rejects_endpoints_other_bytes_and_high_bytes() {
        let mut haystack = Vec::new();
        haystack.extend_from_slice(b"Holmes right--");
        haystack.extend_from_slice(b"left Holmes");
        haystack.extend_from_slice(b"--left-Holmes right--left Holmes-right--");
        haystack.extend_from_slice(b"left\xffHolmes right--left Holmes\x80right--");
        haystack.extend_from_slice(b"left Holmes right--");
        while haystack.len() < CANDIDATE_MIN_INPUT_BYTES * 2 {
            haystack.extend_from_slice(b"xHolmesy-");
        }
        for asserted in [false, true] {
            let plan = plan(b"Holmes", asserted);
            let expected = oracle("Holmes", asserted, &haystack);
            let count = plan
                .count(&haystack, ReduceLimits::unlimited())
                .expect("adversarial anchor count");
            let spans = plan
                .span_sum(&haystack, ReduceLimits::unlimited())
                .expect("adversarial anchor spans");
            assert_eq!((count.count, spans.span_sum), expected);
            assert_eq!(count.accounting.actual.route, Route::LiteralAnchors);
            assert!(count.accounting.actual.anchor_candidates > 5);
            assert!(count.accounting.actual.verification_reads > 0);
        }
    }

    #[test]
    fn long_literal_uses_owned_finder_and_impossible_width_observes_no_source() {
        let literal = vec![b'H'; CANDIDATE_MIN_INPUT_BYTES * 2];
        let plan = plan(&literal, true);
        assert_eq!(plan.literal(), literal);

        let too_short = vec![b'H'; CANDIDATE_MIN_INPUT_BYTES];
        let impossible = plan
            .count(
                &too_short,
                ReduceLimits {
                    max_source_reads: 0,
                    max_classifications: 0,
                    max_literal_comparisons: 0,
                    max_token_events: 0,
                    max_finder_scan_bytes: 0,
                    max_finder_calls: 0,
                    max_anchor_candidates: 0,
                    max_verification_reads: 0,
                    max_match_events: 0,
                    max_count: 0,
                    ..ReduceLimits::unlimited()
                },
            )
            .expect("impossible width is source-free");
        assert_eq!(impossible.count, 0);
        assert_eq!(impossible.accounting.actual.route, Route::ImpossibleWidth);
        assert_eq!(impossible.accounting.actual.source_reads, 0);
        assert_eq!(impossible.accounting.actual.work, FIXED_REDUCE_WORK);

        let mut haystack = b"--left ".to_vec();
        haystack.extend_from_slice(&literal);
        haystack.extend_from_slice(b" right--");
        let literal_string = String::from_utf8(literal).expect("ASCII literal");
        let expected = oracle(&literal_string, true, &haystack);
        let count = plan
            .count(&haystack, ReduceLimits::unlimited())
            .expect("long-literal count");
        let spans = plan
            .span_sum(&haystack, ReduceLimits::unlimited())
            .expect("long-literal spans");
        assert_eq!((count.count, spans.span_sum), expected);
        assert_eq!(count.accounting.actual.route, Route::LiteralAnchors);
        assert_eq!(count.accounting.actual.anchor_candidates, 1);
    }

    #[test]
    fn block_mask_literal_gating_and_accounting_are_exact_and_conservative() {
        let plan = plan(b"Holmes", true);
        assert_eq!(plan.literal(), b"Holmes");
        assert_eq!(
            plan.build.work_upper_bound,
            FIXED_BUILD_WORK
                + b"Holmes".len()
                    * (LITERAL_VALIDATION_WORK_PER_BYTE
                        + LITERAL_COPY_WORK_PER_BYTE
                        + FINDER_BUILD_WORK_PER_BYTE)
                + SIMD_CLASSIFIER_BUILD_WORK
        );
        assert_eq!(
            plan.classifier.selection().policy,
            fre_simd_kernels::DispatchPolicy::Auto
        );

        let haystack = b"noise noise--Sherlock  Holmes \t watson--a Holmes b Holmes c--notHolmes";
        let count = plan
            .count(haystack, ReduceLimits::unlimited())
            .expect("block-mask count");
        let spans = plan
            .span_sum(haystack, ReduceLimits::unlimited())
            .expect("block-mask span sum");
        let actual = count.accounting.actual;
        assert_eq!(actual.route, Route::BlockMasks);
        assert_eq!(actual.source_reads, haystack.len());
        assert_eq!(actual.classifications, haystack.len());
        assert!(actual.literal_comparisons < haystack.len());
        assert_eq!(
            actual.work,
            FIXED_REDUCE_WORK
                + actual.classifications * CLASSIFICATION_WORK
                + actual.literal_comparisons * LITERAL_COMPARISON_WORK
                + actual.tokens * TOKEN_EVENT_WORK
                + actual.matches * MATCH_WORK
        );
        assert_eq!(
            actual.count,
            u64::try_from(actual.matches).expect("test match count fits u64")
        );
        assert_eq!(spans.accounting.actual.source_reads, actual.source_reads);
        assert_eq!(spans.accounting.actual.work, actual.work);
        assert_eq!(
            count.accounting.upper_bounds.classifications,
            haystack.len()
        );
        assert_eq!(count.accounting.upper_bounds.source_reads, haystack.len());
        assert!(count.accounting.upper_bounds.source_reads >= actual.source_reads);
    }

    #[test]
    fn identity_and_construction_refusals_are_exact() {
        let plan = plan(b"Holmes", true);
        let identity = plan.span_sum_identity();
        assert_eq!(identity.plan_id, PLAN_ID);
        assert_eq!(identity.literal_bytes, 6);
        assert_eq!(identity.topology, Topology::WordSpaceLiteralSpaceWord);
        assert!(identity.outer_word_assertions);
        assert!(!identity.unicode);
        assert!(identity.greedy);
        assert!(identity.maximal_tokens);
        assert!(identity.non_overlapping);
        assert!(matches!(
            TokenPhrasePlan::build(b"", false, BuildLimits::default()),
            Err(BuildError::EmptyLiteral)
        ));
        assert!(matches!(
            TokenPhrasePlan::build(b"not-word", false, BuildLimits::default()),
            Err(BuildError::NonWordLiteral { byte: b'-' })
        ));
        assert!(matches!(
            TokenPhrasePlan::build(
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-",
                false,
                BuildLimits {
                    max_build_work: FIXED_BUILD_WORK,
                    ..BuildLimits::default()
                }
            ),
            Err(BuildError::WorkLimit { .. })
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one test audits exact and one-below construction, block-route, and anchor-route limits together"
    )]
    fn every_positive_limit_is_preflighted_at_exact_and_one_below() {
        let build = plan(b"Holmes", true).build_accounting();
        for limits in [
            BuildLimits {
                max_literal_bytes: build.literal_bytes - 1,
                ..BuildLimits::default()
            },
            BuildLimits {
                max_build_work: build.work_upper_bound - 1,
                ..BuildLimits::default()
            },
            BuildLimits {
                max_persistent_bytes: build.persistent_bytes - 1,
                ..BuildLimits::default()
            },
            BuildLimits {
                max_peak_bytes: build.peak_bytes - 1,
                ..BuildLimits::default()
            },
        ] {
            assert!(TokenPhrasePlan::build(b"Holmes", true, limits).is_err());
        }

        let plan = plan(b"Holmes", true);
        let haystack = b"Sherlock Holmes wat and Mycroft Holmes too";
        let upper = plan
            .span_sum(haystack, ReduceLimits::unlimited())
            .unwrap()
            .accounting
            .upper_bounds;
        let exact = exact_limits(upper);
        plan.span_sum(haystack, exact)
            .expect("every exact block-mask limit succeeds");
        let cases = [
            ReduceLimits {
                max_input_bytes: upper.input_bytes - 1,
                ..exact
            },
            ReduceLimits {
                max_source_reads: upper.source_reads - 1,
                ..exact
            },
            ReduceLimits {
                max_work: upper.work - 1,
                ..exact
            },
            ReduceLimits {
                max_classifications: upper.classifications - 1,
                ..exact
            },
            ReduceLimits {
                max_literal_comparisons: upper.literal_comparisons - 1,
                ..exact
            },
            ReduceLimits {
                max_token_events: upper.token_events - 1,
                ..exact
            },
            ReduceLimits {
                max_match_events: upper.match_events - 1,
                ..exact
            },
            ReduceLimits {
                max_count: upper.count - 1,
                ..exact
            },
            ReduceLimits {
                max_span_sum: upper.span_sum - 1,
                ..exact
            },
            ReduceLimits {
                max_persistent_bytes: upper.persistent_bytes - 1,
                ..exact
            },
            ReduceLimits {
                max_peak_bytes: upper.peak_bytes - 1,
                ..exact
            },
        ];
        for limits in cases {
            assert!(plan.span_sum(haystack, limits).is_err());
        }

        let anchor_haystack = vec![b'-'; CANDIDATE_MIN_INPUT_BYTES];
        let anchor_upper = plan
            .count(&anchor_haystack, ReduceLimits::unlimited())
            .unwrap()
            .accounting
            .upper_bounds;
        assert_eq!(anchor_upper.route, Route::LiteralAnchors);
        let anchor_exact = exact_limits(anchor_upper);
        plan.count(&anchor_haystack, anchor_exact)
            .expect("every exact literal-anchor limit succeeds");
        for limits in [
            ReduceLimits {
                max_finder_scan_bytes: anchor_upper.finder_scan_bytes - 1,
                ..anchor_exact
            },
            ReduceLimits {
                max_finder_calls: anchor_upper.finder_calls - 1,
                ..anchor_exact
            },
            ReduceLimits {
                max_anchor_candidates: anchor_upper.anchor_candidates - 1,
                ..anchor_exact
            },
            ReduceLimits {
                max_verification_reads: anchor_upper.verification_reads - 1,
                ..anchor_exact
            },
        ] {
            assert!(plan.count(&anchor_haystack, limits).is_err());
        }
    }

    #[test]
    fn build_attempt_reports_exact_success_and_partial_failure() {
        let literal = b"Holmes";
        let attempt =
            TokenPhrasePlan::build_attempt(literal, true, BuildLimits::default()).unwrap();
        let actual = attempt.actual();
        let (plan, returned_actual) = attempt.into_parts();
        let build = plan.build_accounting();
        assert_eq!(returned_actual, actual);
        assert_eq!(actual.work, u64::try_from(build.work_upper_bound).unwrap());
        assert_eq!(actual.allocations, 1);
        assert_eq!(actual.allocated_bytes, literal.len());
        assert_eq!(actual.copied_bytes, literal.len());
        assert_eq!(actual.initialized_bytes, build.persistent_bytes);
        assert_eq!(actual.live_persistent_bytes, build.persistent_bytes);
        assert_eq!(actual.peak_bytes, build.peak_bytes);

        let error =
            TokenPhrasePlan::build_attempt(b"ok-", false, BuildLimits::default()).unwrap_err();
        assert!(matches!(
            error.source(),
            BuildError::NonWordLiteral { byte: b'-' }
        ));
        assert_eq!(
            error.actual().work,
            u64::try_from(FIXED_BUILD_WORK + 3 * LITERAL_VALIDATION_WORK_PER_BYTE).unwrap()
        );
        assert_eq!(error.actual().allocations, 0);
        assert_eq!(error.actual().allocated_bytes, 0);
        assert_eq!(error.actual().copied_bytes, 0);
        assert_eq!(error.actual().initialized_bytes, 0);
        assert_eq!(error.actual().live_persistent_bytes, 0);
        assert_eq!(error.actual().peak_bytes, 0);
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
    #[test]
    #[ignore = "native aarch64 qualification benchmark"]
    #[allow(
        clippy::too_many_lines,
        reason = "the parseable qualification receipt keeps authentic dispatch, correctness, alternating samples, and accounting rows together"
    )]
    fn benchmark_token_phrase_literal_anchor_against_rust_regex() {
        use std::{env, hint::black_box, time::Instant};

        #[derive(Clone, Copy)]
        enum Backend<'a> {
            Fre(&'a TokenPhrasePlan),
            Rust(&'a regex::bytes::Regex),
        }

        fn env_usize(name: &str, default: usize) -> usize {
            env::var(name).map_or(default, |value| {
                value
                    .parse()
                    .unwrap_or_else(|error| panic!("invalid {name}={value:?}: {error}"))
            })
        }

        fn corpus(pattern: &[u8], bytes: usize, alignment: usize) -> Vec<u8> {
            assert!(!pattern.is_empty());
            let mut haystack = vec![0_u8; alignment];
            haystack.reserve(bytes);
            while haystack.len() - alignment < bytes {
                let remaining = bytes - (haystack.len() - alignment);
                let take = remaining.min(pattern.len());
                haystack.extend_from_slice(&pattern[..take]);
            }
            haystack
        }

        fn execute(backend: Backend<'_>, haystack: &[u8]) -> u64 {
            match backend {
                Backend::Fre(plan) => {
                    plan.count(haystack, ReduceLimits::unlimited())
                        .expect("FRE literal-anchor count")
                        .count
                }
                Backend::Rust(regex) => {
                    u64::try_from(regex.find_iter(haystack).count()).expect("regex count fits u64")
                }
            }
        }

        fn measure(backend: Backend<'_>, haystack: &[u8], iterations: usize) -> (u128, u64) {
            for _ in 0..8 {
                black_box(execute(backend, black_box(haystack)));
            }
            let started = Instant::now();
            let mut checksum = 0_u64;
            for _ in 0..iterations {
                checksum = checksum.wrapping_add(black_box(execute(backend, black_box(haystack))));
            }
            (started.elapsed().as_nanos(), checksum)
        }

        fn median(samples: &mut [u128]) -> u128 {
            samples.sort_unstable();
            samples[samples.len() / 2]
        }

        #[allow(
            clippy::too_many_arguments,
            reason = "each parseable benchmark column is passed explicitly at the single reporting boundary"
        )]
        fn report(
            workload: &str,
            backend: &str,
            haystack: &[u8],
            iterations: usize,
            median_total_ns: u128,
            checksum: u64,
            result: u64,
            accounting: Option<ReduceActualCounters>,
            variant: &str,
        ) {
            let iteration_count = u128::try_from(iterations).expect("iterations fit u128");
            let ns_per_iter = median_total_ns / iteration_count;
            let bytes_per_second = u128::try_from(haystack.len())
                .expect("length fits u128")
                .checked_mul(iteration_count)
                .and_then(|bytes| bytes.checked_mul(1_000_000_000))
                .expect("bounded benchmark rate")
                / median_total_ns.max(1);
            let actual = accounting.unwrap_or(ReduceActualCounters {
                route: Route::LiteralAnchors,
                source_reads: 0,
                work: 0,
                classifications: 0,
                literal_comparisons: 0,
                tokens: 0,
                finder_scan_bytes: 0,
                finder_calls: 0,
                anchor_candidates: 0,
                verification_reads: 0,
                matches: 0,
                count: result,
                span_sum: 0,
                scratch_bytes: 0,
            });
            println!(
                "fre-token-phrase-literal-anchor-v5,{workload},{backend},{},{},{iterations},{median_total_ns},{ns_per_iter},{bytes_per_second},{checksum},{result},{},{},{},{},{},{variant}",
                haystack.len(),
                haystack.as_ptr().addr() & 15,
                actual.source_reads,
                actual.work,
                actual.anchor_candidates,
                actual.finder_calls,
                actual.verification_reads,
            );
        }

        let bytes = env_usize("FRE_TOKEN_PHRASE_ANCHOR_BENCH_BYTES", 1 << 20);
        let iterations = env_usize("FRE_TOKEN_PHRASE_ANCHOR_BENCH_ITERS", 100);
        let samples = env_usize("FRE_TOKEN_PHRASE_ANCHOR_BENCH_SAMPLES", 7);
        let alignment = env_usize("FRE_TOKEN_PHRASE_ANCHOR_BENCH_ALIGNMENT", 0);
        assert!(
            bytes >= CANDIDATE_MIN_INPUT_BYTES
                && iterations > 0
                && samples > 0
                && alignment < ASCII_NARROW_BYTES
        );

        let plan = plan(b"Holmes", true);
        let regex = RegexBuilder::new(r"\b\w+\s+Holmes\s+\w+\b")
            .unicode(false)
            .build()
            .expect("pinned Rust regex");
        let workloads = [
            (
                "long_tokens",
                corpus(
                    b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa Holmes \t bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb--",
                    bytes,
                    alignment,
                ),
            ),
            (
                "short_tokens",
                corpus(b"a Holmes b-", bytes, alignment),
            ),
            (
                "literal_mismatch",
                corpus(
                    b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa Xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb--",
                    bytes,
                    alignment,
                ),
            ),
        ];
        println!(
            "schema,workload,backend,haystack_bytes,alignment_mod16,iterations,median_total_ns,ns_per_iter,bytes_per_second,checksum,result,source_reads,work,anchor_candidates,finder_calls,verification_reads,variant"
        );

        for (workload, storage) in workloads {
            let haystack = &storage[alignment..];
            let fre_result = plan
                .count(haystack, ReduceLimits::unlimited())
                .expect("FRE qualification result");
            assert_eq!(fre_result.accounting.actual.route, Route::LiteralAnchors);
            let rust_result = execute(Backend::Rust(&regex), haystack);
            assert_eq!(fre_result.count, rust_result);

            let mut fre_samples = Vec::with_capacity(samples);
            let mut rust_samples = Vec::with_capacity(samples);
            let mut fre_checksum = 0_u64;
            let mut rust_checksum = 0_u64;
            for sample in 0..samples {
                let (first, second) = if sample % 2 == 0 {
                    (Backend::Fre(&plan), Backend::Rust(&regex))
                } else {
                    (Backend::Rust(&regex), Backend::Fre(&plan))
                };
                let measured = measure(first, haystack, iterations);
                match first {
                    Backend::Fre(_) => {
                        fre_samples.push(measured.0);
                        fre_checksum = measured.1;
                    }
                    Backend::Rust(_) => {
                        rust_samples.push(measured.0);
                        rust_checksum = measured.1;
                    }
                }
                let measured = measure(second, haystack, iterations);
                match second {
                    Backend::Fre(_) => {
                        fre_samples.push(measured.0);
                        fre_checksum = measured.1;
                    }
                    Backend::Rust(_) => {
                        rust_samples.push(measured.0);
                        rust_checksum = measured.1;
                    }
                }
            }
            assert_eq!(fre_checksum, rust_checksum);
            report(
                workload,
                "fre-literal-anchor",
                haystack,
                iterations,
                median(&mut fre_samples),
                fre_checksum,
                fre_result.count,
                Some(fre_result.accounting.actual),
                "memchr-2.8.3-owned-forward-finder",
            );
            report(
                workload,
                "rust-regex",
                haystack,
                iterations,
                median(&mut rust_samples),
                rust_checksum,
                rust_result,
                None,
                "regex-bytes-1.12.4",
            );
        }
    }

    fn exact_limits(upper: ReduceUpperBounds) -> ReduceLimits {
        ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_work: upper.work,
            max_classifications: upper.classifications,
            max_literal_comparisons: upper.literal_comparisons,
            max_token_events: upper.token_events,
            max_finder_scan_bytes: upper.finder_scan_bytes,
            max_finder_calls: upper.finder_calls,
            max_anchor_candidates: upper.anchor_candidates,
            max_verification_reads: upper.verification_reads,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }
}
