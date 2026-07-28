//! Sparse whole-operation reduction for `W+ S+ L S+ W+`.
//!
//! Admission proves byte-mode complete ASCII word and whitespace classes,
//! greedy nonempty repetitions, and one nonempty all-word literal. This owner
//! retains an owned [`memchr::memmem::Finder`] for that literal and traverses
//! its non-overlapping occurrence stream once. An occurrence can be semantic
//! only when the literal is a complete maximal word token, so immediate ASCII
//! space borders reject every occurrence hidden inside a larger word token.
//! Existing generic forward/backward ASCII run scanners then recover the four
//! adjacent maximal runs without classifying unrelated source bytes.
//!
//! Literal occurrences are monotone, but successive phrases can overlap in the
//! intervening word token: `a Holmes b Holmes c` must produce only the first
//! match. A semantic restart floor therefore rejects any later candidate whose
//! recovered left word starts before the previous match end.
//!
//! Finder accounting uses its conservative `needle bytes + haystack bytes`
//! linear contract. Run accounting uses the exact physical examination count
//! returned by each selected scanner leaf, including any failed-block recovery.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all resource and index arithmetic is checked before it affects execution"
)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::CopyError;
use fre_simd_kernels::{
    ASCII_NARROW_BYTES, ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD, AsciiByteSet, AsciiByteSetRunScanner,
};
use memchr::memmem::{Finder, FinderBuilder};

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError};

pub const PLAN_ID: &str = "token-phrase.literal-anchored-maximal-ascii-runs.v2";
pub const COUNT_OPERATION_ID: &str = "token-phrase.count.unicode-off.v2";
pub const SPAN_SUM_OPERATION_ID: &str = "token-phrase.span-sum.unicode-off.v2";

const FIXED_BUILD_WORK: usize = 8;
const LITERAL_BUILD_WORK_PER_BYTE: usize = 2;
const RUN_SCANNER_BUILD_WORK: usize = 128 + 1 + 1;
const RUN_SCANNERS: usize = 2;
const FIXED_REDUCE_WORK: usize = 8;
const CLASSIFICATION_WORK: usize = 2;
const FINDER_TERM_WORK: usize = 1;
const CANDIDATE_WORK: usize = 3;
const MATCH_WORK: usize = 4;
const MINIMUM_NON_LITERAL_BYTES: usize = 4;

const ASCII_WORD_SET: AsciiByteSet =
    AsciiByteSet::from_words([0x03ff_0000_0000_0000, 0x07ff_fffe_87ff_fffe]);
const ASCII_SPACE_SET: AsciiByteSet = AsciiByteSet::from_words([0x0000_0001_0000_3e00, 0]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Topology {
    WordSpaceLiteralSpaceWord,
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
            max_build_work: 16 * 1024 * 1024,
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
    pub input_bytes: usize,
    /// Conservative Finder linear terms plus physical run classifications.
    pub source_reads: usize,
    pub work: usize,
    /// Direct border probes plus exact physical scanner examinations.
    pub classifications: usize,
    /// Conservative `haystack + literal` Finder service terms.
    pub literal_comparisons: usize,
    /// Maximum non-overlapping literal occurrences visited as candidates.
    pub token_events: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    /// Conservative Finder service plus exact physical run/border reads.
    pub source_reads: usize,
    pub work: usize,
    /// Exact border probes and scanner-reported physical examinations.
    pub classifications: usize,
    /// Exact conservative Finder linear-service charge for this invocation.
    pub literal_comparisons: usize,
    /// Literal occurrences returned by the retained non-overlapping iterator.
    pub tokens: usize,
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
    word_scanner: AsciiByteSetRunScanner,
    space_scanner: AsciiByteSetRunScanner,
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

    /// Build while retaining exact successful or partial terminal effects.
    #[allow(
        clippy::too_many_lines,
        reason = "the construction transaction keeps proof validation, exact literal allocation, scanner initialization, and partial effects in one auditable boundary"
    )]
    pub fn build_attempt(
        literal: &[u8],
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
            let scanner_work = RUN_SCANNER_BUILD_WORK.checked_mul(RUN_SCANNERS).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "run-scanner build work",
                },
            )?;
            let work_upper_bound = literal
                .len()
                .checked_mul(LITERAL_BUILD_WORK_PER_BYTE)
                .and_then(|work| work.checked_add(FIXED_BUILD_WORK))
                .and_then(|work| work.checked_add(scanner_work))
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
                actual.work = actual
                    .work
                    .checked_add(u64::try_from(LITERAL_BUILD_WORK_PER_BYTE).map_err(|_| {
                        BuildError::ArithmeticOverflow {
                            computation: "literal byte build work conversion",
                        }
                    })?)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "literal byte build work",
                    })?;
                if !is_ascii_word(byte) {
                    return Err(BuildError::NonWordLiteral { byte });
                }
            }

            let owned = fre_exact_alloc::copy_exact(literal)
                .map(Vec::into_boxed_slice)
                .map_err(|error| match error {
                    CopyError::LayoutOverflow => BuildError::ArithmeticOverflow {
                        computation: "exact literal allocation layout",
                    },
                    CopyError::AllocationFailed => BuildError::AllocationFailed {
                        bytes: literal.len(),
                    },
                })?;
            let finder = FinderBuilder::new().build_forward_owned(owned);
            let word_scanner = AsciiByteSetRunScanner::new(ASCII_WORD_SET);
            let space_scanner = AsciiByteSetRunScanner::new(ASCII_SPACE_SET);
            actual.work = actual
                .work
                .checked_add(u64::try_from(scanner_work).map_err(|_| {
                    BuildError::ArithmeticOverflow {
                        computation: "run-scanner build work conversion",
                    }
                })?)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "complete actual build work",
                })?;
            debug_assert_eq!(usize::try_from(actual.work), Ok(work_upper_bound));
            actual.allocations = 1;
            actual.allocated_bytes = literal.len();
            actual.copied_bytes = literal.len();
            actual.initialized_bytes = persistent_bytes;
            actual.live_persistent_bytes = persistent_bytes;
            actual.peak_bytes = persistent_bytes;
            Ok(Self {
                finder,
                word_scanner,
                space_scanner,
                outer_word_assertions,
                build: BuildAccounting {
                    literal_bytes: literal.len(),
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

    const fn identity(&self, operation_id: &'static str) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id,
            literal_bytes: self.build.literal_bytes,
            topology: Topology::WordSpaceLiteralSpaceWord,
            outer_word_assertions: self.outer_word_assertions,
            unicode: false,
            greedy: true,
            maximal_tokens: true,
            non_overlapping: true,
        }
    }

    pub fn count(&self, haystack: &[u8], limits: ReduceLimits) -> Result<CountResult, ReduceError> {
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

    pub fn span_sum(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult, ReduceError> {
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
        reason = "the source-free derivation keeps each Finder, run, result, and retained-byte bound adjacent"
    )]
    fn derive_upper_bounds(
        &self,
        input_bytes: usize,
        operation: Operation,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let literal_bytes = self.finder.needle().len();
        let literal_comparisons =
            input_bytes
                .checked_add(literal_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "Finder linear service terms",
                })?;
        let token_events =
            input_bytes
                .checked_div(literal_bytes)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "literal candidate divisor",
                })?;

        // A candidate that reaches the run scanners is an exact literal token
        // with at least one space on each side. Adjacent such tokens can share
        // one separating space, hence at most (N - 1) / (L + 1).
        let bordered_minimum =
            literal_bytes
                .checked_add(2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bordered literal minimum width",
                })?;
        let bordered_stride =
            literal_bytes
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bordered literal minimum stride",
                })?;
        let bordered_candidates = if input_bytes < bordered_minimum {
            0
        } else {
            input_bytes
                .checked_sub(1)
                .and_then(|remaining| remaining.checked_div(bordered_stride))
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "bordered literal candidate bound",
                })?
        };

        // Across monotone exact-token candidates, every member byte can occur
        // in at most two adjacent run confirmations. Each candidate has two
        // direct border probes and at most four scanner calls; every scanner
        // call contributes one logical terminating probe and at most the
        // generic scanner continuation's fixed failed-block recovery overhead.
        let classifications = input_bytes
            .checked_mul(2)
            .and_then(|value| {
                token_events
                    .checked_mul(2)
                    .and_then(|probes| value.checked_add(probes))
            })
            .and_then(|value| {
                ASCII_RUN_MAX_CLASSIFICATION_OVERHEAD
                    .checked_add(1)
                    .and_then(|per_run| per_run.checked_mul(4))
                    .and_then(|per_candidate| per_candidate.checked_mul(bordered_candidates))
                    .and_then(|runs| value.checked_add(runs))
            })
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete physical classification bound",
            })?;
        let source_reads = literal_comparisons.checked_add(classifications).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "Finder and run source-read bound",
            },
        )?;
        let minimum_match_bytes = literal_bytes.checked_add(MINIMUM_NON_LITERAL_BYTES).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "minimum token-phrase match width",
            },
        )?;
        let match_events = input_bytes.checked_div(minimum_match_bytes).ok_or(
            ReduceError::ArithmeticOverflow {
                computation: "match-event bound divisor",
            },
        )?;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "match-event bound as count",
        })?;
        let span_sum = match operation {
            Operation::Count => 0,
            Operation::SpanSum => {
                u64::try_from(input_bytes).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "input bytes as span-sum bound",
                })?
            }
        };
        let work = classifications
            .checked_mul(CLASSIFICATION_WORK)
            .and_then(|value| {
                literal_comparisons
                    .checked_mul(FINDER_TERM_WORK)
                    .and_then(|finder| value.checked_add(finder))
            })
            .and_then(|value| {
                token_events
                    .checked_mul(CANDIDATE_WORK)
                    .and_then(|candidates| value.checked_add(candidates))
            })
            .and_then(|value| {
                match_events
                    .checked_mul(MATCH_WORK)
                    .and_then(|matches| value.checked_add(matches))
            })
            .and_then(|value| value.checked_add(FIXED_REDUCE_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete reduction work bound",
            })?;
        let scratch_bytes = 0;
        let persistent_bytes = self.build.persistent_bytes;
        let peak_bytes = persistent_bytes;
        Ok(ReduceUpperBounds {
            input_bytes,
            source_reads,
            work,
            classifications,
            literal_comparisons,
            token_events,
            match_events,
            count,
            span_sum,
            scratch_bytes,
            persistent_bytes,
            peak_bytes,
        })
    }

    fn scan(
        &self,
        haystack: &[u8],
        operation: Operation,
        upper: ReduceUpperBounds,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let finder_terms = upper.literal_comparisons;
        let finder_work =
            finder_terms
                .checked_mul(FINDER_TERM_WORK)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual Finder service work",
                })?;
        let mut actual = ReduceActualCounters {
            source_reads: finder_terms,
            work: FIXED_REDUCE_WORK.checked_add(finder_work).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "initial reduction work",
                },
            )?,
            classifications: 0,
            literal_comparisons: finder_terms,
            tokens: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            scratch_bytes: 0,
        };
        let literal_bytes = self.finder.needle().len();
        let mut restart = 0_usize;

        for anchor_start in self.finder.find_iter(haystack) {
            charge_candidate(&mut actual)?;
            let anchor_end =
                anchor_start
                    .checked_add(literal_bytes)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "literal anchor end",
                    })?;
            if !has_space_borders(haystack, anchor_start, anchor_end, &mut actual)? {
                continue;
            }

            let Some(left_space_start) = scan_backward(
                &self.space_scanner,
                haystack,
                anchor_start,
                &mut actual,
                "left space run",
            )?
            else {
                continue;
            };
            let Some(match_start) = scan_backward(
                &self.word_scanner,
                haystack,
                left_space_start,
                &mut actual,
                "left word run",
            )?
            else {
                continue;
            };
            if match_start < restart {
                continue;
            }

            let Some(right_space_end) = scan_forward(
                &self.space_scanner,
                haystack,
                anchor_end,
                &mut actual,
                "right space run",
            )?
            else {
                continue;
            };
            let Some(match_end) = scan_forward(
                &self.word_scanner,
                haystack,
                right_space_end,
                &mut actual,
                "right word run",
            )?
            else {
                continue;
            };
            record_match(&mut actual, operation, match_start, match_end)?;
            restart = match_end;
        }

        verify_actual(actual, upper)?;
        Ok(actual)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Count,
    SpanSum,
}

const fn is_ascii_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn has_space_borders(
    haystack: &[u8],
    start: usize,
    end: usize,
    actual: &mut ReduceActualCounters,
) -> Result<bool, ReduceError> {
    if start == 0 || end == haystack.len() {
        return Ok(false);
    }
    let previous = start
        .checked_sub(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "literal predecessor",
        })?;
    let left = read_classified(haystack, previous, actual)?;
    if !ASCII_SPACE_SET.contains(left) {
        return Ok(false);
    }
    let right = read_classified(haystack, end, actual)?;
    Ok(ASCII_SPACE_SET.contains(right))
}

fn scan_backward(
    scanner: &AsciiByteSetRunScanner,
    haystack: &[u8],
    end: usize,
    actual: &mut ReduceActualCounters,
    computation: &'static str,
) -> Result<Option<usize>, ReduceError> {
    let source = haystack
        .get(..end)
        .ok_or(ReduceError::ArithmeticOverflow { computation })?;
    let mut scalar_run = 0_usize;
    for &byte in source.iter().rev().take(ASCII_NARROW_BYTES) {
        charge_classifications(actual, 1)?;
        if !scanner.set().contains(byte) {
            return end
                .checked_sub(scalar_run)
                .map(|start| (scalar_run != 0).then_some(start))
                .ok_or(ReduceError::ArithmeticOverflow { computation });
        }
        scalar_run = scalar_run
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow { computation })?;
    }
    if scalar_run == source.len() {
        return end
            .checked_sub(scalar_run)
            .map(|start| (scalar_run != 0).then_some(start))
            .ok_or(ReduceError::ArithmeticOverflow { computation });
    }
    let continuation_end = end
        .checked_sub(scalar_run)
        .ok_or(ReduceError::ArithmeticOverflow { computation })?;
    let continuation = haystack
        .get(..continuation_end)
        .ok_or(ReduceError::ArithmeticOverflow { computation })?;
    let result = scanner.scan_backward(continuation);
    charge_classifications(actual, result.examined_bytes())?;
    let run = scalar_run
        .checked_add(result.member_run_len())
        .ok_or(ReduceError::ArithmeticOverflow { computation })?;
    end.checked_sub(run)
        .map(Some)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
}

fn scan_forward(
    scanner: &AsciiByteSetRunScanner,
    haystack: &[u8],
    start: usize,
    actual: &mut ReduceActualCounters,
    computation: &'static str,
) -> Result<Option<usize>, ReduceError> {
    let source = haystack
        .get(start..)
        .ok_or(ReduceError::ArithmeticOverflow { computation })?;
    let mut scalar_run = 0_usize;
    for &byte in source.iter().take(ASCII_NARROW_BYTES) {
        charge_classifications(actual, 1)?;
        if !scanner.set().contains(byte) {
            return start
                .checked_add(scalar_run)
                .map(|end| (scalar_run != 0).then_some(end))
                .ok_or(ReduceError::ArithmeticOverflow { computation });
        }
        scalar_run = scalar_run
            .checked_add(1)
            .ok_or(ReduceError::ArithmeticOverflow { computation })?;
    }
    if scalar_run == source.len() {
        return start
            .checked_add(scalar_run)
            .map(|end| (scalar_run != 0).then_some(end))
            .ok_or(ReduceError::ArithmeticOverflow { computation });
    }
    let continuation_start = start
        .checked_add(scalar_run)
        .ok_or(ReduceError::ArithmeticOverflow { computation })?;
    let continuation = haystack
        .get(continuation_start..)
        .ok_or(ReduceError::ArithmeticOverflow { computation })?;
    let result = scanner.scan_forward(continuation);
    charge_classifications(actual, result.examined_bytes())?;
    let run = scalar_run
        .checked_add(result.member_run_len())
        .ok_or(ReduceError::ArithmeticOverflow { computation })?;
    start
        .checked_add(run)
        .map(Some)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
}

fn read_classified(
    haystack: &[u8],
    position: usize,
    actual: &mut ReduceActualCounters,
) -> Result<u8, ReduceError> {
    charge_classifications(actual, 1)?;
    haystack
        .get(position)
        .copied()
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "classified border byte",
        })
}

fn charge_classifications(
    actual: &mut ReduceActualCounters,
    count: usize,
) -> Result<(), ReduceError> {
    actual.source_reads = checked_add(actual.source_reads, count, "classification source reads")?;
    actual.classifications = checked_add(actual.classifications, count, "classifications")?;
    let work = count
        .checked_mul(CLASSIFICATION_WORK)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "classification block work",
        })?;
    actual.work = checked_add(actual.work, work, "classification work")?;
    Ok(())
}

fn charge_candidate(actual: &mut ReduceActualCounters) -> Result<(), ReduceError> {
    actual.tokens = checked_add(actual.tokens, 1, "literal candidate events")?;
    actual.work = checked_add(actual.work, CANDIDATE_WORK, "literal candidate work")?;
    Ok(())
}

fn record_match(
    actual: &mut ReduceActualCounters,
    operation: Operation,
    start: usize,
    end: usize,
) -> Result<(), ReduceError> {
    actual.matches = checked_add(actual.matches, 1, "match events")?;
    actual.count = actual
        .count
        .checked_add(1)
        .ok_or(ReduceError::ArithmeticOverflow {
            computation: "actual count",
        })?;
    if operation == Operation::SpanSum {
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
    verify("source reads", actual.source_reads, upper.source_reads)?;
    verify("work", actual.work, upper.work)?;
    verify(
        "classifications",
        actual.classifications,
        upper.classifications,
    )?;
    verify(
        "Finder linear terms",
        actual.literal_comparisons,
        upper.literal_comparisons,
    )?;
    verify("literal candidates", actual.tokens, upper.token_events)?;
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
    fn dense_bordered_literal_occurrences_do_not_hide_exact_token_candidates() {
        let mut haystack = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaa-".to_vec();
        haystack.extend_from_slice(b"left aaa right");
        haystack.extend_from_slice(b"-aaaaaaaaaaaaaaaaaaaaaaaaaaaaa-");
        haystack.extend_from_slice(b"x aaa y aaa z");
        haystack.extend_from_slice(b"-aaaaaaaaaaaaaaaaaaaaaaaaaaaa");
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
            assert!(
                count.accounting.actual.tokens
                    > usize::try_from(count.count).expect("test count fits usize")
            );
            assert!(count.accounting.actual.tokens <= count.accounting.upper_bounds.token_events);
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
    fn retained_finder_and_run_accounting_is_exact_and_conservative() {
        let plan = plan(b"Holmes", true);
        assert_eq!(plan.finder.needle(), b"Holmes");
        assert_eq!(plan.word_scanner.set(), ASCII_WORD_SET);
        assert_eq!(plan.space_scanner.set(), ASCII_SPACE_SET);
        assert_eq!(
            plan.word_scanner.selection().policy,
            fre_simd_kernels::DispatchPolicy::Auto
        );
        assert_eq!(
            plan.space_scanner.selection().policy,
            fre_simd_kernels::DispatchPolicy::Auto
        );

        let haystack = b"noise noise--Sherlock  Holmes \t watson--a Holmes b Holmes c--notHolmes";
        let count = plan
            .count(haystack, ReduceLimits::unlimited())
            .expect("sparse count");
        let spans = plan
            .span_sum(haystack, ReduceLimits::unlimited())
            .expect("sparse span sum");
        let actual = count.accounting.actual;
        let finder_terms = haystack.len() + plan.finder.needle().len();
        assert_eq!(actual.literal_comparisons, finder_terms);
        assert_eq!(actual.source_reads, finder_terms + actual.classifications);
        assert_eq!(
            actual.work,
            FIXED_REDUCE_WORK
                + finder_terms * FINDER_TERM_WORK
                + actual.classifications * CLASSIFICATION_WORK
                + actual.tokens * CANDIDATE_WORK
                + actual.matches * MATCH_WORK
        );
        assert_eq!(
            actual.count,
            u64::try_from(actual.matches).expect("test match count fits u64")
        );
        assert_eq!(spans.accounting.actual.source_reads, actual.source_reads);
        assert_eq!(spans.accounting.actual.work, actual.work);
        assert!(count.accounting.upper_bounds.classifications < haystack.len() * 16);
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
            .expect("every exact sparse limit succeeds");
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
            u64::try_from(FIXED_BUILD_WORK + 3 * LITERAL_BUILD_WORK_PER_BYTE).unwrap()
        );
        assert_eq!(error.actual().allocations, 0);
        assert_eq!(error.actual().allocated_bytes, 0);
        assert_eq!(error.actual().copied_bytes, 0);
        assert_eq!(error.actual().initialized_bytes, 0);
        assert_eq!(error.actual().live_persistent_bytes, 0);
        assert_eq!(error.actual().peak_bytes, 0);
    }

    fn exact_limits(upper: ReduceUpperBounds) -> ReduceLimits {
        ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_source_reads: upper.source_reads,
            max_work: upper.work,
            max_classifications: upper.classifications,
            max_literal_comparisons: upper.literal_comparisons,
            max_token_events: upper.token_events,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: upper.span_sum,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        }
    }
}
