//! Whole-operation reduction for `W+ S+ L S+ W+`.
//!
//! Admission proves byte-mode ASCII word and whitespace classes, greedy
//! nonempty repetitions, and a nonempty all-word literal. Those disjoint
//! classes make every repetition a maximal token. One monotone byte
//! classification stream can therefore recognize the five-token phrase
//! directly while preserving leftmost-first, greedy, non-overlapping Rust
//! semantics. Optional outer ASCII word-boundary assertions are redundant at
//! the proved maximal word-token edges but remain part of the published
//! operation identity.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all resource and index arithmetic is checked before it affects execution"
)]

use core::{fmt, mem::size_of};

use fre_exact_alloc::CopyError;
use fre_simd_kernels::{ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, AsciiWordSpaceClassifier};

use crate::{DirectBuildAttempt, DirectBuildAttemptActual, DirectBuildAttemptError};

pub const PLAN_ID: &str = "token-phrase.maximal-ascii-token-stream.v1";
pub const COUNT_OPERATION_ID: &str = "token-phrase.count.unicode-off.v1";
pub const SPAN_SUM_OPERATION_ID: &str = "token-phrase.span-sum.unicode-off.v1";

const FIXED_BUILD_WORK: usize = 8;
const LITERAL_BUILD_WORK_PER_BYTE: usize = 2;
const FIXED_REDUCE_WORK: usize = 8;
const CLASSIFICATION_WORK: usize = 2;
const LITERAL_COMPARISON_WORK: usize = 1;
const TOKEN_EVENT_WORK: usize = 3;
const MATCH_WORK: usize = 4;
const MINIMUM_NON_LITERAL_BYTES: usize = 4;

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
    pub source_reads: usize,
    pub work: usize,
    pub classifications: usize,
    pub literal_comparisons: usize,
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
    pub source_reads: usize,
    pub work: usize,
    pub classifications: usize,
    pub literal_comparisons: usize,
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
    literal: Box<[u8]>,
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
            let work_upper_bound = literal
                .len()
                .checked_mul(LITERAL_BUILD_WORK_PER_BYTE)
                .and_then(|work| work.checked_add(FIXED_BUILD_WORK))
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
            debug_assert_eq!(usize::try_from(actual.work), Ok(work_upper_bound));
            actual.allocations = 1;
            actual.allocated_bytes = literal.len();
            actual.copied_bytes = literal.len();
            actual.initialized_bytes = persistent_bytes;
            actual.live_persistent_bytes = persistent_bytes;
            actual.peak_bytes = persistent_bytes;
            Ok(Self {
                literal,
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
        let upper = self.preflight(
            haystack.len(),
            Operation::Count,
            ScanImplementation::IncumbentScalar,
            limits,
        )?;
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
        let upper = self.preflight(
            haystack.len(),
            Operation::SpanSum,
            ScanImplementation::IncumbentScalar,
            limits,
        )?;
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

    /// Count through the explicit retained fixed-block classifier.
    ///
    /// This does not alter [`Self::count`] or automatic production routing.
    /// The supplied handle carries its own immutable dispatch receipt.
    pub fn count_with_block_classifier_experimental(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
        classifier: &AsciiWordSpaceClassifier,
    ) -> Result<CountResult, ReduceError> {
        let upper = self.preflight(
            haystack.len(),
            Operation::Count,
            ScanImplementation::BlockClassifier,
            limits,
        )?;
        let actual =
            self.scan_with_block_classifier(haystack, Operation::Count, upper, classifier)?;
        Ok(CountResult {
            count: actual.count,
            accounting: ReduceAccounting {
                identity: self.count_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    /// Sum matched spans through the explicit retained fixed-block classifier.
    ///
    /// See [`Self::count_with_block_classifier_experimental`] for routing and
    /// dispatch guarantees.
    pub fn span_sum_with_block_classifier_experimental(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
        classifier: &AsciiWordSpaceClassifier,
    ) -> Result<SpanSumResult, ReduceError> {
        let upper = self.preflight(
            haystack.len(),
            Operation::SpanSum,
            ScanImplementation::BlockClassifier,
            limits,
        )?;
        let actual =
            self.scan_with_block_classifier(haystack, Operation::SpanSum, upper, classifier)?;
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
        implementation: ScanImplementation,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let upper = self.derive_upper_bounds(input_bytes, operation, implementation)?;
        enforce_upper_bounds(upper, limits)?;
        Ok(upper)
    }

    fn derive_upper_bounds(
        &self,
        input_bytes: usize,
        operation: Operation,
        implementation: ScanImplementation,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let classifications = input_bytes;
        let literal_comparisons = input_bytes;
        let source_reads = match implementation {
            ScanImplementation::IncumbentScalar => classifications,
            ScanImplementation::BlockClassifier => classifications
                .checked_add(literal_comparisons)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "block-classifier source-read bound",
                })?,
        };
        let token_events = input_bytes;
        let minimum_match_bytes = self
            .literal
            .len()
            .checked_add(MINIMUM_NON_LITERAL_BYTES)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "minimum token-phrase match width",
            })?;
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
        let mut actual = ReduceActualCounters {
            source_reads: 0,
            work: FIXED_REDUCE_WORK,
            classifications: 0,
            literal_comparisons: 0,
            tokens: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            scratch_bytes: 0,
        };
        let mut state = PhraseState::SeekingWord;
        let mut token_kind = None;
        let mut token_start = 0_usize;
        let mut word_offset = 0_usize;
        let mut literal_equal = true;

        for (position, &byte) in haystack.iter().enumerate() {
            charge_classification(&mut actual)?;
            let kind = classify(byte);
            if token_kind.is_some_and(|current| current != kind) {
                let current = token_kind.ok_or(ReduceError::ArithmeticOverflow {
                    computation: "current token kind",
                })?;
                self.consume_token(
                    Token {
                        kind: current,
                        start: token_start,
                        end: position,
                        literal_equal,
                    },
                    operation,
                    &mut state,
                    &mut actual,
                )?;
                token_start = position;
                word_offset = 0;
                literal_equal = true;
            }
            token_kind = Some(kind);
            if kind == TokenKind::Word {
                charge_literal_comparison(&mut actual)?;
                literal_equal &= self
                    .literal
                    .get(word_offset)
                    .is_some_and(|&expected| expected == byte);
                word_offset =
                    word_offset
                        .checked_add(1)
                        .ok_or(ReduceError::ArithmeticOverflow {
                            computation: "word-token byte offset",
                        })?;
            }
        }
        if let Some(kind) = token_kind {
            self.consume_token(
                Token {
                    kind,
                    start: token_start,
                    end: haystack.len(),
                    literal_equal,
                },
                operation,
                &mut state,
                &mut actual,
            )?;
        }
        actual.source_reads = actual.classifications;
        verify_actual(actual, upper)?;
        Ok(actual)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fixed 32/16/tail schedule and its exact physical accounting remain together for review"
    )]
    fn scan_with_block_classifier(
        &self,
        haystack: &[u8],
        operation: Operation,
        upper: ReduceUpperBounds,
        classifier: &AsciiWordSpaceClassifier,
    ) -> Result<ReduceActualCounters, ReduceError> {
        let mut actual = ReduceActualCounters {
            source_reads: 0,
            work: FIXED_REDUCE_WORK,
            classifications: 0,
            literal_comparisons: 0,
            tokens: 0,
            matches: 0,
            count: 0,
            span_sum: 0,
            scratch_bytes: 0,
        };
        let mut stream = TokenStreamState::new();
        let mut position = 0_usize;

        while haystack.len() - position >= ASCII_WIDE_BYTES {
            let end =
                position
                    .checked_add(ASCII_WIDE_BYTES)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "wide block end",
                    })?;
            let block: &[u8; ASCII_WIDE_BYTES] = haystack[position..end]
                .try_into()
                .expect("the wide block extent was checked");
            let masks = classifier.classify_32(block);
            self.consume_classified_block(
                block,
                position,
                masks.word_mask(),
                masks.space_mask(),
                operation,
                &mut stream,
                &mut actual,
            )?;
            position = end;
        }

        if haystack.len() - position >= ASCII_NARROW_BYTES {
            let end = position.checked_add(ASCII_NARROW_BYTES).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "narrow block end",
                },
            )?;
            let block: &[u8; ASCII_NARROW_BYTES] = haystack[position..end]
                .try_into()
                .expect("the narrow block extent was checked");
            let masks = classifier.classify_16(block);
            self.consume_classified_block(
                block,
                position,
                u32::from(masks.word_mask()),
                u32::from(masks.space_mask()),
                operation,
                &mut stream,
                &mut actual,
            )?;
            position = end;
        }

        if position < haystack.len() {
            let tail = &haystack[position..];
            let mut words = 0_u32;
            let mut spaces = 0_u32;
            for (lane, &byte) in tail.iter().enumerate() {
                let bit = 1_u32
                    .checked_shl(u32::try_from(lane).map_err(|_| {
                        ReduceError::ArithmeticOverflow {
                            computation: "tail lane as u32",
                        }
                    })?)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "tail lane bit",
                    })?;
                match classify(byte) {
                    TokenKind::Word => words |= bit,
                    TokenKind::Space => spaces |= bit,
                    TokenKind::Other => {}
                }
            }
            self.consume_classified_block(
                tail,
                position,
                words,
                spaces,
                operation,
                &mut stream,
                &mut actual,
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
            )?;
        }
        verify_actual(actual, upper)?;
        Ok(actual)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the explicit block boundary keeps source extent, masks, reducer state, and exact counters visibly coupled"
    )]
    fn consume_classified_block(
        &self,
        bytes: &[u8],
        block_start: usize,
        words: u32,
        spaces: u32,
        operation: Operation,
        stream: &mut TokenStreamState,
        actual: &mut ReduceActualCounters,
    ) -> Result<(), ReduceError> {
        debug_assert!(bytes.len() <= ASCII_WIDE_BYTES);
        let valid = low_mask(bytes.len())?;
        if words & spaces != 0 || (words | spaces) & !valid != 0 {
            return Err(ReduceError::AccountingInvariant {
                resource: "block class masks",
                actual: u64::from((words | spaces) & !valid),
                upper: 0,
            });
        }
        charge_classifications(actual, bytes.len())?;

        let others = valid & !(words | spaces);
        let mut lane = 0_usize;
        while lane < bytes.len() {
            let lane_shift = u32::try_from(lane).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "classified lane as u32",
            })?;
            let bit = 1_u32
                .checked_shl(lane_shift)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "classified lane bit",
                })?;
            let (kind, mask) = if words & bit != 0 {
                (TokenKind::Word, words)
            } else if spaces & bit != 0 {
                (TokenKind::Space, spaces)
            } else {
                (TokenKind::Other, others)
            };
            let run_len = usize::try_from((mask >> lane_shift).trailing_ones())
                .map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "classified run length",
                })?
                .min(bytes.len() - lane);
            if run_len == 0 {
                return Err(ReduceError::AccountingInvariant {
                    resource: "classified run progress",
                    actual: 0,
                    upper: 1,
                });
            }
            let position =
                block_start
                    .checked_add(lane)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "classified token position",
                    })?;
            if stream.token_kind.is_some_and(|current| current != kind) {
                let current = stream.token_kind.ok_or(ReduceError::ArithmeticOverflow {
                    computation: "classified current token kind",
                })?;
                self.consume_token(
                    Token {
                        kind: current,
                        start: stream.token_start,
                        end: position,
                        literal_equal: stream.literal_equal,
                    },
                    operation,
                    &mut stream.phrase,
                    actual,
                )?;
                stream.token_start = position;
                stream.word_offset = 0;
                stream.literal_equal = true;
            }
            stream.token_kind = Some(kind);
            if kind == TokenKind::Word {
                let end = lane
                    .checked_add(run_len)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "classified word-run end",
                    })?;
                self.compare_word_segment(&bytes[lane..end], stream, actual)?;
            }
            lane = lane
                .checked_add(run_len)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "classified lane advance",
                })?;
        }
        Ok(())
    }

    fn compare_word_segment(
        &self,
        bytes: &[u8],
        stream: &mut TokenStreamState,
        actual: &mut ReduceActualCounters,
    ) -> Result<(), ReduceError> {
        for (relative, &byte) in bytes.iter().enumerate() {
            if !stream.literal_equal {
                break;
            }
            charge_literal_comparison(actual)?;
            actual.source_reads = checked_add(actual.source_reads, 1, "literal source reads")?;
            let offset = stream.word_offset.checked_add(relative).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "block word-token byte offset",
                },
            )?;
            stream.literal_equal &= self
                .literal
                .get(offset)
                .is_some_and(|&expected| expected == byte);
        }
        stream.word_offset =
            stream
                .word_offset
                .checked_add(bytes.len())
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "block word-token byte advance",
                })?;
        Ok(())
    }

    fn consume_token(
        &self,
        token: Token,
        operation: Operation,
        state: &mut PhraseState,
        actual: &mut ReduceActualCounters,
    ) -> Result<(), ReduceError> {
        charge_token(actual)?;
        let exact_literal = token.literal_equal
            && token
                .end
                .checked_sub(token.start)
                .is_some_and(|width| width == self.literal.len());
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
                record_match(actual, operation, start, token.end)?;
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanImplementation {
    IncumbentScalar,
    BlockClassifier,
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
    word_offset: usize,
    literal_equal: bool,
}

impl TokenStreamState {
    const fn new() -> Self {
        Self {
            phrase: PhraseState::SeekingWord,
            token_kind: None,
            token_start: 0,
            word_offset: 0,
            literal_equal: true,
        }
    }
}

const fn classify(byte: u8) -> TokenKind {
    if is_ascii_word(byte) {
        TokenKind::Word
    } else if is_ascii_space(byte) {
        TokenKind::Space
    } else {
        TokenKind::Other
    }
}

const fn is_ascii_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

const fn is_ascii_space(byte: u8) -> bool {
    matches!(byte, b'\t'..=b'\r' | b' ')
}

fn charge_classification(actual: &mut ReduceActualCounters) -> Result<(), ReduceError> {
    charge_classifications(actual, 1)
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

fn charge_literal_comparison(actual: &mut ReduceActualCounters) -> Result<(), ReduceError> {
    actual.literal_comparisons = checked_add(actual.literal_comparisons, 1, "literal comparisons")?;
    actual.work = checked_add(
        actual.work,
        LITERAL_COMPARISON_WORK,
        "literal comparison work",
    )?;
    Ok(())
}

fn charge_token(actual: &mut ReduceActualCounters) -> Result<(), ReduceError> {
    actual.tokens = checked_add(actual.tokens, 1, "token events")?;
    actual.work = checked_add(actual.work, TOKEN_EVENT_WORK, "token event work")?;
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

fn low_mask(bits: usize) -> Result<u32, ReduceError> {
    let bits = u32::try_from(bits).map_err(|_| ReduceError::ArithmeticOverflow {
        computation: "class-mask width as u32",
    })?;
    if bits == u32::BITS {
        Ok(u32::MAX)
    } else {
        1_u32
            .checked_shl(bits)
            .and_then(|value| value.checked_sub(1))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "class-mask width",
            })
    }
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
        "literal comparisons",
        actual.literal_comparisons,
        upper.literal_comparisons,
    )?;
    verify("tokens", actual.tokens, upper.token_events)?;
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
                b"A  Holmes \t B--C Holmes D",
                b"A X Holmes Y",
                b"A Holm B Holmes C",
                b"A Holmes X Holmes Y",
                b"A Holmes X B Holmes Y",
                b"_ Holmes z9\nq Holmes r_",
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
    fn exhaustive_small_byte_semantics_match_pinned_regex() {
        for asserted in [false, true] {
            let plan = plan(b"h", asserted);
            let pattern = if asserted {
                r"\b\w+\s+h\s+\w+\b"
            } else {
                r"\w+\s+h\s+\w+"
            };
            let oracle = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            for haystack in generate(&[b'a', b'h', b' ', b'\t', b'-', 0xFF], 6) {
                let expected = oracle
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
                    plan.count(&haystack, ReduceLimits::default())
                        .unwrap()
                        .count,
                    expected.0,
                    "asserted={asserted}, haystack={haystack:?}"
                );
                assert_eq!(
                    plan.span_sum(&haystack, ReduceLimits::default())
                        .unwrap()
                        .span_sum,
                    expected.1,
                    "asserted={asserted}, haystack={haystack:?}"
                );
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the retained-path receipt keeps exhaustive semantics, boundary behavior, source accounting, and exact limits together"
    )]
    fn block_classifier_preserves_tokens_outputs_and_exact_accounting() {
        #[cfg(not(feature = "static-dispatch"))]
        let classifier =
            AsciiWordSpaceClassifier::with_policy(fre_simd_kernels::DispatchPolicy::Portable)
                .expect("portable retained classifier");
        #[cfg(feature = "static-dispatch")]
        let classifier =
            AsciiWordSpaceClassifier::with_policy(fre_simd_kernels::DispatchPolicy::Auto)
                .expect("compiler-fixed retained classifier");
        #[cfg(not(feature = "static-dispatch"))]
        assert_eq!(
            classifier.selection().variant_id,
            "ascii-word-space.mask16x32.scalar.v1"
        );
        #[cfg(feature = "static-dispatch")]
        assert_eq!(
            classifier.selection().policy,
            fre_simd_kernels::DispatchPolicy::Auto
        );

        for asserted in [false, true] {
            let plan = plan(b"h", asserted);
            for haystack in generate(&[b'a', b'h', b' ', b'\t', b'-', 0xff], 5) {
                let scalar_count = plan
                    .count(&haystack, ReduceLimits::unlimited())
                    .expect("scalar count");
                let block_count = plan
                    .count_with_block_classifier_experimental(
                        &haystack,
                        ReduceLimits::unlimited(),
                        &classifier,
                    )
                    .expect("block count");
                let scalar_spans = plan
                    .span_sum(&haystack, ReduceLimits::unlimited())
                    .expect("scalar SpanSum");
                let block_spans = plan
                    .span_sum_with_block_classifier_experimental(
                        &haystack,
                        ReduceLimits::unlimited(),
                        &classifier,
                    )
                    .expect("block SpanSum");
                assert_eq!(block_count.count, scalar_count.count);
                assert_eq!(block_spans.span_sum, scalar_spans.span_sum);
                assert_eq!(
                    block_count.accounting.actual.tokens,
                    scalar_count.accounting.actual.tokens
                );
                assert_eq!(
                    block_count.accounting.actual.matches,
                    scalar_count.accounting.actual.matches
                );
                assert_eq!(
                    block_count.accounting.actual.classifications,
                    haystack.len()
                );
                assert_eq!(
                    block_count.accounting.actual.source_reads,
                    haystack.len() + block_count.accounting.actual.literal_comparisons
                );
                assert_eq!(
                    block_count.accounting.actual.work,
                    FIXED_REDUCE_WORK
                        + haystack.len() * CLASSIFICATION_WORK
                        + block_count.accounting.actual.literal_comparisons
                            * LITERAL_COMPARISON_WORK
                        + block_count.accounting.actual.tokens * TOKEN_EVENT_WORK
                        + block_count.accounting.actual.matches * MATCH_WORK
                );
                assert_eq!(
                    block_count.accounting.upper_bounds.source_reads,
                    haystack.len() * 2
                );
                assert_eq!(
                    block_spans.accounting.actual.source_reads,
                    block_count.accounting.actual.source_reads
                );
                assert_eq!(
                    block_spans.accounting.actual.work,
                    block_count.accounting.actual.work
                );
                assert!(
                    block_count.accounting.actual.literal_comparisons
                        <= scalar_count.accounting.actual.literal_comparisons
                );
            }
        }

        let plan = plan(b"Holmes", true);
        let mut boundary = vec![b'x'; 31];
        boundary.extend_from_slice(b" Sherlock\t Holmes \n watson--");
        boundary.extend_from_slice(&[b'y'; 17]);
        boundary.extend_from_slice(b" A Holmes B");
        let scalar = plan
            .span_sum(&boundary, ReduceLimits::unlimited())
            .expect("boundary scalar");
        let block = plan
            .span_sum_with_block_classifier_experimental(
                &boundary,
                ReduceLimits::unlimited(),
                &classifier,
            )
            .expect("boundary block");
        assert_eq!(block.span_sum, scalar.span_sum);
        assert!(
            block.accounting.actual.literal_comparisons
                < scalar.accounting.actual.literal_comparisons,
            "the retained path skips comparisons after a word-token mismatch"
        );

        let upper = block.accounting.upper_bounds;
        let exact = ReduceLimits {
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
        };
        plan.span_sum_with_block_classifier_experimental(&boundary, exact, &classifier)
            .expect("exact block preflight succeeds");
        assert_eq!(
            plan.span_sum_with_block_classifier_experimental(
                &boundary,
                ReduceLimits {
                    max_source_reads: upper.source_reads - 1,
                    ..exact
                },
                &classifier,
            ),
            Err(ReduceError::SourceReadsLimit {
                needed: upper.source_reads,
                limit: upper.source_reads - 1,
            })
        );
        assert_eq!(
            plan.span_sum_with_block_classifier_experimental(
                &boundary,
                ReduceLimits {
                    max_work: upper.work - 1,
                    ..exact
                },
                &classifier,
            ),
            Err(ReduceError::WorkLimit {
                needed: upper.work,
                limit: upper.work - 1,
            })
        );
    }

    #[test]
    fn identity_and_construction_refusals_are_exact() {
        let plan = plan(b"Holmes", true);
        let identity = plan.span_sum_identity();
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
            .span_sum(haystack, ReduceLimits::default())
            .unwrap()
            .accounting
            .upper_bounds;
        let cases = [
            ReduceLimits {
                max_input_bytes: upper.input_bytes - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_source_reads: upper.source_reads - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_work: upper.work - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_classifications: upper.classifications - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_literal_comparisons: upper.literal_comparisons - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_token_events: upper.token_events - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_match_events: upper.match_events - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_count: upper.count - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_span_sum: upper.span_sum - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_persistent_bytes: upper.persistent_bytes - 1,
                ..ReduceLimits::default()
            },
            ReduceLimits {
                max_peak_bytes: upper.peak_bytes - 1,
                ..ReduceLimits::default()
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

    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little"))]
    #[test]
    #[ignore = "native c9g qualification benchmark; requires OS-usable SVE and SVE2 with inherited VL=16"]
    #[allow(
        clippy::too_many_lines,
        reason = "the parseable qualification receipt keeps authentic dispatch, correctness, alternating samples, and accounting rows together"
    )]
    fn benchmark_token_phrase_sve2_fixed16_against_incumbent() {
        use std::{env, hint::black_box, time::Instant};

        #[derive(Clone, Copy)]
        enum Backend<'a> {
            Incumbent,
            Block(&'a AsciiWordSpaceClassifier),
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

        fn execute(plan: &TokenPhrasePlan, backend: Backend<'_>, haystack: &[u8]) -> CountResult {
            match backend {
                Backend::Incumbent => plan
                    .count(haystack, ReduceLimits::unlimited())
                    .expect("incumbent count"),
                Backend::Block(classifier) => plan
                    .count_with_block_classifier_experimental(
                        haystack,
                        ReduceLimits::unlimited(),
                        classifier,
                    )
                    .expect("block-classifier count"),
            }
        }

        fn measure(
            plan: &TokenPhrasePlan,
            backend: Backend<'_>,
            haystack: &[u8],
            iterations: usize,
        ) -> (u128, u64) {
            for _ in 0..8 {
                black_box(execute(black_box(plan), backend, black_box(haystack)));
            }
            let started = Instant::now();
            let mut checksum = 0_u64;
            for _ in 0..iterations {
                checksum = checksum.wrapping_add(
                    black_box(execute(black_box(plan), backend, black_box(haystack))).count,
                );
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
            result: &CountResult,
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
            println!(
                "fre-token-phrase-sve2-fixed16-v1,{workload},{backend},{},{},{iterations},{median_total_ns},{ns_per_iter},{bytes_per_second},{checksum},{},{},{},{},{variant}",
                haystack.len(),
                haystack.as_ptr().addr() & 15,
                result.count,
                result.accounting.actual.source_reads,
                result.accounting.actual.work,
                result.accounting.actual.literal_comparisons,
            );
        }

        let required = fre_simd_kernels::FeatureSet::EMPTY
            .with(fre_simd_kernels::Feature::ArmSve)
            .with(fre_simd_kernels::Feature::ArmSve2);
        let classifier = AsciiWordSpaceClassifier::require_sve2_fixed16()
            .expect("required SVE2 fixed-16 classifier");
        assert_eq!(
            classifier.selection().variant_id,
            "ascii-word-space.mask16x32.sve2-vl16.v1"
        );
        assert!(classifier.selection().required.contains_all(required));

        let bytes = env_usize("FRE_TOKEN_PHRASE_SVE2_BENCH_BYTES", 1 << 20);
        let iterations = env_usize("FRE_TOKEN_PHRASE_SVE2_BENCH_ITERS", 100);
        let samples = env_usize("FRE_TOKEN_PHRASE_SVE2_BENCH_SAMPLES", 7);
        let alignment = env_usize("FRE_TOKEN_PHRASE_SVE2_BENCH_ALIGNMENT", 0);
        assert!(
            bytes >= ASCII_WIDE_BYTES
                && iterations > 0
                && samples > 0
                && alignment < ASCII_NARROW_BYTES
        );
        let plan = plan(b"Holmes", true);
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
            "schema,workload,backend,haystack_bytes,alignment_mod16,iterations,median_total_ns,ns_per_iter,bytes_per_second,checksum,result,source_reads,work,literal_comparisons,variant"
        );

        for (workload, storage) in workloads {
            let haystack = &storage[alignment..];
            let incumbent_result = execute(&plan, Backend::Incumbent, haystack);
            let block_result = execute(&plan, Backend::Block(&classifier), haystack);
            assert_eq!(block_result.count, incumbent_result.count);
            let mut incumbent_samples = Vec::with_capacity(samples);
            let mut block_samples = Vec::with_capacity(samples);
            let mut incumbent_checksum = 0_u64;
            let mut block_checksum = 0_u64;
            for sample in 0..samples {
                if sample % 2 == 0 {
                    let measured = measure(&plan, Backend::Incumbent, haystack, iterations);
                    incumbent_samples.push(measured.0);
                    incumbent_checksum = measured.1;
                    let measured =
                        measure(&plan, Backend::Block(&classifier), haystack, iterations);
                    block_samples.push(measured.0);
                    block_checksum = measured.1;
                } else {
                    let measured =
                        measure(&plan, Backend::Block(&classifier), haystack, iterations);
                    block_samples.push(measured.0);
                    block_checksum = measured.1;
                    let measured = measure(&plan, Backend::Incumbent, haystack, iterations);
                    incumbent_samples.push(measured.0);
                    incumbent_checksum = measured.1;
                }
            }
            assert_eq!(incumbent_checksum, block_checksum);
            let incumbent_median = median(&mut incumbent_samples);
            let block_median = median(&mut block_samples);
            report(
                workload,
                "production-incumbent",
                haystack,
                iterations,
                incumbent_median,
                incumbent_checksum,
                &incumbent_result,
                "token-phrase.scalar.v1",
            );
            report(
                workload,
                "explicit-sve2-fixed16",
                haystack,
                iterations,
                block_median,
                block_checksum,
                &block_result,
                classifier.selection().variant_id,
            );
        }
    }
}
