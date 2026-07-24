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
        let persistent_bytes =
            size_of::<Self>()
                .checked_add(literal.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "persistent bytes",
                })?;
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
        for &byte in literal {
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

    fn derive_upper_bounds(
        &self,
        input_bytes: usize,
        operation: Operation,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let classifications = input_bytes;
        let source_reads = classifications;
        let literal_comparisons = input_bytes;
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
    actual.classifications = checked_add(actual.classifications, 1, "classifications")?;
    actual.work = checked_add(actual.work, CLASSIFICATION_WORK, "classification work")?;
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
}
