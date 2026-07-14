use core::{fmt, marker::PhantomData};

use sha2::{Digest, Sha256};

use crate::{AnchorFlags, BuildError, Span, ValidateLimits, ValidatedProgram, build_exact_literal};

/// Absolute width of this globally capped exact-literal aggregate leaf.
///
/// Construction, portable oracle execution and native emission all share this
/// cap. This turns candidate confirmation into a fixed implementation constant.
/// Wider literals require a distinct, separately proved linear program type.
pub const MAX_EXACT_AGGREGATE_LITERAL_BYTES: usize = 32;

/// Stable aggregate-output tag, separate from one-match [`crate::OutputKind`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum AggregateOutput {
    /// Number of successive non-overlapping matches.
    Count = 1,
    /// Sum of `end - start` over successive non-overlapping matches.
    SpanSum = 2,
}

mod sealed {
    pub trait Sealed {}
}

/// Compile-time marker for one whole-haystack aggregate contract.
pub trait AggregateOperation: sealed::Sealed + fmt::Debug {
    /// Public reducer value.
    type Output: Copy + fmt::Debug + Eq + PartialEq;

    /// Stable operation tag included in program and native-image identities.
    const OUTPUT: AggregateOutput;

    #[doc(hidden)]
    fn project(count: u64, span_sum: u64) -> Self::Output;
}

/// Whole-haystack non-overlapping match count.
#[derive(Debug)]
pub struct Count;

impl sealed::Sealed for Count {}

impl AggregateOperation for Count {
    type Output = u64;

    const OUTPUT: AggregateOutput = AggregateOutput::Count;

    fn project(count: u64, _span_sum: u64) -> Self::Output {
        count
    }
}

/// Whole-haystack sum of selected match lengths.
#[derive(Debug)]
pub struct SpanSum;

impl sealed::Sealed for SpanSum {}

impl AggregateOperation for SpanSum {
    type Output = u64;

    const OUTPUT: AggregateOutput = AggregateOutput::SpanSum;

    fn project(_count: u64, span_sum: u64) -> Self::Output {
        span_sum
    }
}

/// Domain-separated identity of a complete aggregate semantic program.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct AggregateProgramIdentity([u8; 32]);

impl AggregateProgramIdentity {
    /// Raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AggregateProgramIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AggregateProgramIdentity({self})")
    }
}

impl fmt::Display for AggregateProgramIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Validated, globally width-capped, unanchored exact-literal aggregate leaf.
#[derive(Debug)]
pub struct ExactAggregateProgram<A: AggregateOperation> {
    search: ValidatedProgram<Span>,
    identity: AggregateProgramIdentity,
    operation: PhantomData<fn() -> A>,
}

impl<A: AggregateOperation> ExactAggregateProgram<A> {
    /// Exact byte literal selected by this program.
    #[must_use]
    pub fn literal(&self) -> &[u8] {
        match &self.search.raw().data[0] {
            crate::DataBlob::Bytes(bytes) => bytes,
            crate::DataBlob::ByteClass(_) => {
                unreachable!("validated exact aggregate program stores one byte literal")
            }
        }
    }

    /// Stable aggregate output contract.
    #[must_use]
    pub const fn output(&self) -> AggregateOutput {
        A::OUTPUT
    }

    /// Complete semantic identity, including the aggregate operation.
    #[must_use]
    pub const fn cache_identity(&self) -> AggregateProgramIdentity {
        self.identity
    }

    /// Identity of the enclosed one-match semantic program.
    ///
    /// Native aggregate image containers retain this only as structural
    /// provenance; aggregate caches use [`Self::cache_identity`].
    #[doc(hidden)]
    #[must_use]
    pub const fn search_cache_identity(&self) -> crate::CacheIdentity {
        self.search.cache_identity()
    }

    /// Exact checked upper bounds for one whole-haystack invocation.
    pub fn upper_bounds(
        &self,
        haystack_len: usize,
    ) -> Result<AggregateUpperBounds, AggregateExecuteError> {
        exact_aggregate_upper_bounds(haystack_len, self.literal().len(), A::OUTPUT)
    }

    /// Execute the bounded portable semantic oracle.
    pub fn execute(
        &self,
        haystack: &[u8],
        limits: AggregateExecutionLimits,
    ) -> Result<AggregateExecutionReport<A::Output>, AggregateExecuteError> {
        let literal = self.literal();
        let upper = preflight_exact_aggregate(haystack.len(), literal.len(), A::OUTPUT, limits)?;
        if literal.is_empty() {
            return Ok(AggregateExecutionReport {
                output: A::project(upper.count, 0),
                work: 1,
                match_events: upper.match_events,
                upper_bounds: upper,
            });
        }

        let mut cursor = 0_usize;
        let mut count = 0_u64;
        let mut span_sum = 0_u64;
        let mut work = 0_u64;
        let mut events = 0_usize;
        while let Some(end) = cursor.checked_add(literal.len()) {
            if end > haystack.len() {
                break;
            }
            tick(&mut work, limits.max_work)?;
            let mut equal = true;
            for (offset, expected) in literal.iter().copied().enumerate() {
                tick(&mut work, limits.max_work)?;
                let position = cursor.checked_add(offset).ok_or(
                    AggregateExecuteError::ArithmeticOverflow {
                        computation: "confirmation position",
                    },
                )?;
                if haystack[position] != expected {
                    equal = false;
                    break;
                }
            }
            if equal {
                count = count
                    .checked_add(1)
                    .ok_or(AggregateExecuteError::ArithmeticOverflow {
                        computation: "actual count",
                    })?;
                let width = u64::try_from(literal.len()).map_err(|_| {
                    AggregateExecuteError::ArithmeticOverflow {
                        computation: "literal width as u64",
                    }
                })?;
                span_sum = span_sum.checked_add(width).ok_or(
                    AggregateExecuteError::ArithmeticOverflow {
                        computation: "actual span sum",
                    },
                )?;
                events =
                    events
                        .checked_add(1)
                        .ok_or(AggregateExecuteError::ArithmeticOverflow {
                            computation: "actual match events",
                        })?;
                cursor = end;
            } else {
                cursor =
                    cursor
                        .checked_add(1)
                        .ok_or(AggregateExecuteError::ArithmeticOverflow {
                            computation: "candidate cursor",
                        })?;
            }
        }
        tick(&mut work, limits.max_work)?;
        debug_assert!(work <= upper.work);
        debug_assert!(events <= upper.match_events);
        debug_assert!(count <= upper.count);
        debug_assert!(span_sum <= upper.span_sum);
        Ok(AggregateExecutionReport {
            output: A::project(count, span_sum),
            work,
            match_events: events,
            upper_bounds: upper,
        })
    }
}

/// Construct the globally capped exact-literal aggregate semantic leaf.
///
/// Width 32 is admitted and width 33 is an exact typed refusal. Identity
/// hashing is bounded by this same public cap plus the fixed exact-search
/// serialization envelope, so it is constant-class construction work.
pub fn build_exact_aggregate<A: AggregateOperation>(
    literal: &[u8],
    limits: ValidateLimits,
) -> Result<ExactAggregateProgram<A>, AggregateBuildError> {
    if literal.len() > MAX_EXACT_AGGREGATE_LITERAL_BYTES {
        return Err(AggregateBuildError::LiteralLengthLimit {
            limit: MAX_EXACT_AGGREGATE_LITERAL_BYTES,
            required: literal.len(),
        });
    }
    let search = build_exact_literal::<Span>(literal, AnchorFlags::default(), limits)?;
    let mut hasher = Sha256::new();
    hasher.update(b"FREKAGG\0\x01");
    hasher.update([aggregate_output_tag(A::OUTPUT)]);
    hasher.update(search.serialized().as_bytes());
    let digest = hasher.finalize();
    let mut identity = [0_u8; 32];
    identity.copy_from_slice(&digest);
    Ok(ExactAggregateProgram {
        search,
        identity: AggregateProgramIdentity(identity),
        operation: PhantomData,
    })
}

/// Whole-haystack aggregate-call ceilings checked before traversal or entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateExecutionLimits {
    pub max_haystack_bytes: usize,
    pub max_literal_bytes: usize,
    pub max_candidate_positions: usize,
    pub max_work: u64,
    pub max_match_events: usize,
    pub max_output: u64,
    pub max_reducer_steps: usize,
    pub max_scratch_bytes: usize,
    pub max_native_invocations: u8,
}

impl AggregateExecutionLimits {
    /// Disable caller-selected caps while retaining all checked arithmetic.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_haystack_bytes: usize::MAX,
            max_literal_bytes: usize::MAX,
            max_candidate_positions: usize::MAX,
            max_work: u64::MAX,
            max_match_events: usize::MAX,
            max_output: u64::MAX,
            max_reducer_steps: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_native_invocations: u8::MAX,
        }
    }
}

impl Default for AggregateExecutionLimits {
    fn default() -> Self {
        Self {
            max_haystack_bytes: usize::MAX,
            max_literal_bytes: MAX_EXACT_AGGREGATE_LITERAL_BYTES,
            max_candidate_positions: usize::MAX,
            max_work: 8 << 30,
            max_match_events: 128 << 20,
            max_output: 128 << 20,
            max_reducer_steps: (128 << 20) + 1,
            max_scratch_bytes: 0,
            max_native_invocations: 1,
        }
    }
}

/// Exact conservative bounds checked before one aggregate traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateUpperBounds {
    pub haystack_bytes: usize,
    pub literal_bytes: usize,
    pub candidate_positions: usize,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub reducer_steps: usize,
    pub work: u64,
    pub scratch_bytes: usize,
    pub native_invocations: u8,
}

/// Successful portable-oracle value and accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AggregateExecutionReport<T> {
    output: T,
    work: u64,
    match_events: usize,
    upper_bounds: AggregateUpperBounds,
}

impl<T> AggregateExecutionReport<T> {
    #[must_use]
    pub const fn output(&self) -> &T {
        &self.output
    }

    #[must_use]
    pub const fn work(&self) -> u64 {
        self.work
    }

    #[must_use]
    pub const fn match_events(&self) -> usize {
        self.match_events
    }

    #[must_use]
    pub const fn upper_bounds(&self) -> AggregateUpperBounds {
        self.upper_bounds
    }

    #[must_use]
    pub fn into_output(self) -> T {
        self.output
    }
}

/// Checked construction refusal for the aggregate semantic leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AggregateBuildError {
    LiteralLengthLimit { limit: usize, required: usize },
    Search(BuildError),
}

impl From<BuildError> for AggregateBuildError {
    fn from(value: BuildError) -> Self {
        Self::Search(value)
    }
}

impl fmt::Display for AggregateBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "aggregate kernel build failed: {self:?}")
    }
}

impl std::error::Error for AggregateBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Search(error) => Some(error),
            Self::LiteralLengthLimit { .. } => None,
        }
    }
}

/// Checked aggregate preflight or portable-oracle failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AggregateExecuteError {
    LiteralLengthLimit { limit: usize, required: usize },
    HaystackBytesLimit { needed: usize, limit: usize },
    LiteralBytesLimit { needed: usize, limit: usize },
    CandidatePositionsLimit { needed: usize, limit: usize },
    WorkLimit { needed: u64, limit: u64 },
    MatchEventsLimit { needed: usize, limit: usize },
    OutputLimit { needed: u64, limit: u64 },
    ReducerStepsLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    NativeInvocationsLimit { needed: u8, limit: u8 },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for AggregateExecuteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "aggregate kernel execution failed: {self:?}")
    }
}

impl std::error::Error for AggregateExecuteError {}

/// Compute the exact preflight envelope shared by the oracle and native ABI.
pub fn exact_aggregate_upper_bounds(
    haystack_len: usize,
    literal_len: usize,
    output: AggregateOutput,
) -> Result<AggregateUpperBounds, AggregateExecuteError> {
    if literal_len > MAX_EXACT_AGGREGATE_LITERAL_BYTES {
        return Err(AggregateExecuteError::LiteralLengthLimit {
            limit: MAX_EXACT_AGGREGATE_LITERAL_BYTES,
            required: literal_len,
        });
    }
    if literal_len == 0 {
        let match_events =
            haystack_len
                .checked_add(1)
                .ok_or(AggregateExecuteError::ArithmeticOverflow {
                    computation: "empty byte boundaries",
                })?;
        let count =
            u64::try_from(match_events).map_err(|_| AggregateExecuteError::ArithmeticOverflow {
                computation: "empty count as u64",
            })?;
        return Ok(AggregateUpperBounds {
            haystack_bytes: haystack_len,
            literal_bytes: 0,
            candidate_positions: 0,
            match_events,
            count,
            span_sum: 0,
            reducer_steps: 1,
            work: 1,
            scratch_bytes: 0,
            native_invocations: 1,
        });
    }

    let candidate_positions = haystack_len
        .checked_sub(literal_len)
        .and_then(|last| last.checked_add(1))
        .unwrap_or(0);
    let match_events =
        haystack_len
            .checked_div(literal_len)
            .ok_or(AggregateExecuteError::ArithmeticOverflow {
                computation: "match-event quotient",
            })?;
    let count =
        u64::try_from(match_events).map_err(|_| AggregateExecuteError::ArithmeticOverflow {
            computation: "count upper bound as u64",
        })?;
    let literal_u64 =
        u64::try_from(literal_len).map_err(|_| AggregateExecuteError::ArithmeticOverflow {
            computation: "literal length as u64",
        })?;
    let span_sum =
        count
            .checked_mul(literal_u64)
            .ok_or(AggregateExecuteError::ArithmeticOverflow {
                computation: "span-sum upper bound",
            })?;
    let reducer_steps =
        match_events
            .checked_add(1)
            .ok_or(AggregateExecuteError::ArithmeticOverflow {
                computation: "reducer-step upper bound",
            })?;
    let per_candidate =
        literal_len
            .checked_add(1)
            .ok_or(AggregateExecuteError::ArithmeticOverflow {
                computation: "work per candidate",
            })?;
    let work_usize = candidate_positions
        .checked_mul(per_candidate)
        .and_then(|work| work.checked_add(reducer_steps))
        .ok_or(AggregateExecuteError::ArithmeticOverflow {
            computation: "aggregate work upper bound",
        })?;
    let work =
        u64::try_from(work_usize).map_err(|_| AggregateExecuteError::ArithmeticOverflow {
            computation: "aggregate work as u64",
        })?;
    let requested_span = if output == AggregateOutput::SpanSum {
        span_sum
    } else {
        count
    };
    debug_assert!(requested_span <= u64::try_from(haystack_len).unwrap_or(u64::MAX));
    Ok(AggregateUpperBounds {
        haystack_bytes: haystack_len,
        literal_bytes: literal_len,
        candidate_positions,
        match_events,
        count,
        span_sum,
        reducer_steps,
        work,
        scratch_bytes: 0,
        native_invocations: 1,
    })
}

/// Check every caller-selected ceiling before one aggregate traversal or
/// native entry and return the complete admitted envelope.
pub fn preflight_exact_aggregate(
    haystack_len: usize,
    literal_len: usize,
    output: AggregateOutput,
    limits: AggregateExecutionLimits,
) -> Result<AggregateUpperBounds, AggregateExecuteError> {
    let upper = exact_aggregate_upper_bounds(haystack_len, literal_len, output)?;
    check_limits(upper, output, limits)?;
    Ok(upper)
}

fn check_limits(
    upper: AggregateUpperBounds,
    output: AggregateOutput,
    limits: AggregateExecutionLimits,
) -> Result<(), AggregateExecuteError> {
    if upper.haystack_bytes > limits.max_haystack_bytes {
        return Err(AggregateExecuteError::HaystackBytesLimit {
            needed: upper.haystack_bytes,
            limit: limits.max_haystack_bytes,
        });
    }
    if upper.literal_bytes > limits.max_literal_bytes {
        return Err(AggregateExecuteError::LiteralBytesLimit {
            needed: upper.literal_bytes,
            limit: limits.max_literal_bytes,
        });
    }
    if upper.candidate_positions > limits.max_candidate_positions {
        return Err(AggregateExecuteError::CandidatePositionsLimit {
            needed: upper.candidate_positions,
            limit: limits.max_candidate_positions,
        });
    }
    if upper.work > limits.max_work {
        return Err(AggregateExecuteError::WorkLimit {
            needed: upper.work,
            limit: limits.max_work,
        });
    }
    if upper.match_events > limits.max_match_events {
        return Err(AggregateExecuteError::MatchEventsLimit {
            needed: upper.match_events,
            limit: limits.max_match_events,
        });
    }
    let requested = match output {
        AggregateOutput::Count => upper.count,
        AggregateOutput::SpanSum => upper.span_sum,
    };
    if requested > limits.max_output {
        return Err(AggregateExecuteError::OutputLimit {
            needed: requested,
            limit: limits.max_output,
        });
    }
    if upper.reducer_steps > limits.max_reducer_steps {
        return Err(AggregateExecuteError::ReducerStepsLimit {
            needed: upper.reducer_steps,
            limit: limits.max_reducer_steps,
        });
    }
    if upper.scratch_bytes > limits.max_scratch_bytes {
        return Err(AggregateExecuteError::ScratchLimit {
            needed: upper.scratch_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if upper.native_invocations > limits.max_native_invocations {
        return Err(AggregateExecuteError::NativeInvocationsLimit {
            needed: upper.native_invocations,
            limit: limits.max_native_invocations,
        });
    }
    Ok(())
}

fn tick(work: &mut u64, limit: u64) -> Result<(), AggregateExecuteError> {
    if *work == limit {
        return Err(AggregateExecuteError::WorkLimit {
            needed: work.saturating_add(1),
            limit,
        });
    }
    *work = work
        .checked_add(1)
        .ok_or(AggregateExecuteError::ArithmeticOverflow {
            computation: "actual aggregate work",
        })?;
    Ok(())
}

const fn aggregate_output_tag(output: AggregateOutput) -> u8 {
    match output {
        AggregateOutput::Count => 1,
        AggregateOutput::SpanSum => 2,
    }
}
