//! Theorem-bounded SIMD packed reducers for small ordered literal sets.
//!
//! The pinned packed searcher is not used as a general fallback: arbitrary
//! literal width or count would make its candidate verification bound depend
//! without limit on the compiled language. This plan admits only the absolute
//! constants below. Empty alternatives are refused because the pinned packed
//! iterator does not support them and because nonempty matches are the progress
//! proof: every restarted suffix begins strictly after the previous start.
//!
//! This module is research-only. Its operation path is source-audited as
//! allocation-free, but `Searcher` construction contains dependency-internal
//! infallible `Vec`, `Box`, `BTreeMap` and `Arc` allocations. Consequently the
//! build peak below is a conservative admission envelope, not production-grade
//! resource certification. The general reverse plan has fallible reservations
//! and remains the correctness/resource floor.

use core::{fmt, mem::size_of};

use aho_corasick::packed::Searcher;

use crate::ordered_literal_aggregate::{
    BoundarySemantics, IterationSemantics, MatchSemantics, Operation, Semantics,
};

const CACHE_FORMAT_VERSION: u32 = 1;
const LENGTH_PREFIX_BYTES: usize = size_of::<u64>();
const BUILD_FACTOR: usize = 4_096;
const FIXED_BUILD_WORK: usize = 1024 * 1024;
const PATTERN_BYTE_ENVELOPE: usize = 4_096;
const PATTERN_ENTRY_ENVELOPE: usize = 64 * 1024;
const FIXED_BUILD_ENVELOPE: usize = 4 * 1024 * 1024;
// The pinned Teddy implementations use at most one 256-bit (32-byte) vector
// plus three bytes of mask history. A terminal vector can be revisited once in
// every iterator call, including the final no-match call. The extra one is an
// inclusive boundary charge: 32 + 3 + 1 = 36.
const MAX_TEDDY_TAIL_REVISIT_POSITIONS_PER_CALL: usize = 36;
const FIXED_WORK_PER_EXAMINED_POSITION: usize = 64;
const FIXED_WORK_PER_ITERATOR_CALL: usize = 64;

/// Absolute theorem bound, independent of caller limits.
pub const CERTIFIED_MAX_PATTERNS: usize = 16;
/// Absolute theorem bound, independent of caller limits.
pub const CERTIFIED_MAX_PATTERN_BYTES: usize = 32;
/// Absolute theorem bound, independent of caller limits.
pub const CERTIFIED_MAX_TOTAL_PATTERN_BYTES: usize = 512;
/// Pinned dependency identity.
pub const AHO_CORASICK_VERSION: &str = "1.1.4";
/// crates.io checksum from the pinned lockfile.
pub const AHO_CORASICK_PACKAGE_CHECKSUM: &str =
    "ddd31a130427c27518df266943a5308ed92d4b226cc639f5a8f1002816174301";
pub const ALGORITHM_ID: &str = "ordered-literal-aggregate.packed-bounded-find-iter.v1";
pub const COUNT_PLAN_ID: &str = "ordered-literal-aggregate.count.packed-bounded-find-iter.v1";
pub const SPAN_SUM_PLAN_ID: &str = "ordered-literal-aggregate.span-sum.packed-bounded-find-iter.v1";

/// Collision-free process-local semantic identity for one packed plan.
///
/// The pinned builder runtime-selects a Teddy variant and uses its Rabin-Karp
/// member for short suffixes. This is not a portable serialized-code cache
/// key. Limits are excluded and must be revalidated on reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheIdentity<'a> {
    pub algorithm_id: &'static str,
    pub plan_id: &'static str,
    pub operation: Operation,
    pub cache_format_version: u32,
    pub dependency_version: &'static str,
    pub dependency_checksum: &'static str,
    pub implementation_kind: &'static str,
    pub identity_scope: &'static str,
    pub target_arch: &'static str,
    pub runtime_minimum_haystack_bytes: usize,
    pub semantics: Semantics,
    pub certified_max_patterns: usize,
    pub certified_max_pattern_bytes: usize,
    pub certified_max_total_pattern_bytes: usize,
    pub encoded_patterns: &'a [u8],
}

/// Research admission limits.
///
/// Pattern and identity checks are exact; persistent bytes include the
/// dependency's documented approximate `memory_usage`. Build work and peak
/// checks use deliberately oversized source-derived envelopes, but cannot make
/// the pinned dependency's infallible internal allocations fallible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildLimits {
    pub max_patterns: usize,
    pub max_pattern_bytes: usize,
    pub max_total_pattern_bytes: usize,
    pub max_identity_bytes: usize,
    pub max_build_work: usize,
    pub max_build_peak_bytes: usize,
    pub max_persistent_bytes: usize,
}

impl BuildLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_patterns: usize::MAX,
            max_pattern_bytes: usize::MAX,
            max_total_pattern_bytes: usize::MAX,
            max_identity_bytes: usize::MAX,
            max_build_work: usize::MAX,
            max_build_peak_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
        }
    }
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            max_patterns: CERTIFIED_MAX_PATTERNS,
            max_pattern_bytes: CERTIFIED_MAX_PATTERN_BYTES,
            max_total_pattern_bytes: CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
            max_identity_bytes: 4 * 1024,
            max_build_work: 4 * 1024 * 1024,
            max_build_peak_bytes: 16 * 1024 * 1024,
            max_persistent_bytes: 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub patterns: usize,
    pub pattern_bytes: usize,
    pub max_pattern_bytes: usize,
    pub min_pattern_bytes: usize,
    pub identity_bytes: usize,
    pub identity_capacity_bytes: usize,
    pub build_work_upper_bound: usize,
    pub build_peak_upper_bound: usize,
    pub persistent_bytes: usize,
    pub simd_minimum_haystack_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceLimits {
    pub max_work: u64,
    pub max_match_events: usize,
    pub max_count: u64,
    pub max_span_sum: u64,
    pub max_reducer_steps: usize,
    pub max_scratch_bytes: usize,
    pub max_peak_bytes: usize,
}

impl ReduceLimits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: u64::MAX,
            max_match_events: usize::MAX,
            max_count: u64::MAX,
            max_span_sum: u64::MAX,
            max_reducer_steps: usize::MAX,
            max_scratch_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for ReduceLimits {
    fn default() -> Self {
        Self {
            max_work: 16 * 1024 * 1024 * 1024,
            max_match_events: 128 * 1024 * 1024,
            max_count: 128 * 1024 * 1024,
            max_span_sum: 128 * 1024 * 1024,
            max_reducer_steps: 128 * 1024 * 1024 + 1,
            max_scratch_bytes: 0,
            max_peak_bytes: 2 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub haystack_bytes: usize,
    pub candidate_positions: usize,
    pub restart_tail_positions: usize,
    pub examined_positions: usize,
    pub work_per_position: usize,
    pub iterator_setup_work: usize,
    pub work: u64,
    pub match_events: usize,
    pub count: u64,
    pub span_sum: u64,
    pub reducer_steps: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub match_events: u64,
    pub iterator_next_calls: usize,
    pub count: Option<u64>,
    pub span_sum: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting<'a> {
    pub identity: CacheIdentity<'a>,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountResult<'a> {
    pub count: u64,
    pub accounting: ReduceAccounting<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanSumResult<'a> {
    pub span_sum: u64,
    pub accounting: ReduceAccounting<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyPatternSet,
    EmptyPattern {
        index: usize,
    },
    ProofRefused {
        fact: &'static str,
        needed: usize,
        certified_limit: usize,
    },
    PatternLimit {
        needed: usize,
        limit: usize,
    },
    PatternBytesLimit {
        needed: usize,
        limit: usize,
    },
    TotalPatternBytesLimit {
        needed: usize,
        limit: usize,
    },
    IdentityLimit {
        needed: usize,
        limit: usize,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    BuildPeakLimit {
        needed: usize,
        limit: usize,
    },
    PersistentLimit {
        needed: usize,
        limit: usize,
    },
    UnsupportedTargetOrShape,
    AllocationFailed {
        additional: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "packed ordered-literal build refusal: {self:?}")
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    WorkLimit { needed: u64, limit: u64 },
    MatchEventsLimit { needed: usize, limit: usize },
    CountLimit { needed: u64, limit: u64 },
    SpanSumLimit { needed: u64, limit: u64 },
    ReducerStepsLimit { needed: usize, limit: usize },
    ScratchLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "packed ordered-literal reduce refusal: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

#[derive(Debug)]
struct PlanCore {
    searcher: Searcher,
    encoded_patterns: Vec<u8>,
    build: BuildAccounting,
}

/// Non-`Clone`, count-specialized packed plan.
#[derive(Debug)]
pub struct PackedOrderedLiteralCountPlan {
    core: PlanCore,
}

/// Non-`Clone`, span-specialized packed plan.
#[derive(Debug)]
pub struct PackedOrderedLiteralSpanSumPlan {
    core: PlanCore,
}

impl PackedOrderedLiteralCountPlan {
    pub fn build<P: AsRef<[u8]>>(patterns: &[P], limits: BuildLimits) -> Result<Self, BuildError> {
        PlanCore::build(patterns, limits, size_of::<Self>()).map(|core| Self { core })
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.core.build
    }

    #[must_use]
    pub fn cache_identity(&self) -> CacheIdentity<'_> {
        self.core.identity(Operation::Count)
    }

    #[inline]
    pub fn count<'a>(
        &'a self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<CountResult<'a>, ReduceError> {
        let upper = self.core.preflight(haystack.len(), false, limits)?;
        let mut events = 0_u64;
        let mut calls = 0_usize;
        let mut iterator = self.core.searcher.find_iter(haystack);
        loop {
            calls = calls
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual iterator calls",
                })?;
            if iterator.next().is_none() {
                break;
            }
            events = events
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual count",
                })?;
        }
        debug_assert!(events <= upper.count);
        Ok(CountResult {
            count: events,
            accounting: ReduceAccounting {
                identity: self.cache_identity(),
                upper_bounds: upper,
                actual: ReduceActualCounters {
                    match_events: events,
                    iterator_next_calls: calls,
                    count: Some(events),
                    span_sum: None,
                },
            },
        })
    }
}

impl PackedOrderedLiteralSpanSumPlan {
    pub fn build<P: AsRef<[u8]>>(patterns: &[P], limits: BuildLimits) -> Result<Self, BuildError> {
        PlanCore::build(patterns, limits, size_of::<Self>()).map(|core| Self { core })
    }

    #[must_use]
    pub const fn build_accounting(&self) -> BuildAccounting {
        self.core.build
    }

    #[must_use]
    pub fn cache_identity(&self) -> CacheIdentity<'_> {
        self.core.identity(Operation::SpanSum)
    }

    #[inline]
    pub fn span_sum<'a>(
        &'a self,
        haystack: &[u8],
        limits: ReduceLimits,
    ) -> Result<SpanSumResult<'a>, ReduceError> {
        let upper = self.core.preflight(haystack.len(), true, limits)?;
        let mut events = 0_u64;
        let mut span_sum = 0_u64;
        let mut calls = 0_usize;
        let mut iterator = self.core.searcher.find_iter(haystack);
        loop {
            calls = calls
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual iterator calls",
                })?;
            let Some(matched) = iterator.next() else {
                break;
            };
            events = events
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual span events",
                })?;
            let length_usize = matched.end().checked_sub(matched.start()).ok_or(
                ReduceError::ArithmeticOverflow {
                    computation: "actual matched length",
                },
            )?;
            let length =
                u64::try_from(length_usize).map_err(|_| ReduceError::ArithmeticOverflow {
                    computation: "actual matched length as u64",
                })?;
            span_sum = span_sum
                .checked_add(length)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "actual span sum",
                })?;
        }
        debug_assert!(events <= upper.count);
        debug_assert!(span_sum <= upper.span_sum);
        Ok(SpanSumResult {
            span_sum,
            accounting: ReduceAccounting {
                identity: self.cache_identity(),
                upper_bounds: upper,
                actual: ReduceActualCounters {
                    match_events: events,
                    iterator_next_calls: calls,
                    count: Some(events),
                    span_sum: Some(span_sum),
                },
            },
        })
    }
}

impl PlanCore {
    fn identity(&self, operation: Operation) -> CacheIdentity<'_> {
        CacheIdentity {
            algorithm_id: ALGORITHM_ID,
            plan_id: match operation {
                Operation::Count => COUNT_PLAN_ID,
                Operation::SpanSum => SPAN_SUM_PLAN_ID,
            },
            operation,
            cache_format_version: CACHE_FORMAT_VERSION,
            dependency_version: AHO_CORASICK_VERSION,
            dependency_checksum: AHO_CORASICK_PACKAGE_CHECKSUM,
            implementation_kind: "aho-corasick packed Searcher LeftmostFirst find_iter",
            identity_scope: "process-local semantic identity; runtime Teddy variant is not serialized",
            target_arch: std::env::consts::ARCH,
            runtime_minimum_haystack_bytes: self.build.simd_minimum_haystack_bytes,
            semantics: Semantics {
                match_semantics: MatchSemantics::LeftmostFirst,
                iteration_semantics: IterationSemantics::NonOverlapping,
                boundary_semantics: BoundarySemantics::NonemptyOnlyUnicodeOff,
            },
            certified_max_patterns: CERTIFIED_MAX_PATTERNS,
            certified_max_pattern_bytes: CERTIFIED_MAX_PATTERN_BYTES,
            certified_max_total_pattern_bytes: CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
            encoded_patterns: &self.encoded_patterns,
        }
    }

    fn build<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: BuildLimits,
        inline_bytes: usize,
    ) -> Result<Self, BuildError> {
        let preflight = preflight(patterns, limits, inline_bytes)?;
        let mut encoded_patterns = Vec::new();
        encoded_patterns
            .try_reserve_exact(preflight.identity_bytes)
            .map_err(|_| BuildError::AllocationFailed {
                additional: preflight.identity_bytes,
            })?;
        encode(patterns, preflight.identity_bytes, &mut encoded_patterns)?;
        let searcher = Searcher::new(patterns.iter().map(AsRef::as_ref))
            .ok_or(BuildError::UnsupportedTargetOrShape)?;
        let persistent_bytes = inline_bytes
            .checked_add(encoded_patterns.capacity())
            .and_then(|bytes| bytes.checked_add(searcher.memory_usage()))
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "actual persistent bytes",
            })?;
        if persistent_bytes > limits.max_persistent_bytes {
            return Err(BuildError::PersistentLimit {
                needed: persistent_bytes,
                limit: limits.max_persistent_bytes,
            });
        }
        Ok(Self {
            build: BuildAccounting {
                patterns: patterns.len(),
                pattern_bytes: preflight.pattern_bytes,
                max_pattern_bytes: preflight.max_pattern_bytes,
                min_pattern_bytes: preflight.min_pattern_bytes,
                identity_bytes: preflight.identity_bytes,
                identity_capacity_bytes: encoded_patterns.capacity(),
                build_work_upper_bound: preflight.build_work_upper_bound,
                build_peak_upper_bound: preflight.build_peak_upper_bound,
                persistent_bytes,
                simd_minimum_haystack_bytes: searcher.minimum_len(),
            },
            searcher,
            encoded_patterns,
        })
    }

    fn preflight(
        &self,
        haystack_len: usize,
        check_span: bool,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let candidate_positions =
            haystack_len
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "candidate positions",
                })?;
        let match_events = haystack_len
            .checked_div(self.build.min_pattern_bytes)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "event quotient",
            })?;
        let iterator_calls =
            match_events
                .checked_add(1)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "iterator calls",
                })?;
        let restart_tail_positions = iterator_calls
            .checked_mul(MAX_TEDDY_TAIL_REVISIT_POSITIONS_PER_CALL)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "restarted Teddy tail positions",
            })?;
        let examined_positions = candidate_positions
            .checked_add(restart_tail_positions)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "total packed examined positions",
            })?;
        let work_per_position = self
            .build
            .pattern_bytes
            .checked_add(self.build.patterns)
            .and_then(|work| work.checked_add(FIXED_WORK_PER_EXAMINED_POSITION))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "work per position",
            })?;
        let reducer_steps = iterator_calls;
        let iterator_setup_work = reducer_steps
            .checked_mul(FIXED_WORK_PER_ITERATOR_CALL)
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "iterator setup work",
            })?;
        let work_usize = examined_positions
            .checked_mul(work_per_position)
            .and_then(|work| work.checked_add(iterator_setup_work))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "packed operation work",
            })?;
        let work = u64::try_from(work_usize).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "packed work as u64",
        })?;
        let count = u64::try_from(match_events).map_err(|_| ReduceError::ArithmeticOverflow {
            computation: "count upper bound",
        })?;
        let span_sum =
            u64::try_from(haystack_len).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "span upper bound",
            })?;
        let upper = ReduceUpperBounds {
            haystack_bytes: haystack_len,
            candidate_positions,
            restart_tail_positions,
            examined_positions,
            work_per_position,
            iterator_setup_work,
            work,
            match_events,
            count,
            span_sum,
            reducer_steps,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        };
        check_reduce(upper, check_span, limits)?;
        Ok(upper)
    }
}

#[derive(Clone, Copy)]
struct BuildPreflight {
    pattern_bytes: usize,
    max_pattern_bytes: usize,
    min_pattern_bytes: usize,
    identity_bytes: usize,
    build_work_upper_bound: usize,
    build_peak_upper_bound: usize,
}

#[allow(
    clippy::too_many_lines,
    reason = "eligibility proof and every caller/build envelope are intentionally ordered in one preflight"
)]
fn preflight<P: AsRef<[u8]>>(
    patterns: &[P],
    limits: BuildLimits,
    inline_bytes: usize,
) -> Result<BuildPreflight, BuildError> {
    if patterns.is_empty() {
        return Err(BuildError::EmptyPatternSet);
    }
    if patterns.len() > CERTIFIED_MAX_PATTERNS {
        return Err(BuildError::ProofRefused {
            fact: "pattern count",
            needed: patterns.len(),
            certified_limit: CERTIFIED_MAX_PATTERNS,
        });
    }
    if patterns.len() > limits.max_patterns {
        return Err(BuildError::PatternLimit {
            needed: patterns.len(),
            limit: limits.max_patterns,
        });
    }
    let mut pattern_bytes = 0_usize;
    let mut max_pattern_bytes = 0_usize;
    let mut min_pattern_bytes = usize::MAX;
    for (index, pattern) in patterns.iter().enumerate() {
        let bytes = pattern.as_ref();
        if bytes.is_empty() {
            return Err(BuildError::EmptyPattern { index });
        }
        if bytes.len() > CERTIFIED_MAX_PATTERN_BYTES {
            return Err(BuildError::ProofRefused {
                fact: "literal width",
                needed: bytes.len(),
                certified_limit: CERTIFIED_MAX_PATTERN_BYTES,
            });
        }
        if bytes.len() > limits.max_pattern_bytes {
            return Err(BuildError::PatternBytesLimit {
                needed: bytes.len(),
                limit: limits.max_pattern_bytes,
            });
        }
        pattern_bytes =
            pattern_bytes
                .checked_add(bytes.len())
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "total pattern bytes",
                })?;
        max_pattern_bytes = max_pattern_bytes.max(bytes.len());
        min_pattern_bytes = min_pattern_bytes.min(bytes.len());
    }
    if pattern_bytes > CERTIFIED_MAX_TOTAL_PATTERN_BYTES {
        return Err(BuildError::ProofRefused {
            fact: "total literal bytes",
            needed: pattern_bytes,
            certified_limit: CERTIFIED_MAX_TOTAL_PATTERN_BYTES,
        });
    }
    if pattern_bytes > limits.max_total_pattern_bytes {
        return Err(BuildError::TotalPatternBytesLimit {
            needed: pattern_bytes,
            limit: limits.max_total_pattern_bytes,
        });
    }
    let identity_bytes = LENGTH_PREFIX_BYTES
        .checked_add(patterns.len().checked_mul(LENGTH_PREFIX_BYTES).ok_or(
            BuildError::ArithmeticOverflow {
                computation: "identity prefixes",
            },
        )?)
        .and_then(|bytes| bytes.checked_add(pattern_bytes))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "identity bytes",
        })?;
    if identity_bytes > limits.max_identity_bytes {
        return Err(BuildError::IdentityLimit {
            needed: identity_bytes,
            limit: limits.max_identity_bytes,
        });
    }
    let build_work_upper_bound = pattern_bytes
        .checked_add(patterns.len())
        .and_then(|work| work.checked_mul(BUILD_FACTOR))
        .and_then(|work| work.checked_add(FIXED_BUILD_WORK))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "build work",
        })?;
    if build_work_upper_bound > limits.max_build_work {
        return Err(BuildError::WorkLimit {
            needed: build_work_upper_bound,
            limit: limits.max_build_work,
        });
    }
    let build_peak_upper_bound = pattern_bytes
        .checked_mul(PATTERN_BYTE_ENVELOPE)
        .and_then(|bytes| bytes.checked_add(patterns.len().checked_mul(PATTERN_ENTRY_ENVELOPE)?))
        .and_then(|bytes| bytes.checked_add(FIXED_BUILD_ENVELOPE))
        .and_then(|bytes| bytes.checked_add(identity_bytes))
        .and_then(|bytes| bytes.checked_add(inline_bytes))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "build peak",
        })?;
    if build_peak_upper_bound > limits.max_build_peak_bytes {
        return Err(BuildError::BuildPeakLimit {
            needed: build_peak_upper_bound,
            limit: limits.max_build_peak_bytes,
        });
    }
    Ok(BuildPreflight {
        pattern_bytes,
        max_pattern_bytes,
        min_pattern_bytes,
        identity_bytes,
        build_work_upper_bound,
        build_peak_upper_bound,
    })
}

fn check_reduce(
    upper: ReduceUpperBounds,
    check_span: bool,
    limits: ReduceLimits,
) -> Result<(), ReduceError> {
    if upper.work > limits.max_work {
        return Err(ReduceError::WorkLimit {
            needed: upper.work,
            limit: limits.max_work,
        });
    }
    if upper.match_events > limits.max_match_events {
        return Err(ReduceError::MatchEventsLimit {
            needed: upper.match_events,
            limit: limits.max_match_events,
        });
    }
    if upper.count > limits.max_count {
        return Err(ReduceError::CountLimit {
            needed: upper.count,
            limit: limits.max_count,
        });
    }
    if check_span && upper.span_sum > limits.max_span_sum {
        return Err(ReduceError::SpanSumLimit {
            needed: upper.span_sum,
            limit: limits.max_span_sum,
        });
    }
    if upper.reducer_steps > limits.max_reducer_steps {
        return Err(ReduceError::ReducerStepsLimit {
            needed: upper.reducer_steps,
            limit: limits.max_reducer_steps,
        });
    }
    if upper.scratch_bytes > limits.max_scratch_bytes {
        return Err(ReduceError::ScratchLimit {
            needed: upper.scratch_bytes,
            limit: limits.max_scratch_bytes,
        });
    }
    if upper.peak_bytes > limits.max_peak_bytes {
        return Err(ReduceError::PeakLimit {
            needed: upper.peak_bytes,
            limit: limits.max_peak_bytes,
        });
    }
    Ok(())
}

fn encode<P: AsRef<[u8]>>(
    patterns: &[P],
    expected_bytes: usize,
    encoded: &mut Vec<u8>,
) -> Result<(), BuildError> {
    if encoded.capacity() < expected_bytes {
        return Err(BuildError::ArithmeticOverflow {
            computation: "identity reservation invariant",
        });
    }
    let count = u64::try_from(patterns.len()).map_err(|_| BuildError::ArithmeticOverflow {
        computation: "identity count",
    })?;
    encoded.extend_from_slice(&count.to_le_bytes());
    for pattern in patterns {
        let bytes = pattern.as_ref();
        let length = u64::try_from(bytes.len()).map_err(|_| BuildError::ArithmeticOverflow {
            computation: "identity length",
        })?;
        encoded.extend_from_slice(&length.to_le_bytes());
        encoded.extend_from_slice(bytes);
    }
    if encoded.len() != expected_bytes {
        return Err(BuildError::ArithmeticOverflow {
            computation: "identity encoded length invariant",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use regex::bytes::RegexBuilder;

    use super::{
        BuildError, BuildLimits, PackedOrderedLiteralCountPlan, PackedOrderedLiteralSpanSumPlan,
        ReduceError, ReduceLimits,
    };
    use crate::{
        OrderedLiteralAggregateBuildLimits, OrderedLiteralAggregateReduceLimits,
        OrderedLiteralCountPlan, OrderedLiteralSpanSumPlan,
    };

    fn source(patterns: &[Vec<u8>]) -> String {
        let mut source = String::from("(?:");
        for (index, pattern) in patterns.iter().enumerate() {
            if index != 0 {
                source.push('|');
            }
            for &byte in pattern {
                write!(&mut source, "\\x{byte:02X}").unwrap();
            }
        }
        source.push(')');
        source
    }

    fn words(alphabet: &[u8], maximum_len: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut level = vec![Vec::new()];
        for _ in 0..maximum_len {
            let mut next = Vec::new();
            for prefix in &level {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    next.push(word);
                }
            }
            all.extend(next.iter().cloned());
            level = next;
        }
        all
    }

    fn pattern_lists(universe: &[Vec<u8>], maximum_len: usize) -> Vec<Vec<Vec<u8>>> {
        let mut all = Vec::new();
        let mut level = vec![Vec::new()];
        for _ in 0..maximum_len {
            let mut next = Vec::new();
            for prefix in &level {
                for pattern in universe {
                    let mut list = prefix.clone();
                    list.push(pattern.clone());
                    next.push(list);
                }
            }
            all.extend(next.iter().cloned());
            level = next;
        }
        all
    }

    #[test]
    fn ordered_prefix_duplicate_and_arbitrary_bytes_match_regex() {
        let languages = [
            vec![b"a".to_vec(), b"ab".to_vec()],
            vec![b"ab".to_vec(), b"a".to_vec()],
            vec![b"a".to_vec(), b"a".to_vec()],
            vec![b"\xFF\x00".to_vec(), b"\xFF".to_vec()],
        ];
        let haystacks: &[&[u8]] = &[b"", b"a", b"ababa", b"\xFF\x00\xFF\x80"];
        for patterns in languages {
            let regex = RegexBuilder::new(&source(&patterns))
                .unicode(false)
                .build()
                .unwrap();
            let count =
                PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
            let span = PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited())
                .unwrap();
            for haystack in haystacks {
                let expected_count = u64::try_from(regex.find_iter(haystack).count()).unwrap();
                let expected_span = regex
                    .find_iter(haystack)
                    .map(|matched| u64::try_from(matched.end() - matched.start()).unwrap())
                    .sum::<u64>();
                assert_eq!(
                    count
                        .count(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .count,
                    expected_count
                );
                assert_eq!(
                    span.span_sum(haystack, ReduceLimits::unlimited())
                        .unwrap()
                        .span_sum,
                    expected_span
                );
            }
        }

        let duplicate = PackedOrderedLiteralCountPlan::build(
            &[b"a".as_slice(), b"a".as_slice()],
            BuildLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(
            duplicate
                .core
                .searcher
                .find_iter(b"a")
                .next()
                .unwrap()
                .pattern()
                .as_usize(),
            0
        );
    }

    #[test]
    fn exhaustive_nonempty_languages_match_upstream_and_general_plan() {
        let universe = vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"\xFF".to_vec(),
            b"aa".to_vec(),
            b"ab".to_vec(),
        ];
        let languages = pattern_lists(&universe, 3);
        let haystacks = words(b"\x00a\xFF", 4);
        for patterns in languages {
            let regex = RegexBuilder::new(&source(&patterns))
                .unicode(false)
                .build()
                .unwrap();
            let packed_count =
                PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
            let packed_span =
                PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited())
                    .unwrap();
            let general_count = OrderedLiteralCountPlan::build(
                &patterns,
                OrderedLiteralAggregateBuildLimits::unlimited(),
            )
            .unwrap();
            let general_span = OrderedLiteralSpanSumPlan::build(
                &patterns,
                OrderedLiteralAggregateBuildLimits::unlimited(),
            )
            .unwrap();
            for haystack in &haystacks {
                let expected = regex
                    .find_iter(haystack)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect::<Vec<_>>();
                let actual = packed_count
                    .core
                    .searcher
                    .find_iter(haystack)
                    .map(|matched| (matched.start(), matched.end()))
                    .collect::<Vec<_>>();
                assert_eq!(
                    actual, expected,
                    "patterns={patterns:?}, haystack={haystack:?}"
                );
                let count = packed_count
                    .count(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .count;
                let span = packed_span
                    .span_sum(haystack, ReduceLimits::unlimited())
                    .unwrap()
                    .span_sum;
                assert_eq!(
                    count,
                    general_count
                        .count(haystack, OrderedLiteralAggregateReduceLimits::unlimited())
                        .unwrap()
                        .count
                );
                assert_eq!(
                    span,
                    general_span
                        .span_sum(haystack, OrderedLiteralAggregateReduceLimits::unlimited())
                        .unwrap()
                        .span_sum
                );
            }
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "table-like exact/one-below assertions keep every packed limit visible"
    )]
    fn every_nonzero_limit_has_exact_and_one_below_behavior() {
        let patterns = [b"ab".as_slice(), b"a".as_slice(), b"\xFF\x00".as_slice()];
        let baseline =
            PackedOrderedLiteralCountPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let build = baseline.build_accounting();
        let exact = BuildLimits {
            max_patterns: build.patterns,
            max_pattern_bytes: build.max_pattern_bytes,
            max_total_pattern_bytes: build.pattern_bytes,
            max_identity_bytes: build.identity_bytes,
            max_build_work: build.build_work_upper_bound,
            max_build_peak_bytes: build.build_peak_upper_bound,
            max_persistent_bytes: build.persistent_bytes,
        };
        PackedOrderedLiteralCountPlan::build(&patterns, exact).unwrap();
        let build_cases = [
            BuildLimits {
                max_patterns: exact.max_patterns.checked_sub(1).unwrap(),
                ..exact
            },
            BuildLimits {
                max_pattern_bytes: exact.max_pattern_bytes.checked_sub(1).unwrap(),
                ..exact
            },
            BuildLimits {
                max_total_pattern_bytes: exact.max_total_pattern_bytes.checked_sub(1).unwrap(),
                ..exact
            },
            BuildLimits {
                max_identity_bytes: exact.max_identity_bytes.checked_sub(1).unwrap(),
                ..exact
            },
            BuildLimits {
                max_build_work: exact.max_build_work.checked_sub(1).unwrap(),
                ..exact
            },
            BuildLimits {
                max_build_peak_bytes: exact.max_build_peak_bytes.checked_sub(1).unwrap(),
                ..exact
            },
            BuildLimits {
                max_persistent_bytes: exact.max_persistent_bytes.checked_sub(1).unwrap(),
                ..exact
            },
        ];
        for limits in build_cases {
            assert!(PackedOrderedLiteralCountPlan::build(&patterns, limits).is_err());
        }

        let haystack = b"ababa\xFF\x00";
        let result = baseline.count(haystack, ReduceLimits::unlimited()).unwrap();
        let upper = result.accounting.upper_bounds;
        let reduce_exact = ReduceLimits {
            max_work: upper.work,
            max_match_events: upper.match_events,
            max_count: upper.count,
            max_span_sum: u64::MAX,
            max_reducer_steps: upper.reducer_steps,
            max_scratch_bytes: upper.scratch_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        baseline.count(haystack, reduce_exact).unwrap();
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_work: reduce_exact.max_work.checked_sub(1).unwrap(),
                    ..reduce_exact
                }
            ),
            Err(ReduceError::WorkLimit { .. })
        ));
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_match_events: reduce_exact.max_match_events.checked_sub(1).unwrap(),
                    ..reduce_exact
                }
            ),
            Err(ReduceError::MatchEventsLimit { .. })
        ));
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_count: reduce_exact.max_count.checked_sub(1).unwrap(),
                    ..reduce_exact
                }
            ),
            Err(ReduceError::CountLimit { .. })
        ));
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_reducer_steps: reduce_exact.max_reducer_steps.checked_sub(1).unwrap(),
                    ..reduce_exact
                }
            ),
            Err(ReduceError::ReducerStepsLimit { .. })
        ));
        assert!(matches!(
            baseline.count(
                haystack,
                ReduceLimits {
                    max_peak_bytes: reduce_exact.max_peak_bytes.checked_sub(1).unwrap(),
                    ..reduce_exact
                }
            ),
            Err(ReduceError::PeakLimit { .. })
        ));

        let span_plan =
            PackedOrderedLiteralSpanSumPlan::build(&patterns, BuildLimits::unlimited()).unwrap();
        let span = span_plan
            .span_sum(haystack, ReduceLimits::unlimited())
            .unwrap();
        let span_upper = span.accounting.upper_bounds;
        assert!(matches!(
            span_plan.span_sum(
                haystack,
                ReduceLimits {
                    max_span_sum: span_upper.span_sum.checked_sub(1).unwrap(),
                    ..ReduceLimits::unlimited()
                }
            ),
            Err(ReduceError::SpanSumLimit { .. })
        ));
    }

    #[test]
    fn theorem_refuses_empty_count_width_and_total_outside_absolute_bounds() {
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build::<&[u8]>(&[], BuildLimits::unlimited()),
            Err(BuildError::EmptyPatternSet)
        ));
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build(&[b"".as_slice()], BuildLimits::unlimited()),
            Err(BuildError::EmptyPattern { index: 0 })
        ));
        let too_many = vec![b"a".as_slice(); super::CERTIFIED_MAX_PATTERNS + 1];
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build(&too_many, BuildLimits::unlimited()),
            Err(BuildError::ProofRefused {
                fact: "pattern count",
                ..
            })
        ));
        let too_wide = vec![b'a'; super::CERTIFIED_MAX_PATTERN_BYTES + 1];
        assert!(matches!(
            PackedOrderedLiteralCountPlan::build(&[too_wide], BuildLimits::unlimited()),
            Err(BuildError::ProofRefused {
                fact: "literal width",
                ..
            })
        ));
    }
}
