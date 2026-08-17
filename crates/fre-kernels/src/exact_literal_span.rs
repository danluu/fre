//! Allocation-free complete-span traversal over an exact-literal plan.
//!
//! The existing [`LiteralPlan`] remains the only literal owner. This module
//! only adds an operation view over its retained `memmem::Finder`: empty
//! literals visit every byte boundary, one-byte literals use `memchr`, and
//! wider literals replay the retained finder over monotonically disjoint
//! suffixes. Advancing by the complete literal width preserves successive
//! leftmost non-overlapping Rust-bytes matches, including overlapping-candidate
//! cases such as `aa` in `aaa`.
//!
//! Every caller-controlled limit is checked from the input length and the
//! retained literal width before the first haystack read or callback.

use core::fmt;

use memchr::memchr;

use super::LiteralPlan;

/// Stable identity for direct exact-literal complete-span visitation.
pub const SPAN_VISIT_OPERATION_ID: &str = "exact-literal.span-visit.v1";

/// Semantics authenticated by the retained exact-literal plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    /// Stable operation implementation identity.
    pub operation_id: &'static str,
    /// Exact retained literal width.
    pub literal_bytes: usize,
    /// Whether empty literals match at every byte boundary.
    pub byte_empty_progress: bool,
    /// Whether candidate selection is leftmost.
    pub leftmost: bool,
    /// Whether iteration restarts at the preceding match end.
    pub non_overlapping: bool,
}

/// Source-independent resource envelope for one complete traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpperBounds {
    /// Immutable haystack bytes accepted by the operation.
    pub input_bytes: usize,
    /// Exact retained literal width.
    pub literal_bytes: usize,
    /// Whole-operation linear terms, matching the incumbent literal bound.
    pub linear_terms: usize,
    /// Maximum calls to `memchr` or the retained `memmem::Finder`.
    pub finder_calls: usize,
    /// Maximum complete match callbacks.
    pub match_events: usize,
    /// Maximum sum of visited match widths.
    pub span_sum: u64,
    /// Operation scratch storage. Traversal is allocation-free.
    pub scratch_bytes: usize,
    /// Logical bytes retained by the existing literal owner.
    pub persistent_bytes: usize,
    /// Maximum simultaneous logical operation storage.
    pub peak_bytes: usize,
}

/// Exact no-clock counters from one completed traversal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Actual {
    /// Calls made to `memchr` or the retained `memmem::Finder`.
    pub finder_calls: usize,
    /// Complete matches supplied to the visitor.
    pub matches: usize,
    /// Sum of visited match widths.
    pub span_sum: u64,
}

/// Complete prospective and actual operation receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    /// Authenticated operation semantics.
    pub identity: Identity,
    /// Source-independent preflight envelope.
    pub upper_bounds: UpperBounds,
    /// Exact completed traversal counters.
    pub actual: Actual,
}

/// Hard limits checked before source access or the first callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_linear_terms: usize,
    pub max_finder_calls: usize,
    pub max_match_events: usize,
    pub max_span_sum: u64,
    pub max_scratch_bytes: usize,
    pub max_persistent_bytes: usize,
    pub max_peak_bytes: usize,
}

impl Limits {
    /// Limits that admit every representable execution.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_linear_terms: usize::MAX,
            max_finder_calls: usize::MAX,
            max_match_events: usize::MAX,
            max_span_sum: u64::MAX,
            max_scratch_bytes: usize::MAX,
            max_persistent_bytes: usize::MAX,
            max_peak_bytes: usize::MAX,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_linear_terms: 128 * 1024 * 1024,
            max_finder_calls: 64 * 1024 * 1024,
            max_match_events: 64 * 1024 * 1024,
            max_span_sum: 64 * 1024 * 1024,
            max_scratch_bytes: 0,
            max_persistent_bytes: 32 * 1024 * 1024,
            max_peak_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Checked refusal from direct exact-literal span visitation.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    ArithmeticOverflow { computation: &'static str },
    InputBytesLimit { needed: usize, limit: usize },
    LinearTermLimit { needed: usize, limit: usize },
    FinderCallLimit { needed: usize, limit: usize },
    MatchEventLimit { needed: usize, limit: usize },
    SpanSumLimit { needed: u64, limit: u64 },
    ScratchLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    InternalInvariant(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArithmeticOverflow { computation } => {
                write!(
                    formatter,
                    "exact-literal span visitor {computation} overflowed"
                )
            }
            Self::InputBytesLimit { needed, limit } => write!(
                formatter,
                "exact-literal span visitor needs {needed} input bytes, limit is {limit}",
            ),
            Self::LinearTermLimit { needed, limit } => write!(
                formatter,
                "exact-literal span visitor needs {needed} linear terms, limit is {limit}",
            ),
            Self::FinderCallLimit { needed, limit } => write!(
                formatter,
                "exact-literal span visitor needs {needed} finder calls, limit is {limit}",
            ),
            Self::MatchEventLimit { needed, limit } => write!(
                formatter,
                "exact-literal span visitor needs {needed} match events, limit is {limit}",
            ),
            Self::SpanSumLimit { needed, limit } => write!(
                formatter,
                "exact-literal span visitor needs span sum {needed}, limit is {limit}",
            ),
            Self::ScratchLimit { needed, limit } => write!(
                formatter,
                "exact-literal span visitor needs {needed} scratch bytes, limit is {limit}",
            ),
            Self::PersistentLimit { needed, limit } => write!(
                formatter,
                "exact-literal span visitor needs {needed} persistent bytes, limit is {limit}",
            ),
            Self::PeakLimit { needed, limit } => write!(
                formatter,
                "exact-literal span visitor needs {needed} peak bytes, limit is {limit}",
            ),
            Self::InternalInvariant(detail) => {
                write!(
                    formatter,
                    "exact-literal span visitor invariant failed: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

/// One complete selected match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteSpan {
    pub start: usize,
    pub end: usize,
}

/// Summary of one allocation-free complete traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanVisitResult {
    pub matches: usize,
    pub span_sum: u64,
    pub accounting: Accounting,
}

impl LiteralPlan {
    /// Visit every successive leftmost non-overlapping exact-literal match.
    ///
    /// All source-independent resource limits are checked before the first
    /// haystack read or callback. Execution reuses this plan's retained
    /// `memmem::Finder` and allocates no operation storage.
    ///
    /// # Errors
    ///
    /// Returns a checked arithmetic or resource refusal. Resource refusals
    /// occur before the visitor is called.
    #[inline]
    pub fn visit_spans<F>(
        &self,
        haystack: &[u8],
        limits: Limits,
        mut visitor: F,
    ) -> Result<SpanVisitResult, Error>
    where
        F: FnMut(CompleteSpan),
    {
        let upper_bounds = self.span_visit_preflight(haystack.len(), limits)?;
        let actual = self.visit_spans_after_preflight(haystack, &mut visitor)?;
        if actual.finder_calls > upper_bounds.finder_calls
            || actual.matches > upper_bounds.match_events
            || actual.span_sum > upper_bounds.span_sum
        {
            return Err(Error::InternalInvariant(
                "actual traversal exceeded its source-independent envelope",
            ));
        }
        Ok(SpanVisitResult {
            matches: actual.matches,
            span_sum: actual.span_sum,
            accounting: Accounting {
                identity: self.span_visit_identity(),
                upper_bounds,
                actual,
            },
        })
    }

    #[inline]
    fn span_visit_identity(&self) -> Identity {
        Identity {
            operation_id: SPAN_VISIT_OPERATION_ID,
            literal_bytes: self.needle_bytes,
            byte_empty_progress: true,
            leftmost: true,
            non_overlapping: true,
        }
    }

    fn span_visit_preflight(
        &self,
        input_bytes: usize,
        limits: Limits,
    ) -> Result<UpperBounds, Error> {
        let literal_bytes = self.needle_bytes;
        let linear_terms =
            input_bytes
                .checked_add(literal_bytes)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "linear-term upper bound",
                })?;
        let (finder_calls, match_events) = if literal_bytes == 0 {
            let events = input_bytes
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "empty-literal match-event upper bound",
                })?;
            (0, events)
        } else if input_bytes < literal_bytes {
            (0, 0)
        } else {
            let events = input_bytes / literal_bytes;
            // A terminal miss replaces the last possible successful call.
            // After every success the cursor advances by `literal_bytes`, so
            // at most `floor(input_bytes / literal_bytes)` calls can run.
            (events, events)
        };
        let span_sum = match_events
            .checked_mul(literal_bytes)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(Error::ArithmeticOverflow {
                computation: "span-sum upper bound",
            })?;
        let scratch_bytes = 0;
        let persistent_bytes = self.storage_bytes();
        let peak_bytes = persistent_bytes;
        enforce_usize(input_bytes, limits.max_input_bytes, |needed, limit| {
            Error::InputBytesLimit { needed, limit }
        })?;
        enforce_usize(linear_terms, limits.max_linear_terms, |needed, limit| {
            Error::LinearTermLimit { needed, limit }
        })?;
        enforce_usize(finder_calls, limits.max_finder_calls, |needed, limit| {
            Error::FinderCallLimit { needed, limit }
        })?;
        enforce_usize(match_events, limits.max_match_events, |needed, limit| {
            Error::MatchEventLimit { needed, limit }
        })?;
        if span_sum > limits.max_span_sum {
            return Err(Error::SpanSumLimit {
                needed: span_sum,
                limit: limits.max_span_sum,
            });
        }
        enforce_usize(scratch_bytes, limits.max_scratch_bytes, |needed, limit| {
            Error::ScratchLimit { needed, limit }
        })?;
        enforce_usize(
            persistent_bytes,
            limits.max_persistent_bytes,
            |needed, limit| Error::PersistentLimit { needed, limit },
        )?;
        enforce_usize(peak_bytes, limits.max_peak_bytes, |needed, limit| {
            Error::PeakLimit { needed, limit }
        })?;
        Ok(UpperBounds {
            input_bytes,
            literal_bytes,
            linear_terms,
            finder_calls,
            match_events,
            span_sum,
            scratch_bytes,
            persistent_bytes,
            peak_bytes,
        })
    }

    #[inline]
    fn visit_spans_after_preflight<F>(
        &self,
        haystack: &[u8],
        visitor: &mut F,
    ) -> Result<Actual, Error>
    where
        F: FnMut(CompleteSpan),
    {
        let literal_bytes = self.needle_bytes;
        if literal_bytes == 0 {
            let mut matches = 0usize;
            for at in 0..=haystack.len() {
                visitor(CompleteSpan { start: at, end: at });
                matches = matches.checked_add(1).ok_or(Error::ArithmeticOverflow {
                    computation: "actual empty-literal match count",
                })?;
            }
            return Ok(Actual {
                finder_calls: 0,
                matches,
                span_sum: 0,
            });
        }

        let mut at = 0usize;
        let mut actual = Actual::default();
        while haystack.len().saturating_sub(at) >= literal_bytes {
            actual.finder_calls =
                actual
                    .finder_calls
                    .checked_add(1)
                    .ok_or(Error::ArithmeticOverflow {
                        computation: "actual finder-call count",
                    })?;
            let relative = if literal_bytes == 1 {
                memchr(self.finder.needle()[0], &haystack[at..])
            } else {
                self.finder.find(&haystack[at..])
            };
            let Some(relative) = relative else {
                break;
            };
            let start = at.checked_add(relative).ok_or(Error::ArithmeticOverflow {
                computation: "actual match start",
            })?;
            let end = start
                .checked_add(literal_bytes)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "actual match end",
                })?;
            actual.matches = actual
                .matches
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "actual match count",
                })?;
            actual.span_sum = actual
                .span_sum
                .checked_add(u64::try_from(literal_bytes).map_err(|_| {
                    Error::ArithmeticOverflow {
                        computation: "actual match width",
                    }
                })?)
                .ok_or(Error::ArithmeticOverflow {
                    computation: "actual span sum",
                })?;
            visitor(CompleteSpan { start, end });
            at = end;
        }
        Ok(actual)
    }
}

fn enforce_usize(
    needed: usize,
    limit: usize,
    error: fn(usize, usize) -> Error,
) -> Result<(), Error> {
    if needed > limit {
        Err(error(needed, limit))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{CompleteSpan, Error, Limits, SPAN_VISIT_OPERATION_ID};
    use crate::{LiteralBuildLimits, LiteralPlan, LiteralSearchLimits, Window};

    fn incumbent_spans(plan: &LiteralPlan, haystack: &[u8]) -> Vec<CompleteSpan> {
        if plan.needle().is_empty() {
            return (0..=haystack.len())
                .map(|at| CompleteSpan { start: at, end: at })
                .collect();
        }
        let mut at = 0usize;
        let mut spans = Vec::new();
        while at <= haystack.len() {
            let Some((start, end)) = plan
                .find_window(
                    haystack,
                    Window::new(at, haystack.len()),
                    LiteralSearchLimits::unlimited(),
                )
                .unwrap()
                .0
            else {
                break;
            };
            spans.push(CompleteSpan { start, end });
            at = end;
        }
        spans
    }

    #[test]
    fn complete_spans_replay_incumbent_across_empty_dense_and_overlap_cases() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"", b""),
            (b"", b"ab\xff"),
            (b"a", b""),
            (b"a", b"baaaab"),
            (b"aa", b"aaaaa"),
            (b"aba", b"abababa"),
            (b"needle", b"no match"),
            (b"needle", b"needleneedle-x-needle"),
            (b"\xff", b"a\xff\xffb"),
        ];
        for &(needle, haystack) in cases {
            let plan = LiteralPlan::new(needle, LiteralBuildLimits::default()).unwrap();
            let expected = incumbent_spans(&plan, haystack);
            let mut actual = Vec::new();
            let result = plan
                .visit_spans(haystack, Limits::unlimited(), |span| actual.push(span))
                .unwrap();
            assert_eq!(actual, expected, "needle={needle:?}, haystack={haystack:?}");
            assert_eq!(result.matches, expected.len());
            assert_eq!(result.accounting.actual.matches, result.matches);
            assert_eq!(result.accounting.actual.span_sum, result.span_sum);
            assert_eq!(
                result.accounting.identity.operation_id,
                SPAN_VISIT_OPERATION_ID
            );
            assert!(result.accounting.identity.byte_empty_progress);
            assert!(result.accounting.identity.leftmost);
            assert!(result.accounting.identity.non_overlapping);
        }
    }

    #[test]
    fn complete_span_limits_refuse_before_the_first_callback() {
        let plan = LiteralPlan::new(b"aa", LiteralBuildLimits::default()).unwrap();
        let haystack = b"aaaaa";
        let mut exact_spans = Vec::new();
        let exact = plan
            .visit_spans(haystack, Limits::unlimited(), |span| exact_spans.push(span))
            .unwrap();
        assert_eq!(exact.accounting.upper_bounds.finder_calls, 2);
        assert_eq!(exact.accounting.actual.finder_calls, 2);
        assert_eq!(exact.matches, 2);

        let upper = exact.accounting.upper_bounds;
        let exact_limits = Limits {
            max_input_bytes: upper.input_bytes,
            max_linear_terms: upper.linear_terms,
            max_finder_calls: upper.finder_calls,
            max_match_events: upper.match_events,
            max_span_sum: upper.span_sum,
            max_scratch_bytes: upper.scratch_bytes,
            max_persistent_bytes: upper.persistent_bytes,
            max_peak_bytes: upper.peak_bytes,
        };
        let mut replayed = Vec::new();
        let replay = plan
            .visit_spans(haystack, exact_limits, |span| replayed.push(span))
            .unwrap();
        assert_eq!(replayed, exact_spans);
        assert_eq!(replay.accounting.upper_bounds, upper);

        fn assert_precallback_refusal(
            plan: &LiteralPlan,
            haystack: &[u8],
            limits: Limits,
            expected: Error,
        ) {
            let mut callbacks = 0usize;
            let error = plan
                .visit_spans(haystack, limits, |_| callbacks += 1)
                .unwrap_err();
            assert_eq!(callbacks, 0);
            assert_eq!(error, expected);
        }

        assert_precallback_refusal(
            &plan,
            haystack,
            Limits {
                max_input_bytes: upper.input_bytes - 1,
                ..Limits::unlimited()
            },
            Error::InputBytesLimit {
                needed: upper.input_bytes,
                limit: upper.input_bytes - 1,
            },
        );
        assert_precallback_refusal(
            &plan,
            haystack,
            Limits {
                max_linear_terms: upper.linear_terms - 1,
                ..Limits::unlimited()
            },
            Error::LinearTermLimit {
                needed: upper.linear_terms,
                limit: upper.linear_terms - 1,
            },
        );
        assert_precallback_refusal(
            &plan,
            haystack,
            Limits {
                max_finder_calls: upper.finder_calls - 1,
                ..Limits::unlimited()
            },
            Error::FinderCallLimit {
                needed: upper.finder_calls,
                limit: upper.finder_calls - 1,
            },
        );
        assert_precallback_refusal(
            &plan,
            haystack,
            Limits {
                max_match_events: upper.match_events - 1,
                ..Limits::unlimited()
            },
            Error::MatchEventLimit {
                needed: upper.match_events,
                limit: upper.match_events - 1,
            },
        );
        assert_precallback_refusal(
            &plan,
            haystack,
            Limits {
                max_span_sum: upper.span_sum - 1,
                ..Limits::unlimited()
            },
            Error::SpanSumLimit {
                needed: upper.span_sum,
                limit: upper.span_sum - 1,
            },
        );
        assert_precallback_refusal(
            &plan,
            haystack,
            Limits {
                max_persistent_bytes: upper.persistent_bytes - 1,
                ..Limits::unlimited()
            },
            Error::PersistentLimit {
                needed: upper.persistent_bytes,
                limit: upper.persistent_bytes - 1,
            },
        );
        assert_precallback_refusal(
            &plan,
            haystack,
            Limits {
                max_peak_bytes: upper.peak_bytes - 1,
                ..Limits::unlimited()
            },
            Error::PeakLimit {
                needed: upper.peak_bytes,
                limit: upper.peak_bytes - 1,
            },
        );

        let mut callbacks = 0usize;
        let error = plan
            .visit_spans(
                haystack,
                Limits {
                    max_match_events: 1,
                    ..Limits::unlimited()
                },
                |_| callbacks += 1,
            )
            .unwrap_err();
        assert_eq!(callbacks, 0);
        assert!(matches!(
            error,
            Error::MatchEventLimit {
                needed: 2,
                limit: 1
            }
        ));

        let empty = LiteralPlan::new(b"", LiteralBuildLimits::default()).unwrap();
        let error = empty
            .visit_spans(
                haystack,
                Limits {
                    max_match_events: haystack.len(),
                    ..Limits::unlimited()
                },
                |_| callbacks += 1,
            )
            .unwrap_err();
        assert_eq!(callbacks, 0);
        assert!(matches!(
            error,
            Error::MatchEventLimit { needed, limit }
                if needed == haystack.len() + 1 && limit == haystack.len()
        ));
    }
}
