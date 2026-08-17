//! Complete-span visitation for `BYTE_CLASS+ DELIMITER BYTE_CLASS+`.
//!
//! Admission proves that both greedy nonempty fields use the same byte class
//! and that the one-byte delimiter is excluded from that class. Every
//! delimiter therefore has at most one leftmost candidate: the maximal class
//! run immediately before it. When the following byte starts another class
//! run, greediness fixes the end at that run's maximum. A single monotone
//! delimiter stream plus disjoint outward class scans consequently preserves
//! Rust leftmost-first, non-overlapping spans in linear time and constant
//! space.

use core::{fmt, mem::size_of};

use memchr::memchr_iter;

use crate::{
    BoundedSeparatedFieldsBuildLimits as BuildLimits,
    BoundedSeparatedFieldsReduceLimits as ReduceLimits, DirectBuildAttempt,
    DirectBuildAttemptActual, DirectBuildAttemptError,
};

/// Stable identity of the proved language and physical traversal.
pub const PLAN_ID: &str = "delimiter-field-spans.byte-class-plus-delimiter-byte-class-plus.v1";
/// Stable identity of allocation-free complete-span visitation.
pub const SPAN_VISIT_OPERATION_ID: &str =
    "delimiter-field-spans.span-visit.leftmost-greedy-nonoverlap.v1";

const BITMAP_WORDS: usize = 4;
const FIXED_BUILD_WORK: usize = 8;
const RANGE_BUILD_WORK: usize = 4;
const FINALIZATION_WORK: usize = 8;

/// Exact semantic and physical identity of the visitor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent semantic proof facts remain explicit in the public identity"
)]
pub struct OperationIdentity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub class_words: [u64; BITMAP_WORDS],
    pub delimiter: u8,
    pub unicode: bool,
    pub greedy: bool,
    pub delimiter_excluded: bool,
    pub leftmost_first: bool,
    pub non_overlapping: bool,
}

/// Allocation-free construction receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuildAccounting {
    pub source_ranges: usize,
    pub bitmap_word_writes: usize,
    pub class_members: usize,
    pub delimiter: u8,
    pub work: usize,
    pub allocations: usize,
    pub reserves: usize,
    pub temporary_copies: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Source-free full-input execution bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceUpperBounds {
    pub input_bytes: usize,
    pub delimiter_scan_bytes: usize,
    pub delimiter_events: usize,
    pub membership_tests: usize,
    pub sequential_bytes: usize,
    pub match_events: usize,
    pub span_sum: usize,
    pub work: usize,
    pub allocations: usize,
    pub reserves: usize,
    pub temporary_copies: usize,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

/// Exact structural counters observed by a completed traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceActualCounters {
    pub input_bytes: usize,
    pub delimiter_scan_bytes: usize,
    pub delimiter_events: usize,
    pub membership_tests: usize,
    pub sequential_bytes: usize,
    pub match_events: usize,
    pub matched_bytes: usize,
    pub work: usize,
}

/// Complete execution certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReduceAccounting {
    pub identity: OperationIdentity,
    pub upper_bounds: ReduceUpperBounds,
    pub actual: ReduceActualCounters,
}

/// One complete non-overlapping match span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteSpan {
    pub start: usize,
    pub end: usize,
}

/// Summary of one allocation-free complete-span traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpanVisitResult {
    pub matches: usize,
    pub span_sum: usize,
    pub accounting: ReduceAccounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildError {
    EmptyClass,
    ReversedRange { start: u8, end: u8 },
    NonCanonicalRanges,
    DelimiterInClass { delimiter: u8 },
    RangeLimit { needed: usize, limit: usize },
    WorkLimit { needed: usize, limit: usize },
    PersistentLimit { needed: usize, limit: usize },
    PeakLimit { needed: usize, limit: usize },
    ArithmeticOverflow { computation: &'static str },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "delimiter-field span construction failed: {self:?}"
        )
    }
}

impl std::error::Error for BuildError {}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReduceError {
    InputLimit {
        needed: usize,
        limit: usize,
    },
    SequentialLimit {
        needed: usize,
        limit: usize,
    },
    MatchLimit {
        needed: u64,
        limit: u64,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    PeakLimit {
        needed: usize,
        limit: usize,
    },
    AccountingInvariant {
        counter: &'static str,
        actual: usize,
        bound: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for ReduceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "delimiter-field span traversal failed: {self:?}")
    }
}

impl std::error::Error for ReduceError {}

/// Immutable, allocation-free delimiter-field visitor.
#[derive(Debug)]
pub struct DelimiterFieldSpansPlan {
    class_words: [u64; BITMAP_WORDS],
    delimiter: u8,
    build: BuildAccounting,
}

impl DelimiterFieldSpansPlan {
    pub fn build<I>(ranges: I, delimiter: u8, limits: BuildLimits) -> Result<Self, BuildError>
    where
        I: Clone + ExactSizeIterator<Item = (u8, u8)>,
    {
        Self::build_attempt(ranges, delimiter, limits)
            .map(DirectBuildAttempt::into_plan)
            .map_err(DirectBuildAttemptError::into_source)
    }

    /// Build while retaining exact successful or partial terminal effects.
    #[allow(
        clippy::too_many_lines,
        reason = "one failure-atomic transaction keeps preflight and every partial build effect adjacent"
    )]
    pub fn build_attempt<I>(
        ranges: I,
        delimiter: u8,
        limits: BuildLimits,
    ) -> Result<DirectBuildAttempt<Self>, DirectBuildAttemptError<BuildError>>
    where
        I: Clone + ExactSizeIterator<Item = (u8, u8)>,
    {
        let mut actual = DirectBuildAttemptActual::default();
        let result = (|| {
            let source_ranges = ranges.len();
            if source_ranges == 0 {
                return Err(BuildError::EmptyClass);
            }
            if source_ranges > limits.max_source_ranges {
                return Err(BuildError::RangeLimit {
                    needed: source_ranges,
                    limit: limits.max_source_ranges,
                });
            }
            let work = source_ranges
                .checked_mul(RANGE_BUILD_WORK)
                .and_then(|work| work.checked_add(FIXED_BUILD_WORK))
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "complete build work",
                })?;
            if work > limits.max_build_work {
                return Err(BuildError::WorkLimit {
                    needed: work,
                    limit: limits.max_build_work,
                });
            }
            let persistent_bytes = size_of::<Self>();
            if persistent_bytes > limits.max_persistent_bytes {
                return Err(BuildError::PersistentLimit {
                    needed: persistent_bytes,
                    limit: limits.max_persistent_bytes,
                });
            }
            if persistent_bytes > limits.max_peak_bytes {
                return Err(BuildError::PeakLimit {
                    needed: persistent_bytes,
                    limit: limits.max_peak_bytes,
                });
            }

            let mut class_words = [0_u64; BITMAP_WORDS];
            let mut previous_end = None;
            let mut bitmap_word_writes = 0_usize;
            for (start, end) in ranges {
                charge_build_work(&mut actual, RANGE_BUILD_WORK)?;
                if start > end {
                    return Err(BuildError::ReversedRange { start, end });
                }
                if previous_end.is_some_and(|previous| previous >= start) {
                    return Err(BuildError::NonCanonicalRanges);
                }
                previous_end = Some(end);
                bitmap_word_writes = bitmap_word_writes
                    .checked_add(insert_range(&mut class_words, start, end)?)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "bitmap word writes",
                    })?;
            }
            charge_build_work(&mut actual, FIXED_BUILD_WORK)?;
            if class_contains(class_words, delimiter) {
                return Err(BuildError::DelimiterInClass { delimiter });
            }
            let class_members = class_words.iter().try_fold(0_usize, |total, word| {
                total
                    .checked_add(usize::try_from(word.count_ones()).map_err(|_| {
                        BuildError::ArithmeticOverflow {
                            computation: "class member population",
                        }
                    })?)
                    .ok_or(BuildError::ArithmeticOverflow {
                        computation: "class member population",
                    })
            })?;
            if class_members == 0 {
                return Err(BuildError::EmptyClass);
            }
            debug_assert_eq!(usize::try_from(actual.work), Ok(work));
            actual.copied_bytes = source_ranges.checked_mul(size_of::<(u8, u8)>()).ok_or(
                BuildError::ArithmeticOverflow {
                    computation: "source range copied bytes",
                },
            )?;
            actual.initialized_bytes = persistent_bytes;
            actual.live_persistent_bytes = persistent_bytes;
            actual.peak_bytes = persistent_bytes;
            Ok(Self {
                class_words,
                delimiter,
                build: BuildAccounting {
                    source_ranges,
                    bitmap_word_writes,
                    class_members,
                    delimiter,
                    work,
                    allocations: 0,
                    reserves: 0,
                    temporary_copies: 0,
                    scratch_bytes: 0,
                    persistent_bytes,
                    peak_bytes: persistent_bytes,
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
    pub const fn span_visit_identity(&self) -> OperationIdentity {
        OperationIdentity {
            plan_id: PLAN_ID,
            operation_id: SPAN_VISIT_OPERATION_ID,
            class_words: self.class_words,
            delimiter: self.delimiter,
            unicode: false,
            greedy: true,
            delimiter_excluded: true,
            leftmost_first: true,
            non_overlapping: true,
        }
    }

    /// Derive the complete full-input envelope without reading source bytes.
    pub fn full_window_upper_bounds(
        &self,
        input_bytes: usize,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        let membership_tests =
            input_bytes
                .checked_mul(2)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "membership-test bound",
                })?;
        let sequential_bytes =
            input_bytes
                .checked_add(membership_tests)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "sequential-byte bound",
                })?;
        let match_events = input_bytes / 3;
        let work = sequential_bytes
            .checked_add(input_bytes)
            .and_then(|work| work.checked_add(match_events))
            .and_then(|work| work.checked_add(FINALIZATION_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "complete traversal work",
            })?;
        Ok(ReduceUpperBounds {
            input_bytes,
            delimiter_scan_bytes: input_bytes,
            delimiter_events: input_bytes,
            membership_tests,
            sequential_bytes,
            match_events,
            span_sum: input_bytes,
            work,
            allocations: 0,
            reserves: 0,
            temporary_copies: 0,
            scratch_bytes: 0,
            persistent_bytes: self.build.persistent_bytes,
            peak_bytes: self.build.persistent_bytes,
        })
    }

    /// Visit every complete leftmost-first non-overlapping span.
    ///
    /// All caller limits are checked before the delimiter iterator reads one
    /// source byte or invokes `visitor`.
    #[allow(
        clippy::too_many_lines,
        reason = "one monotone traversal keeps source access and the exact actual-counter ledger adjacent"
    )]
    pub fn visit_spans<F>(
        &self,
        haystack: &[u8],
        limits: ReduceLimits,
        mut visitor: F,
    ) -> Result<SpanVisitResult, ReduceError>
    where
        F: FnMut(CompleteSpan),
    {
        let upper = self.preflight(haystack.len(), limits)?;
        let mut next_start = 0_usize;
        let mut delimiter_events = 0_usize;
        let mut membership_tests = 0_usize;
        let mut matches = 0_usize;
        let mut span_sum = 0_usize;

        for delimiter in memchr_iter(self.delimiter, haystack) {
            delimiter_events = checked_add(delimiter_events, 1, "delimiter events")?;
            if delimiter < next_start {
                continue;
            }
            let mut start = delimiter;
            while start > next_start {
                membership_tests = checked_add(membership_tests, 1, "left membership tests")?;
                let previous = start
                    .checked_sub(1)
                    .ok_or(ReduceError::ArithmeticOverflow {
                        computation: "left field predecessor",
                    })?;
                if !class_contains(self.class_words, haystack[previous]) {
                    break;
                }
                start = previous;
            }
            if start == delimiter {
                continue;
            }
            let Some(mut end) = delimiter.checked_add(1) else {
                return Err(ReduceError::ArithmeticOverflow {
                    computation: "post-delimiter offset",
                });
            };
            let right_start = end;
            while end < haystack.len() {
                membership_tests = checked_add(membership_tests, 1, "right membership tests")?;
                if !class_contains(self.class_words, haystack[end]) {
                    break;
                }
                end = end.checked_add(1).ok_or(ReduceError::ArithmeticOverflow {
                    computation: "right field successor",
                })?;
            }
            if end == right_start {
                continue;
            }
            let width = end
                .checked_sub(start)
                .ok_or(ReduceError::ArithmeticOverflow {
                    computation: "matched width",
                })?;
            matches = checked_add(matches, 1, "match events")?;
            span_sum = checked_add(span_sum, width, "matched byte sum")?;
            next_start = end;
            visitor(CompleteSpan { start, end });
        }

        let sequential_bytes = checked_add(
            upper.delimiter_scan_bytes,
            membership_tests,
            "actual sequential bytes",
        )?;
        let work = sequential_bytes
            .checked_add(delimiter_events)
            .and_then(|work| work.checked_add(matches))
            .and_then(|work| work.checked_add(FINALIZATION_WORK))
            .ok_or(ReduceError::ArithmeticOverflow {
                computation: "actual traversal work",
            })?;
        for (counter, actual, bound) in [
            ("delimiter events", delimiter_events, upper.delimiter_events),
            ("membership tests", membership_tests, upper.membership_tests),
            ("sequential bytes", sequential_bytes, upper.sequential_bytes),
            ("match events", matches, upper.match_events),
            ("matched byte sum", span_sum, upper.span_sum),
            ("work", work, upper.work),
        ] {
            if actual > bound {
                return Err(ReduceError::AccountingInvariant {
                    counter,
                    actual,
                    bound,
                });
            }
        }
        let actual = ReduceActualCounters {
            input_bytes: haystack.len(),
            delimiter_scan_bytes: upper.delimiter_scan_bytes,
            delimiter_events,
            membership_tests,
            sequential_bytes,
            match_events: matches,
            matched_bytes: span_sum,
            work,
        };
        Ok(SpanVisitResult {
            matches,
            span_sum,
            accounting: ReduceAccounting {
                identity: self.span_visit_identity(),
                upper_bounds: upper,
                actual,
            },
        })
    }

    fn preflight(
        &self,
        input_bytes: usize,
        limits: ReduceLimits,
    ) -> Result<ReduceUpperBounds, ReduceError> {
        if input_bytes > limits.max_input_bytes {
            return Err(ReduceError::InputLimit {
                needed: input_bytes,
                limit: limits.max_input_bytes,
            });
        }
        let upper = self.full_window_upper_bounds(input_bytes)?;
        if upper.sequential_bytes > limits.max_sequential_bytes {
            return Err(ReduceError::SequentialLimit {
                needed: upper.sequential_bytes,
                limit: limits.max_sequential_bytes,
            });
        }
        let match_events =
            u64::try_from(upper.match_events).map_err(|_| ReduceError::ArithmeticOverflow {
                computation: "match event bound as u64",
            })?;
        if match_events > limits.max_count {
            return Err(ReduceError::MatchLimit {
                needed: match_events,
                limit: limits.max_count,
            });
        }
        if upper.work > limits.max_work {
            return Err(ReduceError::WorkLimit {
                needed: upper.work,
                limit: limits.max_work,
            });
        }
        if upper.peak_bytes > limits.max_peak_bytes {
            return Err(ReduceError::PeakLimit {
                needed: upper.peak_bytes,
                limit: limits.max_peak_bytes,
            });
        }
        Ok(upper)
    }
}

fn charge_build_work(
    actual: &mut DirectBuildAttemptActual,
    amount: usize,
) -> Result<(), BuildError> {
    actual.work = actual
        .work
        .checked_add(
            u64::try_from(amount).map_err(|_| BuildError::ArithmeticOverflow {
                computation: "build work conversion",
            })?,
        )
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "build work",
        })?;
    Ok(())
}

fn insert_range(words: &mut [u64; BITMAP_WORDS], start: u8, end: u8) -> Result<usize, BuildError> {
    let first = usize::from(start) >> 6;
    let last = usize::from(end) >> 6;
    let selected = words
        .get_mut(first..=last)
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "bitmap word range",
        })?;
    for (relative, slot) in selected.iter_mut().enumerate() {
        let word = first
            .checked_add(relative)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "bitmap word index",
            })?;
        let first_bit = if word == first {
            u32::from(start) & 63
        } else {
            0
        };
        let last_bit = if word == last {
            u32::from(end) & 63
        } else {
            63
        };
        let first_mask = u64::MAX
            .checked_shl(first_bit)
            .ok_or(BuildError::ArithmeticOverflow {
                computation: "bitmap first shift",
            })?;
        let last_mask =
            u64::MAX
                .checked_shr(63_u32.checked_sub(last_bit).ok_or(
                    BuildError::ArithmeticOverflow {
                        computation: "bitmap last shift",
                    },
                )?)
                .ok_or(BuildError::ArithmeticOverflow {
                    computation: "bitmap last shift",
                })?;
        *slot |= first_mask & last_mask;
    }
    last.checked_sub(first)
        .and_then(|width| width.checked_add(1))
        .ok_or(BuildError::ArithmeticOverflow {
            computation: "bitmap word writes",
        })
}

#[inline]
fn class_contains(words: [u64; BITMAP_WORDS], byte: u8) -> bool {
    words[usize::from(byte) >> 6] & (1_u64 << (u32::from(byte) & 63)) != 0
}

fn checked_add(left: usize, right: usize, computation: &'static str) -> Result<usize, ReduceError> {
    left.checked_add(right)
        .ok_or(ReduceError::ArithmeticOverflow { computation })
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;

    use super::{
        BuildError, BuildLimits, CompleteSpan, DelimiterFieldSpansPlan, ReduceError, ReduceLimits,
    };

    fn plan() -> DelimiterFieldSpansPlan {
        DelimiterFieldSpansPlan::build([(b'a', b'b')].into_iter(), b'@', BuildLimits::default())
            .unwrap()
    }

    fn oracle(regex: &regex::bytes::Regex, haystack: &[u8]) -> Vec<CompleteSpan> {
        regex
            .find_iter(haystack)
            .map(|matched| CompleteSpan {
                start: matched.start(),
                end: matched.end(),
            })
            .collect()
    }

    #[test]
    fn exhaustive_small_haystacks_match_regex_oracle() {
        let plan = plan();
        let regex = RegexBuilder::new(r"[ab]+@[ab]+")
            .unicode(false)
            .build()
            .unwrap();
        let alphabet = [b'a', b'b', b'@', b'!'];
        for length in 0_u32..=8 {
            let cases = alphabet.len().pow(length);
            for mut encoded in 0..cases {
                let mut haystack = vec![0_u8; usize::try_from(length).unwrap()];
                for byte in &mut haystack {
                    *byte = alphabet[encoded % alphabet.len()];
                    encoded /= alphabet.len();
                }
                let mut actual = Vec::new();
                let result = plan
                    .visit_spans(&haystack, ReduceLimits::default(), |span| actual.push(span))
                    .unwrap();
                let expected = oracle(&regex, &haystack);
                assert_eq!(actual, expected, "haystack={haystack:?}");
                assert_eq!(result.matches, expected.len());
                assert_eq!(
                    result.span_sum,
                    expected.iter().map(|span| span.end - span.start).sum()
                );
            }
        }
    }

    #[test]
    fn dense_delimiters_and_dense_matches_stay_inside_linear_ledgers() {
        let plan = plan();
        let delimiters = vec![b'@'; 32 * 1024];
        let mut callbacks = 0_usize;
        let result = plan
            .visit_spans(&delimiters, ReduceLimits::default(), |_| callbacks += 1)
            .unwrap();
        assert_eq!(callbacks, 0);
        assert_eq!(result.matches, 0);
        assert!(
            result.accounting.actual.membership_tests
                <= result.accounting.upper_bounds.membership_tests
        );

        let dense = b"a@a!".repeat(8 * 1024);
        let result = plan
            .visit_spans(&dense, ReduceLimits::default(), |_| callbacks += 1)
            .unwrap();
        assert_eq!(result.matches, 8 * 1024);
        assert_eq!(result.span_sum, 3 * 8 * 1024);
        assert_eq!(callbacks, 8 * 1024);
        assert!(result.accounting.actual.work <= result.accounting.upper_bounds.work);
    }

    #[test]
    fn construction_rejects_noncanonical_and_delimiter_bearing_classes() {
        assert!(matches!(
            DelimiterFieldSpansPlan::build(core::iter::empty(), b'@', BuildLimits::default()),
            Err(BuildError::EmptyClass)
        ));
        assert!(matches!(
            DelimiterFieldSpansPlan::build(
                [(b'z', b'a')].into_iter(),
                b'@',
                BuildLimits::default()
            ),
            Err(BuildError::ReversedRange { .. })
        ));
        assert!(matches!(
            DelimiterFieldSpansPlan::build(
                [(b'!', b'z')].into_iter(),
                b'@',
                BuildLimits::default()
            ),
            Err(BuildError::DelimiterInClass { delimiter: b'@' })
        ));
    }

    #[test]
    fn every_execution_refusal_precedes_callbacks() {
        let plan = plan();
        let haystack = b"aa@bb!a@b";
        let upper = plan.full_window_upper_bounds(haystack.len()).unwrap();
        let exact = ReduceLimits {
            max_input_bytes: upper.input_bytes,
            max_sequential_bytes: upper.sequential_bytes,
            max_count: u64::try_from(upper.match_events).unwrap(),
            max_work: upper.work,
            max_peak_bytes: upper.peak_bytes,
        };
        let mut callbacks = 0_usize;
        plan.visit_spans(haystack, exact, |_| callbacks += 1)
            .unwrap();
        assert_eq!(callbacks, 2);

        for refused in [
            ReduceLimits {
                max_input_bytes: upper.input_bytes - 1,
                ..exact
            },
            ReduceLimits {
                max_sequential_bytes: upper.sequential_bytes - 1,
                ..exact
            },
            ReduceLimits {
                max_count: u64::try_from(upper.match_events - 1).unwrap(),
                ..exact
            },
            ReduceLimits {
                max_work: upper.work - 1,
                ..exact
            },
            ReduceLimits {
                max_peak_bytes: upper.peak_bytes - 1,
                ..exact
            },
        ] {
            callbacks = 0;
            let error = plan
                .visit_spans(haystack, refused, |_| callbacks += 1)
                .unwrap_err();
            assert!(matches!(
                error,
                ReduceError::InputLimit { .. }
                    | ReduceError::SequentialLimit { .. }
                    | ReduceError::MatchLimit { .. }
                    | ReduceError::WorkLimit { .. }
                    | ReduceError::PeakLimit { .. }
            ));
            assert_eq!(callbacks, 0);
        }
    }
}
