//! Whole-haystack match statistics and literal replacement.
//!
//! These are operation-level APIs over one prepared Span artifact. They do
//! not change the single-search output contract or the stable program wire.
//! This V1 surface is deliberately a two-pass semantic foundation: literal
//! replacement sizes in one complete selector pass and copies in a second.
//! It does not yet add a generated-object entry or avoid one prepared search
//! call per selected match; native fused selection and copying can be layered
//! on this contract without changing its byte semantics.

use crate::{AotRegexFindError, PreparedAotRegex};

/// Fused scalar statistics for complete non-overlapping match iteration.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct AotMatchStats {
    /// Number of selected matches, including empty matches.
    pub count: u64,
    /// Sum of selected half-open match widths in bytes.
    pub span_sum: u64,
}

/// Resource policy for one owned literal replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotLiteralReplacementLimits {
    /// Maximum exact logical length of the replacement result.
    pub max_output_bytes: usize,
    /// Maximum observed capacity of the retained result allocation.
    pub max_output_capacity_bytes: usize,
}

impl Default for AotLiteralReplacementLimits {
    fn default() -> Self {
        Self {
            max_output_bytes: 67_108_864,
            max_output_capacity_bytes: 67_108_864,
        }
    }
}

/// Exact accounting for a completed literal replacement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AotLiteralReplacementAccounting {
    /// Matches selected by each complete pass.
    pub replacements: u64,
    /// Matched haystack bytes removed by the replacement.
    pub matched_bytes: u64,
    /// Unmatched haystack bytes copied into the result.
    pub haystack_bytes_copied: usize,
    /// Literal replacement bytes copied into the result.
    pub replacement_bytes_copied: usize,
    /// Exact logical result length.
    pub output_bytes: usize,
    /// Observed retained allocation capacity.
    pub output_capacity_bytes: usize,
    /// Complete selector passes. V1 uses one sizing pass and one copy pass.
    pub selector_passes: u8,
}

/// Owned output of one bounded, literal/no-expansion replacement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AotLiteralReplacement {
    bytes: Vec<u8>,
    accounting: AotLiteralReplacementAccounting,
}

impl AotLiteralReplacement {
    /// Borrow the complete replacement bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume this result and return its bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Exact selector, copy and allocation accounting.
    #[must_use]
    pub const fn accounting(&self) -> AotLiteralReplacementAccounting {
        self.accounting
    }
}

/// Failure while sizing or producing an owned literal replacement.
#[derive(Debug)]
pub enum AotLiteralReplacementError {
    /// Complete Span selection failed.
    Find(AotRegexFindError),
    /// Exact result-length arithmetic exceeded `usize`.
    OutputLengthOverflow,
    /// The exact logical result exceeds the configured limit.
    OutputBytesLimit { needed: usize, limit: usize },
    /// The exact result allocation failed.
    AllocationFailed { requested: usize },
    /// Allocator capacity exceeds the configured retained-capacity limit.
    OutputCapacityBytesLimit { needed: usize, limit: usize },
    /// Two deterministic passes over one immutable input disagreed.
    InternalInvariant(&'static str),
}

impl std::fmt::Display for AotLiteralReplacementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Find(error) => write!(formatter, "literal replacement selection failed: {error}"),
            Self::OutputLengthOverflow => {
                formatter.write_str("literal replacement output length overflowed usize")
            }
            Self::OutputBytesLimit { needed, limit } => write!(
                formatter,
                "literal replacement needs {needed} output bytes, limit is {limit}"
            ),
            Self::AllocationFailed { requested } => write!(
                formatter,
                "failed to allocate {requested} literal replacement output bytes"
            ),
            Self::OutputCapacityBytesLimit { needed, limit } => write!(
                formatter,
                "literal replacement retained capacity is {needed} bytes, limit is {limit}"
            ),
            Self::InternalInvariant(detail) => {
                write!(formatter, "literal replacement invariant failed: {detail}")
            }
        }
    }
}

impl std::error::Error for AotLiteralReplacementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Find(error) => Some(error),
            Self::OutputLengthOverflow
            | Self::OutputBytesLimit { .. }
            | Self::AllocationFailed { .. }
            | Self::OutputCapacityBytesLimit { .. }
            | Self::InternalInvariant(_) => None,
        }
    }
}

impl From<AotRegexFindError> for AotLiteralReplacementError {
    fn from(value: AotRegexFindError) -> Self {
        Self::Find(value)
    }
}

impl PreparedAotRegex {
    /// Compute Count and matched-byte `SpanSum` in one complete selector pass.
    ///
    /// This follows the same non-overlap, repeated-empty suppression and
    /// byte-progress semantics as [`Self::find_iter`].
    pub fn match_stats(&mut self, haystack: &[u8]) -> Result<AotMatchStats, AotRegexFindError> {
        let mut stats = AotMatchStats::default();
        for matched in self.find_iter(haystack)? {
            let matched = matched?;
            stats.count = stats.count.checked_add(1).ok_or(AotRegexFindError::Search(
                fre_aot_regex::CompileError::InternalInvariant(
                    "prepared match-stat Count overflowed u64",
                ),
            ))?;
            let width = u64::try_from(matched.len()).map_err(|_| {
                AotRegexFindError::Search(fre_aot_regex::CompileError::InternalInvariant(
                    "prepared match-stat width did not fit u64",
                ))
            })?;
            stats.span_sum = stats
                .span_sum
                .checked_add(width)
                .ok_or(AotRegexFindError::Search(
                    fre_aot_regex::CompileError::InternalInvariant(
                        "prepared match-stat SpanSum overflowed u64",
                    ),
                ))?;
        }
        Ok(stats)
    }

    /// Replace every selected non-overlapping match with literal bytes.
    ///
    /// Dollar syntax is copied verbatim; this API never observes captures.
    /// It first obtains fused exact Count/SpanSum statistics, reserves the
    /// exact logical output once, then replays selection while copying gaps
    /// and replacement bytes. A failure drops private staging and publishes no
    /// partial result.
    pub fn replace_all_literal(
        &mut self,
        haystack: &[u8],
        replacement: &[u8],
        limits: AotLiteralReplacementLimits,
    ) -> Result<AotLiteralReplacement, AotLiteralReplacementError> {
        let stats = self.match_stats(haystack)?;
        let matched_bytes = usize::try_from(stats.span_sum)
            .map_err(|_| AotLiteralReplacementError::OutputLengthOverflow)?;
        let replacements = usize::try_from(stats.count)
            .map_err(|_| AotLiteralReplacementError::OutputLengthOverflow)?;
        let haystack_bytes_copied = haystack.len().checked_sub(matched_bytes).ok_or(
            AotLiteralReplacementError::InternalInvariant(
                "selected match bytes exceed the haystack extent",
            ),
        )?;
        let replacement_bytes_copied = replacement
            .len()
            .checked_mul(replacements)
            .ok_or(AotLiteralReplacementError::OutputLengthOverflow)?;
        let output_bytes = haystack_bytes_copied
            .checked_add(replacement_bytes_copied)
            .ok_or(AotLiteralReplacementError::OutputLengthOverflow)?;
        if output_bytes > limits.max_output_bytes {
            return Err(AotLiteralReplacementError::OutputBytesLimit {
                needed: output_bytes,
                limit: limits.max_output_bytes,
            });
        }

        let mut bytes = Vec::new();
        bytes.try_reserve_exact(output_bytes).map_err(|_| {
            AotLiteralReplacementError::AllocationFailed {
                requested: output_bytes,
            }
        })?;
        let output_capacity_bytes = bytes.capacity();
        if output_capacity_bytes > limits.max_output_capacity_bytes {
            return Err(AotLiteralReplacementError::OutputCapacityBytesLimit {
                needed: output_capacity_bytes,
                limit: limits.max_output_capacity_bytes,
            });
        }

        let mut cursor = 0_usize;
        let mut copied_count = 0_u64;
        let mut copied_span_sum = 0_u64;
        for matched in self.find_iter(haystack)? {
            let matched = matched?;
            let gap = haystack.get(cursor..matched.start()).ok_or(
                AotLiteralReplacementError::InternalInvariant(
                    "replacement spans are not ordered within the haystack",
                ),
            )?;
            bytes.extend_from_slice(gap);
            bytes.extend_from_slice(replacement);
            cursor = matched.end();
            copied_count = copied_count.checked_add(1).ok_or(
                AotLiteralReplacementError::InternalInvariant(
                    "copy-pass Count overflowed after sizing succeeded",
                ),
            )?;
            let width = u64::try_from(matched.len()).map_err(|_| {
                AotLiteralReplacementError::InternalInvariant(
                    "copy-pass match width did not fit u64",
                )
            })?;
            copied_span_sum = copied_span_sum.checked_add(width).ok_or(
                AotLiteralReplacementError::InternalInvariant(
                    "copy-pass SpanSum overflowed after sizing succeeded",
                ),
            )?;
        }
        let tail = haystack
            .get(cursor..)
            .ok_or(AotLiteralReplacementError::InternalInvariant(
                "replacement cursor ended outside the haystack",
            ))?;
        bytes.extend_from_slice(tail);
        if copied_count != stats.count || copied_span_sum != stats.span_sum {
            return Err(AotLiteralReplacementError::InternalInvariant(
                "sizing and copy selector passes disagree",
            ));
        }
        if bytes.len() != output_bytes || bytes.capacity() != output_capacity_bytes {
            return Err(AotLiteralReplacementError::InternalInvariant(
                "replacement output differs from exact preflight",
            ));
        }

        Ok(AotLiteralReplacement {
            bytes,
            accounting: AotLiteralReplacementAccounting {
                replacements: stats.count,
                matched_bytes: stats.span_sum,
                haystack_bytes_copied,
                replacement_bytes_copied,
                output_bytes,
                output_capacity_bytes,
                selector_passes: 2,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fre_aot_regex::{CompileMode, CompileRequest, OutputContract, Target, compile};
    use regex::bytes::{NoExpand, Regex};

    type ReplacementCase<'a> = (&'a str, &'a [u8], &'a [u8], &'a [u8], AotMatchStats);

    fn prepared(pattern: &str, output: OutputContract, mode: CompileMode) -> PreparedAotRegex {
        let compiled = compile(
            CompileRequest::new(pattern, Target::x86_64_linux())
                .mode(mode)
                .output(output),
        )
        .unwrap_or_else(|error| panic!("compile {pattern:?}: {error}"));
        let bytes = compiled.program().serialize().expect("serialize program");
        PreparedAotRegex::deserialize(&bytes).expect("prepare program")
    }

    #[test]
    fn match_stats_and_literal_replacement_follow_byte_iterator_semantics() {
        let cases: [ReplacementCase<'_>; 6] = [
            (
                "a+",
                b"zaa a",
                b"X",
                b"zX X",
                AotMatchStats {
                    count: 2,
                    span_sum: 3,
                },
            ),
            (
                "",
                b"ab",
                b"-",
                b"-a-b-",
                AotMatchStats {
                    count: 3,
                    span_sum: 0,
                },
            ),
            (
                "a?",
                b"ba",
                b"-",
                b"-b-",
                AotMatchStats {
                    count: 2,
                    span_sum: 1,
                },
            ),
            (
                r"(?-u:\xFF+)",
                &[b'a', 0xff, 0xff, b'b'],
                b"$1",
                b"a$1b",
                AotMatchStats {
                    count: 1,
                    span_sum: 2,
                },
            ),
            (
                "z+",
                b"abc",
                b"replacement",
                b"abc",
                AotMatchStats {
                    count: 0,
                    span_sum: 0,
                },
            ),
            (
                "(?:ab|)",
                b"xab",
                b"",
                b"x",
                AotMatchStats {
                    count: 2,
                    span_sum: 2,
                },
            ),
        ];

        for mode in [CompileMode::Fast, CompileMode::Optimizing] {
            for (pattern, haystack, replacement, expected, expected_stats) in cases {
                let mut regex = prepared(pattern, OutputContract::Span, mode);
                assert_eq!(regex.match_stats(haystack).unwrap(), expected_stats);
                let result = regex
                    .replace_all_literal(
                        haystack,
                        replacement,
                        AotLiteralReplacementLimits::default(),
                    )
                    .unwrap();
                assert_eq!(result.as_bytes(), expected, "{mode:?} {pattern:?}");
                let accounting = result.accounting();
                assert_eq!(accounting.replacements, expected_stats.count);
                assert_eq!(accounting.matched_bytes, expected_stats.span_sum);
                assert_eq!(accounting.output_bytes, expected.len());
                assert_eq!(accounting.selector_passes, 2);
            }
        }
    }

    #[test]
    fn literal_replacement_matches_pinned_regex_bytes_no_expand() {
        let invalid = [b'a', 0xff, 0xff, b'b'];
        let nullable_invalid = [0xff, b'a', 0xff];
        let cases: [(&str, &[u8]); 7] = [
            ("", "☃a".as_bytes()),
            ("a?", b"ba"),
            ("(?:ab|)", b"xab"),
            (r"(?m:^|$)", b"a\nb\n"),
            (r"\A|\z", b"ab"),
            (r"(?-u:\xFF+)", &invalid),
            (r"(?-u:\xFF*|a)", &nullable_invalid),
        ];
        let replacements: [&[u8]; 3] = [b"", b"$1", b"<>"];

        for (pattern, haystack) in cases {
            let oracle = Regex::new(pattern)
                .unwrap_or_else(|error| panic!("compile oracle {pattern:?}: {error}"));
            let expected_stats =
                oracle
                    .find_iter(haystack)
                    .fold(AotMatchStats::default(), |mut stats, matched| {
                        stats.count = stats.count.checked_add(1).expect("small oracle Count");
                        stats.span_sum = stats
                            .span_sum
                            .checked_add(u64::try_from(matched.len()).expect("small oracle width"))
                            .expect("small oracle SpanSum");
                        stats
                    });

            for mode in [CompileMode::Fast, CompileMode::Optimizing] {
                let mut regex = prepared(pattern, OutputContract::Span, mode);
                assert_eq!(
                    regex.match_stats(haystack).unwrap(),
                    expected_stats,
                    "stats: {mode:?} {pattern:?}"
                );
                for replacement in replacements {
                    let expected = oracle.replace_all(haystack, NoExpand(replacement));
                    let actual = regex
                        .replace_all_literal(
                            haystack,
                            replacement,
                            AotLiteralReplacementLimits::default(),
                        )
                        .unwrap_or_else(|error| {
                            panic!("replace {mode:?} {pattern:?} {replacement:?}: {error}")
                        });
                    assert_eq!(
                        actual.as_bytes(),
                        expected.as_ref(),
                        "replace: {mode:?} {pattern:?} {replacement:?}"
                    );
                    let accounting = actual.accounting();
                    let replacements = usize::try_from(expected_stats.count)
                        .expect("small oracle replacement count");
                    let matched_bytes = usize::try_from(expected_stats.span_sum)
                        .expect("small oracle matched bytes");
                    assert_eq!(accounting.replacements, expected_stats.count);
                    assert_eq!(accounting.matched_bytes, expected_stats.span_sum);
                    assert_eq!(
                        accounting.haystack_bytes_copied,
                        haystack
                            .len()
                            .checked_sub(matched_bytes)
                            .expect("oracle matches remain within the haystack")
                    );
                    assert_eq!(
                        accounting.replacement_bytes_copied,
                        replacement
                            .len()
                            .checked_mul(replacements)
                            .expect("small oracle replacement bytes")
                    );
                    assert_eq!(accounting.output_bytes, expected.len());
                    assert_eq!(accounting.output_capacity_bytes, actual.bytes.capacity());
                    assert_eq!(accounting.selector_passes, 2);
                }
            }
        }
    }

    #[test]
    fn literal_replacement_rejects_contract_and_resource_limits_before_copy() {
        let haystack = b"aaaa";
        let mut wrong = prepared("a", OutputContract::Exists, CompileMode::Fast);
        assert!(matches!(
            wrong.replace_all_literal(haystack, b"bb", AotLiteralReplacementLimits::default()),
            Err(AotLiteralReplacementError::Find(
                AotRegexFindError::OutputContract {
                    actual: OutputContract::Exists
                }
            ))
        ));

        let mut regex = prepared("a", OutputContract::Span, CompileMode::Fast);
        assert!(matches!(
            regex.replace_all_literal(
                haystack,
                b"bb",
                AotLiteralReplacementLimits {
                    max_output_bytes: 7,
                    max_output_capacity_bytes: usize::MAX,
                }
            ),
            Err(AotLiteralReplacementError::OutputBytesLimit {
                needed: 8,
                limit: 7
            })
        ));

        let result = regex
            .replace_all_literal(
                haystack,
                b"bb",
                AotLiteralReplacementLimits {
                    max_output_bytes: 8,
                    max_output_capacity_bytes: usize::MAX,
                },
            )
            .expect("exact logical limit");
        let exact_capacity = result.accounting().output_capacity_bytes;
        if let Some(tight_capacity_limit) = exact_capacity.checked_sub(1) {
            assert!(matches!(
                regex.replace_all_literal(
                    haystack,
                    b"bb",
                    AotLiteralReplacementLimits {
                        max_output_bytes: 8,
                        max_output_capacity_bytes: tight_capacity_limit,
                    }
                ),
                Err(AotLiteralReplacementError::OutputCapacityBytesLimit {
                    needed,
                    limit
                }) if needed == exact_capacity && limit == tight_capacity_limit
            ));
        }
    }
}
