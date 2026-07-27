//! Syntax-independent literal candidate and bounded anchor recovery types.

use core::{fmt, ops::Range};

/// One exact literal occurrence in original haystack byte offsets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralCandidate {
    pattern_index: usize,
    start: usize,
    end: usize,
}

impl LiteralCandidate {
    /// Construct one candidate. Stream implementations guarantee
    /// `start <= end`; consumers that construct candidates directly are
    /// checked by [`LiteralAnchor::recover`].
    #[must_use]
    pub const fn new(pattern_index: usize, start: usize, end: usize) -> Self {
        Self {
            pattern_index,
            start,
            end,
        }
    }

    /// Source-order index of the retained literal.
    #[must_use]
    pub const fn pattern_index(self) -> usize {
        self.pattern_index
    }

    /// Inclusive original byte start.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Exclusive original byte end.
    #[must_use]
    pub const fn end(self) -> usize {
        self.end
    }

    /// Original half-open byte span.
    #[must_use]
    pub const fn span(self) -> Range<usize> {
        self.start..self.end
    }
}

/// Stable ordering promised by one candidate stream implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateEmissionOrder {
    /// Increasing start, then increasing end, then source pattern index.
    StartEndPattern,
    /// Increasing end; matches sharing an end retain source pattern order.
    EndPattern,
}

/// Inclusive bounded distance between an enclosing match boundary and an
/// anchor boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OffsetBounds {
    min: usize,
    max: usize,
}

impl OffsetBounds {
    /// Validate an inclusive offset interval.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorError::InvalidOffsetBounds`] when `min > max`.
    pub const fn new(min: usize, max: usize) -> Result<Self, AnchorError> {
        if min > max {
            return Err(AnchorError::InvalidOffsetBounds { min, max });
        }
        Ok(Self { min, max })
    }

    /// One exact offset.
    #[must_use]
    pub const fn exact(offset: usize) -> Self {
        Self {
            min: offset,
            max: offset,
        }
    }

    /// Minimum admitted distance.
    #[must_use]
    pub const fn min(self) -> usize {
        self.min
    }

    /// Maximum admitted distance.
    #[must_use]
    pub const fn max(self) -> usize {
        self.max
    }

    /// Whether this interval identifies one exact distance.
    #[must_use]
    pub const fn is_exact(self) -> bool {
        self.min == self.max
    }
}

/// Bounded enclosing-match ranges recovered from one exact anchor occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorRecovery {
    earliest_start: usize,
    latest_start: usize,
    earliest_end: usize,
    latest_end: usize,
}

impl AnchorRecovery {
    /// Inclusive range of possible enclosing-match starts.
    #[must_use]
    pub const fn start_bounds(self) -> OffsetBounds {
        OffsetBounds {
            min: self.earliest_start,
            max: self.latest_start,
        }
    }

    /// Inclusive range of possible enclosing-match ends.
    #[must_use]
    pub const fn end_bounds(self) -> OffsetBounds {
        OffsetBounds {
            min: self.earliest_end,
            max: self.latest_end,
        }
    }

    /// Exact enclosing span when both recovered boundary intervals collapse.
    #[must_use]
    pub const fn exact_span(self) -> Option<Range<usize>> {
        if self.earliest_start == self.latest_start && self.earliest_end == self.latest_end {
            Some(self.earliest_start..self.earliest_end)
        } else {
            None
        }
    }
}

/// A literal's source index and bounded relative location inside an enclosing
/// semantic match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralAnchor {
    pattern_index: usize,
    bytes_before: OffsetBounds,
    bytes_after: OffsetBounds,
}

impl LiteralAnchor {
    /// Construct a bounded anchor from already validated intervals.
    #[must_use]
    pub const fn new(
        pattern_index: usize,
        bytes_before: OffsetBounds,
        bytes_after: OffsetBounds,
    ) -> Self {
        Self {
            pattern_index,
            bytes_before,
            bytes_after,
        }
    }

    /// Construct an anchor at one exact relative byte location.
    #[must_use]
    pub const fn exact(pattern_index: usize, bytes_before: usize, bytes_after: usize) -> Self {
        Self::new(
            pattern_index,
            OffsetBounds::exact(bytes_before),
            OffsetBounds::exact(bytes_after),
        )
    }

    /// Source-order literal index required by this anchor.
    #[must_use]
    pub const fn pattern_index(self) -> usize {
        self.pattern_index
    }

    /// Recover every enclosing boundary still compatible with the haystack.
    ///
    /// `Ok(None)` means the occurrence is too close to a boundary to satisfy
    /// even the minimum relative offsets. This method never reads source
    /// bytes.
    ///
    /// # Errors
    ///
    /// Returns a typed identity or range error for a malformed or mismatched
    /// candidate.
    pub fn recover(
        self,
        candidate: LiteralCandidate,
        haystack_len: usize,
    ) -> Result<Option<AnchorRecovery>, AnchorError> {
        if candidate.pattern_index != self.pattern_index {
            return Err(AnchorError::PatternMismatch {
                expected: self.pattern_index,
                actual: candidate.pattern_index,
            });
        }
        if candidate.start > candidate.end || candidate.end > haystack_len {
            return Err(AnchorError::InvalidCandidate {
                start: candidate.start,
                end: candidate.end,
                haystack_len,
            });
        }
        let Some(latest_start) = candidate.start.checked_sub(self.bytes_before.min) else {
            return Ok(None);
        };
        let earliest_start = candidate.start.saturating_sub(self.bytes_before.max);
        let Some(earliest_end) = candidate.end.checked_add(self.bytes_after.min) else {
            return Ok(None);
        };
        if earliest_end > haystack_len {
            return Ok(None);
        }
        let latest_end = candidate
            .end
            .saturating_add(self.bytes_after.max)
            .min(haystack_len);
        Ok(Some(AnchorRecovery {
            earliest_start,
            latest_start,
            earliest_end,
            latest_end,
        }))
    }
}

/// Literal-anchor construction or recovery failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AnchorError {
    /// An inclusive interval was inverted.
    InvalidOffsetBounds { min: usize, max: usize },
    /// A candidate belongs to a different source literal.
    PatternMismatch { expected: usize, actual: usize },
    /// Candidate offsets do not describe a range in the original haystack.
    InvalidCandidate {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
}

impl fmt::Display for AnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOffsetBounds { min, max } => {
                write!(
                    formatter,
                    "literal-anchor offsets are inverted: {min}..={max}"
                )
            }
            Self::PatternMismatch { expected, actual } => write!(
                formatter,
                "literal-anchor expected pattern {expected}, got {actual}"
            ),
            Self::InvalidCandidate {
                start,
                end,
                haystack_len,
            } => write!(
                formatter,
                "literal candidate {start}..{end} is invalid for {haystack_len} bytes"
            ),
        }
    }
}

impl std::error::Error for AnchorError {}

#[cfg(test)]
mod tests {
    use super::{AnchorError, LiteralAnchor, LiteralCandidate, OffsetBounds};

    #[test]
    fn exact_and_bounded_recovery_preserve_original_offsets() {
        let candidate = LiteralCandidate::new(3, 8, 12);
        let exact = LiteralAnchor::exact(3, 5, 7)
            .recover(candidate, 32)
            .unwrap()
            .unwrap();
        assert_eq!(exact.exact_span(), Some(3..19));

        let bounded = LiteralAnchor::new(
            3,
            OffsetBounds::new(2, 10).unwrap(),
            OffsetBounds::new(1, 30).unwrap(),
        )
        .recover(candidate, 20)
        .unwrap()
        .unwrap();
        assert_eq!(bounded.start_bounds(), OffsetBounds::new(0, 6).unwrap());
        assert_eq!(bounded.end_bounds(), OffsetBounds::new(13, 20).unwrap());
        assert_eq!(bounded.exact_span(), None);
    }

    #[test]
    fn boundary_misses_and_malformed_candidates_are_typed() {
        let candidate = LiteralCandidate::new(1, 2, 4);
        assert_eq!(
            LiteralAnchor::exact(1, 3, 0).recover(candidate, 8),
            Ok(None)
        );
        assert_eq!(
            LiteralAnchor::exact(1, 0, 5).recover(candidate, 8),
            Ok(None)
        );
        assert!(
            LiteralAnchor::exact(1, 2, 4)
                .recover(candidate, 8)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            LiteralAnchor::exact(1, 3, 4).recover(candidate, 8),
            Ok(None)
        );
        assert_eq!(
            LiteralAnchor::exact(1, 2, 5).recover(candidate, 8),
            Ok(None)
        );
        assert!(matches!(
            LiteralAnchor::exact(2, 0, 0).recover(candidate, 8),
            Err(AnchorError::PatternMismatch {
                expected: 2,
                actual: 1
            })
        ));
        assert!(matches!(
            LiteralAnchor::exact(1, 0, 0).recover(LiteralCandidate::new(1, 5, 4), 8),
            Err(AnchorError::InvalidCandidate { .. })
        ));
        assert_eq!(
            OffsetBounds::new(2, 1),
            Err(AnchorError::InvalidOffsetBounds { min: 2, max: 1 })
        );

        let at_max = LiteralCandidate::new(1, usize::MAX, usize::MAX);
        assert_eq!(
            LiteralAnchor::exact(1, 0, 1).recover(at_max, usize::MAX),
            Ok(None)
        );
        let saturated = LiteralAnchor::new(
            1,
            OffsetBounds::exact(0),
            OffsetBounds::new(0, usize::MAX).unwrap(),
        )
        .recover(at_max, usize::MAX)
        .unwrap()
        .unwrap();
        assert_eq!(saturated.end_bounds(), OffsetBounds::exact(usize::MAX));
    }
}
