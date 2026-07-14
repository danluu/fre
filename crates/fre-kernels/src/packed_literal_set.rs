//! SIMD packed ordered finite-literal search with explicit refusal.

use core::fmt;

use aho_corasick::packed::Searcher;

use crate::Window;

const BUILD_FACTOR: usize = 256;
const PATTERN_BYTE_ENVELOPE: usize = 64;
const PATTERN_ENTRY_ENVELOPE: usize = 1_024;
const FIXED_BUILD_ENVELOPE: usize = 1024 * 1024;

/// Hard limits for a packed finite-literal plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedLiteralSetBuildLimits {
    /// Maximum ordered nonempty alternatives admitted to the builder.
    pub max_patterns: usize,
    /// Maximum sum of all alternative byte lengths.
    pub max_pattern_bytes: usize,
    /// Maximum conservative build-work envelope.
    pub max_build_work: usize,
    /// Maximum conservative peak-build byte envelope.
    pub max_build_bytes: usize,
    /// Maximum persistent bytes reported by the completed packed searcher.
    pub max_persistent_bytes: usize,
}

impl Default for PackedLiteralSetBuildLimits {
    fn default() -> Self {
        Self {
            max_patterns: 128,
            max_pattern_bytes: 4 * 1024 * 1024,
            max_build_work: 128 * 1024 * 1024,
            max_build_bytes: 256 * 1024 * 1024,
            max_persistent_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Checked construction facts for a packed finite-literal plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedLiteralSetBuildAccounting {
    /// Number of ordered alternatives.
    pub patterns: usize,
    /// Sum of alternative byte lengths.
    pub pattern_bytes: usize,
    /// Longest alternative, used in the verification bound.
    pub max_pattern_bytes: usize,
    /// Conservative construction work.
    pub build_work_upper_bound: usize,
    /// Conservative pinned-implementation peak-build byte envelope.
    pub build_bytes_upper_bound: usize,
    /// Persistent bytes reported by the completed searcher.
    pub persistent_bytes: usize,
    /// Minimum haystack length at which the SIMD searcher is used.
    pub simd_minimum_haystack_bytes: usize,
}

/// Per-search bound for a packed finite-literal invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedLiteralSetSearchLimits {
    /// Maximum conservative filter-plus-verification work.
    pub max_work: usize,
}

impl PackedLiteralSetSearchLimits {
    /// Disable the caller-selected cap; checked arithmetic remains active.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_work: usize::MAX,
        }
    }
}

impl Default for PackedLiteralSetSearchLimits {
    fn default() -> Self {
        Self {
            max_work: 512 * 1024 * 1024,
        }
    }
}

/// Conservative search certificate for one packed invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedLiteralSetAccounting {
    /// Bytes in the searched window.
    pub searched_bytes: usize,
    /// Candidate positions, including the terminal empty position.
    pub positions_upper_bound: usize,
    /// Bytes that could be checked when verifying all alternatives once.
    pub verification_bytes_per_position: usize,
    /// Conservative total filter-plus-verification work.
    pub work_upper_bound: usize,
    /// External heap scratch required by the immutable search call.
    pub scratch_bytes: usize,
    /// Whether this window is long enough for the packed SIMD implementation.
    pub simd_eligible_length: bool,
}

/// Packed literal-set build or search failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PackedLiteralSetError {
    EmptyPatternSet,
    EmptyPattern {
        index: usize,
    },
    PatternLimit {
        needed: usize,
        limit: usize,
    },
    PatternBytesLimit {
        needed: usize,
        limit: usize,
    },
    BuildWorkLimit {
        needed: usize,
        limit: usize,
    },
    BuildBytesLimit {
        needed: usize,
        limit: usize,
    },
    PersistentBytesLimit {
        needed: usize,
        limit: usize,
    },
    UnsupportedTargetOrShape,
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    WorkLimit {
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow {
        computation: &'static str,
    },
}

impl fmt::Display for PackedLiteralSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPatternSet => write!(f, "a packed literal set needs at least one pattern"),
            Self::EmptyPattern { index } => {
                write!(f, "packed literal alternative {index} is empty")
            }
            Self::PatternLimit { needed, limit } => {
                write!(
                    f,
                    "packed literal set needs {needed} patterns, exceeding {limit}"
                )
            }
            Self::PatternBytesLimit { needed, limit } => write!(
                f,
                "packed literal set needs {needed} pattern bytes, exceeding {limit}"
            ),
            Self::BuildWorkLimit { needed, limit } => write!(
                f,
                "packed literal construction needs at most {needed} work units, exceeding {limit}"
            ),
            Self::BuildBytesLimit { needed, limit } => write!(
                f,
                "packed literal construction needs at most {needed} bytes, exceeding {limit}"
            ),
            Self::PersistentBytesLimit { needed, limit } => write!(
                f,
                "packed literal searcher retained {needed} bytes, exceeding {limit}"
            ),
            Self::UnsupportedTargetOrShape => write!(
                f,
                "the pinned packed searcher does not support this target or pattern shape"
            ),
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "packed literal window {start}..{end} is invalid for {haystack_len} bytes"
            ),
            Self::WorkLimit { needed, limit } => write!(
                f,
                "packed literal search needs at most {needed} work units, exceeding {limit}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
        }
    }
}

impl std::error::Error for PackedLiteralSetError {}

/// Immutable SIMD packed ordered-literal plan.
///
/// This is a shared native primitive, not pattern-specialized JIT code. The
/// pinned implementation uses Teddy on supported x86-64/AArch64 haystacks and
/// a bounded Rabin-Karp path for short inputs. Construction refuses unsupported
/// targets/shapes; search never changes plan after selection.
#[derive(Clone, Debug)]
pub struct PackedLiteralSetPlan {
    searcher: Searcher,
    build: PackedLiteralSetBuildAccounting,
}

impl PackedLiteralSetPlan {
    /// Build a packed ordered-literal searcher.
    ///
    /// # Errors
    ///
    /// Returns a checked limit error before construction or an explicit
    /// unsupported result when the pinned packed builder cannot build.
    pub fn new<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: PackedLiteralSetBuildLimits,
    ) -> Result<Self, PackedLiteralSetError> {
        let mut build = preflight(patterns, limits)?;
        let searcher = Searcher::new(patterns.iter().map(AsRef::as_ref))
            .ok_or(PackedLiteralSetError::UnsupportedTargetOrShape)?;
        build.persistent_bytes = searcher.memory_usage();
        build.simd_minimum_haystack_bytes = searcher.minimum_len();
        if build.persistent_bytes > limits.max_persistent_bytes {
            return Err(PackedLiteralSetError::PersistentBytesLimit {
                needed: build.persistent_bytes,
                limit: limits.max_persistent_bytes,
            });
        }
        Ok(Self { searcher, build })
    }

    /// Checked construction facts and actual persistent footprint.
    #[must_use]
    pub const fn build_accounting(&self) -> PackedLiteralSetBuildAccounting {
        self.build
    }

    /// Find the first ordered-alternation match in a complete haystack.
    ///
    /// # Errors
    ///
    /// Returns a checked resource error before searching.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: PackedLiteralSetSearchLimits,
    ) -> Result<(Option<(usize, usize)>, PackedLiteralSetAccounting), PackedLiteralSetError> {
        self.find_window(haystack, Window::full(haystack), limits)
    }

    /// Find the first ordered-alternation match inside a byte range.
    ///
    /// # Errors
    ///
    /// Returns a checked window, arithmetic, or work-limit error before
    /// searching.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: PackedLiteralSetSearchLimits,
    ) -> Result<(Option<(usize, usize)>, PackedLiteralSetAccounting), PackedLiteralSetError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(PackedLiteralSetError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let searched_bytes = window.end().checked_sub(window.start()).ok_or(
            PackedLiteralSetError::ArithmeticOverflow {
                computation: "packed literal window length",
            },
        )?;
        let positions_upper_bound =
            searched_bytes
                .checked_add(1)
                .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                    computation: "packed literal candidate positions",
                })?;
        let verification_bytes_per_position = self
            .build
            .pattern_bytes
            .checked_add(self.build.patterns)
            .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                computation: "packed literal verification span",
            })?;
        let work_upper_bound = positions_upper_bound
            .checked_mul(verification_bytes_per_position)
            .ok_or(PackedLiteralSetError::ArithmeticOverflow {
                computation: "packed literal search work",
            })?;
        if work_upper_bound > limits.max_work {
            return Err(PackedLiteralSetError::WorkLimit {
                needed: work_upper_bound,
                limit: limits.max_work,
            });
        }
        let accounting = PackedLiteralSetAccounting {
            searched_bytes,
            positions_upper_bound,
            verification_bytes_per_position,
            work_upper_bound,
            scratch_bytes: 0,
            simd_eligible_length: searched_bytes >= self.build.simd_minimum_haystack_bytes,
        };
        let matched = self
            .searcher
            .find(&haystack[window.start()..window.end()])
            .map(|matched| {
                let start = window.start().checked_add(matched.start()).ok_or(
                    PackedLiteralSetError::ArithmeticOverflow {
                        computation: "packed literal match start",
                    },
                )?;
                let end = window.start().checked_add(matched.end()).ok_or(
                    PackedLiteralSetError::ArithmeticOverflow {
                        computation: "packed literal match end",
                    },
                )?;
                Ok((start, end))
            })
            .transpose()?;
        Ok((matched, accounting))
    }
}

fn preflight<P: AsRef<[u8]>>(
    patterns: &[P],
    limits: PackedLiteralSetBuildLimits,
) -> Result<PackedLiteralSetBuildAccounting, PackedLiteralSetError> {
    if patterns.is_empty() {
        return Err(PackedLiteralSetError::EmptyPatternSet);
    }
    if patterns.len() > limits.max_patterns {
        return Err(PackedLiteralSetError::PatternLimit {
            needed: patterns.len(),
            limit: limits.max_patterns,
        });
    }
    let mut pattern_bytes = 0_usize;
    let mut max_pattern_bytes = 0_usize;
    for (index, pattern) in patterns.iter().enumerate() {
        let bytes = pattern.as_ref();
        if bytes.is_empty() {
            return Err(PackedLiteralSetError::EmptyPattern { index });
        }
        pattern_bytes = pattern_bytes.checked_add(bytes.len()).ok_or(
            PackedLiteralSetError::ArithmeticOverflow {
                computation: "packed literal pattern bytes",
            },
        )?;
        max_pattern_bytes = max_pattern_bytes.max(bytes.len());
    }
    if pattern_bytes > limits.max_pattern_bytes {
        return Err(PackedLiteralSetError::PatternBytesLimit {
            needed: pattern_bytes,
            limit: limits.max_pattern_bytes,
        });
    }
    let build_work_upper_bound = pattern_bytes
        .checked_add(patterns.len())
        .and_then(|work| work.checked_mul(BUILD_FACTOR))
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "packed literal build work",
        })?;
    if build_work_upper_bound > limits.max_build_work {
        return Err(PackedLiteralSetError::BuildWorkLimit {
            needed: build_work_upper_bound,
            limit: limits.max_build_work,
        });
    }
    let pattern_storage = pattern_bytes.checked_mul(PATTERN_BYTE_ENVELOPE).ok_or(
        PackedLiteralSetError::ArithmeticOverflow {
            computation: "packed literal pattern storage envelope",
        },
    )?;
    let entry_storage = patterns.len().checked_mul(PATTERN_ENTRY_ENVELOPE).ok_or(
        PackedLiteralSetError::ArithmeticOverflow {
            computation: "packed literal entry storage envelope",
        },
    )?;
    let build_bytes_upper_bound = pattern_storage
        .checked_add(entry_storage)
        .and_then(|bytes| bytes.checked_add(FIXED_BUILD_ENVELOPE))
        .ok_or(PackedLiteralSetError::ArithmeticOverflow {
            computation: "packed literal peak-build byte envelope",
        })?;
    if build_bytes_upper_bound > limits.max_build_bytes {
        return Err(PackedLiteralSetError::BuildBytesLimit {
            needed: build_bytes_upper_bound,
            limit: limits.max_build_bytes,
        });
    }
    Ok(PackedLiteralSetBuildAccounting {
        patterns: patterns.len(),
        pattern_bytes,
        max_pattern_bytes,
        build_work_upper_bound,
        build_bytes_upper_bound,
        persistent_bytes: 0,
        simd_minimum_haystack_bytes: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        PackedLiteralSetBuildLimits, PackedLiteralSetError, PackedLiteralSetPlan,
        PackedLiteralSetSearchLimits,
    };
    use crate::Window;

    fn plan(patterns: &[&[u8]]) -> Option<PackedLiteralSetPlan> {
        match PackedLiteralSetPlan::new(patterns, PackedLiteralSetBuildLimits::default()) {
            Ok(plan) => Some(plan),
            Err(PackedLiteralSetError::UnsupportedTargetOrShape) => None,
            Err(error) => panic!("unexpected packed-plan error: {error}"),
        }
    }

    #[test]
    fn leftmost_first_and_window_offsets_match_the_contract() {
        let Some(short_first) = plan(&[b"a", b"ab"]) else {
            return;
        };
        assert_eq!(
            short_first
                .find_window(
                    b"zzabxx",
                    Window::new(2, 6),
                    PackedLiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some((2, 3))
        );
        let Some(long_first) = plan(&[b"ab", b"a"]) else {
            return;
        };
        assert_eq!(
            long_first
                .find(b"zzab", PackedLiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((2, 4))
        );
    }

    #[test]
    fn unsupported_shapes_and_work_caps_are_explicit() {
        assert!(matches!(
            PackedLiteralSetPlan::new::<&[u8]>(&[], PackedLiteralSetBuildLimits::default()),
            Err(PackedLiteralSetError::EmptyPatternSet)
        ));
        assert!(matches!(
            PackedLiteralSetPlan::new(
                &[b"a".as_slice(), b"".as_slice()],
                PackedLiteralSetBuildLimits::default()
            ),
            Err(PackedLiteralSetError::EmptyPattern { index: 1 })
        ));
        let Some(plan) = plan(&[b"foobar", b"foobaz", b"fooquux"]) else {
            return;
        };
        let (_, exact) = plan
            .find(
                b"foo-no-match/foobaz",
                PackedLiteralSetSearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(
            plan.find(
                b"foo-no-match/foobaz",
                PackedLiteralSetSearchLimits {
                    max_work: exact.work_upper_bound - 1,
                }
            ),
            Err(PackedLiteralSetError::WorkLimit {
                needed: exact.work_upper_bound,
                limit: exact.work_upper_bound - 1,
            })
        );
    }

    #[test]
    fn selected_languages_match_rebar_aligned_rust_regex() {
        let languages: &[&[&[u8]]] = &[
            &[b"a", b"ab"],
            &[b"ab", b"a"],
            &[b"foobar", b"foobaz", b"fooquux"],
            &[b"bc", b"a", b"abc"],
        ];
        let haystacks: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"zzab",
            b"foo-no-match/foobaz",
            b"ccccabc",
        ];
        for patterns in languages {
            let Some(plan) = plan(patterns) else {
                return;
            };
            let source = patterns
                .iter()
                .map(|pattern| regex::escape(core::str::from_utf8(pattern).unwrap()))
                .collect::<Vec<_>>()
                .join("|");
            let oracle = regex::bytes::RegexBuilder::new(&source)
                .unicode(false)
                .build()
                .unwrap();
            for haystack in haystacks {
                let expected = oracle
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let actual = plan
                    .find(haystack, PackedLiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0;
                assert_eq!(actual, expected, "source={source:?}, haystack={haystack:?}");
            }
        }
    }
}
