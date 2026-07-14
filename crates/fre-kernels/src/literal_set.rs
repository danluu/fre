//! Ordered finite-literal alternation over a bounded Aho-Corasick DFA.

use core::fmt;
use core::mem;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};

use crate::Window;

const ALPHABET_LEN: usize = 256;
const BYTES_PER_DFA_CELL_ENVELOPE: usize = 16;
const BYTES_PER_TRIE_STATE_ENVELOPE: usize = 256;
const BYTES_PER_PATTERN_ENVELOPE: usize = 128;

/// Hard limits for constructing one ordered finite-literal plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralSetBuildLimits {
    /// Maximum alternatives, including duplicates and empty alternatives.
    pub max_patterns: usize,
    /// Maximum sum of all alternative byte lengths.
    pub max_pattern_bytes: usize,
    /// Maximum conservative DFA-construction work units.
    pub max_build_work: usize,
    /// Maximum conservative peak-build byte envelope.
    pub max_build_bytes: usize,
    /// Maximum persistent bytes reported by the built automaton.
    pub max_persistent_bytes: usize,
}

impl Default for LiteralSetBuildLimits {
    fn default() -> Self {
        Self {
            max_patterns: 4_096,
            max_pattern_bytes: 32 * 1024 * 1024,
            max_build_work: 128 * 1024 * 1024,
            max_build_bytes: 512 * 1024 * 1024,
            max_persistent_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Checked construction certificate for a finite-literal DFA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralSetBuildAccounting {
    /// Number of ordered alternatives.
    pub patterns: usize,
    /// Sum of alternative byte lengths.
    pub pattern_bytes: usize,
    /// Upper bound on trie states before DFA table decoration.
    pub trie_states_upper_bound: usize,
    /// Conservative alphabet transition cells charged before construction.
    pub dfa_cells_upper_bound: usize,
    /// Conservative construction work charged before construction.
    pub build_work_upper_bound: usize,
    /// Conservative pinned-implementation peak-build byte envelope.
    pub build_bytes_upper_bound: usize,
    /// Persistent bytes reported by the completed automaton.
    pub persistent_bytes: usize,
}

/// Hard limits for one finite-literal search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralSetSearchLimits {
    /// Maximum DFA input transitions, including the initial transition.
    pub max_transitions: usize,
}

impl LiteralSetSearchLimits {
    /// Disable the caller-selected limit; arithmetic remains checked.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_transitions: usize::MAX,
        }
    }
}

impl Default for LiteralSetSearchLimits {
    fn default() -> Self {
        Self {
            max_transitions: 128 * 1024 * 1024,
        }
    }
}

/// Conservative accounting for one finite-literal search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralSetAccounting {
    /// Bytes in the searched window.
    pub searched_bytes: usize,
    /// Maximum DFA transitions for the call, including initialization.
    pub transitions_upper_bound: usize,
    /// External heap scratch required by the immutable search API.
    pub scratch_bytes: usize,
}

/// Finite-literal build or search failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LiteralSetError {
    /// An automaton cannot represent an empty language as a literal set.
    EmptyPatternSet,
    /// Too many ordered alternatives.
    PatternLimit { needed: usize, limit: usize },
    /// Too many total alternative bytes.
    PatternBytesLimit { needed: usize, limit: usize },
    /// The conservative construction-work envelope exceeds its cap.
    BuildWorkLimit { needed: usize, limit: usize },
    /// The conservative peak-build byte envelope exceeds its cap.
    BuildBytesLimit { needed: usize, limit: usize },
    /// The completed immutable automaton exceeds its persistent cap.
    PersistentBytesLimit { needed: usize, limit: usize },
    /// A search window is outside its original haystack.
    InvalidWindow {
        start: usize,
        end: usize,
        haystack_len: usize,
    },
    /// The conservative transition envelope exceeds its per-call cap.
    TransitionLimit { needed: usize, limit: usize },
    /// Checked resource arithmetic overflowed.
    ArithmeticOverflow { computation: &'static str },
    /// The pinned automaton constructor rejected the admitted finite language.
    AutomatonBuild { detail: String },
}

impl fmt::Display for LiteralSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPatternSet => write!(f, "a finite-literal plan needs at least one pattern"),
            Self::PatternLimit { needed, limit } => {
                write!(f, "literal set needs {needed} patterns, exceeding {limit}")
            }
            Self::PatternBytesLimit { needed, limit } => write!(
                f,
                "literal set needs {needed} pattern bytes, exceeding {limit}"
            ),
            Self::BuildWorkLimit { needed, limit } => write!(
                f,
                "literal-set construction needs at most {needed} work units, exceeding {limit}"
            ),
            Self::BuildBytesLimit { needed, limit } => write!(
                f,
                "literal-set construction needs at most {needed} bytes, exceeding {limit}"
            ),
            Self::PersistentBytesLimit { needed, limit } => write!(
                f,
                "literal-set automaton retained {needed} bytes, exceeding {limit}"
            ),
            Self::InvalidWindow {
                start,
                end,
                haystack_len,
            } => write!(
                f,
                "literal-set window {start}..{end} is invalid for {haystack_len} bytes"
            ),
            Self::TransitionLimit { needed, limit } => write!(
                f,
                "literal-set search needs at most {needed} transitions, exceeding {limit}"
            ),
            Self::ArithmeticOverflow { computation } => {
                write!(f, "arithmetic overflow while computing {computation}")
            }
            Self::AutomatonBuild { detail } => {
                write!(f, "finite-literal automaton construction failed: {detail}")
            }
        }
    }
}

impl std::error::Error for LiteralSetError {}

/// Immutable ordered finite-literal matcher.
///
/// `LeftmostFirst` gives earliest-start matching and preserves pattern order at
/// one start, which is exactly the capture-free span semantics of an ordered
/// alternation of literals. Search is linear in the haystack for the pinned
/// Aho-Corasick implementation. Construction is restricted by conservative
/// work and memory envelopes before its DFA is built.
#[derive(Clone, Debug)]
pub struct LiteralSetPlan {
    automaton: AhoCorasick,
    build: LiteralSetBuildAccounting,
}

impl LiteralSetPlan {
    /// Compile ordered literal alternatives into a DFA.
    ///
    /// # Errors
    ///
    /// Returns before automaton construction if any checked count or
    /// conservative construction envelope exceeds its configured cap.
    pub fn new<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: LiteralSetBuildLimits,
    ) -> Result<Self, LiteralSetError> {
        let mut build = preflight(patterns, limits)?;
        let automaton = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns.iter().map(AsRef::as_ref))
            .map_err(|error| LiteralSetError::AutomatonBuild {
                detail: error.to_string(),
            })?;
        build.persistent_bytes = automaton.memory_usage();
        if build.persistent_bytes > limits.max_persistent_bytes {
            return Err(LiteralSetError::PersistentBytesLimit {
                needed: build.persistent_bytes,
                limit: limits.max_persistent_bytes,
            });
        }
        Ok(Self { automaton, build })
    }

    /// Construction certificate and actual persistent footprint.
    #[must_use]
    pub const fn build_accounting(&self) -> LiteralSetBuildAccounting {
        self.build
    }

    /// Find the earliest ordered-alternation match in a complete haystack.
    ///
    /// # Errors
    ///
    /// Returns a checked resource error before invoking the automaton.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: LiteralSetSearchLimits,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        self.find_window(haystack, Window::full(haystack), limits)
    }

    /// Find the earliest ordered-alternation match wholly inside a byte range.
    ///
    /// # Errors
    ///
    /// Returns a checked window, arithmetic, or transition-limit error before
    /// invoking the automaton.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: LiteralSetSearchLimits,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(LiteralSetError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        let searched_bytes = window.end().checked_sub(window.start()).ok_or(
            LiteralSetError::ArithmeticOverflow {
                computation: "literal-set window length",
            },
        )?;
        let transitions_upper_bound =
            searched_bytes
                .checked_add(1)
                .ok_or(LiteralSetError::ArithmeticOverflow {
                    computation: "literal-set transitions",
                })?;
        if transitions_upper_bound > limits.max_transitions {
            return Err(LiteralSetError::TransitionLimit {
                needed: transitions_upper_bound,
                limit: limits.max_transitions,
            });
        }
        let accounting = LiteralSetAccounting {
            searched_bytes,
            transitions_upper_bound,
            scratch_bytes: 0,
        };
        let matched = self
            .automaton
            .find(&haystack[window.start()..window.end()])
            .map(|matched| {
                let start = window.start().checked_add(matched.start()).ok_or(
                    LiteralSetError::ArithmeticOverflow {
                        computation: "literal-set match start",
                    },
                )?;
                let end = window.start().checked_add(matched.end()).ok_or(
                    LiteralSetError::ArithmeticOverflow {
                        computation: "literal-set match end",
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
    limits: LiteralSetBuildLimits,
) -> Result<LiteralSetBuildAccounting, LiteralSetError> {
    if patterns.is_empty() {
        return Err(LiteralSetError::EmptyPatternSet);
    }
    if patterns.len() > limits.max_patterns {
        return Err(LiteralSetError::PatternLimit {
            needed: patterns.len(),
            limit: limits.max_patterns,
        });
    }
    let pattern_bytes = patterns.iter().try_fold(0_usize, |total, pattern| {
        total
            .checked_add(pattern.as_ref().len())
            .ok_or(LiteralSetError::ArithmeticOverflow {
                computation: "literal-set pattern bytes",
            })
    })?;
    if pattern_bytes > limits.max_pattern_bytes {
        return Err(LiteralSetError::PatternBytesLimit {
            needed: pattern_bytes,
            limit: limits.max_pattern_bytes,
        });
    }
    let trie_states_upper_bound =
        pattern_bytes
            .checked_add(1)
            .ok_or(LiteralSetError::ArithmeticOverflow {
                computation: "literal-set trie states",
            })?;
    let dfa_cells_upper_bound = checked_mul(
        trie_states_upper_bound,
        ALPHABET_LEN,
        "literal-set DFA cells",
    )?;
    let build_work_upper_bound = dfa_cells_upper_bound
        .checked_add(pattern_bytes)
        .and_then(|work| work.checked_add(patterns.len()))
        .ok_or(LiteralSetError::ArithmeticOverflow {
            computation: "literal-set build work",
        })?;
    if build_work_upper_bound > limits.max_build_work {
        return Err(LiteralSetError::BuildWorkLimit {
            needed: build_work_upper_bound,
            limit: limits.max_build_work,
        });
    }
    let build_bytes_upper_bound = build_bytes_upper_bound(
        dfa_cells_upper_bound,
        trie_states_upper_bound,
        patterns.len(),
        pattern_bytes,
    )?;
    if build_bytes_upper_bound > limits.max_build_bytes {
        return Err(LiteralSetError::BuildBytesLimit {
            needed: build_bytes_upper_bound,
            limit: limits.max_build_bytes,
        });
    }
    Ok(LiteralSetBuildAccounting {
        patterns: patterns.len(),
        pattern_bytes,
        trie_states_upper_bound,
        dfa_cells_upper_bound,
        build_work_upper_bound,
        build_bytes_upper_bound,
        persistent_bytes: 0,
    })
}

fn build_bytes_upper_bound(
    dfa_cells: usize,
    trie_states: usize,
    patterns: usize,
    pattern_bytes: usize,
) -> Result<usize, LiteralSetError> {
    let dfa_bytes = checked_mul(
        dfa_cells,
        BYTES_PER_DFA_CELL_ENVELOPE,
        "literal-set DFA byte envelope",
    )?;
    let trie_bytes = checked_mul(
        trie_states,
        BYTES_PER_TRIE_STATE_ENVELOPE,
        "literal-set trie byte envelope",
    )?;
    let pattern_overhead = checked_mul(
        patterns,
        BYTES_PER_PATTERN_ENVELOPE,
        "literal-set pattern overhead",
    )?;
    dfa_bytes
        .checked_add(trie_bytes)
        .and_then(|bytes| bytes.checked_add(pattern_overhead))
        .and_then(|bytes| bytes.checked_add(pattern_bytes))
        .and_then(|bytes| bytes.checked_add(mem::size_of::<AhoCorasick>()))
        .ok_or(LiteralSetError::ArithmeticOverflow {
            computation: "literal-set peak-build byte envelope",
        })
}

fn checked_mul(
    left: usize,
    right: usize,
    computation: &'static str,
) -> Result<usize, LiteralSetError> {
    left.checked_mul(right)
        .ok_or(LiteralSetError::ArithmeticOverflow { computation })
}

#[cfg(test)]
mod tests {
    use super::{LiteralSetBuildLimits, LiteralSetError, LiteralSetPlan, LiteralSetSearchLimits};
    use crate::Window;

    #[test]
    fn leftmost_first_preserves_alternative_order_and_empty_patterns() {
        let short_first = LiteralSetPlan::new(
            &[b"a".as_slice(), b"ab".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            short_first
                .find(b"zzab", LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((2, 3))
        );
        let long_first = LiteralSetPlan::new(
            &[b"ab".as_slice(), b"a".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            long_first
                .find(b"zzab", LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((2, 4))
        );

        let empty_first = LiteralSetPlan::new(
            &[b"".as_slice(), b"a".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            empty_first
                .find(b"a", LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((0, 0))
        );
        let empty_second = LiteralSetPlan::new(
            &[b"a".as_slice(), b"".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            empty_second
                .find(b"a", LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((0, 1))
        );
    }

    #[test]
    fn windows_keep_original_offsets_and_limits_preflight() {
        let plan = LiteralSetPlan::new(
            &[b"bar".as_slice(), b"baz".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        let (matched, accounting) = plan
            .find_window(
                b"xxbazbar",
                Window::new(2, 8),
                LiteralSetSearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(matched, Some((2, 5)));
        assert_eq!(accounting.searched_bytes, 6);
        assert_eq!(accounting.transitions_upper_bound, 7);
        assert_eq!(
            plan.find_window(
                b"xxbazbar",
                Window::new(2, 8),
                LiteralSetSearchLimits { max_transitions: 6 },
            ),
            Err(LiteralSetError::TransitionLimit {
                needed: 7,
                limit: 6
            })
        );
    }

    #[test]
    fn construction_limits_are_checked_before_the_dfa() {
        assert!(matches!(
            LiteralSetPlan::new::<&[u8]>(&[], LiteralSetBuildLimits::default()),
            Err(LiteralSetError::EmptyPatternSet)
        ));
        let patterns = [b"abc".as_slice(), b"def".as_slice()];
        let limits = LiteralSetBuildLimits {
            max_patterns: 1,
            ..LiteralSetBuildLimits::default()
        };
        assert!(matches!(
            LiteralSetPlan::new(&patterns, limits),
            Err(LiteralSetError::PatternLimit {
                needed: 2,
                limit: 1
            })
        ));
        let limits = LiteralSetBuildLimits {
            max_pattern_bytes: 5,
            ..LiteralSetBuildLimits::default()
        };
        assert!(matches!(
            LiteralSetPlan::new(&patterns, limits),
            Err(LiteralSetError::PatternBytesLimit {
                needed: 6,
                limit: 5
            })
        ));
    }

    #[test]
    fn selected_finite_languages_match_rebar_aligned_rust_regex() {
        let languages: &[&[&[u8]]] = &[
            &[b"a", b"ab"],
            &[b"ab", b"a"],
            &[b"", b"a"],
            &[b"a", b""],
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
            let source = patterns
                .iter()
                .map(|pattern| regex::escape(core::str::from_utf8(pattern).unwrap()))
                .collect::<Vec<_>>()
                .join("|");
            let oracle = regex::bytes::RegexBuilder::new(&source)
                .unicode(false)
                .build()
                .unwrap();
            let plan = LiteralSetPlan::new(patterns, LiteralSetBuildLimits::default()).unwrap();
            for haystack in haystacks {
                let expected = oracle
                    .find(haystack)
                    .map(|matched| (matched.start(), matched.end()));
                let actual = plan
                    .find(haystack, LiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0;
                assert_eq!(actual, expected, "source={source:?}, haystack={haystack:?}");
            }
        }
    }
}
