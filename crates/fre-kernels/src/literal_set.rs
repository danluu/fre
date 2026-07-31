//! Construction-selected finite-literal matching over a bounded Aho-Corasick DFA.

use core::fmt;
use core::mem;

use aho_corasick::{AhoCorasick, AhoCorasickKind, Input, MatchKind};
use fre_exact_alloc::try_box_preserve;

use crate::Window;
use crate::folded_literal_trie::{
    AdaptiveFindOutcome, FoldedLiteralTriePlan, ScanAttemptError as FoldedScanAttemptError,
    ScanError as FoldedScanError, ScanUpperBounds as FoldedScanUpperBounds,
};

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

/// Match semantics sealed into one finite-literal construction receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiteralSetMatchSemantics {
    /// Earliest start with source-order priority at that start.
    LeftmostFirst,
    /// Earliest ending match, suitable for a forward any-literal stream.
    StreamingAny,
}

/// Checked construction certificate for a finite-literal DFA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralSetBuildAccounting {
    /// Construction-selected search semantics.
    pub match_semantics: LiteralSetMatchSemantics,
    /// Number of ordered alternatives.
    pub patterns: usize,
    /// Sum of alternative byte lengths.
    pub pattern_bytes: usize,
    /// Shortest alternative, used to bound non-overlapping match emissions.
    pub minimum_pattern_bytes: usize,
    /// Upper bound on trie states before DFA table decoration.
    pub trie_states_upper_bound: usize,
    /// Conservative alphabet transition cells charged before construction.
    pub dfa_cells_upper_bound: usize,
    /// Conservative construction work charged before construction.
    pub build_work_upper_bound: usize,
    /// Conservative pinned-implementation peak-build byte envelope.
    pub build_bytes_upper_bound: usize,
    /// Exact persistent bytes for the automaton and any attached accelerator.
    pub persistent_bytes: usize,
}

/// Hard limits for one finite-literal search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralSetSearchLimits {
    /// Maximum incumbent DFA transitions or combined adaptive work units.
    ///
    /// The incumbent charge includes its initial transition. An attached
    /// accelerator instead charges prefix transitions, exact trie work and
    /// any dense-fallback transitions under the same caller-selected cap.
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
    /// Incumbent DFA-transition bound or completed combined adaptive work.
    pub transitions_upper_bound: usize,
    /// External heap scratch required by the immutable search API.
    pub scratch_bytes: usize,
}

/// Conservative accounting for one non-overlapping finite-literal iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralSetIterationAccounting {
    /// Bytes in the complete searched haystack.
    pub searched_bytes: usize,
    /// Maximum non-overlapping match events for the shortest retained literal.
    pub match_events_upper_bound: usize,
    /// Maximum input transitions plus one initialization per search call.
    pub transitions_upper_bound: usize,
    /// External heap scratch required by the immutable iterator API.
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
    /// Non-overlapping iteration requires strictly positive literal width.
    EmptyPatternIterationUnsupported,
    /// A forward iterator requires construction-selected streaming semantics.
    OrderedIterationUnsupported,
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
            Self::EmptyPatternIterationUnsupported => {
                write!(f, "literal-set iteration does not admit empty patterns")
            }
            Self::OrderedIterationUnsupported => {
                write!(
                    f,
                    "literal-set iteration requires streaming-any construction semantics"
                )
            }
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

/// Immutable finite-literal matcher.
///
/// The default constructor uses `LeftmostFirst`, giving earliest-start matches
/// and source priority at one start. The streaming-any constructor uses
/// earliest-end matches for one forward non-overlapping existence stream.
/// Construction is restricted by conservative work and memory envelopes
/// before its DFA is built.
#[derive(Clone, Debug)]
pub struct LiteralSetPlan {
    automaton: AhoCorasick,
    build: LiteralSetBuildAccounting,
    folded_long_tail: Option<Box<FoldedLongTail>>,
}

#[derive(Clone, Debug)]
struct FoldedLongTail {
    trie: FoldedLiteralTriePlan,
    max_pattern_bytes: usize,
    dfa_prefix_bytes: usize,
}

#[derive(Clone, Copy)]
struct FoldedLongProspective {
    work: usize,
    trie: FoldedScanUpperBounds,
}

/// Borrowed iterator over non-overlapping finite-literal matches.
///
/// The enclosing [`LiteralSetPlan`] fixes streaming-any semantics. This wrapper
/// deliberately exposes only byte spans, keeping the matcher implementation
/// and pattern identifiers private.
#[derive(Debug)]
pub struct LiteralSetMatches<'plan, 'haystack> {
    automaton: &'plan AhoCorasick,
    haystack: &'haystack [u8],
    start: usize,
    done: bool,
}

impl Iterator for LiteralSetMatches<'_, '_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let Some(matched) = self
            .automaton
            .find(Input::new(self.haystack).span(self.start..self.haystack.len()))
        else {
            self.done = true;
            return None;
        };
        self.start = matched.end();
        Some((matched.start(), matched.end()))
    }
}

impl core::iter::FusedIterator for LiteralSetMatches<'_, '_> {}

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
        Self::new_with_semantics(patterns, limits, LiteralSetMatchSemantics::LeftmostFirst)
    }

    /// Compile literal alternatives for a forward non-overlapping any-match
    /// stream.
    ///
    /// This mode reports the earliest ending match. It deliberately does not
    /// retain source priority because its contract is existence filtering,
    /// not ordered span selection.
    ///
    /// # Errors
    ///
    /// Returns before automaton construction if any checked count or
    /// conservative construction envelope exceeds its configured cap.
    pub fn new_streaming_any<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: LiteralSetBuildLimits,
    ) -> Result<Self, LiteralSetError> {
        Self::new_with_semantics(patterns, limits, LiteralSetMatchSemantics::StreamingAny)
    }

    fn new_with_semantics<P: AsRef<[u8]>>(
        patterns: &[P],
        limits: LiteralSetBuildLimits,
        match_semantics: LiteralSetMatchSemantics,
    ) -> Result<Self, LiteralSetError> {
        let mut build = preflight(patterns, limits, match_semantics)?;
        let match_kind = match match_semantics {
            LiteralSetMatchSemantics::LeftmostFirst => MatchKind::LeftmostFirst,
            LiteralSetMatchSemantics::StreamingAny => MatchKind::Standard,
        };
        let automaton = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .match_kind(match_kind)
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
        Ok(Self {
            automaton,
            build,
            folded_long_tail: None,
        })
    }

    /// Construction certificate and actual persistent footprint.
    #[must_use]
    pub const fn build_accounting(&self) -> LiteralSetBuildAccounting {
        self.build
    }

    /// Additional owner bytes beyond the trie owner already in its receipt.
    #[doc(hidden)]
    #[must_use]
    pub const fn folded_long_tail_additional_owner_bytes() -> usize {
        mem::size_of::<FoldedLongTail>().saturating_sub(mem::size_of::<FoldedLiteralTriePlan>())
    }

    /// Fallibly attach a source-derived folded accelerator to this ordered
    /// literal set. Refusal leaves the incumbent byte matcher unchanged.
    #[doc(hidden)]
    #[cold]
    #[inline(never)]
    pub fn try_attach_folded_long_tail(
        &mut self,
        trie: FoldedLiteralTriePlan,
        max_pattern_bytes: usize,
        max_persistent_bytes: usize,
    ) -> Result<bool, LiteralSetError> {
        if self.build.match_semantics != LiteralSetMatchSemantics::LeftmostFirst
            || self.folded_long_tail.is_some()
            || max_pattern_bytes == 0
        {
            return Err(invariant_error("invalid folded long-tail attachment"));
        }
        let dfa_prefix_bytes = ALPHABET_LEN.max(max_pattern_bytes);
        let retained_bytes = trie
            .build_accounting()
            .persistent_bytes
            .checked_add(Self::folded_long_tail_additional_owner_bytes())
            .and_then(|tail| self.build.persistent_bytes.checked_add(tail))
            .ok_or(LiteralSetError::ArithmeticOverflow {
                computation: "folded literal-set persistent bytes",
            })?;
        if retained_bytes > max_persistent_bytes {
            return Ok(false);
        }
        let tail = FoldedLongTail {
            trie,
            max_pattern_bytes,
            dfa_prefix_bytes,
        };
        let Ok(tail) = try_box_preserve(tail) else {
            return Ok(false);
        };
        self.folded_long_tail = Some(tail);
        self.build.persistent_bytes = retained_bytes;
        Ok(true)
    }

    /// Find one match under the construction-selected semantics in a complete
    /// haystack.
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

    /// Iterate over every non-overlapping earliest-ending literal match in one
    /// complete haystack under a single checked transition envelope.
    ///
    /// This is useful to partition an outer semantic operation without
    /// restarting the immutable DFA for each partition. The returned
    /// accounting is the complete-haystack prospective and remains valid
    /// whether the iterator reports zero or many matches.
    ///
    /// # Errors
    ///
    /// Returns a checked arithmetic or transition-limit error before creating
    /// the iterator.
    pub fn find_iter<'plan, 'haystack>(
        &'plan self,
        haystack: &'haystack [u8],
        limits: LiteralSetSearchLimits,
    ) -> Result<
        (
            LiteralSetMatches<'plan, 'haystack>,
            LiteralSetIterationAccounting,
        ),
        LiteralSetError,
    > {
        let accounting = self.find_iter_accounting(haystack.len())?;
        if accounting.transitions_upper_bound > limits.max_transitions {
            return Err(LiteralSetError::TransitionLimit {
                needed: accounting.transitions_upper_bound,
                limit: limits.max_transitions,
            });
        }
        Ok((
            LiteralSetMatches {
                automaton: &self.automaton,
                haystack,
                start: 0,
                done: false,
            },
            accounting,
        ))
    }

    /// Derive the complete prospective for [`Self::find_iter`] without
    /// inspecting source bytes.
    pub fn find_iter_accounting(
        &self,
        haystack_len: usize,
    ) -> Result<LiteralSetIterationAccounting, LiteralSetError> {
        if self.build.match_semantics != LiteralSetMatchSemantics::StreamingAny {
            return Err(LiteralSetError::OrderedIterationUnsupported);
        }
        let minimum = self.build.minimum_pattern_bytes;
        if minimum == 0 {
            return Err(LiteralSetError::EmptyPatternIterationUnsupported);
        }
        let match_events_upper_bound =
            haystack_len
                .checked_div(minimum)
                .ok_or(LiteralSetError::ArithmeticOverflow {
                    computation: "literal-set iteration match events",
                })?;
        // Streaming-any search returns at the first ending match, so byte
        // ranges consumed by successive wrapper searches are disjoint. Charge
        // all N input transitions and one start-state initialization for each
        // of at most M matches plus the terminal no-match search.
        let transitions_upper_bound = haystack_len
            .checked_add(match_events_upper_bound)
            .and_then(|transitions| transitions.checked_add(1))
            .ok_or(LiteralSetError::ArithmeticOverflow {
                computation: "literal-set iteration transitions",
            })?;
        Ok(LiteralSetIterationAccounting {
            searched_bytes: haystack_len,
            match_events_upper_bound,
            transitions_upper_bound,
            scratch_bytes: 0,
        })
    }

    /// Find one match under the construction-selected semantics wholly inside
    /// a byte range.
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
        let accounting = search_accounting(window, haystack.len(), limits)?;
        if let Some(tail) = self.folded_long_tail.as_deref()
            && accounting.searched_bytes > tail.dfa_prefix_bytes
        {
            return self.find_window_folded_long(haystack, window, limits, accounting, tail);
        }
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

    #[cold]
    #[inline(never)]
    fn find_window_folded_long(
        &self,
        haystack: &[u8],
        window: Window,
        limits: LiteralSetSearchLimits,
        incumbent_accounting: LiteralSetAccounting,
        tail: &FoldedLongTail,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        let Some(prospective) = folded_long_prospective(tail, window, limits.max_transitions)
        else {
            return self.find_window_incumbent(haystack, window, incumbent_accounting);
        };
        let prefix_end = window.start().checked_add(tail.dfa_prefix_bytes).ok_or(
            LiteralSetError::ArithmeticOverflow {
                computation: "folded literal-set DFA prefix end",
            },
        )?;
        let prefix_window = Window::new(window.start(), prefix_end);
        let (prefix_match, _) =
            self.find_window_incumbent(haystack, prefix_window, incumbent_accounting)?;
        let trie_start = prefix_end
            .checked_sub(tail.max_pattern_bytes)
            .and_then(|start| start.checked_add(1))
            .ok_or(LiteralSetError::ArithmeticOverflow {
                computation: "folded literal-set trie continuation",
            })?;
        if let Some(matched) = prefix_match
            && matched.0 < trie_start
        {
            return Ok((Some(matched), incumbent_accounting));
        }
        let adaptive = tail
            .trie
            .find_window_adaptive_precharged(
                haystack,
                Window::new(trie_start, window.end()),
                prospective.trie,
            )
            .map_err(|error| map_folded_scan_error(&error))?;
        let prefix_transitions =
            tail.dfa_prefix_bytes
                .checked_add(1)
                .ok_or(LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set DFA prefix transitions",
                })?;
        let adaptive_work = adaptive.receipt.actual.work;
        let partial_work = prefix_transitions.checked_add(adaptive_work).ok_or(
            LiteralSetError::ArithmeticOverflow {
                computation: "folded literal-set adaptive work",
            },
        )?;
        match adaptive.outcome {
            AdaptiveFindOutcome::Match(candidate) => {
                let accounting =
                    folded_long_accounting(incumbent_accounting, partial_work, prospective.work)?;
                Ok((Some((candidate.start(), candidate.end())), accounting))
            }
            AdaptiveFindOutcome::NoMatch => {
                let accounting =
                    folded_long_accounting(incumbent_accounting, partial_work, prospective.work)?;
                Ok((None, accounting))
            }
            AdaptiveFindOutcome::DenseFallback { resume_start } => {
                let fallback_window = Window::new(resume_start, window.end());
                let fallback_accounting =
                    search_accounting(fallback_window, haystack.len(), limits)?;
                let (matched, _) =
                    self.find_window_incumbent(haystack, fallback_window, fallback_accounting)?;
                let total_work = partial_work
                    .checked_add(fallback_accounting.transitions_upper_bound)
                    .ok_or(LiteralSetError::ArithmeticOverflow {
                        computation: "folded literal-set fallback work",
                    })?;
                let accounting =
                    folded_long_accounting(incumbent_accounting, total_work, prospective.work)?;
                Ok((matched, accounting))
            }
        }
    }

    #[cold]
    #[inline(never)]
    fn find_window_incumbent(
        &self,
        haystack: &[u8],
        window: Window,
        accounting: LiteralSetAccounting,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        let matched = self
            .automaton
            .find(&haystack[window.start()..window.end()])
            .map(|matched| absolute_match(window.start(), matched))
            .transpose()?;
        Ok((matched, accounting))
    }
}

#[cold]
#[inline(never)]
fn folded_long_prospective(
    tail: &FoldedLongTail,
    window: Window,
    max_work: usize,
) -> Option<FoldedLongProspective> {
    let input_bytes = window.end().saturating_sub(window.start());
    if tail.max_pattern_bytes == 0
        || tail.max_pattern_bytes > tail.dfa_prefix_bytes
        || input_bytes <= tail.dfa_prefix_bytes
    {
        return None;
    }
    let trie_relative_start = tail
        .dfa_prefix_bytes
        .checked_sub(tail.max_pattern_bytes)?
        .checked_add(1)?;
    let trie_input_bytes = input_bytes.checked_sub(trie_relative_start)?;
    let trie = tail.trie.scan_upper_bounds(trie_input_bytes).ok()?;
    let work = tail
        .dfa_prefix_bytes
        .checked_add(1)?
        .checked_add(trie.work)?
        .checked_add(trie_input_bytes)?
        .checked_add(1)?;
    (work <= max_work).then_some(FoldedLongProspective { work, trie })
}

fn folded_long_accounting(
    incumbent: LiteralSetAccounting,
    actual_work: usize,
    prospective_work: usize,
) -> Result<LiteralSetAccounting, LiteralSetError> {
    if actual_work > prospective_work {
        return Err(invariant_error(
            "folded literal-set actual work exceeded its precharged prospective",
        ));
    }
    Ok(LiteralSetAccounting {
        searched_bytes: incumbent.searched_bytes,
        transitions_upper_bound: actual_work,
        scratch_bytes: incumbent.scratch_bytes,
    })
}

fn absolute_match(
    base: usize,
    matched: aho_corasick::Match,
) -> Result<(usize, usize), LiteralSetError> {
    let start = base
        .checked_add(matched.start())
        .ok_or(LiteralSetError::ArithmeticOverflow {
            computation: "literal-set match start",
        })?;
    let end = base
        .checked_add(matched.end())
        .ok_or(LiteralSetError::ArithmeticOverflow {
            computation: "literal-set match end",
        })?;
    Ok((start, end))
}

#[cold]
#[inline(never)]
fn map_folded_scan_error(error: &FoldedScanAttemptError) -> LiteralSetError {
    match &error.source {
        FoldedScanError::InvalidWindow {
            start,
            end,
            haystack_len,
        } => LiteralSetError::InvalidWindow {
            start: *start,
            end: *end,
            haystack_len: *haystack_len,
        },
        FoldedScanError::ArithmeticOverflow { computation } => {
            LiteralSetError::ArithmeticOverflow { computation }
        }
        FoldedScanError::Resource { .. } | FoldedScanError::Invariant { .. } => {
            invariant_error("folded literal-set search invariant failed")
        }
    }
}

#[cold]
#[inline(never)]
fn invariant_error(detail: &'static str) -> LiteralSetError {
    LiteralSetError::AutomatonBuild {
        detail: detail.to_owned(),
    }
}

fn search_accounting(
    window: Window,
    haystack_len: usize,
    limits: LiteralSetSearchLimits,
) -> Result<LiteralSetAccounting, LiteralSetError> {
    if window.start() > window.end() || window.end() > haystack_len {
        return Err(LiteralSetError::InvalidWindow {
            start: window.start(),
            end: window.end(),
            haystack_len,
        });
    }
    let searched_bytes =
        window
            .end()
            .checked_sub(window.start())
            .ok_or(LiteralSetError::ArithmeticOverflow {
                computation: "literal-set window length",
            })?;
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
    Ok(LiteralSetAccounting {
        searched_bytes,
        transitions_upper_bound,
        scratch_bytes: 0,
    })
}

fn preflight<P: AsRef<[u8]>>(
    patterns: &[P],
    limits: LiteralSetBuildLimits,
    match_semantics: LiteralSetMatchSemantics,
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
    let (pattern_bytes, minimum_pattern_bytes) =
        patterns
            .iter()
            .try_fold((0_usize, usize::MAX), |(total, minimum), pattern| {
                let bytes = pattern.as_ref().len();
                let total =
                    total
                        .checked_add(bytes)
                        .ok_or(LiteralSetError::ArithmeticOverflow {
                            computation: "literal-set pattern bytes",
                        })?;
                Ok((total, minimum.min(bytes)))
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
        match_semantics,
        patterns: patterns.len(),
        pattern_bytes,
        minimum_pattern_bytes,
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
mod folded_long_tail_tests {
    use crate::folded_literal_trie::{
        BuildAttempt, BuildLimits, FoldedLiteral, FoldedLiteralTriePlan, FoldedScalarClass,
    };

    use super::{
        LiteralSetBuildLimits, LiteralSetPlan, LiteralSetSearchLimits, Window,
        folded_long_prospective,
    };

    fn patterns() -> [&'static [u8]; 3] {
        [b"Ka", b"ka", "\u{212A}a".as_bytes()]
    }

    fn folded_trie() -> FoldedLiteralTriePlan {
        let root = FoldedScalarClass::new(&['K', 'k', '\u{212A}']);
        let suffix = FoldedScalarClass::new(&['a']);
        let classes = [root, suffix];
        let literals = [FoldedLiteral::new(&classes)];
        match FoldedLiteralTriePlan::build(&literals, BuildLimits::default()).unwrap() {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("synthetic folded trie declined: {fallback:?}")
            }
        }
    }

    fn plans() -> (LiteralSetPlan, LiteralSetPlan) {
        let patterns = patterns();
        let incumbent = LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let mut accelerated =
            LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        assert!(
            accelerated
                .try_attach_folded_long_tail(folded_trie(), 4, usize::MAX)
                .unwrap()
        );
        (incumbent, accelerated)
    }

    #[test]
    fn ordinary_and_short_literal_sets_retain_incumbent_path_and_accounting() {
        let patterns = patterns();
        let ordinary = LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        assert!(ordinary.folded_long_tail.is_none());

        let (incumbent, accelerated) = plans();
        let cutover = accelerated
            .folded_long_tail
            .as_deref()
            .unwrap()
            .dfa_prefix_bytes;
        let mut haystack = vec![b'z'; cutover];
        haystack[cutover - 2..].copy_from_slice(b"ka");
        let expected = incumbent
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap();
        let actual = accelerated
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.1.transitions_upper_bound, haystack.len() + 1);
    }

    #[test]
    fn folded_envelope_refusal_runs_the_incumbent_instead_of_erroring() {
        let (incumbent, accelerated) = plans();
        let mut haystack = vec![b'z'; 320];
        haystack[318..].copy_from_slice(b"Ka");
        let limits = LiteralSetSearchLimits {
            max_transitions: haystack.len() + 1,
        };
        let expected = incumbent.find(&haystack, limits).unwrap();
        let actual = accelerated.find(&haystack, limits).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn folded_long_path_matches_incumbent_across_sparse_and_dense_sources() {
        let (incumbent, accelerated) = plans();
        for mut haystack in [vec![b'z'; 640], vec![b'K'; 640]] {
            haystack.extend_from_slice(b"ka");
            let expected = incumbent
                .find(&haystack, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0;
            let (actual, accounting) = accelerated
                .find(&haystack, LiteralSetSearchLimits::unlimited())
                .unwrap();
            assert_eq!(actual, expected);
            let tail = accelerated.folded_long_tail.as_deref().unwrap();
            let prospective =
                folded_long_prospective(tail, Window::full(&haystack), usize::MAX).unwrap();
            assert!(accounting.transitions_upper_bound <= prospective.work);
        }
    }

    #[test]
    fn prefix_overlap_preserves_earlier_start_and_source_priority() {
        let k = ['K'];
        let a = ['a'];

        let crossing_long = [
            FoldedScalarClass::new(&k),
            FoldedScalarClass::new(&k),
            FoldedScalarClass::new(&a),
            FoldedScalarClass::new(&a),
            FoldedScalarClass::new(&a),
            FoldedScalarClass::new(&a),
            FoldedScalarClass::new(&a),
            FoldedScalarClass::new(&a),
        ];
        let crossing_short = [FoldedScalarClass::new(&k), FoldedScalarClass::new(&a)];
        let crossing_literals = [
            FoldedLiteral::new(&crossing_long),
            FoldedLiteral::new(&crossing_short),
        ];
        let crossing_trie =
            match FoldedLiteralTriePlan::build(&crossing_literals, BuildLimits::default()).unwrap()
            {
                BuildAttempt::Admitted(plan) => plan,
                BuildAttempt::DenseFallback(fallback) => {
                    panic!("synthetic crossing trie declined: {fallback:?}")
                }
            };
        let crossing_patterns: [&[u8]; 2] = [b"KKaaaaaa", b"Ka"];
        let crossing_incumbent =
            LiteralSetPlan::new(&crossing_patterns, LiteralSetBuildLimits::default()).unwrap();
        let mut crossing_accelerated = crossing_incumbent.clone();
        assert!(
            crossing_accelerated
                .try_attach_folded_long_tail(crossing_trie, 8, usize::MAX)
                .unwrap()
        );
        let mut crossing_haystack = vec![b'z'; 253];
        crossing_haystack.extend_from_slice(b"KKaaaaaa");
        assert_eq!(
            crossing_accelerated
                .find(&crossing_haystack, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            crossing_incumbent
                .find(&crossing_haystack, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0
        );

        let preferred_long = [
            FoldedScalarClass::new(&k),
            FoldedScalarClass::new(&a),
            FoldedScalarClass::new(&a),
            FoldedScalarClass::new(&a),
            FoldedScalarClass::new(&a),
            FoldedScalarClass::new(&a),
            FoldedScalarClass::new(&a),
        ];
        let preferred_short = [FoldedScalarClass::new(&k), FoldedScalarClass::new(&a)];
        let preferred_literals = [
            FoldedLiteral::new(&preferred_long),
            FoldedLiteral::new(&preferred_short),
        ];
        let preferred_trie = match FoldedLiteralTriePlan::build(
            &preferred_literals,
            BuildLimits::default(),
        )
        .unwrap()
        {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("synthetic preference trie declined: {fallback:?}")
            }
        };
        let preferred_patterns: [&[u8]; 2] = [b"Kaaaaaa", b"Ka"];
        let preferred_incumbent =
            LiteralSetPlan::new(&preferred_patterns, LiteralSetBuildLimits::default()).unwrap();
        let mut preferred_accelerated = preferred_incumbent.clone();
        assert!(
            preferred_accelerated
                .try_attach_folded_long_tail(preferred_trie, 7, usize::MAX)
                .unwrap()
        );
        let mut preferred_haystack = vec![b'z'; 254];
        preferred_haystack.extend_from_slice(b"Kaaaaaa");
        assert_eq!(
            preferred_accelerated
                .find(&preferred_haystack, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            preferred_incumbent
                .find(&preferred_haystack, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0
        );
    }
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
        assert_eq!(
            empty_first.find_iter_accounting(1),
            Err(LiteralSetError::OrderedIterationUnsupported)
        );
        let streaming_empty = LiteralSetPlan::new_streaming_any(
            &[b"".as_slice(), b"a".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            streaming_empty.find_iter_accounting(1),
            Err(LiteralSetError::EmptyPatternIterationUnsupported)
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
    fn one_checked_iterator_reports_forward_matches_and_exact_full_input_bound() {
        let plan = LiteralSetPlan::new_streaming_any(
            &[b"AB".as_slice(), b"XY".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        let haystack = b"ABAB\nmiss\nXY";
        let prospective = plan.find_iter_accounting(haystack.len()).unwrap();
        let (matches, accounting) = plan
            .find_iter(
                haystack,
                LiteralSetSearchLimits {
                    max_transitions: prospective.transitions_upper_bound,
                },
            )
            .unwrap();
        assert_eq!(matches.collect::<Vec<_>>(), [(0, 2), (2, 4), (10, 12)]);
        assert_eq!(accounting.searched_bytes, haystack.len());
        assert_eq!(accounting.match_events_upper_bound, haystack.len() / 2);
        assert_eq!(
            accounting.transitions_upper_bound,
            prospective.transitions_upper_bound
        );
        assert!(matches!(
            plan.find_iter(
                haystack,
                LiteralSetSearchLimits {
                    max_transitions: prospective.transitions_upper_bound - 1,
                },
            ),
            Err(LiteralSetError::TransitionLimit { needed, limit })
                if needed == prospective.transitions_upper_bound
                    && limit == prospective.transitions_upper_bound - 1
        ));
    }

    #[test]
    fn streaming_any_iteration_avoids_leftmost_lookahead_replay() {
        let plan = LiteralSetPlan::new_streaming_any(
            &[b"aaaaaaaaab".as_slice(), b"a".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        let haystack = b"aaaaaaaaaaaa";
        let prospective = plan.find_iter_accounting(haystack.len()).unwrap();
        assert_eq!(prospective.match_events_upper_bound, haystack.len());
        assert_eq!(prospective.transitions_upper_bound, haystack.len() * 2 + 1);
        assert_eq!(
            plan.find_iter(
                haystack,
                LiteralSetSearchLimits {
                    max_transitions: prospective.transitions_upper_bound,
                },
            )
            .unwrap()
            .0
            .collect::<Vec<_>>(),
            (0..haystack.len())
                .map(|start| (start, start + 1))
                .collect::<Vec<_>>()
        );

        let ordered = LiteralSetPlan::new(
            &[b"aaaaaaaaab".as_slice(), b"a".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            ordered.find_iter_accounting(haystack.len()),
            Err(LiteralSetError::OrderedIterationUnsupported)
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
