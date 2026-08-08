//! Construction-selected finite-literal matching over a bounded Aho-Corasick DFA.

use core::fmt;
use core::mem;
use std::sync::Arc;

use aho_corasick::automaton::Automaton;
use aho_corasick::dfa::DFA;
use aho_corasick::{AhoCorasick, Input, MatchKind};
use fre_exact_alloc::try_box_preserve;
use fre_simd_kernels::BYTE_BUCKET_BLOCK_BYTES;

use crate::Window;
use crate::folded_literal_trie::{
    FoldedLiteralTriePlan, RootCandidateOutcome, ScanAttemptError as FoldedScanAttemptError,
    ScanError as FoldedScanError, ScanUpperBounds as FoldedScanUpperBounds,
};

// A short folded search first settles the complete root-distance region whose
// W-1 right overlap cannot yet be amortized, then pays for a necessary-root
// pass plus any later exact DFA blocks. Require four complete classifier
// blocks of legal starts in total, so both stages are admitted by useful
// structural work rather than by a benchmark byte boundary.
const FOLDED_SHORT_MIN_CLASSIFIER_BLOCKS: usize = 4;

const ALPHABET_LEN: usize = 256;
const BYTES_PER_DFA_CELL_ENVELOPE: usize = 16;
const BYTES_PER_TRIE_STATE_ENVELOPE: usize = 256;
const BYTES_PER_PATTERN_ENVELOPE: usize = 128;
// Keep the published build envelope and its exact limit decisions stable
// after replacing the type-erased owner with a smaller `Arc<DFA>`.
const LEGACY_AHO_OWNER_ENVELOPE_BYTES: usize = mem::size_of::<AhoCorasick>();

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
    automaton: Arc<DFA>,
    build: LiteralSetBuildAccounting,
    folded_long_tail: Option<Box<FoldedLongTail>>,
}

/// Construction-sealed opportunity to attach one folded accelerator.
///
/// This wrapper owns the exact DFA built from `patterns` while borrowing that
/// same immutable pattern slice. It cannot be paired with another plan or
/// another pattern set, and it adds no field or construction work to ordinary
/// [`LiteralSetPlan`] values.
///
/// Generic `AsRef<[u8]>` providers are deliberately rejected because their
/// shared-borrow output may change through interior mutability:
///
/// ```compile_fail
/// use fre_kernels::{LiteralSetBuildLimits, LiteralSetFoldAttachment};
///
/// struct ChangingPattern(Vec<u8>);
/// impl AsRef<[u8]> for ChangingPattern {
///     fn as_ref(&self) -> &[u8] {
///         &self.0
///     }
/// }
/// let patterns = [ChangingPattern(b"literal".to_vec())];
/// let _ = LiteralSetFoldAttachment::new(
///     &patterns,
///     LiteralSetBuildLimits::default(),
/// );
/// ```
#[doc(hidden)]
#[derive(Debug)]
pub struct LiteralSetFoldAttachment<'patterns> {
    plan: LiteralSetPlan,
    patterns: &'patterns [Vec<u8>],
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
    prefix_transitions: usize,
}

#[derive(Clone, Copy)]
struct FoldedLongHead {
    probe: Window,
    settled_starts: usize,
    prefix_transitions: usize,
    continuation: Window,
    continuation_accounting: LiteralSetAccounting,
    miss_work: usize,
}

/// Borrowed iterator over non-overlapping finite-literal matches.
///
/// The enclosing [`LiteralSetPlan`] fixes streaming-any semantics. This wrapper
/// deliberately exposes only byte spans, keeping the matcher implementation
/// and pattern identifiers private.
#[derive(Debug)]
pub struct LiteralSetMatches<'plan, 'haystack> {
    automaton: &'plan DFA,
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
        let input = Input::new(self.haystack).span(self.start..self.haystack.len());
        let Some(matched) = self
            .automaton
            .try_find(&input)
            .expect("the literal-set DFA supports its construction-selected unanchored input")
        else {
            self.done = true;
            return None;
        };
        self.start = matched.end();
        Some((matched.start(), matched.end()))
    }
}

impl core::iter::FusedIterator for LiteralSetMatches<'_, '_> {}

impl<'patterns> LiteralSetFoldAttachment<'patterns> {
    /// Build one exact DFA and retain its construction-time pattern authority
    /// until the caller either attaches a folded trie or declines.
    pub fn new(
        patterns: &'patterns [Vec<u8>],
        limits: LiteralSetBuildLimits,
    ) -> Result<Self, LiteralSetError> {
        Ok(Self {
            plan: LiteralSetPlan::new(patterns, limits)?,
            patterns,
        })
    }

    /// The sealed exact plan while folded planning is in progress.
    #[must_use]
    pub const fn plan(&self) -> &LiteralSetPlan {
        &self.plan
    }

    /// Decline attachment and return the unchanged exact plan.
    #[must_use]
    pub fn into_plan(self) -> LiteralSetPlan {
        self.plan
    }

    /// Validate and attach a folded trie against the exact construction
    /// patterns, returning whether the persistent-byte cap admitted it.
    pub fn try_attach(
        self,
        trie: FoldedLiteralTriePlan,
        max_persistent_bytes: usize,
    ) -> Result<(LiteralSetPlan, bool), LiteralSetError> {
        let Self {
            mut plan,
            patterns,
        } = self;
        let attached =
            plan.try_attach_folded_long_tail(trie, patterns, max_persistent_bytes)?;
        Ok((plan, attached))
    }
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
        let automaton = DFA::builder()
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
            automaton: Arc::new(automaton),
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
    #[cold]
    #[inline(never)]
    fn try_attach_folded_long_tail(
        &mut self,
        trie: FoldedLiteralTriePlan,
        patterns: &[Vec<u8>],
        max_persistent_bytes: usize,
    ) -> Result<bool, LiteralSetError> {
        let max_pattern_bytes = patterns
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or(0);
        if self.build.match_semantics != LiteralSetMatchSemantics::LeftmostFirst
            || self.folded_long_tail.is_some()
            || max_pattern_bytes == 0
            || !trie.root_prefilter_is_necessary_for(patterns)
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
                automaton: self.automaton.as_ref(),
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
            return self.find_window_folded_long_staged(
                haystack, window, limits, accounting, tail,
            );
        }
        if let Some(tail) = self.folded_long_tail.as_deref()
            && folded_short_blocks_admitted(tail, accounting.searched_bytes)
        {
            return self.find_window_folded_short_blocks(
                haystack, window, limits, accounting, tail,
            );
        }
        let input = Input::new(&haystack[window.start()..window.end()]);
        let matched = self
            .automaton
            .as_ref()
            .try_find(&input)
            .expect("the literal-set DFA supports its construction-selected unanchored input")
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

    #[inline(never)]
    fn find_window_folded_short_blocks(
        &self,
        haystack: &[u8],
        window: Window,
        limits: LiteralSetSearchLimits,
        incumbent_accounting: LiteralSetAccounting,
        tail: &FoldedLongTail,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        let Some(head) = folded_short_block_head(tail, window) else {
            return self.find_window_incumbent(haystack, window, incumbent_accounting);
        };
        let Some(prospective) = folded_short_prospective_after_head(
            tail,
            window,
            head,
            limits.max_transitions,
        )
        else {
            return self.find_window_incumbent(haystack, window, incumbent_accounting);
        };
        if let Some(matched) =
            self.find_in_settled_block(haystack, head.probe, head.settled_starts)?
        {
            let accounting = folded_long_accounting(
                incumbent_accounting,
                head.prefix_transitions,
                prospective.work,
            )?;
            return Ok((Some(matched), accounting));
        }
        let mut search_start = head.continuation.start();
        // The exact head contributes its settled starts to the first tail
        // block's overlap amortization. Later accepted blocks reset this
        // origin to their own certified end.
        let mut amortization_start = window.start();
        let mut actual_work = prospective.prefix_transitions;
        loop {
            if search_start >= window.end() {
                let accounting =
                    folded_long_accounting(incumbent_accounting, actual_work, prospective.work)?;
                return Ok((None, accounting));
            }
            let root_window = Window::new(search_start, window.end());
            let root = tail
                .trie
                .find_root_candidate_precharged(haystack, root_window, prospective.trie)
                .map_err(|error| map_folded_scan_error(&error))?;
            actual_work = actual_work
                .checked_add(root.receipt.actual.work)
                .ok_or(LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set root-candidate work",
                })?;
            let candidate_start = match root.outcome {
                RootCandidateOutcome::Candidate { start } => start,
                RootCandidateOutcome::NoCandidate => {
                    let accounting = folded_long_accounting(
                        incumbent_accounting,
                        actual_work,
                        prospective.work,
                    )?;
                    return Ok((None, accounting));
                }
                RootCandidateOutcome::DenseFallback { resume_start } => {
                    return self.finish_folded_long_fallback(
                        haystack,
                        Window::new(resume_start, window.end()),
                        limits,
                        incumbent_accounting,
                        actual_work,
                        prospective.work,
                    );
                }
            };
            if candidate_start < search_start || candidate_start >= window.end() {
                return Err(invariant_error(
                    "folded root candidate escaped its search window",
                ));
            }
            let block_end = candidate_start
                .checked_add(BYTE_BUCKET_BLOCK_BYTES)
                .map_or(window.end(), |end| end.min(window.end()));
            let settled_starts = block_end.checked_sub(candidate_start).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set exact-block starts",
                },
            )?;
            let overlap = tail.max_pattern_bytes.checked_sub(1).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set exact-block overlap",
                },
            )?;
            let probe_end = block_end
                .checked_add(overlap)
                .map_or(window.end(), |end| end.min(window.end()));
            let probe_bytes = probe_end.checked_sub(candidate_start).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set exact-block bytes",
                },
            )?;
            let probe_transitions = probe_bytes.checked_add(1).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set exact-block transitions",
                },
            )?;
            let proved_progress = block_end.checked_sub(amortization_start).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set exact-block progress",
                },
            )?;
            // The necessary-root scan has already settled every start before
            // `candidate_start`. If the authoritative DFA probe would cost
            // more transitions than the total starts settled since the last
            // amortization origin, its right-overlap cost is not yet paid.
            // Preserve the root proof, but let the incumbent resume at the
            // candidate itself so it can still select that start and retain
            // leftmost-first source priority.
            if probe_transitions > proved_progress {
                return self.finish_folded_long_fallback(
                    haystack,
                    Window::new(candidate_start, window.end()),
                    limits,
                    incumbent_accounting,
                    actual_work,
                    prospective.work,
                );
            }
            let matched = self.find_in_settled_block(
                haystack,
                Window::new(candidate_start, probe_end),
                settled_starts,
            )?;
            actual_work = actual_work.checked_add(probe_transitions).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set exact-block work",
                },
            )?;
            if let Some(matched) = matched {
                let accounting =
                    folded_long_accounting(incumbent_accounting, actual_work, prospective.work)?;
                return Ok((Some(matched), accounting));
            }
            if block_end == window.end() {
                let accounting =
                    folded_long_accounting(incumbent_accounting, actual_work, prospective.work)?;
                return Ok((None, accounting));
            }
            search_start = block_end;
            amortization_start = block_end;
        }
    }

    #[inline(never)]
    fn find_window_folded_long_staged(
        &self,
        haystack: &[u8],
        window: Window,
        limits: LiteralSetSearchLimits,
        incumbent_accounting: LiteralSetAccounting,
        tail: &FoldedLongTail,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        let Some(head) = folded_long_head(tail, window) else {
            return self.find_window_incumbent(haystack, window, incumbent_accounting);
        };
        // Admit both outcomes before reading the head. A hit needs only
        // `prefix_transitions`; after a miss, the exact DFA can resume at the
        // first unsettled start under the complete `miss_work` envelope even
        // when the more expensive folded prospective is unavailable.
        if head.miss_work > limits.max_transitions {
            return self.find_window_incumbent(haystack, window, incumbent_accounting);
        }
        if let Some(matched) =
            self.find_in_settled_block(haystack, head.probe, head.settled_starts)?
        {
            let accounting = folded_long_accounting(
                incumbent_accounting,
                head.prefix_transitions,
                head.miss_work,
            )?;
            return Ok((Some(matched), accounting));
        }
        self.find_window_folded_long_after_head_miss(
            haystack,
            window,
            limits,
            incumbent_accounting,
            tail,
            head,
        )
    }

    #[cold]
    #[inline(never)]
    fn find_window_folded_long_after_head_miss(
        &self,
        haystack: &[u8],
        window: Window,
        limits: LiteralSetSearchLimits,
        incumbent_accounting: LiteralSetAccounting,
        tail: &FoldedLongTail,
        head: FoldedLongHead,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        let Some(prospective) = folded_long_prospective_after_head(
            tail,
            window,
            head,
            limits.max_transitions,
        )
        else {
            let (matched, _) = self.find_window_incumbent(
                haystack,
                head.continuation,
                head.continuation_accounting,
            )?;
            let accounting = folded_long_accounting(
                incumbent_accounting,
                head.miss_work,
                head.miss_work,
            )?;
            return Ok((matched, accounting));
        };
        let mut search_start = head.continuation.start();
        let mut actual_work = prospective.prefix_transitions;
        loop {
            if search_start >= window.end() {
                let accounting =
                    folded_long_accounting(incumbent_accounting, actual_work, prospective.work)?;
                return Ok((None, accounting));
            }
            let root_window = Window::new(search_start, window.end());
            let root = tail
                .trie
                .find_root_candidate_precharged(haystack, root_window, prospective.trie)
                .map_err(|error| map_folded_scan_error(&error))?;
            actual_work = actual_work
                .checked_add(root.receipt.actual.work)
                .ok_or(LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set root-candidate work",
                })?;
            let candidate_start = match root.outcome {
                RootCandidateOutcome::Candidate { start } => start,
                RootCandidateOutcome::NoCandidate => {
                    let accounting = folded_long_accounting(
                        incumbent_accounting,
                        actual_work,
                        prospective.work,
                    )?;
                    return Ok((None, accounting));
                }
                RootCandidateOutcome::DenseFallback { resume_start } => {
                    return self.finish_folded_long_fallback(
                        haystack,
                        Window::new(resume_start, window.end()),
                        limits,
                        incumbent_accounting,
                        actual_work,
                        prospective.work,
                    );
                }
            };
            if candidate_start < search_start || candidate_start >= window.end() {
                return Err(invariant_error(
                    "folded root candidate escaped its search window",
                ));
            }
            let block_end = candidate_start
                .checked_add(BYTE_BUCKET_BLOCK_BYTES)
                .map_or(window.end(), |end| end.min(window.end()));
            let settled_starts = block_end.checked_sub(candidate_start).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set exact-block starts",
                },
            )?;
            let overlap = tail.max_pattern_bytes.checked_sub(1).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set exact-block overlap",
                },
            )?;
            let probe_end = block_end
                .checked_add(overlap)
                .map_or(window.end(), |end| end.min(window.end()));
            let probe_bytes = probe_end.checked_sub(candidate_start).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set exact-block bytes",
                },
            )?;
            let probe_transitions = probe_bytes.checked_add(1).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set exact-block transitions",
                },
            )?;
            let matched = self.find_in_settled_block(
                haystack,
                Window::new(candidate_start, probe_end),
                settled_starts,
            )?;
            actual_work = actual_work.checked_add(probe_transitions).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set exact-block work",
                },
            )?;
            if let Some(matched) = matched {
                let accounting =
                    folded_long_accounting(incumbent_accounting, actual_work, prospective.work)?;
                return Ok((Some(matched), accounting));
            }
            if block_end == window.end() {
                let accounting =
                    folded_long_accounting(incumbent_accounting, actual_work, prospective.work)?;
                return Ok((None, accounting));
            }
            let proved_progress = block_end.checked_sub(search_start).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "folded literal-set exact-block progress",
                },
            )?;
            if probe_transitions > proved_progress {
                return self.finish_folded_long_fallback(
                    haystack,
                    Window::new(block_end, window.end()),
                    limits,
                    incumbent_accounting,
                    actual_work,
                    prospective.work,
                );
            }
            search_start = block_end;
        }
    }

    fn find_in_settled_block(
        &self,
        haystack: &[u8],
        probe: Window,
        settled_starts: usize,
    ) -> Result<Option<(usize, usize)>, LiteralSetError> {
        let probe_bytes = probe.end().checked_sub(probe.start()).ok_or(
            LiteralSetError::ArithmeticOverflow {
                computation: "folded literal-set settled-block bytes",
            },
        )?;
        if probe.end() > haystack.len() || settled_starts > probe_bytes {
            return Err(invariant_error(
                "folded literal-set settled block escaped its source",
            ));
        }
        let input = Input::new(&haystack[probe.start()..probe.end()]);
        let matched = self
            .automaton
            .as_ref()
            .try_find(&input)
            .expect("the literal-set DFA supports its construction-selected unanchored input");
        match matched {
            Some(matched) if matched.start() < settled_starts => {
                absolute_match(probe.start(), matched).map(Some)
            }
            Some(_) | None => Ok(None),
        }
    }

    fn finish_folded_long_fallback(
        &self,
        haystack: &[u8],
        fallback_window: Window,
        limits: LiteralSetSearchLimits,
        incumbent_accounting: LiteralSetAccounting,
        partial_work: usize,
        prospective_work: usize,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        let fallback_accounting = search_accounting(fallback_window, haystack.len(), limits)?;
        let (matched, _) =
            self.find_window_incumbent(haystack, fallback_window, fallback_accounting)?;
        let total_work = partial_work
            .checked_add(fallback_accounting.transitions_upper_bound)
            .ok_or(LiteralSetError::ArithmeticOverflow {
                computation: "folded literal-set fallback work",
            })?;
        let accounting =
            folded_long_accounting(incumbent_accounting, total_work, prospective_work)?;
        Ok((matched, accounting))
    }

    #[cold]
    #[inline(never)]
    fn find_window_incumbent(
        &self,
        haystack: &[u8],
        window: Window,
        accounting: LiteralSetAccounting,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        let input = Input::new(&haystack[window.start()..window.end()]);
        let matched = self
            .automaton
            .as_ref()
            .try_find(&input)
            .expect("the literal-set DFA supports its construction-selected unanchored input")
            .map(|matched| absolute_match(window.start(), matched))
            .transpose()?;
        Ok((matched, accounting))
    }
}

#[cfg(test)]
#[cold]
#[inline(never)]
fn folded_long_prospective(
    tail: &FoldedLongTail,
    window: Window,
    max_work: usize,
) -> Option<FoldedLongProspective> {
    let head = folded_long_head(tail, window)?;
    folded_long_prospective_after_head(tail, window, head, max_work)
}

#[cfg(test)]
#[cold]
#[inline(never)]
fn folded_short_prospective(
    tail: &FoldedLongTail,
    window: Window,
    max_work: usize,
) -> Option<FoldedLongProspective> {
    let head = folded_short_block_head(tail, window)?;
    folded_short_prospective_after_head(tail, window, head, max_work)
}

fn folded_long_head(tail: &FoldedLongTail, window: Window) -> Option<FoldedLongHead> {
    let input_bytes = window.end().saturating_sub(window.start());
    if tail.max_pattern_bytes == 0
        || tail.max_pattern_bytes > tail.dfa_prefix_bytes
        || input_bytes <= tail.dfa_prefix_bytes
    {
        return None;
    }
    // The exact DFA prefix was already certified at construction. A maximum
    // width W lets those D bytes settle Q=D-W+1 complete start positions,
    // including every start whose longest alternative ends exactly at D.
    let settled_starts = tail
        .dfa_prefix_bytes
        .checked_sub(tail.max_pattern_bytes)?
        .checked_add(1)?;
    let prefix_bytes = tail.dfa_prefix_bytes;
    let prefix_transitions = prefix_bytes.checked_add(1)?;
    let prefix_end = window.start().checked_add(prefix_bytes)?;
    let continuation_start = window.start().checked_add(settled_starts)?;
    let continuation_bytes = input_bytes.checked_sub(settled_starts)?;
    let continuation_transitions = continuation_bytes.checked_add(1)?;
    let miss_work = prefix_transitions.checked_add(continuation_transitions)?;
    Some(FoldedLongHead {
        probe: Window::new(window.start(), prefix_end),
        settled_starts,
        prefix_transitions,
        continuation: Window::new(continuation_start, window.end()),
        continuation_accounting: LiteralSetAccounting {
            searched_bytes: continuation_bytes,
            transitions_upper_bound: continuation_transitions,
            scratch_bytes: 0,
        },
        miss_work,
    })
}

fn folded_short_block_head(tail: &FoldedLongTail, window: Window) -> Option<FoldedLongHead> {
    let input_bytes = window.end().checked_sub(window.start())?;
    if !folded_short_blocks_admitted(tail, input_bytes) {
        return None;
    }
    // For a root candidate at distance d, the exact block's W-1 right overlap
    // is structurally amortized only once d >= W. Settle that entire d < W
    // region before any root dispatch. When fewer than W maximum-width starts
    // exist, the head settles all of them; shorter alternatives at later
    // starts remain owned by the root-filtered tail.
    let legal_starts = input_bytes
        .checked_sub(tail.max_pattern_bytes)?
        .checked_add(1)?;
    let settled_starts = tail.max_pattern_bytes.min(legal_starts);
    let overlap = tail.max_pattern_bytes.checked_sub(1)?;
    let prefix_bytes = settled_starts.checked_add(overlap)?;
    let prefix_transitions = prefix_bytes.checked_add(1)?;
    let prefix_end = window.start().checked_add(prefix_bytes)?;
    if prefix_end > window.end() {
        return None;
    }
    let continuation_start = window.start().checked_add(settled_starts)?;
    let continuation_bytes = input_bytes.checked_sub(settled_starts)?;
    let continuation_transitions = continuation_bytes.checked_add(1)?;
    let miss_work = prefix_transitions.checked_add(continuation_transitions)?;
    Some(FoldedLongHead {
        probe: Window::new(window.start(), prefix_end),
        settled_starts,
        prefix_transitions,
        continuation: Window::new(continuation_start, window.end()),
        continuation_accounting: LiteralSetAccounting {
            searched_bytes: continuation_bytes,
            transitions_upper_bound: continuation_transitions,
            scratch_bytes: 0,
        },
        miss_work,
    })
}

#[inline]
fn folded_short_minimum_bytes(tail: &FoldedLongTail) -> Option<usize> {
    let minimum_starts =
        BYTE_BUCKET_BLOCK_BYTES.checked_mul(FOLDED_SHORT_MIN_CLASSIFIER_BLOCKS)?;
    tail.max_pattern_bytes
        .checked_add(minimum_starts.checked_sub(1)?)
}

#[inline]
fn folded_short_blocks_admitted(tail: &FoldedLongTail, input_bytes: usize) -> bool {
    folded_short_minimum_bytes(tail).is_some_and(|minimum_bytes| {
        input_bytes >= minimum_bytes && input_bytes <= tail.dfa_prefix_bytes
    })
}

#[cold]
#[inline(never)]
fn folded_long_prospective_after_head(
    tail: &FoldedLongTail,
    window: Window,
    head: FoldedLongHead,
    max_work: usize,
) -> Option<FoldedLongProspective> {
    if head.miss_work > max_work
        || head.probe.start() != window.start()
        || head.continuation.end() != window.end()
    {
        return None;
    }
    let trie_input_bytes = head.continuation_accounting.searched_bytes;
    let trie = tail.trie.scan_upper_bounds(trie_input_bytes).ok()?;
    let exact_blocks = trie_input_bytes
        .checked_add(BYTE_BUCKET_BLOCK_BYTES.checked_sub(1)?)?
        .checked_div(BYTE_BUCKET_BLOCK_BYTES)?;
    // Disjoint settled starts contribute at most T byte transitions, and
    // every occupied block contributes at most W right-overlap transitions.
    // The full folded-trie envelope independently covers the necessary-root
    // stream, including guards and repeated fixed-column overlap.
    let exact_block_work = exact_blocks
        .checked_mul(tail.max_pattern_bytes)?
        .checked_add(trie_input_bytes)?;
    let work = head
        .prefix_transitions
        .checked_add(trie.work)?
        .checked_add(exact_block_work)?
        .checked_add(trie_input_bytes)?
        .checked_add(1)?;
    (work <= max_work).then_some(FoldedLongProspective {
        work,
        trie,
        prefix_transitions: head.prefix_transitions,
    })
}

#[cold]
#[inline(never)]
fn folded_short_prospective_after_head(
    tail: &FoldedLongTail,
    window: Window,
    head: FoldedLongHead,
    max_work: usize,
) -> Option<FoldedLongProspective> {
    if head.miss_work > max_work
        || head.probe.start() != window.start()
        || head.continuation.end() != window.end()
    {
        return None;
    }
    let trie_input_bytes = head.continuation_accounting.searched_bytes;
    let (trie, exact_blocks) = tail
        .trie
        .root_candidate_exact_block_upper_bounds(
            trie_input_bytes,
            tail.max_pattern_bytes,
            BYTE_BUCKET_BLOCK_BYTES,
        )
        .ok()?;
    // Every occupied classifier block contributes at most one exact-pattern
    // width of right overlap. The root-candidate envelope separately charges
    // the necessary fixed columns, guard reads and restart overlap.
    let exact_block_work = exact_blocks
        .checked_mul(tail.max_pattern_bytes)?
        .checked_add(trie_input_bytes)?;
    let work = head
        .prefix_transitions
        .checked_add(trie.work)?
        .checked_add(exact_block_work)?
        .checked_add(trie_input_bytes)?
        .checked_add(1)?;
    (work <= max_work).then_some(FoldedLongProspective {
        work,
        trie,
        prefix_transitions: head.prefix_transitions,
    })
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
        .and_then(|bytes| bytes.checked_add(LEGACY_AHO_OWNER_ENVELOPE_BYTES))
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
        RootCandidateOutcome,
    };

    use super::{
        BYTE_BUCKET_BLOCK_BYTES, FOLDED_SHORT_MIN_CLASSIFIER_BLOCKS, LiteralSetBuildLimits,
        LiteralSetError, LiteralSetFoldAttachment, LiteralSetPlan, LiteralSetSearchLimits, Window,
        folded_long_head, folded_long_prospective, folded_short_block_head,
        folded_short_blocks_admitted, folded_short_minimum_bytes, folded_short_prospective,
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
        let stable_patterns = patterns
            .iter()
            .map(|pattern| pattern.to_vec())
            .collect::<Vec<_>>();
        let attachment =
            LiteralSetFoldAttachment::new(&stable_patterns, LiteralSetBuildLimits::default())
                .unwrap();
        let (accelerated, attached) = attachment.try_attach(folded_trie(), usize::MAX).unwrap();
        assert!(attached);
        (incumbent, accelerated)
    }

    fn singleton_class_plans(
        equivalents: &[char],
        byte_patterns: &[&[u8]],
    ) -> (LiteralSetPlan, LiteralSetPlan) {
        let class = FoldedScalarClass::new(equivalents);
        let classes = [class];
        let literals = [FoldedLiteral::new(&classes)];
        let trie = match FoldedLiteralTriePlan::build(&literals, BuildLimits::default()).unwrap() {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("synthetic singleton trie declined: {fallback:?}")
            }
        };
        let incumbent = LiteralSetPlan::new(byte_patterns, LiteralSetBuildLimits::default()).unwrap();
        let stable_patterns = byte_patterns
            .iter()
            .map(|pattern| pattern.to_vec())
            .collect::<Vec<_>>();
        let attachment =
            LiteralSetFoldAttachment::new(&stable_patterns, LiteralSetBuildLimits::default())
                .unwrap();
        let (accelerated, attached) = attachment.try_attach(trie, usize::MAX).unwrap();
        assert!(attached);
        (incumbent, accelerated)
    }

    fn three_column_plans() -> (LiteralSetPlan, LiteralSetPlan) {
        let a = ['a'];
        let b = ['b'];
        let c = ['c'];
        let classes = [
            FoldedScalarClass::new(&a),
            FoldedScalarClass::new(&b),
            FoldedScalarClass::new(&c),
        ];
        let literals = [FoldedLiteral::new(&classes)];
        let trie = match FoldedLiteralTriePlan::build(&literals, BuildLimits::default()).unwrap() {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("synthetic three-column trie declined: {fallback:?}")
            }
        };
        let patterns = vec![b"abc".to_vec()];
        let incumbent = LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let attachment =
            LiteralSetFoldAttachment::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let (accelerated, attached) = attachment.try_attach(trie, usize::MAX).unwrap();
        assert!(attached);
        (incumbent, accelerated)
    }

    fn late_column_plans_with_width(width: usize) -> (LiteralSetPlan, LiteralSetPlan) {
        assert!(width >= 2);
        let common = ['e'];
        let rare = ['\u{7f}'];
        let mut classes = vec![FoldedScalarClass::new(&common); width];
        classes[width - 1] = FoldedScalarClass::new(&rare);
        let literals = [FoldedLiteral::new(&classes)];
        let trie = match FoldedLiteralTriePlan::build(&literals, BuildLimits::default()).unwrap() {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("synthetic late-column trie declined: {fallback:?}")
            }
        };
        assert_eq!(
            trie.build_accounting().root_prefilter_offset,
            Some(width - 1)
        );
        let mut pattern = vec![b'e'; width];
        pattern[width - 1] = 0x7f;
        let patterns = vec![pattern];
        let incumbent = LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let attachment =
            LiteralSetFoldAttachment::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let (accelerated, attached) = attachment.try_attach(trie, usize::MAX).unwrap();
        assert!(attached);
        (incumbent, accelerated)
    }

    fn late_column_plans() -> (LiteralSetPlan, LiteralSetPlan) {
        late_column_plans_with_width(32)
    }

    fn mixed_width_plans(long_width: usize) -> (LiteralSetPlan, LiteralSetPlan) {
        assert!(long_width >= 2);
        let common = ['e'];
        let rare = ['\u{7f}'];
        let short = ['x'];
        let mut long_classes = vec![FoldedScalarClass::new(&common); long_width];
        long_classes[long_width - 1] = FoldedScalarClass::new(&rare);
        let short_classes = [FoldedScalarClass::new(&short)];
        let literals = [
            FoldedLiteral::new(&long_classes),
            FoldedLiteral::new(&short_classes),
        ];
        let trie = match FoldedLiteralTriePlan::build(&literals, BuildLimits::default()).unwrap() {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("synthetic mixed-width trie declined: {fallback:?}")
            }
        };
        let mut long_pattern = vec![b'e'; long_width];
        long_pattern[long_width - 1] = 0x7f;
        let patterns = vec![long_pattern, b"x".to_vec()];
        let incumbent =
            LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let attachment =
            LiteralSetFoldAttachment::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let (accelerated, attached) = attachment.try_attach(trie, usize::MAX).unwrap();
        assert!(attached);
        (incumbent, accelerated)
    }

    fn wide_late_guard_plans() -> (LiteralSetPlan, LiteralSetPlan) {
        let common = [' '];
        let wide = ['\u{3}', '\u{4}', '\u{5}', '\u{6}'];
        let mut classes = vec![FoldedScalarClass::new(&common); 32];
        classes[31] = FoldedScalarClass::new(&wide);
        let literals = [FoldedLiteral::new(&classes)];
        let trie = match FoldedLiteralTriePlan::build(&literals, BuildLimits::default()).unwrap() {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("synthetic wide late-column trie declined: {fallback:?}")
            }
        };
        let build = trie.build_accounting();
        assert_eq!(build.root_prefilter_offset, Some(31));
        assert_eq!(build.root_prefilter_needles, 4);
        assert!(build.root_prefilter_classifier_selection.is_some());
        assert_eq!(build.root_prefilter_guard_offset, Some(30));
        assert_eq!(build.root_prefilter_guard_needles, 1);
        let patterns = wide
            .iter()
            .map(|&last| {
                let mut pattern = vec![b' '; 32];
                pattern[31] = u8::try_from(last).unwrap();
                pattern
            })
            .collect::<Vec<_>>();
        let incumbent = LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let attachment =
            LiteralSetFoldAttachment::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let (accelerated, attached) = attachment.try_attach(trie, usize::MAX).unwrap();
        assert!(attached);
        (incumbent, accelerated)
    }

    #[test]
    fn ordinary_and_sub_block_literal_sets_retain_incumbent_path_and_accounting() {
        let patterns = patterns();
        let ordinary = LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        assert!(ordinary.folded_long_tail.is_none());

        let (incumbent, accelerated) = plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let minimum = folded_short_minimum_bytes(tail).unwrap();
        let cutover = minimum - 1;
        assert_eq!(
            cutover,
            tail.max_pattern_bytes
                + BYTE_BUCKET_BLOCK_BYTES * FOLDED_SHORT_MIN_CLASSIFIER_BLOCKS
                - 2
        );
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
    fn short_absence_uses_one_exact_head_then_one_necessary_root_pass() {
        let (incumbent, accelerated) = plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let minimum = folded_short_minimum_bytes(tail).unwrap();
        let haystack = vec![b'z'; minimum];
        assert_eq!(
            haystack.len() - tail.max_pattern_bytes + 1,
            BYTE_BUCKET_BLOCK_BYTES * FOLDED_SHORT_MIN_CLASSIFIER_BLOCKS
        );
        assert!(haystack.len() >= minimum);
        assert!(haystack.len() <= tail.dfa_prefix_bytes);
        let expected = incumbent
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap();
        let window = Window::full(&haystack);
        let head = folded_short_block_head(tail, window).unwrap();
        assert_eq!(head.settled_starts, tail.max_pattern_bytes);
        assert_eq!(
            head.probe.end() - head.probe.start(),
            head.settled_starts + tail.max_pattern_bytes - 1
        );
        let prospective = folded_short_prospective(tail, window, usize::MAX).unwrap();
        assert_eq!(
            prospective.trie,
            tail.trie
                .root_candidate_exact_block_upper_bounds(
                    head.continuation_accounting.searched_bytes,
                    tail.max_pattern_bytes,
                    BYTE_BUCKET_BLOCK_BYTES,
                )
                .unwrap()
                .0,
            "the short path must use only the root-candidate prospective envelope"
        );
        let root = tail
            .trie
            .find_root_candidate_precharged(&haystack, head.continuation, prospective.trie)
            .unwrap();
        assert_eq!(root.outcome, RootCandidateOutcome::NoCandidate);
        let (actual, accounting) = accelerated
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap();
        assert_eq!(actual, expected.0);
        assert_eq!(actual, None);
        assert_eq!(accounting.searched_bytes, haystack.len());
        assert_eq!(
            accounting.transitions_upper_bound,
            head.prefix_transitions + root.receipt.actual.work
        );
        assert!(accounting.transitions_upper_bound <= prospective.work);
        assert_eq!(expected.1.transitions_upper_bound, haystack.len() + 1);
    }

    #[test]
    fn root_candidate_block_envelope_seals_classifier_and_width_facts() {
        let (_, accelerated) = plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let (upper, exact_blocks) = tail
            .trie
            .root_candidate_exact_block_upper_bounds(
                64,
                tail.max_pattern_bytes,
                BYTE_BUCKET_BLOCK_BYTES,
            )
            .unwrap();
        assert_eq!(exact_blocks, 4);
        assert_eq!(upper.input_bytes, 64);
        assert_eq!(upper.candidate_starts, 64);
        assert_eq!(upper.work, upper.candidate_starts + upper.source_byte_reads);
        assert!(matches!(
            tail.trie.root_candidate_exact_block_upper_bounds(
                64,
                tail.max_pattern_bytes,
                BYTE_BUCKET_BLOCK_BYTES - 1,
            ),
            Err(crate::folded_literal_trie::ScanError::Invariant { .. })
        ));
        assert!(matches!(
            tail.trie.root_candidate_exact_block_upper_bounds(
                usize::MAX,
                tail.max_pattern_bytes,
                BYTE_BUCKET_BLOCK_BYTES,
            ),
            Err(crate::folded_literal_trie::ScanError::ArithmeticOverflow { .. })
        ));
    }

    #[test]
    fn short_and_long_prospectives_split_exactly_at_the_dfa_prefix() {
        let (_, accelerated) = plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        assert!(folded_short_minimum_bytes(tail).unwrap() <= tail.dfa_prefix_bytes);

        let short_window = Window::new(0, tail.dfa_prefix_bytes);
        let short_head = folded_short_block_head(tail, short_window).unwrap();
        assert_eq!(short_head.settled_starts, tail.max_pattern_bytes);
        assert_eq!(short_head.probe.start(), short_window.start());
        assert_eq!(
            short_head.probe.end() - short_head.probe.start(),
            short_head.settled_starts + tail.max_pattern_bytes - 1
        );
        assert_eq!(
            short_head.continuation.start(),
            short_window.start() + short_head.settled_starts
        );
        assert!(folded_long_head(tail, short_window).is_none());
        assert_eq!(
            folded_short_prospective(tail, short_window, usize::MAX)
                .unwrap()
                .trie,
            tail.trie
                .root_candidate_exact_block_upper_bounds(
                    short_head.continuation_accounting.searched_bytes,
                    tail.max_pattern_bytes,
                    BYTE_BUCKET_BLOCK_BYTES,
                )
                .unwrap()
                .0
        );

        let long_window = Window::new(0, tail.dfa_prefix_bytes + 1);
        assert!(folded_short_block_head(tail, long_window).is_none());
        let long_head = folded_long_head(tail, long_window).unwrap();
        assert!(long_head.settled_starts > 0);
        assert_eq!(
            folded_long_prospective(tail, long_window, usize::MAX)
                .unwrap()
                .trie,
            tail.trie
                .scan_upper_bounds(long_head.continuation_accounting.searched_bytes)
                .unwrap()
        );

        let mut wide = tail.clone();
        wide.max_pattern_bytes = wide.dfa_prefix_bytes;
        assert_eq!(
            folded_short_minimum_bytes(&wide),
            wide.dfa_prefix_bytes.checked_add(
                BYTE_BUCKET_BLOCK_BYTES * FOLDED_SHORT_MIN_CLASSIFIER_BLOCKS - 1
            )
        );
        assert!(folded_short_block_head(&wide, short_window).is_none());
        assert!(
            !folded_short_blocks_admitted(&wide, wide.dfa_prefix_bytes),
            "W+63 beyond D must make the short path unreachable"
        );
    }

    #[test]
    fn short_exact_blocks_match_incumbent_across_windows_and_candidate_shapes() {
        let (incumbent, accelerated) = three_column_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let build = tail.trie.build_accounting();
        let primary = build.root_prefilter_offset.unwrap();
        let guard = build.root_prefilter_guard_offset.unwrap();
        let changed = (0..3)
            .find(|&offset| offset != primary && offset != guard)
            .unwrap();
        let mut false_literal = *b"abc";
        false_literal[changed] = b'z';
        let minimum = folded_short_minimum_bytes(tail).unwrap();

        for input_bytes in [
            minimum - 1,
            minimum,
            minimum + 1,
            31,
            64,
            127,
            tail.dfa_prefix_bytes - 1,
            tail.dfa_prefix_bytes,
        ] {
            for frame in 0..=3 {
                let window = Window::new(frame, frame + input_bytes);
                let mut cases = vec![vec![b'!'; frame + input_bytes + 4]];
                let starts = [
                    0,
                    1,
                    BYTE_BUCKET_BLOCK_BYTES - 1,
                    BYTE_BUCKET_BLOCK_BYTES,
                    input_bytes / 2,
                    input_bytes.saturating_sub(3),
                ];
                for relative_start in starts {
                    if relative_start + 3 > input_bytes {
                        continue;
                    }
                    let start = frame + relative_start;
                    let mut real = vec![b'!'; frame + input_bytes + 4];
                    real[start..start + 3].copy_from_slice(b"abc");
                    cases.push(real);

                    let mut rejected = vec![b'!'; frame + input_bytes + 4];
                    rejected[start..start + 3].copy_from_slice(&false_literal);
                    cases.push(rejected);

                    if relative_start + BYTE_BUCKET_BLOCK_BYTES + 3 <= input_bytes {
                        let later = start + BYTE_BUCKET_BLOCK_BYTES;
                        let mut fallback = vec![b'!'; frame + input_bytes + 4];
                        fallback[start..start + 3].copy_from_slice(&false_literal);
                        fallback[later..later + 3].copy_from_slice(b"abc");
                        cases.push(fallback);
                    }
                }

                let mut dense_rejections = vec![b'!'; frame + input_bytes + 4];
                for relative_start in (0..input_bytes.saturating_sub(2)).step_by(3) {
                    let start = frame + relative_start;
                    dense_rejections[start..start + 3].copy_from_slice(&false_literal);
                }
                cases.push(dense_rejections);

                for haystack in cases {
                    let expected = incumbent
                        .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                        .unwrap()
                        .0;
                    let (actual, accounting) = accelerated
                        .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(actual, expected, "window={window:?}");
                    if input_bytes >= minimum {
                        let prospective = folded_short_prospective(tail, window, usize::MAX)
                            .expect("the complete short block range is admitted");
                        assert!(accounting.transitions_upper_bound <= prospective.work);
                    }
                }
            }
        }
    }

    #[test]
    fn short_exact_head_covers_unamortized_roots_at_every_frame() {
        let (incumbent, accelerated) = three_column_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let build = tail.trie.build_accounting();
        let primary = build.root_prefilter_offset.unwrap();
        let guard = build.root_prefilter_guard_offset.unwrap();
        let changed = (0..3)
            .find(|&offset| offset != primary && offset != guard)
            .unwrap();
        let mut rejected = *b"abc";
        rejected[changed] = b'z';
        let input_bytes = folded_short_minimum_bytes(tail).unwrap();

        for frame in 0..BYTE_BUCKET_BLOCK_BYTES {
            let window = Window::new(frame, frame + input_bytes);
            let head = folded_short_block_head(tail, window).unwrap();
            let prospective = folded_short_prospective(tail, window, usize::MAX).unwrap();
            assert_eq!(head.settled_starts, tail.max_pattern_bytes);
            assert_eq!(head.settled_starts, 3);
            for residue in 0..head.settled_starts {
                let start = frame + residue;
                let mut exact = vec![b'!'; window.end() + tail.max_pattern_bytes];
                exact[start..start + 3].copy_from_slice(b"abc");
                let (matched, accounting) = accelerated
                    .find_window(&exact, window, LiteralSetSearchLimits::unlimited())
                    .unwrap();
                assert_eq!(matched, Some((start, start + 3)));
                assert_eq!(
                    accounting.transitions_upper_bound, head.prefix_transitions,
                    "frame={frame}, residue={residue}: a true head match must return before root dispatch"
                );

                let later = head.continuation.start() + tail.max_pattern_bytes;
                let mut false_root = vec![b'!'; window.end() + tail.max_pattern_bytes];
                false_root[start..start + 3].copy_from_slice(&rejected);
                false_root[later..later + 3].copy_from_slice(b"abc");
                let expected = incumbent
                    .find_window(
                        &false_root,
                        window,
                        LiteralSetSearchLimits::unlimited(),
                    )
                    .unwrap()
                    .0;
                let (matched, accounting) = accelerated
                    .find_window(
                        &false_root,
                        window,
                        LiteralSetSearchLimits::unlimited(),
                    )
                    .unwrap();
                assert_eq!(matched, expected, "frame={frame}, residue={residue}");
                assert_eq!(matched, Some((later, later + 3)));
                assert!(accounting.transitions_upper_bound <= prospective.work);
            }

            let boundary = head.continuation.start();
            let mut at_boundary = vec![b'!'; window.end() + tail.max_pattern_bytes];
            at_boundary[boundary..boundary + 3].copy_from_slice(b"abc");
            let (matched, accounting) = accelerated
                .find_window(
                    &at_boundary,
                    window,
                    LiteralSetSearchLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(matched, Some((boundary, boundary + 3)));
            assert!(accounting.transitions_upper_bound > head.prefix_transitions);
            assert!(accounting.transitions_upper_bound <= prospective.work);
        }
    }

    #[test]
    fn short_exact_head_geometry_and_boundary_matches_follow_pattern_width() {
        for width in [8, 13, 14, 16, 32, 80] {
            let (incumbent, accelerated) = late_column_plans_with_width(width);
            let tail = accelerated.folded_long_tail.as_deref().unwrap();
            assert_eq!(tail.max_pattern_bytes, width);
            let input_bytes = folded_short_minimum_bytes(tail).unwrap();
            let legal_starts = input_bytes - width + 1;
            assert_eq!(legal_starts, BYTE_BUCKET_BLOCK_BYTES * 4);
            let settled_starts = width.min(legal_starts);
            let mut exact = vec![b'e'; width];
            exact[width - 1] = 0x7f;

            for frame in 0..BYTE_BUCKET_BLOCK_BYTES {
                let window = Window::new(frame, frame + input_bytes);
                let head = folded_short_block_head(tail, window).unwrap();
                let prospective = folded_short_prospective(tail, window, usize::MAX).unwrap();
                assert_eq!(
                    head.settled_starts, settled_starts,
                    "width={width}, frame={frame}"
                );
                assert_eq!(
                    head.probe,
                    Window::new(frame, frame + settled_starts + width - 1),
                    "width={width}, frame={frame}"
                );
                assert_eq!(
                    head.prefix_transitions,
                    settled_starts + width,
                    "width={width}, frame={frame}"
                );
                assert_eq!(
                    head.continuation.start(),
                    frame + settled_starts,
                    "width={width}, frame={frame}"
                );

                let head_start = frame + settled_starts - 1;
                let mut in_head = vec![b'!'; window.end() + width];
                in_head[head_start..head_start + width].copy_from_slice(&exact);
                let expected = incumbent
                    .find_window(&in_head, window, LiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0;
                let (actual, accounting) = accelerated
                    .find_window(&in_head, window, LiteralSetSearchLimits::unlimited())
                    .unwrap();
                assert_eq!(actual, expected, "width={width}, frame={frame}");
                assert_eq!(actual, Some((head_start, head_start + width)));
                assert_eq!(accounting.transitions_upper_bound, head.prefix_transitions);

                if settled_starts < legal_starts {
                    let boundary_start = frame + settled_starts;
                    let mut at_boundary = vec![b'!'; window.end() + width];
                    at_boundary[boundary_start..boundary_start + width].copy_from_slice(&exact);
                    let expected = incumbent
                        .find_window(
                            &at_boundary,
                            window,
                            LiteralSetSearchLimits::unlimited(),
                        )
                        .unwrap()
                        .0;
                    let (actual, accounting) = accelerated
                        .find_window(
                            &at_boundary,
                            window,
                            LiteralSetSearchLimits::unlimited(),
                        )
                        .unwrap();
                    assert_eq!(actual, expected, "width={width}, frame={frame}");
                    assert_eq!(actual, Some((boundary_start, boundary_start + width)));
                    assert!(accounting.transitions_upper_bound > head.prefix_transitions);
                    assert!(accounting.transitions_upper_bound <= prospective.work);
                } else {
                    assert!(head.continuation_accounting.searched_bytes < width);
                    assert_eq!(head.probe, window);
                    assert_eq!(head.prefix_transitions, input_bytes + 1);
                }

                let absent = vec![b'!'; window.end() + width];
                let expected = incumbent
                    .find_window(&absent, window, LiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0;
                let (actual, accounting) = accelerated
                    .find_window(&absent, window, LiteralSetSearchLimits::unlimited())
                    .unwrap();
                assert_eq!(actual, expected, "width={width}, frame={frame}");
                assert_eq!(actual, None);
                assert!(accounting.transitions_upper_bound >= head.prefix_transitions);
                assert!(accounting.transitions_upper_bound <= prospective.work);
            }
        }
    }

    #[test]
    fn short_exact_head_continues_for_a_shorter_boundary_alternative() {
        let (incumbent, accelerated) = mixed_width_plans(64);
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        assert_eq!(tail.max_pattern_bytes, 64);
        assert_eq!(tail.trie.build_accounting().root_prefilter_offset, Some(0));
        let input_bytes = folded_short_minimum_bytes(tail).unwrap();
        assert_eq!(input_bytes, 127);
        let incumbent_work = input_bytes + 1;

        for frame in 0..BYTE_BUCKET_BLOCK_BYTES {
            let window = Window::new(frame, frame + input_bytes);
            let head = folded_short_block_head(tail, window).unwrap();
            assert_eq!(head.settled_starts, 64);
            assert_eq!(head.probe, window);
            assert_eq!(head.continuation.start(), frame + 64);
            assert!(head.continuation_accounting.searched_bytes < tail.max_pattern_bytes);
            let prospective = folded_short_prospective(tail, window, usize::MAX).unwrap();
            let tail_bytes = head.continuation_accounting.searched_bytes;
            let (root_upper, exact_blocks) = tail
                .trie
                .root_candidate_exact_block_upper_bounds(
                    tail_bytes,
                    tail.max_pattern_bytes,
                    BYTE_BUCKET_BLOCK_BYTES,
                )
                .unwrap();
            assert_eq!(tail_bytes, 63);
            assert_eq!(exact_blocks, 4);
            assert_eq!(prospective.trie, root_upper);
            assert_eq!(
                prospective.work,
                head.prefix_transitions
                    + root_upper.work
                    + exact_blocks * tail.max_pattern_bytes
                    + tail_bytes
                    + tail_bytes
                    + 1
            );
            assert!(prospective.work > incumbent_work);

            let match_start = head.continuation.start();
            let mut haystack = vec![b'!'; window.end() + 1];
            haystack[match_start] = b'x';
            let expected = incumbent
                .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap();
            assert_eq!(expected.0, Some((match_start, match_start + 1)));

            for limits in [
                LiteralSetSearchLimits::unlimited(),
                LiteralSetSearchLimits {
                    max_transitions: prospective.work,
                },
            ] {
                let actual = accelerated.find_window(&haystack, window, limits).unwrap();
                assert_eq!(actual.0, expected.0, "frame={frame}, limits={limits:?}");
                assert!(actual.1.transitions_upper_bound > head.prefix_transitions);
                assert!(actual.1.transitions_upper_bound <= prospective.work);
            }

            for limits in [
                LiteralSetSearchLimits {
                    max_transitions: prospective.work - 1,
                },
                LiteralSetSearchLimits {
                    max_transitions: incumbent_work,
                },
            ] {
                assert_eq!(
                    accelerated.find_window(&haystack, window, limits).unwrap(),
                    incumbent.find_window(&haystack, window, limits).unwrap(),
                    "frame={frame}, limits={limits:?}"
                );
            }

            let one_below = LiteralSetSearchLimits {
                max_transitions: incumbent_work - 1,
            };
            assert_eq!(
                accelerated.find_window(&haystack, window, one_below),
                incumbent.find_window(&haystack, window, one_below),
                "frame={frame}"
            );
        }
    }

    #[test]
    fn short_root_distance_decides_before_paying_exact_overlap() {
        let (incumbent, accelerated) = three_column_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        assert_eq!(tail.max_pattern_bytes, 3);
        let build = tail.trie.build_accounting();
        let primary = build.root_prefilter_offset.unwrap();
        let guard = build.root_prefilter_guard_offset.unwrap();
        let changed = (0..3)
            .find(|&offset| offset != primary && offset != guard)
            .unwrap();
        let mut rejected = *b"abc";
        rejected[changed] = b'z';
        let input_bytes = folded_short_minimum_bytes(tail).unwrap();
        let window = Window::new(0, input_bytes);
        let head = folded_short_block_head(tail, window).unwrap();
        let prospective = folded_short_prospective(tail, window, usize::MAX).unwrap();

        let first_start = head.continuation.start();
        let first_block_end = first_start + BYTE_BUCKET_BLOCK_BYTES;
        let probe_transitions = BYTE_BUCKET_BLOCK_BYTES + tail.max_pattern_bytes;
        let near_start = first_block_end + tail.max_pattern_bytes - 1;
        let later_match = near_start + BYTE_BUCKET_BLOCK_BYTES;
        let mut near = vec![b'!'; input_bytes];
        near[first_start..first_start + rejected.len()].copy_from_slice(&rejected);
        near[near_start..near_start + rejected.len()].copy_from_slice(&rejected);
        near[later_match..later_match + 3].copy_from_slice(b"abc");
        let first_root = tail
            .trie
            .find_root_candidate_precharged(&near, head.continuation, prospective.trie)
            .unwrap();
        assert_eq!(
            first_root.outcome,
            RootCandidateOutcome::Candidate { start: first_start }
        );
        let near_root = tail
            .trie
            .find_root_candidate_precharged(
                &near,
                Window::new(first_block_end, window.end()),
                prospective.trie,
            )
            .unwrap();
        assert_eq!(
            near_root.outcome,
            RootCandidateOutcome::Candidate { start: near_start }
        );
        let expected = incumbent
            .find_window(&near, window, LiteralSetSearchLimits::unlimited())
            .unwrap()
            .0;
        let (actual, accounting) = accelerated
            .find_window(&near, window, LiteralSetSearchLimits::unlimited())
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual, Some((later_match, later_match + 3)));
        assert_eq!(
            accounting.transitions_upper_bound,
            head.prefix_transitions
                + first_root.receipt.actual.work
                + probe_transitions
                + near_root.receipt.actual.work
                + (window.end() - near_start + 1),
            "a post-head distance W-1 must resume the incumbent before a second exact overlap"
        );

        let amortized_start = first_block_end + tail.max_pattern_bytes;
        let mut amortized = vec![b'!'; input_bytes];
        amortized[first_start..first_start + rejected.len()].copy_from_slice(&rejected);
        amortized[amortized_start..amortized_start + 3].copy_from_slice(b"abc");
        let first_root = tail
            .trie
            .find_root_candidate_precharged(&amortized, head.continuation, prospective.trie)
            .unwrap();
        assert_eq!(
            first_root.outcome,
            RootCandidateOutcome::Candidate { start: first_start }
        );
        let amortized_root = tail
            .trie
            .find_root_candidate_precharged(
                &amortized,
                Window::new(first_block_end, window.end()),
                prospective.trie,
            )
            .unwrap();
        assert_eq!(
            amortized_root.outcome,
            RootCandidateOutcome::Candidate {
                start: amortized_start,
            }
        );
        let (actual, accounting) = accelerated
            .find_window(
                &amortized,
                window,
                LiteralSetSearchLimits::unlimited(),
            )
            .unwrap();
        assert_eq!(actual, Some((amortized_start, amortized_start + 3)));
        assert_eq!(
            accounting.transitions_upper_bound,
            head.prefix_transitions
                + first_root.receipt.actual.work
                + probe_transitions
                + amortized_root.receipt.actual.work
                + probe_transitions,
            "a post-head distance W exactly amortizes the next authoritative block"
        );
        assert!(accounting.transitions_upper_bound <= prospective.work);
    }

    #[test]
    fn short_restarts_account_for_late_fixed_column_overlap() {
        let (incumbent, accelerated) = late_column_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        assert_eq!(tail.max_pattern_bytes, 32);
        assert_eq!(folded_short_minimum_bytes(tail), Some(95));
        let mut exact = vec![b'e'; 32];
        exact[31] = 0x7f;
        let mut rejected = exact.clone();
        rejected[1] = b'x';
        let mut haystack = vec![b'!'; tail.dfa_prefix_bytes];
        for start in [32, 80, 128] {
            haystack[start..start + exact.len()].copy_from_slice(&rejected);
        }
        let real_start = 176;
        haystack[real_start..real_start + exact.len()].copy_from_slice(&exact);
        let window = Window::full(&haystack);
        let prospective = folded_short_prospective(tail, window, usize::MAX).unwrap();
        let expected = incumbent
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap()
            .0;
        let (actual, accounting) = accelerated
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual, Some((real_start, real_start + exact.len())));
        assert!(accounting.transitions_upper_bound <= prospective.work);
    }

    #[test]
    fn short_wide_late_guard_restarts_cover_every_window_residue() {
        let (incumbent, accelerated) = wide_late_guard_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let mut exact = vec![b' '; 32];
        exact[31] = 3;
        let mut rejected = exact.clone();
        rejected[1] = b'x';
        let input_bytes = tail.dfa_prefix_bytes;
        for frame in 0..BYTE_BUCKET_BLOCK_BYTES {
            let window = Window::new(frame, frame + input_bytes);
            let mut haystack = vec![b'!'; window.end() + BYTE_BUCKET_BLOCK_BYTES];
            // Each continuation sees the next candidate at delta 33. With a
            // primary offset of 31, its wide hit is lane zero and the rounded
            // classifier frontier overlaps the next start by the maximum 31
            // bytes while the exact block remains sparse enough to continue.
            for relative_start in [33, 82, 131] {
                let start = frame + relative_start;
                haystack[start..start + rejected.len()].copy_from_slice(&rejected);
            }
            let real_start = frame + 180;
            haystack[real_start..real_start + exact.len()].copy_from_slice(&exact);
            let head = folded_short_block_head(tail, window).unwrap();
            let prospective = folded_short_prospective(tail, window, usize::MAX).unwrap();
            let trie_input_bytes = head.continuation_accounting.searched_bytes;
            let exact_blocks = trie_input_bytes.div_ceil(BYTE_BUCKET_BLOCK_BYTES);
            assert_eq!(
                prospective.trie.source_byte_reads,
                2 * (trie_input_bytes + exact_blocks * tail.max_pattern_bytes)
            );
            let mut root_start = head.continuation.start();
            let mut root_source_reads = 0;
            for relative_start in [33, 82, 131, 180] {
                let expected_start = frame + relative_start;
                let root = tail
                    .trie
                    .find_root_candidate_precharged(
                        &haystack,
                        Window::new(root_start, window.end()),
                        prospective.trie,
                    )
                    .unwrap();
                assert_eq!(
                    root.outcome,
                    RootCandidateOutcome::Candidate {
                        start: expected_start,
                    }
                );
                root_source_reads += root.receipt.actual.source_byte_reads;
                root_start = expected_start + BYTE_BUCKET_BLOCK_BYTES;
            }
            assert!(root_source_reads <= prospective.trie.source_byte_reads);
            let expected = incumbent
                .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0;
            let (actual, accounting) = accelerated
                .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap();
            assert_eq!(actual, expected, "frame={frame}");
            assert_eq!(actual, Some((real_start, real_start + exact.len())));
            assert!(accounting.transitions_upper_bound <= prospective.work);
        }
    }

    #[test]
    fn short_blocks_preserve_leftmost_first_source_priority() {
        let a = ['a'];
        let b = ['b'];
        let c = ['c'];
        let long = [
            FoldedScalarClass::new(&a),
            FoldedScalarClass::new(&b),
            FoldedScalarClass::new(&c),
        ];
        let short = [FoldedScalarClass::new(&a), FoldedScalarClass::new(&b)];
        let literals = [FoldedLiteral::new(&long), FoldedLiteral::new(&short)];
        let trie = match FoldedLiteralTriePlan::build(&literals, BuildLimits::default()).unwrap() {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("synthetic priority trie declined: {fallback:?}")
            }
        };
        let patterns = vec![b"abc".to_vec(), b"ab".to_vec()];
        let attachment =
            LiteralSetFoldAttachment::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let (accelerated, attached) = attachment.try_attach(trie, usize::MAX).unwrap();
        assert!(attached);
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let mut haystack = vec![b'!'; folded_short_minimum_bytes(tail).unwrap() + 5];
        haystack[1..4].copy_from_slice(b"abc");
        haystack[0..2].copy_from_slice(b"ab");
        assert_eq!(
            accelerated
                .find(&haystack, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((0, 2))
        );
        haystack.fill(b'!');
        haystack[1..4].copy_from_slice(b"abc");
        assert_eq!(
            accelerated
                .find(&haystack, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((1, 4))
        );
    }

    #[test]
    fn short_prospective_and_incumbent_limits_are_decided_before_the_path() {
        let (incumbent, accelerated) = plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let frame = 5;
        let input_bytes = folded_short_minimum_bytes(tail).unwrap();
        let window = Window::new(frame, frame + input_bytes);
        let mut haystack = vec![b'z'; window.end() + 7];
        haystack[window.end() - 2..window.end()].copy_from_slice(b"ka");
        let head = folded_short_block_head(tail, window).unwrap();
        assert_eq!(
            head.prefix_transitions,
            head.settled_starts + tail.max_pattern_bytes
        );
        assert_eq!(
            head.continuation,
            Window::new(frame + head.settled_starts, window.end())
        );
        assert_eq!(
            head.miss_work,
            head.prefix_transitions + input_bytes - head.settled_starts + 1
        );
        let prospective = folded_short_prospective(tail, window, usize::MAX).unwrap();
        assert!(prospective.work > head.miss_work);

        let early_start = window.start() + head.settled_starts - 1;
        let mut early = vec![b'z'; window.end() + 7];
        early[early_start..early_start + 2].copy_from_slice(b"ka");
        let early_exact = accelerated
            .find_window(
                &early,
                window,
                LiteralSetSearchLimits {
                    max_transitions: prospective.work,
                },
            )
            .unwrap();
        assert_eq!(early_exact.0, Some((early_start, early_start + 2)));
        assert_eq!(
            early_exact.1.transitions_upper_bound,
            head.prefix_transitions
        );

        let exact = accelerated
            .find_window(
                &haystack,
                window,
                LiteralSetSearchLimits {
                    max_transitions: prospective.work,
                },
            )
            .unwrap();
        assert_eq!(exact.0, Some((window.end() - 2, window.end())));
        assert!(exact.1.transitions_upper_bound <= prospective.work);

        let incumbent_limit = LiteralSetSearchLimits {
            max_transitions: prospective.work - 1,
        };
        let expected = incumbent.find_window(&haystack, window, incumbent_limit).unwrap();
        let declined = accelerated
            .find_window(&haystack, window, incumbent_limit)
            .unwrap();
        assert_eq!(declined, expected);
        assert_eq!(declined.1.transitions_upper_bound, input_bytes + 1);
        assert_eq!(
            accelerated
                .find_window(&early, window, incumbent_limit)
                .unwrap(),
            incumbent
                .find_window(&early, window, incumbent_limit)
                .unwrap(),
            "a one-below prospective must choose the incumbent before reading even a true head"
        );

        let below_incumbent = LiteralSetSearchLimits {
            max_transitions: input_bytes,
        };
        assert_eq!(
            accelerated.find_window(&haystack, window, below_incumbent),
            Err(LiteralSetError::TransitionLimit {
                needed: input_bytes + 1,
                limit: input_bytes,
            })
        );
    }

    #[test]
    fn certified_exact_head_settles_matches_from_seventeen_through_q_minus_one() {
        let (incumbent, accelerated) = plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let head = folded_long_head(tail, Window::new(0, 640)).unwrap();
        let q = head.settled_starts;
        assert!(q > BYTE_BUCKET_BLOCK_BYTES + 1);
        assert_eq!(head.probe.end(), tail.dfa_prefix_bytes);
        for start in [BYTE_BUCKET_BLOCK_BYTES + 1, q - 1, q, q + 1] {
            let mut haystack = vec![b'z'; 640];
            haystack[start..start + 2].copy_from_slice(b"ka");
            let expected = incumbent
                .find(&haystack, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0;
            let (actual, accounting) = accelerated
                .find(&haystack, LiteralSetSearchLimits::unlimited())
                .unwrap();
            assert_eq!(actual, expected);
            assert_eq!(actual, Some((start, start + 2)));
            if start < q {
                assert_eq!(accounting.transitions_upper_bound, tail.dfa_prefix_bytes + 1);
            } else {
                assert!(accounting.transitions_upper_bound > tail.dfa_prefix_bytes + 1);
            }
        }
    }

    #[test]
    fn invalid_windows_precede_zero_limits_on_the_exact_block_path() {
        let (incumbent, accelerated) = plans();
        let haystack = vec![b'z'; 640];
        let limits = LiteralSetSearchLimits { max_transitions: 0 };
        for (window, error) in [
            (
                Window::new(29, 17),
                LiteralSetError::InvalidWindow {
                    start: 29,
                    end: 17,
                    haystack_len: haystack.len(),
                },
            ),
            (
                Window::new(0, haystack.len() + 1),
                LiteralSetError::InvalidWindow {
                    start: 0,
                    end: haystack.len() + 1,
                    haystack_len: haystack.len(),
                },
            ),
        ] {
            assert_eq!(incumbent.find_window(&haystack, window, limits), Err(error.clone()));
            assert_eq!(accelerated.find_window(&haystack, window, limits), Err(error));
        }
    }

    #[test]
    fn attachment_authenticates_the_exact_patterns_and_derives_width() {
        let exact = patterns()
            .iter()
            .map(|pattern| pattern.to_vec())
            .collect::<Vec<_>>();
        let other = ['x'];
        let classes = [FoldedScalarClass::new(&other)];
        let literals = [FoldedLiteral::new(&classes)];
        let mismatched_trie = match FoldedLiteralTriePlan::build(
            &literals,
            BuildLimits::default(),
        )
        .unwrap()
        {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("synthetic mismatched trie declined: {fallback:?}")
            }
        };
        let mismatched =
            LiteralSetFoldAttachment::new(&exact, LiteralSetBuildLimits::default()).unwrap();
        assert!(mismatched.try_attach(mismatched_trie, usize::MAX).is_err());

        let attachment =
            LiteralSetFoldAttachment::new(&exact, LiteralSetBuildLimits::default()).unwrap();
        let (plan, attached) = attachment.try_attach(folded_trie(), usize::MAX).unwrap();
        assert!(attached);
        assert_eq!(
            plan.folded_long_tail
                .as_deref()
                .unwrap()
                .max_pattern_bytes,
            4
        );
    }

    #[test]
    fn exact_prospective_limit_and_one_below_use_preadmitted_paths() {
        let (incumbent, accelerated) = plans();
        let mut haystack = vec![b'z'; 640];
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let head = folded_long_head(tail, Window::full(&haystack)).unwrap();
        let matched_start = head.settled_starts;
        haystack[matched_start..matched_start + 2].copy_from_slice(b"ka");
        assert_eq!(
            head.miss_work,
            haystack.len() + tail.max_pattern_bytes + 1
        );
        let prospective = folded_long_prospective(
            tail,
            Window::full(&haystack),
            usize::MAX,
        )
        .unwrap();
        assert_eq!(
            prospective.trie,
            tail.trie
                .scan_upper_bounds(head.continuation_accounting.searched_bytes)
                .unwrap(),
            "the long path must retain its full-trie prospective envelope"
        );
        assert!(head.miss_work < prospective.work);
        let admitted = accelerated
            .find(
                &haystack,
                LiteralSetSearchLimits {
                    max_transitions: prospective.work,
                },
            )
            .unwrap();
        assert_eq!(admitted.0, Some((matched_start, matched_start + 2)));
        assert!(admitted.1.transitions_upper_bound <= prospective.work);

        let one_below = LiteralSetSearchLimits {
            max_transitions: prospective.work - 1,
        };
        let expected = incumbent.find(&haystack, one_below).unwrap();
        let actual = accelerated.find(&haystack, one_below).unwrap();
        assert_eq!(actual.0, expected.0);
        assert_eq!(actual.1.transitions_upper_bound, head.miss_work);

        let one_below_head = LiteralSetSearchLimits {
            max_transitions: head.miss_work - 1,
        };
        let expected = incumbent.find(&haystack, one_below_head).unwrap();
        let actual = accelerated.find(&haystack, one_below_head).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.1.transitions_upper_bound, haystack.len() + 1);
    }

    #[test]
    fn repeated_early_dense_hits_bypass_the_full_folded_prospective() {
        let (incumbent, accelerated) = plans();
        let haystack = b"Ka".repeat(320);
        let tail = accelerated.folded_long_tail.as_deref().unwrap();

        for start in (0..16).step_by(2) {
            let window = Window::new(start, haystack.len());
            let head = folded_long_head(tail, window).unwrap();
            assert!(
                folded_long_prospective(tail, window, head.miss_work).is_none(),
                "the head-only limit must exclude full folded planning"
            );
            let limits = LiteralSetSearchLimits {
                max_transitions: head.miss_work,
            };
            let expected = incumbent.find_window(&haystack, window, limits).unwrap();
            let actual = accelerated.find_window(&haystack, window, limits).unwrap();
            assert_eq!(actual.0, expected.0);
            assert_eq!(actual.0, Some((start, start + 2)));
            assert_eq!(actual.1.transitions_upper_bound, head.prefix_transitions);
        }
    }

    #[test]
    fn root_candidate_stream_covers_memchr_and_wide_classifier_widths() {
        fn check(equivalents: &[char], byte_patterns: &[&[u8]], matched_byte: u8) {
            let (incumbent, accelerated) = singleton_class_plans(equivalents, byte_patterns);
            let tail = accelerated.folded_long_tail.as_deref().unwrap();
            assert_eq!(
                tail.trie.build_accounting().root_prefilter_needles,
                equivalents.len()
            );
            assert_eq!(
                tail.trie
                    .build_accounting()
                    .root_prefilter_classifier_selection
                    .is_some(),
                equivalents.len() >= 4
            );
            let mut haystack = vec![b'z'; 640];
            let head = folded_long_head(tail, Window::full(&haystack)).unwrap();
            haystack[head.settled_starts] = matched_byte;
            assert_eq!(
                accelerated
                    .find(&haystack, LiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0,
                incumbent
                    .find(&haystack, LiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0
            );
        }

        check(&['a'], &[b"a"], b'a');
        check(&['a', 'b'], &[b"a", b"b"], b'b');
        check(&['a', 'b', 'c'], &[b"a", b"b", b"c"], b'c');
        check(&['a', 'b', 'c', 'd'], &[b"a", b"b", b"c", b"d"], b'd');
    }

    #[test]
    fn false_candidate_and_real_match_in_one_block_are_settled_together() {
        let (incumbent, accelerated) = three_column_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let build = tail.trie.build_accounting();
        let primary = build.root_prefilter_offset.unwrap();
        let guard = build.root_prefilter_guard_offset.unwrap();
        let changed = (0..3)
            .find(|&offset| offset != primary && offset != guard)
            .unwrap();
        let head = folded_long_head(tail, Window::new(0, 640)).unwrap();
        let false_start = head.settled_starts;
        let real_start = false_start + 5;
        let mut false_literal = *b"abc";
        false_literal[changed] = b'z';
        let mut haystack = vec![b'z'; 640];
        haystack[false_start..false_start + 3].copy_from_slice(&false_literal);
        haystack[real_start..real_start + 3].copy_from_slice(b"abc");
        let expected = incumbent
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap()
            .0;
        let (actual, accounting) = accelerated
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual, Some((real_start, real_start + 3)));
        let prospective =
            folded_long_prospective(tail, Window::full(&haystack), usize::MAX).unwrap();
        assert!(accounting.transitions_upper_bound <= prospective.work);
    }

    #[test]
    fn rejected_block_falls_back_from_its_certified_end() {
        let (incumbent, accelerated) = three_column_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let build = tail.trie.build_accounting();
        let primary = build.root_prefilter_offset.unwrap();
        let guard = build.root_prefilter_guard_offset.unwrap();
        let changed = (0..3)
            .find(|&offset| offset != primary && offset != guard)
            .unwrap();
        let head = folded_long_head(tail, Window::new(0, 640)).unwrap();
        let false_start = head.settled_starts;
        let fallback_start = false_start + BYTE_BUCKET_BLOCK_BYTES;
        let mut false_literal = *b"abc";
        false_literal[changed] = b'z';
        let mut haystack = vec![b'z'; 640];
        haystack[false_start..false_start + 3].copy_from_slice(&false_literal);
        haystack[fallback_start..fallback_start + 3].copy_from_slice(b"abc");

        let prospective =
            folded_long_prospective(tail, Window::full(&haystack), usize::MAX).unwrap();
        let root_window = Window::new(false_start, haystack.len());
        let root_upper = tail
            .trie
            .scan_upper_bounds(haystack.len() - false_start)
            .unwrap();
        let root = tail
            .trie
            .find_root_candidate_precharged(&haystack, root_window, root_upper)
            .unwrap();
        assert_eq!(
            root.outcome,
            crate::folded_literal_trie::RootCandidateOutcome::Candidate {
                start: false_start
            }
        );
        let expected_work = prospective
            .prefix_transitions
            .checked_add(root.receipt.actual.work)
            .and_then(|work| work.checked_add(BYTE_BUCKET_BLOCK_BYTES + 3))
            .and_then(|work| work.checked_add(haystack.len() - fallback_start + 1))
            .unwrap();
        let expected = incumbent
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap()
            .0;
        let (actual, accounting) = accelerated
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual, Some((fallback_start, fallback_start + 3)));
        assert_eq!(accounting.transitions_upper_bound, expected_work);
        assert!(accounting.transitions_upper_bound <= prospective.work);
    }

    #[test]
    fn two_sparse_rejected_blocks_reuse_the_full_precharge() {
        let (incumbent, accelerated) = three_column_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let build = tail.trie.build_accounting();
        let primary = build.root_prefilter_offset.unwrap();
        let guard = build.root_prefilter_guard_offset.unwrap();
        let changed = (0..3)
            .find(|&offset| offset != primary && offset != guard)
            .unwrap();
        let mut false_literal = *b"abc";
        false_literal[changed] = b'z';
        let mut haystack = vec![b'z'; 640];
        let head = folded_long_head(tail, Window::full(&haystack)).unwrap();
        let first = head.settled_starts + BYTE_BUCKET_BLOCK_BYTES * 2;
        let second = first + BYTE_BUCKET_BLOCK_BYTES * 4;
        let real = second + BYTE_BUCKET_BLOCK_BYTES * 2;
        haystack[first..first + 3].copy_from_slice(&false_literal);
        haystack[second..second + 3].copy_from_slice(&false_literal);
        haystack[real..real + 3].copy_from_slice(b"abc");
        let prospective =
            folded_long_prospective(tail, Window::full(&haystack), usize::MAX).unwrap();
        let first_root = tail
            .trie
            .find_root_candidate_precharged(
                &haystack,
                head.continuation,
                prospective.trie,
            )
            .unwrap();
        assert_eq!(
            first_root.outcome,
            crate::folded_literal_trie::RootCandidateOutcome::Candidate { start: first }
        );
        let second_root = tail
            .trie
            .find_root_candidate_precharged(
                &haystack,
                Window::new(first + BYTE_BUCKET_BLOCK_BYTES, haystack.len()),
                prospective.trie,
            )
            .unwrap();
        assert_eq!(
            second_root.outcome,
            crate::folded_literal_trie::RootCandidateOutcome::Candidate { start: second }
        );
        let expected = incumbent
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap()
            .0;
        let (actual, accounting) = accelerated
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual, Some((real, real + 3)));
        assert!(accounting.transitions_upper_bound <= prospective.work);
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
        let stable_crossing_patterns = crossing_patterns
            .iter()
            .map(|pattern| pattern.to_vec())
            .collect::<Vec<_>>();
        let crossing_attachment = LiteralSetFoldAttachment::new(
            &stable_crossing_patterns,
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        let (crossing_accelerated, crossing_attached) = crossing_attachment
            .try_attach(crossing_trie, usize::MAX)
            .unwrap();
        assert!(crossing_attached);
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
        let stable_preferred_patterns = preferred_patterns
            .iter()
            .map(|pattern| pattern.to_vec())
            .collect::<Vec<_>>();
        let preferred_attachment = LiteralSetFoldAttachment::new(
            &stable_preferred_patterns,
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        let (preferred_accelerated, preferred_attached) = preferred_attachment
            .try_attach(preferred_trie, usize::MAX)
            .unwrap();
        assert!(preferred_attached);
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
    use std::sync::Arc;

    use super::{LiteralSetBuildLimits, LiteralSetError, LiteralSetPlan, LiteralSetSearchLimits};
    use crate::Window;

    #[test]
    fn concrete_dfa_owner_preserves_clone_accounting_priority_and_iteration() {
        let ordered = LiteralSetPlan::new(
            &[b"ab".as_slice(), b"a".as_slice(), b"".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        let cloned = ordered.clone();
        assert!(Arc::ptr_eq(&ordered.automaton, &cloned.automaton));
        assert_eq!(ordered.build_accounting(), cloned.build_accounting());
        assert_eq!(
            cloned
                .find_window(
                    b"zzab",
                    Window::new(2, 4),
                    LiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some((2, 4))
        );
        assert_eq!(
            cloned
                .find_window(
                    b"zz",
                    Window::new(1, 2),
                    LiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            Some((1, 1))
        );

        let streaming = LiteralSetPlan::new_streaming_any(
            &[b"ab".as_slice(), b"a".as_slice(), b"xy".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        let prospective = streaming.find_iter_accounting(6).unwrap();
        let (matches, accounting) = streaming
            .find_iter(
                b"abaxyz",
                LiteralSetSearchLimits {
                    max_transitions: prospective.transitions_upper_bound,
                },
            )
            .unwrap();
        assert_eq!(matches.collect::<Vec<_>>(), [(0, 1), (2, 3), (3, 5)]);
        assert_eq!(accounting, prospective);
    }

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
