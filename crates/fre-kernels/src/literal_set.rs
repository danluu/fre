//! Construction-selected finite-literal matching over a bounded Aho-Corasick DFA.

use core::fmt;
use core::mem;
use std::sync::Arc;

use aho_corasick::automaton::Automaton;
use aho_corasick::dfa::DFA;
use aho_corasick::{AhoCorasick, Anchored, Input, MatchKind};
use fre_exact_alloc::try_box_preserve;
use fre_simd_kernels::BYTE_BUCKET_BLOCK_BYTES;

use crate::Window;
use crate::folded_literal_trie::{
    FoldedLiteralTriePlan, RootCandidateOutcome, ScanAttemptError as FoldedScanAttemptError,
    ScanError as FoldedScanError, ScanUpperBounds as FoldedScanUpperBounds,
};

// A short folded search performs one necessary-root pass, verifies at most one
// classifier-sized exact block and leaves any remainder to the incumbent DFA.
// Require one complete classifier block of legal starts, so the extra route is
// admitted by useful structural work rather than by a benchmark boundary.
const FOLDED_SHORT_MIN_CLASSIFIER_BLOCKS: usize = 1;

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

/// Construction-bound ordinary-search access to a positive-width,
/// attachment-free literal set.
///
/// The private field makes both properties capabilities established once by
/// [`LiteralSetPlan::ordinary_executor`]. Searches can therefore use the
/// authoritative matcher directly without repeating a route decision or
/// constructing finite-search accounting.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct LiteralSetOrdinaryExecutor<'a> {
    plan: &'a LiteralSetPlan,
}

/// Construction-bound capability for deliberately bypassing the optional
/// prefilter of a positive, fixed-width standard DFA.
///
/// This is obtainable only from an already admitted ordinary executor whose
/// immutable plan proves that first acceptance is its selected endpoint.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct LiteralSetUniformStandardOrdinaryExecutor<'a> {
    plan: &'a LiteralSetPlan,
}

#[cfg(test)]
mod ordinary_direct_probe {
    use std::cell::Cell;

    std::thread_local! {
        static CALLS: Cell<usize> = const { Cell::new(0) };
        static SPECIAL_CHECKS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn reset() {
        CALLS.set(0);
        SPECIAL_CHECKS.set(0);
    }

    pub(super) fn record() {
        CALLS.set(CALLS.get().saturating_add(1));
    }

    pub(super) fn calls() -> usize {
        CALLS.get()
    }

    pub(super) fn record_special_check() {
        SPECIAL_CHECKS.set(SPECIAL_CHECKS.get().saturating_add(1));
    }

    pub(super) fn special_checks() -> usize {
        SPECIAL_CHECKS.get()
    }
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
struct FoldedShortRootProspective {
    work: usize,
    trie: FoldedScanUpperBounds,
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
            plan: LiteralSetPlan::new_stable(patterns, limits)?,
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

    /// Bind the direct ordinary-search engine when every retained literal is
    /// positive-width and no folded attachment owns the selected route.
    ///
    /// A caller receiving `None` must retain the checked canonical engine.
    #[doc(hidden)]
    #[must_use]
    pub fn ordinary_executor(&self) -> Option<LiteralSetOrdinaryExecutor<'_>> {
        // A generic `AsRef` provider can change between preflight and DFA
        // construction, so bind positive width from the retained owner too.
        (self.build.match_semantics == LiteralSetMatchSemantics::LeftmostFirst
            && self.build.minimum_pattern_bytes > 0
            && self.automaton.min_pattern_len() > 0
            && self.folded_long_tail.is_none())
            .then_some(LiteralSetOrdinaryExecutor { plan: self })
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
            return self.find_window_folded_short_root_gate(
                haystack, window, limits, accounting, tail,
            );
        }
        let matched = self.try_find_window_value(haystack, window)?;
        Ok((matched, accounting))
    }

    #[inline]
    fn try_find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<(usize, usize)>, LiteralSetError> {
        let input = Input::new(&haystack[window.start()..window.end()]);
        self.automaton
            .as_ref()
            .try_find(&input)
            .expect("the literal-set DFA supports its construction-selected unanchored input")
            .map(|matched| absolute_match(window.start(), matched))
            .transpose()
    }

    #[inline(never)]
    fn selected_end_window_value<const FIRST_ACCEPTANCE: bool>(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Option<usize> {
        let automaton = self.automaton.as_ref();
        debug_assert!(automaton.prefilter().is_none());
        let anchored = Anchored::No;
        let mut state = automaton
            .start_state(anchored)
            .expect("the literal-set DFA retains its unanchored start state");
        let mut at = window.start();
        let mut selected = None;
        debug_assert!(!automaton.is_match(state));
        while at < window.end() {
            state = automaton.next_state(anchored, state, haystack[at]);
            at += 1;
            if automaton.is_special(state) {
                if automaton.is_dead(state) {
                    return selected;
                }
                debug_assert!(
                    automaton.is_match(state),
                    "a DFA without a prefilter has no other special states",
                );
                if automaton.is_match(state) {
                    if FIRST_ACCEPTANCE {
                        return Some(at);
                    }
                    selected = Some(at);
                }
            }
        }
        selected
    }

    #[inline]
    fn try_exists_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<bool, LiteralSetError> {
        if self.automaton.prefilter().is_some() {
            return self
                .try_find_window_value(haystack, window)
                .map(|matched| matched.is_some());
        }
        Ok(self
            .selected_end_window_value::<true>(haystack, window)
            .is_some())
    }

    #[inline]
    fn try_selected_end_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<usize>, LiteralSetError> {
        if self.automaton.prefilter().is_some()
            || self.automaton.match_kind() == MatchKind::Standard
        {
            return self
                .try_find_window_value(haystack, window)
                .map(|matched| matched.map(|(_, end)| end));
        }
        Ok(self.selected_end_window_value::<false>(haystack, window))
    }

    #[inline]
    fn find_window_folded_short_root_gate(
        &self,
        haystack: &[u8],
        window: Window,
        limits: LiteralSetSearchLimits,
        incumbent_accounting: LiteralSetAccounting,
        tail: &FoldedLongTail,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        let Some(prospective) =
            folded_short_root_prospective(tail, window, limits.max_transitions)
        else {
            return self.find_window_incumbent(haystack, window, incumbent_accounting);
        };
        let root = tail
            .trie
            .find_root_candidate_precharged(haystack, window, prospective.trie)
            .map_err(|error| map_folded_scan_error(&error))?;
        let actual_work = root.receipt.actual.work;
        let candidate_start = match root.outcome {
            RootCandidateOutcome::NoCandidate => {
                let accounting = folded_long_accounting(
                    incumbent_accounting,
                    actual_work,
                    prospective.work,
                )?;
                return Ok((None, accounting));
            }
            RootCandidateOutcome::DenseFallback { resume_start } => {
                return self.finish_folded_short_root_fallback(
                    haystack,
                    Window::new(resume_start, window.end()),
                    limits,
                    incumbent_accounting,
                    actual_work,
                    prospective.work,
                );
            }
            RootCandidateOutcome::Candidate { start } => start,
        };
        if candidate_start < window.start() || candidate_start >= window.end() {
            return Err(invariant_error(
                "folded root candidate escaped its search window",
            ));
        }

        // A candidate closer than one maximum pattern width has not paid for
        // the exact block's right overlap. It is also the dense/early shape in
        // which the incumbent DFA reaches a real match with the least work.
        // The root proof still lets that DFA start at the candidate itself.
        if candidate_start - window.start() < tail.max_pattern_bytes {
            return self.find_window_folded_short_early_candidate(
                haystack,
                window,
                limits,
                incumbent_accounting,
                tail,
                candidate_start,
                actual_work,
                prospective,
            );
        }
        self.find_window_folded_short_late_candidate(
            haystack,
            window,
            limits,
            incumbent_accounting,
            tail,
            candidate_start,
            actual_work,
            prospective,
        )
    }

    #[inline(never)]
    fn find_window_folded_short_early_candidate(
        &self,
        haystack: &[u8],
        window: Window,
        limits: LiteralSetSearchLimits,
        incumbent_accounting: LiteralSetAccounting,
        tail: &FoldedLongTail,
        candidate_start: usize,
        mut actual_work: usize,
        prospective: FoldedShortRootProspective,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        let verify_end = candidate_start
            .checked_add(tail.max_pattern_bytes)
            .map_or(window.end(), |end| end.min(window.end()));
        let verify = Window::new(candidate_start, verify_end);
        let verify_accounting = search_accounting(verify, haystack.len(), limits)?;
        let (bounded, _) =
            self.find_window_incumbent_without_prefilter(haystack, verify, verify_accounting)?;
        actual_work = actual_work
            .checked_add(verify_accounting.transitions_upper_bound)
            .ok_or(LiteralSetError::ArithmeticOverflow {
                computation: "folded literal-set bounded-verifier work",
            })?;
        if let Some(matched) = bounded {
            if matched.0 < candidate_start || matched.1 > verify_end {
                return Err(invariant_error(
                    "folded bounded verifier escaped its search window",
                ));
            }
            // Only a match at the proved root start is globally authoritative.
            // A later-start match at this artificial end may still be shadowed
            // by an earlier maximum-width match that crosses `verify_end`.
            if matched.0 == candidate_start {
                let accounting = folded_long_accounting(
                    incumbent_accounting,
                    actual_work,
                    prospective.work,
                )?;
                return Ok((Some(matched), accounting));
            }
        }
        let resume_start = candidate_start.checked_add(1).ok_or(
            LiteralSetError::ArithmeticOverflow {
                computation: "folded literal-set bounded-verifier continuation",
            },
        )?;
        if resume_start >= window.end() {
            let accounting = folded_long_accounting(
                incumbent_accounting,
                actual_work,
                prospective.work,
            )?;
            return Ok((None, accounting));
        }
        self.finish_folded_short_root_fallback(
            haystack,
            Window::new(resume_start, window.end()),
            limits,
            incumbent_accounting,
            actual_work,
            prospective.work,
        )
    }

    #[inline(never)]
    fn find_window_folded_short_late_candidate(
        &self,
        haystack: &[u8],
        window: Window,
        limits: LiteralSetSearchLimits,
        incumbent_accounting: LiteralSetAccounting,
        tail: &FoldedLongTail,
        candidate_start: usize,
        mut actual_work: usize,
        prospective: FoldedShortRootProspective,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        // Verify at most one classifier-sized block. This captures a sparse
        // late candidate without turning a false-root storm into repeated DFA
        // dispatches; after one miss the incumbent owns the exact remainder.
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
        self.finish_folded_short_root_fallback(
            haystack,
            Window::new(block_end, window.end()),
            limits,
            incumbent_accounting,
            actual_work,
            prospective.work,
        )
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
        #[cfg(test)]
        folded_short_stage_probe::record_settled_scan();
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

    #[inline]
    fn finish_folded_short_root_fallback(
        &self,
        haystack: &[u8],
        fallback_window: Window,
        limits: LiteralSetSearchLimits,
        incumbent_accounting: LiteralSetAccounting,
        partial_work: usize,
        prospective_work: usize,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        let fallback_accounting = search_accounting(fallback_window, haystack.len(), limits)?;
        let input = Input::new(&haystack[fallback_window.start()..fallback_window.end()]);
        let matched = self
            .automaton
            .as_ref()
            .try_find(&input)
            .expect("the literal-set DFA supports its construction-selected unanchored input")
            .map(|matched| absolute_match(fallback_window.start(), matched))
            .transpose()?;
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
        let matched = self.try_find_window_value(haystack, window)?;
        Ok((matched, accounting))
    }

    /// Run the authoritative DFA from a necessary-root continuation without
    /// consulting the DFA's independently retained heuristic prefilter.
    ///
    /// This mirrors `aho-corasick` 1.1.4's forward loop for both retained
    /// construction kinds. A Standard DFA returns its first acceptance;
    /// LeftmostFirst retains the last delayed match before a dead state. The
    /// DFA was built with an unanchored start state whose special-state set
    /// still includes prefilter restart states, so those starts are explicitly
    /// ignored.
    #[inline(never)]
    fn find_window_incumbent_without_prefilter(
        &self,
        haystack: &[u8],
        window: Window,
        accounting: LiteralSetAccounting,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        if self.build.match_semantics != LiteralSetMatchSemantics::LeftmostFirst
            || window.start() > window.end()
            || window.end() > haystack.len()
        {
            return Err(invariant_error(
                "invalid folded authoritative DFA continuation",
            ));
        }
        #[cfg(test)]
        folded_short_stage_probe::record_bounded_verifier();
        let automaton = self.automaton.as_ref();
        let first_acceptance = automaton.match_kind() == MatchKind::Standard;
        let anchored = Anchored::No;
        let mut state = automaton
            .start_state(anchored)
            .expect("the literal-set DFA retains its unanchored start state");
        let mut matched = None;
        if automaton.is_match(state) {
            let pattern = automaton.match_pattern(state, 0);
            let start = 0_usize.checked_sub(automaton.pattern_len(pattern)).ok_or(
                LiteralSetError::ArithmeticOverflow {
                    computation: "literal-set authoritative DFA match start",
                },
            )?;
            matched = Some(aho_corasick::Match::new(pattern, start..0));
        }
        for (index, &byte) in haystack[window.start()..window.end()].iter().enumerate() {
            state = automaton.next_state(anchored, state, byte);
            if !automaton.is_special(state) {
                continue;
            }
            if automaton.is_dead(state) {
                break;
            }
            if automaton.is_match(state) {
                let relative_end = index.checked_add(1).ok_or(
                    LiteralSetError::ArithmeticOverflow {
                        computation: "literal-set authoritative DFA relative end",
                    },
                )?;
                let pattern = automaton.match_pattern(state, 0);
                let relative_start = relative_end
                    .checked_sub(automaton.pattern_len(pattern))
                    .ok_or(LiteralSetError::ArithmeticOverflow {
                        computation: "literal-set authoritative DFA match start",
                    })?;
                matched = Some(aho_corasick::Match::new(
                    pattern,
                    relative_start..relative_end,
                ));
                if first_acceptance {
                    break;
                }
                continue;
            }
            if !automaton.is_start(state) {
                return Err(invariant_error(
                    "literal-set DFA reached an unknown special state",
                ));
            }
        }
        let matched = matched
            .map(|matched| absolute_match(window.start(), matched))
            .transpose()?;
        Ok((matched, accounting))
    }
}

impl<'a> LiteralSetOrdinaryExecutor<'a> {
    /// Bind the capability to select first acceptance by scanning this same
    /// DFA without consulting its construction-selected prefilter.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn uniform_standard_executor(
        self,
    ) -> Option<LiteralSetUniformStandardOrdinaryExecutor<'a>> {
        let build = self.plan.build;
        (self.plan.automaton.match_kind() == MatchKind::Standard
            && self.plan.automaton.prefilter().is_some()
            && build.minimum_pattern_bytes > 0
            && build.minimum_pattern_bytes.checked_mul(build.patterns) == Some(build.pattern_bytes))
        .then_some(LiteralSetUniformStandardOrdinaryExecutor { plan: self.plan })
    }

    /// Return the selected leftmost-first span wholly inside `window` without
    /// finite-search accounting.
    ///
    /// # Errors
    ///
    /// Returns the same exact invalid-window and offset-arithmetic errors as
    /// [`LiteralSetPlan::find_window`].
    #[doc(hidden)]
    #[inline]
    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<(usize, usize)>, LiteralSetError> {
        validate_window(window, haystack.len())?;
        self.plan.try_find_window_value(haystack, window)
    }

    /// Return whether any literal accepts wholly inside `window` without
    /// finite-search accounting or selected-span reconstruction.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::find_window_value`].
    #[doc(hidden)]
    #[inline]
    pub fn exists_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<bool, LiteralSetError> {
        validate_window(window, haystack.len())?;
        self.plan.try_exists_window_value(haystack, window)
    }

    /// Return only the selected span's endpoint without finite-search
    /// accounting.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::find_window_value`].
    #[doc(hidden)]
    #[inline]
    pub fn selected_end_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<usize>, LiteralSetError> {
        validate_window(window, haystack.len())?;
        self.plan.try_selected_end_window_value(haystack, window)
    }

    /// Visit every non-overlapping selected span wholly inside `window`
    /// without finite-search accounting.
    ///
    /// The ordinary-executor capability proves that every selected span has
    /// positive width. Each successful search can therefore resume directly
    /// at the selected end without the empty-match suppression required by a
    /// general regex iterator.
    ///
    /// The callback returns `Ok(true)` to continue, `Ok(false)` to stop
    /// successfully, or `Err(error)` to return that callback error.
    ///
    /// # Errors
    ///
    /// Returns the same exact invalid-window and offset-arithmetic errors as
    /// [`Self::find_window_value`].
    #[doc(hidden)]
    #[inline]
    pub fn try_visit_spans_window_value<F, E>(
        &self,
        haystack: &[u8],
        window: Window,
        mut visitor: F,
    ) -> Result<Result<(), E>, LiteralSetError>
    where
        F: FnMut((usize, usize)) -> Result<bool, E>,
    {
        validate_window(window, haystack.len())?;
        let mut cursor = window.start();
        loop {
            let matched = self
                .plan
                .try_find_window_value(haystack, Window::new(cursor, window.end()))?;
            let Some(matched) = matched else {
                return Ok(Ok(()));
            };
            debug_assert!(
                matched.1 > cursor,
                "a positive-width literal-set match must advance its search cursor",
            );
            cursor = matched.1;
            match visitor(matched) {
                Ok(true) => {}
                Ok(false) => return Ok(Ok(())),
                Err(error) => return Ok(Err(error)),
            }
        }
    }
}

impl<'a> LiteralSetUniformStandardOrdinaryExecutor<'a> {
    /// Recover the ordinary selected-span executor for operations that retain
    /// the construction-selected prefilter unconditionally.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub const fn ordinary_executor(self) -> LiteralSetOrdinaryExecutor<'a> {
        LiteralSetOrdinaryExecutor { plan: self.plan }
    }

    /// Return the construction-proved common positive literal width.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub const fn pattern_bytes(self) -> usize {
        self.plan.build.minimum_pattern_bytes
    }

    /// Return the first accepting boundary while deliberately bypassing the
    /// DFA's optional prefilter.
    ///
    /// This sealed capability proves that first acceptance is identical to the
    /// selected leftmost-first endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`LiteralSetError::InvalidWindow`] when `window` is outside the
    /// original haystack.
    #[doc(hidden)]
    #[inline]
    pub fn first_acceptance_without_prefilter_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<usize>, LiteralSetError> {
        validate_window(window, haystack.len())?;
        Ok(first_acceptance_end_without_prefilter(
            self.plan, haystack, window,
        ))
    }

    /// Visit every non-overlapping selected span with one bounded direct probe
    /// after an early prefiltered acceptance.
    ///
    /// A direct miss replays the authoritative prefiltered search from the
    /// original cursor, preserving matches that cross the probe boundary.
    ///
    /// # Errors
    ///
    /// Returns the same errors as
    /// [`LiteralSetOrdinaryExecutor::try_visit_spans_window_value`].
    #[doc(hidden)]
    #[inline]
    pub fn try_visit_spans_window_value<F, E>(
        &self,
        haystack: &[u8],
        window: Window,
        visitor: F,
    ) -> Result<Result<(), E>, LiteralSetError>
    where
        F: FnMut((usize, usize)) -> Result<bool, E>,
    {
        self.try_visit_spans_window_value_with_initial_direct(
            haystack,
            window,
            false,
            visitor,
        )
    }

    /// Visit every non-overlapping selected span, optionally spending a
    /// caller-authenticated near-acceptance observation on the first bounded
    /// direct probe.
    ///
    /// The observation affects only performance. A direct miss replays the
    /// authoritative prefiltered search from the original cursor, exactly as
    /// later locally promoted probes do.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::try_visit_spans_window_value`].
    #[doc(hidden)]
    #[inline]
    pub fn try_visit_spans_window_value_with_initial_direct<F, E>(
        &self,
        haystack: &[u8],
        window: Window,
        initial_direct: bool,
        mut visitor: F,
    ) -> Result<Result<(), E>, LiteralSetError>
    where
        F: FnMut((usize, usize)) -> Result<bool, E>,
    {
        validate_window(window, haystack.len())?;
        let uniform_width = self.pattern_bytes();
        let mut cursor = window.start();
        let mut direct_probe_bytes = initial_direct
            .then(|| uniform_width.saturating_mul(8));
        loop {
            let search_start = cursor;
            let matched = if let Some(probe_bytes) = direct_probe_bytes {
                let probe_end = cursor.saturating_add(probe_bytes).min(window.end());
                match first_acceptance_end_without_prefilter(
                    self.plan,
                    haystack,
                    Window::new(cursor, probe_end),
                ) {
                    Some(end) => {
                        debug_assert!(
                            end.checked_sub(uniform_width)
                                .is_some_and(|matched_start| matched_start >= cursor),
                            "a selected fixed-width literal must begin within its search window",
                        );
                        Some((end - uniform_width, end))
                    }
                    None => {
                        // A miss costs at most one bounded direct probe. The
                        // authoritative prefiltered search restarts at the
                        // original cursor so a match crossing the probe edge
                        // cannot be skipped.
                        direct_probe_bytes = None;
                        self.plan.try_find_window_value(
                            haystack,
                            Window::new(cursor, window.end()),
                        )?
                    }
                }
            } else {
                self.plan
                    .try_find_window_value(haystack, Window::new(cursor, window.end()))?
            };
            let Some(matched) = matched else {
                return Ok(Ok(()));
            };
            debug_assert!(
                matched.1 > cursor,
                "a positive-width literal-set match must advance its search cursor",
            );
            cursor = matched.1;
            match visitor(matched) {
                Ok(true) => {}
                Ok(false) => return Ok(Ok(())),
                Err(error) => return Ok(Err(error)),
            }
            if direct_probe_bytes.is_none() {
                // An end within 2W places the selected start in the first W
                // bytes. Once promoted, bound a mistaken density prediction
                // to eight pattern widths before authoritative replay.
                let promotion_bytes = uniform_width.saturating_mul(2);
                if cursor.saturating_sub(search_start) <= promotion_bytes {
                    direct_probe_bytes = Some(uniform_width.saturating_mul(8));
                }
            }
        }
    }
}

/// Return the first accepting endpoint while deliberately bypassing a
/// retained heuristic prefilter.
///
/// This is restricted to the stable uniform Standard construction used by
/// the ordinary executor. Its DFA can retain prefilter restart states; those
/// states are search hints rather than semantic states and are therefore
/// ignored by this direct loop.
#[inline]
fn first_acceptance_end_without_prefilter(
    plan: &LiteralSetPlan,
    haystack: &[u8],
    window: Window,
) -> Option<usize> {
    #[cfg(test)]
    ordinary_direct_probe::record();
    let automaton = plan.automaton.as_ref();
    debug_assert_eq!(automaton.match_kind(), MatchKind::Standard);
    debug_assert!(automaton.prefilter().is_some());
    debug_assert!(plan.build.minimum_pattern_bytes > 0);
    let anchored = Anchored::No;
    let mut state = automaton
        .start_state(anchored)
        .expect("the literal-set DFA retains its unanchored start state");
    let mut at = window.start();
    debug_assert!(!automaton.is_match(state));
    let pattern_bytes = plan.build.minimum_pattern_bytes;
    let window_bytes = window.end() - window.start();
    if window_bytes < pattern_bytes {
        return None;
    }
    // A fixed-width literal cannot accept before its Wth consumed byte.
    // Advance the first W-1 transitions without inspecting special-state
    // metadata, then begin the ordinary acceptance loop at byte W.
    let first_acceptance_check = window.start() + pattern_bytes - 1;
    while at < first_acceptance_check {
        state = automaton.next_state(anchored, state, haystack[at]);
        at += 1;
    }
    while at < window.end() {
        state = automaton.next_state(anchored, state, haystack[at]);
        at += 1;
        #[cfg(test)]
        ordinary_direct_probe::record_special_check();
        if !automaton.is_special(state) {
            continue;
        }
        if automaton.is_dead(state) {
            return None;
        }
        if automaton.is_match(state) {
            return Some(at);
        }
        debug_assert!(
            automaton.is_start(state),
            "a prefiltered literal-set DFA has no other special states",
        );
    }
    None
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

#[inline]
fn folded_short_minimum_bytes(tail: &FoldedLongTail) -> Option<usize> {
    let minimum_starts =
        BYTE_BUCKET_BLOCK_BYTES.checked_mul(FOLDED_SHORT_MIN_CLASSIFIER_BLOCKS)?;
    tail.max_pattern_bytes
        .checked_add(minimum_starts.checked_sub(1)?)
}

#[inline]
fn folded_short_blocks_admitted(tail: &FoldedLongTail, input_bytes: usize) -> bool {
    tail.max_pattern_bytes <= BYTE_BUCKET_BLOCK_BYTES
        && folded_short_minimum_bytes(tail).is_some_and(|minimum_bytes| {
            input_bytes >= minimum_bytes && input_bytes <= tail.dfa_prefix_bytes
        })
}

#[inline]
fn folded_short_root_prospective(
    tail: &FoldedLongTail,
    window: Window,
    max_work: usize,
) -> Option<FoldedShortRootProspective> {
    #[cfg(test)]
    folded_short_stage_probe::record_short_prospective();
    let input_bytes = window.end().checked_sub(window.start())?;
    if !folded_short_blocks_admitted(tail, input_bytes) {
        return None;
    }
    let trie = tail
        .trie
        .root_candidate_single_pass_upper_bounds(input_bytes, tail.max_pattern_bytes)
        .ok()?;
    let bounded_verify_transitions = tail.max_pattern_bytes.checked_add(1)?;
    // Every early candidate pays at most W+1 verifier transitions, settles
    // that start, then leaves at most N-1 bytes (N transitions including DFA
    // initialization) to the incumbent. Dense fallback also resumes after at
    // least one settled start. The retained late block plus its continuation
    // is bounded more tightly by N+1, so this same envelope covers every route.
    let incumbent_suffix_transitions = input_bytes;
    let work = trie
        .work
        .checked_add(bounded_verify_transitions)?
        .checked_add(incumbent_suffix_transitions)?;
    (work <= max_work).then_some(FoldedShortRootProspective { work, trie })
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
    validate_window(window, haystack_len)?;
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

#[inline]
fn validate_window(window: Window, haystack_len: usize) -> Result<(), LiteralSetError> {
    if window.start() > window.end() || window.end() > haystack_len {
        return Err(LiteralSetError::InvalidWindow {
            start: window.start(),
            end: window.end(),
            haystack_len,
        });
    }
    Ok(())
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

impl LiteralSetPlan {
    /// Compile stable owned literal alternatives into a DFA.
    ///
    /// Unlike the generic [`Self::new`] seam, the `Vec<u8>` values inspected
    /// here cannot change between preflight and automaton construction. This
    /// lets equal, positive-width alternatives select standard
    /// earliest-acceptance construction: for one fixed width, earliest end is
    /// exactly earliest start, and source priority at that start cannot alter
    /// the exposed byte span. The construction receipt nevertheless retains
    /// [`LiteralSetMatchSemantics::LeftmostFirst`] because that remains the
    /// public span contract.
    ///
    /// # Errors
    ///
    /// Returns the same construction errors as [`Self::new`].
    #[doc(hidden)]
    #[cold]
    #[inline(never)]
    pub fn new_stable(
        patterns: &[Vec<u8>],
        limits: LiteralSetBuildLimits,
    ) -> Result<Self, LiteralSetError> {
        let semantics = LiteralSetMatchSemantics::LeftmostFirst;
        let build = preflight(patterns, limits, semantics)?;
        let uniform_positive = build.minimum_pattern_bytes > 0
            && build.minimum_pattern_bytes.checked_mul(build.patterns)
                == Some(build.pattern_bytes);
        let match_kind = if uniform_positive {
            MatchKind::Standard
        } else {
            MatchKind::LeftmostFirst
        };
        let automaton = DFA::builder()
            .match_kind(match_kind)
            .build(patterns.iter().map(Vec::as_slice))
            .map_err(|error| LiteralSetError::AutomatonBuild {
                detail: error.to_string(),
            })?;
        let mut build = build;
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
}

#[cfg(test)]
mod folded_short_stage_probe {
    use std::cell::Cell;

    std::thread_local! {
        static SETTLED_SCANS: Cell<usize> = const { Cell::new(0) };
        static SHORT_PROSPECTIVES: Cell<usize> = const { Cell::new(0) };
        static BOUNDED_VERIFIERS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn record_settled_scan() {
        SETTLED_SCANS.set(
            SETTLED_SCANS
                .get()
                .checked_add(1)
                .expect("folded settled-scan probe overflow"),
        );
    }

    pub(super) fn record_short_prospective() {
        SHORT_PROSPECTIVES.set(
            SHORT_PROSPECTIVES
                .get()
                .checked_add(1)
                .expect("folded short-prospective probe overflow"),
        );
    }

    pub(super) fn record_bounded_verifier() {
        BOUNDED_VERIFIERS.set(
            BOUNDED_VERIFIERS
                .get()
                .checked_add(1)
                .expect("folded bounded-verifier probe overflow"),
        );
    }

    pub(super) fn reset() {
        SETTLED_SCANS.set(0);
        SHORT_PROSPECTIVES.set(0);
        BOUNDED_VERIFIERS.set(0);
    }

    pub(super) fn settled_scans() -> usize {
        SETTLED_SCANS.get()
    }

    pub(super) fn short_prospectives() -> usize {
        SHORT_PROSPECTIVES.get()
    }

    pub(super) fn bounded_verifiers() -> usize {
        BOUNDED_VERIFIERS.get()
    }
}

#[cfg(test)]
mod folded_long_tail_tests {
    use aho_corasick::MatchKind;
    use aho_corasick::automaton::Automaton;

    use crate::folded_literal_trie::{
        BuildAttempt, BuildLimits, FoldedLiteral, FoldedLiteralTriePlan, FoldedScalarClass,
        RootCandidateOutcome, root_candidate_dispatch_probe,
    };

    use super::{
        BYTE_BUCKET_BLOCK_BYTES, FOLDED_SHORT_MIN_CLASSIFIER_BLOCKS, LiteralSetBuildLimits,
        LiteralSetError, LiteralSetFoldAttachment, LiteralSetPlan, LiteralSetSearchLimits, Window,
        folded_long_head, folded_long_prospective, folded_short_blocks_admitted,
        folded_short_minimum_bytes, folded_short_root_prospective, folded_short_stage_probe,
        search_accounting,
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

    #[test]
    fn folded_attachment_keeps_the_canonical_route() {
        let (incumbent, accelerated) = plans();
        assert!(incumbent.ordinary_executor().is_some());
        assert!(accelerated.ordinary_executor().is_none());
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

    #[test]
    fn uniform_standard_folded_attachment_preserves_leftmost_spans() {
        folded_short_stage_probe::reset();
        let (incumbent, accelerated) = three_column_plans();
        assert_eq!(incumbent.automaton.match_kind(), MatchKind::LeftmostFirst);
        assert_eq!(accelerated.automaton.match_kind(), MatchKind::Standard);
        let tail = accelerated
            .folded_long_tail
            .as_deref()
            .expect("the uniform stable plan retains its folded attachment");
        let minimum = folded_short_minimum_bytes(tail).unwrap();
        let input_sizes = [
            minimum,
            minimum + 1,
            64,
            tail.dfa_prefix_bytes,
            tail.dfa_prefix_bytes + 1,
        ];
        for (size_index, &input_bytes) in input_sizes.iter().enumerate() {
            if input_sizes[..size_index].contains(&input_bytes) {
                continue;
            }
            for frame in 0..=2 {
                let window = Window::new(frame, frame + input_bytes);
                let mut cases = vec![vec![b'!'; window.end() + 4]];
                if input_bytes >= 3 {
                    let starts = [
                        window.start(),
                        window.start() + input_bytes / 2,
                        window.end() - 3,
                    ];
                    for &start in &starts {
                        if start + 3 > window.end() {
                            continue;
                        }
                        let mut haystack = vec![b'!'; window.end() + 4];
                        haystack[start..start + 3].copy_from_slice(b"abc");
                        cases.push(haystack);
                    }
                }
                if input_bytes >= 8 {
                    let later = window.start() + input_bytes / 2;
                    if later + 3 <= window.end() {
                        let mut false_root = vec![b'!'; window.end() + 4];
                        false_root[window.start()..window.start() + 3]
                            .copy_from_slice(b"abz");
                        false_root[later..later + 3].copy_from_slice(b"abc");
                        cases.push(false_root);
                    }
                }
                for haystack in cases {
                    let expected = incumbent
                        .find_window(
                            &haystack,
                            window,
                            LiteralSetSearchLimits::unlimited(),
                        )
                        .unwrap()
                        .0;
                    let actual = accelerated
                        .find_window(
                            &haystack,
                            window,
                            LiteralSetSearchLimits::unlimited(),
                        )
                        .unwrap()
                        .0;
                    assert_eq!(
                        actual, expected,
                        "input_bytes={input_bytes}, frame={frame}, haystack={haystack:?}",
                    );
                }
            }
        }
        assert!(
            folded_short_stage_probe::bounded_verifiers() > 0,
            "the Standard manual verifier branch must remain covered",
        );
    }

    fn bounded_shadow_plans() -> (LiteralSetPlan, LiteralSetPlan) {
        let a = ['a'];
        let b = ['b'];
        let mut long_classes = vec![FoldedScalarClass::new(&a); BYTE_BUCKET_BLOCK_BYTES];
        long_classes[0] = FoldedScalarClass::new(&b);
        let short_classes = [FoldedScalarClass::new(&a)];
        let literals = [
            FoldedLiteral::new(&long_classes),
            FoldedLiteral::new(&short_classes),
        ];
        let trie = match FoldedLiteralTriePlan::build(&literals, BuildLimits::default()).unwrap() {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("synthetic bounded-shadow trie declined: {fallback:?}")
            }
        };
        assert_eq!(trie.build_accounting().root_prefilter_offset, Some(0));
        let mut long_pattern = vec![b'a'; BYTE_BUCKET_BLOCK_BYTES];
        long_pattern[0] = b'b';
        let patterns = vec![long_pattern, b"a".to_vec()];
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
        let incumbent = LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let attachment =
            LiteralSetFoldAttachment::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let (accelerated, attached) = attachment.try_attach(trie, usize::MAX).unwrap();
        assert!(attached);
        (incumbent, accelerated)
    }

    fn wide_primary_guard_plans() -> (LiteralSetPlan, LiteralSetPlan) {
        let primary = ['\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}'];
        let guard = [' '];
        let classes = [
            FoldedScalarClass::new(&primary),
            FoldedScalarClass::new(&guard),
        ];
        let literals = [FoldedLiteral::new(&classes)];
        let trie = match FoldedLiteralTriePlan::build(&literals, BuildLimits::default()).unwrap() {
            BuildAttempt::Admitted(plan) => plan,
            BuildAttempt::DenseFallback(fallback) => {
                panic!("synthetic guarded wide-root trie declined: {fallback:?}")
            }
        };
        assert_eq!(trie.build_accounting().root_prefilter_offset, Some(0));
        assert_eq!(trie.build_accounting().root_prefilter_needles, 4);
        assert_eq!(trie.build_accounting().root_prefilter_guard_offset, Some(1));
        assert_eq!(trie.build_accounting().root_prefilter_guard_needles, 1);
        assert!(
            trie.build_accounting()
                .root_prefilter_classifier_selection
                .is_some()
        );
        let patterns = vec![
            vec![0x1c, b' '],
            vec![0x1d, b' '],
            vec![0x1e, b' '],
            vec![0x1f, b' '],
        ];
        let incumbent = LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
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
    fn bounded_dfa_driver_matches_try_find_exhaustively() {
        let pattern_sets: [Vec<&[u8]>; 8] = [
            vec![b"a", b"ab"],
            vec![b"ab", b"a"],
            vec![b"aba", b"ba", b"a"],
            vec![b"abx", b"bx", b"x"],
            vec![b"aa", b"aaa", b"aab"],
            vec![b"cab", b"ab", b"b"],
            vec![b"", b"a"],
            vec![b"a", b""],
        ];
        let alphabet = [b'a', b'b', b'x'];
        for (patterns_index, patterns) in pattern_sets.iter().enumerate() {
            let plan = LiteralSetPlan::new(patterns, LiteralSetBuildLimits::default()).unwrap();
            for haystack_len in 0..=6 {
                let sources = alphabet.len().pow(u32::try_from(haystack_len).unwrap());
                for encoded in 0..sources {
                    let mut value = encoded;
                    let mut haystack = vec![0_u8; haystack_len];
                    for byte in &mut haystack {
                        *byte = alphabet[value % alphabet.len()];
                        value /= alphabet.len();
                    }
                    for start in 0..=haystack.len() {
                        for end in start..=haystack.len() {
                            let window = Window::new(start, end);
                            let accounting = search_accounting(
                                window,
                                haystack.len(),
                                LiteralSetSearchLimits::unlimited(),
                            )
                            .unwrap();
                            let expected = plan
                                .find_window_incumbent(&haystack, window, accounting)
                                .unwrap();
                            let actual = plan
                                .find_window_incumbent_without_prefilter(
                                    &haystack,
                                    window,
                                    accounting,
                                )
                                .unwrap();
                            assert_eq!(
                                actual, expected,
                                "patterns={patterns_index}, source={haystack:?}, window={window:?}"
                            );
                        }
                    }
                }
            }
        }
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
    fn short_absence_uses_one_necessary_root_pass_without_dfa_dispatch() {
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
        let prospective = folded_short_root_prospective(tail, window, usize::MAX).unwrap();
        assert_eq!(
            prospective.trie,
            tail.trie
                .root_candidate_single_pass_upper_bounds(haystack.len(), tail.max_pattern_bytes)
                .unwrap(),
            "the short path must precharge exactly one root pass"
        );
        let root = tail
            .trie
            .find_root_candidate_precharged(&haystack, window, prospective.trie)
            .unwrap();
        assert_eq!(root.outcome, RootCandidateOutcome::NoCandidate);
        folded_short_stage_probe::reset();
        root_candidate_dispatch_probe::reset();
        let (actual, accounting) = accelerated
            .find(&haystack, LiteralSetSearchLimits::unlimited())
            .unwrap();
        assert_eq!(actual, expected.0);
        assert_eq!(actual, None);
        assert_eq!(accounting.searched_bytes, haystack.len());
        assert_eq!(accounting.transitions_upper_bound, root.receipt.actual.work);
        assert!(accounting.transitions_upper_bound <= prospective.work);
        assert_eq!(folded_short_stage_probe::settled_scans(), 0);
        assert_eq!(folded_short_stage_probe::short_prospectives(), 1);
        assert_eq!(folded_short_stage_probe::bounded_verifiers(), 0);
        assert_eq!(root_candidate_dispatch_probe::dispatches(), 1);
        assert_eq!(expected.1.transitions_upper_bound, haystack.len() + 1);
    }

    #[test]
    fn root_candidate_single_pass_envelope_seals_width_and_overflow_facts() {
        let (_, accelerated) = plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let single = tail
            .trie
            .root_candidate_single_pass_upper_bounds(64, tail.max_pattern_bytes)
            .unwrap();
        assert_eq!(single.input_bytes, 64);
        assert_eq!(single.candidate_starts, 64);
        assert_eq!(single.source_byte_reads, 2 * single.input_bytes + 2);
        assert_eq!(single.work, single.candidate_starts + single.source_byte_reads);
        let input_bytes = folded_short_minimum_bytes(tail).unwrap();
        let prospective = folded_short_root_prospective(
            tail,
            Window::new(0, input_bytes),
            usize::MAX,
        )
        .unwrap();
        assert_eq!(
            prospective.work,
            prospective.trie.work + tail.max_pattern_bytes + 1 + input_bytes,
            "one W-byte verifier and an incumbent suffix after one settled start are prepaid exactly"
        );
        assert!(matches!(
            tail.trie.root_candidate_single_pass_upper_bounds(64, 0),
            Err(crate::folded_literal_trie::ScanError::Invariant { .. })
        ));
        assert!(matches!(
            tail.trie
                .root_candidate_single_pass_upper_bounds(usize::MAX, tail.max_pattern_bytes),
            Err(crate::folded_literal_trie::ScanError::ArithmeticOverflow { .. })
        ));

        let (_, guarded) = wide_primary_guard_plans();
        let guarded_tail = guarded.folded_long_tail.as_deref().unwrap();
        let guarded_build = guarded_tail.trie.build_accounting();
        let required_width = guarded_build
            .root_prefilter_offset
            .unwrap()
            .max(guarded_build.root_prefilter_guard_offset.unwrap())
            + 1;
        assert_eq!(required_width, guarded_tail.max_pattern_bytes);
        let guarded_single = guarded_tail
            .trie
            .root_candidate_single_pass_upper_bounds(64, required_width)
            .unwrap();
        assert_eq!(
            guarded_single.source_byte_reads,
            2 * guarded_single.input_bytes + 2
        );
        assert_eq!(
            guarded_single.work,
            guarded_single.candidate_starts + guarded_single.source_byte_reads
        );
        assert!(matches!(
            guarded_tail
                .trie
                .root_candidate_single_pass_upper_bounds(64, required_width - 1),
            Err(crate::folded_literal_trie::ScanError::Invariant { .. })
        ));
        assert!(matches!(
            guarded_tail.trie.root_candidate_single_pass_upper_bounds(
                usize::MAX,
                required_width,
            ),
            Err(crate::folded_literal_trie::ScanError::ArithmeticOverflow { .. })
        ));
    }

    #[test]
    fn short_root_gate_and_long_tail_split_exactly_at_the_dfa_prefix() {
        let (_, accelerated) = plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        assert!(folded_short_minimum_bytes(tail).unwrap() <= tail.dfa_prefix_bytes);

        let short_window = Window::new(0, tail.dfa_prefix_bytes);
        assert!(folded_short_blocks_admitted(tail, tail.dfa_prefix_bytes));
        let short = folded_short_root_prospective(tail, short_window, usize::MAX).unwrap();
        assert_eq!(
            short.trie,
            tail.trie
                .root_candidate_single_pass_upper_bounds(
                    tail.dfa_prefix_bytes,
                    tail.max_pattern_bytes,
                )
                .unwrap()
        );
        assert!(folded_long_head(tail, short_window).is_none());

        let long_window = Window::new(0, tail.dfa_prefix_bytes + 1);
        assert!(folded_short_root_prospective(tail, long_window, usize::MAX).is_none());
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
        assert!(
            !folded_short_blocks_admitted(&wide, wide.dfa_prefix_bytes),
            "a width larger than one classifier block must retain the incumbent short path"
        );
        assert!(folded_short_root_prospective(&wide, short_window, usize::MAX).is_none());
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
                        let prospective = folded_short_root_prospective(tail, window, usize::MAX)
                            .expect("the complete short root-gate range is admitted");
                        assert!(accounting.transitions_upper_bound <= prospective.work);
                    }
                }
            }
        }
    }

    #[test]
    fn short_root_gate_routes_every_early_candidate_to_the_incumbent() {
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
            let prospective = folded_short_root_prospective(tail, window, usize::MAX).unwrap();
            for residue in 0..tail.max_pattern_bytes {
                let start = frame + residue;
                let mut exact = vec![b'!'; window.end() + tail.max_pattern_bytes];
                exact[start..start + 3].copy_from_slice(b"abc");
                let root = tail
                    .trie
                    .find_root_candidate_precharged(&exact, window, prospective.trie)
                    .unwrap();
                assert_eq!(root.outcome, RootCandidateOutcome::Candidate { start });
                folded_short_stage_probe::reset();
                let (matched, accounting) = accelerated
                    .find_window(&exact, window, LiteralSetSearchLimits::unlimited())
                    .unwrap();
                assert_eq!(matched, Some((start, start + 3)));
                assert_eq!(
                    accounting.transitions_upper_bound,
                    root.receipt.actual.work + tail.max_pattern_bytes + 1,
                    "frame={frame}, residue={residue}"
                );
                assert_eq!(folded_short_stage_probe::settled_scans(), 0);
                assert_eq!(folded_short_stage_probe::short_prospectives(), 1);
                assert_eq!(folded_short_stage_probe::bounded_verifiers(), 1);

                let later = frame + tail.max_pattern_bytes * 2;
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
                folded_short_stage_probe::reset();
                let (matched, accounting) = accelerated
                    .find_window(
                        &false_root,
                        window,
                        LiteralSetSearchLimits::unlimited(),
                    )
                    .unwrap();
                assert_eq!(matched, expected, "frame={frame}, residue={residue}");
                assert_eq!(matched, Some((later, later + 3)));
                assert_eq!(
                    accounting.transitions_upper_bound,
                    root.receipt.actual.work
                        + tail.max_pattern_bytes
                        + 1
                        + window.end()
                        - start
                );
                assert_eq!(folded_short_stage_probe::bounded_verifiers(), 1);
            }

            let boundary = frame + tail.max_pattern_bytes;
            let mut at_boundary = vec![b'!'; window.end() + tail.max_pattern_bytes];
            at_boundary[boundary..boundary + 3].copy_from_slice(b"abc");
            folded_short_stage_probe::reset();
            let (matched, accounting) = accelerated
                .find_window(
                    &at_boundary,
                    window,
                    LiteralSetSearchLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(matched, Some((boundary, boundary + 3)));
            assert!(accounting.transitions_upper_bound <= prospective.work);
            assert_eq!(folded_short_stage_probe::settled_scans(), 1);
            assert_eq!(folded_short_stage_probe::short_prospectives(), 1);
            assert_eq!(folded_short_stage_probe::bounded_verifiers(), 0);
        }
    }

    #[test]
    fn bounded_later_match_cannot_shadow_an_earlier_crossing_match() {
        let (incumbent, accelerated) = bounded_shadow_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let input_bytes = folded_short_minimum_bytes(tail).unwrap();
        let mut long_pattern = vec![b'a'; tail.max_pattern_bytes];
        long_pattern[0] = b'b';

        for frame in 0..BYTE_BUCKET_BLOCK_BYTES {
            let window = Window::new(frame, frame + input_bytes);
            let candidate_start = frame;
            let long_start = candidate_start + 1;
            let mut haystack = vec![b'!'; window.end()];
            haystack[candidate_start] = b'b';
            haystack[long_start..long_start + long_pattern.len()]
                .copy_from_slice(&long_pattern);
            let prospective = folded_short_root_prospective(tail, window, usize::MAX).unwrap();
            let root = tail
                .trie
                .find_root_candidate_precharged(&haystack, window, prospective.trie)
                .unwrap();
            assert_eq!(
                root.outcome,
                RootCandidateOutcome::Candidate {
                    start: candidate_start,
                }
            );
            let verify = Window::new(
                candidate_start,
                candidate_start + tail.max_pattern_bytes,
            );
            let verify_accounting = search_accounting(
                verify,
                haystack.len(),
                LiteralSetSearchLimits::unlimited(),
            )
            .unwrap();
            assert_eq!(
                accelerated
                    .find_window_incumbent_without_prefilter(
                        &haystack,
                        verify,
                        verify_accounting,
                    )
                    .unwrap()
                    .0,
                Some((candidate_start + 2, candidate_start + 3)),
                "the artificial W-byte end exposes the later short match"
            );

            folded_short_stage_probe::reset();
            root_candidate_dispatch_probe::reset();
            let actual = accelerated
                .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap();
            let expected = incumbent
                .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap();
            assert_eq!(actual.0, expected.0, "frame={frame}");
            assert_eq!(
                actual.0,
                Some((long_start, long_start + tail.max_pattern_bytes))
            );
            assert_eq!(
                actual.1.transitions_upper_bound,
                root.receipt.actual.work + tail.max_pattern_bytes + 1 + input_bytes
            );
            assert!(actual.1.transitions_upper_bound <= prospective.work);
            assert_eq!(folded_short_stage_probe::bounded_verifiers(), 1);
            assert_eq!(folded_short_stage_probe::settled_scans(), 0);
            assert_eq!(root_candidate_dispatch_probe::dispatches(), 1);
        }
    }

    #[test]
    fn bounded_false_root_storm_dispatches_once_then_resumes_the_incumbent() {
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
            let real_start = window.end() - 3;
            let mut haystack = vec![b'!'; window.end()];
            for start in (window.start()..real_start).step_by(3) {
                haystack[start..start + 3].copy_from_slice(&rejected);
            }
            haystack[real_start..real_start + 3].copy_from_slice(b"abc");
            let prospective = folded_short_root_prospective(tail, window, usize::MAX).unwrap();
            let root = tail
                .trie
                .find_root_candidate_precharged(&haystack, window, prospective.trie)
                .unwrap();
            assert_eq!(
                root.outcome,
                RootCandidateOutcome::Candidate {
                    start: window.start(),
                }
            );
            folded_short_stage_probe::reset();
            root_candidate_dispatch_probe::reset();
            let actual = accelerated
                .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap();
            let expected = incumbent
                .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap();
            assert_eq!(actual.0, expected.0, "frame={frame}");
            assert_eq!(actual.0, Some((real_start, real_start + 3)));
            assert_eq!(
                actual.1.transitions_upper_bound,
                root.receipt.actual.work + tail.max_pattern_bytes + 1 + input_bytes
            );
            assert!(actual.1.transitions_upper_bound <= prospective.work);
            assert_eq!(folded_short_stage_probe::bounded_verifiers(), 1);
            assert_eq!(folded_short_stage_probe::settled_scans(), 0);
            assert_eq!(root_candidate_dispatch_probe::dispatches(), 1);
        }
    }

    #[test]
    fn short_root_gate_is_structural_at_one_classifier_width() {
        for width in [8, 13, 14, 16] {
            let (incumbent, accelerated) = late_column_plans_with_width(width);
            let tail = accelerated.folded_long_tail.as_deref().unwrap();
            let input_bytes = folded_short_minimum_bytes(tail).unwrap();
            assert!(folded_short_blocks_admitted(tail, input_bytes));
            let mut pattern = vec![b'e'; width];
            pattern[width - 1] = 0x7f;
            for frame in 0..BYTE_BUCKET_BLOCK_BYTES {
                let window = Window::new(frame, frame + input_bytes);
                let prospective =
                    folded_short_root_prospective(tail, window, usize::MAX).unwrap();
                for relative_start in [
                    0,
                    (input_bytes - width) / 2,
                    input_bytes - width,
                ] {
                    let start = frame + relative_start;
                    let mut haystack = vec![b'!'; window.end() + width];
                    haystack[start..start + width].copy_from_slice(&pattern);
                    let expected = incumbent
                        .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                        .unwrap()
                        .0;
                    let (actual, accounting) = accelerated
                        .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                        .unwrap();
                    assert_eq!(actual, expected, "width={width}, frame={frame}");
                    assert_eq!(actual, Some((start, start + width)));
                    assert!(accounting.transitions_upper_bound <= prospective.work);
                }
            }
        }

        for width in [17, 32, 80] {
            let (incumbent, accelerated) = late_column_plans_with_width(width);
            let tail = accelerated.folded_long_tail.as_deref().unwrap();
            let input_bytes = folded_short_minimum_bytes(tail).unwrap();
            assert!(!folded_short_blocks_admitted(tail, input_bytes));
            let window = Window::new(3, 3 + input_bytes);
            assert!(folded_short_root_prospective(tail, window, usize::MAX).is_none());
            let mut pattern = vec![b'e'; width];
            pattern[width - 1] = 0x7f;
            let start = window.start() + width;
            let mut haystack = vec![b'!'; window.end() + width];
            haystack[start..start + width].copy_from_slice(&pattern);
            assert_eq!(
                accelerated
                    .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                    .unwrap(),
                incumbent
                    .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                    .unwrap(),
                "width={width} must retain the incumbent short path"
            );
        }
    }

    #[test]
    fn short_root_gate_admits_exactly_one_classifier_block_of_starts() {
        for width in [2, BYTE_BUCKET_BLOCK_BYTES] {
            let (_, accelerated) = late_column_plans_with_width(width);
            let tail = accelerated.folded_long_tail.as_deref().unwrap();
            assert_eq!(tail.max_pattern_bytes, width);

            let below = width + BYTE_BUCKET_BLOCK_BYTES - 2;
            let boundary = width + BYTE_BUCKET_BLOCK_BYTES - 1;
            assert_eq!(boundary - width + 1, BYTE_BUCKET_BLOCK_BYTES);
            assert!(!folded_short_blocks_admitted(tail, below));
            assert!(folded_short_blocks_admitted(tail, boundary));

            let frame = 7;
            assert!(
                folded_short_root_prospective(
                    tail,
                    Window::new(frame, frame + below),
                    usize::MAX,
                )
                .is_none()
            );
            assert!(
                folded_short_root_prospective(
                    tail,
                    Window::new(frame, frame + boundary),
                    usize::MAX,
                )
                .is_some()
            );
        }
    }

    #[test]
    fn short_root_gate_verifies_once_then_gives_the_remainder_to_the_incumbent() {
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
        let input_bytes = folded_short_minimum_bytes(tail).unwrap() + 19;

        for frame in 0..BYTE_BUCKET_BLOCK_BYTES {
            let window = Window::new(frame, frame + input_bytes);
            let prospective = folded_short_root_prospective(tail, window, usize::MAX).unwrap();
            let false_start = frame + tail.max_pattern_bytes;
            let block_end = false_start + BYTE_BUCKET_BLOCK_BYTES;
            let real_start = block_end + 2;
            let mut haystack = vec![b'!'; window.end() + 3];
            haystack[false_start..false_start + 3].copy_from_slice(&rejected);
            haystack[real_start..real_start + 3].copy_from_slice(b"abc");
            let root = tail
                .trie
                .find_root_candidate_precharged(&haystack, window, prospective.trie)
                .unwrap();
            assert_eq!(
                root.outcome,
                RootCandidateOutcome::Candidate { start: false_start }
            );
            let probe_end = (block_end + tail.max_pattern_bytes - 1).min(window.end());
            let probe_transitions = probe_end - false_start + 1;
            folded_short_stage_probe::reset();
            let (actual, accounting) = accelerated
                .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap();
            assert_eq!(
                actual,
                incumbent
                    .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0
            );
            assert_eq!(actual, Some((real_start, real_start + 3)));
            assert_eq!(
                accounting.transitions_upper_bound,
                root.receipt.actual.work
                    + probe_transitions
                    + window.end()
                    - block_end
                    + 1
            );
            assert!(accounting.transitions_upper_bound <= prospective.work);
            assert_eq!(folded_short_stage_probe::settled_scans(), 1);
            assert_eq!(folded_short_stage_probe::short_prospectives(), 1);
            assert_eq!(folded_short_stage_probe::bounded_verifiers(), 0);
        }
    }

    #[test]
    fn short_mixed_width_preserves_shorter_boundary_matches() {
        let (incumbent, accelerated) = mixed_width_plans(BYTE_BUCKET_BLOCK_BYTES);
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        assert_eq!(tail.max_pattern_bytes, BYTE_BUCKET_BLOCK_BYTES);
        let input_bytes = folded_short_minimum_bytes(tail).unwrap();
        let window = Window::new(0, input_bytes);
        let prospective = folded_short_root_prospective(tail, window, usize::MAX).unwrap();

        for (candidate_start, expected_settled_scans, expected_bounded_verifiers) in [
            (tail.max_pattern_bytes - 1, 0, 1),
            (tail.max_pattern_bytes, 1, 0),
        ] {
            let mut haystack = vec![b'!'; input_bytes];
            haystack[candidate_start] = b'x';
            folded_short_stage_probe::reset();
            root_candidate_dispatch_probe::reset();
            let actual = accelerated
                .find_window(
                    &haystack,
                    window,
                    LiteralSetSearchLimits {
                        max_transitions: prospective.work,
                    },
                )
                .unwrap();
            assert_eq!(
                actual.0,
                incumbent
                    .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0
            );
            assert_eq!(actual.0, Some((candidate_start, candidate_start + 1)));
            assert!(actual.1.transitions_upper_bound <= prospective.work);
            assert_eq!(
                folded_short_stage_probe::settled_scans(),
                expected_settled_scans
            );
            assert_eq!(
                folded_short_stage_probe::bounded_verifiers(),
                expected_bounded_verifiers
            );
            assert_eq!(root_candidate_dispatch_probe::dispatches(), 1);
        }

        let candidate_start = tail.max_pattern_bytes;
        let block_end = candidate_start + BYTE_BUCKET_BLOCK_BYTES;
        let remainder_input_bytes = input_bytes.max(block_end + 1);
        let remainder_window = Window::new(0, remainder_input_bytes);
        let remainder_prospective =
            folded_short_root_prospective(tail, remainder_window, usize::MAX).unwrap();
        let mut haystack = vec![b'!'; remainder_input_bytes];
        haystack[candidate_start..candidate_start + tail.max_pattern_bytes].fill(b'e');
        haystack[block_end] = b'x';
        folded_short_stage_probe::reset();
        root_candidate_dispatch_probe::reset();
        let actual = accelerated
            .find_window(
                &haystack,
                remainder_window,
                LiteralSetSearchLimits {
                    max_transitions: remainder_prospective.work,
                },
            )
            .unwrap();
        assert_eq!(
            actual.0,
            incumbent
                .find_window(
                    &haystack,
                    remainder_window,
                    LiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0
        );
        assert_eq!(actual.0, Some((block_end, block_end + 1)));
        assert!(actual.1.transitions_upper_bound <= remainder_prospective.work);
        assert_eq!(folded_short_stage_probe::settled_scans(), 1);
        assert_eq!(folded_short_stage_probe::bounded_verifiers(), 0);
        assert_eq!(root_candidate_dispatch_probe::dispatches(), 1);
    }

    #[test]
    fn short_guard_rejection_dense_fallback_resumes_after_the_proved_start() {
        let (incumbent, accelerated) = wide_primary_guard_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let real_start = BYTE_BUCKET_BLOCK_BYTES * 2;
        let input_bytes = folded_short_minimum_bytes(tail).unwrap().max(real_start + 2);
        let window = Window::new(0, input_bytes);
        let prospective = folded_short_root_prospective(tail, window, usize::MAX).unwrap();
        let resume_start = 2;
        let mut haystack = vec![0x1c; input_bytes];
        haystack[real_start..real_start + 2].copy_from_slice(&[0x1c, b' ']);
        let root = tail
            .trie
            .find_root_candidate_precharged(&haystack, window, prospective.trie)
            .unwrap();
        assert_eq!(
            root.outcome,
            RootCandidateOutcome::DenseFallback { resume_start }
        );

        folded_short_stage_probe::reset();
        root_candidate_dispatch_probe::reset();
        let actual = accelerated
            .find_window(
                &haystack,
                window,
                LiteralSetSearchLimits {
                    max_transitions: prospective.work,
                },
            )
            .unwrap();
        assert_eq!(
            actual.0,
            incumbent
                .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0
        );
        assert_eq!(actual.0, Some((real_start, real_start + 2)));
        assert_eq!(
            actual.1.transitions_upper_bound,
            root.receipt.actual.work + window.end() - resume_start + 1
        );
        assert!(actual.1.transitions_upper_bound <= prospective.work);
        assert_eq!(folded_short_stage_probe::settled_scans(), 0);
        assert_eq!(folded_short_stage_probe::short_prospectives(), 1);
        assert_eq!(folded_short_stage_probe::bounded_verifiers(), 0);
        assert_eq!(root_candidate_dispatch_probe::dispatches(), 1);
    }

    #[test]
    fn short_root_gate_limit_is_decided_before_source_dispatch() {
        let (incumbent, accelerated) = three_column_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let input_bytes = folded_short_minimum_bytes(tail).unwrap();
        let window = Window::new(5, 5 + input_bytes);
        let prospective = folded_short_root_prospective(tail, window, usize::MAX).unwrap();
        assert!(prospective.work > input_bytes + 1);
        let mut haystack = vec![b'!'; window.end() + 3];
        let start = window.start() + tail.max_pattern_bytes;
        haystack[start..start + 3].copy_from_slice(b"abc");

        folded_short_stage_probe::reset();
        let admitted = accelerated
            .find_window(
                &haystack,
                window,
                LiteralSetSearchLimits {
                    max_transitions: prospective.work,
                },
            )
            .unwrap();
        assert_eq!(admitted.0, Some((start, start + 3)));
        assert_eq!(folded_short_stage_probe::settled_scans(), 1);
        assert_eq!(folded_short_stage_probe::short_prospectives(), 1);

        let declined_limit = LiteralSetSearchLimits {
            max_transitions: prospective.work - 1,
        };
        folded_short_stage_probe::reset();
        assert_eq!(
            accelerated
                .find_window(&haystack, window, declined_limit)
                .unwrap(),
            incumbent
                .find_window(&haystack, window, declined_limit)
                .unwrap()
        );
        assert_eq!(folded_short_stage_probe::settled_scans(), 0);
        assert_eq!(folded_short_stage_probe::short_prospectives(), 1);

        let below_incumbent = LiteralSetSearchLimits {
            max_transitions: input_bytes,
        };
        folded_short_stage_probe::reset();
        assert_eq!(
            accelerated.find_window(&haystack, window, below_incumbent),
            Err(LiteralSetError::TransitionLimit {
                needed: input_bytes + 1,
                limit: input_bytes,
            })
        );
        assert_eq!(folded_short_stage_probe::settled_scans(), 0);
        assert_eq!(folded_short_stage_probe::short_prospectives(), 0);
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
        haystack[..3].copy_from_slice(b"abc");
        folded_short_stage_probe::reset();
        assert_eq!(
            accelerated
                .find(&haystack, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((0, 3)),
            "the bounded verifier must retain source-zero priority over its prefix"
        );
        assert_eq!(folded_short_stage_probe::bounded_verifiers(), 1);
        haystack.fill(b'!');
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
        haystack.fill(b'!');
        let late_start = tail.max_pattern_bytes;
        haystack[late_start..late_start + 3].copy_from_slice(b"abc");
        folded_short_stage_probe::reset();
        root_candidate_dispatch_probe::reset();
        assert_eq!(
            accelerated
                .find(&haystack, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((late_start, late_start + 3))
        );
        assert_eq!(folded_short_stage_probe::settled_scans(), 1);
        assert_eq!(folded_short_stage_probe::bounded_verifiers(), 0);
        assert_eq!(root_candidate_dispatch_probe::dispatches(), 1);
    }

    #[test]
    fn long_wide_late_guard_restarts_cover_every_window_residue() {
        let (incumbent, accelerated) = wide_late_guard_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let mut exact = vec![b' '; 32];
        exact[31] = 3;
        let mut rejected = exact.clone();
        rejected[1] = b'x';
        let input_bytes = tail.dfa_prefix_bytes + 256;
        assert!(input_bytes > tail.dfa_prefix_bytes);

        for frame in 0..BYTE_BUCKET_BLOCK_BYTES {
            let window = Window::new(frame, frame + input_bytes);
            let head = folded_long_head(tail, window).unwrap();
            let prospective = folded_long_prospective(tail, window, usize::MAX).unwrap();
            let continuation = head.continuation.start();
            let relative_candidates = [33, 82, 131, 180];
            let mut haystack = vec![b'!'; window.end() + BYTE_BUCKET_BLOCK_BYTES];
            for relative_start in &relative_candidates[..3] {
                let start = continuation + relative_start;
                haystack[start..start + rejected.len()].copy_from_slice(&rejected);
            }
            let real_start = continuation + relative_candidates[3];
            haystack[real_start..real_start + exact.len()].copy_from_slice(&exact);

            let mut root_start = continuation;
            let mut root_source_reads = 0;
            for relative_start in relative_candidates {
                let expected_start = continuation + relative_start;
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
                    },
                    "frame={frame}"
                );
                root_source_reads += root.receipt.actual.source_byte_reads;
                root_start = expected_start + BYTE_BUCKET_BLOCK_BYTES;
            }
            assert!(root_source_reads <= prospective.trie.source_byte_reads);

            root_candidate_dispatch_probe::reset();
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
            assert_eq!(root_candidate_dispatch_probe::dispatches(), 4);
        }
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

            let short_bytes = folded_short_minimum_bytes(tail).unwrap();
            let short_window = Window::new(3, 3 + short_bytes);
            let prospective =
                folded_short_root_prospective(tail, short_window, usize::MAX).unwrap();
            for relative_start in [0, 1, BYTE_BUCKET_BLOCK_BYTES, short_bytes - 1] {
                let mut short = vec![b'z'; short_window.end() + 1];
                short[short_window.start() + relative_start] = matched_byte;
                let (actual, accounting) = accelerated
                    .find_window(
                        &short,
                        short_window,
                        LiteralSetSearchLimits::unlimited(),
                    )
                    .unwrap();
                assert_eq!(
                    actual,
                    incumbent
                        .find_window(
                            &short,
                            short_window,
                            LiteralSetSearchLimits::unlimited(),
                        )
                        .unwrap()
                        .0
                );
                assert!(accounting.transitions_upper_bound <= prospective.work);
            }
            let absent = vec![b'z'; short_window.end() + 1];
            assert_eq!(
                accelerated
                    .find_window(
                        &absent,
                        short_window,
                        LiteralSetSearchLimits::unlimited(),
                    )
                    .unwrap()
                    .0,
                None
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
    fn unguarded_root_settles_first_start_before_the_unchanged_scanner() {
        let (_, accelerated) =
            singleton_class_plans(&['a', 'b', 'c', 'd'], &[b"a", b"b", b"c", b"d"]);
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let input_bytes = folded_short_minimum_bytes(tail).unwrap();
        let window = Window::new(5, 5 + input_bytes);
        let upper = tail
            .trie
            .root_candidate_single_pass_upper_bounds(input_bytes, tail.max_pattern_bytes)
            .unwrap();
        assert_eq!(upper.source_byte_reads, input_bytes + 1);

        let mut source = vec![b'z'; window.end()];
        let absent = tail
            .trie
            .find_root_candidate_precharged(&source, window, upper)
            .unwrap();
        assert_eq!(absent.outcome, RootCandidateOutcome::NoCandidate);
        assert_eq!(absent.receipt.actual.source_byte_reads, input_bytes + 1);
        assert_eq!(absent.receipt.actual.candidate_starts, 0);
        assert_eq!(absent.receipt.actual.work, input_bytes + 1);

        source[window.start()] = b'd';
        let first = tail
            .trie
            .find_root_candidate_precharged(&source, window, upper)
            .unwrap();
        assert_eq!(
            first.outcome,
            RootCandidateOutcome::Candidate {
                start: window.start(),
            }
        );
        assert_eq!(first.receipt.actual.source_byte_reads, 1);
        assert_eq!(first.receipt.actual.candidate_starts, 1);
        assert_eq!(first.receipt.actual.work, 2);

        source[window.start()] = b'z';
        source[window.start() + 1] = b'd';
        let later = tail
            .trie
            .find_root_candidate_precharged(&source, window, upper)
            .unwrap();
        assert_eq!(
            later.outcome,
            RootCandidateOutcome::Candidate {
                start: window.start() + 1,
            }
        );
        assert_eq!(later.receipt.actual.source_byte_reads, 1 + BYTE_BUCKET_BLOCK_BYTES);
        assert_eq!(later.receipt.actual.candidate_starts, 1);
        assert_eq!(
            later.receipt.actual.work,
            2 + BYTE_BUCKET_BLOCK_BYTES
        );
    }

    #[test]
    fn guarded_root_settles_first_start_before_the_unchanged_scanner() {
        let (_, accelerated) = wide_primary_guard_plans();
        let tail = accelerated.folded_long_tail.as_deref().unwrap();
        let input_bytes = folded_short_minimum_bytes(tail).unwrap();
        let window = Window::new(7, 7 + input_bytes);
        let upper = tail
            .trie
            .root_candidate_single_pass_upper_bounds(input_bytes, tail.max_pattern_bytes)
            .unwrap();
        assert_eq!(upper.source_byte_reads, 2 * input_bytes + 2);

        let mut source = vec![b'z'; window.end()];
        source[window.start()] = 0x1c;
        source[window.start() + 1] = b' ';
        let first = tail
            .trie
            .find_root_candidate_precharged(&source, window, upper)
            .unwrap();
        assert_eq!(
            first.outcome,
            RootCandidateOutcome::Candidate {
                start: window.start(),
            }
        );
        assert_eq!(first.receipt.actual.source_byte_reads, 2);
        assert_eq!(first.receipt.actual.candidate_starts, 1);
        assert_eq!(first.receipt.actual.work, 3);
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
    use std::cell::Cell;
    use std::sync::Arc;

    use aho_corasick::automaton::Automaton;
    use aho_corasick::dfa::DFA;
    use aho_corasick::{Input, MatchKind};

    use super::{
        LiteralSetBuildLimits, LiteralSetError, LiteralSetMatchSemantics, LiteralSetPlan,
        LiteralSetSearchLimits, first_acceptance_end_without_prefilter, ordinary_direct_probe,
    };
    use crate::Window;

    fn reference_find(
        automaton: &DFA,
        haystack: &[u8],
        window: Window,
    ) -> Option<(usize, usize)> {
        let input = Input::new(&haystack[window.start()..window.end()]);
        automaton.try_find(&input).unwrap().map(|matched| {
            (
                window.start() + matched.start(),
                window.start() + matched.end(),
            )
        })
    }

    fn assert_leftmost_window_differential(
        patterns: &[Vec<u8>],
        plan: &LiteralSetPlan,
        maximum_haystack_bytes: usize,
    ) {
        let reference = DFA::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns.iter().map(Vec::as_slice))
            .unwrap();
        let ordinary = plan.ordinary_executor();
        let alphabet = [b'a', b'b', b'x'];
        for haystack_len in 0..=maximum_haystack_bytes {
            let sources = alphabet.len().pow(u32::try_from(haystack_len).unwrap());
            for encoded in 0..sources {
                let mut value = encoded;
                let mut haystack = vec![0_u8; haystack_len];
                for byte in &mut haystack {
                    *byte = alphabet[value % alphabet.len()];
                    value /= alphabet.len();
                }
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = Window::new(start, end);
                        let expected = reference_find(&reference, &haystack, window);
                        let actual = plan
                            .find_window(
                                &haystack,
                                window,
                                LiteralSetSearchLimits::unlimited(),
                            )
                            .unwrap()
                            .0;
                        assert_eq!(
                            actual, expected,
                            "patterns={patterns:?}, haystack={haystack:?}, window={window:?}",
                        );
                        let Some(ordinary) = ordinary else {
                            continue;
                        };
                        assert_eq!(
                            ordinary.find_window_value(&haystack, window),
                            Ok(expected),
                            "patterns={patterns:?}, haystack={haystack:?}, window={window:?}",
                        );
                        assert_eq!(
                            ordinary.exists_window_value(&haystack, window),
                            Ok(expected.is_some()),
                            "patterns={patterns:?}, haystack={haystack:?}, window={window:?}",
                        );
                        assert_eq!(
                            ordinary.selected_end_window_value(&haystack, window),
                            Ok(expected.map(|(_, matched_end)| matched_end)),
                            "patterns={patterns:?}, haystack={haystack:?}, window={window:?}",
                        );
                        if let Some(uniform) = ordinary.uniform_standard_executor() {
                            assert_eq!(
                                uniform.first_acceptance_without_prefilter_window_value(
                                    &haystack, window,
                                ),
                                Ok(expected.map(|(_, matched_end)| matched_end)),
                                "patterns={patterns:?}, haystack={haystack:?}, window={window:?}",
                            );
                        }

                        let mut expected_spans = Vec::new();
                        let mut cursor = window.start();
                        while let Some(matched) = reference_find(
                            &reference,
                            &haystack,
                            Window::new(cursor, window.end()),
                        ) {
                            assert!(matched.1 > cursor);
                            cursor = matched.1;
                            expected_spans.push(matched);
                        }
                        let mut actual_spans = Vec::new();
                        assert_eq!(
                            ordinary.try_visit_spans_window_value(
                                &haystack,
                                window,
                                |matched| {
                                    actual_spans.push(matched);
                                    Ok::<bool, ()>(true)
                                },
                            ),
                            Ok(Ok(())),
                        );
                        assert_eq!(
                            actual_spans, expected_spans,
                            "patterns={patterns:?}, haystack={haystack:?}, window={window:?}",
                        );
                        if let Some(uniform) = ordinary.uniform_standard_executor() {
                            let mut uniform_spans = Vec::new();
                            assert_eq!(
                                uniform.try_visit_spans_window_value(
                                    &haystack,
                                    window,
                                    |matched| {
                                        uniform_spans.push(matched);
                                        Ok::<bool, ()>(true)
                                    },
                                ),
                                Ok(Ok(())),
                            );
                            assert_eq!(
                                uniform_spans, expected_spans,
                                "patterns={patterns:?}, haystack={haystack:?}, window={window:?}",
                            );

                            let mut initially_direct_spans = Vec::new();
                            assert_eq!(
                                uniform.try_visit_spans_window_value_with_initial_direct(
                                    &haystack,
                                    window,
                                    true,
                                    |matched| {
                                        initially_direct_spans.push(matched);
                                        Ok::<bool, ()>(true)
                                    },
                                ),
                                Ok(Ok(())),
                            );
                            assert_eq!(
                                initially_direct_spans, expected_spans,
                                "initial direct replay diverged: patterns={patterns:?}, haystack={haystack:?}, window={window:?}",
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn stable_uniform_standard_matches_leftmost_first_exhaustively() {
        for width in 1..=3 {
            let word_count = 2_usize.pow(u32::try_from(width).unwrap());
            let words = (0..word_count)
                .map(|encoded| {
                    let mut value = encoded;
                    let mut word = vec![0_u8; width];
                    for byte in &mut word {
                        *byte = if value & 1 == 0 { b'a' } else { b'b' };
                        value >>= 1;
                    }
                    word
                })
                .collect::<Vec<_>>();
            for pattern_count in 1..=2 {
                let pattern_sets = words
                    .len()
                    .pow(u32::try_from(pattern_count).unwrap());
                for encoded in 0..pattern_sets {
                    let mut value = encoded;
                    let mut patterns = Vec::with_capacity(pattern_count);
                    for _ in 0..pattern_count {
                        patterns.push(words[value % words.len()].clone());
                        value /= words.len();
                    }
                    let plan = LiteralSetPlan::new_stable(
                        &patterns,
                        LiteralSetBuildLimits::default(),
                    )
                    .unwrap();
                    assert_eq!(
                        plan.build_accounting().match_semantics,
                        LiteralSetMatchSemantics::LeftmostFirst,
                    );
                    assert_eq!(plan.automaton.match_kind(), MatchKind::Standard);
                    assert_leftmost_window_differential(&patterns, &plan, 5);
                }
            }
        }

        let nonuniform_controls = [
            vec![b"a".to_vec(), b"ab".to_vec()],
            vec![b"ab".to_vec(), b"a".to_vec()],
            vec![b"b".to_vec(), b"abc".to_vec()],
            vec![b"aba".to_vec(), b"b".to_vec(), b"aba".to_vec()],
            vec![Vec::new(), b"a".to_vec()],
            vec![Vec::new(), Vec::new()],
        ];
        for patterns in nonuniform_controls {
            let plan = LiteralSetPlan::new_stable(
                &patterns,
                LiteralSetBuildLimits::default(),
            )
            .unwrap();
            assert_eq!(plan.automaton.match_kind(), MatchKind::LeftmostFirst);
            assert_leftmost_window_differential(&patterns, &plan, 5);
        }

        let divergent = LiteralSetPlan::new_stable(
            &[b"b".to_vec(), b"abc".to_vec()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            divergent
                .find(b"abc", LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((0, 3)),
        );

        let generic = LiteralSetPlan::new(
            &[b"ab".as_slice(), b"cd".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert_eq!(generic.automaton.match_kind(), MatchKind::LeftmostFirst);
    }

    #[test]
    fn uniform_standard_span_iteration_bounds_direct_dense_probes() {
        let patterns = (0_u16..256)
            .map(|id| {
                vec![
                    if id & 1 == 0 { b'q' } else { b'z' },
                    (id >> 1) as u8,
                    b'!',
                    b'@',
                    b'#',
                    b'$',
                    b'%',
                    b'^',
                ]
            })
            .collect::<Vec<_>>();
        let plan = LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default())
            .expect("uniform plan");
        assert_eq!(plan.automaton.match_kind(), MatchKind::Standard);
        assert!(plan.automaton.prefilter().is_some());
        let ordinary = plan.ordinary_executor().expect("ordinary executor");
        let uniform = ordinary
            .uniform_standard_executor()
            .expect("prefiltered uniform standard capability");
        assert_eq!(uniform.pattern_bytes(), 8);

        let mut haystack = b"PP".to_vec();
        haystack.extend_from_slice(&patterns[0]);
        haystack.push(b'x');
        haystack.extend_from_slice(&patterns[1]);
        haystack.extend_from_slice(&[b'x'; 61]);
        haystack.extend_from_slice(&patterns[2]);
        haystack.extend_from_slice(b"SS");
        let window = Window::new(2, haystack.len() - 2);
        let reference = DFA::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns.iter().map(Vec::as_slice))
            .unwrap();
        let mut expected = Vec::new();
        let mut cursor = window.start();
        while let Some(matched) = reference_find(
            &reference,
            &haystack,
            Window::new(cursor, window.end()),
        ) {
            cursor = matched.1;
            expected.push(matched);
        }
        assert_eq!(
            uniform.first_acceptance_without_prefilter_window_value(&haystack, window),
            Ok(expected.first().map(|matched| matched.1)),
        );

        ordinary_direct_probe::reset();
        let mut actual = Vec::new();
        assert_eq!(
            uniform.try_visit_spans_window_value(
                &haystack,
                window,
                |matched| {
                    actual.push(matched);
                    Ok::<bool, ()>(true)
                },
            ),
            Ok(Ok(())),
        );
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 3);
        assert!(actual[2].0 < actual[1].1 + 64);
        assert!(actual[2].1 > actual[1].1 + 64);
        assert!(ordinary_direct_probe::calls() >= 2);

        let mut far = vec![b'x'; 32];
        far.extend_from_slice(&patterns[0]);
        far.extend_from_slice(&[b'x'; 32]);
        ordinary_direct_probe::reset();
        assert_eq!(
            uniform.try_visit_spans_window_value(
                &far,
                Window::full(&far),
                |_| Ok::<bool, ()>(true),
            ),
            Ok(Ok(())),
        );
        assert_eq!(ordinary_direct_probe::calls(), 0);

        // An externally authenticated near predecessor may promote the first
        // tail probe. A match crossing the 8W edge is recovered by canonical
        // replay from the original tail cursor.
        let mut crossing = vec![b'x'; 72];
        crossing[57..65].copy_from_slice(&patterns[0]);
        ordinary_direct_probe::reset();
        let mut crossing_actual = Vec::new();
        assert_eq!(
            uniform.try_visit_spans_window_value_with_initial_direct(
                &crossing,
                Window::full(&crossing),
                true,
                |matched| {
                    crossing_actual.push(matched);
                    Ok::<bool, ()>(true)
                },
            ),
            Ok(Ok(())),
        );
        assert_eq!(crossing_actual, [(57, 65)]);
        assert_eq!(ordinary_direct_probe::calls(), 1);

        ordinary_direct_probe::reset();
        assert_eq!(
            uniform.try_visit_spans_window_value_with_initial_direct(
                &far,
                Window::full(&far),
                true,
                |_| Ok::<bool, ()>(false),
            ),
            Ok(Ok(())),
        );
        assert_eq!(ordinary_direct_probe::calls(), 1);

        ordinary_direct_probe::reset();
        assert_eq!(
            uniform.try_visit_spans_window_value_with_initial_direct(
                &far,
                Window::full(&far),
                true,
                |_| Err::<bool, _>("callback"),
            ),
            Ok(Err("callback")),
        );
        assert_eq!(ordinary_direct_probe::calls(), 1);

        ordinary_direct_probe::reset();
        assert_eq!(
            uniform.try_visit_spans_window_value(
                &haystack,
                window,
                |_| Ok::<bool, ()>(false),
            ),
            Ok(Ok(())),
        );
        assert_eq!(ordinary_direct_probe::calls(), 0);

        ordinary_direct_probe::reset();
        assert_eq!(
            uniform.try_visit_spans_window_value(
                &haystack,
                window,
                |_| Err::<bool, _>("callback"),
            ),
            Ok(Err("callback")),
        );
        assert_eq!(ordinary_direct_probe::calls(), 0);

        let no_prefilter_patterns = (0_u8..=u8::MAX)
            .map(|byte| vec![byte, byte])
            .collect::<Vec<_>>();
        let no_prefilter = LiteralSetPlan::new_stable(
            &no_prefilter_patterns,
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert_eq!(no_prefilter.automaton.match_kind(), MatchKind::Standard);
        assert!(no_prefilter.automaton.prefilter().is_none());
        assert!(
            no_prefilter
                .ordinary_executor()
                .unwrap()
                .uniform_standard_executor()
                .is_none(),
        );
        let mut dense = no_prefilter_patterns[1].clone();
        dense.extend_from_slice(&no_prefilter_patterns[2]);
        ordinary_direct_probe::reset();
        assert_eq!(
            no_prefilter
                .ordinary_executor()
                .unwrap()
                .try_visit_spans_window_value(
                    &dense,
                    Window::full(&dense),
                    |_| Ok::<bool, ()>(true),
                ),
            Ok(Ok(())),
        );
        assert_eq!(ordinary_direct_probe::calls(), 0);
    }

    #[test]
    fn uniform_standard_direct_acceptance_respects_width_floor_in_every_window() {
        for uniform_width in [1_usize, 2, 8] {
            let q = vec![b'q'; uniform_width];
            let z = vec![b'z'; uniform_width];
            let patterns = vec![q.clone(), z.clone(), q.clone()];
            let plan = LiteralSetPlan::new_stable(
                &patterns,
                LiteralSetBuildLimits::default(),
            )
            .unwrap();
            assert_eq!(plan.automaton.match_kind(), MatchKind::Standard);
            assert!(plan.automaton.prefilter().is_some());
            let reference = DFA::builder()
                .match_kind(MatchKind::LeftmostFirst)
                .build(patterns.iter().map(Vec::as_slice))
                .unwrap();

            let mut haystacks = vec![
                Vec::new(),
                vec![b'q'; uniform_width.saturating_sub(1)],
                q.clone(),
                z.clone(),
                vec![b'x'; uniform_width],
            ];
            let mut framed = b"PP".to_vec();
            framed.extend_from_slice(&vec![b'q'; uniform_width.saturating_sub(1)]);
            framed.push(b'x');
            framed.extend_from_slice(&q);
            framed.extend_from_slice(b"SS");
            haystacks.push(framed);

            for haystack in haystacks {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = Window::new(start, end);
                        let expected = reference_find(&reference, &haystack, window)
                            .map(|(_, matched_end)| matched_end);
                        let actual = first_acceptance_end_without_prefilter(
                            &plan,
                            &haystack,
                            window,
                        );
                        assert_eq!(
                            actual, expected,
                            "width={uniform_width}, haystack={haystack:?}, window={window:?}",
                        );
                    }
                }
            }

            ordinary_direct_probe::reset();
            let short = vec![b'q'; uniform_width.saturating_sub(1)];
            assert_eq!(
                first_acceptance_end_without_prefilter(
                    &plan,
                    &short,
                    Window::full(&short),
                ),
                None,
            );
            assert_eq!(ordinary_direct_probe::calls(), 1);
            assert_eq!(ordinary_direct_probe::special_checks(), 0);

            ordinary_direct_probe::reset();
            assert_eq!(
                first_acceptance_end_without_prefilter(
                    &plan,
                    &q,
                    Window::full(&q),
                ),
                Some(uniform_width),
            );
            assert_eq!(ordinary_direct_probe::calls(), 1);
            assert_eq!(ordinary_direct_probe::special_checks(), 1);
        }
    }

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
    fn ordinary_executor_preserves_priority_ranges_and_non_overlapping_iteration() {
        let plan = LiteralSetPlan::new(
            &[b"ab".as_slice(), b"a".as_slice(), b"ab".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        let ordinary = plan.ordinary_executor().expect("positive ordered executor");
        let haystack = b"zzababa";
        for start in 0..=haystack.len() {
            let window = Window::new(start, haystack.len());
            let expected = plan
                .find_window(haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0;
            assert_eq!(ordinary.find_window_value(haystack, window), Ok(expected));
            assert_eq!(
                ordinary.exists_window_value(haystack, window),
                Ok(expected.is_some()),
            );
            assert_eq!(
                ordinary.selected_end_window_value(haystack, window),
                Ok(expected.map(|(_, end)| end)),
            );
        }

        let mut cursor = 0;
        let mut spans = Vec::new();
        while let Some(matched) = ordinary
            .find_window_value(haystack, Window::new(cursor, haystack.len()))
            .unwrap()
        {
            spans.push(matched);
            cursor = matched.1;
        }
        assert_eq!(spans, [(2, 4), (4, 6), (6, 7)]);

        let mut visited = Vec::new();
        assert_eq!(
            ordinary.try_visit_spans_window_value(
                haystack,
                Window::new(3, haystack.len()),
                |matched| {
                    visited.push(matched);
                    Ok::<bool, &'static str>(true)
                },
            ),
            Ok(Ok(())),
        );
        assert_eq!(visited, [(4, 6), (6, 7)]);

        visited.clear();
        assert_eq!(
            ordinary.try_visit_spans_window_value(
                haystack,
                Window::full(haystack),
                |matched| {
                    visited.push(matched);
                    Ok::<bool, &'static str>(false)
                },
            ),
            Ok(Ok(())),
        );
        assert_eq!(visited, [(2, 4)]);
        assert_eq!(
            ordinary.try_visit_spans_window_value(
                haystack,
                Window::full(haystack),
                |_| Err::<bool, _>("callback"),
            ),
            Ok(Err("callback")),
        );

        let short_first = LiteralSetPlan::new(
            &[b"a".as_slice(), b"ab".as_slice(), b"a".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert_eq!(
            short_first
                .ordinary_executor()
                .unwrap()
                .find_window_value(b"zzab", Window::new(0, 4)),
            Ok(Some((2, 3))),
        );
    }

    #[test]
    fn ordinary_selected_endpoint_matches_checked_dense_dfa_search() {
        let mut patterns = (0_u8..131)
            .map(|byte| vec![byte; 3])
            .collect::<Vec<_>>();
        patterns[0] = vec![1; 4];
        let plan = LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        assert!(plan.automaton.prefilter().is_none());
        let ordinary = plan.ordinary_executor().expect("positive ordered executor");
        let haystacks = [
            [200, 1, 1, 1, 1, 201].as_slice(),
            [200, 1, 1, 1, 2].as_slice(),
            [200, 57, 57, 57, 201].as_slice(),
            [200, 201, 202].as_slice(),
        ];
        for haystack in haystacks {
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let window = Window::new(start, end);
                    let expected = plan
                        .find_window(haystack, window, LiteralSetSearchLimits::unlimited())
                        .unwrap()
                        .0;
                    assert_eq!(
                        ordinary.find_window_value(haystack, window),
                        Ok(expected),
                        "haystack={haystack:?}, window={window:?}",
                    );
                    assert_eq!(
                        ordinary.exists_window_value(haystack, window),
                        Ok(expected.is_some()),
                        "haystack={haystack:?}, window={window:?}",
                    );
                    assert_eq!(
                        ordinary.selected_end_window_value(haystack, window),
                        Ok(expected.map(|(_, end)| end)),
                        "haystack={haystack:?}, window={window:?}",
                    );
                }
            }
        }

        patterns.swap(0, 1);
        let short_first =
            LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
        assert!(short_first.automaton.prefilter().is_none());
        let ordinary = short_first
            .ordinary_executor()
            .expect("positive ordered executor");
        let haystack = [200, 1, 1, 1, 1, 201];
        let window = Window::full(&haystack);
        let expected = short_first
            .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
            .unwrap()
            .0;
        assert_eq!(expected, Some((1, 4)));
        assert_eq!(
            ordinary.find_window_value(&haystack, window),
            Ok(expected),
        );
        assert_eq!(ordinary.exists_window_value(&haystack, window), Ok(true));
        assert_eq!(
            ordinary.selected_end_window_value(&haystack, window),
            Ok(Some(4)),
        );
    }

    #[test]
    fn ordinary_executor_admission_and_window_validation_are_exact() {
        let positive = LiteralSetPlan::new(
            &[b"ab".as_slice(), b"cd".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        let ordinary = positive.ordinary_executor().unwrap();
        for (window, expected) in [
            (
                Window::new(3, 2),
                LiteralSetError::InvalidWindow {
                    start: 3,
                    end: 2,
                    haystack_len: 4,
                },
            ),
            (
                Window::new(0, 5),
                LiteralSetError::InvalidWindow {
                    start: 0,
                    end: 5,
                    haystack_len: 4,
                },
            ),
        ] {
            assert_eq!(
                ordinary.find_window_value(b"abcd", window),
                Err(expected.clone()),
            );
            assert_eq!(
                ordinary.exists_window_value(b"abcd", window),
                Err(expected.clone()),
            );
            assert_eq!(
                ordinary.selected_end_window_value(b"abcd", window),
                Err(expected.clone()),
            );
            let mut callback_called = false;
            assert_eq!(
                ordinary.try_visit_spans_window_value(b"abcd", window, |_| {
                    callback_called = true;
                    Ok::<bool, ()>(true)
                }),
                Err(expected),
            );
            assert!(!callback_called);
        }

        let nullable = LiteralSetPlan::new(
            &[b"a".as_slice(), b"".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert!(nullable.ordinary_executor().is_none());

        let streaming = LiteralSetPlan::new_streaming_any(
            &[b"ab".as_slice(), b"a".as_slice()],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert!(streaming.ordinary_executor().is_none());

        struct ChangingPattern(Cell<bool>);

        impl AsRef<[u8]> for ChangingPattern {
            fn as_ref(&self) -> &[u8] {
                if self.0.replace(true) {
                    b""
                } else {
                    b"a"
                }
            }
        }

        let changed = LiteralSetPlan::new(
            &[ChangingPattern(Cell::new(false))],
            LiteralSetBuildLimits::default(),
        )
        .unwrap();
        assert_eq!(changed.build.minimum_pattern_bytes, 1);
        assert_eq!(changed.automaton.min_pattern_len(), 0);
        assert!(changed.ordinary_executor().is_none());
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
        let stable_patterns = patterns
            .iter()
            .map(|pattern| pattern.to_vec())
            .collect::<Vec<_>>();
        assert!(matches!(
            LiteralSetPlan::new_stable(&stable_patterns, limits),
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
        assert!(matches!(
            LiteralSetPlan::new_stable(&stable_patterns, limits),
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
