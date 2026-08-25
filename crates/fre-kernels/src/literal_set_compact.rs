//! Contained contiguous-NFA owner for one authenticated literal-set shape.
//!
//! The public and generic literal-set surface remains in `literal_set`. This
//! module supplies only the outlined compact arm selected by the ripgrep
//! stable-borrowed handoff. Ordinary positive-width span iteration and count
//! may share one direct state scanner when the compact NFA has no prefilter;
//! every other operation retains aho-corasick's pinned `Automaton` search.

use aho_corasick::automaton::{Automaton, StateID};
use aho_corasick::dfa::DFA;
use aho_corasick::nfa::contiguous::NFA;
use aho_corasick::nfa::noncontiguous;
use aho_corasick::{Anchored, Input, MatchKind};

use crate::Window;
use crate::literal_set::{
    ALPHABET_LEN, BYTES_PER_DFA_CELL_ENVELOPE, BYTES_PER_TRIE_STATE_ENVELOPE, LiteralSetAccounting,
    LiteralSetBuildAccounting, LiteralSetBuildLimits, LiteralSetError, LiteralSetMatchSemantics,
    LiteralSetPlan, LiteralSetSearchLimits, LiteralSetStablePattern, preflight, validate_window,
};

const MIN_PATTERNS: usize = 129;
const MAX_PATTERNS: usize = 256;
const MIN_PATTERN_BYTES: usize = 128;
const MIN_DENSE_BUILD_WORK: usize = 8 * 1024 * 1024;
const MAX_DENSE_DEPTH: usize = 24;

#[derive(Clone, Debug)]
struct CompactEngine {
    automaton: NFA,
    width: usize,
}

/// One no-prefilter compact-NFA scan shared by ordinary iteration projections.
///
/// Compact admission proves that every pattern has the same positive width
/// and Standard semantics. The first accepting state is therefore the
/// selected endpoint, and resetting to the bound unanchored start state after
/// acceptance exactly implements non-overlapping iteration. Count never
/// constructs an Aho `Match`; span iteration recovers each start only after
/// acceptance. One-shot operations retain Aho's incumbent search.
struct CompactOrdinaryScanner<'a, 'h> {
    automaton: &'a NFA,
    haystack: &'h [u8],
    start_state: StateID,
    state: StateID,
    at: usize,
    end: usize,
    width: usize,
}

#[cfg(test)]
mod compact_ordinary_scanner_probe {
    use std::cell::Cell;

    std::thread_local! {
        static BINDS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn reset() {
        BINDS.set(0);
    }

    pub(super) fn record() {
        BINDS.set(BINDS.get().saturating_add(1));
    }

    pub(super) fn binds() -> usize {
        BINDS.get()
    }
}

/// Compact contiguous-NFA owner for one authenticated flat literal set.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct LiteralSetCompactPlan {
    canonical: LiteralSetPlan,
    engine: CompactEngine,
    build: LiteralSetBuildAccounting,
}

/// Ordinary-only compact owner for ripgrep's authenticated literal handoff.
///
/// This type deliberately exposes no checked or finite-search API. Those
/// contracts remain on [`LiteralSetCompactPlan`] and its canonical DFA.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct LiteralSetCompactOrdinaryPlan {
    engine: CompactEngine,
    build: LiteralSetBuildAccounting,
}

/// Unpublished compact owner retaining its shared construction NFA.
///
/// The caller must resolve this value into either the ordinary-only owner or
/// the canonical DFA. Keeping the shared NFA here lets an outer persistent-cap
/// refusal fall back without rebuilding the trie or retaining both engines.
#[doc(hidden)]
#[derive(Debug)]
pub struct LiteralSetCompactOrdinaryCandidate {
    shared: noncontiguous::NFA,
    ordinary: LiteralSetCompactOrdinaryPlan,
    canonical_build: LiteralSetBuildAccounting,
    limits: LiteralSetBuildLimits,
}

/// Result of attempting the optional compact literal-set construction.
///
/// A completed canonical owner is returned separately from a shape decline so
/// callers never need to rebuild or discard the incumbent after a compact-only
/// resource refusal.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub enum LiteralSetCompactBuildOutcome {
    NotApplicable,
    Canonical(LiteralSetPlan),
    Compact(LiteralSetCompactPlan),
}

/// Result of attempting ordinary-only compact construction.
///
/// A candidate still owns the shared noncontiguous NFA so its caller can apply
/// outer facade accounting before choosing one final owner. A canonical result
/// has already reused that shared NFA whenever construction had reached it.
#[doc(hidden)]
#[derive(Debug)]
pub enum LiteralSetCompactOrdinaryBuildOutcome {
    NotApplicable,
    Canonical(LiteralSetPlan),
    Candidate(LiteralSetCompactOrdinaryCandidate),
}

#[derive(Clone, Copy, Debug)]
enum CompactPreflight {
    NotApplicable,
    Canonical(LiteralSetBuildAccounting),
    Eligible {
        canonical_build: LiteralSetBuildAccounting,
        compact_build: LiteralSetBuildAccounting,
        width: usize,
        dense_depth: usize,
    },
}

/// Choose the forced-dense prefix depth from the deepest possible trie branch.
///
/// Every branching state is witnessed by a pair of patterns whose LCP ends at
/// that state. Nonterminal states strictly deeper than the maximum pairwise
/// LCP have one literal transition and can use Aho's `KIND_ONE`
/// representation; terminal match states have zero literal transitions.
/// Equal patterns, pairs equal through the bounded probe, and source orders
/// with an inversion conservatively retain the legacy maximum. For an
/// already-sorted source, the deepest pairwise LCP is witnessed by adjacent
/// patterns, so one bounded pass finds the exact depth without copying or
/// sorting construction input.
fn deepest_branch_dense_depth<P: AsRef<[u8]>>(
    patterns: &[P],
    width: usize,
) -> Option<usize> {
    debug_assert!(patterns.iter().all(|pattern| pattern.as_ref().len() == width));
    let probe_depth = width.saturating_sub(1).min(MAX_DENSE_DEPTH);
    if probe_depth == 0 || patterns.len() < 2 {
        return Some(0);
    }
    if patterns.len() > MAX_PATTERNS {
        return None;
    }

    let mut deepest = 0_usize;
    for adjacent in patterns.windows(2) {
        let left = adjacent[0].as_ref().get(..probe_depth)?;
        let right = adjacent[1].as_ref().get(..probe_depth)?;
        let mut lcp = 0_usize;
        while lcp < probe_depth {
            let left_byte = *left.get(lcp)?;
            let right_byte = *right.get(lcp)?;
            if left_byte < right_byte {
                break;
            }
            if left_byte > right_byte {
                return Some(probe_depth);
            }
            lcp = lcp.checked_add(1)?;
        }
        deepest = deepest.max(lcp);
        if deepest == probe_depth {
            return Some(probe_depth);
        }
    }
    Some(deepest)
}

fn deepest_branch_build_work_upper_bound(patterns: usize, width: usize) -> Option<usize> {
    if patterns > MAX_PATTERNS {
        return None;
    }
    let probe_depth = width.saturating_sub(1).min(MAX_DENSE_DEPTH);
    // Every adjacent bounded prefix can require `probe_depth` byte comparisons
    // plus one unit for pair formation, order selection and maximum
    // bookkeeping.
    patterns
        .saturating_sub(1)
        .checked_mul(probe_depth.checked_add(1)?)
}

fn compact_preflight<P: AsRef<[u8]>>(
    patterns: &[P],
    limits: LiteralSetBuildLimits,
) -> Result<CompactPreflight, LiteralSetError> {
    if !(MIN_PATTERNS..=MAX_PATTERNS).contains(&patterns.len()) {
        return Ok(CompactPreflight::NotApplicable);
    }
    let canonical_build = preflight(patterns, limits, LiteralSetMatchSemantics::LeftmostFirst)?;
    let width = canonical_build.minimum_pattern_bytes;
    let uniform_positive = width >= MIN_PATTERN_BYTES
        && width.checked_mul(canonical_build.patterns) == Some(canonical_build.pattern_bytes);
    if !uniform_positive || canonical_build.build_work_upper_bound < MIN_DENSE_BUILD_WORK {
        return Ok(CompactPreflight::Canonical(canonical_build));
    }
    let Some(deepest_branch_build_work) =
        deepest_branch_build_work_upper_bound(canonical_build.patterns, width)
    else {
        return Ok(CompactPreflight::Canonical(canonical_build));
    };
    // Contiguous conversion writes every encoded transition and then remaps
    // every encoded state ID in a second pass. Charge those two complete cell
    // traversals, state-map and pattern-vector setup, and the complete bounded
    // topology-selector charge. Together with the canonical receipt this also
    // covers a complete compact attempt followed by same-shared-NFA canonical
    // fallback.
    let Some(compact_build_work) = canonical_build
        .dfa_cells_upper_bound
        .checked_mul(2)
        .and_then(|work| work.checked_add(canonical_build.trie_states_upper_bound))
        .and_then(|work| work.checked_add(canonical_build.patterns))
        .and_then(|work| work.checked_add(deepest_branch_build_work))
        .and_then(|work| work.checked_add(canonical_build.build_work_upper_bound))
    else {
        return Ok(CompactPreflight::Canonical(canonical_build));
    };
    if compact_build_work > limits.max_build_work {
        return Ok(CompactPreflight::Canonical(canonical_build));
    }
    let Some(dense_depth) = deepest_branch_dense_depth(patterns, width) else {
        return Ok(CompactPreflight::Canonical(canonical_build));
    };
    // Retain the established three-owner envelope. It conservatively covers
    // both the dual owner and the ordinary policy's topology selection:
    // shared+compact followed, on refusal, by shared+canonical.
    let Some(dense_states_upper_bound) = canonical_build
        .patterns
        .checked_mul(width.min(MAX_DENSE_DEPTH))
        .and_then(|states| states.checked_add(1))
        .map(|states| states.min(canonical_build.trie_states_upper_bound))
    else {
        return Ok(CompactPreflight::Canonical(canonical_build));
    };
    let Some(compact_build_bytes) = dense_states_upper_bound
        .checked_mul(ALPHABET_LEN)
        .and_then(|cells| cells.checked_mul(BYTES_PER_DFA_CELL_ENVELOPE))
        .and_then(|dense_bytes| {
            canonical_build
                .trie_states_upper_bound
                .checked_mul(BYTES_PER_TRIE_STATE_ENVELOPE)
                .and_then(|trie_bytes| dense_bytes.checked_add(trie_bytes))
        })
        .and_then(|additional| {
            canonical_build
                .build_bytes_upper_bound
                .checked_add(additional)
        })
    else {
        return Ok(CompactPreflight::Canonical(canonical_build));
    };
    if compact_build_bytes > limits.max_build_bytes {
        return Ok(CompactPreflight::Canonical(canonical_build));
    }
    let mut compact_build = canonical_build;
    compact_build.build_work_upper_bound = compact_build_work;
    compact_build.build_bytes_upper_bound = compact_build_bytes;
    Ok(CompactPreflight::Eligible {
        canonical_build,
        compact_build,
        width,
        dense_depth,
    })
}

fn canonical_plan<P: AsRef<[u8]>>(
    patterns: &[P],
    build: LiteralSetBuildAccounting,
    limits: LiteralSetBuildLimits,
) -> Result<LiteralSetPlan, LiteralSetError> {
    let uniform_positive = build.minimum_pattern_bytes > 0
        && build.minimum_pattern_bytes.checked_mul(build.patterns) == Some(build.pattern_bytes);
    let match_kind = if uniform_positive {
        MatchKind::Standard
    } else {
        MatchKind::LeftmostFirst
    };
    let automaton = DFA::builder()
        .match_kind(match_kind)
        .build(patterns.iter().map(AsRef::as_ref))
        .map_err(|error| LiteralSetError::AutomatonBuild {
            detail: error.to_string(),
        })?;
    LiteralSetPlan::from_preflight_dfa(build, automaton, limits)
}

fn canonical_outcome<P: AsRef<[u8]>>(
    patterns: &[P],
    build: LiteralSetBuildAccounting,
    limits: LiteralSetBuildLimits,
) -> Result<LiteralSetCompactBuildOutcome, LiteralSetError> {
    canonical_plan(patterns, build, limits).map(LiteralSetCompactBuildOutcome::Canonical)
}

fn build_shared<P: AsRef<[u8]>>(
    patterns: &[P],
) -> Result<noncontiguous::NFA, LiteralSetError> {
    let mut builder = noncontiguous::Builder::new();
    builder.match_kind(MatchKind::Standard);
    builder
        .build(patterns.iter().map(AsRef::as_ref))
        .map_err(|error| LiteralSetError::AutomatonBuild {
            detail: error.to_string(),
        })
}

fn canonical_from_shared(
    shared: &noncontiguous::NFA,
    build: LiteralSetBuildAccounting,
    limits: LiteralSetBuildLimits,
) -> Result<LiteralSetPlan, LiteralSetError> {
    let automaton = DFA::builder()
        .build_from_noncontiguous(shared)
        .map_err(|error| LiteralSetError::AutomatonBuild {
            detail: error.to_string(),
        })?;
    LiteralSetPlan::from_preflight_dfa(build, automaton, limits)
}

fn compact_engine(
    shared: &noncontiguous::NFA,
    width: usize,
    dense_depth: usize,
) -> Option<CompactEngine> {
    debug_assert!(dense_depth <= MAX_DENSE_DEPTH);
    debug_assert!(dense_depth < width);
    let mut builder = NFA::builder();
    // aho-corasick 1.1.4 interprets this as an exclusive state-depth
    // threshold: states with `state.depth() < dense_depth` are forced dense.
    // The unchanged worst-case byte envelope above also covers Aho's automatic
    // dense-state choices outside this forced prefix.
    builder.dense_depth(dense_depth);
    let automaton = builder.build_from_noncontiguous(shared).ok()?;
    debug_assert_eq!(automaton.match_kind(), MatchKind::Standard);
    debug_assert_eq!(automaton.min_pattern_len(), width);
    debug_assert_eq!(automaton.max_pattern_len(), width);
    Some(CompactEngine { automaton, width })
}

impl CompactEngine {
    #[inline]
    fn memory_usage(&self) -> usize {
        self.automaton.memory_usage()
    }
}

impl<'a, 'h> CompactOrdinaryScanner<'a, 'h> {
    /// Bind the direct scanner only when Aho has no construction-selected
    /// prefilter to preserve. Compact construction independently proves the
    /// positive fixed width and Standard semantics used by the scan body.
    #[inline]
    fn new(engine: &'a CompactEngine, haystack: &'h [u8], window: Window) -> Option<Self> {
        if engine.width == 0 || engine.automaton.prefilter().is_some() {
            return None;
        }
        debug_assert_eq!(engine.automaton.match_kind(), MatchKind::Standard);
        debug_assert_eq!(engine.automaton.min_pattern_len(), engine.width);
        debug_assert_eq!(engine.automaton.max_pattern_len(), engine.width);
        let start_state = engine
            .automaton
            .start_state(Anchored::No)
            .expect("the compact literal NFA retains its unanchored start state");
        debug_assert!(!engine.automaton.is_match(start_state));
        #[cfg(test)]
        compact_ordinary_scanner_probe::record();
        Some(Self {
            automaton: &engine.automaton,
            haystack,
            start_state,
            state: start_state,
            at: window.start(),
            end: window.end(),
            width: engine.width,
        })
    }

    /// Return the next non-overlapping first acceptance without constructing
    /// an Aho input, iterator or match value.
    #[inline(always)]
    fn next_end(&mut self) -> Option<usize> {
        while self.at < self.end {
            self.state = self.automaton.next_state(
                Anchored::No,
                self.state,
                self.haystack[self.at],
            );
            self.at += 1;
            if !self.automaton.is_special(self.state) {
                continue;
            }
            if self.automaton.is_dead(self.state) {
                self.at = self.end;
                return None;
            }
            // Aho deliberately excludes start states from `is_special` when
            // no prefilter is retained, including impossible-root self-loops.
            debug_assert!(
                self.automaton.is_match(self.state),
                "a compact NFA without a prefilter has no other special states",
            );
            let accepted_end = self.at;
            self.state = self.start_state;
            return Some(accepted_end);
        }
        None
    }

    #[inline(always)]
    fn next_span(&mut self) -> Option<(usize, usize)> {
        let end = self.next_end()?;
        debug_assert!(end >= self.width);
        Some((end - self.width, end))
    }
}

/// Construction-bound ordinary access to the compact owner.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct LiteralSetCompactOrdinaryExecutor<'a> {
    engine: &'a CompactEngine,
}

impl LiteralSetCompactPlan {
    #[cold]
    #[inline(never)]
    pub fn try_new_ripgrep_standard_borrowed<P: LiteralSetStablePattern>(
        patterns: &[P],
        limits: LiteralSetBuildLimits,
    ) -> Result<LiteralSetCompactBuildOutcome, LiteralSetError> {
        let (canonical_build, mut compact_build, width, dense_depth) =
            match compact_preflight(patterns, limits)? {
                CompactPreflight::NotApplicable => {
                    return Ok(LiteralSetCompactBuildOutcome::NotApplicable);
                }
                CompactPreflight::Canonical(build) => {
                    return canonical_outcome(patterns, build, limits);
                }
                CompactPreflight::Eligible {
                    canonical_build,
                    compact_build,
                    width,
                    dense_depth,
                } => (canonical_build, compact_build, width, dense_depth),
            };
        let shared = build_shared(patterns)?;
        // Checked and explicit-session calls retain the exact established DFA
        // contract. The compact NFA is an additional ordinary-only engine.
        let canonical = canonical_from_shared(&shared, canonical_build, limits)?;
        let engine = match compact_engine(&shared, width, dense_depth) {
            Some(engine) => engine,
            None => return Ok(LiteralSetCompactBuildOutcome::Canonical(canonical)),
        };
        debug_assert_eq!(
            canonical.build_accounting().match_semantics,
            canonical_build.match_semantics
        );
        debug_assert_eq!(
            canonical.build_accounting().pattern_bytes,
            canonical_build.pattern_bytes
        );
        let Some(persistent_bytes) = canonical
            .build_accounting()
            .persistent_bytes
            .checked_add(engine.memory_usage())
        else {
            return Ok(LiteralSetCompactBuildOutcome::Canonical(canonical));
        };
        compact_build.persistent_bytes = persistent_bytes;
        if persistent_bytes > limits.max_persistent_bytes {
            return Ok(LiteralSetCompactBuildOutcome::Canonical(canonical));
        }
        Ok(LiteralSetCompactBuildOutcome::Compact(Self {
            canonical,
            engine,
            build: compact_build,
        }))
    }

    /// Construction-selected implementation identity.
    #[must_use]
    pub const fn runtime_implementation_id(&self) -> &'static str {
        "literal-set-compact-nfa"
    }

    /// Construction certificate and exact retained automaton payload.
    #[must_use]
    pub const fn build_accounting(&self) -> LiteralSetBuildAccounting {
        self.build
    }

    /// Consume this dual owner and retain its unchanged checked DFA plan.
    #[must_use]
    pub fn into_canonical(self) -> LiteralSetPlan {
        self.canonical
    }

    /// Bind ordinary unmetered operations once to this owner.
    #[must_use]
    pub const fn ordinary_executor(&self) -> LiteralSetCompactOrdinaryExecutor<'_> {
        LiteralSetCompactOrdinaryExecutor {
            engine: &self.engine,
        }
    }

    /// Find one selected span in a complete haystack with checked accounting.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: LiteralSetSearchLimits,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        self.canonical.find(haystack, limits)
    }

    #[inline(never)]
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: Window,
        limits: LiteralSetSearchLimits,
    ) -> Result<(Option<(usize, usize)>, LiteralSetAccounting), LiteralSetError> {
        self.canonical.find_window(haystack, window, limits)
    }
}

impl LiteralSetCompactOrdinaryPlan {
    /// Attempt ordinary-only construction for an authenticated ripgrep handoff.
    #[doc(hidden)]
    #[cold]
    #[inline(never)]
    pub fn try_new_ripgrep_standard_borrowed<P: LiteralSetStablePattern>(
        patterns: &[P],
        limits: LiteralSetBuildLimits,
    ) -> Result<LiteralSetCompactOrdinaryBuildOutcome, LiteralSetError> {
        let (canonical_build, mut compact_build, width, dense_depth) =
            match compact_preflight(patterns, limits)? {
                CompactPreflight::NotApplicable => {
                    return Ok(LiteralSetCompactOrdinaryBuildOutcome::NotApplicable);
                }
                CompactPreflight::Canonical(build) => {
                    return canonical_plan(patterns, build, limits)
                        .map(LiteralSetCompactOrdinaryBuildOutcome::Canonical);
                }
                CompactPreflight::Eligible {
                    canonical_build,
                    compact_build,
                    width,
                    dense_depth,
                } => (canonical_build, compact_build, width, dense_depth),
            };
        let shared = build_shared(patterns)?;
        let Some(engine) = compact_engine(&shared, width, dense_depth) else {
            return canonical_from_shared(&shared, canonical_build, limits)
                .map(LiteralSetCompactOrdinaryBuildOutcome::Canonical);
        };
        compact_build.persistent_bytes = engine.memory_usage();
        if compact_build.persistent_bytes > limits.max_persistent_bytes {
            // Drop the refused engine before allocating the same-shared DFA.
            drop(engine);
            return canonical_from_shared(&shared, canonical_build, limits)
                .map(LiteralSetCompactOrdinaryBuildOutcome::Canonical);
        }
        Ok(LiteralSetCompactOrdinaryBuildOutcome::Candidate(
            LiteralSetCompactOrdinaryCandidate {
                shared,
                ordinary: Self {
                    engine,
                    build: compact_build,
                },
                canonical_build,
                limits,
            },
        ))
    }

    /// Construction-selected implementation identity.
    #[doc(hidden)]
    #[must_use]
    pub const fn runtime_implementation_id(&self) -> &'static str {
        "literal-set-compact-nfa"
    }

    /// Construction certificate and exact retained automaton payload.
    #[doc(hidden)]
    #[must_use]
    pub const fn build_accounting(&self) -> LiteralSetBuildAccounting {
        self.build
    }

    /// Bind ordinary unmetered operations once to this owner.
    #[doc(hidden)]
    #[must_use]
    pub const fn ordinary_executor(&self) -> LiteralSetCompactOrdinaryExecutor<'_> {
        LiteralSetCompactOrdinaryExecutor {
            engine: &self.engine,
        }
    }
}

impl LiteralSetCompactOrdinaryCandidate {
    /// Return the ordinary owner's receipt before resolving this candidate.
    #[doc(hidden)]
    #[must_use]
    pub const fn build_accounting(&self) -> LiteralSetBuildAccounting {
        self.ordinary.build_accounting()
    }

    /// Keep only the ordinary compact engine.
    #[doc(hidden)]
    #[must_use]
    pub fn into_ordinary(self) -> LiteralSetCompactOrdinaryPlan {
        let Self {
            shared,
            ordinary,
            canonical_build: _,
            limits: _,
        } = self;
        drop(shared);
        ordinary
    }

    /// Refuse the ordinary owner and build the canonical DFA from the same NFA.
    #[doc(hidden)]
    pub fn into_canonical(self) -> Result<LiteralSetPlan, LiteralSetError> {
        let Self {
            shared,
            ordinary,
            canonical_build,
            limits,
        } = self;
        // Never retain both final engines. The shared construction NFA is the
        // sole source used to build the canonical fallback.
        drop(ordinary);
        canonical_from_shared(&shared, canonical_build, limits)
    }
}

impl CompactEngine {
    #[inline]
    fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<(usize, usize)>, LiteralSetError> {
        validate_window(window, haystack.len())?;
        self.find_window_value_validated(haystack, window)
    }

    #[inline]
    fn exists_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<bool, LiteralSetError> {
        validate_window(window, haystack.len())?;
        Ok(self
            .first_end_window_value_validated(haystack, window)
            .is_some())
    }

    #[inline]
    fn selected_end_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<usize>, LiteralSetError> {
        validate_window(window, haystack.len())?;
        Ok(self.first_end_window_value_validated(haystack, window))
    }

    #[inline]
    fn try_visit_spans_window_value<F, E>(
        &self,
        haystack: &[u8],
        window: Window,
        visitor: F,
    ) -> Result<Result<(), E>, LiteralSetError>
    where
        F: FnMut((usize, usize)) -> Result<bool, E>,
    {
        validate_window(window, haystack.len())?;
        if self.window_is_too_short(window) {
            return Ok(Ok(()));
        }
        self.try_visit_spans_window_value_nonempty(haystack, window, visitor)
    }

    #[inline(never)]
    fn try_visit_spans_window_value_nonempty<F, E>(
        &self,
        haystack: &[u8],
        window: Window,
        mut visitor: F,
    ) -> Result<Result<(), E>, LiteralSetError>
    where
        F: FnMut((usize, usize)) -> Result<bool, E>,
    {
        debug_assert!(!self.window_is_too_short(window));
        // This is only an optional engine arm inside the incumbent validated
        // visitor. It does not replace the existing span-total structure or
        // change callback/fallback control flow.
        if let Some(mut scanner) = CompactOrdinaryScanner::new(self, haystack, window) {
            while let Some(span) = scanner.next_span() {
                match visitor(span) {
                    Ok(true) => {}
                    Ok(false) => return Ok(Ok(())),
                    Err(error) => return Ok(Err(error)),
                }
            }
            return Ok(Ok(()));
        }
        let input = Input::new(haystack).span(window.start()..window.end());
        let matches = self
            .automaton
            .try_find_iter(input)
            .expect("the compact literal NFA supports unanchored iteration");
        for matched in matches {
            let span = self.absolute_span(matched)?;
            match visitor(span) {
                Ok(true) => {}
                Ok(false) => return Ok(Ok(())),
                Err(error) => return Ok(Err(error)),
            }
        }
        Ok(Ok(()))
    }

    #[inline]
    fn count_spans_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<u64, LiteralSetError> {
        validate_window(window, haystack.len())?;
        if self.window_is_too_short(window) {
            return Ok(0);
        }
        self.count_spans_window_value_nonempty(haystack, window)
    }

    #[inline(never)]
    fn count_spans_window_value_nonempty(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<u64, LiteralSetError> {
        debug_assert!(!self.window_is_too_short(window));
        if let Some(mut scanner) = CompactOrdinaryScanner::new(self, haystack, window) {
            let mut count = 0_usize;
            while scanner.next_end().is_some() {
                // Positive-width, non-overlapping matches bound this count by
                // the already-validated window's byte length.
                count += 1;
            }
            return u64::try_from(count).map_err(|_| LiteralSetError::ArithmeticOverflow {
                computation: "compact literal-set ordinary match count",
            });
        }
        let input = Input::new(haystack).span(window.start()..window.end());
        let count = self
            .automaton
            .try_find_iter(input)
            .expect("the compact literal NFA supports unanchored iteration")
            .count();
        // Matches do not overlap and have positive width, so their count is
        // bounded by the validated window length.
        u64::try_from(count).map_err(|_| LiteralSetError::ArithmeticOverflow {
            computation: "compact literal-set ordinary match count",
        })
    }

    #[inline]
    fn find_window_value_validated(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<(usize, usize)>, LiteralSetError> {
        if self.window_is_too_short(window) {
            return Ok(None);
        }
        let input = Input::new(haystack).span(window.start()..window.end());
        self.automaton
            .try_find(&input)
            .expect("the compact literal NFA supports unanchored search")
            .map(|matched| self.absolute_span(matched))
            .transpose()
    }

    #[inline]
    fn first_end_window_value_validated(&self, haystack: &[u8], window: Window) -> Option<usize> {
        if self.window_is_too_short(window) {
            return None;
        }
        let input = Input::new(haystack)
            .span(window.start()..window.end())
            .earliest(true);
        self.automaton
            .try_find(&input)
            .expect("the compact literal NFA supports unanchored search")
            .map(|matched| matched.end())
    }

    #[inline]
    fn window_is_too_short(&self, window: Window) -> bool {
        window.end() - window.start() < self.width
    }

    #[inline]
    fn absolute_span(
        &self,
        matched: aho_corasick::Match,
    ) -> Result<(usize, usize), LiteralSetError> {
        let end = matched.end();
        let width = self.width;
        debug_assert_eq!(matched.start(), end - width);
        let start = end
            .checked_sub(width)
            .ok_or(LiteralSetError::ArithmeticOverflow {
                computation: "compact literal-set match start",
            })?;
        Ok((start, end))
    }
}

impl LiteralSetCompactOrdinaryExecutor<'_> {
    /// Return whether any retained literal accepts wholly within `window`.
    #[doc(hidden)]
    #[inline]
    pub fn exists_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<bool, LiteralSetError> {
        self.engine.exists_window_value(haystack, window)
    }

    /// Return the first accepting endpoint without projecting a span start.
    #[doc(hidden)]
    #[inline]
    pub fn selected_end_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<usize>, LiteralSetError> {
        self.engine.selected_end_window_value(haystack, window)
    }

    /// Return the selected span, recovering its fixed-width start after hit.
    #[doc(hidden)]
    #[inline]
    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<(usize, usize)>, LiteralSetError> {
        self.engine.find_window_value(haystack, window)
    }

    /// Visit non-overlapping spans through the direct no-prefilter scanner or
    /// the unchanged pinned Aho iterator fallback.
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
        self.engine
            .try_visit_spans_window_value(haystack, window, visitor)
    }

    /// Count non-overlapping spans through the direct no-prefilter scanner or
    /// the unchanged pinned Aho iterator fallback.
    #[doc(hidden)]
    #[inline]
    pub fn count_spans_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<u64, LiteralSetError> {
        self.engine.count_spans_window_value(haystack, window)
    }
}

#[cfg(test)]
mod tests {
    use aho_corasick::automaton::Automaton;

    use super::{
        ALPHABET_LEN, BYTES_PER_DFA_CELL_ENVELOPE, BYTES_PER_TRIE_STATE_ENVELOPE, CompactPreflight,
        CompactOrdinaryScanner, LiteralSetCompactBuildOutcome,
        LiteralSetCompactOrdinaryBuildOutcome, LiteralSetCompactOrdinaryCandidate,
        LiteralSetCompactOrdinaryPlan, LiteralSetCompactPlan, MAX_DENSE_DEPTH, MAX_PATTERNS,
        MIN_PATTERN_BYTES, compact_ordinary_scanner_probe, compact_preflight,
        deepest_branch_build_work_upper_bound, deepest_branch_dense_depth,
    };
    use crate::{
        LiteralSetBuildLimits, LiteralSetError, LiteralSetPlan, LiteralSetSearchLimits, Window,
    };

    fn public_patterns(count: usize, width: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| {
                let prefix = format!("public{index:04}").into_bytes();
                assert!(prefix.len() <= width);
                let mut pattern = vec![b'q'; width];
                pattern[..prefix.len()].copy_from_slice(&prefix);
                pattern
            })
            .collect()
    }

    fn brute_deepest_branch_dense_depth(patterns: &[&[u8]], width: usize) -> usize {
        let probe_depth = width.saturating_sub(1).min(MAX_DENSE_DEPTH);
        let mut deepest = 0_usize;
        for (left_index, left) in patterns.iter().enumerate() {
            for right in &patterns[left_index + 1..] {
                let lcp = left
                    .iter()
                    .zip(*right)
                    .take(probe_depth)
                    .take_while(|(left, right)| left == right)
                    .count();
                deepest = deepest.max(lcp);
            }
        }
        deepest
    }

    #[test]
    fn sorted_gate_matches_pairwise_oracle_and_unsorted_input_retains_legacy_depth() {
        fn next(seed: &mut u64) -> u64 {
            *seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *seed
        }

        fn below(seed: &mut u64, upper: usize) -> usize {
            usize::try_from(next(seed) % u64::try_from(upper).unwrap()).unwrap()
        }

        let mut seed = 0xd1ff_e12a_5eed_0042_u64;
        for case in 0..48 {
            let pattern_count = if case == 0 {
                MAX_PATTERNS
            } else {
                2 + below(&mut seed, MAX_PATTERNS - 1)
            };
            let width = 1 + below(&mut seed, 48);
            let shared = below(&mut seed, width.min(MAX_DENSE_DEPTH + 1));
            let mut common = vec![0_u8; shared];
            for byte in &mut common {
                *byte = u8::try_from(next(&mut seed) & 0xff).unwrap();
            }
            let mut patterns = (0..pattern_count)
                .map(|index| {
                    let mut pattern = (0..width)
                        .map(|_| u8::try_from(next(&mut seed) & 0xff).unwrap())
                        .collect::<Vec<_>>();
                    pattern[..shared].copy_from_slice(&common);
                    if shared < width && index % 5 == 0 {
                        pattern[shared] = 0;
                    }
                    pattern
                })
                .collect::<Vec<_>>();
            if case % 3 == 0 {
                patterns[pattern_count - 1] = patterns[0].clone();
            }

            let probe_depth = width.saturating_sub(1).min(MAX_DENSE_DEPTH);
            patterns.sort_by(|left, right| left[..probe_depth].cmp(&right[..probe_depth]));
            let borrowed = patterns.iter().map(Vec::as_slice).collect::<Vec<_>>();
            assert_eq!(
                deepest_branch_dense_depth(&borrowed, width),
                Some(brute_deepest_branch_dense_depth(&borrowed, width)),
                "sorted source order, case={case}",
            );
            for end in (1..pattern_count).rev() {
                let other = below(&mut seed, end + 1);
                patterns.swap(end, other);
            }
            let borrowed = patterns.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let nondecreasing = borrowed
                .windows(2)
                .all(|pair| pair[0][..probe_depth] <= pair[1][..probe_depth]);
            let expected = if nondecreasing {
                brute_deepest_branch_dense_depth(&borrowed, width)
            } else {
                probe_depth
            };
            assert_eq!(
                deepest_branch_dense_depth(&borrowed, width),
                Some(expected),
                "permuted order, case={case}",
            );
        }
    }

    #[test]
    fn source_order_gate_covers_sorted_inverted_and_equal_prefixes() {
        fn patterns(values: &[u16]) -> Vec<Vec<u8>> {
            values
                .iter()
                .map(|&value| {
                    let mut pattern = vec![b'q'; MIN_PATTERN_BYTES];
                    pattern[MAX_DENSE_DEPTH - 1] = u8::try_from(value).unwrap();
                    pattern
                })
                .collect()
        }

        let sorted = patterns(&(0_u16..256).collect::<Vec<_>>());
        let borrowed = sorted.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_eq!(
            deepest_branch_dense_depth(&borrowed, MIN_PATTERN_BYTES),
            Some(23),
        );

        let reverse = patterns(&(0_u16..256).rev().collect::<Vec<_>>());
        let borrowed = reverse.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_eq!(
            deepest_branch_dense_depth(&borrowed, MIN_PATTERN_BYTES),
            Some(MAX_DENSE_DEPTH),
        );

        let mut late_values = (0_u16..254).collect::<Vec<_>>();
        late_values.extend([255, 254]);
        let late = patterns(&late_values);
        let borrowed = late.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_eq!(
            deepest_branch_dense_depth(&borrowed, MIN_PATTERN_BYTES),
            Some(MAX_DENSE_DEPTH),
        );

        let equal = vec![vec![b'a'; MIN_PATTERN_BYTES]; MAX_PATTERNS];
        let borrowed = equal.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_eq!(
            deepest_branch_dense_depth(&borrowed, MIN_PATTERN_BYTES),
            Some(MAX_DENSE_DEPTH),
        );
    }

    #[test]
    fn deepest_branch_depth_covers_zero_shallow_and_terminal_cases() {
        assert_eq!(
            deepest_branch_dense_depth(&[b"aaaa", b"baaa", b"caaa", b"daaa"], 4),
            Some(0),
        );
        assert_eq!(
            deepest_branch_dense_depth(&[b"aa00", b"aa10", b"ba00"], 4),
            Some(2),
            "one deep pair controls the selected depth",
        );
        assert_eq!(
            deepest_branch_dense_depth(&[b"aaa", b"aab"], 3),
            Some(2),
            "the terminal match-state level is excluded",
        );
    }

    #[test]
    fn deepest_branch_depth_selects_public_depth_22_and_legacy_cap() {
        let patterns = (0_u16..256)
            .map(|index| {
                let group = usize::from(index) / 10;
                let mut pattern = vec![b'q'; MIN_PATTERN_BYTES];
                pattern[20] = u8::try_from(group / 9).unwrap();
                pattern[21] = u8::try_from(group).unwrap();
                pattern[22] = u8::try_from(index).unwrap();
                pattern
            })
            .collect::<Vec<_>>();
        let borrowed = patterns.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_eq!(
            deepest_branch_dense_depth(&borrowed, MIN_PATTERN_BYTES),
            Some(22),
        );

        let duplicate = vec![b'a'; 32];
        assert_eq!(
            deepest_branch_dense_depth(&[&duplicate, &duplicate], duplicate.len()),
            Some(MAX_DENSE_DEPTH),
            "equal-through-cap pairs conservatively retain the rollout maximum",
        );
    }

    #[test]
    fn source_order_probe_work_bound_covers_every_adjacent_prefix() {
        assert_eq!(
            deepest_branch_build_work_upper_bound(MAX_PATTERNS, MIN_PATTERN_BYTES),
            Some(6_375),
        );
        assert_eq!(deepest_branch_build_work_upper_bound(129, 254), Some(3_200),);
        assert_eq!(
            deepest_branch_build_work_upper_bound(MAX_PATTERNS + 1, MIN_PATTERN_BYTES),
            None,
        );
    }

    #[test]
    fn compact_preflight_preserves_the_legacy_worst_case_dense_state_envelope() {
        let patterns = public_patterns(MAX_PATTERNS, MIN_PATTERN_BYTES);
        let borrowed = patterns.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let CompactPreflight::Eligible {
            canonical_build,
            compact_build,
            width,
            dense_depth,
        } = compact_preflight(&borrowed, LiteralSetBuildLimits::default()).unwrap()
        else {
            panic!("public compact fixture should pass preflight");
        };
        assert_eq!(dense_depth, 9);
        assert_eq!(
            deepest_branch_build_work_upper_bound(MAX_PATTERNS, width),
            Some(6_375),
        );
        let dense_states = canonical_build.patterns * width.min(MAX_DENSE_DEPTH) + 1;
        let expected = canonical_build.build_bytes_upper_bound
            + dense_states * ALPHABET_LEN * BYTES_PER_DFA_CELL_ENVELOPE
            + canonical_build.trie_states_upper_bound * BYTES_PER_TRIE_STATE_ENVELOPE;
        assert_eq!(compact_build.build_bytes_upper_bound, expected);
        assert!(matches!(
            compact_preflight(
                &borrowed,
                LiteralSetBuildLimits {
                    max_build_work: compact_build.build_work_upper_bound - 1,
                    ..LiteralSetBuildLimits::default()
                },
            )
            .unwrap(),
            CompactPreflight::Canonical(_),
        ));
    }

    #[test]
    fn zero_deepest_branch_still_builds_the_compact_owner() {
        let patterns = (0_u16..256)
            .map(|first| {
                let mut pattern = vec![b'q'; MIN_PATTERN_BYTES];
                pattern[0] = u8::try_from(first).unwrap();
                pattern
            })
            .collect::<Vec<_>>();
        let borrowed = patterns.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let CompactPreflight::Eligible { dense_depth, .. } =
            compact_preflight(&borrowed, LiteralSetBuildLimits::default()).unwrap()
        else {
            panic!("unique-first-byte fixture should pass compact preflight");
        };
        assert_eq!(dense_depth, 0);

        let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("aho-corasick accepts a zero forced-dense depth")
            .into_ordinary();
        assert!(plan.engine.automaton.prefilter().is_none());
        let mut haystack = vec![b'z'; MIN_PATTERN_BYTES + 2];
        haystack[1..=MIN_PATTERN_BYTES].copy_from_slice(&patterns[17]);
        assert!(
            CompactOrdinaryScanner::new(&plan.engine, &haystack, Window::full(&haystack)).is_some()
        );
        assert_eq!(
            plan.ordinary_executor()
                .find_window_value(&haystack, Window::new(1, MIN_PATTERN_BYTES + 1),),
            Ok(Some((1, MIN_PATTERN_BYTES + 1))),
        );
    }

    fn compact_outcome(
        patterns: &[Vec<u8>],
        limits: LiteralSetBuildLimits,
    ) -> Result<LiteralSetCompactBuildOutcome, LiteralSetError> {
        let borrowed = patterns.iter().map(Vec::as_slice).collect::<Vec<_>>();
        LiteralSetCompactPlan::try_new_ripgrep_standard_borrowed(&borrowed, limits)
    }

    fn compact(
        patterns: &[Vec<u8>],
        limits: LiteralSetBuildLimits,
    ) -> Result<Option<LiteralSetCompactPlan>, LiteralSetError> {
        Ok(match compact_outcome(patterns, limits)? {
            LiteralSetCompactBuildOutcome::Compact(plan) => Some(plan),
            LiteralSetCompactBuildOutcome::NotApplicable
            | LiteralSetCompactBuildOutcome::Canonical(_) => None,
        })
    }

    fn ordinary_outcome(
        patterns: &[Vec<u8>],
        limits: LiteralSetBuildLimits,
    ) -> Result<LiteralSetCompactOrdinaryBuildOutcome, LiteralSetError> {
        let borrowed = patterns.iter().map(Vec::as_slice).collect::<Vec<_>>();
        LiteralSetCompactOrdinaryPlan::try_new_ripgrep_standard_borrowed(&borrowed, limits)
    }

    fn ordinary_candidate(
        patterns: &[Vec<u8>],
        limits: LiteralSetBuildLimits,
    ) -> Result<Option<LiteralSetCompactOrdinaryCandidate>, LiteralSetError> {
        Ok(match ordinary_outcome(patterns, limits)? {
            LiteralSetCompactOrdinaryBuildOutcome::Candidate(candidate) => Some(candidate),
            LiteralSetCompactOrdinaryBuildOutcome::NotApplicable
            | LiteralSetCompactOrdinaryBuildOutcome::Canonical(_) => None,
        })
    }

    #[test]
    fn admission_closes_exact_structural_boundaries() {
        assert!(
            compact(&public_patterns(128, 254), LiteralSetBuildLimits::default(),)
                .unwrap()
                .is_none(),
        );
        assert!(
            compact(
                &public_patterns(257, MIN_PATTERN_BYTES),
                LiteralSetBuildLimits::default(),
            )
            .unwrap()
            .is_none(),
        );

        let below_work = public_patterns(129, 253);
        let dense =
            LiteralSetPlan::new_stable(&below_work, LiteralSetBuildLimits::default()).unwrap();
        assert_eq!(dense.build_accounting().build_work_upper_bound, 8_388_094);
        assert!(matches!(
            compact_outcome(&below_work, LiteralSetBuildLimits::default()).unwrap(),
            LiteralSetCompactBuildOutcome::Canonical(_),
        ));

        let at_work = public_patterns(129, 254);
        let selected = compact(&at_work, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("129x254 crosses the compact work floor");
        assert_eq!(
            selected.build_accounting().build_work_upper_bound,
            25_234_047
        );

        let below_width = public_patterns(MAX_PATTERNS, MIN_PATTERN_BYTES - 1);
        let dense =
            LiteralSetPlan::new_stable(&below_width, LiteralSetBuildLimits::default()).unwrap();
        assert_eq!(dense.build_accounting().build_work_upper_bound, 8_356_096);
        assert!(matches!(
            compact_outcome(&below_width, LiteralSetBuildLimits::default()).unwrap(),
            LiteralSetCompactBuildOutcome::Canonical(_),
        ));

        let at_width = public_patterns(MAX_PATTERNS, MIN_PATTERN_BYTES);
        let selected = compact(&at_width, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("256x128 crosses both compact floors");
        assert_eq!(
            selected.build_accounting().build_work_upper_bound,
            25_239_016
        );

        let mut nonuniform = at_width;
        nonuniform[17].push(b'x');
        assert!(matches!(
            compact_outcome(&nonuniform, LiteralSetBuildLimits::default()).unwrap(),
            LiteralSetCompactBuildOutcome::Canonical(_),
        ));
    }

    #[test]
    fn uniform_spans_match_dense_across_overlap_adjacency_and_windows() {
        let patterns = (0_u16..=255)
            .map(|index| {
                let mut pattern = vec![b'a'; MIN_PATTERN_BYTES];
                pattern[0] = u8::try_from(index.min(254)).unwrap();
                if index == 255 {
                    pattern[1] = b'b';
                }
                pattern
            })
            .collect::<Vec<_>>();
        let dense =
            LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let compact_plan = compact(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .unwrap();
        let ordinary_plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the ordinary route admits the same compact shape")
            .into_ordinary();
        let ordinary = ordinary_plan.ordinary_executor();

        let mut haystack = vec![u8::MAX];
        haystack.extend(core::iter::repeat_n(b'a', 2 * MIN_PATTERN_BYTES));
        haystack.push(u8::MAX);
        assert!(ordinary.engine.automaton.prefilter().is_none());
        let direct = CompactOrdinaryScanner::new(
            ordinary.engine,
            &haystack,
            Window::full(&haystack),
        )
        .expect("the no-prefilter compact NFA admits direct scanning");
        assert!(direct.automaton.is_start(direct.start_state));
        assert!(!direct.automaton.is_special(direct.start_state));
        compact_ordinary_scanner_probe::reset();
        assert_eq!(
            ordinary.selected_end_window_value(&haystack, Window::full(&haystack)),
            Ok(Some(1 + MIN_PATTERN_BYTES)),
            "the impossible root byte must leave the unanchored scanner at start",
        );
        for window in [
            Window::full(&haystack),
            Window::new(1, haystack.len() - 1),
            Window::new(2, haystack.len() - 1),
            Window::new(1, MIN_PATTERN_BYTES),
            Window::new(1, MIN_PATTERN_BYTES + 1),
            Window::new(MIN_PATTERN_BYTES + 1, haystack.len() - 1),
        ] {
            let expected = dense
                .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0;
            let actual = compact_plan
                .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0;
            assert_eq!(actual, expected, "window={window:?}");
            assert_eq!(ordinary.find_window_value(&haystack, window), Ok(expected));
            assert_eq!(
                ordinary.selected_end_window_value(&haystack, window),
                Ok(expected.map(|(_, end)| end)),
            );
            assert_eq!(
                ordinary.exists_window_value(&haystack, window),
                Ok(expected.is_some()),
            );
        }
        assert_eq!(
            compact_ordinary_scanner_probe::binds(),
            0,
            "one-shot find, endpoint and exists must retain Aho search",
        );

        let window = Window::full(&haystack);
        let mut spans = Vec::new();
        assert_eq!(
            ordinary
                .try_visit_spans_window_value(&haystack, window, |span| {
                    spans.push(span);
                    Ok::<bool, ()>(true)
                })
                .unwrap(),
            Ok(()),
        );
        assert_eq!(
            spans,
            [
                (1, 1 + MIN_PATTERN_BYTES),
                (1 + MIN_PATTERN_BYTES, 1 + 2 * MIN_PATTERN_BYTES),
            ],
            "overlapping starts are suppressed while adjacent matches remain",
        );
        assert_eq!(compact_ordinary_scanner_probe::binds(), 1);
        assert_eq!(ordinary.count_spans_window_value(&haystack, window), Ok(2));
        assert_eq!(compact_ordinary_scanner_probe::binds(), 2);
        let mut stopped_calls = 0;
        assert_eq!(
            ordinary.try_visit_spans_window_value(&haystack, window, |_| {
                stopped_calls += 1;
                Ok::<bool, &'static str>(false)
            }),
            Ok(Ok(())),
        );
        assert_eq!(stopped_calls, 1);
        assert_eq!(
            ordinary.try_visit_spans_window_value(&haystack, window, |_| {
                Err::<bool, _>("direct callback")
            }),
            Ok(Err("direct callback")),
        );

        let overlap_only = Window::new(1, 2 + MIN_PATTERN_BYTES);
        let mut overlap_spans = Vec::new();
        ordinary
            .try_visit_spans_window_value(&haystack, overlap_only, |span| {
                overlap_spans.push(span);
                Ok::<bool, ()>(true)
            })
            .unwrap()
            .unwrap();
        assert_eq!(overlap_spans, [(1, 1 + MIN_PATTERN_BYTES)]);
    }

    #[test]
    fn seeded_ordinary_engine_matches_the_canonical_dfa_across_windows() {
        fn next(seed: &mut u64) -> u64 {
            *seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *seed
        }

        fn below(seed: &mut u64, upper: usize) -> usize {
            let upper = u64::try_from(upper).unwrap();
            usize::try_from(next(seed) % upper).unwrap()
        }

        let mut seed = 0x5cee_987d_a7a5_eed5_u64;
        let mut patterns = (0_u16..=255)
            .map(|first| {
                let mut pattern = vec![b'a'; MIN_PATTERN_BYTES];
                pattern[0] = u8::try_from(first).unwrap();
                pattern
            })
            .collect::<Vec<_>>();
        for pattern in &mut patterns {
            for byte in &mut pattern[1..] {
                *byte = b'a' + u8::try_from(next(&mut seed) & 3).unwrap();
            }
        }
        let dual = compact(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the seeded uniform set admits the dual owner");
        let canonical = dual
            .canonical
            .ordinary_executor()
            .expect("the canonical uniform DFA binds ordinary search");
        let ordinary_plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the seeded uniform set admits the ordinary owner")
            .into_ordinary();
        let ordinary = ordinary_plan.ordinary_executor();
        assert!(ordinary.engine.automaton.prefilter().is_none());

        for case in 0..64 {
            let len = usize::try_from(next(&mut seed) % 769).unwrap();
            let mut haystack = (0..len)
                .map(|_| b'a' + u8::try_from(next(&mut seed) & 7).unwrap())
                .collect::<Vec<_>>();
            if case % 3 != 0 && len >= MIN_PATTERN_BYTES {
                let pattern = below(&mut seed, patterns.len());
                let at = below(&mut seed, len - MIN_PATTERN_BYTES + 1);
                haystack[at..at + MIN_PATTERN_BYTES].copy_from_slice(&patterns[pattern]);
            }
            let start = below(&mut seed, len + 1);
            let end = start + below(&mut seed, len - start + 1);
            let window = Window::new(start, end);

            let expected = canonical.find_window_value(&haystack, window);
            assert_eq!(ordinary.find_window_value(&haystack, window), expected);
            assert_eq!(
                ordinary.exists_window_value(&haystack, window),
                canonical.exists_window_value(&haystack, window),
            );
            assert_eq!(
                ordinary.selected_end_window_value(&haystack, window),
                canonical.selected_end_window_value(&haystack, window),
            );
            assert_eq!(
                ordinary.count_spans_window_value(&haystack, window),
                canonical.count_spans_window_value(&haystack, window),
            );
            let mut expected_spans = Vec::new();
            canonical
                .try_visit_spans_window_value(&haystack, window, |span| {
                    expected_spans.push(span);
                    Ok::<bool, ()>(true)
                })
                .unwrap()
                .unwrap();
            let mut actual_spans = Vec::new();
            ordinary
                .try_visit_spans_window_value(&haystack, window, |span| {
                    actual_spans.push(span);
                    Ok::<bool, ()>(true)
                })
                .unwrap()
                .unwrap();
            assert_eq!(
                actual_spans, expected_spans,
                "case={case} window={window:?}"
            );
        }
    }

    #[test]
    fn ordinary_candidate_resolves_one_exact_owner_or_same_shared_fallback() {
        let patterns = public_patterns(MAX_PATTERNS, MIN_PATTERN_BYTES);
        let dual = compact(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .unwrap();
        let canonical_build = dual.canonical.build_accounting();
        let candidate = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .unwrap();
        let ordinary_build = candidate.build_accounting();

        assert_eq!(
            ordinary_build.build_work_upper_bound,
            dual.build_accounting().build_work_upper_bound,
        );
        assert_eq!(
            ordinary_build.build_bytes_upper_bound,
            dual.build_accounting().build_bytes_upper_bound,
        );
        assert_eq!(
            dual.build_accounting().persistent_bytes,
            canonical_build.persistent_bytes + ordinary_build.persistent_bytes,
        );

        let ordinary = candidate.into_ordinary();
        assert_eq!(ordinary.build_accounting(), ordinary_build);
        assert_eq!(
            ordinary.build_accounting().persistent_bytes,
            ordinary.engine.memory_usage(),
        );
        assert_eq!(
            ordinary.runtime_implementation_id(),
            dual.runtime_implementation_id(),
        );

        let fallback = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .unwrap()
            .into_canonical()
            .unwrap();
        assert_eq!(fallback.build_accounting(), canonical_build);
        let haystack = &patterns[7];
        assert_eq!(
            fallback
                .find(haystack, LiteralSetSearchLimits::unlimited())
                .unwrap(),
            dual.canonical
                .find(haystack, LiteralSetSearchLimits::unlimited())
                .unwrap(),
        );

        assert!(
            ordinary_candidate(
                &patterns,
                LiteralSetBuildLimits {
                    max_persistent_bytes: ordinary_build.persistent_bytes,
                    ..LiteralSetBuildLimits::default()
                },
            )
            .unwrap()
            .is_some(),
        );
        assert!(ordinary_build.persistent_bytes < canonical_build.persistent_bytes);
        let limit = ordinary_build.persistent_bytes - 1;
        assert!(matches!(
            ordinary_outcome(
                &patterns,
                LiteralSetBuildLimits {
                    max_persistent_bytes: limit,
                    ..LiteralSetBuildLimits::default()
                },
            ),
            Err(LiteralSetError::PersistentBytesLimit { needed, limit: actual })
                if needed == canonical_build.persistent_bytes && actual == limit
        ));
    }

    #[test]
    fn stable_text_entry_matches_the_borrowed_byte_policy() {
        let patterns = public_patterns(MAX_PATTERNS, MIN_PATTERN_BYTES);
        let text = patterns
            .iter()
            .cloned()
            .map(String::from_utf8)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let borrowed_text = text.iter().map(String::as_str).collect::<Vec<_>>();

        let byte_candidate = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .unwrap();
        let LiteralSetCompactOrdinaryBuildOutcome::Candidate(text_candidate) =
            LiteralSetCompactOrdinaryPlan::try_new_ripgrep_standard_borrowed(
                &borrowed_text,
                LiteralSetBuildLimits::default(),
            )
            .unwrap()
        else {
            panic!("the stable text entry should select the same compact owner");
        };
        assert_eq!(
            text_candidate.build_accounting(),
            byte_candidate.build_accounting(),
        );

        let haystack = patterns[37].as_slice();
        let text_plan = text_candidate.into_ordinary();
        let byte_plan = byte_candidate.into_ordinary();
        assert_eq!(
            text_plan.ordinary_executor().find_window_value(
                haystack,
                Window::new(0, haystack.len()),
            ),
            byte_plan.ordinary_executor().find_window_value(
                haystack,
                Window::new(0, haystack.len()),
            ),
        );

        let short = public_patterns(128, MIN_PATTERN_BYTES);
        let short_text = short
            .into_iter()
            .map(String::from_utf8)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let short_borrowed = short_text.iter().map(String::as_str).collect::<Vec<_>>();
        assert!(matches!(
            LiteralSetCompactOrdinaryPlan::try_new_ripgrep_standard_borrowed(
                &short_borrowed,
                LiteralSetBuildLimits::default(),
            )
            .unwrap(),
            LiteralSetCompactOrdinaryBuildOutcome::NotApplicable,
        ));
    }

    #[test]
    fn ordinary_shape_and_construction_refusals_preserve_canonical_policy() {
        assert!(matches!(
            ordinary_outcome(&public_patterns(128, 254), LiteralSetBuildLimits::default()).unwrap(),
            LiteralSetCompactOrdinaryBuildOutcome::NotApplicable,
        ));

        let below_work = public_patterns(129, 253);
        assert!(matches!(
            ordinary_outcome(&below_work, LiteralSetBuildLimits::default()).unwrap(),
            LiteralSetCompactOrdinaryBuildOutcome::Canonical(_),
        ));

        let patterns = public_patterns(MAX_PATTERNS, MIN_PATTERN_BYTES);
        let admitted = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .unwrap()
            .build_accounting();
        assert!(matches!(
            ordinary_outcome(
                &patterns,
                LiteralSetBuildLimits {
                    max_build_work: admitted.build_work_upper_bound,
                    max_build_bytes: admitted.build_bytes_upper_bound,
                    ..LiteralSetBuildLimits::default()
                },
            )
            .unwrap(),
            LiteralSetCompactOrdinaryBuildOutcome::Candidate(_),
        ));
        for limits in [
            LiteralSetBuildLimits {
                max_build_work: admitted.build_work_upper_bound - 1,
                ..LiteralSetBuildLimits::default()
            },
            LiteralSetBuildLimits {
                max_build_bytes: admitted.build_bytes_upper_bound - 1,
                ..LiteralSetBuildLimits::default()
            },
        ] {
            let LiteralSetCompactOrdinaryBuildOutcome::Canonical(canonical) =
                ordinary_outcome(&patterns, limits).unwrap()
            else {
                panic!("a compact envelope refusal must keep canonical policy");
            };
            let accounting = canonical.build_accounting();
            assert_eq!(accounting.patterns, patterns.len());
            assert_eq!(
                accounting.pattern_bytes,
                patterns.iter().map(Vec::len).sum(),
            );
            assert!(accounting.build_work_upper_bound < admitted.build_work_upper_bound);
        }
    }

    #[test]
    fn checked_canonical_transition_and_combined_persistent_caps_are_exact() {
        let patterns = public_patterns(MAX_PATTERNS, MIN_PATTERN_BYTES);
        let selected = compact(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .unwrap();
        let compact_build = selected.build_accounting();
        let canonical_build = selected.canonical.build_accounting();
        assert!(compact_build.build_work_upper_bound > canonical_build.build_work_upper_bound);
        assert!(compact_build.build_bytes_upper_bound > canonical_build.build_bytes_upper_bound);
        for limits in [
            LiteralSetBuildLimits {
                max_build_work: compact_build.build_work_upper_bound,
                ..LiteralSetBuildLimits::default()
            },
            LiteralSetBuildLimits {
                max_build_bytes: compact_build.build_bytes_upper_bound,
                ..LiteralSetBuildLimits::default()
            },
        ] {
            assert!(compact(&patterns, limits).unwrap().is_some());
        }
        for limits in [
            LiteralSetBuildLimits {
                max_build_work: compact_build.build_work_upper_bound - 1,
                ..LiteralSetBuildLimits::default()
            },
            LiteralSetBuildLimits {
                max_build_bytes: compact_build.build_bytes_upper_bound - 1,
                ..LiteralSetBuildLimits::default()
            },
        ] {
            assert!(compact(&patterns, limits).unwrap().is_none());
            assert!(LiteralSetPlan::new_stable(&patterns, limits).is_ok());
        }
        let haystack = vec![b'z'; 257];
        let window = Window::new(3, 203);
        let needed = 201;
        let limits = LiteralSetSearchLimits {
            max_transitions: needed,
        };
        let expected = selected
            .canonical
            .find_window(&haystack, window, limits)
            .unwrap();
        let actual = selected.find_window(&haystack, window, limits).unwrap();
        assert_eq!(actual, expected);
        let (_, accounting) = actual;
        assert_eq!(accounting.searched_bytes, 200);
        assert_eq!(accounting.transitions_upper_bound, needed);
        assert_eq!(
            selected.find_window(
                &haystack,
                window,
                LiteralSetSearchLimits {
                    max_transitions: needed - 1,
                },
            ),
            Err(LiteralSetError::TransitionLimit {
                needed,
                limit: needed - 1,
            }),
        );

        let persistent = selected.build_accounting().persistent_bytes;
        let canonical_persistent = selected.canonical.build_accounting().persistent_bytes;
        assert_eq!(
            persistent,
            canonical_persistent + selected.engine.memory_usage(),
        );
        assert!(
            compact(
                &patterns,
                LiteralSetBuildLimits {
                    max_persistent_bytes: persistent,
                    ..LiteralSetBuildLimits::default()
                },
            )
            .unwrap()
            .is_some(),
        );
        for limit in [persistent - 1, canonical_persistent] {
            let LiteralSetCompactBuildOutcome::Canonical(retained) = compact_outcome(
                &patterns,
                LiteralSetBuildLimits {
                    max_persistent_bytes: limit,
                    ..LiteralSetBuildLimits::default()
                },
            )
            .unwrap() else {
                panic!("compact-only persistent refusal discarded the canonical owner");
            };
            assert_eq!(
                retained.build_accounting(),
                selected.canonical.build_accounting(),
            );
        }
        assert!(matches!(
            compact(
                &patterns,
                LiteralSetBuildLimits {
                    max_persistent_bytes: canonical_persistent - 1,
                    ..LiteralSetBuildLimits::default()
                },
            ),
            Err(LiteralSetError::PersistentBytesLimit { needed, limit })
                if needed == canonical_persistent && limit == canonical_persistent - 1
        ));
    }

    #[test]
    fn ordinary_windows_and_callback_control_fail_closed() {
        let patterns = public_patterns(MAX_PATTERNS, MIN_PATTERN_BYTES);
        let compact = compact(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .unwrap();
        let ordinary = compact.ordinary_executor();
        let haystack = &patterns[3];
        assert!(ordinary.engine.automaton.prefilter().is_some());
        assert!(
            CompactOrdinaryScanner::new(ordinary.engine, haystack, Window::full(haystack)).is_none()
        );
        compact_ordinary_scanner_probe::reset();
        let invalid = Window::new(1, haystack.len() + 1);
        let expected = LiteralSetError::InvalidWindow {
            start: 1,
            end: haystack.len() + 1,
            haystack_len: haystack.len(),
        };
        assert_eq!(
            ordinary.exists_window_value(haystack, invalid),
            Err(expected.clone())
        );
        assert_eq!(
            ordinary.selected_end_window_value(haystack, invalid),
            Err(expected.clone()),
        );
        assert_eq!(
            ordinary.find_window_value(haystack, invalid),
            Err(expected.clone())
        );
        assert_eq!(
            ordinary.count_spans_window_value(haystack, invalid),
            Err(expected.clone()),
        );
        assert_eq!(
            ordinary.try_visit_spans_window_value(haystack, invalid, |_| { Ok::<bool, ()>(true) }),
            Err(expected),
        );

        let short = Window::new(1, haystack.len());
        assert_eq!(ordinary.exists_window_value(haystack, short), Ok(false));
        assert_eq!(
            ordinary.selected_end_window_value(haystack, short),
            Ok(None)
        );
        assert_eq!(ordinary.find_window_value(haystack, short), Ok(None));
        assert_eq!(ordinary.count_spans_window_value(haystack, short), Ok(0));
        let mut short_calls = 0;
        assert_eq!(
            ordinary.try_visit_spans_window_value(haystack, short, |_| {
                short_calls += 1;
                Ok::<bool, ()>(true)
            }),
            Ok(Ok(())),
        );
        assert_eq!(short_calls, 0);

        let full = Window::full(haystack);
        let mut calls = 0;
        assert_eq!(
            ordinary.try_visit_spans_window_value(haystack, full, |_| {
                calls += 1;
                Ok::<bool, &'static str>(false)
            }),
            Ok(Ok(())),
        );
        assert_eq!(calls, 1);
        assert_eq!(
            ordinary
                .try_visit_spans_window_value(haystack, full, |_| { Err::<bool, _>("callback") }),
            Ok(Err("callback")),
        );
        assert_eq!(compact_ordinary_scanner_probe::binds(), 0);
    }
}
