//! Contained contiguous-NFA owner for one authenticated literal-set shape.
//!
//! The public and generic literal-set surface remains in `literal_set`. This
//! module supplies only the outlined compact arm selected by the ripgrep
//! stable-borrowed handoff. Ordinary positive-width existence, endpoint, find,
//! span iteration and count may share one direct state scanner when the compact
//! NFA has no prefilter; every other operation retains aho-corasick's pinned
//! `Automaton` search.

use aho_corasick::automaton::{Automaton, StateID};
use aho_corasick::dfa::DFA;
use aho_corasick::nfa::contiguous::NFA;
use aho_corasick::nfa::noncontiguous;
use aho_corasick::{Anchored, Input, MatchKind};
use memchr::memchr;

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
// The ordinary owner retains only the compact NFA. It can therefore admit
// shorter, wider-cardinality sets without paying the dual owner's persistent
// DFA cost. Keep a construction-work floor so small canonical DFAs remain on
// their established path.
const ORDINARY_MAX_PATTERNS: usize = 4_096;
const ORDINARY_MIN_PATTERN_BYTES: usize = 8;
const ORDINARY_MIN_DENSE_BUILD_WORK: usize = 4 * 1024 * 1024;
const MAX_DENSE_DEPTH: usize = 24;
const LF_SHORT_SEGMENT_MIN_PATTERN_BYTES: usize = 64;
const LF_SEGMENT_INITIAL_PROBE_BYTES: usize = 256;
const LF_SEGMENT_REFILL_PROBE_BYTES: usize = 4_096;
const ORDINARY_ROUTE_RECEIPT_SCHEMA_VERSION: u32 = 3;
const ORDINARY_ROUTE_CAPABILITY_ID: &str = "literal-set-compact-ordinary-route-v3";

#[derive(Clone, Copy, Debug)]
struct CompactAdmission {
    max_patterns: usize,
    min_pattern_bytes: usize,
    min_dense_build_work: usize,
}

const DUAL_ADMISSION: CompactAdmission = CompactAdmission {
    max_patterns: MAX_PATTERNS,
    min_pattern_bytes: MIN_PATTERN_BYTES,
    min_dense_build_work: MIN_DENSE_BUILD_WORK,
};

const ORDINARY_ADMISSION: CompactAdmission = CompactAdmission {
    max_patterns: ORDINARY_MAX_PATTERNS,
    min_pattern_bytes: ORDINARY_MIN_PATTERN_BYTES,
    min_dense_build_work: ORDINARY_MIN_DENSE_BUILD_WORK,
};

#[derive(Clone, Debug)]
struct CompactEngine {
    automaton: NFA,
    width: usize,
    literals_exclude_lf: bool,
}

/// One no-prefilter compact-NFA scan shared by ordinary projections.
///
/// Compact admission proves that every pattern has the same positive width
/// and Standard semantics. The first accepting state is therefore the
/// selected endpoint, and resetting to the bound unanchored start state after
/// acceptance exactly implements non-overlapping iteration. Existence,
/// endpoint, find and count never construct an Aho `Match`; span iteration
/// recovers each start only after acceptance. Prefiltered operations retain
/// Aho's incumbent search.
struct CompactOrdinaryScanner<'a, 'h> {
    automaton: &'a NFA,
    haystack: &'h [u8],
    start_state: StateID,
    at: usize,
    window_end: usize,
    width: usize,
    skip_short_lf_segments: bool,
    // A bounded LF-free slice may outlive one accepted match. Retaining its
    // endpoint avoids repeatedly searching the same suffix on dense hits.
    segment_end: usize,
    segment_ends_at_lf: bool,
}

#[cfg(test)]
mod compact_ordinary_scanner_probe {
    use std::cell::Cell;

    std::thread_local! {
        static BINDS: Cell<usize> = const { Cell::new(0) };
        static SHORT_LF_PROBE_CALLS: Cell<usize> = const { Cell::new(0) };
        static SHORT_LF_PROBE_BYTES: Cell<usize> = const { Cell::new(0) };
        static SHORT_LF_SEGMENT_SKIPS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn reset() {
        BINDS.set(0);
        SHORT_LF_PROBE_CALLS.set(0);
        SHORT_LF_PROBE_BYTES.set(0);
        SHORT_LF_SEGMENT_SKIPS.set(0);
    }

    pub(super) fn record() {
        BINDS.set(BINDS.get().saturating_add(1));
    }

    pub(super) fn binds() -> usize {
        BINDS.get()
    }

    pub(super) fn record_short_lf_probe(bytes: usize) {
        SHORT_LF_PROBE_CALLS.set(SHORT_LF_PROBE_CALLS.get().saturating_add(1));
        SHORT_LF_PROBE_BYTES.set(SHORT_LF_PROBE_BYTES.get().saturating_add(bytes));
    }

    pub(super) fn record_short_lf_segment_skip() {
        SHORT_LF_SEGMENT_SKIPS.set(SHORT_LF_SEGMENT_SKIPS.get().saturating_add(1));
    }

    pub(super) fn short_lf_probe_calls() -> usize {
        SHORT_LF_PROBE_CALLS.get()
    }

    pub(super) fn short_lf_probe_bytes() -> usize {
        SHORT_LF_PROBE_BYTES.get()
    }

    pub(super) fn short_lf_segment_skips() -> usize {
        SHORT_LF_SEGMENT_SKIPS.get()
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

/// Cold construction-route facts read from one retained compact owner.
#[doc(hidden)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiteralSetCompactOrdinaryRouteReceipt {
    pub schema_version: u32,
    pub capability_id: &'static str,
    pub engine_width_bytes: usize,
    pub automaton_min_pattern_bytes: usize,
    pub automaton_max_pattern_bytes: usize,
    pub automaton_match_kind_standard: bool,
    pub automaton_prefilter_is_none: bool,
    pub compact_ordinary_scanner_eligible: bool,
    /// True only after the ordinary-only, minimum-width-qualified construction
    /// performed a complete LF census and found none. False is conservative:
    /// it may mean LF was present or that this route did not authenticate it.
    pub literals_exclude_lf: bool,
    pub lf_short_segment_min_pattern_bytes: usize,
    pub lf_segment_initial_probe_bytes: usize,
    pub lf_segment_refill_probe_bytes: usize,
    pub lf_short_segment_skip_enabled: bool,
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
        literals_exclude_lf: bool,
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
#[cfg(test)]
fn deepest_branch_dense_depth<P: AsRef<[u8]>>(patterns: &[P], width: usize) -> Option<usize> {
    deepest_branch_dense_depth_with_limit(patterns, width, MAX_PATTERNS)
}

fn deepest_branch_dense_depth_with_limit<P: AsRef<[u8]>>(
    patterns: &[P],
    width: usize,
    max_patterns: usize,
) -> Option<usize> {
    debug_assert!(
        patterns
            .iter()
            .all(|pattern| pattern.as_ref().len() == width)
    );
    let probe_depth = width.saturating_sub(1).min(MAX_DENSE_DEPTH);
    if probe_depth == 0 || patterns.len() < 2 {
        return Some(0);
    }
    if patterns.len() > max_patterns {
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

#[cfg(test)]
fn deepest_branch_build_work_upper_bound(patterns: usize, width: usize) -> Option<usize> {
    deepest_branch_build_work_upper_bound_with_limit(patterns, width, MAX_PATTERNS)
}

fn deepest_branch_build_work_upper_bound_with_limit(
    patterns: usize,
    width: usize,
    max_patterns: usize,
) -> Option<usize> {
    if patterns > max_patterns {
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
    compact_preflight_with_admission(patterns, limits, DUAL_ADMISSION, false)
}

fn compact_ordinary_preflight<P: AsRef<[u8]>>(
    patterns: &[P],
    limits: LiteralSetBuildLimits,
) -> Result<CompactPreflight, LiteralSetError> {
    compact_preflight_with_admission(patterns, limits, ORDINARY_ADMISSION, true)
}

fn compact_preflight_with_admission<P: AsRef<[u8]>>(
    patterns: &[P],
    limits: LiteralSetBuildLimits,
    admission: CompactAdmission,
    authenticate_lf_short_segments: bool,
) -> Result<CompactPreflight, LiteralSetError> {
    if !(MIN_PATTERNS..=admission.max_patterns).contains(&patterns.len()) {
        return Ok(CompactPreflight::NotApplicable);
    }
    let canonical_build = preflight(patterns, limits, LiteralSetMatchSemantics::LeftmostFirst)?;
    let width = canonical_build.minimum_pattern_bytes;
    let uniform_positive = width >= admission.min_pattern_bytes
        && width.checked_mul(canonical_build.patterns) == Some(canonical_build.pattern_bytes);
    if !uniform_positive || canonical_build.build_work_upper_bound < admission.min_dense_build_work
    {
        return Ok(CompactPreflight::Canonical(canonical_build));
    }
    let Some(deepest_branch_build_work) = deepest_branch_build_work_upper_bound_with_limit(
        canonical_build.patterns,
        width,
        admission.max_patterns,
    ) else {
        return Ok(CompactPreflight::Canonical(canonical_build));
    };
    // Contiguous conversion writes every encoded transition and then remaps
    // every encoded state ID in a second pass. Charge those two complete cell
    // traversals, state-map and pattern-vector setup, and the complete bounded
    // topology-selector charge. Together with the canonical receipt this also
    // covers a complete compact attempt followed by same-shared-NFA canonical
    // fallback.
    // The new LF census belongs only to the ordinary-only owner and only to
    // widths that can use it. This leaves the dual-owner policy and narrower
    // ordinary construction accounting byte-for-byte unchanged.
    let authenticate_lf_short_segments =
        authenticate_lf_short_segments && width >= LF_SHORT_SEGMENT_MIN_PATTERN_BYTES;
    let lf_authentication_work = if authenticate_lf_short_segments {
        canonical_build.pattern_bytes
    } else {
        0
    };
    let Some(compact_build_work) = canonical_build
        .dfa_cells_upper_bound
        .checked_mul(2)
        .and_then(|work| work.checked_add(canonical_build.trie_states_upper_bound))
        .and_then(|work| work.checked_add(canonical_build.patterns))
        .and_then(|work| work.checked_add(deepest_branch_build_work))
        .and_then(|work| work.checked_add(lf_authentication_work))
        .and_then(|work| work.checked_add(canonical_build.build_work_upper_bound))
    else {
        return Ok(CompactPreflight::Canonical(canonical_build));
    };
    if compact_build_work > limits.max_build_work {
        return Ok(CompactPreflight::Canonical(canonical_build));
    }
    let Some(dense_depth) =
        deepest_branch_dense_depth_with_limit(patterns, width, admission.max_patterns)
    else {
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
    let literals_exclude_lf = authenticate_lf_short_segments
        && patterns
            .iter()
            .all(|pattern| !pattern.as_ref().contains(&b'\n'));
    Ok(CompactPreflight::Eligible {
        canonical_build,
        compact_build,
        width,
        dense_depth,
        literals_exclude_lf,
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

fn build_shared<P: AsRef<[u8]>>(patterns: &[P]) -> Result<noncontiguous::NFA, LiteralSetError> {
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
    literals_exclude_lf: bool,
) -> Option<CompactEngine> {
    if width == 0 || dense_depth > MAX_DENSE_DEPTH || dense_depth >= width {
        return None;
    }
    debug_assert!(dense_depth <= MAX_DENSE_DEPTH);
    debug_assert!(dense_depth < width);
    let mut builder = NFA::builder();
    // aho-corasick 1.1.4 interprets this as an exclusive state-depth
    // threshold: states with `state.depth() < dense_depth` are forced dense.
    // The unchanged worst-case byte envelope above also covers Aho's automatic
    // dense-state choices outside this forced prefix.
    builder.dense_depth(dense_depth);
    let automaton = builder.build_from_noncontiguous(shared).ok()?;
    if automaton.match_kind() != MatchKind::Standard
        || automaton.min_pattern_len() != width
        || automaton.max_pattern_len() != width
    {
        return None;
    }
    debug_assert_eq!(automaton.match_kind(), MatchKind::Standard);
    debug_assert_eq!(automaton.min_pattern_len(), width);
    debug_assert_eq!(automaton.max_pattern_len(), width);
    Some(CompactEngine {
        automaton,
        width,
        literals_exclude_lf,
    })
}

impl CompactEngine {
    #[inline]
    fn memory_usage(&self) -> usize {
        self.automaton.memory_usage()
    }
}

impl<'a, 'h> CompactOrdinaryScanner<'a, 'h> {
    /// Keep receipt classification and scanner construction on one predicate
    /// without allocating or observing a synthetic source.
    #[inline]
    fn is_eligible(engine: &CompactEngine) -> bool {
        engine.width != 0 && engine.automaton.prefilter().is_none()
    }

    #[inline]
    fn short_lf_segment_skip_enabled(engine: &CompactEngine) -> bool {
        Self::is_eligible(engine)
            && engine.literals_exclude_lf
            && engine.width >= LF_SHORT_SEGMENT_MIN_PATTERN_BYTES
    }

    /// Bind the direct scanner only when Aho has no construction-selected
    /// prefilter to preserve. Compact construction independently proves the
    /// positive fixed width and Standard semantics used by the scan body.
    #[inline]
    fn new(engine: &'a CompactEngine, haystack: &'h [u8], window: Window) -> Option<Self> {
        if !Self::is_eligible(engine) {
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
        let skip_short_lf_segments = Self::short_lf_segment_skip_enabled(engine);
        Some(Self {
            automaton: &engine.automaton,
            haystack,
            start_state,
            at: window.start(),
            window_end: window.end(),
            width: engine.width,
            skip_short_lf_segments,
            segment_end: window.start(),
            segment_ends_at_lf: false,
        })
    }

    /// Discover one bounded LF-free slice. The first probe in each search is
    /// small to bound early-existence lookahead; continued scans amortize the
    /// delimiter search with larger blocks. The LF itself is never included
    /// in the slice. Callers distinguish a real LF from a discovery-block end.
    #[inline(always)]
    fn discover_lf_segment(&mut self, probe_cap: usize) {
        let probe_bytes = probe_cap.min(self.window_end - self.at);
        debug_assert!(probe_bytes > 0);
        #[cfg(test)]
        compact_ordinary_scanner_probe::record_short_lf_probe(probe_bytes);
        let probe_end = self.at + probe_bytes;
        if let Some(relative_lf) = memchr(b'\n', &self.haystack[self.at..probe_end]) {
            self.segment_end = self.at + relative_lf;
            self.segment_ends_at_lf = true;
        } else {
            self.segment_end = probe_end;
            self.segment_ends_at_lf = false;
        }
    }

    #[inline(always)]
    fn exhaust(&mut self) {
        self.at = self.window_end;
    }

    /// Return the next non-overlapping first acceptance without constructing
    /// an Aho input, iterator or match value.
    #[inline(always)]
    fn next_end(&mut self) -> Option<usize> {
        if self.skip_short_lf_segments {
            self.next_end_in_lf_segments()
        } else {
            self.next_end_without_lf_segments()
        }
    }

    /// Non-overlapping searches start at the root, but discovery-block ends
    /// do not reset automaton state: a match may straddle such an end. Only
    /// an authenticated actual LF resets the state. The inner byte loop has
    /// neither a delimiter branch nor a second per-byte bound check.
    #[inline(always)]
    fn next_end_in_lf_segments(&mut self) -> Option<usize> {
        debug_assert!(self.at <= self.window_end);
        if self.at >= self.window_end {
            self.exhaust();
            return None;
        }
        let mut state = self.start_state;
        let mut can_skip = true;
        let mut probe_cap = LF_SEGMENT_INITIAL_PROBE_BYTES;
        loop {
            if self.at >= self.segment_end {
                // The matching-line projection can advance the cursor past
                // this cache. A stale delimiter must not consume a new byte.
                if self.at == self.segment_end && self.segment_ends_at_lf {
                    self.at += 1;
                    state = self.start_state;
                    can_skip = true;
                }
                if self.at >= self.window_end {
                    self.exhaust();
                    return None;
                }
                self.discover_lf_segment(probe_cap);
                probe_cap = LF_SEGMENT_REFILL_PROBE_BYTES;
            }

            // A short block without LF may be the start of a longer record;
            // it must be scanned and its partial NFA state carried forward.
            if can_skip && self.segment_ends_at_lf && self.segment_end - self.at < self.width {
                self.at = self.segment_end + 1;
                state = self.start_state;
                #[cfg(test)]
                compact_ordinary_scanner_probe::record_short_lf_segment_skip();
                continue;
            }
            let remaining = &self.haystack[self.at..self.segment_end];
            let mut bytes = remaining.iter();
            while let Some(&byte) = bytes.next() {
                state = self.automaton.next_state(Anchored::No, state, byte);
                if !self.automaton.is_special(state) {
                    continue;
                }
                // Aho's unanchored Standard traversal has no transitions to
                // its dead state, or special start states without a prefilter.
                debug_assert!(
                    self.automaton.is_match(state),
                    "a Standard compact NFA without a prefilter has no other reachable special states",
                );
                let accepted_end = self.segment_end - bytes.len();
                self.at = accepted_end;
                return Some(accepted_end);
            }
            self.at = self.segment_end;
            can_skip = false;
        }
    }

    #[inline(always)]
    fn next_end_without_lf_segments(&mut self) -> Option<usize> {
        debug_assert!(self.at <= self.window_end);
        if self.at >= self.window_end {
            self.exhaust();
            return None;
        }
        let remaining = &self.haystack[self.at..self.window_end];
        let mut state = self.start_state;
        let mut bytes = remaining.iter();
        while let Some(&byte) = bytes.next() {
            state = self.automaton.next_state(Anchored::No, state, byte);
            if !self.automaton.is_special(state) {
                continue;
            }
            debug_assert!(self.automaton.is_match(state));
            let accepted_end = self.window_end - bytes.len();
            self.at = accepted_end;
            return Some(accepted_end);
        }
        self.exhaust();
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
        let (canonical_build, mut compact_build, width, dense_depth, literals_exclude_lf) =
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
                    literals_exclude_lf,
                } => (
                    canonical_build,
                    compact_build,
                    width,
                    dense_depth,
                    literals_exclude_lf,
                ),
            };
        let shared = build_shared(patterns)?;
        // Checked and explicit-session calls retain the exact established DFA
        // contract. The compact NFA is an additional ordinary-only engine.
        let canonical = canonical_from_shared(&shared, canonical_build, limits)?;
        let engine = match compact_engine(&shared, width, dense_depth, literals_exclude_lf) {
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
        let (canonical_build, mut compact_build, width, dense_depth, literals_exclude_lf) =
            match compact_ordinary_preflight(patterns, limits)? {
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
                    literals_exclude_lf,
                } => (
                    canonical_build,
                    compact_build,
                    width,
                    dense_depth,
                    literals_exclude_lf,
                ),
            };
        let shared = build_shared(patterns)?;
        let Some(engine) = compact_engine(&shared, width, dense_depth, literals_exclude_lf) else {
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

    /// Read the retained automaton and direct-scanner construction route.
    ///
    /// This cold receipt shares the exact eligibility predicates used by the
    /// scanner constructor without allocating or inspecting a source.
    #[doc(hidden)]
    #[cold]
    #[inline(never)]
    #[must_use]
    pub fn construction_route_receipt(&self) -> LiteralSetCompactOrdinaryRouteReceipt {
        let automaton = &self.engine.automaton;
        let compact_ordinary_scanner_eligible = CompactOrdinaryScanner::is_eligible(&self.engine);
        let lf_short_segment_skip_enabled =
            CompactOrdinaryScanner::short_lf_segment_skip_enabled(&self.engine);
        LiteralSetCompactOrdinaryRouteReceipt {
            schema_version: ORDINARY_ROUTE_RECEIPT_SCHEMA_VERSION,
            capability_id: ORDINARY_ROUTE_CAPABILITY_ID,
            engine_width_bytes: self.engine.width,
            automaton_min_pattern_bytes: automaton.min_pattern_len(),
            automaton_max_pattern_bytes: automaton.max_pattern_len(),
            automaton_match_kind_standard: automaton.match_kind() == MatchKind::Standard,
            automaton_prefilter_is_none: automaton.prefilter().is_none(),
            compact_ordinary_scanner_eligible,
            literals_exclude_lf: self.engine.literals_exclude_lf,
            lf_short_segment_min_pattern_bytes: LF_SHORT_SEGMENT_MIN_PATTERN_BYTES,
            lf_segment_initial_probe_bytes: LF_SEGMENT_INITIAL_PROBE_BYTES,
            lf_segment_refill_probe_bytes: LF_SEGMENT_REFILL_PROBE_BYTES,
            lf_short_segment_skip_enabled,
        }
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
            // Aho already derives this absolute start while constructing its
            // match. Reuse it instead of subtracting the uniform width again
            // for every tail match.
            let span = matched.span();
            debug_assert_eq!(span.end - span.start, self.width);
            match visitor((span.start, span.end)) {
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
        let count = self.reduce_endpoints_window_value_nonempty(haystack, window, false)?;
        u64::try_from(count).map_err(|_| LiteralSetError::ArithmeticOverflow {
            computation: "compact literal-set ordinary match count",
        })
    }

    /// Count LF-delimited lines with at least one acceptance. The caller has
    /// authenticated that LF cannot occur in any retained literal, so the
    /// first acceptance in a line permits skipping directly to its boundary.
    #[inline(never)]
    fn count_matching_lf_lines_value(&self, haystack: &[u8]) -> Result<u64, LiteralSetError> {
        let window = Window::full(haystack);
        if self.window_is_too_short(window) {
            return Ok(0);
        }
        let mut count = 0_u64;
        if let Some(mut scanner) = CompactOrdinaryScanner::new(self, haystack, window) {
            while let Some(end) = scanner.next_end() {
                count = count
                    .checked_add(1)
                    .ok_or(LiteralSetError::ArithmeticOverflow {
                        computation: "compact literal-set matching LF-line count",
                    })?;
                let Some(relative_lf) = memchr(b'\n', &haystack[end..]) else {
                    break;
                };
                scanner.at = end
                    .checked_add(relative_lf)
                    .and_then(|at| at.checked_add(1))
                    .ok_or(LiteralSetError::ArithmeticOverflow {
                        computation: "compact literal-set next LF-line start",
                    })?;
            }
            return Ok(count);
        }
        let mut at = 0;
        loop {
            let input = Input::new(haystack).span(at..haystack.len());
            let Some(matched) = self
                .automaton
                .try_find(&input)
                .expect("the compact literal NFA supports unanchored search")
            else {
                break;
            };
            count = count
                .checked_add(1)
                .ok_or(LiteralSetError::ArithmeticOverflow {
                    computation: "compact literal-set matching LF-line count",
                })?;
            let Some(relative_lf) = memchr(b'\n', &haystack[matched.end()..]) else {
                break;
            };
            at = matched
                .end()
                .checked_add(relative_lf)
                .and_then(|at| at.checked_add(1))
                .ok_or(LiteralSetError::ArithmeticOverflow {
                    computation: "compact literal-set next LF-line start",
                })?;
        }
        Ok(count)
    }

    /// Reduce a whole direct-scanner window without outlining each accepted
    /// endpoint. Count mode returns the exact count. First-only mode returns
    /// zero for no match and `end + 1` for a match, preserving a one-word ABI.
    #[inline(never)]
    fn reduce_endpoints_window_value_nonempty(
        &self,
        haystack: &[u8],
        window: Window,
        first_only: bool,
    ) -> Result<usize, LiteralSetError> {
        debug_assert!(!self.window_is_too_short(window));
        if let Some(mut scanner) = CompactOrdinaryScanner::new(self, haystack, window) {
            let mut count = 0_usize;
            while let Some(end) = scanner.next_end() {
                if first_only {
                    return end
                        .checked_add(1)
                        .ok_or(LiteralSetError::ArithmeticOverflow {
                            computation: "compact literal-set encoded selected end",
                        });
                }
                // Positive-width, non-overlapping matches bound this count by
                // the already-validated window's byte length.
                count += 1;
            }
            return Ok(count);
        }
        // First-only callers prove the no-prefilter direct-scanner admission
        // before crossing this outlined boundary. Only count preserves Aho's
        // construction-selected prefilter fallback.
        debug_assert!(!first_only);
        let input = Input::new(haystack).span(window.start()..window.end());
        let count = self
            .automaton
            .try_find_iter(input)
            .expect("the compact literal NFA supports unanchored iteration")
            .count();
        // Matches do not overlap and have positive width, so their count is
        // bounded by the validated window length.
        Ok(count)
    }

    #[inline(never)]
    fn first_end_from_reduced_endpoint_nonempty(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Option<usize> {
        debug_assert!(!self.window_is_too_short(window));
        debug_assert!(self.automaton.prefilter().is_none());
        self.reduce_endpoints_window_value_nonempty(haystack, window, true)
            .expect("an endpoint within a validated slice must permit end + 1 encoding")
            .checked_sub(1)
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
        if self.automaton.prefilter().is_none() {
            let encoded_end =
                self.reduce_endpoints_window_value_nonempty(haystack, window, true)?;
            if encoded_end == 0 {
                return Ok(None);
            }
            let end = encoded_end - 1;
            let start = end
                .checked_sub(self.width)
                .ok_or(LiteralSetError::ArithmeticOverflow {
                    computation: "compact literal-set match start",
                })?;
            return Ok(Some((start, end)));
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
        if self.automaton.prefilter().is_none() {
            return self.first_end_from_reduced_endpoint_nonempty(haystack, window);
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

    /// Count matching LF-delimited lines when the embedding has independently
    /// proved that no retained literal contains LF.
    #[doc(hidden)]
    #[inline]
    pub fn count_matching_lf_lines_value(
        &self,
        haystack: &[u8],
        lf_is_excluded: bool,
    ) -> Result<Option<u64>, LiteralSetError> {
        if !lf_is_excluded {
            return Ok(None);
        }
        self.engine
            .count_matching_lf_lines_value(haystack)
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use aho_corasick::automaton::Automaton;
    use aho_corasick::nfa::noncontiguous;
    use aho_corasick::{Anchored, MatchKind};

    use super::{
        ALPHABET_LEN, BYTES_PER_DFA_CELL_ENVELOPE, BYTES_PER_TRIE_STATE_ENVELOPE,
        CompactOrdinaryScanner, CompactPreflight, LF_SEGMENT_INITIAL_PROBE_BYTES,
        LF_SEGMENT_REFILL_PROBE_BYTES, LF_SHORT_SEGMENT_MIN_PATTERN_BYTES,
        LiteralSetCompactBuildOutcome, LiteralSetCompactOrdinaryBuildOutcome,
        LiteralSetCompactOrdinaryCandidate, LiteralSetCompactOrdinaryPlan,
        LiteralSetCompactOrdinaryRouteReceipt, LiteralSetCompactPlan, MAX_DENSE_DEPTH,
        MAX_PATTERNS, MIN_PATTERN_BYTES, MIN_PATTERNS, ORDINARY_MAX_PATTERNS,
        ORDINARY_MIN_DENSE_BUILD_WORK, build_shared, compact_engine, compact_ordinary_preflight,
        compact_ordinary_scanner_probe, compact_preflight, deepest_branch_build_work_upper_bound,
        deepest_branch_build_work_upper_bound_with_limit, deepest_branch_dense_depth,
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
            literals_exclude_lf,
        } = compact_preflight(&borrowed, LiteralSetBuildLimits::default()).unwrap()
        else {
            panic!("public compact fixture should pass preflight");
        };
        assert_eq!(dense_depth, 9);
        assert!(!literals_exclude_lf);
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
    fn ordinary_lf_authentication_is_exactly_charged_and_fail_closed() {
        let active_width = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES.max(64);
        let lf_free = broad_root_512_lf_free_patterns(active_width);
        let borrowed = lf_free.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let CompactPreflight::Eligible {
            canonical_build,
            compact_build,
            literals_exclude_lf,
            ..
        } = compact_ordinary_preflight(&borrowed, LiteralSetBuildLimits::default()).unwrap()
        else {
            panic!("the threshold-qualified ordinary fixture should pass compact preflight");
        };
        assert!(literals_exclude_lf);
        let topology_work = deepest_branch_build_work_upper_bound_with_limit(
            canonical_build.patterns,
            canonical_build.minimum_pattern_bytes,
            ORDINARY_MAX_PATTERNS,
        )
        .unwrap();
        let without_lf_census = canonical_build.dfa_cells_upper_bound * 2
            + canonical_build.trie_states_upper_bound
            + canonical_build.patterns
            + topology_work
            + canonical_build.build_work_upper_bound;
        assert_eq!(
            compact_build.build_work_upper_bound,
            without_lf_census + canonical_build.pattern_bytes,
        );
        assert!(matches!(
            compact_ordinary_preflight(
                &borrowed,
                LiteralSetBuildLimits {
                    max_build_work: compact_build.build_work_upper_bound,
                    ..LiteralSetBuildLimits::default()
                },
            )
            .unwrap(),
            CompactPreflight::Eligible {
                literals_exclude_lf: true,
                ..
            },
        ));
        assert!(matches!(
            compact_ordinary_preflight(
                &borrowed,
                LiteralSetBuildLimits {
                    max_build_work: compact_build.build_work_upper_bound - 1,
                    ..LiteralSetBuildLimits::default()
                },
            )
            .unwrap(),
            CompactPreflight::Canonical(_),
        ));

        let mut contains_lf = lf_free;
        contains_lf[0][active_width / 2] = b'\n';
        let borrowed_lf = contains_lf.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let CompactPreflight::Eligible {
            compact_build: lf_build,
            literals_exclude_lf: false,
            ..
        } = compact_ordinary_preflight(&borrowed_lf, LiteralSetBuildLimits::default()).unwrap()
        else {
            panic!("LF presence changes the fact, not the conservative work charge");
        };
        assert_eq!(
            lf_build.build_work_upper_bound,
            compact_build.build_work_upper_bound
        );

        let narrow_width = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES
            .checked_sub(1)
            .expect("the positive LF threshold has a one-below boundary");
        let narrow = broad_root_lf_threshold_boundary_patterns(narrow_width);
        let borrowed_narrow = narrow.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let CompactPreflight::Eligible {
            canonical_build: narrow_canonical,
            compact_build: narrow_compact,
            literals_exclude_lf: false,
            ..
        } = compact_ordinary_preflight(&borrowed_narrow, LiteralSetBuildLimits::default()).unwrap()
        else {
            panic!("the narrow ordinary fixture remains compact but skips LF authentication");
        };
        let narrow_topology = deepest_branch_build_work_upper_bound_with_limit(
            narrow_canonical.patterns,
            narrow_canonical.minimum_pattern_bytes,
            ORDINARY_MAX_PATTERNS,
        )
        .unwrap();
        assert_eq!(
            narrow_compact.build_work_upper_bound,
            narrow_canonical.dfa_cells_upper_bound * 2
                + narrow_canonical.trie_states_upper_bound
                + narrow_canonical.patterns
                + narrow_topology
                + narrow_canonical.build_work_upper_bound,
        );
    }

    #[test]
    fn compact_engine_release_contract_fails_closed() {
        let width = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES;
        let patterns = broad_root_512_lf_free_patterns(width);
        let borrowed = patterns.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let shared = build_shared(&borrowed).expect("the standard fixture builds a shared NFA");

        assert!(compact_engine(&shared, width, 1, true).is_some());
        assert!(compact_engine(&shared, 0, 0, true).is_none());
        assert!(compact_engine(&shared, width, MAX_DENSE_DEPTH + 1, true).is_none());
        assert!(compact_engine(&shared, width, width, true).is_none());
        assert!(compact_engine(&shared, width + 1, 1, true).is_none());

        let mut builder = noncontiguous::Builder::new();
        builder.match_kind(MatchKind::LeftmostFirst);
        let leftmost = builder
            .build(borrowed.iter().copied())
            .expect("the leftmost-first fixture builds a shared NFA");
        assert!(compact_engine(&leftmost, width, 1, true).is_none());

        let mut mixed = patterns;
        mixed[0].push(b'X');
        let mixed_borrowed = mixed.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let mixed_shared =
            build_shared(&mixed_borrowed).expect("the mixed-width fixture builds a shared NFA");
        assert!(compact_engine(&mixed_shared, width, 1, true).is_none());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn compact_scanner_release_guards_fail_closed() {
        let width = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES;
        let patterns = broad_root_512_lf_free_patterns(width);
        let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the release-guard fixture admits the compact ordinary owner")
            .into_ordinary();
        let haystack = vec![b'!'; width * 2];

        let mut inverted =
            CompactOrdinaryScanner::new(&plan.engine, &haystack, Window::full(&haystack))
                .expect("the release-guard fixture binds the direct scanner");
        inverted.at = inverted.window_end + 1;
        assert_eq!(inverted.next_end(), None);
        assert_eq!(inverted.at, inverted.window_end);
        compact_ordinary_scanner_probe::reset();
        assert_eq!(inverted.next_end(), None);
        assert_eq!(compact_ordinary_scanner_probe::short_lf_probe_calls(), 0);
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

    fn broad_root_256x128_patterns() -> Vec<Vec<u8>> {
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
        assert_eq!(patterns.len(), 256);
        assert!(patterns.iter().all(|pattern| pattern.len() == 128));
        patterns
    }

    fn broad_root_256x128_lf_free_patterns() -> Vec<Vec<u8>> {
        let mut patterns = broad_root_256x128_patterns();
        for pattern in &mut patterns {
            if pattern[0] >= b'\n' {
                pattern[0] = pattern[0].saturating_add(1);
            }
        }
        assert!(patterns.iter().all(|pattern| !pattern.contains(&b'\n')));
        patterns
    }

    fn broad_root_lf_free_patterns(count: usize, width: usize) -> Vec<Vec<u8>> {
        assert!(width >= 2);
        assert!(count <= ORDINARY_MAX_PATTERNS);
        let patterns = (0_usize..count)
            .map(|index| {
                let mut pattern = vec![b'a'; width];
                let raw_root = u8::try_from(index % 255).unwrap();
                pattern[0] = if raw_root >= b'\n' {
                    raw_root.saturating_add(1)
                } else {
                    raw_root
                };
                pattern[1] = b'a' + u8::try_from(index / 255).unwrap();
                pattern
            })
            .collect::<Vec<_>>();
        assert!(patterns.iter().all(|pattern| !pattern.contains(&b'\n')));
        patterns
    }

    fn broad_root_lf_threshold_boundary_patterns(width: usize) -> Vec<Vec<u8>> {
        let count = (MIN_PATTERNS..=ORDINARY_MAX_PATTERNS)
            .find(|&count| {
                let pattern_bytes = count.checked_mul(width).unwrap();
                let trie_states = pattern_bytes.checked_add(1).unwrap();
                trie_states
                    .checked_mul(ALPHABET_LEN)
                    .and_then(|work| work.checked_add(pattern_bytes))
                    .and_then(|work| work.checked_add(count))
                    .is_some_and(|work| work >= ORDINARY_MIN_DENSE_BUILD_WORK)
            })
            .expect("the one-below-LF-threshold fixture reaches ordinary admission");
        broad_root_lf_free_patterns(count, width)
    }

    fn broad_root_512_lf_free_patterns(width: usize) -> Vec<Vec<u8>> {
        broad_root_lf_free_patterns(512, width)
    }

    fn broad_root_256_lf_free_patterns(width: usize) -> Vec<Vec<u8>> {
        assert!(width >= 2);
        let patterns = (0_u16..=255)
            .map(|index| {
                let mut pattern = vec![b'a'; width];
                let raw_root = u8::try_from(index.min(254)).unwrap();
                pattern[0] = if raw_root >= b'\n' {
                    raw_root.saturating_add(1)
                } else {
                    raw_root
                };
                if index == 255 {
                    pattern[1] = b'b';
                }
                pattern
            })
            .collect::<Vec<_>>();
        assert!(patterns.iter().all(|pattern| !pattern.contains(&b'\n')));
        patterns
    }

    #[test]
    fn standard_unanchored_compact_paths_never_enter_dead() {
        let patterns = broad_root_256x128_patterns();
        let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the broad-root fixed-width set admits the compact owner")
            .into_ordinary();
        let automaton = &plan.engine.automaton;
        assert_eq!(automaton.match_kind(), MatchKind::Standard);
        assert!(automaton.prefilter().is_none());
        let start = automaton
            .start_state(Anchored::No)
            .expect("the compact owner retains its unanchored start");

        for byte in u8::MIN..=u8::MAX {
            let next = automaton.next_state(Anchored::No, start, byte);
            assert!(!automaton.is_dead(next), "root byte {byte:#04x}");
        }
        for (pattern_index, pattern) in patterns.iter().enumerate() {
            let mut state = start;
            for (byte_index, &byte) in pattern.iter().enumerate() {
                state = automaton.next_state(Anchored::No, state, byte);
                assert!(
                    !automaton.is_dead(state),
                    "pattern {pattern_index}, byte {byte_index}",
                );
                for fallback in [u8::MIN, b'x', u8::MAX] {
                    let next = automaton.next_state(Anchored::No, state, fallback);
                    assert!(
                        !automaton.is_dead(next),
                        "pattern {pattern_index}, byte {byte_index}, fallback {fallback:#04x}",
                    );
                }
            }
            assert!(automaton.is_match(state), "pattern {pattern_index}");
        }
    }

    #[test]
    fn standard_unanchored_256x128_count_uses_direct_ordinary_scanner() {
        let patterns = broad_root_256x128_patterns();
        let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the broad-root 256x128 set admits the compact ordinary owner")
            .into_ordinary();
        assert_eq!(plan.engine.automaton.match_kind(), MatchKind::Standard);
        assert!(plan.engine.automaton.prefilter().is_none());

        let mut haystack = vec![u8::MAX];
        haystack.extend_from_slice(&patterns[0]);
        haystack.push(u8::MAX);
        haystack.extend_from_slice(&patterns[255]);
        haystack.push(u8::MAX);
        compact_ordinary_scanner_probe::reset();
        assert_eq!(
            plan.ordinary_executor()
                .count_spans_window_value(&haystack, Window::full(&haystack)),
            Ok(2),
        );
        assert_eq!(
            compact_ordinary_scanner_probe::binds(),
            1,
            "ordinary count binds the direct no-prefilter scanner once",
        );
    }

    #[test]
    fn direct_scanner_counts_each_authenticated_lf_line_once() {
        let patterns = broad_root_256x128_lf_free_patterns();
        let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the broad-root set admits the compact ordinary owner")
            .into_ordinary();
        assert!(plan.engine.automaton.prefilter().is_none());
        let ordinary = plan.ordinary_executor();

        let mut haystack = b"miss\n".to_vec();
        haystack.extend_from_slice(&patterns[0]);
        haystack.extend_from_slice(&patterns[0]);
        haystack.extend_from_slice(b"\n\n");
        haystack.extend_from_slice(&patterns[17]);
        haystack.push(b'\n');
        haystack.extend_from_slice(&patterns[255]);
        haystack.extend_from_slice(&patterns[1]);
        haystack.push(b'\n');
        haystack.extend_from_slice(&patterns[5]);

        compact_ordinary_scanner_probe::reset();
        assert_eq!(
            ordinary.count_matching_lf_lines_value(&haystack, true),
            Ok(Some(4)),
        );
        assert_eq!(compact_ordinary_scanner_probe::binds(), 1);
        assert_eq!(
            ordinary.count_matching_lf_lines_value(&haystack, false),
            Ok(None),
        );
    }

    #[test]
    fn prefiltered_scanner_counts_each_authenticated_lf_line_once() {
        let patterns = public_patterns(MAX_PATTERNS, MIN_PATTERN_BYTES);
        let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the common-prefix set admits the compact ordinary owner")
            .into_ordinary();
        assert!(plan.engine.automaton.prefilter().is_some());
        let ordinary = plan.ordinary_executor();

        let mut haystack = b"miss\n".to_vec();
        haystack.extend_from_slice(&patterns[3]);
        haystack.extend_from_slice(&patterns[3]);
        haystack.push(b'\n');
        haystack.extend_from_slice(&patterns[7]);
        haystack.extend_from_slice(b"\n\n");
        haystack.extend_from_slice(&patterns[11]);
        assert_eq!(
            ordinary.count_matching_lf_lines_value(&haystack, true),
            Ok(Some(3)),
        );
    }

    #[test]
    fn ordinary_route_receipt_matches_actual_scanner_and_lf_admission() {
        let one_below_threshold = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES
            .checked_sub(1)
            .expect("the positive LF threshold has a one-below boundary");
        let cases = [
            (
                broad_root_lf_threshold_boundary_patterns(one_below_threshold),
                true,
                false,
            ),
            (
                broad_root_512_lf_free_patterns(LF_SHORT_SEGMENT_MIN_PATTERN_BYTES),
                true,
                true,
            ),
            (
                broad_root_512_lf_free_patterns(LF_SHORT_SEGMENT_MIN_PATTERN_BYTES + 1),
                true,
                true,
            ),
            (broad_root_256x128_patterns(), true, false),
            (
                public_patterns(MAX_PATTERNS, MIN_PATTERN_BYTES),
                false,
                true,
            ),
        ];
        for (patterns, expected_prefilter_is_none, expected_lf_excluded) in cases {
            let width = patterns[0].len();
            let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
                .unwrap()
                .expect("the focused ordinary shape retains a compact owner")
                .into_ordinary();
            let scratch = vec![0_u8; width];
            let actual_scanner_eligible =
                CompactOrdinaryScanner::new(&plan.engine, &scratch, Window::full(&scratch))
                    .is_some();
            let expected_skip_enabled = expected_prefilter_is_none && expected_lf_excluded;
            assert_eq!(
                plan.construction_route_receipt(),
                LiteralSetCompactOrdinaryRouteReceipt {
                    schema_version: 3,
                    capability_id: "literal-set-compact-ordinary-route-v3",
                    engine_width_bytes: width,
                    automaton_min_pattern_bytes: width,
                    automaton_max_pattern_bytes: width,
                    automaton_match_kind_standard: true,
                    automaton_prefilter_is_none: expected_prefilter_is_none,
                    compact_ordinary_scanner_eligible: actual_scanner_eligible,
                    literals_exclude_lf: expected_lf_excluded,
                    lf_short_segment_min_pattern_bytes: LF_SHORT_SEGMENT_MIN_PATTERN_BYTES,
                    lf_segment_initial_probe_bytes: LF_SEGMENT_INITIAL_PROBE_BYTES,
                    lf_segment_refill_probe_bytes: LF_SEGMENT_REFILL_PROBE_BYTES,
                    lf_short_segment_skip_enabled: expected_skip_enabled,
                },
            );
            assert_eq!(actual_scanner_eligible, expected_prefilter_is_none);
        }

        let dual = compact(
            &broad_root_256x128_lf_free_patterns(),
            LiteralSetBuildLimits::default(),
        )
        .unwrap()
        .expect("the LF-free broad-root shape retains the dual compact owner");
        assert!(dual.engine.automaton.prefilter().is_none());
        assert!(
            !dual.engine.literals_exclude_lf,
            "R74 deliberately authenticates and enables only the ordinary-only owner",
        );
    }

    #[test]
    fn direct_scanner_skips_only_authenticated_short_lf_segments() {
        let width = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES.max(64);
        let mut patterns = broad_root_512_lf_free_patterns(width);
        patterns[17][width - 1] = b'\r';
        let canonical =
            LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the broad-root 512x64 set admits the compact ordinary owner")
            .into_ordinary();
        assert!(plan.engine.automaton.prefilter().is_none());
        let receipt = plan.construction_route_receipt();
        assert!(receipt.literals_exclude_lf);
        assert!(receipt.lf_short_segment_skip_enabled);
        assert_eq!(
            receipt.lf_segment_initial_probe_bytes,
            LF_SEGMENT_INITIAL_PROBE_BYTES,
        );

        let mut haystack = b"\n".to_vec();
        haystack.extend(core::iter::repeat_n(b'!', width - 1));
        haystack.push(b'\n');
        let first_start = haystack.len();
        haystack.extend_from_slice(&patterns[17]);
        let first_end = haystack.len();
        // The LF is exactly one width from `first_start`. Discovering it must
        // leave the CR-ending match immediately before it visible.
        haystack.extend_from_slice(b"\n\r\n");
        let second_start = haystack.len();
        haystack.extend_from_slice(&patterns[31]);
        let second_end = haystack.len();

        let ordinary = plan.ordinary_executor();
        compact_ordinary_scanner_probe::reset();
        let mut spans = Vec::new();
        assert_eq!(
            ordinary.try_visit_spans_window_value(&haystack, Window::full(&haystack), |span| {
                spans.push(span);
                Ok::<bool, ()>(true)
            },),
            Ok(Ok(())),
        );
        assert_eq!(
            spans,
            [(first_start, first_end), (second_start, second_end)]
        );
        assert_eq!(compact_ordinary_scanner_probe::binds(), 1);
        // The LF cached immediately after a hit is consumed directly, not
        // counted as another short-segment skip or delimiter discovery.
        assert_eq!(compact_ordinary_scanner_probe::short_lf_segment_skips(), 3);
        assert_eq!(compact_ordinary_scanner_probe::short_lf_probe_calls(), 5);
        assert!(
            compact_ordinary_scanner_probe::short_lf_probe_bytes()
                <= 5 * LF_SEGMENT_REFILL_PROBE_BYTES,
        );
        assert_eq!(
            ordinary.count_spans_window_value(&haystack, Window::full(&haystack)),
            Ok(2)
        );
        assert_eq!(
            ordinary.count_matching_lf_lines_value(&haystack, true),
            Ok(Some(2))
        );

        let mut stopped = 0;
        assert_eq!(
            ordinary.try_visit_spans_window_value(&haystack, Window::full(&haystack), |_| {
                stopped += 1;
                Ok::<bool, &'static str>(false)
            },),
            Ok(Ok(())),
        );
        assert_eq!(stopped, 1);
        assert_eq!(
            ordinary.try_visit_spans_window_value(&haystack, Window::full(&haystack), |_| Err::<
                bool,
                _,
            >(
                "short-LF callback"
            ),),
            Ok(Err("short-LF callback")),
        );

        for window in [
            Window::new(first_start, first_end),
            Window::new(first_start, first_end + 1),
            Window::new(first_start + 1, first_end + 1),
            Window::new(second_start, second_end),
            Window::new(1, second_end),
        ] {
            let expected = canonical
                .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                .unwrap()
                .0;
            assert_eq!(ordinary.find_window_value(&haystack, window), Ok(expected));
            assert_eq!(
                ordinary.selected_end_window_value(&haystack, window),
                Ok(expected.map(|(_, end)| end)),
            );
            assert_eq!(
                ordinary.exists_window_value(&haystack, window),
                Ok(expected.is_some())
            );
        }
    }

    #[test]
    fn direct_scanner_resumes_short_segment_probes_after_lf() {
        for width in [64, 65, 80, 96, 128] {
            let patterns = broad_root_512_lf_free_patterns(width);
            let canonical =
                LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
            let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
                .unwrap()
                .expect("broad-root LF-resumption fixture")
                .into_ordinary();
            let mut haystack = vec![b'!'; width + 17];
            haystack.push(b'\n');
            for _ in 0..3 {
                haystack.extend(core::iter::repeat_n(b'!', width - 1));
                haystack.push(b'\n');
            }
            let ordinary = plan.ordinary_executor();
            compact_ordinary_scanner_probe::reset();
            assert_eq!(
                ordinary.find_window_value(&haystack, Window::full(&haystack)),
                Ok(None),
            );
            assert_eq!(compact_ordinary_scanner_probe::short_lf_segment_skips(), 3);

            let first_start = haystack.len();
            haystack.extend_from_slice(&patterns[17]);
            let first_end = haystack.len();
            // A partial literal before LF must never combine with a suffix
            // after LF, even when the preceding record is too long to skip.
            haystack.extend_from_slice(&patterns[31][..width - 1]);
            haystack.push(b'\n');
            haystack.extend_from_slice(&patterns[31][width - 1..]);
            haystack.push(b'\n');
            let second_start = haystack.len();
            haystack.extend_from_slice(&patterns[63]);
            let second_end = haystack.len();
            haystack.extend_from_slice(b"\n!\n");
            let window = Window::full(&haystack);
            let mut spans = Vec::new();
            assert_eq!(
                ordinary.try_visit_spans_window_value(&haystack, window, |span| {
                    spans.push(span);
                    Ok::<bool, ()>(true)
                }),
                Ok(Ok(())),
            );
            assert_eq!(
                spans,
                [(first_start, first_end), (second_start, second_end)]
            );
            assert_eq!(ordinary.count_spans_window_value(&haystack, window), Ok(2));
            assert_eq!(
                ordinary.count_matching_lf_lines_value(&haystack, true),
                Ok(Some(2))
            );
            for start in [0, 1, width, first_start, first_start + 1, first_end] {
                for end in [first_end, second_start, second_end, haystack.len()] {
                    if start > end {
                        continue;
                    }
                    let bounded = Window::new(start, end);
                    let expected = canonical
                        .find_window(&haystack, bounded, LiteralSetSearchLimits::unlimited())
                        .unwrap()
                        .0;
                    assert_eq!(ordinary.find_window_value(&haystack, bounded), Ok(expected));
                    assert_eq!(
                        ordinary.exists_window_value(&haystack, bounded),
                        Ok(expected.is_some())
                    );
                    assert_eq!(
                        ordinary.selected_end_window_value(&haystack, bounded),
                        Ok(expected.map(|(_, end)| end))
                    );
                }
            }
        }
    }

    #[test]
    fn active_lf_route_matches_canonical_for_every_small_window_and_projection() {
        let width = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES.max(64);
        let mut patterns = broad_root_256_lf_free_patterns(width);
        patterns[17][width - 1] = b'\r';
        patterns[255] = patterns[17].clone();
        let canonical =
            LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the all-window fixture admits the compact ordinary owner")
            .into_ordinary();
        let receipt = plan.construction_route_receipt();
        assert!(receipt.automaton_prefilter_is_none);
        assert!(receipt.lf_short_segment_skip_enabled);
        let ordinary = plan.ordinary_executor();

        let mut haystack = b"\nxy\r\n".to_vec();
        let matched_start = haystack.len();
        haystack.extend_from_slice(&patterns[17]);
        let matched_end = haystack.len();
        haystack.extend_from_slice(b"\nq\r\n");
        assert_eq!(
            ordinary.count_matching_lf_lines_value(&haystack, true),
            Ok(Some(1)),
        );

        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let window = Window::new(start, end);
                let expected = canonical
                    .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0;
                let expected_spans = if start <= matched_start && matched_end <= end {
                    vec![(matched_start, matched_end)]
                } else {
                    Vec::new()
                };
                assert_eq!(
                    expected,
                    expected_spans.first().copied(),
                    "window={window:?}"
                );
                assert_eq!(
                    ordinary.find_window_value(&haystack, window),
                    Ok(expected),
                    "find window={window:?}",
                );
                assert_eq!(
                    ordinary.selected_end_window_value(&haystack, window),
                    Ok(expected.map(|(_, accepted_end)| accepted_end)),
                    "end window={window:?}",
                );
                assert_eq!(
                    ordinary.exists_window_value(&haystack, window),
                    Ok(expected.is_some()),
                    "exists window={window:?}",
                );
                assert_eq!(
                    ordinary.count_spans_window_value(&haystack, window),
                    Ok(u64::try_from(expected_spans.len()).unwrap()),
                    "count window={window:?}",
                );
                let mut actual_spans = Vec::new();
                assert_eq!(
                    ordinary.try_visit_spans_window_value(&haystack, window, |span| {
                        actual_spans.push(span);
                        Ok::<bool, ()>(true)
                    },),
                    Ok(Ok(())),
                    "visit window={window:?}",
                );
                assert_eq!(actual_spans, expected_spans, "spans window={window:?}");
            }
        }
    }

    #[test]
    fn seeded_active_lf_route_matches_canonical_across_widths_and_windows() {
        fn next(seed: &mut u64) -> u64 {
            *seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *seed
        }

        fn below(seed: &mut u64, upper: usize) -> usize {
            usize::try_from(next(seed) % u64::try_from(upper).unwrap()).unwrap()
        }

        let active_width = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES.max(64);
        let widths = [active_width, active_width + 1, active_width + 64];
        let mut seed = 0x74a0_1f5e_9d3c_27b1_u64;
        for width in widths {
            let mut patterns = broad_root_256_lf_free_patterns(width);
            patterns[31][width - 1] = b'\r';
            patterns[255] = patterns[31].clone();
            let canonical_plan =
                LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
            let canonical = canonical_plan
                .ordinary_executor()
                .expect("the seeded canonical plan binds ordinary search");
            let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
                .unwrap()
                .expect("the seeded LF-rich fixture admits the compact ordinary owner")
                .into_ordinary();
            assert!(
                plan.construction_route_receipt()
                    .lf_short_segment_skip_enabled
            );
            let ordinary = plan.ordinary_executor();

            for case in 0_usize..64 {
                let len = below(&mut seed, width * 4 + 33);
                let mut haystack = (0..len)
                    .map(|_| match next(&mut seed) % 12 {
                        0 | 1 => b'\n',
                        2 => b'\r',
                        value => b'A' + u8::try_from(value - 3).unwrap(),
                    })
                    .collect::<Vec<_>>();
                if len >= width {
                    for injection in 0..=(case % 3) {
                        let pattern_index =
                            (below(&mut seed, patterns.len()) + injection * 31) % patterns.len();
                        let at = below(&mut seed, len - width + 1);
                        haystack[at..at + width].copy_from_slice(&patterns[pattern_index]);
                    }
                }
                let window = if case % 4 == 0 {
                    Window::full(&haystack)
                } else {
                    let start = below(&mut seed, len + 1);
                    let end = start + below(&mut seed, len - start + 1);
                    Window::new(start, end)
                };

                assert_eq!(
                    ordinary.find_window_value(&haystack, window),
                    canonical.find_window_value(&haystack, window),
                    "find width={width}, case={case}, window={window:?}",
                );
                assert_eq!(
                    ordinary.exists_window_value(&haystack, window),
                    canonical.exists_window_value(&haystack, window),
                    "exists width={width}, case={case}, window={window:?}",
                );
                assert_eq!(
                    ordinary.selected_end_window_value(&haystack, window),
                    canonical.selected_end_window_value(&haystack, window),
                    "end width={width}, case={case}, window={window:?}",
                );
                assert_eq!(
                    ordinary.count_spans_window_value(&haystack, window),
                    canonical.count_spans_window_value(&haystack, window),
                    "count width={width}, case={case}, window={window:?}",
                );

                // Count matching LF-delimited lines through an independent
                // line-window oracle. This projection alone advances the
                // compact scanner cursor directly after one acceptance, so it
                // must begin its next search at that cursor with fresh state.
                let mut expected_matching_lines = 0_u64;
                let mut line_start = 0_usize;
                loop {
                    let relative_lf = haystack[line_start..]
                        .iter()
                        .position(|&byte| byte == b'\n');
                    let line_end =
                        relative_lf.map_or(haystack.len(), |relative| line_start + relative);
                    if canonical
                        .find_window_value(&haystack, Window::new(line_start, line_end))
                        .unwrap()
                        .is_some()
                    {
                        expected_matching_lines += 1;
                    }
                    let Some(_) = relative_lf else {
                        break;
                    };
                    line_start = line_end + 1;
                }
                assert_eq!(
                    ordinary.count_matching_lf_lines_value(&haystack, true),
                    Ok(Some(expected_matching_lines)),
                    "matching LF lines width={width}, case={case}",
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
                    "spans width={width}, case={case}, window={window:?}",
                );
            }
        }
    }

    #[test]
    fn lf_probe_boundaries_match_the_canonical_dfa() {
        let active_width = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES.max(64);
        for width in [active_width, active_width + 1, active_width + 64] {
            let patterns = broad_root_512_lf_free_patterns(width);
            let canonical =
                LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
            let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
                .unwrap()
                .expect("the boundary fixture admits the compact ordinary owner")
                .into_ordinary();
            assert!(
                plan.construction_route_receipt()
                    .lf_short_segment_skip_enabled
            );
            let ordinary = plan.ordinary_executor();
            let mut offsets = vec![
                0,
                width - 1,
                width,
                width + 1,
                63,
                64,
                65,
                LF_SEGMENT_INITIAL_PROBE_BYTES - 1,
                LF_SEGMENT_INITIAL_PROBE_BYTES,
                LF_SEGMENT_INITIAL_PROBE_BYTES + 1,
                LF_SEGMENT_INITIAL_PROBE_BYTES + LF_SEGMENT_REFILL_PROBE_BYTES - 1,
                LF_SEGMENT_INITIAL_PROBE_BYTES + LF_SEGMENT_REFILL_PROBE_BYTES,
                LF_SEGMENT_INITIAL_PROBE_BYTES + LF_SEGMENT_REFILL_PROBE_BYTES + 1,
            ];
            offsets.sort_unstable();
            offsets.dedup();
            for lf_offset in offsets {
                let mut haystack = vec![b'!'; lf_offset];
                haystack.push(b'\n');
                haystack.extend(core::iter::repeat_n(b'!', width + 2));
                let window = Window::full(&haystack);
                let expected = canonical
                    .find_window(&haystack, window, LiteralSetSearchLimits::unlimited())
                    .unwrap()
                    .0;
                compact_ordinary_scanner_probe::reset();
                assert_eq!(ordinary.find_window_value(&haystack, window), Ok(expected));
                let expected_skip =
                    usize::from(lf_offset < width && lf_offset < LF_SEGMENT_INITIAL_PROBE_BYTES);
                assert_eq!(
                    compact_ordinary_scanner_probe::short_lf_segment_skips(),
                    expected_skip,
                    "width={width}, lf_offset={lf_offset}",
                );
                assert!(compact_ordinary_scanner_probe::short_lf_probe_calls() >= 1);
                assert!(
                    compact_ordinary_scanner_probe::short_lf_probe_bytes()
                        <= compact_ordinary_scanner_probe::short_lf_probe_calls()
                            * LF_SEGMENT_REFILL_PROBE_BYTES,
                );
            }
        }
    }

    #[test]
    fn any_lf_consuming_literal_disables_short_segment_probing() {
        let width = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES.max(64);
        for lf_index in [0, width / 2, width - 1] {
            let mut patterns = broad_root_512_lf_free_patterns(width);
            patterns[0][lf_index] = b'\n';
            let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
                .unwrap()
                .expect("the LF-containing set retains the compact ordinary owner")
                .into_ordinary();
            let receipt = plan.construction_route_receipt();
            assert!(receipt.compact_ordinary_scanner_eligible);
            assert!(!receipt.literals_exclude_lf);
            assert!(!receipt.lf_short_segment_skip_enabled);
            assert_eq!(
                receipt.lf_segment_initial_probe_bytes,
                LF_SEGMENT_INITIAL_PROBE_BYTES
            );
            assert_eq!(
                receipt.lf_segment_refill_probe_bytes,
                LF_SEGMENT_REFILL_PROBE_BYTES
            );

            compact_ordinary_scanner_probe::reset();
            let ordinary = plan.ordinary_executor();
            assert_eq!(
                ordinary.find_window_value(&patterns[0], Window::full(&patterns[0])),
                Ok(Some((0, width))),
                "LF index {lf_index}",
            );
            assert_eq!(
                ordinary.count_spans_window_value(&patterns[0], Window::full(&patterns[0])),
                Ok(1),
            );
            assert_eq!(compact_ordinary_scanner_probe::short_lf_probe_calls(), 0);
            assert_eq!(compact_ordinary_scanner_probe::short_lf_probe_bytes(), 0);
            assert_eq!(compact_ordinary_scanner_probe::short_lf_segment_skips(), 0);
        }
    }

    #[test]
    fn poisoned_lf_authentication_is_detected_by_the_oracle() {
        let width = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES;
        let mut patterns = broad_root_512_lf_free_patterns(width);
        patterns[0][width / 2] = b'\n';
        let mut plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the poisoned fixture retains the compact ordinary owner")
            .into_ordinary();
        let haystack = &patterns[0];
        let window = Window::full(haystack);
        let canonical =
            LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let expected = canonical
            .find_window(haystack, window, LiteralSetSearchLimits::unlimited())
            .unwrap()
            .0;
        assert_eq!(expected, Some((0, width)));
        assert_eq!(
            plan.ordinary_executor().find_window_value(haystack, window),
            Ok(expected)
        );
        assert!(!plan.engine.literals_exclude_lf);

        // An intentionally false construction fact must make this fixture
        // disagree with the independent DFA; otherwise the negative control
        // cannot detect an unsound LF census.
        plan.engine.literals_exclude_lf = true;
        compact_ordinary_scanner_probe::reset();
        assert_eq!(
            plan.ordinary_executor().find_window_value(haystack, window),
            Ok(None)
        );
        assert_eq!(compact_ordinary_scanner_probe::short_lf_segment_skips(), 1);
    }

    #[test]
    fn lf_at_and_outside_window_end_preserves_exact_width_matches() {
        for width in [64, 65, 128] {
            let patterns = broad_root_512_lf_free_patterns(width);
            let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
                .unwrap()
                .expect("the window-end fixture admits the compact ordinary owner")
                .into_ordinary();
            let mut haystack = b"!\n".to_vec();
            let start = haystack.len();
            haystack.extend_from_slice(&patterns[17]);
            let end = haystack.len();
            haystack.push(b'\n');

            for window_end in [end, end + 1] {
                compact_ordinary_scanner_probe::reset();
                let mut scanner = CompactOrdinaryScanner::new(
                    &plan.engine,
                    &haystack,
                    Window::new(start, window_end),
                )
                .unwrap();
                assert_eq!(scanner.next_span(), Some((start, end)));
                assert_eq!(compact_ordinary_scanner_probe::short_lf_segment_skips(), 0);
                assert_eq!(scanner.next_end(), None);
                let probes = compact_ordinary_scanner_probe::short_lf_probe_calls();
                assert_eq!(scanner.next_end(), None);
                assert_eq!(
                    compact_ordinary_scanner_probe::short_lf_probe_calls(),
                    probes
                );
            }

            // LF immediately outside a short window must not be read even
            // when the probe cap exceeds the remaining source.
            let short = b"!\n";
            compact_ordinary_scanner_probe::reset();
            let mut scanner =
                CompactOrdinaryScanner::new(&plan.engine, short, Window::new(0, 1)).unwrap();
            assert_eq!(scanner.next_end(), None);
            assert_eq!(compact_ordinary_scanner_probe::short_lf_probe_bytes(), 1);
            assert_eq!(compact_ordinary_scanner_probe::short_lf_segment_skips(), 0);

            let mut short_record = patterns[17][..width - 1].to_vec();
            short_record.push(b'\n');
            assert_eq!(
                plan.ordinary_executor()
                    .find_window_value(&short_record, Window::full(&short_record),),
                Ok(None)
            );
        }
    }

    #[test]
    fn no_lf_discovery_is_bounded_and_does_not_reprobe_scanned_bytes() {
        let width = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES.max(64);
        let patterns = broad_root_512_lf_free_patterns(width);
        let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the no-LF fixture admits the compact ordinary owner")
            .into_ordinary();
        let haystack = vec![b'!'; 4_096];
        compact_ordinary_scanner_probe::reset();
        assert_eq!(
            plan.ordinary_executor()
                .find_window_value(&haystack, Window::full(&haystack)),
            Ok(None),
        );
        assert_eq!(compact_ordinary_scanner_probe::short_lf_probe_calls(), 2);
        assert_eq!(
            compact_ordinary_scanner_probe::short_lf_probe_bytes(),
            haystack.len(),
        );
        assert_eq!(compact_ordinary_scanner_probe::short_lf_segment_skips(), 0);

        let mut exhausted =
            CompactOrdinaryScanner::new(&plan.engine, &haystack, Window::full(&haystack))
                .expect("the active no-LF fixture binds the direct scanner");
        compact_ordinary_scanner_probe::reset();
        assert_eq!(exhausted.next_end(), None);
        assert_eq!(exhausted.at, exhausted.window_end);
        let probe_calls_after_exhaustion = compact_ordinary_scanner_probe::short_lf_probe_calls();
        assert_eq!(exhausted.next_end(), None);
        assert_eq!(exhausted.at, exhausted.window_end);
        assert_eq!(
            compact_ordinary_scanner_probe::short_lf_probe_calls(),
            probe_calls_after_exhaustion,
            "a fused exhausted scanner must not re-probe",
        );

        let one_below_threshold = LF_SHORT_SEGMENT_MIN_PATTERN_BYTES
            .checked_sub(1)
            .expect("the positive LF threshold has a one-below boundary");
        let narrow_patterns = broad_root_lf_threshold_boundary_patterns(one_below_threshold);
        let narrow = ordinary_candidate(&narrow_patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the one-below-threshold control retains the compact ordinary owner")
            .into_ordinary();
        assert!(
            !narrow
                .construction_route_receipt()
                .lf_short_segment_skip_enabled
        );
        compact_ordinary_scanner_probe::reset();
        assert_eq!(
            narrow
                .ordinary_executor()
                .find_window_value(&haystack, Window::full(&haystack)),
            Ok(None),
        );
        assert_eq!(compact_ordinary_scanner_probe::short_lf_probe_calls(), 0);
        assert_eq!(compact_ordinary_scanner_probe::short_lf_probe_bytes(), 0);
    }

    fn assert_delimiter_block_projections(
        plan: &LiteralSetCompactOrdinaryPlan,
        canonical: &LiteralSetPlan,
        haystack: &[u8],
        window: Window,
        expected_spans: &[(usize, usize)],
    ) {
        let ordinary = plan.ordinary_executor();
        let oracle = canonical
            .ordinary_executor()
            .expect("canonical ordinary executor");
        let first = expected_spans.first().copied();
        let count = u64::try_from(expected_spans.len()).unwrap();
        assert_eq!(oracle.find_window_value(haystack, window), Ok(first));
        assert_eq!(oracle.count_spans_window_value(haystack, window), Ok(count));
        assert_eq!(
            oracle.exists_window_value(haystack, window),
            Ok(first.is_some())
        );
        assert_eq!(ordinary.find_window_value(haystack, window), Ok(first));
        assert_eq!(
            ordinary.selected_end_window_value(haystack, window),
            Ok(first.map(|(_, end)| end))
        );
        assert_eq!(
            ordinary.count_spans_window_value(haystack, window),
            Ok(count)
        );
        assert_eq!(
            ordinary.exists_window_value(haystack, window),
            Ok(first.is_some())
        );
        let mut actual = Vec::new();
        assert_eq!(
            ordinary.try_visit_spans_window_value(haystack, window, |span| {
                actual.push(span);
                Ok::<bool, ()>(true)
            }),
            Ok(Ok(()))
        );
        assert_eq!(actual.as_slice(), expected_spans);
    }

    #[test]
    fn delimiter_blocks_preserve_matches_crossing_initial_and_refill_edges() {
        for width in [64, 65, 128, 320] {
            let patterns = broad_root_256_lf_free_patterns(width);
            let canonical =
                LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
            let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
                .unwrap()
                .expect("block-crossing ordinary fixture")
                .into_ordinary();
            assert!(
                plan.construction_route_receipt()
                    .lf_short_segment_skip_enabled
            );
            for window_start in [0, 7] {
                for edge in [
                    LF_SEGMENT_INITIAL_PROBE_BYTES,
                    LF_SEGMENT_INITIAL_PROBE_BYTES + LF_SEGMENT_REFILL_PROBE_BYTES,
                ] {
                    // Half the literal lies on either side of a discovery
                    // boundary. A fresh root there would lose the match.
                    let start = window_start + edge - width / 2;
                    let end = start + width;
                    let mut haystack = vec![b'!'; start];
                    haystack.extend_from_slice(&patterns[17]);
                    haystack.extend(core::iter::repeat_n(b'!', width + 17));
                    let window = Window::new(window_start, haystack.len());
                    compact_ordinary_scanner_probe::reset();
                    let mut scanner =
                        CompactOrdinaryScanner::new(&plan.engine, &haystack, window).unwrap();
                    assert_eq!(
                        scanner.next_span(),
                        Some((start, end)),
                        "width={width}, edge={edge}, base={window_start}"
                    );
                    assert_eq!(
                        compact_ordinary_scanner_probe::short_lf_probe_calls(),
                        if edge == LF_SEGMENT_INITIAL_PROBE_BYTES {
                            2
                        } else {
                            3
                        }
                    );
                    assert_eq!(scanner.next_end(), None);
                    assert_delimiter_block_projections(
                        &plan,
                        &canonical,
                        &haystack,
                        window,
                        &[(start, end)],
                    );
                    assert_delimiter_block_projections(
                        &plan,
                        &canonical,
                        &haystack,
                        Window::new(window_start, end - 1),
                        &[],
                    );
                    assert_delimiter_block_projections(
                        &plan,
                        &canonical,
                        &haystack,
                        Window::new(start + 1, haystack.len()),
                        &[],
                    );
                }
            }
        }
    }

    #[test]
    fn delimiter_cache_reuses_discovery_across_many_nonoverlapping_hits() {
        for width in [64, 65, 128, 320] {
            let patterns = broad_root_256_lf_free_patterns(width);
            let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
                .unwrap()
                .expect("cached-hit ordinary fixture")
                .into_ordinary();
            let hits = 96;
            let haystack = patterns[17].repeat(hits);
            compact_ordinary_scanner_probe::reset();
            let mut scanner =
                CompactOrdinaryScanner::new(&plan.engine, &haystack, Window::full(&haystack))
                    .unwrap();
            for index in 0..hits {
                assert_eq!(
                    scanner.next_span(),
                    Some((index * width, (index + 1) * width))
                );
                if index == 0 && width <= LF_SEGMENT_INITIAL_PROBE_BYTES {
                    assert_eq!(compact_ordinary_scanner_probe::short_lf_probe_calls(), 1);
                    assert_eq!(
                        compact_ordinary_scanner_probe::short_lf_probe_bytes(),
                        LF_SEGMENT_INITIAL_PROBE_BYTES,
                        "an early hit must not trigger refill-sized lookahead"
                    );
                }
            }
            assert_eq!(scanner.next_end(), None);
            let calls = compact_ordinary_scanner_probe::short_lf_probe_calls();
            assert!(calls <= haystack.len().div_ceil(LF_SEGMENT_INITIAL_PROBE_BYTES));
            assert_eq!(
                compact_ordinary_scanner_probe::short_lf_probe_bytes(),
                haystack.len(),
                "no-LF discovery slices must partition the corpus, not repeatedly search hit suffixes"
            );
            assert_eq!(compact_ordinary_scanner_probe::short_lf_segment_skips(), 0);
            assert_eq!(scanner.next_end(), None);
            assert_eq!(
                compact_ordinary_scanner_probe::short_lf_probe_calls(),
                calls
            );
            assert_eq!(
                plan.ordinary_executor()
                    .count_spans_window_value(&haystack, Window::full(&haystack)),
                Ok(hits as u64)
            );
        }
    }

    #[test]
    fn actual_lf_at_discovery_and_window_edges_consumes_only_the_delimiter() {
        for width in [64, 65, 128, 320] {
            let patterns = broad_root_256_lf_free_patterns(width);
            let canonical =
                LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
            let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
                .unwrap()
                .expect("delimiter-edge ordinary fixture")
                .into_ordinary();
            for edge in [
                LF_SEGMENT_INITIAL_PROBE_BYTES,
                LF_SEGMENT_INITIAL_PROBE_BYTES + LF_SEGMENT_REFILL_PROBE_BYTES,
            ] {
                for lf_offset in [edge - 1, edge, edge + 1] {
                    let mut haystack = vec![b'!'; lf_offset];
                    haystack.push(b'\n');
                    let start = haystack.len();
                    haystack.extend_from_slice(&patterns[17]);
                    let end = haystack.len();
                    haystack.push(b'\n');
                    for window_end in [lf_offset, lf_offset + 1, end - 1, end, end + 1] {
                        let expected = if window_end >= end {
                            vec![(start, end)]
                        } else {
                            Vec::new()
                        };
                        assert_delimiter_block_projections(
                            &plan,
                            &canonical,
                            &haystack,
                            Window::new(0, window_end),
                            &expected,
                        );
                    }
                    assert_delimiter_block_projections(
                        &plan,
                        &canonical,
                        &haystack,
                        Window::new(lf_offset, end + 1),
                        &[(start, end)],
                    );

                    // Carry a genuine partial literal into the LF boundary.
                    // A delimiter must reset it, unlike a no-LF block end.
                    let prefix = (width - 1).min(lf_offset);
                    let mut split = vec![b'!'; lf_offset - prefix];
                    split.extend_from_slice(&patterns[17][..prefix]);
                    split.push(b'\n');
                    split.extend_from_slice(&patterns[17][prefix..]);
                    split.push(b'!');
                    let valid_start = split.len();
                    split.extend_from_slice(&patterns[31]);
                    assert_delimiter_block_projections(
                        &plan,
                        &canonical,
                        &split,
                        Window::full(&split),
                        &[(valid_start, valid_start + width)],
                    );
                }
            }
        }
    }

    #[test]
    fn matching_line_cursor_jumps_invalidate_cached_lf_and_block_ends() {
        for width in [64, 65, 128, 320] {
            let patterns = broad_root_256_lf_free_patterns(width);
            let canonical =
                LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
            let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
                .unwrap()
                .expect("external-cursor ordinary fixture")
                .into_ordinary();
            for long_line in [false, true] {
                let first_line_len = if long_line {
                    LF_SEGMENT_INITIAL_PROBE_BYTES + LF_SEGMENT_REFILL_PROBE_BYTES + width + 17
                } else {
                    width + 17
                };
                let mut haystack = patterns[17].clone();
                haystack.resize(first_line_len, b'!');
                haystack.push(b'\n');
                let second_start = haystack.len();
                haystack.extend_from_slice(&patterns[31]);
                haystack.extend_from_slice(&patterns[63]);
                haystack.extend_from_slice(b"\n!\n");
                let third_start = haystack.len();
                haystack.extend_from_slice(&patterns[127]);
                let window = Window::full(&haystack);
                let mut scanner =
                    CompactOrdinaryScanner::new(&plan.engine, &haystack, window).unwrap();
                assert_eq!(scanner.next_span(), Some((0, width)));
                assert_eq!(scanner.segment_ends_at_lf, !long_line);
                assert!(scanner.segment_end < second_start);
                // This is the exact external cursor advance used by the
                // matching-line reducer. Consuming a stale cached LF here
                // would drop the first byte of the next valid match.
                scanner.at = second_start;
                assert_eq!(
                    scanner.next_span(),
                    Some((second_start, second_start + width))
                );
                let expected = [
                    (0, width),
                    (second_start, second_start + width),
                    (second_start + width, second_start + 2 * width),
                    (third_start, third_start + width),
                ];
                assert_delimiter_block_projections(&plan, &canonical, &haystack, window, &expected);
                assert_eq!(
                    plan.ordinary_executor()
                        .count_matching_lf_lines_value(&haystack, true),
                    Ok(Some(3))
                );
            }
        }
    }

    #[test]
    fn delimiter_blocks_skip_short_records_above_the_old_sixty_four_byte_cap() {
        for width in [65, 80, 96, 128] {
            let patterns = broad_root_256_lf_free_patterns(width);
            let canonical =
                LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
            let plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
                .unwrap()
                .expect("wide short-record ordinary fixture")
                .into_ordinary();
            let records = 12;
            let mut record = vec![b'!'; width - 1];
            record.push(b'\n');
            let mut haystack = record.repeat(records);
            // An unterminated short suffix must not be mislabelled as an LF
            // skip, even though it also cannot contain a complete match.
            haystack.extend_from_slice(&patterns[17][..width - 1]);
            let window = Window::full(&haystack);
            compact_ordinary_scanner_probe::reset();
            assert_eq!(
                plan.ordinary_executor()
                    .count_spans_window_value(&haystack, window),
                Ok(0)
            );
            assert_eq!(
                compact_ordinary_scanner_probe::short_lf_segment_skips(),
                records
            );
            assert_delimiter_block_projections(&plan, &canonical, &haystack, window, &[]);
        }
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
    fn wider_ordinary_admission_leaves_dual_policy_and_resource_boundaries_unchanged() {
        let admitted = public_patterns(1_024, 19);
        let borrowed = admitted.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert!(matches!(
            compact_preflight(&borrowed, LiteralSetBuildLimits::default()).unwrap(),
            CompactPreflight::NotApplicable,
        ));
        assert!(matches!(
            compact_ordinary_preflight(&borrowed, LiteralSetBuildLimits::default()).unwrap(),
            CompactPreflight::Eligible { .. },
        ));

        let below_work = public_patterns(512, 19);
        let borrowed = below_work.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert!(matches!(
            compact_ordinary_preflight(&borrowed, LiteralSetBuildLimits::default()).unwrap(),
            CompactPreflight::Canonical(_),
        ));

        let resource_refused = public_patterns(4_096, 19);
        let borrowed = resource_refused
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        assert!(matches!(
            compact_ordinary_preflight(&borrowed, LiteralSetBuildLimits::default()).unwrap(),
            CompactPreflight::Canonical(_),
        ));

        let over_cardinality = public_patterns(4_097, 19);
        let borrowed = over_cardinality
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        assert!(matches!(
            compact_ordinary_preflight(&borrowed, LiteralSetBuildLimits::default()).unwrap(),
            CompactPreflight::NotApplicable,
        ));
    }

    #[test]
    fn wider_ordinary_owner_matches_canonical_windows_and_callback_control() {
        let patterns = public_patterns(1_024, 19);
        let canonical =
            LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let canonical = canonical
            .ordinary_executor()
            .expect("the uniform canonical DFA binds ordinary search");
        let ordinary_plan = ordinary_candidate(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .expect("the wider ordinary policy admits 1024x19")
            .into_ordinary();
        let ordinary = ordinary_plan.ordinary_executor();

        let mut haystack = vec![0xff, b'x'];
        haystack.extend_from_slice(&patterns[0]);
        haystack.push(0x80);
        haystack.extend_from_slice(&patterns[1_023]);
        haystack.extend_from_slice(&patterns[17]);
        haystack.extend_from_slice(b"public000");
        haystack.push(0xfe);

        for start in 0..=haystack.len() {
            for end in start..=haystack.len() {
                let window = Window::new(start, end);
                assert_eq!(
                    ordinary.find_window_value(&haystack, window),
                    canonical.find_window_value(&haystack, window),
                    "find window={window:?}",
                );
                assert_eq!(
                    ordinary.exists_window_value(&haystack, window),
                    canonical.exists_window_value(&haystack, window),
                    "exists window={window:?}",
                );
                assert_eq!(
                    ordinary.count_spans_window_value(&haystack, window),
                    canonical.count_spans_window_value(&haystack, window),
                    "count window={window:?}",
                );
                let mut expected = Vec::new();
                canonical
                    .try_visit_spans_window_value(&haystack, window, |span| {
                        expected.push(span);
                        Ok::<bool, ()>(true)
                    })
                    .unwrap()
                    .unwrap();
                let mut actual = Vec::new();
                ordinary
                    .try_visit_spans_window_value(&haystack, window, |span| {
                        actual.push(span);
                        Ok::<bool, ()>(true)
                    })
                    .unwrap()
                    .unwrap();
                assert_eq!(actual, expected, "spans window={window:?}");
            }
        }

        let full = Window::full(&haystack);
        let mut stopped = 0;
        assert_eq!(
            ordinary.try_visit_spans_window_value(&haystack, full, |_| {
                stopped += 1;
                Ok::<bool, &'static str>(false)
            }),
            Ok(Ok(())),
        );
        assert_eq!(stopped, 1);
        assert_eq!(
            ordinary.try_visit_spans_window_value(&haystack, full, |_| {
                Err::<bool, _>("wide callback")
            }),
            Ok(Err("wide callback")),
        );
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
        let direct =
            CompactOrdinaryScanner::new(ordinary.engine, &haystack, Window::full(&haystack))
                .expect("the no-prefilter compact NFA admits direct scanning");
        assert!(direct.automaton.is_start(direct.start_state));
        assert!(!direct.automaton.is_special(direct.start_state));
        compact_ordinary_scanner_probe::reset();
        assert_eq!(
            ordinary.selected_end_window_value(&haystack, Window::full(&haystack)),
            Ok(Some(1 + MIN_PATTERN_BYTES)),
            "the impossible root byte must leave the unanchored scanner at start",
        );
        assert_eq!(
            compact_ordinary_scanner_probe::binds(),
            1,
            "selected endpoints use one whole-window direct reduction",
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
            16,
            "each nonempty find, endpoint and exists window uses one direct reduction",
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
        assert_eq!(compact_ordinary_scanner_probe::binds(), 17);
        assert_eq!(ordinary.count_spans_window_value(&haystack, window), Ok(2));
        assert_eq!(compact_ordinary_scanner_probe::binds(), 18);
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
            dual.build_accounting().build_work_upper_bound + canonical_build.pattern_bytes,
            "the ordinary-only owner charges its complete LF census exactly once",
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
            text_plan
                .ordinary_executor()
                .find_window_value(haystack, Window::new(0, haystack.len()),),
            byte_plan
                .ordinary_executor()
                .find_window_value(haystack, Window::new(0, haystack.len()),),
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

        let below_work = public_patterns(129, 125);
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
            CompactOrdinaryScanner::new(ordinary.engine, haystack, Window::full(haystack))
                .is_none()
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
        assert_eq!(ordinary.exists_window_value(haystack, full), Ok(true));
        assert_eq!(
            ordinary.selected_end_window_value(haystack, full),
            Ok(Some(haystack.len())),
        );
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

    #[test]
    fn prefiltered_tail_spans_keep_absolute_nonzero_windows_and_callback_control() {
        let patterns = public_patterns(MAX_PATTERNS, MIN_PATTERN_BYTES);
        let compact = compact(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .unwrap();
        let ordinary = compact.ordinary_executor();

        let mut haystack = vec![b'x'];
        let start = haystack.len();
        haystack.extend_from_slice(&patterns[3]);
        let adjacent = haystack.len();
        haystack.extend_from_slice(&patterns[7]);
        let end = haystack.len();
        haystack.push(b'x');
        let window = Window::new(start, end);
        let expected = [(start, adjacent), (adjacent, end)];

        assert!(ordinary.engine.automaton.prefilter().is_some());
        assert!(CompactOrdinaryScanner::new(ordinary.engine, &haystack, window).is_none());
        assert_eq!(
            ordinary.find_window_value(&haystack, window),
            Ok(Some(expected[0]))
        );
        assert_eq!(ordinary.count_spans_window_value(&haystack, window), Ok(2));

        let mut spans = Vec::new();
        assert_eq!(
            ordinary.try_visit_spans_window_value(&haystack, window, |span| {
                spans.push(span);
                Ok::<bool, &'static str>(true)
            }),
            Ok(Ok(())),
        );
        assert_eq!(spans, expected);

        let mut stop_calls = 0;
        assert_eq!(
            ordinary.try_visit_spans_window_value(&haystack, window, |span| {
                stop_calls += 1;
                assert_eq!(span, expected[0]);
                Ok::<bool, &'static str>(false)
            }),
            Ok(Ok(())),
        );
        assert_eq!(stop_calls, 1);

        let mut error_calls = 0;
        assert_eq!(
            ordinary.try_visit_spans_window_value(&haystack, window, |span| {
                error_calls += 1;
                assert_eq!(span, expected[0]);
                Err::<bool, _>("callback")
            }),
            Ok(Err("callback")),
        );
        assert_eq!(error_calls, 1);
    }
}
