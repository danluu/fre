//! Contained contiguous-NFA owner for one authenticated literal-set shape.
//!
//! The public and generic literal-set surface remains in `literal_set`. This
//! module supplies only the outlined compact arm selected by the ripgrep
//! stable-borrowed handoff, using aho-corasick's pinned `Automaton` search
//! implementation rather than another scanner.

use aho_corasick::automaton::Automaton;
use aho_corasick::dfa::DFA;
use aho_corasick::nfa::contiguous::NFA;
use aho_corasick::nfa::noncontiguous;
use aho_corasick::{Input, MatchKind};

use crate::Window;
use crate::literal_set::{
    ALPHABET_LEN, BYTES_PER_DFA_CELL_ENVELOPE, BYTES_PER_TRIE_STATE_ENVELOPE, LiteralSetAccounting,
    LiteralSetBuildAccounting, LiteralSetBuildLimits, LiteralSetError, LiteralSetMatchSemantics,
    LiteralSetPlan, LiteralSetSearchLimits, preflight, validate_window,
};

const MIN_PATTERNS: usize = 129;
const MAX_PATTERNS: usize = 256;
const MIN_PATTERN_BYTES: usize = 128;
const MIN_DENSE_BUILD_WORK: usize = 8 * 1024 * 1024;
const MAX_DENSE_DEPTH: usize = 24;

/// Compact contiguous-NFA owner for one authenticated flat literal set.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct LiteralSetCompactPlan {
    canonical: LiteralSetPlan,
    automaton: NFA,
    build: LiteralSetBuildAccounting,
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

fn canonical_outcome(
    patterns: &[&[u8]],
    build: LiteralSetBuildAccounting,
    limits: LiteralSetBuildLimits,
) -> Result<LiteralSetCompactBuildOutcome, LiteralSetError> {
    let uniform_positive = build.minimum_pattern_bytes > 0
        && build.minimum_pattern_bytes.checked_mul(build.patterns) == Some(build.pattern_bytes);
    let match_kind = if uniform_positive {
        MatchKind::Standard
    } else {
        MatchKind::LeftmostFirst
    };
    let automaton = DFA::builder()
        .match_kind(match_kind)
        .build(patterns.iter().copied())
        .map_err(|error| LiteralSetError::AutomatonBuild {
            detail: error.to_string(),
        })?;
    LiteralSetPlan::from_preflight_dfa(build, automaton, limits)
        .map(LiteralSetCompactBuildOutcome::Canonical)
}

/// Construction-bound ordinary access to the compact owner.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct LiteralSetCompactOrdinaryExecutor<'a> {
    plan: &'a LiteralSetCompactPlan,
}

impl LiteralSetCompactPlan {
    #[cold]
    #[inline(never)]
    pub fn try_new_ripgrep_standard_borrowed(
        patterns: &[&[u8]],
        limits: LiteralSetBuildLimits,
    ) -> Result<LiteralSetCompactBuildOutcome, LiteralSetError> {
        if !(MIN_PATTERNS..=MAX_PATTERNS).contains(&patterns.len()) {
            return Ok(LiteralSetCompactBuildOutcome::NotApplicable);
        }
        let mut build = preflight(patterns, limits, LiteralSetMatchSemantics::LeftmostFirst)?;
        let width = build.minimum_pattern_bytes;
        let uniform_positive = width >= MIN_PATTERN_BYTES
            && width.checked_mul(build.patterns) == Some(build.pattern_bytes);
        if !uniform_positive || build.build_work_upper_bound < MIN_DENSE_BUILD_WORK {
            return canonical_outcome(patterns, build, limits);
        }
        // Contiguous conversion writes every encoded transition and then
        // remaps every encoded state ID in a second pass. Charge two complete
        // cell traversals plus state-map and pattern-vector setup.
        let Some(compact_build_work) = build
            .dfa_cells_upper_bound
            .checked_mul(2)
            .and_then(|work| work.checked_add(build.trie_states_upper_bound))
            .and_then(|work| work.checked_add(build.patterns))
            .and_then(|work| work.checked_add(build.build_work_upper_bound))
        else {
            return canonical_outcome(patterns, build, limits);
        };
        if compact_build_work > limits.max_build_work {
            return canonical_outcome(patterns, build, limits);
        }
        // The incumbent envelope already covers the shared trie and checked
        // DFA. Charge one complete trie-state envelope plus every potentially
        // dense row retained by the contiguous NFA while all three owners are
        // simultaneously live. The DFA-cell factor deliberately overbounds
        // aho-corasick's smaller contiguous state identifiers.
        let Some(dense_states_upper_bound) = build
            .patterns
            .checked_mul(width.min(MAX_DENSE_DEPTH))
            .and_then(|states| states.checked_add(1))
            .map(|states| states.min(build.trie_states_upper_bound))
        else {
            return canonical_outcome(patterns, build, limits);
        };
        let Some(compact_build_bytes) = dense_states_upper_bound
            .checked_mul(ALPHABET_LEN)
            .and_then(|cells| cells.checked_mul(BYTES_PER_DFA_CELL_ENVELOPE))
            .and_then(|dense_bytes| {
                build
                    .trie_states_upper_bound
                    .checked_mul(BYTES_PER_TRIE_STATE_ENVELOPE)
                    .and_then(|trie_bytes| dense_bytes.checked_add(trie_bytes))
            })
            .and_then(|additional| build.build_bytes_upper_bound.checked_add(additional))
        else {
            return canonical_outcome(patterns, build, limits);
        };
        if compact_build_bytes > limits.max_build_bytes {
            return canonical_outcome(patterns, build, limits);
        }

        let mut shared_builder = noncontiguous::Builder::new();
        shared_builder.match_kind(MatchKind::Standard);
        let shared = shared_builder
            .build(patterns.iter().copied())
            .map_err(|error| LiteralSetError::AutomatonBuild {
                detail: error.to_string(),
            })?;
        let canonical_automaton =
            DFA::builder()
                .build_from_noncontiguous(&shared)
                .map_err(|error| LiteralSetError::AutomatonBuild {
                    detail: error.to_string(),
                })?;
        // Checked and explicit-session calls retain the exact established DFA
        // contract. The compact NFA is an additional ordinary-only engine.
        let canonical = LiteralSetPlan::from_preflight_dfa(build, canonical_automaton, limits)?;
        let mut compact_builder = NFA::builder();
        compact_builder.dense_depth(width.min(MAX_DENSE_DEPTH));
        let automaton = match compact_builder.build_from_noncontiguous(&shared) {
            Ok(automaton) => automaton,
            Err(_) => return Ok(LiteralSetCompactBuildOutcome::Canonical(canonical)),
        };
        debug_assert_eq!(automaton.match_kind(), MatchKind::Standard);
        debug_assert_eq!(automaton.min_pattern_len(), width);
        debug_assert_eq!(automaton.max_pattern_len(), width);
        debug_assert_eq!(
            canonical.build_accounting().match_semantics,
            build.match_semantics
        );
        debug_assert_eq!(
            canonical.build_accounting().pattern_bytes,
            build.pattern_bytes
        );
        let Some(persistent_bytes) = canonical
            .build_accounting()
            .persistent_bytes
            .checked_add(automaton.memory_usage())
        else {
            return Ok(LiteralSetCompactBuildOutcome::Canonical(canonical));
        };
        build.build_work_upper_bound = compact_build_work;
        build.build_bytes_upper_bound = compact_build_bytes;
        build.persistent_bytes = persistent_bytes;
        if persistent_bytes > limits.max_persistent_bytes {
            return Ok(LiteralSetCompactBuildOutcome::Canonical(canonical));
        }
        Ok(LiteralSetCompactBuildOutcome::Compact(Self {
            canonical,
            automaton,
            build,
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
        LiteralSetCompactOrdinaryExecutor { plan: self }
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

    #[inline(never)]
    fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<(usize, usize)>, LiteralSetError> {
        validate_window(window, haystack.len())?;
        self.find_window_value_validated(haystack, window)
    }

    #[inline(never)]
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

    #[inline(never)]
    fn selected_end_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<usize>, LiteralSetError> {
        validate_window(window, haystack.len())?;
        Ok(self.first_end_window_value_validated(haystack, window))
    }

    #[inline(never)]
    fn try_visit_spans_window_value<F, E>(
        &self,
        haystack: &[u8],
        window: Window,
        mut visitor: F,
    ) -> Result<Result<(), E>, LiteralSetError>
    where
        F: FnMut((usize, usize)) -> Result<bool, E>,
    {
        validate_window(window, haystack.len())?;
        if self.window_is_too_short(window) {
            return Ok(Ok(()));
        }
        let mut input = Input::new(haystack).span(window.start()..window.end());
        loop {
            let Some(matched) = self
                .automaton
                .try_find(&input)
                .expect("the compact literal NFA supports unanchored search")
            else {
                return Ok(Ok(()));
            };
            let span = self.absolute_span(matched)?;
            match visitor(span) {
                Ok(true) => {}
                Ok(false) => return Ok(Ok(())),
                Err(error) => return Ok(Err(error)),
            }
            if window.end() - matched.end() < self.build.minimum_pattern_bytes {
                return Ok(Ok(()));
            }
            input.set_start(matched.end());
        }
    }

    #[inline(never)]
    fn count_spans_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<u64, LiteralSetError> {
        validate_window(window, haystack.len())?;
        if self.window_is_too_short(window) {
            return Ok(0);
        }
        let mut input = Input::new(haystack).span(window.start()..window.end());
        let mut count = 0_usize;
        loop {
            let Some(matched) = self
                .automaton
                .try_find(&input)
                .expect("the compact literal NFA supports unanchored search")
            else {
                break;
            };
            // Matches do not overlap and have positive width, so their count
            // is bounded by the validated window length.
            count += 1;
            if window.end() - matched.end() < self.build.minimum_pattern_bytes {
                break;
            }
            input.set_start(matched.end());
        }
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
        window.end() - window.start() < self.build.minimum_pattern_bytes
    }

    #[inline]
    fn absolute_span(
        &self,
        matched: aho_corasick::Match,
    ) -> Result<(usize, usize), LiteralSetError> {
        let end = matched.end();
        let width = self.build.minimum_pattern_bytes;
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
        self.plan.exists_window_value(haystack, window)
    }

    /// Return the first accepting endpoint without projecting a span start.
    #[doc(hidden)]
    #[inline]
    pub fn selected_end_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<usize>, LiteralSetError> {
        self.plan.selected_end_window_value(haystack, window)
    }

    /// Return the selected span, recovering its fixed-width start after hit.
    #[doc(hidden)]
    #[inline]
    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<(usize, usize)>, LiteralSetError> {
        self.plan.find_window_value(haystack, window)
    }

    /// Visit non-overlapping spans through one pinned Aho iterator.
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
        self.plan
            .try_visit_spans_window_value(haystack, window, visitor)
    }

    /// Count non-overlapping spans through one pinned Aho iterator.
    #[doc(hidden)]
    #[inline]
    pub fn count_spans_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<u64, LiteralSetError> {
        self.plan.count_spans_window_value(haystack, window)
    }
}

#[cfg(test)]
mod tests {
    use aho_corasick::automaton::Automaton;

    use super::{
        LiteralSetCompactBuildOutcome, LiteralSetCompactPlan, MAX_PATTERNS, MIN_PATTERN_BYTES,
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
            25_230_847
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
            25_232_641
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
        let mut patterns = public_patterns(MAX_PATTERNS, MIN_PATTERN_BYTES);
        patterns[0].fill(b'a');
        let dense =
            LiteralSetPlan::new_stable(&patterns, LiteralSetBuildLimits::default()).unwrap();
        let compact_plan = compact(&patterns, LiteralSetBuildLimits::default())
            .unwrap()
            .unwrap();
        let ordinary = compact_plan.ordinary_executor();

        let mut haystack = vec![b'z'];
        haystack.extend(core::iter::repeat_n(b'a', 2 * MIN_PATTERN_BYTES));
        haystack.push(b'z');
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

        let window = Window::new(1, haystack.len() - 1);
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
        assert_eq!(ordinary.count_spans_window_value(&haystack, window), Ok(2));

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
            canonical_persistent + selected.automaton.memory_usage(),
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
    }
}
