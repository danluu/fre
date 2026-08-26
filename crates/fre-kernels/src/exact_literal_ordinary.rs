//! Report-free ordinary execution over a retained positive exact literal.
//!
//! [`LiteralPlan`] remains the only owner of the copied needle and prepared
//! `memmem::Finder`. This module exposes a borrowed capability only when that
//! needle is nonempty. Ordinary unlimited operations can then validate their
//! source window once and use the retained finder directly, without rebuilding
//! finite linear-work accounting or allocating operation state.

use memchr::memmem::Finder;

use super::{LiteralError, LiteralPlan, Window};

/// Stable capability identity for report-free positive exact-literal search.
pub const ORDINARY_CAPABILITY_ID: &str = "exact-literal.ordinary-positive.v1";

#[cfg(target_arch = "aarch64")]
const RETAINED_COUNT_MIN_NEEDLE_BYTES: usize = 8;
#[cfg(target_arch = "aarch64")]
const RETAINED_COUNT_MAX_NEEDLE_BYTES: usize = 32;

#[inline]
fn retained_count_eligible(needle: &[u8]) -> bool {
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = needle;
        false
    }
    #[cfg(target_arch = "aarch64")]
    {
        if !(RETAINED_COUNT_MIN_NEEDLE_BYTES..=RETAINED_COUNT_MAX_NEEDLE_BYTES)
            .contains(&needle.len())
        {
            return false;
        }
        let mut seen = [0_u64; 4];
        let mut distinct = 0_usize;
        for &byte in needle {
            let word = usize::from(byte) / u64::BITS as usize;
            let mask = 1_u64 << (usize::from(byte) % u64::BITS as usize);
            if seen[word] & mask == 0 {
                seen[word] |= mask;
                distinct += 1;
            }
        }
        distinct > needle.len() / 2
    }
}

/// Immutable semantics sealed by an ordinary exact-literal executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    /// Stable capability implementation identity.
    pub capability_id: &'static str,
    /// Exact positive literal width.
    pub literal_bytes: usize,
    /// Whether candidate selection is leftmost.
    pub leftmost: bool,
    /// Whether traversal resumes at the preceding selected end.
    pub non_overlapping: bool,
}

/// Borrowed ordinary engine for one retained positive exact literal.
///
/// The private fields bind both the prepared finder and its exact needle once.
/// Only [`LiteralPlan::ordinary_executor`] can create this capability.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct ExactLiteralOrdinaryExecutor<'a> {
    finder: &'a Finder<'static>,
    needle: &'a [u8],
}

impl LiteralPlan {
    /// Bind report-free ordinary execution when this exact literal is known to
    /// have positive width.
    ///
    /// Empty literals deliberately return `None`: their byte-boundary progress
    /// and nullable semantics remain owned by the canonical checked engine.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn ordinary_executor(&self) -> Option<ExactLiteralOrdinaryExecutor<'_>> {
        let needle = self.finder.needle();
        if needle.is_empty() {
            return None;
        }
        #[cfg(test)]
        ordinary_probe::record_bind();
        Some(ExactLiteralOrdinaryExecutor {
            finder: &self.finder,
            needle,
        })
    }
}

impl ExactLiteralOrdinaryExecutor<'_> {
    /// Return the immutable semantics authenticated at binding time.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn identity(&self) -> Identity {
        Identity {
            capability_id: ORDINARY_CAPABILITY_ID,
            literal_bytes: self.needle.len(),
            leftmost: true,
            non_overlapping: true,
        }
    }

    /// Whether this executor was issued by exactly `plan`, rather than merely
    /// by another plan containing equal bytes.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn is_bound_to(&self, plan: &LiteralPlan) -> bool {
        core::ptr::eq(self.finder, &plan.finder)
    }

    /// Whether a separate ordinary-session count route may use the retained
    /// finder iterator.
    ///
    /// This construction-only classification is sealed once by the session.
    /// Other exact-literal operations and ineligible count calls retain their
    /// established executor variant and implementation.
    #[doc(hidden)]
    #[must_use]
    #[inline]
    pub fn retained_count_eligible(&self) -> bool {
        retained_count_eligible(self.needle)
    }

    /// Return whether the retained literal occurs wholly inside `window`.
    ///
    /// This stops at the first acceptance and does not reconstruct a span.
    ///
    /// # Errors
    ///
    /// Returns [`LiteralError::InvalidWindow`] before source access when the
    /// requested range lies outside `haystack`.
    #[doc(hidden)]
    #[inline]
    pub fn exists_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<bool, LiteralError> {
        validate_window(window, haystack.len())?;
        #[cfg(test)]
        ordinary_probe::record_finder_call();
        Ok(self
            .finder
            .find(&haystack[window.start()..window.end()])
            .is_some())
    }

    /// Return the first accepting endpoint wholly inside `window`.
    ///
    /// # Errors
    ///
    /// Returns the same invalid-window or offset-arithmetic errors as
    /// [`Self::find_window_value`].
    #[doc(hidden)]
    #[inline]
    pub fn first_end_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<usize>, LiteralError> {
        validate_window(window, haystack.len())?;
        self.first_end_after_validation(haystack, window)
    }

    /// Return the selected leftmost span wholly inside `window`.
    ///
    /// The endpoint-only engine runs first. A start is recovered only after a
    /// positive result by subtracting the sealed literal width.
    ///
    /// # Errors
    ///
    /// Returns [`LiteralError::InvalidWindow`] before source access, or a
    /// checked offset-arithmetic failure.
    #[doc(hidden)]
    #[inline]
    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<(usize, usize)>, LiteralError> {
        validate_window(window, haystack.len())?;
        self.first_end_after_validation(haystack, window)?
            .map(|end| {
                let start =
                    end.checked_sub(self.needle.len())
                        .ok_or(LiteralError::ArithmeticOverflow {
                            computation: "ordinary literal match start",
                        })?;
                Ok((start, end))
            })
            .transpose()
    }

    /// Visit every non-overlapping selected span wholly inside `window`.
    ///
    /// The positive-width capability lets every accepted endpoint become the
    /// next cursor directly. The callback returns `Ok(true)` to continue,
    /// `Ok(false)` to stop successfully, or `Err(error)` to return that
    /// callback error.
    ///
    /// # Errors
    ///
    /// Returns an invalid-window or checked offset-arithmetic error. Window
    /// validation completes before the first finder call or callback.
    #[doc(hidden)]
    #[inline]
    pub fn try_visit_spans_window_value<F, E>(
        &self,
        haystack: &[u8],
        window: Window,
        mut visitor: F,
    ) -> Result<Result<(), E>, LiteralError>
    where
        F: FnMut((usize, usize)) -> Result<bool, E>,
    {
        validate_window(window, haystack.len())?;
        self.try_visit_spans_after_validation(haystack, window, &mut visitor)
    }

    /// Count non-overlapping selected spans wholly inside `window`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::try_visit_spans_window_value`], or a
    /// checked counter overflow.
    #[doc(hidden)]
    #[inline]
    pub fn count_spans_window_value(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<u64, LiteralError> {
        let mut count = 0_u64;
        self.try_visit_spans_window_value(haystack, window, |_| {
            count = count
                .checked_add(1)
                .ok_or(LiteralError::ArithmeticOverflow {
                    computation: "ordinary literal match count",
                })?;
            Ok::<bool, LiteralError>(true)
        })??;
        Ok(count)
    }

    /// Count through one retained non-overlapping finder iterator.
    ///
    /// Ordinary sessions call this only from their separately admitted
    /// retained-count variant. Outlining keeps iterator state out of the
    /// incumbent exact-literal count implementation.
    ///
    /// # Errors
    ///
    /// Returns an invalid-window error before binding the iterator, or a
    /// checked counter-conversion failure.
    #[doc(hidden)]
    #[inline(never)]
    pub fn count_spans_window_value_retained(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<u64, LiteralError> {
        validate_window(window, haystack.len())?;
        #[cfg(test)]
        ordinary_probe::record_retained_count_bind();
        let count = self
            .finder
            .find_iter(&haystack[window.start()..window.end()])
            .count();
        u64::try_from(count).map_err(|_| LiteralError::ArithmeticOverflow {
            computation: "ordinary literal match count",
        })
    }

    #[inline]
    fn first_end_after_validation(
        &self,
        haystack: &[u8],
        window: Window,
    ) -> Result<Option<usize>, LiteralError> {
        #[cfg(test)]
        ordinary_probe::record_finder_call();
        self.finder
            .find(&haystack[window.start()..window.end()])
            .map(|relative| {
                window
                    .start()
                    .checked_add(relative)
                    .and_then(|start| start.checked_add(self.needle.len()))
                    .ok_or(LiteralError::ArithmeticOverflow {
                        computation: "ordinary literal match end",
                    })
            })
            .transpose()
    }

    #[inline]
    fn try_visit_spans_after_validation<F, E>(
        &self,
        haystack: &[u8],
        window: Window,
        visitor: &mut F,
    ) -> Result<Result<(), E>, LiteralError>
    where
        F: FnMut((usize, usize)) -> Result<bool, E>,
    {
        let literal_bytes = self.needle.len();
        let mut cursor = window.start();
        while window.end().saturating_sub(cursor) >= literal_bytes {
            #[cfg(test)]
            ordinary_probe::record_finder_call();
            let Some(relative) = self.finder.find(&haystack[cursor..window.end()]) else {
                return Ok(Ok(()));
            };
            let start = cursor
                .checked_add(relative)
                .ok_or(LiteralError::ArithmeticOverflow {
                    computation: "ordinary literal iteration start",
                })?;
            let end = start
                .checked_add(literal_bytes)
                .ok_or(LiteralError::ArithmeticOverflow {
                    computation: "ordinary literal iteration end",
                })?;
            cursor = end;
            match visitor((start, end)) {
                Ok(true) => {}
                Ok(false) => return Ok(Ok(())),
                Err(error) => return Ok(Err(error)),
            }
        }
        Ok(Ok(()))
    }
}

#[inline]
fn validate_window(window: Window, haystack_len: usize) -> Result<(), LiteralError> {
    #[cfg(test)]
    ordinary_probe::record_window_validation();
    if window.start() > window.end() || window.end() > haystack_len {
        return Err(LiteralError::InvalidWindow {
            start: window.start(),
            end: window.end(),
            haystack_len,
        });
    }
    Ok(())
}

#[cfg(test)]
mod ordinary_probe {
    use std::cell::Cell;

    std::thread_local! {
        static COUNTS: Cell<(usize, usize, usize)> = const { Cell::new((0, 0, 0)) };
        static RETAINED_COUNT_BINDS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn reset() {
        COUNTS.set((0, 0, 0));
        RETAINED_COUNT_BINDS.set(0);
    }

    pub(super) fn record_bind() {
        let (binds, validations, finder_calls) = COUNTS.get();
        COUNTS.set((binds.saturating_add(1), validations, finder_calls));
    }

    pub(super) fn record_window_validation() {
        let (binds, validations, finder_calls) = COUNTS.get();
        COUNTS.set((binds, validations.saturating_add(1), finder_calls));
    }

    pub(super) fn record_finder_call() {
        let (binds, validations, finder_calls) = COUNTS.get();
        COUNTS.set((binds, validations, finder_calls.saturating_add(1)));
    }

    pub(super) fn snapshot() -> (usize, usize, usize) {
        COUNTS.get()
    }

    pub(super) fn record_retained_count_bind() {
        RETAINED_COUNT_BINDS.set(RETAINED_COUNT_BINDS.get().saturating_add(1));
    }

    pub(super) fn retained_count_binds() -> usize {
        RETAINED_COUNT_BINDS.get()
    }
}

#[cfg(test)]
mod tests {
    use super::{ORDINARY_CAPABILITY_ID, ordinary_probe};
    use crate::{
        LiteralBuildLimits, LiteralError, LiteralPlan, LiteralSearchLimits, Window,
        literal_preflight_probe,
    };

    fn words(max_len: usize) -> Vec<Vec<u8>> {
        let mut words = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in &frontier {
                for byte in [b'a', b'b'] {
                    let mut word = prefix.clone();
                    word.push(byte);
                    words.push(word.clone());
                    next.push(word);
                }
            }
            frontier = next;
        }
        words
    }

    fn canonical_spans(plan: &LiteralPlan, haystack: &[u8], window: Window) -> Vec<(usize, usize)> {
        let mut cursor = window.start();
        let mut spans = Vec::new();
        loop {
            let Some(matched) = plan
                .find_window_value(
                    haystack,
                    Window::new(cursor, window.end()),
                    LiteralSearchLimits::unlimited(),
                )
                .unwrap()
            else {
                return spans;
            };
            cursor = matched.1;
            spans.push(matched);
        }
    }

    #[test]
    fn admission_binds_one_positive_owner_and_refuses_nullable_literals() {
        let empty = LiteralPlan::new(b"", LiteralBuildLimits::default()).unwrap();
        assert!(empty.ordinary_executor().is_none());

        let plan = LiteralPlan::new(b"needle", LiteralBuildLimits::default()).unwrap();
        let equal = LiteralPlan::new(b"needle", LiteralBuildLimits::default()).unwrap();
        let executor = plan.ordinary_executor().unwrap();
        assert_eq!(
            executor.identity(),
            super::Identity {
                capability_id: ORDINARY_CAPABILITY_ID,
                literal_bytes: 6,
                leftmost: true,
                non_overlapping: true,
            }
        );
        assert!(executor.is_bound_to(&plan));
        assert!(!executor.is_bound_to(&equal));
    }

    #[test]
    fn ordinary_values_exhaustively_match_the_checked_owner() {
        for needle in words(3).into_iter().filter(|needle| !needle.is_empty()) {
            let plan = LiteralPlan::new(&needle, LiteralBuildLimits::default()).unwrap();
            let executor = plan.ordinary_executor().unwrap();
            for haystack in words(5) {
                for start in 0..=haystack.len() {
                    for end in start..=haystack.len() {
                        let window = Window::new(start, end);
                        let expected = plan
                            .find_window_value(&haystack, window, LiteralSearchLimits::unlimited())
                            .unwrap();
                        assert_eq!(
                            executor.exists_window_value(&haystack, window),
                            Ok(expected.is_some()),
                            "exists needle={needle:?} haystack={haystack:?} window={start}..{end}",
                        );
                        assert_eq!(
                            executor.first_end_window_value(&haystack, window),
                            Ok(expected.map(|(_, end)| end)),
                            "end needle={needle:?} haystack={haystack:?} window={start}..{end}",
                        );
                        assert_eq!(
                            executor.find_window_value(&haystack, window),
                            Ok(expected),
                            "span needle={needle:?} haystack={haystack:?} window={start}..{end}",
                        );

                        let expected_spans = canonical_spans(&plan, &haystack, window);
                        let mut spans = Vec::new();
                        assert_eq!(
                            executor
                                .try_visit_spans_window_value(&haystack, window, |span| {
                                    spans.push(span);
                                    Ok::<bool, ()>(true)
                                })
                                .unwrap(),
                            Ok(()),
                        );
                        assert_eq!(spans, expected_spans);
                        assert_eq!(
                            executor.count_spans_window_value(&haystack, window),
                            Ok(u64::try_from(expected_spans.len()).unwrap()),
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn ordinary_operations_validate_once_and_never_enter_finite_preflight() {
        let plan = LiteralPlan::new(b"aa", LiteralBuildLimits::default()).unwrap();
        ordinary_probe::reset();
        literal_preflight_probe::reset();
        let executor = plan.ordinary_executor().unwrap();

        assert_eq!(
            executor.exists_window_value(b"aaaaa", Window::new(0, 5)),
            Ok(true)
        );
        assert_eq!(
            executor.first_end_window_value(b"aaaaa", Window::new(0, 5)),
            Ok(Some(2)),
        );
        assert_eq!(
            executor.find_window_value(b"aaaaa", Window::new(0, 5)),
            Ok(Some((0, 2))),
        );
        let mut spans = Vec::new();
        executor
            .try_visit_spans_window_value(b"aaaaa", Window::new(0, 5), |span| {
                spans.push(span);
                Ok::<bool, ()>(true)
            })
            .unwrap()
            .unwrap();
        assert_eq!(spans, [(0, 2), (2, 4)]);
        assert_eq!(
            executor.count_spans_window_value(b"aaaaa", Window::new(0, 5)),
            Ok(2),
        );
        assert_eq!(ordinary_probe::snapshot().0, 1, "one executor binding");
        assert_eq!(
            ordinary_probe::snapshot().1,
            5,
            "one validation per operation"
        );
        assert!(ordinary_probe::snapshot().2 >= 7);
        assert_eq!(literal_preflight_probe::calls(), 0);

        plan.find_window_value(
            b"aaaaa",
            Window::new(0, 5),
            LiteralSearchLimits::unlimited(),
        )
        .unwrap();
        assert_eq!(literal_preflight_probe::calls(), 1);
    }

    #[test]
    fn invalid_windows_and_callback_control_preserve_atomicity() {
        let plan = LiteralPlan::new(b"aa", LiteralBuildLimits::default()).unwrap();
        let executor = plan.ordinary_executor().unwrap();
        let haystack = b"aaaa";
        let invalid = Window::new(5, haystack.len());
        let expected = LiteralError::InvalidWindow {
            start: 5,
            end: 4,
            haystack_len: 4,
        };

        assert_eq!(
            executor.exists_window_value(haystack, invalid),
            Err(expected.clone())
        );
        assert_eq!(
            executor.first_end_window_value(haystack, invalid),
            Err(expected.clone()),
        );
        assert_eq!(
            executor.find_window_value(haystack, invalid),
            Err(expected.clone())
        );
        assert_eq!(
            executor.count_spans_window_value(haystack, invalid),
            Err(expected.clone())
        );
        let mut callbacks = 0;
        assert_eq!(
            executor.try_visit_spans_window_value(haystack, invalid, |_| {
                callbacks += 1;
                Ok::<bool, ()>(true)
            }),
            Err(expected),
        );
        assert_eq!(callbacks, 0);

        let mut stopped = Vec::new();
        assert_eq!(
            executor
                .try_visit_spans_window_value(haystack, Window::new(0, 4), |span| {
                    stopped.push(span);
                    Ok::<bool, &'static str>(false)
                })
                .unwrap(),
            Ok(()),
        );
        assert_eq!(stopped, [(0, 2)]);
        assert_eq!(
            executor
                .try_visit_spans_window_value(haystack, Window::new(0, 4), |_| {
                    Err::<bool, _>("callback")
                })
                .unwrap(),
            Err("callback"),
        );
    }

    #[test]
    fn retained_count_eligibility_is_conservative_and_target_bound() {
        let cases: &[(&[u8], bool)] = &[
            (b"1234567", false),
            (b"12345678", true),
            (b"needleXYZ", true),
            (b"abcdabcd", false),
            (b"abcdeabc", true),
            (b"aaaaaaaaa", false),
            (b"0123456789abcdef0123456789ABCDEF", true),
            (b"0123456789abcdef0123456789ABCDEFG", false),
        ];
        for &(needle, aarch64_expected) in cases {
            let plan = LiteralPlan::new(needle, LiteralBuildLimits::default()).unwrap();
            let executor = plan.ordinary_executor().unwrap();
            assert_eq!(
                executor.retained_count_eligible(),
                cfg!(target_arch = "aarch64") && aarch64_expected,
                "needle={needle:?}",
            );
        }
    }

    #[test]
    fn retained_count_matches_checked_nonoverlapping_windows() {
        let cases: &[(&[u8], &[u8], Window)] = &[
            (
                b"needleXYZ",
                b"xxneedleXYZneedleXYZneedleXYZy",
                Window::new(0, 30),
            ),
            (b"12345678", b"x1234567812345678y", Window::new(1, 17)),
            (b"aba", b"xababaz", Window::new(1, 6)),
            (b"needleXYZ", b"zzzzzzzz", Window::new(0, 8)),
        ];
        for &(needle, haystack, window) in cases {
            let plan = LiteralPlan::new(needle, LiteralBuildLimits::default()).unwrap();
            let executor = plan.ordinary_executor().unwrap();
            let expected = canonical_spans(&plan, haystack, window);
            assert_eq!(
                executor.count_spans_window_value_retained(haystack, window),
                Ok(u64::try_from(expected.len()).unwrap()),
                "needle={needle:?} haystack={haystack:?} window={window:?}",
            );
        }
    }

    #[test]
    fn retained_count_validates_before_binding_its_iterator() {
        let plan = LiteralPlan::new(b"needleXYZ", LiteralBuildLimits::default()).unwrap();
        let executor = plan.ordinary_executor().unwrap();
        let haystack = b"needleXYZ";

        ordinary_probe::reset();
        assert_eq!(
            executor.count_spans_window_value_retained(haystack, Window::new(10, 9)),
            Err(LiteralError::InvalidWindow {
                start: 10,
                end: 9,
                haystack_len: 9,
            }),
        );
        assert_eq!(ordinary_probe::snapshot(), (0, 1, 0));
        assert_eq!(ordinary_probe::retained_count_binds(), 0);

        ordinary_probe::reset();
        assert_eq!(
            executor.count_spans_window_value_retained(haystack, Window::full(haystack)),
            Ok(1),
        );
        assert_eq!(ordinary_probe::snapshot(), (0, 1, 0));
        assert_eq!(ordinary_probe::retained_count_binds(), 1);
    }
}
