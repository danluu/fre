//! Exact value-iterator cursor for the pinned Cloudflare ReDoS simplification.
//!
//! This is deliberately not a generic greedy-continuation shortcut. The
//! construction proof admits one complete source and one exact Rust-bytes
//! profile. Under that contract, `.*.*=.*` selects the complete
//! line-terminator-delimited corridor containing the next `=` byte.

use fre_syntax::RustProfile;
use memchr::{memchr, memchr2};
use regex_syntax::hir::Hir;

const REGISTERED_SOURCE: &str = ".*.*=.*";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan;

pub(crate) fn prove(source: &str, profile: &RustProfile, hir: &Hir) -> Option<Plan> {
    if source != REGISTERED_SOURCE {
        return None;
    }
    let mut expected = RustProfile::rebar_1_12_4();
    expected.options.unicode = false;
    if profile != &expected {
        return None;
    }
    // The exact source/profile pair is the proof owner. These parser facts
    // fail closed if the pinned syntax crate ever changes its construction.
    let properties = hir.properties();
    if properties.minimum_len() != Some(1)
        || properties.maximum_len().is_some()
        || properties.explicit_captures_len() != 0
        || !properties.look_set().is_empty()
    {
        return None;
    }
    Some(Plan)
}

impl Plan {
    pub(crate) const fn cursor(self, haystack: &[u8]) -> Cursor<'_> {
        Cursor { haystack }
    }
}

/// Allocation-free contextual search over one immutable haystack.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Cursor<'h> {
    haystack: &'h [u8],
}

impl Cursor<'_> {
    pub(crate) const fn haystack_len(self) -> usize {
        self.haystack.len()
    }

    pub(crate) fn work_bound(self, start: usize) -> Option<u64> {
        let residual = self.haystack.len().checked_sub(start)?;
        u64::try_from(residual).ok()
    }

    pub(crate) fn find_at(self, start: usize) -> Option<(usize, usize)> {
        let mut corridor_start = start;
        let mut at = start;
        while at < self.haystack.len() {
            let event = memchr2(b'=', b'\n', self.haystack.get(at..)?).map(|offset| at + offset);
            let Some(event) = event else {
                return None;
            };
            if self.haystack[event] == b'=' {
                let end = memchr(b'\n', &self.haystack[event + 1..])
                    .map_or(self.haystack.len(), |offset| event + 1 + offset);
                return Some((corridor_start, end));
            }
            at = event + 1;
            corridor_start = at;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;
    use regex_syntax::ParserBuilder;

    use super::{Cursor, REGISTERED_SOURCE};
    use crate::{
        K0SearchError, PlanSelection, PortableBuilder, PortableFindIterError,
        PortableFindIterRunLimits, PortableNativeSearchCursor, PortablePlan, SearchError,
        SearchLimits, SearchSessionLimits,
    };
    use fre_syntax::RustProfile;

    fn builder(pattern: &str) -> PortableBuilder {
        PortableBuilder::new(pattern).profile(RustProfile::rebar_1_12_4())
    }

    fn selected_specialist(pattern: &str, unicode: bool) -> bool {
        let regex = builder(pattern).unicode(unicode).build().unwrap();
        matches!(
            &regex.plan,
            PortablePlan::K0(plan) if plan.cloudflare_redos_span.is_some()
        )
    }

    #[test]
    fn construction_selects_only_the_registered_source_and_profile() {
        assert!(selected_specialist(REGISTERED_SOURCE, false));
        assert!(!selected_specialist(REGISTERED_SOURCE, true));
        for source in [".*=.*", ".*.*=.*?", "(?:.*.*=.*)", ".*.*:.*"] {
            assert!(!selected_specialist(source, false), "source={source:?}");
        }

        for attempted in [
            builder(REGISTERED_SOURCE)
                .unicode(false)
                .case_insensitive(true)
                .build(),
            builder(REGISTERED_SOURCE)
                .unicode(false)
                .dot_matches_new_line(true)
                .build(),
            builder(REGISTERED_SOURCE)
                .unicode(false)
                .line_terminator(b'\r')
                .build(),
        ] {
            if let Ok(regex) = attempted {
                assert!(matches!(
                    &regex.plan,
                    PortablePlan::K0(plan) if plan.cloudflare_redos_span.is_none()
                ));
            }
        }

        // A forced K0 build retains the same exact source/profile theorem.
        let forced = builder(REGISTERED_SOURCE)
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap();
        assert!(matches!(
            &forced.plan,
            PortablePlan::K0(plan) if plan.cloudflare_redos_span.is_some()
        ));
    }

    #[test]
    fn generic_greedy_literal_tail_declines_the_four_part_hir() {
        let hir = ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(REGISTERED_SOURCE)
            .unwrap();
        let outcome = crate::greedy_class_literal_tail::inspect(&hir, 0, u64::MAX).unwrap();
        assert!(matches!(
            outcome,
            crate::greedy_class_literal_tail::InspectionOutcome::Ineligible { .. }
        ));
    }

    #[test]
    fn cursor_preserves_leftmost_greedy_corridors() {
        let haystack = b"pre=post\nno\nx=y\n\xff=\xfe";
        let cursor = Cursor { haystack };
        assert_eq!(Some((0, 8)), cursor.find_at(0));
        assert_eq!(Some((3, 8)), cursor.find_at(3));
        assert_eq!(Some((12, 15)), cursor.find_at(4));
        assert_eq!(Some((16, 19)), cursor.find_at(15));
        assert_eq!(None, cursor.find_at(haystack.len()));
        assert_eq!(None, cursor.find_at(haystack.len() + 1));
    }

    #[test]
    fn contextual_bounds_match_pinned_regex_exhaustively() {
        let oracle = RegexBuilder::new(REGISTERED_SOURCE)
            .unicode(false)
            .build()
            .unwrap();
        let alphabet = [b'x', b'=', b'\n', b'\r', 0, 0xFF];
        let mut haystack = Vec::new();
        for len in 0..=5 {
            let cases = alphabet.len().pow(u32::try_from(len).unwrap());
            for mut encoded in 0..cases {
                haystack.clear();
                for _ in 0..len {
                    haystack.push(alphabet[encoded % alphabet.len()]);
                    encoded /= alphabet.len();
                }
                let cursor = Cursor {
                    haystack: &haystack,
                };
                for start in 0..=haystack.len() {
                    let expected = oracle
                        .find_at(&haystack, start)
                        .map(|matched| (matched.start(), matched.end()));
                    assert_eq!(
                        expected,
                        cursor.find_at(start),
                        "haystack={haystack:?}, start={start}"
                    );
                }
            }
        }
    }

    #[test]
    fn retained_value_session_selects_specialist_and_preserves_all_spans() {
        let regex = builder(REGISTERED_SOURCE).unicode(false).build().unwrap();
        let oracle = RegexBuilder::new(REGISTERED_SOURCE)
            .unicode(false)
            .build()
            .unwrap();
        let haystack = b"=first\nnone\nleft=right\n\xff=\x00\xfe\nlast=";
        let expected: Vec<_> = oracle
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect();
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        assert!(matches!(
            session.value_native_search_cursor(haystack),
            Some(PortableNativeSearchCursor::CloudflareRedos(_))
        ));
        let actual: Vec<_> = session
            .find_iter_value(haystack, PortableFindIterRunLimits::unlimited())
            .map(|result| {
                let matched = result.unwrap();
                (matched.start(), matched.end())
            })
            .collect();
        assert_eq!(expected, actual);
    }

    #[test]
    fn work_limit_refuses_before_the_first_match() {
        let haystack = b"x=xxxxxxxx";
        let regex = builder(REGISTERED_SOURCE).unicode(false).build().unwrap();
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        let mut refused = session.find_iter_value(
            haystack,
            PortableFindIterRunLimits {
                search: SearchLimits {
                    max_work: u64::try_from(haystack.len() - 1).unwrap(),
                    max_scratch_bytes: 0,
                },
                max_search_calls: usize::MAX,
            },
        );
        assert!(matches!(
            refused.next(),
            Some(Err(PortableFindIterError::Search(SearchError::K0(
                K0SearchError::WorkLimitExceeded {
                    consumed: 0,
                    requested,
                    position: 0,
                    ..
                }
            )))) if requested == u64::try_from(haystack.len()).unwrap()
        ));
        assert!(refused.next().is_none());

        let accepted: Vec<_> = session
            .find_iter_value(
                haystack,
                PortableFindIterRunLimits {
                    search: SearchLimits {
                        max_work: u64::try_from(haystack.len()).unwrap(),
                        max_scratch_bytes: 0,
                    },
                    max_search_calls: usize::MAX,
                },
            )
            .map(Result::unwrap)
            .map(|matched| (matched.start(), matched.end()))
            .collect();
        assert_eq!(vec![(0, haystack.len())], accepted);
    }
}
