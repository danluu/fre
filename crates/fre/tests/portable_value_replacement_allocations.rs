#![forbid(unsafe_code)]

use std::{alloc::System, borrow::Cow};

use fre::{
    PlanKind, PlanSelection, PortableBuilder, PortableFindIterLimits, PortableFindIterRunLimits,
    SearchLimits, SearchSessionLimits, ValueReplacementOutputLimits,
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn warm_literal_value_replacement_allocates_only_its_matched_output() {
    let regex = PortableBuilder::new(r"(?-u:(?:ab|ac)+z)")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("K0 allocation regex");
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("K0 allocation session");
    assert_eq!(
        session
            .find_value(b"xxxxxxxxabacabacz", SearchLimits::unlimited())
            .expect("session warmup")
            .map(|matched| (matched.start(), matched.end())),
        Some((8, 17)),
    );

    let no_match_region = Region::new(GLOBAL);
    let no_match = session
        .replace_literal_value(
            b"xxxxxxxx",
            b"_",
            PortableFindIterRunLimits::unlimited(),
            ValueReplacementOutputLimits::default(),
        )
        .expect("warm no-match replacement");
    let no_match_change = no_match_region.change();
    assert!(matches!(no_match, Cow::Borrowed(_)));
    assert_eq!(no_match.as_ref(), b"xxxxxxxx");
    assert_eq!(no_match_change, Stats::default());

    let matched_region = Region::new(GLOBAL);
    let matched = session
        .replace_literal_value(
            b"xxxxxxxxabacabacz",
            b"_",
            PortableFindIterRunLimits::unlimited(),
            ValueReplacementOutputLimits::default(),
        )
        .expect("warm matched replacement");
    let matched_change = matched_region.change();
    assert!(matches!(matched, Cow::Owned(_)));
    assert_eq!(matched.as_ref(), b"xxxxxxxx_");
    assert_eq!(matched_change.allocations, 1, "{matched_change:?}");
    assert_eq!(matched_change.reallocations, 0, "{matched_change:?}");
    assert_eq!(matched_change.deallocations, 0, "{matched_change:?}");

    let fixed = PortableBuilder::new(r"[A-D][\x00-\x7F]Q")
        .unicode(false)
        .build()
        .expect("fixed-predicate allocation regex");
    assert_eq!(fixed.build_report().plan, PlanKind::FixedPredicateWord64);

    let fixed_absent_region = Region::new(GLOBAL);
    let fixed_absent = fixed
        .replace_literal_value(
            b"xxxxxxxx",
            b"_",
            PortableFindIterLimits::unlimited(),
            ValueReplacementOutputLimits::default(),
        )
        .expect("fixed-predicate no-match replacement");
    let fixed_absent_change = fixed_absent_region.change();
    assert!(matches!(fixed_absent, Cow::Borrowed(_)));
    assert_eq!(fixed_absent_change, Stats::default());

    let fixed_match_region = Region::new(GLOBAL);
    let fixed_match = fixed
        .replace_literal_value(
            b"xxxxA!Qxxxx",
            b"_",
            PortableFindIterLimits::unlimited(),
            ValueReplacementOutputLimits::default(),
        )
        .expect("fixed-predicate matched replacement");
    let fixed_match_change = fixed_match_region.change();
    assert!(matches!(fixed_match, Cow::Owned(_)));
    assert_eq!(fixed_match.as_ref(), b"xxxx_xxxx");
    assert_eq!(fixed_match_change.allocations, 1, "{fixed_match_change:?}");
    assert_eq!(
        fixed_match_change.reallocations, 0,
        "{fixed_match_change:?}"
    );
    assert_eq!(
        fixed_match_change.deallocations, 0,
        "{fixed_match_change:?}"
    );

    for (pattern, expected_plan, matched_haystack, expected) in [
        (
            r"(?-u:[aceg]+)",
            PlanKind::PureByteClassRepeat,
            b"!!!!acegg!!!!".as_slice(),
            b"!!!!_!!!!".as_slice(),
        ),
        (
            r"(?-u:[aceg]){2,5}",
            PlanKind::PureByteClassRepeat,
            b"!!!!acegg!!!!".as_slice(),
            b"!!!!_!!!!".as_slice(),
        ),
        (
            r"(?-u:[A-Z]){1,3}(?-u:[a-z]){2,5}(?-u:[0-9]){1,2}",
            PlanKind::BoundedByteClassSequence,
            b"!!!!ABCabc12!!!!".as_slice(),
            b"!!!!_!!!!".as_slice(),
        ),
    ] {
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("byte-class allocation regex {pattern:?}: {error}"));
        assert_eq!(regex.build_report().plan, expected_plan, "{pattern:?}");

        let absent_region = Region::new(GLOBAL);
        let absent = regex
            .replace_literal_value(
                b"!!!!!!!!!!!!!!!!",
                b"_",
                PortableFindIterLimits::unlimited(),
                ValueReplacementOutputLimits::default(),
            )
            .expect("byte-class no-match replacement");
        let absent_change = absent_region.change();
        assert!(matches!(absent, Cow::Borrowed(_)));
        assert_eq!(absent_change, Stats::default(), "{pattern:?}");

        let matched_region = Region::new(GLOBAL);
        let matched = regex
            .replace_literal_value(
                matched_haystack,
                b"_",
                PortableFindIterLimits::unlimited(),
                ValueReplacementOutputLimits::default(),
            )
            .expect("byte-class matched replacement");
        let matched_change = matched_region.change();
        assert!(matches!(matched, Cow::Owned(_)));
        assert_eq!(matched.as_ref(), expected, "{pattern:?}");
        assert_eq!(
            matched_change.allocations, 1,
            "{pattern:?} {matched_change:?}"
        );
        assert_eq!(
            matched_change.reallocations, 0,
            "{pattern:?} {matched_change:?}"
        );
        assert_eq!(
            matched_change.deallocations, 0,
            "{pattern:?} {matched_change:?}"
        );
    }
}
