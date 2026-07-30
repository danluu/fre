#![forbid(unsafe_code)]

use fre::{
    K0SearchError, Match, PlanKind, PlanSelection, PortableBuilder, PortableFindIterAccounting,
    PortableFindIterError, PortableFindIterLimits, PortableFindIterRunLimits, PortableTextBuilder,
    SearchAccounting, SearchError, SearchLimits, SearchSessionLimits,
};

fn spans(matches: &[Match]) -> Vec<(usize, usize)> {
    matches
        .iter()
        .map(|matched| (matched.start(), matched.end()))
        .collect()
}

#[derive(Clone, Copy)]
struct ByteCase {
    name: &'static str,
    pattern: &'static str,
    selection: PlanSelection,
    plan: PlanKind,
    first: &'static [u8],
    second: &'static [u8],
}

#[test]
fn byte_sessions_compose_native_and_bound_k0_iteration_shapes() {
    let cases = [
        ByteCase {
            name: "native positive",
            pattern: "Sherlock",
            selection: PlanSelection::Auto,
            plan: PlanKind::ExactLiteral,
            first: b"xxSherlockyy",
            second: b"Sherlock--Sherlock",
        },
        ByteCase {
            name: "K0 positive",
            pattern: "(?:ab)+",
            selection: PlanSelection::ForceK0,
            plan: PlanKind::K0,
            first: b"xxababyyab",
            second: b"ab--abab",
        },
        ByteCase {
            name: "K0 nullable",
            pattern: "(?:a+|)",
            selection: PlanSelection::ForceK0,
            plan: PlanKind::K0,
            first: b"aa-b",
            second: b"\xffa",
        },
        ByteCase {
            name: "K0 contextual",
            pattern: r"(?m:^a$)|(?:ab)+",
            selection: PlanSelection::ForceK0,
            plan: PlanKind::K0,
            first: b"a\nxxabab\na\n",
            second: b"zzab\nb\n",
        },
    ];

    for case in cases {
        let regex = PortableBuilder::new(case.pattern)
            .unicode(false)
            .plan_selection(case.selection)
            .build()
            .unwrap_or_else(|error| panic!("{}: portable build failed: {error}", case.name));
        assert_eq!(regex.build_report().plan, case.plan, "{}: plan", case.name);
        let upstream = regex::bytes::RegexBuilder::new(case.pattern)
            .unicode(false)
            .build()
            .unwrap_or_else(|error| panic!("{}: upstream build failed: {error}", case.name));
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap_or_else(|error| panic!("{}: session setup failed: {error}", case.name));
        let setup = session.workspace_setup_accounting();
        assert_eq!(
            setup.is_some(),
            case.plan == PlanKind::K0,
            "{}: setup",
            case.name
        );

        let direct_expected = upstream
            .find(case.first)
            .map(|matched| (matched.start(), matched.end()));
        let (direct_actual, accounting) = session
            .find(case.first, SearchLimits::unlimited())
            .unwrap_or_else(|error| panic!("{}: bound find failed: {error}", case.name));
        assert_eq!(
            direct_actual.map(|matched| (matched.start(), matched.end())),
            direct_expected,
            "{}: bound find",
            case.name
        );
        if let SearchAccounting::K0(accounting) = accounting {
            assert!(
                accounting.setup().reused(),
                "{}: bound workspace",
                case.name
            );
        } else {
            assert_ne!(case.plan, PlanKind::K0, "{}: accounting plan", case.name);
        }

        for haystack in [case.first, case.second] {
            let expected = upstream
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            let mut iterator = session.find_iter(haystack, PortableFindIterRunLimits::unlimited());
            assert_eq!(
                iterator.accounting(),
                PortableFindIterAccounting::default(),
                "{}: fresh iterator accounting",
                case.name
            );
            assert_eq!(
                iterator.workspace_setup_accounting(),
                setup,
                "{}: stable setup accounting",
                case.name
            );
            let actual = iterator
                .by_ref()
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|error| panic!("{}: iteration failed: {error}", case.name));
            let iteration = iterator.accounting();
            assert_eq!(spans(&actual), expected, "{}: spans", case.name);
            assert_eq!(iteration.matches, expected.len(), "{}: matches", case.name);
            assert!(
                iteration.search_calls >= expected.len(),
                "{}: calls",
                case.name
            );
            assert!(iterator.next().is_none(), "{}: fused iterator", case.name);
        }
    }
}

#[derive(Clone, Copy)]
struct TextCase {
    name: &'static str,
    pattern: &'static str,
    selection: PlanSelection,
    plan: PlanKind,
    first: &'static str,
    second: &'static str,
}

#[test]
fn text_sessions_compose_native_and_bound_k0_iteration_shapes() {
    let cases = [
        TextCase {
            name: "native positive",
            pattern: "Sherlock",
            selection: PlanSelection::Auto,
            plan: PlanKind::ExactLiteral,
            first: "xxSherlockyy",
            second: "Sherlock—Sherlock",
        },
        TextCase {
            name: "K0 positive",
            pattern: "(?:ab)+",
            selection: PlanSelection::ForceK0,
            plan: PlanKind::K0,
            first: "xxababyyab",
            second: "éab—abab",
        },
        TextCase {
            name: "K0 nullable",
            pattern: "(?:a+|)",
            selection: PlanSelection::ForceK0,
            plan: PlanKind::K0,
            first: "aa-é",
            second: "éa",
        },
        TextCase {
            name: "K0 contextual",
            pattern: r"(?m:^a$)|(?:ab)+",
            selection: PlanSelection::ForceK0,
            plan: PlanKind::K0,
            first: "a\néabab\na\n",
            second: "é\nab\nb\n",
        },
    ];

    for case in cases {
        let regex = PortableTextBuilder::new(case.pattern)
            .plan_selection(case.selection)
            .build()
            .unwrap_or_else(|error| panic!("{}: portable build failed: {error}", case.name));
        assert_eq!(
            regex.build_report().portable.plan,
            case.plan,
            "{}: plan",
            case.name
        );
        let upstream = regex::Regex::new(case.pattern)
            .unwrap_or_else(|error| panic!("{}: upstream build failed: {error}", case.name));
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap_or_else(|error| panic!("{}: session setup failed: {error}", case.name));
        let setup = session.workspace_setup_accounting();
        assert_eq!(
            setup.is_some(),
            case.plan == PlanKind::K0,
            "{}: setup",
            case.name
        );

        for haystack in [case.first, case.second] {
            let expected = upstream
                .find_iter(haystack)
                .map(|matched| (matched.start(), matched.end()))
                .collect::<Vec<_>>();
            let mut iterator = session.find_iter(haystack, PortableFindIterRunLimits::unlimited());
            assert_eq!(
                iterator.accounting(),
                PortableFindIterAccounting::default(),
                "{}: fresh iterator accounting",
                case.name
            );
            assert_eq!(
                iterator.workspace_setup_accounting(),
                setup,
                "{}: stable setup accounting",
                case.name
            );
            let actual = iterator
                .by_ref()
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|error| panic!("{}: iteration failed: {error}", case.name));
            let iteration = iterator.accounting();
            assert_eq!(spans(&actual), expected, "{}: spans", case.name);
            assert_eq!(iteration.matches, expected.len(), "{}: matches", case.name);
            assert!(
                iteration.search_calls >= expected.len(),
                "{}: calls",
                case.name
            );
            assert!(iterator.next().is_none(), "{}: fused iterator", case.name);
        }
    }
}

#[test]
fn bound_iterator_recovers_after_mid_execution_work_refusal() {
    let regex = PortableBuilder::new("a+")
        .unicode(false)
        .plan_selection(PlanSelection::ForceK0)
        .build()
        .expect("positive K0");
    let haystack = b"a-----aaaaaaaaaaaaaaaa";
    let mut session = regex
        .search_session(SearchSessionLimits::unlimited())
        .expect("bound K0 session");

    let expected = {
        let mut warm = session.find_iter(haystack, PortableFindIterRunLimits::unlimited());
        warm.by_ref()
            .collect::<Result<Vec<_>, _>>()
            .expect("warm reference iteration")
    };
    assert_eq!(spans(&expected), vec![(0, 1), (6, haystack.len())]);

    let (first_work, second_work) = {
        let mut measured = session.find_iter(haystack, PortableFindIterRunLimits::unlimited());
        assert_eq!(measured.next(), Some(Ok(expected[0])));
        let first_work = measured.accounting().work_or_linear_terms;
        assert_eq!(measured.next(), Some(Ok(expected[1])));
        let second_work = measured
            .accounting()
            .work_or_linear_terms
            .checked_sub(first_work)
            .expect("cumulative iterator work is monotonic");
        (first_work, second_work)
    };
    assert!(
        second_work > first_work,
        "the second search must leave room for a successful first item"
    );
    let limit = second_work - 1;
    assert!(limit >= first_work);

    {
        let mut refused = session.find_iter(
            haystack,
            PortableFindIterRunLimits {
                search: SearchLimits {
                    max_work: limit,
                    max_scratch_bytes: usize::MAX,
                },
                max_search_calls: usize::MAX,
            },
        );
        assert_eq!(refused.next(), Some(Ok(expected[0])));
        match refused.next() {
            Some(Err(PortableFindIterError::Search(SearchError::K0(
                K0SearchError::WorkLimitExceeded {
                    consumed,
                    requested,
                    position,
                    ..
                },
            )))) => {
                assert!(consumed > 0);
                assert!(requested > 0);
                assert!(
                    position > expected[0].end(),
                    "refusal must occur after execution advances into the second search"
                );
            }
            other => panic!("expected mid-execution K0 work refusal, got {other:?}"),
        }
        assert_eq!(refused.accounting().search_calls, 2);
        assert_eq!(refused.accounting().matches, 1);
        assert!(refused.next().is_none(), "refused iterator must fuse");
    }

    let mut recovered = session.find_iter(haystack, PortableFindIterRunLimits::unlimited());
    assert_eq!(
        recovered.accounting(),
        PortableFindIterAccounting::default(),
        "recovered iterator owns a fresh ledger"
    );
    assert_eq!(
        recovered
            .by_ref()
            .collect::<Result<Vec<_>, _>>()
            .expect("iteration after refusal"),
        expected
    );
}

#[test]
fn full_iterator_limits_map_to_reused_run_limits_exactly() {
    let limits = PortableFindIterLimits {
        session: SearchSessionLimits {
            max_setup_work: 11,
            max_scratch_bytes: 13,
        },
        search: SearchLimits {
            max_work: 17,
            max_scratch_bytes: 19,
        },
        max_search_calls: 23,
    };
    assert_eq!(
        limits.run(),
        PortableFindIterRunLimits {
            search: limits.search,
            max_search_calls: limits.max_search_calls,
        }
    );
}
