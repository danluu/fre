use fre::{
    BuildError, BuildLimits, PlanKind, PortableBuilder, PortableRegex, SearchAccounting,
    SearchLimits, SearchWindow,
};

const SOURCE: &str = "(?i:\u{212A}\u{212A}\u{212A}\u{212A}a)";

#[test]
fn finite_unicode_fold_keeps_literal_set_identity_and_matches_all_windows() {
    let plan = PortableRegex::new(SOURCE).unwrap();
    assert_eq!(plan.build_report().plan, PlanKind::LiteralSetDfa);
    assert_eq!(plan.runtime_implementation_id(), "literal-set-dfa");

    let oracle = regex::bytes::Regex::new(SOURCE).unwrap();
    let mut haystack = vec![b'z'; 264];
    haystack.extend_from_slice(b"KKKKa");
    for start in 0..=haystack.len() {
        for end in start..=haystack.len() {
            let expected = oracle
                .find(&haystack[start..end])
                .map(|matched| (start + matched.start(), start + matched.end()));
            let (actual, accounting) = plan
                .find_window(
                    &haystack,
                    SearchWindow::new(start, end),
                    SearchLimits::unlimited(),
                )
                .unwrap();
            assert_eq!(
                actual.map(|matched| (matched.start(), matched.end())),
                expected,
                "window={start}..{end}"
            );
            assert!(matches!(accounting, SearchAccounting::LiteralSetDfa(_)));
        }
    }
}

#[test]
fn sparse_and_dense_long_sources_match_upstream() {
    let plan = PortableRegex::new(SOURCE).unwrap();
    let oracle = regex::bytes::Regex::new(SOURCE).unwrap();
    let sparse = {
        let mut source = vec![b'z'; 640];
        source.extend_from_slice(b"kkkkA");
        source
    };
    let dense = {
        let mut source = b"KKKKx".repeat(128);
        source.extend_from_slice(b"kkkkA");
        source
    };
    for haystack in [&sparse, &dense] {
        let expected = oracle
            .find(haystack)
            .map(|matched| (matched.start(), matched.end()));
        let (actual, accounting) = plan.find(haystack, SearchLimits::unlimited()).unwrap();
        assert_eq!(
            actual.map(|matched| (matched.start(), matched.end())),
            expected
        );
        let SearchAccounting::LiteralSetDfa(accounting) = accounting else {
            panic!("folded source left the literal-set facade");
        };
        assert!(
            accounting.transitions_upper_bound > haystack.len() + 1,
            "long case did not enter the adaptive tail"
        );
    }
}

#[test]
fn prefix_overlap_preserves_leftmost_semantics() {
    let source = "\u{212A}\u{03A3}aaaaaa|\u{03A3}a";
    let plan = PortableBuilder::new(source)
        .unicode(true)
        .case_insensitive(true)
        .build()
        .unwrap();
    assert_eq!(plan.build_report().plan, PlanKind::LiteralSetDfa);
    let mut oracle_builder = regex::bytes::RegexBuilder::new(source);
    let oracle = oracle_builder
        .unicode(true)
        .case_insensitive(true)
        .build()
        .unwrap();
    let mut haystack = vec![b'z'; 252];
    haystack.extend_from_slice("K\u{03A3}aaaaaa".as_bytes());
    let expected = oracle
        .find(&haystack)
        .map(|matched| (matched.start(), matched.end()));
    let (actual, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
    assert_eq!(
        actual.map(|matched| (matched.start(), matched.end())),
        expected
    );
    let SearchAccounting::LiteralSetDfa(accounting) = accounting else {
        panic!("folded overlap left the literal-set facade");
    };
    assert!(
        accounting.transitions_upper_bound > haystack.len() + 1,
        "overlap case did not enter the adaptive tail: work={}",
        accounting.transitions_upper_bound
    );
}

#[test]
fn finite_extraction_order_controls_equal_start_tail_priority() {
    let source = "(?i:\u{212A}|\u{212A}\u{212A}\u{212A}\u{212A}a)";
    let plan = PortableRegex::new(source).unwrap();
    assert_eq!(plan.build_report().plan, PlanKind::LiteralSetDfa);
    let oracle = regex::bytes::Regex::new(source).unwrap();
    let mut haystack = vec![b'z'; 260];
    haystack.extend_from_slice(b"KKKKa");
    let expected = oracle
        .find(&haystack)
        .map(|matched| (matched.start(), matched.end()));
    assert_eq!(expected, Some((260, 261)));

    let (actual, accounting) = plan.find(&haystack, SearchLimits::unlimited()).unwrap();
    assert_eq!(
        actual.map(|matched| (matched.start(), matched.end())),
        expected
    );
    let SearchAccounting::LiteralSetDfa(accounting) = accounting else {
        panic!("equal-start folded source left the literal-set facade");
    };
    assert!(
        accounting.transitions_upper_bound > haystack.len() + 1,
        "equal-start case did not enter the adaptive tail"
    );
}

#[test]
fn optional_tail_resource_refusal_preserves_exact_planner_work() {
    let baseline = PortableRegex::new(SOURCE).unwrap();
    let required_work = baseline.build_report().planner_work;
    let required_bytes = baseline.build_report().charged_persistent_bytes;
    assert!(required_work > 0);
    assert!(required_bytes > 0);

    let planner_declined = PortableBuilder::new(SOURCE)
        .limits(BuildLimits {
            max_planner_work: required_work - 1,
            ..BuildLimits::default()
        })
        .build()
        .unwrap();
    let incumbent_work = planner_declined.build_report().planner_work;
    assert_eq!(
        planner_declined.build_report().plan,
        PlanKind::LiteralSetDfa
    );
    assert!(incumbent_work > 0);
    assert!(incumbent_work < required_work);
    assert!(
        planner_declined.build_report().plan_storage_bytes
            < baseline.build_report().plan_storage_bytes,
        "insufficient prospective planner room must retain the incumbent"
    );

    let tight_bytes = required_bytes - 1;
    let refused_tail = PortableBuilder::new(SOURCE)
        .limits(BuildLimits {
            max_persistent_bytes: tight_bytes,
            ..BuildLimits::default()
        })
        .build()
        .unwrap();
    assert_eq!(refused_tail.build_report().plan, PlanKind::LiteralSetDfa);
    assert_eq!(refused_tail.build_report().planner_work, required_work);
    assert!(
        refused_tail.build_report().plan_storage_bytes < baseline.build_report().plan_storage_bytes
    );

    let exact_incumbent = PortableBuilder::new(SOURCE)
        .limits(BuildLimits {
            max_planner_work: incumbent_work,
            ..BuildLimits::default()
        })
        .build()
        .unwrap();
    assert_eq!(exact_incumbent.build_report().plan, PlanKind::LiteralSetDfa);
    assert_eq!(exact_incumbent.build_report().planner_work, incumbent_work);
    assert!(matches!(
        PortableBuilder::new(SOURCE)
            .limits(BuildLimits {
                max_planner_work: incumbent_work - 1,
                ..BuildLimits::default()
            })
            .build(),
        Err(BuildError::PlannerWorkLimit { needed, limit })
            if needed == incumbent_work && limit == incumbent_work - 1
    ));
}
