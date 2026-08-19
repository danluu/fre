use fre::{
    BuildLimits, PlanKind, PlanSelection, PortableBuilder, PortableRegex, SearchLimits,
    SearchSessionLimits, SearchWindow,
};

const PATTERN: &str = r"(?-u:[A-Za-z0-9_]+).*MANDATORY.*z";

fn build(pattern: &str, selection: PlanSelection, limits: BuildLimits) -> PortableRegex {
    PortableBuilder::new(pattern)
        .plan_selection(selection)
        .limits(limits)
        .build()
        .unwrap_or_else(|error| panic!("failed to build {pattern:?}/{selection:?}: {error}"))
}

fn auto(pattern: &str) -> PortableRegex {
    build(pattern, PlanSelection::Auto, BuildLimits::default())
}

fn forced(pattern: &str) -> PortableRegex {
    build(pattern, PlanSelection::ForceK0, BuildLimits::default())
}

fn put(haystack: &mut [u8], start: usize, bytes: &[u8]) {
    haystack[start..start + bytes.len()].copy_from_slice(bytes);
}

#[test]
fn auto_k0_retains_only_general_mandatory_literals() {
    let optimized = auto(PATTERN);
    let oracle = forced(PATTERN);
    assert_eq!(optimized.build_report().plan, PlanKind::K0);
    assert_eq!(oracle.build_report().plan, PlanKind::K0);
    assert_eq!(optimized.k0_negative_prefilter_needle_bytes(), Some(9));
    assert_eq!(optimized.k0_negative_prefilter_needle_count(), 2);
    assert_eq!(oracle.k0_negative_prefilter_needle_bytes(), None);
    assert_eq!(oracle.k0_negative_prefilter_needle_count(), 0);
    assert!(optimized.build_report().planner_work > oracle.build_report().planner_work);
    assert!(optimized.build_report().plan_storage_bytes > oracle.build_report().plan_storage_bytes);

    assert_eq!(
        auto(r"(?-u:[A-Za-z0-9_]+).*XYZ.*z").k0_negative_prefilter_needle_bytes(),
        Some(3)
    );
    assert_eq!(
        auto(r"(?-u:[A-Za-z0-9_]+).*XY.*z").k0_negative_prefilter_needle_bytes(),
        Some(2)
    );
    assert_eq!(
        auto(r"a(?:MANDATORY)?.*z").k0_negative_prefilter_needle_bytes(),
        Some(1)
    );
    for pattern in [
        r"(?:a.*MANDATORY.*z)?",
        r"(?:a.*LEFT.*z|q.*RIGHT.*r)",
        r"\Aa.*MANDATORY.*z",
    ] {
        assert_eq!(
            auto(pattern).k0_negative_prefilter_needle_bytes(),
            None,
            "pattern={pattern:?}"
        );
    }
    let prefixed = auto(r"a.*MANDATORY.*z");
    assert_eq!(prefixed.k0_negative_prefilter_needle_bytes(), Some(9));
    assert_eq!(prefixed.k0_negative_prefilter_needle_count(), 3);
}

#[test]
fn reusable_values_match_forced_k0_across_negative_positive_and_windows() {
    let optimized = auto(PATTERN);
    let oracle = forced(PATTERN);
    let mut optimized_session = optimized
        .search_session(SearchSessionLimits::unlimited())
        .expect("optimized session");
    let mut oracle_session = oracle
        .search_session(SearchSessionLimits::unlimited())
        .expect("oracle session");
    let mut cases = vec![vec![b'x'; 4_096]];
    let mut present_reject = cases[0].clone();
    put(&mut present_reject, 2_000, b"MANDATORY");
    cases.push(present_reject);
    let mut matched = cases[0].clone();
    matched[100] = b'a';
    put(&mut matched, 200, b"MANDATORY");
    matched[300] = b'z';
    cases.push(matched);

    let windows = [
        SearchWindow::new(0, 1_023),
        SearchWindow::new(0, 1_024),
        SearchWindow::new(0, 4_096),
        SearchWindow::new(101, 4_096),
        SearchWindow::new(1_500, 3_500),
        SearchWindow::new(4_096, 4_096),
    ];
    for haystack in &cases {
        assert_eq!(
            optimized_session.is_match_value(haystack, SearchLimits::unlimited()),
            oracle_session.is_match_value(haystack, SearchLimits::unlimited())
        );
        assert_eq!(
            optimized_session.find_value(haystack, SearchLimits::unlimited()),
            oracle_session.find_value(haystack, SearchLimits::unlimited())
        );
        for &window in &windows {
            assert_eq!(
                optimized_session.is_match_window_value(
                    haystack,
                    window,
                    SearchLimits::unlimited()
                ),
                oracle_session.is_match_window_value(haystack, window, SearchLimits::unlimited())
            );
            assert_eq!(
                optimized_session.find_window_value(haystack, window, SearchLimits::unlimited()),
                oracle_session.find_window_value(haystack, window, SearchLimits::unlimited())
            );
        }
    }
}

#[test]
fn errors_accounting_and_reuse_remain_plain_k0() {
    let optimized = auto(PATTERN);
    let oracle = forced(PATTERN);
    let mut optimized_session = optimized
        .search_session(SearchSessionLimits::unlimited())
        .expect("optimized session");
    let mut oracle_session = oracle
        .search_session(SearchSessionLimits::unlimited())
        .expect("oracle session");
    let absent = vec![b'x'; 4_096];

    for invalid in [
        SearchWindow::new(10, 9),
        SearchWindow::new(0, absent.len() + 1),
    ] {
        assert_eq!(
            optimized_session.is_match_window_value(&absent, invalid, SearchLimits::unlimited()),
            oracle_session.is_match_window_value(&absent, invalid, SearchLimits::unlimited())
        );
    }
    let finite = SearchLimits {
        max_work: 0,
        max_scratch_bytes: usize::MAX,
    };
    assert_eq!(
        optimized_session.is_match_value(&absent, finite),
        oracle_session.is_match_value(&absent, finite)
    );
    assert_eq!(
        optimized_session.find_value(&absent, finite),
        oracle_session.find_value(&absent, finite)
    );
    assert!(optimized_session.is_match_value(&absent, finite).is_err());

    let mut optimized_accounted = optimized
        .search_session(SearchSessionLimits::unlimited())
        .expect("optimized accounted session");
    let mut oracle_accounted = oracle
        .search_session(SearchSessionLimits::unlimited())
        .expect("oracle accounted session");
    assert_eq!(
        optimized_accounted.is_match(&absent, SearchLimits::unlimited()),
        oracle_accounted.is_match(&absent, SearchLimits::unlimited())
    );
    assert_eq!(
        optimized_accounted.find(&absent, SearchLimits::unlimited()),
        oracle_accounted.find(&absent, SearchLimits::unlimited())
    );

    let mut reused = absent;
    let address = reused.as_ptr();
    assert!(
        !optimized_session
            .is_match_value(&reused, SearchLimits::unlimited())
            .unwrap()
    );
    reused[100] = b'a';
    put(&mut reused, 200, b"MANDATORY");
    reused[300] = b'z';
    assert_eq!(address, reused.as_ptr());
    assert!(
        optimized_session
            .is_match_value(&reused, SearchLimits::unlimited())
            .unwrap()
    );
    reused.fill(b'x');
    assert_eq!(address, reused.as_ptr());
    assert!(
        !optimized_session
            .is_match_value(&reused, SearchLimits::unlimited())
            .unwrap()
    );

    let other = auto(r"(?-u:[A-Za-z0-9_]+).*REQUIRED.*r");
    let mut other_session = other
        .search_session(SearchSessionLimits::unlimited())
        .expect("other session");
    reused[10] = b'q';
    put(&mut reused, 20, b"REQUIRED");
    reused[40] = b'r';
    assert!(
        !optimized_session
            .is_match_value(&reused, SearchLimits::unlimited())
            .unwrap()
    );
    assert!(
        other_session
            .is_match_value(&reused, SearchLimits::unlimited())
            .unwrap()
    );
}

#[test]
fn optional_sidecar_closes_planner_literal_and_persistent_limits() {
    let optimized = auto(PATTERN);
    let oracle = forced(PATTERN);

    let mut limits = BuildLimits::default();
    limits.max_persistent_bytes = oracle.build_report().charged_persistent_bytes;
    let persistent_declined = build(PATTERN, PlanSelection::Auto, limits);
    assert_eq!(
        persistent_declined.k0_negative_prefilter_needle_bytes(),
        None
    );
    assert_eq!(
        persistent_declined.build_report().plan_storage_bytes,
        oracle.build_report().plan_storage_bytes
    );

    let mut lower = oracle.build_report().charged_persistent_bytes;
    let mut upper = optimized.build_report().charged_persistent_bytes;
    while lower < upper {
        let remaining = upper.checked_sub(lower).expect("ordered sidecar bounds");
        let middle = lower
            .checked_add(remaining / 2)
            .expect("sidecar midpoint fits usize");
        let mut boundary = BuildLimits::default();
        boundary.max_persistent_bytes = middle;
        if build(PATTERN, PlanSelection::Auto, boundary).k0_negative_prefilter_needle_bytes()
            == Some(9)
        {
            upper = middle;
        } else {
            lower = middle + 1;
        }
    }
    let exact_sidecar_bytes = lower;
    limits = BuildLimits::default();
    limits.max_persistent_bytes = exact_sidecar_bytes;
    assert_eq!(
        build(PATTERN, PlanSelection::Auto, limits).k0_negative_prefilter_needle_bytes(),
        Some(9)
    );
    limits.max_persistent_bytes = exact_sidecar_bytes
        .checked_sub(1)
        .expect("retained sidecar requires nonzero persistent storage");
    assert_eq!(
        build(PATTERN, PlanSelection::Auto, limits).k0_negative_prefilter_needle_bytes(),
        None
    );

    limits = BuildLimits::default();
    limits.literal.max_needle_bytes = 8;
    assert_eq!(
        build(PATTERN, PlanSelection::Auto, limits).k0_negative_prefilter_needle_bytes(),
        Some(1)
    );

    let retains_at_work = |maximum| {
        let mut boundary = BuildLimits::default();
        boundary.max_planner_work = maximum;
        build(PATTERN, PlanSelection::Auto, boundary).k0_negative_prefilter_needle_bytes()
            == Some(9)
    };
    let mut lower = 0;
    let mut upper = optimized.build_report().planner_work;
    while lower < upper {
        let remaining = upper.checked_sub(lower).expect("ordered planner bounds");
        let middle = lower
            .checked_add(remaining / 2)
            .expect("planner midpoint fits u64");
        if retains_at_work(middle) {
            upper = middle;
        } else {
            lower = middle.checked_add(1).expect("planner lower bound fits u64");
        }
    }
    let exact_sidecar_work = lower;
    limits = BuildLimits::default();
    limits.max_planner_work = exact_sidecar_work;
    assert_eq!(
        build(PATTERN, PlanSelection::Auto, limits).k0_negative_prefilter_needle_bytes(),
        Some(9)
    );
    let one_below_sidecar_work = exact_sidecar_work
        .checked_sub(1)
        .expect("retained sidecar requires nonzero planner work");
    assert!(!retains_at_work(one_below_sidecar_work));
    let mut one_below_limits = BuildLimits::default();
    one_below_limits.max_planner_work = one_below_sidecar_work;
    assert_eq!(
        build(PATTERN, PlanSelection::Auto, one_below_limits)
            .build_report()
            .planner_work,
        one_below_sidecar_work,
    );
}
