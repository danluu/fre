use fre_conformance::{
    Agreement, CanonicalSpan, CaseAst, ConformanceCase, Greed, Harness, HarnessLimits, Outcome,
    RefusalKind, UPSTREAM_RUST_REGEX_BASELINE, UnsupportedFeature,
};

fn compare(id: &str, ast: CaseAst, haystack: &[u8]) -> fre_conformance::EngineRecord {
    Harness::new(HarnessLimits::default()).compare(&ConformanceCase::full(
        id,
        0x4652_4543_4f4e_4631,
        0,
        ast,
        haystack.to_vec(),
    ))
}

#[test]
fn canonical_records_cover_every_capture_free_contract() {
    let record = compare(
        "literal-ab",
        CaseAst::Concat(vec![CaseAst::Byte(b'a'), CaseAst::Byte(b'b')]),
        b"zabab",
    );
    assert_eq!(record.agreement, Agreement::Equal);
    assert_eq!(record.oracle.exists, Outcome::Value(true));
    assert_eq!(record.oracle.selected_end, Outcome::Value(Some(3)));
    assert_eq!(
        record.oracle.span,
        Outcome::Value(Some(CanonicalSpan::new(1, 3)))
    );
    assert_eq!(
        record.oracle.global,
        Outcome::Value(vec![CanonicalSpan::new(1, 3), CanonicalSpan::new(3, 5)])
    );
}

#[test]
fn alternation_and_repetition_priority_are_differentially_checked() {
    let short_first = compare(
        "a-or-ab",
        CaseAst::Alt(vec![
            CaseAst::Byte(b'a'),
            CaseAst::Concat(vec![CaseAst::Byte(b'a'), CaseAst::Byte(b'b')]),
        ]),
        b"ab",
    );
    assert_eq!(short_first.agreement, Agreement::Equal);
    assert_eq!(
        short_first.production.span,
        Outcome::Value(Some(CanonicalSpan::new(0, 1)))
    );

    for (greed, end) in [(Greed::Greedy, 3), (Greed::Lazy, 0)] {
        let record = compare(
            "star-priority",
            CaseAst::Repeat {
                child: Box::new(CaseAst::Byte(b'a')),
                min: 0,
                max: None,
                greed,
            },
            b"aaa",
        );
        assert_eq!(record.agreement, Agreement::Equal);
        assert_eq!(
            record.production.span,
            Outcome::Value(Some(CanonicalSpan::new(0, end)))
        );
    }
}

#[test]
fn global_empty_suppression_is_part_of_the_record() {
    let empties = compare("empty", CaseAst::Empty, b"ab");
    assert_eq!(empties.agreement, Agreement::Equal);
    assert_eq!(
        empties.production.global,
        Outcome::Value(vec![
            CanonicalSpan::new(0, 0),
            CanonicalSpan::new(1, 1),
            CanonicalSpan::new(2, 2),
        ])
    );

    let adjacent = compare(
        "nonempty-then-adjacent-empty",
        CaseAst::Alt(vec![CaseAst::Byte(b'a'), CaseAst::Empty]),
        b"a",
    );
    assert_eq!(adjacent.agreement, Agreement::Equal);
    assert_eq!(
        adjacent.production.global,
        Outcome::Value(vec![CanonicalSpan::new(0, 1)])
    );
}

#[test]
fn anchors_keep_original_context_for_ranged_start() {
    let mut case = ConformanceCase::full(
        "ranged-start-anchor",
        7,
        0,
        CaseAst::Concat(vec![CaseAst::StartText, CaseAst::Byte(b'a')]),
        b"za".to_vec(),
    );
    case.window_start = 1;
    let record = Harness::new(HarnessLimits::default()).compare(&case);
    assert_eq!(record.agreement, Agreement::Equal);
    assert_eq!(record.production.span, Outcome::Value(None));

    let end = compare(
        "end-anchor",
        CaseAst::Concat(vec![CaseAst::Byte(b'a'), CaseAst::EndText]),
        b"za",
    );
    assert_eq!(end.agreement, Agreement::Equal);
    assert_eq!(
        end.production.span,
        Outcome::Value(Some(CanonicalSpan::new(1, 2)))
    );
}

#[test]
fn truncated_oracle_windows_are_never_reported_as_passes() {
    let mut case = ConformanceCase::full("truncated", 9, 0, CaseAst::Byte(b'a'), b"az".to_vec());
    case.window_end = 1;
    let record = Harness::new(HarnessLimits::default()).compare(&case);
    assert_eq!(record.agreement, Agreement::NotComparable);
    assert_eq!(
        record.oracle.span,
        Outcome::Unsupported(UnsupportedFeature::TruncatedReferenceWindow)
    );
    assert_eq!(
        record.production.span,
        Outcome::Value(Some(CanonicalSpan::new(0, 1)))
    );
}

#[test]
fn nullable_unbounded_loop_priority_is_an_explicit_gate() {
    for (child, expected) in [
        (
            CaseAst::Alt(vec![CaseAst::Empty, CaseAst::Byte(b'a')]),
            CanonicalSpan::new(0, 0),
        ),
        (
            CaseAst::Alt(vec![CaseAst::Byte(b'a'), CaseAst::Empty]),
            CanonicalSpan::new(0, 1),
        ),
    ] {
        let record = compare(
            "nullable-unbounded-loop",
            CaseAst::Repeat {
                child: Box::new(child),
                min: 0,
                max: None,
                greed: Greed::Greedy,
            },
            b"a",
        );
        assert_eq!(record.agreement, Agreement::NotComparable);
        assert_eq!(record.oracle.span, Outcome::Value(Some(expected)));
        assert_eq!(
            record.production.span,
            Outcome::Unsupported(UnsupportedFeature::NullableUnboundedRepeat)
        );
    }
}

#[test]
fn pinned_upstream_is_labelled_secondary_not_oracle() {
    assert_eq!(UPSTREAM_RUST_REGEX_BASELINE.version, "1.12.4");
    assert_eq!(
        UPSTREAM_RUST_REGEX_BASELINE.role,
        "secondary upstream comparator"
    );
    let regex = regex::bytes::Regex::new("ab").expect("pinned baseline accepts literal");
    assert_eq!(
        regex.find(b"zab").map(|matched| matched.range()),
        Some(1..3)
    );
}

#[test]
fn aggregate_comparison_work_cap_is_conservative_and_visible() {
    let limits = HarnessLimits {
        max_total_search_work: 1,
        ..HarnessLimits::default()
    };
    let record = Harness::new(limits).compare(&ConformanceCase::full(
        "aggregate-work-refusal",
        11,
        0,
        CaseAst::Byte(b'a'),
        b"a".to_vec(),
    ));
    assert_eq!(record.agreement, Agreement::NotComparable);
    assert_eq!(
        record.oracle.span,
        Outcome::Refused(RefusalKind::SearchWork)
    );
    assert_eq!(record.production.span, record.oracle.span);
}
