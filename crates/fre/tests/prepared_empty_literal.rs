use fre::{PlanKind, PortableBuilder, SearchLimits, SearchSessionLimits};

#[test]
fn prepared_empty_literal_is_source_free_bounded_and_plan_checked() {
    let limits = SearchLimits {
        max_work: 5,
        max_scratch_bytes: 0,
    };
    for unicode in [false, true] {
        let regex = PortableBuilder::new("").unicode(unicode).build().unwrap();
        assert_eq!(regex.build_report().plan, PlanKind::ExactLiteral);
        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        let token = session.prepare_is_match_value_token(8, limits);
        assert!(token.uses_prepared_route());
        assert!(token.uses_empty_literal_route());
        assert_eq!(token.maximum_warm_input_bytes(), Some(5));
        for haystack in [
            b"".as_slice(),
            b"a",
            b"12345",
            b"123456",
            b"\xFF\xFE\x80",
        ] {
            assert_eq!(
                session.is_match_value_prepared(haystack, token),
                regex.is_match_value(haystack, limits),
                "unicode={unicode}, haystack={haystack:?}",
            );
        }

        assert!(regex.is_match_value(b"123456", limits).is_err());
    }

    let empty = PortableBuilder::new("").unicode(false).build().unwrap();
    let mut empty_session = empty
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    let wider = SearchLimits {
        max_work: 8,
        max_scratch_bytes: 0,
    };
    let narrow = empty_session.prepare_is_match_value_token(2, wider);
    assert_eq!(narrow.maximum_warm_input_bytes(), Some(2));
    assert_eq!(
        empty_session.is_match_value_prepared(b"12345", narrow),
        empty.is_match_value(b"12345", wider),
    );

    let zero = SearchLimits {
        max_work: 0,
        max_scratch_bytes: 0,
    };
    let zero_token = empty_session.prepare_is_match_value_token(usize::MAX, zero);
    assert!(zero_token.uses_empty_literal_route());
    assert_eq!(zero_token.maximum_warm_input_bytes(), Some(0));
    assert!(
        empty_session
            .is_match_value_prepared(b"", zero_token)
            .unwrap()
    );
    assert_eq!(
        empty_session.is_match_value_prepared(b"x", zero_token),
        empty.is_match_value(b"x", zero),
    );

    let nonempty = PortableBuilder::new("x").unicode(false).build().unwrap();
    let mut nonempty_session = nonempty
        .search_session(SearchSessionLimits::unlimited())
        .unwrap();
    assert_eq!(
        nonempty_session.is_match_value_prepared(b"ordinary", zero_token),
        nonempty.is_match_value(b"ordinary", zero),
    );
}
