use fre::{
    PortableBuilder, QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION,
    QUALIFIED_EXACT_SEARCH_MIN_SEARCHES, QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
    QUALIFIED_EXACT_SEARCH_QUALIFICATION, QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_QUALIFICATION,
    QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION,
    QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION, QualifiedExactSearch,
    QualifiedExactSearchBackendPolicy, QualifiedExactSearchError, QualifiedExactSearchFacadeError,
    QualifiedExactSearchFacadeRoute, QualifiedExactSearchNativeStatus,
    QualifiedExactSearchQualification, QualifiedExactSearchRoute, QualifiedExactSearchWorkload,
    SearchLimits, SearchWindow,
};
use fre_jit_aarch64::EmitLimits;
use fre_jit_runtime::{CallError, PublicationLimits};
use fre_kernel_ir::ValidateLimits;
use fre_kernels::LiteralBuildLimits;

const QUALIFIED_WORKLOAD: QualifiedExactSearchWorkload = QualifiedExactSearchWorkload::new(
    QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
    QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
);
#[test]
fn qualified_router_uses_only_the_declared_width_and_window_envelope() {
    for atom in [
        QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION,
        QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION,
        QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_QUALIFICATION,
        QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION,
    ] {
        assert_eq!(atom, QualifiedExactSearchQualification::Candidate);
        assert!(!atom.is_authorized());
    }
    let literal = b"0123456789abcdef";
    let search =
        QualifiedExactSearch::new(literal, QUALIFIED_WORKLOAD).expect("qualified exact matcher");
    assert_eq!(
        search.build_report().backend_policy,
        QualifiedExactSearchBackendPolicy::AsimdV8
    );
    assert_eq!(
        search.build_report().qualification,
        QualifiedExactSearchQualification::Candidate
    );
    assert_eq!(
        search.build_report().qualification,
        QUALIFIED_EXACT_SEARCH_QUALIFICATION
    );
    assert_eq!(
        search
            .build_report()
            .qualification
            .authorized_bundle_sha256(),
        None
    );
    assert!(!search.build_report().qualification.is_authorized());
    assert_eq!(
        search.build_report().native,
        QualifiedExactSearchNativeStatus::Unqualified {
            qualification: QualifiedExactSearchQualification::Candidate,
        }
    );
    let short = vec![b'x'; QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES - 1];
    let (_, short_execution) = search
        .find(&short, SearchLimits::unlimited())
        .expect("short portable search");
    assert_eq!(
        short_execution.route,
        QualifiedExactSearchRoute::PortableLiteral
    );

    let mut threshold = vec![b'x'; QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES];
    let threshold_match_start = threshold.len() - literal.len();
    threshold[threshold_match_start..].copy_from_slice(literal);
    let (matched, threshold_execution) = search
        .find(&threshold, SearchLimits::unlimited())
        .expect("threshold search");
    assert_eq!(
        matched.map(|span| (span.start(), span.end())),
        Some((threshold.len() - literal.len(), threshold.len()))
    );
    assert_eq!(
        threshold_execution.route,
        QualifiedExactSearchRoute::PortableLiteral
    );

    let other_width = QualifiedExactSearch::new(b"fifteen-byte-li", QUALIFIED_WORKLOAD)
        .expect("portable-only exact matcher");
    assert!(matches!(
        other_width.build_report().native,
        QualifiedExactSearchNativeStatus::IneligibleLiteralWidth { .. }
    ));
    let (_, execution) = other_width
        .find(&threshold, SearchLimits::unlimited())
        .expect("other width search");
    assert_eq!(execution.route, QualifiedExactSearchRoute::PortableLiteral);

    let under_reused = QualifiedExactSearch::new(
        literal,
        QualifiedExactSearchWorkload::new(
            QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
            QUALIFIED_EXACT_SEARCH_MIN_SEARCHES - 1,
        ),
    )
    .expect("under-reused portable matcher");
    assert!(matches!(
        under_reused.build_report().native,
        QualifiedExactSearchNativeStatus::IneligibleWorkload {
            required_searches: Some(QUALIFIED_EXACT_SEARCH_MIN_SEARCHES),
            ..
        }
    ));
    let (_, execution) = under_reused
        .find(&threshold, SearchLimits::unlimited())
        .expect("under-reused portable search");
    assert_eq!(execution.route, QualifiedExactSearchRoute::PortableLiteral);
}

#[test]
fn explicit_backend_policy_is_retained_while_candidate_fails_closed() {
    for policy in [
        QualifiedExactSearchBackendPolicy::AsimdV7,
        QualifiedExactSearchBackendPolicy::AsimdV8,
        QualifiedExactSearchBackendPolicy::Sve16,
        QualifiedExactSearchBackendPolicy::Sve2Fixed16,
        QualifiedExactSearchBackendPolicy::Sve16V6,
        QualifiedExactSearchBackendPolicy::Sve2Fixed16V2,
    ] {
        let search =
            QualifiedExactSearch::new_with_backend(b"0123456789abcdef", QUALIFIED_WORKLOAD, policy)
                .expect("policy-selected exact matcher");
        let report = search.build_report();
        assert_eq!(report.backend_policy, policy);
        assert_eq!(
            report.qualification,
            QualifiedExactSearchQualification::Candidate
        );
        assert_eq!(
            report.native,
            QualifiedExactSearchNativeStatus::Unqualified {
                qualification: QualifiedExactSearchQualification::Candidate,
            }
        );
    }
}

#[test]
fn qualification_state_rejects_zero_and_invalidated_historical_hashes() {
    let zero = QualifiedExactSearchQualification::Qualified {
        bundle_sha256: [0; 32],
    };
    assert_eq!(zero.authorized_bundle_sha256(), None);
    assert!(!zero.is_authorized());

    let invalidated_pre_q8 = QualifiedExactSearchQualification::Qualified {
        bundle_sha256: [
            0x89, 0xaf, 0x5a, 0x04, 0x19, 0x0a, 0x39, 0xc4, 0x0a, 0x48, 0x19, 0xce, 0x91, 0x6f,
            0xc2, 0x86, 0x30, 0x33, 0x05, 0x50, 0xe1, 0xca, 0xfc, 0x15, 0xe9, 0x91, 0x91, 0x22,
            0xaf, 0x0a, 0xe9, 0xf7,
        ],
    };
    assert_eq!(invalidated_pre_q8.authorized_bundle_sha256(), None);
    assert!(!invalidated_pre_q8.is_authorized());

    let retired_v7 = QualifiedExactSearchQualification::Qualified {
        bundle_sha256: [
            0xde, 0x08, 0x4f, 0xf0, 0x56, 0x4a, 0xcd, 0xb8, 0x98, 0x89, 0xf2, 0x8b, 0x9d, 0xcf,
            0xdd, 0xce, 0x9b, 0x6f, 0x09, 0x55, 0xa1, 0xb2, 0xae, 0xad, 0x30, 0xd7, 0x57, 0x70,
            0x03, 0x9e, 0x04, 0x53,
        ],
    };
    assert_eq!(retired_v7.authorized_bundle_sha256(), None);
    assert!(!retired_v7.is_authorized());

    let accepted = QualifiedExactSearchQualification::Qualified {
        bundle_sha256: [0x5a; 32],
    };
    assert_eq!(accepted.authorized_bundle_sha256(), Some([0x5a; 32]));
    assert!(accepted.is_authorized());
}

#[test]
fn qualified_router_preserves_windows_results_and_portable_refusals() {
    let literal = b"0123456789abcdef";
    let search =
        QualifiedExactSearch::new(literal, QUALIFIED_WORKLOAD).expect("qualified exact matcher");
    let session = search
        .begin_current_thread_session()
        .expect("Candidate portable session needs no host contract");
    for (prefix, tail, present) in [
        (0_usize, 0_usize, true),
        (31, 0, true),
        (17, 23, true),
        (63, QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES, true),
        (0, QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES, false),
    ] {
        let mut haystack = vec![b'x'; QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES + prefix + tail];
        let expected = if present {
            let start = prefix + (QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES / 2);
            haystack[start..start + literal.len()].copy_from_slice(literal);
            Some((start, start + literal.len()))
        } else {
            None
        };
        let window = SearchWindow::new(prefix, haystack.len() - tail);
        let (matched, execution) = search
            .find_window(&haystack, window, SearchLimits::unlimited())
            .expect("qualified window search");
        assert_eq!(
            matched.map(|span| (span.start(), span.end())),
            expected,
            "prefix={prefix} tail={tail} present={present}"
        );
        assert_eq!(execution.route, QualifiedExactSearchRoute::PortableLiteral);
        let (session_match, session_execution) = session
            .find_window(&haystack, window, SearchLimits::unlimited())
            .expect("reported session window search");
        assert_eq!(session_match, matched);
        assert_eq!(session_execution, execution);
        assert_eq!(
            session
                .find_window_value(&haystack, window, SearchLimits::unlimited())
                .expect("value-only session window search"),
            matched
        );
    }

    let haystack = vec![b'x'; QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES];
    let needed = haystack
        .len()
        .checked_add(literal.len())
        .expect("bounded linear terms");
    let limits = SearchLimits {
        max_work: u64::try_from(needed - 1).expect("u64 work"),
        max_scratch_bytes: usize::MAX,
    };
    let error = session
        .find(&haystack, limits)
        .expect_err("portable preflight remains authoritative");
    let value_error = session
        .find_value(&haystack, limits)
        .expect_err("value-only portable preflight remains authoritative");
    assert_eq!(value_error, error);
    assert!(matches!(
        error,
        fre::QualifiedExactSearchError::Portable(fre_kernels::LiteralError::LinearTermLimit { .. })
    ));
}

#[test]
fn qualified_facade_session_value_projection_preserves_public_contracts() {
    let literal = b"0123456789abcdef";
    let facade = PortableBuilder::new("0123456789abcdef")
        .build_qualified_exact_search(QUALIFIED_WORKLOAD)
        .expect("Candidate facade retains its exact portable owner");
    let session = facade
        .begin_current_thread_session()
        .expect("Candidate facade session needs no host contract");
    let prefix = 19;
    let tail = 11;
    let mut haystack = vec![b'x'; prefix + QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES + tail];
    let expected_start = prefix + 37;
    let expected_end = expected_start + literal.len();
    haystack[expected_start..expected_end].copy_from_slice(literal);
    let window = SearchWindow::new(prefix, haystack.len() - tail);

    let (reported, execution) = session
        .find_window(&haystack, window, SearchLimits::unlimited())
        .expect("reported facade window search");
    assert_eq!(
        execution.route,
        QualifiedExactSearchFacadeRoute::ExactLiteral(QualifiedExactSearchRoute::PortableLiteral)
    );
    assert_eq!(
        reported.map(|matched| (matched.start(), matched.end())),
        Some((expected_start, expected_end))
    );
    assert_eq!(
        session
            .find_window_value(&haystack, window, SearchLimits::unlimited())
            .expect("value-only facade window search"),
        reported
    );
    assert_eq!(
        session
            .find_at_value(&haystack, prefix, SearchLimits::unlimited())
            .expect("value-only facade start-offset search"),
        reported
    );
    assert_eq!(
        session
            .find_value(&haystack, SearchLimits::unlimited())
            .expect("value-only facade full search"),
        reported
    );
    assert_eq!(
        session
            .is_match_value(&haystack, SearchLimits::unlimited())
            .expect("value-only facade existence search"),
        reported.is_some()
    );

    let needed = haystack
        .len()
        .checked_add(literal.len())
        .expect("bounded facade linear terms");
    let refused_limits = SearchLimits {
        max_work: u64::try_from(needed - 1).expect("facade work fits u64"),
        max_scratch_bytes: usize::MAX,
    };
    let reporting_refusal = session
        .find(&haystack, refused_limits)
        .expect_err("reported facade call must preserve resource refusal");
    let value_refusal = session
        .find_value(&haystack, refused_limits)
        .expect_err("value-only facade call must preserve resource refusal");
    assert_eq!(value_refusal, reporting_refusal);

    let invalid = SearchWindow::new(haystack.len(), haystack.len() - 1);
    let reporting_invalid = session
        .find_window(&haystack, invalid, SearchLimits::unlimited())
        .expect_err("reported facade call must reject an invalid window");
    let value_invalid = session
        .find_window_value(&haystack, invalid, SearchLimits::unlimited())
        .expect_err("value-only facade call must reject an invalid window");
    assert_eq!(value_invalid, reporting_invalid);
}

#[test]
fn qualified_facade_value_projection_preserves_non_exact_portable_plan() {
    let facade = PortableBuilder::new("a+")
        .unicode(false)
        .build_qualified_exact_search(QUALIFIED_WORKLOAD)
        .expect("non-exact facade retains its selected portable plan");
    let session = facade
        .begin_current_thread_session()
        .expect("portable facade plan needs no host contract");
    let haystack = b"xxaaax";
    let (reported, execution) = session
        .find(haystack, SearchLimits::unlimited())
        .expect("reported non-exact facade search");
    assert!(matches!(
        execution.route,
        QualifiedExactSearchFacadeRoute::PortablePlan(_)
    ));
    assert_eq!(
        session
            .find_value(haystack, SearchLimits::unlimited())
            .expect("value-only non-exact facade search"),
        reported
    );
    assert_eq!(
        session
            .is_match_value(haystack, SearchLimits::unlimited())
            .expect("value-only non-exact facade existence search"),
        reported.is_some()
    );

    let invalid = SearchWindow::new(haystack.len(), haystack.len() - 1);
    let reporting_invalid = session
        .find_window(haystack, invalid, SearchLimits::unlimited())
        .expect_err("reported non-exact facade call must reject an invalid window");
    let value_invalid = session
        .find_window_value(haystack, invalid, SearchLimits::unlimited())
        .expect_err("value-only non-exact facade call must reject an invalid window");
    assert_eq!(value_invalid, reporting_invalid);
}

#[test]
fn qualified_router_matches_naive_leftmost_search_across_offsets() {
    let literal = b"0123456789abcdef";
    let search =
        QualifiedExactSearch::new(literal, QUALIFIED_WORKLOAD).expect("qualified exact matcher");
    for alignment in 0..32 {
        for position in [
            alignment,
            alignment + 1,
            alignment + 15,
            alignment + QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES - literal.len(),
        ] {
            let mut haystack = vec![b'x'; alignment + QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES + 32];
            haystack[position..position + literal.len()].copy_from_slice(literal);
            let window = SearchWindow::new(alignment, haystack.len());
            let (matched, _) = search
                .find_window(&haystack, window, SearchLimits::unlimited())
                .expect("differential exact search");
            let expected = haystack[window.start()..window.end()]
                .windows(literal.len())
                .position(|candidate| candidate == literal)
                .map(|relative| {
                    let start = window.start() + relative;
                    (start, start + literal.len())
                });
            assert_eq!(
                matched.map(|span| (span.start(), span.end())),
                expected,
                "alignment={alignment} position={position}"
            );
        }
    }
}

#[test]
fn qualified_router_selects_the_leftmost_match_in_a_nonzero_window() {
    let literal = b"0123456789abcdef";
    let search =
        QualifiedExactSearch::new(literal, QUALIFIED_WORKLOAD).expect("qualified exact matcher");
    let window_start = 23;
    let mut haystack = vec![b'x'; window_start + QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES + 41];
    let first = window_start + 15;
    let second = first + 97;
    haystack[first..first + literal.len()].copy_from_slice(literal);
    haystack[second..second + literal.len()].copy_from_slice(literal);
    let window = SearchWindow::new(window_start, haystack.len() - 7);
    let (matched, execution) = search
        .find_window(&haystack, window, SearchLimits::unlimited())
        .expect("nonzero-window search");
    assert_eq!(
        matched.map(|span| (span.start(), span.end())),
        Some((first, first + literal.len()))
    );
    assert_eq!(execution.route, QualifiedExactSearchRoute::PortableLiteral);
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[test]
fn candidate_refusal_precedes_publication_limits_and_preserves_the_portable_route() {
    let literal = b"0123456789abcdef";
    let search = QualifiedExactSearch::with_limits(
        literal,
        QUALIFIED_WORKLOAD,
        LiteralBuildLimits::default(),
        ValidateLimits::default(),
        EmitLimits::default(),
        PublicationLimits {
            max_code_bytes: 0,
            ..PublicationLimits::default()
        },
    )
    .expect("Candidate refusal is a retained native status");
    assert_eq!(
        search.build_report().native,
        QualifiedExactSearchNativeStatus::Unqualified {
            qualification: QualifiedExactSearchQualification::Candidate,
        }
    );

    let haystack = vec![b'x'; QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES];
    let (_, execution) = search
        .find(&haystack, SearchLimits::unlimited())
        .expect("portable fallback remains usable");
    assert_eq!(execution.route, QualifiedExactSearchRoute::PortableLiteral);
}

#[cfg(not(all(
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
)))]
#[test]
fn candidate_refusal_precedes_unsupported_host_and_aarch64_emission() {
    let search = QualifiedExactSearch::with_limits(
        b"0123456789abcdef",
        QUALIFIED_WORKLOAD,
        LiteralBuildLimits::default(),
        ValidateLimits::default(),
        EmitLimits {
            max_code_bytes: 0,
            ..EmitLimits::default()
        },
        PublicationLimits::default(),
    )
    .expect("Candidate host performs no target-specific emission");
    assert_eq!(
        search.build_report().native,
        QualifiedExactSearchNativeStatus::Unqualified {
            qualification: QualifiedExactSearchQualification::Candidate,
        }
    );
}

#[test]
fn native_call_errors_remain_typed_at_the_facade_boundary() {
    let source = CallError::BackendFault { status: 0x55 };
    let exact_error = QualifiedExactSearchError::from(source.clone());
    assert_eq!(
        exact_error,
        QualifiedExactSearchError::Native(source.clone())
    );
    let facade_error = QualifiedExactSearchFacadeError::from(exact_error.clone());
    assert_eq!(
        facade_error,
        QualifiedExactSearchFacadeError::ExactLiteral(exact_error)
    );
}
