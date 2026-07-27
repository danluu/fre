use fre::{
    QUALIFIED_EXACT_SEARCH_MIN_SEARCHES, QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
    QUALIFIED_EXACT_SEARCH_QUALIFICATION, QualifiedExactSearch, QualifiedExactSearchError,
    QualifiedExactSearchNativeStatus, QualifiedExactSearchQualification, QualifiedExactSearchRoute,
    QualifiedExactSearchWorkload, SearchLimits, SearchWindow,
};
use fre_jit_aarch64::{BackendVersion, EmitLimits, TargetSpec};
use fre_jit_runtime::{CallError, PublicationLimits, PublishError};
use fre_kernel_ir::ValidateLimits;
use fre_kernels::LiteralBuildLimits;

const QUALIFIED_WORKLOAD: QualifiedExactSearchWorkload = QualifiedExactSearchWorkload::new(
    QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
    QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
);
const QUALIFIED_BUNDLE_SHA256: [u8; 32] = [
    0xde, 0x08, 0x4f, 0xf0, 0x56, 0x4a, 0xcd, 0xb8, 0x98, 0x89, 0xf2, 0x8b, 0x9d, 0xcf, 0xdd, 0xce,
    0x9b, 0x6f, 0x09, 0x55, 0xa1, 0xb2, 0xae, 0xad, 0x30, 0xd7, 0x57, 0x70, 0x03, 0x9e, 0x04, 0x53,
];

#[test]
fn qualified_router_uses_only_the_declared_width_and_window_envelope() {
    let literal = b"0123456789abcdef";
    let search =
        QualifiedExactSearch::new(literal, QUALIFIED_WORKLOAD).expect("qualified exact matcher");
    assert_eq!(
        search.build_report().qualification,
        QualifiedExactSearchQualification::Qualified {
            bundle_sha256: QUALIFIED_BUNDLE_SHA256,
        }
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
        Some(QUALIFIED_BUNDLE_SHA256)
    );
    assert!(search.build_report().qualification.is_authorized());
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
    if let QualifiedExactSearchNativeStatus::Published { identity, .. } =
        &search.build_report().native
    {
        assert_eq!(
            threshold_execution.route,
            QualifiedExactSearchRoute::NativeJit
        );
        assert_eq!(identity.target, TargetSpec::AARCH64_AAPCS64);
        assert_eq!(identity.backend, BackendVersion::SEARCH_V7);
        assert_ne!(identity.artifact_sha256, [0; 32]);
        assert_eq!(identity.qualification, search.build_report().qualification);
    } else {
        assert_eq!(
            threshold_execution.route,
            QualifiedExactSearchRoute::PortableLiteral
        );
    }

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
fn qualification_state_rejects_zero_and_invalidated_historical_hashes() {
    let zero = QualifiedExactSearchQualification::Qualified {
        bundle_sha256: [0; 32],
    };
    assert_eq!(zero.authorized_bundle_sha256(), None);
    assert!(!zero.is_authorized());

    let historical = QualifiedExactSearchQualification::Qualified {
        bundle_sha256: [
            0x89, 0xaf, 0x5a, 0x04, 0x19, 0x0a, 0x39, 0xc4, 0x0a, 0x48, 0x19, 0xce, 0x91, 0x6f,
            0xc2, 0x86, 0x30, 0x33, 0x05, 0x50, 0xe1, 0xca, 0xfc, 0x15, 0xe9, 0x91, 0x91, 0x22,
            0xaf, 0x0a, 0xe9, 0xf7,
        ],
    };
    assert_eq!(historical.authorized_bundle_sha256(), None);
    assert!(!historical.is_authorized());

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
        if search.build_report().native.is_published() {
            assert_eq!(execution.route, QualifiedExactSearchRoute::NativeJit);
        }
    }

    let haystack = vec![b'x'; QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES];
    let needed = haystack
        .len()
        .checked_add(literal.len())
        .expect("bounded linear terms");
    let error = search
        .find(
            &haystack,
            SearchLimits {
                max_work: u64::try_from(needed - 1).expect("u64 work"),
                max_scratch_bytes: usize::MAX,
            },
        )
        .expect_err("portable preflight remains authoritative");
    assert!(matches!(
        error,
        fre::QualifiedExactSearchError::Portable(fre_kernels::LiteralError::LinearTermLimit { .. })
    ));
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
    if search.build_report().native.is_published() {
        assert_eq!(execution.route, QualifiedExactSearchRoute::NativeJit);
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[test]
fn publication_refusal_is_reported_and_preserves_the_portable_route() {
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
    .expect("publication refusal is a retained native status");
    assert!(matches!(
        &search.build_report().native,
        QualifiedExactSearchNativeStatus::Unavailable(PublishError::ResourceLimit {
            resource: fre_jit_runtime::ResourceKind::CodeBytes,
            limit: 0,
            required,
        }) if *required > 0
    ));

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
fn unsupported_host_is_reported_before_aarch64_emission() {
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
    .expect("unsupported host performs no target-specific emission");
    assert!(matches!(
        &search.build_report().native,
        QualifiedExactSearchNativeStatus::Unavailable(PublishError::UnsupportedHost {
            reason: fre_jit_runtime::HostSupportReason::Architecture
                | fre_jit_runtime::HostSupportReason::OperatingSystem
                | fre_jit_runtime::HostSupportReason::PointerWidth
                | fre_jit_runtime::HostSupportReason::Endianness,
        })
    ));
}

#[test]
fn native_call_errors_remain_typed_at_the_facade_boundary() {
    let source = CallError::BackendFault { status: 0x55 };
    let error = QualifiedExactSearchError::from(source.clone());
    assert_eq!(error, QualifiedExactSearchError::Native(source));
}
