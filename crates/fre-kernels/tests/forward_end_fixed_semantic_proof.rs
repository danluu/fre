#![forbid(unsafe_code)]

use fre_kernels::{
    FORWARD_ANCHORED_PLAN_ID, ForwardAnchoredAnchors, ForwardAnchoredBuildLimits,
    ForwardAnchoredByteClass, ForwardAnchoredPlan as CandidatePlan, ForwardAnchoredSearchError,
    ForwardAnchoredSearchLimits, ForwardClassImplementation, Window,
};

const FIXED_ID: &str = "anchored-class-suffix.absolute-end-fixed-suffix-first-bitset.v1";

fn plan(class: &[u8], suffix: &[u8]) -> CandidatePlan {
    CandidatePlan::build(
        ForwardAnchoredByteClass::from_bytes(class),
        suffix,
        ForwardAnchoredAnchors {
            start: true,
            end: true,
        },
        ForwardAnchoredBuildLimits::default(),
    )
    .unwrap()
}

fn assert_zero(accounting: fre_kernels::ForwardAnchoredSearchAccounting) {
    assert_eq!(accounting.prefilter_bytes_upper_bound, 0);
    assert_eq!(accounting.prefix_bytes_upper_bound, 0);
    assert_eq!(accounting.suffix_bytes_upper_bound, 0);
    assert_eq!(accounting.examined_bytes_upper_bound, 0);
    assert_eq!(accounting.work_upper_bound, 0);
    assert_eq!(accounting.scratch_bytes, 0);
    assert_eq!(accounting.prefilter_calls, 0);
    assert_eq!(accounting.prefix_bytes_examined, 0);
    assert!(!accounting.suffix_confirmation_attempted);
}

#[test]
fn red_fixed_identity_leaf_and_exact_n_accounting() {
    assert_ne!(FORWARD_ANCHORED_PLAN_ID, FIXED_ID);
    for class in [
        b"a".as_slice(),
        b"ab".as_slice(),
        b"ace".as_slice(),
        b"aceg".as_slice(),
        b"abcdefgh".as_slice(),
    ] {
        let candidate = plan(class, b"ZQ");
        assert_eq!(candidate.plan_id(), FIXED_ID);
        assert_eq!(candidate.implementation(), ForwardClassImplementation::Bitset);

        let haystack = [class[0], class[0], b'Z', b'Q'];
        let (matched, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, Some((0, haystack.len())));
        assert_eq!(accounting.prefilter_bytes_upper_bound, 0);
        assert_eq!(accounting.prefix_bytes_upper_bound, 2);
        assert_eq!(accounting.suffix_bytes_upper_bound, 2);
        assert_eq!(accounting.examined_bytes_upper_bound, haystack.len());
        assert_eq!(accounting.work_upper_bound, haystack.len() as u64);
        assert_eq!(accounting.scratch_bytes, 0);
        assert_eq!(accounting.prefilter_calls, 0);
        assert_eq!(accounting.prefix_bytes_examined, 2);
        assert!(accounting.suffix_confirmation_attempted);
    }
}

#[test]
fn red_absolute_windows_and_short_haystacks_have_preflight_precedence() {
    let candidate = plan(b"a", b"Z");
    for (haystack, window) in [
        (b"aaZx".as_slice(), Window::new(0, 3)),
        (b"xaaZ".as_slice(), Window::new(1, 4)),
    ] {
        let (matched, accounting) = candidate
            .find_window(haystack, window, ForwardAnchoredSearchLimits::default())
            .unwrap();
        assert_eq!(matched, None);
        assert_zero(accounting);
    }

    for haystack in [b"".as_slice(), b"Z".as_slice()] {
        let (matched, accounting) = candidate
            .find(
                haystack,
                ForwardAnchoredSearchLimits {
                    max_work_upper_bound: 0,
                    max_examined_bytes_upper_bound: 0,
                    max_scratch_bytes: 0,
                },
            )
            .unwrap();
        assert_eq!(matched, None);
        assert_zero(accounting);
    }

    assert!(matches!(
        candidate.find_window(
            b"aaZ",
            Window::new(2, 1),
            ForwardAnchoredSearchLimits {
                max_work_upper_bound: 0,
                max_examined_bytes_upper_bound: 0,
                max_scratch_bytes: 0,
            },
        ),
        Err(ForwardAnchoredSearchError::InvalidWindow { .. })
    ));
}

#[test]
fn red_suffix_first_partition_and_mismatch_accounting_kill_core_mutants() {
    let suffix = b"ZQX";
    let candidate = plan(b"ab", suffix);

    assert_eq!(
        candidate
            .find(b"abZQX", ForwardAnchoredSearchLimits::unlimited())
            .unwrap()
            .0,
        Some((0, 5))
    );
    assert_eq!(
        candidate
            .find(b"a!ZQX", ForwardAnchoredSearchLimits::unlimited())
            .unwrap()
            .0,
        None
    );
    assert_eq!(
        candidate
            .find(b"!aZQX", ForwardAnchoredSearchLimits::unlimited())
            .unwrap()
            .0,
        None
    );

    for offset in 0..suffix.len() {
        let mut haystack = b"abZQX".to_vec();
        haystack[2 + offset] ^= 0x20;
        let (matched, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, None, "suffix mismatch offset={offset}");
        assert_eq!(accounting.suffix_bytes_upper_bound, suffix.len());
        assert_eq!(accounting.prefix_bytes_upper_bound, 2);
        assert_eq!(accounting.examined_bytes_upper_bound, haystack.len());
        assert_eq!(accounting.prefix_bytes_examined, 0);
        assert!(accounting.suffix_confirmation_attempted);
        assert_eq!(accounting.prefilter_calls, 0);
    }

    let (matched, accounting) = candidate
        .find(b"a!YQX", ForwardAnchoredSearchLimits::unlimited())
        .unwrap();
    assert_eq!(matched, None);
    assert_eq!(accounting.prefix_bytes_examined, 0);
}

#[test]
fn red_first_mismatch_still_preflights_full_n() {
    let candidate = plan(b"a", b"ZQ");
    let haystack = b"aaYQ";
    for limits in [
        ForwardAnchoredSearchLimits {
            max_work_upper_bound: haystack.len() as u64 - 1,
            max_examined_bytes_upper_bound: haystack.len(),
            max_scratch_bytes: 0,
        },
        ForwardAnchoredSearchLimits {
            max_work_upper_bound: haystack.len() as u64,
            max_examined_bytes_upper_bound: haystack.len() - 1,
            max_scratch_bytes: 0,
        },
    ] {
        assert!(matches!(
            candidate.find(haystack, limits),
            Err(
                ForwardAnchoredSearchError::WorkLimit { .. }
                    | ForwardAnchoredSearchError::ExaminedBytesLimit { .. }
            )
        ));
    }
}

#[test]
fn red_full_byte_normalization_and_bordered_suffix_are_exact() {
    for byte in u8::MIN..=u8::MAX {
        let suffix = byte.wrapping_add(1);
        if suffix == byte {
            continue;
        }
        let candidate = plan(&[byte], &[suffix]);
        assert_eq!(
            candidate
                .find(&[byte, suffix], ForwardAnchoredSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((0, 2)),
            "member=0x{byte:02X} suffix=0x{suffix:02X}"
        );
        assert_eq!(
            candidate
                .find(
                    &[byte.wrapping_add(2), suffix],
                    ForwardAnchoredSearchLimits::unlimited(),
                )
                .unwrap()
                .0,
            None,
            "outsider for member=0x{byte:02X}"
        );
    }

    let bordered = plan(b"b", b"aba");
    assert_eq!(
        bordered
            .find(b"bbbaba", ForwardAnchoredSearchLimits::unlimited())
            .unwrap()
            .0,
        Some((0, 6))
    );
    assert_eq!(
        bordered
            .find(b"bbabaa", ForwardAnchoredSearchLimits::unlimited())
            .unwrap()
            .0,
        None
    );
}
