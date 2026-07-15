#![forbid(unsafe_code)]

use fre_kernels::{
    AbsoluteEndFixedPlan as CandidatePlan, FORWARD_ANCHORED_PLAN_ID, ForwardAnchoredAnchors,
    ForwardAnchoredBuildLimits, ForwardAnchoredByteClass, ForwardAnchoredSearchError,
    ForwardAnchoredSearchLimits, ForwardClassImplementation, Window,
};

const FIXED_ID: &str =
    "anchored-class-suffix.absolute-end-fixed-single1-range64-threshold64-suffix-first-hybrid.v5";

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
fn red_fixed_identity_specialized_leaf_and_n_m_p_accounting() {
    assert_ne!(FORWARD_ANCHORED_PLAN_ID, FIXED_ID);
    for (class, expected) in [
        (
            b"a".as_slice(),
            ForwardClassImplementation::InclusiveRange {
                start: b'a',
                end: b'a',
            },
        ),
        (
            b"ac".as_slice(),
            ForwardClassImplementation::Pair {
                first: b'a',
                second: b'c',
            },
        ),
        (
            b"ace".as_slice(),
            ForwardClassImplementation::Triple {
                first: b'a',
                second: b'c',
                third: b'e',
            },
        ),
        (
            b"aceg".as_slice(),
            ForwardClassImplementation::Quad {
                first: b'a',
                second: b'c',
                third: b'e',
                fourth: b'g',
            },
        ),
        (
            b"acegi".as_slice(),
            ForwardClassImplementation::Quint {
                first: b'a',
                second: b'c',
                third: b'e',
                fourth: b'g',
                fifth: b'i',
            },
        ),
    ] {
        let candidate = plan(class, b"ZQ");
        assert_eq!(candidate.plan_id(), FIXED_ID);
        assert_eq!(candidate.implementation(), expected);
        assert_eq!(candidate.build_accounting().implementation, expected);

        let haystack = [class[0], class[0], b'Z', b'Q'];
        let (matched, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, Some((0, haystack.len())));
        assert_eq!(accounting.prefilter_bytes_upper_bound, 0);
        assert_eq!(accounting.prefix_bytes_upper_bound, 2);
        assert_eq!(accounting.suffix_bytes_upper_bound, 2);
        assert_eq!(accounting.examined_bytes_upper_bound, haystack.len());
        assert_eq!(
            accounting.work_upper_bound,
            u64::try_from(haystack.len()).unwrap()
        );
        assert_eq!(accounting.scratch_bytes, 0);
        assert_eq!(accounting.prefilter_calls, 0);
        assert_eq!(accounting.prefix_bytes_examined, 2);
        assert!(accounting.suffix_confirmation_attempted);
    }
}

#[test]
fn red_specialized_fixed_prefix_retains_first_outsider_and_conservative_block_bound() {
    let candidate = plan(b"az", b"ZQ");
    assert_eq!(
        candidate.implementation(),
        ForwardClassImplementation::Pair {
            first: b'a',
            second: b'z',
        }
    );
    let prefix_len = 65_usize;
    let suffix_len = candidate.suffix().len();
    let mut haystack: Vec<u8> = (0..prefix_len)
        .map(|index| if index % 2 == 0 { b'a' } else { b'z' })
        .collect();
    haystack.extend_from_slice(candidate.suffix());

    let (_, valid) = candidate
        .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
        .unwrap();
    assert_eq!(valid.prefix_bytes_upper_bound, prefix_len + 32);
    assert_eq!(valid.suffix_bytes_upper_bound, suffix_len);
    assert_eq!(
        valid.examined_bytes_upper_bound,
        prefix_len + 32 + suffix_len
    );
    assert_eq!(valid.prefix_bytes_examined, prefix_len);
    assert_eq!(valid.prefilter_calls, 0);

    haystack[33] = b'!';
    let (matched, outsider) = candidate
        .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
        .unwrap();
    assert_eq!(matched, None);
    assert_eq!(outsider.prefix_bytes_examined, 66);
    assert!(outsider.suffix_confirmation_attempted);

    haystack[prefix_len] ^= 1;
    let (matched, mismatch) = candidate
        .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
        .unwrap();
    assert_eq!(matched, None);
    assert_eq!(mismatch.prefix_bytes_examined, 0);
    assert!(mismatch.suffix_confirmation_attempted);
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
            max_work_upper_bound: u64::try_from(haystack.len()).unwrap() - 1,
            max_examined_bytes_upper_bound: haystack.len(),
            max_scratch_bytes: 0,
        },
        ForwardAnchoredSearchLimits {
            max_work_upper_bound: u64::try_from(haystack.len()).unwrap(),
            max_examined_bytes_upper_bound: haystack.len() - 1,
            max_scratch_bytes: 0,
        },
    ] {
        assert!(matches!(
            candidate.find(haystack, limits),
            Err(ForwardAnchoredSearchError::WorkLimit { .. }
                | ForwardAnchoredSearchError::ExaminedBytesLimit { .. })
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

#[test]
fn suffix_partition_lengths_kill_shift_shorten_and_wrapping_mutants() {
    for suffix_len in [1_usize, 2, 15, 16, 17, 31, 32, 33] {
        let mut suffix: Vec<u8> = (0_u8..=u8::MAX).cycle().take(suffix_len).collect();
        suffix[0] = b'Z';
        suffix[suffix_len - 1] = b'Q';
        let candidate = plan(b"a", &suffix);
        let mut haystack = vec![b'a'; 3];
        haystack.extend_from_slice(&suffix);
        assert_eq!(
            candidate
                .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
                .unwrap()
                .0,
            Some((0, haystack.len())),
            "suffix_len={suffix_len}"
        );

        let mut shifted = haystack.clone();
        shifted[3] ^= 0x20;
        assert_eq!(
            candidate
                .find(&shifted, ForwardAnchoredSearchLimits::unlimited())
                .unwrap()
                .0,
            None,
            "first sentinel suffix_len={suffix_len}"
        );
        let last = shifted.len() - 1;
        shifted.copy_from_slice(&haystack);
        shifted[last] ^= 0x20;
        assert_eq!(
            candidate
                .find(&shifted, ForwardAnchoredSearchLimits::unlimited())
                .unwrap()
                .0,
            None,
            "last sentinel suffix_len={suffix_len}"
        );
    }

    let suffix_n_minus_one = vec![b'Z'; 39];
    let candidate = plan(b"a", &suffix_n_minus_one);
    let mut haystack = vec![b'a'];
    haystack.extend_from_slice(&suffix_n_minus_one);
    assert_eq!(
        candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap()
            .0,
        Some((0, 40))
    );

    for suffix_len in [40_usize, 41] {
        let candidate = plan(b"a", &vec![b'Z'; suffix_len]);
        assert_eq!(
            candidate
                .find(&[b'a'; 40], ForwardAnchoredSearchLimits::unlimited())
                .unwrap()
                .0,
            None,
            "M={suffix_len}, N=40"
        );
    }
}

#[test]
fn every_prefix_outsider_position_and_partition_edge_returns_the_first_outsider() {
    let candidate = plan(b"ab", b"ZQ");
    let prefix_len = 65_usize;
    let mut valid = vec![b'a'; prefix_len];
    valid.extend_from_slice(b"ZQ");
    let (matched, accounting) = candidate
        .find(&valid, ForwardAnchoredSearchLimits::unlimited())
        .unwrap();
    assert_eq!(matched, Some((0, valid.len())));
    assert_eq!(accounting.prefix_bytes_examined, prefix_len);

    for outsider in 0..prefix_len {
        let mut haystack = valid.clone();
        haystack[outsider] = b'!';
        let (matched, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, None, "outsider={outsider}");
        let expected_examined = if outsider < 32 {
            outsider + 65
        } else if outsider < 64 {
            outsider + 33
        } else {
            outsider + 1
        };
        assert_eq!(accounting.prefix_bytes_examined, expected_examined);
        assert_eq!(accounting.prefix_bytes_upper_bound, prefix_len + 32);
        assert_eq!(accounting.suffix_bytes_upper_bound, 2);
        assert!(accounting.suffix_confirmation_attempted);
    }
}

#[test]
fn fixed_range_thresholds_retain_exact_first_outsider_and_accounting() {
    let candidate = plan(b"abcdefghijklmnopqrstuvwxyz", b"Z");
    for (prefix_len, outsider, expected_examined) in [
        (63_usize, 62_usize, 63_usize),
        (64, 63, 96),
        (65, 64, 65),
        (127, 126, 127),
        (128, 127, 160),
        (129, 128, 129),
    ] {
        let mut haystack = vec![b'a'; prefix_len];
        haystack.push(b'Z');
        let (matched, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, Some((0, haystack.len())), "N={prefix_len}");
        assert_eq!(accounting.prefix_bytes_examined, prefix_len);
        assert_eq!(accounting.prefix_bytes_upper_bound, prefix_len + 32);

        haystack[outsider] = b'!';
        let (matched, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, None, "N={prefix_len}, outsider={outsider}");
        assert_eq!(accounting.prefix_bytes_examined, expected_examined);
        assert_eq!(accounting.prefix_bytes_upper_bound, prefix_len + 32);
        assert!(accounting.suffix_confirmation_attempted);
    }
}

#[test]
fn fixed_range128_failure_in_each_quarter_has_one_bounded_rescan() {
    let candidate = plan(b"abcdefghijklmnopqrstuvwxyz", b"Z");
    let prefix_len = 128_usize;
    let mut valid = vec![b'a'; prefix_len];
    valid.push(b'Z');

    for outsider in [31_usize, 63, 95, 127] {
        let mut haystack = valid.clone();
        haystack[outsider] = b'!';
        let (matched, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(matched, None, "outsider={outsider}");
        assert_eq!(accounting.prefix_bytes_examined, 160);
        assert_eq!(accounting.prefix_bytes_upper_bound, 160);
        assert!(accounting.suffix_confirmation_attempted);
    }
}

#[test]
fn earlier_suffix_lookalike_never_restarts_and_borders_never_move_the_split() {
    let candidate = plan(b"ab", b"ZQ");
    let (matched, accounting) = candidate
        .find(b"aaZaaZQ", ForwardAnchoredSearchLimits::unlimited())
        .unwrap();
    assert_eq!(matched, None);
    assert_eq!(accounting.prefix_bytes_examined, 3);
    assert_eq!(accounting.prefilter_calls, 0);

    let bordered = plan(b"b", b"aba");
    assert_eq!(
        bordered
            .find(b"bbbaba", ForwardAnchoredSearchLimits::unlimited())
            .unwrap()
            .0,
        Some((0, 6))
    );
    for offset in 0..3 {
        let mut haystack = b"bbbaba".to_vec();
        haystack[3 + offset] ^= 1;
        assert_eq!(
            bordered
                .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
                .unwrap()
                .0,
            None,
            "border mismatch offset={offset}"
        );
    }
}

#[test]
fn exact_n_limits_admit_and_each_one_below_limit_refuses_before_inspection() {
    let candidate = plan(b"a", b"ZQ");
    let haystack = b"aaaZQ";
    let exact = ForwardAnchoredSearchLimits {
        max_work_upper_bound: u64::try_from(haystack.len()).unwrap(),
        max_examined_bytes_upper_bound: haystack.len(),
        max_scratch_bytes: 0,
    };
    let (matched, accounting) = candidate.find(haystack, exact).unwrap();
    assert_eq!(matched, Some((0, haystack.len())));
    assert_eq!(accounting.examined_bytes_upper_bound, haystack.len());
    assert_eq!(
        accounting.work_upper_bound,
        u64::try_from(haystack.len()).unwrap()
    );

    for limited in [
        ForwardAnchoredSearchLimits {
            max_work_upper_bound: u64::try_from(haystack.len()).unwrap() - 1,
            ..exact
        },
        ForwardAnchoredSearchLimits {
            max_examined_bytes_upper_bound: haystack.len() - 1,
            ..exact
        },
    ] {
        assert!(matches!(
            candidate.find(haystack, limited),
            Err(ForwardAnchoredSearchError::WorkLimit { .. }
                | ForwardAnchoredSearchError::ExaminedBytesLimit { .. })
        ));
    }
}

#[test]
fn fixed_kernel_matches_the_direct_theorem_on_small_exhaustive_inputs() {
    fn words(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..max_len {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &byte in alphabet {
                    let mut word = prefix.clone();
                    word.push(byte);
                    next.push(word);
                }
            }
            all.extend(next.iter().cloned());
            frontier = next;
        }
        all
    }

    let alphabet = [0_u8, 1, 2, 3];
    let haystacks = words(&alphabet, 6);
    let suffixes: Vec<Vec<u8>> = words(&alphabet, 3)
        .into_iter()
        .filter(|suffix| !suffix.is_empty())
        .collect();
    let mut comparisons = 0_usize;
    for mask in 1_u8..16 {
        let members: Vec<u8> = alphabet
            .into_iter()
            .enumerate()
            .filter_map(|(bit, byte)| (mask & (1 << bit) != 0).then_some(byte))
            .collect();
        for suffix in &suffixes {
            if members.contains(&suffix[0]) {
                continue;
            }
            let candidate = plan(&members, suffix);
            for haystack in &haystacks {
                let expected = haystack.len() > suffix.len()
                    && haystack.ends_with(suffix)
                    && haystack[..haystack.len() - suffix.len()]
                        .iter()
                        .all(|byte| members.contains(byte));
                let actual = candidate
                    .find(haystack, ForwardAnchoredSearchLimits::unlimited())
                    .unwrap()
                    .0;
                assert_eq!(
                    actual,
                    expected.then_some((0, haystack.len())),
                    "members={members:?} suffix={suffix:?} haystack={haystack:?}"
                );
                comparisons += 1;
            }
        }
    }
    assert_eq!(comparisons, 3_211_068);
}
