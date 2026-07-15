use fre_kernels::{
    FORWARD_ANCHORED_PLAN_ID, ForwardAnchoredAnchors, ForwardAnchoredBuildLimits,
    ForwardAnchoredByteClass, ForwardAnchoredPlan, ForwardAnchoredSearchLimits,
    ForwardClassImplementation,
};

const MIDDLE_HIT_PLAN_ID: &str = "anchored-class-suffix.single-candidate73-65536-equality32-pair-candidate73-4096-neon16-swar8-tail-extension4097-65536-cold-entry-triple-candidate-swar8x4-cold-recovery32-range-swar32-short72-pair-quad-forward-middle-equality5-candidate-reduce32-short-front8-back8-middle40-63-asymmetric-scalar8-reverse32-inline.v17";

fn plan(members: &[u8], suffix: &[u8]) -> ForwardAnchoredPlan {
    ForwardAnchoredPlan::build(
        ForwardAnchoredByteClass::from_bytes(members),
        suffix,
        ForwardAnchoredAnchors {
            start: true,
            end: false,
        },
        ForwardAnchoredBuildLimits::default(),
    )
    .unwrap()
}

#[test]
fn short_middle_hits_use_one_forward_witness_for_pair_and_quad() {
    assert_eq!(FORWARD_ANCHORED_PLAN_ID, MIDDLE_HIT_PLAN_ID);

    for (members, suffix, implementation) in [
        (
            b" \t".as_slice(),
            b"END".as_slice(),
            ForwardClassImplementation::Pair {
                first: b'\t',
                second: b' ',
            },
        ),
        (
            b"aceg".as_slice(),
            b"Z".as_slice(),
            ForwardClassImplementation::Quad {
                first: b'a',
                second: b'c',
                third: b'e',
                fourth: b'g',
            },
        ),
    ] {
        let candidate = plan(members, suffix);
        assert_eq!(candidate.implementation(), implementation);

        for tail_len in 41_usize..=72 {
            let middle = 8 + (tail_len - 41) / 2;
            let boundary = middle + 1;
            let mut haystack: Vec<u8> =
                members.iter().copied().cycle().take(tail_len + 1).collect();
            let suffix_end = boundary + suffix.len();
            haystack[boundary..suffix_end].copy_from_slice(suffix);

            let (span, accounting) = candidate
                .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
                .unwrap();
            assert_eq!(span, Some((0, suffix_end)), "tail={tail_len}");
            assert_eq!(accounting.prefilter_calls, 1, "tail={tail_len}");
            assert_eq!(accounting.prefix_bytes_examined, boundary + 1);
            assert!(accounting.suffix_confirmation_attempted);
        }
    }
}

#[test]
fn quint_and_long_small_classes_keep_the_edge_witness_geometry() {
    let quint = plan(b"acegi", b"Z");
    let triple = plan(b"ace", b"Z");

    for (candidate, members, tail_len) in [
        (&quint, b"acegi".as_slice(), 64_usize),
        (&triple, b"ace".as_slice(), 73_usize),
    ] {
        let mut haystack: Vec<u8> = members.iter().copied().cycle().take(tail_len + 1).collect();
        haystack[tail_len] = b'Z';
        let (span, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(span, Some((0, tail_len + 1)));
        assert_eq!(accounting.prefilter_calls, 1);
        assert!(accounting.suffix_confirmation_attempted);
    }
}

#[test]
fn short_triple_keeps_the_measured_edge_witness_geometry() {
    let triple = plan(b"ace", b"Z");
    let mut haystack: Vec<u8> = b"ace".iter().copied().cycle().take(64).collect();
    haystack[63] = b'Z';
    let (span, accounting) = triple
        .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
        .unwrap();
    assert_eq!(span, Some((0, 64)));
    assert_eq!(accounting.prefilter_calls, 0);
}

#[test]
fn quint_candidate_block_edges_have_exact_accounting() {
    assert_eq!(FORWARD_ANCHORED_PLAN_ID, MIDDLE_HIT_PLAN_ID);
    let candidate = plan(b"acegi", b"Z");

    for prefix_len in [31_usize, 32, 33, 71, 72, 73] {
        let mut haystack: Vec<u8> = b"acegi".iter().copied().cycle().take(prefix_len).collect();
        haystack.push(b'Z');
        let (span, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(span, Some((0, haystack.len())), "prefix={prefix_len}");
        assert_eq!(accounting.prefilter_calls, 1, "prefix={prefix_len}");
        assert_eq!(
            accounting.prefix_bytes_examined,
            prefix_len.checked_add(1).unwrap(),
            "prefix={prefix_len}"
        );
        assert_eq!(
            accounting.prefix_bytes_upper_bound,
            haystack.len().checked_add(32).unwrap(),
            "prefix={prefix_len}"
        );
        assert!(accounting.suffix_confirmation_attempted);
    }
}

#[test]
fn pair_quad_forward_middle_threshold_is_exact_at_71_72_73() {
    for members in [b"ac".as_slice(), b"aceg".as_slice()] {
        let candidate = plan(members, b"Z");
        for (tail_len, expected_calls) in [(71_usize, 1_usize), (72, 1), (73, 2)] {
            let boundary = 36_usize;
            let mut haystack: Vec<u8> = members
                .iter()
                .copied()
                .cycle()
                .take(tail_len.checked_add(1).unwrap())
                .collect();
            haystack[boundary] = b'Z';
            let (span, accounting) = candidate
                .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
                .unwrap();
            assert_eq!(span, Some((0, boundary + 1)), "tail={tail_len}");
            assert_eq!(
                accounting.prefilter_calls, expected_calls,
                "tail={tail_len}"
            );
            assert_eq!(accounting.prefix_bytes_examined, boundary + 1);
            assert!(accounting.suffix_confirmation_attempted);
        }
    }
}

#[test]
fn triple_swar_candidate_boundaries_have_exact_accounting() {
    assert_eq!(FORWARD_ANCHORED_PLAN_ID, MIDDLE_HIT_PLAN_ID);
    let candidate = plan(&[0x00, 0x80, 0xFF], &[0x7F]);

    for (prefix_len, expected_calls) in [
        (31_usize, 1_usize),
        (32, 1),
        (33, 1),
        (55, 0),
        (56, 0),
        (63, 0),
        (64, 1),
        (65, 1),
        (127, 1),
        (128, 1),
        (255, 1),
        (256, 1),
    ] {
        let mut haystack: Vec<u8> = [0x00, 0x80, 0xFF]
            .into_iter()
            .cycle()
            .take(prefix_len)
            .collect();
        haystack.push(0x7F);
        let (span, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(span, Some((0, haystack.len())), "prefix={prefix_len}");
        assert_eq!(
            accounting.prefilter_calls, expected_calls,
            "prefix={prefix_len}"
        );
        assert_eq!(
            accounting.prefix_bytes_examined,
            prefix_len.checked_add(1).unwrap(),
            "prefix={prefix_len}"
        );
        assert_eq!(
            accounting.prefix_bytes_upper_bound,
            haystack.len().checked_add(32).unwrap(),
            "prefix={prefix_len}"
        );
    }
}

#[test]
fn triple_swar_candidate_recovers_every_arbitrary_byte_outsider() {
    let candidate = plan(&[0x00, 0x80, 0xFF], &[0x7F]);
    let prefix_len = 256_usize;
    for outsider_byte in [0x01_u8, 0x40, 0x7E, 0x81, 0xFE] {
        for outsider in 0..prefix_len {
            let mut haystack: Vec<u8> = [0x00, 0x80, 0xFF]
                .into_iter()
                .cycle()
                .take(prefix_len)
                .collect();
            haystack[outsider] = outsider_byte;
            haystack.push(0x7F);
            let (span, accounting) = candidate
                .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
                .unwrap();
            let expected_examined = if outsider == 0 {
                1
            } else {
                let block_start = outsider / 32 * 32;
                1 + block_start + 32 + outsider % 32 + 1
            };
            assert_eq!(
                span,
                None,
                "byte={outsider_byte:#04x} outsider={outsider} lane={}",
                outsider % 32
            );
            assert_eq!(
                accounting.prefix_bytes_examined,
                expected_examined,
                "byte={outsider_byte:#04x} outsider={outsider} lane={}",
                outsider % 32
            );
            assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);
        }
    }
}
