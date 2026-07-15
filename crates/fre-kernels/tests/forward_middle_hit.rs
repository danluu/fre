use fre_kernels::{
    FORWARD_ANCHORED_PLAN_ID, ForwardAnchoredAnchors, ForwardAnchoredBuildLimits,
    ForwardAnchoredByteClass, ForwardAnchoredPlan, ForwardAnchoredSearchLimits,
    ForwardClassImplementation,
};

const MIDDLE_HIT_PLAN_ID: &str =
    "anchored-class-suffix.short72-forward-middle-equality5-isolated-asymmetric-scalar8-reverse32-inline.v4";

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
fn short_middle_hits_use_one_forward_witness_for_pair_triple_and_quad() {
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
            b"ace".as_slice(),
            b"Z".as_slice(),
            ForwardClassImplementation::Triple {
                first: b'a',
                second: b'c',
                third: b'e',
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
            let mut haystack: Vec<u8> = members
                .iter()
                .copied()
                .cycle()
                .take(tail_len + 1)
                .collect();
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
        let mut haystack: Vec<u8> = members
            .iter()
            .copied()
            .cycle()
            .take(tail_len + 1)
            .collect();
        haystack[tail_len] = b'Z';
        let (span, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(span, Some((0, tail_len + 1)));
        assert_eq!(accounting.prefilter_calls, 1);
        assert!(accounting.suffix_confirmation_attempted);
    }
}
