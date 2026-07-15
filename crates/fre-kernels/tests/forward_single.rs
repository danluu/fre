#![forbid(unsafe_code)]

use fre_kernels::{
    FORWARD_ANCHORED_PLAN_ID, ForwardAnchoredAnchors, ForwardAnchoredBuildLimits,
    ForwardAnchoredByteClass, ForwardAnchoredPlan, ForwardAnchoredSearchLimits,
    ForwardClassImplementation,
};

const SINGLE_ID: &str = "anchored-class-suffix.single-candidate73-1024-equality32-pair-candidate73-512-swar8-triple-candidate-swar8x4-short72-pair-quad-forward-middle-equality5-candidate-reduce32-short-front8-back8-middle40-63-asymmetric-scalar8-reverse32-inline.v10";

fn plan() -> ForwardAnchoredPlan {
    ForwardAnchoredPlan::build(
        ForwardAnchoredByteClass::from_bytes(&[0x80]),
        &[0x7F, 0x00],
        ForwardAnchoredAnchors {
            start: true,
            end: false,
        },
        ForwardAnchoredBuildLimits::default(),
    )
    .unwrap()
}

#[test]
fn singleton_candidate_window_boundaries_and_accounting_are_exact() {
    let candidate = plan();
    assert_eq!(FORWARD_ANCHORED_PLAN_ID, SINGLE_ID);
    assert_eq!(candidate.plan_id(), SINGLE_ID);
    assert_eq!(
        candidate.implementation(),
        ForwardClassImplementation::InclusiveRange {
            start: 0x80,
            end: 0x80,
        }
    );

    for boundary in [72_usize, 73, 74, 1_023, 1_024, 1_025] {
        let mut haystack = vec![0x80; boundary];
        haystack.extend_from_slice(candidate.suffix());
        let (span, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(span, Some((0, haystack.len())), "boundary={boundary}");
        assert_eq!(accounting.prefilter_calls, 1);
        assert_eq!(accounting.prefix_bytes_examined, boundary + 1);
        assert_eq!(accounting.prefix_bytes_upper_bound, haystack.len() + 32);
        assert!(accounting.suffix_confirmation_attempted);

        let exact = ForwardAnchoredSearchLimits {
            max_work_upper_bound: accounting.work_upper_bound,
            max_examined_bytes_upper_bound: accounting.examined_bytes_upper_bound,
            max_scratch_bytes: 0,
        };
        assert_eq!(candidate.find(&haystack, exact).unwrap().0, span);
    }
}

#[test]
fn singleton_candidate_differential_preserves_first_outsider_and_arbitrary_bytes() {
    let candidate = plan();
    for boundary in [73_usize, 74, 127, 128, 255, 256, 1_023, 1_024] {
        for earlier in [0_usize, 1, 31, 32, 33, boundary / 2] {
            if earlier >= boundary {
                continue;
            }
            for outsider in [0x00_u8, 0x40, 0xFF] {
                let mut haystack = vec![0x80; boundary];
                haystack[earlier] = outsider;
                haystack.extend_from_slice(candidate.suffix());
                let (span, accounting) = candidate
                    .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
                    .unwrap();
                assert_eq!(span, None, "boundary={boundary} earlier={earlier}");
                assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);
                if earlier == 0 {
                    assert_eq!(accounting.prefix_bytes_examined, 1);
                    assert!(!accounting.suffix_confirmation_attempted);
                }
            }
        }
    }

    for length in [73_usize, 74, 1_023, 1_024] {
        let haystack = vec![0x80; length];
        let (span, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(span, None, "absent length={length}");
        assert_eq!(accounting.prefilter_calls, 1);
        assert_eq!(accounting.prefix_bytes_examined, 1);
        assert!(!accounting.suffix_confirmation_attempted);
    }
}
