#![forbid(unsafe_code)]

use fre_kernels::{
    FORWARD_ANCHORED_PLAN_ID, ForwardAnchoredAnchors, ForwardAnchoredBuildLimits,
    ForwardAnchoredByteClass, ForwardAnchoredPlan, ForwardAnchoredSearchLimits,
    ForwardClassImplementation,
};

const SINGLE_ID: &str = "anchored-class-suffix.single-candidate73-65536-equality32-pair-candidate73-4096-neon16-swar8-tail-extension4097-65536-cold-entry-triple-candidate-swar8x4-cold-recovery32-range-swar32-short72-pair-quad-forward-middle-equality5-candidate-reduce32-short-front8-back8-middle40-63-asymmetric-scalar8-reverse32-inline.v17";
const SINGLE_MIN32_ID: &str = "anchored-class-suffix.single-candidate32-65536-equality32-pair-candidate73-4096-neon16-swar8-tail-extension4097-65536-cold-entry-triple-candidate-swar8x4-cold-recovery32-range-swar32-short72-pair-quad-forward-middle-equality5-candidate-reduce32-short-front8-back8-middle40-63-asymmetric-scalar8-reverse32-inline.v18";

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
fn singleton_candidate_min32_boundaries_lanes_and_confirmation_are_exact() {
    let candidate = plan();
    assert_eq!(FORWARD_ANCHORED_PLAN_ID, SINGLE_MIN32_ID);
    assert_eq!(candidate.plan_id(), SINGLE_MIN32_ID);

    for boundary in [31_usize, 32, 33, 63, 64, 72, 73] {
        let mut haystack = vec![0x80; boundary];
        haystack.extend_from_slice(candidate.suffix());
        let (span, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(span, Some((0, haystack.len())), "boundary={boundary}");
        assert_eq!(accounting.prefix_bytes_examined, boundary + 1);
        assert_eq!(accounting.prefix_bytes_upper_bound, haystack.len() + 32);
        assert!(accounting.suffix_confirmation_attempted);
    }

    let boundary = 72_usize;
    for lane in 0..32 {
        let position = 32 + lane;
        for outsider in [0x00_u8, 0x7F, 0x81, 0xFF] {
            let mut haystack = vec![0x80; boundary];
            haystack[position] = outsider;
            haystack.extend_from_slice(candidate.suffix());
            let (span, accounting) = candidate
                .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
                .unwrap();
            assert_eq!(span, None, "lane={lane} outsider={outsider:#04x}");
            let expected_examined = if outsider == candidate.suffix()[0] {
                position + 1
            } else {
                1 + 32 + 32 + lane + 1
            };
            assert_eq!(
                accounting.prefix_bytes_examined, expected_examined,
                "lane={lane} outsider={outsider:#04x}"
            );
            assert_eq!(
                accounting.suffix_confirmation_attempted,
                outsider == candidate.suffix()[0],
                "lane={lane} outsider={outsider:#04x}"
            );
            assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);
        }
    }

    let mut first_outsider = vec![0x80; boundary];
    first_outsider[0] = 0xFF;
    first_outsider.extend_from_slice(candidate.suffix());
    let (span, accounting) = candidate
        .find(&first_outsider, ForwardAnchoredSearchLimits::unlimited())
        .unwrap();
    assert_eq!(span, None);
    assert_eq!(accounting.prefix_bytes_examined, 1);
    assert!(!accounting.suffix_confirmation_attempted);
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

    for boundary in [
        72_usize, 73, 74, 1_023, 1_024, 1_025, 4_095, 4_096, 4_097, 65_535, 65_536, 65_537,
    ] {
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
    for boundary in [
        73_usize, 74, 127, 128, 255, 256, 1_023, 1_024, 1_025, 4_095, 4_096, 4_097, 65_535, 65_536,
        65_537,
    ] {
        for earlier in [0_usize, 1, 31, 32, 33, boundary / 2, boundary - 1] {
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
                if earlier == 0 {
                    assert_eq!(accounting.prefix_bytes_examined, 1);
                    assert!(!accounting.suffix_confirmation_attempted);
                } else {
                    let complete_bytes = boundary / 32 * 32;
                    let expected_examined = if earlier < complete_bytes {
                        let block_start = earlier / 32 * 32;
                        1 + block_start + 32 + earlier % 32 + 1
                    } else {
                        1 + earlier + 1
                    };
                    assert_eq!(
                        accounting.prefix_bytes_examined, expected_examined,
                        "boundary={boundary} earlier={earlier}"
                    );
                }
                assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);
            }
        }
    }

    for length in [
        73_usize, 74, 1_023, 1_024, 1_025, 4_095, 4_096, 4_097, 65_535, 65_536, 65_537,
    ] {
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
