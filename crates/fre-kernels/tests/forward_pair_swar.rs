#![forbid(unsafe_code)]

use fre_kernels::{
    FORWARD_ANCHORED_PLAN_ID, ForwardAnchoredAnchors, ForwardAnchoredBuildLimits,
    ForwardAnchoredByteClass, ForwardAnchoredPlan, ForwardAnchoredSearchLimits,
    ForwardClassImplementation,
};

const PAIR_SWAR_ID: &str = "anchored-class-suffix.single-candidate73-1024-equality32-pair-candidate73-512-swar8-short72-pair-quad-forward-middle-equality5-candidate-reduce32-short-front8-back8-middle40-63-asymmetric-scalar8-reverse32-inline.v9";

fn plan() -> ForwardAnchoredPlan {
    ForwardAnchoredPlan::build(
        ForwardAnchoredByteClass::from_bytes(&[0x00, 0xFF]),
        &[0x7F, 0x55],
        ForwardAnchoredAnchors {
            start: true,
            end: false,
        },
        ForwardAnchoredBuildLimits::default(),
    )
    .unwrap()
}

fn members(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| if index % 2 == 0 { 0x00 } else { 0xFF })
        .collect()
}

#[test]
fn pair_swar_thresholds_valid_paths_and_resource_limits_are_exact() {
    let candidate = plan();
    assert_eq!(FORWARD_ANCHORED_PLAN_ID, PAIR_SWAR_ID);
    assert_eq!(candidate.plan_id(), PAIR_SWAR_ID);
    assert_eq!(
        candidate.implementation(),
        ForwardClassImplementation::Pair {
            first: 0x00,
            second: 0xFF,
        }
    );

    for boundary in [72_usize, 73, 74, 79, 80, 81, 511, 512, 513] {
        let mut haystack = members(boundary);
        haystack.extend_from_slice(candidate.suffix());
        let (span, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(span, Some((0, haystack.len())), "boundary={boundary}");
        assert_eq!(accounting.prefix_bytes_examined, boundary + 1);
        assert_eq!(accounting.prefilter_calls, 1);
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
fn pair_swar_failed_words_recover_the_exact_first_outsider() {
    let candidate = plan();
    const BOUNDARY: usize = 512;
    for earlier in [1_usize, 7, 8, 9, 31, 32, 33, 255, 256, 511] {
        for outsider in [0x01_u8, 0x40, 0x80, 0xFE] {
            let mut haystack = members(BOUNDARY);
            haystack[earlier] = outsider;
            haystack.extend_from_slice(candidate.suffix());
            let (span, accounting) = candidate
                .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
                .unwrap();
            assert_eq!(span, None, "earlier={earlier} outsider={outsider:#04x}");
            assert_eq!(
                accounting.prefix_bytes_examined,
                earlier + 10,
                "earlier={earlier} outsider={outsider:#04x}"
            );
            assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);
            assert!(accounting.suffix_confirmation_attempted);
        }
    }
}

#[test]
fn pair_swar_differential_covers_every_outsider_byte_and_block_edge() {
    let candidate = plan();
    for boundary in [73_usize, 80, 255, 256, 511, 512] {
        for position in [0_usize, 1, 7, 8, 9, 31, 32, boundary - 1] {
            if position >= boundary {
                continue;
            }
            for outsider in 0_u8..=u8::MAX {
                let mut haystack = members(boundary);
                haystack[position] = outsider;
                haystack.extend_from_slice(candidate.suffix());
                let expected = if outsider == 0x00 || outsider == 0xFF {
                    Some((0, haystack.len()))
                } else {
                    None
                };
                let (actual, accounting) = candidate
                    .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
                    .unwrap();
                assert_eq!(
                    actual, expected,
                    "boundary={boundary} position={position} outsider={outsider:#04x}"
                );
                assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);
            }
        }
    }
}
