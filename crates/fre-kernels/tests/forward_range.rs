#![forbid(unsafe_code)]

use std::mem::size_of;

use fre_kernels::{
    FORWARD_ANCHORED_PLAN_ID, ForwardAnchoredAnchors, ForwardAnchoredBuildLimits,
    ForwardAnchoredByteClass, ForwardAnchoredPlan, ForwardAnchoredSearchLimits,
};

const RANGE_MIN8_ID: &str = "anchored-class-suffix.single-candidate32-65536-equality32-pair-candidate16-4096-neon16-swar8-tail-extension4097-65536-cold-entry-triple-candidate-swar8x4-cold-recovery32-range-swar8-short72-pair-quad-forward-middle-equality5-candidate-reduce32-short-front8-back8-middle40-63-asymmetric-scalar8-reverse32-inline.v21";

fn plan(start: u8, end: u8, suffix: &[u8]) -> ForwardAnchoredPlan {
    ForwardAnchoredPlan::build(
        ForwardAnchoredByteClass::inclusive(start, end),
        suffix,
        ForwardAnchoredAnchors {
            start: true,
            end: false,
        },
        ForwardAnchoredBuildLimits::default(),
    )
    .unwrap()
}

fn expected_failed_word_examinations(boundary: usize, scanned_len: usize) -> usize {
    let word_bytes = size_of::<usize>();
    let completed_words = boundary / word_bytes;
    if completed_words < scanned_len / word_bytes {
        completed_words * word_bytes + word_bytes + boundary % word_bytes + 1
    } else {
        boundary + 1
    }
}

#[test]
fn range_min8_candidate_boundaries_accounting_id_and_unlimited_ceiling_are_exact() {
    let mut suffix = [0_u8; 25];
    suffix[0] = b'Z';
    let candidate = plan(b'a', b'z', &suffix);
    let word_bytes = size_of::<usize>();

    assert_eq!(FORWARD_ANCHORED_PLAN_ID, RANGE_MIN8_ID);
    assert_eq!(candidate.plan_id(), RANGE_MIN8_ID);

    for prefix_len in [7_usize, 8, 15, 16, 65_537] {
        let mut haystack = vec![b'a'; prefix_len];
        haystack.extend_from_slice(candidate.suffix());
        let (span, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(span, Some((0, haystack.len())), "N={prefix_len}");
        assert_eq!(accounting.prefilter_calls, 1, "N={prefix_len}");
        assert_eq!(accounting.prefix_bytes_examined, prefix_len + 1);
        assert_eq!(
            accounting.prefix_bytes_upper_bound,
            haystack.len() + word_bytes,
            "N={prefix_len}"
        );
        assert!(accounting.suffix_confirmation_attempted);
    }
}

#[test]
fn range_min8_direct_words_remainders_byte_zero_and_high_bits_are_exact() {
    let word_bytes = size_of::<usize>();
    for (start, end, member, outsider, suffix) in [
        (0x00_u8, 0x7F_u8, 0x00_u8, 0xFE_u8, 0xFF_u8),
        (0x80, 0xFF, 0xFF, 0x01, 0x00),
        (0x40, 0xC0, 0x80, 0xFF, 0x20),
    ] {
        let candidate = plan(start, end, &[suffix]);
        for prefix_len in [7_usize, 8, 15, 16] {
            let mut valid = vec![member; prefix_len];
            valid.push(suffix);
            let (span, accounting) = candidate
                .find(&valid, ForwardAnchoredSearchLimits::unlimited())
                .unwrap();
            assert_eq!(span, Some((0, valid.len())));
            assert_eq!(accounting.prefilter_calls, 0);
            assert_eq!(
                accounting.prefix_bytes_examined,
                expected_failed_word_examinations(prefix_len, valid.len()),
                "range={start:#04x}-{end:#04x} N={prefix_len}"
            );
            assert_eq!(
                accounting.prefix_bytes_upper_bound,
                valid.len() + word_bytes
            );
            assert!(accounting.suffix_confirmation_attempted);

            for position in [0_usize, prefix_len - 1] {
                let mut invalid = valid.clone();
                invalid[position] = outsider;
                let (span, accounting) = candidate
                    .find(&invalid, ForwardAnchoredSearchLimits::unlimited())
                    .unwrap();
                assert_eq!(
                    span, None,
                    "range={start:#04x}-{end:#04x} N={prefix_len} position={position}"
                );
                assert_eq!(accounting.prefilter_calls, 0);
                assert_eq!(
                    accounting.prefix_bytes_examined,
                    expected_failed_word_examinations(position, invalid.len())
                );
                assert_eq!(accounting.suffix_confirmation_attempted, position != 0);
                assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);
            }
        }
    }
}
