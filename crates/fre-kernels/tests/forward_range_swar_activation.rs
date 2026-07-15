#![forbid(unsafe_code)]

use core::mem::size_of;

use fre_kernels::{
    FORWARD_ANCHORED_PLAN_ID, ForwardAnchoredAnchors, ForwardAnchoredBuildLimits,
    ForwardAnchoredByteClass, ForwardAnchoredPlan, ForwardAnchoredSearchLimits,
};

const RANGE_SWAR1_ID: &str = "anchored-class-suffix.single-candidate32-65536-equality32-pair-candidate16-4096-neon16-swar8-tail-extension4097-65536-cold-entry-triple-candidate-swar8x4-cold-recovery32-range-swar1-short72-pair-quad-forward-middle-equality5-candidate-reduce32-short-front8-back8-middle40-63-asymmetric-scalar8-reverse32-inline.v22";

fn plan(start: u8, end: u8, suffix: u8) -> ForwardAnchoredPlan {
    let members: Vec<u8> = (start..=end).collect();
    ForwardAnchoredPlan::build(
        ForwardAnchoredByteClass::from_bytes(&members),
        &[suffix],
        ForwardAnchoredAnchors {
            start: true,
            end: false,
        },
        ForwardAnchoredBuildLimits::default(),
    )
    .unwrap()
}

#[test]
fn range_swar1_prefix_boundaries_high_bits_and_accounting_are_exact() {
    let word_bytes = size_of::<usize>();
    assert_eq!(word_bytes, 8);
    assert_eq!(FORWARD_ANCHORED_PLAN_ID, RANGE_SWAR1_ID);

    for (start, end, member, outsider, suffix) in [
        (0x80_u8, 0xFE_u8, 0xC0_u8, 0x7F_u8, 0x40_u8),
        (0x40, 0xC0, 0x80, 0xFF, 0x20),
        (0x00, 0x7F, 0x40, 0x80, 0xFF),
    ] {
        let candidate = plan(start, end, suffix);
        assert_eq!(candidate.plan_id(), RANGE_SWAR1_ID);

        for prefix_len in [0_usize, 1, 3, 4, 7, 8] {
            let scanned_len = prefix_len + 1;
            let mut haystack = vec![member; prefix_len];
            haystack.push(suffix);
            let (span, accounting) = candidate
                .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
                .unwrap();
            let expected_span = if prefix_len == 0 {
                None
            } else {
                Some((0, scanned_len))
            };
            let expected_examined = if scanned_len == word_bytes {
                scanned_len + word_bytes
            } else {
                scanned_len
            };
            assert_eq!(
                span, expected_span,
                "range={start:02x}-{end:02x} prefix={prefix_len}"
            );
            assert_eq!(
                accounting.prefix_bytes_examined, expected_examined,
                "range={start:02x}-{end:02x} prefix={prefix_len}"
            );
            assert_eq!(
                accounting.prefix_bytes_upper_bound,
                scanned_len + word_bytes
            );
            assert_eq!(accounting.suffix_confirmation_attempted, prefix_len != 0);

            if prefix_len == 0 {
                continue;
            }
            haystack[prefix_len - 1] = outsider;
            let (span, accounting) = candidate
                .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
                .unwrap();
            let expected_mismatch = if scanned_len == word_bytes {
                word_bytes + prefix_len
            } else if prefix_len == word_bytes {
                2 * word_bytes
            } else {
                prefix_len
            };
            assert_eq!(
                span, None,
                "range={start:02x}-{end:02x} mismatch prefix={prefix_len}"
            );
            assert_eq!(
                accounting.prefix_bytes_examined, expected_mismatch,
                "range={start:02x}-{end:02x} mismatch prefix={prefix_len}"
            );
            assert_eq!(accounting.suffix_confirmation_attempted, prefix_len != 1);
        }
    }
}

#[test]
fn range_swar8_activation_lanes_high_bits_remainders_and_accounting_are_exact() {
    assert_eq!(FORWARD_ANCHORED_PLAN_ID, RANGE_SWAR1_ID);
    let word_bytes = size_of::<usize>();
    let candidate = plan(b'a', b'z', b'Z');

    for prefix_len in [15_usize, 16, 17, 31, 32, 33] {
        let mut haystack = vec![b'm'; prefix_len];
        haystack.push(b'Z');
        let (span, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(span, Some((0, haystack.len())), "prefix={prefix_len}");
        let expected_examined = if haystack.len() == 16 {
            haystack.len() + word_bytes
        } else {
            prefix_len + 1
        };
        assert_eq!(accounting.prefix_bytes_examined, expected_examined);
        assert_eq!(
            accounting.prefix_bytes_upper_bound,
            haystack.len() + word_bytes,
            "prefix={prefix_len}"
        );
    }

    let prefix_len = 33_usize;
    for lane in 0..word_bytes {
        let outsider = word_bytes + lane;
        let mut haystack = vec![b'm'; prefix_len];
        haystack[outsider] = b'!';
        haystack.push(b'Z');
        let (span, accounting) = candidate
            .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
            .unwrap();
        assert_eq!(span, None, "lane={lane}");
        assert_eq!(
            accounting.prefix_bytes_examined,
            2 * word_bytes + lane + 2,
            "lane={lane}"
        );
        assert_eq!(
            accounting.prefix_bytes_upper_bound,
            haystack.len() + word_bytes
        );
    }

    for (start, end, member, outsider, suffix) in [
        (0x80_u8, 0xFE_u8, 0xC0_u8, 0x7F_u8, 0x40_u8),
        (0x40, 0xC0, 0x80, 0xFF, 0x20),
        (0x00, 0x7F, 0x40, 0x80, 0xFF),
    ] {
        let candidate = plan(start, end, suffix);
        for prefix_len in [15_usize, 16, 17, 31, 32, 33] {
            for lane in 0..word_bytes {
                let mut haystack = vec![member; prefix_len];
                if lane < prefix_len {
                    haystack[lane] = outsider;
                }
                haystack.push(suffix);
                let (span, accounting) = candidate
                    .find(&haystack, ForwardAnchoredSearchLimits::unlimited())
                    .unwrap();
                assert_eq!(span, None, "range={start:02x}-{end:02x} lane={lane}");
                assert!(
                    accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound,
                    "range={start:02x}-{end:02x} lane={lane}"
                );
            }
        }
    }
}
