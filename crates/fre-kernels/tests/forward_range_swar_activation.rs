#![forbid(unsafe_code)]

use core::mem::size_of;

use fre_kernels::{
    FORWARD_ANCHORED_PLAN_ID, ForwardAnchoredAnchors, ForwardAnchoredBuildLimits,
    ForwardAnchoredByteClass, ForwardAnchoredPlan, ForwardAnchoredSearchLimits,
};

const RANGE_SWAR16_ID: &str = "anchored-class-suffix.single-candidate73-65536-equality32-pair-candidate73-4096-neon16-swar8-tail-extension4097-65536-cold-entry-triple-candidate-swar8x4-cold-recovery32-range-swar16-short72-pair-quad-forward-middle-equality5-candidate-reduce32-short-front8-back8-middle40-63-asymmetric-scalar8-reverse32-inline.v18";

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
fn range_swar16_activation_lanes_high_bits_remainders_and_accounting_are_exact() {
    assert_eq!(FORWARD_ANCHORED_PLAN_ID, RANGE_SWAR16_ID);
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
