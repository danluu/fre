#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder, PortableRegex};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

fn multibyte_fixture() -> (PortableRegex, Vec<u8>, Vec<u8>, Vec<u8>) {
    let regex = PortableBuilder::new(r"(?-u:(?:ab|cd)+XYZ)")
        .build()
        .unwrap();
    assert_eq!(regex.build_report().plan, PlanKind::K0);
    let mut late = vec![b'!'; 4_089];
    late.extend_from_slice(b"cdabXYZ");
    let absent = vec![b'!'; 4_096];
    let dense = b"XYZ!".repeat(1_024);
    assert!(regex.is_match(&late));
    assert!(!regex.is_match(&absent));
    assert!(!regex.is_match(&dense));
    (regex, late, absent, dense)
}

#[test]
fn line_token_loop_ordinary_values_allocate_nothing() {
    let regex = PortableBuilder::new(r"(?m)^(?:ab+c|de?f)+Z$")
        .unicode(false)
        .build()
        .unwrap();
    assert_eq!(regex.build_report().plan, PlanKind::K0);

    let mut late = vec![b'q'; 4_082];
    late.extend_from_slice(b"\nabbbcdefZ\n");
    let mut rejected_then_late = b"abZ\n".to_vec();
    rejected_then_late.extend_from_slice(&late[4..]);
    let absent = vec![b'q'; 4_093];
    let capped = |rejected_lines: usize| {
        let mut source = vec![b'q'; 4_063];
        for _ in 0..rejected_lines {
            source.extend_from_slice(b"\nabZ");
        }
        source.extend_from_slice(b"\nabbbcdefZ\n");
        source
    };
    let at_cap = capped(4);
    let beyond_cap = capped(5);
    let cap_many = capped(33);
    assert!(regex.is_match(&beyond_cap));
    assert!(regex.is_match(&cap_many));
    let dense_regex = PortableBuilder::new(r"(?m)^(?:Za|bc)+Z$")
        .unicode(false)
        .build()
        .unwrap();
    let mut dense_inline = b"Za".repeat(2_046);
    dense_inline.push(b'Z');
    assert!(dense_regex.is_match(&dense_inline));

    let unanchored = PortableBuilder::new(r"(?-u:(?:ab+c|de?f)+Z)")
        .build()
        .unwrap();
    assert_eq!(unanchored.build_report().plan, PlanKind::K0);
    let mut unanchored_late = vec![b'!'; 4_087];
    unanchored_late.extend_from_slice(b"abbbcdefZ");
    let unanchored_absent = vec![b'!'; 4_096];
    let unanchored_dense = vec![b'Z'; 4_096];
    let mut unanchored_rejected_then_late = vec![b'!'; 4_080];
    unanchored_rejected_then_late.extend_from_slice(b"qbcZ!abcZ");
    assert!(unanchored.is_match(&unanchored_late));
    assert!(!unanchored.is_match(&unanchored_absent));
    assert!(!unanchored.is_match(&unanchored_dense));
    assert!(unanchored.is_match(&unanchored_rejected_then_late));

    let (multibyte, multibyte_late, multibyte_absent, multibyte_dense) = multibyte_fixture();
    let cold_multibyte_hit = PortableBuilder::new(r"(?-u:(?:ab|cd)+XYZ)")
        .build()
        .unwrap();
    let cold_multibyte_miss = PortableBuilder::new(r"(?-u:(?:ab|cd)+XYZ)")
        .build()
        .unwrap();
    let overflow = PortableBuilder::new(r"(?-u:(?:ab+c|de?f)+XYZ)")
        .build()
        .unwrap();
    let mut overflow_long = vec![b'b'; 4_093];
    overflow_long[0] = b'a';
    overflow_long[4_092] = b'c';
    overflow_long.extend_from_slice(b"XYZ");
    assert_eq!(overflow_long.len(), 4_096);

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert!(black_box(regex.is_match(black_box(&late))));
        assert!(!black_box(regex.is_match(black_box(&absent))));
        assert!(black_box(regex.is_match(black_box(&rejected_then_late))));
        assert!(black_box(regex.is_match(black_box(&at_cap))));
        assert!(black_box(regex.is_match(black_box(&beyond_cap))));
        assert!(black_box(regex.is_match(black_box(&cap_many))));
        assert!(black_box(dense_regex.is_match(black_box(&dense_inline))));
        assert_eq!(
            black_box(regex.find(black_box(&late))).map(|matched| (matched.start(), matched.end())),
            Some((4_083, 4_092)),
        );
        assert_eq!(black_box(regex.find(black_box(&absent))), None);
        assert_eq!(
            black_box(regex.find(black_box(&rejected_then_late)))
                .map(|matched| (matched.start(), matched.end())),
            Some((4_083, 4_092)),
        );
        assert!(black_box(unanchored.is_match(black_box(&unanchored_late))));
        assert!(!black_box(
            unanchored.is_match(black_box(&unanchored_absent))
        ));
        assert!(!black_box(
            unanchored.is_match(black_box(&unanchored_dense))
        ));
        assert!(black_box(
            unanchored.is_match(black_box(&unanchored_rejected_then_late))
        ));
        assert_eq!(
            black_box(unanchored.find(black_box(&unanchored_late)))
                .map(|matched| (matched.start(), matched.end())),
            Some((4_087, 4_096)),
        );
        assert_eq!(
            black_box(unanchored.find(black_box(&unanchored_absent))),
            None,
        );
        assert_eq!(
            black_box(unanchored.find(black_box(&unanchored_dense))),
            None,
        );
        assert_eq!(
            black_box(unanchored.find(black_box(&unanchored_rejected_then_late)))
                .map(|matched| (matched.start(), matched.end())),
            Some((4_085, 4_089)),
        );
        assert!(black_box(multibyte.is_match(black_box(&multibyte_late))));
        assert!(!black_box(multibyte.is_match(black_box(&multibyte_absent))));
        assert!(!black_box(multibyte.is_match(black_box(&multibyte_dense))));
        assert_eq!(
            black_box(cold_multibyte_hit.find(black_box(&multibyte_late)))
                .map(|matched| (matched.start(), matched.end())),
            Some((4_089, 4_096)),
        );
        assert_eq!(
            black_box(cold_multibyte_miss.find(black_box(&multibyte_absent))),
            None,
        );
        assert_eq!(
            black_box(overflow.find(black_box(&overflow_long)))
                .map(|matched| (matched.start(), matched.end())),
            Some((0, 4_096)),
        );
    }
    assert_eq!(measured.change(), Stats::default());
}
