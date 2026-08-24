#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

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
    }
    assert_eq!(measured.change(), Stats::default());
}
