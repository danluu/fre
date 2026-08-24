#![forbid(unsafe_code)]

use std::{alloc::System, hint::black_box};

use fre::{PlanKind, PortableBuilder};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn line_token_loop_ordinary_find_allocates_nothing() {
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

    let measured = Region::new(GLOBAL);
    for _ in 0..64 {
        assert_eq!(
            black_box(regex.find(black_box(&late)))
                .map(|matched| (matched.start(), matched.end())),
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
