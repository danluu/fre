use fre_kernels::{
    ForwardAnchoredAnchors as Anchors, ForwardAnchoredBuildLimits as BuildLimits,
    ForwardAnchoredByteClass as ByteClass, ForwardAnchoredPlan,
    ForwardAnchoredSearchAccounting as SearchAccounting,
    ForwardAnchoredSearchLimits as SearchLimits, ForwardClassImplementation as Implementation,
    Window,
};

fn build(class: ByteClass, suffix: &[u8], end: bool) -> ForwardAnchoredPlan {
    ForwardAnchoredPlan::build(
        class,
        suffix,
        Anchors { start: true, end },
        BuildLimits::default(),
    )
    .unwrap()
}

fn oracle(
    class: ByteClass,
    suffix: &[u8],
    end_anchor: bool,
    haystack: &[u8],
    window: Window,
) -> Option<(usize, usize)> {
    if window.start() != 0 || (end_anchor && window.end() != haystack.len()) {
        return None;
    }
    let searched = haystack.get(..window.end())?;
    let boundary = searched.iter().position(|&byte| !class.contains(byte))?;
    if boundary == 0 {
        return None;
    }
    let end = boundary.checked_add(suffix.len())?;
    if end > window.end() || searched.get(boundary..end) != Some(suffix) {
        return None;
    }
    if end_anchor && end != haystack.len() {
        return None;
    }
    Some((0, end))
}

fn assert_accounting(accounting: SearchAccounting, suffix_len: usize) {
    let window = accounting.window_bytes;
    assert_eq!(
        accounting.prefilter_bytes_upper_bound,
        if window >= 32 { window - 1 } else { 0 }
    );
    assert_eq!(
        accounting.prefix_bytes_upper_bound,
        window + if window >= 32 { 32 } else { 0 }
    );
    assert_eq!(accounting.suffix_bytes_upper_bound, suffix_len.min(window));
    assert_eq!(
        accounting.examined_bytes_upper_bound,
        accounting.prefilter_bytes_upper_bound
            + accounting.prefix_bytes_upper_bound
            + accounting.suffix_bytes_upper_bound
    );
    assert_eq!(
        accounting.work_upper_bound,
        u64::try_from(accounting.examined_bytes_upper_bound).unwrap()
    );
    assert_eq!(accounting.scratch_bytes, 0);
    assert!(accounting.prefix_bytes_examined <= accounting.prefix_bytes_upper_bound);
}

#[test]
fn every_position_differential_covers_all_edges_and_suffix_borders() {
    let cases: [(ByteClass, &[u8], Implementation); 3] = [
        (
            ByteClass::from_bytes(&[0x00, 0x80]),
            &[0x00, 0x80],
            Implementation::Pair {
                first: 0x00,
                second: 0x80,
            },
        ),
        (
            ByteClass::from_bytes(&[0x00, 0x80, 0xFF]),
            &[0x00, 0x80, 0xFF],
            Implementation::Triple {
                first: 0x00,
                second: 0x80,
                third: 0xFF,
            },
        ),
        (
            ByteClass::from_bytes(&[0x00, 0x02, 0x80, 0xFF]),
            &[0x00, 0x02, 0x80, 0xFF],
            Implementation::Quad {
                first: 0x00,
                second: 0x02,
                third: 0x80,
                fourth: 0xFF,
            },
        ),
    ];
    let suffixes: [&[u8]; 3] = [&[0x7F], &[0x7F, 0x11, 0x22], &[0x7F, 0x11, 0x7F]];

    let mut comparisons = 0_u64;
    for (class, members, implementation) in cases {
        for suffix in suffixes {
            for end_anchor in [false, true] {
                let plan = build(class, suffix, end_anchor);
                assert_eq!(plan.implementation(), implementation);
                for haystack_len in 0_usize..=132 {
                    for outsider in 0..=haystack_len {
                        let haystack: Vec<u8> = (0..haystack_len)
                            .map(|index| members[index % members.len()])
                            .collect();
                        for make_valid in [false, true] {
                            let mut candidate = haystack.clone();
                            if outsider < candidate.len() {
                                candidate[outsider] = suffix[0];
                            }
                            if make_valid && outsider + suffix.len() <= candidate.len() {
                                candidate[outsider..outsider + suffix.len()]
                                    .copy_from_slice(suffix);
                            }
                            let window = Window::full(&candidate);
                            let expected = oracle(class, suffix, end_anchor, &candidate, window);
                            let (actual, accounting) = plan
                                .find_window(&candidate, window, SearchLimits::unlimited())
                                .unwrap();
                            assert_eq!(
                                actual, expected,
                                "len={haystack_len} outsider={outsider} valid={make_valid} end={end_anchor} suffix={suffix:?}"
                            );
                            assert_accounting(accounting, suffix.len());
                            comparisons += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(comparisons, 320_796);
}

#[derive(Clone, Copy)]
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).unwrap()).unwrap()
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}

#[test]
fn seeded_long_random_and_window_differential_is_stable() {
    let classes = [
        ByteClass::from_bytes(&[0x00, 0x80]),
        ByteClass::from_bytes(&[0x00, 0x80, 0xFF]),
        ByteClass::from_bytes(&[0x00, 0x02, 0x80, 0xFF]),
    ];
    let members: [&[u8]; 3] = [
        &[0x00, 0x80],
        &[0x00, 0x80, 0xFF],
        &[0x00, 0x02, 0x80, 0xFF],
    ];
    let mut random = Random(0x4553_3849_5f41_5544);
    let mut comparisons = 0_u64;

    for iteration in 0_usize..8_192 {
        let class_index = iteration % classes.len();
        let class = classes[class_index];
        let class_members = members[class_index];
        let suffix_len = 1 + random.below(33);
        let mut suffix: Vec<u8> = (0..suffix_len).map(|_| random.byte()).collect();
        while class.contains(suffix[0]) {
            suffix[0] = random.byte();
        }
        if iteration % 4 == 0 && suffix_len >= 3 {
            suffix[suffix_len - 1] = suffix[0];
        }
        let end_anchor = random.below(2) != 0;
        let plan = build(class, &suffix, end_anchor);

        let haystack_len = match iteration % 8 {
            0 => 39,
            1 => 40,
            2 => 41,
            3 => 42,
            4 => 99,
            5 => 100,
            _ => 256 + random.below(16_129),
        };
        let mode = iteration % 4;
        let mut haystack: Vec<u8> = if mode == 0 {
            (0..haystack_len).map(|_| random.byte()).collect()
        } else {
            (0..haystack_len)
                .map(|index| class_members[index % class_members.len()])
                .collect()
        };

        if mode >= 1 && haystack_len > 1 {
            let position = 1 + random.below(haystack_len - 1);
            if position + suffix.len() <= haystack.len() && mode != 2 {
                haystack[position..position + suffix.len()].copy_from_slice(&suffix);
            } else {
                haystack[position] = suffix[0];
                if position + 1 < haystack.len() {
                    let mut decoy = random.byte();
                    while decoy == suffix.get(1).copied().unwrap_or(suffix[0]) {
                        decoy = random.byte();
                    }
                    haystack[position + 1] = decoy;
                }
            }
        }

        let full = Window::full(&haystack);
        let expected = oracle(class, &suffix, end_anchor, &haystack, full);
        let (actual, accounting) = plan
            .find_window(&haystack, full, SearchLimits::unlimited())
            .unwrap();
        assert_eq!(actual, expected, "iteration={iteration} full");
        assert_accounting(accounting, suffix.len());
        comparisons += 1;

        let window_end = random.below(haystack.len() + 1);
        for window in [
            Window::new(0, window_end),
            Window::new(1.min(window_end), window_end),
        ] {
            let expected = oracle(class, &suffix, end_anchor, &haystack, window);
            let (actual, accounting) = plan
                .find_window(&haystack, window, SearchLimits::unlimited())
                .unwrap();
            assert_eq!(actual, expected, "iteration={iteration} window={window:?}");
            if window.start() == 0 && (!end_anchor || window.end() == haystack.len()) {
                assert_accounting(accounting, suffix.len());
            } else {
                assert_eq!(accounting.work_upper_bound, 0);
                assert_eq!(accounting.prefix_bytes_examined, 0);
                assert_eq!(accounting.prefilter_calls, 0);
            }
            comparisons += 1;
        }
    }
    assert_eq!(comparisons, 24_576);
}
