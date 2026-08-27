#![cfg(target_arch = "aarch64")]

use fre_kernels::{LiteralSetBuildLimits, LiteralSetPlan, LiteralSetSearchLimits, Window};

#[test]
fn ascii_engine_preserves_long_partial_prefixes_across_native_boundary() {
    let roots = [b'0', b'2', b'4', b'6', b'8', b'A', b'C', b'E', b'G'];
    // The source-priority 40-byte word follows a shorter 20-byte alternative,
    // while six other widths keep the set above Aho's packed-prefilter ceiling.
    // A match beginning in the native prefix therefore carries a partial or
    // pending LeftmostFirst state across its 32-byte boundary.
    let widths = [40_usize, 20, 36, 37, 38, 39, 41, 42];
    let patterns = roots
        .into_iter()
        .flat_map(|root| widths.into_iter().map(move |width| vec![root; width]))
        .collect::<Vec<_>>();
    let plan = LiteralSetPlan::new(&patterns, LiteralSetBuildLimits::default()).unwrap();
    let ordinary = plan
        .ordinary_executor()
        .expect("positive leftmost-first executor");
    let mut engine = ordinary
        .bind_engine()
        .expect("nine exact ASCII roots bind the worker engine");

    let mut haystack = vec![b'!'; 39];
    haystack.extend(core::iter::repeat_n(roots[0], 42));
    haystack.extend(core::iter::repeat_n(b'!', 137));
    haystack.extend(core::iter::repeat_n(roots[7], 35));
    haystack.extend(core::iter::repeat_n(b'!', 11));

    for start in 0..=haystack.len() {
        for end in start..=haystack.len() {
            let window = Window::new(start, end);
            let expected_first = plan
                .find_window(
                    &haystack,
                    window,
                    LiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0;
            assert_eq!(
                engine.find_window_value(&haystack, window),
                Ok(expected_first),
                "first window={window:?}",
            );

            let mut expected_spans = Vec::new();
            let mut cursor = start;
            while let Some(matched) = plan
                .find_window(
                    &haystack,
                    Window::new(cursor, end),
                    LiteralSetSearchLimits::unlimited(),
                )
                .unwrap()
                .0
            {
                cursor = matched.1;
                expected_spans.push(matched);
            }
            let mut actual_spans = Vec::new();
            assert_eq!(
                engine.try_visit_spans_window_value(&haystack, window, |matched| {
                    actual_spans.push(matched);
                    Ok::<bool, ()>(true)
                }),
                Ok(Ok(())),
                "visit window={window:?}",
            );
            assert_eq!(actual_spans, expected_spans, "spans window={window:?}");
            assert_eq!(
                engine.try_count_spans_window_value(&haystack, window),
                Ok(Some(u64::try_from(expected_spans.len()).unwrap())),
                "count window={window:?}",
            );
        }
    }
}
