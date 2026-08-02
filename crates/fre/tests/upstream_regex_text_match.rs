use core::iter::FusedIterator;

use fre::{PortableFindIterLimits, PortableTextMatch, PortableTextRegex, SearchLimits};

#[test]
fn borrowed_text_match_preserves_pinned_value_semantics_and_accounting() {
    let regex = PortableTextRegex::new(r"\p{Greek}+").expect("proved Greek text regex");
    let haystack = "Greek: αβγδ!";

    let (offset, offset_accounting) = regex
        .find(haystack, SearchLimits::unlimited())
        .expect("offset search");
    let (borrowed, borrowed_accounting) = regex
        .find_borrowed(haystack, SearchLimits::unlimited())
        .expect("borrowed search");
    let (repeated_offset, repeated_offset_accounting) = regex
        .find(haystack, SearchLimits::unlimited())
        .expect("repeated offset search");
    assert_eq!(repeated_offset, offset);
    // Preserve the first cold call above, but compare wrappers only after the
    // shared K0 plan has published its optional immutable start proof.
    assert_eq!(repeated_offset_accounting, borrowed_accounting);
    assert_eq!(offset_accounting.plan(), borrowed_accounting.plan());

    let offset = offset.expect("offset match");
    let borrowed = borrowed.expect("borrowed match");
    assert_eq!(borrowed.start(), 7);
    assert_eq!(borrowed.end(), 15);
    assert_eq!(borrowed.len(), 8);
    assert!(!borrowed.is_empty());
    assert_eq!(borrowed.range(), 7..15);
    assert_eq!(borrowed.as_str(), "αβγδ");
    assert_eq!(borrowed.range(), offset.range());
    assert_eq!(borrowed.as_str().as_ptr(), haystack[7..15].as_ptr());
    assert_eq!(
        format!("{borrowed:?}"),
        "PortableTextMatch { start: 7, end: 15, string: \"αβγδ\" }"
    );

    let selected: &str = borrowed.into();
    assert_eq!(selected, "αβγδ");
    let range: core::ops::Range<usize> = borrowed.into();
    assert_eq!(range, 7..15);
}

#[test]
fn borrowed_text_find_at_preserves_scalar_normalization_and_original_context() {
    let scalar = PortableTextRegex::new(".").expect("proved scalar regex");
    let haystack = "☃a";
    let (offset, offset_accounting) = scalar
        .find_at(haystack, 1, SearchLimits::unlimited())
        .expect("offset ranged search");
    let (borrowed, borrowed_accounting) = scalar
        .find_at_borrowed(haystack, 1, SearchLimits::unlimited())
        .expect("borrowed ranged search");
    let (repeated_offset, repeated_offset_accounting) = scalar
        .find_at(haystack, 1, SearchLimits::unlimited())
        .expect("repeated offset ranged search");
    assert_eq!(repeated_offset, offset);
    // The borrowed projection adds no work; first-use plan specialization does.
    // Compare the two warm invocations without discarding cold output coverage.
    assert_eq!(repeated_offset_accounting, borrowed_accounting);
    assert_eq!(offset_accounting.plan(), borrowed_accounting.plan());
    assert_eq!(offset.expect("offset match").range(), 3..4);
    let borrowed = borrowed.expect("borrowed match");
    assert_eq!(borrowed.range(), 3..4);
    assert_eq!(borrowed.as_str(), "a");

    let offset_error = scalar
        .find_at(haystack, haystack.len() + 1, SearchLimits::unlimited())
        .expect_err("offset API rejects an out-of-bounds start");
    let borrowed_error = scalar
        .find_at_borrowed(haystack, haystack.len() + 1, SearchLimits::unlimited())
        .expect_err("borrowed API rejects an out-of-bounds start");
    assert_eq!(borrowed_error, offset_error);

    let contextual = PortableTextRegex::new(r"\bchew\b").expect("proved assertion regex");
    let context_haystack = "eschew chew";
    let (matched, _) = contextual
        .find_at_borrowed(context_haystack, 2, SearchLimits::unlimited())
        .expect("contextual ranged search");
    let matched = matched.expect("second word is selected");
    assert_eq!(matched.range(), 7..11);
    assert_eq!(matched.as_str(), "chew");
}

#[test]
fn borrowed_text_iteration_is_fused_and_ledger_identical_at_utf8_boundaries() {
    fn assert_fused<I: FusedIterator>(_iterator: &I) {}

    let regex = PortableTextRegex::new("").expect("proved empty text regex");
    let haystack = "💩a";
    let limits = PortableFindIterLimits::unlimited();

    let mut offsets = regex.find_iter(haystack, limits).expect("offset iterator");
    let offset_spans = offsets
        .by_ref()
        .map(|item| item.expect("offset item").range())
        .collect::<Vec<_>>();
    assert_eq!(offset_spans, [0..0, 4..4, 5..5]);
    assert!(offsets.next().is_none());
    let offset_accounting = offsets.accounting();
    let offset_setup = offsets.workspace_setup_accounting();

    let mut borrowed = regex
        .find_iter_borrowed(haystack, limits)
        .expect("borrowed iterator");
    assert_fused(&borrowed);
    let values = borrowed
        .by_ref()
        .map(|item| {
            let matched = item.expect("borrowed item");
            (matched.range(), matched.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(values, [(0..0, ""), (4..4, ""), (5..5, "")]);
    assert!(borrowed.next().is_none());
    assert!(borrowed.next().is_none());
    assert_eq!(borrowed.accounting(), offset_accounting);
    assert_eq!(borrowed.workspace_setup_accounting(), offset_setup);
}

#[test]
fn borrowed_text_match_is_copy_without_owned_storage() {
    fn assert_copy<T: Copy>() {}

    assert_copy::<PortableTextMatch<'static>>();
    assert_eq!(
        core::mem::size_of::<PortableTextMatch<'static>>(),
        core::mem::size_of::<&'static str>() + core::mem::size_of::<fre::Match>()
    );
}
