use super::SourceQualifiedStaticSearchSpanRowV1;

/// Literal, source-reviewed private Search-v1 Span qualification rows.
///
/// This module is compiled only by `search-span-qualification-private-v1`.
/// The table begins empty and stays inert unless a qualification promotion
/// replaces this complete file with the canonical renderer's exact projection
/// of one independently measured and reviewed `source-row-proposal.tsv`.
pub(super) const PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1:
    &[SourceQualifiedStaticSearchSpanRowV1] = &[];

const _: () = assert!(super::qualification_rows_are_canonical(
    PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1
));
