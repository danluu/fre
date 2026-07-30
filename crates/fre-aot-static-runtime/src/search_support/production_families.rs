use super::SourceQualifiedStaticSearchSpanFamilyV1;

/// Artifact-independent Search-v1 production families.
///
/// A row here authorizes only a source-reviewed compiler/manifest/backend/ABI/
/// ISA and literal-width envelope. Every concrete linked image still undergoes
/// strict expectation/metadata inspection, immutable mapping checks, payload
/// hashing, live-literal KIR reconstruction, and byte-for-byte native payload
/// regeneration before adoption.
///
/// This table remains empty until the broad held-out performance transaction
/// identifies an evidence-backed minimum input size and literal-width set.
pub(super) const PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1:
    &[SourceQualifiedStaticSearchSpanFamilyV1] = &[];

const _: () = assert!(super::search_span_families_are_canonical(
    PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1
));
