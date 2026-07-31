use super::SourceQualifiedStaticSearchSpanRowV1;

impl SourceQualifiedStaticSearchSpanRowV1 {
    /// Construct one literal row in this production authority atom.
    ///
    /// Defining the private method in this child module keeps it inaccessible
    /// to the parent support module, `private_rows`, all runtime/routing
    /// siblings, downstream crates, generated build output, and metadata.
    #[allow(
        dead_code,
        clippy::too_many_arguments,
        reason = "the production atom retains this solely for canonical reviewed row construction"
    )]
    const fn production(
        selector: u16,
        live_literal_bytes: u32,
        manifest_identity: [u8; 32],
        semantic_binding_identity: [u8; 32],
        literal_identity: [u8; 32],
        kir_identity: [u8; 32],
        artifact_identity: [u8; 32],
        binding_identity: [u8; 32],
        compile_identity: [u8; 32],
        object_identity: [u8; 32],
        receipt_identity: [u8; 32],
        expectation_identity: [u8; 32],
        payload_identity: [u8; 32],
    ) -> Self {
        Self {
            selector,
            live_literal_bytes,
            manifest_identity: super::SourceQualifiedManifestIdentityV1(manifest_identity),
            semantic_binding_identity: super::SourceQualifiedSemanticBindingIdentityV1(
                semantic_binding_identity,
            ),
            literal_identity: super::SourceQualifiedLiteralIdentityV1(literal_identity),
            kir_identity: super::SourceQualifiedKirIdentityV1(kir_identity),
            artifact_identity: super::SourceQualifiedArtifactIdentityV1(artifact_identity),
            binding_identity: super::SourceQualifiedBindingIdentityV1(binding_identity),
            compile_identity: super::SourceQualifiedCompileIdentityV1(compile_identity),
            object_identity: super::SourceQualifiedObjectIdentityV1(object_identity),
            receipt_identity: super::SourceQualifiedReceiptIdentityV1(receipt_identity),
            expectation_identity: super::SourceQualifiedExpectationIdentityV1(expectation_identity),
            payload_identity: super::SourceQualifiedPayloadIdentityV1(payload_identity),
        }
    }
}

/// Literal, source-reviewed production Search-v1 Span qualification rows.
///
/// No independently authorized Search-v1 Span final image has been promoted
/// for ordinary runtime use. This complete production authority atom therefore
/// begins as, and is compile-time constrained to remain, a canonical empty
/// table.
pub(super) const PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1:
    &[SourceQualifiedStaticSearchSpanRowV1] = &[];

const _: () = assert!(super::qualification_rows_are_canonical(
    PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1
));
const _: () = assert!(PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1.is_empty());
