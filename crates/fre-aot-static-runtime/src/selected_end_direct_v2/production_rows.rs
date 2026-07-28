use super::SourceQualifiedStaticSearchSelectedEndRowV2;

impl SourceQualifiedStaticSearchSelectedEndRowV2 {
    /// Construct one literal row in this production authority atom.
    ///
    /// Defining the constructor in this private child module keeps it
    /// inaccessible to the parent lookup code, qualification-private code,
    /// downstream crates, generated output, build scripts, and metadata.
    #[allow(
        dead_code,
        clippy::too_many_arguments,
        reason = "the production atom retains this solely for complete reviewed row construction"
    )]
    const fn production(
        manifest_identity: [u8; 32],
        source_identity: [u8; 32],
        semantic_binding_identity: [u8; 32],
        literal_identity: [u8; 32],
        kir_identity: [u8; 32],
        artifact_identity: [u8; 32],
        binding_identity: [u8; 32],
        compile_identity: [u8; 32],
        implementation_object_identity: [u8; 32],
        compiler_receipt_identity: [u8; 32],
        expectation_identity: [u8; 32],
        full_payload_identity: [u8; 32],
        glue_source_identity: [u8; 32],
        direct_header_identity: [u8; 32],
        glue_code_identity: [u8; 32],
        glue_object_identity: [u8; 32],
        bundle_identity: [u8; 32],
        full_payload_bytes: u32,
        literal: [u8; super::SELECTED_END_LITERAL_BYTES_V2],
    ) -> Self {
        Self {
            manifest_identity: super::SourceQualifiedManifestIdentityV2(manifest_identity),
            source_identity: super::SourceQualifiedSourceIdentityV2(source_identity),
            semantic_binding_identity: super::SourceQualifiedSemanticBindingIdentityV2(
                semantic_binding_identity,
            ),
            literal_identity: super::SourceQualifiedLiteralIdentityV2(literal_identity),
            kir_identity: super::SourceQualifiedKirIdentityV2(kir_identity),
            artifact_identity: super::SourceQualifiedArtifactIdentityV2(artifact_identity),
            binding_identity: super::SourceQualifiedBindingIdentityV2(binding_identity),
            compile_identity: super::SourceQualifiedCompileIdentityV2(compile_identity),
            implementation_object_identity: super::SourceQualifiedImplementationObjectIdentityV2(
                implementation_object_identity,
            ),
            compiler_receipt_identity: super::SourceQualifiedCompilerReceiptIdentityV2(
                compiler_receipt_identity,
            ),
            expectation_identity: super::SourceQualifiedExpectationIdentityV2(expectation_identity),
            full_payload_identity: super::SourceQualifiedFullPayloadIdentityV2(
                full_payload_identity,
            ),
            glue_source_identity: super::SourceQualifiedGlueSourceIdentityV2(glue_source_identity),
            direct_header_identity: super::SourceQualifiedDirectHeaderIdentityV2(
                direct_header_identity,
            ),
            glue_code_identity: super::SourceQualifiedGlueCodeIdentityV2(glue_code_identity),
            glue_object_identity: super::SourceQualifiedGlueObjectIdentityV2(glue_object_identity),
            bundle_identity: super::SourceQualifiedBundleIdentityV2(bundle_identity),
            full_payload_bytes,
            literal,
        }
    }
}

/// Literal, source-reviewed production tag21/VL16 `SelectedEnd` ABI2 rows.
///
/// No final image has completed the independent post-link qualification and
/// production review required for ordinary runtime use. This authority atom
/// therefore begins as, and is compile-time constrained to remain, an empty
/// canonical table. A promotion is a separate source transaction that must
/// replace the empty-table assertion with the reviewed exact row. Canonical
/// validation rejects every zero identity, a zero payload extent, duplicate or
/// unsorted compile identities, and over-capacity tables before any future row
/// can grant authority. The exact literal remains an unrestricted 16-byte
/// binary value and is matched byte-for-byte during adoption.
pub(super) const PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SELECTED_END_ROWS_V2:
    &[SourceQualifiedStaticSearchSelectedEndRowV2] = &[];

const _: () = assert!(super::production_rows_are_canonical_v2(
    PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SELECTED_END_ROWS_V2
));
const _: () = assert!(PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SELECTED_END_ROWS_V2.is_empty());
