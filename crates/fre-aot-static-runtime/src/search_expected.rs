use fre_aot_search_contract::{
    ClaimedSearchMetadataV1, ClaimedStaticSearchSpanExpectationV1,
    inspect_static_search_span_expectation_v1,
};

use crate::{
    StaticSearchSpanContractFieldV1, StaticSearchSpanVerifyErrorV1,
    error::require_search_span_v1,
    search_support::{
        SourceQualifiedStaticSearchSpanFamilyV1, SourceQualifiedStaticSearchSpanRowV1,
    },
};

/// Private typed projection of a strictly inspected, source-qualified Search
/// V1 Span expectation.
///
/// The neutral contract returns claims. Runtime authority begins only after
/// every authority-bearing identity and the live width match the private row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedStaticSearchSpanV1 {
    claim: ClaimedStaticSearchSpanExpectationV1,
}

impl ExpectedStaticSearchSpanV1 {
    pub(crate) fn from_source_qualified_family_bytes(
        bytes: &[u8],
        family: &SourceQualifiedStaticSearchSpanFamilyV1,
    ) -> Result<Self, StaticSearchSpanVerifyErrorV1> {
        let claim = inspect_static_search_span_expectation_v1(bytes)?;
        family.authenticates_claim(claim)?;
        // The neutral decoder already recomputed the expectation identity,
        // metadata compile identity, and all duplicated metadata fields.
        // The mapped-image boundary completes concrete semantic authority by
        // independently regenerating the exact KIR and payload.
        Ok(Self { claim })
    }

    pub(crate) fn from_source_qualified_bytes(
        bytes: &[u8],
        row: &SourceQualifiedStaticSearchSpanRowV1,
        claimed_linked_compile_identity: &[u8; 32],
    ) -> Result<Self, StaticSearchSpanVerifyErrorV1> {
        let claim = inspect_static_search_span_expectation_v1(bytes)?;
        require_search_span_v1(
            row.compile_identity() == claimed_linked_compile_identity,
            StaticSearchSpanContractFieldV1::SelectedCompileIdentity,
        )?;
        require_search_span_v1(
            claim.manifest_identity() == row.manifest_identity(),
            StaticSearchSpanContractFieldV1::ManifestIdentity,
        )?;
        require_search_span_v1(
            claim.semantic_binding_identity() == row.semantic_binding_identity(),
            StaticSearchSpanContractFieldV1::SemanticBindingIdentity,
        )?;
        require_search_span_v1(
            claim.literal_identity() == row.literal_identity(),
            StaticSearchSpanContractFieldV1::LiteralIdentity,
        )?;
        require_search_span_v1(
            claim.live_literal_bytes() == row.live_literal_bytes(),
            StaticSearchSpanContractFieldV1::LiveLiteralBytes,
        )?;
        require_search_span_v1(
            claim.kir_identity() == row.kir_identity(),
            StaticSearchSpanContractFieldV1::KirIdentity,
        )?;
        require_search_span_v1(
            claim.artifact_identity() == row.artifact_identity(),
            StaticSearchSpanContractFieldV1::ArtifactIdentity,
        )?;
        require_search_span_v1(
            claim.binding_identity() == row.binding_identity(),
            StaticSearchSpanContractFieldV1::BindingIdentity,
        )?;
        require_search_span_v1(
            claim.compile_identity() == row.compile_identity(),
            StaticSearchSpanContractFieldV1::CompileIdentity,
        )?;
        require_search_span_v1(
            claim.object_identity() == row.object_identity(),
            StaticSearchSpanContractFieldV1::ObjectIdentity,
        )?;
        require_search_span_v1(
            claim.receipt_identity() == row.receipt_identity(),
            StaticSearchSpanContractFieldV1::ReceiptIdentity,
        )?;
        require_search_span_v1(
            claim.expectation_identity() == row.expectation_identity(),
            StaticSearchSpanContractFieldV1::ExpectationIdentity,
        )?;

        let metadata = claim.metadata();
        require_search_span_v1(
            metadata.source_identity() == row.kir_identity(),
            StaticSearchSpanContractFieldV1::KirIdentity,
        )?;
        require_search_span_v1(
            metadata.artifact_identity() == row.artifact_identity(),
            StaticSearchSpanContractFieldV1::ArtifactIdentity,
        )?;
        require_search_span_v1(
            metadata.binding_identity() == row.binding_identity(),
            StaticSearchSpanContractFieldV1::BindingIdentity,
        )?;
        require_search_span_v1(
            metadata.compile_identity() == row.compile_identity(),
            StaticSearchSpanContractFieldV1::CompileIdentity,
        )?;
        require_search_span_v1(
            metadata.payload_sha256() == row.payload_identity(),
            StaticSearchSpanContractFieldV1::PayloadIdentity,
        )?;
        Ok(Self { claim })
    }

    pub(crate) const fn metadata(&self) -> ClaimedSearchMetadataV1 {
        self.claim.metadata()
    }

    pub(crate) const fn payload_identity(&self) -> [u8; 32] {
        *self.claim.metadata().payload_sha256()
    }

    pub(crate) const fn live_literal_bytes(&self) -> u32 {
        self.claim.live_literal_bytes()
    }

    pub(crate) const fn manifest_identity(&self) -> &[u8; 32] {
        self.claim.manifest_identity()
    }

    pub(crate) const fn semantic_binding_identity(&self) -> &[u8; 32] {
        self.claim.semantic_binding_identity()
    }

    pub(crate) const fn literal_identity(&self) -> &[u8; 32] {
        self.claim.literal_identity()
    }

    pub(crate) const fn kir_identity(&self) -> &[u8; 32] {
        self.claim.kir_identity()
    }

    pub(crate) const fn artifact_identity(&self) -> &[u8; 32] {
        self.claim.artifact_identity()
    }

    pub(crate) const fn binding_identity(&self) -> &[u8; 32] {
        self.claim.binding_identity()
    }

    pub(crate) const fn compile_identity(&self) -> &[u8; 32] {
        self.claim.compile_identity()
    }

    pub(crate) const fn object_identity(&self) -> &[u8; 32] {
        self.claim.object_identity()
    }

    pub(crate) const fn receipt_identity(&self) -> &[u8; 32] {
        self.claim.receipt_identity()
    }

    pub(crate) const fn expectation_identity(&self) -> &[u8; 32] {
        self.claim.expectation_identity()
    }
}

#[cfg(test)]
mod tests {
    use fre_aot_search_contract::{
        STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1,
        STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1,
        compute_static_search_span_expectation_identity_v1,
    };

    use super::*;
    use crate::{
        search_support::SourceQualifiedStaticSearchSpanRowV1,
        search_test_fixture::static_search_span_fixture_v1,
    };

    #[test]
    fn exact_584_byte_expectation_is_source_qualified() {
        let fixture = static_search_span_fixture_v1();
        let expected = ExpectedStaticSearchSpanV1::from_source_qualified_bytes(
            &fixture.expectation,
            &fixture.row,
            fixture.row.compile_identity(),
        )
        .expect("exact source-qualified expectation");
        assert_eq!(expected.compile_identity(), fixture.row.compile_identity());
        assert_eq!(
            expected.expectation_identity(),
            fixture.row.expectation_identity()
        );
        assert_eq!(
            expected.metadata().payload_sha256(),
            fixture.row.payload_identity()
        );
    }

    #[test]
    fn every_expectation_byte_mutation_is_refused() {
        let fixture = static_search_span_fixture_v1();
        for index in 0..fixture.expectation.len() {
            let mut mutated = fixture.expectation;
            mutated[index] ^= 1;
            assert!(
                ExpectedStaticSearchSpanV1::from_source_qualified_bytes(
                    &mutated,
                    &fixture.row,
                    fixture.row.compile_identity(),
                )
                .is_err(),
                "mutated expectation byte {index} was accepted"
            );
        }
    }

    #[test]
    fn internally_rehashed_identity_splices_remain_unqualified() {
        let fixture = static_search_span_fixture_v1();
        for offset in (48..336).step_by(32) {
            let mut splice = fixture.expectation;
            splice[offset] ^= 1;
            let body: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1] = splice
                .get(..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1)
                .and_then(|bytes| bytes.try_into().ok())
                .expect("fixed expectation body");
            let identity = compute_static_search_span_expectation_identity_v1(body);
            splice[STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1..].copy_from_slice(&identity);
            assert!(
                ExpectedStaticSearchSpanV1::from_source_qualified_bytes(
                    &splice,
                    &fixture.row,
                    fixture.row.compile_identity(),
                )
                .is_err(),
                "rehashed identity splice at {offset} was accepted"
            );
        }
    }

    #[test]
    fn every_private_row_authority_field_is_bound() {
        let fixture = static_search_span_fixture_v1();
        let row = fixture.row;
        for field in 0..12 {
            let mut live_literal_bytes = row.live_literal_bytes();
            let mut manifest = *row.manifest_identity();
            let mut semantic = *row.semantic_binding_identity();
            let mut literal = *row.literal_identity();
            let mut kir = *row.kir_identity();
            let mut artifact = *row.artifact_identity();
            let mut binding = *row.binding_identity();
            let mut compile = *row.compile_identity();
            let mut object = *row.object_identity();
            let mut receipt = *row.receipt_identity();
            let mut expectation = *row.expectation_identity();
            let mut payload = *row.payload_identity();
            match field {
                0 => live_literal_bytes ^= 1,
                1 => manifest[0] ^= 1,
                2 => semantic[0] ^= 1,
                3 => literal[0] ^= 1,
                4 => kir[0] ^= 1,
                5 => artifact[0] ^= 1,
                6 => binding[0] ^= 1,
                7 => compile[0] ^= 1,
                8 => object[0] ^= 1,
                9 => receipt[0] ^= 1,
                10 => expectation[0] ^= 1,
                11 => payload[0] ^= 1,
                _ => unreachable!(),
            }
            let changed = SourceQualifiedStaticSearchSpanRowV1::test_only(
                row.selector(),
                live_literal_bytes,
                manifest,
                semantic,
                literal,
                kir,
                artifact,
                binding,
                compile,
                object,
                receipt,
                expectation,
                payload,
            );
            assert!(
                ExpectedStaticSearchSpanV1::from_source_qualified_bytes(
                    &fixture.expectation,
                    &changed,
                    changed.compile_identity(),
                )
                .is_err(),
                "changed row authority field {field} was accepted"
            );
        }
    }

    #[test]
    fn linked_compile_claim_is_independently_bound() {
        let fixture = static_search_span_fixture_v1();
        let mut changed = *fixture.row.compile_identity();
        changed[0] ^= 1;
        assert_eq!(
            ExpectedStaticSearchSpanV1::from_source_qualified_bytes(
                &fixture.expectation,
                &fixture.row,
                &changed,
            ),
            Err(StaticSearchSpanVerifyErrorV1::ContractMismatch {
                field: StaticSearchSpanContractFieldV1::SelectedCompileIdentity,
            })
        );
    }
}
