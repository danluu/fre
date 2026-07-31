use fre_aot_count_contract::{
    ClaimedCountMetadataV2, ClaimedStaticCountExpectationV2, inspect_static_count_expectation_v2,
};

use crate::{
    StaticContractField, StaticVerifyError, error::require, support::QualifiedStaticCountRowV2,
};

/// Private typed projection of a strictly inspected and qualified expectation.
///
/// Identity arrays in the compiler claim remain claims; authority comes from
/// the private row and every authority-bearing field is compared here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedStaticCountV2 {
    claim: ClaimedStaticCountExpectationV2,
}

impl ExpectedStaticCountV2 {
    pub(crate) fn from_qualified_bytes(
        bytes: &[u8],
        row: &QualifiedStaticCountRowV2,
        claimed_linked_compile_identity: &[u8; 32],
    ) -> Result<Self, StaticVerifyError> {
        let claim = inspect_static_count_expectation_v2(bytes)?;
        require(
            row.compile_identity() == claimed_linked_compile_identity,
            StaticContractField::SelectedCompileIdentity,
        )?;
        require(
            claim.compile_identity() == row.compile_identity(),
            StaticContractField::CompileIdentity,
        )?;
        require(
            claim.expectation_identity() == row.expectation_identity(),
            StaticContractField::ExpectationIdentity,
        )?;
        require(
            claim.object_identity() == row.object_identity(),
            StaticContractField::ObjectIdentity,
        )?;
        require(
            claim.receipt_identity() == row.receipt_identity(),
            StaticContractField::ReceiptIdentity,
        )?;
        require(
            claim.resource_receipt_identity() == row.resource_receipt_identity(),
            StaticContractField::ResourceReceiptIdentity,
        )?;
        Ok(Self { claim })
    }

    #[allow(
        dead_code,
        reason = "the mapped-image verifier is feature-gated while the production row table remains empty"
    )]
    pub(crate) const fn metadata(&self) -> ClaimedCountMetadataV2 {
        self.claim.metadata()
    }

    pub(crate) const fn live_literal_bytes(&self) -> u32 {
        self.claim.live_literal_bytes()
    }

    pub(crate) const fn compile_identity(&self) -> &[u8; 32] {
        self.claim.compile_identity()
    }

    pub(crate) const fn expectation_identity(&self) -> &[u8; 32] {
        self.claim.expectation_identity()
    }

    pub(crate) const fn receipt_identity(&self) -> &[u8; 32] {
        self.claim.receipt_identity()
    }

    pub(crate) const fn object_identity(&self) -> &[u8; 32] {
        self.claim.object_identity()
    }

    pub(crate) const fn resource_receipt_identity(&self) -> &[u8; 32] {
        self.claim.resource_receipt_identity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixture::static_fixture_v2;

    #[test]
    fn exact_672_byte_expectation_is_qualified() {
        let fixture = static_fixture_v2();
        let bytes = fixture.expectation;
        let row = fixture.row;
        let expected =
            ExpectedStaticCountV2::from_qualified_bytes(&bytes, &row, row.compile_identity())
                .expect("exact qualified expectation");
        assert_eq!(expected.compile_identity(), row.compile_identity());
        assert_eq!(expected.expectation_identity(), row.expectation_identity());
    }

    #[test]
    fn every_expectation_byte_mutation_is_refused() {
        let fixture = static_fixture_v2();
        let original = fixture.expectation;
        let row = fixture.row;
        for index in 0..original.len() {
            let mut mutated = original;
            mutated[index] ^= 1;
            assert!(
                ExpectedStaticCountV2::from_qualified_bytes(
                    &mutated,
                    &row,
                    row.compile_identity(),
                )
                .is_err(),
                "mutated expectation byte {index} was accepted"
            );
        }
    }

    #[test]
    fn every_private_qualification_identity_is_bound() {
        let fixture = static_fixture_v2();
        let bytes = fixture.expectation;
        let row = fixture.row;
        for field in 0..5 {
            let mut compile = *row.compile_identity();
            let mut expectation = *row.expectation_identity();
            let mut object = *row.object_identity();
            let mut receipt = *row.receipt_identity();
            let mut resource = *row.resource_receipt_identity();
            match field {
                0 => compile[0] ^= 1,
                1 => expectation[0] ^= 1,
                2 => object[0] ^= 1,
                3 => receipt[0] ^= 1,
                4 => resource[0] ^= 1,
                _ => unreachable!(),
            }
            let changed = QualifiedStaticCountRowV2::test_only(
                row.selector(),
                compile,
                expectation,
                object,
                receipt,
                resource,
            );
            assert!(
                ExpectedStaticCountV2::from_qualified_bytes(
                    &bytes,
                    &changed,
                    changed.compile_identity(),
                )
                .is_err()
            );
        }
    }
}
