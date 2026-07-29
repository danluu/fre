use fre_aot_count_contract::v3::{
    ClaimedCountMetadataV3, ClaimedStaticCountExpectationV3, CountGeneralEligibilityTupleV3,
    inspect_static_count_expectation_v3,
};

use crate::StaticCountVerifyErrorV3;

/// Private projection of a canonical but still unauthoritative expectation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedStaticCountV3 {
    claim: ClaimedStaticCountExpectationV3,
}

impl ExpectedStaticCountV3 {
    pub(crate) fn inspect(bytes: &[u8]) -> Result<Self, StaticCountVerifyErrorV3> {
        Ok(Self {
            claim: inspect_static_count_expectation_v3(bytes)?,
        })
    }

    pub(crate) const fn metadata(&self) -> ClaimedCountMetadataV3 {
        self.claim.metadata()
    }

    pub(crate) const fn eligibility_tuple(&self) -> CountGeneralEligibilityTupleV3 {
        self.claim.metadata().general_eligibility_tuple()
    }

    pub(crate) const fn semantic_binding_identity(&self) -> &[u8; 32] {
        self.claim.semantic_binding_identity()
    }

    pub(crate) const fn planning_receipt_identity(&self) -> &[u8; 32] {
        self.claim.planning_receipt_identity()
    }

    pub(crate) const fn expectation_identity(&self) -> &[u8; 32] {
        self.claim.expectation_identity()
    }

    pub(crate) const fn compile_identity(&self) -> &[u8; 32] {
        self.claim.compile_identity()
    }

    pub(crate) const fn object_identity(&self) -> &[u8; 32] {
        self.claim.object_identity()
    }

    pub(crate) const fn live_literal_bytes(&self) -> u32 {
        self.claim.live_literal_bytes()
    }
}
