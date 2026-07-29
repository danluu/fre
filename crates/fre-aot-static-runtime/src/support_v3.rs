//! Source-owned authority for optimizing Count-v3 static artifacts.
//!
//! Compiler output and artifact self-hashes are deliberately absent here.
//! Production authority is an exact match on the complete, artifact-independent
//! eligibility tuple.  The table starts empty and can change only in a
//! reviewed source promotion.

use fre_aot_count_contract::v3::CountGeneralEligibilityTupleV3;

use crate::StaticCountVerifyErrorV3;

/// Hard source-review ceiling for one Count-v3 promotion transaction.
pub(crate) const HARD_MAX_STATIC_COUNT_ELIGIBILITY_ROWS_V3: usize = 256;

/// Sealed qualification bundle identity.
///
/// All zeroes means that no Count-v3 class has been promoted. A future
/// promotion must update this atom and the exact tuple rows together.
const COUNT_V3_PROMOTION_BUNDLE_MANIFEST_SHA256: [u8; 32] = [0; 32];

/// Exact production classes admitted by reviewed held-out evidence.
///
/// This is intentionally empty. In particular, neither enabling a Cargo
/// feature nor presenting a compiler-produced expectation can add a row.
const PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS: &[CountGeneralEligibilityTupleV3] = &[];

const _: () = assert!(identity_is_zero(&COUNT_V3_PROMOTION_BUNDLE_MANIFEST_SHA256));
const _: () = assert!(PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS.is_empty());
const _: () = assert!(
    PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS.len() <= HARD_MAX_STATIC_COUNT_ELIGIBILITY_ROWS_V3
);

/// Refuse before touching any caller-provided address when production has no
/// source-reviewed class.
pub(crate) fn require_nonempty_production_authority() -> Result<(), StaticCountVerifyErrorV3> {
    if PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS.is_empty() {
        Err(StaticCountVerifyErrorV3::NoProductionAuthority)
    } else {
        Ok(())
    }
}

/// Match every field of the artifact-independent eligibility tuple exactly.
pub(crate) fn require_production_tuple(
    tuple: CountGeneralEligibilityTupleV3,
) -> Result<(), StaticCountVerifyErrorV3> {
    require_nonempty_production_authority()?;
    if PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS.contains(&tuple) {
        Ok(())
    } else {
        Err(StaticCountVerifyErrorV3::EligibilityTupleNotAuthorized)
    }
}

/// Private evidence-gathering authority.
///
/// This predicate exists only in a build with the default-off private feature.
/// It admits a tuple only after the contract inspector has proved that tuple's
/// complete closed shape. It cannot call, mutate, or populate the production
/// table and it is not consulted by the production adopter.
#[cfg(feature = "count-v3-qualification-private")]
pub(crate) const fn qualification_accepts_inspected_tuple(
    _tuple: CountGeneralEligibilityTupleV3,
) -> bool {
    true
}

const fn identity_is_zero(identity: &[u8; 32]) -> bool {
    let mut index = 0_usize;
    while index < identity.len() {
        if identity[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_authority_is_source_empty() {
        assert_eq!(
            require_nonempty_production_authority(),
            Err(StaticCountVerifyErrorV3::NoProductionAuthority)
        );
        assert!(identity_is_zero(&COUNT_V3_PROMOTION_BUNDLE_MANIFEST_SHA256));
    }
}
