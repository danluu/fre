//! Source-owned authority for optimizing Count-v3 static artifacts.
//!
//! Compiler output and artifact self-hashes are deliberately absent here.
//! Production authority is an exact match on the complete, artifact-independent
//! eligibility tuple.  The table starts empty and can change only in a
//! reviewed source promotion.

use fre_aot_count_contract::v3::{CountGeneralEligibilityTupleV3, CountObjectFormatV3};

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
/// source-reviewed movable ASIMD class.
///
/// SVE/SVE2 rows use the disjoint same-thread adopter, which authenticates its
/// caller-supplied tuple before reading an address. An SVE-only promotion must
/// therefore not open the ordinary movable-handle address boundary.
pub(crate) fn require_nonempty_production_asimd_authority() -> Result<(), StaticCountVerifyErrorV3>
{
    if !PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS
        .iter()
        .any(|tuple| tuple.required_isa_id == 1 && production_tuple_target_shape_is_closed(tuple))
    {
        Err(StaticCountVerifyErrorV3::NoProductionAuthority)
    } else {
        Ok(())
    }
}

/// Match every field of the artifact-independent eligibility tuple exactly.
pub(crate) fn require_production_tuple(
    tuple: CountGeneralEligibilityTupleV3,
) -> Result<(), StaticCountVerifyErrorV3> {
    if PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS.is_empty() {
        return Err(StaticCountVerifyErrorV3::NoProductionAuthority);
    }
    if production_tuple_target_shape_is_closed(&tuple)
        && PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS.contains(&tuple)
    {
        Ok(())
    } else {
        Err(StaticCountVerifyErrorV3::EligibilityTupleNotAuthorized)
    }
}

fn production_tuple_target_shape_is_closed(tuple: &CountGeneralEligibilityTupleV3) -> bool {
    production_target_shape_is_closed(
        tuple.required_isa_id,
        tuple.register_plan_id,
        tuple.actual_features,
        tuple.allowed_features,
        tuple.object_format,
        tuple.candidate_block_starts,
        tuple.vector_bytes,
        tuple.sve_vector_length_bytes,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the source-authority target closure is an explicit fixed wire projection"
)]
const fn production_target_shape_is_closed(
    required_isa_id: u8,
    register_plan_id: u8,
    actual_features: u64,
    allowed_features: u64,
    object_format: CountObjectFormatV3,
    candidate_block_starts: u8,
    vector_bytes: u16,
    sve_vector_length_bytes: u16,
) -> bool {
    if candidate_block_starts != 16 || vector_bytes != 16 {
        return false;
    }
    match required_isa_id {
        1 => {
            register_plan_id == 1
                && actual_features == 1
                && allowed_features == 1
                && sve_vector_length_bytes == 0
        }
        2 => {
            register_plan_id == 4
                && actual_features == 3
                && allowed_features == 3
                && matches!(object_format, CountObjectFormatV3::Elf64Aarch64)
                && sve_vector_length_bytes == 16
        }
        3 => {
            register_plan_id == 5
                && actual_features == 7
                && allowed_features == 7
                && matches!(object_format, CountObjectFormatV3::Elf64Aarch64)
                && sve_vector_length_bytes == 16
        }
        _ => false,
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
            require_nonempty_production_asimd_authority(),
            Err(StaticCountVerifyErrorV3::NoProductionAuthority)
        );
        assert!(identity_is_zero(&COUNT_V3_PROMOTION_BUNDLE_MANIFEST_SHA256));
    }

    #[test]
    fn dormant_source_rows_represent_only_mixed_sve_register_plans() {
        assert!(production_target_shape_is_closed(
            2,
            4,
            3,
            3,
            CountObjectFormatV3::Elf64Aarch64,
            16,
            16,
            16,
        ));
        assert!(production_target_shape_is_closed(
            3,
            5,
            7,
            7,
            CountObjectFormatV3::Elf64Aarch64,
            16,
            16,
            16,
        ));
        for (required_isa_id, register_plan_id, features) in
            [(2, 2, 2), (3, 3, 6), (2, 4, 2), (3, 5, 6)]
        {
            assert!(!production_target_shape_is_closed(
                required_isa_id,
                register_plan_id,
                features,
                features,
                CountObjectFormatV3::Elf64Aarch64,
                16,
                16,
                16,
            ));
        }
        assert!(PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS.is_empty());
        assert!(identity_is_zero(&COUNT_V3_PROMOTION_BUNDLE_MANIFEST_SHA256));
    }
}
