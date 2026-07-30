//! Source-owned authority for optimizing Count-v3 static artifacts.
//!
//! Compiler output and artifact self-hashes are deliberately absent here.
//! Production authority is an exact match on the complete, artifact-independent
//! eligibility tuple. The table can change only in a reviewed source promotion.

use fre_aot_count_contract::v3::{CountGeneralEligibilityTupleV3, CountObjectFormatV3};

use crate::StaticCountVerifyErrorV3;

/// Hard source-review ceiling for one Count-v3 promotion transaction.
pub(crate) const HARD_MAX_STATIC_COUNT_ELIGIBILITY_ROWS_V3: usize = 256;

/// Sealed qualification bundle identity.
///
/// This atom and the exact tuple rows must be updated together.
const COUNT_V3_PROMOTION_BUNDLE_MANIFEST_SHA256: [u8; 32] = [
    0xaf, 0x3a, 0x72, 0x0e, 0xbb, 0xf4, 0x95, 0xdb, 0xc2, 0x1a, 0x28, 0x76, 0xf8, 0x6d, 0x24, 0x48,
    0x17, 0x81, 0x3e, 0x7a, 0x70, 0xbf, 0x86, 0xcb, 0xd2, 0x7b, 0xb4, 0x80, 0xa1, 0x37, 0x2e, 0x20,
];

/// Exact production classes admitted by reviewed held-out evidence.
///
/// Neither enabling a Cargo feature nor presenting a compiler-produced
/// expectation can add a row.
const PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS: &[CountGeneralEligibilityTupleV3] =
    &[CountGeneralEligibilityTupleV3 {
        compiler_version: 3,
        metadata_version: 3,
        image_schema_version: 3,
        backend_version: 40963,
        algorithm_version: 11,
        auditor_version: 2,
        kir_semantics_version: 1,
        kir_abi_version: 1,
        recipe_schema_version: 3,
        optimizer_version: 7,
        tuning_class_id: 3,
        strategy_id: 2,
        schedule_id: 2,
        register_plan_id: 5,
        literal_bytes: 5,
        filter_len: 4,
        sparse_group_count: 1,
        match_stride: 5,
        periodic_stride: 0,
        call_abi_schema: 2,
        abi_kind: 2,
        status_bits: 64,
        output_kind: 1,
        architecture: 1,
        little_endian: true,
        pointer_width: 64,
        target_abi: 1,
        object_format: fre_aot_count_contract::v3::CountObjectFormatV3::Elf64Aarch64,
        required_isa_id: 3,
        actual_features: 7,
        allowed_features: 7,
        candidate_block_starts: 16,
        vector_bytes: 16,
        sve_vector_length_bytes: 16,
        max_literal_bytes: 32,
    }];

const _: () = assert!(!identity_is_zero(
    &COUNT_V3_PROMOTION_BUNDLE_MANIFEST_SHA256
));
const _: () = assert!(!PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS.is_empty());
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
    fn sve2_authority_is_bound_while_movable_asimd_remains_closed() {
        assert_eq!(
            require_nonempty_production_asimd_authority(),
            Err(StaticCountVerifyErrorV3::NoProductionAuthority)
        );
        assert!(!identity_is_zero(
            &COUNT_V3_PROMOTION_BUNDLE_MANIFEST_SHA256
        ));
        assert_eq!(PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS.len(), 1);
        let promoted = PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS[0];
        assert_eq!(require_production_tuple(promoted), Ok(()));
        let mut changed = promoted;
        changed.filter_len -= 1;
        assert_eq!(
            require_production_tuple(changed),
            Err(StaticCountVerifyErrorV3::EligibilityTupleNotAuthorized)
        );
    }

    #[test]
    fn source_rows_are_unique_closed_and_sve2_only() {
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
        for (index, tuple) in PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS.iter().enumerate() {
            assert_eq!(tuple.required_isa_id, 3);
            assert!(production_tuple_target_shape_is_closed(tuple));
            assert!(
                !PRODUCTION_COUNT_V3_ELIGIBILITY_ROWS[..index].contains(tuple),
                "production tuple {index} is duplicated"
            );
        }
    }
}
