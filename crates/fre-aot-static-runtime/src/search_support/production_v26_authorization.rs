use super::SourceQualifiedStaticSearchSpanFamilyV1;
use fre_aot_search_contract::{
    SEARCH_BACKEND_ASIMD_TAG39_V1, SEARCH_PLATFORM_LINUX_V1, SEARCH_PLATFORM_MACOS_V1,
    SEARCH_V26_MAX_LITERAL_BYTES_V1, SEARCH_V26_MIN_LITERAL_BYTES_V1,
    SEARCH_V26_PORTABLE_MAX_LITERAL_BYTES_V1, SEARCH_V26_PRODUCTION_MIN_LITERAL_BYTES_V1,
};

/// Source-sealed authority chain required before tag39 can enter the ordinary
/// production family table.
///
/// This private shape mirrors the frozen V26 review transaction. Generated
/// objects, linked glue, Cargo features, and qualification output cannot
/// construct it. The checked-in value remains [`None`]; a future promotion
/// must independently review and replace this exact source atom as well as
/// adding target-conditional family rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    clippy::struct_excessive_bools,
    reason = "the complete source authority shape is retained while the V26 production atom is deliberately absent"
)]
pub(super) struct SearchV26ProductionAuthorizationV1 {
    v25_terminal_failed: bool,
    v25_terminal_analysis_sha256: [u8; 32],
    source_commit: [u8; 20],
    source_tree: [u8; 20],
    regex_codegen_architecture_review_sha256: [u8; 32],
    regex_codegen_uses_llvm: bool,
    campaign_is_fresh_and_disjoint_from_v25: bool,
    campaign_contract_sha256: [u8; 32],
    development_pass_sha256: [u8; 32],
    two_host_correctness_gate_sha256: [u8; 32],
    heldout_pass_sha256: [u8; 32],
    heldout_analysis_sha256: [u8; 32],
    production_review_sha256: [u8; 32],
    authorization_sha256: [u8; 32],
    source_inventory_review_sha256: [u8; 32],
    macos_build_receipt_sha256: [u8; 32],
    macos_final_image_review_sha256: [u8; 32],
    linux_build_receipt_sha256: [u8; 32],
    linux_final_image_review_sha256: [u8; 32],
    selector: u16,
    candidate_minimum_literal_bytes: u32,
    portable_maximum_literal_bytes: u32,
    production_minimum_literal_bytes: u32,
    maximum_literal_bytes: u32,
    short_width_production_authority: bool,
    minimum_window_bytes: u32,
    portable_prefix_candidate_starts: u32,
    macos_manifest_identity: [u8; 32],
    linux_manifest_identity: [u8; 32],
    plan_identity: [u8; 32],
    analyzer_identity: [u8; 32],
    evidence_identity: [u8; 32],
}

/// No V26 production authorization exists in this prequalification seam.
///
/// This absence is compile-time fixed and is not conditioned on Cargo
/// features. Consequently `--all-features` still cannot authorize tag39.
pub(super) const SEARCH_V26_PRODUCTION_AUTHORIZATION_V1: Option<
    SearchV26ProductionAuthorizationV1,
> = None;

const _: () = assert!(SEARCH_V26_PRODUCTION_AUTHORIZATION_V1.is_none());

/// Whether one target-conditional production row is exactly covered by the
/// separately sealed V26 authority chain.
pub(super) const fn authorizes(family: &SourceQualifiedStaticSearchSpanFamilyV1) -> bool {
    let Some(authorization) = SEARCH_V26_PRODUCTION_AUTHORIZATION_V1 else {
        return false;
    };
    authorization_matches(&authorization, family)
}

const fn authorization_matches(
    authorization: &SearchV26ProductionAuthorizationV1,
    family: &SourceQualifiedStaticSearchSpanFamilyV1,
) -> bool {
    if !all_authority_identities_are_nonzero(authorization)
        || !authorization.v25_terminal_failed
        || authorization.regex_codegen_uses_llvm
        || !authorization.campaign_is_fresh_and_disjoint_from_v25
        || authorization.short_width_production_authority
        || authorization.candidate_minimum_literal_bytes != SEARCH_V26_MIN_LITERAL_BYTES_V1
        || authorization.portable_maximum_literal_bytes != SEARCH_V26_PORTABLE_MAX_LITERAL_BYTES_V1
        || authorization.production_minimum_literal_bytes
            != SEARCH_V26_PRODUCTION_MIN_LITERAL_BYTES_V1
        || authorization.maximum_literal_bytes != SEARCH_V26_MAX_LITERAL_BYTES_V1
        || family.backend_version != SEARCH_BACKEND_ASIMD_TAG39_V1
        || family.selector != authorization.selector
        || family.minimum_literal_bytes != authorization.production_minimum_literal_bytes
        || family.maximum_literal_bytes != authorization.maximum_literal_bytes
        || family.minimum_window_bytes != authorization.minimum_window_bytes
        || family.portable_prefix_candidate_starts != authorization.portable_prefix_candidate_starts
        || !equal32(
            family.plan_identity.as_bytes(),
            &authorization.plan_identity,
        )
        || !equal32(
            family.analyzer_identity.as_bytes(),
            &authorization.analyzer_identity,
        )
        || !equal32(
            family.evidence_identity.as_bytes(),
            &authorization.evidence_identity,
        )
    {
        return false;
    }
    match family.platform {
        SEARCH_PLATFORM_MACOS_V1 => equal32(
            family.manifest_identity.as_bytes(),
            &authorization.macos_manifest_identity,
        ),
        SEARCH_PLATFORM_LINUX_V1 => equal32(
            family.manifest_identity.as_bytes(),
            &authorization.linux_manifest_identity,
        ),
        _ => false,
    }
}

const fn all_authority_identities_are_nonzero(
    authorization: &SearchV26ProductionAuthorizationV1,
) -> bool {
    nonzero32(&authorization.v25_terminal_analysis_sha256)
        && nonzero20(&authorization.source_commit)
        && nonzero20(&authorization.source_tree)
        && nonzero32(&authorization.regex_codegen_architecture_review_sha256)
        && nonzero32(&authorization.campaign_contract_sha256)
        && nonzero32(&authorization.development_pass_sha256)
        && nonzero32(&authorization.two_host_correctness_gate_sha256)
        && nonzero32(&authorization.heldout_pass_sha256)
        && nonzero32(&authorization.heldout_analysis_sha256)
        && nonzero32(&authorization.production_review_sha256)
        && nonzero32(&authorization.authorization_sha256)
        && nonzero32(&authorization.source_inventory_review_sha256)
        && nonzero32(&authorization.macos_build_receipt_sha256)
        && nonzero32(&authorization.macos_final_image_review_sha256)
        && nonzero32(&authorization.linux_build_receipt_sha256)
        && nonzero32(&authorization.linux_final_image_review_sha256)
        && nonzero32(&authorization.macos_manifest_identity)
        && nonzero32(&authorization.linux_manifest_identity)
        && nonzero32(&authorization.plan_identity)
        && nonzero32(&authorization.analyzer_identity)
        && nonzero32(&authorization.evidence_identity)
        && authorization.selector != 0
        && authorization.minimum_window_bytes != 0
        && authorization.portable_prefix_candidate_starts != 0
}

const fn nonzero20(value: &[u8; 20]) -> bool {
    let mut index = 0_usize;
    while index < value.len() {
        if value[index] != 0 {
            return true;
        }
        let Some(next) = index.checked_add(1) else {
            return false;
        };
        index = next;
    }
    false
}

const fn nonzero32(value: &[u8; 32]) -> bool {
    let mut index = 0_usize;
    while index < value.len() {
        if value[index] != 0 {
            return true;
        }
        let Some(next) = index.checked_add(1) else {
            return false;
        };
        index = next;
    }
    false
}

const fn equal32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut index = 0_usize;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        let Some(next) = index.checked_add(1) else {
            return false;
        };
        index = next;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization() -> SearchV26ProductionAuthorizationV1 {
        SearchV26ProductionAuthorizationV1 {
            v25_terminal_failed: true,
            v25_terminal_analysis_sha256: [0x01; 32],
            source_commit: [0x02; 20],
            source_tree: [0x03; 20],
            regex_codegen_architecture_review_sha256: [0x04; 32],
            regex_codegen_uses_llvm: false,
            campaign_is_fresh_and_disjoint_from_v25: true,
            campaign_contract_sha256: [0x05; 32],
            development_pass_sha256: [0x06; 32],
            two_host_correctness_gate_sha256: [0x07; 32],
            heldout_pass_sha256: [0x08; 32],
            heldout_analysis_sha256: [0x09; 32],
            production_review_sha256: [0x0a; 32],
            authorization_sha256: [0x0b; 32],
            source_inventory_review_sha256: [0x0c; 32],
            macos_build_receipt_sha256: [0x0d; 32],
            macos_final_image_review_sha256: [0x0e; 32],
            linux_build_receipt_sha256: [0x0f; 32],
            linux_final_image_review_sha256: [0x10; 32],
            selector: 17,
            candidate_minimum_literal_bytes: SEARCH_V26_MIN_LITERAL_BYTES_V1,
            portable_maximum_literal_bytes: SEARCH_V26_PORTABLE_MAX_LITERAL_BYTES_V1,
            production_minimum_literal_bytes: SEARCH_V26_PRODUCTION_MIN_LITERAL_BYTES_V1,
            maximum_literal_bytes: SEARCH_V26_MAX_LITERAL_BYTES_V1,
            short_width_production_authority: false,
            minimum_window_bytes: 4_093,
            portable_prefix_candidate_starts: 256,
            macos_manifest_identity: [0xa5; 32],
            linux_manifest_identity: [0x5a; 32],
            plan_identity: [0x6b; 32],
            analyzer_identity: [0x7c; 32],
            evidence_identity: [0x8d; 32],
        }
    }

    fn linux_family() -> SourceQualifiedStaticSearchSpanFamilyV1 {
        let mut family = SourceQualifiedStaticSearchSpanFamilyV1::test_only(
            17,
            SEARCH_V26_PRODUCTION_MIN_LITERAL_BYTES_V1,
            SEARCH_V26_MAX_LITERAL_BYTES_V1,
        );
        family.backend_version = SEARCH_BACKEND_ASIMD_TAG39_V1;
        family
    }

    #[test]
    fn complete_non_llvm_authority_matches_only_its_two_target_rows() {
        let authorization = authorization();
        let linux = linux_family();
        assert!(authorization_matches(&authorization, &linux));

        let mut macos = linux;
        macos.platform = SEARCH_PLATFORM_MACOS_V1;
        macos.exported_symbol_n_type = 0x0f;
        macos.manifest_identity.0 = authorization.macos_manifest_identity;
        assert!(authorization_matches(&authorization, &macos));

        let mut unsupported = linux;
        unsupported.platform = 9;
        assert!(!authorization_matches(&authorization, &unsupported));
    }

    #[test]
    fn authority_refuses_short_widths_llvm_stale_provenance_and_family_drift() {
        let canonical = authorization();
        let family = linux_family();

        let mut short_width = canonical;
        short_width.production_minimum_literal_bytes = SEARCH_V26_PORTABLE_MAX_LITERAL_BYTES_V1;
        assert!(!authorization_matches(&short_width, &family));

        let mut short_width_authority = canonical;
        short_width_authority.short_width_production_authority = true;
        assert!(!authorization_matches(&short_width_authority, &family));

        let mut llvm = canonical;
        llvm.regex_codegen_uses_llvm = true;
        assert!(!authorization_matches(&llvm, &family));

        let mut not_disjoint = canonical;
        not_disjoint.campaign_is_fresh_and_disjoint_from_v25 = false;
        assert!(!authorization_matches(&not_disjoint, &family));

        let mut zero_inventory_review = canonical;
        zero_inventory_review.source_inventory_review_sha256 = [0; 32];
        assert!(!authorization_matches(&zero_inventory_review, &family));

        let mut wrong_backend = family;
        wrong_backend.backend_version = 38;
        assert!(!authorization_matches(&canonical, &wrong_backend));

        let mut wrong_selector = family;
        wrong_selector.selector = canonical.selector.checked_add(1).unwrap();
        assert!(!authorization_matches(&canonical, &wrong_selector));

        let mut wrong_manifest = family;
        wrong_manifest.manifest_identity.0[0] ^= 0xff;
        assert!(!authorization_matches(&canonical, &wrong_manifest));
    }

    #[test]
    fn checked_in_authorization_is_unconditionally_absent() {
        assert!(SEARCH_V26_PRODUCTION_AUTHORIZATION_V1.is_none());
        assert!(!authorizes(&linux_family()));
    }
}
