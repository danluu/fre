use super::SourceQualifiedStaticSearchSpanFamilyV1;
use fre_aot_search_contract::{
    SEARCH_BACKEND_ASIMD_TAG38_V1, SEARCH_PLATFORM_LINUX_V1, SEARCH_PLATFORM_MACOS_V1,
};

/// Source-sealed authority chain required before tag38 can enter the ordinary
/// production family table.
///
/// This is deliberately a separate atom from the family tuple. A compiler
/// object, generated glue, Cargo feature, environment variable, or
/// qualification analyzer output cannot construct it. A later promotion must
/// replace [`SEARCH_V25_PRODUCTION_AUTHORIZATION_V1`] with one independently
/// reviewed value that binds the exact development decision, held-out
/// correctness seal, held-out analysis, production review, and both target
/// builds. `regex_codegen_uses_llvm` concerns the emitted regex payload, not
/// the implementation of the Rust compiler used to build these crates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the complete source authority shape is retained while the V25 production atom is deliberately absent"
)]
pub(super) struct SearchV25ProductionAuthorizationV1 {
    source_commit: [u8; 20],
    source_tree: [u8; 20],
    regex_codegen_architecture_review_sha256: [u8; 32],
    regex_codegen_uses_llvm: bool,
    development_pass_sha256: [u8; 32],
    campaign_contract_sha256: [u8; 32],
    correctness_binding_sha256: [u8; 32],
    two_host_correctness_gate_sha256: [u8; 32],
    heldout_analysis_sha256: [u8; 32],
    production_review_sha256: [u8; 32],
    authorization_sha256: [u8; 32],
    macos_build_receipt_sha256: [u8; 32],
    linux_build_receipt_sha256: [u8; 32],
    selector: u16,
    minimum_literal_bytes: u32,
    maximum_literal_bytes: u32,
    minimum_window_bytes: u32,
    portable_prefix_candidate_starts: u32,
    macos_manifest_identity: [u8; 32],
    linux_manifest_identity: [u8; 32],
    plan_identity: [u8; 32],
    analyzer_identity: [u8; 32],
    evidence_identity: [u8; 32],
}

/// No V25 production authorization exists in this scaffold.
///
/// Keeping the absence in a private source atom makes the unactivated state
/// reviewable and compile-time fixed. A future promotion must change this
/// exact file as well as the disjoint production-family atom.
pub(super) const SEARCH_V25_PRODUCTION_AUTHORIZATION_V1: Option<
    SearchV25ProductionAuthorizationV1,
> = None;

const _: () = assert!(SEARCH_V25_PRODUCTION_AUTHORIZATION_V1.is_none());

/// Whether one target-conditional production row is exactly covered by the
/// separately sealed V25 authority chain.
pub(super) const fn authorizes(family: &SourceQualifiedStaticSearchSpanFamilyV1) -> bool {
    let Some(authorization) = SEARCH_V25_PRODUCTION_AUTHORIZATION_V1 else {
        return false;
    };
    authorization_matches(&authorization, family)
}

const fn authorization_matches(
    authorization: &SearchV25ProductionAuthorizationV1,
    family: &SourceQualifiedStaticSearchSpanFamilyV1,
) -> bool {
    if !all_authority_identities_are_nonzero(authorization)
        || family.backend_version != SEARCH_BACKEND_ASIMD_TAG38_V1
        || family.selector != authorization.selector
        || family.minimum_literal_bytes != authorization.minimum_literal_bytes
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
    authorization: &SearchV25ProductionAuthorizationV1,
) -> bool {
    nonzero20(&authorization.source_commit)
        && nonzero20(&authorization.source_tree)
        && nonzero32(&authorization.regex_codegen_architecture_review_sha256)
        && !authorization.regex_codegen_uses_llvm
        && nonzero32(&authorization.development_pass_sha256)
        && nonzero32(&authorization.campaign_contract_sha256)
        && nonzero32(&authorization.correctness_binding_sha256)
        && nonzero32(&authorization.two_host_correctness_gate_sha256)
        && nonzero32(&authorization.heldout_analysis_sha256)
        && nonzero32(&authorization.production_review_sha256)
        && nonzero32(&authorization.authorization_sha256)
        && nonzero32(&authorization.macos_build_receipt_sha256)
        && nonzero32(&authorization.linux_build_receipt_sha256)
        && nonzero32(&authorization.macos_manifest_identity)
        && nonzero32(&authorization.linux_manifest_identity)
        && nonzero32(&authorization.plan_identity)
        && nonzero32(&authorization.analyzer_identity)
        && nonzero32(&authorization.evidence_identity)
        && authorization.selector != 0
        && authorization.minimum_literal_bytes != 0
        && authorization.minimum_literal_bytes <= authorization.maximum_literal_bytes
        && authorization.minimum_window_bytes != 0
        && authorization.portable_prefix_candidate_starts != 0
}

const fn nonzero20(value: &[u8; 20]) -> bool {
    let mut index = 0_usize;
    while index < value.len() {
        if value[index] != 0 {
            return true;
        }
        index += 1;
    }
    false
}

const fn nonzero32(value: &[u8; 32]) -> bool {
    let mut index = 0_usize;
    while index < value.len() {
        if value[index] != 0 {
            return true;
        }
        index += 1;
    }
    false
}

const fn equal32(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut index = 0_usize;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization() -> SearchV25ProductionAuthorizationV1 {
        SearchV25ProductionAuthorizationV1 {
            source_commit: [0x01; 20],
            source_tree: [0x02; 20],
            regex_codegen_architecture_review_sha256: [0x03; 32],
            regex_codegen_uses_llvm: false,
            development_pass_sha256: [0x04; 32],
            campaign_contract_sha256: [0x05; 32],
            correctness_binding_sha256: [0x06; 32],
            two_host_correctness_gate_sha256: [0x07; 32],
            heldout_analysis_sha256: [0x08; 32],
            production_review_sha256: [0x09; 32],
            authorization_sha256: [0x0a; 32],
            macos_build_receipt_sha256: [0x0b; 32],
            linux_build_receipt_sha256: [0x0c; 32],
            selector: 17,
            minimum_literal_bytes: 6,
            maximum_literal_bytes: 32,
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
        let mut family = SourceQualifiedStaticSearchSpanFamilyV1::test_only(17, 6, 32);
        family.backend_version = SEARCH_BACKEND_ASIMD_TAG38_V1;
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
    fn authority_refuses_llvm_zero_provenance_and_family_drift() {
        let canonical = authorization();
        let family = linux_family();

        let mut llvm = canonical;
        llvm.regex_codegen_uses_llvm = true;
        assert!(!authorization_matches(&llvm, &family));

        let mut zero_architecture_review = canonical;
        zero_architecture_review.regex_codegen_architecture_review_sha256 = [0; 32];
        assert!(!authorization_matches(&zero_architecture_review, &family));

        let mut zero_target_receipt = canonical;
        zero_target_receipt.linux_build_receipt_sha256 = [0; 32];
        assert!(!authorization_matches(&zero_target_receipt, &family));

        let mut wrong_selector = family;
        wrong_selector.selector = canonical.selector.checked_add(1).unwrap();
        assert!(!authorization_matches(&canonical, &wrong_selector));

        let mut wrong_envelope = family;
        wrong_envelope.minimum_window_bytes =
            canonical.minimum_window_bytes.checked_add(1).unwrap();
        assert!(!authorization_matches(&canonical, &wrong_envelope));

        let mut wrong_plan = family;
        wrong_plan.plan_identity.0[0] ^= 0xff;
        assert!(!authorization_matches(&canonical, &wrong_plan));

        let mut wrong_manifest = family;
        wrong_manifest.manifest_identity.0[0] ^= 0xff;
        assert!(!authorization_matches(&canonical, &wrong_manifest));
    }
}
