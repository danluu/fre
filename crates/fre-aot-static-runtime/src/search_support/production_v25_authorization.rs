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
/// builds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the complete source authority shape is retained while the V25 production atom is deliberately absent"
)]
pub(super) struct SearchV25ProductionAuthorizationV1 {
    source_commit: [u8; 20],
    source_tree: [u8; 20],
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
pub(super) const SEARCH_V25_PRODUCTION_AUTHORIZATION_V1:
    Option<SearchV25ProductionAuthorizationV1> = None;

const _: () = assert!(SEARCH_V25_PRODUCTION_AUTHORIZATION_V1.is_none());

/// Whether one target-conditional production row is exactly covered by the
/// separately sealed V25 authority chain.
pub(super) const fn authorizes(family: &SourceQualifiedStaticSearchSpanFamilyV1) -> bool {
    let Some(authorization) = SEARCH_V25_PRODUCTION_AUTHORIZATION_V1 else {
        return false;
    };
    if !all_authority_identities_are_nonzero(&authorization)
        || family.backend_version != SEARCH_BACKEND_ASIMD_TAG38_V1
        || family.selector != authorization.selector
        || family.minimum_literal_bytes != authorization.minimum_literal_bytes
        || family.maximum_literal_bytes != authorization.maximum_literal_bytes
        || family.minimum_window_bytes != authorization.minimum_window_bytes
        || family.portable_prefix_candidate_starts
            != authorization.portable_prefix_candidate_starts
        || !equal32(family.plan_identity.as_bytes(), &authorization.plan_identity)
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
        SEARCH_PLATFORM_MACOS_V1 => {
            equal32(
                family.manifest_identity.as_bytes(),
                &authorization.macos_manifest_identity,
            )
        }
        SEARCH_PLATFORM_LINUX_V1 => {
            equal32(
                family.manifest_identity.as_bytes(),
                &authorization.linux_manifest_identity,
            )
        }
        _ => false,
    }
}

const fn all_authority_identities_are_nonzero(
    authorization: &SearchV25ProductionAuthorizationV1,
) -> bool {
    nonzero20(&authorization.source_commit)
        && nonzero20(&authorization.source_tree)
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
