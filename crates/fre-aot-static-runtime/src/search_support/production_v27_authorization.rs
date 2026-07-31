use super::SourceQualifiedStaticSearchSpanFamilyV1;
use fre_aot_search_contract::{
    SEARCH_BACKEND_ASIMD_TAG40_V1, SEARCH_PLATFORM_LINUX_V1, SEARCH_PLATFORM_MACOS_V1,
    SEARCH_V27_PRODUCTION_MAX_LITERAL_BYTES_V1, SEARCH_V27_PRODUCTION_MIN_LITERAL_BYTES_V1,
};

/// Source-sealed authority for the evidence-qualified tag40 production class.
///
/// This atom binds the non-LLVM architecture, exact cross-host raw results,
/// topology-authenticated V25-fast graph decision, target manifests, and the
/// hybrid execution envelope. Generated objects, linked glue, Cargo features,
/// and runtime input cannot construct or widen it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SearchV27ProductionAuthorizationV1 {
    source_commit: [u8; 20],
    source_tree: [u8; 20],
    regex_codegen_uses_llvm: bool,
    v25_fast_graph_only: bool,
    corpus_sha256: [u8; 32],
    apple_direct_result_sha256: [u8; 32],
    c9g_direct_result_sha256: [u8; 32],
    apple_hybrid_result_sha256: [u8; 32],
    c9g_hybrid_result_sha256: [u8; 32],
    analyzer_build_sha256: [u8; 32],
    analyzer_runner_sha256: [u8; 32],
    production_review_sha256: [u8; 32],
    authorization_sha256: [u8; 32],
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

/// Reviewed V27 production authorization.
///
/// Runtime publication additionally requires the default-off linked feature,
/// a target-conditional family row with this exact tuple, and successful
/// per-artifact mapped-image, semantic, and selected-graph reconstruction.
pub(super) const SEARCH_V27_PRODUCTION_AUTHORIZATION_V1: Option<
    SearchV27ProductionAuthorizationV1,
> = Some(SearchV27ProductionAuthorizationV1 {
    source_commit: [
        0x20, 0xba, 0x79, 0xa9, 0xfd, 0xa2, 0x4e, 0x06, 0x47, 0x45, 0x91, 0x5d, 0x4a, 0x2f, 0x9d,
        0xa5, 0x77, 0x7d, 0x2c, 0x91,
    ],
    source_tree: [
        0xd1, 0x50, 0x67, 0xea, 0xa2, 0x5f, 0xc0, 0x33, 0xdd, 0x4c, 0xf3, 0x3d, 0xb2, 0xe4, 0x5e,
        0xa4, 0x7c, 0x46, 0x59, 0x38,
    ],
    regex_codegen_uses_llvm: false,
    v25_fast_graph_only: true,
    corpus_sha256: [
        0x63, 0xe5, 0x81, 0x91, 0x5a, 0x65, 0x49, 0x28, 0xe6, 0x16, 0xad, 0x20, 0x9d, 0x70, 0x50,
        0x0a, 0x85, 0xb3, 0x77, 0x14, 0xc1, 0xf9, 0x6d, 0x39, 0x03, 0x2f, 0xe9, 0xef, 0x87, 0x52,
        0x1f, 0x20,
    ],
    apple_direct_result_sha256: [
        0x82, 0x3b, 0x2c, 0x41, 0x88, 0xe3, 0x4e, 0x37, 0x77, 0x9c, 0xaa, 0x1b, 0x96, 0xea, 0xb5,
        0xdc, 0xff, 0xb7, 0xf8, 0x8f, 0xbf, 0x9a, 0x55, 0x0c, 0xf1, 0xf4, 0xdf, 0xab, 0xa9, 0xa4,
        0x3d, 0x30,
    ],
    c9g_direct_result_sha256: [
        0xc1, 0x5e, 0x27, 0x43, 0xf3, 0x9f, 0x87, 0x10, 0xa3, 0xd7, 0x6c, 0xbb, 0x98, 0x7e, 0x37,
        0x9f, 0x04, 0x93, 0xaf, 0x1b, 0x71, 0x72, 0x3d, 0x76, 0x04, 0xa3, 0x20, 0x4f, 0x49, 0xf4,
        0xb2, 0xbb,
    ],
    apple_hybrid_result_sha256: [
        0x30, 0xf5, 0x3b, 0x01, 0x89, 0x3c, 0x8d, 0x93, 0x05, 0x28, 0x8c, 0x2f, 0xa6, 0x6f, 0x45,
        0xd1, 0xd5, 0x1a, 0x4d, 0x15, 0x8a, 0xe1, 0xdb, 0x71, 0xb3, 0x94, 0xc5, 0x3b, 0xc1, 0x3a,
        0x9c, 0xad,
    ],
    c9g_hybrid_result_sha256: [
        0xf1, 0x25, 0x76, 0x98, 0xca, 0x78, 0x43, 0xf2, 0xb0, 0x56, 0x39, 0xe3, 0x0a, 0x0f, 0x59,
        0xcb, 0x0a, 0x1b, 0xc6, 0x07, 0x1f, 0x1f, 0xfa, 0x18, 0x5c, 0x7c, 0x0b, 0x7f, 0x2b, 0xe5,
        0x09, 0x15,
    ],
    analyzer_build_sha256: [
        0x98, 0x6e, 0xfb, 0xbf, 0x34, 0x34, 0xa2, 0x3a, 0x2b, 0xed, 0x55, 0xcb, 0xd3, 0xc1, 0xcf,
        0x9c, 0xe5, 0xdf, 0xeb, 0x5e, 0xe2, 0xac, 0x3e, 0x16, 0xcb, 0x52, 0x77, 0x1d, 0x06, 0x31,
        0x05, 0xae,
    ],
    analyzer_runner_sha256: [
        0x6b, 0x05, 0xae, 0xd1, 0x4b, 0xfe, 0x2a, 0x2e, 0x43, 0xd7, 0x6e, 0x41, 0x60, 0x12, 0xbb,
        0x01, 0xcd, 0xe9, 0x63, 0xec, 0x25, 0x5d, 0x6d, 0xcc, 0xae, 0x7a, 0x11, 0x05, 0xd8, 0xdf,
        0xc0, 0xe7,
    ],
    production_review_sha256: [
        0xf5, 0x49, 0x51, 0x5a, 0x13, 0x05, 0x10, 0x2c, 0xcd, 0x75, 0xac, 0x78, 0x73, 0x59, 0xb5,
        0x43, 0xfc, 0x62, 0x47, 0x3e, 0xf7, 0x69, 0xf3, 0x57, 0xa5, 0xa7, 0x68, 0xa4, 0x80, 0x94,
        0x3a, 0x8b,
    ],
    authorization_sha256: [
        0x79, 0x84, 0x2e, 0x3d, 0x6f, 0x7a, 0xbf, 0x30, 0x04, 0x55, 0x9a, 0x87, 0x7e, 0x3f, 0xe2,
        0x29, 0xa4, 0x08, 0xf8, 0x02, 0xd8, 0x71, 0x76, 0x41, 0x3d, 0x05, 0x3e, 0xa7, 0x49, 0x38,
        0x3e, 0xdf,
    ],
    selector: 41,
    minimum_literal_bytes: SEARCH_V27_PRODUCTION_MIN_LITERAL_BYTES_V1,
    maximum_literal_bytes: SEARCH_V27_PRODUCTION_MAX_LITERAL_BYTES_V1,
    minimum_window_bytes: 65_536,
    portable_prefix_candidate_starts: 256,
    macos_manifest_identity: [
        0x8c, 0xdd, 0xb0, 0x3c, 0x39, 0xcf, 0x95, 0xd7, 0x8d, 0x87, 0xe4, 0x30, 0x78, 0x24, 0x7d,
        0xdf, 0x5c, 0x03, 0x48, 0xc4, 0x53, 0x61, 0xa1, 0xfa, 0xbb, 0x36, 0x91, 0x3a, 0xce, 0x10,
        0x6f, 0xe1,
    ],
    linux_manifest_identity: [
        0x0f, 0x22, 0x0e, 0x3f, 0x4b, 0x3b, 0x8e, 0x65, 0x9c, 0x80, 0x03, 0x49, 0x01, 0x5f, 0x69,
        0x95, 0xa4, 0x60, 0x52, 0xe7, 0x4f, 0x8e, 0xdc, 0xc8, 0x44, 0xda, 0x65, 0x61, 0x3f, 0x42,
        0x6f, 0x06,
    ],
    plan_identity: [
        0xcc, 0x59, 0x59, 0xf0, 0xb2, 0x00, 0xcf, 0xad, 0xf5, 0xd4, 0xa5, 0x56, 0x1f, 0x16, 0x76,
        0xcd, 0x3b, 0x09, 0xcf, 0xdb, 0xe1, 0x58, 0xad, 0xf5, 0x53, 0x86, 0x02, 0x89, 0x7f, 0x42,
        0xe1, 0xf0,
    ],
    analyzer_identity: [
        0x2f, 0xde, 0xb6, 0xc5, 0xac, 0x74, 0x30, 0xcd, 0xad, 0xc6, 0xce, 0xce, 0xeb, 0x2f, 0x9b,
        0xd4, 0x01, 0x08, 0xf9, 0x76, 0xe6, 0xb1, 0x2f, 0xd2, 0x25, 0x16, 0x7c, 0x1a, 0x25, 0xac,
        0x27, 0x24,
    ],
    evidence_identity: [
        0x6a, 0x17, 0x6e, 0x47, 0x3a, 0xff, 0x32, 0x4b, 0x3b, 0x4f, 0x69, 0x5a, 0x07, 0x8f, 0xf9,
        0x48, 0x47, 0x44, 0x99, 0x3a, 0x18, 0xf2, 0x2f, 0x29, 0xf3, 0x8a, 0xd0, 0xcf, 0xfa, 0x0f,
        0x59, 0x82,
    ],
});

const _: () = assert!(SEARCH_V27_PRODUCTION_AUTHORIZATION_V1.is_some());

/// Whether one target-conditional production row is exactly covered by the
/// separately sealed V27 authority chain.
pub(super) const fn authorizes(family: &SourceQualifiedStaticSearchSpanFamilyV1) -> bool {
    let Some(authorization) = SEARCH_V27_PRODUCTION_AUTHORIZATION_V1 else {
        return false;
    };
    authorization_matches(&authorization, family)
}

const fn authorization_matches(
    authorization: &SearchV27ProductionAuthorizationV1,
    family: &SourceQualifiedStaticSearchSpanFamilyV1,
) -> bool {
    if !all_authority_identities_are_nonzero(authorization)
        || authorization.regex_codegen_uses_llvm
        || !authorization.v25_fast_graph_only
        || family.backend_version != SEARCH_BACKEND_ASIMD_TAG40_V1
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
    authorization: &SearchV27ProductionAuthorizationV1,
) -> bool {
    nonzero20(&authorization.source_commit)
        && nonzero20(&authorization.source_tree)
        && nonzero32(&authorization.corpus_sha256)
        && nonzero32(&authorization.apple_direct_result_sha256)
        && nonzero32(&authorization.c9g_direct_result_sha256)
        && nonzero32(&authorization.apple_hybrid_result_sha256)
        && nonzero32(&authorization.c9g_hybrid_result_sha256)
        && nonzero32(&authorization.analyzer_build_sha256)
        && nonzero32(&authorization.analyzer_runner_sha256)
        && nonzero32(&authorization.production_review_sha256)
        && nonzero32(&authorization.authorization_sha256)
        && nonzero32(&authorization.macos_manifest_identity)
        && nonzero32(&authorization.linux_manifest_identity)
        && nonzero32(&authorization.plan_identity)
        && nonzero32(&authorization.analyzer_identity)
        && nonzero32(&authorization.evidence_identity)
        && authorization.selector != 0
        && authorization.minimum_literal_bytes == SEARCH_V27_PRODUCTION_MIN_LITERAL_BYTES_V1
        && authorization.maximum_literal_bytes == SEARCH_V27_PRODUCTION_MAX_LITERAL_BYTES_V1
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
    use fre_aot_search_contract::{
        SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1, SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
    };

    fn linux_family() -> SourceQualifiedStaticSearchSpanFamilyV1 {
        let authorization = SEARCH_V27_PRODUCTION_AUTHORIZATION_V1.unwrap();
        let mut family = SourceQualifiedStaticSearchSpanFamilyV1::test_only(
            authorization.selector,
            authorization.minimum_literal_bytes,
            authorization.maximum_literal_bytes,
        );
        family.backend_version = SEARCH_BACKEND_ASIMD_TAG40_V1;
        family.minimum_window_bytes = authorization.minimum_window_bytes;
        family.portable_prefix_candidate_starts = authorization.portable_prefix_candidate_starts;
        family.manifest_identity.0 = authorization.linux_manifest_identity;
        family.plan_identity.0 = authorization.plan_identity;
        family.analyzer_identity.0 = authorization.analyzer_identity;
        family.evidence_identity.0 = authorization.evidence_identity;
        family
    }

    #[test]
    fn complete_non_llvm_authority_matches_only_its_two_target_rows() {
        let authorization = SEARCH_V27_PRODUCTION_AUTHORIZATION_V1.unwrap();
        let linux = linux_family();
        assert!(authorization_matches(&authorization, &linux));

        let mut macos = linux;
        macos.platform = SEARCH_PLATFORM_MACOS_V1;
        macos.exported_symbol_n_type = SEARCH_EXPORTED_SYMBOL_N_TYPE_V1;
        macos.manifest_identity.0 = authorization.macos_manifest_identity;
        assert!(authorization_matches(&authorization, &macos));
    }

    #[test]
    fn authority_refuses_backend_envelope_identity_and_platform_drift() {
        let authorization = SEARCH_V27_PRODUCTION_AUTHORIZATION_V1.unwrap();
        let family = linux_family();
        assert_eq!(
            family.exported_symbol_n_type,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1
        );

        let mut wrong_backend = family;
        wrong_backend.backend_version -= 1;
        assert!(!authorization_matches(&authorization, &wrong_backend));

        let mut wrong_width = family;
        wrong_width.minimum_literal_bytes -= 1;
        assert!(!authorization_matches(&authorization, &wrong_width));

        let mut wrong_plan = family;
        wrong_plan.plan_identity.0[0] ^= 1;
        assert!(!authorization_matches(&authorization, &wrong_plan));

        let mut unsupported = family;
        unsupported.platform = 9;
        assert!(!authorization_matches(&authorization, &unsupported));
    }
}
