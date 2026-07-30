use fre_aot_search_contract::{
    AOT_SEARCH_COMPILER_VERSION_V1, ClaimedStaticSearchSpanExpectationV1,
    MAX_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1, MIN_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1,
    SEARCH_ARCHITECTURE_AARCH64_V1, SEARCH_BACKEND_ASIMD_TAG22_V1, SEARCH_BACKEND_ASIMD_TAG23_V1,
    SEARCH_BACKEND_ASIMD_TAG25_V1, SEARCH_BACKEND_ASIMD_TAG26_V1, SEARCH_BACKEND_ASIMD_TAG28_V1,
    SEARCH_BACKEND_ASIMD_TAG29_V1, SEARCH_BACKEND_ASIMD_TAG30_V1,
    SEARCH_BACKEND_ASIMD_TAG37_MAX_LITERAL_BYTES_V1,
    SEARCH_BACKEND_ASIMD_TAG37_MIN_LITERAL_BYTES_V1, SEARCH_BACKEND_ASIMD_TAG37_V1,
    SEARCH_BACKEND_ASIMD_TAG38_MAX_LITERAL_BYTES_V1,
    SEARCH_BACKEND_ASIMD_TAG38_MIN_LITERAL_BYTES_V1, SEARCH_BACKEND_ASIMD_TAG38_V1,
    SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1, SEARCH_BACKEND_VERSION_V1, SEARCH_CALL_ABI_SCHEMA_V1,
    SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1, SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
    SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1, SEARCH_METADATA_VERSION_V1, SEARCH_PLATFORM_LINUX_V1,
    SEARCH_PLATFORM_MACOS_V1, SEARCH_POINTER_WIDTH_V1, SEARCH_REQUIRED_ASIMD_FEATURES_V1,
    SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1, SEARCH_SPAN_OUTPUT_KIND_V1, SEARCH_STATUS_BITS_V1,
    SEARCH_TARGET_ABI_AAPCS64_V1,
};

use crate::{StaticSearchSpanContractFieldV1, StaticSearchSpanVerifyErrorV1};

pub(crate) const HARD_MAX_STATIC_SEARCH_SPAN_QUALIFICATION_ROWS_V1: usize = 256;
pub(crate) const HARD_MAX_STATIC_SEARCH_SPAN_PRODUCTION_FAMILIES_V1: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceQualifiedStaticSearchSpanAuthorityV1 {
    Exact(&'static SourceQualifiedStaticSearchSpanRowV1),
    Family(&'static SourceQualifiedStaticSearchSpanFamilyV1),
}

mod production_rows;
use production_rows::PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1;
mod production_families;
use production_families::PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1;

#[cfg(feature = "search-span-qualification-private-v1")]
mod private_rows;
#[cfg(feature = "search-span-qualification-private-v1")]
use private_rows::{
    PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_FAMILIES_V1,
    PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1,
};

macro_rules! source_qualified_identity_v1 {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        struct $name([u8; 32]);

        impl $name {
            #[cfg(test)]
            const fn test_only(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

source_qualified_identity_v1!(SourceQualifiedManifestIdentityV1);
source_qualified_identity_v1!(SourceQualifiedSemanticBindingIdentityV1);
source_qualified_identity_v1!(SourceQualifiedLiteralIdentityV1);
source_qualified_identity_v1!(SourceQualifiedKirIdentityV1);
source_qualified_identity_v1!(SourceQualifiedArtifactIdentityV1);
source_qualified_identity_v1!(SourceQualifiedBindingIdentityV1);
source_qualified_identity_v1!(SourceQualifiedCompileIdentityV1);
source_qualified_identity_v1!(SourceQualifiedObjectIdentityV1);
source_qualified_identity_v1!(SourceQualifiedReceiptIdentityV1);
source_qualified_identity_v1!(SourceQualifiedExpectationIdentityV1);
source_qualified_identity_v1!(SourceQualifiedPayloadIdentityV1);
source_qualified_identity_v1!(SourceQualifiedPlanIdentityV1);
source_qualified_identity_v1!(SourceQualifiedAnalyzerIdentityV1);
source_qualified_identity_v1!(SourceQualifiedEvidenceIdentityV1);

/// Artifact-independent production authority for one compiler/backend family.
///
/// Unlike a legacy exact row, this tuple intentionally contains no literal,
/// KIR, artifact, object, receipt, or payload identity. Those values remain
/// mandatory and are authenticated from each linked image, then the runtime
/// independently rebuilds the exact KIR and native payload from the mapped
/// literal before a callable can exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceQualifiedStaticSearchSpanFamilyV1 {
    selector: u16,
    compiler_version: u16,
    metadata_version: u16,
    backend_version: u16,
    call_abi_schema: u16,
    exported_symbol_schema: u16,
    output_kind: u8,
    architecture: u8,
    little_endian: bool,
    pointer_width: u8,
    target_abi: u8,
    platform: u8,
    status_bits: u8,
    exported_symbol_n_type: u8,
    required_features: u64,
    minimum_literal_bytes: u32,
    maximum_literal_bytes: u32,
    minimum_window_bytes: u32,
    portable_prefix_candidate_starts: u32,
    manifest_identity: SourceQualifiedManifestIdentityV1,
    plan_identity: SourceQualifiedPlanIdentityV1,
    analyzer_identity: SourceQualifiedAnalyzerIdentityV1,
    evidence_identity: SourceQualifiedEvidenceIdentityV1,
}

impl SourceQualifiedStaticSearchSpanFamilyV1 {
    #[allow(
        clippy::too_many_arguments,
        reason = "the production family is the complete artifact-independent Search-v1 wire tuple"
    )]
    const fn production(
        selector: u16,
        compiler_version: u16,
        metadata_version: u16,
        backend_version: u16,
        call_abi_schema: u16,
        exported_symbol_schema: u16,
        output_kind: u8,
        architecture: u8,
        little_endian: bool,
        pointer_width: u8,
        target_abi: u8,
        platform: u8,
        status_bits: u8,
        exported_symbol_n_type: u8,
        required_features: u64,
        minimum_literal_bytes: u32,
        maximum_literal_bytes: u32,
        minimum_window_bytes: u32,
        portable_prefix_candidate_starts: u32,
        manifest_identity: [u8; 32],
        plan_identity: [u8; 32],
        analyzer_identity: [u8; 32],
        evidence_identity: [u8; 32],
    ) -> Self {
        Self {
            selector,
            compiler_version,
            metadata_version,
            backend_version,
            call_abi_schema,
            exported_symbol_schema,
            output_kind,
            architecture,
            little_endian,
            pointer_width,
            target_abi,
            platform,
            status_bits,
            exported_symbol_n_type,
            required_features,
            minimum_literal_bytes,
            maximum_literal_bytes,
            minimum_window_bytes,
            portable_prefix_candidate_starts,
            manifest_identity: SourceQualifiedManifestIdentityV1(manifest_identity),
            plan_identity: SourceQualifiedPlanIdentityV1(plan_identity),
            analyzer_identity: SourceQualifiedAnalyzerIdentityV1(analyzer_identity),
            evidence_identity: SourceQualifiedEvidenceIdentityV1(evidence_identity),
        }
    }

    /// Construct one compiler-family row in the feature-gated private source
    /// module.
    ///
    /// The qualification family remains artifact independent. Every concrete
    /// linked object must still pass expectation, mapped-image, live-literal
    /// KIR, and regenerated-payload verification before adoption.
    #[cfg(feature = "search-span-qualification-private-v1")]
    #[allow(
        dead_code,
        clippy::too_many_arguments,
        reason = "the private atom retains this solely for canonical reviewed family construction"
    )]
    const fn private_qualification(
        selector: u16,
        compiler_version: u16,
        metadata_version: u16,
        backend_version: u16,
        call_abi_schema: u16,
        exported_symbol_schema: u16,
        output_kind: u8,
        architecture: u8,
        little_endian: bool,
        pointer_width: u8,
        target_abi: u8,
        platform: u8,
        status_bits: u8,
        exported_symbol_n_type: u8,
        required_features: u64,
        minimum_literal_bytes: u32,
        maximum_literal_bytes: u32,
        minimum_window_bytes: u32,
        portable_prefix_candidate_starts: u32,
        manifest_identity: [u8; 32],
        plan_identity: [u8; 32],
        analyzer_identity: [u8; 32],
        evidence_identity: [u8; 32],
    ) -> Self {
        Self::production(
            selector,
            compiler_version,
            metadata_version,
            backend_version,
            call_abi_schema,
            exported_symbol_schema,
            output_kind,
            architecture,
            little_endian,
            pointer_width,
            target_abi,
            platform,
            status_bits,
            exported_symbol_n_type,
            required_features,
            minimum_literal_bytes,
            maximum_literal_bytes,
            minimum_window_bytes,
            portable_prefix_candidate_starts,
            manifest_identity,
            plan_identity,
            analyzer_identity,
            evidence_identity,
        )
    }

    #[cfg(test)]
    const fn test_only(
        selector: u16,
        minimum_literal_bytes: u32,
        maximum_literal_bytes: u32,
    ) -> Self {
        Self::production(
            selector,
            1,
            1,
            8,
            1,
            1,
            3,
            1,
            true,
            64,
            1,
            2,
            64,
            0x12,
            1,
            minimum_literal_bytes,
            maximum_literal_bytes,
            4_093,
            256,
            [0x5a; 32],
            [0x6b; 32],
            [0x7c; 32],
            [0x8d; 32],
        )
    }

    #[cfg(test)]
    pub(crate) fn from_test_claim(
        selector: u16,
        claim: ClaimedStaticSearchSpanExpectationV1,
        minimum_literal_bytes: u32,
        maximum_literal_bytes: u32,
    ) -> Self {
        Self::production(
            selector,
            claim.compiler_version(),
            claim.metadata_version(),
            claim.backend_version(),
            claim.call_abi_schema(),
            claim.exported_symbol_schema(),
            claim.output_kind(),
            claim.architecture(),
            claim.little_endian(),
            claim.pointer_width(),
            claim.target_abi(),
            claim.platform(),
            claim.status_bits(),
            claim.exported_symbol_n_type(),
            claim.required_features(),
            minimum_literal_bytes,
            maximum_literal_bytes,
            4_093,
            256,
            *claim.manifest_identity(),
            [0x6b; 32],
            [0x7c; 32],
            [0x8d; 32],
        )
    }

    pub(crate) const fn selector(&self) -> u16 {
        self.selector
    }

    pub(crate) const fn manifest_identity(&self) -> &[u8; 32] {
        self.manifest_identity.as_bytes()
    }

    pub(crate) const fn minimum_window_bytes(&self) -> u32 {
        self.minimum_window_bytes
    }

    pub(crate) const fn portable_prefix_candidate_starts(&self) -> u32 {
        self.portable_prefix_candidate_starts
    }

    pub(crate) const fn plan_identity(&self) -> &[u8; 32] {
        self.plan_identity.as_bytes()
    }

    pub(crate) const fn analyzer_identity(&self) -> &[u8; 32] {
        self.analyzer_identity.as_bytes()
    }

    pub(crate) const fn evidence_identity(&self) -> &[u8; 32] {
        self.evidence_identity.as_bytes()
    }

    pub(crate) fn authenticates_claim(
        &self,
        claim: ClaimedStaticSearchSpanExpectationV1,
    ) -> Result<(), StaticSearchSpanVerifyErrorV1> {
        let header_matches = claim.compiler_version() == self.compiler_version
            && claim.metadata_version() == self.metadata_version
            && claim.backend_version() == self.backend_version
            && claim.call_abi_schema() == self.call_abi_schema
            && claim.exported_symbol_schema() == self.exported_symbol_schema
            && claim.output_kind() == self.output_kind
            && !claim.anchor_start()
            && !claim.anchor_end()
            && claim.architecture() == self.architecture
            && claim.little_endian() == self.little_endian
            && claim.pointer_width() == self.pointer_width
            && claim.target_abi() == self.target_abi
            && claim.platform() == self.platform
            && claim.status_bits() == self.status_bits
            && claim.exported_symbol_n_type() == self.exported_symbol_n_type
            && claim.required_features() == self.required_features
            && (self.minimum_literal_bytes..=self.maximum_literal_bytes)
                .contains(&claim.live_literal_bytes());
        if !header_matches {
            return Err(StaticSearchSpanVerifyErrorV1::ContractMismatch {
                field: StaticSearchSpanContractFieldV1::ProductionFamily,
            });
        }
        if claim.manifest_identity() != self.manifest_identity() {
            return Err(StaticSearchSpanVerifyErrorV1::ContractMismatch {
                field: StaticSearchSpanContractFieldV1::ManifestIdentity,
            });
        }
        Ok(())
    }
}

/// One exact, source-reviewed final-image Search-v1 Span decision.
///
/// Construction is private. Metadata, an expectation, build-script output,
/// environment variables, or a Cargo feature cannot manufacture this type.
/// Rows can enter authority only as literal field values in one complete,
/// source-reviewed private or production child module after the linked image
/// has been independently sealed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the repeated identity suffix keeps eleven security domains explicit"
)]
pub(crate) struct SourceQualifiedStaticSearchSpanRowV1 {
    selector: u16,
    live_literal_bytes: u32,
    manifest_identity: SourceQualifiedManifestIdentityV1,
    semantic_binding_identity: SourceQualifiedSemanticBindingIdentityV1,
    literal_identity: SourceQualifiedLiteralIdentityV1,
    kir_identity: SourceQualifiedKirIdentityV1,
    artifact_identity: SourceQualifiedArtifactIdentityV1,
    binding_identity: SourceQualifiedBindingIdentityV1,
    compile_identity: SourceQualifiedCompileIdentityV1,
    object_identity: SourceQualifiedObjectIdentityV1,
    receipt_identity: SourceQualifiedReceiptIdentityV1,
    expectation_identity: SourceQualifiedExpectationIdentityV1,
    payload_identity: SourceQualifiedPayloadIdentityV1,
}

impl SourceQualifiedStaticSearchSpanRowV1 {
    /// Construct one literal row in the feature-gated private source module.
    ///
    /// This constructor is deliberately private to `search_support` and is
    /// absent unless the private qualification feature is enabled. Descendant
    /// module `private_rows` can use it; sibling runtime/routing modules,
    /// downstream crates, generated code, and ordinary production builds
    /// cannot.
    #[cfg(feature = "search-span-qualification-private-v1")]
    #[allow(
        dead_code,
        clippy::too_many_arguments,
        reason = "the private atom retains this solely for canonical reviewed row construction"
    )]
    const fn private_qualification(
        selector: u16,
        live_literal_bytes: u32,
        manifest_identity: [u8; 32],
        semantic_binding_identity: [u8; 32],
        literal_identity: [u8; 32],
        kir_identity: [u8; 32],
        artifact_identity: [u8; 32],
        binding_identity: [u8; 32],
        compile_identity: [u8; 32],
        object_identity: [u8; 32],
        receipt_identity: [u8; 32],
        expectation_identity: [u8; 32],
        payload_identity: [u8; 32],
    ) -> Self {
        Self {
            selector,
            live_literal_bytes,
            manifest_identity: SourceQualifiedManifestIdentityV1(manifest_identity),
            semantic_binding_identity: SourceQualifiedSemanticBindingIdentityV1(
                semantic_binding_identity,
            ),
            literal_identity: SourceQualifiedLiteralIdentityV1(literal_identity),
            kir_identity: SourceQualifiedKirIdentityV1(kir_identity),
            artifact_identity: SourceQualifiedArtifactIdentityV1(artifact_identity),
            binding_identity: SourceQualifiedBindingIdentityV1(binding_identity),
            compile_identity: SourceQualifiedCompileIdentityV1(compile_identity),
            object_identity: SourceQualifiedObjectIdentityV1(object_identity),
            receipt_identity: SourceQualifiedReceiptIdentityV1(receipt_identity),
            expectation_identity: SourceQualifiedExpectationIdentityV1(expectation_identity),
            payload_identity: SourceQualifiedPayloadIdentityV1(payload_identity),
        }
    }

    #[cfg(test)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the test constructor exposes every independently pinned authority field"
    )]
    pub(crate) const fn test_only(
        selector: u16,
        live_literal_bytes: u32,
        manifest_identity: [u8; 32],
        semantic_binding_identity: [u8; 32],
        literal_identity: [u8; 32],
        kir_identity: [u8; 32],
        artifact_identity: [u8; 32],
        binding_identity: [u8; 32],
        compile_identity: [u8; 32],
        object_identity: [u8; 32],
        receipt_identity: [u8; 32],
        expectation_identity: [u8; 32],
        payload_identity: [u8; 32],
    ) -> Self {
        Self {
            selector,
            live_literal_bytes,
            manifest_identity: SourceQualifiedManifestIdentityV1::test_only(manifest_identity),
            semantic_binding_identity: SourceQualifiedSemanticBindingIdentityV1::test_only(
                semantic_binding_identity,
            ),
            literal_identity: SourceQualifiedLiteralIdentityV1::test_only(literal_identity),
            kir_identity: SourceQualifiedKirIdentityV1::test_only(kir_identity),
            artifact_identity: SourceQualifiedArtifactIdentityV1::test_only(artifact_identity),
            binding_identity: SourceQualifiedBindingIdentityV1::test_only(binding_identity),
            compile_identity: SourceQualifiedCompileIdentityV1::test_only(compile_identity),
            object_identity: SourceQualifiedObjectIdentityV1::test_only(object_identity),
            receipt_identity: SourceQualifiedReceiptIdentityV1::test_only(receipt_identity),
            expectation_identity: SourceQualifiedExpectationIdentityV1::test_only(
                expectation_identity,
            ),
            payload_identity: SourceQualifiedPayloadIdentityV1::test_only(payload_identity),
        }
    }

    pub(crate) const fn selector(&self) -> u16 {
        self.selector
    }

    pub(crate) const fn live_literal_bytes(&self) -> u32 {
        self.live_literal_bytes
    }

    pub(crate) const fn manifest_identity(&self) -> &[u8; 32] {
        self.manifest_identity.as_bytes()
    }

    pub(crate) const fn semantic_binding_identity(&self) -> &[u8; 32] {
        self.semantic_binding_identity.as_bytes()
    }

    pub(crate) const fn literal_identity(&self) -> &[u8; 32] {
        self.literal_identity.as_bytes()
    }

    pub(crate) const fn kir_identity(&self) -> &[u8; 32] {
        self.kir_identity.as_bytes()
    }

    pub(crate) const fn artifact_identity(&self) -> &[u8; 32] {
        self.artifact_identity.as_bytes()
    }

    pub(crate) const fn binding_identity(&self) -> &[u8; 32] {
        self.binding_identity.as_bytes()
    }

    pub(crate) const fn compile_identity(&self) -> &[u8; 32] {
        self.compile_identity.as_bytes()
    }

    pub(crate) const fn object_identity(&self) -> &[u8; 32] {
        self.object_identity.as_bytes()
    }

    pub(crate) const fn receipt_identity(&self) -> &[u8; 32] {
        self.receipt_identity.as_bytes()
    }

    pub(crate) const fn expectation_identity(&self) -> &[u8; 32] {
        self.expectation_identity.as_bytes()
    }

    pub(crate) const fn payload_identity(&self) -> &[u8; 32] {
        self.payload_identity.as_bytes()
    }
}

const fn qualification_rows_are_canonical(rows: &[SourceQualifiedStaticSearchSpanRowV1]) -> bool {
    if rows.len() > HARD_MAX_STATIC_SEARCH_SPAN_QUALIFICATION_ROWS_V1 {
        return false;
    }
    let mut index = 1_usize;
    while index < rows.len() {
        let Some(previous) = index.checked_sub(1) else {
            return false;
        };
        if rows[previous].selector >= rows[index].selector {
            return false;
        }
        let Some(next) = index.checked_add(1) else {
            return false;
        };
        index = next;
    }
    true
}

const fn search_span_families_are_canonical(
    rows: &[SourceQualifiedStaticSearchSpanFamilyV1],
) -> bool {
    if rows.len() > HARD_MAX_STATIC_SEARCH_SPAN_PRODUCTION_FAMILIES_V1 {
        return false;
    }
    let mut index = 0_usize;
    while index < rows.len() {
        let row = &rows[index];
        if !production_family_profile_is_canonical(row)
            || identity_is_zero(&row.manifest_identity.0)
            || identity_is_zero(&row.plan_identity.0)
            || identity_is_zero(&row.analyzer_identity.0)
            || identity_is_zero(&row.evidence_identity.0)
        {
            return false;
        }
        if index > 0 && rows[index - 1].selector >= row.selector {
            return false;
        }
        let mut earlier = 0_usize;
        while earlier < index {
            if same_production_family_profile(&rows[earlier], row)
                && ranges_overlap(
                    rows[earlier].minimum_literal_bytes,
                    rows[earlier].maximum_literal_bytes,
                    row.minimum_literal_bytes,
                    row.maximum_literal_bytes,
                )
                && execution_envelopes_overlap(
                    rows[earlier].minimum_window_bytes,
                    row.minimum_window_bytes,
                )
            {
                return false;
            }
            earlier += 1;
        }
        index += 1;
    }
    true
}

const fn production_family_profile_is_canonical(
    family: &SourceQualifiedStaticSearchSpanFamilyV1,
) -> bool {
    let Some(prefix_with_literal_bytes) = family
        .portable_prefix_candidate_starts
        .checked_add(family.maximum_literal_bytes)
    else {
        return false;
    };
    let Some(minimum_prefix_window_bytes) = prefix_with_literal_bytes.checked_sub(1) else {
        return false;
    };
    if family.compiler_version != AOT_SEARCH_COMPILER_VERSION_V1
        || family.metadata_version != SEARCH_METADATA_VERSION_V1
        || family.call_abi_schema != SEARCH_CALL_ABI_SCHEMA_V1
        || family.exported_symbol_schema != SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1
        || family.output_kind != SEARCH_SPAN_OUTPUT_KIND_V1
        || family.architecture != SEARCH_ARCHITECTURE_AARCH64_V1
        || !family.little_endian
        || family.pointer_width != SEARCH_POINTER_WIDTH_V1
        || family.target_abi != SEARCH_TARGET_ABI_AAPCS64_V1
        || family.status_bits != SEARCH_STATUS_BITS_V1
        || family.minimum_literal_bytes < MIN_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1
        || family.maximum_literal_bytes > MAX_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1
        || family.minimum_literal_bytes > family.maximum_literal_bytes
        || family.minimum_window_bytes == 0
        || family.portable_prefix_candidate_starts == 0
        || family.minimum_window_bytes < minimum_prefix_window_bytes
    {
        return false;
    }
    match (
        family.platform,
        family.backend_version,
        family.required_features,
        family.exported_symbol_n_type,
    ) {
        (
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_BACKEND_VERSION_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
        )
        | (
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_BACKEND_VERSION_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        )
        | (
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_BACKEND_ASIMD_TAG22_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
        )
        | (
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_BACKEND_ASIMD_TAG22_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        )
        | (
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_BACKEND_ASIMD_TAG23_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
        )
        | (
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_BACKEND_ASIMD_TAG23_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        )
        | (
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_BACKEND_ASIMD_TAG25_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
        )
        | (
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_BACKEND_ASIMD_TAG25_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        )
        | (
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_BACKEND_ASIMD_TAG26_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
        )
        | (
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_BACKEND_ASIMD_TAG26_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        )
        | (
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_BACKEND_ASIMD_TAG28_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
        )
        | (
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_BACKEND_ASIMD_TAG28_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        )
        | (
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_BACKEND_ASIMD_TAG29_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
        )
        | (
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_BACKEND_ASIMD_TAG29_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        )
        | (
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_BACKEND_ASIMD_TAG30_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
        )
        | (
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_BACKEND_ASIMD_TAG30_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        ) => true,
        (
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_BACKEND_ASIMD_TAG37_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
        )
        | (
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_BACKEND_ASIMD_TAG37_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        ) => {
            family.minimum_literal_bytes >= SEARCH_BACKEND_ASIMD_TAG37_MIN_LITERAL_BYTES_V1
                && family.maximum_literal_bytes <= SEARCH_BACKEND_ASIMD_TAG37_MAX_LITERAL_BYTES_V1
        }
        (
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_BACKEND_ASIMD_TAG38_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
        )
        | (
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_BACKEND_ASIMD_TAG38_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        ) => {
            family.minimum_literal_bytes >= SEARCH_BACKEND_ASIMD_TAG38_MIN_LITERAL_BYTES_V1
                && family.maximum_literal_bytes <= SEARCH_BACKEND_ASIMD_TAG38_MAX_LITERAL_BYTES_V1
        }
        (
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1,
            SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        ) => family.minimum_literal_bytes == 16 && family.maximum_literal_bytes == 16,
        _ => false,
    }
}

const fn same_production_family_profile(
    left: &SourceQualifiedStaticSearchSpanFamilyV1,
    right: &SourceQualifiedStaticSearchSpanFamilyV1,
) -> bool {
    left.compiler_version == right.compiler_version
        && left.metadata_version == right.metadata_version
        && left.backend_version == right.backend_version
        && left.call_abi_schema == right.call_abi_schema
        && left.exported_symbol_schema == right.exported_symbol_schema
        && left.output_kind == right.output_kind
        && left.architecture == right.architecture
        && left.little_endian == right.little_endian
        && left.pointer_width == right.pointer_width
        && left.target_abi == right.target_abi
        && left.platform == right.platform
        && left.status_bits == right.status_bits
        && left.exported_symbol_n_type == right.exported_symbol_n_type
        && left.required_features == right.required_features
}

/// A minimum-only deployment envelope extends to every larger input. Two
/// source families with the same machine profile therefore remain ambiguous
/// above the larger floor; changing the floor cannot make overlapping literal
/// widths disjoint.
const fn execution_envelopes_overlap(left_minimum: u32, right_minimum: u32) -> bool {
    left_minimum != 0 && right_minimum != 0
}

const fn ranges_overlap(
    left_minimum: u32,
    left_maximum: u32,
    right_minimum: u32,
    right_maximum: u32,
) -> bool {
    left_minimum <= right_maximum && right_minimum <= left_maximum
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

/// Production remains closed to candidate-only backend identities even when
/// the common family validator must understand them for private qualification.
const fn production_search_span_families_are_canonical(
    rows: &[SourceQualifiedStaticSearchSpanFamilyV1],
) -> bool {
    if !search_span_families_are_canonical(rows) {
        return false;
    }
    let mut index = 0_usize;
    while index < rows.len() {
        if matches!(
            rows[index].backend_version,
            SEARCH_BACKEND_ASIMD_TAG37_V1 | SEARCH_BACKEND_ASIMD_TAG38_V1
        ) {
            return false;
        }
        let Some(next) = index.checked_add(1) else {
            return false;
        };
        index = next;
    }
    true
}

fn production_authority_tables_are_canonical() -> bool {
    production_search_span_families_are_canonical(
        PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1,
    ) && authority_tables_are_canonical_for(
        PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1,
        PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1,
    )
}

#[cfg(feature = "search-span-qualification-private-v1")]
fn private_qualification_authority_tables_are_canonical() -> bool {
    authority_tables_are_canonical_for(
        PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1,
        PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_FAMILIES_V1,
    )
}

fn authority_tables_are_canonical_for(
    rows: &[SourceQualifiedStaticSearchSpanRowV1],
    families: &[SourceQualifiedStaticSearchSpanFamilyV1],
) -> bool {
    if !qualification_rows_are_canonical(rows) || !search_span_families_are_canonical(families) {
        return false;
    }
    for row in rows {
        if families
            .iter()
            .any(|family| family.selector == row.selector)
        {
            return false;
        }
    }
    true
}

pub(crate) fn require_production_search_span_authority_v1(
    selector: u32,
) -> Result<SourceQualifiedStaticSearchSpanAuthorityV1, StaticSearchSpanVerifyErrorV1> {
    let rows = PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1;
    let families = PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1;
    if rows.is_empty() && families.is_empty() {
        return Err(StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1);
    }
    if !production_authority_tables_are_canonical() {
        return Err(StaticSearchSpanVerifyErrorV1::MalformedStaticSearchSpanQualificationTableV1);
    }
    let selector = u16::try_from(selector)
        .map_err(|_| StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1)?;
    if let Some(row) = rows.iter().find(|row| row.selector == selector) {
        return Ok(SourceQualifiedStaticSearchSpanAuthorityV1::Exact(row));
    }
    if let Some(family) = families.iter().find(|family| family.selector == selector) {
        return Ok(SourceQualifiedStaticSearchSpanAuthorityV1::Family(family));
    }
    Err(StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1)
}

pub(crate) fn require_production_search_span_family_v1(
    selector: u32,
) -> Result<&'static SourceQualifiedStaticSearchSpanFamilyV1, StaticSearchSpanVerifyErrorV1> {
    if PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1.is_empty() {
        return Err(StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1);
    }
    if !production_search_span_families_are_canonical(
        PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1,
    ) {
        return Err(StaticSearchSpanVerifyErrorV1::MalformedStaticSearchSpanQualificationTableV1);
    }
    let selector = u16::try_from(selector)
        .map_err(|_| StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1)?;
    PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1
        .iter()
        .find(|family| family.selector == selector)
        .ok_or(StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1)
}

pub(crate) fn require_production_search_span_row_v1(
    selector: u32,
) -> Result<&'static SourceQualifiedStaticSearchSpanRowV1, StaticSearchSpanVerifyErrorV1> {
    if PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1.is_empty() {
        return Err(StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1);
    }
    find_row(
        PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1,
        selector,
    )
}

#[cfg(feature = "search-span-qualification-private-v1")]
pub(crate) fn require_private_qualification_search_span_row_v1(
    selector: u32,
) -> Result<&'static SourceQualifiedStaticSearchSpanRowV1, StaticSearchSpanVerifyErrorV1> {
    if PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1.is_empty() {
        return Err(StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1);
    }
    if !private_qualification_authority_tables_are_canonical() {
        return Err(StaticSearchSpanVerifyErrorV1::MalformedStaticSearchSpanQualificationTableV1);
    }
    find_row(PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1, selector)
}

#[cfg(feature = "search-span-qualification-private-v1")]
pub(crate) fn require_private_qualification_search_span_family_v1(
    selector: u32,
) -> Result<&'static SourceQualifiedStaticSearchSpanFamilyV1, StaticSearchSpanVerifyErrorV1> {
    if PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_FAMILIES_V1.is_empty() {
        return Err(StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1);
    }
    if !private_qualification_authority_tables_are_canonical() {
        return Err(StaticSearchSpanVerifyErrorV1::MalformedStaticSearchSpanQualificationTableV1);
    }
    let selector = u16::try_from(selector)
        .map_err(|_| StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1)?;
    PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_FAMILIES_V1
        .iter()
        .find(|family| family.selector == selector)
        .ok_or(StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1)
}

#[cfg(test)]
pub(crate) const fn production_authorities_are_empty_for_test_v1() -> bool {
    PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1.is_empty()
        && PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1.is_empty()
}

#[cfg(all(test, feature = "search-span-qualification-private-v1"))]
pub(crate) const fn private_qualification_rows_are_empty_for_test_v1() -> bool {
    PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1.is_empty()
}

#[cfg(all(test, feature = "search-span-qualification-private-v1"))]
pub(crate) const fn private_qualification_families_are_empty_for_test_v1() -> bool {
    PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_FAMILIES_V1.is_empty()
}

fn find_row(
    rows: &[SourceQualifiedStaticSearchSpanRowV1],
    selector: u32,
) -> Result<&SourceQualifiedStaticSearchSpanRowV1, StaticSearchSpanVerifyErrorV1> {
    if rows.len() > HARD_MAX_STATIC_SEARCH_SPAN_QUALIFICATION_ROWS_V1 {
        return Err(StaticSearchSpanVerifyErrorV1::MalformedStaticSearchSpanQualificationTableV1);
    }
    let selector_u16 = u16::try_from(selector)
        .map_err(|_| StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1)?;

    let mut previous_selector = None;
    let mut selected = None;
    for row in rows {
        if previous_selector.is_some_and(|previous| previous >= row.selector) {
            return Err(
                StaticSearchSpanVerifyErrorV1::MalformedStaticSearchSpanQualificationTableV1,
            );
        }
        previous_selector = Some(row.selector);
        if row.selector == selector_u16 {
            selected = Some(row);
        }
    }
    selected.ok_or(StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1)
}

#[cfg(test)]
pub(crate) fn require_test_search_span_row_v1(
    rows: &[SourceQualifiedStaticSearchSpanRowV1],
    selector: u32,
) -> Result<&SourceQualifiedStaticSearchSpanRowV1, StaticSearchSpanVerifyErrorV1> {
    find_row(rows, selector)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(selector: u16, identity: u8) -> SourceQualifiedStaticSearchSpanRowV1 {
        SourceQualifiedStaticSearchSpanRowV1::test_only(
            selector,
            16,
            [identity; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            [5; 32],
            [6; 32],
            [7; 32],
            [8; 32],
            [9; 32],
            [10; 32],
            [11; 32],
        )
    }

    #[test]
    fn production_qualification_state_is_canonical_bounded_and_fails_closed() {
        assert!(qualification_rows_are_canonical(
            PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1
        ));
        assert!(
            PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1.len()
                <= HARD_MAX_STATIC_SEARCH_SPAN_QUALIFICATION_ROWS_V1
        );
        if PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1.is_empty() {
            assert_eq!(
                require_production_search_span_row_v1(0),
                Err(StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1)
            );
        }
        let expected = if PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1.is_empty() {
            StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1
        } else {
            StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1
        };
        assert_eq!(
            require_production_search_span_row_v1(u32::from(u16::MAX) + 1),
            Err(expected)
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the table test keeps every production-family canonicality and tag-specific width refusal in one ordered audit"
    )]
    fn production_family_state_is_canonical_bounded_and_fails_closed() {
        assert!(search_span_families_are_canonical(
            PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1
        ));
        assert!(
            PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1.len()
                <= HARD_MAX_STATIC_SEARCH_SPAN_PRODUCTION_FAMILIES_V1
        );
        if PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1.is_empty() {
            assert_eq!(
                require_production_search_span_family_v1(0),
                Err(StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1)
            );
        }
        let valid = [
            SourceQualifiedStaticSearchSpanFamilyV1::test_only(3, 2, 8),
            SourceQualifiedStaticSearchSpanFamilyV1::test_only(9, 16, 32),
        ];
        assert!(search_span_families_are_canonical(&valid));
        let reversed = [valid[1], valid[0]];
        assert!(!search_span_families_are_canonical(&reversed));
        let empty_width = [SourceQualifiedStaticSearchSpanFamilyV1::test_only(3, 0, 8)];
        assert!(!search_span_families_are_canonical(&empty_width));
        let inverted = [SourceQualifiedStaticSearchSpanFamilyV1::test_only(3, 9, 8)];
        assert!(!search_span_families_are_canonical(&inverted));
        let overlapping = [
            SourceQualifiedStaticSearchSpanFamilyV1::test_only(3, 2, 16),
            SourceQualifiedStaticSearchSpanFamilyV1::test_only(9, 8, 32),
        ];
        assert!(!search_span_families_are_canonical(&overlapping));
        let mut overlapping_different_manifest = overlapping;
        overlapping_different_manifest[1].manifest_identity =
            SourceQualifiedManifestIdentityV1([0xa5; 32]);
        assert!(!search_span_families_are_canonical(
            &overlapping_different_manifest
        ));
        let mut overlapping_different_floor = overlapping;
        overlapping_different_floor[1].minimum_window_bytes = 8_192;
        assert!(!search_span_families_are_canonical(
            &overlapping_different_floor
        ));

        let mut wrong_backend = valid[0];
        wrong_backend.backend_version = 7;
        assert!(!search_span_families_are_canonical(&[wrong_backend]));
        let mut wrong_platform = valid[0];
        wrong_platform.platform = 9;
        assert!(!search_span_families_are_canonical(&[wrong_platform]));
        let mut wrong_features = valid[0];
        wrong_features.required_features = SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1;
        assert!(!search_span_families_are_canonical(&[wrong_features]));
        let mut v9 = valid[0];
        v9.backend_version = SEARCH_BACKEND_ASIMD_TAG22_V1;
        assert!(search_span_families_are_canonical(&[v9]));
        let mut v10 = valid[0];
        v10.backend_version = SEARCH_BACKEND_ASIMD_TAG23_V1;
        assert!(search_span_families_are_canonical(&[v10]));
        let mut v24_below_width_envelope = valid[0];
        v24_below_width_envelope.backend_version = SEARCH_BACKEND_ASIMD_TAG37_V1;
        assert!(!search_span_families_are_canonical(&[
            v24_below_width_envelope
        ]));
        let mut v24 = v24_below_width_envelope;
        v24.minimum_literal_bytes = SEARCH_BACKEND_ASIMD_TAG37_MIN_LITERAL_BYTES_V1;
        assert!(search_span_families_are_canonical(&[v24]));
        assert!(
            !production_search_span_families_are_canonical(&[v24]),
            "candidate-only tag37 must not acquire production-table authority"
        );
        let mut v24_too_wide = v24;
        v24_too_wide.maximum_literal_bytes = SEARCH_BACKEND_ASIMD_TAG37_MAX_LITERAL_BYTES_V1 + 1;
        assert!(!search_span_families_are_canonical(&[v24_too_wide]));
        let mut v25_below_width_envelope = valid[0];
        v25_below_width_envelope.backend_version = SEARCH_BACKEND_ASIMD_TAG38_V1;
        assert!(!search_span_families_are_canonical(&[
            v25_below_width_envelope
        ]));
        let mut v25 = v25_below_width_envelope;
        v25.minimum_literal_bytes = SEARCH_BACKEND_ASIMD_TAG38_MIN_LITERAL_BYTES_V1;
        assert!(search_span_families_are_canonical(&[v25]));
        assert!(
            !production_search_span_families_are_canonical(&[v25]),
            "candidate-only tag38 must not acquire production-table authority"
        );
        let mut v25_too_wide = v25;
        v25_too_wide.maximum_literal_bytes = SEARCH_BACKEND_ASIMD_TAG38_MAX_LITERAL_BYTES_V1 + 1;
        assert!(!search_span_families_are_canonical(&[v25_too_wide]));
        let mut zero_floor = valid[0];
        zero_floor.minimum_window_bytes = 0;
        assert!(!search_span_families_are_canonical(&[zero_floor]));
        let mut zero_prefix = valid[0];
        zero_prefix.portable_prefix_candidate_starts = 0;
        assert!(!search_span_families_are_canonical(&[zero_prefix]));
        let mut prefix_exceeds_floor = valid[0];
        prefix_exceeds_floor.minimum_window_bytes = 262;
        assert!(!search_span_families_are_canonical(&[prefix_exceeds_floor]));
        let mut zero_plan = valid[0];
        zero_plan.plan_identity = SourceQualifiedPlanIdentityV1([0; 32]);
        assert!(!search_span_families_are_canonical(&[zero_plan]));
        let mut zero_analyzer = valid[0];
        zero_analyzer.analyzer_identity = SourceQualifiedAnalyzerIdentityV1([0; 32]);
        assert!(!search_span_families_are_canonical(&[zero_analyzer]));
        let mut zero_evidence = valid[0];
        zero_evidence.evidence_identity = SourceQualifiedEvidenceIdentityV1([0; 32]);
        assert!(!search_span_families_are_canonical(&[zero_evidence]));

        let fixture = crate::search_test_fixture::static_search_span_fixture_v1();
        let ambiguous = [SourceQualifiedStaticSearchSpanFamilyV1::test_only(
            fixture.row.selector(),
            1,
            32,
        )];
        assert!(!authority_tables_are_canonical_for(
            &[fixture.row],
            &ambiguous,
        ));
        let disjoint = [SourceQualifiedStaticSearchSpanFamilyV1::test_only(
            fixture.row.selector().checked_add(1).unwrap(),
            1,
            32,
        )];
        assert!(authority_tables_are_canonical_for(
            &[fixture.row],
            &disjoint,
        ));
    }

    #[cfg(feature = "search-span-qualification-private-v1")]
    #[test]
    fn private_qualification_state_fails_closed_for_unqualified_selectors() {
        assert!(qualification_rows_are_canonical(
            PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1
        ));
        if PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1.is_empty() {
            assert_eq!(
                require_private_qualification_search_span_row_v1(0),
                Err(StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1)
            );
        }
        let expected = if PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1.is_empty() {
            StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1
        } else {
            StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1
        };
        assert_eq!(
            require_private_qualification_search_span_row_v1(u32::from(u16::MAX) + 1),
            Err(expected)
        );
    }

    #[cfg(feature = "search-span-qualification-private-v1")]
    #[test]
    fn private_qualification_family_state_is_canonical_bounded_and_fails_closed() {
        assert!(search_span_families_are_canonical(
            PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_FAMILIES_V1
        ));
        assert!(private_qualification_authority_tables_are_canonical());
        assert!(
            PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_FAMILIES_V1.len()
                <= HARD_MAX_STATIC_SEARCH_SPAN_PRODUCTION_FAMILIES_V1
        );
        if PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_FAMILIES_V1.is_empty() {
            assert_eq!(
                require_private_qualification_search_span_family_v1(0),
                Err(StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1)
            );
        }
        let expected = if PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_FAMILIES_V1.is_empty() {
            StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1
        } else {
            StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1
        };
        assert_eq!(
            require_private_qualification_search_span_family_v1(u32::from(u16::MAX) + 1),
            Err(expected)
        );
    }

    #[test]
    fn synthetic_test_rows_require_strict_order_and_exact_selector() {
        let rows = [row(3, 1), row(11, 9)];
        assert!(qualification_rows_are_canonical(&rows));
        assert_eq!(
            require_test_search_span_row_v1(&rows, 3)
                .expect("first test row")
                .manifest_identity(),
            &[1; 32]
        );
        assert_eq!(
            require_test_search_span_row_v1(&rows, 11)
                .expect("second test row")
                .manifest_identity(),
            &[9; 32]
        );
        for missing in [0, 1, 2, 4, 10, 12, u32::from(u16::MAX) + 1] {
            assert_eq!(
                require_test_search_span_row_v1(&rows, missing),
                Err(StaticSearchSpanVerifyErrorV1::UnqualifiedStaticSearchSpanSelectorV1)
            );
        }

        let duplicate = [row(11, 1), row(11, 9)];
        assert!(!qualification_rows_are_canonical(&duplicate));
        assert_eq!(
            require_test_search_span_row_v1(&duplicate, 11),
            Err(StaticSearchSpanVerifyErrorV1::MalformedStaticSearchSpanQualificationTableV1)
        );
        let reversed = [row(11, 1), row(3, 9)];
        assert!(!qualification_rows_are_canonical(&reversed));
        assert_eq!(
            require_test_search_span_row_v1(&reversed, 3),
            Err(StaticSearchSpanVerifyErrorV1::MalformedStaticSearchSpanQualificationTableV1)
        );
    }
}
