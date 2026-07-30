use fre_aot_search_contract::ClaimedStaticSearchSpanExpectationV1;

use crate::{StaticSearchSpanContractFieldV1, StaticSearchSpanVerifyErrorV1};

pub(crate) const HARD_MAX_STATIC_SEARCH_SPAN_QUALIFICATION_ROWS_V1: usize = 256;
pub(crate) const HARD_MAX_STATIC_SEARCH_SPAN_PRODUCTION_FAMILIES_V1: usize = 32;

mod production_rows;
use production_rows::PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1;
mod production_families;
use production_families::PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1;

#[cfg(feature = "search-span-qualification-private-v1")]
mod private_rows;
#[cfg(feature = "search-span-qualification-private-v1")]
use private_rows::PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1;

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
    manifest_identity: SourceQualifiedManifestIdentityV1,
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
        manifest_identity: [u8; 32],
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
            manifest_identity: SourceQualifiedManifestIdentityV1(manifest_identity),
        }
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
            [0x5a; 32],
        )
    }

    pub(crate) const fn selector(&self) -> u16 {
        self.selector
    }

    pub(crate) const fn manifest_identity(&self) -> &[u8; 32] {
        self.manifest_identity.as_bytes()
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

const fn production_families_are_canonical(
    rows: &[SourceQualifiedStaticSearchSpanFamilyV1],
) -> bool {
    if rows.len() > HARD_MAX_STATIC_SEARCH_SPAN_PRODUCTION_FAMILIES_V1 {
        return false;
    }
    let mut index = 0_usize;
    while index < rows.len() {
        let row = &rows[index];
        if row.minimum_literal_bytes == 0
            || row.minimum_literal_bytes > row.maximum_literal_bytes
            || identity_is_zero(&row.manifest_identity.0)
        {
            return false;
        }
        if index > 0 && rows[index - 1].selector >= row.selector {
            return false;
        }
        index += 1;
    }
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

pub(crate) fn require_production_search_span_family_v1(
    selector: u32,
) -> Result<&'static SourceQualifiedStaticSearchSpanFamilyV1, StaticSearchSpanVerifyErrorV1> {
    if PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_FAMILIES_V1.is_empty() {
        return Err(StaticSearchSpanVerifyErrorV1::NoQualifiedStaticSearchSpanRowV1);
    }
    if !production_families_are_canonical(
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
    find_row(PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1, selector)
}

#[cfg(test)]
pub(crate) const fn production_rows_are_empty_for_test_v1() -> bool {
    PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1.is_empty()
}

#[cfg(all(test, feature = "search-span-qualification-private-v1"))]
pub(crate) const fn private_qualification_rows_are_empty_for_test_v1() -> bool {
    PRIVATE_QUALIFICATION_STATIC_SEARCH_SPAN_ROWS_V1.is_empty()
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
    fn production_family_state_is_canonical_bounded_and_fails_closed() {
        assert!(production_families_are_canonical(
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
        assert!(production_families_are_canonical(&valid));
        let reversed = [valid[1], valid[0]];
        assert!(!production_families_are_canonical(&reversed));
        let empty_width = [SourceQualifiedStaticSearchSpanFamilyV1::test_only(3, 0, 8)];
        assert!(!production_families_are_canonical(&empty_width));
        let inverted = [SourceQualifiedStaticSearchSpanFamilyV1::test_only(3, 9, 8)];
        assert!(!production_families_are_canonical(&inverted));
    }

    #[cfg(feature = "search-span-qualification-private-v1")]
    #[test]
    fn private_qualification_state_fails_closed_for_unqualified_selectors() {
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
