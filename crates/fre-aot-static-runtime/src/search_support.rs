use crate::StaticSearchSpanVerifyErrorV1;

pub(crate) const HARD_MAX_STATIC_SEARCH_SPAN_QUALIFICATION_ROWS_V1: usize = 256;

mod production_rows;
use production_rows::PRODUCTION_SOURCE_QUALIFIED_STATIC_SEARCH_SPAN_ROWS_V1;

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
