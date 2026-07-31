use crate::StaticVerifyError;

pub(crate) const HARD_MAX_STATIC_COUNT_QUALIFICATION_ROWS_V2: usize = 256;

macro_rules! qualified_identity {
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

qualified_identity!(QualifiedCompileIdentityV2);
qualified_identity!(QualifiedExpectationIdentityV2);
qualified_identity!(QualifiedObjectIdentityV2);
qualified_identity!(QualifiedReceiptIdentityV2);
qualified_identity!(QualifiedResourceReceiptIdentityV2);

/// One exact final-image qualification decision.
///
/// This type and its constructor stay private so linked metadata, expectation
/// bytes, features, environment variables, and downstream generated code
/// cannot manufacture production authorization. Backend support tuples only
/// describe compiler capability; they never activate runtime execution. This
/// independent table's exact identity pins are the sole activation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the repeated identity suffix makes five security-domain fields unambiguous"
)]
pub(crate) struct QualifiedStaticCountRowV2 {
    selector: u16,
    compile_identity: QualifiedCompileIdentityV2,
    expectation_identity: QualifiedExpectationIdentityV2,
    object_identity: QualifiedObjectIdentityV2,
    receipt_identity: QualifiedReceiptIdentityV2,
    resource_receipt_identity: QualifiedResourceReceiptIdentityV2,
}

impl QualifiedStaticCountRowV2 {
    #[cfg(test)]
    pub(crate) const fn test_only(
        selector: u16,
        compile_identity: [u8; 32],
        expectation_identity: [u8; 32],
        object_identity: [u8; 32],
        receipt_identity: [u8; 32],
        resource_receipt_identity: [u8; 32],
    ) -> Self {
        Self {
            selector,
            compile_identity: QualifiedCompileIdentityV2::test_only(compile_identity),
            expectation_identity: QualifiedExpectationIdentityV2::test_only(expectation_identity),
            object_identity: QualifiedObjectIdentityV2::test_only(object_identity),
            receipt_identity: QualifiedReceiptIdentityV2::test_only(receipt_identity),
            resource_receipt_identity: QualifiedResourceReceiptIdentityV2::test_only(
                resource_receipt_identity,
            ),
        }
    }

    pub(crate) const fn selector(&self) -> u16 {
        self.selector
    }

    pub(crate) const fn compile_identity(&self) -> &[u8; 32] {
        self.compile_identity.as_bytes()
    }

    pub(crate) const fn expectation_identity(&self) -> &[u8; 32] {
        self.expectation_identity.as_bytes()
    }

    pub(crate) const fn object_identity(&self) -> &[u8; 32] {
        self.object_identity.as_bytes()
    }

    pub(crate) const fn receipt_identity(&self) -> &[u8; 32] {
        self.receipt_identity.as_bytes()
    }

    pub(crate) const fn resource_receipt_identity(&self) -> &[u8; 32] {
        self.resource_receipt_identity.as_bytes()
    }
}

/// Exact C5 row under qualification.
///
/// Keeping the row separate from the production table lets the qualification
/// binary exercise its exact bytes without authorizing ordinary
/// `linked-count-v2` builds.
const C5_CANDIDATE_STATIC_COUNT_ROW_V2: QualifiedStaticCountRowV2 = QualifiedStaticCountRowV2 {
    selector: 11,
    compile_identity: QualifiedCompileIdentityV2([
        0xed, 0x06, 0x36, 0x6e, 0xfa, 0xed, 0x9d, 0xe0, 0x23, 0x16, 0x6d, 0x65, 0xfc, 0xee, 0x6d,
        0xbc, 0xe7, 0x61, 0xbe, 0xc7, 0xaa, 0x62, 0xc9, 0x6b, 0xa1, 0x7d, 0x5b, 0xec, 0xe4, 0x45,
        0x83, 0x1f,
    ]),
    expectation_identity: QualifiedExpectationIdentityV2([
        0xaf, 0xc0, 0x02, 0x75, 0xb8, 0xbe, 0x5b, 0x66, 0x1f, 0x41, 0x52, 0x1e, 0xdc, 0x8f, 0x04,
        0x77, 0xb6, 0x68, 0xc3, 0x65, 0xd7, 0x79, 0xec, 0xc0, 0xe5, 0x16, 0x36, 0xa2, 0xaa, 0x1f,
        0x57, 0xd5,
    ]),
    object_identity: QualifiedObjectIdentityV2([
        0xb8, 0x87, 0x28, 0xfc, 0xfd, 0x04, 0x0f, 0xf9, 0xe8, 0xe7, 0x09, 0x4a, 0xe1, 0x9e, 0x25,
        0x29, 0xf9, 0xc0, 0xb0, 0x8b, 0x2d, 0xa6, 0xf0, 0xa0, 0xd5, 0xd4, 0x71, 0xc0, 0x51, 0x0f,
        0xad, 0x0b,
    ]),
    receipt_identity: QualifiedReceiptIdentityV2([
        0x6c, 0x04, 0x35, 0x7f, 0xc2, 0x2f, 0x5e, 0x5d, 0x97, 0x74, 0x23, 0x61, 0xd9, 0xea, 0x2e,
        0x0b, 0xe2, 0x3c, 0x05, 0xd4, 0xb6, 0xc2, 0x3c, 0x4c, 0x49, 0x48, 0x90, 0x69, 0x8e, 0xcf,
        0x7d, 0x7f,
    ]),
    resource_receipt_identity: QualifiedResourceReceiptIdentityV2([
        0x32, 0x82, 0x9b, 0x6c, 0xe4, 0xc4, 0x02, 0xc4, 0xc1, 0x5f, 0xe7, 0xb1, 0x44, 0x44, 0x0b,
        0x07, 0x28, 0x08, 0xb8, 0x68, 0xd9, 0xa0, 0x59, 0x4d, 0x04, 0xe5, 0x28, 0x1c, 0x73, 0x22,
        0xe7, 0xb7,
    ]),
};

/// Source-reviewed promotion atom for the exact C5 qualification bundle.
///
/// All-zero means unpromoted and leaves the production table empty. A later
/// promotion changes only these bytes to the independently verified sealed
/// bundle-manifest SHA-256. No feature, environment variable, build script,
/// generated file, or runtime input can change this atom.
const C5_PROMOTION_BUNDLE_MANIFEST_SHA256_V2: [u8; 32] = [0; 32];

/// Literal production qualification table for this build.
///
/// Rows may use sparse selectors but must be strictly selector-ordered and
/// unique. A gap does not authorize its missing selector.
pub(crate) const QUALIFIED_STATIC_COUNT_ROWS_V2: &[QualifiedStaticCountRowV2] =
    if identity_is_zero(&C5_PROMOTION_BUNDLE_MANIFEST_SHA256_V2) {
        &[]
    } else {
        &[C5_CANDIDATE_STATIC_COUNT_ROW_V2]
    };

#[cfg(feature = "c5-qualification-private-v2")]
const CANDIDATE_STATIC_COUNT_ROWS_V2: &[QualifiedStaticCountRowV2] =
    &[C5_CANDIDATE_STATIC_COUNT_ROW_V2];

const fn identity_is_zero(identity: &[u8; 32]) -> bool {
    let mut index = 0_usize;
    while index < identity.len() {
        if identity[index] != 0 {
            return false;
        }
        let Some(next) = index.checked_add(1) else {
            return false;
        };
        index = next;
    }
    true
}

const _: () = assert!(qualification_rows_are_canonical(
    QUALIFIED_STATIC_COUNT_ROWS_V2
));
const _: () = assert!(
    identity_is_zero(&C5_PROMOTION_BUNDLE_MANIFEST_SHA256_V2)
        == QUALIFIED_STATIC_COUNT_ROWS_V2.is_empty()
);
#[cfg(feature = "c5-qualification-private-v2")]
const _: () = assert!(qualification_rows_are_canonical(
    CANDIDATE_STATIC_COUNT_ROWS_V2
));

const fn qualification_rows_are_canonical(rows: &[QualifiedStaticCountRowV2]) -> bool {
    if rows.len() > HARD_MAX_STATIC_COUNT_QUALIFICATION_ROWS_V2 {
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

pub(crate) fn require_runtime_row(
    selector: u32,
) -> Result<&'static QualifiedStaticCountRowV2, StaticVerifyError> {
    if QUALIFIED_STATIC_COUNT_ROWS_V2.is_empty() {
        return Err(StaticVerifyError::NoQualifiedStaticCountRowV2);
    }
    find_row(QUALIFIED_STATIC_COUNT_ROWS_V2, selector)
}

#[cfg(feature = "c5-qualification-private-v2")]
pub(crate) fn require_candidate_row(
    selector: u32,
) -> Result<&'static QualifiedStaticCountRowV2, StaticVerifyError> {
    find_row(CANDIDATE_STATIC_COUNT_ROWS_V2, selector)
}

fn find_row(
    rows: &[QualifiedStaticCountRowV2],
    selector: u32,
) -> Result<&QualifiedStaticCountRowV2, StaticVerifyError> {
    if rows.len() > HARD_MAX_STATIC_COUNT_QUALIFICATION_ROWS_V2 {
        return Err(StaticVerifyError::MalformedStaticCountQualificationTableV2);
    }
    let selector_u16 =
        u16::try_from(selector).map_err(|_| StaticVerifyError::UnqualifiedStaticCountSelectorV2)?;

    let mut previous_selector = None;
    let mut selected = None;
    for row in rows {
        if previous_selector.is_some_and(|previous| previous >= row.selector) {
            return Err(StaticVerifyError::MalformedStaticCountQualificationTableV2);
        }
        previous_selector = Some(row.selector);
        if row.selector == selector_u16 {
            selected = Some(row);
        }
    }
    selected.ok_or(StaticVerifyError::UnqualifiedStaticCountSelectorV2)
}

#[cfg(test)]
pub(crate) fn require_test_row(
    rows: &[QualifiedStaticCountRowV2],
    selector: u32,
) -> Result<&QualifiedStaticCountRowV2, StaticVerifyError> {
    find_row(rows, selector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_table_exactly_tracks_the_c5_promotion_atom() {
        if identity_is_zero(&C5_PROMOTION_BUNDLE_MANIFEST_SHA256_V2) {
            assert!(QUALIFIED_STATIC_COUNT_ROWS_V2.is_empty());
            assert_eq!(
                require_runtime_row(11),
                Err(StaticVerifyError::NoQualifiedStaticCountRowV2)
            );
        } else {
            assert_eq!(QUALIFIED_STATIC_COUNT_ROWS_V2.len(), 1);
            assert_eq!(
                require_runtime_row(11).expect("promoted C5 row").selector(),
                11
            );
        }
    }

    #[cfg(feature = "c5-qualification-private-v2")]
    #[test]
    fn private_qualification_lookup_does_not_depend_on_the_runtime_table() {
        assert_eq!(CANDIDATE_STATIC_COUNT_ROWS_V2.len(), 1);
        let row = require_candidate_row(11).expect("exact private C5 candidate row");
        assert_eq!(row.selector(), 11);
        assert_eq!(
            require_candidate_row(0),
            Err(StaticVerifyError::UnqualifiedStaticCountSelectorV2)
        );
    }

    #[test]
    fn ordinary_runtime_lookup_rejects_unqualified_selectors() {
        let expected = if identity_is_zero(&C5_PROMOTION_BUNDLE_MANIFEST_SHA256_V2) {
            StaticVerifyError::NoQualifiedStaticCountRowV2
        } else {
            StaticVerifyError::UnqualifiedStaticCountSelectorV2
        };
        assert_eq!(require_runtime_row(0), Err(expected));
    }

    #[test]
    fn private_sparse_rows_require_strict_order_and_exact_selector() {
        let row = |selector, identity| {
            QualifiedStaticCountRowV2::test_only(
                selector,
                [identity; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                [5; 32],
            )
        };
        let rows = [row(3, 1), row(11, 9)];
        assert!(qualification_rows_are_canonical(&rows));
        assert_eq!(
            require_test_row(&rows, 0),
            Err(StaticVerifyError::UnqualifiedStaticCountSelectorV2)
        );
        assert_eq!(
            require_test_row(&rows, 3)
                .expect("first sparse private test row")
                .compile_identity(),
            &[1; 32]
        );
        assert_eq!(
            require_test_row(&rows, 11)
                .expect("second sparse private test row")
                .compile_identity(),
            &[9; 32]
        );
        for missing in [1, 2, 4, 10, 12] {
            assert_eq!(
                require_test_row(&rows, missing),
                Err(StaticVerifyError::UnqualifiedStaticCountSelectorV2)
            );
        }
        assert_eq!(
            require_test_row(&rows, u32::from(u16::MAX) + 1),
            Err(StaticVerifyError::UnqualifiedStaticCountSelectorV2)
        );

        let duplicate = [row(11, 1), row(11, 9)];
        assert!(!qualification_rows_are_canonical(&duplicate));
        assert_eq!(
            require_test_row(&duplicate, 11),
            Err(StaticVerifyError::MalformedStaticCountQualificationTableV2)
        );
        let reversed = [row(11, 1), row(3, 9)];
        assert!(!qualification_rows_are_canonical(&reversed));
        assert_eq!(
            require_test_row(&reversed, 3),
            Err(StaticVerifyError::MalformedStaticCountQualificationTableV2)
        );
        assert_eq!(
            require_test_row(&reversed, 11),
            Err(StaticVerifyError::MalformedStaticCountQualificationTableV2)
        );

        let oversized = vec![row(3, 1); HARD_MAX_STATIC_COUNT_QUALIFICATION_ROWS_V2 + 1];
        assert!(!qualification_rows_are_canonical(&oversized));
        assert_eq!(
            require_test_row(&oversized, 3),
            Err(StaticVerifyError::MalformedStaticCountQualificationTableV2)
        );
    }
}
