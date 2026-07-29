//! Static-link verification and adoption boundaries for FRE AOT objects.
//!
//! Count-v2 retains its existing production and C5 qualification architecture.
//! Optimizing Count-v3 adds an independent, self-contained non-LLVM boundary:
//! fixed expectation/metadata inspection, exact Count KIR reconstruction,
//! canonical recipe decode, mapped-code regeneration audit, and a direct
//! value-only handle. Its artifact-independent production authority is exact
//! full-tuple source data and begins empty. The default-off qualification path
//! has disjoint address/handle APIs and cannot populate production authority.
//! The current movable handle is ASIMD-only; future SVE/SVE2 support requires
//! a separate same-thread exact-VL session because Linux SVE VL is mutable per
//! thread.
//! The independent Search-v1 Span architecture uses a JIT- and compiler-neutral
//! 584-byte expectation contract. Its literal source qualification table is
//! checked before any final-image pointer is used, every identity is matched,
//! mapped protections and bytes are verified, and only then can a callable be
//! created inside a registry-owned safe handle.
//!
//! The isolated Search production and private qualification tables begin empty
//! and can gain rows only through their separate reviewed source-promotion
//! transactions; neither a feature nor compiler output can populate them.
//! Compiler `RuntimeAuthority::Absent` remains conceptually separate from this
//! runtime's source-qualified private or production authority.
//!
//! The default-off Linux tag21 `SelectedEnd` ABI2 boundary is intentionally
//! narrower. It owns no address adopter or function pointer:
//! compiler-generated identity-suffixed source retains the direct call. This
//! crate supplies an identity-only lookup against a source-reviewed production
//! table, exact-literal scalar preflight/result decoding, and a
//! neither-`Send`-nor-`Sync` current-thread token whose construction performs
//! the sole VL16 observation. The production table begins empty and is
//! compile-time constrained to remain empty in this source atom. The separate
//! qualification-private feature grants no production authority.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

mod call;
mod error;
mod error_v3;
mod expected;
mod expected_v3;
mod linked;
mod linked_v3;
mod search_call;
mod search_expected;
mod search_linked;
mod search_support;
#[cfg(test)]
mod search_test_fixture;
#[cfg(feature = "linked-search-selected-end-v2")]
mod selected_end_direct_v2;
mod support;
mod support_v3;
#[cfg(test)]
mod test_fixture;

pub use error::{
    CallError, StaticAdoptionErrorV2, StaticContractField, StaticSearchSpanAdoptionErrorV1,
    StaticSearchSpanCallErrorV1, StaticSearchSpanContractFieldV1,
    StaticSearchSpanThreadContractErrorV1, StaticSearchSpanVerifyErrorV1, StaticVerifyError,
};
pub use error_v3::{StaticCountCallErrorV3, StaticCountContractFieldV3, StaticCountVerifyErrorV3};
#[cfg(feature = "linked-hardware-matrix-v2")]
#[doc(hidden)]
pub use linked::invoke_raw_count_hardware_matrix_v2;
pub use linked::{
    HARD_MAX_STATIC_COUNT_OBJECTS_V2, RawAggregateResultV2, RawStaticCountAdoptionOutputV2,
    STATIC_COUNT_ADOPT_STATUS_NO_QUALIFIED_ROW_V2, STATIC_COUNT_ADOPT_STATUS_OK_V2,
    STATIC_COUNT_ADOPT_STATUS_REFUSED_V2, STATIC_COUNT_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V2,
    StaticAggregateEntryV2, StaticLinkedAddressV2, StaticRuntimeInspectionAccountingV2,
    VerifiedStaticCountV2, adopt_linked_static_count_v2, fre_aot_static_count_adopt_raw_v2,
};
#[cfg(feature = "c5-qualification-private-v2")]
#[doc(hidden)]
pub use linked::{
    adopt_linked_static_count_qualification_v2, fre_aot_static_count_adopt_qualification_raw_v2,
};
pub use linked_v3::{
    RawAggregateResultV3, StaticAggregateEntryV3, StaticCountInspectionAccountingV3,
    StaticCountLinkedAddressesV3, VerifiedStaticCountV3, adopt_linked_static_count_v3,
};
#[cfg(feature = "count-v3-qualification-private")]
#[doc(hidden)]
pub use linked_v3::{
    StaticCountQualificationFacadeBindingV3, StaticCountQualificationLinkedAddressesV3,
    VerifiedStaticCountQualificationV3, adopt_linked_static_count_qualification_v3,
};
pub use search_call::{
    RawSearchCallV1, RawSearchResultV1, SEARCH_END_POISON_V1, SEARCH_START_POISON_V1,
    SearchCallErrorV1, StaticSearchOperationV1, decode_search_call_v1,
};
pub use search_linked::{
    HARD_MAX_STATIC_SEARCH_SPAN_OBJECTS_V1, RawStaticSearchSpanAdoptionOutputV1,
    STATIC_SEARCH_SPAN_ADOPT_STATUS_NO_QUALIFIED_ROW_V1, STATIC_SEARCH_SPAN_ADOPT_STATUS_OK_V1,
    STATIC_SEARCH_SPAN_ADOPT_STATUS_REFUSED_V1,
    STATIC_SEARCH_SPAN_ADOPT_STATUS_UNQUALIFIED_SELECTOR_V1, StaticSearchSpanEntryV1,
    StaticSearchSpanInspectionAccountingV1, StaticSearchSpanLinkedAddressV1,
    StaticSearchSpanThreadSessionV1, VerifiedStaticSearchSpanV1,
    adopt_linked_static_search_span_v1, fre_aot_static_search_span_adopt_raw_v1,
};
#[cfg(feature = "search-span-qualification-private-v1")]
#[doc(hidden)]
pub use search_linked::{
    adopt_linked_static_search_span_qualification_v1,
    configure_current_thread_sve_vl16_for_search_qualification_v1,
    fre_aot_static_search_span_adopt_qualification_raw_v1,
};
#[cfg(feature = "selected-end-qualification-private-v2")]
#[doc(hidden)]
pub use selected_end_direct_v2::StaticSearchSelectedEndQualificationV2;
#[cfg(feature = "linked-search-selected-end-v2")]
pub use selected_end_direct_v2::{
    StaticSearchSelectedEndAdoptionV2, StaticSearchSelectedEndArtifactClaimsV2,
    StaticSearchSelectedEndBindingKeyV2, StaticSearchSelectedEndCallErrorV2,
    StaticSearchSelectedEndFallbackStatusV2, StaticSearchSelectedEndOwnedPlanSessionV2,
    StaticSearchSelectedEndPlanSessionV2, StaticSearchSelectedEndPreparedCallV2,
    StaticSearchSelectedEndProductionAuthorityV2, StaticSearchSelectedEndProductionThreadSessionV2,
    StaticSearchSelectedEndProductionV2, StaticSearchSelectedEndQualificationThreadSessionV2,
    StaticSearchSelectedEndSourceQualificationV2, StaticSearchSelectedEndThreadContractErrorV2,
    adopt_compiler_generated_static_search_selected_end_v2,
};
