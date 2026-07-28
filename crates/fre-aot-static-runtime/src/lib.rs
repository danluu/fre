//! Static-link verification and adoption boundaries for FRE AOT objects.
//!
//! Count-v2 retains its existing production and C5 qualification architecture.
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
//! The default-off Linux tag21 `SelectedEnd` ABI2 qualification boundary is
//! intentionally narrower. It owns no address adopter or function pointer:
//! compiler-generated identity-suffixed source retains the direct call. This
//! crate supplies only exact-literal scalar preflight/result decoding and a
//! neither-`Send`-nor-`Sync` current-thread token whose construction performs
//! the sole VL16 observation. There is no ABI2 production row.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]

mod call;
mod error;
mod expected;
mod linked;
mod search_call;
mod search_expected;
mod search_linked;
mod search_support;
#[cfg(test)]
mod search_test_fixture;
#[cfg(feature = "selected-end-qualification-private-v2")]
mod selected_end_direct_v2;
mod support;
#[cfg(test)]
mod test_fixture;

pub use error::{
    CallError, StaticAdoptionErrorV2, StaticContractField, StaticSearchSpanAdoptionErrorV1,
    StaticSearchSpanCallErrorV1, StaticSearchSpanContractFieldV1,
    StaticSearchSpanThreadContractErrorV1, StaticSearchSpanVerifyErrorV1, StaticVerifyError,
};
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
pub use selected_end_direct_v2::{
    StaticSearchSelectedEndCallErrorV2, StaticSearchSelectedEndPlanSessionV2,
    StaticSearchSelectedEndPreparedCallV2, StaticSearchSelectedEndProductionAuthorityV2,
    StaticSearchSelectedEndQualificationV2, StaticSearchSelectedEndThreadContractErrorV2,
    StaticSearchSelectedEndThreadSessionV2,
};
