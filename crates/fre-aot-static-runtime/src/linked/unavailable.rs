use fre_aot_count_contract::STATIC_COUNT_EXPECTATION_BYTES_V2;

use crate::{
    StaticVerifyError,
    call::RawAggregateCallV2,
    expected::ExpectedStaticCountV2,
    linked::{
        AggregateEntryV2, CopiedExpectationV2, LinkedStaticCountSymbolsV2,
        StaticRuntimeInspectionAccountingV2,
    },
};

#[allow(
    unsafe_code,
    reason = "the unavailable implementation never reads the raw pointer"
)]
pub(super) unsafe fn copy_expectation(
    _expectation: *const [u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
) -> Result<CopiedExpectationV2, StaticVerifyError> {
    unavailable()
}

pub(super) fn verify(
    _expected: &ExpectedStaticCountV2,
    _symbols: LinkedStaticCountSymbolsV2,
    _expectation_regions: usize,
) -> Result<(AggregateEntryV2, StaticRuntimeInspectionAccountingV2), StaticVerifyError> {
    unavailable()
}

pub(super) fn invoke_count(_entry: AggregateEntryV2, _haystack: &[u8]) -> RawAggregateCallV2 {
    RawAggregateCallV2 {
        status: u64::MAX,
        value: u64::MAX,
    }
}

#[cfg(test)]
pub(super) const fn verified_entry_conversion_count() -> usize {
    0
}

fn unavailable<T>() -> Result<T, StaticVerifyError> {
    if cfg!(feature = "linked-count-v2") {
        Err(StaticVerifyError::UnsupportedHost)
    } else {
        Err(StaticVerifyError::LinkedCountFeatureDisabled)
    }
}
