use fre_kernel_ir::SearchWindow;

use crate::{
    RawSearchCallV1, RawSearchResultV1, StaticSearchSpanVerifyErrorV1,
    search_expected::ExpectedStaticSearchSpanV1,
    search_linked::{
        CopiedSearchSpanExpectationV1, LinkedStaticSearchSpanSymbolsV1, SearchSpanEntryV1,
        StaticSearchSpanInspectionAccountingV1, StaticSearchSpanLinkedAddressV1,
    },
};

#[allow(
    unsafe_code,
    reason = "the unavailable implementation never reads the retained address"
)]
pub(super) unsafe fn copy_expectation(
    _expectation: StaticSearchSpanLinkedAddressV1,
) -> Result<CopiedSearchSpanExpectationV1, StaticSearchSpanVerifyErrorV1> {
    unavailable()
}

pub(super) fn verify(
    _expected: &ExpectedStaticSearchSpanV1,
    _symbols: LinkedStaticSearchSpanSymbolsV1,
    _expectation_regions: usize,
) -> Result<
    (SearchSpanEntryV1, StaticSearchSpanInspectionAccountingV1),
    StaticSearchSpanVerifyErrorV1,
> {
    unavailable()
}

pub(super) fn invoke_search_span(
    _entry: SearchSpanEntryV1,
    _haystack: &[u8],
    _window: SearchWindow,
) -> RawSearchCallV1 {
    RawSearchCallV1 {
        status: u64::MAX,
        result: RawSearchResultV1::poisoned(),
    }
}

#[cfg(test)]
pub(super) const fn verified_entry_conversion_count() -> usize {
    0
}

fn unavailable<T>() -> Result<T, StaticSearchSpanVerifyErrorV1> {
    if cfg!(feature = "linked-search-span-v1") {
        Err(StaticSearchSpanVerifyErrorV1::UnsupportedHost)
    } else {
        Err(StaticSearchSpanVerifyErrorV1::LinkedSearchSpanFeatureDisabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StaticSearchSpanLinkedAddressV1;

    #[test]
    #[allow(
        unsafe_code,
        reason = "the test proves the unavailable implementation returns without reading an invalid address"
    )]
    fn unavailable_copy_fails_closed_without_address_use() {
        let expected = if cfg!(feature = "linked-search-span-v1") {
            StaticSearchSpanVerifyErrorV1::UnsupportedHost
        } else {
            StaticSearchSpanVerifyErrorV1::LinkedSearchSpanFeatureDisabled
        };
        // SAFETY: this implementation is selected only when it promises not to
        // inspect the retained address.
        let result =
            unsafe { copy_expectation(StaticSearchSpanLinkedAddressV1::from_exposed_address(1)) };
        assert!(matches!(result, Err(error) if error == expected));
    }

    #[test]
    #[allow(
        unsafe_code,
        reason = "the inert function pointer is retained but never invoked by the unavailable implementation"
    )]
    fn unavailable_invoke_returns_poisoned_fault_without_calling_entry() {
        #[allow(
            unsafe_code,
            reason = "this ABI-compatible test entry must remain unreachable"
        )]
        unsafe extern "C" fn must_not_run(
            _haystack: *const u8,
            _haystack_len: usize,
            _window_start: usize,
            _window_end: usize,
            _result: *mut RawSearchResultV1,
        ) -> u64 {
            panic!("unavailable implementation called an entry")
        }
        let raw = invoke_search_span(must_not_run, b"haystack", SearchWindow::new(0, 8));
        assert_eq!(raw.status, u64::MAX);
        assert_eq!(raw.result, RawSearchResultV1::poisoned());
        assert_eq!(verified_entry_conversion_count(), 0);
    }
}
