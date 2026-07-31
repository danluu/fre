//! Inert decoder for one already-completed Search-v1 raw call.
//!
//! This module only checks the operation-specific status/result-slot
//! semantics emitted by the existing `AArch64` search backend. It does not
//! authenticate an object, adopt an entry point, grant runtime authority, or
//! make a deployment claim.
//!
//! In particular, the generic Search-v1 prose in `fre_aot_macho.h` is not
//! production authority for result publication. Existing machine code has
//! three distinct contracts: [`Exists`] publishes neither result word,
//! [`SelectedEnd`] publishes only `end`, and [`Span`] publishes both words.

use core::fmt;

use fre_kernel_ir::{Exists, MatchSpan, Operation, OutputKind, SearchWindow, SelectedEnd, Span};

/// Start-word poison used at the Search-v1 raw-call boundary.
///
/// Repeating one byte across the native word keeps this value independent of
/// endianness. Search-v1 generated code is currently an `AArch64` ABI, where
/// this is `0xa5a5_a5a5_a5a5_a5a5`.
pub const SEARCH_START_POISON_V1: usize =
    usize::from_ne_bytes([0xa5; core::mem::size_of::<usize>()]);

/// End-word poison used at the Search-v1 raw-call boundary.
///
/// This is deliberately distinct from [`SEARCH_START_POISON_V1`]. On the
/// current 64-bit Search-v1 target it is `0x5a5a_5a5a_5a5a_5a5a`.
pub const SEARCH_END_POISON_V1: usize = usize::from_ne_bytes([0x5a; core::mem::size_of::<usize>()]);

/// Snapshot of the two-word Search-v1 result slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct RawSearchResultV1 {
    pub start: usize,
    pub end: usize,
}

const _: () =
    assert!(core::mem::size_of::<RawSearchResultV1>() == core::mem::size_of::<[usize; 2]>());
const _: () = assert!(core::mem::align_of::<RawSearchResultV1>() == core::mem::align_of::<usize>());

impl RawSearchResultV1 {
    /// Construct the exact poison state required before a raw Search-v1 call.
    #[must_use]
    pub const fn poisoned() -> Self {
        Self {
            start: SEARCH_START_POISON_V1,
            end: SEARCH_END_POISON_V1,
        }
    }
}

/// Status and result-slot snapshot from one completed Search-v1 raw call.
///
/// This value carries no evidence that the called entry was authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawSearchCallV1 {
    pub status: u64,
    pub result: RawSearchResultV1,
}

/// Failure while decoding the operation-specific Search-v1 machine contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchCallErrorV1 {
    /// The caller supplied an inverted half-open search window.
    InvalidWindow { start: usize, end: usize },
    /// The result words changed differently from the selected operation's
    /// exact publication contract.
    NativeResultPublicationMismatch {
        output: OutputKind,
        status: u64,
        expected_start_changed: bool,
        expected_end_changed: bool,
        observed_start_changed: bool,
        observed_end_changed: bool,
    },
    /// Generated code returned a status outside the fixed no-match/match pair.
    BackendFault { status: u64 },
    /// A published offset or span violated the checked window or exact literal
    /// width.
    InvalidNativeOutput {
        output: OutputKind,
        start: usize,
        end: usize,
        window_start: usize,
        window_end: usize,
        literal_len: usize,
    },
}

impl fmt::Display for SearchCallErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE Search-v1 inert raw-call decode failed: {self:?}"
        )
    }
}

impl std::error::Error for SearchCallErrorV1 {}

mod operation {
    use fre_kernel_ir::{Operation, SearchWindow};

    use super::{RawSearchCallV1, SearchCallErrorV1};

    pub trait Sealed: Operation {
        fn decode_no_match() -> Self::Output;

        fn decode_match(
            raw: RawSearchCallV1,
            window: SearchWindow,
            literal_len: usize,
        ) -> Result<Self::Output, SearchCallErrorV1>;
    }
}

/// Typed Search-v1 output contracts admitted by the inert raw-call decoder.
///
/// This trait is sealed by [`Operation`]'s existing marker types; it does not
/// authorize calling or adopting native code.
pub trait StaticSearchOperationV1: Operation + operation::Sealed {}

impl operation::Sealed for Exists {
    #[inline]
    fn decode_no_match() -> Self::Output {
        false
    }

    #[inline]
    fn decode_match(
        raw: RawSearchCallV1,
        _window: SearchWindow,
        _literal_len: usize,
    ) -> Result<Self::Output, SearchCallErrorV1> {
        require_publication(raw, OutputKind::Exists, false, false)?;
        Ok(true)
    }
}

impl StaticSearchOperationV1 for Exists {}

impl operation::Sealed for SelectedEnd {
    #[inline]
    fn decode_no_match() -> Self::Output {
        None
    }

    #[inline]
    fn decode_match(
        raw: RawSearchCallV1,
        window: SearchWindow,
        literal_len: usize,
    ) -> Result<Self::Output, SearchCallErrorV1> {
        require_publication(raw, OutputKind::SelectedEnd, false, true)?;
        let inferred_start = raw.result.end.checked_sub(literal_len);
        if raw.result.end > window.end()
            || inferred_start.is_none_or(|start| start < window.start())
        {
            return Err(invalid_output(
                OutputKind::SelectedEnd,
                raw.result,
                window,
                literal_len,
            ));
        }
        Ok(Some(raw.result.end))
    }
}

impl StaticSearchOperationV1 for SelectedEnd {}

impl operation::Sealed for Span {
    #[inline]
    fn decode_no_match() -> Self::Output {
        None
    }

    #[inline]
    fn decode_match(
        raw: RawSearchCallV1,
        window: SearchWindow,
        literal_len: usize,
    ) -> Result<Self::Output, SearchCallErrorV1> {
        require_publication(raw, OutputKind::Span, true, true)?;
        let width = raw.result.end.checked_sub(raw.result.start);
        if raw.result.start < window.start()
            || raw.result.end > window.end()
            || width != Some(literal_len)
        {
            return Err(invalid_output(
                OutputKind::Span,
                raw.result,
                window,
                literal_len,
            ));
        }
        Ok(Some(MatchSpan::new(raw.result.start, raw.result.end)))
    }
}

impl StaticSearchOperationV1 for Span {}

/// Decode one completed raw call under an exact, compile-time Search-v1 output
/// contract.
///
/// Status zero is no match and must leave both poison words unchanged. Status
/// one is decoded according to `O`: [`Exists`] leaves both words unchanged,
/// [`SelectedEnd`] changes only `end`, and [`Span`] changes both words. Any
/// other status is a backend fault and must also leave both words unchanged.
///
/// This function checks only returned scalar values. Pointer validity, input
/// preflight, object authentication, entry adoption, and deployment authority
/// are deliberately out of scope.
#[inline]
pub fn decode_search_call_v1<O: StaticSearchOperationV1>(
    raw: RawSearchCallV1,
    window: SearchWindow,
    literal_len: usize,
) -> Result<O::Output, SearchCallErrorV1> {
    if window.start() > window.end() {
        return Err(SearchCallErrorV1::InvalidWindow {
            start: window.start(),
            end: window.end(),
        });
    }

    match raw.status {
        0 => {
            require_publication(raw, O::KIND, false, false)?;
            Ok(<O as operation::Sealed>::decode_no_match())
        }
        1 => <O as operation::Sealed>::decode_match(raw, window, literal_len),
        status => {
            require_publication(raw, O::KIND, false, false)?;
            Err(SearchCallErrorV1::BackendFault { status })
        }
    }
}

#[inline]
fn require_publication(
    raw: RawSearchCallV1,
    output: OutputKind,
    expected_start_changed: bool,
    expected_end_changed: bool,
) -> Result<(), SearchCallErrorV1> {
    let observed_start_changed = raw.result.start != SEARCH_START_POISON_V1;
    let observed_end_changed = raw.result.end != SEARCH_END_POISON_V1;
    if observed_start_changed == expected_start_changed
        && observed_end_changed == expected_end_changed
    {
        return Ok(());
    }
    Err(SearchCallErrorV1::NativeResultPublicationMismatch {
        output,
        status: raw.status,
        expected_start_changed,
        expected_end_changed,
        observed_start_changed,
        observed_end_changed,
    })
}

const fn invalid_output(
    output: OutputKind,
    result: RawSearchResultV1,
    window: SearchWindow,
    literal_len: usize,
) -> SearchCallErrorV1 {
    SearchCallErrorV1::InvalidNativeOutput {
        output,
        start: result.start,
        end: result.end,
        window_start: window.start(),
        window_end: window.end(),
        literal_len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(status: u64, start: usize, end: usize) -> RawSearchCallV1 {
        RawSearchCallV1 {
            status,
            result: RawSearchResultV1 { start, end },
        }
    }

    fn poisoned(status: u64) -> RawSearchCallV1 {
        RawSearchCallV1 {
            status,
            result: RawSearchResultV1::poisoned(),
        }
    }

    #[test]
    fn poison_words_are_distinct_and_repeat_the_documented_bytes() {
        assert_ne!(SEARCH_START_POISON_V1, SEARCH_END_POISON_V1);
        assert_eq!(
            core::mem::size_of::<RawSearchResultV1>(),
            core::mem::size_of::<[usize; 2]>()
        );
        assert_eq!(
            core::mem::align_of::<RawSearchResultV1>(),
            core::mem::align_of::<usize>()
        );
        assert_eq!(
            SEARCH_START_POISON_V1.to_ne_bytes(),
            [0xa5; core::mem::size_of::<usize>()]
        );
        assert_eq!(
            SEARCH_END_POISON_V1.to_ne_bytes(),
            [0x5a; core::mem::size_of::<usize>()]
        );
    }

    #[test]
    fn no_match_is_operation_typed_and_requires_both_words_unchanged() {
        let window = SearchWindow::new(2, 9);
        assert_eq!(
            decode_search_call_v1::<Exists>(poisoned(0), window, 3),
            Ok(false)
        );
        assert_eq!(
            decode_search_call_v1::<SelectedEnd>(poisoned(0), window, 3),
            Ok(None)
        );
        assert_eq!(
            decode_search_call_v1::<Span>(poisoned(0), window, 3),
            Ok(None)
        );

        for changed in [
            raw(0, 4, SEARCH_END_POISON_V1),
            raw(0, SEARCH_START_POISON_V1, 7),
            raw(0, 4, 7),
        ] {
            assert!(matches!(
                decode_search_call_v1::<Span>(changed, window, 3),
                Err(SearchCallErrorV1::NativeResultPublicationMismatch { status: 0, .. })
            ));
        }
    }

    #[test]
    fn backend_fault_requires_both_words_unchanged() {
        let window = SearchWindow::new(0, 8);
        assert_eq!(
            decode_search_call_v1::<Exists>(poisoned(7), window, 2),
            Err(SearchCallErrorV1::BackendFault { status: 7 })
        );
        assert!(matches!(
            decode_search_call_v1::<Exists>(raw(7, SEARCH_START_POISON_V1, 3), window, 2),
            Err(SearchCallErrorV1::NativeResultPublicationMismatch { status: 7, .. })
        ));
    }

    #[test]
    fn exists_match_publishes_no_result_words() {
        let window = SearchWindow::new(3, 11);
        assert_eq!(
            decode_search_call_v1::<Exists>(poisoned(1), window, 4),
            Ok(true)
        );
        assert!(matches!(
            decode_search_call_v1::<Exists>(raw(1, 3, SEARCH_END_POISON_V1), window, 4),
            Err(SearchCallErrorV1::NativeResultPublicationMismatch {
                output: OutputKind::Exists,
                ..
            })
        ));
    }

    #[test]
    fn selected_end_match_publishes_only_a_bounded_end() {
        let window = SearchWindow::new(3, 11);
        assert_eq!(
            decode_search_call_v1::<SelectedEnd>(raw(1, SEARCH_START_POISON_V1, 7), window, 4),
            Ok(Some(7))
        );
        for call in [
            raw(1, 4, 8),
            poisoned(1),
            raw(1, SEARCH_START_POISON_V1, 3),
            raw(1, SEARCH_START_POISON_V1, 12),
        ] {
            assert!(
                decode_search_call_v1::<SelectedEnd>(call, window, 4).is_err(),
                "call unexpectedly passed: {call:?}"
            );
        }
    }

    #[test]
    fn selected_end_rejects_literal_width_underflow() {
        let window = SearchWindow::new(0, 11);
        assert!(matches!(
            decode_search_call_v1::<SelectedEnd>(raw(1, SEARCH_START_POISON_V1, 3), window, 4),
            Err(SearchCallErrorV1::InvalidNativeOutput {
                output: OutputKind::SelectedEnd,
                ..
            })
        ));
    }

    #[test]
    fn span_match_publishes_two_bounded_offsets_of_exact_literal_width() {
        let window = SearchWindow::new(3, 11);
        assert_eq!(
            decode_search_call_v1::<Span>(raw(1, 4, 8), window, 4),
            Ok(Some(MatchSpan::new(4, 8)))
        );
        for call in [
            raw(1, 4, SEARCH_END_POISON_V1),
            raw(1, SEARCH_START_POISON_V1, 8),
            raw(1, 8, 4),
            raw(1, 2, 6),
            raw(1, 8, 12),
            raw(1, 4, 9),
        ] {
            assert!(
                decode_search_call_v1::<Span>(call, window, 4).is_err(),
                "call unexpectedly passed: {call:?}"
            );
        }
    }

    #[test]
    fn inverted_window_is_rejected_before_status_decode() {
        assert_eq!(
            decode_search_call_v1::<Exists>(poisoned(0), SearchWindow::new(9, 3), 1),
            Err(SearchCallErrorV1::InvalidWindow { start: 9, end: 3 })
        );
    }
}
