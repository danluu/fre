//! Pre-input native Span selection, separate from fallible preparation.

use super::{AotMatcher, AotMode, AotOutput, BackendFactory, CompiledSpec, generated};

/// A raw-free failure after an exact native Span entry was selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AotSpanError {
    /// More than one entry claims the exact same source/profile tuple.
    AmbiguousTuple,
    /// The selected native entry does not implement Span iteration.
    MissingIterator,
    /// The selected artifact failed validation or exclusive preparation.
    Preparation,
}

impl std::fmt::Display for AotSpanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AmbiguousTuple => "native AOT Span registry tuple is ambiguous",
            Self::MissingIterator => "selected native AOT Span has no iterator entry",
            Self::Preparation => "selected native AOT Span preparation failed",
        })
    }
}

impl std::error::Error for AotSpanError {}

/// Immutable exact-key selection for a native selected-leftmost-first matcher.
///
/// Selection happens before reading input. Absence (including a portable-only
/// entry) is a structural decline; malformed native entries are errors. Once
/// selected, preparation or execution failure must not trigger fallback.
/// Each worker must call `prepare` to obtain its own exclusive mutable handle.
#[derive(Clone, Copy)]
pub struct AotSpanFactory {
    spec: &'static CompiledSpec,
}

impl std::fmt::Debug for AotSpanFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AotSpanFactory").finish_non_exhaustive()
    }
}

impl AotSpanFactory {
    /// Select an exact native Span tuple, without preparing or searching it.
    ///
    /// This API does not certify equivalence to a caller's external regex
    /// configuration. That proof must precede selection at the integration.
    ///
    /// # Errors
    /// A duplicate exact tuple or native entry missing its iterator is an
    /// integrity failure, never a structural decline.
    pub fn select(
        mode: AotMode,
        pattern: &str,
        case_insensitive: bool,
    ) -> Result<Option<Self>, AotSpanError> {
        Self::select_from(generated::SPECS, mode, pattern, case_insensitive)
    }

    fn select_from(
        specs: &'static [CompiledSpec],
        mode: AotMode,
        pattern: &str,
        case_insensitive: bool,
    ) -> Result<Option<Self>, AotSpanError> {
        let mut matching = specs.iter().filter(|spec| {
            spec.mode == mode
                && spec.output == AotOutput::Span
                && spec.pattern == pattern
                && spec.case_insensitive == case_insensitive
        });
        let Some(spec) = matching.next() else {
            return Ok(None);
        };
        if matching.next().is_some() {
            return Err(AotSpanError::AmbiguousTuple);
        }
        match spec.backend {
            BackendFactory::Runtime(_) => Ok(None),
            BackendFactory::Native { fill: None, .. }
            | BackendFactory::Prepared {
                span_fill: None, ..
            } => Err(AotSpanError::MissingIterator),
            // A compatibility fill invokes the same compiler-produced native
            // scalar Span entry; it is not a portable execution fallback.
            BackendFactory::Native { fill: Some(_), .. }
            | BackendFactory::Prepared {
                span_fill: Some(_), ..
            } => Ok(Some(Self { spec })),
        }
    }

    /// Prepare independent mutable worker state for this exact entry.
    ///
    /// # Errors
    /// Validation/preparation failure is authoritative and contains no source.
    pub fn prepare(self) -> Result<AotMatcher, AotSpanError> {
        AotMatcher::prepare_spec(self.spec).map_err(|_| AotSpanError::Preparation)
    }
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "test ABI stubs never dereference their pointer arguments"
)]
mod tests {
    use super::*;
    use crate::{AbiResult, NativeFillOutcome, NativeIterState, PreparedSpanFillFactory};
    use std::mem::MaybeUninit;

    unsafe extern "C" fn failed_search(
        _: *const u8,
        _: usize,
        _: usize,
        _: usize,
        _: *mut AbiResult,
    ) -> u32 {
        99
    }

    fn failed_fill(
        _: &[u8],
        _: &mut NativeIterState,
        _: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        panic!("not invoked during selection or preparation")
    }

    unsafe extern "C" fn failed_prepared_search(
        _: crate::FreAotRegexExclusiveHandleV1,
        _: *const u8,
        _: usize,
        _: usize,
        _: usize,
        _: *mut AbiResult,
    ) -> u32 {
        99
    }

    fn failed_prepared_fill(
        _: crate::FreAotRegexExclusiveHandleV1,
        _: &[u8],
        _: &mut NativeIterState,
        _: &mut [MaybeUninit<AbiResult>],
    ) -> NativeFillOutcome {
        panic!("not invoked during selection or preparation")
    }

    static SPECS: [CompiledSpec; 4] = [
        CompiledSpec {
            mode: AotMode::Optimizing,
            output: AotOutput::Span,
            pattern: "public_native",
            case_insensitive: false,
            description: "test native",
            backend: BackendFactory::Native {
                search: failed_search,
                fill: Some(failed_fill),
                exists_batch: None,
            },
        },
        CompiledSpec {
            mode: AotMode::Optimizing,
            output: AotOutput::Span,
            pattern: "public_missing_iterator",
            case_insensitive: false,
            description: "test malformed",
            backend: BackendFactory::Native {
                search: failed_search,
                fill: None,
                exists_batch: None,
            },
        },
        CompiledSpec {
            mode: AotMode::Optimizing,
            output: AotOutput::Span,
            pattern: "public_runtime",
            case_insensitive: false,
            description: "test portable",
            backend: BackendFactory::Runtime(b"not prepared"),
        },
        CompiledSpec {
            mode: AotMode::Optimizing,
            output: AotOutput::Span,
            pattern: "public_bad_program",
            case_insensitive: false,
            description: "test bad program",
            backend: BackendFactory::Prepared {
                search: failed_prepared_search,
                program: b"invalid",
                span_fill: Some(PreparedSpanFillFactory::Compatibility(failed_prepared_fill)),
                exists_batch: None,
                required_prepare_capabilities: 0,
            },
        },
    ];

    fn select(pattern: &str) -> Result<Option<AotSpanFactory>, AotSpanError> {
        AotSpanFactory::select_from(&SPECS, AotMode::Optimizing, pattern, false)
    }

    #[test]
    fn span_factory_absence_profile_and_portable_decline_before_preparation() {
        assert!(select("absent").unwrap().is_none());
        assert!(select("public_runtime").unwrap().is_none());
        assert!(
            AotSpanFactory::select_from(&SPECS, AotMode::Fast, "public_native", false)
                .unwrap()
                .is_none()
        );
        assert!(
            AotSpanFactory::select_from(&SPECS, AotMode::Optimizing, "public_native", true)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn span_factory_selected_integrity_preparation_and_search_errors_are_not_absence() {
        let duplicate = Box::leak(vec![SPECS[0], SPECS[0]].into_boxed_slice());
        assert_eq!(
            AotSpanFactory::select_from(duplicate, AotMode::Optimizing, "public_native", false)
                .unwrap_err(),
            AotSpanError::AmbiguousTuple,
        );
        assert_eq!(
            select("public_missing_iterator").unwrap_err(),
            AotSpanError::MissingIterator
        );
        let malformed = select("public_bad_program").unwrap().unwrap();
        assert_eq!(malformed.prepare().unwrap_err(), AotSpanError::Preparation);
        let factory = select("public_native").unwrap().unwrap();
        assert!(!format!("{factory:?}").contains("public_native"));
        let mut first = factory.prepare().unwrap();
        let mut second = factory.prepare().unwrap();
        assert!(first.find_at(b"public", 0).is_err());
        assert!(second.find_at(b"public", 0).is_err());
    }

    #[test]
    fn span_factory_rejects_unsupported_prepare_capabilities() {
        // Capabilities are checked before program preparation. Use the fixed
        // injected entry so this negative gate also runs in count-only builds
        // whose generated ordinary registry is deliberately empty.
        let spec = &SPECS[3];
        let mut unsupported = *spec;
        if let BackendFactory::Prepared {
            ref mut required_prepare_capabilities,
            ..
        } = unsupported.backend
        {
            *required_prepare_capabilities |= 1_u64 << 63;
        }
        let specs = Box::leak(vec![unsupported].into_boxed_slice());
        let factory =
            AotSpanFactory::select_from(specs, spec.mode, spec.pattern, spec.case_insensitive)
                .unwrap()
                .unwrap();
        assert_eq!(factory.prepare().unwrap_err(), AotSpanError::Preparation);
    }
}
