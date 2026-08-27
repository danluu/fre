//! Build-time authentication for generated prepared factories.

use fre_aot_regex::{OutputContract, PREPARED_CAPABILITY_ORDERED_NFA_V15, PreparedBulkStrategy};

pub(crate) fn authenticate_prepared_factory(
    output: OutputContract,
    bulk_strategy: Option<PreparedBulkStrategy>,
    required_prepare_capabilities: u64,
    has_span_fill: bool,
    has_exists_batch: bool,
) -> Result<(), String> {
    if required_prepare_capabilities == 0 {
        if bulk_strategy == Some(PreparedBulkStrategy::NativeOrderedNfaLoop) {
            return Err(
                "native Ordered-NFA prepared factory is missing its required V15 capability"
                    .to_owned(),
            );
        }
        return Ok(());
    }
    if required_prepare_capabilities != PREPARED_CAPABILITY_ORDERED_NFA_V15 {
        return Err(format!(
            "prepared factory requires unsupported capability mask {required_prepare_capabilities:#x}"
        ));
    }
    if output != OutputContract::Span {
        return Err("Ordered-NFA V15 prepared factory must have Span output".to_owned());
    }
    if bulk_strategy != Some(PreparedBulkStrategy::NativeOrderedNfaLoop) {
        return Err(
            "Ordered-NFA V15 capability requires the native Ordered-NFA bulk strategy".to_owned(),
        );
    }
    if !has_span_fill || has_exists_batch {
        return Err(
            "Ordered-NFA V15 prepared factory requires SpanFill and forbids ExistsBatch".to_owned(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capability_preserves_non_ordered_prepared_factories() {
        authenticate_prepared_factory(
            OutputContract::Exists,
            Some(PreparedBulkStrategy::RuntimeHelper),
            0,
            false,
            true,
        )
        .expect("legacy prepared factory");
    }

    #[test]
    fn ordered_nfa_factory_requires_exact_v15_span_shape() {
        authenticate_prepared_factory(
            OutputContract::Span,
            Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
            PREPARED_CAPABILITY_ORDERED_NFA_V15,
            true,
            false,
        )
        .expect("authenticated Ordered-NFA V15 factory");

        for (output, bulk, required, span_fill, exists_batch, expected) in [
            (
                OutputContract::Span,
                Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
                0,
                true,
                false,
                "missing its required V15 capability",
            ),
            (
                OutputContract::Span,
                Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
                PREPARED_CAPABILITY_ORDERED_NFA_V15 | (1 << 9),
                true,
                false,
                "unsupported capability mask",
            ),
            (
                OutputContract::Exists,
                Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
                PREPARED_CAPABILITY_ORDERED_NFA_V15,
                false,
                true,
                "must have Span output",
            ),
            (
                OutputContract::Span,
                Some(PreparedBulkStrategy::RuntimeHelper),
                PREPARED_CAPABILITY_ORDERED_NFA_V15,
                true,
                false,
                "native Ordered-NFA bulk strategy",
            ),
            (
                OutputContract::Span,
                Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
                PREPARED_CAPABILITY_ORDERED_NFA_V15,
                false,
                false,
                "requires SpanFill",
            ),
            (
                OutputContract::Span,
                Some(PreparedBulkStrategy::NativeOrderedNfaLoop),
                PREPARED_CAPABILITY_ORDERED_NFA_V15,
                true,
                true,
                "forbids ExistsBatch",
            ),
        ] {
            let error =
                authenticate_prepared_factory(output, bulk, required, span_fill, exists_batch)
                    .expect_err("invalid prepared factory must fail closed");
            assert!(error.contains(expected), "{error:?}");
        }
    }
}
