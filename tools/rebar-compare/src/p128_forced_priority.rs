//! Explicit Rebar-facing lifecycle for forced priority-automata qualification.
//!
//! This module is deliberately separate from the default Rebar adapter and
//! from the Foundation attribution ledger. Its construction inputs are only
//! source, semantic profile, output operation, exact input length, forced
//! route, target capabilities, and checked limits.

use fre::{
    ForcedExecution, PriorityAggregateBuildLimits, PriorityAggregateBuildReport,
    PriorityAggregateBuilder, PriorityAggregateCountRegex, PriorityAggregateExecutionReceipt,
    PriorityAggregateOperation, PriorityAggregateRunLimits, PriorityAggregateSpanSumRegex,
    PriorityExecutionKernel, PriorityTarget, RustProfile,
};

#[cfg(test)]
use fre::{PRIORITY_AGGREGATE_ACCOUNTING_ID, PRIORITY_AGGREGATE_SCHEMA_VERSION};

use crate::CompareError;

/// Schema for the Rebar-facing forced-priority receipt envelope.
pub const P128_FORCED_PRIORITY_RECEIPT_SCHEMA: &str = "fre.rebar.p128-forced-priority-receipt.v5";

/// Complete construction and execution policy for one retained lifecycle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct P128ForcedPriorityLimits {
    pub construction: PriorityAggregateBuildLimits,
    pub execution: PriorityAggregateRunLimits,
}

#[derive(Debug)]
enum P128ForcedPriorityArtifact {
    Count(PriorityAggregateCountRegex),
    SpanSum(PriorityAggregateSpanSumRegex),
}

impl P128ForcedPriorityArtifact {
    const fn build_report(&self) -> &PriorityAggregateBuildReport {
        match self {
            Self::Count(regex) => regex.build_report(),
            Self::SpanSum(regex) => regex.build_report(),
        }
    }

    fn execute(
        &self,
        haystack: &[u8],
        limits: PriorityAggregateRunLimits,
    ) -> Result<PriorityAggregateExecutionReceipt, CompareError> {
        match self {
            Self::Count(regex) => regex.count(haystack, limits).map_err(|error| {
                CompareError::new(format!("forced-priority Count execution: {error}"))
            }),
            Self::SpanSum(regex) => regex.span_sum(haystack, limits).map_err(|error| {
                CompareError::new(format!("forced-priority SpanSum execution: {error}"))
            }),
        }
    }
}

/// One retained explicit forced-priority construction.
///
/// Repeated calls to [`Self::execute`] reuse this exact artifact. The
/// lifecycle accepts only the structural inputs listed by its constructor and
/// has no automatic-planner input.
#[derive(Debug)]
pub struct P128ForcedPriorityLifecycle {
    operation: PriorityAggregateOperation,
    haystack_len: usize,
    execution: ForcedExecution,
    target: PriorityTarget,
    limits: P128ForcedPriorityLimits,
    artifact: P128ForcedPriorityArtifact,
}

impl P128ForcedPriorityLifecycle {
    /// Operation fixed before canonical parsing and construction.
    #[must_use]
    pub const fn operation(&self) -> PriorityAggregateOperation {
        self.operation
    }

    /// Exact input length bound at retained construction.
    #[must_use]
    pub const fn haystack_len(&self) -> usize {
        self.haystack_len
    }

    /// Route prepared explicitly before any source execution.
    #[must_use]
    pub const fn execution(&self) -> ForcedExecution {
        self.execution
    }

    /// Target capabilities used by exact forced preparation.
    #[must_use]
    pub const fn target(&self) -> PriorityTarget {
        self.target
    }

    /// Complete construction and execution limits.
    #[must_use]
    pub const fn limits(&self) -> P128ForcedPriorityLimits {
        self.limits
    }

    /// Immutable successful construction evidence for the retained artifact.
    #[must_use]
    pub fn build_report(&self) -> &PriorityAggregateBuildReport {
        self.artifact.build_report()
    }

    /// Execute the retained artifact on the exact prepared input length.
    ///
    /// The returned receipt is the native priority receipt wrapped with its
    /// exact successful build, target, and length binding. It is not a
    /// continuation receipt and cannot be submitted to the Foundation binder.
    pub fn execute(&self, haystack: &[u8]) -> Result<P128ForcedPriorityReceipt, CompareError> {
        if haystack.len() != self.haystack_len {
            return Err(CompareError::new(format!(
                "forced-priority haystack length {} differs from retained {}",
                haystack.len(),
                self.haystack_len
            )));
        }
        if !self.closes() {
            return Err(CompareError::new(
                "forced-priority retained construction no longer closes",
            ));
        }
        let native = self.artifact.execute(haystack, self.limits.execution)?;
        let receipt = P128ForcedPriorityReceipt {
            schema: P128_FORCED_PRIORITY_RECEIPT_SCHEMA,
            operation: self.operation,
            haystack_len: self.haystack_len,
            execution: self.execution,
            target: self.target,
            limits: self.limits,
            build: P128ForcedPriorityBuildBinding::from_report(self.artifact.build_report()),
            native,
        };
        if !receipt.closes() {
            return Err(CompareError::new(
                "forced-priority execution receipt does not close",
            ));
        }
        Ok(receipt)
    }

    fn closes(&self) -> bool {
        let report = self.artifact.build_report();
        report.closes()
            && report.operation() == self.operation
            && report.execution() == self.execution
            && report.target() == self.target
            && self.target.supports_execution(self.execution)
            && self.target.supports_kernel(report.kernel())
            && report.limits() == self.limits.construction
    }
}

/// Build one retained, explicitly forced priority lifecycle.
///
/// No automatic aggregate planner, Foundation attribution record, or default
/// Rebar runner path calls this function.
pub fn p128_forced_priority_lifecycle(
    pattern: impl Into<String>,
    profile: RustProfile,
    operation: PriorityAggregateOperation,
    haystack_len: usize,
    execution: ForcedExecution,
    target: PriorityTarget,
    limits: P128ForcedPriorityLimits,
) -> Result<P128ForcedPriorityLifecycle, CompareError> {
    let builder = PriorityAggregateBuilder::new(pattern)
        .profile(profile)
        .limits(limits.construction);
    let artifact = if operation == PriorityAggregateOperation::Count {
        P128ForcedPriorityArtifact::Count(builder.build_count(execution, target).map_err(
            |error| CompareError::new(format!("forced-priority Count construction: {error}")),
        )?)
    } else if operation == PriorityAggregateOperation::SpanSum {
        P128ForcedPriorityArtifact::SpanSum(builder.build_span_sum(execution, target).map_err(
            |error| CompareError::new(format!("forced-priority SpanSum construction: {error}")),
        )?)
    } else {
        return Err(CompareError::new(
            "forced-priority lifecycle received an unsupported operation",
        ));
    };
    let lifecycle = P128ForcedPriorityLifecycle {
        operation,
        haystack_len,
        execution,
        target,
        limits,
        artifact,
    };
    if !lifecycle.closes() {
        return Err(CompareError::new(
            "forced-priority construction report does not close",
        ));
    }
    Ok(lifecycle)
}

/// Immutable successful forced-priority execution and construction evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct P128ForcedPriorityBuildBinding {
    operation: PriorityAggregateOperation,
    execution: ForcedExecution,
    kernel: PriorityExecutionKernel,
    target: PriorityTarget,
    limits: PriorityAggregateBuildLimits,
    static_reducer_retention_bytes: Option<usize>,
    preparation: fre::PreparationAccounting,
}

impl P128ForcedPriorityBuildBinding {
    fn from_report(report: &PriorityAggregateBuildReport) -> Self {
        Self {
            operation: report.operation(),
            execution: report.execution(),
            kernel: report.kernel(),
            target: report.target(),
            limits: report.limits(),
            static_reducer_retention_bytes: report.static_reducer_retention_bytes(),
            preparation: report.preparation(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P128ForcedPriorityReceipt {
    schema: &'static str,
    operation: PriorityAggregateOperation,
    haystack_len: usize,
    execution: ForcedExecution,
    target: PriorityTarget,
    limits: P128ForcedPriorityLimits,
    build: P128ForcedPriorityBuildBinding,
    native: PriorityAggregateExecutionReceipt,
}

impl P128ForcedPriorityReceipt {
    /// Complete reducer value.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.native.value()
    }

    /// Exact input length authenticated before execution.
    #[must_use]
    pub const fn haystack_len(&self) -> usize {
        self.haystack_len
    }

    /// Concrete prepared kernel bound into this retained lifecycle receipt.
    #[must_use]
    pub const fn kernel(&self) -> PriorityExecutionKernel {
        self.build.kernel
    }

    /// Native priority-automata execution receipt.
    #[must_use]
    pub const fn native_receipt(&self) -> &PriorityAggregateExecutionReceipt {
        &self.native
    }

    /// Whether the exact build, route, target, length, limits, and native P/A
    /// receipt all close.
    #[must_use]
    pub fn closes(&self) -> bool {
        let route_kernel_closes = matches!(
            (self.execution, self.build.kernel),
            (
                ForcedExecution::Sparse,
                PriorityExecutionKernel::SparseReverse
            ) | (
                ForcedExecution::FiniteHorizon,
                PriorityExecutionKernel::FiniteHorizonReverse
                    | PriorityExecutionKernel::InputBoundedReverse
            ) | (
                ForcedExecution::FullDfa,
                PriorityExecutionKernel::FullDfa | PriorityExecutionKernel::FullTaggedReverse
            ) | (
                ForcedExecution::LazyDfa,
                PriorityExecutionKernel::LazyDfa | PriorityExecutionKernel::LazyTaggedReverse
            )
        );
        let native_input_bound_closes = match self.build.kernel {
            PriorityExecutionKernel::InputBoundedReverse => {
                self.native.input_bounded_source_bytes() == Some(self.haystack_len)
            }
            _ => self.native.input_bounded_source_bytes().is_none(),
        };
        self.schema == P128_FORCED_PRIORITY_RECEIPT_SCHEMA
            && self.build.operation == self.operation
            && self.build.execution == self.execution
            && self.build.kernel == self.native.kernel()
            && self.build.target == self.target
            && self.target.supports_execution(self.execution)
            && self.target.supports_kernel(self.build.kernel)
            && self.build.limits == self.limits.construction
            && self.build.preparation == self.native.preparation()
            && self.build.static_reducer_retention_bytes
                == self.native.static_reducer_retention_bytes()
            && self.native.closes()
            && self.native.operation() == self.operation
            && self.native.execution() == self.execution
            && self.native.limits() == self.limits.execution
            && self.native.actual().source_bytes == self.haystack_len
            && native_input_bound_closes
            && route_kernel_closes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_priority_receipt_schema_identity_is_current() {
        assert_eq!(PRIORITY_AGGREGATE_SCHEMA_VERSION, 6);
        assert_eq!(
            PRIORITY_AGGREGATE_ACCOUNTING_ID,
            "fre.priority-aggregate.facade.v6"
        );
        assert_eq!(
            P128_FORCED_PRIORITY_RECEIPT_SCHEMA,
            "fre.rebar.p128-forced-priority-receipt.v5"
        );
    }

    #[test]
    fn retained_lifecycle_runs_every_explicit_route_for_both_operations() {
        let haystack = b"zababxab";
        for execution in [
            ForcedExecution::Sparse,
            ForcedExecution::FiniteHorizon,
            ForcedExecution::FullDfa,
            ForcedExecution::LazyDfa,
        ] {
            for (operation, expected) in [
                (PriorityAggregateOperation::Count, 3),
                (PriorityAggregateOperation::SpanSum, 6),
            ] {
                let lifecycle = p128_forced_priority_lifecycle(
                    "ab",
                    RustProfile::default(),
                    operation,
                    haystack.len(),
                    execution,
                    PriorityTarget::portable(),
                    P128ForcedPriorityLimits::default(),
                )
                .unwrap();
                assert_eq!(lifecycle.operation(), operation);
                assert_eq!(lifecycle.execution(), execution);
                assert_eq!(lifecycle.haystack_len(), haystack.len());
                let expected_kernel = match execution {
                    ForcedExecution::Sparse => PriorityExecutionKernel::SparseReverse,
                    ForcedExecution::FiniteHorizon => PriorityExecutionKernel::FiniteHorizonReverse,
                    ForcedExecution::FullDfa => PriorityExecutionKernel::FullDfa,
                    ForcedExecution::LazyDfa => PriorityExecutionKernel::LazyDfa,
                    _ => unreachable!("test covers explicit forced routes only"),
                };
                assert_eq!(lifecycle.build_report().kernel(), expected_kernel);
                assert!(lifecycle.build_report().closes());

                for _ in 0..2 {
                    let receipt = lifecycle.execute(haystack).unwrap();
                    assert_eq!(receipt.value(), expected);
                    assert_eq!(receipt.haystack_len(), haystack.len());
                    assert_eq!(receipt.kernel(), expected_kernel);
                    assert_eq!(receipt.native_receipt().kernel(), expected_kernel);
                    assert!(receipt.closes());
                }
            }
        }
    }

    #[test]
    fn retained_lifecycle_binds_variable_width_assertion_aware_kernels() {
        let haystack = b"cat cater scat cat\xc3\xa9 cat";
        let mut profile = RustProfile::rebar_1_12_4();
        profile.options.unicode = true;
        for (execution, expected_kernel) in [
            (
                ForcedExecution::FullDfa,
                PriorityExecutionKernel::FullTaggedReverse,
            ),
            (
                ForcedExecution::LazyDfa,
                PriorityExecutionKernel::LazyTaggedReverse,
            ),
        ] {
            let lifecycle = p128_forced_priority_lifecycle(
                r"\b(?:cat|cater)\b",
                profile.clone(),
                PriorityAggregateOperation::SpanSum,
                haystack.len(),
                execution,
                PriorityTarget::portable(),
                P128ForcedPriorityLimits::default(),
            )
            .unwrap_or_else(|error| panic!("{execution:?} lifecycle: {error}"));
            assert_eq!(lifecycle.build_report().kernel(), expected_kernel);
            assert!(lifecycle.build_report().closes());

            let receipt = lifecycle
                .execute(haystack)
                .unwrap_or_else(|error| panic!("{execution:?} execution: {error}"));
            assert_eq!(receipt.value(), 11, "{execution:?}");
            assert_eq!(receipt.kernel(), expected_kernel);
            assert_eq!(receipt.native_receipt().kernel(), expected_kernel);
            assert!(receipt.closes());
        }
    }

    #[test]
    fn retained_lifecycle_binds_input_bounded_sparse_fallback() {
        let haystack = b"baaa";
        for (operation, expected_value) in [
            (PriorityAggregateOperation::Count, 2),
            (PriorityAggregateOperation::SpanSum, 3),
        ] {
            let lifecycle = p128_forced_priority_lifecycle(
                r"a*\z",
                RustProfile::default(),
                operation,
                haystack.len(),
                ForcedExecution::FiniteHorizon,
                PriorityTarget::portable(),
                P128ForcedPriorityLimits::default(),
            )
            .unwrap_or_else(|error| panic!("{operation:?} input-bounded lifecycle: {error}"));
            assert_eq!(
                lifecycle.build_report().kernel(),
                PriorityExecutionKernel::InputBoundedReverse,
                "{operation:?}"
            );
            assert!(lifecycle.build_report().closes(), "{operation:?}");

            let receipt = lifecycle
                .execute(haystack)
                .unwrap_or_else(|error| panic!("{operation:?} input-bounded execution: {error}"));
            assert_eq!(receipt.value(), expected_value, "{operation:?}");
            assert_eq!(
                receipt.kernel(),
                PriorityExecutionKernel::InputBoundedReverse,
                "{operation:?}"
            );
            assert_eq!(
                receipt.native_receipt().kernel(),
                PriorityExecutionKernel::InputBoundedReverse,
                "{operation:?}"
            );
            assert_eq!(
                receipt.native_receipt().input_bounded_source_bytes(),
                Some(haystack.len()),
                "{operation:?}"
            );
            assert_eq!(
                receipt.native_receipt().static_reducer_retention_bytes(),
                None,
                "{operation:?}"
            );
            assert!(receipt.closes(), "{operation:?}");
        }
    }

    #[test]
    fn retained_lifecycle_binds_finite_whole_input_without_a_streaming_claim() {
        let haystack = b"baaa";
        for (operation, expected_value) in [
            (PriorityAggregateOperation::Count, 1),
            (PriorityAggregateOperation::SpanSum, 3),
        ] {
            let lifecycle = p128_forced_priority_lifecycle(
                r"a{1,3}\z",
                RustProfile::default(),
                operation,
                haystack.len(),
                ForcedExecution::FiniteHorizon,
                PriorityTarget::portable(),
                P128ForcedPriorityLimits::default(),
            )
            .unwrap_or_else(|error| panic!("{operation:?} finite whole-input lifecycle: {error}"));
            assert_eq!(
                lifecycle.build_report().kernel(),
                PriorityExecutionKernel::FiniteHorizonReverse,
                "{operation:?}"
            );
            assert!(matches!(
                lifecycle.build_report().route_proof(),
                fre::PriorityAggregateRouteProof::FiniteRetentionAtStreamEnd {
                    maximum_match_bytes: 3
                }
            ));
            assert_eq!(
                lifecycle.build_report().static_reducer_retention_bytes(),
                Some(3),
                "{operation:?}"
            );
            assert!(lifecycle.build_report().closes(), "{operation:?}");

            let receipt = lifecycle.execute(haystack).unwrap_or_else(|error| {
                panic!("{operation:?} finite whole-input execution: {error}")
            });
            assert_eq!(receipt.value(), expected_value, "{operation:?}");
            assert_eq!(
                receipt.kernel(),
                PriorityExecutionKernel::FiniteHorizonReverse,
                "{operation:?}"
            );
            assert_eq!(
                receipt.native_receipt().static_reducer_retention_bytes(),
                Some(3),
                "{operation:?}"
            );
            assert_eq!(
                receipt.native_receipt().input_bounded_source_bytes(),
                None,
                "{operation:?}"
            );
            assert!(receipt.closes(), "{operation:?}");
        }
    }

    #[test]
    fn retained_lifecycle_rejects_legacy_route_bits_without_concrete_kernels() {
        let mut missing_input_bounded_sparse = PriorityTarget::portable();
        missing_input_bounded_sparse.sparse = false;
        let error = p128_forced_priority_lifecycle(
            r"a*\z",
            RustProfile::default(),
            PriorityAggregateOperation::Count,
            4,
            ForcedExecution::FiniteHorizon,
            missing_input_bounded_sparse,
            P128ForcedPriorityLimits::default(),
        )
        .expect_err("P128 must reject an undeclared input-bounded sparse fallback");
        assert!(error.to_string().contains("concrete kernel"));

        let mut missing_full_tagged_sparse = PriorityTarget::portable();
        missing_full_tagged_sparse.sparse = false;
        let error = p128_forced_priority_lifecycle(
            "a|ab",
            RustProfile::default(),
            PriorityAggregateOperation::Count,
            2,
            ForcedExecution::FullDfa,
            missing_full_tagged_sparse,
            P128ForcedPriorityLimits::default(),
        )
        .expect_err("P128 must reject an undeclared Full tagged kernel");
        assert!(error.to_string().contains("concrete kernel"));

        let mut missing_lazy_tagged_sparse = PriorityTarget::portable();
        missing_lazy_tagged_sparse.sparse = false;
        let error = p128_forced_priority_lifecycle(
            "a|ab",
            RustProfile::default(),
            PriorityAggregateOperation::Count,
            2,
            ForcedExecution::LazyDfa,
            missing_lazy_tagged_sparse,
            P128ForcedPriorityLimits::default(),
        )
        .expect_err("P128 must reject an undeclared Lazy tagged kernel");
        assert!(error.to_string().contains("concrete kernel"));
    }

    #[test]
    fn retained_lifecycle_rejects_a_different_input_length_before_execution() {
        let lifecycle = p128_forced_priority_lifecycle(
            r"a*\z",
            RustProfile::default(),
            PriorityAggregateOperation::Count,
            4,
            ForcedExecution::FiniteHorizon,
            PriorityTarget::portable(),
            P128ForcedPriorityLimits::default(),
        )
        .unwrap();
        assert_eq!(
            lifecycle.build_report().kernel(),
            PriorityExecutionKernel::InputBoundedReverse
        );
        let error = lifecycle.execute(b"baaaa").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("haystack length 5 differs from retained 4")
        );
    }
}
