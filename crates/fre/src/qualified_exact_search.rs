//! Experimental, explicit opt-in routing for the narrow exact-literal JIT leaf.

use core::fmt;

#[path = "qualified_exact_search_qualification.rs"]
mod qualification_subject;

use fre_jit_aarch64::{
    BackendVersion, EmitError, EmitLimits, ImageStats, TargetSpec, emit_with_backend,
};
use fre_jit_runtime::{
    CallError, PublicationAccounting, PublicationLimits, PublishError, PublishedKernel,
    native_host_support, publish,
};
use fre_kernel_ir::{
    AnchorFlags, BuildError as KernelBuildError, SearchWindow as NativeSearchWindow,
    Span as NativeSpan, ValidateLimits, build_exact_literal,
};
use fre_kernels::{
    LiteralAccounting, LiteralBuildLimits, LiteralError, LiteralPlan, LiteralSearchLimits,
    Window as LiteralWindow,
};

use crate::{Match, SearchLimits, SearchWindow};

pub use fre_jit_aarch64::SearchBackendPolicy as QualifiedExactSearchBackendPolicy;
pub use qualification_subject::QUALIFIED_EXACT_SEARCH_QUALIFICATION;

/// Only this exact literal width is admitted to the qualified JIT route.
pub const QUALIFIED_EXACT_SEARCH_LITERAL_BYTES: usize = 16;

/// Smallest searched window admitted to the qualified JIT route.
///
/// Shorter windows retain the portable literal plan. The fixed threshold is
/// semantic input metadata, never a fixture name or content identity.
pub const QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES: usize = 64 * 1024;

/// Large-window tier with a lower measured amortization threshold.
pub const QUALIFIED_EXACT_SEARCH_LARGE_WINDOW_BYTES: usize = 1024 * 1024;

/// Conservative reuse requirement for windows from 64 KiB through 1 MiB.
///
/// The clean fixed matrix's worst portable break-even was 626 calls. This
/// power-of-two threshold keeps additional margin for process noise.
pub const QUALIFIED_EXACT_SEARCH_MIN_SEARCHES: usize = 1024;

/// Conservative reuse requirement for windows of at least 1 MiB.
///
/// The clean fixed matrix's worst portable break-even was 36 calls.
pub const QUALIFIED_EXACT_SEARCH_LARGE_MIN_SEARCHES: usize = 64;

/// Review state of the exact source revision being exercised by this facade.
///
/// `Candidate` is deliberately not authorization. `Qualified` names the
/// externally hashed, canonical evidence bundle accepted for this exact
/// source subject. The facade has no caller-controlled setter for this state:
/// the current V7 policy uses the source-bound constant, while explicitly
/// selected fixed-lane policies remain `Candidate` until their own evidence
/// and independent review exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualifiedExactSearchQualification {
    /// A qualification subject that may be measured but is not yet accepted.
    Candidate,
    /// An accepted subject bound to one canonical external evidence bundle.
    Qualified { bundle_sha256: [u8; 32] },
}

impl QualifiedExactSearchQualification {
    /// Accepted bundle identity, or `None` for candidates and invalid legacy
    /// or all-zero identities.
    ///
    /// The historical manifest hash was explicitly invalidated. Keeping that
    /// exact value out of the authorization predicate prevents old hash-only
    /// reports from becoming qualified merely by changing their enum tag.
    #[must_use]
    pub fn authorized_bundle_sha256(self) -> Option<[u8; 32]> {
        let Self::Qualified { bundle_sha256 } = self else {
            return None;
        };
        let nonzero = bundle_sha256.iter().any(|byte| *byte != 0);
        let invalidated_historical = bundle_sha256
            == [
                0x89, 0xaf, 0x5a, 0x04, 0x19, 0x0a, 0x39, 0xc4, 0x0a, 0x48, 0x19, 0xce, 0x91, 0x6f,
                0xc2, 0x86, 0x30, 0x33, 0x05, 0x50, 0xe1, 0xca, 0xfc, 0x15, 0xe9, 0x91, 0x91, 0x22,
                0xaf, 0x0a, 0xe9, 0xf7,
            ];
        (nonzero && !invalidated_historical).then_some(bundle_sha256)
    }

    /// Whether this state carries a valid accepted bundle identity.
    #[must_use]
    pub fn is_authorized(self) -> bool {
        self.authorized_bundle_sha256().is_some()
    }
}

/// Caller-proved lower bounds used to admit native construction and routing.
///
/// `minimum_qualifying_searches` counts only calls whose searched windows meet
/// `minimum_window_bytes`, including the first such call. Overstating either
/// bound can hurt performance but cannot change matching semantics or safety.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualifiedExactSearchWorkload {
    minimum_window_bytes: usize,
    minimum_qualifying_searches: usize,
}

impl QualifiedExactSearchWorkload {
    /// Declare the minimum searched bytes and number of qualifying calls.
    #[must_use]
    pub const fn new(minimum_window_bytes: usize, minimum_qualifying_searches: usize) -> Self {
        Self {
            minimum_window_bytes,
            minimum_qualifying_searches,
        }
    }

    /// Smallest searched window the caller promises for native-routed calls.
    #[must_use]
    pub const fn minimum_window_bytes(self) -> usize {
        self.minimum_window_bytes
    }

    /// Minimum number of calls at or above the declared window bound.
    #[must_use]
    pub const fn minimum_qualifying_searches(self) -> usize {
        self.minimum_qualifying_searches
    }

    /// Required call count for this declared minimum window.
    #[must_use]
    pub const fn required_searches(self) -> Option<usize> {
        if self.minimum_window_bytes >= QUALIFIED_EXACT_SEARCH_LARGE_WINDOW_BYTES {
            Some(QUALIFIED_EXACT_SEARCH_LARGE_MIN_SEARCHES)
        } else if self.minimum_window_bytes >= QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES {
            Some(QUALIFIED_EXACT_SEARCH_MIN_SEARCHES)
        } else {
            None
        }
    }

    const fn is_qualified(self) -> bool {
        match self.required_searches() {
            Some(required) => self.minimum_qualifying_searches >= required,
            None => false,
        }
    }
}

/// Which executor handled one exact-literal search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualifiedExactSearchRoute {
    /// The existing safe preprocessed literal plan.
    PortableLiteral,
    /// An audited native JIT selected inside the qualified semantic envelope.
    ///
    /// The stable route name deliberately excludes architecture and backend
    /// version. Concrete publication identity is reported separately.
    NativeJit,
}

/// Concrete identity of one published native route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualifiedExactSearchNativeIdentity {
    /// Explicit construction policy that selected this backend.
    pub backend_policy: QualifiedExactSearchBackendPolicy,
    /// Target and required CPU-feature stamp authenticated from the image.
    pub target: TargetSpec,
    /// Backend contract version authenticated from the image.
    pub backend: BackendVersion,
    /// SHA-256 of the complete deterministic native image and manifest.
    pub artifact_sha256: [u8; 32],
    /// Typed review state for the exact qualification subject.
    pub qualification: QualifiedExactSearchQualification,
}

/// Native publication state retained by a qualified exact matcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualifiedExactSearchNativeStatus {
    /// The literal width is outside the measured JIT envelope.
    IneligibleLiteralWidth { actual: usize, required: usize },
    /// The caller did not declare enough large-window reuse to amortize JIT
    /// construction under the measured cold-cost gate.
    IneligibleWorkload {
        minimum_window_bytes: usize,
        minimum_qualifying_searches: usize,
        required_searches: Option<usize>,
    },
    /// A strict-W^X native mapping is available for qualified calls.
    Published {
        image: ImageStats,
        mapping: PublicationAccounting,
        identity: QualifiedExactSearchNativeIdentity,
    },
    /// The native leaf was valid but could not be published on this process.
    ///
    /// Searches safely retain the portable route, and the complete typed
    /// reason remains inspectable instead of becoming a silent fallback.
    Unavailable(PublishError),
}

impl QualifiedExactSearchNativeStatus {
    /// Whether qualified calls can enter generated code.
    #[must_use]
    pub const fn is_published(&self) -> bool {
        matches!(self, Self::Published { .. })
    }
}

/// Immutable construction facts for one qualified exact matcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualifiedExactSearchBuildReport {
    pub literal_bytes: usize,
    pub jit_literal_bytes: usize,
    pub jit_min_window_bytes: usize,
    pub workload: QualifiedExactSearchWorkload,
    pub backend_policy: QualifiedExactSearchBackendPolicy,
    pub qualification: QualifiedExactSearchQualification,
    pub native: QualifiedExactSearchNativeStatus,
}

/// Per-search executor choice plus the portable refusal/accounting certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualifiedExactSearchExecution {
    pub route: QualifiedExactSearchRoute,
    pub accounting: LiteralAccounting,
}

/// Failure while building both the portable semantic owner and JIT candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QualifiedExactSearchBuildError {
    Portable(LiteralError),
    KernelIr(KernelBuildError),
    Emit(EmitError),
}

impl fmt::Display for QualifiedExactSearchBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "qualified exact-search build failed: {self:?}")
    }
}

impl std::error::Error for QualifiedExactSearchBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Portable(error) => Some(error),
            Self::KernelIr(error) => Some(error),
            Self::Emit(error) => Some(error),
        }
    }
}

impl From<LiteralError> for QualifiedExactSearchBuildError {
    fn from(value: LiteralError) -> Self {
        Self::Portable(value)
    }
}

impl From<KernelBuildError> for QualifiedExactSearchBuildError {
    fn from(value: KernelBuildError) -> Self {
        Self::KernelIr(value)
    }
}

impl From<EmitError> for QualifiedExactSearchBuildError {
    fn from(value: EmitError) -> Self {
        Self::Emit(value)
    }
}

/// Search failure after route-independent portable preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QualifiedExactSearchError {
    Portable(LiteralError),
    Native(CallError),
}

impl fmt::Display for QualifiedExactSearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "qualified exact-search execution failed: {self:?}"
        )
    }
}

impl std::error::Error for QualifiedExactSearchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Portable(error) => Some(error),
            Self::Native(error) => Some(error),
        }
    }
}

impl From<LiteralError> for QualifiedExactSearchError {
    fn from(value: LiteralError) -> Self {
        Self::Portable(value)
    }
}

impl From<CallError> for QualifiedExactSearchError {
    fn from(value: CallError) -> Self {
        Self::Native(value)
    }
}

/// Experimental exact-literal matcher with an evidence-gated native leaf.
///
/// This API is an explicit opt-in and is not selected by FRE's default
/// facades. Construction always retains the portable semantic owner. A
/// 16-byte literal with a qualified reuse declaration additionally attempts
/// bounded `AArch64` emission and strict-W^X publication. Searches enter
/// generated code only when their windows satisfy that declared minimum.
/// Every other width/window/workload, and every unavailable native host,
/// remains on the portable plan.
#[derive(Debug)]
pub struct QualifiedExactSearch {
    portable: LiteralPlan,
    native: Option<PublishedKernel<NativeSpan>>,
    report: QualifiedExactSearchBuildReport,
}

impl QualifiedExactSearch {
    /// Build with the production portable, emission, validation, and
    /// publication limits.
    pub fn new(
        literal: &[u8],
        workload: QualifiedExactSearchWorkload,
    ) -> Result<Self, QualifiedExactSearchBuildError> {
        Self::new_with_backend(
            literal,
            workload,
            QualifiedExactSearchBackendPolicy::CURRENT,
        )
    }

    /// Build with an explicit `AArch64` backend policy and production limits.
    ///
    /// Fixed-lane SVE policies remain caller opt-ins; [`Self::new`] continues
    /// to select Advanced SIMD V7.
    pub fn new_with_backend(
        literal: &[u8],
        workload: QualifiedExactSearchWorkload,
        backend_policy: QualifiedExactSearchBackendPolicy,
    ) -> Result<Self, QualifiedExactSearchBuildError> {
        Self::with_backend_and_limits(
            literal,
            workload,
            backend_policy,
            LiteralBuildLimits::default(),
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits::default(),
        )
    }

    /// Build under explicit bounded component policies using default V7.
    pub fn with_limits(
        literal: &[u8],
        workload: QualifiedExactSearchWorkload,
        literal_limits: LiteralBuildLimits,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
    ) -> Result<Self, QualifiedExactSearchBuildError> {
        Self::with_backend_and_limits(
            literal,
            workload,
            QualifiedExactSearchBackendPolicy::CURRENT,
            literal_limits,
            validation_limits,
            emission_limits,
            publication_limits,
        )
    }

    /// Build under explicit backend and bounded component policies.
    pub fn with_backend_and_limits(
        literal: &[u8],
        workload: QualifiedExactSearchWorkload,
        backend_policy: QualifiedExactSearchBackendPolicy,
        literal_limits: LiteralBuildLimits,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
    ) -> Result<Self, QualifiedExactSearchBuildError> {
        let portable = LiteralPlan::new(literal, literal_limits)?;
        let qualification = if backend_policy == QualifiedExactSearchBackendPolicy::CURRENT {
            QUALIFIED_EXACT_SEARCH_QUALIFICATION
        } else {
            QualifiedExactSearchQualification::Candidate
        };
        let (native, native_status) = if literal.len() != QUALIFIED_EXACT_SEARCH_LITERAL_BYTES {
            (
                None,
                QualifiedExactSearchNativeStatus::IneligibleLiteralWidth {
                    actual: literal.len(),
                    required: QUALIFIED_EXACT_SEARCH_LITERAL_BYTES,
                },
            )
        } else if !workload.is_qualified() {
            (
                None,
                QualifiedExactSearchNativeStatus::IneligibleWorkload {
                    minimum_window_bytes: workload.minimum_window_bytes(),
                    minimum_qualifying_searches: workload.minimum_qualifying_searches(),
                    required_searches: workload.required_searches(),
                },
            )
        } else if let Err(error) = native_host_support() {
            (None, QualifiedExactSearchNativeStatus::Unavailable(error))
        } else {
            let program = build_exact_literal::<NativeSpan>(
                literal,
                AnchorFlags::default(),
                validation_limits,
            )?;
            let image = emit_with_backend(&program, backend_policy, emission_limits)?;
            let image_stats = image.stats();
            match publish::<NativeSpan>(&image, publication_limits) {
                Ok(kernel) => {
                    let mapping = kernel.accounting();
                    let identity = QualifiedExactSearchNativeIdentity {
                        backend_policy,
                        target: image.target(),
                        backend: image.backend_version(),
                        artifact_sha256: *image.artifact_identity().as_bytes(),
                        qualification,
                    };
                    (
                        Some(kernel),
                        QualifiedExactSearchNativeStatus::Published {
                            image: image_stats,
                            mapping,
                            identity,
                        },
                    )
                }
                Err(error) => (None, QualifiedExactSearchNativeStatus::Unavailable(error)),
            }
        };
        Ok(Self {
            portable,
            native,
            report: QualifiedExactSearchBuildReport {
                literal_bytes: literal.len(),
                jit_literal_bytes: QUALIFIED_EXACT_SEARCH_LITERAL_BYTES,
                jit_min_window_bytes: QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
                workload,
                backend_policy,
                qualification,
                native: native_status,
            },
        })
    }

    /// The exact literal retained by the portable semantic owner.
    #[must_use]
    pub fn literal(&self) -> &[u8] {
        self.portable.needle()
    }

    /// Immutable construction and native-availability facts.
    #[must_use]
    pub const fn build_report(&self) -> &QualifiedExactSearchBuildReport {
        &self.report
    }

    /// Find the first match in the complete haystack.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, QualifiedExactSearchExecution), QualifiedExactSearchError> {
        self.find_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Find the first match wholly inside a checked byte window.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, QualifiedExactSearchExecution), QualifiedExactSearchError> {
        let literal_window = LiteralWindow::new(window.start(), window.end());
        let literal_limits = LiteralSearchLimits {
            max_linear_terms: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
        };
        let accounting =
            self.portable
                .preflight_window(haystack.len(), literal_window, literal_limits)?;
        if accounting.searched_bytes >= self.report.workload.minimum_window_bytes()
            && let Some(native) = &self.native
        {
            let matched = native.search(
                haystack,
                NativeSearchWindow::new(window.start(), window.end()),
            )?;
            return Ok((
                matched.map(|span| Match {
                    start: span.start(),
                    end: span.end(),
                }),
                QualifiedExactSearchExecution {
                    route: QualifiedExactSearchRoute::NativeJit,
                    accounting,
                },
            ));
        }
        let (matched, portable_accounting) =
            self.portable
                .find_window(haystack, literal_window, literal_limits)?;
        debug_assert_eq!(portable_accounting, accounting);
        Ok((
            matched.map(|(start, end)| Match { start, end }),
            QualifiedExactSearchExecution {
                route: QualifiedExactSearchRoute::PortableLiteral,
                accounting,
            },
        ))
    }

    /// Whether a selected match exists in the complete haystack.
    pub fn is_match(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(bool, QualifiedExactSearchExecution), QualifiedExactSearchError> {
        self.find(haystack, limits)
            .map(|(matched, execution)| (matched.is_some(), execution))
    }
}
