//! Experimental, explicit opt-in routing for the narrow exact-literal JIT leaf.

use core::fmt;
use std::sync::OnceLock;

#[cfg(test)]
use std::cell::Cell;

#[path = "qualified_exact_search_qualification.rs"]
mod qualification_subject;

use fre_jit_aarch64::{
    BackendVersion, EmitError, EmitLimits, ImageStats, SelectedEndRegisterBackendV2, TargetSpec,
    emit_audited_with_backend, emit_selected_end_register_v2,
};
use fre_jit_cache::{
    CacheCreateError, CacheError, CacheLimits, SelectedEndRegisterCacheErrorV2,
    SelectedEndRegisterCacheV2, SelectedEndRegisterLeaseV2,
};
use fre_jit_runtime::{
    CallError, PublicationAccounting, PublicationLimits, PublishError, PublishedKernel,
    PublishedKernelThreadSession, PublishedSelectedEndRegisterPlanThreadSessionV2,
    PublishedSelectedEndRegisterV2, SelectedEndRegisterCallErrorV2, native_search_backend_support,
    native_selected_end_register_backend_support_v2, publish_audited,
    publish_selected_end_register_v2,
};
use fre_kernel_ir::{
    AnchorFlags, BuildError as KernelBuildError, CheckedSearchWindow as NativeCheckedSearchWindow,
    OutputKind as NativeOutputKind, SearchWindow as NativeSearchWindow,
    SelectedEnd as NativeSelectedEnd, ValidateLimits, build_exact_literal,
};
use fre_kernels::{
    LiteralAccounting, LiteralBuildLimits, LiteralError, LiteralPlan, LiteralSearchLimits,
    Window as LiteralWindow,
};

use crate::{
    BuildError, BuildReport, ByteMatch, CompatibilityProfile, Match, PlanKind, PortableBuilder,
    PortableCaptureNames, PortablePlan, PortableRegex, SearchAccounting, SearchError, SearchLimits,
    SearchWindow,
};

pub use fre_jit_aarch64::SearchBackendPolicy as QualifiedExactSearchBackendPolicy;
pub use fre_jit_runtime::KernelThreadContractError as QualifiedExactSearchThreadContractError;
pub use qualification_subject::{
    QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION,
    QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_QUALIFICATION,
    QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION,
    QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION,
};

/// Compatibility name for the default V8 qualification atom.
///
/// Authorization lookup is keyed to the exact backend policy and never follows
/// this alias or the mutable `SearchBackendPolicy::CURRENT` selection.
pub const QUALIFIED_EXACT_SEARCH_QUALIFICATION: QualifiedExactSearchQualification =
    QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION;

const fn qualification_for_backend_with_atoms(
    backend_policy: QualifiedExactSearchBackendPolicy,
    asimd_v8: QualifiedExactSearchQualification,
    sve16_v6: QualifiedExactSearchQualification,
    sve2_fixed16: QualifiedExactSearchQualification,
    sve2_fixed16_v2: QualifiedExactSearchQualification,
) -> QualifiedExactSearchQualification {
    match backend_policy {
        QualifiedExactSearchBackendPolicy::AsimdV8 => asimd_v8,
        QualifiedExactSearchBackendPolicy::Sve16V6 => sve16_v6,
        QualifiedExactSearchBackendPolicy::Sve2Fixed16 => sve2_fixed16,
        QualifiedExactSearchBackendPolicy::Sve2Fixed16V2 => sve2_fixed16_v2,
        QualifiedExactSearchBackendPolicy::AsimdV7
        | QualifiedExactSearchBackendPolicy::AsimdV9
        | QualifiedExactSearchBackendPolicy::AsimdV10
        | QualifiedExactSearchBackendPolicy::AsimdV11
        | QualifiedExactSearchBackendPolicy::Sve16 => QualifiedExactSearchQualification::Candidate,
    }
}

const fn qualification_for_backend(
    backend_policy: QualifiedExactSearchBackendPolicy,
) -> QualifiedExactSearchQualification {
    qualification_for_backend_with_atoms(
        backend_policy,
        QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION,
        QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION,
        QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_QUALIFICATION,
        QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AutomaticBackendSelection {
    backend_policy: QualifiedExactSearchBackendPolicy,
    qualification: QualifiedExactSearchQualification,
    prechecked_host_support: Option<Result<(), PublishError>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AutomaticBackendQualifications {
    asimd_v8: QualifiedExactSearchQualification,
    sve16_v6: QualifiedExactSearchQualification,
    sve2_fixed16: QualifiedExactSearchQualification,
    sve2_fixed16_v2: QualifiedExactSearchQualification,
}

impl AutomaticBackendQualifications {
    const fn new(
        asimd_v8: QualifiedExactSearchQualification,
        sve16_v6: QualifiedExactSearchQualification,
        sve2_fixed16: QualifiedExactSearchQualification,
        sve2_fixed16_v2: QualifiedExactSearchQualification,
    ) -> Self {
        Self {
            asimd_v8,
            sve16_v6,
            sve2_fixed16,
            sve2_fixed16_v2,
        }
    }

    const fn probed_backends(
        self,
    ) -> [(
        QualifiedExactSearchBackendPolicy,
        QualifiedExactSearchQualification,
    ); 3] {
        [
            (
                QualifiedExactSearchBackendPolicy::Sve2Fixed16V2,
                self.sve2_fixed16_v2,
            ),
            (
                QualifiedExactSearchBackendPolicy::Sve2Fixed16,
                self.sve2_fixed16,
            ),
            (QualifiedExactSearchBackendPolicy::Sve16V6, self.sve16_v6),
        ]
    }
}

fn automatic_backend_selection(
    backend_policy: QualifiedExactSearchBackendPolicy,
    qualification: QualifiedExactSearchQualification,
    prechecked_host_support: Option<Result<(), PublishError>>,
) -> AutomaticBackendSelection {
    AutomaticBackendSelection {
        backend_policy,
        qualification,
        prechecked_host_support,
    }
}

fn probe_automatic_backend(
    highest_failure: &mut Option<AutomaticBackendSelection>,
    backend_policy: QualifiedExactSearchBackendPolicy,
    qualification: QualifiedExactSearchQualification,
    probe: impl FnOnce() -> Result<(), PublishError>,
) -> Option<AutomaticBackendSelection> {
    if !qualification.is_authorized() {
        return None;
    }
    match probe() {
        Ok(()) => Some(automatic_backend_selection(
            backend_policy,
            qualification,
            Some(Ok(())),
        )),
        Err(error) => {
            if highest_failure.is_none() {
                *highest_failure = Some(automatic_backend_selection(
                    backend_policy,
                    qualification,
                    Some(Err(error)),
                ));
            }
            None
        }
    }
}

fn automatic_backend_selection_with(
    qualifications: AutomaticBackendQualifications,
    allow_host_probe: bool,
    probe_sve2_fixed16_v2: impl FnOnce() -> Result<(), PublishError>,
    probe_sve2_fixed16: impl FnOnce() -> Result<(), PublishError>,
    probe_sve16_v6: impl FnOnce() -> Result<(), PublishError>,
) -> AutomaticBackendSelection {
    let probed_backends = qualifications.probed_backends();
    if !allow_host_probe {
        for (backend_policy, qualification) in probed_backends {
            if qualification.is_authorized() {
                return automatic_backend_selection(backend_policy, qualification, None);
            }
        }
        return automatic_backend_selection(
            QualifiedExactSearchBackendPolicy::AsimdV8,
            qualifications.asimd_v8,
            None,
        );
    }

    let mut highest_failure = None;
    if let Some(selection) = probe_automatic_backend(
        &mut highest_failure,
        QualifiedExactSearchBackendPolicy::Sve2Fixed16V2,
        qualifications.sve2_fixed16_v2,
        probe_sve2_fixed16_v2,
    ) {
        return selection;
    }
    if let Some(selection) = probe_automatic_backend(
        &mut highest_failure,
        QualifiedExactSearchBackendPolicy::Sve2Fixed16,
        qualifications.sve2_fixed16,
        probe_sve2_fixed16,
    ) {
        return selection;
    }
    if let Some(selection) = probe_automatic_backend(
        &mut highest_failure,
        QualifiedExactSearchBackendPolicy::Sve16V6,
        qualifications.sve16_v6,
        probe_sve16_v6,
    ) {
        return selection;
    }
    if qualifications.asimd_v8.is_authorized() {
        return automatic_backend_selection(
            QualifiedExactSearchBackendPolicy::AsimdV8,
            qualifications.asimd_v8,
            None,
        );
    }
    highest_failure.unwrap_or_else(|| {
        automatic_backend_selection(
            QualifiedExactSearchBackendPolicy::AsimdV8,
            qualifications.asimd_v8,
            None,
        )
    })
}

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

/// Reconstruct the facade's span after the typed runtime has validated the
/// generated `SelectedEnd` result against this same window.
///
/// The qualified native leaf admits exactly one immutable 16-byte literal, so
/// returning only its end removes one generated result store without losing
/// any match information.
#[inline]
fn match_from_legacy_native_selected_end(
    end: usize,
    window: NativeSearchWindow,
) -> Result<Match, CallError> {
    let start = end
        .checked_sub(QUALIFIED_EXACT_SEARCH_LITERAL_BYTES)
        .ok_or(CallError::InvalidNativeOutput {
            output: NativeOutputKind::SelectedEnd,
            start: usize::MAX,
            end,
            window_start: window.start(),
            window_end: window.end(),
        })?;
    if start < window.start() {
        return Err(CallError::InvalidNativeOutput {
            output: NativeOutputKind::SelectedEnd,
            start,
            end,
            window_start: window.start(),
            window_end: window.end(),
        });
    }
    Ok(Match { start, end })
}

/// Review state of the exact source revision being exercised by this facade.
///
/// `Candidate` is deliberately not authorization. `Qualified` names the
/// externally hashed, canonical evidence bundle accepted for this exact
/// source subject. The facade has no caller-controlled setter for this state:
/// exact backend policies use separate source-bound atoms. A bundle accepted
/// for V8, tag 10, tag 19, or tag 21 cannot authorize any peer or a legacy
/// backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualifiedExactSearchQualification {
    /// A qualification subject that may be measured but is not yet accepted.
    Candidate,
    /// An accepted subject bound to one canonical external evidence bundle.
    Qualified { bundle_sha256: [u8; 32] },
}

impl QualifiedExactSearchQualification {
    /// Accepted bundle identity, or `None` for candidates, invalidated
    /// historical identities, or the all-zero identity.
    ///
    /// Historical manifest hashes are explicitly invalidated when their output
    /// contracts no longer match the current route. Keeping those exact values
    /// out of the authorization predicate prevents old hash-only
    /// reports from becoming qualified merely by changing their enum tag.
    #[must_use]
    pub fn authorized_bundle_sha256(self) -> Option<[u8; 32]> {
        let Self::Qualified { bundle_sha256 } = self else {
            return None;
        };
        let nonzero = bundle_sha256.iter().any(|byte| *byte != 0);
        let invalidated_historical = [
            [
                0x89, 0xaf, 0x5a, 0x04, 0x19, 0x0a, 0x39, 0xc4, 0x0a, 0x48, 0x19, 0xce, 0x91, 0x6f,
                0xc2, 0x86, 0x30, 0x33, 0x05, 0x50, 0xe1, 0xca, 0xfc, 0x15, 0xe9, 0x91, 0x91, 0x22,
                0xaf, 0x0a, 0xe9, 0xf7,
            ],
            [
                0xde, 0x08, 0x4f, 0xf0, 0x56, 0x4a, 0xcd, 0xb8, 0x98, 0x89, 0xf2, 0x8b, 0x9d, 0xcf,
                0xdd, 0xce, 0x9b, 0x6f, 0x09, 0x55, 0xa1, 0xb2, 0xae, 0xad, 0x30, 0xd7, 0x57, 0x70,
                0x03, 0x9e, 0x04, 0x53,
            ],
        ]
        .contains(&bundle_sha256);
        (nonzero && !invalidated_historical).then_some(bundle_sha256)
    }

    /// Whether this state carries a valid accepted bundle identity.
    #[must_use]
    pub fn is_authorized(self) -> bool {
        self.authorized_bundle_sha256().is_some()
    }
}

#[cfg(test)]
std::thread_local! {
    static TEST_CANDIDATE_EXECUTION: Cell<bool> = const { Cell::new(false) };
}

/// Qualification-private proof that Candidate execution remains scoped to the
/// current thread.
///
/// The permit is deliberately neither `Send` nor `Sync`. A qualification
/// session borrows it for its complete lifetime, so timed calls can use the
/// same already-authorized projection as a production-qualified release
/// without repeating the test-only thread-local lookup. Normal test sessions
/// do not borrow this permit and retain their dynamic guard-loss fallback.
#[cfg(test)]
#[derive(Debug)]
struct QualificationCandidateExecutionPermit {
    _thread_bound: core::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(test)]
impl QualificationCandidateExecutionPermit {
    fn acquire() -> Self {
        TEST_CANDIDATE_EXECUTION.with(|enabled| {
            assert!(!enabled.replace(true), "nested Candidate execution guard");
        });
        Self {
            _thread_bound: core::marker::PhantomData,
        }
    }

    fn assert_active(&self) {
        TEST_CANDIDATE_EXECUTION.with(|enabled| {
            assert!(
                enabled.get(),
                "Candidate qualification permit lost its thread-local authority"
            );
        });
    }
}

#[cfg(test)]
impl Drop for QualificationCandidateExecutionPermit {
    fn drop(&mut self) {
        TEST_CANDIDATE_EXECUTION.with(|enabled| {
            assert!(enabled.replace(false), "Candidate execution guard was lost");
        });
    }
}

fn qualification_authorizes_native_execution(
    qualification: QualifiedExactSearchQualification,
) -> bool {
    if qualification.is_authorized() {
        return true;
    }
    #[cfg(test)]
    {
        TEST_CANDIDATE_EXECUTION.get()
    }
    #[cfg(not(test))]
    {
        false
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

/// Generated-code call ABI retained by one published native route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualifiedExactSearchNativeAbi {
    /// Sealed Search-v1 out-pointer ABI retained only for tag10 fallback.
    LegacySelectedEndV1,
    /// Register-return ABI2 used by V8, tag19, and tag21.
    SelectedEndRegisterV2,
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
    /// Generated-code call ABI authenticated by the retained publication type.
    pub abi: QualifiedExactSearchNativeAbi,
    /// SHA-256 of the complete deterministic native image and manifest.
    pub artifact_sha256: [u8; 32],
    /// Typed review state for the exact qualification subject.
    pub qualification: QualifiedExactSearchQualification,
    /// SVE vector length bound at publication, when the backend requires one.
    pub sve_vector_bytes_at_publication: Option<u16>,
    /// SVE vector length required when opening an invocation session.
    ///
    /// Register-return tags 19 and 21 report `Some(16)` here and `None` for
    /// `sve_vector_bytes_at_publication`, because ABI2 performs its sole VL
    /// observation at session construction.
    pub required_thread_sve_vector_bytes: Option<u16>,
}

/// Typed reason the bounded process cache could not retain an ABI2 route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualifiedExactSearchCacheUnavailable {
    /// The bounded process cache could not reserve its bookkeeping arrays.
    Create(CacheCreateError),
    /// This lookup was refused or failed a cache-owned contract check.
    Request(SelectedEndRegisterCacheErrorV2),
}

impl fmt::Display for QualifiedExactSearchCacheUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "qualified exact-search native cache unavailable: {self:?}"
        )
    }
}

impl std::error::Error for QualifiedExactSearchCacheUnavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Create(error) => Some(error),
            Self::Request(error) => Some(error),
        }
    }
}

/// Native publication state retained by a qualified exact matcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualifiedExactSearchNativeStatus {
    /// The exact composed source has no accepted evidence bundle.
    ///
    /// Candidate source never reaches host probing, emission, publication, or
    /// generated-code execution.
    Unqualified {
        qualification: QualifiedExactSearchQualification,
    },
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
        abi: QualifiedExactSearchNativeAbi,
        sve_vector_bytes_at_publication: Option<u16>,
        required_thread_sve_vector_bytes: Option<u16>,
        identity: QualifiedExactSearchNativeIdentity,
    },
    /// The native leaf was valid but could not be published on this process.
    ///
    /// Searches safely retain the portable route, and the complete typed
    /// reason remains inspectable instead of becoming a silent fallback.
    Unavailable(PublishError),
    /// The default ABI2 cache could not serve this request.
    ///
    /// Searches safely retain the portable route. Kernel-IR, emission, and
    /// publication failures retain their existing dedicated status/error
    /// routes; this variant covers cache construction, admission, accounting,
    /// and cache-owned contract failures.
    CacheUnavailable(QualifiedExactSearchCacheUnavailable),
    /// This source revision does not expose an invocation ABI for a retired
    /// candidate backend.
    UnsupportedBackendAbi {
        backend_policy: QualifiedExactSearchBackendPolicy,
    },
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
    /// Legacy Search-v1 native call failure.
    Native(CallError),
    /// Register-return Search ABI2 native call failure.
    NativeRegisterV2(SelectedEndRegisterCallErrorV2),
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
            Self::NativeRegisterV2(error) => Some(error),
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

impl From<SelectedEndRegisterCallErrorV2> for QualifiedExactSearchError {
    fn from(value: SelectedEndRegisterCallErrorV2) -> Self {
        Self::NativeRegisterV2(value)
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
/// remains on the portable plan. Every generated-code invocation goes through
/// [`Self::begin_current_thread_session`]. Sessionless calls deliberately
/// retain the portable owner, including V8; tag10 uses the sealed legacy ABI
/// only as fallback, while V8/tag19/tag21 use the register-return ABI2.
#[derive(Debug)]
pub struct QualifiedExactSearch {
    portable: LiteralPlan,
    native: Option<QualifiedExactSearchNative>,
    report: QualifiedExactSearchBuildReport,
}

#[derive(Debug)]
enum QualifiedExactSearchNative {
    LegacyV1(PublishedKernel<NativeSelectedEnd>),
    RegisterV2(QualifiedExactSearchRegisterV2Owner),
}

#[derive(Debug)]
enum QualifiedExactSearchRegisterV2Owner {
    Owned(PublishedSelectedEndRegisterV2),
    Cached(SelectedEndRegisterLeaseV2),
}

impl QualifiedExactSearchRegisterV2Owner {
    #[inline]
    fn kernel(&self) -> &PublishedSelectedEndRegisterV2 {
        match self {
            Self::Owned(kernel) => kernel,
            Self::Cached(lease) => lease.kernel(),
        }
    }
}

impl QualifiedExactSearchNative {
    #[inline]
    fn begin_current_thread_session<'session>(
        &'session self,
        literal_plan: &'session LiteralPlan,
    ) -> Result<
        QualifiedExactSearchNativeThreadSession<'session>,
        QualifiedExactSearchThreadContractError,
    > {
        match self {
            Self::LegacyV1(native) => native
                .begin_current_thread_session()
                .map(QualifiedExactSearchNativeThreadSession::LegacyV1),
            Self::RegisterV2(owner) => owner
                .kernel()
                .begin_current_thread_session_for_literal_plan(literal_plan)
                .map(QualifiedExactSearchNativeThreadSession::RegisterV2),
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the ownership-transfer boundary keeps the authenticated backend, artifact, image, mapping, and qualification receipts explicit"
)]
fn retained_selected_end_register_v2(
    owner: QualifiedExactSearchRegisterV2Owner,
    backend_policy: QualifiedExactSearchBackendPolicy,
    qualification: QualifiedExactSearchQualification,
    target: TargetSpec,
    backend: BackendVersion,
    artifact_sha256: [u8; 32],
    image: ImageStats,
    mapping: PublicationAccounting,
) -> (
    Option<QualifiedExactSearchNative>,
    QualifiedExactSearchNativeStatus,
) {
    let abi = QualifiedExactSearchNativeAbi::SelectedEndRegisterV2;
    let sve_vector_bytes_at_publication = None;
    let required_thread_sve_vector_bytes =
        match owner.kernel().backend().fixed_active_vector_bytes() {
            0 => None,
            bytes => Some(bytes),
        };
    let identity = QualifiedExactSearchNativeIdentity {
        backend_policy,
        target,
        backend,
        abi,
        artifact_sha256,
        qualification,
        sve_vector_bytes_at_publication,
        required_thread_sve_vector_bytes,
    };
    (
        Some(QualifiedExactSearchNative::RegisterV2(owner)),
        QualifiedExactSearchNativeStatus::Published {
            image,
            mapping,
            abi,
            sve_vector_bytes_at_publication,
            required_thread_sve_vector_bytes,
            identity,
        },
    )
}

#[derive(Debug)]
enum QualifiedExactSearchNativeThreadSession<'kernel> {
    LegacyV1(PublishedKernelThreadSession<'kernel, NativeSelectedEnd>),
    RegisterV2(PublishedSelectedEndRegisterPlanThreadSessionV2<'kernel>),
}

impl QualifiedExactSearchNativeThreadSession<'_> {
    #[inline]
    fn search_preflighted(
        &self,
        preflight: fre_kernels::LiteralSearchPreflight<'_, '_>,
    ) -> Result<(Option<Match>, LiteralAccounting), QualifiedExactSearchError> {
        match self {
            Self::LegacyV1(native) => {
                let accounting = preflight.accounting();
                let checked_window = preflight.checked_window();
                let decode_window = checked_window.window();
                let matched = native
                    .search_checked(checked_window)?
                    .map(|end| match_from_legacy_native_selected_end(end, decode_window))
                    .transpose()?;
                Ok((matched, accounting))
            }
            Self::RegisterV2(native) => {
                let (matched, accounting) = native.search_preflighted(preflight)?;
                Ok((
                    matched.map(|span| Match {
                        start: span.start(),
                        end: span.end(),
                    }),
                    accounting,
                ))
            }
        }
    }
}

#[inline]
fn retained_native_if_authorized<T>(
    native: Option<T>,
    authorization: impl FnOnce() -> bool,
) -> Option<T> {
    match native {
        Some(native) if authorization() => Some(native),
        _ => None,
    }
}

const fn selected_end_register_backend_v2(
    backend_policy: QualifiedExactSearchBackendPolicy,
) -> Option<SelectedEndRegisterBackendV2> {
    match backend_policy {
        QualifiedExactSearchBackendPolicy::AsimdV8 => Some(SelectedEndRegisterBackendV2::AsimdV8),
        QualifiedExactSearchBackendPolicy::Sve16V6 => {
            Some(SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16)
        }
        QualifiedExactSearchBackendPolicy::Sve2Fixed16V2 => {
            Some(SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16)
        }
        QualifiedExactSearchBackendPolicy::AsimdV7
        | QualifiedExactSearchBackendPolicy::AsimdV9
        | QualifiedExactSearchBackendPolicy::AsimdV10
        | QualifiedExactSearchBackendPolicy::AsimdV11
        | QualifiedExactSearchBackendPolicy::Sve16
        | QualifiedExactSearchBackendPolicy::Sve2Fixed16 => None,
    }
}

const fn legacy_selected_end_v1_backend(backend_policy: QualifiedExactSearchBackendPolicy) -> bool {
    matches!(
        backend_policy,
        QualifiedExactSearchBackendPolicy::Sve2Fixed16
    )
}

fn qualified_exact_search_backend_support(
    backend_policy: QualifiedExactSearchBackendPolicy,
) -> Result<(), PublishError> {
    if let Some(backend) = selected_end_register_backend_v2(backend_policy) {
        native_selected_end_register_backend_support_v2(backend)
    } else {
        native_search_backend_support(backend_policy.backend_version())
    }
}

static DEFAULT_SELECTED_END_REGISTER_CACHE_V2: OnceLock<
    Result<SelectedEndRegisterCacheV2, CacheCreateError>,
> = OnceLock::new();

fn default_selected_end_register_cache_v2()
-> Result<&'static SelectedEndRegisterCacheV2, CacheCreateError> {
    DEFAULT_SELECTED_END_REGISTER_CACHE_V2
        .get_or_init(|| {
            SelectedEndRegisterCacheV2::new(CacheLimits::default(), PublicationLimits::default())
        })
        .as_ref()
        .map_err(Clone::clone)
}

impl QualifiedExactSearch {
    /// Build with the production portable, emission, validation, and
    /// publication limits.
    pub fn new(
        literal: &[u8],
        workload: QualifiedExactSearchWorkload,
    ) -> Result<Self, QualifiedExactSearchBuildError> {
        Self::with_limits(
            literal,
            workload,
            LiteralBuildLimits::default(),
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits::default(),
        )
    }

    /// Build with an explicit `AArch64` backend policy and production limits.
    ///
    /// [`Self::new`] automatically prefers independently qualified tag 21
    /// when process-wide ASIMD, SVE, SVE2, and tuning admission succeeds.
    /// Tag21 checks the calling thread's VL16 contract only when opening its
    /// invocation session. Construction otherwise falls back through
    /// independently qualified tag 10, tag 19, and V8. This method never
    /// substitutes another backend for the caller's explicit policy.
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

    /// Build under explicit bounded component policies with automatic
    /// qualified-backend selection.
    pub fn with_limits(
        literal: &[u8],
        workload: QualifiedExactSearchWorkload,
        literal_limits: LiteralBuildLimits,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
    ) -> Result<Self, QualifiedExactSearchBuildError> {
        let portable = LiteralPlan::new(literal, literal_limits)?;
        Self::with_portable_plan_automatic_qualification(
            portable,
            workload,
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
        let qualification = qualification_for_backend(backend_policy);
        Self::with_backend_limits_and_qualification(
            literal,
            workload,
            backend_policy,
            literal_limits,
            validation_limits,
            emission_limits,
            publication_limits,
            qualification,
        )
    }

    #[cfg(test)]
    fn with_limits_and_qualification(
        literal: &[u8],
        workload: QualifiedExactSearchWorkload,
        literal_limits: LiteralBuildLimits,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
        qualification: QualifiedExactSearchQualification,
    ) -> Result<Self, QualifiedExactSearchBuildError> {
        Self::with_backend_limits_and_qualification(
            literal,
            workload,
            QualifiedExactSearchBackendPolicy::CURRENT,
            literal_limits,
            validation_limits,
            emission_limits,
            publication_limits,
            qualification,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the internal construction atom keeps backend identity, bounded policies, and source-final qualification explicit"
    )]
    fn with_backend_limits_and_qualification(
        literal: &[u8],
        workload: QualifiedExactSearchWorkload,
        backend_policy: QualifiedExactSearchBackendPolicy,
        literal_limits: LiteralBuildLimits,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
        qualification: QualifiedExactSearchQualification,
    ) -> Result<Self, QualifiedExactSearchBuildError> {
        let portable = LiteralPlan::new(literal, literal_limits)?;
        Self::with_portable_plan_backend_and_qualification(
            portable,
            workload,
            backend_policy,
            validation_limits,
            emission_limits,
            publication_limits,
            qualification,
            None,
        )
    }

    fn with_portable_plan_automatic_qualification(
        portable: LiteralPlan,
        workload: QualifiedExactSearchWorkload,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
    ) -> Result<Self, QualifiedExactSearchBuildError> {
        Self::with_portable_plan_automatic_qualification_from(
            portable,
            workload,
            validation_limits,
            emission_limits,
            publication_limits,
            QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION,
            QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION,
            QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_QUALIFICATION,
            QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION,
            || {
                native_selected_end_register_backend_support_v2(
                    SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
                )
            },
            || {
                native_search_backend_support(
                    QualifiedExactSearchBackendPolicy::Sve2Fixed16.backend_version(),
                )
            },
            || {
                native_selected_end_register_backend_support_v2(
                    SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16,
                )
            },
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the internal automatic-selection atom keeps four backend authorities and three construction-time fixed-lane host proofs explicit"
    )]
    fn with_portable_plan_automatic_qualification_from(
        portable: LiteralPlan,
        workload: QualifiedExactSearchWorkload,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
        asimd_v8: QualifiedExactSearchQualification,
        sve16_v6: QualifiedExactSearchQualification,
        sve2_fixed16: QualifiedExactSearchQualification,
        sve2_fixed16_v2: QualifiedExactSearchQualification,
        probe_sve2_fixed16_v2: impl FnOnce() -> Result<(), PublishError>,
        probe_sve2_fixed16: impl FnOnce() -> Result<(), PublishError>,
        probe_sve16_v6: impl FnOnce() -> Result<(), PublishError>,
    ) -> Result<Self, QualifiedExactSearchBuildError> {
        let allow_host_probe = portable.needle().len() == QUALIFIED_EXACT_SEARCH_LITERAL_BYTES
            && workload.is_qualified();
        let selection = automatic_backend_selection_with(
            AutomaticBackendQualifications::new(asimd_v8, sve16_v6, sve2_fixed16, sve2_fixed16_v2),
            allow_host_probe,
            probe_sve2_fixed16_v2,
            probe_sve2_fixed16,
            probe_sve16_v6,
        );
        Self::with_portable_plan_backend_and_qualification(
            portable,
            workload,
            selection.backend_policy,
            validation_limits,
            emission_limits,
            publication_limits,
            selection.qualification,
            selection.prechecked_host_support,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the internal construction atom keeps backend identity, bounded policies, source-final qualification, and optional auto-selection host proof explicit"
    )]
    fn with_portable_plan_backend_and_qualification(
        portable: LiteralPlan,
        workload: QualifiedExactSearchWorkload,
        backend_policy: QualifiedExactSearchBackendPolicy,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
        qualification: QualifiedExactSearchQualification,
        prechecked_host_support: Option<Result<(), PublishError>>,
    ) -> Result<Self, QualifiedExactSearchBuildError> {
        Self::with_portable_plan_backend_qualification_and_cache(
            portable,
            workload,
            backend_policy,
            validation_limits,
            emission_limits,
            publication_limits,
            qualification,
            prechecked_host_support,
            None,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the qualification-only cache-injection atom keeps backend identity, bounded policies, source-final qualification, optional host proof, and the exact cache owner explicit"
    )]
    fn with_portable_plan_backend_qualification_and_cache(
        portable: LiteralPlan,
        workload: QualifiedExactSearchWorkload,
        backend_policy: QualifiedExactSearchBackendPolicy,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
        qualification: QualifiedExactSearchQualification,
        prechecked_host_support: Option<Result<(), PublishError>>,
        selected_end_register_cache: Option<&SelectedEndRegisterCacheV2>,
    ) -> Result<Self, QualifiedExactSearchBuildError> {
        let literal_bytes = portable.needle().len();
        let (native, native_status) = if literal_bytes != QUALIFIED_EXACT_SEARCH_LITERAL_BYTES {
            (
                None,
                QualifiedExactSearchNativeStatus::IneligibleLiteralWidth {
                    actual: literal_bytes,
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
        } else if !qualification_authorizes_native_execution(qualification) {
            (
                None,
                QualifiedExactSearchNativeStatus::Unqualified { qualification },
            )
        } else if selected_end_register_backend_v2(backend_policy).is_none()
            && !legacy_selected_end_v1_backend(backend_policy)
        {
            (
                None,
                QualifiedExactSearchNativeStatus::UnsupportedBackendAbi { backend_policy },
            )
        } else if let Err(error) = prechecked_host_support
            .unwrap_or_else(|| qualified_exact_search_backend_support(backend_policy))
        {
            (None, QualifiedExactSearchNativeStatus::Unavailable(error))
        } else if let Some(register_backend) = selected_end_register_backend_v2(backend_policy) {
            if publication_limits == PublicationLimits::default() {
                let cache = match selected_end_register_cache {
                    Some(cache) => Ok(cache),
                    None => default_selected_end_register_cache_v2(),
                };
                match cache {
                    Ok(cache) => match cache.get_or_compile_exact_literal(
                        portable.needle(),
                        AnchorFlags::default(),
                        register_backend,
                        validation_limits,
                        emission_limits,
                    ) {
                        Ok(lease) => {
                            let target = lease.target();
                            let backend = lease.backend_version();
                            let artifact_sha256 = *lease.artifact_identity().as_bytes();
                            let image = lease.image_stats();
                            let mapping = lease.accounting();
                            retained_selected_end_register_v2(
                                QualifiedExactSearchRegisterV2Owner::Cached(lease),
                                backend_policy,
                                qualification,
                                target,
                                backend,
                                artifact_sha256,
                                image,
                                mapping,
                            )
                        }
                        Err(CacheError::KernelIr(error)) => return Err(error.into()),
                        Err(CacheError::Emit(error)) => return Err(error.into()),
                        Err(CacheError::Publish(error)) => {
                            (None, QualifiedExactSearchNativeStatus::Unavailable(error))
                        }
                        Err(error) => (
                            None,
                            QualifiedExactSearchNativeStatus::CacheUnavailable(
                                QualifiedExactSearchCacheUnavailable::Request(error),
                            ),
                        ),
                    },
                    Err(error) => (
                        None,
                        QualifiedExactSearchNativeStatus::CacheUnavailable(
                            QualifiedExactSearchCacheUnavailable::Create(error),
                        ),
                    ),
                }
            } else {
                let program = build_exact_literal::<NativeSelectedEnd>(
                    portable.needle(),
                    AnchorFlags::default(),
                    validation_limits,
                )?;
                let audited_image =
                    emit_selected_end_register_v2(&program, register_backend, emission_limits)?;
                let image_stats = audited_image.stats();
                match publish_selected_end_register_v2(&audited_image, publication_limits) {
                    Ok(kernel) => {
                        let mapping = kernel.accounting();
                        retained_selected_end_register_v2(
                            QualifiedExactSearchRegisterV2Owner::Owned(kernel),
                            backend_policy,
                            qualification,
                            audited_image.target(),
                            audited_image.backend_version(),
                            *audited_image.artifact_identity().as_bytes(),
                            image_stats,
                            mapping,
                        )
                    }
                    Err(error) => (None, QualifiedExactSearchNativeStatus::Unavailable(error)),
                }
            }
        } else {
            debug_assert!(legacy_selected_end_v1_backend(backend_policy));
            let program = build_exact_literal::<NativeSelectedEnd>(
                portable.needle(),
                AnchorFlags::default(),
                validation_limits,
            )?;
            let audited_image =
                emit_audited_with_backend(&program, backend_policy, emission_limits)?;
            let image = audited_image.as_image();
            let image_stats = image.stats();
            match publish_audited::<NativeSelectedEnd>(&audited_image, publication_limits) {
                Ok(kernel) => {
                    let mapping = kernel.accounting();
                    let abi = QualifiedExactSearchNativeAbi::LegacySelectedEndV1;
                    let sve_vector_bytes_at_publication = kernel.sve_vector_bytes_at_publication();
                    let required_thread_sve_vector_bytes = sve_vector_bytes_at_publication;
                    let identity = QualifiedExactSearchNativeIdentity {
                        backend_policy,
                        target: image.target(),
                        backend: image.backend_version(),
                        abi,
                        artifact_sha256: *image.artifact_identity().as_bytes(),
                        qualification,
                        sve_vector_bytes_at_publication,
                        required_thread_sve_vector_bytes,
                    };
                    (
                        Some(QualifiedExactSearchNative::LegacyV1(kernel)),
                        QualifiedExactSearchNativeStatus::Published {
                            image: image_stats,
                            mapping,
                            abi,
                            sve_vector_bytes_at_publication,
                            required_thread_sve_vector_bytes,
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
                literal_bytes,
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

    /// Establish a same-thread session for repeated calls.
    ///
    /// A retained fixed-VL SVE/SVE2 mapping checks the calling thread's vector
    /// length exactly once here. A matcher without an authorized native
    /// mapping creates a portable session without probing the host. The
    /// returned token is neither [`Send`] nor [`Sync`]. A typed construction
    /// error performs no search and is not converted into a fallback attempt.
    /// Changing the calling thread's VL invalidates a successful token and
    /// requires a new session.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<QualifiedExactSearchThreadSession<'_>, QualifiedExactSearchThreadContractError>
    {
        self.begin_current_thread_session_authorized_by(|| {
            self.retained_native_execution_authorized()
        })
    }

    #[inline]
    fn begin_current_thread_session_authorized_by(
        &self,
        authorize_native: impl FnOnce() -> bool,
    ) -> Result<QualifiedExactSearchThreadSession<'_>, QualifiedExactSearchThreadContractError>
    {
        let native = retained_native_if_authorized(self.native.as_ref(), authorize_native)
            .map(|native| native.begin_current_thread_session(&self.portable))
            .transpose()?;
        Ok(QualifiedExactSearchThreadSession {
            search: self,
            native,
        })
    }

    #[inline]
    fn retained_native_execution_authorized(&self) -> bool {
        #[cfg(test)]
        {
            // Candidate mappings exist only behind the scoped test guard. The
            // dynamic check preserves the guard-loss fallback tests.
            qualification_authorizes_native_execution(self.report.qualification)
        }
        #[cfg(not(test))]
        {
            // Production construction retains a native mapping only after the
            // source-bound qualification atom authorizes it. No public API can
            // mutate either field afterward, so repeating the 32-byte atom
            // check on every search would add work without strengthening the
            // call boundary.
            debug_assert!(self.report.qualification.is_authorized());
            true
        }
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
        self.find_window_with_native(
            haystack,
            window,
            limits,
            None,
            || false,
            |matched, route, accounting| {
                (matched, QualifiedExactSearchExecution { route, accounting })
            },
        )
    }

    #[inline]
    fn find_window_with_native<R>(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        native: Option<&QualifiedExactSearchNativeThreadSession<'_>>,
        authorize_native: impl FnOnce() -> bool,
        project: impl FnOnce(Option<Match>, QualifiedExactSearchRoute, LiteralAccounting) -> R,
    ) -> Result<R, QualifiedExactSearchError> {
        let literal_limits = LiteralSearchLimits {
            max_linear_terms: usize::try_from(limits.max_work).unwrap_or(usize::MAX),
        };
        if let Some(native) = native
            && authorize_native()
            && let Some(checked_window) = NativeCheckedSearchWindow::new(
                haystack,
                NativeSearchWindow::new(window.start(), window.end()),
            )
        {
            // This is the single authoritative resource preflight for either
            // executor. Its private-field token binds this plan, haystack,
            // window, accounting, and limit result.
            let preflight = self
                .portable
                .preflight_checked_window(checked_window, literal_limits)?;
            if preflight.searched_bytes() >= self.report.workload.minimum_window_bytes() {
                let (matched, accounting) = native.search_preflighted(preflight)?;
                return Ok(project(
                    matched,
                    QualifiedExactSearchRoute::NativeJit,
                    accounting,
                ));
            }
            let accounting = preflight.accounting();
            let matched = preflight.find()?;
            return Ok(project(
                matched.map(|(start, end)| Match { start, end }),
                QualifiedExactSearchRoute::PortableLiteral,
                accounting,
            ));
        }
        let literal_window = LiteralWindow::new(window.start(), window.end());
        let (matched, portable_accounting) =
            self.portable
                .find_window(haystack, literal_window, literal_limits)?;
        Ok(project(
            matched.map(|(start, end)| Match { start, end }),
            QualifiedExactSearchRoute::PortableLiteral,
            portable_accounting,
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

/// Same-thread invocation token for one qualified exact-literal matcher.
///
/// The token borrows both semantic owners for its complete lifetime. Its
/// runtime session makes the value neither [`Send`] nor [`Sync`], including
/// when this particular matcher has no native mapping and executes portably.
/// Session calls do not repeat the fixed-VL host query. Changing VL on the
/// owning thread invalidates this token and requires a new one.
///
/// The current-thread contract is enforced by the type system:
///
/// ```compile_fail,E0277
/// use fre::QualifiedExactSearchThreadSession;
///
/// fn require_send<T: Send>() {}
/// require_send::<QualifiedExactSearchThreadSession<'static>>();
/// ```
///
/// ```compile_fail,E0277
/// use fre::QualifiedExactSearchThreadSession;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<QualifiedExactSearchThreadSession<'static>>();
/// ```
#[derive(Debug)]
pub struct QualifiedExactSearchThreadSession<'session> {
    search: &'session QualifiedExactSearch,
    native: Option<QualifiedExactSearchNativeThreadSession<'session>>,
}

impl QualifiedExactSearchThreadSession<'_> {
    /// Find the first match in the complete haystack.
    #[inline]
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, QualifiedExactSearchExecution), QualifiedExactSearchError> {
        self.find_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Find the first match wholly inside a checked byte window.
    #[inline]
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, QualifiedExactSearchExecution), QualifiedExactSearchError> {
        self.find_window_projected(haystack, window, limits, |matched, route, accounting| {
            (matched, QualifiedExactSearchExecution { route, accounting })
        })
    }

    /// Find the first match in the complete haystack without returning the
    /// per-search execution report.
    ///
    /// This is the value-only counterpart to [`Self::find`]. It uses the same
    /// authority gate, checked window, single resource preflight, minimum-window
    /// fallback, typed errors, and native-result validation. Only the final
    /// diagnostic projection is omitted.
    #[inline]
    pub fn find_value(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<Option<Match>, QualifiedExactSearchError> {
        self.find_window_value(haystack, SearchWindow::full(haystack), limits)
    }

    /// Find the first match wholly inside a checked byte window without
    /// returning the per-search execution report.
    ///
    /// This follows the same semantic and refusal path as
    /// [`Self::find_window`].
    #[inline]
    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, QualifiedExactSearchError> {
        self.find_window_projected(haystack, window, limits, |matched, _, _| matched)
    }

    /// Whether a selected match exists in the complete haystack.
    #[inline]
    pub fn is_match(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(bool, QualifiedExactSearchExecution), QualifiedExactSearchError> {
        self.find(haystack, limits)
            .map(|(matched, execution)| (matched.is_some(), execution))
    }

    /// Whether a selected match exists without returning the per-search
    /// execution report.
    ///
    /// This is the value-only counterpart to [`Self::is_match`] and preserves
    /// its semantic, authority, resource, fallback, and error contracts.
    #[inline]
    pub fn is_match_value(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<bool, QualifiedExactSearchError> {
        self.find_window_projected(
            haystack,
            SearchWindow::full(haystack),
            limits,
            |matched, _, _| matched.is_some(),
        )
    }

    #[inline]
    fn find_window_projected<R>(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        project: impl FnOnce(Option<Match>, QualifiedExactSearchRoute, LiteralAccounting) -> R,
    ) -> Result<R, QualifiedExactSearchError> {
        self.find_window_projected_authorized_by(
            haystack,
            window,
            limits,
            || self.search.retained_native_execution_authorized(),
            project,
        )
    }

    #[inline]
    fn find_window_projected_authorized_by<R>(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        authorize_native: impl FnOnce() -> bool,
        project: impl FnOnce(Option<Match>, QualifiedExactSearchRoute, LiteralAccounting) -> R,
    ) -> Result<R, QualifiedExactSearchError> {
        self.search.find_window_with_native(
            haystack,
            window,
            limits,
            self.native.as_ref(),
            authorize_native,
            project,
        )
    }
}

/// Semantic route selected by [`PortableBuilder::build_qualified_exact_search`].
///
/// `ExactLiteral` means the parsed regular expression proved to be one exact
/// byte string and therefore reached [`QualifiedExactSearch`]. Its per-call
/// executor is still reported separately as either portable or native.
/// `PortablePlan` means the normal facade selected another certified plan;
/// that plan is retained exactly and no JIT lowering is attempted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualifiedExactSearchFacadeSelection {
    ExactLiteral,
    PortablePlan(PlanKind),
}

/// Executor used by one search through the explicit facade integration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualifiedExactSearchFacadeRoute {
    /// The exact-literal leaf was selected; the nested route says whether its
    /// qualified native mapping or its portable semantic owner executed.
    ExactLiteral(QualifiedExactSearchRoute),
    /// A non-exact normal-facade plan executed without JIT reinterpretation.
    PortablePlan(PlanKind),
}

/// Per-search route and the normal facade's operation accounting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualifiedExactSearchFacadeExecution {
    pub route: QualifiedExactSearchFacadeRoute,
    pub accounting: SearchAccounting,
}

/// Construction failure from the explicit normal-facade JIT integration.
#[derive(Debug)]
#[non_exhaustive]
pub enum QualifiedExactSearchFacadeBuildError {
    /// Normal syntax, admission, planning, or portable construction failed.
    Portable(BuildError),
    /// An eligible exact plan failed bounded KIR or native-image construction.
    ExactLiteral(QualifiedExactSearchBuildError),
}

impl fmt::Display for QualifiedExactSearchFacadeBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Portable(error) => {
                write!(formatter, "portable facade construction failed: {error}")
            }
            Self::ExactLiteral(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for QualifiedExactSearchFacadeBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Portable(error) => Some(error),
            Self::ExactLiteral(error) => Some(error),
        }
    }
}

impl From<BuildError> for QualifiedExactSearchFacadeBuildError {
    fn from(value: BuildError) -> Self {
        Self::Portable(value)
    }
}

impl From<QualifiedExactSearchBuildError> for QualifiedExactSearchFacadeBuildError {
    fn from(value: QualifiedExactSearchBuildError) -> Self {
        Self::ExactLiteral(value)
    }
}

/// Search failure from the selected explicit facade route.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QualifiedExactSearchFacadeError {
    /// The retained normal-facade plan refused the search.
    Portable(SearchError),
    /// The exact-literal leaf refused preflight or returned a native call fault.
    ExactLiteral(QualifiedExactSearchError),
}

impl fmt::Display for QualifiedExactSearchFacadeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Portable(error) => write!(formatter, "portable facade search failed: {error}"),
            Self::ExactLiteral(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for QualifiedExactSearchFacadeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Portable(error) => Some(error),
            Self::ExactLiteral(error) => Some(error),
        }
    }
}

impl From<SearchError> for QualifiedExactSearchFacadeError {
    fn from(value: SearchError) -> Self {
        Self::Portable(value)
    }
}

impl From<QualifiedExactSearchError> for QualifiedExactSearchFacadeError {
    fn from(value: QualifiedExactSearchError) -> Self {
        Self::ExactLiteral(value)
    }
}

#[derive(Debug)]
struct ExactFacadePlan {
    source: Box<str>,
    capture_names: Box<[Option<Box<str>>]>,
    profile: CompatibilityProfile,
    portable_report: BuildReport,
    search: QualifiedExactSearch,
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "the opt-in facade retains either semantic owner inline and does not add an unaccounted box allocation"
)]
enum QualifiedExactSearchFacadePlan {
    ExactLiteral(ExactFacadePlan),
    Portable(PortableRegex),
}

/// Explicit search-only normal-facade integration for the qualified JIT leaf.
///
/// Construction first runs [`PortableBuilder::build`] in full. If and only if
/// that exact profile and source select [`PlanKind::ExactLiteral`], ownership
/// of the already-built literal plan moves into [`QualifiedExactSearch`].
/// Every other admitted pattern retains its original [`PortableRegex`] plan.
/// Invalid or unsupported syntax remains a typed portable build error.
///
/// This type does not alter [`PortableBuilder::build`] or [`PortableRegex`].
/// The native route additionally remains sealed by the exact selected
/// backend's [`QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION`],
/// [`QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION`],
/// [`QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_QUALIFICATION`], or
/// [`QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION`] atom, the 16-byte
/// width, the declared large-window reuse envelope, host support, bounded
/// custom `AArch64` emission, independent image audit, and strict-W^X
/// publication. The custom emitter has no LLVM dependency. When no
/// selected-backend atom is authorized, construction builds an observable
/// portable fallback and performs no host probe or native work. Automatic
/// construction prefers admitted tag 21, then tag 10, tag 19, and V8; every
/// fallback must carry its own independent authorization. Fallback applies
/// only to construction-time host admission. Emission, audit, resource, and
/// publication failures remain typed failures for the selected backend and are
/// never masked by rebuilding a different backend.
///
/// All generated-code calls require [`Self::begin_current_thread_session`].
/// Sessionless calls use the retained portable owner. V8 session construction
/// performs no SVE syscall; ABI2 tag19/tag21 check VL16 once there, while
/// legacy tag10 retains its sealed fixed-VL session contract.
#[derive(Debug)]
pub struct QualifiedExactSearchFacade {
    plan: QualifiedExactSearchFacadePlan,
}

#[derive(Debug)]
enum QualifiedExactSearchFacadeThreadSessionPlan<'session> {
    ExactLiteral(QualifiedExactSearchThreadSession<'session>),
    Portable(&'session PortableRegex),
}

/// Same-thread invocation token for the explicit qualified-search facade.
///
/// Exact-literal plans use [`QualifiedExactSearchThreadSession`]. Every other
/// normal-facade plan remains portable, while the enclosing token preserves
/// the same neither-[`Send`]-nor-[`Sync`] lifecycle on every route.
///
/// ```compile_fail,E0277
/// use fre::QualifiedExactSearchFacadeThreadSession;
///
/// fn require_send<T: Send>() {}
/// require_send::<QualifiedExactSearchFacadeThreadSession<'static>>();
/// ```
///
/// ```compile_fail,E0277
/// use fre::QualifiedExactSearchFacadeThreadSession;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<QualifiedExactSearchFacadeThreadSession<'static>>();
/// ```
#[derive(Debug)]
pub struct QualifiedExactSearchFacadeThreadSession<'session> {
    plan: QualifiedExactSearchFacadeThreadSessionPlan<'session>,
}

#[cfg(test)]
#[derive(Debug)]
enum QualificationSessionAuthority<'session> {
    Candidate {
        _permit: &'session QualificationCandidateExecutionPermit,
    },
    Qualified,
}

/// Qualification-only facade session whose authority is sealed once.
///
/// Candidate sessions borrow their thread-bound RAII permit, preventing guard
/// retirement while the session exists. Only the test-only authority lookup
/// is hoisted: every timed call retains the production facade projection,
/// checked-window and work-limit preflight, minimum-window fallback, plan
/// identity check, native invocation, and result validation.
#[cfg(test)]
#[derive(Debug)]
struct QualifiedExactSearchFacadeQualificationThreadSession<'session> {
    session: QualifiedExactSearchFacadeThreadSession<'session>,
    authority: QualificationSessionAuthority<'session>,
}

impl PortableBuilder {
    /// Build the normal portable facade plus the explicit qualified exact JIT
    /// strategy using production component limits.
    ///
    /// This is the opt-in deployment boundary. The default [`Self::build`]
    /// remains unchanged.
    pub fn build_qualified_exact_search(
        self,
        workload: QualifiedExactSearchWorkload,
    ) -> Result<QualifiedExactSearchFacade, QualifiedExactSearchFacadeBuildError> {
        self.build_qualified_exact_search_automatic_with_limits(
            workload,
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits::default(),
        )
    }

    /// Build the explicit exact JIT strategy with a selected backend policy.
    ///
    /// V8, tags 19 and 21, and SVE2-fixed16 tag 10 consult only their exact
    /// backend-keyed atoms. Legacy V7 and SVE16 V1 remain hard Candidate
    /// policies and cannot inherit any other backend's atom.
    pub fn build_qualified_exact_search_with_backend(
        self,
        workload: QualifiedExactSearchWorkload,
        backend_policy: QualifiedExactSearchBackendPolicy,
    ) -> Result<QualifiedExactSearchFacade, QualifiedExactSearchFacadeBuildError> {
        self.build_qualified_exact_search_with_backend_and_limits(
            workload,
            backend_policy,
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits::default(),
        )
    }

    /// Build the explicit qualified exact JIT strategy under bounded native
    /// validation, emission, and publication policies.
    pub fn build_qualified_exact_search_with_limits(
        self,
        workload: QualifiedExactSearchWorkload,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
    ) -> Result<QualifiedExactSearchFacade, QualifiedExactSearchFacadeBuildError> {
        self.build_qualified_exact_search_automatic_with_limits(
            workload,
            validation_limits,
            emission_limits,
            publication_limits,
        )
    }

    fn build_qualified_exact_search_automatic_with_limits(
        self,
        workload: QualifiedExactSearchWorkload,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
    ) -> Result<QualifiedExactSearchFacade, QualifiedExactSearchFacadeBuildError> {
        QualifiedExactSearchFacade::from_builder_with_automatic_qualification(
            self,
            workload,
            validation_limits,
            emission_limits,
            publication_limits,
        )
    }

    /// Build the explicit exact JIT strategy with selected backend and bounded
    /// validation, emission, and publication policies.
    pub fn build_qualified_exact_search_with_backend_and_limits(
        self,
        workload: QualifiedExactSearchWorkload,
        backend_policy: QualifiedExactSearchBackendPolicy,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
    ) -> Result<QualifiedExactSearchFacade, QualifiedExactSearchFacadeBuildError> {
        let qualification = qualification_for_backend(backend_policy);
        QualifiedExactSearchFacade::from_builder_with_backend_and_qualification(
            self,
            workload,
            backend_policy,
            validation_limits,
            emission_limits,
            publication_limits,
            qualification,
        )
    }
}

impl QualifiedExactSearchFacade {
    fn from_builder_with_automatic_qualification(
        builder: PortableBuilder,
        workload: QualifiedExactSearchWorkload,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
    ) -> Result<Self, QualifiedExactSearchFacadeBuildError> {
        Self::from_builder_with_automatic_qualification_from(
            builder,
            workload,
            validation_limits,
            emission_limits,
            publication_limits,
            QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION,
            QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION,
            QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_QUALIFICATION,
            QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION,
            || {
                native_selected_end_register_backend_support_v2(
                    SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
                )
            },
            || {
                native_search_backend_support(
                    QualifiedExactSearchBackendPolicy::Sve2Fixed16.backend_version(),
                )
            },
            || {
                native_selected_end_register_backend_support_v2(
                    SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16,
                )
            },
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the internal facade qualification driver keeps four backend authorities and three construction-time fixed-lane host proofs explicit"
    )]
    fn from_builder_with_automatic_qualification_from(
        builder: PortableBuilder,
        workload: QualifiedExactSearchWorkload,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
        asimd_v8: QualifiedExactSearchQualification,
        sve16_v6: QualifiedExactSearchQualification,
        sve2_fixed16: QualifiedExactSearchQualification,
        sve2_fixed16_v2: QualifiedExactSearchQualification,
        probe_sve2_fixed16_v2: impl FnOnce() -> Result<(), PublishError>,
        probe_sve2_fixed16: impl FnOnce() -> Result<(), PublishError>,
        probe_sve16_v6: impl FnOnce() -> Result<(), PublishError>,
    ) -> Result<Self, QualifiedExactSearchFacadeBuildError> {
        let portable = builder.build()?;
        let PortableRegex {
            source,
            capture_names,
            plan,
            profile,
            limits,
            selection,
            report,
        } = portable;
        let plan = match plan {
            PortablePlan::ExactLiteral(literal) => {
                let search = QualifiedExactSearch::with_portable_plan_automatic_qualification_from(
                    literal,
                    workload,
                    validation_limits,
                    emission_limits,
                    publication_limits,
                    asimd_v8,
                    sve16_v6,
                    sve2_fixed16,
                    sve2_fixed16_v2,
                    probe_sve2_fixed16_v2,
                    probe_sve2_fixed16,
                    probe_sve16_v6,
                )?;
                QualifiedExactSearchFacadePlan::ExactLiteral(ExactFacadePlan {
                    source,
                    capture_names,
                    profile,
                    portable_report: report,
                    search,
                })
            }
            plan => QualifiedExactSearchFacadePlan::Portable(PortableRegex {
                source,
                capture_names,
                plan,
                profile,
                limits,
                selection,
                report,
            }),
        };
        Ok(Self { plan })
    }

    #[cfg(test)]
    fn from_builder_with_qualification(
        builder: PortableBuilder,
        workload: QualifiedExactSearchWorkload,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
        qualification: QualifiedExactSearchQualification,
    ) -> Result<Self, QualifiedExactSearchFacadeBuildError> {
        Self::from_builder_with_backend_and_qualification(
            builder,
            workload,
            QualifiedExactSearchBackendPolicy::CURRENT,
            validation_limits,
            emission_limits,
            publication_limits,
            qualification,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the internal facade handoff keeps backend identity, bounded policies, and source-final qualification explicit"
    )]
    fn from_builder_with_backend_and_qualification(
        builder: PortableBuilder,
        workload: QualifiedExactSearchWorkload,
        backend_policy: QualifiedExactSearchBackendPolicy,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
        qualification: QualifiedExactSearchQualification,
    ) -> Result<Self, QualifiedExactSearchFacadeBuildError> {
        Self::from_builder_with_backend_qualification_and_cache(
            builder,
            workload,
            backend_policy,
            validation_limits,
            emission_limits,
            publication_limits,
            qualification,
            None,
        )
    }

    #[cfg(test)]
    #[allow(
        clippy::too_many_arguments,
        reason = "the qualification harness must bind one fresh cache to the exact backend, bounded policies, and qualification subject"
    )]
    fn from_builder_with_fresh_cache_for_qualification(
        builder: PortableBuilder,
        workload: QualifiedExactSearchWorkload,
        backend_policy: QualifiedExactSearchBackendPolicy,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
        qualification: QualifiedExactSearchQualification,
        cache: &SelectedEndRegisterCacheV2,
    ) -> Result<Self, QualifiedExactSearchFacadeBuildError> {
        Self::from_builder_with_backend_qualification_and_cache(
            builder,
            workload,
            backend_policy,
            validation_limits,
            emission_limits,
            publication_limits,
            qualification,
            Some(cache),
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the internal facade handoff keeps backend identity, bounded policies, source-final qualification, and the optional construction-only cache explicit"
    )]
    fn from_builder_with_backend_qualification_and_cache(
        builder: PortableBuilder,
        workload: QualifiedExactSearchWorkload,
        backend_policy: QualifiedExactSearchBackendPolicy,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
        publication_limits: PublicationLimits,
        qualification: QualifiedExactSearchQualification,
        cache: Option<&SelectedEndRegisterCacheV2>,
    ) -> Result<Self, QualifiedExactSearchFacadeBuildError> {
        let portable = builder.build()?;
        let PortableRegex {
            source,
            capture_names,
            plan,
            profile,
            limits,
            selection,
            report,
        } = portable;
        let plan = match plan {
            PortablePlan::ExactLiteral(literal) => {
                let search =
                    QualifiedExactSearch::with_portable_plan_backend_qualification_and_cache(
                        literal,
                        workload,
                        backend_policy,
                        validation_limits,
                        emission_limits,
                        publication_limits,
                        qualification,
                        None,
                        cache,
                    )?;
                QualifiedExactSearchFacadePlan::ExactLiteral(ExactFacadePlan {
                    source,
                    capture_names,
                    profile,
                    portable_report: report,
                    search,
                })
            }
            plan => QualifiedExactSearchFacadePlan::Portable(PortableRegex {
                source,
                capture_names,
                plan,
                profile,
                limits,
                selection,
                report,
            }),
        };
        Ok(Self { plan })
    }

    /// Return the original regular-expression source without normalization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.plan {
            QualifiedExactSearchFacadePlan::ExactLiteral(exact) => &exact.source,
            QualifiedExactSearchFacadePlan::Portable(portable) => portable.as_str(),
        }
    }

    /// Return the exact compatibility profile used for syntax admission.
    #[must_use]
    pub const fn profile(&self) -> &CompatibilityProfile {
        match &self.plan {
            QualifiedExactSearchFacadePlan::ExactLiteral(exact) => &exact.profile,
            QualifiedExactSearchFacadePlan::Portable(portable) => portable.profile(),
        }
    }

    /// Return normal-facade syntax, admission, planner, and storage provenance.
    #[must_use]
    pub const fn portable_build_report(&self) -> &BuildReport {
        match &self.plan {
            QualifiedExactSearchFacadePlan::ExactLiteral(exact) => &exact.portable_report,
            QualifiedExactSearchFacadePlan::Portable(portable) => portable.build_report(),
        }
    }

    /// Return the semantic plan selected before any native eligibility check.
    #[must_use]
    pub const fn selection(&self) -> QualifiedExactSearchFacadeSelection {
        match &self.plan {
            QualifiedExactSearchFacadePlan::ExactLiteral(_) => {
                QualifiedExactSearchFacadeSelection::ExactLiteral
            }
            QualifiedExactSearchFacadePlan::Portable(portable) => {
                QualifiedExactSearchFacadeSelection::PortablePlan(portable.build_report().plan)
            }
        }
    }

    /// Return qualified-leaf publication and artifact provenance when the
    /// parsed regular expression selected the exact-literal semantic plan.
    #[must_use]
    pub const fn qualified_build_report(&self) -> Option<&QualifiedExactSearchBuildReport> {
        match &self.plan {
            QualifiedExactSearchFacadePlan::ExactLiteral(exact) => {
                Some(exact.search.build_report())
            }
            QualifiedExactSearchFacadePlan::Portable(_) => None,
        }
    }

    /// Iterate over retained capture names in opening-parenthesis order.
    #[must_use]
    pub fn capture_names(&self) -> PortableCaptureNames<'_> {
        match &self.plan {
            QualifiedExactSearchFacadePlan::ExactLiteral(exact) => PortableCaptureNames {
                names: exact.capture_names.iter(),
            },
            QualifiedExactSearchFacadePlan::Portable(portable) => portable.capture_names(),
        }
    }

    /// Return the number of capture slots, including group zero.
    #[must_use]
    pub const fn captures_len(&self) -> usize {
        self.portable_build_report().captures_len
    }

    /// Establish one same-thread session for repeated facade calls.
    ///
    /// Exact fixed-VL native plans check the calling thread's SVE vector
    /// length once here. V8 creates its required native session without an SVE
    /// host query. Portable and non-native plans create a portable session
    /// without a host query. A typed error performs no search and is never
    /// converted into an implicit portable retry.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<QualifiedExactSearchFacadeThreadSession<'_>, QualifiedExactSearchThreadContractError>
    {
        self.begin_current_thread_session_authorized_by(|search| {
            search.retained_native_execution_authorized()
        })
    }

    #[inline]
    fn begin_current_thread_session_authorized_by(
        &self,
        authorize_exact: impl FnOnce(&QualifiedExactSearch) -> bool,
    ) -> Result<QualifiedExactSearchFacadeThreadSession<'_>, QualifiedExactSearchThreadContractError>
    {
        let plan = match &self.plan {
            QualifiedExactSearchFacadePlan::ExactLiteral(exact) => {
                QualifiedExactSearchFacadeThreadSessionPlan::ExactLiteral(
                    exact
                        .search
                        .begin_current_thread_session_authorized_by(|| {
                            authorize_exact(&exact.search)
                        })?,
                )
            }
            QualifiedExactSearchFacadePlan::Portable(portable) => {
                QualifiedExactSearchFacadeThreadSessionPlan::Portable(portable)
            }
        };
        Ok(QualifiedExactSearchFacadeThreadSession { plan })
    }

    #[cfg(test)]
    fn begin_current_thread_session_for_qualification<'session>(
        &'session self,
        candidate_permit: Option<&'session QualificationCandidateExecutionPermit>,
    ) -> Result<
        QualifiedExactSearchFacadeQualificationThreadSession<'session>,
        QualifiedExactSearchThreadContractError,
    > {
        let qualification = self
            .qualified_build_report()
            .expect("qualification session requires an exact-literal facade")
            .qualification;
        let authority = match qualification {
            QualifiedExactSearchQualification::Candidate => {
                let permit =
                    candidate_permit.expect("Candidate qualification session requires its permit");
                permit.assert_active();
                QualificationSessionAuthority::Candidate { _permit: permit }
            }
            qualified if qualified.is_authorized() => {
                assert!(
                    candidate_permit.is_none(),
                    "production-qualified session must not borrow a Candidate permit"
                );
                QualificationSessionAuthority::Qualified
            }
            _ => panic!("qualification session requires valid source-bound authority"),
        };
        let session = self.begin_current_thread_session_authorized_by(|_| true)?;
        Ok(QualifiedExactSearchFacadeQualificationThreadSession { session, authority })
    }

    /// Find the first match in the complete haystack.
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, QualifiedExactSearchFacadeExecution), QualifiedExactSearchFacadeError>
    {
        self.find_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Find the first match at or after a checked start offset.
    pub fn find_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, QualifiedExactSearchFacadeExecution), QualifiedExactSearchFacadeError>
    {
        self.find_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Find the first match wholly inside a checked byte window.
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, QualifiedExactSearchFacadeExecution), QualifiedExactSearchFacadeError>
    {
        match &self.plan {
            QualifiedExactSearchFacadePlan::ExactLiteral(exact) => {
                let (matched, execution) = exact.search.find_window(haystack, window, limits)?;
                Ok((
                    matched,
                    QualifiedExactSearchFacadeExecution {
                        route: QualifiedExactSearchFacadeRoute::ExactLiteral(execution.route),
                        accounting: SearchAccounting::ExactLiteral(execution.accounting),
                    },
                ))
            }
            QualifiedExactSearchFacadePlan::Portable(portable) => {
                let (matched, accounting) = portable.find_window(haystack, window, limits)?;
                Ok((
                    matched,
                    QualifiedExactSearchFacadeExecution {
                        route: QualifiedExactSearchFacadeRoute::PortablePlan(accounting.plan()),
                        accounting,
                    },
                ))
            }
        }
    }

    /// Return the first match while retaining the original haystack.
    pub fn find_borrowed<'h>(
        &self,
        haystack: &'h [u8],
        limits: SearchLimits,
    ) -> Result<
        (Option<ByteMatch<'h>>, QualifiedExactSearchFacadeExecution),
        QualifiedExactSearchFacadeError,
    > {
        let (matched, execution) = self.find(haystack, limits)?;
        Ok((matched.map(|span| ByteMatch { haystack, span }), execution))
    }

    /// Whether a selected match exists in the complete haystack.
    pub fn is_match(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(bool, QualifiedExactSearchFacadeExecution), QualifiedExactSearchFacadeError> {
        self.find(haystack, limits)
            .map(|(matched, execution)| (matched.is_some(), execution))
    }
}

impl QualifiedExactSearchFacadeThreadSession<'_> {
    /// Find the first match in the complete haystack.
    #[inline]
    pub fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, QualifiedExactSearchFacadeExecution), QualifiedExactSearchFacadeError>
    {
        self.find_window(haystack, SearchWindow::full(haystack), limits)
    }

    /// Find the first match at or after a checked start offset.
    #[inline]
    pub fn find_at(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, QualifiedExactSearchFacadeExecution), QualifiedExactSearchFacadeError>
    {
        self.find_window(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Find the first match wholly inside a checked byte window.
    #[inline]
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<(Option<Match>, QualifiedExactSearchFacadeExecution), QualifiedExactSearchFacadeError>
    {
        self.find_window_projected(
            haystack,
            window,
            limits,
            |matched, route, accounting| {
                (
                    matched,
                    QualifiedExactSearchFacadeExecution {
                        route: QualifiedExactSearchFacadeRoute::ExactLiteral(route),
                        accounting: SearchAccounting::ExactLiteral(accounting),
                    },
                )
            },
            |matched, accounting| {
                (
                    matched,
                    QualifiedExactSearchFacadeExecution {
                        route: QualifiedExactSearchFacadeRoute::PortablePlan(accounting.plan()),
                        accounting,
                    },
                )
            },
        )
    }

    /// Find the first match in the complete haystack without returning the
    /// per-search facade execution report.
    ///
    /// This is the value-only counterpart to [`Self::find`]. It preserves the
    /// selected facade plan and the exact leaf's authority, single-preflight,
    /// fallback, validation, and typed-error contracts.
    #[inline]
    pub fn find_value(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<Option<Match>, QualifiedExactSearchFacadeError> {
        self.find_window_value(haystack, SearchWindow::full(haystack), limits)
    }

    /// Find the first match at or after a checked start offset without
    /// returning the per-search facade execution report.
    #[inline]
    pub fn find_at_value(
        &self,
        haystack: &[u8],
        start: usize,
        limits: SearchLimits,
    ) -> Result<Option<Match>, QualifiedExactSearchFacadeError> {
        self.find_window_value(haystack, SearchWindow::new(start, haystack.len()), limits)
    }

    /// Find the first match wholly inside a checked byte window without
    /// returning the per-search facade execution report.
    ///
    /// This follows the same semantic and refusal path as
    /// [`Self::find_window`].
    #[inline]
    pub fn find_window_value(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
    ) -> Result<Option<Match>, QualifiedExactSearchFacadeError> {
        self.find_window_projected(
            haystack,
            window,
            limits,
            |matched, _, _| matched,
            |matched, _| matched,
        )
    }

    #[inline]
    fn find_window_projected<R>(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        exact_project: impl FnOnce(Option<Match>, QualifiedExactSearchRoute, LiteralAccounting) -> R,
        portable_project: impl FnOnce(Option<Match>, SearchAccounting) -> R,
    ) -> Result<R, QualifiedExactSearchFacadeError> {
        self.find_window_projected_authorized_by(
            haystack,
            window,
            limits,
            |search| search.search.retained_native_execution_authorized(),
            exact_project,
            portable_project,
        )
    }

    #[inline]
    fn find_window_projected_authorized_by<R>(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: SearchLimits,
        authorize_exact: impl FnOnce(&QualifiedExactSearchThreadSession<'_>) -> bool,
        exact_project: impl FnOnce(Option<Match>, QualifiedExactSearchRoute, LiteralAccounting) -> R,
        portable_project: impl FnOnce(Option<Match>, SearchAccounting) -> R,
    ) -> Result<R, QualifiedExactSearchFacadeError> {
        match &self.plan {
            QualifiedExactSearchFacadeThreadSessionPlan::ExactLiteral(search) => search
                .find_window_projected_authorized_by(
                    haystack,
                    window,
                    limits,
                    || authorize_exact(search),
                    exact_project,
                )
                .map_err(QualifiedExactSearchFacadeError::from),
            QualifiedExactSearchFacadeThreadSessionPlan::Portable(portable) => {
                let (matched, accounting) = portable.find_window(haystack, window, limits)?;
                Ok(portable_project(matched, accounting))
            }
        }
    }

    /// Return the first match while retaining the original haystack.
    #[inline]
    pub fn find_borrowed<'h>(
        &self,
        haystack: &'h [u8],
        limits: SearchLimits,
    ) -> Result<
        (Option<ByteMatch<'h>>, QualifiedExactSearchFacadeExecution),
        QualifiedExactSearchFacadeError,
    > {
        let (matched, execution) = self.find(haystack, limits)?;
        Ok((matched.map(|span| ByteMatch { haystack, span }), execution))
    }

    /// Whether a selected match exists in the complete haystack.
    #[inline]
    pub fn is_match(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(bool, QualifiedExactSearchFacadeExecution), QualifiedExactSearchFacadeError> {
        self.find(haystack, limits)
            .map(|(matched, execution)| (matched.is_some(), execution))
    }

    /// Whether a selected match exists without returning the per-search facade
    /// execution report.
    ///
    /// This is the value-only counterpart to [`Self::is_match`] and preserves
    /// its semantic, authority, resource, fallback, and error contracts.
    #[inline]
    pub fn is_match_value(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<bool, QualifiedExactSearchFacadeError> {
        self.find_window_projected(
            haystack,
            SearchWindow::full(haystack),
            limits,
            |matched, _, _| matched.is_some(),
            |matched, _| matched.is_some(),
        )
    }
}

#[cfg(test)]
impl QualifiedExactSearchFacadeQualificationThreadSession<'_> {
    /// Exercise the normal reporting path outside qualification timers.
    fn find(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<(Option<Match>, QualifiedExactSearchFacadeExecution), QualifiedExactSearchFacadeError>
    {
        self.session.find(haystack, limits)
    }

    /// Return only the semantic match through the authority-hoisted
    /// qualification boundary.
    #[inline]
    fn find_value(
        &self,
        haystack: &[u8],
        limits: SearchLimits,
    ) -> Result<Option<Match>, QualifiedExactSearchFacadeError> {
        let _authority = &self.authority;
        self.session.find_window_projected_authorized_by(
            haystack,
            SearchWindow::full(haystack),
            limits,
            |_| true,
            |matched, _, _| matched,
            |matched, _| matched,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod bridge_qualification {
        include!("qualified_exact_search_bridge_qualification.rs");
    }

    mod tag21_facade_qualification {
        include!("qualified_exact_search_tag21_facade_qualification.rs");
    }

    const TEST_QUALIFICATION: QualifiedExactSearchQualification =
        QualifiedExactSearchQualification::Candidate;

    #[test]
    fn backend_abi_selection_is_closed() {
        assert_eq!(
            selected_end_register_backend_v2(QualifiedExactSearchBackendPolicy::AsimdV8),
            Some(SelectedEndRegisterBackendV2::AsimdV8)
        );
        assert_eq!(
            selected_end_register_backend_v2(QualifiedExactSearchBackendPolicy::Sve2Fixed16V2),
            Some(SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16)
        );
        assert_eq!(
            selected_end_register_backend_v2(QualifiedExactSearchBackendPolicy::Sve16V6),
            Some(SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16)
        );
        assert_eq!(
            selected_end_register_backend_v2(QualifiedExactSearchBackendPolicy::Sve2Fixed16),
            None
        );
        assert!(legacy_selected_end_v1_backend(
            QualifiedExactSearchBackendPolicy::Sve2Fixed16
        ));
        for policy in [
            QualifiedExactSearchBackendPolicy::AsimdV7,
            QualifiedExactSearchBackendPolicy::AsimdV9,
            QualifiedExactSearchBackendPolicy::AsimdV10,
            QualifiedExactSearchBackendPolicy::AsimdV11,
            QualifiedExactSearchBackendPolicy::Sve16,
        ] {
            assert_eq!(selected_end_register_backend_v2(policy), None);
            assert!(!legacy_selected_end_v1_backend(policy));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one source seal keeps cache ownership, gate ordering, session-only ABI2 invocation, and the authoritative-preflight handoff together"
    )]
    fn public_native_abi2_and_single_preflight_boundaries_are_source_sealed() {
        fn position(source: &str, marker: &str) -> usize {
            source
                .find(marker)
                .unwrap_or_else(|| panic!("missing public ABI2 source marker: {marker}"))
        }

        let source = include_str!("qualified_exact_search.rs");
        let owner_start = position(source, "enum QualifiedExactSearchNative {");
        let owner_end = owner_start
            + position(
                &source[owner_start..],
                "\nimpl QualifiedExactSearchNative {",
            );
        let owner = &source[owner_start..owner_end];
        assert!(owner.contains("LegacyV1(PublishedKernel<NativeSelectedEnd>)"));
        assert!(owner.contains("RegisterV2(QualifiedExactSearchRegisterV2Owner)"));
        assert!(owner.contains("Owned(PublishedSelectedEndRegisterV2)"));
        assert!(owner.contains("Cached(SelectedEndRegisterLeaseV2)"));
        assert!(owner.contains("Self::Cached(lease) => lease.kernel()"));

        let session_start = position(
            source,
            "enum QualifiedExactSearchNativeThreadSession<'kernel> {",
        );
        let session_end = session_start
            + position(
                &source[session_start..],
                "\nimpl QualifiedExactSearchNativeThreadSession<'_> {",
            );
        let session = &source[session_start..session_end];
        assert!(session.contains("PublishedKernelThreadSession<'kernel, NativeSelectedEnd>"));
        assert!(session.contains("PublishedSelectedEndRegisterPlanThreadSessionV2<'kernel>"));

        let native_session_start = position(source, "\nimpl QualifiedExactSearchNative {");
        let native_session_end = native_session_start
            + position(
                &source[native_session_start..],
                "\n#[derive(Debug)]\nenum QualifiedExactSearchNativeThreadSession",
            );
        let native_session = &source[native_session_start..native_session_end];
        assert!(
            native_session.contains(".begin_current_thread_session_for_literal_plan(literal_plan)")
        );
        assert!(native_session.contains(".kernel()"));

        let construction_start = position(
            source,
            "    fn with_portable_plan_backend_and_qualification(",
        );
        let construction_end = construction_start
            + position(
                &source[construction_start..],
                "\n    /// The exact literal retained by the portable semantic owner.",
            );
        let construction = &source[construction_start..construction_end];
        assert!(construction.contains("emit_selected_end_register_v2("));
        assert!(construction.contains("publish_selected_end_register_v2("));
        assert!(construction.contains("emit_audited_with_backend("));
        assert!(construction.contains("publish_audited::<NativeSelectedEnd>("));
        assert!(construction.contains("QualifiedExactSearchRegisterV2Owner::Cached(lease)"));
        assert!(construction.contains("QualifiedExactSearchRegisterV2Owner::Owned(kernel)"));
        let literal_gate = position(construction, "literal_bytes !=");
        let workload_gate = position(construction, "!workload.is_qualified()");
        let qualification_gate = position(
            construction,
            "!qualification_authorizes_native_execution(qualification)",
        );
        let host_gate = position(
            construction,
            "qualified_exact_search_backend_support(backend_policy)",
        );
        let cache_lookup = position(construction, "cache.get_or_compile_exact_literal(");
        let direct_kernel_ir = position(
            construction,
            "let program = build_exact_literal::<NativeSelectedEnd>(",
        );
        assert!(literal_gate < workload_gate);
        assert!(workload_gate < qualification_gate);
        assert!(qualification_gate < host_gate);
        assert!(host_gate < cache_lookup);
        assert!(cache_lookup < direct_kernel_ir);

        let sessionless_start = position(
            source,
            "    pub fn find_window(\n        &self,\n        haystack: &[u8],",
        );
        let sessionless_end = sessionless_start
            + position(
                &source[sessionless_start..],
                "\n    #[inline]\n    fn find_window_with_native<R>(",
            );
        let sessionless = &source[sessionless_start..sessionless_end];
        assert!(sessionless.contains("self.find_window_with_native("));
        assert!(sessionless.contains("\n            None,"));
        assert!(sessionless.contains("\n            || false,"));
        assert!(!sessionless.contains("self.native"));

        let call_start = position(source, "    fn find_window_with_native<R>(");
        let call_end = call_start
            + position(
                &source[call_start..],
                "\n    /// Whether a selected match exists in the complete haystack.",
            );
        let call = &source[call_start..call_end];
        assert_eq!(call.matches(".preflight_checked_window(").count(), 1);
        assert!(call.contains("authorize_native: impl FnOnce() -> bool"));
        assert!(call.contains("&& authorize_native()"));
        assert!(call.contains("native.search_preflighted(preflight)?"));
        assert!(!call.contains("preflight_literal_window("));
        assert!(!call.contains("retained_native_execution_authorized"));

        let invocation_start =
            position(source, "impl QualifiedExactSearchNativeThreadSession<'_> {");
        let invocation_end = invocation_start
            + position(
                &source[invocation_start..],
                "\n#[inline]\nfn retained_native_if_authorized",
            );
        let invocation = &source[invocation_start..invocation_end];
        assert!(invocation.contains("Self::RegisterV2(native)"));
        assert!(invocation.contains("native.search_preflighted(preflight)?"));
        assert!(invocation.contains("Self::LegacyV1(native)"));
        assert!(invocation.contains("match_from_legacy_native_selected_end(end, decode_window)"));

        let public_session_start = position(
            source,
            "    pub fn begin_current_thread_session(\n        &self,",
        );
        let public_session_end = public_session_start
            + position(
                &source[public_session_start..],
                "\n    #[inline]\n    fn retained_native_execution_authorized",
            );
        let public_session = &source[public_session_start..public_session_end];
        assert!(public_session.contains("self.begin_current_thread_session_authorized_by(|| {"));
        assert!(public_session.contains("self.retained_native_execution_authorized()"));
        assert!(public_session.contains("authorize_native: impl FnOnce() -> bool"));
        assert!(public_session.contains("native.begin_current_thread_session(&self.portable)"));

        let projected_start = position(source, "impl QualifiedExactSearchThreadSession<'_> {");
        let projected_end = projected_start
            + position(
                &source[projected_start..],
                "\n/// Semantic route selected by",
            );
        let projected = &source[projected_start..projected_end];
        assert!(projected.contains("fn find_window_projected_authorized_by<R>("));
        assert!(projected.contains("|| self.search.retained_native_execution_authorized(),"));
        assert_eq!(
            projected
                .matches("self.search.find_window_with_native(")
                .count(),
            1
        );

        let permit_start = position(source, "struct QualificationCandidateExecutionPermit {");
        let permit_end = permit_start
            + position(
                &source[permit_start..],
                "\nfn qualification_authorizes_native_execution(",
            );
        let permit = &source[permit_start..permit_end];
        assert!(permit.contains("PhantomData<std::rc::Rc<()>>"));
        assert!(permit.contains("impl Drop for QualificationCandidateExecutionPermit"));
        assert!(permit.contains("TEST_CANDIDATE_EXECUTION.with("));

        let authority_start = position(source, "enum QualificationSessionAuthority<'session> {");
        let authority_end = authority_start
            + position(
                &source[authority_start..],
                "\n/// Qualification-only facade session",
            );
        let authority = &source[authority_start..authority_end];
        assert!(authority.contains("_permit: &'session QualificationCandidateExecutionPermit"));

        let qualification_session_start = position(
            source,
            "struct QualifiedExactSearchFacadeQualificationThreadSession<'session>",
        );
        let qualification_session_end = qualification_session_start
            + position(
                &source[qualification_session_start..],
                "\nimpl PortableBuilder {",
            );
        let qualification_session = &source[qualification_session_start..qualification_session_end];
        assert!(
            qualification_session.contains("authority: QualificationSessionAuthority<'session>")
        );
    }

    #[test]
    fn absent_retained_native_does_not_consult_session_authorization() {
        let consulted = Cell::new(false);
        let retained = retained_native_if_authorized::<u8>(None, || {
            consulted.set(true);
            true
        });
        assert_eq!(retained, None);
        assert!(!consulted.get());

        assert_eq!(retained_native_if_authorized(Some(7_u8), || false), None);
        assert_eq!(retained_native_if_authorized(Some(7_u8), || true), Some(7));
    }

    #[test]
    fn selected_end_reconstructs_the_fixed_width_span_and_rejects_underflow() {
        let offset_window = NativeSearchWindow::new(32, 128);
        assert_eq!(
            match_from_legacy_native_selected_end(48, offset_window)
                .expect("exact fixed-width span"),
            Match { start: 32, end: 48 }
        );
        assert!(matches!(
            match_from_legacy_native_selected_end(47, offset_window),
            Err(CallError::InvalidNativeOutput {
                output: NativeOutputKind::SelectedEnd,
                start: 31,
                end: 47,
                window_start: 32,
                window_end: 128,
            })
        ));
        assert!(matches!(
            match_from_legacy_native_selected_end(
                QUALIFIED_EXACT_SEARCH_LITERAL_BYTES - 1,
                NativeSearchWindow::new(0, 128),
            ),
            Err(CallError::InvalidNativeOutput {
                output: NativeOutputKind::SelectedEnd,
                start: usize::MAX,
                end,
                window_start: 0,
                window_end: 128,
            }) if end == QUALIFIED_EXACT_SEARCH_LITERAL_BYTES - 1
        ));
    }

    struct CandidateExecutionGuard;

    impl CandidateExecutionGuard {
        fn acquire() -> Self {
            TEST_CANDIDATE_EXECUTION.with(|enabled| {
                assert!(!enabled.replace(true), "nested Candidate execution guard");
            });
            Self
        }
    }

    impl Drop for CandidateExecutionGuard {
        fn drop(&mut self) {
            TEST_CANDIDATE_EXECUTION.with(|enabled| {
                assert!(enabled.replace(false), "Candidate execution guard was lost");
            });
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the closed atom-isolation matrix keeps every backend and cross-atom refusal auditable in one fixture"
    )]
    fn qualification_atoms_authorize_only_their_exact_backend() {
        let v8 = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x18; 32],
        };
        let tag19 = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x19; 32],
        };
        let tag10 = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x10; 32],
        };
        let tag21 = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x21; 32],
        };
        for policy in [
            QualifiedExactSearchBackendPolicy::AsimdV7,
            QualifiedExactSearchBackendPolicy::Sve16,
        ] {
            assert_eq!(
                qualification_for_backend_with_atoms(policy, v8, tag19, tag10, tag21),
                QualifiedExactSearchQualification::Candidate
            );
        }
        assert_eq!(
            qualification_for_backend_with_atoms(
                QualifiedExactSearchBackendPolicy::AsimdV8,
                v8,
                QualifiedExactSearchQualification::Candidate,
                QualifiedExactSearchQualification::Candidate,
                QualifiedExactSearchQualification::Candidate,
            ),
            v8
        );
        assert_eq!(
            qualification_for_backend_with_atoms(
                QualifiedExactSearchBackendPolicy::Sve16V6,
                QualifiedExactSearchQualification::Candidate,
                tag19,
                QualifiedExactSearchQualification::Candidate,
                QualifiedExactSearchQualification::Candidate,
            ),
            tag19
        );
        assert_eq!(
            qualification_for_backend_with_atoms(
                QualifiedExactSearchBackendPolicy::Sve2Fixed16,
                QualifiedExactSearchQualification::Candidate,
                QualifiedExactSearchQualification::Candidate,
                tag10,
                QualifiedExactSearchQualification::Candidate,
            ),
            tag10
        );
        assert_eq!(
            qualification_for_backend_with_atoms(
                QualifiedExactSearchBackendPolicy::Sve2Fixed16V2,
                QualifiedExactSearchQualification::Candidate,
                QualifiedExactSearchQualification::Candidate,
                QualifiedExactSearchQualification::Candidate,
                tag21,
            ),
            tag21
        );
        for (policy, atoms) in [
            (
                QualifiedExactSearchBackendPolicy::AsimdV8,
                (
                    QualifiedExactSearchQualification::Candidate,
                    tag19,
                    tag10,
                    tag21,
                ),
            ),
            (
                QualifiedExactSearchBackendPolicy::Sve16V6,
                (
                    v8,
                    QualifiedExactSearchQualification::Candidate,
                    tag10,
                    tag21,
                ),
            ),
            (
                QualifiedExactSearchBackendPolicy::Sve2Fixed16,
                (
                    v8,
                    tag19,
                    QualifiedExactSearchQualification::Candidate,
                    tag21,
                ),
            ),
            (
                QualifiedExactSearchBackendPolicy::Sve2Fixed16V2,
                (
                    v8,
                    tag19,
                    tag10,
                    QualifiedExactSearchQualification::Candidate,
                ),
            ),
        ] {
            assert_eq!(
                qualification_for_backend_with_atoms(policy, atoms.0, atoms.1, atoms.2, atoms.3,),
                QualifiedExactSearchQualification::Candidate
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the pure table exercises every authorized priority and fallback boundary with exact probe counts"
    )]
    fn automatic_selection_preserves_tag10_tag19_v8_fallbacks_when_tag21_is_candidate() {
        fn select(
            asimd_v8: QualifiedExactSearchQualification,
            sve16_v6: QualifiedExactSearchQualification,
            sve2_fixed16: QualifiedExactSearchQualification,
            allow_host_probe: bool,
            sve2_result: Result<(), PublishError>,
            sve16_result: Result<(), PublishError>,
        ) -> (AutomaticBackendSelection, usize, usize) {
            let sve2_probes = Cell::new(0_usize);
            let sve16_probes = Cell::new(0_usize);
            let selection = automatic_backend_selection_with(
                AutomaticBackendQualifications::new(
                    asimd_v8,
                    sve16_v6,
                    sve2_fixed16,
                    QualifiedExactSearchQualification::Candidate,
                ),
                allow_host_probe,
                || panic!("Candidate tag21 must not be probed"),
                || {
                    sve2_probes.set(sve2_probes.get() + 1);
                    sve2_result
                },
                || {
                    sve16_probes.set(sve16_probes.get() + 1);
                    sve16_result
                },
            );
            (selection, sve2_probes.get(), sve16_probes.get())
        }

        let candidate = QualifiedExactSearchQualification::Candidate;
        let v8 = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x18; 32],
        };
        let tag19 = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x19; 32],
        };
        let tag10 = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x10; 32],
        };
        let tag10_unavailable = PublishError::CpuFeatureUnavailable { feature: "sve2" };
        let tag19_unavailable = PublishError::CpuFeatureUnavailable { feature: "sve" };

        let (selection, sve2_probes, sve16_probes) =
            select(candidate, candidate, candidate, true, Ok(()), Ok(()));
        assert_eq!((sve2_probes, sve16_probes), (0, 0));
        assert_eq!(
            selection.backend_policy,
            QualifiedExactSearchBackendPolicy::AsimdV8
        );
        assert_eq!(selection.qualification, candidate);
        assert_eq!(selection.prechecked_host_support, None);

        let (selection, sve2_probes, sve16_probes) =
            select(v8, candidate, candidate, true, Ok(()), Ok(()));
        assert_eq!((sve2_probes, sve16_probes), (0, 0));
        assert_eq!(
            selection.backend_policy,
            QualifiedExactSearchBackendPolicy::AsimdV8
        );
        assert_eq!(selection.qualification, v8);
        assert_eq!(selection.prechecked_host_support, None);

        let (selection, sve2_probes, sve16_probes) =
            select(candidate, tag19, candidate, true, Ok(()), Ok(()));
        assert_eq!((sve2_probes, sve16_probes), (0, 1));
        assert_eq!(
            selection.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve16V6
        );
        assert_eq!(selection.qualification, tag19);
        assert_eq!(selection.prechecked_host_support, Some(Ok(())));

        let (selection, sve2_probes, sve16_probes) = select(v8, tag19, tag10, true, Ok(()), Ok(()));
        assert_eq!((sve2_probes, sve16_probes), (1, 0));
        assert_eq!(
            selection.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve2Fixed16
        );
        assert_eq!(selection.qualification, tag10);
        assert_eq!(selection.prechecked_host_support, Some(Ok(())));

        let (selection, sve2_probes, sve16_probes) = select(
            v8,
            tag19,
            tag10,
            true,
            Err(tag10_unavailable.clone()),
            Ok(()),
        );
        assert_eq!((sve2_probes, sve16_probes), (1, 1));
        assert_eq!(
            selection.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve16V6
        );
        assert_eq!(selection.qualification, tag19);
        assert_eq!(selection.prechecked_host_support, Some(Ok(())));

        let (selection, sve2_probes, sve16_probes) = select(
            v8,
            tag19,
            tag10,
            true,
            Err(tag10_unavailable.clone()),
            Err(tag19_unavailable.clone()),
        );
        assert_eq!((sve2_probes, sve16_probes), (1, 1));
        assert_eq!(
            selection.backend_policy,
            QualifiedExactSearchBackendPolicy::AsimdV8
        );
        assert_eq!(selection.qualification, v8);
        assert_eq!(selection.prechecked_host_support, None);

        let (selection, sve2_probes, sve16_probes) = select(
            candidate,
            candidate,
            tag10,
            true,
            Err(tag10_unavailable.clone()),
            Ok(()),
        );
        assert_eq!((sve2_probes, sve16_probes), (1, 0));
        assert_eq!(
            selection.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve2Fixed16
        );
        assert_eq!(selection.qualification, tag10);
        assert_eq!(
            selection.prechecked_host_support,
            Some(Err(tag10_unavailable.clone()))
        );

        let (selection, sve2_probes, sve16_probes) = select(
            candidate,
            tag19,
            tag10,
            true,
            Err(tag10_unavailable.clone()),
            Err(tag19_unavailable.clone()),
        );
        assert_eq!((sve2_probes, sve16_probes), (1, 1));
        assert_eq!(
            selection.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve2Fixed16
        );
        assert_eq!(selection.qualification, tag10);
        assert_eq!(
            selection.prechecked_host_support,
            Some(Err(tag10_unavailable))
        );

        let (selection, sve2_probes, sve16_probes) = select(
            v8,
            tag19,
            candidate,
            true,
            Ok(()),
            Err(tag19_unavailable.clone()),
        );
        assert_eq!((sve2_probes, sve16_probes), (0, 1));
        assert_eq!(
            selection.backend_policy,
            QualifiedExactSearchBackendPolicy::AsimdV8
        );
        assert_eq!(selection.qualification, v8);
        assert_eq!(selection.prechecked_host_support, None);

        let (selection, sve2_probes, sve16_probes) = select(
            candidate,
            tag19,
            candidate,
            true,
            Ok(()),
            Err(tag19_unavailable.clone()),
        );
        assert_eq!((sve2_probes, sve16_probes), (0, 1));
        assert_eq!(
            selection.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve16V6
        );
        assert_eq!(selection.qualification, tag19);
        assert_eq!(
            selection.prechecked_host_support,
            Some(Err(tag19_unavailable))
        );

        let (selection, sve2_probes, sve16_probes) =
            select(v8, tag19, tag10, false, Ok(()), Ok(()));
        assert_eq!((sve2_probes, sve16_probes), (0, 0));
        assert_eq!(
            selection.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve2Fixed16
        );
        assert_eq!(selection.qualification, tag10);
        assert_eq!(selection.prechecked_host_support, None);

        let (selection, sve2_probes, sve16_probes) =
            select(v8, tag19, candidate, false, Ok(()), Ok(()));
        assert_eq!((sve2_probes, sve16_probes), (0, 0));
        assert_eq!(
            selection.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve16V6
        );
        assert_eq!(selection.qualification, tag19);
        assert_eq!(selection.prechecked_host_support, None);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the closed priority table keeps every fallback, retained failure, and exact probe count together"
    )]
    fn automatic_selection_prefers_tag21_then_falls_back_in_backend_order() {
        fn select(
            qualifications: AutomaticBackendQualifications,
            allow_host_probe: bool,
            tag21_result: Result<(), PublishError>,
            tag10_result: Result<(), PublishError>,
            tag19_result: Result<(), PublishError>,
        ) -> (AutomaticBackendSelection, [usize; 3]) {
            let probes = [Cell::new(0_usize), Cell::new(0_usize), Cell::new(0_usize)];
            let selection = automatic_backend_selection_with(
                qualifications,
                allow_host_probe,
                || {
                    probes[0].set(probes[0].get() + 1);
                    tag21_result
                },
                || {
                    probes[1].set(probes[1].get() + 1);
                    tag10_result
                },
                || {
                    probes[2].set(probes[2].get() + 1);
                    tag19_result
                },
            );
            (
                selection,
                [probes[0].get(), probes[1].get(), probes[2].get()],
            )
        }

        let candidate = QualifiedExactSearchQualification::Candidate;
        let qualified = |byte| QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [byte; 32],
        };
        let v8 = qualified(0x18);
        let tag19 = qualified(0x19);
        let tag10 = qualified(0x10);
        let tag21 = qualified(0x21);
        let tag21_error = PublishError::CpuFeatureUnavailable {
            feature: "tag21-sve2",
        };
        let tag10_error = PublishError::CpuFeatureUnavailable {
            feature: "tag10-sve2",
        };
        let tag19_error = PublishError::CpuFeatureUnavailable {
            feature: "tag19-sve",
        };

        let (selection, probes) = select(
            AutomaticBackendQualifications::new(v8, tag19, tag10, tag21),
            true,
            Ok(()),
            Ok(()),
            Ok(()),
        );
        assert_eq!(probes, [1, 0, 0]);
        assert_eq!(
            selection,
            AutomaticBackendSelection {
                backend_policy: QualifiedExactSearchBackendPolicy::Sve2Fixed16V2,
                qualification: tag21,
                prechecked_host_support: Some(Ok(())),
            }
        );

        let (selection, probes) = select(
            AutomaticBackendQualifications::new(v8, tag19, tag10, tag21),
            true,
            Err(tag21_error.clone()),
            Ok(()),
            Ok(()),
        );
        assert_eq!(probes, [1, 1, 0]);
        assert_eq!(
            selection,
            AutomaticBackendSelection {
                backend_policy: QualifiedExactSearchBackendPolicy::Sve2Fixed16,
                qualification: tag10,
                prechecked_host_support: Some(Ok(())),
            }
        );

        let (selection, probes) = select(
            AutomaticBackendQualifications::new(v8, tag19, tag10, tag21),
            true,
            Err(tag21_error.clone()),
            Err(tag10_error),
            Ok(()),
        );
        assert_eq!(probes, [1, 1, 1]);
        assert_eq!(
            selection,
            AutomaticBackendSelection {
                backend_policy: QualifiedExactSearchBackendPolicy::Sve16V6,
                qualification: tag19,
                prechecked_host_support: Some(Ok(())),
            }
        );

        let (selection, probes) = select(
            AutomaticBackendQualifications::new(v8, tag19, tag10, tag21),
            true,
            Err(tag21_error.clone()),
            Err(PublishError::CpuFeatureUnavailable {
                feature: "tag10-sve2",
            }),
            Err(tag19_error),
        );
        assert_eq!(probes, [1, 1, 1]);
        assert_eq!(
            selection,
            AutomaticBackendSelection {
                backend_policy: QualifiedExactSearchBackendPolicy::AsimdV8,
                qualification: v8,
                prechecked_host_support: None,
            }
        );

        let (selection, probes) = select(
            AutomaticBackendQualifications::new(candidate, candidate, candidate, tag21),
            true,
            Err(tag21_error.clone()),
            Ok(()),
            Ok(()),
        );
        assert_eq!(probes, [1, 0, 0]);
        assert_eq!(
            selection,
            AutomaticBackendSelection {
                backend_policy: QualifiedExactSearchBackendPolicy::Sve2Fixed16V2,
                qualification: tag21,
                prechecked_host_support: Some(Err(tag21_error)),
            }
        );

        let (selection, probes) = select(
            AutomaticBackendQualifications::new(v8, tag19, tag10, tag21),
            false,
            Ok(()),
            Ok(()),
            Ok(()),
        );
        assert_eq!(probes, [0, 0, 0]);
        assert_eq!(
            selection,
            AutomaticBackendSelection {
                backend_policy: QualifiedExactSearchBackendPolicy::Sve2Fixed16V2,
                qualification: tag21,
                prechecked_host_support: None,
            }
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the closed table covers every four-atom authority, three-probe support, and eligibility combination"
    )]
    fn automatic_selection_matches_complete_four_atom_truth_table() {
        let candidate = QualifiedExactSearchQualification::Candidate;
        let qualified = |byte| QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [byte; 32],
        };
        let qualified_v8 = qualified(0x18);
        let qualified_tag19 = qualified(0x19);
        let qualified_tag10 = qualified(0x10);
        let qualified_tag21 = qualified(0x21);
        let tag21_error = PublishError::CpuFeatureUnavailable {
            feature: "tag21-sve2",
        };
        let tag10_error = PublishError::CpuFeatureUnavailable {
            feature: "tag10-sve2",
        };
        let tag19_error = PublishError::CpuFeatureUnavailable {
            feature: "tag19-sve",
        };
        let mut cases = 0_usize;

        for authority_bits in 0_u8..16 {
            let v8 = if authority_bits & 1 != 0 {
                qualified_v8
            } else {
                candidate
            };
            let tag19 = if authority_bits & 2 != 0 {
                qualified_tag19
            } else {
                candidate
            };
            let tag10 = if authority_bits & 4 != 0 {
                qualified_tag10
            } else {
                candidate
            };
            let tag21 = if authority_bits & 8 != 0 {
                qualified_tag21
            } else {
                candidate
            };
            for allow_host_probe in [false, true] {
                for support_bits in 0_u8..8 {
                    let probes = [Cell::new(0_usize), Cell::new(0_usize), Cell::new(0_usize)];
                    let actual = automatic_backend_selection_with(
                        AutomaticBackendQualifications::new(v8, tag19, tag10, tag21),
                        allow_host_probe,
                        || {
                            probes[0].set(probes[0].get() + 1);
                            if support_bits & 1 != 0 {
                                Ok(())
                            } else {
                                Err(tag21_error.clone())
                            }
                        },
                        || {
                            probes[1].set(probes[1].get() + 1);
                            if support_bits & 2 != 0 {
                                Ok(())
                            } else {
                                Err(tag10_error.clone())
                            }
                        },
                        || {
                            probes[2].set(probes[2].get() + 1);
                            if support_bits & 4 != 0 {
                                Ok(())
                            } else {
                                Err(tag19_error.clone())
                            }
                        },
                    );

                    let fixed_backends = [
                        (
                            QualifiedExactSearchBackendPolicy::Sve2Fixed16V2,
                            tag21,
                            tag21_error.clone(),
                        ),
                        (
                            QualifiedExactSearchBackendPolicy::Sve2Fixed16,
                            tag10,
                            tag10_error.clone(),
                        ),
                        (
                            QualifiedExactSearchBackendPolicy::Sve16V6,
                            tag19,
                            tag19_error.clone(),
                        ),
                    ];
                    let mut expected_probes = [0_usize; 3];
                    let expected = if allow_host_probe {
                        let mut supported_selection = None;
                        let mut highest_failure = None;
                        for (index, (policy, qualification, error)) in
                            fixed_backends.iter().enumerate()
                        {
                            if !qualification.is_authorized() {
                                continue;
                            }
                            expected_probes[index] += 1;
                            if support_bits & (1 << index) != 0 {
                                supported_selection = Some(AutomaticBackendSelection {
                                    backend_policy: *policy,
                                    qualification: *qualification,
                                    prechecked_host_support: Some(Ok(())),
                                });
                                break;
                            }
                            if highest_failure.is_none() {
                                highest_failure = Some(AutomaticBackendSelection {
                                    backend_policy: *policy,
                                    qualification: *qualification,
                                    prechecked_host_support: Some(Err(error.clone())),
                                });
                            }
                        }
                        supported_selection.unwrap_or_else(|| {
                            if v8.is_authorized() {
                                AutomaticBackendSelection {
                                    backend_policy: QualifiedExactSearchBackendPolicy::AsimdV8,
                                    qualification: v8,
                                    prechecked_host_support: None,
                                }
                            } else {
                                highest_failure.unwrap_or(AutomaticBackendSelection {
                                    backend_policy: QualifiedExactSearchBackendPolicy::AsimdV8,
                                    qualification: v8,
                                    prechecked_host_support: None,
                                })
                            }
                        })
                    } else {
                        fixed_backends
                            .iter()
                            .find_map(|(policy, qualification, _)| {
                                qualification
                                    .is_authorized()
                                    .then_some(AutomaticBackendSelection {
                                        backend_policy: *policy,
                                        qualification: *qualification,
                                        prechecked_host_support: None,
                                    })
                            })
                            .unwrap_or(AutomaticBackendSelection {
                                backend_policy: QualifiedExactSearchBackendPolicy::AsimdV8,
                                qualification: v8,
                                prechecked_host_support: None,
                            })
                    };
                    let actual_probes = [probes[0].get(), probes[1].get(), probes[2].get()];
                    assert_eq!(
                        actual, expected,
                        "selection mismatch for authority={authority_bits:04b}, allow_host_probe={allow_host_probe}, support={support_bits:03b}"
                    );
                    assert_eq!(
                        actual_probes, expected_probes,
                        "probe mismatch for authority={authority_bits:04b}, allow_host_probe={allow_host_probe}, support={support_bits:03b}"
                    );
                    cases = cases.checked_add(1).expect("bounded truth table");
                }
            }
        }
        assert_eq!(cases, 256);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "all 64 authority, support, and eligibility combinations remain one auditable closed truth table"
    )]
    fn automatic_selection_matches_legacy_truth_table_when_tag21_is_candidate() {
        let candidate = QualifiedExactSearchQualification::Candidate;
        let qualified = |byte| QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [byte; 32],
        };
        let v8_qualified = qualified(0x18);
        let tag19_qualified = qualified(0x19);
        let tag10_qualified = qualified(0x10);
        let tag10_probe_error = PublishError::CpuFeatureUnavailable { feature: "sve2" };
        let tag19_probe_error = PublishError::CpuFeatureUnavailable { feature: "sve" };
        let mut cases = 0_usize;

        for v8_authorized in [false, true] {
            for tag19_authorized in [false, true] {
                for tag10_authorized in [false, true] {
                    for allow_host_probe in [false, true] {
                        for tag10_supported in [false, true] {
                            for tag19_supported in [false, true] {
                                let v8 = if v8_authorized {
                                    v8_qualified
                                } else {
                                    candidate
                                };
                                let tag19 = if tag19_authorized {
                                    tag19_qualified
                                } else {
                                    candidate
                                };
                                let tag10 = if tag10_authorized {
                                    tag10_qualified
                                } else {
                                    candidate
                                };
                                let tag10_probe_count = Cell::new(0_usize);
                                let tag19_probe_count = Cell::new(0_usize);
                                let actual = automatic_backend_selection_with(
                                    AutomaticBackendQualifications::new(
                                        v8, tag19, tag10, candidate,
                                    ),
                                    allow_host_probe,
                                    || panic!("Candidate tag21 must not be probed"),
                                    || {
                                        tag10_probe_count.set(tag10_probe_count.get() + 1);
                                        if tag10_supported {
                                            Ok(())
                                        } else {
                                            Err(tag10_probe_error.clone())
                                        }
                                    },
                                    || {
                                        tag19_probe_count.set(tag19_probe_count.get() + 1);
                                        if tag19_supported {
                                            Ok(())
                                        } else {
                                            Err(tag19_probe_error.clone())
                                        }
                                    },
                                );

                                let (expected, expected_tag10_probes, expected_tag19_probes) =
                                    if tag10_authorized {
                                        if !allow_host_probe {
                                            (
                                                AutomaticBackendSelection {
                                                    backend_policy:
                                                        QualifiedExactSearchBackendPolicy::Sve2Fixed16,
                                                    qualification: tag10,
                                                    prechecked_host_support: None,
                                                },
                                                0,
                                                0,
                                            )
                                        } else if tag10_supported {
                                            (
                                                AutomaticBackendSelection {
                                                    backend_policy:
                                                        QualifiedExactSearchBackendPolicy::Sve2Fixed16,
                                                    qualification: tag10,
                                                    prechecked_host_support: Some(Ok(())),
                                                },
                                                1,
                                                0,
                                            )
                                        } else if tag19_authorized && tag19_supported {
                                            (
                                                AutomaticBackendSelection {
                                                    backend_policy:
                                                        QualifiedExactSearchBackendPolicy::Sve16V6,
                                                    qualification: tag19,
                                                    prechecked_host_support: Some(Ok(())),
                                                },
                                                1,
                                                1,
                                            )
                                        } else if v8_authorized {
                                            (
                                                AutomaticBackendSelection {
                                                    backend_policy:
                                                        QualifiedExactSearchBackendPolicy::AsimdV8,
                                                    qualification: v8,
                                                    prechecked_host_support: None,
                                                },
                                                1,
                                                usize::from(tag19_authorized),
                                            )
                                        } else {
                                            (
                                                AutomaticBackendSelection {
                                                    backend_policy:
                                                        QualifiedExactSearchBackendPolicy::Sve2Fixed16,
                                                    qualification: tag10,
                                                    prechecked_host_support: Some(Err(
                                                        tag10_probe_error.clone(),
                                                    )),
                                                },
                                                1,
                                                usize::from(tag19_authorized),
                                            )
                                        }
                                    } else if tag19_authorized {
                                        if !allow_host_probe {
                                            (
                                                AutomaticBackendSelection {
                                                    backend_policy:
                                                        QualifiedExactSearchBackendPolicy::Sve16V6,
                                                    qualification: tag19,
                                                    prechecked_host_support: None,
                                                },
                                                0,
                                                0,
                                            )
                                        } else if tag19_supported {
                                            (
                                                AutomaticBackendSelection {
                                                    backend_policy:
                                                        QualifiedExactSearchBackendPolicy::Sve16V6,
                                                    qualification: tag19,
                                                    prechecked_host_support: Some(Ok(())),
                                                },
                                                0,
                                                1,
                                            )
                                        } else if v8_authorized {
                                            (
                                                AutomaticBackendSelection {
                                                    backend_policy:
                                                        QualifiedExactSearchBackendPolicy::AsimdV8,
                                                    qualification: v8,
                                                    prechecked_host_support: None,
                                                },
                                                0,
                                                1,
                                            )
                                        } else {
                                            (
                                                AutomaticBackendSelection {
                                                    backend_policy:
                                                        QualifiedExactSearchBackendPolicy::Sve16V6,
                                                    qualification: tag19,
                                                    prechecked_host_support: Some(Err(
                                                        tag19_probe_error.clone(),
                                                    )),
                                                },
                                                0,
                                                1,
                                            )
                                        }
                                    } else {
                                        (
                                            AutomaticBackendSelection {
                                                backend_policy:
                                                    QualifiedExactSearchBackendPolicy::AsimdV8,
                                                qualification: v8,
                                                prechecked_host_support: None,
                                            },
                                            0,
                                            0,
                                        )
                                    };
                                assert_eq!(actual, expected);
                                assert_eq!(tag10_probe_count.get(), expected_tag10_probes);
                                assert_eq!(tag19_probe_count.get(), expected_tag19_probes);
                                cases = cases.checked_add(1).expect("bounded truth table");
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 64);
    }

    #[test]
    fn automatic_authority_does_not_probe_ineligible_literal_or_workload() {
        let v8 = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x18; 32],
        };
        let tag19 = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x19; 32],
        };
        let tag10 = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x10; 32],
        };
        let tag21 = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x21; 32],
        };
        let probes = Cell::new(0_usize);
        let ineligible_width =
            QualifiedExactSearchFacade::from_builder_with_automatic_qualification_from(
                PortableBuilder::new("fifteen-byte-li"),
                QualifiedExactSearchWorkload::new(
                    QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
                    QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
                ),
                ValidateLimits::default(),
                EmitLimits::default(),
                PublicationLimits::default(),
                v8,
                tag19,
                tag10,
                tag21,
                || {
                    probes.set(probes.get() + 1);
                    Ok(())
                },
                || {
                    probes.set(probes.get() + 1);
                    Ok(())
                },
                || {
                    probes.set(probes.get() + 1);
                    Ok(())
                },
            )
            .expect("ineligible-width facade");
        let width_report = ineligible_width
            .qualified_build_report()
            .expect("exact-literal report");
        assert_eq!(
            width_report.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve2Fixed16V2
        );
        assert!(matches!(
            width_report.native,
            QualifiedExactSearchNativeStatus::IneligibleLiteralWidth {
                actual: 15,
                required: QUALIFIED_EXACT_SEARCH_LITERAL_BYTES,
            }
        ));

        let ineligible_workload =
            QualifiedExactSearchFacade::from_builder_with_automatic_qualification_from(
                PortableBuilder::new("0123456789abcdef"),
                QualifiedExactSearchWorkload::new(
                    QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
                    QUALIFIED_EXACT_SEARCH_MIN_SEARCHES - 1,
                ),
                ValidateLimits::default(),
                EmitLimits::default(),
                PublicationLimits::default(),
                v8,
                tag19,
                tag10,
                tag21,
                || {
                    probes.set(probes.get() + 1);
                    Ok(())
                },
                || {
                    probes.set(probes.get() + 1);
                    Ok(())
                },
                || {
                    probes.set(probes.get() + 1);
                    Ok(())
                },
            )
            .expect("ineligible-workload facade");
        let workload_report = ineligible_workload
            .qualified_build_report()
            .expect("exact-literal report");
        assert_eq!(
            workload_report.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve2Fixed16V2
        );
        assert!(matches!(
            workload_report.native,
            QualifiedExactSearchNativeStatus::IneligibleWorkload {
                required_searches: Some(QUALIFIED_EXACT_SEARCH_MIN_SEARCHES),
                ..
            }
        ));
        assert_eq!(probes.get(), 0);
    }

    #[cfg(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    #[test]
    #[ignore = "sealed m9g receipt: run the exact test binary through set-vl16-and-exec.py"]
    #[allow(
        clippy::too_many_lines,
        reason = "the ignored hardware receipt keeps six ordered facade-routing cases in one sealed driver"
    )]
    fn fixed16_automatic_facade_qualification_receipt() {
        use std::fmt::Write as _;

        fn artifact_hex(bytes: [u8; 32]) -> String {
            let mut output = String::with_capacity(64);
            for byte in bytes {
                write!(output, "{byte:02x}").expect("String formatting cannot fail");
            }
            output
        }

        fn haystack() -> Vec<u8> {
            let literal = b"0123456789abcdef";
            let mut bytes = vec![b'x'; QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES];
            let start = bytes
                .len()
                .checked_sub(literal.len())
                .and_then(|value| value.checked_sub(31))
                .expect("fixed receipt fixture fits its haystack");
            let end = start
                .checked_add(literal.len())
                .expect("fixed receipt literal end is bounded");
            bytes[start..end].copy_from_slice(literal);
            bytes
        }

        fn workload() -> QualifiedExactSearchWorkload {
            QualifiedExactSearchWorkload::new(
                QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
                QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
            )
        }

        let literal = "0123456789abcdef";
        let bytes = haystack();
        let candidate = QualifiedExactSearchFacade::from_builder_with_automatic_qualification_from(
            PortableBuilder::new(literal),
            workload(),
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits::default(),
            QualifiedExactSearchQualification::Candidate,
            QualifiedExactSearchQualification::Candidate,
            QualifiedExactSearchQualification::Candidate,
            QualifiedExactSearchQualification::Candidate,
            || panic!("Candidate-closed facade must not probe tag21"),
            || panic!("Candidate-closed facade must not probe tag10"),
            || panic!("Candidate-closed facade must not probe tag19"),
        )
        .expect("synthetic Candidate-closed facade");
        let candidate_report = candidate
            .qualified_build_report()
            .expect("exact Candidate report");
        assert_eq!(
            candidate_report.backend_policy,
            QualifiedExactSearchBackendPolicy::AsimdV8
        );
        assert_eq!(
            candidate_report.native,
            QualifiedExactSearchNativeStatus::Unqualified {
                qualification: QualifiedExactSearchQualification::Candidate,
            }
        );
        let candidate_session = candidate
            .begin_current_thread_session()
            .expect("Candidate portable session needs no host contract");
        let (_, candidate_execution) = candidate_session
            .find(&bytes, SearchLimits::unlimited())
            .expect("Candidate portable session search");
        assert_eq!(
            candidate_execution.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(
                QualifiedExactSearchRoute::PortableLiteral
            )
        );
        println!(
            "fre-jit-auto-facade-v4\tcase=candidate_closed\tpolicy=AsimdV8\tbackend=none\tabi=none\tqualification=Candidate\tpublication_vl=none\tsession_vl=none\troute=PortableLiteral\tartifact_sha256=none\tstatus=PASS"
        );

        let v8_qualified = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x18; 32],
        };
        let tag19_qualified = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x19; 32],
        };
        let tag10_qualified = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x10; 32],
        };
        let tag21_qualified = QualifiedExactSearchQualification::Qualified {
            bundle_sha256: [0x21; 32],
        };

        let tag21 = QualifiedExactSearchFacade::from_builder_with_automatic_qualification_from(
            PortableBuilder::new(literal),
            workload(),
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits::default(),
            v8_qualified,
            tag19_qualified,
            tag10_qualified,
            tag21_qualified,
            || {
                native_selected_end_register_backend_support_v2(
                    SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
                )
            },
            || panic!("supported tag21 must win before probing tag10"),
            || panic!("supported tag21 must win before probing tag19"),
        )
        .expect("test-qualified tag21 facade");
        let tag21_report = tag21.qualified_build_report().expect("tag21 exact report");
        let QualifiedExactSearchNativeStatus::Published {
            identity: tag21_identity,
            abi: tag21_abi,
            sve_vector_bytes_at_publication: tag21_publication_vl,
            required_thread_sve_vector_bytes: tag21_session_vl,
            ..
        } = &tag21_report.native
        else {
            panic!("tag21 did not publish: {:?}", tag21_report.native);
        };
        assert_eq!(
            tag21_report.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve2Fixed16V2
        );
        assert_eq!(
            tag21_identity.backend,
            BackendVersion::SEARCH_SVE2_FIXED16_V2
        );
        assert_eq!(tag21_identity.target.features.bits(), 7);
        assert_eq!(tag21_identity.qualification, tag21_qualified);
        assert_eq!(
            tag21_identity.abi,
            QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
        );
        assert_eq!(
            *tag21_abi,
            QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
        );
        assert_eq!(tag21_identity.sve_vector_bytes_at_publication, None);
        assert_eq!(tag21_identity.required_thread_sve_vector_bytes, Some(16));
        assert_eq!(*tag21_publication_vl, None);
        assert_eq!(*tag21_session_vl, Some(16));
        let (_, tag21_sessionless) = tag21
            .find(&bytes, SearchLimits::unlimited())
            .expect("tag21 sessionless portable fallback");
        assert_eq!(
            tag21_sessionless.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(
                QualifiedExactSearchRoute::PortableLiteral
            )
        );
        let tag21_session = tag21
            .begin_current_thread_session()
            .expect("tag21 VL16 current-thread session");
        let (_, tag21_execution) = tag21_session
            .find(&bytes, SearchLimits::unlimited())
            .expect("tag21 native session search");
        assert_eq!(
            tag21_execution.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(QualifiedExactSearchRoute::NativeJit)
        );
        println!(
            "fre-jit-auto-facade-v4\tcase=tag21_auto\tpolicy=Sve2Fixed16V2\tbackend=21\tabi=SelectedEndRegisterV2\tqualification=TestQualified\tpublication_vl=none\tsession_vl=16\troute=NativeJit\tartifact_sha256={}\tstatus=PASS",
            artifact_hex(tag21_identity.artifact_sha256)
        );

        let tag10 = QualifiedExactSearchFacade::from_builder_with_automatic_qualification_from(
            PortableBuilder::new(literal),
            workload(),
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits::default(),
            v8_qualified,
            tag19_qualified,
            tag10_qualified,
            tag21_qualified,
            || {
                Err(PublishError::CpuFeatureUnavailable {
                    feature: "tag21-sve2",
                })
            },
            || {
                native_search_backend_support(
                    QualifiedExactSearchBackendPolicy::Sve2Fixed16.backend_version(),
                )
            },
            || panic!("supported tag10 must win before probing tag19"),
        )
        .expect("test-qualified tag10 facade");
        let tag10_report = tag10.qualified_build_report().expect("tag10 exact report");
        let QualifiedExactSearchNativeStatus::Published {
            identity: tag10_identity,
            abi: tag10_abi,
            sve_vector_bytes_at_publication: tag10_publication_vl,
            required_thread_sve_vector_bytes: tag10_session_vl,
            ..
        } = &tag10_report.native
        else {
            panic!("tag10 did not publish: {:?}", tag10_report.native);
        };
        assert_eq!(
            tag10_report.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve2Fixed16
        );
        assert_eq!(tag10_identity.backend, BackendVersion::SEARCH_SVE2_16_V1);
        assert_eq!(tag10_identity.target.features.bits(), 7);
        assert_eq!(tag10_identity.qualification, tag10_qualified);
        assert_ne!(
            tag10_identity.artifact_sha256,
            tag21_identity.artifact_sha256
        );
        assert_eq!(
            tag10_identity.abi,
            QualifiedExactSearchNativeAbi::LegacySelectedEndV1
        );
        assert_eq!(
            *tag10_abi,
            QualifiedExactSearchNativeAbi::LegacySelectedEndV1
        );
        assert_eq!(tag10_identity.sve_vector_bytes_at_publication, Some(16));
        assert_eq!(tag10_identity.required_thread_sve_vector_bytes, Some(16));
        assert_eq!(*tag10_publication_vl, Some(16));
        assert_eq!(*tag10_session_vl, Some(16));
        assert_eq!(
            *tag10_publication_vl,
            tag10_identity.sve_vector_bytes_at_publication
        );
        let (_, tag10_sessionless) = tag10
            .find(&bytes, SearchLimits::unlimited())
            .expect("tag10 sessionless portable fallback");
        assert_eq!(
            tag10_sessionless.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(
                QualifiedExactSearchRoute::PortableLiteral
            )
        );
        let tag10_session = tag10
            .begin_current_thread_session()
            .expect("tag10 VL16 current-thread session");
        let (_, tag10_execution) = tag10_session
            .find(&bytes, SearchLimits::unlimited())
            .expect("tag10 native session search");
        assert_eq!(
            tag10_execution.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(QualifiedExactSearchRoute::NativeJit)
        );
        println!(
            "fre-jit-auto-facade-v4\tcase=tag10_fallback\tpolicy=Sve2Fixed16\tbackend=10\tabi=LegacySelectedEndV1\tqualification=TestQualified\tpublication_vl=16\tsession_vl=16\troute=NativeJit\tartifact_sha256={}\tstatus=PASS",
            artifact_hex(tag10_identity.artifact_sha256)
        );

        let tag19 = QualifiedExactSearchFacade::from_builder_with_automatic_qualification_from(
            PortableBuilder::new(literal),
            workload(),
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits::default(),
            v8_qualified,
            tag19_qualified,
            tag10_qualified,
            tag21_qualified,
            || {
                Err(PublishError::CpuFeatureUnavailable {
                    feature: "tag21-sve2",
                })
            },
            || Err(PublishError::CpuFeatureUnavailable { feature: "sve2" }),
            || {
                native_selected_end_register_backend_support_v2(
                    SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16,
                )
            },
        )
        .expect("test-qualified tag19 facade");
        let tag19_report = tag19.qualified_build_report().expect("tag19 exact report");
        let QualifiedExactSearchNativeStatus::Published {
            identity: tag19_identity,
            abi: tag19_abi,
            sve_vector_bytes_at_publication: tag19_publication_vl,
            required_thread_sve_vector_bytes: tag19_session_vl,
            ..
        } = &tag19_report.native
        else {
            panic!("tag19 did not publish: {:?}", tag19_report.native);
        };
        assert_eq!(
            tag19_report.backend_policy,
            QualifiedExactSearchBackendPolicy::Sve16V6
        );
        assert_eq!(tag19_identity.backend, BackendVersion::SEARCH_SVE16_V6);
        assert_eq!(tag19_identity.target.features.bits(), 3);
        assert_eq!(tag19_identity.qualification, tag19_qualified);
        assert_eq!(
            tag19_identity.abi,
            QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
        );
        assert_eq!(
            *tag19_abi,
            QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
        );
        assert_eq!(tag19_identity.sve_vector_bytes_at_publication, None);
        assert_eq!(tag19_identity.required_thread_sve_vector_bytes, Some(16));
        assert_eq!(*tag19_publication_vl, None);
        assert_eq!(*tag19_session_vl, Some(16));
        assert_eq!(
            *tag19_publication_vl,
            tag19_identity.sve_vector_bytes_at_publication
        );
        assert_ne!(
            tag19_identity.artifact_sha256,
            tag10_identity.artifact_sha256
        );
        let (_, tag19_sessionless) = tag19
            .find(&bytes, SearchLimits::unlimited())
            .expect("tag19 sessionless portable fallback");
        assert_eq!(
            tag19_sessionless.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(
                QualifiedExactSearchRoute::PortableLiteral
            )
        );
        let tag19_session = tag19
            .begin_current_thread_session()
            .expect("tag19 VL16 current-thread session");
        let (_, tag19_execution) = tag19_session
            .find(&bytes, SearchLimits::unlimited())
            .expect("tag19 native session search");
        assert_eq!(
            tag19_execution.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(QualifiedExactSearchRoute::NativeJit)
        );
        // V5 is deliberately a tag-19-only ABI2 receipt contract. The V4
        // sibling rows remain byte-stable for their independently versioned
        // V8/tag-10/tag-21 evidence consumers.
        println!(
            "fre-jit-auto-facade-v5\tcase=tag19_fallback\tpolicy=Sve16V6\tbackend=19\tabi=SelectedEndRegisterV2\tqualification=TestQualified\tpublication_vl=none\tsession_vl=16\troute=NativeJit\tartifact_sha256={}\tstatus=PASS",
            artifact_hex(tag19_identity.artifact_sha256)
        );

        let v8 = QualifiedExactSearchFacade::from_builder_with_automatic_qualification_from(
            PortableBuilder::new(literal),
            workload(),
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits::default(),
            v8_qualified,
            tag19_qualified,
            tag10_qualified,
            tag21_qualified,
            || {
                Err(PublishError::CpuFeatureUnavailable {
                    feature: "tag21-sve2",
                })
            },
            || Err(PublishError::CpuFeatureUnavailable { feature: "sve2" }),
            || Err(PublishError::CpuFeatureUnavailable { feature: "sve" }),
        )
        .expect("test-qualified V8 fallback facade");
        let v8_report = v8.qualified_build_report().expect("V8 exact report");
        let QualifiedExactSearchNativeStatus::Published {
            identity: v8_identity,
            abi: v8_abi,
            sve_vector_bytes_at_publication: v8_publication_vl,
            required_thread_sve_vector_bytes: v8_session_vl,
            ..
        } = &v8_report.native
        else {
            panic!("V8 fallback did not publish: {:?}", v8_report.native);
        };
        assert_eq!(
            v8_report.backend_policy,
            QualifiedExactSearchBackendPolicy::AsimdV8
        );
        assert_eq!(v8_identity.backend, BackendVersion::SEARCH_V8);
        assert_eq!(v8_identity.qualification, v8_qualified);
        assert_eq!(
            v8_identity.abi,
            QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
        );
        assert_eq!(
            *v8_abi,
            QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
        );
        assert_eq!(v8_identity.sve_vector_bytes_at_publication, None);
        assert_eq!(v8_identity.required_thread_sve_vector_bytes, None);
        assert_eq!(*v8_publication_vl, None);
        assert_eq!(*v8_session_vl, None);
        assert_eq!(
            *v8_publication_vl,
            v8_identity.sve_vector_bytes_at_publication
        );
        assert_ne!(v8_identity.artifact_sha256, tag19_identity.artifact_sha256);
        assert_ne!(v8_identity.artifact_sha256, tag10_identity.artifact_sha256);
        let (_, v8_sessionless) = v8
            .find(&bytes, SearchLimits::unlimited())
            .expect("V8 sessionless portable fallback");
        assert_eq!(
            v8_sessionless.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(
                QualifiedExactSearchRoute::PortableLiteral
            )
        );
        let v8_session = v8
            .begin_current_thread_session()
            .expect("V8 ABI2 session construction is SVE-syscall-free");
        let (_, v8_execution) = v8_session
            .find(&bytes, SearchLimits::unlimited())
            .expect("V8 fallback native session search");
        assert_eq!(
            v8_execution.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(QualifiedExactSearchRoute::NativeJit)
        );
        println!(
            "fre-jit-auto-facade-v4\tcase=v8_fallback\tpolicy=AsimdV8\tbackend=8\tabi=SelectedEndRegisterV2\tqualification=TestQualified\tpublication_vl=none\tsession_vl=none\troute=NativeJit\tartifact_sha256={}\tstatus=PASS",
            artifact_hex(v8_identity.artifact_sha256)
        );

        let guard = CandidateExecutionGuard::acquire();
        let guard_loss = PortableBuilder::new(literal)
            .build_qualified_exact_search(workload())
            .expect("guarded default Candidate facade");
        let guard_report = guard_loss
            .qualified_build_report()
            .expect("guarded exact report");
        let QualifiedExactSearchNativeStatus::Published {
            identity: guard_identity,
            abi: guard_abi,
            sve_vector_bytes_at_publication: guard_publication_vl,
            required_thread_sve_vector_bytes: guard_session_vl,
            ..
        } = &guard_report.native
        else {
            panic!("guarded V8 did not publish: {:?}", guard_report.native);
        };
        assert_eq!(guard_identity.backend, BackendVersion::SEARCH_V8);
        assert_eq!(
            guard_identity.qualification,
            QualifiedExactSearchQualification::Candidate
        );
        assert_eq!(
            *guard_abi,
            QualifiedExactSearchNativeAbi::SelectedEndRegisterV2
        );
        assert_eq!(*guard_publication_vl, None);
        assert_eq!(*guard_session_vl, None);
        assert_eq!(guard_identity.artifact_sha256, v8_identity.artifact_sha256);
        let guard_loss_session = guard_loss
            .begin_current_thread_session()
            .expect("guarded V8 facade current-thread session");
        let (_, guarded_execution) = guard_loss_session
            .find(&bytes, SearchLimits::unlimited())
            .expect("guarded V8 native session search");
        assert_eq!(
            guarded_execution.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(QualifiedExactSearchRoute::NativeJit)
        );
        let guard_artifact = artifact_hex(guard_identity.artifact_sha256);
        drop(guard);
        let (_, after_loss) = guard_loss_session
            .find(&bytes, SearchLimits::unlimited())
            .expect("session guard loss portable fallback");
        assert_eq!(
            after_loss.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(
                QualifiedExactSearchRoute::PortableLiteral
            )
        );
        println!(
            "fre-jit-auto-facade-v4\tcase=guard_loss\tpolicy=AsimdV8\tbackend=8\tabi=SelectedEndRegisterV2\tqualification=Candidate\tpublication_vl=none\tsession_vl=none\troute=PortableLiteral\tartifact_sha256={guard_artifact}\tstatus=PASS"
        );
    }

    #[test]
    fn candidate_public_builder_is_fail_closed_without_private_guard() {
        for atom in [
            QUALIFIED_EXACT_SEARCH_QUALIFICATION,
            QUALIFIED_EXACT_SEARCH_ASIMD_V8_QUALIFICATION,
            QUALIFIED_EXACT_SEARCH_SVE16_V6_QUALIFICATION,
            QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_QUALIFICATION,
            QUALIFIED_EXACT_SEARCH_SVE2_FIXED16_V2_QUALIFICATION,
        ] {
            assert_eq!(atom, QualifiedExactSearchQualification::Candidate);
            assert!(!atom.is_authorized());
        }
        let facade = PortableBuilder::new("0123456789abcdef")
            .build_qualified_exact_search(QualifiedExactSearchWorkload::new(
                QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
                QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
            ))
            .expect("Candidate public facade builds with its portable owner");
        let report = facade
            .qualified_build_report()
            .expect("exact literal retains its qualification report");
        assert_eq!(
            report.backend_policy,
            QualifiedExactSearchBackendPolicy::CURRENT
        );
        assert_eq!(
            report.native,
            QualifiedExactSearchNativeStatus::Unqualified {
                qualification: QualifiedExactSearchQualification::Candidate,
            }
        );
        let haystack = vec![b'x'; QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES];
        let session = facade
            .begin_current_thread_session()
            .expect("Candidate portable session needs no host contract");
        let (matched, execution) = session
            .find(&haystack, SearchLimits::unlimited())
            .expect("Candidate public facade session searches portably");
        assert_eq!(
            execution.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(
                QualifiedExactSearchRoute::PortableLiteral
            )
        );
        assert_eq!(
            session
                .find_value(&haystack, SearchLimits::unlimited())
                .expect("Candidate value-only facade session searches portably"),
            matched
        );
        assert_eq!(
            session
                .find_window_value(
                    &haystack,
                    SearchWindow::full(&haystack),
                    SearchLimits::unlimited(),
                )
                .expect("Candidate value-only window search remains portable"),
            matched
        );
        assert_eq!(
            session
                .is_match_value(&haystack, SearchLimits::unlimited())
                .expect("Candidate value-only existence search remains portable"),
            matched.is_some()
        );
    }

    #[test]
    fn explicit_public_policies_preserve_identity_and_fail_closed() {
        for backend_policy in [
            QualifiedExactSearchBackendPolicy::AsimdV8,
            QualifiedExactSearchBackendPolicy::Sve2Fixed16,
            QualifiedExactSearchBackendPolicy::Sve16V6,
            QualifiedExactSearchBackendPolicy::Sve2Fixed16V2,
        ] {
            let facade = PortableBuilder::new("0123456789abcdef")
                .build_qualified_exact_search_with_backend(
                    QualifiedExactSearchWorkload::new(
                        QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
                        QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
                    ),
                    backend_policy,
                )
                .expect("Candidate explicit-policy facade builds portably");
            let report = facade
                .qualified_build_report()
                .expect("exact literal retains its qualification report");
            assert_eq!(report.backend_policy, backend_policy);
            assert_eq!(
                report.qualification,
                QualifiedExactSearchQualification::Candidate
            );
            assert_eq!(
                report.native,
                QualifiedExactSearchNativeStatus::Unqualified {
                    qualification: QualifiedExactSearchQualification::Candidate,
                }
            );
        }
    }

    #[test]
    fn private_candidate_guard_preserves_native_path_coverage() {
        let guard = CandidateExecutionGuard::acquire();
        let literal = b"0123456789abcdef";
        let workload = QualifiedExactSearchWorkload::new(
            QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
            QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
        );
        let search = QualifiedExactSearch::with_limits_and_qualification(
            literal,
            workload,
            LiteralBuildLimits::default(),
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits::default(),
            TEST_QUALIFICATION,
        )
        .expect("guarded Candidate test subject builds or reports host refusal");
        assert_eq!(search.build_report().qualification, TEST_QUALIFICATION);
        let published = match &search.build_report().native {
            QualifiedExactSearchNativeStatus::Published { identity, .. } => {
                assert_eq!(identity.qualification, TEST_QUALIFICATION);
                true
            }
            QualifiedExactSearchNativeStatus::Unavailable(_) => false,
            other => panic!("guarded Candidate test subject was not admitted: {other:?}"),
        };
        if published {
            let haystack = vec![b'x'; QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES];
            let session = search
                .begin_current_thread_session()
                .expect("guarded V8 current-thread session");
            let (matched, execution) = session
                .find(&haystack, SearchLimits::unlimited())
                .expect("guarded Candidate native session search");
            assert_eq!(execution.route, QualifiedExactSearchRoute::NativeJit);
            assert_eq!(
                session
                    .find_value(&haystack, SearchLimits::unlimited())
                    .expect("guarded Candidate value-only native session search"),
                matched
            );
            assert_eq!(
                session
                    .is_match_value(&haystack, SearchLimits::unlimited())
                    .expect("guarded Candidate value-only native existence search"),
                matched.is_some()
            );

            // Losing the scoped test-only guard independently refuses a
            // retained native mapping even through an already-created session
            // while the qualification stays Candidate.
            drop(guard);
            let (fallback_match, execution) = session
                .find(&haystack, SearchLimits::unlimited())
                .expect("session guard loss falls back portably");
            assert_eq!(execution.route, QualifiedExactSearchRoute::PortableLiteral);
            assert_eq!(
                session
                    .find_value(&haystack, SearchLimits::unlimited())
                    .expect("value-only session guard loss falls back portably"),
                fallback_match
            );
        }
    }

    #[cfg(all(
        target_arch = "aarch64",
        any(target_os = "linux", target_os = "macos"),
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the retained-mapping fixture keeps exact admission, accounting, fallback, and invalid-window refusal in one safety sequence"
    )]
    fn retained_v8_native_preflight_is_exact_and_refuses_before_entry() {
        let _guard = CandidateExecutionGuard::acquire();
        let literal = b"0123456789abcdef";
        let workload = QualifiedExactSearchWorkload::new(
            QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
            QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
        );
        let search = QualifiedExactSearch::with_backend_limits_and_qualification(
            literal,
            workload,
            QualifiedExactSearchBackendPolicy::AsimdV8,
            LiteralBuildLimits::default(),
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits::default(),
            TEST_QUALIFICATION,
        )
        .expect("supported AArch64 host must construct the guarded V8 subject");
        let QualifiedExactSearchNativeStatus::Published { identity, .. } =
            &search.build_report().native
        else {
            panic!(
                "supported AArch64 host must retain a native mapping: {:?}",
                &search.build_report().native
            );
        };
        assert_eq!(
            identity.backend_policy,
            QualifiedExactSearchBackendPolicy::AsimdV8
        );
        assert_eq!(identity.backend, BackendVersion::SEARCH_V8);

        let mut haystack = vec![b'x'; QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES];
        let expected_start = haystack
            .len()
            .checked_sub(literal.len())
            .and_then(|end| end.checked_sub(17))
            .expect("bounded native fixture");
        let expected_end = expected_start
            .checked_add(literal.len())
            .expect("bounded expected match");
        haystack[expected_start..expected_end].copy_from_slice(literal);
        let exact_terms = haystack
            .len()
            .checked_add(literal.len())
            .expect("bounded exact linear terms");
        let exact_limits = SearchLimits {
            max_work: u64::try_from(exact_terms).expect("exact work fits u64"),
            max_scratch_bytes: 0,
        };
        let (matched, execution) = search
            .find(&haystack, exact_limits)
            .expect("exact cap admits the retained native route");
        assert_eq!(
            matched.map(|span| (span.start(), span.end())),
            Some((expected_start, expected_end))
        );
        assert_eq!(execution.route, QualifiedExactSearchRoute::PortableLiteral);
        assert_eq!(execution.accounting.linear_terms, exact_terms);

        let session = search
            .begin_current_thread_session()
            .expect("V8 current-thread session requires no fixed-VL query");
        let (session_matched, session_execution) = session
            .find(&haystack, exact_limits)
            .expect("V8 session shares the exact native preflight");
        assert_eq!(session_matched, matched);
        assert_eq!(
            session_execution.route,
            QualifiedExactSearchRoute::NativeJit
        );
        assert_eq!(session_execution.accounting, execution.accounting);
        assert_eq!(
            session
                .find_value(&haystack, exact_limits)
                .expect("V8 value-only session shares the exact native preflight"),
            session_matched
        );
        assert_eq!(
            session
                .find_window_value(&haystack, SearchWindow::full(&haystack), exact_limits)
                .expect("V8 value-only window shares the exact native preflight"),
            session_matched
        );
        assert_eq!(
            session
                .is_match_value(&haystack, exact_limits)
                .expect("V8 value-only existence search shares the native path"),
            session_matched.is_some()
        );

        let one_below = exact_terms.checked_sub(1).expect("positive exact work");
        let refused_limits = SearchLimits {
            max_work: u64::try_from(one_below).expect("one-below work fits u64"),
            max_scratch_bytes: 0,
        };
        let reporting_refusal = session
            .find(&haystack, refused_limits)
            .expect_err("one-below reporting session call must refuse");
        let value_refusal = session
            .find_value(&haystack, refused_limits)
            .expect_err("one-below value-only session call must refuse");
        assert_eq!(value_refusal, reporting_refusal);
        assert!(matches!(
            reporting_refusal,
            QualifiedExactSearchError::Portable(LiteralError::LinearTermLimit {
                needed,
                limit
            }) if needed == exact_terms && limit == one_below
        ));
        assert!(matches!(
            search.find(
                &haystack,
                refused_limits,
            ),
            Err(QualifiedExactSearchError::Portable(
                LiteralError::LinearTermLimit { needed, limit }
            )) if needed == exact_terms && limit == one_below
        ));

        let small_window = SearchWindow::new(1, haystack.len());
        let small_terms = small_window
            .end()
            .checked_sub(small_window.start())
            .and_then(|bytes| bytes.checked_add(literal.len()))
            .expect("bounded small-window work");
        let (matched, execution) = search
            .find_window(
                &haystack,
                small_window,
                SearchLimits {
                    max_work: u64::try_from(small_terms).expect("small work fits u64"),
                    max_scratch_bytes: 0,
                },
            )
            .expect("below-threshold retained-native call remains portable");
        assert_eq!(
            matched.map(|span| (span.start(), span.end())),
            Some((expected_start, expected_end))
        );
        assert_eq!(execution.route, QualifiedExactSearchRoute::PortableLiteral);
        assert_eq!(execution.accounting.linear_terms, small_terms);
        assert_eq!(
            session
                .find_window_value(
                    &haystack,
                    small_window,
                    SearchLimits {
                        max_work: u64::try_from(small_terms).expect("small work fits u64"),
                        max_scratch_bytes: 0,
                    },
                )
                .expect("value-only below-threshold call remains portable"),
            matched
        );

        let before_end = haystack.len().checked_sub(1).expect("nonempty haystack");
        let past_end = haystack.len().checked_add(1).expect("bounded haystack");
        for invalid in [
            SearchWindow::new(haystack.len(), before_end),
            SearchWindow::new(0, past_end),
        ] {
            assert!(matches!(
                search.find_window(&haystack, invalid, SearchLimits::unlimited()),
                Err(QualifiedExactSearchError::Portable(
                    LiteralError::InvalidWindow {
                        start,
                        end,
                        haystack_len,
                    }
                )) if start == invalid.start()
                    && end == invalid.end()
                    && haystack_len == haystack.len()
            ));
            let reporting_error = session
                .find_window(&haystack, invalid, SearchLimits::unlimited())
                .expect_err("invalid reporting window must refuse");
            let value_error = session
                .find_window_value(&haystack, invalid, SearchLimits::unlimited())
                .expect_err("invalid value-only window must refuse");
            assert_eq!(value_error, reporting_error);
        }
    }

    #[test]
    fn private_candidate_guard_preserves_facade_routing_and_scope_loss() {
        let guard = CandidateExecutionGuard::acquire();
        let workload = QualifiedExactSearchWorkload::new(
            QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
            QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
        );
        let facade = QualifiedExactSearchFacade::from_builder_with_qualification(
            PortableBuilder::new("0123456789abcdef"),
            workload,
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits::default(),
            TEST_QUALIFICATION,
        )
        .expect("guarded Candidate facade builds or reports host refusal");
        assert_eq!(
            facade.selection(),
            QualifiedExactSearchFacadeSelection::ExactLiteral
        );
        let published = matches!(
            facade
                .qualified_build_report()
                .expect("exact build report")
                .native,
            QualifiedExactSearchNativeStatus::Published { .. }
        );
        let haystack = vec![b'x'; QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES];
        let session = facade
            .begin_current_thread_session()
            .expect("guarded V8 facade current-thread session");
        let (matched, execution) = session
            .find(&haystack, SearchLimits::unlimited())
            .expect("guarded Candidate facade session search");
        assert_eq!(
            execution.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(if published {
                QualifiedExactSearchRoute::NativeJit
            } else {
                QualifiedExactSearchRoute::PortableLiteral
            })
        );
        assert_eq!(
            session
                .find_value(&haystack, SearchLimits::unlimited())
                .expect("guarded Candidate value-only facade session search"),
            matched
        );
        assert_eq!(
            session
                .is_match_value(&haystack, SearchLimits::unlimited())
                .expect("guarded Candidate value-only facade existence search"),
            matched.is_some()
        );

        if published {
            drop(guard);
            let (fallback_match, execution) = session
                .find(&haystack, SearchLimits::unlimited())
                .expect("facade session guard loss falls back portably");
            assert_eq!(
                execution.route,
                QualifiedExactSearchFacadeRoute::ExactLiteral(
                    QualifiedExactSearchRoute::PortableLiteral
                )
            );
            assert_eq!(
                session
                    .find_value(&haystack, SearchLimits::unlimited())
                    .expect("value-only facade session guard loss falls back portably"),
                fallback_match
            );
        }
    }

    #[cfg(all(
        target_arch = "aarch64",
        any(target_os = "macos", target_os = "linux"),
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    #[test]
    fn private_candidate_guard_reaches_publication_refusal() {
        let _guard = CandidateExecutionGuard::acquire();
        let search = QualifiedExactSearch::with_limits_and_qualification(
            b"0123456789abcdef",
            QualifiedExactSearchWorkload::new(
                QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
                QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
            ),
            LiteralBuildLimits::default(),
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits {
                max_code_bytes: 0,
                ..PublicationLimits::default()
            },
            TEST_QUALIFICATION,
        )
        .expect("publication refusal is retained as native status");
        assert!(matches!(
            &search.build_report().native,
            QualifiedExactSearchNativeStatus::Unavailable(PublishError::ResourceLimit {
                resource: fre_jit_runtime::ResourceKind::CodeBytes,
                limit: 0,
                required,
            }) if *required > 0
        ));
    }

    #[cfg(all(
        target_arch = "aarch64",
        any(target_os = "macos", target_os = "linux"),
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    #[test]
    fn private_candidate_guard_facade_publication_refusal_falls_back_observably() {
        let _guard = CandidateExecutionGuard::acquire();
        let facade = QualifiedExactSearchFacade::from_builder_with_qualification(
            PortableBuilder::new("0123456789abcdef"),
            QualifiedExactSearchWorkload::new(
                QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
                QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
            ),
            ValidateLimits::default(),
            EmitLimits::default(),
            PublicationLimits {
                max_code_bytes: 0,
                ..PublicationLimits::default()
            },
            TEST_QUALIFICATION,
        )
        .expect("publication refusal remains a retained status");
        assert!(matches!(
            &facade
                .qualified_build_report()
                .expect("exact build report")
                .native,
            QualifiedExactSearchNativeStatus::Unavailable(PublishError::ResourceLimit {
                resource: fre_jit_runtime::ResourceKind::CodeBytes,
                limit: 0,
                required,
            }) if *required > 0
        ));
        let haystack = vec![b'x'; QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES];
        let (_, execution) = facade
            .find(&haystack, SearchLimits::unlimited())
            .expect("publication refusal uses portable owner");
        assert_eq!(
            execution.route,
            QualifiedExactSearchFacadeRoute::ExactLiteral(
                QualifiedExactSearchRoute::PortableLiteral
            )
        );
    }

    #[cfg(not(all(
        target_arch = "aarch64",
        any(target_os = "macos", target_os = "linux"),
        target_pointer_width = "64",
        target_endian = "little"
    )))]
    #[test]
    fn private_candidate_guard_facade_unsupported_host_precedes_emission() {
        let _guard = CandidateExecutionGuard::acquire();
        let facade = QualifiedExactSearchFacade::from_builder_with_qualification(
            PortableBuilder::new("0123456789abcdef"),
            QualifiedExactSearchWorkload::new(
                QUALIFIED_EXACT_SEARCH_MIN_WINDOW_BYTES,
                QUALIFIED_EXACT_SEARCH_MIN_SEARCHES,
            ),
            ValidateLimits::default(),
            EmitLimits {
                max_code_bytes: 0,
                ..EmitLimits::default()
            },
            PublicationLimits::default(),
            TEST_QUALIFICATION,
        )
        .expect("unsupported host avoids target-specific emission");
        assert!(matches!(
            &facade
                .qualified_build_report()
                .expect("exact build report")
                .native,
            QualifiedExactSearchNativeStatus::Unavailable(PublishError::UnsupportedHost { .. })
        ));
    }
}
