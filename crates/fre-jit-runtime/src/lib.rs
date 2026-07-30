//! Audited executable-memory publication for FRE native images.
//!
//! The admitted publishers use strict-W^X on `AArch64` macOS and Linux. Plain
//! images re-run the same independent whole-image auditor at each runtime trust
//! boundary. Those repeats detect intervening mutation but add no independent
//! audit-logic coverage. [`AuditedNativeImage`] instead carries that auditor's
//! successful emitter-finalization result through an immutable, privately
//! constructed typestate boundary. Both paths copy between inaccessible guard
//! pages, byte-verify the complete payload, change it from writable to
//! executable (never both), and synchronize the instruction cache before
//! exposing a callable object. Other hosts and hardened-runtime configurations
//! that deny this sequence return typed errors.
//!
//! Generated code is leaf-only and cannot unwind. Unix signals and Mach
//! exceptions raised by generated code are deliberately outside this API's
//! recovery contract and must not cross the native call boundary.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(unsafe_code)]

mod error;
mod identity;
mod limits;
mod operation;
mod platform;
mod selected_end_register_v2;

use core::{fmt, marker::PhantomData};
use std::{rc::Rc, sync::Arc};

use fre_jit_aarch64::{BackendVersion, CpuFeatures, TargetSpec, audit, audit_aggregate};
use fre_kernel_ir::{
    AggregateExecutionLimits, CheckedSearchWindow, SearchWindow, preflight_exact_aggregate,
};
use fre_target_features::TuningClass;

pub use error::{
    ArithmeticSite, CallError, FailureStage, HostSupportReason, KernelThreadContractError,
    PublishError, ResourceKind, WxMode,
};
pub use fre_jit_aarch64::{AuditedNativeImage, NativeAggregateImage, NativeImage};
pub use fre_kernels::{
    LiteralAccounting, LiteralError, LiteralSearchLimits, LiteralSearchPreflight,
};
pub use identity::RuntimeIdentity;
pub use limits::{PublicationAccounting, PublicationLimits};
pub use operation::{RuntimeAggregateOperation, RuntimeOperation};
pub use selected_end_register_v2::{
    PublishedSelectedEndRegisterPlanThreadSessionV2, PublishedSelectedEndRegisterThreadSessionV2,
    PublishedSelectedEndRegisterV2, SelectedEndRegisterCallErrorV2,
    native_selected_end_register_backend_support_v2, publish_selected_end_register_v2,
};

use crate::{limits::PublicationPlan, platform::ExecutableMapping};

/// Process-visible `AArch64` features admitted by the native publisher.
///
/// `sve_vector_bytes` is an observation of the calling Linux thread. It is
/// `None` when SVE is absent or the query is unavailable. Most fixed-lane
/// images use predication and do not bind to this value. Legacy Search-v1
/// fixed16 tags 10, 19, and 21 require and record exactly 16 bytes at
/// construction and publication. The qualified register-return ABI2
/// tag-19/tag-21 routes instead use feature-only publication admission and
/// defer their one VL16 observation to current-thread session construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHostCapabilities {
    asimd: bool,
    sve: bool,
    sve2: bool,
    sve_vector_bytes: Option<u16>,
}

impl NativeHostCapabilities {
    pub(crate) const fn new(
        asimd: bool,
        sve: bool,
        sve2: bool,
        sve_vector_bytes: Option<u16>,
    ) -> Self {
        Self {
            asimd,
            sve,
            sve2,
            sve_vector_bytes,
        }
    }

    #[must_use]
    pub const fn has_asimd(self) -> bool {
        self.asimd
    }

    #[must_use]
    pub const fn has_sve(self) -> bool {
        self.sve
    }

    #[must_use]
    pub const fn has_sve2(self) -> bool {
        self.sve2
    }

    #[must_use]
    pub const fn sve_vector_bytes(self) -> Option<u16> {
        self.sve_vector_bytes
    }
}

/// Check whether this process implements the native publication target.
///
/// Facades may call this before constructing a target-specific image so an
/// unsupported host pays no Kernel IR, emission, audit, or mapping work.
pub fn native_host_support() -> Result<(), PublishError> {
    platform::ensure_host_supported()
}

/// Discover native `AArch64` features exposed to this process.
///
/// Linux activation comes from `AT_HWCAP`/`AT_HWCAP2`. If SVE is active, the
/// current per-thread vector length is queried. Search-v1 tags 10 and 21
/// use that value for construction/publication admission; callers may also
/// report it in hardware qualification evidence. Register-return ABI2 tags 19
/// and 21 use a separate feature-only admission helper and query VL only when
/// opening a callable current-thread session.
pub fn native_host_capabilities() -> Result<NativeHostCapabilities, PublishError> {
    platform::capabilities()
}

const SEARCH_FIXED16_VECTOR_BYTES: u16 = 16;
const SEARCH_FIXED16_TUNING_NAME: &str = "arm-41-d84";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SearchHostAdmission {
    sve_vector_bytes_at_publication: Option<u16>,
}

const fn required_search_sve_vector_bytes(backend: BackendVersion) -> Option<u16> {
    match backend {
        BackendVersion::SEARCH_SVE2_16_V1
        | BackendVersion::SEARCH_SVE16_V6
        | BackendVersion::SEARCH_SVE2_FIXED16_V2 => Some(SEARCH_FIXED16_VECTOR_BYTES),
        _ => None,
    }
}

const fn search_backend_requires_capability_snapshot(backend: BackendVersion) -> bool {
    matches!(
        backend,
        BackendVersion::SEARCH_SVE16_V1
            | BackendVersion::SEARCH_SVE2_16_V1
            | BackendVersion::SEARCH_SVE16_V6
            | BackendVersion::SEARCH_SVE2_FIXED16_V2
    )
}

const fn search_backend_requires_fixed16_tuning(backend: BackendVersion) -> bool {
    matches!(
        backend,
        BackendVersion::SEARCH_SVE2_16_V1
            | BackendVersion::SEARCH_SVE16_V6
            | BackendVersion::SEARCH_SVE2_FIXED16_V2
    )
}

fn validate_search_sve_vector_bytes(
    backend: BackendVersion,
    actual: Option<u16>,
) -> Result<Option<u16>, PublishError> {
    let Some(expected) = required_search_sve_vector_bytes(backend) else {
        return Ok(None);
    };
    if actual != Some(expected) {
        return Err(PublishError::SveVectorLengthMismatch { expected, actual });
    }
    Ok(Some(expected))
}

fn validate_search_backend_capabilities(
    backend: BackendVersion,
    capabilities: NativeHostCapabilities,
) -> Result<Option<u16>, PublishError> {
    if matches!(
        backend,
        BackendVersion::SEARCH_SVE2_16_V1
            | BackendVersion::SEARCH_SVE16_V6
            | BackendVersion::SEARCH_SVE2_FIXED16_V2
    ) && !capabilities.has_asimd()
    {
        return Err(PublishError::CpuFeatureUnavailable { feature: "asimd" });
    }
    if matches!(
        backend,
        BackendVersion::SEARCH_SVE16_V1
            | BackendVersion::SEARCH_SVE2_16_V1
            | BackendVersion::SEARCH_SVE16_V6
            | BackendVersion::SEARCH_SVE2_FIXED16_V2
    ) && !capabilities.has_sve()
    {
        return Err(PublishError::CpuFeatureUnavailable { feature: "sve" });
    }
    if matches!(
        backend,
        BackendVersion::SEARCH_SVE2_16_V1 | BackendVersion::SEARCH_SVE2_FIXED16_V2
    ) && !capabilities.has_sve2()
    {
        return Err(PublishError::CpuFeatureUnavailable { feature: "sve2" });
    }
    validate_search_sve_vector_bytes(backend, capabilities.sve_vector_bytes())
}

fn validate_search_backend_tuning(
    backend: BackendVersion,
    tuning: TuningClass,
) -> Result<(), PublishError> {
    if !search_backend_requires_fixed16_tuning(backend) {
        return Ok(());
    }
    if matches!(
        tuning,
        TuningClass::ArmServer { cpu: Some(cpu) }
            if cpu.implementer == 0x41 && cpu.part == 0x0d84
    ) {
        return Ok(());
    }
    Err(PublishError::CpuTuningUnavailable {
        required: SEARCH_FIXED16_TUNING_NAME,
    })
}

#[inline]
pub(crate) fn search_vector_length_contract_valid(
    backend: BackendVersion,
    actual: Option<u16>,
) -> bool {
    validate_search_sve_vector_bytes(backend, actual).is_ok()
        && (required_search_sve_vector_bytes(backend).is_some() || actual.is_none())
}

fn search_host_admission(backend: BackendVersion) -> Result<SearchHostAdmission, PublishError> {
    let sve_vector_bytes_at_publication = if search_backend_requires_capability_snapshot(backend) {
        let capabilities = platform::capabilities()?;
        validate_search_backend_capabilities(backend, capabilities)?
    } else {
        platform::ensure_host_supported()?;
        None
    };
    if search_backend_requires_fixed16_tuning(backend) {
        validate_search_backend_tuning(backend, fre_target_features::host().tuning())?;
    }
    Ok(SearchHostAdmission {
        sve_vector_bytes_at_publication,
    })
}

/// Check host admission for one exact search backend before emission.
///
/// Legacy search tag 9 requires OS-usable SVE before emission. Search tag 10
/// requires ASIMD, SVE, SVE2, calling-thread vector length 16, and the
/// homogeneous Arm `0x41/0xd84` host class named by its independent
/// performance-qualification scope. The qualified public facade has no legacy
/// Search-v1 tag-19 route: its typed register-return ABI2 boundary owns tag
/// 19's ASIMD, SVE, vector-length 16, and same-host-class contract without
/// requiring SVE2. Versioned low-level legacy emitter and publisher APIs
/// remain available for research and compatibility, outside facade
/// qualification and promotion.
/// Candidate Search-v1 tag 21 restores the tag-10 SVE2 requirements for its
/// paired-ASIMD and predicate-recovery graph. These construction-time checks
/// are repeated independently at publication; generated-code calls do not
/// perform a `prctl` syscall. Register-return ABI2 callers use
/// [`native_selected_end_register_backend_support_v2`] instead, deferring the
/// tag19/tag21 VL check to session construction.
pub fn native_search_backend_support(backend: BackendVersion) -> Result<(), PublishError> {
    search_host_admission(backend).map(|_| ())
}

/// Invoke one published kernel through the qualification-only AAPCS64 vector
/// callee-saved-lane canary.
#[cfg(all(
    feature = "sve-hardware-qualification",
    target_arch = "aarch64",
    any(target_os = "macos", target_os = "linux"),
    target_pointer_width = "64",
    target_endian = "little"
))]
#[doc(hidden)]
pub fn qualification_preserves_vector_callee_saved_lanes<O: RuntimeOperation>(
    kernel: &PublishedKernel<O>,
    haystack: &[u8],
    window: SearchWindow,
    canaries: [u64; 8],
) -> Result<bool, CallError> {
    if window.start() > window.end() || window.end() > haystack.len() {
        return Err(CallError::InvalidWindow {
            start: window.start(),
            end: window.end(),
            haystack_len: haystack.len(),
        });
    }
    if kernel.mapping.identity() != kernel.identity
        || kernel.mapping.output() != O::KIND
        || !kernel.mapping.call_contract_valid(O::KIND)
    {
        return Err(CallError::PublicationIdentityMismatch);
    }
    let (raw, observed) = platform::invoke_with_vector_callee_saved_canary(
        &kernel.mapping,
        haystack,
        window,
        canaries,
    );
    operation::decode::<O>(raw, window)?;
    Ok(observed == canaries)
}

/// Place one qualification haystack directly against an inaccessible guard
/// page for a single higher-ranked callback.
///
/// This helper is feature-gated and doc-hidden because it is evidence
/// infrastructure, not a production search API.
#[cfg(all(
    feature = "sve-hardware-qualification",
    target_arch = "aarch64",
    any(target_os = "macos", target_os = "linux"),
    target_pointer_width = "64",
    target_endian = "little"
))]
#[doc(hidden)]
pub fn qualification_with_guarded_haystack<T>(
    bytes: &[u8],
    at_right_boundary: bool,
    callback: impl for<'haystack> FnOnce(&'haystack [u8]) -> T,
) -> Result<T, PublishError> {
    platform::with_guarded_haystack(bytes, at_right_boundary, callback)
}

/// An immutable, reference-counted native kernel with a typed output contract.
///
/// Cloning is cheap. The executable mapping remains owned for every call
/// borrow, so dropping another clone cannot race an in-progress call. The
/// final clone unmaps the code only after all such borrows have ended.
pub struct PublishedKernel<O: RuntimeOperation> {
    mapping: Arc<ExecutableMapping>,
    entry: platform::SearchEntry,
    identity: RuntimeIdentity,
    accounting: PublicationAccounting,
    operation: PhantomData<fn() -> O>,
}

/// Current-thread invocation token for one already published search kernel.
///
/// Construction relies on the immutable contract sealed before publication.
/// Fixed-VL SVE/SVE2 kernels additionally observe the calling thread's vector
/// length once and require it to match the value authenticated at publication.
/// The token is deliberately neither `Send` nor `Sync`: changing the calling
/// thread's SVE vector length invalidates it and requires a new token.
///
/// Calls through this token retain the checked window and native-result
/// boundary, but do not repeat immutable mapping, target, feature, identity,
/// or vector-length checks in the hot path.
pub struct PublishedKernelThreadSession<'kernel, O: RuntimeOperation> {
    kernel: &'kernel PublishedKernel<O>,
    thread_bound: PhantomData<Rc<()>>,
}

/// Immutable one-call whole-haystack aggregate kernel.
pub struct PublishedAggregateKernel<A: RuntimeAggregateOperation> {
    mapping: Arc<ExecutableMapping>,
    identity: RuntimeIdentity,
    accounting: PublicationAccounting,
    literal_bytes: u32,
    operation: PhantomData<fn() -> A>,
}

impl<O: RuntimeOperation> Clone for PublishedKernel<O> {
    fn clone(&self) -> Self {
        Self {
            mapping: Arc::clone(&self.mapping),
            entry: self.entry,
            identity: self.identity,
            accounting: self.accounting,
            operation: PhantomData,
        }
    }
}

impl<A: RuntimeAggregateOperation> Clone for PublishedAggregateKernel<A> {
    fn clone(&self) -> Self {
        Self {
            mapping: Arc::clone(&self.mapping),
            identity: self.identity,
            accounting: self.accounting,
            literal_bytes: self.literal_bytes,
            operation: PhantomData,
        }
    }
}

impl<O: RuntimeOperation> fmt::Debug for PublishedKernel<O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedKernel")
            .field("output", &O::KIND)
            .field("identity", &self.identity)
            .field("accounting", &self.accounting)
            .field(
                "sve_vector_bytes_at_publication",
                &self.mapping.sve_vector_bytes_at_publication(),
            )
            .finish_non_exhaustive()
    }
}

impl<O: RuntimeOperation> fmt::Debug for PublishedKernelThreadSession<'_, O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedKernelThreadSession")
            .field("output", &O::KIND)
            .field("identity", &self.kernel.identity)
            .field(
                "sve_vector_bytes_at_publication",
                &self.kernel.mapping.sve_vector_bytes_at_publication(),
            )
            .finish_non_exhaustive()
    }
}

impl<A: RuntimeAggregateOperation> fmt::Debug for PublishedAggregateKernel<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedAggregateKernel")
            .field("output", &A::OUTPUT)
            .field("literal_bytes", &self.literal_bytes)
            .field("identity", &self.identity)
            .field("accounting", &self.accounting)
            .finish_non_exhaustive()
    }
}

impl<O: RuntimeOperation> PublishedKernel<O> {
    /// Execute within a checked half-open byte window.
    ///
    /// Native code is passed the complete slice length so whole-haystack
    /// anchors retain their Kernel IR meaning. No raw pointer or result slot
    /// escapes this method. All immutable mapping and host facts were checked
    /// before publication; this boundary checks only per-call state.
    ///
    /// For a fixed-VL SVE/SVE2 kernel this direct boundary preserves the
    /// publisher's deployment assumption that calling threads retain the
    /// recorded vector length. Callers that need an independently checked
    /// current-thread proof should use [`Self::begin_current_thread_session`].
    #[inline]
    pub fn search(&self, haystack: &[u8], window: SearchWindow) -> Result<O::Output, CallError> {
        let checked =
            CheckedSearchWindow::new(haystack, window).ok_or(CallError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            })?;
        self.search_checked(checked)
    }

    /// Execute from a private-field proof that already binds window bounds to
    /// the borrowed haystack.
    #[doc(hidden)]
    #[inline]
    pub fn search_checked(&self, checked: CheckedSearchWindow<'_>) -> Result<O::Output, CallError> {
        self.search_after_publication_contract(checked)
    }

    /// Establish one current-thread session for repeated native calls.
    ///
    /// Non-fixed-VL kernels perform no system call. Fixed-VL SVE/SVE2 kernels
    /// query the calling thread once and require the exact vector length
    /// recorded at publication. The immutable mapping contract is already
    /// sealed by `publish`; session creation does not redundantly re-audit it.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<PublishedKernelThreadSession<'_, O>, KernelThreadContractError> {
        if let Some(expected) = self.mapping.sve_vector_bytes_at_publication() {
            let actual = platform::current_thread_sve_vector_bytes()
                .map_err(KernelThreadContractError::HostCapabilities)?;
            if actual != Some(expected) {
                return Err(
                    KernelThreadContractError::RequiredSveVectorLengthUnavailable {
                        required_bytes: expected,
                        actual_bytes: actual,
                    },
                );
            }
        }
        Ok(PublishedKernelThreadSession {
            kernel: self,
            thread_bound: PhantomData,
        })
    }

    #[inline]
    fn search_after_publication_contract(
        &self,
        checked: CheckedSearchWindow<'_>,
    ) -> Result<O::Output, CallError> {
        let haystack = checked.haystack();
        let window = checked.window();
        debug_assert_eq!(self.mapping.identity(), self.identity);
        debug_assert_eq!(self.mapping.output(), O::KIND);
        debug_assert!(self.mapping.call_contract_valid(O::KIND));
        let raw = self.entry.invoke::<O>(haystack, window);
        operation::decode::<O>(raw, window)
    }

    /// Exact page/code/data accounting charged at publication.
    #[must_use]
    pub const fn accounting(&self) -> PublicationAccounting {
        self.accounting
    }

    /// Content identity retained from the authenticated source image.
    #[must_use]
    pub const fn identity(&self) -> RuntimeIdentity {
        self.identity
    }

    /// SVE vector length bound into this search publication, if required.
    ///
    /// Search tags 10, 19, and 21 return `Some(16)`. Other admitted backends
    /// return `None`. Publication validates and records this immutable fact;
    /// current-thread sessions independently check the calling thread without
    /// a per-call host syscall.
    #[must_use]
    pub fn sve_vector_bytes_at_publication(&self) -> Option<u16> {
        self.mapping.sve_vector_bytes_at_publication()
    }

    /// Whether independently checked invocation uses a current-thread token.
    ///
    /// Direct calls retain the documented deployment assumption for backward
    /// compatibility. A `true` result tells a stricter caller to establish a
    /// [`PublishedKernelThreadSession`] before repeated execution.
    #[must_use]
    pub fn requires_current_thread_session(&self) -> bool {
        self.mapping.sve_vector_bytes_at_publication().is_some()
    }

    /// Whether this handle uniquely owns its executable mapping.
    ///
    /// Bounded caches use this only at ownership-transfer admission. It does
    /// not weaken the mapping's immutable call contract.
    #[doc(hidden)]
    #[must_use]
    pub fn has_unique_mapping_ownership(&self) -> bool {
        Arc::strong_count(&self.mapping) == 1
    }
}

impl<O: RuntimeOperation> PublishedKernelThreadSession<'_, O> {
    /// Execute within a checked half-open byte window under the established
    /// current-thread publication contract.
    #[inline]
    pub fn search(&self, haystack: &[u8], window: SearchWindow) -> Result<O::Output, CallError> {
        self.kernel.search(haystack, window)
    }

    /// Execute from an already checked window under this thread contract.
    #[doc(hidden)]
    #[inline]
    pub fn search_checked(&self, checked: CheckedSearchWindow<'_>) -> Result<O::Output, CallError> {
        self.kernel.search_after_publication_contract(checked)
    }

    /// The immutable published kernel borrowed by this session.
    #[must_use]
    pub const fn kernel(&self) -> &PublishedKernel<O> {
        self.kernel
    }
}

impl<A: RuntimeAggregateOperation> PublishedAggregateKernel<A> {
    /// Execute one complete, preflighted native aggregate call.
    pub fn aggregate(
        &self,
        haystack: &[u8],
        limits: AggregateExecutionLimits,
    ) -> Result<u64, CallError> {
        if self.mapping.identity() != self.identity
            || !self
                .mapping
                .aggregate_contract_valid(A::OUTPUT, self.literal_bytes)
        {
            return Err(CallError::PublicationIdentityMismatch);
        }
        let literal_len = usize::try_from(self.literal_bytes)
            .map_err(|_| CallError::PublicationIdentityMismatch)?;
        preflight_exact_aggregate(haystack.len(), literal_len, A::OUTPUT, limits)
            .map_err(CallError::AggregatePreflight)?;
        let raw = self.mapping.invoke_aggregate(haystack)?;
        operation::decode_aggregate::<A>(raw, haystack.len(), literal_len)
    }

    #[must_use]
    pub const fn accounting(&self) -> PublicationAccounting {
        self.accounting
    }

    #[must_use]
    pub const fn identity(&self) -> RuntimeIdentity {
        self.identity
    }

    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        self.literal_bytes
    }
}

/// Publish one already-emitted image for a compile-time checked output type.
///
/// The returned object is the first point at which a callable entry exists.
/// Every earlier failure follows an unpublished cleanup path.
pub fn publish<O: RuntimeOperation>(
    image: &NativeImage,
    limits: PublicationLimits,
) -> Result<PublishedKernel<O>, PublishError> {
    publish_impl::<O>(image, limits, platform::FailureInjection::None)
}

/// Publish an immutable image carrying the emitter's successful final audit.
///
/// The private construction boundary of [`AuditedNativeImage`] prevents this
/// path from accepting arbitrary or subsequently mutated images. Publication
/// still performs host and output admission, resource planning, exact byte
/// copy verification, strict W^X, and all final mapping-contract checks.
pub fn publish_audited<O: RuntimeOperation>(
    image: &AuditedNativeImage,
    limits: PublicationLimits,
) -> Result<PublishedKernel<O>, PublishError> {
    publish_audited_impl::<O>(image, limits, platform::FailureInjection::None)
}

/// Publish one separately typed aggregate image under strict W^X.
pub fn publish_aggregate<A: RuntimeAggregateOperation>(
    image: &NativeAggregateImage,
    limits: PublicationLimits,
) -> Result<PublishedAggregateKernel<A>, PublishError> {
    publish_aggregate_impl::<A>(image, limits, platform::FailureInjection::None)
}

fn publish_impl<O: RuntimeOperation>(
    image: &NativeImage,
    limits: PublicationLimits,
    failure: platform::FailureInjection,
) -> Result<PublishedKernel<O>, PublishError> {
    let admission = preflight::<O>(image)?;
    let page_bytes = platform::page_size()?;
    let plan = PublicationPlan::new(image, page_bytes, limits)?;
    let identity = RuntimeIdentity::from_preflight_image(image);

    // This second invocation of the independent auditor is intentionally
    // adjacent to publication. The platform path invokes that same auditor a
    // third time after byte verification and before its RX transition.
    audit(image).map_err(PublishError::ImageAudit)?;
    let mapping = platform::publish(
        image,
        plan,
        identity,
        admission.sve_vector_bytes_at_publication,
        failure,
    )?;
    if mapping.identity() != identity
        || mapping.output() != O::KIND
        || !mapping.call_contract_valid(O::KIND)
    {
        return Err(PublishError::PublicationIdentityMismatch);
    }
    let entry = mapping.search_entry();
    Ok(PublishedKernel {
        mapping: Arc::new(mapping),
        entry,
        identity,
        accounting: plan.accounting,
        operation: PhantomData,
    })
}

fn publish_audited_impl<O: RuntimeOperation>(
    audited: &AuditedNativeImage,
    limits: PublicationLimits,
    failure: platform::FailureInjection,
) -> Result<PublishedKernel<O>, PublishError> {
    let image = audited.as_image();
    let admission = preflight_audited::<O>(audited)?;
    let page_bytes = platform::page_size()?;
    let plan = PublicationPlan::new(image, page_bytes, limits)?;
    let identity = RuntimeIdentity::from_preflight_image(image);

    let mapping = platform::publish_audited(
        audited,
        plan,
        identity,
        admission.sve_vector_bytes_at_publication,
        failure,
    )?;
    if mapping.identity() != identity
        || mapping.output() != O::KIND
        || !mapping.call_contract_valid(O::KIND)
    {
        return Err(PublishError::PublicationIdentityMismatch);
    }
    let entry = mapping.search_entry();
    Ok(PublishedKernel {
        mapping: Arc::new(mapping),
        entry,
        identity,
        accounting: plan.accounting,
        operation: PhantomData,
    })
}

fn publish_aggregate_impl<A: RuntimeAggregateOperation>(
    image: &NativeAggregateImage,
    limits: PublicationLimits,
    failure: platform::FailureInjection,
) -> Result<PublishedAggregateKernel<A>, PublishError> {
    preflight_aggregate::<A>(image)?;
    let page_bytes = platform::page_size()?;
    let plan = PublicationPlan::new_aggregate(image, page_bytes, limits)?;
    let identity = RuntimeIdentity::from_preflight_aggregate_image(image);

    audit_aggregate(image).map_err(PublishError::ImageAudit)?;
    let mapping = platform::publish_aggregate(image, plan, identity, failure)?;
    if mapping.identity() != identity
        || !mapping.aggregate_contract_valid(A::OUTPUT, image.literal_bytes())
    {
        return Err(PublishError::PublicationIdentityMismatch);
    }
    Ok(PublishedAggregateKernel {
        mapping: Arc::new(mapping),
        identity,
        accounting: plan.accounting,
        literal_bytes: image.literal_bytes(),
        operation: PhantomData,
    })
}

fn preflight<O: RuntimeOperation>(
    image: &NativeImage,
) -> Result<SearchHostAdmission, PublishError> {
    preflight_search_backend_version(image)?;
    let admission = search_host_admission(image.backend_version())?;
    audit(image).map_err(PublishError::ImageAudit)?;
    preflight_search_contract::<O>(image)?;
    Ok(admission)
}

fn preflight_audited<O: RuntimeOperation>(
    audited: &AuditedNativeImage,
) -> Result<SearchHostAdmission, PublishError> {
    let image = audited.as_image();
    preflight_search_backend_version(image)?;
    let admission = search_host_admission(image.backend_version())?;
    preflight_search_contract::<O>(image)?;
    Ok(admission)
}

fn preflight_search_contract<O: RuntimeOperation>(image: &NativeImage) -> Result<(), PublishError> {
    let target = image.target();
    let baseline = TargetSpec::AARCH64_AAPCS64;
    if target.architecture != baseline.architecture
        || target.little_endian != baseline.little_endian
        || target.pointer_width != baseline.pointer_width
        || target.abi != baseline.abi
    {
        return Err(PublishError::TargetMismatch);
    }
    let known_features = CpuFeatures::ASIMD_SVE2.bits();
    if target.features.bits() & !known_features != 0 {
        return Err(PublishError::UnknownCpuFeatures {
            bits: target.features.bits(),
        });
    }
    if target.features.contains(CpuFeatures::ASIMD) && !platform::has_asimd() {
        return Err(PublishError::CpuFeatureUnavailable { feature: "asimd" });
    }
    if target.features.contains(CpuFeatures::SVE) && !platform::has_sve() {
        return Err(PublishError::CpuFeatureUnavailable { feature: "sve" });
    }
    if target.features.contains(CpuFeatures::SVE2) && !platform::has_sve2() {
        return Err(PublishError::CpuFeatureUnavailable { feature: "sve2" });
    }
    if image.output() != O::KIND {
        return Err(PublishError::OutputContractMismatch {
            expected: O::KIND,
            actual: image.output(),
        });
    }
    Ok(())
}

fn preflight_aggregate<A: RuntimeAggregateOperation>(
    image: &NativeAggregateImage,
) -> Result<(), PublishError> {
    platform::ensure_host_supported()?;
    preflight_aggregate_backend_version(image)?;
    audit_aggregate(image).map_err(PublishError::ImageAudit)?;
    let target = image.target();
    let baseline = TargetSpec::AARCH64_AAPCS64;
    if target.architecture != baseline.architecture
        || target.little_endian != baseline.little_endian
        || target.pointer_width != baseline.pointer_width
        || target.abi != baseline.abi
    {
        return Err(PublishError::TargetMismatch);
    }
    let known_features = CpuFeatures::ASIMD
        .union(CpuFeatures::SVE)
        .union(CpuFeatures::SVE2)
        .bits();
    if target.features.bits() & !known_features != 0 {
        return Err(PublishError::UnknownCpuFeatures {
            bits: target.features.bits(),
        });
    }
    if target.features.contains(CpuFeatures::ASIMD) && !platform::has_asimd() {
        return Err(PublishError::CpuFeatureUnavailable { feature: "asimd" });
    }
    if target.features.contains(CpuFeatures::SVE) && !platform::has_sve() {
        return Err(PublishError::CpuFeatureUnavailable { feature: "sve" });
    }
    if target.features.contains(CpuFeatures::SVE2) && !platform::has_sve2() {
        return Err(PublishError::CpuFeatureUnavailable { feature: "sve2" });
    }
    if image.output() != A::OUTPUT {
        return Err(PublishError::AggregateOutputContractMismatch {
            expected: A::OUTPUT,
            actual: image.output(),
        });
    }
    Ok(())
}

fn preflight_search_backend_version(image: &NativeImage) -> Result<(), PublishError> {
    match image.backend_version() {
        BackendVersion::SEARCH_V1
        | BackendVersion::SEARCH_V2
        | BackendVersion::SEARCH_V3
        | BackendVersion::SEARCH_V4
        | BackendVersion::SEARCH_V5
        | BackendVersion::SEARCH_V6
        | BackendVersion::SEARCH_V7
        | BackendVersion::SEARCH_V8
        | BackendVersion::SEARCH_V9
        | BackendVersion::SEARCH_V10
        | BackendVersion::SEARCH_V11
        | BackendVersion::SEARCH_V12
        | BackendVersion::SEARCH_V13
        | BackendVersion::SEARCH_V14
        | BackendVersion::SEARCH_V15
        | BackendVersion::SEARCH_V16
        | BackendVersion::SEARCH_V17
        | BackendVersion::SEARCH_V18
        | BackendVersion::SEARCH_V19
        | BackendVersion::SEARCH_V20
        | BackendVersion::SEARCH_V21
        | BackendVersion::SEARCH_V22
        | BackendVersion::SEARCH_SVE16_V1
        | BackendVersion::SEARCH_SVE2_16_V1
        | BackendVersion::SEARCH_SVE16_V6
        | BackendVersion::SEARCH_SVE2_FIXED16_V2 => Ok(()),
        actual => Err(PublishError::BackendVersionMismatch {
            expected: BackendVersion::SEARCH_CURRENT.0,
            actual: actual.0,
        }),
    }
}

fn preflight_aggregate_backend_version(image: &NativeAggregateImage) -> Result<(), PublishError> {
    if !matches!(
        image.backend_version(),
        BackendVersion::AGGREGATE_V1
            | BackendVersion::AGGREGATE_HISTORICAL_V2
            | BackendVersion::AGGREGATE_SVE2_FIXED16_COUNT_EXPERIMENTAL_V1
            | BackendVersion::AGGREGATE_SVE2_FIXED16_SPAN_SUM_EXPERIMENTAL_V1
            | BackendVersion::AGGREGATE_SVE2_FIXED16_PAIR_COUNT_EXPERIMENTAL_V1
            | BackendVersion::AGGREGATE_SVE2_FIXED16_PAIR_SPAN_SUM_EXPERIMENTAL_V1
    ) {
        return Err(PublishError::BackendVersionMismatch {
            expected: BackendVersion::AGGREGATE_CURRENT.0,
            actual: image.backend_version().0,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
