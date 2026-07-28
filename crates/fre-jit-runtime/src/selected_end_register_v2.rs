//! Strictly separate publication and invocation for the register-return
//! `SelectedEnd` ABI2.

use core::{fmt, marker::PhantomData, num::NonZeroU32};
use std::{rc::Rc, sync::Arc};

use fre_jit_aarch64::{
    AuditedSelectedEndRegisterImageV2, BackendVersion, CpuFeatures, MAX_REPEATED_CONFIRM_BYTES,
    SelectedEndRegisterArtifactIdentityV2, SelectedEndRegisterBackendV2, TargetSpec,
    audit_selected_end_register_v2,
};
use fre_kernel_ir::{MatchSpan, OutputKind, SearchWindow};
use fre_kernels::{
    LiteralAccounting, LiteralError, LiteralPlan, LiteralSearchLimits, LiteralSearchPreflight,
    Window, preflight_literal_window,
};

use crate::{
    KernelThreadContractError, PublicationAccounting, PublicationLimits, PublishError,
    RuntimeIdentity,
    limits::PublicationPlan,
    platform::{self, ExecutableMapping, FailureInjection, SelectedEndRegisterEntryV2},
};

/// Failure at the safe register-return ABI2 call boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectedEndRegisterCallErrorV2 {
    /// The authenticated literal width did not fit the current address space.
    LiteralWidthNotRepresentable { bytes: u32 },
    /// Shared scalar literal/window/resource preflight refused the call.
    Preflight(LiteralError),
    /// A preflight token's literal width differs from the sealed artifact.
    LiteralWidthMismatch {
        expected_bytes: usize,
        actual_bytes: usize,
    },
    /// A same-width preflight token belongs to a different exact literal.
    LiteralIdentityMismatch,
    /// Native code returned an end that cannot encode a match inside the
    /// checked window for the authenticated nonzero literal width.
    InvalidNativeEnd {
        end_or_zero: usize,
        literal_bytes: usize,
        window_start: usize,
        window_end: usize,
    },
}

impl fmt::Display for SelectedEndRegisterCallErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "selected-end register ABI2 call failed: {self:?}"
        )
    }
}

impl std::error::Error for SelectedEndRegisterCallErrorV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Preflight(error) => Some(error),
            Self::LiteralWidthNotRepresentable { .. }
            | Self::LiteralWidthMismatch { .. }
            | Self::LiteralIdentityMismatch
            | Self::InvalidNativeEnd { .. } => None,
        }
    }
}

impl From<LiteralError> for SelectedEndRegisterCallErrorV2 {
    fn from(error: LiteralError) -> Self {
        Self::Preflight(error)
    }
}

/// Immutable strict-W^X publication of one register-return ABI2 image.
///
/// The handle intentionally has no direct call method. Every invocation goes
/// through [`PublishedSelectedEndRegisterThreadSessionV2`] or
/// [`PublishedSelectedEndRegisterPlanThreadSessionV2`], so tag19 and tag21
/// cannot inherit Search-v1's backward-compatible unchecked-thread assumption.
pub struct PublishedSelectedEndRegisterV2 {
    pub(crate) mapping: Arc<ExecutableMapping>,
    entry: SelectedEndRegisterEntryV2,
    runtime_identity: RuntimeIdentity,
    artifact_identity: SelectedEndRegisterArtifactIdentityV2,
    accounting: PublicationAccounting,
    backend: SelectedEndRegisterBackendV2,
    literal_bytes: NonZeroU32,
    exact_literal: [u8; MAX_REPEATED_CONFIRM_BYTES],
}

/// Current-thread invocation token for one register-return ABI2 publication.
///
/// V8 construction is syscall-free. Tag19 and tag21 observe the calling
/// thread's SVE vector length exactly once during construction and require
/// VL16. Search calls perform no host query or `prctl`.
///
/// ```compile_fail,E0277
/// use fre_jit_runtime::PublishedSelectedEndRegisterThreadSessionV2;
///
/// fn require_send<T: Send>() {}
/// require_send::<PublishedSelectedEndRegisterThreadSessionV2<'static>>();
/// ```
///
/// ```compile_fail,E0277
/// use fre_jit_runtime::PublishedSelectedEndRegisterThreadSessionV2;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<PublishedSelectedEndRegisterThreadSessionV2<'static>>();
/// ```
pub struct PublishedSelectedEndRegisterThreadSessionV2<'kernel> {
    entry: SelectedEndRegisterEntryV2,
    literal_bytes: NonZeroU32,
    kernel: &'kernel PublishedSelectedEndRegisterV2,
    thread_bound: PhantomData<Rc<()>>,
}

/// Current-thread ABI2 token bound once to one exact portable literal plan.
///
/// Construction proves that the plan's immutable literal equals the sealed
/// artifact and performs the same sole fixed-VL observation as the general
/// session. Repeated preflighted calls therefore need only prove that their
/// private-field certificate came from this exact plan before invoking native
/// code. The token remains neither [`Send`] nor [`Sync`].
///
/// ```compile_fail,E0277
/// use fre_jit_runtime::PublishedSelectedEndRegisterPlanThreadSessionV2;
///
/// fn require_send<T: Send>() {}
/// require_send::<PublishedSelectedEndRegisterPlanThreadSessionV2<'static>>();
/// ```
///
/// ```compile_fail,E0277
/// use fre_jit_runtime::PublishedSelectedEndRegisterPlanThreadSessionV2;
///
/// fn require_sync<T: Sync>() {}
/// require_sync::<PublishedSelectedEndRegisterPlanThreadSessionV2<'static>>();
/// ```
pub struct PublishedSelectedEndRegisterPlanThreadSessionV2<'kernel> {
    session: PublishedSelectedEndRegisterThreadSessionV2<'kernel>,
    literal_plan: &'kernel LiteralPlan,
    literal_bytes: usize,
}

impl Clone for PublishedSelectedEndRegisterV2 {
    fn clone(&self) -> Self {
        Self {
            mapping: Arc::clone(&self.mapping),
            entry: self.entry,
            runtime_identity: self.runtime_identity,
            artifact_identity: self.artifact_identity,
            accounting: self.accounting,
            backend: self.backend,
            literal_bytes: self.literal_bytes,
            exact_literal: self.exact_literal,
        }
    }
}

impl fmt::Debug for PublishedSelectedEndRegisterV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedSelectedEndRegisterV2")
            .field("artifact_identity", &self.artifact_identity)
            .field("accounting", &self.accounting)
            .field("backend", &self.backend)
            .field("literal_bytes", &self.literal_bytes)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PublishedSelectedEndRegisterThreadSessionV2<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedSelectedEndRegisterThreadSessionV2")
            .field("artifact_identity", &self.kernel.artifact_identity)
            .field("backend", &self.kernel.backend)
            .field("literal_bytes", &self.literal_bytes)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PublishedSelectedEndRegisterPlanThreadSessionV2<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedSelectedEndRegisterPlanThreadSessionV2")
            .field("artifact_identity", &self.session.kernel.artifact_identity)
            .field("backend", &self.session.kernel.backend)
            .field("literal_bytes", &self.literal_bytes)
            .finish_non_exhaustive()
    }
}

impl PublishedSelectedEndRegisterV2 {
    /// Establish the only callable boundary for this ABI2 publication.
    ///
    /// V8 returns a token without querying SVE state. Tag19 and tag21 perform
    /// one current-thread vector-length query and require exactly sixteen
    /// bytes.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<PublishedSelectedEndRegisterThreadSessionV2<'_>, KernelThreadContractError> {
        self.begin_current_thread_session_impl()
    }

    /// Establish a plan-bound session for the qualified exact-literal facade.
    ///
    /// This compares the plan's immutable literal with the sealed artifact
    /// once. Repeated preflighted calls can then prove that their token came
    /// from this exact plan with a pointer-identity check instead of comparing
    /// up to 32 literal bytes on every hot call.
    #[doc(hidden)]
    pub fn begin_current_thread_session_for_literal_plan<'session>(
        &'session self,
        plan: &'session LiteralPlan,
    ) -> Result<PublishedSelectedEndRegisterPlanThreadSessionV2<'session>, KernelThreadContractError>
    {
        let literal = plan.needle();
        if literal != self.exact_literal() {
            return Err(KernelThreadContractError::LiteralIdentityMismatch);
        }
        let session = self.begin_current_thread_session_impl()?;
        Ok(PublishedSelectedEndRegisterPlanThreadSessionV2 {
            session,
            literal_plan: plan,
            literal_bytes: literal.len(),
        })
    }

    fn begin_current_thread_session_impl(
        &self,
    ) -> Result<PublishedSelectedEndRegisterThreadSessionV2<'_>, KernelThreadContractError> {
        let required = self.backend.fixed_active_vector_bytes();
        if required != 0 {
            let actual = platform::current_thread_sve_vector_bytes()
                .map_err(KernelThreadContractError::HostCapabilities)?;
            if actual != Some(required) {
                return Err(
                    KernelThreadContractError::RequiredSveVectorLengthUnavailable {
                        required_bytes: required,
                        actual_bytes: actual,
                    },
                );
            }
        }
        Ok(PublishedSelectedEndRegisterThreadSessionV2 {
            entry: self.entry,
            literal_bytes: self.literal_bytes,
            kernel: self,
            thread_bound: PhantomData,
        })
    }

    #[inline]
    fn exact_literal(&self) -> &[u8] {
        let bytes = usize::try_from(self.literal_bytes.get())
            .expect("u32 literal width fits every supported runtime host");
        &self.exact_literal[..bytes]
    }

    /// Exact page/code/data accounting charged at publication.
    #[must_use]
    pub const fn accounting(&self) -> PublicationAccounting {
        self.accounting
    }

    /// Domain-separated identity of the complete ABI2 artifact.
    #[must_use]
    pub const fn artifact_identity(&self) -> SelectedEndRegisterArtifactIdentityV2 {
        self.artifact_identity
    }

    /// Exact scan backend authenticated by the sealed image.
    #[must_use]
    pub const fn backend(&self) -> SelectedEndRegisterBackendV2 {
        self.backend
    }

    /// Authenticated nonzero exact-literal width.
    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        self.literal_bytes.get()
    }

    /// Qualification observation of the SVE vector length recorded by
    /// publication.
    ///
    /// Register-return ABI2 publication is feature-only, so this remains
    /// `None`; fixed-VL tag19/tag21 observe the calling thread only when a
    /// callable session opens.
    #[cfg(all(
        feature = "sve-hardware-qualification",
        target_arch = "aarch64",
        any(target_os = "macos", target_os = "linux"),
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    #[doc(hidden)]
    #[must_use]
    pub fn qualification_sve_vector_bytes_at_publication(&self) -> Option<u16> {
        self.mapping.sve_vector_bytes_at_publication()
    }

    /// Qualification observation of the fixed SVE bytes required when this
    /// publication opens a callable current-thread session, or `None` for the
    /// ASIMD-only V8 backend.
    #[cfg(all(
        feature = "sve-hardware-qualification",
        target_arch = "aarch64",
        any(target_os = "macos", target_os = "linux"),
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    #[doc(hidden)]
    #[must_use]
    pub const fn qualification_required_thread_sve_vector_bytes(&self) -> Option<u16> {
        match self.backend.fixed_active_vector_bytes() {
            0 => None,
            bytes => Some(bytes),
        }
    }
}

impl PublishedSelectedEndRegisterThreadSessionV2<'_> {
    /// SVE vector length validated while this qualification session opened,
    /// or `None` for an ASIMD-only session.
    #[cfg(all(
        feature = "sve-hardware-qualification",
        target_arch = "aarch64",
        any(target_os = "macos", target_os = "linux"),
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    #[doc(hidden)]
    #[must_use]
    pub const fn qualification_validated_thread_sve_vector_bytes(&self) -> Option<u16> {
        match self.kernel.backend.fixed_active_vector_bytes() {
            0 => None,
            bytes => Some(bytes),
        }
    }

    /// Search one half-open byte window after shared scalar preflight.
    ///
    /// Window validation and the literal linear-work limit complete before a
    /// haystack pointer is passed to the exact four-argument native entry.
    #[inline]
    pub fn search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: LiteralSearchLimits,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), SelectedEndRegisterCallErrorV2> {
        checked_selected_end_register_call_v2(self.literal_bytes, haystack, window, limits, || {
            self.entry.invoke(haystack, window)
        })
    }

    /// Exercise this session's exact four-argument ABI2 entry through the
    /// qualification-only AAPCS64 vector callee-saved-lane canary.
    ///
    /// The wrapper forwards only x0 through x3, clears x4 instead of passing a
    /// result slot, returns the generated entry's x0, and verifies that the
    /// native result still decodes inside the scalar-preflighted window.
    #[cfg(all(
        any(test, feature = "sve-hardware-qualification"),
        target_arch = "aarch64",
        any(target_os = "macos", target_os = "linux"),
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    #[doc(hidden)]
    pub fn qualification_preserves_abi2_vector_callee_saved_lanes(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: LiteralSearchLimits,
        canaries: [u64; 8],
    ) -> Result<bool, SelectedEndRegisterCallErrorV2> {
        let mut preserved = false;
        checked_selected_end_register_call_v2(
            self.literal_bytes,
            haystack,
            window,
            limits,
            || {
                let (end_or_zero, observed) =
                    platform::invoke_selected_end_register_v2_with_vector_callee_saved_canary(
                        self.entry, haystack, window, canaries,
                    );
                preserved = observed == canaries;
                end_or_zero
            },
        )?;
        Ok(preserved)
    }

    /// Search the complete haystack after shared scalar preflight.
    #[inline]
    pub fn find(
        &self,
        haystack: &[u8],
        limits: LiteralSearchLimits,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), SelectedEndRegisterCallErrorV2> {
        self.search(haystack, SearchWindow::new(0, haystack.len()), limits)
    }

    /// Invoke from an existing authoritative literal preflight token.
    ///
    /// The token's private fields bind its exact plan, haystack, window,
    /// accounting, and successful resource admission. This boundary verifies
    /// that plan's exact literal against the sealed ABI2 image, then invokes
    /// native code without repeating scalar preflight. General sessions compare
    /// the exact bytes on every call; qualified facade sessions use the
    /// distinct once-bound plan token below.
    #[doc(hidden)]
    #[inline]
    pub fn search_preflighted(
        &self,
        preflight: LiteralSearchPreflight<'_, '_>,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), SelectedEndRegisterCallErrorV2> {
        invoke_preflighted_selected_end_register_v2(
            self.literal_bytes,
            self.kernel.exact_literal(),
            preflight,
            |haystack, window| self.entry.invoke(haystack, window),
        )
    }

    /// Immutable publication retained for this session's complete lifetime.
    #[must_use]
    pub const fn kernel(&self) -> &PublishedSelectedEndRegisterV2 {
        self.kernel
    }
}

impl PublishedSelectedEndRegisterPlanThreadSessionV2<'_> {
    /// SVE vector length validated while this qualification session opened,
    /// or `None` for an ASIMD-only session.
    #[cfg(all(
        feature = "sve-hardware-qualification",
        target_arch = "aarch64",
        any(target_os = "macos", target_os = "linux"),
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    #[doc(hidden)]
    #[must_use]
    pub const fn qualification_validated_thread_sve_vector_bytes(&self) -> Option<u16> {
        self.session
            .qualification_validated_thread_sve_vector_bytes()
    }

    /// Search one half-open byte window after shared scalar preflight.
    #[inline]
    pub fn search(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: LiteralSearchLimits,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), SelectedEndRegisterCallErrorV2> {
        self.session.search(haystack, window, limits)
    }

    /// Exercise the exact ABI2 entry through the qualification-only vector
    /// callee-saved-lane canary.
    #[cfg(all(
        any(test, feature = "sve-hardware-qualification"),
        target_arch = "aarch64",
        any(target_os = "macos", target_os = "linux"),
        target_pointer_width = "64",
        target_endian = "little"
    ))]
    #[doc(hidden)]
    pub fn qualification_preserves_abi2_vector_callee_saved_lanes(
        &self,
        haystack: &[u8],
        window: SearchWindow,
        limits: LiteralSearchLimits,
        canaries: [u64; 8],
    ) -> Result<bool, SelectedEndRegisterCallErrorV2> {
        self.session
            .qualification_preserves_abi2_vector_callee_saved_lanes(
                haystack, window, limits, canaries,
            )
    }

    /// Search the complete haystack after shared scalar preflight.
    #[inline]
    pub fn find(
        &self,
        haystack: &[u8],
        limits: LiteralSearchLimits,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), SelectedEndRegisterCallErrorV2> {
        self.session.find(haystack, limits)
    }

    /// Invoke from a preflight issued by the exact plan bound at construction.
    ///
    /// The successful hot path performs one allocation-free plan-pointer
    /// identity check, then invokes and decodes the native result. Literal
    /// width and bytes were already authenticated when this session opened and
    /// are consulted only to classify a mismatched token.
    #[doc(hidden)]
    #[inline(always)]
    pub fn search_preflighted(
        &self,
        preflight: LiteralSearchPreflight<'_, '_>,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), SelectedEndRegisterCallErrorV2> {
        invoke_plan_preflighted_selected_end_register_v2(
            self.literal_bytes,
            self.literal_plan,
            preflight,
            |haystack, window| self.session.entry.invoke(haystack, window),
        )
    }

    /// Immutable publication retained for this session's complete lifetime.
    #[must_use]
    pub const fn kernel(&self) -> &PublishedSelectedEndRegisterV2 {
        self.session.kernel
    }
}

/// Publish only a sealed register-return ABI2 image.
///
/// This boundary repeats the independent P1 whole-image audit before mapping
/// and again after exact copy verification but before RX publication.
///
/// ```compile_fail,E0308
/// use fre_jit_runtime::{
///     AuditedNativeImage, PublicationLimits, publish_selected_end_register_v2,
/// };
///
/// fn v1_cannot_enter_v2(image: &AuditedNativeImage) {
///     let _ = publish_selected_end_register_v2(image, PublicationLimits::default());
/// }
/// ```
///
/// ```compile_fail,E0308
/// use fre_jit_aarch64::AuditedSelectedEndRegisterImageV2;
/// use fre_jit_runtime::{PublicationLimits, publish_audited};
/// use fre_kernel_ir::SelectedEnd;
///
/// fn v2_cannot_enter_v1(image: &AuditedSelectedEndRegisterImageV2) {
///     let _ = publish_audited::<SelectedEnd>(image, PublicationLimits::default());
/// }
/// ```
pub fn publish_selected_end_register_v2(
    image: &AuditedSelectedEndRegisterImageV2,
    limits: PublicationLimits,
) -> Result<PublishedSelectedEndRegisterV2, PublishError> {
    publish_selected_end_register_v2_impl(image, limits, FailureInjection::None)
}

/// Check process-wide host admission for one register-return ABI2 backend.
///
/// This deliberately does not inspect the calling thread's SVE vector length.
/// V8 needs no SVE thread contract, while tag19 and tag21 perform their one
/// VL16 check only when
/// [`PublishedSelectedEndRegisterV2::begin_current_thread_session`] creates
/// the session that may invoke generated code.
pub fn native_selected_end_register_backend_support_v2(
    backend: SelectedEndRegisterBackendV2,
) -> Result<(), PublishError> {
    platform::ensure_host_supported()?;
    validate_selected_end_register_host_features_v2(
        backend,
        SelectedEndRegisterHostFeaturesV2 {
            asimd: platform::has_asimd(),
            sve: platform::has_sve(),
            sve2: platform::has_sve2(),
        },
    )?;
    if matches!(
        backend,
        SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16
            | SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16
    ) {
        crate::validate_search_backend_tuning(
            backend.backend_version(),
            fre_target_features::host().tuning(),
        )?;
    }
    Ok(())
}

pub(crate) fn publish_selected_end_register_v2_impl(
    image: &AuditedSelectedEndRegisterImageV2,
    limits: PublicationLimits,
    failure: FailureInjection,
) -> Result<PublishedSelectedEndRegisterV2, PublishError> {
    let literal_bytes = preflight_selected_end_register_v2(image)?;
    let exact_literal = copy_selected_end_register_literal_v2(image, literal_bytes)?;
    let page_bytes = platform::page_size()?;
    let plan = PublicationPlan::new_selected_end_register_v2(image, page_bytes, limits)?;
    let runtime_identity = RuntimeIdentity::from_preflight_selected_end_register_v2(image);
    let artifact_identity = image.artifact_identity();

    // Keep an independent P1 audit adjacent to publication. The platform
    // boundary repeats it after byte-for-byte copy verification and before RX.
    audit_selected_end_register_v2(image).map_err(PublishError::ImageAudit)?;
    let mapping = platform::publish_selected_end_register_v2(
        image,
        plan,
        runtime_identity,
        literal_bytes.get(),
        failure,
    )?;
    if mapping.identity() != runtime_identity
        || !mapping.selected_end_register_v2_contract_valid(literal_bytes.get())
    {
        return Err(PublishError::PublicationIdentityMismatch);
    }
    let entry = mapping.selected_end_register_entry_v2();
    Ok(PublishedSelectedEndRegisterV2 {
        mapping: Arc::new(mapping),
        entry,
        runtime_identity,
        artifact_identity,
        accounting: plan.accounting,
        backend: image.backend(),
        literal_bytes,
        exact_literal,
    })
}

fn copy_selected_end_register_literal_v2(
    image: &AuditedSelectedEndRegisterImageV2,
    literal_bytes: NonZeroU32,
) -> Result<[u8; MAX_REPEATED_CONFIRM_BYTES], PublishError> {
    let literal_len = usize::try_from(literal_bytes.get())
        .map_err(|_| PublishError::PublicationIdentityMismatch)?;
    let source = image.rodata();
    if literal_len > MAX_REPEATED_CONFIRM_BYTES || source.len() != literal_len {
        return Err(PublishError::PublicationIdentityMismatch);
    }
    let mut exact_literal = [0_u8; MAX_REPEATED_CONFIRM_BYTES];
    exact_literal[..literal_len].copy_from_slice(source);
    Ok(exact_literal)
}

fn preflight_selected_end_register_v2(
    image: &AuditedSelectedEndRegisterImageV2,
) -> Result<NonZeroU32, PublishError> {
    native_selected_end_register_backend_support_v2(image.backend())?;
    audit_selected_end_register_v2(image).map_err(PublishError::ImageAudit)?;
    validate_selected_end_register_target_v2(image)?;
    NonZeroU32::new(image.literal_bytes()).ok_or(PublishError::PublicationIdentityMismatch)
}

fn validate_selected_end_register_target_v2(
    image: &AuditedSelectedEndRegisterImageV2,
) -> Result<(), PublishError> {
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
    let expected_features = match image.backend() {
        SelectedEndRegisterBackendV2::AsimdV8 => CpuFeatures::ASIMD,
        SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16 => CpuFeatures::ASIMD_SVE,
        SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16 => CpuFeatures::ASIMD_SVE2,
    };
    if target.features != expected_features
        || image.output() != OutputKind::SelectedEnd
        || !matches!(
            image.backend_version(),
            BackendVersion::SEARCH_V8
                | BackendVersion::SEARCH_SVE16_V6
                | BackendVersion::SEARCH_SVE2_FIXED16_V2
        )
    {
        return Err(PublishError::PublicationIdentityMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SelectedEndRegisterHostFeaturesV2 {
    pub(crate) asimd: bool,
    pub(crate) sve: bool,
    pub(crate) sve2: bool,
}

pub(crate) fn validate_selected_end_register_host_features_v2(
    backend: SelectedEndRegisterBackendV2,
    features: SelectedEndRegisterHostFeaturesV2,
) -> Result<(), PublishError> {
    if !features.asimd {
        return Err(PublishError::CpuFeatureUnavailable { feature: "asimd" });
    }
    if matches!(
        backend,
        SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16
            | SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16
    ) && !features.sve
    {
        return Err(PublishError::CpuFeatureUnavailable { feature: "sve" });
    }
    if backend == SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16 && !features.sve2 {
        return Err(PublishError::CpuFeatureUnavailable { feature: "sve2" });
    }
    Ok(())
}

#[inline]
pub(crate) fn checked_selected_end_register_call_v2(
    literal_bytes: NonZeroU32,
    haystack: &[u8],
    window: SearchWindow,
    limits: LiteralSearchLimits,
    invoke: impl FnOnce() -> usize,
) -> Result<(Option<MatchSpan>, LiteralAccounting), SelectedEndRegisterCallErrorV2> {
    let literal_len = usize::try_from(literal_bytes.get()).map_err(|_| {
        SelectedEndRegisterCallErrorV2::LiteralWidthNotRepresentable {
            bytes: literal_bytes.get(),
        }
    })?;
    let accounting = preflight_literal_window(
        literal_len,
        haystack.len(),
        Window::new(window.start(), window.end()),
        limits,
    )?;
    let matched = decode_selected_end_register_v2(invoke(), window, literal_len)?;
    Ok((matched, accounting))
}

#[inline]
pub(crate) fn invoke_preflighted_selected_end_register_v2(
    literal_bytes: NonZeroU32,
    exact_literal: &[u8],
    preflight: LiteralSearchPreflight<'_, '_>,
    invoke: impl FnOnce(&[u8], SearchWindow) -> usize,
) -> Result<(Option<MatchSpan>, LiteralAccounting), SelectedEndRegisterCallErrorV2> {
    let expected_bytes = usize::try_from(literal_bytes.get()).map_err(|_| {
        SelectedEndRegisterCallErrorV2::LiteralWidthNotRepresentable {
            bytes: literal_bytes.get(),
        }
    })?;
    let actual_bytes = preflight.literal_bytes();
    if actual_bytes != expected_bytes {
        return Err(SelectedEndRegisterCallErrorV2::LiteralWidthMismatch {
            expected_bytes,
            actual_bytes,
        });
    }
    if exact_literal.len() != expected_bytes {
        return Err(SelectedEndRegisterCallErrorV2::LiteralIdentityMismatch);
    }
    if preflight.literal() != exact_literal {
        return Err(SelectedEndRegisterCallErrorV2::LiteralIdentityMismatch);
    }
    let accounting = preflight.accounting();
    let checked = preflight.checked_window();
    let window = checked.window();
    let matched = decode_selected_end_register_v2(
        invoke(checked.haystack(), window),
        window,
        expected_bytes,
    )?;
    Ok((matched, accounting))
}

#[inline(always)]
pub(crate) fn invoke_plan_preflighted_selected_end_register_v2(
    literal_bytes: usize,
    literal_plan: &LiteralPlan,
    preflight: LiteralSearchPreflight<'_, '_>,
    invoke: impl FnOnce(&[u8], SearchWindow) -> usize,
) -> Result<(Option<MatchSpan>, LiteralAccounting), SelectedEndRegisterCallErrorV2> {
    if !preflight.was_issued_by(literal_plan) {
        let actual_bytes = preflight.literal_bytes();
        if actual_bytes != literal_bytes {
            return Err(SelectedEndRegisterCallErrorV2::LiteralWidthMismatch {
                expected_bytes: literal_bytes,
                actual_bytes,
            });
        }
        return Err(SelectedEndRegisterCallErrorV2::LiteralIdentityMismatch);
    }
    let accounting = preflight.accounting();
    let checked = preflight.checked_window();
    let window = checked.window();
    let matched =
        decode_selected_end_register_v2(invoke(checked.haystack(), window), window, literal_bytes)?;
    Ok((matched, accounting))
}

#[inline(always)]
pub(crate) fn decode_selected_end_register_v2(
    end_or_zero: usize,
    window: SearchWindow,
    literal_len: usize,
) -> Result<Option<MatchSpan>, SelectedEndRegisterCallErrorV2> {
    if end_or_zero == 0 {
        return Ok(None);
    }
    match end_or_zero.checked_sub(literal_len) {
        Some(start)
            if end_or_zero <= window.end() && start >= window.start() && literal_len != 0 =>
        {
            Ok(Some(MatchSpan::new(start, end_or_zero)))
        }
        _ => Err(SelectedEndRegisterCallErrorV2::InvalidNativeEnd {
            end_or_zero,
            literal_bytes: literal_len,
            window_start: window.start(),
            window_end: window.end(),
        }),
    }
}
