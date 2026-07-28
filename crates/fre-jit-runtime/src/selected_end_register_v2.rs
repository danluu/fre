//! Strictly separate publication and invocation for the register-return
//! `SelectedEnd` ABI2.

use core::{fmt, marker::PhantomData, num::NonZeroU32};
use std::{rc::Rc, sync::Arc};

use fre_jit_aarch64::{
    AuditedSelectedEndRegisterImageV2, BackendVersion, CpuFeatures,
    SelectedEndRegisterArtifactIdentityV2, SelectedEndRegisterBackendV2, TargetSpec,
    audit_selected_end_register_v2,
};
use fre_kernel_ir::{MatchSpan, OutputKind, SearchWindow};
use fre_kernels::{
    LiteralAccounting, LiteralError, LiteralSearchLimits, LiteralSearchPreflight, Window,
    preflight_literal_window,
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
    /// A preflight token came from a different literal plan.
    LiteralWidthMismatch {
        expected_bytes: usize,
        actual_bytes: usize,
    },
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
/// through [`PublishedSelectedEndRegisterThreadSessionV2`], so tag21 cannot
/// inherit Search-v1's backward-compatible unchecked-thread assumption.
pub struct PublishedSelectedEndRegisterV2 {
    pub(crate) mapping: Arc<ExecutableMapping>,
    entry: SelectedEndRegisterEntryV2,
    runtime_identity: RuntimeIdentity,
    artifact_identity: SelectedEndRegisterArtifactIdentityV2,
    accounting: PublicationAccounting,
    backend: SelectedEndRegisterBackendV2,
    literal_bytes: NonZeroU32,
}

/// Current-thread invocation token for one register-return ABI2 publication.
///
/// V8 construction is syscall-free. Tag21 observes the calling thread's SVE
/// vector length exactly once during construction and requires VL16. Search
/// calls perform no host query or `prctl`.
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

impl PublishedSelectedEndRegisterV2 {
    /// Establish the only callable boundary for this ABI2 publication.
    ///
    /// V8 returns a token without querying SVE state. Tag21 performs one
    /// current-thread vector-length query and requires exactly sixteen bytes.
    pub fn begin_current_thread_session(
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
}

impl PublishedSelectedEndRegisterThreadSessionV2<'_> {
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
    /// that plan's literal width against the sealed ABI2 image, then invokes
    /// native code without repeating scalar preflight.
    #[doc(hidden)]
    #[inline]
    pub fn search_preflighted(
        &self,
        preflight: LiteralSearchPreflight<'_, '_>,
    ) -> Result<(Option<MatchSpan>, LiteralAccounting), SelectedEndRegisterCallErrorV2> {
        invoke_preflighted_selected_end_register_v2(
            self.literal_bytes,
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
/// V8 needs no SVE thread contract, while tag21 performs its one VL16 check
/// only when [`PublishedSelectedEndRegisterV2::begin_current_thread_session`]
/// creates the session that may invoke generated code.
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
    if backend == SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16 {
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
    })
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
        SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16 => CpuFeatures::ASIMD_SVE2,
    };
    if target.features != expected_features
        || image.output() != OutputKind::SelectedEnd
        || !matches!(
            image.backend_version(),
            BackendVersion::SEARCH_V8 | BackendVersion::SEARCH_SVE2_FIXED16_V2
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
    if backend == SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16 && !features.sve {
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

pub(crate) fn decode_selected_end_register_v2(
    end_or_zero: usize,
    window: SearchWindow,
    literal_len: usize,
) -> Result<Option<MatchSpan>, SelectedEndRegisterCallErrorV2> {
    if end_or_zero == 0 {
        return Ok(None);
    }
    let start = end_or_zero.checked_sub(literal_len);
    if end_or_zero > window.end()
        || start.is_none_or(|start| start < window.start())
        || literal_len == 0
    {
        return Err(SelectedEndRegisterCallErrorV2::InvalidNativeEnd {
            end_or_zero,
            literal_bytes: literal_len,
            window_start: window.start(),
            window_end: window.end(),
        });
    }
    Ok(Some(MatchSpan::new(
        start.expect("validated selected-end start"),
        end_or_zero,
    )))
}
