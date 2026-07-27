//! Audited executable-memory publication for FRE native images.
//!
//! The only admitted publisher is currently strict-W^X `AArch64` macOS. An
//! image is independently audited, copied between inaccessible guard pages,
//! byte-verified, changed from writable to executable (never both), and has
//! its instruction cache synchronized before a callable object is exposed.
//! Other hosts and hardened-runtime configurations that deny this sequence
//! return typed errors.
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

use core::{fmt, marker::PhantomData};
use std::sync::Arc;

use fre_jit_aarch64::{BackendVersion, CpuFeatures, TargetSpec, audit, audit_aggregate};
use fre_kernel_ir::{AggregateExecutionLimits, SearchWindow, preflight_exact_aggregate};

pub use error::{
    ArithmeticSite, CallError, FailureStage, HostSupportReason, PublishError, ResourceKind, WxMode,
};
pub use fre_jit_aarch64::{NativeAggregateImage, NativeImage};
pub use identity::RuntimeIdentity;
pub use limits::{PublicationAccounting, PublicationLimits};
pub use operation::{RuntimeAggregateOperation, RuntimeOperation};

use crate::{limits::PublicationPlan, platform::ExecutableMapping};

/// Check whether this process implements the native publication target.
///
/// Facades may call this before constructing a target-specific image so an
/// unsupported host pays no Kernel IR, emission, audit, or mapping work.
pub fn native_host_support() -> Result<(), PublishError> {
    platform::ensure_host_supported()
}

/// An immutable, reference-counted native kernel with a typed output contract.
///
/// Cloning is cheap. The executable mapping remains owned for every call
/// borrow, so dropping another clone cannot race an in-progress call. The
/// final clone unmaps the code only after all such borrows have ended.
pub struct PublishedKernel<O: RuntimeOperation> {
    mapping: Arc<ExecutableMapping>,
    identity: RuntimeIdentity,
    accounting: PublicationAccounting,
    operation: PhantomData<fn() -> O>,
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
    /// escapes this method.
    pub fn search(&self, haystack: &[u8], window: SearchWindow) -> Result<O::Output, CallError> {
        if window.start() > window.end() || window.end() > haystack.len() {
            return Err(CallError::InvalidWindow {
                start: window.start(),
                end: window.end(),
                haystack_len: haystack.len(),
            });
        }
        if self.mapping.identity() != self.identity
            || self.mapping.output() != O::KIND
            || !self.mapping.call_contract_valid(O::KIND)
        {
            return Err(CallError::PublicationIdentityMismatch);
        }
        let raw = self.mapping.invoke(haystack, window)?;
        operation::decode::<O>(raw, window)
    }

    /// Exact page/code/data accounting charged at publication.
    #[must_use]
    pub const fn accounting(&self) -> PublicationAccounting {
        self.accounting
    }

    /// Content identity retained from the repeatedly audited source image.
    #[must_use]
    pub const fn identity(&self) -> RuntimeIdentity {
        self.identity
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
    preflight::<O>(image)?;
    let page_bytes = platform::page_size()?;
    let plan = PublicationPlan::new(image, page_bytes, limits)?;
    let identity = RuntimeIdentity::from_preflight_image(image);

    // This second independent audit is intentionally adjacent to publication.
    // The platform path performs a third audit after byte verification and
    // before its RX transition.
    audit(image).map_err(PublishError::ImageAudit)?;
    let mapping = platform::publish(image, plan, identity, failure)?;
    if mapping.identity() != identity || mapping.output() != O::KIND {
        return Err(PublishError::PublicationIdentityMismatch);
    }
    Ok(PublishedKernel {
        mapping: Arc::new(mapping),
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

fn preflight<O: RuntimeOperation>(image: &NativeImage) -> Result<(), PublishError> {
    platform::ensure_host_supported()?;
    preflight_search_backend_version(image)?;
    audit(image).map_err(PublishError::ImageAudit)?;
    let target = image.target();
    let baseline = TargetSpec::AARCH64_AAPCS64;
    if target.architecture != baseline.architecture
        || target.little_endian != baseline.little_endian
        || target.pointer_width != baseline.pointer_width
        || target.abi != baseline.abi
    {
        return Err(PublishError::TargetMismatch);
    }
    let known_features = CpuFeatures::ASIMD.bits();
    if target.features.bits() & !known_features != 0 {
        return Err(PublishError::UnknownCpuFeatures {
            bits: target.features.bits(),
        });
    }
    if target.features.contains(CpuFeatures::ASIMD) && !platform::has_asimd() {
        return Err(PublishError::CpuFeatureUnavailable { feature: "asimd" });
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
    let known_features = CpuFeatures::ASIMD.bits();
    if target.features.bits() & !known_features != 0 {
        return Err(PublishError::UnknownCpuFeatures {
            bits: target.features.bits(),
        });
    }
    if target.features.contains(CpuFeatures::ASIMD) && !platform::has_asimd() {
        return Err(PublishError::CpuFeatureUnavailable { feature: "asimd" });
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
        | BackendVersion::SEARCH_V7 => Ok(()),
        actual => Err(PublishError::BackendVersionMismatch {
            expected: BackendVersion::SEARCH_CURRENT.0,
            actual: actual.0,
        }),
    }
}

fn preflight_aggregate_backend_version(image: &NativeAggregateImage) -> Result<(), PublishError> {
    if !matches!(
        image.backend_version(),
        BackendVersion::AGGREGATE_V1 | BackendVersion::AGGREGATE_HISTORICAL_V2
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
