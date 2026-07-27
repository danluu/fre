//! Platform dispatch. Unsafe code is allowed only in a target implementation.

use fre_jit_aarch64::{NativeAggregateImage, NativeImage};
use fre_kernel_ir::{AggregateOutput, OutputKind, SearchWindow};

use crate::{
    CallError, FailureStage, PublishError, RuntimeIdentity,
    limits::PublicationPlan,
    operation::{RawAggregateCallResult, RawCallResult},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureInjection {
    None,
    At(FailureStage),
    CorruptCopy,
}

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
))]
#[allow(
    unsafe_code,
    reason = "the audited AArch64 mmap and native-call boundary is isolated here"
)]
mod aarch64;

#[cfg(all(
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[allow(
    unsafe_code,
    reason = "the macOS instruction-cache and VM-introspection hooks are isolated here"
)]
mod macos_aarch64;

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
#[allow(
    unsafe_code,
    reason = "the Linux auxv and AArch64 cache-maintenance hooks are isolated here"
)]
mod linux_aarch64;

#[cfg(all(
    target_arch = "aarch64",
    target_os = "macos",
    target_pointer_width = "64",
    target_endian = "little"
))]
use macos_aarch64 as host;

#[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_pointer_width = "64",
    target_endian = "little"
))]
use linux_aarch64 as host;

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
))]
use aarch64 as implementation;

#[cfg(not(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
)))]
mod unsupported;

#[cfg(not(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
)))]
use unsupported as implementation;

pub(crate) use implementation::ExecutableMapping;

#[cfg(all(
    test,
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
))]
pub(crate) use implementation::{
    invoke_with_vector_callee_saved_canary, live_code_mappings, with_guarded_haystack,
};

pub(crate) fn ensure_host_supported() -> Result<(), PublishError> {
    implementation::ensure_host_supported()
}

pub(crate) fn page_size() -> Result<usize, PublishError> {
    implementation::page_size()
}

pub(crate) fn has_asimd() -> bool {
    implementation::has_asimd()
}

pub(crate) fn publish(
    image: &NativeImage,
    plan: PublicationPlan,
    identity: RuntimeIdentity,
    failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    implementation::publish(image, plan, identity, failure)
}

pub(crate) fn publish_aggregate(
    image: &NativeAggregateImage,
    plan: PublicationPlan,
    identity: RuntimeIdentity,
    failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    implementation::publish_aggregate(image, plan, identity, failure)
}

pub(crate) trait Mapping {
    fn identity(&self) -> RuntimeIdentity;
    fn output(&self) -> OutputKind;
    fn call_contract_valid(&self, expected_output: OutputKind) -> bool;
    fn invoke(&self, haystack: &[u8], window: SearchWindow) -> Result<RawCallResult, CallError>;
    fn aggregate_contract_valid(
        &self,
        expected_output: AggregateOutput,
        literal_bytes: u32,
    ) -> bool;
    fn invoke_aggregate(&self, haystack: &[u8]) -> Result<RawAggregateCallResult, CallError>;
}

impl ExecutableMapping {
    pub(crate) fn identity(&self) -> RuntimeIdentity {
        <Self as Mapping>::identity(self)
    }

    pub(crate) fn output(&self) -> OutputKind {
        <Self as Mapping>::output(self)
    }

    pub(crate) fn call_contract_valid(&self, expected_output: OutputKind) -> bool {
        <Self as Mapping>::call_contract_valid(self, expected_output)
    }

    pub(crate) fn invoke(
        &self,
        haystack: &[u8],
        window: SearchWindow,
    ) -> Result<RawCallResult, CallError> {
        <Self as Mapping>::invoke(self, haystack, window)
    }

    pub(crate) fn aggregate_contract_valid(
        &self,
        expected_output: AggregateOutput,
        literal_bytes: u32,
    ) -> bool {
        <Self as Mapping>::aggregate_contract_valid(self, expected_output, literal_bytes)
    }

    pub(crate) fn invoke_aggregate(
        &self,
        haystack: &[u8],
    ) -> Result<RawAggregateCallResult, CallError> {
        <Self as Mapping>::invoke_aggregate(self, haystack)
    }
}
