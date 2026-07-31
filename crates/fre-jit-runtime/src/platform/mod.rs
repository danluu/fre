//! Platform dispatch. Unsafe code is allowed only in a target implementation.

use fre_jit_aarch64::{
    AuditedNativeImage, AuditedSelectedEndRegisterImageV2, NativeAggregateImage, NativeImage,
};
use fre_kernel_ir::{AggregateOutput, OutputKind};

use crate::{
    CallError, FailureStage, NativeHostCapabilities, PublishError, RuntimeIdentity,
    limits::PublicationPlan, operation::RawAggregateCallResult,
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

pub(crate) use implementation::{ExecutableMapping, SearchEntry, SelectedEndRegisterEntryV2};

#[cfg(all(
    test,
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
))]
pub(crate) use implementation::live_code_mappings;

#[cfg(all(
    any(test, feature = "sve-hardware-qualification"),
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64",
    target_endian = "little"
))]
pub(crate) use implementation::{
    invoke_selected_end_register_v2_with_vector_callee_saved_canary,
    invoke_with_vector_callee_saved_canary, with_guarded_haystack,
};

pub(crate) fn capabilities() -> Result<NativeHostCapabilities, PublishError> {
    implementation::capabilities()
}

pub(crate) fn current_thread_sve_vector_bytes() -> Result<Option<u16>, PublishError> {
    implementation::current_thread_sve_vector_bytes()
}

pub(crate) fn ensure_host_supported() -> Result<(), PublishError> {
    implementation::ensure_host_supported()
}

pub(crate) fn page_size() -> Result<usize, PublishError> {
    implementation::page_size()
}

pub(crate) fn has_asimd() -> bool {
    implementation::has_asimd()
}

pub(crate) fn has_sve() -> bool {
    implementation::has_sve()
}

pub(crate) fn has_sve2() -> bool {
    implementation::has_sve2()
}

pub(crate) fn publish(
    image: &NativeImage,
    plan: PublicationPlan,
    identity: RuntimeIdentity,
    sve_vector_bytes_at_publication: Option<u16>,
    failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    implementation::publish(
        image,
        plan,
        identity,
        sve_vector_bytes_at_publication,
        failure,
    )
}

pub(crate) fn publish_audited(
    image: &AuditedNativeImage,
    plan: PublicationPlan,
    identity: RuntimeIdentity,
    sve_vector_bytes_at_publication: Option<u16>,
    failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    implementation::publish_audited(
        image,
        plan,
        identity,
        sve_vector_bytes_at_publication,
        failure,
    )
}

pub(crate) fn publish_selected_end_register_v2(
    image: &AuditedSelectedEndRegisterImageV2,
    plan: PublicationPlan,
    identity: RuntimeIdentity,
    literal_bytes: u32,
    failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    implementation::publish_selected_end_register_v2(image, plan, identity, literal_bytes, failure)
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
    fn sve_vector_bytes_at_publication(&self) -> Option<u16>;
    fn call_contract_valid(&self, expected_output: OutputKind) -> bool;
    fn selected_end_register_v2_contract_valid(&self, literal_bytes: u32) -> bool;
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

    pub(crate) fn sve_vector_bytes_at_publication(&self) -> Option<u16> {
        <Self as Mapping>::sve_vector_bytes_at_publication(self)
    }

    pub(crate) fn call_contract_valid(&self, expected_output: OutputKind) -> bool {
        <Self as Mapping>::call_contract_valid(self, expected_output)
    }

    pub(crate) fn selected_end_register_v2_contract_valid(&self, literal_bytes: u32) -> bool {
        <Self as Mapping>::selected_end_register_v2_contract_valid(self, literal_bytes)
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
