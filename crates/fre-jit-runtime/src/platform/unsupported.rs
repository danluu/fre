use fre_jit_aarch64::{NativeAggregateImage, NativeImage};
use fre_kernel_ir::{AggregateOutput, OutputKind, SearchWindow};

use crate::{
    CallError, HostSupportReason, PublishError, RuntimeIdentity,
    limits::PublicationPlan,
    operation::{RawAggregateCallResult, RawCallResult},
};

use super::{FailureInjection, Mapping};

#[derive(Debug)]
pub(crate) struct ExecutableMapping;

impl Mapping for ExecutableMapping {
    fn identity(&self) -> RuntimeIdentity {
        unreachable!("unsupported hosts cannot construct a mapping")
    }

    fn output(&self) -> OutputKind {
        unreachable!("unsupported hosts cannot construct a mapping")
    }

    fn call_contract_valid(&self, _expected_output: OutputKind) -> bool {
        false
    }

    fn invoke(&self, _haystack: &[u8], _window: SearchWindow) -> Result<RawCallResult, CallError> {
        unreachable!("unsupported hosts cannot construct a mapping")
    }

    fn aggregate_contract_valid(
        &self,
        _expected_output: AggregateOutput,
        _literal_bytes: u32,
    ) -> bool {
        false
    }

    fn invoke_aggregate(&self, _haystack: &[u8]) -> Result<RawAggregateCallResult, CallError> {
        unreachable!("unsupported hosts cannot construct a mapping")
    }
}

pub(crate) fn ensure_host_supported() -> Result<(), PublishError> {
    let reason = if !cfg!(target_arch = "aarch64") {
        HostSupportReason::Architecture
    } else if !cfg!(any(target_os = "linux", target_os = "macos")) {
        HostSupportReason::OperatingSystem
    } else if !cfg!(target_pointer_width = "64") {
        HostSupportReason::PointerWidth
    } else {
        HostSupportReason::Endianness
    };
    Err(PublishError::UnsupportedHost { reason })
}

pub(crate) fn page_size() -> Result<usize, PublishError> {
    ensure_host_supported().map(|()| 0)
}

pub(crate) const fn has_asimd() -> bool {
    false
}

pub(crate) const fn has_sve() -> bool {
    false
}

pub(crate) const fn has_sve2() -> bool {
    false
}

pub(crate) fn publish(
    _image: &NativeImage,
    _plan: PublicationPlan,
    _identity: RuntimeIdentity,
    _failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    ensure_host_supported().map(|()| ExecutableMapping)
}

pub(crate) fn publish_aggregate(
    _image: &NativeAggregateImage,
    _plan: PublicationPlan,
    _identity: RuntimeIdentity,
    _failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    ensure_host_supported().map(|()| ExecutableMapping)
}
