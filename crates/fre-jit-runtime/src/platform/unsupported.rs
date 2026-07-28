use fre_jit_aarch64::{
    AuditedNativeImage, AuditedSelectedEndRegisterImageV2, NativeAggregateImage, NativeImage,
};
use fre_kernel_ir::{AggregateOutput, OutputKind, SearchWindow};

use crate::{
    CallError, HostSupportReason, NativeHostCapabilities, PublishError, RuntimeIdentity,
    limits::PublicationPlan,
    operation::{RawAggregateCallResult, RawCallResult},
};

use super::{FailureInjection, Mapping};

#[derive(Debug)]
pub(crate) struct ExecutableMapping;

#[derive(Clone, Copy, Debug)]
pub(crate) struct SearchEntry;

#[derive(Clone, Copy, Debug)]
pub(crate) struct SelectedEndRegisterEntryV2;

impl SearchEntry {
    pub(crate) fn invoke<O: crate::RuntimeOperation>(
        self,
        _haystack: &[u8],
        _window: SearchWindow,
    ) -> RawCallResult {
        let _output = O::KIND;
        unreachable!("unsupported hosts cannot construct a search entry")
    }
}

impl SelectedEndRegisterEntryV2 {
    pub(crate) fn invoke(self, _haystack: &[u8], _window: SearchWindow) -> usize {
        unreachable!("unsupported hosts cannot construct an ABI2 search entry")
    }
}

impl ExecutableMapping {
    pub(crate) fn search_entry(&self) -> SearchEntry {
        unreachable!("unsupported hosts cannot construct a search entry")
    }

    pub(crate) fn selected_end_register_entry_v2(&self) -> SelectedEndRegisterEntryV2 {
        unreachable!("unsupported hosts cannot construct an ABI2 search entry")
    }
}

impl Mapping for ExecutableMapping {
    fn identity(&self) -> RuntimeIdentity {
        unreachable!("unsupported hosts cannot construct a mapping")
    }

    fn output(&self) -> OutputKind {
        unreachable!("unsupported hosts cannot construct a mapping")
    }

    fn sve_vector_bytes_at_publication(&self) -> Option<u16> {
        None
    }

    fn call_contract_valid(&self, _expected_output: OutputKind) -> bool {
        false
    }

    fn selected_end_register_v2_contract_valid(&self, _literal_bytes: u32) -> bool {
        false
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

pub(crate) fn capabilities() -> Result<NativeHostCapabilities, PublishError> {
    ensure_host_supported().map(|()| NativeHostCapabilities::new(false, false, false, None))
}

pub(crate) fn current_thread_sve_vector_bytes() -> Result<Option<u16>, PublishError> {
    ensure_host_supported().map(|()| None)
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
    _sve_vector_bytes_at_publication: Option<u16>,
    _failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    ensure_host_supported().map(|()| ExecutableMapping)
}

pub(crate) fn publish_audited(
    _image: &AuditedNativeImage,
    _plan: PublicationPlan,
    _identity: RuntimeIdentity,
    _sve_vector_bytes_at_publication: Option<u16>,
    _failure: FailureInjection,
) -> Result<ExecutableMapping, PublishError> {
    ensure_host_supported().map(|()| ExecutableMapping)
}

pub(crate) fn publish_selected_end_register_v2(
    _image: &AuditedSelectedEndRegisterImageV2,
    _plan: PublicationPlan,
    _identity: RuntimeIdentity,
    _literal_bytes: u32,
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
