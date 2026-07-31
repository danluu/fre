use crate::StaticCountSveThreadContractErrorV3;
use crate::StaticCountVerifyErrorV3;

pub(super) const VM_QUERY_INPUT_BYTES_UPPER_BOUND_V3: u32 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RegionPurposeV3 {
    Expectation,
    Metadata,
    Payload,
}

pub(super) fn verify_range(
    _start: usize,
    _bytes: usize,
    _purpose: RegionPurposeV3,
) -> Result<usize, StaticCountVerifyErrorV3> {
    if cfg!(feature = "linked-count-v3") {
        Err(StaticCountVerifyErrorV3::UnsupportedHost)
    } else {
        Err(StaticCountVerifyErrorV3::LinkedCountV3FeatureDisabled)
    }
}

pub(super) fn require_asimd_host_contract(
    _actual_features: u64,
    _sve_vector_length_bytes: u16,
) -> Result<(), StaticCountVerifyErrorV3> {
    if cfg!(feature = "linked-count-v3") {
        Err(StaticCountVerifyErrorV3::UnsupportedHost)
    } else {
        Err(StaticCountVerifyErrorV3::LinkedCountV3FeatureDisabled)
    }
}

pub(super) fn require_sve_host_contract(
    _actual_features: u64,
    _required_isa_id: u8,
    _sve_vector_length_bytes: u16,
) -> Result<(), StaticCountVerifyErrorV3> {
    if cfg!(feature = "linked-count-v3") {
        Err(StaticCountVerifyErrorV3::UnsupportedHost)
    } else {
        Err(StaticCountVerifyErrorV3::LinkedCountV3FeatureDisabled)
    }
}

pub(super) fn require_current_thread_sve_target_v3(
    _required_isa_id: u8,
    _actual_features: u64,
    _sve_vector_length_bytes: u16,
) -> Result<(), StaticCountSveThreadContractErrorV3> {
    Err(StaticCountSveThreadContractErrorV3::UnsupportedHost)
}

#[cfg(feature = "count-v3-qualification-private")]
pub(super) fn configure_current_thread_sve_vl16_v3()
-> Result<u16, StaticCountSveThreadContractErrorV3> {
    Err(StaticCountSveThreadContractErrorV3::UnsupportedHost)
}
