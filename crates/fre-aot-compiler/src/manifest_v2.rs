use fre::{
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_CANDIDATE_IDENTITY_WORK_UPPER_BOUND_V1,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_MAX_LITERAL_BYTES_V1,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_MAX_SOURCE_BYTES_V1,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_POLICY_VERSION,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_WORK_UPPER_BOUND_V1,
};
use fre_aot_aarch64::{
    AOT_COUNT_IMAGE_SCHEMA_VERSION_V2, AotCountBackendSupportV2, AotCountCpuFeatures,
    CountAotResource, CountEmitLimitsV2, SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2,
    is_supported_aot_count_backend_tuple_v2,
};
use fre_aot_macho::{
    CALL_ABI_SCHEMA_V2, ENTRY_OFFSET_V2, HARD_MAX_OBJECT_BYTES, HARD_MAX_PAYLOAD_BYTES,
    HARD_MAX_PERSISTENT_BYTES, HARD_MAX_SCRATCH_BYTES, HARD_MAX_SECTIONS, HARD_MAX_SYMBOLS,
    HARD_MAX_WORK, METADATA_BYTES_V2, METADATA_VERSION_V2, MIN_MACOS_VERSION_V1, ObjectLimits,
    PLATFORM_MACOS, STATUS_BITS_V2,
};
use fre_kernel_ir::{MAX_EXACT_AGGREGATE_LITERAL_BYTES, ValidateLimits};

use crate::{
    canonical::{CanonicalEncoder, CanonicalError},
    identity::{ManifestIdentity, PolicyLimitsIdentity},
    manifest::{ManifestError, encode_object_limits, encode_validate_limits},
    static_expectation_v2::{
        STATIC_COUNT_EXPECTATION_BYTES_V2,
        STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2,
        STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_TRAVERSED_V2,
        STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2, STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2,
        STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2,
        STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2,
        STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V2,
    },
};

pub const AOT_COMPILER_VERSION_V2: u16 = 2;
pub const AOT_MANIFEST_SCHEMA_VERSION_V2: u16 = 2;
pub const AOT_COMPILE_RECEIPT_SCHEMA_VERSION_V2: u16 = 2;
pub const AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2: u16 = 2;
pub const MAX_AOT_SOURCE_BYTES_V2: u64 = AGGREGATE_COUNT_EXACT_LITERAL_AOT_MAX_SOURCE_BYTES_V1;
pub const MAX_COMPILER_IDENTITY_WORK_V2: u64 = 32 << 10;
pub const MIN_PIPELINE_PEAK_LIVE_BYTES_V2: u64 = 96 << 20;
pub const POLICY_LIMITS_CANONICAL_BYTES_V2: u64 = 392;

const MANIFEST_DOMAIN_V2: &[u8] = b"FRE-AOT-COMPILER-MANIFEST\0\x02";
const POLICY_LIMITS_DOMAIN_V2: &[u8] = b"FRE-AOT-COMPILER-POLICY-LIMITS\0\x02";
const MAX_EXACT_AGGREGATE_LITERAL_BYTES_U64: u64 = 32;
const _: () = assert!(MAX_EXACT_AGGREGATE_LITERAL_BYTES == 32);
const _: () = assert!(
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_MAX_LITERAL_BYTES_V1 == MAX_EXACT_AGGREGATE_LITERAL_BYTES
);
const _: () = assert!(SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2.len() == 1);

/// The one exact backend/KIR/output/target tuple admitted by compiler v2.
pub const AOT_COUNT_COMPILER_SUPPORT_V2: AotCountBackendSupportV2 =
    SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2[0];

/// Caller-selected finite limits for the explicit Count compiler-v2 path.
///
/// This is intentionally a different type from [`crate::CompilePolicyV1`].
/// In particular, `native` is the direct Count AOT backend's typed policy and
/// can never be interpreted as generic JIT-emitter limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompilePolicyV2 {
    pub max_source_bytes: u64,
    pub max_literal_bytes: u64,
    pub max_facade_planning_work: u64,
    pub max_candidate_identity_work: u64,
    pub kernel_ir: ValidateLimits,
    pub native: CountEmitLimitsV2,
    pub object: ObjectLimits,
    pub max_pipeline_work: u64,
    pub max_final_persistent_bytes: u64,
    pub max_peak_scratch_bytes: u64,
    pub max_pipeline_peak_live_bytes: u64,
}

impl CompilePolicyV2 {
    #[must_use]
    pub const fn high_fuel() -> Self {
        let legacy = crate::CompilePolicyV1::high_fuel();
        Self {
            max_source_bytes: MAX_AOT_SOURCE_BYTES_V2,
            max_literal_bytes: MAX_EXACT_AGGREGATE_LITERAL_BYTES_U64,
            max_facade_planning_work: legacy.max_facade_planning_work,
            max_candidate_identity_work: legacy.max_candidate_identity_work,
            kernel_ir: legacy.kernel_ir,
            native: CountEmitLimitsV2 {
                max_code_bytes: 16 << 10,
                max_data_bytes: 0,
                max_labels: 18,
                max_relocations: 96,
                max_work: 2 << 20,
                max_scratch_bytes: 128 << 10,
                max_persistent_bytes: 128 << 10,
            },
            object: legacy.object,
            // This covers both the publication audit and the compiler-v2
            // post-publication validation audit.
            max_pipeline_work: 192 << 20,
            max_final_persistent_bytes: 8 << 20,
            max_peak_scratch_bytes: 8 << 20,
            max_pipeline_peak_live_bytes: 128 << 20,
        }
    }
}

impl Default for CompilePolicyV2 {
    fn default() -> Self {
        Self::high_fuel()
    }
}

/// Sealed request for the explicit direct-Count compiler-v2 pipeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacosAarch64CountManifestV2 {
    policy: CompilePolicyV2,
    support: AotCountBackendSupportV2,
    identity: ManifestIdentity,
    identity_bytes_hashed: u64,
    policy_limits_identity: PolicyLimitsIdentity,
    policy_limits_identity_bytes_hashed: u64,
    declared_stage_work_upper_bound: u64,
}

impl MacosAarch64CountManifestV2 {
    pub fn new(policy: CompilePolicyV2) -> Result<Self, ManifestError> {
        validate_policy(&policy)?;
        let support = AOT_COUNT_COMPILER_SUPPORT_V2;
        if !is_supported_aot_count_backend_tuple_v2(support) {
            return Err(ManifestError::UnsupportedCountBackendTuple);
        }
        let declared_stage_work_upper_bound = declared_stage_work_upper_bound(&policy)?;
        if declared_stage_work_upper_bound > policy.max_pipeline_work {
            return Err(ManifestError::InconsistentWorkCeiling {
                declared_stage_maximum: declared_stage_work_upper_bound,
                pipeline_limit: policy.max_pipeline_work,
            });
        }
        let encoded = encode_manifest_v2(&policy, support).map_err(map_canonical)?;
        let identity = ManifestIdentity::new(encoded.bytes);
        let policy_limits =
            encode_policy_limits_v2(&policy, identity, support).map_err(map_canonical)?;
        Ok(Self {
            policy,
            support,
            identity,
            identity_bytes_hashed: encoded.hashed_bytes,
            policy_limits_identity: PolicyLimitsIdentity::new(policy_limits.bytes),
            policy_limits_identity_bytes_hashed: policy_limits.hashed_bytes,
            declared_stage_work_upper_bound,
        })
    }

    #[must_use]
    pub const fn policy(&self) -> &CompilePolicyV2 {
        &self.policy
    }

    #[must_use]
    pub const fn support(&self) -> AotCountBackendSupportV2 {
        self.support
    }

    #[must_use]
    pub const fn identity(&self) -> ManifestIdentity {
        self.identity
    }

    #[must_use]
    pub const fn identity_bytes_hashed(&self) -> u64 {
        self.identity_bytes_hashed
    }

    #[must_use]
    pub const fn policy_limits_identity(&self) -> PolicyLimitsIdentity {
        self.policy_limits_identity
    }

    #[must_use]
    pub const fn policy_limits_identity_bytes_hashed(&self) -> u64 {
        self.policy_limits_identity_bytes_hashed
    }

    #[must_use]
    pub const fn declared_stage_work_upper_bound(&self) -> u64 {
        self.declared_stage_work_upper_bound
    }

    #[must_use]
    /// Manifest-wide architectural baseline.
    ///
    /// Empty Count images bind `NONE`; every nonempty image binds `ASIMD` in
    /// its target, object metadata, receipt, and static expectation. The
    /// compiler checks that exact per-image requirement against
    /// [`Self::allowed_cpu_features`] before object publication.
    pub const fn required_cpu_features(&self) -> AotCountCpuFeatures {
        AotCountCpuFeatures::NONE
    }

    #[must_use]
    /// Complete feature mask any object produced under this manifest may use.
    pub const fn allowed_cpu_features(&self) -> AotCountCpuFeatures {
        self.support.allowed_features
    }

    pub(crate) fn authenticates_itself(&self) -> bool {
        self.support == AOT_COUNT_COMPILER_SUPPORT_V2
            && is_supported_aot_count_backend_tuple_v2(self.support)
            && encode_manifest_v2(&self.policy, self.support).is_ok_and(|encoded| {
                self.identity == ManifestIdentity::new(encoded.bytes)
                    && self.identity_bytes_hashed == encoded.hashed_bytes
            })
            && encode_policy_limits_v2(&self.policy, self.identity, self.support).is_ok_and(
                |encoded| {
                    self.policy_limits_identity == PolicyLimitsIdentity::new(encoded.bytes)
                        && self.policy_limits_identity_bytes_hashed == encoded.hashed_bytes
                },
            )
            && declared_stage_work_upper_bound(&self.policy)
                .is_ok_and(|work| work == self.declared_stage_work_upper_bound)
    }
}

impl Default for MacosAarch64CountManifestV2 {
    fn default() -> Self {
        Self::new(CompilePolicyV2::high_fuel())
            .expect("the fixed compiler-v2 manifest must remain internally consistent")
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one manifest admission transaction visibly checks every caller-selected v2 limit"
)]
fn validate_policy(policy: &CompilePolicyV2) -> Result<(), ManifestError> {
    if policy.max_source_bytes > MAX_AOT_SOURCE_BYTES_V2 {
        return Err(ManifestError::SourcePolicyExceedsHardLimit {
            limit: MAX_AOT_SOURCE_BYTES_V2,
            requested: policy.max_source_bytes,
        });
    }
    let hard_literal = u64::try_from(MAX_EXACT_AGGREGATE_LITERAL_BYTES)
        .map_err(|_| ManifestError::ArithmeticOverflow)?;
    if policy.max_literal_bytes > hard_literal {
        return Err(ManifestError::LiteralPolicyExceedsHardLimit {
            limit: hard_literal,
            requested: policy.max_literal_bytes,
        });
    }
    if policy.max_literal_bytes < hard_literal {
        return Err(ManifestError::LiteralPolicyBelowFixedEnvelope {
            required: hard_literal,
            supplied: policy.max_literal_bytes,
        });
    }
    if policy.max_facade_planning_work
        < AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_WORK_UPPER_BOUND_V1
    {
        return Err(ManifestError::InsufficientFacadePlanningCeiling {
            required: AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_WORK_UPPER_BOUND_V1,
            supplied: policy.max_facade_planning_work,
        });
    }
    if policy.max_candidate_identity_work
        < AGGREGATE_COUNT_EXACT_LITERAL_AOT_CANDIDATE_IDENTITY_WORK_UPPER_BOUND_V1
    {
        return Err(ManifestError::InsufficientCandidateIdentityCeiling {
            required: AGGREGATE_COUNT_EXACT_LITERAL_AOT_CANDIDATE_IDENTITY_WORK_UPPER_BOUND_V1,
            supplied: policy.max_candidate_identity_work,
        });
    }
    if policy.max_pipeline_peak_live_bytes < MIN_PIPELINE_PEAK_LIVE_BYTES_V2 {
        return Err(ManifestError::InsufficientPipelinePeakLiveCeiling {
            required: MIN_PIPELINE_PEAK_LIVE_BYTES_V2,
            supplied: policy.max_pipeline_peak_live_bytes,
        });
    }
    let hard = CountEmitLimitsV2::default();
    for (resource, requested, limit) in [
        (
            CountAotResource::CodeBytes,
            policy.native.max_code_bytes,
            hard.max_code_bytes,
        ),
        (
            CountAotResource::DataBytes,
            policy.native.max_data_bytes,
            hard.max_data_bytes,
        ),
        (
            CountAotResource::Labels,
            policy.native.max_labels,
            hard.max_labels,
        ),
        (
            CountAotResource::Relocations,
            policy.native.max_relocations,
            hard.max_relocations,
        ),
        (
            CountAotResource::Work,
            policy.native.max_work,
            hard.max_work,
        ),
        (
            CountAotResource::ScratchBytes,
            policy.native.max_scratch_bytes,
            hard.max_scratch_bytes,
        ),
        (
            CountAotResource::PersistentBytes,
            policy.native.max_persistent_bytes,
            hard.max_persistent_bytes,
        ),
    ] {
        if requested > limit {
            return Err(ManifestError::CountNativePolicyExceedsHardLimit {
                resource,
                limit,
                requested,
            });
        }
    }
    let declared_scratch = policy
        .kernel_ir
        .max_validation_scratch_bytes
        .max(policy.native.max_scratch_bytes)
        .max(policy.object.max_scratch_bytes)
        .max(STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2);
    if declared_scratch > policy.max_peak_scratch_bytes {
        return Err(ManifestError::InconsistentScratchCeiling {
            declared_stage_maximum: declared_scratch,
            peak_limit: policy.max_peak_scratch_bytes,
        });
    }
    if policy.max_peak_scratch_bytes > policy.max_pipeline_peak_live_bytes {
        return Err(ManifestError::InconsistentScratchCeiling {
            declared_stage_maximum: policy.max_peak_scratch_bytes,
            peak_limit: policy.max_pipeline_peak_live_bytes,
        });
    }
    Ok(())
}

fn declared_stage_work_upper_bound(policy: &CompilePolicyV2) -> Result<u64, ManifestError> {
    policy
        .max_facade_planning_work
        .checked_add(policy.max_source_bytes)
        .and_then(|work| work.checked_add(policy.kernel_ir.max_construction_work))
        .and_then(|work| work.checked_add(policy.native.max_work))
        // Object publication plus the required compiler-v2 validation pass.
        .and_then(|work| work.checked_add(policy.object.max_work))
        .and_then(|work| work.checked_add(policy.object.max_work))
        .and_then(|work| work.checked_add(MAX_COMPILER_IDENTITY_WORK_V2))
        .and_then(|work| {
            work.checked_add(STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2)
        })
        .ok_or(ManifestError::ArithmeticOverflow)
}

fn encode_manifest_v2(
    policy: &CompilePolicyV2,
    support: AotCountBackendSupportV2,
) -> Result<crate::canonical::EncodedDigest, CanonicalError> {
    #[cfg(test)]
    manifest_encode_trace::record();
    let mut encoder = CanonicalEncoder::hashing();
    encoder.raw(MANIFEST_DOMAIN_V2)?;
    encoder.u16(AOT_MANIFEST_SCHEMA_VERSION_V2)?;
    encoder.u16(AOT_COMPILER_VERSION_V2)?;
    encoder.u16(AOT_COMPILE_RECEIPT_SCHEMA_VERSION_V2)?;
    encoder.u16(AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2)?;
    encoder.u32(AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_POLICY_VERSION)?;
    encoder.u64(AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_WORK_UPPER_BOUND_V1)?;
    encoder.u64(AGGREGATE_COUNT_EXACT_LITERAL_AOT_CANDIDATE_IDENTITY_WORK_UPPER_BOUND_V1)?;
    encoder.u16(AOT_COUNT_IMAGE_SCHEMA_VERSION_V2)?;
    encode_support(&mut encoder, support)?;
    encoder.u8(2)?; // AbiKind::Aggregate.
    encoder.u8(PLATFORM_MACOS)?;
    encoder.u32(MIN_MACOS_VERSION_V1)?;
    encoder.u8(STATUS_BITS_V2)?;
    encoder.u16(CALL_ABI_SCHEMA_V2)?;
    encoder.u16(METADATA_VERSION_V2)?;
    encoder.usize(METADATA_BYTES_V2)?;
    encoder.u32(ENTRY_OFFSET_V2)?;

    encoder.u64(policy.max_source_bytes)?;
    encoder.u64(policy.max_literal_bytes)?;
    encoder.u64(policy.max_facade_planning_work)?;
    encoder.u64(policy.max_candidate_identity_work)?;
    encode_validate_limits(&mut encoder, policy.kernel_ir)?;
    encode_count_emit_limits(&mut encoder, policy.native)?;
    encode_object_limits(&mut encoder, policy.object)?;
    encoder.u64(policy.max_pipeline_work)?;
    encoder.u64(policy.max_final_persistent_bytes)?;
    encoder.u64(policy.max_peak_scratch_bytes)?;
    encoder.u64(policy.max_pipeline_peak_live_bytes)?;

    encoder.u64(HARD_MAX_PAYLOAD_BYTES)?;
    encoder.u64(HARD_MAX_OBJECT_BYTES)?;
    encoder.u64(HARD_MAX_PERSISTENT_BYTES)?;
    encoder.u64(HARD_MAX_WORK)?;
    encoder.u64(HARD_MAX_SCRATCH_BYTES)?;
    encoder.u64(HARD_MAX_SECTIONS)?;
    encoder.u64(HARD_MAX_SYMBOLS)?;
    encoder.u64(MAX_COMPILER_IDENTITY_WORK_V2)?;
    encoder.u64(MAX_AOT_SOURCE_BYTES_V2)?;
    encoder.u64(MIN_PIPELINE_PEAK_LIVE_BYTES_V2)?;
    encoder.u64(STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2)?;
    encoder.u64(STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_TRAVERSED_V2)?;
    encoder.u64(STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2)?;
    encoder.u64(STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2)?;
    encoder.usize(STATIC_COUNT_EXPECTATION_BYTES_V2)?;
    encoder.usize(STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2)?;
    encoder.usize(STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2)?;
    encoder.usize(STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V2)?;
    encoder.finish()
}

fn encode_policy_limits_v2(
    policy: &CompilePolicyV2,
    manifest_identity: ManifestIdentity,
    support: AotCountBackendSupportV2,
) -> Result<crate::canonical::EncodedDigest, CanonicalError> {
    #[cfg(test)]
    policy_limits_encode_trace::record();
    let mut encoder = CanonicalEncoder::hashing();
    encoder.raw(POLICY_LIMITS_DOMAIN_V2)?;
    encoder.raw(manifest_identity.as_bytes())?;
    encoder.u64(policy.max_source_bytes)?;
    encoder.u64(policy.max_literal_bytes)?;
    encoder.u64(policy.max_facade_planning_work)?;
    encoder.u64(policy.max_candidate_identity_work)?;
    encode_validate_limits(&mut encoder, policy.kernel_ir)?;
    encode_count_emit_limits(&mut encoder, policy.native)?;
    encode_object_limits(&mut encoder, policy.object)?;
    encoder.u64(policy.max_pipeline_work)?;
    encoder.u64(policy.max_final_persistent_bytes)?;
    encoder.u64(policy.max_peak_scratch_bytes)?;
    encoder.u64(policy.max_pipeline_peak_live_bytes)?;
    encoder.u64(AotCountCpuFeatures::NONE.bits())?;
    encoder.u64(support.allowed_features.bits())?;
    let projection = encoder.finish()?;
    if projection.hashed_bytes != POLICY_LIMITS_CANONICAL_BYTES_V2 {
        return Err(CanonicalError::ByteCountOverflow);
    }
    Ok(projection)
}

pub(crate) fn encode_support(
    encoder: &mut CanonicalEncoder,
    support: AotCountBackendSupportV2,
) -> Result<(), CanonicalError> {
    encoder.u16(support.backend_version.0)?;
    encoder.u16(support.algorithm_version)?;
    encoder.u16(support.kir_semantics_version)?;
    encoder.u16(support.kir_abi_version)?;
    encoder.u8(support.output_kind)?;
    encoder.u8(support.architecture)?;
    encoder.boolean(support.little_endian)?;
    encoder.u8(support.pointer_width)?;
    encoder.u8(support.target_abi)?;
    encoder.u64(support.allowed_features.bits())?;
    encoder.u16(support.max_literal_bytes)?;
    encoder.u8(support.candidate_block_starts)
}

fn encode_count_emit_limits(
    encoder: &mut CanonicalEncoder,
    limits: CountEmitLimitsV2,
) -> Result<(), CanonicalError> {
    encoder.u64(limits.max_code_bytes)?;
    encoder.u64(limits.max_data_bytes)?;
    encoder.u64(limits.max_labels)?;
    encoder.u64(limits.max_relocations)?;
    encoder.u64(limits.max_work)?;
    encoder.u64(limits.max_scratch_bytes)?;
    encoder.u64(limits.max_persistent_bytes)
}

const fn map_canonical(_error: CanonicalError) -> ManifestError {
    ManifestError::ArithmeticOverflow
}

#[cfg(test)]
pub(crate) mod manifest_encode_trace {
    use std::cell::Cell;

    std::thread_local! {
        static ENCODE_PASSES: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn record() {
        ENCODE_PASSES.with(|passes| passes.set(passes.get().saturating_add(1)));
    }

    pub(crate) fn reset() {
        ENCODE_PASSES.with(|passes| passes.set(0));
    }

    pub(crate) fn passes() -> u64 {
        ENCODE_PASSES.with(Cell::get)
    }
}

#[cfg(test)]
pub(crate) mod policy_limits_encode_trace {
    use std::cell::Cell;

    std::thread_local! {
        static ENCODE_PASSES: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn record() {
        ENCODE_PASSES.with(|passes| passes.set(passes.get().saturating_add(1)));
    }

    pub(crate) fn reset() {
        ENCODE_PASSES.with(|passes| passes.set(0));
    }

    pub(crate) fn passes() -> u64 {
        ENCODE_PASSES.with(Cell::get)
    }
}
