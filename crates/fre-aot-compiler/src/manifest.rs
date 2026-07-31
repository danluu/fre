use core::fmt;

use fre::{
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_CANDIDATE_IDENTITY_WORK_UPPER_BOUND_V1,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_MAX_LITERAL_BYTES_V1,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_MAX_SOURCE_BYTES_V1,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_POLICY_VERSION,
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_WORK_UPPER_BOUND_V1,
};
use fre_aot_aarch64::CountAotResource;
use fre_aot_macho::{
    CALL_ABI_SCHEMA_V1, ENTRY_OFFSET_V1, HARD_MAX_OBJECT_BYTES, HARD_MAX_PAYLOAD_BYTES,
    HARD_MAX_PERSISTENT_BYTES, HARD_MAX_SCRATCH_BYTES, HARD_MAX_SECTIONS, HARD_MAX_SYMBOLS,
    HARD_MAX_WORK, METADATA_BYTES_V1, METADATA_VERSION, MIN_MACOS_VERSION_V1, ObjectLimits,
    PLATFORM_MACOS, STATUS_BITS_V1,
};
use fre_jit_aarch64::{BackendVersion, CpuFeatures, EmitLimits, TargetSpec};
use fre_kernel_ir::{MAX_EXACT_AGGREGATE_LITERAL_BYTES, ValidateLimits};

use crate::{
    canonical::{CanonicalEncoder, CanonicalError},
    identity::ManifestIdentity,
    static_expectation::{
        STATIC_COUNT_EXPECTATION_BYTES_V1, STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V1,
        STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V1,
    },
};

pub const AOT_COMPILER_VERSION_V1: u16 = 1;
pub const AOT_MANIFEST_SCHEMA_VERSION_V1: u16 = 1;
pub const AOT_AGGREGATE_BACKEND_VERSION_V1: u16 = 1;
pub const SUPPORTED_AOT_AGGREGATE_BACKEND_VERSIONS_V1: &[u16] = &[AOT_AGGREGATE_BACKEND_VERSION_V1];
const _: () = assert!(BackendVersion::AGGREGATE_CURRENT.0 == AOT_AGGREGATE_BACKEND_VERSION_V1);

/// Hard pre-parse source ceiling for the fixed exact-literal planning path.
pub const MAX_AOT_SOURCE_BYTES_V1: u64 = AGGREGATE_COUNT_EXACT_LITERAL_AOT_MAX_SOURCE_BYTES_V1;
pub const MIN_PIPELINE_PEAK_LIVE_BYTES_V1: u64 = 96 << 20;
pub const MAX_NATIVE_AGGREGATE_AUDIT_WORK_V1: u64 = 16 << 20;

/// Hard ceiling on compiler-owned identity hashing for one admitted compile.
///
/// Stage-local KIR, native-image, payload, and whole-object hashing is charged
/// in the corresponding stage receipts instead.
pub const MAX_COMPILER_IDENTITY_WORK_V1: u64 = 16 << 10;

const MANIFEST_DOMAIN: &[u8] = b"FRE-AOT-COMPILER-MANIFEST\0\x01";
const _: () = assert!(
    AGGREGATE_COUNT_EXACT_LITERAL_AOT_MAX_LITERAL_BYTES_V1 == MAX_EXACT_AGGREGATE_LITERAL_BYTES
);
const MAX_EXACT_AGGREGATE_LITERAL_BYTES_U64: u64 = 32;
const _: () = assert!(MAX_EXACT_AGGREGATE_LITERAL_BYTES == 32);
/// Every caller-selected bound for one exact-literal count compilation.
///
/// These values remain part of the manifest identity even when the selected
/// program uses less fuel. The compiler never silently widens a field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompilePolicyV1 {
    pub max_source_bytes: u64,
    pub max_literal_bytes: u64,
    pub max_facade_planning_work: u64,
    pub max_candidate_identity_work: u64,
    pub kernel_ir: ValidateLimits,
    pub native: EmitLimits,
    pub object: ObjectLimits,
    pub max_pipeline_work: u64,
    pub max_final_persistent_bytes: u64,
    pub max_peak_scratch_bytes: u64,
    pub max_pipeline_peak_live_bytes: u64,
}

impl CompilePolicyV1 {
    /// Explicit high-fuel defaults for the narrow width-32 vertical slice.
    ///
    /// The large work allowance is still finite and composes the declared
    /// maxima of validation, emission, both native audits, object publication,
    /// and compiler-owned identity hashing.
    #[must_use]
    pub const fn high_fuel() -> Self {
        Self {
            max_source_bytes: MAX_AOT_SOURCE_BYTES_V1,
            max_literal_bytes: MAX_EXACT_AGGREGATE_LITERAL_BYTES_U64,
            max_facade_planning_work: 4 << 20,
            max_candidate_identity_work: 4 << 20,
            kernel_ir: ValidateLimits {
                max_blocks: 64,
                max_instructions: 64,
                max_data_blobs: 16,
                max_data_bytes: 1 << 20,
                max_serialized_bytes: (1 << 20) + 4_096,
                max_serialized_capacity_bytes: (1 << 20) + 4_096,
                max_construction_allocation_bytes: 4 << 20,
                max_raw_program_capacity_bytes: 2 << 20,
                max_estimated_code_bytes: 1 << 20,
                max_validation_work: 8 << 20,
                max_construction_work: 16 << 20,
                max_validation_scratch_bytes: 1 << 20,
                max_validation_phase_bytes: 4 << 20,
                max_serialization_phase_bytes: 4 << 20,
                max_identity_phase_bytes: 4 << 20,
                max_retained_program_bytes: 4 << 20,
                max_work_factor: (1 << 20) + 16,
            },
            native: EmitLimits {
                max_code_bytes: 64 << 10,
                max_data_bytes: 1 << 20,
                max_relocations: 256,
                max_labels: 128,
                max_emission_work: 4 << 20,
                max_scratch_bytes: 64 << 10,
            },
            object: ObjectLimits {
                max_object_bytes: HARD_MAX_OBJECT_BYTES,
                max_persistent_bytes: HARD_MAX_PERSISTENT_BYTES,
                max_payload_bytes: HARD_MAX_PAYLOAD_BYTES,
                max_work: HARD_MAX_WORK,
                max_scratch_bytes: HARD_MAX_SCRATCH_BYTES,
                max_sections: HARD_MAX_SECTIONS,
                max_symbols: HARD_MAX_SYMBOLS,
            },
            max_pipeline_work: 128 << 20,
            max_final_persistent_bytes: 8 << 20,
            max_peak_scratch_bytes: 8 << 20,
            max_pipeline_peak_live_bytes: 128 << 20,
        }
    }
}

impl Default for CompilePolicyV1 {
    fn default() -> Self {
        Self::high_fuel()
    }
}

/// Structural refusal while sealing a typed manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ManifestError {
    SourcePolicyExceedsHardLimit {
        limit: u64,
        requested: u64,
    },
    LiteralPolicyExceedsHardLimit {
        limit: u64,
        requested: u64,
    },
    LiteralPolicyBelowFixedEnvelope {
        required: u64,
        supplied: u64,
    },
    InconsistentWorkCeiling {
        declared_stage_maximum: u64,
        pipeline_limit: u64,
    },
    InsufficientFacadePlanningCeiling {
        required: u64,
        supplied: u64,
    },
    InsufficientCandidateIdentityCeiling {
        required: u64,
        supplied: u64,
    },
    InsufficientPipelinePeakLiveCeiling {
        required: u64,
        supplied: u64,
    },
    InconsistentScratchCeiling {
        declared_stage_maximum: u64,
        peak_limit: u64,
    },
    CountNativePolicyExceedsHardLimit {
        resource: CountAotResource,
        limit: u64,
        requested: u64,
    },
    UnsupportedCountBackendTuple,
    ArithmeticOverflow,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid FRE AOT manifest: {self:?}")
    }
}

impl std::error::Error for ManifestError {}

/// Sealed v1 request for a normal macOS `AArch64` aggregate-count object.
///
/// Target, ABI, status width, output, object schema, and minimum OS are fixed
/// by this type. Private fields ensure only [`Self::new`] can create a value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacosAarch64CountManifestV1 {
    policy: CompilePolicyV1,
    identity: ManifestIdentity,
    identity_bytes_hashed: u64,
    declared_stage_work_upper_bound: u64,
}

impl MacosAarch64CountManifestV1 {
    pub fn new(policy: CompilePolicyV1) -> Result<Self, ManifestError> {
        if policy.max_source_bytes > MAX_AOT_SOURCE_BYTES_V1 {
            return Err(ManifestError::SourcePolicyExceedsHardLimit {
                limit: MAX_AOT_SOURCE_BYTES_V1,
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
        if policy.max_pipeline_peak_live_bytes < MIN_PIPELINE_PEAK_LIVE_BYTES_V1 {
            return Err(ManifestError::InsufficientPipelinePeakLiveCeiling {
                required: MIN_PIPELINE_PEAK_LIVE_BYTES_V1,
                supplied: policy.max_pipeline_peak_live_bytes,
            });
        }
        let declared_stage_work_upper_bound = declared_stage_work_upper_bound(&policy)?;
        if declared_stage_work_upper_bound > policy.max_pipeline_work {
            return Err(ManifestError::InconsistentWorkCeiling {
                declared_stage_maximum: declared_stage_work_upper_bound,
                pipeline_limit: policy.max_pipeline_work,
            });
        }
        let declared_scratch = policy
            .kernel_ir
            .max_validation_scratch_bytes
            .max(policy.native.max_scratch_bytes)
            .max(policy.object.max_scratch_bytes);
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
        let encoded = encode_manifest(&policy).map_err(map_canonical)?;
        Ok(Self {
            policy,
            identity: ManifestIdentity::new(encoded.bytes),
            identity_bytes_hashed: encoded.hashed_bytes,
            declared_stage_work_upper_bound,
        })
    }

    #[must_use]
    pub const fn policy(&self) -> CompilePolicyV1 {
        self.policy
    }

    #[must_use]
    pub const fn identity(&self) -> ManifestIdentity {
        self.identity
    }

    #[must_use]
    pub const fn identity_bytes_hashed(&self) -> u64 {
        self.identity_bytes_hashed
    }

    /// Architectural features every admitted object requires.
    #[must_use]
    pub const fn required_cpu_features(&self) -> CpuFeatures {
        CpuFeatures::NONE
    }

    /// Complete feature mask an emitted object may require.
    #[must_use]
    pub const fn allowed_cpu_features(&self) -> CpuFeatures {
        CpuFeatures::ASIMD
    }

    #[must_use]
    pub const fn declared_stage_work_upper_bound(&self) -> u64 {
        self.declared_stage_work_upper_bound
    }

    pub(crate) fn authenticates_itself(&self) -> bool {
        let Ok(encoded) = encode_manifest(&self.policy) else {
            return false;
        };
        self.identity == ManifestIdentity::new(encoded.bytes)
            && self.identity_bytes_hashed == encoded.hashed_bytes
            && declared_stage_work_upper_bound(&self.policy)
                .is_ok_and(|work| work == self.declared_stage_work_upper_bound)
    }
}

impl Default for MacosAarch64CountManifestV1 {
    fn default() -> Self {
        Self::new(CompilePolicyV1::high_fuel())
            .expect("the fixed v1 high-fuel manifest must remain internally consistent")
    }
}

fn declared_stage_work_upper_bound(policy: &CompilePolicyV1) -> Result<u64, ManifestError> {
    policy
        .max_facade_planning_work
        // UTF-8 validation is compiler-owned and occurs after the byte
        // length/capacity gates but before the facade receives a `String`.
        .checked_add(policy.max_source_bytes)
        .and_then(|work| work.checked_add(policy.kernel_ir.max_construction_work))
        .and_then(|work| work.checked_add(policy.native.max_emission_work))
        .and_then(|work| work.checked_add(MAX_NATIVE_AGGREGATE_AUDIT_WORK_V1))
        .and_then(|work| work.checked_add(policy.object.max_work))
        .and_then(|work| work.checked_add(MAX_COMPILER_IDENTITY_WORK_V1))
        .and_then(|work| {
            work.checked_add(STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V1)
        })
        .ok_or(ManifestError::ArithmeticOverflow)
}

fn encode_manifest(
    policy: &CompilePolicyV1,
) -> Result<crate::canonical::EncodedDigest, CanonicalError> {
    let mut encoder = CanonicalEncoder::hashing();
    encoder.raw(MANIFEST_DOMAIN)?;
    encoder.u16(AOT_MANIFEST_SCHEMA_VERSION_V1)?;
    encoder.u16(AOT_COMPILER_VERSION_V1)?;
    encoder.u32(AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_POLICY_VERSION)?;
    encoder.u64(AGGREGATE_COUNT_EXACT_LITERAL_AOT_PLANNING_WORK_UPPER_BOUND_V1)?;
    encoder.u64(AGGREGATE_COUNT_EXACT_LITERAL_AOT_CANDIDATE_IDENTITY_WORK_UPPER_BOUND_V1)?;

    let target = TargetSpec::AARCH64_AAPCS64;
    encoder.u8(target.architecture)?;
    encoder.boolean(target.little_endian)?;
    encoder.u8(target.pointer_width)?;
    encoder.u8(target.abi)?;
    // Generic AArch64 is the baseline; ASIMD is the complete allowed mask.
    // The sealed receipt separately records the exact emitted requirement.
    encoder.u64(CpuFeatures::NONE.bits())?;
    encoder.u64(CpuFeatures::ASIMD.bits())?;
    encoder.u16(AOT_AGGREGATE_BACKEND_VERSION_V1)?;
    encoder.u16(1)?;
    encoder.u16(SUPPORTED_AOT_AGGREGATE_BACKEND_VERSIONS_V1[0])?;
    encoder.u8(2)?; // AbiKind::Aggregate.
    encoder.u8(1)?; // AggregateOutput::Count.
    encoder.u8(PLATFORM_MACOS)?;
    encoder.u32(MIN_MACOS_VERSION_V1)?;
    encoder.u8(STATUS_BITS_V1)?;
    encoder.u16(CALL_ABI_SCHEMA_V1)?;
    encoder.u16(METADATA_VERSION)?;
    encoder.usize(METADATA_BYTES_V1)?;
    encoder.u32(ENTRY_OFFSET_V1)?;
    encoder.usize(MAX_EXACT_AGGREGATE_LITERAL_BYTES)?;

    encoder.u64(policy.max_source_bytes)?;
    encoder.u64(policy.max_literal_bytes)?;
    encoder.u64(policy.max_facade_planning_work)?;
    encoder.u64(policy.max_candidate_identity_work)?;
    encode_validate_limits(&mut encoder, policy.kernel_ir)?;
    encode_emit_limits(&mut encoder, policy.native)?;
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
    encoder.u64(MAX_COMPILER_IDENTITY_WORK_V1)?;
    encoder.u64(MAX_AOT_SOURCE_BYTES_V1)?;
    encoder.u64(MIN_PIPELINE_PEAK_LIVE_BYTES_V1)?;
    encoder.u64(MAX_NATIVE_AGGREGATE_AUDIT_WORK_V1)?;
    encoder.u64(STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V1)?;
    encoder.usize(STATIC_COUNT_EXPECTATION_BYTES_V1)?;
    encoder.usize(STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V1)?;
    encoder.finish()
}

pub(crate) fn encode_validate_limits(
    encoder: &mut CanonicalEncoder,
    limits: ValidateLimits,
) -> Result<(), CanonicalError> {
    encoder.u64(limits.max_blocks)?;
    encoder.u64(limits.max_instructions)?;
    encoder.u64(limits.max_data_blobs)?;
    encoder.u64(limits.max_data_bytes)?;
    encoder.u64(limits.max_serialized_bytes)?;
    encoder.u64(limits.max_serialized_capacity_bytes)?;
    encoder.u64(limits.max_construction_allocation_bytes)?;
    encoder.u64(limits.max_raw_program_capacity_bytes)?;
    encoder.u64(limits.max_estimated_code_bytes)?;
    encoder.u64(limits.max_validation_work)?;
    encoder.u64(limits.max_construction_work)?;
    encoder.u64(limits.max_validation_scratch_bytes)?;
    encoder.u64(limits.max_validation_phase_bytes)?;
    encoder.u64(limits.max_serialization_phase_bytes)?;
    encoder.u64(limits.max_identity_phase_bytes)?;
    encoder.u64(limits.max_retained_program_bytes)?;
    encoder.u64(limits.max_work_factor)
}

pub(crate) fn encode_emit_limits(
    encoder: &mut CanonicalEncoder,
    limits: EmitLimits,
) -> Result<(), CanonicalError> {
    encoder.u64(limits.max_code_bytes)?;
    encoder.u64(limits.max_data_bytes)?;
    encoder.u64(limits.max_relocations)?;
    encoder.u64(limits.max_labels)?;
    encoder.u64(limits.max_emission_work)?;
    encoder.u64(limits.max_scratch_bytes)
}

pub(crate) fn encode_object_limits(
    encoder: &mut CanonicalEncoder,
    limits: ObjectLimits,
) -> Result<(), CanonicalError> {
    encoder.u64(limits.max_object_bytes)?;
    encoder.u64(limits.max_persistent_bytes)?;
    encoder.u64(limits.max_payload_bytes)?;
    encoder.u64(limits.max_work)?;
    encoder.u64(limits.max_scratch_bytes)?;
    encoder.u64(limits.max_sections)?;
    encoder.u64(limits.max_symbols)
}

const fn map_canonical(_error: CanonicalError) -> ManifestError {
    ManifestError::ArithmeticOverflow
}
