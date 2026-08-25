//! Explicit exact-singleton Count-v3 candidate preparation.
//!
//! This module consumes only an authenticated finite-language witness and
//! structural target/limit facts. It never observes a haystack, benchmark,
//! corpus name, or source-pattern identity outside the bound artifact hash.

use fre_aot_aarch64::{
    AOT_COUNT_CODE_ALIGNMENT_V3, AotCountMappedMetadataV3, CountAotError, CountAotUnsupported,
    CountEmitLimitsV3, audit_count_mapped_code_v3,
};
use fre_aot_count_compiler::{
    CountCompileErrorV3, CountCompileLimitsV3, CountCompileRequestV3, CountCompileTargetV3,
    CountObjectFormatV3, CountObjectLimitsV3, CountSemanticCandidateV3, compile_count_v3,
};
use fre_aot_optimizer::{
    COUNT_V3_RECIPE_CANONICAL_BYTES, CountV3OptimizeError, CountV3RequiredIsa,
    CountV3Strategy, CountV3TuningClass, encode_count_recipe_v3,
};
use fre_kernel_ir::{
    AggregateBuildError, BuildError, Count, ValidateError, ValidateLimits,
    build_exact_aggregate,
};
use sha2::{Digest, Sha256};

use crate::{
    Architecture, CallAbi, CpuFeature, FeatureSet, ObjectError, OperatingSystem,
    PreparedAggregateStrategy, Target,
};

pub const DIRECT_EXACT_SINGLETON_COUNT_AOT_SCHEMA_VERSION: u16 = 5;

pub(crate) const DIRECT_EXACT_SINGLETON_COUNT_CORE_ALIGNMENT_BYTES: usize =
    AOT_COUNT_CODE_ALIGNMENT_V3;

/// Largest source length routed to the authenticated incumbent body for the
/// short-input periodic schedule. The focused core starts at one complete
/// 8-KiB source span, so one shifted AArch64 immediate performs the admission
/// without materializing a constant register.
pub const DIRECT_EXACT_SINGLETON_COUNT_SHORT_FALLBACK_MAX_BYTES: u32 = 8191;

/// Derive the complete source-only admission policy from an independently
/// inspected optimizer strategy and the authenticated finite-literal width.
pub(crate) const fn direct_exact_singleton_count_short_fallback_max_bytes(
    strategy: CountV3Strategy,
    literal_bytes: usize,
) -> Option<u32> {
    if matches!(strategy, CountV3Strategy::PeriodicRun) && matches!(literal_bytes, 2 | 4) {
        Some(DIRECT_EXACT_SINGLETON_COUNT_SHORT_FALLBACK_MAX_BYTES)
    } else {
        None
    }
}

/// Count successor rule authenticated by both exact finite-language facts and
/// the focused Count-v3 recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectExactSingletonCountSuccessorMode {
    NonOverlapping,
}

/// Source-independent reason the direct core beat the fully materialized
/// incumbent aggregate route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectExactSingletonCountSelectionBasis {
    /// Both scan once, while the focused core removes the incumbent's
    /// per-match search call and internal span publication.
    StructuralSingleScanDominance,
    /// The direct arm has the same structural dominance, while a source-only
    /// cold-long gate preserves the incumbent short-path instruction count and
    /// layout, replacing only its signed-length check and branch in place.
    StructuralSingleScanDominanceWithShortIncumbent,
}

/// Comparable operation shape. Smaller is better in every runtime field;
/// code bytes break an otherwise exact tie only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectExactSingletonCountCostShape {
    pub scan_passes: u8,
    pub native_calls_per_match: u8,
    pub internal_span_publications_per_match: u8,
    pub unresolved_runtime_helpers: u8,
    /// Count-operation code only; the ordinary search entry shared by both
    /// portfolio choices is excluded.
    pub code_bytes: u32,
}

impl DirectExactSingletonCountCostShape {
    pub(crate) const fn runtime_components(self) -> [u8; 4] {
        [
            self.unresolved_runtime_helpers,
            self.scan_passes,
            self.native_calls_per_match,
            self.internal_span_publications_per_match,
        ]
    }
}

/// Authenticated selected-route receipt. No literal bytes are retained or
/// exposed here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectExactSingletonCountAotReport {
    pub schema_version: u16,
    pub literal_bytes: u8,
    pub successor_mode: DirectExactSingletonCountSuccessorMode,
    pub selection_basis: DirectExactSingletonCountSelectionBasis,
    pub incumbent_strategy: PreparedAggregateStrategy,
    pub incumbent_cost: DirectExactSingletonCountCostShape,
    /// Cost of the selected direct arm. When `short_fallback_max_bytes` is
    /// present, shorter sources use the exact `incumbent_cost` arm instead.
    pub selected_cost: DirectExactSingletonCountCostShape,
    pub authenticated_wrapper_body_offset: usize,
    /// Inclusive source-length ceiling for the incumbent short arm after its
    /// signed-length pair is replaced by the in-place cold-long gate. `None`
    /// means the selected core owns every authenticated source length.
    pub short_fallback_max_bytes: Option<u32>,
    /// Text extent of a relocated incumbent body used by an older gate layout.
    /// Schema V5's cold-long gate leaves both fields absent because the
    /// incumbent body remains at its original offsets; only the signed-length
    /// pair is rewritten in place.
    pub copied_incumbent_body_offset: Option<usize>,
    pub copied_incumbent_body_bytes: Option<usize>,
    /// Appended cold path that rechecks invalid-length precedence, validates
    /// the result pointer, reauthenticates the handle, and enters the core.
    /// The established short path never executes this extent. Its byte count
    /// includes any trailing NOPs needed to align the Count-v3 core.
    pub cold_long_offset: Option<usize>,
    pub cold_long_bytes: Option<usize>,
    /// Required start alignment inherited from the independently audited
    /// Count-v3 producer layout.
    pub core_alignment_bytes: usize,
    pub core_offset: usize,
    pub core_bytes: usize,
    pub core_sha256: [u8; 32],
    /// Identity of the independently compiled inert Count-v3 candidate.
    pub compile_identity: [u8; 32],
    /// Identity of that candidate's standalone implementation container, not
    /// the enclosing merged regex object.
    pub object_identity: [u8; 32],
    pub recipe_identity: [u8; 32],
    /// Identity of the selected merged wrapper/core transaction.
    pub module_identity: [u8; 32],
}

pub(crate) struct PreparedDirectExactSingletonCount {
    pub(crate) code: Box<[u8]>,
    pub(crate) mapped_metadata: AotCountMappedMetadataV3,
    pub(crate) canonical_recipe: [u8; COUNT_V3_RECIPE_CANONICAL_BYTES],
    pub(crate) native_limits: CountEmitLimitsV3,
    pub(crate) kernel_limits: ValidateLimits,
    pub(crate) target: Target,
    pub(crate) artifact_identity: [u8; 32],
    pub(crate) literal_sha256: [u8; 32],
    pub(crate) compile_identity: [u8; 32],
    pub(crate) object_identity: [u8; 32],
    pub(crate) recipe_identity: [u8; 32],
    pub(crate) core_sha256: [u8; 32],
}

impl PreparedDirectExactSingletonCount {
    /// Rebuild the exact KIR and independently audit the core after it has
    /// been placed at its final module offset. Count-v3 is PIC, but its
    /// producer layout still requires an aligned code start; the exact bounded
    /// slice is otherwise the complete offset-independent audit surface.
    pub(crate) fn authenticate_embedded(
        &self,
        literal: &[u8],
        embedded_offset: usize,
        embedded: &[u8],
    ) -> Result<(), ObjectError> {
        if !embedded_offset.is_multiple_of(DIRECT_EXACT_SINGLETON_COUNT_CORE_ALIGNMENT_BYTES)
            || <[u8; 32]>::from(Sha256::digest(literal)) != self.literal_sha256
            || embedded != self.code.as_ref()
            || <[u8; 32]>::from(Sha256::digest(embedded)) != self.core_sha256
        {
            return Err(ObjectError::InvalidModule(
                "embedded direct Count-v3 core identity or alignment disagrees",
            ));
        }
        let program = build_exact_aggregate::<Count>(literal, self.kernel_limits)
            .map_err(classify_regeneration_error)?;
        audit_count_mapped_code_v3(
            &program,
            &self.canonical_recipe,
            embedded,
            self.mapped_metadata,
            self.native_limits,
        )
        .map_err(classify_audit_error)?;
        Ok(())
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "boxing the sole successful arm would add a second fallible allocation after candidate authentication"
)]
pub(crate) enum DirectExactSingletonCountPreparation {
    Candidate(PreparedDirectExactSingletonCount),
    Declined,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectExactSingletonCountTestPreparation {
    Normal,
    Decline,
    AllocationFailure,
    UnsupportedBackendFailure,
}

#[cfg(test)]
std::thread_local! {
    static TEST_PREPARATION: std::cell::Cell<DirectExactSingletonCountTestPreparation> =
        const { std::cell::Cell::new(DirectExactSingletonCountTestPreparation::Normal) };
}

#[cfg(test)]
pub(crate) struct DirectExactSingletonCountTestPreparationGuard {
    previous: DirectExactSingletonCountTestPreparation,
}

#[cfg(test)]
impl Drop for DirectExactSingletonCountTestPreparationGuard {
    fn drop(&mut self) {
        TEST_PREPARATION.with(|preparation| preparation.set(self.previous));
    }
}

#[cfg(test)]
pub(crate) fn test_direct_exact_singleton_count_preparation(
    selected: DirectExactSingletonCountTestPreparation,
) -> DirectExactSingletonCountTestPreparationGuard {
    let previous = TEST_PREPARATION.with(|preparation| preparation.replace(selected));
    DirectExactSingletonCountTestPreparationGuard { previous }
}

pub(crate) fn prepare_direct_exact_singleton_count(
    literal: &[u8],
    artifact_identity: [u8; 32],
    target: Target,
    max_object_bytes: usize,
) -> Result<DirectExactSingletonCountPreparation, ObjectError> {
    if artifact_identity == [0; 32]
        || !(1..=fre_aot_optimizer::COUNT_V3_MAX_LITERAL_BYTES).contains(&literal.len())
        || target.architecture != Architecture::Aarch64
        || target.abi != CallAbi::Aapcs64
        || !target
            .features
            .contains(FeatureSet::of(CpuFeature::Aarch64Asimd))
    {
        return Ok(DirectExactSingletonCountPreparation::Declined);
    }
    #[cfg(test)]
    match TEST_PREPARATION.with(std::cell::Cell::get) {
        DirectExactSingletonCountTestPreparation::Normal => {}
        DirectExactSingletonCountTestPreparation::Decline => {
            return Ok(DirectExactSingletonCountPreparation::Declined);
        }
        DirectExactSingletonCountTestPreparation::AllocationFailure => {
            return Err(ObjectError::Allocation(
                "injected direct Count-v3 candidate",
            ));
        }
        DirectExactSingletonCountTestPreparation::UnsupportedBackendFailure => {
            return classify_compile_error(CountCompileErrorV3::Image(
                CountAotError::Unsupported {
                    reason: CountAotUnsupported::BackendTuple,
                },
            ));
        }
    }
    let object_format = match target.operating_system {
        OperatingSystem::Linux => CountObjectFormatV3::Elf64Aarch64,
        OperatingSystem::Macos => CountObjectFormatV3::MachOArm64,
    };
    let cap = u64::try_from(max_object_bytes).unwrap_or(u64::MAX);
    let mut limits = CountCompileLimitsV3::default();
    limits.native.max_code_bytes = limits.native.max_code_bytes.min(cap);
    limits.native.max_persistent_bytes = limits.native.max_persistent_bytes.min(cap);
    limits.object = CountObjectLimitsV3 {
        max_payload_bytes: CountObjectLimitsV3::default().max_payload_bytes.min(cap),
        max_object_bytes: CountObjectLimitsV3::default().max_object_bytes.min(cap),
    };
    let semantic_candidate = semantic_candidate(artifact_identity, target, literal, &limits);
    let compiled = match compile_count_v3(
        CountCompileRequestV3 {
            literal,
            semantic_candidate,
            target: CountCompileTargetV3 {
                object_format,
                tuning_class: CountV3TuningClass::GenericAarch64,
                required_isa: CountV3RequiredIsa::Aarch64Neon128,
            },
        },
        limits,
    ) {
        Ok(compiled) => compiled,
        Err(error) => return classify_compile_error(error),
    };
    let inspection = compiled
        .unsigned_prelink_receipt()
        .validate_candidate(compiled.implementation_object().as_bytes(), limits.object)
        .map_err(|_| ObjectError::InvalidModule("Count-v3 prelink authentication failed"))?;
    let mapped_metadata = inspection
        .mapped_metadata()
        .map_err(|_| ObjectError::InvalidModule("Count-v3 mapped metadata was invalid"))?;
    let canonical_recipe = encode_count_recipe_v3(compiled.recipe());
    let program = build_exact_aggregate::<Count>(literal, limits.kernel_ir)
        .map_err(classify_regeneration_error)?;
    audit_count_mapped_code_v3(
        &program,
        &canonical_recipe,
        inspection.code(),
        mapped_metadata,
        limits.native,
    )
    .map_err(classify_audit_error)?;

    let mut code = Vec::new();
    code.try_reserve_exact(inspection.code().len())
        .map_err(|_| ObjectError::Allocation("direct Count-v3 core"))?;
    code.extend_from_slice(inspection.code());
    let core_sha256 = Sha256::digest(&code).into();
    Ok(DirectExactSingletonCountPreparation::Candidate(
        PreparedDirectExactSingletonCount {
            code: code.into_boxed_slice(),
            mapped_metadata,
            canonical_recipe,
            native_limits: limits.native,
            kernel_limits: limits.kernel_ir,
            target,
            artifact_identity,
            literal_sha256: Sha256::digest(literal).into(),
            compile_identity: *inspection.compile_identity(),
            object_identity: *inspection.object_identity(),
            recipe_identity: *compiled.recipe().identity().as_bytes(),
            core_sha256,
        },
    ))
}

fn semantic_candidate(
    artifact_identity: [u8; 32],
    target: Target,
    literal: &[u8],
    limits: &CountCompileLimitsV3,
) -> CountSemanticCandidateV3 {
    let identity = |tag: u8| {
        let mut digest = Sha256::new();
        digest.update(b"fre-aot-regex/direct-exact-singleton-count/v1\0");
        digest.update([tag]);
        digest.update(artifact_identity);
        digest.update([
            match target.operating_system {
                OperatingSystem::Linux => 1,
                OperatingSystem::Macos => 2,
            },
            match target.abi {
                CallAbi::SystemV => 1,
                CallAbi::Aapcs64 => 2,
            },
        ]);
        digest.update(target.features.bits().to_le_bytes());
        digest.update(u64::try_from(literal.len()).unwrap_or(u64::MAX).to_le_bytes());
        digest.update(Sha256::digest(literal));
        digest.update(limits.native.max_code_bytes.to_le_bytes());
        digest.update(limits.object.max_object_bytes.to_le_bytes());
        let mut identity: [u8; 32] = digest.finalize().into();
        if identity == [0; 32] {
            identity[31] = tag;
        }
        identity
    };
    CountSemanticCandidateV3 {
        manifest_identity: identity(1),
        policy_limits_identity: identity(2),
        semantic_binding_identity: identity(3),
        planning_receipt_identity: identity(4),
        object_binding_identity: identity(5),
        claimed_receipt_identity: identity(6),
        claimed_resource_receipt_identity: identity(7),
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err transfers ownership of the compiler error into this exhaustive classifier"
)]
fn classify_compile_error(
    error: CountCompileErrorV3,
) -> Result<DirectExactSingletonCountPreparation, ObjectError> {
    match error {
        CountCompileErrorV3::ResourceLimit { .. }
        | CountCompileErrorV3::Kernel(
            AggregateBuildError::LiteralLengthLimit { .. }
            | AggregateBuildError::Search(BuildError::Validate(
                ValidateError::ResourceLimit { .. },
            )),
        )
        | CountCompileErrorV3::Optimizer(
            CountV3OptimizeError::LiteralBytes { .. }
            | CountV3OptimizeError::CandidateColumns { .. }
            | CountV3OptimizeError::PortfolioRecipes { .. }
            | CountV3OptimizeError::AnalysisWork { .. }
            | CountV3OptimizeError::ScratchBytes { .. }
            | CountV3OptimizeError::AllocationRequests { .. }
            | CountV3OptimizeError::RetainedBytes { .. }
            | CountV3OptimizeError::IdentityBytesHashed { .. },
        )
        | CountCompileErrorV3::Image(CountAotError::ResourceLimit { .. }) => {
            Ok(DirectExactSingletonCountPreparation::Declined)
        }
        CountCompileErrorV3::AllocationFailed
        | CountCompileErrorV3::Kernel(AggregateBuildError::Search(
            BuildError::AllocationFailed { .. }
            | BuildError::Validate(ValidateError::AllocationFailed { .. }),
        ))
        | CountCompileErrorV3::Optimizer(
            CountV3OptimizeError::PortfolioAllocationFailed { .. },
        )
        | CountCompileErrorV3::Image(CountAotError::AllocationFailed { .. }) => {
            Err(ObjectError::Allocation("direct Count-v3 candidate"))
        }
        CountCompileErrorV3::ArithmeticOverflow { .. }
        | CountCompileErrorV3::Kernel(AggregateBuildError::Search(
            BuildError::Validate(ValidateError::ArithmeticOverflow { .. }),
        ))
        | CountCompileErrorV3::Optimizer(CountV3OptimizeError::ArithmeticOverflow { .. })
        | CountCompileErrorV3::Image(CountAotError::ArithmeticOverflow { .. }) => Err(
            ObjectError::ArithmeticOverflow("direct Count-v3 candidate"),
        ),
        CountCompileErrorV3::Image(CountAotError::Unsupported { reason }) => {
            Err(classify_unsupported_backend(reason))
        }
        _ => Err(ObjectError::InvalidModule(
            "direct Count-v3 candidate authentication failed",
        )),
    }
}

fn classify_unsupported_backend(reason: CountAotUnsupported) -> ObjectError {
    let at = match reason {
        CountAotUnsupported::Output => "direct Count-v3 backend rejected Count output",
        CountAotUnsupported::LiteralWidth => {
            "direct Count-v3 backend rejected authenticated literal width"
        }
        CountAotUnsupported::KernelShape => {
            "direct Count-v3 backend rejected authenticated kernel shape"
        }
        CountAotUnsupported::BackendTuple => {
            "direct Count-v3 backend rejected authenticated target tuple"
        }
        CountAotUnsupported::OptimizerRecipe => {
            "direct Count-v3 backend rejected authenticated optimizer recipe"
        }
        CountAotUnsupported::RecipeSchedule => {
            "direct Count-v3 backend rejected authenticated recipe schedule"
        }
        CountAotUnsupported::TargetFeature => {
            "direct Count-v3 backend rejected authenticated target features"
        }
        _ => "direct Count-v3 backend reported an unsupported authenticated contract",
    };
    ObjectError::InvalidModule(at)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err transfers ownership of the builder error into this exhaustive classifier"
)]
fn classify_regeneration_error(error: AggregateBuildError) -> ObjectError {
    match error {
        AggregateBuildError::Search(
            BuildError::AllocationFailed { .. }
            | BuildError::Validate(ValidateError::AllocationFailed { .. }),
        ) => ObjectError::Allocation("embedded direct Count-v3 KIR audit"),
        AggregateBuildError::Search(BuildError::Validate(
            ValidateError::ArithmeticOverflow { .. },
        )) => ObjectError::ArithmeticOverflow("embedded direct Count-v3 KIR audit"),
        _ => ObjectError::InvalidModule("embedded direct Count-v3 KIR audit failed"),
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err transfers ownership of the audit error into this exhaustive classifier"
)]
fn classify_audit_error(error: CountAotError) -> ObjectError {
    match error {
        CountAotError::AllocationFailed { .. } => {
            ObjectError::Allocation("embedded direct Count-v3 mapped-code audit")
        }
        CountAotError::ArithmeticOverflow { .. } => {
            ObjectError::ArithmeticOverflow("embedded direct Count-v3 mapped-code audit")
        }
        _ => ObjectError::InvalidModule("embedded direct Count-v3 mapped-code audit failed"),
    }
}
