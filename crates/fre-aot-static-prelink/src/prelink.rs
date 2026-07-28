use core::mem::size_of;

use fre_aot_aarch64::AotCountBackendSupportV2;
use fre_aot_compiler::{
    ClaimedStaticCountExpectationV2, CompileReceiptIdentity, CompileReceiptV2, CompiledObjectV2,
    ResourceReceiptIdentity, STATIC_COUNT_EXPECTATION_BYTES_V2,
    STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2,
    STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_TRAVERSED_V2,
    STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2,
    STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2,
    STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V2, StaticCountExpectationIdentity,
    StaticCountExpectationV2, inspect_static_count_expectation_v2,
};
use fre_aot_count_contract::{
    ClaimedCountMetadataV2 as NeutralMetadataClaimV2,
    ClaimedStaticCountExpectationV2 as NeutralExpectationClaimV2,
    inspect_count_metadata_v2 as inspect_neutral_metadata_v2,
    inspect_static_count_expectation_v2 as inspect_neutral_expectation_v2,
};
use fre_aot_macho::{AbiKind, CountCompileIdentityV2, CountObjectIdentityV2, MetadataV2};
use fre_aot_macho::{CountObjectBuildReportV2, METADATA_BYTES_V2};

use crate::{PrelinkContractFieldV2, PrelinkErrorV2, error::require};

/// Explicit, allocation-free accounting for the compatibility prelink inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrelinkInspectionAccountingV2 {
    object_bytes: usize,
    exact_object_equality_bytes_traversed: u64,
    receipt_authentication_work_upper_bound: u64,
    receipt_authentication_scratch_bytes_upper_bound: u64,
    object_inspection_work_upper_bound: u64,
    object_inspection_scratch_bytes_upper_bound: u64,
    expectation_bytes: usize,
    expectation_inspection_work_upper_bound: u64,
    expectation_inspection_scratch_bytes_upper_bound: u64,
    post_inspection_comparison_work_upper_bound: u64,
    total_work_upper_bound: u64,
    scratch_bytes_upper_bound: u64,
    retained_bytes: usize,
    allocations: u8,
}

impl PrelinkInspectionAccountingV2 {
    fn new(
        object_bytes: usize,
        receipt_authentication_work_upper_bound: u64,
        receipt_authentication_scratch_bytes_upper_bound: u64,
        object_inspection_work_upper_bound: u64,
        object_inspection_scratch_bytes_upper_bound: u64,
    ) -> Result<Self, PrelinkErrorV2> {
        let exact_object_equality_bytes_traversed = u64::try_from(object_bytes)
            .map_err(|_| PrelinkErrorV2::InspectionAccountingOverflow)?;
        let post_inspection_comparison_work_upper_bound =
            post_inspection_comparison_work_upper_bound_v2()?;
        let total_work_upper_bound = receipt_authentication_work_upper_bound
            .checked_add(object_inspection_work_upper_bound)
            .and_then(|work| work.checked_add(exact_object_equality_bytes_traversed))
            .and_then(|work| {
                work.checked_add(STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2)
            })
            .and_then(|work| work.checked_add(post_inspection_comparison_work_upper_bound))
            .ok_or(PrelinkErrorV2::InspectionAccountingOverflow)?;
        let comparison_scratch = u64::try_from(
            size_of::<ClaimedStaticCountExpectationV2>()
                .checked_add(size_of::<StaticCountExpectationV2>())
                .ok_or(PrelinkErrorV2::InspectionAccountingOverflow)?,
        )
        .map_err(|_| PrelinkErrorV2::InspectionAccountingOverflow)?;
        Ok(Self {
            object_bytes,
            exact_object_equality_bytes_traversed,
            receipt_authentication_work_upper_bound,
            receipt_authentication_scratch_bytes_upper_bound,
            object_inspection_work_upper_bound,
            object_inspection_scratch_bytes_upper_bound,
            expectation_bytes: STATIC_COUNT_EXPECTATION_BYTES_V2,
            // The compiler publishes a complete conservative envelope for the
            // same fixed parse/hash/cross-field path. C1 reuses that bound
            // instead of inventing an unbound inspector cost.
            expectation_inspection_work_upper_bound:
                STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2,
            expectation_inspection_scratch_bytes_upper_bound:
                STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2,
            post_inspection_comparison_work_upper_bound,
            total_work_upper_bound,
            scratch_bytes_upper_bound: object_inspection_scratch_bytes_upper_bound
                .max(receipt_authentication_scratch_bytes_upper_bound)
                .max(STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2)
                .max(comparison_scratch),
            retained_bytes: size_of::<PrelinkValidationV2>(),
            allocations: 0,
        })
    }

    #[must_use]
    pub const fn object_bytes(&self) -> usize {
        self.object_bytes
    }

    #[must_use]
    pub const fn exact_object_equality_bytes_traversed(&self) -> u64 {
        self.exact_object_equality_bytes_traversed
    }

    #[must_use]
    pub const fn receipt_authentication_work_upper_bound(&self) -> u64 {
        self.receipt_authentication_work_upper_bound
    }

    #[must_use]
    pub const fn receipt_authentication_scratch_bytes_upper_bound(&self) -> u64 {
        self.receipt_authentication_scratch_bytes_upper_bound
    }

    #[must_use]
    pub const fn object_inspection_work_upper_bound(&self) -> u64 {
        self.object_inspection_work_upper_bound
    }

    #[must_use]
    pub const fn object_inspection_scratch_bytes_upper_bound(&self) -> u64 {
        self.object_inspection_scratch_bytes_upper_bound
    }

    #[must_use]
    pub const fn expectation_bytes(&self) -> usize {
        self.expectation_bytes
    }

    #[must_use]
    pub const fn expectation_inspection_work_upper_bound(&self) -> u64 {
        self.expectation_inspection_work_upper_bound
    }

    #[must_use]
    pub const fn expectation_inspection_scratch_bytes_upper_bound(&self) -> u64 {
        self.expectation_inspection_scratch_bytes_upper_bound
    }

    #[must_use]
    pub const fn post_inspection_comparison_work_upper_bound(&self) -> u64 {
        self.post_inspection_comparison_work_upper_bound
    }

    #[must_use]
    pub const fn total_work_upper_bound(&self) -> u64 {
        self.total_work_upper_bound
    }

    #[must_use]
    pub const fn scratch_bytes_upper_bound(&self) -> u64 {
        self.scratch_bytes_upper_bound
    }

    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    #[must_use]
    pub const fn allocations(&self) -> u8 {
        self.allocations
    }
}

fn post_inspection_comparison_work_upper_bound_v2() -> Result<u64, PrelinkErrorV2> {
    // Successful prelink performs: two metadata comparisons, object-report
    // comparison, two Count identity comparisons, inspected/trusted claim
    // comparison, expectation build-report checks, and every typed
    // expectation/receipt comparison. Charging the complete inline widths is
    // a deterministic upper bound even when Rust's Eq short-circuits.
    let bytes = METADATA_BYTES_V2
        .checked_mul(2)
        .and_then(|work| work.checked_add(size_of::<CountObjectBuildReportV2>()))
        .and_then(|work| work.checked_add(2 * 32))
        .and_then(|work| work.checked_add(size_of::<ClaimedStaticCountExpectationV2>()))
        .and_then(|work| work.checked_add(size_of::<StaticCountExpectationV2>()))
        .and_then(|work| work.checked_add(size_of::<CompileReceiptV2>()))
        .and_then(|work| {
            work.checked_add(size_of::<
                fre_aot_compiler::StaticCountExpectationBuildReportV2,
            >())
        })
        .ok_or(PrelinkErrorV2::InspectionAccountingOverflow)?;
    u64::try_from(bytes).map_err(|_| PrelinkErrorV2::InspectionAccountingOverflow)
}

/// Successful exact validation of candidate Count-v2 `MH_OBJECT` bytes.
///
/// Trusted Count identity newtypes come only from `compiled`; arbitrary object
/// and expectation bytes remain claims until those types authenticate them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrelinkValidationV2 {
    object_bytes: usize,
    support: AotCountBackendSupportV2,
    metadata: MetadataV2,
    compile_identity: CountCompileIdentityV2,
    object_identity: CountObjectIdentityV2,
    expectation_identity: StaticCountExpectationIdentity,
    receipt_identity: CompileReceiptIdentity,
    resource_receipt_identity: ResourceReceiptIdentity,
    accounting: PrelinkInspectionAccountingV2,
}

impl PrelinkValidationV2 {
    #[must_use]
    pub const fn object_bytes(&self) -> usize {
        self.object_bytes
    }

    #[must_use]
    pub const fn support(&self) -> AotCountBackendSupportV2 {
        self.support
    }

    #[must_use]
    pub const fn metadata(&self) -> MetadataV2 {
        self.metadata
    }

    #[must_use]
    pub const fn compile_identity(&self) -> CountCompileIdentityV2 {
        self.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> CountObjectIdentityV2 {
        self.object_identity
    }

    #[must_use]
    pub const fn expectation_identity(&self) -> StaticCountExpectationIdentity {
        self.expectation_identity
    }

    #[must_use]
    pub const fn receipt_identity(&self) -> CompileReceiptIdentity {
        self.receipt_identity
    }

    #[must_use]
    pub const fn resource_receipt_identity(&self) -> ResourceReceiptIdentity {
        self.resource_receipt_identity
    }

    #[must_use]
    pub const fn accounting(&self) -> PrelinkInspectionAccountingV2 {
        self.accounting
    }
}

/// Strictly validate the exact external object bytes selected for the linker.
///
/// The compiler's trusted receipt supplies every authority-bearing identity.
/// The candidate bytes and embedded expectation are independently inspected
/// and compared byte-for-byte and field-for-field.
#[allow(
    clippy::too_many_lines,
    reason = "one ordered prelink transaction keeps every typed authority comparison and its accounting adjacent"
)]
pub fn validate_prelink_count_v2(
    compiled: &CompiledObjectV2,
    candidate_object_bytes: &[u8],
) -> Result<PrelinkValidationV2, PrelinkErrorV2> {
    let object = compiled.object();
    let receipt = compiled.receipt();
    let expectation = compiled.static_count_expectation();

    let candidate_inspection = receipt.validate_object_bytes(candidate_object_bytes)?;
    require(
        candidate_object_bytes == object.as_bytes(),
        PrelinkContractFieldV2::CompiledObjectBytes,
    )?;
    require(
        candidate_inspection.metadata() == object.metadata()
            && receipt.metadata() == object.metadata(),
        PrelinkContractFieldV2::Metadata,
    )?;
    require(
        receipt.accounting().object_report() == object.report(),
        PrelinkContractFieldV2::ObjectAccounting,
    )?;
    require(
        receipt.compile_identity() == object.compile_identity(),
        PrelinkContractFieldV2::CompileIdentity,
    )?;
    require(
        receipt.object_identity() == object.object_identity(),
        PrelinkContractFieldV2::ObjectIdentity,
    )?;

    let claim = inspect_static_count_expectation_v2(expectation.as_bytes())?;
    require(
        claim == expectation.claim(),
        PrelinkContractFieldV2::ExpectationIdentity,
    )?;
    let neutral_claim = inspect_neutral_expectation_v2(expectation.as_bytes())?;
    let neutral_metadata_bytes = neutral_metadata_wire_v2(expectation.as_bytes())?;
    validate_neutral_expectation_claim_v2(&claim, &neutral_claim, neutral_metadata_bytes)?;
    let neutral_metadata = inspect_neutral_metadata_v2(neutral_metadata_bytes)?;
    require(
        neutral_metadata == neutral_claim.metadata(),
        PrelinkContractFieldV2::NeutralWireContract,
    )?;
    validate_neutral_metadata_claim_v2(claim.metadata(), neutral_metadata)?;
    let expectation_report = expectation.build_report();
    require(
        expectation_report.canonical_bytes_hashed()
            == STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2
            && expectation_report.canonical_bytes_traversed()
                == STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_TRAVERSED_V2
            && expectation_report.canonical_count_passes() == 1
            && expectation_report.canonical_hash_passes() == 1
            && expectation_report.work_upper_bound()
                == STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2
            && expectation_report.scratch_bytes_upper_bound()
                == STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2
            && expectation_report.retained_bytes() == STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V2
            && expectation_report.allocations() == 0,
        PrelinkContractFieldV2::ExpectationAccounting,
    )?;
    require(
        expectation.support() == receipt.support(),
        PrelinkContractFieldV2::Support,
    )?;
    require(
        expectation.manifest_identity() == receipt.manifest_identity(),
        PrelinkContractFieldV2::ManifestIdentity,
    )?;
    require(
        expectation.policy_limits_identity() == receipt.manifest().policy_limits_identity(),
        PrelinkContractFieldV2::PolicyLimitsIdentity,
    )?;
    require(
        expectation.semantic_binding_identity() == receipt.semantic_binding_identity(),
        PrelinkContractFieldV2::SemanticBindingIdentity,
    )?;
    require(
        expectation.planning_receipt_identity() == receipt.planning_receipt_identity(),
        PrelinkContractFieldV2::PlanningReceiptIdentity,
    )?;
    require(
        expectation.live_literal_identity() == receipt.live_literal_identity(),
        PrelinkContractFieldV2::LiveLiteralIdentity,
    )?;
    require(
        expectation.live_literal_bytes() == receipt.live_literal_bytes(),
        PrelinkContractFieldV2::LiveLiteralBytes,
    )?;
    require(
        expectation.program_identity() == receipt.program_identity(),
        PrelinkContractFieldV2::ProgramIdentity,
    )?;
    require(
        expectation.image_identity() == receipt.image_identity(),
        PrelinkContractFieldV2::ImageIdentity,
    )?;
    require(
        expectation.object_binding_identity() == receipt.object_binding_identity(),
        PrelinkContractFieldV2::ObjectBindingIdentity,
    )?;
    require(
        expectation.compile_identity() == receipt.compile_identity(),
        PrelinkContractFieldV2::CompileIdentity,
    )?;
    require(
        expectation.object_identity() == receipt.object_identity(),
        PrelinkContractFieldV2::ObjectIdentity,
    )?;
    require(
        expectation.receipt_identity() == receipt.receipt_identity(),
        PrelinkContractFieldV2::ReceiptIdentity,
    )?;
    require(
        expectation.resource_receipt_identity() == receipt.resource_receipt_identity(),
        PrelinkContractFieldV2::ResourceReceiptIdentity,
    )?;
    require(
        expectation.metadata() == receipt.metadata(),
        PrelinkContractFieldV2::Metadata,
    )?;

    let accounting = PrelinkInspectionAccountingV2::new(
        candidate_inspection.object_bytes(),
        receipt.accounting().compiler_identity_work(),
        receipt
            .accounting()
            .compiler_identity()
            .identity_scratch_bytes_upper_bound(),
        candidate_inspection.work_upper_bound(),
        candidate_inspection.scratch_bytes_upper_bound(),
    )?;
    Ok(PrelinkValidationV2 {
        object_bytes: candidate_inspection.object_bytes(),
        support: receipt.support(),
        metadata: candidate_inspection.metadata(),
        compile_identity: receipt.compile_identity(),
        object_identity: receipt.object_identity(),
        expectation_identity: expectation.expectation_identity(),
        receipt_identity: receipt.receipt_identity(),
        resource_receipt_identity: receipt.resource_receipt_identity(),
        accounting,
    })
}

fn validate_neutral_expectation_claim_v2(
    compiler: &ClaimedStaticCountExpectationV2,
    neutral: &NeutralExpectationClaimV2,
    neutral_metadata_bytes: &[u8; METADATA_BYTES_V2],
) -> Result<(), PrelinkErrorV2> {
    require(
        compiler.schema_version() == neutral.schema_version()
            && compiler.compiler_version() == neutral.compiler_version()
            && compiler.image_schema_version() == neutral.image_schema_version()
            && compiler.manifest_identity() == neutral.manifest_identity()
            && compiler.policy_limits_identity() == neutral.policy_limits_identity()
            && compiler.semantic_binding_identity() == neutral.semantic_binding_identity()
            && compiler.planning_receipt_identity() == neutral.planning_receipt_identity()
            && compiler.live_literal_identity() == neutral.live_literal_identity()
            && compiler.live_literal_bytes() == neutral.live_literal_bytes()
            && compiler.program_identity() == neutral.program_identity()
            && compiler.image_identity() == neutral.image_identity()
            && compiler.object_binding_identity() == neutral.object_binding_identity()
            && compiler.compile_identity() == neutral.compile_identity()
            && compiler.object_identity() == neutral.object_identity()
            && compiler.receipt_identity() == neutral.receipt_identity()
            && compiler.resource_receipt_identity() == neutral.resource_receipt_identity()
            && compiler.metadata_bytes_v2() == neutral_metadata_bytes
            && compiler.expectation_identity() == neutral.expectation_identity(),
        PrelinkContractFieldV2::NeutralWireContract,
    )
}

fn neutral_metadata_wire_v2(
    expectation_bytes: &[u8],
) -> Result<&[u8; METADATA_BYTES_V2], PrelinkErrorV2> {
    expectation_bytes
        .get(
            fre_aot_count_contract::STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2
                ..fre_aot_count_contract::STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2,
        )
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(PrelinkErrorV2::ContractMismatch {
            field: PrelinkContractFieldV2::NeutralWireContract,
        })
}

fn validate_neutral_metadata_claim_v2(
    compiler: MetadataV2,
    neutral: NeutralMetadataClaimV2,
) -> Result<(), PrelinkErrorV2> {
    require(
        compiler.format_version() == neutral.format_version()
            && compiler.record_bytes() == neutral.record_bytes()
            && compiler.backend_version() == neutral.backend_version()
            && compiler.algorithm_version() == neutral.algorithm_version()
            && compiler.kir_semantics_version() == neutral.kir_semantics_version()
            && compiler.kir_abi_version() == neutral.kir_abi_version()
            && compiler.abi_schema() == neutral.abi_schema()
            && compiler.max_literal_bytes() == neutral.max_literal_bytes()
            && compiler.abi_kind() == AbiKind::Aggregate
            && neutral.abi_kind() == 2
            && compiler.output_kind() == neutral.output_kind()
            && compiler.architecture() == neutral.architecture()
            && compiler.little_endian() == neutral.little_endian()
            && compiler.pointer_width() == neutral.pointer_width()
            && compiler.target_abi() == neutral.target_abi()
            && compiler.platform() == neutral.platform()
            && compiler.status_bits() == neutral.status_bits()
            && compiler.actual_features() == neutral.actual_features()
            && compiler.allowed_features() == neutral.allowed_features()
            && compiler.payload_bytes() == neutral.payload_bytes()
            && compiler.entry_offset() == neutral.entry_offset()
            && compiler.code_bytes() == neutral.code_bytes()
            && compiler.rodata_offset() == neutral.rodata_offset()
            && compiler.rodata_bytes() == neutral.rodata_bytes()
            && compiler.literal_bytes() == neutral.literal_bytes()
            && compiler.source_identity() == neutral.source_identity()
            && compiler.artifact_identity() == neutral.artifact_identity()
            && compiler.claimed_binding_identity().as_bytes() == neutral.binding_identity()
            && compiler.payload_sha256() == neutral.payload_sha256()
            && compiler.claimed_compile_identity().as_bytes() == neutral.compile_identity(),
        PrelinkContractFieldV2::NeutralWireContract,
    )
}

#[cfg(test)]
mod tests {
    use fre::RustProfile;
    use fre_aot_compiler::{
        AOT_COMPILER_VERSION_V2, AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2,
        MacosAarch64CountManifestV2, STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2,
        STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2, plan_and_compile_macos_aarch64_count_v2,
    };
    use fre_aot_macho::{
        CALL_ABI_SCHEMA_V2, COUNT_ENTRY_SYMBOL_PREFIX_V2, COUNT_EXPORTED_SYMBOL_N_TYPE_V2,
        COUNT_METADATA_SYMBOL_PREFIX_V2, COUNT_PAYLOAD_SYMBOL_PREFIX_V2, ENTRY_OFFSET_V2,
        EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2, EXPORTED_SYMBOL_SCHEMA_VERSION_V2,
        METADATA_VERSION_V2,
    };

    use super::*;

    fn compile(pattern: &str) -> CompiledObjectV2 {
        let mut profile = RustProfile::default();
        profile.options.unicode = false;
        plan_and_compile_macos_aarch64_count_v2(
            MacosAarch64CountManifestV2::default(),
            pattern.as_bytes().to_vec(),
            profile,
        )
        .expect("Count-v2 fixture")
    }

    #[test]
    fn exact_candidate_returns_trusted_typed_identities_and_accounting() {
        let compiled = compile("needle");
        let validation = validate_prelink_count_v2(&compiled, compiled.object().as_bytes())
            .expect("exact candidate");
        assert_eq!(
            validation.compile_identity(),
            compiled.receipt().compile_identity()
        );
        assert_eq!(
            validation.object_identity(),
            compiled.receipt().object_identity()
        );
        assert_eq!(
            validation.expectation_identity(),
            compiled.static_count_expectation().expectation_identity()
        );
        assert_eq!(
            validation.accounting().object_bytes(),
            compiled.object().as_bytes().len()
        );
        assert_eq!(validation.accounting().expectation_bytes(), 672);
        assert_eq!(
            validation
                .accounting()
                .exact_object_equality_bytes_traversed(),
            u64::try_from(compiled.object().as_bytes().len()).unwrap()
        );
        let accounting = validation.accounting();
        assert_eq!(
            accounting.total_work_upper_bound(),
            accounting
                .receipt_authentication_work_upper_bound()
                .checked_add(accounting.object_inspection_work_upper_bound())
                .and_then(|work| {
                    work.checked_add(accounting.exact_object_equality_bytes_traversed())
                })
                .and_then(|work| {
                    work.checked_add(accounting.expectation_inspection_work_upper_bound())
                })
                .and_then(|work| {
                    work.checked_add(accounting.post_inspection_comparison_work_upper_bound())
                })
                .unwrap()
        );
        assert_eq!(
            accounting.post_inspection_comparison_work_upper_bound(),
            post_inspection_comparison_work_upper_bound_v2().unwrap()
        );
        assert_eq!(validation.accounting().allocations(), 0);
        assert_eq!(
            validation.accounting().retained_bytes(),
            size_of::<PrelinkValidationV2>()
        );
    }

    #[test]
    fn neutral_wire_constants_are_exactly_the_compiler_macho_contract() {
        assert_eq!(
            fre_aot_count_contract::AOT_COMPILER_VERSION_V2,
            AOT_COMPILER_VERSION_V2
        );
        assert_eq!(
            fre_aot_count_contract::AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2,
            AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2
        );
        assert_eq!(
            fre_aot_count_contract::STATIC_COUNT_EXPECTATION_BYTES_V2,
            STATIC_COUNT_EXPECTATION_BYTES_V2
        );
        assert_eq!(
            fre_aot_count_contract::STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2,
            STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2
        );
        assert_eq!(
            fre_aot_count_contract::STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2,
            STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2
        );
        assert_eq!(fre_aot_count_contract::METADATA_BYTES_V2, METADATA_BYTES_V2);
        assert_eq!(
            fre_aot_count_contract::METADATA_VERSION_V2,
            METADATA_VERSION_V2
        );
        assert_eq!(
            fre_aot_count_contract::CALL_ABI_SCHEMA_V2,
            CALL_ABI_SCHEMA_V2
        );
        assert_eq!(fre_aot_count_contract::ENTRY_OFFSET_V2, ENTRY_OFFSET_V2);
        assert_eq!(
            fre_aot_count_contract::EXPORTED_SYMBOL_SCHEMA_VERSION_V2,
            EXPORTED_SYMBOL_SCHEMA_VERSION_V2
        );
        assert_eq!(
            fre_aot_count_contract::EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2,
            EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2
        );
        assert_eq!(
            fre_aot_count_contract::COUNT_EXPORTED_SYMBOL_N_TYPE_V2,
            COUNT_EXPORTED_SYMBOL_N_TYPE_V2
        );
        assert_eq!(
            fre_aot_count_contract::COUNT_ENTRY_SYMBOL_PREFIX_V2,
            COUNT_ENTRY_SYMBOL_PREFIX_V2
        );
        assert_eq!(
            fre_aot_count_contract::COUNT_PAYLOAD_SYMBOL_PREFIX_V2,
            COUNT_PAYLOAD_SYMBOL_PREFIX_V2
        );
        assert_eq!(
            fre_aot_count_contract::COUNT_METADATA_SYMBOL_PREFIX_V2,
            COUNT_METADATA_SYMBOL_PREFIX_V2
        );
    }

    #[test]
    fn neutral_and_compiler_parsers_have_mutation_equivalent_contracts() {
        let compiled = compile("needle");
        let expectation = compiled.static_count_expectation().as_bytes();
        let compiler_claim =
            inspect_static_count_expectation_v2(expectation).expect("compiler expectation parser");
        let neutral_claim =
            inspect_neutral_expectation_v2(expectation).expect("neutral expectation parser");
        let neutral_metadata_bytes =
            neutral_metadata_wire_v2(expectation).expect("fixed neutral metadata wire");
        validate_neutral_expectation_claim_v2(
            &compiler_claim,
            &neutral_claim,
            neutral_metadata_bytes,
        )
        .expect("exact claim equivalence");
        validate_neutral_metadata_claim_v2(compiler_claim.metadata(), neutral_claim.metadata())
            .expect("exact metadata equivalence");

        for index in 0..expectation.len() {
            let mut mutated = *expectation;
            mutated[index] ^= 1;
            let compiler_accepted = inspect_static_count_expectation_v2(&mutated).is_ok();
            let neutral_accepted = inspect_neutral_expectation_v2(&mutated).is_ok();
            assert_eq!(
                neutral_accepted, compiler_accepted,
                "parser disagreement at expectation byte {index}"
            );
            assert!(
                !compiler_accepted,
                "self-authenticating expectation mutation {index} was accepted"
            );
        }

        let metadata = *compiled.static_count_expectation().metadata_bytes_v2();
        for index in 0..metadata.len() {
            let mut mutated = metadata;
            mutated[index] ^= 1;
            let compiler_result = MetadataV2::decode_canonical(&mutated);
            let neutral_result = inspect_neutral_metadata_v2(&mutated);
            assert_eq!(
                neutral_result.is_ok(),
                compiler_result.is_ok(),
                "parser disagreement at metadata byte {index}"
            );
            if let (Ok(compiler_metadata), Ok(neutral_metadata)) = (compiler_result, neutral_result)
            {
                validate_neutral_metadata_claim_v2(compiler_metadata, neutral_metadata)
                    .unwrap_or_else(|_| panic!("projection disagreement at metadata byte {index}"));
            }
        }
    }

    #[test]
    fn every_candidate_object_byte_mutation_is_refused() {
        let compiled = compile("needle");
        let original = compiled.object().as_bytes();
        for index in 0..original.len() {
            let mut mutated = original.to_vec();
            mutated[index] ^= 1;
            assert!(
                validate_prelink_count_v2(&compiled, &mutated).is_err(),
                "mutated object byte {index} was accepted"
            );
        }
    }
}
