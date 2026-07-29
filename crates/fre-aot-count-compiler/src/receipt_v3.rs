use fre_aot_aarch64::{CountEmitLimitsV3, emit_count_v3};
use fre_aot_count_contract::v3::{
    AOT_COMPILER_VERSION_V3, AOT_COUNT_AUDITOR_VERSION_V3,
    AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V3, CountGeneralEligibilityTupleV3, CountObjectFormatV3,
    METADATA_BYTES_V3, STATIC_COUNT_EXPECTATION_BYTES_V3,
    STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3, inspect_count_metadata_v3,
    inspect_static_count_expectation_v3,
};
use fre_aot_optimizer::{
    COUNT_V3_MAX_LITERAL_BYTES, COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES, CountRecipeV3,
    CountV3OptimizerLimits, CountV3OptimizerReceipt, CountV3RequiredIsa, CountV3TuningClass,
    compute_count_v3_literal_identity, encode_count_recipe_v3, encode_count_v3_optimizer_receipt,
    inspect_count_v3_optimizer_receipt, optimize_count_v3, validate_count_recipe_v3,
};
use fre_kernel_ir::{Count, ValidateLimits, build_exact_aggregate};
use sha2::{Digest, Sha256};

use crate::{
    CountCompileErrorV3, CountImplementationInspectionV3, CountImplementationObjectV3,
    CountObjectLimitsV3, inspect_count_implementation_object_v3,
    object_v3::emit_count_implementation_object_v3,
};

const EXPECTATION_IDENTITY_DOMAIN_V3: &[u8] = b"FRE-AOT-STATIC-COUNT-EXPECTATION-IDENTITY\0\x03";
const PRELINK_CONTENT_IDENTITY_DOMAIN_V3: &[u8] = b"FRE-AOT-COUNT-V3-UNSIGNED-PRELINK\0\x03";
const PRELINK_MAGIC_V3: [u8; 8] = *b"FRECPR\0\x03";
const PRELINK_SCHEMA_VERSION_V3: u16 = 3;
const PRELINK_OBJECT_BYTES_OFFSET: usize = 16;
const PRELINK_PAYLOAD_BYTES_OFFSET: usize = 24;
const PRELINK_COMPILE_IDENTITY_OFFSET: usize = 32;
const PRELINK_OBJECT_IDENTITY_OFFSET: usize = 64;
const PRELINK_EXPECTATION_IDENTITY_OFFSET: usize = 96;
const PRELINK_OPTIMIZER_RECEIPT_OFFSET: usize = 128;
const PRELINK_EXPECTATION_OFFSET: usize =
    PRELINK_OPTIMIZER_RECEIPT_OFFSET + COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES;
const PRELINK_CONTENT_IDENTITY_OFFSET: usize =
    PRELINK_EXPECTATION_OFFSET + STATIC_COUNT_EXPECTATION_BYTES_V3;
pub const UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V3: usize = PRELINK_CONTENT_IDENTITY_OFFSET + 32;
const _: () = assert!(PRELINK_EXPECTATION_OFFSET == 320);
const _: () = assert!(UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V3 == 1_496);

/// Fixed source/planner provenance associated with a semantic Count candidate.
///
/// These identities remain unsigned claims.  Recipe, optimizer, image, target,
/// object, and expectation identities are deliberately not caller inputs:
/// the focused compiler computes them once from the literal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountSemanticCandidateV3 {
    pub manifest_identity: [u8; 32],
    pub policy_limits_identity: [u8; 32],
    pub semantic_binding_identity: [u8; 32],
    pub planning_receipt_identity: [u8; 32],
    pub object_binding_identity: [u8; 32],
    pub claimed_receipt_identity: [u8; 32],
    pub claimed_resource_receipt_identity: [u8; 32],
}

/// Explicit offline target selection.  No host feature probing occurs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountCompileTargetV3 {
    pub object_format: CountObjectFormatV3,
    pub tuning_class: CountV3TuningClass,
    pub required_isa: CountV3RequiredIsa,
}

/// Borrowed one-pass optimizing Count-v3 compile request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountCompileRequestV3<'a> {
    pub literal: &'a [u8],
    pub semantic_candidate: CountSemanticCandidateV3,
    pub target: CountCompileTargetV3,
}

/// Finite limits for KIR, deterministic optimization, native emission, and
/// deterministic object publication.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CountCompileLimitsV3 {
    pub kernel_ir: ValidateLimits,
    pub optimizer: CountV3OptimizerLimits,
    pub native: CountEmitLimitsV3,
    pub object: CountObjectLimitsV3,
}

/// The only authority state carried by an unsigned v3 compile result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAuthorityV3 {
    /// Canonical self-hashes are not a signature or qualification row.
    Absent,
}

/// Canonical path-free, signer-free prelink content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsignedCountPrelinkReceiptV3 {
    canonical_bytes: [u8; UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V3],
}

impl UnsignedCountPrelinkReceiptV3 {
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V3] {
        &self.canonical_bytes
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> RuntimeAuthorityV3 {
        RuntimeAuthorityV3::Absent
    }

    #[must_use]
    pub fn compile_identity(&self) -> &[u8; 32] {
        self.canonical_bytes[PRELINK_COMPILE_IDENTITY_OFFSET..PRELINK_OBJECT_IDENTITY_OFFSET]
            .try_into()
            .expect("fixed v3 compile identity range")
    }

    #[must_use]
    pub fn object_identity(&self) -> &[u8; 32] {
        self.canonical_bytes[PRELINK_OBJECT_IDENTITY_OFFSET..PRELINK_EXPECTATION_IDENTITY_OFFSET]
            .try_into()
            .expect("fixed v3 object identity range")
    }

    #[must_use]
    pub fn expectation_identity(&self) -> &[u8; 32] {
        self.canonical_bytes[PRELINK_EXPECTATION_IDENTITY_OFFSET..PRELINK_OPTIMIZER_RECEIPT_OFFSET]
            .try_into()
            .expect("fixed v3 expectation identity range")
    }

    #[must_use]
    pub fn optimizer_receipt(&self) -> &[u8; COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES] {
        self.canonical_bytes[PRELINK_OPTIMIZER_RECEIPT_OFFSET..PRELINK_EXPECTATION_OFFSET]
            .try_into()
            .expect("fixed v3 optimizer receipt range")
    }

    #[must_use]
    pub fn expectation(&self) -> &[u8; STATIC_COUNT_EXPECTATION_BYTES_V3] {
        self.canonical_bytes[PRELINK_EXPECTATION_OFFSET..PRELINK_CONTENT_IDENTITY_OFFSET]
            .try_into()
            .expect("fixed v3 expectation range")
    }

    #[must_use]
    pub fn content_identity(&self) -> &[u8; 32] {
        self.canonical_bytes[PRELINK_CONTENT_IDENTITY_OFFSET..]
            .try_into()
            .expect("fixed v3 prelink content identity range")
    }

    /// Prove canonical self-consistency without manufacturing authority.
    #[must_use]
    pub fn authenticates_itself(&self) -> bool {
        if self.canonical_bytes[..8] != PRELINK_MAGIC_V3
            || self.canonical_bytes[8..10] != PRELINK_SCHEMA_VERSION_V3.to_le_bytes()
            || self.canonical_bytes[10..12] != [0; 2]
            || self.canonical_bytes[12..16]
                != u32::try_from(UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V3)
                    .expect("fixed v3 receipt width")
                    .to_le_bytes()
            || digest_with_domain(
                PRELINK_CONTENT_IDENTITY_DOMAIN_V3,
                &self.canonical_bytes[..PRELINK_CONTENT_IDENTITY_OFFSET],
            ) != *self.content_identity()
        {
            return false;
        }
        let Ok(optimizer) = inspect_count_v3_optimizer_receipt(self.optimizer_receipt()) else {
            return false;
        };
        let Ok(expectation) = inspect_static_count_expectation_v3(self.expectation()) else {
            return false;
        };
        expectation.compile_identity() == self.compile_identity()
            && expectation.object_identity() == self.object_identity()
            && expectation.expectation_identity() == self.expectation_identity()
            && expectation.optimizer_receipt_identity() == optimizer.identity().as_bytes()
            && expectation.program_identity() == optimizer.program_identity()
            && expectation.recipe_identity() == optimizer.recipe_identity().as_bytes()
            && expectation.metadata().tuning_class_id() == optimizer.tuning_class().wire_id()
    }

    /// Validate candidate object bytes without granting runtime adoption.
    pub fn validate_candidate<'a>(
        &self,
        candidate: &'a [u8],
        limits: CountObjectLimitsV3,
    ) -> Result<CountImplementationInspectionV3<'a>, CountCompileErrorV3> {
        if !self.authenticates_itself() {
            return Err(CountCompileErrorV3::InvalidUnsignedReceipt {
                at: "prelink self-authentication",
            });
        }
        let inspection = inspect_count_implementation_object_v3(candidate, limits)?;
        let expectation =
            inspect_static_count_expectation_v3(self.expectation()).map_err(|_| {
                CountCompileErrorV3::InvalidUnsignedReceipt {
                    at: "prelink expectation",
                }
            })?;
        let expected_object_bytes = read_u64(
            &self.canonical_bytes,
            PRELINK_OBJECT_BYTES_OFFSET,
            "prelink object bytes",
        )?;
        let expected_payload_bytes = read_u64(
            &self.canonical_bytes,
            PRELINK_PAYLOAD_BYTES_OFFSET,
            "prelink payload bytes",
        )?;
        if u64::try_from(inspection.object_bytes()).ok() != Some(expected_object_bytes)
            || u64::try_from(inspection.payload().len()).ok() != Some(expected_payload_bytes)
            || inspection.compile_identity() != self.compile_identity()
            || inspection.object_identity() != self.object_identity()
            || inspection.metadata() != expectation.metadata()
        {
            return Err(CountCompileErrorV3::InvalidUnsignedReceipt {
                at: "candidate object binding",
            });
        }
        Ok(inspection)
    }
}

/// Complete inert output of one-pass optimizing Count-v3 compilation.
#[derive(Debug, Eq, PartialEq)]
pub struct FocusedCompiledCountV3 {
    implementation_object: CountImplementationObjectV3,
    expectation: [u8; STATIC_COUNT_EXPECTATION_BYTES_V3],
    unsigned_prelink_receipt: UnsignedCountPrelinkReceiptV3,
    recipe: CountRecipeV3,
    optimizer_receipt: CountV3OptimizerReceipt,
}

impl FocusedCompiledCountV3 {
    #[must_use]
    pub const fn implementation_object(&self) -> &CountImplementationObjectV3 {
        &self.implementation_object
    }

    #[must_use]
    pub const fn expectation(&self) -> &[u8; STATIC_COUNT_EXPECTATION_BYTES_V3] {
        &self.expectation
    }

    #[must_use]
    pub const fn unsigned_prelink_receipt(&self) -> &UnsignedCountPrelinkReceiptV3 {
        &self.unsigned_prelink_receipt
    }

    #[must_use]
    pub const fn recipe(&self) -> &CountRecipeV3 {
        &self.recipe
    }

    #[must_use]
    pub const fn optimizer_receipt(&self) -> &CountV3OptimizerReceipt {
        &self.optimizer_receipt
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> RuntimeAuthorityV3 {
        RuntimeAuthorityV3::Absent
    }

    #[must_use]
    pub fn general_eligibility_tuple(
        &self,
    ) -> Result<CountGeneralEligibilityTupleV3, CountCompileErrorV3> {
        inspect_static_count_expectation_v3(&self.expectation)
            .map(|claim| claim.metadata().general_eligibility_tuple())
            .map_err(|_| CountCompileErrorV3::InvalidExpectation {
                at: "eligibility projection",
            })
    }
}

/// Compile literal -> KIR -> deterministic optimizer -> audited native image ->
/// deterministic relocatable object in one source-only transaction.
///
/// No LLVM, external assembler/compiler, linker, JIT, process spawn, timing,
/// corpus name, benchmark name, haystack, or profile participates.
pub fn compile_count_v3(
    request: CountCompileRequestV3<'_>,
    limits: CountCompileLimitsV3,
) -> Result<FocusedCompiledCountV3, CountCompileErrorV3> {
    if request.literal.len() > COUNT_V3_MAX_LITERAL_BYTES {
        return Err(CountCompileErrorV3::InvalidSemanticCandidate {
            field: "literal width",
        });
    }
    require_candidate_identities(request.semantic_candidate)?;
    let live_literal_identity: [u8; 32] = Sha256::digest(request.literal).into();
    let recipe_literal_identity = compute_count_v3_literal_identity(request.literal);
    let program = build_exact_aggregate::<Count>(request.literal, limits.kernel_ir)?;
    let optimized = optimize_count_v3(&program, request.target.tuning_class, limits.optimizer)?;
    let recipe = *optimized.recipe();
    let optimizer_receipt = *optimized.receipt();
    if !optimizer_receipt.authenticates()
        || optimizer_receipt.program_identity() != program.cache_identity()
        || optimizer_receipt.recipe_identity() != recipe.identity()
        || recipe.required_isa() != request.target.required_isa
        || validate_count_recipe_v3(&program, &recipe).is_err()
    {
        return Err(CountCompileErrorV3::InvalidSemanticCandidate {
            field: "sealed optimizer result",
        });
    }
    let image = emit_count_v3(&program, &recipe, limits.native)?;
    let image_recipe = image.recipe_manifest();
    if image.source_identity() != program.cache_identity()
        || image.literal_manifest().literal() != request.literal
        || image_recipe.literal_identity() != recipe_literal_identity
        || image_recipe.recipe_identity() != *recipe.identity().as_bytes()
        || image_recipe.canonical_recipe() != &encode_count_recipe_v3(&recipe)
        || image_recipe.required_isa_id() != request.target.required_isa.wire_id()
    {
        return Err(CountCompileErrorV3::InvalidSemanticCandidate {
            field: "image semantic binding",
        });
    }
    let implementation_object = emit_count_implementation_object_v3(
        &image,
        *optimizer_receipt.identity().as_bytes(),
        request.semantic_candidate.object_binding_identity,
        request.target.object_format,
        limits.object,
    )?;
    let expectation = build_expectation(
        &request,
        live_literal_identity,
        *program.cache_identity().as_bytes(),
        *image.artifact_identity().as_bytes(),
        *recipe.identity().as_bytes(),
        *optimizer_receipt.identity().as_bytes(),
        &implementation_object,
    )?;
    let expectation_claim = inspect_static_count_expectation_v3(&expectation).map_err(|_| {
        CountCompileErrorV3::InvalidExpectation {
            at: "compiled expectation",
        }
    })?;
    let object_metadata = inspect_count_metadata_v3(implementation_object.metadata_bytes())
        .map_err(|_| CountCompileErrorV3::InvalidExpectation {
            at: "compiled object metadata",
        })?;
    if expectation_claim.metadata() != object_metadata
        || expectation_claim.compile_identity() != implementation_object.compile_identity()
        || expectation_claim.object_identity() != implementation_object.object_identity()
    {
        return Err(CountCompileErrorV3::InvalidExpectation {
            at: "expectation/object binding",
        });
    }
    let unsigned_prelink_receipt =
        build_unsigned_prelink_receipt(&implementation_object, &expectation, &optimizer_receipt)?;
    if unsigned_prelink_receipt.runtime_authority() != RuntimeAuthorityV3::Absent
        || unsigned_prelink_receipt
            .validate_candidate(implementation_object.as_bytes(), limits.object)
            .is_err()
    {
        return Err(CountCompileErrorV3::InvalidUnsignedReceipt {
            at: "compiled prelink validation",
        });
    }
    Ok(FocusedCompiledCountV3 {
        implementation_object,
        expectation,
        unsigned_prelink_receipt,
        recipe,
        optimizer_receipt,
    })
}

fn require_candidate_identities(
    candidate: CountSemanticCandidateV3,
) -> Result<(), CountCompileErrorV3> {
    for (field, identity) in [
        ("manifest identity", candidate.manifest_identity),
        ("policy limits identity", candidate.policy_limits_identity),
        (
            "semantic binding identity",
            candidate.semantic_binding_identity,
        ),
        (
            "planning receipt identity",
            candidate.planning_receipt_identity,
        ),
        ("object binding identity", candidate.object_binding_identity),
        (
            "claimed receipt identity",
            candidate.claimed_receipt_identity,
        ),
        (
            "claimed resource receipt identity",
            candidate.claimed_resource_receipt_identity,
        ),
    ] {
        if identity == [0; 32] {
            return Err(CountCompileErrorV3::InvalidSemanticCandidate { field });
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "arguments enumerate the complete independently recomputed identity chain"
)]
fn build_expectation(
    request: &CountCompileRequestV3<'_>,
    literal_identity: [u8; 32],
    program_identity: [u8; 32],
    image_identity: [u8; 32],
    recipe_identity: [u8; 32],
    optimizer_receipt_identity: [u8; 32],
    object: &CountImplementationObjectV3,
) -> Result<[u8; STATIC_COUNT_EXPECTATION_BYTES_V3], CountCompileErrorV3> {
    let mut bytes = [0_u8; STATIC_COUNT_EXPECTATION_BYTES_V3];
    let mut writer = FixedWriter::new(&mut bytes);
    writer.bytes(b"FRESCEX\x03")?;
    writer.u16(AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V3)?;
    writer.u16(AOT_COMPILER_VERSION_V3)?;
    writer.u32(
        u32::try_from(STATIC_COUNT_EXPECTATION_BYTES_V3).expect("fixed v3 expectation width"),
    )?;
    for identity in [
        request.semantic_candidate.manifest_identity,
        request.semantic_candidate.policy_limits_identity,
        request.semantic_candidate.semantic_binding_identity,
        request.semantic_candidate.planning_receipt_identity,
        literal_identity,
        program_identity,
        image_identity,
        recipe_identity,
        optimizer_receipt_identity,
        request.semantic_candidate.object_binding_identity,
        *object.compile_identity(),
        *object.object_identity(),
        request.semantic_candidate.claimed_receipt_identity,
        request.semantic_candidate.claimed_resource_receipt_identity,
    ] {
        writer.bytes(&identity)?;
    }
    writer.u32(
        u32::try_from(request.literal.len()).map_err(|_| overflow("expectation literal length"))?,
    )?;
    writer.u16(u16::try_from(METADATA_BYTES_V3).expect("fixed v3 metadata width"))?;
    writer.u16(fre_aot_aarch64::AOT_COUNT_IMAGE_SCHEMA_VERSION_V3)?;
    if writer.position() != 472 {
        return Err(CountCompileErrorV3::InvalidExpectation {
            at: "expectation metadata offset",
        });
    }
    writer.bytes(object.metadata_bytes())?;
    if writer.position() != STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3 {
        return Err(CountCompileErrorV3::InvalidExpectation {
            at: "expectation identity offset",
        });
    }
    let identity = digest_with_domain(
        EXPECTATION_IDENTITY_DOMAIN_V3,
        &bytes[..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3],
    );
    bytes[STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3..].copy_from_slice(&identity);
    Ok(bytes)
}

fn build_unsigned_prelink_receipt(
    object: &CountImplementationObjectV3,
    expectation: &[u8; STATIC_COUNT_EXPECTATION_BYTES_V3],
    optimizer_receipt: &CountV3OptimizerReceipt,
) -> Result<UnsignedCountPrelinkReceiptV3, CountCompileErrorV3> {
    let optimizer_bytes = encode_count_v3_optimizer_receipt(optimizer_receipt);
    if !authenticate_optimizer_receipt_bytes(&optimizer_bytes) {
        return Err(CountCompileErrorV3::InvalidUnsignedReceipt {
            at: "optimizer receipt encoding",
        });
    }
    let expectation_claim = inspect_static_count_expectation_v3(expectation).map_err(|_| {
        CountCompileErrorV3::InvalidUnsignedReceipt {
            at: "prelink expectation input",
        }
    })?;
    let mut bytes = [0_u8; UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V3];
    let mut writer = FixedWriter::new(&mut bytes);
    writer.bytes(&PRELINK_MAGIC_V3)?;
    writer.u16(PRELINK_SCHEMA_VERSION_V3)?;
    writer.u16(0)?;
    writer.u32(
        u32::try_from(UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V3).expect("fixed v3 prelink width"),
    )?;
    writer.u64(
        u64::try_from(object.as_bytes().len()).map_err(|_| overflow("prelink object bytes"))?,
    )?;
    writer.u64(
        u64::try_from(object.payload_bytes()).map_err(|_| overflow("prelink payload bytes"))?,
    )?;
    writer.bytes(object.compile_identity())?;
    writer.bytes(object.object_identity())?;
    writer.bytes(expectation_claim.expectation_identity())?;
    writer.bytes(&optimizer_bytes)?;
    writer.bytes(expectation)?;
    if writer.position() != PRELINK_CONTENT_IDENTITY_OFFSET {
        return Err(CountCompileErrorV3::InvalidUnsignedReceipt {
            at: "prelink content identity offset",
        });
    }
    let content_identity = digest_with_domain(
        PRELINK_CONTENT_IDENTITY_DOMAIN_V3,
        &bytes[..PRELINK_CONTENT_IDENTITY_OFFSET],
    );
    bytes[PRELINK_CONTENT_IDENTITY_OFFSET..].copy_from_slice(&content_identity);
    let receipt = UnsignedCountPrelinkReceiptV3 {
        canonical_bytes: bytes,
    };
    if !receipt.authenticates_itself() {
        return Err(CountCompileErrorV3::InvalidUnsignedReceipt {
            at: "prelink self-inspection",
        });
    }
    Ok(receipt)
}

fn authenticate_optimizer_receipt_bytes(
    bytes: &[u8; COUNT_V3_OPTIMIZER_RECEIPT_CANONICAL_BYTES],
) -> bool {
    inspect_count_v3_optimizer_receipt(bytes).is_ok()
}

struct FixedWriter<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> FixedWriter<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), CountCompileErrorV3> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or_else(|| overflow("fixed writer offset"))?;
        self.bytes
            .get_mut(self.position..end)
            .ok_or(CountCompileErrorV3::InvalidExpectation {
                at: "fixed writer destination",
            })?
            .copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn u16(&mut self, value: u16) -> Result<(), CountCompileErrorV3> {
        self.bytes(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), CountCompileErrorV3> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), CountCompileErrorV3> {
        self.bytes(&value.to_le_bytes())
    }

    const fn position(&self) -> usize {
        self.position
    }
}

fn read_u64(bytes: &[u8], offset: usize, at: &'static str) -> Result<u64, CountCompileErrorV3> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| overflow("prelink reader offset"))?;
    let value: [u8; 8] = bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or(CountCompileErrorV3::InvalidUnsignedReceipt { at })?;
    Ok(u64::from_le_bytes(value))
}

fn digest_with_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

const fn overflow(at: &'static str) -> CountCompileErrorV3 {
    CountCompileErrorV3::ArithmeticOverflow { at }
}

const _: () = assert!(AOT_COUNT_AUDITOR_VERSION_V3 == 1);
