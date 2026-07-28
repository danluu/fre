use fre_aot_aarch64::{AOT_COUNT_IMAGE_SCHEMA_VERSION_V2, CountEmitLimitsV2, emit_count_v2};
use fre_aot_count_contract::{
    AOT_COMPILER_VERSION_V2, AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2, METADATA_BYTES_V2,
    STATIC_COUNT_EXPECTATION_BYTES_V2, STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2,
    STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2, inspect_count_metadata_v2,
    inspect_static_count_expectation_v2,
};
use fre_kernel_ir::{
    AggregateBuildError, Count, MAX_EXACT_AGGREGATE_LITERAL_BYTES, ValidateLimits,
    build_exact_aggregate,
};
use sha2::{Digest, Sha256};

use crate::{
    CountCompileErrorV2, CountImplementationInspectionV2, CountImplementationObjectV2,
    CountObjectLimitsV2, object::emit_count_implementation_object_v2,
};

const EXPECTATION_IDENTITY_DOMAIN_V2: &[u8] = b"FRE-AOT-STATIC-COUNT-EXPECTATION-IDENTITY\0\x02";
const PRELINK_CONTENT_IDENTITY_DOMAIN_V2: &[u8] = b"FRE-AOT-COUNT-UNSIGNED-PRELINK-CONTENT\0\x02";
const PRELINK_MAGIC_V2: [u8; 8] = *b"FRECPR\0\x02";
const PRELINK_SCHEMA_VERSION_V2: u16 = 2;
const PRELINK_CLAIM_IDENTITIES: usize = 10;
const PRELINK_HEADER_BYTES: usize = 16;
const PRELINK_CLAIMS_OFFSET: usize = PRELINK_HEADER_BYTES;
const PRELINK_LITERAL_BYTES_OFFSET: usize = PRELINK_CLAIMS_OFFSET + (PRELINK_CLAIM_IDENTITIES * 32);
const PRELINK_SUPPORT_OFFSET: usize = PRELINK_LITERAL_BYTES_OFFSET + 4;
const PRELINK_SUPPORT_BYTES: usize = 24;
const PRELINK_OBJECT_BYTES_OFFSET: usize = PRELINK_SUPPORT_OFFSET + PRELINK_SUPPORT_BYTES;
const PRELINK_PAYLOAD_BYTES_OFFSET: usize = PRELINK_OBJECT_BYTES_OFFSET + 8;
const PRELINK_COMPILE_IDENTITY_OFFSET: usize = PRELINK_PAYLOAD_BYTES_OFFSET + 8;
const PRELINK_OBJECT_IDENTITY_OFFSET: usize = PRELINK_COMPILE_IDENTITY_OFFSET + 32;
const PRELINK_EXPECTATION_IDENTITY_OFFSET: usize = PRELINK_OBJECT_IDENTITY_OFFSET + 32;
const PRELINK_METADATA_OFFSET: usize = PRELINK_EXPECTATION_IDENTITY_OFFSET + 32;
const PRELINK_CONTENT_IDENTITY_OFFSET: usize = PRELINK_METADATA_OFFSET + METADATA_BYTES_V2;
pub const UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V2: usize = PRELINK_CONTENT_IDENTITY_OFFSET + 32;
const _: () = assert!(UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V2 == 740);

/// Untrusted planner-provenance claims bound into focused compiler output.
///
/// Literal/KIR/image claims are independently recomputed. Manifest, policy,
/// semantic-planning, object-binding, and legacy receipt claims cannot be
/// recreated without the facade and remain explicitly unauthoritative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountCompileClaimsV2 {
    pub manifest_identity: [u8; 32],
    pub policy_limits_identity: [u8; 32],
    pub semantic_binding_identity: [u8; 32],
    pub planning_receipt_identity: [u8; 32],
    pub live_literal_identity: [u8; 32],
    pub program_identity: [u8; 32],
    pub image_identity: [u8; 32],
    pub object_binding_identity: [u8; 32],
    pub claimed_receipt_identity: [u8; 32],
    pub claimed_resource_receipt_identity: [u8; 32],
}

impl CountCompileClaimsV2 {
    fn identities(self) -> [[u8; 32]; PRELINK_CLAIM_IDENTITIES] {
        [
            self.manifest_identity,
            self.policy_limits_identity,
            self.semantic_binding_identity,
            self.planning_receipt_identity,
            self.live_literal_identity,
            self.program_identity,
            self.image_identity,
            self.object_binding_identity,
            self.claimed_receipt_identity,
            self.claimed_resource_receipt_identity,
        ]
    }
}

/// Borrowed typed exact-literal compile request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountCompileRequestV2<'a> {
    pub literal: &'a [u8],
    pub claims: CountCompileClaimsV2,
}

/// Finite limits for the focused KIR, `AArch64`, and object stages.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CountCompileLimitsV2 {
    pub kernel_ir: ValidateLimits,
    pub native: CountEmitLimitsV2,
    pub object: CountObjectLimitsV2,
}

/// The only authority state carried by an unsigned compile result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeAuthorityV2 {
    /// Canonical content has no source-bound signature or final-image row.
    Absent,
}

/// Canonical, path-free and signer-free prelink content.
///
/// Its self-hash detects mutation but is not a signature, certificate,
/// qualification row, or runtime-adoption authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsignedCountPrelinkReceiptV2 {
    canonical_bytes: [u8; UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V2],
}

impl UnsignedCountPrelinkReceiptV2 {
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V2] {
        &self.canonical_bytes
    }

    #[must_use]
    pub fn content_identity(&self) -> &[u8; 32] {
        self.canonical_bytes[PRELINK_CONTENT_IDENTITY_OFFSET..]
            .try_into()
            .expect("fixed prelink content identity range")
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> RuntimeAuthorityV2 {
        RuntimeAuthorityV2::Absent
    }

    #[must_use]
    pub fn authenticates_itself(&self) -> bool {
        self.canonical_bytes[..8] == PRELINK_MAGIC_V2
            && self.canonical_bytes[8..10] == PRELINK_SCHEMA_VERSION_V2.to_le_bytes()
            && self.canonical_bytes[12..16]
                == u32::try_from(UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V2)
                    .expect("fixed receipt length")
                    .to_le_bytes()
            && digest_with_domain(
                PRELINK_CONTENT_IDENTITY_DOMAIN_V2,
                &self.canonical_bytes[..PRELINK_CONTENT_IDENTITY_OFFSET],
            ) == *self.content_identity()
            && self
                .metadata_bytes()
                .is_some_and(|metadata| inspect_count_metadata_v2(metadata).is_ok())
    }

    #[must_use]
    pub fn compile_identity(&self) -> &[u8; 32] {
        self.canonical_bytes[PRELINK_COMPILE_IDENTITY_OFFSET..PRELINK_OBJECT_IDENTITY_OFFSET]
            .try_into()
            .expect("fixed compile identity range")
    }

    #[must_use]
    pub fn object_identity(&self) -> &[u8; 32] {
        self.canonical_bytes[PRELINK_OBJECT_IDENTITY_OFFSET..PRELINK_EXPECTATION_IDENTITY_OFFSET]
            .try_into()
            .expect("fixed object identity range")
    }

    #[must_use]
    pub fn expectation_identity(&self) -> &[u8; 32] {
        self.canonical_bytes[PRELINK_EXPECTATION_IDENTITY_OFFSET..PRELINK_METADATA_OFFSET]
            .try_into()
            .expect("fixed expectation identity range")
    }

    #[must_use]
    pub fn metadata_bytes(&self) -> Option<&[u8; METADATA_BYTES_V2]> {
        self.canonical_bytes
            .get(PRELINK_METADATA_OFFSET..PRELINK_CONTENT_IDENTITY_OFFSET)?
            .try_into()
            .ok()
    }

    /// Validate candidate object bytes without manufacturing runtime authority.
    pub fn validate_candidate<'a>(
        &self,
        candidate: &'a [u8],
        limits: CountObjectLimitsV2,
    ) -> Result<CountImplementationInspectionV2<'a>, CountCompileErrorV2> {
        if !self.authenticates_itself() {
            return Err(CountCompileErrorV2::InvalidUnsignedReceipt);
        }
        let inspection = crate::inspect_count_implementation_object_v2(candidate, limits)?;
        let expected_object_bytes = read_u64(
            &self.canonical_bytes,
            PRELINK_OBJECT_BYTES_OFFSET,
            "receipt object bytes",
        )?;
        let expected_payload_bytes = read_u64(
            &self.canonical_bytes,
            PRELINK_PAYLOAD_BYTES_OFFSET,
            "receipt payload bytes",
        )?;
        if u64::try_from(inspection.object_bytes()).ok() != Some(expected_object_bytes)
            || u64::try_from(inspection.payload().len()).ok() != Some(expected_payload_bytes)
            || inspection.compile_identity() != self.compile_identity()
            || inspection.object_identity() != self.object_identity()
            || self.metadata_bytes() != Some(inspection.metadata_bytes())
        {
            return Err(CountCompileErrorV2::InvalidUnsignedReceipt);
        }
        Ok(inspection)
    }
}

/// Complete inert output of focused Count-v2 compilation.
#[derive(Debug, Eq, PartialEq)]
pub struct FocusedCompiledCountV2 {
    implementation_object: CountImplementationObjectV2,
    expectation: [u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
    unsigned_prelink_receipt: UnsignedCountPrelinkReceiptV2,
}

impl FocusedCompiledCountV2 {
    #[must_use]
    pub const fn implementation_object(&self) -> &CountImplementationObjectV2 {
        &self.implementation_object
    }

    #[must_use]
    pub const fn expectation(&self) -> &[u8; STATIC_COUNT_EXPECTATION_BYTES_V2] {
        &self.expectation
    }

    #[must_use]
    pub const fn unsigned_prelink_receipt(&self) -> &UnsignedCountPrelinkReceiptV2 {
        &self.unsigned_prelink_receipt
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> RuntimeAuthorityV2 {
        RuntimeAuthorityV2::Absent
    }
}

/// Compile typed exact-literal Count KIR through the independent `AArch64` path.
///
/// No compiler, assembler, linker, LLVM, JIT, or process-spawn API is used.
pub fn compile_count_v2(
    request: CountCompileRequestV2<'_>,
    limits: CountCompileLimitsV2,
) -> Result<FocusedCompiledCountV2, CountCompileErrorV2> {
    preflight_literal_width(request.literal.len())?;
    require_nonzero_claims(&request.claims)?;
    let literal_identity = compute_literal_identity(request.literal);
    require_claim(
        literal_identity == request.claims.live_literal_identity,
        "live literal identity",
    )?;

    let program = build_exact_aggregate::<Count>(request.literal, limits.kernel_ir)?;
    require_claim(
        program.cache_identity().as_bytes() == &request.claims.program_identity,
        "program identity",
    )?;
    let image = emit_count_v2(&program, limits.native)?;
    require_claim(
        image.source_identity().as_bytes() == &request.claims.program_identity,
        "image source identity",
    )?;
    require_claim(
        image.artifact_identity().as_bytes() == &request.claims.image_identity,
        "image identity",
    )?;
    let implementation_object = emit_count_implementation_object_v2(
        &image,
        request.claims.object_binding_identity,
        limits.object,
    )?;
    let expectation = build_expectation(&request, &implementation_object)?;
    let expectation_claim = inspect_static_count_expectation_v2(&expectation)
        .map_err(|_| CountCompileErrorV2::InvalidExpectation)?;
    if expectation_claim.compile_identity() != implementation_object.compile_identity()
        || expectation_claim.object_identity() != implementation_object.object_identity()
        || expectation_claim.metadata()
            != inspect_count_metadata_v2(implementation_object.metadata_bytes())
                .map_err(|_| CountCompileErrorV2::InvalidExpectation)?
    {
        return Err(CountCompileErrorV2::InvalidExpectation);
    }
    let unsigned_prelink_receipt =
        build_unsigned_prelink_receipt(&request, &implementation_object, &expectation)?;
    if unsigned_prelink_receipt.runtime_authority() != RuntimeAuthorityV2::Absent
        || unsigned_prelink_receipt
            .validate_candidate(implementation_object.as_bytes(), limits.object)
            .is_err()
    {
        return Err(CountCompileErrorV2::InvalidUnsignedReceipt);
    }
    Ok(FocusedCompiledCountV2 {
        implementation_object,
        expectation,
        unsigned_prelink_receipt,
    })
}

fn preflight_literal_width(literal_bytes: usize) -> Result<(), AggregateBuildError> {
    if literal_bytes > MAX_EXACT_AGGREGATE_LITERAL_BYTES {
        return Err(AggregateBuildError::LiteralLengthLimit {
            limit: MAX_EXACT_AGGREGATE_LITERAL_BYTES,
            required: literal_bytes,
        });
    }
    Ok(())
}

fn compute_literal_identity(literal: &[u8]) -> [u8; 32] {
    #[cfg(test)]
    LITERAL_IDENTITY_COMPUTATIONS_V2.with(|computations| {
        computations.set(
            computations
                .get()
                .checked_add(1)
                .expect("test-only literal identity computation counter"),
        );
    });
    Sha256::digest(literal).into()
}

#[cfg(test)]
std::thread_local! {
    static LITERAL_IDENTITY_COMPUTATIONS_V2: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn literal_identity_computations_v2_for_test() -> usize {
    LITERAL_IDENTITY_COMPUTATIONS_V2.with(std::cell::Cell::get)
}

fn build_expectation(
    request: &CountCompileRequestV2<'_>,
    object: &CountImplementationObjectV2,
) -> Result<[u8; STATIC_COUNT_EXPECTATION_BYTES_V2], CountCompileErrorV2> {
    let mut bytes = [0_u8; STATIC_COUNT_EXPECTATION_BYTES_V2];
    let mut writer = FixedWriter::new(&mut bytes);
    writer.bytes(b"FRESCEX\x02")?;
    writer.u16(AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2)?;
    writer.u16(AOT_COMPILER_VERSION_V2)?;
    writer
        .u32(u32::try_from(STATIC_COUNT_EXPECTATION_BYTES_V2).expect("fixed expectation length"))?;
    for identity in [
        request.claims.manifest_identity,
        request.claims.policy_limits_identity,
        request.claims.semantic_binding_identity,
        request.claims.planning_receipt_identity,
        request.claims.live_literal_identity,
        request.claims.program_identity,
        request.claims.image_identity,
        request.claims.object_binding_identity,
        *object.compile_identity(),
        *object.object_identity(),
        request.claims.claimed_receipt_identity,
        request.claims.claimed_resource_receipt_identity,
    ] {
        writer.bytes(&identity)?;
    }
    writer.u32(u32::try_from(request.literal.len()).map_err(|_| {
        CountCompileErrorV2::ArithmeticOverflow {
            at: "literal length",
        }
    })?)?;
    writer.u16(u16::try_from(METADATA_BYTES_V2).expect("fixed metadata length"))?;
    writer.u16(AOT_COUNT_IMAGE_SCHEMA_VERSION_V2)?;
    if writer.position() != STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2 {
        return Err(CountCompileErrorV2::InvalidExpectation);
    }
    writer.bytes(object.metadata_bytes())?;
    if writer.position() != STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2 {
        return Err(CountCompileErrorV2::InvalidExpectation);
    }
    let identity = digest_with_domain(
        EXPECTATION_IDENTITY_DOMAIN_V2,
        &bytes[..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2],
    );
    bytes[STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2..].copy_from_slice(&identity);
    inspect_static_count_expectation_v2(&bytes)
        .map_err(|_| CountCompileErrorV2::InvalidExpectation)?;
    Ok(bytes)
}

fn build_unsigned_prelink_receipt(
    request: &CountCompileRequestV2<'_>,
    object: &CountImplementationObjectV2,
    expectation: &[u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
) -> Result<UnsignedCountPrelinkReceiptV2, CountCompileErrorV2> {
    let expectation_identity: &[u8; 32] = expectation
        .get(STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2..)
        .and_then(|value| value.try_into().ok())
        .ok_or(CountCompileErrorV2::InvalidExpectation)?;
    let metadata = inspect_count_metadata_v2(object.metadata_bytes())
        .map_err(|_| CountCompileErrorV2::InvalidUnsignedReceipt)?;
    let mut bytes = [0_u8; UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V2];
    let mut writer = FixedWriter::new(&mut bytes);
    writer.bytes(&PRELINK_MAGIC_V2)?;
    writer.u16(PRELINK_SCHEMA_VERSION_V2)?;
    writer.u16(0)?;
    writer.u32(
        u32::try_from(UNSIGNED_COUNT_PRELINK_RECEIPT_BYTES_V2)
            .expect("fixed prelink receipt length"),
    )?;
    for identity in request.claims.identities() {
        writer.bytes(&identity)?;
    }
    writer.u32(u32::try_from(request.literal.len()).map_err(|_| {
        CountCompileErrorV2::ArithmeticOverflow {
            at: "receipt literal length",
        }
    })?)?;
    let support = fre_aot_aarch64::SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2[0];
    writer.u16(support.backend_version.0)?;
    writer.u16(support.algorithm_version)?;
    writer.u16(support.kir_semantics_version)?;
    writer.u16(support.kir_abi_version)?;
    writer.u8(support.output_kind)?;
    writer.u8(support.architecture)?;
    writer.u8(u8::from(support.little_endian))?;
    writer.u8(support.pointer_width)?;
    writer.u8(support.target_abi)?;
    writer.u64(support.allowed_features.bits())?;
    writer.u16(support.max_literal_bytes)?;
    writer.u8(support.candidate_block_starts)?;
    if writer.position() != PRELINK_OBJECT_BYTES_OFFSET {
        return Err(CountCompileErrorV2::InvalidUnsignedReceipt);
    }
    writer.u64(u64::try_from(object.as_bytes().len()).map_err(|_| {
        CountCompileErrorV2::ArithmeticOverflow {
            at: "receipt object bytes",
        }
    })?)?;
    writer.u64(u64::try_from(object.payload_bytes()).map_err(|_| {
        CountCompileErrorV2::ArithmeticOverflow {
            at: "receipt payload bytes",
        }
    })?)?;
    writer.bytes(object.compile_identity())?;
    writer.bytes(object.object_identity())?;
    writer.bytes(expectation_identity)?;
    writer.bytes(object.metadata_bytes())?;
    if writer.position() != PRELINK_CONTENT_IDENTITY_OFFSET
        || metadata.compile_identity() != object.compile_identity()
    {
        return Err(CountCompileErrorV2::InvalidUnsignedReceipt);
    }
    let content_identity = digest_with_domain(
        PRELINK_CONTENT_IDENTITY_DOMAIN_V2,
        &bytes[..PRELINK_CONTENT_IDENTITY_OFFSET],
    );
    bytes[PRELINK_CONTENT_IDENTITY_OFFSET..].copy_from_slice(&content_identity);
    let receipt = UnsignedCountPrelinkReceiptV2 {
        canonical_bytes: bytes,
    };
    if !receipt.authenticates_itself() {
        return Err(CountCompileErrorV2::InvalidUnsignedReceipt);
    }
    Ok(receipt)
}

fn require_nonzero_claims(claims: &CountCompileClaimsV2) -> Result<(), CountCompileErrorV2> {
    for (field, identity) in [
        ("manifest identity", claims.manifest_identity),
        ("policy limits identity", claims.policy_limits_identity),
        (
            "semantic binding identity",
            claims.semantic_binding_identity,
        ),
        (
            "planning receipt identity",
            claims.planning_receipt_identity,
        ),
        ("live literal identity", claims.live_literal_identity),
        ("program identity", claims.program_identity),
        ("image identity", claims.image_identity),
        ("object binding identity", claims.object_binding_identity),
        ("claimed receipt identity", claims.claimed_receipt_identity),
        (
            "claimed resource receipt identity",
            claims.claimed_resource_receipt_identity,
        ),
    ] {
        if identity == [0; 32] {
            return Err(CountCompileErrorV2::InvalidClaim { field });
        }
    }
    Ok(())
}

fn require_claim(condition: bool, field: &'static str) -> Result<(), CountCompileErrorV2> {
    if condition {
        Ok(())
    } else {
        Err(CountCompileErrorV2::ClaimMismatch { field })
    }
}

struct FixedWriter<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> FixedWriter<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), CountCompileErrorV2> {
        let end = self.position.checked_add(value.len()).ok_or(
            CountCompileErrorV2::ArithmeticOverflow {
                at: "fixed writer offset",
            },
        )?;
        self.bytes
            .get_mut(self.position..end)
            .ok_or(CountCompileErrorV2::InvalidUnsignedReceipt)?
            .copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), CountCompileErrorV2> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), CountCompileErrorV2> {
        self.bytes(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), CountCompileErrorV2> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), CountCompileErrorV2> {
        self.bytes(&value.to_le_bytes())
    }

    const fn position(&self) -> usize {
        self.position
    }
}

fn read_u64(bytes: &[u8], offset: usize, at: &'static str) -> Result<u64, CountCompileErrorV2> {
    let end = offset
        .checked_add(8)
        .ok_or(CountCompileErrorV2::ArithmeticOverflow { at })?;
    let encoded: [u8; 8] = bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or(CountCompileErrorV2::InvalidUnsignedReceipt)?;
    Ok(u64::from_le_bytes(encoded))
}

fn digest_with_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}
