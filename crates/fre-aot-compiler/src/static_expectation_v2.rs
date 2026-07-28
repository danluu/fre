use core::{fmt, mem::size_of};

use fre::{
    AggregateCountExactLiteralAotPlanningReceiptIdentity,
    AggregateCountExactLiteralAotSemanticBindingIdentity,
};
use fre_aot_aarch64::{
    AOT_COUNT_IMAGE_SCHEMA_VERSION_V2, AotCountArtifactIdentityV2, AotCountBackendSupportV2,
    AotCountCpuFeatures, is_supported_aot_count_backend_tuple_v2,
};
use fre_aot_macho::{
    BindingIdentity, CountCompileIdentityV2, CountObjectIdentityV2, METADATA_BYTES_V2,
    METADATA_V2_WRITER_SCRATCH_BYTES, MetadataV2,
};
use fre_kernel_ir::{AggregateProgramIdentity, MAX_EXACT_AGGREGATE_LITERAL_BYTES};
use sha2::{Digest, Sha256};

use crate::{
    canonical::{
        CANONICAL_TRAVERSAL_FIXED_WORK_V2, CanonicalEncoder, CanonicalError,
        IDENTITY_HASH_FINALIZE_WORK_V2,
    },
    identity::{
        CompileReceiptIdentity, LiveLiteralIdentity, ManifestIdentity, PolicyLimitsIdentity,
        ResourceReceiptIdentity, StaticCountExpectationIdentity,
    },
    manifest_v2::{
        AOT_COMPILER_VERSION_V2, AOT_COUNT_COMPILER_SUPPORT_V2,
        AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2,
    },
    receipt_v2::SealedCompileReceiptV2,
    static_expectation::StaticCountExpectationError,
};

pub const STATIC_COUNT_EXPECTATION_BYTES_V2: usize = 672;
pub const STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2: usize = 408;
pub const STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2: usize = 640;
pub const STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2: u64 = 683;
pub const STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_TRAVERSED_V2: u64 = 1_963;
pub const STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2: u64 = 4_083;

const STATIC_EXPECTATION_MAGIC_V2: [u8; 8] = *b"FRESCEX\x02";
const STATIC_EXPECTATION_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-STATIC-COUNT-EXPECTATION-IDENTITY\0\x02";
const BODY_IDENTITY_COUNT_V2: usize = 12;
const WIRE_PREFIX_BYTES_V2: usize = 16;
const METADATA_PREFIX_BYTES_V2: usize = 8;
const BODY_COUNT_BYTES_V2: u64 = 640;
const BODY_WRITE_BYTES_V2: u64 = 640;
const WIRE_ZEROING_BYTES_V2: u64 = 2 * 672;
const DIGEST_WRITE_BYTES_V2: u64 = 32;
const WIRE_COPY_BYTES_V2: u64 = 672;
const PROJECTION_FIXED_PASSES_V2: u64 = 4;
static ZERO_EXPECTATION_BODY_V2: [u8; STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2] =
    [0; STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2];

const _: () = assert!(STATIC_EXPECTATION_IDENTITY_DOMAIN_V2.len() == 43);
const _: () = assert!(
    WIRE_PREFIX_BYTES_V2 + (BODY_IDENTITY_COUNT_V2 * 32) + METADATA_PREFIX_BYTES_V2
        == STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2
);
const _: () = assert!(
    STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2 + METADATA_BYTES_V2
        == STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2
);
const _: () =
    assert!(STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2 + 32 == STATIC_COUNT_EXPECTATION_BYTES_V2);
const _: () = assert!(
    BODY_COUNT_BYTES_V2
        + BODY_WRITE_BYTES_V2
        + STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2
        == STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_TRAVERSED_V2
);
const _: () = assert!(
    STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_TRAVERSED_V2
        + WIRE_ZEROING_BYTES_V2
        + DIGEST_WRITE_BYTES_V2
        + WIRE_COPY_BYTES_V2
        + (PROJECTION_FIXED_PASSES_V2 * CANONICAL_TRAVERSAL_FIXED_WORK_V2)
        + IDENTITY_HASH_FINALIZE_WORK_V2
        == STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2
);

/// Strictly canonical and internally consistent, but still untrusted, bytes.
///
/// Identity fields remain byte arrays: inspection never manufactures trusted
/// compiler identity newtypes from an untrusted record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedStaticCountExpectationV2 {
    schema_version: u16,
    compiler_version: u16,
    image_schema_version: u16,
    manifest_identity: [u8; 32],
    policy_limits_identity: [u8; 32],
    semantic_binding_identity: [u8; 32],
    planning_receipt_identity: [u8; 32],
    live_literal_identity: [u8; 32],
    live_literal_bytes: u32,
    program_identity: [u8; 32],
    image_identity: [u8; 32],
    object_binding_identity: [u8; 32],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    receipt_identity: [u8; 32],
    resource_receipt_identity: [u8; 32],
    metadata: MetadataV2,
    metadata_bytes: [u8; METADATA_BYTES_V2],
    expectation_identity: [u8; 32],
}

macro_rules! claim_identity_getter {
    ($name:ident) => {
        #[must_use]
        pub const fn $name(&self) -> &[u8; 32] {
            &self.$name
        }
    };
}

impl ClaimedStaticCountExpectationV2 {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn compiler_version(&self) -> u16 {
        self.compiler_version
    }

    #[must_use]
    pub const fn image_schema_version(&self) -> u16 {
        self.image_schema_version
    }

    claim_identity_getter!(manifest_identity);
    claim_identity_getter!(policy_limits_identity);
    claim_identity_getter!(semantic_binding_identity);
    claim_identity_getter!(planning_receipt_identity);
    claim_identity_getter!(live_literal_identity);
    claim_identity_getter!(program_identity);
    claim_identity_getter!(image_identity);
    claim_identity_getter!(object_binding_identity);
    claim_identity_getter!(compile_identity);
    claim_identity_getter!(object_identity);
    claim_identity_getter!(receipt_identity);
    claim_identity_getter!(resource_receipt_identity);
    claim_identity_getter!(expectation_identity);

    #[must_use]
    pub const fn live_literal_bytes(&self) -> u32 {
        self.live_literal_bytes
    }

    #[must_use]
    pub const fn metadata(&self) -> MetadataV2 {
        self.metadata
    }

    #[must_use]
    pub const fn metadata_bytes_v2(&self) -> &[u8; METADATA_BYTES_V2] {
        &self.metadata_bytes
    }
}

/// Exact resource report for the fixed-width expectation projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticCountExpectationBuildReportV2 {
    pub(crate) canonical_bytes_hashed: u64,
    pub(crate) canonical_bytes_traversed: u64,
    pub(crate) canonical_count_passes: u8,
    pub(crate) canonical_hash_passes: u8,
    pub(crate) work_upper_bound: u64,
    pub(crate) scratch_bytes_upper_bound: u64,
    pub(crate) retained_bytes: usize,
    pub(crate) allocations: u8,
}

impl StaticCountExpectationBuildReportV2 {
    #[must_use]
    pub const fn identity_bytes_hashed(&self) -> u64 {
        self.canonical_bytes_hashed
    }

    #[must_use]
    pub const fn canonical_bytes_hashed(&self) -> u64 {
        self.canonical_bytes_hashed
    }

    #[must_use]
    pub const fn canonical_bytes_traversed(&self) -> u64 {
        self.canonical_bytes_traversed
    }

    #[must_use]
    pub const fn canonical_count_passes(&self) -> u8 {
        self.canonical_count_passes
    }

    #[must_use]
    pub const fn canonical_hash_passes(&self) -> u8 {
        self.canonical_hash_passes
    }

    #[must_use]
    pub const fn work_upper_bound(&self) -> u64 {
        self.work_upper_bound
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

    const fn current() -> Self {
        Self {
            canonical_bytes_hashed: STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2,
            canonical_bytes_traversed: STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_TRAVERSED_V2,
            canonical_count_passes: 1,
            canonical_hash_passes: 1,
            work_upper_bound: STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2,
            scratch_bytes_upper_bound: STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2,
            retained_bytes: STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V2,
            allocations: 0,
        }
    }
}

/// Trusted build-time projection of one compiler-sealed Count-v2 receipt.
///
/// The wire authenticates its own bytes. It remains an unsigned build result,
/// not linker evidence or runtime-adoption authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticCountExpectationV2 {
    manifest_identity: ManifestIdentity,
    policy_limits_identity: PolicyLimitsIdentity,
    semantic_binding_identity: AggregateCountExactLiteralAotSemanticBindingIdentity,
    planning_receipt_identity: AggregateCountExactLiteralAotPlanningReceiptIdentity,
    live_literal_identity: LiveLiteralIdentity,
    live_literal_bytes: u32,
    program_identity: AggregateProgramIdentity,
    image_identity: AotCountArtifactIdentityV2,
    object_binding_identity: BindingIdentity,
    compile_identity: CountCompileIdentityV2,
    object_identity: CountObjectIdentityV2,
    receipt_identity: CompileReceiptIdentity,
    resource_receipt_identity: ResourceReceiptIdentity,
    metadata: MetadataV2,
    expectation_identity: StaticCountExpectationIdentity,
    build_report: StaticCountExpectationBuildReportV2,
    wire: [u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
}

pub const STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V2: usize = size_of::<StaticCountExpectationV2>();

const BODY_WRITER_SCRATCH_BYTES_V2: usize = max_usize(
    size_of::<FixedWriter<'static>>(),
    METADATA_V2_WRITER_SCRATCH_BYTES,
);
const HASH_STATE_SCRATCH_BYTES_V2: usize = max_usize(size_of::<Sha256>(), 32);
const BODY_PHASE_SCRATCH_BYTES_V2: usize = STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V2
    + STATIC_COUNT_EXPECTATION_BYTES_V2
    + BODY_WRITER_SCRATCH_BYTES_V2;
const HASH_PHASE_SCRATCH_BYTES_V2: usize = STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V2
    + STATIC_COUNT_EXPECTATION_BYTES_V2
    + HASH_STATE_SCRATCH_BYTES_V2;
const PROJECTION_SCRATCH_BYTES_V2_USIZE: usize = max_usize(
    size_of::<CanonicalEncoder>(),
    max_usize(BODY_PHASE_SCRATCH_BYTES_V2, HASH_PHASE_SCRATCH_BYTES_V2),
);
const _: () = assert!(PROJECTION_SCRATCH_BYTES_V2_USIZE >= BODY_PHASE_SCRATCH_BYTES_V2);
const _: () = assert!(PROJECTION_SCRATCH_BYTES_V2_USIZE >= HASH_PHASE_SCRATCH_BYTES_V2);

#[allow(
    clippy::as_conversions,
    reason = "the compile-time assertion proves this exact usize layout fits the public u64 receipt"
)]
pub const STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2: u64 =
    PROJECTION_SCRATCH_BYTES_V2_USIZE as u64;

const _: () = assert!(size_of::<usize>() <= size_of::<u64>());

impl StaticCountExpectationV2 {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2
    }

    #[must_use]
    pub const fn compiler_version(&self) -> u16 {
        AOT_COMPILER_VERSION_V2
    }

    #[must_use]
    pub const fn image_schema_version(&self) -> u16 {
        AOT_COUNT_IMAGE_SCHEMA_VERSION_V2
    }

    #[must_use]
    pub const fn support(&self) -> AotCountBackendSupportV2 {
        AOT_COUNT_COMPILER_SUPPORT_V2
    }

    #[must_use]
    pub const fn manifest_identity(&self) -> ManifestIdentity {
        self.manifest_identity
    }

    #[must_use]
    pub const fn policy_limits_identity(&self) -> PolicyLimitsIdentity {
        self.policy_limits_identity
    }

    #[must_use]
    pub const fn semantic_binding_identity(
        &self,
    ) -> AggregateCountExactLiteralAotSemanticBindingIdentity {
        self.semantic_binding_identity
    }

    #[must_use]
    pub const fn planning_receipt_identity(
        &self,
    ) -> AggregateCountExactLiteralAotPlanningReceiptIdentity {
        self.planning_receipt_identity
    }

    #[must_use]
    pub const fn live_literal_identity(&self) -> LiveLiteralIdentity {
        self.live_literal_identity
    }

    #[must_use]
    pub const fn live_literal_bytes(&self) -> u32 {
        self.live_literal_bytes
    }

    #[must_use]
    pub const fn program_identity(&self) -> AggregateProgramIdentity {
        self.program_identity
    }

    #[must_use]
    pub const fn image_identity(&self) -> AotCountArtifactIdentityV2 {
        self.image_identity
    }

    #[must_use]
    pub const fn object_binding_identity(&self) -> BindingIdentity {
        self.object_binding_identity
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
    pub const fn receipt_identity(&self) -> CompileReceiptIdentity {
        self.receipt_identity
    }

    #[must_use]
    pub const fn resource_receipt_identity(&self) -> ResourceReceiptIdentity {
        self.resource_receipt_identity
    }

    #[must_use]
    pub const fn metadata(&self) -> MetadataV2 {
        self.metadata
    }

    #[must_use]
    pub const fn expectation_identity(&self) -> StaticCountExpectationIdentity {
        self.expectation_identity
    }

    #[must_use]
    pub const fn build_report(&self) -> StaticCountExpectationBuildReportV2 {
        self.build_report
    }

    #[must_use]
    pub fn metadata_bytes_v2(&self) -> &[u8; METADATA_BYTES_V2] {
        self.wire[STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2
            ..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2]
            .try_into()
            .expect("fixed Count-v2 expectation metadata range")
    }

    /// Borrow the once-built canonical wire without re-encoding or hashing.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; STATIC_COUNT_EXPECTATION_BYTES_V2] {
        &self.wire
    }

    #[must_use]
    pub fn claim(&self) -> ClaimedStaticCountExpectationV2 {
        ClaimedStaticCountExpectationV2 {
            schema_version: self.schema_version(),
            compiler_version: self.compiler_version(),
            image_schema_version: self.image_schema_version(),
            manifest_identity: *self.manifest_identity.as_bytes(),
            policy_limits_identity: *self.policy_limits_identity.as_bytes(),
            semantic_binding_identity: *self.semantic_binding_identity.as_bytes(),
            planning_receipt_identity: *self.planning_receipt_identity.as_bytes(),
            live_literal_identity: *self.live_literal_identity.as_bytes(),
            live_literal_bytes: self.live_literal_bytes,
            program_identity: *self.program_identity.as_bytes(),
            image_identity: *self.image_identity.as_bytes(),
            object_binding_identity: *self.object_binding_identity.as_bytes(),
            compile_identity: *self.compile_identity.as_bytes(),
            object_identity: *self.object_identity.as_bytes(),
            receipt_identity: *self.receipt_identity.as_bytes(),
            resource_receipt_identity: *self.resource_receipt_identity.as_bytes(),
            metadata: self.metadata,
            metadata_bytes: *self.metadata_bytes_v2(),
            expectation_identity: *self.expectation_identity.as_bytes(),
        }
    }

    /// Compare every inspected byte claim with the trusted compiler result.
    #[must_use]
    pub fn authenticates_claim(&self, claim: &ClaimedStaticCountExpectationV2) -> bool {
        self.authenticates_itself() && self.matches_claim(claim)
    }

    #[must_use]
    pub fn authenticates_itself(&self) -> bool {
        self.build_report == StaticCountExpectationBuildReportV2::current()
            && inspect_static_count_expectation_v2(&self.wire)
                .is_ok_and(|claim| self.matches_claim(&claim))
    }

    fn matches_claim(&self, claim: &ClaimedStaticCountExpectationV2) -> bool {
        claim.schema_version == self.schema_version()
            && claim.compiler_version == self.compiler_version()
            && claim.image_schema_version == self.image_schema_version()
            && claim.manifest_identity == *self.manifest_identity.as_bytes()
            && claim.policy_limits_identity == *self.policy_limits_identity.as_bytes()
            && claim.semantic_binding_identity == *self.semantic_binding_identity.as_bytes()
            && claim.planning_receipt_identity == *self.planning_receipt_identity.as_bytes()
            && claim.live_literal_identity == *self.live_literal_identity.as_bytes()
            && claim.live_literal_bytes == self.live_literal_bytes
            && claim.program_identity == *self.program_identity.as_bytes()
            && claim.image_identity == *self.image_identity.as_bytes()
            && claim.object_binding_identity == *self.object_binding_identity.as_bytes()
            && claim.compile_identity == *self.compile_identity.as_bytes()
            && claim.object_identity == *self.object_identity.as_bytes()
            && claim.receipt_identity == *self.receipt_identity.as_bytes()
            && claim.resource_receipt_identity == *self.resource_receipt_identity.as_bytes()
            && claim.metadata == self.metadata
            && claim.metadata_bytes == *self.metadata_bytes_v2()
            && claim.expectation_identity == *self.expectation_identity.as_bytes()
    }
}

/// Strictly inspect arbitrary bytes for the fixed Count-v2 expectation shape.
///
/// Success proves canonical structure and internal integrity only. Runtime
/// adoption remains disabled and requires separate trusted provenance.
pub fn inspect_static_count_expectation_v2(
    bytes: &[u8],
) -> Result<ClaimedStaticCountExpectationV2, StaticCountExpectationError> {
    if bytes.len() != STATIC_COUNT_EXPECTATION_BYTES_V2 {
        return Err(invalid("expectation record bytes"));
    }
    let mut reader = FixedReader::new(bytes);
    reader.expect(&STATIC_EXPECTATION_MAGIC_V2, "expectation domain")?;
    let schema_version = reader.u16("expectation schema")?;
    let compiler_version = reader.u16("compiler version")?;
    if schema_version != AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2
        || compiler_version != AOT_COMPILER_VERSION_V2
        || reader.u32("expectation record bytes")?
            != u32::try_from(STATIC_COUNT_EXPECTATION_BYTES_V2)
                .map_err(|_| invalid("expectation record bytes"))?
    {
        return Err(invalid("expectation header"));
    }
    let manifest_identity = reader.array("manifest identity")?;
    let policy_limits_identity = reader.array("policy limits identity")?;
    let semantic_binding_identity = reader.array("semantic binding identity")?;
    let planning_receipt_identity = reader.array("planning receipt identity")?;
    let live_literal_identity = reader.array("live literal identity")?;
    let program_identity = reader.array("program identity")?;
    let image_identity = reader.array("image identity")?;
    let object_binding_identity = reader.array("object binding identity")?;
    let compile_identity = reader.array("compile identity")?;
    let object_identity = reader.array("object identity")?;
    let receipt_identity = reader.array("compile receipt identity")?;
    let resource_receipt_identity = reader.array("resource receipt identity")?;
    let live_literal_bytes = reader.u32("live literal bytes")?;
    let metadata_record_bytes = reader.u16("metadata record bytes")?;
    let image_schema_version = reader.u16("image schema version")?;
    if usize::from(metadata_record_bytes) != METADATA_BYTES_V2
        || image_schema_version != AOT_COUNT_IMAGE_SCHEMA_VERSION_V2
        || reader.position() != STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2
    {
        return Err(invalid("metadata envelope"));
    }
    let metadata_bytes = reader.array("metadata")?;
    let metadata =
        MetadataV2::decode_canonical(&metadata_bytes).map_err(|_| invalid("metadata contract"))?;
    if reader.position() != STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2 {
        return Err(invalid("expectation identity offset"));
    }
    let claimed_expectation_identity = reader.array("expectation identity")?;
    if reader.position() != STATIC_COUNT_EXPECTATION_BYTES_V2
        || expectation_identity(
            bytes
                .get(..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2)
                .ok_or_else(|| invalid("expectation identity body"))?,
        )
        .as_bytes()
            != &claimed_expectation_identity
    {
        return Err(invalid("expectation identity"));
    }
    validate_claimed_metadata(
        metadata,
        live_literal_bytes,
        &program_identity,
        &image_identity,
        &object_binding_identity,
        &compile_identity,
    )?;
    Ok(ClaimedStaticCountExpectationV2 {
        schema_version,
        compiler_version,
        image_schema_version,
        manifest_identity,
        policy_limits_identity,
        semantic_binding_identity,
        planning_receipt_identity,
        live_literal_identity,
        live_literal_bytes,
        program_identity,
        image_identity,
        object_binding_identity,
        compile_identity,
        object_identity,
        receipt_identity,
        resource_receipt_identity,
        metadata,
        metadata_bytes,
        expectation_identity: claimed_expectation_identity,
    })
}

/// Count the fixed body before receipt sealing. No receipt identity is read:
/// both authenticated receipt identities are copied only from sealed typestate.
pub(crate) fn prospective_static_count_expectation_v2()
-> Result<StaticCountExpectationBuildReportV2, CanonicalError> {
    let mut encoder = CanonicalEncoder::counting();
    encoder.raw(&ZERO_EXPECTATION_BODY_V2)?;
    if encoder.bytes_written() != BODY_COUNT_BYTES_V2 {
        return Err(CanonicalError::ByteCountOverflow);
    }
    Ok(StaticCountExpectationBuildReportV2::current())
}

pub(crate) fn build_static_count_expectation_v2(
    sealed_receipt: &SealedCompileReceiptV2,
    expected_report: StaticCountExpectationBuildReportV2,
) -> Result<StaticCountExpectationV2, StaticCountExpectationError> {
    let build_report = StaticCountExpectationBuildReportV2::current();
    if build_report != expected_report
        || build_report
            != sealed_receipt
                .receipt()
                .accounting()
                .static_expectation_build()
    {
        return Err(StaticCountExpectationError::IdentityEncoding);
    }
    let receipt = sealed_receipt.receipt();
    let mut expectation = StaticCountExpectationV2 {
        manifest_identity: receipt.manifest_identity(),
        policy_limits_identity: receipt.manifest().policy_limits_identity(),
        semantic_binding_identity: receipt.semantic_binding_identity(),
        planning_receipt_identity: receipt.planning_receipt_identity(),
        live_literal_identity: receipt.live_literal_identity(),
        live_literal_bytes: receipt.live_literal_bytes(),
        program_identity: receipt.program_identity(),
        image_identity: receipt.image_identity(),
        object_binding_identity: receipt.object_binding_identity(),
        compile_identity: receipt.compile_identity(),
        object_identity: receipt.object_identity(),
        receipt_identity: sealed_receipt.receipt_identity(),
        resource_receipt_identity: sealed_receipt.resource_receipt_identity(),
        metadata: receipt.metadata(),
        expectation_identity: StaticCountExpectationIdentity::new([0; 32]),
        build_report,
        wire: [0; STATIC_COUNT_EXPECTATION_BYTES_V2],
    };
    let mut wire = [0_u8; STATIC_COUNT_EXPECTATION_BYTES_V2];
    encode_expectation_body(&expectation, &mut wire)?;
    expectation.expectation_identity = expectation_identity(
        wire.get(..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2)
            .ok_or_else(|| invalid("expectation identity body"))?,
    );
    wire[STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2..]
        .copy_from_slice(expectation.expectation_identity.as_bytes());
    expectation.wire.copy_from_slice(&wire);
    Ok(expectation)
}

fn encode_expectation_body(
    expectation: &StaticCountExpectationV2,
    wire: &mut [u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
) -> Result<(), StaticCountExpectationError> {
    {
        let mut writer = FixedWriter::new(wire);
        writer.raw(&STATIC_EXPECTATION_MAGIC_V2);
        writer.u16(AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2);
        writer.u16(AOT_COMPILER_VERSION_V2);
        writer.u32(
            u32::try_from(STATIC_COUNT_EXPECTATION_BYTES_V2)
                .expect("fixed Count-v2 expectation length fits u32"),
        );
        for identity in [
            expectation.manifest_identity.as_bytes(),
            expectation.policy_limits_identity.as_bytes(),
            expectation.semantic_binding_identity.as_bytes(),
            expectation.planning_receipt_identity.as_bytes(),
            expectation.live_literal_identity.as_bytes(),
            expectation.program_identity.as_bytes(),
            expectation.image_identity.as_bytes(),
            expectation.object_binding_identity.as_bytes(),
            expectation.compile_identity.as_bytes(),
            expectation.object_identity.as_bytes(),
            expectation.receipt_identity.as_bytes(),
            expectation.resource_receipt_identity.as_bytes(),
        ] {
            writer.raw(identity);
        }
        writer.u32(expectation.live_literal_bytes);
        writer.u16(u16::try_from(METADATA_BYTES_V2).expect("metadata length fits u16"));
        writer.u16(AOT_COUNT_IMAGE_SCHEMA_VERSION_V2);
        if writer.position() != STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2 {
            return Err(invalid("expectation metadata offset"));
        }
    }
    let metadata_destination: &mut [u8; METADATA_BYTES_V2] = wire
        .get_mut(
            STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2
                ..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2,
        )
        .ok_or_else(|| invalid("expectation metadata range"))?
        .try_into()
        .map_err(|_| invalid("expectation metadata range"))?;
    expectation
        .metadata
        .write_canonical_into(metadata_destination)
        .map_err(|_| invalid("metadata encoding"))
}

fn validate_claimed_metadata(
    metadata: MetadataV2,
    live_literal_bytes: u32,
    program_identity: &[u8; 32],
    image_identity: &[u8; 32],
    object_binding_identity: &[u8; 32],
    compile_identity: &[u8; 32],
) -> Result<(), StaticCountExpectationError> {
    let support = AOT_COUNT_COMPILER_SUPPORT_V2;
    let expected_actual_features = if live_literal_bytes == 0 {
        AotCountCpuFeatures::NONE
    } else {
        AotCountCpuFeatures::ASIMD
    };
    if !is_supported_aot_count_backend_tuple_v2(support)
        || metadata.backend_version() != support.backend_version.0
        || metadata.algorithm_version() != support.algorithm_version
        || metadata.kir_semantics_version() != support.kir_semantics_version
        || metadata.kir_abi_version() != support.kir_abi_version
        || metadata.output_kind() != support.output_kind
        || metadata.architecture() != support.architecture
        || metadata.little_endian() != support.little_endian
        || metadata.pointer_width() != support.pointer_width
        || metadata.target_abi() != support.target_abi
        || metadata.allowed_features() != support.allowed_features.bits()
        || metadata.max_literal_bytes() != support.max_literal_bytes
        || metadata.actual_features() != expected_actual_features.bits()
        || metadata.literal_bytes() != live_literal_bytes
        || usize::try_from(live_literal_bytes)
            .map_or(true, |bytes| bytes > MAX_EXACT_AGGREGATE_LITERAL_BYTES)
        || metadata.source_identity() != program_identity
        || metadata.artifact_identity() != image_identity
        || metadata.claimed_binding_identity().as_bytes() != object_binding_identity
        || metadata.claimed_compile_identity().as_bytes() != compile_identity
    {
        return Err(invalid("metadata expectation binding"));
    }
    Ok(())
}

fn expectation_identity(body: &[u8]) -> StaticCountExpectationIdentity {
    #[cfg(test)]
    expectation_identity_trace::record();
    let mut hasher = Sha256::new();
    hasher.update(STATIC_EXPECTATION_IDENTITY_DOMAIN_V2);
    hasher.update(body);
    StaticCountExpectationIdentity::new(hasher.finalize().into())
}

const fn max_usize(left: usize, right: usize) -> usize {
    if left >= right { left } else { right }
}

struct FixedWriter<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> FixedWriter<'a> {
    const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn raw(&mut self, value: &[u8]) {
        let end = self
            .position
            .checked_add(value.len())
            .expect("fixed writer");
        self.bytes[self.position..end].copy_from_slice(value);
        self.position = end;
    }

    fn u16(&mut self, value: u16) {
        self.raw(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.raw(&value.to_le_bytes());
    }

    const fn position(&self) -> usize {
        self.position
    }
}

struct FixedReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> FixedReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn array<const N: usize>(
        &mut self,
        at: &'static str,
    ) -> Result<[u8; N], StaticCountExpectationError> {
        let end = self.position.checked_add(N).ok_or_else(|| invalid(at))?;
        let source = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid(at))?;
        let mut value = [0_u8; N];
        value.copy_from_slice(source);
        self.position = end;
        Ok(value)
    }

    fn expect(
        &mut self,
        expected: &[u8],
        at: &'static str,
    ) -> Result<(), StaticCountExpectationError> {
        let end = self
            .position
            .checked_add(expected.len())
            .ok_or_else(|| invalid(at))?;
        if self.bytes.get(self.position..end) != Some(expected) {
            return Err(invalid(at));
        }
        self.position = end;
        Ok(())
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, StaticCountExpectationError> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, StaticCountExpectationError> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    const fn position(&self) -> usize {
        self.position
    }
}

const fn invalid(at: &'static str) -> StaticCountExpectationError {
    StaticCountExpectationError::InvalidWire { at }
}

impl fmt::Display for StaticCountExpectationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.expectation_identity)
    }
}

#[cfg(test)]
mod tests {
    use fre::RustProfile;

    use super::{
        ClaimedStaticCountExpectationV2, PROJECTION_SCRATCH_BYTES_V2_USIZE,
        STATIC_COUNT_EXPECTATION_BYTES_V2,
        STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2,
        STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_TRAVERSED_V2,
        STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2, STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2,
        STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2,
        STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2,
        STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V2, StaticCountExpectationV2, expectation_identity,
        inspect_static_count_expectation_v2,
    };
    use crate::{MacosAarch64CountManifestV2, plan_and_compile_macos_aarch64_count_v2};

    fn compile_expectation(pattern: &str) -> StaticCountExpectationV2 {
        let mut profile = RustProfile::default();
        profile.options.unicode = false;
        *plan_and_compile_macos_aarch64_count_v2(
            MacosAarch64CountManifestV2::default(),
            pattern.as_bytes().to_vec(),
            profile,
        )
        .expect("fixed Count-v2 expectation")
        .static_count_expectation()
    }

    fn reseal(wire: &mut [u8; STATIC_COUNT_EXPECTATION_BYTES_V2]) {
        let identity = expectation_identity(&wire[..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2]);
        wire[STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2..].copy_from_slice(identity.as_bytes());
    }

    fn inspect_resealed(
        mut wire: [u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
    ) -> (
        [u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
        Result<ClaimedStaticCountExpectationV2, crate::StaticCountExpectationError>,
    ) {
        reseal(&mut wire);
        let claim = inspect_static_count_expectation_v2(&wire);
        (wire, claim)
    }

    #[test]
    fn fixed_wire_offsets_round_trip_all_literal_width_boundaries() {
        for pattern in [
            "",
            "x",
            "0123456789abcdef",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ] {
            let expectation = compile_expectation(pattern);
            let wire = expectation.as_bytes();
            assert_eq!(wire.len(), 672);
            assert_eq!(&wire[..8], b"FRESCEX\x02");
            assert_eq!(&wire[8..10], &2_u16.to_le_bytes());
            assert_eq!(&wire[10..12], &2_u16.to_le_bytes());
            assert_eq!(&wire[12..16], &672_u32.to_le_bytes());
            assert_eq!(&wire[16..48], expectation.manifest_identity().as_bytes());
            assert_eq!(
                &wire[48..80],
                expectation.policy_limits_identity().as_bytes()
            );
            assert_eq!(
                &wire[80..112],
                expectation.semantic_binding_identity().as_bytes()
            );
            assert_eq!(
                &wire[112..144],
                expectation.planning_receipt_identity().as_bytes()
            );
            assert_eq!(
                &wire[144..176],
                expectation.live_literal_identity().as_bytes()
            );
            assert_eq!(&wire[176..208], expectation.program_identity().as_bytes());
            assert_eq!(&wire[208..240], expectation.image_identity().as_bytes());
            assert_eq!(
                &wire[240..272],
                expectation.object_binding_identity().as_bytes()
            );
            assert_eq!(&wire[272..304], expectation.compile_identity().as_bytes());
            assert_eq!(&wire[304..336], expectation.object_identity().as_bytes());
            assert_eq!(&wire[336..368], expectation.receipt_identity().as_bytes());
            assert_eq!(
                &wire[368..400],
                expectation.resource_receipt_identity().as_bytes()
            );
            assert_eq!(
                &wire[400..404],
                &expectation.live_literal_bytes().to_le_bytes()
            );
            assert_eq!(&wire[404..406], &232_u16.to_le_bytes());
            assert_eq!(&wire[406..408], &2_u16.to_le_bytes());
            assert_eq!(
                &wire[STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2
                    ..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2],
                expectation.metadata().canonical_bytes().unwrap().as_slice()
            );
            assert_eq!(
                expectation.metadata_bytes_v2(),
                &wire[STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2
                    ..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2]
            );
            let claim = inspect_static_count_expectation_v2(wire).unwrap();
            assert_eq!(claim.metadata_bytes_v2(), expectation.metadata_bytes_v2());
            assert_eq!(
                claim.program_identity(),
                expectation.program_identity().as_bytes()
            );
            assert!(expectation.authenticates_claim(&claim));
        }
    }

    #[test]
    fn exact_projection_report_and_derived_two_wire_scratch_are_frozen() {
        let expectation = compile_expectation("accounting");
        let report = expectation.build_report();
        assert_eq!(STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V2, 1_376);
        assert_eq!(
            STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2,
            2_160
        );
        assert_eq!(
            usize::try_from(STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2).unwrap(),
            PROJECTION_SCRATCH_BYTES_V2_USIZE
        );
        assert_eq!(
            report.canonical_bytes_hashed(),
            STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V2
        );
        assert_eq!(report.canonical_bytes_hashed(), 683);
        assert_eq!(
            report.canonical_bytes_traversed(),
            STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_TRAVERSED_V2
        );
        assert_eq!(report.canonical_bytes_traversed(), 1_963);
        assert_eq!(report.canonical_count_passes(), 1);
        assert_eq!(report.canonical_hash_passes(), 1);
        assert_eq!(
            report.work_upper_bound(),
            STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2
        );
        assert_eq!(report.work_upper_bound(), 4_083);
        assert_eq!(
            report.scratch_bytes_upper_bound(),
            STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V2
        );
        assert_eq!(
            report.retained_bytes(),
            STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V2
        );
        assert_eq!(report.allocations(), 0);
    }

    #[test]
    fn every_unresealed_wire_byte_mutation_and_wrong_length_is_rejected() {
        let expectation = compile_expectation("wire-mutation");
        let original = *expectation.as_bytes();
        for index in 0..STATIC_COUNT_EXPECTATION_BYTES_V2 {
            let mut changed = original;
            changed[index] ^= 1;
            assert!(
                inspect_static_count_expectation_v2(&changed).is_err(),
                "unresealed mutation at byte {index}"
            );
        }
        assert!(inspect_static_count_expectation_v2(&original[..671]).is_err());
        let mut too_long = [0_u8; 673];
        too_long[..672].copy_from_slice(&original);
        assert!(inspect_static_count_expectation_v2(&too_long).is_err());
    }

    #[test]
    fn resealed_opaque_mutations_remain_untrusted_and_cross_bindings_refuse() {
        let expectation = compile_expectation("cross-bindings");
        let original = *expectation.as_bytes();

        for offset in [16, 48, 80, 112, 144, 304, 336, 368] {
            let mut changed = original;
            changed[offset] ^= 1;
            let (_wire, claim) = inspect_resealed(changed);
            let claim = claim.expect("opaque identity remains structurally inspectable");
            assert!(!expectation.authenticates_claim(&claim));
        }

        for offset in [176, 208, 240, 272, 400] {
            let mut changed = original;
            changed[offset] ^= 1;
            let (_wire, claim) = inspect_resealed(changed);
            assert!(claim.is_err(), "cross-binding mutation at offset {offset}");
        }

        for (offset, stale) in [(8, 1_u16), (406, 1_u16)] {
            let mut changed = original;
            changed[offset..offset + 2].copy_from_slice(&stale.to_le_bytes());
            let (_wire, claim) = inspect_resealed(changed);
            assert!(claim.is_err(), "stale schema at offset {offset}");
        }
        let mut stale_algorithm = original;
        let algorithm_offset = STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2 + 14;
        stale_algorithm[algorithm_offset..algorithm_offset + 2]
            .copy_from_slice(&3_u16.to_le_bytes());
        let (_wire, claim) = inspect_resealed(stale_algorithm);
        assert!(claim.is_err(), "stale algorithm 3 must never inspect");
    }

    #[test]
    fn every_metadata_field_mutation_is_rejected_or_fails_trusted_comparison() {
        let expectation = compile_expectation("metadata-mutation");
        let original = *expectation.as_bytes();
        let metadata_field_offsets = [
            0, 8, 10, 12, 14, 16, 18, 20, 22, 24, 25, 26, 27, 28, 29, 30, 31, 32, 40, 48, 52, 56,
            60, 64, 68, 72, 104, 136, 168, 200,
        ];
        for field_offset in metadata_field_offsets {
            let mut changed = original;
            changed[STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2 + field_offset] ^= 1;
            let (_wire, inspected) = inspect_resealed(changed);
            if let Ok(claim) = inspected {
                assert!(
                    !expectation.authenticates_claim(&claim),
                    "metadata field at offset {field_offset} cannot authenticate"
                );
            }
        }

        let mut payload_digest = original;
        payload_digest[STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2 + 168] ^= 1;
        let (_wire, inspected) = inspect_resealed(payload_digest);
        let claim = inspected.expect("opaque payload digest remains structurally valid");
        assert!(!expectation.authenticates_claim(&claim));
    }

    #[test]
    fn every_projection_report_field_is_part_of_trusted_self_authentication() {
        let original = compile_expectation("report-binding");
        assert!(original.authenticates_itself());
        macro_rules! mutate_report {
            ($field:ident) => {{
                let mut changed = original;
                changed.build_report.$field = changed.build_report.$field.checked_add(1).unwrap();
                assert!(!changed.authenticates_itself());
                assert!(!changed.authenticates_claim(&changed.claim()));
            }};
        }
        mutate_report!(canonical_bytes_hashed);
        mutate_report!(canonical_bytes_traversed);
        mutate_report!(canonical_count_passes);
        mutate_report!(canonical_hash_passes);
        mutate_report!(work_upper_bound);
        mutate_report!(scratch_bytes_upper_bound);
        mutate_report!(retained_bytes);
        mutate_report!(allocations);
    }
}

#[cfg(test)]
pub(crate) mod expectation_identity_trace {
    use std::cell::Cell;

    std::thread_local! {
        static HASH_PASSES: Cell<u64> = const { Cell::new(0) };
    }

    pub(crate) fn record() {
        HASH_PASSES.with(|passes| passes.set(passes.get().saturating_add(1)));
    }

    pub(crate) fn reset() {
        HASH_PASSES.with(|passes| passes.set(0));
    }

    pub(crate) fn passes() -> u64 {
        HASH_PASSES.with(Cell::get)
    }
}
