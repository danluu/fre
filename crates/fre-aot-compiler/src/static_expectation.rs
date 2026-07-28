use core::{fmt, mem::size_of};

use fre::{
    AggregateCountExactLiteralAotPlanningReceiptIdentity,
    AggregateCountExactLiteralAotSemanticBindingIdentity,
};
use fre_aot_macho::{
    AbiKind, BindingIdentity, CALL_ABI_SCHEMA_V1, CompileIdentity, ENTRY_OFFSET_V1,
    METADATA_BYTES_V1, METADATA_VERSION, MetadataV1, ObjectIdentity, PLATFORM_MACOS,
    STATUS_BITS_V1,
};
use fre_jit_aarch64::{ArtifactIdentity, CpuFeatures};
use fre_kernel_ir::{AggregateProgramIdentity, MAX_EXACT_AGGREGATE_LITERAL_BYTES};
use sha2::{Digest, Sha256};

use crate::{
    canonical::{CanonicalEncoder, CanonicalError},
    identity::{
        CompileReceiptIdentity, LiveLiteralIdentity, ManifestIdentity, PolicyLimitsIdentity,
        ResourceReceiptIdentity, StaticCountExpectationIdentity,
    },
    manifest::{
        AOT_AGGREGATE_BACKEND_VERSION_V1, AOT_COMPILER_VERSION_V1, MacosAarch64CountManifestV1,
        encode_emit_limits, encode_object_limits, encode_validate_limits,
    },
    receipt::{CompileReceiptV1, encode_accounting},
};

pub const STATIC_COUNT_EXPECTATION_SCHEMA_VERSION_V1: u16 = 1;
pub const STATIC_COUNT_EXPECTATION_BYTES_V1: usize = 656;
/// Combined policy, resource-receipt, and self-identity canonical-byte ceiling.
pub const STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V1: u64 = 16 << 10;
pub const STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V1: u64 =
    (STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V1 * 2) + 4_096;
pub const STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V1: u64 = 256;

const STATIC_EXPECTATION_MAGIC: [u8; 8] = *b"FRESCEX\x01";
const STATIC_EXPECTATION_IDENTITY_DOMAIN: &[u8] =
    b"FRE-AOT-STATIC-COUNT-EXPECTATION-IDENTITY\0\x01";
const POLICY_LIMITS_DOMAIN: &[u8] = b"FRE-AOT-COMPILER-POLICY-LIMITS\0\x01";
const RESOURCE_RECEIPT_DOMAIN: &[u8] = b"FRE-AOT-COMPILER-RESOURCE-RECEIPT\0\x01";
const BODY_IDENTITY_COUNT: usize = 12;
const WIRE_PREFIX_BYTES: usize = 16;
const METADATA_PREFIX_BYTES: usize = 8;
const EXPECTATION_METADATA_OFFSET: usize =
    WIRE_PREFIX_BYTES + (BODY_IDENTITY_COUNT * 32) + METADATA_PREFIX_BYTES;
const EXPECTATION_IDENTITY_OFFSET: usize = EXPECTATION_METADATA_OFFSET + METADATA_BYTES_V1;

const _: () = assert!(EXPECTATION_IDENTITY_OFFSET + 32 == STATIC_COUNT_EXPECTATION_BYTES_V1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticCountExpectationError {
    IdentityEncoding,
    InvalidWire { at: &'static str },
}

impl fmt::Display for StaticCountExpectationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid static count expectation: {self:?}")
    }
}

impl std::error::Error for StaticCountExpectationError {}

/// Separate bounded receipt for post-compile expectation projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticCountExpectationBuildReportV1 {
    canonical_bytes_hashed: u64,
    work_upper_bound: u64,
    scratch_bytes_upper_bound: u64,
    retained_bytes: usize,
    allocations: u8,
}

impl StaticCountExpectationBuildReportV1 {
    #[must_use]
    pub const fn canonical_bytes_hashed(&self) -> u64 {
        self.canonical_bytes_hashed
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
}

/// Trusted build-time projection of one compiler-sealed count receipt.
///
/// Private construction proves atomic projection from a trusted receipt. The
/// self-identity is bounded wire integrity, never cross-process provenance;
/// only trusted build/signing policy may authorize runtime adoption.
#[derive(Debug, Eq, PartialEq)]
pub struct StaticCountExpectationV1 {
    manifest_identity: ManifestIdentity,
    policy_limits_identity: PolicyLimitsIdentity,
    semantic_binding_identity: AggregateCountExactLiteralAotSemanticBindingIdentity,
    planning_receipt_identity: AggregateCountExactLiteralAotPlanningReceiptIdentity,
    live_literal_identity: LiveLiteralIdentity,
    live_literal_bytes: u32,
    kir_identity: AggregateProgramIdentity,
    native_artifact_identity: ArtifactIdentity,
    object_binding_identity: BindingIdentity,
    compile_identity: CompileIdentity,
    object_identity: ObjectIdentity,
    receipt_identity: CompileReceiptIdentity,
    resource_receipt_identity: ResourceReceiptIdentity,
    metadata: MetadataV1,
    expectation_identity: StaticCountExpectationIdentity,
    build_report: StaticCountExpectationBuildReportV1,
    wire: [u8; STATIC_COUNT_EXPECTATION_BYTES_V1],
}

/// Complete inline retained trusted expectation, including its cached wire.
pub const STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V1: usize = size_of::<StaticCountExpectationV1>();

impl StaticCountExpectationV1 {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        STATIC_COUNT_EXPECTATION_SCHEMA_VERSION_V1
    }

    #[must_use]
    pub const fn compiler_version(&self) -> u16 {
        AOT_COMPILER_VERSION_V1
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
    pub const fn kir_identity(&self) -> AggregateProgramIdentity {
        self.kir_identity
    }

    #[must_use]
    pub const fn native_artifact_identity(&self) -> ArtifactIdentity {
        self.native_artifact_identity
    }

    #[must_use]
    pub const fn object_binding_identity(&self) -> BindingIdentity {
        self.object_binding_identity
    }

    #[must_use]
    pub const fn compile_identity(&self) -> CompileIdentity {
        self.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> ObjectIdentity {
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
    pub const fn metadata(&self) -> MetadataV1 {
        self.metadata
    }

    #[must_use]
    pub const fn expectation_identity(&self) -> StaticCountExpectationIdentity {
        self.expectation_identity
    }

    #[must_use]
    pub const fn build_report(&self) -> StaticCountExpectationBuildReportV1 {
        self.build_report
    }

    #[must_use]
    pub fn metadata_bytes_v1(&self) -> &[u8; METADATA_BYTES_V1] {
        self.wire[EXPECTATION_METADATA_OFFSET..EXPECTATION_METADATA_OFFSET + METADATA_BYTES_V1]
            .try_into()
            .expect("fixed expectation metadata range has canonical length")
    }

    /// Borrow the once-built canonical wire without re-encoding or hashing.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; STATIC_COUNT_EXPECTATION_BYTES_V1] {
        &self.wire
    }

    #[must_use]
    pub fn authenticates_claim(&self, claim: &ClaimedStaticCountExpectationV1) -> bool {
        claim.schema_version == STATIC_COUNT_EXPECTATION_SCHEMA_VERSION_V1
            && claim.compiler_version == AOT_COMPILER_VERSION_V1
            && claim.manifest_identity == *self.manifest_identity.as_bytes()
            && claim.policy_limits_identity == *self.policy_limits_identity.as_bytes()
            && claim.semantic_binding_identity == *self.semantic_binding_identity.as_bytes()
            && claim.planning_receipt_identity == *self.planning_receipt_identity.as_bytes()
            && claim.live_literal_identity == *self.live_literal_identity.as_bytes()
            && claim.live_literal_bytes == self.live_literal_bytes
            && claim.kir_identity == *self.kir_identity.as_bytes()
            && claim.native_artifact_identity == *self.native_artifact_identity.as_bytes()
            && claim.object_binding_identity == *self.object_binding_identity.as_bytes()
            && claim.compile_identity == *self.compile_identity.as_bytes()
            && claim.object_identity == *self.object_identity.as_bytes()
            && claim.receipt_identity == *self.receipt_identity.as_bytes()
            && claim.resource_receipt_identity == *self.resource_receipt_identity.as_bytes()
            && claim.metadata_bytes == *self.metadata_bytes_v1()
            && claim.expectation_identity == *self.expectation_identity.as_bytes()
    }
}

/// Strictly canonical and internally consistent, but still untrusted, bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedStaticCountExpectationV1 {
    schema_version: u16,
    compiler_version: u16,
    manifest_identity: [u8; 32],
    policy_limits_identity: [u8; 32],
    semantic_binding_identity: [u8; 32],
    planning_receipt_identity: [u8; 32],
    live_literal_identity: [u8; 32],
    live_literal_bytes: u32,
    kir_identity: [u8; 32],
    native_artifact_identity: [u8; 32],
    object_binding_identity: [u8; 32],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    receipt_identity: [u8; 32],
    resource_receipt_identity: [u8; 32],
    metadata_bytes: [u8; METADATA_BYTES_V1],
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

impl ClaimedStaticCountExpectationV1 {
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn compiler_version(&self) -> u16 {
        self.compiler_version
    }

    claim_identity_getter!(manifest_identity);
    claim_identity_getter!(policy_limits_identity);
    claim_identity_getter!(semantic_binding_identity);
    claim_identity_getter!(planning_receipt_identity);
    claim_identity_getter!(live_literal_identity);
    claim_identity_getter!(kir_identity);
    claim_identity_getter!(native_artifact_identity);
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
    pub const fn metadata_bytes_v1(&self) -> &[u8; METADATA_BYTES_V1] {
        &self.metadata_bytes
    }
}

pub fn inspect_static_count_expectation_v1(
    bytes: &[u8; STATIC_COUNT_EXPECTATION_BYTES_V1],
) -> Result<ClaimedStaticCountExpectationV1, StaticCountExpectationError> {
    let mut reader = FixedReader::new(bytes);
    reader.expect(&STATIC_EXPECTATION_MAGIC, "expectation domain")?;
    let schema_version = reader.u16("expectation schema")?;
    let compiler_version = reader.u16("compiler version")?;
    if schema_version != STATIC_COUNT_EXPECTATION_SCHEMA_VERSION_V1
        || compiler_version != AOT_COMPILER_VERSION_V1
        || reader.u32("expectation record bytes")?
            != u32::try_from(STATIC_COUNT_EXPECTATION_BYTES_V1)
                .map_err(|_| invalid("expectation record bytes"))?
    {
        return Err(invalid("expectation header"));
    }
    let manifest_identity = reader.array("manifest identity")?;
    let policy_limits_identity = reader.array("policy limits identity")?;
    let semantic_binding_identity = reader.array("semantic binding identity")?;
    let planning_receipt_identity = reader.array("planning receipt identity")?;
    let live_literal_identity = reader.array("live literal identity")?;
    let kir_identity = reader.array("KIR identity")?;
    let native_artifact_identity = reader.array("native artifact identity")?;
    let object_binding_identity = reader.array("object binding identity")?;
    let compile_identity = reader.array("compile identity")?;
    let object_identity = reader.array("object identity")?;
    let receipt_identity = reader.array("receipt identity")?;
    let resource_receipt_identity = reader.array("resource receipt identity")?;
    let live_literal_bytes = reader.u32("live literal bytes")?;
    if reader.u16("metadata record bytes")?
        != u16::try_from(METADATA_BYTES_V1).map_err(|_| invalid("metadata record bytes"))?
        || reader.u16("expectation reserved")? != 0
    {
        return Err(invalid("metadata envelope"));
    }
    let metadata_bytes = reader.array("metadata")?;
    if reader.position() != EXPECTATION_IDENTITY_OFFSET {
        return Err(invalid("expectation identity offset"));
    }
    let claimed_expectation_identity = reader.array("expectation identity")?;
    if reader.position() != STATIC_COUNT_EXPECTATION_BYTES_V1
        || expectation_identity(&bytes[..EXPECTATION_IDENTITY_OFFSET]).as_bytes()
            != &claimed_expectation_identity
    {
        return Err(invalid("expectation identity"));
    }
    validate_claimed_metadata(
        &metadata_bytes,
        live_literal_bytes,
        &kir_identity,
        &native_artifact_identity,
        &object_binding_identity,
        &compile_identity,
    )?;
    Ok(ClaimedStaticCountExpectationV1 {
        schema_version,
        compiler_version,
        manifest_identity,
        policy_limits_identity,
        semantic_binding_identity,
        planning_receipt_identity,
        live_literal_identity,
        live_literal_bytes,
        kir_identity,
        native_artifact_identity,
        object_binding_identity,
        compile_identity,
        object_identity,
        receipt_identity,
        resource_receipt_identity,
        metadata_bytes,
        expectation_identity: claimed_expectation_identity,
    })
}

pub(crate) fn build_static_count_expectation(
    receipt: &CompileReceiptV1,
) -> Result<StaticCountExpectationV1, StaticCountExpectationError> {
    let (policy_limits_identity, policy_identity_bytes_hashed) =
        policy_limits_identity(receipt.manifest_ref()).map_err(map_canonical)?;
    let (resource_receipt_identity, resource_identity_bytes_hashed) =
        resource_receipt_identity(receipt).map_err(map_canonical)?;
    let self_identity_bytes_hashed = u64::try_from(STATIC_EXPECTATION_IDENTITY_DOMAIN.len())
        .ok()
        .and_then(|domain| {
            u64::try_from(EXPECTATION_IDENTITY_OFFSET)
                .ok()
                .and_then(|body| domain.checked_add(body))
        })
        .ok_or(StaticCountExpectationError::IdentityEncoding)?;
    let canonical_bytes_hashed = policy_identity_bytes_hashed
        .checked_add(resource_identity_bytes_hashed)
        .and_then(|bytes| bytes.checked_add(self_identity_bytes_hashed))
        .ok_or(StaticCountExpectationError::IdentityEncoding)?;
    let work_upper_bound = canonical_bytes_hashed
        .checked_mul(2)
        .and_then(|work| work.checked_add(4_096))
        .ok_or(StaticCountExpectationError::IdentityEncoding)?;
    if canonical_bytes_hashed > STATIC_COUNT_EXPECTATION_CANONICAL_BYTES_HASHED_UPPER_BOUND_V1
        || work_upper_bound > STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V1
        || size_of::<CanonicalEncoder>().max(size_of::<Sha256>())
            > usize::try_from(STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V1)
                .map_err(|_| StaticCountExpectationError::IdentityEncoding)?
    {
        return Err(StaticCountExpectationError::IdentityEncoding);
    }
    let build_report = StaticCountExpectationBuildReportV1 {
        canonical_bytes_hashed,
        work_upper_bound,
        scratch_bytes_upper_bound: STATIC_COUNT_EXPECTATION_PROJECTION_SCRATCH_UPPER_BOUND_V1,
        retained_bytes: STATIC_COUNT_EXPECTATION_RETAINED_BYTES_V1,
        allocations: 0,
    };
    let mut expectation = StaticCountExpectationV1 {
        manifest_identity: receipt.manifest_identity(),
        policy_limits_identity,
        semantic_binding_identity: receipt.semantic_binding_identity(),
        planning_receipt_identity: receipt.planning_receipt_identity(),
        live_literal_identity: receipt.live_literal_identity(),
        live_literal_bytes: receipt.live_literal_bytes(),
        kir_identity: receipt.kir_identity(),
        native_artifact_identity: receipt.native_artifact_identity(),
        object_binding_identity: receipt.object_binding_identity(),
        compile_identity: receipt.compile_identity(),
        object_identity: receipt.object_identity(),
        receipt_identity: receipt.receipt_identity(),
        resource_receipt_identity,
        metadata: receipt.metadata(),
        expectation_identity: StaticCountExpectationIdentity::new([0; 32]),
        build_report,
        wire: [0; STATIC_COUNT_EXPECTATION_BYTES_V1],
    };
    let mut bytes = [0_u8; STATIC_COUNT_EXPECTATION_BYTES_V1];
    encode_expectation_body(&expectation, &mut bytes);
    expectation.expectation_identity = expectation_identity(&bytes[..EXPECTATION_IDENTITY_OFFSET]);
    bytes[EXPECTATION_IDENTITY_OFFSET..]
        .copy_from_slice(expectation.expectation_identity.as_bytes());
    expectation.wire = bytes;
    Ok(expectation)
}

fn encode_expectation_body(
    expectation: &StaticCountExpectationV1,
    bytes: &mut [u8; STATIC_COUNT_EXPECTATION_BYTES_V1],
) {
    let mut writer = FixedWriter::new(bytes);
    writer.raw(&STATIC_EXPECTATION_MAGIC);
    writer.u16(STATIC_COUNT_EXPECTATION_SCHEMA_VERSION_V1);
    writer.u16(AOT_COMPILER_VERSION_V1);
    writer.u32(
        u32::try_from(STATIC_COUNT_EXPECTATION_BYTES_V1)
            .expect("fixed v1 expectation length fits u32"),
    );
    for identity in [
        expectation.manifest_identity.as_bytes(),
        expectation.policy_limits_identity.as_bytes(),
        expectation.semantic_binding_identity.as_bytes(),
        expectation.planning_receipt_identity.as_bytes(),
        expectation.live_literal_identity.as_bytes(),
        expectation.kir_identity.as_bytes(),
        expectation.native_artifact_identity.as_bytes(),
        expectation.object_binding_identity.as_bytes(),
        expectation.compile_identity.as_bytes(),
        expectation.object_identity.as_bytes(),
        expectation.receipt_identity.as_bytes(),
        expectation.resource_receipt_identity.as_bytes(),
    ] {
        writer.raw(identity);
    }
    writer.u32(expectation.live_literal_bytes);
    writer.u16(u16::try_from(METADATA_BYTES_V1).expect("metadata length fits u16"));
    writer.u16(0);
    writer.raw(&encode_metadata(expectation.metadata));
    assert_eq!(writer.position(), EXPECTATION_IDENTITY_OFFSET);
}

fn expectation_identity(body: &[u8]) -> StaticCountExpectationIdentity {
    let mut hasher = Sha256::new();
    hasher.update(STATIC_EXPECTATION_IDENTITY_DOMAIN);
    hasher.update(body);
    StaticCountExpectationIdentity::new(hasher.finalize().into())
}

fn policy_limits_identity(
    manifest: &MacosAarch64CountManifestV1,
) -> Result<(PolicyLimitsIdentity, u64), CanonicalError> {
    let mut encoder = CanonicalEncoder::hashing();
    encoder.raw(POLICY_LIMITS_DOMAIN)?;
    encoder.raw(manifest.identity().as_bytes())?;
    let policy = manifest.policy();
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
    encoder.u64(manifest.required_cpu_features().bits())?;
    encoder.u64(manifest.allowed_cpu_features().bits())?;
    let projection = encoder.finish()?;
    Ok((
        PolicyLimitsIdentity::new(projection.bytes),
        projection.hashed_bytes,
    ))
}

fn resource_receipt_identity(
    receipt: &CompileReceiptV1,
) -> Result<(ResourceReceiptIdentity, u64), CanonicalError> {
    let mut encoder = CanonicalEncoder::hashing();
    encoder.raw(RESOURCE_RECEIPT_DOMAIN)?;
    encoder.raw(receipt.receipt_identity().as_bytes())?;
    encode_accounting(&mut encoder, receipt.accounting_ref())?;
    let projection = encoder.finish()?;
    Ok((
        ResourceReceiptIdentity::new(projection.bytes),
        projection.hashed_bytes,
    ))
}

fn encode_metadata(metadata: MetadataV1) -> [u8; METADATA_BYTES_V1] {
    let mut bytes = [0_u8; METADATA_BYTES_V1];
    let mut writer = FixedWriter::new(&mut bytes);
    writer.raw(b"FREOM64\x01");
    writer.u16(metadata.format_version());
    writer.u16(metadata.record_bytes());
    writer.u16(metadata.backend_version());
    writer.u8(match metadata.abi_kind() {
        AbiKind::Search => 1,
        AbiKind::Aggregate => 2,
    });
    writer.u8(metadata.output_kind());
    writer.u8(metadata.architecture());
    writer.u8(u8::from(metadata.little_endian()));
    writer.u8(metadata.pointer_width());
    writer.u8(metadata.target_abi());
    writer.u8(metadata.platform());
    writer.u8(metadata.status_bits());
    writer.u16(metadata.abi_schema());
    writer.u64(metadata.features());
    writer.u32(metadata.payload_bytes());
    writer.u32(metadata.entry_offset());
    writer.u32(metadata.code_bytes());
    writer.u32(metadata.rodata_offset());
    writer.u32(metadata.rodata_bytes());
    writer.u32(metadata.literal_bytes());
    writer.raw(metadata.source_identity());
    writer.raw(metadata.artifact_identity());
    writer.raw(metadata.claimed_binding_identity().as_bytes());
    writer.raw(metadata.payload_sha256());
    writer.raw(metadata.claimed_compile_identity().as_bytes());
    assert_eq!(writer.position(), METADATA_BYTES_V1);
    bytes
}

fn validate_claimed_metadata(
    bytes: &[u8; METADATA_BYTES_V1],
    live_literal_bytes: u32,
    kir_identity: &[u8; 32],
    native_artifact_identity: &[u8; 32],
    object_binding_identity: &[u8; 32],
    compile_identity: &[u8; 32],
) -> Result<(), StaticCountExpectationError> {
    let mut reader = FixedReader::new(bytes);
    reader.expect(b"FREOM64\x01", "metadata magic")?;
    if reader.u16("metadata version")? != METADATA_VERSION
        || usize::from(reader.u16("metadata bytes")?) != METADATA_BYTES_V1
        || reader.u16("metadata backend")? != AOT_AGGREGATE_BACKEND_VERSION_V1
        || reader.u8("metadata ABI kind")? != 2
        || reader.u8("metadata output")? != 1
        || reader.u8("metadata architecture")? != 1
        || reader.u8("metadata endian")? != 1
        || reader.u8("metadata pointer width")? != 64
        || reader.u8("metadata target ABI")? != 1
        || reader.u8("metadata platform")? != PLATFORM_MACOS
        || reader.u8("metadata status bits")? != STATUS_BITS_V1
        || reader.u16("metadata ABI schema")? != CALL_ABI_SCHEMA_V1
    {
        return Err(invalid("metadata fixed contract"));
    }
    let features = reader.u64("metadata features")?;
    let payload_bytes = reader.u32("metadata payload bytes")?;
    let entry_offset = reader.u32("metadata entry offset")?;
    let code_bytes = reader.u32("metadata code bytes")?;
    let rodata_offset = reader.u32("metadata rodata offset")?;
    let rodata_bytes = reader.u32("metadata rodata bytes")?;
    let metadata_literal_bytes = reader.u32("metadata literal bytes")?;
    let literal_width =
        usize::try_from(live_literal_bytes).map_err(|_| invalid("metadata literal bytes"))?;
    if features & !CpuFeatures::ASIMD.bits() != 0
        || entry_offset != ENTRY_OFFSET_V1
        || code_bytes == 0
        || !code_bytes.is_multiple_of(4)
        || !rodata_offset.is_multiple_of(16)
        || rodata_offset < code_bytes
        || rodata_offset.checked_add(rodata_bytes) != Some(payload_bytes)
        || metadata_literal_bytes != live_literal_bytes
        || literal_width > MAX_EXACT_AGGREGATE_LITERAL_BYTES
    {
        return Err(invalid("metadata image contract"));
    }
    if reader.array::<32>("metadata source identity")? != *kir_identity
        || reader.array::<32>("metadata artifact identity")? != *native_artifact_identity
        || reader.array::<32>("metadata binding identity")? != *object_binding_identity
    {
        return Err(invalid("metadata identity binding"));
    }
    let _payload_sha256 = reader.array::<32>("metadata payload digest")?;
    if reader.array::<32>("metadata compile identity")? != *compile_identity
        || reader.position() != METADATA_BYTES_V1
    {
        return Err(invalid("metadata compile binding"));
    }
    Ok(())
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

    fn u8(&mut self, value: u8) {
        self.raw(&[value]);
    }

    fn u16(&mut self, value: u16) {
        self.raw(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.raw(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
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

    fn u8(&mut self, at: &'static str) -> Result<u8, StaticCountExpectationError> {
        Ok(self.array::<1>(at)?[0])
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, StaticCountExpectationError> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, StaticCountExpectationError> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn u64(&mut self, at: &'static str) -> Result<u64, StaticCountExpectationError> {
        Ok(u64::from_le_bytes(self.array(at)?))
    }

    const fn position(&self) -> usize {
        self.position
    }
}

const fn invalid(at: &'static str) -> StaticCountExpectationError {
    StaticCountExpectationError::InvalidWire { at }
}

fn map_canonical(_error: CanonicalError) -> StaticCountExpectationError {
    StaticCountExpectationError::IdentityEncoding
}
