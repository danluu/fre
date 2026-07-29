//! Versioned claim-side wire contract for optimizing Count-v3 AOT images.
//!
//! The records in this module are inert and unauthoritative.  Inspection is
//! allocation-free and proves only canonical shape, internal identity
//! consistency, and membership in an explicit backend support row.

use core::fmt;

use fre_aot_aarch64::{
    AOT_COUNT_IMAGE_SCHEMA_VERSION_V3, AotCountBackendSupportV3, AotCountCpuFeatures,
    AotCountTargetSpec, SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3,
};
use fre_aot_optimizer::{
    COUNT_V3_OPTIMIZER_VERSION, COUNT_V3_RECIPE_CANONICAL_BYTES, COUNT_V3_RECIPE_SCHEMA_VERSION,
    inspect_count_recipe_v3,
};
use sha2::{Digest, Sha256};

pub const METADATA_VERSION_V3: u16 = 3;
pub const METADATA_BYTES_V3: usize = 640;
pub const ENTRY_OFFSET_V3: u32 = 0;
/// Count-v3 changes compiler/image schemas, not the proven three-argument
/// Count entry ABI or its status semantics.
pub const CALL_ABI_SCHEMA_V3: u16 = 2;
pub const STATUS_BITS_V3: u8 = 64;
pub const EXPORTED_SYMBOL_SCHEMA_VERSION_V3: u16 = 4;
pub const EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V3: usize = 64;
pub const COUNT_ENTRY_SYMBOL_PREFIX_V3: &str = "fre_aot_count_entry_v3_";
pub const COUNT_PAYLOAD_SYMBOL_PREFIX_V3: &str = "fre_aot_count_payload_v3_";
pub const COUNT_METADATA_SYMBOL_PREFIX_V3: &str = "fre_aot_count_metadata_v3_";

pub const AOT_COMPILER_VERSION_V3: u16 = 3;
pub const AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V3: u16 = 3;
pub const STATIC_COUNT_EXPECTATION_BYTES_V3: usize = 1_144;
pub const STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V3: usize = 472;
pub const STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3: usize = 1_112;
pub const STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V3: u64 = 6_144;

pub const COUNT_ABI_KIND_V3: u8 = 2;
pub const COUNT_OUTPUT_KIND_V3: u8 = 1;

pub const AOT_COUNT_AUDITOR_VERSION_V3: u16 = 1;
pub const METADATA_COMPILE_IDENTITY_OFFSET_V3: usize = 608;

const METADATA_MAGIC_V3: [u8; 8] = *b"FREOM64\x03";
const STATIC_EXPECTATION_MAGIC_V3: [u8; 8] = *b"FRESCEX\x03";
const STATIC_EXPECTATION_IDENTITY_DOMAIN_V3: &[u8] =
    b"FRE-AOT-STATIC-COUNT-EXPECTATION-IDENTITY\0\x03";
const TARGET_IDENTITY_DOMAIN_V3: &[u8] = b"FRE-AOT-COUNT-TARGET-IDENTITY\0\x03";
pub const RECIPE_CANONICAL_BYTES_V3: usize = COUNT_V3_RECIPE_CANONICAL_BYTES;
const PADDED_LITERAL_BYTES_V3: usize = 32;

const _: () = assert!(METADATA_COMPILE_IDENTITY_OFFSET_V3 + 32 == METADATA_BYTES_V3);
const _: () = assert!(
    STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V3 + METADATA_BYTES_V3
        == STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3
);
const _: () =
    assert!(STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3 + 32 == STATIC_COUNT_EXPECTATION_BYTES_V3);

/// Deterministic relocatable container used for one Count-v3 implementation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum CountObjectFormatV3 {
    MachOArm64 = 1,
    Elf64Aarch64 = 2,
}

impl CountObjectFormatV3 {
    #[must_use]
    pub const fn wire_id(self) -> u8 {
        self as u8
    }

    const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::MachOArm64),
            2 => Some(Self::Elf64Aarch64),
            _ => None,
        }
    }
}

/// A fixed Count-v3 metadata record was not canonical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountMetadataErrorV3 {
    at: &'static str,
}

impl CountMetadataErrorV3 {
    #[must_use]
    pub const fn at(&self) -> &'static str {
        self.at
    }
}

impl fmt::Display for CountMetadataErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Count-v3 metadata at {}", self.at)
    }
}

impl std::error::Error for CountMetadataErrorV3 {}

/// A fixed Count-v3 expectation was not canonical or internally consistent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticCountExpectationErrorV3 {
    at: &'static str,
}

impl StaticCountExpectationErrorV3 {
    #[must_use]
    pub const fn at(&self) -> &'static str {
        self.at
    }
}

impl fmt::Display for StaticCountExpectationErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid Count-v3 static expectation at {}",
            self.at
        )
    }
}

impl std::error::Error for StaticCountExpectationErrorV3 {}

/// Strictly decoded but untrusted optimizing Count-v3 metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedCountMetadataV3 {
    format_version: u16,
    record_bytes: u16,
    backend_version: u16,
    algorithm_version: u16,
    kir_semantics_version: u16,
    kir_abi_version: u16,
    abi_schema: u16,
    max_literal_bytes: u16,
    abi_kind: u8,
    output_kind: u8,
    architecture: u8,
    little_endian: u8,
    pointer_width: u8,
    target_abi: u8,
    object_format: CountObjectFormatV3,
    status_bits: u8,
    candidate_block_starts: u8,
    required_isa_id: u8,
    tuning_class_id: u8,
    strategy_id: u8,
    schedule_id: u8,
    register_plan_id: u8,
    filter_len: u8,
    confirmation_len: u8,
    sparse_group_count: u8,
    mismatch_stride: u8,
    match_stride: u8,
    periodic_stride: u8,
    vector_bytes: u16,
    sve_vector_length_bytes: u16,
    recipe_schema_version: u16,
    optimizer_version: u16,
    auditor_version: u16,
    reserved: u16,
    actual_features: u64,
    allowed_features: u64,
    payload_bytes: u32,
    entry_offset: u32,
    code_bytes: u32,
    rodata_offset: u32,
    rodata_bytes: u32,
    literal_bytes: u32,
    literal_manifest: [u8; PADDED_LITERAL_BYTES_V3],
    canonical_recipe: [u8; RECIPE_CANONICAL_BYTES_V3],
    program_identity: [u8; 32],
    artifact_identity: [u8; 32],
    binding_identity: [u8; 32],
    payload_sha256: [u8; 32],
    recipe_identity: [u8; 32],
    optimizer_receipt_identity: [u8; 32],
    target_identity: [u8; 32],
    compile_identity: [u8; 32],
}

/// Artifact-independent production qualification key.
///
/// A promotion row may admit this exact compiler/backend/auditor/semantics and
/// target tuple for every structurally valid literal/recipe.  Per-artifact
/// hashes remain mandatory integrity bindings, but are intentionally absent
/// here so qualification does not overfit a list of benchmark identities.
/// Pattern-derived class fields scope promotion to the closed recipe classes
/// actually covered by held-out evidence, without enumerating literal bytes or
/// Rebar case names.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CountGeneralEligibilityTupleV3 {
    pub compiler_version: u16,
    pub metadata_version: u16,
    pub image_schema_version: u16,
    pub backend_version: u16,
    pub algorithm_version: u16,
    pub auditor_version: u16,
    pub kir_semantics_version: u16,
    pub kir_abi_version: u16,
    pub recipe_schema_version: u16,
    pub optimizer_version: u16,
    pub tuning_class_id: u8,
    pub strategy_id: u8,
    pub schedule_id: u8,
    pub register_plan_id: u8,
    pub literal_bytes: u32,
    pub filter_len: u8,
    pub sparse_group_count: u8,
    pub match_stride: u8,
    pub periodic_stride: u8,
    pub call_abi_schema: u16,
    pub abi_kind: u8,
    pub status_bits: u8,
    pub output_kind: u8,
    pub architecture: u8,
    pub little_endian: bool,
    pub pointer_width: u8,
    pub target_abi: u8,
    pub object_format: CountObjectFormatV3,
    pub required_isa_id: u8,
    pub actual_features: u64,
    pub allowed_features: u64,
    pub candidate_block_starts: u8,
    pub vector_bytes: u16,
    pub sve_vector_length_bytes: u16,
    pub max_literal_bytes: u16,
}

macro_rules! scalar_getter {
    ($name:ident, $type:ty) => {
        #[must_use]
        pub const fn $name(&self) -> $type {
            self.$name
        }
    };
}

macro_rules! identity_getter {
    ($name:ident) => {
        #[must_use]
        pub const fn $name(&self) -> &[u8; 32] {
            &self.$name
        }
    };
}

impl ClaimedCountMetadataV3 {
    scalar_getter!(format_version, u16);
    scalar_getter!(record_bytes, u16);
    scalar_getter!(backend_version, u16);
    scalar_getter!(algorithm_version, u16);
    scalar_getter!(kir_semantics_version, u16);
    scalar_getter!(kir_abi_version, u16);
    scalar_getter!(abi_schema, u16);
    scalar_getter!(max_literal_bytes, u16);
    scalar_getter!(abi_kind, u8);
    scalar_getter!(output_kind, u8);
    scalar_getter!(architecture, u8);
    scalar_getter!(pointer_width, u8);
    scalar_getter!(target_abi, u8);
    scalar_getter!(object_format, CountObjectFormatV3);
    scalar_getter!(status_bits, u8);
    scalar_getter!(candidate_block_starts, u8);
    scalar_getter!(required_isa_id, u8);
    scalar_getter!(tuning_class_id, u8);
    scalar_getter!(strategy_id, u8);
    scalar_getter!(schedule_id, u8);
    scalar_getter!(register_plan_id, u8);
    scalar_getter!(filter_len, u8);
    scalar_getter!(confirmation_len, u8);
    scalar_getter!(sparse_group_count, u8);
    scalar_getter!(mismatch_stride, u8);
    scalar_getter!(match_stride, u8);
    scalar_getter!(periodic_stride, u8);
    scalar_getter!(vector_bytes, u16);
    scalar_getter!(sve_vector_length_bytes, u16);
    scalar_getter!(recipe_schema_version, u16);
    scalar_getter!(optimizer_version, u16);
    scalar_getter!(auditor_version, u16);
    scalar_getter!(actual_features, u64);
    scalar_getter!(allowed_features, u64);
    scalar_getter!(payload_bytes, u32);
    scalar_getter!(entry_offset, u32);
    scalar_getter!(code_bytes, u32);
    scalar_getter!(rodata_offset, u32);
    scalar_getter!(rodata_bytes, u32);
    scalar_getter!(literal_bytes, u32);

    #[must_use]
    pub const fn little_endian(&self) -> bool {
        self.little_endian == 1
    }

    #[must_use]
    pub const fn literal_manifest(&self) -> &[u8; PADDED_LITERAL_BYTES_V3] {
        &self.literal_manifest
    }

    #[must_use]
    pub const fn canonical_recipe(&self) -> &[u8; RECIPE_CANONICAL_BYTES_V3] {
        &self.canonical_recipe
    }

    identity_getter!(program_identity);
    identity_getter!(artifact_identity);
    identity_getter!(binding_identity);
    identity_getter!(payload_sha256);
    identity_getter!(recipe_identity);
    identity_getter!(optimizer_receipt_identity);
    identity_getter!(target_identity);
    identity_getter!(compile_identity);

    #[must_use]
    pub const fn general_eligibility_tuple(&self) -> CountGeneralEligibilityTupleV3 {
        CountGeneralEligibilityTupleV3 {
            compiler_version: AOT_COMPILER_VERSION_V3,
            metadata_version: self.format_version,
            image_schema_version: AOT_COUNT_IMAGE_SCHEMA_VERSION_V3,
            backend_version: self.backend_version,
            algorithm_version: self.algorithm_version,
            auditor_version: self.auditor_version,
            kir_semantics_version: self.kir_semantics_version,
            kir_abi_version: self.kir_abi_version,
            recipe_schema_version: self.recipe_schema_version,
            optimizer_version: self.optimizer_version,
            tuning_class_id: self.tuning_class_id,
            strategy_id: self.strategy_id,
            schedule_id: self.schedule_id,
            register_plan_id: self.register_plan_id,
            literal_bytes: self.literal_bytes,
            filter_len: self.filter_len,
            sparse_group_count: self.sparse_group_count,
            match_stride: self.match_stride,
            periodic_stride: self.periodic_stride,
            call_abi_schema: self.abi_schema,
            abi_kind: self.abi_kind,
            status_bits: self.status_bits,
            output_kind: self.output_kind,
            architecture: self.architecture,
            little_endian: self.little_endian(),
            pointer_width: self.pointer_width,
            target_abi: self.target_abi,
            object_format: self.object_format,
            required_isa_id: self.required_isa_id,
            actual_features: self.actual_features,
            allowed_features: self.allowed_features,
            candidate_block_starts: self.candidate_block_starts,
            vector_bytes: self.vector_bytes,
            sve_vector_length_bytes: self.sve_vector_length_bytes,
            max_literal_bytes: self.max_literal_bytes,
        }
    }
}

/// Domain-separated identity of all target and object-format facts.
#[must_use]
pub fn compute_count_target_identity_v3(
    object_format: CountObjectFormatV3,
    support: AotCountBackendSupportV3,
    target: AotCountTargetSpec,
    tuning_class_id: u8,
    register_plan_id: u8,
    required_isa_id: u8,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TARGET_IDENTITY_DOMAIN_V3);
    hasher.update(support.backend_version.0.to_le_bytes());
    hasher.update(support.algorithm_version.to_le_bytes());
    hasher.update(support.kir_semantics_version.to_le_bytes());
    hasher.update(support.kir_abi_version.to_le_bytes());
    hasher.update([support.output_kind]);
    hasher.update([target.architecture]);
    hasher.update([u8::from(target.little_endian)]);
    hasher.update([target.pointer_width]);
    hasher.update([target.abi]);
    hasher.update([object_format.wire_id()]);
    hasher.update(target.features.bits().to_le_bytes());
    hasher.update(support.allowed_features.bits().to_le_bytes());
    hasher.update([support.candidate_block_starts]);
    hasher.update(support.vector_bytes.to_le_bytes());
    hasher.update(support.sve_vector_length_bytes.to_le_bytes());
    hasher.update([tuning_class_id]);
    hasher.update([register_plan_id]);
    hasher.update([required_isa_id]);
    hasher.finalize().into()
}

/// Decode and validate one complete canonical Count-v3 metadata record.
pub fn inspect_count_metadata_v3(
    bytes: &[u8; METADATA_BYTES_V3],
) -> Result<ClaimedCountMetadataV3, CountMetadataErrorV3> {
    let mut reader = MetadataReader::new(bytes);
    reader.expect(&METADATA_MAGIC_V3, "metadata magic")?;
    let format_version = reader.u16("metadata version")?;
    let record_bytes = reader.u16("metadata record bytes")?;
    let backend_version = reader.u16("backend version")?;
    let algorithm_version = reader.u16("algorithm version")?;
    let kir_semantics_version = reader.u16("KIR semantics version")?;
    let kir_abi_version = reader.u16("KIR ABI version")?;
    let abi_schema = reader.u16("call ABI schema")?;
    let max_literal_bytes = reader.u16("maximum literal bytes")?;
    let abi_kind = reader.u8("ABI kind")?;
    let output_kind = reader.u8("output kind")?;
    let architecture = reader.u8("architecture")?;
    let little_endian = reader.u8("byte order")?;
    let pointer_width = reader.u8("pointer width")?;
    let target_abi = reader.u8("target ABI")?;
    let object_format = CountObjectFormatV3::from_wire(reader.u8("object format")?)
        .ok_or_else(|| metadata_error("object format"))?;
    let metadata = ClaimedCountMetadataV3 {
        format_version,
        record_bytes,
        backend_version,
        algorithm_version,
        kir_semantics_version,
        kir_abi_version,
        abi_schema,
        max_literal_bytes,
        abi_kind,
        output_kind,
        architecture,
        little_endian,
        pointer_width,
        target_abi,
        object_format,
        status_bits: reader.u8("status width")?,
        candidate_block_starts: reader.u8("candidate block starts")?,
        required_isa_id: reader.u8("required ISA")?,
        tuning_class_id: reader.u8("tuning class")?,
        strategy_id: reader.u8("strategy")?,
        schedule_id: reader.u8("schedule")?,
        register_plan_id: reader.u8("register plan")?,
        filter_len: reader.u8("filter length")?,
        confirmation_len: reader.u8("confirmation length")?,
        sparse_group_count: reader.u8("sparse group count")?,
        mismatch_stride: reader.u8("mismatch stride")?,
        match_stride: reader.u8("match stride")?,
        periodic_stride: reader.u8("periodic stride")?,
        vector_bytes: reader.u16("vector bytes")?,
        sve_vector_length_bytes: reader.u16("SVE vector length")?,
        recipe_schema_version: reader.u16("recipe schema")?,
        optimizer_version: reader.u16("optimizer version")?,
        auditor_version: reader.u16("auditor version")?,
        reserved: reader.u16("metadata reserved")?,
        actual_features: reader.u64("actual features")?,
        allowed_features: reader.u64("allowed features")?,
        payload_bytes: reader.u32("payload bytes")?,
        entry_offset: reader.u32("entry offset")?,
        code_bytes: reader.u32("code bytes")?,
        rodata_offset: reader.u32("rodata offset")?,
        rodata_bytes: reader.u32("rodata bytes")?,
        literal_bytes: reader.u32("literal bytes")?,
        literal_manifest: reader.array("literal manifest")?,
        canonical_recipe: reader.array("canonical recipe")?,
        program_identity: reader.array("program identity")?,
        artifact_identity: reader.array("artifact identity")?,
        binding_identity: reader.array("binding identity")?,
        payload_sha256: reader.array("payload digest")?,
        recipe_identity: reader.array("recipe identity")?,
        optimizer_receipt_identity: reader.array("optimizer receipt identity")?,
        target_identity: reader.array("target identity")?,
        compile_identity: reader.array("compile identity")?,
    };
    if reader.position() != bytes.len() {
        return Err(metadata_error("metadata trailing bytes"));
    }
    validate_metadata_shape(metadata)?;
    Ok(metadata)
}

fn validate_metadata_shape(metadata: ClaimedCountMetadataV3) -> Result<(), CountMetadataErrorV3> {
    if metadata.format_version != METADATA_VERSION_V3
        || usize::from(metadata.record_bytes) != METADATA_BYTES_V3
        || metadata.abi_kind != COUNT_ABI_KIND_V3
        || metadata.output_kind != COUNT_OUTPUT_KIND_V3
        || metadata.abi_schema != CALL_ABI_SCHEMA_V3
        || metadata.status_bits != STATUS_BITS_V3
        || metadata.entry_offset != ENTRY_OFFSET_V3
        || metadata.little_endian != 1
        || metadata.actual_features & !metadata.allowed_features != 0
        || metadata.auditor_version != AOT_COUNT_AUDITOR_VERSION_V3
        || metadata.reserved != 0
        || !metadata_support_row_is_explicit(metadata)
    {
        return Err(metadata_error("metadata contract"));
    }
    if metadata.code_bytes == 0
        || !metadata.code_bytes.is_multiple_of(4)
        || !metadata.rodata_offset.is_multiple_of(16)
        || metadata.rodata_offset < metadata.code_bytes
        || metadata.rodata_bytes != 0
        || metadata.rodata_offset != metadata.payload_bytes
        || metadata.literal_bytes > u32::from(metadata.max_literal_bytes)
        || u32::from(metadata.confirmation_len) != metadata.literal_bytes
        || metadata.filter_len > 4
        || metadata.sparse_group_count > 4
    {
        return Err(metadata_error("image or recipe layout"));
    }
    validate_embedded_manifests(metadata)?;
    if [
        metadata.program_identity,
        metadata.artifact_identity,
        metadata.binding_identity,
        metadata.recipe_identity,
        metadata.optimizer_receipt_identity,
        metadata.target_identity,
        metadata.compile_identity,
    ]
    .contains(&[0; 32])
    {
        return Err(metadata_error("zero identity"));
    }
    let support = matched_support(metadata).ok_or_else(|| metadata_error("backend support row"))?;
    let target = AotCountTargetSpec {
        architecture: metadata.architecture,
        little_endian: metadata.little_endian(),
        pointer_width: metadata.pointer_width,
        abi: metadata.target_abi,
        features: AotCountCpuFeatures::from_bits(metadata.actual_features)
            .ok_or_else(|| metadata_error("actual feature bitmap"))?,
    };
    let expected_target = compute_count_target_identity_v3(
        metadata.object_format,
        support,
        target,
        metadata.tuning_class_id,
        metadata.register_plan_id,
        metadata.required_isa_id,
    );
    if expected_target != metadata.target_identity {
        return Err(metadata_error("target identity"));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the complete fixed recipe wire is deliberately checked in one allocation-free pass"
)]
fn validate_embedded_manifests(
    metadata: ClaimedCountMetadataV3,
) -> Result<(), CountMetadataErrorV3> {
    let literal_len =
        usize::try_from(metadata.literal_bytes).map_err(|_| metadata_error("literal length"))?;
    if literal_len > metadata.literal_manifest.len()
        || metadata.literal_manifest[literal_len..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(metadata_error("literal manifest padding"));
    }

    let inspected = inspect_count_recipe_v3(&metadata.canonical_recipe)
        .map_err(|_| metadata_error("canonical recipe"))?;
    let literal_identity: [u8; 32] =
        Sha256::digest(&metadata.literal_manifest[..literal_len]).into();
    if metadata.recipe_schema_version != COUNT_V3_RECIPE_SCHEMA_VERSION
        || metadata.optimizer_version != COUNT_V3_OPTIMIZER_VERSION
        || inspected.program_identity() != &metadata.program_identity
        || inspected.literal_identity() != &literal_identity
        || inspected.tuning_class().wire_id() != metadata.tuning_class_id
        || inspected.strategy().wire_id() != metadata.strategy_id
        || inspected.schedule_id().wire_id() != metadata.schedule_id
        || inspected.register_plan_id().wire_id() != metadata.register_plan_id
        || inspected.required_isa().wire_id() != metadata.required_isa_id
        || inspected.filter_offsets().len() != usize::from(metadata.filter_len)
        || inspected.confirmation_order().len() != usize::from(metadata.confirmation_len)
        || inspected.sparse_group_blocks().len() != usize::from(metadata.sparse_group_count)
        || metadata.mismatch_stride != 1
        || inspected.match_stride() != metadata.match_stride
        || inspected.periodic_stride() != metadata.periodic_stride
        || inspected.identity().as_bytes() != &metadata.recipe_identity
    {
        return Err(metadata_error("recipe scalar projection"));
    }
    Ok(())
}

fn matched_support(metadata: ClaimedCountMetadataV3) -> Option<AotCountBackendSupportV3> {
    SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3
        .iter()
        .copied()
        .find(|support| support_matches(metadata, *support))
}

fn metadata_support_row_is_explicit(metadata: ClaimedCountMetadataV3) -> bool {
    matched_support(metadata).is_some()
}

fn support_matches(metadata: ClaimedCountMetadataV3, support: AotCountBackendSupportV3) -> bool {
    metadata.backend_version == support.backend_version.0
        && metadata.algorithm_version == support.algorithm_version
        && metadata.kir_semantics_version == support.kir_semantics_version
        && metadata.kir_abi_version == support.kir_abi_version
        && metadata.output_kind == support.output_kind
        && metadata.architecture == support.architecture
        && metadata.little_endian() == support.little_endian
        && metadata.pointer_width == support.pointer_width
        && metadata.target_abi == support.target_abi
        && metadata.allowed_features == support.allowed_features.bits()
        && metadata.max_literal_bytes == support.max_literal_bytes
        && metadata.candidate_block_starts == support.candidate_block_starts
        && metadata.vector_bytes == support.vector_bytes
        && metadata.sve_vector_length_bytes == support.sve_vector_length_bytes
}

/// Canonical and internally consistent expectation bytes remain untrusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedStaticCountExpectationV3 {
    schema_version: u16,
    compiler_version: u16,
    image_schema_version: u16,
    manifest_identity: [u8; 32],
    policy_limits_identity: [u8; 32],
    semantic_binding_identity: [u8; 32],
    planning_receipt_identity: [u8; 32],
    live_literal_identity: [u8; 32],
    program_identity: [u8; 32],
    image_identity: [u8; 32],
    recipe_identity: [u8; 32],
    optimizer_receipt_identity: [u8; 32],
    object_binding_identity: [u8; 32],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    receipt_identity: [u8; 32],
    resource_receipt_identity: [u8; 32],
    live_literal_bytes: u32,
    metadata: ClaimedCountMetadataV3,
    expectation_identity: [u8; 32],
}

impl ClaimedStaticCountExpectationV3 {
    scalar_getter!(schema_version, u16);
    scalar_getter!(compiler_version, u16);
    scalar_getter!(image_schema_version, u16);
    scalar_getter!(live_literal_bytes, u32);
    identity_getter!(manifest_identity);
    identity_getter!(policy_limits_identity);
    identity_getter!(semantic_binding_identity);
    identity_getter!(planning_receipt_identity);
    identity_getter!(live_literal_identity);
    identity_getter!(program_identity);
    identity_getter!(image_identity);
    identity_getter!(recipe_identity);
    identity_getter!(optimizer_receipt_identity);
    identity_getter!(object_binding_identity);
    identity_getter!(compile_identity);
    identity_getter!(object_identity);
    identity_getter!(receipt_identity);
    identity_getter!(resource_receipt_identity);
    identity_getter!(expectation_identity);

    #[must_use]
    pub const fn metadata(&self) -> ClaimedCountMetadataV3 {
        self.metadata
    }
}

/// Strictly inspect arbitrary bytes for the fixed Count-v3 expectation shape.
pub fn inspect_static_count_expectation_v3(
    bytes: &[u8],
) -> Result<ClaimedStaticCountExpectationV3, StaticCountExpectationErrorV3> {
    if bytes.len() != STATIC_COUNT_EXPECTATION_BYTES_V3 {
        return Err(expectation_error("record bytes"));
    }
    let mut reader = ExpectationReader::new(bytes);
    reader.expect(&STATIC_EXPECTATION_MAGIC_V3, "expectation magic")?;
    let schema_version = reader.u16("expectation schema")?;
    let compiler_version = reader.u16("compiler version")?;
    let record_bytes = reader.u32("expectation record bytes")?;
    if schema_version != AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V3
        || compiler_version != AOT_COMPILER_VERSION_V3
        || usize::try_from(record_bytes).ok() != Some(STATIC_COUNT_EXPECTATION_BYTES_V3)
    {
        return Err(expectation_error("expectation header"));
    }
    let manifest_identity = reader.array("manifest identity")?;
    let policy_limits_identity = reader.array("policy limits identity")?;
    let semantic_binding_identity = reader.array("semantic binding identity")?;
    let planning_receipt_identity = reader.array("planning receipt identity")?;
    let live_literal_identity = reader.array("live literal identity")?;
    let program_identity = reader.array("program identity")?;
    let image_identity = reader.array("image identity")?;
    let recipe_identity = reader.array("recipe identity")?;
    let optimizer_receipt_identity = reader.array("optimizer receipt identity")?;
    let object_binding_identity = reader.array("object binding identity")?;
    let compile_identity = reader.array("compile identity")?;
    let object_identity = reader.array("object identity")?;
    let receipt_identity = reader.array("compile receipt identity")?;
    let resource_receipt_identity = reader.array("resource receipt identity")?;
    let live_literal_bytes = reader.u32("live literal bytes")?;
    let metadata_record_bytes = reader.u16("metadata record bytes")?;
    let image_schema_version = reader.u16("image schema version")?;
    if usize::from(metadata_record_bytes) != METADATA_BYTES_V3
        || image_schema_version != AOT_COUNT_IMAGE_SCHEMA_VERSION_V3
        || reader.position() != STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V3
    {
        return Err(expectation_error("metadata envelope"));
    }
    let metadata_bytes = reader.array("metadata")?;
    let metadata = inspect_count_metadata_v3(&metadata_bytes)
        .map_err(|_| expectation_error("metadata contract"))?;
    if reader.position() != STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3 {
        return Err(expectation_error("expectation identity offset"));
    }
    let expectation_identity = reader.array("expectation identity")?;
    let body = bytes
        .get(..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3)
        .ok_or_else(|| expectation_error("expectation identity body"))?;
    let mut hasher = Sha256::new();
    hasher.update(STATIC_EXPECTATION_IDENTITY_DOMAIN_V3);
    hasher.update(body);
    let computed_identity: [u8; 32] = hasher.finalize().into();
    if reader.position() != bytes.len() || computed_identity != expectation_identity {
        return Err(expectation_error("expectation identity"));
    }
    let literal_len = usize::try_from(live_literal_bytes)
        .ok()
        .filter(|length| *length <= PADDED_LITERAL_BYTES_V3)
        .ok_or_else(|| expectation_error("live literal length"))?;
    let computed_literal_identity: [u8; 32] =
        Sha256::digest(&metadata.literal_manifest[..literal_len]).into();
    let required_features = required_features_for_isa(metadata.required_isa_id)
        .ok_or_else(|| expectation_error("required ISA"))?;
    if metadata.literal_bytes != live_literal_bytes
        || live_literal_identity != computed_literal_identity
        || metadata.program_identity != program_identity
        || metadata.artifact_identity != image_identity
        || metadata.recipe_identity != recipe_identity
        || metadata.optimizer_receipt_identity != optimizer_receipt_identity
        || metadata.binding_identity != object_binding_identity
        || metadata.compile_identity != compile_identity
        || (live_literal_bytes == 0 && metadata.actual_features != 0)
        || (live_literal_bytes != 0
            && metadata.actual_features & required_features.bits() != required_features.bits())
    {
        return Err(expectation_error("metadata expectation binding"));
    }
    Ok(ClaimedStaticCountExpectationV3 {
        schema_version,
        compiler_version,
        image_schema_version,
        manifest_identity,
        policy_limits_identity,
        semantic_binding_identity,
        planning_receipt_identity,
        live_literal_identity,
        program_identity,
        image_identity,
        recipe_identity,
        optimizer_receipt_identity,
        object_binding_identity,
        compile_identity,
        object_identity,
        receipt_identity,
        resource_receipt_identity,
        live_literal_bytes,
        metadata,
        expectation_identity,
    })
}

fn required_features_for_isa(required_isa_id: u8) -> Option<AotCountCpuFeatures> {
    match required_isa_id {
        1 => Some(AotCountCpuFeatures::ASIMD),
        2 => Some(AotCountCpuFeatures::SVE),
        3 => Some(AotCountCpuFeatures::SVE2),
        _ => None,
    }
}

const fn metadata_error(at: &'static str) -> CountMetadataErrorV3 {
    CountMetadataErrorV3 { at }
}

const fn expectation_error(at: &'static str) -> StaticCountExpectationErrorV3 {
    StaticCountExpectationErrorV3 { at }
}

struct MetadataReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> MetadataReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, count: usize, at: &'static str) -> Result<&'a [u8], CountMetadataErrorV3> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| metadata_error(at))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| metadata_error(at))?;
        self.position = end;
        Ok(value)
    }

    fn expect(&mut self, value: &[u8], at: &'static str) -> Result<(), CountMetadataErrorV3> {
        if self.take(value.len(), at)? == value {
            Ok(())
        } else {
            Err(metadata_error(at))
        }
    }

    fn u8(&mut self, at: &'static str) -> Result<u8, CountMetadataErrorV3> {
        self.take(1, at)?
            .first()
            .copied()
            .ok_or_else(|| metadata_error(at))
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, CountMetadataErrorV3> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, CountMetadataErrorV3> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn u64(&mut self, at: &'static str) -> Result<u64, CountMetadataErrorV3> {
        Ok(u64::from_le_bytes(self.array(at)?))
    }

    fn array<const BYTES: usize>(
        &mut self,
        at: &'static str,
    ) -> Result<[u8; BYTES], CountMetadataErrorV3> {
        self.take(BYTES, at)?
            .try_into()
            .map_err(|_| metadata_error(at))
    }

    const fn position(&self) -> usize {
        self.position
    }
}

struct ExpectationReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ExpectationReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(
        &mut self,
        count: usize,
        at: &'static str,
    ) -> Result<&'a [u8], StaticCountExpectationErrorV3> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| expectation_error(at))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| expectation_error(at))?;
        self.position = end;
        Ok(value)
    }

    fn expect(
        &mut self,
        value: &[u8],
        at: &'static str,
    ) -> Result<(), StaticCountExpectationErrorV3> {
        if self.take(value.len(), at)? == value {
            Ok(())
        } else {
            Err(expectation_error(at))
        }
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, StaticCountExpectationErrorV3> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, StaticCountExpectationErrorV3> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn array<const BYTES: usize>(
        &mut self,
        at: &'static str,
    ) -> Result<[u8; BYTES], StaticCountExpectationErrorV3> {
        self.take(BYTES, at)?
            .try_into()
            .map_err(|_| expectation_error(at))
    }

    const fn position(&self) -> usize {
        self.position
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_offsets_are_self_consistent() {
        assert_eq!(METADATA_COMPILE_IDENTITY_OFFSET_V3 + 32, METADATA_BYTES_V3);
        assert_eq!(
            STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V3 + METADATA_BYTES_V3,
            STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3
        );
        assert_eq!(
            STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V3 + 32,
            STATIC_COUNT_EXPECTATION_BYTES_V3
        );
    }

    #[test]
    fn object_format_wire_values_are_closed() {
        assert_eq!(
            CountObjectFormatV3::from_wire(1),
            Some(CountObjectFormatV3::MachOArm64)
        );
        assert_eq!(
            CountObjectFormatV3::from_wire(2),
            Some(CountObjectFormatV3::Elf64Aarch64)
        );
        assert_eq!(CountObjectFormatV3::from_wire(0), None);
        assert_eq!(CountObjectFormatV3::from_wire(3), None);
    }
}
