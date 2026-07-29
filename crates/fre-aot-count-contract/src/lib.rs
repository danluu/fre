//! JIT-neutral, claim-side wire contract for Count-v2 static AOT images.
//!
//! This crate deliberately knows neither the compiler nor the Mach-O
//! publisher. It can prove that arbitrary fixed-size metadata and expectation
//! bytes are canonical and internally consistent, but it cannot manufacture
//! compiler authority or authorize runtime execution.

#![forbid(unsafe_code)]

pub mod v3;

use core::fmt;

use fre_aot_aarch64::{
    AOT_COUNT_IMAGE_SCHEMA_VERSION_V2, AotCountCpuFeatures, SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2,
};
use sha2::{Digest, Sha256};

pub const METADATA_VERSION_V2: u16 = 2;
pub const METADATA_BYTES_V2: usize = 232;
pub const ENTRY_OFFSET_V2: u32 = 0;
pub const CALL_ABI_SCHEMA_V2: u16 = 2;
pub const STATUS_BITS_V2: u8 = 64;
pub const EXPORTED_SYMBOL_SCHEMA_VERSION_V2: u16 = 3;
pub const EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2: usize = 64;
pub const COUNT_EXPORTED_SYMBOL_N_TYPE_V2: u8 = 0x1f;
pub const COUNT_ENTRY_SYMBOL_PREFIX_V2: &str = "fre_aot_count_entry_v2_";
pub const COUNT_PAYLOAD_SYMBOL_PREFIX_V2: &str = "fre_aot_count_payload_v2_";
pub const COUNT_METADATA_SYMBOL_PREFIX_V2: &str = "fre_aot_count_metadata_v2_";

pub const AOT_COMPILER_VERSION_V2: u16 = 2;
pub const AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2: u16 = 2;
pub const STATIC_COUNT_EXPECTATION_BYTES_V2: usize = 672;
pub const STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2: usize = 408;
pub const STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2: usize = 640;
/// Conservative work envelope retained from the reviewed Count-v2 claim
/// projection. Runtime inspection adds its mapped-copy/hash/VM work separately.
pub const STATIC_COUNT_EXPECTATION_PROJECTION_WORK_UPPER_BOUND_V2: u64 = 4_083;

pub const COUNT_ABI_KIND_V2: u8 = 2;
pub const COUNT_OUTPUT_KIND_V2: u8 = 1;
pub const COUNT_PLATFORM_MACOS_V2: u8 = 1;

const METADATA_MAGIC_V2: [u8; 8] = *b"FREOM64\x02";
const STATIC_EXPECTATION_MAGIC_V2: [u8; 8] = *b"FRESCEX\x02";
const STATIC_EXPECTATION_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-STATIC-COUNT-EXPECTATION-IDENTITY\0\x02";

const _: () = assert!(METADATA_BYTES_V2 == 232);
const _: () = assert!(STATIC_EXPECTATION_IDENTITY_DOMAIN_V2.len() == 43);
const _: () = assert!(
    STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2 + METADATA_BYTES_V2
        == STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2
);
const _: () =
    assert!(STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2 + 32 == STATIC_COUNT_EXPECTATION_BYTES_V2);

/// A fixed metadata record was not canonical Count-v2 metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountMetadataErrorV2 {
    at: &'static str,
}

impl CountMetadataErrorV2 {
    #[must_use]
    pub const fn at(&self) -> &'static str {
        self.at
    }
}

impl fmt::Display for CountMetadataErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Count-v2 metadata at {}", self.at)
    }
}

impl std::error::Error for CountMetadataErrorV2 {}

/// A fixed expectation record was not canonical or internally consistent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticCountExpectationErrorV2 {
    at: &'static str,
}

impl StaticCountExpectationErrorV2 {
    #[must_use]
    pub const fn at(&self) -> &'static str {
        self.at
    }
}

impl fmt::Display for StaticCountExpectationErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid Count-v2 static expectation at {}",
            self.at
        )
    }
}

impl std::error::Error for StaticCountExpectationErrorV2 {}

/// Strictly decoded but untrusted Count-v2 metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedCountMetadataV2 {
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
    platform: u8,
    status_bits: u8,
    actual_features: u64,
    allowed_features: u64,
    payload_bytes: u32,
    entry_offset: u32,
    code_bytes: u32,
    rodata_offset: u32,
    rodata_bytes: u32,
    literal_bytes: u32,
    source_identity: [u8; 32],
    artifact_identity: [u8; 32],
    binding_identity: [u8; 32],
    payload_sha256: [u8; 32],
    compile_identity: [u8; 32],
}

macro_rules! metadata_scalar_getter {
    ($name:ident, $type:ty) => {
        #[must_use]
        pub const fn $name(&self) -> $type {
            self.$name
        }
    };
}

impl ClaimedCountMetadataV2 {
    metadata_scalar_getter!(format_version, u16);
    metadata_scalar_getter!(record_bytes, u16);
    metadata_scalar_getter!(backend_version, u16);
    metadata_scalar_getter!(algorithm_version, u16);
    metadata_scalar_getter!(kir_semantics_version, u16);
    metadata_scalar_getter!(kir_abi_version, u16);
    metadata_scalar_getter!(abi_schema, u16);
    metadata_scalar_getter!(max_literal_bytes, u16);
    metadata_scalar_getter!(abi_kind, u8);
    metadata_scalar_getter!(output_kind, u8);
    metadata_scalar_getter!(architecture, u8);
    metadata_scalar_getter!(pointer_width, u8);
    metadata_scalar_getter!(target_abi, u8);
    metadata_scalar_getter!(platform, u8);
    metadata_scalar_getter!(status_bits, u8);
    metadata_scalar_getter!(actual_features, u64);
    metadata_scalar_getter!(allowed_features, u64);
    metadata_scalar_getter!(payload_bytes, u32);
    metadata_scalar_getter!(entry_offset, u32);
    metadata_scalar_getter!(code_bytes, u32);
    metadata_scalar_getter!(rodata_offset, u32);
    metadata_scalar_getter!(rodata_bytes, u32);
    metadata_scalar_getter!(literal_bytes, u32);

    #[must_use]
    pub const fn little_endian(&self) -> bool {
        self.little_endian == 1
    }

    #[must_use]
    pub const fn source_identity(&self) -> &[u8; 32] {
        &self.source_identity
    }

    #[must_use]
    pub const fn artifact_identity(&self) -> &[u8; 32] {
        &self.artifact_identity
    }

    #[must_use]
    pub const fn binding_identity(&self) -> &[u8; 32] {
        &self.binding_identity
    }

    #[must_use]
    pub const fn payload_sha256(&self) -> &[u8; 32] {
        &self.payload_sha256
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        &self.compile_identity
    }
}

/// Decode and validate one complete canonical Count-v2 metadata record.
pub fn inspect_count_metadata_v2(
    bytes: &[u8; METADATA_BYTES_V2],
) -> Result<ClaimedCountMetadataV2, CountMetadataErrorV2> {
    let mut reader = Reader::new(bytes);
    reader.expect(&METADATA_MAGIC_V2, "metadata magic")?;
    let metadata = ClaimedCountMetadataV2 {
        format_version: reader.u16("metadata version")?,
        record_bytes: reader.u16("metadata record bytes")?,
        backend_version: reader.u16("backend version")?,
        algorithm_version: reader.u16("algorithm version")?,
        kir_semantics_version: reader.u16("KIR semantics version")?,
        kir_abi_version: reader.u16("KIR ABI version")?,
        abi_schema: reader.u16("call ABI schema")?,
        max_literal_bytes: reader.u16("maximum literal bytes")?,
        abi_kind: reader.u8("ABI kind")?,
        output_kind: reader.u8("output kind")?,
        architecture: reader.u8("architecture")?,
        little_endian: reader.u8("byte order")?,
        pointer_width: reader.u8("pointer width")?,
        target_abi: reader.u8("target ABI")?,
        platform: reader.u8("platform")?,
        status_bits: reader.u8("status width")?,
        actual_features: reader.u64("actual features")?,
        allowed_features: reader.u64("allowed features")?,
        payload_bytes: reader.u32("payload bytes")?,
        entry_offset: reader.u32("entry offset")?,
        code_bytes: reader.u32("code bytes")?,
        rodata_offset: reader.u32("rodata offset")?,
        rodata_bytes: reader.u32("rodata bytes")?,
        literal_bytes: reader.u32("literal bytes")?,
        source_identity: reader.array("source identity")?,
        artifact_identity: reader.array("artifact identity")?,
        binding_identity: reader.array("binding identity")?,
        payload_sha256: reader.array("payload digest")?,
        compile_identity: reader.array("compile identity")?,
    };
    if reader.position() != bytes.len() {
        return Err(metadata_error("metadata trailing bytes"));
    }
    validate_metadata_shape(metadata)?;
    Ok(metadata)
}

fn validate_metadata_shape(metadata: ClaimedCountMetadataV2) -> Result<(), CountMetadataErrorV2> {
    if metadata.format_version != METADATA_VERSION_V2
        || usize::from(metadata.record_bytes) != METADATA_BYTES_V2
        || metadata.abi_kind != COUNT_ABI_KIND_V2
        || metadata.output_kind != COUNT_OUTPUT_KIND_V2
        || metadata.abi_schema != CALL_ABI_SCHEMA_V2
        || metadata.platform != COUNT_PLATFORM_MACOS_V2
        || metadata.status_bits != STATUS_BITS_V2
        || metadata.entry_offset != ENTRY_OFFSET_V2
        || metadata.little_endian != 1
        || metadata.actual_features & !metadata.allowed_features != 0
        || metadata.binding_identity == [0; 32]
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
    {
        return Err(metadata_error("image layout"));
    }
    Ok(())
}

fn metadata_support_row_is_explicit(metadata: ClaimedCountMetadataV2) -> bool {
    SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2.iter().any(|support| {
        metadata.backend_version == support.backend_version.0
            && metadata.algorithm_version == support.algorithm_version
            && metadata.kir_semantics_version == support.kir_semantics_version
            && metadata.kir_abi_version == support.kir_abi_version
            && metadata.output_kind == support.output_kind
            && metadata.architecture == support.architecture
            && metadata.little_endian == u8::from(support.little_endian)
            && metadata.pointer_width == support.pointer_width
            && metadata.target_abi == support.target_abi
            && metadata.allowed_features == support.allowed_features.bits()
            && metadata.max_literal_bytes == support.max_literal_bytes
    })
}

/// Canonical and internally consistent expectation bytes remain untrusted.
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
    metadata: ClaimedCountMetadataV2,
    expectation_identity: [u8; 32],
}

macro_rules! expectation_identity_getter {
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

    expectation_identity_getter!(manifest_identity);
    expectation_identity_getter!(policy_limits_identity);
    expectation_identity_getter!(semantic_binding_identity);
    expectation_identity_getter!(planning_receipt_identity);
    expectation_identity_getter!(live_literal_identity);
    expectation_identity_getter!(program_identity);
    expectation_identity_getter!(image_identity);
    expectation_identity_getter!(object_binding_identity);
    expectation_identity_getter!(compile_identity);
    expectation_identity_getter!(object_identity);
    expectation_identity_getter!(receipt_identity);
    expectation_identity_getter!(resource_receipt_identity);
    expectation_identity_getter!(expectation_identity);

    #[must_use]
    pub const fn live_literal_bytes(&self) -> u32 {
        self.live_literal_bytes
    }

    #[must_use]
    pub const fn metadata(&self) -> ClaimedCountMetadataV2 {
        self.metadata
    }
}

/// Strictly inspect arbitrary bytes for the fixed Count-v2 expectation shape.
pub fn inspect_static_count_expectation_v2(
    bytes: &[u8],
) -> Result<ClaimedStaticCountExpectationV2, StaticCountExpectationErrorV2> {
    if bytes.len() != STATIC_COUNT_EXPECTATION_BYTES_V2 {
        return Err(expectation_error("record bytes"));
    }
    let mut reader = ExpectationReader::new(bytes);
    reader.expect(&STATIC_EXPECTATION_MAGIC_V2, "expectation magic")?;
    let schema_version = reader.u16("expectation schema")?;
    let compiler_version = reader.u16("compiler version")?;
    let record_bytes = reader.u32("expectation record bytes")?;
    if schema_version != AOT_STATIC_EXPECTATION_SCHEMA_VERSION_V2
        || compiler_version != AOT_COMPILER_VERSION_V2
        || usize::try_from(record_bytes).ok() != Some(STATIC_COUNT_EXPECTATION_BYTES_V2)
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
        return Err(expectation_error("metadata envelope"));
    }
    let metadata_bytes = reader.array("metadata")?;
    let metadata = inspect_count_metadata_v2(&metadata_bytes)
        .map_err(|_| expectation_error("metadata contract"))?;
    if reader.position() != STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2 {
        return Err(expectation_error("expectation identity offset"));
    }
    let expectation_identity = reader.array("expectation identity")?;
    let body = bytes
        .get(..STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2)
        .ok_or_else(|| expectation_error("expectation identity body"))?;
    let mut hasher = Sha256::new();
    hasher.update(STATIC_EXPECTATION_IDENTITY_DOMAIN_V2);
    hasher.update(body);
    let computed_identity: [u8; 32] = hasher.finalize().into();
    if reader.position() != bytes.len() || computed_identity != expectation_identity {
        return Err(expectation_error("expectation identity"));
    }
    validate_expectation_metadata(
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
        expectation_identity,
    })
}

fn validate_expectation_metadata(
    metadata: ClaimedCountMetadataV2,
    live_literal_bytes: u32,
    program_identity: &[u8; 32],
    image_identity: &[u8; 32],
    object_binding_identity: &[u8; 32],
    compile_identity: &[u8; 32],
) -> Result<(), StaticCountExpectationErrorV2> {
    let expected_features = if live_literal_bytes == 0 {
        AotCountCpuFeatures::NONE.bits()
    } else {
        AotCountCpuFeatures::ASIMD.bits()
    };
    if metadata.actual_features != expected_features
        || metadata.literal_bytes != live_literal_bytes
        || live_literal_bytes > u32::from(metadata.max_literal_bytes)
        || metadata.source_identity != *program_identity
        || metadata.artifact_identity != *image_identity
        || metadata.binding_identity != *object_binding_identity
        || metadata.compile_identity != *compile_identity
    {
        return Err(expectation_error("metadata expectation binding"));
    }
    Ok(())
}

const fn metadata_error(at: &'static str) -> CountMetadataErrorV2 {
    CountMetadataErrorV2 { at }
}

const fn expectation_error(at: &'static str) -> StaticCountExpectationErrorV2 {
    StaticCountExpectationErrorV2 { at }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, bytes: usize, at: &'static str) -> Result<&'a [u8], CountMetadataErrorV2> {
        let end = self
            .position
            .checked_add(bytes)
            .ok_or_else(|| metadata_error(at))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| metadata_error(at))?;
        self.position = end;
        Ok(value)
    }

    fn expect(&mut self, value: &[u8], at: &'static str) -> Result<(), CountMetadataErrorV2> {
        if self.take(value.len(), at)? == value {
            Ok(())
        } else {
            Err(metadata_error(at))
        }
    }

    fn u8(&mut self, at: &'static str) -> Result<u8, CountMetadataErrorV2> {
        self.take(1, at)?
            .first()
            .copied()
            .ok_or_else(|| metadata_error(at))
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, CountMetadataErrorV2> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, CountMetadataErrorV2> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn u64(&mut self, at: &'static str) -> Result<u64, CountMetadataErrorV2> {
        Ok(u64::from_le_bytes(self.array(at)?))
    }

    fn array<const BYTES: usize>(
        &mut self,
        at: &'static str,
    ) -> Result<[u8; BYTES], CountMetadataErrorV2> {
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
        bytes: usize,
        at: &'static str,
    ) -> Result<&'a [u8], StaticCountExpectationErrorV2> {
        let end = self
            .position
            .checked_add(bytes)
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
    ) -> Result<(), StaticCountExpectationErrorV2> {
        if self.take(value.len(), at)? == value {
            Ok(())
        } else {
            Err(expectation_error(at))
        }
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, StaticCountExpectationErrorV2> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, StaticCountExpectationErrorV2> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn array<const BYTES: usize>(
        &mut self,
        at: &'static str,
    ) -> Result<[u8; BYTES], StaticCountExpectationErrorV2> {
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
    fn wire_widths_and_current_support_are_literal() {
        assert_eq!(METADATA_BYTES_V2, 232);
        assert_eq!(STATIC_COUNT_EXPECTATION_BYTES_V2, 672);
        assert_eq!(STATIC_COUNT_EXPECTATION_METADATA_OFFSET_V2, 408);
        assert_eq!(STATIC_COUNT_EXPECTATION_IDENTITY_OFFSET_V2, 640);
        assert_eq!(SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2.len(), 1);
        let support = SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2[0];
        assert_eq!(support.backend_version.0, 0xa002);
        assert_eq!(support.algorithm_version, 4);
        assert_eq!(support.kir_semantics_version, 1);
        assert_eq!(support.kir_abi_version, 1);
        assert_eq!(support.allowed_features.bits(), 1);
    }

    #[test]
    fn metadata_projection_retains_fields_not_a_second_wire_record() {
        assert_eq!(core::mem::size_of::<ClaimedCountMetadataV2>(), 224);
        assert!(
            core::mem::size_of::<ClaimedCountMetadataV2>() < METADATA_BYTES_V2,
            "a fields-only projection must not embed the 232-byte wire record"
        );
    }

    #[test]
    fn expectation_projection_retains_fields_not_embedded_wire_copies() {
        assert_eq!(core::mem::size_of::<ClaimedStaticCountExpectationV2>(), 656);
        assert!(
            core::mem::size_of::<ClaimedStaticCountExpectationV2>()
                < STATIC_COUNT_EXPECTATION_BYTES_V2,
            "the production claim must not retain metadata or expectation wire copies"
        );
    }

    #[test]
    fn zero_records_are_refused() {
        assert!(inspect_count_metadata_v2(&[0; METADATA_BYTES_V2]).is_err());
        assert!(
            inspect_static_count_expectation_v2(&[0; STATIC_COUNT_EXPECTATION_BYTES_V2]).is_err()
        );
    }
}
