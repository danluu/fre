//! Claim-side Linux Search tag21 `SelectedEnd` register-return V2 contract.
//!
//! This module is intentionally parallel to, rather than an extension of, the
//! crate's Search V1 Span wire. Successful inspection proves only canonical
//! internal consistency. It does not grant compiler, linker, runtime,
//! qualification, or deployment authority.

use core::fmt;

use sha2::{Digest, Sha256};

/// Published Search `SelectedEnd` metadata format version.
pub const SEARCH_SELECTED_END_METADATA_VERSION_V2: u16 = 2;
/// Exact canonical Search `SelectedEnd` metadata width.
pub const SEARCH_SELECTED_END_METADATA_BYTES_V2: usize = 224;
/// Search register-return V2 generated entries begin at the payload base.
pub const SEARCH_SELECTED_END_ENTRY_OFFSET_V2: u32 = 0;
/// Scan-algorithm tag for the fixed-VL16 SVE2 implementation.
pub const SEARCH_SELECTED_END_BACKEND_TAG21_V2: u16 = 21;
/// Metadata ABI-kind tag for register return.
pub const SEARCH_SELECTED_END_ABI_KIND_V2: u8 = 2;
/// Metadata output-kind tag for an absolute selected match end.
pub const SEARCH_SELECTED_END_OUTPUT_KIND_V2: u8 = 2;
/// Target architecture tag for AArch64.
pub const SEARCH_SELECTED_END_ARCHITECTURE_AARCH64_V2: u8 = 1;
/// Canonical little-endian byte-order tag.
pub const SEARCH_SELECTED_END_LITTLE_ENDIAN_V2: u8 = 1;
/// Canonical target pointer width.
pub const SEARCH_SELECTED_END_POINTER_WIDTH_V2: u8 = 64;
/// Target ABI tag for AAPCS64.
pub const SEARCH_SELECTED_END_TARGET_ABI_AAPCS64_V2: u8 = 1;
/// Object platform tag for Linux ELF.
pub const SEARCH_SELECTED_END_PLATFORM_LINUX_V2: u8 = 2;
/// Width of the scalar return register.
pub const SEARCH_SELECTED_END_RETURN_BITS_V2: u8 = 64;
/// Raw four-argument register-return call ABI schema.
pub const SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2: u16 = 2;
/// Zero means miss; nonzero means the absolute exclusive selected match end.
pub const SEARCH_SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2: u8 = 1;
/// The window is half-open and the returned end is haystack-absolute.
pub const SEARCH_SELECTED_END_WINDOW_HALF_OPEN_ABSOLUTE_END_V2: u8 = 1;
/// Fixed active SVE/SVE2 vector width admitted by this tag21 slice.
pub const SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2: u16 = 16;
/// Exact ASIMD+SVE+SVE2 feature bitmap required by tag21.
pub const SEARCH_SELECTED_END_REQUIRED_FEATURES_V2: u64 = 7;
/// Exact live literal width admitted by the fixed-VL16 tag21 slice.
pub const SEARCH_SELECTED_END_LITERAL_BYTES_V2: u32 = 16;

/// Identity-derived external-symbol schema carried by the V2 compile digest.
pub const EXPORTED_SYMBOL_SCHEMA_VERSION_V2: u16 = 2;
/// Full lowercase hexadecimal compile identity in every generated V2 symbol.
pub const EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2: u16 = 64;
/// ELF `STB_GLOBAL | STT_FUNC` for the identity-suffixed entry.
pub const EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V2: u8 = 0x12;
/// ELF `STB_GLOBAL | STT_OBJECT` for payload and metadata objects.
pub const EXPORTED_SYMBOL_INFO_ELF_OBJECT_V2: u8 = 0x11;
/// ELF `STV_HIDDEN` for all identity-suffixed implementation symbols.
pub const EXPORTED_SYMBOL_VISIBILITY_HIDDEN_V2: u8 = 2;
/// Identity-suffixed register-return entry prefix.
pub const SEARCH_SELECTED_END_ENTRY_SYMBOL_PREFIX_V2: &str =
    "fre_aot_search_selected_end_entry_v2_";
/// Identity-suffixed register-return payload prefix.
pub const SELECTED_END_PAYLOAD_SYMBOL_PREFIX_V2: &str = "fre_aot_search_selected_end_payload_v2_";
/// Identity-suffixed register-return metadata prefix.
pub const SELECTED_END_METADATA_SYMBOL_PREFIX_V2: &str = "fre_aot_search_selected_end_metadata_v2_";

/// Source-first compiler version admitted by the V2 expectation.
pub const AOT_SEARCH_SELECTED_END_COMPILER_VERSION_V2: u16 = 2;
/// Schema of the domain-separated static V2 expectation.
pub const AOT_STATIC_SEARCH_SELECTED_END_EXPECTATION_SCHEMA_VERSION_V2: u16 = 2;
/// Fixed byte offset at which the metadata record begins.
pub const STATIC_SEARCH_SELECTED_END_EXPECTATION_METADATA_OFFSET_V2: usize = 352;
/// Fixed byte offset at which the expectation identity begins.
pub const STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2: usize = 576;
/// Exact canonical static Search `SelectedEnd` expectation width.
pub const STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2: usize = 608;
/// Bytes covered by the domain-separated expectation identity.
pub const STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_BODY_BYTES_V2: usize =
    STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2;

/// The exact register-return ABI has four arguments.
pub const SEARCH_SELECTED_END_ARGUMENT_COUNT_V2: u8 = 4;
/// AArch64 register tag for scalar result register `x0`.
pub const SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2: u8 = 0;
/// Register return has no caller-owned result slot.
pub const SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2: u16 = 0;
/// Canonical no-match return.
pub const SEARCH_SELECTED_END_NO_MATCH_SENTINEL_V2: u64 = 0;
/// The exact-literal slice admits no start anchor.
pub const SEARCH_SELECTED_END_DEFAULT_START_ANCHOR_V2: u8 = 0;
/// The exact-literal slice admits no end anchor.
pub const SEARCH_SELECTED_END_DEFAULT_END_ANCHOR_V2: u8 = 0;

/// Exact fixed-width expectation wire. Possessing these bytes grants no
/// compiler, linker, runtime, qualification, or deployment authority.
pub type StaticSearchSelectedEndExpectationV2 =
    [u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2];

const SEARCH_SELECTED_END_METADATA_MAGIC_V2: [u8; 8] = *b"FRESE64\x02";
const STATIC_SEARCH_SELECTED_END_EXPECTATION_MAGIC_V2: [u8; 8] = *b"FRESEX\0\x02";
const STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-STATIC-SEARCH-SELECTED-END-EXPECTATION-IDENTITY\0\x02";
const ELF_SEARCH_SELECTED_END_COMPILE_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-ELF-SEARCH-SELECTED-END-COMPILE\0\x02";

const ELF_CLASS_64_V2: u8 = 2;
const ELF_DATA_LSB_V2: u8 = 1;
const ELF_VERSION_CURRENT_V2: u8 = 1;
const ELF_OS_ABI_SYSV_V2: u8 = 0;
const ELF_RELOCATABLE_TYPE_V2: u16 = 1;
const ELF_MACHINE_AARCH64_V2: u16 = 183;

const EXPECTATION_HEADER_BYTES_V2: usize = 64;
const EXPECTATION_IDENTITY_BYTES_V2: usize = 32;
const EXPECTATION_MANIFEST_IDENTITY_OFFSET_V2: usize = EXPECTATION_HEADER_BYTES_V2;
const EXPECTATION_SEMANTIC_BINDING_IDENTITY_OFFSET_V2: usize =
    EXPECTATION_MANIFEST_IDENTITY_OFFSET_V2 + 32;
const EXPECTATION_LITERAL_IDENTITY_OFFSET_V2: usize =
    EXPECTATION_SEMANTIC_BINDING_IDENTITY_OFFSET_V2 + 32;
const EXPECTATION_KIR_IDENTITY_OFFSET_V2: usize = EXPECTATION_LITERAL_IDENTITY_OFFSET_V2 + 32;
const EXPECTATION_ARTIFACT_IDENTITY_OFFSET_V2: usize = EXPECTATION_KIR_IDENTITY_OFFSET_V2 + 32;
const EXPECTATION_BINDING_IDENTITY_OFFSET_V2: usize = EXPECTATION_ARTIFACT_IDENTITY_OFFSET_V2 + 32;
const EXPECTATION_COMPILE_IDENTITY_OFFSET_V2: usize = EXPECTATION_BINDING_IDENTITY_OFFSET_V2 + 32;
const EXPECTATION_OBJECT_IDENTITY_OFFSET_V2: usize = EXPECTATION_COMPILE_IDENTITY_OFFSET_V2 + 32;
const EXPECTATION_RECEIPT_IDENTITY_OFFSET_V2: usize = EXPECTATION_OBJECT_IDENTITY_OFFSET_V2 + 32;

const _: () = assert!(SEARCH_SELECTED_END_METADATA_BYTES_V2 == 224);
const _: () = assert!(EXPECTATION_MANIFEST_IDENTITY_OFFSET_V2 == 64);
const _: () = assert!(EXPECTATION_SEMANTIC_BINDING_IDENTITY_OFFSET_V2 == 96);
const _: () = assert!(EXPECTATION_LITERAL_IDENTITY_OFFSET_V2 == 128);
const _: () = assert!(EXPECTATION_KIR_IDENTITY_OFFSET_V2 == 160);
const _: () = assert!(EXPECTATION_ARTIFACT_IDENTITY_OFFSET_V2 == 192);
const _: () = assert!(EXPECTATION_BINDING_IDENTITY_OFFSET_V2 == 224);
const _: () = assert!(EXPECTATION_COMPILE_IDENTITY_OFFSET_V2 == 256);
const _: () = assert!(EXPECTATION_OBJECT_IDENTITY_OFFSET_V2 == 288);
const _: () = assert!(EXPECTATION_RECEIPT_IDENTITY_OFFSET_V2 == 320);
const _: () = assert!(
    EXPECTATION_RECEIPT_IDENTITY_OFFSET_V2 + 32
        == STATIC_SEARCH_SELECTED_END_EXPECTATION_METADATA_OFFSET_V2
);
const _: () = assert!(
    STATIC_SEARCH_SELECTED_END_EXPECTATION_METADATA_OFFSET_V2
        + SEARCH_SELECTED_END_METADATA_BYTES_V2
        == STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2
);
const _: () = assert!(
    STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2 + EXPECTATION_IDENTITY_BYTES_V2
        == STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2
);

/// A fixed byte sequence was not canonical Search `SelectedEnd` V2 metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchSelectedEndMetadataErrorV2 {
    at: &'static str,
}

impl SearchSelectedEndMetadataErrorV2 {
    /// Return the field or invariant that rejected the record.
    #[must_use]
    pub const fn at(&self) -> &'static str {
        self.at
    }
}

impl fmt::Display for SearchSelectedEndMetadataErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid Search SelectedEnd V2 metadata at {}",
            self.at
        )
    }
}

impl std::error::Error for SearchSelectedEndMetadataErrorV2 {}

/// A V2 expectation was not canonical or internally consistent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticSearchSelectedEndExpectationErrorV2 {
    at: &'static str,
}

impl StaticSearchSelectedEndExpectationErrorV2 {
    /// Return the field or invariant that rejected the record.
    #[must_use]
    pub const fn at(&self) -> &'static str {
        self.at
    }
}

impl fmt::Display for StaticSearchSelectedEndExpectationErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid static Search SelectedEnd V2 expectation at {}",
            self.at
        )
    }
}

impl std::error::Error for StaticSearchSelectedEndExpectationErrorV2 {}

/// Strictly decoded but untrusted Search `SelectedEnd` V2 metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedSearchSelectedEndMetadataV2 {
    format_version: u16,
    record_bytes: u16,
    backend_version: u16,
    abi_kind: u8,
    output_kind: u8,
    architecture: u8,
    little_endian: u8,
    pointer_width: u8,
    target_abi: u8,
    platform: u8,
    return_bits: u8,
    call_abi_schema: u16,
    return_encoding: u8,
    window_contract: u8,
    fixed_active_vector_bytes: u16,
    reserved: u32,
    features: u64,
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

impl ClaimedSearchSelectedEndMetadataV2 {
    metadata_scalar_getter!(format_version, u16);
    metadata_scalar_getter!(record_bytes, u16);
    metadata_scalar_getter!(backend_version, u16);
    metadata_scalar_getter!(abi_kind, u8);
    metadata_scalar_getter!(output_kind, u8);
    metadata_scalar_getter!(architecture, u8);
    metadata_scalar_getter!(pointer_width, u8);
    metadata_scalar_getter!(target_abi, u8);
    metadata_scalar_getter!(platform, u8);
    metadata_scalar_getter!(return_bits, u8);
    metadata_scalar_getter!(call_abi_schema, u16);
    metadata_scalar_getter!(return_encoding, u8);
    metadata_scalar_getter!(window_contract, u8);
    metadata_scalar_getter!(fixed_active_vector_bytes, u16);
    metadata_scalar_getter!(features, u64);
    metadata_scalar_getter!(payload_bytes, u32);
    metadata_scalar_getter!(entry_offset, u32);
    metadata_scalar_getter!(code_bytes, u32);
    metadata_scalar_getter!(rodata_offset, u32);
    metadata_scalar_getter!(rodata_bytes, u32);
    metadata_scalar_getter!(literal_bytes, u32);

    /// Whether the canonical byte-order tag is little endian.
    #[must_use]
    pub const fn little_endian(&self) -> bool {
        self.little_endian == SEARCH_SELECTED_END_LITTLE_ENDIAN_V2
    }

    /// Exact KIR/source identity carried by the object.
    #[must_use]
    pub const fn source_identity(&self) -> &[u8; 32] {
        &self.source_identity
    }

    /// Exact sealed emitter-artifact identity carried by the object.
    #[must_use]
    pub const fn artifact_identity(&self) -> &[u8; 32] {
        &self.artifact_identity
    }

    /// Exact semantic binding identity carried by the object.
    #[must_use]
    pub const fn binding_identity(&self) -> &[u8; 32] {
        &self.binding_identity
    }

    /// Digest of the complete implementation payload.
    #[must_use]
    pub const fn payload_sha256(&self) -> &[u8; 32] {
        &self.payload_sha256
    }

    /// Domain-separated compile identity naming this implementation.
    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        &self.compile_identity
    }
}

/// Decode and validate exactly one complete V2 metadata record.
///
/// The returned value remains an untrusted claim. In particular, this
/// function does not establish mapped-code or runtime-call authority.
pub fn inspect_search_selected_end_metadata_v2(
    bytes: &[u8],
) -> Result<ClaimedSearchSelectedEndMetadataV2, SearchSelectedEndMetadataErrorV2> {
    if bytes.len() != SEARCH_SELECTED_END_METADATA_BYTES_V2 {
        return Err(metadata_error("record bytes"));
    }
    let mut reader = MetadataReader::new(bytes);
    reader.expect(&SEARCH_SELECTED_END_METADATA_MAGIC_V2, "metadata magic")?;
    let metadata = ClaimedSearchSelectedEndMetadataV2 {
        format_version: reader.u16("metadata version")?,
        record_bytes: reader.u16("metadata record bytes")?,
        backend_version: reader.u16("backend version")?,
        abi_kind: reader.u8("ABI kind")?,
        output_kind: reader.u8("output kind")?,
        architecture: reader.u8("architecture")?,
        little_endian: reader.u8("byte order")?,
        pointer_width: reader.u8("pointer width")?,
        target_abi: reader.u8("target ABI")?,
        platform: reader.u8("platform")?,
        return_bits: reader.u8("return width")?,
        call_abi_schema: reader.u16("call ABI schema")?,
        return_encoding: reader.u8("return encoding")?,
        window_contract: reader.u8("window contract")?,
        fixed_active_vector_bytes: reader.u16("fixed active vector bytes")?,
        reserved: reader.u32("reserved")?,
        features: reader.u64("features")?,
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
    let computed_compile_identity = compute_metadata_compile_identity_v2(metadata);
    if metadata.compile_identity != computed_compile_identity {
        return Err(metadata_error("compile identity"));
    }
    Ok(metadata)
}

fn validate_metadata_shape(
    metadata: ClaimedSearchSelectedEndMetadataV2,
) -> Result<(), SearchSelectedEndMetadataErrorV2> {
    if metadata.format_version != SEARCH_SELECTED_END_METADATA_VERSION_V2
        || usize::from(metadata.record_bytes) != SEARCH_SELECTED_END_METADATA_BYTES_V2
        || metadata.backend_version != SEARCH_SELECTED_END_BACKEND_TAG21_V2
        || metadata.abi_kind != SEARCH_SELECTED_END_ABI_KIND_V2
        || metadata.output_kind != SEARCH_SELECTED_END_OUTPUT_KIND_V2
        || metadata.architecture != SEARCH_SELECTED_END_ARCHITECTURE_AARCH64_V2
        || metadata.little_endian != SEARCH_SELECTED_END_LITTLE_ENDIAN_V2
        || metadata.pointer_width != SEARCH_SELECTED_END_POINTER_WIDTH_V2
        || metadata.target_abi != SEARCH_SELECTED_END_TARGET_ABI_AAPCS64_V2
        || metadata.platform != SEARCH_SELECTED_END_PLATFORM_LINUX_V2
        || metadata.return_bits != SEARCH_SELECTED_END_RETURN_BITS_V2
        || metadata.call_abi_schema != SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2
        || metadata.return_encoding != SEARCH_SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2
        || metadata.window_contract != SEARCH_SELECTED_END_WINDOW_HALF_OPEN_ABSOLUTE_END_V2
        || metadata.fixed_active_vector_bytes != SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2
        || metadata.reserved != 0
        || metadata.features != SEARCH_SELECTED_END_REQUIRED_FEATURES_V2
        || metadata.entry_offset != SEARCH_SELECTED_END_ENTRY_OFFSET_V2
        || metadata.rodata_bytes != SEARCH_SELECTED_END_LITERAL_BYTES_V2
        || metadata.literal_bytes != SEARCH_SELECTED_END_LITERAL_BYTES_V2
        || metadata.source_identity == [0; 32]
        || metadata.artifact_identity == [0; 32]
        || metadata.binding_identity == [0; 32]
        || metadata.payload_sha256 == [0; 32]
        || metadata.compile_identity == [0; 32]
    {
        return Err(metadata_error("metadata contract"));
    }
    if metadata.code_bytes == 0
        || !metadata.code_bytes.is_multiple_of(4)
        || !metadata.rodata_offset.is_multiple_of(16)
        || metadata.rodata_offset < metadata.code_bytes
        || metadata.rodata_offset.checked_add(metadata.rodata_bytes) != Some(metadata.payload_bytes)
    {
        return Err(metadata_error("image layout"));
    }
    Ok(())
}

fn compute_metadata_compile_identity_v2(metadata: ClaimedSearchSelectedEndMetadataV2) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ELF_SEARCH_SELECTED_END_COMPILE_IDENTITY_DOMAIN_V2);
    hasher.update(SEARCH_SELECTED_END_METADATA_VERSION_V2.to_le_bytes());
    hasher.update(EXPORTED_SYMBOL_SCHEMA_VERSION_V2.to_le_bytes());
    hasher.update(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2.to_le_bytes());
    for (prefix, symbol_info) in [
        (
            SEARCH_SELECTED_END_ENTRY_SYMBOL_PREFIX_V2,
            EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V2,
        ),
        (
            SELECTED_END_PAYLOAD_SYMBOL_PREFIX_V2,
            EXPORTED_SYMBOL_INFO_ELF_OBJECT_V2,
        ),
        (
            SELECTED_END_METADATA_SYMBOL_PREFIX_V2,
            EXPORTED_SYMBOL_INFO_ELF_OBJECT_V2,
        ),
    ] {
        hasher.update(
            u16::try_from(prefix.len())
                .expect("fixed V2 symbol prefix length fits u16")
                .to_le_bytes(),
        );
        hasher.update(prefix.as_bytes());
        hasher.update([symbol_info, EXPORTED_SYMBOL_VISIBILITY_HIDDEN_V2]);
    }
    hasher.update([
        ELF_CLASS_64_V2,
        ELF_DATA_LSB_V2,
        ELF_VERSION_CURRENT_V2,
        ELF_OS_ABI_SYSV_V2,
    ]);
    hasher.update(ELF_RELOCATABLE_TYPE_V2.to_le_bytes());
    hasher.update(ELF_MACHINE_AARCH64_V2.to_le_bytes());
    let mut metadata_bytes = encode_metadata_v2(metadata);
    metadata_bytes[192..224].fill(0);
    hasher.update(metadata_bytes);
    hasher.finalize().into()
}

fn encode_metadata_v2(
    metadata: ClaimedSearchSelectedEndMetadataV2,
) -> [u8; SEARCH_SELECTED_END_METADATA_BYTES_V2] {
    let mut bytes = [0_u8; SEARCH_SELECTED_END_METADATA_BYTES_V2];
    bytes[0..8].copy_from_slice(&SEARCH_SELECTED_END_METADATA_MAGIC_V2);
    bytes[8..10].copy_from_slice(&metadata.format_version.to_le_bytes());
    bytes[10..12].copy_from_slice(&metadata.record_bytes.to_le_bytes());
    bytes[12..14].copy_from_slice(&metadata.backend_version.to_le_bytes());
    bytes[14] = metadata.abi_kind;
    bytes[15] = metadata.output_kind;
    bytes[16] = metadata.architecture;
    bytes[17] = metadata.little_endian;
    bytes[18] = metadata.pointer_width;
    bytes[19] = metadata.target_abi;
    bytes[20] = metadata.platform;
    bytes[21] = metadata.return_bits;
    bytes[22..24].copy_from_slice(&metadata.call_abi_schema.to_le_bytes());
    bytes[24] = metadata.return_encoding;
    bytes[25] = metadata.window_contract;
    bytes[26..28].copy_from_slice(&metadata.fixed_active_vector_bytes.to_le_bytes());
    bytes[28..32].copy_from_slice(&metadata.reserved.to_le_bytes());
    bytes[32..40].copy_from_slice(&metadata.features.to_le_bytes());
    bytes[40..44].copy_from_slice(&metadata.payload_bytes.to_le_bytes());
    bytes[44..48].copy_from_slice(&metadata.entry_offset.to_le_bytes());
    bytes[48..52].copy_from_slice(&metadata.code_bytes.to_le_bytes());
    bytes[52..56].copy_from_slice(&metadata.rodata_offset.to_le_bytes());
    bytes[56..60].copy_from_slice(&metadata.rodata_bytes.to_le_bytes());
    bytes[60..64].copy_from_slice(&metadata.literal_bytes.to_le_bytes());
    bytes[64..96].copy_from_slice(&metadata.source_identity);
    bytes[96..128].copy_from_slice(&metadata.artifact_identity);
    bytes[128..160].copy_from_slice(&metadata.binding_identity);
    bytes[160..192].copy_from_slice(&metadata.payload_sha256);
    bytes[192..224].copy_from_slice(&metadata.compile_identity);
    bytes
}

/// Canonical and internally consistent, but still untrusted, V2 expectation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedStaticSearchSelectedEndExpectationV2 {
    schema_version: u16,
    compiler_version: u16,
    metadata_record_bytes: u16,
    metadata_version: u16,
    backend_version: u16,
    call_abi_schema: u16,
    exported_symbol_schema: u16,
    output_kind: u8,
    anchor_start: u8,
    anchor_end: u8,
    architecture: u8,
    little_endian: u8,
    pointer_width: u8,
    target_abi: u8,
    platform: u8,
    return_bits: u8,
    exported_symbol_info: u8,
    return_encoding: u8,
    window_contract: u8,
    fixed_active_vector_bytes: u16,
    required_features: u64,
    live_literal_bytes: u32,
    argument_count: u8,
    return_register: u8,
    result_slot_bytes: u16,
    no_match_sentinel: u64,
    manifest_identity: [u8; 32],
    semantic_binding_identity: [u8; 32],
    literal_identity: [u8; 32],
    kir_identity: [u8; 32],
    artifact_identity: [u8; 32],
    binding_identity: [u8; 32],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    receipt_identity: [u8; 32],
    metadata: ClaimedSearchSelectedEndMetadataV2,
    expectation_identity: [u8; 32],
}

macro_rules! expectation_scalar_getter {
    ($name:ident, $type:ty) => {
        #[must_use]
        pub const fn $name(&self) -> $type {
            self.$name
        }
    };
}

macro_rules! expectation_identity_getter {
    ($name:ident) => {
        #[must_use]
        pub const fn $name(&self) -> &[u8; 32] {
            &self.$name
        }
    };
}

impl ClaimedStaticSearchSelectedEndExpectationV2 {
    expectation_scalar_getter!(schema_version, u16);
    expectation_scalar_getter!(compiler_version, u16);
    expectation_scalar_getter!(metadata_record_bytes, u16);
    expectation_scalar_getter!(metadata_version, u16);
    expectation_scalar_getter!(backend_version, u16);
    expectation_scalar_getter!(call_abi_schema, u16);
    expectation_scalar_getter!(exported_symbol_schema, u16);
    expectation_scalar_getter!(output_kind, u8);
    expectation_scalar_getter!(architecture, u8);
    expectation_scalar_getter!(pointer_width, u8);
    expectation_scalar_getter!(target_abi, u8);
    expectation_scalar_getter!(platform, u8);
    expectation_scalar_getter!(return_bits, u8);
    expectation_scalar_getter!(exported_symbol_info, u8);
    expectation_scalar_getter!(return_encoding, u8);
    expectation_scalar_getter!(window_contract, u8);
    expectation_scalar_getter!(fixed_active_vector_bytes, u16);
    expectation_scalar_getter!(required_features, u64);
    expectation_scalar_getter!(live_literal_bytes, u32);
    expectation_scalar_getter!(argument_count, u8);
    expectation_scalar_getter!(return_register, u8);
    expectation_scalar_getter!(result_slot_bytes, u16);
    expectation_scalar_getter!(no_match_sentinel, u64);

    /// Whether the expectation carries the canonical no-start-anchor tag.
    #[must_use]
    pub const fn anchor_start(&self) -> bool {
        self.anchor_start == 1
    }

    /// Whether the expectation carries the canonical no-end-anchor tag.
    #[must_use]
    pub const fn anchor_end(&self) -> bool {
        self.anchor_end == 1
    }

    /// Whether the canonical byte-order tag is little endian.
    #[must_use]
    pub const fn little_endian(&self) -> bool {
        self.little_endian == SEARCH_SELECTED_END_LITTLE_ENDIAN_V2
    }

    expectation_identity_getter!(manifest_identity);
    expectation_identity_getter!(semantic_binding_identity);
    expectation_identity_getter!(literal_identity);
    expectation_identity_getter!(kir_identity);
    expectation_identity_getter!(artifact_identity);
    expectation_identity_getter!(binding_identity);
    expectation_identity_getter!(compile_identity);
    expectation_identity_getter!(object_identity);
    expectation_identity_getter!(receipt_identity);
    expectation_identity_getter!(expectation_identity);

    /// Return the fully validated embedded metadata claim.
    #[must_use]
    pub const fn metadata(&self) -> ClaimedSearchSelectedEndMetadataV2 {
        self.metadata
    }
}

/// Compute the domain-separated identity of one exact V2 expectation body.
///
/// This authenticates bytes only to themselves and cannot grant runtime
/// authority.
#[must_use]
pub fn compute_static_search_selected_end_expectation_identity_v2(
    body: &[u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_BODY_BYTES_V2],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_DOMAIN_V2);
    hasher.update(body);
    hasher.finalize().into()
}

/// Strictly inspect arbitrary bytes for the fixed V2 expectation shape.
///
/// The call contract is exactly
/// `(haystack, haystack_len, window_start, window_end) -> x0`, where zero is a
/// miss and any nonzero value is an absolute exclusive selected match end.
/// Successful inspection does not authorize reading or calling a linked
/// address.
#[allow(
    clippy::too_many_lines,
    reason = "one linear decoder keeps every field, offset, correlation, and identity check auditable in wire order"
)]
pub fn inspect_static_search_selected_end_expectation_v2(
    bytes: &[u8],
) -> Result<ClaimedStaticSearchSelectedEndExpectationV2, StaticSearchSelectedEndExpectationErrorV2>
{
    if bytes.len() != STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2 {
        return Err(expectation_error("record bytes"));
    }
    let mut reader = ExpectationReader::new(bytes);
    reader.expect(
        &STATIC_SEARCH_SELECTED_END_EXPECTATION_MAGIC_V2,
        "expectation magic",
    )?;
    let schema_version = reader.u16("expectation schema")?;
    let compiler_version = reader.u16("compiler version")?;
    let record_bytes = reader.u32("expectation record bytes")?;
    let metadata_record_bytes = reader.u16("metadata record bytes")?;
    let metadata_version = reader.u16("metadata version")?;
    let backend_version = reader.u16("backend version")?;
    let call_abi_schema = reader.u16("call ABI schema")?;
    let exported_symbol_schema = reader.u16("exported symbol schema")?;
    let output_kind = reader.u8("output kind")?;
    let anchor_start = reader.u8("start anchor")?;
    let anchor_end = reader.u8("end anchor")?;
    let architecture = reader.u8("architecture")?;
    let little_endian = reader.u8("byte order")?;
    let pointer_width = reader.u8("pointer width")?;
    let target_abi = reader.u8("target ABI")?;
    let platform = reader.u8("platform")?;
    let return_bits = reader.u8("return width")?;
    let exported_symbol_info = reader.u8("exported symbol info")?;
    let return_encoding = reader.u8("return encoding")?;
    let window_contract = reader.u8("window contract")?;
    let fixed_active_vector_bytes = reader.u16("fixed active vector bytes")?;
    let required_features = reader.u64("required features")?;
    let live_literal_bytes = reader.u32("live literal bytes")?;
    let argument_count = reader.u8("argument count")?;
    let return_register = reader.u8("return register")?;
    let result_slot_bytes = reader.u16("result slot bytes")?;
    let no_match_sentinel = reader.u64("no-match sentinel")?;
    if schema_version != AOT_STATIC_SEARCH_SELECTED_END_EXPECTATION_SCHEMA_VERSION_V2
        || compiler_version != AOT_SEARCH_SELECTED_END_COMPILER_VERSION_V2
        || usize::try_from(record_bytes).ok()
            != Some(STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2)
        || usize::from(metadata_record_bytes) != SEARCH_SELECTED_END_METADATA_BYTES_V2
        || metadata_version != SEARCH_SELECTED_END_METADATA_VERSION_V2
        || backend_version != SEARCH_SELECTED_END_BACKEND_TAG21_V2
        || call_abi_schema != SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2
        || exported_symbol_schema != EXPORTED_SYMBOL_SCHEMA_VERSION_V2
        || output_kind != SEARCH_SELECTED_END_OUTPUT_KIND_V2
        || anchor_start != SEARCH_SELECTED_END_DEFAULT_START_ANCHOR_V2
        || anchor_end != SEARCH_SELECTED_END_DEFAULT_END_ANCHOR_V2
        || architecture != SEARCH_SELECTED_END_ARCHITECTURE_AARCH64_V2
        || little_endian != SEARCH_SELECTED_END_LITTLE_ENDIAN_V2
        || pointer_width != SEARCH_SELECTED_END_POINTER_WIDTH_V2
        || target_abi != SEARCH_SELECTED_END_TARGET_ABI_AAPCS64_V2
        || platform != SEARCH_SELECTED_END_PLATFORM_LINUX_V2
        || return_bits != SEARCH_SELECTED_END_RETURN_BITS_V2
        || exported_symbol_info != EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V2
        || return_encoding != SEARCH_SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2
        || window_contract != SEARCH_SELECTED_END_WINDOW_HALF_OPEN_ABSOLUTE_END_V2
        || fixed_active_vector_bytes != SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2
        || required_features != SEARCH_SELECTED_END_REQUIRED_FEATURES_V2
        || live_literal_bytes != SEARCH_SELECTED_END_LITERAL_BYTES_V2
        || argument_count != SEARCH_SELECTED_END_ARGUMENT_COUNT_V2
        || return_register != SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2
        || result_slot_bytes != SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2
        || no_match_sentinel != SEARCH_SELECTED_END_NO_MATCH_SENTINEL_V2
        || reader.position() != EXPECTATION_HEADER_BYTES_V2
    {
        return Err(expectation_error("expectation header"));
    }

    let manifest_identity = reader.array("manifest identity")?;
    let semantic_binding_identity = reader.array("semantic binding identity")?;
    let literal_identity = reader.array("literal identity")?;
    let kir_identity = reader.array("KIR identity")?;
    let artifact_identity = reader.array("artifact identity")?;
    let binding_identity = reader.array("binding identity")?;
    let compile_identity = reader.array("compile identity")?;
    let object_identity = reader.array("object identity")?;
    let receipt_identity = reader.array("compile receipt identity")?;
    if manifest_identity == [0; 32]
        || semantic_binding_identity == [0; 32]
        || literal_identity == [0; 32]
        || kir_identity == [0; 32]
        || artifact_identity == [0; 32]
        || binding_identity == [0; 32]
        || compile_identity == [0; 32]
        || object_identity == [0; 32]
        || receipt_identity == [0; 32]
    {
        return Err(expectation_error("zero identity"));
    }
    if reader.position() != STATIC_SEARCH_SELECTED_END_EXPECTATION_METADATA_OFFSET_V2 {
        return Err(expectation_error("metadata offset"));
    }
    let metadata_bytes: [u8; SEARCH_SELECTED_END_METADATA_BYTES_V2] = reader.array("metadata")?;
    let metadata = inspect_search_selected_end_metadata_v2(&metadata_bytes)
        .map_err(|_| expectation_error("metadata contract"))?;
    if reader.position() != STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2 {
        return Err(expectation_error("expectation identity offset"));
    }
    let expectation_identity = reader.array("expectation identity")?;
    let body: &[u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_BODY_BYTES_V2] = bytes
        .get(..STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2)
        .and_then(|body| body.try_into().ok())
        .ok_or_else(|| expectation_error("expectation identity body"))?;
    let computed_identity = compute_static_search_selected_end_expectation_identity_v2(body);
    if reader.position() != bytes.len()
        || expectation_identity == [0; 32]
        || expectation_identity != computed_identity
    {
        return Err(expectation_error("expectation identity"));
    }
    validate_expectation_metadata(
        metadata,
        metadata_record_bytes,
        metadata_version,
        backend_version,
        call_abi_schema,
        output_kind,
        architecture,
        little_endian,
        pointer_width,
        target_abi,
        platform,
        return_bits,
        return_encoding,
        window_contract,
        fixed_active_vector_bytes,
        required_features,
        live_literal_bytes,
        &kir_identity,
        &artifact_identity,
        &binding_identity,
        &compile_identity,
    )?;
    Ok(ClaimedStaticSearchSelectedEndExpectationV2 {
        schema_version,
        compiler_version,
        metadata_record_bytes,
        metadata_version,
        backend_version,
        call_abi_schema,
        exported_symbol_schema,
        output_kind,
        anchor_start,
        anchor_end,
        architecture,
        little_endian,
        pointer_width,
        target_abi,
        platform,
        return_bits,
        exported_symbol_info,
        return_encoding,
        window_contract,
        fixed_active_vector_bytes,
        required_features,
        live_literal_bytes,
        argument_count,
        return_register,
        result_slot_bytes,
        no_match_sentinel,
        manifest_identity,
        semantic_binding_identity,
        literal_identity,
        kir_identity,
        artifact_identity,
        binding_identity,
        compile_identity,
        object_identity,
        receipt_identity,
        metadata,
        expectation_identity,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments enumerate every duplicated expectation/metadata correlation"
)]
fn validate_expectation_metadata(
    metadata: ClaimedSearchSelectedEndMetadataV2,
    metadata_record_bytes: u16,
    metadata_version: u16,
    backend_version: u16,
    call_abi_schema: u16,
    output_kind: u8,
    architecture: u8,
    little_endian: u8,
    pointer_width: u8,
    target_abi: u8,
    platform: u8,
    return_bits: u8,
    return_encoding: u8,
    window_contract: u8,
    fixed_active_vector_bytes: u16,
    required_features: u64,
    live_literal_bytes: u32,
    kir_identity: &[u8; 32],
    artifact_identity: &[u8; 32],
    binding_identity: &[u8; 32],
    compile_identity: &[u8; 32],
) -> Result<(), StaticSearchSelectedEndExpectationErrorV2> {
    if metadata.record_bytes != metadata_record_bytes
        || metadata.format_version != metadata_version
        || metadata.backend_version != backend_version
        || metadata.call_abi_schema != call_abi_schema
        || metadata.output_kind != output_kind
        || metadata.architecture != architecture
        || metadata.little_endian != little_endian
        || metadata.pointer_width != pointer_width
        || metadata.target_abi != target_abi
        || metadata.platform != platform
        || metadata.return_bits != return_bits
        || metadata.return_encoding != return_encoding
        || metadata.window_contract != window_contract
        || metadata.fixed_active_vector_bytes != fixed_active_vector_bytes
        || metadata.features != required_features
        || metadata.literal_bytes != live_literal_bytes
        || metadata.rodata_bytes != live_literal_bytes
        || metadata.source_identity != *kir_identity
        || metadata.artifact_identity != *artifact_identity
        || metadata.binding_identity != *binding_identity
        || metadata.compile_identity != *compile_identity
    {
        return Err(expectation_error("metadata expectation binding"));
    }
    Ok(())
}

const fn metadata_error(at: &'static str) -> SearchSelectedEndMetadataErrorV2 {
    SearchSelectedEndMetadataErrorV2 { at }
}

const fn expectation_error(at: &'static str) -> StaticSearchSelectedEndExpectationErrorV2 {
    StaticSearchSelectedEndExpectationErrorV2 { at }
}

struct MetadataReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> MetadataReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(
        &mut self,
        count: usize,
        at: &'static str,
    ) -> Result<&'a [u8], SearchSelectedEndMetadataErrorV2> {
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

    fn expect(
        &mut self,
        expected: &[u8],
        at: &'static str,
    ) -> Result<(), SearchSelectedEndMetadataErrorV2> {
        if self.take(expected.len(), at)? == expected {
            Ok(())
        } else {
            Err(metadata_error(at))
        }
    }

    fn u8(&mut self, at: &'static str) -> Result<u8, SearchSelectedEndMetadataErrorV2> {
        Ok(self.take(1, at)?[0])
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, SearchSelectedEndMetadataErrorV2> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, SearchSelectedEndMetadataErrorV2> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn u64(&mut self, at: &'static str) -> Result<u64, SearchSelectedEndMetadataErrorV2> {
        Ok(u64::from_le_bytes(self.array(at)?))
    }

    fn array<const BYTES: usize>(
        &mut self,
        at: &'static str,
    ) -> Result<[u8; BYTES], SearchSelectedEndMetadataErrorV2> {
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
    ) -> Result<&'a [u8], StaticSearchSelectedEndExpectationErrorV2> {
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
        expected: &[u8],
        at: &'static str,
    ) -> Result<(), StaticSearchSelectedEndExpectationErrorV2> {
        if self.take(expected.len(), at)? == expected {
            Ok(())
        } else {
            Err(expectation_error(at))
        }
    }

    fn u8(&mut self, at: &'static str) -> Result<u8, StaticSearchSelectedEndExpectationErrorV2> {
        Ok(self.take(1, at)?[0])
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, StaticSearchSelectedEndExpectationErrorV2> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, StaticSearchSelectedEndExpectationErrorV2> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn u64(&mut self, at: &'static str) -> Result<u64, StaticSearchSelectedEndExpectationErrorV2> {
        Ok(u64::from_le_bytes(self.array(at)?))
    }

    fn array<const BYTES: usize>(
        &mut self,
        at: &'static str,
    ) -> Result<[u8; BYTES], StaticSearchSelectedEndExpectationErrorV2> {
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

    const METADATA_FORMAT_VERSION_OFFSET: usize = 8;
    const METADATA_RECORD_BYTES_OFFSET: usize = 10;
    const METADATA_BACKEND_VERSION_OFFSET: usize = 12;
    const METADATA_ABI_KIND_OFFSET: usize = 14;
    const METADATA_OUTPUT_KIND_OFFSET: usize = 15;
    const METADATA_ARCHITECTURE_OFFSET: usize = 16;
    const METADATA_LITTLE_ENDIAN_OFFSET: usize = 17;
    const METADATA_POINTER_WIDTH_OFFSET: usize = 18;
    const METADATA_TARGET_ABI_OFFSET: usize = 19;
    const METADATA_PLATFORM_OFFSET: usize = 20;
    const METADATA_RETURN_BITS_OFFSET: usize = 21;
    const METADATA_CALL_ABI_OFFSET: usize = 22;
    const METADATA_RETURN_ENCODING_OFFSET: usize = 24;
    const METADATA_WINDOW_CONTRACT_OFFSET: usize = 25;
    const METADATA_FIXED_ACTIVE_VECTOR_BYTES_OFFSET: usize = 26;
    const METADATA_RESERVED_OFFSET: usize = 28;
    const METADATA_FEATURES_OFFSET: usize = 32;
    const METADATA_PAYLOAD_BYTES_OFFSET: usize = 40;
    const METADATA_ENTRY_OFFSET_OFFSET: usize = 44;
    const METADATA_CODE_BYTES_OFFSET: usize = 48;
    const METADATA_RODATA_OFFSET_OFFSET: usize = 52;
    const METADATA_RODATA_BYTES_OFFSET: usize = 56;
    const METADATA_LITERAL_BYTES_OFFSET: usize = 60;
    const METADATA_SOURCE_IDENTITY_OFFSET: usize = 64;
    const METADATA_ARTIFACT_IDENTITY_OFFSET: usize = 96;
    const METADATA_BINDING_IDENTITY_OFFSET: usize = 128;
    const METADATA_PAYLOAD_DIGEST_OFFSET: usize = 160;
    const METADATA_COMPILE_IDENTITY_OFFSET: usize = 192;

    const EXPECTATION_SCHEMA_OFFSET: usize = 8;
    const EXPECTATION_COMPILER_OFFSET: usize = 10;
    const EXPECTATION_RECORD_BYTES_OFFSET: usize = 12;
    const EXPECTATION_METADATA_BYTES_OFFSET: usize = 16;
    const EXPECTATION_METADATA_VERSION_OFFSET: usize = 18;
    const EXPECTATION_BACKEND_OFFSET: usize = 20;
    const EXPECTATION_CALL_ABI_OFFSET: usize = 22;
    const EXPECTATION_SYMBOL_SCHEMA_OFFSET: usize = 24;
    const EXPECTATION_OUTPUT_OFFSET: usize = 26;
    const EXPECTATION_ANCHOR_START_OFFSET: usize = 27;
    const EXPECTATION_ANCHOR_END_OFFSET: usize = 28;
    const EXPECTATION_ARCHITECTURE_OFFSET: usize = 29;
    const EXPECTATION_LITTLE_ENDIAN_OFFSET: usize = 30;
    const EXPECTATION_POINTER_WIDTH_OFFSET: usize = 31;
    const EXPECTATION_TARGET_ABI_OFFSET: usize = 32;
    const EXPECTATION_PLATFORM_OFFSET: usize = 33;
    const EXPECTATION_RETURN_BITS_OFFSET: usize = 34;
    const EXPECTATION_SYMBOL_INFO_OFFSET: usize = 35;
    const EXPECTATION_RETURN_ENCODING_OFFSET: usize = 36;
    const EXPECTATION_WINDOW_CONTRACT_OFFSET: usize = 37;
    const EXPECTATION_FIXED_ACTIVE_VECTOR_BYTES_OFFSET: usize = 38;
    const EXPECTATION_REQUIRED_FEATURES_OFFSET: usize = 40;
    const EXPECTATION_LIVE_LITERAL_BYTES_OFFSET: usize = 48;
    const EXPECTATION_ARGUMENT_COUNT_OFFSET: usize = 52;
    const EXPECTATION_RETURN_REGISTER_OFFSET: usize = 53;
    const EXPECTATION_RESULT_SLOT_BYTES_OFFSET: usize = 54;
    const EXPECTATION_NO_MATCH_SENTINEL_OFFSET: usize = 56;

    fn fixture_metadata_claim() -> ClaimedSearchSelectedEndMetadataV2 {
        let mut metadata = ClaimedSearchSelectedEndMetadataV2 {
            format_version: SEARCH_SELECTED_END_METADATA_VERSION_V2,
            record_bytes: u16::try_from(SEARCH_SELECTED_END_METADATA_BYTES_V2)
                .expect("small metadata"),
            backend_version: SEARCH_SELECTED_END_BACKEND_TAG21_V2,
            abi_kind: SEARCH_SELECTED_END_ABI_KIND_V2,
            output_kind: SEARCH_SELECTED_END_OUTPUT_KIND_V2,
            architecture: SEARCH_SELECTED_END_ARCHITECTURE_AARCH64_V2,
            little_endian: SEARCH_SELECTED_END_LITTLE_ENDIAN_V2,
            pointer_width: SEARCH_SELECTED_END_POINTER_WIDTH_V2,
            target_abi: SEARCH_SELECTED_END_TARGET_ABI_AAPCS64_V2,
            platform: SEARCH_SELECTED_END_PLATFORM_LINUX_V2,
            return_bits: SEARCH_SELECTED_END_RETURN_BITS_V2,
            call_abi_schema: SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2,
            return_encoding: SEARCH_SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2,
            window_contract: SEARCH_SELECTED_END_WINDOW_HALF_OPEN_ABSOLUTE_END_V2,
            fixed_active_vector_bytes: SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2,
            reserved: 0,
            features: SEARCH_SELECTED_END_REQUIRED_FEATURES_V2,
            payload_bytes: 256,
            entry_offset: SEARCH_SELECTED_END_ENTRY_OFFSET_V2,
            code_bytes: 240,
            rodata_offset: 240,
            rodata_bytes: SEARCH_SELECTED_END_LITERAL_BYTES_V2,
            literal_bytes: SEARCH_SELECTED_END_LITERAL_BYTES_V2,
            source_identity: [0x11; 32],
            artifact_identity: [0x22; 32],
            binding_identity: [0x33; 32],
            payload_sha256: [0x44; 32],
            compile_identity: [0; 32],
        };
        metadata.compile_identity = compute_metadata_compile_identity_v2(metadata);
        metadata
    }

    fn fixture_metadata() -> [u8; SEARCH_SELECTED_END_METADATA_BYTES_V2] {
        encode_metadata_v2(fixture_metadata_claim())
    }

    fn fixture_expectation() -> StaticSearchSelectedEndExpectationV2 {
        let metadata = fixture_metadata_claim();
        let metadata_bytes = encode_metadata_v2(metadata);
        let mut bytes = [0_u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2];
        let mut writer = TestWriter::new(&mut bytes);
        writer.bytes(&STATIC_SEARCH_SELECTED_END_EXPECTATION_MAGIC_V2);
        writer.u16(AOT_STATIC_SEARCH_SELECTED_END_EXPECTATION_SCHEMA_VERSION_V2);
        writer.u16(AOT_SEARCH_SELECTED_END_COMPILER_VERSION_V2);
        writer.u32(
            u32::try_from(STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2)
                .expect("small expectation"),
        );
        writer.u16(u16::try_from(SEARCH_SELECTED_END_METADATA_BYTES_V2).expect("small metadata"));
        writer.u16(SEARCH_SELECTED_END_METADATA_VERSION_V2);
        writer.u16(SEARCH_SELECTED_END_BACKEND_TAG21_V2);
        writer.u16(SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2);
        writer.u16(EXPORTED_SYMBOL_SCHEMA_VERSION_V2);
        writer.u8(SEARCH_SELECTED_END_OUTPUT_KIND_V2);
        writer.u8(SEARCH_SELECTED_END_DEFAULT_START_ANCHOR_V2);
        writer.u8(SEARCH_SELECTED_END_DEFAULT_END_ANCHOR_V2);
        writer.u8(SEARCH_SELECTED_END_ARCHITECTURE_AARCH64_V2);
        writer.u8(SEARCH_SELECTED_END_LITTLE_ENDIAN_V2);
        writer.u8(SEARCH_SELECTED_END_POINTER_WIDTH_V2);
        writer.u8(SEARCH_SELECTED_END_TARGET_ABI_AAPCS64_V2);
        writer.u8(SEARCH_SELECTED_END_PLATFORM_LINUX_V2);
        writer.u8(SEARCH_SELECTED_END_RETURN_BITS_V2);
        writer.u8(EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V2);
        writer.u8(SEARCH_SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2);
        writer.u8(SEARCH_SELECTED_END_WINDOW_HALF_OPEN_ABSOLUTE_END_V2);
        writer.u16(SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2);
        writer.u64(SEARCH_SELECTED_END_REQUIRED_FEATURES_V2);
        writer.u32(SEARCH_SELECTED_END_LITERAL_BYTES_V2);
        writer.u8(SEARCH_SELECTED_END_ARGUMENT_COUNT_V2);
        writer.u8(SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2);
        writer.u16(SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2);
        writer.u64(SEARCH_SELECTED_END_NO_MATCH_SENTINEL_V2);
        assert_eq!(writer.position(), EXPECTATION_HEADER_BYTES_V2);
        for identity in [
            [0x51; 32],
            [0x52; 32],
            [0x53; 32],
            *metadata.source_identity(),
            *metadata.artifact_identity(),
            *metadata.binding_identity(),
            *metadata.compile_identity(),
            [0x58; 32],
            [0x59; 32],
        ] {
            writer.bytes(&identity);
        }
        assert_eq!(
            writer.position(),
            STATIC_SEARCH_SELECTED_END_EXPECTATION_METADATA_OFFSET_V2
        );
        writer.bytes(&metadata_bytes);
        assert_eq!(
            writer.position(),
            STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2
        );
        let body: &[u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_BODY_BYTES_V2] = writer
            .written()
            .try_into()
            .expect("exact expectation identity body");
        let identity = compute_static_search_selected_end_expectation_identity_v2(body);
        writer.bytes(&identity);
        assert_eq!(
            writer.position(),
            STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2
        );
        bytes
    }

    fn refresh_expectation_identity(expectation: &mut StaticSearchSelectedEndExpectationV2) {
        let body: &[u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_BODY_BYTES_V2] =
            expectation
                .get(..STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2)
                .and_then(|body| body.try_into().ok())
                .expect("fixed expectation body");
        let identity = compute_static_search_selected_end_expectation_identity_v2(body);
        expectation[STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2..]
            .copy_from_slice(&identity);
    }

    #[test]
    fn wire_constants_pin_the_parallel_selected_end_v2_slice() {
        assert_eq!(SEARCH_SELECTED_END_METADATA_BYTES_V2, 224);
        assert_eq!(SEARCH_SELECTED_END_BACKEND_TAG21_V2, 21);
        assert_eq!(SEARCH_SELECTED_END_ABI_KIND_V2, 2);
        assert_eq!(SEARCH_SELECTED_END_OUTPUT_KIND_V2, 2);
        assert_eq!(SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2, 2);
        assert_eq!(SEARCH_SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2, 1);
        assert_eq!(SEARCH_SELECTED_END_WINDOW_HALF_OPEN_ABSOLUTE_END_V2, 1);
        assert_eq!(SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2, 16);
        assert_eq!(SEARCH_SELECTED_END_REQUIRED_FEATURES_V2, 7);
        assert_eq!(SEARCH_SELECTED_END_LITERAL_BYTES_V2, 16);
        assert_eq!(
            STATIC_SEARCH_SELECTED_END_EXPECTATION_METADATA_OFFSET_V2,
            352
        );
        assert_eq!(
            STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2,
            576
        );
        assert_eq!(STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2, 608);
        assert_eq!(
            SEARCH_SELECTED_END_ENTRY_SYMBOL_PREFIX_V2,
            "fre_aot_search_selected_end_entry_v2_"
        );
        assert_eq!(
            SELECTED_END_PAYLOAD_SYMBOL_PREFIX_V2,
            "fre_aot_search_selected_end_payload_v2_"
        );
        assert_eq!(
            SELECTED_END_METADATA_SYMBOL_PREFIX_V2,
            "fre_aot_search_selected_end_metadata_v2_"
        );
    }

    #[test]
    fn exact_metadata_is_strictly_projected() {
        let expected = fixture_metadata_claim();
        let actual = inspect_search_selected_end_metadata_v2(&fixture_metadata())
            .expect("canonical metadata");
        assert_eq!(actual, expected);
        assert_eq!(actual.backend_version(), 21);
        assert_eq!(actual.output_kind(), 2);
        assert_eq!(actual.call_abi_schema(), 2);
        assert_eq!(actual.return_encoding(), 1);
        assert_eq!(actual.window_contract(), 1);
        assert_eq!(actual.fixed_active_vector_bytes(), 16);
        assert_eq!(actual.features(), 7);
        assert_eq!(actual.literal_bytes(), 16);
        assert_eq!(actual.rodata_bytes(), 16);
        assert_eq!(actual.entry_offset(), 0);
    }

    #[test]
    fn exact_expectation_is_strictly_projected_without_authority() {
        let bytes = fixture_expectation();
        let claim = inspect_static_search_selected_end_expectation_v2(&bytes)
            .expect("canonical expectation");
        assert_eq!(
            claim.schema_version(),
            AOT_STATIC_SEARCH_SELECTED_END_EXPECTATION_SCHEMA_VERSION_V2
        );
        assert_eq!(
            claim.compiler_version(),
            AOT_SEARCH_SELECTED_END_COMPILER_VERSION_V2
        );
        assert_eq!(claim.live_literal_bytes(), 16);
        assert_eq!(claim.output_kind(), 2);
        assert!(!claim.anchor_start());
        assert!(!claim.anchor_end());
        assert_eq!(claim.argument_count(), 4);
        assert_eq!(claim.return_register(), 0);
        assert_eq!(claim.result_slot_bytes(), 0);
        assert_eq!(claim.no_match_sentinel(), 0);
        assert_eq!(claim.kir_identity(), &[0x11; 32]);
        assert_eq!(claim.artifact_identity(), &[0x22; 32]);
        assert_eq!(claim.binding_identity(), &[0x33; 32]);
        assert_eq!(claim.metadata(), fixture_metadata_claim());
        assert_eq!(
            claim.expectation_identity(),
            &bytes[STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2..]
        );
    }

    #[test]
    fn independent_known_vectors_pin_both_v2_identity_domains() {
        const EXPECTED_COMPILE: [u8; 32] = [
            0x70, 0xb5, 0xc7, 0xd2, 0x1f, 0x5c, 0x14, 0xba, 0x3f, 0x40, 0xe8, 0x31, 0xba, 0xaa,
            0x10, 0x8f, 0xd4, 0xe0, 0x1c, 0xfc, 0x80, 0x04, 0x41, 0x2f, 0x30, 0xf0, 0x76, 0x2d,
            0xf5, 0xad, 0x10, 0xd8,
        ];
        const EXPECTED_EXPECTATION: [u8; 32] = [
            0x93, 0xcc, 0x00, 0x46, 0x56, 0xfc, 0x42, 0xd7, 0xdf, 0xdb, 0x34, 0x9c, 0x22, 0x82,
            0xb7, 0xcf, 0x3c, 0x02, 0x3a, 0xe4, 0x32, 0x78, 0x77, 0xcd, 0x22, 0xb5, 0xba, 0x51,
            0xc7, 0xd2, 0x66, 0x18,
        ];
        let metadata = fixture_metadata_claim();
        assert_eq!(metadata.compile_identity, EXPECTED_COMPILE);
        let expectation = fixture_expectation();
        assert_eq!(
            expectation[STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2..],
            EXPECTED_EXPECTATION
        );
    }

    #[test]
    fn wrong_record_lengths_and_zero_records_are_refused() {
        let metadata = fixture_metadata();
        assert!(inspect_search_selected_end_metadata_v2(&metadata[..metadata.len() - 1]).is_err());
        let mut longer_metadata = metadata.to_vec();
        longer_metadata.push(0);
        assert!(inspect_search_selected_end_metadata_v2(&longer_metadata).is_err());
        assert!(
            inspect_search_selected_end_metadata_v2(&[0; SEARCH_SELECTED_END_METADATA_BYTES_V2])
                .is_err()
        );

        let expectation = fixture_expectation();
        assert!(
            inspect_static_search_selected_end_expectation_v2(
                &expectation[..expectation.len() - 1]
            )
            .is_err()
        );
        let mut longer_expectation = expectation.to_vec();
        longer_expectation.push(0);
        assert!(inspect_static_search_selected_end_expectation_v2(&longer_expectation).is_err());
        assert!(
            inspect_static_search_selected_end_expectation_v2(
                &[0; STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2]
            )
            .is_err()
        );
    }

    #[test]
    fn every_metadata_byte_is_bound_by_shape_or_compile_identity() {
        let original = fixture_metadata();
        for offset in 0..original.len() {
            let mut changed = original;
            changed[offset] ^= 1;
            assert!(
                inspect_search_selected_end_metadata_v2(&changed).is_err(),
                "mutated metadata byte {offset} was accepted"
            );
        }
    }

    #[test]
    fn every_expectation_byte_is_bound_by_shape_or_expectation_identity() {
        let original = fixture_expectation();
        for offset in 0..original.len() {
            let mut changed = original;
            changed[offset] ^= 1;
            assert!(
                inspect_static_search_selected_end_expectation_v2(&changed).is_err(),
                "mutated expectation byte {offset} was accepted"
            );
        }
    }

    #[test]
    fn metadata_rejects_every_fixed_contract_field_after_compile_rehash() {
        let original = fixture_metadata_claim();
        let mutations: &[fn(&mut ClaimedSearchSelectedEndMetadataV2)] = &[
            |value| value.format_version ^= 1,
            |value| value.record_bytes = value.record_bytes.saturating_sub(1),
            |value| value.backend_version ^= 1,
            |value| value.abi_kind ^= 1,
            |value| value.output_kind ^= 1,
            |value| value.architecture ^= 1,
            |value| value.little_endian = 0,
            |value| value.pointer_width = 32,
            |value| value.target_abi ^= 1,
            |value| value.platform ^= 1,
            |value| value.return_bits = 32,
            |value| value.call_abi_schema ^= 1,
            |value| value.return_encoding ^= 1,
            |value| value.window_contract ^= 1,
            |value| value.fixed_active_vector_bytes = 32,
            |value| value.reserved = 1,
            |value| value.features ^= 1,
            |value| value.entry_offset = 4,
            |value| value.rodata_bytes = 15,
            |value| value.literal_bytes = 15,
        ];
        for mutate in mutations {
            let mut changed = original;
            mutate(&mut changed);
            changed.compile_identity = compute_metadata_compile_identity_v2(changed);
            assert!(inspect_search_selected_end_metadata_v2(&encode_metadata_v2(changed)).is_err());
        }
    }

    #[test]
    fn metadata_rejects_every_zero_identity_even_after_compile_rehash() {
        let original = fixture_metadata_claim();
        let mutations: &[fn(&mut ClaimedSearchSelectedEndMetadataV2)] = &[
            |value| value.source_identity = [0; 32],
            |value| value.artifact_identity = [0; 32],
            |value| value.binding_identity = [0; 32],
            |value| value.payload_sha256 = [0; 32],
        ];
        for mutate in mutations {
            let mut changed = original;
            mutate(&mut changed);
            changed.compile_identity = compute_metadata_compile_identity_v2(changed);
            assert!(inspect_search_selected_end_metadata_v2(&encode_metadata_v2(changed)).is_err());
        }
        let mut zero_compile = original;
        zero_compile.compile_identity = [0; 32];
        assert!(
            inspect_search_selected_end_metadata_v2(&encode_metadata_v2(zero_compile)).is_err()
        );
    }

    #[test]
    fn metadata_rejects_every_invalid_image_layout_after_compile_rehash() {
        let original = fixture_metadata_claim();
        let mutations: &[fn(&mut ClaimedSearchSelectedEndMetadataV2)] = &[
            |value| value.code_bytes = 0,
            |value| value.code_bytes = 239,
            |value| value.rodata_offset = 239,
            |value| value.rodata_offset = 224,
            |value| value.payload_bytes = 255,
            |value| value.rodata_offset = u32::MAX - 15,
        ];
        for mutate in mutations {
            let mut changed = original;
            mutate(&mut changed);
            changed.compile_identity = compute_metadata_compile_identity_v2(changed);
            assert!(inspect_search_selected_end_metadata_v2(&encode_metadata_v2(changed)).is_err());
        }
    }

    #[test]
    fn expectation_rejects_rehashed_header_contract_mutations() {
        let original = fixture_expectation();
        let offsets = [
            EXPECTATION_SCHEMA_OFFSET,
            EXPECTATION_COMPILER_OFFSET,
            EXPECTATION_RECORD_BYTES_OFFSET,
            EXPECTATION_METADATA_BYTES_OFFSET,
            EXPECTATION_METADATA_VERSION_OFFSET,
            EXPECTATION_BACKEND_OFFSET,
            EXPECTATION_CALL_ABI_OFFSET,
            EXPECTATION_SYMBOL_SCHEMA_OFFSET,
            EXPECTATION_OUTPUT_OFFSET,
            EXPECTATION_ANCHOR_START_OFFSET,
            EXPECTATION_ANCHOR_END_OFFSET,
            EXPECTATION_ARCHITECTURE_OFFSET,
            EXPECTATION_LITTLE_ENDIAN_OFFSET,
            EXPECTATION_POINTER_WIDTH_OFFSET,
            EXPECTATION_TARGET_ABI_OFFSET,
            EXPECTATION_PLATFORM_OFFSET,
            EXPECTATION_RETURN_BITS_OFFSET,
            EXPECTATION_SYMBOL_INFO_OFFSET,
            EXPECTATION_RETURN_ENCODING_OFFSET,
            EXPECTATION_WINDOW_CONTRACT_OFFSET,
            EXPECTATION_FIXED_ACTIVE_VECTOR_BYTES_OFFSET,
            EXPECTATION_REQUIRED_FEATURES_OFFSET,
            EXPECTATION_LIVE_LITERAL_BYTES_OFFSET,
            EXPECTATION_ARGUMENT_COUNT_OFFSET,
            EXPECTATION_RETURN_REGISTER_OFFSET,
            EXPECTATION_RESULT_SLOT_BYTES_OFFSET,
            EXPECTATION_NO_MATCH_SENTINEL_OFFSET,
        ];
        for offset in offsets {
            let mut changed = original;
            changed[offset] ^= 1;
            refresh_expectation_identity(&mut changed);
            assert!(
                inspect_static_search_selected_end_expectation_v2(&changed).is_err(),
                "rehashed header mutation at {offset} was accepted"
            );
        }
    }

    #[test]
    fn expectation_rejects_every_zero_identity_after_outer_rehash() {
        let original = fixture_expectation();
        for offset in [
            EXPECTATION_MANIFEST_IDENTITY_OFFSET_V2,
            EXPECTATION_SEMANTIC_BINDING_IDENTITY_OFFSET_V2,
            EXPECTATION_LITERAL_IDENTITY_OFFSET_V2,
            EXPECTATION_KIR_IDENTITY_OFFSET_V2,
            EXPECTATION_ARTIFACT_IDENTITY_OFFSET_V2,
            EXPECTATION_BINDING_IDENTITY_OFFSET_V2,
            EXPECTATION_COMPILE_IDENTITY_OFFSET_V2,
            EXPECTATION_OBJECT_IDENTITY_OFFSET_V2,
            EXPECTATION_RECEIPT_IDENTITY_OFFSET_V2,
        ] {
            let mut changed = original;
            changed[offset..offset + 32].fill(0);
            refresh_expectation_identity(&mut changed);
            assert!(
                inspect_static_search_selected_end_expectation_v2(&changed).is_err(),
                "zero identity at {offset} was accepted"
            );
        }
        let mut zero_expectation_identity = original;
        zero_expectation_identity[STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2..]
            .fill(0);
        assert!(
            inspect_static_search_selected_end_expectation_v2(&zero_expectation_identity).is_err()
        );
    }

    #[test]
    fn expectation_rejects_every_rehashed_metadata_correlation_splice() {
        let original = fixture_expectation();
        for offset in [
            EXPECTATION_KIR_IDENTITY_OFFSET_V2,
            EXPECTATION_ARTIFACT_IDENTITY_OFFSET_V2,
            EXPECTATION_BINDING_IDENTITY_OFFSET_V2,
            EXPECTATION_COMPILE_IDENTITY_OFFSET_V2,
        ] {
            let mut changed = original;
            changed[offset] ^= 1;
            refresh_expectation_identity(&mut changed);
            assert!(
                inspect_static_search_selected_end_expectation_v2(&changed).is_err(),
                "rehashed correlation splice at {offset} was accepted"
            );
        }
    }

    #[test]
    fn noncorrelated_claims_remain_untrusted_and_change_the_outer_identity() {
        let original = fixture_expectation();
        let original_claim =
            inspect_static_search_selected_end_expectation_v2(&original).expect("baseline claim");
        for offset in [
            EXPECTATION_MANIFEST_IDENTITY_OFFSET_V2,
            EXPECTATION_SEMANTIC_BINDING_IDENTITY_OFFSET_V2,
            EXPECTATION_LITERAL_IDENTITY_OFFSET_V2,
            EXPECTATION_OBJECT_IDENTITY_OFFSET_V2,
            EXPECTATION_RECEIPT_IDENTITY_OFFSET_V2,
        ] {
            let mut changed = original;
            changed[offset] ^= 1;
            refresh_expectation_identity(&mut changed);
            let changed_claim = inspect_static_search_selected_end_expectation_v2(&changed)
                .expect("a nonzero self-consistent claim is not qualification authority");
            assert_ne!(
                changed_claim.expectation_identity(),
                original_claim.expectation_identity()
            );
        }
    }

    #[test]
    fn expectation_identity_domain_covers_every_body_byte() {
        let original = fixture_expectation();
        let body: &[u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_BODY_BYTES_V2] = original
            .get(..STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2)
            .and_then(|body| body.try_into().ok())
            .expect("fixed body");
        let original_identity = compute_static_search_selected_end_expectation_identity_v2(body);
        for offset in 0..body.len() {
            let mut changed = *body;
            changed[offset] ^= 1;
            assert_ne!(
                compute_static_search_selected_end_expectation_identity_v2(&changed),
                original_identity,
                "body mutation at {offset} preserved the expectation identity"
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one offset test keeps the complete V2 metadata and expectation headers visible in byte order"
    )]
    fn documented_offsets_match_the_published_v2_wires() {
        let metadata = fixture_metadata();
        assert_eq!(&metadata[0..8], &SEARCH_SELECTED_END_METADATA_MAGIC_V2);
        assert_eq!(
            u16::from_le_bytes(
                metadata[METADATA_FORMAT_VERSION_OFFSET..METADATA_FORMAT_VERSION_OFFSET + 2]
                    .try_into()
                    .expect("u16")
            ),
            2
        );
        assert_eq!(
            u16::from_le_bytes(
                metadata[METADATA_RECORD_BYTES_OFFSET..METADATA_RECORD_BYTES_OFFSET + 2]
                    .try_into()
                    .expect("u16")
            ),
            224
        );
        assert_eq!(
            u16::from_le_bytes(
                metadata[METADATA_BACKEND_VERSION_OFFSET..METADATA_BACKEND_VERSION_OFFSET + 2]
                    .try_into()
                    .expect("u16")
            ),
            21
        );
        assert_eq!(metadata[METADATA_ABI_KIND_OFFSET], 2);
        assert_eq!(metadata[METADATA_OUTPUT_KIND_OFFSET], 2);
        assert_eq!(metadata[METADATA_ARCHITECTURE_OFFSET], 1);
        assert_eq!(metadata[METADATA_LITTLE_ENDIAN_OFFSET], 1);
        assert_eq!(metadata[METADATA_POINTER_WIDTH_OFFSET], 64);
        assert_eq!(metadata[METADATA_TARGET_ABI_OFFSET], 1);
        assert_eq!(metadata[METADATA_PLATFORM_OFFSET], 2);
        assert_eq!(metadata[METADATA_RETURN_BITS_OFFSET], 64);
        assert_eq!(
            u16::from_le_bytes(
                metadata[METADATA_CALL_ABI_OFFSET..METADATA_CALL_ABI_OFFSET + 2]
                    .try_into()
                    .expect("u16")
            ),
            2
        );
        assert_eq!(metadata[METADATA_RETURN_ENCODING_OFFSET], 1);
        assert_eq!(metadata[METADATA_WINDOW_CONTRACT_OFFSET], 1);
        assert_eq!(
            u16::from_le_bytes(
                metadata[METADATA_FIXED_ACTIVE_VECTOR_BYTES_OFFSET
                    ..METADATA_FIXED_ACTIVE_VECTOR_BYTES_OFFSET + 2]
                    .try_into()
                    .expect("u16")
            ),
            16
        );
        assert_eq!(
            u32::from_le_bytes(
                metadata[METADATA_RESERVED_OFFSET..METADATA_RESERVED_OFFSET + 4]
                    .try_into()
                    .expect("u32")
            ),
            0
        );
        assert_eq!(
            u64::from_le_bytes(
                metadata[METADATA_FEATURES_OFFSET..METADATA_FEATURES_OFFSET + 8]
                    .try_into()
                    .expect("u64")
            ),
            7
        );
        for (offset, expected) in [
            (METADATA_PAYLOAD_BYTES_OFFSET, 256),
            (METADATA_ENTRY_OFFSET_OFFSET, 0),
            (METADATA_CODE_BYTES_OFFSET, 240),
            (METADATA_RODATA_OFFSET_OFFSET, 240),
            (METADATA_RODATA_BYTES_OFFSET, 16),
            (METADATA_LITERAL_BYTES_OFFSET, 16),
        ] {
            assert_eq!(
                u32::from_le_bytes(metadata[offset..offset + 4].try_into().expect("u32 field")),
                expected
            );
        }
        assert_eq!(
            &metadata[METADATA_SOURCE_IDENTITY_OFFSET..METADATA_ARTIFACT_IDENTITY_OFFSET],
            &[0x11; 32]
        );
        assert_eq!(
            &metadata[METADATA_ARTIFACT_IDENTITY_OFFSET..METADATA_BINDING_IDENTITY_OFFSET],
            &[0x22; 32]
        );
        assert_eq!(
            &metadata[METADATA_BINDING_IDENTITY_OFFSET..METADATA_PAYLOAD_DIGEST_OFFSET],
            &[0x33; 32]
        );
        assert_eq!(
            &metadata[METADATA_PAYLOAD_DIGEST_OFFSET..METADATA_COMPILE_IDENTITY_OFFSET],
            &[0x44; 32]
        );

        let expectation = fixture_expectation();
        assert_eq!(
            &expectation[0..8],
            &STATIC_SEARCH_SELECTED_END_EXPECTATION_MAGIC_V2
        );
        for (offset, expected) in [
            (EXPECTATION_SCHEMA_OFFSET, 2_u16),
            (EXPECTATION_COMPILER_OFFSET, 2),
            (EXPECTATION_METADATA_BYTES_OFFSET, 224),
            (EXPECTATION_METADATA_VERSION_OFFSET, 2),
            (EXPECTATION_BACKEND_OFFSET, 21),
            (EXPECTATION_CALL_ABI_OFFSET, 2),
            (EXPECTATION_SYMBOL_SCHEMA_OFFSET, 2),
            (EXPECTATION_FIXED_ACTIVE_VECTOR_BYTES_OFFSET, 16),
            (EXPECTATION_RESULT_SLOT_BYTES_OFFSET, 0),
        ] {
            assert_eq!(
                u16::from_le_bytes(
                    expectation[offset..offset + 2]
                        .try_into()
                        .expect("u16 field")
                ),
                expected
            );
        }
        assert_eq!(
            u32::from_le_bytes(
                expectation[EXPECTATION_RECORD_BYTES_OFFSET..EXPECTATION_RECORD_BYTES_OFFSET + 4]
                    .try_into()
                    .expect("u32")
            ),
            608
        );
        for (offset, expected) in [
            (EXPECTATION_OUTPUT_OFFSET, 2_u8),
            (EXPECTATION_ANCHOR_START_OFFSET, 0),
            (EXPECTATION_ANCHOR_END_OFFSET, 0),
            (EXPECTATION_ARCHITECTURE_OFFSET, 1),
            (EXPECTATION_LITTLE_ENDIAN_OFFSET, 1),
            (EXPECTATION_POINTER_WIDTH_OFFSET, 64),
            (EXPECTATION_TARGET_ABI_OFFSET, 1),
            (EXPECTATION_PLATFORM_OFFSET, 2),
            (EXPECTATION_RETURN_BITS_OFFSET, 64),
            (EXPECTATION_SYMBOL_INFO_OFFSET, 0x12),
            (EXPECTATION_RETURN_ENCODING_OFFSET, 1),
            (EXPECTATION_WINDOW_CONTRACT_OFFSET, 1),
            (EXPECTATION_ARGUMENT_COUNT_OFFSET, 4),
            (EXPECTATION_RETURN_REGISTER_OFFSET, 0),
        ] {
            assert_eq!(expectation[offset], expected);
        }
        assert_eq!(
            u64::from_le_bytes(
                expectation[EXPECTATION_REQUIRED_FEATURES_OFFSET
                    ..EXPECTATION_REQUIRED_FEATURES_OFFSET + 8]
                    .try_into()
                    .expect("u64")
            ),
            7
        );
        assert_eq!(
            u32::from_le_bytes(
                expectation[EXPECTATION_LIVE_LITERAL_BYTES_OFFSET
                    ..EXPECTATION_LIVE_LITERAL_BYTES_OFFSET + 4]
                    .try_into()
                    .expect("u32")
            ),
            16
        );
        assert_eq!(
            u64::from_le_bytes(
                expectation[EXPECTATION_NO_MATCH_SENTINEL_OFFSET
                    ..EXPECTATION_NO_MATCH_SENTINEL_OFFSET + 8]
                    .try_into()
                    .expect("u64")
            ),
            0
        );
    }

    #[test]
    fn valid_v1_and_v2_records_are_strictly_cross_rejected() {
        let v1_metadata = fixture_v1_metadata();
        assert!(crate::inspect_search_metadata_v1(&v1_metadata).is_ok());
        assert!(inspect_search_selected_end_metadata_v2(&v1_metadata).is_err());

        let v2_metadata = fixture_metadata();
        assert!(inspect_search_selected_end_metadata_v2(&v2_metadata).is_ok());
        assert!(crate::inspect_search_metadata_v1(&v2_metadata).is_err());

        let mut v1_width_foreign_magic = [0_u8; SEARCH_SELECTED_END_METADATA_BYTES_V2];
        v1_width_foreign_magic[..v1_metadata.len()].copy_from_slice(&v1_metadata);
        assert!(inspect_search_selected_end_metadata_v2(&v1_width_foreign_magic).is_err());
        let mut v2_width_foreign_magic = [0_u8; crate::SEARCH_METADATA_BYTES_V1];
        v2_width_foreign_magic.copy_from_slice(&v2_metadata[..crate::SEARCH_METADATA_BYTES_V1]);
        assert!(crate::inspect_search_metadata_v1(&v2_width_foreign_magic).is_err());

        let v1_expectation = fixture_v1_expectation();
        assert!(crate::inspect_static_search_span_expectation_v1(&v1_expectation).is_ok());
        assert!(inspect_static_search_selected_end_expectation_v2(&v1_expectation).is_err());

        let v2_expectation = fixture_expectation();
        assert!(inspect_static_search_selected_end_expectation_v2(&v2_expectation).is_ok());
        assert!(crate::inspect_static_search_span_expectation_v1(&v2_expectation).is_err());
    }

    fn fixture_v1_metadata_claim() -> crate::ClaimedSearchMetadataV1 {
        let mut metadata = crate::ClaimedSearchMetadataV1 {
            format_version: crate::SEARCH_METADATA_VERSION_V1,
            record_bytes: u16::try_from(crate::SEARCH_METADATA_BYTES_V1)
                .expect("small V1 metadata"),
            backend_version: crate::SEARCH_BACKEND_VERSION_V1,
            abi_kind: crate::SEARCH_ABI_KIND_V1,
            output_kind: crate::SEARCH_SPAN_OUTPUT_KIND_V1,
            architecture: crate::SEARCH_ARCHITECTURE_AARCH64_V1,
            little_endian: crate::SEARCH_LITTLE_ENDIAN_V1,
            pointer_width: crate::SEARCH_POINTER_WIDTH_V1,
            target_abi: crate::SEARCH_TARGET_ABI_AAPCS64_V1,
            platform: crate::SEARCH_PLATFORM_MACOS_V1,
            status_bits: crate::SEARCH_STATUS_BITS_V1,
            abi_schema: crate::SEARCH_CALL_ABI_SCHEMA_V1,
            features: crate::SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            payload_bytes: 256,
            entry_offset: crate::SEARCH_ENTRY_OFFSET_V1,
            code_bytes: 240,
            rodata_offset: 240,
            rodata_bytes: 16,
            literal_bytes: 0,
            source_identity: [0x11; 32],
            artifact_identity: [0x22; 32],
            binding_identity: [0x33; 32],
            payload_sha256: [0x44; 32],
            compile_identity: [0; 32],
        };
        metadata.compile_identity =
            crate::compute_metadata_compile_identity_v1(metadata).expect("fixed V1 target");
        metadata
    }

    fn fixture_v1_metadata() -> [u8; crate::SEARCH_METADATA_BYTES_V1] {
        let metadata = fixture_v1_metadata_claim();
        let mut bytes = [0_u8; crate::SEARCH_METADATA_BYTES_V1];
        let mut writer = TestWriter::new(&mut bytes);
        writer.bytes(&crate::SEARCH_METADATA_MAGIC_V1);
        writer.u16(metadata.format_version());
        writer.u16(metadata.record_bytes());
        writer.u16(metadata.backend_version());
        writer.u8(metadata.abi_kind());
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
        writer.bytes(metadata.source_identity());
        writer.bytes(metadata.artifact_identity());
        writer.bytes(metadata.binding_identity());
        writer.bytes(metadata.payload_sha256());
        writer.bytes(metadata.compile_identity());
        assert_eq!(writer.position(), crate::SEARCH_METADATA_BYTES_V1);
        bytes
    }

    fn fixture_v1_expectation() -> crate::StaticSearchSpanExpectationV1 {
        let metadata = fixture_v1_metadata_claim();
        let metadata_bytes = fixture_v1_metadata();
        let mut bytes = [0_u8; crate::STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1];
        let mut writer = TestWriter::new(&mut bytes);
        writer.bytes(&crate::STATIC_SEARCH_SPAN_EXPECTATION_MAGIC_V1);
        writer.u16(crate::AOT_STATIC_SEARCH_SPAN_EXPECTATION_SCHEMA_VERSION_V1);
        writer.u16(crate::AOT_SEARCH_COMPILER_VERSION_V1);
        writer.u32(
            u32::try_from(crate::STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1)
                .expect("small V1 expectation"),
        );
        writer.u16(u16::try_from(crate::SEARCH_METADATA_BYTES_V1).expect("small V1 metadata"));
        writer.u16(crate::SEARCH_METADATA_VERSION_V1);
        writer.u16(crate::SEARCH_BACKEND_VERSION_V1);
        writer.u16(crate::SEARCH_CALL_ABI_SCHEMA_V1);
        writer.u16(crate::SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1);
        writer.u8(crate::SEARCH_SPAN_OUTPUT_KIND_V1);
        writer.u8(crate::SEARCH_DEFAULT_START_ANCHOR_V1);
        writer.u8(crate::SEARCH_DEFAULT_END_ANCHOR_V1);
        writer.u8(crate::SEARCH_ARCHITECTURE_AARCH64_V1);
        writer.u8(crate::SEARCH_LITTLE_ENDIAN_V1);
        writer.u8(crate::SEARCH_POINTER_WIDTH_V1);
        writer.u8(crate::SEARCH_TARGET_ABI_AAPCS64_V1);
        writer.u8(crate::SEARCH_PLATFORM_MACOS_V1);
        writer.u8(crate::SEARCH_STATUS_BITS_V1);
        writer.u8(crate::SEARCH_EXPORTED_SYMBOL_N_TYPE_V1);
        writer.u64(crate::SEARCH_REQUIRED_ASIMD_FEATURES_V1);
        writer.u32(16);
        for identity in [
            [0x51; 32],
            [0x52; 32],
            [0x53; 32],
            *metadata.source_identity(),
            *metadata.artifact_identity(),
            *metadata.binding_identity(),
            *metadata.compile_identity(),
            [0x58; 32],
            [0x59; 32],
        ] {
            writer.bytes(&identity);
        }
        assert_eq!(
            writer.position(),
            crate::STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1
        );
        writer.bytes(&metadata_bytes);
        assert_eq!(
            writer.position(),
            crate::STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1
        );
        let body: &[u8; crate::STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1] = writer
            .written()
            .try_into()
            .expect("exact V1 expectation body");
        let identity = crate::compute_static_search_span_expectation_identity_v1(body);
        writer.bytes(&identity);
        assert_eq!(
            writer.position(),
            crate::STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1
        );
        bytes
    }

    struct TestWriter<'a> {
        bytes: &'a mut [u8],
        position: usize,
    }

    impl<'a> TestWriter<'a> {
        fn new(bytes: &'a mut [u8]) -> Self {
            Self { bytes, position: 0 }
        }

        fn bytes(&mut self, value: &[u8]) {
            let end = self
                .position
                .checked_add(value.len())
                .expect("test fixture offset");
            self.bytes[self.position..end].copy_from_slice(value);
            self.position = end;
        }

        fn u8(&mut self, value: u8) {
            self.bytes(&[value]);
        }

        fn u16(&mut self, value: u16) {
            self.bytes(&value.to_le_bytes());
        }

        fn u32(&mut self, value: u32) {
            self.bytes(&value.to_le_bytes());
        }

        fn u64(&mut self, value: u64) {
            self.bytes(&value.to_le_bytes());
        }

        fn position(&self) -> usize {
            self.position
        }

        fn written(&self) -> &[u8] {
            &self.bytes[..self.position]
        }
    }
}
