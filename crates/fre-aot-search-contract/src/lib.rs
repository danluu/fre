//! JIT- and runtime-neutral claim-side wire contracts for static Search
//! candidates.
//!
//! This crate strictly projects canonical metadata and expectation bytes into
//! typed, allocation-free claims. It deliberately depends on neither the
//! compiler, Mach-O publisher, JIT emitter, executable-memory runtime, nor
//! platform loader. A valid claim is not runtime or deployment authority:
//! later static adoption must match it against a private source-qualified row
//! before reading linked addresses.
//!
//! The metadata constants below reproduce the shared 216-byte metadata wire.
//! macOS V8 retains its published Mach-O compile-identity domain byte for byte;
//! Linux V8 and explicit tag21 use the separate ELF domain and structural
//! tuple. They are duplicated here so a verifier does not import either code
//! generator. The Span expectation uses its own magic, schema, and
//! domain-separated identity.

#![forbid(unsafe_code)]

/// Strict, parallel contract for Linux tag21 `SelectedEnd` register-return V2.
///
/// Its distinct record sizes, magics, identity domains, ABI tuple, and symbol
/// prefixes deliberately prevent either Search V1 parser from admitting it.
pub mod selected_end_v2;

use core::fmt;

use sha2::{Digest, Sha256};

/// Published Search `MetadataV1` format version.
pub const SEARCH_METADATA_VERSION_V1: u16 = 1;
/// Exact canonical Search `MetadataV1` width.
pub const SEARCH_METADATA_BYTES_V1: usize = 216;
/// Search V1 generated entries begin at the payload base.
pub const SEARCH_ENTRY_OFFSET_V1: u32 = 0;
/// Raw Search call ABI schema carried by `MetadataV1`.
pub const SEARCH_CALL_ABI_SCHEMA_V1: u16 = 1;
/// Width of the raw Search status return.
pub const SEARCH_STATUS_BITS_V1: u8 = 64;
/// Identity-derived external-symbol schema carried by the V1 compile digest.
pub const SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1: u16 = 1;
/// Full lowercase hexadecimal compile identity in every generated V1 symbol.
pub const SEARCH_EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1: u16 = 64;
/// Mach-O `N_SECT | N_EXT` used by the legacy V1 implementation object.
///
/// This is intentionally recorded as `0x0f`, not private-external `0x1f`.
/// Consequently this contract is scoped to a private candidate and makes no
/// production-hardening claim.
pub const SEARCH_EXPORTED_SYMBOL_N_TYPE_V1: u8 = 0x0f;
/// Fixed Search backend selected by the inert source-first compiler.
pub const SEARCH_BACKEND_VERSION_V1: u16 = 8;
/// Advanced SIMD Search V9/tag22 with the exact first-candidate fast path.
pub const SEARCH_BACKEND_ASIMD_TAG22_V1: u16 = 22;
/// Advanced SIMD Search V10/tag23 with terminal-aware fifth-column screening.
///
/// This is an inert compiler/static-link identity until a separately frozen
/// qualification family grants execution authority.
pub const SEARCH_BACKEND_ASIMD_TAG23_V1: u16 = 23;
/// Advanced SIMD Search V12/tag25 with length-specialized exact confirmation.
///
/// This remains an inert compiler/static-link identity until a separately
/// frozen qualification family grants execution authority. Tag24 is
/// intentionally absent because its candidate was not promoted.
pub const SEARCH_BACKEND_ASIMD_TAG25_V1: u16 = 25;
/// Advanced SIMD Search V13/tag26 with adaptive exact retained-mask recovery.
///
/// This remains an inert compiler/static-link identity until a separately
/// frozen qualification family grants execution authority.
pub const SEARCH_BACKEND_ASIMD_TAG26_V1: u16 = 26;
/// Advanced SIMD Search V15/tag28 with a phase-unique five-column selector
/// and one persistent mismatch-directed learned column.
///
/// This remains an inert compiler/static-link identity until a separately
/// frozen broad qualification family grants execution authority. Tag27 is
/// intentionally absent because that unrestricted candidate was rejected.
pub const SEARCH_BACKEND_ASIMD_TAG28_V1: u16 = 28;
/// Advanced SIMD Search V16/tag29 with a staged learned-byte/primary-byte
/// discriminator before complete retained-mask recovery.
///
/// This remains an inert compiler/static-link identity until a separately
/// frozen broad qualification family grants execution authority. Tag28
/// remains frozen and rejected.
pub const SEARCH_BACKEND_ASIMD_TAG29_V1: u16 = 29;
/// Advanced SIMD Search V17/tag30 with retained learned-mask continuation.
///
/// This remains an inert compiler/static-link identity until a separately
/// frozen broad qualification family grants execution authority. Tag29
/// remains frozen and unchanged.
pub const SEARCH_BACKEND_ASIMD_TAG30_V1: u16 = 30;
/// Advanced SIMD Search V24/tag37 with one deterministic sixth static
/// screening column derived from, but deliberately absent from, the exact
/// five-field authenticated search manifest.
///
/// This remains an inert compiler/static-link identity until a separately
/// frozen broad qualification family grants execution authority. Tag36 is
/// intentionally absent because Search V23 was rejected.
pub const SEARCH_BACKEND_ASIMD_TAG37_V1: u16 = 37;
/// Minimum exact-literal width admitted by the Search V24/tag37 backend.
pub const SEARCH_BACKEND_ASIMD_TAG37_MIN_LITERAL_BYTES_V1: u32 = 6;
/// Maximum exact-literal width admitted by the Search V24/tag37 backend.
pub const SEARCH_BACKEND_ASIMD_TAG37_MAX_LITERAL_BYTES_V1: u32 = 32;
/// Number of authenticated static filter offsets carried by the V24 manifest.
///
/// The sixth offset is deterministically derived from the literal and these
/// five fields by the audited emitter; it is not a sixth manifest field.
pub const SEARCH_BACKEND_ASIMD_TAG37_MANIFEST_FILTER_FIELDS_V1: u8 = 5;
/// Explicit fixed-VL16 SVE2 candidate backend. This never changes the V8
/// default or grants qualification authority.
pub const SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1: u16 = 21;
/// Metadata ABI-kind tag for Search.
pub const SEARCH_ABI_KIND_V1: u8 = 1;
/// Metadata output-kind tag for a complete match span.
pub const SEARCH_SPAN_OUTPUT_KIND_V1: u8 = 3;
/// Target architecture tag for `AArch64`.
pub const SEARCH_ARCHITECTURE_AARCH64_V1: u8 = 1;
/// Canonical little-endian byte-order tag.
pub const SEARCH_LITTLE_ENDIAN_V1: u8 = 1;
/// Canonical target pointer width.
pub const SEARCH_POINTER_WIDTH_V1: u8 = 64;
/// Target ABI tag for AAPCS64.
pub const SEARCH_TARGET_ABI_AAPCS64_V1: u8 = 1;
/// Object platform tag for macOS.
pub const SEARCH_PLATFORM_MACOS_V1: u8 = 1;
/// Object platform tag for Linux ELF.
pub const SEARCH_PLATFORM_LINUX_V1: u8 = 2;
/// Exact Advanced SIMD feature bitmap required by Search V8.
pub const SEARCH_REQUIRED_ASIMD_FEATURES_V1: u64 = 1;
/// Exact ASIMD+SVE+SVE2 feature bitmap required by the tag21 candidate.
pub const SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1: u64 = 7;
/// ELF `STB_GLOBAL | STT_FUNC` used by the identity-suffixed entry symbol.
pub const SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1: u8 = 0x12;
/// The source-first exact-literal compiler admits no start anchor.
pub const SEARCH_DEFAULT_START_ANCHOR_V1: u8 = 0;
/// The source-first exact-literal compiler admits no end anchor.
pub const SEARCH_DEFAULT_END_ANCHOR_V1: u8 = 0;
/// Minimum live exact-literal width admitted by the static Span slice.
pub const MIN_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1: u32 = 1;
/// Maximum live exact-literal width admitted by this static Span slice.
pub const MAX_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1: u32 = 32;

/// Return whether a live literal width is canonical for a Search backend.
///
/// This single neutral predicate is used at every persisted-contract boundary
/// so tag-specific width rules cannot drift between compiler, object, and
/// static-runtime decoders.
#[must_use]
pub const fn search_backend_literal_width_is_valid_v1(
    backend: u16,
    live_literal_bytes: u32,
) -> bool {
    match backend {
        SEARCH_BACKEND_ASIMD_TAG37_V1 => {
            live_literal_bytes >= SEARCH_BACKEND_ASIMD_TAG37_MIN_LITERAL_BYTES_V1
                && live_literal_bytes <= SEARCH_BACKEND_ASIMD_TAG37_MAX_LITERAL_BYTES_V1
        }
        SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1 => live_literal_bytes == 16,
        _ => {
            live_literal_bytes >= MIN_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1
                && live_literal_bytes <= MAX_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1
        }
    }
}

/// Source-first Search compiler version admitted by the expectation.
pub const AOT_SEARCH_COMPILER_VERSION_V1: u16 = 1;
/// Schema of the domain-separated static Search Span expectation.
pub const AOT_STATIC_SEARCH_SPAN_EXPECTATION_SCHEMA_VERSION_V1: u16 = 1;
/// Fixed byte offset at which the exact `MetadataV1` record begins.
pub const STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1: usize = 336;
/// Fixed byte offset at which the expectation identity begins.
pub const STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1: usize = 552;
/// Exact canonical static Search Span expectation width.
pub const STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1: usize = 584;
/// Bytes covered by the domain-separated expectation identity.
pub const STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1: usize =
    STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1;

/// Exact fixed-width expectation wire. Possessing these bytes grants no
/// compiler, linker, runtime, qualification, or deployment authority.
pub type StaticSearchSpanExpectationV1 = [u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1];

const SEARCH_METADATA_MAGIC_V1: [u8; 8] = *b"FREOM64\x01";
const STATIC_SEARCH_SPAN_EXPECTATION_MAGIC_V1: [u8; 8] = *b"FRESSPX\x01";
const STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_DOMAIN_V1: &[u8] =
    b"FRE-AOT-STATIC-SEARCH-SPAN-EXPECTATION-IDENTITY\0\x01";

// These values are part of the published MetadataV1 compile-identity wire.
// They must remain byte-for-byte identical to `fre-aot-macho/src/macho.rs`;
// changing any of them requires a new metadata/object contract.
const MACHO_COMPILE_IDENTITY_DOMAIN_V1: &[u8] = b"FRE-AOT-MACHO-COMPILE\0\x02";
const ELF_COMPILE_IDENTITY_DOMAIN_V1: &[u8] = b"FRE-AOT-ELF-COMPILE\0\x01";
const SEARCH_ENTRY_SYMBOL_PREFIX_V1: &str = "fre_aot_search_entry_v1_";
const AGGREGATE_ENTRY_SYMBOL_PREFIX_V1: &str = "fre_aot_aggregate_entry_v1_";
const PAYLOAD_SYMBOL_PREFIX_V1: &str = "fre_aot_payload_v1_";
const METADATA_SYMBOL_PREFIX_V1: &str = "fre_aot_metadata_v1_";
const MIN_MACOS_VERSION_V1: u32 = 0x000b_0000;
const ELF_CLASS_64_V1: u8 = 2;
const ELF_DATA_LSB_V1: u8 = 1;
const ELF_VERSION_CURRENT_V1: u8 = 1;
const ELF_OS_ABI_SYSV_V1: u8 = 0;
const ELF_RELOCATABLE_TYPE_V1: u16 = 1;
const ELF_MACHINE_AARCH64_V1: u16 = 183;

const EXPECTATION_HEADER_BYTES_V1: usize = 48;
const EXPECTATION_IDENTITY_BYTES_V1: usize = 32;
const EXPECTATION_MANIFEST_IDENTITY_OFFSET_V1: usize = EXPECTATION_HEADER_BYTES_V1;
const EXPECTATION_SEMANTIC_BINDING_IDENTITY_OFFSET_V1: usize =
    EXPECTATION_MANIFEST_IDENTITY_OFFSET_V1 + 32;
const EXPECTATION_LITERAL_IDENTITY_OFFSET_V1: usize =
    EXPECTATION_SEMANTIC_BINDING_IDENTITY_OFFSET_V1 + 32;
const EXPECTATION_KIR_IDENTITY_OFFSET_V1: usize = EXPECTATION_LITERAL_IDENTITY_OFFSET_V1 + 32;
const EXPECTATION_ARTIFACT_IDENTITY_OFFSET_V1: usize = EXPECTATION_KIR_IDENTITY_OFFSET_V1 + 32;
const EXPECTATION_BINDING_IDENTITY_OFFSET_V1: usize = EXPECTATION_ARTIFACT_IDENTITY_OFFSET_V1 + 32;
const EXPECTATION_COMPILE_IDENTITY_OFFSET_V1: usize = EXPECTATION_BINDING_IDENTITY_OFFSET_V1 + 32;
const EXPECTATION_OBJECT_IDENTITY_OFFSET_V1: usize = EXPECTATION_COMPILE_IDENTITY_OFFSET_V1 + 32;
const EXPECTATION_RECEIPT_IDENTITY_OFFSET_V1: usize = EXPECTATION_OBJECT_IDENTITY_OFFSET_V1 + 32;

const _: () = assert!(SEARCH_METADATA_BYTES_V1 == 216);
const _: () = assert!(EXPECTATION_MANIFEST_IDENTITY_OFFSET_V1 == 48);
const _: () = assert!(EXPECTATION_SEMANTIC_BINDING_IDENTITY_OFFSET_V1 == 80);
const _: () = assert!(EXPECTATION_LITERAL_IDENTITY_OFFSET_V1 == 112);
const _: () = assert!(EXPECTATION_KIR_IDENTITY_OFFSET_V1 == 144);
const _: () = assert!(EXPECTATION_ARTIFACT_IDENTITY_OFFSET_V1 == 176);
const _: () = assert!(EXPECTATION_BINDING_IDENTITY_OFFSET_V1 == 208);
const _: () = assert!(EXPECTATION_COMPILE_IDENTITY_OFFSET_V1 == 240);
const _: () = assert!(EXPECTATION_OBJECT_IDENTITY_OFFSET_V1 == 272);
const _: () = assert!(EXPECTATION_RECEIPT_IDENTITY_OFFSET_V1 == 304);
const _: () = assert!(
    EXPECTATION_RECEIPT_IDENTITY_OFFSET_V1 + 32
        == STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1
);
const _: () = assert!(
    STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1 + SEARCH_METADATA_BYTES_V1
        == STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1
);
const _: () = assert!(
    STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1 + EXPECTATION_IDENTITY_BYTES_V1
        == STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1
);

/// A fixed byte sequence was not canonical Search V1 Span metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchMetadataErrorV1 {
    at: &'static str,
}

impl SearchMetadataErrorV1 {
    #[must_use]
    pub const fn at(&self) -> &'static str {
        self.at
    }
}

impl fmt::Display for SearchMetadataErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Search V1 Span metadata at {}", self.at)
    }
}

impl std::error::Error for SearchMetadataErrorV1 {}

/// A fixed expectation was not canonical or internally consistent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticSearchSpanExpectationErrorV1 {
    at: &'static str,
}

impl StaticSearchSpanExpectationErrorV1 {
    #[must_use]
    pub const fn at(&self) -> &'static str {
        self.at
    }
}

impl fmt::Display for StaticSearchSpanExpectationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid static Search V1 Span expectation at {}",
            self.at
        )
    }
}

impl std::error::Error for StaticSearchSpanExpectationErrorV1 {}

/// Strictly decoded but untrusted Search `MetadataV1` claim.
///
/// This projection retains every variable metadata field. Equality of two
/// canonical projections therefore proves equality of their complete
/// 216-byte records; fixed magic and version bytes cannot vary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedSearchMetadataV1 {
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
    status_bits: u8,
    abi_schema: u16,
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

impl ClaimedSearchMetadataV1 {
    metadata_scalar_getter!(format_version, u16);
    metadata_scalar_getter!(record_bytes, u16);
    metadata_scalar_getter!(backend_version, u16);
    metadata_scalar_getter!(abi_kind, u8);
    metadata_scalar_getter!(output_kind, u8);
    metadata_scalar_getter!(architecture, u8);
    metadata_scalar_getter!(pointer_width, u8);
    metadata_scalar_getter!(target_abi, u8);
    metadata_scalar_getter!(platform, u8);
    metadata_scalar_getter!(status_bits, u8);
    metadata_scalar_getter!(abi_schema, u16);
    metadata_scalar_getter!(features, u64);
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

/// Decode and validate exactly one complete Search `MetadataV1` record.
///
/// Besides checking an admitted macOS/Linux ASIMD candidate or Linux-tag21
/// target and image shape, this recomputes the platform-specific `MetadataV1`
/// compile identity. The resulting value remains a claim; no support row,
/// mapped image, or callable address is authorized here.
pub fn inspect_search_metadata_v1(
    bytes: &[u8],
) -> Result<ClaimedSearchMetadataV1, SearchMetadataErrorV1> {
    if bytes.len() != SEARCH_METADATA_BYTES_V1 {
        return Err(metadata_error("record bytes"));
    }
    let mut reader = MetadataReader::new(bytes);
    reader.expect(&SEARCH_METADATA_MAGIC_V1, "metadata magic")?;
    let metadata = ClaimedSearchMetadataV1 {
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
        status_bits: reader.u8("status width")?,
        abi_schema: reader.u16("call ABI schema")?,
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
    let computed_compile_identity = compute_metadata_compile_identity_v1(metadata)?;
    if metadata.compile_identity != computed_compile_identity {
        return Err(metadata_error("compile identity"));
    }
    Ok(metadata)
}

fn validate_metadata_shape(metadata: ClaimedSearchMetadataV1) -> Result<(), SearchMetadataErrorV1> {
    if metadata.format_version != SEARCH_METADATA_VERSION_V1
        || usize::from(metadata.record_bytes) != SEARCH_METADATA_BYTES_V1
        || metadata.abi_kind != SEARCH_ABI_KIND_V1
        || metadata.output_kind != SEARCH_SPAN_OUTPUT_KIND_V1
        || metadata.architecture != SEARCH_ARCHITECTURE_AARCH64_V1
        || metadata.little_endian != SEARCH_LITTLE_ENDIAN_V1
        || metadata.pointer_width != SEARCH_POINTER_WIDTH_V1
        || metadata.target_abi != SEARCH_TARGET_ABI_AAPCS64_V1
        || metadata.status_bits != SEARCH_STATUS_BITS_V1
        || metadata.abi_schema != SEARCH_CALL_ABI_SCHEMA_V1
        || !valid_metadata_target_profile(
            metadata.backend_version,
            metadata.platform,
            metadata.features,
        )
        || metadata.entry_offset != SEARCH_ENTRY_OFFSET_V1
        || metadata.literal_bytes != 0
        || !search_backend_literal_width_is_valid_v1(
            metadata.backend_version,
            metadata.rodata_bytes,
        )
        || metadata.binding_identity == [0; 32]
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

fn compute_metadata_compile_identity_v1(
    metadata: ClaimedSearchMetadataV1,
) -> Result<[u8; 32], SearchMetadataErrorV1> {
    match metadata.platform {
        SEARCH_PLATFORM_MACOS_V1 => Ok(compute_macho_metadata_compile_identity_v1(metadata)),
        SEARCH_PLATFORM_LINUX_V1 => Ok(compute_elf_metadata_compile_identity_v1(metadata)),
        _ => Err(metadata_error("compile identity platform")),
    }
}

fn compute_macho_metadata_compile_identity_v1(metadata: ClaimedSearchMetadataV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MACHO_COMPILE_IDENTITY_DOMAIN_V1);
    hasher.update(SEARCH_METADATA_VERSION_V1.to_le_bytes());
    hasher.update(SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1.to_le_bytes());
    hasher.update(SEARCH_EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1.to_le_bytes());
    for prefix in [
        SEARCH_ENTRY_SYMBOL_PREFIX_V1,
        AGGREGATE_ENTRY_SYMBOL_PREFIX_V1,
        PAYLOAD_SYMBOL_PREFIX_V1,
        METADATA_SYMBOL_PREFIX_V1,
    ] {
        hasher.update(
            u16::try_from(prefix.len())
                .expect("fixed MetadataV1 symbol prefix length fits u16")
                .to_le_bytes(),
        );
        hasher.update(prefix.as_bytes());
    }
    hasher.update(MIN_MACOS_VERSION_V1.to_le_bytes());
    hasher.update(metadata.backend_version.to_le_bytes());
    hasher.update([
        metadata.abi_kind,
        metadata.output_kind,
        metadata.architecture,
        metadata.little_endian,
        metadata.pointer_width,
        metadata.target_abi,
        metadata.platform,
        metadata.status_bits,
    ]);
    hasher.update(metadata.abi_schema.to_le_bytes());
    hasher.update(metadata.features.to_le_bytes());
    hasher.update(metadata.binding_identity);
    hasher.update(metadata.source_identity);
    hasher.update(metadata.artifact_identity);
    hasher.update(metadata.payload_sha256);
    hasher.update(metadata.payload_bytes.to_le_bytes());
    hasher.update(metadata.entry_offset.to_le_bytes());
    hasher.update(metadata.code_bytes.to_le_bytes());
    hasher.update(metadata.rodata_offset.to_le_bytes());
    hasher.update(metadata.rodata_bytes.to_le_bytes());
    hasher.update(metadata.literal_bytes.to_le_bytes());
    hasher.finalize().into()
}

fn compute_elf_metadata_compile_identity_v1(metadata: ClaimedSearchMetadataV1) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ELF_COMPILE_IDENTITY_DOMAIN_V1);
    hasher.update(SEARCH_METADATA_VERSION_V1.to_le_bytes());
    hasher.update(SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1.to_le_bytes());
    hasher.update(SEARCH_EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1.to_le_bytes());
    for prefix in [
        SEARCH_ENTRY_SYMBOL_PREFIX_V1,
        PAYLOAD_SYMBOL_PREFIX_V1,
        METADATA_SYMBOL_PREFIX_V1,
    ] {
        hasher.update(
            u16::try_from(prefix.len())
                .expect("fixed MetadataV1 symbol prefix length fits u16")
                .to_le_bytes(),
        );
        hasher.update(prefix.as_bytes());
    }
    hasher.update([
        ELF_CLASS_64_V1,
        ELF_DATA_LSB_V1,
        ELF_VERSION_CURRENT_V1,
        ELF_OS_ABI_SYSV_V1,
    ]);
    hasher.update(ELF_RELOCATABLE_TYPE_V1.to_le_bytes());
    hasher.update(ELF_MACHINE_AARCH64_V1.to_le_bytes());
    hasher.update(metadata.backend_version.to_le_bytes());
    hasher.update([
        metadata.abi_kind,
        metadata.output_kind,
        metadata.architecture,
        metadata.little_endian,
        metadata.pointer_width,
        metadata.target_abi,
        metadata.platform,
        metadata.status_bits,
    ]);
    hasher.update(metadata.abi_schema.to_le_bytes());
    hasher.update(metadata.features.to_le_bytes());
    hasher.update(metadata.binding_identity);
    hasher.update(metadata.source_identity);
    hasher.update(metadata.artifact_identity);
    hasher.update(metadata.payload_sha256);
    hasher.update(metadata.payload_bytes.to_le_bytes());
    hasher.update(metadata.entry_offset.to_le_bytes());
    hasher.update(metadata.code_bytes.to_le_bytes());
    hasher.update(metadata.rodata_offset.to_le_bytes());
    hasher.update(metadata.rodata_bytes.to_le_bytes());
    hasher.update(metadata.literal_bytes.to_le_bytes());
    hasher.finalize().into()
}

const fn valid_metadata_target_profile(backend: u16, platform: u8, features: u64) -> bool {
    let asimd = matches!(
        backend,
        SEARCH_BACKEND_VERSION_V1
            | SEARCH_BACKEND_ASIMD_TAG22_V1
            | SEARCH_BACKEND_ASIMD_TAG23_V1
            | SEARCH_BACKEND_ASIMD_TAG25_V1
            | SEARCH_BACKEND_ASIMD_TAG26_V1
            | SEARCH_BACKEND_ASIMD_TAG28_V1
            | SEARCH_BACKEND_ASIMD_TAG29_V1
            | SEARCH_BACKEND_ASIMD_TAG30_V1
            | SEARCH_BACKEND_ASIMD_TAG37_V1
    ) && (platform == SEARCH_PLATFORM_MACOS_V1 || platform == SEARCH_PLATFORM_LINUX_V1)
        && features == SEARCH_REQUIRED_ASIMD_FEATURES_V1;
    let tag21 = backend == SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1
        && platform == SEARCH_PLATFORM_LINUX_V1
        && features == SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1;
    asimd || tag21
}

const fn valid_expectation_target_profile(
    backend: u16,
    platform: u8,
    features: u64,
    symbol_info: u8,
) -> bool {
    matches!(
        (backend, platform, features, symbol_info),
        (
            SEARCH_BACKEND_VERSION_V1
                | SEARCH_BACKEND_ASIMD_TAG22_V1
                | SEARCH_BACKEND_ASIMD_TAG23_V1
                | SEARCH_BACKEND_ASIMD_TAG25_V1
                | SEARCH_BACKEND_ASIMD_TAG26_V1
                | SEARCH_BACKEND_ASIMD_TAG28_V1
                | SEARCH_BACKEND_ASIMD_TAG29_V1
                | SEARCH_BACKEND_ASIMD_TAG30_V1
                | SEARCH_BACKEND_ASIMD_TAG37_V1,
            SEARCH_PLATFORM_MACOS_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
        ) | (
            SEARCH_BACKEND_VERSION_V1
                | SEARCH_BACKEND_ASIMD_TAG22_V1
                | SEARCH_BACKEND_ASIMD_TAG23_V1
                | SEARCH_BACKEND_ASIMD_TAG25_V1
                | SEARCH_BACKEND_ASIMD_TAG26_V1
                | SEARCH_BACKEND_ASIMD_TAG28_V1
                | SEARCH_BACKEND_ASIMD_TAG29_V1
                | SEARCH_BACKEND_ASIMD_TAG30_V1
                | SEARCH_BACKEND_ASIMD_TAG37_V1,
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        ) | (
            SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1,
            SEARCH_PLATFORM_LINUX_V1,
            SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1,
            SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
        )
    )
}

/// Canonical, internally consistent, but still untrusted static expectation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedStaticSearchSpanExpectationV1 {
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
    status_bits: u8,
    exported_symbol_n_type: u8,
    required_features: u64,
    live_literal_bytes: u32,
    manifest_identity: [u8; 32],
    semantic_binding_identity: [u8; 32],
    literal_identity: [u8; 32],
    kir_identity: [u8; 32],
    artifact_identity: [u8; 32],
    binding_identity: [u8; 32],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    receipt_identity: [u8; 32],
    metadata: ClaimedSearchMetadataV1,
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

impl ClaimedStaticSearchSpanExpectationV1 {
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
    expectation_scalar_getter!(status_bits, u8);
    expectation_scalar_getter!(exported_symbol_n_type, u8);
    expectation_scalar_getter!(required_features, u64);
    expectation_scalar_getter!(live_literal_bytes, u32);

    #[must_use]
    pub const fn anchor_start(&self) -> bool {
        self.anchor_start == 1
    }

    #[must_use]
    pub const fn anchor_end(&self) -> bool {
        self.anchor_end == 1
    }

    #[must_use]
    pub const fn little_endian(&self) -> bool {
        self.little_endian == 1
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

    #[must_use]
    pub const fn metadata(&self) -> ClaimedSearchMetadataV1 {
        self.metadata
    }
}

/// Compute the domain-separated identity of one exact expectation body.
///
/// This function authenticates bytes only to themselves. It cannot create a
/// qualification row or grant runtime authority.
#[must_use]
pub fn compute_static_search_span_expectation_identity_v1(
    body: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_DOMAIN_V1);
    hasher.update(body);
    hasher.finalize().into()
}

/// Strictly inspect arbitrary bytes for the fixed static Search Span shape.
///
/// Successful inspection proves only canonical internal consistency. A
/// separate private qualification row must compare every authority-bearing
/// identity before a loader may inspect linked pointers or mapped bytes.
#[allow(
    clippy::too_many_lines,
    reason = "one linear decoder keeps every fixed expectation field, offset, correlation, and identity check auditable in wire order"
)]
pub fn inspect_static_search_span_expectation_v1(
    bytes: &[u8],
) -> Result<ClaimedStaticSearchSpanExpectationV1, StaticSearchSpanExpectationErrorV1> {
    if bytes.len() != STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1 {
        return Err(expectation_error("record bytes"));
    }
    let mut reader = ExpectationReader::new(bytes);
    reader.expect(
        &STATIC_SEARCH_SPAN_EXPECTATION_MAGIC_V1,
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
    let status_bits = reader.u8("status width")?;
    let exported_symbol_n_type = reader.u8("exported symbol n_type")?;
    let required_features = reader.u64("required features")?;
    let live_literal_bytes = reader.u32("live literal bytes")?;
    if schema_version != AOT_STATIC_SEARCH_SPAN_EXPECTATION_SCHEMA_VERSION_V1
        || compiler_version != AOT_SEARCH_COMPILER_VERSION_V1
        || usize::try_from(record_bytes).ok() != Some(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1)
        || usize::from(metadata_record_bytes) != SEARCH_METADATA_BYTES_V1
        || metadata_version != SEARCH_METADATA_VERSION_V1
        || call_abi_schema != SEARCH_CALL_ABI_SCHEMA_V1
        || exported_symbol_schema != SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1
        || output_kind != SEARCH_SPAN_OUTPUT_KIND_V1
        || anchor_start != SEARCH_DEFAULT_START_ANCHOR_V1
        || anchor_end != SEARCH_DEFAULT_END_ANCHOR_V1
        || architecture != SEARCH_ARCHITECTURE_AARCH64_V1
        || little_endian != SEARCH_LITTLE_ENDIAN_V1
        || pointer_width != SEARCH_POINTER_WIDTH_V1
        || target_abi != SEARCH_TARGET_ABI_AAPCS64_V1
        || status_bits != SEARCH_STATUS_BITS_V1
        || !valid_expectation_target_profile(
            backend_version,
            platform,
            required_features,
            exported_symbol_n_type,
        )
        || !search_backend_literal_width_is_valid_v1(backend_version, live_literal_bytes)
        || reader.position() != EXPECTATION_HEADER_BYTES_V1
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
    if reader.position() != STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1 {
        return Err(expectation_error("metadata offset"));
    }
    let metadata_bytes: [u8; SEARCH_METADATA_BYTES_V1] = reader.array("metadata")?;
    let metadata = inspect_search_metadata_v1(&metadata_bytes)
        .map_err(|_| expectation_error("metadata contract"))?;
    if reader.position() != STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1 {
        return Err(expectation_error("expectation identity offset"));
    }
    let expectation_identity = reader.array("expectation identity")?;
    let body: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1] = bytes
        .get(..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1)
        .and_then(|body| body.try_into().ok())
        .ok_or_else(|| expectation_error("expectation identity body"))?;
    let computed_identity = compute_static_search_span_expectation_identity_v1(body);
    if reader.position() != bytes.len() || expectation_identity != computed_identity {
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
        status_bits,
        required_features,
        live_literal_bytes,
        &kir_identity,
        &artifact_identity,
        &binding_identity,
        &compile_identity,
    )?;
    Ok(ClaimedStaticSearchSpanExpectationV1 {
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
        status_bits,
        exported_symbol_n_type,
        required_features,
        live_literal_bytes,
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
    metadata: ClaimedSearchMetadataV1,
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
    status_bits: u8,
    required_features: u64,
    live_literal_bytes: u32,
    kir_identity: &[u8; 32],
    artifact_identity: &[u8; 32],
    binding_identity: &[u8; 32],
    compile_identity: &[u8; 32],
) -> Result<(), StaticSearchSpanExpectationErrorV1> {
    if metadata.record_bytes != metadata_record_bytes
        || metadata.format_version != metadata_version
        || metadata.backend_version != backend_version
        || metadata.abi_schema != call_abi_schema
        || metadata.output_kind != output_kind
        || metadata.architecture != architecture
        || metadata.little_endian != little_endian
        || metadata.pointer_width != pointer_width
        || metadata.target_abi != target_abi
        || metadata.platform != platform
        || metadata.status_bits != status_bits
        || metadata.features != required_features
        || metadata.literal_bytes != 0
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

const fn metadata_error(at: &'static str) -> SearchMetadataErrorV1 {
    SearchMetadataErrorV1 { at }
}

const fn expectation_error(at: &'static str) -> StaticSearchSpanExpectationErrorV1 {
    StaticSearchSpanExpectationErrorV1 { at }
}

struct MetadataReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> MetadataReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, bytes: usize, at: &'static str) -> Result<&'a [u8], SearchMetadataErrorV1> {
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

    fn expect(&mut self, value: &[u8], at: &'static str) -> Result<(), SearchMetadataErrorV1> {
        if self.take(value.len(), at)? == value {
            Ok(())
        } else {
            Err(metadata_error(at))
        }
    }

    fn u8(&mut self, at: &'static str) -> Result<u8, SearchMetadataErrorV1> {
        self.take(1, at)?
            .first()
            .copied()
            .ok_or_else(|| metadata_error(at))
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, SearchMetadataErrorV1> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, SearchMetadataErrorV1> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn u64(&mut self, at: &'static str) -> Result<u64, SearchMetadataErrorV1> {
        Ok(u64::from_le_bytes(self.array(at)?))
    }

    fn array<const BYTES: usize>(
        &mut self,
        at: &'static str,
    ) -> Result<[u8; BYTES], SearchMetadataErrorV1> {
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
    ) -> Result<&'a [u8], StaticSearchSpanExpectationErrorV1> {
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
    ) -> Result<(), StaticSearchSpanExpectationErrorV1> {
        if self.take(value.len(), at)? == value {
            Ok(())
        } else {
            Err(expectation_error(at))
        }
    }

    fn u8(&mut self, at: &'static str) -> Result<u8, StaticSearchSpanExpectationErrorV1> {
        self.take(1, at)?
            .first()
            .copied()
            .ok_or_else(|| expectation_error(at))
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, StaticSearchSpanExpectationErrorV1> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, StaticSearchSpanExpectationErrorV1> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn u64(&mut self, at: &'static str) -> Result<u64, StaticSearchSpanExpectationErrorV1> {
        Ok(u64::from_le_bytes(self.array(at)?))
    }

    fn array<const BYTES: usize>(
        &mut self,
        at: &'static str,
    ) -> Result<[u8; BYTES], StaticSearchSpanExpectationErrorV1> {
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
    const METADATA_STATUS_BITS_OFFSET: usize = 21;
    const METADATA_ABI_SCHEMA_OFFSET: usize = 22;
    const METADATA_FEATURES_OFFSET: usize = 24;
    const METADATA_PAYLOAD_BYTES_OFFSET: usize = 32;
    const METADATA_ENTRY_OFFSET_OFFSET: usize = 36;
    const METADATA_CODE_BYTES_OFFSET: usize = 40;
    const METADATA_RODATA_OFFSET_OFFSET: usize = 44;
    const METADATA_RODATA_BYTES_OFFSET: usize = 48;
    const METADATA_LITERAL_BYTES_OFFSET: usize = 52;

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
    const EXPECTATION_STATUS_BITS_OFFSET: usize = 34;
    const EXPECTATION_SYMBOL_N_TYPE_OFFSET: usize = 35;
    const EXPECTATION_REQUIRED_FEATURES_OFFSET: usize = 36;
    const EXPECTATION_LIVE_LITERAL_BYTES_OFFSET: usize = 44;

    fn fixture_metadata_claim_with_literal_bytes(
        live_literal_bytes: u32,
    ) -> ClaimedSearchMetadataV1 {
        let mut metadata = ClaimedSearchMetadataV1 {
            format_version: SEARCH_METADATA_VERSION_V1,
            record_bytes: u16::try_from(SEARCH_METADATA_BYTES_V1).expect("small metadata"),
            backend_version: SEARCH_BACKEND_VERSION_V1,
            abi_kind: SEARCH_ABI_KIND_V1,
            output_kind: SEARCH_SPAN_OUTPUT_KIND_V1,
            architecture: SEARCH_ARCHITECTURE_AARCH64_V1,
            little_endian: SEARCH_LITTLE_ENDIAN_V1,
            pointer_width: SEARCH_POINTER_WIDTH_V1,
            target_abi: SEARCH_TARGET_ABI_AAPCS64_V1,
            platform: SEARCH_PLATFORM_MACOS_V1,
            status_bits: SEARCH_STATUS_BITS_V1,
            abi_schema: SEARCH_CALL_ABI_SCHEMA_V1,
            features: SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            payload_bytes: 240_u32
                .checked_add(live_literal_bytes)
                .expect("small fixture literal"),
            entry_offset: SEARCH_ENTRY_OFFSET_V1,
            code_bytes: 240,
            rodata_offset: 240,
            rodata_bytes: live_literal_bytes,
            literal_bytes: 0,
            source_identity: [0x11; 32],
            artifact_identity: [0x22; 32],
            binding_identity: [0x33; 32],
            payload_sha256: [0x44; 32],
            compile_identity: [0; 32],
        };
        metadata.compile_identity =
            compute_metadata_compile_identity_v1(metadata).expect("fixed metadata profile");
        metadata
    }

    fn fixture_metadata_claim() -> ClaimedSearchMetadataV1 {
        fixture_metadata_claim_with_literal_bytes(16)
    }

    fn fixture_metadata_with_literal_bytes(
        live_literal_bytes: u32,
    ) -> [u8; SEARCH_METADATA_BYTES_V1] {
        encode_metadata(fixture_metadata_claim_with_literal_bytes(
            live_literal_bytes,
        ))
    }

    fn fixture_metadata() -> [u8; SEARCH_METADATA_BYTES_V1] {
        fixture_metadata_with_literal_bytes(16)
    }

    fn encode_metadata(metadata: ClaimedSearchMetadataV1) -> [u8; SEARCH_METADATA_BYTES_V1] {
        let mut bytes = [0_u8; SEARCH_METADATA_BYTES_V1];
        let mut writer = TestWriter::new(&mut bytes);
        writer.bytes(&SEARCH_METADATA_MAGIC_V1);
        writer.u16(metadata.format_version);
        writer.u16(metadata.record_bytes);
        writer.u16(metadata.backend_version);
        writer.u8(metadata.abi_kind);
        writer.u8(metadata.output_kind);
        writer.u8(metadata.architecture);
        writer.u8(metadata.little_endian);
        writer.u8(metadata.pointer_width);
        writer.u8(metadata.target_abi);
        writer.u8(metadata.platform);
        writer.u8(metadata.status_bits);
        writer.u16(metadata.abi_schema);
        writer.u64(metadata.features);
        writer.u32(metadata.payload_bytes);
        writer.u32(metadata.entry_offset);
        writer.u32(metadata.code_bytes);
        writer.u32(metadata.rodata_offset);
        writer.u32(metadata.rodata_bytes);
        writer.u32(metadata.literal_bytes);
        writer.bytes(&metadata.source_identity);
        writer.bytes(&metadata.artifact_identity);
        writer.bytes(&metadata.binding_identity);
        writer.bytes(&metadata.payload_sha256);
        writer.bytes(&metadata.compile_identity);
        assert_eq!(writer.position(), SEARCH_METADATA_BYTES_V1);
        bytes
    }

    fn fixture_expectation_with_literal_bytes(
        live_literal_bytes: u32,
    ) -> StaticSearchSpanExpectationV1 {
        let metadata_claim = fixture_metadata_claim_with_literal_bytes(live_literal_bytes);
        let metadata = encode_metadata(metadata_claim);
        let mut bytes = [0_u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1];
        let mut writer = TestWriter::new(&mut bytes);
        writer.bytes(&STATIC_SEARCH_SPAN_EXPECTATION_MAGIC_V1);
        writer.u16(AOT_STATIC_SEARCH_SPAN_EXPECTATION_SCHEMA_VERSION_V1);
        writer.u16(AOT_SEARCH_COMPILER_VERSION_V1);
        writer.u32(
            u32::try_from(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1).expect("small expectation"),
        );
        writer.u16(u16::try_from(SEARCH_METADATA_BYTES_V1).expect("small metadata"));
        writer.u16(SEARCH_METADATA_VERSION_V1);
        writer.u16(SEARCH_BACKEND_VERSION_V1);
        writer.u16(SEARCH_CALL_ABI_SCHEMA_V1);
        writer.u16(SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1);
        writer.u8(SEARCH_SPAN_OUTPUT_KIND_V1);
        writer.u8(SEARCH_DEFAULT_START_ANCHOR_V1);
        writer.u8(SEARCH_DEFAULT_END_ANCHOR_V1);
        writer.u8(SEARCH_ARCHITECTURE_AARCH64_V1);
        writer.u8(SEARCH_LITTLE_ENDIAN_V1);
        writer.u8(SEARCH_POINTER_WIDTH_V1);
        writer.u8(SEARCH_TARGET_ABI_AAPCS64_V1);
        writer.u8(SEARCH_PLATFORM_MACOS_V1);
        writer.u8(SEARCH_STATUS_BITS_V1);
        writer.u8(SEARCH_EXPORTED_SYMBOL_N_TYPE_V1);
        writer.u64(SEARCH_REQUIRED_ASIMD_FEATURES_V1);
        writer.u32(live_literal_bytes);
        for identity_byte in [0x51, 0x52, 0x53] {
            writer.bytes(&[identity_byte; 32]);
        }
        writer.bytes(metadata_claim.source_identity());
        writer.bytes(metadata_claim.artifact_identity());
        writer.bytes(metadata_claim.binding_identity());
        writer.bytes(metadata_claim.compile_identity());
        writer.bytes(&[0x58; 32]);
        writer.bytes(&[0x59; 32]);
        assert_eq!(
            writer.position(),
            STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1
        );
        writer.bytes(&metadata);
        assert_eq!(
            writer.position(),
            STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1
        );
        let body: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1] = writer
            .written()
            .try_into()
            .expect("exact expectation identity body");
        let identity = compute_static_search_span_expectation_identity_v1(body);
        writer.bytes(&identity);
        assert_eq!(writer.position(), STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1);
        bytes
    }

    fn fixture_expectation() -> StaticSearchSpanExpectationV1 {
        fixture_expectation_with_literal_bytes(16)
    }

    fn linux_fixture_expectation_with_literal_bytes(
        backend: u16,
        features: u64,
        live_literal_bytes: u32,
    ) -> StaticSearchSpanExpectationV1 {
        let mut metadata = fixture_metadata_claim_with_literal_bytes(live_literal_bytes);
        metadata.backend_version = backend;
        metadata.platform = SEARCH_PLATFORM_LINUX_V1;
        metadata.features = features;
        metadata.compile_identity =
            compute_metadata_compile_identity_v1(metadata).expect("admitted Linux profile");
        let metadata_bytes = encode_metadata(metadata);

        let mut expectation = fixture_expectation();
        expectation[EXPECTATION_BACKEND_OFFSET..EXPECTATION_BACKEND_OFFSET + 2]
            .copy_from_slice(&backend.to_le_bytes());
        expectation[EXPECTATION_PLATFORM_OFFSET] = SEARCH_PLATFORM_LINUX_V1;
        expectation[EXPECTATION_SYMBOL_N_TYPE_OFFSET] = SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1;
        expectation[EXPECTATION_REQUIRED_FEATURES_OFFSET..EXPECTATION_LIVE_LITERAL_BYTES_OFFSET]
            .copy_from_slice(&features.to_le_bytes());
        expectation
            [EXPECTATION_LIVE_LITERAL_BYTES_OFFSET..EXPECTATION_LIVE_LITERAL_BYTES_OFFSET + 4]
            .copy_from_slice(&live_literal_bytes.to_le_bytes());
        expectation
            [EXPECTATION_COMPILE_IDENTITY_OFFSET_V1..EXPECTATION_COMPILE_IDENTITY_OFFSET_V1 + 32]
            .copy_from_slice(&metadata.compile_identity);
        expectation[STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1
            ..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1]
            .copy_from_slice(&metadata_bytes);
        refresh_expectation_identity(&mut expectation);
        expectation
    }

    fn linux_fixture_expectation(backend: u16, features: u64) -> StaticSearchSpanExpectationV1 {
        linux_fixture_expectation_with_literal_bytes(backend, features, 16)
    }

    fn refresh_expectation_identity(expectation: &mut StaticSearchSpanExpectationV1) {
        let body: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1] = expectation
            .get(..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1)
            .and_then(|body| body.try_into().ok())
            .expect("fixed expectation body");
        let identity = compute_static_search_span_expectation_identity_v1(body);
        expectation[STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1..].copy_from_slice(&identity);
    }

    #[test]
    fn wire_constants_pin_the_private_search_v1_span_slice() {
        assert_eq!(SEARCH_METADATA_BYTES_V1, 216);
        assert_eq!(SEARCH_BACKEND_VERSION_V1, 8);
        assert_eq!(SEARCH_BACKEND_ASIMD_TAG22_V1, 22);
        assert_eq!(SEARCH_BACKEND_ASIMD_TAG23_V1, 23);
        assert_eq!(SEARCH_BACKEND_ASIMD_TAG25_V1, 25);
        assert_eq!(SEARCH_BACKEND_ASIMD_TAG26_V1, 26);
        assert_eq!(SEARCH_BACKEND_ASIMD_TAG28_V1, 28);
        assert_eq!(SEARCH_BACKEND_ASIMD_TAG29_V1, 29);
        assert_eq!(SEARCH_BACKEND_ASIMD_TAG30_V1, 30);
        assert_eq!(SEARCH_BACKEND_ASIMD_TAG37_V1, 37);
        assert_eq!(SEARCH_BACKEND_ASIMD_TAG37_MIN_LITERAL_BYTES_V1, 6);
        assert_eq!(SEARCH_BACKEND_ASIMD_TAG37_MAX_LITERAL_BYTES_V1, 32);
        assert_eq!(SEARCH_BACKEND_ASIMD_TAG37_MANIFEST_FILTER_FIELDS_V1, 5);
        assert_eq!(SEARCH_SPAN_OUTPUT_KIND_V1, 3);
        assert_eq!(SEARCH_REQUIRED_ASIMD_FEATURES_V1, 1);
        assert_eq!(MIN_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1, 1);
        assert_eq!(MAX_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1, 32);
        assert_eq!(SEARCH_EXPORTED_SYMBOL_N_TYPE_V1, 0x0f);
        assert_eq!(STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1, 336);
        assert_eq!(STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1, 552);
        assert_eq!(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1, 584);
        assert_eq!(SEARCH_ENTRY_SYMBOL_PREFIX_V1, "fre_aot_search_entry_v1_");
        assert_eq!(
            AGGREGATE_ENTRY_SYMBOL_PREFIX_V1,
            "fre_aot_aggregate_entry_v1_"
        );
        assert_eq!(PAYLOAD_SYMBOL_PREFIX_V1, "fre_aot_payload_v1_");
        assert_eq!(METADATA_SYMBOL_PREFIX_V1, "fre_aot_metadata_v1_");
    }

    #[test]
    fn linux_v8_through_v24_candidates_and_explicit_tag21_are_structurally_admitted() {
        for (backend, features) in [
            (SEARCH_BACKEND_VERSION_V1, SEARCH_REQUIRED_ASIMD_FEATURES_V1),
            (
                SEARCH_BACKEND_ASIMD_TAG22_V1,
                SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            ),
            (
                SEARCH_BACKEND_ASIMD_TAG23_V1,
                SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            ),
            (
                SEARCH_BACKEND_ASIMD_TAG25_V1,
                SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            ),
            (
                SEARCH_BACKEND_ASIMD_TAG26_V1,
                SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            ),
            (
                SEARCH_BACKEND_ASIMD_TAG28_V1,
                SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            ),
            (
                SEARCH_BACKEND_ASIMD_TAG29_V1,
                SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            ),
            (
                SEARCH_BACKEND_ASIMD_TAG30_V1,
                SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            ),
            (
                SEARCH_BACKEND_ASIMD_TAG37_V1,
                SEARCH_REQUIRED_ASIMD_FEATURES_V1,
            ),
            (
                SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1,
                SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1,
            ),
        ] {
            let expectation = linux_fixture_expectation(backend, features);
            let claim = inspect_static_search_span_expectation_v1(&expectation)
                .expect("canonical Linux expectation");
            assert_eq!(claim.backend_version(), backend);
            assert_eq!(claim.platform(), SEARCH_PLATFORM_LINUX_V1);
            assert_eq!(claim.required_features(), features);
            assert_eq!(
                claim.exported_symbol_n_type(),
                SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1
            );
            assert_eq!(claim.metadata().backend_version(), backend);
            assert_eq!(claim.metadata().platform(), SEARCH_PLATFORM_LINUX_V1);
            assert_eq!(claim.metadata().features(), features);
        }
    }

    #[test]
    fn exact_metadata_is_strictly_projected() {
        let expected = fixture_metadata_claim();
        let actual = inspect_search_metadata_v1(&fixture_metadata()).expect("canonical metadata");
        assert_eq!(actual, expected);
        assert_eq!(actual.backend_version(), SEARCH_BACKEND_VERSION_V1);
        assert_eq!(actual.output_kind(), SEARCH_SPAN_OUTPUT_KIND_V1);
        assert_eq!(actual.features(), SEARCH_REQUIRED_ASIMD_FEATURES_V1);
        assert_eq!(actual.literal_bytes(), 0);
        assert_eq!(actual.rodata_bytes(), 16);
        assert_eq!(actual.entry_offset(), 0);
    }

    #[test]
    fn exact_expectation_is_strictly_projected_without_authority() {
        let bytes = fixture_expectation();
        let claim =
            inspect_static_search_span_expectation_v1(&bytes).expect("canonical expectation");
        assert_eq!(
            claim.schema_version(),
            AOT_STATIC_SEARCH_SPAN_EXPECTATION_SCHEMA_VERSION_V1
        );
        assert_eq!(claim.compiler_version(), AOT_SEARCH_COMPILER_VERSION_V1);
        assert_eq!(claim.live_literal_bytes(), 16);
        assert_eq!(claim.output_kind(), SEARCH_SPAN_OUTPUT_KIND_V1);
        assert!(!claim.anchor_start());
        assert!(!claim.anchor_end());
        assert_eq!(
            claim.exported_symbol_n_type(),
            SEARCH_EXPORTED_SYMBOL_N_TYPE_V1
        );
        assert_eq!(claim.kir_identity(), &[0x11; 32]);
        assert_eq!(claim.artifact_identity(), &[0x22; 32]);
        assert_eq!(claim.binding_identity(), &[0x33; 32]);
        assert_eq!(claim.metadata(), fixture_metadata_claim());
        assert_eq!(
            claim.expectation_identity(),
            &bytes[STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1..]
        );
    }

    #[test]
    fn independent_known_vectors_pin_both_identity_domains() {
        const EXPECTED_COMPILE: [u8; 32] = [
            0xb2, 0x87, 0xe0, 0xda, 0xcb, 0x82, 0x82, 0x4e, 0xcf, 0x8f, 0x0d, 0xe4, 0x5b, 0xf7,
            0x1f, 0x0c, 0x8d, 0x4e, 0x0e, 0x58, 0xb8, 0xc0, 0xcd, 0x16, 0xf4, 0x95, 0xc0, 0x7a,
            0x77, 0x57, 0x9d, 0x93,
        ];
        const EXPECTED_EXPECTATION: [u8; 32] = [
            0xf6, 0xb6, 0x15, 0xac, 0xa7, 0x39, 0x21, 0x5f, 0xfe, 0x2b, 0xfd, 0x43, 0xf6, 0x68,
            0xfa, 0xc9, 0x35, 0xc6, 0x13, 0xd8, 0x2d, 0xb6, 0xd2, 0x19, 0x7b, 0x0e, 0xbf, 0xdd,
            0x29, 0x80, 0xda, 0x90,
        ];
        let metadata = fixture_metadata_claim();
        assert_eq!(metadata.compile_identity, EXPECTED_COMPILE);
        let expectation = fixture_expectation();
        assert_eq!(
            expectation[STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1..],
            EXPECTED_EXPECTATION
        );
    }

    #[test]
    fn wrong_record_lengths_and_zero_records_are_refused() {
        let metadata = fixture_metadata();
        assert!(inspect_search_metadata_v1(&metadata[..metadata.len() - 1]).is_err());
        let mut longer_metadata = metadata.to_vec();
        longer_metadata.push(0);
        assert!(inspect_search_metadata_v1(&longer_metadata).is_err());
        assert!(inspect_search_metadata_v1(&[0; SEARCH_METADATA_BYTES_V1]).is_err());

        let expectation = fixture_expectation();
        assert!(
            inspect_static_search_span_expectation_v1(&expectation[..expectation.len() - 1])
                .is_err()
        );
        let mut longer_expectation = expectation.to_vec();
        longer_expectation.push(0);
        assert!(inspect_static_search_span_expectation_v1(&longer_expectation).is_err());
        assert!(
            inspect_static_search_span_expectation_v1(
                &[0; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1]
            )
            .is_err()
        );
    }

    #[test]
    fn live_literal_width_boundaries_are_exact() {
        for width in [
            MIN_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1,
            MAX_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1,
        ] {
            let expectation = fixture_expectation_with_literal_bytes(width);
            let claim = inspect_static_search_span_expectation_v1(&expectation)
                .expect("inclusive nonempty literal boundary");
            assert_eq!(claim.live_literal_bytes(), width);
            assert_eq!(claim.metadata().rodata_bytes(), width);
        }
        for width in [0_u32, 33_u32] {
            let expectation = fixture_expectation_with_literal_bytes(width);
            assert!(
                inspect_static_search_span_expectation_v1(&expectation).is_err(),
                "out-of-range live literal width {width} was accepted"
            );
        }
    }

    #[test]
    fn tag37_width_envelope_is_enforced_by_both_neutral_decoders() {
        for width in [
            SEARCH_BACKEND_ASIMD_TAG37_MIN_LITERAL_BYTES_V1,
            SEARCH_BACKEND_ASIMD_TAG37_MAX_LITERAL_BYTES_V1,
        ] {
            let expectation = linux_fixture_expectation_with_literal_bytes(
                SEARCH_BACKEND_ASIMD_TAG37_V1,
                SEARCH_REQUIRED_ASIMD_FEATURES_V1,
                width,
            );
            let claim = inspect_static_search_span_expectation_v1(&expectation)
                .expect("inclusive tag37 width boundary");
            assert_eq!(claim.live_literal_bytes(), width);
            assert_eq!(claim.metadata().rodata_bytes(), width);
        }
        for width in [0, 1, 5, 33] {
            let expectation = linux_fixture_expectation_with_literal_bytes(
                SEARCH_BACKEND_ASIMD_TAG37_V1,
                SEARCH_REQUIRED_ASIMD_FEATURES_V1,
                width,
            );
            assert!(
                inspect_static_search_span_expectation_v1(&expectation).is_err(),
                "out-of-envelope tag37 width {width} was accepted"
            );
            let metadata = expectation[STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1
                ..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1]
                .try_into()
                .expect("fixed metadata bytes");
            assert!(
                inspect_search_metadata_v1(metadata).is_err(),
                "metadata decoder accepted tag37 width {width}"
            );
        }
    }

    #[test]
    fn every_metadata_byte_is_bound_by_shape_or_compile_identity() {
        let original = fixture_metadata();
        for offset in 0..original.len() {
            let mut changed = original;
            changed[offset] ^= 1;
            assert!(
                inspect_search_metadata_v1(&changed).is_err(),
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
                inspect_static_search_span_expectation_v1(&changed).is_err(),
                "mutated expectation byte {offset} was accepted"
            );
        }
    }

    #[test]
    fn metadata_rejects_every_fixed_contract_field_with_or_without_compile_rehash() {
        let original = fixture_metadata_claim();
        let mutations: &[fn(&mut ClaimedSearchMetadataV1)] = &[
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
            |value| value.status_bits = 32,
            |value| value.abi_schema ^= 1,
            |value| value.features = 0,
            |value| value.entry_offset = 4,
            |value| value.literal_bytes = 1,
            |value| value.binding_identity = [0; 32],
        ];
        for mutate in mutations {
            let mut changed = original;
            mutate(&mut changed);
            if let Ok(identity) = compute_metadata_compile_identity_v1(changed) {
                changed.compile_identity = identity;
            }
            assert!(inspect_search_metadata_v1(&encode_metadata(changed)).is_err());
        }
    }

    #[test]
    fn metadata_rejects_every_invalid_image_layout_after_compile_rehash() {
        let original = fixture_metadata_claim();
        let mutations: &[fn(&mut ClaimedSearchMetadataV1)] = &[
            |value| value.code_bytes = 0,
            |value| value.code_bytes = 239,
            |value| value.rodata_offset = 239,
            |value| value.rodata_offset = 224,
            |value| value.payload_bytes = 255,
            |value| value.payload_bytes = u32::MAX,
        ];
        for mutate in mutations {
            let mut changed = original;
            mutate(&mut changed);
            changed.compile_identity =
                compute_metadata_compile_identity_v1(changed).expect("fixed metadata profile");
            assert!(inspect_search_metadata_v1(&encode_metadata(changed)).is_err());
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
            EXPECTATION_STATUS_BITS_OFFSET,
            EXPECTATION_SYMBOL_N_TYPE_OFFSET,
            EXPECTATION_REQUIRED_FEATURES_OFFSET,
        ];
        for offset in offsets {
            let mut changed = original;
            changed[offset] ^= 1;
            refresh_expectation_identity(&mut changed);
            assert!(
                inspect_static_search_span_expectation_v1(&changed).is_err(),
                "rehashed header mutation at {offset} was accepted"
            );
        }
        let mut too_wide = original;
        too_wide[EXPECTATION_LIVE_LITERAL_BYTES_OFFSET..EXPECTATION_LIVE_LITERAL_BYTES_OFFSET + 4]
            .copy_from_slice(&(MAX_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1 + 1).to_le_bytes());
        refresh_expectation_identity(&mut too_wide);
        assert!(inspect_static_search_span_expectation_v1(&too_wide).is_err());
    }

    #[test]
    fn expectation_rejects_every_rehashed_metadata_correlation_splice() {
        let original = fixture_expectation();
        for offset in [
            EXPECTATION_KIR_IDENTITY_OFFSET_V1,
            EXPECTATION_ARTIFACT_IDENTITY_OFFSET_V1,
            EXPECTATION_BINDING_IDENTITY_OFFSET_V1,
            EXPECTATION_COMPILE_IDENTITY_OFFSET_V1,
        ] {
            let mut changed = original;
            changed[offset] ^= 1;
            refresh_expectation_identity(&mut changed);
            assert!(
                inspect_static_search_span_expectation_v1(&changed).is_err(),
                "rehashed correlation splice at {offset} was accepted"
            );
        }

        let mut wrong_live_width = original;
        wrong_live_width
            [EXPECTATION_LIVE_LITERAL_BYTES_OFFSET..EXPECTATION_LIVE_LITERAL_BYTES_OFFSET + 4]
            .copy_from_slice(&15_u32.to_le_bytes());
        refresh_expectation_identity(&mut wrong_live_width);
        assert!(inspect_static_search_span_expectation_v1(&wrong_live_width).is_err());
    }

    #[test]
    fn uncorrelated_claims_remain_untrusted_and_change_the_outer_identity() {
        let original = fixture_expectation();
        let original_claim =
            inspect_static_search_span_expectation_v1(&original).expect("baseline claim");
        for offset in [
            EXPECTATION_MANIFEST_IDENTITY_OFFSET_V1,
            EXPECTATION_SEMANTIC_BINDING_IDENTITY_OFFSET_V1,
            EXPECTATION_LITERAL_IDENTITY_OFFSET_V1,
            EXPECTATION_OBJECT_IDENTITY_OFFSET_V1,
            EXPECTATION_RECEIPT_IDENTITY_OFFSET_V1,
        ] {
            let mut changed = original;
            changed[offset] ^= 1;
            refresh_expectation_identity(&mut changed);
            let changed_claim = inspect_static_search_span_expectation_v1(&changed)
                .expect("a self-consistent claim is not qualification authority");
            assert_ne!(
                changed_claim.expectation_identity(),
                original_claim.expectation_identity()
            );
        }
    }

    #[test]
    fn expectation_identity_domain_covers_every_body_byte() {
        let original = fixture_expectation();
        let body: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1] = original
            .get(..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1)
            .and_then(|body| body.try_into().ok())
            .expect("fixed body");
        let original_identity = compute_static_search_span_expectation_identity_v1(body);
        for offset in 0..body.len() {
            let mut changed = *body;
            changed[offset] ^= 1;
            assert_ne!(
                compute_static_search_span_expectation_identity_v1(&changed),
                original_identity,
                "body mutation at {offset} preserved the expectation identity"
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one offset test keeps the complete published MetadataV1 wire layout visible in byte order"
    )]
    fn documented_metadata_offsets_match_the_published_v1_wire() {
        let metadata = fixture_metadata();
        assert_eq!(
            u16::from_le_bytes(
                metadata[METADATA_FORMAT_VERSION_OFFSET..METADATA_FORMAT_VERSION_OFFSET + 2]
                    .try_into()
                    .expect("u16")
            ),
            SEARCH_METADATA_VERSION_V1
        );
        assert_eq!(
            u16::from_le_bytes(
                metadata[METADATA_RECORD_BYTES_OFFSET..METADATA_RECORD_BYTES_OFFSET + 2]
                    .try_into()
                    .expect("u16")
            ),
            u16::try_from(SEARCH_METADATA_BYTES_V1).expect("small metadata")
        );
        assert_eq!(
            u16::from_le_bytes(
                metadata[METADATA_BACKEND_VERSION_OFFSET..METADATA_BACKEND_VERSION_OFFSET + 2]
                    .try_into()
                    .expect("u16")
            ),
            SEARCH_BACKEND_VERSION_V1
        );
        assert_eq!(metadata[METADATA_ABI_KIND_OFFSET], SEARCH_ABI_KIND_V1);
        assert_eq!(
            metadata[METADATA_OUTPUT_KIND_OFFSET],
            SEARCH_SPAN_OUTPUT_KIND_V1
        );
        assert_eq!(
            metadata[METADATA_ARCHITECTURE_OFFSET],
            SEARCH_ARCHITECTURE_AARCH64_V1
        );
        assert_eq!(
            metadata[METADATA_LITTLE_ENDIAN_OFFSET],
            SEARCH_LITTLE_ENDIAN_V1
        );
        assert_eq!(
            metadata[METADATA_POINTER_WIDTH_OFFSET],
            SEARCH_POINTER_WIDTH_V1
        );
        assert_eq!(
            metadata[METADATA_TARGET_ABI_OFFSET],
            SEARCH_TARGET_ABI_AAPCS64_V1
        );
        assert_eq!(metadata[METADATA_PLATFORM_OFFSET], SEARCH_PLATFORM_MACOS_V1);
        assert_eq!(metadata[METADATA_STATUS_BITS_OFFSET], SEARCH_STATUS_BITS_V1);
        assert_eq!(
            u16::from_le_bytes(
                metadata[METADATA_ABI_SCHEMA_OFFSET..METADATA_ABI_SCHEMA_OFFSET + 2]
                    .try_into()
                    .expect("u16")
            ),
            SEARCH_CALL_ABI_SCHEMA_V1
        );
        assert_eq!(
            u64::from_le_bytes(
                metadata[METADATA_FEATURES_OFFSET..METADATA_FEATURES_OFFSET + 8]
                    .try_into()
                    .expect("u64")
            ),
            SEARCH_REQUIRED_ASIMD_FEATURES_V1
        );
        assert_eq!(
            u32::from_le_bytes(
                metadata[METADATA_PAYLOAD_BYTES_OFFSET..METADATA_PAYLOAD_BYTES_OFFSET + 4]
                    .try_into()
                    .expect("u32")
            ),
            256
        );
        assert_eq!(
            u32::from_le_bytes(
                metadata[METADATA_ENTRY_OFFSET_OFFSET..METADATA_ENTRY_OFFSET_OFFSET + 4]
                    .try_into()
                    .expect("u32")
            ),
            SEARCH_ENTRY_OFFSET_V1
        );
        assert_eq!(
            u32::from_le_bytes(
                metadata[METADATA_CODE_BYTES_OFFSET..METADATA_CODE_BYTES_OFFSET + 4]
                    .try_into()
                    .expect("u32")
            ),
            240
        );
        assert_eq!(
            u32::from_le_bytes(
                metadata[METADATA_RODATA_OFFSET_OFFSET..METADATA_RODATA_OFFSET_OFFSET + 4]
                    .try_into()
                    .expect("u32")
            ),
            240
        );
        assert_eq!(
            u32::from_le_bytes(
                metadata[METADATA_RODATA_BYTES_OFFSET..METADATA_RODATA_BYTES_OFFSET + 4]
                    .try_into()
                    .expect("u32")
            ),
            16
        );
        assert_eq!(
            u32::from_le_bytes(
                metadata[METADATA_LITERAL_BYTES_OFFSET..METADATA_LITERAL_BYTES_OFFSET + 4]
                    .try_into()
                    .expect("u32")
            ),
            0
        );
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
