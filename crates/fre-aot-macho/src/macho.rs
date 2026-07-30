use core::{fmt, mem::size_of};

use fre_aot_aarch64::{
    AOT_COUNT_BACKEND_VERSION_V2, AotCountCpuFeatures, AotCountImageV2, CountAuditReportV2,
    audit_count_image_v2, is_supported_aot_count_backend_tuple_v2, prospective_count_v2,
};
use fre_jit_aarch64::{
    AuditReport, BackendVersion, CpuFeatures, DecodedInstruction, ImageLayout,
    NativeAggregateImage, NativeImage, TargetSpec, audit, audit_aggregate,
};
use fre_kernel_ir::{AggregateOutput, Count, ExactAggregateProgram, OutputKind};
use sha2::{Digest, Sha256};

use crate::{ArithmeticSite, BindingIdentityError, ObjectError, ObjectResource};

mod count_v2;
pub use count_v2::{
    BuiltCountObjectV2, CALL_ABI_SCHEMA_V2, COUNT_ENTRY_SYMBOL_PREFIX_V2,
    COUNT_EXPORTED_SYMBOL_N_TYPE_V2, COUNT_METADATA_SYMBOL_PREFIX_V2,
    COUNT_PAYLOAD_SYMBOL_PREFIX_V2, ClaimedCountCompileIdentityV2, ClaimedCountObjectIdentityV2,
    CountCompileIdentityV2, CountObjectBuildReportV2, CountObjectIdentityV2,
    CountObjectInspectionV2, CountObjectValidationV2, ENTRY_OFFSET_V2,
    EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2, EXPORTED_SYMBOL_SCHEMA_VERSION_V2, ExportedSymbolNameV2,
    ExportedSymbolsV2, METADATA_BYTES_V2, METADATA_V2_WRITER_SCRATCH_BYTES, METADATA_VERSION_V2,
    MetadataV2, STATUS_BITS_V2, emit_count_object_v2, inspect_count_object_v2,
    validate_count_object_v2,
};

/// Stable C types and ABI declarations shared by every generated symbol set.
///
/// Concrete extern declarations are identity-specific and are rendered with
/// [`ExportedSymbolsV1::write_c_declarations`].
pub const C_HEADER: &str = include_str!("../include/fre_aot_macho.h");

pub const SEARCH_ENTRY_SYMBOL_PREFIX_V1: &str = "fre_aot_search_entry_v1_";
pub const AGGREGATE_ENTRY_SYMBOL_PREFIX_V1: &str = "fre_aot_aggregate_entry_v1_";
pub const PAYLOAD_SYMBOL_PREFIX_V1: &str = "fre_aot_payload_v1_";
pub const METADATA_SYMBOL_PREFIX_V1: &str = "fre_aot_metadata_v1_";
pub const EXPORTED_SYMBOL_SCHEMA_VERSION_V1: u16 = 1;
pub const EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1: usize = 64;
const EXPORTED_SYMBOL_STORAGE_BYTES_V1: usize = 96;
const MACH_EXTERNAL_PREFIX_BYTES: usize = 1;
const SYMBOL_TERMINATOR_BYTES: usize = 1;

pub const METADATA_VERSION: u16 = 1;
pub const METADATA_BYTES_V1: usize = 216;
pub const ENTRY_OFFSET_V1: u32 = 0;
const METADATA_MAGIC: [u8; 8] = *b"FREOM64\x01";
pub const PLATFORM_MACOS: u8 = 1;
pub const CALL_ABI_SCHEMA_V1: u16 = 1;
pub const STATUS_BITS_V1: u8 = 64;
pub const MIN_MACOS_VERSION_V1: u32 = 0x000b_0000;
const COMPILE_IDENTITY_DOMAIN: &[u8] = b"FRE-AOT-MACHO-COMPILE\0\x02";
const _: () = assert!(BackendVersion::SEARCH_V8.0 == 8);
const _: () = assert!(BackendVersion::AGGREGATE_CURRENT.0 == 1);
const _: () = assert!(AOT_COUNT_BACKEND_VERSION_V2.0 == 0xa002);

pub const HARD_MAX_PAYLOAD_BYTES: u64 = 4 << 20;
pub const HARD_MAX_OBJECT_BYTES: u64 = 5 << 20;
pub const HARD_MAX_PERSISTENT_BYTES: u64 = 6 << 20;
pub const HARD_MAX_WORK: u64 = 24 << 20;
pub const HARD_MAX_SCRATCH_BYTES: u64 = 64 << 10;
pub const HARD_MAX_SECTIONS: u64 = 2;
pub const HARD_MAX_SYMBOLS: u64 = 3;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
const MH_OBJECT: u32 = 1;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x02;
const LC_DYSYMTAB: u32 = 0x0b;
const LC_BUILD_VERSION: u32 = 0x32;
const PLATFORM_MACOS_LOAD_COMMAND: u32 = 1;
const MACH_HEADER_BYTES: usize = 32;
const SEGMENT_COMMAND_BYTES: usize = 72;
const SECTION_COMMAND_BYTES: usize = 80;
const SEGMENT_WITH_SECTIONS_BYTES: usize = SEGMENT_COMMAND_BYTES + (SECTION_COMMAND_BYTES * 2);
const BUILD_VERSION_COMMAND_BYTES: usize = 24;
const SYMTAB_COMMAND_BYTES: usize = 24;
const DYSYMTAB_COMMAND_BYTES: usize = 80;
const LOAD_COMMAND_BYTES: usize = SEGMENT_WITH_SECTIONS_BYTES
    + BUILD_VERSION_COMMAND_BYTES
    + SYMTAB_COMMAND_BYTES
    + DYSYMTAB_COMMAND_BYTES;
const LOAD_COMMAND_COUNT: u32 = 4;
pub(crate) const CONTENT_OFFSET: usize = 400;
const NLIST_64_BYTES: usize = 16;
const N_SECT_EXT: u8 = 0x0f;
const PAYLOAD_SECTION_FLAGS: u32 = 0x1000_0400;
const METADATA_SECTION_FLAGS: u32 = 0x1000_0000;
const VM_PROT_RWX: u32 = 7;

const _: () = assert!(MACH_HEADER_BYTES + LOAD_COMMAND_BYTES <= CONTENT_OFFSET);
const _: () = assert!(METADATA_BYTES_V1 == 216);

/// Callable contract carried by one object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AbiKind {
    Search = 1,
    Aggregate = 2,
}

impl AbiKind {
    fn from_byte(value: u8) -> Result<Self, ObjectError> {
        match value {
            1 => Ok(Self::Search),
            2 => Ok(Self::Aggregate),
            _ => Err(ObjectError::InvalidObject {
                at: "metadata ABI kind",
            }),
        }
    }

    const fn entry_symbol_prefix(self) -> &'static str {
        match self {
            Self::Search => SEARCH_ENTRY_SYMBOL_PREFIX_V1,
            Self::Aggregate => AGGREGATE_ENTRY_SYMBOL_PREFIX_V1,
        }
    }

    const fn as_byte(self) -> u8 {
        match self {
            Self::Search => 1,
            Self::Aggregate => 2,
        }
    }
}

/// Required planner/build provenance digest, separate from IR and native identity.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct BindingIdentity([u8; 32]);

impl BindingIdentity {
    /// Domain-separated fallback for callers operating directly below a planner.
    ///
    /// Higher-level compilation facades should always pass their own canonical
    /// profile/source/plan/build digest instead.
    pub const LOW_LEVEL_V1: Self = Self([
        0x99, 0x40, 0xec, 0xaa, 0x20, 0xb4, 0xc3, 0x4b, 0xa2, 0x8e, 0x82, 0xc0, 0xc0, 0xac, 0x28,
        0x7e, 0xbb, 0xf2, 0xd0, 0xfd, 0xe6, 0x18, 0xf9, 0x80, 0x83, 0x93, 0x26, 0x7c, 0x2b, 0x5d,
        0x54, 0x1a,
    ]);

    pub fn new(bytes: [u8; 32]) -> Result<Self, BindingIdentityError> {
        if bytes == [0; 32] {
            return Err(BindingIdentityError);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn matches_claim(self, claim: ClaimedBindingIdentity) -> bool {
        self.0 == claim.0
    }
}

/// Untrusted planner-binding claim read from object metadata.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ClaimedBindingIdentity([u8; 32]);

impl ClaimedBindingIdentity {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ClaimedBindingIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ClaimedBindingIdentity({self})")
    }
}

impl fmt::Display for ClaimedBindingIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_digest(formatter, &self.0)
    }
}

impl fmt::Debug for BindingIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BindingIdentity({self})")
    }
}

impl fmt::Display for BindingIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_digest(formatter, &self.0)
    }
}

/// Trusted expected compile value persisted outside the generated artifact.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CompileIdentity([u8; 32]);

impl CompileIdentity {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn matches_claim(self, claim: ClaimedCompileIdentity) -> bool {
        self.0 == claim.0
    }
}

/// Untrusted compile-identity claim read from self-described metadata.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ClaimedCompileIdentity([u8; 32]);

impl ClaimedCompileIdentity {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ClaimedCompileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ClaimedCompileIdentity({self})")
    }
}

impl fmt::Display for ClaimedCompileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_digest(formatter, &self.0)
    }
}

impl fmt::Debug for CompileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CompileIdentity({self})")
    }
}

impl fmt::Display for CompileIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_digest(formatter, &self.0)
    }
}

/// One allocation-free external symbol name derived from a compile identity.
///
/// The full 256-bit lowercase hexadecimal identity is retained. No truncated
/// namespace or process-global alias is emitted.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ExportedSymbolNameV1 {
    bytes: [u8; EXPORTED_SYMBOL_STORAGE_BYTES_V1],
    len: usize,
}

impl ExportedSymbolNameV1 {
    fn new(prefix: &str, identity: CompileIdentity) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let mut bytes = [0_u8; EXPORTED_SYMBOL_STORAGE_BYTES_V1];
        let prefix_bytes = prefix.as_bytes();
        let expected_len = prefix_bytes
            .len()
            .checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1)
            .expect("fixed symbol-name length fits usize");
        assert!(
            expected_len <= EXPORTED_SYMBOL_STORAGE_BYTES_V1,
            "fixed symbol-name storage must fit every v1 prefix"
        );
        bytes[..prefix_bytes.len()].copy_from_slice(prefix_bytes);
        for (byte, output) in identity
            .0
            .into_iter()
            .zip(bytes[prefix_bytes.len()..expected_len].chunks_exact_mut(2))
        {
            output[0] = HEX[usize::from(byte >> 4)];
            output[1] = HEX[usize::from(byte & 0x0f)];
        }
        Self {
            bytes,
            len: expected_len,
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes())
            .expect("identity-suffixed v1 symbol names are canonical ASCII")
    }
}

impl fmt::Debug for ExportedSymbolNameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ExportedSymbolNameV1")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for ExportedSymbolNameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Complete, collision-resistant external namespace for one generated object.
///
/// Entry, payload, and metadata names all carry the same full compile
/// identity. The ABI kind selects only the entry prefix. A loader must derive
/// this set from its trusted expected compile identity rather than trusting a
/// name discovered in the linked image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportedSymbolsV1 {
    abi_kind: AbiKind,
    compile_identity: CompileIdentity,
    entry: ExportedSymbolNameV1,
    payload: ExportedSymbolNameV1,
    metadata: ExportedSymbolNameV1,
}

impl ExportedSymbolsV1 {
    #[must_use]
    pub fn for_compile_identity(abi_kind: AbiKind, compile_identity: CompileIdentity) -> Self {
        Self {
            abi_kind,
            compile_identity,
            entry: ExportedSymbolNameV1::new(abi_kind.entry_symbol_prefix(), compile_identity),
            payload: ExportedSymbolNameV1::new(PAYLOAD_SYMBOL_PREFIX_V1, compile_identity),
            metadata: ExportedSymbolNameV1::new(METADATA_SYMBOL_PREFIX_V1, compile_identity),
        }
    }

    #[must_use]
    pub const fn abi_kind(&self) -> AbiKind {
        self.abi_kind
    }

    #[must_use]
    pub const fn compile_identity(&self) -> CompileIdentity {
        self.compile_identity
    }

    #[must_use]
    pub const fn entry(&self) -> &ExportedSymbolNameV1 {
        &self.entry
    }

    #[must_use]
    pub const fn payload(&self) -> &ExportedSymbolNameV1 {
        &self.payload
    }

    #[must_use]
    pub const fn metadata(&self) -> &ExportedSymbolNameV1 {
        &self.metadata
    }

    /// Render the concrete extern declarations paired with [`C_HEADER`].
    ///
    /// This does not allocate; build tooling chooses the destination. The
    /// identity-specific declaration must be generated from a trusted
    /// [`BuiltObject`] or compile receipt, not from an unauthenticated object.
    pub fn write_c_declarations(&self, output: &mut impl fmt::Write) -> fmt::Result {
        writeln!(output, "#if defined(__cplusplus)")?;
        writeln!(output, "extern \"C\" {{")?;
        writeln!(output, "#endif")?;
        match self.abi_kind {
            AbiKind::Search => writeln!(
                output,
                "extern uint64_t {}(const uint8_t *haystack, size_t haystack_len, size_t window_start, size_t window_end, struct fre_aot_search_result_v1 *result);",
                self.entry
            )?,
            AbiKind::Aggregate => writeln!(
                output,
                "extern uint64_t {}(const uint8_t *haystack, size_t haystack_len, struct fre_aot_aggregate_result_v1 *result);",
                self.entry
            )?,
        }
        writeln!(output, "extern const uint8_t {}[];", self.payload)?;
        writeln!(
            output,
            "extern const struct fre_aot_metadata_v1 {};",
            self.metadata
        )?;
        writeln!(output, "#if defined(__cplusplus)")?;
        writeln!(output, "}}")?;
        writeln!(output, "#endif")
    }
}

/// SHA-256 over every byte of the final `MH_OBJECT`.
///
/// This identity is intentionally external to metadata to avoid a
/// self-reference. The higher-level compiler receipt persists it as the
/// loader's expected file identity.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ObjectIdentity([u8; 32]);

impl ObjectIdentity {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn matches_claim(self, claim: ClaimedObjectIdentity) -> bool {
        self.0 == claim.0
    }
}

/// Untrusted complete-file digest computed while inspecting caller bytes.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ClaimedObjectIdentity([u8; 32]);

impl ClaimedObjectIdentity {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ClaimedObjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ClaimedObjectIdentity({self})")
    }
}

impl fmt::Display for ClaimedObjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_digest(formatter, &self.0)
    }
}

impl fmt::Debug for ObjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ObjectIdentity({self})")
    }
}

impl fmt::Display for ObjectIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_digest(formatter, &self.0)
    }
}

fn write_digest(formatter: &mut fmt::Formatter<'_>, bytes: &[u8; 32]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// Fixed-version metadata record emitted as canonical little-endian bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataV1 {
    magic: [u8; 8],
    format_version: u16,
    record_bytes: u16,
    backend_version: u16,
    abi_kind: AbiKind,
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

impl MetadataV1 {
    #[must_use]
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }

    #[must_use]
    pub const fn record_bytes(&self) -> u16 {
        self.record_bytes
    }

    #[must_use]
    pub const fn backend_version(&self) -> u16 {
        self.backend_version
    }

    #[must_use]
    pub const fn abi_kind(&self) -> AbiKind {
        self.abi_kind
    }

    #[must_use]
    pub const fn output_kind(&self) -> u8 {
        self.output_kind
    }

    #[must_use]
    pub const fn architecture(&self) -> u8 {
        self.architecture
    }

    #[must_use]
    pub const fn little_endian(&self) -> bool {
        self.little_endian == 1
    }

    #[must_use]
    pub const fn pointer_width(&self) -> u8 {
        self.pointer_width
    }

    #[must_use]
    pub const fn target_abi(&self) -> u8 {
        self.target_abi
    }

    #[must_use]
    pub const fn platform(&self) -> u8 {
        self.platform
    }

    #[must_use]
    pub const fn status_bits(&self) -> u8 {
        self.status_bits
    }

    #[must_use]
    pub const fn abi_schema(&self) -> u16 {
        self.abi_schema
    }

    #[must_use]
    pub const fn features(&self) -> u64 {
        self.features
    }

    #[must_use]
    pub const fn payload_bytes(&self) -> u32 {
        self.payload_bytes
    }

    #[must_use]
    pub const fn entry_offset(&self) -> u32 {
        self.entry_offset
    }

    #[must_use]
    pub const fn code_bytes(&self) -> u32 {
        self.code_bytes
    }

    #[must_use]
    pub const fn rodata_offset(&self) -> u32 {
        self.rodata_offset
    }

    #[must_use]
    pub const fn rodata_bytes(&self) -> u32 {
        self.rodata_bytes
    }

    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        self.literal_bytes
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
    pub const fn payload_sha256(&self) -> &[u8; 32] {
        &self.payload_sha256
    }

    #[must_use]
    pub const fn claimed_compile_identity(&self) -> ClaimedCompileIdentity {
        ClaimedCompileIdentity(self.compile_identity)
    }

    #[must_use]
    pub const fn claimed_binding_identity(&self) -> ClaimedBindingIdentity {
        ClaimedBindingIdentity(self.binding_identity)
    }

    fn encode(self) -> Result<[u8; METADATA_BYTES_V1], ObjectError> {
        let mut bytes = [0_u8; METADATA_BYTES_V1];
        let mut writer = FixedWriter::new(&mut bytes);
        writer.bytes(&self.magic)?;
        writer.u16(self.format_version)?;
        writer.u16(self.record_bytes)?;
        writer.u16(self.backend_version)?;
        writer.u8(self.abi_kind.as_byte())?;
        writer.u8(self.output_kind)?;
        writer.u8(self.architecture)?;
        writer.u8(self.little_endian)?;
        writer.u8(self.pointer_width)?;
        writer.u8(self.target_abi)?;
        writer.u8(self.platform)?;
        writer.u8(self.status_bits)?;
        writer.u16(self.abi_schema)?;
        writer.u64(self.features)?;
        writer.u32(self.payload_bytes)?;
        writer.u32(self.entry_offset)?;
        writer.u32(self.code_bytes)?;
        writer.u32(self.rodata_offset)?;
        writer.u32(self.rodata_bytes)?;
        writer.u32(self.literal_bytes)?;
        writer.bytes(&self.source_identity)?;
        writer.bytes(&self.artifact_identity)?;
        writer.bytes(&self.binding_identity)?;
        writer.bytes(&self.payload_sha256)?;
        writer.bytes(&self.compile_identity)?;
        if writer.position() != METADATA_BYTES_V1 {
            return Err(ObjectError::InternalInvariant {
                at: "metadata encoding length",
            });
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, ObjectError> {
        if bytes.len() != METADATA_BYTES_V1 {
            return Err(ObjectError::InvalidObject {
                at: "metadata section length",
            });
        }
        let mut reader = Reader::new(bytes);
        let metadata = Self {
            magic: reader.array("metadata magic")?,
            format_version: reader.u16("metadata version")?,
            record_bytes: reader.u16("metadata record bytes")?,
            backend_version: reader.u16("metadata backend version")?,
            abi_kind: AbiKind::from_byte(reader.u8("metadata ABI kind")?)?,
            output_kind: reader.u8("metadata output kind")?,
            architecture: reader.u8("metadata architecture")?,
            little_endian: reader.u8("metadata byte order")?,
            pointer_width: reader.u8("metadata pointer width")?,
            target_abi: reader.u8("metadata target ABI")?,
            platform: reader.u8("metadata platform")?,
            status_bits: reader.u8("metadata status width")?,
            abi_schema: reader.u16("metadata ABI schema")?,
            features: reader.u64("metadata features")?,
            payload_bytes: reader.u32("metadata payload bytes")?,
            entry_offset: reader.u32("metadata entry offset")?,
            code_bytes: reader.u32("metadata code bytes")?,
            rodata_offset: reader.u32("metadata rodata offset")?,
            rodata_bytes: reader.u32("metadata rodata bytes")?,
            literal_bytes: reader.u32("metadata literal bytes")?,
            source_identity: reader.array("metadata source identity")?,
            artifact_identity: reader.array("metadata artifact identity")?,
            binding_identity: reader.array("metadata binding identity")?,
            payload_sha256: reader.array("metadata payload digest")?,
            compile_identity: reader.array("metadata compile identity")?,
        };
        if reader.position() != bytes.len() {
            return Err(ObjectError::InvalidObject {
                at: "metadata trailing bytes",
            });
        }
        metadata.validate_shape()?;
        Ok(metadata)
    }

    fn validate_shape(self) -> Result<(), ObjectError> {
        if self.magic != METADATA_MAGIC
            || self.format_version != METADATA_VERSION
            || usize::from(self.record_bytes) != METADATA_BYTES_V1
            || self.platform != PLATFORM_MACOS
            || self.status_bits != STATUS_BITS_V1
            || self.abi_schema != CALL_ABI_SCHEMA_V1
            || self.architecture != 1
            || self.little_endian != 1
            || self.pointer_width != 64
            || self.target_abi != 1
            || self.entry_offset != ENTRY_OFFSET_V1
            || self.features & !1 != 0
            || self.binding_identity == [0; 32]
        {
            return Err(ObjectError::InvalidObject {
                at: "metadata v1 contract",
            });
        }
        let backend_contract = match (self.abi_kind, self.backend_version) {
            (AbiKind::Search, version)
                if version == BackendVersion::SEARCH_V8.0
                    || version == BackendVersion::SEARCH_V9.0
                    || version == BackendVersion::SEARCH_V10.0
                    || version == BackendVersion::SEARCH_V12.0
                    || version == BackendVersion::SEARCH_V13.0
                    || version == BackendVersion::SEARCH_V15.0
                    || version == BackendVersion::SEARCH_V16.0 =>
            {
                (1..=3).contains(&self.output_kind) && self.literal_bytes == 0
            }
            (AbiKind::Aggregate, version) if version == BackendVersion::AGGREGATE_CURRENT.0 => {
                (1..=2).contains(&self.output_kind)
                    && self.literal_bytes <= 32
                    && self.rodata_bytes == self.literal_bytes
            }
            (AbiKind::Aggregate, version) if version == AOT_COUNT_BACKEND_VERSION_V2.0 => {
                self.output_kind == 1
                    && self.literal_bytes <= 32
                    && self.rodata_bytes == 0
                    && self.features == u64::from(self.literal_bytes != 0)
            }
            _ => false,
        };
        if !backend_contract {
            return Err(ObjectError::InvalidObject {
                at: "metadata backend contract",
            });
        }
        if self.code_bytes == 0
            || !self.code_bytes.is_multiple_of(4)
            || !self.rodata_offset.is_multiple_of(16)
            || self.rodata_offset < self.code_bytes
            || self
                .rodata_offset
                .checked_add(self.rodata_bytes)
                .is_none_or(|total| total != self.payload_bytes)
        {
            return Err(ObjectError::InvalidObject {
                at: "metadata image layout",
            });
        }
        Ok(())
    }
}

/// Caller-selected limits, each additionally capped by a crate hard maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectLimits {
    pub max_object_bytes: u64,
    /// Retained `Vec` capacity, which may exceed the serialized file length.
    pub max_persistent_bytes: u64,
    pub max_payload_bytes: u64,
    pub max_work: u64,
    pub max_scratch_bytes: u64,
    pub max_sections: u64,
    pub max_symbols: u64,
}

impl Default for ObjectLimits {
    fn default() -> Self {
        Self {
            max_object_bytes: HARD_MAX_OBJECT_BYTES,
            max_persistent_bytes: HARD_MAX_PERSISTENT_BYTES,
            max_payload_bytes: HARD_MAX_PAYLOAD_BYTES,
            max_work: HARD_MAX_WORK,
            max_scratch_bytes: HARD_MAX_SCRATCH_BYTES,
            max_sections: HARD_MAX_SECTIONS,
            max_symbols: HARD_MAX_SYMBOLS,
        }
    }
}

/// Bounded resource and authenticity receipt from object construction.
///
/// Work and image-audit scratch are conservative upper bounds. Object length
/// and retained capacity are observed exact values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectBuildReport {
    pub object_bytes: usize,
    pub persistent_capacity_bytes: usize,
    pub payload_bytes: usize,
    /// Conservative work ceiling charged before the independent image audit.
    pub image_audit_work_upper_bound: u64,
    /// Expected-image payload/identity comparisons charged before validation.
    pub image_binding_work_upper_bound: u64,
    /// Payload hashing, object writing, strict parsing, and both digest passes.
    pub object_work: u64,
    pub total_work: u64,
    pub object_scratch_bytes: u64,
    pub image_audit_scratch_upper_bound: u64,
    pub scratch_bytes: u64,
    pub sections: u32,
    pub symbols: u32,
    pub image_audit: AuditReport,
    pub compile_identity: CompileIdentity,
    pub object_identity: ObjectIdentity,
}

/// Owned deterministic Mach-O bytes paired with a trusted compile receipt.
#[derive(Debug, Eq, PartialEq)]
pub struct BuiltObject {
    bytes: Vec<u8>,
    metadata: MetadataV1,
    report: ObjectBuildReport,
}

impl BuiltObject {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn metadata(&self) -> MetadataV1 {
        self.metadata
    }

    #[must_use]
    pub const fn report(&self) -> ObjectBuildReport {
        self.report
    }

    #[must_use]
    pub const fn compile_identity(&self) -> CompileIdentity {
        self.report.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> ObjectIdentity {
        self.report.object_identity
    }

    /// Exact identity-suffixed names emitted by this trusted object.
    #[must_use]
    pub fn exported_symbols(&self) -> ExportedSymbolsV1 {
        ExportedSymbolsV1::for_compile_identity(
            self.metadata.abi_kind,
            self.report.compile_identity,
        )
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Allocation-free view of canonical, internally self-consistent caller bytes.
///
/// Identities in this view remain untrusted claims until compared with an
/// external receipt or returned through `validate_*` against a retained image
/// and expected binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectInspection<'a> {
    metadata: MetadataV1,
    metadata_bytes: &'a [u8],
    payload: &'a [u8],
    object_bytes: usize,
    work: u64,
    scratch_bytes: u64,
    claimed_object_identity: ClaimedObjectIdentity,
}

impl<'a> ObjectInspection<'a> {
    #[must_use]
    pub const fn metadata(&self) -> MetadataV1 {
        self.metadata
    }

    /// Canonical validated metadata bytes exactly as retained in the object.
    #[must_use]
    pub const fn metadata_bytes(&self) -> &'a [u8] {
        self.metadata_bytes
    }

    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    #[must_use]
    pub const fn object_bytes(&self) -> usize {
        self.object_bytes
    }

    #[must_use]
    pub const fn work(&self) -> u64 {
        self.work
    }

    #[must_use]
    pub const fn scratch_bytes(&self) -> u64 {
        self.scratch_bytes
    }

    #[must_use]
    pub const fn claimed_compile_identity(&self) -> ClaimedCompileIdentity {
        self.metadata.claimed_compile_identity()
    }

    #[must_use]
    pub const fn claimed_object_identity(&self) -> ClaimedObjectIdentity {
        self.claimed_object_identity
    }
}

/// Strict object inspection plus a fresh semantic audit of the expected image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectValidation<'a> {
    pub inspection: ObjectInspection<'a>,
    pub image_audit: AuditReport,
}

#[derive(Clone, Copy)]
struct ImageView<'a> {
    backend_version: u16,
    target: TargetSpec,
    abi_kind: AbiKind,
    output_kind: u8,
    source_identity: [u8; 32],
    artifact_identity: [u8; 32],
    layout: ImageLayout,
    code: &'a [u8],
    rodata: &'a [u8],
    literal_bytes: u32,
    labels: usize,
    data_symbols: usize,
    relocations: usize,
}

impl<'a> ImageView<'a> {
    fn search(image: &'a NativeImage) -> Self {
        Self {
            backend_version: image.backend_version().0,
            target: image.target(),
            abi_kind: AbiKind::Search,
            output_kind: output_tag(image.output()),
            source_identity: *image.source_identity().as_bytes(),
            artifact_identity: *image.artifact_identity().as_bytes(),
            layout: image.layout(),
            code: image.code(),
            rodata: image.rodata(),
            literal_bytes: 0,
            labels: image.labels().len(),
            data_symbols: image.symbols().len(),
            relocations: image.relocations().len(),
        }
    }

    fn aggregate(image: &'a NativeAggregateImage) -> Self {
        Self {
            backend_version: image.backend_version().0,
            target: image.target(),
            abi_kind: AbiKind::Aggregate,
            output_kind: aggregate_output_tag(image.output()),
            source_identity: *image.source_identity().as_bytes(),
            artifact_identity: *image.artifact_identity().as_bytes(),
            layout: image.layout(),
            code: image.code(),
            rodata: image.rodata(),
            literal_bytes: image.literal_bytes(),
            labels: image.labels().len(),
            data_symbols: image.symbols().len(),
            relocations: image.relocations().len(),
        }
    }

    fn count_v2(image: &'a AotCountImageV2) -> Result<Self, ObjectError> {
        let support = image.support();
        let source_target = image.target();
        let literal_bytes = image.literal_bytes();
        let expected_features = if literal_bytes == 0 {
            AotCountCpuFeatures::NONE
        } else {
            AotCountCpuFeatures::ASIMD
        };
        if image.backend_version() != AOT_COUNT_BACKEND_VERSION_V2
            || !is_supported_aot_count_backend_tuple_v2(support)
            || support.output_kind != 1
            || literal_bytes > u32::from(support.max_literal_bytes)
            || source_target.architecture != support.architecture
            || source_target.little_endian != support.little_endian
            || source_target.pointer_width != support.pointer_width
            || source_target.abi != support.target_abi
            || source_target.features != expected_features
            || !image.rodata().is_empty()
        {
            return Err(ObjectError::InvalidObject {
                at: "Count v2 backend support tuple",
            });
        }
        let features = match source_target.features.bits() {
            bits if bits == AotCountCpuFeatures::NONE.bits() => CpuFeatures::NONE,
            bits if bits == AotCountCpuFeatures::ASIMD.bits() => CpuFeatures::ASIMD,
            _ => {
                return Err(ObjectError::InvalidObject {
                    at: "Count v2 target features",
                });
            }
        };
        let source_layout = image.layout();
        Ok(Self {
            backend_version: image.backend_version().0,
            target: TargetSpec {
                architecture: source_target.architecture,
                little_endian: source_target.little_endian,
                pointer_width: source_target.pointer_width,
                abi: source_target.abi,
                features,
            },
            abi_kind: AbiKind::Aggregate,
            output_kind: image.output_kind(),
            source_identity: *image.source_identity().as_bytes(),
            artifact_identity: *image.artifact_identity().as_bytes(),
            layout: ImageLayout {
                code_alignment: source_layout.code_alignment,
                rodata_alignment: source_layout.rodata_alignment,
                rodata_from_code_start: source_layout.rodata_from_code_start,
                total_mapped_bytes: source_layout.total_mapped_bytes,
            },
            code: image.code(),
            rodata: image.rodata(),
            literal_bytes,
            labels: image.labels().len(),
            data_symbols: image.data_symbol_count(),
            relocations: image.relocations().len(),
        })
    }
}

const fn output_tag(output: OutputKind) -> u8 {
    match output {
        OutputKind::Exists => 1,
        OutputKind::SelectedEnd => 2,
        OutputKind::Span => 3,
    }
}

const fn aggregate_output_tag(output: AggregateOutput) -> u8 {
    match output {
        AggregateOutput::Count => 1,
        AggregateOutput::SpanSum => 2,
    }
}

/// Independently audit and publish a five-argument search image as `MH_OBJECT`.
pub fn emit_search_object(
    image: &NativeImage,
    binding: BindingIdentity,
    limits: ObjectLimits,
) -> Result<BuiltObject, ObjectError> {
    let view = ImageView::search(image);
    let preflight = preflight(view, limits)?;
    let image_audit = audit(image).map_err(ObjectError::ImageAudit)?;
    build_object(view, binding, limits, preflight, image_audit)
}

/// Independently audit and publish a whole-haystack aggregate image as `MH_OBJECT`.
pub fn emit_aggregate_object(
    image: &NativeAggregateImage,
    binding: BindingIdentity,
    limits: ObjectLimits,
) -> Result<BuiltObject, ObjectError> {
    let view = ImageView::aggregate(image);
    let preflight = preflight(view, limits)?;
    let image_audit = audit_aggregate(image).map_err(ObjectError::ImageAudit)?;
    build_object(view, binding, limits, preflight, image_audit)
}

/// Independently audit and publish a direct Count AOT v2 image as `MH_OBJECT`.
pub fn emit_count_v2_object(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV2,
    binding: BindingIdentity,
    limits: ObjectLimits,
) -> Result<BuiltObject, ObjectError> {
    let view = ImageView::count_v2(image)?;
    let prospective = prospective_count_v2(program).map_err(ObjectError::CountImageAudit)?;
    let preflight = preflight_with_image_audit(
        view,
        limits,
        prospective.audit_work_upper_bound,
        prospective.audit_scratch_bytes_upper_bound,
    )?;
    let image_audit = audit_count_image_v2(program, image).map_err(ObjectError::CountImageAudit)?;
    let image_audit = sealed_count_v2_audit_report(
        image,
        prospective.audit_work_upper_bound,
        prospective.audit_scratch_bytes_upper_bound,
        image_audit,
    )?;
    build_object(view, binding, limits, preflight, image_audit)
}

/// Re-audit an expected search image and bind it to strict object inspection.
pub fn validate_search_object<'a>(
    image: &NativeImage,
    binding: BindingIdentity,
    bytes: &'a [u8],
    limits: ObjectLimits,
) -> Result<ObjectValidation<'a>, ObjectError> {
    let view = ImageView::search(image);
    let inspection_work = preflight_inspection_resources(bytes.len(), limits)?;
    enforce_validation_resources(view, inspection_work, limits)?;
    let inspection = inspect_object(bytes, limits)?;
    let image_audit = audit(image).map_err(ObjectError::ImageAudit)?;
    validate_view(view, binding, &inspection)?;
    Ok(ObjectValidation {
        inspection,
        image_audit,
    })
}

/// Re-audit an expected aggregate image and bind it to strict object inspection.
pub fn validate_aggregate_object<'a>(
    image: &NativeAggregateImage,
    binding: BindingIdentity,
    bytes: &'a [u8],
    limits: ObjectLimits,
) -> Result<ObjectValidation<'a>, ObjectError> {
    let view = ImageView::aggregate(image);
    let inspection_work = preflight_inspection_resources(bytes.len(), limits)?;
    enforce_validation_resources(view, inspection_work, limits)?;
    let inspection = inspect_object(bytes, limits)?;
    let image_audit = audit_aggregate(image).map_err(ObjectError::ImageAudit)?;
    validate_view(view, binding, &inspection)?;
    Ok(ObjectValidation {
        inspection,
        image_audit,
    })
}

/// Re-audit an expected Count AOT v2 image and bind it to strict object inspection.
pub fn validate_count_v2_object<'a>(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV2,
    binding: BindingIdentity,
    bytes: &'a [u8],
    limits: ObjectLimits,
) -> Result<ObjectValidation<'a>, ObjectError> {
    let view = ImageView::count_v2(image)?;
    let prospective = prospective_count_v2(program).map_err(ObjectError::CountImageAudit)?;
    let inspection_work = preflight_inspection_resources(bytes.len(), limits)?;
    enforce_validation_resources_with_image_audit(
        view,
        inspection_work,
        limits,
        prospective.audit_work_upper_bound,
        prospective.audit_scratch_bytes_upper_bound,
    )?;
    let inspection = inspect_object(bytes, limits)?;
    let image_audit = audit_count_image_v2(program, image).map_err(ObjectError::CountImageAudit)?;
    let image_audit = sealed_count_v2_audit_report(
        image,
        prospective.audit_work_upper_bound,
        prospective.audit_scratch_bytes_upper_bound,
        image_audit,
    )?;
    validate_view(view, binding, &inspection)?;
    Ok(ObjectValidation {
        inspection,
        image_audit,
    })
}

fn sealed_count_v2_audit_report(
    image: &AotCountImageV2,
    source_work: u64,
    source_scratch: u64,
    report: CountAuditReportV2,
) -> Result<AuditReport, ObjectError> {
    let receipt = image.build_receipt();
    let stats = image.stats();
    if report != receipt.audit
        || report.work_upper_bound != source_work
        || report.scratch_bytes_upper_bound != source_scratch
        || stats.audit_work_upper_bound != source_work
        || receipt.work_upper_bound != stats.total_work_upper_bound
        || receipt.scratch_bytes_upper_bound != stats.scratch_bytes_upper_bound
    {
        return Err(ObjectError::InvalidObject {
            at: "Count v2 sealed resource report",
        });
    }
    Ok(count_v2_audit_report(report))
}

const fn count_v2_audit_report(report: CountAuditReportV2) -> AuditReport {
    AuditReport {
        decode_passes: report.decode_passes,
        source_identity_rebuilds: report.source_identity_rebuilds,
        instructions: report.instructions,
        direct_branches: report.direct_branches,
        data_addresses: 0,
        vector_instructions: report.vector_instructions,
        stores: report.stores,
        returns: report.returns,
    }
}

#[derive(Clone, Copy)]
struct BuildPreflight {
    layout: ObjectLayout,
    image_audit_work_upper_bound: u64,
    image_binding_work_upper_bound: u64,
    object_scratch_bytes: u64,
    image_audit_scratch_upper_bound: u64,
    scratch_bytes: u64,
    total_work: u64,
}

fn preflight(view: ImageView<'_>, limits: ObjectLimits) -> Result<BuildPreflight, ObjectError> {
    let image_audit_work_upper_bound = audit_work_upper_bound(view)?;
    let image_audit_scratch_upper_bound = audit_scratch_upper_bound(view)?;
    preflight_with_image_audit(
        view,
        limits,
        image_audit_work_upper_bound,
        image_audit_scratch_upper_bound,
    )
}

fn preflight_with_image_audit(
    view: ImageView<'_>,
    limits: ObjectLimits,
    image_audit_work_upper_bound: u64,
    image_audit_scratch_upper_bound: u64,
) -> Result<BuildPreflight, ObjectError> {
    let payload_bytes = usize::try_from(view.layout.total_mapped_bytes).map_err(|_| {
        ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        }
    })?;
    if usize::try_from(view.layout.rodata_from_code_start).ok()
        != Some(payload_bytes.checked_sub(view.rodata.len()).ok_or(
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::ImageLayout,
            },
        )?)
        || view.code.len()
            > usize::try_from(view.layout.rodata_from_code_start).map_err(|_| {
                ObjectError::ArithmeticOverflow {
                    site: ArithmeticSite::Conversion,
                }
            })?
    {
        return Err(ObjectError::InvalidObject {
            at: "source image layout",
        });
    }
    let layout = ObjectLayout::new(payload_bytes, view.abi_kind)?;
    let image_binding_work_upper_bound = binding_work_upper_bound(view)?;
    let object_scratch_bytes = object_scratch_bytes()?;
    let scratch_bytes = object_scratch_bytes
        .checked_add(image_audit_scratch_upper_bound)
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::ObjectLayout,
        })?;
    let total_work = layout
        .total_work
        .checked_add(image_audit_work_upper_bound)
        .and_then(|work| work.checked_add(image_binding_work_upper_bound))
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        })?;
    enforce_all(
        ObjectResource::PayloadBytes,
        usize_u64(payload_bytes)?,
        limits.max_payload_bytes,
        HARD_MAX_PAYLOAD_BYTES,
    )?;
    enforce_all(
        ObjectResource::ObjectBytes,
        usize_u64(layout.object_bytes)?,
        limits.max_object_bytes,
        HARD_MAX_OBJECT_BYTES,
    )?;
    enforce_all(
        ObjectResource::PersistentBytes,
        usize_u64(layout.object_bytes)?,
        limits.max_persistent_bytes,
        HARD_MAX_PERSISTENT_BYTES,
    )?;
    enforce_all(
        ObjectResource::Work,
        total_work,
        limits.max_work,
        HARD_MAX_WORK,
    )?;
    enforce_all(
        ObjectResource::ScratchBytes,
        scratch_bytes,
        limits.max_scratch_bytes,
        HARD_MAX_SCRATCH_BYTES,
    )?;
    enforce_all(
        ObjectResource::Sections,
        HARD_MAX_SECTIONS,
        limits.max_sections,
        HARD_MAX_SECTIONS,
    )?;
    enforce_all(
        ObjectResource::Symbols,
        HARD_MAX_SYMBOLS,
        limits.max_symbols,
        HARD_MAX_SYMBOLS,
    )?;
    Ok(BuildPreflight {
        layout,
        image_audit_work_upper_bound,
        image_binding_work_upper_bound,
        object_scratch_bytes,
        image_audit_scratch_upper_bound,
        scratch_bytes,
        total_work,
    })
}

fn audit_work_upper_bound(view: ImageView<'_>) -> Result<u64, ObjectError> {
    let code_bytes = usize_u64(view.code.len())?;
    let code_words = code_bytes.checked_add(3).map(|bytes| bytes / 4).ok_or(
        ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        },
    )?;
    let labels = usize_u64(view.labels)?;
    let symbols = usize_u64(view.data_symbols)?;
    let relocations = usize_u64(view.relocations)?;
    let rodata_bytes = usize_u64(view.rodata.len())?;
    let manifest_records = labels
        .checked_add(symbols)
        .and_then(|value| value.checked_add(relocations))
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        })?;
    let instruction_scan =
        code_words
            .checked_mul(manifest_records.checked_add(64).ok_or(
                ObjectError::ArithmeticOverflow {
                    site: ArithmeticSite::Work,
                },
            )?)
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Work,
            })?;
    // This deliberately charges a full instruction-pair matrix even though
    // current auditors are predominantly linear. It bounds CFG/template
    // cross-checks without coupling this crate to their internal iteration.
    let instruction_pairs =
        code_words
            .checked_mul(code_words)
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Work,
            })?;
    let symbol_pairs = symbols
        .checked_mul(symbols)
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        })?;
    let identity_bytes = 132_u64
        .checked_add(code_bytes)
        .and_then(|value| value.checked_add(rodata_bytes))
        .and_then(|value| value.checked_add(labels.checked_mul(8)?))
        .and_then(|value| value.checked_add(symbols.checked_mul(16)?))
        .and_then(|value| value.checked_add(relocations.checked_mul(20)?))
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        })?;
    instruction_scan
        .checked_add(instruction_pairs)
        .and_then(|value| value.checked_add(symbol_pairs))
        .and_then(|value| value.checked_add(identity_bytes))
        .and_then(|value| value.checked_mul(8))
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        })
}

fn audit_scratch_upper_bound(view: ImageView<'_>) -> Result<u64, ObjectError> {
    let code_words = view
        .code
        .len()
        .checked_add(3)
        .map(|bytes| bytes / 4)
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::ObjectLayout,
        })?;
    let decoded_bytes = code_words
        .checked_mul(size_of::<DecodedInstruction>())
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::ObjectLayout,
        })?;
    let decoded_capacity_bound = decoded_bytes
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(size_of::<Vec<DecodedInstruction>>()))
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::ObjectLayout,
        })?;
    let reachability_capacity_bound =
        code_words
            .checked_mul(2)
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::ObjectLayout,
            })?;
    // Aggregate control-flow reachability plus small exact-program rebuilding
    // are covered by one byte per instruction and a fixed width-32 envelope.
    let logical_bytes = (16_usize << 10)
        .checked_add(decoded_capacity_bound)
        .and_then(|bytes| bytes.checked_add(reachability_capacity_bound))
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::ObjectLayout,
        })?;
    usize_u64(logical_bytes)
}

fn binding_work_upper_bound(view: ImageView<'_>) -> Result<u64, ObjectError> {
    // validate_view compares every payload byte against the trusted expected
    // image plus a fixed set of scalar and 32-byte identity fields.
    usize_u64(view.code.len())?
        .checked_add(usize_u64(view.rodata.len())?)
        .and_then(|work| work.checked_add(16))
        .and_then(|work| work.checked_add(256))
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        })
}

fn enforce_validation_resources(
    view: ImageView<'_>,
    inspection_work: u64,
    limits: ObjectLimits,
) -> Result<(), ObjectError> {
    let image_audit_work = audit_work_upper_bound(view)?;
    let image_audit_scratch = audit_scratch_upper_bound(view)?;
    enforce_validation_resources_with_image_audit(
        view,
        inspection_work,
        limits,
        image_audit_work,
        image_audit_scratch,
    )
}

fn enforce_validation_resources_with_image_audit(
    view: ImageView<'_>,
    inspection_work: u64,
    limits: ObjectLimits,
    image_audit_work: u64,
    image_audit_scratch: u64,
) -> Result<(), ObjectError> {
    let image_binding_work = binding_work_upper_bound(view)?;
    let total = inspection_work
        .checked_add(image_audit_work)
        .and_then(|work| work.checked_add(image_binding_work))
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        })?;
    enforce_all(ObjectResource::Work, total, limits.max_work, HARD_MAX_WORK)?;
    enforce_all(
        ObjectResource::ScratchBytes,
        object_scratch_bytes()?
            .checked_add(image_audit_scratch)
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::ObjectLayout,
            })?,
        limits.max_scratch_bytes,
        HARD_MAX_SCRATCH_BYTES,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "one ordered object-construction transaction keeps publication checks auditable"
)]
fn build_object(
    view: ImageView<'_>,
    binding: BindingIdentity,
    limits: ObjectLimits,
    preflight: BuildPreflight,
    image_audit: AuditReport,
) -> Result<BuiltObject, ObjectError> {
    let layout = preflight.layout;
    let payload_sha256 = hash_image_payload(view)?;
    let payload_u32 =
        u32::try_from(layout.payload_bytes).map_err(|_| ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        })?;
    let mut metadata = MetadataV1 {
        magic: METADATA_MAGIC,
        format_version: METADATA_VERSION,
        record_bytes: u16::try_from(METADATA_BYTES_V1).map_err(|_| {
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            }
        })?,
        backend_version: view.backend_version,
        abi_kind: view.abi_kind,
        output_kind: view.output_kind,
        architecture: view.target.architecture,
        little_endian: u8::from(view.target.little_endian),
        pointer_width: view.target.pointer_width,
        target_abi: view.target.abi,
        platform: PLATFORM_MACOS,
        status_bits: STATUS_BITS_V1,
        abi_schema: CALL_ABI_SCHEMA_V1,
        features: view.target.features.bits(),
        payload_bytes: payload_u32,
        entry_offset: ENTRY_OFFSET_V1,
        code_bytes: u32::try_from(view.code.len()).map_err(|_| {
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            }
        })?,
        rodata_offset: view.layout.rodata_from_code_start,
        rodata_bytes: u32::try_from(view.rodata.len()).map_err(|_| {
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            }
        })?,
        literal_bytes: view.literal_bytes,
        source_identity: view.source_identity,
        artifact_identity: view.artifact_identity,
        binding_identity: *binding.as_bytes(),
        payload_sha256,
        compile_identity: [0; 32],
    };
    let compile_identity = compute_compile_identity(metadata);
    metadata.compile_identity = compile_identity.0;
    let exported_symbols = ExportedSymbolsV1::for_compile_identity(view.abi_kind, compile_identity);
    let metadata_bytes = metadata.encode()?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(layout.object_bytes)
        .map_err(|_| ObjectError::AllocationFailed)?;
    let persistent_capacity_bytes = bytes.capacity();
    enforce_all(
        ObjectResource::PersistentBytes,
        usize_u64(persistent_capacity_bytes)?,
        limits.max_persistent_bytes,
        HARD_MAX_PERSISTENT_BYTES,
    )?;
    write_object_prefix(&mut bytes, layout)?;
    expect_length(&bytes, CONTENT_OFFSET, "payload file offset")?;
    bytes.extend_from_slice(view.code);
    let rodata_offset = usize::try_from(view.layout.rodata_from_code_start).map_err(|_| {
        ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        }
    })?;
    resize_zero(
        &mut bytes,
        CONTENT_OFFSET
            .checked_add(rodata_offset)
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::FileOffset,
            })?,
    )?;
    bytes.extend_from_slice(view.rodata);
    resize_zero(&mut bytes, layout.metadata_file_offset)?;
    bytes.extend_from_slice(&metadata_bytes);
    write_symbol_and_string_tables(&mut bytes, layout, &exported_symbols)?;
    expect_length(&bytes, layout.object_bytes, "complete object length")?;

    let inspection = inspect_object(&bytes, limits)?;
    validate_view(view, binding, &inspection)?;
    if inspection.metadata != metadata {
        return Err(ObjectError::InternalInvariant {
            at: "self-inspected metadata",
        });
    }
    let object_identity = ObjectIdentity(*inspection.claimed_object_identity().as_bytes());
    Ok(BuiltObject {
        bytes,
        metadata,
        report: ObjectBuildReport {
            object_bytes: layout.object_bytes,
            persistent_capacity_bytes,
            payload_bytes: layout.payload_bytes,
            image_audit_work_upper_bound: preflight.image_audit_work_upper_bound,
            image_binding_work_upper_bound: preflight.image_binding_work_upper_bound,
            object_work: layout.total_work,
            total_work: preflight.total_work,
            object_scratch_bytes: preflight.object_scratch_bytes,
            image_audit_scratch_upper_bound: preflight.image_audit_scratch_upper_bound,
            scratch_bytes: preflight.scratch_bytes,
            sections: u32::try_from(HARD_MAX_SECTIONS).expect("small constant"),
            symbols: u32::try_from(HARD_MAX_SYMBOLS).expect("small constant"),
            image_audit,
            compile_identity,
            object_identity,
        },
    })
}

fn hash_image_payload(view: ImageView<'_>) -> Result<[u8; 32], ObjectError> {
    let rodata_offset = usize::try_from(view.layout.rodata_from_code_start).map_err(|_| {
        ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        }
    })?;
    let gap = rodata_offset
        .checked_sub(view.code.len())
        .ok_or(ObjectError::InvalidObject {
            at: "source code/rodata overlap",
        })?;
    if gap >= 16 {
        return Err(ObjectError::InvalidObject {
            at: "source image alignment gap",
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(view.code);
    hasher.update(&[0_u8; 16][..gap]);
    hasher.update(view.rodata);
    let digest = hasher.finalize();
    digest_array(&digest)
}

fn compute_compile_identity(metadata: MetadataV1) -> CompileIdentity {
    let mut hasher = Sha256::new();
    hasher.update(COMPILE_IDENTITY_DOMAIN);
    hasher.update(METADATA_VERSION.to_le_bytes());
    hasher.update(EXPORTED_SYMBOL_SCHEMA_VERSION_V1.to_le_bytes());
    hasher.update(
        u16::try_from(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1)
            .expect("fixed identity width fits u16")
            .to_le_bytes(),
    );
    for prefix in [
        SEARCH_ENTRY_SYMBOL_PREFIX_V1,
        AGGREGATE_ENTRY_SYMBOL_PREFIX_V1,
        PAYLOAD_SYMBOL_PREFIX_V1,
        METADATA_SYMBOL_PREFIX_V1,
    ] {
        hasher.update(
            u16::try_from(prefix.len())
                .expect("fixed symbol prefix length fits u16")
                .to_le_bytes(),
        );
        hasher.update(prefix.as_bytes());
    }
    hasher.update(MIN_MACOS_VERSION_V1.to_le_bytes());
    hasher.update(metadata.backend_version.to_le_bytes());
    hasher.update([
        metadata.abi_kind.as_byte(),
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
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    CompileIdentity(bytes)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MetadataMutationForTest {
    AbiSearch,
    AbiAggregate,
    OutputSpanSum,
    FeaturesNone,
    LiteralTooWide,
    BackendSearchV8,
    BackendAggregateCurrent,
    BackendCountV2,
    UnknownBackend,
    RodataPresent,
}

#[cfg(test)]
pub(crate) fn rewrite_metadata_with_recomputed_compile_identity_for_test(
    built: &BuiltObject,
    mutation: MetadataMutationForTest,
) -> Vec<u8> {
    let mut metadata = built.metadata;
    let original_abi = metadata.abi_kind;
    match mutation {
        MetadataMutationForTest::AbiSearch => {
            metadata.abi_kind = AbiKind::Search;
        }
        MetadataMutationForTest::AbiAggregate => {
            metadata.abi_kind = AbiKind::Aggregate;
        }
        MetadataMutationForTest::OutputSpanSum => {
            metadata.output_kind = 2;
        }
        MetadataMutationForTest::FeaturesNone => {
            metadata.features = 0;
        }
        MetadataMutationForTest::LiteralTooWide => {
            metadata.literal_bytes = 33;
        }
        MetadataMutationForTest::BackendSearchV8 => {
            metadata.backend_version = BackendVersion::SEARCH_V8.0;
        }
        MetadataMutationForTest::BackendAggregateCurrent => {
            metadata.backend_version = BackendVersion::AGGREGATE_CURRENT.0;
        }
        MetadataMutationForTest::BackendCountV2 => {
            metadata.backend_version = AOT_COUNT_BACKEND_VERSION_V2.0;
        }
        MetadataMutationForTest::UnknownBackend => {
            metadata.backend_version = 0xa003;
        }
        MetadataMutationForTest::RodataPresent => {
            metadata.rodata_bytes = 1;
        }
    }
    metadata.compile_identity = compute_compile_identity(metadata).0;
    let layout = ObjectLayout::new(
        usize::try_from(metadata.payload_bytes).expect("test metadata payload fits usize"),
        original_abi,
    )
    .expect("canonical test object layout");
    let encoded = metadata.encode().expect("encode hostile test metadata");
    let mut bytes = built.as_bytes().to_vec();
    let metadata_end = layout
        .metadata_file_offset
        .checked_add(METADATA_BYTES_V1)
        .expect("test metadata end");
    bytes[layout.metadata_file_offset..metadata_end].copy_from_slice(&encoded);
    let compile_identity_start = layout
        .metadata_file_offset
        .checked_add(184)
        .expect("test compile identity start");
    let compile_identity_end = layout
        .metadata_file_offset
        .checked_add(216)
        .expect("test compile identity end");
    assert_eq!(
        &bytes[compile_identity_start..compile_identity_end],
        metadata.compile_identity.as_slice()
    );
    bytes
}

fn digest_array(bytes: &[u8]) -> Result<[u8; 32], ObjectError> {
    bytes
        .try_into()
        .map_err(|_| ObjectError::InternalInvariant {
            at: "SHA-256 output length",
        })
}

#[derive(Clone, Copy)]
pub(crate) struct ObjectLayout {
    payload_bytes: usize,
    metadata_address: usize,
    pub(crate) metadata_file_offset: usize,
    segment_bytes: usize,
    pub(crate) symbol_file_offset: usize,
    string_file_offset: usize,
    string_bytes: usize,
    object_bytes: usize,
    inspect_work: u64,
    total_work: u64,
}

impl ObjectLayout {
    pub(crate) fn new(payload_bytes: usize, abi_kind: AbiKind) -> Result<Self, ObjectError> {
        Self::new_custom(
            payload_bytes,
            METADATA_BYTES_V1,
            symbol_string_bytes(abi_kind)?,
        )
    }

    fn new_custom(
        payload_bytes: usize,
        metadata_bytes: usize,
        raw_string_bytes: usize,
    ) -> Result<Self, ObjectError> {
        let metadata_address = align_up(payload_bytes, 8, ArithmeticSite::ObjectLayout)?;
        let segment_bytes = metadata_address.checked_add(metadata_bytes).ok_or(
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::ObjectLayout,
            },
        )?;
        let metadata_file_offset = CONTENT_OFFSET.checked_add(metadata_address).ok_or(
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::FileOffset,
            },
        )?;
        let symbol_file_offset =
            CONTENT_OFFSET
                .checked_add(segment_bytes)
                .ok_or(ObjectError::ArithmeticOverflow {
                    site: ArithmeticSite::FileOffset,
                })?;
        let symbol_table_bytes = NLIST_64_BYTES
            .checked_mul(usize::try_from(HARD_MAX_SYMBOLS).map_err(|_| {
                ObjectError::ArithmeticOverflow {
                    site: ArithmeticSite::Conversion,
                }
            })?)
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::ObjectLayout,
            })?;
        let string_file_offset = symbol_file_offset.checked_add(symbol_table_bytes).ok_or(
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::FileOffset,
            },
        )?;
        let string_bytes = align_up(raw_string_bytes, 4, ArithmeticSite::StringTable)?;
        let object_bytes = string_file_offset.checked_add(string_bytes).ok_or(
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::ObjectLayout,
            },
        )?;
        let object_work = usize_u64(object_bytes)?;
        let payload_work = usize_u64(payload_bytes)?;
        let inspect_work = inspection_work_upper_bound(object_bytes)?;
        let total_work = inspect_work
            .checked_add(object_work)
            .and_then(|work| work.checked_add(payload_work))
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Work,
            })?;
        Ok(Self {
            payload_bytes,
            metadata_address,
            metadata_file_offset,
            segment_bytes,
            symbol_file_offset,
            string_file_offset,
            string_bytes,
            object_bytes,
            inspect_work,
            total_work,
        })
    }
}

fn inspection_work_upper_bound(object_bytes: usize) -> Result<u64, ObjectError> {
    // Before parsing, payload size is untrusted. Three full object-byte passes
    // conservatively cover canonical prefix/section/symbol validation, payload
    // hashing, and the complete-object identity hash. This bound is enforceable
    // from the caller slice length before any content-dependent scan or hash.
    usize_u64(object_bytes)?
        .checked_mul(3)
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        })
}

#[derive(Clone, Copy)]
enum SymbolLocation {
    Entry,
    Payload,
    Metadata,
}

#[derive(Clone, Copy)]
struct SymbolSpec<'a> {
    name: &'a ExportedSymbolNameV1,
    section: u8,
    location: SymbolLocation,
}

fn symbol_specs(symbols: &ExportedSymbolsV1) -> [SymbolSpec<'_>; 3] {
    let entry = SymbolSpec {
        name: symbols.entry(),
        section: 1,
        location: SymbolLocation::Entry,
    };
    let payload = SymbolSpec {
        name: symbols.payload(),
        section: 1,
        location: SymbolLocation::Payload,
    };
    let metadata = SymbolSpec {
        name: symbols.metadata(),
        section: 2,
        location: SymbolLocation::Metadata,
    };
    // LC_DYSYMTAB requires external definitions to be sorted by name. Sort the
    // actual canonical bytes so a future prefix change cannot invalidate the
    // table while leaving a stale ABI-specific ordering branch behind.
    let mut specs = [entry, payload, metadata];
    specs.sort_unstable_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    specs
}

fn symbol_string_bytes(abi_kind: AbiKind) -> Result<usize, ObjectError> {
    [
        abi_kind.entry_symbol_prefix(),
        PAYLOAD_SYMBOL_PREFIX_V1,
        METADATA_SYMBOL_PREFIX_V1,
    ]
    .into_iter()
    .try_fold(4_usize, |total, prefix| {
        total
            .checked_add(MACH_EXTERNAL_PREFIX_BYTES)
            .and_then(|bytes| bytes.checked_add(prefix.len()))
            .and_then(|bytes| bytes.checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1))
            .and_then(|bytes| bytes.checked_add(SYMBOL_TERMINATOR_BYTES))
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::StringTable,
            })
    })
}

fn symbol_value(symbol: SymbolSpec<'_>, layout: ObjectLayout) -> Result<u64, ObjectError> {
    match symbol.location {
        SymbolLocation::Entry | SymbolLocation::Payload => Ok(u64::from(ENTRY_OFFSET_V1)),
        SymbolLocation::Metadata => {
            u64::try_from(layout.metadata_address).map_err(|_| ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            })
        }
    }
}

fn write_object_prefix(bytes: &mut Vec<u8>, layout: ObjectLayout) -> Result<(), ObjectError> {
    write_object_prefix_with_metadata(bytes, layout, METADATA_BYTES_V1)
}

fn write_object_prefix_with_metadata(
    bytes: &mut Vec<u8>,
    layout: ObjectLayout,
    metadata_bytes: usize,
) -> Result<(), ObjectError> {
    put_u32(bytes, MH_MAGIC_64);
    put_u32(bytes, CPU_TYPE_ARM64);
    put_u32(bytes, CPU_SUBTYPE_ARM64_ALL);
    put_u32(bytes, MH_OBJECT);
    put_u32(bytes, LOAD_COMMAND_COUNT);
    put_u32(bytes, to_u32(LOAD_COMMAND_BYTES)?);
    put_u32(bytes, 0);
    put_u32(bytes, 0);

    put_u32(bytes, LC_SEGMENT_64);
    put_u32(bytes, to_u32(SEGMENT_WITH_SECTIONS_BYTES)?);
    put_fixed_name(bytes, "");
    put_u64(bytes, 0);
    put_u64(bytes, usize_u64(layout.segment_bytes)?);
    put_u64(bytes, usize_u64(CONTENT_OFFSET)?);
    put_u64(bytes, usize_u64(layout.segment_bytes)?);
    put_u32(bytes, VM_PROT_RWX);
    put_u32(bytes, VM_PROT_RWX);
    put_u32(
        bytes,
        to_u32(usize::try_from(HARD_MAX_SECTIONS).map_err(|_| {
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            }
        })?)?,
    );
    put_u32(bytes, 0);

    write_section(
        bytes,
        "__fre_image",
        "__TEXT",
        0,
        usize_u64(layout.payload_bytes)?,
        to_u32(CONTENT_OFFSET)?,
        4,
        PAYLOAD_SECTION_FLAGS,
    );
    write_section(
        bytes,
        "__fre_meta",
        "__FRE_CONST",
        usize_u64(layout.metadata_address)?,
        usize_u64(metadata_bytes)?,
        to_u32(layout.metadata_file_offset)?,
        3,
        METADATA_SECTION_FLAGS,
    );

    put_u32(bytes, LC_BUILD_VERSION);
    put_u32(bytes, to_u32(BUILD_VERSION_COMMAND_BYTES)?);
    put_u32(bytes, PLATFORM_MACOS_LOAD_COMMAND);
    put_u32(bytes, MIN_MACOS_VERSION_V1);
    put_u32(bytes, 0);
    put_u32(bytes, 0);

    put_u32(bytes, LC_SYMTAB);
    put_u32(bytes, to_u32(SYMTAB_COMMAND_BYTES)?);
    put_u32(bytes, to_u32(layout.symbol_file_offset)?);
    put_u32(
        bytes,
        to_u32(usize::try_from(HARD_MAX_SYMBOLS).map_err(|_| {
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            }
        })?)?,
    );
    put_u32(bytes, to_u32(layout.string_file_offset)?);
    put_u32(bytes, to_u32(layout.string_bytes)?);

    put_u32(bytes, LC_DYSYMTAB);
    put_u32(bytes, to_u32(DYSYMTAB_COMMAND_BYTES)?);
    for value in [0, 0, 0, 3, 3, 0] {
        put_u32(bytes, value);
    }
    for _ in 0..12 {
        put_u32(bytes, 0);
    }
    expect_length(
        bytes,
        MACH_HEADER_BYTES + LOAD_COMMAND_BYTES,
        "load commands",
    )?;
    resize_zero(bytes, CONTENT_OFFSET)
}

#[allow(
    clippy::too_many_arguments,
    reason = "fields mirror the fixed Mach-O section_64 wire record"
)]
fn write_section(
    bytes: &mut Vec<u8>,
    section_name: &str,
    segment_name: &str,
    address: u64,
    size: u64,
    offset: u32,
    alignment_power: u32,
    flags: u32,
) {
    put_fixed_name(bytes, section_name);
    put_fixed_name(bytes, segment_name);
    put_u64(bytes, address);
    put_u64(bytes, size);
    put_u32(bytes, offset);
    put_u32(bytes, alignment_power);
    put_u32(bytes, 0);
    put_u32(bytes, 0);
    put_u32(bytes, flags);
    put_u32(bytes, 0);
    put_u32(bytes, 0);
    put_u32(bytes, 0);
}

fn write_symbol_and_string_tables(
    bytes: &mut Vec<u8>,
    layout: ObjectLayout,
    exported_symbols: &ExportedSymbolsV1,
) -> Result<(), ObjectError> {
    expect_length(bytes, layout.symbol_file_offset, "symbol table offset")?;
    let symbols = symbol_specs(exported_symbols);
    let mut string_index = 4_usize;
    for symbol in symbols {
        put_u32(bytes, to_u32(string_index)?);
        put_u8(bytes, N_SECT_EXT);
        put_u8(bytes, symbol.section);
        put_u16(bytes, 0);
        put_u64(bytes, symbol_value(symbol, layout)?);
        string_index = string_index
            .checked_add(MACH_EXTERNAL_PREFIX_BYTES)
            .and_then(|value| value.checked_add(symbol.name.as_bytes().len()))
            .and_then(|value| value.checked_add(SYMBOL_TERMINATOR_BYTES))
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::StringTable,
            })?;
    }
    expect_length(bytes, layout.string_file_offset, "string table offset")?;
    bytes.extend_from_slice(&[0; 4]);
    for symbol in symbols {
        bytes.push(b'_');
        bytes.extend_from_slice(symbol.name.as_bytes());
        put_u8(bytes, 0);
    }
    resize_zero(bytes, layout.object_bytes)
}

fn put_fixed_name(bytes: &mut Vec<u8>, name: &str) {
    debug_assert!(name.len() <= 16);
    bytes.extend_from_slice(name.as_bytes());
    let padding = 16_usize.saturating_sub(name.len());
    bytes.extend(core::iter::repeat_n(0, padding));
}

fn put_u8(bytes: &mut Vec<u8>, value: u8) {
    bytes.push(value);
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn resize_zero(bytes: &mut Vec<u8>, length: usize) -> Result<(), ObjectError> {
    if bytes.len() > length {
        return Err(ObjectError::InternalInvariant {
            at: "zero padding overlap",
        });
    }
    bytes.resize(length, 0);
    Ok(())
}

fn expect_length(bytes: &[u8], expected: usize, at: &'static str) -> Result<(), ObjectError> {
    if bytes.len() != expected {
        return Err(ObjectError::InternalInvariant { at });
    }
    Ok(())
}

fn align_up(value: usize, alignment: usize, site: ArithmeticSite) -> Result<usize, ObjectError> {
    if !alignment.is_power_of_two() {
        return Err(ObjectError::InternalInvariant {
            at: "non-power-of-two alignment",
        });
    }
    let mask = alignment
        .checked_sub(1)
        .ok_or(ObjectError::ArithmeticOverflow { site })?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(ObjectError::ArithmeticOverflow { site })
}

fn to_u32(value: usize) -> Result<u32, ObjectError> {
    u32::try_from(value).map_err(|_| ObjectError::ArithmeticOverflow {
        site: ArithmeticSite::Conversion,
    })
}

fn usize_u64(value: usize) -> Result<u64, ObjectError> {
    u64::try_from(value).map_err(|_| ObjectError::ArithmeticOverflow {
        site: ArithmeticSite::Conversion,
    })
}

fn object_scratch_bytes() -> Result<u64, ObjectError> {
    // Deliberately overcount every fixed state that can be live anywhere in
    // emission, inspection, or expected-image validation. This includes
    // borrowed views and result envelopes, not just dynamic audit storage.
    // Some components are mutually exclusive; summing them makes the bound
    // stable across compiler stack-slot reuse and future inlining decisions.
    let components = [
        METADATA_BYTES_V1,
        size_of::<MetadataV1>(),
        size_of::<Sha256>(),
        size_of::<[u8; 32]>(),
        size_of::<ExportedSymbolsV1>(),
        size_of::<[SymbolSpec<'static>; 3]>(),
        size_of::<ImageView<'static>>(),
        size_of::<BuildPreflight>(),
        size_of::<ObjectLayout>(),
        size_of::<ParsedSection>(),
        size_of::<ParsedPrefix>(),
        size_of::<FixedWriter<'static>>(),
        size_of::<Reader<'static>>(),
        size_of::<ObjectInspection<'static>>(),
        size_of::<ObjectValidation<'static>>(),
        size_of::<ObjectBuildReport>(),
        size_of::<BuiltObject>(),
        size_of::<AuditReport>(),
        size_of::<ObjectLimits>(),
        size_of::<BindingIdentity>(),
    ];
    let bytes = components
        .into_iter()
        .try_fold(0_usize, |total, component| {
            total
                .checked_add(component)
                .ok_or(ObjectError::ArithmeticOverflow {
                    site: ArithmeticSite::ObjectLayout,
                })
        })?;
    usize_u64(bytes)
}

fn enforce_all(
    resource: ObjectResource,
    required: u64,
    caller_limit: u64,
    hard_limit: u64,
) -> Result<(), ObjectError> {
    let effective = caller_limit.min(hard_limit);
    if required > effective {
        return Err(ObjectError::ResourceLimit {
            resource,
            limit: effective,
            required,
        });
    }
    Ok(())
}

fn preflight_inspection_resources(
    byte_len: usize,
    limits: ObjectLimits,
) -> Result<u64, ObjectError> {
    let object_bytes = usize_u64(byte_len)?;
    enforce_all(
        ObjectResource::ObjectBytes,
        object_bytes,
        limits.max_object_bytes,
        HARD_MAX_OBJECT_BYTES,
    )?;
    let work = inspection_work_upper_bound(byte_len)?;
    enforce_all(ObjectResource::Work, work, limits.max_work, HARD_MAX_WORK)?;
    enforce_all(
        ObjectResource::ScratchBytes,
        object_scratch_bytes()?,
        limits.max_scratch_bytes,
        HARD_MAX_SCRATCH_BYTES,
    )?;
    enforce_all(
        ObjectResource::Sections,
        HARD_MAX_SECTIONS,
        limits.max_sections,
        HARD_MAX_SECTIONS,
    )?;
    enforce_all(
        ObjectResource::Symbols,
        HARD_MAX_SYMBOLS,
        limits.max_symbols,
        HARD_MAX_SYMBOLS,
    )?;
    Ok(work)
}

/// Strictly parse the one canonical object shape and verify self-consistency.
///
/// This rejects every load command, section, symbol, relocation, import, byte
/// of padding, or trailing byte not emitted by this crate. Returned identities
/// are untrusted claims until compared with an external receipt.
pub fn inspect_object(
    bytes: &[u8],
    limits: ObjectLimits,
) -> Result<ObjectInspection<'_>, ObjectError> {
    let preparse_work = preflight_inspection_resources(bytes.len(), limits)?;

    let parsed = parse_prefix(bytes)?;
    let metadata_bytes = checked_region(
        bytes,
        parsed.metadata.offset,
        parsed.metadata.size,
        "metadata section",
    )?;
    let metadata = MetadataV1::decode(metadata_bytes)?;
    let layout = ObjectLayout::new(parsed.payload.size, metadata.abi_kind)?;
    validate_parsed_layout(bytes, parsed, layout)?;
    enforce_all(
        ObjectResource::PayloadBytes,
        usize_u64(layout.payload_bytes)?,
        limits.max_payload_bytes,
        HARD_MAX_PAYLOAD_BYTES,
    )?;
    if layout.inspect_work != preparse_work {
        return Err(ObjectError::InvalidObject {
            at: "preparse work envelope",
        });
    }
    if compute_compile_identity(metadata).as_bytes() != &metadata.compile_identity {
        return Err(ObjectError::CompileIdentityMismatch);
    }
    let claimed_symbols = ExportedSymbolsV1::for_compile_identity(
        metadata.abi_kind,
        CompileIdentity(metadata.compile_identity),
    );
    validate_symbols_and_strings(bytes, &claimed_symbols, layout)?;

    let payload = checked_region(
        bytes,
        parsed.payload.offset,
        parsed.payload.size,
        "payload section",
    )?;
    validate_payload_shape(payload, metadata)?;
    let actual_digest = digest_array(&Sha256::digest(payload))?;
    if actual_digest != metadata.payload_sha256 {
        return Err(ObjectError::PayloadDigestMismatch);
    }
    let claimed_object_identity = ClaimedObjectIdentity(digest_array(&Sha256::digest(bytes))?);
    Ok(ObjectInspection {
        metadata,
        metadata_bytes,
        payload,
        object_bytes: bytes.len(),
        work: layout.inspect_work,
        scratch_bytes: object_scratch_bytes()?,
        claimed_object_identity,
    })
}

#[derive(Clone, Copy)]
struct ParsedSection {
    address: u64,
    size: usize,
    offset: usize,
}

#[derive(Clone, Copy)]
struct ParsedPrefix {
    segment_vm_bytes: usize,
    segment_file_offset: usize,
    segment_file_bytes: usize,
    payload: ParsedSection,
    metadata: ParsedSection,
    symbol_file_offset: usize,
    symbol_count: u32,
    string_file_offset: usize,
    string_bytes: usize,
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear parser keeps the fixed Mach-O prefix order explicit"
)]
fn parse_prefix(bytes: &[u8]) -> Result<ParsedPrefix, ObjectError> {
    let mut reader = Reader::new(bytes);
    reader.expect_u32(MH_MAGIC_64, "Mach-O magic")?;
    reader.expect_u32(CPU_TYPE_ARM64, "Mach-O CPU type")?;
    reader.expect_u32(CPU_SUBTYPE_ARM64_ALL, "Mach-O CPU subtype")?;
    reader.expect_u32(MH_OBJECT, "Mach-O file type")?;
    reader.expect_u32(LOAD_COMMAND_COUNT, "Mach-O load command count")?;
    reader.expect_u32(to_u32(LOAD_COMMAND_BYTES)?, "Mach-O load command bytes")?;
    reader.expect_u32(0, "Mach-O flags")?;
    reader.expect_u32(0, "Mach-O reserved header")?;

    reader.expect_u32(LC_SEGMENT_64, "segment command kind")?;
    reader.expect_u32(to_u32(SEGMENT_WITH_SECTIONS_BYTES)?, "segment command size")?;
    reader.expect_fixed_name("", "object segment name")?;
    reader.expect_u64(0, "object segment VM address")?;
    let segment_vm_bytes = reader.usize_u64("object segment VM size")?;
    let segment_file_offset = reader.usize_u64("object segment file offset")?;
    let segment_file_bytes = reader.usize_u64("object segment file size")?;
    reader.expect_u32(VM_PROT_RWX, "object segment maximum protection")?;
    reader.expect_u32(VM_PROT_RWX, "object segment initial protection")?;
    reader.expect_u32(
        u32::try_from(HARD_MAX_SECTIONS).expect("small constant"),
        "object section count",
    )?;
    reader.expect_u32(0, "object segment flags")?;

    let payload = reader.section("__fre_image", "__TEXT", 4, PAYLOAD_SECTION_FLAGS, "payload")?;
    let metadata = reader.section(
        "__fre_meta",
        "__FRE_CONST",
        3,
        METADATA_SECTION_FLAGS,
        "metadata",
    )?;

    reader.expect_u32(LC_BUILD_VERSION, "build-version command kind")?;
    reader.expect_u32(
        to_u32(BUILD_VERSION_COMMAND_BYTES)?,
        "build-version command size",
    )?;
    reader.expect_u32(PLATFORM_MACOS_LOAD_COMMAND, "build-version platform")?;
    reader.expect_u32(MIN_MACOS_VERSION_V1, "build-version minimum OS")?;
    reader.expect_u32(0, "build-version SDK")?;
    reader.expect_u32(0, "build-version tool count")?;

    reader.expect_u32(LC_SYMTAB, "symbol-table command kind")?;
    reader.expect_u32(to_u32(SYMTAB_COMMAND_BYTES)?, "symbol-table command size")?;
    let symbol_file_offset = reader.usize_u32("symbol-table file offset")?;
    let symbol_count = reader.u32("symbol count")?;
    let string_file_offset = reader.usize_u32("string-table file offset")?;
    let string_bytes = reader.usize_u32("string-table bytes")?;

    reader.expect_u32(LC_DYSYMTAB, "dynamic-symbol command kind")?;
    reader.expect_u32(
        to_u32(DYSYMTAB_COMMAND_BYTES)?,
        "dynamic-symbol command size",
    )?;
    for (expected, at) in [
        (0, "local symbol index"),
        (0, "local symbol count"),
        (0, "external definition index"),
        (3, "external definition count"),
        (3, "undefined symbol index"),
        (0, "undefined symbol count"),
    ] {
        reader.expect_u32(expected, at)?;
    }
    for at in [
        "table-of-contents offset",
        "table-of-contents count",
        "module-table offset",
        "module-table count",
        "external-reference offset",
        "external-reference count",
        "indirect-symbol offset",
        "indirect-symbol count",
        "external-relocation offset",
        "external-relocation count",
        "local-relocation offset",
        "local-relocation count",
    ] {
        reader.expect_u32(0, at)?;
    }
    if reader.position() != MACH_HEADER_BYTES + LOAD_COMMAND_BYTES {
        return Err(ObjectError::InvalidObject {
            at: "load-command boundary",
        });
    }
    reader.expect_zeroes(
        CONTENT_OFFSET
            .checked_sub(reader.position())
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::ObjectLayout,
            })?,
        "header-to-payload padding",
    )?;
    Ok(ParsedPrefix {
        segment_vm_bytes,
        segment_file_offset,
        segment_file_bytes,
        payload,
        metadata,
        symbol_file_offset,
        symbol_count,
        string_file_offset,
        string_bytes,
    })
}

fn validate_parsed_layout(
    bytes: &[u8],
    parsed: ParsedPrefix,
    layout: ObjectLayout,
) -> Result<(), ObjectError> {
    validate_parsed_layout_with_metadata(bytes, parsed, layout, METADATA_BYTES_V1)
}

fn validate_parsed_layout_with_metadata(
    bytes: &[u8],
    parsed: ParsedPrefix,
    layout: ObjectLayout,
    metadata_bytes: usize,
) -> Result<(), ObjectError> {
    let metadata_address =
        u64::try_from(layout.metadata_address).map_err(|_| ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        })?;
    if bytes.len() != layout.object_bytes
        || parsed.segment_vm_bytes != layout.segment_bytes
        || parsed.segment_file_offset != CONTENT_OFFSET
        || parsed.segment_file_bytes != layout.segment_bytes
        || parsed.payload.address != 0
        || parsed.payload.size != layout.payload_bytes
        || parsed.payload.offset != CONTENT_OFFSET
        || parsed.metadata.address != metadata_address
        || parsed.metadata.size != metadata_bytes
        || parsed.metadata.offset != layout.metadata_file_offset
        || parsed.symbol_file_offset != layout.symbol_file_offset
        || parsed.symbol_count != u32::try_from(HARD_MAX_SYMBOLS).expect("small constant")
        || parsed.string_file_offset != layout.string_file_offset
        || parsed.string_bytes != layout.string_bytes
    {
        return Err(ObjectError::InvalidObject {
            at: "canonical object layout",
        });
    }
    let payload_end = parsed
        .payload
        .offset
        .checked_add(parsed.payload.size)
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::FileOffset,
        })?;
    let section_padding = checked_region(
        bytes,
        payload_end,
        parsed
            .metadata
            .offset
            .checked_sub(payload_end)
            .ok_or(ObjectError::InvalidObject {
                at: "overlapping sections",
            })?,
        "section padding",
    )?;
    if section_padding.iter().any(|&byte| byte != 0) {
        return Err(ObjectError::InvalidObject {
            at: "nonzero section padding",
        });
    }
    Ok(())
}

fn validate_symbols_and_strings(
    bytes: &[u8],
    exported_symbols: &ExportedSymbolsV1,
    layout: ObjectLayout,
) -> Result<(), ObjectError> {
    let symbol_table_bytes = NLIST_64_BYTES
        .checked_mul(symbol_specs(exported_symbols).len())
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::ObjectLayout,
        })?;
    let symbol_bytes = checked_region(
        bytes,
        layout.symbol_file_offset,
        symbol_table_bytes,
        "symbol table",
    )?;
    let string_bytes = checked_region(
        bytes,
        layout.string_file_offset,
        layout.string_bytes,
        "string table",
    )?;
    let mut symbol_reader = Reader::new(symbol_bytes);
    let mut string_index = 4_usize;
    for symbol in symbol_specs(exported_symbols) {
        symbol_reader.expect_u32(to_u32(string_index)?, "symbol string index")?;
        symbol_reader.expect_u8(N_SECT_EXT, "symbol type")?;
        symbol_reader.expect_u8(symbol.section, "symbol section")?;
        symbol_reader.expect_u16(0, "symbol descriptor")?;
        symbol_reader.expect_u64(symbol_value(symbol, layout)?, "symbol value")?;
        string_index = string_index
            .checked_add(MACH_EXTERNAL_PREFIX_BYTES)
            .and_then(|value| value.checked_add(symbol.name.as_bytes().len()))
            .and_then(|value| value.checked_add(SYMBOL_TERMINATOR_BYTES))
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::StringTable,
            })?;
    }
    if symbol_reader.position() != symbol_bytes.len() {
        return Err(ObjectError::InvalidObject {
            at: "symbol table length",
        });
    }
    let mut string_reader = Reader::new(string_bytes);
    string_reader.expect_zeroes(4, "string-table prefix")?;
    for symbol in symbol_specs(exported_symbols) {
        string_reader.expect_u8(b'_', "Mach external-name prefix")?;
        string_reader.expect_bytes(symbol.name.as_bytes(), "symbol name")?;
        string_reader.expect_u8(0, "symbol-name terminator")?;
    }
    string_reader.expect_zeroes(
        string_bytes
            .len()
            .checked_sub(string_reader.position())
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::StringTable,
            })?,
        "string-table padding",
    )?;
    Ok(())
}

fn validate_payload_shape(payload: &[u8], metadata: MetadataV1) -> Result<(), ObjectError> {
    if payload.len()
        != usize::try_from(metadata.payload_bytes).map_err(|_| ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        })?
    {
        return Err(ObjectError::InvalidObject {
            at: "payload size metadata",
        });
    }
    let code_end =
        usize::try_from(metadata.code_bytes).map_err(|_| ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        })?;
    let rodata_start =
        usize::try_from(metadata.rodata_offset).map_err(|_| ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        })?;
    let gap = checked_region(
        payload,
        code_end,
        rodata_start
            .checked_sub(code_end)
            .ok_or(ObjectError::InvalidObject {
                at: "payload code/rodata overlap",
            })?,
        "payload alignment gap",
    )?;
    if gap.len() >= 16 || gap.iter().any(|&byte| byte != 0) {
        return Err(ObjectError::InvalidObject {
            at: "payload alignment gap",
        });
    }
    checked_region(
        payload,
        rodata_start,
        usize::try_from(metadata.rodata_bytes).map_err(|_| ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        })?,
        "payload rodata",
    )?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one ordered comparison keeps every authenticated image binding visible"
)]
fn validate_view(
    view: ImageView<'_>,
    binding: BindingIdentity,
    inspection: &ObjectInspection<'_>,
) -> Result<(), ObjectError> {
    let metadata = inspection.metadata;
    let expected_scalars = [
        (
            u64::from(metadata.backend_version),
            u64::from(view.backend_version),
            "backend version",
        ),
        (
            u64::from(metadata.abi_kind.as_byte()),
            u64::from(view.abi_kind.as_byte()),
            "ABI kind",
        ),
        (
            u64::from(metadata.output_kind),
            u64::from(view.output_kind),
            "output kind",
        ),
        (
            u64::from(metadata.architecture),
            u64::from(view.target.architecture),
            "target architecture",
        ),
        (
            u64::from(metadata.little_endian),
            u64::from(u8::from(view.target.little_endian)),
            "target byte order",
        ),
        (
            u64::from(metadata.pointer_width),
            u64::from(view.target.pointer_width),
            "target pointer width",
        ),
        (
            u64::from(metadata.target_abi),
            u64::from(view.target.abi),
            "target ABI",
        ),
        (
            metadata.features,
            view.target.features.bits(),
            "target features",
        ),
        (
            u64::from(metadata.payload_bytes),
            u64::from(view.layout.total_mapped_bytes),
            "payload bytes",
        ),
        (
            u64::from(metadata.code_bytes),
            usize_u64(view.code.len())?,
            "code bytes",
        ),
        (
            u64::from(metadata.rodata_offset),
            u64::from(view.layout.rodata_from_code_start),
            "rodata offset",
        ),
        (
            u64::from(metadata.rodata_bytes),
            usize_u64(view.rodata.len())?,
            "rodata bytes",
        ),
        (
            u64::from(metadata.literal_bytes),
            u64::from(view.literal_bytes),
            "literal bytes",
        ),
    ];
    for (actual, expected, field) in expected_scalars {
        if actual != expected {
            return Err(ObjectError::ImageBindingMismatch { field });
        }
    }
    for (actual, expected, field) in [
        (
            metadata.source_identity,
            view.source_identity,
            "source identity",
        ),
        (
            metadata.artifact_identity,
            view.artifact_identity,
            "native artifact identity",
        ),
        (
            metadata.binding_identity,
            *binding.as_bytes(),
            "planner binding identity",
        ),
    ] {
        if actual != expected {
            return Err(ObjectError::ImageBindingMismatch { field });
        }
    }
    let code_end = view.code.len();
    let rodata_start = usize::try_from(view.layout.rodata_from_code_start).map_err(|_| {
        ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        }
    })?;
    if checked_region(inspection.payload, 0, code_end, "bound code")? != view.code {
        return Err(ObjectError::ImageBindingMismatch {
            field: "code payload",
        });
    }
    if checked_region(
        inspection.payload,
        code_end,
        rodata_start
            .checked_sub(code_end)
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::ImageLayout,
            })?,
        "bound alignment gap",
    )?
    .iter()
    .any(|&byte| byte != 0)
    {
        return Err(ObjectError::ImageBindingMismatch {
            field: "alignment gap",
        });
    }
    if checked_region(
        inspection.payload,
        rodata_start,
        view.rodata.len(),
        "bound rodata",
    )? != view.rodata
    {
        return Err(ObjectError::ImageBindingMismatch {
            field: "rodata payload",
        });
    }
    Ok(())
}

fn checked_region<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    at: &'static str,
) -> Result<&'a [u8], ObjectError> {
    let end = offset
        .checked_add(length)
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::FileOffset,
        })?;
    bytes.get(offset..end).ok_or(ObjectError::Truncated { at })
}

struct FixedWriter<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> FixedWriter<'a> {
    const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), ObjectError> {
        let end =
            self.position
                .checked_add(value.len())
                .ok_or(ObjectError::ArithmeticOverflow {
                    site: ArithmeticSite::ObjectLayout,
                })?;
        let destination =
            self.bytes
                .get_mut(self.position..end)
                .ok_or(ObjectError::InternalInvariant {
                    at: "fixed metadata writer",
                })?;
        destination.copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), ObjectError> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), ObjectError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), ObjectError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), ObjectError> {
        self.bytes(&value.to_le_bytes())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn take(&mut self, length: usize, at: &'static str) -> Result<&'a [u8], ObjectError> {
        let value = checked_region(self.bytes, self.position, length, at)?;
        self.position =
            self.position
                .checked_add(length)
                .ok_or(ObjectError::ArithmeticOverflow {
                    site: ArithmeticSite::FileOffset,
                })?;
        Ok(value)
    }

    fn array<const N: usize>(&mut self, at: &'static str) -> Result<[u8; N], ObjectError> {
        self.take(N, at)?
            .try_into()
            .map_err(|_| ObjectError::InternalInvariant {
                at: "fixed array reader",
            })
    }

    fn u8(&mut self, at: &'static str) -> Result<u8, ObjectError> {
        self.take(1, at)?
            .first()
            .copied()
            .ok_or(ObjectError::Truncated { at })
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, ObjectError> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, ObjectError> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn u64(&mut self, at: &'static str) -> Result<u64, ObjectError> {
        Ok(u64::from_le_bytes(self.array(at)?))
    }

    fn usize_u32(&mut self, at: &'static str) -> Result<usize, ObjectError> {
        usize::try_from(self.u32(at)?).map_err(|_| ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        })
    }

    fn usize_u64(&mut self, at: &'static str) -> Result<usize, ObjectError> {
        usize::try_from(self.u64(at)?).map_err(|_| ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        })
    }

    fn expect_u8(&mut self, expected: u8, at: &'static str) -> Result<(), ObjectError> {
        if self.u8(at)? != expected {
            return Err(ObjectError::InvalidObject { at });
        }
        Ok(())
    }

    fn expect_u16(&mut self, expected: u16, at: &'static str) -> Result<(), ObjectError> {
        if self.u16(at)? != expected {
            return Err(ObjectError::InvalidObject { at });
        }
        Ok(())
    }

    fn expect_u32(&mut self, expected: u32, at: &'static str) -> Result<(), ObjectError> {
        if self.u32(at)? != expected {
            return Err(ObjectError::InvalidObject { at });
        }
        Ok(())
    }

    fn expect_u64(&mut self, expected: u64, at: &'static str) -> Result<(), ObjectError> {
        if self.u64(at)? != expected {
            return Err(ObjectError::InvalidObject { at });
        }
        Ok(())
    }

    fn expect_bytes(&mut self, expected: &[u8], at: &'static str) -> Result<(), ObjectError> {
        if self.take(expected.len(), at)? != expected {
            return Err(ObjectError::InvalidObject { at });
        }
        Ok(())
    }

    fn expect_zeroes(&mut self, length: usize, at: &'static str) -> Result<(), ObjectError> {
        if self.take(length, at)?.iter().any(|&byte| byte != 0) {
            return Err(ObjectError::InvalidObject { at });
        }
        Ok(())
    }

    fn expect_fixed_name(&mut self, expected: &str, at: &'static str) -> Result<(), ObjectError> {
        if expected.len() > 16 {
            return Err(ObjectError::InternalInvariant {
                at: "fixed Mach-O name length",
            });
        }
        let actual = self.take(16, at)?;
        if actual.get(..expected.len()) != Some(expected.as_bytes())
            || actual
                .get(expected.len()..)
                .is_none_or(|padding| padding.iter().any(|&byte| byte != 0))
        {
            return Err(ObjectError::InvalidObject { at });
        }
        Ok(())
    }

    fn section(
        &mut self,
        section_name: &'static str,
        segment_name: &'static str,
        alignment_power: u32,
        flags: u32,
        description: &'static str,
    ) -> Result<ParsedSection, ObjectError> {
        self.expect_fixed_name(section_name, description)?;
        self.expect_fixed_name(segment_name, description)?;
        let address = self.u64(description)?;
        let size = self.usize_u64(description)?;
        let offset = self.usize_u32(description)?;
        self.expect_u32(alignment_power, description)?;
        self.expect_u32(0, description)?;
        self.expect_u32(0, description)?;
        self.expect_u32(flags, description)?;
        self.expect_u32(0, description)?;
        self.expect_u32(0, description)?;
        self.expect_u32(0, description)?;
        Ok(ParsedSection {
            address,
            size,
            offset,
        })
    }
}
