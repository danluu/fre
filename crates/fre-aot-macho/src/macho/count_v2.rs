use core::{fmt, mem::size_of};

use fre_aot_aarch64::{
    AotCountBackendSupportV2, AotCountImageV2, AotCountTargetSpec, CountAuditReportV2,
    SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2, audit_count_image_v2,
    is_supported_aot_count_backend_tuple_v2,
};
use fre_exact_alloc::zeroed_exact;
use fre_kernel_ir::{Count, ExactAggregateProgram};
use sha2::{Digest, Sha256};

use super::{
    AbiKind, ArithmeticSite, BUILD_VERSION_COMMAND_BYTES, BindingIdentity, CONTENT_OFFSET,
    CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, ClaimedBindingIdentity, DYSYMTAB_COMMAND_BYTES,
    FixedWriter, HARD_MAX_OBJECT_BYTES, HARD_MAX_PAYLOAD_BYTES, HARD_MAX_PERSISTENT_BYTES,
    HARD_MAX_SCRATCH_BYTES, HARD_MAX_SECTIONS, HARD_MAX_SYMBOLS, HARD_MAX_WORK, LC_BUILD_VERSION,
    LC_DYSYMTAB, LC_SEGMENT_64, LC_SYMTAB, LOAD_COMMAND_BYTES, LOAD_COMMAND_COUNT,
    MACH_EXTERNAL_PREFIX_BYTES, MACH_HEADER_BYTES, METADATA_SECTION_FLAGS, MH_MAGIC_64, MH_OBJECT,
    MIN_MACOS_VERSION_V1, N_SECT_EXT, NLIST_64_BYTES, ObjectError, ObjectLayout, ObjectLimits,
    ObjectResource, PAYLOAD_SECTION_FLAGS, PLATFORM_MACOS, PLATFORM_MACOS_LOAD_COMMAND,
    ParsedPrefix, ParsedSection, Reader, SEGMENT_WITH_SECTIONS_BYTES, SYMBOL_TERMINATOR_BYTES,
    SYMTAB_COMMAND_BYTES, SymbolLocation, VM_PROT_RWX, checked_region, digest_array, enforce_all,
    inspection_work_upper_bound, parse_prefix, to_u32, usize_u64,
    validate_parsed_layout_with_metadata, write_digest,
};

/// Aggregate-only metadata wire version. V1 remains the search/JIT object API.
pub const METADATA_VERSION_V2: u16 = 2;
pub const METADATA_BYTES_V2: usize = 232;
/// Exact inline state used by [`MetadataV2::write_canonical_into`], excluding
/// the caller-owned 232-byte destination.
pub const METADATA_V2_WRITER_SCRATCH_BYTES: usize = size_of::<FixedWriter<'static>>();
pub const ENTRY_OFFSET_V2: u32 = 0;
pub const CALL_ABI_SCHEMA_V2: u16 = 2;
pub const STATUS_BITS_V2: u8 = 64;
pub const EXPORTED_SYMBOL_SCHEMA_VERSION_V2: u16 = 3;
pub const EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2: usize = 64;
/// Mach-O `n_type` for every identity-scoped Count implementation symbol.
///
/// `N_SECT | N_EXT | N_PEXT` permits cross-object static resolution while
/// requiring the final linker to keep the definition private-external.
pub const COUNT_EXPORTED_SYMBOL_N_TYPE_V2: u8 = 0x1f;

pub const COUNT_ENTRY_SYMBOL_PREFIX_V2: &str = "fre_aot_count_entry_v2_";
pub const COUNT_PAYLOAD_SYMBOL_PREFIX_V2: &str = "fre_aot_count_payload_v2_";
pub const COUNT_METADATA_SYMBOL_PREFIX_V2: &str = "fre_aot_count_metadata_v2_";

const METADATA_MAGIC_V2: [u8; 8] = *b"FREOM64\x02";
const COUNT_COMPILE_IDENTITY_DOMAIN_V2: &[u8] = b"FRE-AOT-MACHO-COUNT-COMPILE\0\x02";
const EXPORTED_SYMBOL_STORAGE_BYTES_V2: usize = 112;
const COUNT_FIXED_IDENTITY_WORK_V2: u64 = 2 << 10;
const COUNT_FIXED_BINDING_WORK_V2: u64 = 512;
const N_PEXT_V2: u8 = 0x10;
const N_SECT_PRIVATE_EXT_V2: u8 = N_SECT_EXT | N_PEXT_V2;
const LOWER_HEX_V2: &[u8; 16] = b"0123456789abcdef";

const _: () = assert!(METADATA_BYTES_V2 == 232);
const _: () = assert!(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2 == 64);
const _: () = assert!(N_SECT_PRIVATE_EXT_V2 == COUNT_EXPORTED_SYMBOL_N_TYPE_V2);

/// Trusted identity of one aggregate-only V2 object contract.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CountCompileIdentityV2([u8; 32]);

impl CountCompileIdentityV2 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn matches_claim(self, claim: ClaimedCountCompileIdentityV2) -> bool {
        self.0 == claim.0
    }
}

impl fmt::Debug for CountCompileIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CountCompileIdentityV2({self})")
    }
}

impl fmt::Display for CountCompileIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_digest(formatter, &self.0)
    }
}

/// Untrusted compile-identity claim recovered from V2 metadata.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ClaimedCountCompileIdentityV2([u8; 32]);

impl ClaimedCountCompileIdentityV2 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ClaimedCountCompileIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ClaimedCountCompileIdentityV2({self})")
    }
}

impl fmt::Display for ClaimedCountCompileIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_digest(formatter, &self.0)
    }
}

/// Trusted SHA-256 identity over the complete aggregate-only V2 `MH_OBJECT`.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CountObjectIdentityV2([u8; 32]);

impl CountObjectIdentityV2 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn matches_claim(self, claim: ClaimedCountObjectIdentityV2) -> bool {
        self.0 == claim.0
    }
}

impl fmt::Debug for CountObjectIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CountObjectIdentityV2({self})")
    }
}

impl fmt::Display for CountObjectIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_digest(formatter, &self.0)
    }
}

/// Untrusted complete-file digest computed during strict V2 inspection.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ClaimedCountObjectIdentityV2([u8; 32]);

impl ClaimedCountObjectIdentityV2 {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ClaimedCountObjectIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ClaimedCountObjectIdentityV2({self})")
    }
}

impl fmt::Display for ClaimedCountObjectIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_digest(formatter, &self.0)
    }
}

/// One allocation-free identity-suffixed V2 symbol name.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ExportedSymbolNameV2 {
    bytes: [u8; EXPORTED_SYMBOL_STORAGE_BYTES_V2],
    len: usize,
}

impl ExportedSymbolNameV2 {
    fn new(prefix: &str, identity: CountCompileIdentityV2) -> Self {
        let mut bytes = [0_u8; EXPORTED_SYMBOL_STORAGE_BYTES_V2];
        let prefix_bytes = prefix.as_bytes();
        let expected_len = prefix_bytes
            .len()
            .checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2)
            .expect("fixed V2 symbol-name length fits usize");
        assert!(
            expected_len <= EXPORTED_SYMBOL_STORAGE_BYTES_V2,
            "fixed V2 symbol-name storage fits every prefix"
        );
        bytes[..prefix_bytes.len()].copy_from_slice(prefix_bytes);
        let mut position = prefix_bytes.len();
        for byte in identity.0 {
            let low_position = position
                .checked_add(1)
                .expect("fixed V2 symbol position fits usize");
            bytes[position] = LOWER_HEX_V2[usize::from(byte >> 4)];
            bytes[low_position] = LOWER_HEX_V2[usize::from(byte & 0x0f)];
            position = position
                .checked_add(2)
                .expect("fixed V2 symbol position fits usize");
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
            .expect("identity-suffixed V2 symbol names are canonical ASCII")
    }
}

impl fmt::Debug for ExportedSymbolNameV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ExportedSymbolNameV2")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for ExportedSymbolNameV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Collision-resistant aggregate-only V2 private-external namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportedSymbolsV2 {
    compile_identity: CountCompileIdentityV2,
    entry: ExportedSymbolNameV2,
    payload: ExportedSymbolNameV2,
    metadata: ExportedSymbolNameV2,
}

impl ExportedSymbolsV2 {
    #[must_use]
    pub fn for_compile_identity(compile_identity: CountCompileIdentityV2) -> Self {
        Self {
            compile_identity,
            entry: ExportedSymbolNameV2::new(COUNT_ENTRY_SYMBOL_PREFIX_V2, compile_identity),
            payload: ExportedSymbolNameV2::new(COUNT_PAYLOAD_SYMBOL_PREFIX_V2, compile_identity),
            metadata: ExportedSymbolNameV2::new(COUNT_METADATA_SYMBOL_PREFIX_V2, compile_identity),
        }
    }

    #[must_use]
    pub const fn compile_identity(&self) -> CountCompileIdentityV2 {
        self.compile_identity
    }

    #[must_use]
    pub const fn entry(&self) -> &ExportedSymbolNameV2 {
        &self.entry
    }

    #[must_use]
    pub const fn payload(&self) -> &ExportedSymbolNameV2 {
        &self.payload
    }

    #[must_use]
    pub const fn metadata(&self) -> &ExportedSymbolNameV2 {
        &self.metadata
    }

    /// Render build-internal declarations from a trusted compile receipt.
    ///
    /// All three definitions are private-external implementation symbols. The
    /// entry is a raw backend boundary referenced only by authenticated V2
    /// runtime glue and never published directly.
    pub fn write_c_declarations(&self, output: &mut impl fmt::Write) -> fmt::Result {
        writeln!(output, "#if defined(__cplusplus)")?;
        writeln!(output, "extern \"C\" {{")?;
        writeln!(output, "#endif")?;
        writeln!(
            output,
            "extern uint64_t {}(const uint8_t *haystack, size_t haystack_len, struct fre_aot_count_result_v2 *result) __attribute__((visibility(\"hidden\")));",
            self.entry
        )?;
        writeln!(
            output,
            "extern const uint8_t {}[] __attribute__((visibility(\"hidden\")));",
            self.payload
        )?;
        writeln!(
            output,
            "extern const struct fre_aot_metadata_v2 {} __attribute__((visibility(\"hidden\")));",
            self.metadata
        )?;
        writeln!(output, "#if defined(__cplusplus)")?;
        writeln!(output, "}}")?;
        writeln!(output, "#endif")
    }
}

/// Canonical aggregate-only V2 metadata.
///
/// Field order is the wire order. The full independent backend support row,
/// actual target features, and allowed feature ceiling are distinct fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataV2 {
    magic: [u8; 8],
    format_version: u16,
    record_bytes: u16,
    backend_version: u16,
    algorithm_version: u16,
    kir_semantics_version: u16,
    kir_abi_version: u16,
    abi_schema: u16,
    max_literal_bytes: u16,
    abi_kind: AbiKind,
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

impl MetadataV2 {
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
    pub const fn algorithm_version(&self) -> u16 {
        self.algorithm_version
    }

    #[must_use]
    pub const fn kir_semantics_version(&self) -> u16 {
        self.kir_semantics_version
    }

    #[must_use]
    pub const fn kir_abi_version(&self) -> u16 {
        self.kir_abi_version
    }

    #[must_use]
    pub const fn abi_schema(&self) -> u16 {
        self.abi_schema
    }

    #[must_use]
    pub const fn max_literal_bytes(&self) -> u16 {
        self.max_literal_bytes
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
    pub const fn actual_features(&self) -> u64 {
        self.actual_features
    }

    #[must_use]
    pub const fn allowed_features(&self) -> u64 {
        self.allowed_features
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
    pub const fn claimed_binding_identity(&self) -> ClaimedBindingIdentity {
        ClaimedBindingIdentity(self.binding_identity)
    }

    #[must_use]
    pub const fn payload_sha256(&self) -> &[u8; 32] {
        &self.payload_sha256
    }

    #[must_use]
    pub const fn claimed_compile_identity(&self) -> ClaimedCountCompileIdentityV2 {
        ClaimedCountCompileIdentityV2(self.compile_identity)
    }

    /// Canonical little-endian wire bytes.
    pub fn canonical_bytes(self) -> Result<[u8; METADATA_BYTES_V2], ObjectError> {
        let mut bytes = [0_u8; METADATA_BYTES_V2];
        self.write_canonical_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Write the canonical little-endian wire directly into caller storage.
    ///
    /// This path allocates nothing and does not materialize a second metadata
    /// record. [`METADATA_V2_WRITER_SCRATCH_BYTES`] reports its exact inline
    /// writer state, excluding the borrowed destination.
    pub fn write_canonical_into(
        &self,
        bytes: &mut [u8; METADATA_BYTES_V2],
    ) -> Result<(), ObjectError> {
        let mut writer = FixedWriter::new(bytes);
        writer.bytes(&self.magic)?;
        writer.u16(self.format_version)?;
        writer.u16(self.record_bytes)?;
        writer.u16(self.backend_version)?;
        writer.u16(self.algorithm_version)?;
        writer.u16(self.kir_semantics_version)?;
        writer.u16(self.kir_abi_version)?;
        writer.u16(self.abi_schema)?;
        writer.u16(self.max_literal_bytes)?;
        writer.u8(self.abi_kind.as_byte())?;
        writer.u8(self.output_kind)?;
        writer.u8(self.architecture)?;
        writer.u8(self.little_endian)?;
        writer.u8(self.pointer_width)?;
        writer.u8(self.target_abi)?;
        writer.u8(self.platform)?;
        writer.u8(self.status_bits)?;
        writer.u64(self.actual_features)?;
        writer.u64(self.allowed_features)?;
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
        if writer.position() != METADATA_BYTES_V2 {
            return Err(ObjectError::InternalInvariant {
                at: "V2 metadata encoding length",
            });
        }
        Ok(())
    }

    /// Strictly decode one canonical V2 record.
    pub fn decode_canonical(bytes: &[u8; METADATA_BYTES_V2]) -> Result<Self, ObjectError> {
        Self::decode(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, ObjectError> {
        if bytes.len() != METADATA_BYTES_V2 {
            return Err(ObjectError::InvalidObject {
                at: "V2 metadata section length",
            });
        }
        let mut reader = Reader::new(bytes);
        let metadata = Self {
            magic: reader.array("V2 metadata magic")?,
            format_version: reader.u16("V2 metadata version")?,
            record_bytes: reader.u16("V2 metadata record bytes")?,
            backend_version: reader.u16("V2 backend version")?,
            algorithm_version: reader.u16("V2 algorithm version")?,
            kir_semantics_version: reader.u16("V2 KIR semantics version")?,
            kir_abi_version: reader.u16("V2 KIR ABI version")?,
            abi_schema: reader.u16("V2 call ABI schema")?,
            max_literal_bytes: reader.u16("V2 maximum literal bytes")?,
            abi_kind: AbiKind::from_byte(reader.u8("V2 ABI kind")?)?,
            output_kind: reader.u8("V2 output kind")?,
            architecture: reader.u8("V2 architecture")?,
            little_endian: reader.u8("V2 byte order")?,
            pointer_width: reader.u8("V2 pointer width")?,
            target_abi: reader.u8("V2 target ABI")?,
            platform: reader.u8("V2 platform")?,
            status_bits: reader.u8("V2 status width")?,
            actual_features: reader.u64("V2 actual features")?,
            allowed_features: reader.u64("V2 allowed features")?,
            payload_bytes: reader.u32("V2 payload bytes")?,
            entry_offset: reader.u32("V2 entry offset")?,
            code_bytes: reader.u32("V2 code bytes")?,
            rodata_offset: reader.u32("V2 rodata offset")?,
            rodata_bytes: reader.u32("V2 rodata bytes")?,
            literal_bytes: reader.u32("V2 literal bytes")?,
            source_identity: reader.array("V2 source identity")?,
            artifact_identity: reader.array("V2 artifact identity")?,
            binding_identity: reader.array("V2 binding identity")?,
            payload_sha256: reader.array("V2 payload digest")?,
            compile_identity: reader.array("V2 compile identity")?,
        };
        if reader.position() != bytes.len() {
            return Err(ObjectError::InvalidObject {
                at: "V2 metadata trailing bytes",
            });
        }
        metadata.validate_shape()?;
        Ok(metadata)
    }

    fn validate_shape(self) -> Result<(), ObjectError> {
        if self.magic != METADATA_MAGIC_V2
            || self.format_version != METADATA_VERSION_V2
            || usize::from(self.record_bytes) != METADATA_BYTES_V2
            || self.abi_kind != AbiKind::Aggregate
            || self.output_kind != 1
            || self.abi_schema != CALL_ABI_SCHEMA_V2
            || self.platform != PLATFORM_MACOS
            || self.status_bits != STATUS_BITS_V2
            || self.entry_offset != ENTRY_OFFSET_V2
            || self.little_endian != 1
            || self.actual_features & !self.allowed_features != 0
            || self.binding_identity == [0; 32]
            || !metadata_support_row_is_explicit(self)
        {
            return Err(ObjectError::InvalidObject {
                at: "aggregate-only V2 metadata contract",
            });
        }
        if self.code_bytes == 0
            || !self.code_bytes.is_multiple_of(4)
            || !self.rodata_offset.is_multiple_of(16)
            || self.rodata_offset < self.code_bytes
            || self.rodata_bytes != 0
            || self.rodata_offset != self.payload_bytes
            || self.literal_bytes > u32::from(self.max_literal_bytes)
        {
            return Err(ObjectError::InvalidObject {
                at: "aggregate-only V2 image layout",
            });
        }
        Ok(())
    }
}

/// Exact object construction receipt for the V2 Count path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountObjectBuildReportV2 {
    pub object_bytes: usize,
    /// Exact allocation layout; equal to `object_bytes`.
    pub persistent_capacity_bytes: usize,
    pub payload_bytes: usize,
    pub image_audit_work_upper_bound: u64,
    pub image_binding_work_upper_bound: u64,
    pub object_work_upper_bound: u64,
    pub total_work_upper_bound: u64,
    pub object_scratch_bytes_upper_bound: u64,
    /// Complete accepted direct-backend scratch receipt. Unlike the audit
    /// report's inner scratch field, this includes retained image backing and
    /// the public sealed-audit caller/wrapper envelope.
    pub image_audit_scratch_upper_bound: u64,
    /// Checked sum of object state and the co-live public image-audit envelope.
    pub scratch_bytes_upper_bound: u64,
    pub sections: u32,
    pub symbols: u32,
    pub image_audit: CountAuditReportV2,
    pub compile_identity: CountCompileIdentityV2,
    pub object_identity: CountObjectIdentityV2,
}

/// Exact-layout owned V2 Count object.
#[derive(Debug, Eq, PartialEq)]
pub struct BuiltCountObjectV2 {
    bytes: Vec<u8>,
    metadata: MetadataV2,
    report: CountObjectBuildReportV2,
}

impl BuiltCountObjectV2 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn metadata(&self) -> MetadataV2 {
        self.metadata
    }

    #[must_use]
    pub const fn report(&self) -> CountObjectBuildReportV2 {
        self.report
    }

    #[must_use]
    pub const fn compile_identity(&self) -> CountCompileIdentityV2 {
        self.report.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> CountObjectIdentityV2 {
        self.report.object_identity
    }

    #[must_use]
    pub fn exported_symbols(&self) -> ExportedSymbolsV2 {
        ExportedSymbolsV2::for_compile_identity(self.report.compile_identity)
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Allocation-free strict view of canonical aggregate-only V2 caller bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountObjectInspectionV2<'a> {
    metadata: MetadataV2,
    metadata_bytes: &'a [u8],
    payload: &'a [u8],
    object_bytes: usize,
    work_upper_bound: u64,
    scratch_bytes_upper_bound: u64,
    claimed_object_identity: ClaimedCountObjectIdentityV2,
}

impl<'a> CountObjectInspectionV2<'a> {
    #[must_use]
    pub const fn metadata(&self) -> MetadataV2 {
        self.metadata
    }

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
    pub const fn work_upper_bound(&self) -> u64 {
        self.work_upper_bound
    }

    #[must_use]
    pub const fn scratch_bytes_upper_bound(&self) -> u64 {
        self.scratch_bytes_upper_bound
    }

    #[must_use]
    pub const fn claimed_compile_identity(&self) -> ClaimedCountCompileIdentityV2 {
        self.metadata.claimed_compile_identity()
    }

    #[must_use]
    pub const fn claimed_object_identity(&self) -> ClaimedCountObjectIdentityV2 {
        self.claimed_object_identity
    }
}

/// Strict V2 object inspection bound to a fresh source-dependent Count audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountObjectValidationV2<'a> {
    pub inspection: CountObjectInspectionV2<'a>,
    pub image_audit: CountAuditReportV2,
    pub object_scratch_bytes_upper_bound: u64,
    /// Complete accepted direct-backend public-audit scratch receipt.
    pub image_audit_scratch_upper_bound: u64,
    /// Checked co-live sum enforced before object parsing or image audit.
    pub scratch_bytes_upper_bound: u64,
}

#[derive(Clone, Copy)]
struct CountImageView<'a> {
    support: AotCountBackendSupportV2,
    target: AotCountTargetSpec,
    source_identity: [u8; 32],
    artifact_identity: [u8; 32],
    payload_bytes: usize,
    code: &'a [u8],
    rodata: &'a [u8],
    rodata_offset: u32,
    literal_bytes: u32,
    image_audit_work_upper_bound: u64,
    image_audit_scratch_upper_bound: u64,
}

impl<'a> CountImageView<'a> {
    fn new(
        program: &ExactAggregateProgram<Count>,
        image: &'a AotCountImageV2,
    ) -> Result<Self, ObjectError> {
        if program.cache_identity() != image.source_identity()
            || program.literal().len()
                != usize::try_from(image.literal_bytes()).map_err(|_| {
                    ObjectError::ArithmeticOverflow {
                        site: ArithmeticSite::Conversion,
                    }
                })?
        {
            return Err(ObjectError::ImageBindingMismatch {
                field: "typed Count KIR source",
            });
        }
        let support = image.support();
        let target = image.target();
        if !is_supported_aot_count_backend_tuple_v2(support)
            || support.output_kind != 1
            || target.architecture != support.architecture
            || target.little_endian != support.little_endian
            || target.pointer_width != support.pointer_width
            || target.abi != support.target_abi
            || !support.allowed_features.contains(target.features)
            || image.output_kind() != support.output_kind
            || image.literal_bytes() > u32::from(support.max_literal_bytes)
        {
            return Err(ObjectError::ImageBindingMismatch {
                field: "explicit Count backend support row",
            });
        }
        let payload_bytes = usize::try_from(image.layout().total_mapped_bytes).map_err(|_| {
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            }
        })?;
        let rodata_offset = image.layout().rodata_from_code_start;
        let rodata_offset_usize =
            usize::try_from(rodata_offset).map_err(|_| ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            })?;
        let Some(alignment_gap) = rodata_offset_usize.checked_sub(image.code().len()) else {
            return Err(ObjectError::ImageBindingMismatch {
                field: "Count image layout",
            });
        };
        if rodata_offset_usize
            .checked_add(image.rodata().len())
            .is_none_or(|total| total != payload_bytes)
            || alignment_gap >= 16
        {
            return Err(ObjectError::ImageBindingMismatch {
                field: "Count image layout",
            });
        }
        let receipt = image.build_receipt();
        let audit = receipt.audit;
        Ok(Self {
            support,
            target,
            source_identity: *image.source_identity().as_bytes(),
            artifact_identity: *image.artifact_identity().as_bytes(),
            payload_bytes,
            code: image.code(),
            rodata: image.rodata(),
            rodata_offset,
            literal_bytes: image.literal_bytes(),
            image_audit_work_upper_bound: audit.work_upper_bound,
            image_audit_scratch_upper_bound: receipt.scratch_bytes_upper_bound,
        })
    }
}

#[derive(Clone, Copy)]
struct CountScratchEnvelopeV2 {
    object: u64,
    image_audit: u64,
    total: u64,
}

#[derive(Clone, Copy)]
struct CountBuildPreflight {
    layout: ObjectLayout,
    image_audit_work_upper_bound: u64,
    image_binding_work_upper_bound: u64,
    object_work_upper_bound: u64,
    total_work_upper_bound: u64,
    object_scratch_bytes_upper_bound: u64,
    image_audit_scratch_upper_bound: u64,
    scratch_bytes_upper_bound: u64,
}

/// Audit and publish an accepted independent Count image as aggregate-only V2.
///
/// The original typed program is mandatory because the direct backend audit
/// deliberately refuses to treat a self-described image as semantic evidence.
pub fn emit_count_object_v2(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV2,
    binding: BindingIdentity,
    limits: ObjectLimits,
) -> Result<BuiltCountObjectV2, ObjectError> {
    let view = CountImageView::new(program, image)?;
    let preflight = preflight_count_build(view, limits)?;
    let image_audit = audit_count_image_v2(program, image).map_err(ObjectError::CountImageAudit)?;
    validate_accepted_count_audit_receipt(
        image,
        image_audit,
        preflight.image_audit_work_upper_bound,
        preflight.image_audit_scratch_upper_bound,
    )?;
    build_count_object_v2(view, binding, limits, preflight, image_audit)
}

/// Re-audit a trusted typed Count source and bind it to caller-supplied V2 bytes.
pub fn validate_count_object_v2<'a>(
    program: &ExactAggregateProgram<Count>,
    image: &AotCountImageV2,
    binding: BindingIdentity,
    bytes: &'a [u8],
    limits: ObjectLimits,
) -> Result<CountObjectValidationV2<'a>, ObjectError> {
    let view = CountImageView::new(program, image)?;
    let inspection_work = preflight_count_inspection_resources(bytes.len(), limits)?;
    let binding_work = count_binding_work_upper_bound(view)?;
    let total_work = inspection_work
        .checked_add(view.image_audit_work_upper_bound)
        .and_then(|work| work.checked_add(binding_work))
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        })?;
    enforce_all(
        ObjectResource::Work,
        total_work,
        limits.max_work,
        HARD_MAX_WORK,
    )?;
    let scratch = count_co_live_scratch_envelope(view)?;
    enforce_all(
        ObjectResource::ScratchBytes,
        scratch.total,
        limits.max_scratch_bytes,
        HARD_MAX_SCRATCH_BYTES,
    )?;
    let inspection = inspect_count_object_v2(bytes, limits)?;
    let image_audit = audit_count_image_v2(program, image).map_err(ObjectError::CountImageAudit)?;
    validate_accepted_count_audit_receipt(
        image,
        image_audit,
        view.image_audit_work_upper_bound,
        scratch.image_audit,
    )?;
    validate_count_view(view, binding, &inspection)?;
    Ok(CountObjectValidationV2 {
        inspection,
        image_audit,
        object_scratch_bytes_upper_bound: scratch.object,
        image_audit_scratch_upper_bound: scratch.image_audit,
        scratch_bytes_upper_bound: scratch.total,
    })
}

fn preflight_count_build(
    view: CountImageView<'_>,
    limits: ObjectLimits,
) -> Result<CountBuildPreflight, ObjectError> {
    let raw_string_bytes = count_symbol_string_bytes()?;
    let layout = ObjectLayout::new_custom(view.payload_bytes, METADATA_BYTES_V2, raw_string_bytes)?;
    let image_binding_work_upper_bound = count_binding_work_upper_bound(view)?;
    let object_work_upper_bound = count_object_work_upper_bound(layout)?;
    let total_work_upper_bound = object_work_upper_bound
        .checked_add(view.image_audit_work_upper_bound)
        .and_then(|work| work.checked_add(image_binding_work_upper_bound))
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        })?;
    let scratch = count_co_live_scratch_envelope(view)?;
    enforce_all(
        ObjectResource::PayloadBytes,
        usize_u64(view.payload_bytes)?,
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
        total_work_upper_bound,
        limits.max_work,
        HARD_MAX_WORK,
    )?;
    enforce_all(
        ObjectResource::ScratchBytes,
        scratch.total,
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
    Ok(CountBuildPreflight {
        layout,
        image_audit_work_upper_bound: view.image_audit_work_upper_bound,
        image_binding_work_upper_bound,
        object_work_upper_bound,
        total_work_upper_bound,
        object_scratch_bytes_upper_bound: scratch.object,
        image_audit_scratch_upper_bound: scratch.image_audit,
        scratch_bytes_upper_bound: scratch.total,
    })
}

fn count_co_live_scratch_envelope(
    view: CountImageView<'_>,
) -> Result<CountScratchEnvelopeV2, ObjectError> {
    let object_scratch_bytes_upper_bound = count_object_scratch_bytes()?;
    let scratch_bytes_upper_bound = object_scratch_bytes_upper_bound
        .checked_add(view.image_audit_scratch_upper_bound)
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::ObjectLayout,
        })?;
    Ok(CountScratchEnvelopeV2 {
        object: object_scratch_bytes_upper_bound,
        image_audit: view.image_audit_scratch_upper_bound,
        total: scratch_bytes_upper_bound,
    })
}

fn validate_accepted_count_audit_receipt(
    image: &AotCountImageV2,
    image_audit: CountAuditReportV2,
    expected_work_upper_bound: u64,
    expected_scratch_upper_bound: u64,
) -> Result<(), ObjectError> {
    let accepted = image.build_receipt();
    if accepted.audit != image_audit
        || image_audit.work_upper_bound != expected_work_upper_bound
        || accepted.scratch_bytes_upper_bound != expected_scratch_upper_bound
        || accepted.scratch_bytes_upper_bound < image_audit.scratch_bytes_upper_bound
    {
        return Err(ObjectError::InternalInvariant {
            at: "V2 Count accepted public-audit receipt seal",
        });
    }
    Ok(())
}

fn count_object_work_upper_bound(layout: ObjectLayout) -> Result<u64, ObjectError> {
    // Exact allocation zero-initialization, bounded overwrites, strict
    // inspection/hash passes, payload hashing, and fixed identity encoding.
    usize_u64(layout.object_bytes)?
        .checked_mul(5)
        .and_then(|work| work.checked_add(usize_u64(layout.payload_bytes).ok()?))
        .and_then(|work| work.checked_add(COUNT_FIXED_IDENTITY_WORK_V2))
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        })
}

fn count_binding_work_upper_bound(view: CountImageView<'_>) -> Result<u64, ObjectError> {
    usize_u64(view.payload_bytes)?
        .checked_add(COUNT_FIXED_BINDING_WORK_V2)
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Work,
        })
}

#[allow(
    clippy::too_many_lines,
    reason = "one fixed-layout publication transaction keeps admitted allocation, bytes, and receipts together"
)]
fn build_count_object_v2(
    view: CountImageView<'_>,
    binding: BindingIdentity,
    limits: ObjectLimits,
    preflight: CountBuildPreflight,
    image_audit: CountAuditReportV2,
) -> Result<BuiltCountObjectV2, ObjectError> {
    let layout = preflight.layout;
    let payload_sha256 = hash_count_payload(view)?;
    let support = view.support;
    let mut metadata = MetadataV2 {
        magic: METADATA_MAGIC_V2,
        format_version: METADATA_VERSION_V2,
        record_bytes: u16::try_from(METADATA_BYTES_V2).map_err(|_| {
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            }
        })?,
        backend_version: support.backend_version.0,
        algorithm_version: support.algorithm_version,
        kir_semantics_version: support.kir_semantics_version,
        kir_abi_version: support.kir_abi_version,
        abi_schema: CALL_ABI_SCHEMA_V2,
        max_literal_bytes: support.max_literal_bytes,
        abi_kind: AbiKind::Aggregate,
        output_kind: support.output_kind,
        architecture: view.target.architecture,
        little_endian: u8::from(view.target.little_endian),
        pointer_width: view.target.pointer_width,
        target_abi: view.target.abi,
        platform: PLATFORM_MACOS,
        status_bits: STATUS_BITS_V2,
        actual_features: view.target.features.bits(),
        allowed_features: support.allowed_features.bits(),
        payload_bytes: u32::try_from(view.payload_bytes).map_err(|_| {
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            }
        })?,
        entry_offset: ENTRY_OFFSET_V2,
        code_bytes: u32::try_from(view.code.len()).map_err(|_| {
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            }
        })?,
        rodata_offset: view.rodata_offset,
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
    metadata.validate_shape()?;
    let compile_identity = compute_count_compile_identity_v2(metadata)?;
    metadata.compile_identity = compile_identity.0;
    let exported_symbols = ExportedSymbolsV2::for_compile_identity(compile_identity);
    let metadata_bytes = metadata.canonical_bytes()?;

    // This is one fallible allocation of exactly the already-admitted final
    // file layout. No growable builder or shrink conversion exists on V2.
    let mut bytes = zeroed_exact(layout.object_bytes).map_err(|_| ObjectError::AllocationFailed)?;
    if bytes.len() != layout.object_bytes || bytes.capacity() != layout.object_bytes {
        return Err(ObjectError::InternalInvariant {
            at: "exact V2 object allocation",
        });
    }
    write_count_object_prefix_v2(&mut bytes, layout)?;
    copy_region(&mut bytes, CONTENT_OFFSET, view.code, "V2 code payload")?;
    copy_region(
        &mut bytes,
        CONTENT_OFFSET
            .checked_add(usize::try_from(view.rodata_offset).map_err(|_| {
                ObjectError::ArithmeticOverflow {
                    site: ArithmeticSite::Conversion,
                }
            })?)
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::FileOffset,
            })?,
        view.rodata,
        "V2 rodata payload",
    )?;
    copy_region(
        &mut bytes,
        layout.metadata_file_offset,
        &metadata_bytes,
        "V2 metadata payload",
    )?;
    write_count_symbol_and_string_tables_v2(&mut bytes, layout, &exported_symbols)?;

    let inspection = inspect_count_object_v2(&bytes, limits)?;
    validate_count_view(view, binding, &inspection)?;
    if inspection.metadata != metadata {
        return Err(ObjectError::InternalInvariant {
            at: "self-inspected V2 metadata",
        });
    }
    let object_identity = CountObjectIdentityV2(*inspection.claimed_object_identity().as_bytes());
    Ok(BuiltCountObjectV2 {
        bytes,
        metadata,
        report: CountObjectBuildReportV2 {
            object_bytes: layout.object_bytes,
            persistent_capacity_bytes: layout.object_bytes,
            payload_bytes: layout.payload_bytes,
            image_audit_work_upper_bound: preflight.image_audit_work_upper_bound,
            image_binding_work_upper_bound: preflight.image_binding_work_upper_bound,
            object_work_upper_bound: preflight.object_work_upper_bound,
            total_work_upper_bound: preflight.total_work_upper_bound,
            object_scratch_bytes_upper_bound: preflight.object_scratch_bytes_upper_bound,
            image_audit_scratch_upper_bound: preflight.image_audit_scratch_upper_bound,
            scratch_bytes_upper_bound: preflight.scratch_bytes_upper_bound,
            sections: u32::try_from(HARD_MAX_SECTIONS).expect("small constant"),
            symbols: u32::try_from(HARD_MAX_SYMBOLS).expect("small constant"),
            image_audit,
            compile_identity,
            object_identity,
        },
    })
}

fn hash_count_payload(view: CountImageView<'_>) -> Result<[u8; 32], ObjectError> {
    let rodata_offset =
        usize::try_from(view.rodata_offset).map_err(|_| ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        })?;
    let gap = rodata_offset
        .checked_sub(view.code.len())
        .ok_or(ObjectError::InvalidObject {
            at: "V2 source code/rodata overlap",
        })?;
    if gap >= 16 {
        return Err(ObjectError::InvalidObject {
            at: "V2 source image alignment gap",
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(view.code);
    hasher.update(&[0_u8; 16][..gap]);
    hasher.update(view.rodata);
    digest_array(&hasher.finalize())
}

fn compute_count_compile_identity_v2(
    mut metadata: MetadataV2,
) -> Result<CountCompileIdentityV2, ObjectError> {
    metadata.compile_identity = [0; 32];
    let mut hasher = Sha256::new();
    hasher.update(COUNT_COMPILE_IDENTITY_DOMAIN_V2);
    hasher.update(EXPORTED_SYMBOL_SCHEMA_VERSION_V2.to_le_bytes());
    hasher.update(
        u16::try_from(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2)
            .expect("fixed identity width fits u16")
            .to_le_bytes(),
    );
    for (prefix, symbol_type) in [
        (COUNT_ENTRY_SYMBOL_PREFIX_V2, N_SECT_PRIVATE_EXT_V2),
        (COUNT_PAYLOAD_SYMBOL_PREFIX_V2, N_SECT_PRIVATE_EXT_V2),
        (COUNT_METADATA_SYMBOL_PREFIX_V2, N_SECT_PRIVATE_EXT_V2),
    ] {
        hasher.update(
            u16::try_from(prefix.len())
                .expect("fixed symbol prefix fits u16")
                .to_le_bytes(),
        );
        hasher.update(prefix.as_bytes());
        hasher.update([symbol_type]);
    }
    hasher.update(MIN_MACOS_VERSION_V1.to_le_bytes());
    hasher.update(metadata.canonical_bytes()?);
    Ok(CountCompileIdentityV2(digest_array(&hasher.finalize())?))
}

fn metadata_support_row_is_explicit(metadata: MetadataV2) -> bool {
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

/// Strictly inspect only the canonical aggregate-only V2 object shape.
pub fn inspect_count_object_v2(
    bytes: &[u8],
    limits: ObjectLimits,
) -> Result<CountObjectInspectionV2<'_>, ObjectError> {
    let preparse_work = preflight_count_inspection_resources(bytes.len(), limits)?;
    let parsed = parse_prefix(bytes)?;
    let metadata_bytes = checked_region(
        bytes,
        parsed.metadata.offset,
        parsed.metadata.size,
        "V2 metadata section",
    )?;
    let metadata = MetadataV2::decode(metadata_bytes)?;
    let layout = ObjectLayout::new_custom(
        parsed.payload.size,
        METADATA_BYTES_V2,
        count_symbol_string_bytes()?,
    )?;
    validate_parsed_layout_with_metadata(bytes, parsed, layout, METADATA_BYTES_V2)?;
    enforce_all(
        ObjectResource::PayloadBytes,
        usize_u64(layout.payload_bytes)?,
        limits.max_payload_bytes,
        HARD_MAX_PAYLOAD_BYTES,
    )?;
    if inspection_work_upper_bound(bytes.len())? != preparse_work {
        return Err(ObjectError::InvalidObject {
            at: "V2 preparse work envelope",
        });
    }
    if compute_count_compile_identity_v2(metadata)?.as_bytes() != &metadata.compile_identity {
        return Err(ObjectError::CompileIdentityMismatch);
    }
    let symbols =
        ExportedSymbolsV2::for_compile_identity(CountCompileIdentityV2(metadata.compile_identity));
    validate_count_symbols_and_strings_v2(bytes, &symbols, layout)?;
    let payload = checked_region(
        bytes,
        parsed.payload.offset,
        parsed.payload.size,
        "V2 payload section",
    )?;
    validate_count_payload_shape_v2(payload, metadata)?;
    if digest_array(&Sha256::digest(payload))? != metadata.payload_sha256 {
        return Err(ObjectError::PayloadDigestMismatch);
    }
    let claimed_object_identity =
        ClaimedCountObjectIdentityV2(digest_array(&Sha256::digest(bytes))?);
    Ok(CountObjectInspectionV2 {
        metadata,
        metadata_bytes,
        payload,
        object_bytes: bytes.len(),
        work_upper_bound: preparse_work,
        scratch_bytes_upper_bound: count_object_scratch_bytes()?,
        claimed_object_identity,
    })
}

fn preflight_count_inspection_resources(
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
        count_object_scratch_bytes()?,
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

fn validate_count_payload_shape_v2(
    payload: &[u8],
    metadata: MetadataV2,
) -> Result<(), ObjectError> {
    if payload.len()
        != usize::try_from(metadata.payload_bytes).map_err(|_| ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        })?
    {
        return Err(ObjectError::InvalidObject {
            at: "V2 payload size metadata",
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
                at: "V2 payload code/rodata overlap",
            })?,
        "V2 payload alignment gap",
    )?;
    if gap.len() >= 16 || gap.iter().any(|&byte| byte != 0) {
        return Err(ObjectError::InvalidObject {
            at: "V2 payload alignment gap",
        });
    }
    if rodata_start != payload.len() {
        return Err(ObjectError::InvalidObject {
            at: "V2 payload must have empty rodata",
        });
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "one explicit comparison matrix binds every authenticated V2 metadata field"
)]
fn validate_count_view(
    view: CountImageView<'_>,
    binding: BindingIdentity,
    inspection: &CountObjectInspectionV2<'_>,
) -> Result<(), ObjectError> {
    let metadata = inspection.metadata;
    let support = view.support;
    let expected_scalars = [
        (
            u64::from(metadata.backend_version),
            u64::from(support.backend_version.0),
            "Count backend version",
        ),
        (
            u64::from(metadata.algorithm_version),
            u64::from(support.algorithm_version),
            "Count algorithm version",
        ),
        (
            u64::from(metadata.kir_semantics_version),
            u64::from(support.kir_semantics_version),
            "Count KIR semantics version",
        ),
        (
            u64::from(metadata.kir_abi_version),
            u64::from(support.kir_abi_version),
            "Count KIR ABI version",
        ),
        (
            u64::from(metadata.max_literal_bytes),
            u64::from(support.max_literal_bytes),
            "Count maximum literal bytes",
        ),
        (
            u64::from(metadata.architecture),
            u64::from(view.target.architecture),
            "Count target architecture",
        ),
        (
            u64::from(metadata.little_endian),
            u64::from(u8::from(view.target.little_endian)),
            "Count target byte order",
        ),
        (
            u64::from(metadata.pointer_width),
            u64::from(view.target.pointer_width),
            "Count target pointer width",
        ),
        (
            u64::from(metadata.target_abi),
            u64::from(view.target.abi),
            "Count target ABI",
        ),
        (
            metadata.actual_features,
            view.target.features.bits(),
            "Count actual features",
        ),
        (
            metadata.allowed_features,
            support.allowed_features.bits(),
            "Count allowed features",
        ),
        (
            u64::from(metadata.payload_bytes),
            usize_u64(view.payload_bytes)?,
            "Count payload bytes",
        ),
        (
            u64::from(metadata.code_bytes),
            usize_u64(view.code.len())?,
            "Count code bytes",
        ),
        (
            u64::from(metadata.rodata_offset),
            u64::from(view.rodata_offset),
            "Count rodata offset",
        ),
        (
            u64::from(metadata.rodata_bytes),
            usize_u64(view.rodata.len())?,
            "Count rodata bytes",
        ),
        (
            u64::from(metadata.literal_bytes),
            u64::from(view.literal_bytes),
            "Count literal bytes",
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
            "Count source identity",
        ),
        (
            metadata.artifact_identity,
            view.artifact_identity,
            "Count artifact identity",
        ),
        (
            metadata.binding_identity,
            *binding.as_bytes(),
            "Count planner binding identity",
        ),
    ] {
        if actual != expected {
            return Err(ObjectError::ImageBindingMismatch { field });
        }
    }
    if checked_region(
        inspection.payload,
        0,
        view.code.len(),
        "bound V2 Count code",
    )? != view.code
    {
        return Err(ObjectError::ImageBindingMismatch {
            field: "Count code payload",
        });
    }
    let rodata_start =
        usize::try_from(view.rodata_offset).map_err(|_| ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::Conversion,
        })?;
    if checked_region(
        inspection.payload,
        view.code.len(),
        rodata_start
            .checked_sub(view.code.len())
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::ImageLayout,
            })?,
        "bound V2 alignment gap",
    )?
    .iter()
    .any(|&byte| byte != 0)
    {
        return Err(ObjectError::ImageBindingMismatch {
            field: "Count alignment gap",
        });
    }
    Ok(())
}

fn count_symbol_string_bytes() -> Result<usize, ObjectError> {
    [
        COUNT_ENTRY_SYMBOL_PREFIX_V2,
        COUNT_PAYLOAD_SYMBOL_PREFIX_V2,
        COUNT_METADATA_SYMBOL_PREFIX_V2,
    ]
    .into_iter()
    .try_fold(4_usize, |total, prefix| {
        total
            .checked_add(MACH_EXTERNAL_PREFIX_BYTES)
            .and_then(|bytes| bytes.checked_add(prefix.len()))
            .and_then(|bytes| bytes.checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2))
            .and_then(|bytes| bytes.checked_add(SYMBOL_TERMINATOR_BYTES))
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::StringTable,
            })
    })
}

#[derive(Clone, Copy)]
struct CountSymbolSpecV2<'a> {
    name: &'a ExportedSymbolNameV2,
    symbol_type: u8,
    section: u8,
    location: SymbolLocation,
}

fn count_symbol_specs_v2(symbols: &ExportedSymbolsV2) -> [CountSymbolSpecV2<'_>; 3] {
    let mut specs = [
        CountSymbolSpecV2 {
            name: symbols.entry(),
            symbol_type: N_SECT_PRIVATE_EXT_V2,
            section: 1,
            location: SymbolLocation::Entry,
        },
        CountSymbolSpecV2 {
            name: symbols.payload(),
            symbol_type: N_SECT_PRIVATE_EXT_V2,
            section: 1,
            location: SymbolLocation::Payload,
        },
        CountSymbolSpecV2 {
            name: symbols.metadata(),
            symbol_type: N_SECT_PRIVATE_EXT_V2,
            section: 2,
            location: SymbolLocation::Metadata,
        },
    ];
    specs.sort_unstable_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    specs
}

fn count_symbol_value_v2(
    symbol: CountSymbolSpecV2<'_>,
    layout: ObjectLayout,
) -> Result<u64, ObjectError> {
    match symbol.location {
        SymbolLocation::Entry | SymbolLocation::Payload => Ok(u64::from(ENTRY_OFFSET_V2)),
        SymbolLocation::Metadata => {
            u64::try_from(layout.metadata_address).map_err(|_| ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            })
        }
    }
}

fn write_count_object_prefix_v2(bytes: &mut [u8], layout: ObjectLayout) -> Result<(), ObjectError> {
    let prefix = bytes
        .get_mut(..CONTENT_OFFSET)
        .ok_or(ObjectError::InternalInvariant {
            at: "V2 object prefix allocation",
        })?;
    let mut writer = FixedWriter::new(prefix);
    writer.u32(MH_MAGIC_64)?;
    writer.u32(CPU_TYPE_ARM64)?;
    writer.u32(CPU_SUBTYPE_ARM64_ALL)?;
    writer.u32(MH_OBJECT)?;
    writer.u32(LOAD_COMMAND_COUNT)?;
    writer.u32(to_u32(LOAD_COMMAND_BYTES)?)?;
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(LC_SEGMENT_64)?;
    writer.u32(to_u32(SEGMENT_WITH_SECTIONS_BYTES)?)?;
    fixed_name_v2(&mut writer, "")?;
    writer.u64(0)?;
    writer.u64(usize_u64(layout.segment_bytes)?)?;
    writer.u64(usize_u64(CONTENT_OFFSET)?)?;
    writer.u64(usize_u64(layout.segment_bytes)?)?;
    writer.u32(VM_PROT_RWX)?;
    writer.u32(VM_PROT_RWX)?;
    writer.u32(u32::try_from(HARD_MAX_SECTIONS).expect("small constant"))?;
    writer.u32(0)?;

    write_section_v2(
        &mut writer,
        "__fre_image",
        "__TEXT",
        0,
        usize_u64(layout.payload_bytes)?,
        to_u32(CONTENT_OFFSET)?,
        4,
        PAYLOAD_SECTION_FLAGS,
    )?;
    write_section_v2(
        &mut writer,
        "__fre_meta",
        "__FRE_CONST",
        usize_u64(layout.metadata_address)?,
        usize_u64(METADATA_BYTES_V2)?,
        to_u32(layout.metadata_file_offset)?,
        3,
        METADATA_SECTION_FLAGS,
    )?;

    writer.u32(LC_BUILD_VERSION)?;
    writer.u32(to_u32(BUILD_VERSION_COMMAND_BYTES)?)?;
    writer.u32(PLATFORM_MACOS_LOAD_COMMAND)?;
    writer.u32(MIN_MACOS_VERSION_V1)?;
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(LC_SYMTAB)?;
    writer.u32(to_u32(SYMTAB_COMMAND_BYTES)?)?;
    writer.u32(to_u32(layout.symbol_file_offset)?)?;
    writer.u32(u32::try_from(HARD_MAX_SYMBOLS).expect("small constant"))?;
    writer.u32(to_u32(layout.string_file_offset)?)?;
    writer.u32(to_u32(layout.string_bytes)?)?;

    writer.u32(LC_DYSYMTAB)?;
    writer.u32(to_u32(DYSYMTAB_COMMAND_BYTES)?)?;
    for value in [0, 0, 0, 3, 3, 0] {
        writer.u32(value)?;
    }
    for _ in 0..12 {
        writer.u32(0)?;
    }
    if writer.position() != MACH_HEADER_BYTES + LOAD_COMMAND_BYTES {
        return Err(ObjectError::InternalInvariant {
            at: "V2 load-command length",
        });
    }
    // Remaining bytes through CONTENT_OFFSET were initialized to canonical 0.
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "fields mirror the fixed Mach-O section_64 wire record"
)]
fn write_section_v2(
    writer: &mut FixedWriter<'_>,
    section_name: &str,
    segment_name: &str,
    address: u64,
    size: u64,
    offset: u32,
    alignment_power: u32,
    flags: u32,
) -> Result<(), ObjectError> {
    fixed_name_v2(writer, section_name)?;
    fixed_name_v2(writer, segment_name)?;
    writer.u64(address)?;
    writer.u64(size)?;
    writer.u32(offset)?;
    writer.u32(alignment_power)?;
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u32(flags)?;
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u32(0)
}

fn fixed_name_v2(writer: &mut FixedWriter<'_>, name: &str) -> Result<(), ObjectError> {
    if name.len() > 16 {
        return Err(ObjectError::InternalInvariant {
            at: "V2 fixed Mach-O name",
        });
    }
    let mut bytes = [0_u8; 16];
    bytes[..name.len()].copy_from_slice(name.as_bytes());
    writer.bytes(&bytes)
}

fn write_count_symbol_and_string_tables_v2(
    bytes: &mut [u8],
    layout: ObjectLayout,
    symbols: &ExportedSymbolsV2,
) -> Result<(), ObjectError> {
    let symbol_table_bytes = NLIST_64_BYTES
        .checked_mul(usize::try_from(HARD_MAX_SYMBOLS).map_err(|_| {
            ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::Conversion,
            }
        })?)
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::ObjectLayout,
        })?;
    let symbol_end = layout
        .symbol_file_offset
        .checked_add(symbol_table_bytes)
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::FileOffset,
        })?;
    let symbol_bytes = bytes.get_mut(layout.symbol_file_offset..symbol_end).ok_or(
        ObjectError::InternalInvariant {
            at: "V2 symbol table allocation",
        },
    )?;
    let specs = count_symbol_specs_v2(symbols);
    let mut writer = FixedWriter::new(symbol_bytes);
    let mut string_index = 4_usize;
    for symbol in specs {
        writer.u32(to_u32(string_index)?)?;
        writer.u8(symbol.symbol_type)?;
        writer.u8(symbol.section)?;
        writer.u16(0)?;
        writer.u64(count_symbol_value_v2(symbol, layout)?)?;
        string_index = string_index
            .checked_add(MACH_EXTERNAL_PREFIX_BYTES)
            .and_then(|value| value.checked_add(symbol.name.as_bytes().len()))
            .and_then(|value| value.checked_add(SYMBOL_TERMINATOR_BYTES))
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::StringTable,
            })?;
    }
    if writer.position() != symbol_table_bytes {
        return Err(ObjectError::InternalInvariant {
            at: "V2 symbol table length",
        });
    }
    let string_end = layout
        .string_file_offset
        .checked_add(layout.string_bytes)
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::FileOffset,
        })?;
    let string_bytes = bytes.get_mut(layout.string_file_offset..string_end).ok_or(
        ObjectError::InternalInvariant {
            at: "V2 string table allocation",
        },
    )?;
    let mut writer = FixedWriter::new(string_bytes);
    writer.u32(0)?;
    for symbol in specs {
        writer.u8(b'_')?;
        writer.bytes(symbol.name.as_bytes())?;
        writer.u8(0)?;
    }
    // Alignment padding retains the allocation's canonical zero initialization.
    Ok(())
}

fn validate_count_symbols_and_strings_v2(
    bytes: &[u8],
    symbols: &ExportedSymbolsV2,
    layout: ObjectLayout,
) -> Result<(), ObjectError> {
    let specs = count_symbol_specs_v2(symbols);
    let symbol_table_bytes =
        NLIST_64_BYTES
            .checked_mul(specs.len())
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::ObjectLayout,
            })?;
    let symbol_bytes = checked_region(
        bytes,
        layout.symbol_file_offset,
        symbol_table_bytes,
        "V2 symbol table",
    )?;
    let string_bytes = checked_region(
        bytes,
        layout.string_file_offset,
        layout.string_bytes,
        "V2 string table",
    )?;
    let mut symbol_reader = Reader::new(symbol_bytes);
    let mut string_index = 4_usize;
    for symbol in specs {
        symbol_reader.expect_u32(to_u32(string_index)?, "V2 symbol string index")?;
        symbol_reader.expect_u8(symbol.symbol_type, "V2 symbol type")?;
        symbol_reader.expect_u8(symbol.section, "V2 symbol section")?;
        symbol_reader.expect_u16(0, "V2 symbol descriptor")?;
        symbol_reader.expect_u64(count_symbol_value_v2(symbol, layout)?, "V2 symbol value")?;
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
            at: "V2 symbol table length",
        });
    }
    let mut string_reader = Reader::new(string_bytes);
    string_reader.expect_zeroes(4, "V2 string-table prefix")?;
    for symbol in specs {
        string_reader.expect_u8(b'_', "V2 external-name prefix")?;
        string_reader.expect_bytes(symbol.name.as_bytes(), "V2 symbol name")?;
        string_reader.expect_u8(0, "V2 symbol-name terminator")?;
    }
    string_reader.expect_zeroes(
        string_bytes
            .len()
            .checked_sub(string_reader.position())
            .ok_or(ObjectError::ArithmeticOverflow {
                site: ArithmeticSite::StringTable,
            })?,
        "V2 string-table padding",
    )
}

fn copy_region(
    bytes: &mut [u8],
    offset: usize,
    source: &[u8],
    at: &'static str,
) -> Result<(), ObjectError> {
    let end = offset
        .checked_add(source.len())
        .ok_or(ObjectError::ArithmeticOverflow {
            site: ArithmeticSite::FileOffset,
        })?;
    let destination = bytes
        .get_mut(offset..end)
        .ok_or(ObjectError::InternalInvariant { at })?;
    destination.copy_from_slice(source);
    Ok(())
}

fn count_object_scratch_bytes() -> Result<u64, ObjectError> {
    let components = [
        METADATA_BYTES_V2,
        size_of::<MetadataV2>(),
        size_of::<Sha256>(),
        size_of::<[u8; 32]>(),
        size_of::<ExportedSymbolsV2>(),
        size_of::<[CountSymbolSpecV2<'static>; 3]>(),
        size_of::<CountImageView<'static>>(),
        size_of::<CountScratchEnvelopeV2>(),
        size_of::<CountBuildPreflight>(),
        size_of::<ObjectLayout>(),
        size_of::<ParsedSection>(),
        size_of::<ParsedPrefix>(),
        size_of::<FixedWriter<'static>>(),
        size_of::<Reader<'static>>(),
        size_of::<CountObjectInspectionV2<'static>>(),
        size_of::<CountObjectValidationV2<'static>>(),
        size_of::<CountObjectBuildReportV2>(),
        size_of::<BuiltCountObjectV2>(),
        size_of::<CountAuditReportV2>(),
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

#[cfg(test)]
mod tests {
    use fre_aot_aarch64::{CountEmitLimitsV2, emit_count_v2};
    use fre_kernel_ir::{ValidateLimits, build_exact_aggregate};

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MetadataFieldMutation {
        Magic,
        FormatVersion,
        RecordBytes,
        BackendVersion,
        AlgorithmVersion,
        KirSemanticsVersion,
        KirAbiVersion,
        AbiSchema,
        MaxLiteralBytes,
        AbiKind,
        OutputKind,
        Architecture,
        LittleEndian,
        PointerWidth,
        TargetAbi,
        Platform,
        StatusBits,
        ActualFeatures,
        AllowedFeatures,
        PayloadBytes,
        EntryOffset,
        CodeBytes,
        RodataOffset,
        RodataBytes,
        LiteralBytes,
        SourceIdentity,
        ArtifactIdentity,
        BindingIdentity,
        PayloadSha256,
        CompileIdentity,
    }

    const EVERY_METADATA_FIELD_MUTATION: &[MetadataFieldMutation] = &[
        MetadataFieldMutation::Magic,
        MetadataFieldMutation::FormatVersion,
        MetadataFieldMutation::RecordBytes,
        MetadataFieldMutation::BackendVersion,
        MetadataFieldMutation::AlgorithmVersion,
        MetadataFieldMutation::KirSemanticsVersion,
        MetadataFieldMutation::KirAbiVersion,
        MetadataFieldMutation::AbiSchema,
        MetadataFieldMutation::MaxLiteralBytes,
        MetadataFieldMutation::AbiKind,
        MetadataFieldMutation::OutputKind,
        MetadataFieldMutation::Architecture,
        MetadataFieldMutation::LittleEndian,
        MetadataFieldMutation::PointerWidth,
        MetadataFieldMutation::TargetAbi,
        MetadataFieldMutation::Platform,
        MetadataFieldMutation::StatusBits,
        MetadataFieldMutation::ActualFeatures,
        MetadataFieldMutation::AllowedFeatures,
        MetadataFieldMutation::PayloadBytes,
        MetadataFieldMutation::EntryOffset,
        MetadataFieldMutation::CodeBytes,
        MetadataFieldMutation::RodataOffset,
        MetadataFieldMutation::RodataBytes,
        MetadataFieldMutation::LiteralBytes,
        MetadataFieldMutation::SourceIdentity,
        MetadataFieldMutation::ArtifactIdentity,
        MetadataFieldMutation::BindingIdentity,
        MetadataFieldMutation::PayloadSha256,
        MetadataFieldMutation::CompileIdentity,
    ];

    fn metadata_fixture() -> MetadataV2 {
        let support = SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2[0];
        MetadataV2 {
            magic: METADATA_MAGIC_V2,
            format_version: METADATA_VERSION_V2,
            record_bytes: u16::try_from(METADATA_BYTES_V2).unwrap(),
            backend_version: support.backend_version.0,
            algorithm_version: support.algorithm_version,
            kir_semantics_version: support.kir_semantics_version,
            kir_abi_version: support.kir_abi_version,
            abi_schema: CALL_ABI_SCHEMA_V2,
            max_literal_bytes: support.max_literal_bytes,
            abi_kind: AbiKind::Aggregate,
            output_kind: support.output_kind,
            architecture: support.architecture,
            little_endian: u8::from(support.little_endian),
            pointer_width: support.pointer_width,
            target_abi: support.target_abi,
            platform: PLATFORM_MACOS,
            status_bits: STATUS_BITS_V2,
            actual_features: 0,
            allowed_features: support.allowed_features.bits(),
            payload_bytes: 16,
            entry_offset: ENTRY_OFFSET_V2,
            code_bytes: 4,
            rodata_offset: 16,
            rodata_bytes: 0,
            literal_bytes: 3,
            source_identity: [1; 32],
            artifact_identity: [2; 32],
            binding_identity: [3; 32],
            payload_sha256: [4; 32],
            compile_identity: [0; 32],
        }
    }

    fn mutate_metadata(metadata: &mut MetadataV2, mutation: MetadataFieldMutation) {
        match mutation {
            MetadataFieldMutation::Magic => metadata.magic[0] ^= 1,
            MetadataFieldMutation::FormatVersion => metadata.format_version ^= 1,
            MetadataFieldMutation::RecordBytes => metadata.record_bytes ^= 1,
            MetadataFieldMutation::BackendVersion => metadata.backend_version ^= 1,
            MetadataFieldMutation::AlgorithmVersion => {
                metadata.algorithm_version = metadata.algorithm_version.checked_sub(1).unwrap();
            }
            MetadataFieldMutation::KirSemanticsVersion => metadata.kir_semantics_version ^= 1,
            MetadataFieldMutation::KirAbiVersion => metadata.kir_abi_version ^= 1,
            MetadataFieldMutation::AbiSchema => metadata.abi_schema ^= 1,
            MetadataFieldMutation::MaxLiteralBytes => {
                metadata.max_literal_bytes = metadata.max_literal_bytes.checked_sub(1).unwrap();
            }
            MetadataFieldMutation::AbiKind => metadata.abi_kind = AbiKind::Search,
            MetadataFieldMutation::OutputKind => metadata.output_kind ^= 1,
            MetadataFieldMutation::Architecture => metadata.architecture ^= 1,
            MetadataFieldMutation::LittleEndian => metadata.little_endian ^= 1,
            MetadataFieldMutation::PointerWidth => metadata.pointer_width ^= 1,
            MetadataFieldMutation::TargetAbi => metadata.target_abi ^= 1,
            MetadataFieldMutation::Platform => metadata.platform ^= 1,
            MetadataFieldMutation::StatusBits => {
                metadata.status_bits = metadata.status_bits.checked_sub(1).unwrap();
            }
            MetadataFieldMutation::ActualFeatures => metadata.actual_features = 0,
            MetadataFieldMutation::AllowedFeatures => metadata.allowed_features ^= 1,
            MetadataFieldMutation::PayloadBytes => {
                metadata.payload_bytes = metadata.payload_bytes.checked_add(16).unwrap();
            }
            MetadataFieldMutation::EntryOffset => metadata.entry_offset = 4,
            MetadataFieldMutation::CodeBytes => {
                metadata.code_bytes = metadata.code_bytes.checked_sub(4).unwrap();
            }
            MetadataFieldMutation::RodataOffset => {
                metadata.rodata_offset = metadata.rodata_offset.checked_add(16).unwrap();
            }
            MetadataFieldMutation::RodataBytes => metadata.rodata_bytes = 1,
            MetadataFieldMutation::LiteralBytes => {
                metadata.literal_bytes = metadata.literal_bytes.checked_sub(1).unwrap();
            }
            MetadataFieldMutation::SourceIdentity => metadata.source_identity[0] ^= 1,
            MetadataFieldMutation::ArtifactIdentity => metadata.artifact_identity[0] ^= 1,
            MetadataFieldMutation::BindingIdentity => metadata.binding_identity[0] ^= 1,
            MetadataFieldMutation::PayloadSha256 => metadata.payload_sha256[0] ^= 1,
            MetadataFieldMutation::CompileIdentity => metadata.compile_identity[0] ^= 1,
        }
    }

    fn rewrite_metadata_and_symbols(
        built: &BuiltCountObjectV2,
        mutation: MetadataFieldMutation,
    ) -> Vec<u8> {
        let mut metadata = built.metadata();
        mutate_metadata(&mut metadata, mutation);
        if mutation != MetadataFieldMutation::CompileIdentity {
            metadata.compile_identity = *compute_count_compile_identity_v2(metadata)
                .unwrap()
                .as_bytes();
        }
        let layout = ObjectLayout::new_custom(
            built.report().payload_bytes,
            METADATA_BYTES_V2,
            count_symbol_string_bytes().unwrap(),
        )
        .unwrap();
        let mut bytes = built.as_bytes().to_vec();
        copy_region(
            &mut bytes,
            layout.metadata_file_offset,
            &metadata.canonical_bytes().unwrap(),
            "mutated V2 metadata",
        )
        .unwrap();
        write_count_symbol_and_string_tables_v2(
            &mut bytes,
            layout,
            &ExportedSymbolsV2::for_compile_identity(CountCompileIdentityV2(
                metadata.compile_identity,
            )),
        )
        .unwrap();
        bytes
    }

    #[test]
    fn metadata_v2_pins_accepted_offsets_and_complete_support_row() {
        let mut metadata = metadata_fixture();
        let identity = compute_count_compile_identity_v2(metadata).unwrap();
        metadata.compile_identity = *identity.as_bytes();
        let bytes = metadata.canonical_bytes().unwrap();

        assert_eq!(&bytes[..8], b"FREOM64\x02");
        assert_eq!(&bytes[8..10], &METADATA_VERSION_V2.to_le_bytes());
        assert_eq!(
            &bytes[10..12],
            &u16::try_from(METADATA_BYTES_V2).unwrap().to_le_bytes()
        );
        assert_eq!(&bytes[12..14], &metadata.backend_version().to_le_bytes());
        assert_eq!(&bytes[14..16], &metadata.algorithm_version().to_le_bytes());
        assert_eq!(
            &bytes[16..18],
            &metadata.kir_semantics_version().to_le_bytes()
        );
        assert_eq!(&bytes[18..20], &metadata.kir_abi_version().to_le_bytes());
        assert_eq!(&bytes[20..22], &CALL_ABI_SCHEMA_V2.to_le_bytes());
        assert_eq!(&bytes[22..24], &metadata.max_literal_bytes().to_le_bytes());
        assert_eq!(
            &bytes[24..32],
            &[
                AbiKind::Aggregate.as_byte(),
                metadata.output_kind(),
                metadata.architecture(),
                u8::from(metadata.little_endian()),
                metadata.pointer_width(),
                metadata.target_abi(),
                PLATFORM_MACOS,
                STATUS_BITS_V2,
            ]
        );
        assert_eq!(&bytes[32..40], &0_u64.to_le_bytes());
        assert_eq!(&bytes[40..48], &metadata.allowed_features().to_le_bytes());
        assert_eq!(&bytes[48..52], &metadata.payload_bytes().to_le_bytes());
        assert_eq!(&bytes[52..56], &metadata.entry_offset().to_le_bytes());
        assert_eq!(&bytes[56..60], &metadata.code_bytes().to_le_bytes());
        assert_eq!(&bytes[60..64], &metadata.rodata_offset().to_le_bytes());
        assert_eq!(&bytes[64..68], &metadata.rodata_bytes().to_le_bytes());
        assert_eq!(&bytes[68..72], &metadata.literal_bytes().to_le_bytes());
        assert_eq!(&bytes[72..104], &[1; 32]);
        assert_eq!(&bytes[104..136], &[2; 32]);
        assert_eq!(&bytes[136..168], &[3; 32]);
        assert_eq!(&bytes[168..200], &[4; 32]);
        assert_eq!(&bytes[200..232], identity.as_bytes());
        assert_eq!(MetadataV2::decode_canonical(&bytes).unwrap(), metadata);
        assert_eq!(
            METADATA_V2_WRITER_SCRATCH_BYTES,
            size_of::<FixedWriter<'static>>()
        );
    }

    #[test]
    fn v2_symbols_are_count_scoped_and_never_alias_v1() {
        let identity = compute_count_compile_identity_v2(metadata_fixture()).unwrap();
        let symbols = ExportedSymbolsV2::for_compile_identity(identity);
        assert!(
            symbols
                .entry()
                .as_str()
                .starts_with(COUNT_ENTRY_SYMBOL_PREFIX_V2)
        );
        assert!(
            symbols
                .payload()
                .as_str()
                .starts_with(COUNT_PAYLOAD_SYMBOL_PREFIX_V2)
        );
        assert!(
            symbols
                .metadata()
                .as_str()
                .starts_with(COUNT_METADATA_SYMBOL_PREFIX_V2)
        );
        assert!(!symbols.entry().as_str().contains("_v1_"));

        for symbol in count_symbol_specs_v2(&symbols) {
            assert_eq!(symbol.symbol_type, N_SECT_PRIVATE_EXT_V2);
        }

        let mut declarations = String::new();
        symbols.write_c_declarations(&mut declarations).unwrap();
        assert_eq!(declarations.matches("visibility(\"hidden\")").count(), 3);
    }

    #[test]
    fn v2_parser_rejects_a_public_raw_implementation_symbol() {
        let program =
            build_exact_aggregate::<Count>(b"private", ValidateLimits::default()).unwrap();
        let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
        let built = emit_count_object_v2(
            &program,
            &image,
            BindingIdentity::new([0x35; 32]).unwrap(),
            ObjectLimits::default(),
        )
        .unwrap();
        let layout = ObjectLayout::new_custom(
            built.report().payload_bytes,
            METADATA_BYTES_V2,
            count_symbol_string_bytes().unwrap(),
        )
        .unwrap();
        let mut bytes = built.into_bytes();
        for index in 0..usize::try_from(HARD_MAX_SYMBOLS).unwrap() {
            let symbol_type_offset = layout
                .symbol_file_offset
                .checked_add(index.checked_mul(NLIST_64_BYTES).unwrap())
                .and_then(|offset| offset.checked_add(4))
                .unwrap();
            let private_type = bytes[symbol_type_offset];
            assert_eq!(private_type, N_SECT_PRIVATE_EXT_V2);
            bytes[symbol_type_offset] = N_SECT_EXT;
            assert!(matches!(
                inspect_count_object_v2(&bytes, ObjectLimits::default()),
                Err(ObjectError::InvalidObject {
                    at: "V2 symbol type"
                })
            ));
            bytes[symbol_type_offset] = private_type;
        }
    }

    #[test]
    fn v2_rejects_feature_ceiling_and_backend_row_forgery() {
        let mut features = metadata_fixture();
        features.actual_features = features.allowed_features | (1 << 63);
        assert!(features.validate_shape().is_err());

        let mut backend = metadata_fixture();
        backend.backend_version ^= 1;
        assert!(backend.validate_shape().is_err());
    }

    #[test]
    fn current_v2_object_contract_names_only_backend_a002_algorithm_4_and_rejects_stale_3() {
        assert_eq!(SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2.len(), 1);
        let support = SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2[0];
        assert_eq!(support.backend_version.0, 0xa002);
        assert_eq!(support.algorithm_version, 4);
        assert!(
            SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2
                .iter()
                .all(|row| row.algorithm_version != 3)
        );
    }

    #[test]
    fn every_v2_metadata_field_mutation_is_rejected_by_inspection_or_external_validation() {
        let program =
            build_exact_aggregate::<Count>(b"field-mutation", ValidateLimits::default()).unwrap();
        let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
        let binding = BindingIdentity::new([0x47; 32]).unwrap();
        let built =
            emit_count_object_v2(&program, &image, binding, ObjectLimits::default()).unwrap();

        for &mutation in EVERY_METADATA_FIELD_MUTATION {
            let hostile = rewrite_metadata_and_symbols(&built, mutation);
            match inspect_count_object_v2(&hostile, ObjectLimits::default()) {
                Err(_) => {}
                Ok(_) => assert!(
                    validate_count_object_v2(
                        &program,
                        &image,
                        binding,
                        &hostile,
                        ObjectLimits::default(),
                    )
                    .is_err(),
                    "external validation accepted {mutation:?}"
                ),
            }
        }
    }

    #[test]
    fn self_consistent_identity_feature_and_literal_forgeries_reach_external_validation() {
        let program =
            build_exact_aggregate::<Count>(b"semantic-forgery", ValidateLimits::default()).unwrap();
        let image = emit_count_v2(&program, CountEmitLimitsV2::default()).unwrap();
        let binding = BindingIdentity::new([0x58; 32]).unwrap();
        let built =
            emit_count_object_v2(&program, &image, binding, ObjectLimits::default()).unwrap();

        for mutation in [
            MetadataFieldMutation::ActualFeatures,
            MetadataFieldMutation::LiteralBytes,
            MetadataFieldMutation::SourceIdentity,
            MetadataFieldMutation::ArtifactIdentity,
            MetadataFieldMutation::BindingIdentity,
        ] {
            let hostile = rewrite_metadata_and_symbols(&built, mutation);
            let inspection = inspect_count_object_v2(&hostile, ObjectLimits::default())
                .unwrap_or_else(|error| panic!("self-consistent {mutation:?} failed: {error}"));
            assert!(
                !built
                    .compile_identity()
                    .matches_claim(inspection.claimed_compile_identity())
            );
            assert!(
                !built
                    .object_identity()
                    .matches_claim(inspection.claimed_object_identity())
            );
            assert!(
                matches!(
                    validate_count_object_v2(
                        &program,
                        &image,
                        binding,
                        &hostile,
                        ObjectLimits::default(),
                    ),
                    Err(ObjectError::ImageBindingMismatch { .. })
                ),
                "external validation accepted {mutation:?}"
            );
        }
    }
}
