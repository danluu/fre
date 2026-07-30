use core::mem::size_of;

use fre_jit_aarch64::{AuditReport, BackendVersion, CpuFeatures, NativeImage, TargetSpec, audit};
use sha2::{Digest, Sha256};

use crate::{
    BindingIdentity, ClaimedObjectIdentity, CompileIdentity, ELF_CLASS_64_V1, ELF_DATA_LSB_V1,
    ELF_MACHINE_AARCH64_V1, ELF_OS_ABI_SYSV_V1, ELF_RELOCATABLE_TYPE_V1, ELF_VERSION_CURRENT_V1,
    ElfObjectError, ElfObjectResource, ExportedSymbolsV1, METADATA_BYTES_V1, MetadataV1,
    ObjectIdentity,
};

pub const HARD_MAX_PAYLOAD_BYTES_V1: u64 = 4 << 20;
pub const HARD_MAX_OBJECT_BYTES_V1: u64 = 5 << 20;
pub const HARD_MAX_PERSISTENT_BYTES_V1: u64 = 6 << 20;
const HARD_MAX_WORK_V1: u64 = 24 << 20;

const ELF_HEADER_BYTES: usize = 64;
const SECTION_HEADER_BYTES: usize = 64;
const SYMBOL_BYTES: usize = 24;
const SECTION_COUNT: usize = 7;
const SYMBOL_COUNT: usize = 5;

const PAYLOAD_SECTION: u16 = 1;
const METADATA_SECTION: u16 = 2;
const STRING_SECTION: u16 = 3;
const SECTION_STRING_SECTION: u16 = 6;

const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHF_ALLOC: u64 = 1 << 1;
const SHF_EXECINSTR: u64 = 1 << 2;
const STB_LOCAL_SECTION: u8 = 0x03;
const STB_GLOBAL_OBJECT: u8 = 0x11;
const STB_GLOBAL_FUNCTION: u8 = 0x12;
const STV_HIDDEN: u8 = 2;

const PAYLOAD_SECTION_NAME: &str = ".text.fre_aot_search";
const METADATA_SECTION_NAME: &str = ".rodata.fre_aot_metadata";
const STRING_SECTION_NAME: &str = ".strtab";
const SYMBOL_SECTION_NAME: &str = ".symtab";
const GNU_STACK_SECTION_NAME: &str = ".note.GNU-stack";
const SECTION_STRING_SECTION_NAME: &str = ".shstrtab";

/// Caller-selected limits, each additionally capped by a crate hard maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectLimitsV1 {
    pub max_object_bytes: u64,
    pub max_persistent_bytes: u64,
    pub max_payload_bytes: u64,
    pub max_work: u64,
}

impl Default for ObjectLimitsV1 {
    fn default() -> Self {
        Self {
            max_object_bytes: HARD_MAX_OBJECT_BYTES_V1,
            max_persistent_bytes: HARD_MAX_PERSISTENT_BYTES_V1,
            max_payload_bytes: HARD_MAX_PAYLOAD_BYTES_V1,
            max_work: HARD_MAX_WORK_V1,
        }
    }
}

/// Exact serialized sizes and authenticated identities from object emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectBuildReportV1 {
    pub object_bytes: usize,
    pub persistent_capacity_bytes: usize,
    pub payload_bytes: usize,
    pub total_work: u64,
    pub sections: u16,
    pub symbols: u16,
    pub image_audit: AuditReport,
    pub compile_identity: CompileIdentity,
    pub object_identity: ObjectIdentity,
}

/// Owned canonical Linux `AArch64` relocatable object.
#[derive(Debug, Eq, PartialEq)]
pub struct BuiltSearchObjectV1 {
    bytes: Vec<u8>,
    metadata: MetadataV1,
    report: ObjectBuildReportV1,
}

impl BuiltSearchObjectV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn metadata(&self) -> MetadataV1 {
        self.metadata
    }

    #[must_use]
    pub const fn compile_identity(&self) -> CompileIdentity {
        self.report.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> ObjectIdentity {
        self.report.object_identity
    }

    #[must_use]
    pub const fn report(&self) -> ObjectBuildReportV1 {
        self.report
    }

    #[must_use]
    pub fn exported_symbols(&self) -> ExportedSymbolsV1 {
        ExportedSymbolsV1::for_compile_identity(self.compile_identity())
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Strict borrowed projection of one canonical object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectInspectionV1<'a> {
    metadata: MetadataV1,
    metadata_bytes: &'a [u8],
    payload: &'a [u8],
    object_bytes: usize,
    work: u64,
    claimed_object_identity: ClaimedObjectIdentity,
}

impl<'a> ObjectInspectionV1<'a> {
    #[must_use]
    pub const fn metadata(&self) -> MetadataV1 {
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
    pub const fn work(&self) -> u64 {
        self.work
    }

    #[must_use]
    pub const fn claimed_compile_identity(&self) -> crate::ClaimedCompileIdentity {
        self.metadata.claimed_compile_identity()
    }

    #[must_use]
    pub const fn claimed_object_identity(&self) -> ClaimedObjectIdentity {
        self.claimed_object_identity
    }
}

/// Strict object inspection paired with an independent image audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectValidationV1<'a> {
    inspection: ObjectInspectionV1<'a>,
    image_audit: AuditReport,
}

impl<'a> ObjectValidationV1<'a> {
    #[must_use]
    pub const fn inspection(&self) -> ObjectInspectionV1<'a> {
        self.inspection
    }

    #[must_use]
    pub const fn image_audit(&self) -> AuditReport {
        self.image_audit
    }
}

/// Independently audit and wrap a supported Search image as canonical
/// `ELF64LE` `ET_REL`.
pub fn emit_search_object_v1(
    image: &NativeImage,
    binding: BindingIdentity,
    limits: ObjectLimitsV1,
) -> Result<BuiltSearchObjectV1, ElfObjectError> {
    validate_image_shape(image)?;
    let payload_bytes = payload_bytes(image)?;
    preflight_payload(payload_bytes, limits)?;
    let image_audit = audit(image).map_err(ElfObjectError::ImageAudit)?;
    let payload = build_payload(image, payload_bytes)?;
    let payload_sha256 = Sha256::digest(&payload).into();
    let metadata = MetadataV1::from_image(image, binding, payload_sha256, payload_bytes)?;
    let bytes = encode_object(&payload, metadata, limits)?;
    let persistent_capacity_bytes = bytes.capacity();
    enforce(
        ElfObjectResource::PersistentBytes,
        usize_u64(persistent_capacity_bytes, "persistent bytes")?,
        limits.max_persistent_bytes,
        HARD_MAX_PERSISTENT_BYTES_V1,
    )?;
    let inspection = inspect_search_object_v1(&bytes, limits)?;
    validate_image_binding(image, binding, &inspection)?;
    if inspection.metadata != metadata {
        return Err(invalid("self-inspected metadata"));
    }
    let object_identity = ObjectIdentity(*inspection.claimed_object_identity().as_bytes());
    let work = inspection.work;
    let object_bytes = inspection.object_bytes;
    Ok(BuiltSearchObjectV1 {
        bytes,
        metadata,
        report: ObjectBuildReportV1 {
            object_bytes,
            persistent_capacity_bytes,
            payload_bytes,
            total_work: work,
            sections: u16::try_from(SECTION_COUNT).expect("fixed section count"),
            symbols: u16::try_from(SYMBOL_COUNT).expect("fixed symbol count"),
            image_audit,
            compile_identity: metadata.compile_identity(),
            object_identity,
        },
    })
}

/// Strictly inspect the sole canonical object shape.
///
/// Every header, section, symbol, table, padding byte, and trailing byte is
/// covered by an exact canonical re-emission comparison.
pub fn inspect_search_object_v1(
    bytes: &[u8],
    limits: ObjectLimitsV1,
) -> Result<ObjectInspectionV1<'_>, ElfObjectError> {
    enforce(
        ElfObjectResource::ObjectBytes,
        usize_u64(bytes.len(), "object bytes")?,
        limits.max_object_bytes,
        HARD_MAX_OBJECT_BYTES_V1,
    )?;
    let parsed = parse_header(bytes)?;
    if parsed.count != SECTION_COUNT || parsed.string_index != SECTION_STRING_SECTION {
        return Err(invalid("ELF section header contract"));
    }
    let metadata_header = read_section_header(bytes, parsed.headers_offset, METADATA_SECTION)?;
    let metadata_bytes = region(
        bytes,
        to_usize(metadata_header.offset, "metadata offset")?,
        to_usize(metadata_header.size, "metadata size")?,
        "metadata section",
    )?;
    let metadata = MetadataV1::decode(metadata_bytes)?;
    let payload_header = read_section_header(bytes, parsed.headers_offset, PAYLOAD_SECTION)?;
    let payload = region(
        bytes,
        to_usize(payload_header.offset, "payload offset")?,
        to_usize(payload_header.size, "payload size")?,
        "payload section",
    )?;
    enforce(
        ElfObjectResource::PayloadBytes,
        usize_u64(payload.len(), "payload bytes")?,
        limits.max_payload_bytes,
        HARD_MAX_PAYLOAD_BYTES_V1,
    )?;
    if usize::try_from(metadata.payload_bytes()).ok() != Some(payload.len()) {
        return Err(invalid("metadata payload extent"));
    }
    validate_payload(payload, metadata)?;

    let canonical = encode_object(payload, metadata, limits)?;
    if canonical != bytes {
        return Err(invalid("canonical whole ELF object"));
    }
    let work = usize_u64(bytes.len(), "inspection work")?
        .checked_mul(4)
        .ok_or(ElfObjectError::ArithmeticOverflow {
            at: "inspection work",
        })?;
    enforce(
        ElfObjectResource::Work,
        work,
        limits.max_work,
        HARD_MAX_WORK_V1,
    )?;
    let claimed_object_identity = ClaimedObjectIdentity(Sha256::digest(bytes).into());
    Ok(ObjectInspectionV1 {
        metadata,
        metadata_bytes,
        payload,
        object_bytes: bytes.len(),
        work,
        claimed_object_identity,
    })
}

/// Re-audit an expected image and bind every image/object identity.
pub fn validate_search_object_v1<'a>(
    image: &NativeImage,
    binding: BindingIdentity,
    bytes: &'a [u8],
    limits: ObjectLimitsV1,
) -> Result<ObjectValidationV1<'a>, ElfObjectError> {
    validate_image_shape(image)?;
    let inspection = inspect_search_object_v1(bytes, limits)?;
    let image_audit = audit(image).map_err(ElfObjectError::ImageAudit)?;
    validate_image_binding(image, binding, &inspection)?;
    Ok(ObjectValidationV1 {
        inspection,
        image_audit,
    })
}

fn validate_image_shape(image: &NativeImage) -> Result<(), ElfObjectError> {
    let target = image.target();
    let baseline = TargetSpec::AARCH64_AAPCS64;
    let supported = match image.backend_version() {
        version
            if matches!(
                version,
                BackendVersion::SEARCH_V8 | BackendVersion::SEARCH_V9
            ) =>
        {
            target.features == CpuFeatures::ASIMD
        }
        version if version == BackendVersion::SEARCH_SVE2_FIXED16_V2 => {
            target.features == CpuFeatures::ASIMD_SVE2
        }
        _ => false,
    };
    let layout = image.layout();
    let code_bytes = u32::try_from(image.code().len())
        .map_err(|_| ElfObjectError::ArithmeticOverflow { at: "code bytes" })?;
    let rodata_bytes = u32::try_from(image.rodata().len())
        .map_err(|_| ElfObjectError::ArithmeticOverflow { at: "rodata bytes" })?;
    let rodata_offset = usize::try_from(layout.rodata_from_code_start).map_err(|_| {
        ElfObjectError::ArithmeticOverflow {
            at: "rodata offset",
        }
    })?;
    let rodata_end = layout
        .rodata_from_code_start
        .checked_add(rodata_bytes)
        .ok_or(ElfObjectError::ArithmeticOverflow {
            at: "image layout end",
        })?;
    if !supported
        || target.architecture != baseline.architecture
        || target.little_endian != baseline.little_endian
        || target.pointer_width != baseline.pointer_width
        || target.abi != baseline.abi
        || layout.code_alignment != 16
        || layout.rodata_alignment != 16
        || !layout.rodata_from_code_start.is_multiple_of(16)
        || rodata_offset < image.code().len()
        || rodata_end != layout.total_mapped_bytes
        || image.code().is_empty()
        || !image.code().len().is_multiple_of(4)
        || image.stats().code_bytes != code_bytes
        || image.stats().data_bytes != rodata_bytes
    {
        return Err(invalid("supported Linux Search image"));
    }
    Ok(())
}

fn payload_bytes(image: &NativeImage) -> Result<usize, ElfObjectError> {
    usize::try_from(image.layout().total_mapped_bytes).map_err(|_| {
        ElfObjectError::ArithmeticOverflow {
            at: "payload bytes",
        }
    })
}

fn preflight_payload(payload_bytes: usize, limits: ObjectLimitsV1) -> Result<(), ElfObjectError> {
    enforce(
        ElfObjectResource::PayloadBytes,
        usize_u64(payload_bytes, "payload bytes")?,
        limits.max_payload_bytes,
        HARD_MAX_PAYLOAD_BYTES_V1,
    )
}

fn build_payload(image: &NativeImage, payload_bytes: usize) -> Result<Vec<u8>, ElfObjectError> {
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_bytes)
        .map_err(|_| ElfObjectError::AllocationFailed)?;
    payload.extend_from_slice(image.code());
    payload.resize(
        usize::try_from(image.layout().rodata_from_code_start).map_err(|_| {
            ElfObjectError::ArithmeticOverflow {
                at: "rodata offset",
            }
        })?,
        0,
    );
    payload.extend_from_slice(image.rodata());
    if payload.len() != payload_bytes {
        return Err(invalid("constructed payload extent"));
    }
    Ok(payload)
}

fn validate_image_binding(
    image: &NativeImage,
    binding: BindingIdentity,
    inspection: &ObjectInspectionV1<'_>,
) -> Result<(), ElfObjectError> {
    let metadata = inspection.metadata;
    let code_bytes = u32::try_from(image.code().len())
        .map_err(|_| ElfObjectError::ArithmeticOverflow { at: "code bytes" })?;
    let rodata_bytes = u32::try_from(image.rodata().len())
        .map_err(|_| ElfObjectError::ArithmeticOverflow { at: "rodata bytes" })?;
    if metadata.backend_version() != image.backend_version().0
        || metadata.output_kind() != output_tag(image.output())
        || metadata.architecture() != image.target().architecture
        || metadata.little_endian() != image.target().little_endian
        || metadata.pointer_width() != image.target().pointer_width
        || metadata.target_abi() != image.target().abi
        || metadata.features() != image.target().features.bits()
        || metadata.code_bytes() != code_bytes
        || metadata.rodata_offset() != image.layout().rodata_from_code_start
        || metadata.rodata_bytes() != rodata_bytes
        || metadata.source_identity() != image.source_identity().as_bytes()
        || metadata.artifact_identity() != image.artifact_identity().as_bytes()
        || !binding.matches_claim(metadata.claimed_binding_identity())
    {
        return Err(invalid("image/object binding"));
    }
    let rodata_offset = usize::try_from(metadata.rodata_offset()).map_err(|_| {
        ElfObjectError::ArithmeticOverflow {
            at: "rodata offset",
        }
    })?;
    if inspection.payload.get(..image.code().len()) != Some(image.code())
        || inspection
            .payload
            .get(image.code().len()..rodata_offset)
            .is_none_or(|padding| padding.iter().any(|&byte| byte != 0))
        || inspection.payload.get(rodata_offset..) != Some(image.rodata())
    {
        return Err(invalid("image/object payload"));
    }
    Ok(())
}

fn validate_payload(payload: &[u8], metadata: MetadataV1) -> Result<(), ElfObjectError> {
    let code_end = usize::try_from(metadata.code_bytes())
        .map_err(|_| ElfObjectError::ArithmeticOverflow { at: "code bytes" })?;
    let rodata_offset = usize::try_from(metadata.rodata_offset()).map_err(|_| {
        ElfObjectError::ArithmeticOverflow {
            at: "rodata offset",
        }
    })?;
    if payload
        .get(code_end..rodata_offset)
        .is_none_or(|padding| padding.len() >= 16 || padding.iter().any(|&byte| byte != 0))
    {
        return Err(invalid("payload alignment gap"));
    }
    let digest: [u8; 32] = Sha256::digest(payload).into();
    if &digest != metadata.payload_sha256() {
        return Err(ElfObjectError::PayloadDigestMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ParsedHeader {
    headers_offset: usize,
    count: usize,
    string_index: u16,
}

fn parse_header(bytes: &[u8]) -> Result<ParsedHeader, ElfObjectError> {
    let mut reader = Reader::new(bytes);
    reader.expect(&[0x7f, b'E', b'L', b'F'], "ELF magic")?;
    reader.expect(
        &[
            ELF_CLASS_64_V1,
            ELF_DATA_LSB_V1,
            ELF_VERSION_CURRENT_V1,
            ELF_OS_ABI_SYSV_V1,
            0,
        ],
        "ELF identity",
    )?;
    reader.expect(&[0; 7], "ELF identity padding")?;
    reader.expect_u16(ELF_RELOCATABLE_TYPE_V1, "ELF type")?;
    reader.expect_u16(ELF_MACHINE_AARCH64_V1, "ELF machine")?;
    reader.expect_u32(u32::from(ELF_VERSION_CURRENT_V1), "ELF version")?;
    reader.expect_u64(0, "ELF entry")?;
    reader.expect_u64(0, "program headers")?;
    let section_headers = reader.usize_u64("section headers")?;
    reader.expect_u32(0, "ELF flags")?;
    reader.expect_u16(
        u16::try_from(ELF_HEADER_BYTES).expect("fixed header"),
        "ELF header bytes",
    )?;
    reader.expect_u16(0, "program header bytes")?;
    reader.expect_u16(0, "program header count")?;
    reader.expect_u16(
        u16::try_from(SECTION_HEADER_BYTES).expect("fixed section header"),
        "section header bytes",
    )?;
    let section_count = usize::from(reader.u16("section count")?);
    let section_string_index = reader.u16("section string index")?;
    if reader.position() != ELF_HEADER_BYTES
        || section_headers < ELF_HEADER_BYTES
        || section_headers > bytes.len()
    {
        return Err(invalid("ELF header extent"));
    }
    Ok(ParsedHeader {
        headers_offset: section_headers,
        count: section_count,
        string_index: section_string_index,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SectionHeader {
    name: u32,
    kind: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_bytes: u64,
}

fn read_section_header(
    bytes: &[u8],
    base: usize,
    index: u16,
) -> Result<SectionHeader, ElfObjectError> {
    let offset = usize::from(index)
        .checked_mul(SECTION_HEADER_BYTES)
        .and_then(|bytes| base.checked_add(bytes))
        .ok_or(ElfObjectError::ArithmeticOverflow {
            at: "section header offset",
        })?;
    let mut reader = Reader::new(region(
        bytes,
        offset,
        SECTION_HEADER_BYTES,
        "section header",
    )?);
    let header = SectionHeader {
        name: reader.u32("section name")?,
        kind: reader.u32("section kind")?,
        flags: reader.u64("section flags")?,
        address: reader.u64("section address")?,
        offset: reader.u64("section offset")?,
        size: reader.u64("section size")?,
        link: reader.u32("section link")?,
        info: reader.u32("section info")?,
        alignment: reader.u64("section alignment")?,
        entry_bytes: reader.u64("section entry bytes")?,
    };
    if reader.position() != SECTION_HEADER_BYTES {
        return Err(invalid("section header width"));
    }
    Ok(header)
}

struct StringTables {
    symbol: Vec<u8>,
    entry_name: u32,
    payload_name: u32,
    metadata_name: u32,
    section: Vec<u8>,
    payload_section_name: u32,
    metadata_section_name: u32,
    string_section_name: u32,
    symbol_section_name: u32,
    gnu_stack_section_name: u32,
    section_string_section_name: u32,
}

impl StringTables {
    fn new(symbols: &ExportedSymbolsV1) -> Result<Self, ElfObjectError> {
        let mut symbol = vec![0];
        let entry_name = push_string(&mut symbol, symbols.entry().as_bytes())?;
        let payload_name = push_string(&mut symbol, symbols.payload().as_bytes())?;
        let metadata_name = push_string(&mut symbol, symbols.metadata().as_bytes())?;

        let mut section = vec![0];
        let payload_section_name = push_string(&mut section, PAYLOAD_SECTION_NAME.as_bytes())?;
        let metadata_section_name = push_string(&mut section, METADATA_SECTION_NAME.as_bytes())?;
        let string_section_name = push_string(&mut section, STRING_SECTION_NAME.as_bytes())?;
        let symbol_section_name = push_string(&mut section, SYMBOL_SECTION_NAME.as_bytes())?;
        let gnu_stack_section_name = push_string(&mut section, GNU_STACK_SECTION_NAME.as_bytes())?;
        let section_string_section_name =
            push_string(&mut section, SECTION_STRING_SECTION_NAME.as_bytes())?;
        Ok(Self {
            symbol,
            entry_name,
            payload_name,
            metadata_name,
            section,
            payload_section_name,
            metadata_section_name,
            string_section_name,
            symbol_section_name,
            gnu_stack_section_name,
            section_string_section_name,
        })
    }
}

#[derive(Clone, Copy)]
struct Layout {
    payload_offset: usize,
    metadata_offset: usize,
    string_offset: usize,
    symbol_offset: usize,
    section_string_offset: usize,
    section_header_offset: usize,
    object_bytes: usize,
}

impl Layout {
    fn new(payload_bytes: usize, tables: &StringTables) -> Result<Self, ElfObjectError> {
        let payload_offset = align_up(ELF_HEADER_BYTES, 16, "payload offset")?;
        let metadata_offset = align_up(
            payload_offset
                .checked_add(payload_bytes)
                .ok_or(ElfObjectError::ArithmeticOverflow { at: "payload end" })?,
            8,
            "metadata offset",
        )?;
        let string_offset = metadata_offset
            .checked_add(METADATA_BYTES_V1)
            .ok_or(ElfObjectError::ArithmeticOverflow { at: "metadata end" })?;
        let symbol_offset = align_up(
            string_offset.checked_add(tables.symbol.len()).ok_or(
                ElfObjectError::ArithmeticOverflow {
                    at: "string table end",
                },
            )?,
            8,
            "symbol offset",
        )?;
        let section_string_offset = symbol_offset
            .checked_add(SYMBOL_BYTES.checked_mul(SYMBOL_COUNT).ok_or(
                ElfObjectError::ArithmeticOverflow {
                    at: "symbol table bytes",
                },
            )?)
            .ok_or(ElfObjectError::ArithmeticOverflow {
                at: "symbol table end",
            })?;
        let section_header_offset = align_up(
            section_string_offset
                .checked_add(tables.section.len())
                .ok_or(ElfObjectError::ArithmeticOverflow {
                    at: "section string end",
                })?,
            8,
            "section header offset",
        )?;
        let object_bytes = section_header_offset
            .checked_add(SECTION_HEADER_BYTES.checked_mul(SECTION_COUNT).ok_or(
                ElfObjectError::ArithmeticOverflow {
                    at: "section header bytes",
                },
            )?)
            .ok_or(ElfObjectError::ArithmeticOverflow { at: "object bytes" })?;
        Ok(Self {
            payload_offset,
            metadata_offset,
            string_offset,
            symbol_offset,
            section_string_offset,
            section_header_offset,
            object_bytes,
        })
    }
}

fn encode_object(
    payload: &[u8],
    metadata: MetadataV1,
    limits: ObjectLimitsV1,
) -> Result<Vec<u8>, ElfObjectError> {
    let symbols = ExportedSymbolsV1::for_compile_identity(metadata.compile_identity());
    let tables = StringTables::new(&symbols)?;
    let layout = Layout::new(payload.len(), &tables)?;
    enforce(
        ElfObjectResource::ObjectBytes,
        usize_u64(layout.object_bytes, "object bytes")?,
        limits.max_object_bytes,
        HARD_MAX_OBJECT_BYTES_V1,
    )?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(layout.object_bytes)
        .map_err(|_| ElfObjectError::AllocationFailed)?;
    bytes.resize(layout.object_bytes, 0);

    write_header(&mut bytes[..ELF_HEADER_BYTES], layout)?;
    copy_region(&mut bytes, layout.payload_offset, payload, "payload")?;
    copy_region(
        &mut bytes,
        layout.metadata_offset,
        &metadata.encode()?,
        "metadata",
    )?;
    copy_region(
        &mut bytes,
        layout.string_offset,
        &tables.symbol,
        "string table",
    )?;
    write_symbols(&mut bytes, layout, &tables, metadata)?;
    copy_region(
        &mut bytes,
        layout.section_string_offset,
        &tables.section,
        "section string table",
    )?;
    write_sections(&mut bytes, layout, &tables, payload.len())?;
    Ok(bytes)
}

fn write_header(destination: &mut [u8], layout: Layout) -> Result<(), ElfObjectError> {
    let mut writer = Writer::new(destination);
    writer.raw(&[0x7f, b'E', b'L', b'F'])?;
    writer.raw(&[
        ELF_CLASS_64_V1,
        ELF_DATA_LSB_V1,
        ELF_VERSION_CURRENT_V1,
        ELF_OS_ABI_SYSV_V1,
        0,
    ])?;
    writer.raw(&[0; 7])?;
    writer.u16(ELF_RELOCATABLE_TYPE_V1)?;
    writer.u16(ELF_MACHINE_AARCH64_V1)?;
    writer.u32(u32::from(ELF_VERSION_CURRENT_V1))?;
    writer.u64(0)?;
    writer.u64(0)?;
    writer.u64(usize_u64(
        layout.section_header_offset,
        "section header offset",
    )?)?;
    writer.u32(0)?;
    writer.u16(u16::try_from(ELF_HEADER_BYTES).expect("fixed header"))?;
    writer.u16(0)?;
    writer.u16(0)?;
    writer.u16(u16::try_from(SECTION_HEADER_BYTES).expect("fixed section header"))?;
    writer.u16(u16::try_from(SECTION_COUNT).expect("fixed section count"))?;
    writer.u16(SECTION_STRING_SECTION)?;
    if writer.position() != ELF_HEADER_BYTES {
        return Err(invalid("ELF header width"));
    }
    Ok(())
}

fn write_symbols(
    bytes: &mut [u8],
    layout: Layout,
    tables: &StringTables,
    metadata: MetadataV1,
) -> Result<(), ElfObjectError> {
    let symbol_bytes =
        SYMBOL_BYTES
            .checked_mul(SYMBOL_COUNT)
            .ok_or(ElfObjectError::ArithmeticOverflow {
                at: "symbol table bytes",
            })?;
    let destination = region_mut(bytes, layout.symbol_offset, symbol_bytes, "symbol table")?;
    let mut writer = Writer::new(destination);
    write_symbol(&mut writer, 0, 0, 0, 0, 0, 0)?;
    write_symbol(&mut writer, 0, STB_LOCAL_SECTION, 0, PAYLOAD_SECTION, 0, 0)?;
    write_symbol(
        &mut writer,
        tables.entry_name,
        STB_GLOBAL_FUNCTION,
        STV_HIDDEN,
        PAYLOAD_SECTION,
        u64::from(metadata.entry_offset()),
        u64::from(metadata.code_bytes()),
    )?;
    write_symbol(
        &mut writer,
        tables.payload_name,
        STB_GLOBAL_OBJECT,
        STV_HIDDEN,
        PAYLOAD_SECTION,
        0,
        u64::from(metadata.payload_bytes()),
    )?;
    write_symbol(
        &mut writer,
        tables.metadata_name,
        STB_GLOBAL_OBJECT,
        STV_HIDDEN,
        METADATA_SECTION,
        0,
        u64::try_from(METADATA_BYTES_V1).expect("fixed metadata bytes"),
    )?;
    if writer.position() != symbol_bytes {
        return Err(invalid("symbol table width"));
    }
    Ok(())
}

fn write_symbol(
    writer: &mut Writer<'_>,
    name: u32,
    info: u8,
    other: u8,
    section: u16,
    value: u64,
    bytes: u64,
) -> Result<(), ElfObjectError> {
    writer.u32(name)?;
    writer.u8(info)?;
    writer.u8(other)?;
    writer.u16(section)?;
    writer.u64(value)?;
    writer.u64(bytes)
}

#[allow(
    clippy::too_many_lines,
    reason = "keeping all seven canonical section headers together makes their exact order and byte fields directly auditable"
)]
fn write_sections(
    bytes: &mut [u8],
    layout: Layout,
    tables: &StringTables,
    payload_bytes: usize,
) -> Result<(), ElfObjectError> {
    let section_bytes = SECTION_HEADER_BYTES.checked_mul(SECTION_COUNT).ok_or(
        ElfObjectError::ArithmeticOverflow {
            at: "section table bytes",
        },
    )?;
    let mut writer = Writer::new(region_mut(
        bytes,
        layout.section_header_offset,
        section_bytes,
        "section table",
    )?);
    write_section(&mut writer, SectionHeader::null())?;
    write_section(
        &mut writer,
        SectionHeader {
            name: tables.payload_section_name,
            kind: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXECINSTR,
            address: 0,
            offset: usize_u64(layout.payload_offset, "payload offset")?,
            size: usize_u64(payload_bytes, "payload bytes")?,
            link: 0,
            info: 0,
            alignment: 16,
            entry_bytes: 0,
        },
    )?;
    write_section(
        &mut writer,
        SectionHeader {
            name: tables.metadata_section_name,
            kind: SHT_PROGBITS,
            flags: SHF_ALLOC,
            address: 0,
            offset: usize_u64(layout.metadata_offset, "metadata offset")?,
            size: u64::try_from(METADATA_BYTES_V1).expect("fixed metadata bytes"),
            link: 0,
            info: 0,
            alignment: 8,
            entry_bytes: 0,
        },
    )?;
    write_section(
        &mut writer,
        SectionHeader {
            name: tables.string_section_name,
            kind: SHT_STRTAB,
            flags: 0,
            address: 0,
            offset: usize_u64(layout.string_offset, "string offset")?,
            size: usize_u64(tables.symbol.len(), "string bytes")?,
            link: 0,
            info: 0,
            alignment: 1,
            entry_bytes: 0,
        },
    )?;
    write_section(
        &mut writer,
        SectionHeader {
            name: tables.symbol_section_name,
            kind: SHT_SYMTAB,
            flags: 0,
            address: 0,
            offset: usize_u64(layout.symbol_offset, "symbol offset")?,
            size: usize_u64(
                SYMBOL_BYTES
                    .checked_mul(SYMBOL_COUNT)
                    .ok_or(ElfObjectError::ArithmeticOverflow { at: "symbol bytes" })?,
                "symbol bytes",
            )?,
            link: u32::from(STRING_SECTION),
            info: 2,
            alignment: 8,
            entry_bytes: u64::try_from(SYMBOL_BYTES).expect("fixed symbol bytes"),
        },
    )?;
    write_section(
        &mut writer,
        SectionHeader {
            name: tables.gnu_stack_section_name,
            kind: SHT_PROGBITS,
            flags: 0,
            address: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            alignment: 1,
            entry_bytes: 0,
        },
    )?;
    write_section(
        &mut writer,
        SectionHeader {
            name: tables.section_string_section_name,
            kind: SHT_STRTAB,
            flags: 0,
            address: 0,
            offset: usize_u64(layout.section_string_offset, "section string offset")?,
            size: usize_u64(tables.section.len(), "section string bytes")?,
            link: 0,
            info: 0,
            alignment: 1,
            entry_bytes: 0,
        },
    )?;
    if writer.position() != section_bytes {
        return Err(invalid("section table width"));
    }
    Ok(())
}

impl SectionHeader {
    const fn null() -> Self {
        Self {
            name: 0,
            kind: SHT_NULL,
            flags: 0,
            address: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            alignment: 0,
            entry_bytes: 0,
        }
    }
}

fn write_section(writer: &mut Writer<'_>, section: SectionHeader) -> Result<(), ElfObjectError> {
    writer.u32(section.name)?;
    writer.u32(section.kind)?;
    writer.u64(section.flags)?;
    writer.u64(section.address)?;
    writer.u64(section.offset)?;
    writer.u64(section.size)?;
    writer.u32(section.link)?;
    writer.u32(section.info)?;
    writer.u64(section.alignment)?;
    writer.u64(section.entry_bytes)
}

fn push_string(destination: &mut Vec<u8>, value: &[u8]) -> Result<u32, ElfObjectError> {
    if value.contains(&0) {
        return Err(invalid("embedded symbol NUL"));
    }
    let offset =
        u32::try_from(destination.len()).map_err(|_| ElfObjectError::ArithmeticOverflow {
            at: "string table offset",
        })?;
    destination.extend_from_slice(value);
    destination.push(0);
    Ok(offset)
}

fn copy_region(
    destination: &mut [u8],
    offset: usize,
    source: &[u8],
    at: &'static str,
) -> Result<(), ElfObjectError> {
    region_mut(destination, offset, source.len(), at)?.copy_from_slice(source);
    Ok(())
}

fn region<'a>(
    source: &'a [u8],
    offset: usize,
    bytes: usize,
    at: &'static str,
) -> Result<&'a [u8], ElfObjectError> {
    let end = offset
        .checked_add(bytes)
        .ok_or(ElfObjectError::ArithmeticOverflow { at })?;
    source.get(offset..end).ok_or_else(|| invalid(at))
}

fn region_mut<'a>(
    destination: &'a mut [u8],
    offset: usize,
    bytes: usize,
    at: &'static str,
) -> Result<&'a mut [u8], ElfObjectError> {
    let end = offset
        .checked_add(bytes)
        .ok_or(ElfObjectError::ArithmeticOverflow { at })?;
    destination.get_mut(offset..end).ok_or_else(|| invalid(at))
}

fn align_up(value: usize, alignment: usize, at: &'static str) -> Result<usize, ElfObjectError> {
    if !alignment.is_power_of_two() {
        return Err(invalid("alignment"));
    }
    let mask = alignment
        .checked_sub(1)
        .ok_or_else(|| invalid("alignment"))?;
    value
        .checked_add(mask)
        .map(|value| value & !mask)
        .ok_or(ElfObjectError::ArithmeticOverflow { at })
}

fn enforce(
    resource: ElfObjectResource,
    required: u64,
    caller_limit: u64,
    hard_limit: u64,
) -> Result<(), ElfObjectError> {
    let limit = caller_limit.min(hard_limit);
    if required > limit {
        Err(ElfObjectError::ResourceLimit {
            resource,
            limit,
            required,
        })
    } else {
        Ok(())
    }
}

fn usize_u64(value: usize, at: &'static str) -> Result<u64, ElfObjectError> {
    u64::try_from(value).map_err(|_| ElfObjectError::ArithmeticOverflow { at })
}

fn to_usize(value: u64, at: &'static str) -> Result<usize, ElfObjectError> {
    usize::try_from(value).map_err(|_| ElfObjectError::ArithmeticOverflow { at })
}

const fn output_tag(output: fre_kernel_ir::OutputKind) -> u8 {
    match output {
        fre_kernel_ir::OutputKind::Exists => 1,
        fre_kernel_ir::OutputKind::SelectedEnd => 2,
        fre_kernel_ir::OutputKind::Span => 3,
    }
}

const fn invalid(at: &'static str) -> ElfObjectError {
    ElfObjectError::InvalidObject { at }
}

struct Writer<'a> {
    destination: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    const fn new(destination: &'a mut [u8]) -> Self {
        Self {
            destination,
            position: 0,
        }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), ElfObjectError> {
        let end =
            self.position
                .checked_add(bytes.len())
                .ok_or(ElfObjectError::ArithmeticOverflow {
                    at: "object writer",
                })?;
        self.destination
            .get_mut(self.position..end)
            .ok_or_else(|| invalid("object writer range"))?
            .copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), ElfObjectError> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), ElfObjectError> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), ElfObjectError> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), ElfObjectError> {
        self.raw(&value.to_le_bytes())
    }
}

struct Reader<'a> {
    source: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            position: 0,
        }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn raw(&mut self, bytes: usize, at: &'static str) -> Result<&'a [u8], ElfObjectError> {
        let end = self
            .position
            .checked_add(bytes)
            .ok_or(ElfObjectError::ArithmeticOverflow { at })?;
        let value = self
            .source
            .get(self.position..end)
            .ok_or_else(|| invalid(at))?;
        self.position = end;
        Ok(value)
    }

    fn expect(&mut self, expected: &[u8], at: &'static str) -> Result<(), ElfObjectError> {
        if self.raw(expected.len(), at)? == expected {
            Ok(())
        } else {
            Err(invalid(at))
        }
    }

    fn array<const N: usize>(&mut self, at: &'static str) -> Result<[u8; N], ElfObjectError> {
        self.raw(N, at)?.try_into().map_err(|_| invalid(at))
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, ElfObjectError> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, ElfObjectError> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn u64(&mut self, at: &'static str) -> Result<u64, ElfObjectError> {
        Ok(u64::from_le_bytes(self.array(at)?))
    }

    fn usize_u64(&mut self, at: &'static str) -> Result<usize, ElfObjectError> {
        to_usize(self.u64(at)?, at)
    }

    fn expect_u16(&mut self, expected: u16, at: &'static str) -> Result<(), ElfObjectError> {
        if self.u16(at)? == expected {
            Ok(())
        } else {
            Err(invalid(at))
        }
    }

    fn expect_u32(&mut self, expected: u32, at: &'static str) -> Result<(), ElfObjectError> {
        if self.u32(at)? == expected {
            Ok(())
        } else {
            Err(invalid(at))
        }
    }

    fn expect_u64(&mut self, expected: u64, at: &'static str) -> Result<(), ElfObjectError> {
        if self.u64(at)? == expected {
            Ok(())
        } else {
            Err(invalid(at))
        }
    }
}

const _: () = assert!(size_of::<u64>() == 8);
const _: () = assert!(ELF_HEADER_BYTES == 64);
const _: () = assert!(SECTION_HEADER_BYTES == 64);
const _: () = assert!(SYMBOL_BYTES == 24);
const _: () = assert!(METADATA_BYTES_V1 == 216);

#[cfg(test)]
mod image_binding_tests {
    use fre_jit_aarch64::{EmitLimits, SearchBackendPolicy, emit_with_backend};
    use fre_kernel_ir::{AnchorFlags, Span, ValidateLimits, build_exact_literal};

    use super::*;

    #[test]
    fn full_validation_rejects_an_internally_consistent_substituted_payload() {
        let program = build_exact_literal::<Span>(
            b"0123456789abcdef",
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("exact-literal test KIR");
        let image = emit_with_backend(
            &program,
            SearchBackendPolicy::Sve2Fixed16V2,
            EmitLimits::default(),
        )
        .expect("test native image");
        let binding = BindingIdentity::new([0x5a; 32]).expect("nonzero test binding");
        let limits = ObjectLimitsV1::default();
        let payload_bytes = payload_bytes(&image).expect("payload extent");
        let mut substituted =
            build_payload(&image, payload_bytes).expect("canonical image payload");
        substituted[0] ^= 1;
        let substituted_digest = Sha256::digest(&substituted).into();
        let metadata = MetadataV1::from_image(&image, binding, substituted_digest, payload_bytes)
            .expect("self-consistent substituted metadata");
        let object =
            encode_object(&substituted, metadata, limits).expect("canonical substituted object");

        inspect_search_object_v1(&object, limits)
            .expect("signer-free substituted object remains internally consistent");
        assert!(
            validate_search_object_v1(&image, binding, &object, limits).is_err(),
            "full image binding accepted substituted machine code"
        );
    }
}
