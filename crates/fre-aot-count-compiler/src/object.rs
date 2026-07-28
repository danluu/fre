use fre_aot_aarch64::AotCountImageV2;
use fre_aot_count_contract::{
    CALL_ABI_SCHEMA_V2, COUNT_ABI_KIND_V2, COUNT_ENTRY_SYMBOL_PREFIX_V2,
    COUNT_EXPORTED_SYMBOL_N_TYPE_V2, COUNT_METADATA_SYMBOL_PREFIX_V2, COUNT_OUTPUT_KIND_V2,
    COUNT_PAYLOAD_SYMBOL_PREFIX_V2, COUNT_PLATFORM_MACOS_V2, ClaimedCountMetadataV2,
    ENTRY_OFFSET_V2, EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2, EXPORTED_SYMBOL_SCHEMA_VERSION_V2,
    METADATA_BYTES_V2, METADATA_VERSION_V2, STATUS_BITS_V2, inspect_count_metadata_v2,
};
use fre_exact_alloc::zeroed_exact;
use sha2::{Digest, Sha256};

use crate::CountCompileErrorV2;

const COMPILE_IDENTITY_DOMAIN_V2: &[u8] = b"FRE-AOT-MACHO-COUNT-COMPILE\0\x02";
const MIN_MACOS_VERSION_V2: u32 = 0x000b_0000;
const CONTENT_OFFSET: usize = 400;
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
const NLIST_64_BYTES: usize = 16;
const SYMBOLS: usize = 3;
const SECTIONS: u32 = 2;
const SYMBOL_TERMINATOR_BYTES: usize = 1;
const MACH_EXTERNAL_PREFIX_BYTES: usize = 1;
const SYMBOL_NAME_STORAGE_BYTES: usize = 112;
const MAX_STRING_TABLE_BYTES: usize = 320;
const METADATA_COMPILE_IDENTITY_OFFSET: usize = 200;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
const MH_OBJECT: u32 = 1;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x02;
const LC_DYSYMTAB: u32 = 0x0b;
const LC_BUILD_VERSION: u32 = 0x32;
const PLATFORM_MACOS_LOAD_COMMAND: u32 = 1;
const PAYLOAD_SECTION_FLAGS: u32 = 0x1000_0400;
const METADATA_SECTION_FLAGS: u32 = 0x1000_0000;
const VM_PROT_RWX: u32 = 7;

const _: () = assert!(MACH_HEADER_BYTES + LOAD_COMMAND_BYTES <= CONTENT_OFFSET);
const _: () = assert!(METADATA_COMPILE_IDENTITY_OFFSET + 32 == METADATA_BYTES_V2);

/// Hard and caller-selected bounds for one implementation object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountObjectLimitsV2 {
    pub max_payload_bytes: u64,
    pub max_object_bytes: u64,
}

impl Default for CountObjectLimitsV2 {
    fn default() -> Self {
        Self {
            max_payload_bytes: 4 << 20,
            max_object_bytes: 5 << 20,
        }
    }
}

/// Deterministic Count implementation `MH_OBJECT` and recomputed identities.
#[derive(Debug, Eq, PartialEq)]
pub struct CountImplementationObjectV2 {
    bytes: Vec<u8>,
    metadata_bytes: [u8; METADATA_BYTES_V2],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    payload_bytes: usize,
}

impl CountImplementationObjectV2 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn metadata_bytes(&self) -> &[u8; METADATA_BYTES_V2] {
        &self.metadata_bytes
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        &self.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> &[u8; 32] {
        &self.object_identity
    }

    #[must_use]
    pub const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.bytes.capacity()
    }

    #[must_use]
    pub const fn allocations(&self) -> u8 {
        1
    }
}

/// Strict allocation-free view of one canonical implementation object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountImplementationInspectionV2<'a> {
    object_bytes: usize,
    payload: &'a [u8],
    metadata_bytes: &'a [u8; METADATA_BYTES_V2],
    metadata: ClaimedCountMetadataV2,
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
}

impl<'a> CountImplementationInspectionV2<'a> {
    #[must_use]
    pub const fn object_bytes(&self) -> usize {
        self.object_bytes
    }

    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    #[must_use]
    pub const fn metadata_bytes(&self) -> &'a [u8; METADATA_BYTES_V2] {
        self.metadata_bytes
    }

    #[must_use]
    pub const fn metadata(&self) -> ClaimedCountMetadataV2 {
        self.metadata
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        &self.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> &[u8; 32] {
        &self.object_identity
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectLayout {
    payload_bytes: usize,
    metadata_address: usize,
    metadata_file_offset: usize,
    segment_bytes: usize,
    symbol_file_offset: usize,
    string_file_offset: usize,
    string_bytes: usize,
    object_bytes: usize,
}

impl ObjectLayout {
    fn new(payload_bytes: usize) -> Result<Self, CountCompileErrorV2> {
        let metadata_address = align_up(payload_bytes, 8, "metadata address")?;
        let segment_bytes = metadata_address
            .checked_add(METADATA_BYTES_V2)
            .ok_or(overflow("segment bytes"))?;
        let metadata_file_offset = CONTENT_OFFSET
            .checked_add(metadata_address)
            .ok_or(overflow("metadata file offset"))?;
        let symbol_file_offset = CONTENT_OFFSET
            .checked_add(segment_bytes)
            .ok_or(overflow("symbol file offset"))?;
        let symbol_table_bytes = NLIST_64_BYTES
            .checked_mul(SYMBOLS)
            .ok_or(overflow("symbol table bytes"))?;
        let string_file_offset = symbol_file_offset
            .checked_add(symbol_table_bytes)
            .ok_or(overflow("string file offset"))?;
        let string_bytes = align_up(count_symbol_string_bytes()?, 4, "string table bytes")?;
        let object_bytes = string_file_offset
            .checked_add(string_bytes)
            .ok_or(overflow("object bytes"))?;
        Ok(Self {
            payload_bytes,
            metadata_address,
            metadata_file_offset,
            segment_bytes,
            symbol_file_offset,
            string_file_offset,
            string_bytes,
            object_bytes,
        })
    }
}

#[derive(Clone, Copy)]
struct SymbolName {
    bytes: [u8; SYMBOL_NAME_STORAGE_BYTES],
    len: usize,
}

impl SymbolName {
    fn new(prefix: &str, identity: &[u8; 32]) -> Result<Self, CountCompileErrorV2> {
        let len = prefix
            .len()
            .checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2)
            .ok_or(overflow("symbol name length"))?;
        if len > SYMBOL_NAME_STORAGE_BYTES {
            return Err(CountCompileErrorV2::InvalidObject {
                at: "symbol name storage",
            });
        }
        let mut bytes = [0_u8; SYMBOL_NAME_STORAGE_BYTES];
        bytes
            .get_mut(..prefix.len())
            .ok_or(CountCompileErrorV2::InvalidObject {
                at: "symbol prefix range",
            })?
            .copy_from_slice(prefix.as_bytes());
        let mut cursor = prefix.len();
        for byte in identity {
            let encoded = [lower_hex(byte >> 4), lower_hex(byte & 0x0f)];
            let end = cursor
                .checked_add(encoded.len())
                .ok_or(overflow("symbol hex offset"))?;
            bytes
                .get_mut(cursor..end)
                .ok_or(CountCompileErrorV2::InvalidObject {
                    at: "symbol hex range",
                })?
                .copy_from_slice(&encoded);
            cursor = end;
        }
        if cursor != len {
            return Err(CountCompileErrorV2::InvalidObject {
                at: "symbol name length",
            });
        }
        Ok(Self { bytes, len })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Clone, Copy)]
enum SymbolLocation {
    Entry,
    Payload,
    Metadata,
}

#[derive(Clone, Copy)]
struct SymbolSpec {
    name: SymbolName,
    section: u8,
    location: SymbolLocation,
}

fn symbol_specs(identity: &[u8; 32]) -> Result<[SymbolSpec; SYMBOLS], CountCompileErrorV2> {
    let mut specs = [
        SymbolSpec {
            name: SymbolName::new(COUNT_ENTRY_SYMBOL_PREFIX_V2, identity)?,
            section: 1,
            location: SymbolLocation::Entry,
        },
        SymbolSpec {
            name: SymbolName::new(COUNT_PAYLOAD_SYMBOL_PREFIX_V2, identity)?,
            section: 1,
            location: SymbolLocation::Payload,
        },
        SymbolSpec {
            name: SymbolName::new(COUNT_METADATA_SYMBOL_PREFIX_V2, identity)?,
            section: 2,
            location: SymbolLocation::Metadata,
        },
    ];
    specs.sort_unstable_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    Ok(specs)
}

pub(crate) fn emit_count_implementation_object_v2(
    image: &AotCountImageV2,
    binding_identity: [u8; 32],
    limits: CountObjectLimitsV2,
) -> Result<CountImplementationObjectV2, CountCompileErrorV2> {
    if binding_identity == [0; 32] {
        return Err(CountCompileErrorV2::InvalidClaim {
            field: "object binding identity",
        });
    }
    let layout = image.layout();
    let payload_bytes =
        usize::try_from(layout.total_mapped_bytes).map_err(|_| overflow("payload bytes"))?;
    let rodata_offset =
        usize::try_from(layout.rodata_from_code_start).map_err(|_| overflow("rodata offset"))?;
    if !image.rodata().is_empty()
        || rodata_offset != payload_bytes
        || image.code().len() > rodata_offset
        || rodata_offset
            .checked_sub(image.code().len())
            .is_none_or(|gap| gap >= 16)
    {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "Count image layout",
        });
    }
    enforce_limit(
        "payload bytes",
        limits.max_payload_bytes,
        usize_u64(payload_bytes, "payload bytes")?,
    )?;
    let object_layout = ObjectLayout::new(payload_bytes)?;
    enforce_limit(
        "object bytes",
        limits.max_object_bytes,
        usize_u64(object_layout.object_bytes, "object bytes")?,
    )?;

    let payload_sha256 = hash_payload(image, payload_bytes)?;
    let mut metadata_bytes = encode_metadata(image, binding_identity, payload_sha256, [0; 32])?;
    let compile_identity = compute_compile_identity(metadata_bytes)?;
    metadata_bytes[METADATA_COMPILE_IDENTITY_OFFSET..].copy_from_slice(&compile_identity);
    inspect_count_metadata_v2(&metadata_bytes).map_err(|_| CountCompileErrorV2::InvalidObject {
        at: "self-inspected metadata",
    })?;

    let mut bytes = zeroed_exact(object_layout.object_bytes)
        .map_err(|_| CountCompileErrorV2::AllocationFailed)?;
    if bytes.len() != object_layout.object_bytes || bytes.capacity() != object_layout.object_bytes {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "exact object allocation",
        });
    }
    write_prefix(&mut bytes[..CONTENT_OFFSET], object_layout)?;
    copy_region(&mut bytes, CONTENT_OFFSET, image.code(), "code payload")?;
    copy_region(
        &mut bytes,
        object_layout.metadata_file_offset,
        &metadata_bytes,
        "metadata payload",
    )?;
    write_symbols_and_strings(&mut bytes, object_layout, &compile_identity)?;
    let payload_end = CONTENT_OFFSET
        .checked_add(payload_bytes)
        .ok_or(overflow("self-inspected payload end"))?;
    let object_identity = {
        let inspection = inspect_count_implementation_object_v2(&bytes, limits)?;
        if inspection.metadata_bytes != &metadata_bytes
            || inspection.compile_identity != compile_identity
            || inspection.payload
                != bytes.get(CONTENT_OFFSET..payload_end).ok_or(
                    CountCompileErrorV2::InvalidObject {
                        at: "self-inspected payload",
                    },
                )?
        {
            return Err(CountCompileErrorV2::InvalidObject {
                at: "self-inspection mismatch",
            });
        }
        inspection.object_identity
    };
    Ok(CountImplementationObjectV2 {
        bytes,
        metadata_bytes,
        compile_identity,
        object_identity,
        payload_bytes,
    })
}

/// Strictly inspect a deterministic Count-v2 implementation object.
pub fn inspect_count_implementation_object_v2(
    bytes: &[u8],
    limits: CountObjectLimitsV2,
) -> Result<CountImplementationInspectionV2<'_>, CountCompileErrorV2> {
    if bytes.len() < CONTENT_OFFSET {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "object prefix",
        });
    }
    let payload_bytes = usize::try_from(read_u64(bytes, 144, "payload section size")?)
        .map_err(|_| overflow("payload section size"))?;
    enforce_limit(
        "payload bytes",
        limits.max_payload_bytes,
        usize_u64(payload_bytes, "payload bytes")?,
    )?;
    let layout = ObjectLayout::new(payload_bytes)?;
    enforce_limit(
        "object bytes",
        limits.max_object_bytes,
        usize_u64(bytes.len(), "object bytes")?,
    )?;
    if bytes.len() != layout.object_bytes {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "object length",
        });
    }
    let mut expected_prefix = [0_u8; CONTENT_OFFSET];
    write_prefix(&mut expected_prefix, layout)?;
    if bytes.get(..CONTENT_OFFSET) != Some(expected_prefix.as_slice()) {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "Mach-O prefix",
        });
    }
    let metadata_end = layout
        .metadata_file_offset
        .checked_add(METADATA_BYTES_V2)
        .ok_or(overflow("metadata end"))?;
    let metadata_bytes: &[u8; METADATA_BYTES_V2] = bytes
        .get(layout.metadata_file_offset..metadata_end)
        .and_then(|value| value.try_into().ok())
        .ok_or(CountCompileErrorV2::InvalidObject {
            at: "metadata range",
        })?;
    let metadata = inspect_count_metadata_v2(metadata_bytes).map_err(|_| {
        CountCompileErrorV2::InvalidObject {
            at: "metadata contract",
        }
    })?;
    if usize::try_from(metadata.payload_bytes()).ok() != Some(payload_bytes) {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "metadata payload extent",
        });
    }
    let compile_identity = compute_compile_identity(*metadata_bytes)?;
    if metadata.compile_identity() != &compile_identity {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "compile identity",
        });
    }
    validate_symbols_and_strings(bytes, layout, &compile_identity)?;
    let payload_end = CONTENT_OFFSET
        .checked_add(payload_bytes)
        .ok_or(overflow("payload end"))?;
    let payload =
        bytes
            .get(CONTENT_OFFSET..payload_end)
            .ok_or(CountCompileErrorV2::InvalidObject {
                at: "payload range",
            })?;
    if digest(payload) != *metadata.payload_sha256() {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "payload digest",
        });
    }
    Ok(CountImplementationInspectionV2 {
        object_bytes: bytes.len(),
        payload,
        metadata_bytes,
        metadata,
        compile_identity,
        object_identity: digest(bytes),
    })
}

fn encode_metadata(
    image: &AotCountImageV2,
    binding_identity: [u8; 32],
    payload_sha256: [u8; 32],
    compile_identity: [u8; 32],
) -> Result<[u8; METADATA_BYTES_V2], CountCompileErrorV2> {
    let support = image.support();
    let target = image.target();
    let layout = image.layout();
    let mut bytes = [0_u8; METADATA_BYTES_V2];
    let mut writer = Writer::new(&mut bytes);
    writer.bytes(b"FREOM64\x02")?;
    writer.u16(METADATA_VERSION_V2)?;
    writer.u16(u16::try_from(METADATA_BYTES_V2).expect("fixed metadata width"))?;
    writer.u16(support.backend_version.0)?;
    writer.u16(support.algorithm_version)?;
    writer.u16(support.kir_semantics_version)?;
    writer.u16(support.kir_abi_version)?;
    writer.u16(CALL_ABI_SCHEMA_V2)?;
    writer.u16(support.max_literal_bytes)?;
    writer.u8(COUNT_ABI_KIND_V2)?;
    writer.u8(COUNT_OUTPUT_KIND_V2)?;
    writer.u8(target.architecture)?;
    writer.u8(u8::from(target.little_endian))?;
    writer.u8(target.pointer_width)?;
    writer.u8(target.abi)?;
    writer.u8(COUNT_PLATFORM_MACOS_V2)?;
    writer.u8(STATUS_BITS_V2)?;
    writer.u64(target.features.bits())?;
    writer.u64(support.allowed_features.bits())?;
    writer.u32(layout.total_mapped_bytes)?;
    writer.u32(ENTRY_OFFSET_V2)?;
    writer.u32(u32::try_from(image.code().len()).map_err(|_| overflow("code bytes"))?)?;
    writer.u32(layout.rodata_from_code_start)?;
    writer.u32(u32::try_from(image.rodata().len()).map_err(|_| overflow("rodata bytes"))?)?;
    writer.u32(image.literal_bytes())?;
    writer.bytes(image.source_identity().as_bytes())?;
    writer.bytes(image.artifact_identity().as_bytes())?;
    writer.bytes(&binding_identity)?;
    writer.bytes(&payload_sha256)?;
    writer.bytes(&compile_identity)?;
    if writer.position() != METADATA_BYTES_V2 {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "metadata encoding length",
        });
    }
    Ok(bytes)
}

fn compute_compile_identity(
    mut metadata_bytes: [u8; METADATA_BYTES_V2],
) -> Result<[u8; 32], CountCompileErrorV2> {
    metadata_bytes[METADATA_COMPILE_IDENTITY_OFFSET..].fill(0);
    let mut hasher = Sha256::new();
    hasher.update(COMPILE_IDENTITY_DOMAIN_V2);
    hasher.update(EXPORTED_SYMBOL_SCHEMA_VERSION_V2.to_le_bytes());
    hasher.update(
        u16::try_from(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2)
            .expect("fixed identity width")
            .to_le_bytes(),
    );
    for prefix in [
        COUNT_ENTRY_SYMBOL_PREFIX_V2,
        COUNT_PAYLOAD_SYMBOL_PREFIX_V2,
        COUNT_METADATA_SYMBOL_PREFIX_V2,
    ] {
        hasher.update(
            u16::try_from(prefix.len())
                .map_err(|_| overflow("symbol prefix length"))?
                .to_le_bytes(),
        );
        hasher.update(prefix.as_bytes());
        hasher.update([COUNT_EXPORTED_SYMBOL_N_TYPE_V2]);
    }
    hasher.update(MIN_MACOS_VERSION_V2.to_le_bytes());
    hasher.update(metadata_bytes);
    Ok(hasher.finalize().into())
}

fn hash_payload(
    image: &AotCountImageV2,
    payload_bytes: usize,
) -> Result<[u8; 32], CountCompileErrorV2> {
    let gap = payload_bytes
        .checked_sub(image.code().len())
        .ok_or(CountCompileErrorV2::InvalidObject { at: "payload gap" })?;
    if gap >= 16 {
        return Err(CountCompileErrorV2::InvalidObject { at: "payload gap" });
    }
    let mut hasher = Sha256::new();
    hasher.update(image.code());
    hasher.update(&[0_u8; 16][..gap]);
    hasher.update(image.rodata());
    Ok(hasher.finalize().into())
}

fn write_prefix(prefix: &mut [u8], layout: ObjectLayout) -> Result<(), CountCompileErrorV2> {
    if prefix.len() != CONTENT_OFFSET {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "prefix destination",
        });
    }
    prefix.fill(0);
    let mut writer = Writer::new(prefix);
    writer.u32(MH_MAGIC_64)?;
    writer.u32(CPU_TYPE_ARM64)?;
    writer.u32(CPU_SUBTYPE_ARM64_ALL)?;
    writer.u32(MH_OBJECT)?;
    writer.u32(LOAD_COMMAND_COUNT)?;
    writer.u32(u32_from_usize(LOAD_COMMAND_BYTES, "load command bytes")?)?;
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(LC_SEGMENT_64)?;
    writer.u32(u32_from_usize(
        SEGMENT_WITH_SECTIONS_BYTES,
        "segment command bytes",
    )?)?;
    writer.fixed_name("")?;
    writer.u64(0)?;
    writer.u64(usize_u64(layout.segment_bytes, "segment bytes")?)?;
    writer.u64(usize_u64(CONTENT_OFFSET, "content offset")?)?;
    writer.u64(usize_u64(layout.segment_bytes, "segment file bytes")?)?;
    writer.u32(VM_PROT_RWX)?;
    writer.u32(VM_PROT_RWX)?;
    writer.u32(SECTIONS)?;
    writer.u32(0)?;
    writer.section(
        "__fre_image",
        "__TEXT",
        0,
        usize_u64(layout.payload_bytes, "payload section bytes")?,
        u32_from_usize(CONTENT_OFFSET, "payload file offset")?,
        4,
        PAYLOAD_SECTION_FLAGS,
    )?;
    writer.section(
        "__fre_meta",
        "__FRE_CONST",
        usize_u64(layout.metadata_address, "metadata address")?,
        usize_u64(METADATA_BYTES_V2, "metadata bytes")?,
        u32_from_usize(layout.metadata_file_offset, "metadata file offset")?,
        3,
        METADATA_SECTION_FLAGS,
    )?;

    writer.u32(LC_BUILD_VERSION)?;
    writer.u32(u32_from_usize(
        BUILD_VERSION_COMMAND_BYTES,
        "build version command bytes",
    )?)?;
    writer.u32(PLATFORM_MACOS_LOAD_COMMAND)?;
    writer.u32(MIN_MACOS_VERSION_V2)?;
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(LC_SYMTAB)?;
    writer.u32(u32_from_usize(
        SYMTAB_COMMAND_BYTES,
        "symbol command bytes",
    )?)?;
    writer.u32(u32_from_usize(
        layout.symbol_file_offset,
        "symbol file offset",
    )?)?;
    writer.u32(u32::try_from(SYMBOLS).expect("small symbol count"))?;
    writer.u32(u32_from_usize(
        layout.string_file_offset,
        "string file offset",
    )?)?;
    writer.u32(u32_from_usize(layout.string_bytes, "string bytes")?)?;

    writer.u32(LC_DYSYMTAB)?;
    writer.u32(u32_from_usize(
        DYSYMTAB_COMMAND_BYTES,
        "dynamic symbol command bytes",
    )?)?;
    for value in [0, 0, 0, 3, 3, 0] {
        writer.u32(value)?;
    }
    for _ in 0..12 {
        writer.u32(0)?;
    }
    if writer.position() != MACH_HEADER_BYTES + LOAD_COMMAND_BYTES {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "load command length",
        });
    }
    Ok(())
}

fn write_symbols_and_strings(
    bytes: &mut [u8],
    layout: ObjectLayout,
    compile_identity: &[u8; 32],
) -> Result<(), CountCompileErrorV2> {
    let specs = symbol_specs(compile_identity)?;
    let symbol_end = layout
        .symbol_file_offset
        .checked_add(NLIST_64_BYTES * SYMBOLS)
        .ok_or(overflow("symbol table end"))?;
    let mut writer = Writer::new(bytes.get_mut(layout.symbol_file_offset..symbol_end).ok_or(
        CountCompileErrorV2::InvalidObject {
            at: "symbol table destination",
        },
    )?);
    let mut string_index = 4_usize;
    for spec in specs {
        writer.u32(u32_from_usize(string_index, "string index")?)?;
        writer.u8(COUNT_EXPORTED_SYMBOL_N_TYPE_V2)?;
        writer.u8(spec.section)?;
        writer.u16(0)?;
        writer.u64(symbol_value(spec, layout)?)?;
        string_index = string_index
            .checked_add(MACH_EXTERNAL_PREFIX_BYTES)
            .and_then(|value| value.checked_add(spec.name.as_bytes().len()))
            .and_then(|value| value.checked_add(SYMBOL_TERMINATOR_BYTES))
            .ok_or(overflow("string index"))?;
    }
    if writer.position() != NLIST_64_BYTES * SYMBOLS {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "symbol table length",
        });
    }
    let string_end = layout
        .string_file_offset
        .checked_add(layout.string_bytes)
        .ok_or(overflow("string table end"))?;
    let string_table = bytes.get_mut(layout.string_file_offset..string_end).ok_or(
        CountCompileErrorV2::InvalidObject {
            at: "string table destination",
        },
    )?;
    let mut writer = Writer::new(string_table);
    writer.u32(0)?;
    for spec in specs {
        writer.u8(b'_')?;
        writer.bytes(spec.name.as_bytes())?;
        writer.u8(0)?;
    }
    Ok(())
}

fn validate_symbols_and_strings(
    bytes: &[u8],
    layout: ObjectLayout,
    compile_identity: &[u8; 32],
) -> Result<(), CountCompileErrorV2> {
    let mut expected_symbols = [0_u8; NLIST_64_BYTES * SYMBOLS];
    let mut expected_strings = [0_u8; MAX_STRING_TABLE_BYTES];
    if layout.string_bytes > expected_strings.len() {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "string table inspection bound",
        });
    }
    let specs = symbol_specs(compile_identity)?;
    let mut writer = Writer::new(&mut expected_symbols);
    let mut string_index = 4_usize;
    for spec in specs {
        writer.u32(u32_from_usize(string_index, "string index")?)?;
        writer.u8(COUNT_EXPORTED_SYMBOL_N_TYPE_V2)?;
        writer.u8(spec.section)?;
        writer.u16(0)?;
        writer.u64(symbol_value(spec, layout)?)?;
        string_index = string_index
            .checked_add(MACH_EXTERNAL_PREFIX_BYTES)
            .and_then(|value| value.checked_add(spec.name.as_bytes().len()))
            .and_then(|value| value.checked_add(SYMBOL_TERMINATOR_BYTES))
            .ok_or(overflow("string index"))?;
    }
    let mut writer = Writer::new(&mut expected_strings[..layout.string_bytes]);
    writer.u32(0)?;
    for spec in specs {
        writer.u8(b'_')?;
        writer.bytes(spec.name.as_bytes())?;
        writer.u8(0)?;
    }
    let symbol_end = layout
        .symbol_file_offset
        .checked_add(expected_symbols.len())
        .ok_or(overflow("symbol inspection end"))?;
    let string_end = layout
        .string_file_offset
        .checked_add(layout.string_bytes)
        .ok_or(overflow("string inspection end"))?;
    let actual_symbols = bytes.get(layout.symbol_file_offset..symbol_end).ok_or(
        CountCompileErrorV2::InvalidObject {
            at: "symbol table range",
        },
    )?;
    let actual_strings = bytes.get(layout.string_file_offset..string_end).ok_or(
        CountCompileErrorV2::InvalidObject {
            at: "string table range",
        },
    )?;
    if actual_symbols != expected_symbols
        || actual_strings != &expected_strings[..layout.string_bytes]
    {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "symbol or string table",
        });
    }
    Ok(())
}

fn symbol_value(
    specification: SymbolSpec,
    layout: ObjectLayout,
) -> Result<u64, CountCompileErrorV2> {
    match specification.location {
        SymbolLocation::Entry | SymbolLocation::Payload => Ok(u64::from(ENTRY_OFFSET_V2)),
        SymbolLocation::Metadata => usize_u64(layout.metadata_address, "metadata symbol value"),
    }
}

fn count_symbol_string_bytes() -> Result<usize, CountCompileErrorV2> {
    [
        COUNT_ENTRY_SYMBOL_PREFIX_V2,
        COUNT_PAYLOAD_SYMBOL_PREFIX_V2,
        COUNT_METADATA_SYMBOL_PREFIX_V2,
    ]
    .into_iter()
    .try_fold(4_usize, |total, prefix| {
        total
            .checked_add(MACH_EXTERNAL_PREFIX_BYTES)
            .and_then(|value| value.checked_add(prefix.len()))
            .and_then(|value| value.checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2))
            .and_then(|value| value.checked_add(SYMBOL_TERMINATOR_BYTES))
            .ok_or(overflow("string table bytes"))
    })
}

fn copy_region(
    destination: &mut [u8],
    offset: usize,
    source: &[u8],
    at: &'static str,
) -> Result<(), CountCompileErrorV2> {
    let end = offset
        .checked_add(source.len())
        .ok_or(overflow("copy region"))?;
    destination
        .get_mut(offset..end)
        .ok_or(CountCompileErrorV2::InvalidObject { at })?
        .copy_from_slice(source);
    Ok(())
}

struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), CountCompileErrorV2> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or(overflow("writer offset"))?;
        self.bytes
            .get_mut(self.position..end)
            .ok_or(CountCompileErrorV2::InvalidObject {
                at: "writer destination",
            })?
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

    fn fixed_name(&mut self, name: &str) -> Result<(), CountCompileErrorV2> {
        if name.len() > 16 {
            return Err(CountCompileErrorV2::InvalidObject {
                at: "fixed Mach-O name",
            });
        }
        let mut bytes = [0_u8; 16];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        self.bytes(&bytes)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "arguments mirror the fixed Mach-O section_64 wire record"
    )]
    fn section(
        &mut self,
        section: &str,
        segment: &str,
        address: u64,
        size: u64,
        offset: u32,
        alignment_power: u32,
        flags: u32,
    ) -> Result<(), CountCompileErrorV2> {
        self.fixed_name(section)?;
        self.fixed_name(segment)?;
        self.u64(address)?;
        self.u64(size)?;
        self.u32(offset)?;
        self.u32(alignment_power)?;
        self.u32(0)?;
        self.u32(0)?;
        self.u32(flags)?;
        self.u32(0)?;
        self.u32(0)?;
        self.u32(0)
    }

    const fn position(&self) -> usize {
        self.position
    }
}

fn read_u64(bytes: &[u8], offset: usize, at: &'static str) -> Result<u64, CountCompileErrorV2> {
    let end = offset.checked_add(8).ok_or(overflow("reader offset"))?;
    let value: [u8; 8] = bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or(CountCompileErrorV2::InvalidObject { at })?;
    Ok(u64::from_le_bytes(value))
}

fn align_up(
    value: usize,
    alignment: usize,
    at: &'static str,
) -> Result<usize, CountCompileErrorV2> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(CountCompileErrorV2::ArithmeticOverflow { at })?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(CountCompileErrorV2::ArithmeticOverflow { at })
}

fn enforce_limit(
    resource: &'static str,
    limit: u64,
    required: u64,
) -> Result<(), CountCompileErrorV2> {
    if required <= limit {
        Ok(())
    } else {
        Err(CountCompileErrorV2::ResourceLimit {
            resource,
            limit,
            required,
        })
    }
}

fn u32_from_usize(value: usize, at: &'static str) -> Result<u32, CountCompileErrorV2> {
    u32::try_from(value).map_err(|_| CountCompileErrorV2::ArithmeticOverflow { at })
}

fn usize_u64(value: usize, at: &'static str) -> Result<u64, CountCompileErrorV2> {
    u64::try_from(value).map_err(|_| CountCompileErrorV2::ArithmeticOverflow { at })
}

const fn overflow(at: &'static str) -> CountCompileErrorV2 {
    CountCompileErrorV2::ArithmeticOverflow { at }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

const fn lower_hex(nibble: u8) -> u8 {
    match nibble {
        0 => b'0',
        1 => b'1',
        2 => b'2',
        3 => b'3',
        4 => b'4',
        5 => b'5',
        6 => b'6',
        7 => b'7',
        8 => b'8',
        9 => b'9',
        10 => b'a',
        11 => b'b',
        12 => b'c',
        13 => b'd',
        14 => b'e',
        _ => b'f',
    }
}
