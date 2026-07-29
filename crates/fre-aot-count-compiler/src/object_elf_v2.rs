//! Qualification-only ELF64/AArch64 wrapper for a fresh Count-v2 control.
//!
//! Count-v2's immutable metadata and compile-symbol identity are preserved
//! byte-for-byte.  In particular, the legacy metadata retains its original
//! macOS platform discriminator and therefore cannot become Linux production
//! authority.  The wrapper exists solely to link the same audited v2 payload
//! into Linux qualification binaries beside Count-v3 and portable controls.

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

use crate::{CountCompileErrorV2, CountObjectLimitsV2};

const COMPILE_IDENTITY_DOMAIN_V2: &[u8] = b"FRE-AOT-MACHO-COUNT-COMPILE\0\x02";
const MIN_MACOS_VERSION_V2: u32 = 0x000b_0000;
const METADATA_COMPILE_IDENTITY_OFFSET_V2: usize = 200;
const SYMBOLS: usize = 3;
const SYMBOL_NAME_STORAGE_BYTES: usize = 112;
const MAX_STRING_TABLE_BYTES: usize = 384;

const ELF_HEADER_BYTES: usize = 64;
const ELF_SECTION_HEADER_BYTES: usize = 64;
const ELF_SECTION_HEADERS: usize = 6;
const ELF_SYMBOL_BYTES: usize = 24;
const ELF_SYMBOLS_WITH_NULL: usize = SYMBOLS + 1;
const ELF_SHSTRTAB: &[u8] = b"\0.text\0.fre.meta\0.symtab\0.strtab\0.shstrtab\0";
const ELF_EM_AARCH64: u16 = 183;
const ELF_STV_HIDDEN: u8 = 2;

/// One deterministic qualification-only v2 ELF object.
#[derive(Debug, Eq, PartialEq)]
pub struct CountImplementationObjectElfV2 {
    bytes: Vec<u8>,
    metadata_bytes: [u8; METADATA_BYTES_V2],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    payload_bytes: usize,
}

impl CountImplementationObjectElfV2 {
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
}

/// Strict allocation-free view of a qualification-only v2 ELF object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountImplementationInspectionElfV2<'a> {
    object_bytes: usize,
    payload: &'a [u8],
    metadata_bytes: &'a [u8; METADATA_BYTES_V2],
    metadata: ClaimedCountMetadataV2,
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
}

impl<'a> CountImplementationInspectionElfV2<'a> {
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
struct Layout {
    payload_offset: usize,
    payload_bytes: usize,
    metadata_offset: usize,
    symtab_offset: usize,
    strtab_offset: usize,
    strtab_bytes: usize,
    shstrtab_offset: usize,
    section_header_offset: usize,
    object_bytes: usize,
}

impl Layout {
    fn new(payload_bytes: usize) -> Result<Self, CountCompileErrorV2> {
        let payload_offset = ELF_HEADER_BYTES;
        let metadata_offset = align_up(
            payload_offset
                .checked_add(payload_bytes)
                .ok_or_else(|| overflow("v2 ELF payload end"))?,
            8,
            "v2 ELF metadata offset",
        )?;
        let symtab_offset = align_up(
            metadata_offset
                .checked_add(METADATA_BYTES_V2)
                .ok_or_else(|| overflow("v2 ELF metadata end"))?,
            8,
            "v2 ELF symtab offset",
        )?;
        let strtab_offset = symtab_offset
            .checked_add(ELF_SYMBOL_BYTES * ELF_SYMBOLS_WITH_NULL)
            .ok_or_else(|| overflow("v2 ELF strtab offset"))?;
        let strtab_bytes = symbol_string_bytes()?;
        let shstrtab_offset = strtab_offset
            .checked_add(strtab_bytes)
            .ok_or_else(|| overflow("v2 ELF shstrtab offset"))?;
        let section_header_offset = align_up(
            shstrtab_offset
                .checked_add(ELF_SHSTRTAB.len())
                .ok_or_else(|| overflow("v2 ELF shstrtab end"))?,
            8,
            "v2 ELF section header offset",
        )?;
        let object_bytes = section_header_offset
            .checked_add(ELF_SECTION_HEADER_BYTES * ELF_SECTION_HEADERS)
            .ok_or_else(|| overflow("v2 ELF object bytes"))?;
        Ok(Self {
            payload_offset,
            payload_bytes,
            metadata_offset,
            symtab_offset,
            strtab_offset,
            strtab_bytes,
            shstrtab_offset,
            section_header_offset,
            object_bytes,
        })
    }
}

/// Publish a linkable Linux qualification control while preserving every v2
/// metadata byte and v2 identity-suffixed symbol name.
pub fn publish_count_implementation_object_elf_v2(
    image: &AotCountImageV2,
    binding_identity: [u8; 32],
    limits: CountObjectLimitsV2,
) -> Result<CountImplementationObjectElfV2, CountCompileErrorV2> {
    if binding_identity == [0; 32] {
        return Err(CountCompileErrorV2::InvalidClaim {
            field: "object binding identity",
        });
    }
    let payload_bytes = usize::try_from(image.layout().total_mapped_bytes)
        .map_err(|_| overflow("v2 ELF payload bytes"))?;
    if !image.rodata().is_empty()
        || usize::try_from(image.layout().rodata_from_code_start).ok() != Some(payload_bytes)
        || image.code().len() > payload_bytes
        || payload_bytes
            .checked_sub(image.code().len())
            .is_none_or(|gap| gap >= 16)
    {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF image layout",
        });
    }
    enforce_limit(
        "payload bytes",
        limits.max_payload_bytes,
        usize_u64(payload_bytes, "v2 ELF payload bytes")?,
    )?;
    let layout = Layout::new(payload_bytes)?;
    enforce_limit(
        "object bytes",
        limits.max_object_bytes,
        usize_u64(layout.object_bytes, "v2 ELF object bytes")?,
    )?;
    let payload_sha256 = hash_payload(image, payload_bytes)?;
    let mut metadata_bytes = encode_metadata(image, binding_identity, payload_sha256, [0; 32])?;
    let compile_identity = compute_compile_identity(metadata_bytes)?;
    metadata_bytes[METADATA_COMPILE_IDENTITY_OFFSET_V2..].copy_from_slice(&compile_identity);
    inspect_count_metadata_v2(&metadata_bytes).map_err(|_| CountCompileErrorV2::InvalidObject {
        at: "v2 ELF self-inspected metadata",
    })?;

    let mut bytes =
        zeroed_exact(layout.object_bytes).map_err(|_| CountCompileErrorV2::AllocationFailed)?;
    write_header(&mut bytes[..ELF_HEADER_BYTES], layout)?;
    copy_region(
        &mut bytes,
        layout.payload_offset,
        image.code(),
        "v2 ELF code",
    )?;
    copy_region(
        &mut bytes,
        layout.metadata_offset,
        &metadata_bytes,
        "v2 ELF metadata",
    )?;
    write_symbols(&mut bytes, layout, &compile_identity)?;
    copy_region(
        &mut bytes,
        layout.shstrtab_offset,
        ELF_SHSTRTAB,
        "v2 ELF shstrtab",
    )?;
    write_section_headers(&mut bytes[layout.section_header_offset..], layout)?;
    let inspection = inspect_count_implementation_object_elf_v2(&bytes, limits)?;
    if inspection.metadata_bytes != &metadata_bytes
        || inspection.compile_identity != compile_identity
        || inspection.payload.len() != payload_bytes
    {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF self-inspection mismatch",
        });
    }
    Ok(CountImplementationObjectElfV2 {
        object_identity: inspection.object_identity,
        bytes,
        metadata_bytes,
        compile_identity,
        payload_bytes,
    })
}

/// Strictly inspect the deterministic qualification-only v2 ELF wrapper.
pub fn inspect_count_implementation_object_elf_v2(
    bytes: &[u8],
    limits: CountObjectLimitsV2,
) -> Result<CountImplementationInspectionElfV2<'_>, CountCompileErrorV2> {
    if bytes.len() < ELF_HEADER_BYTES || bytes[..4] != *b"\x7fELF" {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF header",
        });
    }
    let section_header_offset =
        usize::try_from(read_u64(bytes, 40, "v2 ELF section header offset")?)
            .map_err(|_| overflow("v2 ELF section header offset"))?;
    let metadata_section = section_header_offset
        .checked_add(ELF_SECTION_HEADER_BYTES * 2)
        .ok_or_else(|| overflow("v2 ELF metadata section"))?;
    let metadata_offset = usize::try_from(read_u64(
        bytes,
        metadata_section + 24,
        "v2 ELF metadata offset",
    )?)
    .map_err(|_| overflow("v2 ELF metadata offset"))?;
    let metadata_bytes: &[u8; METADATA_BYTES_V2] = bytes
        .get(
            metadata_offset
                ..metadata_offset
                    .checked_add(METADATA_BYTES_V2)
                    .ok_or_else(|| overflow("v2 ELF metadata end"))?,
        )
        .and_then(|value| value.try_into().ok())
        .ok_or(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF metadata range",
        })?;
    let metadata = inspect_count_metadata_v2(metadata_bytes).map_err(|_| {
        CountCompileErrorV2::InvalidObject {
            at: "v2 ELF metadata contract",
        }
    })?;
    let payload_bytes =
        usize::try_from(metadata.payload_bytes()).map_err(|_| overflow("v2 ELF payload bytes"))?;
    enforce_limit(
        "payload bytes",
        limits.max_payload_bytes,
        usize_u64(payload_bytes, "v2 ELF payload bytes")?,
    )?;
    let layout = Layout::new(payload_bytes)?;
    enforce_limit(
        "object bytes",
        limits.max_object_bytes,
        usize_u64(bytes.len(), "v2 ELF object bytes")?,
    )?;
    if bytes.len() != layout.object_bytes
        || section_header_offset != layout.section_header_offset
        || metadata_offset != layout.metadata_offset
        || read_u64(bytes, metadata_section + 32, "v2 ELF metadata size")?
            != u64::try_from(METADATA_BYTES_V2).expect("fixed v2 metadata width")
    {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF canonical layout",
        });
    }
    let mut expected_header = [0_u8; ELF_HEADER_BYTES];
    write_header(&mut expected_header, layout)?;
    let mut expected_sections = [0_u8; ELF_SECTION_HEADER_BYTES * ELF_SECTION_HEADERS];
    write_section_headers(&mut expected_sections, layout)?;
    if bytes[..ELF_HEADER_BYTES] != expected_header
        || bytes[layout.section_header_offset..] != expected_sections
        || bytes.get(layout.shstrtab_offset..layout.shstrtab_offset + ELF_SHSTRTAB.len())
            != Some(ELF_SHSTRTAB)
    {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF canonical tables",
        });
    }
    let compile_identity = compute_compile_identity(*metadata_bytes)?;
    if metadata.compile_identity() != &compile_identity {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF compile identity",
        });
    }
    validate_symbols(bytes, layout, &compile_identity)?;
    validate_zero_padding(bytes, layout)?;
    let payload = bytes
        .get(layout.payload_offset..layout.payload_offset + payload_bytes)
        .ok_or(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF payload range",
        })?;
    let payload_digest: [u8; 32] = Sha256::digest(payload).into();
    if &payload_digest != metadata.payload_sha256() {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF payload digest",
        });
    }
    let code_bytes =
        usize::try_from(metadata.code_bytes()).map_err(|_| overflow("v2 ELF code bytes"))?;
    if payload
        .get(code_bytes..)
        .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
    {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF payload padding",
        });
    }
    Ok(CountImplementationInspectionElfV2 {
        object_bytes: bytes.len(),
        payload,
        metadata_bytes,
        metadata,
        compile_identity,
        object_identity: Sha256::digest(bytes).into(),
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
    writer.u16(u16::try_from(METADATA_BYTES_V2).expect("fixed v2 metadata width"))?;
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
    writer.u32(
        u32::try_from(image.code().len()).map_err(|_| overflow("v2 ELF metadata code bytes"))?,
    )?;
    writer.u32(layout.rodata_from_code_start)?;
    writer.u32(
        u32::try_from(image.rodata().len())
            .map_err(|_| overflow("v2 ELF metadata rodata bytes"))?,
    )?;
    writer.u32(image.literal_bytes())?;
    writer.bytes(image.source_identity().as_bytes())?;
    writer.bytes(image.artifact_identity().as_bytes())?;
    writer.bytes(&binding_identity)?;
    writer.bytes(&payload_sha256)?;
    writer.bytes(&compile_identity)?;
    if writer.position() != METADATA_BYTES_V2 {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF metadata encoding length",
        });
    }
    Ok(bytes)
}

fn compute_compile_identity(
    mut metadata: [u8; METADATA_BYTES_V2],
) -> Result<[u8; 32], CountCompileErrorV2> {
    metadata[METADATA_COMPILE_IDENTITY_OFFSET_V2..].fill(0);
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
                .map_err(|_| overflow("v2 ELF symbol prefix length"))?
                .to_le_bytes(),
        );
        hasher.update(prefix.as_bytes());
        hasher.update([COUNT_EXPORTED_SYMBOL_N_TYPE_V2]);
    }
    hasher.update(MIN_MACOS_VERSION_V2.to_le_bytes());
    hasher.update(metadata);
    Ok(hasher.finalize().into())
}

fn hash_payload(
    image: &AotCountImageV2,
    payload_bytes: usize,
) -> Result<[u8; 32], CountCompileErrorV2> {
    let gap = payload_bytes.checked_sub(image.code().len()).ok_or(
        CountCompileErrorV2::InvalidObject {
            at: "v2 ELF payload gap",
        },
    )?;
    if gap >= 16 {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF payload gap",
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(image.code());
    hasher.update(&[0_u8; 16][..gap]);
    hasher.update(image.rodata());
    Ok(hasher.finalize().into())
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
            .ok_or_else(|| overflow("v2 ELF symbol name length"))?;
        if len > SYMBOL_NAME_STORAGE_BYTES {
            return Err(CountCompileErrorV2::InvalidObject {
                at: "v2 ELF symbol name storage",
            });
        }
        let mut bytes = [0_u8; SYMBOL_NAME_STORAGE_BYTES];
        bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
        let mut cursor = prefix.len();
        for byte in identity {
            bytes[cursor] = lower_hex(byte >> 4);
            bytes[cursor + 1] = lower_hex(byte & 0x0f);
            cursor += 2;
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
    location: SymbolLocation,
}

fn symbol_specs(identity: &[u8; 32]) -> Result<[SymbolSpec; SYMBOLS], CountCompileErrorV2> {
    let mut specs = [
        SymbolSpec {
            name: SymbolName::new(COUNT_ENTRY_SYMBOL_PREFIX_V2, identity)?,
            location: SymbolLocation::Entry,
        },
        SymbolSpec {
            name: SymbolName::new(COUNT_PAYLOAD_SYMBOL_PREFIX_V2, identity)?,
            location: SymbolLocation::Payload,
        },
        SymbolSpec {
            name: SymbolName::new(COUNT_METADATA_SYMBOL_PREFIX_V2, identity)?,
            location: SymbolLocation::Metadata,
        },
    ];
    specs.sort_unstable_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    Ok(specs)
}

fn write_header(header: &mut [u8], layout: Layout) -> Result<(), CountCompileErrorV2> {
    header.fill(0);
    let mut writer = Writer::new(header);
    writer.bytes(b"\x7fELF")?;
    writer.u8(2)?;
    writer.u8(1)?;
    writer.u8(1)?;
    writer.u8(0)?;
    writer.bytes(&[0; 8])?;
    writer.u16(1)?;
    writer.u16(ELF_EM_AARCH64)?;
    writer.u32(1)?;
    writer.u64(0)?;
    writer.u64(0)?;
    writer.u64(usize_u64(
        layout.section_header_offset,
        "v2 ELF section header offset",
    )?)?;
    writer.u32(0)?;
    writer.u16(u16::try_from(ELF_HEADER_BYTES).expect("fixed ELF header"))?;
    writer.u16(0)?;
    writer.u16(0)?;
    writer.u16(u16::try_from(ELF_SECTION_HEADER_BYTES).expect("fixed section header"))?;
    writer.u16(u16::try_from(ELF_SECTION_HEADERS).expect("small section count"))?;
    writer.u16(5)?;
    if writer.position() != ELF_HEADER_BYTES {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF header length",
        });
    }
    Ok(())
}

fn write_section_headers(
    destination: &mut [u8],
    layout: Layout,
) -> Result<(), CountCompileErrorV2> {
    if destination.len() != ELF_SECTION_HEADER_BYTES * ELF_SECTION_HEADERS {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF section headers destination",
        });
    }
    destination.fill(0);
    let mut writer = Writer::new(destination);
    writer.bytes(&[0; ELF_SECTION_HEADER_BYTES])?;
    writer.elf_section(
        1,
        1,
        0x6,
        layout.payload_offset,
        layout.payload_bytes,
        0,
        0,
        16,
        0,
    )?;
    writer.elf_section(
        7,
        1,
        0x2,
        layout.metadata_offset,
        METADATA_BYTES_V2,
        0,
        0,
        8,
        0,
    )?;
    writer.elf_section(
        17,
        2,
        0,
        layout.symtab_offset,
        ELF_SYMBOL_BYTES * ELF_SYMBOLS_WITH_NULL,
        4,
        1,
        8,
        ELF_SYMBOL_BYTES,
    )?;
    writer.elf_section(
        25,
        3,
        0,
        layout.strtab_offset,
        layout.strtab_bytes,
        0,
        0,
        1,
        0,
    )?;
    writer.elf_section(
        33,
        3,
        0,
        layout.shstrtab_offset,
        ELF_SHSTRTAB.len(),
        0,
        0,
        1,
        0,
    )?;
    Ok(())
}

fn write_symbols(
    bytes: &mut [u8],
    layout: Layout,
    compile_identity: &[u8; 32],
) -> Result<(), CountCompileErrorV2> {
    let specs = symbol_specs(compile_identity)?;
    let symtab_end = layout.symtab_offset + ELF_SYMBOL_BYTES * ELF_SYMBOLS_WITH_NULL;
    let mut writer = Writer::new(&mut bytes[layout.symtab_offset..symtab_end]);
    writer.bytes(&[0; ELF_SYMBOL_BYTES])?;
    let mut string_index = 1_usize;
    for spec in specs {
        writer.u32(u32_from_usize(string_index, "v2 ELF string index")?)?;
        writer.u8(match spec.location {
            SymbolLocation::Entry => 0x12,
            SymbolLocation::Payload | SymbolLocation::Metadata => 0x11,
        })?;
        writer.u8(ELF_STV_HIDDEN)?;
        writer.u16(match spec.location {
            SymbolLocation::Entry | SymbolLocation::Payload => 1,
            SymbolLocation::Metadata => 2,
        })?;
        writer.u64(0)?;
        writer.u64(match spec.location {
            SymbolLocation::Entry => 0,
            SymbolLocation::Payload => usize_u64(layout.payload_bytes, "v2 ELF payload size")?,
            SymbolLocation::Metadata => usize_u64(METADATA_BYTES_V2, "v2 ELF metadata size")?,
        })?;
        string_index += spec.name.as_bytes().len() + 1;
    }
    let mut writer =
        Writer::new(&mut bytes[layout.strtab_offset..layout.strtab_offset + layout.strtab_bytes]);
    writer.u8(0)?;
    for spec in specs {
        writer.bytes(spec.name.as_bytes())?;
        writer.u8(0)?;
    }
    Ok(())
}

fn validate_symbols(
    bytes: &[u8],
    layout: Layout,
    compile_identity: &[u8; 32],
) -> Result<(), CountCompileErrorV2> {
    let mut expected_symbols = [0_u8; ELF_SYMBOL_BYTES * ELF_SYMBOLS_WITH_NULL];
    let mut expected_strings = [0_u8; MAX_STRING_TABLE_BYTES];
    if layout.strtab_bytes > expected_strings.len() {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF string inspection bound",
        });
    }
    let specs = symbol_specs(compile_identity)?;
    let mut writer = Writer::new(&mut expected_symbols);
    writer.bytes(&[0; ELF_SYMBOL_BYTES])?;
    let mut string_index = 1_usize;
    for spec in specs {
        writer.u32(u32_from_usize(string_index, "v2 ELF string index")?)?;
        writer.u8(match spec.location {
            SymbolLocation::Entry => 0x12,
            SymbolLocation::Payload | SymbolLocation::Metadata => 0x11,
        })?;
        writer.u8(ELF_STV_HIDDEN)?;
        writer.u16(match spec.location {
            SymbolLocation::Entry | SymbolLocation::Payload => 1,
            SymbolLocation::Metadata => 2,
        })?;
        writer.u64(0)?;
        writer.u64(match spec.location {
            SymbolLocation::Entry => 0,
            SymbolLocation::Payload => usize_u64(layout.payload_bytes, "v2 ELF payload size")?,
            SymbolLocation::Metadata => usize_u64(METADATA_BYTES_V2, "v2 ELF metadata size")?,
        })?;
        string_index += spec.name.as_bytes().len() + 1;
    }
    let mut writer = Writer::new(&mut expected_strings[..layout.strtab_bytes]);
    writer.u8(0)?;
    for spec in specs {
        writer.bytes(spec.name.as_bytes())?;
        writer.u8(0)?;
    }
    if bytes.get(layout.symtab_offset..layout.symtab_offset + expected_symbols.len())
        != Some(expected_symbols.as_slice())
        || bytes.get(layout.strtab_offset..layout.strtab_offset + layout.strtab_bytes)
            != Some(&expected_strings[..layout.strtab_bytes])
    {
        return Err(CountCompileErrorV2::InvalidObject {
            at: "v2 ELF symbols",
        });
    }
    Ok(())
}

fn validate_zero_padding(bytes: &[u8], layout: Layout) -> Result<(), CountCompileErrorV2> {
    let payload_end = layout.payload_offset + layout.payload_bytes;
    let metadata_end = layout.metadata_offset + METADATA_BYTES_V2;
    let shstrtab_end = layout.shstrtab_offset + ELF_SHSTRTAB.len();
    for range in [
        payload_end..layout.metadata_offset,
        metadata_end..layout.symtab_offset,
        shstrtab_end..layout.section_header_offset,
    ] {
        if bytes[range].iter().any(|byte| *byte != 0) {
            return Err(CountCompileErrorV2::InvalidObject {
                at: "v2 ELF noncanonical padding",
            });
        }
    }
    Ok(())
}

fn symbol_string_bytes() -> Result<usize, CountCompileErrorV2> {
    [
        COUNT_ENTRY_SYMBOL_PREFIX_V2,
        COUNT_PAYLOAD_SYMBOL_PREFIX_V2,
        COUNT_METADATA_SYMBOL_PREFIX_V2,
    ]
    .into_iter()
    .try_fold(1_usize, |total, prefix| {
        total
            .checked_add(prefix.len())
            .and_then(|value| value.checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| overflow("v2 ELF string bytes"))
    })
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
            .ok_or_else(|| overflow("v2 ELF writer offset"))?;
        self.bytes
            .get_mut(self.position..end)
            .ok_or(CountCompileErrorV2::InvalidObject {
                at: "v2 ELF writer destination",
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

    #[allow(
        clippy::too_many_arguments,
        reason = "arguments mirror the fixed ELF64 section-header wire record"
    )]
    fn elf_section(
        &mut self,
        name: u32,
        section_type: u32,
        flags: u64,
        offset: usize,
        size: usize,
        link: u32,
        info: u32,
        alignment: u64,
        entry_size: usize,
    ) -> Result<(), CountCompileErrorV2> {
        self.u32(name)?;
        self.u32(section_type)?;
        self.u64(flags)?;
        self.u64(0)?;
        self.u64(usize_u64(offset, "v2 ELF section offset")?)?;
        self.u64(usize_u64(size, "v2 ELF section size")?)?;
        self.u32(link)?;
        self.u32(info)?;
        self.u64(alignment)?;
        self.u64(usize_u64(entry_size, "v2 ELF section entry size")?)
    }

    const fn position(&self) -> usize {
        self.position
    }
}

fn copy_region(
    destination: &mut [u8],
    offset: usize,
    source: &[u8],
    at: &'static str,
) -> Result<(), CountCompileErrorV2> {
    let end = offset
        .checked_add(source.len())
        .ok_or_else(|| overflow("v2 ELF copy region"))?;
    destination
        .get_mut(offset..end)
        .ok_or(CountCompileErrorV2::InvalidObject { at })?
        .copy_from_slice(source);
    Ok(())
}

fn read_u64(bytes: &[u8], offset: usize, at: &'static str) -> Result<u64, CountCompileErrorV2> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| overflow("v2 ELF reader offset"))?;
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
