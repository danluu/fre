use fre_aot_aarch64::{AotCountImageV3, AotCountMappedMetadataV3};
use fre_aot_count_contract::v3::{
    AOT_COUNT_AUDITOR_VERSION_V3, CALL_ABI_SCHEMA_V3, COUNT_ABI_KIND_V3,
    COUNT_ENTRY_SYMBOL_PREFIX_V3, COUNT_METADATA_SYMBOL_PREFIX_V3, COUNT_OUTPUT_KIND_V3,
    COUNT_PAYLOAD_SYMBOL_PREFIX_V3, ClaimedCountMetadataV3, CountObjectFormatV3, ENTRY_OFFSET_V3,
    EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V3, EXPORTED_SYMBOL_SCHEMA_VERSION_V3, METADATA_BYTES_V3,
    METADATA_COMPILE_IDENTITY_OFFSET_V3, METADATA_VERSION_V3, STATUS_BITS_V3,
    compute_count_target_identity_v3, inspect_count_metadata_v3,
};
use fre_exact_alloc::zeroed_exact;
use sha2::{Digest, Sha256};

use crate::CountCompileErrorV3;

const COMPILE_IDENTITY_DOMAIN_V3: &[u8] = b"FRE-AOT-COUNT-V3-COMPILE\0\x03";
const SYMBOLS: usize = 3;
const SYMBOL_NAME_STORAGE_BYTES: usize = 112;
const MAX_STRING_TABLE_BYTES: usize = 384;

const MACH_CONTENT_OFFSET: usize = 400;
const MACH_HEADER_BYTES: usize = 32;
const MACH_SEGMENT_COMMAND_BYTES: usize = 72;
const MACH_SECTION_COMMAND_BYTES: usize = 80;
const MACH_SEGMENT_WITH_SECTIONS_BYTES: usize =
    MACH_SEGMENT_COMMAND_BYTES + (MACH_SECTION_COMMAND_BYTES * 2);
const MACH_BUILD_VERSION_COMMAND_BYTES: usize = 24;
const MACH_SYMTAB_COMMAND_BYTES: usize = 24;
const MACH_DYSYMTAB_COMMAND_BYTES: usize = 80;
const MACH_LOAD_COMMAND_BYTES: usize = MACH_SEGMENT_WITH_SECTIONS_BYTES
    + MACH_BUILD_VERSION_COMMAND_BYTES
    + MACH_SYMTAB_COMMAND_BYTES
    + MACH_DYSYMTAB_COMMAND_BYTES;
const MACH_LOAD_COMMAND_COUNT: u32 = 4;
const MACH_NLIST_64_BYTES: usize = 16;
const MACH_MIN_MACOS_VERSION_V3: u32 = 0x000b_0000;
const MACH_SYMBOL_N_TYPE_V3: u8 = 0x1f;
const MACH_EXTERNAL_PREFIX_BYTES: usize = 1;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
const MH_OBJECT: u32 = 1;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x02;
const LC_DYSYMTAB: u32 = 0x0b;
const LC_BUILD_VERSION: u32 = 0x32;
const PLATFORM_MACOS_LOAD_COMMAND: u32 = 1;
const MACH_PAYLOAD_SECTION_FLAGS: u32 = 0x1000_0400;
const MACH_METADATA_SECTION_FLAGS: u32 = 0x1000_0000;
const VM_PROT_RWX: u32 = 7;

const ELF_HEADER_BYTES: usize = 64;
const ELF_SECTION_HEADER_BYTES: usize = 64;
const ELF_SECTION_HEADERS: usize = 6;
const ELF_SYMBOL_BYTES: usize = 24;
const ELF_SYMBOLS_WITH_NULL: usize = SYMBOLS + 1;
const ELF_SHSTRTAB: &[u8] = b"\0.text\0.fre.meta\0.symtab\0.strtab\0.shstrtab\0";
const ELF_TEXT_NAME: u32 = 1;
const ELF_METADATA_NAME: u32 = 7;
const ELF_SYMTAB_NAME: u32 = 17;
const ELF_STRTAB_NAME: u32 = 25;
const ELF_SHSTRTAB_NAME: u32 = 33;
const ELF_EM_AARCH64: u16 = 183;
const ELF_STV_HIDDEN: u8 = 2;

const _: () = assert!(MACH_HEADER_BYTES + MACH_LOAD_COMMAND_BYTES <= MACH_CONTENT_OFFSET);
const _: () = assert!(ELF_SHSTRTAB.len() == 43);

/// Hard and caller-selected bounds for one optimizing implementation object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountObjectLimitsV3 {
    pub max_payload_bytes: u64,
    pub max_object_bytes: u64,
}

impl Default for CountObjectLimitsV3 {
    fn default() -> Self {
        Self {
            max_payload_bytes: 4 << 20,
            max_object_bytes: 5 << 20,
        }
    }
}

/// Deterministic Mach-O or ELF implementation object and recomputed identities.
#[derive(Debug, Eq, PartialEq)]
pub struct CountImplementationObjectV3 {
    bytes: Vec<u8>,
    format: CountObjectFormatV3,
    metadata_bytes: [u8; METADATA_BYTES_V3],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    payload_bytes: usize,
}

impl CountImplementationObjectV3 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn format(&self) -> CountObjectFormatV3 {
        self.format
    }

    #[must_use]
    pub const fn metadata_bytes(&self) -> &[u8; METADATA_BYTES_V3] {
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

/// Strict allocation-free view of one canonical v3 implementation object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountImplementationInspectionV3<'a> {
    object_bytes: usize,
    format: CountObjectFormatV3,
    payload: &'a [u8],
    code: &'a [u8],
    metadata_bytes: &'a [u8; METADATA_BYTES_V3],
    metadata: ClaimedCountMetadataV3,
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
}

impl<'a> CountImplementationInspectionV3<'a> {
    #[must_use]
    pub const fn object_bytes(&self) -> usize {
        self.object_bytes
    }

    #[must_use]
    pub const fn format(&self) -> CountObjectFormatV3 {
        self.format
    }

    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Audited code bytes, excluding canonical alignment padding.
    #[must_use]
    pub const fn code(&self) -> &'a [u8] {
        self.code
    }

    #[must_use]
    pub const fn metadata_bytes(&self) -> &'a [u8; METADATA_BYTES_V3] {
        self.metadata_bytes
    }

    #[must_use]
    pub const fn metadata(&self) -> ClaimedCountMetadataV3 {
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

    /// Compact input for the independent mapped-code regeneration audit.
    #[must_use]
    pub fn mapped_metadata(&self) -> Result<AotCountMappedMetadataV3, CountCompileErrorV3> {
        AotCountMappedMetadataV3::from_wire_parts(
            self.metadata.backend_version(),
            self.metadata.algorithm_version(),
            self.metadata.kir_semantics_version(),
            self.metadata.kir_abi_version(),
            self.metadata.output_kind(),
            self.metadata.architecture(),
            self.metadata.little_endian(),
            self.metadata.pointer_width(),
            self.metadata.target_abi(),
            self.metadata.actual_features(),
            self.metadata.allowed_features(),
            self.metadata.max_literal_bytes(),
            self.metadata.candidate_block_starts(),
            self.metadata.vector_bytes(),
            self.metadata.sve_vector_length_bytes(),
            *self.metadata.program_identity(),
            self.metadata.literal_bytes(),
            *self.metadata.recipe_identity(),
            *self.metadata.artifact_identity(),
            self.metadata.code_bytes(),
        )
        .ok_or(CountCompileErrorV3::InvalidObject {
            at: "mapped-audit metadata projection",
        })
    }
}

/// Emit one inert optimizing Count-v3 object without a compiler, assembler,
/// linker, process spawn, or executable-memory API.
pub(crate) fn emit_count_implementation_object_v3(
    image: &AotCountImageV3,
    optimizer_receipt_identity: [u8; 32],
    binding_identity: [u8; 32],
    format: CountObjectFormatV3,
    limits: CountObjectLimitsV3,
) -> Result<CountImplementationObjectV3, CountCompileErrorV3> {
    if optimizer_receipt_identity == [0; 32] {
        return Err(CountCompileErrorV3::InvalidSemanticCandidate {
            field: "optimizer receipt identity",
        });
    }
    if binding_identity == [0; 32] {
        return Err(CountCompileErrorV3::InvalidSemanticCandidate {
            field: "object binding identity",
        });
    }
    let image_layout = image.layout();
    let payload_bytes =
        usize::try_from(image_layout.total_mapped_bytes).map_err(|_| overflow("payload bytes"))?;
    let rodata_offset = usize::try_from(image_layout.rodata_from_code_start)
        .map_err(|_| overflow("rodata offset"))?;
    if !image.rodata().is_empty()
        || rodata_offset != payload_bytes
        || image.code().len() > rodata_offset
        || rodata_offset
            .checked_sub(image.code().len())
            .is_none_or(|gap| gap >= 16)
    {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "Count-v3 image layout",
        });
    }
    enforce_limit(
        "payload bytes",
        limits.max_payload_bytes,
        usize_u64(payload_bytes, "payload bytes")?,
    )?;
    let payload_sha256 = hash_image_payload(image, payload_bytes)?;
    let mut metadata_bytes = encode_metadata(
        image,
        optimizer_receipt_identity,
        binding_identity,
        format,
        payload_sha256,
        [0; 32],
    )?;
    let compile_identity = compute_compile_identity(format, metadata_bytes)?;
    metadata_bytes[METADATA_COMPILE_IDENTITY_OFFSET_V3..].copy_from_slice(&compile_identity);
    inspect_count_metadata_v3(&metadata_bytes).map_err(|_| CountCompileErrorV3::InvalidObject {
        at: "self-inspected v3 metadata",
    })?;

    let bytes = match format {
        CountObjectFormatV3::MachOArm64 => {
            emit_macho(image, &metadata_bytes, &compile_identity, limits)?
        }
        CountObjectFormatV3::Elf64Aarch64 => {
            emit_elf(image, &metadata_bytes, &compile_identity, limits)?
        }
    };
    if bytes.len() != bytes.capacity() {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "exact object allocation",
        });
    }
    let inspection = inspect_count_implementation_object_v3(&bytes, limits)?;
    if inspection.format != format
        || inspection.metadata_bytes != &metadata_bytes
        || inspection.compile_identity != compile_identity
        || inspection.payload.len() != payload_bytes
    {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "self-inspection mismatch",
        });
    }
    let object_identity = inspection.object_identity;
    Ok(CountImplementationObjectV3 {
        bytes,
        format,
        metadata_bytes,
        compile_identity,
        object_identity,
        payload_bytes,
    })
}

/// Strictly inspect either supported deterministic object container.
pub fn inspect_count_implementation_object_v3(
    bytes: &[u8],
    limits: CountObjectLimitsV3,
) -> Result<CountImplementationInspectionV3<'_>, CountCompileErrorV3> {
    let magic = bytes
        .get(..4)
        .ok_or(CountCompileErrorV3::InvalidObject { at: "object magic" })?;
    if magic == MH_MAGIC_64.to_le_bytes() {
        inspect_macho(bytes, limits)
    } else if magic == b"\x7fELF" {
        inspect_elf(bytes, limits)
    } else {
        Err(CountCompileErrorV3::InvalidObject {
            at: "object format magic",
        })
    }
}

fn encode_metadata(
    image: &AotCountImageV3,
    optimizer_receipt_identity: [u8; 32],
    binding_identity: [u8; 32],
    format: CountObjectFormatV3,
    payload_sha256: [u8; 32],
    compile_identity: [u8; 32],
) -> Result<[u8; METADATA_BYTES_V3], CountCompileErrorV3> {
    let support = image.support();
    let target = image.target();
    let layout = image.layout();
    let recipe = image.recipe_manifest();
    let literal = image.literal_manifest();
    let target_identity = compute_count_target_identity_v3(
        format,
        support,
        target,
        recipe.tuning_class_id(),
        recipe.register_plan_id(),
        recipe.required_isa_id(),
    );
    let mut literal_manifest = [0_u8; 32];
    literal_manifest[..literal.literal().len()].copy_from_slice(literal.literal());

    let mut bytes = [0_u8; METADATA_BYTES_V3];
    let mut writer = Writer::new(&mut bytes);
    writer.bytes(b"FREOM64\x03")?;
    writer.u16(METADATA_VERSION_V3)?;
    writer.u16(u16::try_from(METADATA_BYTES_V3).expect("fixed v3 metadata width"))?;
    writer.u16(support.backend_version.0)?;
    writer.u16(support.algorithm_version)?;
    writer.u16(support.kir_semantics_version)?;
    writer.u16(support.kir_abi_version)?;
    writer.u16(CALL_ABI_SCHEMA_V3)?;
    writer.u16(support.max_literal_bytes)?;
    writer.u8(COUNT_ABI_KIND_V3)?;
    writer.u8(COUNT_OUTPUT_KIND_V3)?;
    writer.u8(target.architecture)?;
    writer.u8(u8::from(target.little_endian))?;
    writer.u8(target.pointer_width)?;
    writer.u8(target.abi)?;
    writer.u8(format.wire_id())?;
    writer.u8(STATUS_BITS_V3)?;
    writer.u8(support.candidate_block_starts)?;
    writer.u8(recipe.required_isa_id())?;
    writer.u8(recipe.tuning_class_id())?;
    writer.u8(recipe.strategy_id())?;
    writer.u8(recipe.schedule_id())?;
    writer.u8(recipe.register_plan_id())?;
    writer.u8(recipe.filter_len())?;
    writer.u8(recipe.confirmation_len())?;
    writer.u8(recipe.sparse_group_count())?;
    writer.u8(recipe.mismatch_stride())?;
    writer.u8(recipe.match_stride())?;
    writer.u8(recipe.periodic_stride())?;
    writer.u16(support.vector_bytes)?;
    writer.u16(support.sve_vector_length_bytes)?;
    writer.u16(recipe.recipe_schema_version())?;
    writer.u16(recipe.optimizer_version())?;
    writer.u16(AOT_COUNT_AUDITOR_VERSION_V3)?;
    writer.u16(0)?;
    writer.u64(target.features.bits())?;
    writer.u64(support.allowed_features.bits())?;
    writer.u32(layout.total_mapped_bytes)?;
    writer.u32(ENTRY_OFFSET_V3)?;
    writer.u32(u32::try_from(image.code().len()).map_err(|_| overflow("code bytes"))?)?;
    writer.u32(layout.rodata_from_code_start)?;
    writer.u32(u32::try_from(image.rodata().len()).map_err(|_| overflow("rodata bytes"))?)?;
    writer.u32(image.literal_bytes())?;
    writer.bytes(&literal_manifest)?;
    writer.bytes(recipe.canonical_recipe())?;
    writer.bytes(image.source_identity().as_bytes())?;
    writer.bytes(image.artifact_identity().as_bytes())?;
    writer.bytes(&binding_identity)?;
    writer.bytes(&payload_sha256)?;
    writer.bytes(&recipe.recipe_identity())?;
    writer.bytes(&optimizer_receipt_identity)?;
    writer.bytes(&target_identity)?;
    writer.bytes(&compile_identity)?;
    if writer.position() != METADATA_BYTES_V3 {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "v3 metadata encoding length",
        });
    }
    Ok(bytes)
}

fn compute_compile_identity(
    format: CountObjectFormatV3,
    mut metadata_bytes: [u8; METADATA_BYTES_V3],
) -> Result<[u8; 32], CountCompileErrorV3> {
    metadata_bytes[METADATA_COMPILE_IDENTITY_OFFSET_V3..].fill(0);
    let mut hasher = Sha256::new();
    hasher.update(COMPILE_IDENTITY_DOMAIN_V3);
    hasher.update([format.wire_id()]);
    hasher.update(EXPORTED_SYMBOL_SCHEMA_VERSION_V3.to_le_bytes());
    hasher.update(
        u16::try_from(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V3)
            .expect("fixed identity width")
            .to_le_bytes(),
    );
    for prefix in [
        COUNT_ENTRY_SYMBOL_PREFIX_V3,
        COUNT_PAYLOAD_SYMBOL_PREFIX_V3,
        COUNT_METADATA_SYMBOL_PREFIX_V3,
    ] {
        hasher.update(
            u16::try_from(prefix.len())
                .map_err(|_| overflow("symbol prefix length"))?
                .to_le_bytes(),
        );
        hasher.update(prefix.as_bytes());
    }
    match format {
        CountObjectFormatV3::MachOArm64 => {
            hasher.update(MACH_MIN_MACOS_VERSION_V3.to_le_bytes());
            hasher.update([MACH_SYMBOL_N_TYPE_V3]);
        }
        CountObjectFormatV3::Elf64Aarch64 => {
            hasher.update(ELF_EM_AARCH64.to_le_bytes());
            hasher.update([ELF_STV_HIDDEN]);
            hasher.update(
                u16::try_from(ELF_SECTION_HEADERS)
                    .expect("small ELF section count")
                    .to_le_bytes(),
            );
        }
    }
    hasher.update(metadata_bytes);
    Ok(hasher.finalize().into())
}

fn hash_image_payload(
    image: &AotCountImageV3,
    payload_bytes: usize,
) -> Result<[u8; 32], CountCompileErrorV3> {
    let gap = payload_bytes
        .checked_sub(image.code().len())
        .ok_or(CountCompileErrorV3::InvalidObject { at: "payload gap" })?;
    if gap >= 16 {
        return Err(CountCompileErrorV3::InvalidObject { at: "payload gap" });
    }
    let mut hasher = Sha256::new();
    hasher.update(image.code());
    hasher.update(&[0_u8; 16][..gap]);
    hasher.update(image.rodata());
    Ok(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MachLayout {
    payload_bytes: usize,
    metadata_address: usize,
    metadata_file_offset: usize,
    segment_bytes: usize,
    symbol_file_offset: usize,
    string_file_offset: usize,
    string_bytes: usize,
    object_bytes: usize,
}

impl MachLayout {
    fn new(payload_bytes: usize) -> Result<Self, CountCompileErrorV3> {
        let metadata_address = align_up(payload_bytes, 8, "Mach metadata address")?;
        let segment_bytes = metadata_address
            .checked_add(METADATA_BYTES_V3)
            .ok_or_else(|| overflow("Mach segment bytes"))?;
        let metadata_file_offset = MACH_CONTENT_OFFSET
            .checked_add(metadata_address)
            .ok_or_else(|| overflow("Mach metadata file offset"))?;
        let symbol_file_offset = MACH_CONTENT_OFFSET
            .checked_add(segment_bytes)
            .ok_or_else(|| overflow("Mach symbol file offset"))?;
        let symbol_table_bytes = MACH_NLIST_64_BYTES
            .checked_mul(SYMBOLS)
            .ok_or_else(|| overflow("Mach symbol table bytes"))?;
        let string_file_offset = symbol_file_offset
            .checked_add(symbol_table_bytes)
            .ok_or_else(|| overflow("Mach string file offset"))?;
        let string_bytes = align_up(symbol_string_bytes(true)?, 4, "Mach string table alignment")?;
        let object_bytes = string_file_offset
            .checked_add(string_bytes)
            .ok_or_else(|| overflow("Mach object bytes"))?;
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
    fn new(prefix: &str, identity: &[u8; 32]) -> Result<Self, CountCompileErrorV3> {
        let len = prefix
            .len()
            .checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V3)
            .ok_or_else(|| overflow("symbol name length"))?;
        if len > SYMBOL_NAME_STORAGE_BYTES {
            return Err(CountCompileErrorV3::InvalidObject {
                at: "symbol name storage",
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
        if cursor != len {
            return Err(CountCompileErrorV3::InvalidObject {
                at: "symbol name length",
            });
        }
        Ok(Self { bytes, len })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

fn symbol_specs(identity: &[u8; 32]) -> Result<[SymbolSpec; SYMBOLS], CountCompileErrorV3> {
    let mut specs = [
        SymbolSpec {
            name: SymbolName::new(COUNT_ENTRY_SYMBOL_PREFIX_V3, identity)?,
            location: SymbolLocation::Entry,
        },
        SymbolSpec {
            name: SymbolName::new(COUNT_PAYLOAD_SYMBOL_PREFIX_V3, identity)?,
            location: SymbolLocation::Payload,
        },
        SymbolSpec {
            name: SymbolName::new(COUNT_METADATA_SYMBOL_PREFIX_V3, identity)?,
            location: SymbolLocation::Metadata,
        },
    ];
    specs.sort_unstable_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    Ok(specs)
}

fn emit_macho(
    image: &AotCountImageV3,
    metadata: &[u8; METADATA_BYTES_V3],
    compile_identity: &[u8; 32],
    limits: CountObjectLimitsV3,
) -> Result<Vec<u8>, CountCompileErrorV3> {
    let payload_bytes = usize::try_from(image.layout().total_mapped_bytes)
        .map_err(|_| overflow("payload bytes"))?;
    let layout = MachLayout::new(payload_bytes)?;
    enforce_limit(
        "object bytes",
        limits.max_object_bytes,
        usize_u64(layout.object_bytes, "Mach object bytes")?,
    )?;
    let mut bytes =
        zeroed_exact(layout.object_bytes).map_err(|_| CountCompileErrorV3::AllocationFailed)?;
    write_mach_prefix(&mut bytes[..MACH_CONTENT_OFFSET], layout)?;
    copy_region(
        &mut bytes,
        MACH_CONTENT_OFFSET,
        image.code(),
        "Mach code payload",
    )?;
    copy_region(
        &mut bytes,
        layout.metadata_file_offset,
        metadata,
        "Mach metadata payload",
    )?;
    write_mach_symbols(&mut bytes, layout, compile_identity)?;
    Ok(bytes)
}

fn inspect_macho(
    bytes: &[u8],
    limits: CountObjectLimitsV3,
) -> Result<CountImplementationInspectionV3<'_>, CountCompileErrorV3> {
    if bytes.len() < MACH_CONTENT_OFFSET {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "Mach object prefix",
        });
    }
    let payload_bytes = usize::try_from(read_u64(bytes, 144, "Mach payload section size")?)
        .map_err(|_| overflow("Mach payload section size"))?;
    enforce_limit(
        "payload bytes",
        limits.max_payload_bytes,
        usize_u64(payload_bytes, "Mach payload bytes")?,
    )?;
    let layout = MachLayout::new(payload_bytes)?;
    enforce_limit(
        "object bytes",
        limits.max_object_bytes,
        usize_u64(bytes.len(), "Mach object bytes")?,
    )?;
    if bytes.len() != layout.object_bytes {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "Mach object length",
        });
    }
    let mut expected_prefix = [0_u8; MACH_CONTENT_OFFSET];
    write_mach_prefix(&mut expected_prefix, layout)?;
    if bytes[..MACH_CONTENT_OFFSET] != expected_prefix {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "Mach canonical prefix",
        });
    }
    let metadata_end = layout
        .metadata_file_offset
        .checked_add(METADATA_BYTES_V3)
        .ok_or_else(|| overflow("Mach metadata end"))?;
    let metadata_bytes: &[u8; METADATA_BYTES_V3] = bytes
        .get(layout.metadata_file_offset..metadata_end)
        .and_then(|value| value.try_into().ok())
        .ok_or(CountCompileErrorV3::InvalidObject {
            at: "Mach metadata range",
        })?;
    let metadata = inspect_count_metadata_v3(metadata_bytes).map_err(|_| {
        CountCompileErrorV3::InvalidObject {
            at: "Mach metadata contract",
        }
    })?;
    if metadata.object_format() != CountObjectFormatV3::MachOArm64
        || usize::try_from(metadata.payload_bytes()).ok() != Some(payload_bytes)
    {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "Mach metadata container binding",
        });
    }
    let compile_identity =
        validate_metadata_compile_identity(metadata_bytes, CountObjectFormatV3::MachOArm64)?;
    validate_mach_symbols(bytes, layout, &compile_identity)?;
    let payload_end = MACH_CONTENT_OFFSET
        .checked_add(payload_bytes)
        .ok_or_else(|| overflow("Mach payload end"))?;
    let payload =
        bytes
            .get(MACH_CONTENT_OFFSET..payload_end)
            .ok_or(CountCompileErrorV3::InvalidObject {
                at: "Mach payload range",
            })?;
    finish_inspection(
        bytes,
        CountObjectFormatV3::MachOArm64,
        payload,
        metadata_bytes,
        metadata,
        compile_identity,
    )
}

fn write_mach_prefix(prefix: &mut [u8], layout: MachLayout) -> Result<(), CountCompileErrorV3> {
    if prefix.len() != MACH_CONTENT_OFFSET {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "Mach prefix destination",
        });
    }
    prefix.fill(0);
    let mut writer = Writer::new(prefix);
    writer.u32(MH_MAGIC_64)?;
    writer.u32(CPU_TYPE_ARM64)?;
    writer.u32(CPU_SUBTYPE_ARM64_ALL)?;
    writer.u32(MH_OBJECT)?;
    writer.u32(MACH_LOAD_COMMAND_COUNT)?;
    writer.u32(u32_from_usize(
        MACH_LOAD_COMMAND_BYTES,
        "Mach load command bytes",
    )?)?;
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(LC_SEGMENT_64)?;
    writer.u32(u32_from_usize(
        MACH_SEGMENT_WITH_SECTIONS_BYTES,
        "Mach segment command bytes",
    )?)?;
    writer.fixed_name("")?;
    writer.u64(0)?;
    writer.u64(usize_u64(layout.segment_bytes, "Mach segment bytes")?)?;
    writer.u64(usize_u64(MACH_CONTENT_OFFSET, "Mach content offset")?)?;
    writer.u64(usize_u64(layout.segment_bytes, "Mach segment file bytes")?)?;
    writer.u32(VM_PROT_RWX)?;
    writer.u32(VM_PROT_RWX)?;
    writer.u32(2)?;
    writer.u32(0)?;
    writer.mach_section(
        "__fre_image",
        "__TEXT",
        0,
        usize_u64(layout.payload_bytes, "Mach payload section bytes")?,
        u32_from_usize(MACH_CONTENT_OFFSET, "Mach payload file offset")?,
        4,
        MACH_PAYLOAD_SECTION_FLAGS,
    )?;
    writer.mach_section(
        "__fre_meta",
        "__FRE_CONST",
        usize_u64(layout.metadata_address, "Mach metadata address")?,
        usize_u64(METADATA_BYTES_V3, "Mach metadata bytes")?,
        u32_from_usize(layout.metadata_file_offset, "Mach metadata file offset")?,
        3,
        MACH_METADATA_SECTION_FLAGS,
    )?;

    writer.u32(LC_BUILD_VERSION)?;
    writer.u32(u32_from_usize(
        MACH_BUILD_VERSION_COMMAND_BYTES,
        "Mach build version command bytes",
    )?)?;
    writer.u32(PLATFORM_MACOS_LOAD_COMMAND)?;
    writer.u32(MACH_MIN_MACOS_VERSION_V3)?;
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(LC_SYMTAB)?;
    writer.u32(u32_from_usize(
        MACH_SYMTAB_COMMAND_BYTES,
        "Mach symtab command bytes",
    )?)?;
    writer.u32(u32_from_usize(
        layout.symbol_file_offset,
        "Mach symbol file offset",
    )?)?;
    writer.u32(u32::try_from(SYMBOLS).expect("small symbol count"))?;
    writer.u32(u32_from_usize(
        layout.string_file_offset,
        "Mach string file offset",
    )?)?;
    writer.u32(u32_from_usize(layout.string_bytes, "Mach string bytes")?)?;

    writer.u32(LC_DYSYMTAB)?;
    writer.u32(u32_from_usize(
        MACH_DYSYMTAB_COMMAND_BYTES,
        "Mach dysymtab command bytes",
    )?)?;
    for value in [0, 0, 0, 3, 3, 0] {
        writer.u32(value)?;
    }
    for _ in 0..12 {
        writer.u32(0)?;
    }
    if writer.position() != MACH_HEADER_BYTES + MACH_LOAD_COMMAND_BYTES {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "Mach load command length",
        });
    }
    Ok(())
}

fn write_mach_symbols(
    bytes: &mut [u8],
    layout: MachLayout,
    compile_identity: &[u8; 32],
) -> Result<(), CountCompileErrorV3> {
    let specs = symbol_specs(compile_identity)?;
    let symbol_end = layout
        .symbol_file_offset
        .checked_add(MACH_NLIST_64_BYTES * SYMBOLS)
        .ok_or_else(|| overflow("Mach symbol table end"))?;
    let mut writer = Writer::new(bytes.get_mut(layout.symbol_file_offset..symbol_end).ok_or(
        CountCompileErrorV3::InvalidObject {
            at: "Mach symbol table destination",
        },
    )?);
    let mut string_index = 4_usize;
    for spec in specs {
        writer.u32(u32_from_usize(string_index, "Mach string index")?)?;
        writer.u8(MACH_SYMBOL_N_TYPE_V3)?;
        writer.u8(match spec.location {
            SymbolLocation::Entry | SymbolLocation::Payload => 1,
            SymbolLocation::Metadata => 2,
        })?;
        writer.u16(0)?;
        writer.u64(match spec.location {
            SymbolLocation::Entry | SymbolLocation::Payload => u64::from(ENTRY_OFFSET_V3),
            SymbolLocation::Metadata => {
                usize_u64(layout.metadata_address, "Mach metadata symbol value")?
            }
        })?;
        string_index = string_index
            .checked_add(MACH_EXTERNAL_PREFIX_BYTES)
            .and_then(|value| value.checked_add(spec.name.as_bytes().len()))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| overflow("Mach string index"))?;
    }
    let string_end = layout
        .string_file_offset
        .checked_add(layout.string_bytes)
        .ok_or_else(|| overflow("Mach string table end"))?;
    let mut writer = Writer::new(bytes.get_mut(layout.string_file_offset..string_end).ok_or(
        CountCompileErrorV3::InvalidObject {
            at: "Mach string table destination",
        },
    )?);
    writer.u32(0)?;
    for spec in specs {
        writer.u8(b'_')?;
        writer.bytes(spec.name.as_bytes())?;
        writer.u8(0)?;
    }
    Ok(())
}

fn validate_mach_symbols(
    bytes: &[u8],
    layout: MachLayout,
    compile_identity: &[u8; 32],
) -> Result<(), CountCompileErrorV3> {
    let mut expected_symbols = [0_u8; MACH_NLIST_64_BYTES * SYMBOLS];
    let mut expected_strings = [0_u8; MAX_STRING_TABLE_BYTES];
    if layout.string_bytes > expected_strings.len() {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "Mach string table inspection bound",
        });
    }
    let specs = symbol_specs(compile_identity)?;
    let mut writer = Writer::new(&mut expected_symbols);
    let mut string_index = 4_usize;
    for spec in specs {
        writer.u32(u32_from_usize(string_index, "Mach string index")?)?;
        writer.u8(MACH_SYMBOL_N_TYPE_V3)?;
        writer.u8(match spec.location {
            SymbolLocation::Entry | SymbolLocation::Payload => 1,
            SymbolLocation::Metadata => 2,
        })?;
        writer.u16(0)?;
        writer.u64(match spec.location {
            SymbolLocation::Entry | SymbolLocation::Payload => u64::from(ENTRY_OFFSET_V3),
            SymbolLocation::Metadata => {
                usize_u64(layout.metadata_address, "Mach metadata symbol value")?
            }
        })?;
        string_index = string_index
            .checked_add(MACH_EXTERNAL_PREFIX_BYTES)
            .and_then(|value| value.checked_add(spec.name.as_bytes().len()))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| overflow("Mach string index"))?;
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
        .ok_or_else(|| overflow("Mach symbol inspection end"))?;
    let string_end = layout
        .string_file_offset
        .checked_add(layout.string_bytes)
        .ok_or_else(|| overflow("Mach string inspection end"))?;
    if bytes.get(layout.symbol_file_offset..symbol_end) != Some(expected_symbols.as_slice())
        || bytes.get(layout.string_file_offset..string_end)
            != Some(&expected_strings[..layout.string_bytes])
    {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "Mach symbol or string table",
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ElfLayout {
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

impl ElfLayout {
    fn new(payload_bytes: usize) -> Result<Self, CountCompileErrorV3> {
        let payload_offset = ELF_HEADER_BYTES;
        let payload_end = payload_offset
            .checked_add(payload_bytes)
            .ok_or_else(|| overflow("ELF payload end"))?;
        let metadata_offset = align_up(payload_end, 8, "ELF metadata offset")?;
        let metadata_end = metadata_offset
            .checked_add(METADATA_BYTES_V3)
            .ok_or_else(|| overflow("ELF metadata end"))?;
        let symtab_offset = align_up(metadata_end, 8, "ELF symtab offset")?;
        let symtab_bytes = ELF_SYMBOL_BYTES
            .checked_mul(ELF_SYMBOLS_WITH_NULL)
            .ok_or_else(|| overflow("ELF symtab bytes"))?;
        let strtab_offset = symtab_offset
            .checked_add(symtab_bytes)
            .ok_or_else(|| overflow("ELF strtab offset"))?;
        let strtab_bytes = symbol_string_bytes(false)?;
        let shstrtab_offset = strtab_offset
            .checked_add(strtab_bytes)
            .ok_or_else(|| overflow("ELF shstrtab offset"))?;
        let section_header_offset = align_up(
            shstrtab_offset
                .checked_add(ELF_SHSTRTAB.len())
                .ok_or_else(|| overflow("ELF shstrtab end"))?,
            8,
            "ELF section header offset",
        )?;
        let object_bytes = section_header_offset
            .checked_add(
                ELF_SECTION_HEADER_BYTES
                    .checked_mul(ELF_SECTION_HEADERS)
                    .ok_or_else(|| overflow("ELF section header bytes"))?,
            )
            .ok_or_else(|| overflow("ELF object bytes"))?;
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

fn emit_elf(
    image: &AotCountImageV3,
    metadata: &[u8; METADATA_BYTES_V3],
    compile_identity: &[u8; 32],
    limits: CountObjectLimitsV3,
) -> Result<Vec<u8>, CountCompileErrorV3> {
    let payload_bytes = usize::try_from(image.layout().total_mapped_bytes)
        .map_err(|_| overflow("payload bytes"))?;
    let layout = ElfLayout::new(payload_bytes)?;
    enforce_limit(
        "object bytes",
        limits.max_object_bytes,
        usize_u64(layout.object_bytes, "ELF object bytes")?,
    )?;
    let mut bytes =
        zeroed_exact(layout.object_bytes).map_err(|_| CountCompileErrorV3::AllocationFailed)?;
    write_elf_header(&mut bytes[..ELF_HEADER_BYTES], layout)?;
    copy_region(
        &mut bytes,
        layout.payload_offset,
        image.code(),
        "ELF code payload",
    )?;
    copy_region(
        &mut bytes,
        layout.metadata_offset,
        metadata,
        "ELF metadata payload",
    )?;
    write_elf_symbols(&mut bytes, layout, compile_identity)?;
    copy_region(
        &mut bytes,
        layout.shstrtab_offset,
        ELF_SHSTRTAB,
        "ELF section string table",
    )?;
    let section_headers_end = layout
        .section_header_offset
        .checked_add(ELF_SECTION_HEADER_BYTES * ELF_SECTION_HEADERS)
        .ok_or_else(|| overflow("ELF section headers end"))?;
    write_elf_section_headers(
        bytes
            .get_mut(layout.section_header_offset..section_headers_end)
            .ok_or(CountCompileErrorV3::InvalidObject {
                at: "ELF section header destination",
            })?,
        layout,
    )?;
    Ok(bytes)
}

fn inspect_elf(
    bytes: &[u8],
    limits: CountObjectLimitsV3,
) -> Result<CountImplementationInspectionV3<'_>, CountCompileErrorV3> {
    if bytes.len() < ELF_HEADER_BYTES {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF object header",
        });
    }
    let section_header_offset = usize::try_from(read_u64(bytes, 40, "ELF section header offset")?)
        .map_err(|_| overflow("ELF section header offset"))?;
    let metadata_section = section_header_offset
        .checked_add(ELF_SECTION_HEADER_BYTES * 2)
        .ok_or_else(|| overflow("ELF metadata section header"))?;
    let metadata_offset = usize::try_from(read_u64(
        bytes,
        metadata_section + 24,
        "ELF metadata offset",
    )?)
    .map_err(|_| overflow("ELF metadata offset"))?;
    let metadata_size =
        usize::try_from(read_u64(bytes, metadata_section + 32, "ELF metadata size")?)
            .map_err(|_| overflow("ELF metadata size"))?;
    if metadata_size != METADATA_BYTES_V3 {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF metadata size",
        });
    }
    let metadata_end = metadata_offset
        .checked_add(metadata_size)
        .ok_or_else(|| overflow("ELF metadata end"))?;
    let metadata_bytes: &[u8; METADATA_BYTES_V3] = bytes
        .get(metadata_offset..metadata_end)
        .and_then(|value| value.try_into().ok())
        .ok_or(CountCompileErrorV3::InvalidObject {
            at: "ELF metadata range",
        })?;
    let metadata = inspect_count_metadata_v3(metadata_bytes).map_err(|_| {
        CountCompileErrorV3::InvalidObject {
            at: "ELF metadata contract",
        }
    })?;
    if metadata.object_format() != CountObjectFormatV3::Elf64Aarch64 {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF metadata container binding",
        });
    }
    let payload_bytes =
        usize::try_from(metadata.payload_bytes()).map_err(|_| overflow("ELF payload bytes"))?;
    enforce_limit(
        "payload bytes",
        limits.max_payload_bytes,
        usize_u64(payload_bytes, "ELF payload bytes")?,
    )?;
    let layout = ElfLayout::new(payload_bytes)?;
    enforce_limit(
        "object bytes",
        limits.max_object_bytes,
        usize_u64(bytes.len(), "ELF object bytes")?,
    )?;
    if bytes.len() != layout.object_bytes
        || section_header_offset != layout.section_header_offset
        || metadata_offset != layout.metadata_offset
    {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF canonical layout",
        });
    }
    let mut expected_header = [0_u8; ELF_HEADER_BYTES];
    write_elf_header(&mut expected_header, layout)?;
    if bytes[..ELF_HEADER_BYTES] != expected_header {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF canonical header",
        });
    }
    let mut expected_sections = [0_u8; ELF_SECTION_HEADER_BYTES * ELF_SECTION_HEADERS];
    write_elf_section_headers(&mut expected_sections, layout)?;
    if bytes[layout.section_header_offset..] != expected_sections {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF canonical section headers",
        });
    }
    if bytes.get(
        layout.shstrtab_offset
            ..layout
                .shstrtab_offset
                .checked_add(ELF_SHSTRTAB.len())
                .ok_or_else(|| overflow("ELF shstrtab end"))?,
    ) != Some(ELF_SHSTRTAB)
    {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF section string table",
        });
    }
    validate_elf_zero_padding(bytes, layout)?;
    let compile_identity =
        validate_metadata_compile_identity(metadata_bytes, CountObjectFormatV3::Elf64Aarch64)?;
    validate_elf_symbols(bytes, layout, &compile_identity)?;
    let payload_end = layout
        .payload_offset
        .checked_add(payload_bytes)
        .ok_or_else(|| overflow("ELF payload end"))?;
    let payload = bytes.get(layout.payload_offset..payload_end).ok_or(
        CountCompileErrorV3::InvalidObject {
            at: "ELF payload range",
        },
    )?;
    finish_inspection(
        bytes,
        CountObjectFormatV3::Elf64Aarch64,
        payload,
        metadata_bytes,
        metadata,
        compile_identity,
    )
}

fn write_elf_header(header: &mut [u8], layout: ElfLayout) -> Result<(), CountCompileErrorV3> {
    if header.len() != ELF_HEADER_BYTES {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF header destination",
        });
    }
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
        "ELF section header offset",
    )?)?;
    writer.u32(0)?;
    writer.u16(u16::try_from(ELF_HEADER_BYTES).expect("fixed ELF header size"))?;
    writer.u16(0)?;
    writer.u16(0)?;
    writer.u16(u16::try_from(ELF_SECTION_HEADER_BYTES).expect("fixed ELF section header size"))?;
    writer.u16(u16::try_from(ELF_SECTION_HEADERS).expect("small ELF section count"))?;
    writer.u16(5)?;
    if writer.position() != ELF_HEADER_BYTES {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF header length",
        });
    }
    Ok(())
}

fn write_elf_section_headers(
    destination: &mut [u8],
    layout: ElfLayout,
) -> Result<(), CountCompileErrorV3> {
    if destination.len() != ELF_SECTION_HEADER_BYTES * ELF_SECTION_HEADERS {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF section header destination",
        });
    }
    destination.fill(0);
    let mut writer = Writer::new(destination);
    writer.bytes(&[0; ELF_SECTION_HEADER_BYTES])?;
    writer.elf_section(
        ELF_TEXT_NAME,
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
        ELF_METADATA_NAME,
        1,
        0x2,
        layout.metadata_offset,
        METADATA_BYTES_V3,
        0,
        0,
        8,
        0,
    )?;
    writer.elf_section(
        ELF_SYMTAB_NAME,
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
        ELF_STRTAB_NAME,
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
        ELF_SHSTRTAB_NAME,
        3,
        0,
        layout.shstrtab_offset,
        ELF_SHSTRTAB.len(),
        0,
        0,
        1,
        0,
    )?;
    if writer.position() != destination.len() {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF section header length",
        });
    }
    Ok(())
}

fn write_elf_symbols(
    bytes: &mut [u8],
    layout: ElfLayout,
    compile_identity: &[u8; 32],
) -> Result<(), CountCompileErrorV3> {
    let specs = symbol_specs(compile_identity)?;
    let symtab_end = layout
        .symtab_offset
        .checked_add(ELF_SYMBOL_BYTES * ELF_SYMBOLS_WITH_NULL)
        .ok_or_else(|| overflow("ELF symtab end"))?;
    let mut writer = Writer::new(bytes.get_mut(layout.symtab_offset..symtab_end).ok_or(
        CountCompileErrorV3::InvalidObject {
            at: "ELF symtab destination",
        },
    )?);
    writer.bytes(&[0; ELF_SYMBOL_BYTES])?;
    let mut string_index = 1_usize;
    for spec in specs {
        writer.u32(u32_from_usize(string_index, "ELF string index")?)?;
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
            SymbolLocation::Payload => usize_u64(layout.payload_bytes, "ELF payload symbol size")?,
            SymbolLocation::Metadata => usize_u64(METADATA_BYTES_V3, "ELF metadata symbol size")?,
        })?;
        string_index = string_index
            .checked_add(spec.name.as_bytes().len())
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| overflow("ELF string index"))?;
    }
    let strtab_end = layout
        .strtab_offset
        .checked_add(layout.strtab_bytes)
        .ok_or_else(|| overflow("ELF strtab end"))?;
    let mut writer = Writer::new(bytes.get_mut(layout.strtab_offset..strtab_end).ok_or(
        CountCompileErrorV3::InvalidObject {
            at: "ELF strtab destination",
        },
    )?);
    writer.u8(0)?;
    for spec in specs {
        writer.bytes(spec.name.as_bytes())?;
        writer.u8(0)?;
    }
    Ok(())
}

fn validate_elf_symbols(
    bytes: &[u8],
    layout: ElfLayout,
    compile_identity: &[u8; 32],
) -> Result<(), CountCompileErrorV3> {
    let mut expected_symbols = [0_u8; ELF_SYMBOL_BYTES * ELF_SYMBOLS_WITH_NULL];
    let mut expected_strings = [0_u8; MAX_STRING_TABLE_BYTES];
    if layout.strtab_bytes > expected_strings.len() {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF string table inspection bound",
        });
    }
    let specs = symbol_specs(compile_identity)?;
    let mut writer = Writer::new(&mut expected_symbols);
    writer.bytes(&[0; ELF_SYMBOL_BYTES])?;
    let mut string_index = 1_usize;
    for spec in specs {
        writer.u32(u32_from_usize(string_index, "ELF string index")?)?;
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
            SymbolLocation::Payload => usize_u64(layout.payload_bytes, "ELF payload symbol size")?,
            SymbolLocation::Metadata => usize_u64(METADATA_BYTES_V3, "ELF metadata symbol size")?,
        })?;
        string_index = string_index
            .checked_add(spec.name.as_bytes().len())
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| overflow("ELF string index"))?;
    }
    let mut writer = Writer::new(&mut expected_strings[..layout.strtab_bytes]);
    writer.u8(0)?;
    for spec in specs {
        writer.bytes(spec.name.as_bytes())?;
        writer.u8(0)?;
    }
    let symbol_end = layout
        .symtab_offset
        .checked_add(expected_symbols.len())
        .ok_or_else(|| overflow("ELF symbol inspection end"))?;
    let string_end = layout
        .strtab_offset
        .checked_add(layout.strtab_bytes)
        .ok_or_else(|| overflow("ELF string inspection end"))?;
    if bytes.get(layout.symtab_offset..symbol_end) != Some(expected_symbols.as_slice())
        || bytes.get(layout.strtab_offset..string_end)
            != Some(&expected_strings[..layout.strtab_bytes])
    {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "ELF symbol or string table",
        });
    }
    Ok(())
}

fn validate_elf_zero_padding(bytes: &[u8], layout: ElfLayout) -> Result<(), CountCompileErrorV3> {
    let payload_end = layout
        .payload_offset
        .checked_add(layout.payload_bytes)
        .ok_or_else(|| overflow("ELF payload end"))?;
    let metadata_end = layout
        .metadata_offset
        .checked_add(METADATA_BYTES_V3)
        .ok_or_else(|| overflow("ELF metadata end"))?;
    let shstrtab_end = layout
        .shstrtab_offset
        .checked_add(ELF_SHSTRTAB.len())
        .ok_or_else(|| overflow("ELF shstrtab end"))?;
    for range in [
        payload_end..layout.metadata_offset,
        metadata_end..layout.symtab_offset,
        shstrtab_end..layout.section_header_offset,
    ] {
        if bytes
            .get(range)
            .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
        {
            return Err(CountCompileErrorV3::InvalidObject {
                at: "ELF noncanonical padding",
            });
        }
    }
    Ok(())
}

fn finish_inspection<'a>(
    object: &'a [u8],
    format: CountObjectFormatV3,
    payload: &'a [u8],
    metadata_bytes: &'a [u8; METADATA_BYTES_V3],
    metadata: ClaimedCountMetadataV3,
    compile_identity: [u8; 32],
) -> Result<CountImplementationInspectionV3<'a>, CountCompileErrorV3> {
    if digest(payload) != *metadata.payload_sha256() {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "payload digest",
        });
    }
    let code_bytes = usize::try_from(metadata.code_bytes()).map_err(|_| overflow("code bytes"))?;
    let code = payload
        .get(..code_bytes)
        .ok_or(CountCompileErrorV3::InvalidObject { at: "code range" })?;
    if payload[code_bytes..].iter().any(|byte| *byte != 0) {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "payload alignment padding",
        });
    }
    Ok(CountImplementationInspectionV3 {
        object_bytes: object.len(),
        format,
        payload,
        code,
        metadata_bytes,
        metadata,
        compile_identity,
        object_identity: digest(object),
    })
}

fn validate_metadata_compile_identity(
    metadata_bytes: &[u8; METADATA_BYTES_V3],
    format: CountObjectFormatV3,
) -> Result<[u8; 32], CountCompileErrorV3> {
    let metadata = inspect_count_metadata_v3(metadata_bytes).map_err(|_| {
        CountCompileErrorV3::InvalidObject {
            at: "metadata compile identity input",
        }
    })?;
    let compile_identity = compute_compile_identity(format, *metadata_bytes)?;
    if metadata.compile_identity() != &compile_identity {
        return Err(CountCompileErrorV3::InvalidObject {
            at: "compile identity",
        });
    }
    Ok(compile_identity)
}

fn symbol_string_bytes(mach_external_prefix: bool) -> Result<usize, CountCompileErrorV3> {
    let initial = if mach_external_prefix { 4 } else { 1 };
    [
        COUNT_ENTRY_SYMBOL_PREFIX_V3,
        COUNT_PAYLOAD_SYMBOL_PREFIX_V3,
        COUNT_METADATA_SYMBOL_PREFIX_V3,
    ]
    .into_iter()
    .try_fold(initial, |total, prefix| {
        total
            .checked_add(usize::from(mach_external_prefix))
            .and_then(|value| value.checked_add(prefix.len()))
            .and_then(|value| value.checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V3))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| overflow("symbol string bytes"))
    })
}

fn copy_region(
    destination: &mut [u8],
    offset: usize,
    source: &[u8],
    at: &'static str,
) -> Result<(), CountCompileErrorV3> {
    let end = offset
        .checked_add(source.len())
        .ok_or_else(|| overflow("copy region"))?;
    destination
        .get_mut(offset..end)
        .ok_or(CountCompileErrorV3::InvalidObject { at })?
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

    fn bytes(&mut self, value: &[u8]) -> Result<(), CountCompileErrorV3> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or_else(|| overflow("writer offset"))?;
        self.bytes
            .get_mut(self.position..end)
            .ok_or(CountCompileErrorV3::InvalidObject {
                at: "writer destination",
            })?
            .copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), CountCompileErrorV3> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), CountCompileErrorV3> {
        self.bytes(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), CountCompileErrorV3> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), CountCompileErrorV3> {
        self.bytes(&value.to_le_bytes())
    }

    fn fixed_name(&mut self, name: &str) -> Result<(), CountCompileErrorV3> {
        if name.len() > 16 {
            return Err(CountCompileErrorV3::InvalidObject {
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
    fn mach_section(
        &mut self,
        section: &str,
        segment: &str,
        address: u64,
        size: u64,
        offset: u32,
        alignment_power: u32,
        flags: u32,
    ) -> Result<(), CountCompileErrorV3> {
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
    ) -> Result<(), CountCompileErrorV3> {
        self.u32(name)?;
        self.u32(section_type)?;
        self.u64(flags)?;
        self.u64(0)?;
        self.u64(usize_u64(offset, "ELF section offset")?)?;
        self.u64(usize_u64(size, "ELF section size")?)?;
        self.u32(link)?;
        self.u32(info)?;
        self.u64(alignment)?;
        self.u64(usize_u64(entry_size, "ELF section entry size")?)
    }

    const fn position(&self) -> usize {
        self.position
    }
}

fn read_u64(bytes: &[u8], offset: usize, at: &'static str) -> Result<u64, CountCompileErrorV3> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| overflow("reader offset"))?;
    let value: [u8; 8] = bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or(CountCompileErrorV3::InvalidObject { at })?;
    Ok(u64::from_le_bytes(value))
}

fn align_up(
    value: usize,
    alignment: usize,
    at: &'static str,
) -> Result<usize, CountCompileErrorV3> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(CountCompileErrorV3::ArithmeticOverflow { at })?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or(CountCompileErrorV3::ArithmeticOverflow { at })
}

fn enforce_limit(
    resource: &'static str,
    limit: u64,
    required: u64,
) -> Result<(), CountCompileErrorV3> {
    if required <= limit {
        Ok(())
    } else {
        Err(CountCompileErrorV3::ResourceLimit {
            resource,
            limit,
            required,
        })
    }
}

fn u32_from_usize(value: usize, at: &'static str) -> Result<u32, CountCompileErrorV3> {
    u32::try_from(value).map_err(|_| CountCompileErrorV3::ArithmeticOverflow { at })
}

fn usize_u64(value: usize, at: &'static str) -> Result<u64, CountCompileErrorV3> {
    u64::try_from(value).map_err(|_| CountCompileErrorV3::ArithmeticOverflow { at })
}

const fn overflow(at: &'static str) -> CountCompileErrorV3 {
    CountCompileErrorV3::ArithmeticOverflow { at }
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
