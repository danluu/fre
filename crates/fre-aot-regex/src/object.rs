//! Deterministic, dependency-free relocatable object serialization.
//!
//! The native lowering stage deliberately stops at [`CompiledModule`]. This
//! module is the only place where the common, mathematical relocation model is
//! translated into ELF64 RELA records or Mach-O's in-place relocation model.

use std::borrow::Cow;

use crate::error::{CompileResource, ObjectError};
use crate::module::{
    Architecture, CompiledModule, ModuleRelocation, ModuleSection, OperatingSystem, RelocationKind,
    SectionKind, SymbolBinding, SymbolKind, Target,
};

const ELF_HEADER_BYTES: usize = 64;
const ELF_SECTION_HEADER_BYTES: usize = 64;
const ELF_SYMBOL_BYTES: usize = 24;
const ELF_RELA_BYTES: usize = 24;

const MACH_HEADER_BYTES: usize = 32;
const MACH_SEGMENT_COMMAND_BYTES: usize = 72;
const MACH_SECTION_BYTES: usize = 80;
const MACH_BUILD_VERSION_BYTES: usize = 24;
const MACH_SYMTAB_COMMAND_BYTES: usize = 24;
const MACH_DYSYMTAB_COMMAND_BYTES: usize = 80;
const MACH_NLIST_BYTES: usize = 16;
const MACH_RELOCATION_BYTES: usize = 8;

/// Relocatable container selected independently from native instruction
/// lowering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectFormat {
    /// Little-endian ELF64 `ET_REL`.
    Elf64,
    /// Little-endian 64-bit Mach-O `MH_OBJECT`.
    MachO64,
}

impl ObjectFormat {
    /// Return the canonical relocatable container for `target`.
    #[must_use]
    pub const fn for_target(target: Target) -> Self {
        match target.operating_system {
            OperatingSystem::Linux => Self::Elf64,
            OperatingSystem::Macos => Self::MachO64,
        }
    }
}

/// Serialize a lowered native module without invoking an assembler, linker, or
/// subprocess.
///
/// # Errors
///
/// Returns a typed error if the module and requested format disagree, the
/// module contains an invalid reference, checked layout arithmetic overflows,
/// or the completed object would exceed `max_bytes`.
pub fn emit_object(
    module: &CompiledModule,
    format: ObjectFormat,
    max_bytes: usize,
) -> Result<Vec<u8>, ObjectError> {
    validate_module(module)?;
    match (module.target().operating_system, format) {
        (OperatingSystem::Linux, ObjectFormat::Elf64) => emit_elf(module, max_bytes),
        (OperatingSystem::Macos, ObjectFormat::MachO64) => emit_macho(module, max_bytes),
        _ => Err(ObjectError::UnsupportedTarget),
    }
}

fn validate_module(module: &CompiledModule) -> Result<(), ObjectError> {
    let target = module.target();
    match target.architecture {
        Architecture::X86_64 | Architecture::Aarch64 => {}
    }
    if module.sections().is_empty() {
        return Err(invalid("module has no sections"));
    }
    if module.sections().len() > usize::from(u8::MAX) {
        return Err(invalid("too many object sections"));
    }

    let mut text_sections = 0_usize;
    let mut data_sections = 0_usize;
    for (index, section) in module.sections().iter().enumerate() {
        validate_name(section.name, "section name")?;
        validate_alignment(section.alignment)?;
        match section.kind {
            SectionKind::Text => text_sections = checked_add(text_sections, 1, "text sections")?,
            SectionKind::ReadOnlyData => {
                data_sections = checked_add(data_sections, 1, "data sections")?;
            }
        }
        for previous in &module.sections()[..index] {
            if previous.name == section.name {
                return Err(invalid("duplicate section name"));
            }
        }
    }
    if text_sections != 1 || data_sections != 1 {
        return Err(invalid(
            "module must contain one text and one read-only data section",
        ));
    }

    for (index, symbol) in module.symbols().iter().enumerate() {
        validate_name(&symbol.name, "symbol name")?;
        if let Some(section_index) = symbol.section {
            let section = module
                .sections()
                .get(section_index)
                .ok_or_else(|| invalid("symbol section index"))?;
            let end = checked_u64_add(symbol.offset, symbol.size, "symbol extent")?;
            let section_len = u64_from_usize(section.data.len(), "section length")?;
            if end > section_len {
                return Err(invalid("symbol outside section"));
            }
        } else {
            if symbol.binding != SymbolBinding::Global {
                return Err(invalid("undefined local symbol"));
            }
            if symbol.offset != 0 || symbol.size != 0 {
                return Err(invalid("undefined symbol value"));
            }
        }
        for previous in &module.symbols()[..index] {
            if previous.name == symbol.name {
                return Err(invalid("duplicate symbol name"));
            }
        }
    }

    for relocation in module.relocations() {
        let section = module
            .sections()
            .get(relocation.section)
            .ok_or_else(|| invalid("relocation section index"))?;
        module
            .symbols()
            .get(relocation.symbol)
            .ok_or_else(|| invalid("relocation symbol index"))?;
        let end = checked_u64_add(relocation.offset, 4, "relocation extent")?;
        if end > u64_from_usize(section.data.len(), "relocation section length")? {
            return Err(invalid("relocation outside section"));
        }
        if section.kind != SectionKind::Text {
            return Err(invalid("native relocation outside text"));
        }
        let compatible = matches!(
            (target.architecture, relocation.kind),
            (
                Architecture::X86_64,
                RelocationKind::X86PcRelative32 | RelocationKind::X86PltRelative32
            ) | (
                Architecture::Aarch64,
                RelocationKind::Aarch64Page21
                    | RelocationKind::Aarch64PageOff12
                    | RelocationKind::Aarch64Branch26
            )
        );
        if !compatible {
            return Err(invalid("relocation kind does not match architecture"));
        }
    }
    Ok(())
}

fn validate_name(name: &str, at: &'static str) -> Result<(), ObjectError> {
    if name.is_empty() || name.as_bytes().contains(&0) {
        return Err(invalid(at));
    }
    Ok(())
}

fn validate_alignment(alignment: u64) -> Result<(), ObjectError> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(invalid("section alignment"));
    }
    Ok(())
}

// --------------------------------------------------------------------------
// ELF64

const ELF_ET_REL: u16 = 1;
const ELF_EM_X86_64: u16 = 62;
const ELF_EM_AARCH64: u16 = 183;
const ELF_SHT_PROGBITS: u32 = 1;
const ELF_SHT_SYMTAB: u32 = 2;
const ELF_SHT_STRTAB: u32 = 3;
const ELF_SHT_RELA: u32 = 4;
const ELF_SHF_ALLOC: u64 = 0x2;
const ELF_SHF_EXECINSTR: u64 = 0x4;
const ELF_STB_LOCAL: u8 = 0;
const ELF_STB_GLOBAL: u8 = 1;
const ELF_STT_OBJECT: u8 = 1;
const ELF_STT_FUNC: u8 = 2;
const ELF_R_X86_64_PC32: u32 = 2;
const ELF_R_X86_64_PLT32: u32 = 4;
const ELF_R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;
const ELF_R_AARCH64_ADD_ABS_LO12_NC: u32 = 277;
const ELF_R_AARCH64_JUMP26: u32 = 282;

struct ElfSection<'a> {
    name: Cow<'static, str>,
    section_type: u32,
    flags: u64,
    alignment: u64,
    link: u32,
    info: u32,
    entry_size: u64,
    data: Cow<'a, [u8]>,
    name_offset: u32,
    file_offset: u64,
}

struct ElfSymbols {
    data: Vec<u8>,
    strings: Vec<u8>,
    map: Vec<u32>,
    first_global: u32,
}

impl<'a> ElfSection<'a> {
    fn progbits(section: &'a ModuleSection) -> Self {
        let flags = match section.kind {
            SectionKind::Text => ELF_SHF_ALLOC | ELF_SHF_EXECINSTR,
            SectionKind::ReadOnlyData => ELF_SHF_ALLOC,
        };
        Self {
            name: Cow::Borrowed(section.name),
            section_type: ELF_SHT_PROGBITS,
            flags,
            alignment: section.alignment,
            link: 0,
            info: 0,
            entry_size: 0,
            data: Cow::Borrowed(section.data.as_ref()),
            name_offset: 0,
            file_offset: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ElfPreflight {
    object_bytes: usize,
    section_records: usize,
}

fn elf_relocation_count(module: &CompiledModule, section: usize) -> usize {
    module
        .relocations()
        .iter()
        .filter(|relocation| relocation.section == section)
        .count()
}

fn checked_string_table_extent(
    current: usize,
    value_bytes: usize,
    offset_site: &'static str,
    extent_site: &'static str,
) -> Result<usize, ObjectError> {
    u32_from_usize(current, offset_site)?;
    checked_add(
        current,
        checked_add(value_bytes, 1, extent_site)?,
        extent_site,
    )
}

/// Compute the exact ELF extent without constructing a section, symbol, string,
/// or relocation table. This must stay allocation-free: callers use it to
/// reject `max_object_bytes` before any module payload can be cloned.
#[allow(
    clippy::too_many_lines,
    reason = "the allocation-free preflight mirrors canonical ELF section order for exact sizing"
)]
fn preflight_elf(module: &CompiledModule) -> Result<ElfPreflight, ObjectError> {
    let module_section_count = module.sections().len();
    let relocation_section_count = (0..module_section_count)
        .filter(|&section| elf_relocation_count(module, section) != 0)
        .count();
    // Module sections, relocation sections, GNU-stack, symtab, strtab, and
    // shstrtab. The null section is represented only by its header.
    let section_records = checked_add(
        checked_add(
            module_section_count,
            relocation_section_count,
            "ELF preflight relocation sections",
        )?,
        4,
        "ELF preflight section records",
    )?;
    let section_count = checked_add(section_records, 1, "ELF preflight section count")?;
    u16_from_usize(section_count, "ELF preflight section count")?;

    let symbol_records = checked_add(module.symbols().len(), 1, "ELF preflight symbol records")?;
    u32_from_usize(module.symbols().len(), "ELF preflight maximum symbol index")?;
    let symbol_bytes = checked_mul(
        symbol_records,
        ELF_SYMBOL_BYTES,
        "ELF preflight symbol bytes",
    )?;
    let mut symbol_strings = 1_usize;
    for symbol in module.symbols() {
        symbol_strings = checked_string_table_extent(
            symbol_strings,
            symbol.name.len(),
            "ELF preflight symbol string offset",
            "ELF preflight symbol strings",
        )?;
    }

    let mut section_strings = 1_usize;
    for section in module.sections() {
        section_strings = checked_string_table_extent(
            section_strings,
            section.name.len(),
            "ELF preflight section string offset",
            "ELF preflight section strings",
        )?;
    }
    for section_index in 0..module_section_count {
        if elf_relocation_count(module, section_index) == 0 {
            continue;
        }
        let name_bytes = checked_add(
            ".rela".len(),
            module.sections()[section_index].name.len(),
            "ELF preflight relocation section name",
        )?;
        section_strings = checked_string_table_extent(
            section_strings,
            name_bytes,
            "ELF preflight section string offset",
            "ELF preflight section strings",
        )?;
    }
    for name in [".note.GNU-stack", ".symtab", ".strtab", ".shstrtab"] {
        section_strings = checked_string_table_extent(
            section_strings,
            name.len(),
            "ELF preflight section string offset",
            "ELF preflight section strings",
        )?;
    }

    let mut cursor = ELF_HEADER_BYTES;
    for section in module.sections() {
        cursor = align_usize(
            cursor,
            usize_from_u64(section.alignment, "ELF preflight section alignment")?,
        )?;
        cursor = checked_add(
            cursor,
            section.data.len(),
            "ELF preflight module section data",
        )?;
    }
    for section_index in 0..module_section_count {
        let relocations = elf_relocation_count(module, section_index);
        if relocations == 0 {
            continue;
        }
        cursor = align_usize(cursor, 8)?;
        cursor = checked_add(
            cursor,
            checked_mul(
                relocations,
                ELF_RELA_BYTES,
                "ELF preflight relocation bytes",
            )?,
            "ELF preflight relocation section",
        )?;
    }
    // The empty GNU-stack section has unit alignment and no payload.
    cursor = align_usize(cursor, 8)?;
    cursor = checked_add(cursor, symbol_bytes, "ELF preflight symbol table")?;
    cursor = checked_add(cursor, symbol_strings, "ELF preflight string table")?;
    cursor = checked_add(
        cursor,
        section_strings,
        "ELF preflight section string table",
    )?;
    let section_headers_offset = align_usize(cursor, 8)?;
    let object_bytes = checked_add(
        section_headers_offset,
        checked_mul(
            section_count,
            ELF_SECTION_HEADER_BYTES,
            "ELF preflight section headers",
        )?,
        "ELF preflight object bytes",
    )?;
    Ok(ElfPreflight {
        object_bytes,
        section_records,
    })
}

// Keeping the canonical record order visible makes the section-index
// arithmetic easier to audit against the ELF specification.
#[allow(
    clippy::too_many_lines,
    reason = "the canonical ELF record order keeps all checked section indices auditable"
)]
fn emit_elf(module: &CompiledModule, max_bytes: usize) -> Result<Vec<u8>, ObjectError> {
    let preflight = preflight_elf(module)?;
    enforce_object_limit(preflight.object_bytes, max_bytes)?;

    let module_section_count = module.sections().len();
    let mut sections = Vec::new();
    try_reserve_items(
        &mut sections,
        preflight.section_records,
        "ELF section metadata allocation",
    )?;
    for section in module.sections() {
        sections.push(ElfSection::progbits(section));
    }

    let symbols = build_elf_symbols(module)?;

    let mut relocation_groups: Vec<Vec<&ModuleRelocation>> = Vec::new();
    try_reserve_items(
        &mut relocation_groups,
        module_section_count,
        "ELF relocation-group allocation",
    )?;
    for section in 0..module_section_count {
        let count = elf_relocation_count(module, section);
        let mut group = Vec::new();
        try_reserve_items(&mut group, count, "ELF relocation-group entries")?;
        relocation_groups.push(group);
    }
    for relocation in module.relocations() {
        relocation_groups[relocation.section].push(relocation);
    }
    for group in &mut relocation_groups {
        group.sort_by_key(|relocation| {
            (
                relocation.offset,
                relocation.symbol,
                relocation_kind_order(relocation.kind),
                relocation.addend,
            )
        });
    }

    for (target_index, group) in relocation_groups.iter().enumerate() {
        if group.is_empty() {
            continue;
        }
        let mut data = Vec::new();
        let bytes = checked_mul(group.len(), ELF_RELA_BYTES, "ELF relocation bytes")?;
        try_reserve_items(&mut data, bytes, "ELF relocation allocation")?;
        for relocation in group {
            push_u64(&mut data, relocation.offset);
            let symbol = u64::from(
                *symbols
                    .map
                    .get(relocation.symbol)
                    .ok_or_else(|| invalid("ELF relocation symbol map"))?,
            );
            let relocation_type = u64::from(elf_relocation_type(relocation.kind));
            push_u64(&mut data, (symbol << 32) | relocation_type);
            push_i64(&mut data, relocation.addend);
        }
        sections.push(ElfSection {
            name: Cow::Owned(prefixed_string(
                ".rela",
                module.sections()[target_index].name,
                "ELF relocation section name allocation",
            )?),
            section_type: ELF_SHT_RELA,
            flags: 0,
            alignment: 8,
            link: 0,
            info: u32_from_usize(
                checked_add(target_index, 1, "ELF target section index")?,
                "ELF target section index",
            )?,
            entry_size: u64_from_usize(ELF_RELA_BYTES, "ELF RELA entry size")?,
            data: Cow::Owned(data),
            name_offset: 0,
            file_offset: 0,
        });
    }

    sections.push(ElfSection {
        name: Cow::Borrowed(".note.GNU-stack"),
        section_type: ELF_SHT_PROGBITS,
        flags: 0,
        alignment: 1,
        link: 0,
        info: 0,
        entry_size: 0,
        data: Cow::Borrowed(&[]),
        name_offset: 0,
        file_offset: 0,
    });

    let symtab_index = checked_add(sections.len(), 1, "ELF symtab index")?;
    let strtab_index = checked_add(symtab_index, 1, "ELF strtab index")?;
    let shstrtab_index = checked_add(strtab_index, 1, "ELF shstrtab index")?;
    let symtab_index_u32 = u32_from_usize(symtab_index, "ELF symtab index")?;
    let strtab_index_u32 = u32_from_usize(strtab_index, "ELF strtab index")?;
    for section in sections.iter_mut().skip(module_section_count) {
        if section.section_type == ELF_SHT_RELA {
            section.link = symtab_index_u32;
        }
    }
    sections.push(ElfSection {
        name: Cow::Borrowed(".symtab"),
        section_type: ELF_SHT_SYMTAB,
        flags: 0,
        alignment: 8,
        link: strtab_index_u32,
        info: symbols.first_global,
        entry_size: u64_from_usize(ELF_SYMBOL_BYTES, "ELF symbol entry size")?,
        data: Cow::Owned(symbols.data),
        name_offset: 0,
        file_offset: 0,
    });
    sections.push(ElfSection {
        name: Cow::Borrowed(".strtab"),
        section_type: ELF_SHT_STRTAB,
        flags: 0,
        alignment: 1,
        link: 0,
        info: 0,
        entry_size: 0,
        data: Cow::Owned(symbols.strings),
        name_offset: 0,
        file_offset: 0,
    });
    sections.push(ElfSection {
        name: Cow::Borrowed(".shstrtab"),
        section_type: ELF_SHT_STRTAB,
        flags: 0,
        alignment: 1,
        link: 0,
        info: 0,
        entry_size: 0,
        data: Cow::Borrowed(&[]),
        name_offset: 0,
        file_offset: 0,
    });

    let mut section_strings = Vec::new();
    try_reserve_items(&mut section_strings, 1, "ELF section-string allocation")?;
    section_strings.push(0);
    for section in &mut sections {
        section.name_offset = add_string(&mut section_strings, &section.name)?;
    }
    sections
        .get_mut(
            shstrtab_index
                .checked_sub(1)
                .ok_or_else(|| overflow("shstrtab index"))?,
        )
        .ok_or_else(|| invalid("ELF shstrtab section"))?
        .data = Cow::Owned(section_strings);

    let mut cursor = ELF_HEADER_BYTES;
    for section in &mut sections {
        cursor = align_usize(cursor, usize_from_u64(section.alignment, "ELF alignment")?)?;
        section.file_offset = u64_from_usize(cursor, "ELF section offset")?;
        cursor = checked_add(cursor, section.data.len(), "ELF section data")?;
    }
    let section_headers_offset = align_usize(cursor, 8)?;
    let section_count = checked_add(sections.len(), 1, "ELF section count")?;
    let section_headers_bytes = checked_mul(
        section_count,
        ELF_SECTION_HEADER_BYTES,
        "ELF section headers",
    )?;
    let object_bytes = checked_add(
        section_headers_offset,
        section_headers_bytes,
        "ELF object bytes",
    )?;
    if object_bytes != preflight.object_bytes {
        return Err(invalid("ELF preflight layout mismatch"));
    }

    let mut bytes = zeroed_object_bytes(object_bytes, max_bytes)?;
    write_elf_header(
        &mut bytes,
        module.target().architecture,
        section_headers_offset,
        section_count,
        shstrtab_index,
    )?;
    for section in &sections {
        let offset = usize_from_u64(section.file_offset, "ELF section offset")?;
        copy_at(
            &mut bytes,
            offset,
            section.data.as_ref(),
            "ELF section data",
        )?;
    }
    for (index, section) in sections.iter().enumerate() {
        let header_index = checked_add(index, 1, "ELF section header index")?;
        let header_offset = checked_add(
            section_headers_offset,
            checked_mul(
                header_index,
                ELF_SECTION_HEADER_BYTES,
                "ELF section header offset",
            )?,
            "ELF section header offset",
        )?;
        write_elf_section_header(&mut bytes, header_offset, section)?;
    }
    Ok(bytes)
}

fn build_elf_symbols(module: &CompiledModule) -> Result<ElfSymbols, ObjectError> {
    let symbol_count = module.symbols().len();
    let mut ordered = Vec::new();
    try_reserve_items(&mut ordered, symbol_count, "ELF symbol-order allocation")?;
    ordered.extend(
        module
            .symbols()
            .iter()
            .enumerate()
            .filter_map(|(index, symbol)| {
                (symbol.binding == SymbolBinding::Local).then_some(index)
            }),
    );
    let first_global = checked_add(ordered.len(), 1, "ELF first global symbol")?;
    ordered.extend(
        module
            .symbols()
            .iter()
            .enumerate()
            .filter_map(|(index, symbol)| {
                (symbol.binding == SymbolBinding::Global).then_some(index)
            }),
    );

    let mut strings = Vec::new();
    try_reserve_items(&mut strings, 1, "ELF symbol-string allocation")?;
    strings.push(0);
    let symbol_records = checked_add(symbol_count, 1, "ELF symbol records")?;
    let symbol_bytes = checked_mul(symbol_records, ELF_SYMBOL_BYTES, "ELF symbol bytes")?;
    let mut data = Vec::new();
    try_reserve_items(&mut data, symbol_bytes, "ELF symbol-table allocation")?;
    data.resize(ELF_SYMBOL_BYTES, 0);
    let mut map = Vec::new();
    try_reserve_items(&mut map, symbol_count, "ELF symbol-map allocation")?;
    map.resize(symbol_count, 0);
    for (ordered_index, module_index) in ordered.into_iter().enumerate() {
        let symbol = &module.symbols()[module_index];
        let object_index = checked_add(ordered_index, 1, "ELF symbol index")?;
        map[module_index] = u32_from_usize(object_index, "ELF symbol index")?;
        let name = add_string(&mut strings, &symbol.name)?;
        push_u32(&mut data, name);
        let binding = match symbol.binding {
            SymbolBinding::Local => ELF_STB_LOCAL,
            SymbolBinding::Global => ELF_STB_GLOBAL,
        };
        let kind = match symbol.kind {
            SymbolKind::Function => ELF_STT_FUNC,
            SymbolKind::Object => ELF_STT_OBJECT,
        };
        data.push((binding << 4) | kind);
        data.push(0);
        let section = match symbol.section {
            Some(index) => u16_from_usize(
                checked_add(index, 1, "ELF symbol section")?,
                "ELF symbol section",
            )?,
            None => 0,
        };
        push_u16(&mut data, section);
        push_u64(&mut data, symbol.offset);
        push_u64(&mut data, symbol.size);
    }
    Ok(ElfSymbols {
        data,
        strings,
        map,
        first_global: u32_from_usize(first_global, "ELF first global symbol")?,
    })
}

fn elf_relocation_type(kind: RelocationKind) -> u32 {
    match kind {
        RelocationKind::X86PcRelative32 => ELF_R_X86_64_PC32,
        RelocationKind::X86PltRelative32 => ELF_R_X86_64_PLT32,
        RelocationKind::Aarch64Page21 => ELF_R_AARCH64_ADR_PREL_PG_HI21,
        RelocationKind::Aarch64PageOff12 => ELF_R_AARCH64_ADD_ABS_LO12_NC,
        RelocationKind::Aarch64Branch26 => ELF_R_AARCH64_JUMP26,
    }
}

fn write_elf_header(
    bytes: &mut [u8],
    architecture: Architecture,
    section_headers_offset: usize,
    section_count: usize,
    section_strings: usize,
) -> Result<(), ObjectError> {
    copy_at(bytes, 0, b"\x7fELF", "ELF magic")?;
    write_u8(bytes, 4, 2, "ELF class")?;
    write_u8(bytes, 5, 1, "ELF data")?;
    write_u8(bytes, 6, 1, "ELF ident version")?;
    write_u16(bytes, 16, ELF_ET_REL, "ELF type")?;
    let machine = match architecture {
        Architecture::X86_64 => ELF_EM_X86_64,
        Architecture::Aarch64 => ELF_EM_AARCH64,
    };
    write_u16(bytes, 18, machine, "ELF machine")?;
    write_u32(bytes, 20, 1, "ELF version")?;
    write_u64(
        bytes,
        40,
        u64_from_usize(section_headers_offset, "ELF section headers offset")?,
        "ELF section headers offset",
    )?;
    write_u16(bytes, 52, 64, "ELF header size")?;
    write_u16(bytes, 58, 64, "ELF section header size")?;
    write_u16(
        bytes,
        60,
        u16_from_usize(section_count, "ELF section count")?,
        "ELF section count",
    )?;
    write_u16(
        bytes,
        62,
        u16_from_usize(section_strings, "ELF section string index")?,
        "ELF section string index",
    )
}

fn write_elf_section_header(
    bytes: &mut [u8],
    offset: usize,
    section: &ElfSection<'_>,
) -> Result<(), ObjectError> {
    write_u32(bytes, offset, section.name_offset, "ELF section name")?;
    write_u32(
        bytes,
        checked_add(offset, 4, "ELF section type")?,
        section.section_type,
        "ELF section type",
    )?;
    write_u64(
        bytes,
        checked_add(offset, 8, "ELF section flags")?,
        section.flags,
        "ELF section flags",
    )?;
    write_u64(
        bytes,
        checked_add(offset, 24, "ELF section offset")?,
        section.file_offset,
        "ELF section offset",
    )?;
    write_u64(
        bytes,
        checked_add(offset, 32, "ELF section size")?,
        u64_from_usize(section.data.len(), "ELF section size")?,
        "ELF section size",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 40, "ELF section link")?,
        section.link,
        "ELF section link",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 44, "ELF section info")?,
        section.info,
        "ELF section info",
    )?;
    write_u64(
        bytes,
        checked_add(offset, 48, "ELF section alignment")?,
        section.alignment,
        "ELF section alignment",
    )?;
    write_u64(
        bytes,
        checked_add(offset, 56, "ELF section entry size")?,
        section.entry_size,
        "ELF section entry size",
    )
}

// --------------------------------------------------------------------------
// Mach-O 64

const MACH_MAGIC_64: u32 = 0xfeed_facf;
const MACH_CPU_TYPE_X86_64: u32 = 0x0100_0007;
const MACH_CPU_SUBTYPE_X86_64_ALL: u32 = 3;
const MACH_CPU_TYPE_ARM64: u32 = 0x0100_000c;
const MACH_CPU_SUBTYPE_ARM64_ALL: u32 = 0;
const MACH_MH_OBJECT: u32 = 1;
const MACH_LC_SEGMENT_64: u32 = 0x19;
const MACH_LC_SYMTAB: u32 = 0x02;
const MACH_LC_DYSYMTAB: u32 = 0x0b;
const MACH_LC_BUILD_VERSION: u32 = 0x32;
const MACH_PLATFORM_MACOS: u32 = 1;
const MACH_MIN_MACOS_11: u32 = 0x000b_0000;
const MACH_VM_PROT_RWX: u32 = 7;
const MACH_S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const MACH_S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
const MACH_N_EXT: u8 = 0x01;
const MACH_N_SECT: u8 = 0x0e;
const MACH_N_UNDF: u8 = 0x00;
const MACH_X86_RELOC_SIGNED: u8 = 1;
const MACH_X86_RELOC_BRANCH: u8 = 2;
const MACH_ARM64_RELOC_BRANCH26: u8 = 2;
const MACH_ARM64_RELOC_PAGE21: u8 = 3;
const MACH_ARM64_RELOC_PAGEOFF12: u8 = 4;
const MACH_ARM64_RELOC_ADDEND: u8 = 10;

struct MachSection<'a> {
    section_name: &'static str,
    segment_name: &'static str,
    kind: SectionKind,
    alignment_exponent: u32,
    address: u64,
    file_offset: u32,
    relocation_offset: u32,
    data: &'a [u8],
    patches: Vec<MachPatch>,
    relocations: Vec<MachRelocation>,
}

#[derive(Clone, Copy)]
struct MachPatch {
    offset: usize,
    value: i32,
}

#[derive(Clone, Copy)]
struct MachRelocation {
    address: u32,
    info: u32,
    pair_order: u8,
}

struct MachSymbols {
    data: Vec<u8>,
    strings: Vec<u8>,
    map: Vec<u32>,
    local_count: u32,
    external_defined_count: u32,
    undefined_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MachPreflight {
    object_bytes: usize,
    segment_command_bytes: usize,
    load_command_bytes: usize,
    content_start: usize,
}

fn mach_relocation_record_count(relocation: &ModuleRelocation) -> Result<usize, ObjectError> {
    let extra_addend = match relocation.kind {
        RelocationKind::X86PcRelative32 | RelocationKind::X86PltRelative32 => 0,
        RelocationKind::Aarch64Page21
        | RelocationKind::Aarch64PageOff12
        | RelocationKind::Aarch64Branch26 => {
            if relocation.addend != 0 {
                signed_24(relocation.addend)?;
                1
            } else {
                0
            }
        }
    };
    checked_add(1, extra_addend, "Mach preflight relocation records")
}

fn mach_relocations_for_section(
    module: &CompiledModule,
    section: usize,
) -> Result<usize, ObjectError> {
    let mut records = 0_usize;
    for relocation in module
        .relocations()
        .iter()
        .filter(|relocation| relocation.section == section)
    {
        u32_from_u64(relocation.offset, "Mach preflight relocation address")?;
        records = checked_add(
            records,
            mach_relocation_record_count(relocation)?,
            "Mach preflight section relocation records",
        )?;
    }
    u32_from_usize(records, "Mach preflight relocation count")?;
    Ok(records)
}

/// Compute every Mach-O file-table extent before constructing section metadata,
/// symbol tables, relocation vectors, or copied payloads.
fn preflight_macho(module: &CompiledModule) -> Result<MachPreflight, ObjectError> {
    let section_count = module.sections().len();
    let segment_command_bytes = checked_add(
        MACH_SEGMENT_COMMAND_BYTES,
        checked_mul(
            section_count,
            MACH_SECTION_BYTES,
            "Mach preflight section commands",
        )?,
        "Mach preflight segment command",
    )?;
    let load_command_bytes = checked_add(
        checked_add(
            segment_command_bytes,
            MACH_BUILD_VERSION_BYTES,
            "Mach preflight load commands",
        )?,
        checked_add(
            MACH_SYMTAB_COMMAND_BYTES,
            MACH_DYSYMTAB_COMMAND_BYTES,
            "Mach preflight symbol commands",
        )?,
        "Mach preflight load commands",
    )?;
    u32_from_usize(load_command_bytes, "Mach preflight load command bytes")?;
    u32_from_usize(section_count, "Mach preflight section count")?;
    let commands_end = checked_add(
        MACH_HEADER_BYTES,
        load_command_bytes,
        "Mach preflight load commands end",
    )?;
    let content_start = align_usize(commands_end, 16)?;

    let mut virtual_cursor = 0_usize;
    let mut file_cursor = content_start;
    for section in module.sections() {
        let alignment = usize_from_u64(section.alignment, "Mach preflight section alignment")?;
        virtual_cursor = align_usize(virtual_cursor, alignment)?;
        file_cursor = align_usize(file_cursor, alignment)?;
        u64_from_usize(virtual_cursor, "Mach preflight section address")?;
        u32_from_usize(file_cursor, "Mach preflight section offset")?;
        virtual_cursor = checked_add(
            virtual_cursor,
            section.data.len(),
            "Mach preflight virtual section data",
        )?;
        file_cursor = checked_add(
            file_cursor,
            section.data.len(),
            "Mach preflight section data",
        )?;
    }

    file_cursor = align_usize(file_cursor, 4)?;
    for section in 0..section_count {
        let records = mach_relocations_for_section(module, section)?;
        if records == 0 {
            continue;
        }
        u32_from_usize(file_cursor, "Mach preflight relocation table offset")?;
        file_cursor = checked_add(
            file_cursor,
            checked_mul(
                records,
                MACH_RELOCATION_BYTES,
                "Mach preflight relocation table",
            )?,
            "Mach preflight relocation tables",
        )?;
    }

    let symbol_offset = align_usize(file_cursor, 8)?;
    u32_from_usize(symbol_offset, "Mach preflight symbol offset")?;
    u32_from_usize(module.symbols().len(), "Mach preflight symbol count")?;
    let symbol_bytes = checked_mul(
        module.symbols().len(),
        MACH_NLIST_BYTES,
        "Mach preflight symbol bytes",
    )?;
    let string_offset = checked_add(symbol_offset, symbol_bytes, "Mach preflight string offset")?;
    u32_from_usize(string_offset, "Mach preflight string offset")?;
    let mut string_bytes = 1_usize;
    for symbol in module.symbols() {
        let prefix = usize::from(symbol.binding == SymbolBinding::Global);
        let name_bytes = checked_add(prefix, symbol.name.len(), "Mach preflight symbol name")?;
        string_bytes = checked_string_table_extent(
            string_bytes,
            name_bytes,
            "Mach preflight string offset",
            "Mach preflight string table",
        )?;
    }
    u32_from_usize(string_bytes, "Mach preflight string bytes")?;
    let unpadded_bytes = checked_add(string_offset, string_bytes, "Mach preflight object bytes")?;
    let object_bytes = align_usize(unpadded_bytes, 8)?;
    Ok(MachPreflight {
        object_bytes,
        segment_command_bytes,
        load_command_bytes,
        content_start,
    })
}

// Keeping command construction and file layout adjacent makes the checked
// offsets easier to review than a stateful, format-generic writer.
#[allow(
    clippy::too_many_lines,
    reason = "the canonical Mach-O command order keeps all checked file offsets auditable"
)]
fn emit_macho(module: &CompiledModule, max_bytes: usize) -> Result<Vec<u8>, ObjectError> {
    let preflight = preflight_macho(module)?;
    enforce_object_limit(preflight.object_bytes, max_bytes)?;

    let section_count = module.sections().len();
    let segment_command_bytes = preflight.segment_command_bytes;
    let load_command_bytes = preflight.load_command_bytes;
    let commands_end = checked_add(
        MACH_HEADER_BYTES,
        load_command_bytes,
        "Mach load commands end",
    )?;
    let content_start = preflight.content_start;
    if align_usize(commands_end, 16)? != content_start {
        return Err(invalid("Mach preflight command layout mismatch"));
    }

    let mut sections = Vec::new();
    try_reserve_items(
        &mut sections,
        section_count,
        "Mach section metadata allocation",
    )?;
    let mut virtual_cursor = 0_usize;
    let mut file_cursor = content_start;
    for (section_index, section) in module.sections().iter().enumerate() {
        let alignment = usize_from_u64(section.alignment, "Mach section alignment")?;
        virtual_cursor = align_usize(virtual_cursor, alignment)?;
        file_cursor = align_usize(file_cursor, alignment)?;
        let (section_name, segment_name) = match section.kind {
            SectionKind::Text => ("__text", "__TEXT"),
            SectionKind::ReadOnlyData => ("__const", "__TEXT"),
        };
        sections.push(MachSection {
            section_name,
            segment_name,
            kind: section.kind,
            alignment_exponent: section.alignment.trailing_zeros(),
            address: u64_from_usize(virtual_cursor, "Mach section address")?,
            file_offset: u32_from_usize(file_cursor, "Mach section offset")?,
            relocation_offset: 0,
            data: section.data.as_ref(),
            patches: {
                let count = module
                    .relocations()
                    .iter()
                    .filter(|relocation| {
                        relocation.section == section_index
                            && matches!(
                                relocation.kind,
                                RelocationKind::X86PcRelative32 | RelocationKind::X86PltRelative32
                            )
                    })
                    .count();
                let mut patches = Vec::new();
                try_reserve_items(&mut patches, count, "Mach patch allocation")?;
                patches
            },
            relocations: {
                let count = mach_relocations_for_section(module, section_index)?;
                let mut relocations = Vec::new();
                try_reserve_items(
                    &mut relocations,
                    count,
                    "Mach relocation metadata allocation",
                )?;
                relocations
            },
        });
        virtual_cursor = checked_add(
            virtual_cursor,
            section.data.len(),
            "Mach virtual section data",
        )?;
        file_cursor = checked_add(file_cursor, section.data.len(), "Mach section data")?;
    }
    let segment_file_bytes = file_cursor
        .checked_sub(content_start)
        .ok_or_else(|| overflow("Mach segment file size"))?;

    let symbols = build_mach_symbols(module, &sections)?;
    build_mach_relocations(module, &mut sections, &symbols.map)?;

    file_cursor = align_usize(file_cursor, 4)?;
    for section in &mut sections {
        if section.relocations.is_empty() {
            continue;
        }
        section.relocation_offset = u32_from_usize(file_cursor, "Mach relocation table offset")?;
        let relocation_bytes = checked_mul(
            section.relocations.len(),
            MACH_RELOCATION_BYTES,
            "Mach relocation table",
        )?;
        file_cursor = checked_add(file_cursor, relocation_bytes, "Mach relocation table")?;
    }
    let symbol_offset = align_usize(file_cursor, 8)?;
    let string_offset = checked_add(symbol_offset, symbols.data.len(), "Mach string offset")?;
    let unpadded_bytes = checked_add(string_offset, symbols.strings.len(), "Mach object bytes")?;
    let object_bytes = align_usize(unpadded_bytes, 8)?;
    if object_bytes != preflight.object_bytes {
        return Err(invalid("Mach preflight layout mismatch"));
    }

    let mut bytes = zeroed_object_bytes(object_bytes, max_bytes)?;
    write_mach_header(&mut bytes, module.target().architecture, load_command_bytes)?;
    let mut command_offset = MACH_HEADER_BYTES;
    write_mach_segment(
        &mut bytes,
        command_offset,
        segment_command_bytes,
        content_start,
        segment_file_bytes,
        virtual_cursor,
        &sections,
    )?;
    command_offset = checked_add(command_offset, segment_command_bytes, "Mach command offset")?;
    write_mach_build_version(&mut bytes, command_offset)?;
    command_offset = checked_add(
        command_offset,
        MACH_BUILD_VERSION_BYTES,
        "Mach command offset",
    )?;
    write_mach_symtab_command(
        &mut bytes,
        command_offset,
        symbol_offset,
        module.symbols().len(),
        string_offset,
        symbols.strings.len(),
    )?;
    command_offset = checked_add(
        command_offset,
        MACH_SYMTAB_COMMAND_BYTES,
        "Mach command offset",
    )?;
    write_mach_dysymtab_command(&mut bytes, command_offset, &symbols)?;

    for section in &sections {
        let section_offset = usize_from_u32(section.file_offset, "Mach section offset")?;
        copy_at(
            &mut bytes,
            section_offset,
            section.data,
            "Mach section data",
        )?;
        for patch in &section.patches {
            write_i32_vec(
                &mut bytes,
                checked_add(section_offset, patch.offset, "Mach patch offset")?,
                patch.value,
            )?;
        }
        let mut relocation_offset =
            usize_from_u32(section.relocation_offset, "Mach relocation offset")?;
        for relocation in &section.relocations {
            write_u32(
                &mut bytes,
                relocation_offset,
                relocation.address,
                "Mach relocation address",
            )?;
            write_u32(
                &mut bytes,
                checked_add(relocation_offset, 4, "Mach relocation info")?,
                relocation.info,
                "Mach relocation info",
            )?;
            relocation_offset = checked_add(
                relocation_offset,
                MACH_RELOCATION_BYTES,
                "Mach relocation cursor",
            )?;
        }
    }
    copy_at(
        &mut bytes,
        symbol_offset,
        &symbols.data,
        "Mach symbol table",
    )?;
    copy_at(
        &mut bytes,
        string_offset,
        &symbols.strings,
        "Mach string table",
    )?;
    Ok(bytes)
}

fn build_mach_symbols(
    module: &CompiledModule,
    sections: &[MachSection<'_>],
) -> Result<MachSymbols, ObjectError> {
    let symbol_count = module.symbols().len();
    let mut ordered = Vec::new();
    try_reserve_items(&mut ordered, symbol_count, "Mach symbol-order allocation")?;
    ordered.extend(
        module
            .symbols()
            .iter()
            .enumerate()
            .filter_map(|(index, symbol)| {
                (symbol.binding == SymbolBinding::Local && symbol.section.is_some())
                    .then_some(index)
            }),
    );
    let local_count = ordered.len();
    ordered.extend(
        module
            .symbols()
            .iter()
            .enumerate()
            .filter_map(|(index, symbol)| {
                (symbol.binding == SymbolBinding::Global && symbol.section.is_some())
                    .then_some(index)
            }),
    );
    let external_defined_count = ordered
        .len()
        .checked_sub(local_count)
        .ok_or_else(|| overflow("Mach external symbol count"))?;
    ordered.extend(
        module
            .symbols()
            .iter()
            .enumerate()
            .filter_map(|(index, symbol)| symbol.section.is_none().then_some(index)),
    );
    let undefined_count = ordered
        .len()
        .checked_sub(local_count)
        .and_then(|count| count.checked_sub(external_defined_count))
        .ok_or_else(|| overflow("Mach undefined symbol count"))?;

    let mut strings = Vec::new();
    try_reserve_items(&mut strings, 1, "Mach symbol-string allocation")?;
    strings.push(0);
    let mut data = Vec::new();
    let bytes = checked_mul(symbol_count, MACH_NLIST_BYTES, "Mach symbol bytes")?;
    try_reserve_items(&mut data, bytes, "Mach symbol allocation")?;
    let mut map = Vec::new();
    try_reserve_items(&mut map, symbol_count, "Mach symbol-map allocation")?;
    map.resize(symbol_count, 0);
    for (object_index, module_index) in ordered.into_iter().enumerate() {
        let symbol = &module.symbols()[module_index];
        map[module_index] = u32_from_usize(object_index, "Mach symbol index")?;
        let name = add_mach_symbol_string(&mut strings, symbol)?;
        push_u32(&mut data, name);
        let (symbol_type, section_number, value) = match symbol.section {
            Some(section_index) => {
                let section = sections
                    .get(section_index)
                    .ok_or_else(|| invalid("Mach symbol section"))?;
                let external = if symbol.binding == SymbolBinding::Global {
                    MACH_N_EXT
                } else {
                    0
                };
                (
                    MACH_N_SECT | external,
                    u8_from_usize(
                        checked_add(section_index, 1, "Mach symbol section")?,
                        "Mach symbol section",
                    )?,
                    checked_u64_add(section.address, symbol.offset, "Mach symbol value")?,
                )
            }
            None => (MACH_N_UNDF | MACH_N_EXT, 0, 0),
        };
        data.push(symbol_type);
        data.push(section_number);
        push_u16(&mut data, 0);
        push_u64(&mut data, value);
    }
    Ok(MachSymbols {
        data,
        strings,
        map,
        local_count: u32_from_usize(local_count, "Mach local symbols")?,
        external_defined_count: u32_from_usize(
            external_defined_count,
            "Mach external defined symbols",
        )?,
        undefined_count: u32_from_usize(undefined_count, "Mach undefined symbols")?,
    })
}

// Pair ordering and target-specific relocation translation are intentionally
// adjacent: splitting them makes Mach-O ADDEND ordering much harder to audit.
#[allow(
    clippy::too_many_lines,
    reason = "relocation expansion and Mach-O pair ordering must remain visibly adjacent"
)]
fn build_mach_relocations(
    module: &CompiledModule,
    sections: &mut [MachSection<'_>],
    symbol_map: &[u32],
) -> Result<(), ObjectError> {
    for relocation in module.relocations() {
        let symbol = &module.symbols()[relocation.symbol];
        let object_symbol = *symbol_map
            .get(relocation.symbol)
            .ok_or_else(|| invalid("Mach relocation symbol map"))?;
        let source_address = sections
            .get(relocation.section)
            .ok_or_else(|| invalid("Mach relocation section"))?;
        let source_address = source_address.address;
        let address = u32_from_u64(relocation.offset, "Mach relocation address")?;
        match relocation.kind {
            RelocationKind::X86PcRelative32 | RelocationKind::X86PltRelative32 => {
                let relocation_type = if relocation.kind == RelocationKind::X86PcRelative32 {
                    MACH_X86_RELOC_SIGNED
                } else {
                    MACH_X86_RELOC_BRANCH
                };
                let (target, external, embedded_addend) =
                    if let Some(target_section_index) = symbol.section {
                        if symbol.binding == SymbolBinding::Local {
                            let target_section = sections
                                .get(target_section_index)
                                .ok_or_else(|| invalid("Mach local relocation target"))?;
                            let target = u32_from_usize(
                                checked_add(target_section_index, 1, "Mach section ordinal")?,
                                "Mach section ordinal",
                            )?;
                            let target_value = checked_i128_add(
                                i128::from(target_section.address),
                                i128::from(symbol.offset),
                                "Mach local relocation target",
                            )?;
                            let source_value = checked_i128_add(
                                i128::from(source_address),
                                i128::from(relocation.offset),
                                "Mach local relocation source",
                            )?;
                            let with_addend = checked_i128_add(
                                target_value,
                                i128::from(relocation.addend),
                                "Mach local relocation addend",
                            )?;
                            (
                                target,
                                false,
                                checked_i128_sub(
                                    with_addend,
                                    source_value,
                                    "Mach local relocation displacement",
                                )?,
                            )
                        } else {
                            (
                                object_symbol,
                                true,
                                checked_i128_add(
                                    i128::from(relocation.addend),
                                    i128::from(4),
                                    "Mach external relocation addend",
                                )?,
                            )
                        }
                    } else {
                        (
                            object_symbol,
                            true,
                            checked_i128_add(
                                i128::from(relocation.addend),
                                i128::from(4),
                                "Mach undefined relocation addend",
                            )?,
                        )
                    };
                let embedded = i32::try_from(embedded_addend)
                    .map_err(|_| invalid("Mach x86 relocation addend"))?;
                let section = sections
                    .get_mut(relocation.section)
                    .ok_or_else(|| invalid("Mach relocation section"))?;
                let patch_offset = usize_from_u64(relocation.offset, "Mach x86 relocation offset")?;
                let patch_end = checked_add(
                    patch_offset,
                    core::mem::size_of::<i32>(),
                    "Mach x86 relocation extent",
                )?;
                if patch_end > section.data.len() {
                    return Err(invalid("Mach x86 relocation outside section"));
                }
                section.patches.push(MachPatch {
                    offset: patch_offset,
                    value: embedded,
                });
                section.relocations.push(MachRelocation {
                    address,
                    info: pack_mach_relocation(target, true, 2, external, relocation_type)?,
                    pair_order: 1,
                });
            }
            RelocationKind::Aarch64Page21
            | RelocationKind::Aarch64PageOff12
            | RelocationKind::Aarch64Branch26 => {
                let section = sections
                    .get_mut(relocation.section)
                    .ok_or_else(|| invalid("Mach relocation section"))?;
                if relocation.addend != 0 {
                    let addend = signed_24(relocation.addend)?;
                    section.relocations.push(MachRelocation {
                        address,
                        info: pack_mach_relocation(
                            addend,
                            false,
                            2,
                            false,
                            MACH_ARM64_RELOC_ADDEND,
                        )?,
                        pair_order: 0,
                    });
                }
                let (pc_relative, relocation_type) = match relocation.kind {
                    RelocationKind::Aarch64Page21 => (true, MACH_ARM64_RELOC_PAGE21),
                    RelocationKind::Aarch64PageOff12 => (false, MACH_ARM64_RELOC_PAGEOFF12),
                    RelocationKind::Aarch64Branch26 => (true, MACH_ARM64_RELOC_BRANCH26),
                    RelocationKind::X86PcRelative32 | RelocationKind::X86PltRelative32 => {
                        return Err(invalid("unreachable Mach relocation kind"));
                    }
                };
                // arm64 Mach-O permits an external relocation to a local N_SECT
                // symbol. clang uses this exact representation for cross-section
                // PAGE21/PAGEOFF12 pairs.
                section.relocations.push(MachRelocation {
                    address,
                    info: pack_mach_relocation(
                        object_symbol,
                        pc_relative,
                        2,
                        true,
                        relocation_type,
                    )?,
                    pair_order: 1,
                });
            }
        }
    }
    for section in sections {
        section.relocations.sort_by(|left, right| {
            right
                .address
                .cmp(&left.address)
                .then_with(|| left.pair_order.cmp(&right.pair_order))
                .then_with(|| left.info.cmp(&right.info))
        });
    }
    Ok(())
}

fn pack_mach_relocation(
    symbol: u32,
    pc_relative: bool,
    length: u8,
    external: bool,
    relocation_type: u8,
) -> Result<u32, ObjectError> {
    if symbol > 0x00ff_ffff || length > 3 || relocation_type > 15 {
        return Err(invalid("Mach relocation encoding"));
    }
    Ok(symbol
        | (u32::from(pc_relative) << 24)
        | (u32::from(length) << 25)
        | (u32::from(external) << 27)
        | (u32::from(relocation_type) << 28))
}

fn signed_24(value: i64) -> Result<u32, ObjectError> {
    if !(-0x80_0000..=0x7f_ffff).contains(&value) {
        return Err(invalid("Mach arm64 relocation addend"));
    }
    let encoded = if value < 0 {
        value
            .checked_add(0x100_0000)
            .ok_or_else(|| overflow("Mach arm64 relocation addend"))?
    } else {
        value
    };
    u32::try_from(encoded).map_err(|_| overflow("Mach arm64 relocation addend"))
}

fn write_mach_header(
    bytes: &mut [u8],
    architecture: Architecture,
    load_command_bytes: usize,
) -> Result<(), ObjectError> {
    let (cpu_type, cpu_subtype) = match architecture {
        Architecture::X86_64 => (MACH_CPU_TYPE_X86_64, MACH_CPU_SUBTYPE_X86_64_ALL),
        Architecture::Aarch64 => (MACH_CPU_TYPE_ARM64, MACH_CPU_SUBTYPE_ARM64_ALL),
    };
    write_u32(bytes, 0, MACH_MAGIC_64, "Mach magic")?;
    write_u32(bytes, 4, cpu_type, "Mach CPU type")?;
    write_u32(bytes, 8, cpu_subtype, "Mach CPU subtype")?;
    write_u32(bytes, 12, MACH_MH_OBJECT, "Mach file type")?;
    write_u32(bytes, 16, 4, "Mach load command count")?;
    write_u32(
        bytes,
        20,
        u32_from_usize(load_command_bytes, "Mach load command bytes")?,
        "Mach load command bytes",
    )
}

// A section_64 has twelve independently checked fields; keeping them in one
// routine preserves the format's field order for review.
#[allow(
    clippy::too_many_lines,
    reason = "keeping every section_64 field in format order makes the writer auditable"
)]
fn write_mach_segment(
    bytes: &mut [u8],
    offset: usize,
    command_bytes: usize,
    content_start: usize,
    file_bytes: usize,
    virtual_bytes: usize,
    sections: &[MachSection<'_>],
) -> Result<(), ObjectError> {
    write_u32(bytes, offset, MACH_LC_SEGMENT_64, "Mach segment command")?;
    write_u32(
        bytes,
        checked_add(offset, 4, "Mach segment command size")?,
        u32_from_usize(command_bytes, "Mach segment command size")?,
        "Mach segment command size",
    )?;
    write_u64(
        bytes,
        checked_add(offset, 32, "Mach segment virtual size")?,
        u64_from_usize(virtual_bytes, "Mach segment virtual size")?,
        "Mach segment virtual size",
    )?;
    write_u64(
        bytes,
        checked_add(offset, 40, "Mach segment file offset")?,
        u64_from_usize(content_start, "Mach segment file offset")?,
        "Mach segment file offset",
    )?;
    write_u64(
        bytes,
        checked_add(offset, 48, "Mach segment file size")?,
        u64_from_usize(file_bytes, "Mach segment file size")?,
        "Mach segment file size",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 56, "Mach segment max protection")?,
        MACH_VM_PROT_RWX,
        "Mach segment max protection",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 60, "Mach segment protection")?,
        MACH_VM_PROT_RWX,
        "Mach segment protection",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 64, "Mach segment section count")?,
        u32_from_usize(sections.len(), "Mach segment section count")?,
        "Mach segment section count",
    )?;
    let mut section_offset =
        checked_add(offset, MACH_SEGMENT_COMMAND_BYTES, "Mach section command")?;
    for section in sections {
        write_fixed_name(
            bytes,
            section_offset,
            section.section_name,
            "Mach section name",
        )?;
        write_fixed_name(
            bytes,
            checked_add(section_offset, 16, "Mach segment name")?,
            section.segment_name,
            "Mach segment name",
        )?;
        write_u64(
            bytes,
            checked_add(section_offset, 32, "Mach section address")?,
            section.address,
            "Mach section address",
        )?;
        write_u64(
            bytes,
            checked_add(section_offset, 40, "Mach section size")?,
            u64_from_usize(section.data.len(), "Mach section size")?,
            "Mach section size",
        )?;
        write_u32(
            bytes,
            checked_add(section_offset, 48, "Mach section offset")?,
            section.file_offset,
            "Mach section offset",
        )?;
        write_u32(
            bytes,
            checked_add(section_offset, 52, "Mach section alignment")?,
            section.alignment_exponent,
            "Mach section alignment",
        )?;
        write_u32(
            bytes,
            checked_add(section_offset, 56, "Mach section relocation offset")?,
            section.relocation_offset,
            "Mach section relocation offset",
        )?;
        write_u32(
            bytes,
            checked_add(section_offset, 60, "Mach section relocation count")?,
            u32_from_usize(section.relocations.len(), "Mach relocation count")?,
            "Mach section relocation count",
        )?;
        let flags = match section.kind {
            SectionKind::Text => MACH_S_ATTR_PURE_INSTRUCTIONS | MACH_S_ATTR_SOME_INSTRUCTIONS,
            SectionKind::ReadOnlyData => 0,
        };
        write_u32(
            bytes,
            checked_add(section_offset, 64, "Mach section flags")?,
            flags,
            "Mach section flags",
        )?;
        section_offset = checked_add(section_offset, MACH_SECTION_BYTES, "Mach section command")?;
    }
    Ok(())
}

fn write_mach_build_version(bytes: &mut [u8], offset: usize) -> Result<(), ObjectError> {
    write_u32(
        bytes,
        offset,
        MACH_LC_BUILD_VERSION,
        "Mach build version command",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 4, "Mach build version command size")?,
        u32_from_usize(MACH_BUILD_VERSION_BYTES, "Mach build version command size")?,
        "Mach build version command size",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 8, "Mach platform")?,
        MACH_PLATFORM_MACOS,
        "Mach platform",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 12, "Mach minimum OS")?,
        MACH_MIN_MACOS_11,
        "Mach minimum OS",
    )
}

fn write_mach_symtab_command(
    bytes: &mut [u8],
    offset: usize,
    symbol_offset: usize,
    symbol_count: usize,
    string_offset: usize,
    string_bytes: usize,
) -> Result<(), ObjectError> {
    write_u32(bytes, offset, MACH_LC_SYMTAB, "Mach symtab command")?;
    write_u32(
        bytes,
        checked_add(offset, 4, "Mach symtab command size")?,
        u32_from_usize(MACH_SYMTAB_COMMAND_BYTES, "Mach symtab command size")?,
        "Mach symtab command size",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 8, "Mach symbol offset")?,
        u32_from_usize(symbol_offset, "Mach symbol offset")?,
        "Mach symbol offset",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 12, "Mach symbol count")?,
        u32_from_usize(symbol_count, "Mach symbol count")?,
        "Mach symbol count",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 16, "Mach string offset")?,
        u32_from_usize(string_offset, "Mach string offset")?,
        "Mach string offset",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 20, "Mach string bytes")?,
        u32_from_usize(string_bytes, "Mach string bytes")?,
        "Mach string bytes",
    )
}

fn write_mach_dysymtab_command(
    bytes: &mut [u8],
    offset: usize,
    symbols: &MachSymbols,
) -> Result<(), ObjectError> {
    write_u32(bytes, offset, MACH_LC_DYSYMTAB, "Mach dysymtab command")?;
    write_u32(
        bytes,
        checked_add(offset, 4, "Mach dysymtab command size")?,
        u32_from_usize(MACH_DYSYMTAB_COMMAND_BYTES, "Mach dysymtab command size")?,
        "Mach dysymtab command size",
    )?;
    // ilocalsym is zero.
    write_u32(
        bytes,
        checked_add(offset, 12, "Mach local symbol count")?,
        symbols.local_count,
        "Mach local symbol count",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 16, "Mach external symbol index")?,
        symbols.local_count,
        "Mach external symbol index",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 20, "Mach external symbol count")?,
        symbols.external_defined_count,
        "Mach external symbol count",
    )?;
    let undefined_index = symbols
        .local_count
        .checked_add(symbols.external_defined_count)
        .ok_or_else(|| overflow("Mach undefined symbol index"))?;
    write_u32(
        bytes,
        checked_add(offset, 24, "Mach undefined symbol index")?,
        undefined_index,
        "Mach undefined symbol index",
    )?;
    write_u32(
        bytes,
        checked_add(offset, 28, "Mach undefined symbol count")?,
        symbols.undefined_count,
        "Mach undefined symbol count",
    )
}

// --------------------------------------------------------------------------
// Checked layout and byte writers.

fn relocation_kind_order(kind: RelocationKind) -> u8 {
    match kind {
        RelocationKind::X86PcRelative32 => 0,
        RelocationKind::X86PltRelative32 => 1,
        RelocationKind::Aarch64Page21 => 2,
        RelocationKind::Aarch64PageOff12 => 3,
        RelocationKind::Aarch64Branch26 => 4,
    }
}

fn invalid(detail: &'static str) -> ObjectError {
    ObjectError::InvalidModule(detail)
}

fn overflow(site: &'static str) -> ObjectError {
    ObjectError::ArithmeticOverflow(site)
}

fn resource(required: usize, limit: usize) -> ObjectError {
    ObjectError::Resource {
        resource: CompileResource::ObjectBytes,
        limit,
        required,
    }
}

fn enforce_object_limit(required: usize, limit: usize) -> Result<(), ObjectError> {
    if required > limit {
        Err(resource(required, limit))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ObjectAllocationStats {
    calls: usize,
    requested_bytes: usize,
    largest_request: usize,
}

#[cfg(test)]
std::thread_local! {
    static OBJECT_ALLOCATION_TRACKER:
        std::cell::Cell<Option<ObjectAllocationStats>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn note_object_allocation(bytes: usize) {
    OBJECT_ALLOCATION_TRACKER.with(|tracker| {
        let Some(mut stats) = tracker.get() else {
            return;
        };
        stats.calls = stats.calls.saturating_add(1);
        stats.requested_bytes = stats.requested_bytes.saturating_add(bytes);
        stats.largest_request = stats.largest_request.max(bytes);
        tracker.set(Some(stats));
    });
}

#[cfg(not(test))]
const fn note_object_allocation(_: usize) {}

fn try_reserve_items<T>(
    values: &mut Vec<T>,
    additional: usize,
    allocation_error: &'static str,
) -> Result<(), ObjectError> {
    let requested_bytes = additional
        .checked_mul(core::mem::size_of::<T>())
        .ok_or_else(|| overflow("object allocation byte count"))?;
    note_object_allocation(requested_bytes);
    values
        .try_reserve_exact(additional)
        .map_err(|_| invalid(allocation_error))
}

fn zeroed_object_bytes(required: usize, max_bytes: usize) -> Result<Vec<u8>, ObjectError> {
    let mut bytes = Vec::new();
    note_object_allocation(required);
    bytes
        .try_reserve_exact(required)
        .map_err(|_| resource(required, max_bytes))?;
    // `try_reserve_items` established capacity first, so this initialization
    // cannot trigger another allocation.
    bytes.resize(required, 0);
    Ok(bytes)
}

fn prefixed_string(
    prefix: &str,
    value: &str,
    allocation_error: &'static str,
) -> Result<String, ObjectError> {
    let bytes = checked_add(prefix.len(), value.len(), "object prefixed string bytes")?;
    note_object_allocation(bytes);
    let mut output = String::new();
    output
        .try_reserve_exact(bytes)
        .map_err(|_| invalid(allocation_error))?;
    output.push_str(prefix);
    output.push_str(value);
    Ok(output)
}

fn checked_add(left: usize, right: usize, site: &'static str) -> Result<usize, ObjectError> {
    left.checked_add(right).ok_or_else(|| overflow(site))
}

fn checked_mul(left: usize, right: usize, site: &'static str) -> Result<usize, ObjectError> {
    left.checked_mul(right).ok_or_else(|| overflow(site))
}

fn checked_u64_add(left: u64, right: u64, site: &'static str) -> Result<u64, ObjectError> {
    left.checked_add(right).ok_or_else(|| overflow(site))
}

fn checked_i128_add(left: i128, right: i128, site: &'static str) -> Result<i128, ObjectError> {
    left.checked_add(right).ok_or_else(|| overflow(site))
}

fn checked_i128_sub(left: i128, right: i128, site: &'static str) -> Result<i128, ObjectError> {
    left.checked_sub(right).ok_or_else(|| overflow(site))
}

fn align_usize(value: usize, alignment: usize) -> Result<usize, ObjectError> {
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err(invalid("object alignment"));
    }
    let mask = alignment
        .checked_sub(1)
        .ok_or_else(|| overflow("object alignment mask"))?;
    checked_add(value, mask, "object alignment").map(|sum| sum & !mask)
}

fn u64_from_usize(value: usize, site: &'static str) -> Result<u64, ObjectError> {
    u64::try_from(value).map_err(|_| overflow(site))
}

fn usize_from_u64(value: u64, site: &'static str) -> Result<usize, ObjectError> {
    usize::try_from(value).map_err(|_| overflow(site))
}

fn usize_from_u32(value: u32, site: &'static str) -> Result<usize, ObjectError> {
    usize::try_from(value).map_err(|_| overflow(site))
}

fn u32_from_usize(value: usize, site: &'static str) -> Result<u32, ObjectError> {
    u32::try_from(value).map_err(|_| overflow(site))
}

fn u32_from_u64(value: u64, site: &'static str) -> Result<u32, ObjectError> {
    u32::try_from(value).map_err(|_| overflow(site))
}

fn u16_from_usize(value: usize, site: &'static str) -> Result<u16, ObjectError> {
    u16::try_from(value).map_err(|_| overflow(site))
}

fn u8_from_usize(value: usize, site: &'static str) -> Result<u8, ObjectError> {
    u8::try_from(value).map_err(|_| overflow(site))
}

fn add_string(table: &mut Vec<u8>, value: &str) -> Result<u32, ObjectError> {
    validate_name(value, "object string")?;
    let offset = u32_from_usize(table.len(), "object string offset")?;
    let required = checked_add(value.len(), 1, "object string bytes")?;
    try_reserve_items(table, required, "object string allocation")?;
    table.extend_from_slice(value.as_bytes());
    table.push(0);
    Ok(offset)
}

fn add_mach_symbol_string(
    table: &mut Vec<u8>,
    symbol: &crate::module::ModuleSymbol,
) -> Result<u32, ObjectError> {
    validate_name(&symbol.name, "Mach symbol name")?;
    let offset = u32_from_usize(table.len(), "Mach symbol string offset")?;
    let prefix_bytes = usize::from(symbol.binding == SymbolBinding::Global);
    let required = checked_add(
        checked_add(prefix_bytes, symbol.name.len(), "Mach symbol string bytes")?,
        1,
        "Mach symbol string bytes",
    )?;
    try_reserve_items(table, required, "Mach symbol string allocation")?;
    if prefix_bytes != 0 {
        table.push(b'_');
    }
    table.extend_from_slice(symbol.name.as_bytes());
    table.push(0);
    Ok(offset)
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_i64(bytes: &mut Vec<u8>, value: i64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn copy_at(
    destination: &mut [u8],
    offset: usize,
    source: &[u8],
    site: &'static str,
) -> Result<(), ObjectError> {
    let end = checked_add(offset, source.len(), site)?;
    let output = destination
        .get_mut(offset..end)
        .ok_or_else(|| overflow(site))?;
    output.copy_from_slice(source);
    Ok(())
}

fn write_fixed_name(
    bytes: &mut [u8],
    offset: usize,
    value: &str,
    site: &'static str,
) -> Result<(), ObjectError> {
    if value.len() > 16 || value.as_bytes().contains(&0) {
        return Err(invalid(site));
    }
    copy_at(bytes, offset, value.as_bytes(), site)
}

fn write_u8(
    bytes: &mut [u8],
    offset: usize,
    value: u8,
    site: &'static str,
) -> Result<(), ObjectError> {
    let output = bytes.get_mut(offset).ok_or_else(|| overflow(site))?;
    *output = value;
    Ok(())
}

fn write_u16(
    bytes: &mut [u8],
    offset: usize,
    value: u16,
    site: &'static str,
) -> Result<(), ObjectError> {
    copy_at(bytes, offset, &value.to_le_bytes(), site)
}

fn write_u32(
    bytes: &mut [u8],
    offset: usize,
    value: u32,
    site: &'static str,
) -> Result<(), ObjectError> {
    copy_at(bytes, offset, &value.to_le_bytes(), site)
}

fn write_u64(
    bytes: &mut [u8],
    offset: usize,
    value: u64,
    site: &'static str,
) -> Result<(), ObjectError> {
    copy_at(bytes, offset, &value.to_le_bytes(), site)
}

fn write_i32_vec(bytes: &mut [u8], offset: usize, value: i32) -> Result<(), ObjectError> {
    copy_at(
        bytes,
        offset,
        &value.to_le_bytes(),
        "Mach relocation addend",
    )
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "fixed-width parser tests first prove every table extent before field access"
)]
mod tests {
    use super::*;
    use crate::{CompileMode, CompileRequest, Target, compile};

    const PATTERN: &str = r"(?:[A-Za-z_][A-Za-z0-9_]*::)+item";

    fn module_and_object(target: Target, mode: CompileMode) -> (CompiledModule, Vec<u8>) {
        let compiled = compile(CompileRequest::new(PATTERN, target).mode(mode)).unwrap();
        (compiled.module().clone(), compiled.object().to_vec())
    }

    fn expected_elf_relocation_types(module: &CompiledModule) -> Vec<u32> {
        let section = module
            .relocations()
            .first()
            .expect("object fixture has relocations")
            .section;
        assert!(
            module
                .relocations()
                .iter()
                .all(|relocation| relocation.section == section),
            "the compact parser below audits one relocation section"
        );
        let mut relocations = module.relocations().iter().collect::<Vec<_>>();
        relocations.sort_by_key(|relocation| {
            (
                relocation.offset,
                relocation.symbol,
                relocation_kind_order(relocation.kind),
                relocation.addend,
            )
        });
        relocations
            .into_iter()
            .map(|relocation| match relocation.kind {
                RelocationKind::X86PcRelative32 => ELF_R_X86_64_PC32,
                RelocationKind::X86PltRelative32 => ELF_R_X86_64_PLT32,
                RelocationKind::Aarch64Page21 => ELF_R_AARCH64_ADR_PREL_PG_HI21,
                RelocationKind::Aarch64PageOff12 => ELF_R_AARCH64_ADD_ABS_LO12_NC,
                RelocationKind::Aarch64Branch26 => ELF_R_AARCH64_JUMP26,
            })
            .collect()
    }

    fn expected_mach_relocation_types(module: &CompiledModule) -> Vec<u8> {
        let section = module
            .relocations()
            .first()
            .expect("object fixture has relocations")
            .section;
        assert!(
            module
                .relocations()
                .iter()
                .all(|relocation| relocation.section == section),
            "the compact parser below audits one relocation section"
        );
        let mut records = Vec::new();
        for relocation in module.relocations() {
            let kind = match relocation.kind {
                RelocationKind::X86PcRelative32 => MACH_X86_RELOC_SIGNED,
                RelocationKind::X86PltRelative32 => MACH_X86_RELOC_BRANCH,
                RelocationKind::Aarch64Page21 => MACH_ARM64_RELOC_PAGE21,
                RelocationKind::Aarch64PageOff12 => MACH_ARM64_RELOC_PAGEOFF12,
                RelocationKind::Aarch64Branch26 => MACH_ARM64_RELOC_BRANCH26,
            };
            if matches!(
                relocation.kind,
                RelocationKind::Aarch64Page21
                    | RelocationKind::Aarch64PageOff12
                    | RelocationKind::Aarch64Branch26
            ) && relocation.addend != 0
            {
                records.push((relocation.offset, 0_u8, MACH_ARM64_RELOC_ADDEND));
            }
            records.push((relocation.offset, 1_u8, kind));
        }
        records.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.cmp(&right.2))
        });
        records.into_iter().map(|(_, _, kind)| kind).collect()
    }

    fn expected_mach_symbol_types(module: &CompiledModule) -> Vec<u8> {
        let mut types = Vec::with_capacity(module.symbols().len());
        for (binding, section) in [
            (SymbolBinding::Local, true),
            (SymbolBinding::Global, true),
            (SymbolBinding::Global, false),
        ] {
            types.extend(module.symbols().iter().filter_map(|symbol| {
                (symbol.binding == binding && symbol.section.is_some() == section).then_some(
                    if section {
                        MACH_N_SECT
                            | if binding == SymbolBinding::Global {
                                MACH_N_EXT
                            } else {
                                0
                            }
                    } else {
                        MACH_N_UNDF | MACH_N_EXT
                    },
                )
            }));
        }
        types
    }

    fn track_object_allocations<T>(operation: impl FnOnce() -> T) -> (T, ObjectAllocationStats) {
        OBJECT_ALLOCATION_TRACKER.with(|tracker| {
            assert!(
                tracker
                    .replace(Some(ObjectAllocationStats::default()))
                    .is_none(),
                "object allocation tracking cannot be nested"
            );
        });
        let output = operation();
        let stats = OBJECT_ALLOCATION_TRACKER.with(|tracker| {
            tracker
                .replace(None)
                .expect("object allocation tracker was active")
        });
        (output, stats)
    }

    fn assert_exact_object_limit(target: Target, format: ObjectFormat) {
        let compiled = compile(CompileRequest::new(PATTERN, target).mode(CompileMode::Fast))
            .expect("compile object-limit fixture");
        let expected = compiled.object();
        let exact_limit = expected.len();
        let exact = emit_object(compiled.module(), format, exact_limit)
            .expect("exact object byte limit must succeed");
        assert_eq!(exact, expected);

        let one_less = exact_limit
            .checked_sub(1)
            .expect("relocatable object is nonempty");
        assert_eq!(
            emit_object(compiled.module(), format, one_less),
            Err(ObjectError::Resource {
                resource: CompileResource::ObjectBytes,
                limit: one_less,
                required: exact_limit,
            })
        );
    }

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    fn validate_elf(bytes: &[u8], machine: u16, relocation_types: &[u32]) {
        assert_eq!(&bytes[..4], b"\x7fELF");
        assert_eq!(u16_at(bytes, 16), ELF_ET_REL);
        assert_eq!(u16_at(bytes, 18), machine);
        assert_eq!(
            u16_at(bytes, 58),
            u16::try_from(ELF_SECTION_HEADER_BYTES).unwrap()
        );
        let headers = usize::try_from(u64_at(bytes, 40)).unwrap();
        let count = usize::from(u16_at(bytes, 60));
        assert_eq!(headers + count * ELF_SECTION_HEADER_BYTES, bytes.len());

        let mut found = None;
        for index in 1..count {
            let header = headers + index * ELF_SECTION_HEADER_BYTES;
            let offset = usize::try_from(u64_at(bytes, header + 24)).unwrap();
            let size = usize::try_from(u64_at(bytes, header + 32)).unwrap();
            assert!(offset + size <= headers);
            if u32_at(bytes, header + 4) == ELF_SHT_RELA {
                assert_eq!(
                    u64_at(bytes, header + 56),
                    u64::try_from(ELF_RELA_BYTES).unwrap()
                );
                found = Some((offset, size));
            }
        }
        let (offset, size) = found.expect("text relocation section");
        assert_eq!(size, relocation_types.len() * ELF_RELA_BYTES);
        let actual = (0..relocation_types.len())
            .map(|index| {
                let info = u64_at(bytes, offset + index * ELF_RELA_BYTES + 8);
                u32::try_from(info & u64::from(u32::MAX)).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, relocation_types);
    }

    fn fixed_name(bytes: &[u8], offset: usize) -> &str {
        let field = &bytes[offset..offset + 16];
        let end = field.iter().position(|&byte| byte == 0).unwrap_or(16);
        core::str::from_utf8(&field[..end]).unwrap()
    }

    fn validate_macho(
        bytes: &[u8],
        cpu: u32,
        relocation_types: &[u8],
        expected_symbol_types: &[u8],
    ) {
        assert_eq!(u32_at(bytes, 0), MACH_MAGIC_64);
        assert_eq!(u32_at(bytes, 4), cpu);
        assert_eq!(u32_at(bytes, 12), MACH_MH_OBJECT);
        assert_eq!(u32_at(bytes, 16), 4);
        assert_eq!(u32_at(bytes, 32), MACH_LC_SEGMENT_64);
        assert_eq!(u32_at(bytes, 36), 232);
        let file_offset = usize::try_from(u64_at(bytes, 72)).unwrap();
        let file_size = usize::try_from(u64_at(bytes, 80)).unwrap();
        assert!(file_offset + file_size <= bytes.len());
        assert_eq!(u32_at(bytes, 96), 2);

        let text = 32 + MACH_SEGMENT_COMMAND_BYTES;
        let rodata = text + MACH_SECTION_BYTES;
        assert_eq!(fixed_name(bytes, text), "__text");
        assert_eq!(fixed_name(bytes, rodata), "__const");
        let text_offset = usize::try_from(u32_at(bytes, text + 48)).unwrap();
        let text_size = usize::try_from(u64_at(bytes, text + 40)).unwrap();
        let data_offset = usize::try_from(u32_at(bytes, rodata + 48)).unwrap();
        let data_size = usize::try_from(u64_at(bytes, rodata + 40)).unwrap();
        assert!(text_offset + text_size <= bytes.len());
        assert!(data_offset + data_size <= bytes.len());
        assert!(text_offset + text_size <= data_offset);

        let relocation_offset = usize::try_from(u32_at(bytes, text + 56)).unwrap();
        let relocation_count = usize::try_from(u32_at(bytes, text + 60)).unwrap();
        assert_eq!(relocation_count, relocation_types.len());
        assert!(relocation_offset + relocation_count * MACH_RELOCATION_BYTES <= bytes.len());
        let actual = (0..relocation_count)
            .map(|index| {
                let info = u32_at(bytes, relocation_offset + index * MACH_RELOCATION_BYTES + 4);
                u8::try_from(info >> 28).unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, relocation_types);

        let symtab =
            32 + (MACH_SEGMENT_COMMAND_BYTES + 2 * MACH_SECTION_BYTES) + MACH_BUILD_VERSION_BYTES;
        assert_eq!(u32_at(bytes, symtab), MACH_LC_SYMTAB);
        let symbols = usize::try_from(u32_at(bytes, symtab + 8)).unwrap();
        let symbol_count = usize::try_from(u32_at(bytes, symtab + 12)).unwrap();
        let strings = usize::try_from(u32_at(bytes, symtab + 16)).unwrap();
        let string_size = usize::try_from(u32_at(bytes, symtab + 20)).unwrap();
        assert_eq!(symbol_count, expected_symbol_types.len());
        assert!(symbols + symbol_count * MACH_NLIST_BYTES <= strings);
        assert!(strings + string_size <= bytes.len());
        let actual_symbol_types = (0..symbol_count)
            .map(|index| bytes[symbols + index * MACH_NLIST_BYTES + 4])
            .collect::<Vec<_>>();
        assert_eq!(actual_symbol_types, expected_symbol_types);
    }

    #[test]
    fn elf_headers_sections_symbols_and_relocations_are_self_consistent() {
        for (target, mode, machine) in [
            (Target::x86_64_linux(), CompileMode::Fast, ELF_EM_X86_64),
            (Target::aarch64_linux(), CompileMode::Fast, ELF_EM_AARCH64),
            (
                Target::x86_64_linux(),
                CompileMode::Optimizing,
                ELF_EM_X86_64,
            ),
            (
                Target::aarch64_linux(),
                CompileMode::Optimizing,
                ELF_EM_AARCH64,
            ),
        ] {
            let (module, object) = module_and_object(target, mode);
            let relocation_types = expected_elf_relocation_types(&module);
            validate_elf(&object, machine, &relocation_types);
        }
    }

    #[test]
    fn macho_commands_sections_symbols_and_relocations_are_self_consistent() {
        for (target, mode, cpu) in [
            (
                Target::x86_64_macos(),
                CompileMode::Fast,
                MACH_CPU_TYPE_X86_64,
            ),
            (
                Target::aarch64_macos(),
                CompileMode::Fast,
                MACH_CPU_TYPE_ARM64,
            ),
            (
                Target::x86_64_macos(),
                CompileMode::Optimizing,
                MACH_CPU_TYPE_X86_64,
            ),
            (
                Target::aarch64_macos(),
                CompileMode::Optimizing,
                MACH_CPU_TYPE_ARM64,
            ),
        ] {
            let (module, object) = module_and_object(target, mode);
            let relocation_types = expected_mach_relocation_types(&module);
            let symbol_types = expected_mach_symbol_types(&module);
            validate_macho(
                &object,
                cpu,
                &relocation_types,
                &symbol_types,
            );
        }
    }

    #[test]
    fn exact_and_one_less_object_limits_are_enforced_before_emission() {
        assert_exact_object_limit(Target::x86_64_linux(), ObjectFormat::Elf64);
        assert_exact_object_limit(Target::x86_64_macos(), ObjectFormat::MachO64);
    }

    #[test]
    fn tiny_limits_allocate_nothing_after_large_modules_exist() {
        let compiled = compile(
            CompileRequest::new("a".repeat(16 * 1024), Target::x86_64_linux())
                .mode(CompileMode::Fast),
        )
        .expect("compile large allocation-preflight fixture");
        let macos_module = CompiledModule::lower(compiled.program(), Target::x86_64_macos())
            .expect("lower large Mach-O allocation-preflight fixture");
        let largest_payload = compiled
            .module()
            .sections()
            .iter()
            .chain(macos_module.sections())
            .map(|section| section.data.len())
            .max()
            .expect("fixture modules have sections");
        assert!(
            largest_payload >= 128 * 1024,
            "fixture must contain a meaningfully large immutable section"
        );

        for (module, format) in [
            (compiled.module(), ObjectFormat::Elf64),
            (&macos_module, ObjectFormat::MachO64),
        ] {
            let (result, allocations) = track_object_allocations(|| emit_object(module, format, 1));
            assert!(matches!(
                result,
                Err(ObjectError::Resource {
                    resource: CompileResource::ObjectBytes,
                    limit: 1,
                    required,
                }) if required > largest_payload
            ));
            assert_eq!(
                allocations,
                ObjectAllocationStats::default(),
                "tiny-limit rejection must precede every writer allocation request"
            );
        }
    }
}
