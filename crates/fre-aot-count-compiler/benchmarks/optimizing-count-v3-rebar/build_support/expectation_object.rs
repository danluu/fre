//! Minimal deterministic relocatable wrapper for one fixed Count-v3
//! expectation. The implementation object already owns entry/payload/metadata;
//! this disjoint object adds the fourth immutable symbol required by the
//! qualification adopter.

const EXPECTATION_BYTES: usize = 1_144;

const MACH_HEADER_BYTES: usize = 32;
const MACH_SEGMENT_COMMAND_BYTES: usize = 72;
const MACH_SECTION_COMMAND_BYTES: usize = 80;
const MACH_BUILD_VERSION_COMMAND_BYTES: usize = 24;
const MACH_SYMTAB_COMMAND_BYTES: usize = 24;
const MACH_DYSYMTAB_COMMAND_BYTES: usize = 80;
const MACH_LOAD_COMMAND_BYTES: usize = MACH_SEGMENT_COMMAND_BYTES
    + MACH_SECTION_COMMAND_BYTES
    + MACH_BUILD_VERSION_COMMAND_BYTES
    + MACH_SYMTAB_COMMAND_BYTES
    + MACH_DYSYMTAB_COMMAND_BYTES;
const MACH_CONTENT_OFFSET: usize = 320;
const MACH_NLIST_BYTES: usize = 16;

const ELF_HEADER_BYTES: usize = 64;
const ELF_SECTION_HEADER_BYTES: usize = 64;
const ELF_SECTION_HEADERS: usize = 5;
const ELF_SYMBOL_BYTES: usize = 24;
// Use the conventional `.rodata.*` namespace instead of an orphan allocated
// section. Both GNU ld and LLD collect this input into their read-only output
// section; the final link also requests separate code/data PT_LOAD segments.
const ELF_SHSTRTAB: &[u8] = b"\0.rodata.fre.expect\0.symtab\0.strtab\0.shstrtab\0";

const _: () = assert!(MACH_HEADER_BYTES + MACH_LOAD_COMMAND_BYTES <= MACH_CONTENT_OFFSET);
const _: () = assert!(ELF_SHSTRTAB.len() == 46);

pub fn macho(expectation: &[u8], symbol: &str) -> Result<Vec<u8>, String> {
    if expectation.len() != EXPECTATION_BYTES {
        return Err("Count-v3 expectation has an unexpected width".to_string());
    }
    validate_symbol(symbol)?;
    let symbol_offset = align_up(
        MACH_CONTENT_OFFSET
            .checked_add(expectation.len())
            .ok_or("Mach expectation end overflow")?,
        8,
    )?;
    let string_offset = symbol_offset
        .checked_add(MACH_NLIST_BYTES)
        .ok_or("Mach string-table offset overflow")?;
    let string_bytes = 4_usize
        .checked_add(1)
        .and_then(|value| value.checked_add(symbol.len()))
        .and_then(|value| value.checked_add(1))
        .ok_or("Mach string-table size overflow")?;
    let object_bytes = string_offset
        .checked_add(string_bytes)
        .ok_or("Mach object size overflow")?;
    let mut bytes = vec![0_u8; object_bytes];
    let mut writer = Writer::new(&mut bytes);

    writer.u32(0xfeed_facf)?; // MH_MAGIC_64
    writer.u32(0x0100_000c)?; // CPU_TYPE_ARM64
    writer.u32(0)?; // CPU_SUBTYPE_ARM64_ALL
    writer.u32(1)?; // MH_OBJECT
    writer.u32(4)?;
    writer.u32(to_u32(MACH_LOAD_COMMAND_BYTES, "Mach load-command bytes")?)?;
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(0x19)?; // LC_SEGMENT_64
    writer.u32(to_u32(
        MACH_SEGMENT_COMMAND_BYTES + MACH_SECTION_COMMAND_BYTES,
        "Mach segment-command bytes",
    )?)?;
    writer.fixed_name("")?;
    writer.u64(0)?;
    writer.u64(to_u64(expectation.len(), "Mach segment VM bytes")?)?;
    writer.u64(to_u64(MACH_CONTENT_OFFSET, "Mach segment file offset")?)?;
    writer.u64(to_u64(expectation.len(), "Mach segment file bytes")?)?;
    writer.u32(7)?;
    writer.u32(7)?;
    writer.u32(1)?;
    writer.u32(0)?;

    writer.fixed_name("__fre_expect")?;
    writer.fixed_name("__FRE_CONST")?;
    writer.u64(0)?;
    writer.u64(to_u64(expectation.len(), "Mach expectation bytes")?)?;
    writer.u32(to_u32(MACH_CONTENT_OFFSET, "Mach expectation offset")?)?;
    writer.u32(3)?;
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u32(0x1000_0000)?; // S_ATTR_NO_DEAD_STRIP
    writer.u32(0)?;
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(0x32)?; // LC_BUILD_VERSION
    writer.u32(to_u32(
        MACH_BUILD_VERSION_COMMAND_BYTES,
        "Mach build-version bytes",
    )?)?;
    writer.u32(1)?; // PLATFORM_MACOS
    writer.u32(0x000b_0000)?; // macOS 11
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(0x02)?; // LC_SYMTAB
    writer.u32(to_u32(MACH_SYMTAB_COMMAND_BYTES, "Mach symtab bytes")?)?;
    writer.u32(to_u32(symbol_offset, "Mach symbol offset")?)?;
    writer.u32(1)?;
    writer.u32(to_u32(string_offset, "Mach string offset")?)?;
    writer.u32(to_u32(string_bytes, "Mach string bytes")?)?;

    writer.u32(0x0b)?; // LC_DYSYMTAB
    writer.u32(to_u32(MACH_DYSYMTAB_COMMAND_BYTES, "Mach dysymtab bytes")?)?;
    for value in [0_u32, 0, 0, 1, 1, 0] {
        writer.u32(value)?;
    }
    for _ in 0..12 {
        writer.u32(0)?;
    }
    if writer.position() != MACH_HEADER_BYTES + MACH_LOAD_COMMAND_BYTES {
        return Err("Mach load-command layout mismatch".to_string());
    }

    bytes[MACH_CONTENT_OFFSET..MACH_CONTENT_OFFSET + expectation.len()]
        .copy_from_slice(expectation);
    let mut writer = Writer::at(&mut bytes, symbol_offset)?;
    writer.u32(4)?;
    writer.u8(0x1f)?; // N_SECT | N_EXT | N_PEXT
    writer.u8(1)?;
    writer.u16(0)?;
    writer.u64(0)?;
    let mut writer = Writer::at(&mut bytes, string_offset)?;
    writer.u32(0)?;
    writer.u8(b'_')?;
    writer.bytes(symbol.as_bytes())?;
    writer.u8(0)?;
    if writer.position() != string_offset + string_bytes {
        return Err("Mach string-table layout mismatch".to_string());
    }
    Ok(bytes)
}

pub fn elf(expectation: &[u8], symbol: &str) -> Result<Vec<u8>, String> {
    if expectation.len() != EXPECTATION_BYTES {
        return Err("Count-v3 expectation has an unexpected width".to_string());
    }
    validate_symbol(symbol)?;
    let expectation_offset = ELF_HEADER_BYTES;
    let symbol_offset = align_up(
        expectation_offset
            .checked_add(expectation.len())
            .ok_or("ELF expectation end overflow")?,
        8,
    )?;
    let symbol_bytes = ELF_SYMBOL_BYTES * 2;
    let string_offset = symbol_offset
        .checked_add(symbol_bytes)
        .ok_or("ELF string-table offset overflow")?;
    let string_bytes = 1_usize
        .checked_add(symbol.len())
        .and_then(|value| value.checked_add(1))
        .ok_or("ELF string-table bytes overflow")?;
    let shstrtab_offset = string_offset
        .checked_add(string_bytes)
        .ok_or("ELF section-string offset overflow")?;
    let section_header_offset = align_up(
        shstrtab_offset
            .checked_add(ELF_SHSTRTAB.len())
            .ok_or("ELF section-header offset overflow")?,
        8,
    )?;
    let object_bytes = section_header_offset
        .checked_add(ELF_SECTION_HEADER_BYTES * ELF_SECTION_HEADERS)
        .ok_or("ELF object size overflow")?;
    let mut bytes = vec![0_u8; object_bytes];

    {
        let mut writer = Writer::new(&mut bytes);
        writer.bytes(b"\x7fELF")?;
        writer.u8(2)?; // ELFCLASS64
        writer.u8(1)?; // ELFDATA2LSB
        writer.u8(1)?; // EV_CURRENT
        writer.u8(0)?; // ELFOSABI_NONE
        writer.bytes(&[0; 8])?;
        writer.u16(1)?; // ET_REL
        writer.u16(183)?; // EM_AARCH64
        writer.u32(1)?;
        writer.u64(0)?;
        writer.u64(0)?;
        writer.u64(to_u64(section_header_offset, "ELF section-header offset")?)?;
        writer.u32(0)?;
        writer.u16(to_u16(ELF_HEADER_BYTES, "ELF header bytes")?)?;
        writer.u16(0)?;
        writer.u16(0)?;
        writer.u16(to_u16(
            ELF_SECTION_HEADER_BYTES,
            "ELF section-header bytes",
        )?)?;
        writer.u16(to_u16(ELF_SECTION_HEADERS, "ELF section count")?)?;
        writer.u16(4)?;
    }
    bytes[expectation_offset..expectation_offset + expectation.len()].copy_from_slice(expectation);
    {
        let mut writer = Writer::at(&mut bytes, symbol_offset)?;
        writer.bytes(&[0; ELF_SYMBOL_BYTES])?;
        writer.u32(1)?;
        writer.u8(0x11)?; // STB_GLOBAL | STT_OBJECT
        writer.u8(2)?; // STV_HIDDEN
        writer.u16(1)?;
        writer.u64(0)?;
        writer.u64(to_u64(expectation.len(), "ELF expectation symbol bytes")?)?;
    }
    {
        let mut writer = Writer::at(&mut bytes, string_offset)?;
        writer.u8(0)?;
        writer.bytes(symbol.as_bytes())?;
        writer.u8(0)?;
    }
    bytes[shstrtab_offset..shstrtab_offset + ELF_SHSTRTAB.len()].copy_from_slice(ELF_SHSTRTAB);

    let mut writer = Writer::at(&mut bytes, section_header_offset)?;
    writer.bytes(&[0; ELF_SECTION_HEADER_BYTES])?;
    writer.elf_section(1, 1, 0x2, expectation_offset, expectation.len(), 0, 0, 8, 0)?;
    writer.elf_section(
        20,
        2,
        0,
        symbol_offset,
        symbol_bytes,
        3,
        1,
        8,
        ELF_SYMBOL_BYTES,
    )?;
    writer.elf_section(28, 3, 0, string_offset, string_bytes, 0, 0, 1, 0)?;
    writer.elf_section(36, 3, 0, shstrtab_offset, ELF_SHSTRTAB.len(), 0, 0, 1, 0)?;
    if writer.position() != section_header_offset + ELF_SECTION_HEADER_BYTES * ELF_SECTION_HEADERS {
        return Err("ELF section-header layout mismatch".to_string());
    }
    Ok(bytes)
}

fn validate_symbol(symbol: &str) -> Result<(), String> {
    if symbol.is_empty()
        || symbol.len() > 160
        || !symbol
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        Err("expectation symbol is not canonical".to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{EXPECTATION_BYTES, elf};

    const ELF_HEADER_BYTES: usize = 64;
    const ELF_SECTION_HEADER_BYTES: usize = 64;
    const ELF_SYMBOL_BYTES: usize = 24;

    fn u16_at(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("u16 field"))
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 field"))
    }

    fn u64_at(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("u64 field"))
    }

    fn section_offset(bytes: &[u8], index: usize) -> usize {
        let table = usize::try_from(u64_at(bytes, 40)).expect("section-table offset");
        table + index * ELF_SECTION_HEADER_BYTES
    }

    fn section_name(bytes: &[u8], index: usize) -> &str {
        let names_index = usize::from(u16_at(bytes, 62));
        let names = section_offset(bytes, names_index);
        let names_file_offset =
            usize::try_from(u64_at(bytes, names + 24)).expect("section-name file offset");
        let name_offset =
            usize::try_from(u32_at(bytes, section_offset(bytes, index))).expect("section name");
        let start = names_file_offset + name_offset;
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|relative| start + relative)
            .expect("terminated section name");
        std::str::from_utf8(&bytes[start..end]).expect("ASCII section name")
    }

    #[test]
    fn elf_expectation_is_conventional_read_only_input() {
        let expectation = [0x5a; EXPECTATION_BYTES];
        let symbol = "fre_aot_count_expectation_v3_test";
        let object = elf(&expectation, symbol).expect("ELF expectation object");

        assert_eq!(&object[..7], b"\x7fELF\x02\x01\x01");
        assert_eq!(u16_at(&object, 16), 1);
        assert_eq!(u16_at(&object, 18), 183);
        assert_eq!(u16_at(&object, 52), ELF_HEADER_BYTES as u16);
        assert_eq!(u16_at(&object, 58), ELF_SECTION_HEADER_BYTES as u16);
        assert_eq!(u16_at(&object, 60), 5);
        assert_eq!(section_name(&object, 1), ".rodata.fre.expect");

        let expectation_section = section_offset(&object, 1);
        assert_eq!(u32_at(&object, expectation_section + 4), 1);
        assert_eq!(u64_at(&object, expectation_section + 8), 0x2);
        assert_eq!(
            u64_at(&object, expectation_section + 32),
            EXPECTATION_BYTES as u64
        );
        assert_eq!(u64_at(&object, expectation_section + 48), 8);

        let expectation_file_offset =
            usize::try_from(u64_at(&object, expectation_section + 24)).expect("file offset");
        assert_eq!(
            &object[expectation_file_offset..expectation_file_offset + EXPECTATION_BYTES],
            expectation
        );
    }

    #[test]
    fn elf_expectation_symbol_remains_global_hidden_object() {
        let symbol = "fre_aot_count_expectation_v3_test";
        let object = elf(&[0xa5; EXPECTATION_BYTES], symbol).expect("ELF expectation object");
        let symbol_section = section_offset(&object, 2);
        assert_eq!(section_name(&object, 2), ".symtab");
        assert_eq!(
            u64_at(&object, symbol_section + 56),
            ELF_SYMBOL_BYTES as u64
        );
        let symbol_table_offset =
            usize::try_from(u64_at(&object, symbol_section + 24)).expect("symbol-table offset");
        let definition = symbol_table_offset + ELF_SYMBOL_BYTES;
        assert_eq!(u32_at(&object, definition), 1);
        assert_eq!(object[definition + 4], 0x11);
        assert_eq!(object[definition + 5], 2);
        assert_eq!(u16_at(&object, definition + 6), 1);
        assert_eq!(u64_at(&object, definition + 8), 0);
        assert_eq!(u64_at(&object, definition + 16), EXPECTATION_BYTES as u64);

        let string_section = section_offset(&object, 3);
        let string_table_offset =
            usize::try_from(u64_at(&object, string_section + 24)).expect("string-table offset");
        assert_eq!(
            &object[string_table_offset + 1..string_table_offset + 1 + symbol.len()],
            symbol.as_bytes()
        );
    }
}

fn align_up(value: usize, alignment: usize) -> Result<usize, String> {
    let mask = alignment.checked_sub(1).ok_or("zero object alignment")?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or_else(|| "object alignment overflow".to_string())
}

fn to_u64(value: usize, label: &str) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| format!("{label} does not fit u64"))
}

fn to_u32(value: usize, label: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("{label} does not fit u32"))
}

fn to_u16(value: usize, label: &str) -> Result<u16, String> {
    u16::try_from(value).map_err(|_| format!("{label} does not fit u16"))
}

struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn at(bytes: &'a mut [u8], offset: usize) -> Result<Self, String> {
        if offset > bytes.len() {
            return Err("object writer offset is out of bounds".to_string());
        }
        Ok(Self {
            bytes,
            position: offset,
        })
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), String> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or("object writer offset overflow")?;
        self.bytes
            .get_mut(self.position..end)
            .ok_or("object writer destination is out of bounds")?
            .copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), String> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), String> {
        self.bytes(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), String> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), String> {
        self.bytes(&value.to_le_bytes())
    }

    fn fixed_name(&mut self, value: &str) -> Result<(), String> {
        if value.len() > 16 {
            return Err("Mach fixed name is too long".to_string());
        }
        self.bytes(value.as_bytes())?;
        self.bytes(&[0; 16][value.len()..])
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "arguments are the fixed ELF64 section-header fields"
    )]
    fn elf_section(
        &mut self,
        name: u32,
        kind: u32,
        flags: u64,
        offset: usize,
        size: usize,
        link: u32,
        info: u32,
        alignment: u64,
        entry_size: usize,
    ) -> Result<(), String> {
        self.u32(name)?;
        self.u32(kind)?;
        self.u64(flags)?;
        self.u64(0)?;
        self.u64(to_u64(offset, "ELF section offset")?)?;
        self.u64(to_u64(size, "ELF section size")?)?;
        self.u32(link)?;
        self.u32(info)?;
        self.u64(alignment)?;
        self.u64(to_u64(entry_size, "ELF section entry size")?)
    }
}
