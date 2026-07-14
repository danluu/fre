use std::{env, fmt::Write as _, fs, path::PathBuf};

const MAGIC: &[u8; 8] = b"FREQX64\x01";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1).map(PathBuf::from);
    let bundle_path = arguments
        .next()
        .ok_or("usage: bundle_to_asm BUNDLE ASSEMBLY ENTRIES_C")?;
    let assembly_path = arguments
        .next()
        .ok_or("usage: bundle_to_asm BUNDLE ASSEMBLY ENTRIES_C")?;
    let entries_path = arguments
        .next()
        .ok_or("usage: bundle_to_asm BUNDLE ASSEMBLY ENTRIES_C")?;
    if arguments.next().is_some() {
        return Err("usage: bundle_to_asm BUNDLE ASSEMBLY ENTRIES_C".into());
    }
    let bundle = fs::read(bundle_path)?;
    let images = parse_images(&bundle)?;
    fs::write(assembly_path, assembly(&images)?)?;
    fs::write(entries_path, entries(images.len())?)?;
    println!("images={}", images.len());
    Ok(())
}

fn parse_images(bundle: &[u8]) -> Result<Vec<&[u8]>, Box<dyn std::error::Error>> {
    if bundle.get(..8) != Some(MAGIC) {
        return Err("invalid qualification bundle magic".into());
    }
    let count = usize::try_from(read_u32(bundle, 8)?)?;
    let mut cursor = 12_usize;
    let mut images = Vec::new();
    images.try_reserve_exact(count)?;
    for _ in 0..count {
        let fixed_end = cursor.checked_add(12).ok_or("record offset overflow")?;
        let fixed = bundle.get(cursor..fixed_end).ok_or("truncated record")?;
        let pattern_len = usize::try_from(read_u32(fixed, 4)?)?;
        let image_len = usize::try_from(read_u32(fixed, 8)?)?;
        let image_start = fixed_end
            .checked_add(32)
            .and_then(|offset| offset.checked_add(pattern_len))
            .ok_or("record offset overflow")?;
        let image_end = image_start
            .checked_add(image_len)
            .ok_or("record offset overflow")?;
        images.push(
            bundle
                .get(image_start..image_end)
                .ok_or("truncated image")?,
        );
        cursor = image_end;
    }
    if cursor != bundle.len() {
        return Err("trailing bundle bytes".into());
    }
    Ok(images)
}

fn assembly(images: &[&[u8]]) -> Result<String, std::fmt::Error> {
    let mut output = String::from(".text\n");
    for (index, image) in images.iter().enumerate() {
        writeln!(output, ".p2align 5")?;
        writeln!(output, ".globl _fre_q_{index}")?;
        writeln!(output, "_fre_q_{index}:")?;
        for chunk in image.chunks(16) {
            output.push_str(".byte ");
            for (byte_index, byte) in chunk.iter().enumerate() {
                if byte_index != 0 {
                    output.push(',');
                }
                write!(output, "0x{byte:02x}")?;
            }
            output.push('\n');
        }
    }
    Ok(output)
}

fn entries(count: usize) -> Result<String, std::fmt::Error> {
    let mut output = String::from(
        "#include <stddef.h>\n#include <stdint.h>\n\nstruct native_match;\n\
         typedef uint32_t (*entry_fn)(const uint8_t *, size_t, size_t, size_t, struct native_match *);\n",
    );
    for index in 0..count {
        writeln!(
            output,
            "extern uint32_t fre_q_{index}(const uint8_t *, size_t, size_t, size_t, struct native_match *);"
        )?;
    }
    output.push_str("entry_fn fre_qualified_entries[] = {\n");
    for index in 0..count {
        writeln!(output, "    fre_q_{index},")?;
    }
    output.push_str("};\n");
    writeln!(output, "size_t fre_qualified_entry_count = {count};")?;
    Ok(output)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Box<dyn std::error::Error>> {
    let end = offset.checked_add(4).ok_or("field offset overflow")?;
    let value: [u8; 4] = bytes.get(offset..end).ok_or("truncated u32")?.try_into()?;
    Ok(u32::from_le_bytes(value))
}
