use core::fmt;

use crate::CompileIdentity;

pub const SEARCH_SELECTED_END_ENTRY_SYMBOL_PREFIX_V2: &str =
    "fre_aot_search_selected_end_entry_v2_";
pub const SELECTED_END_PAYLOAD_SYMBOL_PREFIX_V2: &str = "fre_aot_search_selected_end_payload_v2_";
pub const SELECTED_END_METADATA_SYMBOL_PREFIX_V2: &str = "fre_aot_search_selected_end_metadata_v2_";
pub const EXPORTED_SYMBOL_SCHEMA_VERSION_V2: u16 = 2;
pub const EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2: usize = 64;

const EXPORTED_SYMBOL_STORAGE_BYTES_V2: usize = 128;

/// One allocation-free identity-suffixed ELF symbol in the SelectedEnd-v2
/// namespace.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ExportedSymbolNameV2 {
    bytes: [u8; EXPORTED_SYMBOL_STORAGE_BYTES_V2],
    len: usize,
}

impl ExportedSymbolNameV2 {
    fn new(prefix: &str, identity: CompileIdentity) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let mut bytes = [0_u8; EXPORTED_SYMBOL_STORAGE_BYTES_V2];
        let prefix_bytes = prefix.as_bytes();
        let len = prefix_bytes
            .len()
            .checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2)
            .expect("fixed SelectedEnd-v2 ELF symbol length");
        assert!(len <= EXPORTED_SYMBOL_STORAGE_BYTES_V2);
        bytes[..prefix_bytes.len()].copy_from_slice(prefix_bytes);
        for (byte, output) in identity
            .0
            .into_iter()
            .zip(bytes[prefix_bytes.len()..len].chunks_exact_mut(2))
        {
            output[0] = HEX[usize::from(byte >> 4)];
            output[1] = HEX[usize::from(byte & 0x0f)];
        }
        Self { bytes, len }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).expect("canonical ASCII ELF symbol")
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

/// Complete hidden ELF namespace for one SelectedEnd register-return object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportedSymbolsV2 {
    compile_identity: CompileIdentity,
    entry: ExportedSymbolNameV2,
    payload: ExportedSymbolNameV2,
    metadata: ExportedSymbolNameV2,
}

impl ExportedSymbolsV2 {
    #[must_use]
    pub fn for_compile_identity(compile_identity: CompileIdentity) -> Self {
        Self {
            compile_identity,
            entry: ExportedSymbolNameV2::new(
                SEARCH_SELECTED_END_ENTRY_SYMBOL_PREFIX_V2,
                compile_identity,
            ),
            payload: ExportedSymbolNameV2::new(
                SELECTED_END_PAYLOAD_SYMBOL_PREFIX_V2,
                compile_identity,
            ),
            metadata: ExportedSymbolNameV2::new(
                SELECTED_END_METADATA_SYMBOL_PREFIX_V2,
                compile_identity,
            ),
        }
    }

    #[must_use]
    pub const fn compile_identity(&self) -> CompileIdentity {
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

    /// Write exact identity-suffixed declarations with hidden visibility.
    ///
    /// The entry remains a direct four-argument declaration; this emits no
    /// callable alias or function-pointer typedef.
    pub fn write_c_declarations(&self, output: &mut impl fmt::Write) -> fmt::Result {
        writeln!(
            output,
            "#if defined(__GNUC__) || defined(__clang__)\n#define FRE_AOT_SELECTED_END_HIDDEN_V2 __attribute__((visibility(\"hidden\")))\n#else\n#define FRE_AOT_SELECTED_END_HIDDEN_V2\n#endif"
        )?;
        writeln!(output, "#if defined(__cplusplus)")?;
        writeln!(output, "extern \"C\" {{")?;
        writeln!(output, "#endif")?;
        writeln!(
            output,
            "extern size_t {}(const uint8_t *haystack, size_t haystack_len, size_t window_start, size_t window_end) FRE_AOT_SELECTED_END_HIDDEN_V2;",
            self.entry
        )?;
        writeln!(
            output,
            "extern const uint8_t {}[] FRE_AOT_SELECTED_END_HIDDEN_V2;",
            self.payload
        )?;
        writeln!(
            output,
            "extern const struct fre_aot_search_selected_end_metadata_v2 {} FRE_AOT_SELECTED_END_HIDDEN_V2;",
            self.metadata
        )?;
        writeln!(output, "#if defined(__cplusplus)")?;
        writeln!(output, "}}")?;
        writeln!(output, "#endif")?;
        writeln!(output, "#undef FRE_AOT_SELECTED_END_HIDDEN_V2")
    }
}
