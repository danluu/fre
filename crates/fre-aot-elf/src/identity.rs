use core::fmt;

pub const SEARCH_ENTRY_SYMBOL_PREFIX_V1: &str = "fre_aot_search_entry_v1_";
pub const PAYLOAD_SYMBOL_PREFIX_V1: &str = "fre_aot_payload_v1_";
pub const METADATA_SYMBOL_PREFIX_V1: &str = "fre_aot_metadata_v1_";
pub const EXPORTED_SYMBOL_SCHEMA_VERSION_V1: u16 = 1;
pub const EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1: usize = 64;

const EXPORTED_SYMBOL_STORAGE_BYTES_V1: usize = 96;

macro_rules! identity {
    ($trusted:ident, $claimed:ident, $label:literal) => {
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $trusted(pub(crate) [u8; 32]);

        impl $trusted {
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            #[must_use]
            pub fn matches_claim(self, claim: $claimed) -> bool {
                self.0 == claim.0
            }
        }

        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $claimed(pub(crate) [u8; 32]);

        impl $claimed {
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $trusted {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!($label, "({})"), self)
            }
        }

        impl fmt::Display for $trusted {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_digest(formatter, &self.0)
            }
        }

        impl fmt::Debug for $claimed {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!("Claimed", $label, "({})"), self)
            }
        }

        impl fmt::Display for $claimed {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_digest(formatter, &self.0)
            }
        }
    };
}

identity!(CompileIdentity, ClaimedCompileIdentity, "CompileIdentity");
identity!(ObjectIdentity, ClaimedObjectIdentity, "ObjectIdentity");

/// Binding identities must be nonzero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingIdentityError;

impl fmt::Display for BindingIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FRE ELF binding identity must be nonzero")
    }
}

impl std::error::Error for BindingIdentityError {}

/// Required planner/compiler provenance digest, separate from IR and native
/// artifact identity.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct BindingIdentity(pub(crate) [u8; 32]);

impl BindingIdentity {
    pub fn new(bytes: [u8; 32]) -> Result<Self, BindingIdentityError> {
        if bytes == [0; 32] {
            Err(BindingIdentityError)
        } else {
            Ok(Self(bytes))
        }
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

/// Untrusted binding claim decoded from object metadata.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ClaimedBindingIdentity(pub(crate) [u8; 32]);

impl ClaimedBindingIdentity {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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

/// One allocation-free identity-suffixed ELF symbol name.
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
        let len = prefix_bytes
            .len()
            .checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1)
            .expect("fixed ELF symbol length");
        assert!(len <= EXPORTED_SYMBOL_STORAGE_BYTES_V1);
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

/// Complete hidden ELF namespace for one Search object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportedSymbolsV1 {
    compile_identity: CompileIdentity,
    entry: ExportedSymbolNameV1,
    payload: ExportedSymbolNameV1,
    metadata: ExportedSymbolNameV1,
}

impl ExportedSymbolsV1 {
    #[must_use]
    pub fn for_compile_identity(compile_identity: CompileIdentity) -> Self {
        Self {
            compile_identity,
            entry: ExportedSymbolNameV1::new(SEARCH_ENTRY_SYMBOL_PREFIX_V1, compile_identity),
            payload: ExportedSymbolNameV1::new(PAYLOAD_SYMBOL_PREFIX_V1, compile_identity),
            metadata: ExportedSymbolNameV1::new(METADATA_SYMBOL_PREFIX_V1, compile_identity),
        }
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

    pub fn write_c_declarations(&self, output: &mut impl fmt::Write) -> fmt::Result {
        writeln!(output, "#if defined(__cplusplus)")?;
        writeln!(output, "extern \"C\" {{")?;
        writeln!(output, "#endif")?;
        writeln!(
            output,
            "extern uint64_t {}(const uint8_t *haystack, size_t haystack_len, size_t window_start, size_t window_end, struct fre_aot_search_result_v1 *result);",
            self.entry
        )?;
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

fn write_digest(formatter: &mut fmt::Formatter<'_>, bytes: &[u8; 32]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
