//! Qualification-private, source-bound Linux `AArch64` direct-call glue for
//! one exact tag21 `SelectedEnd` register-return implementation.
//!
//! The canonical relocatable emitted here contains exactly one four-instruction
//! wrapper:
//!
//! ```text
//! stp x29, x30, [sp, #-16]!
//! bl  <identity-suffixed SelectedEnd entry>
//! ldp x29, x30, [sp], #16
//! ret
//! ```
//!
//! Its sole relocation is `R_AARCH64_CALL26` at the `bl`. The undefined entry
//! and all generated declarations are hidden and identity-suffixed. There is
//! no function-pointer API, indirect branch, fifth argument, caller-owned
//! result slot, runtime adopter, or production publication path.
//!
//! The bundle also retains deterministic assembly and C declarations plus a
//! signer-free receipt. The receipt records the post-link qualification rules:
//! disassembly must show a direct `bl` to the exact entry and must reject
//! `blr`, a PLT target, any x4 argument, or any result slot. Those are pending
//! proof obligations, not a claim that a final image has already been linked
//! or inspected. Every value in this module grants no runtime or deployment
//! authority.

use core::fmt;
use core::fmt::Write as _;

use fre_aot_elf::{ExportedSymbolsV2, SelectedEndObjectLimitsV2};
use fre_aot_search_contract::selected_end_v2::{
    SEARCH_SELECTED_END_ARGUMENT_COUNT_V2, SEARCH_SELECTED_END_BACKEND_TAG21_V2,
    SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2, SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2,
    SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2, STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2,
    inspect_static_search_selected_end_expectation_v2,
};
use sha2::{Digest, Sha256};

use crate::search_selected_end_expectation_v2::{
    LinuxStaticSearchSelectedEndExpectationBuildErrorV2, LinuxStaticSearchSelectedEndExpectationV2,
    build_linux_static_search_selected_end_expectation_v2,
};
use crate::search_selected_end_v2::{
    LinuxSelectedEndCompileErrorV2, LinuxSelectedEndCompileReceiptInspectionV2,
    LinuxSelectedEndCompiledObjectV2, SelectedEndAotRuntimeAuthorityV2,
};

pub const LINUX_SELECTED_END_DIRECT_GLUE_CODE_BYTES_V2: usize = 16;
pub const LINUX_SELECTED_END_DIRECT_GLUE_INSTRUCTIONS_V2: u16 = 4;
pub const LINUX_SELECTED_END_DIRECT_GLUE_RELOCATIONS_V2: usize = 1;
pub const LINUX_SELECTED_END_DIRECT_GLUE_CALL_OFFSET_V2: u16 = 4;
pub const LINUX_SELECTED_END_QUALIFICATION_RECEIPT_BYTES_V2: usize = 512;
pub const HARD_MAX_LINUX_SELECTED_END_DIRECT_GLUE_OBJECT_BYTES_V2: u64 = 64 << 10;
pub const HARD_MAX_LINUX_SELECTED_END_DIRECT_GLUE_SOURCE_BYTES_V2: u64 = 256 << 10;
pub const HARD_MAX_LINUX_SELECTED_END_DIRECT_HEADER_BYTES_V2: u64 = 64 << 10;

/// `R_AARCH64_CALL26`, whose instruction is necessarily a direct `bl`.
pub const R_AARCH64_CALL26_V2: u32 = 283;

/// Receipt requirement: the final wrapper contains a direct `bl`.
pub const POST_LINK_REQUIRE_DIRECT_BL_V2: u32 = 1 << 0;
/// Receipt requirement: the final wrapper contains no `blr`.
pub const POST_LINK_REJECT_BLR_V2: u32 = 1 << 1;
/// Receipt requirement: the direct call does not resolve through a PLT.
pub const POST_LINK_REJECT_PLT_V2: u32 = 1 << 2;
/// Receipt requirement: the wrapper neither reads nor synthesizes x4.
pub const POST_LINK_REJECT_X4_ARGUMENT_V2: u32 = 1 << 3;
/// Receipt requirement: the wrapper has no caller-owned result slot.
pub const POST_LINK_REJECT_RESULT_SLOT_V2: u32 = 1 << 4;
/// Receipt requirement: entry, payload, and metadata names match one identity.
pub const POST_LINK_REQUIRE_IDENTITY_SUFFIXED_BINDINGS_V2: u32 = 1 << 5;
/// Receipt requirement: all implementation and wrapper bindings are hidden.
pub const POST_LINK_REQUIRE_HIDDEN_BINDINGS_V2: u32 = 1 << 6;

pub const POST_LINK_DISASSEMBLY_REQUIREMENTS_V2: u32 = POST_LINK_REQUIRE_DIRECT_BL_V2
    | POST_LINK_REJECT_BLR_V2
    | POST_LINK_REJECT_PLT_V2
    | POST_LINK_REJECT_X4_ARGUMENT_V2
    | POST_LINK_REJECT_RESULT_SLOT_V2
    | POST_LINK_REQUIRE_IDENTITY_SUFFIXED_BINDINGS_V2
    | POST_LINK_REQUIRE_HIDDEN_BINDINGS_V2;

const GLUE_RECEIPT_SCHEMA_VERSION_V2: u16 = 2;
const GLUE_RECEIPT_MAGIC_V2: [u8; 8] = *b"FRESDG\0\x02";
const GLUE_RECEIPT_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-QUALIFICATION-RECEIPT\0\x02";
const GLUE_OBJECT_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-DIRECT-GLUE-OBJECT\0\x02";
const GLUE_CODE_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-DIRECT-GLUE-CODE\0\x02";
const GLUE_SOURCE_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-DIRECT-GLUE-SOURCE\0\x02";
const GLUE_HEADER_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-DIRECT-HEADER\0\x02";

const RECEIPT_IDENTITIES_OFFSET_V2: usize = 64;
const RECEIPT_CODE_OFFSET_V2: usize = 448;
const RECEIPT_RESERVED_OFFSET_V2: usize = 464;
const RECEIPT_IDENTITY_OFFSET_V2: usize = 480;
const RECEIPT_IDENTITY_COUNT_V2: usize = 12;

const WRAPPER_SYMBOL_PREFIX_V2: &str = "fre_aot_search_selected_end_qualification_direct_v2_";
const EXPECTATION_SYMBOL_PREFIX_V2: &str =
    "fre_aot_search_selected_end_qualification_expectation_v2_";
const SYMBOL_NAME_STORAGE_BYTES_V2: usize = 128;

const ELF_HEADER_BYTES: usize = 64;
const SECTION_HEADER_BYTES: usize = 64;
const SYMBOL_BYTES: usize = 24;
const RELA_BYTES: usize = 24;
const SECTION_COUNT: usize = 8;
const SYMBOL_COUNT: usize = 8;
const FIRST_GLOBAL_SYMBOL: u32 = 3;

const TEXT_SECTION: u16 = 1;
const EXPECTATION_SECTION: u16 = 2;
const STRING_SECTION: u16 = 4;
const SYMBOL_SECTION: u16 = 5;
const SECTION_STRING_SECTION: u16 = 7;

const TEXT_OFFSET: usize = ELF_HEADER_BYTES;
const EXPECTATION_OFFSET: usize = TEXT_OFFSET + LINUX_SELECTED_END_DIRECT_GLUE_CODE_BYTES_V2;
const EXPECTATION_END: usize = EXPECTATION_OFFSET + STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2;

const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LSB: u8 = 1;
const ELF_VERSION_CURRENT: u8 = 1;
const ELF_OS_ABI_SYSV: u8 = 0;
const ELF_RELOCATABLE: u16 = 1;
const ELF_MACHINE_AARCH64: u16 = 183;
const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHF_ALLOC: u64 = 1 << 1;
const SHF_EXECINSTR: u64 = 1 << 2;
const STB_LOCAL_SECTION: u8 = 0x03;
const STB_GLOBAL_OBJECT: u8 = 0x11;
const STB_GLOBAL_FUNCTION: u8 = 0x12;
const STV_HIDDEN: u8 = 2;

const TEXT_SECTION_NAME: &str = ".text.fre_aot_selected_end_direct_v2";
const EXPECTATION_SECTION_NAME: &str = ".rodata.fre_aot_selected_end_expectation_v2";
const RELA_SECTION_NAME: &str = ".rela.text.fre_aot_selected_end_direct_v2";
const STRING_SECTION_NAME: &str = ".strtab";
const SYMBOL_SECTION_NAME: &str = ".symtab";
const GNU_STACK_SECTION_NAME: &str = ".note.GNU-stack";
const SECTION_STRING_SECTION_NAME: &str = ".shstrtab";

pub const LINUX_SELECTED_END_DIRECT_GLUE_CODE_V2: [u8;
    LINUX_SELECTED_END_DIRECT_GLUE_CODE_BYTES_V2] = [
    0xfd, 0x7b, 0xbf, 0xa9, // stp x29, x30, [sp, #-16]!
    0x00, 0x00, 0x00, 0x94, // bl + R_AARCH64_CALL26
    0xfd, 0x7b, 0xc1, 0xa8, // ldp x29, x30, [sp], #16
    0xc0, 0x03, 0x5f, 0xd6, // ret
];

const _: () = assert!(EXPECTATION_OFFSET == 80);
const _: () = assert!(EXPECTATION_END == 688);
const _: () = assert!(RECEIPT_IDENTITIES_OFFSET_V2 + (RECEIPT_IDENTITY_COUNT_V2 * 32) == 448);
const _: () = assert!(RECEIPT_CODE_OFFSET_V2 + LINUX_SELECTED_END_DIRECT_GLUE_CODE_BYTES_V2 == 464);
const _: () = assert!(RECEIPT_RESERVED_OFFSET_V2 + 16 == RECEIPT_IDENTITY_OFFSET_V2);
const _: () =
    assert!(RECEIPT_IDENTITY_OFFSET_V2 + 32 == LINUX_SELECTED_END_QUALIFICATION_RECEIPT_BYTES_V2);
const _: () = assert!(SEARCH_SELECTED_END_ARGUMENT_COUNT_V2 == 4);
const _: () = assert!(SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2 == 0);
const _: () = assert!(SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2 == 0);

macro_rules! identity {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!($label, "({})"), self)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

identity!(
    LinuxSelectedEndDirectGlueObjectIdentityV2,
    "LinuxSelectedEndDirectGlueObjectIdentityV2"
);
identity!(
    LinuxSelectedEndDirectGlueCodeIdentityV2,
    "LinuxSelectedEndDirectGlueCodeIdentityV2"
);
identity!(
    LinuxSelectedEndDirectGlueSourceIdentityV2,
    "LinuxSelectedEndDirectGlueSourceIdentityV2"
);
identity!(
    LinuxSelectedEndDirectHeaderIdentityV2,
    "LinuxSelectedEndDirectHeaderIdentityV2"
);
identity!(
    LinuxSelectedEndCandidateBundleIdentityV2,
    "LinuxSelectedEndCandidateBundleIdentityV2"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndDirectGlueLimitsV2 {
    pub max_object_bytes: u64,
    pub max_source_bytes: u64,
    pub max_header_bytes: u64,
}

impl Default for LinuxSelectedEndDirectGlueLimitsV2 {
    fn default() -> Self {
        Self {
            max_object_bytes: HARD_MAX_LINUX_SELECTED_END_DIRECT_GLUE_OBJECT_BYTES_V2,
            max_source_bytes: HARD_MAX_LINUX_SELECTED_END_DIRECT_GLUE_SOURCE_BYTES_V2,
            max_header_bytes: HARD_MAX_LINUX_SELECTED_END_DIRECT_HEADER_BYTES_V2,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum LinuxSelectedEndDirectGlueErrorV2 {
    Compiler(LinuxSelectedEndCompileErrorV2),
    Expectation(LinuxStaticSearchSelectedEndExpectationBuildErrorV2),
    ResourceLimit {
        resource: &'static str,
        limit: u64,
        required: u64,
    },
    AllocationFailed,
    InvalidGlue {
        at: &'static str,
    },
    SourceBinding {
        at: &'static str,
    },
    InvalidReceipt,
    ArithmeticOverflow {
        at: &'static str,
    },
}

impl fmt::Display for LinuxSelectedEndDirectGlueErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Linux Search SelectedEnd V2 direct glue failed: {self:?}"
        )
    }
}

impl std::error::Error for LinuxSelectedEndDirectGlueErrorV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Compiler(error) => Some(error),
            Self::Expectation(error) => Some(error),
            _ => None,
        }
    }
}

impl From<LinuxSelectedEndCompileErrorV2> for LinuxSelectedEndDirectGlueErrorV2 {
    fn from(value: LinuxSelectedEndCompileErrorV2) -> Self {
        Self::Compiler(value)
    }
}

impl From<LinuxStaticSearchSelectedEndExpectationBuildErrorV2>
    for LinuxSelectedEndDirectGlueErrorV2
{
    fn from(value: LinuxStaticSearchSelectedEndExpectationBuildErrorV2) -> Self {
        Self::Expectation(value)
    }
}

/// One allocation-free exact identity-suffixed symbol name.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct LinuxSelectedEndDirectSymbolNameV2 {
    bytes: [u8; SYMBOL_NAME_STORAGE_BYTES_V2],
    len: usize,
}

impl LinuxSelectedEndDirectSymbolNameV2 {
    fn suffixed(
        prefix: &str,
        identity: &[u8; 32],
    ) -> Result<Self, LinuxSelectedEndDirectGlueErrorV2> {
        let len = prefix
            .len()
            .checked_add(64)
            .ok_or_else(|| overflow("symbol name length"))?;
        if len > SYMBOL_NAME_STORAGE_BYTES_V2 {
            return Err(glue_error("symbol name storage"));
        }
        let mut bytes = [0_u8; SYMBOL_NAME_STORAGE_BYTES_V2];
        bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
        let mut cursor = prefix.len();
        for byte in identity {
            bytes[cursor] = lower_hex(byte >> 4);
            bytes[cursor + 1] = lower_hex(byte & 0x0f);
            cursor = cursor
                .checked_add(2)
                .ok_or_else(|| overflow("symbol name cursor"))?;
        }
        if cursor != len {
            return Err(glue_error("symbol name width"));
        }
        Ok(Self { bytes, len })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).expect("canonical ASCII direct-glue symbol")
    }
}

impl fmt::Debug for LinuxSelectedEndDirectSymbolNameV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LinuxSelectedEndDirectSymbolNameV2")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for LinuxSelectedEndDirectSymbolNameV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Exact wrapper plus P2a implementation namespace for one compile identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndDirectSymbolsV2 {
    compile_identity: [u8; 32],
    wrapper: LinuxSelectedEndDirectSymbolNameV2,
    expectation: LinuxSelectedEndDirectSymbolNameV2,
    entry: LinuxSelectedEndDirectSymbolNameV2,
    payload: LinuxSelectedEndDirectSymbolNameV2,
    metadata: LinuxSelectedEndDirectSymbolNameV2,
}

impl LinuxSelectedEndDirectSymbolsV2 {
    pub fn from_compile_identity_claim(
        compile_identity: &[u8; 32],
    ) -> Result<Self, LinuxSelectedEndDirectGlueErrorV2> {
        Ok(Self {
            compile_identity: *compile_identity,
            wrapper: LinuxSelectedEndDirectSymbolNameV2::suffixed(
                WRAPPER_SYMBOL_PREFIX_V2,
                compile_identity,
            )?,
            expectation: LinuxSelectedEndDirectSymbolNameV2::suffixed(
                EXPECTATION_SYMBOL_PREFIX_V2,
                compile_identity,
            )?,
            entry: LinuxSelectedEndDirectSymbolNameV2::suffixed(
                fre_aot_elf::SEARCH_SELECTED_END_ENTRY_SYMBOL_PREFIX_V2,
                compile_identity,
            )?,
            payload: LinuxSelectedEndDirectSymbolNameV2::suffixed(
                fre_aot_elf::SELECTED_END_PAYLOAD_SYMBOL_PREFIX_V2,
                compile_identity,
            )?,
            metadata: LinuxSelectedEndDirectSymbolNameV2::suffixed(
                fre_aot_elf::SELECTED_END_METADATA_SYMBOL_PREFIX_V2,
                compile_identity,
            )?,
        })
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        &self.compile_identity
    }

    #[must_use]
    pub const fn wrapper(&self) -> &LinuxSelectedEndDirectSymbolNameV2 {
        &self.wrapper
    }

    #[must_use]
    pub const fn expectation(&self) -> &LinuxSelectedEndDirectSymbolNameV2 {
        &self.expectation
    }

    #[must_use]
    pub const fn entry(&self) -> &LinuxSelectedEndDirectSymbolNameV2 {
        &self.entry
    }

    #[must_use]
    pub const fn payload(&self) -> &LinuxSelectedEndDirectSymbolNameV2 {
        &self.payload
    }

    #[must_use]
    pub const fn metadata(&self) -> &LinuxSelectedEndDirectSymbolNameV2 {
        &self.metadata
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }

    /// Emit exact direct declarations. No function-pointer typedef is present.
    pub fn write_c_header(&self, output: &mut impl fmt::Write) -> fmt::Result {
        writeln!(
            output,
            "{}",
            fre_aot_elf::C_SELECTED_END_HEADER_V2.trim_end()
        )?;
        writeln!(
            output,
            "\n#ifndef FRE_AOT_LINUX_SEARCH_SELECTED_END_DIRECT_V2_H"
        )?;
        writeln!(
            output,
            "#define FRE_AOT_LINUX_SEARCH_SELECTED_END_DIRECT_V2_H"
        )?;
        writeln!(
            output,
            "\n#if defined(__GNUC__) || defined(__clang__)\n#define FRE_AOT_SELECTED_END_HIDDEN_V2 __attribute__((visibility(\"hidden\")))\n#else\n#define FRE_AOT_SELECTED_END_HIDDEN_V2\n#endif"
        )?;
        writeln!(
            output,
            "\n#if defined(__cplusplus)\nextern \"C\" {{\n#endif"
        )?;
        writeln!(
            output,
            "extern size_t {}(const uint8_t *haystack, size_t haystack_len, size_t window_start, size_t window_end) FRE_AOT_SELECTED_END_HIDDEN_V2;",
            self.wrapper
        )?;
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
        writeln!(
            output,
            "extern const uint8_t {}[{}] FRE_AOT_SELECTED_END_HIDDEN_V2;",
            self.expectation, STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2
        )?;
        writeln!(output, "#if defined(__cplusplus)\n}}\n#endif")?;
        writeln!(output, "#undef FRE_AOT_SELECTED_END_HIDDEN_V2")?;
        writeln!(
            output,
            "\n#endif /* FRE_AOT_LINUX_SEARCH_SELECTED_END_DIRECT_V2_H */"
        )
    }
}

/// Canonical deterministic assembly source corresponding to the direct glue.
#[derive(Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndDirectGlueSourceV2 {
    bytes: Box<[u8]>,
    identity: LinuxSelectedEndDirectGlueSourceIdentityV2,
}

impl LinuxSelectedEndDirectGlueSourceV2 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes).expect("canonical direct-glue assembly is UTF-8")
    }

    #[must_use]
    pub const fn identity(&self) -> LinuxSelectedEndDirectGlueSourceIdentityV2 {
        self.identity
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }
}

/// Canonical deterministic direct-only C declarations.
#[derive(Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndDirectHeaderV2 {
    bytes: Box<[u8]>,
    identity: LinuxSelectedEndDirectHeaderIdentityV2,
}

impl LinuxSelectedEndDirectHeaderV2 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes).expect("canonical direct-glue header is UTF-8")
    }

    #[must_use]
    pub const fn identity(&self) -> LinuxSelectedEndDirectHeaderIdentityV2 {
        self.identity
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }
}

/// Canonical deterministic `ELF64LE` qualification-private wrapper.
#[derive(Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndDirectGlueObjectV2 {
    bytes: Vec<u8>,
    compile_identity: [u8; 32],
    object_identity: LinuxSelectedEndDirectGlueObjectIdentityV2,
    code_identity: LinuxSelectedEndDirectGlueCodeIdentityV2,
}

impl LinuxSelectedEndDirectGlueObjectV2 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        &self.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> LinuxSelectedEndDirectGlueObjectIdentityV2 {
        self.object_identity
    }

    #[must_use]
    pub const fn code_identity(&self) -> LinuxSelectedEndDirectGlueCodeIdentityV2 {
        self.code_identity
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }

    pub fn symbols(
        &self,
    ) -> Result<LinuxSelectedEndDirectSymbolsV2, LinuxSelectedEndDirectGlueErrorV2> {
        LinuxSelectedEndDirectSymbolsV2::from_compile_identity_claim(&self.compile_identity)
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Explicit post-link disassembly obligations carried by every bundle.
///
/// This is a requirements projection, not evidence that linking or
/// disassembly has happened. A later qualification step must satisfy every
/// bit against the final image before it may issue an observation receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndPostLinkDisassemblyRequirementsV2 {
    flags: u32,
    direct_call_offset: u16,
    relocation_kind: u32,
    observation_complete: bool,
}

impl LinuxSelectedEndPostLinkDisassemblyRequirementsV2 {
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    #[must_use]
    pub const fn direct_call_offset(&self) -> u16 {
        self.direct_call_offset
    }

    #[must_use]
    pub const fn relocation_kind(&self) -> u32 {
        self.relocation_kind
    }

    #[must_use]
    pub const fn requires_direct_bl(&self) -> bool {
        self.flags & POST_LINK_REQUIRE_DIRECT_BL_V2 != 0
    }

    #[must_use]
    pub const fn rejects_blr(&self) -> bool {
        self.flags & POST_LINK_REJECT_BLR_V2 != 0
    }

    #[must_use]
    pub const fn rejects_plt(&self) -> bool {
        self.flags & POST_LINK_REJECT_PLT_V2 != 0
    }

    #[must_use]
    pub const fn rejects_x4_argument(&self) -> bool {
        self.flags & POST_LINK_REJECT_X4_ARGUMENT_V2 != 0
    }

    #[must_use]
    pub const fn rejects_result_slot(&self) -> bool {
        self.flags & POST_LINK_REJECT_RESULT_SLOT_V2 != 0
    }

    #[must_use]
    pub const fn requires_identity_suffixed_bindings(&self) -> bool {
        self.flags & POST_LINK_REQUIRE_IDENTITY_SUFFIXED_BINDINGS_V2 != 0
    }

    #[must_use]
    pub const fn requires_hidden_bindings(&self) -> bool {
        self.flags & POST_LINK_REQUIRE_HIDDEN_BINDINGS_V2 != 0
    }

    /// These requirements alone never constitute final-image evidence.
    #[must_use]
    pub const fn observation_complete(&self) -> bool {
        self.observation_complete
    }
}

/// Strict whole-object inspection of one canonical direct glue object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndDirectGlueInspectionV2<'a> {
    object_bytes: usize,
    compile_identity: [u8; 32],
    expectation_identity: [u8; 32],
    object_identity: LinuxSelectedEndDirectGlueObjectIdentityV2,
    code_identity: LinuxSelectedEndDirectGlueCodeIdentityV2,
    expectation: &'a [u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2],
}

impl<'a> LinuxSelectedEndDirectGlueInspectionV2<'a> {
    #[must_use]
    pub const fn object_bytes(&self) -> usize {
        self.object_bytes
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        &self.compile_identity
    }

    #[must_use]
    pub const fn expectation_identity(&self) -> &[u8; 32] {
        &self.expectation_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> LinuxSelectedEndDirectGlueObjectIdentityV2 {
        self.object_identity
    }

    #[must_use]
    pub const fn code_identity(&self) -> LinuxSelectedEndDirectGlueCodeIdentityV2 {
        self.code_identity
    }

    #[must_use]
    pub const fn expectation(&self) -> &'a [u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2] {
        self.expectation
    }

    pub fn symbols(
        &self,
    ) -> Result<LinuxSelectedEndDirectSymbolsV2, LinuxSelectedEndDirectGlueErrorV2> {
        LinuxSelectedEndDirectSymbolsV2::from_compile_identity_claim(&self.compile_identity)
    }

    #[must_use]
    pub const fn post_link_disassembly_requirements(
        &self,
    ) -> LinuxSelectedEndPostLinkDisassemblyRequirementsV2 {
        canonical_post_link_requirements()
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }
}

/// Signer-free source/object qualification receipt.
///
/// The fixed wire authenticates the complete candidate tuple and records the
/// mandatory post-link disassembly checks. It remains diagnostic-only and
/// cannot prove that those checks have yet run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndQualificationReceiptV2 {
    bytes: [u8; LINUX_SELECTED_END_QUALIFICATION_RECEIPT_BYTES_V2],
}

impl LinuxSelectedEndQualificationReceiptV2 {
    #[must_use]
    pub const fn canonical_bytes(
        &self,
    ) -> &[u8; LINUX_SELECTED_END_QUALIFICATION_RECEIPT_BYTES_V2] {
        &self.bytes
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, LinuxSelectedEndDirectGlueErrorV2> {
        let bytes: [u8; LINUX_SELECTED_END_QUALIFICATION_RECEIPT_BYTES_V2] = bytes
            .try_into()
            .map_err(|_| LinuxSelectedEndDirectGlueErrorV2::InvalidReceipt)?;
        let receipt = Self { bytes };
        if !receipt.authenticates_itself() {
            return Err(LinuxSelectedEndDirectGlueErrorV2::InvalidReceipt);
        }
        Ok(receipt)
    }

    #[must_use]
    pub fn authenticates_itself(&self) -> bool {
        self.bytes[..8] == GLUE_RECEIPT_MAGIC_V2
            && self.bytes[8..10] == GLUE_RECEIPT_SCHEMA_VERSION_V2.to_le_bytes()
            && self.bytes[10..12]
                == crate::search_selected_end_v2::AOT_LINUX_SELECTED_END_COMPILER_VERSION_V2
                    .to_le_bytes()
            && self.bytes[12..16]
                == u32::try_from(LINUX_SELECTED_END_QUALIFICATION_RECEIPT_BYTES_V2)
                    .expect("fixed qualification receipt bytes")
                    .to_le_bytes()
            && self.bytes[16..18]
                == u16::try_from(LINUX_SELECTED_END_DIRECT_GLUE_CODE_BYTES_V2)
                    .expect("fixed direct glue code bytes")
                    .to_le_bytes()
            && self.bytes[18..20]
                == u16::try_from(LINUX_SELECTED_END_DIRECT_GLUE_RELOCATIONS_V2)
                    .expect("fixed direct glue relocation count")
                    .to_le_bytes()
            && self.bytes[20..24] == R_AARCH64_CALL26_V2.to_le_bytes()
            && self.bytes[24] == SEARCH_SELECTED_END_ARGUMENT_COUNT_V2
            && self.bytes[25] == SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2
            && self.bytes[26..28] == SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2.to_le_bytes()
            && self.bytes[28..30] == LINUX_SELECTED_END_DIRECT_GLUE_INSTRUCTIONS_V2.to_le_bytes()
            && self.bytes[30..32] == LINUX_SELECTED_END_DIRECT_GLUE_CALL_OFFSET_V2.to_le_bytes()
            && self.bytes[32..34] == SEARCH_SELECTED_END_BACKEND_TAG21_V2.to_le_bytes()
            && self.bytes[34..36] == SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2.to_le_bytes()
            && self.bytes[36] == 0
            && self.bytes[37] == STV_HIDDEN
            && self.bytes[38..40] == [0; 2]
            && self.bytes[40..44] == POST_LINK_DISASSEMBLY_REQUIREMENTS_V2.to_le_bytes()
            && self.object_bytes() > 0
            && self.object_bytes() <= HARD_MAX_LINUX_SELECTED_END_DIRECT_GLUE_OBJECT_BYTES_V2
            && self.source_bytes() > 0
            && self.source_bytes() <= HARD_MAX_LINUX_SELECTED_END_DIRECT_GLUE_SOURCE_BYTES_V2
            && self.header_bytes() > 0
            && self.header_bytes() <= HARD_MAX_LINUX_SELECTED_END_DIRECT_HEADER_BYTES_V2
            && self.bytes[60..64] == [0; 4]
            && receipt_identities(&self.bytes)
                .iter()
                .all(|identity| *identity != &[0; 32])
            && self.bytes[RECEIPT_CODE_OFFSET_V2..RECEIPT_RESERVED_OFFSET_V2]
                == LINUX_SELECTED_END_DIRECT_GLUE_CODE_V2
            && self.bytes[RECEIPT_RESERVED_OFFSET_V2..RECEIPT_IDENTITY_OFFSET_V2] == [0; 16]
            && digest_with_domain(
                GLUE_RECEIPT_IDENTITY_DOMAIN_V2,
                &self.bytes[..RECEIPT_IDENTITY_OFFSET_V2],
            ) == *self.bundle_identity().as_bytes()
    }

    #[must_use]
    pub fn object_bytes(&self) -> u64 {
        u64::from_le_bytes(
            self.bytes[44..52]
                .try_into()
                .expect("fixed glue object bytes field"),
        )
    }

    #[must_use]
    pub fn source_bytes(&self) -> u64 {
        u64::from(u32::from_le_bytes(
            self.bytes[52..56]
                .try_into()
                .expect("fixed glue source bytes field"),
        ))
    }

    #[must_use]
    pub fn header_bytes(&self) -> u64 {
        u64::from(u32::from_le_bytes(
            self.bytes[56..60]
                .try_into()
                .expect("fixed direct header bytes field"),
        ))
    }

    #[must_use]
    pub fn manifest_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, 64)
    }

    #[must_use]
    pub fn semantic_binding_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, 96)
    }

    #[must_use]
    pub fn artifact_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, 128)
    }

    #[must_use]
    pub fn binding_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, 160)
    }

    #[must_use]
    pub fn compile_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, 192)
    }

    #[must_use]
    pub fn implementation_object_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, 224)
    }

    #[must_use]
    pub fn compiler_receipt_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, 256)
    }

    #[must_use]
    pub fn expectation_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, 288)
    }

    #[must_use]
    pub fn source_identity(&self) -> LinuxSelectedEndDirectGlueSourceIdentityV2 {
        LinuxSelectedEndDirectGlueSourceIdentityV2::new(*fixed_receipt_identity(&self.bytes, 320))
    }

    #[must_use]
    pub fn header_identity(&self) -> LinuxSelectedEndDirectHeaderIdentityV2 {
        LinuxSelectedEndDirectHeaderIdentityV2::new(*fixed_receipt_identity(&self.bytes, 352))
    }

    #[must_use]
    pub fn glue_code_identity(&self) -> LinuxSelectedEndDirectGlueCodeIdentityV2 {
        LinuxSelectedEndDirectGlueCodeIdentityV2::new(*fixed_receipt_identity(&self.bytes, 384))
    }

    #[must_use]
    pub fn glue_object_identity(&self) -> LinuxSelectedEndDirectGlueObjectIdentityV2 {
        LinuxSelectedEndDirectGlueObjectIdentityV2::new(*fixed_receipt_identity(&self.bytes, 416))
    }

    #[must_use]
    pub fn bundle_identity(&self) -> LinuxSelectedEndCandidateBundleIdentityV2 {
        LinuxSelectedEndCandidateBundleIdentityV2::new(*fixed_receipt_identity(
            &self.bytes,
            RECEIPT_IDENTITY_OFFSET_V2,
        ))
    }

    #[must_use]
    pub const fn post_link_disassembly_requirements(
        &self,
    ) -> LinuxSelectedEndPostLinkDisassemblyRequirementsV2 {
        canonical_post_link_requirements()
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }

    pub fn validate_candidate<'a>(
        &self,
        compiled: &LinuxSelectedEndCompiledObjectV2,
        expectation: &LinuxStaticSearchSelectedEndExpectationV2,
        source: &[u8],
        header: &[u8],
        glue_bytes: &'a [u8],
        limits: LinuxSelectedEndDirectGlueLimitsV2,
    ) -> Result<LinuxSelectedEndDirectGlueInspectionV2<'a>, LinuxSelectedEndDirectGlueErrorV2> {
        if !self.authenticates_itself()
            || self.source_bytes() != usize_u64(source.len(), "glue source bytes")?
            || self.header_bytes() != usize_u64(header.len(), "direct header bytes")?
            || self.object_bytes() != usize_u64(glue_bytes.len(), "glue object bytes")?
            || self.source_identity()
                != LinuxSelectedEndDirectGlueSourceIdentityV2::new(length_prefixed_identity(
                    GLUE_SOURCE_IDENTITY_DOMAIN_V2,
                    source,
                ))
            || self.header_identity()
                != LinuxSelectedEndDirectHeaderIdentityV2::new(length_prefixed_identity(
                    GLUE_HEADER_IDENTITY_DOMAIN_V2,
                    header,
                ))
            || self.glue_object_identity()
                != LinuxSelectedEndDirectGlueObjectIdentityV2::new(digest_with_domain(
                    GLUE_OBJECT_IDENTITY_DOMAIN_V2,
                    glue_bytes,
                ))
        {
            return Err(LinuxSelectedEndDirectGlueErrorV2::InvalidReceipt);
        }
        let binding = authenticate_source(compiled, expectation)?;
        let generated_source =
            generate_assembly_source(&binding.symbols, expectation.as_bytes(), limits)?;
        let generated_header = generate_c_header(&binding.symbols, limits)?;
        let inspection =
            inspect_linux_selected_end_direct_glue_v2(glue_bytes, expectation.as_bytes(), limits)?;
        if source != generated_source.as_bytes()
            || header != generated_header.as_bytes()
            || self.manifest_identity() != &binding.manifest_identity
            || self.semantic_binding_identity() != &binding.semantic_binding_identity
            || self.artifact_identity() != &binding.artifact_identity
            || self.binding_identity() != &binding.binding_identity
            || self.compile_identity() != &binding.compile_identity
            || self.implementation_object_identity() != &binding.implementation_object_identity
            || self.compiler_receipt_identity() != &binding.compiler_receipt_identity
            || self.expectation_identity() != &binding.expectation_identity
            || self.source_identity() != generated_source.identity()
            || self.header_identity() != generated_header.identity()
            || self.glue_code_identity() != inspection.code_identity()
            || self.glue_object_identity() != inspection.object_identity()
        {
            return Err(LinuxSelectedEndDirectGlueErrorV2::InvalidReceipt);
        }
        Ok(inspection)
    }

    /// Reopen every persisted artifact independently and correlate the whole
    /// diagnostic candidate. Success still grants no call authority.
    #[allow(
        clippy::too_many_arguments,
        reason = "all independently persisted artifacts are explicit qualification inputs"
    )]
    pub fn validate_reopened_candidate<'a>(
        &self,
        compiler_receipt: &LinuxSelectedEndCompileReceiptInspectionV2,
        implementation_bytes: &[u8],
        expectation_bytes: &[u8],
        source: &[u8],
        header: &[u8],
        glue_bytes: &'a [u8],
        object_limits: SelectedEndObjectLimitsV2,
        glue_limits: LinuxSelectedEndDirectGlueLimitsV2,
    ) -> Result<LinuxSelectedEndDirectGlueInspectionV2<'a>, LinuxSelectedEndDirectGlueErrorV2> {
        if !self.authenticates_itself()
            || compiler_receipt.runtime_authority() != SelectedEndAotRuntimeAuthorityV2::Absent
            || self.source_bytes() != usize_u64(source.len(), "glue source bytes")?
            || self.header_bytes() != usize_u64(header.len(), "direct header bytes")?
            || self.object_bytes() != usize_u64(glue_bytes.len(), "glue object bytes")?
            || self.source_identity()
                != LinuxSelectedEndDirectGlueSourceIdentityV2::new(length_prefixed_identity(
                    GLUE_SOURCE_IDENTITY_DOMAIN_V2,
                    source,
                ))
            || self.header_identity()
                != LinuxSelectedEndDirectHeaderIdentityV2::new(length_prefixed_identity(
                    GLUE_HEADER_IDENTITY_DOMAIN_V2,
                    header,
                ))
            || self.glue_object_identity()
                != LinuxSelectedEndDirectGlueObjectIdentityV2::new(digest_with_domain(
                    GLUE_OBJECT_IDENTITY_DOMAIN_V2,
                    glue_bytes,
                ))
        {
            return Err(LinuxSelectedEndDirectGlueErrorV2::InvalidReceipt);
        }
        compiler_receipt.validate_object(implementation_bytes, object_limits)?;
        let expectation_claim = compiler_receipt.validate_expectation(expectation_bytes)?;
        let compile_identity = *compiler_receipt.compile_identity();
        let symbols =
            LinuxSelectedEndDirectSymbolsV2::from_compile_identity_claim(&compile_identity)?;
        let generated_source = generate_assembly_source(&symbols, expectation_bytes, glue_limits)?;
        let generated_header = generate_c_header(&symbols, glue_limits)?;
        let inspection =
            inspect_linux_selected_end_direct_glue_v2(glue_bytes, expectation_bytes, glue_limits)?;
        if source != generated_source.as_bytes()
            || header != generated_header.as_bytes()
            || self.manifest_identity() != compiler_receipt.manifest_identity()
            || self.semantic_binding_identity() != compiler_receipt.semantic_binding_identity()
            || self.artifact_identity() != compiler_receipt.artifact_identity()
            || self.binding_identity() != compiler_receipt.binding_identity()
            || self.compile_identity() != compiler_receipt.compile_identity()
            || self.implementation_object_identity() != compiler_receipt.object_identity()
            || self.compiler_receipt_identity() != compiler_receipt.receipt_identity().as_bytes()
            || self.expectation_identity() != expectation_claim.expectation_identity()
            || self.source_identity() != generated_source.identity()
            || self.header_identity() != generated_header.identity()
            || self.glue_code_identity() != inspection.code_identity()
            || self.glue_object_identity() != inspection.object_identity()
            || inspection.compile_identity() != &compile_identity
        {
            return Err(LinuxSelectedEndDirectGlueErrorV2::InvalidReceipt);
        }
        Ok(inspection)
    }
}

/// Complete deterministic qualification candidate.
#[derive(Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndQualificationBundleV2 {
    compiled: LinuxSelectedEndCompiledObjectV2,
    expectation: LinuxStaticSearchSelectedEndExpectationV2,
    source: LinuxSelectedEndDirectGlueSourceV2,
    header: LinuxSelectedEndDirectHeaderV2,
    glue: LinuxSelectedEndDirectGlueObjectV2,
    receipt: LinuxSelectedEndQualificationReceiptV2,
}

impl LinuxSelectedEndQualificationBundleV2 {
    #[must_use]
    pub const fn compiled(&self) -> &LinuxSelectedEndCompiledObjectV2 {
        &self.compiled
    }

    #[must_use]
    pub const fn expectation(&self) -> &LinuxStaticSearchSelectedEndExpectationV2 {
        &self.expectation
    }

    #[must_use]
    pub const fn source(&self) -> &LinuxSelectedEndDirectGlueSourceV2 {
        &self.source
    }

    #[must_use]
    pub const fn header(&self) -> &LinuxSelectedEndDirectHeaderV2 {
        &self.header
    }

    #[must_use]
    pub const fn glue(&self) -> &LinuxSelectedEndDirectGlueObjectV2 {
        &self.glue
    }

    #[must_use]
    pub const fn receipt(&self) -> &LinuxSelectedEndQualificationReceiptV2 {
        &self.receipt
    }

    #[must_use]
    pub fn bundle_identity(&self) -> LinuxSelectedEndCandidateBundleIdentityV2 {
        self.receipt.bundle_identity()
    }

    #[must_use]
    pub const fn post_link_disassembly_requirements(
        &self,
    ) -> LinuxSelectedEndPostLinkDisassemblyRequirementsV2 {
        canonical_post_link_requirements()
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }

    pub fn validate(
        &self,
        limits: LinuxSelectedEndDirectGlueLimitsV2,
    ) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
        self.receipt.validate_candidate(
            &self.compiled,
            &self.expectation,
            self.source.as_bytes(),
            self.header.as_bytes(),
            self.glue.as_bytes(),
            limits,
        )?;
        Ok(())
    }

    #[must_use]
    pub fn into_compiled(self) -> LinuxSelectedEndCompiledObjectV2 {
        self.compiled
    }
}

/// Build one inert, deterministic candidate bundle around an already sealed
/// P2b compilation result.
pub fn build_linux_selected_end_qualification_bundle_v2(
    compiled: LinuxSelectedEndCompiledObjectV2,
    limits: LinuxSelectedEndDirectGlueLimitsV2,
) -> Result<LinuxSelectedEndQualificationBundleV2, LinuxSelectedEndDirectGlueErrorV2> {
    let expectation = build_linux_static_search_selected_end_expectation_v2(&compiled)?;
    let binding = authenticate_source(&compiled, &expectation)?;
    let source = generate_assembly_source(&binding.symbols, expectation.as_bytes(), limits)?;
    let header = generate_c_header(&binding.symbols, limits)?;
    let glue_bytes =
        emit_direct_glue_bytes(expectation.as_bytes(), &binding.compile_identity, limits)?;
    let inspection =
        inspect_linux_selected_end_direct_glue_v2(&glue_bytes, expectation.as_bytes(), limits)?;
    let object_identity = inspection.object_identity();
    let code_identity = inspection.code_identity();
    let glue = LinuxSelectedEndDirectGlueObjectV2 {
        bytes: glue_bytes,
        compile_identity: binding.compile_identity,
        object_identity,
        code_identity,
    };
    let receipt = build_qualification_receipt(binding, &source, &header, &glue)?;
    let bundle = LinuxSelectedEndQualificationBundleV2 {
        compiled,
        expectation,
        source,
        header,
        glue,
        receipt,
    };
    bundle.validate(limits)?;
    Ok(bundle)
}

/// Strictly inspect a direct glue object against its separately persisted
/// expectation. Canonical whole-object regeneration rejects any extra symbol,
/// relocation, section, instruction, padding byte, or visibility change.
pub fn inspect_linux_selected_end_direct_glue_v2<'a>(
    bytes: &'a [u8],
    expectation_bytes: &[u8],
    limits: LinuxSelectedEndDirectGlueLimitsV2,
) -> Result<LinuxSelectedEndDirectGlueInspectionV2<'a>, LinuxSelectedEndDirectGlueErrorV2> {
    enforce_limit(
        "glue object bytes",
        usize_u64(bytes.len(), "glue object bytes")?,
        limits.max_object_bytes,
        HARD_MAX_LINUX_SELECTED_END_DIRECT_GLUE_OBJECT_BYTES_V2,
    )?;
    let expected_expectation: &[u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2] =
        expectation_bytes
            .try_into()
            .map_err(|_| glue_error("separate expectation extent"))?;
    let expectation: &[u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2] = bytes
        .get(EXPECTATION_OFFSET..EXPECTATION_END)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| glue_error("embedded expectation range"))?;
    if expectation != expected_expectation {
        return Err(source_error("embedded/separate expectation"));
    }
    let claim = inspect_static_search_selected_end_expectation_v2(expectation)
        .map_err(|_| glue_error("embedded expectation contract"))?;
    let compile_identity = *claim.compile_identity();
    let canonical = emit_direct_glue_bytes(expectation, &compile_identity, limits)?;
    if bytes != canonical.as_slice() {
        return Err(glue_error("canonical whole direct-glue ELF"));
    }
    let code: &[u8; LINUX_SELECTED_END_DIRECT_GLUE_CODE_BYTES_V2] = bytes
        .get(TEXT_OFFSET..EXPECTATION_OFFSET)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| glue_error("direct glue code range"))?;
    if code != &LINUX_SELECTED_END_DIRECT_GLUE_CODE_V2 {
        return Err(glue_error("direct glue instruction sequence"));
    }
    Ok(LinuxSelectedEndDirectGlueInspectionV2 {
        object_bytes: bytes.len(),
        compile_identity,
        expectation_identity: *claim.expectation_identity(),
        object_identity: LinuxSelectedEndDirectGlueObjectIdentityV2::new(digest_with_domain(
            GLUE_OBJECT_IDENTITY_DOMAIN_V2,
            bytes,
        )),
        code_identity: LinuxSelectedEndDirectGlueCodeIdentityV2::new(digest_with_domain(
            GLUE_CODE_IDENTITY_DOMAIN_V2,
            code,
        )),
        expectation,
    })
}

#[derive(Clone, Copy)]
struct SourceBindingV2 {
    manifest_identity: [u8; 32],
    semantic_binding_identity: [u8; 32],
    artifact_identity: [u8; 32],
    binding_identity: [u8; 32],
    compile_identity: [u8; 32],
    implementation_object_identity: [u8; 32],
    compiler_receipt_identity: [u8; 32],
    expectation_identity: [u8; 32],
    symbols: LinuxSelectedEndDirectSymbolsV2,
}

fn authenticate_source(
    compiled: &LinuxSelectedEndCompiledObjectV2,
    expectation: &LinuxStaticSearchSelectedEndExpectationV2,
) -> Result<SourceBindingV2, LinuxSelectedEndDirectGlueErrorV2> {
    if compiled.runtime_authority() != SelectedEndAotRuntimeAuthorityV2::Absent
        || compiled.receipt().runtime_authority() != SelectedEndAotRuntimeAuthorityV2::Absent
        || expectation.runtime_authority() != SelectedEndAotRuntimeAuthorityV2::Absent
    {
        return Err(source_error("runtime authority"));
    }
    let object_limits = SelectedEndObjectLimitsV2::default();
    compiled.validate_source_image_object(object_limits)?;
    let receipt = compiled.receipt();
    receipt.validate_object(compiled.object().as_bytes(), object_limits)?;
    let claim = expectation.validate_canonical_bytes(expectation.as_bytes())?;
    receipt.validate_expectation(expectation.as_bytes())?;
    if expectation.manifest_identity() != receipt.manifest_identity()
        || expectation.semantic_binding_identity() != receipt.semantic_binding_identity()
        || expectation.literal_identity() != receipt.literal_identity()
        || expectation.kir_identity() != receipt.kir_identity()
        || expectation.artifact_identity() != receipt.artifact_identity()
        || expectation.binding_identity() != receipt.binding_identity()
        || expectation.compile_identity() != receipt.compile_identity()
        || expectation.object_identity() != receipt.object_identity()
        || expectation.receipt_identity() != receipt.receipt_identity()
        || expectation.metadata() != receipt.metadata()
        || !expectation.authenticates_claim(&claim)
    {
        return Err(source_error("compiler/expectation binding"));
    }
    let compile_identity = *receipt.compile_identity().as_bytes();
    let symbols = LinuxSelectedEndDirectSymbolsV2::from_compile_identity_claim(&compile_identity)?;
    let trusted = ExportedSymbolsV2::for_compile_identity(receipt.compile_identity());
    if symbols.entry().as_str() != trusted.entry().as_str()
        || symbols.payload().as_str() != trusted.payload().as_str()
        || symbols.metadata().as_str() != trusted.metadata().as_str()
    {
        return Err(source_error("P2a identity-derived namespace"));
    }
    Ok(SourceBindingV2 {
        manifest_identity: *receipt.manifest_identity().as_bytes(),
        semantic_binding_identity: *receipt.semantic_binding_identity().as_bytes(),
        artifact_identity: *receipt.artifact_identity().as_bytes(),
        binding_identity: *receipt.binding_identity().as_bytes(),
        compile_identity,
        implementation_object_identity: *receipt.object_identity().as_bytes(),
        compiler_receipt_identity: *receipt.receipt_identity().as_bytes(),
        expectation_identity: *expectation.expectation_identity().as_bytes(),
        symbols,
    })
}

fn generate_assembly_source(
    symbols: &LinuxSelectedEndDirectSymbolsV2,
    expectation_bytes: &[u8],
    limits: LinuxSelectedEndDirectGlueLimitsV2,
) -> Result<LinuxSelectedEndDirectGlueSourceV2, LinuxSelectedEndDirectGlueErrorV2> {
    let expectation: &[u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2] = expectation_bytes
        .try_into()
        .map_err(|_| source_error("assembly expectation extent"))?;
    let claim = inspect_static_search_selected_end_expectation_v2(expectation)
        .map_err(|_| source_error("assembly expectation contract"))?;
    if claim.compile_identity() != symbols.compile_identity() {
        return Err(source_error("assembly symbol identity"));
    }
    let mut source = String::new();
    source
        .try_reserve_exact(16 << 10)
        .map_err(|_| LinuxSelectedEndDirectGlueErrorV2::AllocationFailed)?;
    writeln!(source, ".arch armv8-a").map_err(|_| glue_error("assembly preamble"))?;
    writeln!(source, ".global {}", symbols.entry())
        .map_err(|_| glue_error("assembly entry global"))?;
    writeln!(source, ".hidden {}", symbols.entry())
        .map_err(|_| glue_error("assembly entry visibility"))?;
    writeln!(source, ".type {}, %function", symbols.entry())
        .map_err(|_| glue_error("assembly entry type"))?;
    writeln!(source, ".global {}", symbols.payload())
        .map_err(|_| glue_error("assembly payload global"))?;
    writeln!(source, ".hidden {}", symbols.payload())
        .map_err(|_| glue_error("assembly payload visibility"))?;
    writeln!(source, ".type {}, %object", symbols.payload())
        .map_err(|_| glue_error("assembly payload type"))?;
    writeln!(source, ".global {}", symbols.metadata())
        .map_err(|_| glue_error("assembly metadata global"))?;
    writeln!(source, ".hidden {}", symbols.metadata())
        .map_err(|_| glue_error("assembly metadata visibility"))?;
    writeln!(source, ".type {}, %object", symbols.metadata())
        .map_err(|_| glue_error("assembly metadata type"))?;
    writeln!(source, ".section {TEXT_SECTION_NAME}, \"ax\", %progbits")
        .map_err(|_| glue_error("assembly text section"))?;
    writeln!(source, ".p2align 2").map_err(|_| glue_error("assembly text alignment"))?;
    writeln!(source, ".global {}", symbols.wrapper())
        .map_err(|_| glue_error("assembly wrapper global"))?;
    writeln!(source, ".hidden {}", symbols.wrapper())
        .map_err(|_| glue_error("assembly wrapper visibility"))?;
    writeln!(source, ".type {}, %function", symbols.wrapper())
        .map_err(|_| glue_error("assembly wrapper type"))?;
    writeln!(source, "{}:", symbols.wrapper()).map_err(|_| glue_error("assembly wrapper label"))?;
    writeln!(source, "  stp x29, x30, [sp, #-16]!")
        .map_err(|_| glue_error("assembly save link register"))?;
    writeln!(source, "  bl {}", symbols.entry()).map_err(|_| glue_error("assembly direct call"))?;
    writeln!(source, "  ldp x29, x30, [sp], #16")
        .map_err(|_| glue_error("assembly restore link register"))?;
    writeln!(source, "  ret").map_err(|_| glue_error("assembly return"))?;
    writeln!(
        source,
        ".size {}, .-{}",
        symbols.wrapper(),
        symbols.wrapper()
    )
    .map_err(|_| glue_error("assembly wrapper size"))?;
    writeln!(
        source,
        ".section {EXPECTATION_SECTION_NAME}, \"a\", %progbits"
    )
    .map_err(|_| glue_error("assembly expectation section"))?;
    writeln!(source, ".p2align 3").map_err(|_| glue_error("assembly expectation alignment"))?;
    writeln!(source, ".global {}", symbols.expectation())
        .map_err(|_| glue_error("assembly expectation global"))?;
    writeln!(source, ".hidden {}", symbols.expectation())
        .map_err(|_| glue_error("assembly expectation visibility"))?;
    writeln!(source, ".type {}, %object", symbols.expectation())
        .map_err(|_| glue_error("assembly expectation type"))?;
    writeln!(source, "{}:", symbols.expectation())
        .map_err(|_| glue_error("assembly expectation label"))?;
    for row in expectation.chunks(16) {
        source
            .write_str("  .byte ")
            .map_err(|_| glue_error("assembly expectation byte prefix"))?;
        for (index, byte) in row.iter().enumerate() {
            if index != 0 {
                source
                    .write_str(", ")
                    .map_err(|_| glue_error("assembly expectation byte separator"))?;
            }
            write!(source, "0x{byte:02x}").map_err(|_| glue_error("assembly expectation byte"))?;
        }
        source
            .write_char('\n')
            .map_err(|_| glue_error("assembly expectation byte row"))?;
    }
    writeln!(
        source,
        ".size {}, .-{}",
        symbols.expectation(),
        symbols.expectation()
    )
    .map_err(|_| glue_error("assembly expectation size"))?;
    writeln!(source, ".section {GNU_STACK_SECTION_NAME}, \"\", %progbits")
        .map_err(|_| glue_error("assembly GNU stack section"))?;
    let source_bytes = usize_u64(source.len(), "assembly source bytes")?;
    enforce_limit(
        "assembly source bytes",
        source_bytes,
        limits.max_source_bytes,
        HARD_MAX_LINUX_SELECTED_END_DIRECT_GLUE_SOURCE_BYTES_V2,
    )?;
    let identity = LinuxSelectedEndDirectGlueSourceIdentityV2::new(length_prefixed_identity(
        GLUE_SOURCE_IDENTITY_DOMAIN_V2,
        source.as_bytes(),
    ));
    Ok(LinuxSelectedEndDirectGlueSourceV2 {
        bytes: source.into_bytes().into_boxed_slice(),
        identity,
    })
}

fn generate_c_header(
    symbols: &LinuxSelectedEndDirectSymbolsV2,
    limits: LinuxSelectedEndDirectGlueLimitsV2,
) -> Result<LinuxSelectedEndDirectHeaderV2, LinuxSelectedEndDirectGlueErrorV2> {
    let mut header = String::new();
    header
        .try_reserve_exact(16 << 10)
        .map_err(|_| LinuxSelectedEndDirectGlueErrorV2::AllocationFailed)?;
    symbols
        .write_c_header(&mut header)
        .map_err(|_| glue_error("direct C header"))?;
    if header.contains("(*")
        || header.contains("fre_aot_search_result_v1")
        || header.contains("result_slot")
    {
        return Err(source_error("direct C header API"));
    }
    let header_bytes = usize_u64(header.len(), "direct header bytes")?;
    enforce_limit(
        "direct header bytes",
        header_bytes,
        limits.max_header_bytes,
        HARD_MAX_LINUX_SELECTED_END_DIRECT_HEADER_BYTES_V2,
    )?;
    let identity = LinuxSelectedEndDirectHeaderIdentityV2::new(length_prefixed_identity(
        GLUE_HEADER_IDENTITY_DOMAIN_V2,
        header.as_bytes(),
    ));
    Ok(LinuxSelectedEndDirectHeaderV2 {
        bytes: header.into_bytes().into_boxed_slice(),
        identity,
    })
}

fn build_qualification_receipt(
    binding: SourceBindingV2,
    source: &LinuxSelectedEndDirectGlueSourceV2,
    header: &LinuxSelectedEndDirectHeaderV2,
    glue: &LinuxSelectedEndDirectGlueObjectV2,
) -> Result<LinuxSelectedEndQualificationReceiptV2, LinuxSelectedEndDirectGlueErrorV2> {
    let mut bytes = [0_u8; LINUX_SELECTED_END_QUALIFICATION_RECEIPT_BYTES_V2];
    {
        let mut writer = Writer::new(&mut bytes);
        writer.raw(&GLUE_RECEIPT_MAGIC_V2)?;
        writer.u16(GLUE_RECEIPT_SCHEMA_VERSION_V2)?;
        writer.u16(crate::search_selected_end_v2::AOT_LINUX_SELECTED_END_COMPILER_VERSION_V2)?;
        writer.u32(
            u32::try_from(LINUX_SELECTED_END_QUALIFICATION_RECEIPT_BYTES_V2)
                .expect("fixed qualification receipt bytes"),
        )?;
        writer.u16(
            u16::try_from(LINUX_SELECTED_END_DIRECT_GLUE_CODE_BYTES_V2)
                .expect("fixed direct glue code bytes"),
        )?;
        writer.u16(
            u16::try_from(LINUX_SELECTED_END_DIRECT_GLUE_RELOCATIONS_V2)
                .expect("fixed direct glue relocation count"),
        )?;
        writer.u32(R_AARCH64_CALL26_V2)?;
        writer.u8(SEARCH_SELECTED_END_ARGUMENT_COUNT_V2)?;
        writer.u8(SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2)?;
        writer.u16(SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2)?;
        writer.u16(LINUX_SELECTED_END_DIRECT_GLUE_INSTRUCTIONS_V2)?;
        writer.u16(LINUX_SELECTED_END_DIRECT_GLUE_CALL_OFFSET_V2)?;
        writer.u16(SEARCH_SELECTED_END_BACKEND_TAG21_V2)?;
        writer.u16(SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2)?;
        writer.u8(0)?;
        writer.u8(STV_HIDDEN)?;
        writer.u16(0)?;
        writer.u32(POST_LINK_DISASSEMBLY_REQUIREMENTS_V2)?;
        writer.u64(usize_u64(glue.as_bytes().len(), "glue object bytes")?)?;
        writer.u32(
            u32::try_from(source.as_bytes().len())
                .map_err(|_| overflow("assembly source bytes"))?,
        )?;
        writer.u32(
            u32::try_from(header.as_bytes().len()).map_err(|_| overflow("direct header bytes"))?,
        )?;
        writer.u32(0)?;
        if writer.position() != RECEIPT_IDENTITIES_OFFSET_V2 {
            return Err(glue_error("qualification receipt header width"));
        }
        for identity in [
            &binding.manifest_identity,
            &binding.semantic_binding_identity,
            &binding.artifact_identity,
            &binding.binding_identity,
            &binding.compile_identity,
            &binding.implementation_object_identity,
            &binding.compiler_receipt_identity,
            &binding.expectation_identity,
            source.identity().as_bytes(),
            header.identity().as_bytes(),
            glue.code_identity().as_bytes(),
            glue.object_identity().as_bytes(),
        ] {
            writer.raw(identity)?;
        }
        if writer.position() != RECEIPT_CODE_OFFSET_V2 {
            return Err(glue_error("qualification receipt identity width"));
        }
        writer.raw(&LINUX_SELECTED_END_DIRECT_GLUE_CODE_V2)?;
        writer.raw(&[0; 16])?;
        if writer.position() != RECEIPT_IDENTITY_OFFSET_V2 {
            return Err(glue_error("qualification receipt body width"));
        }
    }
    let identity = digest_with_domain(
        GLUE_RECEIPT_IDENTITY_DOMAIN_V2,
        &bytes[..RECEIPT_IDENTITY_OFFSET_V2],
    );
    bytes[RECEIPT_IDENTITY_OFFSET_V2..].copy_from_slice(&identity);
    let receipt = LinuxSelectedEndQualificationReceiptV2 { bytes };
    if !receipt.authenticates_itself() {
        return Err(LinuxSelectedEndDirectGlueErrorV2::InvalidReceipt);
    }
    Ok(receipt)
}

struct StringTables {
    symbols: Vec<u8>,
    wrapper_name: u32,
    expectation_name: u32,
    entry_name: u32,
    payload_name: u32,
    metadata_name: u32,
    sections: Vec<u8>,
    text_section_name: u32,
    expectation_section_name: u32,
    rela_section_name: u32,
    string_section_name: u32,
    symbol_section_name: u32,
    gnu_stack_section_name: u32,
    section_string_section_name: u32,
}

impl StringTables {
    fn new(compile_identity: &[u8; 32]) -> Result<Self, LinuxSelectedEndDirectGlueErrorV2> {
        let exported =
            LinuxSelectedEndDirectSymbolsV2::from_compile_identity_claim(compile_identity)?;
        let mut symbols = Vec::new();
        symbols
            .try_reserve_exact(1024)
            .map_err(|_| LinuxSelectedEndDirectGlueErrorV2::AllocationFailed)?;
        symbols.push(0);
        let wrapper_name = push_string(&mut symbols, exported.wrapper().as_bytes())?;
        let expectation_name = push_string(&mut symbols, exported.expectation().as_bytes())?;
        let entry_name = push_string(&mut symbols, exported.entry().as_bytes())?;
        let payload_name = push_string(&mut symbols, exported.payload().as_bytes())?;
        let metadata_name = push_string(&mut symbols, exported.metadata().as_bytes())?;

        let mut sections = Vec::new();
        sections
            .try_reserve_exact(256)
            .map_err(|_| LinuxSelectedEndDirectGlueErrorV2::AllocationFailed)?;
        sections.push(0);
        let text_section_name = push_string(&mut sections, TEXT_SECTION_NAME.as_bytes())?;
        let expectation_section_name =
            push_string(&mut sections, EXPECTATION_SECTION_NAME.as_bytes())?;
        let rela_section_name = push_string(&mut sections, RELA_SECTION_NAME.as_bytes())?;
        let string_section_name = push_string(&mut sections, STRING_SECTION_NAME.as_bytes())?;
        let symbol_section_name = push_string(&mut sections, SYMBOL_SECTION_NAME.as_bytes())?;
        let gnu_stack_section_name = push_string(&mut sections, GNU_STACK_SECTION_NAME.as_bytes())?;
        let section_string_section_name =
            push_string(&mut sections, SECTION_STRING_SECTION_NAME.as_bytes())?;
        Ok(Self {
            symbols,
            wrapper_name,
            expectation_name,
            entry_name,
            payload_name,
            metadata_name,
            sections,
            text_section_name,
            expectation_section_name,
            rela_section_name,
            string_section_name,
            symbol_section_name,
            gnu_stack_section_name,
            section_string_section_name,
        })
    }
}

#[derive(Clone, Copy)]
struct Layout {
    rela_offset: usize,
    string_offset: usize,
    symbol_offset: usize,
    section_string_offset: usize,
    section_header_offset: usize,
    object_bytes: usize,
}

impl Layout {
    fn new(tables: &StringTables) -> Result<Self, LinuxSelectedEndDirectGlueErrorV2> {
        let rela_offset = align_up(EXPECTATION_END, 8, "RELA offset")?;
        let string_offset = rela_offset
            .checked_add(RELA_BYTES * LINUX_SELECTED_END_DIRECT_GLUE_RELOCATIONS_V2)
            .ok_or_else(|| overflow("string offset"))?;
        let symbol_offset = align_up(
            string_offset
                .checked_add(tables.symbols.len())
                .ok_or_else(|| overflow("symbol offset"))?,
            8,
            "symbol offset",
        )?;
        let section_string_offset = symbol_offset
            .checked_add(
                SYMBOL_BYTES
                    .checked_mul(SYMBOL_COUNT)
                    .ok_or_else(|| overflow("symbol table bytes"))?,
            )
            .ok_or_else(|| overflow("section string offset"))?;
        let section_header_offset = align_up(
            section_string_offset
                .checked_add(tables.sections.len())
                .ok_or_else(|| overflow("section header offset"))?,
            8,
            "section header offset",
        )?;
        let object_bytes = section_header_offset
            .checked_add(
                SECTION_HEADER_BYTES
                    .checked_mul(SECTION_COUNT)
                    .ok_or_else(|| overflow("section header bytes"))?,
            )
            .ok_or_else(|| overflow("object bytes"))?;
        Ok(Self {
            rela_offset,
            string_offset,
            symbol_offset,
            section_string_offset,
            section_header_offset,
            object_bytes,
        })
    }
}

fn emit_direct_glue_bytes(
    expectation: &[u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2],
    compile_identity: &[u8; 32],
    limits: LinuxSelectedEndDirectGlueLimitsV2,
) -> Result<Vec<u8>, LinuxSelectedEndDirectGlueErrorV2> {
    let claim = inspect_static_search_selected_end_expectation_v2(expectation)
        .map_err(|_| source_error("object expectation contract"))?;
    if claim.compile_identity() != compile_identity {
        return Err(source_error("object expectation compile identity"));
    }
    let tables = StringTables::new(compile_identity)?;
    let layout = Layout::new(&tables)?;
    enforce_limit(
        "glue object bytes",
        usize_u64(layout.object_bytes, "glue object bytes")?,
        limits.max_object_bytes,
        HARD_MAX_LINUX_SELECTED_END_DIRECT_GLUE_OBJECT_BYTES_V2,
    )?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(layout.object_bytes)
        .map_err(|_| LinuxSelectedEndDirectGlueErrorV2::AllocationFailed)?;
    bytes.resize(layout.object_bytes, 0);
    write_header(&mut bytes[..ELF_HEADER_BYTES], layout)?;
    copy_region(
        &mut bytes,
        TEXT_OFFSET,
        &LINUX_SELECTED_END_DIRECT_GLUE_CODE_V2,
        "glue code",
    )?;
    copy_region(
        &mut bytes,
        EXPECTATION_OFFSET,
        expectation,
        "embedded expectation",
    )?;
    write_relocation(&mut bytes, layout)?;
    copy_region(
        &mut bytes,
        layout.string_offset,
        &tables.symbols,
        "symbol strings",
    )?;
    write_symbols(&mut bytes, layout, &tables)?;
    copy_region(
        &mut bytes,
        layout.section_string_offset,
        &tables.sections,
        "section strings",
    )?;
    write_sections(&mut bytes, layout, &tables)?;
    Ok(bytes)
}

fn write_header(
    destination: &mut [u8],
    layout: Layout,
) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
    let mut writer = Writer::new(destination);
    writer.raw(&[0x7f, b'E', b'L', b'F'])?;
    writer.raw(&[
        ELF_CLASS_64,
        ELF_DATA_LSB,
        ELF_VERSION_CURRENT,
        ELF_OS_ABI_SYSV,
        0,
    ])?;
    writer.raw(&[0; 7])?;
    writer.u16(ELF_RELOCATABLE)?;
    writer.u16(ELF_MACHINE_AARCH64)?;
    writer.u32(u32::from(ELF_VERSION_CURRENT))?;
    writer.u64(0)?;
    writer.u64(0)?;
    writer.u64(usize_u64(
        layout.section_header_offset,
        "section header offset",
    )?)?;
    writer.u32(0)?;
    writer.u16(u16::try_from(ELF_HEADER_BYTES).expect("fixed ELF header bytes"))?;
    writer.u16(0)?;
    writer.u16(0)?;
    writer.u16(u16::try_from(SECTION_HEADER_BYTES).expect("fixed section header bytes"))?;
    writer.u16(u16::try_from(SECTION_COUNT).expect("fixed section count"))?;
    writer.u16(SECTION_STRING_SECTION)?;
    if writer.position() != ELF_HEADER_BYTES {
        return Err(glue_error("ELF header width"));
    }
    Ok(())
}

fn write_relocation(
    bytes: &mut [u8],
    layout: Layout,
) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
    let mut writer = Writer::new(region_mut(
        bytes,
        layout.rela_offset,
        RELA_BYTES,
        "RELA table",
    )?);
    writer.u64(u64::from(LINUX_SELECTED_END_DIRECT_GLUE_CALL_OFFSET_V2))?;
    writer.u64((5_u64 << 32) | u64::from(R_AARCH64_CALL26_V2))?;
    writer.i64(0)?;
    if writer.position() != RELA_BYTES {
        return Err(glue_error("RELA width"));
    }
    Ok(())
}

fn write_symbols(
    bytes: &mut [u8],
    layout: Layout,
    tables: &StringTables,
) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
    let extent = SYMBOL_BYTES
        .checked_mul(SYMBOL_COUNT)
        .ok_or_else(|| overflow("symbol table extent"))?;
    let mut writer = Writer::new(region_mut(
        bytes,
        layout.symbol_offset,
        extent,
        "symbol table",
    )?);
    write_symbol(&mut writer, 0, 0, 0, 0, 0, 0)?;
    write_symbol(&mut writer, 0, STB_LOCAL_SECTION, 0, TEXT_SECTION, 0, 0)?;
    write_symbol(
        &mut writer,
        0,
        STB_LOCAL_SECTION,
        0,
        EXPECTATION_SECTION,
        0,
        0,
    )?;
    write_symbol(
        &mut writer,
        tables.wrapper_name,
        STB_GLOBAL_FUNCTION,
        STV_HIDDEN,
        TEXT_SECTION,
        0,
        u64::try_from(LINUX_SELECTED_END_DIRECT_GLUE_CODE_BYTES_V2)
            .expect("fixed direct glue code bytes"),
    )?;
    write_symbol(
        &mut writer,
        tables.expectation_name,
        STB_GLOBAL_OBJECT,
        STV_HIDDEN,
        EXPECTATION_SECTION,
        0,
        u64::try_from(STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2)
            .expect("fixed expectation bytes"),
    )?;
    write_symbol(
        &mut writer,
        tables.entry_name,
        STB_GLOBAL_FUNCTION,
        STV_HIDDEN,
        0,
        0,
        0,
    )?;
    write_symbol(
        &mut writer,
        tables.payload_name,
        STB_GLOBAL_OBJECT,
        STV_HIDDEN,
        0,
        0,
        0,
    )?;
    write_symbol(
        &mut writer,
        tables.metadata_name,
        STB_GLOBAL_OBJECT,
        STV_HIDDEN,
        0,
        0,
        0,
    )?;
    if writer.position() != extent {
        return Err(glue_error("symbol table width"));
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
) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
    writer.u32(name)?;
    writer.u8(info)?;
    writer.u8(other)?;
    writer.u16(section)?;
    writer.u64(value)?;
    writer.u64(bytes)
}

fn write_sections(
    bytes: &mut [u8],
    layout: Layout,
    tables: &StringTables,
) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
    let extent = SECTION_HEADER_BYTES
        .checked_mul(SECTION_COUNT)
        .ok_or_else(|| overflow("section table extent"))?;
    let mut writer = Writer::new(region_mut(
        bytes,
        layout.section_header_offset,
        extent,
        "section table",
    )?);
    write_section(&mut writer, SectionHeader::null())?;
    write_section(
        &mut writer,
        SectionHeader {
            name: tables.text_section_name,
            kind: SHT_PROGBITS,
            flags: SHF_ALLOC | SHF_EXECINSTR,
            offset: usize_u64(TEXT_OFFSET, "text offset")?,
            size: u64::try_from(LINUX_SELECTED_END_DIRECT_GLUE_CODE_BYTES_V2)
                .expect("fixed direct glue code bytes"),
            link: 0,
            info: 0,
            alignment: 4,
            entry_bytes: 0,
        },
    )?;
    write_section(
        &mut writer,
        SectionHeader {
            name: tables.expectation_section_name,
            kind: SHT_PROGBITS,
            flags: SHF_ALLOC,
            offset: usize_u64(EXPECTATION_OFFSET, "expectation offset")?,
            size: u64::try_from(STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2)
                .expect("fixed expectation bytes"),
            link: 0,
            info: 0,
            alignment: 8,
            entry_bytes: 0,
        },
    )?;
    write_section(
        &mut writer,
        SectionHeader {
            name: tables.rela_section_name,
            kind: SHT_RELA,
            flags: 0,
            offset: usize_u64(layout.rela_offset, "RELA offset")?,
            size: u64::try_from(RELA_BYTES).expect("fixed RELA bytes"),
            link: u32::from(SYMBOL_SECTION),
            info: u32::from(TEXT_SECTION),
            alignment: 8,
            entry_bytes: u64::try_from(RELA_BYTES).expect("fixed RELA bytes"),
        },
    )?;
    write_section(
        &mut writer,
        SectionHeader {
            name: tables.string_section_name,
            kind: SHT_STRTAB,
            flags: 0,
            offset: usize_u64(layout.string_offset, "string offset")?,
            size: usize_u64(tables.symbols.len(), "symbol string bytes")?,
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
            offset: usize_u64(layout.symbol_offset, "symbol table offset")?,
            size: usize_u64(
                SYMBOL_BYTES
                    .checked_mul(SYMBOL_COUNT)
                    .ok_or_else(|| overflow("symbol table bytes"))?,
                "symbol table bytes",
            )?,
            link: u32::from(STRING_SECTION),
            info: FIRST_GLOBAL_SYMBOL,
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
            offset: usize_u64(layout.section_string_offset, "section string offset")?,
            size: usize_u64(tables.sections.len(), "section string bytes")?,
            link: 0,
            info: 0,
            alignment: 1,
            entry_bytes: 0,
        },
    )?;
    if writer.position() != extent {
        return Err(glue_error("section table width"));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct SectionHeader {
    name: u32,
    kind: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_bytes: u64,
}

impl SectionHeader {
    const fn null() -> Self {
        Self {
            name: 0,
            kind: SHT_NULL,
            flags: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            alignment: 0,
            entry_bytes: 0,
        }
    }
}

fn write_section(
    writer: &mut Writer<'_>,
    section: SectionHeader,
) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
    writer.u32(section.name)?;
    writer.u32(section.kind)?;
    writer.u64(section.flags)?;
    writer.u64(0)?;
    writer.u64(section.offset)?;
    writer.u64(section.size)?;
    writer.u32(section.link)?;
    writer.u32(section.info)?;
    writer.u64(section.alignment)?;
    writer.u64(section.entry_bytes)
}

const fn canonical_post_link_requirements() -> LinuxSelectedEndPostLinkDisassemblyRequirementsV2 {
    LinuxSelectedEndPostLinkDisassemblyRequirementsV2 {
        flags: POST_LINK_DISASSEMBLY_REQUIREMENTS_V2,
        direct_call_offset: LINUX_SELECTED_END_DIRECT_GLUE_CALL_OFFSET_V2,
        relocation_kind: R_AARCH64_CALL26_V2,
        observation_complete: false,
    }
}

fn receipt_identities(
    bytes: &[u8; LINUX_SELECTED_END_QUALIFICATION_RECEIPT_BYTES_V2],
) -> [&[u8; 32]; RECEIPT_IDENTITY_COUNT_V2] {
    core::array::from_fn(|index| {
        fixed_receipt_identity(bytes, RECEIPT_IDENTITIES_OFFSET_V2 + (index * 32))
    })
}

fn fixed_receipt_identity(
    bytes: &[u8; LINUX_SELECTED_END_QUALIFICATION_RECEIPT_BYTES_V2],
    offset: usize,
) -> &[u8; 32] {
    bytes
        .get(offset..offset + 32)
        .and_then(|slice| slice.try_into().ok())
        .expect("fixed qualification receipt identity range")
}

fn push_string(
    destination: &mut Vec<u8>,
    value: &[u8],
) -> Result<u32, LinuxSelectedEndDirectGlueErrorV2> {
    if value.contains(&0) {
        return Err(glue_error("embedded string NUL"));
    }
    let offset = u32::try_from(destination.len()).map_err(|_| overflow("string table offset"))?;
    destination.extend_from_slice(value);
    destination.push(0);
    Ok(offset)
}

fn copy_region(
    destination: &mut [u8],
    offset: usize,
    source: &[u8],
    at: &'static str,
) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
    region_mut(destination, offset, source.len(), at)?.copy_from_slice(source);
    Ok(())
}

fn region_mut<'a>(
    destination: &'a mut [u8],
    offset: usize,
    bytes: usize,
    at: &'static str,
) -> Result<&'a mut [u8], LinuxSelectedEndDirectGlueErrorV2> {
    let end = offset.checked_add(bytes).ok_or_else(|| overflow(at))?;
    destination
        .get_mut(offset..end)
        .ok_or_else(|| glue_error(at))
}

fn align_up(
    value: usize,
    alignment: usize,
    at: &'static str,
) -> Result<usize, LinuxSelectedEndDirectGlueErrorV2> {
    let mask = alignment
        .checked_sub(1)
        .ok_or_else(|| overflow("alignment mask"))?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or_else(|| overflow(at))
}

fn enforce_limit(
    resource: &'static str,
    required: u64,
    configured: u64,
    hard: u64,
) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
    let limit = configured.min(hard);
    if required > limit {
        Err(LinuxSelectedEndDirectGlueErrorV2::ResourceLimit {
            resource,
            limit,
            required,
        })
    } else {
        Ok(())
    }
}

fn usize_u64(value: usize, at: &'static str) -> Result<u64, LinuxSelectedEndDirectGlueErrorV2> {
    u64::try_from(value).map_err(|_| overflow(at))
}

fn length_prefixed_identity(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(bytes.len())
            .expect("candidate source/header length admitted below u64")
            .to_le_bytes(),
    );
    hasher.update(bytes);
    hasher.finalize().into()
}

fn digest_with_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
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
        15 => b'f',
        _ => b'?',
    }
}

fn glue_error(at: &'static str) -> LinuxSelectedEndDirectGlueErrorV2 {
    LinuxSelectedEndDirectGlueErrorV2::InvalidGlue { at }
}

fn source_error(at: &'static str) -> LinuxSelectedEndDirectGlueErrorV2 {
    LinuxSelectedEndDirectGlueErrorV2::SourceBinding { at }
}

fn overflow(at: &'static str) -> LinuxSelectedEndDirectGlueErrorV2 {
    LinuxSelectedEndDirectGlueErrorV2::ArithmeticOverflow { at }
}

struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or_else(|| overflow("writer cursor"))?;
        let destination = self
            .bytes
            .get_mut(self.position..end)
            .ok_or_else(|| glue_error("writer extent"))?;
        destination.copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
        self.raw(&value.to_le_bytes())
    }

    fn i64(&mut self, value: i64) -> Result<(), LinuxSelectedEndDirectGlueErrorV2> {
        self.raw(&value.to_le_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write as _;
    use fre::RustProfile;

    use crate::search_selected_end_v2::{
        LinuxAarch64SelectedEndManifestV2, inspect_linux_selected_end_compile_receipt_v2,
        plan_and_compile_linux_aarch64_selected_end_v2,
    };

    fn compile() -> LinuxSelectedEndCompiledObjectV2 {
        plan_and_compile_linux_aarch64_selected_end_v2(
            LinuxAarch64SelectedEndManifestV2::default(),
            b"0123456789abcdef".to_vec(),
            RustProfile::default(),
        )
        .expect("Linux tag21 SelectedEnd object")
    }

    fn bundle() -> LinuxSelectedEndQualificationBundleV2 {
        build_linux_selected_end_qualification_bundle_v2(
            compile(),
            LinuxSelectedEndDirectGlueLimitsV2::default(),
        )
        .expect("Linux tag21 SelectedEnd direct bundle")
    }

    #[test]
    fn bundle_is_deterministic_direct_hidden_and_authority_free() {
        let first = bundle();
        let second = bundle();
        assert_eq!(
            first.compiled().object().as_bytes(),
            second.compiled().object().as_bytes()
        );
        assert_eq!(first.expectation(), second.expectation());
        assert_eq!(first.source(), second.source());
        assert_eq!(first.header(), second.header());
        assert_eq!(first.glue(), second.glue());
        assert_eq!(first.receipt(), second.receipt());
        assert_eq!(first.bundle_identity(), second.bundle_identity());
        assert_eq!(
            first.runtime_authority(),
            SelectedEndAotRuntimeAuthorityV2::Absent
        );
        assert_eq!(
            first.source().runtime_authority(),
            SelectedEndAotRuntimeAuthorityV2::Absent
        );
        assert_eq!(
            first.header().runtime_authority(),
            SelectedEndAotRuntimeAuthorityV2::Absent
        );
        assert_eq!(
            first.glue().runtime_authority(),
            SelectedEndAotRuntimeAuthorityV2::Absent
        );
        assert!(
            first
                .validate(LinuxSelectedEndDirectGlueLimitsV2::default())
                .is_ok()
        );

        let source = first.source().as_str();
        let symbols = first.glue().symbols().expect("exact symbols");
        assert_eq!(
            symbols.runtime_authority(),
            SelectedEndAotRuntimeAuthorityV2::Absent
        );
        assert!(source.contains(&format!("  bl {}", symbols.entry())));
        assert!(!source.contains("blr"));
        assert!(!source.contains(" x4"));
        assert!(!source.contains("result"));
        for symbol in [
            symbols.wrapper(),
            symbols.expectation(),
            symbols.entry(),
            symbols.payload(),
            symbols.metadata(),
        ] {
            assert!(source.contains(&format!(".hidden {symbol}")));
            assert!(source.contains(&format!(".global {symbol}")));
            assert!(
                symbol
                    .as_str()
                    .ends_with(&hex(first.receipt().compile_identity()))
            );
        }

        let header = first.header().as_str();
        assert!(!header.contains("(*"));
        assert!(!header.contains("fre_aot_search_result_v1"));
        assert!(!header.contains("result_slot"));
        assert_eq!(header.matches("window_end").count(), 2);

        let glue = first.glue().as_bytes();
        assert!(
            crate::inspect_linux_search_span_final_image_glue_v1(
                glue,
                crate::LinuxSearchSpanFinalImageGlueLimitsV1::default(),
            )
            .is_err()
        );
        assert_eq!(
            &glue[TEXT_OFFSET..EXPECTATION_OFFSET],
            LINUX_SELECTED_END_DIRECT_GLUE_CODE_V2.as_slice()
        );
        let tables =
            StringTables::new(first.receipt().compile_identity()).expect("direct symbol tables");
        let layout = Layout::new(&tables).expect("direct object layout");
        assert_eq!(
            u64::from_le_bytes(
                glue[layout.rela_offset..layout.rela_offset + 8]
                    .try_into()
                    .expect("RELA offset")
            ),
            u64::from(LINUX_SELECTED_END_DIRECT_GLUE_CALL_OFFSET_V2)
        );
        let info = u64::from_le_bytes(
            glue[layout.rela_offset + 8..layout.rela_offset + 16]
                .try_into()
                .expect("RELA info"),
        );
        assert_eq!(info >> 32, 5);
        assert_eq!(info as u32, R_AARCH64_CALL26_V2);

        let requirements = first.post_link_disassembly_requirements();
        assert!(requirements.requires_direct_bl());
        assert!(requirements.rejects_blr());
        assert!(requirements.rejects_plt());
        assert!(requirements.rejects_x4_argument());
        assert!(requirements.rejects_result_slot());
        assert!(requirements.requires_identity_suffixed_bindings());
        assert!(requirements.requires_hidden_bindings());
        assert!(!requirements.observation_complete());
    }

    #[test]
    fn all_persisted_artifacts_reopen_and_correlate() {
        let bundle = bundle();
        let compiler_receipt_bytes = bundle
            .compiled()
            .receipt()
            .canonical_receipt_bytes()
            .expect("compiler receipt bytes");
        let compiler_receipt =
            inspect_linux_selected_end_compile_receipt_v2(&compiler_receipt_bytes)
                .expect("compiler receipt inspection");
        let receipt = LinuxSelectedEndQualificationReceiptV2::from_canonical_bytes(
            bundle.receipt().canonical_bytes(),
        )
        .expect("qualification receipt");
        let inspection = receipt
            .validate_reopened_candidate(
                &compiler_receipt,
                bundle.compiled().object().as_bytes(),
                bundle.expectation().as_bytes(),
                bundle.source().as_bytes(),
                bundle.header().as_bytes(),
                bundle.glue().as_bytes(),
                SelectedEndObjectLimitsV2::default(),
                LinuxSelectedEndDirectGlueLimitsV2::default(),
            )
            .expect("fully reopened bundle");
        assert_eq!(
            inspection.compile_identity(),
            bundle.compiled().receipt().compile_identity().as_bytes()
        );
        assert_eq!(
            inspection.expectation_identity(),
            bundle.expectation().expectation_identity().as_bytes()
        );
        assert_eq!(
            inspection.runtime_authority(),
            SelectedEndAotRuntimeAuthorityV2::Absent
        );
    }

    #[test]
    fn every_single_byte_glue_or_receipt_mutation_is_rejected() {
        let bundle = bundle();
        for offset in 0..bundle.glue().as_bytes().len() {
            let mut changed = bundle.glue().as_bytes().to_vec();
            changed[offset] ^= 1;
            assert!(
                inspect_linux_selected_end_direct_glue_v2(
                    &changed,
                    bundle.expectation().as_bytes(),
                    LinuxSelectedEndDirectGlueLimitsV2::default(),
                )
                .is_err(),
                "glue mutation at byte {offset} was accepted"
            );
        }
        for offset in 0..bundle.receipt().canonical_bytes().len() {
            let mut changed = *bundle.receipt().canonical_bytes();
            changed[offset] ^= 1;
            assert!(
                LinuxSelectedEndQualificationReceiptV2::from_canonical_bytes(&changed).is_err(),
                "receipt mutation at byte {offset} was accepted"
            );
        }
    }

    #[test]
    fn every_single_byte_source_or_header_mutation_loses_bundle_binding() {
        let bundle = bundle();
        for offset in 0..bundle.source().as_bytes().len() {
            let mut changed = bundle.source().as_bytes().to_vec();
            changed[offset] ^= 1;
            assert!(
                bundle
                    .receipt()
                    .validate_candidate(
                        bundle.compiled(),
                        bundle.expectation(),
                        &changed,
                        bundle.header().as_bytes(),
                        bundle.glue().as_bytes(),
                        LinuxSelectedEndDirectGlueLimitsV2::default(),
                    )
                    .is_err(),
                "source mutation at byte {offset} was accepted"
            );
        }
        for offset in 0..bundle.header().as_bytes().len() {
            let mut changed = bundle.header().as_bytes().to_vec();
            changed[offset] ^= 1;
            assert!(
                bundle
                    .receipt()
                    .validate_candidate(
                        bundle.compiled(),
                        bundle.expectation(),
                        bundle.source().as_bytes(),
                        &changed,
                        bundle.glue().as_bytes(),
                        LinuxSelectedEndDirectGlueLimitsV2::default(),
                    )
                    .is_err(),
                "header mutation at byte {offset} was accepted"
            );
        }
    }

    #[test]
    fn configured_limits_fail_closed() {
        let bundle = bundle();
        let object_bytes =
            u64::try_from(bundle.glue().as_bytes().len()).expect("glue length fits u64");
        let source_bytes =
            u64::try_from(bundle.source().as_bytes().len()).expect("source length fits u64");
        let header_bytes =
            u64::try_from(bundle.header().as_bytes().len()).expect("header length fits u64");
        for limits in [
            LinuxSelectedEndDirectGlueLimitsV2 {
                max_object_bytes: object_bytes - 1,
                ..LinuxSelectedEndDirectGlueLimitsV2::default()
            },
            LinuxSelectedEndDirectGlueLimitsV2 {
                max_source_bytes: source_bytes - 1,
                ..LinuxSelectedEndDirectGlueLimitsV2::default()
            },
            LinuxSelectedEndDirectGlueLimitsV2 {
                max_header_bytes: header_bytes - 1,
                ..LinuxSelectedEndDirectGlueLimitsV2::default()
            },
        ] {
            assert!(build_linux_selected_end_qualification_bundle_v2(compile(), limits).is_err());
        }
    }

    fn hex(bytes: &[u8; 32]) -> String {
        let mut output = String::with_capacity(64);
        for byte in bytes {
            write!(output, "{byte:02x}").expect("write to String");
        }
        output
    }
}
