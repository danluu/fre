//! Deterministic Linux `AArch64` final-image glue for one authenticated Search
//! Span implementation object.
//!
//! The emitted `ELF64LE` relocatable contains a 40-byte row-selector-first
//! trampoline, the exact neutral expectation, and nine `AArch64` RELA records.
//! It refers only to the implementation object's identity-suffixed symbols and
//! one explicitly selected runtime adopter. Emission and its unsigned receipt
//! remain inert: neither qualification table nor runtime authority is changed.

use core::fmt;

use fre_aot_elf::{
    EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1, METADATA_SYMBOL_PREFIX_V1, ObjectLimitsV1,
    PAYLOAD_SYMBOL_PREFIX_V1, SEARCH_ENTRY_SYMBOL_PREFIX_V1,
};
use fre_aot_search_contract::{
    STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1, inspect_static_search_span_expectation_v1,
};
use fre_kernel_ir::{OutputKind, Span};
use sha2::{Digest, Sha256};

use crate::{
    LinuxSearchCompileReceiptInspectionV1, LinuxSearchCompiledObjectV1,
    LinuxStaticSearchSpanExpectationV1, SearchAotRuntimeAuthorityV1, SearchSpanFinalImageAdopterV1,
};

pub const LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1: usize = 40;
pub const LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1: usize = 9;
pub const LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1: usize = 256;
pub const HARD_MAX_LINUX_SEARCH_SPAN_GLUE_OBJECT_BYTES_V1: u64 = 64 << 10;

const RECEIPT_SCHEMA_VERSION_V1: u16 = 1;
const RECEIPT_DOMAIN_V1: &[u8] = b"FRE-AOT-LINUX-SEARCH-SPAN-FINAL-IMAGE-RECEIPT\0\x01";
const RECEIPT_MAGIC_V1: [u8; 8] = *b"FRELSG\0\x01";
const RECEIPT_ADOPTER_OFFSET: usize = 10;
const RECEIPT_ROW_OFFSET: usize = 16;
const RECEIPT_OBJECT_BYTES_OFFSET: usize = 24;
const RECEIPT_COMPILE_IDENTITY_OFFSET: usize = 32;
const RECEIPT_IMPLEMENTATION_OBJECT_IDENTITY_OFFSET: usize = 64;
const RECEIPT_COMPILER_RECEIPT_IDENTITY_OFFSET: usize = 96;
const RECEIPT_EXPECTATION_IDENTITY_OFFSET: usize = 128;
const RECEIPT_GLUE_OBJECT_IDENTITY_OFFSET: usize = 160;
const RECEIPT_GLUE_CODE_IDENTITY_OFFSET: usize = 192;
const RECEIPT_CONTENT_IDENTITY_OFFSET: usize = 224;
const GLUE_SYMBOL_PREFIX_V1: &str = "fre_aot_search_span_glue_v1_";
const EXPECTATION_SYMBOL_PREFIX_V1: &str = "fre_aot_search_span_expectation_v1_";
const RUNTIME_ADOPT_SYMBOL_V1: &str = "fre_aot_static_search_span_adopt_raw_v1";
const QUALIFICATION_RUNTIME_ADOPT_SYMBOL_V1: &str =
    "fre_aot_static_search_span_adopt_qualification_raw_v1";

const ELF_HEADER_BYTES: usize = 64;
const SECTION_HEADER_BYTES: usize = 64;
const SYMBOL_BYTES: usize = 24;
const RELA_BYTES: usize = 24;
const SECTION_COUNT: usize = 8;
const SYMBOL_COUNT: usize = 9;
const FIRST_GLOBAL_SYMBOL: u32 = 3;

const TEXT_SECTION: u16 = 1;
const EXPECTATION_SECTION: u16 = 2;
const STRING_SECTION: u16 = 4;
const SYMBOL_SECTION: u16 = 5;
const SECTION_STRING_SECTION: u16 = 7;

const TEXT_OFFSET: usize = ELF_HEADER_BYTES;
const EXPECTATION_OFFSET: usize = TEXT_OFFSET + LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1;
const EXPECTATION_END: usize = EXPECTATION_OFFSET + STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1;

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
const STB_GLOBAL_NOTYPE: u8 = 0x10;
const STB_GLOBAL_OBJECT: u8 = 0x11;
const STB_GLOBAL_FUNCTION: u8 = 0x12;
const STV_DEFAULT: u8 = 0;
const STV_HIDDEN: u8 = 2;
const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;
const R_AARCH64_ADD_ABS_LO12_NC: u32 = 277;
const R_AARCH64_JUMP26: u32 = 282;

const TEXT_SECTION_NAME: &str = ".text.fre_aot_search_glue";
const EXPECTATION_SECTION_NAME: &str = ".rodata.fre_aot_search_expectation";
const RELA_SECTION_NAME: &str = ".rela.text.fre_aot_search_glue";
const STRING_SECTION_NAME: &str = ".strtab";
const SYMBOL_SECTION_NAME: &str = ".symtab";
const GNU_STACK_SECTION_NAME: &str = ".note.GNU-stack";
const SECTION_STRING_SECTION_NAME: &str = ".shstrtab";
const SYMBOL_NAME_STORAGE_BYTES: usize = 112;

const _: () = assert!(EXPECTATION_OFFSET == 104);
const _: () = assert!(EXPECTATION_END == 688);
const _: () = assert!(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1 == 64);
const _: () = assert!(LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1 == 256);

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
    LinuxSearchSpanGlueObjectIdentityV1,
    "LinuxSearchSpanGlueObjectIdentityV1"
);
identity!(
    LinuxSearchSpanGlueCodeIdentityV1,
    "LinuxSearchSpanGlueCodeIdentityV1"
);
identity!(
    LinuxSearchSpanFinalImageReceiptIdentityV1,
    "LinuxSearchSpanFinalImageReceiptIdentityV1"
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSearchSpanFinalImageGlueLimitsV1 {
    pub max_object_bytes: u64,
}

impl Default for LinuxSearchSpanFinalImageGlueLimitsV1 {
    fn default() -> Self {
        Self {
            max_object_bytes: HARD_MAX_LINUX_SEARCH_SPAN_GLUE_OBJECT_BYTES_V1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LinuxSearchSpanFinalImageGlueErrorV1 {
    ResourceLimit { limit: u64, required: u64 },
    AllocationFailed,
    InvalidGlue { at: &'static str },
    SourceBinding { at: &'static str },
    InvalidReceipt,
    ArithmeticOverflow { at: &'static str },
}

impl fmt::Display for LinuxSearchSpanFinalImageGlueErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Linux Search Span final-image glue failed: {self:?}"
        )
    }
}

impl std::error::Error for LinuxSearchSpanFinalImageGlueErrorV1 {}

#[derive(Debug, Eq, PartialEq)]
pub struct LinuxSearchSpanFinalImageGlueObjectV1 {
    bytes: Vec<u8>,
    row_selector: u16,
    adopter: SearchSpanFinalImageAdopterV1,
    compile_identity: [u8; 32],
    expectation_identity: [u8; 32],
    object_identity: LinuxSearchSpanGlueObjectIdentityV1,
    code_identity: LinuxSearchSpanGlueCodeIdentityV1,
}

impl LinuxSearchSpanFinalImageGlueObjectV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn row_selector(&self) -> u16 {
        self.row_selector
    }

    #[must_use]
    pub const fn adopter(&self) -> SearchSpanFinalImageAdopterV1 {
        self.adopter
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
    pub const fn object_identity(&self) -> LinuxSearchSpanGlueObjectIdentityV1 {
        self.object_identity
    }

    #[must_use]
    pub const fn code_identity(&self) -> LinuxSearchSpanGlueCodeIdentityV1 {
        self.code_identity
    }

    /// Derive the complete final-image namespace from retained identity and
    /// adopter data, without parsing this object's ELF symbol table.
    pub fn exported_symbols(
        &self,
    ) -> Result<LinuxSearchSpanFinalImageSymbolsV1, LinuxSearchSpanFinalImageGlueErrorV1> {
        LinuxSearchSpanFinalImageSymbolsV1::from_compile_identity_claim(
            &self.compile_identity,
            self.adopter,
        )
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSearchSpanFinalImageGlueInspectionV1<'a> {
    object_bytes: usize,
    row_selector: u16,
    adopter: SearchSpanFinalImageAdopterV1,
    compile_identity: [u8; 32],
    implementation_object_identity: [u8; 32],
    compiler_receipt_identity: [u8; 32],
    expectation_identity: [u8; 32],
    object_identity: LinuxSearchSpanGlueObjectIdentityV1,
    code_identity: LinuxSearchSpanGlueCodeIdentityV1,
    expectation: &'a [u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1],
}

impl<'a> LinuxSearchSpanFinalImageGlueInspectionV1<'a> {
    #[must_use]
    pub const fn object_bytes(&self) -> usize {
        self.object_bytes
    }

    #[must_use]
    pub const fn row_selector(&self) -> u16 {
        self.row_selector
    }

    #[must_use]
    pub const fn adopter(&self) -> SearchSpanFinalImageAdopterV1 {
        self.adopter
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        &self.compile_identity
    }

    #[must_use]
    pub const fn implementation_object_identity(&self) -> &[u8; 32] {
        &self.implementation_object_identity
    }

    #[must_use]
    pub const fn compiler_receipt_identity(&self) -> &[u8; 32] {
        &self.compiler_receipt_identity
    }

    #[must_use]
    pub const fn expectation_identity(&self) -> &[u8; 32] {
        &self.expectation_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> LinuxSearchSpanGlueObjectIdentityV1 {
        self.object_identity
    }

    #[must_use]
    pub const fn code_identity(&self) -> LinuxSearchSpanGlueCodeIdentityV1 {
        self.code_identity
    }

    #[must_use]
    pub const fn expectation(&self) -> &'a [u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1] {
        self.expectation
    }

    /// Derive the complete final-image namespace from the independently
    /// decoded compile identity and adopter.
    pub fn exported_symbols(
        &self,
    ) -> Result<LinuxSearchSpanFinalImageSymbolsV1, LinuxSearchSpanFinalImageGlueErrorV1> {
        LinuxSearchSpanFinalImageSymbolsV1::from_compile_identity_claim(
            &self.compile_identity,
            self.adopter,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxUnsignedSearchSpanFinalImageReceiptV1 {
    bytes: [u8; LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1],
}

impl LinuxUnsignedSearchSpanFinalImageReceiptV1 {
    #[must_use]
    pub const fn canonical_bytes(
        &self,
    ) -> &[u8; LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1] {
        &self.bytes
    }

    /// Strictly reopen one canonical signer-free receipt wire.
    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, LinuxSearchSpanFinalImageGlueErrorV1> {
        let bytes: [u8; LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1] = bytes
            .try_into()
            .map_err(|_| LinuxSearchSpanFinalImageGlueErrorV1::InvalidReceipt)?;
        let receipt = Self { bytes };
        if !receipt.authenticates_itself() {
            return Err(LinuxSearchSpanFinalImageGlueErrorV1::InvalidReceipt);
        }
        Ok(receipt)
    }

    #[must_use]
    pub fn authenticates_itself(&self) -> bool {
        let Some(adopter) = self.adopter() else {
            return false;
        };
        self.bytes[..8] == RECEIPT_MAGIC_V1
            && self.bytes[8..10] == RECEIPT_SCHEMA_VERSION_V1.to_le_bytes()
            && self.bytes[RECEIPT_ADOPTER_OFFSET..12] == adopter_code(adopter).to_le_bytes()
            && self.bytes[12..16]
                == u32::try_from(LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1)
                    .expect("fixed Linux final-image receipt width")
                    .to_le_bytes()
            && self.bytes[18..20]
                == u16::try_from(LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1)
                    .expect("fixed relocation count")
                    .to_le_bytes()
            && self.bytes[20..22]
                == u16::try_from(LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1)
                    .expect("fixed glue code width")
                    .to_le_bytes()
            && self.bytes[22..24] == [0; 2]
            && self.object_bytes() > 0
            && self.object_bytes() <= HARD_MAX_LINUX_SEARCH_SPAN_GLUE_OBJECT_BYTES_V1
            && digest_with_domain(
                RECEIPT_DOMAIN_V1,
                &self.bytes[..RECEIPT_CONTENT_IDENTITY_OFFSET],
            ) == *self.content_identity()
    }

    #[must_use]
    pub fn adopter(&self) -> Option<SearchSpanFinalImageAdopterV1> {
        adopter_from_code(u16::from_le_bytes(
            self.bytes[RECEIPT_ADOPTER_OFFSET..12]
                .try_into()
                .expect("fixed adopter range"),
        ))
    }

    #[must_use]
    pub fn row_selector(&self) -> u16 {
        u16::from_le_bytes(
            self.bytes[RECEIPT_ROW_OFFSET..RECEIPT_ROW_OFFSET + 2]
                .try_into()
                .expect("fixed row-selector range"),
        )
    }

    #[must_use]
    pub fn object_bytes(&self) -> u64 {
        u64::from_le_bytes(
            self.bytes[RECEIPT_OBJECT_BYTES_OFFSET..RECEIPT_OBJECT_BYTES_OFFSET + 8]
                .try_into()
                .expect("fixed object-bytes range"),
        )
    }

    #[must_use]
    pub fn compile_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, RECEIPT_COMPILE_IDENTITY_OFFSET)
    }

    #[must_use]
    pub fn implementation_object_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, RECEIPT_IMPLEMENTATION_OBJECT_IDENTITY_OFFSET)
    }

    #[must_use]
    pub fn compiler_receipt_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, RECEIPT_COMPILER_RECEIPT_IDENTITY_OFFSET)
    }

    #[must_use]
    pub fn expectation_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, RECEIPT_EXPECTATION_IDENTITY_OFFSET)
    }

    #[must_use]
    pub fn glue_object_identity(&self) -> LinuxSearchSpanGlueObjectIdentityV1 {
        LinuxSearchSpanGlueObjectIdentityV1::new(*fixed_receipt_identity(
            &self.bytes,
            RECEIPT_GLUE_OBJECT_IDENTITY_OFFSET,
        ))
    }

    #[must_use]
    pub fn glue_code_identity(&self) -> LinuxSearchSpanGlueCodeIdentityV1 {
        LinuxSearchSpanGlueCodeIdentityV1::new(*fixed_receipt_identity(
            &self.bytes,
            RECEIPT_GLUE_CODE_IDENTITY_OFFSET,
        ))
    }

    #[must_use]
    pub fn receipt_identity(&self) -> LinuxSearchSpanFinalImageReceiptIdentityV1 {
        LinuxSearchSpanFinalImageReceiptIdentityV1::new(*self.content_identity())
    }

    #[must_use]
    pub fn content_identity(&self) -> &[u8; 32] {
        fixed_receipt_identity(&self.bytes, RECEIPT_CONTENT_IDENTITY_OFFSET)
    }

    /// Derive the expected final-image namespace from this authenticated
    /// signer-free receipt, without discovering names in either ELF object.
    pub fn exported_symbols(
        &self,
    ) -> Result<LinuxSearchSpanFinalImageSymbolsV1, LinuxSearchSpanFinalImageGlueErrorV1> {
        if !self.authenticates_itself() {
            return Err(LinuxSearchSpanFinalImageGlueErrorV1::InvalidReceipt);
        }
        LinuxSearchSpanFinalImageSymbolsV1::from_compile_identity_claim(
            self.compile_identity(),
            self.adopter()
                .ok_or(LinuxSearchSpanFinalImageGlueErrorV1::InvalidReceipt)?,
        )
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }

    pub fn validate_candidate<'a>(
        &self,
        compiled: &LinuxSearchCompiledObjectV1<Span>,
        expectation: &LinuxStaticSearchSpanExpectationV1,
        glue_bytes: &'a [u8],
        limits: LinuxSearchSpanFinalImageGlueLimitsV1,
    ) -> Result<LinuxSearchSpanFinalImageGlueInspectionV1<'a>, LinuxSearchSpanFinalImageGlueErrorV1>
    {
        let adopter = self
            .adopter()
            .ok_or(LinuxSearchSpanFinalImageGlueErrorV1::InvalidReceipt)?;
        if !self.authenticates_itself() {
            return Err(LinuxSearchSpanFinalImageGlueErrorV1::InvalidReceipt);
        }
        let source = authenticate_source(compiled, expectation)?;
        let inspection = inspect_linux_search_span_final_image_glue_v1(glue_bytes, limits)?;
        if adopter != inspection.adopter()
            || self.row_selector() != inspection.row_selector()
            || self.object_bytes()
                != u64::try_from(inspection.object_bytes())
                    .map_err(|_| overflow("glue object bytes"))?
            || self.compile_identity() != &source.compile_identity
            || self.implementation_object_identity() != &source.implementation_object_identity
            || self.compiler_receipt_identity() != &source.compiler_receipt_identity
            || self.expectation_identity() != &source.expectation_identity
            || self.glue_object_identity() != inspection.object_identity()
            || self.glue_code_identity() != inspection.code_identity()
            || inspection.expectation() != expectation.as_bytes()
        {
            return Err(LinuxSearchSpanFinalImageGlueErrorV1::InvalidReceipt);
        }
        Ok(inspection)
    }

    /// Reopen and correlate all four persisted Linux candidate artifacts.
    ///
    /// The compiler receipt, implementation object, neutral expectation, glue
    /// object, and this final-image receipt are independently decoded from
    /// bytes before any identity is accepted. Success remains signer-free and
    /// grants no runtime authority.
    pub fn validate_reopened_candidate<'a>(
        &self,
        compiler_receipt: &LinuxSearchCompileReceiptInspectionV1,
        implementation_bytes: &[u8],
        expectation_bytes: &[u8],
        glue_bytes: &'a [u8],
        object_limits: ObjectLimitsV1,
        glue_limits: LinuxSearchSpanFinalImageGlueLimitsV1,
    ) -> Result<LinuxSearchSpanFinalImageGlueInspectionV1<'a>, LinuxSearchSpanFinalImageGlueErrorV1>
    {
        if !self.authenticates_itself()
            || compiler_receipt.runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
        {
            return Err(LinuxSearchSpanFinalImageGlueErrorV1::InvalidReceipt);
        }
        compiler_receipt
            .validate_object(implementation_bytes, object_limits)
            .map_err(|_| source_error("reopened implementation object"))?;
        let expectation = compiler_receipt
            .validate_span_expectation(expectation_bytes)
            .map_err(|_| source_error("reopened neutral expectation"))?;
        let inspection = inspect_linux_search_span_final_image_glue_v1(glue_bytes, glue_limits)?;
        let adopter = self
            .adopter()
            .ok_or(LinuxSearchSpanFinalImageGlueErrorV1::InvalidReceipt)?;
        if adopter != inspection.adopter()
            || self.row_selector() != inspection.row_selector()
            || self.object_bytes()
                != u64::try_from(inspection.object_bytes())
                    .map_err(|_| overflow("reopened glue object bytes"))?
            || self.compile_identity() != compiler_receipt.compile_identity()
            || self.implementation_object_identity() != compiler_receipt.object_identity()
            || self.compiler_receipt_identity() != compiler_receipt.receipt_identity().as_bytes()
            || self.expectation_identity() != expectation.expectation_identity()
            || self.glue_object_identity() != inspection.object_identity()
            || self.glue_code_identity() != inspection.code_identity()
            || inspection.expectation().as_slice() != expectation_bytes
        {
            return Err(LinuxSearchSpanFinalImageGlueErrorV1::InvalidReceipt);
        }
        Ok(inspection)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PublishedLinuxSearchSpanFinalImageGlueV1 {
    object: LinuxSearchSpanFinalImageGlueObjectV1,
    receipt: LinuxUnsignedSearchSpanFinalImageReceiptV1,
}

impl PublishedLinuxSearchSpanFinalImageGlueV1 {
    #[must_use]
    pub const fn object(&self) -> &LinuxSearchSpanFinalImageGlueObjectV1 {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> &LinuxUnsignedSearchSpanFinalImageReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }
}

pub fn publish_linux_search_span_final_image_glue_v1(
    compiled: &LinuxSearchCompiledObjectV1<Span>,
    expectation: &LinuxStaticSearchSpanExpectationV1,
    row_selector: u16,
    limits: LinuxSearchSpanFinalImageGlueLimitsV1,
) -> Result<PublishedLinuxSearchSpanFinalImageGlueV1, LinuxSearchSpanFinalImageGlueErrorV1> {
    publish_for_adopter(
        compiled,
        expectation,
        row_selector,
        SearchSpanFinalImageAdopterV1::Production,
        limits,
    )
}

pub fn publish_linux_search_span_qualification_final_image_glue_v1(
    compiled: &LinuxSearchCompiledObjectV1<Span>,
    expectation: &LinuxStaticSearchSpanExpectationV1,
    row_selector: u16,
    limits: LinuxSearchSpanFinalImageGlueLimitsV1,
) -> Result<PublishedLinuxSearchSpanFinalImageGlueV1, LinuxSearchSpanFinalImageGlueErrorV1> {
    publish_for_adopter(
        compiled,
        expectation,
        row_selector,
        SearchSpanFinalImageAdopterV1::QualificationPrivate,
        limits,
    )
}

fn publish_for_adopter(
    compiled: &LinuxSearchCompiledObjectV1<Span>,
    expectation: &LinuxStaticSearchSpanExpectationV1,
    row_selector: u16,
    adopter: SearchSpanFinalImageAdopterV1,
    limits: LinuxSearchSpanFinalImageGlueLimitsV1,
) -> Result<PublishedLinuxSearchSpanFinalImageGlueV1, LinuxSearchSpanFinalImageGlueErrorV1> {
    let source = authenticate_source(compiled, expectation)?;
    let bytes = emit_glue_bytes(
        expectation.as_bytes(),
        &source.compile_identity,
        row_selector,
        adopter,
        limits,
    )?;
    let inspection = inspect_linux_search_span_final_image_glue_v1(&bytes, limits)?;
    if inspection.row_selector() != row_selector
        || inspection.adopter() != adopter
        || inspection.compile_identity() != &source.compile_identity
        || inspection.implementation_object_identity() != &source.implementation_object_identity
        || inspection.compiler_receipt_identity() != &source.compiler_receipt_identity
        || inspection.expectation_identity() != &source.expectation_identity
    {
        return Err(glue_error("fresh glue inspection"));
    }
    let object_identity = inspection.object_identity();
    let code_identity = inspection.code_identity();
    let object = LinuxSearchSpanFinalImageGlueObjectV1 {
        bytes,
        row_selector,
        adopter,
        compile_identity: source.compile_identity,
        expectation_identity: source.expectation_identity,
        object_identity,
        code_identity,
    };
    let receipt = build_final_image_receipt(source, &object)?;
    if receipt.runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
        || receipt
            .validate_candidate(compiled, expectation, object.as_bytes(), limits)
            .is_err()
    {
        return Err(LinuxSearchSpanFinalImageGlueErrorV1::InvalidReceipt);
    }
    Ok(PublishedLinuxSearchSpanFinalImageGlueV1 { object, receipt })
}

pub fn inspect_linux_search_span_final_image_glue_v1(
    bytes: &[u8],
    limits: LinuxSearchSpanFinalImageGlueLimitsV1,
) -> Result<LinuxSearchSpanFinalImageGlueInspectionV1<'_>, LinuxSearchSpanFinalImageGlueErrorV1> {
    enforce_limit(bytes.len(), limits)?;
    let expectation: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1] = bytes
        .get(EXPECTATION_OFFSET..EXPECTATION_END)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| glue_error("expectation range"))?;
    let claim = inspect_static_search_span_expectation_v1(expectation)
        .map_err(|_| glue_error("expectation contract"))?;
    let code: &[u8; LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1] = bytes
        .get(TEXT_OFFSET..EXPECTATION_OFFSET)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| glue_error("code range"))?;
    let row_selector = decode_row_selector(code)?;
    let compile_identity = *claim.compile_identity();
    let production = emit_glue_bytes(
        expectation,
        &compile_identity,
        row_selector,
        SearchSpanFinalImageAdopterV1::Production,
        limits,
    )?;
    let adopter = if bytes == production.as_slice() {
        SearchSpanFinalImageAdopterV1::Production
    } else {
        let qualification = emit_glue_bytes(
            expectation,
            &compile_identity,
            row_selector,
            SearchSpanFinalImageAdopterV1::QualificationPrivate,
            limits,
        )?;
        if bytes != qualification.as_slice() {
            return Err(glue_error("canonical whole ELF glue"));
        }
        SearchSpanFinalImageAdopterV1::QualificationPrivate
    };
    Ok(LinuxSearchSpanFinalImageGlueInspectionV1 {
        object_bytes: bytes.len(),
        row_selector,
        adopter,
        compile_identity,
        implementation_object_identity: *claim.object_identity(),
        compiler_receipt_identity: *claim.receipt_identity(),
        expectation_identity: *claim.expectation_identity(),
        object_identity: LinuxSearchSpanGlueObjectIdentityV1::new(Sha256::digest(bytes).into()),
        code_identity: LinuxSearchSpanGlueCodeIdentityV1::new(Sha256::digest(code).into()),
        expectation,
    })
}

#[derive(Clone, Copy)]
#[allow(
    clippy::struct_field_names,
    reason = "each field is a distinct identity in the authenticated source-binding tuple"
)]
struct SourceBindingV1 {
    compile_identity: [u8; 32],
    implementation_object_identity: [u8; 32],
    compiler_receipt_identity: [u8; 32],
    expectation_identity: [u8; 32],
}

fn authenticate_source(
    compiled: &LinuxSearchCompiledObjectV1<Span>,
    expectation: &LinuxStaticSearchSpanExpectationV1,
) -> Result<SourceBindingV1, LinuxSearchSpanFinalImageGlueErrorV1> {
    if compiled.runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
        || compiled.receipt().runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
        || expectation.runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
    {
        return Err(source_error("runtime authority"));
    }
    let receipt = compiled.receipt();
    if receipt.output() != OutputKind::Span {
        return Err(source_error("typed Span receipt"));
    }
    let object = receipt
        .validate_object(compiled.object().as_bytes(), ObjectLimitsV1::default())
        .map_err(|_| source_error("compiler object receipt"))?;
    let claim = inspect_static_search_span_expectation_v1(expectation.as_bytes())
        .map_err(|_| source_error("neutral expectation"))?;
    if !expectation.authenticates_claim(&claim)
        || object.metadata() != receipt.metadata()
        || object.metadata_bytes() != expectation.metadata_bytes_v1()
        || expectation.compile_identity() != receipt.compile_identity()
        || expectation.object_identity() != receipt.object_identity()
        || expectation.receipt_identity() != receipt.receipt_identity()
        || claim.compile_identity() != receipt.compile_identity().as_bytes()
        || claim.object_identity() != receipt.object_identity().as_bytes()
        || claim.receipt_identity() != receipt.receipt_identity().as_bytes()
        || claim.expectation_identity() != expectation.expectation_identity().as_bytes()
    {
        return Err(source_error("object/expectation binding"));
    }
    Ok(SourceBindingV1 {
        compile_identity: *receipt.compile_identity().as_bytes(),
        implementation_object_identity: *receipt.object_identity().as_bytes(),
        compiler_receipt_identity: *receipt.receipt_identity().as_bytes(),
        expectation_identity: *expectation.expectation_identity().as_bytes(),
    })
}

fn build_final_image_receipt(
    source: SourceBindingV1,
    object: &LinuxSearchSpanFinalImageGlueObjectV1,
) -> Result<LinuxUnsignedSearchSpanFinalImageReceiptV1, LinuxSearchSpanFinalImageGlueErrorV1> {
    let mut bytes = [0_u8; LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1];
    {
        let mut writer = Writer::new(&mut bytes);
        writer.raw(&RECEIPT_MAGIC_V1)?;
        writer.u16(RECEIPT_SCHEMA_VERSION_V1)?;
        writer.u16(adopter_code(object.adopter()))?;
        writer.u32(
            u32::try_from(LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1)
                .map_err(|_| overflow("final-image receipt width"))?,
        )?;
        writer.u16(object.row_selector())?;
        writer.u16(
            u16::try_from(LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1)
                .map_err(|_| overflow("glue relocation count"))?,
        )?;
        writer.u16(
            u16::try_from(LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1)
                .map_err(|_| overflow("glue code bytes"))?,
        )?;
        writer.u16(0)?;
        writer.u64(
            u64::try_from(object.as_bytes().len()).map_err(|_| overflow("glue object bytes"))?,
        )?;
        writer.raw(&source.compile_identity)?;
        writer.raw(&source.implementation_object_identity)?;
        writer.raw(&source.compiler_receipt_identity)?;
        writer.raw(&source.expectation_identity)?;
        writer.raw(object.object_identity().as_bytes())?;
        writer.raw(object.code_identity().as_bytes())?;
        if writer.position() != RECEIPT_CONTENT_IDENTITY_OFFSET {
            return Err(glue_error("final-image receipt body width"));
        }
    }
    let identity = digest_with_domain(RECEIPT_DOMAIN_V1, &bytes[..RECEIPT_CONTENT_IDENTITY_OFFSET]);
    bytes[RECEIPT_CONTENT_IDENTITY_OFFSET..].copy_from_slice(&identity);
    let receipt = LinuxUnsignedSearchSpanFinalImageReceiptV1 { bytes };
    if !receipt.authenticates_itself() {
        return Err(LinuxSearchSpanFinalImageGlueErrorV1::InvalidReceipt);
    }
    Ok(receipt)
}

fn digest_with_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn fixed_receipt_identity(
    bytes: &[u8; LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1],
    offset: usize,
) -> &[u8; 32] {
    bytes
        .get(offset..)
        .and_then(|tail| tail.get(..32))
        .and_then(|slice| slice.try_into().ok())
        .expect("fixed final-image receipt identity range")
}

const fn adopter_from_code(code: u16) -> Option<SearchSpanFinalImageAdopterV1> {
    match code {
        0 => Some(SearchSpanFinalImageAdopterV1::Production),
        1 => Some(SearchSpanFinalImageAdopterV1::QualificationPrivate),
        _ => None,
    }
}

const fn adopter_code(adopter: SearchSpanFinalImageAdopterV1) -> u16 {
    match adopter {
        SearchSpanFinalImageAdopterV1::Production => 0,
        SearchSpanFinalImageAdopterV1::QualificationPrivate => 1,
    }
}

const fn adopter_symbol(adopter: SearchSpanFinalImageAdopterV1) -> &'static str {
    match adopter {
        SearchSpanFinalImageAdopterV1::Production => RUNTIME_ADOPT_SYMBOL_V1,
        SearchSpanFinalImageAdopterV1::QualificationPrivate => {
            QUALIFICATION_RUNTIME_ADOPT_SYMBOL_V1
        }
    }
}

/// One allocation-free, identity-derived Linux final-image symbol name.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct LinuxSearchSpanFinalImageSymbolNameV1 {
    bytes: [u8; SYMBOL_NAME_STORAGE_BYTES],
    len: usize,
}

impl LinuxSearchSpanFinalImageSymbolNameV1 {
    fn suffixed(
        prefix: &str,
        identity: &[u8; 32],
    ) -> Result<Self, LinuxSearchSpanFinalImageGlueErrorV1> {
        let len = prefix
            .len()
            .checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1)
            .ok_or_else(|| overflow("symbol name length"))?;
        if len > SYMBOL_NAME_STORAGE_BYTES {
            return Err(glue_error("symbol name storage"));
        }
        let mut bytes = [0_u8; SYMBOL_NAME_STORAGE_BYTES];
        bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
        let mut cursor = prefix.len();
        for byte in identity {
            for nibble in [byte >> 4, byte & 0x0f] {
                bytes[cursor] = lower_hex(nibble);
                cursor = cursor
                    .checked_add(1)
                    .ok_or_else(|| overflow("symbol name cursor"))?;
            }
        }
        if cursor != len {
            return Err(glue_error("symbol name width"));
        }
        Ok(Self { bytes, len })
    }

    fn fixed(value: &str) -> Result<Self, LinuxSearchSpanFinalImageGlueErrorV1> {
        if value.len() > SYMBOL_NAME_STORAGE_BYTES {
            return Err(glue_error("fixed symbol name storage"));
        }
        let mut bytes = [0_u8; SYMBOL_NAME_STORAGE_BYTES];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            bytes,
            len: value.len(),
        })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).expect("canonical ASCII Linux final-image symbol")
    }
}

impl fmt::Debug for LinuxSearchSpanFinalImageSymbolNameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LinuxSearchSpanFinalImageSymbolNameV1")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for LinuxSearchSpanFinalImageSymbolNameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Complete namespace and source-language declarations for exactly one Linux
/// Search Span final-image glue selection.
///
/// Construction is a pure projection of a compile-identity claim and an
/// explicit adopter. It neither scans ELF bytes nor authenticates the claim;
/// callers bind it to strict receipt/object inspection separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSearchSpanFinalImageSymbolsV1 {
    compile_identity: [u8; 32],
    adopter: SearchSpanFinalImageAdopterV1,
    glue: LinuxSearchSpanFinalImageSymbolNameV1,
    expectation: LinuxSearchSpanFinalImageSymbolNameV1,
    entry: LinuxSearchSpanFinalImageSymbolNameV1,
    payload: LinuxSearchSpanFinalImageSymbolNameV1,
    metadata: LinuxSearchSpanFinalImageSymbolNameV1,
    adopter_symbol: LinuxSearchSpanFinalImageSymbolNameV1,
}

impl LinuxSearchSpanFinalImageSymbolsV1 {
    pub fn from_compile_identity_claim(
        compile_identity: &[u8; 32],
        adopter: SearchSpanFinalImageAdopterV1,
    ) -> Result<Self, LinuxSearchSpanFinalImageGlueErrorV1> {
        Ok(Self {
            compile_identity: *compile_identity,
            adopter,
            glue: LinuxSearchSpanFinalImageSymbolNameV1::suffixed(
                GLUE_SYMBOL_PREFIX_V1,
                compile_identity,
            )?,
            expectation: LinuxSearchSpanFinalImageSymbolNameV1::suffixed(
                EXPECTATION_SYMBOL_PREFIX_V1,
                compile_identity,
            )?,
            entry: LinuxSearchSpanFinalImageSymbolNameV1::suffixed(
                SEARCH_ENTRY_SYMBOL_PREFIX_V1,
                compile_identity,
            )?,
            payload: LinuxSearchSpanFinalImageSymbolNameV1::suffixed(
                PAYLOAD_SYMBOL_PREFIX_V1,
                compile_identity,
            )?,
            metadata: LinuxSearchSpanFinalImageSymbolNameV1::suffixed(
                METADATA_SYMBOL_PREFIX_V1,
                compile_identity,
            )?,
            adopter_symbol: LinuxSearchSpanFinalImageSymbolNameV1::fixed(adopter_symbol(adopter))?,
        })
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        &self.compile_identity
    }

    #[must_use]
    pub const fn adopter(&self) -> SearchSpanFinalImageAdopterV1 {
        self.adopter
    }

    #[must_use]
    pub const fn glue(&self) -> &LinuxSearchSpanFinalImageSymbolNameV1 {
        &self.glue
    }

    #[must_use]
    pub const fn expectation(&self) -> &LinuxSearchSpanFinalImageSymbolNameV1 {
        &self.expectation
    }

    #[must_use]
    pub const fn entry(&self) -> &LinuxSearchSpanFinalImageSymbolNameV1 {
        &self.entry
    }

    #[must_use]
    pub const fn payload(&self) -> &LinuxSearchSpanFinalImageSymbolNameV1 {
        &self.payload
    }

    #[must_use]
    pub const fn metadata(&self) -> &LinuxSearchSpanFinalImageSymbolNameV1 {
        &self.metadata
    }

    #[must_use]
    pub const fn adopter_symbol(&self) -> &LinuxSearchSpanFinalImageSymbolNameV1 {
        &self.adopter_symbol
    }

    /// Emit one standalone C header whose declarations name this exact
    /// identity. It deliberately declares a single glue entry.
    pub fn write_c_header(&self, output: &mut impl fmt::Write) -> fmt::Result {
        writeln!(output, "{}", fre_aot_elf::C_HEADER_V1.trim_end())?;
        writeln!(
            output,
            "\n#ifndef FRE_AOT_LINUX_SEARCH_SPAN_FINAL_IMAGE_V1_H"
        )?;
        writeln!(output, "#define FRE_AOT_LINUX_SEARCH_SPAN_FINAL_IMAGE_V1_H")?;
        writeln!(output, "\n#if defined(__cplusplus)")?;
        writeln!(output, "extern \"C\" {{")?;
        writeln!(output, "#endif")?;
        writeln!(
            output,
            "\nstruct fre_aot_static_search_span_adoption_output_v1 {{"
        )?;
        writeln!(output, "  const void *verified;")?;
        writeln!(output, "}};")?;
        writeln!(
            output,
            "\nextern uint64_t {}(const uint8_t *haystack, size_t haystack_len, size_t window_start, size_t window_end, struct fre_aot_search_result_v1 *result);",
            self.entry
        )?;
        writeln!(output, "extern const uint8_t {}[];", self.payload)?;
        writeln!(
            output,
            "extern const struct fre_aot_metadata_v1 {};",
            self.metadata
        )?;
        writeln!(
            output,
            "extern const uint8_t {}[{}];",
            self.expectation, STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1
        )?;
        writeln!(
            output,
            "extern uint32_t {}(struct fre_aot_static_search_span_adoption_output_v1 *output);",
            self.glue
        )?;
        writeln!(
            output,
            "extern uint32_t {}(struct fre_aot_static_search_span_adoption_output_v1 *output, uint32_t row_selector, const uint8_t *expectation, const uint8_t *entry, const uint8_t *payload, const uint8_t *metadata);",
            self.adopter_symbol
        )?;
        writeln!(output, "\n#if defined(__cplusplus)")?;
        writeln!(output, "}}")?;
        writeln!(output, "#endif")?;
        writeln!(
            output,
            "\n#endif /* FRE_AOT_LINUX_SEARCH_SPAN_FINAL_IMAGE_V1_H */"
        )
    }

    /// Emit Rust FFI declarations with fixed local identifiers and exact
    /// identity-derived `link_name` attributes. One generated module binds one
    /// and only one glue object.
    pub fn write_rust_bindings(&self, output: &mut impl fmt::Write) -> fmt::Result {
        writeln!(
            output,
            "pub const FRE_AOT_LINKED_SEARCH_SPAN_EXPECTATION_BYTES_V1: usize = {STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1};"
        )?;
        writeln!(output, "#[repr(C)]")?;
        writeln!(output, "pub struct FreAotSearchResultV1 {{")?;
        writeln!(output, "    pub start: usize,")?;
        writeln!(output, "    pub end: usize,")?;
        writeln!(output, "}}")?;
        writeln!(output, "#[repr(C)]")?;
        writeln!(
            output,
            "pub struct FreAotStaticSearchSpanAdoptionOutputV1 {{"
        )?;
        writeln!(output, "    pub verified: *const core::ffi::c_void,")?;
        writeln!(output, "}}")?;
        writeln!(output, "unsafe extern \"C\" {{")?;
        writeln!(output, "    #[link_name = \"{}\"]", self.entry)?;
        writeln!(
            output,
            "    pub fn fre_aot_linked_search_entry_v1(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize, result: *mut FreAotSearchResultV1) -> u64;"
        )?;
        for (name, symbol) in [
            ("fre_aot_linked_search_payload_v1", self.payload),
            ("fre_aot_linked_search_metadata_v1", self.metadata),
            (
                "fre_aot_linked_search_span_expectation_v1",
                self.expectation,
            ),
        ] {
            writeln!(output, "    #[link_name = \"{symbol}\"]")?;
            writeln!(output, "    pub static {name}: u8;")?;
        }
        writeln!(output, "    #[link_name = \"{}\"]", self.glue)?;
        writeln!(
            output,
            "    pub fn fre_aot_linked_search_span_glue_v1(output: *mut FreAotStaticSearchSpanAdoptionOutputV1) -> u32;"
        )?;
        writeln!(output, "    #[link_name = \"{}\"]", self.adopter_symbol)?;
        writeln!(
            output,
            "    pub fn fre_aot_linked_search_span_adopter_v1(output: *mut FreAotStaticSearchSpanAdoptionOutputV1, row_selector: u32, expectation: *const u8, entry: *const u8, payload: *const u8, metadata: *const u8) -> u32;"
        )?;
        writeln!(output, "}}")
    }
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

struct StringTables {
    symbols: Vec<u8>,
    glue_name: u32,
    expectation_name: u32,
    entry_name: u32,
    payload_name: u32,
    metadata_name: u32,
    adopter_name: u32,
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
    fn new(
        compile_identity: &[u8; 32],
        adopter: SearchSpanFinalImageAdopterV1,
    ) -> Result<Self, LinuxSearchSpanFinalImageGlueErrorV1> {
        let exported = LinuxSearchSpanFinalImageSymbolsV1::from_compile_identity_claim(
            compile_identity,
            adopter,
        )?;
        let names = [
            exported.glue,
            exported.expectation,
            exported.entry,
            exported.payload,
            exported.metadata,
            exported.adopter_symbol,
        ];
        let mut symbols = Vec::new();
        symbols
            .try_reserve_exact(1024)
            .map_err(|_| LinuxSearchSpanFinalImageGlueErrorV1::AllocationFailed)?;
        symbols.push(0);
        let glue_name = push_string(&mut symbols, names[0].as_bytes())?;
        let expectation_name = push_string(&mut symbols, names[1].as_bytes())?;
        let entry_name = push_string(&mut symbols, names[2].as_bytes())?;
        let payload_name = push_string(&mut symbols, names[3].as_bytes())?;
        let metadata_name = push_string(&mut symbols, names[4].as_bytes())?;
        let adopter_name = push_string(&mut symbols, names[5].as_bytes())?;

        let mut sections = Vec::new();
        sections
            .try_reserve_exact(256)
            .map_err(|_| LinuxSearchSpanFinalImageGlueErrorV1::AllocationFailed)?;
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
            glue_name,
            expectation_name,
            entry_name,
            payload_name,
            metadata_name,
            adopter_name,
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
    fn new(tables: &StringTables) -> Result<Self, LinuxSearchSpanFinalImageGlueErrorV1> {
        let rela_offset = align_up(EXPECTATION_END, 8, "RELA offset")?;
        let string_offset = rela_offset
            .checked_add(
                RELA_BYTES
                    .checked_mul(LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1)
                    .ok_or_else(|| overflow("RELA bytes"))?,
            )
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
                    .ok_or_else(|| overflow("symbol bytes"))?,
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

fn emit_glue_bytes(
    expectation: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1],
    compile_identity: &[u8; 32],
    row_selector: u16,
    adopter: SearchSpanFinalImageAdopterV1,
    limits: LinuxSearchSpanFinalImageGlueLimitsV1,
) -> Result<Vec<u8>, LinuxSearchSpanFinalImageGlueErrorV1> {
    let tables = StringTables::new(compile_identity, adopter)?;
    let layout = Layout::new(&tables)?;
    enforce_limit(layout.object_bytes, limits)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(layout.object_bytes)
        .map_err(|_| LinuxSearchSpanFinalImageGlueErrorV1::AllocationFailed)?;
    bytes.resize(layout.object_bytes, 0);
    write_header(&mut bytes[..ELF_HEADER_BYTES], layout)?;
    copy_region(
        &mut bytes,
        TEXT_OFFSET,
        &encode_glue_code(row_selector)?,
        "glue code",
    )?;
    copy_region(&mut bytes, EXPECTATION_OFFSET, expectation, "expectation")?;
    write_relocations(&mut bytes, layout)?;
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
) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
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
    writer.u64(usize_u64(layout.section_header_offset, "section headers")?)?;
    writer.u32(0)?;
    writer.u16(u16::try_from(ELF_HEADER_BYTES).expect("fixed ELF header"))?;
    writer.u16(0)?;
    writer.u16(0)?;
    writer.u16(u16::try_from(SECTION_HEADER_BYTES).expect("fixed section header"))?;
    writer.u16(u16::try_from(SECTION_COUNT).expect("fixed section count"))?;
    writer.u16(SECTION_STRING_SECTION)?;
    if writer.position() != ELF_HEADER_BYTES {
        return Err(glue_error("ELF header width"));
    }
    Ok(())
}

fn write_relocations(
    bytes: &mut [u8],
    layout: Layout,
) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
    let extent = RELA_BYTES
        .checked_mul(LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1)
        .ok_or_else(|| overflow("RELA extent"))?;
    let mut writer = Writer::new(region_mut(bytes, layout.rela_offset, extent, "RELA table")?);
    for (offset, symbol, kind) in [
        (4_u64, 4_u32, R_AARCH64_ADR_PREL_PG_HI21),
        (8, 4, R_AARCH64_ADD_ABS_LO12_NC),
        (12, 5, R_AARCH64_ADR_PREL_PG_HI21),
        (16, 5, R_AARCH64_ADD_ABS_LO12_NC),
        (20, 6, R_AARCH64_ADR_PREL_PG_HI21),
        (24, 6, R_AARCH64_ADD_ABS_LO12_NC),
        (28, 7, R_AARCH64_ADR_PREL_PG_HI21),
        (32, 7, R_AARCH64_ADD_ABS_LO12_NC),
        (36, 8, R_AARCH64_JUMP26),
    ] {
        writer.u64(offset)?;
        writer.u64((u64::from(symbol) << 32) | u64::from(kind))?;
        writer.i64(0)?;
    }
    if writer.position() != extent {
        return Err(glue_error("RELA table width"));
    }
    Ok(())
}

fn write_symbols(
    bytes: &mut [u8],
    layout: Layout,
    tables: &StringTables,
) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
    let extent = SYMBOL_BYTES
        .checked_mul(SYMBOL_COUNT)
        .ok_or_else(|| overflow("symbol extent"))?;
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
        tables.glue_name,
        STB_GLOBAL_FUNCTION,
        STV_HIDDEN,
        TEXT_SECTION,
        0,
        u64::try_from(LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1).expect("fixed code bytes"),
    )?;
    write_symbol(
        &mut writer,
        tables.expectation_name,
        STB_GLOBAL_OBJECT,
        STV_HIDDEN,
        EXPECTATION_SECTION,
        0,
        u64::try_from(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1).expect("fixed expectation bytes"),
    )?;
    for name in [
        tables.entry_name,
        tables.payload_name,
        tables.metadata_name,
        tables.adopter_name,
    ] {
        write_symbol(&mut writer, name, STB_GLOBAL_NOTYPE, STV_DEFAULT, 0, 0, 0)?;
    }
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
) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
    writer.u32(name)?;
    writer.u8(info)?;
    writer.u8(other)?;
    writer.u16(section)?;
    writer.u64(value)?;
    writer.u64(bytes)
}

#[allow(
    clippy::too_many_lines,
    reason = "the eight canonical ELF section headers remain adjacent for byte-layout auditability"
)]
fn write_sections(
    bytes: &mut [u8],
    layout: Layout,
    tables: &StringTables,
) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
    let extent = SECTION_HEADER_BYTES
        .checked_mul(SECTION_COUNT)
        .ok_or_else(|| overflow("section extent"))?;
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
            size: u64::try_from(LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1)
                .expect("fixed code bytes"),
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
            size: u64::try_from(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1)
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
            size: usize_u64(
                RELA_BYTES
                    .checked_mul(LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1)
                    .ok_or_else(|| overflow("RELA bytes"))?,
                "RELA bytes",
            )?,
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
            size: usize_u64(tables.symbols.len(), "string bytes")?,
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
            offset: usize_u64(layout.symbol_offset, "symbol offset")?,
            size: usize_u64(
                SYMBOL_BYTES
                    .checked_mul(SYMBOL_COUNT)
                    .ok_or_else(|| overflow("symbol bytes"))?,
                "symbol bytes",
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
            offset: usize_u64(layout.section_string_offset, "section strings")?,
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
) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
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

#[allow(
    clippy::arithmetic_side_effects,
    reason = "fixed AArch64 instruction fields contain one u16 selector and audited registers"
)]
fn encode_glue_code(
    row_selector: u16,
) -> Result<
    [u8; LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1],
    LinuxSearchSpanFinalImageGlueErrorV1,
> {
    let mut code = [0_u8; LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1];
    let mut writer = Writer::new(&mut code);
    writer.u32(0x5280_0001 | (u32::from(row_selector) << 5))?;
    for register in [2_u32, 3, 4, 5] {
        writer.u32(0x9000_0000 | register)?;
        writer.u32(0x9100_0000 | (register << 5) | register)?;
    }
    writer.u32(0x1400_0000)?;
    if writer.position() != LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1 {
        return Err(glue_error("glue code width"));
    }
    Ok(code)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "whole-object canonical comparison authenticates the decoded MOVZ selector"
)]
fn decode_row_selector(
    code: &[u8; LINUX_SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1],
) -> Result<u16, LinuxSearchSpanFinalImageGlueErrorV1> {
    let instruction =
        u32::from_le_bytes(code[..4].try_into().expect("fixed first instruction width"));
    let selector =
        u16::try_from((instruction >> 5) & 0xffff).map_err(|_| glue_error("row selector"))?;
    if encode_glue_code(selector)? != *code {
        return Err(glue_error("instruction sequence"));
    }
    Ok(selector)
}

fn push_string(
    destination: &mut Vec<u8>,
    value: &[u8],
) -> Result<u32, LinuxSearchSpanFinalImageGlueErrorV1> {
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
) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
    region_mut(destination, offset, source.len(), at)?.copy_from_slice(source);
    Ok(())
}

fn region_mut<'a>(
    destination: &'a mut [u8],
    offset: usize,
    bytes: usize,
    at: &'static str,
) -> Result<&'a mut [u8], LinuxSearchSpanFinalImageGlueErrorV1> {
    let end = offset.checked_add(bytes).ok_or_else(|| overflow(at))?;
    destination
        .get_mut(offset..end)
        .ok_or_else(|| glue_error(at))
}

fn align_up(
    value: usize,
    alignment: usize,
    at: &'static str,
) -> Result<usize, LinuxSearchSpanFinalImageGlueErrorV1> {
    if !alignment.is_power_of_two() {
        return Err(glue_error("alignment"));
    }
    let mask = alignment
        .checked_sub(1)
        .ok_or_else(|| overflow("alignment mask"))?;
    value
        .checked_add(mask)
        .map(|value| value & !mask)
        .ok_or_else(|| overflow(at))
}

fn enforce_limit(
    required: usize,
    limits: LinuxSearchSpanFinalImageGlueLimitsV1,
) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
    let required = u64::try_from(required).map_err(|_| overflow("object bytes"))?;
    let limit = limits
        .max_object_bytes
        .min(HARD_MAX_LINUX_SEARCH_SPAN_GLUE_OBJECT_BYTES_V1);
    if required > limit {
        Err(LinuxSearchSpanFinalImageGlueErrorV1::ResourceLimit { limit, required })
    } else {
        Ok(())
    }
}

fn usize_u64(value: usize, at: &'static str) -> Result<u64, LinuxSearchSpanFinalImageGlueErrorV1> {
    u64::try_from(value).map_err(|_| overflow(at))
}

const fn glue_error(at: &'static str) -> LinuxSearchSpanFinalImageGlueErrorV1 {
    LinuxSearchSpanFinalImageGlueErrorV1::InvalidGlue { at }
}

const fn source_error(at: &'static str) -> LinuxSearchSpanFinalImageGlueErrorV1 {
    LinuxSearchSpanFinalImageGlueErrorV1::SourceBinding { at }
}

const fn overflow(at: &'static str) -> LinuxSearchSpanFinalImageGlueErrorV1 {
    LinuxSearchSpanFinalImageGlueErrorV1::ArithmeticOverflow { at }
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

    fn raw(&mut self, bytes: &[u8]) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or_else(|| overflow("writer"))?;
        self.destination
            .get_mut(self.position..end)
            .ok_or_else(|| glue_error("writer range"))?
            .copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
        self.raw(&value.to_le_bytes())
    }

    fn i64(&mut self, value: i64) -> Result<(), LinuxSearchSpanFinalImageGlueErrorV1> {
        self.raw(&value.to_le_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LinuxAarch64ExactSearchManifestV1, LinuxAarch64SearchCompilePolicyV1,
        build_linux_static_search_span_expectation_v1,
        plan_and_compile_linux_aarch64_exact_search_v1,
    };
    use fre::RustProfile;

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end test compares the complete tag21 object and both adopter variants"
    )]
    fn tag21_implementation_and_both_adopter_glues_are_deterministic_and_disjoint() {
        let manifest = LinuxAarch64ExactSearchManifestV1::<Span>::tag21_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("tag21 manifest");
        let compiled = plan_and_compile_linux_aarch64_exact_search_v1(
            manifest,
            b"0123456789abcdef".to_vec(),
            RustProfile::default(),
        )
        .expect("tag21 ELF implementation");
        let expectation =
            build_linux_static_search_span_expectation_v1(&compiled).expect("tag21 expectation");
        let limits = LinuxSearchSpanFinalImageGlueLimitsV1::default();
        let production =
            publish_linux_search_span_final_image_glue_v1(&compiled, &expectation, 7, limits)
                .expect("production glue");
        let production_repeat =
            publish_linux_search_span_final_image_glue_v1(&compiled, &expectation, 7, limits)
                .expect("repeated production glue");
        let qualification = publish_linux_search_span_qualification_final_image_glue_v1(
            &compiled,
            &expectation,
            7,
            limits,
        )
        .expect("qualification glue");

        assert_eq!(
            production.object().as_bytes(),
            production_repeat.object().as_bytes()
        );
        assert_eq!(production.receipt(), production_repeat.receipt());
        assert_ne!(
            production.object().object_identity(),
            qualification.object().object_identity()
        );
        assert_ne!(
            production.receipt().receipt_identity(),
            qualification.receipt().receipt_identity()
        );
        assert_eq!(
            production.runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );

        let receipt_bytes = *production.receipt().canonical_bytes();
        assert_eq!(
            receipt_bytes.len(),
            LINUX_UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1
        );
        let reopened_receipt =
            LinuxUnsignedSearchSpanFinalImageReceiptV1::from_canonical_bytes(&receipt_bytes)
                .expect("reopened final-image receipt");
        assert_eq!(&reopened_receipt, production.receipt());
        let compiler_receipt_bytes = compiled
            .receipt()
            .canonical_receipt_bytes()
            .expect("canonical compiler receipt");
        let reopened_compiler =
            crate::inspect_linux_search_compile_receipt_v1(&compiler_receipt_bytes)
                .expect("reopened compiler receipt");
        let reopened_glue = reopened_receipt
            .validate_reopened_candidate(
                &reopened_compiler,
                compiled.object().as_bytes(),
                expectation.as_bytes(),
                production.object().as_bytes(),
                ObjectLimitsV1::default(),
                limits,
            )
            .expect("fully reopened candidate");
        let symbols = reopened_receipt
            .exported_symbols()
            .expect("receipt-derived symbols");
        assert_eq!(
            symbols,
            production
                .object()
                .exported_symbols()
                .expect("object-derived symbols")
        );
        assert_eq!(
            symbols,
            reopened_glue
                .exported_symbols()
                .expect("inspection-derived symbols")
        );
        let qualification_symbols = qualification
            .receipt()
            .exported_symbols()
            .expect("qualification symbols");
        assert_eq!(symbols.glue(), qualification_symbols.glue());
        assert_eq!(symbols.expectation(), qualification_symbols.expectation());
        assert_ne!(
            symbols.adopter_symbol(),
            qualification_symbols.adopter_symbol()
        );
        let identity_hex = hex(symbols.compile_identity());
        for symbol in [
            symbols.glue(),
            symbols.expectation(),
            symbols.entry(),
            symbols.payload(),
            symbols.metadata(),
        ] {
            assert!(symbol.as_str().ends_with(&identity_hex));
        }
        let mut c_header = String::new();
        symbols
            .write_c_header(&mut c_header)
            .expect("generated C header");
        let mut rust_bindings = String::new();
        symbols
            .write_rust_bindings(&mut rust_bindings)
            .expect("generated Rust bindings");
        for symbol in [
            symbols.glue(),
            symbols.expectation(),
            symbols.entry(),
            symbols.payload(),
            symbols.metadata(),
            symbols.adopter_symbol(),
        ] {
            assert!(c_header.contains(symbol.as_str()));
            assert!(rust_bindings.contains(symbol.as_str()));
        }
        assert_eq!(c_header.matches(symbols.glue().as_str()).count(), 1);
        assert_eq!(rust_bindings.matches(symbols.glue().as_str()).count(), 1);

        for index in 0..receipt_bytes.len() {
            let mut changed = receipt_bytes;
            changed[index] ^= 1;
            assert!(
                LinuxUnsignedSearchSpanFinalImageReceiptV1::from_canonical_bytes(&changed).is_err(),
                "single-byte final-image receipt mutation {index} survived"
            );
        }

        for index in 0..production.object().as_bytes().len() {
            let mut changed = production.object().as_bytes().to_vec();
            changed[index] ^= 1;
            if let Ok(inspection) = inspect_linux_search_span_final_image_glue_v1(&changed, limits)
            {
                assert_ne!(
                    inspection.row_selector(),
                    production.object().row_selector(),
                    "structurally valid glue mutation {index} retained the selector"
                );
                assert_ne!(
                    inspection.object_identity(),
                    production.object().object_identity(),
                    "structurally valid glue mutation {index} retained the object identity"
                );
                assert_ne!(
                    inspection.code_identity(),
                    production.object().code_identity(),
                    "structurally valid glue mutation {index} retained the code identity"
                );
            }
            assert!(
                production
                    .receipt()
                    .validate_candidate(&compiled, &expectation, &changed, limits)
                    .is_err(),
                "single-byte glue mutation {index} survived source-bound validation"
            );
            assert!(
                reopened_receipt
                    .validate_reopened_candidate(
                        &reopened_compiler,
                        compiled.object().as_bytes(),
                        expectation.as_bytes(),
                        &changed,
                        ObjectLimitsV1::default(),
                        limits,
                    )
                    .is_err(),
                "single-byte glue mutation {index} survived reopened validation"
            );
        }
    }

    fn hex(bytes: &[u8; 32]) -> String {
        use core::fmt::Write as _;

        let mut output = String::new();
        for byte in bytes {
            write!(output, "{byte:02x}").expect("String formatting");
        }
        output
    }
}
