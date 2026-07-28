//! Deterministic final-image glue for one source-authenticated Search V1 Span.
//!
//! This module emits a bounded arm64 Mach-O relocatable object. The object
//! contains a 40-byte row-selector-first trampoline and the exact 584-byte
//! Search Span expectation. It refers only to identity-suffixed implementation
//! symbols and to one explicitly selected runtime adopter symbol.
//!
//! Emission, inspection, and the unsigned receipt remain compiler artifacts.
//! They do not invoke a linker, inspect a mapped final image, populate a
//! static-runtime qualification row, or grant runtime authority.

use core::fmt;

use fre_aot_macho::{
    EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1, METADATA_SYMBOL_PREFIX_V1, ObjectLimits,
    PAYLOAD_SYMBOL_PREFIX_V1, SEARCH_ENTRY_SYMBOL_PREFIX_V1,
};
use fre_aot_search_contract::{
    STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1, inspect_static_search_span_expectation_v1,
};
use fre_kernel_ir::{OutputKind, Span};
use sha2::{Digest, Sha256};

use crate::{SearchAotRuntimeAuthorityV1, SearchCompiledObjectV1, StaticSearchSpanExpectationV1};

const FINAL_IMAGE_RECEIPT_DOMAIN_V1: &[u8] = b"FRE-AOT-SEARCH-SPAN-UNSIGNED-FINAL-IMAGE\0\x01";
const FINAL_IMAGE_RECEIPT_MAGIC_V1: [u8; 8] = *b"FRESSG\0\x01";
const FINAL_IMAGE_RECEIPT_SCHEMA_V1: u16 = 1;
const FINAL_IMAGE_RECEIPT_ADOPTER_OFFSET: usize = 10;
const FINAL_IMAGE_RECEIPT_ROW_OFFSET: usize = 16;
const FINAL_IMAGE_RECEIPT_OBJECT_BYTES_OFFSET: usize = 24;
const FINAL_IMAGE_RECEIPT_COMPILE_IDENTITY_OFFSET: usize = 32;
const FINAL_IMAGE_RECEIPT_IMPLEMENTATION_OBJECT_IDENTITY_OFFSET: usize = 64;
const FINAL_IMAGE_RECEIPT_COMPILER_RECEIPT_IDENTITY_OFFSET: usize = 96;
const FINAL_IMAGE_RECEIPT_EXPECTATION_IDENTITY_OFFSET: usize = 128;
const FINAL_IMAGE_RECEIPT_GLUE_IDENTITY_OFFSET: usize = 160;
const FINAL_IMAGE_RECEIPT_CODE_IDENTITY_OFFSET: usize = 192;
const FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET: usize = 224;

/// Exact canonical width of the signer-free Search final-image receipt.
pub const UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1: usize = 256;
/// Exact `AArch64` trampoline width.
pub const SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1: usize = 40;
/// Exact external relocation count in the trampoline section.
pub const SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1: usize = 9;
/// Strict canonical inspection performs no heap allocation.
pub const SEARCH_SPAN_FINAL_IMAGE_GLUE_INSPECTION_ALLOCATIONS_V1: u8 = 0;

const GLUE_SYMBOL_PREFIX_V1: &str = "fre_aot_search_span_glue_v1_";
const EXPECTATION_SYMBOL_PREFIX_V1: &str = "fre_aot_search_span_expectation_v1_";
const RUNTIME_ADOPT_SYMBOL_V1: &str = "fre_aot_static_search_span_adopt_raw_v1";
const QUALIFICATION_RUNTIME_ADOPT_SYMBOL_V1: &str =
    "fre_aot_static_search_span_adopt_qualification_raw_v1";

const CONTENT_OFFSET: usize = 400;
const EXPECTATION_FILE_OFFSET: usize = CONTENT_OFFSET + SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1;
const EXPECTATION_ADDRESS: usize = SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1;
const SEGMENT_BYTES: usize =
    SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1 + STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1;
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
const RELOCATION_BYTES: usize = 8;
const NLIST_64_BYTES: usize = 16;
const SYMBOLS: usize = 6;
const DEFINED_SYMBOLS: u32 = 2;
const UNDEFINED_SYMBOLS: u32 = 4;
const SECTIONS: u32 = 2;
const SYMBOL_NAME_STORAGE_BYTES: usize = 112;
const CANONICAL_REEMIT_BUFFER_BYTES: usize = 2048;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
const MH_OBJECT: u32 = 1;
const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x02;
const LC_DYSYMTAB: u32 = 0x0b;
const LC_BUILD_VERSION: u32 = 0x32;
const LOAD_COMMAND_COUNT: u32 = 4;
const PLATFORM_MACOS_LOAD_COMMAND: u32 = 1;
const MIN_MACOS_VERSION_V1: u32 = 0x000b_0000;
const VM_PROT_RWX: u32 = 7;
const TEXT_SECTION_FLAGS: u32 = 0x8000_0400;
const EXPECTATION_SECTION_FLAGS: u32 = 0;
const DEFINED_PRIVATE_EXTERNAL_N_TYPE: u8 = 0x1f;
const UNDEFINED_EXTERNAL_N_TYPE: u8 = 0x01;

const ARM64_RELOC_BRANCH26: u8 = 2;
const ARM64_RELOC_PAGE21: u8 = 3;
const ARM64_RELOC_PAGEOFF12: u8 = 4;

const _: () = assert!(MACH_HEADER_BYTES + LOAD_COMMAND_BYTES <= CONTENT_OFFSET);
const _: () = assert!(
    EXPECTATION_FILE_OFFSET + STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1
        == CONTENT_OFFSET + SEGMENT_BYTES
);
const _: () = assert!(UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1 == 256);
const _: () = assert!(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1 == 64);

/// Refusal while emitting or strictly inspecting Search final-image glue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchSpanFinalImageGlueErrorV1 {
    ResourceLimit {
        resource: &'static str,
        limit: u64,
        required: u64,
    },
    AllocationFailed,
    InvalidGlue {
        at: &'static str,
    },
    InvalidReceipt,
    SourceBinding {
        at: &'static str,
    },
    ArithmeticOverflow {
        at: &'static str,
    },
}

impl fmt::Display for SearchSpanFinalImageGlueErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE Search Span final-image glue failed: {self:?}"
        )
    }
}

impl std::error::Error for SearchSpanFinalImageGlueErrorV1 {}

/// Runtime boundary named by one deterministic Search glue object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchSpanFinalImageAdopterV1 {
    /// Ordinary production adoption. The runtime production row table remains
    /// empty until a separate reviewed promotion transaction changes it.
    Production,
    /// Separately named private qualification adoption.
    QualificationPrivate,
}

impl SearchSpanFinalImageAdopterV1 {
    const fn symbol(self) -> &'static str {
        match self {
            Self::Production => RUNTIME_ADOPT_SYMBOL_V1,
            Self::QualificationPrivate => QUALIFICATION_RUNTIME_ADOPT_SYMBOL_V1,
        }
    }

    const fn receipt_code(self) -> u16 {
        match self {
            Self::Production => 0,
            Self::QualificationPrivate => 1,
        }
    }

    const fn from_receipt_code(code: u16) -> Option<Self> {
        match code {
            0 => Some(Self::Production),
            1 => Some(Self::QualificationPrivate),
            _ => None,
        }
    }
}

/// Caller-selected finite bound for one Search glue object's canonical bytes
/// and actual retained allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchSpanFinalImageGlueLimitsV1 {
    pub max_object_bytes: u64,
}

impl Default for SearchSpanFinalImageGlueLimitsV1 {
    fn default() -> Self {
        Self {
            max_object_bytes: 16 << 10,
        }
    }
}

/// One owned deterministic relocatable Search glue object.
#[derive(Debug, Eq, PartialEq)]
pub struct SearchSpanFinalImageGlueObjectV1 {
    bytes: Vec<u8>,
    row_selector: u16,
    adopter: SearchSpanFinalImageAdopterV1,
    compile_identity: [u8; 32],
    implementation_object_identity: [u8; 32],
    compiler_receipt_identity: [u8; 32],
    expectation_identity: [u8; 32],
    glue_object_identity: [u8; 32],
    glue_code_identity: [u8; 32],
}

impl SearchSpanFinalImageGlueObjectV1 {
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
    pub const fn glue_object_identity(&self) -> &[u8; 32] {
        &self.glue_object_identity
    }

    #[must_use]
    pub const fn glue_code_identity(&self) -> &[u8; 32] {
        &self.glue_code_identity
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

/// Allocation-free strict view of one canonical Search glue object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchSpanFinalImageGlueInspectionV1<'a> {
    object_bytes: usize,
    row_selector: u16,
    adopter: SearchSpanFinalImageAdopterV1,
    compile_identity: [u8; 32],
    implementation_object_identity: [u8; 32],
    compiler_receipt_identity: [u8; 32],
    expectation_identity: [u8; 32],
    glue_object_identity: [u8; 32],
    glue_code_identity: [u8; 32],
    expectation: &'a [u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1],
}

impl<'a> SearchSpanFinalImageGlueInspectionV1<'a> {
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
    pub const fn glue_object_identity(&self) -> &[u8; 32] {
        &self.glue_object_identity
    }

    #[must_use]
    pub const fn glue_code_identity(&self) -> &[u8; 32] {
        &self.glue_code_identity
    }

    #[must_use]
    pub const fn expectation(&self) -> &'a [u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1] {
        self.expectation
    }

    #[must_use]
    pub const fn allocations(&self) -> u8 {
        SEARCH_SPAN_FINAL_IMAGE_GLUE_INSPECTION_ALLOCATIONS_V1
    }
}

/// Canonical signer-free binding of one Search implementation and glue object.
///
/// The receipt binds the implementation compile/object/receipt identities, the
/// expectation identity, and the complete glue/code identities. It is neither
/// a signature nor a runtime support row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsignedSearchSpanFinalImageReceiptV1 {
    bytes: [u8; UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1],
}

impl UnsignedSearchSpanFinalImageReceiptV1 {
    #[must_use]
    pub const fn canonical_bytes(
        &self,
    ) -> &[u8; UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1] {
        &self.bytes
    }

    /// An unsigned final-image receipt never grants runtime authority.
    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }

    #[must_use]
    pub fn authenticates_itself(&self) -> bool {
        let Some(adopter) = self.adopter() else {
            return false;
        };
        self.bytes[..8] == FINAL_IMAGE_RECEIPT_MAGIC_V1
            && self.bytes[8..10] == FINAL_IMAGE_RECEIPT_SCHEMA_V1.to_le_bytes()
            && self.bytes[FINAL_IMAGE_RECEIPT_ADOPTER_OFFSET..12]
                == adopter.receipt_code().to_le_bytes()
            && self.bytes[12..16]
                == u32::try_from(UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1)
                    .expect("fixed Search final-image receipt width")
                    .to_le_bytes()
            && self.bytes[18..20]
                == u16::try_from(SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1)
                    .expect("fixed Search relocation count")
                    .to_le_bytes()
            && self.bytes[20..22]
                == u16::try_from(SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1)
                    .expect("fixed Search glue code width")
                    .to_le_bytes()
            && self.bytes[22..24] == [0; 2]
            && digest_with_domain(
                FINAL_IMAGE_RECEIPT_DOMAIN_V1,
                &self.bytes[..FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET],
            ) == *self.content_identity()
    }

    #[must_use]
    pub fn adopter(&self) -> Option<SearchSpanFinalImageAdopterV1> {
        SearchSpanFinalImageAdopterV1::from_receipt_code(u16::from_le_bytes(
            self.bytes[FINAL_IMAGE_RECEIPT_ADOPTER_OFFSET..12]
                .try_into()
                .expect("fixed Search final-image adopter range"),
        ))
    }

    #[must_use]
    pub fn row_selector(&self) -> u16 {
        u16::from_le_bytes(
            self.bytes[FINAL_IMAGE_RECEIPT_ROW_OFFSET..FINAL_IMAGE_RECEIPT_ROW_OFFSET + 2]
                .try_into()
                .expect("fixed Search row-selector range"),
        )
    }

    /// Canonical object content bytes bound by this receipt.
    ///
    /// This is distinct from the emitter's retained allocation, which is
    /// reported by [`SearchSpanFinalImageGlueObjectV1::retained_bytes`].
    #[must_use]
    pub fn object_bytes(&self) -> u64 {
        u64::from_le_bytes(
            self.bytes[FINAL_IMAGE_RECEIPT_OBJECT_BYTES_OFFSET
                ..FINAL_IMAGE_RECEIPT_OBJECT_BYTES_OFFSET + 8]
                .try_into()
                .expect("fixed Search final-image object-bytes range"),
        )
    }

    #[must_use]
    pub fn compile_identity(&self) -> &[u8; 32] {
        fixed_identity(&self.bytes, FINAL_IMAGE_RECEIPT_COMPILE_IDENTITY_OFFSET)
    }

    #[must_use]
    pub fn implementation_object_identity(&self) -> &[u8; 32] {
        fixed_identity(
            &self.bytes,
            FINAL_IMAGE_RECEIPT_IMPLEMENTATION_OBJECT_IDENTITY_OFFSET,
        )
    }

    #[must_use]
    pub fn compiler_receipt_identity(&self) -> &[u8; 32] {
        fixed_identity(
            &self.bytes,
            FINAL_IMAGE_RECEIPT_COMPILER_RECEIPT_IDENTITY_OFFSET,
        )
    }

    #[must_use]
    pub fn expectation_identity(&self) -> &[u8; 32] {
        fixed_identity(&self.bytes, FINAL_IMAGE_RECEIPT_EXPECTATION_IDENTITY_OFFSET)
    }

    #[must_use]
    pub fn glue_object_identity(&self) -> &[u8; 32] {
        fixed_identity(&self.bytes, FINAL_IMAGE_RECEIPT_GLUE_IDENTITY_OFFSET)
    }

    #[must_use]
    pub fn glue_code_identity(&self) -> &[u8; 32] {
        fixed_identity(&self.bytes, FINAL_IMAGE_RECEIPT_CODE_IDENTITY_OFFSET)
    }

    #[must_use]
    pub fn content_identity(&self) -> &[u8; 32] {
        fixed_identity(&self.bytes, FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET)
    }

    /// Validate source objects and arbitrary glue bytes without creating
    /// runtime authority.
    pub fn validate_candidate<'a>(
        &self,
        compiled: &SearchCompiledObjectV1<Span>,
        expectation: &StaticSearchSpanExpectationV1,
        candidate: &'a [u8],
        limits: SearchSpanFinalImageGlueLimitsV1,
    ) -> Result<SearchSpanFinalImageGlueInspectionV1<'a>, SearchSpanFinalImageGlueErrorV1> {
        if !self.authenticates_itself() {
            return Err(SearchSpanFinalImageGlueErrorV1::InvalidReceipt);
        }
        let source = authenticate_source(compiled, expectation)?;
        let inspection = inspect_search_span_final_image_glue_v1(candidate, limits)?;
        let expected_object_bytes = self.object_bytes();
        let adopter = self
            .adopter()
            .ok_or(SearchSpanFinalImageGlueErrorV1::InvalidReceipt)?;
        if u64::try_from(inspection.object_bytes()).ok() != Some(expected_object_bytes)
            || inspection.row_selector() != self.row_selector()
            || inspection.adopter() != adopter
            || inspection.compile_identity() != self.compile_identity()
            || inspection.implementation_object_identity() != self.implementation_object_identity()
            || inspection.compiler_receipt_identity() != self.compiler_receipt_identity()
            || inspection.expectation_identity() != self.expectation_identity()
            || inspection.glue_object_identity() != self.glue_object_identity()
            || inspection.glue_code_identity() != self.glue_code_identity()
            || source.compile_identity != *self.compile_identity()
            || source.implementation_object_identity != *self.implementation_object_identity()
            || source.compiler_receipt_identity != *self.compiler_receipt_identity()
            || source.expectation_identity != *self.expectation_identity()
            || inspection.expectation() != expectation.as_bytes()
        {
            return Err(SearchSpanFinalImageGlueErrorV1::InvalidReceipt);
        }
        Ok(inspection)
    }
}

/// Inert deterministic Search glue plus its unsigned receipt.
#[derive(Debug, Eq, PartialEq)]
pub struct PublishedSearchSpanFinalImageGlueV1 {
    object: SearchSpanFinalImageGlueObjectV1,
    receipt: UnsignedSearchSpanFinalImageReceiptV1,
}

impl PublishedSearchSpanFinalImageGlueV1 {
    #[must_use]
    pub const fn object(&self) -> &SearchSpanFinalImageGlueObjectV1 {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> &UnsignedSearchSpanFinalImageReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }
}

/// Emit production-adopter glue for one compiler-authenticated Search Span.
///
/// The `AArch64` trampoline preserves the caller's output pointer in `x0`, loads
/// the source-qualified row selector into `w1`, materializes expectation,
/// entry, payload, and metadata addresses in `x2..x5`, and tail-branches to the
/// production raw adopter. The production runtime row table is not changed by
/// this function and remains empty in the current source revision.
pub fn publish_search_span_final_image_glue_v1(
    compiled: &SearchCompiledObjectV1<Span>,
    expectation: &StaticSearchSpanExpectationV1,
    row_selector: u16,
    limits: SearchSpanFinalImageGlueLimitsV1,
) -> Result<PublishedSearchSpanFinalImageGlueV1, SearchSpanFinalImageGlueErrorV1> {
    publish_search_span_final_image_glue_for_adopter_v1(
        compiled,
        expectation,
        row_selector,
        SearchSpanFinalImageAdopterV1::Production,
        limits,
    )
}

/// Emit glue for the separately named private qualification adopter.
///
/// This only changes the undefined adopter symbol and its receipt binding. It
/// neither enables the runtime feature nor inserts a qualification row.
pub fn publish_search_span_qualification_final_image_glue_v1(
    compiled: &SearchCompiledObjectV1<Span>,
    expectation: &StaticSearchSpanExpectationV1,
    row_selector: u16,
    limits: SearchSpanFinalImageGlueLimitsV1,
) -> Result<PublishedSearchSpanFinalImageGlueV1, SearchSpanFinalImageGlueErrorV1> {
    publish_search_span_final_image_glue_for_adopter_v1(
        compiled,
        expectation,
        row_selector,
        SearchSpanFinalImageAdopterV1::QualificationPrivate,
        limits,
    )
}

fn publish_search_span_final_image_glue_for_adopter_v1(
    compiled: &SearchCompiledObjectV1<Span>,
    expectation: &StaticSearchSpanExpectationV1,
    row_selector: u16,
    adopter: SearchSpanFinalImageAdopterV1,
    limits: SearchSpanFinalImageGlueLimitsV1,
) -> Result<PublishedSearchSpanFinalImageGlueV1, SearchSpanFinalImageGlueErrorV1> {
    let source = authenticate_source(compiled, expectation)?;
    let bytes = emit_owned_glue_bytes(
        expectation.as_bytes(),
        source.compile_identity,
        row_selector,
        adopter,
        limits,
    )?;
    let inspection = inspect_search_span_final_image_glue_v1(&bytes, limits)?;
    if inspection.adopter() != adopter
        || inspection.row_selector() != row_selector
        || inspection.compile_identity() != &source.compile_identity
        || inspection.implementation_object_identity() != &source.implementation_object_identity
        || inspection.compiler_receipt_identity() != &source.compiler_receipt_identity
        || inspection.expectation_identity() != &source.expectation_identity
        || inspection.expectation() != expectation.as_bytes()
    {
        return Err(glue_error("fresh Search glue inspection"));
    }
    let object = SearchSpanFinalImageGlueObjectV1 {
        row_selector: inspection.row_selector,
        adopter: inspection.adopter,
        compile_identity: inspection.compile_identity,
        implementation_object_identity: inspection.implementation_object_identity,
        compiler_receipt_identity: inspection.compiler_receipt_identity,
        expectation_identity: inspection.expectation_identity,
        glue_object_identity: inspection.glue_object_identity,
        glue_code_identity: inspection.glue_code_identity,
        bytes,
    };
    let receipt = build_final_image_receipt(source, &object)?;
    if receipt.runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
        || receipt
            .validate_candidate(compiled, expectation, object.as_bytes(), limits)
            .is_err()
    {
        return Err(SearchSpanFinalImageGlueErrorV1::InvalidReceipt);
    }
    Ok(PublishedSearchSpanFinalImageGlueV1 { object, receipt })
}

/// Strictly inspect one canonical Search Span final-image glue object.
///
/// Inspection checks the caller's byte limit, strictly parses the embedded
/// expectation, decodes only the bounded selector immediate, re-emits both
/// allowed adopter variants into one fixed stack buffer, and accepts only an
/// exact whole-object match. It performs no heap allocation.
pub fn inspect_search_span_final_image_glue_v1(
    bytes: &[u8],
    limits: SearchSpanFinalImageGlueLimitsV1,
) -> Result<SearchSpanFinalImageGlueInspectionV1<'_>, SearchSpanFinalImageGlueErrorV1> {
    enforce_limit(
        limits.max_object_bytes,
        usize_u64(bytes.len(), "Search glue object bytes")?,
    )?;
    if bytes.len() > CANONICAL_REEMIT_BUFFER_BYTES {
        return Err(glue_error("Search glue canonical object bound"));
    }
    let expectation_end = EXPECTATION_FILE_OFFSET
        .checked_add(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1)
        .ok_or_else(|| overflow("Search glue expectation end"))?;
    let expectation: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1] = bytes
        .get(EXPECTATION_FILE_OFFSET..expectation_end)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| glue_error("Search glue expectation range"))?;
    let claim = inspect_static_search_span_expectation_v1(expectation)
        .map_err(|_| glue_error("Search glue expectation contract"))?;
    let compile_identity = *claim.compile_identity();
    let implementation_object_identity = *claim.object_identity();
    let compiler_receipt_identity = *claim.receipt_identity();
    let expectation_identity = *claim.expectation_identity();
    let code: &[u8; SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1] = bytes
        .get(CONTENT_OFFSET..EXPECTATION_FILE_OFFSET)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| glue_error("Search glue code range"))?;
    let row_selector = decode_row_selector(code)?;

    let mut canonical = [0_u8; CANONICAL_REEMIT_BUFFER_BYTES];
    let production_layout = emit_glue_bytes_into(
        &mut canonical,
        expectation,
        compile_identity,
        row_selector,
        SearchSpanFinalImageAdopterV1::Production,
    )?;
    let adopter = if bytes == &canonical[..production_layout.object_bytes] {
        SearchSpanFinalImageAdopterV1::Production
    } else {
        let qualification_layout = emit_glue_bytes_into(
            &mut canonical,
            expectation,
            compile_identity,
            row_selector,
            SearchSpanFinalImageAdopterV1::QualificationPrivate,
        )?;
        if bytes != &canonical[..qualification_layout.object_bytes] {
            return Err(glue_error("canonical Search glue object"));
        }
        SearchSpanFinalImageAdopterV1::QualificationPrivate
    };

    Ok(SearchSpanFinalImageGlueInspectionV1 {
        object_bytes: bytes.len(),
        row_selector,
        adopter,
        compile_identity,
        implementation_object_identity,
        compiler_receipt_identity,
        expectation_identity,
        glue_object_identity: digest(bytes),
        glue_code_identity: digest(code),
        expectation,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "each field is a distinct identity in the authenticated source-binding tuple"
)]
struct SearchGlueSourceBindingV1 {
    compile_identity: [u8; 32],
    implementation_object_identity: [u8; 32],
    compiler_receipt_identity: [u8; 32],
    expectation_identity: [u8; 32],
}

fn authenticate_source(
    compiled: &SearchCompiledObjectV1<Span>,
    expectation: &StaticSearchSpanExpectationV1,
) -> Result<SearchGlueSourceBindingV1, SearchSpanFinalImageGlueErrorV1> {
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
    let object_inspection = receipt
        .validate_object(compiled.object().as_bytes(), ObjectLimits::default())
        .map_err(|_| source_error("compiler object receipt"))?;
    let claim = inspect_static_search_span_expectation_v1(expectation.as_bytes())
        .map_err(|_| source_error("Search Span expectation"))?;
    if !expectation.authenticates_claim(&claim)
        || object_inspection.metadata() != receipt.metadata()
        || object_inspection.metadata_bytes() != expectation.metadata_bytes_v1()
        || compiled.object().metadata() != receipt.metadata()
        || compiled.object().compile_identity() != receipt.compile_identity()
        || compiled.object().object_identity() != receipt.object_identity()
        || expectation.compile_identity() != receipt.compile_identity()
        || expectation.object_identity() != receipt.object_identity()
        || expectation.receipt_identity() != receipt.receipt_identity()
        || claim.compile_identity() != receipt.compile_identity().as_bytes()
        || claim.object_identity() != receipt.object_identity().as_bytes()
        || claim.receipt_identity() != receipt.receipt_identity().as_bytes()
        || claim.expectation_identity() != expectation.expectation_identity().as_bytes()
    {
        return Err(source_error("compiler object and expectation binding"));
    }
    Ok(SearchGlueSourceBindingV1 {
        compile_identity: *receipt.compile_identity().as_bytes(),
        implementation_object_identity: *receipt.object_identity().as_bytes(),
        compiler_receipt_identity: *receipt.receipt_identity().as_bytes(),
        expectation_identity: *expectation.expectation_identity().as_bytes(),
    })
}

fn build_final_image_receipt(
    source: SearchGlueSourceBindingV1,
    object: &SearchSpanFinalImageGlueObjectV1,
) -> Result<UnsignedSearchSpanFinalImageReceiptV1, SearchSpanFinalImageGlueErrorV1> {
    let mut bytes = [0_u8; UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1];
    {
        let mut writer = Writer::new(&mut bytes);
        writer.bytes(&FINAL_IMAGE_RECEIPT_MAGIC_V1)?;
        writer.u16(FINAL_IMAGE_RECEIPT_SCHEMA_V1)?;
        writer.u16(object.adopter().receipt_code())?;
        writer.u32(
            u32::try_from(UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1)
                .expect("fixed Search final-image receipt width"),
        )?;
        writer.u16(object.row_selector())?;
        writer.u16(
            u16::try_from(SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1)
                .expect("fixed Search relocation count"),
        )?;
        writer.u16(
            u16::try_from(SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1)
                .expect("fixed Search glue code width"),
        )?;
        writer.u16(0)?;
        writer.u64(usize_u64(
            object.as_bytes().len(),
            "Search glue object bytes",
        )?)?;
        writer.bytes(&source.compile_identity)?;
        writer.bytes(&source.implementation_object_identity)?;
        writer.bytes(&source.compiler_receipt_identity)?;
        writer.bytes(&source.expectation_identity)?;
        writer.bytes(object.glue_object_identity())?;
        writer.bytes(object.glue_code_identity())?;
        if writer.position() != FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET {
            return Err(SearchSpanFinalImageGlueErrorV1::InvalidReceipt);
        }
    }
    let content_identity = digest_with_domain(
        FINAL_IMAGE_RECEIPT_DOMAIN_V1,
        &bytes[..FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET],
    );
    bytes[FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET..].copy_from_slice(&content_identity);
    let receipt = UnsignedSearchSpanFinalImageReceiptV1 { bytes };
    if !receipt.authenticates_itself() {
        return Err(SearchSpanFinalImageGlueErrorV1::InvalidReceipt);
    }
    Ok(receipt)
}

fn emit_owned_glue_bytes(
    expectation: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1],
    compile_identity: [u8; 32],
    row_selector: u16,
    adopter: SearchSpanFinalImageAdopterV1,
    limits: SearchSpanFinalImageGlueLimitsV1,
) -> Result<Vec<u8>, SearchSpanFinalImageGlueErrorV1> {
    let layout = GlueLayout::new(&compile_identity, adopter)?;
    enforce_limit(
        limits.max_object_bytes,
        usize_u64(layout.object_bytes, "Search glue object bytes")?,
    )?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(layout.object_bytes)
        .map_err(|_| SearchSpanFinalImageGlueErrorV1::AllocationFailed)?;
    let retained_bytes = usize_u64(bytes.capacity(), "Search glue retained bytes")?;
    enforce_retained_limit(limits.max_object_bytes, retained_bytes)?;
    if bytes.capacity() < layout.object_bytes {
        return Err(glue_error("Search glue allocation capacity"));
    }
    bytes.resize(layout.object_bytes, 0);
    let emitted = emit_glue_bytes_into(
        &mut bytes,
        expectation,
        compile_identity,
        row_selector,
        adopter,
    )?;
    if emitted != layout || bytes.len() != layout.object_bytes {
        return Err(glue_error("owned Search glue allocation"));
    }
    Ok(bytes)
}

fn emit_glue_bytes_into(
    destination: &mut [u8],
    expectation: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1],
    compile_identity: [u8; 32],
    row_selector: u16,
    adopter: SearchSpanFinalImageAdopterV1,
) -> Result<GlueLayout, SearchSpanFinalImageGlueErrorV1> {
    let layout = GlueLayout::new(&compile_identity, adopter)?;
    destination.fill(0);
    let bytes = destination
        .get_mut(..layout.object_bytes)
        .ok_or_else(|| glue_error("Search glue emission destination"))?;
    write_prefix(
        bytes
            .get_mut(..CONTENT_OFFSET)
            .ok_or_else(|| glue_error("Search glue prefix range"))?,
        layout,
    )?;
    copy_region(
        bytes,
        CONTENT_OFFSET,
        &encode_glue_code(row_selector)?,
        "Search glue code",
    )?;
    copy_region(
        bytes,
        EXPECTATION_FILE_OFFSET,
        expectation,
        "Search glue expectation",
    )?;
    write_relocations(bytes, layout, &compile_identity, adopter)?;
    write_symbols_and_strings(bytes, layout, &compile_identity, adopter)?;
    Ok(layout)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GlueLayout {
    relocation_offset: usize,
    symbol_offset: usize,
    string_offset: usize,
    string_bytes: usize,
    object_bytes: usize,
}

impl GlueLayout {
    fn new(
        compile_identity: &[u8; 32],
        adopter: SearchSpanFinalImageAdopterV1,
    ) -> Result<Self, SearchSpanFinalImageGlueErrorV1> {
        let relocation_offset = CONTENT_OFFSET
            .checked_add(SEGMENT_BYTES)
            .ok_or_else(|| overflow("Search glue relocation offset"))?;
        let relocation_bytes = RELOCATION_BYTES
            .checked_mul(SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1)
            .ok_or_else(|| overflow("Search glue relocation bytes"))?;
        let symbol_offset = relocation_offset
            .checked_add(relocation_bytes)
            .ok_or_else(|| overflow("Search glue symbol offset"))?;
        let symbol_bytes = NLIST_64_BYTES
            .checked_mul(SYMBOLS)
            .ok_or_else(|| overflow("Search glue symbol bytes"))?;
        let string_offset = symbol_offset
            .checked_add(symbol_bytes)
            .ok_or_else(|| overflow("Search glue string offset"))?;
        let string_bytes = align_up(
            symbol_string_bytes(compile_identity, adopter)?,
            4,
            "Search glue string bytes",
        )?;
        let object_bytes = string_offset
            .checked_add(string_bytes)
            .ok_or_else(|| overflow("Search glue object bytes"))?;
        if object_bytes > CANONICAL_REEMIT_BUFFER_BYTES {
            return Err(glue_error("Search glue canonical re-emission bound"));
        }
        Ok(Self {
            relocation_offset,
            symbol_offset,
            string_offset,
            string_bytes,
            object_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SymbolRole {
    Glue,
    Expectation,
    Entry,
    Payload,
    Metadata,
    RuntimeAdopt,
}

#[derive(Clone, Copy)]
struct SymbolName {
    bytes: [u8; SYMBOL_NAME_STORAGE_BYTES],
    len: usize,
}

impl SymbolName {
    fn suffixed(
        prefix: &str,
        identity: &[u8; 32],
    ) -> Result<Self, SearchSpanFinalImageGlueErrorV1> {
        let len = prefix
            .len()
            .checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V1)
            .ok_or_else(|| overflow("Search glue symbol name length"))?;
        if len > SYMBOL_NAME_STORAGE_BYTES {
            return Err(glue_error("Search glue symbol name storage"));
        }
        let mut bytes = [0_u8; SYMBOL_NAME_STORAGE_BYTES];
        bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
        let mut cursor = prefix.len();
        for byte in identity {
            for nibble in [byte >> 4, byte & 0x0f] {
                let slot = bytes
                    .get_mut(cursor)
                    .ok_or_else(|| glue_error("Search glue symbol hex range"))?;
                *slot = lower_hex(nibble);
                cursor = cursor
                    .checked_add(1)
                    .ok_or_else(|| overflow("Search glue symbol hex offset"))?;
            }
        }
        if cursor != len {
            return Err(glue_error("Search glue symbol name length"));
        }
        Ok(Self { bytes, len })
    }

    fn fixed(name: &str) -> Result<Self, SearchSpanFinalImageGlueErrorV1> {
        if name.len() > SYMBOL_NAME_STORAGE_BYTES {
            return Err(glue_error("fixed Search glue symbol name storage"));
        }
        let mut bytes = [0_u8; SYMBOL_NAME_STORAGE_BYTES];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(Self {
            bytes,
            len: name.len(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Clone, Copy)]
struct SymbolSpec {
    role: SymbolRole,
    name: SymbolName,
    defined: bool,
    section: u8,
    value: u64,
}

fn symbol_specs(
    compile_identity: &[u8; 32],
    adopter: SearchSpanFinalImageAdopterV1,
) -> Result<[SymbolSpec; SYMBOLS], SearchSpanFinalImageGlueErrorV1> {
    let mut specs = [
        SymbolSpec {
            role: SymbolRole::Glue,
            name: SymbolName::suffixed(GLUE_SYMBOL_PREFIX_V1, compile_identity)?,
            defined: true,
            section: 1,
            value: 0,
        },
        SymbolSpec {
            role: SymbolRole::Expectation,
            name: SymbolName::suffixed(EXPECTATION_SYMBOL_PREFIX_V1, compile_identity)?,
            defined: true,
            section: 2,
            value: usize_u64(EXPECTATION_ADDRESS, "Search expectation symbol value")?,
        },
        SymbolSpec {
            role: SymbolRole::Entry,
            name: SymbolName::suffixed(SEARCH_ENTRY_SYMBOL_PREFIX_V1, compile_identity)?,
            defined: false,
            section: 0,
            value: 0,
        },
        SymbolSpec {
            role: SymbolRole::Payload,
            name: SymbolName::suffixed(PAYLOAD_SYMBOL_PREFIX_V1, compile_identity)?,
            defined: false,
            section: 0,
            value: 0,
        },
        SymbolSpec {
            role: SymbolRole::Metadata,
            name: SymbolName::suffixed(METADATA_SYMBOL_PREFIX_V1, compile_identity)?,
            defined: false,
            section: 0,
            value: 0,
        },
        SymbolSpec {
            role: SymbolRole::RuntimeAdopt,
            name: SymbolName::fixed(adopter.symbol())?,
            defined: false,
            section: 0,
            value: 0,
        },
    ];
    specs.sort_unstable_by(|left, right| {
        right
            .defined
            .cmp(&left.defined)
            .then_with(|| left.name.as_bytes().cmp(right.name.as_bytes()))
    });
    Ok(specs)
}

fn symbol_index(
    specs: &[SymbolSpec; SYMBOLS],
    role: SymbolRole,
) -> Result<u32, SearchSpanFinalImageGlueErrorV1> {
    specs
        .iter()
        .position(|spec| spec.role == role)
        .and_then(|index| u32::try_from(index).ok())
        .ok_or_else(|| glue_error("Search glue relocation symbol index"))
}

#[allow(
    clippy::too_many_lines,
    reason = "one bounded writer emits the complete fixed Mach-O header and four load commands"
)]
fn write_prefix(
    prefix: &mut [u8],
    layout: GlueLayout,
) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
    if prefix.len() != CONTENT_OFFSET {
        return Err(glue_error("Search glue prefix destination"));
    }
    prefix.fill(0);
    let mut writer = Writer::new(prefix);
    writer.u32(MH_MAGIC_64)?;
    writer.u32(CPU_TYPE_ARM64)?;
    writer.u32(CPU_SUBTYPE_ARM64_ALL)?;
    writer.u32(MH_OBJECT)?;
    writer.u32(LOAD_COMMAND_COUNT)?;
    writer.u32(u32_from_usize(
        LOAD_COMMAND_BYTES,
        "Search glue load command bytes",
    )?)?;
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(LC_SEGMENT_64)?;
    writer.u32(u32_from_usize(
        SEGMENT_WITH_SECTIONS_BYTES,
        "Search glue segment command bytes",
    )?)?;
    writer.fixed_name("")?;
    writer.u64(0)?;
    writer.u64(usize_u64(SEGMENT_BYTES, "Search glue segment bytes")?)?;
    writer.u64(usize_u64(CONTENT_OFFSET, "Search glue content offset")?)?;
    writer.u64(usize_u64(SEGMENT_BYTES, "Search glue segment file bytes")?)?;
    writer.u32(VM_PROT_RWX)?;
    writer.u32(VM_PROT_RWX)?;
    writer.u32(SECTIONS)?;
    writer.u32(0)?;
    writer.section(
        "__text",
        "__TEXT",
        0,
        usize_u64(
            SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1,
            "Search glue code bytes",
        )?,
        u32_from_usize(CONTENT_OFFSET, "Search glue code file offset")?,
        2,
        u32_from_usize(layout.relocation_offset, "Search glue relocation offset")?,
        u32::try_from(SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1)
            .expect("fixed Search relocation count"),
        TEXT_SECTION_FLAGS,
    )?;
    writer.section(
        "__fre_expect",
        "__FRE_CONST",
        usize_u64(EXPECTATION_ADDRESS, "Search glue expectation address")?,
        usize_u64(
            STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1,
            "Search glue expectation bytes",
        )?,
        u32_from_usize(
            EXPECTATION_FILE_OFFSET,
            "Search glue expectation file offset",
        )?,
        3,
        0,
        0,
        EXPECTATION_SECTION_FLAGS,
    )?;

    writer.u32(LC_BUILD_VERSION)?;
    writer.u32(u32_from_usize(
        BUILD_VERSION_COMMAND_BYTES,
        "Search glue build-version command bytes",
    )?)?;
    writer.u32(PLATFORM_MACOS_LOAD_COMMAND)?;
    writer.u32(MIN_MACOS_VERSION_V1)?;
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(LC_SYMTAB)?;
    writer.u32(u32_from_usize(
        SYMTAB_COMMAND_BYTES,
        "Search glue symtab command bytes",
    )?)?;
    writer.u32(u32_from_usize(
        layout.symbol_offset,
        "Search glue symbol offset",
    )?)?;
    writer.u32(u32::try_from(SYMBOLS).expect("fixed Search symbol count"))?;
    writer.u32(u32_from_usize(
        layout.string_offset,
        "Search glue string offset",
    )?)?;
    writer.u32(u32_from_usize(
        layout.string_bytes,
        "Search glue string bytes",
    )?)?;

    writer.u32(LC_DYSYMTAB)?;
    writer.u32(u32_from_usize(
        DYSYMTAB_COMMAND_BYTES,
        "Search glue dysymtab command bytes",
    )?)?;
    for value in [0, 0, 0, DEFINED_SYMBOLS, DEFINED_SYMBOLS, UNDEFINED_SYMBOLS] {
        writer.u32(value)?;
    }
    for _ in 0..12 {
        writer.u32(0)?;
    }
    if writer.position() != MACH_HEADER_BYTES + LOAD_COMMAND_BYTES {
        return Err(glue_error("Search glue load command length"));
    }
    Ok(())
}

fn write_relocations(
    bytes: &mut [u8],
    layout: GlueLayout,
    compile_identity: &[u8; 32],
    adopter: SearchSpanFinalImageAdopterV1,
) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
    let specs = symbol_specs(compile_identity, adopter)?;
    let relocation_bytes = RELOCATION_BYTES
        .checked_mul(SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1)
        .ok_or_else(|| overflow("Search glue relocation bytes"))?;
    let end = layout
        .relocation_offset
        .checked_add(relocation_bytes)
        .ok_or_else(|| overflow("Search glue relocation end"))?;
    let destination = bytes
        .get_mut(layout.relocation_offset..end)
        .ok_or_else(|| glue_error("Search glue relocation destination"))?;
    let mut writer = Writer::new(destination);
    for relocation in canonical_relocations() {
        writer.i32(relocation.address)?;
        writer.u32(relocation.word(symbol_index(&specs, relocation.role)?)?)?;
    }
    if writer.position() != relocation_bytes {
        return Err(glue_error("Search glue relocation length"));
    }
    Ok(())
}

const fn canonical_relocations() -> [Relocation; SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1] {
    [
        Relocation::branch(36, SymbolRole::RuntimeAdopt),
        Relocation::page_off(32, SymbolRole::Metadata),
        Relocation::page(28, SymbolRole::Metadata),
        Relocation::page_off(24, SymbolRole::Payload),
        Relocation::page(20, SymbolRole::Payload),
        Relocation::page_off(16, SymbolRole::Entry),
        Relocation::page(12, SymbolRole::Entry),
        Relocation::page_off(8, SymbolRole::Expectation),
        Relocation::page(4, SymbolRole::Expectation),
    ]
}

#[derive(Clone, Copy)]
struct Relocation {
    address: i32,
    role: SymbolRole,
    kind: u8,
    pc_relative: bool,
}

impl Relocation {
    const fn branch(address: i32, role: SymbolRole) -> Self {
        Self {
            address,
            role,
            kind: ARM64_RELOC_BRANCH26,
            pc_relative: true,
        }
    }

    const fn page(address: i32, role: SymbolRole) -> Self {
        Self {
            address,
            role,
            kind: ARM64_RELOC_PAGE21,
            pc_relative: true,
        }
    }

    const fn page_off(address: i32, role: SymbolRole) -> Self {
        Self {
            address,
            role,
            kind: ARM64_RELOC_PAGEOFF12,
            pc_relative: false,
        }
    }

    #[allow(
        clippy::arithmetic_side_effects,
        reason = "fixed Mach-O relocation bitfields are checked before packing"
    )]
    fn word(self, symbol_index: u32) -> Result<u32, SearchSpanFinalImageGlueErrorV1> {
        if symbol_index >= (1 << 24) || self.kind >= 16 {
            return Err(glue_error("Search glue relocation bitfield"));
        }
        Ok(symbol_index
            | (u32::from(self.pc_relative) << 24)
            | (2 << 25)
            | (1 << 27)
            | (u32::from(self.kind) << 28))
    }
}

fn write_symbols_and_strings(
    bytes: &mut [u8],
    layout: GlueLayout,
    compile_identity: &[u8; 32],
    adopter: SearchSpanFinalImageAdopterV1,
) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
    let specs = symbol_specs(compile_identity, adopter)?;
    let symbol_bytes = NLIST_64_BYTES
        .checked_mul(SYMBOLS)
        .ok_or_else(|| overflow("Search glue symbol bytes"))?;
    let symbol_end = layout
        .symbol_offset
        .checked_add(symbol_bytes)
        .ok_or_else(|| overflow("Search glue symbol end"))?;
    let mut writer = Writer::new(
        bytes
            .get_mut(layout.symbol_offset..symbol_end)
            .ok_or_else(|| glue_error("Search glue symbol destination"))?,
    );
    let mut string_index = 4_usize;
    for spec in specs {
        writer.u32(u32_from_usize(string_index, "Search glue string index")?)?;
        writer.u8(if spec.defined {
            DEFINED_PRIVATE_EXTERNAL_N_TYPE
        } else {
            UNDEFINED_EXTERNAL_N_TYPE
        })?;
        writer.u8(spec.section)?;
        writer.u16(0)?;
        writer.u64(spec.value)?;
        string_index = string_index
            .checked_add(1)
            .and_then(|value| value.checked_add(spec.name.as_bytes().len()))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| overflow("Search glue string index"))?;
    }
    if writer.position() != symbol_bytes {
        return Err(glue_error("Search glue symbol length"));
    }

    let string_end = layout
        .string_offset
        .checked_add(layout.string_bytes)
        .ok_or_else(|| overflow("Search glue string end"))?;
    let mut writer = Writer::new(
        bytes
            .get_mut(layout.string_offset..string_end)
            .ok_or_else(|| glue_error("Search glue string destination"))?,
    );
    writer.u32(0)?;
    for spec in specs {
        writer.u8(b'_')?;
        writer.bytes(spec.name.as_bytes())?;
        writer.u8(0)?;
    }
    Ok(())
}

fn symbol_string_bytes(
    compile_identity: &[u8; 32],
    adopter: SearchSpanFinalImageAdopterV1,
) -> Result<usize, SearchSpanFinalImageGlueErrorV1> {
    symbol_specs(compile_identity, adopter)?
        .into_iter()
        .try_fold(4_usize, |total, spec| {
            total
                .checked_add(1)
                .and_then(|value| value.checked_add(spec.name.as_bytes().len()))
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| overflow("Search glue string bytes"))
        })
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "fixed A64 instruction fields use one u16 selector and audited registers"
)]
fn encode_glue_code(
    row_selector: u16,
) -> Result<[u8; SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1], SearchSpanFinalImageGlueErrorV1> {
    let mut code = [0_u8; SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1];
    let mut writer = Writer::new(&mut code);
    writer.u32(0x5280_0001 | (u32::from(row_selector) << 5))?;
    for register in [2_u32, 3, 4, 5] {
        writer.u32(0x9000_0000 | register)?;
        writer.u32(0x9100_0000 | (register << 5) | register)?;
    }
    writer.u32(0x1400_0000)?;
    if writer.position() != SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1 {
        return Err(glue_error("Search glue code length"));
    }
    Ok(code)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "whole-object canonical comparison validates the decoded MOVZ field"
)]
fn decode_row_selector(
    code: &[u8; SEARCH_SPAN_FINAL_IMAGE_GLUE_CODE_BYTES_V1],
) -> Result<u16, SearchSpanFinalImageGlueErrorV1> {
    let instruction =
        u32::from_le_bytes(code[..4].try_into().expect("fixed Search glue instruction"));
    let selector = u16::try_from((instruction >> 5) & 0xffff)
        .map_err(|_| glue_error("Search glue row selector"))?;
    if encode_glue_code(selector)? != *code {
        return Err(glue_error("Search glue instruction sequence"));
    }
    Ok(selector)
}

fn copy_region(
    destination: &mut [u8],
    offset: usize,
    source: &[u8],
    at: &'static str,
) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
    let end = offset
        .checked_add(source.len())
        .ok_or_else(|| overflow("Search glue copy region"))?;
    destination
        .get_mut(offset..end)
        .ok_or_else(|| glue_error(at))?
        .copy_from_slice(source);
    Ok(())
}

struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or_else(|| overflow("Search glue writer offset"))?;
        self.bytes
            .get_mut(self.position..end)
            .ok_or_else(|| glue_error("Search glue writer destination"))?
            .copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
        self.bytes(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
        self.bytes(&value.to_le_bytes())
    }

    fn i32(&mut self, value: i32) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
        self.bytes(&value.to_le_bytes())
    }

    fn fixed_name(&mut self, name: &str) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
        if name.len() > 16 {
            return Err(glue_error("Search glue Mach-O fixed name"));
        }
        self.bytes(name.as_bytes())?;
        self.bytes(&[0; 16][name.len()..])
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the arguments exactly mirror one Mach-O section_64 record"
    )]
    fn section(
        &mut self,
        section_name: &str,
        segment_name: &str,
        address: u64,
        size: u64,
        offset: u32,
        alignment: u32,
        relocation_offset: u32,
        relocations: u32,
        flags: u32,
    ) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
        self.fixed_name(section_name)?;
        self.fixed_name(segment_name)?;
        self.u64(address)?;
        self.u64(size)?;
        self.u32(offset)?;
        self.u32(alignment)?;
        self.u32(relocation_offset)?;
        self.u32(relocations)?;
        self.u32(flags)?;
        self.u32(0)?;
        self.u32(0)?;
        self.u32(0)
    }

    const fn position(&self) -> usize {
        self.position
    }
}

fn fixed_identity(bytes: &[u8], offset: usize) -> &[u8; 32] {
    let end = offset
        .checked_add(32)
        .expect("fixed Search final-image receipt identity end");
    bytes[offset..end]
        .try_into()
        .expect("fixed Search final-image receipt identity range")
}

fn align_up(
    value: usize,
    alignment: usize,
    at: &'static str,
) -> Result<usize, SearchSpanFinalImageGlueErrorV1> {
    let mask = alignment.checked_sub(1).ok_or_else(|| overflow(at))?;
    if alignment == 0 || alignment & mask != 0 {
        return Err(glue_error(at));
    }
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or_else(|| overflow(at))
}

fn enforce_limit(limit: u64, required: u64) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
    if required <= limit {
        Ok(())
    } else {
        Err(SearchSpanFinalImageGlueErrorV1::ResourceLimit {
            resource: "Search final-image glue object bytes",
            limit,
            required,
        })
    }
}

fn enforce_retained_limit(
    limit: u64,
    required: u64,
) -> Result<(), SearchSpanFinalImageGlueErrorV1> {
    if required <= limit {
        Ok(())
    } else {
        Err(SearchSpanFinalImageGlueErrorV1::ResourceLimit {
            resource: "Search final-image glue retained bytes",
            limit,
            required,
        })
    }
}

fn u32_from_usize(value: usize, at: &'static str) -> Result<u32, SearchSpanFinalImageGlueErrorV1> {
    u32::try_from(value).map_err(|_| overflow(at))
}

fn usize_u64(value: usize, at: &'static str) -> Result<u64, SearchSpanFinalImageGlueErrorV1> {
    u64::try_from(value).map_err(|_| overflow(at))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
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
        _ => b'f',
    }
}

const fn glue_error(at: &'static str) -> SearchSpanFinalImageGlueErrorV1 {
    SearchSpanFinalImageGlueErrorV1::InvalidGlue { at }
}

const fn source_error(at: &'static str) -> SearchSpanFinalImageGlueErrorV1 {
    SearchSpanFinalImageGlueErrorV1::SourceBinding { at }
}

const fn overflow(at: &'static str) -> SearchSpanFinalImageGlueErrorV1 {
    SearchSpanFinalImageGlueErrorV1::ArithmeticOverflow { at }
}

#[cfg(test)]
mod tests {
    use fre::RustProfile;
    use fre_kernel_ir::Span;

    use super::*;
    use crate::{
        MacosAarch64ExactSearchManifestV1, SearchCompiledObjectV1,
        build_static_search_span_expectation_v1, plan_and_compile_macos_aarch64_exact_search_v1,
    };

    fn compile_span(
        literal: &[u8],
    ) -> (SearchCompiledObjectV1<Span>, StaticSearchSpanExpectationV1) {
        let compiled = plan_and_compile_macos_aarch64_exact_search_v1(
            MacosAarch64ExactSearchManifestV1::<Span>::default(),
            literal.to_vec(),
            RustProfile::default(),
        )
        .expect("inert Search Span implementation object");
        let expectation =
            build_static_search_span_expectation_v1(&compiled).expect("static Search expectation");
        (compiled, expectation)
    }

    fn contains(bytes: &[u8], needle: &[u8]) -> bool {
        bytes
            .windows(needle.len())
            .any(|candidate| candidate == needle)
    }

    fn read_u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(
            bytes
                .get(offset..)
                .and_then(|tail| tail.get(..4))
                .and_then(|slice| slice.try_into().ok())
                .expect("four-byte test field"),
        )
    }

    fn read_i32_at(bytes: &[u8], offset: usize) -> i32 {
        i32::from_le_bytes(
            bytes
                .get(offset..)
                .and_then(|tail| tail.get(..4))
                .and_then(|slice| slice.try_into().ok())
                .expect("four-byte signed test field"),
        )
    }

    fn read_u64_at(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(
            bytes
                .get(offset..)
                .and_then(|tail| tail.get(..8))
                .and_then(|slice| slice.try_into().ok())
                .expect("eight-byte test field"),
        )
    }

    fn reseal_receipt(
        mut bytes: [u8; UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1],
    ) -> UnsignedSearchSpanFinalImageReceiptV1 {
        let content_identity = digest_with_domain(
            FINAL_IMAGE_RECEIPT_DOMAIN_V1,
            &bytes[..FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET],
        );
        bytes[FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET..].copy_from_slice(&content_identity);
        UnsignedSearchSpanFinalImageReceiptV1 { bytes }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one source-bound artifact test checks every published identity and instruction"
    )]
    fn deterministic_glue_binds_every_source_identity_and_stays_inert() {
        let (compiled, expectation) = compile_span(b"needle");
        let first = publish_search_span_final_image_glue_v1(
            &compiled,
            &expectation,
            37,
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .expect("production Search glue");
        let second = publish_search_span_final_image_glue_v1(
            &compiled,
            &expectation,
            37,
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .expect("repeated production Search glue");
        assert_eq!(first, second);
        assert_eq!(
            first.runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );
        assert_eq!(
            first.receipt().runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );
        assert_eq!(first.object().row_selector(), 37);
        assert_eq!(
            first.object().adopter(),
            SearchSpanFinalImageAdopterV1::Production
        );
        assert_eq!(
            first.object().compile_identity(),
            compiled.receipt().compile_identity().as_bytes()
        );
        assert_eq!(
            first.object().implementation_object_identity(),
            compiled.receipt().object_identity().as_bytes()
        );
        assert_eq!(
            first.object().compiler_receipt_identity(),
            compiled.receipt().receipt_identity().as_bytes()
        );
        assert_eq!(
            first.object().expectation_identity(),
            expectation.expectation_identity().as_bytes()
        );
        assert_eq!(
            first.receipt().compile_identity(),
            compiled.receipt().compile_identity().as_bytes()
        );
        assert_eq!(
            first.receipt().implementation_object_identity(),
            compiled.receipt().object_identity().as_bytes()
        );
        assert_eq!(
            first.receipt().compiler_receipt_identity(),
            compiled.receipt().receipt_identity().as_bytes()
        );
        assert_eq!(
            first.receipt().expectation_identity(),
            expectation.expectation_identity().as_bytes()
        );
        assert_eq!(
            first.receipt().glue_object_identity(),
            first.object().glue_object_identity()
        );
        assert_eq!(
            first.receipt().glue_code_identity(),
            first.object().glue_code_identity()
        );
        assert_eq!(
            first.receipt().object_bytes(),
            u64::try_from(first.object().as_bytes().len()).expect("small Search glue object")
        );

        let inspection = first
            .receipt()
            .validate_candidate(
                &compiled,
                &expectation,
                first.object().as_bytes(),
                SearchSpanFinalImageGlueLimitsV1::default(),
            )
            .expect("strict source-bound Search glue inspection");
        assert_eq!(
            inspection.allocations(),
            SEARCH_SPAN_FINAL_IMAGE_GLUE_INSPECTION_ALLOCATIONS_V1
        );
        assert_eq!(inspection.expectation(), expectation.as_bytes());
        assert_eq!(
            inspection.glue_object_identity(),
            first.object().glue_object_identity()
        );
        assert_eq!(
            inspection.glue_code_identity(),
            first.object().glue_code_identity()
        );
        assert!(first.object().retained_bytes() >= first.object().as_bytes().len());
        assert_eq!(first.object().allocations(), 1);

        let code = first
            .object()
            .as_bytes()
            .get(CONTENT_OFFSET..EXPECTATION_FILE_OFFSET)
            .expect("fixed Search glue code");
        let words: Vec<u32> = code
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("A64 instruction")))
            .collect();
        assert_eq!(
            words,
            [
                0x5280_04a1,
                0x9000_0002,
                0x9100_0042,
                0x9000_0003,
                0x9100_0063,
                0x9000_0004,
                0x9100_0084,
                0x9000_0005,
                0x9100_00a5,
                0x1400_0000,
            ]
        );
    }

    #[test]
    fn production_and_private_adopters_are_canonical_and_disjoint() {
        let (compiled, expectation) = compile_span(b"needle");
        let production = publish_search_span_final_image_glue_v1(
            &compiled,
            &expectation,
            11,
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .expect("production Search glue");
        let qualification = publish_search_span_qualification_final_image_glue_v1(
            &compiled,
            &expectation,
            11,
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .expect("private qualification Search glue");
        assert_ne!(
            production.object().as_bytes(),
            qualification.object().as_bytes()
        );
        assert_ne!(
            production.object().glue_object_identity(),
            qualification.object().glue_object_identity()
        );
        assert_eq!(
            production.object().glue_code_identity(),
            qualification.object().glue_code_identity()
        );
        assert_eq!(
            production.object().adopter(),
            SearchSpanFinalImageAdopterV1::Production
        );
        assert_eq!(
            qualification.object().adopter(),
            SearchSpanFinalImageAdopterV1::QualificationPrivate
        );
        assert_eq!(
            production.receipt().adopter(),
            Some(SearchSpanFinalImageAdopterV1::Production)
        );
        assert_eq!(
            qualification.receipt().adopter(),
            Some(SearchSpanFinalImageAdopterV1::QualificationPrivate)
        );
        assert!(contains(
            production.object().as_bytes(),
            RUNTIME_ADOPT_SYMBOL_V1.as_bytes()
        ));
        assert!(!contains(
            production.object().as_bytes(),
            QUALIFICATION_RUNTIME_ADOPT_SYMBOL_V1.as_bytes()
        ));
        assert!(contains(
            qualification.object().as_bytes(),
            QUALIFICATION_RUNTIME_ADOPT_SYMBOL_V1.as_bytes()
        ));
        assert!(!contains(
            qualification.object().as_bytes(),
            format!("_{RUNTIME_ADOPT_SYMBOL_V1}\0").as_bytes()
        ));
        let inspected = inspect_search_span_final_image_glue_v1(
            qualification.object().as_bytes(),
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .expect("canonical qualification inspection");
        assert_eq!(
            inspected.adopter(),
            SearchSpanFinalImageAdopterV1::QualificationPrivate
        );
    }

    #[test]
    fn every_glue_and_receipt_byte_is_bound() {
        let (compiled, expectation) = compile_span(b"needle");
        let published = publish_search_span_final_image_glue_v1(
            &compiled,
            &expectation,
            5,
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .expect("production Search glue");
        let mut candidate = published.object().as_bytes().to_vec();
        for offset in 0..candidate.len() {
            candidate[offset] ^= 1;
            assert!(
                published
                    .receipt()
                    .validate_candidate(
                        &compiled,
                        &expectation,
                        &candidate,
                        SearchSpanFinalImageGlueLimitsV1::default(),
                    )
                    .is_err(),
                "mutated Search glue byte {offset} was accepted"
            );
            candidate[offset] ^= 1;
        }

        for offset in 0..UNSIGNED_SEARCH_SPAN_FINAL_IMAGE_RECEIPT_BYTES_V1 {
            let mut receipt = published.receipt().bytes;
            receipt[offset] ^= 1;
            let changed = UnsignedSearchSpanFinalImageReceiptV1 { bytes: receipt };
            assert!(
                !changed.authenticates_itself()
                    || changed
                        .validate_candidate(
                            &compiled,
                            &expectation,
                            published.object().as_bytes(),
                            SearchSpanFinalImageGlueLimitsV1::default(),
                        )
                        .is_err(),
                "mutated Search final-image receipt byte {offset} was accepted"
            );
        }
    }

    #[test]
    fn self_rehashed_unsigned_receipt_splices_still_fail_source_bound_validation() {
        let (compiled, expectation) = compile_span(b"needle");
        let published = publish_search_span_final_image_glue_v1(
            &compiled,
            &expectation,
            5,
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .expect("production Search glue");

        for offset in [
            FINAL_IMAGE_RECEIPT_ADOPTER_OFFSET,
            FINAL_IMAGE_RECEIPT_ROW_OFFSET,
            FINAL_IMAGE_RECEIPT_OBJECT_BYTES_OFFSET,
            FINAL_IMAGE_RECEIPT_COMPILE_IDENTITY_OFFSET,
            FINAL_IMAGE_RECEIPT_IMPLEMENTATION_OBJECT_IDENTITY_OFFSET,
            FINAL_IMAGE_RECEIPT_COMPILER_RECEIPT_IDENTITY_OFFSET,
            FINAL_IMAGE_RECEIPT_EXPECTATION_IDENTITY_OFFSET,
            FINAL_IMAGE_RECEIPT_GLUE_IDENTITY_OFFSET,
            FINAL_IMAGE_RECEIPT_CODE_IDENTITY_OFFSET,
        ] {
            let mut bytes = *published.receipt().canonical_bytes();
            bytes[offset] ^= 1;
            let forged = reseal_receipt(bytes);
            assert!(
                forged.authenticates_itself(),
                "self-rehashed semantic receipt field {offset} should remain merely self-consistent"
            );
            assert!(
                forged
                    .validate_candidate(
                        &compiled,
                        &expectation,
                        published.object().as_bytes(),
                        SearchSpanFinalImageGlueLimitsV1::default(),
                    )
                    .is_err(),
                "self-rehashed semantic receipt field {offset} escaped source binding"
            );
        }

        for offset in [0, 8, 12, 18, 20, 22] {
            let mut bytes = *published.receipt().canonical_bytes();
            bytes[offset] ^= 1;
            assert!(
                !reseal_receipt(bytes).authenticates_itself(),
                "self-rehashed structural receipt field {offset} was accepted"
            );
        }
    }

    #[test]
    fn every_truncation_and_extension_is_noncanonical() {
        let (compiled, expectation) = compile_span(b"needle");
        let published = publish_search_span_final_image_glue_v1(
            &compiled,
            &expectation,
            7,
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .expect("production Search glue");
        let bytes = published.object().as_bytes();
        for length in 0..bytes.len() {
            assert!(
                inspect_search_span_final_image_glue_v1(
                    &bytes[..length],
                    SearchSpanFinalImageGlueLimitsV1::default(),
                )
                .is_err(),
                "truncated Search glue length {length} was accepted"
            );
        }
        for extension in [0, 1, u8::MAX] {
            let mut extended = bytes.to_vec();
            extended.push(extension);
            assert!(
                inspect_search_span_final_image_glue_v1(
                    &extended,
                    SearchSpanFinalImageGlueLimitsV1::default(),
                )
                .is_err(),
                "extended Search glue byte {extension} was accepted"
            );
        }
        let oversized = vec![0_u8; CANONICAL_REEMIT_BUFFER_BYTES + 1];
        assert!(matches!(
            inspect_search_span_final_image_glue_v1(
                &oversized,
                SearchSpanFinalImageGlueLimitsV1::default(),
            ),
            Err(SearchSpanFinalImageGlueErrorV1::InvalidGlue {
                at: "Search glue canonical object bound",
            })
        ));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one canonical-object test checks the complete relocation and symbol tables"
    )]
    fn relocation_and_symbol_tables_are_exact_and_complete() {
        let (compiled, expectation) = compile_span(b"needle");
        let published = publish_search_span_final_image_glue_v1(
            &compiled,
            &expectation,
            19,
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .expect("production Search glue");
        let bytes = published.object().as_bytes();
        let identity = published.object().compile_identity();
        let adopter = SearchSpanFinalImageAdopterV1::Production;
        let layout = GlueLayout::new(identity, adopter).expect("fixed Search glue layout");
        assert_eq!(layout.object_bytes, bytes.len());
        assert_eq!(SEARCH_SPAN_FINAL_IMAGE_GLUE_RELOCATIONS_V1, 9);
        let specs = symbol_specs(identity, adopter).expect("fixed Search symbol specs");

        let expected_relocations = [
            (36, SymbolRole::RuntimeAdopt, ARM64_RELOC_BRANCH26, true),
            (32, SymbolRole::Metadata, ARM64_RELOC_PAGEOFF12, false),
            (28, SymbolRole::Metadata, ARM64_RELOC_PAGE21, true),
            (24, SymbolRole::Payload, ARM64_RELOC_PAGEOFF12, false),
            (20, SymbolRole::Payload, ARM64_RELOC_PAGE21, true),
            (16, SymbolRole::Entry, ARM64_RELOC_PAGEOFF12, false),
            (12, SymbolRole::Entry, ARM64_RELOC_PAGE21, true),
            (8, SymbolRole::Expectation, ARM64_RELOC_PAGEOFF12, false),
            (4, SymbolRole::Expectation, ARM64_RELOC_PAGE21, true),
        ];
        for (index, (relocation, expected)) in canonical_relocations()
            .into_iter()
            .zip(expected_relocations)
            .enumerate()
        {
            assert_eq!(
                (
                    relocation.address,
                    relocation.role,
                    relocation.kind,
                    relocation.pc_relative
                ),
                expected
            );
            let offset = layout.relocation_offset + (index * RELOCATION_BYTES);
            assert_eq!(read_i32_at(bytes, offset), relocation.address);
            assert_eq!(
                read_u32_at(bytes, offset + 4),
                relocation
                    .word(symbol_index(&specs, relocation.role).expect("symbol role"))
                    .expect("relocation word")
            );
        }

        for (index, spec) in specs.into_iter().enumerate() {
            let offset = layout.symbol_offset + (index * NLIST_64_BYTES);
            let string_index =
                usize::try_from(read_u32_at(bytes, offset)).expect("small string index");
            assert_eq!(
                bytes[offset + 4],
                if spec.defined {
                    DEFINED_PRIVATE_EXTERNAL_N_TYPE
                } else {
                    UNDEFINED_EXTERNAL_N_TYPE
                }
            );
            assert_eq!(bytes[offset + 5], spec.section);
            assert_eq!(&bytes[offset + 6..offset + 8], &[0; 2]);
            assert_eq!(read_u64_at(bytes, offset + 8), spec.value);

            let start = layout.string_offset + string_index;
            let expected_end = start + 1 + spec.name.as_bytes().len();
            assert_eq!(bytes[start], b'_');
            assert_eq!(
                &bytes[start + 1..expected_end],
                spec.name.as_bytes(),
                "symbol {index}"
            );
            assert_eq!(bytes[expected_end], 0);
        }

        for role in [
            SymbolRole::Glue,
            SymbolRole::Expectation,
            SymbolRole::Entry,
            SymbolRole::Payload,
            SymbolRole::Metadata,
            SymbolRole::RuntimeAdopt,
        ] {
            assert!(symbol_index(&specs, role).is_ok());
        }
        assert!(contains(bytes, GLUE_SYMBOL_PREFIX_V1.as_bytes()));
        assert!(contains(bytes, EXPECTATION_SYMBOL_PREFIX_V1.as_bytes()));
        assert!(contains(bytes, SEARCH_ENTRY_SYMBOL_PREFIX_V1.as_bytes()));
        assert!(contains(bytes, PAYLOAD_SYMBOL_PREFIX_V1.as_bytes()));
        assert!(contains(bytes, METADATA_SYMBOL_PREFIX_V1.as_bytes()));

        let expectation_section = MACH_HEADER_BYTES + SEGMENT_COMMAND_BYTES + SECTION_COMMAND_BYTES;
        assert_eq!(
            &bytes[expectation_section..expectation_section + 12],
            b"__fre_expect"
        );
        assert_eq!(
            &bytes[expectation_section + 16..expectation_section + 27],
            b"__FRE_CONST"
        );
        assert_eq!(
            read_u64_at(bytes, expectation_section + 32),
            u64::try_from(EXPECTATION_ADDRESS).expect("small expectation address")
        );
        assert_eq!(
            read_u64_at(bytes, expectation_section + 40),
            u64::try_from(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1)
                .expect("small expectation width")
        );
        assert_eq!(
            read_u32_at(bytes, expectation_section + 48),
            u32::try_from(EXPECTATION_FILE_OFFSET).expect("small expectation offset")
        );
        assert_eq!(read_u32_at(bytes, expectation_section + 52), 3);
        assert_eq!(read_u32_at(bytes, expectation_section + 56), 0);
        assert_eq!(read_u32_at(bytes, expectation_section + 60), 0);
        assert_eq!(read_u32_at(bytes, expectation_section + 64), 0);
        assert_eq!(
            &bytes[EXPECTATION_FILE_OFFSET
                ..EXPECTATION_FILE_OFFSET + STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1],
            expectation.as_bytes()
        );
    }

    #[test]
    fn selectors_and_actual_retained_capacity_are_bounded_before_use() {
        let (compiled, expectation) = compile_span(b"x");
        for selector in [0, u16::MAX] {
            let published = publish_search_span_final_image_glue_v1(
                &compiled,
                &expectation,
                selector,
                SearchSpanFinalImageGlueLimitsV1::default(),
            )
            .expect("selector boundary Search glue");
            assert_eq!(published.object().row_selector(), selector);
            assert_eq!(published.receipt().row_selector(), selector);
            assert_eq!(
                decode_row_selector(
                    published.object().as_bytes()[CONTENT_OFFSET..EXPECTATION_FILE_OFFSET]
                        .try_into()
                        .expect("fixed Search glue code")
                )
                .expect("selector immediate"),
                selector
            );
        }

        let baseline = publish_search_span_final_image_glue_v1(
            &compiled,
            &expectation,
            1,
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .expect("baseline Search glue");
        let object_bytes =
            u64::try_from(baseline.object().as_bytes().len()).expect("small Search object");
        let retained_bytes =
            u64::try_from(baseline.object().retained_bytes()).expect("small Search retention");
        assert!(retained_bytes >= object_bytes);
        let exact_retained = publish_search_span_final_image_glue_v1(
            &compiled,
            &expectation,
            1,
            SearchSpanFinalImageGlueLimitsV1 {
                max_object_bytes: retained_bytes,
            },
        )
        .expect("actual retained-capacity limit");
        assert!(
            u64::try_from(exact_retained.object().retained_bytes()).expect("small retention")
                <= retained_bytes
        );

        let one_below_object = object_bytes.checked_sub(1).expect("nonempty Search glue");
        assert!(matches!(
            publish_search_span_final_image_glue_v1(
                &compiled,
                &expectation,
                1,
                SearchSpanFinalImageGlueLimitsV1 {
                    max_object_bytes: one_below_object,
                },
            ),
            Err(SearchSpanFinalImageGlueErrorV1::ResourceLimit {
                limit,
                required,
                ..
            }) if limit == one_below_object && required == object_bytes
        ));
        assert!(matches!(
            inspect_search_span_final_image_glue_v1(
                baseline.object().as_bytes(),
                SearchSpanFinalImageGlueLimitsV1 {
                    max_object_bytes: one_below_object,
                },
            ),
            Err(SearchSpanFinalImageGlueErrorV1::ResourceLimit {
                limit,
                required,
                ..
            }) if limit == one_below_object && required == object_bytes
        ));

        let one_below_retained = retained_bytes
            .checked_sub(1)
            .expect("nonempty Search glue retention");
        assert_eq!(
            enforce_retained_limit(retained_bytes, retained_bytes),
            Ok(())
        );
        assert!(matches!(
            enforce_retained_limit(one_below_retained, retained_bytes),
            Err(SearchSpanFinalImageGlueErrorV1::ResourceLimit {
                limit,
                required,
                ..
            }) if limit == one_below_retained
                && required == retained_bytes
        ));
    }

    #[test]
    fn source_splices_rows_and_unsigned_receipts_never_manufacture_authority() {
        let (compiled_a, expectation_a) = compile_span(b"needle");
        let (compiled_b, expectation_b) = compile_span(b"different");
        assert!(matches!(
            publish_search_span_final_image_glue_v1(
                &compiled_a,
                &expectation_b,
                1,
                SearchSpanFinalImageGlueLimitsV1::default(),
            ),
            Err(SearchSpanFinalImageGlueErrorV1::SourceBinding { .. })
        ));
        assert!(matches!(
            publish_search_span_final_image_glue_v1(
                &compiled_b,
                &expectation_a,
                1,
                SearchSpanFinalImageGlueLimitsV1::default(),
            ),
            Err(SearchSpanFinalImageGlueErrorV1::SourceBinding { .. })
        ));

        let row_one = publish_search_span_final_image_glue_v1(
            &compiled_a,
            &expectation_a,
            1,
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .expect("row-one Search glue");
        let row_two = publish_search_span_final_image_glue_v1(
            &compiled_a,
            &expectation_a,
            2,
            SearchSpanFinalImageGlueLimitsV1::default(),
        )
        .expect("row-two Search glue");
        assert_ne!(row_one.object().as_bytes(), row_two.object().as_bytes());
        assert_ne!(
            row_one.object().glue_code_identity(),
            row_two.object().glue_code_identity()
        );
        assert_ne!(
            row_one.receipt().content_identity(),
            row_two.receipt().content_identity()
        );
        assert!(
            row_one
                .receipt()
                .validate_candidate(
                    &compiled_a,
                    &expectation_a,
                    row_two.object().as_bytes(),
                    SearchSpanFinalImageGlueLimitsV1::default(),
                )
                .is_err()
        );
        assert!(
            row_one
                .receipt()
                .validate_candidate(
                    &compiled_b,
                    &expectation_b,
                    row_one.object().as_bytes(),
                    SearchSpanFinalImageGlueLimitsV1::default(),
                )
                .is_err()
        );
        assert_eq!(
            row_one.receipt().runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );
    }
}
