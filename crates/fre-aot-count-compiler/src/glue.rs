use fre_aot_count_contract::{
    COUNT_ENTRY_SYMBOL_PREFIX_V2, COUNT_METADATA_SYMBOL_PREFIX_V2, COUNT_PAYLOAD_SYMBOL_PREFIX_V2,
    EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2, STATIC_COUNT_EXPECTATION_BYTES_V2,
    inspect_static_count_expectation_v2,
};
use fre_exact_alloc::zeroed_exact;
use sha2::{Digest, Sha256};

use crate::{CountCompileErrorV2, FocusedCompiledCountV2, RuntimeAuthorityV2};

const FINAL_IMAGE_RECEIPT_DOMAIN_V2: &[u8] = b"FRE-AOT-COUNT-UNSIGNED-FINAL-IMAGE\0\x03";
const FINAL_IMAGE_RECEIPT_MAGIC_V2: [u8; 8] = *b"FRECFI\0\x03";
const FINAL_IMAGE_RECEIPT_SCHEMA_V2: u16 = 3;
const FINAL_IMAGE_RECEIPT_ADOPTER_OFFSET: usize = 10;
const FINAL_IMAGE_RECEIPT_ROW_OFFSET: usize = 16;
const FINAL_IMAGE_RECEIPT_OBJECT_BYTES_OFFSET: usize = 24;
const FINAL_IMAGE_RECEIPT_PRELINK_IDENTITY_OFFSET: usize = 32;
const FINAL_IMAGE_RECEIPT_COMPILE_IDENTITY_OFFSET: usize = 64;
const FINAL_IMAGE_RECEIPT_IMPLEMENTATION_IDENTITY_OFFSET: usize = 96;
const FINAL_IMAGE_RECEIPT_EXPECTATION_IDENTITY_OFFSET: usize = 128;
const FINAL_IMAGE_RECEIPT_GLUE_IDENTITY_OFFSET: usize = 160;
const FINAL_IMAGE_RECEIPT_CODE_IDENTITY_OFFSET: usize = 192;
const FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET: usize = 224;
pub const UNSIGNED_COUNT_FINAL_IMAGE_RECEIPT_BYTES_V2: usize = 256;

pub const COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2: usize = 40;
pub const COUNT_FINAL_IMAGE_GLUE_RELOCATIONS_V2: usize = 9;

const GLUE_SYMBOL_PREFIX_V2: &str = "fre_aot_count_glue_v2_";
const EXPECTATION_SYMBOL_PREFIX_V2: &str = "fre_aot_count_expectation_v2_";
const RUNTIME_ADOPT_SYMBOL_V2: &str = "fre_aot_static_count_adopt_raw_v2";
const QUALIFICATION_RUNTIME_ADOPT_SYMBOL_V2: &str =
    "fre_aot_static_count_adopt_qualification_raw_v2";
const CONTENT_OFFSET: usize = 400;
const EXPECTATION_FILE_OFFSET: usize = CONTENT_OFFSET + COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2;
const EXPECTATION_ADDRESS: usize = COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2;
const SEGMENT_BYTES: usize =
    COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2 + STATIC_COUNT_EXPECTATION_BYTES_V2;
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
const MIN_MACOS_VERSION_V2: u32 = 0x000b_0000;
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
    EXPECTATION_FILE_OFFSET + STATIC_COUNT_EXPECTATION_BYTES_V2 == CONTENT_OFFSET + SEGMENT_BYTES
);
const _: () = assert!(UNSIGNED_COUNT_FINAL_IMAGE_RECEIPT_BYTES_V2 == 256);

/// Runtime boundary named by one deterministic final-image glue object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CountFinalImageAdopterV2 {
    /// Ordinary production adoption, whose rows come only from source-reviewed
    /// promotion atoms.
    Production,
    /// Explicitly unsafe private qualification adoption, isolated from the
    /// production row table and registry.
    QualificationPrivate,
}

impl CountFinalImageAdopterV2 {
    const fn symbol(self) -> &'static str {
        match self {
            Self::Production => RUNTIME_ADOPT_SYMBOL_V2,
            Self::QualificationPrivate => QUALIFICATION_RUNTIME_ADOPT_SYMBOL_V2,
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

/// Hard bound for one deterministic final-image glue object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountFinalImageGlueLimitsV2 {
    pub max_object_bytes: u64,
}

impl Default for CountFinalImageGlueLimitsV2 {
    fn default() -> Self {
        Self {
            max_object_bytes: 16 << 10,
        }
    }
}

/// One deterministic relocatable object containing glue and expectation bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct CountFinalImageGlueObjectV2 {
    bytes: Vec<u8>,
    row_selector: u16,
    adopter: CountFinalImageAdopterV2,
    compile_identity: [u8; 32],
    expectation_identity: [u8; 32],
    object_identity: [u8; 32],
    code_identity: [u8; 32],
}

impl CountFinalImageGlueObjectV2 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn row_selector(&self) -> u16 {
        self.row_selector
    }

    #[must_use]
    pub const fn adopter(&self) -> CountFinalImageAdopterV2 {
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
    pub const fn object_identity(&self) -> &[u8; 32] {
        &self.object_identity
    }

    #[must_use]
    pub const fn code_identity(&self) -> &[u8; 32] {
        &self.code_identity
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

/// Strict view of one canonical final-image glue object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CountFinalImageGlueInspectionV2<'a> {
    object_bytes: usize,
    row_selector: u16,
    adopter: CountFinalImageAdopterV2,
    compile_identity: [u8; 32],
    expectation_identity: [u8; 32],
    object_identity: [u8; 32],
    code_identity: [u8; 32],
    expectation: &'a [u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
}

impl<'a> CountFinalImageGlueInspectionV2<'a> {
    #[must_use]
    pub const fn object_bytes(&self) -> usize {
        self.object_bytes
    }

    #[must_use]
    pub const fn row_selector(&self) -> u16 {
        self.row_selector
    }

    #[must_use]
    pub const fn adopter(&self) -> CountFinalImageAdopterV2 {
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
    pub const fn object_identity(&self) -> &[u8; 32] {
        &self.object_identity
    }

    #[must_use]
    pub const fn code_identity(&self) -> &[u8; 32] {
        &self.code_identity
    }

    #[must_use]
    pub const fn expectation(&self) -> &'a [u8; STATIC_COUNT_EXPECTATION_BYTES_V2] {
        self.expectation
    }
}

/// Canonical signer-free binding of prelink content to one glue object.
///
/// This is an integrity receipt, not a signature or runtime support row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsignedCountFinalImageReceiptV2 {
    bytes: [u8; UNSIGNED_COUNT_FINAL_IMAGE_RECEIPT_BYTES_V2],
}

impl UnsignedCountFinalImageReceiptV2 {
    #[must_use]
    pub const fn canonical_bytes(&self) -> &[u8; UNSIGNED_COUNT_FINAL_IMAGE_RECEIPT_BYTES_V2] {
        &self.bytes
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> RuntimeAuthorityV2 {
        RuntimeAuthorityV2::Absent
    }

    #[must_use]
    pub fn authenticates_itself(&self) -> bool {
        let Some(adopter) = self.adopter() else {
            return false;
        };
        self.bytes[..8] == FINAL_IMAGE_RECEIPT_MAGIC_V2
            && self.bytes[8..10] == FINAL_IMAGE_RECEIPT_SCHEMA_V2.to_le_bytes()
            && self.bytes[FINAL_IMAGE_RECEIPT_ADOPTER_OFFSET..12]
                == adopter.receipt_code().to_le_bytes()
            && self.bytes[12..16]
                == u32::try_from(UNSIGNED_COUNT_FINAL_IMAGE_RECEIPT_BYTES_V2)
                    .expect("fixed final-image receipt width")
                    .to_le_bytes()
            && self.bytes[18..20]
                == u16::try_from(COUNT_FINAL_IMAGE_GLUE_RELOCATIONS_V2)
                    .expect("fixed relocation count")
                    .to_le_bytes()
            && self.bytes[20..22]
                == u16::try_from(COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2)
                    .expect("fixed code width")
                    .to_le_bytes()
            && self.bytes[22..24] == [0; 2]
            && digest_with_domain(
                FINAL_IMAGE_RECEIPT_DOMAIN_V2,
                &self.bytes[..FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET],
            ) == *self.content_identity()
    }

    #[must_use]
    pub fn adopter(&self) -> Option<CountFinalImageAdopterV2> {
        CountFinalImageAdopterV2::from_receipt_code(u16::from_le_bytes(
            self.bytes[FINAL_IMAGE_RECEIPT_ADOPTER_OFFSET..12]
                .try_into()
                .expect("fixed final-image adopter range"),
        ))
    }

    #[must_use]
    pub fn row_selector(&self) -> u16 {
        u16::from_le_bytes(
            self.bytes[FINAL_IMAGE_RECEIPT_ROW_OFFSET..FINAL_IMAGE_RECEIPT_ROW_OFFSET + 2]
                .try_into()
                .expect("fixed row-selector range"),
        )
    }

    #[must_use]
    pub fn prelink_content_identity(&self) -> &[u8; 32] {
        fixed_identity(&self.bytes, FINAL_IMAGE_RECEIPT_PRELINK_IDENTITY_OFFSET)
    }

    #[must_use]
    pub fn compile_identity(&self) -> &[u8; 32] {
        fixed_identity(&self.bytes, FINAL_IMAGE_RECEIPT_COMPILE_IDENTITY_OFFSET)
    }

    #[must_use]
    pub fn implementation_object_identity(&self) -> &[u8; 32] {
        fixed_identity(
            &self.bytes,
            FINAL_IMAGE_RECEIPT_IMPLEMENTATION_IDENTITY_OFFSET,
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

    /// Validate arbitrary glue bytes without manufacturing runtime authority.
    pub fn validate_candidate<'a>(
        &self,
        candidate: &'a [u8],
        limits: CountFinalImageGlueLimitsV2,
    ) -> Result<CountFinalImageGlueInspectionV2<'a>, CountCompileErrorV2> {
        if !self.authenticates_itself() {
            return Err(CountCompileErrorV2::InvalidFinalImageReceipt);
        }
        let inspection = inspect_count_final_image_glue_v2(candidate, limits)?;
        let adopter = self
            .adopter()
            .ok_or(CountCompileErrorV2::InvalidFinalImageReceipt)?;
        let expected_object_bytes = read_u64(
            &self.bytes,
            FINAL_IMAGE_RECEIPT_OBJECT_BYTES_OFFSET,
            "final-image receipt object bytes",
        )?;
        if u64::try_from(inspection.object_bytes()).ok() != Some(expected_object_bytes)
            || inspection.row_selector() != self.row_selector()
            || inspection.adopter() != adopter
            || inspection.compile_identity() != self.compile_identity()
            || inspection.expectation_identity() != self.expectation_identity()
            || inspection.object_identity() != self.glue_object_identity()
            || inspection.code_identity() != self.glue_code_identity()
        {
            return Err(CountCompileErrorV2::InvalidFinalImageReceipt);
        }
        Ok(inspection)
    }
}

/// Inert deterministic glue plus its unsigned final-image receipt.
#[derive(Debug, Eq, PartialEq)]
pub struct PublishedCountFinalImageGlueV2 {
    object: CountFinalImageGlueObjectV2,
    receipt: UnsignedCountFinalImageReceiptV2,
}

impl PublishedCountFinalImageGlueV2 {
    #[must_use]
    pub const fn object(&self) -> &CountFinalImageGlueObjectV2 {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> &UnsignedCountFinalImageReceiptV2 {
        &self.receipt
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> RuntimeAuthorityV2 {
        RuntimeAuthorityV2::Absent
    }
}

/// Publish a deterministic row-selector-first final-image glue object.
///
/// The emitted `AArch64` trampoline preserves `x0`, loads the literal row
/// selector into `w1`, materializes expectation/entry/payload/metadata
/// addresses in `x2..x5`, and tail-branches to the runtime adopter. The result
/// remains unsigned and inert.
pub fn publish_count_final_image_glue_v2(
    compiled: &FocusedCompiledCountV2,
    row_selector: u16,
    limits: CountFinalImageGlueLimitsV2,
) -> Result<PublishedCountFinalImageGlueV2, CountCompileErrorV2> {
    publish_count_final_image_glue_for_adopter_v2(
        compiled,
        row_selector,
        CountFinalImageAdopterV2::Production,
        limits,
    )
}

/// Publish deterministic glue for the separately named private qualification
/// adopter.
///
/// The resulting object is still inert and unsigned. It cannot link unless
/// the runtime's private qualification feature explicitly supplies that
/// adopter symbol.
pub fn publish_count_qualification_final_image_glue_v2(
    compiled: &FocusedCompiledCountV2,
    row_selector: u16,
    limits: CountFinalImageGlueLimitsV2,
) -> Result<PublishedCountFinalImageGlueV2, CountCompileErrorV2> {
    publish_count_final_image_glue_for_adopter_v2(
        compiled,
        row_selector,
        CountFinalImageAdopterV2::QualificationPrivate,
        limits,
    )
}

fn publish_count_final_image_glue_for_adopter_v2(
    compiled: &FocusedCompiledCountV2,
    row_selector: u16,
    adopter: CountFinalImageAdopterV2,
    limits: CountFinalImageGlueLimitsV2,
) -> Result<PublishedCountFinalImageGlueV2, CountCompileErrorV2> {
    let expectation_claim = inspect_static_count_expectation_v2(compiled.expectation())
        .map_err(|_| glue_error("focused expectation"))?;
    let compile_identity = *compiled.implementation_object().compile_identity();
    if expectation_claim.compile_identity() != &compile_identity
        || expectation_claim.object_identity() != compiled.implementation_object().object_identity()
    {
        return Err(glue_error("focused object binding"));
    }
    let bytes = emit_glue_bytes(
        compiled.expectation(),
        compile_identity,
        row_selector,
        adopter,
        limits,
    )?;
    let inspection = inspect_count_final_image_glue_v2(&bytes, limits)?;
    if inspection.adopter() != adopter {
        return Err(glue_error("final-image adopter"));
    }
    let object = CountFinalImageGlueObjectV2 {
        row_selector: inspection.row_selector,
        adopter: inspection.adopter,
        compile_identity: inspection.compile_identity,
        expectation_identity: inspection.expectation_identity,
        object_identity: inspection.object_identity,
        code_identity: inspection.code_identity,
        bytes,
    };
    let receipt = build_final_image_receipt(compiled, &object)?;
    if receipt.runtime_authority() != RuntimeAuthorityV2::Absent
        || receipt
            .validate_candidate(object.as_bytes(), limits)
            .is_err()
    {
        return Err(CountCompileErrorV2::InvalidFinalImageReceipt);
    }
    Ok(PublishedCountFinalImageGlueV2 { object, receipt })
}

/// Strictly inspect one deterministic final-image glue object.
pub fn inspect_count_final_image_glue_v2(
    bytes: &[u8],
    limits: CountFinalImageGlueLimitsV2,
) -> Result<CountFinalImageGlueInspectionV2<'_>, CountCompileErrorV2> {
    enforce_limit(
        limits.max_object_bytes,
        usize_u64(bytes.len(), "glue object bytes")?,
    )?;
    let expectation_end = EXPECTATION_FILE_OFFSET
        .checked_add(STATIC_COUNT_EXPECTATION_BYTES_V2)
        .ok_or_else(|| overflow("glue expectation end"))?;
    let expectation: &[u8; STATIC_COUNT_EXPECTATION_BYTES_V2] = bytes
        .get(EXPECTATION_FILE_OFFSET..expectation_end)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| glue_error("glue expectation range"))?;
    let claim = inspect_static_count_expectation_v2(expectation)
        .map_err(|_| glue_error("glue expectation contract"))?;
    let compile_identity = *claim.compile_identity();
    let expectation_identity = *claim.expectation_identity();
    let code: &[u8; COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2] = bytes
        .get(CONTENT_OFFSET..EXPECTATION_FILE_OFFSET)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| glue_error("glue code range"))?;
    let row_selector = decode_row_selector(code)?;
    let production = emit_glue_bytes(
        expectation,
        compile_identity,
        row_selector,
        CountFinalImageAdopterV2::Production,
        limits,
    )?;
    let adopter = if bytes == production {
        CountFinalImageAdopterV2::Production
    } else {
        let qualification = emit_glue_bytes(
            expectation,
            compile_identity,
            row_selector,
            CountFinalImageAdopterV2::QualificationPrivate,
            limits,
        )?;
        if bytes != qualification {
            return Err(glue_error("canonical glue object"));
        }
        CountFinalImageAdopterV2::QualificationPrivate
    };
    Ok(CountFinalImageGlueInspectionV2 {
        object_bytes: bytes.len(),
        row_selector,
        adopter,
        compile_identity,
        expectation_identity,
        object_identity: digest(bytes),
        code_identity: digest(code),
        expectation,
    })
}

fn build_final_image_receipt(
    compiled: &FocusedCompiledCountV2,
    object: &CountFinalImageGlueObjectV2,
) -> Result<UnsignedCountFinalImageReceiptV2, CountCompileErrorV2> {
    let mut bytes = [0_u8; UNSIGNED_COUNT_FINAL_IMAGE_RECEIPT_BYTES_V2];
    {
        let mut writer = Writer::new(&mut bytes);
        writer.bytes(&FINAL_IMAGE_RECEIPT_MAGIC_V2)?;
        writer.u16(FINAL_IMAGE_RECEIPT_SCHEMA_V2)?;
        writer.u16(object.adopter().receipt_code())?;
        writer.u32(
            u32::try_from(UNSIGNED_COUNT_FINAL_IMAGE_RECEIPT_BYTES_V2)
                .expect("fixed final-image receipt width"),
        )?;
        writer.u16(object.row_selector())?;
        writer.u16(
            u16::try_from(COUNT_FINAL_IMAGE_GLUE_RELOCATIONS_V2).expect("fixed relocation count"),
        )?;
        writer.u16(
            u16::try_from(COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2).expect("fixed glue code width"),
        )?;
        writer.u16(0)?;
        writer.u64(usize_u64(object.as_bytes().len(), "glue object bytes")?)?;
        writer.bytes(compiled.unsigned_prelink_receipt().content_identity())?;
        writer.bytes(object.compile_identity())?;
        writer.bytes(compiled.implementation_object().object_identity())?;
        writer.bytes(object.expectation_identity())?;
        writer.bytes(object.object_identity())?;
        writer.bytes(object.code_identity())?;
        if writer.position() != FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET {
            return Err(CountCompileErrorV2::InvalidFinalImageReceipt);
        }
    }
    let content_identity = digest_with_domain(
        FINAL_IMAGE_RECEIPT_DOMAIN_V2,
        &bytes[..FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET],
    );
    bytes[FINAL_IMAGE_RECEIPT_CONTENT_IDENTITY_OFFSET..].copy_from_slice(&content_identity);
    let receipt = UnsignedCountFinalImageReceiptV2 { bytes };
    if !receipt.authenticates_itself() {
        return Err(CountCompileErrorV2::InvalidFinalImageReceipt);
    }
    Ok(receipt)
}

fn emit_glue_bytes(
    expectation: &[u8; STATIC_COUNT_EXPECTATION_BYTES_V2],
    compile_identity: [u8; 32],
    row_selector: u16,
    adopter: CountFinalImageAdopterV2,
    limits: CountFinalImageGlueLimitsV2,
) -> Result<Vec<u8>, CountCompileErrorV2> {
    let layout = GlueLayout::new(&compile_identity, adopter)?;
    enforce_limit(
        limits.max_object_bytes,
        usize_u64(layout.object_bytes, "glue object bytes")?,
    )?;
    let mut bytes =
        zeroed_exact(layout.object_bytes).map_err(|_| CountCompileErrorV2::AllocationFailed)?;
    if bytes.len() != layout.object_bytes || bytes.capacity() != layout.object_bytes {
        return Err(glue_error("exact glue allocation"));
    }
    write_prefix(&mut bytes[..CONTENT_OFFSET], layout)?;
    copy_region(
        &mut bytes,
        CONTENT_OFFSET,
        &encode_glue_code(row_selector)?,
        "glue code",
    )?;
    copy_region(
        &mut bytes,
        EXPECTATION_FILE_OFFSET,
        expectation,
        "glue expectation",
    )?;
    write_relocations(&mut bytes, layout, &compile_identity, adopter)?;
    write_symbols_and_strings(&mut bytes, layout, &compile_identity, adopter)?;
    Ok(bytes)
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
        adopter: CountFinalImageAdopterV2,
    ) -> Result<Self, CountCompileErrorV2> {
        let relocation_offset = CONTENT_OFFSET
            .checked_add(SEGMENT_BYTES)
            .ok_or_else(|| overflow("glue relocation offset"))?;
        let relocation_bytes = RELOCATION_BYTES
            .checked_mul(COUNT_FINAL_IMAGE_GLUE_RELOCATIONS_V2)
            .ok_or_else(|| overflow("glue relocation bytes"))?;
        let symbol_offset = relocation_offset
            .checked_add(relocation_bytes)
            .ok_or_else(|| overflow("glue symbol offset"))?;
        let symbol_bytes = NLIST_64_BYTES
            .checked_mul(SYMBOLS)
            .ok_or_else(|| overflow("glue symbol bytes"))?;
        let string_offset = symbol_offset
            .checked_add(symbol_bytes)
            .ok_or_else(|| overflow("glue string offset"))?;
        let string_bytes = align_up(
            symbol_string_bytes(compile_identity, adopter)?,
            4,
            "glue string bytes",
        )?;
        let object_bytes = string_offset
            .checked_add(string_bytes)
            .ok_or_else(|| overflow("glue object bytes"))?;
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
    fn suffixed(prefix: &str, identity: &[u8; 32]) -> Result<Self, CountCompileErrorV2> {
        let len = prefix
            .len()
            .checked_add(EXPORTED_SYMBOL_IDENTITY_HEX_BYTES_V2)
            .ok_or_else(|| overflow("glue symbol name length"))?;
        if len > SYMBOL_NAME_STORAGE_BYTES {
            return Err(glue_error("glue symbol name storage"));
        }
        let mut bytes = [0_u8; SYMBOL_NAME_STORAGE_BYTES];
        bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
        let mut cursor = prefix.len();
        for byte in identity {
            for nibble in [byte >> 4, byte & 0x0f] {
                let slot = bytes
                    .get_mut(cursor)
                    .ok_or_else(|| glue_error("glue symbol hex range"))?;
                *slot = lower_hex(nibble);
                cursor = cursor
                    .checked_add(1)
                    .ok_or_else(|| overflow("glue symbol hex offset"))?;
            }
        }
        if cursor != len {
            return Err(glue_error("glue symbol name length"));
        }
        Ok(Self { bytes, len })
    }

    fn fixed(name: &str) -> Result<Self, CountCompileErrorV2> {
        if name.len() > SYMBOL_NAME_STORAGE_BYTES {
            return Err(glue_error("fixed glue symbol name storage"));
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
    adopter: CountFinalImageAdopterV2,
) -> Result<[SymbolSpec; SYMBOLS], CountCompileErrorV2> {
    let mut specs = [
        SymbolSpec {
            role: SymbolRole::Glue,
            name: SymbolName::suffixed(GLUE_SYMBOL_PREFIX_V2, compile_identity)?,
            defined: true,
            section: 1,
            value: 0,
        },
        SymbolSpec {
            role: SymbolRole::Expectation,
            name: SymbolName::suffixed(EXPECTATION_SYMBOL_PREFIX_V2, compile_identity)?,
            defined: true,
            section: 2,
            value: usize_u64(EXPECTATION_ADDRESS, "expectation symbol value")?,
        },
        SymbolSpec {
            role: SymbolRole::Entry,
            name: SymbolName::suffixed(COUNT_ENTRY_SYMBOL_PREFIX_V2, compile_identity)?,
            defined: false,
            section: 0,
            value: 0,
        },
        SymbolSpec {
            role: SymbolRole::Payload,
            name: SymbolName::suffixed(COUNT_PAYLOAD_SYMBOL_PREFIX_V2, compile_identity)?,
            defined: false,
            section: 0,
            value: 0,
        },
        SymbolSpec {
            role: SymbolRole::Metadata,
            name: SymbolName::suffixed(COUNT_METADATA_SYMBOL_PREFIX_V2, compile_identity)?,
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
) -> Result<u32, CountCompileErrorV2> {
    specs
        .iter()
        .position(|spec| spec.role == role)
        .and_then(|index| u32::try_from(index).ok())
        .ok_or_else(|| glue_error("glue relocation symbol index"))
}

fn write_prefix(prefix: &mut [u8], layout: GlueLayout) -> Result<(), CountCompileErrorV2> {
    if prefix.len() != CONTENT_OFFSET {
        return Err(glue_error("glue prefix destination"));
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
        "glue load command bytes",
    )?)?;
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(LC_SEGMENT_64)?;
    writer.u32(u32_from_usize(
        SEGMENT_WITH_SECTIONS_BYTES,
        "glue segment command bytes",
    )?)?;
    writer.fixed_name("")?;
    writer.u64(0)?;
    writer.u64(usize_u64(SEGMENT_BYTES, "glue segment bytes")?)?;
    writer.u64(usize_u64(CONTENT_OFFSET, "glue content offset")?)?;
    writer.u64(usize_u64(SEGMENT_BYTES, "glue segment file bytes")?)?;
    writer.u32(VM_PROT_RWX)?;
    writer.u32(VM_PROT_RWX)?;
    writer.u32(SECTIONS)?;
    writer.u32(0)?;
    writer.section(
        "__text",
        "__TEXT",
        0,
        usize_u64(COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2, "glue code bytes")?,
        u32_from_usize(CONTENT_OFFSET, "glue code file offset")?,
        2,
        u32_from_usize(layout.relocation_offset, "glue relocation offset")?,
        u32::try_from(COUNT_FINAL_IMAGE_GLUE_RELOCATIONS_V2).expect("fixed relocation count"),
        TEXT_SECTION_FLAGS,
    )?;
    writer.section(
        "__fre_expect",
        "__FRE_CONST",
        usize_u64(EXPECTATION_ADDRESS, "glue expectation address")?,
        usize_u64(STATIC_COUNT_EXPECTATION_BYTES_V2, "glue expectation bytes")?,
        u32_from_usize(EXPECTATION_FILE_OFFSET, "glue expectation file offset")?,
        3,
        0,
        0,
        EXPECTATION_SECTION_FLAGS,
    )?;

    writer.u32(LC_BUILD_VERSION)?;
    writer.u32(u32_from_usize(
        BUILD_VERSION_COMMAND_BYTES,
        "glue build-version command bytes",
    )?)?;
    writer.u32(PLATFORM_MACOS_LOAD_COMMAND)?;
    writer.u32(MIN_MACOS_VERSION_V2)?;
    writer.u32(0)?;
    writer.u32(0)?;

    writer.u32(LC_SYMTAB)?;
    writer.u32(u32_from_usize(
        SYMTAB_COMMAND_BYTES,
        "glue symtab command bytes",
    )?)?;
    writer.u32(u32_from_usize(layout.symbol_offset, "glue symbol offset")?)?;
    writer.u32(u32::try_from(SYMBOLS).expect("fixed glue symbol count"))?;
    writer.u32(u32_from_usize(layout.string_offset, "glue string offset")?)?;
    writer.u32(u32_from_usize(layout.string_bytes, "glue string bytes")?)?;

    writer.u32(LC_DYSYMTAB)?;
    writer.u32(u32_from_usize(
        DYSYMTAB_COMMAND_BYTES,
        "glue dysymtab command bytes",
    )?)?;
    for value in [0, 0, 0, DEFINED_SYMBOLS, DEFINED_SYMBOLS, UNDEFINED_SYMBOLS] {
        writer.u32(value)?;
    }
    for _ in 0..12 {
        writer.u32(0)?;
    }
    if writer.position() != MACH_HEADER_BYTES + LOAD_COMMAND_BYTES {
        return Err(glue_error("glue load command length"));
    }
    Ok(())
}

fn write_relocations(
    bytes: &mut [u8],
    layout: GlueLayout,
    compile_identity: &[u8; 32],
    adopter: CountFinalImageAdopterV2,
) -> Result<(), CountCompileErrorV2> {
    let specs = symbol_specs(compile_identity, adopter)?;
    let relocation_bytes = RELOCATION_BYTES
        .checked_mul(COUNT_FINAL_IMAGE_GLUE_RELOCATIONS_V2)
        .ok_or_else(|| overflow("glue relocation bytes"))?;
    let end = layout
        .relocation_offset
        .checked_add(relocation_bytes)
        .ok_or_else(|| overflow("glue relocation end"))?;
    let destination = bytes
        .get_mut(layout.relocation_offset..end)
        .ok_or_else(|| glue_error("glue relocation destination"))?;
    let mut writer = Writer::new(destination);
    for relocation in [
        Relocation::branch(36, SymbolRole::RuntimeAdopt),
        Relocation::page_off(32, SymbolRole::Metadata),
        Relocation::page(28, SymbolRole::Metadata),
        Relocation::page_off(24, SymbolRole::Payload),
        Relocation::page(20, SymbolRole::Payload),
        Relocation::page_off(16, SymbolRole::Entry),
        Relocation::page(12, SymbolRole::Entry),
        Relocation::page_off(8, SymbolRole::Expectation),
        Relocation::page(4, SymbolRole::Expectation),
    ] {
        writer.i32(relocation.address)?;
        writer.u32(relocation.word(symbol_index(&specs, relocation.role)?)?)?;
    }
    if writer.position() != relocation_bytes {
        return Err(glue_error("glue relocation length"));
    }
    Ok(())
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
        reason = "fixed Mach-O relocation bitfields are range-checked before packing"
    )]
    fn word(self, symbol_index: u32) -> Result<u32, CountCompileErrorV2> {
        if symbol_index >= (1 << 24) || self.kind >= 16 {
            return Err(glue_error("glue relocation bitfield"));
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
    adopter: CountFinalImageAdopterV2,
) -> Result<(), CountCompileErrorV2> {
    let specs = symbol_specs(compile_identity, adopter)?;
    let symbol_bytes = NLIST_64_BYTES
        .checked_mul(SYMBOLS)
        .ok_or_else(|| overflow("glue symbol bytes"))?;
    let symbol_end = layout
        .symbol_offset
        .checked_add(symbol_bytes)
        .ok_or_else(|| overflow("glue symbol end"))?;
    let mut writer = Writer::new(
        bytes
            .get_mut(layout.symbol_offset..symbol_end)
            .ok_or_else(|| glue_error("glue symbol destination"))?,
    );
    let mut string_index = 4_usize;
    for spec in specs {
        writer.u32(u32_from_usize(string_index, "glue string index")?)?;
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
            .ok_or_else(|| overflow("glue string index"))?;
    }
    if writer.position() != symbol_bytes {
        return Err(glue_error("glue symbol length"));
    }

    let string_end = layout
        .string_offset
        .checked_add(layout.string_bytes)
        .ok_or_else(|| overflow("glue string end"))?;
    let mut writer = Writer::new(
        bytes
            .get_mut(layout.string_offset..string_end)
            .ok_or_else(|| glue_error("glue string destination"))?,
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
    adopter: CountFinalImageAdopterV2,
) -> Result<usize, CountCompileErrorV2> {
    symbol_specs(compile_identity, adopter)?
        .into_iter()
        .try_fold(4_usize, |total, spec| {
            total
                .checked_add(1)
                .and_then(|value| value.checked_add(spec.name.as_bytes().len()))
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| overflow("glue string bytes"))
        })
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "fixed A64 instruction bitfields are assembled from one u16 selector and audited register constants"
)]
fn encode_glue_code(
    row_selector: u16,
) -> Result<[u8; COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2], CountCompileErrorV2> {
    let mut code = [0_u8; COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2];
    let mut writer = Writer::new(&mut code);
    writer.u32(0x5280_0001 | (u32::from(row_selector) << 5))?;
    for register in [2_u32, 3, 4, 5] {
        writer.u32(0x9000_0000 | register)?;
        writer.u32(0x9100_0000 | (register << 5) | register)?;
    }
    writer.u32(0x1400_0000)?;
    if writer.position() != COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2 {
        return Err(glue_error("glue code length"));
    }
    Ok(code)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the canonical full-object comparison validates the decoded fixed MOVZ bitfield"
)]
fn decode_row_selector(
    code: &[u8; COUNT_FINAL_IMAGE_GLUE_CODE_BYTES_V2],
) -> Result<u16, CountCompileErrorV2> {
    let instruction =
        u32::from_le_bytes(code[..4].try_into().expect("fixed first glue instruction"));
    let selector =
        u16::try_from((instruction >> 5) & 0xffff).map_err(|_| glue_error("glue row selector"))?;
    if encode_glue_code(selector)? != *code {
        return Err(glue_error("glue instruction sequence"));
    }
    Ok(selector)
}

fn copy_region(
    destination: &mut [u8],
    offset: usize,
    source: &[u8],
    at: &'static str,
) -> Result<(), CountCompileErrorV2> {
    let end = offset
        .checked_add(source.len())
        .ok_or_else(|| overflow("glue copy region"))?;
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
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), CountCompileErrorV2> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or_else(|| overflow("glue writer offset"))?;
        self.bytes
            .get_mut(self.position..end)
            .ok_or_else(|| glue_error("glue writer destination"))?
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

    fn i32(&mut self, value: i32) -> Result<(), CountCompileErrorV2> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), CountCompileErrorV2> {
        self.bytes(&value.to_le_bytes())
    }

    fn fixed_name(&mut self, name: &str) -> Result<(), CountCompileErrorV2> {
        if name.len() > 16 {
            return Err(glue_error("glue Mach-O fixed name"));
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
    ) -> Result<(), CountCompileErrorV2> {
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
        .expect("fixed final-image receipt identity end");
    bytes[offset..end]
        .try_into()
        .expect("fixed final-image receipt identity range")
}

fn read_u64(bytes: &[u8], offset: usize, at: &'static str) -> Result<u64, CountCompileErrorV2> {
    let end = offset.checked_add(8).ok_or_else(|| overflow(at))?;
    let encoded: [u8; 8] = bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or(CountCompileErrorV2::InvalidFinalImageReceipt)?;
    Ok(u64::from_le_bytes(encoded))
}

fn align_up(
    value: usize,
    alignment: usize,
    at: &'static str,
) -> Result<usize, CountCompileErrorV2> {
    let mask = alignment.checked_sub(1).ok_or_else(|| overflow(at))?;
    if alignment == 0 || alignment & mask != 0 {
        return Err(glue_error(at));
    }
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or_else(|| overflow(at))
}

fn enforce_limit(limit: u64, required: u64) -> Result<(), CountCompileErrorV2> {
    if required <= limit {
        Ok(())
    } else {
        Err(CountCompileErrorV2::ResourceLimit {
            resource: "final-image glue object bytes",
            limit,
            required,
        })
    }
}

fn u32_from_usize(value: usize, at: &'static str) -> Result<u32, CountCompileErrorV2> {
    u32::try_from(value).map_err(|_| overflow(at))
}

fn usize_u64(value: usize, at: &'static str) -> Result<u64, CountCompileErrorV2> {
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

const fn glue_error(at: &'static str) -> CountCompileErrorV2 {
    CountCompileErrorV2::InvalidFinalImageGlue { at }
}

const fn overflow(at: &'static str) -> CountCompileErrorV2 {
    CountCompileErrorV2::ArithmeticOverflow { at }
}
