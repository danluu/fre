//! Explicit static-link ABI bindings for inert V26/tag39 Search objects.
//!
//! The compiler's implementation objects already contain the exact
//! five-argument Search-v1 machine ABI, but the historical public C wording
//! describes Span's two result stores. This module gives `Exists` and
//! `SelectedEnd` separate declarations and emits a one-instruction direct
//! tail-branch object whose only undefined symbol is the implementation
//! object's identity-suffixed entry.
//!
//! The binding is deliberately manual. It contains no expectation, adopter,
//! source-qualification selector, registry row, function pointer, or runtime
//! authority. A caller must explicitly retain and link both the compiler
//! object and this glue object. Strict inspection re-emits the whole glue
//! object from compiler-sealed output and identity claims, so a sibling output
//! or implementation identity is refused before publication.

use core::{fmt, fmt::Write as _};

use fre_aot_search_contract::{
    SEARCH_BACKEND_ASIMD_TAG39_V1, search_v26_production_literal_width_is_valid_v1,
};
use fre_kernel_ir::{Exists, Operation, OutputKind, SelectedEnd};
use sha2::{Digest, Sha256};

use crate::{
    LinuxAarch64SearchBackendV1, LinuxSearchCompiledObjectV1, SearchAotRuntimeAuthorityV1,
    SearchCompiledObjectV1,
};

/// Exact `AArch64` direct tail-branch instruction bytes.
pub const SEARCH_V26_STATIC_GLUE_CODE_V1: [u8; 4] = [0x00, 0x00, 0x00, 0x14];
/// Every binding object contains exactly one external relocation.
pub const SEARCH_V26_STATIC_GLUE_RELOCATIONS_V1: usize = 1;
/// Mach-O `ARM64_RELOC_BRANCH26`.
pub const SEARCH_V26_STATIC_MACHO_RELOCATION_V1: u32 = 2;
/// ELF `R_AARCH64_JUMP26`.
pub const SEARCH_V26_STATIC_ELF_RELOCATION_V1: u32 = 282;
/// Hard bound for one tiny direct-binding object.
pub const HARD_MAX_SEARCH_V26_STATIC_GLUE_OBJECT_BYTES_V1: usize = 64 << 10;

const GLUE_IDENTITY_DOMAIN_V1: &[u8] = b"FRE-AOT-SEARCH-V26-STATIC-GLUE\0\x01";
const HEADER_IDENTITY_DOMAIN_V1: &[u8] = b"FRE-AOT-SEARCH-V26-STATIC-HEADER\0\x01";
const SYMBOL_STORAGE_BYTES_V1: usize = 160;
const WRAPPER_EXISTS_PREFIX_V1: &str = "fre_aot_search_v26_exists_static_v1_";
const WRAPPER_SELECTED_END_PREFIX_V1: &str = "fre_aot_search_v26_selected_end_static_v1_";
const RESULT_EXISTS_PREFIX_V1: &str = "fre_aot_search_v26_exists_result_v1_";
const RESULT_SELECTED_END_PREFIX_V1: &str = "fre_aot_search_v26_selected_end_result_v1_";

/// Object format selected by one explicit static binding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SearchV26StaticPlatformV1 {
    MacosAarch64,
    LinuxAarch64,
}

impl SearchV26StaticPlatformV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::MacosAarch64 => 1,
            Self::LinuxAarch64 => 2,
        }
    }
}

/// Failure while authenticating or emitting an output-specific static bind.
#[derive(Debug)]
#[non_exhaustive]
pub enum SearchV26StaticAbiErrorV1 {
    UnsupportedOutput {
        output: OutputKind,
    },
    WrongOutput {
        expected: OutputKind,
        actual: OutputKind,
    },
    WrongPlatform {
        expected: SearchV26StaticPlatformV1,
        actual: SearchV26StaticPlatformV1,
    },
    SourceBinding {
        at: &'static str,
    },
    InvalidGlue {
        at: &'static str,
    },
    AllocationFailed,
    ArithmeticOverflow {
        at: &'static str,
    },
}

impl fmt::Display for SearchV26StaticAbiErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE V26 output-specific static ABI binding failed: {self:?}"
        )
    }
}

impl std::error::Error for SearchV26StaticAbiErrorV1 {}

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
    SearchV26StaticGlueIdentityV1,
    "SearchV26StaticGlueIdentityV1"
);
identity!(
    SearchV26StaticHeaderIdentityV1,
    "SearchV26StaticHeaderIdentityV1"
);

/// One allocation-free identity-derived C or linker name.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SearchV26StaticSymbolNameV1 {
    bytes: [u8; SYMBOL_STORAGE_BYTES_V1],
    len: usize,
}

impl SearchV26StaticSymbolNameV1 {
    fn suffixed(prefix: &str, identity: &[u8; 32]) -> Result<Self, SearchV26StaticAbiErrorV1> {
        let len = prefix
            .len()
            .checked_add(64)
            .ok_or_else(|| overflow("symbol name length"))?;
        if len > SYMBOL_STORAGE_BYTES_V1 {
            return Err(glue_error("symbol name storage"));
        }
        let mut bytes = [0_u8; SYMBOL_STORAGE_BYTES_V1];
        bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
        let mut cursor = prefix.len();
        for byte in identity {
            bytes[cursor] = lower_hex(byte >> 4);
            let low = cursor
                .checked_add(1)
                .ok_or_else(|| overflow("symbol low-nibble cursor"))?;
            bytes[low] = lower_hex(byte & 0x0f);
            cursor = cursor
                .checked_add(2)
                .ok_or_else(|| overflow("symbol name cursor"))?;
        }
        Ok(Self { bytes, len })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).expect("canonical ASCII static-binding symbol")
    }
}

impl fmt::Debug for SearchV26StaticSymbolNameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SearchV26StaticSymbolNameV1")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for SearchV26StaticSymbolNameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Exact wrapper, implementation entry, and result type for one binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchV26StaticSymbolsV1 {
    wrapper: SearchV26StaticSymbolNameV1,
    entry: SearchV26StaticSymbolNameV1,
    result_type: SearchV26StaticSymbolNameV1,
}

impl SearchV26StaticSymbolsV1 {
    fn new(
        platform: SearchV26StaticPlatformV1,
        output: OutputKind,
        compile_identity: &[u8; 32],
    ) -> Result<Self, SearchV26StaticAbiErrorV1> {
        let (wrapper_prefix, result_prefix) = output_prefixes(output)?;
        let entry_prefix = match platform {
            SearchV26StaticPlatformV1::MacosAarch64 => fre_aot_macho::SEARCH_ENTRY_SYMBOL_PREFIX_V1,
            SearchV26StaticPlatformV1::LinuxAarch64 => fre_aot_elf::SEARCH_ENTRY_SYMBOL_PREFIX_V1,
        };
        Ok(Self {
            wrapper: SearchV26StaticSymbolNameV1::suffixed(wrapper_prefix, compile_identity)?,
            entry: SearchV26StaticSymbolNameV1::suffixed(entry_prefix, compile_identity)?,
            result_type: SearchV26StaticSymbolNameV1::suffixed(result_prefix, compile_identity)?,
        })
    }

    #[must_use]
    pub const fn wrapper(&self) -> &SearchV26StaticSymbolNameV1 {
        &self.wrapper
    }

    #[must_use]
    pub const fn entry(&self) -> &SearchV26StaticSymbolNameV1 {
        &self.entry
    }

    #[must_use]
    pub const fn result_type(&self) -> &SearchV26StaticSymbolNameV1 {
        &self.result_type
    }
}

/// Compiler-sealed claims copied into one manual static binding.
///
/// Construction is private: values originate only from a fully revalidated
/// typed compiler object. The claims are still signer-free and grant no
/// authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchV26StaticBindingClaimsV1 {
    platform: SearchV26StaticPlatformV1,
    output: OutputKind,
    backend_version: u16,
    literal_bytes: u32,
    compile_identity: [u8; 32],
    implementation_object_identity: [u8; 32],
    compiler_receipt_identity: [u8; 32],
}

impl SearchV26StaticBindingClaimsV1 {
    #[must_use]
    pub const fn platform(&self) -> SearchV26StaticPlatformV1 {
        self.platform
    }

    #[must_use]
    pub const fn output(&self) -> OutputKind {
        self.output
    }

    #[must_use]
    pub const fn backend_version(&self) -> u16 {
        self.backend_version
    }

    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        self.literal_bytes
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
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }
}

/// Deterministic manual static-link artifacts for one V26/tag39 object.
#[derive(Debug, Eq, PartialEq)]
pub struct SearchV26StaticBindingV1 {
    claims: SearchV26StaticBindingClaimsV1,
    symbols: SearchV26StaticSymbolsV1,
    glue_object: Box<[u8]>,
    c_header: Box<str>,
    glue_identity: SearchV26StaticGlueIdentityV1,
    header_identity: SearchV26StaticHeaderIdentityV1,
}

impl SearchV26StaticBindingV1 {
    #[must_use]
    pub const fn claims(&self) -> SearchV26StaticBindingClaimsV1 {
        self.claims
    }

    #[must_use]
    pub const fn symbols(&self) -> SearchV26StaticSymbolsV1 {
        self.symbols
    }

    #[must_use]
    pub fn glue_object(&self) -> &[u8] {
        &self.glue_object
    }

    #[must_use]
    pub fn c_header(&self) -> &str {
        &self.c_header
    }

    #[must_use]
    pub const fn glue_identity(&self) -> SearchV26StaticGlueIdentityV1 {
        self.glue_identity
    }

    #[must_use]
    pub const fn header_identity(&self) -> SearchV26StaticHeaderIdentityV1 {
        self.header_identity
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }

    /// Re-emit and compare every retained public artifact.
    pub fn validate(&self) -> Result<(), SearchV26StaticAbiErrorV1> {
        inspect_search_v26_static_glue_v1(
            self.claims.platform,
            self.claims.output,
            &self.glue_object,
            self.claims,
        )?;
        let expected_header = generate_header(self.claims, &self.symbols)?;
        if expected_header.as_str() != self.c_header.as_ref() {
            return Err(glue_error("canonical C header"));
        }
        let glue_identity =
            artifact_identity(GLUE_IDENTITY_DOMAIN_V1, self.claims, &self.glue_object);
        let header_identity = artifact_identity(
            HEADER_IDENTITY_DOMAIN_V1,
            self.claims,
            self.c_header.as_bytes(),
        );
        if glue_identity != *self.glue_identity.as_bytes()
            || header_identity != *self.header_identity.as_bytes()
        {
            return Err(glue_error("binding artifact identity"));
        }
        Ok(())
    }
}

/// Strict whole-object inspection of a manual output-specific glue object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchV26StaticGlueInspectionV1<'a> {
    bytes: &'a [u8],
    claims: SearchV26StaticBindingClaimsV1,
    symbols: SearchV26StaticSymbolsV1,
}

impl<'a> SearchV26StaticGlueInspectionV1<'a> {
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub const fn claims(&self) -> SearchV26StaticBindingClaimsV1 {
        self.claims
    }

    #[must_use]
    pub const fn symbols(&self) -> SearchV26StaticSymbolsV1 {
        self.symbols
    }

    #[must_use]
    pub const fn relocation_kind(&self) -> u32 {
        match self.claims.platform {
            SearchV26StaticPlatformV1::MacosAarch64 => SEARCH_V26_STATIC_MACHO_RELOCATION_V1,
            SearchV26StaticPlatformV1::LinuxAarch64 => SEARCH_V26_STATIC_ELF_RELOCATION_V1,
        }
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }
}

/// Build one manual Mach-O binding for a typed tag39 `Exists` object.
pub fn build_macos_aarch64_search_v26_exists_static_binding_v1(
    compiled: &SearchCompiledObjectV1<Exists>,
) -> Result<SearchV26StaticBindingV1, SearchV26StaticAbiErrorV1> {
    build_macos_binding(compiled, OutputKind::Exists)
}

/// Build one manual Mach-O binding for a typed tag39 `SelectedEnd` object.
pub fn build_macos_aarch64_search_v26_selected_end_static_binding_v1(
    compiled: &SearchCompiledObjectV1<SelectedEnd>,
) -> Result<SearchV26StaticBindingV1, SearchV26StaticAbiErrorV1> {
    build_macos_binding(compiled, OutputKind::SelectedEnd)
}

/// Build one manual ELF binding for a typed tag39 `Exists` object.
pub fn build_linux_aarch64_search_v26_exists_static_binding_v1(
    compiled: &LinuxSearchCompiledObjectV1<Exists>,
) -> Result<SearchV26StaticBindingV1, SearchV26StaticAbiErrorV1> {
    build_linux_binding(compiled, OutputKind::Exists)
}

/// Build one manual ELF binding for a typed tag39 `SelectedEnd` object.
pub fn build_linux_aarch64_search_v26_selected_end_static_binding_v1(
    compiled: &LinuxSearchCompiledObjectV1<SelectedEnd>,
) -> Result<SearchV26StaticBindingV1, SearchV26StaticAbiErrorV1> {
    build_linux_binding(compiled, OutputKind::SelectedEnd)
}

/// Strictly inspect a direct glue object against exact platform, output, and
/// compiler-sealed identity claims.
pub fn inspect_search_v26_static_glue_v1(
    platform: SearchV26StaticPlatformV1,
    expected_output: OutputKind,
    bytes: &[u8],
    claims: SearchV26StaticBindingClaimsV1,
) -> Result<SearchV26StaticGlueInspectionV1<'_>, SearchV26StaticAbiErrorV1> {
    ensure_supported_output(expected_output)?;
    if claims.platform != platform {
        return Err(SearchV26StaticAbiErrorV1::WrongPlatform {
            expected: platform,
            actual: claims.platform,
        });
    }
    if claims.output != expected_output {
        return Err(SearchV26StaticAbiErrorV1::WrongOutput {
            expected: expected_output,
            actual: claims.output,
        });
    }
    validate_claim_shape(claims)?;
    let symbols =
        SearchV26StaticSymbolsV1::new(claims.platform, claims.output, &claims.compile_identity)?;
    let expected = emit_glue_object(claims.platform, &symbols)?;
    if expected.as_slice() != bytes {
        return Err(glue_error("canonical direct glue object"));
    }
    Ok(SearchV26StaticGlueInspectionV1 {
        bytes,
        claims,
        symbols,
    })
}

fn build_macos_binding<O: Operation>(
    compiled: &SearchCompiledObjectV1<O>,
    expected_output: OutputKind,
) -> Result<SearchV26StaticBindingV1, SearchV26StaticAbiErrorV1> {
    if O::KIND != expected_output || compiled.receipt().output() != expected_output {
        return Err(SearchV26StaticAbiErrorV1::WrongOutput {
            expected: expected_output,
            actual: compiled.receipt().output(),
        });
    }
    if compiled.runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
        || compiled.receipt().runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
    {
        return Err(source_error("runtime authority"));
    }
    let receipt = compiled.receipt();
    if receipt.metadata().backend_version() != SEARCH_BACKEND_ASIMD_TAG39_V1
        || !search_v26_production_literal_width_is_valid_v1(receipt.literal_bytes())
    {
        return Err(source_error("V26 backend/literal envelope"));
    }
    receipt
        .canonical_bytes()
        .map_err(|_| source_error("canonical compiler receipt"))?;
    receipt
        .validate_object(
            compiled.object().as_bytes(),
            fre_aot_macho::ObjectLimits::default(),
        )
        .map_err(|_| source_error("compiler receipt/object"))?;
    let claims = SearchV26StaticBindingClaimsV1 {
        platform: SearchV26StaticPlatformV1::MacosAarch64,
        output: expected_output,
        backend_version: receipt.metadata().backend_version(),
        literal_bytes: receipt.literal_bytes(),
        compile_identity: *receipt.compile_identity().as_bytes(),
        implementation_object_identity: *receipt.object_identity().as_bytes(),
        compiler_receipt_identity: *receipt.receipt_identity().as_bytes(),
    };
    let symbols =
        SearchV26StaticSymbolsV1::new(claims.platform, claims.output, &claims.compile_identity)?;
    if compiled.object().exported_symbols().entry().as_str() != symbols.entry.as_str() {
        return Err(source_error("identity-suffixed implementation entry"));
    }
    finish_binding(claims, &symbols)
}

fn build_linux_binding<O: Operation>(
    compiled: &LinuxSearchCompiledObjectV1<O>,
    expected_output: OutputKind,
) -> Result<SearchV26StaticBindingV1, SearchV26StaticAbiErrorV1> {
    if O::KIND != expected_output || compiled.receipt().output() != expected_output {
        return Err(SearchV26StaticAbiErrorV1::WrongOutput {
            expected: expected_output,
            actual: compiled.receipt().output(),
        });
    }
    if compiled.runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
        || compiled.receipt().runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
    {
        return Err(source_error("runtime authority"));
    }
    let receipt = compiled.receipt();
    if receipt.backend() != LinuxAarch64SearchBackendV1::AsimdV26
        || receipt.metadata().backend_version() != SEARCH_BACKEND_ASIMD_TAG39_V1
        || !search_v26_production_literal_width_is_valid_v1(receipt.literal_bytes())
    {
        return Err(source_error("V26 backend/literal envelope"));
    }
    receipt
        .canonical_receipt_bytes()
        .map_err(|_| source_error("canonical compiler receipt"))?;
    receipt
        .validate_object(
            compiled.object().as_bytes(),
            fre_aot_elf::ObjectLimitsV1::default(),
        )
        .map_err(|_| source_error("compiler receipt/object"))?;
    let claims = SearchV26StaticBindingClaimsV1 {
        platform: SearchV26StaticPlatformV1::LinuxAarch64,
        output: expected_output,
        backend_version: receipt.metadata().backend_version(),
        literal_bytes: receipt.literal_bytes(),
        compile_identity: *receipt.compile_identity().as_bytes(),
        implementation_object_identity: *receipt.object_identity().as_bytes(),
        compiler_receipt_identity: *receipt.receipt_identity().as_bytes(),
    };
    let symbols =
        SearchV26StaticSymbolsV1::new(claims.platform, claims.output, &claims.compile_identity)?;
    if compiled.object().exported_symbols().entry().as_str() != symbols.entry.as_str() {
        return Err(source_error("identity-suffixed implementation entry"));
    }
    finish_binding(claims, &symbols)
}

fn finish_binding(
    claims: SearchV26StaticBindingClaimsV1,
    symbols: &SearchV26StaticSymbolsV1,
) -> Result<SearchV26StaticBindingV1, SearchV26StaticAbiErrorV1> {
    validate_claim_shape(claims)?;
    let glue_object = emit_glue_object(claims.platform, symbols)?.into_boxed_slice();
    let c_header = generate_header(claims, symbols)?.into_boxed_str();
    let glue_identity = SearchV26StaticGlueIdentityV1::new(artifact_identity(
        GLUE_IDENTITY_DOMAIN_V1,
        claims,
        &glue_object,
    ));
    let header_identity = SearchV26StaticHeaderIdentityV1::new(artifact_identity(
        HEADER_IDENTITY_DOMAIN_V1,
        claims,
        c_header.as_bytes(),
    ));
    let binding = SearchV26StaticBindingV1 {
        claims,
        symbols: *symbols,
        glue_object,
        c_header,
        glue_identity,
        header_identity,
    };
    binding.validate()?;
    Ok(binding)
}

fn validate_claim_shape(
    claims: SearchV26StaticBindingClaimsV1,
) -> Result<(), SearchV26StaticAbiErrorV1> {
    ensure_supported_output(claims.output)?;
    if claims.backend_version != SEARCH_BACKEND_ASIMD_TAG39_V1
        || !search_v26_production_literal_width_is_valid_v1(claims.literal_bytes)
        || claims.compile_identity == [0; 32]
        || claims.implementation_object_identity == [0; 32]
        || claims.compiler_receipt_identity == [0; 32]
    {
        return Err(source_error("sealed binding claims"));
    }
    Ok(())
}

fn generate_header(
    claims: SearchV26StaticBindingClaimsV1,
    symbols: &SearchV26StaticSymbolsV1,
) -> Result<String, SearchV26StaticAbiErrorV1> {
    let mut header = String::new();
    header
        .try_reserve_exact(4096)
        .map_err(|_| SearchV26StaticAbiErrorV1::AllocationFailed)?;
    let guard = format_guard(&claims.compile_identity, claims.output);
    writeln!(header, "#ifndef {guard}").map_err(|_| glue_error("C header guard"))?;
    writeln!(header, "#define {guard}").map_err(|_| glue_error("C header guard"))?;
    writeln!(header, "#include <stdint.h>").map_err(|_| glue_error("C header include"))?;
    writeln!(header, "#if defined(__cplusplus)\nextern \"C\" {{\n#endif")
        .map_err(|_| glue_error("C header C++ guard"))?;
    match claims.output {
        OutputKind::Exists => {
            writeln!(
                header,
                "/* Exists: status 1 publishes neither word; status 0 also leaves both words unchanged. */"
            )
            .map_err(|_| glue_error("Exists C header contract"))?;
            writeln!(
                header,
                "struct {} {{ uint64_t untouched_start; uint64_t untouched_end; }};",
                symbols.result_type
            )
            .map_err(|_| glue_error("Exists C result"))?;
        }
        OutputKind::SelectedEnd => {
            writeln!(
                header,
                "/* SelectedEnd: status 1 publishes only end; status 0 leaves both words unchanged. */"
            )
            .map_err(|_| glue_error("SelectedEnd C header contract"))?;
            writeln!(
                header,
                "struct {} {{ uint64_t untouched_start; uint64_t end; }};",
                symbols.result_type
            )
            .map_err(|_| glue_error("SelectedEnd C result"))?;
        }
        output @ OutputKind::Span => {
            return Err(SearchV26StaticAbiErrorV1::UnsupportedOutput { output });
        }
    }
    writeln!(
        header,
        "extern uint64_t {}(const uint8_t *haystack, uint64_t haystack_len, uint64_t window_start, uint64_t window_end, struct {} *result);",
        symbols.wrapper, symbols.result_type
    )
    .map_err(|_| glue_error("C wrapper declaration"))?;
    writeln!(header, "#if defined(__cplusplus)\n}}\n#endif")
        .map_err(|_| glue_error("C header C++ close"))?;
    writeln!(header, "#endif /* {guard} */").map_err(|_| glue_error("C header close"))?;
    Ok(header)
}

fn format_guard(identity: &[u8; 32], output: OutputKind) -> String {
    let mut guard = String::with_capacity(96);
    guard.push_str(match output {
        OutputKind::Exists => "FRE_AOT_SEARCH_V26_EXISTS_STATIC_V1_",
        OutputKind::SelectedEnd => "FRE_AOT_SEARCH_V26_SELECTED_END_STATIC_V1_",
        OutputKind::Span => "FRE_AOT_SEARCH_V26_UNSUPPORTED_STATIC_V1_",
    });
    for byte in identity {
        guard.push(char::from(upper_hex(byte >> 4)));
        guard.push(char::from(upper_hex(byte & 0x0f)));
    }
    guard.push_str("_H");
    guard
}

fn output_prefixes(
    output: OutputKind,
) -> Result<(&'static str, &'static str), SearchV26StaticAbiErrorV1> {
    match output {
        OutputKind::Exists => Ok((WRAPPER_EXISTS_PREFIX_V1, RESULT_EXISTS_PREFIX_V1)),
        OutputKind::SelectedEnd => Ok((
            WRAPPER_SELECTED_END_PREFIX_V1,
            RESULT_SELECTED_END_PREFIX_V1,
        )),
        output @ OutputKind::Span => Err(SearchV26StaticAbiErrorV1::UnsupportedOutput { output }),
    }
}

fn ensure_supported_output(output: OutputKind) -> Result<(), SearchV26StaticAbiErrorV1> {
    output_prefixes(output).map(|_| ())
}

fn emit_glue_object(
    platform: SearchV26StaticPlatformV1,
    symbols: &SearchV26StaticSymbolsV1,
) -> Result<Vec<u8>, SearchV26StaticAbiErrorV1> {
    match platform {
        SearchV26StaticPlatformV1::MacosAarch64 => emit_macho_glue(symbols),
        SearchV26StaticPlatformV1::LinuxAarch64 => emit_elf_glue(symbols),
    }
}

// ---- Minimal Mach-O writer -------------------------------------------------

const MACH_HEADER_BYTES: usize = 32;
const MACH_SEGMENT_COMMAND_BYTES: usize = 72;
const MACH_SECTION_BYTES: usize = 80;
const MACH_BUILD_VERSION_BYTES: usize = 24;
const MACH_SYMTAB_COMMAND_BYTES: usize = 24;
const MACH_DYSYMTAB_COMMAND_BYTES: usize = 80;
const MACH_LOAD_COMMAND_BYTES: usize = MACH_SEGMENT_COMMAND_BYTES
    + MACH_SECTION_BYTES
    + MACH_BUILD_VERSION_BYTES
    + MACH_SYMTAB_COMMAND_BYTES
    + MACH_DYSYMTAB_COMMAND_BYTES;
const MACH_CONTENT_OFFSET: usize = 320;
const MACH_RELOCATION_OFFSET: usize = MACH_CONTENT_OFFSET + SEARCH_V26_STATIC_GLUE_CODE_V1.len();
const MACH_SYMBOL_OFFSET: usize = MACH_RELOCATION_OFFSET + 8;
const MACH_STRING_OFFSET: usize = MACH_SYMBOL_OFFSET + (2 * 16);

#[allow(
    clippy::too_many_lines,
    reason = "one bounded writer keeps the complete tiny Mach-O layout auditable"
)]
fn emit_macho_glue(
    symbols: &SearchV26StaticSymbolsV1,
) -> Result<Vec<u8>, SearchV26StaticAbiErrorV1> {
    let wrapper_string_bytes = symbols
        .wrapper
        .as_bytes()
        .len()
        .checked_add(2)
        .ok_or_else(|| overflow("Mach-O wrapper string bytes"))?;
    let entry_string_bytes = symbols
        .entry
        .as_bytes()
        .len()
        .checked_add(2)
        .ok_or_else(|| overflow("Mach-O entry string bytes"))?;
    let string_bytes = align_up(
        4_usize
            .checked_add(wrapper_string_bytes)
            .and_then(|value| value.checked_add(entry_string_bytes))
            .ok_or_else(|| overflow("Mach-O string bytes"))?,
        4,
        "Mach-O string alignment",
    )?;
    let object_bytes = MACH_STRING_OFFSET
        .checked_add(string_bytes)
        .ok_or_else(|| overflow("Mach-O object bytes"))?;
    enforce_object_bound(object_bytes)?;
    let mut bytes = allocate_zeroed(object_bytes)?;
    {
        let mut writer = Writer::new(
            bytes
                .get_mut(..MACH_CONTENT_OFFSET)
                .ok_or_else(|| glue_error("Mach-O prefix"))?,
        );
        writer.u32(0xfeed_facf)?;
        writer.u32(0x0100_000c)?;
        writer.u32(0)?;
        writer.u32(1)?;
        writer.u32(4)?;
        writer.u32(to_u32(MACH_LOAD_COMMAND_BYTES, "Mach-O load commands")?)?;
        writer.u32(0)?;
        writer.u32(0)?;

        writer.u32(0x19)?;
        writer.u32(to_u32(
            MACH_SEGMENT_COMMAND_BYTES + MACH_SECTION_BYTES,
            "Mach-O segment command",
        )?)?;
        writer.fixed_name("")?;
        writer.u64(0)?;
        writer.u64(4)?;
        writer.u64(to_u64(MACH_CONTENT_OFFSET, "Mach-O content offset")?)?;
        writer.u64(4)?;
        writer.u32(7)?;
        writer.u32(7)?;
        writer.u32(1)?;
        writer.u32(0)?;
        writer.fixed_name("__text")?;
        writer.fixed_name("__TEXT")?;
        writer.u64(0)?;
        writer.u64(4)?;
        writer.u32(to_u32(MACH_CONTENT_OFFSET, "Mach-O text offset")?)?;
        writer.u32(2)?;
        writer.u32(to_u32(MACH_RELOCATION_OFFSET, "Mach-O relocation offset")?)?;
        writer.u32(1)?;
        writer.u32(0x8000_0400)?;
        writer.u32(0)?;
        writer.u32(0)?;
        writer.u32(0)?;

        writer.u32(0x32)?;
        writer.u32(to_u32(
            MACH_BUILD_VERSION_BYTES,
            "Mach-O build version command",
        )?)?;
        writer.u32(1)?;
        writer.u32(0x000b_0000)?;
        writer.u32(0)?;
        writer.u32(0)?;

        writer.u32(0x02)?;
        writer.u32(to_u32(MACH_SYMTAB_COMMAND_BYTES, "Mach-O symtab command")?)?;
        writer.u32(to_u32(MACH_SYMBOL_OFFSET, "Mach-O symbol offset")?)?;
        writer.u32(2)?;
        writer.u32(to_u32(MACH_STRING_OFFSET, "Mach-O string offset")?)?;
        writer.u32(to_u32(string_bytes, "Mach-O string bytes")?)?;

        writer.u32(0x0b)?;
        writer.u32(to_u32(
            MACH_DYSYMTAB_COMMAND_BYTES,
            "Mach-O dysymtab command",
        )?)?;
        for value in [0_u32, 0, 0, 1, 1, 1] {
            writer.u32(value)?;
        }
        for _ in 0..12 {
            writer.u32(0)?;
        }
        if writer.position() != MACH_HEADER_BYTES + MACH_LOAD_COMMAND_BYTES {
            return Err(glue_error("Mach-O load command width"));
        }
    }
    bytes[MACH_CONTENT_OFFSET..MACH_CONTENT_OFFSET + 4]
        .copy_from_slice(&SEARCH_V26_STATIC_GLUE_CODE_V1);
    {
        let mut writer = Writer::new(
            bytes
                .get_mut(MACH_RELOCATION_OFFSET..MACH_RELOCATION_OFFSET + 8)
                .ok_or_else(|| glue_error("Mach-O relocation"))?,
        );
        writer.i32(0)?;
        let relocation_word = 1_u32 | (1 << 24) | (2 << 25) | (1 << 27) | (2 << 28);
        writer.u32(relocation_word)?;
    }
    let wrapper_string_index = 4_u32;
    let entry_string_index = to_u32(
        4_usize
            .checked_add(wrapper_string_bytes)
            .ok_or_else(|| overflow("Mach-O entry string index"))?,
        "Mach-O entry string index",
    )?;
    {
        let mut writer = Writer::new(
            bytes
                .get_mut(MACH_SYMBOL_OFFSET..MACH_STRING_OFFSET)
                .ok_or_else(|| glue_error("Mach-O symbols"))?,
        );
        writer.u32(wrapper_string_index)?;
        writer.u8(0x1f)?;
        writer.u8(1)?;
        writer.u16(0)?;
        writer.u64(0)?;
        writer.u32(entry_string_index)?;
        writer.u8(0x01)?;
        writer.u8(0)?;
        writer.u16(0)?;
        writer.u64(0)?;
    }
    {
        let mut writer = Writer::new(
            bytes
                .get_mut(MACH_STRING_OFFSET..)
                .ok_or_else(|| glue_error("Mach-O strings"))?,
        );
        writer.u32(0)?;
        for name in [symbols.wrapper, symbols.entry] {
            writer.u8(b'_')?;
            writer.raw(name.as_bytes())?;
            writer.u8(0)?;
        }
    }
    Ok(bytes)
}

// ---- Minimal ELF writer ----------------------------------------------------

const ELF_HEADER_BYTES: usize = 64;
const ELF_RELA_OFFSET: usize = 72;
const ELF_STRING_OFFSET: usize = 96;
const ELF_SYMBOL_BYTES: usize = 24;
const ELF_SYMBOL_COUNT: usize = 4;
const ELF_SECTION_BYTES: usize = 64;
const ELF_SECTION_COUNT: usize = 7;

#[derive(Clone, Copy)]
struct ElfLayout {
    symbol_offset: usize,
    section_string_offset: usize,
    section_header_offset: usize,
    object_bytes: usize,
}

fn emit_elf_glue(symbols: &SearchV26StaticSymbolsV1) -> Result<Vec<u8>, SearchV26StaticAbiErrorV1> {
    let mut symbol_strings = Vec::new();
    symbol_strings
        .try_reserve_exact(512)
        .map_err(|_| SearchV26StaticAbiErrorV1::AllocationFailed)?;
    symbol_strings.push(0);
    let wrapper_name = push_string(&mut symbol_strings, symbols.wrapper.as_bytes())?;
    let entry_name = push_string(&mut symbol_strings, symbols.entry.as_bytes())?;

    let section_names = [
        b".text.fre_aot_search_v26_static".as_slice(),
        b".rela.text.fre_aot_search_v26_static".as_slice(),
        b".strtab".as_slice(),
        b".symtab".as_slice(),
        b".note.GNU-stack".as_slice(),
        b".shstrtab".as_slice(),
    ];
    let mut section_strings = Vec::new();
    section_strings
        .try_reserve_exact(256)
        .map_err(|_| SearchV26StaticAbiErrorV1::AllocationFailed)?;
    section_strings.push(0);
    let mut section_offsets = [0_u32; 6];
    for (slot, name) in section_offsets.iter_mut().zip(section_names) {
        *slot = push_string(&mut section_strings, name)?;
    }
    let layout = ElfLayout::new(symbol_strings.len(), section_strings.len())?;
    enforce_object_bound(layout.object_bytes)?;
    let mut bytes = allocate_zeroed(layout.object_bytes)?;
    write_elf_header(&mut bytes[..ELF_HEADER_BYTES], layout)?;
    bytes[ELF_HEADER_BYTES..ELF_HEADER_BYTES + 4].copy_from_slice(&SEARCH_V26_STATIC_GLUE_CODE_V1);
    {
        let mut writer = Writer::new(
            bytes
                .get_mut(ELF_RELA_OFFSET..ELF_RELA_OFFSET + 24)
                .ok_or_else(|| glue_error("ELF RELA"))?,
        );
        writer.u64(0)?;
        writer.u64((3_u64 << 32) | u64::from(SEARCH_V26_STATIC_ELF_RELOCATION_V1))?;
        writer.i64(0)?;
    }
    copy_region(
        &mut bytes,
        ELF_STRING_OFFSET,
        &symbol_strings,
        "ELF symbol strings",
    )?;
    write_elf_symbols(&mut bytes, layout, wrapper_name, entry_name)?;
    copy_region(
        &mut bytes,
        layout.section_string_offset,
        &section_strings,
        "ELF section strings",
    )?;
    write_elf_sections(
        &mut bytes,
        layout,
        symbol_strings.len(),
        section_strings.len(),
        section_offsets,
    )?;
    Ok(bytes)
}

impl ElfLayout {
    fn new(
        symbol_string_bytes: usize,
        section_string_bytes: usize,
    ) -> Result<Self, SearchV26StaticAbiErrorV1> {
        let symbol_offset = align_up(
            ELF_STRING_OFFSET
                .checked_add(symbol_string_bytes)
                .ok_or_else(|| overflow("ELF symbol offset"))?,
            8,
            "ELF symbol alignment",
        )?;
        let section_string_offset = symbol_offset
            .checked_add(ELF_SYMBOL_BYTES * ELF_SYMBOL_COUNT)
            .ok_or_else(|| overflow("ELF section string offset"))?;
        let section_header_offset = align_up(
            section_string_offset
                .checked_add(section_string_bytes)
                .ok_or_else(|| overflow("ELF section header offset"))?,
            8,
            "ELF section header alignment",
        )?;
        let object_bytes = section_header_offset
            .checked_add(ELF_SECTION_BYTES * ELF_SECTION_COUNT)
            .ok_or_else(|| overflow("ELF object bytes"))?;
        Ok(Self {
            symbol_offset,
            section_string_offset,
            section_header_offset,
            object_bytes,
        })
    }
}

fn write_elf_header(
    destination: &mut [u8],
    layout: ElfLayout,
) -> Result<(), SearchV26StaticAbiErrorV1> {
    let mut writer = Writer::new(destination);
    writer.raw(&[0x7f, b'E', b'L', b'F'])?;
    writer.raw(&[2, 1, 1, 0])?;
    writer.raw(&[0; 8])?;
    writer.u16(1)?;
    writer.u16(183)?;
    writer.u32(1)?;
    writer.u64(0)?;
    writer.u64(0)?;
    writer.u64(to_u64(
        layout.section_header_offset,
        "ELF section header offset",
    )?)?;
    writer.u32(0)?;
    writer.u16(u16::try_from(ELF_HEADER_BYTES).expect("fixed ELF header bytes"))?;
    writer.u16(0)?;
    writer.u16(0)?;
    writer.u16(u16::try_from(ELF_SECTION_BYTES).expect("fixed ELF section bytes"))?;
    writer.u16(u16::try_from(ELF_SECTION_COUNT).expect("fixed ELF section count"))?;
    writer.u16(6)?;
    if writer.position() != ELF_HEADER_BYTES {
        return Err(glue_error("ELF header width"));
    }
    Ok(())
}

fn write_elf_symbols(
    bytes: &mut [u8],
    layout: ElfLayout,
    wrapper_name: u32,
    entry_name: u32,
) -> Result<(), SearchV26StaticAbiErrorV1> {
    let end = layout
        .symbol_offset
        .checked_add(ELF_SYMBOL_BYTES * ELF_SYMBOL_COUNT)
        .ok_or_else(|| overflow("ELF symbol extent"))?;
    let mut writer = Writer::new(
        bytes
            .get_mut(layout.symbol_offset..end)
            .ok_or_else(|| glue_error("ELF symbols"))?,
    );
    write_elf_symbol(&mut writer, 0, 0, 0, 0, 0, 0)?;
    write_elf_symbol(&mut writer, 0, 0x03, 0, 1, 0, 0)?;
    write_elf_symbol(&mut writer, wrapper_name, 0x12, 2, 1, 0, 4)?;
    write_elf_symbol(&mut writer, entry_name, 0x12, 2, 0, 0, 0)?;
    Ok(())
}

fn write_elf_symbol(
    writer: &mut Writer<'_>,
    name: u32,
    info: u8,
    other: u8,
    section: u16,
    value: u64,
    bytes: u64,
) -> Result<(), SearchV26StaticAbiErrorV1> {
    writer.u32(name)?;
    writer.u8(info)?;
    writer.u8(other)?;
    writer.u16(section)?;
    writer.u64(value)?;
    writer.u64(bytes)
}

#[allow(
    clippy::too_many_arguments,
    reason = "arguments mirror one fixed ELF64 section header"
)]
fn write_elf_section(
    writer: &mut Writer<'_>,
    name: u32,
    kind: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_bytes: u64,
) -> Result<(), SearchV26StaticAbiErrorV1> {
    writer.u32(name)?;
    writer.u32(kind)?;
    writer.u64(flags)?;
    writer.u64(0)?;
    writer.u64(offset)?;
    writer.u64(size)?;
    writer.u32(link)?;
    writer.u32(info)?;
    writer.u64(alignment)?;
    writer.u64(entry_bytes)
}

fn write_elf_sections(
    bytes: &mut [u8],
    layout: ElfLayout,
    symbol_string_bytes: usize,
    section_string_bytes: usize,
    names: [u32; 6],
) -> Result<(), SearchV26StaticAbiErrorV1> {
    let mut writer = Writer::new(
        bytes
            .get_mut(layout.section_header_offset..)
            .ok_or_else(|| glue_error("ELF section headers"))?,
    );
    write_elf_section(&mut writer, 0, 0, 0, 0, 0, 0, 0, 0, 0)?;
    write_elf_section(
        &mut writer,
        names[0],
        1,
        6,
        to_u64(ELF_HEADER_BYTES, "ELF text offset")?,
        4,
        0,
        0,
        4,
        0,
    )?;
    write_elf_section(
        &mut writer,
        names[1],
        4,
        0,
        to_u64(ELF_RELA_OFFSET, "ELF RELA offset")?,
        24,
        4,
        1,
        8,
        24,
    )?;
    write_elf_section(
        &mut writer,
        names[2],
        3,
        0,
        to_u64(ELF_STRING_OFFSET, "ELF string offset")?,
        to_u64(symbol_string_bytes, "ELF symbol string bytes")?,
        0,
        0,
        1,
        0,
    )?;
    write_elf_section(
        &mut writer,
        names[3],
        2,
        0,
        to_u64(layout.symbol_offset, "ELF symbol offset")?,
        to_u64(
            ELF_SYMBOL_BYTES
                .checked_mul(ELF_SYMBOL_COUNT)
                .ok_or_else(|| overflow("ELF symbol table bytes"))?,
            "ELF symbol table bytes",
        )?,
        3,
        2,
        8,
        to_u64(ELF_SYMBOL_BYTES, "ELF symbol entry bytes")?,
    )?;
    write_elf_section(&mut writer, names[4], 1, 0, 0, 0, 0, 0, 1, 0)?;
    write_elf_section(
        &mut writer,
        names[5],
        3,
        0,
        to_u64(layout.section_string_offset, "ELF section string offset")?,
        to_u64(section_string_bytes, "ELF section string bytes")?,
        0,
        0,
        1,
        0,
    )?;
    if writer.position() != ELF_SECTION_BYTES * ELF_SECTION_COUNT {
        return Err(glue_error("ELF section header width"));
    }
    Ok(())
}

// ---- Shared helpers --------------------------------------------------------

fn artifact_identity(
    domain: &[u8],
    claims: SearchV26StaticBindingClaimsV1,
    bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([claims.platform.tag(), output_tag(claims.output)]);
    hasher.update(claims.backend_version.to_le_bytes());
    hasher.update(claims.literal_bytes.to_le_bytes());
    hasher.update(claims.compile_identity);
    hasher.update(claims.implementation_object_identity);
    hasher.update(claims.compiler_receipt_identity);
    hasher.update(
        u64::try_from(bytes.len())
            .expect("bounded static artifact length")
            .to_le_bytes(),
    );
    hasher.update(bytes);
    hasher.finalize().into()
}

const fn output_tag(output: OutputKind) -> u8 {
    match output {
        OutputKind::Exists => 1,
        OutputKind::SelectedEnd => 2,
        OutputKind::Span => 3,
    }
}

fn allocate_zeroed(bytes: usize) -> Result<Vec<u8>, SearchV26StaticAbiErrorV1> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(bytes)
        .map_err(|_| SearchV26StaticAbiErrorV1::AllocationFailed)?;
    output.resize(bytes, 0);
    Ok(output)
}

fn enforce_object_bound(bytes: usize) -> Result<(), SearchV26StaticAbiErrorV1> {
    if bytes <= HARD_MAX_SEARCH_V26_STATIC_GLUE_OBJECT_BYTES_V1 {
        Ok(())
    } else {
        Err(glue_error("hard glue object bound"))
    }
}

fn push_string(destination: &mut Vec<u8>, value: &[u8]) -> Result<u32, SearchV26StaticAbiErrorV1> {
    if value.contains(&0) {
        return Err(glue_error("embedded string NUL"));
    }
    let offset = to_u32(destination.len(), "string offset")?;
    destination.extend_from_slice(value);
    destination.push(0);
    Ok(offset)
}

fn copy_region(
    destination: &mut [u8],
    offset: usize,
    source: &[u8],
    at: &'static str,
) -> Result<(), SearchV26StaticAbiErrorV1> {
    let end = offset
        .checked_add(source.len())
        .ok_or_else(|| overflow(at))?;
    destination
        .get_mut(offset..end)
        .ok_or_else(|| glue_error(at))?
        .copy_from_slice(source);
    Ok(())
}

fn align_up(
    value: usize,
    alignment: usize,
    at: &'static str,
) -> Result<usize, SearchV26StaticAbiErrorV1> {
    let mask = alignment.checked_sub(1).ok_or_else(|| overflow(at))?;
    if alignment == 0 || alignment & mask != 0 {
        return Err(glue_error(at));
    }
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or_else(|| overflow(at))
}

fn to_u32(value: usize, at: &'static str) -> Result<u32, SearchV26StaticAbiErrorV1> {
    u32::try_from(value).map_err(|_| overflow(at))
}

fn to_u64(value: usize, at: &'static str) -> Result<u64, SearchV26StaticAbiErrorV1> {
    u64::try_from(value).map_err(|_| overflow(at))
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

const fn upper_hex(nibble: u8) -> u8 {
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
        10 => b'A',
        11 => b'B',
        12 => b'C',
        13 => b'D',
        14 => b'E',
        15 => b'F',
        _ => b'?',
    }
}

const fn glue_error(at: &'static str) -> SearchV26StaticAbiErrorV1 {
    SearchV26StaticAbiErrorV1::InvalidGlue { at }
}

const fn source_error(at: &'static str) -> SearchV26StaticAbiErrorV1 {
    SearchV26StaticAbiErrorV1::SourceBinding { at }
}

const fn overflow(at: &'static str) -> SearchV26StaticAbiErrorV1 {
    SearchV26StaticAbiErrorV1::ArithmeticOverflow { at }
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

    fn raw(&mut self, value: &[u8]) -> Result<(), SearchV26StaticAbiErrorV1> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or_else(|| overflow("writer cursor"))?;
        self.bytes
            .get_mut(self.position..end)
            .ok_or_else(|| glue_error("writer extent"))?
            .copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), SearchV26StaticAbiErrorV1> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), SearchV26StaticAbiErrorV1> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), SearchV26StaticAbiErrorV1> {
        self.raw(&value.to_le_bytes())
    }

    fn i32(&mut self, value: i32) -> Result<(), SearchV26StaticAbiErrorV1> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), SearchV26StaticAbiErrorV1> {
        self.raw(&value.to_le_bytes())
    }

    fn i64(&mut self, value: i64) -> Result<(), SearchV26StaticAbiErrorV1> {
        self.raw(&value.to_le_bytes())
    }

    fn fixed_name(&mut self, value: &str) -> Result<(), SearchV26StaticAbiErrorV1> {
        if value.len() > 16 {
            return Err(glue_error("Mach-O fixed name"));
        }
        self.raw(value.as_bytes())?;
        self.raw(&[0; 16][value.len()..])
    }
}

#[cfg(test)]
mod tests {
    use fre::RustProfile;

    use super::*;
    use crate::{
        LinuxAarch64SearchCompilePolicyV1, SearchCompilePolicyV1,
        build_linux_aarch64_search_v26_exists_object_v1,
        build_linux_aarch64_search_v26_selected_end_object_v1,
        build_macos_aarch64_search_v26_exists_object_v1,
        build_macos_aarch64_search_v26_selected_end_object_v1,
    };

    const FIRST: &[u8] = b"abcdefghi";
    const SECOND: &[u8] = b"abcdefghj";

    #[test]
    fn both_formats_and_outputs_are_deterministic_direct_and_inert() {
        let mac_exists = build_macos_aarch64_search_v26_exists_object_v1(
            FIRST.to_vec(),
            RustProfile::default(),
            SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let mac_end = build_macos_aarch64_search_v26_selected_end_object_v1(
            FIRST.to_vec(),
            RustProfile::default(),
            SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let linux_exists = build_linux_aarch64_search_v26_exists_object_v1(
            FIRST.to_vec(),
            RustProfile::default(),
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let linux_end = build_linux_aarch64_search_v26_selected_end_object_v1(
            FIRST.to_vec(),
            RustProfile::default(),
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let bindings = [
            build_macos_aarch64_search_v26_exists_static_binding_v1(&mac_exists).unwrap(),
            build_macos_aarch64_search_v26_selected_end_static_binding_v1(&mac_end).unwrap(),
            build_linux_aarch64_search_v26_exists_static_binding_v1(&linux_exists).unwrap(),
            build_linux_aarch64_search_v26_selected_end_static_binding_v1(&linux_end).unwrap(),
        ];
        for binding in &bindings {
            binding.validate().unwrap();
            assert_eq!(
                binding.runtime_authority(),
                SearchAotRuntimeAuthorityV1::Absent
            );
            assert_eq!(
                binding.claims().runtime_authority(),
                SearchAotRuntimeAuthorityV1::Absent
            );
            assert!(binding.glue_object().len() < 2048);
            assert!(!binding.c_header().contains("fre_aot_search_result_v1"));
            assert!(!binding.c_header().contains("Span"));
            let inspection = inspect_search_v26_static_glue_v1(
                binding.claims().platform(),
                binding.claims().output(),
                binding.glue_object(),
                binding.claims(),
            )
            .unwrap();
            assert_eq!(
                inspection.runtime_authority(),
                SearchAotRuntimeAuthorityV1::Absent
            );
        }
        assert!(bindings[0].c_header().contains("publishes neither word"));
        assert!(bindings[1].c_header().contains("publishes only end"));
        assert_eq!(
            &bindings[0].glue_object()[MACH_CONTENT_OFFSET..MACH_CONTENT_OFFSET + 4],
            SEARCH_V26_STATIC_GLUE_CODE_V1.as_slice()
        );
        let macho_relocation = u32::from_le_bytes(
            bindings[0].glue_object()[MACH_RELOCATION_OFFSET + 4..MACH_RELOCATION_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(macho_relocation & 0x00ff_ffff, 1);
        assert_eq!(
            macho_relocation >> 28,
            SEARCH_V26_STATIC_MACHO_RELOCATION_V1
        );
        assert_eq!(bindings[0].glue_object()[MACH_SYMBOL_OFFSET + 4], 0x1f);
        assert_eq!(
            &bindings[2].glue_object()[ELF_HEADER_BYTES..ELF_HEADER_BYTES + 4],
            SEARCH_V26_STATIC_GLUE_CODE_V1.as_slice()
        );
        let elf_relocation = u64::from_le_bytes(
            bindings[2].glue_object()[ELF_RELA_OFFSET + 8..ELF_RELA_OFFSET + 16]
                .try_into()
                .unwrap(),
        );
        assert_eq!(elf_relocation >> 32, 3);
        assert_eq!(
            u32::try_from(elf_relocation & u64::from(u32::MAX)).unwrap(),
            SEARCH_V26_STATIC_ELF_RELOCATION_V1
        );
        let symbol_strings = 1
            + bindings[2].symbols().wrapper().as_bytes().len()
            + 1
            + bindings[2].symbols().entry().as_bytes().len()
            + 1;
        let elf_layout = ElfLayout::new(symbol_strings, 117).unwrap();
        assert_eq!(
            bindings[2].glue_object()[elf_layout.symbol_offset + (2 * ELF_SYMBOL_BYTES) + 5],
            2
        );
        assert_eq!(
            bindings[2].glue_object()[elf_layout.symbol_offset + (3 * ELF_SYMBOL_BYTES) + 5],
            2
        );
        for binding in &bindings {
            assert!(
                !binding
                    .glue_object()
                    .windows(b"adopt".len())
                    .any(|window| window == b"adopt")
            );
        }
    }

    #[test]
    fn wrong_output_and_identity_are_refused_for_both_formats() {
        let mac_first = build_macos_aarch64_search_v26_exists_object_v1(
            FIRST.to_vec(),
            RustProfile::default(),
            SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let mac_second = build_macos_aarch64_search_v26_exists_object_v1(
            SECOND.to_vec(),
            RustProfile::default(),
            SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let linux_first = build_linux_aarch64_search_v26_exists_object_v1(
            FIRST.to_vec(),
            RustProfile::default(),
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let linux_second = build_linux_aarch64_search_v26_exists_object_v1(
            SECOND.to_vec(),
            RustProfile::default(),
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let mac_binding =
            build_macos_aarch64_search_v26_exists_static_binding_v1(&mac_first).unwrap();
        let mac_other =
            build_macos_aarch64_search_v26_exists_static_binding_v1(&mac_second).unwrap();
        let linux_binding =
            build_linux_aarch64_search_v26_exists_static_binding_v1(&linux_first).unwrap();
        let linux_other =
            build_linux_aarch64_search_v26_exists_static_binding_v1(&linux_second).unwrap();

        assert!(matches!(
            inspect_search_v26_static_glue_v1(
                SearchV26StaticPlatformV1::MacosAarch64,
                OutputKind::SelectedEnd,
                mac_binding.glue_object(),
                mac_binding.claims(),
            ),
            Err(SearchV26StaticAbiErrorV1::WrongOutput { .. })
        ));
        assert!(matches!(
            inspect_search_v26_static_glue_v1(
                SearchV26StaticPlatformV1::LinuxAarch64,
                OutputKind::SelectedEnd,
                linux_binding.glue_object(),
                linux_binding.claims(),
            ),
            Err(SearchV26StaticAbiErrorV1::WrongOutput { .. })
        ));
        assert!(
            inspect_search_v26_static_glue_v1(
                SearchV26StaticPlatformV1::MacosAarch64,
                OutputKind::Exists,
                mac_binding.glue_object(),
                mac_other.claims(),
            )
            .is_err()
        );
        assert!(
            inspect_search_v26_static_glue_v1(
                SearchV26StaticPlatformV1::LinuxAarch64,
                OutputKind::Exists,
                linux_binding.glue_object(),
                linux_other.claims(),
            )
            .is_err()
        );
    }

    #[test]
    fn every_glue_byte_mutation_is_refused() {
        let compiled = build_linux_aarch64_search_v26_selected_end_object_v1(
            FIRST.to_vec(),
            RustProfile::default(),
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let binding =
            build_linux_aarch64_search_v26_selected_end_static_binding_v1(&compiled).unwrap();
        for offset in 0..binding.glue_object().len() {
            let mut changed = binding.glue_object().to_vec();
            changed[offset] ^= 1;
            assert!(
                inspect_search_v26_static_glue_v1(
                    SearchV26StaticPlatformV1::LinuxAarch64,
                    OutputKind::SelectedEnd,
                    &changed,
                    binding.claims(),
                )
                .is_err(),
                "accepted byte mutation at {offset}"
            );
        }
    }
}
