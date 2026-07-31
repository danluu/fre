//! Explicit static-link ABI bindings for inert V27/tag40 Search objects.
//!
//! V27 admits every nonempty exact-literal topology from 1 through 32 bytes.
//! This module gives [`Exists`] and [`SelectedEnd`] distinct declarations and
//! emits the same audited one-instruction direct tail-branch shape as V26,
//! under disjoint V27 symbols, section names, identities, and public types.
//!
//! The binding remains manual and authority-free. It contains no expectation,
//! adopter, qualification selector, table row, function pointer, or runtime
//! authorization.

use core::{fmt, fmt::Write as _};

use fre_aot_search_contract::{
    SEARCH_BACKEND_ASIMD_TAG40_MAX_LITERAL_BYTES_V1,
    SEARCH_BACKEND_ASIMD_TAG40_MIN_LITERAL_BYTES_V1, SEARCH_BACKEND_ASIMD_TAG40_V1,
};
use fre_kernel_ir::{Exists, Operation, OutputKind, SelectedEnd};
use sha2::{Digest, Sha256};

use crate::{
    LinuxAarch64SearchBackendV1, LinuxSearchCompiledObjectV1, SearchAotRuntimeAuthorityV1,
    SearchCompiledObjectV1,
    search_v26_static_abi::{
        SearchStaticDirectObjectPlatformV1, SearchStaticDirectObjectVersionV1,
        emit_search_static_direct_object_v1,
    },
};

/// Exact `AArch64` direct tail-branch instruction bytes.
pub const SEARCH_V27_STATIC_GLUE_CODE_V1: [u8; 4] = [0x00, 0x00, 0x00, 0x14];
/// Every binding object contains exactly one external relocation.
pub const SEARCH_V27_STATIC_GLUE_RELOCATIONS_V1: usize = 1;
/// Mach-O `ARM64_RELOC_BRANCH26`.
pub const SEARCH_V27_STATIC_MACHO_RELOCATION_V1: u32 = 2;
/// ELF `R_AARCH64_JUMP26`.
pub const SEARCH_V27_STATIC_ELF_RELOCATION_V1: u32 = 282;
/// Hard bound for one tiny direct-binding object.
pub const HARD_MAX_SEARCH_V27_STATIC_GLUE_OBJECT_BYTES_V1: usize = 64 << 10;

const GLUE_IDENTITY_DOMAIN_V1: &[u8] = b"FRE-AOT-SEARCH-V27-STATIC-GLUE\0\x01";
const HEADER_IDENTITY_DOMAIN_V1: &[u8] = b"FRE-AOT-SEARCH-V27-STATIC-HEADER\0\x01";
const SYMBOL_STORAGE_BYTES_V1: usize = 160;
const WRAPPER_EXISTS_PREFIX_V1: &str = "fre_aot_search_v27_exists_static_v1_";
const WRAPPER_SELECTED_END_PREFIX_V1: &str = "fre_aot_search_v27_selected_end_static_v1_";
const RESULT_EXISTS_PREFIX_V1: &str = "fre_aot_search_v27_exists_result_v1_";
const RESULT_SELECTED_END_PREFIX_V1: &str = "fre_aot_search_v27_selected_end_result_v1_";

/// Object format selected by one explicit V27 static binding.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SearchV27StaticPlatformV1 {
    MacosAarch64,
    LinuxAarch64,
}

impl SearchV27StaticPlatformV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::MacosAarch64 => 1,
            Self::LinuxAarch64 => 2,
        }
    }

    const fn direct(self) -> SearchStaticDirectObjectPlatformV1 {
        match self {
            Self::MacosAarch64 => SearchStaticDirectObjectPlatformV1::MacosAarch64,
            Self::LinuxAarch64 => SearchStaticDirectObjectPlatformV1::LinuxAarch64,
        }
    }
}

/// Failure while authenticating or emitting a V27 output-specific static bind.
#[derive(Debug)]
#[non_exhaustive]
pub enum SearchV27StaticAbiErrorV1 {
    UnsupportedOutput {
        output: OutputKind,
    },
    WrongOutput {
        expected: OutputKind,
        actual: OutputKind,
    },
    WrongPlatform {
        expected: SearchV27StaticPlatformV1,
        actual: SearchV27StaticPlatformV1,
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

impl fmt::Display for SearchV27StaticAbiErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE V27 output-specific static ABI binding failed: {self:?}"
        )
    }
}

impl std::error::Error for SearchV27StaticAbiErrorV1 {}

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
    SearchV27StaticGlueIdentityV1,
    "SearchV27StaticGlueIdentityV1"
);
identity!(
    SearchV27StaticHeaderIdentityV1,
    "SearchV27StaticHeaderIdentityV1"
);

/// One allocation-free identity-derived C or linker name.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SearchV27StaticSymbolNameV1 {
    bytes: [u8; SYMBOL_STORAGE_BYTES_V1],
    len: usize,
}

impl SearchV27StaticSymbolNameV1 {
    fn suffixed(prefix: &str, identity: &[u8; 32]) -> Result<Self, SearchV27StaticAbiErrorV1> {
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
        core::str::from_utf8(self.as_bytes()).expect("canonical ASCII V27 static-binding symbol")
    }
}

impl fmt::Debug for SearchV27StaticSymbolNameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SearchV27StaticSymbolNameV1")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for SearchV27StaticSymbolNameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Exact wrapper, implementation entry, and result type for one V27 binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchV27StaticSymbolsV1 {
    wrapper: SearchV27StaticSymbolNameV1,
    entry: SearchV27StaticSymbolNameV1,
    result_type: SearchV27StaticSymbolNameV1,
}

impl SearchV27StaticSymbolsV1 {
    fn new(
        platform: SearchV27StaticPlatformV1,
        output: OutputKind,
        compile_identity: &[u8; 32],
    ) -> Result<Self, SearchV27StaticAbiErrorV1> {
        let (wrapper_prefix, result_prefix) = output_prefixes(output)?;
        let entry_prefix = match platform {
            SearchV27StaticPlatformV1::MacosAarch64 => fre_aot_macho::SEARCH_ENTRY_SYMBOL_PREFIX_V1,
            SearchV27StaticPlatformV1::LinuxAarch64 => fre_aot_elf::SEARCH_ENTRY_SYMBOL_PREFIX_V1,
        };
        Ok(Self {
            wrapper: SearchV27StaticSymbolNameV1::suffixed(wrapper_prefix, compile_identity)?,
            entry: SearchV27StaticSymbolNameV1::suffixed(entry_prefix, compile_identity)?,
            result_type: SearchV27StaticSymbolNameV1::suffixed(result_prefix, compile_identity)?,
        })
    }

    #[must_use]
    pub const fn wrapper(&self) -> &SearchV27StaticSymbolNameV1 {
        &self.wrapper
    }

    #[must_use]
    pub const fn entry(&self) -> &SearchV27StaticSymbolNameV1 {
        &self.entry
    }

    #[must_use]
    pub const fn result_type(&self) -> &SearchV27StaticSymbolNameV1 {
        &self.result_type
    }
}

/// Compiler-sealed claims copied into one manual V27 static binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchV27StaticBindingClaimsV1 {
    platform: SearchV27StaticPlatformV1,
    output: OutputKind,
    backend_version: u16,
    literal_bytes: u32,
    compile_identity: [u8; 32],
    implementation_object_identity: [u8; 32],
    compiler_receipt_identity: [u8; 32],
}

impl SearchV27StaticBindingClaimsV1 {
    #[must_use]
    pub const fn platform(&self) -> SearchV27StaticPlatformV1 {
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

/// Deterministic manual static-link artifacts for one V27/tag40 object.
#[derive(Debug, Eq, PartialEq)]
pub struct SearchV27StaticBindingV1 {
    claims: SearchV27StaticBindingClaimsV1,
    symbols: SearchV27StaticSymbolsV1,
    glue_object: Box<[u8]>,
    c_header: Box<str>,
    glue_identity: SearchV27StaticGlueIdentityV1,
    header_identity: SearchV27StaticHeaderIdentityV1,
}

impl SearchV27StaticBindingV1 {
    #[must_use]
    pub const fn claims(&self) -> SearchV27StaticBindingClaimsV1 {
        self.claims
    }

    #[must_use]
    pub const fn symbols(&self) -> SearchV27StaticSymbolsV1 {
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
    pub const fn glue_identity(&self) -> SearchV27StaticGlueIdentityV1 {
        self.glue_identity
    }

    #[must_use]
    pub const fn header_identity(&self) -> SearchV27StaticHeaderIdentityV1 {
        self.header_identity
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }

    /// Re-emit and compare every retained public artifact.
    pub fn validate(&self) -> Result<(), SearchV27StaticAbiErrorV1> {
        inspect_search_v27_static_glue_v1(
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

/// Strict whole-object inspection of a V27 direct glue object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchV27StaticGlueInspectionV1<'a> {
    bytes: &'a [u8],
    claims: SearchV27StaticBindingClaimsV1,
    symbols: SearchV27StaticSymbolsV1,
}

impl<'a> SearchV27StaticGlueInspectionV1<'a> {
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub const fn claims(&self) -> SearchV27StaticBindingClaimsV1 {
        self.claims
    }

    #[must_use]
    pub const fn symbols(&self) -> SearchV27StaticSymbolsV1 {
        self.symbols
    }

    #[must_use]
    pub const fn relocation_kind(&self) -> u32 {
        match self.claims.platform {
            SearchV27StaticPlatformV1::MacosAarch64 => SEARCH_V27_STATIC_MACHO_RELOCATION_V1,
            SearchV27StaticPlatformV1::LinuxAarch64 => SEARCH_V27_STATIC_ELF_RELOCATION_V1,
        }
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }
}

/// Build one manual Mach-O binding for a typed tag40 `Exists` object.
pub fn build_macos_aarch64_search_v27_exists_static_binding_v1(
    compiled: &SearchCompiledObjectV1<Exists>,
) -> Result<SearchV27StaticBindingV1, SearchV27StaticAbiErrorV1> {
    build_macos_binding(compiled, OutputKind::Exists)
}

/// Build one manual Mach-O binding for a typed tag40 `SelectedEnd` object.
pub fn build_macos_aarch64_search_v27_selected_end_static_binding_v1(
    compiled: &SearchCompiledObjectV1<SelectedEnd>,
) -> Result<SearchV27StaticBindingV1, SearchV27StaticAbiErrorV1> {
    build_macos_binding(compiled, OutputKind::SelectedEnd)
}

/// Build one manual ELF binding for a typed tag40 `Exists` object.
pub fn build_linux_aarch64_search_v27_exists_static_binding_v1(
    compiled: &LinuxSearchCompiledObjectV1<Exists>,
) -> Result<SearchV27StaticBindingV1, SearchV27StaticAbiErrorV1> {
    build_linux_binding(compiled, OutputKind::Exists)
}

/// Build one manual ELF binding for a typed tag40 `SelectedEnd` object.
pub fn build_linux_aarch64_search_v27_selected_end_static_binding_v1(
    compiled: &LinuxSearchCompiledObjectV1<SelectedEnd>,
) -> Result<SearchV27StaticBindingV1, SearchV27StaticAbiErrorV1> {
    build_linux_binding(compiled, OutputKind::SelectedEnd)
}

/// Strictly inspect a direct V27 glue object against exact platform, output,
/// and compiler-sealed identity claims.
pub fn inspect_search_v27_static_glue_v1(
    platform: SearchV27StaticPlatformV1,
    expected_output: OutputKind,
    bytes: &[u8],
    claims: SearchV27StaticBindingClaimsV1,
) -> Result<SearchV27StaticGlueInspectionV1<'_>, SearchV27StaticAbiErrorV1> {
    ensure_supported_output(expected_output)?;
    if claims.platform != platform {
        return Err(SearchV27StaticAbiErrorV1::WrongPlatform {
            expected: platform,
            actual: claims.platform,
        });
    }
    if claims.output != expected_output {
        return Err(SearchV27StaticAbiErrorV1::WrongOutput {
            expected: expected_output,
            actual: claims.output,
        });
    }
    validate_claim_shape(claims)?;
    let symbols =
        SearchV27StaticSymbolsV1::new(claims.platform, claims.output, &claims.compile_identity)?;
    let expected = emit_glue_object(claims.platform, &symbols)?;
    if expected.as_slice() != bytes {
        return Err(glue_error("canonical direct glue object"));
    }
    Ok(SearchV27StaticGlueInspectionV1 {
        bytes,
        claims,
        symbols,
    })
}

fn build_macos_binding<O: Operation>(
    compiled: &SearchCompiledObjectV1<O>,
    expected_output: OutputKind,
) -> Result<SearchV27StaticBindingV1, SearchV27StaticAbiErrorV1> {
    if O::KIND != expected_output || compiled.receipt().output() != expected_output {
        return Err(SearchV27StaticAbiErrorV1::WrongOutput {
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
    if receipt.metadata().backend_version() != SEARCH_BACKEND_ASIMD_TAG40_V1
        || !width_is_valid(receipt.literal_bytes())
    {
        return Err(source_error("V27 backend/literal envelope"));
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
    let claims = SearchV27StaticBindingClaimsV1 {
        platform: SearchV27StaticPlatformV1::MacosAarch64,
        output: expected_output,
        backend_version: receipt.metadata().backend_version(),
        literal_bytes: receipt.literal_bytes(),
        compile_identity: *receipt.compile_identity().as_bytes(),
        implementation_object_identity: *receipt.object_identity().as_bytes(),
        compiler_receipt_identity: *receipt.receipt_identity().as_bytes(),
    };
    let symbols =
        SearchV27StaticSymbolsV1::new(claims.platform, claims.output, &claims.compile_identity)?;
    if compiled.object().exported_symbols().entry().as_str() != symbols.entry.as_str() {
        return Err(source_error("identity-suffixed implementation entry"));
    }
    finish_binding(claims, &symbols)
}

fn build_linux_binding<O: Operation>(
    compiled: &LinuxSearchCompiledObjectV1<O>,
    expected_output: OutputKind,
) -> Result<SearchV27StaticBindingV1, SearchV27StaticAbiErrorV1> {
    if O::KIND != expected_output || compiled.receipt().output() != expected_output {
        return Err(SearchV27StaticAbiErrorV1::WrongOutput {
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
    if receipt.backend() != LinuxAarch64SearchBackendV1::AsimdV27
        || receipt.metadata().backend_version() != SEARCH_BACKEND_ASIMD_TAG40_V1
        || !width_is_valid(receipt.literal_bytes())
    {
        return Err(source_error("V27 backend/literal envelope"));
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
    let claims = SearchV27StaticBindingClaimsV1 {
        platform: SearchV27StaticPlatformV1::LinuxAarch64,
        output: expected_output,
        backend_version: receipt.metadata().backend_version(),
        literal_bytes: receipt.literal_bytes(),
        compile_identity: *receipt.compile_identity().as_bytes(),
        implementation_object_identity: *receipt.object_identity().as_bytes(),
        compiler_receipt_identity: *receipt.receipt_identity().as_bytes(),
    };
    let symbols =
        SearchV27StaticSymbolsV1::new(claims.platform, claims.output, &claims.compile_identity)?;
    if compiled.object().exported_symbols().entry().as_str() != symbols.entry.as_str() {
        return Err(source_error("identity-suffixed implementation entry"));
    }
    finish_binding(claims, &symbols)
}

fn finish_binding(
    claims: SearchV27StaticBindingClaimsV1,
    symbols: &SearchV27StaticSymbolsV1,
) -> Result<SearchV27StaticBindingV1, SearchV27StaticAbiErrorV1> {
    validate_claim_shape(claims)?;
    let glue_object = emit_glue_object(claims.platform, symbols)?.into_boxed_slice();
    let c_header = generate_header(claims, symbols)?.into_boxed_str();
    let glue_identity = SearchV27StaticGlueIdentityV1::new(artifact_identity(
        GLUE_IDENTITY_DOMAIN_V1,
        claims,
        &glue_object,
    ));
    let header_identity = SearchV27StaticHeaderIdentityV1::new(artifact_identity(
        HEADER_IDENTITY_DOMAIN_V1,
        claims,
        c_header.as_bytes(),
    ));
    let binding = SearchV27StaticBindingV1 {
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
    claims: SearchV27StaticBindingClaimsV1,
) -> Result<(), SearchV27StaticAbiErrorV1> {
    ensure_supported_output(claims.output)?;
    if claims.backend_version != SEARCH_BACKEND_ASIMD_TAG40_V1
        || !width_is_valid(claims.literal_bytes)
        || claims.compile_identity == [0; 32]
        || claims.implementation_object_identity == [0; 32]
        || claims.compiler_receipt_identity == [0; 32]
    {
        return Err(source_error("sealed binding claims"));
    }
    Ok(())
}

fn generate_header(
    claims: SearchV27StaticBindingClaimsV1,
    symbols: &SearchV27StaticSymbolsV1,
) -> Result<String, SearchV27StaticAbiErrorV1> {
    let mut header = String::new();
    header
        .try_reserve_exact(4096)
        .map_err(|_| SearchV27StaticAbiErrorV1::AllocationFailed)?;
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
                "/* V27 Exists: status 1 publishes neither word; status 0 also leaves both words unchanged. */"
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
                "/* V27 SelectedEnd: status 1 publishes only end; status 0 leaves both words unchanged. */"
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
            return Err(SearchV27StaticAbiErrorV1::UnsupportedOutput { output });
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
        OutputKind::Exists => "FRE_AOT_SEARCH_V27_EXISTS_STATIC_V1_",
        OutputKind::SelectedEnd => "FRE_AOT_SEARCH_V27_SELECTED_END_STATIC_V1_",
        OutputKind::Span => "FRE_AOT_SEARCH_V27_UNSUPPORTED_STATIC_V1_",
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
) -> Result<(&'static str, &'static str), SearchV27StaticAbiErrorV1> {
    match output {
        OutputKind::Exists => Ok((WRAPPER_EXISTS_PREFIX_V1, RESULT_EXISTS_PREFIX_V1)),
        OutputKind::SelectedEnd => Ok((
            WRAPPER_SELECTED_END_PREFIX_V1,
            RESULT_SELECTED_END_PREFIX_V1,
        )),
        output @ OutputKind::Span => Err(SearchV27StaticAbiErrorV1::UnsupportedOutput { output }),
    }
}

fn ensure_supported_output(output: OutputKind) -> Result<(), SearchV27StaticAbiErrorV1> {
    output_prefixes(output).map(|_| ())
}

fn width_is_valid(bytes: u32) -> bool {
    (SEARCH_BACKEND_ASIMD_TAG40_MIN_LITERAL_BYTES_V1
        ..=SEARCH_BACKEND_ASIMD_TAG40_MAX_LITERAL_BYTES_V1)
        .contains(&bytes)
}

fn emit_glue_object(
    platform: SearchV27StaticPlatformV1,
    symbols: &SearchV27StaticSymbolsV1,
) -> Result<Vec<u8>, SearchV27StaticAbiErrorV1> {
    emit_search_static_direct_object_v1(
        SearchStaticDirectObjectVersionV1::V27,
        platform.direct(),
        symbols.wrapper.as_str(),
        symbols.entry.as_str(),
    )
    .map_err(|_| glue_error("direct object emission"))
    .and_then(|bytes| {
        if bytes.len() <= HARD_MAX_SEARCH_V27_STATIC_GLUE_OBJECT_BYTES_V1 {
            Ok(bytes)
        } else {
            Err(glue_error("hard glue object bound"))
        }
    })
}

fn artifact_identity(
    domain: &[u8],
    claims: SearchV27StaticBindingClaimsV1,
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

const fn glue_error(at: &'static str) -> SearchV27StaticAbiErrorV1 {
    SearchV27StaticAbiErrorV1::InvalidGlue { at }
}

const fn source_error(at: &'static str) -> SearchV27StaticAbiErrorV1 {
    SearchV27StaticAbiErrorV1::SourceBinding { at }
}

const fn overflow(at: &'static str) -> SearchV27StaticAbiErrorV1 {
    SearchV27StaticAbiErrorV1::ArithmeticOverflow { at }
}

#[cfg(test)]
mod tests {
    use fre::RustProfile;

    use super::*;
    use crate::{
        LinuxAarch64SearchCompilePolicyV1, SearchCompilePolicyV1,
        build_linux_aarch64_search_v27_exists_object_v1,
        build_linux_aarch64_search_v27_selected_end_object_v1,
        build_macos_aarch64_search_v27_exists_object_v1,
        build_macos_aarch64_search_v27_selected_end_object_v1,
    };

    const FIRST: &[u8] = b"abcabcabc";
    const SECOND: &[u8] = b"abdabdabd";

    fn bindings(source: &[u8]) -> [SearchV27StaticBindingV1; 4] {
        let mac_exists = build_macos_aarch64_search_v27_exists_object_v1(
            source.to_vec(),
            RustProfile::default(),
            SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let mac_end = build_macos_aarch64_search_v27_selected_end_object_v1(
            source.to_vec(),
            RustProfile::default(),
            SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let linux_exists = build_linux_aarch64_search_v27_exists_object_v1(
            source.to_vec(),
            RustProfile::default(),
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .unwrap();
        let linux_end = build_linux_aarch64_search_v27_selected_end_object_v1(
            source.to_vec(),
            RustProfile::default(),
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .unwrap();
        [
            build_macos_aarch64_search_v27_exists_static_binding_v1(&mac_exists).unwrap(),
            build_macos_aarch64_search_v27_selected_end_static_binding_v1(&mac_end).unwrap(),
            build_linux_aarch64_search_v27_exists_static_binding_v1(&linux_exists).unwrap(),
            build_linux_aarch64_search_v27_selected_end_static_binding_v1(&linux_end).unwrap(),
        ]
    }

    #[test]
    fn both_formats_and_outputs_are_deterministic_direct_and_inert() {
        let first = bindings(FIRST);
        let second = bindings(FIRST);
        assert_eq!(first, second);
        for binding in &first {
            binding.validate().unwrap();
            assert_eq!(
                binding.runtime_authority(),
                SearchAotRuntimeAuthorityV1::Absent
            );
            assert_eq!(binding.claims().backend_version(), 40);
            assert_eq!(binding.claims().literal_bytes(), 9);
            assert_eq!(
                binding
                    .glue_object()
                    .windows(4)
                    .filter(|code| { *code == SEARCH_V27_STATIC_GLUE_CODE_V1.as_slice() })
                    .count(),
                1
            );
            assert!(!binding.c_header().contains("Span"));
            assert!(!binding.c_header().contains("v26"));
            assert!(
                !binding
                    .glue_object()
                    .windows(b"adopt".len())
                    .any(|window| window == b"adopt")
            );
        }
        assert!(first[0].c_header().contains("publishes neither word"));
        assert!(first[1].c_header().contains("publishes only end"));
    }

    #[test]
    fn every_width_and_literal_topology_builds_both_outputs_and_formats() {
        const PHASE_UNIQUE: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz012345";

        for width in 1..=32 {
            let uniform = vec![b'a'; width];
            let periodic = b"abc"
                .iter()
                .copied()
                .cycle()
                .take(width)
                .collect::<Vec<_>>();
            let phase_unique = PHASE_UNIQUE[..width].to_vec();

            for source in [&uniform, &periodic, &phase_unique] {
                for binding in bindings(source) {
                    binding.validate().unwrap();
                    assert_eq!(binding.claims().backend_version(), 40);
                    assert_eq!(
                        binding.claims().literal_bytes(),
                        u32::try_from(width).unwrap()
                    );
                }
            }
        }
    }

    #[test]
    fn wrong_output_platform_and_identity_are_refused() {
        let first = bindings(FIRST);
        let other = bindings(SECOND);
        for (index, platform) in [
            SearchV27StaticPlatformV1::MacosAarch64,
            SearchV27StaticPlatformV1::MacosAarch64,
            SearchV27StaticPlatformV1::LinuxAarch64,
            SearchV27StaticPlatformV1::LinuxAarch64,
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                inspect_search_v27_static_glue_v1(
                    platform,
                    first[index].claims().output(),
                    first[index].glue_object(),
                    other[index].claims(),
                )
                .is_err()
            );
        }
        assert!(matches!(
            inspect_search_v27_static_glue_v1(
                SearchV27StaticPlatformV1::MacosAarch64,
                OutputKind::SelectedEnd,
                first[0].glue_object(),
                first[0].claims(),
            ),
            Err(SearchV27StaticAbiErrorV1::WrongOutput { .. })
        ));
        assert!(matches!(
            inspect_search_v27_static_glue_v1(
                SearchV27StaticPlatformV1::LinuxAarch64,
                OutputKind::Exists,
                first[0].glue_object(),
                first[0].claims(),
            ),
            Err(SearchV27StaticAbiErrorV1::WrongPlatform { .. })
        ));
    }

    #[test]
    fn every_macho_and_elf_glue_byte_mutation_is_refused() {
        let bindings = bindings(FIRST);
        for index in [0_usize, 2] {
            let binding = &bindings[index];
            for offset in 0..binding.glue_object().len() {
                let mut changed = binding.glue_object().to_vec();
                changed[offset] ^= 1;
                assert!(
                    inspect_search_v27_static_glue_v1(
                        binding.claims().platform(),
                        binding.claims().output(),
                        &changed,
                        binding.claims(),
                    )
                    .is_err(),
                    "accepted byte mutation at binding {index} offset {offset}"
                );
            }
        }
    }
}
