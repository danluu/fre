//! JIT-neutral static expectation for one Linux `AArch64` Search Span object.

use core::fmt;

use fre::SearchExactLiteralAotSemanticBindingIdentity;
use fre_aot_elf::{BindingIdentity, CompileIdentity, MetadataV1, ObjectIdentity};
use fre_aot_search_contract::{
    AOT_SEARCH_COMPILER_VERSION_V1 as CONTRACT_COMPILER_VERSION_V1,
    AOT_STATIC_SEARCH_SPAN_EXPECTATION_SCHEMA_VERSION_V1, ClaimedStaticSearchSpanExpectationV1,
    SEARCH_ARCHITECTURE_AARCH64_V1, SEARCH_CALL_ABI_SCHEMA_V1, SEARCH_DEFAULT_END_ANCHOR_V1,
    SEARCH_DEFAULT_START_ANCHOR_V1, SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1,
    SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1, SEARCH_LITTLE_ENDIAN_V1, SEARCH_METADATA_BYTES_V1,
    SEARCH_METADATA_VERSION_V1, SEARCH_PLATFORM_LINUX_V1, SEARCH_POINTER_WIDTH_V1,
    SEARCH_SPAN_OUTPUT_KIND_V1, SEARCH_STATUS_BITS_V1, SEARCH_TARGET_ABI_AAPCS64_V1,
    STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1, STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1,
    STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1,
    STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1, StaticSearchSpanExpectationErrorV1,
    StaticSearchSpanExpectationV1 as StaticSearchSpanExpectationWireV1,
    compute_static_search_span_expectation_identity_v1, inspect_static_search_span_expectation_v1,
};
use fre_jit_aarch64::ArtifactIdentity;
use fre_kernel_ir::{CacheIdentity, OutputKind, Span};

use crate::{
    AOT_LINUX_SEARCH_COMPILER_VERSION_V1, LinuxAarch64SearchBackendV1, LinuxSearchCompileErrorV1,
    LinuxSearchCompileReceiptIdentityV1, LinuxSearchCompiledObjectV1, LinuxSearchLiteralIdentityV1,
    LinuxSearchManifestIdentityV1, SearchAotRuntimeAuthorityV1,
};

const EXPECTATION_MAGIC_V1: [u8; 8] = *b"FRESSPX\x01";
const EXPECTATION_HEADER_BYTES_V1: usize = 48;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LinuxStaticSearchSpanExpectationIdentityV1([u8; 32]);

impl LinuxStaticSearchSpanExpectationIdentityV1 {
    const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LinuxStaticSearchSpanExpectationIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "LinuxStaticSearchSpanExpectationIdentityV1({self})"
        )
    }
}

impl fmt::Display for LinuxStaticSearchSpanExpectationIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum LinuxStaticSearchSpanExpectationBuildErrorV1 {
    Compiler(LinuxSearchCompileErrorV1),
    Neutral(StaticSearchSpanExpectationErrorV1),
    TrustedMismatch { field: &'static str },
    WireLayout { at: &'static str },
}

impl fmt::Display for LinuxStaticSearchSpanExpectationBuildErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Linux static Search Span expectation failed: {self:?}"
        )
    }
}

impl std::error::Error for LinuxStaticSearchSpanExpectationBuildErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Compiler(error) => Some(error),
            Self::Neutral(error) => Some(error),
            Self::TrustedMismatch { .. } | Self::WireLayout { .. } => None,
        }
    }
}

impl From<LinuxSearchCompileErrorV1> for LinuxStaticSearchSpanExpectationBuildErrorV1 {
    fn from(value: LinuxSearchCompileErrorV1) -> Self {
        Self::Compiler(value)
    }
}

impl From<StaticSearchSpanExpectationErrorV1> for LinuxStaticSearchSpanExpectationBuildErrorV1 {
    fn from(value: StaticSearchSpanExpectationErrorV1) -> Self {
        Self::Neutral(value)
    }
}

/// Compiler-trusted expectation used by final-image glue. It remains inert
/// until an independently reviewed source-qualification row admits every
/// retained identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxStaticSearchSpanExpectationV1 {
    backend: LinuxAarch64SearchBackendV1,
    manifest_identity: LinuxSearchManifestIdentityV1,
    semantic_binding_identity: SearchExactLiteralAotSemanticBindingIdentity,
    literal_identity: LinuxSearchLiteralIdentityV1,
    live_literal_bytes: u32,
    kir_identity: CacheIdentity,
    artifact_identity: ArtifactIdentity,
    binding_identity: BindingIdentity,
    compile_identity: CompileIdentity,
    object_identity: ObjectIdentity,
    receipt_identity: LinuxSearchCompileReceiptIdentityV1,
    metadata: MetadataV1,
    expectation_identity: LinuxStaticSearchSpanExpectationIdentityV1,
    wire: StaticSearchSpanExpectationWireV1,
}

impl LinuxStaticSearchSpanExpectationV1 {
    #[must_use]
    pub const fn backend(&self) -> LinuxAarch64SearchBackendV1 {
        self.backend
    }

    #[must_use]
    pub const fn manifest_identity(&self) -> LinuxSearchManifestIdentityV1 {
        self.manifest_identity
    }

    #[must_use]
    pub const fn semantic_binding_identity(&self) -> SearchExactLiteralAotSemanticBindingIdentity {
        self.semantic_binding_identity
    }

    #[must_use]
    pub const fn literal_identity(&self) -> LinuxSearchLiteralIdentityV1 {
        self.literal_identity
    }

    #[must_use]
    pub const fn live_literal_bytes(&self) -> u32 {
        self.live_literal_bytes
    }

    #[must_use]
    pub const fn kir_identity(&self) -> CacheIdentity {
        self.kir_identity
    }

    #[must_use]
    pub const fn artifact_identity(&self) -> ArtifactIdentity {
        self.artifact_identity
    }

    #[must_use]
    pub const fn binding_identity(&self) -> BindingIdentity {
        self.binding_identity
    }

    #[must_use]
    pub const fn compile_identity(&self) -> CompileIdentity {
        self.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> ObjectIdentity {
        self.object_identity
    }

    #[must_use]
    pub const fn receipt_identity(&self) -> LinuxSearchCompileReceiptIdentityV1 {
        self.receipt_identity
    }

    #[must_use]
    pub const fn metadata(&self) -> MetadataV1 {
        self.metadata
    }

    #[must_use]
    pub const fn expectation_identity(&self) -> LinuxStaticSearchSpanExpectationIdentityV1 {
        self.expectation_identity
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &StaticSearchSpanExpectationWireV1 {
        &self.wire
    }

    #[must_use]
    pub fn metadata_bytes_v1(&self) -> &[u8; SEARCH_METADATA_BYTES_V1] {
        self.wire
            .get(
                STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1
                    ..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1,
            )
            .and_then(|bytes| bytes.try_into().ok())
            .expect("fixed expectation metadata range")
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }

    #[must_use]
    pub fn authenticates_claim(&self, claim: &ClaimedStaticSearchSpanExpectationV1) -> bool {
        claim.compiler_version() == CONTRACT_COMPILER_VERSION_V1
            && claim.backend_version() == self.backend.backend_version().0
            && claim.platform() == SEARCH_PLATFORM_LINUX_V1
            && claim.required_features() == self.backend.required_features().bits()
            && claim.exported_symbol_n_type() == SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1
            && claim.live_literal_bytes() == self.live_literal_bytes
            && claim.manifest_identity() == self.manifest_identity.as_bytes()
            && claim.semantic_binding_identity() == self.semantic_binding_identity.as_bytes()
            && claim.literal_identity() == self.literal_identity.as_bytes()
            && claim.kir_identity() == self.kir_identity.as_bytes()
            && claim.artifact_identity() == self.artifact_identity.as_bytes()
            && claim.binding_identity() == self.binding_identity.as_bytes()
            && claim.compile_identity() == self.compile_identity.as_bytes()
            && claim.object_identity() == self.object_identity.as_bytes()
            && claim.receipt_identity() == self.receipt_identity.as_bytes()
            && claim.expectation_identity() == self.expectation_identity.as_bytes()
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixed expectation wire is emitted and authenticated in one auditable sequence"
)]
pub fn build_linux_static_search_span_expectation_v1(
    compiled: &LinuxSearchCompiledObjectV1<Span>,
) -> Result<LinuxStaticSearchSpanExpectationV1, LinuxStaticSearchSpanExpectationBuildErrorV1> {
    if compiled.runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
        || compiled.receipt().runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
    {
        return Err(mismatch("runtime authority"));
    }
    let receipt = compiled.receipt();
    if receipt.output() != OutputKind::Span {
        return Err(mismatch("typed Span receipt"));
    }
    let inspection = receipt.validate_object(
        compiled.object().as_bytes(),
        fre_aot_elf::ObjectLimitsV1::default(),
    )?;
    let metadata_bytes: &[u8; SEARCH_METADATA_BYTES_V1] = inspection
        .metadata_bytes()
        .try_into()
        .map_err(|_| wire("metadata extent"))?;
    if inspection.metadata() != receipt.metadata()
        || receipt.metadata().rodata_bytes() != receipt.literal_bytes()
        || receipt.metadata().compile_identity() != receipt.compile_identity()
    {
        return Err(mismatch("compiler object projection"));
    }

    let mut wire_bytes = [0_u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1];
    {
        let mut writer = Writer::new(&mut wire_bytes);
        writer.raw(&EXPECTATION_MAGIC_V1)?;
        writer.u16(AOT_STATIC_SEARCH_SPAN_EXPECTATION_SCHEMA_VERSION_V1)?;
        writer.u16(CONTRACT_COMPILER_VERSION_V1)?;
        writer.u32(
            u32::try_from(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1)
                .expect("fixed expectation bytes"),
        )?;
        writer.u16(u16::try_from(SEARCH_METADATA_BYTES_V1).expect("fixed metadata bytes"))?;
        writer.u16(SEARCH_METADATA_VERSION_V1)?;
        writer.u16(receipt.backend().backend_version().0)?;
        writer.u16(SEARCH_CALL_ABI_SCHEMA_V1)?;
        writer.u16(SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1)?;
        writer.u8(SEARCH_SPAN_OUTPUT_KIND_V1)?;
        writer.u8(SEARCH_DEFAULT_START_ANCHOR_V1)?;
        writer.u8(SEARCH_DEFAULT_END_ANCHOR_V1)?;
        writer.u8(SEARCH_ARCHITECTURE_AARCH64_V1)?;
        writer.u8(SEARCH_LITTLE_ENDIAN_V1)?;
        writer.u8(SEARCH_POINTER_WIDTH_V1)?;
        writer.u8(SEARCH_TARGET_ABI_AAPCS64_V1)?;
        writer.u8(SEARCH_PLATFORM_LINUX_V1)?;
        writer.u8(SEARCH_STATUS_BITS_V1)?;
        writer.u8(SEARCH_EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V1)?;
        writer.u64(receipt.backend().required_features().bits())?;
        writer.u32(receipt.literal_bytes())?;
        if writer.position() != EXPECTATION_HEADER_BYTES_V1 {
            return Err(wire("expectation header width"));
        }
        writer.raw(receipt.manifest_identity().as_bytes())?;
        writer.raw(receipt.semantic_binding_identity().as_bytes())?;
        writer.raw(receipt.literal_identity().as_bytes())?;
        writer.raw(receipt.kir_identity().as_bytes())?;
        writer.raw(receipt.artifact_identity().as_bytes())?;
        writer.raw(receipt.binding_identity().as_bytes())?;
        writer.raw(receipt.compile_identity().as_bytes())?;
        writer.raw(receipt.object_identity().as_bytes())?;
        writer.raw(receipt.receipt_identity().as_bytes())?;
        if writer.position() != STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1 {
            return Err(wire("expectation identity tuple width"));
        }
        writer.raw(metadata_bytes)?;
        if writer.position() != STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1 {
            return Err(wire("expectation metadata boundary"));
        }
    }
    let body: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1] = wire_bytes
        .get(..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| wire("expectation identity body"))?;
    let expectation_identity = compute_static_search_span_expectation_identity_v1(body);
    wire_bytes[STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1..]
        .copy_from_slice(&expectation_identity);
    let claim = inspect_static_search_span_expectation_v1(&wire_bytes)?;
    let expectation = LinuxStaticSearchSpanExpectationV1 {
        backend: receipt.backend(),
        manifest_identity: receipt.manifest_identity(),
        semantic_binding_identity: receipt.semantic_binding_identity(),
        literal_identity: receipt.literal_identity(),
        live_literal_bytes: receipt.literal_bytes(),
        kir_identity: receipt.kir_identity(),
        artifact_identity: receipt.artifact_identity(),
        binding_identity: receipt.binding_identity(),
        compile_identity: receipt.compile_identity(),
        object_identity: receipt.object_identity(),
        receipt_identity: receipt.receipt_identity(),
        metadata: receipt.metadata(),
        expectation_identity: LinuxStaticSearchSpanExpectationIdentityV1::new(expectation_identity),
        wire: wire_bytes,
    };
    if AOT_LINUX_SEARCH_COMPILER_VERSION_V1 != CONTRACT_COMPILER_VERSION_V1
        || !expectation.authenticates_claim(&claim)
        || claim.metadata().compile_identity() != receipt.compile_identity().as_bytes()
        || claim.metadata().payload_sha256() != receipt.metadata().payload_sha256()
    {
        return Err(mismatch("neutral expectation claim"));
    }
    Ok(expectation)
}

const fn mismatch(field: &'static str) -> LinuxStaticSearchSpanExpectationBuildErrorV1 {
    LinuxStaticSearchSpanExpectationBuildErrorV1::TrustedMismatch { field }
}

const fn wire(at: &'static str) -> LinuxStaticSearchSpanExpectationBuildErrorV1 {
    LinuxStaticSearchSpanExpectationBuildErrorV1::WireLayout { at }
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

    fn raw(&mut self, bytes: &[u8]) -> Result<(), LinuxStaticSearchSpanExpectationBuildErrorV1> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or_else(|| wire("expectation writer overflow"))?;
        self.destination
            .get_mut(self.position..end)
            .ok_or_else(|| wire("expectation writer range"))?
            .copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), LinuxStaticSearchSpanExpectationBuildErrorV1> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), LinuxStaticSearchSpanExpectationBuildErrorV1> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), LinuxStaticSearchSpanExpectationBuildErrorV1> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), LinuxStaticSearchSpanExpectationBuildErrorV1> {
        self.raw(&value.to_le_bytes())
    }
}

const _: () = assert!(CONTRACT_COMPILER_VERSION_V1 == AOT_LINUX_SEARCH_COMPILER_VERSION_V1);
const _: () = assert!(SEARCH_METADATA_BYTES_V1 == fre_aot_elf::METADATA_BYTES_V1);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        LinuxAarch64ExactSearchManifestV1, LinuxAarch64SearchCompilePolicyV1,
        plan_and_compile_linux_aarch64_exact_search_v1,
    };
    use fre::RustProfile;
    use fre_aot_search_contract::{
        SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1, SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1,
    };

    #[test]
    fn tag21_compiler_object_projects_to_the_neutral_linux_contract() {
        let manifest = LinuxAarch64ExactSearchManifestV1::<Span>::tag21_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("tag21 candidate manifest");
        let compiled = plan_and_compile_linux_aarch64_exact_search_v1(
            manifest,
            b"0123456789abcdef".to_vec(),
            RustProfile::default(),
        )
        .expect("Linux tag21 object");
        let expectation = build_linux_static_search_span_expectation_v1(&compiled)
            .expect("Linux tag21 expectation");
        let claim = inspect_static_search_span_expectation_v1(expectation.as_bytes())
            .expect("neutral expectation inspection");
        assert!(expectation.authenticates_claim(&claim));
        assert_eq!(
            claim.backend_version(),
            SEARCH_BACKEND_SVE2_FIXED16_TAG21_V1
        );
        assert_eq!(claim.platform(), SEARCH_PLATFORM_LINUX_V1);
        assert_eq!(
            claim.required_features(),
            SEARCH_REQUIRED_SVE2_FIXED16_FEATURES_V1
        );
        assert_eq!(
            claim.expectation_identity(),
            expectation.expectation_identity().as_bytes()
        );
    }
}
