//! JIT-neutral static expectation for one Linux `AArch64` tag21
//! `SelectedEnd` register-return object.
//!
//! This module turns only the compiler-sealed P2b object aggregate into the
//! exact neutral 608-byte expectation. The resulting value carries identities
//! and inert contract bytes; it grants no qualification, mapping, calling,
//! runtime, or deployment authority.

use core::fmt;

use fre::SearchExactLiteralAotSemanticBindingIdentity;
use fre_aot_elf::{
    BindingIdentity, CompileIdentity, ObjectIdentity, SELECTED_END_METADATA_BYTES_V2,
    SelectedEndMetadataV2, SelectedEndObjectLimitsV2,
};
use fre_aot_search_contract::selected_end_v2::{
    AOT_SEARCH_SELECTED_END_COMPILER_VERSION_V2 as CONTRACT_COMPILER_VERSION_V2,
    AOT_STATIC_SEARCH_SELECTED_END_EXPECTATION_SCHEMA_VERSION_V2,
    ClaimedSearchSelectedEndMetadataV2, ClaimedStaticSearchSelectedEndExpectationV2,
    EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V2, EXPORTED_SYMBOL_SCHEMA_VERSION_V2,
    SEARCH_SELECTED_END_ARCHITECTURE_AARCH64_V2, SEARCH_SELECTED_END_ARGUMENT_COUNT_V2,
    SEARCH_SELECTED_END_BACKEND_TAG21_V2, SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2,
    SEARCH_SELECTED_END_DEFAULT_END_ANCHOR_V2, SEARCH_SELECTED_END_DEFAULT_START_ANCHOR_V2,
    SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2, SEARCH_SELECTED_END_LITERAL_BYTES_V2,
    SEARCH_SELECTED_END_LITTLE_ENDIAN_V2, SEARCH_SELECTED_END_METADATA_BYTES_V2,
    SEARCH_SELECTED_END_METADATA_VERSION_V2, SEARCH_SELECTED_END_NO_MATCH_SENTINEL_V2,
    SEARCH_SELECTED_END_OUTPUT_KIND_V2, SEARCH_SELECTED_END_PLATFORM_LINUX_V2,
    SEARCH_SELECTED_END_POINTER_WIDTH_V2, SEARCH_SELECTED_END_REQUIRED_FEATURES_V2,
    SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2, SEARCH_SELECTED_END_RETURN_BITS_V2,
    SEARCH_SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2, SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2,
    SEARCH_SELECTED_END_TARGET_ABI_AAPCS64_V2,
    SEARCH_SELECTED_END_WINDOW_HALF_OPEN_ABSOLUTE_END_V2,
    STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2,
    STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_BODY_BYTES_V2,
    STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2,
    STATIC_SEARCH_SELECTED_END_EXPECTATION_METADATA_OFFSET_V2,
    StaticSearchSelectedEndExpectationErrorV2,
    StaticSearchSelectedEndExpectationV2 as StaticSearchSelectedEndExpectationWireV2,
    compute_static_search_selected_end_expectation_identity_v2,
    inspect_static_search_selected_end_expectation_v2,
};
use fre_jit_aarch64::SelectedEndRegisterArtifactIdentityV2;
use fre_kernel_ir::CacheIdentity;

use crate::search_selected_end_v2::{
    AOT_LINUX_SELECTED_END_COMPILER_VERSION_V2, LinuxSelectedEndCompileErrorV2,
    LinuxSelectedEndCompileReceiptIdentityV2, LinuxSelectedEndCompiledObjectV2,
    LinuxSelectedEndLiteralIdentityV2, LinuxSelectedEndManifestIdentityV2,
    SelectedEndAotRuntimeAuthorityV2,
};

const EXPECTATION_MAGIC_V2: [u8; 8] = *b"FRESEX\0\x02";
const EXPECTATION_HEADER_BYTES_V2: usize = 64;

const _: () = assert!(CONTRACT_COMPILER_VERSION_V2 == AOT_LINUX_SELECTED_END_COMPILER_VERSION_V2);
const _: () = assert!(SEARCH_SELECTED_END_METADATA_BYTES_V2 == SELECTED_END_METADATA_BYTES_V2);
const _: () = assert!(STATIC_SEARCH_SELECTED_END_EXPECTATION_METADATA_OFFSET_V2 == 352);
const _: () = assert!(STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2 == 576);
const _: () = assert!(STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2 == 608);

/// Domain-separated identity of one exact static `SelectedEnd` expectation.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LinuxStaticSearchSelectedEndExpectationIdentityV2([u8; 32]);

impl LinuxStaticSearchSelectedEndExpectationIdentityV2 {
    const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LinuxStaticSearchSelectedEndExpectationIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "LinuxStaticSearchSelectedEndExpectationIdentityV2({self})"
        )
    }
}

impl fmt::Display for LinuxStaticSearchSelectedEndExpectationIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Failure to project a sealed P2b compiler result into the neutral wire.
#[derive(Debug)]
#[non_exhaustive]
pub enum LinuxStaticSearchSelectedEndExpectationBuildErrorV2 {
    Compiler(LinuxSelectedEndCompileErrorV2),
    Neutral(StaticSearchSelectedEndExpectationErrorV2),
    TrustedMismatch { field: &'static str },
    WireLayout { at: &'static str },
}

impl fmt::Display for LinuxStaticSearchSelectedEndExpectationBuildErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Linux static Search SelectedEnd V2 expectation failed: {self:?}"
        )
    }
}

impl std::error::Error for LinuxStaticSearchSelectedEndExpectationBuildErrorV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Compiler(error) => Some(error),
            Self::Neutral(error) => Some(error),
            Self::TrustedMismatch { .. } | Self::WireLayout { .. } => None,
        }
    }
}

impl From<LinuxSelectedEndCompileErrorV2> for LinuxStaticSearchSelectedEndExpectationBuildErrorV2 {
    fn from(value: LinuxSelectedEndCompileErrorV2) -> Self {
        Self::Compiler(value)
    }
}

impl From<StaticSearchSelectedEndExpectationErrorV2>
    for LinuxStaticSearchSelectedEndExpectationBuildErrorV2
{
    fn from(value: StaticSearchSelectedEndExpectationErrorV2) -> Self {
        Self::Neutral(value)
    }
}

/// Compiler-trusted exact 608-byte expectation for qualification glue.
///
/// The wrapper can be constructed only from a
/// [`LinuxSelectedEndCompiledObjectV2`]. Its claim authenticator compares
/// every public neutral header, identity, and metadata projection. Possession
/// of the wrapper still carries no authority to call the implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxStaticSearchSelectedEndExpectationV2 {
    manifest_identity: LinuxSelectedEndManifestIdentityV2,
    semantic_binding_identity: SearchExactLiteralAotSemanticBindingIdentity,
    literal_identity: LinuxSelectedEndLiteralIdentityV2,
    kir_identity: CacheIdentity,
    artifact_identity: SelectedEndRegisterArtifactIdentityV2,
    binding_identity: BindingIdentity,
    compile_identity: CompileIdentity,
    object_identity: ObjectIdentity,
    receipt_identity: LinuxSelectedEndCompileReceiptIdentityV2,
    metadata: SelectedEndMetadataV2,
    expectation_identity: LinuxStaticSearchSelectedEndExpectationIdentityV2,
    wire: StaticSearchSelectedEndExpectationWireV2,
}

impl LinuxStaticSearchSelectedEndExpectationV2 {
    #[must_use]
    pub const fn manifest_identity(&self) -> LinuxSelectedEndManifestIdentityV2 {
        self.manifest_identity
    }

    #[must_use]
    pub const fn semantic_binding_identity(&self) -> SearchExactLiteralAotSemanticBindingIdentity {
        self.semantic_binding_identity
    }

    #[must_use]
    pub const fn literal_identity(&self) -> LinuxSelectedEndLiteralIdentityV2 {
        self.literal_identity
    }

    #[must_use]
    pub const fn live_literal_bytes(&self) -> u32 {
        SEARCH_SELECTED_END_LITERAL_BYTES_V2
    }

    #[must_use]
    pub const fn kir_identity(&self) -> CacheIdentity {
        self.kir_identity
    }

    #[must_use]
    pub fn artifact_identity(&self) -> SelectedEndRegisterArtifactIdentityV2 {
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
    pub const fn receipt_identity(&self) -> LinuxSelectedEndCompileReceiptIdentityV2 {
        self.receipt_identity
    }

    #[must_use]
    pub const fn metadata(&self) -> SelectedEndMetadataV2 {
        self.metadata
    }

    #[must_use]
    pub const fn expectation_identity(&self) -> LinuxStaticSearchSelectedEndExpectationIdentityV2 {
        self.expectation_identity
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &StaticSearchSelectedEndExpectationWireV2 {
        &self.wire
    }

    #[must_use]
    pub fn metadata_bytes_v2(&self) -> &[u8; SEARCH_SELECTED_END_METADATA_BYTES_V2] {
        self.wire
            .get(
                STATIC_SEARCH_SELECTED_END_EXPECTATION_METADATA_OFFSET_V2
                    ..STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2,
            )
            .and_then(|bytes| bytes.try_into().ok())
            .expect("fixed SelectedEnd V2 expectation metadata range")
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }

    /// Compare every exposed field in a canonical neutral claim with this
    /// compiler-trusted projection.
    #[must_use]
    pub fn authenticates_claim(&self, claim: &ClaimedStaticSearchSelectedEndExpectationV2) -> bool {
        claim.schema_version() == AOT_STATIC_SEARCH_SELECTED_END_EXPECTATION_SCHEMA_VERSION_V2
            && claim.compiler_version() == CONTRACT_COMPILER_VERSION_V2
            && usize::from(claim.metadata_record_bytes()) == SEARCH_SELECTED_END_METADATA_BYTES_V2
            && claim.metadata_version() == SEARCH_SELECTED_END_METADATA_VERSION_V2
            && claim.backend_version() == SEARCH_SELECTED_END_BACKEND_TAG21_V2
            && claim.call_abi_schema() == SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2
            && claim.exported_symbol_schema() == EXPORTED_SYMBOL_SCHEMA_VERSION_V2
            && claim.output_kind() == SEARCH_SELECTED_END_OUTPUT_KIND_V2
            && !claim.anchor_start()
            && !claim.anchor_end()
            && claim.architecture() == SEARCH_SELECTED_END_ARCHITECTURE_AARCH64_V2
            && claim.little_endian()
            && claim.pointer_width() == SEARCH_SELECTED_END_POINTER_WIDTH_V2
            && claim.target_abi() == SEARCH_SELECTED_END_TARGET_ABI_AAPCS64_V2
            && claim.platform() == SEARCH_SELECTED_END_PLATFORM_LINUX_V2
            && claim.return_bits() == SEARCH_SELECTED_END_RETURN_BITS_V2
            && claim.exported_symbol_info() == EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V2
            && claim.return_encoding() == SEARCH_SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2
            && claim.window_contract() == SEARCH_SELECTED_END_WINDOW_HALF_OPEN_ABSOLUTE_END_V2
            && claim.fixed_active_vector_bytes() == SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2
            && claim.required_features() == SEARCH_SELECTED_END_REQUIRED_FEATURES_V2
            && claim.live_literal_bytes() == SEARCH_SELECTED_END_LITERAL_BYTES_V2
            && claim.argument_count() == SEARCH_SELECTED_END_ARGUMENT_COUNT_V2
            && claim.return_register() == SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2
            && claim.result_slot_bytes() == SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2
            && claim.no_match_sentinel() == SEARCH_SELECTED_END_NO_MATCH_SENTINEL_V2
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
            && metadata_claim_matches_trusted(claim.metadata(), self.metadata)
    }

    /// Reopen only the exact retained wire and recheck the complete neutral
    /// projection. The returned value remains a claim and grants no authority.
    pub fn validate_canonical_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<
        ClaimedStaticSearchSelectedEndExpectationV2,
        LinuxStaticSearchSelectedEndExpectationBuildErrorV2,
    > {
        if self.wire.as_slice() != bytes {
            return Err(mismatch("reopened expectation bytes"));
        }
        let claim = inspect_static_search_selected_end_expectation_v2(bytes)?;
        if !self.authenticates_claim(&claim) {
            return Err(mismatch("reopened neutral expectation claim"));
        }
        Ok(claim)
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear writer keeps every fixed ABI2 field, identity, boundary, and reinspection auditable"
)]
pub fn build_linux_static_search_selected_end_expectation_v2(
    compiled: &LinuxSelectedEndCompiledObjectV2,
) -> Result<
    LinuxStaticSearchSelectedEndExpectationV2,
    LinuxStaticSearchSelectedEndExpectationBuildErrorV2,
> {
    if compiled.runtime_authority() != SelectedEndAotRuntimeAuthorityV2::Absent
        || compiled.receipt().runtime_authority() != SelectedEndAotRuntimeAuthorityV2::Absent
    {
        return Err(mismatch("runtime authority"));
    }

    let limits = SelectedEndObjectLimitsV2::default();
    compiled.validate_source_image_object(limits)?;
    let receipt = compiled.receipt();
    let inspection = receipt.validate_object(compiled.object().as_bytes(), limits)?;
    let metadata = inspection.metadata();
    let canonical_metadata = metadata
        .encode()
        .map_err(LinuxSelectedEndCompileErrorV2::from)?;
    if metadata != receipt.metadata()
        || inspection.metadata_bytes() != &canonical_metadata
        || receipt.literal_bytes() != SEARCH_SELECTED_END_LITERAL_BYTES_V2
        || metadata.literal_bytes() != receipt.literal_bytes()
        || metadata.rodata_bytes() != receipt.literal_bytes()
        || metadata.source_identity() != receipt.kir_identity().as_bytes()
        || metadata.artifact_identity() != receipt.artifact_identity().as_bytes()
        || !receipt
            .binding_identity()
            .matches_claim(metadata.claimed_binding_identity())
        || !receipt
            .compile_identity()
            .matches_claim(metadata.claimed_compile_identity())
        || compiled.object().object_identity() != receipt.object_identity()
    {
        return Err(mismatch("compiler object projection"));
    }

    let artifact_identity = receipt.artifact_identity();
    let mut wire = [0_u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2];
    {
        let mut writer = Writer::new(&mut wire);
        writer.raw(&EXPECTATION_MAGIC_V2)?;
        writer.u16(AOT_STATIC_SEARCH_SELECTED_END_EXPECTATION_SCHEMA_VERSION_V2)?;
        writer.u16(CONTRACT_COMPILER_VERSION_V2)?;
        writer.u32(
            u32::try_from(STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2)
                .expect("fixed SelectedEnd V2 expectation bytes"),
        )?;
        writer.u16(
            u16::try_from(SEARCH_SELECTED_END_METADATA_BYTES_V2)
                .expect("fixed SelectedEnd V2 metadata bytes"),
        )?;
        writer.u16(SEARCH_SELECTED_END_METADATA_VERSION_V2)?;
        writer.u16(SEARCH_SELECTED_END_BACKEND_TAG21_V2)?;
        writer.u16(SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2)?;
        writer.u16(EXPORTED_SYMBOL_SCHEMA_VERSION_V2)?;
        writer.u8(SEARCH_SELECTED_END_OUTPUT_KIND_V2)?;
        writer.u8(SEARCH_SELECTED_END_DEFAULT_START_ANCHOR_V2)?;
        writer.u8(SEARCH_SELECTED_END_DEFAULT_END_ANCHOR_V2)?;
        writer.u8(SEARCH_SELECTED_END_ARCHITECTURE_AARCH64_V2)?;
        writer.u8(SEARCH_SELECTED_END_LITTLE_ENDIAN_V2)?;
        writer.u8(SEARCH_SELECTED_END_POINTER_WIDTH_V2)?;
        writer.u8(SEARCH_SELECTED_END_TARGET_ABI_AAPCS64_V2)?;
        writer.u8(SEARCH_SELECTED_END_PLATFORM_LINUX_V2)?;
        writer.u8(SEARCH_SELECTED_END_RETURN_BITS_V2)?;
        writer.u8(EXPORTED_SYMBOL_INFO_ELF_FUNCTION_V2)?;
        writer.u8(SEARCH_SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2)?;
        writer.u8(SEARCH_SELECTED_END_WINDOW_HALF_OPEN_ABSOLUTE_END_V2)?;
        writer.u16(SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2)?;
        writer.u64(SEARCH_SELECTED_END_REQUIRED_FEATURES_V2)?;
        writer.u32(SEARCH_SELECTED_END_LITERAL_BYTES_V2)?;
        writer.u8(SEARCH_SELECTED_END_ARGUMENT_COUNT_V2)?;
        writer.u8(SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2)?;
        writer.u16(SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2)?;
        writer.u64(SEARCH_SELECTED_END_NO_MATCH_SENTINEL_V2)?;
        if writer.position() != EXPECTATION_HEADER_BYTES_V2 {
            return Err(wire_error("expectation header width"));
        }

        writer.raw(receipt.manifest_identity().as_bytes())?;
        writer.raw(receipt.semantic_binding_identity().as_bytes())?;
        writer.raw(receipt.literal_identity().as_bytes())?;
        writer.raw(receipt.kir_identity().as_bytes())?;
        writer.raw(artifact_identity.as_bytes())?;
        writer.raw(receipt.binding_identity().as_bytes())?;
        writer.raw(receipt.compile_identity().as_bytes())?;
        writer.raw(receipt.object_identity().as_bytes())?;
        writer.raw(receipt.receipt_identity().as_bytes())?;
        if writer.position() != STATIC_SEARCH_SELECTED_END_EXPECTATION_METADATA_OFFSET_V2 {
            return Err(wire_error("expectation identity tuple width"));
        }

        writer.raw(&canonical_metadata)?;
        if writer.position() != STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2 {
            return Err(wire_error("expectation metadata boundary"));
        }
    }

    let body: &[u8; STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_BODY_BYTES_V2] = wire
        .get(..STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| wire_error("expectation identity body"))?;
    let expectation_identity = compute_static_search_selected_end_expectation_identity_v2(body);
    wire[STATIC_SEARCH_SELECTED_END_EXPECTATION_IDENTITY_OFFSET_V2..]
        .copy_from_slice(&expectation_identity);

    let claim = inspect_static_search_selected_end_expectation_v2(&wire)?;
    let receipt_claim = receipt.validate_expectation(&wire)?;
    let expectation = LinuxStaticSearchSelectedEndExpectationV2 {
        manifest_identity: receipt.manifest_identity(),
        semantic_binding_identity: receipt.semantic_binding_identity(),
        literal_identity: receipt.literal_identity(),
        kir_identity: receipt.kir_identity(),
        artifact_identity,
        binding_identity: receipt.binding_identity(),
        compile_identity: receipt.compile_identity(),
        object_identity: receipt.object_identity(),
        receipt_identity: receipt.receipt_identity(),
        metadata,
        expectation_identity: LinuxStaticSearchSelectedEndExpectationIdentityV2::new(
            expectation_identity,
        ),
        wire,
    };
    if claim != receipt_claim
        || !expectation.authenticates_claim(&claim)
        || expectation.runtime_authority() != SelectedEndAotRuntimeAuthorityV2::Absent
    {
        return Err(mismatch("neutral expectation claim"));
    }
    Ok(expectation)
}

fn metadata_claim_matches_trusted(
    claim: ClaimedSearchSelectedEndMetadataV2,
    metadata: SelectedEndMetadataV2,
) -> bool {
    claim.format_version() == metadata.format_version()
        && claim.record_bytes() == metadata.record_bytes()
        && claim.backend_version() == metadata.backend_version()
        && claim.abi_kind() == metadata.abi_kind()
        && claim.output_kind() == metadata.output_kind()
        && claim.architecture() == metadata.architecture()
        && claim.little_endian() == metadata.little_endian()
        && claim.pointer_width() == metadata.pointer_width()
        && claim.target_abi() == metadata.target_abi()
        && claim.platform() == metadata.platform()
        && claim.return_bits() == metadata.return_bits()
        && claim.call_abi_schema() == metadata.abi_schema()
        && claim.return_encoding() == metadata.return_encoding()
        && claim.window_contract() == metadata.window_contract()
        && claim.fixed_active_vector_bytes() == metadata.fixed_active_vector_bytes()
        && claim.features() == metadata.features()
        && claim.payload_bytes() == metadata.payload_bytes()
        && claim.entry_offset() == metadata.entry_offset()
        && claim.code_bytes() == metadata.code_bytes()
        && claim.rodata_offset() == metadata.rodata_offset()
        && claim.rodata_bytes() == metadata.rodata_bytes()
        && claim.literal_bytes() == metadata.literal_bytes()
        && claim.source_identity() == metadata.source_identity()
        && claim.artifact_identity() == metadata.artifact_identity()
        && claim.binding_identity() == metadata.claimed_binding_identity().as_bytes()
        && claim.payload_sha256() == metadata.payload_sha256()
        && claim.compile_identity() == metadata.claimed_compile_identity().as_bytes()
}

const fn mismatch(field: &'static str) -> LinuxStaticSearchSelectedEndExpectationBuildErrorV2 {
    LinuxStaticSearchSelectedEndExpectationBuildErrorV2::TrustedMismatch { field }
}

const fn wire_error(at: &'static str) -> LinuxStaticSearchSelectedEndExpectationBuildErrorV2 {
    LinuxStaticSearchSelectedEndExpectationBuildErrorV2::WireLayout { at }
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

    fn raw(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), LinuxStaticSearchSelectedEndExpectationBuildErrorV2> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or_else(|| wire_error("expectation writer overflow"))?;
        self.destination
            .get_mut(self.position..end)
            .ok_or_else(|| wire_error("expectation writer range"))?
            .copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), LinuxStaticSearchSelectedEndExpectationBuildErrorV2> {
        self.raw(&[value])
    }

    fn u16(
        &mut self,
        value: u16,
    ) -> Result<(), LinuxStaticSearchSelectedEndExpectationBuildErrorV2> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(
        &mut self,
        value: u32,
    ) -> Result<(), LinuxStaticSearchSelectedEndExpectationBuildErrorV2> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(
        &mut self,
        value: u64,
    ) -> Result<(), LinuxStaticSearchSelectedEndExpectationBuildErrorV2> {
        self.raw(&value.to_le_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fre::RustProfile;

    use crate::search_selected_end_v2::{
        LinuxAarch64SelectedEndManifestV2, plan_and_compile_linux_aarch64_selected_end_v2,
    };

    fn compile(source: &[u8]) -> LinuxSelectedEndCompiledObjectV2 {
        plan_and_compile_linux_aarch64_selected_end_v2(
            LinuxAarch64SelectedEndManifestV2::default(),
            source.to_vec(),
            RustProfile::default(),
        )
        .expect("Linux tag21 SelectedEnd object")
    }

    #[test]
    fn sealed_compiler_object_projects_deterministically_to_exact_neutral_wire() {
        let compiled = compile(b"0123456789abcdef");
        let first = build_linux_static_search_selected_end_expectation_v2(&compiled)
            .expect("first expectation");
        let second = build_linux_static_search_selected_end_expectation_v2(&compiled)
            .expect("second expectation");
        assert_eq!(first, second);
        assert_eq!(
            first.as_bytes().len(),
            STATIC_SEARCH_SELECTED_END_EXPECTATION_BYTES_V2
        );
        assert_eq!(
            first.metadata_bytes_v2(),
            &compiled
                .receipt()
                .metadata()
                .encode()
                .expect("canonical metadata")
        );
        let claim = first
            .validate_canonical_bytes(first.as_bytes())
            .expect("trusted reopened expectation");
        assert!(first.authenticates_claim(&claim));
        assert!(
            fre_aot_search_contract::inspect_static_search_span_expectation_v1(first.as_bytes())
                .is_err()
        );
        assert_eq!(
            first.runtime_authority(),
            SelectedEndAotRuntimeAuthorityV2::Absent
        );
    }

    #[test]
    fn every_single_byte_mutation_loses_canonical_expectation_identity() {
        let compiled = compile(b"0123456789abcdef");
        let expectation = build_linux_static_search_selected_end_expectation_v2(&compiled)
            .expect("baseline expectation");
        for offset in 0..expectation.as_bytes().len() {
            let mut changed = *expectation.as_bytes();
            changed[offset] ^= 1;
            assert!(
                inspect_static_search_selected_end_expectation_v2(&changed).is_err(),
                "mutation at byte {offset} was accepted"
            );
            assert!(
                expectation.validate_canonical_bytes(&changed).is_err(),
                "trusted wrapper accepted mutation at byte {offset}"
            );
        }
    }
}
