//! Compiler-side trusted projection for one inert static Search V1 Span object.
//!
//! The only public builder accepts a compiler-sealed
//! [`SearchCompiledObjectV1<Span>`]. It allocation-free reopens that exact
//! Mach-O object, copies the object's canonical metadata bytes, emits the
//! fixed JIT-neutral expectation wire, and asks `fre-aot-search-contract` to
//! inspect the result before returning a trusted wrapper. Contract inspection
//! authenticates bytes only to themselves, so every resulting claim is also
//! compared with the typed compiler receipt.
//!
//! This is build-time evidence only. It does not invoke a linker, name a
//! linked address, inspect a mapped image, grant qualification, or change the
//! explicit [`SearchAotRuntimeAuthorityV1::Absent`] result.

use core::{fmt, mem::size_of};

use fre::SearchExactLiteralAotSemanticBindingIdentity;
use fre_aot_macho::{
    AbiKind, BindingIdentity, CompileIdentity, MetadataV1, ObjectIdentity, ObjectLimits,
};
use fre_aot_search_contract::{
    AOT_SEARCH_COMPILER_VERSION_V1 as CONTRACT_AOT_SEARCH_COMPILER_VERSION_V1,
    AOT_STATIC_SEARCH_SPAN_EXPECTATION_SCHEMA_VERSION_V1, ClaimedSearchMetadataV1,
    ClaimedStaticSearchSpanExpectationV1, MAX_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1,
    MIN_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1, SEARCH_ARCHITECTURE_AARCH64_V1,
    SEARCH_BACKEND_VERSION_V1, SEARCH_CALL_ABI_SCHEMA_V1, SEARCH_DEFAULT_END_ANCHOR_V1,
    SEARCH_DEFAULT_START_ANCHOR_V1, SEARCH_EXPORTED_SYMBOL_N_TYPE_V1,
    SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1, SEARCH_LITTLE_ENDIAN_V1, SEARCH_METADATA_BYTES_V1,
    SEARCH_METADATA_VERSION_V1, SEARCH_PLATFORM_MACOS_V1, SEARCH_POINTER_WIDTH_V1,
    SEARCH_REQUIRED_ASIMD_FEATURES_V1, SEARCH_SPAN_OUTPUT_KIND_V1, SEARCH_STATUS_BITS_V1,
    SEARCH_TARGET_ABI_AAPCS64_V1, STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1,
    STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1,
    STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1,
    STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1,
    StaticSearchSpanExpectationErrorV1 as NeutralExpectationErrorV1,
    StaticSearchSpanExpectationV1 as StaticSearchSpanExpectationWireV1,
    compute_static_search_span_expectation_identity_v1, inspect_static_search_span_expectation_v1,
};
use fre_jit_aarch64::ArtifactIdentity;
use fre_kernel_ir::{CacheIdentity, OutputKind, Span};

use crate::search::{
    AOT_SEARCH_COMPILER_VERSION_V1, MAX_AOT_SEARCH_LITERAL_BYTES_V1,
    MIN_AOT_SEARCH_LITERAL_BYTES_V1, SearchAotRuntimeAuthorityV1, SearchCompileReceiptIdentityV1,
    SearchCompiledObjectV1, SearchLiteralIdentityV1, SearchManifestIdentityV1,
    SearchReceiptValidationErrorV1,
};

const STATIC_SEARCH_SPAN_EXPECTATION_MAGIC_V1: [u8; 8] = *b"FRESSPX\x01";
const EXPECTATION_HEADER_BYTES_V1: usize = 48;
const RECEIPT_IDENTITY_COUNT_V1: usize = 9;

const _: () = assert!(CONTRACT_AOT_SEARCH_COMPILER_VERSION_V1 == AOT_SEARCH_COMPILER_VERSION_V1);
#[allow(
    clippy::as_conversions,
    clippy::cast_lossless,
    reason = "the widening u32-to-u64 cast is exact and keeps this dependency contract compile-time checked"
)]
const _: () =
    assert!(MIN_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1 as u64 == MIN_AOT_SEARCH_LITERAL_BYTES_V1);
#[allow(
    clippy::as_conversions,
    clippy::cast_lossless,
    reason = "the widening u32-to-u64 cast is exact and keeps this dependency contract compile-time checked"
)]
const _: () =
    assert!(MAX_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1 as u64 == MAX_AOT_SEARCH_LITERAL_BYTES_V1);
const _: () = assert!(SEARCH_METADATA_BYTES_V1 == fre_aot_macho::METADATA_BYTES_V1);
const _: () = assert!(
    EXPECTATION_HEADER_BYTES_V1 + (RECEIPT_IDENTITY_COUNT_V1 * 32)
        == STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1
);
const _: () = assert!(
    STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1 + SEARCH_METADATA_BYTES_V1
        == STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1
);
const _: () = assert!(
    STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1 + 32
        == STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1
);

/// The fixed projection itself performs no heap allocations.
///
/// Its object and neutral-contract inspections are also explicitly
/// allocation-free. The returned wrapper owns only fixed-width inline state.
pub const STATIC_SEARCH_SPAN_EXPECTATION_BUILD_ALLOCATIONS_V1: u8 = 0;

/// Trusted inline state retained by one compiler-side Search Span expectation.
pub const STATIC_SEARCH_SPAN_EXPECTATION_RETAINED_BYTES_V1: usize =
    size_of::<StaticSearchSpanExpectationV1>();

/// Domain-separated identity of an exact static Search Span expectation.
///
/// There is deliberately no public constructor from arbitrary digest bytes.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StaticSearchSpanExpectationIdentityV1([u8; 32]);

impl StaticSearchSpanExpectationIdentityV1 {
    const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for StaticSearchSpanExpectationIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "StaticSearchSpanExpectationIdentityV1({self})")
    }
}

impl fmt::Display for StaticSearchSpanExpectationIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Refusal while projecting a trusted compiler result into the neutral wire.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StaticSearchSpanExpectationBuildErrorV1 {
    /// The sealed receipt did not reopen and authenticate its exact object.
    Object(SearchReceiptValidationErrorV1),
    /// A compiler-trusted field disagreed with the fixed Span contract.
    TrustedMismatch { field: &'static str },
    /// The generated wire was not canonical according to the neutral crate.
    NeutralContract(NeutralExpectationErrorV1),
    /// A fixed-width conversion or writer position was not representable.
    WireLayout { at: &'static str },
}

impl fmt::Display for StaticSearchSpanExpectationBuildErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE static Search Span expectation build failed: {self:?}"
        )
    }
}

impl std::error::Error for StaticSearchSpanExpectationBuildErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Object(error) => Some(error),
            Self::NeutralContract(error) => Some(error),
            Self::TrustedMismatch { .. } | Self::WireLayout { .. } => None,
        }
    }
}

impl From<SearchReceiptValidationErrorV1> for StaticSearchSpanExpectationBuildErrorV1 {
    fn from(value: SearchReceiptValidationErrorV1) -> Self {
        Self::Object(value)
    }
}

impl From<NeutralExpectationErrorV1> for StaticSearchSpanExpectationBuildErrorV1 {
    fn from(value: NeutralExpectationErrorV1) -> Self {
        Self::NeutralContract(value)
    }
}

/// Trusted build-time projection of exactly one compiler-sealed Search Span.
///
/// The nine identity fields retain the typed compiler receipt values. The
/// cached wire is a private V1 candidate expectation, not a linker receipt,
/// mapped-image proof, callable handle, or runtime authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticSearchSpanExpectationV1 {
    manifest_identity: SearchManifestIdentityV1,
    semantic_binding_identity: SearchExactLiteralAotSemanticBindingIdentity,
    literal_identity: SearchLiteralIdentityV1,
    live_literal_bytes: u32,
    kir_identity: CacheIdentity,
    artifact_identity: ArtifactIdentity,
    binding_identity: BindingIdentity,
    compile_identity: CompileIdentity,
    object_identity: ObjectIdentity,
    receipt_identity: SearchCompileReceiptIdentityV1,
    metadata: MetadataV1,
    expectation_identity: StaticSearchSpanExpectationIdentityV1,
    wire: StaticSearchSpanExpectationWireV1,
}

impl StaticSearchSpanExpectationV1 {
    #[must_use]
    pub const fn manifest_identity(&self) -> SearchManifestIdentityV1 {
        self.manifest_identity
    }

    #[must_use]
    pub const fn semantic_binding_identity(&self) -> SearchExactLiteralAotSemanticBindingIdentity {
        self.semantic_binding_identity
    }

    #[must_use]
    pub const fn literal_identity(&self) -> SearchLiteralIdentityV1 {
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
    pub const fn receipt_identity(&self) -> SearchCompileReceiptIdentityV1 {
        self.receipt_identity
    }

    #[must_use]
    pub const fn metadata(&self) -> MetadataV1 {
        self.metadata
    }

    #[must_use]
    pub const fn expectation_identity(&self) -> StaticSearchSpanExpectationIdentityV1 {
        self.expectation_identity
    }

    /// Explicitly retain the compiler's lack of deployment authority.
    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }

    /// Borrow the exact canonical 216-byte metadata record copied from the
    /// independently reopened object.
    #[must_use]
    pub fn metadata_bytes_v1(&self) -> &[u8; SEARCH_METADATA_BYTES_V1] {
        self.wire
            .get(
                STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1
                    ..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1,
            )
            .and_then(|bytes| bytes.try_into().ok())
            .expect("fixed trusted expectation metadata range")
    }

    /// Borrow the once-built canonical wire without allocating or rehashing.
    #[must_use]
    pub const fn as_bytes(&self) -> &StaticSearchSpanExpectationWireV1 {
        &self.wire
    }

    /// Compare every neutral claim with the retained trusted compiler values.
    ///
    /// A neutral claim can be internally valid after an attacker rehashes
    /// some fields. It becomes useful to later policy only after this exact
    /// compiler-side comparison and, separately, a private qualification row.
    #[must_use]
    pub fn authenticates_claim(&self, claim: &ClaimedStaticSearchSpanExpectationV1) -> bool {
        claim.schema_version() == AOT_STATIC_SEARCH_SPAN_EXPECTATION_SCHEMA_VERSION_V1
            && claim.compiler_version() == CONTRACT_AOT_SEARCH_COMPILER_VERSION_V1
            && usize::from(claim.metadata_record_bytes()) == SEARCH_METADATA_BYTES_V1
            && claim.metadata_version() == SEARCH_METADATA_VERSION_V1
            && claim.backend_version() == SEARCH_BACKEND_VERSION_V1
            && claim.call_abi_schema() == SEARCH_CALL_ABI_SCHEMA_V1
            && claim.exported_symbol_schema() == SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1
            && claim.output_kind() == SEARCH_SPAN_OUTPUT_KIND_V1
            && !claim.anchor_start()
            && !claim.anchor_end()
            && claim.architecture() == SEARCH_ARCHITECTURE_AARCH64_V1
            && claim.little_endian()
            && claim.pointer_width() == SEARCH_POINTER_WIDTH_V1
            && claim.target_abi() == SEARCH_TARGET_ABI_AAPCS64_V1
            && claim.platform() == SEARCH_PLATFORM_MACOS_V1
            && claim.status_bits() == SEARCH_STATUS_BITS_V1
            && claim.exported_symbol_n_type() == SEARCH_EXPORTED_SYMBOL_N_TYPE_V1
            && claim.required_features() == SEARCH_REQUIRED_ASIMD_FEATURES_V1
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
            && metadata_claim_matches_trusted(claim.metadata(), self.metadata)
    }
}

/// Build the fixed neutral expectation from exactly one compiler-sealed Span.
///
/// The type signature intentionally has no `Exists`, `SelectedEnd`, receipt,
/// metadata, byte-array, or digest-only overload.
pub fn build_static_search_span_expectation_v1(
    compiled: &SearchCompiledObjectV1<Span>,
) -> Result<StaticSearchSpanExpectationV1, StaticSearchSpanExpectationBuildErrorV1> {
    if compiled.runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
        || compiled.receipt().runtime_authority() != SearchAotRuntimeAuthorityV1::Absent
    {
        return Err(trusted_mismatch("runtime authority"));
    }

    let receipt = compiled.receipt();
    if receipt.output() != OutputKind::Span {
        return Err(trusted_mismatch("typed Span receipt"));
    }

    // `validate_object` first re-authenticates the complete private receipt,
    // then allocation-free parses and hashes the exact retained Mach-O bytes.
    let inspection =
        receipt.validate_object(compiled.object().as_bytes(), ObjectLimits::default())?;
    if inspection.metadata() != receipt.metadata()
        || compiled.object().metadata() != receipt.metadata()
        || compiled.object().compile_identity() != receipt.compile_identity()
        || compiled.object().object_identity() != receipt.object_identity()
    {
        return Err(trusted_mismatch("sealed object"));
    }

    let live_literal_bytes = receipt.literal_bytes();
    if !(MIN_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1..=MAX_STATIC_SEARCH_SPAN_LITERAL_BYTES_V1)
        .contains(&live_literal_bytes)
        || receipt.accounting().literal_bytes() != u64::from(live_literal_bytes)
        || receipt.metadata().rodata_bytes() != live_literal_bytes
    {
        return Err(trusted_mismatch("live literal width"));
    }

    let metadata_bytes: &[u8; SEARCH_METADATA_BYTES_V1] = inspection
        .metadata_bytes()
        .try_into()
        .map_err(|_| wire_layout("object metadata bytes"))?;
    let fields = ExpectationFields {
        manifest_identity: *receipt.manifest_identity().as_bytes(),
        semantic_binding_identity: *receipt.semantic_binding_identity().as_bytes(),
        literal_identity: *receipt.literal_identity().as_bytes(),
        kir_identity: *receipt.kir_identity().as_bytes(),
        artifact_identity: *receipt.native_artifact_identity().as_bytes(),
        binding_identity: *receipt.binding_identity().as_bytes(),
        compile_identity: *receipt.compile_identity().as_bytes(),
        object_identity: *receipt.object_identity().as_bytes(),
        receipt_identity: *receipt.receipt_identity().as_bytes(),
        live_literal_bytes,
        metadata_bytes: *metadata_bytes,
    };
    let wire = encode_expectation_wire(&fields)?;
    let claim = inspect_static_search_span_expectation_v1(&wire)?;
    let expectation_identity =
        StaticSearchSpanExpectationIdentityV1::new(*claim.expectation_identity());
    let expectation = StaticSearchSpanExpectationV1 {
        manifest_identity: receipt.manifest_identity(),
        semantic_binding_identity: receipt.semantic_binding_identity(),
        literal_identity: receipt.literal_identity(),
        live_literal_bytes,
        kir_identity: receipt.kir_identity(),
        artifact_identity: receipt.native_artifact_identity(),
        binding_identity: receipt.binding_identity(),
        compile_identity: receipt.compile_identity(),
        object_identity: receipt.object_identity(),
        receipt_identity: receipt.receipt_identity(),
        metadata: receipt.metadata(),
        expectation_identity,
        wire,
    };
    if expectation.metadata_bytes_v1() != metadata_bytes || !expectation.authenticates_claim(&claim)
    {
        return Err(trusted_mismatch("neutral claim"));
    }
    Ok(expectation)
}

fn metadata_claim_matches_trusted(claim: ClaimedSearchMetadataV1, trusted: MetadataV1) -> bool {
    claim.format_version() == trusted.format_version()
        && claim.record_bytes() == trusted.record_bytes()
        && claim.backend_version() == trusted.backend_version()
        && claim.abi_kind()
            == match trusted.abi_kind() {
                AbiKind::Search => 1,
                AbiKind::Aggregate => 2,
            }
        && claim.output_kind() == trusted.output_kind()
        && claim.architecture() == trusted.architecture()
        && claim.little_endian() == trusted.little_endian()
        && claim.pointer_width() == trusted.pointer_width()
        && claim.target_abi() == trusted.target_abi()
        && claim.platform() == trusted.platform()
        && claim.status_bits() == trusted.status_bits()
        && claim.abi_schema() == trusted.abi_schema()
        && claim.features() == trusted.features()
        && claim.payload_bytes() == trusted.payload_bytes()
        && claim.entry_offset() == trusted.entry_offset()
        && claim.code_bytes() == trusted.code_bytes()
        && claim.rodata_offset() == trusted.rodata_offset()
        && claim.rodata_bytes() == trusted.rodata_bytes()
        && claim.literal_bytes() == trusted.literal_bytes()
        && claim.source_identity() == trusted.source_identity()
        && claim.artifact_identity() == trusted.artifact_identity()
        && claim.binding_identity() == trusted.claimed_binding_identity().as_bytes()
        && claim.payload_sha256() == trusted.payload_sha256()
        && claim.compile_identity() == trusted.claimed_compile_identity().as_bytes()
}

#[derive(Clone, Copy)]
struct ExpectationFields {
    manifest_identity: [u8; 32],
    semantic_binding_identity: [u8; 32],
    literal_identity: [u8; 32],
    kir_identity: [u8; 32],
    artifact_identity: [u8; 32],
    binding_identity: [u8; 32],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    receipt_identity: [u8; 32],
    live_literal_bytes: u32,
    metadata_bytes: [u8; SEARCH_METADATA_BYTES_V1],
}

fn encode_expectation_wire(
    fields: &ExpectationFields,
) -> Result<StaticSearchSpanExpectationWireV1, StaticSearchSpanExpectationBuildErrorV1> {
    let mut wire = [0_u8; STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1];
    {
        let mut writer = FixedWriter::new(&mut wire);
        writer.bytes(&STATIC_SEARCH_SPAN_EXPECTATION_MAGIC_V1)?;
        writer.u16(AOT_STATIC_SEARCH_SPAN_EXPECTATION_SCHEMA_VERSION_V1)?;
        writer.u16(CONTRACT_AOT_SEARCH_COMPILER_VERSION_V1)?;
        writer.u32(
            u32::try_from(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1)
                .map_err(|_| wire_layout("expectation record bytes"))?,
        )?;
        writer.u16(
            u16::try_from(SEARCH_METADATA_BYTES_V1)
                .map_err(|_| wire_layout("metadata record bytes"))?,
        )?;
        writer.u16(SEARCH_METADATA_VERSION_V1)?;
        writer.u16(SEARCH_BACKEND_VERSION_V1)?;
        writer.u16(SEARCH_CALL_ABI_SCHEMA_V1)?;
        writer.u16(SEARCH_EXPORTED_SYMBOL_SCHEMA_VERSION_V1)?;
        writer.u8(SEARCH_SPAN_OUTPUT_KIND_V1)?;
        writer.u8(SEARCH_DEFAULT_START_ANCHOR_V1)?;
        writer.u8(SEARCH_DEFAULT_END_ANCHOR_V1)?;
        writer.u8(SEARCH_ARCHITECTURE_AARCH64_V1)?;
        writer.u8(SEARCH_LITTLE_ENDIAN_V1)?;
        writer.u8(SEARCH_POINTER_WIDTH_V1)?;
        writer.u8(SEARCH_TARGET_ABI_AAPCS64_V1)?;
        writer.u8(SEARCH_PLATFORM_MACOS_V1)?;
        writer.u8(SEARCH_STATUS_BITS_V1)?;
        writer.u8(SEARCH_EXPORTED_SYMBOL_N_TYPE_V1)?;
        writer.u64(SEARCH_REQUIRED_ASIMD_FEATURES_V1)?;
        writer.u32(fields.live_literal_bytes)?;
        for identity in [
            &fields.manifest_identity,
            &fields.semantic_binding_identity,
            &fields.literal_identity,
            &fields.kir_identity,
            &fields.artifact_identity,
            &fields.binding_identity,
            &fields.compile_identity,
            &fields.object_identity,
            &fields.receipt_identity,
        ] {
            writer.bytes(identity)?;
        }
        if writer.position() != STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1 {
            return Err(wire_layout("metadata offset"));
        }
        writer.bytes(&fields.metadata_bytes)?;
        if writer.position() != STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1 {
            return Err(wire_layout("expectation identity offset"));
        }
    }

    let body: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1] = wire
        .get(..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| wire_layout("expectation identity body"))?;
    let expectation_identity = compute_static_search_span_expectation_identity_v1(body);
    wire.get_mut(STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1..)
        .ok_or_else(|| wire_layout("expectation identity destination"))?
        .copy_from_slice(&expectation_identity);
    Ok(wire)
}

struct FixedWriter<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> FixedWriter<'a> {
    const fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), StaticSearchSpanExpectationBuildErrorV1> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or_else(|| wire_layout("writer arithmetic"))?;
        self.bytes
            .get_mut(self.position..end)
            .ok_or_else(|| wire_layout("writer bounds"))?
            .copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), StaticSearchSpanExpectationBuildErrorV1> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), StaticSearchSpanExpectationBuildErrorV1> {
        self.bytes(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), StaticSearchSpanExpectationBuildErrorV1> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), StaticSearchSpanExpectationBuildErrorV1> {
        self.bytes(&value.to_le_bytes())
    }

    const fn position(&self) -> usize {
        self.position
    }
}

const fn trusted_mismatch(field: &'static str) -> StaticSearchSpanExpectationBuildErrorV1 {
    StaticSearchSpanExpectationBuildErrorV1::TrustedMismatch { field }
}

const fn wire_layout(at: &'static str) -> StaticSearchSpanExpectationBuildErrorV1 {
    StaticSearchSpanExpectationBuildErrorV1::WireLayout { at }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fre::RustProfile;
    use fre_aot_search_contract::inspect_search_metadata_v1;
    use sha2::{Digest, Sha256};

    use crate::search::{
        MacosAarch64ExactSearchManifestV1, plan_and_compile_macos_aarch64_exact_search_v1,
    };

    const EXPECTED_FIXTURE_COMPILE_IDENTITY: [u8; 32] = [
        0xb2, 0x87, 0xe0, 0xda, 0xcb, 0x82, 0x82, 0x4e, 0xcf, 0x8f, 0x0d, 0xe4, 0x5b, 0xf7, 0x1f,
        0x0c, 0x8d, 0x4e, 0x0e, 0x58, 0xb8, 0xc0, 0xcd, 0x16, 0xf4, 0x95, 0xc0, 0x7a, 0x77, 0x57,
        0x9d, 0x93,
    ];
    const EXPECTED_FIXTURE_EXPECTATION_IDENTITY: [u8; 32] = [
        0xf6, 0xb6, 0x15, 0xac, 0xa7, 0x39, 0x21, 0x5f, 0xfe, 0x2b, 0xfd, 0x43, 0xf6, 0x68, 0xfa,
        0xc9, 0x35, 0xc6, 0x13, 0xd8, 0x2d, 0xb6, 0xd2, 0x19, 0x7b, 0x0e, 0xbf, 0xdd, 0x29, 0x80,
        0xda, 0x90,
    ];
    const EXPECTED_FIXTURE_WIRE_SHA256: [u8; 32] = [
        0x76, 0x8e, 0x83, 0x83, 0x8d, 0xb9, 0xef, 0x4c, 0x78, 0xce, 0xca, 0xc8, 0x95, 0x9a, 0x55,
        0xa0, 0x98, 0x3d, 0x41, 0x77, 0x69, 0xa2, 0x95, 0xa2, 0x40, 0xd6, 0x1e, 0x6e, 0x5b, 0x69,
        0xda, 0xfb,
    ];

    fn compile_span(literal: &[u8]) -> SearchCompiledObjectV1<Span> {
        plan_and_compile_macos_aarch64_exact_search_v1(
            MacosAarch64ExactSearchManifestV1::<Span>::default(),
            literal.to_vec(),
            RustProfile::default(),
        )
        .expect("inert exact Search Span object")
    }

    fn fixture_metadata() -> [u8; SEARCH_METADATA_BYTES_V1] {
        let mut metadata = [0_u8; SEARCH_METADATA_BYTES_V1];
        let mut writer = FixedWriter::new(&mut metadata);
        writer.bytes(b"FREOM64\x01").unwrap();
        writer.u16(SEARCH_METADATA_VERSION_V1).unwrap();
        writer
            .u16(u16::try_from(SEARCH_METADATA_BYTES_V1).unwrap())
            .unwrap();
        writer.u16(SEARCH_BACKEND_VERSION_V1).unwrap();
        writer.u8(1).unwrap();
        writer.u8(SEARCH_SPAN_OUTPUT_KIND_V1).unwrap();
        writer.u8(SEARCH_ARCHITECTURE_AARCH64_V1).unwrap();
        writer.u8(SEARCH_LITTLE_ENDIAN_V1).unwrap();
        writer.u8(SEARCH_POINTER_WIDTH_V1).unwrap();
        writer.u8(SEARCH_TARGET_ABI_AAPCS64_V1).unwrap();
        writer.u8(SEARCH_PLATFORM_MACOS_V1).unwrap();
        writer.u8(SEARCH_STATUS_BITS_V1).unwrap();
        writer.u16(SEARCH_CALL_ABI_SCHEMA_V1).unwrap();
        writer.u64(SEARCH_REQUIRED_ASIMD_FEATURES_V1).unwrap();
        writer.u32(256).unwrap();
        writer.u32(0).unwrap();
        writer.u32(240).unwrap();
        writer.u32(240).unwrap();
        writer.u32(16).unwrap();
        writer.u32(0).unwrap();
        writer.bytes(&[0x11; 32]).unwrap();
        writer.bytes(&[0x22; 32]).unwrap();
        writer.bytes(&[0x33; 32]).unwrap();
        writer.bytes(&[0x44; 32]).unwrap();
        writer.bytes(&EXPECTED_FIXTURE_COMPILE_IDENTITY).unwrap();
        assert_eq!(writer.position(), SEARCH_METADATA_BYTES_V1);
        metadata
    }

    fn fixture_wire() -> StaticSearchSpanExpectationWireV1 {
        let metadata = fixture_metadata();
        encode_expectation_wire(&ExpectationFields {
            manifest_identity: [0x51; 32],
            semantic_binding_identity: [0x52; 32],
            literal_identity: [0x53; 32],
            kir_identity: [0x11; 32],
            artifact_identity: [0x22; 32],
            binding_identity: [0x33; 32],
            compile_identity: EXPECTED_FIXTURE_COMPILE_IDENTITY,
            object_identity: [0x58; 32],
            receipt_identity: [0x59; 32],
            live_literal_bytes: 16,
            metadata_bytes: metadata,
        })
        .unwrap()
    }

    fn refresh_identity(wire: &mut StaticSearchSpanExpectationWireV1) {
        let body: &[u8; STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_BODY_BYTES_V1] = wire
            .get(..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1)
            .unwrap()
            .try_into()
            .unwrap();
        let identity = compute_static_search_span_expectation_identity_v1(body);
        wire[STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1..].copy_from_slice(&identity);
    }

    #[test]
    fn independent_known_vector_pins_the_exact_neutral_wire() {
        let metadata = fixture_metadata();
        assert_eq!(
            inspect_search_metadata_v1(&metadata)
                .unwrap()
                .compile_identity(),
            &EXPECTED_FIXTURE_COMPILE_IDENTITY
        );
        let wire = fixture_wire();
        assert_eq!(
            &wire[STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1..],
            &EXPECTED_FIXTURE_EXPECTATION_IDENTITY
        );
        let claim = inspect_static_search_span_expectation_v1(&wire).unwrap();
        assert_eq!(claim.manifest_identity(), &[0x51; 32]);
        assert_eq!(claim.semantic_binding_identity(), &[0x52; 32]);
        assert_eq!(claim.literal_identity(), &[0x53; 32]);
        assert_eq!(claim.kir_identity(), &[0x11; 32]);
        assert_eq!(claim.artifact_identity(), &[0x22; 32]);
        assert_eq!(claim.binding_identity(), &[0x33; 32]);
        assert_eq!(claim.compile_identity(), &EXPECTED_FIXTURE_COMPILE_IDENTITY);
        assert_eq!(claim.object_identity(), &[0x58; 32]);
        assert_eq!(claim.receipt_identity(), &[0x59; 32]);
    }

    #[test]
    fn compiler_sealed_span_projects_deterministically_and_remains_inert() {
        let compiled = compile_span(b"needle");
        let first = build_static_search_span_expectation_v1(&compiled).unwrap();
        let second = build_static_search_span_expectation_v1(&compiled).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );
        assert_eq!(STATIC_SEARCH_SPAN_EXPECTATION_BUILD_ALLOCATIONS_V1, 0);
        assert_eq!(
            first.as_bytes().len(),
            STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1
        );
        assert_eq!(
            first.metadata_bytes_v1(),
            compiled
                .receipt()
                .validate_object(compiled.object().as_bytes(), ObjectLimits::default())
                .unwrap()
                .metadata_bytes()
        );
        let claim = inspect_static_search_span_expectation_v1(first.as_bytes()).unwrap();
        assert!(first.authenticates_claim(&claim));
    }

    #[test]
    fn all_nine_receipt_identities_are_exact_and_splices_never_authenticate() {
        let expectation =
            build_static_search_span_expectation_v1(&compile_span(b"needle")).unwrap();
        let claim = inspect_static_search_span_expectation_v1(expectation.as_bytes()).unwrap();
        assert_eq!(
            claim.manifest_identity(),
            expectation.manifest_identity().as_bytes()
        );
        assert_eq!(
            claim.semantic_binding_identity(),
            expectation.semantic_binding_identity().as_bytes()
        );
        assert_eq!(
            claim.literal_identity(),
            expectation.literal_identity().as_bytes()
        );
        assert_eq!(claim.kir_identity(), expectation.kir_identity().as_bytes());
        assert_eq!(
            claim.artifact_identity(),
            expectation.artifact_identity().as_bytes()
        );
        assert_eq!(
            claim.binding_identity(),
            expectation.binding_identity().as_bytes()
        );
        assert_eq!(
            claim.compile_identity(),
            expectation.compile_identity().as_bytes()
        );
        assert_eq!(
            claim.object_identity(),
            expectation.object_identity().as_bytes()
        );
        assert_eq!(
            claim.receipt_identity(),
            expectation.receipt_identity().as_bytes()
        );

        let mut internally_valid_splices = 0;
        for offset in (48..336).step_by(32) {
            let mut splice = *expectation.as_bytes();
            splice[offset] ^= 1;
            refresh_identity(&mut splice);
            if let Ok(spliced_claim) = inspect_static_search_span_expectation_v1(&splice) {
                internally_valid_splices += 1;
                assert!(!expectation.authenticates_claim(&spliced_claim));
            }
        }
        assert_eq!(
            internally_valid_splices, 5,
            "manifest, semantic, literal, object, and receipt claims are neutral until compared"
        );
    }

    #[test]
    fn every_wire_byte_is_bound_and_object_metadata_is_copied_exactly() {
        let compiled = compile_span(b"0123456789abcdef");
        let expectation = build_static_search_span_expectation_v1(&compiled).unwrap();
        let inspection = compiled
            .receipt()
            .validate_object(compiled.object().as_bytes(), ObjectLimits::default())
            .unwrap();
        assert_eq!(expectation.metadata_bytes_v1(), inspection.metadata_bytes());
        assert_eq!(
            &expectation.as_bytes()[..8],
            &STATIC_SEARCH_SPAN_EXPECTATION_MAGIC_V1
        );
        assert_eq!(
            &expectation.as_bytes()[STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1
                ..STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1],
            inspection.metadata_bytes()
        );

        for index in 0..STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1 {
            let mut mutated = *expectation.as_bytes();
            mutated[index] ^= 1;
            assert!(
                inspect_static_search_span_expectation_v1(&mutated).is_err(),
                "byte {index} was not bound"
            );
        }
    }

    #[test]
    fn admitted_literal_boundaries_are_preserved_in_header_and_metadata() {
        for literal in [&b"x"[..], &b"0123456789abcdef0123456789abcdef"[..]] {
            let expectation =
                build_static_search_span_expectation_v1(&compile_span(literal)).unwrap();
            let claim = inspect_static_search_span_expectation_v1(expectation.as_bytes()).unwrap();
            assert_eq!(
                usize::try_from(claim.live_literal_bytes()).unwrap(),
                literal.len()
            );
            assert_eq!(
                usize::try_from(claim.metadata().rodata_bytes()).unwrap(),
                literal.len()
            );
            assert!(expectation.authenticates_claim(&claim));
        }
    }

    #[test]
    fn layout_constants_and_full_wire_digest_are_stable() {
        assert_eq!(EXPECTATION_HEADER_BYTES_V1, 48);
        assert_eq!(STATIC_SEARCH_SPAN_EXPECTATION_METADATA_OFFSET_V1, 336);
        assert_eq!(STATIC_SEARCH_SPAN_EXPECTATION_IDENTITY_OFFSET_V1, 552);
        assert_eq!(STATIC_SEARCH_SPAN_EXPECTATION_BYTES_V1, 584);
        let digest: [u8; 32] = Sha256::digest(fixture_wire()).into();
        assert_eq!(digest, EXPECTED_FIXTURE_WIRE_SHA256);
    }
}
