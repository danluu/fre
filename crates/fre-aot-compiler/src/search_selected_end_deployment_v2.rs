//! Deterministic Rust consumer binding and default-off public adopter facade
//! for one exact Linux tag21 `SelectedEnd` ABI2 bundle.
//!
//! The P2b implementation object and direct-glue object are already the real
//! AOT boundary. This module does not add an address adopter. Instead it emits
//! an exact identity-suffixed `extern` declaration whose four-argument call is
//! visible to the static linker, and requires the default-off static-runtime
//! same-thread session token. The generated safe boundary binds the exact
//! portable literal plan and one private compile-identity key once, consumes
//! and encloses that thread session in a field-private nominal type, then
//! uses only plan pointer identity on repeated preflighted calls. The generated
//! public seam submits every non-circular compiler, expectation, full-payload,
//! and direct-glue identity to the static runtime's private production table
//! and otherwise returns a typed portable fallback. It accepts no caller
//! address, symbol, selector, callback, or authority value. A companion
//! signer-free receipt binds the generated source itself to that complete
//! tuple.
//!
//! This source atom remains diagnostic-only because the runtime production
//! table is empty. The generated source, deployment value, and receipt carry
//! no production or runtime authority. A future source-reviewed row still
//! requires an independent post-link observation proving the retained
//! mechanics callsite's direct `bl`, its proof-scope no-`blr`/x4 contract,
//! exact hidden symbols, byte-for-byte full payload and metadata, and non-RWX
//! load segments. The actual hot consumer callsite remains a separate,
//! consumer-specific proof obligation.

use core::{fmt, fmt::Write as _};

use fre_aot_elf::HARD_MAX_SELECTED_END_PAYLOAD_BYTES_V2;
use fre_aot_search_contract::selected_end_v2::{
    SEARCH_SELECTED_END_ARGUMENT_COUNT_V2, SEARCH_SELECTED_END_BACKEND_TAG21_V2,
    SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2, SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2,
    SEARCH_SELECTED_END_LITERAL_BYTES_V2, SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2,
    SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2,
};
use sha2::{Digest, Sha256};

use crate::{
    LinuxSelectedEndDirectGlueErrorV2, LinuxSelectedEndDirectGlueLimitsV2,
    LinuxSelectedEndQualificationBundleV2, POST_LINK_DISASSEMBLY_REQUIREMENTS_V2,
    SelectedEndAotRuntimeAuthorityV2,
};

pub const HARD_MAX_LINUX_SELECTED_END_QUALIFICATION_RUST_BINDING_BYTES_V2: u64 = 256 << 10;
pub const LINUX_SELECTED_END_QUALIFICATION_DEPLOYMENT_RECEIPT_BYTES_V2: usize = 672;

const DEPLOYMENT_RECEIPT_SCHEMA_VERSION_V2: u16 = 2;
const DEPLOYMENT_RECEIPT_MAGIC_V2: [u8; 8] = *b"FRESDP\0\x02";
const DEPLOYMENT_RECEIPT_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-QUALIFICATION-DEPLOYMENT-RECEIPT\0\x02";
const RUST_BINDING_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-QUALIFICATION-RUST-BINDING\0\x02";
const PRIMARY_CALLSITE_SYMBOL_PREFIX_V2: &str =
    "fre_aot_search_selected_end_qualification_primary_callsite_v2_";

const RECEIPT_IDENTITIES_OFFSET_V2: usize = 64;
const RECEIPT_IDENTITY_COUNT_WITHOUT_SELF_V2: usize = 18;
const RECEIPT_IDENTITY_OFFSET_V2: usize =
    RECEIPT_IDENTITIES_OFFSET_V2 + (RECEIPT_IDENTITY_COUNT_WITHOUT_SELF_V2 * 32);

const MANIFEST_IDENTITY_INDEX_V2: usize = 0;
const SOURCE_IDENTITY_INDEX_V2: usize = 1;
const SEMANTIC_BINDING_IDENTITY_INDEX_V2: usize = 2;
const LITERAL_IDENTITY_INDEX_V2: usize = 3;
const KIR_IDENTITY_INDEX_V2: usize = 4;
const ARTIFACT_IDENTITY_INDEX_V2: usize = 5;
const BINDING_IDENTITY_INDEX_V2: usize = 6;
const COMPILE_IDENTITY_INDEX_V2: usize = 7;
const IMPLEMENTATION_OBJECT_IDENTITY_INDEX_V2: usize = 8;
const COMPILER_RECEIPT_IDENTITY_INDEX_V2: usize = 9;
const EXPECTATION_IDENTITY_INDEX_V2: usize = 10;
const FULL_PAYLOAD_IDENTITY_INDEX_V2: usize = 11;
const GLUE_SOURCE_IDENTITY_INDEX_V2: usize = 12;
const DIRECT_HEADER_IDENTITY_INDEX_V2: usize = 13;
const GLUE_CODE_IDENTITY_INDEX_V2: usize = 14;
const GLUE_OBJECT_IDENTITY_INDEX_V2: usize = 15;
const BUNDLE_IDENTITY_INDEX_V2: usize = 16;
const RUST_BINDING_IDENTITY_INDEX_V2: usize = 17;

const _: () = assert!(SEARCH_SELECTED_END_ARGUMENT_COUNT_V2 == 4);
const _: () = assert!(SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2 == 0);
const _: () = assert!(SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2 == 0);
const _: () = assert!(SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2 == 16);
const _: () = assert!(RECEIPT_IDENTITY_OFFSET_V2 == 640);
const _: () = assert!(
    RECEIPT_IDENTITY_OFFSET_V2 + 32 == LINUX_SELECTED_END_QUALIFICATION_DEPLOYMENT_RECEIPT_BYTES_V2
);

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
    LinuxSelectedEndQualificationRustBindingIdentityV2,
    "LinuxSelectedEndQualificationRustBindingIdentityV2"
);
identity!(
    LinuxSelectedEndQualificationDeploymentReceiptIdentityV2,
    "LinuxSelectedEndQualificationDeploymentReceiptIdentityV2"
);

macro_rules! identity_getter {
    ($name:ident, $index:ident) => {
        #[must_use]
        pub fn $name(&self) -> &[u8; 32] {
            self.identity_at($index)
        }
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndQualificationDeploymentLimitsV2 {
    pub direct_glue: LinuxSelectedEndDirectGlueLimitsV2,
    pub max_rust_binding_bytes: u64,
}

impl Default for LinuxSelectedEndQualificationDeploymentLimitsV2 {
    fn default() -> Self {
        Self {
            direct_glue: LinuxSelectedEndDirectGlueLimitsV2::default(),
            max_rust_binding_bytes: HARD_MAX_LINUX_SELECTED_END_QUALIFICATION_RUST_BINDING_BYTES_V2,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum LinuxSelectedEndQualificationDeploymentErrorV2 {
    Bundle(LinuxSelectedEndDirectGlueErrorV2),
    ResourceLimit { limit: u64, required: u64 },
    Render,
    InvalidBinding,
    InvalidReceipt,
}

impl fmt::Display for LinuxSelectedEndQualificationDeploymentErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Linux SelectedEnd ABI2 qualification deployment failed: {self:?}"
        )
    }
}

impl std::error::Error for LinuxSelectedEndQualificationDeploymentErrorV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bundle(error) => Some(error),
            Self::ResourceLimit { .. }
            | Self::Render
            | Self::InvalidBinding
            | Self::InvalidReceipt => None,
        }
    }
}

impl From<LinuxSelectedEndDirectGlueErrorV2> for LinuxSelectedEndQualificationDeploymentErrorV2 {
    fn from(error: LinuxSelectedEndDirectGlueErrorV2) -> Self {
        Self::Bundle(error)
    }
}

/// Canonical generated Rust module containing the exact direct symbol calls.
#[derive(Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndQualificationRustBindingV2 {
    bytes: Box<[u8]>,
    identity: LinuxSelectedEndQualificationRustBindingIdentityV2,
    primary_callsite_symbol: Box<str>,
}

impl LinuxSelectedEndQualificationRustBindingV2 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes).expect("canonical SelectedEnd ABI2 Rust binding is UTF-8")
    }

    #[must_use]
    pub const fn identity(&self) -> LinuxSelectedEndQualificationRustBindingIdentityV2 {
        self.identity
    }

    /// Exact hidden generated proof-callsite symbol that a qualification link
    /// must retain for post-link inspection.
    #[must_use]
    pub fn primary_callsite_symbol(&self) -> &str {
        &self.primary_callsite_symbol
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }
}

/// Signer-free receipt for the exact generated consumer binding.
///
/// The receipt is an authenticated correlation record, not a signature or an
/// authority grant. Validation against the trusted P2b bundle regenerates the
/// source and compares every identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndQualificationDeploymentReceiptV2 {
    bytes: [u8; LINUX_SELECTED_END_QUALIFICATION_DEPLOYMENT_RECEIPT_BYTES_V2],
}

impl LinuxSelectedEndQualificationDeploymentReceiptV2 {
    #[must_use]
    pub const fn canonical_bytes(
        &self,
    ) -> &[u8; LINUX_SELECTED_END_QUALIFICATION_DEPLOYMENT_RECEIPT_BYTES_V2] {
        &self.bytes
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
    ) -> Result<Self, LinuxSelectedEndQualificationDeploymentErrorV2> {
        let bytes: [u8; LINUX_SELECTED_END_QUALIFICATION_DEPLOYMENT_RECEIPT_BYTES_V2] = bytes
            .try_into()
            .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::InvalidReceipt)?;
        let receipt = Self { bytes };
        if !receipt.authenticates_itself() {
            return Err(LinuxSelectedEndQualificationDeploymentErrorV2::InvalidReceipt);
        }
        Ok(receipt)
    }

    #[must_use]
    pub fn authenticates_itself(&self) -> bool {
        self.bytes[..8] == DEPLOYMENT_RECEIPT_MAGIC_V2
            && self.bytes[8..10] == DEPLOYMENT_RECEIPT_SCHEMA_VERSION_V2.to_le_bytes()
            && self.bytes[10..12] == crate::AOT_LINUX_SELECTED_END_COMPILER_VERSION_V2.to_le_bytes()
            && self.bytes[12..16]
                == u32::try_from(LINUX_SELECTED_END_QUALIFICATION_DEPLOYMENT_RECEIPT_BYTES_V2)
                    .expect("fixed deployment receipt bytes")
                    .to_le_bytes()
            && self.rust_binding_bytes() > 0
            && self.rust_binding_bytes()
                <= HARD_MAX_LINUX_SELECTED_END_QUALIFICATION_RUST_BINDING_BYTES_V2
            && self.bytes[20] == SEARCH_SELECTED_END_ARGUMENT_COUNT_V2
            && self.bytes[21] == SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2
            && self.bytes[22..24] == SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2.to_le_bytes()
            && self.bytes[24..26] == SEARCH_SELECTED_END_BACKEND_TAG21_V2.to_le_bytes()
            && self.bytes[26..28] == SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2.to_le_bytes()
            && self.bytes[28..30] == SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2.to_le_bytes()
            && self.bytes[30] == 0
            && self.bytes[31] == 2
            && self.bytes[32..36] == POST_LINK_DISASSEMBLY_REQUIREMENTS_V2.to_le_bytes()
            && self.bytes[36..40] == SEARCH_SELECTED_END_LITERAL_BYTES_V2.to_le_bytes()
            && self.full_payload_bytes() > 0
            && self.full_payload_bytes() <= HARD_MAX_SELECTED_END_PAYLOAD_BYTES_V2
            && self.bytes[44..46]
                == u16::try_from(RECEIPT_IDENTITY_COUNT_WITHOUT_SELF_V2)
                    .expect("fixed deployment identity count")
                    .to_le_bytes()
            && self.bytes[46..64] == [0; 18]
            && (0..RECEIPT_IDENTITY_COUNT_WITHOUT_SELF_V2)
                .all(|index| self.identity_at(index) != &[0; 32])
            && digest_with_domain(
                DEPLOYMENT_RECEIPT_IDENTITY_DOMAIN_V2,
                &self.bytes[..RECEIPT_IDENTITY_OFFSET_V2],
            ) == *self.receipt_identity().as_bytes()
    }

    #[must_use]
    pub fn rust_binding_bytes(&self) -> u64 {
        u64::from(u32::from_le_bytes(
            self.bytes[16..20]
                .try_into()
                .expect("fixed Rust binding bytes field"),
        ))
    }

    #[must_use]
    pub fn full_payload_bytes(&self) -> u64 {
        u64::from(u32::from_le_bytes(
            self.bytes[40..44]
                .try_into()
                .expect("fixed full payload bytes field"),
        ))
    }

    identity_getter!(manifest_identity, MANIFEST_IDENTITY_INDEX_V2);
    identity_getter!(source_identity, SOURCE_IDENTITY_INDEX_V2);
    identity_getter!(
        semantic_binding_identity,
        SEMANTIC_BINDING_IDENTITY_INDEX_V2
    );
    identity_getter!(literal_identity, LITERAL_IDENTITY_INDEX_V2);
    identity_getter!(kir_identity, KIR_IDENTITY_INDEX_V2);
    identity_getter!(artifact_identity, ARTIFACT_IDENTITY_INDEX_V2);
    identity_getter!(binding_identity, BINDING_IDENTITY_INDEX_V2);
    identity_getter!(compile_identity, COMPILE_IDENTITY_INDEX_V2);
    identity_getter!(
        implementation_object_identity,
        IMPLEMENTATION_OBJECT_IDENTITY_INDEX_V2
    );
    identity_getter!(
        compiler_receipt_identity,
        COMPILER_RECEIPT_IDENTITY_INDEX_V2
    );
    identity_getter!(expectation_identity, EXPECTATION_IDENTITY_INDEX_V2);
    identity_getter!(full_payload_identity, FULL_PAYLOAD_IDENTITY_INDEX_V2);

    #[must_use]
    pub fn glue_source_identity(&self) -> &[u8; 32] {
        self.identity_at(GLUE_SOURCE_IDENTITY_INDEX_V2)
    }

    #[must_use]
    pub fn direct_header_identity(&self) -> &[u8; 32] {
        self.identity_at(DIRECT_HEADER_IDENTITY_INDEX_V2)
    }

    #[must_use]
    pub fn glue_code_identity(&self) -> &[u8; 32] {
        self.identity_at(GLUE_CODE_IDENTITY_INDEX_V2)
    }

    #[must_use]
    pub fn glue_object_identity(&self) -> &[u8; 32] {
        self.identity_at(GLUE_OBJECT_IDENTITY_INDEX_V2)
    }

    #[must_use]
    pub fn bundle_identity(&self) -> &[u8; 32] {
        self.identity_at(BUNDLE_IDENTITY_INDEX_V2)
    }

    #[must_use]
    pub fn rust_binding_identity(&self) -> LinuxSelectedEndQualificationRustBindingIdentityV2 {
        LinuxSelectedEndQualificationRustBindingIdentityV2::new(
            *self.identity_at(RUST_BINDING_IDENTITY_INDEX_V2),
        )
    }

    #[must_use]
    pub fn receipt_identity(&self) -> LinuxSelectedEndQualificationDeploymentReceiptIdentityV2 {
        LinuxSelectedEndQualificationDeploymentReceiptIdentityV2::new(
            *self
                .bytes
                .get(RECEIPT_IDENTITY_OFFSET_V2..RECEIPT_IDENTITY_OFFSET_V2 + 32)
                .and_then(|bytes| bytes.try_into().ok())
                .expect("fixed deployment receipt identity range"),
        )
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }

    fn identity_at(&self, index: usize) -> &[u8; 32] {
        let offset = RECEIPT_IDENTITIES_OFFSET_V2 + (index * 32);
        self.bytes
            .get(offset..offset + 32)
            .and_then(|bytes| bytes.try_into().ok())
            .expect("fixed deployment receipt identity range")
    }

    /// Revalidate separately persisted generated source against one trusted,
    /// fully validated P2b bundle.
    ///
    /// This is a correlation check only and grants no call or deployment
    /// authority.
    pub fn validate_candidate(
        &self,
        bundle: &LinuxSelectedEndQualificationBundleV2,
        binding_bytes: &[u8],
        limits: LinuxSelectedEndQualificationDeploymentLimitsV2,
    ) -> Result<(), LinuxSelectedEndQualificationDeploymentErrorV2> {
        bundle.validate(limits.direct_glue)?;
        let claims = DeploymentClaimsV2::from_bundle(bundle);
        let binding_identity = LinuxSelectedEndQualificationRustBindingIdentityV2::new(
            length_prefixed_identity(RUST_BINDING_IDENTITY_DOMAIN_V2, binding_bytes),
        );
        if !self.authenticates_itself()
            || self.runtime_authority() != SelectedEndAotRuntimeAuthorityV2::Absent
            || self.rust_binding_bytes() != usize_u64(binding_bytes.len())?
            || self.full_payload_bytes() != u64::from(claims.full_payload_bytes)
            || self.rust_binding_identity() != binding_identity
            || !self.matches_claims(&claims)
        {
            return Err(LinuxSelectedEndQualificationDeploymentErrorV2::InvalidReceipt);
        }
        let regenerated = render_rust_binding(&claims, limits)?;
        if regenerated.as_bytes() != binding_bytes || regenerated.identity() != binding_identity {
            return Err(LinuxSelectedEndQualificationDeploymentErrorV2::InvalidBinding);
        }
        Ok(())
    }

    fn matches_claims(&self, claims: &DeploymentClaimsV2) -> bool {
        self.manifest_identity() == &claims.manifest_identity
            && self.source_identity() == &claims.source_identity
            && self.semantic_binding_identity() == &claims.semantic_binding_identity
            && self.literal_identity() == &claims.literal_identity
            && self.kir_identity() == &claims.kir_identity
            && self.artifact_identity() == &claims.artifact_identity
            && self.binding_identity() == &claims.binding_identity
            && self.compile_identity() == &claims.compile_identity
            && self.implementation_object_identity() == &claims.implementation_object_identity
            && self.compiler_receipt_identity() == &claims.compiler_receipt_identity
            && self.expectation_identity() == &claims.expectation_identity
            && self.full_payload_identity() == &claims.full_payload_identity
            && self.glue_source_identity() == &claims.glue_source_identity
            && self.direct_header_identity() == &claims.direct_header_identity
            && self.glue_code_identity() == &claims.glue_code_identity
            && self.glue_object_identity() == &claims.glue_object_identity
            && self.bundle_identity() == &claims.bundle_identity
    }
}

/// Generated public-adopter consumer source plus its authenticated correlation
/// receipt.
///
/// The deployment value remains authority-free; only a separately reviewed
/// static-runtime production row can activate its native facade.
#[derive(Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndQualificationDeploymentV2 {
    binding: LinuxSelectedEndQualificationRustBindingV2,
    receipt: LinuxSelectedEndQualificationDeploymentReceiptV2,
}

impl LinuxSelectedEndQualificationDeploymentV2 {
    #[must_use]
    pub const fn binding(&self) -> &LinuxSelectedEndQualificationRustBindingV2 {
        &self.binding
    }

    #[must_use]
    pub const fn receipt(&self) -> &LinuxSelectedEndQualificationDeploymentReceiptV2 {
        &self.receipt
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }

    pub fn validate(
        &self,
        bundle: &LinuxSelectedEndQualificationBundleV2,
        limits: LinuxSelectedEndQualificationDeploymentLimitsV2,
    ) -> Result<(), LinuxSelectedEndQualificationDeploymentErrorV2> {
        self.receipt
            .validate_candidate(bundle, self.binding.as_bytes(), limits)
    }
}

/// Generate the reusable public-adopter and qualification-private consumer
/// binding for one exact validated P2b bundle.
pub fn build_linux_selected_end_qualification_deployment_v2(
    bundle: &LinuxSelectedEndQualificationBundleV2,
    limits: LinuxSelectedEndQualificationDeploymentLimitsV2,
) -> Result<LinuxSelectedEndQualificationDeploymentV2, LinuxSelectedEndQualificationDeploymentErrorV2>
{
    bundle.validate(limits.direct_glue)?;
    let claims = DeploymentClaimsV2::from_bundle(bundle);
    let binding = render_rust_binding(&claims, limits)?;
    let receipt = build_receipt(&claims, &binding)?;
    let deployment = LinuxSelectedEndQualificationDeploymentV2 { binding, receipt };
    deployment.validate(bundle, limits)?;
    Ok(deployment)
}

#[derive(Clone, Copy)]
struct DeploymentClaimsV2 {
    manifest_identity: [u8; 32],
    source_identity: [u8; 32],
    semantic_binding_identity: [u8; 32],
    literal_identity: [u8; 32],
    kir_identity: [u8; 32],
    artifact_identity: [u8; 32],
    binding_identity: [u8; 32],
    compile_identity: [u8; 32],
    implementation_object_identity: [u8; 32],
    compiler_receipt_identity: [u8; 32],
    expectation_identity: [u8; 32],
    full_payload_identity: [u8; 32],
    glue_source_identity: [u8; 32],
    direct_header_identity: [u8; 32],
    glue_code_identity: [u8; 32],
    glue_object_identity: [u8; 32],
    bundle_identity: [u8; 32],
    full_payload_bytes: u32,
    literal: [u8; 16],
    symbols: crate::LinuxSelectedEndDirectSymbolsV2,
}

impl DeploymentClaimsV2 {
    fn from_bundle(bundle: &LinuxSelectedEndQualificationBundleV2) -> Self {
        let compiler = bundle.compiled().receipt();
        let metadata = compiler.metadata();
        Self {
            manifest_identity: *compiler.manifest_identity().as_bytes(),
            source_identity: *compiler.source_identity().as_bytes(),
            semantic_binding_identity: *compiler.semantic_binding_identity().as_bytes(),
            literal_identity: *compiler.literal_identity().as_bytes(),
            kir_identity: *compiler.kir_identity().as_bytes(),
            artifact_identity: *compiler.artifact_identity().as_bytes(),
            binding_identity: *compiler.binding_identity().as_bytes(),
            compile_identity: *compiler.compile_identity().as_bytes(),
            implementation_object_identity: *compiler.object_identity().as_bytes(),
            compiler_receipt_identity: *compiler.receipt_identity().as_bytes(),
            expectation_identity: *bundle.expectation().expectation_identity().as_bytes(),
            full_payload_identity: *metadata.payload_sha256(),
            glue_source_identity: *bundle.source().identity().as_bytes(),
            direct_header_identity: *bundle.header().identity().as_bytes(),
            glue_code_identity: *bundle.glue().code_identity().as_bytes(),
            glue_object_identity: *bundle.glue().object_identity().as_bytes(),
            bundle_identity: *bundle.bundle_identity().as_bytes(),
            full_payload_bytes: metadata.payload_bytes(),
            literal: *bundle.compiled().literal(),
            symbols: bundle
                .glue()
                .symbols()
                .expect("validated bundle has its identity-derived symbol namespace"),
        }
    }
}

fn render_rust_binding(
    claims: &DeploymentClaimsV2,
    limits: LinuxSelectedEndQualificationDeploymentLimitsV2,
) -> Result<
    LinuxSelectedEndQualificationRustBindingV2,
    LinuxSelectedEndQualificationDeploymentErrorV2,
> {
    let entry = claims.symbols.entry().as_str();
    let wrapper = claims.symbols.wrapper().as_str();
    let entry_local = format!(
        "exact_linked_aot_selected_end_entry_v2_{}",
        hex(&claims.compile_identity)
    );
    let wrapper_local = format!(
        "exact_linked_aot_selected_end_qualification_wrapper_v2_{}",
        hex(&claims.compile_identity)
    );
    let primary_callsite = format!(
        "{PRIMARY_CALLSITE_SYMBOL_PREFIX_V2}{}",
        hex(&claims.compile_identity)
    );
    let primary_callsite_local = format!(
        "exact_linked_aot_selected_end_primary_callsite_v2_{}",
        hex(&claims.compile_identity)
    );
    let mut output = String::new();
    writeln!(
        output,
        "// @generated by fre-aot-compiler; identity-gated and non-authoritative."
    )
    .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    writeln!(
        output,
        "#[cfg(not(all(target_arch = \"aarch64\", target_os = \"linux\", target_pointer_width = \"64\", target_endian = \"little\")))]\ncompile_error!(\"SelectedEnd ABI2 qualification binding requires little-endian Linux/AArch64 LP64\");"
    )
    .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    writeln!(
        output,
        "pub(super) const PRODUCTION_AUTHORITY: &str = \"absent\";"
    )
    .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    writeln!(
        output,
        "pub(super) const RUNTIME_AUTHORITY: &str = \"absent\";"
    )
    .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    for (name, value) in claims.identity_constants() {
        writeln!(output, "pub(super) const {name}: [u8; 32] = {value:?};")
            .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    }
    for (name, value) in [
        ("WRAPPER_SYMBOL", wrapper),
        ("PRIMARY_CALLSITE_SYMBOL", &primary_callsite),
        ("ENTRY_SYMBOL", entry),
        ("PAYLOAD_SYMBOL", claims.symbols.payload().as_str()),
        ("METADATA_SYMBOL", claims.symbols.metadata().as_str()),
        ("EXPECTATION_SYMBOL", claims.symbols.expectation().as_str()),
    ] {
        writeln!(output, "pub(super) const {name}: &str = {value:?};")
            .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    }
    writeln!(
        output,
        "pub(super) const EXACT_LITERAL: [u8; 16] = {:?};\npub(super) const FULL_PAYLOAD_BYTES: u32 = {};\nconst _: () = assert!({} == 4);\nconst _: () = assert!({} == 0);\nconst _: () = assert!({} == 0);\nconst _: () = assert!({} == 16);",
        claims.literal,
        claims.full_payload_bytes,
        SEARCH_SELECTED_END_ARGUMENT_COUNT_V2,
        SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2,
        SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2,
        SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2,
    )
    .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    writeln!(
        output,
        "static EXACT_PLAN_BINDING_KEY: fre_aot_static_runtime::StaticSearchSelectedEndBindingKeyV2 = fre_aot_static_runtime::StaticSearchSelectedEndBindingKeyV2::compiler_generated(COMPILE_IDENTITY);"
    )
    .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    writeln!(
        output,
        "static EXACT_PRODUCTION_CLAIMS: fre_aot_static_runtime::StaticSearchSelectedEndArtifactClaimsV2 = fre_aot_static_runtime::StaticSearchSelectedEndArtifactClaimsV2::compiler_generated(\n    MANIFEST_IDENTITY,\n    SOURCE_IDENTITY,\n    SEMANTIC_BINDING_IDENTITY,\n    LITERAL_IDENTITY,\n    KIR_IDENTITY,\n    ARTIFACT_IDENTITY,\n    BINDING_IDENTITY,\n    COMPILE_IDENTITY,\n    IMPLEMENTATION_OBJECT_IDENTITY,\n    COMPILER_RECEIPT_IDENTITY,\n    EXPECTATION_IDENTITY,\n    FULL_PAYLOAD_IDENTITY,\n    GLUE_SOURCE_IDENTITY,\n    DIRECT_HEADER_IDENTITY,\n    GLUE_CODE_IDENTITY,\n    GLUE_OBJECT_IDENTITY,\n    BUNDLE_IDENTITY,\n    FULL_PAYLOAD_BYTES,\n    EXACT_LITERAL,\n);"
    )
    .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    writeln!(
        output,
        "\n/// Nominal proof that one owning plan session was issued by this exact generated artifact.\n///\n/// Its field is private: safe callers can obtain it only through this module's\n/// identity-gated public facade or its qualification-private parent seam.\n#[derive(Debug)]\npub struct ExactLinkedAotSelectedEndPlanSessionV2<'owner, 'plan> {{\n    inner: fre_aot_static_runtime::StaticSearchSelectedEndOwnedPlanSessionV2<'owner, 'plan>,\n}}"
    )
    .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    writeln!(
        output,
        "#[allow(unsafe_code, reason = \"generated FFI declares only the exact identity-suffixed ABI2 symbols\")]\nunsafe extern \"C\" {{\n    #[link_name = {entry:?}]\n    fn {entry_local}(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize) -> usize;\n    #[link_name = {wrapper:?}]\n    fn {wrapper_local}(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize) -> usize;\n}}"
    )
    .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    writeln!(
        output,
        "#[allow(unsafe_code, reason = \"the exact exported proof callsite remains hidden and uses only the sealed four-argument ABI2\")]\ncore::arch::global_asm!({:?});\n\n#[allow(unsafe_code, reason = \"this hidden proof callsite names only the exact identity-suffixed ABI2 entry\")]\n#[unsafe(export_name = {primary_callsite:?})]\n#[inline(never)]\npub(super) unsafe extern \"C\" fn {primary_callsite_local}(\n    haystack: *const u8,\n    haystack_len: usize,\n    window_start: usize,\n    window_end: usize,\n) -> usize {{\n    // SAFETY: callers must satisfy the exact raw ABI2 pointer/window contract.\n    let end_or_zero = unsafe {{\n        {entry_local}(haystack, haystack_len, window_start, window_end)\n    }};\n    // Keep a real post-call operation in the retained proof copy so it cannot\n    // be tail-called. The hot consumer route below bypasses this proof copy\n    // and exposes the exact entry call directly to its caller.\n    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);\n    end_or_zero\n}}",
        format!(".hidden {primary_callsite}"),
    )
    .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    writeln!(
        output,
        "\n#[inline]\nfn bind_exact_linked_aot_selected_end_production_plan_v2<'owner, 'plan>(\n    session: fre_aot_static_runtime::StaticSearchSelectedEndProductionThreadSessionV2<'owner>,\n    plan: &'plan fre_kernels::LiteralPlan,\n) -> Result<\n    ExactLinkedAotSelectedEndPlanSessionV2<'owner, 'plan>,\n    fre_aot_static_runtime::StaticSearchSelectedEndCallErrorV2,\n> {{\n    Ok(ExactLinkedAotSelectedEndPlanSessionV2 {{\n        inner: session.bind_compiler_generated_literal_plan_owned(\n            plan,\n            &EXACT_LITERAL,\n            &EXACT_PLAN_BINDING_KEY,\n            &COMPILE_IDENTITY,\n        )?,\n    }})\n}}\n\n/// Qualification-private bind kept separate from production authority.\n/// Safe construction of its input token requires the static runtime's\n/// default-off qualification feature.\n#[inline]\npub(super) fn bind_exact_linked_aot_selected_end_qualification_plan_v2<'owner, 'plan>(\n    session: fre_aot_static_runtime::StaticSearchSelectedEndQualificationThreadSessionV2<'owner>,\n    plan: &'plan fre_kernels::LiteralPlan,\n) -> Result<\n    ExactLinkedAotSelectedEndPlanSessionV2<'owner, 'plan>,\n    fre_aot_static_runtime::StaticSearchSelectedEndCallErrorV2,\n> {{\n    Ok(ExactLinkedAotSelectedEndPlanSessionV2 {{\n        inner: session.bind_literal_plan_owned(plan, &EXACT_LITERAL, &EXACT_PLAN_BINDING_KEY)?,\n    }})\n}}"
    )
    .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    write_call(
        &mut output,
        "pub",
        "search_exact_linked_aot_selected_end_v2",
        &entry_local,
        "primary exact-entry route",
    )?;
    write_call(
        &mut output,
        "pub(super)",
        "search_exact_linked_aot_selected_end_qualification_wrapper_v2",
        &wrapper_local,
        "diagnostic direct-glue route",
    )?;
    write_public_adopter(&mut output)?;
    let required = usize_u64(output.len())?;
    let effective_limit = limits
        .max_rust_binding_bytes
        .min(HARD_MAX_LINUX_SELECTED_END_QUALIFICATION_RUST_BINDING_BYTES_V2);
    if required == 0 || required > effective_limit {
        return Err(
            LinuxSelectedEndQualificationDeploymentErrorV2::ResourceLimit {
                limit: effective_limit,
                required,
            },
        );
    }
    if output.contains("transmute")
        || output.contains("dyn Fn")
        || output.contains("extern \"C\" fn(")
        || output.contains("result_slot")
        || output.contains(" x4")
        || output.contains("blr")
    {
        return Err(LinuxSelectedEndQualificationDeploymentErrorV2::InvalidBinding);
    }
    let bytes = output.into_bytes().into_boxed_slice();
    let identity = LinuxSelectedEndQualificationRustBindingIdentityV2::new(
        length_prefixed_identity(RUST_BINDING_IDENTITY_DOMAIN_V2, &bytes),
    );
    Ok(LinuxSelectedEndQualificationRustBindingV2 {
        bytes,
        identity,
        primary_callsite_symbol: primary_callsite.into_boxed_str(),
    })
}

fn write_call(
    output: &mut String,
    visibility: &str,
    public_name: &str,
    exact_local: &str,
    reason: &str,
) -> Result<(), LinuxSelectedEndQualificationDeploymentErrorV2> {
    writeln!(
        output,
        "\n#[allow(unsafe_code, reason = \"the checked same-thread plan session guards this {reason}\")]\n#[inline(always)]\n{visibility} fn {public_name}<'preflight, 'haystack>(\n    plan_session: &ExactLinkedAotSelectedEndPlanSessionV2<'_, '_>,\n    preflight: fre_kernels::LiteralSearchPreflight<'preflight, 'haystack>,\n) -> Result<\n    (Option<fre_kernel_ir::MatchSpan>, fre_kernels::LiteralAccounting),\n    fre_aot_static_runtime::StaticSearchSelectedEndCallErrorV2,\n> {{\n    let prepared = plan_session.inner.prepare_plan_bound(preflight)?;\n    let haystack = prepared.haystack();\n    let window = prepared.window();\n    // SAFETY: the generated declaration names the exact hidden P2b symbol;\n    // `prepared` proves the same-thread VL16 session, once-bound exact literal\n    // plan, scalar window bounds, and haystack ownership. The field-private\n    // nominal session proves this exact artifact without a hot pointer check.\n    // Post-link qualification must still prove this remains a direct non-PLT\n    // `bl` in the final image.\n    let end_or_zero = unsafe {{\n        {exact_local}(\n            haystack.as_ptr(),\n            haystack.len(),\n            window.start(),\n            window.end(),\n        )\n    }};\n    prepared.decode(end_or_zero)\n}}"
    )
    .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)
}

fn write_public_adopter(
    output: &mut String,
) -> Result<(), LinuxSelectedEndQualificationDeploymentErrorV2> {
    output
        .write_str(
            r#"

/// Portable fallback for this exact generated artifact.
///
/// The status distinguishes a globally absent production authority table from
/// an unqualified artifact. The exact portable plan remains the semantic
/// owner and no host probe or native work has occurred.
#[derive(Debug)]
pub struct ExactLinkedAotSelectedEndPortableFallbackV2<'plan> {
    plan: &'plan fre_kernels::LiteralPlan,
    status: fre_aot_static_runtime::StaticSearchSelectedEndFallbackStatusV2,
}

impl<'plan> ExactLinkedAotSelectedEndPortableFallbackV2<'plan> {
    #[must_use]
    pub const fn status(
        &self,
    ) -> fre_aot_static_runtime::StaticSearchSelectedEndFallbackStatusV2 {
        self.status
    }

    #[must_use]
    pub const fn plan(&self) -> &'plan fre_kernels::LiteralPlan {
        self.plan
    }

    /// Execute the retained portable plan over a complete haystack.
    #[inline]
    pub fn find(
        &self,
        haystack: &[u8],
        limits: fre_kernels::LiteralSearchLimits,
    ) -> Result<
        (Option<fre_kernel_ir::MatchSpan>, fre_kernels::LiteralAccounting),
        fre_kernels::LiteralError,
    > {
        let (matched, accounting) = self.plan.find(haystack, limits)?;
        Ok((
            matched.map(|(start, end)| fre_kernel_ir::MatchSpan::new(start, end)),
            accounting,
        ))
    }

    /// Execute the retained portable plan over one checked half-open window.
    #[inline]
    pub fn find_window(
        &self,
        haystack: &[u8],
        window: fre_kernels::Window,
        limits: fre_kernels::LiteralSearchLimits,
    ) -> Result<
        (Option<fre_kernel_ir::MatchSpan>, fre_kernels::LiteralAccounting),
        fre_kernels::LiteralError,
    > {
        let (matched, accounting) = self.plan.find_window(haystack, window, limits)?;
        Ok((
            matched.map(|(start, end)| fre_kernel_ir::MatchSpan::new(start, end)),
            accounting,
        ))
    }
}

/// Failure while opening this exact artifact's production same-thread
/// session.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExactLinkedAotSelectedEndSessionErrorV2 {
    Thread(fre_aot_static_runtime::StaticSearchSelectedEndThreadContractErrorV2),
    Binding(fre_aot_static_runtime::StaticSearchSelectedEndCallErrorV2),
}

impl core::fmt::Display for ExactLinkedAotSelectedEndSessionErrorV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Thread(error) => core::fmt::Display::fmt(error, formatter),
            Self::Binding(error) => core::fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for ExactLinkedAotSelectedEndSessionErrorV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Thread(error) => Some(error),
            Self::Binding(error) => Some(error),
        }
    }
}

impl From<fre_aot_static_runtime::StaticSearchSelectedEndThreadContractErrorV2>
    for ExactLinkedAotSelectedEndSessionErrorV2
{
    fn from(
        error: fre_aot_static_runtime::StaticSearchSelectedEndThreadContractErrorV2,
    ) -> Self {
        Self::Thread(error)
    }
}

impl From<fre_aot_static_runtime::StaticSearchSelectedEndCallErrorV2>
    for ExactLinkedAotSelectedEndSessionErrorV2
{
    fn from(error: fre_aot_static_runtime::StaticSearchSelectedEndCallErrorV2) -> Self {
        Self::Binding(error)
    }
}

/// Public production facade for this exact identity-suffixed ABI2 binding.
///
/// The opaque production owner exists only after all generated identity
/// claims match one private source-reviewed row. This value contains no
/// address, symbol, callback, or function pointer.
#[derive(Debug)]
pub struct ExactLinkedAotSelectedEndFacadeV2<'plan> {
    plan: &'plan fre_kernels::LiteralPlan,
    production: fre_aot_static_runtime::StaticSearchSelectedEndProductionV2,
}

impl<'plan> ExactLinkedAotSelectedEndFacadeV2<'plan> {
    #[must_use]
    pub const fn plan(&self) -> &'plan fre_kernels::LiteralPlan {
        self.plan
    }

    #[must_use]
    pub const fn production_authority(
        &self,
    ) -> fre_aot_static_runtime::StaticSearchSelectedEndProductionAuthorityV2 {
        self.production.production_authority()
    }

    #[must_use]
    pub const fn qualification(
        &self,
    ) -> fre_aot_static_runtime::StaticSearchSelectedEndSourceQualificationV2 {
        self.production.qualification()
    }

    /// Admit the calling thread once and bind the exact portable plan into
    /// this generated module's nominal session.
    pub fn begin_current_thread_session(
        &self,
    ) -> Result<
        ExactLinkedAotSelectedEndPlanSessionV2<'_, 'plan>,
        ExactLinkedAotSelectedEndSessionErrorV2,
    > {
        let thread = self.production.begin_current_thread_session()?;
        bind_exact_linked_aot_selected_end_production_plan_v2(thread, self.plan)
            .map_err(ExactLinkedAotSelectedEndSessionErrorV2::Binding)
    }
}

/// Typed result of attempting to adopt this exact generated ABI2 artifact.
#[derive(Debug)]
pub enum ExactLinkedAotSelectedEndAdoptionV2<'plan> {
    PortableFallback(ExactLinkedAotSelectedEndPortableFallbackV2<'plan>),
    Adopted(ExactLinkedAotSelectedEndFacadeV2<'plan>),
}

impl ExactLinkedAotSelectedEndAdoptionV2<'_> {
    #[must_use]
    pub const fn production_authority(
        &self,
    ) -> fre_aot_static_runtime::StaticSearchSelectedEndProductionAuthorityV2 {
        match self {
            Self::PortableFallback(fallback) => fallback.status().production_authority(),
            Self::Adopted(facade) => facade.production_authority(),
        }
    }

    #[must_use]
    pub const fn qualification(
        &self,
    ) -> fre_aot_static_runtime::StaticSearchSelectedEndSourceQualificationV2 {
        match self {
            Self::PortableFallback(fallback) => fallback.status().qualification(),
            Self::Adopted(facade) => facade.qualification(),
        }
    }
}

/// Bind an exact portable plan to this generated artifact's lookup-only
/// identity claims.
///
/// The only caller input is the semantic `LiteralPlan`. There is no
/// caller-supplied address, symbol, selector, callback, or authority setter.
/// With the current empty production table this returns a typed portable
/// fallback before host probing or native work.
pub fn adopt_exact_linked_aot_selected_end_v2<'plan>(
    plan: &'plan fre_kernels::LiteralPlan,
) -> Result<
    ExactLinkedAotSelectedEndAdoptionV2<'plan>,
    fre_aot_static_runtime::StaticSearchSelectedEndCallErrorV2,
> {
    let actual_bytes = plan.needle().len();
    if actual_bytes != EXACT_LITERAL.len() {
        return Err(
            fre_aot_static_runtime::StaticSearchSelectedEndCallErrorV2::LiteralWidthMismatch {
                expected_bytes: EXACT_LITERAL.len(),
                actual_bytes,
            },
        );
    }
    if plan.needle() != EXACT_LITERAL {
        return Err(
            fre_aot_static_runtime::StaticSearchSelectedEndCallErrorV2::LiteralIdentityMismatch,
        );
    }
    Ok(
        match fre_aot_static_runtime::adopt_compiler_generated_static_search_selected_end_v2(
            &EXACT_PRODUCTION_CLAIMS,
        ) {
            fre_aot_static_runtime::StaticSearchSelectedEndAdoptionV2::Fallback(status) => {
                ExactLinkedAotSelectedEndAdoptionV2::PortableFallback(
                    ExactLinkedAotSelectedEndPortableFallbackV2 { plan, status },
                )
            }
            fre_aot_static_runtime::StaticSearchSelectedEndAdoptionV2::Adopted(production) => {
                ExactLinkedAotSelectedEndAdoptionV2::Adopted(
                    ExactLinkedAotSelectedEndFacadeV2 { plan, production },
                )
            }
        },
    )
}

impl ExactLinkedAotSelectedEndPlanSessionV2<'_, '_> {
    /// Search through the exact identity-suffixed direct entry.
    #[inline(always)]
    pub fn search<'preflight, 'haystack>(
        &self,
        preflight: fre_kernels::LiteralSearchPreflight<'preflight, 'haystack>,
    ) -> Result<
        (Option<fre_kernel_ir::MatchSpan>, fre_kernels::LiteralAccounting),
        fre_aot_static_runtime::StaticSearchSelectedEndCallErrorV2,
    > {
        search_exact_linked_aot_selected_end_v2(self, preflight)
    }
}
"#,
        )
        .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)
}

impl DeploymentClaimsV2 {
    fn identity_constants(&self) -> [(&'static str, [u8; 32]); 17] {
        [
            ("MANIFEST_IDENTITY", self.manifest_identity),
            ("SOURCE_IDENTITY", self.source_identity),
            ("SEMANTIC_BINDING_IDENTITY", self.semantic_binding_identity),
            ("LITERAL_IDENTITY", self.literal_identity),
            ("KIR_IDENTITY", self.kir_identity),
            ("ARTIFACT_IDENTITY", self.artifact_identity),
            ("BINDING_IDENTITY", self.binding_identity),
            ("COMPILE_IDENTITY", self.compile_identity),
            (
                "IMPLEMENTATION_OBJECT_IDENTITY",
                self.implementation_object_identity,
            ),
            ("COMPILER_RECEIPT_IDENTITY", self.compiler_receipt_identity),
            ("EXPECTATION_IDENTITY", self.expectation_identity),
            ("FULL_PAYLOAD_IDENTITY", self.full_payload_identity),
            ("GLUE_SOURCE_IDENTITY", self.glue_source_identity),
            ("DIRECT_HEADER_IDENTITY", self.direct_header_identity),
            ("GLUE_CODE_IDENTITY", self.glue_code_identity),
            ("GLUE_OBJECT_IDENTITY", self.glue_object_identity),
            ("BUNDLE_IDENTITY", self.bundle_identity),
        ]
    }

    fn receipt_identities(
        &self,
        rust_binding_identity: LinuxSelectedEndQualificationRustBindingIdentityV2,
    ) -> [[u8; 32]; RECEIPT_IDENTITY_COUNT_WITHOUT_SELF_V2] {
        [
            self.manifest_identity,
            self.source_identity,
            self.semantic_binding_identity,
            self.literal_identity,
            self.kir_identity,
            self.artifact_identity,
            self.binding_identity,
            self.compile_identity,
            self.implementation_object_identity,
            self.compiler_receipt_identity,
            self.expectation_identity,
            self.full_payload_identity,
            self.glue_source_identity,
            self.direct_header_identity,
            self.glue_code_identity,
            self.glue_object_identity,
            self.bundle_identity,
            *rust_binding_identity.as_bytes(),
        ]
    }
}

fn build_receipt(
    claims: &DeploymentClaimsV2,
    binding: &LinuxSelectedEndQualificationRustBindingV2,
) -> Result<
    LinuxSelectedEndQualificationDeploymentReceiptV2,
    LinuxSelectedEndQualificationDeploymentErrorV2,
> {
    let mut bytes = [0_u8; LINUX_SELECTED_END_QUALIFICATION_DEPLOYMENT_RECEIPT_BYTES_V2];
    bytes[..8].copy_from_slice(&DEPLOYMENT_RECEIPT_MAGIC_V2);
    bytes[8..10].copy_from_slice(&DEPLOYMENT_RECEIPT_SCHEMA_VERSION_V2.to_le_bytes());
    bytes[10..12].copy_from_slice(&crate::AOT_LINUX_SELECTED_END_COMPILER_VERSION_V2.to_le_bytes());
    bytes[12..16].copy_from_slice(
        &u32::try_from(LINUX_SELECTED_END_QUALIFICATION_DEPLOYMENT_RECEIPT_BYTES_V2)
            .expect("fixed deployment receipt bytes")
            .to_le_bytes(),
    );
    bytes[16..20].copy_from_slice(
        &u32::try_from(binding.as_bytes().len())
            .map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)?
            .to_le_bytes(),
    );
    bytes[20] = SEARCH_SELECTED_END_ARGUMENT_COUNT_V2;
    bytes[21] = SEARCH_SELECTED_END_RETURN_REGISTER_X0_V2;
    bytes[22..24].copy_from_slice(&SEARCH_SELECTED_END_RESULT_SLOT_BYTES_V2.to_le_bytes());
    bytes[24..26].copy_from_slice(&SEARCH_SELECTED_END_BACKEND_TAG21_V2.to_le_bytes());
    bytes[26..28].copy_from_slice(&SEARCH_SELECTED_END_CALL_ABI_SCHEMA_V2.to_le_bytes());
    bytes[28..30].copy_from_slice(&SEARCH_SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2.to_le_bytes());
    bytes[30] = 0;
    bytes[31] = 2;
    bytes[32..36].copy_from_slice(&POST_LINK_DISASSEMBLY_REQUIREMENTS_V2.to_le_bytes());
    bytes[36..40].copy_from_slice(&SEARCH_SELECTED_END_LITERAL_BYTES_V2.to_le_bytes());
    bytes[40..44].copy_from_slice(&claims.full_payload_bytes.to_le_bytes());
    bytes[44..46].copy_from_slice(
        &u16::try_from(RECEIPT_IDENTITY_COUNT_WITHOUT_SELF_V2)
            .expect("fixed deployment identity count")
            .to_le_bytes(),
    );
    let mut offset = RECEIPT_IDENTITIES_OFFSET_V2;
    for identity in claims.receipt_identities(binding.identity()) {
        bytes[offset..offset + 32].copy_from_slice(&identity);
        offset = offset
            .checked_add(32)
            .ok_or(LinuxSelectedEndQualificationDeploymentErrorV2::Render)?;
    }
    if offset != RECEIPT_IDENTITY_OFFSET_V2 {
        return Err(LinuxSelectedEndQualificationDeploymentErrorV2::Render);
    }
    let receipt_identity = digest_with_domain(
        DEPLOYMENT_RECEIPT_IDENTITY_DOMAIN_V2,
        &bytes[..RECEIPT_IDENTITY_OFFSET_V2],
    );
    bytes[RECEIPT_IDENTITY_OFFSET_V2..].copy_from_slice(&receipt_identity);
    let receipt = LinuxSelectedEndQualificationDeploymentReceiptV2 { bytes };
    if !receipt.authenticates_itself() {
        return Err(LinuxSelectedEndQualificationDeploymentErrorV2::InvalidReceipt);
    }
    Ok(receipt)
}

fn length_prefixed_identity(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(bytes.len())
            .expect("bounded deployment source length fits u64")
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

fn usize_u64(value: usize) -> Result<u64, LinuxSelectedEndQualificationDeploymentErrorV2> {
    u64::try_from(value).map_err(|_| LinuxSelectedEndQualificationDeploymentErrorV2::Render)
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use fre::RustProfile;

    use super::*;
    use crate::{
        LinuxAarch64SelectedEndManifestV2, build_linux_selected_end_qualification_bundle_v2,
        plan_and_compile_linux_aarch64_selected_end_v2,
    };

    fn bundle() -> LinuxSelectedEndQualificationBundleV2 {
        let compiled = plan_and_compile_linux_aarch64_selected_end_v2(
            LinuxAarch64SelectedEndManifestV2::default(),
            b"0123456789abcdef".to_vec(),
            RustProfile::default(),
        )
        .expect("SelectedEnd ABI2 compile");
        build_linux_selected_end_qualification_bundle_v2(
            compiled,
            LinuxSelectedEndDirectGlueLimitsV2::default(),
        )
        .expect("SelectedEnd ABI2 bundle")
    }

    #[test]
    fn deployment_is_deterministic_direct_and_authority_free() {
        let bundle = bundle();
        let limits = LinuxSelectedEndQualificationDeploymentLimitsV2::default();
        let first = build_linux_selected_end_qualification_deployment_v2(&bundle, limits).unwrap();
        let second = build_linux_selected_end_qualification_deployment_v2(&bundle, limits).unwrap();
        assert_eq!(first, second);
        first.validate(&bundle, limits).unwrap();
        assert_eq!(
            first.runtime_authority(),
            SelectedEndAotRuntimeAuthorityV2::Absent
        );
        assert_eq!(
            first.binding().runtime_authority(),
            SelectedEndAotRuntimeAuthorityV2::Absent
        );
        assert_eq!(
            first.receipt().runtime_authority(),
            SelectedEndAotRuntimeAuthorityV2::Absent
        );
        let source = first.binding().as_str();
        let symbols = bundle.glue().symbols().unwrap();
        assert!(source.contains("pub(super) const PRODUCTION_AUTHORITY: &str = \"absent\";"));
        assert!(source.contains("pub(super) const RUNTIME_AUTHORITY: &str = \"absent\";"));
        assert!(source.contains(&format!("#[link_name = {:?}]", symbols.entry().as_str())));
        assert!(source.contains(&format!("#[link_name = {:?}]", symbols.wrapper().as_str())));
        assert!(
            source.contains(
                "StaticSearchSelectedEndBindingKeyV2::compiler_generated(COMPILE_IDENTITY)"
            )
        );
        assert!(source.contains("StaticSearchSelectedEndArtifactClaimsV2::compiler_generated("));
        assert!(source.contains(
            "inner: session.bind_literal_plan_owned(plan, &EXACT_LITERAL, &EXACT_PLAN_BINDING_KEY)?"
        ));
        assert!(source.contains(
            "\nfn bind_exact_linked_aot_selected_end_production_plan_v2<'owner, 'plan>("
        ));
        assert!(
            !source.contains("pub(super) fn bind_exact_linked_aot_selected_end_production_plan_v2")
        );
        assert!(!source.contains("pub fn bind_exact_linked_aot_selected_end_production_plan_v2"));
        assert!(source.contains(
            "session: fre_aot_static_runtime::StaticSearchSelectedEndProductionThreadSessionV2<'owner>"
        ));
        assert!(source.contains("inner: session.bind_compiler_generated_literal_plan_owned("));
        assert!(source.contains("&EXACT_PLAN_BINDING_KEY,\n            &COMPILE_IDENTITY,"));
        assert!(source.contains(
            "pub(super) fn bind_exact_linked_aot_selected_end_qualification_plan_v2<'owner, 'plan>("
        ));
        assert!(source.contains(
            "session: fre_aot_static_runtime::StaticSearchSelectedEndQualificationThreadSessionV2<'owner>"
        ));
        assert!(!source.contains("pub(super) fn bind_exact_linked_aot_selected_end_plan_v2"));
        assert!(!source.contains("StaticSearchSelectedEndThreadSessionV2"));
        assert!(
            source.contains("pub struct ExactLinkedAotSelectedEndPlanSessionV2<'owner, 'plan>")
        );
        assert!(source.contains(
            "inner: fre_aot_static_runtime::StaticSearchSelectedEndOwnedPlanSessionV2<'owner, 'plan>"
        ));
        assert!(!source.contains(
            "pub(super) inner: fre_aot_static_runtime::StaticSearchSelectedEndOwnedPlanSessionV2"
        ));
        assert_eq!(
            source
                .matches("let prepared = plan_session.inner.prepare_plan_bound(preflight)?;")
                .count(),
            2
        );
        assert_eq!(
            source
                .matches("plan_session: &ExactLinkedAotSelectedEndPlanSessionV2<'_, '_>")
                .count(),
            2
        );
        assert!(!source.contains("session.prepare(preflight, &EXACT_LITERAL)?"));
        assert!(!source.contains("plan_session.prepare(preflight)?"));
        assert!(
            !source.contains(
                "let prepared = plan_session.prepare(preflight, &EXACT_PLAN_BINDING_KEY)?;"
            )
        );
        let callsite = format!(
            "{PRIMARY_CALLSITE_SYMBOL_PREFIX_V2}{}",
            hex(symbols.compile_identity())
        );
        assert_eq!(first.binding().primary_callsite_symbol(), callsite);
        assert!(source.contains(&format!("#[unsafe(export_name = {callsite:?})]")));
        assert!(source.contains(&format!("core::arch::global_asm!(\".hidden {callsite}\");")));
        assert!(source.contains("compiler_fence(core::sync::atomic::Ordering::SeqCst)"));
        assert!(source.contains("fn exact_linked_aot_selected_end_entry_v2_"));
        assert!(source.contains(
            "(haystack: *const u8, haystack_len: usize, window_start: usize, window_end: usize) -> usize;"
        ));
        assert!(!source.contains("*mut"));
        assert!(source.contains(
            "pub(super) const EXACT_LITERAL: [u8; 16] = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102];"
        ));
        assert!(!source.contains("transmute"));
        assert!(!source.contains("extern \"C\" fn("));
        assert!(!source.contains("result_slot"));
        assert!(!source.contains(" x4"));
        assert!(!source.contains("blr"));
        assert!(source.contains("pub enum ExactLinkedAotSelectedEndAdoptionV2<'plan>"));
        assert!(source.contains("pub struct ExactLinkedAotSelectedEndPortableFallbackV2<'plan>"));
        assert!(source.contains("pub struct ExactLinkedAotSelectedEndFacadeV2<'plan>"));
        assert!(source.contains("pub fn search_exact_linked_aot_selected_end_v2"));
        assert!(source.contains("pub fn adopt_exact_linked_aot_selected_end_v2<'plan>("));
        assert!(source.contains("adopt_compiler_generated_static_search_selected_end_v2("));
        assert!(source.contains("StaticSearchSelectedEndAdoptionV2::Fallback(status)"));
        assert!(source.contains("ExactLinkedAotSelectedEndAdoptionV2::PortableFallback("));
        assert!(source.contains("let thread = self.production.begin_current_thread_session()?;"));
        assert!(
            source.contains(
                "bind_exact_linked_aot_selected_end_production_plan_v2(thread, self.plan)"
            )
        );
        assert!(!source.contains(
            "bind_exact_linked_aot_selected_end_qualification_plan_v2(thread, self.plan)"
        ));
        assert!(!source.contains("from_address"));
        assert!(!source.contains("from_symbol"));
        assert!(!source.contains("set_authority"));
    }

    #[test]
    fn deployment_receipt_rejects_mutation_and_binds_full_payload() {
        let bundle = bundle();
        let limits = LinuxSelectedEndQualificationDeploymentLimitsV2::default();
        let deployment =
            build_linux_selected_end_qualification_deployment_v2(&bundle, limits).unwrap();
        assert_eq!(
            deployment.receipt().full_payload_identity(),
            bundle.compiled().receipt().metadata().payload_sha256()
        );
        let reopened = LinuxSelectedEndQualificationDeploymentReceiptV2::from_canonical_bytes(
            deployment.receipt().canonical_bytes(),
        )
        .unwrap();
        reopened
            .validate_candidate(&bundle, deployment.binding().as_bytes(), limits)
            .unwrap();
        let mut binding = deployment.binding().as_bytes().to_vec();
        binding[0] ^= 1;
        assert!(
            reopened
                .validate_candidate(&bundle, &binding, limits)
                .is_err()
        );
        let mut bytes = *deployment.receipt().canonical_bytes();
        bytes[RECEIPT_IDENTITIES_OFFSET_V2 + 5] ^= 1;
        assert!(
            LinuxSelectedEndQualificationDeploymentReceiptV2::from_canonical_bytes(&bytes).is_err()
        );
    }
}
