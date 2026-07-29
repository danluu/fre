//! Source-first Linux `AArch64` tag21 SelectedEnd register-return compilation.
//!
//! This module is deliberately parallel to Search V1. Its sole native input is
//! the sealed ABI2 image returned by `fre-jit-aarch64`, and its sole object
//! output is the V2-only ELF object from `fre-aot-elf`. The compiler retains
//! both values so later diagnostic tooling can recheck their exact binding.
//! No type in this module names a linked address, publishes executable memory,
//! or grants qualification, runtime, or deployment authority.

use core::fmt;

use fre::{
    BuildError as FacadeBuildError, BuildLimits, PlanSelection, PortableBuilder, RustProfile,
    SearchExactLiteralAotSemanticBindingIdentity,
};
use fre_aot_elf::{
    BindingIdentity, BindingIdentityError, BuiltSelectedEndSearchObjectV2, CompileIdentity,
    ELF_CLASS_64_V2, ELF_DATA_LSB_V2, ELF_MACHINE_AARCH64_V2, ELF_OS_ABI_SYSV_V2,
    ELF_RELOCATABLE_TYPE_V2, ELF_VERSION_CURRENT_V2, ElfObjectError, ObjectIdentity,
    SELECTED_END_ABI_KIND_V2, SELECTED_END_ARCHITECTURE_AARCH64_V2, SELECTED_END_ARGUMENT_COUNT_V2,
    SELECTED_END_BACKEND_VERSION_V2, SELECTED_END_CALL_ABI_SCHEMA_V2,
    SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2, SELECTED_END_LITERAL_BYTES_V2,
    SELECTED_END_LITTLE_ENDIAN_V2, SELECTED_END_METADATA_BYTES_V2,
    SELECTED_END_NO_MATCH_SENTINEL_V2, SELECTED_END_OUTPUT_KIND_V2, SELECTED_END_PLATFORM_LINUX_V2,
    SELECTED_END_POINTER_WIDTH_V2, SELECTED_END_REQUIRED_FEATURES_V2,
    SELECTED_END_RESULT_SLOT_BYTES_V2, SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2,
    SELECTED_END_RETURN_REGISTER_V2, SELECTED_END_TARGET_ABI_AAPCS64_V2,
    SELECTED_END_WINDOW_CONTRACT_HALF_OPEN_ABSOLUTE_END_V2, SelectedEndMetadataV2,
    SelectedEndObjectLimitsV2, emit_selected_end_search_object_v2,
    inspect_selected_end_metadata_v2, inspect_selected_end_search_object_v2,
    validate_selected_end_search_object_v2,
};
use fre_aot_search_contract::selected_end_v2::{
    AOT_SEARCH_SELECTED_END_COMPILER_VERSION_V2 as CONTRACT_COMPILER_VERSION_V2,
    ClaimedSearchSelectedEndMetadataV2, ClaimedStaticSearchSelectedEndExpectationV2,
    inspect_static_search_selected_end_expectation_v2,
};
use fre_jit_aarch64::{
    AuditedSelectedEndRegisterImageV2, EmitError, EmitLimits, ImageStats,
    SelectedEndRegisterArtifactIdentityV2, SelectedEndRegisterBackendV2, TargetSpec,
    emit_selected_end_register_v2,
};
use fre_kernel_ir::{
    AnchorFlags, BuildError as KernelBuildError, CacheIdentity, OutputKind, SelectedEnd,
    ValidateLimits, build_exact_literal,
};
use sha2::{Digest, Sha256};

pub const AOT_LINUX_SELECTED_END_COMPILER_VERSION_V2: u16 = 2;
pub const AOT_LINUX_SELECTED_END_MANIFEST_SCHEMA_VERSION_V2: u16 = 2;
pub const AOT_LINUX_SELECTED_END_COMPILE_RECEIPT_SCHEMA_VERSION_V2: u16 = 2;
pub const LINUX_SELECTED_END_COMPILE_RECEIPT_BODY_BYTES_V2: usize = 640;
pub const LINUX_SELECTED_END_COMPILE_RECEIPT_BYTES_V2: usize = 672;
pub const MAX_AOT_LINUX_SELECTED_END_SOURCE_BYTES_V2: u64 = 1 << 20;

const MANIFEST_DOMAIN_V2: &[u8] = b"FRE-AOT-LINUX-SEARCH-SELECTED-END-MANIFEST\0\x02";
const SOURCE_DOMAIN_V2: &[u8] = b"FRE-AOT-LINUX-SEARCH-SELECTED-END-SOURCE\0\x02";
const LITERAL_DOMAIN_V2: &[u8] = b"FRE-AOT-LINUX-SEARCH-SELECTED-END-LITERAL\0\x02";
const BINDING_DOMAIN_V2: &[u8] = b"FRE-AOT-LINUX-SEARCH-SELECTED-END-OBJECT-BINDING\0\x02";
const RECEIPT_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-AOT-LINUX-SEARCH-SELECTED-END-COMPILE-RECEIPT\0\x02";
const RECEIPT_MAGIC_V2: [u8; 8] = *b"FRESEC\0\x02";

const RECEIPT_IDENTITIES_OFFSET_V2: usize = 64;
const RECEIPT_METADATA_OFFSET_V2: usize = 352;
const RECEIPT_STATS_OFFSET_V2: usize = 576;
const RECEIPT_IDENTITY_OFFSET_V2: usize = LINUX_SELECTED_END_COMPILE_RECEIPT_BODY_BYTES_V2;
const FIXED_LITERAL_BYTES_V2: usize = 16;

const _: () = assert!(CONTRACT_COMPILER_VERSION_V2 == AOT_LINUX_SELECTED_END_COMPILER_VERSION_V2);
const _: () = assert!(RECEIPT_IDENTITIES_OFFSET_V2 + (9 * 32) == RECEIPT_METADATA_OFFSET_V2);
const _: () =
    assert!(RECEIPT_METADATA_OFFSET_V2 + SELECTED_END_METADATA_BYTES_V2 == RECEIPT_STATS_OFFSET_V2);
const _: () =
    assert!(RECEIPT_STATS_OFFSET_V2 + 64 == LINUX_SELECTED_END_COMPILE_RECEIPT_BODY_BYTES_V2);
const _: () =
    assert!(RECEIPT_IDENTITY_OFFSET_V2 + 32 == LINUX_SELECTED_END_COMPILE_RECEIPT_BYTES_V2);
const _: () = assert!(FIXED_LITERAL_BYTES_V2 == 16);
const _: () = assert!(SELECTED_END_LITERAL_BYTES_V2 == 16);

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
    LinuxSelectedEndManifestIdentityV2,
    "LinuxSelectedEndManifestIdentityV2"
);
identity!(
    LinuxSelectedEndSourceIdentityV2,
    "LinuxSelectedEndSourceIdentityV2"
);
identity!(
    LinuxSelectedEndLiteralIdentityV2,
    "LinuxSelectedEndLiteralIdentityV2"
);
identity!(
    LinuxSelectedEndCompileReceiptIdentityV2,
    "LinuxSelectedEndCompileReceiptIdentityV2"
);

/// Explicit absence of callable or deployment authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedEndAotRuntimeAuthorityV2 {
    Absent,
}

/// Finite source, KIR, sealed-image, and ELF limits for the sole tag21 slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxAarch64SelectedEndCompilePolicyV2 {
    pub max_source_bytes: u64,
    pub kernel_ir: ValidateLimits,
    pub native: EmitLimits,
    pub object: SelectedEndObjectLimitsV2,
}

impl LinuxAarch64SelectedEndCompilePolicyV2 {
    #[must_use]
    pub fn high_fuel() -> Self {
        Self {
            max_source_bytes: MAX_AOT_LINUX_SELECTED_END_SOURCE_BYTES_V2,
            kernel_ir: ValidateLimits::default(),
            native: EmitLimits::default(),
            object: SelectedEndObjectLimitsV2::default(),
        }
    }
}

impl Default for LinuxAarch64SelectedEndCompilePolicyV2 {
    fn default() -> Self {
        Self::high_fuel()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LinuxSelectedEndManifestErrorV2 {
    SourcePolicyExceedsHardLimit { limit: u64, requested: u64 },
}

impl fmt::Display for LinuxSelectedEndManifestErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid Linux SelectedEnd V2 AOT manifest: {self:?}"
        )
    }
}

impl std::error::Error for LinuxSelectedEndManifestErrorV2 {}

/// Sealed request for the only admitted Linux tag21 ABI2 implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxAarch64SelectedEndManifestV2 {
    policy: LinuxAarch64SelectedEndCompilePolicyV2,
    identity: LinuxSelectedEndManifestIdentityV2,
}

impl LinuxAarch64SelectedEndManifestV2 {
    pub fn new(
        policy: LinuxAarch64SelectedEndCompilePolicyV2,
    ) -> Result<Self, LinuxSelectedEndManifestErrorV2> {
        validate_policy(policy)?;
        Ok(Self {
            policy,
            identity: manifest_identity(policy),
        })
    }

    #[must_use]
    pub const fn policy(&self) -> &LinuxAarch64SelectedEndCompilePolicyV2 {
        &self.policy
    }

    #[must_use]
    pub const fn identity(&self) -> LinuxSelectedEndManifestIdentityV2 {
        self.identity
    }

    #[must_use]
    pub const fn backend(&self) -> SelectedEndRegisterBackendV2 {
        SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16
    }

    fn authenticates_itself(&self) -> bool {
        validate_policy(self.policy).is_ok() && manifest_identity(self.policy) == self.identity
    }
}

impl Default for LinuxAarch64SelectedEndManifestV2 {
    fn default() -> Self {
        Self::new(LinuxAarch64SelectedEndCompilePolicyV2::high_fuel())
            .expect("fixed tag21 SelectedEnd manifest")
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum LinuxSelectedEndCompileErrorV2 {
    ManifestAuthentication,
    ResourceLimit {
        resource: &'static str,
        limit: u64,
        required: u64,
    },
    InvalidUtf8Source,
    Facade(FacadeBuildError),
    ExactLiteralRequired,
    LiteralWidth {
        required: u32,
        actual: u64,
    },
    CandidateAuthentication,
    Kernel(KernelBuildError),
    Native(EmitError),
    Binding(BindingIdentityError),
    Object(ElfObjectError),
    ContractMismatch {
        field: &'static str,
    },
    ArithmeticOverflow {
        at: &'static str,
    },
}

impl fmt::Display for LinuxSelectedEndCompileErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Linux tag21 SelectedEnd V2 AOT compilation failed: {self:?}"
        )
    }
}

impl std::error::Error for LinuxSelectedEndCompileErrorV2 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Facade(error) => Some(error),
            Self::Kernel(error) => Some(error),
            Self::Native(error) => Some(error),
            Self::Binding(error) => Some(error),
            Self::Object(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FacadeBuildError> for LinuxSelectedEndCompileErrorV2 {
    fn from(value: FacadeBuildError) -> Self {
        Self::Facade(value)
    }
}

impl From<KernelBuildError> for LinuxSelectedEndCompileErrorV2 {
    fn from(value: KernelBuildError) -> Self {
        Self::Kernel(value)
    }
}

impl From<EmitError> for LinuxSelectedEndCompileErrorV2 {
    fn from(value: EmitError) -> Self {
        Self::Native(value)
    }
}

impl From<BindingIdentityError> for LinuxSelectedEndCompileErrorV2 {
    fn from(value: BindingIdentityError) -> Self {
        Self::Binding(value)
    }
}

impl From<ElfObjectError> for LinuxSelectedEndCompileErrorV2 {
    fn from(value: ElfObjectError) -> Self {
        Self::Object(value)
    }
}

/// Strict claim-side projection of one fixed 672-byte compiler receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndCompileReceiptInspectionV2 {
    manifest_identity: [u8; 32],
    semantic_binding_identity: [u8; 32],
    source_identity: [u8; 32],
    literal_identity: [u8; 32],
    kir_identity: [u8; 32],
    artifact_identity: [u8; 32],
    binding_identity: [u8; 32],
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    metadata: SelectedEndMetadataV2,
    object_bytes: u64,
    payload_bytes: u64,
    object_work: u64,
    native_stats: ImageStats,
    source_bytes: u64,
    receipt_identity: LinuxSelectedEndCompileReceiptIdentityV2,
}

macro_rules! inspection_identity_getter {
    ($name:ident) => {
        #[must_use]
        pub const fn $name(&self) -> &[u8; 32] {
            &self.$name
        }
    };
}

impl LinuxSelectedEndCompileReceiptInspectionV2 {
    inspection_identity_getter!(manifest_identity);
    inspection_identity_getter!(semantic_binding_identity);
    inspection_identity_getter!(source_identity);
    inspection_identity_getter!(literal_identity);
    inspection_identity_getter!(kir_identity);
    inspection_identity_getter!(artifact_identity);
    inspection_identity_getter!(binding_identity);
    inspection_identity_getter!(compile_identity);
    inspection_identity_getter!(object_identity);

    #[must_use]
    pub const fn metadata(&self) -> SelectedEndMetadataV2 {
        self.metadata
    }

    #[must_use]
    pub const fn object_bytes(&self) -> u64 {
        self.object_bytes
    }

    #[must_use]
    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    #[must_use]
    pub const fn object_work(&self) -> u64 {
        self.object_work
    }

    #[must_use]
    pub const fn native_stats(&self) -> ImageStats {
        self.native_stats
    }

    #[must_use]
    pub const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    #[must_use]
    pub const fn receipt_identity(&self) -> LinuxSelectedEndCompileReceiptIdentityV2 {
        self.receipt_identity
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }

    pub fn validate_object<'a>(
        &self,
        bytes: &'a [u8],
        limits: SelectedEndObjectLimitsV2,
    ) -> Result<fre_aot_elf::SelectedEndObjectInspectionV2<'a>, LinuxSelectedEndCompileErrorV2>
    {
        let inspection = inspect_selected_end_search_object_v2(bytes, limits)?;
        if inspection.metadata() != self.metadata
            || usize_u64(inspection.object_bytes(), "decoded object bytes")? != self.object_bytes
            || usize_u64(inspection.payload().len(), "decoded payload bytes")? != self.payload_bytes
            || inspection.work() != self.object_work
            || inspection.claimed_compile_identity().as_bytes() != &self.compile_identity
            || inspection.claimed_object_identity().as_bytes() != &self.object_identity
        {
            return Err(contract("decoded compiler receipt/object"));
        }
        Ok(inspection)
    }

    pub fn validate_reconstructed_image_object<'a>(
        &self,
        image: &AuditedSelectedEndRegisterImageV2,
        bytes: &'a [u8],
        limits: SelectedEndObjectLimitsV2,
    ) -> Result<fre_aot_elf::SelectedEndObjectValidationV2<'a>, LinuxSelectedEndCompileErrorV2>
    {
        if image.backend() != SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16
            || image.source_identity().as_bytes() != &self.kir_identity
            || image.artifact_identity().as_bytes() != &self.artifact_identity
            || image.stats() != self.native_stats
        {
            return Err(contract("decoded compiler receipt/reconstructed image"));
        }
        let binding = BindingIdentity::new(self.binding_identity)?;
        let validation = validate_selected_end_search_object_v2(image, binding, bytes, limits)?;
        let inspection = validation.inspection();
        if inspection.metadata() != self.metadata
            || usize_u64(inspection.object_bytes(), "validated object bytes")? != self.object_bytes
            || inspection.claimed_compile_identity().as_bytes() != &self.compile_identity
            || inspection.claimed_object_identity().as_bytes() != &self.object_identity
        {
            return Err(contract(
                "decoded compiler receipt/reconstructed image/object",
            ));
        }
        Ok(validation)
    }

    pub fn validate_expectation(
        &self,
        bytes: &[u8],
    ) -> Result<ClaimedStaticSearchSelectedEndExpectationV2, LinuxSelectedEndCompileErrorV2> {
        let claim = inspect_static_search_selected_end_expectation_v2(bytes)
            .map_err(|_| contract("decoded compiler receipt/expectation"))?;
        if claim.manifest_identity() != &self.manifest_identity
            || claim.semantic_binding_identity() != &self.semantic_binding_identity
            || claim.literal_identity() != &self.literal_identity
            || claim.kir_identity() != &self.kir_identity
            || claim.artifact_identity() != &self.artifact_identity
            || claim.binding_identity() != &self.binding_identity
            || claim.compile_identity() != &self.compile_identity
            || claim.object_identity() != &self.object_identity
            || claim.receipt_identity() != self.receipt_identity.as_bytes()
            || !metadata_claim_matches_elf(claim.metadata(), self.metadata)
        {
            return Err(contract("decoded compiler receipt/expectation binding"));
        }
        Ok(claim)
    }
}

/// Compiler-sealed source/image/object receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndCompileReceiptV2 {
    manifest_identity: LinuxSelectedEndManifestIdentityV2,
    semantic_binding_identity: SearchExactLiteralAotSemanticBindingIdentity,
    source_identity: LinuxSelectedEndSourceIdentityV2,
    literal_identity: LinuxSelectedEndLiteralIdentityV2,
    kir_identity: CacheIdentity,
    artifact_identity: SelectedEndRegisterArtifactIdentityV2,
    binding_identity: BindingIdentity,
    compile_identity: CompileIdentity,
    object_identity: ObjectIdentity,
    metadata: SelectedEndMetadataV2,
    object_bytes: u64,
    payload_bytes: u64,
    object_work: u64,
    native_stats: ImageStats,
    source_bytes: u64,
    receipt_identity: LinuxSelectedEndCompileReceiptIdentityV2,
}

impl LinuxSelectedEndCompileReceiptV2 {
    #[must_use]
    pub const fn manifest_identity(&self) -> LinuxSelectedEndManifestIdentityV2 {
        self.manifest_identity
    }

    #[must_use]
    pub const fn semantic_binding_identity(&self) -> SearchExactLiteralAotSemanticBindingIdentity {
        self.semantic_binding_identity
    }

    #[must_use]
    pub const fn source_identity(&self) -> LinuxSelectedEndSourceIdentityV2 {
        self.source_identity
    }

    #[must_use]
    pub const fn literal_identity(&self) -> LinuxSelectedEndLiteralIdentityV2 {
        self.literal_identity
    }

    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        SELECTED_END_LITERAL_BYTES_V2
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
    pub const fn metadata(&self) -> SelectedEndMetadataV2 {
        self.metadata
    }

    #[must_use]
    pub const fn object_bytes(&self) -> u64 {
        self.object_bytes
    }

    #[must_use]
    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    #[must_use]
    pub const fn object_work(&self) -> u64 {
        self.object_work
    }

    #[must_use]
    pub const fn native_stats(&self) -> ImageStats {
        self.native_stats
    }

    #[must_use]
    pub const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    #[must_use]
    pub const fn receipt_identity(&self) -> LinuxSelectedEndCompileReceiptIdentityV2 {
        self.receipt_identity
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }

    pub fn canonical_receipt_bytes(
        &self,
    ) -> Result<[u8; LINUX_SELECTED_END_COMPILE_RECEIPT_BYTES_V2], LinuxSelectedEndCompileErrorV2>
    {
        if !self.authenticates_itself() {
            return Err(contract("compiler receipt"));
        }
        encode_receipt(self)
    }

    pub fn validate_canonical_receipt_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<LinuxSelectedEndCompileReceiptInspectionV2, LinuxSelectedEndCompileErrorV2> {
        if !self.authenticates_itself() || self.canonical_receipt_bytes()?.as_slice() != bytes {
            return Err(contract("reopened compiler receipt"));
        }
        let inspection = inspect_linux_selected_end_compile_receipt_v2(bytes)?;
        if inspection.receipt_identity != self.receipt_identity {
            return Err(contract("reopened compiler receipt identity"));
        }
        Ok(inspection)
    }

    pub fn validate_object<'a>(
        &self,
        bytes: &'a [u8],
        limits: SelectedEndObjectLimitsV2,
    ) -> Result<fre_aot_elf::SelectedEndObjectInspectionV2<'a>, LinuxSelectedEndCompileErrorV2>
    {
        if !self.authenticates_itself() {
            return Err(contract("compiler receipt"));
        }
        let inspection = inspect_selected_end_search_object_v2(bytes, limits)?;
        if inspection.metadata() != self.metadata
            || usize_u64(inspection.object_bytes(), "object bytes")? != self.object_bytes
            || usize_u64(inspection.payload().len(), "payload bytes")? != self.payload_bytes
            || inspection.work() != self.object_work
            || !self
                .compile_identity
                .matches_claim(inspection.claimed_compile_identity())
            || !self
                .object_identity
                .matches_claim(inspection.claimed_object_identity())
        {
            return Err(contract("ELF object receipt"));
        }
        Ok(inspection)
    }

    pub fn validate_expectation(
        &self,
        bytes: &[u8],
    ) -> Result<ClaimedStaticSearchSelectedEndExpectationV2, LinuxSelectedEndCompileErrorV2> {
        if !self.authenticates_itself() {
            return Err(contract("compiler receipt"));
        }
        let claim = inspect_static_search_selected_end_expectation_v2(bytes)
            .map_err(|_| contract("compiler receipt/expectation"))?;
        if claim.manifest_identity() != self.manifest_identity.as_bytes()
            || claim.semantic_binding_identity() != self.semantic_binding_identity.as_bytes()
            || claim.literal_identity() != self.literal_identity.as_bytes()
            || claim.kir_identity() != self.kir_identity.as_bytes()
            || claim.artifact_identity() != self.artifact_identity.as_bytes()
            || claim.binding_identity() != self.binding_identity.as_bytes()
            || claim.compile_identity() != self.compile_identity.as_bytes()
            || claim.object_identity() != self.object_identity.as_bytes()
            || claim.receipt_identity() != self.receipt_identity.as_bytes()
            || !metadata_claim_matches_elf(claim.metadata(), self.metadata)
        {
            return Err(contract("compiler receipt/expectation binding"));
        }
        Ok(claim)
    }

    fn authenticates_itself(&self) -> bool {
        self.source_bytes != 0
            && self.source_bytes <= MAX_AOT_LINUX_SELECTED_END_SOURCE_BYTES_V2
            && self.object_bytes != 0
            && self.payload_bytes != 0
            && self.object_work != 0
            && metadata_matches_receipt(self.metadata, self)
            && object_binding_identity(
                self.manifest_identity,
                self.semantic_binding_identity,
                self.source_identity,
                self.literal_identity,
                self.kir_identity,
                self.artifact_identity,
                self.native_stats,
            ) == *self.binding_identity.as_bytes()
            && receipt_identity(self).is_ok_and(|identity| identity == self.receipt_identity)
    }
}

/// Deterministic compiler result retaining the sealed ABI2 image and P2a ELF.
#[derive(Debug, Eq, PartialEq)]
pub struct LinuxSelectedEndCompiledObjectV2 {
    source: Box<[u8]>,
    literal: [u8; FIXED_LITERAL_BYTES_V2],
    profile: RustProfile,
    image: AuditedSelectedEndRegisterImageV2,
    object: BuiltSelectedEndSearchObjectV2,
    receipt: LinuxSelectedEndCompileReceiptV2,
}

impl LinuxSelectedEndCompiledObjectV2 {
    #[must_use]
    pub fn source(&self) -> &[u8] {
        &self.source
    }

    #[must_use]
    pub const fn literal(&self) -> &[u8; FIXED_LITERAL_BYTES_V2] {
        &self.literal
    }

    #[must_use]
    pub const fn profile(&self) -> &RustProfile {
        &self.profile
    }

    #[must_use]
    pub const fn image(&self) -> &AuditedSelectedEndRegisterImageV2 {
        &self.image
    }

    #[must_use]
    pub const fn object(&self) -> &BuiltSelectedEndSearchObjectV2 {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> &LinuxSelectedEndCompileReceiptV2 {
        &self.receipt
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SelectedEndAotRuntimeAuthorityV2 {
        SelectedEndAotRuntimeAuthorityV2::Absent
    }

    pub fn validate_source_image_object(
        &self,
        limits: SelectedEndObjectLimitsV2,
    ) -> Result<(), LinuxSelectedEndCompileErrorV2> {
        authenticate_source(&self.source, &self.literal, &self.profile, &self.receipt)?;
        if self.image.source_identity() != self.receipt.kir_identity
            || self.image.artifact_identity() != self.receipt.artifact_identity
            || self.image.stats() != self.receipt.native_stats
            || self.object.metadata() != self.receipt.metadata
            || self.object.compile_identity() != self.receipt.compile_identity
            || self.object.object_identity() != self.receipt.object_identity
        {
            return Err(contract("retained compiler result"));
        }
        validate_selected_end_search_object_v2(
            &self.image,
            self.receipt.binding_identity,
            self.object.as_bytes(),
            limits,
        )?;
        Ok(())
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one linear pipeline keeps each source/KIR/sealed-image/object binding auditable"
)]
pub fn plan_and_compile_linux_aarch64_selected_end_v2(
    manifest: LinuxAarch64SelectedEndManifestV2,
    source: Vec<u8>,
    profile: RustProfile,
) -> Result<LinuxSelectedEndCompiledObjectV2, LinuxSelectedEndCompileErrorV2> {
    if !manifest.authenticates_itself() {
        return Err(LinuxSelectedEndCompileErrorV2::ManifestAuthentication);
    }
    let source_bytes = usize_u64(source.len(), "source bytes")?;
    let source_capacity_bytes = usize_u64(source.capacity(), "source capacity bytes")?;
    enforce(
        "source bytes",
        source_bytes,
        manifest.policy.max_source_bytes,
    )?;
    enforce(
        "source capacity bytes",
        source_capacity_bytes,
        manifest.policy.max_source_bytes,
    )?;
    let retained_profile = profile.clone();
    let source =
        String::from_utf8(source).map_err(|_| LinuxSelectedEndCompileErrorV2::InvalidUtf8Source)?;
    let regex = PortableBuilder::new(source).profile(profile).build()?;
    let candidate = regex
        .exact_literal_search_aot_candidate()
        .ok_or(LinuxSelectedEndCompileErrorV2::ExactLiteralRequired)?;
    if candidate.selection() != PlanSelection::Auto
        || candidate.build_limits() != BuildLimits::default()
        || candidate.source() != regex.as_str()
        || candidate.profile() != &retained_profile
        || candidate.build_report() != regex.build_report()
    {
        return Err(LinuxSelectedEndCompileErrorV2::CandidateAuthentication);
    }
    let literal_bytes = usize_u64(candidate.literal().len(), "literal bytes")?;
    if literal_bytes != u64::from(SELECTED_END_LITERAL_BYTES_V2) {
        return Err(LinuxSelectedEndCompileErrorV2::LiteralWidth {
            required: SELECTED_END_LITERAL_BYTES_V2,
            actual: literal_bytes,
        });
    }
    let literal: [u8; FIXED_LITERAL_BYTES_V2] = candidate
        .literal()
        .try_into()
        .map_err(|_| contract("fixed literal copy"))?;
    let retained_source = candidate.source().as_bytes().to_vec().into_boxed_slice();
    let semantic_binding_identity = candidate.semantic_binding_identity();

    let program = build_exact_literal::<SelectedEnd>(
        &literal,
        AnchorFlags::default(),
        manifest.policy.kernel_ir,
    )?;
    let kir_identity = program.cache_identity();
    let image = emit_selected_end_register_v2(
        &program,
        SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16,
        manifest.policy.native,
    )?;
    authenticate_image(&image, kir_identity, &literal)?;

    let source_identity = compute_linux_selected_end_source_identity_v2(&retained_source);
    let literal_identity = compute_linux_selected_end_literal_identity_v2(&literal);
    let binding_bytes = object_binding_identity(
        manifest.identity,
        semantic_binding_identity,
        source_identity,
        literal_identity,
        kir_identity,
        image.artifact_identity(),
        image.stats(),
    );
    let binding_identity = BindingIdentity::new(binding_bytes)?;
    let object =
        emit_selected_end_search_object_v2(&image, binding_identity, manifest.policy.object)?;
    validate_selected_end_search_object_v2(
        &image,
        binding_identity,
        object.as_bytes(),
        manifest.policy.object,
    )?;
    let report = object.report();
    let mut receipt = LinuxSelectedEndCompileReceiptV2 {
        manifest_identity: manifest.identity,
        semantic_binding_identity,
        source_identity,
        literal_identity,
        kir_identity,
        artifact_identity: image.artifact_identity(),
        binding_identity,
        compile_identity: object.compile_identity(),
        object_identity: object.object_identity(),
        metadata: object.metadata(),
        object_bytes: usize_u64(report.object_bytes, "object bytes")?,
        payload_bytes: usize_u64(report.payload_bytes, "payload bytes")?,
        object_work: report.total_work,
        native_stats: image.stats(),
        source_bytes,
        receipt_identity: LinuxSelectedEndCompileReceiptIdentityV2::new([0; 32]),
    };
    receipt.receipt_identity = receipt_identity(&receipt)?;
    let compiled = LinuxSelectedEndCompiledObjectV2 {
        source: retained_source,
        literal,
        profile: retained_profile,
        image,
        object,
        receipt,
    };
    if !compiled.receipt.authenticates_itself()
        || compiled
            .validate_source_image_object(manifest.policy.object)
            .is_err()
    {
        return Err(contract("fresh SelectedEnd compiler result"));
    }
    Ok(compiled)
}

#[must_use]
pub fn compute_linux_selected_end_source_identity_v2(
    source: &[u8],
) -> LinuxSelectedEndSourceIdentityV2 {
    LinuxSelectedEndSourceIdentityV2::new(length_prefixed_identity(SOURCE_DOMAIN_V2, source))
}

#[must_use]
pub fn compute_linux_selected_end_literal_identity_v2(
    literal: &[u8],
) -> LinuxSelectedEndLiteralIdentityV2 {
    LinuxSelectedEndLiteralIdentityV2::new(length_prefixed_identity(LITERAL_DOMAIN_V2, literal))
}

pub fn inspect_linux_selected_end_compile_receipt_v2(
    bytes: &[u8],
) -> Result<LinuxSelectedEndCompileReceiptInspectionV2, LinuxSelectedEndCompileErrorV2> {
    if bytes.len() != LINUX_SELECTED_END_COMPILE_RECEIPT_BYTES_V2 {
        return Err(contract("compiler receipt wire extent"));
    }
    let mut reader = ReceiptReader::new(bytes);
    reader.expect(&RECEIPT_MAGIC_V2, "compiler receipt magic")?;
    if reader.u16("compiler receipt schema")?
        != AOT_LINUX_SELECTED_END_COMPILE_RECEIPT_SCHEMA_VERSION_V2
        || reader.u16("compiler version")? != AOT_LINUX_SELECTED_END_COMPILER_VERSION_V2
        || usize::try_from(reader.u32("compiler receipt bytes")?).ok()
            != Some(LINUX_SELECTED_END_COMPILE_RECEIPT_BYTES_V2)
        || reader.u16("backend version")? != SELECTED_END_BACKEND_VERSION_V2
        || reader.u16("call ABI schema")? != SELECTED_END_CALL_ABI_SCHEMA_V2
        || reader.u8("output kind")? != SELECTED_END_OUTPUT_KIND_V2
        || reader.u8("return encoding")? != SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2
        || reader.u8("window contract")? != SELECTED_END_WINDOW_CONTRACT_HALF_OPEN_ABSOLUTE_END_V2
        || reader.u8("argument count")? != SELECTED_END_ARGUMENT_COUNT_V2
        || reader.u16("fixed active vector bytes")? != SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2
        || reader.u16("result slot bytes")? != SELECTED_END_RESULT_SLOT_BYTES_V2
        || reader.u8("return register")? != SELECTED_END_RETURN_REGISTER_V2
        || reader.u8("architecture")? != SELECTED_END_ARCHITECTURE_AARCH64_V2
        || reader.u8("byte order")? != SELECTED_END_LITTLE_ENDIAN_V2
        || reader.u8("pointer width")? != SELECTED_END_POINTER_WIDTH_V2
        || reader.u8("target ABI")? != SELECTED_END_TARGET_ABI_AAPCS64_V2
        || reader.u8("platform")? != SELECTED_END_PLATFORM_LINUX_V2
        || reader.u16("reserved header")? != 0
        || reader.u32("literal bytes")? != SELECTED_END_LITERAL_BYTES_V2
        || reader.u64("required features")? != SELECTED_END_REQUIRED_FEATURES_V2
        || reader.u64("no-match sentinel")? != SELECTED_END_NO_MATCH_SENTINEL_V2
    {
        return Err(contract("compiler receipt header"));
    }
    let source_bytes = reader.u64("source bytes")?;
    if reader.position() != RECEIPT_IDENTITIES_OFFSET_V2 {
        return Err(contract("compiler receipt identity offset"));
    }
    let manifest_identity = reader.array("manifest identity")?;
    let semantic_binding_identity = reader.array("semantic binding identity")?;
    let source_identity = reader.array("source identity")?;
    let literal_identity = reader.array("literal identity")?;
    let kir_identity = reader.array("KIR identity")?;
    let artifact_identity = reader.array("artifact identity")?;
    let binding_identity = reader.array("binding identity")?;
    let compile_identity = reader.array("compile identity")?;
    let object_identity = reader.array("object identity")?;
    if [
        manifest_identity,
        semantic_binding_identity,
        source_identity,
        literal_identity,
        kir_identity,
        artifact_identity,
        binding_identity,
        compile_identity,
        object_identity,
    ]
    .contains(&[0; 32])
        || reader.position() != RECEIPT_METADATA_OFFSET_V2
    {
        return Err(contract("compiler receipt identities"));
    }
    let metadata_bytes: [u8; SELECTED_END_METADATA_BYTES_V2] = reader.array("metadata")?;
    let metadata = inspect_selected_end_metadata_v2(&metadata_bytes)?;
    if reader.position() != RECEIPT_STATS_OFFSET_V2 {
        return Err(contract("compiler receipt metadata offset"));
    }
    let object_bytes = reader.u64("object bytes")?;
    let payload_bytes = reader.u64("payload bytes")?;
    let object_work = reader.u64("object work")?;
    let native_stats = ImageStats {
        emission_work: reader.u64("native emission work")?,
        scratch_bytes: reader.u64("native scratch bytes")?,
        code_bytes: reader.u32("native code bytes")?,
        data_bytes: reader.u32("native data bytes")?,
        relocations: reader.u32("native relocations")?,
        labels: reader.u32("native labels")?,
        vector_instructions: reader.u32("native vector instructions")?,
    };
    if reader.u32("reserved stats")? != 0
        || reader.position() != RECEIPT_IDENTITY_OFFSET_V2
        || source_bytes == 0
        || source_bytes > MAX_AOT_LINUX_SELECTED_END_SOURCE_BYTES_V2
        || object_bytes == 0
        || payload_bytes == 0
        || object_work == 0
        || metadata.source_identity() != &kir_identity
        || metadata.artifact_identity() != &artifact_identity
        || metadata.claimed_binding_identity().as_bytes() != &binding_identity
        || metadata.claimed_compile_identity().as_bytes() != &compile_identity
        || u64::from(metadata.payload_bytes()) != payload_bytes
        || metadata.code_bytes() != native_stats.code_bytes
        || metadata.rodata_bytes() != native_stats.data_bytes
        || object_binding_identity_claim(
            &manifest_identity,
            &semantic_binding_identity,
            &source_identity,
            &literal_identity,
            &kir_identity,
            &artifact_identity,
            native_stats,
        ) != binding_identity
    {
        return Err(contract("compiler receipt wire contract"));
    }
    let claimed_receipt_identity = reader.array("compiler receipt identity")?;
    if reader.position() != bytes.len()
        || claimed_receipt_identity
            != digest_with_domain(
                RECEIPT_IDENTITY_DOMAIN_V2,
                &bytes[..RECEIPT_IDENTITY_OFFSET_V2],
            )
    {
        return Err(contract("compiler receipt identity"));
    }
    Ok(LinuxSelectedEndCompileReceiptInspectionV2 {
        manifest_identity,
        semantic_binding_identity,
        source_identity,
        literal_identity,
        kir_identity,
        artifact_identity,
        binding_identity,
        compile_identity,
        object_identity,
        metadata,
        object_bytes,
        payload_bytes,
        object_work,
        native_stats,
        source_bytes,
        receipt_identity: LinuxSelectedEndCompileReceiptIdentityV2::new(claimed_receipt_identity),
    })
}

fn validate_policy(
    policy: LinuxAarch64SelectedEndCompilePolicyV2,
) -> Result<(), LinuxSelectedEndManifestErrorV2> {
    if policy.max_source_bytes > MAX_AOT_LINUX_SELECTED_END_SOURCE_BYTES_V2 {
        Err(
            LinuxSelectedEndManifestErrorV2::SourcePolicyExceedsHardLimit {
                limit: MAX_AOT_LINUX_SELECTED_END_SOURCE_BYTES_V2,
                requested: policy.max_source_bytes,
            },
        )
    } else {
        Ok(())
    }
}

fn manifest_identity(
    policy: LinuxAarch64SelectedEndCompilePolicyV2,
) -> LinuxSelectedEndManifestIdentityV2 {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_DOMAIN_V2);
    hasher.update(AOT_LINUX_SELECTED_END_COMPILER_VERSION_V2.to_le_bytes());
    hasher.update(AOT_LINUX_SELECTED_END_MANIFEST_SCHEMA_VERSION_V2.to_le_bytes());
    encode_fixed_contract(&mut hasher);
    hasher.update([
        ELF_CLASS_64_V2,
        ELF_DATA_LSB_V2,
        ELF_VERSION_CURRENT_V2,
        ELF_OS_ABI_SYSV_V2,
    ]);
    hasher.update(ELF_RELOCATABLE_TYPE_V2.to_le_bytes());
    hasher.update(ELF_MACHINE_AARCH64_V2.to_le_bytes());
    encode_target(&mut hasher, TargetSpec::AARCH64_AAPCS64_SVE2_16);
    hasher.update(policy.max_source_bytes.to_le_bytes());
    encode_validate_limits(&mut hasher, policy.kernel_ir);
    encode_emit_limits(&mut hasher, policy.native);
    encode_object_limits(&mut hasher, policy.object);
    LinuxSelectedEndManifestIdentityV2::new(hasher.finalize().into())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the binding covers every source, semantic, KIR, and sealed-image identity"
)]
fn object_binding_identity(
    manifest: LinuxSelectedEndManifestIdentityV2,
    semantic: SearchExactLiteralAotSemanticBindingIdentity,
    source: LinuxSelectedEndSourceIdentityV2,
    literal: LinuxSelectedEndLiteralIdentityV2,
    kir: CacheIdentity,
    artifact: SelectedEndRegisterArtifactIdentityV2,
    stats: ImageStats,
) -> [u8; 32] {
    object_binding_identity_claim(
        manifest.as_bytes(),
        semantic.as_bytes(),
        source.as_bytes(),
        literal.as_bytes(),
        kir.as_bytes(),
        artifact.as_bytes(),
        stats,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the decoded receipt independently reconstructs the complete object-binding tuple"
)]
fn object_binding_identity_claim(
    manifest: &[u8; 32],
    semantic: &[u8; 32],
    source: &[u8; 32],
    literal: &[u8; 32],
    kir: &[u8; 32],
    artifact: &[u8; 32],
    stats: ImageStats,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN_V2);
    encode_fixed_contract(&mut hasher);
    for identity in [manifest, semantic, source, literal, kir, artifact] {
        hasher.update(identity);
    }
    encode_image_stats(&mut hasher, stats);
    hasher.finalize().into()
}

fn metadata_matches_receipt(
    metadata: SelectedEndMetadataV2,
    receipt: &LinuxSelectedEndCompileReceiptV2,
) -> bool {
    metadata.backend_version() == SELECTED_END_BACKEND_VERSION_V2
        && metadata.abi_kind() == SELECTED_END_ABI_KIND_V2
        && metadata.output_kind() == SELECTED_END_OUTPUT_KIND_V2
        && metadata.literal_bytes() == SELECTED_END_LITERAL_BYTES_V2
        && metadata.source_identity() == receipt.kir_identity.as_bytes()
        && metadata.artifact_identity() == receipt.artifact_identity.as_bytes()
        && receipt
            .binding_identity
            .matches_claim(metadata.claimed_binding_identity())
        && receipt
            .compile_identity
            .matches_claim(metadata.claimed_compile_identity())
        && u64::from(metadata.payload_bytes()) == receipt.payload_bytes
        && metadata.code_bytes() == receipt.native_stats.code_bytes
        && metadata.rodata_bytes() == receipt.native_stats.data_bytes
}

fn metadata_claim_matches_elf(
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

fn authenticate_image(
    image: &AuditedSelectedEndRegisterImageV2,
    kir_identity: CacheIdentity,
    literal: &[u8; FIXED_LITERAL_BYTES_V2],
) -> Result<(), LinuxSelectedEndCompileErrorV2> {
    if image.backend() != SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16
        || image.backend_version().0 != SELECTED_END_BACKEND_VERSION_V2
        || image.output() != OutputKind::SelectedEnd
        || image.source_identity() != kir_identity
        || image.target() != TargetSpec::AARCH64_AAPCS64_SVE2_16
        || image.literal_bytes() != SELECTED_END_LITERAL_BYTES_V2
        || image.rodata() != literal
        || image.stats().data_bytes != SELECTED_END_LITERAL_BYTES_V2
    {
        return Err(contract("sealed tag21 SelectedEnd image"));
    }
    Ok(())
}

fn authenticate_source(
    source: &[u8],
    literal: &[u8; FIXED_LITERAL_BYTES_V2],
    profile: &RustProfile,
    receipt: &LinuxSelectedEndCompileReceiptV2,
) -> Result<(), LinuxSelectedEndCompileErrorV2> {
    if compute_linux_selected_end_source_identity_v2(source) != receipt.source_identity
        || compute_linux_selected_end_literal_identity_v2(literal) != receipt.literal_identity
        || usize_u64(source.len(), "retained source bytes")? != receipt.source_bytes
    {
        return Err(contract("retained source identity"));
    }
    let source =
        String::from_utf8(source.to_vec()).map_err(|_| contract("retained source UTF-8"))?;
    let regex = PortableBuilder::new(source)
        .profile(profile.clone())
        .build()?;
    let candidate = regex
        .exact_literal_search_aot_candidate()
        .ok_or(LinuxSelectedEndCompileErrorV2::ExactLiteralRequired)?;
    if candidate.selection() != PlanSelection::Auto
        || candidate.build_limits() != BuildLimits::default()
        || candidate.source() != regex.as_str()
        || candidate.profile() != profile
        || candidate.build_report() != regex.build_report()
        || candidate.literal() != literal
        || candidate.semantic_binding_identity() != receipt.semantic_binding_identity
    {
        return Err(contract("retained source semantic binding"));
    }
    Ok(())
}

fn receipt_identity(
    receipt: &LinuxSelectedEndCompileReceiptV2,
) -> Result<LinuxSelectedEndCompileReceiptIdentityV2, LinuxSelectedEndCompileErrorV2> {
    Ok(LinuxSelectedEndCompileReceiptIdentityV2::new(
        digest_with_domain(RECEIPT_IDENTITY_DOMAIN_V2, &encode_receipt_body(receipt)?),
    ))
}

fn encode_receipt_body(
    receipt: &LinuxSelectedEndCompileReceiptV2,
) -> Result<[u8; LINUX_SELECTED_END_COMPILE_RECEIPT_BODY_BYTES_V2], LinuxSelectedEndCompileErrorV2>
{
    let mut bytes = [0_u8; LINUX_SELECTED_END_COMPILE_RECEIPT_BODY_BYTES_V2];
    let mut writer = ReceiptWriter::new(&mut bytes);
    writer.raw(&RECEIPT_MAGIC_V2)?;
    writer.u16(AOT_LINUX_SELECTED_END_COMPILE_RECEIPT_SCHEMA_VERSION_V2)?;
    writer.u16(AOT_LINUX_SELECTED_END_COMPILER_VERSION_V2)?;
    writer.u32(
        u32::try_from(LINUX_SELECTED_END_COMPILE_RECEIPT_BYTES_V2).expect("fixed receipt width"),
    )?;
    writer.u16(SELECTED_END_BACKEND_VERSION_V2)?;
    writer.u16(SELECTED_END_CALL_ABI_SCHEMA_V2)?;
    writer.u8(SELECTED_END_OUTPUT_KIND_V2)?;
    writer.u8(SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2)?;
    writer.u8(SELECTED_END_WINDOW_CONTRACT_HALF_OPEN_ABSOLUTE_END_V2)?;
    writer.u8(SELECTED_END_ARGUMENT_COUNT_V2)?;
    writer.u16(SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2)?;
    writer.u16(SELECTED_END_RESULT_SLOT_BYTES_V2)?;
    writer.u8(SELECTED_END_RETURN_REGISTER_V2)?;
    writer.u8(SELECTED_END_ARCHITECTURE_AARCH64_V2)?;
    writer.u8(SELECTED_END_LITTLE_ENDIAN_V2)?;
    writer.u8(SELECTED_END_POINTER_WIDTH_V2)?;
    writer.u8(SELECTED_END_TARGET_ABI_AAPCS64_V2)?;
    writer.u8(SELECTED_END_PLATFORM_LINUX_V2)?;
    writer.u16(0)?;
    writer.u32(SELECTED_END_LITERAL_BYTES_V2)?;
    writer.u64(SELECTED_END_REQUIRED_FEATURES_V2)?;
    writer.u64(SELECTED_END_NO_MATCH_SENTINEL_V2)?;
    writer.u64(receipt.source_bytes)?;
    if writer.position() != RECEIPT_IDENTITIES_OFFSET_V2 {
        return Err(contract("compiler receipt header width"));
    }
    for identity in [
        receipt.manifest_identity.as_bytes(),
        receipt.semantic_binding_identity.as_bytes(),
        receipt.source_identity.as_bytes(),
        receipt.literal_identity.as_bytes(),
        receipt.kir_identity.as_bytes(),
        receipt.artifact_identity.as_bytes(),
        receipt.binding_identity.as_bytes(),
        receipt.compile_identity.as_bytes(),
        receipt.object_identity.as_bytes(),
    ] {
        writer.raw(identity)?;
    }
    if writer.position() != RECEIPT_METADATA_OFFSET_V2 {
        return Err(contract("compiler receipt identity width"));
    }
    writer.raw(&receipt.metadata.encode()?)?;
    if writer.position() != RECEIPT_STATS_OFFSET_V2 {
        return Err(contract("compiler receipt metadata width"));
    }
    writer.u64(receipt.object_bytes)?;
    writer.u64(receipt.payload_bytes)?;
    writer.u64(receipt.object_work)?;
    writer.u64(receipt.native_stats.emission_work)?;
    writer.u64(receipt.native_stats.scratch_bytes)?;
    writer.u32(receipt.native_stats.code_bytes)?;
    writer.u32(receipt.native_stats.data_bytes)?;
    writer.u32(receipt.native_stats.relocations)?;
    writer.u32(receipt.native_stats.labels)?;
    writer.u32(receipt.native_stats.vector_instructions)?;
    writer.u32(0)?;
    if writer.position() != bytes.len() {
        return Err(contract("compiler receipt encoding width"));
    }
    Ok(bytes)
}

fn encode_receipt(
    receipt: &LinuxSelectedEndCompileReceiptV2,
) -> Result<[u8; LINUX_SELECTED_END_COMPILE_RECEIPT_BYTES_V2], LinuxSelectedEndCompileErrorV2> {
    let body = encode_receipt_body(receipt)?;
    let mut bytes = [0_u8; LINUX_SELECTED_END_COMPILE_RECEIPT_BYTES_V2];
    bytes[..RECEIPT_IDENTITY_OFFSET_V2].copy_from_slice(&body);
    bytes[RECEIPT_IDENTITY_OFFSET_V2..].copy_from_slice(receipt.receipt_identity.as_bytes());
    Ok(bytes)
}

fn encode_fixed_contract(hasher: &mut Sha256) {
    hasher.update(SELECTED_END_BACKEND_VERSION_V2.to_le_bytes());
    hasher.update(SELECTED_END_CALL_ABI_SCHEMA_V2.to_le_bytes());
    hasher.update([
        SELECTED_END_ABI_KIND_V2,
        SELECTED_END_OUTPUT_KIND_V2,
        SELECTED_END_RETURN_ENCODING_END_OR_ZERO_V2,
        SELECTED_END_WINDOW_CONTRACT_HALF_OPEN_ABSOLUTE_END_V2,
        SELECTED_END_ARGUMENT_COUNT_V2,
        SELECTED_END_RETURN_REGISTER_V2,
    ]);
    hasher.update(SELECTED_END_RESULT_SLOT_BYTES_V2.to_le_bytes());
    hasher.update(SELECTED_END_FIXED_ACTIVE_VECTOR_BYTES_V2.to_le_bytes());
    hasher.update(SELECTED_END_REQUIRED_FEATURES_V2.to_le_bytes());
    hasher.update(SELECTED_END_LITERAL_BYTES_V2.to_le_bytes());
}

fn encode_target(hasher: &mut Sha256, target: TargetSpec) {
    hasher.update([
        target.architecture,
        u8::from(target.little_endian),
        target.pointer_width,
        target.abi,
    ]);
    hasher.update(target.features.bits().to_le_bytes());
}

fn encode_validate_limits(hasher: &mut Sha256, limits: ValidateLimits) {
    for value in [
        limits.max_blocks,
        limits.max_instructions,
        limits.max_data_blobs,
        limits.max_data_bytes,
        limits.max_serialized_bytes,
        limits.max_serialized_capacity_bytes,
        limits.max_construction_allocation_bytes,
        limits.max_raw_program_capacity_bytes,
        limits.max_estimated_code_bytes,
        limits.max_validation_work,
        limits.max_construction_work,
        limits.max_validation_scratch_bytes,
        limits.max_validation_phase_bytes,
        limits.max_serialization_phase_bytes,
        limits.max_identity_phase_bytes,
        limits.max_retained_program_bytes,
        limits.max_work_factor,
    ] {
        hasher.update(value.to_le_bytes());
    }
}

fn encode_emit_limits(hasher: &mut Sha256, limits: EmitLimits) {
    for value in [
        limits.max_code_bytes,
        limits.max_data_bytes,
        limits.max_relocations,
        limits.max_labels,
        limits.max_emission_work,
        limits.max_scratch_bytes,
    ] {
        hasher.update(value.to_le_bytes());
    }
}

fn encode_object_limits(hasher: &mut Sha256, limits: SelectedEndObjectLimitsV2) {
    for value in [
        limits.max_object_bytes,
        limits.max_persistent_bytes,
        limits.max_payload_bytes,
        limits.max_work,
    ] {
        hasher.update(value.to_le_bytes());
    }
}

fn encode_image_stats(hasher: &mut Sha256, stats: ImageStats) {
    hasher.update(stats.code_bytes.to_le_bytes());
    hasher.update(stats.data_bytes.to_le_bytes());
    hasher.update(stats.relocations.to_le_bytes());
    hasher.update(stats.labels.to_le_bytes());
    hasher.update(stats.emission_work.to_le_bytes());
    hasher.update(stats.scratch_bytes.to_le_bytes());
    hasher.update(stats.vector_instructions.to_le_bytes());
}

fn length_prefixed_identity(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(bytes.len())
            .expect("admitted identity input length")
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

fn enforce(
    resource: &'static str,
    required: u64,
    limit: u64,
) -> Result<(), LinuxSelectedEndCompileErrorV2> {
    if required > limit {
        Err(LinuxSelectedEndCompileErrorV2::ResourceLimit {
            resource,
            limit,
            required,
        })
    } else {
        Ok(())
    }
}

fn usize_u64(value: usize, at: &'static str) -> Result<u64, LinuxSelectedEndCompileErrorV2> {
    u64::try_from(value).map_err(|_| LinuxSelectedEndCompileErrorV2::ArithmeticOverflow { at })
}

const fn contract(field: &'static str) -> LinuxSelectedEndCompileErrorV2 {
    LinuxSelectedEndCompileErrorV2::ContractMismatch { field }
}

struct ReceiptWriter<'a> {
    destination: &'a mut [u8],
    position: usize,
}

impl<'a> ReceiptWriter<'a> {
    const fn new(destination: &'a mut [u8]) -> Self {
        Self {
            destination,
            position: 0,
        }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), LinuxSelectedEndCompileErrorV2> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or_else(|| contract("compiler receipt writer overflow"))?;
        self.destination
            .get_mut(self.position..end)
            .ok_or_else(|| contract("compiler receipt writer range"))?
            .copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), LinuxSelectedEndCompileErrorV2> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), LinuxSelectedEndCompileErrorV2> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), LinuxSelectedEndCompileErrorV2> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), LinuxSelectedEndCompileErrorV2> {
        self.raw(&value.to_le_bytes())
    }
}

struct ReceiptReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ReceiptReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn take(
        &mut self,
        bytes: usize,
        at: &'static str,
    ) -> Result<&'a [u8], LinuxSelectedEndCompileErrorV2> {
        let end = self
            .position
            .checked_add(bytes)
            .ok_or_else(|| contract(at))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| contract(at))?;
        self.position = end;
        Ok(value)
    }

    fn expect(
        &mut self,
        expected: &[u8],
        at: &'static str,
    ) -> Result<(), LinuxSelectedEndCompileErrorV2> {
        if self.take(expected.len(), at)? == expected {
            Ok(())
        } else {
            Err(contract(at))
        }
    }

    fn u8(&mut self, at: &'static str) -> Result<u8, LinuxSelectedEndCompileErrorV2> {
        self.take(1, at)?
            .first()
            .copied()
            .ok_or_else(|| contract(at))
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, LinuxSelectedEndCompileErrorV2> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, LinuxSelectedEndCompileErrorV2> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn u64(&mut self, at: &'static str) -> Result<u64, LinuxSelectedEndCompileErrorV2> {
        Ok(u64::from_le_bytes(self.array(at)?))
    }

    fn array<const BYTES: usize>(
        &mut self,
        at: &'static str,
    ) -> Result<[u8; BYTES], LinuxSelectedEndCompileErrorV2> {
        self.take(BYTES, at)?.try_into().map_err(|_| contract(at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(source: Vec<u8>) -> LinuxSelectedEndCompiledObjectV2 {
        plan_and_compile_linux_aarch64_selected_end_v2(
            LinuxAarch64SelectedEndManifestV2::default(),
            source,
            RustProfile::default(),
        )
        .expect("Linux tag21 SelectedEnd object")
    }

    #[test]
    fn source_first_compilation_is_deterministic_and_capacity_independent() {
        let exact = b"0123456789abcdef".to_vec();
        let mut spare = Vec::with_capacity(4096);
        spare.extend_from_slice(b"0123456789abcdef");
        let first = compile(exact);
        let second = compile(spare);
        assert_eq!(first.source(), second.source());
        assert_eq!(first.literal(), second.literal());
        assert_eq!(first.profile(), second.profile());
        assert_eq!(first.image(), second.image());
        assert_eq!(first.object(), second.object());
        assert_eq!(first.receipt(), second.receipt());
        assert_eq!(
            first.runtime_authority(),
            SelectedEndAotRuntimeAuthorityV2::Absent
        );
        assert!(
            first
                .validate_source_image_object(SelectedEndObjectLimitsV2::default())
                .is_ok()
        );
        assert!(
            fre_aot_elf::inspect_search_object_v1(
                first.object().as_bytes(),
                fre_aot_elf::ObjectLimitsV1::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn compiler_receipt_reopens_and_every_single_byte_mutation_is_rejected() {
        let compiled = compile(b"0123456789abcdef".to_vec());
        let bytes = compiled
            .receipt()
            .canonical_receipt_bytes()
            .expect("canonical compiler receipt");
        let inspection =
            inspect_linux_selected_end_compile_receipt_v2(&bytes).expect("receipt inspection");
        assert_eq!(
            inspection.receipt_identity(),
            compiled.receipt().receipt_identity()
        );
        assert_eq!(
            inspection.runtime_authority(),
            SelectedEndAotRuntimeAuthorityV2::Absent
        );
        inspection
            .validate_object(
                compiled.object().as_bytes(),
                SelectedEndObjectLimitsV2::default(),
            )
            .expect("reopened compiler object");
        inspection
            .validate_reconstructed_image_object(
                compiled.image(),
                compiled.object().as_bytes(),
                SelectedEndObjectLimitsV2::default(),
            )
            .expect("reconstructed image/object");

        for offset in 0..bytes.len() {
            let mut changed = bytes;
            changed[offset] ^= 1;
            assert!(
                inspect_linux_selected_end_compile_receipt_v2(&changed).is_err(),
                "receipt mutation at byte {offset} was accepted"
            );
            assert!(
                compiled
                    .receipt()
                    .validate_canonical_receipt_bytes(&changed)
                    .is_err(),
                "trusted receipt accepted mutation at byte {offset}"
            );
        }
    }

    #[test]
    fn v1_contracts_refuse_the_v2_receipt() {
        let compiled = compile(b"0123456789abcdef".to_vec());
        let bytes = compiled
            .receipt()
            .canonical_receipt_bytes()
            .expect("canonical compiler receipt");
        assert!(crate::inspect_linux_search_compile_receipt_v1(&bytes).is_err());
        assert!(
            fre_aot_search_contract::inspect_static_search_span_expectation_v1(&bytes).is_err()
        );
    }

    #[test]
    fn compiler_refuses_nonexact_wrong_width_and_invalid_utf8_sources() {
        for source in [
            b"0123456789abcde".to_vec(),
            b"0123456789abcdefg".to_vec(),
            b"01234567.*abcdef".to_vec(),
            vec![0xff; FIXED_LITERAL_BYTES_V2],
        ] {
            assert!(
                plan_and_compile_linux_aarch64_selected_end_v2(
                    LinuxAarch64SelectedEndManifestV2::default(),
                    source,
                    RustProfile::default(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn source_length_and_capacity_are_admitted_before_parsing() {
        let mut policy = LinuxAarch64SelectedEndCompilePolicyV2::default();
        policy.max_source_bytes = 16;
        let manifest =
            LinuxAarch64SelectedEndManifestV2::new(policy).expect("bounded source manifest");

        let mut excess_capacity = Vec::with_capacity(17);
        excess_capacity.extend_from_slice(b"0123456789abcdef");
        assert!(matches!(
            plan_and_compile_linux_aarch64_selected_end_v2(
                manifest,
                excess_capacity,
                RustProfile::default(),
            ),
            Err(LinuxSelectedEndCompileErrorV2::ResourceLimit {
                resource: "source capacity bytes",
                ..
            })
        ));

        let mut excess_length = b"0123456789abcdef".to_vec();
        excess_length.push(0xff);
        excess_length.shrink_to_fit();
        assert!(matches!(
            plan_and_compile_linux_aarch64_selected_end_v2(
                manifest,
                excess_length,
                RustProfile::default(),
            ),
            Err(LinuxSelectedEndCompileErrorV2::ResourceLimit {
                resource: "source bytes",
                ..
            })
        ));
    }

    #[test]
    fn manifest_refuses_source_policy_above_the_hard_limit() {
        let mut policy = LinuxAarch64SelectedEndCompilePolicyV2::default();
        policy.max_source_bytes = MAX_AOT_LINUX_SELECTED_END_SOURCE_BYTES_V2 + 1;
        assert!(matches!(
            LinuxAarch64SelectedEndManifestV2::new(policy),
            Err(
                LinuxSelectedEndManifestErrorV2::SourcePolicyExceedsHardLimit {
                    limit: MAX_AOT_LINUX_SELECTED_END_SOURCE_BYTES_V2,
                    ..
                }
            )
        ));
    }
}
