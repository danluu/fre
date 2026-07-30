//! Source-first Linux `AArch64` exact-literal Search compilation.
//!
//! This vertical slice is deliberately parallel to the byte-stable macOS V8
//! path. A sealed manifest explicitly selects Linux ASIMD V8, an ASIMD V9/V10
//! candidate, or the fixed-VL16 SVE2 tag21 candidate. Selection here stamps
//! an inert compiler artifact only: candidate profiles remain inert and this
//! module neither changes automatic routing nor grants qualification/runtime
//! authority.

use core::{fmt, marker::PhantomData};

use fre::{
    BuildError as FacadeBuildError, BuildLimits, PlanSelection, PortableBuilder, RustProfile,
    SearchExactLiteralAotSemanticBindingIdentity,
};
use fre_aot_elf::{
    BindingIdentity, BindingIdentityError, BuiltSearchObjectV1, CompileIdentity, ELF_CLASS_64_V1,
    ELF_DATA_LSB_V1, ELF_MACHINE_AARCH64_V1, ELF_OS_ABI_SYSV_V1, ELF_RELOCATABLE_TYPE_V1,
    ELF_VERSION_CURRENT_V1, ElfObjectError, METADATA_BYTES_V1, MetadataV1, ObjectIdentity,
    ObjectLimitsV1, PLATFORM_LINUX_V1, emit_search_object_v1, inspect_metadata_v1,
    inspect_search_object_v1,
};
use fre_aot_search_contract::{
    ClaimedSearchMetadataV1, ClaimedStaticSearchSpanExpectationV1, SEARCH_BACKEND_ASIMD_TAG23_V1,
    SEARCH_BACKEND_ASIMD_TAG25_V1, SEARCH_BACKEND_ASIMD_TAG26_V1, SEARCH_BACKEND_ASIMD_TAG28_V1,
    inspect_static_search_span_expectation_v1,
};
use fre_jit_aarch64::{
    ArtifactIdentity, AuditedNativeImage, BackendVersion, CpuFeatures, EmitError, EmitLimits,
    ImageStats, NativeImage, SearchBackendPolicy, TargetSpec, emit_audited_with_backend,
};
use fre_kernel_ir::{
    AnchorFlags, BuildError as KernelBuildError, CacheIdentity, Operation, OutputKind,
    ValidateLimits, build_exact_literal,
};
use sha2::{Digest, Sha256};

use crate::SearchAotRuntimeAuthorityV1;

pub const AOT_LINUX_SEARCH_COMPILER_VERSION_V1: u16 = 1;
pub const AOT_LINUX_SEARCH_MANIFEST_SCHEMA_VERSION_V1: u16 = 1;
pub const AOT_LINUX_SEARCH_COMPILE_RECEIPT_SCHEMA_VERSION_V1: u16 = 1;
/// Exact canonical Linux Search compiler-receipt wire width.
pub const LINUX_SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1: usize = 592;
pub(crate) const MAX_AOT_LINUX_SEARCH_SOURCE_BYTES_V1: u64 = 1 << 20;
pub(crate) const MAX_AOT_LINUX_SEARCH_LITERAL_BYTES_V1: u64 = 32;

const MANIFEST_DOMAIN_V1: &[u8] = b"FRE-AOT-LINUX-SEARCH-MANIFEST\0\x01";
const BINDING_DOMAIN_V1: &[u8] = b"FRE-AOT-LINUX-SEARCH-OBJECT-BINDING\0\x01";
const RECEIPT_DOMAIN_V1: &[u8] = b"FRE-AOT-LINUX-SEARCH-COMPILE-RECEIPT\0\x01";
const LITERAL_DOMAIN_V1: &[u8] = b"FRE-AOT-LINUX-SEARCH-LITERAL\0\x01";

const _: () = assert!(RECEIPT_DOMAIN_V1.len() == 38);
const _: () = assert!(
    RECEIPT_DOMAIN_V1.len()
        + 2
        + 2
        + 32
        + 1
        + 1
        + 2
        + 8
        + 2
        + 32
        + 32
        + 4
        + 32
        + 32
        + 32
        + METADATA_BYTES_V1
        + 32
        + 32
        + 8
        + 8
        + 8
        + 4
        + 4
        + 4
        + 4
        + 8
        + 8
        + 4
        == LINUX_SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1
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
    LinuxSearchManifestIdentityV1,
    "LinuxSearchManifestIdentityV1"
);
identity!(LinuxSearchLiteralIdentityV1, "LinuxSearchLiteralIdentityV1");
identity!(
    LinuxSearchCompileReceiptIdentityV1,
    "LinuxSearchCompileReceiptIdentityV1"
);

/// Explicit Linux code-generation profile. Neither variant participates in
/// facade automatic routing; tag21 is intentionally named as a candidate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LinuxAarch64SearchBackendV1 {
    #[default]
    AsimdV8,
    AsimdV9,
    AsimdV10,
    AsimdV12,
    AsimdV13,
    AsimdV15,
    Sve2Fixed16Tag21Vl16,
}

impl LinuxAarch64SearchBackendV1 {
    #[must_use]
    pub const fn emitter_policy(self) -> SearchBackendPolicy {
        match self {
            Self::AsimdV8 => SearchBackendPolicy::AsimdV8,
            Self::AsimdV9 => SearchBackendPolicy::AsimdV9,
            Self::AsimdV10 => SearchBackendPolicy::AsimdV10,
            Self::AsimdV12 => SearchBackendPolicy::AsimdV12,
            Self::AsimdV13 => SearchBackendPolicy::AsimdV13,
            Self::AsimdV15 => SearchBackendPolicy::AsimdV15,
            Self::Sve2Fixed16Tag21Vl16 => SearchBackendPolicy::Sve2Fixed16V2,
        }
    }

    #[must_use]
    pub const fn backend_version(self) -> BackendVersion {
        self.emitter_policy().backend_version()
    }

    #[must_use]
    pub const fn required_features(self) -> CpuFeatures {
        match self {
            Self::AsimdV8
            | Self::AsimdV9
            | Self::AsimdV10
            | Self::AsimdV12
            | Self::AsimdV13
            | Self::AsimdV15 => CpuFeatures::ASIMD,
            Self::Sve2Fixed16Tag21Vl16 => CpuFeatures::ASIMD_SVE2,
        }
    }

    #[must_use]
    pub const fn fixed_active_vector_bytes(self) -> u16 {
        match self {
            Self::AsimdV8
            | Self::AsimdV9
            | Self::AsimdV10
            | Self::AsimdV12
            | Self::AsimdV13
            | Self::AsimdV15 => 0,
            Self::Sve2Fixed16Tag21Vl16 => 16,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::AsimdV8 => 1,
            Self::AsimdV9 => 3,
            Self::AsimdV10 => 4,
            Self::AsimdV12 => 5,
            Self::AsimdV13 => 6,
            Self::AsimdV15 => 7,
            Self::Sve2Fixed16Tag21Vl16 => 2,
        }
    }
}

/// Finite source, KIR, native-image, and ELF limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxAarch64SearchCompilePolicyV1 {
    pub max_source_bytes: u64,
    pub max_literal_bytes: u64,
    pub kernel_ir: ValidateLimits,
    pub native: EmitLimits,
    pub object: ObjectLimitsV1,
}

impl LinuxAarch64SearchCompilePolicyV1 {
    #[must_use]
    pub fn high_fuel() -> Self {
        Self {
            max_source_bytes: MAX_AOT_LINUX_SEARCH_SOURCE_BYTES_V1,
            max_literal_bytes: MAX_AOT_LINUX_SEARCH_LITERAL_BYTES_V1,
            kernel_ir: ValidateLimits::default(),
            native: EmitLimits::default(),
            object: ObjectLimitsV1::default(),
        }
    }
}

impl Default for LinuxAarch64SearchCompilePolicyV1 {
    fn default() -> Self {
        Self::high_fuel()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LinuxSearchManifestErrorV1 {
    SourcePolicyExceedsHardLimit { limit: u64, requested: u64 },
    LiteralPolicyExceedsHardLimit { limit: u64, requested: u64 },
    UnsupportedCandidateBackendTag { requested: u16 },
}

impl fmt::Display for LinuxSearchManifestErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Linux Search AOT manifest: {self:?}")
    }
}

impl std::error::Error for LinuxSearchManifestErrorV1 {}

/// Sealed Linux `AArch64` request for one output type and explicit backend.
pub struct LinuxAarch64ExactSearchManifestV1<O: Operation> {
    policy: LinuxAarch64SearchCompilePolicyV1,
    backend: LinuxAarch64SearchBackendV1,
    identity: LinuxSearchManifestIdentityV1,
    operation: PhantomData<fn() -> O>,
}

impl<O: Operation> Copy for LinuxAarch64ExactSearchManifestV1<O> {}

impl<O: Operation> Clone for LinuxAarch64ExactSearchManifestV1<O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<O: Operation> fmt::Debug for LinuxAarch64ExactSearchManifestV1<O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxAarch64ExactSearchManifestV1")
            .field("policy", &self.policy)
            .field("backend", &self.backend)
            .field("identity", &self.identity)
            .field("output", &O::KIND)
            .finish()
    }
}

impl<O: Operation> LinuxAarch64ExactSearchManifestV1<O> {
    pub fn new(
        policy: LinuxAarch64SearchCompilePolicyV1,
        backend: LinuxAarch64SearchBackendV1,
    ) -> Result<Self, LinuxSearchManifestErrorV1> {
        validate_policy(policy)?;
        Ok(Self {
            policy,
            backend,
            identity: manifest_identity::<O>(policy, backend),
            operation: PhantomData,
        })
    }

    /// Explicit tag21 candidate constructor. No automatic/default call reaches
    /// this profile.
    pub fn tag21_candidate(
        policy: LinuxAarch64SearchCompilePolicyV1,
    ) -> Result<Self, LinuxSearchManifestErrorV1> {
        Self::new(policy, LinuxAarch64SearchBackendV1::Sve2Fixed16Tag21Vl16)
    }

    /// Explicit ASIMD V9 candidate constructor. No automatic/default call
    /// reaches this profile.
    pub fn v9_candidate(
        policy: LinuxAarch64SearchCompilePolicyV1,
    ) -> Result<Self, LinuxSearchManifestErrorV1> {
        Self::new(policy, LinuxAarch64SearchBackendV1::AsimdV9)
    }

    /// Explicit ASIMD V10 candidate constructor. No automatic/default call
    /// reaches this profile.
    pub fn v10_candidate(
        policy: LinuxAarch64SearchCompilePolicyV1,
    ) -> Result<Self, LinuxSearchManifestErrorV1> {
        Self::new(policy, LinuxAarch64SearchBackendV1::AsimdV10)
    }

    /// Construct an explicit ASIMD V12/tag25 candidate. This does not grant
    /// runtime or automatic-routing authority.
    pub fn v12_candidate(
        policy: LinuxAarch64SearchCompilePolicyV1,
    ) -> Result<Self, LinuxSearchManifestErrorV1> {
        Self::new(policy, LinuxAarch64SearchBackendV1::AsimdV12)
    }

    /// Construct an explicit ASIMD V13/tag26 candidate. This does not grant
    /// runtime or automatic-routing authority.
    pub fn v13_candidate(
        policy: LinuxAarch64SearchCompilePolicyV1,
    ) -> Result<Self, LinuxSearchManifestErrorV1> {
        Self::new(policy, LinuxAarch64SearchBackendV1::AsimdV13)
    }

    /// Construct an explicit ASIMD V15/tag28 phase-unique candidate. This
    /// does not grant runtime or automatic-routing authority.
    pub fn v15_candidate(
        policy: LinuxAarch64SearchCompilePolicyV1,
    ) -> Result<Self, LinuxSearchManifestErrorV1> {
        Self::new(policy, LinuxAarch64SearchBackendV1::AsimdV15)
    }

    /// Construct a named candidate by its static-contract backend tag.
    ///
    /// The external evidence runner can therefore carry the backend as sealed
    /// data. Extending this closed mapping for a later reviewed backend does
    /// not require fixture or runner changes.
    pub fn candidate_backend_tag(
        policy: LinuxAarch64SearchCompilePolicyV1,
        backend_tag: u16,
    ) -> Result<Self, LinuxSearchManifestErrorV1> {
        match backend_tag {
            SEARCH_BACKEND_ASIMD_TAG23_V1 => Self::v10_candidate(policy),
            SEARCH_BACKEND_ASIMD_TAG25_V1 => Self::v12_candidate(policy),
            SEARCH_BACKEND_ASIMD_TAG26_V1 => Self::v13_candidate(policy),
            SEARCH_BACKEND_ASIMD_TAG28_V1 => Self::v15_candidate(policy),
            requested => {
                Err(LinuxSearchManifestErrorV1::UnsupportedCandidateBackendTag { requested })
            }
        }
    }

    #[must_use]
    pub const fn policy(&self) -> &LinuxAarch64SearchCompilePolicyV1 {
        &self.policy
    }

    #[must_use]
    pub const fn backend(&self) -> LinuxAarch64SearchBackendV1 {
        self.backend
    }

    #[must_use]
    pub const fn identity(&self) -> LinuxSearchManifestIdentityV1 {
        self.identity
    }

    fn authenticates_itself(&self) -> bool {
        validate_policy(self.policy).is_ok()
            && manifest_identity::<O>(self.policy, self.backend) == self.identity
    }
}

impl<O: Operation> Default for LinuxAarch64ExactSearchManifestV1<O> {
    fn default() -> Self {
        Self::new(
            LinuxAarch64SearchCompilePolicyV1::high_fuel(),
            LinuxAarch64SearchBackendV1::AsimdV8,
        )
        .expect("fixed Linux V8 manifest")
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum LinuxSearchCompileErrorV1 {
    ManifestAuthentication,
    ResourceLimit {
        resource: &'static str,
        limit: u64,
        required: u64,
    },
    InvalidUtf8Source,
    Facade(FacadeBuildError),
    ExactLiteralRequired,
    EmptyLiteralUnsupported,
    BackendLiteralShape {
        backend: LinuxAarch64SearchBackendV1,
        literal_bytes: u64,
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

impl fmt::Display for LinuxSearchCompileErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Linux exact Search AOT compilation failed: {self:?}"
        )
    }
}

impl std::error::Error for LinuxSearchCompileErrorV1 {
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

impl From<FacadeBuildError> for LinuxSearchCompileErrorV1 {
    fn from(value: FacadeBuildError) -> Self {
        Self::Facade(value)
    }
}

impl From<KernelBuildError> for LinuxSearchCompileErrorV1 {
    fn from(value: KernelBuildError) -> Self {
        Self::Kernel(value)
    }
}

impl From<EmitError> for LinuxSearchCompileErrorV1 {
    fn from(value: EmitError) -> Self {
        Self::Native(value)
    }
}

impl From<BindingIdentityError> for LinuxSearchCompileErrorV1 {
    fn from(value: BindingIdentityError) -> Self {
        Self::Binding(value)
    }
}

impl From<ElfObjectError> for LinuxSearchCompileErrorV1 {
    fn from(value: ElfObjectError) -> Self {
        Self::Object(value)
    }
}

/// Strict claim-side projection of one fixed-width Linux compiler receipt.
///
/// The receipt wire authenticates itself and closes all compiler/object
/// identities, but remains inert. Runtime authority requires an independent
/// source-qualified final-image row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSearchCompileReceiptInspectionV1 {
    manifest_identity: [u8; 32],
    backend: LinuxAarch64SearchBackendV1,
    semantic_binding_identity: [u8; 32],
    literal_identity: [u8; 32],
    literal_bytes: u32,
    output: OutputKind,
    kir_identity: [u8; 32],
    artifact_identity: [u8; 32],
    binding_identity: [u8; 32],
    metadata: MetadataV1,
    compile_identity: [u8; 32],
    object_identity: [u8; 32],
    object_bytes: u64,
    source_bytes: u64,
    source_capacity_bytes: u64,
    native_stats: ImageStats,
    receipt_identity: LinuxSearchCompileReceiptIdentityV1,
}

impl LinuxSearchCompileReceiptInspectionV1 {
    #[must_use]
    pub const fn manifest_identity(&self) -> &[u8; 32] {
        &self.manifest_identity
    }

    #[must_use]
    pub const fn backend(&self) -> LinuxAarch64SearchBackendV1 {
        self.backend
    }

    #[must_use]
    pub const fn semantic_binding_identity(&self) -> &[u8; 32] {
        &self.semantic_binding_identity
    }

    #[must_use]
    pub const fn literal_identity(&self) -> &[u8; 32] {
        &self.literal_identity
    }

    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        self.literal_bytes
    }

    #[must_use]
    pub const fn output(&self) -> OutputKind {
        self.output
    }

    #[must_use]
    pub const fn kir_identity(&self) -> &[u8; 32] {
        &self.kir_identity
    }

    #[must_use]
    pub const fn artifact_identity(&self) -> &[u8; 32] {
        &self.artifact_identity
    }

    #[must_use]
    pub const fn binding_identity(&self) -> &[u8; 32] {
        &self.binding_identity
    }

    #[must_use]
    pub const fn metadata(&self) -> MetadataV1 {
        self.metadata
    }

    #[must_use]
    pub const fn compile_identity(&self) -> &[u8; 32] {
        &self.compile_identity
    }

    #[must_use]
    pub const fn object_identity(&self) -> &[u8; 32] {
        &self.object_identity
    }

    #[must_use]
    pub const fn object_bytes(&self) -> u64 {
        self.object_bytes
    }

    #[must_use]
    pub const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    #[must_use]
    pub const fn source_capacity_bytes(&self) -> u64 {
        self.source_capacity_bytes
    }

    #[must_use]
    pub const fn native_stats(&self) -> ImageStats {
        self.native_stats
    }

    #[must_use]
    pub const fn receipt_identity(&self) -> LinuxSearchCompileReceiptIdentityV1 {
        self.receipt_identity
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }

    /// Bind arbitrary implementation bytes to this independently decoded
    /// receipt.
    pub fn validate_object<'a>(
        &self,
        bytes: &'a [u8],
        limits: ObjectLimitsV1,
    ) -> Result<fre_aot_elf::ObjectInspectionV1<'a>, LinuxSearchCompileErrorV1> {
        let inspection = inspect_search_object_v1(bytes, limits)?;
        if inspection.metadata() != self.metadata
            || u64::try_from(inspection.object_bytes()).ok() != Some(self.object_bytes)
            || inspection.claimed_compile_identity().as_bytes() != &self.compile_identity
            || inspection.claimed_object_identity().as_bytes() != &self.object_identity
        {
            return Err(contract("decoded compiler receipt/object"));
        }
        Ok(inspection)
    }

    /// Bind one independently reconstructed native image to both this decoded
    /// receipt and the exact canonical implementation object.
    ///
    /// The caller is responsible for reconstructing `image` from the
    /// authenticated source. This method then compares the complete native
    /// statistics retained by the receipt and delegates the code, padding,
    /// rodata, layout, target, and metadata comparison to the ELF validator.
    pub fn validate_reconstructed_image_object<'a>(
        &self,
        image: &NativeImage,
        bytes: &'a [u8],
        limits: ObjectLimitsV1,
    ) -> Result<fre_aot_elf::ObjectValidationV1<'a>, LinuxSearchCompileErrorV1> {
        if image.backend_version() != self.backend.backend_version()
            || image.output() != self.output
            || image.source_identity().as_bytes() != &self.kir_identity
            || image.artifact_identity().as_bytes() != &self.artifact_identity
            || image.stats() != self.native_stats
        {
            return Err(contract("decoded compiler receipt/reconstructed image"));
        }
        let binding = BindingIdentity::new(self.binding_identity)?;
        let validation = fre_aot_elf::validate_search_object_v1(image, binding, bytes, limits)?;
        let inspection = validation.inspection();
        if inspection.metadata() != self.metadata
            || u64::try_from(inspection.object_bytes()).ok() != Some(self.object_bytes)
            || inspection.claimed_compile_identity().as_bytes() != &self.compile_identity
            || inspection.claimed_object_identity().as_bytes() != &self.object_identity
        {
            return Err(contract(
                "decoded compiler receipt/reconstructed image/object",
            ));
        }
        Ok(validation)
    }

    /// Bind one neutral Span expectation to this decoded compiler receipt.
    pub fn validate_span_expectation(
        &self,
        bytes: &[u8],
    ) -> Result<ClaimedStaticSearchSpanExpectationV1, LinuxSearchCompileErrorV1> {
        if self.output != OutputKind::Span {
            return Err(contract("decoded compiler receipt Span output"));
        }
        let claim = inspect_static_search_span_expectation_v1(bytes)
            .map_err(|_| contract("decoded compiler receipt expectation"))?;
        if claim.backend_version() != self.backend.backend_version().0
            || claim.required_features() != self.backend.required_features().bits()
            || claim.live_literal_bytes() != self.literal_bytes
            || claim.manifest_identity() != &self.manifest_identity
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

/// Source/compiler/object receipt. Every object-facing identity is either
/// independently reconstructable from retained fields or compared against a
/// strict reinspection of the exact ELF bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSearchCompileReceiptV1 {
    manifest_identity: LinuxSearchManifestIdentityV1,
    backend: LinuxAarch64SearchBackendV1,
    semantic_binding_identity: SearchExactLiteralAotSemanticBindingIdentity,
    literal_identity: LinuxSearchLiteralIdentityV1,
    literal_bytes: u32,
    output: OutputKind,
    kir_identity: CacheIdentity,
    artifact_identity: ArtifactIdentity,
    binding_identity: BindingIdentity,
    metadata: MetadataV1,
    compile_identity: CompileIdentity,
    object_identity: ObjectIdentity,
    object_bytes: u64,
    source_bytes: u64,
    source_capacity_bytes: u64,
    native_stats: ImageStats,
    receipt_identity: LinuxSearchCompileReceiptIdentityV1,
}

impl LinuxSearchCompileReceiptV1 {
    #[must_use]
    pub const fn manifest_identity(&self) -> LinuxSearchManifestIdentityV1 {
        self.manifest_identity
    }

    #[must_use]
    pub const fn backend(&self) -> LinuxAarch64SearchBackendV1 {
        self.backend
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
    pub const fn literal_bytes(&self) -> u32 {
        self.literal_bytes
    }

    #[must_use]
    pub const fn output(&self) -> OutputKind {
        self.output
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
    pub const fn metadata(&self) -> MetadataV1 {
        self.metadata
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
    pub const fn object_bytes(&self) -> u64 {
        self.object_bytes
    }

    #[must_use]
    pub const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    #[must_use]
    pub const fn source_capacity_bytes(&self) -> u64 {
        self.source_capacity_bytes
    }

    #[must_use]
    pub const fn native_stats(&self) -> ImageStats {
        self.native_stats
    }

    #[must_use]
    pub const fn receipt_identity(&self) -> LinuxSearchCompileReceiptIdentityV1 {
        self.receipt_identity
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }

    pub fn canonical_receipt_bytes(
        &self,
    ) -> Result<[u8; LINUX_SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1], LinuxSearchCompileErrorV1>
    {
        if !self.authenticates_itself() {
            return Err(contract("compiler receipt"));
        }
        encode_receipt_body(self)
    }

    /// Reopen and strictly bind an externally persisted canonical receipt
    /// wire to this trusted in-process receipt.
    pub fn validate_canonical_receipt_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<LinuxSearchCompileReceiptInspectionV1, LinuxSearchCompileErrorV1> {
        if !self.authenticates_itself() || self.canonical_receipt_bytes()?.as_slice() != bytes {
            return Err(contract("reopened compiler receipt"));
        }
        let inspection = inspect_linux_search_compile_receipt_v1(bytes)?;
        if inspection.receipt_identity != self.receipt_identity {
            return Err(contract("reopened compiler receipt identity"));
        }
        Ok(inspection)
    }

    pub fn validate_object<'a>(
        &self,
        bytes: &'a [u8],
        limits: ObjectLimitsV1,
    ) -> Result<fre_aot_elf::ObjectInspectionV1<'a>, LinuxSearchCompileErrorV1> {
        if !self.authenticates_itself() {
            return Err(contract("compiler receipt"));
        }
        let inspection = inspect_search_object_v1(bytes, limits)?;
        if inspection.metadata() != self.metadata
            || u64::try_from(inspection.object_bytes()).ok() != Some(self.object_bytes)
            || !self
                .object_identity
                .matches_claim(inspection.claimed_object_identity())
            || !self
                .compile_identity
                .matches_claim(inspection.claimed_compile_identity())
        {
            return Err(contract("ELF object receipt"));
        }
        Ok(inspection)
    }

    fn authenticates_itself(&self) -> bool {
        let metadata = self.metadata;
        self.source_bytes <= self.source_capacity_bytes
            && self.literal_bytes != 0
            && u64::from(self.literal_bytes) <= MAX_AOT_LINUX_SEARCH_LITERAL_BYTES_V1
            && metadata.backend_version() == self.backend.backend_version().0
            && metadata.output_kind() == output_tag(self.output)
            && metadata.features() == self.backend.required_features().bits()
            && metadata.source_identity() == self.kir_identity.as_bytes()
            && metadata.artifact_identity() == self.artifact_identity.as_bytes()
            && self
                .binding_identity
                .matches_claim(metadata.claimed_binding_identity())
            && self
                .compile_identity
                .matches_claim(metadata.claimed_compile_identity())
            && object_binding_identity(
                self.manifest_identity,
                self.backend,
                self.semantic_binding_identity,
                self.literal_identity,
                self.literal_bytes,
                self.output,
                self.kir_identity,
                self.artifact_identity,
                self.native_stats,
            ) == *self.binding_identity.as_bytes()
            && receipt_identity(self).is_ok_and(|identity| identity == self.receipt_identity)
    }
}

/// Typed inert ELF object with compiler-trusted receipt.
pub struct LinuxSearchCompiledObjectV1<O: Operation> {
    object: BuiltSearchObjectV1,
    receipt: LinuxSearchCompileReceiptV1,
    operation: PhantomData<fn() -> O>,
}

impl<O: Operation> fmt::Debug for LinuxSearchCompiledObjectV1<O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxSearchCompiledObjectV1")
            .field("output", &O::KIND)
            .field("object", &self.object)
            .field("receipt", &self.receipt)
            .field("runtime_authority", &SearchAotRuntimeAuthorityV1::Absent)
            .finish()
    }
}

impl<O: Operation> LinuxSearchCompiledObjectV1<O> {
    #[must_use]
    pub const fn object(&self) -> &BuiltSearchObjectV1 {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> &LinuxSearchCompileReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }

    #[must_use]
    pub fn into_object_bytes(self) -> Vec<u8> {
        self.object.into_bytes()
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the canonical compiler pipeline keeps each authenticated phase in one auditable sequence"
)]
pub fn plan_and_compile_linux_aarch64_exact_search_v1<O: Operation>(
    manifest: LinuxAarch64ExactSearchManifestV1<O>,
    source: Vec<u8>,
    profile: RustProfile,
) -> Result<LinuxSearchCompiledObjectV1<O>, LinuxSearchCompileErrorV1> {
    if !manifest.authenticates_itself() {
        return Err(LinuxSearchCompileErrorV1::ManifestAuthentication);
    }
    let source_bytes = usize_u64(source.len(), "source bytes")?;
    let source_capacity_bytes = usize_u64(source.capacity(), "source capacity")?;
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
    let source =
        String::from_utf8(source).map_err(|_| LinuxSearchCompileErrorV1::InvalidUtf8Source)?;
    let regex = PortableBuilder::new(source).profile(profile).build()?;
    let candidate = regex
        .exact_literal_search_aot_candidate()
        .ok_or(LinuxSearchCompileErrorV1::ExactLiteralRequired)?;
    if candidate.selection() != PlanSelection::Auto
        || candidate.build_limits() != BuildLimits::default()
        || candidate.source() != regex.as_str()
        || candidate.build_report() != regex.build_report()
    {
        return Err(LinuxSearchCompileErrorV1::CandidateAuthentication);
    }
    let literal_bytes = usize_u64(candidate.literal().len(), "literal bytes")?;
    if literal_bytes == 0 {
        return Err(LinuxSearchCompileErrorV1::EmptyLiteralUnsupported);
    }
    enforce(
        "literal bytes",
        literal_bytes,
        manifest.policy.max_literal_bytes,
    )?;
    if manifest.backend == LinuxAarch64SearchBackendV1::Sve2Fixed16Tag21Vl16 && literal_bytes != 16
    {
        return Err(LinuxSearchCompileErrorV1::BackendLiteralShape {
            backend: manifest.backend,
            literal_bytes,
        });
    }

    let program = build_exact_literal::<O>(
        candidate.literal(),
        AnchorFlags::default(),
        manifest.policy.kernel_ir,
    )?;
    let kir_identity = program.cache_identity();
    let audited_image = emit_audited_with_backend(
        &program,
        manifest.backend.emitter_policy(),
        manifest.policy.native,
    )?;
    authenticate_audited_image::<O>(&audited_image, kir_identity, manifest.backend)?;
    let image = audited_image.as_image();
    let literal_identity = compute_linux_search_literal_identity_v1(candidate.literal());
    let binding_bytes = object_binding_identity(
        manifest.identity,
        manifest.backend,
        candidate.semantic_binding_identity(),
        literal_identity,
        u32::try_from(candidate.literal().len()).map_err(|_| {
            LinuxSearchCompileErrorV1::ArithmeticOverflow {
                at: "literal u32 bytes",
            }
        })?,
        O::KIND,
        kir_identity,
        image.artifact_identity(),
        image.stats(),
    );
    let binding_identity = BindingIdentity::new(binding_bytes)?;
    let object = emit_search_object_v1(image, binding_identity, manifest.policy.object)?;
    fre_aot_elf::validate_search_object_v1(
        image,
        binding_identity,
        object.as_bytes(),
        manifest.policy.object,
    )?;

    let mut receipt = LinuxSearchCompileReceiptV1 {
        manifest_identity: manifest.identity,
        backend: manifest.backend,
        semantic_binding_identity: candidate.semantic_binding_identity(),
        literal_identity,
        literal_bytes: u32::try_from(candidate.literal().len()).map_err(|_| {
            LinuxSearchCompileErrorV1::ArithmeticOverflow {
                at: "literal u32 bytes",
            }
        })?,
        output: O::KIND,
        kir_identity,
        artifact_identity: image.artifact_identity(),
        binding_identity,
        metadata: object.metadata(),
        compile_identity: object.compile_identity(),
        object_identity: object.object_identity(),
        object_bytes: usize_u64(object.as_bytes().len(), "object bytes")?,
        source_bytes,
        source_capacity_bytes,
        native_stats: image.stats(),
        receipt_identity: LinuxSearchCompileReceiptIdentityV1::new([0; 32]),
    };
    receipt.receipt_identity = receipt_identity(&receipt)?;
    if !receipt.authenticates_itself()
        || receipt
            .validate_object(object.as_bytes(), manifest.policy.object)
            .is_err()
    {
        return Err(contract("fresh compiler receipt"));
    }
    Ok(LinuxSearchCompiledObjectV1 {
        object,
        receipt,
        operation: PhantomData,
    })
}

fn validate_policy(
    policy: LinuxAarch64SearchCompilePolicyV1,
) -> Result<(), LinuxSearchManifestErrorV1> {
    if policy.max_source_bytes > MAX_AOT_LINUX_SEARCH_SOURCE_BYTES_V1 {
        return Err(LinuxSearchManifestErrorV1::SourcePolicyExceedsHardLimit {
            limit: MAX_AOT_LINUX_SEARCH_SOURCE_BYTES_V1,
            requested: policy.max_source_bytes,
        });
    }
    if policy.max_literal_bytes > MAX_AOT_LINUX_SEARCH_LITERAL_BYTES_V1 {
        return Err(LinuxSearchManifestErrorV1::LiteralPolicyExceedsHardLimit {
            limit: MAX_AOT_LINUX_SEARCH_LITERAL_BYTES_V1,
            requested: policy.max_literal_bytes,
        });
    }
    Ok(())
}

fn manifest_identity<O: Operation>(
    policy: LinuxAarch64SearchCompilePolicyV1,
    backend: LinuxAarch64SearchBackendV1,
) -> LinuxSearchManifestIdentityV1 {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_DOMAIN_V1);
    hasher.update(AOT_LINUX_SEARCH_COMPILER_VERSION_V1.to_le_bytes());
    hasher.update(AOT_LINUX_SEARCH_MANIFEST_SCHEMA_VERSION_V1.to_le_bytes());
    hasher.update([output_tag(O::KIND), backend.tag()]);
    hasher.update(backend.backend_version().0.to_le_bytes());
    hasher.update(backend.required_features().bits().to_le_bytes());
    hasher.update(backend.fixed_active_vector_bytes().to_le_bytes());
    hasher.update([
        PLATFORM_LINUX_V1,
        ELF_CLASS_64_V1,
        ELF_DATA_LSB_V1,
        ELF_VERSION_CURRENT_V1,
        ELF_OS_ABI_SYSV_V1,
    ]);
    hasher.update(ELF_RELOCATABLE_TYPE_V1.to_le_bytes());
    hasher.update(ELF_MACHINE_AARCH64_V1.to_le_bytes());
    encode_target(&mut hasher, target_for_backend(backend));
    hasher.update(policy.max_source_bytes.to_le_bytes());
    hasher.update(policy.max_literal_bytes.to_le_bytes());
    encode_validate_limits(&mut hasher, policy.kernel_ir);
    encode_emit_limits(&mut hasher, policy.native);
    encode_object_limits(&mut hasher, policy.object);
    LinuxSearchManifestIdentityV1::new(hasher.finalize().into())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the binding covers every source/KIR/native target field"
)]
fn object_binding_identity(
    manifest: LinuxSearchManifestIdentityV1,
    backend: LinuxAarch64SearchBackendV1,
    semantic: SearchExactLiteralAotSemanticBindingIdentity,
    literal: LinuxSearchLiteralIdentityV1,
    literal_bytes: u32,
    output: OutputKind,
    kir: CacheIdentity,
    artifact: ArtifactIdentity,
    stats: ImageStats,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN_V1);
    hasher.update(manifest.as_bytes());
    hasher.update([backend.tag(), output_tag(output)]);
    hasher.update(backend.backend_version().0.to_le_bytes());
    hasher.update(backend.required_features().bits().to_le_bytes());
    hasher.update(backend.fixed_active_vector_bytes().to_le_bytes());
    hasher.update(semantic.as_bytes());
    hasher.update(literal.as_bytes());
    hasher.update(literal_bytes.to_le_bytes());
    hasher.update(kir.as_bytes());
    hasher.update(artifact.as_bytes());
    encode_image_stats(&mut hasher, stats);
    hasher.finalize().into()
}

#[allow(
    clippy::too_many_arguments,
    reason = "the decoded receipt must independently reconstruct the complete object-binding tuple"
)]
fn object_binding_identity_claim(
    manifest: &[u8; 32],
    backend: LinuxAarch64SearchBackendV1,
    semantic: &[u8; 32],
    literal: &[u8; 32],
    literal_bytes: u32,
    output: OutputKind,
    kir: &[u8; 32],
    artifact: &[u8; 32],
    stats: ImageStats,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN_V1);
    hasher.update(manifest);
    hasher.update([backend.tag(), output_tag(output)]);
    hasher.update(backend.backend_version().0.to_le_bytes());
    hasher.update(backend.required_features().bits().to_le_bytes());
    hasher.update(backend.fixed_active_vector_bytes().to_le_bytes());
    hasher.update(semantic);
    hasher.update(literal);
    hasher.update(literal_bytes.to_le_bytes());
    hasher.update(kir);
    hasher.update(artifact);
    encode_image_stats(&mut hasher, stats);
    hasher.finalize().into()
}

fn metadata_claim_matches_elf(claim: ClaimedSearchMetadataV1, metadata: MetadataV1) -> bool {
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
        && claim.status_bits() == metadata.status_bits()
        && claim.abi_schema() == metadata.abi_schema()
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

/// Compute the canonical Linux Search literal identity from exact source
/// bytes. This is an integrity projection only and grants no runtime or
/// qualification authority.
#[must_use]
pub fn compute_linux_search_literal_identity_v1(literal: &[u8]) -> LinuxSearchLiteralIdentityV1 {
    let mut hasher = Sha256::new();
    hasher.update(LITERAL_DOMAIN_V1);
    hasher.update(
        u64::try_from(literal.len())
            .expect("admitted literal length")
            .to_le_bytes(),
    );
    hasher.update(literal);
    LinuxSearchLiteralIdentityV1::new(hasher.finalize().into())
}

/// Strictly decode the fixed canonical Linux Search compiler-receipt wire.
///
/// Successful inspection recomputes the receipt and object-binding identities
/// and validates the embedded metadata. It does not trust a linked address or
/// grant runtime authority.
#[allow(
    clippy::too_many_lines,
    reason = "one linear decoder keeps every canonical compiler-receipt field auditable in wire order"
)]
pub fn inspect_linux_search_compile_receipt_v1(
    bytes: &[u8],
) -> Result<LinuxSearchCompileReceiptInspectionV1, LinuxSearchCompileErrorV1> {
    if bytes.len() != LINUX_SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1 {
        return Err(contract("compiler receipt wire extent"));
    }
    let mut reader = ReceiptReader::new(bytes);
    reader.expect(RECEIPT_DOMAIN_V1, "compiler receipt domain")?;
    if reader.u16("compiler receipt schema")? != AOT_LINUX_SEARCH_COMPILE_RECEIPT_SCHEMA_VERSION_V1
        || reader.u16("compiler version")? != AOT_LINUX_SEARCH_COMPILER_VERSION_V1
    {
        return Err(contract("compiler receipt header"));
    }
    let manifest_identity = reader.array("manifest identity")?;
    let backend_tag = reader.u8("backend tag")?;
    let output_tag = reader.u8("output tag")?;
    let backend_version = reader.u16("backend version")?;
    let required_features = reader.u64("required features")?;
    let fixed_active_vector_bytes = reader.u16("fixed active vector bytes")?;
    let backend = decode_backend_profile(
        backend_tag,
        backend_version,
        required_features,
        fixed_active_vector_bytes,
    )?;
    let output = decode_output_tag(output_tag)?;
    let semantic_binding_identity = reader.array("semantic binding identity")?;
    let literal_identity = reader.array("literal identity")?;
    let literal_bytes = reader.u32("literal bytes")?;
    let kir_identity = reader.array("KIR identity")?;
    let artifact_identity = reader.array("artifact identity")?;
    let binding_identity = reader.array("binding identity")?;
    let metadata_bytes: [u8; METADATA_BYTES_V1] = reader.array("metadata")?;
    let metadata = inspect_metadata_v1(&metadata_bytes)?;
    let compile_identity = reader.array("compile identity")?;
    let object_identity = reader.array("object identity")?;
    let object_bytes = reader.u64("object bytes")?;
    let source_bytes = reader.u64("source bytes")?;
    let source_capacity_bytes = reader.u64("source capacity bytes")?;
    let native_stats = ImageStats {
        code_bytes: reader.u32("native code bytes")?,
        data_bytes: reader.u32("native data bytes")?,
        relocations: reader.u32("native relocations")?,
        labels: reader.u32("native labels")?,
        emission_work: reader.u64("native emission work")?,
        scratch_bytes: reader.u64("native scratch bytes")?,
        vector_instructions: reader.u32("native vector instructions")?,
    };
    if reader.position() != bytes.len()
        || literal_bytes == 0
        || u64::from(literal_bytes) > MAX_AOT_LINUX_SEARCH_LITERAL_BYTES_V1
        || (backend == LinuxAarch64SearchBackendV1::Sve2Fixed16Tag21Vl16 && literal_bytes != 16)
        || source_bytes > source_capacity_bytes
        || source_capacity_bytes > MAX_AOT_LINUX_SEARCH_SOURCE_BYTES_V1
        || object_bytes == 0
        || metadata.backend_version() != backend.backend_version().0
        || metadata.output_kind() != output_tag
        || metadata.features() != backend.required_features().bits()
        || metadata.rodata_bytes() != literal_bytes
        || metadata.source_identity() != &kir_identity
        || metadata.artifact_identity() != &artifact_identity
        || metadata.claimed_binding_identity().as_bytes() != &binding_identity
        || metadata.claimed_compile_identity().as_bytes() != &compile_identity
        || metadata.code_bytes() != native_stats.code_bytes
        || metadata.rodata_bytes() != native_stats.data_bytes
        || object_binding_identity_claim(
            &manifest_identity,
            backend,
            &semantic_binding_identity,
            &literal_identity,
            literal_bytes,
            output,
            &kir_identity,
            &artifact_identity,
            native_stats,
        ) != binding_identity
    {
        return Err(contract("compiler receipt wire contract"));
    }
    Ok(LinuxSearchCompileReceiptInspectionV1 {
        manifest_identity,
        backend,
        semantic_binding_identity,
        literal_identity,
        literal_bytes,
        output,
        kir_identity,
        artifact_identity,
        binding_identity,
        metadata,
        compile_identity,
        object_identity,
        object_bytes,
        source_bytes,
        source_capacity_bytes,
        native_stats,
        receipt_identity: LinuxSearchCompileReceiptIdentityV1::new(Sha256::digest(bytes).into()),
    })
}

fn receipt_identity(
    receipt: &LinuxSearchCompileReceiptV1,
) -> Result<LinuxSearchCompileReceiptIdentityV1, LinuxSearchCompileErrorV1> {
    let bytes = encode_receipt_body(receipt)?;
    Ok(LinuxSearchCompileReceiptIdentityV1::new(
        Sha256::digest(bytes).into(),
    ))
}

fn encode_receipt_body(
    receipt: &LinuxSearchCompileReceiptV1,
) -> Result<[u8; LINUX_SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1], LinuxSearchCompileErrorV1> {
    let mut bytes = [0_u8; LINUX_SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1];
    let mut writer = ReceiptWriter::new(&mut bytes);
    writer.raw(RECEIPT_DOMAIN_V1)?;
    writer.u16(AOT_LINUX_SEARCH_COMPILE_RECEIPT_SCHEMA_VERSION_V1)?;
    writer.u16(AOT_LINUX_SEARCH_COMPILER_VERSION_V1)?;
    writer.raw(receipt.manifest_identity.as_bytes())?;
    writer.u8(receipt.backend.tag())?;
    writer.u8(output_tag(receipt.output))?;
    writer.u16(receipt.backend.backend_version().0)?;
    writer.u64(receipt.backend.required_features().bits())?;
    writer.u16(receipt.backend.fixed_active_vector_bytes())?;
    writer.raw(receipt.semantic_binding_identity.as_bytes())?;
    writer.raw(receipt.literal_identity.as_bytes())?;
    writer.u32(receipt.literal_bytes)?;
    writer.raw(receipt.kir_identity.as_bytes())?;
    writer.raw(receipt.artifact_identity.as_bytes())?;
    writer.raw(receipt.binding_identity.as_bytes())?;
    writer.raw(&receipt.metadata.encode()?)?;
    writer.raw(receipt.compile_identity.as_bytes())?;
    writer.raw(receipt.object_identity.as_bytes())?;
    writer.u64(receipt.object_bytes)?;
    writer.u64(receipt.source_bytes)?;
    writer.u64(receipt.source_capacity_bytes)?;
    writer.u32(receipt.native_stats.code_bytes)?;
    writer.u32(receipt.native_stats.data_bytes)?;
    writer.u32(receipt.native_stats.relocations)?;
    writer.u32(receipt.native_stats.labels)?;
    writer.u64(receipt.native_stats.emission_work)?;
    writer.u64(receipt.native_stats.scratch_bytes)?;
    writer.u32(receipt.native_stats.vector_instructions)?;
    if writer.position() != bytes.len() {
        return Err(contract("compiler receipt encoding width"));
    }
    Ok(bytes)
}

fn authenticate_audited_image<O: Operation>(
    audited_image: &AuditedNativeImage,
    kir_identity: CacheIdentity,
    backend: LinuxAarch64SearchBackendV1,
) -> Result<(), LinuxSearchCompileErrorV1> {
    // The emitter constructs this typestate only after its independent
    // whole-image audit succeeds. Retain that immutable attestation instead
    // of discarding it and decoding the same fresh image a second time.
    let image = audited_image.as_image();
    if image.backend_version() != backend.backend_version()
        || image.output() != O::KIND
        || image.source_identity() != kir_identity
        || image.target() != target_for_backend(backend)
    {
        return Err(contract("backend-native image"));
    }
    Ok(())
}

const fn target_for_backend(backend: LinuxAarch64SearchBackendV1) -> TargetSpec {
    match backend {
        LinuxAarch64SearchBackendV1::AsimdV8
        | LinuxAarch64SearchBackendV1::AsimdV9
        | LinuxAarch64SearchBackendV1::AsimdV10
        | LinuxAarch64SearchBackendV1::AsimdV12
        | LinuxAarch64SearchBackendV1::AsimdV13
        | LinuxAarch64SearchBackendV1::AsimdV15 => TargetSpec::AARCH64_AAPCS64,
        LinuxAarch64SearchBackendV1::Sve2Fixed16Tag21Vl16 => TargetSpec::AARCH64_AAPCS64_SVE2_16,
    }
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

fn encode_object_limits(hasher: &mut Sha256, limits: ObjectLimitsV1) {
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

fn decode_backend_profile(
    tag: u8,
    version: u16,
    features: u64,
    fixed_active_vector_bytes: u16,
) -> Result<LinuxAarch64SearchBackendV1, LinuxSearchCompileErrorV1> {
    for backend in [
        LinuxAarch64SearchBackendV1::AsimdV8,
        LinuxAarch64SearchBackendV1::AsimdV9,
        LinuxAarch64SearchBackendV1::AsimdV10,
        LinuxAarch64SearchBackendV1::AsimdV12,
        LinuxAarch64SearchBackendV1::AsimdV13,
        LinuxAarch64SearchBackendV1::AsimdV15,
        LinuxAarch64SearchBackendV1::Sve2Fixed16Tag21Vl16,
    ] {
        if tag == backend.tag()
            && version == backend.backend_version().0
            && features == backend.required_features().bits()
            && fixed_active_vector_bytes == backend.fixed_active_vector_bytes()
        {
            return Ok(backend);
        }
    }
    Err(contract("compiler receipt backend profile"))
}

const fn decode_output_tag(tag: u8) -> Result<OutputKind, LinuxSearchCompileErrorV1> {
    match tag {
        1 => Ok(OutputKind::Exists),
        2 => Ok(OutputKind::SelectedEnd),
        3 => Ok(OutputKind::Span),
        _ => Err(LinuxSearchCompileErrorV1::ContractMismatch {
            field: "compiler receipt output tag",
        }),
    }
}

fn enforce(
    resource: &'static str,
    required: u64,
    limit: u64,
) -> Result<(), LinuxSearchCompileErrorV1> {
    if required > limit {
        Err(LinuxSearchCompileErrorV1::ResourceLimit {
            resource,
            limit,
            required,
        })
    } else {
        Ok(())
    }
}

fn usize_u64(value: usize, at: &'static str) -> Result<u64, LinuxSearchCompileErrorV1> {
    u64::try_from(value).map_err(|_| LinuxSearchCompileErrorV1::ArithmeticOverflow { at })
}

const fn output_tag(output: OutputKind) -> u8 {
    match output {
        OutputKind::Exists => 1,
        OutputKind::SelectedEnd => 2,
        OutputKind::Span => 3,
    }
}

const fn contract(field: &'static str) -> LinuxSearchCompileErrorV1 {
    LinuxSearchCompileErrorV1::ContractMismatch { field }
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

    fn raw(&mut self, value: &[u8]) -> Result<(), LinuxSearchCompileErrorV1> {
        let end = self.position.checked_add(value.len()).ok_or(
            LinuxSearchCompileErrorV1::ArithmeticOverflow {
                at: "compiler receipt writer",
            },
        )?;
        self.destination
            .get_mut(self.position..end)
            .ok_or_else(|| contract("compiler receipt writer range"))?
            .copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), LinuxSearchCompileErrorV1> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), LinuxSearchCompileErrorV1> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), LinuxSearchCompileErrorV1> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), LinuxSearchCompileErrorV1> {
        self.raw(&value.to_le_bytes())
    }
}

struct ReceiptReader<'a> {
    source: &'a [u8],
    position: usize,
}

impl<'a> ReceiptReader<'a> {
    const fn new(source: &'a [u8]) -> Self {
        Self {
            source,
            position: 0,
        }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn raw(
        &mut self,
        bytes: usize,
        at: &'static str,
    ) -> Result<&'a [u8], LinuxSearchCompileErrorV1> {
        let end = self
            .position
            .checked_add(bytes)
            .ok_or(LinuxSearchCompileErrorV1::ArithmeticOverflow { at })?;
        let value = self
            .source
            .get(self.position..end)
            .ok_or_else(|| contract(at))?;
        self.position = end;
        Ok(value)
    }

    fn expect(
        &mut self,
        expected: &[u8],
        at: &'static str,
    ) -> Result<(), LinuxSearchCompileErrorV1> {
        if self.raw(expected.len(), at)? == expected {
            Ok(())
        } else {
            Err(contract(at))
        }
    }

    fn array<const N: usize>(
        &mut self,
        at: &'static str,
    ) -> Result<[u8; N], LinuxSearchCompileErrorV1> {
        self.raw(N, at)?.try_into().map_err(|_| contract(at))
    }

    fn u8(&mut self, at: &'static str) -> Result<u8, LinuxSearchCompileErrorV1> {
        Ok(self.array::<1>(at)?[0])
    }

    fn u16(&mut self, at: &'static str) -> Result<u16, LinuxSearchCompileErrorV1> {
        Ok(u16::from_le_bytes(self.array(at)?))
    }

    fn u32(&mut self, at: &'static str) -> Result<u32, LinuxSearchCompileErrorV1> {
        Ok(u32::from_le_bytes(self.array(at)?))
    }

    fn u64(&mut self, at: &'static str) -> Result<u64, LinuxSearchCompileErrorV1> {
        Ok(u64::from_le_bytes(self.array(at)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fre_jit_aarch64::emit_with_backend;
    use fre_kernel_ir::Span;

    #[test]
    fn explicit_v9_is_deterministic_and_identity_disjoint_from_v8() {
        let v8_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::default();
        let v9_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::v9_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("V9 candidate manifest");
        let source = b"needle".to_vec();
        let v8 = plan_and_compile_linux_aarch64_exact_search_v1(
            v8_manifest,
            source.clone(),
            RustProfile::default(),
        )
        .expect("Linux V8 object");
        let first = plan_and_compile_linux_aarch64_exact_search_v1(
            v9_manifest,
            source.clone(),
            RustProfile::default(),
        )
        .expect("first Linux V9 object");
        let second = plan_and_compile_linux_aarch64_exact_search_v1(
            v9_manifest,
            source,
            RustProfile::default(),
        )
        .expect("second Linux V9 object");
        assert_eq!(
            first.receipt().backend(),
            LinuxAarch64SearchBackendV1::AsimdV9
        );
        assert_eq!(
            first.receipt().metadata().backend_version(),
            BackendVersion::SEARCH_V9.0
        );
        assert_ne!(
            v8.receipt().manifest_identity(),
            first.receipt().manifest_identity()
        );
        assert_ne!(
            v8.receipt().artifact_identity(),
            first.receipt().artifact_identity()
        );
        assert_eq!(first.object().as_bytes(), second.object().as_bytes());
        assert_eq!(first.receipt(), second.receipt());
        let expectation = crate::build_linux_static_search_span_expectation_v1(&first)
            .expect("Linux V9 neutral expectation");
        let claim = inspect_static_search_span_expectation_v1(expectation.as_bytes())
            .expect("Linux V9 expectation inspection");
        assert_eq!(
            claim.backend_version(),
            fre_aot_search_contract::SEARCH_BACKEND_ASIMD_TAG22_V1
        );
        assert!(expectation.authenticates_claim(&claim));
    }

    #[test]
    fn explicit_v10_is_deterministic_static_and_identity_disjoint_from_v8_v9() {
        let v8_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::default();
        let v9_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::v9_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("V9 candidate manifest");
        let v10_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::v10_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("V10 candidate manifest");
        let tagged = LinuxAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
            LinuxAarch64SearchCompilePolicyV1::default(),
            SEARCH_BACKEND_ASIMD_TAG23_V1,
        )
        .expect("tag23 candidate manifest");
        assert_eq!(tagged.backend(), v10_manifest.backend());
        assert_eq!(tagged.identity(), v10_manifest.identity());
        assert!(matches!(
            LinuxAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
                LinuxAarch64SearchCompilePolicyV1::default(),
                u16::MAX,
            ),
            Err(LinuxSearchManifestErrorV1::UnsupportedCandidateBackendTag {
                requested: u16::MAX
            })
        ));
        let source = b"needle".to_vec();
        let v8 = plan_and_compile_linux_aarch64_exact_search_v1(
            v8_manifest,
            source.clone(),
            RustProfile::default(),
        )
        .expect("Linux V8 object");
        let v9 = plan_and_compile_linux_aarch64_exact_search_v1(
            v9_manifest,
            source.clone(),
            RustProfile::default(),
        )
        .expect("Linux V9 object");
        let first = plan_and_compile_linux_aarch64_exact_search_v1(
            v10_manifest,
            source.clone(),
            RustProfile::default(),
        )
        .expect("first Linux V10 object");
        let second = plan_and_compile_linux_aarch64_exact_search_v1(
            v10_manifest,
            source,
            RustProfile::default(),
        )
        .expect("second Linux V10 object");
        assert_eq!(
            first.receipt().backend(),
            LinuxAarch64SearchBackendV1::AsimdV10
        );
        assert_eq!(
            first.receipt().metadata().backend_version(),
            BackendVersion::SEARCH_V10.0
        );
        assert_ne!(
            v8.receipt().manifest_identity(),
            first.receipt().manifest_identity()
        );
        assert_ne!(
            v9.receipt().manifest_identity(),
            first.receipt().manifest_identity()
        );
        assert_ne!(
            v8.receipt().artifact_identity(),
            first.receipt().artifact_identity()
        );
        assert_ne!(
            v9.receipt().artifact_identity(),
            first.receipt().artifact_identity()
        );
        assert_eq!(first.object().as_bytes(), second.object().as_bytes());
        assert_eq!(first.receipt(), second.receipt());
        let expectation = crate::build_linux_static_search_span_expectation_v1(&first)
            .expect("Linux V10 neutral expectation");
        let claim = inspect_static_search_span_expectation_v1(expectation.as_bytes())
            .expect("Linux V10 expectation inspection");
        assert_eq!(
            claim.backend_version(),
            fre_aot_search_contract::SEARCH_BACKEND_ASIMD_TAG23_V1
        );
        assert!(expectation.authenticates_claim(&claim));
    }

    #[test]
    fn explicit_v12_tag25_is_deterministic_static_and_candidate_only() {
        let v10_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::v10_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("V10 candidate manifest");
        let v12_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::v12_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("V12 candidate manifest");
        let tagged = LinuxAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
            LinuxAarch64SearchCompilePolicyV1::default(),
            SEARCH_BACKEND_ASIMD_TAG25_V1,
        )
        .expect("tag25 candidate manifest");
        assert_eq!(
            v12_manifest.backend(),
            LinuxAarch64SearchBackendV1::AsimdV12
        );
        assert_eq!(tagged.backend(), v12_manifest.backend());
        assert_eq!(tagged.identity(), v12_manifest.identity());
        assert_ne!(v12_manifest.identity(), v10_manifest.identity());
        assert!(matches!(
            LinuxAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
                LinuxAarch64SearchCompilePolicyV1::default(),
                24,
            ),
            Err(LinuxSearchManifestErrorV1::UnsupportedCandidateBackendTag { requested: 24 })
        ));

        let first = plan_and_compile_linux_aarch64_exact_search_v1(
            v12_manifest,
            b"needle".to_vec(),
            RustProfile::default(),
        )
        .expect("first Linux V12 object");
        let second = plan_and_compile_linux_aarch64_exact_search_v1(
            v12_manifest,
            b"needle".to_vec(),
            RustProfile::default(),
        )
        .expect("second Linux V12 object");
        assert_eq!(
            first.receipt().backend(),
            LinuxAarch64SearchBackendV1::AsimdV12
        );
        assert_eq!(
            first.receipt().metadata().backend_version(),
            BackendVersion::SEARCH_V12.0
        );
        assert_eq!(first.object().as_bytes(), second.object().as_bytes());
        assert_eq!(first.receipt(), second.receipt());
        let expectation = crate::build_linux_static_search_span_expectation_v1(&first)
            .expect("Linux V12 neutral expectation");
        let claim = inspect_static_search_span_expectation_v1(expectation.as_bytes())
            .expect("Linux V12 expectation inspection");
        assert_eq!(claim.backend_version(), SEARCH_BACKEND_ASIMD_TAG25_V1);
        assert!(expectation.authenticates_claim(&claim));
    }

    #[test]
    fn explicit_v13_tag26_is_deterministic_static_and_candidate_only() {
        let v12_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::v12_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("V12 candidate manifest");
        let v13_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::v13_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("V13 candidate manifest");
        let tagged = LinuxAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
            LinuxAarch64SearchCompilePolicyV1::default(),
            SEARCH_BACKEND_ASIMD_TAG26_V1,
        )
        .expect("tag26 candidate manifest");
        assert_eq!(
            v13_manifest.backend(),
            LinuxAarch64SearchBackendV1::AsimdV13
        );
        assert_eq!(tagged.backend(), v13_manifest.backend());
        assert_eq!(tagged.identity(), v13_manifest.identity());
        assert_ne!(v13_manifest.identity(), v12_manifest.identity());

        let first = plan_and_compile_linux_aarch64_exact_search_v1(
            v13_manifest,
            b"needle".to_vec(),
            RustProfile::default(),
        )
        .expect("first Linux V13 object");
        let second = plan_and_compile_linux_aarch64_exact_search_v1(
            v13_manifest,
            b"needle".to_vec(),
            RustProfile::default(),
        )
        .expect("second Linux V13 object");
        assert_eq!(
            first.receipt().backend(),
            LinuxAarch64SearchBackendV1::AsimdV13
        );
        assert_eq!(
            first.receipt().metadata().backend_version(),
            BackendVersion::SEARCH_V13.0
        );
        assert_eq!(first.object().as_bytes(), second.object().as_bytes());
        assert_eq!(first.receipt(), second.receipt());
        let expectation = crate::build_linux_static_search_span_expectation_v1(&first)
            .expect("Linux V13 neutral expectation");
        let claim = inspect_static_search_span_expectation_v1(expectation.as_bytes())
            .expect("Linux V13 expectation inspection");
        assert_eq!(claim.backend_version(), SEARCH_BACKEND_ASIMD_TAG26_V1);
        assert!(expectation.authenticates_claim(&claim));
    }

    #[test]
    fn explicit_v15_tag28_is_deterministic_static_and_candidate_only() {
        let v13_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::v13_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("V13 candidate manifest");
        let v15_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::v15_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("V15 candidate manifest");
        let tagged = LinuxAarch64ExactSearchManifestV1::<Span>::candidate_backend_tag(
            LinuxAarch64SearchCompilePolicyV1::default(),
            SEARCH_BACKEND_ASIMD_TAG28_V1,
        )
        .expect("tag28 candidate manifest");
        assert_eq!(
            v15_manifest.backend(),
            LinuxAarch64SearchBackendV1::AsimdV15
        );
        assert_eq!(tagged.backend(), v15_manifest.backend());
        assert_eq!(tagged.identity(), v15_manifest.identity());
        assert_ne!(v15_manifest.identity(), v13_manifest.identity());

        let source = b"phase-unique-15!".to_vec();
        let first = plan_and_compile_linux_aarch64_exact_search_v1(
            v15_manifest,
            source.clone(),
            RustProfile::default(),
        )
        .expect("first Linux V15 object");
        let second = plan_and_compile_linux_aarch64_exact_search_v1(
            v15_manifest,
            source,
            RustProfile::default(),
        )
        .expect("second Linux V15 object");
        assert_eq!(
            first.receipt().backend(),
            LinuxAarch64SearchBackendV1::AsimdV15
        );
        assert_eq!(
            first.receipt().metadata().backend_version(),
            BackendVersion::SEARCH_V15.0
        );
        assert_eq!(first.object().as_bytes(), second.object().as_bytes());
        assert_eq!(first.receipt(), second.receipt());
        let expectation = crate::build_linux_static_search_span_expectation_v1(&first)
            .expect("Linux V15 neutral expectation");
        let claim = inspect_static_search_span_expectation_v1(expectation.as_bytes())
            .expect("Linux V15 expectation inspection");
        assert_eq!(claim.backend_version(), SEARCH_BACKEND_ASIMD_TAG28_V1);
        assert!(expectation.authenticates_claim(&claim));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one end-to-end test compares every identity and byte-stability property for both backends"
    )]
    fn v8_and_explicit_tag21_are_deterministic_and_identity_disjoint() {
        let v8_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::default();
        let tag21_manifest = LinuxAarch64ExactSearchManifestV1::<Span>::tag21_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("tag21 candidate manifest");
        let source = b"0123456789abcdef".to_vec();
        let v8 = plan_and_compile_linux_aarch64_exact_search_v1(
            v8_manifest,
            source.clone(),
            RustProfile::default(),
        )
        .expect("Linux V8 object");
        let tag21 = plan_and_compile_linux_aarch64_exact_search_v1(
            tag21_manifest,
            source.clone(),
            RustProfile::default(),
        )
        .expect("Linux tag21 object");
        let tag21_repeat = plan_and_compile_linux_aarch64_exact_search_v1(
            tag21_manifest,
            source,
            RustProfile::default(),
        )
        .expect("repeated Linux tag21 object");

        assert_eq!(v8.receipt().backend(), LinuxAarch64SearchBackendV1::AsimdV8);
        assert_eq!(
            tag21.receipt().backend(),
            LinuxAarch64SearchBackendV1::Sve2Fixed16Tag21Vl16
        );
        assert_ne!(
            v8.receipt().manifest_identity(),
            tag21.receipt().manifest_identity()
        );
        assert_ne!(
            v8.receipt().artifact_identity(),
            tag21.receipt().artifact_identity()
        );
        assert_ne!(
            v8.receipt().binding_identity(),
            tag21.receipt().binding_identity()
        );
        assert_ne!(
            v8.receipt().compile_identity(),
            tag21.receipt().compile_identity()
        );
        assert_eq!(tag21.object().as_bytes(), tag21_repeat.object().as_bytes());
        assert_eq!(tag21.receipt(), tag21_repeat.receipt());
        assert_eq!(
            tag21.receipt().canonical_receipt_bytes().unwrap(),
            tag21_repeat.receipt().canonical_receipt_bytes().unwrap()
        );

        let receipt_bytes = tag21
            .receipt()
            .canonical_receipt_bytes()
            .expect("canonical compiler receipt");
        let reopened = tag21
            .receipt()
            .validate_canonical_receipt_bytes(&receipt_bytes)
            .expect("typed compiler-receipt reopen");
        assert_eq!(
            receipt_bytes.len(),
            LINUX_SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1
        );
        assert_eq!(
            reopened.receipt_identity(),
            tag21.receipt().receipt_identity()
        );
        reopened
            .validate_object(tag21.object().as_bytes(), ObjectLimitsV1::default())
            .expect("reopened compiler receipt/object");
        let reconstructed_program = build_exact_literal::<Span>(
            b"0123456789abcdef",
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .expect("reconstructed tag21 KIR");
        let reconstructed_image = emit_with_backend(
            &reconstructed_program,
            SearchBackendPolicy::Sve2Fixed16V2,
            EmitLimits::default(),
        )
        .expect("reconstructed tag21 image");
        let reconstructed_validation = reopened
            .validate_reconstructed_image_object(
                &reconstructed_image,
                tag21.object().as_bytes(),
                ObjectLimitsV1::default(),
            )
            .expect("reconstructed image/object binding");
        assert_eq!(
            reconstructed_validation.inspection(),
            reopened
                .validate_object(tag21.object().as_bytes(), ObjectLimitsV1::default())
                .expect("strict object inspection")
        );
        let expectation = crate::build_linux_static_search_span_expectation_v1(&tag21)
            .expect("neutral expectation");
        reopened
            .validate_span_expectation(expectation.as_bytes())
            .expect("reopened compiler receipt/expectation");

        for index in 0..receipt_bytes.len() {
            let mut changed = receipt_bytes;
            changed[index] ^= 1;
            assert!(
                tag21
                    .receipt()
                    .validate_canonical_receipt_bytes(&changed)
                    .is_err(),
                "typed receipt reopen accepted byte mutation {index}"
            );
        }

        // An unsigned claim may choose a different object identity; only
        // correlation with the independently decoded object closes that claim.
        let mut changed_object_claim = receipt_bytes;
        changed_object_claim[500] ^= 1;
        let changed_claim = inspect_linux_search_compile_receipt_v1(&changed_object_claim)
            .expect("well-shaped unsigned receipt claim");
        assert!(
            changed_claim
                .validate_object(tag21.object().as_bytes(), ObjectLimitsV1::default())
                .is_err()
        );
    }

    #[test]
    fn tag21_constructor_never_accepts_a_non_16_byte_literal() {
        let manifest = LinuxAarch64ExactSearchManifestV1::<Span>::tag21_candidate(
            LinuxAarch64SearchCompilePolicyV1::default(),
        )
        .expect("tag21 candidate manifest");
        let error = plan_and_compile_linux_aarch64_exact_search_v1(
            manifest,
            b"not-sixteen".to_vec(),
            RustProfile::default(),
        )
        .expect_err("tag21 width must be exact");
        assert!(matches!(
            error,
            LinuxSearchCompileErrorV1::BackendLiteralShape {
                backend: LinuxAarch64SearchBackendV1::Sve2Fixed16Tag21Vl16,
                ..
            }
        ));
    }
}
