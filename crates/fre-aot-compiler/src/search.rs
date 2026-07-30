//! Inert source-first nonempty exact-literal Search object compilation.
//!
//! This is deliberately narrower than runtime deployment. It accepts only a
//! facade-authenticated nonempty exact-literal plan built under the fixed automatic
//! policy, emits one typed Search `NativeImage`, and wraps it as a
//! deterministic macOS `AArch64` `MH_OBJECT`. The result carries no runtime
//! authority and this module never probes the build host, invokes a linker,
//! maps code, or calls a generated entry.
//!
//! The V1 raw C header describes the full `(start, end)` publication rule that
//! is true only for [`fre_kernel_ir::Span`]. Machine code for
//! [`fre_kernel_ir::Exists`] leaves both result words untouched and
//! [`fre_kernel_ir::SelectedEnd`] writes only `end`. All three outputs remain
//! useful as inert, output-bound compiler artifacts, but only Span is a
//! prospective later static-adoption slice. This module does not reinterpret
//! the V1 ABI or claim that its generic C wording is a deployable safe API.

use core::{fmt, marker::PhantomData, mem::size_of};

use fre::{
    BuildError as FacadeBuildError, BuildLimits, PlanSelection, PortableBuilder, RustProfile,
    SearchExactLiteralAotSemanticBindingIdentity,
};
use fre_aot_macho::{
    AbiKind, BindingIdentity, BindingIdentityError, BuiltObject, CompileIdentity, MetadataV1,
    ObjectError, ObjectIdentity, ObjectLimits, inspect_object,
};
use fre_jit_aarch64::{
    ArtifactIdentity, BackendVersion, CpuFeatures, EmitError, EmitLimits, ImageStats, NativeImage,
    SearchBackendPolicy, TargetSpec, emit_with_backend,
};
use fre_kernel_ir::{
    AnchorFlags, BuildError as KernelBuildError, CacheIdentity, Operation, OutputKind,
    ProgramStats, ValidateLimits, build_exact_literal,
};
use sha2::{Digest, Sha256};

use crate::{
    canonical::{CanonicalEncoder, CanonicalError},
    manifest::{encode_emit_limits, encode_object_limits, encode_validate_limits},
};

pub const AOT_SEARCH_COMPILER_VERSION_V1: u16 = 1;
pub const AOT_SEARCH_MANIFEST_SCHEMA_VERSION_V1: u16 = 1;
pub const AOT_SEARCH_COMPILE_RECEIPT_SCHEMA_VERSION_V1: u16 = 1;
/// Exact width of the canonical compiler-receipt stream hashed by V1.
pub const SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1: usize = 916;
pub const MAX_AOT_SEARCH_SOURCE_BYTES_V1: u64 = 1 << 20;
pub const MIN_AOT_SEARCH_LITERAL_BYTES_V1: u64 = 1;
pub const MAX_AOT_SEARCH_LITERAL_BYTES_V1: u64 = 32;

const MANIFEST_DOMAIN: &[u8] = b"FRE-AOT-SEARCH-COMPILER-MANIFEST\0\x01";
const OBJECT_BINDING_DOMAIN: &[u8] = b"FRE-AOT-SEARCH-COMPILER-OBJECT-BINDING\0\x01";
const RECEIPT_DOMAIN: &[u8] = b"FRE-AOT-SEARCH-COMPILER-RECEIPT\0\x01";
const LITERAL_DOMAIN: &[u8] = b"FRE-AOT-SEARCH-COMPILER-LITERAL\0\x01";
const IDENTITY_SCRATCH_BYTES: u64 = 256;

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

identity!(SearchManifestIdentityV1, "SearchManifestIdentityV1");
identity!(SearchLiteralIdentityV1, "SearchLiteralIdentityV1");
identity!(
    SearchCompileReceiptIdentityV1,
    "SearchCompileReceiptIdentityV1"
);

/// Caller-selected finite limits for the source-first Search compiler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchCompilePolicyV1 {
    pub max_source_bytes: u64,
    pub max_literal_bytes: u64,
    pub kernel_ir: ValidateLimits,
    pub native: EmitLimits,
    pub object: ObjectLimits,
    /// Post-build acceptance ceiling for the retained compiled result.
    pub max_result_persistent_bytes: u64,
    /// Post-build ceiling for the largest measured single-stage scratch use.
    ///
    /// This is not a whole-pipeline peak-live bound: live facade, KIR,
    /// native-image, and object allocations can overlap. Their retained sizes
    /// are separately constrained by stage limits but are not summed here.
    pub max_observed_stage_scratch_bytes: u64,
}

impl SearchCompilePolicyV1 {
    /// Explicit finite defaults for the exact-literal Search slice.
    #[must_use]
    pub fn high_fuel() -> Self {
        Self {
            max_source_bytes: MAX_AOT_SEARCH_SOURCE_BYTES_V1,
            max_literal_bytes: MAX_AOT_SEARCH_LITERAL_BYTES_V1,
            kernel_ir: ValidateLimits::default(),
            native: EmitLimits::default(),
            object: ObjectLimits::default(),
            max_result_persistent_bytes: 8 << 20,
            max_observed_stage_scratch_bytes: 8 << 20,
        }
    }
}

impl Default for SearchCompilePolicyV1 {
    fn default() -> Self {
        Self::high_fuel()
    }
}

/// Structural refusal while sealing a typed Search compiler manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchManifestErrorV1 {
    SourcePolicyExceedsHardLimit { limit: u64, requested: u64 },
    LiteralPolicyExceedsHardLimit { limit: u64, requested: u64 },
    ZeroResultPersistentLimit,
    ZeroObservedStageScratchLimit,
    ArithmeticOverflow,
}

impl fmt::Display for SearchManifestErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid FRE exact Search AOT manifest: {self:?}")
    }
}

impl std::error::Error for SearchManifestErrorV1 {}

/// Explicit macOS `AArch64` code-generation profile.
///
/// The default remains V8 so all existing manifests and artifact identities
/// remain byte-for-byte stable. V9 is reachable only through its named
/// candidate constructor until source qualification grants deployment
/// authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MacosAarch64SearchBackendV1 {
    #[default]
    AsimdV8,
    AsimdV9,
}

impl MacosAarch64SearchBackendV1 {
    #[must_use]
    pub const fn emitter_policy(self) -> SearchBackendPolicy {
        match self {
            Self::AsimdV8 => SearchBackendPolicy::AsimdV8,
            Self::AsimdV9 => SearchBackendPolicy::AsimdV9,
        }
    }

    #[must_use]
    pub const fn backend_version(self) -> BackendVersion {
        self.emitter_policy().backend_version()
    }
}

/// Sealed macOS `AArch64` Search request for one compile-time output type.
pub struct MacosAarch64ExactSearchManifestV1<O: Operation> {
    policy: SearchCompilePolicyV1,
    backend: MacosAarch64SearchBackendV1,
    identity: SearchManifestIdentityV1,
    identity_bytes_hashed: u64,
    operation: PhantomData<fn() -> O>,
}

impl<O: Operation> Copy for MacosAarch64ExactSearchManifestV1<O> {}

impl<O: Operation> Clone for MacosAarch64ExactSearchManifestV1<O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<O: Operation> fmt::Debug for MacosAarch64ExactSearchManifestV1<O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosAarch64ExactSearchManifestV1")
            .field("policy", &self.policy)
            .field("backend", &self.backend)
            .field("identity", &self.identity)
            .field("identity_bytes_hashed", &self.identity_bytes_hashed)
            .field("output", &O::KIND)
            .finish()
    }
}

impl<O: Operation> MacosAarch64ExactSearchManifestV1<O> {
    pub fn new(policy: SearchCompilePolicyV1) -> Result<Self, SearchManifestErrorV1> {
        Self::with_backend(policy, MacosAarch64SearchBackendV1::AsimdV8)
    }

    fn with_backend(
        policy: SearchCompilePolicyV1,
        backend: MacosAarch64SearchBackendV1,
    ) -> Result<Self, SearchManifestErrorV1> {
        validate_policy(&policy)?;
        let (identity, identity_bytes_hashed) =
            encode_manifest::<O>(&policy, backend).map_err(map_manifest_canonical)?;
        Ok(Self {
            policy,
            backend,
            identity: SearchManifestIdentityV1::new(identity),
            identity_bytes_hashed,
            operation: PhantomData,
        })
    }

    /// Construct an explicit ASIMD V9 candidate manifest. This does not grant
    /// runtime or automatic-routing authority.
    pub fn v9_candidate(policy: SearchCompilePolicyV1) -> Result<Self, SearchManifestErrorV1> {
        Self::with_backend(policy, MacosAarch64SearchBackendV1::AsimdV9)
    }

    #[must_use]
    pub const fn policy(&self) -> &SearchCompilePolicyV1 {
        &self.policy
    }

    #[must_use]
    pub const fn backend(&self) -> MacosAarch64SearchBackendV1 {
        self.backend
    }

    #[must_use]
    pub const fn identity(&self) -> SearchManifestIdentityV1 {
        self.identity
    }

    #[must_use]
    pub const fn identity_bytes_hashed(&self) -> u64 {
        self.identity_bytes_hashed
    }

    #[must_use]
    pub const fn output(&self) -> OutputKind {
        O::KIND
    }

    fn authenticates_itself(&self) -> bool {
        validate_policy(&self.policy).is_ok()
            && encode_manifest::<O>(&self.policy, self.backend).is_ok_and(|(identity, bytes)| {
                self.identity == SearchManifestIdentityV1::new(identity)
                    && self.identity_bytes_hashed == bytes
            })
    }
}

impl<O: Operation> Default for MacosAarch64ExactSearchManifestV1<O> {
    fn default() -> Self {
        Self::new(SearchCompilePolicyV1::high_fuel())
            .expect("the fixed Search compiler manifest must remain internally consistent")
    }
}

/// Explicit absence of linked-code runtime authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchAotRuntimeAuthorityV1 {
    Absent,
}

/// Compiler-sealed named-stage observations retained by one inert receipt.
///
/// This deliberately contains no aggregate pipeline-work or pipeline-peak
/// claim. Independent audits and validations are bounded by their owning
/// stages but are not summed into a purported total here. Values that cannot
/// be reconstructed from object bytes (such as original source capacity) are
/// hash-bound compiler observations, not independent object proofs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchCompileAccountingV1 {
    source_bytes: u64,
    source_capacity_bytes: u64,
    literal_bytes: u64,
    candidate_identity_bytes_hashed: u64,
    manifest_identity_bytes_hashed: u64,
    object_binding_bytes_hashed: u64,
    kernel: ProgramStats,
    native: ImageStats,
    object_bytes: u64,
    object_persistent_bytes: u64,
    object_payload_bytes: u64,
    object_work: u64,
    object_scratch_bytes: u64,
    result_persistent_bytes: u64,
    observed_stage_scratch_bytes_upper_bound: u64,
}

impl SearchCompileAccountingV1 {
    #[must_use]
    pub const fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    #[must_use]
    pub const fn source_capacity_bytes(&self) -> u64 {
        self.source_capacity_bytes
    }

    #[must_use]
    pub const fn literal_bytes(&self) -> u64 {
        self.literal_bytes
    }

    #[must_use]
    pub const fn candidate_identity_bytes_hashed(&self) -> u64 {
        self.candidate_identity_bytes_hashed
    }

    #[must_use]
    pub const fn kernel(&self) -> ProgramStats {
        self.kernel
    }

    #[must_use]
    pub const fn native(&self) -> ImageStats {
        self.native
    }

    #[must_use]
    pub const fn object_bytes(&self) -> u64 {
        self.object_bytes
    }

    #[must_use]
    pub const fn result_persistent_bytes(&self) -> u64 {
        self.result_persistent_bytes
    }

    /// Maximum of the separately measured KIR, native, object, and identity
    /// scratch requirements.
    ///
    /// This excludes retained values that can be live across stages and must
    /// not be interpreted as a whole-pipeline peak-live measurement.
    #[must_use]
    pub const fn observed_stage_scratch_bytes_upper_bound(&self) -> u64 {
        self.observed_stage_scratch_bytes_upper_bound
    }

    #[must_use]
    pub const fn object_scratch_bytes(&self) -> u64 {
        self.object_scratch_bytes
    }
}

/// Typed source-first compilation refusal.
#[derive(Debug)]
#[non_exhaustive]
pub enum SearchCompileErrorV1 {
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
    CandidateAuthentication,
    Kernel(KernelBuildError),
    Native(EmitError),
    ObjectBinding(BindingIdentityError),
    Object(ObjectError),
    ContractMismatch {
        field: &'static str,
    },
    ArithmeticOverflow {
        at: &'static str,
    },
}

impl fmt::Display for SearchCompileErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE exact Search AOT compilation failed: {self:?}"
        )
    }
}

impl std::error::Error for SearchCompileErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Facade(error) => Some(error),
            Self::Kernel(error) => Some(error),
            Self::Native(error) => Some(error),
            Self::ObjectBinding(error) => Some(error),
            Self::Object(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FacadeBuildError> for SearchCompileErrorV1 {
    fn from(value: FacadeBuildError) -> Self {
        Self::Facade(value)
    }
}

impl From<KernelBuildError> for SearchCompileErrorV1 {
    fn from(value: KernelBuildError) -> Self {
        Self::Kernel(value)
    }
}

impl From<EmitError> for SearchCompileErrorV1 {
    fn from(value: EmitError) -> Self {
        Self::Native(value)
    }
}

impl From<BindingIdentityError> for SearchCompileErrorV1 {
    fn from(value: BindingIdentityError) -> Self {
        Self::ObjectBinding(value)
    }
}

impl From<ObjectError> for SearchCompileErrorV1 {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

/// Compiler-sealed inert-object receipt with closed object-facing identities.
///
/// Private construction plus the receipt digest seals source-stage
/// observations. Self-authentication additionally recomputes every identity
/// whose complete preimage is retained here, including the object binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchCompileReceiptV1 {
    schema_version: u16,
    compiler_version: u16,
    manifest_identity: SearchManifestIdentityV1,
    semantic_binding_identity: SearchExactLiteralAotSemanticBindingIdentity,
    literal_identity: SearchLiteralIdentityV1,
    literal_bytes: u32,
    output: OutputKind,
    anchors: AnchorFlags,
    kir_identity: CacheIdentity,
    native_artifact_identity: ArtifactIdentity,
    binding_identity: BindingIdentity,
    metadata: MetadataV1,
    compile_identity: CompileIdentity,
    object_identity: ObjectIdentity,
    object_bytes: u64,
    accounting: SearchCompileAccountingV1,
    receipt_identity: SearchCompileReceiptIdentityV1,
}

impl SearchCompileReceiptV1 {
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
    pub const fn native_artifact_identity(&self) -> ArtifactIdentity {
        self.native_artifact_identity
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
    pub const fn accounting(&self) -> SearchCompileAccountingV1 {
        self.accounting
    }

    #[must_use]
    pub const fn receipt_identity(&self) -> SearchCompileReceiptIdentityV1 {
        self.receipt_identity
    }

    /// Materialize the exact fixed-width stream hashed by
    /// [`Self::receipt_identity`].
    ///
    /// The returned bytes remain an inert compiler receipt. They are not a
    /// signature, source-qualification row, linker receipt, or runtime
    /// authority.
    pub fn canonical_bytes(
        &self,
    ) -> Result<[u8; SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1], SearchCompileErrorV1> {
        if !self.authenticates_itself() {
            return Err(SearchCompileErrorV1::ContractMismatch {
                field: "compiler receipt identity",
            });
        }
        let mut bytes = [0_u8; SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1];
        let encoded_bytes = {
            let mut encoder = FixedCanonicalEncoder::new(&mut bytes);
            encode_receipt_fields(&mut encoder, self).map_err(map_compile_canonical)?;
            encoder.position()
        };
        if encoded_bytes != SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1 {
            return Err(SearchCompileErrorV1::ContractMismatch {
                field: "compiler receipt canonical width",
            });
        }
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if digest != *self.receipt_identity.as_bytes() {
            return Err(SearchCompileErrorV1::ContractMismatch {
                field: "compiler receipt canonical bytes",
            });
        }
        Ok(bytes)
    }

    #[must_use]
    pub const fn runtime_authority(&self) -> SearchAotRuntimeAuthorityV1 {
        SearchAotRuntimeAuthorityV1::Absent
    }

    pub fn validate_object<'a>(
        &self,
        bytes: &'a [u8],
        limits: ObjectLimits,
    ) -> Result<fre_aot_macho::ObjectInspection<'a>, SearchReceiptValidationErrorV1> {
        if !self.authenticates_itself() {
            return Err(SearchReceiptValidationErrorV1::Mismatch {
                field: SearchReceiptMismatchV1::ReceiptIdentity,
            });
        }
        let inspection = inspect_object(bytes, limits)?;
        let object_bytes = u64::try_from(inspection.object_bytes())
            .map_err(|_| SearchReceiptValidationErrorV1::ArithmeticOverflow)?;
        if object_bytes != self.object_bytes {
            return Err(SearchReceiptValidationErrorV1::Mismatch {
                field: SearchReceiptMismatchV1::ObjectBytes,
            });
        }
        if inspection.metadata() != self.metadata {
            return Err(SearchReceiptValidationErrorV1::Mismatch {
                field: SearchReceiptMismatchV1::Metadata,
            });
        }
        if !self
            .object_identity
            .matches_claim(inspection.claimed_object_identity())
        {
            return Err(SearchReceiptValidationErrorV1::Mismatch {
                field: SearchReceiptMismatchV1::ObjectIdentity,
            });
        }
        if !self
            .compile_identity
            .matches_claim(inspection.claimed_compile_identity())
        {
            return Err(SearchReceiptValidationErrorV1::Mismatch {
                field: SearchReceiptMismatchV1::CompileIdentity,
            });
        }
        if !self
            .binding_identity
            .matches_claim(inspection.metadata().claimed_binding_identity())
        {
            return Err(SearchReceiptValidationErrorV1::Mismatch {
                field: SearchReceiptMismatchV1::BindingIdentity,
            });
        }
        Ok(inspection)
    }

    fn authenticates_itself(&self) -> bool {
        let metadata = self.metadata;
        self.schema_version == AOT_SEARCH_COMPILE_RECEIPT_SCHEMA_VERSION_V1
            && self.compiler_version == AOT_SEARCH_COMPILER_VERSION_V1
            && self.anchors == AnchorFlags::default()
            && u64::from(self.literal_bytes) >= MIN_AOT_SEARCH_LITERAL_BYTES_V1
            && u64::from(self.literal_bytes) <= MAX_AOT_SEARCH_LITERAL_BYTES_V1
            && output_tag(self.output) == metadata.output_kind()
            && metadata.format_version() == fre_aot_macho::METADATA_VERSION
            && matches!(
                metadata.backend_version(),
                value if value == BackendVersion::SEARCH_V8.0
                    || value == BackendVersion::SEARCH_V9.0
            )
            && metadata.abi_kind() == AbiKind::Search
            && metadata.literal_bytes() == 0
            && metadata.source_identity() == self.kir_identity.as_bytes()
            && metadata.artifact_identity() == self.native_artifact_identity.as_bytes()
            && self
                .binding_identity
                .matches_claim(metadata.claimed_binding_identity())
            && self
                .compile_identity
                .matches_claim(metadata.claimed_compile_identity())
            && object_binding_identity(
                self.manifest_identity,
                self.semantic_binding_identity,
                self.literal_identity,
                u64::from(self.literal_bytes),
                self.output,
                self.anchors,
                self.kir_identity,
                self.native_artifact_identity,
                self.accounting.native,
            )
            .is_ok_and(|(identity, bytes_hashed)| {
                self.binding_identity.as_bytes() == &identity
                    && self.accounting.object_binding_bytes_hashed == bytes_hashed
            })
            && self.accounting_authenticates()
            && encode_receipt(self).is_ok_and(|identity| identity == self.receipt_identity)
    }

    fn accounting_authenticates(&self) -> bool {
        let accounting = self.accounting;
        let resources = accounting.kernel.resources();
        let Some(result_inline_bytes) = compiled_object_inline_bytes(self.output) else {
            return false;
        };
        let Some(expected_result_persistent_bytes) = accounting
            .object_persistent_bytes
            .checked_add(result_inline_bytes)
        else {
            return false;
        };
        let expected_stage_scratch = (|| {
            [
                u64::try_from(resources.validation_scratch_bytes()).ok()?,
                u64::try_from(resources.validation_phase_peak_bytes()).ok()?,
                u64::try_from(resources.serialization_phase_peak_bytes()).ok()?,
                u64::try_from(resources.identity_phase_peak_bytes()).ok()?,
                accounting.native.scratch_bytes,
                accounting.object_scratch_bytes,
                IDENTITY_SCRATCH_BYTES,
            ]
            .into_iter()
            .max()
        })();
        let Some(expected_stage_scratch) = expected_stage_scratch else {
            return false;
        };

        accounting.source_bytes <= accounting.source_capacity_bytes
            && accounting.literal_bytes == u64::from(self.literal_bytes)
            && accounting.candidate_identity_bytes_hashed != 0
            && accounting.manifest_identity_bytes_hashed != 0
            && accounting.object_binding_bytes_hashed != 0
            && accounting.object_bytes == self.object_bytes
            && accounting.object_persistent_bytes >= accounting.object_bytes
            && accounting.object_payload_bytes == u64::from(self.metadata.payload_bytes())
            && accounting.native.code_bytes == self.metadata.code_bytes()
            && accounting.native.data_bytes == self.metadata.rodata_bytes()
            && accounting.result_persistent_bytes == expected_result_persistent_bytes
            && accounting.observed_stage_scratch_bytes_upper_bound == expected_stage_scratch
    }
}

/// Receipt field that disagreed with independently inspected object bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchReceiptMismatchV1 {
    ReceiptIdentity,
    ObjectBytes,
    Metadata,
    ObjectIdentity,
    CompileIdentity,
    BindingIdentity,
}

/// Strict inert-object receipt validation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SearchReceiptValidationErrorV1 {
    Object(ObjectError),
    Mismatch { field: SearchReceiptMismatchV1 },
    ArithmeticOverflow,
}

impl fmt::Display for SearchReceiptValidationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "FRE exact Search AOT receipt validation failed: {self:?}"
        )
    }
}

impl std::error::Error for SearchReceiptValidationErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Object(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ObjectError> for SearchReceiptValidationErrorV1 {
    fn from(value: ObjectError) -> Self {
        Self::Object(value)
    }
}

/// Inert deterministic Mach-O bytes paired with a typed trusted receipt.
pub struct SearchCompiledObjectV1<O: Operation> {
    object: BuiltObject,
    receipt: SearchCompileReceiptV1,
    operation: PhantomData<fn() -> O>,
}

impl<O: Operation> fmt::Debug for SearchCompiledObjectV1<O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchCompiledObjectV1")
            .field("output", &O::KIND)
            .field("object", &self.object)
            .field("receipt", &self.receipt)
            .field("runtime_authority", &SearchAotRuntimeAuthorityV1::Absent)
            .finish()
    }
}

impl<O: Operation> SearchCompiledObjectV1<O> {
    #[must_use]
    pub const fn object(&self) -> &BuiltObject {
        &self.object
    }

    #[must_use]
    pub const fn receipt(&self) -> &SearchCompileReceiptV1 {
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

/// Plan and compile one owned UTF-8 source into an inert Search object.
///
/// Source length and allocation capacity are checked before UTF-8 validation
/// or syntax work. The normal facade must select its live exact-literal plan;
/// there is no semantic fallback and no direct literal-only bypass.
#[allow(
    clippy::too_many_lines,
    reason = "the canonical compiler pipeline keeps each authenticated phase in one auditable sequence"
)]
pub fn plan_and_compile_macos_aarch64_exact_search_v1<O: Operation>(
    manifest: MacosAarch64ExactSearchManifestV1<O>,
    source: Vec<u8>,
    profile: RustProfile,
) -> Result<SearchCompiledObjectV1<O>, SearchCompileErrorV1> {
    if !manifest.authenticates_itself() {
        return Err(SearchCompileErrorV1::ManifestAuthentication);
    }
    let source_bytes = usize_u64(source.len(), "source length")?;
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
    let source = String::from_utf8(source).map_err(|_| SearchCompileErrorV1::InvalidUtf8Source)?;
    let regex = PortableBuilder::new(source).profile(profile).build()?;
    let candidate = regex
        .exact_literal_search_aot_candidate()
        .ok_or(SearchCompileErrorV1::ExactLiteralRequired)?;
    if candidate.selection() != PlanSelection::Auto
        || candidate.build_limits() != BuildLimits::default()
        || candidate.source() != regex.as_str()
        || candidate.build_report() != regex.build_report()
    {
        return Err(SearchCompileErrorV1::CandidateAuthentication);
    }
    let literal_bytes = usize_u64(candidate.literal().len(), "literal length")?;
    if literal_bytes < MIN_AOT_SEARCH_LITERAL_BYTES_V1 {
        return Err(SearchCompileErrorV1::EmptyLiteralUnsupported);
    }
    enforce(
        "literal bytes",
        literal_bytes,
        manifest.policy.max_literal_bytes,
    )?;

    let program = build_exact_literal::<O>(
        candidate.literal(),
        AnchorFlags::default(),
        manifest.policy.kernel_ir,
    )?;
    if program.raw().output != O::KIND
        || program.raw().blocks.len() != 4
        || program.raw().data.len() != 1
    {
        return Err(SearchCompileErrorV1::ContractMismatch {
            field: "typed exact Search KIR",
        });
    }
    let kir_identity = program.cache_identity();
    let kernel_stats = program.stats();
    let image = emit_with_backend(
        &program,
        manifest.backend.emitter_policy(),
        manifest.policy.native,
    )?;
    authenticate_image::<O>(&image, kir_identity, manifest.backend)?;

    let literal_identity = literal_identity(candidate.literal());
    let (binding_bytes, object_binding_bytes_hashed) = object_binding_identity(
        manifest.identity,
        candidate.semantic_binding_identity(),
        literal_identity,
        literal_bytes,
        O::KIND,
        AnchorFlags::default(),
        kir_identity,
        image.artifact_identity(),
        image.stats(),
    )?;
    let binding_identity = BindingIdentity::new(binding_bytes)?;
    let object =
        fre_aot_macho::emit_search_object(&image, binding_identity, manifest.policy.object)?;
    authenticate_object::<O>(
        &object,
        &image,
        binding_identity,
        manifest.backend,
        manifest.policy.object,
    )?;

    let accounting = compile_accounting(
        &manifest,
        source_bytes,
        source_capacity_bytes,
        literal_bytes,
        candidate.semantic_identity_bytes_hashed(),
        object_binding_bytes_hashed,
        kernel_stats,
        &image,
        &object,
    )?;
    let metadata = object.metadata();
    let compile_identity = object.compile_identity();
    let object_identity = object.object_identity();
    let object_bytes = usize_u64(object.as_bytes().len(), "object bytes")?;
    let mut receipt = SearchCompileReceiptV1 {
        schema_version: AOT_SEARCH_COMPILE_RECEIPT_SCHEMA_VERSION_V1,
        compiler_version: AOT_SEARCH_COMPILER_VERSION_V1,
        manifest_identity: manifest.identity,
        semantic_binding_identity: candidate.semantic_binding_identity(),
        literal_identity,
        literal_bytes: u32::try_from(candidate.literal().len()).map_err(|_| {
            SearchCompileErrorV1::ArithmeticOverflow {
                at: "literal u32 width",
            }
        })?,
        output: O::KIND,
        anchors: AnchorFlags::default(),
        kir_identity,
        native_artifact_identity: image.artifact_identity(),
        binding_identity,
        metadata,
        compile_identity,
        object_identity,
        object_bytes,
        accounting,
        receipt_identity: SearchCompileReceiptIdentityV1::new([0; 32]),
    };
    receipt.receipt_identity = encode_receipt(&receipt)?;
    if !receipt.authenticates_itself()
        || receipt
            .validate_object(object.as_bytes(), manifest.policy.object)
            .is_err()
    {
        return Err(SearchCompileErrorV1::ContractMismatch {
            field: "fresh compiler receipt",
        });
    }
    Ok(SearchCompiledObjectV1 {
        object,
        receipt,
        operation: PhantomData,
    })
}

fn validate_policy(policy: &SearchCompilePolicyV1) -> Result<(), SearchManifestErrorV1> {
    if policy.max_source_bytes > MAX_AOT_SEARCH_SOURCE_BYTES_V1 {
        return Err(SearchManifestErrorV1::SourcePolicyExceedsHardLimit {
            limit: MAX_AOT_SEARCH_SOURCE_BYTES_V1,
            requested: policy.max_source_bytes,
        });
    }
    if policy.max_literal_bytes > MAX_AOT_SEARCH_LITERAL_BYTES_V1 {
        return Err(SearchManifestErrorV1::LiteralPolicyExceedsHardLimit {
            limit: MAX_AOT_SEARCH_LITERAL_BYTES_V1,
            requested: policy.max_literal_bytes,
        });
    }
    if policy.max_result_persistent_bytes == 0 {
        return Err(SearchManifestErrorV1::ZeroResultPersistentLimit);
    }
    if policy.max_observed_stage_scratch_bytes == 0 {
        return Err(SearchManifestErrorV1::ZeroObservedStageScratchLimit);
    }
    Ok(())
}

fn encode_manifest<O: Operation>(
    policy: &SearchCompilePolicyV1,
    backend: MacosAarch64SearchBackendV1,
) -> Result<([u8; 32], u64), CanonicalError> {
    let mut encoder = CanonicalEncoder::hashing();
    encoder.raw(MANIFEST_DOMAIN)?;
    encoder.u16(AOT_SEARCH_COMPILER_VERSION_V1)?;
    encoder.u16(AOT_SEARCH_MANIFEST_SCHEMA_VERSION_V1)?;
    encoder.u8(output_tag(O::KIND))?;
    encoder.u16(backend.backend_version().0)?;
    encode_target(&mut encoder, TargetSpec::AARCH64_AAPCS64)?;
    encoder.u64(CpuFeatures::ASIMD.bits())?;
    encoder.u64(policy.max_source_bytes)?;
    encoder.u64(policy.max_literal_bytes)?;
    encode_validate_limits(&mut encoder, policy.kernel_ir)?;
    encode_emit_limits(&mut encoder, policy.native)?;
    encode_object_limits(&mut encoder, policy.object)?;
    encoder.u64(policy.max_result_persistent_bytes)?;
    encoder.u64(policy.max_observed_stage_scratch_bytes)?;
    encoder.u64(MAX_AOT_SEARCH_SOURCE_BYTES_V1)?;
    encoder.u64(MIN_AOT_SEARCH_LITERAL_BYTES_V1)?;
    encoder.u64(MAX_AOT_SEARCH_LITERAL_BYTES_V1)?;
    let finished = encoder.finish()?;
    Ok((finished.bytes, finished.hashed_bytes))
}

#[allow(
    clippy::too_many_arguments,
    reason = "the binding preimage is the complete receipt-carried source/IR/native tuple"
)]
fn object_binding_identity(
    manifest_identity: SearchManifestIdentityV1,
    semantic: SearchExactLiteralAotSemanticBindingIdentity,
    literal_identity: SearchLiteralIdentityV1,
    literal_bytes: u64,
    output: OutputKind,
    anchors: AnchorFlags,
    kir_identity: CacheIdentity,
    artifact_identity: ArtifactIdentity,
    native: ImageStats,
) -> Result<([u8; 32], u64), SearchCompileErrorV1> {
    let mut encoder = CanonicalEncoder::hashing();
    encoder
        .raw(OBJECT_BINDING_DOMAIN)
        .map_err(map_compile_canonical)?;
    encoder
        .raw(manifest_identity.as_bytes())
        .map_err(map_compile_canonical)?;
    encoder
        .raw(semantic.as_bytes())
        .map_err(map_compile_canonical)?;
    encoder
        .raw(literal_identity.as_bytes())
        .map_err(map_compile_canonical)?;
    encoder.u64(literal_bytes).map_err(map_compile_canonical)?;
    encoder
        .u8(output_tag(output))
        .map_err(map_compile_canonical)?;
    encoder
        .boolean(anchors.start)
        .map_err(map_compile_canonical)?;
    encoder
        .boolean(anchors.end)
        .map_err(map_compile_canonical)?;
    encoder
        .raw(kir_identity.as_bytes())
        .map_err(map_compile_canonical)?;
    encoder
        .raw(artifact_identity.as_bytes())
        .map_err(map_compile_canonical)?;
    encode_image_stats(&mut encoder, native).map_err(map_compile_canonical)?;
    let finished = encoder.finish().map_err(map_compile_canonical)?;
    Ok((finished.bytes, finished.hashed_bytes))
}

fn literal_identity(literal: &[u8]) -> SearchLiteralIdentityV1 {
    let mut hasher = Sha256::new();
    hasher.update(LITERAL_DOMAIN);
    hasher.update(
        u64::try_from(literal.len())
            .expect("the admitted width-32 Search literal length always fits u64")
            .to_le_bytes(),
    );
    hasher.update(literal);
    SearchLiteralIdentityV1::new(hasher.finalize().into())
}

fn authenticate_image<O: Operation>(
    image: &NativeImage,
    kir_identity: CacheIdentity,
    backend: MacosAarch64SearchBackendV1,
) -> Result<(), SearchCompileErrorV1> {
    let target = image.target();
    let baseline = TargetSpec::AARCH64_AAPCS64;
    if image.backend_version() != backend.backend_version()
        || image.output() != O::KIND
        || image.source_identity() != kir_identity
        || target.architecture != baseline.architecture
        || target.little_endian != baseline.little_endian
        || target.pointer_width != baseline.pointer_width
        || target.abi != baseline.abi
        || target.features != CpuFeatures::ASIMD
    {
        return Err(SearchCompileErrorV1::ContractMismatch {
            field: "Search native image",
        });
    }
    fre_jit_aarch64::audit(image).map_err(|_| SearchCompileErrorV1::ContractMismatch {
        field: "independent Search image audit",
    })?;
    Ok(())
}

fn authenticate_object<O: Operation>(
    object: &BuiltObject,
    image: &NativeImage,
    binding: BindingIdentity,
    backend: MacosAarch64SearchBackendV1,
    object_limits: ObjectLimits,
) -> Result<(), SearchCompileErrorV1> {
    let metadata = object.metadata();
    let report = object.report();
    if metadata.format_version() != fre_aot_macho::METADATA_VERSION
        || usize::from(metadata.record_bytes()) != fre_aot_macho::METADATA_BYTES_V1
        || metadata.backend_version() != backend.backend_version().0
        || metadata.abi_kind() != AbiKind::Search
        || metadata.output_kind() != output_tag(O::KIND)
        || metadata.architecture() != image.target().architecture
        || metadata.little_endian() != image.target().little_endian
        || metadata.pointer_width() != image.target().pointer_width
        || metadata.target_abi() != image.target().abi
        || metadata.platform() != fre_aot_macho::PLATFORM_MACOS
        || metadata.status_bits() != fre_aot_macho::STATUS_BITS_V1
        || metadata.abi_schema() != fre_aot_macho::CALL_ABI_SCHEMA_V1
        || metadata.features() != image.target().features.bits()
        || metadata.entry_offset() != fre_aot_macho::ENTRY_OFFSET_V1
        || metadata.code_bytes() != image.stats().code_bytes
        || metadata.rodata_offset() != image.layout().rodata_from_code_start
        || metadata.rodata_bytes() != image.stats().data_bytes
        || metadata.literal_bytes() != 0
        || metadata.source_identity() != image.source_identity().as_bytes()
        || metadata.artifact_identity() != image.artifact_identity().as_bytes()
        || !binding.matches_claim(metadata.claimed_binding_identity())
        || !report
            .compile_identity
            .matches_claim(metadata.claimed_compile_identity())
        || report.compile_identity != object.compile_identity()
        || report.object_identity != object.object_identity()
    {
        return Err(SearchCompileErrorV1::ContractMismatch {
            field: "Search Mach-O object",
        });
    }
    fre_aot_macho::validate_search_object(image, binding, object.as_bytes(), object_limits)
        .map_err(SearchCompileErrorV1::Object)?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the compiler receipt accounts each sequential source/KIR/native/object stage explicitly"
)]
fn compile_accounting<O: Operation>(
    manifest: &MacosAarch64ExactSearchManifestV1<O>,
    source_bytes: u64,
    source_capacity_bytes: u64,
    literal_bytes: u64,
    candidate_identity_bytes_hashed: u64,
    object_binding_bytes_hashed: u64,
    kernel: ProgramStats,
    image: &NativeImage,
    object: &BuiltObject,
) -> Result<SearchCompileAccountingV1, SearchCompileErrorV1> {
    let object_report = object.report();
    let resources = kernel.resources();
    let typed_inline_bytes = usize_u64(
        size_of::<SearchCompiledObjectV1<O>>(),
        "compiled object inline bytes",
    )?;
    if compiled_object_inline_bytes(O::KIND) != Some(typed_inline_bytes) {
        return Err(SearchCompileErrorV1::ContractMismatch {
            field: "typed compiled-object layout",
        });
    }

    let result_persistent_bytes =
        usize_u64(object_report.persistent_capacity_bytes, "object capacity")?
            .checked_add(typed_inline_bytes)
            .ok_or(SearchCompileErrorV1::ArithmeticOverflow {
                at: "result persistent bytes",
            })?;
    enforce(
        "result persistent bytes",
        result_persistent_bytes,
        manifest.policy.max_result_persistent_bytes,
    )?;

    let observed_stage_scratch_bytes_upper_bound = [
        usize_u64(
            resources.validation_scratch_bytes(),
            "KIR validation scratch",
        )?,
        usize_u64(
            resources.validation_phase_peak_bytes(),
            "KIR validation phase",
        )?,
        usize_u64(
            resources.serialization_phase_peak_bytes(),
            "KIR serialization phase",
        )?,
        usize_u64(resources.identity_phase_peak_bytes(), "KIR identity phase")?,
        image.stats().scratch_bytes,
        object_report.scratch_bytes,
        IDENTITY_SCRATCH_BYTES,
    ]
    .into_iter()
    .max()
    .ok_or(SearchCompileErrorV1::ArithmeticOverflow {
        at: "peak scratch set",
    })?;
    enforce(
        "per-stage scratch bytes",
        observed_stage_scratch_bytes_upper_bound,
        manifest.policy.max_observed_stage_scratch_bytes,
    )?;

    Ok(SearchCompileAccountingV1 {
        source_bytes,
        source_capacity_bytes,
        literal_bytes,
        candidate_identity_bytes_hashed,
        manifest_identity_bytes_hashed: manifest.identity_bytes_hashed,
        object_binding_bytes_hashed,
        kernel,
        native: image.stats(),
        object_bytes: usize_u64(object_report.object_bytes, "object bytes")?,
        object_persistent_bytes: usize_u64(
            object_report.persistent_capacity_bytes,
            "object persistent bytes",
        )?,
        object_payload_bytes: usize_u64(object_report.payload_bytes, "object payload bytes")?,
        object_work: object_report.total_work,
        object_scratch_bytes: object_report.scratch_bytes,
        result_persistent_bytes,
        observed_stage_scratch_bytes_upper_bound,
    })
}

fn encode_receipt(
    receipt: &SearchCompileReceiptV1,
) -> Result<SearchCompileReceiptIdentityV1, SearchCompileErrorV1> {
    let mut encoder = CanonicalEncoder::hashing();
    encode_receipt_fields(&mut encoder, receipt).map_err(map_compile_canonical)?;
    let finished = encoder.finish().map_err(map_compile_canonical)?;
    Ok(SearchCompileReceiptIdentityV1::new(finished.bytes))
}

trait SearchCanonicalEncoder {
    fn raw(&mut self, bytes: &[u8]) -> Result<(), CanonicalError>;

    fn boolean(&mut self, value: bool) -> Result<(), CanonicalError> {
        self.u8(u8::from(value))
    }

    fn u8(&mut self, value: u8) -> Result<(), CanonicalError> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), CanonicalError> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), CanonicalError> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), CanonicalError> {
        self.raw(&value.to_le_bytes())
    }

    fn usize(&mut self, value: usize) -> Result<(), CanonicalError> {
        self.u64(u64::try_from(value).map_err(|_| CanonicalError::ByteCountOverflow)?)
    }
}

impl SearchCanonicalEncoder for CanonicalEncoder {
    fn raw(&mut self, bytes: &[u8]) -> Result<(), CanonicalError> {
        CanonicalEncoder::raw(self, bytes)
    }
}

struct FixedCanonicalEncoder<'a> {
    destination: &'a mut [u8],
    position: usize,
}

impl<'a> FixedCanonicalEncoder<'a> {
    const fn new(destination: &'a mut [u8]) -> Self {
        Self {
            destination,
            position: 0,
        }
    }

    const fn position(&self) -> usize {
        self.position
    }
}

impl SearchCanonicalEncoder for FixedCanonicalEncoder<'_> {
    fn raw(&mut self, bytes: &[u8]) -> Result<(), CanonicalError> {
        let end = self
            .position
            .checked_add(bytes.len())
            .ok_or(CanonicalError::ByteCountOverflow)?;
        let destination = self
            .destination
            .get_mut(self.position..end)
            .ok_or(CanonicalError::ByteCountOverflow)?;
        destination.copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }
}

fn encode_receipt_fields(
    encoder: &mut impl SearchCanonicalEncoder,
    receipt: &SearchCompileReceiptV1,
) -> Result<(), CanonicalError> {
    encoder.raw(RECEIPT_DOMAIN)?;
    encoder.u16(receipt.schema_version)?;
    encoder.u16(receipt.compiler_version)?;
    encoder.raw(receipt.manifest_identity.as_bytes())?;
    encoder.raw(receipt.semantic_binding_identity.as_bytes())?;
    encoder.raw(receipt.literal_identity.as_bytes())?;
    encoder.u32(receipt.literal_bytes)?;
    encoder.u8(output_tag(receipt.output))?;
    encoder.boolean(receipt.anchors.start)?;
    encoder.boolean(receipt.anchors.end)?;
    encoder.raw(receipt.kir_identity.as_bytes())?;
    encoder.raw(receipt.native_artifact_identity.as_bytes())?;
    encoder.raw(receipt.binding_identity.as_bytes())?;
    encode_metadata(encoder, receipt.metadata)?;
    encoder.raw(receipt.compile_identity.as_bytes())?;
    encoder.raw(receipt.object_identity.as_bytes())?;
    encoder.u64(receipt.object_bytes)?;
    encode_accounting(encoder, &receipt.accounting)
}

fn encode_target(
    encoder: &mut impl SearchCanonicalEncoder,
    target: TargetSpec,
) -> Result<(), CanonicalError> {
    encoder.u8(target.architecture)?;
    encoder.boolean(target.little_endian)?;
    encoder.u8(target.pointer_width)?;
    encoder.u8(target.abi)?;
    encoder.u64(target.features.bits())
}

fn encode_program_stats(
    encoder: &mut impl SearchCanonicalEncoder,
    stats: ProgramStats,
) -> Result<(), CanonicalError> {
    encoder.usize(stats.blocks())?;
    encoder.usize(stats.instructions())?;
    encoder.usize(stats.data_blobs())?;
    encoder.usize(stats.data_bytes())?;
    encoder.usize(stats.serialized_bytes())?;
    encoder.usize(stats.serialized_capacity_bytes())?;
    encoder.usize(stats.estimated_code_bytes())?;
    encoder.u64(stats.validation_work())?;
    encoder.u64(stats.work_factor())?;
    let resources = stats.resources();
    encoder.u16(resources.version())?;
    encoder.u8(resources.allocation_requests())?;
    encoder.usize(resources.literal_allocation_request_bytes())?;
    encoder.usize(resources.block_allocation_request_bytes())?;
    encoder.usize(resources.data_table_allocation_request_bytes())?;
    encoder.usize(resources.raw_allocation_request_bytes())?;
    encoder.usize(resources.serialized_allocation_request_bytes())?;
    encoder.usize(resources.allocation_request_bytes())?;
    encoder.usize(resources.literal_capacity_bytes())?;
    encoder.usize(resources.block_capacity_bytes())?;
    encoder.usize(resources.data_table_capacity_bytes())?;
    encoder.usize(resources.raw_program_capacity_bytes())?;
    encoder.usize(resources.serialized_capacity_bytes())?;
    encoder.u64(resources.planning_work())?;
    encoder.u64(resources.initialization_work())?;
    encoder.u64(resources.copy_work())?;
    encoder.u8(resources.hash_invocations())?;
    encoder.u64(resources.hash_work())?;
    encoder.u64(resources.validation_work())?;
    encoder.u64(resources.validation_work_upper_bound())?;
    encoder.u64(resources.construction_work())?;
    encoder.usize(resources.validation_scratch_bytes())?;
    encoder.usize(resources.validation_phase_peak_bytes())?;
    encoder.usize(resources.serialization_phase_peak_bytes())?;
    encoder.usize(resources.identity_phase_peak_bytes())?;
    encoder.usize(resources.retained_program_bytes())
}

fn encode_image_stats(
    encoder: &mut impl SearchCanonicalEncoder,
    stats: ImageStats,
) -> Result<(), CanonicalError> {
    encoder.u32(stats.code_bytes)?;
    encoder.u32(stats.data_bytes)?;
    encoder.u32(stats.relocations)?;
    encoder.u32(stats.labels)?;
    encoder.u64(stats.emission_work)?;
    encoder.u64(stats.scratch_bytes)?;
    encoder.u32(stats.vector_instructions)
}

fn encode_metadata(
    encoder: &mut impl SearchCanonicalEncoder,
    metadata: MetadataV1,
) -> Result<(), CanonicalError> {
    encoder.u16(metadata.format_version())?;
    encoder.u16(metadata.record_bytes())?;
    encoder.u16(metadata.backend_version())?;
    encoder.u8(match metadata.abi_kind() {
        AbiKind::Search => 1,
        AbiKind::Aggregate => 2,
    })?;
    encoder.u8(metadata.output_kind())?;
    encoder.u8(metadata.architecture())?;
    encoder.boolean(metadata.little_endian())?;
    encoder.u8(metadata.pointer_width())?;
    encoder.u8(metadata.target_abi())?;
    encoder.u8(metadata.platform())?;
    encoder.u8(metadata.status_bits())?;
    encoder.u16(metadata.abi_schema())?;
    encoder.u64(metadata.features())?;
    encoder.u32(metadata.payload_bytes())?;
    encoder.u32(metadata.entry_offset())?;
    encoder.u32(metadata.code_bytes())?;
    encoder.u32(metadata.rodata_offset())?;
    encoder.u32(metadata.rodata_bytes())?;
    encoder.u32(metadata.literal_bytes())?;
    encoder.raw(metadata.source_identity())?;
    encoder.raw(metadata.artifact_identity())?;
    encoder.raw(metadata.claimed_binding_identity().as_bytes())?;
    encoder.raw(metadata.payload_sha256())?;
    encoder.raw(metadata.claimed_compile_identity().as_bytes())
}

fn encode_accounting(
    encoder: &mut impl SearchCanonicalEncoder,
    accounting: &SearchCompileAccountingV1,
) -> Result<(), CanonicalError> {
    encoder.u64(accounting.source_bytes)?;
    encoder.u64(accounting.source_capacity_bytes)?;
    encoder.u64(accounting.literal_bytes)?;
    encoder.u64(accounting.candidate_identity_bytes_hashed)?;
    encoder.u64(accounting.manifest_identity_bytes_hashed)?;
    encoder.u64(accounting.object_binding_bytes_hashed)?;
    encode_program_stats(encoder, accounting.kernel)?;
    encode_image_stats(encoder, accounting.native)?;
    encoder.u64(accounting.object_bytes)?;
    encoder.u64(accounting.object_persistent_bytes)?;
    encoder.u64(accounting.object_payload_bytes)?;
    encoder.u64(accounting.object_work)?;
    encoder.u64(accounting.object_scratch_bytes)?;
    encoder.u64(accounting.result_persistent_bytes)?;
    encoder.u64(accounting.observed_stage_scratch_bytes_upper_bound)
}

const fn output_tag(output: OutputKind) -> u8 {
    match output {
        OutputKind::Exists => 1,
        OutputKind::SelectedEnd => 2,
        OutputKind::Span => 3,
    }
}

fn compiled_object_inline_bytes(output: OutputKind) -> Option<u64> {
    let bytes = match output {
        OutputKind::Exists => size_of::<SearchCompiledObjectV1<fre_kernel_ir::Exists>>(),
        OutputKind::SelectedEnd => size_of::<SearchCompiledObjectV1<fre_kernel_ir::SelectedEnd>>(),
        OutputKind::Span => size_of::<SearchCompiledObjectV1<fre_kernel_ir::Span>>(),
    };
    u64::try_from(bytes).ok()
}

fn enforce(resource: &'static str, required: u64, limit: u64) -> Result<(), SearchCompileErrorV1> {
    if required > limit {
        Err(SearchCompileErrorV1::ResourceLimit {
            resource,
            limit,
            required,
        })
    } else {
        Ok(())
    }
}

fn usize_u64(value: usize, at: &'static str) -> Result<u64, SearchCompileErrorV1> {
    u64::try_from(value).map_err(|_| SearchCompileErrorV1::ArithmeticOverflow { at })
}

const fn map_manifest_canonical(_error: CanonicalError) -> SearchManifestErrorV1 {
    SearchManifestErrorV1::ArithmeticOverflow
}

const fn map_compile_canonical(_error: CanonicalError) -> SearchCompileErrorV1 {
    SearchCompileErrorV1::ArithmeticOverflow {
        at: "canonical identity",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fre_kernel_ir::{Exists, SelectedEnd, Span};

    fn compile<O: Operation>() -> SearchCompiledObjectV1<O> {
        plan_and_compile_macos_aarch64_exact_search_v1(
            MacosAarch64ExactSearchManifestV1::<O>::default(),
            b"needle".to_vec(),
            RustProfile::default(),
        )
        .expect("inert exact Search object")
    }

    fn assert_output<O: Operation>(output: OutputKind, tag: u8) {
        let compiled = compile::<O>();
        assert_eq!(compiled.receipt().output(), output);
        assert_eq!(compiled.receipt().metadata().output_kind(), tag);
        assert_eq!(
            compiled.runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );
        assert_eq!(
            compiled.receipt().runtime_authority(),
            SearchAotRuntimeAuthorityV1::Absent
        );
        compiled
            .receipt()
            .validate_object(compiled.object().as_bytes(), ObjectLimits::default())
            .expect("typed receipt reopens its inert object");
    }

    fn assert_deterministic<O: Operation>() {
        let first = compile::<O>();
        let second = compile::<O>();
        assert_eq!(first.object().as_bytes(), second.object().as_bytes());
        assert_eq!(first.receipt(), second.receipt());
        let first_receipt = first.receipt().canonical_bytes().unwrap();
        let second_receipt = second.receipt().canonical_bytes().unwrap();
        assert_eq!(first_receipt, second_receipt);
        assert_eq!(
            first_receipt.len(),
            SEARCH_COMPILE_RECEIPT_CANONICAL_BYTES_V1
        );
        let digest: [u8; 32] = Sha256::digest(first_receipt).into();
        assert_eq!(digest, *first.receipt().receipt_identity().as_bytes());
    }

    #[test]
    fn program_stats_encoding_covers_the_complete_public_resource_receipt() {
        let stats = build_exact_literal::<Span>(
            b"needle",
            AnchorFlags::default(),
            ValidateLimits::default(),
        )
        .unwrap()
        .stats();
        let mut actual = CanonicalEncoder::hashing();
        encode_program_stats(&mut actual, stats).unwrap();
        let actual = actual.finish().unwrap();

        let resources = stats.resources();
        let mut expected = CanonicalEncoder::hashing();
        expected.usize(stats.blocks()).unwrap();
        expected.usize(stats.instructions()).unwrap();
        expected.usize(stats.data_blobs()).unwrap();
        expected.usize(stats.data_bytes()).unwrap();
        expected.usize(stats.serialized_bytes()).unwrap();
        expected.usize(stats.serialized_capacity_bytes()).unwrap();
        expected.usize(stats.estimated_code_bytes()).unwrap();
        expected.u64(stats.validation_work()).unwrap();
        expected.u64(stats.work_factor()).unwrap();
        expected.u16(resources.version()).unwrap();
        expected.u8(resources.allocation_requests()).unwrap();
        expected
            .usize(resources.literal_allocation_request_bytes())
            .unwrap();
        expected
            .usize(resources.block_allocation_request_bytes())
            .unwrap();
        expected
            .usize(resources.data_table_allocation_request_bytes())
            .unwrap();
        expected
            .usize(resources.raw_allocation_request_bytes())
            .unwrap();
        expected
            .usize(resources.serialized_allocation_request_bytes())
            .unwrap();
        expected
            .usize(resources.allocation_request_bytes())
            .unwrap();
        expected.usize(resources.literal_capacity_bytes()).unwrap();
        expected.usize(resources.block_capacity_bytes()).unwrap();
        expected
            .usize(resources.data_table_capacity_bytes())
            .unwrap();
        expected
            .usize(resources.raw_program_capacity_bytes())
            .unwrap();
        expected
            .usize(resources.serialized_capacity_bytes())
            .unwrap();
        expected.u64(resources.planning_work()).unwrap();
        expected.u64(resources.initialization_work()).unwrap();
        expected.u64(resources.copy_work()).unwrap();
        expected.u8(resources.hash_invocations()).unwrap();
        expected.u64(resources.hash_work()).unwrap();
        expected.u64(resources.validation_work()).unwrap();
        expected
            .u64(resources.validation_work_upper_bound())
            .unwrap();
        expected.u64(resources.construction_work()).unwrap();
        expected
            .usize(resources.validation_scratch_bytes())
            .unwrap();
        expected
            .usize(resources.validation_phase_peak_bytes())
            .unwrap();
        expected
            .usize(resources.serialization_phase_peak_bytes())
            .unwrap();
        expected
            .usize(resources.identity_phase_peak_bytes())
            .unwrap();
        expected.usize(resources.retained_program_bytes()).unwrap();
        let expected = expected.finish().unwrap();

        assert_eq!(actual, expected);
        assert_eq!(actual.hashed_bytes, 260);
    }

    #[test]
    fn all_outputs_are_typed_deterministic_and_runtime_inert() {
        assert_output::<Exists>(OutputKind::Exists, 1);
        assert_output::<SelectedEnd>(OutputKind::SelectedEnd, 2);
        assert_output::<Span>(OutputKind::Span, 3);
        assert_deterministic::<Exists>();
        assert_deterministic::<SelectedEnd>();
        assert_deterministic::<Span>();
    }

    #[test]
    fn manifest_identity_separates_every_output_type() {
        let exists = MacosAarch64ExactSearchManifestV1::<Exists>::default();
        let end = MacosAarch64ExactSearchManifestV1::<SelectedEnd>::default();
        let span = MacosAarch64ExactSearchManifestV1::<Span>::default();
        assert_ne!(exists.identity(), end.identity());
        assert_ne!(exists.identity(), span.identity());
        assert_ne!(end.identity(), span.identity());
    }

    #[test]
    fn explicit_v9_is_deterministic_and_identity_disjoint_from_unchanged_v8_default() {
        let v8_manifest = MacosAarch64ExactSearchManifestV1::<Span>::default();
        let v9_manifest = MacosAarch64ExactSearchManifestV1::<Span>::v9_candidate(
            SearchCompilePolicyV1::default(),
        )
        .expect("V9 candidate manifest");
        assert_eq!(v8_manifest.backend(), MacosAarch64SearchBackendV1::AsimdV8);
        assert_eq!(v9_manifest.backend(), MacosAarch64SearchBackendV1::AsimdV9);
        assert_ne!(v8_manifest.identity(), v9_manifest.identity());

        let first = plan_and_compile_macos_aarch64_exact_search_v1(
            v9_manifest,
            b"needle".to_vec(),
            RustProfile::default(),
        )
        .expect("first V9 object");
        let second = plan_and_compile_macos_aarch64_exact_search_v1(
            v9_manifest,
            b"needle".to_vec(),
            RustProfile::default(),
        )
        .expect("second V9 object");
        assert_eq!(
            first.receipt().metadata().backend_version(),
            BackendVersion::SEARCH_V9.0
        );
        assert_eq!(first.object().as_bytes(), second.object().as_bytes());
        assert_eq!(first.receipt(), second.receipt());
        let expectation =
            crate::build_static_search_span_expectation_v1(&first).expect("V9 neutral expectation");
        let claim = fre_aot_search_contract::inspect_static_search_span_expectation_v1(
            expectation.as_bytes(),
        )
        .expect("V9 expectation inspection");
        assert_eq!(
            claim.backend_version(),
            fre_aot_search_contract::SEARCH_BACKEND_ASIMD_TAG22_V1
        );
        assert!(expectation.authenticates_claim(&claim));
    }

    #[test]
    fn source_capacity_precedes_utf8_and_nonexact_sources_fail_closed() {
        let mut policy = SearchCompilePolicyV1::high_fuel();
        policy.max_source_bytes = 1;
        let manifest = MacosAarch64ExactSearchManifestV1::<Span>::new(policy).unwrap();
        let mut oversized_capacity = Vec::with_capacity(2);
        oversized_capacity.push(0xff);
        assert!(matches!(
            plan_and_compile_macos_aarch64_exact_search_v1(
                manifest,
                oversized_capacity,
                RustProfile::default(),
            ),
            Err(SearchCompileErrorV1::ResourceLimit {
                resource: "source capacity bytes",
                limit: 1,
                required,
            }) if required >= 2
        ));

        assert!(matches!(
            plan_and_compile_macos_aarch64_exact_search_v1(
                MacosAarch64ExactSearchManifestV1::<Span>::default(),
                vec![0xff],
                RustProfile::default(),
            ),
            Err(SearchCompileErrorV1::InvalidUtf8Source)
        ));
        assert!(matches!(
            plan_and_compile_macos_aarch64_exact_search_v1(
                MacosAarch64ExactSearchManifestV1::<Span>::default(),
                b"foo|bar".to_vec(),
                RustProfile::default(),
            ),
            Err(SearchCompileErrorV1::ExactLiteralRequired)
        ));
    }

    #[test]
    fn receipt_closure_rejects_rehashed_output_and_accounting_splices() {
        let compiled = compile::<Span>();
        let mut output_splice = *compiled.receipt();
        output_splice.output = OutputKind::Exists;
        output_splice.receipt_identity = encode_receipt(&output_splice).unwrap();
        assert!(!output_splice.authenticates_itself());
        assert!(matches!(
            output_splice.validate_object(compiled.object().as_bytes(), ObjectLimits::default()),
            Err(SearchReceiptValidationErrorV1::Mismatch {
                field: SearchReceiptMismatchV1::ReceiptIdentity,
            })
        ));

        let mut accounting_splice = *compiled.receipt();
        accounting_splice.accounting.object_bytes = accounting_splice
            .accounting
            .object_bytes
            .checked_add(1)
            .unwrap();
        accounting_splice.receipt_identity = encode_receipt(&accounting_splice).unwrap();
        assert!(!accounting_splice.authenticates_itself());
    }

    #[test]
    fn receipt_closure_rejects_a_rehashed_binding_preimage_splice() {
        let compiled = compile::<Span>();
        let mut splice = *compiled.receipt();
        let mut literal_identity = *splice.literal_identity.as_bytes();
        literal_identity[0] ^= 1;
        splice.literal_identity = SearchLiteralIdentityV1::new(literal_identity);
        splice.receipt_identity = encode_receipt(&splice).unwrap();

        assert!(!splice.authenticates_itself());
        assert!(matches!(
            splice.validate_object(compiled.object().as_bytes(), ObjectLimits::default()),
            Err(SearchReceiptValidationErrorV1::Mismatch {
                field: SearchReceiptMismatchV1::ReceiptIdentity,
            })
        ));
    }

    #[test]
    fn receipt_rejects_mutated_object_bytes() {
        let compiled = compile::<Span>();
        let mut bytes = compiled.object().as_bytes().to_vec();
        bytes[0] ^= 1;
        assert!(
            compiled
                .receipt()
                .validate_object(&bytes, ObjectLimits::default())
                .is_err()
        );
    }

    #[test]
    fn observed_result_and_stage_scratch_ceilings_are_post_build_gates() {
        let baseline = compile::<Span>();
        let accounting = baseline.receipt().accounting();
        let resources = accounting.kernel().resources();
        let expected_stage_scratch = [
            u64::try_from(resources.validation_scratch_bytes()).unwrap(),
            u64::try_from(resources.validation_phase_peak_bytes()).unwrap(),
            u64::try_from(resources.serialization_phase_peak_bytes()).unwrap(),
            u64::try_from(resources.identity_phase_peak_bytes()).unwrap(),
            accounting.native().scratch_bytes,
            accounting.object_scratch_bytes(),
            IDENTITY_SCRATCH_BYTES,
        ]
        .into_iter()
        .max()
        .unwrap();
        assert_eq!(
            accounting.observed_stage_scratch_bytes_upper_bound(),
            expected_stage_scratch
        );

        let mut result_policy = SearchCompilePolicyV1::high_fuel();
        result_policy.max_result_persistent_bytes =
            accounting.result_persistent_bytes().checked_sub(1).unwrap();
        let result_manifest =
            MacosAarch64ExactSearchManifestV1::<Span>::new(result_policy).unwrap();
        assert!(matches!(
            plan_and_compile_macos_aarch64_exact_search_v1(
                result_manifest,
                b"needle".to_vec(),
                RustProfile::default(),
            ),
            Err(SearchCompileErrorV1::ResourceLimit {
                resource: "result persistent bytes",
                limit,
                required,
            }) if limit + 1 == required
        ));

        let mut scratch_policy = SearchCompilePolicyV1::high_fuel();
        scratch_policy.max_observed_stage_scratch_bytes =
            expected_stage_scratch.checked_sub(1).unwrap();
        let scratch_manifest =
            MacosAarch64ExactSearchManifestV1::<Span>::new(scratch_policy).unwrap();
        assert!(matches!(
            plan_and_compile_macos_aarch64_exact_search_v1(
                scratch_manifest,
                b"needle".to_vec(),
                RustProfile::default(),
            ),
            Err(SearchCompileErrorV1::ResourceLimit {
                resource: "per-stage scratch bytes",
                limit,
                required,
            }) if limit + 1 == required
        ));
    }

    #[test]
    fn empty_exact_literal_is_not_an_asimd_search_candidate() {
        assert!(matches!(
            plan_and_compile_macos_aarch64_exact_search_v1(
                MacosAarch64ExactSearchManifestV1::<Span>::default(),
                Vec::new(),
                RustProfile::default(),
            ),
            Err(SearchCompileErrorV1::EmptyLiteralUnsupported)
        ));
    }
}
