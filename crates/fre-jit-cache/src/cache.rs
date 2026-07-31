//! Concurrent single-flight state machine and lease lifetime tracking.

use core::{fmt, marker::PhantomData};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, ThreadId},
};

use fre_jit_aarch64::{
    BackendVersion, EmitLimits, ImageStats, MAX_REPEATED_CONFIRM_BYTES,
    SELECTED_END_REGISTER_CALL_ABI_SCHEMA_V2, SELECTED_END_REGISTER_RETURN_ENCODING_V2,
    SelectedEndRegisterArtifactIdentityV2, SelectedEndRegisterBackendV2, TargetSpec,
    emit_selected_end_register_v2, selected_end_register_target_v2,
};
use fre_jit_runtime::{
    CallError, NativeImage, PublicationAccounting, PublicationLimits, PublishError,
    PublishedKernel, PublishedSelectedEndRegisterV2, RuntimeIdentity, RuntimeOperation, publish,
    publish_selected_end_register_v2,
};
use fre_kernel_ir::{
    AbiVersion, AnchorFlags, CacheIdentity as KernelIrIdentity, OutputKind, RawProgram,
    SearchWindow, SelectedEnd, SemanticsVersion, ValidateLimits, build_exact_literal,
};
use sha2::{Digest, Sha256};

use crate::{
    CacheCreateError, CacheError, CacheLimits, CachePolicyIdentity, CacheResource, CacheSnapshot,
    CacheTotals, CacheUsage, SelectedEndRegisterCachePolicyIdentityV2,
    policy::SELECTED_END_REGISTER_COMPILE_KEY_SCHEMA_V2,
};

/// A bounded process-local cache for one compile-time output contract.
pub struct KernelCache<O: RuntimeOperation> {
    core: CacheCore<RuntimeKernelContract<O>>,
}

/// A caller-owned mapping lease that remains callable after resident eviction.
pub struct KernelLease<O: RuntimeOperation> {
    core: CacheLeaseCore<RuntimeKernelContract<O>>,
}

/// A bounded process-local cache for audited register-return ABI2 images.
///
/// Cache synchronization occurs only while acquiring a lease. A caller keeps
/// the lease with its matcher and opens a current-thread session by borrowing
/// [`SelectedEndRegisterLeaseV2::kernel`]; repeated searches never touch this
/// cache state.
pub struct SelectedEndRegisterCacheV2 {
    core: CacheCore<SelectedEndRegisterContractV2>,
}

/// A caller-owned ABI2 mapping lease that survives resident eviction.
pub struct SelectedEndRegisterLeaseV2 {
    core: CacheLeaseCore<SelectedEndRegisterContractV2>,
}

/// Request failure for one register-return ABI2 cache.
pub type SelectedEndRegisterCacheErrorV2 = CacheError<SelectedEndRegisterCompileIdentityV2>;

/// Domain-separated identity of a complete pre-emission ABI2 compile request.
///
/// This is deliberately distinct from the eventual artifact identity. It
/// includes every input that can affect construction success or generated
/// bytes, so a cache hit may safely skip Kernel IR construction, emission,
/// emitter-final audit, and executable publication.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SelectedEndRegisterCompileIdentityV2([u8; 32]);

impl SelectedEndRegisterCompileIdentityV2 {
    /// Borrow the canonical compile-request digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SelectedEndRegisterCompileIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SelectedEndRegisterCompileIdentityV2({self})")
    }
}

impl fmt::Display for SelectedEndRegisterCompileIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct SelectedEndRegisterCompileRequestV2 {
    literal: [u8; MAX_REPEATED_CONFIRM_BYTES],
    literal_bytes: u32,
    anchors: AnchorFlags,
    backend: SelectedEndRegisterBackendV2,
    validation_limits: ValidateLimits,
    emission_limits: EmitLimits,
    identity: SelectedEndRegisterCompileIdentityV2,
}

struct CachedSelectedEndRegisterPublicationV2 {
    kernel: PublishedSelectedEndRegisterV2,
    compile_identity: SelectedEndRegisterCompileIdentityV2,
    source_identity: KernelIrIdentity,
    target: TargetSpec,
    image_stats: ImageStats,
}

const SELECTED_END_REGISTER_COMPILE_IDENTITY_DOMAIN_V2: &[u8] =
    b"FRE-JIT-CACHE-SELECTED-END-REGISTER-COMPILE\0\x02";
impl SelectedEndRegisterCompileRequestV2 {
    fn new(
        literal: &[u8],
        anchors: AnchorFlags,
        backend: SelectedEndRegisterBackendV2,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
    ) -> Result<Self, SelectedEndRegisterCacheErrorV2> {
        if literal.len() > MAX_REPEATED_CONFIRM_BYTES {
            return Err(CacheError::RequestLiteralBytes {
                max: MAX_REPEATED_CONFIRM_BYTES,
                actual: literal.len(),
            });
        }
        let literal_bytes =
            u32::try_from(literal.len()).map_err(|_| CacheError::RequestLiteralBytes {
                max: MAX_REPEATED_CONFIRM_BYTES,
                actual: literal.len(),
            })?;
        let mut retained_literal = [0_u8; MAX_REPEATED_CONFIRM_BYTES];
        retained_literal[..literal.len()].copy_from_slice(literal);
        let identity = selected_end_register_compile_identity_v2(
            literal,
            literal_bytes,
            anchors,
            backend,
            validation_limits,
            emission_limits,
        );
        Ok(Self {
            literal: retained_literal,
            literal_bytes,
            anchors,
            backend,
            validation_limits,
            emission_limits,
            identity,
        })
    }

    fn literal(&self) -> &[u8] {
        let bytes = usize::try_from(self.literal_bytes)
            .expect("u32 compile-request literal width fits every supported host");
        &self.literal[..bytes]
    }
}

fn selected_end_register_compile_identity_v2(
    literal: &[u8],
    literal_bytes: u32,
    anchors: AnchorFlags,
    backend: SelectedEndRegisterBackendV2,
    validation: ValidateLimits,
    emission: EmitLimits,
) -> SelectedEndRegisterCompileIdentityV2 {
    let ValidateLimits {
        max_blocks,
        max_instructions,
        max_data_blobs,
        max_data_bytes,
        max_serialized_bytes,
        max_serialized_capacity_bytes,
        max_construction_allocation_bytes,
        max_raw_program_capacity_bytes,
        max_estimated_code_bytes,
        max_validation_work,
        max_construction_work,
        max_validation_scratch_bytes,
        max_validation_phase_bytes,
        max_serialization_phase_bytes,
        max_identity_phase_bytes,
        max_retained_program_bytes,
        max_work_factor,
    } = validation;
    let EmitLimits {
        max_code_bytes,
        max_data_bytes: max_emitted_data_bytes,
        max_relocations,
        max_labels,
        max_emission_work,
        max_scratch_bytes,
    } = emission;
    let target = selected_end_register_target_v2(backend, anchors, literal_bytes);
    let mut hasher = Sha256::new();
    hasher.update(SELECTED_END_REGISTER_COMPILE_IDENTITY_DOMAIN_V2);
    hasher.update(SELECTED_END_REGISTER_COMPILE_KEY_SCHEMA_V2.to_le_bytes());
    hasher.update(RawProgram::SCHEMA_VERSION.to_le_bytes());
    hasher.update(SemanticsVersion::CURRENT.0.to_le_bytes());
    hasher.update(AbiVersion::CURRENT.0.to_le_bytes());
    hasher.update(SELECTED_END_REGISTER_CALL_ABI_SCHEMA_V2.to_le_bytes());
    hasher.update([SELECTED_END_REGISTER_RETURN_ENCODING_V2]);
    hasher.update([output_key_tag_v2(OutputKind::SelectedEnd)]);
    hasher.update([u8::from(anchors.start), u8::from(anchors.end)]);
    hasher.update([selected_end_register_backend_key_tag_v2(backend)]);
    hasher.update(backend.backend_version().0.to_le_bytes());
    hasher.update(backend.fixed_active_vector_bytes().to_le_bytes());
    hasher.update([
        target.architecture,
        u8::from(target.little_endian),
        target.pointer_width,
        target.abi,
    ]);
    hasher.update(target.features.bits().to_le_bytes());
    for value in [
        max_blocks,
        max_instructions,
        max_data_blobs,
        max_data_bytes,
        max_serialized_bytes,
        max_serialized_capacity_bytes,
        max_construction_allocation_bytes,
        max_raw_program_capacity_bytes,
        max_estimated_code_bytes,
        max_validation_work,
        max_construction_work,
        max_validation_scratch_bytes,
        max_validation_phase_bytes,
        max_serialization_phase_bytes,
        max_identity_phase_bytes,
        max_retained_program_bytes,
        max_work_factor,
        max_code_bytes,
        max_emitted_data_bytes,
        max_relocations,
        max_labels,
        max_emission_work,
        max_scratch_bytes,
    ] {
        hasher.update(value.to_le_bytes());
    }
    hasher.update(u64::from(literal_bytes).to_le_bytes());
    hasher.update(literal);
    SelectedEndRegisterCompileIdentityV2(hasher.finalize().into())
}

const fn selected_end_register_backend_key_tag_v2(backend: SelectedEndRegisterBackendV2) -> u8 {
    match backend {
        SelectedEndRegisterBackendV2::AsimdV8 => 1,
        SelectedEndRegisterBackendV2::Sve16V6Tag19Vl16 => 2,
        SelectedEndRegisterBackendV2::Sve2Fixed16Tag21Vl16 => 3,
    }
}

const fn output_key_tag_v2(output: OutputKind) -> u8 {
    match output {
        OutputKind::Exists => 1,
        OutputKind::SelectedEnd => 2,
        OutputKind::Span => 3,
    }
}

trait CacheContract {
    type Identity: CacheIdentity;
    type Image;
    type Publication;

    fn image_identity(image: &Self::Image) -> Self::Identity;
    fn publication_identity(publication: &Self::Publication) -> Self::Identity;
    fn accounting(publication: &Self::Publication) -> PublicationAccounting;
    fn has_unique_mapping_ownership(publication: &Self::Publication) -> bool;
    fn required_bookkeeping_bytes(limits: CacheLimits) -> Result<u64, CacheCreateError>;
}

trait CacheIdentity: Copy + Eq + fmt::Debug {
    fn as_cache_bytes(&self) -> &[u8; 32];
}

type ContractCacheError<C> = CacheError<<C as CacheContract>::Identity>;

struct RuntimeKernelContract<O: RuntimeOperation>(PhantomData<fn() -> O>);
struct SelectedEndRegisterContractV2;

struct CacheCore<C: CacheContract> {
    inner: Arc<Inner<C>>,
}

struct CacheLeaseCore<C: CacheContract> {
    tracked: Arc<TrackedKernel<C>>,
}

struct Inner<C: CacheContract> {
    state: Mutex<State<C>>,
    wake: Condvar,
    cache_limits: CacheLimits,
    publication_limits: PublicationLimits,
}

struct State<C: CacheContract> {
    entries: Vec<Entry<C>>,
    flights: Vec<Flight<C::Identity>>,
    live: Vec<LiveRecord<C>>,
    totals: CacheTotals,
    current: CacheUsage,
    peak: CacheUsage,
    clock: u128,
    generation: u128,
    accounting_consistent: bool,
}

struct Entry<C: CacheContract> {
    identity: C::Identity,
    last_used: u128,
    tracked: Arc<TrackedKernel<C>>,
}

#[derive(Clone, Copy, Debug)]
struct Flight<I: CacheIdentity> {
    identity: I,
    generation: u128,
    owner: ThreadId,
}

struct LiveRecord<C: CacheContract> {
    identity: C::Identity,
    token: u128,
    tracked: Weak<TrackedKernel<C>>,
}

struct TrackedKernel<C: CacheContract> {
    publication: Option<C::Publication>,
    owner: Weak<Inner<C>>,
    token: u128,
    accounted: AtomicBool,
}

enum Lookup<C: CacheContract> {
    Hit(Arc<TrackedKernel<C>>),
    Retiring,
    Miss,
}

impl CacheIdentity for RuntimeIdentity {
    fn as_cache_bytes(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

impl CacheIdentity for SelectedEndRegisterCompileIdentityV2 {
    fn as_cache_bytes(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

impl<O: RuntimeOperation> CacheContract for RuntimeKernelContract<O> {
    type Identity = RuntimeIdentity;
    type Image = NativeImage;
    type Publication = PublishedKernel<O>;

    fn image_identity(image: &Self::Image) -> Self::Identity {
        RuntimeIdentity::for_image(image)
    }

    fn publication_identity(publication: &Self::Publication) -> Self::Identity {
        publication.identity()
    }

    fn accounting(publication: &Self::Publication) -> PublicationAccounting {
        publication.accounting()
    }

    fn has_unique_mapping_ownership(publication: &Self::Publication) -> bool {
        publication.has_unique_mapping_ownership()
    }

    fn required_bookkeeping_bytes(limits: CacheLimits) -> Result<u64, CacheCreateError> {
        limits.required_bookkeeping_bytes()
    }
}

impl CacheContract for SelectedEndRegisterContractV2 {
    type Identity = SelectedEndRegisterCompileIdentityV2;
    type Image = SelectedEndRegisterCompileRequestV2;
    type Publication = CachedSelectedEndRegisterPublicationV2;

    fn image_identity(image: &Self::Image) -> Self::Identity {
        image.identity
    }

    fn publication_identity(publication: &Self::Publication) -> Self::Identity {
        publication.compile_identity
    }

    fn accounting(publication: &Self::Publication) -> PublicationAccounting {
        publication.kernel.accounting()
    }

    fn has_unique_mapping_ownership(publication: &Self::Publication) -> bool {
        publication.kernel.has_unique_mapping_ownership()
    }

    fn required_bookkeeping_bytes(limits: CacheLimits) -> Result<u64, CacheCreateError> {
        limits.required_selected_end_register_bookkeeping_bytes_v2()
    }
}

impl<C: CacheContract> Clone for CacheCore<C> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<C: CacheContract> Clone for CacheLeaseCore<C> {
    fn clone(&self) -> Self {
        Self {
            tracked: Arc::clone(&self.tracked),
        }
    }
}

impl<C: CacheContract> TrackedKernel<C> {
    #[inline]
    fn publication(&self) -> &C::Publication {
        self.publication
            .as_ref()
            .expect("tracked publication remains present until final owner drop")
    }
}

impl<O: RuntimeOperation> Clone for KernelCache<O> {
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
        }
    }
}

impl<O: RuntimeOperation> fmt::Debug for KernelCache<O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KernelCache")
            .field("policy", &self.policy_identity())
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl<O: RuntimeOperation> Clone for KernelLease<O> {
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
        }
    }
}

impl<O: RuntimeOperation> fmt::Debug for KernelLease<O> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KernelLease")
            .field("kernel", self.core.tracked.publication())
            .finish()
    }
}

impl<O: RuntimeOperation> KernelLease<O> {
    /// Execute within a checked half-open byte window.
    pub fn search(&self, haystack: &[u8], window: SearchWindow) -> Result<O::Output, CallError> {
        self.core.tracked.publication().search(haystack, window)
    }

    /// Exact page/code/data accounting charged for this mapping.
    #[must_use]
    pub fn accounting(&self) -> PublicationAccounting {
        self.core.tracked.publication().accounting()
    }

    /// Complete authenticated native image identity.
    #[must_use]
    pub fn identity(&self) -> RuntimeIdentity {
        self.core.tracked.publication().identity()
    }
}

impl Clone for SelectedEndRegisterCacheV2 {
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
        }
    }
}

impl fmt::Debug for SelectedEndRegisterCacheV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedEndRegisterCacheV2")
            .field("policy", &self.policy_identity())
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl Clone for SelectedEndRegisterLeaseV2 {
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
        }
    }
}

impl fmt::Debug for SelectedEndRegisterLeaseV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let publication = self.core.tracked.publication();
        formatter
            .debug_struct("SelectedEndRegisterLeaseV2")
            .field("kernel", &publication.kernel)
            .field("compile_identity", &publication.compile_identity)
            .finish()
    }
}

impl SelectedEndRegisterLeaseV2 {
    /// Borrow the immutable publication retained by this lease.
    ///
    /// Current-thread invocation sessions borrow this object directly. No
    /// cache lookup, mutex, or reference-count update occurs in a search.
    #[must_use]
    pub fn kernel(&self) -> &PublishedSelectedEndRegisterV2 {
        &self.core.tracked.publication().kernel
    }

    /// Exact page/code/data accounting charged for this mapping.
    #[must_use]
    pub fn accounting(&self) -> PublicationAccounting {
        self.core.tracked.publication().kernel.accounting()
    }

    /// Complete authenticated ABI2 artifact identity.
    #[must_use]
    pub fn artifact_identity(&self) -> SelectedEndRegisterArtifactIdentityV2 {
        self.core.tracked.publication().kernel.artifact_identity()
    }

    /// Pre-emission request identity used for this cache lookup.
    #[must_use]
    pub fn compile_identity(&self) -> SelectedEndRegisterCompileIdentityV2 {
        self.core.tracked.publication().compile_identity
    }

    /// Exact validated Kernel IR identity emitted on the miss path.
    #[must_use]
    pub fn source_identity(&self) -> KernelIrIdentity {
        self.core.tracked.publication().source_identity
    }

    /// Complete target stamp authenticated before publication.
    #[must_use]
    pub fn target(&self) -> TargetSpec {
        self.core.tracked.publication().target
    }

    /// Exact emitted backend version.
    #[must_use]
    pub fn backend_version(&self) -> BackendVersion {
        self.core
            .tracked
            .publication()
            .kernel
            .backend()
            .backend_version()
    }

    /// Exact bounded emission statistics retained across cache hits.
    #[must_use]
    pub fn image_stats(&self) -> ImageStats {
        self.core.tracked.publication().image_stats
    }
}

impl<O: RuntimeOperation> KernelCache<O> {
    /// Construct a cache and reserve its bounded entry/flight/registry arrays.
    pub fn new(
        limits: CacheLimits,
        publication_limits: PublicationLimits,
    ) -> Result<Self, CacheCreateError> {
        CacheCore::new(limits, publication_limits).map(|core| Self { core })
    }

    /// Stable cache and per-publication policy identity.
    #[must_use]
    pub fn policy_identity(&self) -> CachePolicyIdentity<O> {
        CachePolicyIdentity::new(
            self.core.inner.cache_limits,
            self.core.inner.publication_limits,
        )
    }

    /// Publish on a miss using the cache's fixed runtime publication policy.
    pub fn get_or_publish(&self, image: &NativeImage) -> Result<KernelLease<O>, CacheError> {
        self.get_or_build(image, |source, limits| publish::<O>(source, limits))
    }

    pub(crate) fn get_or_build<F>(
        &self,
        image: &NativeImage,
        build: F,
    ) -> Result<KernelLease<O>, CacheError>
    where
        F: FnOnce(&NativeImage, PublicationLimits) -> Result<PublishedKernel<O>, PublishError>,
    {
        self.core
            .get_or_build(image, |source, limits| {
                build(source, limits).map_err(CacheError::Publish)
            })
            .map(|core| KernelLease { core })
    }

    /// Exact diagnostic counters and charged usage under one state lock.
    #[must_use]
    pub fn snapshot(&self) -> CacheSnapshot {
        self.core.snapshot()
    }

    #[cfg(test)]
    pub(crate) fn poison_state_lock_for_test(&self) {
        self.core.poison_state_lock_for_test();
    }

    #[cfg(test)]
    pub(crate) fn equalize_recency_for_test(&self) {
        self.core.equalize_recency_for_test();
    }

    #[cfg(test)]
    pub(crate) fn resident_identities_for_test(&self) -> Vec<RuntimeIdentity> {
        self.core.resident_identities_for_test()
    }
}

impl SelectedEndRegisterCacheV2 {
    /// Construct an ABI2 cache and reserve all bounded bookkeeping arrays.
    pub fn new(
        limits: CacheLimits,
        publication_limits: PublicationLimits,
    ) -> Result<Self, CacheCreateError> {
        CacheCore::new(limits, publication_limits).map(|core| Self { core })
    }

    /// Stable nominal ABI2 cache and publication policy identity.
    #[must_use]
    pub fn policy_identity(&self) -> SelectedEndRegisterCachePolicyIdentityV2 {
        SelectedEndRegisterCachePolicyIdentityV2::new(
            self.core.inner.cache_limits,
            self.core.inner.publication_limits,
        )
    }

    /// Compute the exact pre-emission identity used by this cache.
    pub fn compile_identity(
        literal: &[u8],
        anchors: AnchorFlags,
        backend: SelectedEndRegisterBackendV2,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
    ) -> Result<SelectedEndRegisterCompileIdentityV2, SelectedEndRegisterCacheErrorV2> {
        SelectedEndRegisterCompileRequestV2::new(
            literal,
            anchors,
            backend,
            validation_limits,
            emission_limits,
        )
        .map(|request| request.identity)
    }

    /// Look up or single-flight the complete exact-literal ABI2 compiler.
    ///
    /// The lookup key is computed before Kernel IR construction. A hit skips
    /// validation, emission, emitter-final whole-image audit, runtime audit,
    /// mapping, copy, and W^X publication. The returned lease retains the
    /// publication and exact compile receipt without retaining the image.
    pub fn get_or_compile_exact_literal(
        &self,
        literal: &[u8],
        anchors: AnchorFlags,
        backend: SelectedEndRegisterBackendV2,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
    ) -> Result<SelectedEndRegisterLeaseV2, SelectedEndRegisterCacheErrorV2> {
        let request = SelectedEndRegisterCompileRequestV2::new(
            literal,
            anchors,
            backend,
            validation_limits,
            emission_limits,
        )?;
        self.core
            .get_or_build(&request, |request, publication_limits| {
                compile_selected_end_register_request_v2(request, publication_limits)
            })
            .map(|core| SelectedEndRegisterLeaseV2 { core })
    }

    #[cfg(test)]
    pub(crate) fn get_or_compile_substitute_for_test(
        &self,
        requested_literal: &[u8],
        substitute_literal: &[u8],
        backend: SelectedEndRegisterBackendV2,
        validation_limits: ValidateLimits,
        emission_limits: EmitLimits,
    ) -> Result<SelectedEndRegisterLeaseV2, SelectedEndRegisterCacheErrorV2> {
        let request = SelectedEndRegisterCompileRequestV2::new(
            requested_literal,
            AnchorFlags::default(),
            backend,
            validation_limits,
            emission_limits,
        )?;
        let substitute = SelectedEndRegisterCompileRequestV2::new(
            substitute_literal,
            AnchorFlags::default(),
            backend,
            validation_limits,
            emission_limits,
        )?;
        self.core
            .get_or_build(&request, |_, limits| {
                compile_selected_end_register_request_v2(&substitute, limits)
            })
            .map(|core| SelectedEndRegisterLeaseV2 { core })
    }

    #[cfg(test)]
    pub(crate) fn get_or_compile_with_hook_for_test(
        &self,
        literal: &[u8],
        backend: SelectedEndRegisterBackendV2,
        before_compile: impl FnOnce(),
    ) -> Result<SelectedEndRegisterLeaseV2, SelectedEndRegisterCacheErrorV2> {
        let request = SelectedEndRegisterCompileRequestV2::new(
            literal,
            AnchorFlags::default(),
            backend,
            ValidateLimits::default(),
            EmitLimits::default(),
        )?;
        self.core
            .get_or_build(&request, |request, limits| {
                before_compile();
                compile_selected_end_register_request_v2(request, limits)
            })
            .map(|core| SelectedEndRegisterLeaseV2 { core })
    }

    /// Exact diagnostic counters and charged usage under one state lock.
    #[must_use]
    pub fn snapshot(&self) -> CacheSnapshot {
        self.core.snapshot()
    }
}

fn compile_selected_end_register_request_v2(
    request: &SelectedEndRegisterCompileRequestV2,
    publication_limits: PublicationLimits,
) -> Result<CachedSelectedEndRegisterPublicationV2, SelectedEndRegisterCacheErrorV2> {
    let program = build_exact_literal::<SelectedEnd>(
        request.literal(),
        request.anchors,
        request.validation_limits,
    )
    .map_err(CacheError::KernelIr)?;
    let source_identity = program.cache_identity();
    let image = emit_selected_end_register_v2(&program, request.backend, request.emission_limits)
        .map_err(CacheError::Emit)?;
    let target =
        selected_end_register_target_v2(request.backend, request.anchors, request.literal_bytes);
    if image.source_identity() != source_identity
        || image.rodata() != request.literal()
        || image.literal_bytes() != request.literal_bytes
        || image.anchors() != request.anchors
        || image.backend() != request.backend
        || image.backend_version() != request.backend.backend_version()
        || image.target() != target
        || image.output() != OutputKind::SelectedEnd
    {
        return Err(CacheError::BuilderContractMismatch {
            identity: request.identity,
        });
    }
    let artifact_identity = image.artifact_identity();
    let image_stats = image.stats();
    let kernel = publish_selected_end_register_v2(&image, publication_limits)
        .map_err(CacheError::Publish)?;
    if kernel.artifact_identity() != artifact_identity
        || kernel.backend() != request.backend
        || kernel.literal_bytes() != request.literal_bytes
    {
        return Err(CacheError::BuilderContractMismatch {
            identity: request.identity,
        });
    }
    Ok(CachedSelectedEndRegisterPublicationV2 {
        kernel,
        compile_identity: request.identity,
        source_identity,
        target,
        image_stats,
    })
}

impl<C: CacheContract> CacheCore<C> {
    /// Construct a cache and reserve its bounded entry/flight/registry arrays.
    fn new(
        limits: CacheLimits,
        publication_limits: PublicationLimits,
    ) -> Result<Self, CacheCreateError> {
        let bookkeeping = C::required_bookkeeping_bytes(limits)?;
        if bookkeeping > limits.max_bookkeeping_bytes {
            return Err(CacheCreateError::ResourceLimit {
                resource: CacheResource::BookkeepingBytes,
                limit: limits.max_bookkeeping_bytes,
                required: bookkeeping,
            });
        }
        let entry_capacity = capacity(limits.max_entries, CacheResource::Entries)?;
        let flight_capacity = capacity(limits.max_in_flight_builds, CacheResource::InFlightBuilds)?;
        let live_capacity = capacity(limits.max_live_mappings, CacheResource::LiveMappings)?;
        let mut entries = Vec::new();
        entries.try_reserve_exact(entry_capacity).map_err(|_| {
            CacheCreateError::AllocationFailed {
                resource: CacheResource::Entries,
                entries: limits.max_entries,
            }
        })?;
        let mut flights = Vec::new();
        flights.try_reserve_exact(flight_capacity).map_err(|_| {
            CacheCreateError::AllocationFailed {
                resource: CacheResource::InFlightBuilds,
                entries: limits.max_in_flight_builds,
            }
        })?;
        let mut live = Vec::new();
        live.try_reserve_exact(live_capacity)
            .map_err(|_| CacheCreateError::AllocationFailed {
                resource: CacheResource::LiveMappings,
                entries: limits.max_live_mappings,
            })?;
        let current = CacheUsage {
            bookkeeping_bytes: bookkeeping,
            ..CacheUsage::default()
        };
        Ok(Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    entries,
                    flights,
                    live,
                    totals: CacheTotals::default(),
                    current,
                    peak: current,
                    clock: 0,
                    generation: 0,
                    accounting_consistent: true,
                }),
                wake: Condvar::new(),
                cache_limits: limits,
                publication_limits,
            }),
        })
    }

    /// Look up or single-flight one crate-owned typed publisher.
    ///
    /// The closure runs without a cache lock. Its result is admitted only when
    /// the contract-specific publication identity matches the request and its
    /// exact accounting obeys both the publication and aggregate cache
    /// policies. This seam is private so callers cannot share a published
    /// mapping before the cache has accepted and charged its linear ownership
    /// transfer.
    #[allow(
        clippy::too_many_lines,
        reason = "the full lookup/wait/build transition is kept together so every exit visibly cleans its flight"
    )]
    fn get_or_build<F>(
        &self,
        image: &C::Image,
        build: F,
    ) -> Result<CacheLeaseCore<C>, ContractCacheError<C>>
    where
        F: FnOnce(&C::Image, PublicationLimits) -> Result<C::Publication, ContractCacheError<C>>,
    {
        let identity = C::image_identity(image);
        let mut build = Some(build);
        let mut classified = false;
        let generation = loop {
            let mut retired = None;
            let mut state = self.lock();
            match state.lookup(identity)? {
                Lookup::Hit(tracked) => {
                    if !classified {
                        bump(&mut state.totals.hits)?;
                    }
                    drop(state);
                    return Ok(CacheLeaseCore { tracked });
                }
                Lookup::Retiring => {
                    if !classified {
                        bump(&mut state.totals.misses)?;
                        classified = true;
                    }
                    bump(&mut state.totals.wait_events)?;
                    state.current.waiters =
                        checked_add(state.current.waiters, 1, CacheResource::Counter)?;
                    state.update_peak();
                    state = self.wait(state);
                    state.current.waiters = checked_sub_usage(
                        state.current.waiters,
                        1,
                        &mut state.accounting_consistent,
                    );
                    drop(state);
                    continue;
                }
                Lookup::Miss => {}
            }
            if !classified {
                bump(&mut state.totals.misses)?;
                classified = true;
            }
            if let Ok(index) = flight_index(&state.flights, identity) {
                if state.flights[index].owner == thread::current().id() {
                    bump(&mut state.totals.refusals)?;
                    return Err(CacheError::ReentrantBuild { identity });
                }
                bump(&mut state.totals.wait_events)?;
                state.current.waiters =
                    checked_add(state.current.waiters, 1, CacheResource::Counter)?;
                state.update_peak();
                state = self.wait(state);
                state.current.waiters =
                    checked_sub_usage(state.current.waiters, 1, &mut state.accounting_consistent);
                drop(state);
                continue;
            }
            if state.current.in_flight_builds >= self.inner.cache_limits.max_in_flight_builds {
                let current = state.current.in_flight_builds;
                return Err(state.refusal(
                    CacheResource::InFlightBuilds,
                    self.inner.cache_limits.max_in_flight_builds,
                    current,
                    1,
                )?);
            }
            let occupied = state
                .current
                .entries
                .checked_add(state.current.reserved_entries)
                .ok_or(CacheError::AccountingOverflow {
                    resource: CacheResource::Entries,
                })?;
            if occupied >= self.inner.cache_limits.max_entries {
                if self.inner.cache_limits.max_entries == 0 {
                    return Err(state.refusal(CacheResource::Entries, 0, occupied, 1)?);
                }
                let Some(index) = state.eviction_index(false) else {
                    return Err(state.refusal(
                        CacheResource::Entries,
                        self.inner.cache_limits.max_entries,
                        occupied,
                        1,
                    )?);
                };
                retired = Some(state.remove_entry(index)?);
            }
            let next_generation =
                state
                    .generation
                    .checked_add(1)
                    .ok_or(CacheError::AccountingOverflow {
                        resource: CacheResource::Counter,
                    })?;
            bump(&mut state.totals.builds_started)?;
            let flight = Flight {
                identity,
                generation: next_generation,
                owner: thread::current().id(),
            };
            let index = state
                .flights
                .binary_search_by(|candidate| compare(candidate.identity, identity))
                .unwrap_or_else(core::convert::identity);
            state.flights.insert(index, flight);
            state.generation = next_generation;
            state.current.in_flight_builds = checked_add(
                state.current.in_flight_builds,
                1,
                CacheResource::InFlightBuilds,
            )?;
            state.current.reserved_entries =
                checked_add(state.current.reserved_entries, 1, CacheResource::Entries)?;
            state.update_peak();
            drop(state);
            drop(retired);
            break next_generation;
        };

        let builder = build.take().ok_or(CacheError::AccountingOverflow {
            resource: CacheResource::Counter,
        })?;
        let build_outcome = catch_unwind(AssertUnwindSafe(|| {
            builder(image, self.inner.publication_limits)
        }));
        let kernel = match build_outcome {
            Ok(Ok(kernel)) => kernel,
            Ok(Err(error)) => {
                self.finish_failed(identity, generation, Failure::Error)?;
                return Err(error);
            }
            Err(_) => {
                self.finish_failed(identity, generation, Failure::Panic)?;
                return Err(CacheError::BuildPanicked);
            }
        };
        if C::publication_identity(&kernel) != identity {
            let actual = C::publication_identity(&kernel);
            drop(kernel);
            self.finish_failed(identity, generation, Failure::Error)?;
            return Err(CacheError::BuilderIdentityMismatch {
                expected: identity,
                actual,
            });
        }
        if !C::has_unique_mapping_ownership(&kernel) {
            drop(kernel);
            self.finish_failed(identity, generation, Failure::Error)?;
            return Err(CacheError::BuilderSharedMapping { identity });
        }
        if let Err(error) = enforce_publication_accounting::<C::Identity>(
            C::accounting(&kernel),
            self.inner.publication_limits,
        ) {
            drop(kernel);
            self.finish_failed(identity, generation, Failure::Error)?;
            return Err(error);
        }
        self.admit(identity, generation, kernel)
    }

    /// Exact diagnostic counters and charged usage under one state lock.
    #[must_use]
    fn snapshot(&self) -> CacheSnapshot {
        let state = self.lock();
        CacheSnapshot {
            totals: state.totals,
            current: state.current,
            peak: state.peak,
            accounting_consistent: state.accounting_consistent,
        }
    }

    #[cfg(test)]
    fn poison_state_lock_for_test(&self) {
        let _guard = self
            .inner
            .state
            .lock()
            .expect("initially healthy test lock");
        panic!("intentional state poison");
    }

    #[cfg(test)]
    fn equalize_recency_for_test(&self) {
        let mut state = self.lock();
        for entry in &mut state.entries {
            entry.last_used = 1;
        }
    }

    #[cfg(test)]
    fn resident_identities_for_test(&self) -> Vec<C::Identity> {
        self.lock()
            .entries
            .iter()
            .map(|entry| entry.identity)
            .collect()
    }

    fn admit(
        &self,
        identity: C::Identity,
        generation: u128,
        kernel: C::Publication,
    ) -> Result<CacheLeaseCore<C>, ContractCacheError<C>> {
        let accounting = C::accounting(&kernel);
        let tracked = Arc::new(TrackedKernel {
            publication: Some(kernel),
            owner: Arc::downgrade(&self.inner),
            token: generation,
            accounted: AtomicBool::new(false),
        });
        loop {
            let mut state = self.lock();
            state.require_flight(identity, generation)?;
            if let Some(failure) = state.aggregate_failure(accounting, self.inner.cache_limits)? {
                if let Some(index) = state.eviction_index(true) {
                    let retired = state.remove_entry(index)?;
                    drop(state);
                    drop(retired);
                    continue;
                }
                let error = state.refusal(
                    failure.resource,
                    failure.limit,
                    failure.current,
                    failure.required,
                )?;
                drop(state);
                drop(tracked);
                let mut state = self.lock();
                state.remove_flight(identity, generation)?;
                drop(state);
                self.inner.wake.notify_all();
                return Err(error);
            }
            let use_sequence = state.next_clock()?;
            bump(&mut state.totals.builds_succeeded)?;
            state.add_live(accounting)?;
            tracked.accounted.store(true, Ordering::Release);
            let live_index = state
                .live
                .binary_search_by(|record| compare(record.identity, identity))
                .unwrap_or_else(core::convert::identity);
            state.live.insert(
                live_index,
                LiveRecord {
                    identity,
                    token: generation,
                    tracked: Arc::downgrade(&tracked),
                },
            );
            let entry_index = state
                .entries
                .binary_search_by(|entry| compare(entry.identity, identity))
                .unwrap_or_else(core::convert::identity);
            state.entries.insert(
                entry_index,
                Entry {
                    identity,
                    last_used: use_sequence,
                    tracked: Arc::clone(&tracked),
                },
            );
            state.current.entries = checked_add(state.current.entries, 1, CacheResource::Entries)?;
            state.remove_flight(identity, generation)?;
            state.update_peak();
            drop(state);
            self.inner.wake.notify_all();
            return Ok(CacheLeaseCore { tracked });
        }
    }

    fn finish_failed(
        &self,
        identity: C::Identity,
        generation: u128,
        failure: Failure,
    ) -> Result<(), ContractCacheError<C>> {
        let mut state = self.lock();
        match failure {
            Failure::Error => bump(&mut state.totals.build_failures)?,
            Failure::Panic => bump(&mut state.totals.build_panics)?,
        }
        state.remove_flight(identity, generation)?;
        drop(state);
        self.inner.wake.notify_all();
        Ok(())
    }

    fn lock(&self) -> MutexGuard<'_, State<C>> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn wait<'a>(&self, state: MutexGuard<'a, State<C>>) -> MutexGuard<'a, State<C>> {
        self.inner
            .wake
            .wait(state)
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl<C: CacheContract> State<C> {
    fn lookup(&mut self, identity: C::Identity) -> Result<Lookup<C>, ContractCacheError<C>> {
        if let Ok(index) = entry_index(&self.entries, identity) {
            let sequence = self.next_clock()?;
            self.entries[index].last_used = sequence;
            return Ok(Lookup::Hit(Arc::clone(&self.entries[index].tracked)));
        }
        if let Ok(index) = live_index(&self.live, identity) {
            return Ok(match self.live[index].tracked.upgrade() {
                Some(tracked) => Lookup::Hit(tracked),
                None => Lookup::Retiring,
            });
        }
        Ok(Lookup::Miss)
    }

    fn next_clock(&mut self) -> Result<u128, ContractCacheError<C>> {
        let next = self
            .clock
            .checked_add(1)
            .ok_or(CacheError::AccountingOverflow {
                resource: CacheResource::Counter,
            })?;
        self.clock = next;
        Ok(next)
    }

    fn eviction_index(&self, cache_only: bool) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| !cache_only || Arc::strong_count(&entry.tracked) == 1)
            .min_by(|(_, left), (_, right)| {
                left.last_used
                    .cmp(&right.last_used)
                    .then_with(|| compare(left.identity, right.identity))
            })
            .map(|(index, _)| index)
    }

    fn remove_entry(
        &mut self,
        index: usize,
    ) -> Result<Arc<TrackedKernel<C>>, ContractCacheError<C>> {
        let entry = self.entries.remove(index);
        self.current.entries =
            checked_sub_usage(self.current.entries, 1, &mut self.accounting_consistent);
        bump(&mut self.totals.evictions)?;
        Ok(entry.tracked)
    }

    fn require_flight(
        &self,
        identity: C::Identity,
        generation: u128,
    ) -> Result<(), ContractCacheError<C>> {
        let index =
            flight_index(&self.flights, identity).map_err(|_| CacheError::AccountingOverflow {
                resource: CacheResource::InFlightBuilds,
            })?;
        if self.flights[index].generation != generation {
            return Err(CacheError::AccountingOverflow {
                resource: CacheResource::InFlightBuilds,
            });
        }
        Ok(())
    }

    fn remove_flight(
        &mut self,
        identity: C::Identity,
        generation: u128,
    ) -> Result<(), ContractCacheError<C>> {
        self.require_flight(identity, generation)?;
        let index =
            flight_index(&self.flights, identity).map_err(|_| CacheError::AccountingOverflow {
                resource: CacheResource::InFlightBuilds,
            })?;
        self.flights.remove(index);
        self.current.in_flight_builds = checked_sub_usage(
            self.current.in_flight_builds,
            1,
            &mut self.accounting_consistent,
        );
        self.current.reserved_entries = checked_sub_usage(
            self.current.reserved_entries,
            1,
            &mut self.accounting_consistent,
        );
        Ok(())
    }

    fn aggregate_failure(
        &self,
        accounting: PublicationAccounting,
        limits: CacheLimits,
    ) -> Result<Option<LimitFailure>, ContractCacheError<C>> {
        for (resource, current, required, limit) in [
            (
                CacheResource::LiveMappings,
                self.current.live_mappings,
                1,
                limits.max_live_mappings,
            ),
            (
                CacheResource::MappedBytes,
                self.current.mapped_bytes,
                to_u64(accounting.total_mapped_bytes, CacheResource::MappedBytes)?,
                limits.max_mapped_bytes,
            ),
            (
                CacheResource::CodeBytes,
                self.current.code_bytes,
                to_u64(accounting.code_bytes, CacheResource::CodeBytes)?,
                limits.max_code_bytes,
            ),
            (
                CacheResource::DataBytes,
                self.current.data_bytes,
                to_u64(accounting.data_bytes, CacheResource::DataBytes)?,
                limits.max_data_bytes,
            ),
        ] {
            let total = current
                .checked_add(required)
                .ok_or(CacheError::AccountingOverflow { resource })?;
            if total > limit {
                return Ok(Some(LimitFailure {
                    resource,
                    limit,
                    current,
                    required,
                }));
            }
        }
        Ok(None)
    }

    fn add_live(&mut self, accounting: PublicationAccounting) -> Result<(), ContractCacheError<C>> {
        self.current.live_mappings =
            checked_add(self.current.live_mappings, 1, CacheResource::LiveMappings)?;
        self.current.mapped_bytes = checked_add(
            self.current.mapped_bytes,
            to_u64(accounting.total_mapped_bytes, CacheResource::MappedBytes)?,
            CacheResource::MappedBytes,
        )?;
        self.current.code_bytes = checked_add(
            self.current.code_bytes,
            to_u64(accounting.code_bytes, CacheResource::CodeBytes)?,
            CacheResource::CodeBytes,
        )?;
        self.current.data_bytes = checked_add(
            self.current.data_bytes,
            to_u64(accounting.data_bytes, CacheResource::DataBytes)?,
            CacheResource::DataBytes,
        )?;
        Ok(())
    }

    fn remove_live(
        &mut self,
        identity: C::Identity,
        token: u128,
        accounting: PublicationAccounting,
    ) {
        if let Some(index) = self
            .live
            .iter()
            .position(|record| record.identity == identity && record.token == token)
        {
            self.live.remove(index);
        } else {
            self.accounting_consistent = false;
        }
        subtract(
            &mut self.current.live_mappings,
            1,
            &mut self.accounting_consistent,
        );
        subtract(
            &mut self.current.mapped_bytes,
            u64::try_from(accounting.total_mapped_bytes).unwrap_or(u64::MAX),
            &mut self.accounting_consistent,
        );
        subtract(
            &mut self.current.code_bytes,
            u64::try_from(accounting.code_bytes).unwrap_or(u64::MAX),
            &mut self.accounting_consistent,
        );
        subtract(
            &mut self.current.data_bytes,
            u64::try_from(accounting.data_bytes).unwrap_or(u64::MAX),
            &mut self.accounting_consistent,
        );
    }

    fn refusal(
        &mut self,
        resource: CacheResource,
        limit: u64,
        current: u64,
        required: u64,
    ) -> Result<ContractCacheError<C>, ContractCacheError<C>> {
        bump(&mut self.totals.refusals)?;
        Ok(CacheError::Refused {
            resource,
            limit,
            current,
            required,
        })
    }

    fn update_peak(&mut self) {
        self.peak.entries = self.peak.entries.max(self.current.entries);
        self.peak.reserved_entries = self
            .peak
            .reserved_entries
            .max(self.current.reserved_entries);
        self.peak.in_flight_builds = self
            .peak
            .in_flight_builds
            .max(self.current.in_flight_builds);
        self.peak.waiters = self.peak.waiters.max(self.current.waiters);
        self.peak.live_mappings = self.peak.live_mappings.max(self.current.live_mappings);
        self.peak.mapped_bytes = self.peak.mapped_bytes.max(self.current.mapped_bytes);
        self.peak.code_bytes = self.peak.code_bytes.max(self.current.code_bytes);
        self.peak.data_bytes = self.peak.data_bytes.max(self.current.data_bytes);
        self.peak.bookkeeping_bytes = self
            .peak
            .bookkeeping_bytes
            .max(self.current.bookkeeping_bytes);
    }
}

impl<C: CacheContract> Drop for TrackedKernel<C> {
    fn drop(&mut self) {
        if !self.accounted.load(Ordering::Acquire) {
            return;
        }
        let identity = C::publication_identity(self.publication());
        let accounting = C::accounting(self.publication());
        #[cfg(test)]
        run_drop_hook(identity.as_cache_bytes());
        let owner = self.owner.upgrade();
        let publication = self
            .publication
            .take()
            .expect("accounted tracked publication is present at final drop");
        drop(publication);
        if let Some(owner) = owner {
            {
                let mut state = owner.state.lock().unwrap_or_else(PoisonError::into_inner);
                state.remove_live(identity, self.token, accounting);
            }
            owner.wake.notify_all();
            drop(owner);
        }
        // The executable mapping is gone before its live record and exact
        // aggregate charge are released or any waiter is awakened.
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Error,
    Panic,
}

#[derive(Clone, Copy)]
struct LimitFailure {
    resource: CacheResource,
    limit: u64,
    current: u64,
    required: u64,
}

#[cfg(test)]
struct DropHook {
    identity: [u8; 32],
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[cfg(test)]
static DROP_HOOK: Mutex<Option<DropHook>> = Mutex::new(None);

#[cfg(test)]
pub(crate) fn install_drop_hook(
    identity: RuntimeIdentity,
) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
    let entered = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    let mut hook = DROP_HOOK.lock().unwrap_or_else(PoisonError::into_inner);
    assert!(hook.is_none(), "only one serialized drop hook is supported");
    *hook = Some(DropHook {
        identity: *identity.as_bytes(),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    });
    (entered, release)
}

#[cfg(test)]
pub(crate) fn bookkeeping_structural_sizes_for_test<O: RuntimeOperation>()
-> (usize, usize, usize, usize) {
    let arc_header = core::mem::size_of::<usize>()
        .checked_mul(2)
        .expect("two pointer-sized Arc counters");
    (
        core::mem::size_of::<Inner<RuntimeKernelContract<O>>>()
            .checked_add(arc_header)
            .expect("bounded inner size"),
        core::mem::size_of::<Entry<RuntimeKernelContract<O>>>(),
        core::mem::size_of::<Flight<RuntimeIdentity>>(),
        core::mem::size_of::<LiveRecord<RuntimeKernelContract<O>>>()
            .checked_add(core::mem::size_of::<TrackedKernel<RuntimeKernelContract<O>>>())
            .and_then(|bytes| bytes.checked_add(arc_header))
            .expect("bounded live structural size"),
    )
}

#[cfg(test)]
pub(crate) fn selected_end_bookkeeping_structural_sizes_for_test() -> (usize, usize, usize, usize) {
    let arc_header = core::mem::size_of::<usize>()
        .checked_mul(2)
        .expect("two pointer-sized Arc counters");
    (
        core::mem::size_of::<Inner<SelectedEndRegisterContractV2>>()
            .checked_add(arc_header)
            .expect("bounded inner size"),
        core::mem::size_of::<Entry<SelectedEndRegisterContractV2>>(),
        core::mem::size_of::<Flight<SelectedEndRegisterCompileIdentityV2>>(),
        core::mem::size_of::<LiveRecord<SelectedEndRegisterContractV2>>()
            .checked_add(core::mem::size_of::<
                TrackedKernel<SelectedEndRegisterContractV2>,
            >())
            .and_then(|bytes| bytes.checked_add(arc_header))
            .expect("bounded live structural size"),
    )
}

#[cfg(test)]
fn run_drop_hook(identity: &[u8; 32]) {
    let barriers = {
        let mut hook = DROP_HOOK.lock().unwrap_or_else(PoisonError::into_inner);
        if hook
            .as_ref()
            .is_some_and(|candidate| &candidate.identity == identity)
        {
            hook.take()
                .map(|candidate| (candidate.entered, candidate.release))
        } else {
            None
        }
    };
    if let Some((entered, release)) = barriers {
        entered.wait();
        release.wait();
    }
}

fn enforce_publication_accounting<I>(
    accounting: PublicationAccounting,
    limits: PublicationLimits,
) -> Result<(), CacheError<I>> {
    for (resource, required, limit) in [
        (
            CacheResource::CodeBytes,
            to_u64(accounting.code_bytes, CacheResource::CodeBytes)?,
            limits.max_code_bytes,
        ),
        (
            CacheResource::DataBytes,
            to_u64(accounting.data_bytes, CacheResource::DataBytes)?,
            limits.max_data_bytes,
        ),
        (
            CacheResource::PayloadBytes,
            to_u64(accounting.payload_mapped_bytes, CacheResource::PayloadBytes)?,
            limits.max_payload_bytes,
        ),
        (
            CacheResource::MappedBytes,
            to_u64(accounting.total_mapped_bytes, CacheResource::MappedBytes)?,
            limits.max_mapped_bytes,
        ),
        (
            CacheResource::Pages,
            to_u64(accounting.total_pages, CacheResource::Pages)?,
            limits.max_pages,
        ),
    ] {
        if required > limit {
            return Err(CacheError::BuilderPublicationLimit {
                resource,
                limit,
                required,
            });
        }
    }
    Ok(())
}

fn entry_index<C: CacheContract>(
    entries: &[Entry<C>],
    identity: C::Identity,
) -> Result<usize, usize> {
    entries.binary_search_by(|entry| compare(entry.identity, identity))
}

fn flight_index<I: CacheIdentity>(flights: &[Flight<I>], identity: I) -> Result<usize, usize> {
    flights.binary_search_by(|flight| compare(flight.identity, identity))
}

fn live_index<C: CacheContract>(
    records: &[LiveRecord<C>],
    identity: C::Identity,
) -> Result<usize, usize> {
    records.binary_search_by(|record| compare(record.identity, identity))
}

fn compare<I: CacheIdentity>(left: I, right: I) -> core::cmp::Ordering {
    left.as_cache_bytes().cmp(right.as_cache_bytes())
}

fn capacity(value: u64, resource: CacheResource) -> Result<usize, CacheCreateError> {
    usize::try_from(value).map_err(|_| CacheCreateError::ResourceLimit {
        resource,
        limit: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        required: value,
    })
}

fn to_u64<I>(value: usize, resource: CacheResource) -> Result<u64, CacheError<I>> {
    u64::try_from(value).map_err(|_| CacheError::AccountingOverflow { resource })
}

fn bump<I>(counter: &mut u128) -> Result<(), CacheError<I>> {
    *counter = counter
        .checked_add(1)
        .ok_or(CacheError::AccountingOverflow {
            resource: CacheResource::Counter,
        })?;
    Ok(())
}

fn checked_add<I>(left: u64, right: u64, resource: CacheResource) -> Result<u64, CacheError<I>> {
    left.checked_add(right)
        .ok_or(CacheError::AccountingOverflow { resource })
}

fn checked_sub_usage(current: u64, amount: u64, consistent: &mut bool) -> u64 {
    if let Some(value) = current.checked_sub(amount) {
        value
    } else {
        *consistent = false;
        0
    }
}

fn subtract(current: &mut u64, amount: u64, consistent: &mut bool) {
    *current = checked_sub_usage(*current, amount, consistent);
}
