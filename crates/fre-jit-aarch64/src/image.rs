use core::fmt;

use fre_kernel_ir::{
    AggregateOutput, AggregateProgramIdentity, AnchorFlags, CacheIdentity, OutputKind,
};
use sha2::{Digest, Sha256};

use crate::{ArithmeticSite, EmitError, ResourceKind};

/// Version of the deterministic backend contract and encoding policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendVersion(pub u16);

impl BackendVersion {
    /// Original search templates using `UMAXV`/`UMOV` candidate reduction.
    pub const SEARCH_V1: Self = Self(1);
    /// Search templates using `UMAXP`/`FMOV` and scalar-remainder recovery.
    pub const SEARCH_V2: Self = Self(2);
    /// Search templates with sealed manifests and block-local recovery.
    pub const SEARCH_V3: Self = Self(3);
    /// Search templates with sealed manifests and mask-guided block recovery.
    pub const SEARCH_V4: Self = Self(4);
    /// Mask-guided recovery with a sealed third-byte false-pair filter.
    pub const SEARCH_V5: Self = Self(5);
    /// Exact per-lane recovery from a sealed three-byte candidate mask.
    pub const SEARCH_V6: Self = Self(6);
    /// Exact per-lane recovery with ranked, staged four-column filtering.
    pub const SEARCH_V7: Self = Self(7);
    /// SVE exact-literal screening with exactly sixteen active byte lanes.
    ///
    /// Tag 8 remains reserved for the separately developed Search V8 wire
    /// contract; these opt-in backends do not change [`Self::SEARCH_CURRENT`].
    pub const SEARCH_SVE16_V1: Self = Self(9);
    /// SVE2 exact-literal screening with exactly sixteen active byte lanes.
    pub const SEARCH_SVE2_16_V1: Self = Self(10);
    /// Compatibility name for the original search backend.
    pub const SEARCH_LEGACY: Self = Self::SEARCH_V1;
    /// Current search backend and AOT wire contract.
    pub const SEARCH_CURRENT: Self = Self::SEARCH_V7;
    /// Explicit tag assigned to the unchanged aggregate contract by c4d.
    pub const AGGREGATE_V1: Self = Self(1);
    /// Historical pre-c4d tag for the same aggregate machine-code contract.
    pub const AGGREGATE_HISTORICAL_V2: Self = Self(2);
    /// Experimental fixed-16-lane SVE2 backend for one-byte Count programs.
    ///
    /// This is deliberately not [`Self::AGGREGATE_CURRENT`]. Callers must opt
    /// into its emitter and the runtime must independently admit SVE2.
    pub const AGGREGATE_SVE2_FIXED16_COUNT_EXPERIMENTAL_V1: Self = Self(3);
    /// Current aggregate tag; its AOT wire remains aggregate v1.
    pub const AGGREGATE_CURRENT: Self = Self::AGGREGATE_V1;
    /// Compatibility alias for callers that only handle search images.
    pub const CURRENT: Self = Self::SEARCH_CURRENT;
}

/// `AArch64` target properties included in every cache/AOT identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetSpec {
    pub architecture: u8,
    pub little_endian: bool,
    pub pointer_width: u8,
    pub abi: u8,
    pub features: CpuFeatures,
}

impl TargetSpec {
    /// Generic 64-bit little-endian AAPCS64 with baseline Advanced SIMD.
    pub const AARCH64_AAPCS64: Self = Self {
        architecture: 1,
        little_endian: true,
        pointer_width: 64,
        abi: 1,
        features: CpuFeatures::ASIMD,
    };

    /// AAPCS64 plus the complete feature envelope used by SVE16 search.
    pub const AARCH64_AAPCS64_SVE16: Self = Self {
        features: CpuFeatures::ASIMD_SVE,
        ..Self::AARCH64_AAPCS64
    };

    /// AAPCS64 plus the complete feature envelope used by SVE2-16 search.
    pub const AARCH64_AAPCS64_SVE2_16: Self = Self {
        features: CpuFeatures::ASIMD_SVE2,
        ..Self::AARCH64_AAPCS64
    };
}

/// Required architectural feature bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuFeatures(u64);

impl CpuFeatures {
    pub const NONE: Self = Self(0);
    pub const ASIMD: Self = Self(1);
    pub const SVE: Self = Self(1 << 1);
    pub const SVE2: Self = Self(1 << 2);
    pub const ASIMD_SVE: Self = Self(Self::ASIMD.0 | Self::SVE.0);
    pub const ASIMD_SVE2: Self = Self(Self::ASIMD.0 | Self::SVE.0 | Self::SVE2.0);

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Purpose of a declared code target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LabelKind {
    Entry = 1,
    Loop = 2,
    SlowPath = 3,
    ReturnFound = 4,
    ReturnNone = 5,
    Internal = 6,
}

/// One valid direct-control-flow target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CodeLabel {
    pub offset: u32,
    pub kind: LabelKind,
}

/// Immutable data kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DataSymbolKind {
    Bytes = 1,
    ByteClass = 2,
}

/// One independently bounds-checked rodata object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataSymbol {
    pub ir_data_id: u32,
    pub offset: u32,
    pub length: u32,
    pub alignment: u8,
    pub kind: DataSymbolKind,
}

/// Final section placement required of a publisher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageLayout {
    pub code_alignment: u32,
    pub rodata_alignment: u32,
    /// Rodata begins at this offset from the code base.
    pub rodata_from_code_start: u32,
    pub total_mapped_bytes: u32,
}

/// Typed, already-applied `AArch64` relocation encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelocationKind {
    Branch26 = 1,
    ConditionalBranch19 = 2,
    CompareBranch19 = 3,
    Address21 = 4,
}

/// Relocation destination; raw process addresses are intentionally absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationTarget {
    CodeOffset(u32),
    RodataOffset(u32),
}

/// One non-overlapping four-byte instruction relocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Relocation {
    pub code_offset: u32,
    pub kind: RelocationKind,
    pub target: RelocationTarget,
    pub addend: i32,
    pub resolved_word: u32,
}

/// Exact resource consumption of one emitted image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageStats {
    pub code_bytes: u32,
    pub data_bytes: u32,
    pub relocations: u32,
    pub labels: u32,
    pub emission_work: u64,
    pub scratch_bytes: u64,
    pub vector_instructions: u32,
}

/// Immutable, audited, position-independent code and data image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeImage {
    pub(crate) backend_version: BackendVersion,
    pub(crate) target: TargetSpec,
    pub(crate) output: OutputKind,
    pub(crate) source_identity: CacheIdentity,
    pub(crate) layout: ImageLayout,
    pub(crate) code: Box<[u8]>,
    pub(crate) rodata: Box<[u8]>,
    pub(crate) labels: Box<[CodeLabel]>,
    pub(crate) symbols: Box<[DataSymbol]>,
    pub(crate) relocations: Box<[Relocation]>,
    pub(crate) stats: ImageStats,
    pub(crate) artifact_identity: ArtifactIdentity,
    pub(crate) search: Option<SearchManifest>,
    pub(crate) aggregate: Option<AggregateManifest>,
}

/// Sealed semantic and backend envelope for one search image.
///
/// This is deliberately distinct from instruction-shape inference. The
/// independent auditor authenticates these facts against immutable rodata and
/// the Kernel IR identity before selecting a backend-versioned template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SearchManifest {
    pub(crate) backend_version: BackendVersion,
    pub(crate) shape: SearchShape,
    pub(crate) output: OutputKind,
    pub(crate) anchors: AnchorFlags,
    pub(crate) source_identity: CacheIdentity,
    /// Exact-literal bytes, or suffix bytes for `ClassSuffix`. A backend may
    /// append independently derived, authenticated auxiliary rodata.
    pub(crate) literal_bytes: u32,
    /// Version of the deterministic candidate-selection policy, or zero when
    /// the authenticated shape has no vector candidate selector.
    pub(crate) candidate_policy_version: u16,
    /// Candidate block width selected by that policy.
    pub(crate) candidate_block_width: u16,
    /// Selected primary literal/suffix byte offset.
    pub(crate) primary_offset: u16,
    /// Selected secondary offset, or `u16::MAX` when absent.
    pub(crate) secondary_offset: u16,
    /// Selected third-byte verification offset, or `u16::MAX` when absent.
    pub(crate) verification_offset: u16,
    /// Selected fourth-byte verification offset, or `u16::MAX` when absent.
    pub(crate) quaternary_offset: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum SearchShape {
    ExactLiteral = 1,
    ClassSuffix = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AggregateManifest {
    pub(crate) output: AggregateOutput,
    pub(crate) source_identity: AggregateProgramIdentity,
    pub(crate) literal_bytes: u32,
}

/// Immutable image for the distinct whole-haystack aggregate ABI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAggregateImage(NativeImage);

impl NativeImage {
    #[must_use]
    pub const fn backend_version(&self) -> BackendVersion {
        self.backend_version
    }

    #[must_use]
    pub const fn target(&self) -> TargetSpec {
        self.target
    }

    #[must_use]
    pub const fn output(&self) -> OutputKind {
        self.output
    }

    #[must_use]
    pub const fn source_identity(&self) -> CacheIdentity {
        self.source_identity
    }

    #[must_use]
    pub const fn layout(&self) -> ImageLayout {
        self.layout
    }

    #[must_use]
    pub fn code(&self) -> &[u8] {
        &self.code
    }

    #[must_use]
    pub fn rodata(&self) -> &[u8] {
        &self.rodata
    }

    #[must_use]
    pub fn labels(&self) -> &[CodeLabel] {
        &self.labels
    }

    #[must_use]
    pub fn symbols(&self) -> &[DataSymbol] {
        &self.symbols
    }

    #[must_use]
    pub fn relocations(&self) -> &[Relocation] {
        &self.relocations
    }

    #[must_use]
    pub const fn stats(&self) -> ImageStats {
        self.stats
    }

    /// Precomputed SHA-256 identity of the complete canonical AOT encoding.
    ///
    /// Emission computes and charges this digest once. Access is an O(1),
    /// allocation-free copy and does not serialize or hash the image again.
    #[must_use]
    pub const fn artifact_identity(&self) -> ArtifactIdentity {
        self.artifact_identity
    }

    /// Structural accounting receipt for hot identity access.
    #[must_use]
    pub const fn artifact_identity_receipt(&self) -> ArtifactIdentityReceipt {
        ArtifactIdentityReceipt {
            identity: self.artifact_identity,
            canonical_bytes_hashed: 0,
            scratch_bytes: 0,
            heap_allocations: 0,
        }
    }

    pub(crate) const fn aggregate_manifest(&self) -> Option<AggregateManifest> {
        self.aggregate
    }

    pub(crate) const fn search_manifest(&self) -> Option<SearchManifest> {
        self.search
    }

    pub(crate) fn compute_artifact_identity(&self) -> Result<ArtifactIdentity, EmitError> {
        let mut hasher = Sha256::new();
        encode_aot(self, &mut |bytes| hasher.update(bytes))?;
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Ok(ArtifactIdentity(bytes))
    }

    /// Serialize a deterministic, address-free AOT container.
    pub fn to_aot(&self, limits: AotLimits) -> Result<AotArtifact, EmitError> {
        let required = aot_size(self)?;
        enforce(ResourceKind::AotBytes, required, limits.max_bytes)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(required)
            .map_err(|_| EmitError::AllocationFailed {
                resource: ResourceKind::AotBytes,
            })?;
        encode_aot(self, &mut |chunk| bytes.extend_from_slice(chunk))?;
        debug_assert_eq!(bytes.len(), required);
        Ok(AotArtifact(bytes.into_boxed_slice()))
    }
}

impl NativeAggregateImage {
    pub(crate) fn try_new(inner: NativeImage) -> Result<Self, EmitError> {
        if inner.search.is_some() || inner.aggregate.is_none() {
            return Err(EmitError::InternalInvariant);
        }
        Ok(Self(inner))
    }

    #[cfg(test)]
    pub(crate) fn new(inner: NativeImage) -> Self {
        Self(inner)
    }

    pub(crate) const fn inner(&self) -> &NativeImage {
        &self.0
    }

    #[must_use]
    pub const fn backend_version(&self) -> BackendVersion {
        self.0.backend_version()
    }

    #[must_use]
    pub const fn target(&self) -> TargetSpec {
        self.0.target()
    }

    #[must_use]
    pub const fn output(&self) -> AggregateOutput {
        match self.0.aggregate {
            Some(manifest) => manifest.output,
            None => unreachable!(),
        }
    }

    #[must_use]
    pub const fn source_identity(&self) -> AggregateProgramIdentity {
        match self.0.aggregate {
            Some(manifest) => manifest.source_identity,
            None => unreachable!(),
        }
    }

    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        match self.0.aggregate {
            Some(manifest) => manifest.literal_bytes,
            None => unreachable!(),
        }
    }

    #[must_use]
    pub const fn layout(&self) -> ImageLayout {
        self.0.layout()
    }

    #[must_use]
    pub fn code(&self) -> &[u8] {
        self.0.code()
    }

    #[must_use]
    pub fn rodata(&self) -> &[u8] {
        self.0.rodata()
    }

    #[must_use]
    pub fn labels(&self) -> &[CodeLabel] {
        self.0.labels()
    }

    #[must_use]
    pub fn symbols(&self) -> &[DataSymbol] {
        self.0.symbols()
    }

    #[must_use]
    pub fn relocations(&self) -> &[Relocation] {
        self.0.relocations()
    }

    #[must_use]
    pub const fn stats(&self) -> ImageStats {
        self.0.stats()
    }

    #[must_use]
    pub const fn artifact_identity(&self) -> ArtifactIdentity {
        self.0.artifact_identity()
    }

    #[must_use]
    pub const fn artifact_identity_receipt(&self) -> ArtifactIdentityReceipt {
        self.0.artifact_identity_receipt()
    }

    /// Serialize the distinct aggregate image contract.
    pub fn to_aot(&self, limits: AotLimits) -> Result<AotArtifact, EmitError> {
        self.0.to_aot(limits)
    }
}

/// AOT container size limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotLimits {
    pub max_bytes: u64,
}

impl Default for AotLimits {
    fn default() -> Self {
        Self { max_bytes: 4 << 20 }
    }
}

/// Deterministic, endian-stable, address-free AOT bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AotArtifact(Box<[u8]>);

impl AotArtifact {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// SHA-256 over the complete address-free image and manifest.
    #[must_use]
    pub fn identity(&self) -> ArtifactIdentity {
        let digest = Sha256::digest(&self.0);
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        ArtifactIdentity(bytes)
    }
}

/// Stable content identity of finalized AOT bytes, including relocations.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ArtifactIdentity([u8; 32]);

impl ArtifactIdentity {
    pub(crate) const ZERO: Self = Self([0; 32]);

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact work performed when reading a precomputed image identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactIdentityReceipt {
    pub identity: ArtifactIdentity,
    pub canonical_bytes_hashed: u64,
    pub scratch_bytes: u64,
    pub heap_allocations: u64,
}

impl fmt::Debug for ArtifactIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ArtifactIdentity({self})")
    }
}

impl fmt::Display for ArtifactIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub(crate) fn aot_size(image: &NativeImage) -> Result<usize, EmitError> {
    // Search v3 and later add an independently authenticated, source-bound
    // semantic envelope. V5 and later include the sealed verification offset;
    // V7 and the fixed-lane SVE backends also include the sealed fourth
    // ranked offset.
    // Aggregate serialization retains its separate four-byte extension and
    // does not inherit the search wire contract.
    let manifest_bytes = if image.aggregate.is_some() {
        4
    } else if image.search.is_some() {
        if matches!(
            image.backend_version,
            BackendVersion::SEARCH_V7
                | BackendVersion::SEARCH_SVE16_V1
                | BackendVersion::SEARCH_SVE2_16_V1
        ) {
            54
        } else if matches!(
            image.backend_version,
            BackendVersion::SEARCH_V5 | BackendVersion::SEARCH_V6
        ) {
            52
        } else {
            50
        }
    } else {
        0
    };
    let header = (8_usize + 2 + 6 + 8 + 32 + 16 + 20 + 36)
        .checked_add(manifest_bytes)
        .ok_or(EmitError::ArithmeticOverflow {
            site: ArithmeticSite::AotSize,
        })?;
    header
        .checked_add(image.code.len())
        .and_then(|size| size.checked_add(image.rodata.len()))
        .and_then(|size| size.checked_add(image.labels.len().checked_mul(8)?))
        .and_then(|size| size.checked_add(image.symbols.len().checked_mul(16)?))
        .and_then(|size| size.checked_add(image.relocations.len().checked_mul(20)?))
        .ok_or(EmitError::ArithmeticOverflow {
            site: ArithmeticSite::AotSize,
        })
}

fn enforce(resource: ResourceKind, required: usize, limit: u64) -> Result<(), EmitError> {
    let required = u64::try_from(required).map_err(|_| EmitError::ArithmeticOverflow {
        site: ArithmeticSite::AotSize,
    })?;
    if required > limit {
        return Err(EmitError::ResourceLimit {
            resource,
            limit,
            required,
        });
    }
    Ok(())
}

fn aot_magic(image: &NativeImage) -> Result<&'static [u8; 8], EmitError> {
    if image.aggregate.is_some() {
        Ok(b"FREA64A\x01")
    } else if image.search.is_some() {
        match image.backend_version {
            BackendVersion::SEARCH_V3 => Ok(b"FREA64\0\x03"),
            BackendVersion::SEARCH_V4 => Ok(b"FREA64\0\x04"),
            BackendVersion::SEARCH_V5 => Ok(b"FREA64\0\x05"),
            BackendVersion::SEARCH_V6 => Ok(b"FREA64\0\x06"),
            BackendVersion::SEARCH_V7 => Ok(b"FREA64\0\x07"),
            BackendVersion::SEARCH_SVE16_V1 => Ok(b"FREA64\0\x09"),
            BackendVersion::SEARCH_SVE2_16_V1 => Ok(b"FREA64\0\x0a"),
            _ => Err(EmitError::InternalInvariant),
        }
    } else {
        Ok(b"FREA64\0\x01")
    }
}

fn encode_aot(image: &NativeImage, write: &mut impl FnMut(&[u8])) -> Result<(), EmitError> {
    let aggregate = image.aggregate;
    let search = image.search;
    write(aot_magic(image)?);
    write(&image.backend_version.0.to_le_bytes());
    write(&[
        image.target.architecture,
        u8::from(image.target.little_endian),
        image.target.pointer_width,
        image.target.abi,
        aggregate.map_or_else(
            || output_tag(image.output),
            |value| aggregate_tag(value.output),
        ),
        0,
    ]);
    write(&image.target.features.bits().to_le_bytes());
    if let Some(manifest) = aggregate {
        write(manifest.source_identity.as_bytes());
        write(&manifest.literal_bytes.to_le_bytes());
    } else if let Some(manifest) = search {
        // Retain the legacy source field and also bind the sealed manifest's
        // copy. Audit requires equality; encoding both makes either mutation
        // change the artifact identity.
        write(image.source_identity.as_bytes());
        write(&manifest.backend_version.0.to_le_bytes());
        write(&[
            search_shape_tag(manifest.shape),
            output_tag(manifest.output),
            u8::from(manifest.anchors.start) | (u8::from(manifest.anchors.end) << 1),
            0,
        ]);
        write(&manifest.literal_bytes.to_le_bytes());
        write(&manifest.candidate_policy_version.to_le_bytes());
        write(&manifest.candidate_block_width.to_le_bytes());
        write(&manifest.primary_offset.to_le_bytes());
        write(&manifest.secondary_offset.to_le_bytes());
        if matches!(
            image.backend_version,
            BackendVersion::SEARCH_V5
                | BackendVersion::SEARCH_V6
                | BackendVersion::SEARCH_V7
                | BackendVersion::SEARCH_SVE16_V1
                | BackendVersion::SEARCH_SVE2_16_V1
        ) {
            write(&manifest.verification_offset.to_le_bytes());
        }
        if matches!(
            image.backend_version,
            BackendVersion::SEARCH_V7
                | BackendVersion::SEARCH_SVE16_V1
                | BackendVersion::SEARCH_SVE2_16_V1
        ) {
            write(&manifest.quaternary_offset.to_le_bytes());
        }
        write(manifest.source_identity.as_bytes());
    } else {
        write(image.source_identity.as_bytes());
    }
    write(&image.layout.code_alignment.to_le_bytes());
    write(&image.layout.rodata_alignment.to_le_bytes());
    write(&image.layout.rodata_from_code_start.to_le_bytes());
    write(&image.layout.total_mapped_bytes.to_le_bytes());
    write_len(write, image.code.len())?;
    write_len(write, image.rodata.len())?;
    write_len(write, image.labels.len())?;
    write_len(write, image.symbols.len())?;
    write_len(write, image.relocations.len())?;
    write(&image.stats.code_bytes.to_le_bytes());
    write(&image.stats.data_bytes.to_le_bytes());
    write(&image.stats.relocations.to_le_bytes());
    write(&image.stats.labels.to_le_bytes());
    write(&image.stats.emission_work.to_le_bytes());
    write(&image.stats.scratch_bytes.to_le_bytes());
    write(&image.stats.vector_instructions.to_le_bytes());
    write(&image.code);
    write(&image.rodata);
    for label in &image.labels {
        write(&label.offset.to_le_bytes());
        write(&[label_kind_tag(label.kind), 0, 0, 0]);
    }
    for symbol in &image.symbols {
        write(&symbol.ir_data_id.to_le_bytes());
        write(&symbol.offset.to_le_bytes());
        write(&symbol.length.to_le_bytes());
        write(&[symbol.alignment, data_symbol_kind_tag(symbol.kind), 0, 0]);
    }
    for relocation in &image.relocations {
        write(&relocation.code_offset.to_le_bytes());
        let (section, target) = match relocation.target {
            RelocationTarget::CodeOffset(offset) => (1, offset),
            RelocationTarget::RodataOffset(offset) => (2, offset),
        };
        write(&[relocation_kind_tag(relocation.kind), section, 0, 0]);
        write(&target.to_le_bytes());
        write(&relocation.addend.to_le_bytes());
        write(&relocation.resolved_word.to_le_bytes());
    }
    Ok(())
}

fn write_len(write: &mut impl FnMut(&[u8]), value: usize) -> Result<(), EmitError> {
    let value = u32::try_from(value).map_err(|_| EmitError::ArithmeticOverflow {
        site: ArithmeticSite::AotSize,
    })?;
    write(&value.to_le_bytes());
    Ok(())
}

const fn output_tag(output: OutputKind) -> u8 {
    match output {
        OutputKind::Exists => 1,
        OutputKind::SelectedEnd => 2,
        OutputKind::Span => 3,
    }
}

const fn search_shape_tag(shape: SearchShape) -> u8 {
    match shape {
        SearchShape::ExactLiteral => 1,
        SearchShape::ClassSuffix => 2,
    }
}

const fn aggregate_tag(output: AggregateOutput) -> u8 {
    match output {
        AggregateOutput::Count => 1,
        AggregateOutput::SpanSum => 2,
    }
}

const fn label_kind_tag(kind: LabelKind) -> u8 {
    match kind {
        LabelKind::Entry => 1,
        LabelKind::Loop => 2,
        LabelKind::SlowPath => 3,
        LabelKind::ReturnFound => 4,
        LabelKind::ReturnNone => 5,
        LabelKind::Internal => 6,
    }
}

const fn data_symbol_kind_tag(kind: DataSymbolKind) -> u8 {
    match kind {
        DataSymbolKind::Bytes => 1,
        DataSymbolKind::ByteClass => 2,
    }
}

const fn relocation_kind_tag(kind: RelocationKind) -> u8 {
    match kind {
        RelocationKind::Branch26 => 1,
        RelocationKind::ConditionalBranch19 => 2,
        RelocationKind::CompareBranch19 => 3,
        RelocationKind::Address21 => 4,
    }
}
