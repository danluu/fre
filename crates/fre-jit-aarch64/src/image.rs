use core::fmt;

use fre_kernel_ir::{AggregateOutput, AggregateProgramIdentity, CacheIdentity, OutputKind};
use sha2::{Digest, Sha256};

use crate::{ArithmeticSite, EmitError, ResourceKind};

/// Version of the deterministic backend contract and encoding policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendVersion(pub u16);

impl BackendVersion {
    pub const CURRENT: Self = Self(1);
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
}

/// Required architectural feature bitmap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuFeatures(u64);

impl CpuFeatures {
    pub const NONE: Self = Self(0);
    pub const ASIMD: Self = Self(1);

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
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
    pub(crate) aggregate: Option<AggregateManifest>,
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
    pub(crate) fn new(inner: NativeImage) -> Self {
        debug_assert!(inner.aggregate.is_some());
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
    let aggregate_bytes = if image.aggregate.is_some() { 4 } else { 0 };
    let header = (8_usize + 2 + 6 + 8 + 32 + 16 + 20 + 36)
        .checked_add(aggregate_bytes)
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

fn encode_aot(image: &NativeImage, write: &mut impl FnMut(&[u8])) -> Result<(), EmitError> {
    let aggregate = image.aggregate;
    write(if aggregate.is_some() {
        b"FREA64A\x01"
    } else {
        b"FREA64\0\x01"
    });
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
