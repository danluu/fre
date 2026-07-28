use core::fmt;

use fre_exact_alloc::ExactVec;
use fre_kernel_ir::{AbiVersion, AggregateProgramIdentity, SemanticsVersion};

use crate::CountAuditReportV1;

/// Canonical wire schema of an independent Count AOT image identity.
pub const AOT_COUNT_IMAGE_SCHEMA_VERSION_V1: u16 = 1;
/// Numerically disjoint from every generic search-JIT backend version.
pub const AOT_COUNT_BACKEND_VERSION_V1: AotCountBackendVersion = AotCountBackendVersion(0xa001);
/// Pattern-specialized width-0/vector-width-1/chunked-width-2..32 template.
pub const AOT_COUNT_BACKEND_ALGORITHM_VERSION_V1: u16 = 1;
/// KIR wire contracts pinned by backend version `0xa001`.
pub const AOT_COUNT_KIR_SEMANTICS_VERSION_V1: u16 = 1;
pub const AOT_COUNT_KIR_ABI_VERSION_V1: u16 = 1;
const AOT_COUNT_LITERAL_MANIFEST_BYTES_V1: usize = 32;
const _: () = assert!(SemanticsVersion::CURRENT.0 == AOT_COUNT_KIR_SEMANTICS_VERSION_V1);
const _: () = assert!(AbiVersion::CURRENT.0 == AOT_COUNT_KIR_ABI_VERSION_V1);

/// Independent aggregate AOT backend version carried on the wire.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AotCountBackendVersion(pub u16);

/// Architectural feature bitmap required by one emitted Count image.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AotCountCpuFeatures(u64);

impl AotCountCpuFeatures {
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

/// Fixed `AArch64` little-endian AAPCS64 target tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountTargetSpec {
    pub architecture: u8,
    pub little_endian: bool,
    pub pointer_width: u8,
    pub abi: u8,
    pub features: AotCountCpuFeatures,
}

impl AotCountTargetSpec {
    pub const AARCH64_AAPCS64_BASELINE: Self = Self {
        architecture: 1,
        little_endian: true,
        pointer_width: 64,
        abi: 1,
        features: AotCountCpuFeatures::NONE,
    };
}

/// Exact backend/KIR/output/target support row admitted by v1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountBackendSupportV1 {
    pub backend_version: AotCountBackendVersion,
    pub algorithm_version: u16,
    pub kir_semantics_version: u16,
    pub kir_abi_version: u16,
    pub output_kind: u8,
    pub architecture: u8,
    pub little_endian: bool,
    pub pointer_width: u8,
    pub target_abi: u8,
    pub allowed_features: AotCountCpuFeatures,
    pub max_literal_bytes: u16,
}

/// Complete explicit support table; no implicit `CURRENT` alias is accepted.
pub const SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V1: &[AotCountBackendSupportV1] =
    &[AotCountBackendSupportV1 {
        backend_version: AOT_COUNT_BACKEND_VERSION_V1,
        algorithm_version: AOT_COUNT_BACKEND_ALGORITHM_VERSION_V1,
        kir_semantics_version: AOT_COUNT_KIR_SEMANTICS_VERSION_V1,
        kir_abi_version: AOT_COUNT_KIR_ABI_VERSION_V1,
        output_kind: 1,
        architecture: 1,
        little_endian: true,
        pointer_width: 64,
        target_abi: 1,
        allowed_features: AotCountCpuFeatures::ASIMD,
        max_literal_bytes: 32,
    }];

#[must_use]
pub fn is_supported_aot_count_backend_tuple_v1(candidate: AotCountBackendSupportV1) -> bool {
    SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V1.contains(&candidate)
}

/// One valid direct-control-flow target.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CodeLabelV1 {
    pub offset: u32,
    pub kind: LabelKindV1,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LabelKindV1 {
    Entry = 1,
    Loop = 2,
    SlowPath = 3,
    Success = 4,
    Overflow = 5,
    Internal = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelocationKindV1 {
    Branch26 = 1,
    ConditionalBranch19 = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationTargetV1 {
    CodeOffset(u32),
}

/// One already-applied direct branch relocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelocationV1 {
    pub code_offset: u32,
    pub kind: RelocationKindV1,
    pub target: RelocationTargetV1,
    pub resolved_word: u32,
}

/// Final relative placement required of a Mach-O publisher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountImageLayoutV1 {
    pub code_alignment: u32,
    pub rodata_alignment: u32,
    pub rodata_from_code_start: u32,
    pub total_mapped_bytes: u32,
}

/// Fixed-size audit manifest for the literal embedded into machine immediates.
///
/// The original typed KIR is still required by the public auditor. Retaining
/// these bytes additionally makes the exact semantic input part of the inert
/// image and its artifact identity instead of trusting only a digest-shaped
/// source identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountLiteralManifestV1 {
    len: u8,
    bytes: [u8; AOT_COUNT_LITERAL_MANIFEST_BYTES_V1],
}

impl AotCountLiteralManifestV1 {
    pub(crate) fn from_literal(literal: &[u8]) -> Option<Self> {
        let len = u8::try_from(literal.len()).ok()?;
        if literal.len() > AOT_COUNT_LITERAL_MANIFEST_BYTES_V1 {
            return None;
        }
        let mut bytes = [0_u8; AOT_COUNT_LITERAL_MANIFEST_BYTES_V1];
        bytes.get_mut(..literal.len())?.copy_from_slice(literal);
        Some(Self { len, bytes })
    }

    #[must_use]
    pub const fn len(self) -> u8 {
        self.len
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn literal(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    pub(crate) const fn padded_bytes(self) -> [u8; AOT_COUNT_LITERAL_MANIFEST_BYTES_V1] {
        self.bytes
    }
}

/// Domain-separated identity of the complete typed Count image.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AotCountArtifactIdentity([u8; 32]);

impl AotCountArtifactIdentity {
    pub(crate) const ZERO: Self = Self([0; 32]);

    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AotCountArtifactIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AotCountArtifactIdentity({self})")
    }
}

impl fmt::Display for AotCountArtifactIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Exact observed image dimensions plus prospective bounded work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountImageStatsV1 {
    pub code_bytes: u32,
    pub data_bytes: u32,
    pub labels: u32,
    pub relocations: u32,
    pub emitted_instructions: u32,
    pub vector_instructions: u32,
    pub emission_work: u64,
    pub identity_bytes_hashed: u64,
    pub audit_work_upper_bound: u64,
    pub total_work_upper_bound: u64,
    pub scratch_bytes_upper_bound: u64,
}

/// Sealed resource and independent-audit receipt retained by the image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountImageBuildReceiptV1 {
    pub support: AotCountBackendSupportV1,
    pub code_capacity_bytes: usize,
    pub label_capacity_bytes: usize,
    pub relocation_capacity_bytes: usize,
    pub retained_heap_bytes: usize,
    pub inline_bytes: usize,
    pub emission_peak_scratch_bytes: u64,
    pub work_upper_bound: u64,
    pub scratch_bytes_upper_bound: u64,
    pub audit: CountAuditReportV1,
}

/// Immutable inert image for the three-argument Count ABI.
#[derive(Debug, Eq, PartialEq)]
pub struct AotCountImageV1 {
    pub(crate) support: AotCountBackendSupportV1,
    pub(crate) target: AotCountTargetSpec,
    pub(crate) source_identity: AggregateProgramIdentity,
    pub(crate) literal_bytes: u32,
    pub(crate) literal_manifest: AotCountLiteralManifestV1,
    pub(crate) layout: AotCountImageLayoutV1,
    pub(crate) code: ExactVec<u8>,
    pub(crate) labels: ExactVec<CodeLabelV1>,
    pub(crate) relocations: ExactVec<RelocationV1>,
    pub(crate) stats: AotCountImageStatsV1,
    pub(crate) artifact_identity: AotCountArtifactIdentity,
    pub(crate) build_receipt: AotCountImageBuildReceiptV1,
}

impl AotCountImageV1 {
    #[must_use]
    pub const fn support(&self) -> AotCountBackendSupportV1 {
        self.support
    }

    #[must_use]
    pub const fn backend_version(&self) -> AotCountBackendVersion {
        self.support.backend_version
    }

    #[must_use]
    pub const fn target(&self) -> AotCountTargetSpec {
        self.target
    }

    #[must_use]
    pub const fn output_kind(&self) -> u8 {
        self.support.output_kind
    }

    #[must_use]
    pub const fn source_identity(&self) -> AggregateProgramIdentity {
        self.source_identity
    }

    #[must_use]
    pub const fn literal_bytes(&self) -> u32 {
        self.literal_bytes
    }

    #[must_use]
    pub const fn literal_manifest(&self) -> AotCountLiteralManifestV1 {
        self.literal_manifest
    }

    #[must_use]
    pub const fn layout(&self) -> AotCountImageLayoutV1 {
        self.layout
    }

    #[must_use]
    pub fn code(&self) -> &[u8] {
        &self.code
    }

    /// The v1 AOT template embeds literal immediates and retains no rodata.
    #[must_use]
    pub const fn rodata(&self) -> &[u8] {
        &[]
    }

    #[must_use]
    pub fn labels(&self) -> &[CodeLabelV1] {
        &self.labels
    }

    #[must_use]
    pub const fn data_symbol_count(&self) -> usize {
        0
    }

    #[must_use]
    pub fn relocations(&self) -> &[RelocationV1] {
        &self.relocations
    }

    #[must_use]
    pub const fn stats(&self) -> AotCountImageStatsV1 {
        self.stats
    }

    #[must_use]
    pub const fn artifact_identity(&self) -> AotCountArtifactIdentity {
        self.artifact_identity
    }

    #[must_use]
    pub const fn build_receipt(&self) -> AotCountImageBuildReceiptV1 {
        self.build_receipt
    }

    pub(crate) fn retained_heap_bytes(
        code_capacity_bytes: usize,
        label_capacity_bytes: usize,
        relocation_capacity_bytes: usize,
    ) -> Option<usize> {
        code_capacity_bytes
            .checked_add(label_capacity_bytes)
            .and_then(|bytes| bytes.checked_add(relocation_capacity_bytes))
    }
}
