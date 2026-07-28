use core::fmt;

use fre_exact_alloc::ExactVec;
use fre_kernel_ir::{AbiVersion, AggregateProgramIdentity, SemanticsVersion};

use crate::{AotCountBackendVersion, AotCountCpuFeatures, AotCountTargetSpec, CountAuditReportV2};

/// Canonical wire schema of an experimental Count SIMD image identity.
pub const AOT_COUNT_IMAGE_SCHEMA_VERSION_V2: u16 = 2;
/// Numerically disjoint from v1 and from every generic search-JIT backend.
pub const AOT_COUNT_BACKEND_VERSION_V2: AotCountBackendVersion = AotCountBackendVersion(0xa002);
/// Retired staged rare-byte SIMD filtering with four-block sparse-run skipping.
///
/// This exact value remains named so stale algorithm-3 images and receipts can
/// be rejected explicitly. Its evidence remains bound to the immutable
/// algorithm-3 source commit; it is not silently reinterpreted by algorithm 4.
pub const AOT_COUNT_BACKEND_ALGORITHM_VERSION_SPARSE_V3: u16 = 3;
/// Content-adaptive filtering plus exact-successor run confirmation.
///
/// Algorithm 4 preserves the four-block sparse scan from algorithm 3. A
/// bounded, per-block pair-density observation selects a first/last filter for
/// pair-dense blocks, while confirmed matches enter an exact-width run loop.
/// The generated code and exact audit policy are therefore a distinct tuple.
pub const AOT_COUNT_BACKEND_ALGORITHM_VERSION_V2: u16 = 4;
pub const AOT_COUNT_KIR_SEMANTICS_VERSION_V2: u16 = 1;
pub const AOT_COUNT_KIR_ABI_VERSION_V2: u16 = 1;
const AOT_COUNT_LITERAL_MANIFEST_BYTES_V2: usize = 32;
const AOT_COUNT_NO_FILTER_OFFSET_V2: u8 = u8::MAX;
const _: () = assert!(SemanticsVersion::CURRENT.0 == AOT_COUNT_KIR_SEMANTICS_VERSION_V2);
const _: () = assert!(AbiVersion::CURRENT.0 == AOT_COUNT_KIR_ABI_VERSION_V2);

/// Exact backend/KIR/output/target support row admitted by experimental v2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountBackendSupportV2 {
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
    pub candidate_block_starts: u8,
}

/// Complete explicit v2 support table; no implicit current-version alias.
pub const SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2: &[AotCountBackendSupportV2] =
    &[AotCountBackendSupportV2 {
        backend_version: AOT_COUNT_BACKEND_VERSION_V2,
        algorithm_version: AOT_COUNT_BACKEND_ALGORITHM_VERSION_V2,
        kir_semantics_version: AOT_COUNT_KIR_SEMANTICS_VERSION_V2,
        kir_abi_version: AOT_COUNT_KIR_ABI_VERSION_V2,
        output_kind: 1,
        architecture: 1,
        little_endian: true,
        pointer_width: 64,
        target_abi: 1,
        allowed_features: AotCountCpuFeatures::ASIMD,
        max_literal_bytes: 32,
        candidate_block_starts: 16,
    }];

#[must_use]
pub fn is_supported_aot_count_backend_tuple_v2(candidate: AotCountBackendSupportV2) -> bool {
    SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V2.contains(&candidate)
}

/// One valid direct-control-flow target in a v2 code image.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CodeLabelV2 {
    pub offset: u32,
    pub kind: LabelKindV2,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LabelKindV2 {
    Entry = 1,
    VectorLoop = 2,
    CandidateLoop = 3,
    ScalarTail = 4,
    Miss = 5,
    Success = 6,
    Overflow = 7,
    Internal = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelocationKindV2 {
    Branch26 = 1,
    ConditionalBranch19 = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationTargetV2 {
    CodeOffset(u32),
}

/// One already-applied direct branch relocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelocationV2 {
    pub code_offset: u32,
    pub kind: RelocationKindV2,
    pub target: RelocationTargetV2,
    pub resolved_word: u32,
}

/// Final relative placement required of a Mach-O publisher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountImageLayoutV2 {
    pub code_alignment: u32,
    pub rodata_alignment: u32,
    pub rodata_from_code_start: u32,
    pub total_mapped_bytes: u32,
}

/// Exact semantic input plus the independently auditable staged-filter choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountLiteralManifestV2 {
    len: u8,
    filter_len: u8,
    filter_offsets: [u8; 4],
    bytes: [u8; AOT_COUNT_LITERAL_MANIFEST_BYTES_V2],
}

impl AotCountLiteralManifestV2 {
    pub(crate) fn from_literal_and_offsets(literal: &[u8], filter_offsets: &[u8]) -> Option<Self> {
        let len = u8::try_from(literal.len()).ok()?;
        if literal.len() > AOT_COUNT_LITERAL_MANIFEST_BYTES_V2 {
            return None;
        }
        if !matches!(filter_offsets.len(), 0 | 2..=4)
            || filter_offsets
                .iter()
                .any(|offset| usize::from(*offset) >= literal.len())
            || filter_offsets
                .iter()
                .enumerate()
                .any(|(index, offset)| filter_offsets[..index].contains(offset))
        {
            return None;
        }
        let mut encoded_filter_offsets = [AOT_COUNT_NO_FILTER_OFFSET_V2; 4];
        encoded_filter_offsets
            .get_mut(..filter_offsets.len())?
            .copy_from_slice(filter_offsets);
        let mut bytes = [0_u8; AOT_COUNT_LITERAL_MANIFEST_BYTES_V2];
        bytes.get_mut(..literal.len())?.copy_from_slice(literal);
        Some(Self {
            len,
            filter_len: u8::try_from(filter_offsets.len()).ok()?,
            filter_offsets: encoded_filter_offsets,
            bytes,
        })
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

    #[must_use]
    pub const fn candidate_pair(self) -> Option<(u8, u8)> {
        if self.filter_len < 2 {
            None
        } else {
            Some((self.filter_offsets[0], self.filter_offsets[1]))
        }
    }

    #[must_use]
    pub const fn candidate_filter_len(self) -> u8 {
        self.filter_len
    }

    #[must_use]
    pub fn candidate_filter_offsets(&self) -> &[u8] {
        &self.filter_offsets[..usize::from(self.filter_len)]
    }

    pub(crate) const fn padded_bytes(self) -> [u8; AOT_COUNT_LITERAL_MANIFEST_BYTES_V2] {
        self.bytes
    }

    pub(crate) const fn padded_filter_offsets(self) -> [u8; 4] {
        self.filter_offsets
    }
}

/// Domain-separated identity of the complete experimental v2 image.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AotCountArtifactIdentityV2([u8; 32]);

impl AotCountArtifactIdentityV2 {
    pub(crate) const ZERO: Self = Self([0; 32]);

    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AotCountArtifactIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AotCountArtifactIdentityV2({self})")
    }
}

impl fmt::Display for AotCountArtifactIdentityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Observed image dimensions and conservative source-derived resource bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountImageStatsV2 {
    pub code_bytes: u32,
    pub data_bytes: u32,
    pub labels: u32,
    pub relocations: u32,
    pub emitted_instructions: u32,
    pub vector_instructions: u32,
    pub candidate_filter_bytes: u8,
    pub confirmation_chunks: u8,
    pub confirmation_tail_bytes: u8,
    pub emission_work: u64,
    pub identity_bytes_hashed: u64,
    pub audit_work_upper_bound: u64,
    pub total_work_upper_bound: u64,
    pub scratch_bytes_upper_bound: u64,
}

/// Resource and independent-audit receipt retained by a v2 image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountImageBuildReceiptV2 {
    pub support: AotCountBackendSupportV2,
    pub code_capacity_bytes: usize,
    pub label_capacity_bytes: usize,
    pub relocation_capacity_bytes: usize,
    pub retained_heap_bytes: usize,
    pub inline_bytes: usize,
    pub emission_peak_scratch_bytes: u64,
    pub work_upper_bound: u64,
    pub scratch_bytes_upper_bound: u64,
    pub audit: CountAuditReportV2,
}

/// Immutable inert direct-AOT image for the three-argument Count ABI.
#[derive(Debug, Eq, PartialEq)]
pub struct AotCountImageV2 {
    pub(crate) support: AotCountBackendSupportV2,
    pub(crate) target: AotCountTargetSpec,
    pub(crate) source_identity: AggregateProgramIdentity,
    pub(crate) literal_manifest: AotCountLiteralManifestV2,
    pub(crate) layout: AotCountImageLayoutV2,
    pub(crate) code: ExactVec<u8>,
    pub(crate) labels: ExactVec<CodeLabelV2>,
    pub(crate) relocations: ExactVec<RelocationV2>,
    pub(crate) stats: AotCountImageStatsV2,
    pub(crate) artifact_identity: AotCountArtifactIdentityV2,
    pub(crate) build_receipt: AotCountImageBuildReceiptV2,
}

impl AotCountImageV2 {
    #[must_use]
    pub const fn support(&self) -> AotCountBackendSupportV2 {
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
    pub const fn literal_manifest(&self) -> AotCountLiteralManifestV2 {
        self.literal_manifest
    }

    #[must_use]
    pub fn literal_bytes(&self) -> u32 {
        u32::from(self.literal_manifest.len)
    }

    #[must_use]
    pub const fn layout(&self) -> AotCountImageLayoutV2 {
        self.layout
    }

    #[must_use]
    pub fn code(&self) -> &[u8] {
        &self.code
    }

    /// The v2 prototype hoists literal immediates and retains no rodata.
    #[must_use]
    pub const fn rodata(&self) -> &[u8] {
        &[]
    }

    #[must_use]
    pub fn labels(&self) -> &[CodeLabelV2] {
        &self.labels
    }

    #[must_use]
    pub const fn data_symbol_count(&self) -> usize {
        0
    }

    #[must_use]
    pub fn relocations(&self) -> &[RelocationV2] {
        &self.relocations
    }

    #[must_use]
    pub const fn stats(&self) -> AotCountImageStatsV2 {
        self.stats
    }

    #[must_use]
    pub const fn artifact_identity(&self) -> AotCountArtifactIdentityV2 {
        self.artifact_identity
    }

    #[must_use]
    pub const fn build_receipt(&self) -> AotCountImageBuildReceiptV2 {
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
