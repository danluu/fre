use core::fmt;

use fre_aot_optimizer::{COUNT_V3_RECIPE_CANONICAL_BYTES, CountRecipeV3, encode_count_recipe_v3};
use fre_exact_alloc::ExactVec;
use fre_kernel_ir::{AbiVersion, AggregateProgramIdentity, SemanticsVersion};

use crate::{AotCountBackendVersion, AotCountCpuFeatures, AotCountTargetSpec, CountAuditReportV3};

/// Canonical wire schema of an optimizing Count-v3 image identity.
pub const AOT_COUNT_IMAGE_SCHEMA_VERSION_V3: u16 = 3;
/// Numerically disjoint from Count-v1, Count-v2, and every search-JIT backend.
pub const AOT_COUNT_BACKEND_VERSION_V3: AotCountBackendVersion = AotCountBackendVersion(0xa003);
/// Closed recipe-specialized ASIMD/SVE/SVE2 lowering.
///
/// This is deliberately not an alias for Count-v2 algorithm 4. The recipe,
/// schedule, register plan, and complete optimizer identity are authenticated
/// inputs to both lowering and the final artifact identity.
pub const AOT_COUNT_BACKEND_ALGORITHM_VERSION_V3: u16 = 11;
pub const AOT_COUNT_KIR_SEMANTICS_VERSION_V3: u16 = 1;
pub const AOT_COUNT_KIR_ABI_VERSION_V3: u16 = 1;
const AOT_COUNT_LITERAL_MANIFEST_BYTES_V3: usize = 32;
const AOT_COUNT_NO_FILTER_OFFSET_V3: u8 = u8::MAX;
const _: () = assert!(SemanticsVersion::CURRENT.0 == AOT_COUNT_KIR_SEMANTICS_VERSION_V3);
const _: () = assert!(AbiVersion::CURRENT.0 == AOT_COUNT_KIR_ABI_VERSION_V3);
const _: () = assert!(COUNT_V3_RECIPE_CANONICAL_BYTES == 256);

/// Exact backend/KIR/output/target support row admitted by optimizing v3.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountBackendSupportV3 {
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
    /// Architectural vector width assumed by the reviewed recipe.
    pub vector_bytes: u16,
    /// Exact SVE vector length, or zero for a non-SVE row.
    pub sve_vector_length_bytes: u16,
}

/// Complete explicit v3 support table; no implicit current-version alias.
pub const SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3: &[AotCountBackendSupportV3] = &[
    AotCountBackendSupportV3 {
        backend_version: AOT_COUNT_BACKEND_VERSION_V3,
        algorithm_version: AOT_COUNT_BACKEND_ALGORITHM_VERSION_V3,
        kir_semantics_version: AOT_COUNT_KIR_SEMANTICS_VERSION_V3,
        kir_abi_version: AOT_COUNT_KIR_ABI_VERSION_V3,
        output_kind: 1,
        architecture: 1,
        little_endian: true,
        pointer_width: 64,
        target_abi: 1,
        allowed_features: AotCountCpuFeatures::ASIMD,
        max_literal_bytes: 32,
        candidate_block_starts: 16,
        vector_bytes: 16,
        sve_vector_length_bytes: 0,
    },
    AotCountBackendSupportV3 {
        backend_version: AOT_COUNT_BACKEND_VERSION_V3,
        algorithm_version: AOT_COUNT_BACKEND_ALGORITHM_VERSION_V3,
        kir_semantics_version: AOT_COUNT_KIR_SEMANTICS_VERSION_V3,
        kir_abi_version: AOT_COUNT_KIR_ABI_VERSION_V3,
        output_kind: 1,
        architecture: 1,
        little_endian: true,
        pointer_width: 64,
        target_abi: 1,
        allowed_features: AotCountCpuFeatures::SVE,
        max_literal_bytes: 32,
        candidate_block_starts: 16,
        vector_bytes: 16,
        sve_vector_length_bytes: 16,
    },
    AotCountBackendSupportV3 {
        backend_version: AOT_COUNT_BACKEND_VERSION_V3,
        algorithm_version: AOT_COUNT_BACKEND_ALGORITHM_VERSION_V3,
        kir_semantics_version: AOT_COUNT_KIR_SEMANTICS_VERSION_V3,
        kir_abi_version: AOT_COUNT_KIR_ABI_VERSION_V3,
        output_kind: 1,
        architecture: 1,
        little_endian: true,
        pointer_width: 64,
        target_abi: 1,
        allowed_features: AotCountCpuFeatures::SVE.union(AotCountCpuFeatures::SVE2),
        max_literal_bytes: 32,
        candidate_block_starts: 16,
        vector_bytes: 16,
        sve_vector_length_bytes: 16,
    },
];

#[must_use]
pub fn is_supported_aot_count_backend_tuple_v3(candidate: AotCountBackendSupportV3) -> bool {
    SUPPORTED_AOT_COUNT_BACKEND_TUPLES_V3.contains(&candidate)
}

/// One valid direct-control-flow target in a v3 code image.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CodeLabelV3 {
    pub offset: u32,
    pub kind: LabelKindV3,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LabelKindV3 {
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
pub enum RelocationKindV3 {
    Branch26 = 1,
    ConditionalBranch19 = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationTargetV3 {
    CodeOffset(u32),
}

/// One already-applied direct branch relocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelocationV3 {
    pub code_offset: u32,
    pub kind: RelocationKindV3,
    pub target: RelocationTargetV3,
    pub resolved_word: u32,
}

/// Final relative placement required of a Mach-O publisher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountImageLayoutV3 {
    pub code_alignment: u32,
    pub rodata_alignment: u32,
    pub rodata_from_code_start: u32,
    pub total_mapped_bytes: u32,
}

/// Exact semantic input retained independently of the optimizer recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountLiteralManifestV3 {
    len: u8,
    filter_len: u8,
    filter_offsets: [u8; 4],
    bytes: [u8; AOT_COUNT_LITERAL_MANIFEST_BYTES_V3],
}

/// Fixed canonical projection of the sealed optimizer recipe.
///
/// The backend retains primitive wire values instead of an optimizer-owned
/// Rust layout. This keeps image/object schemas stable if the optimizer grows
/// private bookkeeping while binding every code-shape choice used by lowering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountRecipeManifestV3 {
    pub(crate) recipe_schema_version: u16,
    pub(crate) optimizer_version: u16,
    pub(crate) tuning_class_id: u8,
    pub(crate) strategy_id: u8,
    pub(crate) schedule_id: u8,
    pub(crate) register_plan_id: u8,
    pub(crate) required_isa_id: u8,
    pub(crate) successor_mode_id: u8,
    pub(crate) filter_len: u8,
    pub(crate) confirmation_len: u8,
    pub(crate) sparse_group_count: u8,
    pub(crate) mismatch_stride: u8,
    pub(crate) match_stride: u8,
    pub(crate) periodic_stride: u8,
    pub(crate) filter_offsets: [u8; 4],
    pub(crate) confirmation_order: [u8; 32],
    pub(crate) sparse_group_first_offsets: [u8; 4],
    pub(crate) sparse_group_lengths: [u8; 4],
    pub(crate) literal_identity: [u8; 32],
    pub(crate) recipe_identity: [u8; 32],
    pub(crate) canonical_recipe: [u8; COUNT_V3_RECIPE_CANONICAL_BYTES],
}

impl AotCountRecipeManifestV3 {
    /// Project an optimizer recipe into the fixed backend/object wire record.
    ///
    /// This is a structural conversion, not authority. Emitters and auditors
    /// separately validate the recipe against its typed source program.
    #[must_use]
    pub fn from_optimizer_recipe(recipe: &CountRecipeV3) -> Option<Self> {
        let filters = recipe.filter_offsets();
        let order = recipe.confirmation_order();
        let groups = recipe.sparse_group_blocks();
        if filters.len() > 4 || order.len() > 32 || groups.len() > 4 {
            return None;
        }
        let mut filter_offsets = [0_u8; 4];
        filter_offsets[..filters.len()].copy_from_slice(filters);
        let mut confirmation_order = [0_u8; 32];
        confirmation_order[..order.len()].copy_from_slice(order);
        let mut sparse_group_first_offsets = [0_u8; 4];
        let mut sparse_group_lengths = [0_u8; 4];
        for (index, group) in groups.iter().copied().enumerate() {
            sparse_group_first_offsets[index] = group.first_offset();
            sparse_group_lengths[index] = group.len();
        }
        Some(Self {
            recipe_schema_version: recipe.schema_version(),
            optimizer_version: recipe.optimizer_version(),
            tuning_class_id: recipe.tuning_class().wire_id(),
            strategy_id: recipe.strategy().wire_id(),
            schedule_id: recipe.schedule_id().wire_id(),
            register_plan_id: recipe.register_plan_id().wire_id(),
            required_isa_id: recipe.required_isa().wire_id(),
            successor_mode_id: recipe.successor_mode().wire_id(),
            filter_len: u8::try_from(filters.len()).ok()?,
            confirmation_len: u8::try_from(order.len()).ok()?,
            sparse_group_count: u8::try_from(groups.len()).ok()?,
            mismatch_stride: recipe.mismatch_stride(),
            match_stride: recipe.match_stride(),
            periodic_stride: recipe.periodic_stride(),
            filter_offsets,
            confirmation_order,
            sparse_group_first_offsets,
            sparse_group_lengths,
            literal_identity: *recipe.literal_identity(),
            recipe_identity: *recipe.identity().as_bytes(),
            canonical_recipe: encode_count_recipe_v3(recipe),
        })
    }

    #[must_use]
    pub const fn recipe_schema_version(self) -> u16 {
        self.recipe_schema_version
    }

    #[must_use]
    pub const fn optimizer_version(self) -> u16 {
        self.optimizer_version
    }

    #[must_use]
    pub const fn tuning_class_id(self) -> u8 {
        self.tuning_class_id
    }

    #[must_use]
    pub const fn strategy_id(self) -> u8 {
        self.strategy_id
    }

    #[must_use]
    pub const fn schedule_id(self) -> u8 {
        self.schedule_id
    }

    #[must_use]
    pub const fn register_plan_id(self) -> u8 {
        self.register_plan_id
    }

    #[must_use]
    pub const fn required_isa_id(self) -> u8 {
        self.required_isa_id
    }

    #[must_use]
    pub const fn successor_mode_id(self) -> u8 {
        self.successor_mode_id
    }

    #[must_use]
    pub fn filter_offsets(&self) -> &[u8] {
        &self.filter_offsets[..usize::from(self.filter_len)]
    }

    #[must_use]
    pub const fn filter_len(self) -> u8 {
        self.filter_len
    }

    #[must_use]
    pub fn confirmation_order(&self) -> &[u8] {
        &self.confirmation_order[..usize::from(self.confirmation_len)]
    }

    #[must_use]
    pub const fn confirmation_len(self) -> u8 {
        self.confirmation_len
    }

    #[must_use]
    pub const fn sparse_group_count(self) -> u8 {
        self.sparse_group_count
    }

    #[must_use]
    pub const fn mismatch_stride(self) -> u8 {
        self.mismatch_stride
    }

    #[must_use]
    pub const fn match_stride(self) -> u8 {
        self.match_stride
    }

    #[must_use]
    pub const fn periodic_stride(self) -> u8 {
        self.periodic_stride
    }

    #[must_use]
    pub const fn recipe_identity(self) -> [u8; 32] {
        self.recipe_identity
    }

    #[must_use]
    pub const fn literal_identity(self) -> [u8; 32] {
        self.literal_identity
    }

    #[must_use]
    pub const fn canonical_recipe(&self) -> &[u8; COUNT_V3_RECIPE_CANONICAL_BYTES] {
        &self.canonical_recipe
    }

    #[must_use]
    pub const fn padded_filter_offsets(self) -> [u8; 4] {
        self.filter_offsets
    }

    #[must_use]
    pub const fn padded_confirmation_order(self) -> [u8; 32] {
        self.confirmation_order
    }

    #[must_use]
    pub const fn padded_sparse_group_first_offsets(self) -> [u8; 4] {
        self.sparse_group_first_offsets
    }

    #[must_use]
    pub const fn padded_sparse_group_lengths(self) -> [u8; 4] {
        self.sparse_group_lengths
    }
}

impl AotCountLiteralManifestV3 {
    #[must_use]
    pub fn from_literal_and_offsets(literal: &[u8], filter_offsets: &[u8]) -> Option<Self> {
        let len = u8::try_from(literal.len()).ok()?;
        if literal.len() > AOT_COUNT_LITERAL_MANIFEST_BYTES_V3 {
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
        let mut encoded_filter_offsets = [AOT_COUNT_NO_FILTER_OFFSET_V3; 4];
        encoded_filter_offsets
            .get_mut(..filter_offsets.len())?
            .copy_from_slice(filter_offsets);
        let mut bytes = [0_u8; AOT_COUNT_LITERAL_MANIFEST_BYTES_V3];
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

    pub(crate) const fn padded_bytes(self) -> [u8; AOT_COUNT_LITERAL_MANIFEST_BYTES_V3] {
        self.bytes
    }

    pub(crate) const fn padded_filter_offsets(self) -> [u8; 4] {
        self.filter_offsets
    }
}

/// Domain-separated identity of the complete optimizing v3 image.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AotCountArtifactIdentityV3([u8; 32]);

impl AotCountArtifactIdentityV3 {
    pub(crate) const ZERO: Self = Self([0; 32]);

    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Construct an inert identity parsed from authenticated object metadata.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AotCountArtifactIdentityV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "AotCountArtifactIdentityV3({self})")
    }
}

impl fmt::Display for AotCountArtifactIdentityV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Observed image dimensions and conservative source-derived resource bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountImageStatsV3 {
    pub code_bytes: u32,
    pub data_bytes: u32,
    pub labels: u32,
    pub relocations: u32,
    pub emitted_instructions: u32,
    pub vector_instructions: u32,
    pub strategy_id: u8,
    pub schedule_id: u8,
    pub register_plan_id: u8,
    pub candidate_filter_bytes: u8,
    pub confirmation_chunks: u8,
    pub confirmation_tail_bytes: u8,
    pub emission_work: u64,
    pub identity_bytes_hashed: u64,
    pub audit_work_upper_bound: u64,
    pub total_work_upper_bound: u64,
    pub scratch_bytes_upper_bound: u64,
}

/// Resource and independent-audit receipt retained by a v3 image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountImageBuildReceiptV3 {
    pub support: AotCountBackendSupportV3,
    pub recipe: AotCountRecipeManifestV3,
    pub code_capacity_bytes: usize,
    pub label_capacity_bytes: usize,
    pub relocation_capacity_bytes: usize,
    pub retained_heap_bytes: usize,
    pub inline_bytes: usize,
    pub emission_peak_scratch_bytes: u64,
    pub work_upper_bound: u64,
    pub scratch_bytes_upper_bound: u64,
    pub audit: CountAuditReportV3,
}

/// Immutable inert direct-AOT image for the three-argument Count ABI.
#[derive(Debug, Eq, PartialEq)]
pub struct AotCountImageV3 {
    pub(crate) support: AotCountBackendSupportV3,
    pub(crate) target: AotCountTargetSpec,
    pub(crate) source_identity: AggregateProgramIdentity,
    pub(crate) literal_manifest: AotCountLiteralManifestV3,
    pub(crate) recipe_manifest: AotCountRecipeManifestV3,
    pub(crate) layout: AotCountImageLayoutV3,
    pub(crate) code: ExactVec<u8>,
    pub(crate) labels: ExactVec<CodeLabelV3>,
    pub(crate) relocations: ExactVec<RelocationV3>,
    pub(crate) stats: AotCountImageStatsV3,
    pub(crate) artifact_identity: AotCountArtifactIdentityV3,
    pub(crate) build_receipt: AotCountImageBuildReceiptV3,
}

/// Allocation-free borrowed view used to audit compiler-owned or mapped
/// Count-v3 artifacts through the same exact recipe contract.
#[derive(Clone, Copy, Debug)]
pub struct AotCountImageViewV3<'a> {
    pub support: AotCountBackendSupportV3,
    pub target: AotCountTargetSpec,
    pub source_identity: AggregateProgramIdentity,
    pub literal_manifest: AotCountLiteralManifestV3,
    pub recipe_manifest: AotCountRecipeManifestV3,
    pub layout: AotCountImageLayoutV3,
    pub code: &'a [u8],
    pub labels: &'a [CodeLabelV3],
    pub relocations: &'a [RelocationV3],
    pub stats: AotCountImageStatsV3,
    pub artifact_identity: AotCountArtifactIdentityV3,
    pub build_receipt: AotCountImageBuildReceiptV3,
}

/// Compact metadata required to adopt mapped Count-v3 code.
///
/// Labels, relocations, statistics, and build receipts are deliberately not
/// wire requirements: the bounded mapped-code auditor regenerates them from
/// the source-bound sealed recipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AotCountMappedMetadataV3 {
    pub image_schema_version: u16,
    pub support: AotCountBackendSupportV3,
    pub target: AotCountTargetSpec,
    pub source_identity: [u8; 32],
    pub literal_bytes: u8,
    pub recipe_identity: [u8; 32],
    pub artifact_identity: AotCountArtifactIdentityV3,
    pub code_bytes: u32,
}

impl AotCountMappedMetadataV3 {
    /// Project strictly parsed object-wire scalars into the compact mapped
    /// audit record.
    ///
    /// This constructor validates only closed target/support structure. The
    /// mapped-code auditor regenerates the typed program/recipe image and
    /// requires exact equality of every field and code byte before adoption.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "the explicit scalar list is the untrusted fixed-wire boundary"
    )]
    pub fn from_wire_parts(
        backend_version: u16,
        algorithm_version: u16,
        kir_semantics_version: u16,
        kir_abi_version: u16,
        output_kind: u8,
        architecture: u8,
        little_endian: bool,
        pointer_width: u8,
        target_abi: u8,
        actual_features: u64,
        allowed_features: u64,
        max_literal_bytes: u16,
        candidate_block_starts: u8,
        vector_bytes: u16,
        sve_vector_length_bytes: u16,
        source_identity: [u8; 32],
        literal_bytes: u32,
        recipe_identity: [u8; 32],
        artifact_identity: [u8; 32],
        code_bytes: u32,
    ) -> Option<Self> {
        let actual_features = AotCountCpuFeatures::from_bits(actual_features)?;
        let allowed_features = AotCountCpuFeatures::from_bits(allowed_features)?;
        let support = AotCountBackendSupportV3 {
            backend_version: AotCountBackendVersion(backend_version),
            algorithm_version,
            kir_semantics_version,
            kir_abi_version,
            output_kind,
            architecture,
            little_endian,
            pointer_width,
            target_abi,
            allowed_features,
            max_literal_bytes,
            candidate_block_starts,
            vector_bytes,
            sve_vector_length_bytes,
        };
        if !is_supported_aot_count_backend_tuple_v3(support)
            || !allowed_features.contains(actual_features)
            || code_bytes == 0
            || code_bytes % 4 != 0
        {
            return None;
        }
        let literal_bytes = u8::try_from(literal_bytes).ok()?;
        if u16::from(literal_bytes) > max_literal_bytes {
            return None;
        }
        Some(Self {
            image_schema_version: AOT_COUNT_IMAGE_SCHEMA_VERSION_V3,
            support,
            target: AotCountTargetSpec {
                architecture,
                little_endian,
                pointer_width,
                abi: target_abi,
                features: actual_features,
            },
            source_identity,
            literal_bytes,
            recipe_identity,
            artifact_identity: AotCountArtifactIdentityV3::from_bytes(artifact_identity),
            code_bytes,
        })
    }

    #[must_use]
    pub fn from_image(image: &AotCountImageV3) -> Self {
        Self {
            image_schema_version: AOT_COUNT_IMAGE_SCHEMA_VERSION_V3,
            support: image.support,
            target: image.target,
            source_identity: *image.source_identity.as_bytes(),
            literal_bytes: image.literal_manifest.len,
            recipe_identity: image.recipe_manifest.recipe_identity,
            artifact_identity: image.artifact_identity,
            code_bytes: image.stats.code_bytes,
        }
    }
}

impl<'a> From<&'a AotCountImageV3> for AotCountImageViewV3<'a> {
    fn from(image: &'a AotCountImageV3) -> Self {
        Self {
            support: image.support,
            target: image.target,
            source_identity: image.source_identity,
            literal_manifest: image.literal_manifest,
            recipe_manifest: image.recipe_manifest,
            layout: image.layout,
            code: &image.code,
            labels: &image.labels,
            relocations: &image.relocations,
            stats: image.stats,
            artifact_identity: image.artifact_identity,
            build_receipt: image.build_receipt,
        }
    }
}

impl AotCountImageV3 {
    #[must_use]
    pub const fn support(&self) -> AotCountBackendSupportV3 {
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
    pub const fn literal_manifest(&self) -> AotCountLiteralManifestV3 {
        self.literal_manifest
    }

    #[must_use]
    pub const fn recipe_manifest(&self) -> AotCountRecipeManifestV3 {
        self.recipe_manifest
    }

    #[must_use]
    pub fn literal_bytes(&self) -> u32 {
        u32::from(self.literal_manifest.len)
    }

    #[must_use]
    pub const fn layout(&self) -> AotCountImageLayoutV3 {
        self.layout
    }

    #[must_use]
    pub fn code(&self) -> &[u8] {
        &self.code
    }

    /// The v3 backend hoists literal immediates and retains no rodata.
    #[must_use]
    pub const fn rodata(&self) -> &[u8] {
        &[]
    }

    #[must_use]
    pub fn labels(&self) -> &[CodeLabelV3] {
        &self.labels
    }

    #[must_use]
    pub const fn data_symbol_count(&self) -> usize {
        0
    }

    #[must_use]
    pub fn relocations(&self) -> &[RelocationV3] {
        &self.relocations
    }

    #[must_use]
    pub const fn stats(&self) -> AotCountImageStatsV3 {
        self.stats
    }

    #[must_use]
    pub const fn artifact_identity(&self) -> AotCountArtifactIdentityV3 {
        self.artifact_identity
    }

    #[must_use]
    pub const fn build_receipt(&self) -> AotCountImageBuildReceiptV3 {
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
