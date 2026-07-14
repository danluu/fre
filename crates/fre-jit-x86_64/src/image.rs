use fre_kernel_ir::{AnchorFlags, CacheIdentity, OutputKind};

use crate::{FeatureTier, TargetStamp};

/// Native section named by a relocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Section {
    Code = 1,
    Data = 2,
}

/// Relocation form supported by the immutable contiguous image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelocationKind {
    /// Signed little-endian displacement relative to the end of its i32 field.
    RipRelativeI32 = 1,
}

/// Auditable record for one already-resolved, image-relative data reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Relocation {
    pub kind: RelocationKind,
    pub source_section: Section,
    pub displacement_offset: u32,
    pub target_section: Section,
    pub target_offset: u32,
}

/// Backend-neutral semantic shape extracted from validated Kernel IR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelShape {
    ExactLiteral {
        literal_len: u32,
        anchors: AnchorFlags,
    },
    DisjointClassSuffix {
        class_population: u16,
        suffix_len: u32,
        anchors: AnchorFlags,
    },
}

/// Complete machine/ABI/feature stamp incorporated into AOT identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X86AbiStamp {
    pub target: TargetStamp,
    /// Requested maximum feature tier.
    pub requested_tier: FeatureTier,
    /// Highest tier actually used by decoded instructions.
    pub used_tier: FeatureTier,
    pub kernel_abi_version: u16,
    pub kernel_semantics_version: u16,
}

/// Exact dimensions charged by a completed native image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageStats {
    pub code_bytes: usize,
    pub data_bytes: usize,
    pub image_bytes: usize,
    pub padding_bytes: usize,
    pub relocations: usize,
    pub internal_branches: usize,
    pub maximum_branch_displacement: u64,
    pub maximum_relocation_displacement: u64,
    pub emit_work: u64,
    pub emit_scratch_bytes: usize,
    pub runtime_work_factor: u64,
    pub runtime_scratch_bytes: usize,
}

/// Immutable, fully image-relative native bytes.
///
/// The publisher must copy `image_bytes()` contiguously without changing
/// offsets. Code is `[0, code_len)`, padding follows, and immutable constants
/// begin at `data_offset()`. RIP displacements are already resolved for that
/// layout; the relocation list exists for verification and object wrapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeImage {
    pub(crate) stamp: X86AbiStamp,
    pub(crate) output: OutputKind,
    pub(crate) shape: KernelShape,
    pub(crate) kernel_identity: CacheIdentity,
    pub(crate) entry_offset: u32,
    pub(crate) code_len: u32,
    pub(crate) data_offset: u32,
    pub(crate) image: Box<[u8]>,
    pub(crate) relocations: Box<[Relocation]>,
    pub(crate) stats: ImageStats,
}

impl NativeImage {
    #[must_use]
    pub const fn stamp(&self) -> X86AbiStamp {
        self.stamp
    }

    #[must_use]
    pub const fn output_kind(&self) -> OutputKind {
        self.output
    }

    #[must_use]
    pub const fn kernel_shape(&self) -> KernelShape {
        self.shape
    }

    #[must_use]
    pub const fn kernel_identity(&self) -> CacheIdentity {
        self.kernel_identity
    }

    #[must_use]
    pub const fn entry_offset(&self) -> u32 {
        self.entry_offset
    }

    #[must_use]
    pub fn code(&self) -> &[u8] {
        let end = usize::try_from(self.code_len).unwrap_or(0);
        self.image.get(..end).unwrap_or(&[])
    }

    #[must_use]
    pub fn data(&self) -> &[u8] {
        let start = usize::try_from(self.data_offset).unwrap_or(self.image.len());
        self.image.get(start..).unwrap_or(&[])
    }

    #[must_use]
    pub fn image_bytes(&self) -> &[u8] {
        &self.image
    }

    #[must_use]
    pub const fn data_offset(&self) -> u32 {
        self.data_offset
    }

    #[must_use]
    pub fn relocations(&self) -> &[Relocation] {
        &self.relocations
    }

    #[must_use]
    pub const fn stats(&self) -> ImageStats {
        self.stats
    }
}
