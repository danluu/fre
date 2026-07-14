use crate::OutputKind;

/// Current stable semantic contract encoded in every program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticsVersion(pub u16);

impl SemanticsVersion {
    pub const CURRENT: Self = Self(1);
}

/// Native backend calling convention required by this IR generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiVersion(pub u16);

impl AbiVersion {
    pub const CURRENT: Self = Self(1);
}

/// Index of a control-flow block.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockId(pub u32);

/// Index of an immutable data-pool entry.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DataId(pub u32);

/// Absolute whole-haystack anchors attached to a specialized pattern.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AnchorFlags {
    pub start: bool,
    pub end: bool,
}

/// A 256-bit byte membership set with a stable lane order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteClass {
    lanes: [u64; 4],
}

impl ByteClass {
    #[must_use]
    pub const fn empty() -> Self {
        Self { lanes: [0; 4] }
    }

    /// Build a membership set. Duplicate input bytes have no effect.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut class = Self::empty();
        for &byte in bytes {
            let lane = usize::from(byte / 64);
            let bit = u32::from(byte % 64);
            class.lanes[lane] |= 1_u64 << bit;
        }
        class
    }

    #[must_use]
    pub fn contains(self, byte: u8) -> bool {
        let lane = usize::from(byte / 64);
        let bit = u32::from(byte % 64);
        (self.lanes[lane] & (1_u64 << bit)) != 0
    }

    #[must_use]
    pub fn is_empty(self) -> bool {
        self.lanes.iter().all(|lane| *lane == 0)
    }

    #[must_use]
    pub const fn lanes(self) -> [u64; 4] {
        self.lanes
    }
}

/// Immutable material referenced by native blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataBlob {
    Bytes(Vec<u8>),
    ByteClass(ByteClass),
}

/// One structured native operation. Every successor is explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockOp {
    Entry {
        next: BlockId,
    },
    ScanLiteral {
        needle: DataId,
        anchors: AnchorFlags,
        matched: BlockId,
        exhausted: BlockId,
    },
    ScanClassStart {
        class: DataId,
        anchored_start: bool,
        run: BlockId,
        exhausted: BlockId,
    },
    ExtendClassRun {
        class: DataId,
        next: BlockId,
    },
    ConfirmSuffix {
        suffix: DataId,
        anchored_end: bool,
        matched: BlockId,
        rejected: BlockId,
    },
    AdvanceAfterReject {
        next: BlockId,
    },
    ReturnFound,
    ReturnNone,
}

impl BlockOp {
    pub(crate) fn successors(&self) -> ([Option<BlockId>; 2], usize) {
        match *self {
            Self::Entry { next }
            | Self::ExtendClassRun { next, .. }
            | Self::AdvanceAfterReject { next } => ([Some(next), None], 1),
            Self::ScanLiteral {
                matched, exhausted, ..
            }
            | Self::ConfirmSuffix {
                matched,
                rejected: exhausted,
                ..
            } => ([Some(matched), Some(exhausted)], 2),
            Self::ScanClassStart { run, exhausted, .. } => ([Some(run), Some(exhausted)], 2),
            Self::ReturnFound | Self::ReturnNone => ([None, None], 0),
        }
    }
}

/// A numbered control-flow block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub op: BlockOp,
}

/// Mutable, untrusted interchange form accepted by the total validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawProgram {
    pub schema_version: u16,
    pub semantics: SemanticsVersion,
    pub abi: AbiVersion,
    pub output: OutputKind,
    pub entry: BlockId,
    pub blocks: Vec<Block>,
    pub data: Vec<DataBlob>,
}

impl RawProgram {
    pub const SCHEMA_VERSION: u16 = 1;
}
