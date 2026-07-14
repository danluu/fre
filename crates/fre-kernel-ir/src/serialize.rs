use core::fmt;

use sha2::{Digest, Sha256};

use crate::{
    AbiVersion, AnchorFlags, BlockId, BlockOp, DataBlob, DataId, OutputKind, RawProgram,
    SemanticsVersion, error::ResourceKind,
};

/// Stable SHA-256 identity of the complete serialized semantic program.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CacheIdentity([u8; 32]);

impl CacheIdentity {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CacheIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CacheIdentity({self})")
    }
}

impl fmt::Display for CacheIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Deterministic, endian-independent cache and AOT interchange bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SerializedProgram(Box<[u8]>);

impl SerializedProgram {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn identity(&self) -> CacheIdentity {
        let digest = Sha256::digest(&self.0);
        let mut identity = [0_u8; 32];
        identity.copy_from_slice(&digest);
        CacheIdentity(identity)
    }
}

pub(crate) fn serialized_size(raw: &RawProgram) -> Option<usize> {
    // magic + three versions + output + entry + block/data counts
    let mut size = 8_usize
        .checked_add(2)?
        .checked_add(2)?
        .checked_add(2)?
        .checked_add(1)?
        .checked_add(4)?
        .checked_add(4)?
        .checked_add(4)?;
    for block in &raw.blocks {
        let operands = match block.op {
            BlockOp::Entry { .. } | BlockOp::AdvanceAfterReject { .. } => 4,
            BlockOp::ExtendClassRun { .. } => 8,
            BlockOp::ScanLiteral { .. }
            | BlockOp::ScanClassStart { .. }
            | BlockOp::ConfirmSuffix { .. } => 4 + 1 + 4 + 4,
            BlockOp::ReturnFound | BlockOp::ReturnNone => 0,
        };
        size = size.checked_add(1)?.checked_add(operands)?;
    }
    for blob in &raw.data {
        size = size.checked_add(1)?.checked_add(4)?;
        size = match blob {
            DataBlob::Bytes(bytes) => size.checked_add(bytes.len())?,
            DataBlob::ByteClass(_) => size.checked_add(32)?,
        };
    }
    Some(size)
}

pub(crate) fn serialize(
    raw: &RawProgram,
    expected_size: usize,
) -> Result<SerializedProgram, ResourceKind> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_size)
        .map_err(|_| ResourceKind::SerializedBytes)?;
    bytes.extend_from_slice(b"FREKIR\0\x01");
    put_u16(&mut bytes, raw.schema_version);
    put_version(&mut bytes, raw.semantics, raw.abi);
    bytes.push(output_tag(raw.output));
    put_block(&mut bytes, raw.entry);
    put_u32(&mut bytes, raw.blocks.len());
    put_u32(&mut bytes, raw.data.len());
    for block in &raw.blocks {
        put_op(&mut bytes, &block.op);
    }
    for blob in &raw.data {
        match blob {
            DataBlob::Bytes(value) => {
                bytes.push(1);
                put_u32(&mut bytes, value.len());
                bytes.extend_from_slice(value);
            }
            DataBlob::ByteClass(class) => {
                bytes.push(2);
                put_u32(&mut bytes, 32);
                for lane in class.lanes() {
                    bytes.extend_from_slice(&lane.to_le_bytes());
                }
            }
        }
    }
    debug_assert_eq!(bytes.len(), expected_size);
    Ok(SerializedProgram(bytes.into_boxed_slice()))
}

fn put_version(bytes: &mut Vec<u8>, semantics: SemanticsVersion, abi: AbiVersion) {
    put_u16(bytes, semantics.0);
    put_u16(bytes, abi.0);
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut Vec<u8>, value: usize) {
    let value = u32::try_from(value).expect("validated program dimensions fit u32");
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_block(bytes: &mut Vec<u8>, block: BlockId) {
    bytes.extend_from_slice(&block.0.to_le_bytes());
}

fn put_data(bytes: &mut Vec<u8>, data: DataId) {
    bytes.extend_from_slice(&data.0.to_le_bytes());
}

const fn output_tag(output: OutputKind) -> u8 {
    match output {
        OutputKind::Exists => 1,
        OutputKind::SelectedEnd => 2,
        OutputKind::Span => 3,
    }
}

fn put_anchor(bytes: &mut Vec<u8>, anchors: AnchorFlags) {
    bytes.push(u8::from(anchors.start) | (u8::from(anchors.end) << 1));
}

fn put_op(bytes: &mut Vec<u8>, op: &BlockOp) {
    match *op {
        BlockOp::Entry { next } => {
            bytes.push(1);
            put_block(bytes, next);
        }
        BlockOp::ScanLiteral {
            needle,
            anchors,
            matched,
            exhausted,
        } => {
            bytes.push(2);
            put_data(bytes, needle);
            put_anchor(bytes, anchors);
            put_block(bytes, matched);
            put_block(bytes, exhausted);
        }
        BlockOp::ScanClassStart {
            class,
            anchored_start,
            run,
            exhausted,
        } => {
            bytes.push(3);
            put_data(bytes, class);
            bytes.push(u8::from(anchored_start));
            put_block(bytes, run);
            put_block(bytes, exhausted);
        }
        BlockOp::ExtendClassRun { class, next } => {
            bytes.push(4);
            put_data(bytes, class);
            put_block(bytes, next);
        }
        BlockOp::ConfirmSuffix {
            suffix,
            anchored_end,
            matched,
            rejected,
        } => {
            bytes.push(5);
            put_data(bytes, suffix);
            bytes.push(u8::from(anchored_end));
            put_block(bytes, matched);
            put_block(bytes, rejected);
        }
        BlockOp::AdvanceAfterReject { next } => {
            bytes.push(6);
            put_block(bytes, next);
        }
        BlockOp::ReturnFound => bytes.push(7),
        BlockOp::ReturnNone => bytes.push(8),
    }
}
