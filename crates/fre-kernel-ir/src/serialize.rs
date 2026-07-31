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
///
/// The backing allocation is deliberately retained as a `Vec`: converting an
/// allocator-rounded capacity into a boxed slice may allocate and copy again.
/// Construction records and limits that retained capacity explicitly. The
/// identity is computed once during admitted construction and cached so that
/// public identity reads cannot trigger an unmetered hash.
#[derive(Debug, Eq, PartialEq)]
pub struct SerializedProgram {
    bytes: Vec<u8>,
    identity: CacheIdentity,
}

impl SerializedProgram {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Bytes retained by the serialization allocation, including allocator
    /// capacity above the canonical byte length.
    #[must_use]
    pub fn retained_capacity_bytes(&self) -> usize {
        self.bytes.capacity()
    }

    #[must_use]
    pub const fn identity(&self) -> CacheIdentity {
        self.identity
    }
}

pub(crate) fn serialize(
    raw: &RawProgram,
    expected_size: usize,
    max_retained_capacity_bytes: u64,
    admit_capacity: impl FnOnce(usize) -> Result<(), crate::ValidateError>,
) -> Result<SerializedProgram, crate::ValidateError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_size)
        .map_err(|_| crate::ValidateError::AllocationFailed {
            resource: ResourceKind::SerializedBytes,
        })?;
    let retained_capacity =
        u64::try_from(bytes.capacity()).map_err(|_| crate::ValidateError::ResourceLimit {
            resource: ResourceKind::SerializedCapacityBytes,
            limit: max_retained_capacity_bytes,
            required: u64::MAX,
        })?;
    if retained_capacity > max_retained_capacity_bytes {
        return Err(crate::ValidateError::ResourceLimit {
            resource: ResourceKind::SerializedCapacityBytes,
            limit: max_retained_capacity_bytes,
            required: retained_capacity,
        });
    }
    admit_capacity(bytes.capacity())?;
    if bytes.capacity() < expected_size {
        return Err(crate::ValidateError::SerializationLengthMismatch {
            expected: expected_size,
            attempted: bytes.capacity(),
        });
    }
    bytes.resize(expected_size, 0);
    let mut writer = FixedWriter::new(&mut bytes);
    writer.raw(b"FREKIR\0\x01")?;
    writer.u16(raw.schema_version)?;
    writer.version(raw.semantics, raw.abi)?;
    writer.byte(output_tag(raw.output))?;
    writer.block(raw.entry)?;
    writer.u32(raw.blocks.len())?;
    writer.u32(raw.data.len())?;
    for block in &raw.blocks {
        writer.op(&block.op)?;
    }
    for blob in &raw.data {
        match blob {
            DataBlob::Bytes(value) => {
                writer.byte(1)?;
                writer.u32(value.len())?;
                writer.raw(value)?;
            }
            DataBlob::ByteClass(class) => {
                writer.byte(2)?;
                writer.u32(32)?;
                for lane in class.lanes() {
                    writer.raw(&lane.to_le_bytes())?;
                }
            }
        }
    }
    writer.finish()?;
    let digest = Sha256::digest(&bytes);
    let mut identity = [0_u8; 32];
    identity.copy_from_slice(&digest);
    Ok(SerializedProgram {
        bytes,
        identity: CacheIdentity(identity),
    })
}

pub(crate) const fn serialization_inline_scratch_bytes() -> usize {
    core::mem::size_of::<Vec<u8>>().saturating_add(core::mem::size_of::<FixedWriter<'static>>())
}

pub(crate) const fn identity_inline_scratch_bytes() -> usize {
    core::mem::size_of::<Sha256>()
        .saturating_add(2_usize.saturating_mul(core::mem::size_of::<[u8; 32]>()))
}

struct FixedWriter<'a> {
    bytes: &'a mut [u8],
    cursor: usize,
}

impl<'a> FixedWriter<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        FixedWriter { bytes, cursor: 0 }
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), crate::ValidateError> {
        let end = self.cursor.checked_add(value.len()).ok_or(
            crate::ValidateError::ArithmeticOverflow {
                site: crate::ArithmeticSite::SerializedBytes,
            },
        )?;
        let expected = self.bytes.len();
        let destination = self.bytes.get_mut(self.cursor..end).ok_or(
            crate::ValidateError::SerializationLengthMismatch {
                expected,
                attempted: end,
            },
        )?;
        destination.copy_from_slice(value);
        self.cursor = end;
        Ok(())
    }

    fn finish(self) -> Result<(), crate::ValidateError> {
        if self.cursor != self.bytes.len() {
            return Err(crate::ValidateError::SerializationLengthMismatch {
                expected: self.bytes.len(),
                attempted: self.cursor,
            });
        }
        Ok(())
    }

    fn byte(&mut self, value: u8) -> Result<(), crate::ValidateError> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), crate::ValidateError> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: usize) -> Result<(), crate::ValidateError> {
        let value = u32::try_from(value).map_err(|_| crate::ValidateError::ArithmeticOverflow {
            site: crate::ArithmeticSite::SerializedBytes,
        })?;
        self.raw(&value.to_le_bytes())
    }

    fn version(
        &mut self,
        semantics: SemanticsVersion,
        abi: AbiVersion,
    ) -> Result<(), crate::ValidateError> {
        self.u16(semantics.0)?;
        self.u16(abi.0)
    }

    fn block(&mut self, block: BlockId) -> Result<(), crate::ValidateError> {
        self.raw(&block.0.to_le_bytes())
    }

    fn data(&mut self, data: DataId) -> Result<(), crate::ValidateError> {
        self.raw(&data.0.to_le_bytes())
    }

    fn anchor(&mut self, anchors: AnchorFlags) -> Result<(), crate::ValidateError> {
        self.byte(u8::from(anchors.start) | (u8::from(anchors.end) << 1))
    }

    fn op(&mut self, op: &BlockOp) -> Result<(), crate::ValidateError> {
        match *op {
            BlockOp::Entry { next } => {
                self.byte(1)?;
                self.block(next)?;
            }
            BlockOp::ScanLiteral {
                needle,
                anchors,
                matched,
                exhausted,
            } => {
                self.byte(2)?;
                self.data(needle)?;
                self.anchor(anchors)?;
                self.block(matched)?;
                self.block(exhausted)?;
            }
            BlockOp::ScanClassStart {
                class,
                anchored_start,
                run,
                exhausted,
            } => {
                self.byte(3)?;
                self.data(class)?;
                self.byte(u8::from(anchored_start))?;
                self.block(run)?;
                self.block(exhausted)?;
            }
            BlockOp::ExtendClassRun { class, next } => {
                self.byte(4)?;
                self.data(class)?;
                self.block(next)?;
            }
            BlockOp::ConfirmSuffix {
                suffix,
                anchored_end,
                matched,
                rejected,
            } => {
                self.byte(5)?;
                self.data(suffix)?;
                self.byte(u8::from(anchored_end))?;
                self.block(matched)?;
                self.block(rejected)?;
            }
            BlockOp::AdvanceAfterReject { next } => {
                self.byte(6)?;
                self.block(next)?;
            }
            BlockOp::ReturnFound => self.byte(7)?,
            BlockOp::ReturnNone => self.byte(8)?,
        }
        Ok(())
    }
}

const fn output_tag(output: OutputKind) -> u8 {
    match output {
        OutputKind::Exists => 1,
        OutputKind::SelectedEnd => 2,
        OutputKind::Span => 3,
    }
}

#[cfg(test)]
mod fixed_writer_tests {
    use super::FixedWriter;

    #[test]
    fn fixed_writer_refuses_overflow_and_underfill() {
        let mut overflow = [0_u8; 2];
        let error = FixedWriter::new(&mut overflow)
            .raw(&[1, 2, 3])
            .expect_err("fixed writer cannot grow");
        assert!(matches!(
            error,
            crate::ValidateError::SerializationLengthMismatch {
                expected: 2,
                attempted: 3
            }
        ));

        let mut underfill = [0_u8; 2];
        let mut writer = FixedWriter::new(&mut underfill);
        writer.raw(&[1]).expect("one admitted byte");
        let error = writer.finish().expect_err("underfill is not canonical");
        assert!(matches!(
            error,
            crate::ValidateError::SerializationLengthMismatch {
                expected: 2,
                attempted: 1
            }
        ));
    }
}
