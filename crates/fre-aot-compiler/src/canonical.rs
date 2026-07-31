use sha2::{Digest, Sha256};

/// Conservative fixed work charged for entering and traversing one canonical
/// encoder/hash pass, excluding the bytes themselves.
pub(crate) const CANONICAL_TRAVERSAL_FIXED_WORK_V2: u64 = 16;
/// Conservative fixed work charged for finalizing one SHA-256 identity pass.
pub(crate) const IDENTITY_HASH_FINALIZE_WORK_V2: u64 = 8;
/// Current in-memory encoder/hash envelope. This is deliberately wider than
/// both concrete values (128-byte `CanonicalEncoder`, 112-byte `Sha256`) and
/// does not qualify any future external expectation wire.
pub(crate) const CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2: u64 = 256;
const CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2_USIZE: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanonicalError {
    ByteCountOverflow,
    MissingHasher,
}

pub(crate) struct CanonicalEncoder {
    hasher: Option<Sha256>,
    bytes: u64,
}

const _: () = assert!(
    core::mem::size_of::<CanonicalEncoder>() <= CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2_USIZE
);
const _: () =
    assert!(core::mem::size_of::<Sha256>() <= CURRENT_IDENTITY_SCRATCH_BYTES_UPPER_BOUND_V2_USIZE);

impl CanonicalEncoder {
    pub(crate) fn hashing() -> Self {
        Self {
            hasher: Some(Sha256::new()),
            bytes: 0,
        }
    }

    pub(crate) const fn counting() -> Self {
        Self {
            hasher: None,
            bytes: 0,
        }
    }

    pub(crate) fn raw(&mut self, bytes: &[u8]) -> Result<(), CanonicalError> {
        let additional =
            u64::try_from(bytes.len()).map_err(|_| CanonicalError::ByteCountOverflow)?;
        self.bytes = self
            .bytes
            .checked_add(additional)
            .ok_or(CanonicalError::ByteCountOverflow)?;
        if let Some(hasher) = &mut self.hasher {
            hasher.update(bytes);
        }
        Ok(())
    }

    pub(crate) fn boolean(&mut self, value: bool) -> Result<(), CanonicalError> {
        self.u8(u8::from(value))
    }

    pub(crate) fn u8(&mut self, value: u8) -> Result<(), CanonicalError> {
        self.raw(&[value])
    }

    pub(crate) fn u16(&mut self, value: u16) -> Result<(), CanonicalError> {
        self.raw(&value.to_le_bytes())
    }

    pub(crate) fn u32(&mut self, value: u32) -> Result<(), CanonicalError> {
        self.raw(&value.to_le_bytes())
    }

    pub(crate) fn u64(&mut self, value: u64) -> Result<(), CanonicalError> {
        self.raw(&value.to_le_bytes())
    }

    pub(crate) fn usize(&mut self, value: usize) -> Result<(), CanonicalError> {
        let value = u64::try_from(value).map_err(|_| CanonicalError::ByteCountOverflow)?;
        self.u64(value)
    }

    pub(crate) const fn bytes_written(&self) -> u64 {
        self.bytes
    }

    pub(crate) fn finish(self) -> Result<EncodedDigest, CanonicalError> {
        let digest = self.hasher.ok_or(CanonicalError::MissingHasher)?.finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Ok(EncodedDigest {
            bytes,
            hashed_bytes: self.bytes,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EncodedDigest {
    pub(crate) bytes: [u8; 32],
    pub(crate) hashed_bytes: u64,
}
