//! Bounded integer codec for determinized-state representations.

use core::fmt;

pub const PLAN_ID: &str = "determinize-state.varint-zigzag.v1";
pub const MAX_ENCODED_BYTES: usize = 5;
const FIXED_WORK: usize = 32;
const WORK_PER_BYTE: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resource {
    InputBytes,
    OutputBytes,
    Work,
    SequentialReadBytes,
    SequentialWriteBytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_work: usize,
    pub max_sequential_read_bytes: usize,
    pub max_sequential_write_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: MAX_ENCODED_BYTES,
            max_output_bytes: MAX_ENCODED_BYTES,
            max_work: 128,
            max_sequential_read_bytes: MAX_ENCODED_BYTES,
            max_sequential_write_bytes: MAX_ENCODED_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub work: usize,
    pub sequential_read_bytes: usize,
    pub sequential_write_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decoded<T> {
    pub value: T,
    pub encoded_bytes: usize,
    pub accounting: Accounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    DestinationTooSmall {
        needed: usize,
        available: usize,
    },
    MissingTerminator {
        scanned: usize,
    },
    NonCanonical,
    ResourceLimit {
        resource: Resource,
        needed: usize,
        limit: usize,
    },
    ArithmeticOverflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestinationTooSmall { needed, available } => {
                write!(f, "destination needs {needed} bytes but has {available}")
            }
            Self::MissingTerminator { scanned } => {
                write!(f, "varint has no terminator in {scanned} bytes")
            }
            Self::NonCanonical => f.write_str("non-canonical u32 varint"),
            Self::ResourceLimit {
                resource,
                needed,
                limit,
            } => {
                write!(f, "{resource:?} requires {needed}, limit is {limit}")
            }
            Self::ArithmeticOverflow => f.write_str("state-codec arithmetic overflow"),
        }
    }
}

impl std::error::Error for Error {}

#[must_use]
pub const fn encoded_len(value: u32) -> usize {
    match value {
        0..=0x7F => 1,
        0x80..=0x3FFF => 2,
        0x4000..=0x1F_FFFF => 3,
        0x20_0000..=0x0FFF_FFFF => 4,
        _ => 5,
    }
}

pub fn encode_requirements(value: u32) -> Result<Accounting, Error> {
    let bytes = encoded_len(value);
    accounting(0, bytes, 0, bytes)
}

pub fn decode_requirements(input_len: usize) -> Result<Accounting, Error> {
    let bytes = input_len.min(MAX_ENCODED_BYTES);
    accounting(input_len, 0, bytes, 0)
}

fn accounting(
    input_bytes: usize,
    output_bytes: usize,
    reads: usize,
    writes: usize,
) -> Result<Accounting, Error> {
    let traversed = reads.checked_add(writes).ok_or(Error::ArithmeticOverflow)?;
    let work = traversed
        .checked_mul(WORK_PER_BYTE)
        .and_then(|n| FIXED_WORK.checked_add(n))
        .ok_or(Error::ArithmeticOverflow)?;
    Ok(Accounting {
        input_bytes,
        output_bytes,
        work,
        sequential_read_bytes: reads,
        sequential_write_bytes: writes,
    })
}

pub fn encode_u32(
    mut value: u32,
    destination: &mut [u8],
    limits: Limits,
) -> Result<Accounting, Error> {
    let required = encode_requirements(value)?;
    enforce(required, limits)?;
    if destination.len() < required.output_bytes {
        return Err(Error::DestinationTooSmall {
            needed: required.output_bytes,
            available: destination.len(),
        });
    }
    for byte in &mut destination[..required.output_bytes] {
        let low = u8::try_from(value & 0x7F).map_err(|_| Error::ArithmeticOverflow)?;
        value >>= 7;
        *byte = if value == 0 { low } else { low | 0x80 };
    }
    Ok(required)
}

pub fn decode_u32(input: &[u8], limits: Limits) -> Result<Decoded<u32>, Error> {
    let required = decode_requirements(input.len())?;
    enforce(required, limits)?;
    let scan = input.len().min(MAX_ENCODED_BYTES);
    let mut value = 0u32;
    for (index, &byte) in input[..scan].iter().enumerate() {
        let shift = u32::try_from(index)
            .map_err(|_| Error::ArithmeticOverflow)?
            .checked_mul(7)
            .ok_or(Error::ArithmeticOverflow)?;
        if index == 4 && byte > 0x0F {
            return Err(Error::NonCanonical);
        }
        value |= u32::from(byte & 0x7F)
            .checked_shl(shift)
            .ok_or(Error::ArithmeticOverflow)?;
        if byte < 0x80 {
            let encoded_bytes = index.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
            if encoded_len(value) != encoded_bytes {
                return Err(Error::NonCanonical);
            }
            return Ok(Decoded {
                value,
                encoded_bytes,
                accounting: required,
            });
        }
    }
    Err(Error::MissingTerminator { scanned: scan })
}

pub fn encode_i32(value: i32, destination: &mut [u8], limits: Limits) -> Result<Accounting, Error> {
    let bits = u32::from_ne_bytes(value.to_ne_bytes());
    let zigzag = if value < 0 { !(bits << 1) } else { bits << 1 };
    encode_u32(zigzag, destination, limits)
}

pub fn decode_i32(input: &[u8], limits: Limits) -> Result<Decoded<i32>, Error> {
    let decoded = decode_u32(input, limits)?;
    let mut value = i32::from_ne_bytes((decoded.value >> 1).to_ne_bytes());
    if decoded.value & 1 != 0 {
        value = !value;
    }
    Ok(Decoded {
        value,
        encoded_bytes: decoded.encoded_bytes,
        accounting: decoded.accounting,
    })
}

fn enforce(a: Accounting, l: Limits) -> Result<(), Error> {
    for (resource, needed, limit) in [
        (Resource::InputBytes, a.input_bytes, l.max_input_bytes),
        (Resource::OutputBytes, a.output_bytes, l.max_output_bytes),
        (Resource::Work, a.work, l.max_work),
        (
            Resource::SequentialReadBytes,
            a.sequential_read_bytes,
            l.max_sequential_read_bytes,
        ),
        (
            Resource::SequentialWriteBytes,
            a.sequential_write_bytes,
            l.max_sequential_write_bytes,
        ),
    ] {
        if needed > limit {
            return Err(Error::ResourceLimit {
                resource,
                needed,
                limit,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(a: Accounting) -> Limits {
        Limits {
            max_input_bytes: a.input_bytes,
            max_output_bytes: a.output_bytes,
            max_work: a.work,
            max_sequential_read_bytes: a.sequential_read_bytes,
            max_sequential_write_bytes: a.sequential_write_bytes,
        }
    }

    fn one_below(value: usize) -> usize {
        value.checked_sub(1).unwrap()
    }

    #[test]
    fn unsigned_roundtrips_boundaries() {
        for value in [0, 1, 127, 128, 16_383, 16_384, u32::MAX] {
            let e = encode_requirements(value).unwrap();
            let mut bytes = [0; MAX_ENCODED_BYTES];
            encode_u32(value, &mut bytes, limits(e)).unwrap();
            let d = decode_requirements(e.output_bytes).unwrap();
            assert_eq!(
                decode_u32(&bytes[..e.output_bytes], limits(d))
                    .unwrap()
                    .value,
                value
            );
        }
    }

    #[test]
    fn signed_roundtrips_boundaries() {
        for value in [i32::MIN, -16_384, -1, 0, 1, 16_384, i32::MAX] {
            let bits = u32::from_ne_bytes(value.to_ne_bytes());
            let zigzag = if value < 0 { !(bits << 1) } else { bits << 1 };
            let e = encode_requirements(zigzag).unwrap();
            let mut bytes = [0; MAX_ENCODED_BYTES];
            encode_i32(value, &mut bytes, limits(e)).unwrap();
            let d = decode_requirements(e.output_bytes).unwrap();
            assert_eq!(
                decode_i32(&bytes[..e.output_bytes], limits(d))
                    .unwrap()
                    .value,
                value
            );
        }
    }

    #[test]
    fn malformed_and_one_below_refuse() {
        assert_eq!(
            decode_u32(&[0x80; 5], Limits::default()),
            Err(Error::NonCanonical)
        );
        assert_eq!(
            decode_u32(&[0x80; 4], Limits::default()),
            Err(Error::MissingTerminator { scanned: 4 })
        );
        assert_eq!(
            decode_u32(&[0x80, 0], Limits::default()),
            Err(Error::NonCanonical)
        );
        let encoded = encode_requirements(128).unwrap();
        for resource in [
            Resource::OutputBytes,
            Resource::Work,
            Resource::SequentialWriteBytes,
        ] {
            let mut below = limits(encoded);
            match resource {
                Resource::OutputBytes => {
                    below.max_output_bytes = one_below(encoded.output_bytes);
                }
                Resource::Work => below.max_work = one_below(encoded.work),
                Resource::SequentialWriteBytes => {
                    below.max_sequential_write_bytes = one_below(encoded.sequential_write_bytes);
                }
                Resource::InputBytes | Resource::SequentialReadBytes => unreachable!(),
            }
            let mut output = [0xA5; 5];
            assert!(matches!(
                encode_u32(128, &mut output, below),
                Err(Error::ResourceLimit { resource: got, .. }) if got == resource
            ));
            assert_eq!(output, [0xA5; 5]);
        }
        let mut bytes = [0; 5];
        encode_u32(128, &mut bytes, limits(encoded)).unwrap();
        let decoded = decode_requirements(encoded.output_bytes).unwrap();
        for resource in [
            Resource::InputBytes,
            Resource::Work,
            Resource::SequentialReadBytes,
        ] {
            let mut below = limits(decoded);
            match resource {
                Resource::InputBytes => below.max_input_bytes = one_below(decoded.input_bytes),
                Resource::Work => below.max_work = one_below(decoded.work),
                Resource::SequentialReadBytes => {
                    below.max_sequential_read_bytes = one_below(decoded.sequential_read_bytes);
                }
                Resource::OutputBytes | Resource::SequentialWriteBytes => unreachable!(),
            }
            assert!(matches!(
                decode_u32(&bytes[..encoded.output_bytes], below),
                Err(Error::ResourceLimit { resource: got, .. }) if got == resource
            ));
        }
    }
}
