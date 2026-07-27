use super::{ASCII_NARROW_BYTES, AsciiByteSet, AsciiMasks16, AsciiRunResult, HIGH_NIBBLE_BITS};
#[cfg(test)]
use super::{ASCII_WIDE_BYTES, AsciiMasks32};

pub(super) fn classify_16(
    columns: &[u8; ASCII_NARROW_BYTES],
    bytes: &[u8; ASCII_NARROW_BYTES],
) -> AsciiMasks16 {
    let mut ascii = 0_u16;
    let mut members = 0_u16;
    for (lane, &byte) in bytes.iter().enumerate() {
        let lane_bit = 1_u16
            .checked_shl(u32::try_from(lane).expect("a 16-byte lane index fits in u32"))
            .expect("a 16-byte lane index is below the u16 width");
        if byte.is_ascii() {
            ascii |= lane_bit;
            let low_nibble = usize::from(byte & 0x0f);
            let high_nibble = usize::from(byte >> 4);
            if columns[low_nibble] & HIGH_NIBBLE_BITS[high_nibble] != 0 {
                members |= lane_bit;
            }
        }
    }
    AsciiMasks16::new(ascii, members)
}

pub(super) fn scan_run_forward(set: AsciiByteSet, bytes: &[u8]) -> AsciiRunResult {
    for (index, &byte) in bytes.iter().enumerate() {
        if !set.contains(byte) {
            return AsciiRunResult::new(
                index,
                index
                    .checked_add(1)
                    .expect("a live slice index is below usize::MAX"),
            );
        }
    }
    AsciiRunResult::new(bytes.len(), bytes.len())
}

pub(super) fn scan_run_backward(set: AsciiByteSet, bytes: &[u8]) -> AsciiRunResult {
    for (index, &byte) in bytes.iter().enumerate().rev() {
        if !set.contains(byte) {
            let member_run_len = bytes
                .len()
                .checked_sub(
                    index
                        .checked_add(1)
                        .expect("a live slice index is below usize::MAX"),
                )
                .expect("the nonmember index is within the slice");
            return AsciiRunResult::new(
                member_run_len,
                member_run_len
                    .checked_add(1)
                    .expect("a suffix shorter than its slice can include one nonmember"),
            );
        }
    }
    AsciiRunResult::new(bytes.len(), bytes.len())
}

#[cfg(test)]
pub(super) fn classify_32(
    columns: &[u8; ASCII_NARROW_BYTES],
    bytes: &[u8; ASCII_WIDE_BYTES],
) -> AsciiMasks32 {
    let first: &[u8; ASCII_NARROW_BYTES] = bytes[..ASCII_NARROW_BYTES]
        .try_into()
        .expect("the first half has exactly 16 bytes");
    let second: &[u8; ASCII_NARROW_BYTES] = bytes[ASCII_NARROW_BYTES..]
        .try_into()
        .expect("the second half has exactly 16 bytes");
    AsciiMasks32::from_halves(classify_16(columns, first), classify_16(columns, second))
}
