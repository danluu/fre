//! Compile-time-specialized classification for one bounded wrapping delta.

use crate::{BYTE_SET_BLOCK_BYTES, ByteSetMask16};

/// Classify one exact sixteen-byte block by modular distance from `origin`.
///
/// Bit `i` is set exactly when
/// `bytes[i].wrapping_sub(origin) <= maximum_delta`. A caller that proves
/// `origin.checked_add(maximum_delta).is_some()` therefore classifies the
/// ordinary inclusive range `origin..=origin + maximum_delta`.
///
/// The implementation is fixed by compiler target features. This operation
/// performs no runtime feature detection or indirect dispatch.
#[must_use]
#[inline]
#[allow(
    unsafe_code,
    reason = "compiler target features select a private fixed-width leaf whose source extent is proven by the public array type"
)]
pub fn classify_byte_delta_16(
    origin: u8,
    maximum_delta: u8,
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    {
        // SAFETY: the compiler target guarantees NEON, and the fixed array
        // proves the complete source extent required by the private leaf.
        unsafe { crate::aarch64::classify_byte_delta_16_neon(origin, maximum_delta, bytes) }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    {
        // SAFETY: the compiler target guarantees SSE2, and the fixed array
        // proves the complete source extent required by the private leaf.
        unsafe { crate::x86_64::classify_byte_delta_16_sse2(origin, maximum_delta, bytes) }
    }

    #[cfg(not(any(
        all(target_arch = "aarch64", target_feature = "neon"),
        all(target_arch = "x86_64", target_feature = "sse2")
    )))]
    classify_byte_delta_16_scalar(origin, maximum_delta, bytes)
}

/// Find the first byte within one bounded wrapping delta.
///
/// Compiler target features select the fixed-width classifier once around
/// the complete-slice loop. When `origin + maximum_delta` does not wrap, this
/// finds the first byte in the ordinary inclusive range.
#[must_use]
#[inline]
#[allow(
    unsafe_code,
    reason = "compiler target features select the whole-slice NEON leaf without runtime detection"
)]
pub fn find_byte_delta(origin: u8, maximum_delta: u8, bytes: &[u8]) -> Option<usize> {
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    {
        // SAFETY: NEON is guaranteed by compiler target features.
        unsafe { crate::aarch64::find_byte_delta_neon(origin, maximum_delta, bytes) }
    }

    #[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
    {
        let complete_len = bytes
            .len()
            .checked_sub(bytes.len() % BYTE_SET_BLOCK_BYTES)
            .expect("a remainder cannot exceed its source length");
        for (block_index, block) in bytes[..complete_len]
            .chunks_exact(BYTE_SET_BLOCK_BYTES)
            .enumerate()
        {
            let block: &[u8; BYTE_SET_BLOCK_BYTES] = block
                .try_into()
                .expect("an exact chunk has the fixed block extent");
            let member_mask = classify_byte_delta_16(origin, maximum_delta, block).member_mask();
            if member_mask != 0 {
                let block_start = block_index
                    .checked_mul(BYTE_SET_BLOCK_BYTES)
                    .expect("a complete block index is bounded by the source slice");
                return block_start.checked_add(
                    usize::try_from(member_mask.trailing_zeros())
                        .expect("a 16-bit lane index fits in usize"),
                );
            }
        }
        bytes[complete_len..]
            .iter()
            .position(|byte| byte.wrapping_sub(origin) <= maximum_delta)
            .and_then(|relative| complete_len.checked_add(relative))
    }
}

#[cfg_attr(
    any(
        all(target_arch = "aarch64", target_feature = "neon"),
        all(target_arch = "x86_64", target_feature = "sse2")
    ),
    allow(
        dead_code,
        reason = "vector compiler targets retain the scalar implementation only for differential tests"
    )
)]
fn classify_byte_delta_16_scalar(
    origin: u8,
    maximum_delta: u8,
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    let members = bytes.iter().enumerate().fold(0_u16, |mask, (lane, &byte)| {
        mask | (u16::from(byte.wrapping_sub(origin) <= maximum_delta) << lane)
    });
    ByteSetMask16::new(members)
}

#[cfg(test)]
mod tests {
    use super::{
        BYTE_SET_BLOCK_BYTES, classify_byte_delta_16, classify_byte_delta_16_scalar,
        find_byte_delta,
    };

    #[test]
    fn selected_range_classifier_matches_scalar_for_all_bounds() {
        for start in 0_u8..=u8::MAX {
            for end in start..=u8::MAX {
                let bytes: [u8; BYTE_SET_BLOCK_BYTES] = core::array::from_fn(|lane| {
                    u8::try_from(
                        lane.wrapping_mul(197)
                            .wrapping_add(usize::from(start))
                            .wrapping_add(usize::from(end))
                            & 255,
                    )
                    .expect("the masked byte fits in u8")
                });
                assert_eq!(
                    classify_byte_delta_16(start, end.wrapping_sub(start), &bytes),
                    classify_byte_delta_16_scalar(start, end.wrapping_sub(start), &bytes),
                    "range {start:#04x}..={end:#04x} bytes={bytes:?}"
                );
            }
        }
    }

    #[test]
    fn whole_slice_range_finder_matches_scalar_across_boundaries_and_alignments() {
        for alignment in 0..=31 {
            for len in [0_usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 129] {
                for (origin, maximum_delta) in [(b'a', 25), (0, 0), (240, 15), (250, 10)] {
                    let nonmember = origin.wrapping_add(maximum_delta).wrapping_add(1);
                    let mut source = vec![nonmember; alignment + len];
                    let bytes = &source[alignment..];
                    assert_eq!(find_byte_delta(origin, maximum_delta, bytes), None);
                    for position in [0_usize, 1, 15, 16, 17, 31, 32, 63, 64, 128] {
                        if position >= len {
                            continue;
                        }
                        source[alignment + position] = origin.wrapping_add(maximum_delta);
                        let bytes = &source[alignment..];
                        assert_eq!(
                            find_byte_delta(origin, maximum_delta, bytes),
                            bytes
                                .iter()
                                .position(|byte| byte.wrapping_sub(origin) <= maximum_delta),
                            "alignment={alignment} len={len} position={position} origin={origin:#04x} delta={maximum_delta}",
                        );
                        source[alignment + position] = nonmember;
                    }
                }
            }
        }
    }
}
