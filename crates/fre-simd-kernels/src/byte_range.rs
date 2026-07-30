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
    use super::{BYTE_SET_BLOCK_BYTES, classify_byte_delta_16, classify_byte_delta_16_scalar};

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
}
