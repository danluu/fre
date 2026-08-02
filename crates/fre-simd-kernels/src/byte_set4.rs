//! Compile-time-specialized classification for four arbitrary byte values.

use crate::{BYTE_SET_BLOCK_BYTES, ByteSetMask16};

/// Classify one exact sixteen-byte block against four arbitrary byte values.
///
/// Bit `i` is set exactly when `bytes[i]` equals at least one value in
/// `members`. Duplicate member values are harmless. The implementation is
/// fixed by compiler target features and performs no runtime feature detection
/// or indirect dispatch.
#[must_use]
#[inline]
#[allow(
    unsafe_code,
    reason = "compiler target features select a private fixed-width leaf whose source extent is proven by the public array type"
)]
pub fn classify_byte_set4_16(
    members: [u8; 4],
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    #[cfg(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    {
        // SAFETY: the compiler target guarantees SVE plus SVE2, and the fixed
        // array proves the complete source extent required by the private leaf.
        unsafe { crate::aarch64_sve2::classify_byte_set4_16_sve2(members, bytes) }
    }

    #[cfg(all(
        target_arch = "aarch64",
        target_feature = "neon",
        not(all(
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ))
    ))]
    {
        // SAFETY: the compiler target guarantees NEON, and the fixed array
        // proves the complete source extent required by the private leaf.
        unsafe { crate::aarch64::classify_byte_set4_16_neon(members, bytes) }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    {
        // SAFETY: the compiler target guarantees SSE2, and the fixed array
        // proves the complete source extent required by the private leaf.
        unsafe { crate::x86_64::classify_byte_set4_16_sse2(members, bytes) }
    }

    #[cfg(not(any(
        all(
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ),
        all(target_arch = "aarch64", target_feature = "neon"),
        all(target_arch = "x86_64", target_feature = "sse2")
    )))]
    classify_byte_set4_16_scalar(members, bytes)
}

#[cfg_attr(
    any(
        all(
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ),
        all(target_arch = "aarch64", target_feature = "neon"),
        all(target_arch = "x86_64", target_feature = "sse2")
    ),
    allow(
        dead_code,
        reason = "vector compiler targets retain the scalar implementation only for differential tests"
    )
)]
fn classify_byte_set4_16_scalar(
    members: [u8; 4],
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    let member_mask = bytes.iter().enumerate().fold(0_u16, |mask, (lane, &byte)| {
        mask | (u16::from(members.contains(&byte)) << lane)
    });
    ByteSetMask16::new(member_mask)
}

#[cfg(test)]
mod tests {
    use super::{BYTE_SET_BLOCK_BYTES, classify_byte_set4_16, classify_byte_set4_16_scalar};

    fn next_random(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn selected_set4_classifier_matches_scalar_for_full_domain_and_alignments() {
        let mut random = 0x8f3f_73b5_cf1c_9ade_u64;
        let mut source = [0_u8; BYTE_SET_BLOCK_BYTES + 31];
        for case in 0_u16..=u16::from(u8::MAX) {
            let members = [
                u8::try_from(case).unwrap(),
                u8::try_from(case.wrapping_mul(73) & 255).unwrap(),
                u8::try_from(case.wrapping_mul(151).wrapping_add(17) & 255).unwrap(),
                u8::try_from(case.wrapping_mul(239).wrapping_add(193) & 255).unwrap(),
            ];
            for (index, byte) in source.iter_mut().enumerate() {
                *byte = u8::try_from(
                    next_random(&mut random)
                        .wrapping_add(u64::try_from(index.wrapping_mul(197)).unwrap())
                        & 255,
                )
                .unwrap();
            }
            for alignment in 0..=31 {
                let block: &[u8; BYTE_SET_BLOCK_BYTES] = source
                    [alignment..alignment + BYTE_SET_BLOCK_BYTES]
                    .try_into()
                    .unwrap();
                assert_eq!(
                    classify_byte_set4_16(members, block),
                    classify_byte_set4_16_scalar(members, block),
                    "members={members:?} alignment={alignment} block={block:?}"
                );
            }
        }
    }

    #[test]
    fn duplicate_members_are_exact_for_every_byte_and_lane() {
        for member in 0_u8..=u8::MAX {
            for lane in 0..BYTE_SET_BLOCK_BYTES {
                let mut block = core::array::from_fn(|index| {
                    member
                        .wrapping_add(u8::try_from(index).unwrap())
                        .wrapping_add(1)
                });
                block[lane] = member;
                assert_eq!(
                    classify_byte_set4_16([member; 4], &block).member_mask(),
                    1_u16 << lane,
                    "member={member:#04x} lane={lane} block={block:?}"
                );
            }
        }
    }
}
