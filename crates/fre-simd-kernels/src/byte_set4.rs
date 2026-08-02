//! Compile-time-specialized classification for four arbitrary byte values.

use crate::{BYTE_SET_BLOCK_BYTES, BYTE_SET_WIDE_BLOCK_BYTES, ByteSetMask16, ByteSetMask32};

/// Classify one exact sixteen-byte block against one byte value.
#[must_use]
#[inline]
#[allow(
    unsafe_code,
    reason = "compiler target features select a private exact-one leaf whose source extent is proven by the public array type"
)]
pub fn classify_byte_set1_16(member: u8, bytes: &[u8; BYTE_SET_BLOCK_BYTES]) -> ByteSetMask16 {
    #[cfg(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    {
        unsafe { crate::aarch64_sve2::classify_byte_set1_16_sve2(member, bytes) }
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
        unsafe { crate::aarch64::classify_byte_set1_16_neon(member, bytes) }
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    {
        unsafe { crate::x86_64::classify_byte_set1_16_sse2(member, bytes) }
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
    classify_byte_members_16_scalar(&[member], bytes)
}

/// Classify one exact sixteen-byte block against two byte values.
#[must_use]
#[inline]
#[allow(
    unsafe_code,
    reason = "compiler target features select a private exact-two leaf whose source extent is proven by the public array type"
)]
pub fn classify_byte_set2_16(
    members: [u8; 2],
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
        unsafe { crate::aarch64_sve2::classify_byte_set2_16_sve2(members, bytes) }
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
        unsafe { crate::aarch64::classify_byte_set2_16_neon(members, bytes) }
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    {
        unsafe { crate::x86_64::classify_byte_set2_16_sse2(members, bytes) }
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
    classify_byte_members_16_scalar(&members, bytes)
}

/// Classify one exact sixteen-byte block against three byte values.
#[must_use]
#[inline]
#[allow(
    unsafe_code,
    reason = "compiler target features select a private exact-three leaf whose source extent is proven by the public array type"
)]
pub fn classify_byte_set3_16(
    members: [u8; 3],
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
        unsafe { crate::aarch64_sve2::classify_byte_set3_16_sve2(members, bytes) }
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
        unsafe { crate::aarch64::classify_byte_set3_16_neon(members, bytes) }
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    {
        unsafe { crate::x86_64::classify_byte_set3_16_sse2(members, bytes) }
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
    classify_byte_members_16_scalar(&members, bytes)
}

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

/// Classify one exact 32-byte block against one byte value.
#[must_use]
#[inline]
#[allow(
    unsafe_code,
    reason = "authenticated compiler-static profiles select private exact-one wide leaves whose source extent is proven by the public array type"
)]
pub fn classify_byte_set1_32(member: u8, bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES]) -> ByteSetMask32 {
    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    {
        unsafe { crate::aarch64_sve2::classify_byte_set1_32_sve2(member, bytes) }
    }
    #[cfg(all(
        feature = "static-dispatch",
        target_arch = "x86_64",
        target_feature = "avx2"
    ))]
    {
        unsafe { crate::x86_64::classify_byte_set1_32_avx2(member, bytes) }
    }
    #[cfg(not(any(
        all(
            feature = "static-dispatch-arm-41-d84",
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ),
        all(
            feature = "static-dispatch",
            target_arch = "x86_64",
            target_feature = "avx2"
        )
    )))]
    split_32(bytes, |block| classify_byte_set1_16(member, block))
}

/// Classify one exact 32-byte block against two byte values.
#[must_use]
#[inline]
#[allow(
    unsafe_code,
    reason = "authenticated compiler-static profiles select private exact-two wide leaves whose source extent is proven by the public array type"
)]
pub fn classify_byte_set2_32(
    members: [u8; 2],
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    {
        unsafe { crate::aarch64_sve2::classify_byte_set2_32_sve2(members, bytes) }
    }
    #[cfg(all(
        feature = "static-dispatch",
        target_arch = "x86_64",
        target_feature = "avx2"
    ))]
    {
        unsafe { crate::x86_64::classify_byte_set2_32_avx2(members, bytes) }
    }
    #[cfg(not(any(
        all(
            feature = "static-dispatch-arm-41-d84",
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ),
        all(
            feature = "static-dispatch",
            target_arch = "x86_64",
            target_feature = "avx2"
        )
    )))]
    split_32(bytes, |block| classify_byte_set2_16(members, block))
}

/// Classify one exact 32-byte block against three byte values.
#[must_use]
#[inline]
#[allow(
    unsafe_code,
    reason = "authenticated compiler-static profiles select private exact-three wide leaves whose source extent is proven by the public array type"
)]
pub fn classify_byte_set3_32(
    members: [u8; 3],
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    {
        unsafe { crate::aarch64_sve2::classify_byte_set3_32_sve2(members, bytes) }
    }
    #[cfg(all(
        feature = "static-dispatch",
        target_arch = "x86_64",
        target_feature = "avx2"
    ))]
    {
        unsafe { crate::x86_64::classify_byte_set3_32_avx2(members, bytes) }
    }
    #[cfg(not(any(
        all(
            feature = "static-dispatch-arm-41-d84",
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ),
        all(
            feature = "static-dispatch",
            target_arch = "x86_64",
            target_feature = "avx2"
        )
    )))]
    split_32(bytes, |block| classify_byte_set3_16(members, block))
}

/// Classify one exact 32-byte block against four arbitrary byte values.
///
/// Portable builds compose two fixed 16-byte operations. A native 32-byte
/// leaf is selected only by an authenticated compiler-static profile, so this
/// operation introduces neither runtime feature discovery nor indirect
/// dispatch into a candidate loop.
#[must_use]
#[inline]
#[allow(
    unsafe_code,
    reason = "authenticated compiler-static profiles select private wide leaves whose complete source extent is proven by the public array type"
)]
pub fn classify_byte_set4_32(
    members: [u8; 4],
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    {
        // SAFETY: the authenticated static profile proves SVE plus SVE2, and
        // the fixed array proves the complete source extent.
        unsafe { crate::aarch64_sve2::classify_byte_set4_32_sve2(members, bytes) }
    }

    #[cfg(all(
        feature = "static-dispatch",
        target_arch = "x86_64",
        target_feature = "avx2"
    ))]
    {
        // SAFETY: the authenticated static profile proves AVX2, and the fixed
        // array proves the complete source extent.
        unsafe { crate::x86_64::classify_byte_set4_32_avx2(members, bytes) }
    }

    #[cfg(not(any(
        all(
            feature = "static-dispatch-arm-41-d84",
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ),
        all(
            feature = "static-dispatch",
            target_arch = "x86_64",
            target_feature = "avx2"
        )
    )))]
    split_32(bytes, |block| classify_byte_set4_16(members, block))
}

#[inline]
#[cfg_attr(
    any(
        all(
            feature = "static-dispatch-arm-41-d84",
            target_arch = "aarch64",
            target_os = "linux",
            target_endian = "little",
            target_feature = "sve",
            target_feature = "sve2"
        ),
        all(
            feature = "static-dispatch",
            target_arch = "x86_64",
            target_feature = "avx2"
        )
    ),
    allow(
        dead_code,
        reason = "authenticated native-wide profiles do not execute the portable split operation"
    )
)]
fn split_32(
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
    mut classify_16: impl FnMut(&[u8; BYTE_SET_BLOCK_BYTES]) -> ByteSetMask16,
) -> ByteSetMask32 {
    let first: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[..BYTE_SET_BLOCK_BYTES]
        .try_into()
        .expect("the first wide half is exactly sixteen bytes");
    let second: &[u8; BYTE_SET_BLOCK_BYTES] = bytes[BYTE_SET_BLOCK_BYTES..]
        .try_into()
        .expect("the second wide half is exactly sixteen bytes");
    ByteSetMask32::from_halves(classify_16(first), classify_16(second))
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
    classify_byte_members_16_scalar(&members, bytes)
}

fn classify_byte_members_16_scalar(
    members: &[u8],
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    ByteSetMask16::new(bytes.iter().enumerate().fold(0_u16, |mask, (lane, &byte)| {
        mask | (u16::from(members.contains(&byte)) << lane)
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        BYTE_SET_BLOCK_BYTES, BYTE_SET_WIDE_BLOCK_BYTES, ByteSetMask32, classify_byte_set1_16,
        classify_byte_set1_32, classify_byte_set2_16, classify_byte_set2_32, classify_byte_set3_16,
        classify_byte_set3_32, classify_byte_set4_16, classify_byte_set4_16_scalar,
        classify_byte_set4_32,
    };

    fn classify_byte_set4_32_scalar(
        members: [u8; 4],
        bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
    ) -> ByteSetMask32 {
        let member_mask = bytes.iter().enumerate().fold(0_u32, |mask, (lane, &byte)| {
            mask | (u32::from(members.contains(&byte)) << lane)
        });
        ByteSetMask32::new(member_mask)
    }

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

    #[test]
    fn selected_wide_set4_classifier_matches_scalar_for_full_domain_and_alignments() {
        let mut random = 0x1702_6a79_6f20_458b_u64;
        let mut source = [0_u8; BYTE_SET_WIDE_BLOCK_BYTES + 31];
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
                let block: &[u8; BYTE_SET_WIDE_BLOCK_BYTES] = source
                    [alignment..alignment + BYTE_SET_WIDE_BLOCK_BYTES]
                    .try_into()
                    .unwrap();
                assert_eq!(
                    classify_byte_set4_32(members, block),
                    classify_byte_set4_32_scalar(members, block),
                    "members={members:?} alignment={alignment} block={block:?}"
                );
            }
        }
    }

    #[test]
    fn exact_small_cardinality_apis_match_scalar_for_every_alignment() {
        let mut random = 0x1319_8a2e_0370_7344_u64;
        let mut source = [0_u8; BYTE_SET_WIDE_BLOCK_BYTES + 31];
        for case in 0_u16..=u16::from(u8::MAX) {
            let members = [
                u8::try_from(case).unwrap(),
                u8::try_from(case.wrapping_mul(97).wrapping_add(31) & 255).unwrap(),
                u8::try_from(case.wrapping_mul(193).wrapping_add(67) & 255).unwrap(),
            ];
            for byte in &mut source {
                *byte = next_random(&mut random).to_le_bytes()[0];
            }
            for alignment in 0..=31 {
                let wide: &[u8; BYTE_SET_WIDE_BLOCK_BYTES] = source
                    [alignment..alignment + BYTE_SET_WIDE_BLOCK_BYTES]
                    .try_into()
                    .unwrap();
                let narrow: &[u8; BYTE_SET_BLOCK_BYTES] =
                    wide[..BYTE_SET_BLOCK_BYTES].try_into().unwrap();
                for cardinality in 1..=3 {
                    let expected_narrow =
                        narrow
                            .iter()
                            .enumerate()
                            .fold(0_u16, |mask, (lane, &byte)| {
                                mask | (u16::from(members[..cardinality].contains(&byte)) << lane)
                            });
                    let expected_wide =
                        wide.iter().enumerate().fold(0_u32, |mask, (lane, &byte)| {
                            mask | (u32::from(members[..cardinality].contains(&byte)) << lane)
                        });
                    let actual_narrow = match cardinality {
                        1 => classify_byte_set1_16(members[0], narrow).member_mask(),
                        2 => classify_byte_set2_16([members[0], members[1]], narrow).member_mask(),
                        3 => classify_byte_set3_16(members, narrow).member_mask(),
                        _ => unreachable!(),
                    };
                    let actual_wide = match cardinality {
                        1 => classify_byte_set1_32(members[0], wide).member_mask(),
                        2 => classify_byte_set2_32([members[0], members[1]], wide).member_mask(),
                        3 => classify_byte_set3_32(members, wide).member_mask(),
                        _ => unreachable!(),
                    };
                    assert_eq!(actual_narrow, expected_narrow);
                    assert_eq!(actual_wide, expected_wide);
                }
            }
        }
    }
}
