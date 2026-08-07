use core::arch::x86_64::{
    __m128i, __m256i, _mm_and_si128, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8,
    _mm_set1_epi8, _mm_setzero_si128, _mm_shuffle_epi8, _mm_srli_epi16, _mm256_and_si256,
    _mm256_broadcastsi128_si256, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8,
    _mm256_set1_epi8, _mm256_setzero_si256, _mm256_shuffle_epi8, _mm256_srli_epi16,
};

use super::{
    ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, AsciiMasks16, AsciiMasks32, AsciiRunResult,
    AsciiRunTables, HIGH_NIBBLE_BITS, scalar,
};
use crate::{BYTE_SET_BLOCK_BYTES, BYTE_SET_WIDE_BLOCK_BYTES, ByteSetMask16, ByteSetMask32};

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the compiler target proved SSE2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm_loadu_si128 explicitly accepts an unaligned byte-backed address"
)]
#[target_feature(enable = "sse2")]
#[inline]
pub(super) unsafe fn classify_byte_delta_16_sse2(
    origin: u8,
    maximum_delta: u8,
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    use core::arch::x86_64::{_mm_sub_epi8, _mm_subs_epu8};

    // SAFETY: `bytes` is an initialized `[u8; 16]`; the unaligned load reads
    // exactly that object, and the compiler target proves SSE2.
    let input = unsafe { _mm_loadu_si128(bytes.as_ptr().cast::<__m128i>()) };
    let origin_lanes = _mm_set1_epi8(i8::from_ne_bytes([origin]));
    let maximum_delta_lanes = _mm_set1_epi8(i8::from_ne_bytes([maximum_delta]));
    let offsets = _mm_sub_epi8(input, origin_lanes);
    let above_range = _mm_subs_epu8(offsets, maximum_delta_lanes);
    let member_lanes = _mm_cmpeq_epi8(above_range, _mm_setzero_si128());
    ByteSetMask16::new(
        u16::try_from(_mm_movemask_epi8(member_lanes))
            .expect("a sixteen-lane movemask fits in u16"),
    )
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the compiler target proved SSE2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm_loadu_si128 explicitly accepts an unaligned byte-backed address"
)]
#[target_feature(enable = "sse2")]
#[inline]
pub(super) unsafe fn classify_byte_set1_16_sse2(
    member: u8,
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    let input = unsafe { _mm_loadu_si128(bytes.as_ptr().cast::<__m128i>()) };
    let lanes = _mm_cmpeq_epi8(input, _mm_set1_epi8(i8::from_ne_bytes([member])));
    ByteSetMask16::new(
        u16::try_from(_mm_movemask_epi8(lanes)).expect("a sixteen-lane movemask fits in u16"),
    )
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the compiler target proved SSE2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm_loadu_si128 explicitly accepts an unaligned byte-backed address"
)]
#[target_feature(enable = "sse2")]
#[inline]
pub(super) unsafe fn classify_byte_set2_16_sse2(
    members: [u8; 2],
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    use core::arch::x86_64::_mm_or_si128;

    let input = unsafe { _mm_loadu_si128(bytes.as_ptr().cast::<__m128i>()) };
    let lanes = _mm_or_si128(
        _mm_cmpeq_epi8(input, _mm_set1_epi8(i8::from_ne_bytes([members[0]]))),
        _mm_cmpeq_epi8(input, _mm_set1_epi8(i8::from_ne_bytes([members[1]]))),
    );
    ByteSetMask16::new(
        u16::try_from(_mm_movemask_epi8(lanes)).expect("a sixteen-lane movemask fits in u16"),
    )
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the compiler target proved SSE2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm_loadu_si128 explicitly accepts an unaligned byte-backed address"
)]
#[target_feature(enable = "sse2")]
#[inline]
pub(super) unsafe fn classify_byte_set3_16_sse2(
    members: [u8; 3],
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    use core::arch::x86_64::_mm_or_si128;

    let input = unsafe { _mm_loadu_si128(bytes.as_ptr().cast::<__m128i>()) };
    let lanes = _mm_or_si128(
        _mm_or_si128(
            _mm_cmpeq_epi8(input, _mm_set1_epi8(i8::from_ne_bytes([members[0]]))),
            _mm_cmpeq_epi8(input, _mm_set1_epi8(i8::from_ne_bytes([members[1]]))),
        ),
        _mm_cmpeq_epi8(input, _mm_set1_epi8(i8::from_ne_bytes([members[2]]))),
    );
    ByteSetMask16::new(
        u16::try_from(_mm_movemask_epi8(lanes)).expect("a sixteen-lane movemask fits in u16"),
    )
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the compiler target proved SSE2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm_loadu_si128 explicitly accepts an unaligned byte-backed address"
)]
#[target_feature(enable = "sse2")]
#[inline]
pub(super) unsafe fn classify_byte_set4_16_sse2(
    members: [u8; 4],
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    use core::arch::x86_64::_mm_or_si128;

    // SAFETY: `bytes` is an initialized `[u8; 16]`; the unaligned load reads
    // exactly that object, and the compiler target proves SSE2.
    let input = unsafe { _mm_loadu_si128(bytes.as_ptr().cast::<__m128i>()) };
    let first_or_second = _mm_or_si128(
        _mm_cmpeq_epi8(input, _mm_set1_epi8(i8::from_ne_bytes([members[0]]))),
        _mm_cmpeq_epi8(input, _mm_set1_epi8(i8::from_ne_bytes([members[1]]))),
    );
    let third_or_fourth = _mm_or_si128(
        _mm_cmpeq_epi8(input, _mm_set1_epi8(i8::from_ne_bytes([members[2]]))),
        _mm_cmpeq_epi8(input, _mm_set1_epi8(i8::from_ne_bytes([members[3]]))),
    );
    let member_lanes = _mm_or_si128(first_or_second, third_or_fourth);
    ByteSetMask16::new(
        u16::try_from(_mm_movemask_epi8(member_lanes))
            .expect("a sixteen-lane movemask fits in u16"),
    )
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the authenticated compiler-static profile proved AVX2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm256_loadu_si256 explicitly accepts an unaligned byte-backed address"
)]
#[target_feature(enable = "avx2")]
#[inline]
pub(super) unsafe fn classify_byte_set1_32_avx2(
    member: u8,
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    let input = unsafe { _mm256_loadu_si256(bytes.as_ptr().cast::<__m256i>()) };
    let lanes = _mm256_cmpeq_epi8(input, _mm256_set1_epi8(i8::from_ne_bytes([member])));
    ByteSetMask32::new(_mm256_movemask_epi8(lanes).cast_unsigned())
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the authenticated compiler-static profile proved AVX2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm256_loadu_si256 explicitly accepts an unaligned byte-backed address"
)]
#[target_feature(enable = "avx2")]
#[inline]
pub(super) unsafe fn classify_byte_set2_32_avx2(
    members: [u8; 2],
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    use core::arch::x86_64::_mm256_or_si256;

    let input = unsafe { _mm256_loadu_si256(bytes.as_ptr().cast::<__m256i>()) };
    let lanes = _mm256_or_si256(
        _mm256_cmpeq_epi8(input, _mm256_set1_epi8(i8::from_ne_bytes([members[0]]))),
        _mm256_cmpeq_epi8(input, _mm256_set1_epi8(i8::from_ne_bytes([members[1]]))),
    );
    ByteSetMask32::new(_mm256_movemask_epi8(lanes).cast_unsigned())
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the authenticated compiler-static profile proved AVX2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm256_loadu_si256 explicitly accepts an unaligned byte-backed address"
)]
#[target_feature(enable = "avx2")]
#[inline]
pub(super) unsafe fn classify_byte_set3_32_avx2(
    members: [u8; 3],
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    use core::arch::x86_64::_mm256_or_si256;

    let input = unsafe { _mm256_loadu_si256(bytes.as_ptr().cast::<__m256i>()) };
    let lanes = _mm256_or_si256(
        _mm256_or_si256(
            _mm256_cmpeq_epi8(input, _mm256_set1_epi8(i8::from_ne_bytes([members[0]]))),
            _mm256_cmpeq_epi8(input, _mm256_set1_epi8(i8::from_ne_bytes([members[1]]))),
        ),
        _mm256_cmpeq_epi8(input, _mm256_set1_epi8(i8::from_ne_bytes([members[2]]))),
    );
    ByteSetMask32::new(_mm256_movemask_epi8(lanes).cast_unsigned())
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the authenticated compiler-static profile proved AVX2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm256_loadu_si256 explicitly accepts an unaligned byte-backed address"
)]
#[target_feature(enable = "avx2")]
#[inline]
pub(super) unsafe fn classify_byte_set4_32_avx2(
    members: [u8; 4],
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    use core::arch::x86_64::_mm256_or_si256;

    // SAFETY: `bytes` is an initialized `[u8; 32]`; the unaligned load reads
    // exactly that object, and the authenticated compiler profile proves
    // AVX2.
    let input = unsafe { _mm256_loadu_si256(bytes.as_ptr().cast::<__m256i>()) };
    let first_or_second = _mm256_or_si256(
        _mm256_cmpeq_epi8(input, _mm256_set1_epi8(i8::from_ne_bytes([members[0]]))),
        _mm256_cmpeq_epi8(input, _mm256_set1_epi8(i8::from_ne_bytes([members[1]]))),
    );
    let third_or_fourth = _mm256_or_si256(
        _mm256_cmpeq_epi8(input, _mm256_set1_epi8(i8::from_ne_bytes([members[2]]))),
        _mm256_cmpeq_epi8(input, _mm256_set1_epi8(i8::from_ne_bytes([members[3]]))),
    );
    ByteSetMask32::new(
        _mm256_movemask_epi8(_mm256_or_si256(first_or_second, third_or_fourth)).cast_unsigned(),
    )
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact 16-byte array after its retained classifier handle proved SSE2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm_loadu_si128 explicitly accepts unaligned byte-backed addresses"
)]
#[target_feature(enable = "sse2")]
#[inline(never)]
pub(super) unsafe fn classify_16_sse2(
    columns: &[u8; ASCII_NARROW_BYTES],
    bytes: &[u8; ASCII_NARROW_BYTES],
) -> AsciiMasks16 {
    // SAFETY: `bytes` is an initialized `[u8; 16]`. The unaligned load reads
    // exactly that object, and the only caller retains a dispatch receipt
    // proving SSE2 usable.
    let input = unsafe { _mm_loadu_si128(bytes.as_ptr().cast::<__m128i>()) };
    let non_ascii_mask = u16::try_from(_mm_movemask_epi8(input))
        .expect("a 16-lane movemask has exactly 16 significant bits");

    // SSE2 has no byte-table shuffle. Keep the arbitrary byte-set lookup
    // scalar while using its guaranteed lane movemask for the ASCII proof.
    // This is a general fallback for every 128-bit byte set, not a
    // set-specific specialization.
    let mut members = 0_u16;
    for (lane, &byte) in bytes.iter().enumerate() {
        let low_nibble = usize::from(byte & 0x0f);
        let high_nibble = usize::from(byte >> 4);
        let selected = columns[low_nibble] & HIGH_NIBBLE_BITS[high_nibble] != 0;
        let lane_bit = u16::from(selected)
            .checked_shl(u32::try_from(lane).expect("a 16-byte lane index fits in u32"))
            .expect("a 16-byte lane index is below the u16 width");
        members |= lane_bit;
    }
    AsciiMasks16::new(!non_ascii_mask, members)
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads three exact 16-byte arrays after its retained classifier handle proved SSSE3 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm_loadu_si128 explicitly accepts unaligned byte-backed addresses"
)]
#[target_feature(enable = "ssse3")]
#[inline(never)]
pub(super) unsafe fn classify_16_ssse3(
    columns: &[u8; ASCII_NARROW_BYTES],
    bytes: &[u8; ASCII_NARROW_BYTES],
) -> AsciiMasks16 {
    // SAFETY: the arguments and fixed table are initialized `[u8; 16]`
    // values. The unaligned loads read exactly those objects, and the only
    // caller retains a dispatch receipt proving SSSE3 is OS-usable.
    let (input, columns, high_nibble_bits) = unsafe {
        (
            _mm_loadu_si128(bytes.as_ptr().cast::<__m128i>()),
            _mm_loadu_si128(columns.as_ptr().cast::<__m128i>()),
            _mm_loadu_si128(HIGH_NIBBLE_BITS.as_ptr().cast::<__m128i>()),
        )
    };
    let nibble_mask = _mm_set1_epi8(0x0f);
    let low_nibbles = _mm_and_si128(input, nibble_mask);
    // A 16-bit shift mixes adjacent bytes. Masking is required to recover
    // independent per-byte high nibbles.
    let high_nibbles = _mm_and_si128(_mm_srli_epi16::<4>(input), nibble_mask);
    let selected_columns = _mm_shuffle_epi8(columns, low_nibbles);
    let selected_high_bits = _mm_shuffle_epi8(high_nibble_bits, high_nibbles);
    let selected_bits = _mm_and_si128(selected_columns, selected_high_bits);
    let zero_lanes = _mm_cmpeq_epi8(selected_bits, _mm_setzero_si128());
    let zero_mask = u16::try_from(_mm_movemask_epi8(zero_lanes))
        .expect("a 16-lane movemask has exactly 16 significant bits");
    let non_ascii_mask = u16::try_from(_mm_movemask_epi8(input))
        .expect("a 16-lane movemask has exactly 16 significant bits");
    AsciiMasks16::new(!non_ascii_mask, !zero_mask)
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact 32-byte array and two exact 16-byte tables after its retained classifier handle proved AVX2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "_mm_loadu_si128 and _mm256_loadu_si256 explicitly accept unaligned byte-backed addresses"
)]
#[target_feature(enable = "avx2")]
#[inline(never)]
pub(super) unsafe fn classify_32_avx2(
    columns: &[u8; ASCII_NARROW_BYTES],
    bytes: &[u8; ASCII_WIDE_BYTES],
) -> AsciiMasks32 {
    // SAFETY: the arguments and fixed table are initialized arrays of exactly
    // the widths loaded. The unaligned loads stay within those objects, and
    // the only caller retains a dispatch receipt proving AVX2 is OS-usable.
    let (input, columns_128, high_nibble_bits_128) = unsafe {
        (
            _mm256_loadu_si256(bytes.as_ptr().cast::<__m256i>()),
            _mm_loadu_si128(columns.as_ptr().cast::<__m128i>()),
            _mm_loadu_si128(HIGH_NIBBLE_BITS.as_ptr().cast::<__m128i>()),
        )
    };
    // AVX2 byte shuffles are lane-local, so both complete lookup tables must
    // be present in both 128-bit halves.
    let columns = _mm256_broadcastsi128_si256(columns_128);
    let high_nibble_bits = _mm256_broadcastsi128_si256(high_nibble_bits_128);
    let nibble_mask = _mm256_set1_epi8(0x0f);
    let low_nibbles = _mm256_and_si256(input, nibble_mask);
    // A 16-bit shift mixes adjacent bytes. Masking is required to recover
    // independent per-byte high nibbles.
    let high_nibbles = _mm256_and_si256(_mm256_srli_epi16::<4>(input), nibble_mask);
    let selected_columns = _mm256_shuffle_epi8(columns, low_nibbles);
    let selected_high_bits = _mm256_shuffle_epi8(high_nibble_bits, high_nibbles);
    let selected_bits = _mm256_and_si256(selected_columns, selected_high_bits);
    let zero_lanes = _mm256_cmpeq_epi8(selected_bits, _mm256_setzero_si256());
    let zero_mask = _mm256_movemask_epi8(zero_lanes).cast_unsigned();
    let non_ascii_mask = _mm256_movemask_epi8(input).cast_unsigned();
    AsciiMasks32::new(!non_ascii_mask, !zero_mask)
}

#[allow(
    unsafe_code,
    reason = "this private ISA-gated leaf uses one reviewed EVEX YMM-data inline-assembly block after its retained classifier handle proved AVX-512F, AVX-512BW and AVX-512VL usable"
)]
// Deliberately no `target_feature`: Rust's x86 contract implicitly enables
// AVX2, FMA and F16C with AVX-512F. This explicit assembly body requires only
// the three independently receipted AVX-512 features.
#[inline(never)]
pub(super) unsafe fn classify_32_avx512(
    columns: &[u8; ASCII_NARROW_BYTES],
    bytes: &[u8; ASCII_WIDE_BYTES],
) -> AsciiMasks32 {
    let ascii_mask: u32;
    let members: u32;
    // SAFETY: `bytes` supplies exactly 32 initialized readable bytes and each
    // table supplies exactly 16. `vmovdqu8` is the sole input load;
    // `vbroadcasti32x4` is the sole load for each table. Every vector data
    // instruction has an all-lanes `k1` modifier, forcing its EVEX encoding.
    // The instruction set is exactly AVX-512F/BW/VL plus `vzeroupper`; it
    // contains no AVX2-only VEX broadcast or shuffle. The caller retained this
    // entry only after proving all three AVX-512 features OS-usable. The full
    // YMM0..15 output list models every legacy vector register whose upper
    // lanes `vzeroupper` changes.
    unsafe {
        core::arch::asm!(
            "kxnord k1, k1, k1",
            "vmovdqu8 ymm0 {{k1}}, ymmword ptr [{bytes}]",
            "vbroadcasti32x4 ymm1 {{k1}}, xmmword ptr [{columns}]",
            "vbroadcasti32x4 ymm2 {{k1}}, xmmword ptr [{high_bits}]",
            "mov {scratch:e}, 0x0f0f0f0f",
            "vpbroadcastd ymm3 {{k1}}, {scratch:e}",
            "vpandd ymm4 {{k1}}, ymm0, ymm3",
            "vpsrlw ymm5 {{k1}}, ymm0, 4",
            "vpandd ymm5 {{k1}}, ymm5, ymm3",
            "vpshufb ymm1 {{k1}}, ymm1, ymm4",
            "vpshufb ymm2 {{k1}}, ymm2, ymm5",
            "vptestmb k2, ymm1, ymm2",
            "vpmovb2m k3, ymm0",
            "kmovd {members:e}, k2",
            "kmovd {ascii:e}, k3",
            "not {ascii:e}",
            "vzeroupper",
            bytes = in(reg) bytes.as_ptr(),
            columns = in(reg) columns.as_ptr(),
            high_bits = in(reg) HIGH_NIBBLE_BITS.as_ptr(),
            scratch = lateout(reg) _,
            ascii = lateout(reg) ascii_mask,
            members = lateout(reg) members,
            out("ymm0") _,
            out("ymm1") _,
            out("ymm2") _,
            out("ymm3") _,
            out("ymm4") _,
            out("ymm5") _,
            out("ymm6") _,
            out("ymm7") _,
            out("ymm8") _,
            out("ymm9") _,
            out("ymm10") _,
            out("ymm11") _,
            out("ymm12") _,
            out("ymm13") _,
            out("ymm14") _,
            out("ymm15") _,
            out("k1") _,
            out("k2") _,
            out("k3") _,
            options(nostack, readonly),
        );
    }
    AsciiMasks32::new(ascii_mask, members)
}

#[allow(
    unsafe_code,
    reason = "this private fused run leaf reads complete 32-byte blocks only after retained dispatch proved AVX2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "the AVX2 unaligned loads explicitly accept byte-backed addresses"
)]
#[target_feature(enable = "avx2")]
#[inline(never)]
pub(super) unsafe fn scan_run_forward_avx2(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    let vector_len = bytes.len() / ASCII_WIDE_BYTES * ASCII_WIDE_BYTES;
    let mut offset = 0_usize;
    if vector_len != 0 {
        // Hoist both lookup tables and the nibble mask out of the block loop.
        // AVX2 byte shuffles are lane-local, so each 16-byte table is
        // broadcast into both halves once per complete run scan.
        // SAFETY: both table loads read one initialized 16-byte object. The
        // retained entry proves AVX2 usable before this target-feature leaf is
        // entered.
        let (columns, high_nibble_bits) = unsafe {
            (
                _mm256_broadcastsi128_si256(_mm_loadu_si128(
                    tables.columns.as_ptr().cast::<__m128i>(),
                )),
                _mm256_broadcastsi128_si256(_mm_loadu_si128(
                    HIGH_NIBBLE_BITS.as_ptr().cast::<__m128i>(),
                )),
            )
        };
        let nibble_mask = _mm256_set1_epi8(0x0f);
        let zero = _mm256_setzero_si256();
        while offset < vector_len {
            // SAFETY: `offset < vector_len` and `vector_len` is rounded down
            // to a multiple of 32, so this load stays within `bytes`.
            let input = unsafe {
                _mm256_loadu_si256(bytes.as_ptr().add(offset).cast::<__m256i>())
            };
            let low_nibbles = _mm256_and_si256(input, nibble_mask);
            let high_nibbles =
                _mm256_and_si256(_mm256_srli_epi16::<4>(input), nibble_mask);
            let selected_columns = _mm256_shuffle_epi8(columns, low_nibbles);
            let selected_high_bits = _mm256_shuffle_epi8(high_nibble_bits, high_nibbles);
            let selected_bits = _mm256_and_si256(selected_columns, selected_high_bits);
            let zero_lanes = _mm256_cmpeq_epi8(selected_bits, zero);
            let members = !_mm256_movemask_epi8(zero_lanes).cast_unsigned();
            let examined_bytes = offset
                .checked_add(ASCII_WIDE_BYTES)
                .expect("a complete AVX2 block stays within its slice");
            if members != u32::MAX {
                let prefix = usize::try_from(members.trailing_ones())
                    .expect("a 32-lane prefix length fits in usize");
                return AsciiRunResult::new(
                    offset
                        .checked_add(prefix)
                        .expect("the failed block boundary stays within its slice"),
                    examined_bytes,
                );
            }
            offset = examined_bytes;
        }
    }

    let tail = scalar::scan_run_forward(tables.set, &bytes[vector_len..]);
    AsciiRunResult::new(
        vector_len
            .checked_add(tail.member_run_len())
            .expect("the AVX2 prefix and scalar tail partition the slice"),
        vector_len
            .checked_add(tail.examined_bytes())
            .expect("the AVX2 prefix and scalar tail partition the slice"),
    )
}

#[allow(
    unsafe_code,
    reason = "this private fused run leaf reads complete 32-byte blocks only after retained dispatch proved AVX2 usable"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "the AVX2 unaligned loads explicitly accept byte-backed addresses"
)]
#[target_feature(enable = "avx2")]
#[inline(never)]
pub(super) unsafe fn scan_run_backward_avx2(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    let head_len = bytes.len() % ASCII_WIDE_BYTES;
    let vector_len = bytes.len() - head_len;
    let mut offset = vector_len;
    if vector_len != 0 {
        // SAFETY: identical exact-table-load and AVX2 authorization proof to
        // the forward leaf.
        let (columns, high_nibble_bits) = unsafe {
            (
                _mm256_broadcastsi128_si256(_mm_loadu_si128(
                    tables.columns.as_ptr().cast::<__m128i>(),
                )),
                _mm256_broadcastsi128_si256(_mm_loadu_si128(
                    HIGH_NIBBLE_BITS.as_ptr().cast::<__m128i>(),
                )),
            )
        };
        let nibble_mask = _mm256_set1_epi8(0x0f);
        let zero = _mm256_setzero_si256();
        while offset != 0 {
            offset = offset
                .checked_sub(ASCII_WIDE_BYTES)
                .expect("the reverse AVX2 cursor starts on a block boundary");
            let block_start = head_len
                .checked_add(offset)
                .expect("the reverse AVX2 block stays within its slice");
            // SAFETY: `block_start` identifies a complete 32-byte block in
            // the vector suffix `[head_len..]`.
            let input = unsafe {
                _mm256_loadu_si256(bytes.as_ptr().add(block_start).cast::<__m256i>())
            };
            let low_nibbles = _mm256_and_si256(input, nibble_mask);
            let high_nibbles =
                _mm256_and_si256(_mm256_srli_epi16::<4>(input), nibble_mask);
            let selected_columns = _mm256_shuffle_epi8(columns, low_nibbles);
            let selected_high_bits = _mm256_shuffle_epi8(high_nibble_bits, high_nibbles);
            let selected_bits = _mm256_and_si256(selected_columns, selected_high_bits);
            let zero_lanes = _mm256_cmpeq_epi8(selected_bits, zero);
            let members = !_mm256_movemask_epi8(zero_lanes).cast_unsigned();
            let examined_bytes = vector_len
                .checked_sub(offset)
                .expect("the reverse cursor stays inside the vector suffix");
            if members != u32::MAX {
                let suffix = usize::try_from(members.leading_ones())
                    .expect("a 32-lane suffix length fits in usize");
                let completed = examined_bytes
                    .checked_sub(ASCII_WIDE_BYTES)
                    .expect("a failed AVX2 probe examined its complete block");
                return AsciiRunResult::new(
                    completed
                        .checked_add(suffix)
                        .expect("the failed reverse boundary stays within its slice"),
                    examined_bytes,
                );
            }
        }
    }

    let head = scalar::scan_run_backward(tables.set, &bytes[..head_len]);
    AsciiRunResult::new(
        vector_len
            .checked_add(head.member_run_len())
            .expect("the scalar head and AVX2 suffix partition the slice"),
        vector_len
            .checked_add(head.examined_bytes())
            .expect("the scalar head and AVX2 suffix partition the slice"),
    )
}

#[allow(
    unsafe_code,
    reason = "this private fused assembly loop is reachable only through a retained AVX-512F/BW/VL dispatch receipt"
)]
// Deliberately no `target_feature`: Rust's x86 contract implicitly enables
// AVX2, FMA and F16C with AVX-512F. This assembly loop requires only the
// independently receipted AVX-512F/BW/VL features and does not rely on those
// implicit extras.
#[inline(never)]
pub(super) unsafe fn scan_run_forward_avx512(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    let vector_len = bytes.len() / ASCII_WIDE_BYTES * ASCII_WIDE_BYTES;
    if vector_len != 0 {
        let vector_offset: usize;
        let members: u32;
        // SAFETY: the retained entry proves AVX-512F/BW/VL OS-usable. Each
        // iteration reads exactly one of the `vector_len / 32` complete
        // blocks. Table broadcasts happen before the backedge and
        // `vzeroupper` executes exactly once after the loop, including its
        // failed-block exit. YMM0..15 are all outputs because that final
        // instruction changes every legacy vector register's upper lanes.
        unsafe {
            core::arch::asm!(
                "kxnord k1, k1, k1",
                "vbroadcasti32x4 ymm1 {{k1}}, xmmword ptr [{columns}]",
                "vbroadcasti32x4 ymm2 {{k1}}, xmmword ptr [{high_bits}]",
                "mov {scratch:e}, 0x0f0f0f0f",
                "vpbroadcastd ymm3 {{k1}}, {scratch:e}",
                "xor {offset}, {offset}",
                "2:",
                "vmovdqu8 ymm0 {{k1}}, ymmword ptr [{bytes} + {offset}]",
                "vpandd ymm4 {{k1}}, ymm0, ymm3",
                "vpsrlw ymm5 {{k1}}, ymm0, 4",
                "vpandd ymm5 {{k1}}, ymm5, ymm3",
                "vpshufb ymm4 {{k1}}, ymm1, ymm4",
                "vpshufb ymm5 {{k1}}, ymm2, ymm5",
                "vptestmb k2, ymm4, ymm5",
                "kmovd {members:e}, k2",
                "cmp {members:e}, -1",
                "jne 3f",
                "add {offset}, 32",
                "cmp {offset}, {vector_len}",
                "jb 2b",
                "3:",
                "vzeroupper",
                bytes = in(reg) bytes.as_ptr(),
                columns = in(reg) tables.columns.as_ptr(),
                high_bits = in(reg) HIGH_NIBBLE_BITS.as_ptr(),
                vector_len = in(reg) vector_len,
                offset = out(reg) vector_offset,
                members = out(reg) members,
                scratch = out(reg) _,
                out("ymm0") _,
                out("ymm1") _,
                out("ymm2") _,
                out("ymm3") _,
                out("ymm4") _,
                out("ymm5") _,
                out("ymm6") _,
                out("ymm7") _,
                out("ymm8") _,
                out("ymm9") _,
                out("ymm10") _,
                out("ymm11") _,
                out("ymm12") _,
                out("ymm13") _,
                out("ymm14") _,
                out("ymm15") _,
                out("k1") _,
                out("k2") _,
                options(nostack, readonly),
            );
        }
        if members != u32::MAX {
            let prefix = usize::try_from(members.trailing_ones())
                .expect("a 32-lane prefix length fits in usize");
            return AsciiRunResult::new(
                vector_offset
                    .checked_add(prefix)
                    .expect("the failed AVX-512 block boundary stays within its slice"),
                vector_offset
                    .checked_add(ASCII_WIDE_BYTES)
                    .expect("the failed AVX-512 probe examined one complete block"),
            );
        }
        debug_assert_eq!(vector_offset, vector_len);
    }

    let tail = scalar::scan_run_forward(tables.set, &bytes[vector_len..]);
    AsciiRunResult::new(
        vector_len
            .checked_add(tail.member_run_len())
            .expect("the AVX-512 prefix and scalar tail partition the slice"),
        vector_len
            .checked_add(tail.examined_bytes())
            .expect("the AVX-512 prefix and scalar tail partition the slice"),
    )
}

#[allow(
    unsafe_code,
    reason = "this private fused assembly loop is reachable only through a retained AVX-512F/BW/VL dispatch receipt"
)]
// See the forward leaf for the deliberate feature-gating boundary.
#[inline(never)]
pub(super) unsafe fn scan_run_backward_avx512(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    let head_len = bytes.len() % ASCII_WIDE_BYTES;
    let vector_len = bytes.len() - head_len;
    if vector_len != 0 {
        let vector_offset: usize;
        let members: u32;
        // SAFETY: identical feature proof to the forward leaf. `block_base`
        // starts the complete-block suffix, and the loop subtracts one block
        // before each load. Broadcasts and `vzeroupper` remain outside the
        // backedge.
        unsafe {
            core::arch::asm!(
                "kxnord k1, k1, k1",
                "vbroadcasti32x4 ymm1 {{k1}}, xmmword ptr [{columns}]",
                "vbroadcasti32x4 ymm2 {{k1}}, xmmword ptr [{high_bits}]",
                "mov {scratch:e}, 0x0f0f0f0f",
                "vpbroadcastd ymm3 {{k1}}, {scratch:e}",
                "mov {offset}, {vector_len}",
                "2:",
                "sub {offset}, 32",
                "vmovdqu8 ymm0 {{k1}}, ymmword ptr [{block_base} + {offset}]",
                "vpandd ymm4 {{k1}}, ymm0, ymm3",
                "vpsrlw ymm5 {{k1}}, ymm0, 4",
                "vpandd ymm5 {{k1}}, ymm5, ymm3",
                "vpshufb ymm4 {{k1}}, ymm1, ymm4",
                "vpshufb ymm5 {{k1}}, ymm2, ymm5",
                "vptestmb k2, ymm4, ymm5",
                "kmovd {members:e}, k2",
                "cmp {members:e}, -1",
                "jne 3f",
                "test {offset}, {offset}",
                "jnz 2b",
                "3:",
                "vzeroupper",
                block_base = in(reg) bytes.as_ptr().add(head_len),
                columns = in(reg) tables.columns.as_ptr(),
                high_bits = in(reg) HIGH_NIBBLE_BITS.as_ptr(),
                vector_len = in(reg) vector_len,
                offset = out(reg) vector_offset,
                members = out(reg) members,
                scratch = out(reg) _,
                out("ymm0") _,
                out("ymm1") _,
                out("ymm2") _,
                out("ymm3") _,
                out("ymm4") _,
                out("ymm5") _,
                out("ymm6") _,
                out("ymm7") _,
                out("ymm8") _,
                out("ymm9") _,
                out("ymm10") _,
                out("ymm11") _,
                out("ymm12") _,
                out("ymm13") _,
                out("ymm14") _,
                out("ymm15") _,
                out("k1") _,
                out("k2") _,
                options(nostack, readonly),
            );
        }
        if members != u32::MAX {
            let suffix = usize::try_from(members.leading_ones())
                .expect("a 32-lane suffix length fits in usize");
            let examined_bytes = vector_len
                .checked_sub(vector_offset)
                .expect("the reverse AVX-512 cursor stays inside its suffix");
            let completed = examined_bytes
                .checked_sub(ASCII_WIDE_BYTES)
                .expect("a failed AVX-512 probe examined one complete block");
            return AsciiRunResult::new(
                completed
                    .checked_add(suffix)
                    .expect("the failed reverse AVX-512 boundary stays in its slice"),
                examined_bytes,
            );
        }
        debug_assert_eq!(vector_offset, 0);
    }

    let head = scalar::scan_run_backward(tables.set, &bytes[..head_len]);
    AsciiRunResult::new(
        vector_len
            .checked_add(head.member_run_len())
            .expect("the scalar head and AVX-512 suffix partition the slice"),
        vector_len
            .checked_add(head.examined_bytes())
            .expect("the scalar head and AVX-512 suffix partition the slice"),
    )
}
