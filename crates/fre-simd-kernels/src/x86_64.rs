use core::arch::x86_64::{
    __m128i, __m256i, _mm_and_si128, _mm_cmpeq_epi8, _mm_loadu_si128, _mm_movemask_epi8,
    _mm_set1_epi8, _mm_setzero_si128, _mm_shuffle_epi8, _mm_srli_epi16, _mm256_and_si256,
    _mm256_broadcastsi128_si256, _mm256_cmpeq_epi8, _mm256_loadu_si256, _mm256_movemask_epi8,
    _mm256_set1_epi8, _mm256_setzero_si256, _mm256_shuffle_epi8, _mm256_srli_epi16,
};

use super::{ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, AsciiMasks16, AsciiMasks32, HIGH_NIBBLE_BITS};
use crate::{BYTE_SET_BLOCK_BYTES, ByteSetMask16};

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
    // entry only after proving all three AVX-512 features OS-usable.
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
            out("k1") _,
            out("k2") _,
            out("k3") _,
            options(nostack, readonly),
        );
    }
    AsciiMasks32::new(ascii_mask, members)
}
