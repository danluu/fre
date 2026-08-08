use core::arch::aarch64::{
    uint8x16_t, vaddv_u8, vandq_u8, vceqq_u8, vcgtq_u8, vdupq_n_u8, vget_high_u8, vget_low_u8,
    vld1q_u8, vminvq_u8, vmulq_u8, vqtbl1q_u8, vshrq_n_u8,
};

use super::{
    ASCII_NARROW_BYTES, AsciiMasks16, AsciiRunResult, AsciiRunTables, HIGH_NIBBLE_BITS,
    LANE_WEIGHTS, scalar,
};
#[cfg(any(not(feature = "static-dispatch"), target_feature = "neon"))]
use super::AsciiByteSet;
use crate::{BYTE_SET_BLOCK_BYTES, ByteSetMask16};
#[cfg(any(not(feature = "static-dispatch"), target_feature = "neon"))]
use crate::BYTE_SET_WIDE_BLOCK_BYTES;

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads three exact 16-byte arrays after its retained classifier handle proved NEON usable"
)]
#[target_feature(enable = "neon")]
#[inline(never)]
pub(super) unsafe fn classify_16_neon(
    columns: &[u8; ASCII_NARROW_BYTES],
    bytes: &[u8; ASCII_NARROW_BYTES],
) -> AsciiMasks16 {
    // SAFETY: the arguments and fixed tables are initialized `[u8; 16]`
    // values, so each unaligned load reads exactly its borrowed object. The
    // only caller retains a dispatch receipt that proves NEON is OS-usable.
    let (input, columns, high_nibble_bits, lane_weights) = unsafe {
        (
            vld1q_u8(bytes.as_ptr()),
            vld1q_u8(columns.as_ptr()),
            vld1q_u8(HIGH_NIBBLE_BITS.as_ptr()),
            vld1q_u8(LANE_WEIGHTS.as_ptr()),
        )
    };
    let low_nibbles = vandq_u8(input, vdupq_n_u8(0x0f));
    let high_nibbles = vshrq_n_u8::<4>(input);
    let selected_columns = vqtbl1q_u8(columns, low_nibbles);
    let selected_high_bits = vqtbl1q_u8(high_nibble_bits, high_nibbles);
    let selected_bits = vandq_u8(selected_columns, selected_high_bits);
    let member_lanes = vcgtq_u8(selected_bits, vdupq_n_u8(0));
    let ascii_lanes = vceqq_u8(vandq_u8(input, vdupq_n_u8(0x80)), vdupq_n_u8(0));
    // SAFETY: this function itself is entered only with NEON enabled, and the
    // helper has no memory access or additional precondition.
    let (ascii, members) = unsafe {
        (
            boolean_lanes_to_mask(ascii_lanes, lane_weights),
            boolean_lanes_to_mask(member_lanes, lane_weights),
        )
    };
    AsciiMasks16::new(ascii, members)
}

#[allow(
    unsafe_code,
    reason = "this private register-only helper inherits the proved NEON boundary from its sole target-feature caller"
)]
#[target_feature(enable = "neon")]
#[inline]
unsafe fn boolean_lanes_to_mask(lanes: uint8x16_t, weights: uint8x16_t) -> u16 {
    let one_or_zero = vshrq_n_u8::<7>(lanes);
    let weighted = vmulq_u8(one_or_zero, weights);
    let low = u16::from(vaddv_u8(vget_low_u8(weighted)));
    let high = u16::from(vaddv_u8(vget_high_u8(weighted)));
    low | (high << 8)
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the compiler target proved NEON usable"
)]
#[target_feature(enable = "neon")]
#[inline]
pub(super) unsafe fn classify_byte_delta_16_neon(
    origin: u8,
    maximum_delta: u8,
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    use core::arch::aarch64::{vcleq_u8, vsubq_u8};

    // SAFETY: `bytes` and the fixed weights are initialized exact-width
    // arrays, and the compiler target proves NEON before this leaf is called.
    let (input, lane_weights) =
        unsafe { (vld1q_u8(bytes.as_ptr()), vld1q_u8(LANE_WEIGHTS.as_ptr())) };
    let offsets = vsubq_u8(input, vdupq_n_u8(origin));
    let member_lanes = vcleq_u8(offsets, vdupq_n_u8(maximum_delta));
    // SAFETY: this function itself is entered only with NEON enabled, and the
    // helper has no memory access or additional precondition.
    ByteSetMask16::new(unsafe { boolean_lanes_to_mask(member_lanes, lane_weights) })
}

#[allow(
    unsafe_code,
    reason = "compiler target features prove NEON once around the whole-slice bounded-delta loop"
)]
#[cfg(target_feature = "neon")]
#[target_feature(enable = "neon")]
#[inline(never)]
pub(super) unsafe fn find_byte_delta_neon(
    origin: u8,
    maximum_delta: u8,
    bytes: &[u8],
) -> Option<usize> {
    use core::arch::aarch64::{vcleq_u8, vmaxvq_u8, vorrq_u8, vsubq_u8};

    let origin_vector = vdupq_n_u8(origin);
    let maximum_delta_vector = vdupq_n_u8(maximum_delta);
    let classify = |input| vcleq_u8(vsubq_u8(input, origin_vector), maximum_delta_vector);
    let mut block_start = 0_usize;
    let mut groups = bytes.chunks_exact(BYTE_SET_WIDE_BLOCK_BYTES);
    for group in &mut groups {
        let first: &[u8; BYTE_SET_BLOCK_BYTES] = group[..BYTE_SET_BLOCK_BYTES]
            .try_into()
            .expect("a wide group has one exact first NEON block");
        let second: &[u8; BYTE_SET_BLOCK_BYTES] = group[BYTE_SET_BLOCK_BYTES..]
            .try_into()
            .expect("a wide group has one exact second NEON block");
        // SAFETY: both array references prove their exact load extents.
        let (first_input, second_input) = unsafe {
            (
                vld1q_u8(first.as_ptr()),
                vld1q_u8(second.as_ptr()),
            )
        };
        if vmaxvq_u8(vorrq_u8(classify(first_input), classify(second_input))) != 0 {
            return group
                .iter()
                .position(|&byte| byte.wrapping_sub(origin) <= maximum_delta)
                .and_then(|relative| block_start.checked_add(relative));
        }
        block_start = block_start
            .checked_add(BYTE_SET_WIDE_BLOCK_BYTES)
            .expect("a complete group stays within its source slice");
    }
    let remainder = groups.remainder();
    let mut tail = remainder;
    if remainder.len() >= BYTE_SET_BLOCK_BYTES {
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = remainder[..BYTE_SET_BLOCK_BYTES]
            .try_into()
            .expect("a wide remainder has one exact NEON block");
        // SAFETY: the array reference proves the exact load extent.
        let input = unsafe { vld1q_u8(block.as_ptr()) };
        if vmaxvq_u8(classify(input)) != 0 {
            return block
                .iter()
                .position(|&byte| byte.wrapping_sub(origin) <= maximum_delta)
                .and_then(|relative| block_start.checked_add(relative));
        }
        block_start = block_start
            .checked_add(BYTE_SET_BLOCK_BYTES)
            .expect("a trailing vector block stays within its source slice");
        tail = &remainder[BYTE_SET_BLOCK_BYTES..];
    }
    tail.iter()
        .position(|&byte| byte.wrapping_sub(origin) <= maximum_delta)
        .and_then(|relative| block_start.checked_add(relative))
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the compiler target proved NEON usable"
)]
#[target_feature(enable = "neon")]
#[inline]
#[cfg_attr(
    all(
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ),
    allow(
        dead_code,
        reason = "SVE2 compiler targets select the direct exact-one leaf instead of NEON"
    )
)]
pub(super) unsafe fn classify_byte_set1_16_neon(
    member: u8,
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    let (input, lane_weights) =
        unsafe { (vld1q_u8(bytes.as_ptr()), vld1q_u8(LANE_WEIGHTS.as_ptr())) };
    let member_lanes = vceqq_u8(input, vdupq_n_u8(member));
    ByteSetMask16::new(unsafe { boolean_lanes_to_mask(member_lanes, lane_weights) })
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the compiler target proved NEON usable"
)]
#[target_feature(enable = "neon")]
#[inline]
#[cfg_attr(
    all(
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ),
    allow(
        dead_code,
        reason = "SVE2 compiler targets select the direct exact-two leaf instead of NEON"
    )
)]
pub(super) unsafe fn classify_byte_set2_16_neon(
    members: [u8; 2],
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    use core::arch::aarch64::vorrq_u8;

    let (input, lane_weights) =
        unsafe { (vld1q_u8(bytes.as_ptr()), vld1q_u8(LANE_WEIGHTS.as_ptr())) };
    let member_lanes = vorrq_u8(
        vceqq_u8(input, vdupq_n_u8(members[0])),
        vceqq_u8(input, vdupq_n_u8(members[1])),
    );
    ByteSetMask16::new(unsafe { boolean_lanes_to_mask(member_lanes, lane_weights) })
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the compiler target proved NEON usable"
)]
#[target_feature(enable = "neon")]
#[inline]
#[cfg_attr(
    all(
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ),
    allow(
        dead_code,
        reason = "SVE2 compiler targets select the direct exact-three MATCH leaf instead of NEON"
    )
)]
pub(super) unsafe fn classify_byte_set3_16_neon(
    members: [u8; 3],
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    use core::arch::aarch64::vorrq_u8;

    let (input, lane_weights) =
        unsafe { (vld1q_u8(bytes.as_ptr()), vld1q_u8(LANE_WEIGHTS.as_ptr())) };
    let member_lanes = vorrq_u8(
        vorrq_u8(
            vceqq_u8(input, vdupq_n_u8(members[0])),
            vceqq_u8(input, vdupq_n_u8(members[1])),
        ),
        vceqq_u8(input, vdupq_n_u8(members[2])),
    );
    ByteSetMask16::new(unsafe { boolean_lanes_to_mask(member_lanes, lane_weights) })
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf loads one exact block after the compiler target proved NEON usable"
)]
#[cfg_attr(
    all(
        target_os = "linux",
        target_endian = "little",
        target_feature = "sve",
        target_feature = "sve2"
    ),
    allow(
        dead_code,
        reason = "SVE2 compiler targets select the direct MATCH leaf instead of the NEON four-byte classifier"
    )
)]
#[target_feature(enable = "neon")]
#[inline]
pub(super) unsafe fn classify_byte_set4_16_neon(
    members: [u8; 4],
    bytes: &[u8; BYTE_SET_BLOCK_BYTES],
) -> ByteSetMask16 {
    use core::arch::aarch64::vorrq_u8;

    // SAFETY: `bytes` and the fixed weights are initialized exact-width
    // arrays, and the compiler target proves NEON before this leaf is called.
    let (input, lane_weights) =
        unsafe { (vld1q_u8(bytes.as_ptr()), vld1q_u8(LANE_WEIGHTS.as_ptr())) };
    let first_or_second = vorrq_u8(
        vceqq_u8(input, vdupq_n_u8(members[0])),
        vceqq_u8(input, vdupq_n_u8(members[1])),
    );
    let third_or_fourth = vorrq_u8(
        vceqq_u8(input, vdupq_n_u8(members[2])),
        vceqq_u8(input, vdupq_n_u8(members[3])),
    );
    let member_lanes = vorrq_u8(first_or_second, third_or_fourth);
    // SAFETY: this function itself is entered only with NEON enabled, and the
    // helper has no memory access or additional precondition.
    ByteSetMask16::new(unsafe { boolean_lanes_to_mask(member_lanes, lane_weights) })
}

#[allow(
    unsafe_code,
    reason = "compiler target features prove NEON once around the whole-slice four-value loop"
)]
#[cfg(all(
    target_feature = "neon",
    not(feature = "static-dispatch-arm-41-d84")
))]
#[target_feature(enable = "neon")]
#[inline(never)]
pub(super) unsafe fn find_byte_set4_neon(members: [u8; 4], bytes: &[u8]) -> Option<usize> {
    use core::arch::aarch64::{vmaxvq_u8, vorrq_u8};

    let first = vdupq_n_u8(members[0]);
    let second = vdupq_n_u8(members[1]);
    let third = vdupq_n_u8(members[2]);
    let fourth = vdupq_n_u8(members[3]);
    let classify = |input| {
        vorrq_u8(
            vorrq_u8(vceqq_u8(input, first), vceqq_u8(input, second)),
            vorrq_u8(vceqq_u8(input, third), vceqq_u8(input, fourth)),
        )
    };
    let mut block_start = 0_usize;
    let mut groups = bytes.chunks_exact(BYTE_SET_WIDE_BLOCK_BYTES);
    for group in &mut groups {
        let first_block: &[u8; BYTE_SET_BLOCK_BYTES] = group[..BYTE_SET_BLOCK_BYTES]
            .try_into()
            .expect("a wide group has one exact first NEON block");
        let second_block: &[u8; BYTE_SET_BLOCK_BYTES] = group[BYTE_SET_BLOCK_BYTES..]
            .try_into()
            .expect("a wide group has one exact second NEON block");
        // SAFETY: both array references prove their exact load extents.
        let (first_input, second_input) = unsafe {
            (
                vld1q_u8(first_block.as_ptr()),
                vld1q_u8(second_block.as_ptr()),
            )
        };
        if vmaxvq_u8(vorrq_u8(classify(first_input), classify(second_input))) != 0 {
            return group
                .iter()
                .position(|byte| members.contains(byte))
                .and_then(|relative| block_start.checked_add(relative));
        }
        block_start = block_start
            .checked_add(BYTE_SET_WIDE_BLOCK_BYTES)
            .expect("a complete group stays within its source slice");
    }
    let remainder = groups.remainder();
    let mut tail = remainder;
    if remainder.len() >= BYTE_SET_BLOCK_BYTES {
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = remainder[..BYTE_SET_BLOCK_BYTES]
            .try_into()
            .expect("a wide remainder has one exact NEON block");
        // SAFETY: the array reference proves the exact load extent.
        let input = unsafe { vld1q_u8(block.as_ptr()) };
        if vmaxvq_u8(classify(input)) != 0 {
            return block
                .iter()
                .position(|byte| members.contains(byte))
                .and_then(|relative| block_start.checked_add(relative));
        }
        block_start = block_start
            .checked_add(BYTE_SET_BLOCK_BYTES)
            .expect("a trailing vector block stays within its source slice");
        tail = &remainder[BYTE_SET_BLOCK_BYTES..];
    }
    tail.iter()
        .position(|byte| members.contains(byte))
        .and_then(|relative| block_start.checked_add(relative))
}

#[allow(
    unsafe_code,
    reason = "this private target-feature helper reads one exact 16-byte block after its retained scanner proved NEON usable"
)]
#[target_feature(enable = "neon")]
pub(super) unsafe fn block_all_members_neon(
    columns: &[u8; ASCII_NARROW_BYTES],
    bytes: &[u8; ASCII_NARROW_BYTES],
) -> bool {
    // SAFETY: both arguments are initialized exact-width arrays, and the only
    // callers execute after construction retained a NEON-authorized entry.
    let (input, columns, high_nibble_bits) = unsafe {
        (
            vld1q_u8(bytes.as_ptr()),
            vld1q_u8(columns.as_ptr()),
            vld1q_u8(HIGH_NIBBLE_BITS.as_ptr()),
        )
    };
    let low_nibbles = vandq_u8(input, vdupq_n_u8(0x0f));
    let high_nibbles = vshrq_n_u8::<4>(input);
    let selected_columns = vqtbl1q_u8(columns, low_nibbles);
    let selected_high_bits = vqtbl1q_u8(high_nibble_bits, high_nibbles);
    let selected_bits = vandq_u8(selected_columns, selected_high_bits);
    let member_lanes = vcgtq_u8(selected_bits, vdupq_n_u8(0));
    vminvq_u8(member_lanes) == u8::MAX
}

#[allow(
    unsafe_code,
    reason = "compiler target features prove NEON once around the whole-slice ASCII member loop"
)]
#[cfg(any(not(feature = "static-dispatch"), target_feature = "neon"))]
#[target_feature(enable = "neon")]
#[inline(never)]
pub(super) unsafe fn find_ascii_members_neon(
    columns: &[u8; ASCII_NARROW_BYTES],
    set: AsciiByteSet,
    bytes: &[u8],
) -> Option<usize> {
    use core::arch::aarch64::{vmaxvq_u8, vorrq_u8};

    // SAFETY: both tables contain exactly sixteen initialized bytes and this
    // enclosing leaf already has NEON enabled.
    let (columns, high_nibble_bits) = unsafe {
        (
            vld1q_u8(columns.as_ptr()),
            vld1q_u8(HIGH_NIBBLE_BITS.as_ptr()),
        )
    };
    let classify = |input| {
        let low_nibbles = vandq_u8(input, vdupq_n_u8(0x0f));
        let high_nibbles = vshrq_n_u8::<4>(input);
        let selected_columns = vqtbl1q_u8(columns, low_nibbles);
        let selected_high_bits = vqtbl1q_u8(high_nibble_bits, high_nibbles);
        vcgtq_u8(
            vandq_u8(selected_columns, selected_high_bits),
            vdupq_n_u8(0),
        )
    };
    let scalar_find = |slice: &[u8]| slice.iter().position(|&byte| set.contains(byte));
    let mut block_start = 0_usize;
    let mut groups = bytes.chunks_exact(BYTE_SET_WIDE_BLOCK_BYTES);
    for group in &mut groups {
        let first: &[u8; BYTE_SET_BLOCK_BYTES] = group[..BYTE_SET_BLOCK_BYTES]
            .try_into()
            .expect("a wide group has one exact first NEON block");
        let second: &[u8; BYTE_SET_BLOCK_BYTES] = group[BYTE_SET_BLOCK_BYTES..]
            .try_into()
            .expect("a wide group has one exact second NEON block");
        // SAFETY: both array references prove their exact load extents.
        let (first_input, second_input) = unsafe {
            (
                vld1q_u8(first.as_ptr()),
                vld1q_u8(second.as_ptr()),
            )
        };
        if vmaxvq_u8(vorrq_u8(classify(first_input), classify(second_input))) != 0 {
            return scalar_find(group).and_then(|relative| block_start.checked_add(relative));
        }
        block_start = block_start
            .checked_add(BYTE_SET_WIDE_BLOCK_BYTES)
            .expect("a complete group stays within its source slice");
    }
    let remainder = groups.remainder();
    let mut tail = remainder;
    if remainder.len() >= BYTE_SET_BLOCK_BYTES {
        let block: &[u8; BYTE_SET_BLOCK_BYTES] = remainder[..BYTE_SET_BLOCK_BYTES]
            .try_into()
            .expect("a wide remainder has one exact NEON block");
        // SAFETY: the array reference proves the exact load extent.
        let input = unsafe { vld1q_u8(block.as_ptr()) };
        if vmaxvq_u8(classify(input)) != 0 {
            return scalar_find(block).and_then(|relative| block_start.checked_add(relative));
        }
        block_start = block_start
            .checked_add(BYTE_SET_BLOCK_BYTES)
            .expect("a trailing vector block stays within its source slice");
        tail = &remainder[BYTE_SET_BLOCK_BYTES..];
    }
    scalar_find(tail).and_then(|relative| block_start.checked_add(relative))
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf performs exact 16-byte NEON loads only after retained dispatch proved NEON usable"
)]
#[target_feature(enable = "neon")]
#[inline(never)]
pub(super) unsafe fn scan_run_forward_neon(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    let mut member_run_len = 0_usize;
    let mut examined_bytes = 0_usize;
    let mut blocks = bytes.chunks_exact(ASCII_NARROW_BYTES);
    for block in &mut blocks {
        let block: &[u8; ASCII_NARROW_BYTES] = block
            .try_into()
            .expect("chunks_exact yields one exact NEON block");
        examined_bytes = examined_bytes
            .checked_add(ASCII_NARROW_BYTES)
            .expect("a slice's vector block count fits in usize");
        // SAFETY: this leaf is itself entered only after NEON authorization,
        // and `block` proves the exact load extent.
        if !unsafe { block_all_members_neon(&tables.columns, block) } {
            let recovery = scalar::scan_run_forward(tables.set, block);
            return AsciiRunResult::new(
                member_run_len
                    .checked_add(recovery.member_run_len())
                    .expect("a block boundary stays within its slice"),
                examined_bytes
                    .checked_add(recovery.examined_bytes())
                    .expect("vector probing plus one scalar block fits in usize"),
            );
        }
        member_run_len = member_run_len
            .checked_add(ASCII_NARROW_BYTES)
            .expect("a completed vector block stays within its slice");
    }
    let tail = scalar::scan_run_forward(tables.set, blocks.remainder());
    AsciiRunResult::new(
        member_run_len
            .checked_add(tail.member_run_len())
            .expect("the vector prefix and scalar tail partition the slice"),
        examined_bytes
            .checked_add(tail.examined_bytes())
            .expect("the vector prefix and scalar tail partition the slice"),
    )
}

#[allow(
    unsafe_code,
    reason = "this private target-feature leaf performs exact 16-byte NEON loads only after retained dispatch proved NEON usable"
)]
#[target_feature(enable = "neon")]
#[inline(never)]
pub(super) unsafe fn scan_run_backward_neon(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    let mut member_run_len = 0_usize;
    let mut examined_bytes = 0_usize;
    let mut blocks = bytes.rchunks_exact(ASCII_NARROW_BYTES);
    for block in &mut blocks {
        let block: &[u8; ASCII_NARROW_BYTES] = block
            .try_into()
            .expect("rchunks_exact yields one exact NEON block");
        examined_bytes = examined_bytes
            .checked_add(ASCII_NARROW_BYTES)
            .expect("a slice's vector block count fits in usize");
        // SAFETY: this leaf is itself entered only after NEON authorization,
        // and `block` proves the exact load extent.
        if !unsafe { block_all_members_neon(&tables.columns, block) } {
            let recovery = scalar::scan_run_backward(tables.set, block);
            return AsciiRunResult::new(
                member_run_len
                    .checked_add(recovery.member_run_len())
                    .expect("a block boundary stays within its slice"),
                examined_bytes
                    .checked_add(recovery.examined_bytes())
                    .expect("vector probing plus one scalar block fits in usize"),
            );
        }
        member_run_len = member_run_len
            .checked_add(ASCII_NARROW_BYTES)
            .expect("a completed vector block stays within its slice");
    }
    let head = scalar::scan_run_backward(tables.set, blocks.remainder());
    AsciiRunResult::new(
        member_run_len
            .checked_add(head.member_run_len())
            .expect("the scalar head and vector suffix partition the slice"),
        examined_bytes
            .checked_add(head.examined_bytes())
            .expect("the scalar head and vector suffix partition the slice"),
    )
}
