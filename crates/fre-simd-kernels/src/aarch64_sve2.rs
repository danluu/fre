use super::{ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, AsciiMasks32};

// This is a leaf AAPCS64 function. Its two pointer arguments arrive in x0/x1
// and its packed u64 result returns in x0: member lanes occupy bits 0..31 and
// ASCII lanes occupy bits 32..63. It clobbers only caller-saved x8..x15,
// z0..z6 and p0..p3.
//
// The input is processed in `cntb`-sized chunks under `whilelo`, so both the
// architectural minimum VL=16 and every larger legal VL consume exactly 32
// bytes. TBL implements byte-set lookup. SVE2 MATCH computes the ASCII
// predicate by matching high nibbles against 0..7 in each 128-bit segment.
// Predicates are serialized into one fixed 32-byte stack slot. The architecture
// caps VL at 256 bytes, so a stored byte predicate occupies at most VL/8 = 32
// bytes. VL=16 reads its exact two predicate bytes, while VL>=32 reads the first
// four. A fixed slot also permits ordinary constant-CFA unwind metadata.
#[allow(
    unsafe_code,
    reason = "this module contains only the reviewed global assembly boundary; private Rust dispatch proves SVE and SVE2 usable before entry"
)]
mod reviewed_assembly {
    use core::arch::global_asm;

    global_asm!(
        r#"
    .pushsection .text.fre_ascii_mask32_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_ascii_mask32_sve2_asm
    .global fre_ascii_mask32_sve2_asm
    .type fre_ascii_mask32_sve2_asm, %function
fre_ascii_mask32_sve2_asm:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    mov x8, #0
    mov x9, #32
    mov x10, #16
    mov x12, #0
    mov x13, #0

    // The nibble table has exactly 16 initialized bytes. All higher lanes are
    // zeroed, and every TBL index below is in 0..15.
    whilelo p3.b, xzr, x10
    ld1b z0.b, p3/z, [x0]
    cntb x11

1:
    whilelo p0.b, x8, x9
    ld1b z2.b, p0/z, [x1, x8]

    mov z3.d, z2.d
    and z3.b, z3.b, #0x0f
    mov z4.d, z2.d
    lsr z4.b, z4.b, #4
    tbl z3.b, {{z0.b}}, z3.b

    // 1 << high_nibble is zero for non-ASCII high nibbles 8..15.
    mov z5.b, #1
    lsl z5.b, p0/m, z5.b, z4.b
    and z3.d, z3.d, z5.d
    cmpne p1.b, p0/z, z3.b, #0

    // MATCH is SVE2. Each architectural 128-bit segment of z6 contains 0..7
    // twice, so an active lane matches iff its high nibble denotes ASCII.
    index z6.b, #0, #1
    and z6.b, z6.b, #7
    match p2.b, p0/z, z4.b, z6.b

    str p1, [sp]
    cmp x11, #32
    b.lo 2f
    ldr w14, [sp]
    b 3f
2:
    // SVE vector lengths are multiples of 16 bytes; therefore the only legal
    // VL below 32 is 16, whose byte predicate occupies exactly two bytes.
    ldrh w14, [sp]
3:
    str p2, [sp]
    cmp x11, #32
    b.lo 4f
    ldr w15, [sp]
    b 5f
4:
    ldrh w15, [sp]
5:
    lsl x14, x14, x8
    lsl x15, x15, x8
    orr x12, x12, x14
    orr x13, x13, x15

    incb x8
    cmp x8, #32
    b.lo 1b

    orr x0, x12, x13, lsl #32
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size fre_ascii_mask32_sve2_asm, .-fre_ascii_mask32_sve2_asm
    .popsection
"#
    );
}

#[allow(
    unsafe_code,
    reason = "this private declaration is implemented by the reviewed SVE2 global assembly above"
)]
unsafe extern "C" {
    fn fre_ascii_mask32_sve2_asm(columns: *const u8, bytes: *const u8) -> u64;
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed assembly after its retained classifier handle proved SVE and SVE2 usable"
)]
#[inline(never)]
pub(super) unsafe fn classify_32_sve2(
    columns: &[u8; ASCII_NARROW_BYTES],
    bytes: &[u8; ASCII_WIDE_BYTES],
) -> AsciiMasks32 {
    // SAFETY: the assembly loads exactly 16 initialized bytes from `columns`
    // and exactly 32 initialized bytes from `bytes`, predicated in legal-VL
    // chunks. Its only other memory is a 32-byte stack slot, large enough for
    // the architectural maximum predicate store, and covered by constant-CFA
    // unwind metadata. The retained private entry is reachable only after
    // dispatch proves SVE and SVE2 are both OS-usable for this thread.
    let packed = unsafe { fre_ascii_mask32_sve2_asm(columns.as_ptr(), bytes.as_ptr()) };
    let members = u32::try_from(packed & u64::from(u32::MAX))
        .expect("the low half of a u64 always fits in u32");
    let ascii = u32::try_from(packed >> 32).expect("the high half of a u64 always fits in u32");
    AsciiMasks32::new(ascii, members)
}
