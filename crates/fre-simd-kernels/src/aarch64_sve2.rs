#![cfg_attr(
    feature = "static-dispatch",
    allow(
        dead_code,
        reason = "compiler-fixed profiles deliberately prune SVE/SVE2 leaves that are not selected by their tuning policy"
    )
)]

use super::{
    ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, AsciiMasks32, AsciiNonMemberRunResult, AsciiRunResult,
    AsciiRunTables, AsciiWordSpaceMasks16, AsciiWordSpaceMasks32, AsciiWordSpaceTables, aarch64,
    scalar,
};
use crate::byte_set::ByteSetTables;
use crate::{BYTE_SET_WIDE_BLOCK_BYTES, ByteSetMask32};

// This is a leaf AAPCS64 function. Its two pointer arguments arrive in x0/x1
// and its packed u64 result returns in x0: member lanes occupy bits 0..31 and
// ASCII lanes occupy bits 32..63. It clobbers only caller-saved x8..x15,
// z0..z7 and p0..p3.
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
    reason = "this module contains only reviewed global assembly boundaries; private Rust dispatch proves each leaf's exact SVE or SVE2 feature set usable before entry"
)]
mod reviewed_assembly {
    use core::arch::global_asm;

    global_asm!(
        r#"
    .pushsection .text.fre_byte_set1_mask16_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_byte_set1_mask16_sve2_asm
    .global fre_byte_set1_mask16_sve2_asm
    .type fre_byte_set1_mask16_sve2_asm, %function
fre_byte_set1_mask16_sve2_asm:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    ptrue p0.b, vl16
    dup z0.b, w0
    ld1b z1.b, p0/z, [x1]
    cmpeq p1.b, p0/z, z1.b, z0.b
    str p1, [sp]
    ldrh w0, [sp]
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size fre_byte_set1_mask16_sve2_asm, .-fre_byte_set1_mask16_sve2_asm
    .popsection

    .pushsection .text.fre_byte_set2_mask16_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_byte_set2_mask16_sve2_asm
    .global fre_byte_set2_mask16_sve2_asm
    .type fre_byte_set2_mask16_sve2_asm, %function
fre_byte_set2_mask16_sve2_asm:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    ptrue p0.b, vl16
    dup z0.h, w0
    ld1b z1.b, p0/z, [x1]
    match p1.b, p0/z, z1.b, z0.b
    str p1, [sp]
    ldrh w0, [sp]
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size fre_byte_set2_mask16_sve2_asm, .-fre_byte_set2_mask16_sve2_asm
    .popsection

    // One fixed-width full-byte four-value classifier. DUP repeats the four
    // construction-time bytes in every 32-bit lane, so each architectural
    // 128-bit MATCH segment contains the same complete set. Only the first
    // sixteen source lanes are active. A predicate store serializes their
    // membership bits in increasing lane order.
    .pushsection .text.fre_byte_set4_mask16_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_byte_set4_mask16_sve2_asm
    .global fre_byte_set4_mask16_sve2_asm
    .type fre_byte_set4_mask16_sve2_asm, %function
fre_byte_set4_mask16_sve2_asm:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    ptrue p0.b, vl16
    dup z0.s, w0
    ld1b z1.b, p0/z, [x1]
    match p1.b, p0/z, z1.b, z0.b
    str p1, [sp]
    ldrh w0, [sp]
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size fre_byte_set4_mask16_sve2_asm, .-fre_byte_set4_mask16_sve2_asm
    .popsection
"#
    );

    global_asm!(
        r#"
    .pushsection .text.fre_byte_set1_mask32_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_byte_set1_mask32_sve2_asm
    .global fre_byte_set1_mask32_sve2_asm
    .type fre_byte_set1_mask32_sve2_asm, %function
fre_byte_set1_mask32_sve2_asm:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    dup z0.b, w0
    mov x8, #0
    mov x9, #32
    mov x12, #0
    cntb x11
1:
    whilelo p0.b, x8, x9
    ld1b z1.b, p0/z, [x1, x8]
    cmpeq p1.b, p0/z, z1.b, z0.b
    str p1, [sp]
    cmp x11, #32
    b.lo 2f
    ldr w14, [sp]
    b 3f
2:
    ldrh w14, [sp]
3:
    lsl x14, x14, x8
    orr x12, x12, x14
    incb x8
    cmp x8, #32
    b.lo 1b
    mov w0, w12
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size fre_byte_set1_mask32_sve2_asm, .-fre_byte_set1_mask32_sve2_asm
    .popsection

    .pushsection .text.fre_byte_set2_mask32_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_byte_set2_mask32_sve2_asm
    .global fre_byte_set2_mask32_sve2_asm
    .type fre_byte_set2_mask32_sve2_asm, %function
fre_byte_set2_mask32_sve2_asm:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    dup z0.h, w0
    mov x8, #0
    mov x9, #32
    mov x12, #0
    cntb x11
1:
    whilelo p0.b, x8, x9
    ld1b z1.b, p0/z, [x1, x8]
    match p1.b, p0/z, z1.b, z0.b
    str p1, [sp]
    cmp x11, #32
    b.lo 2f
    ldr w14, [sp]
    b 3f
2:
    ldrh w14, [sp]
3:
    lsl x14, x14, x8
    orr x12, x12, x14
    incb x8
    cmp x8, #32
    b.lo 1b
    mov w0, w12
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size fre_byte_set2_mask32_sve2_asm, .-fre_byte_set2_mask32_sve2_asm
    .popsection

    // Wide exact four-value classification for authenticated static profiles.
    // The loop handles both the architectural minimum VL=16 and every larger
    // legal VL while consuming exactly 32 source lanes.
    .pushsection .text.fre_byte_set4_mask32_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_byte_set4_mask32_sve2_asm
    .global fre_byte_set4_mask32_sve2_asm
    .type fre_byte_set4_mask32_sve2_asm, %function
fre_byte_set4_mask32_sve2_asm:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    dup z0.s, w0
    mov x8, #0
    mov x9, #32
    mov x12, #0
    cntb x11
1:
    whilelo p0.b, x8, x9
    ld1b z1.b, p0/z, [x1, x8]
    match p1.b, p0/z, z1.b, z0.b
    str p1, [sp]
    cmp x11, #32
    b.lo 2f
    ldr w14, [sp]
    b 3f
2:
    ldrh w14, [sp]
3:
    lsl x14, x14, x8
    orr x12, x12, x14
    incb x8
    cmp x8, #32
    b.lo 1b
    mov w0, w12
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size fre_byte_set4_mask32_sve2_asm, .-fre_byte_set4_mask32_sve2_asm
    .popsection

    // Scan complete 32-byte blocks for a construction-time set of at most 16
    // byte values. LD1RQB repeats the padded table in every 128-bit segment.
    // Keeping the table, predicate spill slot, and outer zero-mask loop in one
    // leaf avoids repeating fixed setup for long candidate-free prefixes. A
    // hit returns its block-relative source offset in x0 and the complete block
    // mask in x1; no hit returns the supplied complete length and a zero mask.
    .pushsection .text.fre_byte_values16_first_mask32_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_byte_values16_first_mask32_sve2_asm
    .global fre_byte_values16_first_mask32_sve2_asm
    .type fre_byte_values16_first_mask32_sve2_asm, %function
fre_byte_values16_first_mask32_sve2_asm:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    ptrue p2.b
    ld1rqb z0.b, p2/z, [x0]
    mov x8, #0
    mov x14, #32
    cntb x11
1:
    cmp x8, x2
    b.hs 6f
    mov x9, #0
    mov x12, #0
2:
    whilelo p0.b, x9, x14
    add x10, x8, x9
    ld1b z1.b, p0/z, [x1, x10]
    match p1.b, p0/z, z1.b, z0.b
    ptest p0, p1.b
    b.none 7f
    str p1, [sp]
    cmp x11, #32
    b.lo 3f
    ldr w13, [sp]
    b 4f
3:
    ldrh w13, [sp]
4:
    lsl x15, x13, x9
    orr x12, x12, x15
7:
    incb x9
    cmp x9, #32
    b.lo 2b
    cbnz x12, 5f
    add x8, x8, #32
    b 1b
5:
    mov x0, x8
    mov x1, x12
    b 8f
6:
    mov x0, x2
    mov x1, xzr
8:
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size fre_byte_values16_first_mask32_sve2_asm, .-fre_byte_values16_first_mask32_sve2_asm
    .popsection

    // Scan complete 128-byte groups for any of at most sixteen byte values.
    // Predicate OR accumulation replaces four fixed-32 ptest/branch pairs with
    // one group decision. A caller that observes a hit recovers its exact lane
    // within that bounded group; no hit returns the supplied complete length.
    // The loop is vector-length agnostic: WHILELO bounds every load even when
    // the effective vector length exceeds the fixed group extent.
    .pushsection .text.fre_byte_values16_first_group128_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_byte_values16_first_group128_sve2_asm
    .global fre_byte_values16_first_group128_sve2_asm
    .type fre_byte_values16_first_group128_sve2_asm, %function
fre_byte_values16_first_group128_sve2_asm:
    .cfi_startproc
    ptrue p2.b
    ld1rqb z0.b, p2/z, [x0]
    mov x8, #0
    mov x14, #128
1:
    cmp x8, x2
    b.hs 4f
    mov x9, #0
    pfalse p3.b
2:
    whilelo p0.b, x9, x14
    add x10, x8, x9
    ld1b z1.b, p0/z, [x1, x10]
    match p1.b, p0/z, z1.b, z0.b
    orr p3.b, p2/z, p3.b, p1.b
    incb x9
    cmp x9, #128
    b.lo 2b
    ptest p2, p3.b
    b.any 3f
    add x8, x8, #128
    b 1b
3:
    mov x0, x8
    ret
4:
    mov x0, x2
    ret
    .cfi_endproc
    .size fre_byte_values16_first_group128_sve2_asm, .-fre_byte_values16_first_group128_sve2_asm
    .popsection

    // Wide arbitrary full-byte-set classification. The two nibble tables
    // together represent all 256 byte values. SVE2 MATCH selects the lower or
    // upper high-nibble table without any input-dependent dispatch.
    .pushsection .text.fre_byte_set_mask32_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_byte_set_mask32_sve2_asm
    .global fre_byte_set_mask32_sve2_asm
    .type fre_byte_set_mask32_sve2_asm, %function
fre_byte_set_mask32_sve2_asm:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    mov x8, #0
    mov x9, #32
    mov x12, #0
    ptrue p3.b, vl16
    ld1b z0.b, p3/z, [x0]
    ld1b z1.b, p3/z, [x1]
    cntb x11
1:
    whilelo p0.b, x8, x9
    ld1b z2.b, p0/z, [x2, x8]
    mov z3.d, z2.d
    and z3.b, z3.b, #0x0f
    mov z4.d, z2.d
    lsr z4.b, z4.b, #4
    tbl z5.b, {{z0.b}}, z3.b
    tbl z6.b, {{z1.b}}, z3.b

    // High nibbles above seven select the upper table. Unlike MATCH against
    // a synthesized 0..7 vector, the immediate comparison needs no temporary
    // vector construction and remains exact at every architectural SVE
    // vector length.
    cmphi p2.b, p0/z, z4.b, #7
    sel z5.b, p2, z6.b, z5.b
    and z4.b, z4.b, #7
    mov z7.b, #1
    lsl z7.b, p0/m, z7.b, z4.b
    and z5.d, z5.d, z7.d
    cmpne p1.b, p0/z, z5.b, #0

    str p1, [sp]
    cmp x11, #32
    b.lo 2f
    ldr w14, [sp]
    b 3f
2:
    ldrh w14, [sp]
3:
    lsl x14, x14, x8
    orr x12, x12, x14
    incb x8
    cmp x8, #32
    b.lo 1b
    mov w0, w12
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size fre_byte_set_mask32_sve2_asm, .-fre_byte_set_mask32_sve2_asm
    .popsection
"#
    );

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

    global_asm!(
        r#"
    // Fused three-class token-phrase classifiers. Both leaves activate
    // exactly sixteen byte lanes. The word class uses one nibble table; the
    // six ASCII whitespace bytes use SVE2 MATCH. All remaining lanes,
    // including non-ASCII bytes, are implicitly `other`.
    .pushsection .text.fre_ascii_word_space_mask16_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_ascii_word_space_mask16_sve2_asm
    .global fre_ascii_word_space_mask16_sve2_asm
    .type fre_ascii_word_space_mask16_sve2_asm, %function
fre_ascii_word_space_mask16_sve2_asm:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    ptrue p0.b, vl16
    ld1b z0.b, p0/z, [x0]
    ld1rqb z1.b, p0/z, [x1]
    ld1b z2.b, p0/z, [x2]

    mov z3.d, z2.d
    and z3.b, z3.b, #0x0f
    mov z4.d, z2.d
    lsr z4.b, z4.b, #4
    tbl z3.b, {{z0.b}}, z3.b
    mov z5.b, #1
    lsl z5.b, p0/m, z5.b, z4.b
    and z3.d, z3.d, z5.d
    cmpne p1.b, p0/z, z3.b, #0
    match p2.b, p0/z, z2.b, z1.b

    str p1, [sp]
    ldrh w8, [sp]
    str p2, [sp]
    ldrh w9, [sp]
    orr w0, w8, w9, lsl #16
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size fre_ascii_word_space_mask16_sve2_asm, .-fre_ascii_word_space_mask16_sve2_asm
    .popsection

    .pushsection .text.fre_ascii_word_space_mask32_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_ascii_word_space_mask32_sve2_asm
    .global fre_ascii_word_space_mask32_sve2_asm
    .type fre_ascii_word_space_mask32_sve2_asm, %function
fre_ascii_word_space_mask32_sve2_asm:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    ptrue p0.b, vl16
    ld1b z0.b, p0/z, [x0]
    ld1rqb z1.b, p0/z, [x1]

    ld1b z2.b, p0/z, [x2]
    mov z3.d, z2.d
    and z3.b, z3.b, #0x0f
    mov z4.d, z2.d
    lsr z4.b, z4.b, #4
    tbl z3.b, {{z0.b}}, z3.b
    mov z5.b, #1
    lsl z5.b, p0/m, z5.b, z4.b
    and z3.d, z3.d, z5.d
    cmpne p1.b, p0/z, z3.b, #0
    match p2.b, p0/z, z2.b, z1.b
    str p1, [sp]
    ldrh w10, [sp]
    str p2, [sp]
    ldrh w11, [sp]

    add x8, x2, #16
    ld1b z2.b, p0/z, [x8]
    mov z3.d, z2.d
    and z3.b, z3.b, #0x0f
    mov z4.d, z2.d
    lsr z4.b, z4.b, #4
    tbl z3.b, {{z0.b}}, z3.b
    mov z5.b, #1
    lsl z5.b, p0/m, z5.b, z4.b
    and z3.d, z3.d, z5.d
    cmpne p1.b, p0/z, z3.b, #0
    match p2.b, p0/z, z2.b, z1.b
    str p1, [sp]
    ldrh w12, [sp]
    str p2, [sp]
    ldrh w13, [sp]

    orr w10, w10, w12, lsl #16
    orr w11, w11, w13, lsl #16
    orr x0, x10, x11, lsl #32
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc
    .size fre_ascii_word_space_mask32_sve2_asm, .-fre_ascii_word_space_mask32_sve2_asm
    .popsection
"#
    );

    global_asm!(
        r#"
    // Run leaves deliberately activate at most 16 byte lanes per load. That
    // preserves the operation's published +16 accounting bound and makes
    // qualification at the requested 128-bit shape independent of hardware VL.

    // Direct base-SVE prefix scanner. It returns AsciiRunResult in x0/x1:
    // member prefix length followed by exact physically classified bytes.
    .pushsection .text.fre_ascii_run_forward_sve_asm, "ax", %progbits
    .arch armv8-a+sve
    .p2align 2
    .hidden fre_ascii_run_forward_sve_asm
    .global fre_ascii_run_forward_sve_asm
    .type fre_ascii_run_forward_sve_asm, %function
fre_ascii_run_forward_sve_asm:
    .cfi_startproc
    ptrue p0.b, vl16
    ld1b z0.b, p0/z, [x0]
    mov x8, #0
    cmp x2, #16
    b.lo 3f
1:
    ld1b z2.b, p0/z, [x1, x8]

    mov z3.d, z2.d
    and z3.b, z3.b, #0x0f
    mov z4.d, z2.d
    lsr z4.b, z4.b, #4
    tbl z3.b, {{z0.b}}, z3.b
    mov z5.b, #1
    lsl z5.b, p0/m, z5.b, z4.b
    and z3.d, z3.d, z5.d
    cmpne p1.b, p0/z, z3.b, #0
    not p2.b, p0/z, p1.b
    ptest p0, p2.b
    b.none 2f
    b 4f

2:
    add x8, x8, #16
    sub x10, x2, x8
    cmp x10, #16
    b.hs 1b
3:
    cmp x8, x2
    b.hs 5f
    whilelo p0.b, x8, x2
    ld1b z2.b, p0/z, [x1, x8]

    mov z3.d, z2.d
    and z3.b, z3.b, #0x0f
    mov z4.d, z2.d
    lsr z4.b, z4.b, #4
    tbl z3.b, {{z0.b}}, z3.b
    mov z5.b, #1
    lsl z5.b, p0/m, z5.b, z4.b
    and z3.d, z3.d, z5.d
    cmpne p1.b, p0/z, z3.b, #0
    not p2.b, p0/z, p1.b
    ptest p0, p2.b
    b.none 5f
4:
    // BRKB retains active lanes strictly before the first nonmember.
    brkb p3.b, p0/z, p2.b
    cntp x10, p0, p3.b
    add x0, x8, x10
    cntp x11, p0, p0.b
    add x1, x8, x11
    ret
5:
    mov x0, x2
    mov x1, x2
    ret
    .cfi_endproc
    .size fre_ascii_run_forward_sve_asm, .-fre_ascii_run_forward_sve_asm
    .popsection

    // Direct base-SVE suffix scanner. LASTB obtains the final nonmember lane
    // from a byte index vector without serializing a predicate.
    .pushsection .text.fre_ascii_run_backward_sve_asm, "ax", %progbits
    .arch armv8-a+sve
    .p2align 2
    .hidden fre_ascii_run_backward_sve_asm
    .global fre_ascii_run_backward_sve_asm
    .type fre_ascii_run_backward_sve_asm, %function
fre_ascii_run_backward_sve_asm:
    .cfi_startproc
    ptrue p0.b, vl16
    ld1b z0.b, p0/z, [x0]
    index z6.b, #0, #1
    mov x8, x2
    cmp x8, #16
    b.lo 3f
1:
    sub x11, x8, #16
    ld1b z2.b, p0/z, [x1, x11]

    mov z3.d, z2.d
    and z3.b, z3.b, #0x0f
    mov z4.d, z2.d
    lsr z4.b, z4.b, #4
    tbl z3.b, {{z0.b}}, z3.b
    mov z5.b, #1
    lsl z5.b, p0/m, z5.b, z4.b
    and z3.d, z3.d, z5.d
    cmpne p1.b, p0/z, z3.b, #0
    not p2.b, p0/z, p1.b
    ptest p0, p2.b
    b.none 2f
    b 4f

2:
    mov x8, x11
    cmp x8, #16
    b.hs 1b
3:
    cbz x8, 5f
    mov x11, #0
    whilelo p0.b, xzr, x8
    ld1b z2.b, p0/z, [x1]

    mov z3.d, z2.d
    and z3.b, z3.b, #0x0f
    mov z4.d, z2.d
    lsr z4.b, z4.b, #4
    tbl z3.b, {{z0.b}}, z3.b
    mov z5.b, #1
    lsl z5.b, p0/m, z5.b, z4.b
    and z3.d, z3.d, z5.d
    cmpne p1.b, p0/z, z3.b, #0
    not p2.b, p0/z, p1.b
    ptest p0, p2.b
    b.none 5f
4:
    lastb w12, p2, z6.b
    uxtb x12, w12
    add x12, x11, x12
    add x12, x12, #1
    sub x0, x2, x12
    sub x1, x2, x11
    ret
5:
    mov x0, x2
    mov x1, x2
    ret
    .cfi_endproc
    .size fre_ascii_run_backward_sve_asm, .-fre_ascii_run_backward_sve_asm
    .popsection

    // SVE2 MATCH compares each input lane with the construction-time set of
    // 1..=16 ASCII values. LD1RQB repeats that set in every 128-bit segment,
    // preserving correctness at every architectural vector length.
    .pushsection .text.fre_ascii_run_forward_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_ascii_run_forward_sve2_asm
    .global fre_ascii_run_forward_sve2_asm
    .type fre_ascii_run_forward_sve2_asm, %function
fre_ascii_run_forward_sve2_asm:
    .cfi_startproc
    ptrue p0.b, vl16
    ld1rqb z0.b, p0/z, [x0]
    mov x8, #0
    cmp x2, #16
    b.lo 3f
1:
    ld1b z2.b, p0/z, [x1, x8]
    match p1.b, p0/z, z2.b, z0.b
    not p2.b, p0/z, p1.b
    ptest p0, p2.b
    b.none 2f
    b 4f

2:
    add x8, x8, #16
    sub x10, x2, x8
    cmp x10, #16
    b.hs 1b
3:
    cmp x8, x2
    b.hs 5f
    whilelo p0.b, x8, x2
    ld1b z2.b, p0/z, [x1, x8]
    match p1.b, p0/z, z2.b, z0.b
    not p2.b, p0/z, p1.b
    ptest p0, p2.b
    b.none 5f
4:
    brkb p3.b, p0/z, p2.b
    cntp x10, p0, p3.b
    add x0, x8, x10
    cntp x11, p0, p0.b
    add x1, x8, x11
    ret
5:
    mov x0, x2
    mov x1, x2
    ret
    .cfi_endproc
    .size fre_ascii_run_forward_sve2_asm, .-fre_ascii_run_forward_sve2_asm
    .popsection

    // SVE2 MATCH-until-member is the inverse traversal of the member-run
    // scanner above. High bytes cannot match the construction-time ASCII set,
    // so they extend the nonmember run without any separate ASCII barrier.
    .pushsection .text.fre_ascii_nonmember_run_forward_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_ascii_nonmember_run_forward_sve2_asm
    .global fre_ascii_nonmember_run_forward_sve2_asm
    .type fre_ascii_nonmember_run_forward_sve2_asm, %function
fre_ascii_nonmember_run_forward_sve2_asm:
    .cfi_startproc
    ptrue p0.b, vl16
    ld1rqb z0.b, p0/z, [x0]
    mov x8, #0
    cmp x2, #16
    b.lo 3f
1:
    ld1b z2.b, p0/z, [x1, x8]
    match p1.b, p0/z, z2.b, z0.b
    ptest p0, p1.b
    b.none 2f
    b 4f

2:
    add x8, x8, #16
    sub x10, x2, x8
    cmp x10, #16
    b.hs 1b
3:
    cmp x8, x2
    b.hs 5f
    whilelo p0.b, x8, x2
    ld1b z2.b, p0/z, [x1, x8]
    match p1.b, p0/z, z2.b, z0.b
    ptest p0, p1.b
    b.none 5f
4:
    brkb p3.b, p0/z, p1.b
    cntp x10, p0, p3.b
    add x0, x8, x10
    cntp x11, p0, p0.b
    add x1, x8, x11
    ret
5:
    mov x0, x2
    mov x1, x2
    ret
    .cfi_endproc
    .size fre_ascii_nonmember_run_forward_sve2_asm, .-fre_ascii_nonmember_run_forward_sve2_asm
    .popsection

    .pushsection .text.fre_ascii_run_backward_sve2_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_ascii_run_backward_sve2_asm
    .global fre_ascii_run_backward_sve2_asm
    .type fre_ascii_run_backward_sve2_asm, %function
fre_ascii_run_backward_sve2_asm:
    .cfi_startproc
    ptrue p0.b, vl16
    ld1rqb z0.b, p0/z, [x0]
    index z6.b, #0, #1
    mov x8, x2
    cmp x8, #16
    b.lo 3f
1:
    sub x11, x8, #16
    ld1b z2.b, p0/z, [x1, x11]
    match p1.b, p0/z, z2.b, z0.b
    not p2.b, p0/z, p1.b
    ptest p0, p2.b
    b.none 2f
    b 4f

2:
    mov x8, x11
    cmp x8, #16
    b.hs 1b
3:
    cbz x8, 5f
    mov x11, #0
    whilelo p0.b, xzr, x8
    ld1b z2.b, p0/z, [x1]
    match p1.b, p0/z, z2.b, z0.b
    not p2.b, p0/z, p1.b
    ptest p0, p2.b
    b.none 5f
4:
    lastb w12, p2, z6.b
    uxtb x12, w12
    add x12, x11, x12
    add x12, x12, #1
    sub x0, x2, x12
    sub x1, x2, x11
    ret
5:
    mov x0, x2
    mov x1, x2
    ret
    .cfi_endproc
    .size fre_ascii_run_backward_sve2_asm, .-fre_ascii_run_backward_sve2_asm
    .popsection

    // Complement MATCH treats the 1..=16 table values as excluded ASCII.
    // Every high-bit byte is also a barrier so Unicode-aware callers regain
    // control to validate and decode it instead of consuming it as ASCII.
    .pushsection .text.fre_ascii_run_forward_sve2_complement_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_ascii_run_forward_sve2_complement_asm
    .global fre_ascii_run_forward_sve2_complement_asm
    .type fre_ascii_run_forward_sve2_complement_asm, %function
fre_ascii_run_forward_sve2_complement_asm:
    .cfi_startproc
    ptrue p0.b, vl16
    ld1rqb z0.b, p0/z, [x0]
    mov x8, #0
    cmp x2, #16
    b.lo 3f
1:
    ld1b z2.b, p0/z, [x1, x8]
    match p1.b, p0/z, z2.b, z0.b
    cmplt p2.b, p0/z, z2.b, #0
    orr p2.b, p0/z, p2.b, p1.b
    ptest p0, p2.b
    b.none 2f
    b 4f
2:
    add x8, x8, #16
    sub x10, x2, x8
    cmp x10, #16
    b.hs 1b
3:
    cmp x8, x2
    b.hs 5f
    whilelo p0.b, x8, x2
    ld1b z2.b, p0/z, [x1, x8]
    match p1.b, p0/z, z2.b, z0.b
    cmplt p2.b, p0/z, z2.b, #0
    orr p2.b, p0/z, p2.b, p1.b
    ptest p0, p2.b
    b.none 5f
4:
    brkb p3.b, p0/z, p2.b
    cntp x10, p0, p3.b
    add x0, x8, x10
    cntp x11, p0, p0.b
    add x1, x8, x11
    ret
5:
    mov x0, x2
    mov x1, x2
    ret
    .cfi_endproc
    .size fre_ascii_run_forward_sve2_complement_asm, .-fre_ascii_run_forward_sve2_complement_asm
    .popsection

    .pushsection .text.fre_ascii_run_backward_sve2_complement_asm, "ax", %progbits
    .arch armv8-a+sve2
    .p2align 2
    .hidden fre_ascii_run_backward_sve2_complement_asm
    .global fre_ascii_run_backward_sve2_complement_asm
    .type fre_ascii_run_backward_sve2_complement_asm, %function
fre_ascii_run_backward_sve2_complement_asm:
    .cfi_startproc
    ptrue p0.b, vl16
    ld1rqb z0.b, p0/z, [x0]
    index z6.b, #0, #1
    mov x8, x2
    cmp x8, #16
    b.lo 3f
1:
    sub x11, x8, #16
    ld1b z2.b, p0/z, [x1, x11]
    match p1.b, p0/z, z2.b, z0.b
    cmplt p2.b, p0/z, z2.b, #0
    orr p2.b, p0/z, p2.b, p1.b
    ptest p0, p2.b
    b.none 2f
    b 4f
2:
    mov x8, x11
    cmp x8, #16
    b.hs 1b
3:
    cbz x8, 5f
    mov x11, #0
    whilelo p0.b, xzr, x8
    ld1b z2.b, p0/z, [x1]
    match p1.b, p0/z, z2.b, z0.b
    cmplt p2.b, p0/z, z2.b, #0
    orr p2.b, p0/z, p2.b, p1.b
    ptest p0, p2.b
    b.none 5f
4:
    lastb w12, p2, z6.b
    uxtb x12, w12
    add x12, x11, x12
    add x12, x12, #1
    sub x0, x2, x12
    sub x1, x2, x11
    ret
5:
    mov x0, x2
    mov x1, x2
    ret
    .cfi_endproc
    .size fre_ascii_run_backward_sve2_complement_asm, .-fre_ascii_run_backward_sve2_complement_asm
    .popsection
"#
    );
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct ByteValues16BlockScanResult {
    block_start: usize,
    member_mask: usize,
}

#[allow(
    unsafe_code,
    reason = "these private declarations are implemented by the reviewed base-SVE and SVE2 global assembly above"
)]
unsafe extern "C" {
    fn fre_byte_set1_mask16_sve2_asm(member: u8, bytes: *const u8) -> u16;
    fn fre_byte_set2_mask16_sve2_asm(members: u16, bytes: *const u8) -> u16;
    fn fre_byte_set4_mask16_sve2_asm(members: u32, bytes: *const u8) -> u16;
    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    fn fre_byte_set1_mask32_sve2_asm(member: u8, bytes: *const u8) -> u32;
    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    fn fre_byte_set2_mask32_sve2_asm(members: u16, bytes: *const u8) -> u32;
    #[cfg(all(
        feature = "static-dispatch-arm-41-d84",
        target_feature = "sve",
        target_feature = "sve2"
    ))]
    fn fre_byte_set4_mask32_sve2_asm(members: u32, bytes: *const u8) -> u32;
    fn fre_byte_values16_first_mask32_sve2_asm(
        match_values: *const u8,
        bytes: *const u8,
        len: usize,
    ) -> ByteValues16BlockScanResult;
    fn fre_byte_values16_first_group128_sve2_asm(
        match_values: *const u8,
        bytes: *const u8,
        len: usize,
    ) -> usize;
    fn fre_byte_set_mask32_sve2_asm(
        lower_columns: *const u8,
        upper_columns: *const u8,
        bytes: *const u8,
    ) -> u32;
    fn fre_ascii_mask32_sve2_asm(columns: *const u8, bytes: *const u8) -> u64;
    fn fre_ascii_word_space_mask16_sve2_asm(
        word_columns: *const u8,
        space_values: *const u8,
        bytes: *const u8,
    ) -> u32;
    fn fre_ascii_word_space_mask32_sve2_asm(
        word_columns: *const u8,
        space_values: *const u8,
        bytes: *const u8,
    ) -> u64;
    #[cfg_attr(
        feature = "static-dispatch-arm-41-d84",
        allow(
            dead_code,
            reason = "the compiler-fixed V3 run profile uses the qualified NEON/SVE2 hybrid instead of the base-SVE leaf"
        )
    )]
    fn fre_ascii_run_forward_sve_asm(
        columns: *const u8,
        bytes: *const u8,
        len: usize,
    ) -> AsciiRunResult;
    #[cfg_attr(
        feature = "static-dispatch-arm-41-d84",
        allow(
            dead_code,
            reason = "the compiler-fixed V3 run profile uses the qualified NEON/SVE2 hybrid instead of the base-SVE leaf"
        )
    )]
    fn fre_ascii_run_backward_sve_asm(
        columns: *const u8,
        bytes: *const u8,
        len: usize,
    ) -> AsciiRunResult;
    fn fre_ascii_run_forward_sve2_asm(
        match_values: *const u8,
        bytes: *const u8,
        len: usize,
    ) -> AsciiRunResult;
    fn fre_ascii_nonmember_run_forward_sve2_asm(
        match_values: *const u8,
        bytes: *const u8,
        len: usize,
    ) -> AsciiNonMemberRunResult;
    fn fre_ascii_run_backward_sve2_asm(
        match_values: *const u8,
        bytes: *const u8,
        len: usize,
    ) -> AsciiRunResult;
    fn fre_ascii_run_forward_sve2_complement_asm(
        excluded_ascii: *const u8,
        bytes: *const u8,
        len: usize,
    ) -> AsciiRunResult;
    fn fre_ascii_run_backward_sve2_complement_asm(
        excluded_ascii: *const u8,
        bytes: *const u8,
        len: usize,
    ) -> AsciiRunResult;
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed fixed-16 SVE2 assembly after compiler target features prove SVE plus SVE2 usable"
)]
#[inline]
pub(super) unsafe fn classify_byte_set1_16_sve2(
    member: u8,
    bytes: &[u8; crate::BYTE_SET_BLOCK_BYTES],
) -> crate::ByteSetMask16 {
    crate::ByteSetMask16::new(unsafe { fre_byte_set1_mask16_sve2_asm(member, bytes.as_ptr()) })
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed fixed-16 SVE2 assembly after compiler target features prove SVE plus SVE2 usable"
)]
#[inline]
pub(super) unsafe fn classify_byte_set2_16_sve2(
    members: [u8; 2],
    bytes: &[u8; crate::BYTE_SET_BLOCK_BYTES],
) -> crate::ByteSetMask16 {
    crate::ByteSetMask16::new(unsafe {
        fre_byte_set2_mask16_sve2_asm(u16::from_ne_bytes(members), bytes.as_ptr())
    })
}

#[allow(
    unsafe_code,
    reason = "SVE2 MATCH consumes an unordered segment-local set in one instruction, so repeating one of three members adds no comparison"
)]
#[inline]
pub(super) unsafe fn classify_byte_set3_16_sve2(
    members: [u8; 3],
    bytes: &[u8; crate::BYTE_SET_BLOCK_BYTES],
) -> crate::ByteSetMask16 {
    unsafe { classify_byte_set4_16_sve2([members[0], members[1], members[2], members[0]], bytes) }
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed fixed-16 SVE2 assembly after compiler target features prove SVE plus SVE2 usable"
)]
#[inline]
pub(super) unsafe fn classify_byte_set4_16_sve2(
    members: [u8; 4],
    bytes: &[u8; crate::BYTE_SET_BLOCK_BYTES],
) -> crate::ByteSetMask16 {
    let packed_members = u32::from_ne_bytes(members);
    // SAFETY: the compiler-selected caller proves SVE plus SVE2 globally. The
    // fixed array supplies all sixteen source bytes read by reviewed assembly;
    // the packed value contains the complete unordered four-byte set.
    crate::ByteSetMask16::new(unsafe {
        fre_byte_set4_mask16_sve2_asm(packed_members, bytes.as_ptr())
    })
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed fixed-32 SVE2 assembly after the authenticated compiler-static profile proves SVE plus SVE2 usable"
)]
#[cfg(all(
    feature = "static-dispatch-arm-41-d84",
    target_feature = "sve",
    target_feature = "sve2"
))]
#[inline]
pub(super) unsafe fn classify_byte_set1_32_sve2(
    member: u8,
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    ByteSetMask32::new(unsafe { fre_byte_set1_mask32_sve2_asm(member, bytes.as_ptr()) })
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed fixed-32 SVE2 assembly after the authenticated compiler-static profile proves SVE plus SVE2 usable"
)]
#[cfg(all(
    feature = "static-dispatch-arm-41-d84",
    target_feature = "sve",
    target_feature = "sve2"
))]
#[inline]
pub(super) unsafe fn classify_byte_set2_32_sve2(
    members: [u8; 2],
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    ByteSetMask32::new(unsafe {
        fre_byte_set2_mask32_sve2_asm(u16::from_ne_bytes(members), bytes.as_ptr())
    })
}

#[allow(
    unsafe_code,
    reason = "SVE2 MATCH consumes an unordered segment-local set in one instruction, so repeating one of three members adds no comparison"
)]
#[cfg(all(
    feature = "static-dispatch-arm-41-d84",
    target_feature = "sve",
    target_feature = "sve2"
))]
#[inline]
pub(super) unsafe fn classify_byte_set3_32_sve2(
    members: [u8; 3],
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    unsafe { classify_byte_set4_32_sve2([members[0], members[1], members[2], members[0]], bytes) }
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed fixed-32 SVE2 assembly after the authenticated compiler-static profile proves SVE plus SVE2 usable"
)]
#[cfg(all(
    feature = "static-dispatch-arm-41-d84",
    target_feature = "sve",
    target_feature = "sve2"
))]
#[inline]
pub(super) unsafe fn classify_byte_set4_32_sve2(
    members: [u8; 4],
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    let packed_members = u32::from_ne_bytes(members);
    // SAFETY: the compiler-static caller proves SVE plus SVE2. The fixed array
    // supplies all 32 source bytes and the packed value contains the complete
    // unordered four-byte set.
    ByteSetMask32::new(unsafe { fre_byte_set4_mask32_sve2_asm(packed_members, bytes.as_ptr()) })
}

#[allow(
    unsafe_code,
    reason = "this private leaf is reachable only when compiler target features guarantee SVE2 and scans complete fixed-width blocks from the supplied slice"
)]
#[inline]
pub(super) unsafe fn find_byte_values16_32_block_sve2(
    match_values: &[u8; 16],
    bytes: &[u8],
) -> Option<(usize, ByteSetMask32)> {
    debug_assert_eq!(bytes.len() % BYTE_SET_WIDE_BLOCK_BYTES, 0);
    // SAFETY: compiler target features prove SVE2 and the caller supplies only
    // complete 32-byte blocks. The complete initialized table is repeated in
    // every 128-bit segment; the assembly predicates every source load within
    // the reported length and returns one complete mask from the first hit block.
    let result = unsafe {
        fre_byte_values16_first_mask32_sve2_asm(
            match_values.as_ptr(),
            bytes.as_ptr(),
            bytes.len(),
        )
    };
    if result.member_mask == 0 {
        debug_assert_eq!(result.block_start, bytes.len());
        return None;
    }
    debug_assert!(result.block_start < bytes.len());
    debug_assert_eq!(result.block_start % BYTE_SET_WIDE_BLOCK_BYTES, 0);
    let member_mask = u32::try_from(result.member_mask)
        .expect("the exact 32-byte block mask occupies only the low 32 bits");
    Some((result.block_start, ByteSetMask32::new(member_mask)))
}

#[allow(
    unsafe_code,
    reason = "this private leaf is reachable only when compiler target features guarantee SVE2 and scans complete fixed-width groups from the supplied slice"
)]
#[inline]
pub(super) unsafe fn find_byte_values16_128_group_sve2(
    match_values: &[u8; 16],
    bytes: &[u8],
) -> usize {
    const GROUP_BYTES: usize = BYTE_SET_WIDE_BLOCK_BYTES * 4;
    debug_assert_eq!(bytes.len() % GROUP_BYTES, 0);
    // SAFETY: compiler target features prove SVE2, the caller supplies only
    // complete 128-byte groups, and the initialized table has sixteen bytes.
    let group_start = unsafe {
        fre_byte_values16_first_group128_sve2_asm(
            match_values.as_ptr(),
            bytes.as_ptr(),
            bytes.len(),
        )
    };
    debug_assert!(group_start == bytes.len() || group_start % GROUP_BYTES == 0);
    debug_assert!(group_start <= bytes.len());
    group_start
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed fixed-32 SVE2 assembly after the authenticated compiler-static profile proves SVE plus SVE2 usable"
)]
#[inline]
pub(super) unsafe fn classify_byte_set_32_sve2(
    tables: &ByteSetTables,
    bytes: &[u8; BYTE_SET_WIDE_BLOCK_BYTES],
) -> ByteSetMask32 {
    // SAFETY: each table has exactly 16 initialized bytes, the source has
    // exactly 32 initialized bytes, and the compiler-static caller proves SVE
    // plus SVE2 for the reviewed leaf.
    ByteSetMask32::new(unsafe {
        fre_byte_set_mask32_sve2_asm(tables.lower.as_ptr(), tables.upper.as_ptr(), bytes.as_ptr())
    })
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed fixed-16 assembly after retained dispatch proved SVE and SVE2 usable"
)]
#[inline(never)]
pub(super) unsafe fn classify_word_space_16_sve2(
    tables: &AsciiWordSpaceTables,
    bytes: &[u8; ASCII_NARROW_BYTES],
) -> AsciiWordSpaceMasks16 {
    // SAFETY: both tables and the source are exact initialized 16-byte
    // objects. The private retained entry proves Linux/AArch64 SVE plus SVE2.
    let packed = unsafe {
        fre_ascii_word_space_mask16_sve2_asm(
            tables.word_columns.as_ptr(),
            tables.space_values.as_ptr(),
            bytes.as_ptr(),
        )
    };
    let words =
        u16::try_from(packed & u32::from(u16::MAX)).expect("the low half of a u32 fits in u16");
    let spaces = u16::try_from(packed >> 16).expect("the high half of a u32 fits in u16");
    AsciiWordSpaceMasks16::new(words, spaces)
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed fixed-16x2 assembly after retained dispatch proved SVE and SVE2 usable"
)]
#[inline(never)]
pub(super) unsafe fn classify_word_space_32_sve2(
    tables: &AsciiWordSpaceTables,
    bytes: &[u8; ASCII_WIDE_BYTES],
) -> AsciiWordSpaceMasks32 {
    // SAFETY: the two fixed tables contain exactly 16 initialized bytes and
    // the source array proves both exact active-16 load extents.
    let packed = unsafe {
        fre_ascii_word_space_mask32_sve2_asm(
            tables.word_columns.as_ptr(),
            tables.space_values.as_ptr(),
            bytes.as_ptr(),
        )
    };
    let words =
        u32::try_from(packed & u64::from(u32::MAX)).expect("the low half of a u64 fits in u32");
    let spaces = u32::try_from(packed >> 32).expect("the high half of a u64 fits in u32");
    AsciiWordSpaceMasks32::new(words, spaces)
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

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed base-SVE assembly only after retained dispatch proved SVE usable"
)]
#[cfg_attr(
    feature = "static-dispatch-arm-41-d84",
    allow(
        dead_code,
        reason = "the compiler-fixed V3 run profile uses the qualified NEON/SVE2 hybrid instead of the base-SVE leaf"
    )
)]
#[inline(never)]
pub(super) unsafe fn scan_run_forward_sve(tables: &AsciiRunTables, bytes: &[u8]) -> AsciiRunResult {
    // SAFETY: the table has exactly 16 initialized bytes, the slice pointer and
    // length describe every predicated source load, and retained dispatch
    // independently proved SVE OS-usable.
    unsafe { fre_ascii_run_forward_sve_asm(tables.columns.as_ptr(), bytes.as_ptr(), bytes.len()) }
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed base-SVE assembly only after retained dispatch proved SVE usable"
)]
#[cfg_attr(
    feature = "static-dispatch-arm-41-d84",
    allow(
        dead_code,
        reason = "the compiler-fixed V3 run profile uses the qualified NEON/SVE2 hybrid instead of the base-SVE leaf"
    )
)]
#[inline(never)]
pub(super) unsafe fn scan_run_backward_sve(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    // SAFETY: identical table, slice-extent, and feature proof to the forward
    // base-SVE operation.
    unsafe { fre_ascii_run_backward_sve_asm(tables.columns.as_ptr(), bytes.as_ptr(), bytes.len()) }
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed SVE2 assembly only after retained dispatch proved SVE and SVE2 usable"
)]
#[inline(never)]
pub(super) unsafe fn scan_run_forward_sve2(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    // SAFETY: construction selects this entry only for a nonempty set of at
    // most 16 values, fills every table lane with a valid member, and retained
    // dispatch proves SVE plus SVE2 OS-usable. The slice proves every source
    // extent.
    unsafe {
        fre_ascii_run_forward_sve2_asm(tables.match_values.as_ptr(), bytes.as_ptr(), bytes.len())
    }
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed SVE2 assembly only after retained dispatch proved SVE and SVE2 usable"
)]
#[inline(never)]
pub(super) unsafe fn scan_nonmember_run_forward_sve2(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiNonMemberRunResult {
    // SAFETY: construction selects this entry only for a nonempty set of at
    // most 16 ASCII values, fills every MATCH table lane with a valid member,
    // and retained dispatch proves SVE plus SVE2 OS-usable. High bytes cannot
    // match the table and the slice proves every predicated source extent.
    unsafe {
        fre_ascii_nonmember_run_forward_sve2_asm(
            tables.match_values.as_ptr(),
            bytes.as_ptr(),
            bytes.len(),
        )
    }
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed SVE2 assembly only after retained dispatch proved SVE and SVE2 usable"
)]
#[inline(never)]
pub(super) unsafe fn scan_run_backward_sve2(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    // SAFETY: identical compiled-set, source-extent, and feature proof to the
    // forward SVE2 operation.
    unsafe {
        fre_ascii_run_backward_sve2_asm(tables.match_values.as_ptr(), bytes.as_ptr(), bytes.len())
    }
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed SVE2 assembly only after retained dispatch proved SVE and SVE2 usable"
)]
#[inline(never)]
pub(super) unsafe fn scan_run_forward_sve2_complement(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    // SAFETY: construction selects this entry only for 1..=16 excluded ASCII
    // values, fills every table lane with an exclusion, and retained dispatch
    // proves SVE plus SVE2 OS-usable. The assembly also rejects every high-bit
    // byte, and the slice proves every source extent.
    unsafe {
        fre_ascii_run_forward_sve2_complement_asm(
            tables.match_values.as_ptr(),
            bytes.as_ptr(),
            bytes.len(),
        )
    }
}

#[allow(
    unsafe_code,
    reason = "this private leaf calls reviewed SVE2 assembly only after retained dispatch proved SVE and SVE2 usable"
)]
#[inline(never)]
pub(super) unsafe fn scan_run_backward_sve2_complement(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    // SAFETY: identical exclusion-table, high-bit-barrier, source-extent, and
    // feature proof to the forward complement operation.
    unsafe {
        fre_ascii_run_backward_sve2_complement_asm(
            tables.match_values.as_ptr(),
            bytes.as_ptr(),
            bytes.len(),
        )
    }
}

#[allow(
    unsafe_code,
    reason = "retained dispatch proves both NEON and SVE2 before this hybrid performs one exact NEON probe and calls the reviewed SVE2 leaf"
)]
#[inline(never)]
pub(super) unsafe fn scan_run_forward_neon_sve2(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    let Some((first, tail)) = bytes.split_at_checked(ASCII_NARROW_BYTES) else {
        return scalar::scan_run_forward(tables.set, bytes);
    };
    let first: &[u8; ASCII_NARROW_BYTES] = first
        .try_into()
        .expect("split_at_checked produced one exact NEON block");
    // SAFETY: this hybrid is selected only with retained NEON authorization,
    // and `first` proves the exact 16-byte load extent.
    if !unsafe { aarch64::block_all_members_neon(&tables.columns, first) } {
        let recovery = scalar::scan_run_forward(tables.set, first);
        return AsciiRunResult::new(
            recovery.member_run_len(),
            ASCII_NARROW_BYTES
                .checked_add(recovery.examined_bytes())
                .expect("one fixed probe plus its recovery fits usize"),
        );
    }
    if tail.is_empty() {
        return AsciiRunResult::new(ASCII_NARROW_BYTES, ASCII_NARROW_BYTES);
    }
    // SAFETY: retained dispatch also proves SVE and SVE2, while `tail`
    // carries its complete source extent.
    let continuation = unsafe { scan_run_forward_sve2(tables, tail) };
    AsciiRunResult::new(
        ASCII_NARROW_BYTES
            .checked_add(continuation.member_run_len())
            .expect("the first block and continuation partition one slice"),
        ASCII_NARROW_BYTES
            .checked_add(continuation.examined_bytes())
            .expect("the first probe and continuation work fit one slice bound"),
    )
}

#[allow(
    unsafe_code,
    reason = "retained dispatch proves both NEON and SVE2 before this hybrid performs one exact NEON probe and calls the reviewed SVE2 leaf"
)]
#[inline(never)]
pub(super) unsafe fn scan_run_backward_neon_sve2(
    tables: &AsciiRunTables,
    bytes: &[u8],
) -> AsciiRunResult {
    let Some(split) = bytes.len().checked_sub(ASCII_NARROW_BYTES) else {
        return scalar::scan_run_backward(tables.set, bytes);
    };
    let (head, last) = bytes.split_at(split);
    let last: &[u8; ASCII_NARROW_BYTES] = last
        .try_into()
        .expect("checked split retained one exact NEON block");
    // SAFETY: this hybrid is selected only with retained NEON authorization,
    // and `last` proves the exact 16-byte load extent.
    if !unsafe { aarch64::block_all_members_neon(&tables.columns, last) } {
        let recovery = scalar::scan_run_backward(tables.set, last);
        return AsciiRunResult::new(
            recovery.member_run_len(),
            ASCII_NARROW_BYTES
                .checked_add(recovery.examined_bytes())
                .expect("one fixed probe plus its recovery fits usize"),
        );
    }
    if head.is_empty() {
        return AsciiRunResult::new(ASCII_NARROW_BYTES, ASCII_NARROW_BYTES);
    }
    // SAFETY: retained dispatch also proves SVE and SVE2, while `head`
    // carries its complete source extent.
    let continuation = unsafe { scan_run_backward_sve2(tables, head) };
    AsciiRunResult::new(
        ASCII_NARROW_BYTES
            .checked_add(continuation.member_run_len())
            .expect("the last block and continuation partition one slice"),
        ASCII_NARROW_BYTES
            .checked_add(continuation.examined_bytes())
            .expect("the last probe and continuation work fit one slice bound"),
    )
}
