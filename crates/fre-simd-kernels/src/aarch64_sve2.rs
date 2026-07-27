use super::{
    ASCII_NARROW_BYTES, ASCII_WIDE_BYTES, AsciiMasks32, AsciiRunResult, AsciiRunTables, aarch64,
    scalar,
};

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
    reason = "this module contains only reviewed global assembly boundaries; private Rust dispatch proves each leaf's exact SVE or SVE2 feature set usable before entry"
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
"#
    );
}

#[allow(
    unsafe_code,
    reason = "these private declarations are implemented by the reviewed base-SVE and SVE2 global assembly above"
)]
unsafe extern "C" {
    fn fre_ascii_mask32_sve2_asm(columns: *const u8, bytes: *const u8) -> u64;
    fn fre_ascii_run_forward_sve_asm(
        columns: *const u8,
        bytes: *const u8,
        len: usize,
    ) -> AsciiRunResult;
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
    fn fre_ascii_run_backward_sve2_asm(
        match_values: *const u8,
        bytes: *const u8,
        len: usize,
    ) -> AsciiRunResult;
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
