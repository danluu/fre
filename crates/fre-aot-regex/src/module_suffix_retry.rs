//! Native bounded mandatory-candidate verifiers.
//!
//! This is a child of `module`, so it shares the checked assemblers without
//! widening their crate-visible API. Both backends use only caller-saved
//! registers and make no runtime calls.

#[allow(
    clippy::wildcard_imports,
    reason = "this private module deliberately shares its parent's assembler vocabulary"
)]
use super::*;
use crate::bounded_suffix_retry::BoundedSuffixRetryPlan;

fn x86_emit_retry_forward_end(
    assembler: &mut X86Assembler,
    forward_width: u64,
) -> Result<(), ObjectError> {
    if let Ok(width) = u8::try_from(forward_width)
        && width <= 0x7f
    {
        assembler.instruction(&[0x4c, 0x8d, 0x5a, width])?; // r11 = base + width
    } else if let Ok(width) = i32::try_from(forward_width) {
        let mut instruction = vec![0x4c, 0x8d, 0x9a]; // lea width(rdx), r11
        instruction.extend_from_slice(&width.to_le_bytes());
        assembler.instruction(&instruction)?;
    } else {
        return Err(ObjectError::InvalidModule(
            "x86 bounded retry forward width is not encodable",
        ));
    }
    Ok(())
}

/// Verify the current mandatory base with the forward DFA and retry at the
/// next base after a false candidate. This path is selected only for `Exists`,
/// so the result span remains the ABI-mandated zero pair.
#[allow(
    clippy::large_types_passed_by_value,
    reason = "the parent lowering passes its frozen copyable native layout by value"
)]
pub(super) fn x86_emit_bounded_suffix_retry(
    assembler: &mut X86Assembler,
    layout: NativeDfaLayout,
    plan: BoundedSuffixRetryPlan,
    retry_scan: X86Label,
    no_match: X86Label,
    matched: X86Label,
) -> Result<(), ObjectError> {
    if layout.output != OutputContract::Exists
        || layout.initial_pending
        || plan.minimum_width() == 0
    {
        return Err(ObjectError::InvalidModule(
            "x86 bounded retry has unsupported semantics",
        ));
    }
    let verifier = assembler.label()?;
    let rejected = assembler.label()?;
    let accepted = assembler.label()?;
    let exhausted = assembler.label()?;

    // r11 = verifier end = candidate base + maximum through-accept width.
    x86_emit_retry_forward_end(assembler, plan.forward_width())?;
    assembler.instruction(&[0x49, 0x39, 0xcb])?; // verifier end > semantic end?
    if plan.clamps_forward_end() {
        let end_ready = assembler.label()?;
        assembler.branch(&[0x0f, 0x86], end_ready)?;
        assembler.instruction(&[0x49, 0x89, 0xcb])?; // clamp verifier end
        assembler.bind(end_ready)?;
    } else {
        assembler.branch(&[0x0f, 0x87], exhausted)?;
    }
    // Exists does not publish a span. Borrow result.start for the next suffix
    // base, then clear it on every path leaving the verifier.
    assembler.instruction(&[0x48, 0x8d, 0x42, 1])?;
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    x86_emit_suffix_lower_bound(assembler, plan.backtrack())?;
    x86_set_row(assembler, layout.forward_offset)?;

    assembler.bind(verifier)?;
    assembler.instruction(&[0x4c, 0x39, 0xda])?; // position >= verifier end?
    assembler.branch(&[0x0f, 0x83], rejected)?;
    x86_emit_table_lookup(assembler, layout.transitions)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.instruction(&[0xa9, 0x00, 0x00, 0x00, 0x80])?;
    assembler.branch(&[0x0f, 0x88], accepted)?;
    // Forward cells reserve bit 31 for acceptance and bit 30 for accelerator
    // dispatch. A retry verifier follows the semantic transition directly,
    // so neither flag may participate in the absolute next-row token.
    let mut next_mask = vec![0x25]; // and eax, imm32
    next_mask.extend_from_slice(&CELL_NEXT_MASK.to_le_bytes());
    assembler.instruction(&next_mask)?;
    assembler.branch(&[0x0f, 0x84], rejected)?;
    assembler.instruction(&[0x4d, 0x8d, 0x54, 0x01, 0xff])?;
    assembler.branch(&[0xe9], verifier)?;

    assembler.bind(rejected)?;
    assembler.instruction(&[0x49, 0x8b, 0x10])?; // next suffix base
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    assembler.branch(&[0xe9], retry_scan)?;

    assembler.bind(accepted)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    assembler.branch(&[0xe9], matched)?;

    // Terminal candidate bases are monotone. If this exact suffix would
    // extend past the semantic end, every later base does too. Interior plans
    // clamp above and cannot reach this label.
    assembler.bind(exhausted)?;
    assembler.branch(&[0xe9], no_match)?;
    Ok(())
}

/// `AArch64` counterpart of [`x86_emit_bounded_suffix_retry`]. Registers x7
/// and x10 hold the next base and verifier end; both are caller-saved and are
/// reinitialized by the ordinary DFA path when a short window skips retry.
#[allow(
    clippy::large_types_passed_by_value,
    reason = "the parent lowering passes its frozen copyable native layout by value"
)]
pub(super) fn aarch64_emit_bounded_suffix_retry(
    assembler: &mut Aarch64Assembler,
    layout: NativeDfaLayout,
    plan: BoundedSuffixRetryPlan,
    retry_scan: Aarch64Label,
    no_match: Aarch64Label,
    matched: Aarch64Label,
) -> Result<(), ObjectError> {
    if layout.output != OutputContract::Exists
        || layout.initial_pending
        || plan.minimum_width() == 0
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 bounded retry has unsupported semantics",
        ));
    }
    let verifier = assembler.label()?;
    let rejected = assembler.label()?;
    let accepted = assembler.label()?;

    let forward_width = u16::try_from(plan.forward_width())
        .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 retry forward width"))?;
    assembler.instruction(aarch64_add_x_imm(10, 2, forward_width)?)?;
    assembler.instruction(aarch64_cmp_x(10, 3)?)?;
    if plan.clamps_forward_end() {
        let end_ready = assembler.label()?;
        assembler.branch_cond(AARCH64_LS, end_ready)?;
        assembler.instruction(aarch64_mov_x(10, 3)?)?;
        assembler.bind(end_ready)?;
    } else {
        assembler.branch_cond(AARCH64_HI, no_match)?;
    }
    assembler.instruction(aarch64_add_x_imm(7, 2, 1)?)?;
    aarch64_emit_suffix_lower_bound(assembler, plan.backtrack())?;
    aarch64_set_row_base(assembler, layout.forward_offset)?;

    assembler.bind(verifier)?;
    assembler.instruction(aarch64_cmp_x(2, 10)?)?;
    assembler.branch_cond(AARCH64_HS, rejected)?;
    aarch64_emit_table_lookup(assembler, layout.transitions)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.instruction(aarch64_cmp_w_zero(8)?)?;
    assembler.branch_cond(AARCH64_MI, accepted)?;
    // Mirror the ordinary forward dispatcher: both the accept and
    // accelerator tag are metadata, while the low 30 bits are the row token.
    assembler.instruction(aarch64_and_low_w(6, 8, 30)?)?;
    assembler.instruction(aarch64_cmp_w_zero(6)?)?;
    assembler.branch_cond(AARCH64_EQ, rejected)?;
    assembler.instruction(aarch64_sub_w_imm(6, 6, 1)?)?;
    assembler.instruction(
        0x8b00_0000 | aarch64_reg(6, 16)? | aarch64_reg(5, 5)? | aarch64_reg(11, 0)?,
    )?;
    assembler.branch(verifier)?;

    assembler.bind(rejected)?;
    assembler.instruction(aarch64_mov_x(2, 7)?)?;
    assembler.branch(retry_scan)?;

    assembler.bind(accepted)?;
    assembler.branch(matched)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CompileMode, CompileRequest, Target, bounded_suffix_retry::select_bounded_interior_retry,
        compile,
    };

    fn exists_layout() -> NativeDfaLayout {
        let compiled = compile(
            CompileRequest::new("(?:ab|c)X(?:de|f)", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .unwrap();
        build_native_dfa_table(compiled.program().native_dfa_view().unwrap())
            .unwrap()
            .1
    }

    fn finish_x86_retry(
        layout: &NativeDfaLayout,
        plan: BoundedSuffixRetryPlan,
    ) -> Result<Vec<u8>, ObjectError> {
        let mut assembler = X86Assembler::new();
        let retry = assembler.label()?;
        let no_match = assembler.label()?;
        let matched = assembler.label()?;
        x86_emit_bounded_suffix_retry(&mut assembler, *layout, plan, retry, no_match, matched)?;
        assembler.bind(retry)?;
        assembler.bind(no_match)?;
        assembler.bind(matched)?;
        assembler.instruction(&[0xc3])?;
        assembler.finish()
    }

    #[test]
    fn interior_forward_end_clamps_on_both_isas_and_x86_128_is_not_disp8() {
        let layout = exists_layout();
        assert_eq!(layout.transitions, TransitionLayout::DirectByte);
        let plan =
            select_bounded_interior_retry(OutputContract::Exists, false, 1, 2, 3, 1).unwrap();
        let x86 = finish_x86_retry(&layout, plan).unwrap();
        assert!(
            x86.windows(4)
                .any(|bytes| bytes == [0x41, 0x8b, 0x04, 0x82]),
            "bounded direct-table retry must load a dword cell"
        );
        assert!(
            x86.windows(5)
                .any(|bytes| bytes == [0x25, 0xff, 0xff, 0xff, 0x3f]),
            "bounded retry must clear the accept and accelerator bits"
        );
        assert!(
            !x86.windows(5)
                .any(|bytes| bytes == [0x25, 0xff, 0xff, 0xff, 0x7f]),
            "bounded retry must not retain the accelerator tag in a row token"
        );
        assert!(
            x86.windows(3).any(|bytes| bytes == [0x49, 0x89, 0xcb]),
            "interior verifier must clamp r11 to the semantic end"
        );

        let mut aarch64 = Aarch64Assembler::new();
        let retry = aarch64.label().unwrap();
        let no_match = aarch64.label().unwrap();
        let matched = aarch64.label().unwrap();
        aarch64_emit_bounded_suffix_retry(&mut aarch64, layout, plan, retry, no_match, matched)
            .unwrap();
        aarch64.bind(retry).unwrap();
        aarch64.bind(no_match).unwrap();
        aarch64.bind(matched).unwrap();
        aarch64.instruction(0xd65f_03c0).unwrap();
        let words = aarch64
            .finish()
            .unwrap()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        assert!(words.contains(&aarch64_load_w_uxtw(8, 11, 8).unwrap()));
        assert!(words.contains(&aarch64_and_low_w(6, 8, 30).unwrap()));
        assert!(!words.contains(&aarch64_and_low_31(6, 8).unwrap()));
        assert!(words.contains(&aarch64_mov_x(10, 3).unwrap()));

        let width_128 =
            select_bounded_interior_retry(OutputContract::Exists, false, 1, 0, 128, 1).unwrap();
        let x86 = finish_x86_retry(&layout, width_128).unwrap();
        assert!(
            x86.windows(7)
                .any(|bytes| bytes == [0x4c, 0x8d, 0x9a, 0x80, 0, 0, 0]),
            "128 must use a positive disp32 instead of a sign-extended disp8"
        );
    }
}
