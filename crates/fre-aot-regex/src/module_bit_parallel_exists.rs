//! Self-contained lowering for the bounded one-word `Exists` executor.
//!
//! This backend consumes only the canonical byte-class/nibble-union view. It
//! emits a scalar leaf on both architectures and therefore remains valid when
//! the surrounding target advertises SSE2, AVX2, AVX-512, ASIMD, SVE, or
//! SVE2. Those feature facts may select other scanners, but never weaken this
//! route's publication proof.

use crate::{
    ObjectError,
    bit_parallel_exists::{
        BitParallelExists, MAX_BIT_PARALLEL_EXISTS_STATES, NativeBitParallelExistsView,
    },
};

use super::{
    AARCH64_HI, AARCH64_HS, AARCH64_MI, AARCH64_NE, Aarch64Assembler, Architecture,
    ModuleRelocation, NativeLowering, PROGRAM_SYMBOL, RelocationKind, StartAccelerator,
    TEXT_SECTION, Target, X86Assembler, aarch64_add_x_imm, aarch64_add_x_reg, aarch64_and_low_x,
    aarch64_cmp_x, aarch64_load_byte_imm, aarch64_load_byte_reg, aarch64_load_u64_constant,
    aarch64_load_x_lsl3, aarch64_lsr_x_imm, aarch64_mov_x, aarch64_movz_w, aarch64_reg,
    aarch64_store_x, offset_u64, push_bytes,
};

const BYTE_VALUES: usize = 256;
const NIBBLE_BITS: usize = 4;
const NIBBLE_SUBSETS: usize = 1 << NIBBLE_BITS;
const NIBBLE_ROW_BYTES: usize = NIBBLE_SUBSETS * core::mem::size_of::<u64>();
const ACCEPT_BIT: u64 = 1_u64 << 63;
const CONSUMING_BITS: u64 = ACCEPT_BIT - 1;

// The sidecar itself proves a tighter retained-memory ceiling. These native
// caps independently bound object growth and make a failed optional lowering
// fall back to the serialized runtime route.
const MAX_NATIVE_BIT_PARALLEL_DATA_BYTES: usize =
    BYTE_VALUES + 256 * (MAX_BIT_PARALLEL_EXISTS_STATES / NIBBLE_BITS) * NIBBLE_ROW_BYTES;
const MAX_NATIVE_BIT_PARALLEL_CODE_BYTES: usize = 2 * 1024;

#[derive(Debug)]
struct NativeBitParallelLayout {
    data: Vec<u8>,
    root: u64,
    source_nibbles: usize,
    constant_result: Option<bool>,
}

#[derive(Debug)]
struct NativeBitParallelEmission {
    code: Vec<u8>,
    relocations: Vec<ModuleRelocation>,
    emitted_nibbles: usize,
}

pub(super) fn lower_native_bit_parallel_exists(
    view: NativeBitParallelExistsView<'_>,
    target: Target,
) -> Result<Option<NativeLowering>, ObjectError> {
    let Some(layout) = build_native_bit_parallel_layout(view) else {
        return Ok(None);
    };
    let emission = match target.architecture {
        Architecture::X86_64 => lower_x86_64_bit_parallel(&layout)?,
        Architecture::Aarch64 => lower_aarch64_bit_parallel(&layout)?,
    };
    if emission.code.len() > MAX_NATIVE_BIT_PARALLEL_CODE_BYTES
        || emission.emitted_nibbles != layout.source_nibbles
    {
        return Ok(None);
    }
    Ok(Some(NativeLowering {
        code: emission.code,
        data: layout.data,
        relocations: emission.relocations,
        needs_runtime: false,
        start_accelerator: StartAccelerator::None,
        anchored_prefix_filter_bytes: 0,
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "canonical dimensions, masks, exact extent, and allocation form one publication proof"
)]
fn build_native_bit_parallel_layout(
    view: NativeBitParallelExistsView<'_>,
) -> Option<NativeBitParallelLayout> {
    let stats = view.stats;
    if stats.thompson_states == 0
        || stats.thompson_states > MAX_BIT_PARALLEL_EXISTS_STATES
        || stats.consuming_states > 63
        || !(1..=BYTE_VALUES).contains(&stats.byte_classes)
    {
        return None;
    }
    let source_nibbles = stats.consuming_states.checked_add(NIBBLE_BITS - 1)? / NIBBLE_BITS;
    let transition_entries = stats
        .byte_classes
        .checked_mul(source_nibbles)?
        .checked_mul(NIBBLE_SUBSETS)?;
    let transition_bytes = transition_entries.checked_mul(core::mem::size_of::<u64>())?;
    let data_bytes = BYTE_VALUES.checked_add(transition_bytes)?;
    let retained_bytes = core::mem::size_of::<BitParallelExists>().checked_add(transition_bytes)?;
    if stats.source_nibbles != source_nibbles
        || stats.transition_entries != transition_entries
        || view.transition_masks.len() != transition_entries
        || stats.retained_bytes != retained_bytes
        || stats.peak_build_bytes < stats.retained_bytes
        || data_bytes > MAX_NATIVE_BIT_PARALLEL_DATA_BYTES
    {
        return None;
    }
    let mut prior_class = 0_u8;
    for (byte, &class) in view.byte_to_class.iter().enumerate() {
        if usize::from(class) >= stats.byte_classes
            || byte == 0 && class != 0
            || byte != 0 && class != prior_class && class != prior_class.checked_add(1)?
        {
            return None;
        }
        prior_class = class;
    }
    if usize::from(prior_class).checked_add(1)? != stats.byte_classes {
        return None;
    }

    let consuming_mask = match stats.consuming_states {
        0 => 0,
        63 => CONSUMING_BITS,
        consuming_count => 1_u64
            .checked_shl(u32::try_from(consuming_count).ok()?)?
            .checked_sub(1)?,
    };
    let valid_mask = consuming_mask | ACCEPT_BIT;
    if view.initial & !valid_mask != 0 {
        return None;
    }
    for row in view.transition_masks.chunks_exact(NIBBLE_SUBSETS) {
        if row[0] != 0 || row.iter().any(|mask| mask & !valid_mask != 0) {
            return None;
        }
        for subset in 1..NIBBLE_SUBSETS {
            let previous_subset = subset & subset.checked_sub(1)?;
            let isolated_bit = 1_usize.checked_shl(subset.trailing_zeros())?;
            if row[subset] != row[previous_subset] | row[isolated_bit] {
                return None;
            }
        }
    }

    let root = view.initial & CONSUMING_BITS;
    let constant_result = if view.initial & ACCEPT_BIT != 0 {
        Some(true)
    } else if root == 0 {
        Some(false)
    } else {
        None
    };
    if constant_result.is_none() && source_nibbles == 0 {
        return None;
    }

    let mut data = Vec::new();
    if constant_result.is_none() {
        data.try_reserve_exact(data_bytes).ok()?;
        data.extend_from_slice(view.byte_to_class);
        for &mask in view.transition_masks {
            data.extend_from_slice(&mask.to_le_bytes());
        }
        if data.len() != data_bytes {
            return None;
        }
    }
    Some(NativeBitParallelLayout {
        data,
        root,
        source_nibbles,
        constant_result,
    })
}

fn x86_emit_abi_validation(
    assembler: &mut X86Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    assembler.instruction(&[0x48, 0x85, 0xf6])?; // test length sign bit
    assembler.branch(&[0x0f, 0x88], invalid)?; // js
    assembler.instruction(&[0x48, 0x39, 0xf1])?; // cmp end, length
    assembler.branch(&[0x0f, 0x87], invalid)?; // ja
    assembler.instruction(&[0x48, 0x39, 0xca])?; // cmp start, end
    assembler.branch(&[0x0f, 0x87], invalid)?;
    assembler.instruction(&[0x4d, 0x85, 0xc0])?; // test result, result
    assembler.branch(&[0x0f, 0x84], invalid)?;
    assembler.instruction(&[0x41, 0xf6, 0xc0, 0x07])?; // 8-byte result alignment
    assembler.branch(&[0x0f, 0x85], invalid)?;
    assembler.instruction(&[0x48, 0x85, 0xff])?; // test haystack, haystack
    assembler.branch(&[0x0f, 0x84], invalid)?;
    Ok(())
}

fn x86_emit_result_zero(assembler: &mut X86Assembler) -> Result<(), ObjectError> {
    assembler.instruction(&[0x31, 0xc0])?; // xor eax, eax
    assembler.instruction(&[0x49, 0x89, 0x00])?; // mov [r8], rax
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?; // mov [r8 + 8], rax
    Ok(())
}

fn lower_x86_64_bit_parallel(
    layout: &NativeBitParallelLayout,
) -> Result<NativeBitParallelEmission, ObjectError> {
    let mut assembler = X86Assembler::new();
    let loop_head = assembler.label()?;
    let no_match = assembler.label()?;
    let matched = assembler.label()?;
    let invalid = assembler.label()?;
    let done = assembler.label()?;

    x86_emit_abi_validation(&mut assembler, invalid)?;
    x86_emit_result_zero(&mut assembler)?;
    if let Some(result) = layout.constant_result {
        assembler.instruction(&[0xb8, u8::from(result), 0, 0, 0])?;
        assembler.branch(&[0xe9], done)?;
    } else {
        // lea table(%rip), r9
        assembler.instruction(&[0x4c, 0x8d, 0x0d])?;
        let table_displacement_label = assembler.label()?;
        assembler.bind(table_displacement_label)?;
        push_bytes(&mut assembler.code, &[0; 4])?;

        assembler.instruction(&[0x4c, 0x8d, 0x1c, 0x0f])?; // lea [rdi + rcx], r11
        assembler.instruction(&[0x48, 0x01, 0xd7])?; // add rdx, rdi
        let mut root = vec![0x48, 0xb9]; // movabs root, rcx
        root.extend_from_slice(&layout.root.to_le_bytes());
        assembler.instruction(&root)?;
        assembler.instruction(&[0x48, 0x89, 0xce])?; // mov rcx, rsi

        assembler.bind(loop_head)?;
        assembler.instruction(&[0x4c, 0x39, 0xdf])?; // cmp r11, rdi
        assembler.branch(&[0x0f, 0x83], no_match)?; // jae
        assembler.instruction(&[0x0f, 0xb6, 0x07])?; // movzx [rdi], eax
        assembler.instruction(&[0x48, 0xff, 0xc7])?; // inc rdi
        assembler.instruction(&[0x41, 0x0f, 0xb6, 0x04, 0x01])?; // class = table[byte]
        let class_stride =
            u32::try_from(layout.source_nibbles.checked_mul(NIBBLE_ROW_BYTES).ok_or(
                ObjectError::ArithmeticOverflow("x86 bit-parallel class stride"),
            )?)
            .map_err(|_| ObjectError::ArithmeticOverflow("x86 bit-parallel class stride"))?;
        let mut scale_class = vec![0x48, 0x69, 0xd0]; // imul stride, rax, rdx
        scale_class.extend_from_slice(&class_stride.to_le_bytes());
        assembler.instruction(&scale_class)?;
        assembler.instruction(&[0x49, 0x8d, 0x94, 0x11, 0x00, 0x01, 0x00, 0x00])?;
        assembler.instruction(&[0x31, 0xc0])?; // reached = 0

        for nibble in 0..layout.source_nibbles {
            assembler.instruction(&[0x49, 0x89, 0xf2])?; // active -> r10
            let shift = u8::try_from(
                nibble
                    .checked_mul(NIBBLE_BITS)
                    .ok_or(ObjectError::ArithmeticOverflow("x86 bit-parallel shift"))?,
            )
            .map_err(|_| ObjectError::ArithmeticOverflow("x86 bit-parallel shift"))?;
            if shift != 0 {
                assembler.instruction(&[0x49, 0xc1, 0xea, shift])?;
            }
            assembler.instruction(&[0x41, 0x83, 0xe2, 0x0f])?;
            let displacement = u32::try_from(nibble.checked_mul(NIBBLE_ROW_BYTES).ok_or(
                ObjectError::ArithmeticOverflow("x86 bit-parallel row offset"),
            )?)
            .map_err(|_| ObjectError::ArithmeticOverflow("x86 bit-parallel row offset"))?;
            let mut union = vec![0x4a, 0x0b, 0x84, 0xd2];
            union.extend_from_slice(&displacement.to_le_bytes());
            assembler.instruction(&union)?; // or [rdx + r10*8 + row], rax
        }
        assembler.instruction(&[0x48, 0x85, 0xc0])?;
        assembler.branch(&[0x0f, 0x88], matched)?; // acceptance marker is the sign bit
        assembler.instruction(&[0x48, 0x0f, 0xba, 0xf0, 0x3f])?; // btr 63, rax
        assembler.instruction(&[0x48, 0x09, 0xc8])?; // root | reached
        assembler.instruction(&[0x48, 0x89, 0xc6])?; // next active
        assembler.branch(&[0xe9], loop_head)?;

        assembler.bind(no_match)?;
        assembler.instruction(&[0x31, 0xc0])?;
        assembler.branch(&[0xe9], done)?;
        assembler.bind(matched)?;
        assembler.instruction(&[0xb8, 0x01, 0, 0, 0])?;
        assembler.branch(&[0xe9], done)?;

        assembler.bind(invalid)?;
        assembler.instruction(&[0xb8, 0x02, 0, 0, 0])?;
        assembler.bind(done)?;
        assembler.instruction(&[0xc3])?;
        let finished = assembler.finish_with_label_offsets()?;
        let table_displacement = finished.label_offset(table_displacement_label)?;
        return Ok(NativeBitParallelEmission {
            code: finished.code,
            relocations: vec![ModuleRelocation {
                section: TEXT_SECTION,
                offset: offset_u64(
                    table_displacement,
                    "x86 bit-parallel table relocation offset",
                )?,
                kind: RelocationKind::X86PcRelative32,
                symbol: PROGRAM_SYMBOL,
                addend: -4,
            }],
            emitted_nibbles: layout.source_nibbles,
        });
    }

    assembler.bind(invalid)?;
    assembler.instruction(&[0xb8, 0x02, 0, 0, 0])?;
    assembler.bind(done)?;
    assembler.instruction(&[0xc3])?;
    Ok(NativeBitParallelEmission {
        code: assembler.finish_with_label_offsets()?.code,
        relocations: Vec::new(),
        emitted_nibbles: layout.source_nibbles,
    })
}

fn aarch64_mul_x(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0x9b00_7c00
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_lsl_x_imm(destination: u8, source: u8, shift: u8) -> Result<u32, ObjectError> {
    if shift > 63 {
        return Err(ObjectError::InvalidModule("AArch64 LSL immediate"));
    }
    let rotation = (64_u8.wrapping_sub(shift)) & 63;
    let size = 63_u8.wrapping_sub(shift);
    Ok(0xd340_0000
        | (u32::from(rotation) << 16)
        | (u32::from(size) << 10)
        | aarch64_reg(source, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_orr_x(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0xaa00_0000
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_emit_abi_validation(
    assembler: &mut Aarch64Assembler,
    invalid: usize,
) -> Result<(), ObjectError> {
    assembler.instruction(0xf100_003f)?; // cmp length, #0
    assembler.branch_cond(AARCH64_MI, invalid)?;
    assembler.instruction(aarch64_cmp_x(3, 1)?)?;
    assembler.branch_cond(AARCH64_HI, invalid)?;
    assembler.instruction(aarch64_cmp_x(2, 3)?)?;
    assembler.branch_cond(AARCH64_HI, invalid)?;
    assembler.instruction(0xf100_009f)?; // cmp x4, #0
    assembler.branch_cond(super::AARCH64_EQ, invalid)?;
    assembler.instruction(super::aarch64_and_low_x(5, 4, 3)?)?;
    assembler.instruction(0xf100_00bf)?;
    assembler.branch_cond(AARCH64_NE, invalid)?;
    assembler.instruction(0xf100_001f)?; // cmp x0, #0
    assembler.branch_cond(super::AARCH64_EQ, invalid)?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the validated leaf CFG and its exact relocation transaction remain contiguous"
)]
fn lower_aarch64_bit_parallel(
    layout: &NativeBitParallelLayout,
) -> Result<NativeBitParallelEmission, ObjectError> {
    let mut assembler = Aarch64Assembler::new();
    let loop_head = assembler.label()?;
    let no_match = assembler.label()?;
    let matched = assembler.label()?;
    let invalid = assembler.label()?;
    let done = assembler.label()?;

    aarch64_emit_abi_validation(&mut assembler, invalid)?;
    assembler.instruction(aarch64_store_x(31, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 8)?)?;
    if let Some(result) = layout.constant_result {
        assembler.instruction(aarch64_movz_w(0, u16::from(result))?)?;
        assembler.branch(done)?;
    } else {
        let table_page = assembler.instruction(0x9000_0005)?; // adrp x5, table
        let table_page_offset = assembler.instruction(aarch64_add_x_imm(5, 5, 0)?)?;
        assembler.instruction(aarch64_add_x_reg(7, 0, 3)?)?; // end pointer
        assembler.instruction(aarch64_add_x_reg(6, 0, 2)?)?; // current pointer
        aarch64_load_u64_constant(&mut assembler, 9, layout.root)?;
        assembler.instruction(aarch64_mov_x(8, 9)?)?;
        aarch64_load_u64_constant(
            &mut assembler,
            14,
            u64::try_from(layout.source_nibbles)
                .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 nibble count"))?,
        )?;

        assembler.bind(loop_head)?;
        assembler.instruction(aarch64_cmp_x(6, 7)?)?;
        assembler.branch_cond(AARCH64_HS, no_match)?;
        assembler.instruction(aarch64_load_byte_imm(12, 6, 0)?)?;
        assembler.instruction(aarch64_add_x_imm(6, 6, 1)?)?;
        assembler.instruction(aarch64_load_byte_reg(12, 5, 12)?)?;
        assembler.instruction(aarch64_mul_x(11, 12, 14)?)?;
        assembler.instruction(aarch64_lsl_x_imm(11, 11, 7)?)?;
        assembler.instruction(aarch64_add_x_reg(11, 5, 11)?)?;
        assembler.instruction(aarch64_add_x_imm(
            11,
            11,
            u16::try_from(BYTE_VALUES)
                .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 classifier extent"))?,
        )?)?;
        assembler.instruction(aarch64_movz_w(10, 0)?)?;

        for nibble in 0..layout.source_nibbles {
            let shift = u8::try_from(nibble.checked_mul(NIBBLE_BITS).ok_or(
                ObjectError::ArithmeticOverflow("AArch64 bit-parallel shift"),
            )?)
            .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 bit-parallel shift"))?;
            if shift == 0 {
                assembler.instruction(aarch64_mov_x(12, 8)?)?;
            } else {
                assembler.instruction(aarch64_lsr_x_imm(12, 8, shift)?)?;
            }
            assembler.instruction(aarch64_and_low_x(
                12,
                12,
                u8::try_from(NIBBLE_BITS)
                    .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 nibble width"))?,
            )?)?;
            assembler.instruction(aarch64_load_x_lsl3(13, 11, 12)?)?;
            assembler.instruction(aarch64_orr_x(10, 10, 13)?)?;
            if nibble
                .checked_add(1)
                .ok_or(ObjectError::ArithmeticOverflow("AArch64 next nibble"))?
                != layout.source_nibbles
            {
                assembler.instruction(aarch64_add_x_imm(
                    11,
                    11,
                    u16::try_from(NIBBLE_ROW_BYTES).map_err(|_| {
                        ObjectError::ArithmeticOverflow("AArch64 bit-parallel row stride")
                    })?,
                )?)?;
            }
        }
        assembler.instruction(aarch64_lsr_x_imm(12, 10, 63)?)?;
        assembler.branch_nonzero_w(12, matched)?;
        assembler.instruction(aarch64_and_low_x(8, 10, 63)?)?;
        assembler.instruction(aarch64_orr_x(8, 8, 9)?)?;
        assembler.branch(loop_head)?;

        assembler.bind(no_match)?;
        assembler.instruction(aarch64_movz_w(0, 0)?)?;
        assembler.branch(done)?;
        assembler.bind(matched)?;
        assembler.instruction(aarch64_movz_w(0, 1)?)?;
        assembler.branch(done)?;
        assembler.bind(invalid)?;
        assembler.instruction(aarch64_movz_w(0, 2)?)?;
        assembler.bind(done)?;
        assembler.instruction(0xd65f_03c0)?;
        let mut relocation_offsets = [table_page, table_page_offset];
        let code = assembler.finish_with_offsets(&mut relocation_offsets)?;
        return Ok(NativeBitParallelEmission {
            code,
            relocations: vec![
                ModuleRelocation {
                    section: TEXT_SECTION,
                    offset: offset_u64(
                        relocation_offsets[0],
                        "AArch64 bit-parallel ADRP relocation offset",
                    )?,
                    kind: RelocationKind::Aarch64Page21,
                    symbol: PROGRAM_SYMBOL,
                    addend: 0,
                },
                ModuleRelocation {
                    section: TEXT_SECTION,
                    offset: offset_u64(
                        relocation_offsets[1],
                        "AArch64 bit-parallel ADD relocation offset",
                    )?,
                    kind: RelocationKind::Aarch64PageOff12,
                    symbol: PROGRAM_SYMBOL,
                    addend: 0,
                },
            ],
            emitted_nibbles: layout.source_nibbles,
        });
    }

    assembler.bind(invalid)?;
    assembler.instruction(aarch64_movz_w(0, 2)?)?;
    assembler.bind(done)?;
    assembler.instruction(0xd65f_03c0)?;
    Ok(NativeBitParallelEmission {
        code: assembler.finish_with_offsets(&mut [])?,
        relocations: Vec::new(),
        emitted_nibbles: layout.source_nibbles,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CompileLimitsV1, CompileMode, CompileRequest, CompiledProgram, CpuFeature,
        DeterminizeLimits, FeatureSet, MatchResult, OutputContract, SearchWindow, Target, compile,
    };

    const GENERAL_PATTERN: &str = r"(?:ab|c)*z";

    fn fallback_limits() -> CompileLimitsV1 {
        CompileLimitsV1 {
            determinize: DeterminizeLimits {
                max_states: 0,
                ..DeterminizeLimits::default()
            },
            ..CompileLimitsV1::default()
        }
    }

    fn compiled_sidecar(target: Target) -> crate::CompiledRegex {
        let compiled = compile(
            CompileRequest::new(GENERAL_PATTERN, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists)
                .limits(fallback_limits()),
        )
        .expect("compile bit-parallel fallback");
        assert!(compiled.program().bit_parallel_exists_stats().is_some());
        compiled
    }

    fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
        haystack
            .windows(needle.len())
            .filter(|window| *window == needle)
            .count()
    }

    fn synthetic_view<'a>(
        consuming_states: usize,
        byte_to_class: &'a [u8; BYTE_VALUES],
        masks: &'a [u64],
    ) -> NativeBitParallelExistsView<'a> {
        let source_nibbles = consuming_states.div_ceil(NIBBLE_BITS);
        let transition_bytes = core::mem::size_of_val(masks);
        let retained_bytes = core::mem::size_of::<BitParallelExists>()
            .checked_add(transition_bytes)
            .expect("synthetic retained extent");
        NativeBitParallelExistsView {
            byte_to_class,
            transition_masks: masks,
            initial: 1,
            stats: crate::BitParallelExistsStats {
                thompson_states: consuming_states.max(1),
                thompson_edges: 0,
                consuming_states,
                byte_classes: 1,
                source_nibbles,
                transition_entries: masks.len(),
                retained_bytes,
                peak_build_bytes: retained_bytes,
                derivation_work: 0,
            },
        }
    }

    #[test]
    fn canonical_table_extent_and_union_addressing_are_exhaustive() {
        let compiled = compiled_sidecar(Target::aarch64_macos());
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("native bit-parallel view");
        assert!(
            view.stats.consuming_states <= 16,
            "keep full subset audit bounded"
        );
        let layout = build_native_bit_parallel_layout(view).expect("native layout");
        assert_eq!(&layout.data[..BYTE_VALUES], view.byte_to_class);
        assert_eq!(
            layout.data.len(),
            BYTE_VALUES
                .checked_add(core::mem::size_of_val(view.transition_masks))
                .expect("native data extent")
        );

        for class in 0..view.stats.byte_classes {
            for nibble in 0..view.stats.source_nibbles {
                for subset in 0..NIBBLE_SUBSETS {
                    let table_index =
                        (class * view.stats.source_nibbles + nibble) * NIBBLE_SUBSETS + subset;
                    let offset = BYTE_VALUES + table_index * core::mem::size_of::<u64>();
                    let actual = u64::from_le_bytes(
                        layout.data[offset..offset + 8]
                            .try_into()
                            .expect("one native union word"),
                    );
                    assert_eq!(actual, view.transition_masks[table_index]);
                }
            }
        }

        let subset_count = 1_u64 << view.stats.consuming_states;
        for active in 0..subset_count {
            for byte in 0_u16..=u16::from(u8::MAX) {
                let byte = u8::try_from(byte).unwrap();
                let class = usize::from(view.byte_to_class[usize::from(byte)]);
                let mut canonical = 0_u64;
                let mut packed = 0_u64;
                for nibble in 0..view.stats.source_nibbles {
                    let subset = usize::try_from((active >> (nibble * NIBBLE_BITS)) & 15)
                        .expect("four-bit subset");
                    let index =
                        (class * view.stats.source_nibbles + nibble) * NIBBLE_SUBSETS + subset;
                    canonical |= view.transition_masks[index];
                    let offset = BYTE_VALUES + index * core::mem::size_of::<u64>();
                    packed |= u64::from_le_bytes(
                        layout.data[offset..offset + 8]
                            .try_into()
                            .expect("packed transition word"),
                    );
                }
                assert_eq!(packed, canonical, "active={active:#x}, byte={byte:#04x}");
            }
        }
    }

    #[test]
    fn every_bounded_nibble_count_has_exact_unrolled_cross_isa_code_shape() {
        let byte_to_class = [0_u8; BYTE_VALUES];
        for source_nibbles in 1..=MAX_BIT_PARALLEL_EXISTS_STATES / NIBBLE_BITS {
            let consuming_states = if source_nibbles == MAX_BIT_PARALLEL_EXISTS_STATES / NIBBLE_BITS
            {
                63
            } else {
                source_nibbles * NIBBLE_BITS
            };
            let masks = vec![0_u64; source_nibbles * NIBBLE_SUBSETS];
            let view = synthetic_view(consuming_states, &byte_to_class, &masks);
            let layout = build_native_bit_parallel_layout(view).expect("synthetic native layout");
            assert_eq!(layout.source_nibbles, source_nibbles);
            assert_eq!(
                layout.data.len(),
                BYTE_VALUES + source_nibbles * NIBBLE_ROW_BYTES
            );

            let x86 = lower_x86_64_bit_parallel(&layout).expect("x86 leaf");
            assert_eq!(x86.emitted_nibbles, source_nibbles);
            assert_eq!(
                count_bytes(&x86.code, &[0x4a, 0x0b, 0x84, 0xd2]),
                source_nibbles
            );
            assert_eq!(x86.relocations.len(), 1);
            assert!(x86.code.len() <= MAX_NATIVE_BIT_PARALLEL_CODE_BYTES);

            let aarch64 = lower_aarch64_bit_parallel(&layout).expect("AArch64 leaf");
            let union_load = aarch64_load_x_lsl3(13, 11, 12).unwrap();
            assert_eq!(
                aarch64
                    .code
                    .chunks_exact(4)
                    .filter(|bytes| {
                        u32::from_le_bytes((*bytes).try_into().unwrap()) == union_load
                    })
                    .count(),
                source_nibbles
            );
            assert_eq!(aarch64.emitted_nibbles, source_nibbles);
            assert_eq!(aarch64.relocations.len(), 2);
            assert!(aarch64.code.len() <= MAX_NATIVE_BIT_PARALLEL_CODE_BYTES);
        }
    }

    #[test]
    fn malformed_native_views_decline_without_weakening_the_runtime_fallback() {
        let compiled = compiled_sidecar(Target::x86_64_linux());
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("native bit-parallel view");

        let mut wrong_extent = view;
        wrong_extent.stats.transition_entries -= 1;
        assert!(build_native_bit_parallel_layout(wrong_extent).is_none());

        let mut wrong_nibbles = view;
        wrong_nibbles.stats.source_nibbles += 1;
        assert!(build_native_bit_parallel_layout(wrong_nibbles).is_none());

        let mut wrong_class = *view.byte_to_class;
        wrong_class[0] = u8::try_from(view.stats.byte_classes).unwrap();
        let wrong_class = NativeBitParallelExistsView {
            byte_to_class: &wrong_class,
            ..view
        };
        assert!(build_native_bit_parallel_layout(wrong_class).is_none());

        let mut wrong_mask = view.transition_masks.to_vec();
        wrong_mask[0] = 1;
        let wrong_mask = NativeBitParallelExistsView {
            transition_masks: &wrong_mask,
            ..view
        };
        assert!(build_native_bit_parallel_layout(wrong_mask).is_none());
    }

    #[test]
    fn every_target_and_feature_tier_publishes_the_same_self_contained_machine() {
        let x86_features = [
            FeatureSet::EMPTY,
            FeatureSet::of(CpuFeature::X86Sse2),
            FeatureSet::of(CpuFeature::X86Avx2),
            FeatureSet::of(CpuFeature::X86Avx512F)
                .with(CpuFeature::X86Avx512Bw)
                .with(CpuFeature::X86Avx512Vl),
        ];
        let arm_features = [
            FeatureSet::EMPTY,
            FeatureSet::of(CpuFeature::Aarch64Asimd),
            FeatureSet::of(CpuFeature::Aarch64Sve),
            FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2),
            FeatureSet::of(CpuFeature::Aarch64Asimd)
                .with(CpuFeature::Aarch64Sve)
                .with(CpuFeature::Aarch64Sve2),
        ];
        let mut targets = Vec::new();
        for base in [Target::x86_64_linux(), Target::x86_64_macos()] {
            for features in x86_features {
                targets.push(base.with_features(features).unwrap());
            }
        }
        for base in [Target::aarch64_linux(), Target::aarch64_macos()] {
            for features in arm_features {
                targets.push(base.with_features(features).unwrap());
            }
        }

        let mut canonical_data = None::<Vec<u8>>;
        for target in targets {
            let compiled = compiled_sidecar(target);
            assert!(!compiled.receipt().runtime_helper_required, "{target:?}");
            assert!(
                compiled.module().required_runtime_symbol().is_none(),
                "{target:?}"
            );
            assert_eq!(
                compiled.module().start_accelerator(),
                StartAccelerator::None
            );
            assert_eq!(compiled.module().anchored_prefix_filter_bytes(), 0);
            let data = compiled.module().sections()[1].bytes();
            let view = compiled
                .program()
                .native_bit_parallel_exists_view()
                .expect("native view");
            assert_eq!(
                data.len(),
                BYTE_VALUES + view.stats.transition_entries * core::mem::size_of::<u64>()
            );
            if let Some(expected) = &canonical_data {
                assert_eq!(
                    data, expected,
                    "target-private table changed for {target:?}"
                );
            } else {
                canonical_data = Some(data.to_vec());
            }
            assert!(compiled.module().relocations().iter().all(|relocation| {
                relocation.section == TEXT_SECTION
                    && relocation.symbol == PROGRAM_SYMBOL
                    && usize::try_from(relocation.offset)
                        .is_ok_and(|offset| offset < compiled.module().code_bytes())
            }));
            match target.architecture {
                Architecture::X86_64 => assert_eq!(
                    compiled
                        .module()
                        .relocations()
                        .iter()
                        .map(|relocation| relocation.kind)
                        .collect::<Vec<_>>(),
                    [RelocationKind::X86PcRelative32]
                ),
                Architecture::Aarch64 => assert_eq!(
                    compiled
                        .module()
                        .relocations()
                        .iter()
                        .map(|relocation| relocation.kind)
                        .collect::<Vec<_>>(),
                    [
                        RelocationKind::Aarch64Page21,
                        RelocationKind::Aarch64PageOff12
                    ]
                ),
            }

            let bytes = compiled.program().serialize().expect("serialize sidecar");
            let restored = CompiledProgram::deserialize(&bytes).expect("restore sidecar");
            let restored_module = super::super::CompiledModule::lower(&restored, target)
                .expect("lower restored sidecar");
            assert!(restored_module.required_runtime_symbol().is_none());
            assert_eq!(restored_module.sections()[1].bytes(), data);
            assert_eq!(
                restored_module.relocations(),
                compiled.module().relocations()
            );
        }
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    ))]
    #[allow(
        clippy::too_many_lines,
        reason = "the opt-in linker differential keeps object, ABI, and every-window expectations together"
    )]
    fn run_linked_bit_parallel_differential(target: Target, x86_rosetta: bool) {
        use std::{fmt::Write as _, fs, process::Command};

        let compiled = compiled_sidecar(target);
        assert!(compiled.module().required_runtime_symbol().is_none());
        let haystacks = [
            b"".as_slice(),
            b"z".as_slice(),
            b"xxabczxx".as_slice(),
            b"ababababx".as_slice(),
            b"ccabccz".as_slice(),
        ];
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-bit-parallel-exists-{}-{}",
            std::process::id(),
            if x86_rosetta { "x86" } else { "host" }
        ));
        fs::create_dir_all(&directory).expect("create linked fixture directory");
        let object = directory.join("bit_parallel.o");
        fs::write(&object, compiled.object()).expect("write bit-parallel object");
        let symbol = compiled.module().entry_symbol();
        let mut source = format!(
            "#include <stdint.h>\n#include <stddef.h>\nextern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\n"
        );
        let mut calls = String::from("int main(void){size_t r[2];uint32_t s;\n");
        for (haystack_index, haystack) in haystacks.iter().enumerate() {
            let bytes = if haystack.is_empty() {
                "0".to_owned()
            } else {
                haystack
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            };
            writeln!(
                source,
                "static const unsigned char h{haystack_index}[]={{{bytes}}};"
            )
            .unwrap();
            for start in 0..=haystack.len() {
                for end in start..=haystack.len() {
                    let expected = compiled
                        .search(haystack, SearchWindow::new(start, end))
                        .expect("portable result");
                    let MatchResult::Exists(found) = expected else {
                        panic!("Exists contract changed")
                    };
                    writeln!(
                        calls,
                        "r[0]=99;r[1]=99;s={symbol}(h{haystack_index},{},{start},{end},r);if(s!={}||r[0]!=0||r[1]!=0)return {};",
                        haystack.len(),
                        u8::from(found),
                        haystack_index.checked_add(10).expect("fixture failure code")
                    )
                    .unwrap();
                }
            }
        }
        writeln!(
            calls,
            "r[0]=71;r[1]=73;s={symbol}(h1,1,1,0,r);if(s!=2||r[0]!=71||r[1]!=73)return 80;"
        )
        .unwrap();
        writeln!(
            calls,
            "r[0]=71;r[1]=73;s={symbol}(h1,1,0,2,r);if(s!=2||r[0]!=71||r[1]!=73)return 81;"
        )
        .unwrap();
        writeln!(calls, "s={symbol}(h1,1,0,1,(size_t*)0);if(s!=2)return 82;").unwrap();
        writeln!(
            calls,
            "s={symbol}((const unsigned char*)0,0,0,0,r);if(s!=2)return 83;"
        )
        .unwrap();
        calls.push_str("return 0;}\n");
        source.push_str(&calls);
        let c_path = directory.join("bit_parallel.c");
        let executable = directory.join("bit_parallel");
        fs::write(&c_path, source).expect("write linked harness");
        let compiler_command = if cfg!(target_os = "macos") {
            "clang"
        } else {
            "cc"
        };
        let mut linker = Command::new(compiler_command);
        linker.arg("-O0");
        if x86_rosetta {
            linker.args(["-arch", "x86_64"]);
        }
        let status = linker
            .arg(&c_path)
            .arg(&object)
            .arg("-o")
            .arg(&executable)
            .status()
            .expect("invoke host C compiler");
        assert!(status.success());
        let output = if x86_rosetta {
            Command::new("arch")
                .arg("-x86_64")
                .arg(&executable)
                .output()
        } else {
            Command::new(&executable).output()
        }
        .expect("execute linked bit-parallel leaf");
        assert!(
            output.status.success(),
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    #[ignore = "links and executes the bit-parallel fallback leaf on the host"]
    fn linked_host_bit_parallel_exists_matches_portable_for_every_window() {
        let target = if cfg!(target_arch = "x86_64") {
            if cfg!(target_os = "linux") {
                Target::x86_64_linux()
            } else {
                Target::x86_64_macos()
            }
        } else if cfg!(target_os = "linux") {
            Target::aarch64_linux()
        } else {
            Target::aarch64_macos()
        };
        run_linked_bit_parallel_differential(target, false);
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    #[test]
    #[ignore = "cross-links x86-64 and executes it through macOS Rosetta"]
    fn linked_x86_64_bit_parallel_exists_matches_portable_under_rosetta() {
        run_linked_bit_parallel_differential(Target::x86_64_macos(), true);
    }
}
