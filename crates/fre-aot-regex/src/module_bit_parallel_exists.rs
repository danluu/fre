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
    AARCH64_EQ, AARCH64_HI, AARCH64_HS, AARCH64_LO, AARCH64_MI, AARCH64_NE,
    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT, Aarch64Assembler, Aarch64SveFilterKind, Architecture,
    CpuFeature, ModuleRelocation, NativeLowering, NativeStartFilter, OperatingSystem,
    PROGRAM_SYMBOL, RelocationKind, StartAccelerator, TEXT_SECTION, Target, X86Assembler,
    X86CandidateMask, aarch64_add_x_imm, aarch64_add_x_reg, aarch64_and_low_x, aarch64_cmp_x,
    aarch64_emit_candidate_any, aarch64_emit_candidate_batch_any,
    aarch64_emit_first_candidate_in_batch, aarch64_emit_first_candidate_lane,
    aarch64_emit_first_lane_constants, aarch64_emit_scalar_filter_membership,
    aarch64_emit_start_filter_address, aarch64_emit_start_filter_batch_candidates,
    aarch64_emit_start_filter_constants, aarch64_emit_start_filter_scalar_bound,
    aarch64_emit_start_filter_vector_candidates, aarch64_emit_sve_filter_setup,
    aarch64_emit_sve_start_filter_scanner, aarch64_load_byte_reg, aarch64_load_q,
    aarch64_load_u64_constant, aarch64_load_x_lsl3, aarch64_lsr_x_imm, aarch64_mov_x,
    aarch64_movz_w, aarch64_reg, aarch64_store_x, filter_from_membership_words, offset_u64,
    push_bytes, x86_emit_first_candidate_lane, x86_emit_scalar_filter_membership,
    x86_emit_start_filter_constants, x86_emit_start_filter_scalar_bound,
    x86_emit_start_filter_vector_candidate, x86_range_scanner_emission, x86_start_filter_kind,
};

const BYTE_VALUES: usize = 256;
const CLASSIFIER_ENTRY_BYTES: usize = core::mem::size_of::<u32>();
const CLASSIFIER_BYTES: usize = BYTE_VALUES * CLASSIFIER_ENTRY_BYTES;
const NIBBLE_BITS: usize = 4;
const NIBBLE_SUBSETS: usize = 1 << NIBBLE_BITS;
const NIBBLE_ROW_BYTES: usize = NIBBLE_SUBSETS * core::mem::size_of::<u64>();
const ACCEPT_BIT: u64 = 1_u64 << 63;
const CONSUMING_BITS: u64 = ACCEPT_BIT - 1;

// This prototype is deliberately narrower than semantic compilability. A
// root-departure set wider than one eighth of the alphabet makes recurrence
// replay common enough that publication must remain with the prepared K0
// runtime until a stronger cost model proves otherwise.
const MAX_ROOT_SKIP_CANDIDATE_BYTES: u16 = 32;
const ROOT_SKIP_FIRST_LANE_BYTES: usize = 16;

// The sidecar itself proves a tighter retained-memory ceiling. These native
// caps independently bound object growth and make a failed optional lowering
// fall back to the serialized runtime route.
const MAX_NATIVE_BIT_PARALLEL_DATA_BYTES: usize =
    CLASSIFIER_BYTES
        + 256 * (MAX_BIT_PARALLEL_EXISTS_STATES / NIBBLE_BITS) * NIBBLE_ROW_BYTES
        + ROOT_SKIP_FIRST_LANE_BYTES * 2;
const MAX_NATIVE_BIT_PARALLEL_CODE_BYTES: usize = 2 * 1024;

#[derive(Debug)]
struct NativeBitParallelLayout {
    data: Vec<u8>,
    root: u64,
    source_nibbles: usize,
    constant_result: Option<bool>,
    root_filter: Option<NativeStartFilter>,
    first_lane_table_offset: Option<u32>,
    sve2_match_table_offset: Option<u32>,
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
    if layout.constant_result.is_none() {
        let Some(filter) = layout.root_filter else {
            return Ok(None);
        };
        if layout.source_nibbles != 1
            || filter.candidate_bytes > MAX_ROOT_SKIP_CANDIDATE_BYTES
            || filter.constant_count() > 8
            || filter.ranges().is_empty()
        {
            return Ok(None);
        }
        if target.architecture == Architecture::Aarch64
            && !target.features.has(CpuFeature::Aarch64Asimd)
            && !(target.operating_system == OperatingSystem::Linux
                && target.features.has(CpuFeature::Aarch64Sve))
        {
            return Ok(None);
        }
    }
    let emission = match target.architecture {
        Architecture::X86_64 => lower_x86_64_bit_parallel(&layout, target)?,
        Architecture::Aarch64 => lower_aarch64_bit_parallel(&layout, target)?,
    };
    if emission.code.len() > MAX_NATIVE_BIT_PARALLEL_CODE_BYTES
        || emission.emitted_nibbles != layout.source_nibbles
    {
        return Ok(None);
    }
    let start_accelerator = if layout.constant_result.is_some() {
        StartAccelerator::None
    } else {
        let filter = layout.root_filter.ok_or(ObjectError::InvalidModule(
            "native bit-parallel scanner receipt has no root filter",
        ))?;
        match target.architecture {
            Architecture::X86_64 => {
                x86_range_scanner_emission(filter, x86_start_filter_kind(target.features))?
                    .start_accelerator()
            }
            Architecture::Aarch64
                if target.operating_system == OperatingSystem::Linux
                    && target.features.has(CpuFeature::Aarch64Sve2)
                    && layout.sve2_match_table_offset.is_some() =>
            {
                StartAccelerator::Aarch64Sve2
            }
            Architecture::Aarch64
                if target.operating_system == OperatingSystem::Linux
                    && target.features.has(CpuFeature::Aarch64Sve) =>
            {
                StartAccelerator::Aarch64Sve
            }
            Architecture::Aarch64 => StartAccelerator::Aarch64Asimd,
        }
    };
    Ok(Some(NativeLowering {
        code: emission.code,
        data: layout.data,
        relocations: emission.relocations,
        slow_partial_table: None,
        needs_runtime: false,
        start_accelerator,
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
    let data_bytes = CLASSIFIER_BYTES.checked_add(transition_bytes)?;
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

    let root_filter = if constant_result.is_none() && source_nibbles == 1 {
        let subset = usize::try_from(root & 0x0f).ok()?;
        let mut membership = [0_u64; 4];
        for byte in u8::MIN..=u8::MAX {
            let class = usize::from(view.byte_to_class[usize::from(byte)]);
            let index = class.checked_mul(NIBBLE_SUBSETS)?.checked_add(subset)?;
            let reached = *view.transition_masks.get(index)?;
            let changes_root = reached & (ACCEPT_BIT | (CONSUMING_BITS & !root)) != 0;
            if changes_root {
                let byte = usize::from(byte);
                membership[byte / 64] |= 1_u64 << (byte % 64);
            }
        }
        filter_from_membership_words(membership, 0, false)
            .ok()
            .flatten()
    } else {
        None
    };

    let mut data = Vec::new();
    if constant_result.is_none() {
        data.try_reserve_exact(data_bytes).ok()?;
        let class_stride = source_nibbles.checked_mul(NIBBLE_ROW_BYTES)?;
        for &class in view.byte_to_class {
            let offset = usize::from(class)
                .checked_mul(class_stride)?
                .checked_add(CLASSIFIER_BYTES)?;
            data.extend_from_slice(&u32::try_from(offset).ok()?.to_le_bytes());
        }
        for &mask in view.transition_masks {
            data.extend_from_slice(&mask.to_le_bytes());
        }
        if data.len() != data_bytes {
            return None;
        }
    }

    let mut first_lane_table_offset = None;
    let mut sve2_match_table_offset = None;
    if let Some(filter) = root_filter.filter(|filter| !filter.ranges().is_empty()) {
        first_lane_table_offset = Some(u32::try_from(data.len()).ok()?);
        data.try_reserve_exact(ROOT_SKIP_FIRST_LANE_BYTES.checked_mul(2)?)
            .ok()?;
        data.extend(0_u8..u8::try_from(ROOT_SKIP_FIRST_LANE_BYTES).ok()?);
        if filter.is_exact() {
            sve2_match_table_offset = Some(u32::try_from(data.len()).ok()?);
            let first = filter.ranges().first()?.start;
            for index in 0..ROOT_SKIP_FIRST_LANE_BYTES {
                data.push(
                    filter
                        .ranges()
                        .get(index)
                        .map_or(first, |range| range.start),
                );
            }
        }
    }
    if data.len() > MAX_NATIVE_BIT_PARALLEL_DATA_BYTES {
        return None;
    }
    Some(NativeBitParallelLayout {
        data,
        root,
        source_nibbles,
        constant_result,
        root_filter,
        first_lane_table_offset,
        sve2_match_table_offset,
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
    target: Target,
) -> Result<NativeBitParallelEmission, ObjectError> {
    let mut assembler = X86Assembler::new();
    let scan = assembler.label()?;
    let vector_scan = assembler.label()?;
    let vector_hit = assembler.label()?;
    let scalar_scan = assembler.label()?;
    let scalar_miss = assembler.label()?;
    let recurrence = assembler.label()?;
    let no_match = assembler.label()?;
    let matched = assembler.label()?;
    let invalid = assembler.label()?;
    let done = assembler.label()?;

    x86_emit_abi_validation(&mut assembler, invalid)?;
    x86_emit_result_zero(&mut assembler)?;
    let filter_kind = layout
        .root_filter
        .map(|_| x86_start_filter_kind(target.features));
    if let Some(result) = layout.constant_result {
        assembler.instruction(&[0xb8, u8::from(result), 0, 0, 0])?;
        assembler.branch(&[0xe9], done)?;
    } else {
        let filter = layout.root_filter.ok_or(ObjectError::InvalidModule(
            "native bit-parallel root scanner is absent",
        ))?;
        let kind = filter_kind.ok_or(ObjectError::InvalidModule(
            "native bit-parallel x86 scanner kind is absent",
        ))?;
        // lea table(%rip), r9
        assembler.instruction(&[0x4c, 0x8d, 0x0d])?;
        let table_displacement_label = assembler.label()?;
        assembler.bind(table_displacement_label)?;
        push_bytes(&mut assembler.code, &[0; 4])?;

        let mut root = vec![0x49, 0xbb]; // movabs root, r11
        root.extend_from_slice(&layout.root.to_le_bytes());
        assembler.instruction(&root)?;
        assembler.instruction(&[0x4d, 0x89, 0xda])?; // active r10 = root r11
        x86_emit_start_filter_constants(&mut assembler, filter, kind, 1)?;

        // Only this edge owns the exact restart/root state. Every miss byte is
        // graph-proven to leave both that state and acceptance unchanged.
        assembler.bind(scan)?;
        assembler.bind(vector_scan)?;
        assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
        assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= position
        assembler.instruction(&[0x48, 0x83, 0xf8, kind.width()])?;
        assembler.branch(&[0x0f, 0x82], scalar_scan)?;
        x86_emit_start_filter_vector_candidate(&mut assembler, filter, kind, vector_hit)?;
        assembler.instruction(&[0x48, 0x83, 0xc2, kind.width()])?;
        assembler.branch(&[0xe9], vector_scan)?;

        assembler.bind(vector_hit)?;
        x86_emit_first_candidate_lane(&mut assembler, X86CandidateMask::for_filter(filter, kind))?;
        assembler.instruction(&[0x48, 0x01, 0xc2])?; // position += first lane
        assembler.branch(&[0xe9], recurrence)?;

        assembler.bind(scalar_scan)?;
        x86_emit_start_filter_scalar_bound(&mut assembler, 0, no_match)?;
        x86_emit_scalar_filter_membership(&mut assembler, filter, scalar_miss)?;
        assembler.branch(&[0xe9], recurrence)?;
        assembler.bind(scalar_miss)?;
        assembler.instruction(&[0x48, 0xff, 0xc2])?;
        assembler.branch(&[0xe9], scalar_scan)?;

        assembler.bind(recurrence)?;
        assembler.instruction(&[0x48, 0x39, 0xca])?; // position >= end
        assembler.branch(&[0x0f, 0x83], no_match)?;
        assembler.instruction(&[0x0f, 0xb6, 0x04, 0x17])?; // byte at position
        assembler.instruction(&[0x48, 0xff, 0xc2])?; // position += 1
        assembler.instruction(&[0x41, 0x8b, 0x04, 0x81])?; // row offset = table[byte]
        assembler.instruction(&[0x49, 0x8d, 0x34, 0x01])?; // row = table + offset
        assembler.instruction(&[0x4c, 0x89, 0xd0])?; // subset = active
        assembler.instruction(&[0x83, 0xe0, 0x0f])?;
        assembler.instruction(&[0x48, 0x8b, 0x04, 0xc6])?; // reached = row[subset]
        assembler.instruction(&[0x48, 0x85, 0xc0])?;
        assembler.branch(&[0x0f, 0x88], matched)?; // acceptance marker is the sign bit
        assembler.instruction(&[0x48, 0x0f, 0xba, 0xf0, 0x3f])?; // btr 63, rax
        assembler.instruction(&[0x4c, 0x09, 0xd8])?; // root | reached
        assembler.instruction(&[0x49, 0x89, 0xc2])?; // next active
        assembler.instruction(&[0x4d, 0x39, 0xda])?; // root restored?
        assembler.branch(&[0x0f, 0x84], scan)?;
        assembler.branch(&[0xe9], recurrence)?;

        assembler.bind(no_match)?;
        assembler.instruction(&[0x31, 0xc0])?;
        assembler.branch(&[0xe9], done)?;
        assembler.bind(matched)?;
        assembler.instruction(&[0xb8, 0x01, 0, 0, 0])?;
        assembler.branch(&[0xe9], done)?;

        assembler.bind(invalid)?;
        assembler.instruction(&[0xb8, 0x02, 0, 0, 0])?;
        assembler.bind(done)?;
        if kind.needs_vzeroupper() {
            assembler.instruction(&[0xc5, 0xf8, 0x77])?;
        }
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
    if filter_kind.is_some_and(|kind| kind.needs_vzeroupper()) {
        assembler.instruction(&[0xc5, 0xf8, 0x77])?;
    }
    assembler.instruction(&[0xc3])?;
    Ok(NativeBitParallelEmission {
        code: assembler.finish_with_label_offsets()?.code,
        relocations: Vec::new(),
        emitted_nibbles: layout.source_nibbles,
    })
}

fn aarch64_load_w_lsl2(destination: u8, base: u8, index: u8) -> Result<u32, ObjectError> {
    Ok(
        0xb860_7800
            | aarch64_reg(index, 16)?
            | aarch64_reg(base, 5)?
            | aarch64_reg(destination, 0)?,
    )
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
    target: Target,
) -> Result<NativeBitParallelEmission, ObjectError> {
    let mut assembler = Aarch64Assembler::new();
    let scan = assembler.label()?;
    let single_vector = assembler.label()?;
    let single_hit = assembler.label()?;
    let batch_hit = assembler.label()?;
    let scalar_scan = assembler.label()?;
    let scalar_miss = assembler.label()?;
    let recurrence = assembler.label()?;
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
        let filter = layout.root_filter.ok_or(ObjectError::InvalidModule(
            "native bit-parallel root scanner is absent",
        ))?;
        let use_sve = target.operating_system == OperatingSystem::Linux
            && target.features.has(CpuFeature::Aarch64Sve);
        let use_asimd = !use_sve && target.features.has(CpuFeature::Aarch64Asimd);
        if !use_sve && !use_asimd {
            return Err(ObjectError::InvalidModule(
                "native bit-parallel AArch64 scanner is not vectorized",
            ));
        }
        let table_page = assembler.instruction(0x9000_0005)?; // adrp x5, table
        let table_page_offset = assembler.instruction(aarch64_add_x_imm(5, 5, 0)?)?;
        aarch64_load_u64_constant(&mut assembler, 9, layout.root)?;
        assembler.instruction(aarch64_mov_x(8, 9)?)?;

        if use_sve {
            let kind = if target.features.has(CpuFeature::Aarch64Sve2)
                && let Some(match_table_offset) = layout.sve2_match_table_offset
            {
                Aarch64SveFilterKind::Sve2 { match_table_offset }
            } else {
                Aarch64SveFilterKind::Sve
            };
            aarch64_emit_sve_filter_setup(&mut assembler, filter, kind, 0)?;
            aarch64_emit_sve_start_filter_scanner(
                &mut assembler,
                filter,
                0,
                kind,
                false,
                false,
                scan,
                scalar_scan,
                recurrence,
            )?;
        } else {
            aarch64_emit_start_filter_constants(
                &mut assembler,
                filter,
                AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
            )?;
            aarch64_emit_first_lane_constants(
                &mut assembler,
                layout
                    .first_lane_table_offset
                    .ok_or(ObjectError::InvalidModule(
                        "native bit-parallel ASIMD first-lane table is absent",
                    ))?,
            )?;

            assembler.bind(scan)?;
            assembler.instruction(super::aarch64_sub_x_reg(12, 3, 2)?)?;
            assembler.instruction(super::aarch64_cmp_x_imm(12, 64)?)?;
            assembler.branch_cond(AARCH64_LO, single_vector)?;
            let first_candidates = aarch64_emit_start_filter_batch_candidates(
                &mut assembler,
                filter,
                AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
            )?;
            aarch64_emit_candidate_batch_any(&mut assembler, first_candidates)?;
            assembler.branch_cond(AARCH64_NE, batch_hit)?;
            assembler.instruction(aarch64_add_x_imm(2, 2, 64)?)?;
            assembler.branch(scan)?;

            assembler.bind(batch_hit)?;
            aarch64_emit_first_candidate_in_batch(&mut assembler, first_candidates)?;
            assembler.branch(recurrence)?;

            assembler.bind(single_vector)?;
            assembler.instruction(super::aarch64_sub_x_reg(12, 3, 2)?)?;
            assembler.instruction(super::aarch64_cmp_x_imm(12, 16)?)?;
            assembler.branch_cond(AARCH64_LO, scalar_scan)?;
            aarch64_emit_start_filter_address(&mut assembler, 0)?;
            assembler.instruction(aarch64_load_q(0, 12)?)?;
            aarch64_emit_start_filter_vector_candidates(
                &mut assembler,
                filter,
                0,
                24,
                AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
            )?;
            aarch64_emit_candidate_any(&mut assembler, 24)?;
            assembler.branch_cond(AARCH64_NE, single_hit)?;
            assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
            assembler.branch(scan)?;

            assembler.bind(single_hit)?;
            aarch64_emit_first_candidate_lane(&mut assembler, 24)?;
            assembler.branch(recurrence)?;
        }

        assembler.bind(scalar_scan)?;
        aarch64_emit_start_filter_scalar_bound(&mut assembler, 0, no_match)?;
        aarch64_emit_scalar_filter_membership(&mut assembler, filter, scalar_miss)?;
        assembler.branch(recurrence)?;
        assembler.bind(scalar_miss)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
        assembler.branch(scalar_scan)?;

        assembler.bind(recurrence)?;
        assembler.instruction(aarch64_cmp_x(2, 3)?)?;
        assembler.branch_cond(AARCH64_HS, no_match)?;
        assembler.instruction(aarch64_load_byte_reg(12, 0, 2)?)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
        assembler.instruction(aarch64_load_w_lsl2(11, 5, 12)?)?;
        assembler.instruction(aarch64_add_x_reg(11, 5, 11)?)?;
        assembler.instruction(aarch64_and_low_x(12, 8, 4)?)?;
        assembler.instruction(aarch64_load_x_lsl3(10, 11, 12)?)?;
        assembler.instruction(aarch64_lsr_x_imm(12, 10, 63)?)?;
        assembler.branch_nonzero_w(12, matched)?;
        assembler.instruction(aarch64_and_low_x(8, 10, 63)?)?;
        assembler.instruction(aarch64_orr_x(8, 8, 9)?)?;
        assembler.instruction(aarch64_cmp_x(8, 9)?)?;
        assembler.branch_cond(AARCH64_EQ, scan)?;
        assembler.branch(recurrence)?;

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
        DeterminizeLimits, FeatureSet, MatchResult, OutputContract, SearchWindow, SlowAotLimits,
        Target, compile_with_slow_aot_limits,
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
        let compiled = compile_with_slow_aot_limits(
            CompileRequest::new(GENERAL_PATTERN, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists)
                .limits(fallback_limits()),
            SlowAotLimits {
                determinize: DeterminizeLimits {
                    max_states: 0,
                    max_transitions: 0,
                    max_work: 0,
                },
                max_allocation_bytes: 0,
                max_native_data_bytes: 0,
            },
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
        let transition_extent = CLASSIFIER_BYTES
            .checked_add(core::mem::size_of_val(view.transition_masks))
            .expect("native transition extent");
        assert_eq!(
            layout.first_lane_table_offset,
            Some(u32::try_from(transition_extent).unwrap())
        );
        assert_eq!(layout.data.len(), transition_extent + 32);
        let class_stride = view.stats.source_nibbles * NIBBLE_ROW_BYTES;
        for (byte, &class) in view.byte_to_class.iter().enumerate() {
            let classifier_offset = byte * CLASSIFIER_ENTRY_BYTES;
            let actual = u32::from_le_bytes(
                layout.data[classifier_offset..classifier_offset + CLASSIFIER_ENTRY_BYTES]
                    .try_into()
                    .expect("one classifier offset"),
            );
            assert_eq!(
                usize::try_from(actual).unwrap(),
                CLASSIFIER_BYTES + usize::from(class) * class_stride
            );
        }

        for class in 0..view.stats.byte_classes {
            for nibble in 0..view.stats.source_nibbles {
                for subset in 0..NIBBLE_SUBSETS {
                    let table_index =
                        (class * view.stats.source_nibbles + nibble) * NIBBLE_SUBSETS + subset;
                    let offset = CLASSIFIER_BYTES + table_index * core::mem::size_of::<u64>();
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
                let classifier_offset = usize::from(byte) * CLASSIFIER_ENTRY_BYTES;
                let class_offset = usize::try_from(u32::from_le_bytes(
                    layout.data[classifier_offset..classifier_offset + CLASSIFIER_ENTRY_BYTES]
                        .try_into()
                        .expect("one classifier offset"),
                ))
                .unwrap();
                assert_eq!(class_offset, CLASSIFIER_BYTES + class * class_stride);
                let mut canonical = 0_u64;
                let mut packed = 0_u64;
                for nibble in 0..view.stats.source_nibbles {
                    let subset = usize::try_from((active >> (nibble * NIBBLE_BITS)) & 15)
                        .expect("four-bit subset");
                    let index =
                        (class * view.stats.source_nibbles + nibble) * NIBBLE_SUBSETS + subset;
                    canonical |= view.transition_masks[index];
                    let offset = class_offset
                        + nibble * NIBBLE_ROW_BYTES
                        + subset * core::mem::size_of::<u64>();
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
    fn exact_w1_has_one_recurrence_load_and_wider_words_do_not_publish() {
        let compiled = compiled_sidecar(Target::x86_64_linux());
        let view = compiled
            .program()
            .native_bit_parallel_exists_view()
            .expect("native W1 view");
        let layout = build_native_bit_parallel_layout(view).expect("native W1 layout");
        assert_eq!(layout.source_nibbles, 1);
        let filter = layout.root_filter.expect("exact root filter");
        assert!(!filter.ranges().is_empty());
        assert!(filter.candidate_bytes <= MAX_ROOT_SKIP_CANDIDATE_BYTES);
        let root_subset = usize::try_from(layout.root & 0x0f).unwrap();
        for byte in u8::MIN..=u8::MAX {
            let class = usize::from(view.byte_to_class[usize::from(byte)]);
            let reached = view.transition_masks[class * NIBBLE_SUBSETS + root_subset];
            let expected = reached & (ACCEPT_BIT | (CONSUMING_BITS & !layout.root)) != 0;
            let admitted = filter
                .ranges()
                .iter()
                .any(|range| range.start <= byte && byte <= range.end);
            assert_eq!(admitted, expected, "root departure byte {byte:#04x}");
            if !admitted {
                assert_eq!(reached & ACCEPT_BIT, 0);
                assert_eq!((reached & CONSUMING_BITS) | layout.root, layout.root);
            }
        }

        let avx2 = Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        let x86 = lower_x86_64_bit_parallel(&layout, avx2).expect("x86 W1 leaf");
        assert_eq!(x86.emitted_nibbles, 1);
        assert_eq!(count_bytes(&x86.code, &[0x41, 0x8b, 0x04, 0x81]), 1);
        assert_eq!(count_bytes(&x86.code, &[0xc5, 0xf8, 0x77]), 1);
        assert_eq!(x86.relocations.len(), 1);

        let asimd = Target::aarch64_macos()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
            .unwrap();
        let aarch64 = lower_aarch64_bit_parallel(&layout, asimd).expect("ASIMD W1 leaf");
        let union_load = aarch64_load_x_lsl3(10, 11, 12).unwrap();
        let classifier_load = aarch64_load_w_lsl2(11, 5, 12).unwrap();
        for expected in [union_load, classifier_load] {
            assert_eq!(
                aarch64
                    .code
                    .chunks_exact(4)
                    .filter(|bytes| u32::from_le_bytes((*bytes).try_into().unwrap()) == expected)
                    .count(),
                1
            );
        }
        assert_eq!(aarch64.emitted_nibbles, 1);
        assert_eq!(aarch64.relocations.len(), 2);

        let byte_to_class = [0_u8; BYTE_VALUES];
        for source_nibbles in 2..=MAX_BIT_PARALLEL_EXISTS_STATES / NIBBLE_BITS {
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
            assert!(layout.root_filter.is_none());
            assert_eq!(
                layout.data.len(),
                CLASSIFIER_BYTES + source_nibbles * NIBBLE_ROW_BYTES
            );
            assert!(
                lower_native_bit_parallel_exists(view, Target::x86_64_linux())
                    .unwrap()
                    .is_none()
            );
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
    fn publication_receipt_requires_and_names_the_emitted_vector_scanner() {
        let avx512 = FeatureSet::of(CpuFeature::X86Avx512F)
            .with(CpuFeature::X86Avx512Bw)
            .with(CpuFeature::X86Avx512Vl);
        let sve = FeatureSet::of(CpuFeature::Aarch64Sve);
        let sve2 = sve.with(CpuFeature::Aarch64Sve2);
        let mixed_sve2 = FeatureSet::of(CpuFeature::Aarch64Asimd).union(sve2);
        let targets = [
            (Target::x86_64_linux(), Some(StartAccelerator::X86Sse2)),
            (
                Target::x86_64_macos()
                    .with_features(FeatureSet::of(CpuFeature::X86Avx2))
                    .unwrap(),
                Some(StartAccelerator::X86Avx2),
            ),
            (
                Target::x86_64_linux().with_features(avx512).unwrap(),
                Some(StartAccelerator::X86Avx512Bw),
            ),
            (Target::aarch64_linux(), None),
            (Target::aarch64_macos(), None),
            (
                Target::aarch64_macos()
                    .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                    .unwrap(),
                Some(StartAccelerator::Aarch64Asimd),
            ),
            (
                Target::aarch64_linux().with_features(sve).unwrap(),
                Some(StartAccelerator::Aarch64Sve),
            ),
            (
                Target::aarch64_linux().with_features(sve2).unwrap(),
                Some(StartAccelerator::Aarch64Sve2),
            ),
            (
                Target::aarch64_linux().with_features(mixed_sve2).unwrap(),
                Some(StartAccelerator::Aarch64Sve2),
            ),
            (Target::aarch64_macos().with_features(sve2).unwrap(), None),
            (
                Target::aarch64_macos().with_features(mixed_sve2).unwrap(),
                Some(StartAccelerator::Aarch64Asimd),
            ),
        ];

        let mut canonical_native_data = None::<Vec<u8>>;
        for (target, expected_accelerator) in targets {
            let compiled = compiled_sidecar(target);
            let native = expected_accelerator.is_some();
            assert_eq!(
                compiled.receipt().runtime_helper_required,
                !native,
                "{target:?}"
            );
            assert_eq!(
                compiled.module().required_runtime_symbol().is_none(),
                native,
                "{target:?}"
            );
            assert_eq!(
                compiled.module().start_accelerator(),
                expected_accelerator.unwrap_or(StartAccelerator::None),
                "{target:?}"
            );
            assert_eq!(compiled.module().anchored_prefix_filter_bytes(), 0);
            let data = compiled.module().sections()[1].bytes();
            if native {
                if let Some(expected) = &canonical_native_data {
                    assert_eq!(
                        data, expected,
                        "target-private table changed for {target:?}"
                    );
                } else {
                    canonical_native_data = Some(data.to_vec());
                }
            }
            assert!(compiled.module().relocations().iter().all(|relocation| {
                relocation.section == TEXT_SECTION
                    && (!native || relocation.symbol == PROGRAM_SYMBOL)
                    && usize::try_from(relocation.offset)
                        .is_ok_and(|offset| offset < compiled.module().code_bytes())
            }));
            if native {
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
            }

            let bytes = compiled.program().serialize().expect("serialize sidecar");
            let restored = CompiledProgram::deserialize(&bytes).expect("restore sidecar");
            let restored_module = super::super::CompiledModule::lower(&restored, target)
                .expect("lower restored sidecar");
            assert_eq!(restored_module.required_runtime_symbol().is_none(), native);
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
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap()
        } else {
            Target::aarch64_macos()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap()
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
