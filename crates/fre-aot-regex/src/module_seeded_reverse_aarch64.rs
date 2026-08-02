//! `AArch64` lowering for the independent seeded-reverse mandatory-factor proof.
//!
//! This is a child of `module`, so it deliberately reuses the same checked
//! assembler and graph-derived filter primitives as the ordinary suffix
//! prepass. The emitted leaf uses only AAPCS64 caller-saved general and SIMD
//! registers and makes no runtime calls.

#[allow(
    clippy::wildcard_imports,
    reason = "this private module deliberately shares its parent's assembler vocabulary"
)]
use super::*;

// Persistent state is kept outside every scratch register used by the shared
// scalar and ASIMD scanners. All five registers are AAPCS64 caller-saved; X18
// remains untouched because platforms may reserve it.
const REVERSE_CLASS_MAP: u8 = 10;
const REVERSE_FUEL: u8 = 13;
const REVERSE_MINIMUM: u8 = 14;
const REVERSE_NEXT_BASE: u8 = 15;
const REVERSE_CURSOR: u8 = 16;

fn aarch64_movn_zero_x(destination: u8) -> Result<u32, ObjectError> {
    // MOVN Xd, #0 materializes the all-ones sentinel without consuming a
    // second persistent register.
    Ok(0x9280_0000 | aarch64_reg(destination, 0)?)
}

/// Scan every graph-required factor candidate and prove candidate starts with
/// the independently determinized exact reverse machine.
///
/// Total reverse-table work is capped at one transition per byte in the
/// semantic input window. Fuel exhaustion restores X2 from the untouched X9
/// window start and enters the ordinary forward DFA. Candidate exhaustion is
/// a proof of no match when no reverse walk reached a possible start.
#[allow(
    clippy::large_types_passed_by_value,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the factor scanner and reverse-proof control flow form one auditable native loop"
)]
pub(super) fn aarch64_emit_seeded_reverse_prepass(
    assembler: &mut Aarch64Assembler,
    suffix: NativeSuffixFilter,
    reverse: NativeSeededReverseLayout,
    use_asimd: bool,
    use_asimd_batch: bool,
    use_exact_asimd_lane: bool,
    layout: NativeDfaLayout,
    no_match: Aarch64Label,
    matched: Aarch64Label,
) -> Result<(), ObjectError> {
    let vector = assembler.label()?;
    let single_vector = assembler.label()?;
    let scalar = assembler.label()?;
    let scalar_columns = assembler.label()?;
    let scalar_reject = assembler.label()?;
    let batch_primary_hit = assembler.label()?;
    let single_primary_hit = assembler.label()?;
    let batch_hit = assembler.label()?;
    let single_hit = assembler.label()?;
    let candidate = assembler.label()?;
    let reverse_loop = assembler.label()?;
    let record_start = assembler.label()?;
    let reverse_continue = assembler.label()?;
    let reverse_done = assembler.label()?;
    let finalize = assembler.label()?;
    let global_minimum = assembler.label()?;
    let fallback = assembler.label()?;
    let done = assembler.label()?;
    let filter = suffix.filter;

    if suffix.minimum_width == 0 || filter.ranges().is_empty() {
        return Err(ObjectError::InvalidModule(
            "AArch64 seeded reverse filter has no mandatory bytes",
        ));
    }
    if layout.seeded_reverse != Some(reverse) {
        return Err(ObjectError::InvalidModule(
            "AArch64 seeded reverse layout changed during lowering",
        ));
    }
    if suffix.retry.is_some() || matches!(suffix.restart, NativeSuffixRestart::Synchronizing { .. })
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 seeded reverse escaped its graph admission gate",
        ));
    }
    if use_asimd_batch && !use_asimd {
        return Err(ObjectError::InvalidModule(
            "AArch64 seeded reverse selected an ASIMD batch on a scalar target",
        ));
    }
    let lazy_vector_filter = suffix.vector_filter;
    let scalar_filter = suffix.vector_filter.or(suffix.scalar_filter);
    let maximum_filter_offset =
        scalar_filter.map_or(filter.scan_offset, NativeVectorFilter::max_scan_offset);
    // An Accept seed starts at base + minimum_width. Requiring the last byte
    // before that boundary to be in-bounds makes every reverse load safe.
    let maximum_scan_offset = maximum_filter_offset.max(reverse.boundary_offset.saturating_sub(1));
    let emit_constants = |assembler: &mut Aarch64Assembler| -> Result<(), ObjectError> {
        if use_asimd {
            if let Some(vector_filter) = lazy_vector_filter {
                let mut first_register = AARCH64_VECTOR_FILTER_FIRST_CONSTANT;
                for &column in vector_filter.columns() {
                    aarch64_emit_start_filter_constants(assembler, column, first_register)?;
                    first_register = first_register
                        .checked_add(u8::try_from(column.constant_count()).map_err(|_| {
                            ObjectError::ArithmeticOverflow(
                                "AArch64 seeded reverse filter constants",
                            )
                        })?)
                        .ok_or(ObjectError::ArithmeticOverflow(
                            "AArch64 seeded reverse filter constants",
                        ))?;
                }
            } else {
                aarch64_emit_start_filter_constants(
                    assembler,
                    filter,
                    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                )?;
            }
        }
        Ok(())
    };

    if !ENABLE_DEFERRED_SUFFIX_FILTER_CONSTANTS {
        emit_constants(assembler)?;
    }
    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
    assembler.instruction(aarch64_cmp_x_imm(12, SUFFIX_PREFILTER_MIN_WINDOW_BYTES)?)?;
    assembler.branch_cond(AARCH64_LO, done)?;
    assembler.instruction(aarch64_mov_x(REVERSE_FUEL, 12)?)?;
    assembler.instruction(aarch64_movn_zero_x(REVERSE_MINIMUM)?)?;
    if ENABLE_DEFERRED_SUFFIX_FILTER_CONSTANTS {
        emit_constants(assembler)?;
    }
    // Unlike the ordinary DFA's optional compact/direct layout, the sidecar
    // always owns an independent exact raw-byte class map.
    aarch64_set_table_address(assembler, REVERSE_CLASS_MAP, reverse.class_map_offset)?;

    let mut batch_first_candidates = None;
    if use_asimd {
        assembler.bind(vector)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        if use_asimd_batch {
            let batch_bytes = u16::from(maximum_scan_offset)
                .checked_add(AARCH64_BATCH_BYTES)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 seeded reverse filter width",
                ))?;
            assembler.instruction(aarch64_cmp_x_imm(12, batch_bytes)?)?;
            assembler.branch_cond(AARCH64_LO, single_vector)?;
            let first_register = if lazy_vector_filter.is_some() {
                AARCH64_VECTOR_FILTER_FIRST_CONSTANT
            } else {
                AARCH64_STANDALONE_FILTER_FIRST_CONSTANT
            };
            let first_candidates =
                aarch64_emit_start_filter_batch_candidates(assembler, filter, first_register)?;
            batch_first_candidates = Some(first_candidates);
            aarch64_emit_candidate_batch_any(assembler, first_candidates)?;
            assembler.branch_cond(
                AARCH64_NE,
                if lazy_vector_filter.is_some() {
                    batch_primary_hit
                } else if use_exact_asimd_lane {
                    batch_hit
                } else {
                    scalar
                },
            )?;
            assembler.instruction(aarch64_add_x_imm(2, 2, AARCH64_BATCH_BYTES)?)?;
            assembler.branch(vector)?;
        }

        assembler.bind(single_vector)?;
        let vector_bytes = u16::from(maximum_scan_offset).checked_add(16).ok_or(
            ObjectError::ArithmeticOverflow("AArch64 seeded reverse filter width"),
        )?;
        assembler.instruction(aarch64_cmp_x_imm(12, vector_bytes)?)?;
        assembler.branch_cond(AARCH64_LO, scalar)?;
        aarch64_emit_start_filter_address(assembler, filter.scan_offset)?;
        assembler.instruction(aarch64_load_q(0, 12)?)?;
        if lazy_vector_filter.is_some() {
            aarch64_emit_start_filter_vector_candidates(
                assembler,
                filter,
                0,
                24,
                AARCH64_VECTOR_FILTER_FIRST_CONSTANT,
            )?;
            aarch64_emit_candidate_any(assembler, 24)?;
            assembler.branch_cond(AARCH64_NE, single_primary_hit)?;
        } else {
            aarch64_emit_start_filter_vector_candidates(
                assembler,
                filter,
                0,
                24,
                AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
            )?;
            aarch64_emit_candidate_any(assembler, 24)?;
            assembler.branch_cond(
                AARCH64_NE,
                if use_exact_asimd_lane {
                    single_hit
                } else {
                    scalar
                },
            )?;
        }
        assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
        assembler.branch(vector)?;

        if let Some(vector_filter) = lazy_vector_filter {
            assembler.bind(batch_primary_hit)?;
            if use_asimd_batch {
                aarch64_emit_vector_filter_secondary_batch(assembler, vector_filter)?;
                aarch64_emit_candidate_batch_any(assembler, 24)?;
                assembler.branch_cond(
                    AARCH64_NE,
                    if use_exact_asimd_lane {
                        batch_hit
                    } else {
                        scalar
                    },
                )?;
                assembler.instruction(aarch64_add_x_imm(2, 2, AARCH64_BATCH_BYTES)?)?;
                assembler.branch(vector)?;
            } else {
                assembler.branch(scalar)?;
            }

            assembler.bind(single_primary_hit)?;
            aarch64_emit_vector_filter_secondary_candidates_at(assembler, vector_filter, 0, 24)?;
            aarch64_emit_candidate_any(assembler, 24)?;
            assembler.branch_cond(
                AARCH64_NE,
                if use_exact_asimd_lane {
                    single_hit
                } else {
                    scalar
                },
            )?;
            assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
            assembler.branch(vector)?;
        } else {
            assembler.bind(batch_primary_hit)?;
            assembler.branch(scalar)?;
            assembler.bind(single_primary_hit)?;
            assembler.branch(scalar)?;
        }

        let selected = if lazy_vector_filter.is_some() || suffix.scalar_filter.is_none() {
            candidate
        } else {
            scalar_columns
        };
        assembler.bind(batch_hit)?;
        if use_exact_asimd_lane && let Some(first_candidates) = batch_first_candidates {
            aarch64_emit_first_candidate_in_batch(assembler, first_candidates)?;
            assembler.branch(selected)?;
        } else {
            assembler.branch(scalar)?;
        }
        assembler.bind(single_hit)?;
        if use_exact_asimd_lane {
            aarch64_emit_first_candidate_lane(assembler, 24)?;
            assembler.branch(selected)?;
        } else {
            assembler.branch(scalar)?;
        }
    } else {
        // Keep all shared labels complete on scalar Linux and macOS targets.
        assembler.bind(vector)?;
        assembler.branch(scalar)?;
        assembler.bind(single_vector)?;
        assembler.branch(scalar)?;
        assembler.bind(batch_primary_hit)?;
        assembler.branch(scalar)?;
        assembler.bind(single_primary_hit)?;
        assembler.branch(scalar)?;
        assembler.bind(batch_hit)?;
        assembler.branch(scalar)?;
        assembler.bind(single_hit)?;
        assembler.branch(scalar)?;
    }

    assembler.bind(scalar)?;
    aarch64_emit_start_filter_scalar_bound(assembler, maximum_scan_offset, finalize)?;
    aarch64_emit_start_filter_scalar_load(assembler, filter.scan_offset)?;
    let scalar_candidate = if scalar_filter.is_some() {
        scalar_columns
    } else {
        candidate
    };
    for range in filter.ranges() {
        assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.start))?)?;
        if range.start == range.end {
            assembler.branch_cond(AARCH64_EQ, scalar_candidate)?;
        } else {
            let next_range = assembler.label()?;
            assembler.branch_cond(AARCH64_LO, next_range)?;
            assembler.instruction(aarch64_cmp_w_imm(8, u16::from(range.end))?)?;
            assembler.branch_cond(AARCH64_LS, scalar_candidate)?;
            assembler.bind(next_range)?;
        }
    }
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    assembler.branch(scalar)?;

    if let Some(vector_filter) = scalar_filter {
        assembler.bind(scalar_columns)?;
        for &column in &vector_filter.columns()[1..] {
            aarch64_emit_scalar_filter_membership(assembler, column, scalar_reject)?;
        }
        assembler.branch(candidate)?;
        assembler.bind(scalar_reject)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
        assembler.branch(vector)?;
    } else {
        assembler.bind(scalar_columns)?;
        assembler.branch(candidate)?;
        assembler.bind(scalar_reject)?;
        assembler.branch(scalar)?;
    }

    assembler.bind(candidate)?;
    assembler.instruction(aarch64_add_x_imm(REVERSE_NEXT_BASE, 2, 1)?)?;
    if reverse.boundary_offset == 0 {
        assembler.instruction(aarch64_mov_x(REVERSE_CURSOR, 2)?)?;
    } else {
        assembler.instruction(aarch64_add_x_imm(
            REVERSE_CURSOR,
            2,
            u16::from(reverse.boundary_offset),
        )?)?;
    }
    aarch64_set_row_base(assembler, reverse.initial_row_offset)?;

    // A start reachable without consuming a reverse byte is recorded before
    // entering the table loop. It must not flow through `reverse_continue`,
    // whose W8 cell exists only after a table load.
    if reverse.initial_reaches_start {
        if reverse.proves_match && layout.output == OutputContract::Exists {
            assembler.branch(matched)?;
        } else {
            assembler.instruction(aarch64_cmp_x(REVERSE_CURSOR, REVERSE_MINIMUM)?)?;
            assembler.branch_cond(AARCH64_HS, reverse_loop)?;
            assembler.instruction(aarch64_mov_x(REVERSE_MINIMUM, REVERSE_CURSOR)?)?;
            assembler.instruction(aarch64_cmp_x(REVERSE_MINIMUM, 9)?)?;
            assembler.branch_cond(AARCH64_EQ, global_minimum)?;
        }
    }

    assembler.bind(reverse_loop)?;
    assembler.instruction(aarch64_cmp_x(REVERSE_CURSOR, 9)?)?;
    assembler.branch_cond(AARCH64_LS, reverse_done)?;
    assembler.instruction(aarch64_cmp_x_imm(REVERSE_FUEL, 0)?)?;
    assembler.branch_cond(AARCH64_EQ, fallback)?;
    assembler.instruction(aarch64_sub_x_imm(REVERSE_CURSOR, REVERSE_CURSOR, 1)?)?;
    assembler.instruction(aarch64_sub_x_imm(REVERSE_FUEL, REVERSE_FUEL, 1)?)?;
    assembler.instruction(aarch64_load_byte_reg(8, 0, REVERSE_CURSOR)?)?;
    assembler.instruction(aarch64_load_byte_reg(8, REVERSE_CLASS_MAP, 8)?)?;
    assembler.instruction(aarch64_load_w_uxtw(8, 11, 8)?)?;
    assembler.branch_bit_set_w(8, 31, record_start)?;

    assembler.bind(reverse_continue)?;
    // Seeded-reverse rows never carry the forward accelerator tag, so their
    // absolute next-row token occupies all low 31 bits.
    assembler.instruction(aarch64_and_low_31(6, 8)?)?;
    assembler.branch_zero_w(6, reverse_done)?;
    assembler.instruction(aarch64_sub_w_imm(6, 6, 1)?)?;
    assembler.instruction(aarch64_add_x_reg(11, 5, 6)?)?;
    assembler.branch(reverse_loop)?;

    assembler.bind(record_start)?;
    if reverse.proves_match && layout.output == OutputContract::Exists {
        assembler.branch(matched)?;
    } else {
        assembler.instruction(aarch64_cmp_x(REVERSE_CURSOR, REVERSE_MINIMUM)?)?;
        assembler.branch_cond(AARCH64_HS, reverse_continue)?;
        assembler.instruction(aarch64_mov_x(REVERSE_MINIMUM, REVERSE_CURSOR)?)?;
        assembler.instruction(aarch64_cmp_x(REVERSE_MINIMUM, 9)?)?;
        assembler.branch_cond(AARCH64_EQ, global_minimum)?;
        assembler.branch(reverse_continue)?;
    }

    assembler.bind(reverse_done)?;
    assembler.instruction(aarch64_mov_x(2, REVERSE_NEXT_BASE)?)?;
    assembler.branch(vector)?;

    assembler.bind(finalize)?;
    assembler.instruction(aarch64_add_x_imm(12, REVERSE_MINIMUM, 1)?)?;
    assembler.instruction(aarch64_cmp_x_imm(12, 0)?)?;
    assembler.branch_cond(AARCH64_EQ, no_match)?;
    assembler.bind(global_minimum)?;
    assembler.instruction(aarch64_mov_x(2, REVERSE_MINIMUM)?)?;
    assembler.branch(done)?;

    assembler.bind(fallback)?;
    assembler.instruction(aarch64_mov_x(2, 9)?)?;
    assembler.bind(done)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompileMode, CompileRequest, Target, compile};

    fn test_layout(
        proves_match: bool,
    ) -> (
        NativeDfaLayout,
        NativeSuffixFilter,
        NativeSeededReverseLayout,
    ) {
        let mut filter = EMPTY_NATIVE_START_FILTER;
        filter.ranges[0] = NativeByteRange {
            start: b'Z',
            end: b'Z',
        };
        filter.range_count = 1;
        filter.candidate_bytes = 1;
        let suffix = NativeSuffixFilter {
            filter,
            vector_filter: None,
            scalar_filter: None,
            minimum_width: 1,
            restart: NativeSuffixRestart::OriginalStart,
            retry: None,
            retry_cost_rejected: false,
            reverse_seed: NativeSuffixReverseSeed::AcceptBoundary,
        };
        let reverse = NativeSeededReverseLayout {
            class_map_offset: 0x100,
            initial_row_offset: 0x200,
            boundary_offset: 1,
            initial_reaches_start: false,
            proves_match,
        };
        let layout = NativeDfaLayout {
            transitions: TransitionLayout::DirectByte,
            cells: NativeCellEncoding::Wide32,
            forward_offset: 0,
            reverse_offset: 0,
            asimd_lane_index_offset: None,
            initial_pending: false,
            initial_terminal: false,
            has_reverse: false,
            exact_span_width: None,
            exact_prefix_match_width: None,
            output: OutputContract::Exists,
            start_filter: None,
            suffix_filter: Some(suffix),
            declined_redundant_root_reverse: false,
            seeded_reverse: Some(reverse),
            loop_skip: None,
            vector_filter: None,
            prefix_filter: None,
            prefix_relation: None,
            prefix_block: None,
            prefix_fast_forward: None,
        };
        (layout, suffix, reverse)
    }

    fn emitted_words(use_asimd: bool, use_asimd_batch: bool, proves_match: bool) -> Vec<u32> {
        let (layout, suffix, reverse) = test_layout(proves_match);
        let mut assembler = Aarch64Assembler::new();
        let no_match = assembler.label().unwrap();
        let matched = assembler.label().unwrap();
        aarch64_emit_seeded_reverse_prepass(
            &mut assembler,
            suffix,
            reverse,
            use_asimd,
            use_asimd_batch,
            true,
            layout,
            no_match,
            matched,
        )
        .unwrap();
        assembler.bind(no_match).unwrap();
        assembler
            .instruction(aarch64_movz_w(0, 0).unwrap())
            .unwrap();
        assembler.bind(matched).unwrap();
        assembler
            .instruction(aarch64_movz_w(0, 1).unwrap())
            .unwrap();
        assembler.instruction(0xd65f_03c0).unwrap();
        assembler
            .finish()
            .unwrap()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn seeded_reverse_uses_exact_class_map_low_31_token_and_runtime_fuel() {
        let words = emitted_words(false, false, false);
        assert!(words.contains(&aarch64_movn_zero_x(REVERSE_MINIMUM).unwrap()));
        assert!(words.contains(&aarch64_mov_x(REVERSE_FUEL, 12).unwrap()));
        assert!(words.contains(&aarch64_sub_x_imm(REVERSE_FUEL, REVERSE_FUEL, 1).unwrap()));
        assert!(words.contains(&aarch64_load_byte_reg(8, 0, REVERSE_CURSOR).unwrap()));
        assert!(words.contains(&aarch64_load_byte_reg(8, REVERSE_CLASS_MAP, 8).unwrap()));
        assert!(words.contains(&aarch64_load_w_uxtw(8, 11, 8).unwrap()));
        assert!(words.contains(&aarch64_and_low_31(6, 8).unwrap()));
        assert!(words.contains(&aarch64_mov_x(2, 9).unwrap()));
    }

    #[test]
    fn seeded_reverse_asimd_batch_reuses_the_general_mandatory_scanner() {
        let words = emitted_words(true, true, false);
        assert!(words.contains(&aarch64_ld1_four_16b(24, 12).unwrap()));
        assert!(
            words.contains(
                &aarch64_movi_16b(AARCH64_STANDALONE_FILTER_FIRST_CONSTANT, b'Z',).unwrap()
            )
        );
        assert!(words.contains(&aarch64_uminv_16b(0, 0).unwrap()));
    }

    #[test]
    fn seeded_reverse_persistent_registers_are_aapcs64_caller_saved() {
        for register in [
            REVERSE_CLASS_MAP,
            REVERSE_FUEL,
            REVERSE_MINIMUM,
            REVERSE_NEXT_BASE,
            REVERSE_CURSOR,
        ] {
            assert!(register <= 17);
            assert_ne!(register, 18);
        }
    }

    #[test]
    fn accept_seeded_exists_emits_the_short_direct_match_path() {
        let ordinary = emitted_words(false, false, false);
        let proving = emitted_words(false, false, true);
        assert!(proving.len() < ordinary.len());
    }

    #[test]
    fn general_accept_and_root_seeded_layouts_reach_the_aarch64_emitter() {
        for (pattern, proves_match) in [("(?s:.+)z", true), ("(?s:.+)MAGIC(?s:.*)", false)] {
            let compiled = compile(
                CompileRequest::new(pattern, Target::aarch64_linux())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Exists),
            )
            .unwrap();
            let layout = build_native_dfa_table_for_architecture(
                compiled.program().native_dfa_view().unwrap(),
                Architecture::Aarch64,
            )
            .unwrap()
            .1;
            let reverse = layout
                .seeded_reverse
                .unwrap_or_else(|| panic!("missing AArch64 seeded reverse for {pattern:?}"));
            assert_eq!(reverse.proves_match, proves_match);

            let words = lower_aarch64_dfa(layout, FeatureSet::EMPTY)
                .unwrap()
                .0
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            let exact_sidecar_lookup = [
                aarch64_load_byte_reg(8, 0, REVERSE_CURSOR).unwrap(),
                aarch64_load_byte_reg(8, REVERSE_CLASS_MAP, 8).unwrap(),
                aarch64_load_w_uxtw(8, 11, 8).unwrap(),
            ];
            assert!(
                words
                    .windows(exact_sidecar_lookup.len())
                    .any(|window| window == exact_sidecar_lookup),
                "AArch64 lowering omitted the exact seeded sidecar lookup for {pattern:?}"
            );
        }
    }
}
