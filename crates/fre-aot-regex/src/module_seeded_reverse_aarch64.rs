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
// scalar and ASIMD scanners. All six registers are AAPCS64 caller-saved; X18
// remains untouched because platforms may reserve it.
const REVERSE_CLASS_MAP: u8 = 10;
pub(super) const REVERSE_FUEL: u8 = 13;
const REVERSE_MINIMUM: u8 = 14;
const REVERSE_NEXT_BASE: u8 = 15;
const REVERSE_CURSOR: u8 = 16;
// X7 is outside the reverse machine's persistent and scalar scratch sets. Its
// mutually exclusive users record either the one-way replacement of projected
// ASIMD constants by the exact relation bank or the bounded exact-only
// follow-ups after a complete-pair false primary.
pub(super) const REVERSE_RELATION_PHASE: u8 = 7;

// Four-vector complete-pair scans carry a wider native body and more hot
// SIMD state than the independently retained one-vector incumbent. Keep the
// incumbent for short calls, where its lower fixed cost dominates, and use
// the batch only once that setup is amortized. This is a runtime input-length
// policy: it does not depend on the authenticated language or observed data.
pub(super) const COMPLETE_PAIR_BATCH_MIN_WINDOW_BYTES_LSL12: u16 = 4;
// Two bounded exact-only follow-ups amortize a proved dense false primary
// without ever turning one observation into an unbounded input policy. A
// sparse false primary therefore adds at most 128 bytes of exact scanning.
pub(super) const COMPLETE_PAIR_FALSE_PRIMARY_FOLLOW_UP_BATCHES: u16 = 2;

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
    complete_span_fill_verifier: Option<NativeCompleteSpanFillExactVerifier>,
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
    let complete_pair_short_vector = assembler.label()?;
    let complete_pair_short_primary_hit = assembler.label()?;
    let complete_pair_short_hit = assembler.label()?;
    let scalar_relation_candidate = assembler.label()?;
    let relation_candidate = assembler.label()?;
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
    let malformed_certificate = reverse.first_endpoint_proves_no_earlier_match
        && (!reverse.proves_match
            || !matches!(suffix.reverse_seed, NativeSuffixReverseSeed::AcceptBoundary));
    let endpoint_without_certificate = layout.output != OutputContract::Exists
        && (!reverse.proves_match || !reverse.first_endpoint_proves_no_earlier_match);
    let malformed_seed = match suffix.reverse_seed {
        NativeSuffixReverseSeed::AcceptBoundary => {
            reverse.boundary_offset != suffix.minimum_width || !reverse.proves_match
        }
        NativeSuffixReverseSeed::RootState(_) => {
            reverse.boundary_offset != 0 || reverse.proves_match
        }
    };
    let unsupported_synchronizing_reverse =
        matches!(suffix.restart, NativeSuffixRestart::Synchronizing { .. })
            && !(layout.output == OutputContract::Exists
                && matches!(suffix.reverse_seed, NativeSuffixReverseSeed::AcceptBoundary)
                && reverse.proves_match
                && reverse.first_endpoint_proves_no_earlier_match);
    if malformed_certificate
        || endpoint_without_certificate
        || malformed_seed
        || unsupported_synchronizing_reverse
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 seeded reverse escaped its graph admission gate",
        ));
    }
    if suffix.retry.is_some() {
        return Err(ObjectError::InvalidModule(
            "AArch64 seeded reverse escaped its graph admission gate",
        ));
    }
    if reverse.complete_pair_relation_handoff_eligible
        && (layout.initial_pending
            || layout.partial.is_some()
            || (layout.output != OutputContract::Exists && !layout.start_scanner_preserves_pending)
            || suffix.minimum_width != 2
            || !matches!(
                suffix.restart,
                NativeSuffixRestart::Bounded { backtrack: 0 }
            )
            || !matches!(suffix.reverse_seed, NativeSuffixReverseSeed::AcceptBoundary)
            || reverse.boundary_offset != suffix.minimum_width
            || suffix.exact_pair_filter.is_some()
            || suffix.vector_filter.is_some()
            || suffix.scalar_filter.is_some()
            || layout.prefix_relation.is_none_or(|relation| {
                relation.context_assertions || relation.vector_plan.is_none()
            }))
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 seeded reverse complete-pair handoff receipt is inconsistent",
        ));
    }
    if let Some(receipt) = reverse.complete_pair_relation_registers
        && !aarch64_complete_pair_relation_register_receipt_is_valid(
            receipt,
            layout,
            use_asimd,
            use_asimd_batch,
            use_exact_asimd_lane,
        )
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 complete-pair relation register receipt is inconsistent",
        ));
    }
    let complete_pair_relation = if reverse.complete_pair_relation_handoff_eligible {
        Some(layout.prefix_relation.ok_or(ObjectError::InvalidModule(
            "AArch64 seeded reverse complete-pair relation is absent",
        ))?)
    } else {
        None
    };
    let complete_pair_vector = complete_pair_relation.and_then(|relation| relation.vector_plan);
    let complete_pair_registers = reverse.complete_pair_relation_registers;
    if use_asimd_batch && !use_asimd {
        return Err(ObjectError::InvalidModule(
            "AArch64 seeded reverse selected an ASIMD batch on a scalar target",
        ));
    }
    let exact_pair_filter = suffix.exact_pair_filter;
    let lazy_vector_filter = exact_pair_filter.is_none().then_some(suffix.vector_filter).flatten();
    let scalar_filter = exact_pair_filter
        .is_none()
        .then_some(suffix.vector_filter.or(suffix.scalar_filter))
        .flatten();
    let maximum_filter_offset = exact_pair_filter.map_or_else(
        || scalar_filter.map_or(filter.scan_offset, NativeVectorFilter::max_scan_offset),
        |_| 1,
    );
    let proven_exists = reverse.proves_match && layout.output == OutputContract::Exists;
    // An Accept seed starts at base + minimum_width. Requiring the last byte
    // before that boundary to be in-bounds makes every reverse load safe.
    let maximum_scan_offset = maximum_filter_offset.max(reverse.boundary_offset.saturating_sub(1));
    let complete_span_fill_verifier = complete_span_fill_verifier
        .map(|verifier| {
            select_complete_span_fill_suffix_verifier(
                layout,
                suffix,
                reverse,
                verifier,
                maximum_scan_offset,
            )
        })
        .transpose()?
        .flatten();
    let exact_pair_primary_cold_filter =
        aarch64_exact_pair_primary_cold_filter(suffix, use_asimd, use_asimd_batch)?;
    let exact_pair_primary_vector = exact_pair_primary_cold_filter
        .map(|_| assembler.label())
        .transpose()?;
    let exact_pair_relation_activate = exact_pair_primary_cold_filter
        .map(|_| assembler.label())
        .transpose()?;
    let exact_pair_primary_single_vector = exact_pair_primary_cold_filter
        .map(|_| assembler.label())
        .transpose()?;
    let exact_pair_primary_scalar = exact_pair_primary_cold_filter
        .map(|_| assembler.label())
        .transpose()?;
    let exact_pair_primary_batch_hit = exact_pair_primary_cold_filter
        .map(|_| assembler.label())
        .transpose()?;
    let exact_pair_primary_single_hit = exact_pair_primary_cold_filter
        .map(|_| assembler.label())
        .transpose()?;
    let exact_pair_primary_candidate = exact_pair_primary_cold_filter
        .map(|_| assembler.label())
        .transpose()?;
    let complete_pair_persistent_batch_hit = complete_pair_registers
        .filter(|receipt| receipt.batch_vectors == 4)
        .map(|_| assembler.label())
        .transpose()?;
    let complete_pair_persistent_relation_batch = complete_pair_registers
        .filter(|receipt| receipt.batch_vectors == 4)
        .map(|_| assembler.label())
        .transpose()?;
    if exact_pair_primary_cold_filter.is_some() && layout.output != OutputContract::Exists {
        return Err(ObjectError::InvalidModule(
            "AArch64 seeded exact-pair primary phase escaped Exists admission",
        ));
    }
    let emit_constants = |assembler: &mut Aarch64Assembler| -> Result<(), ObjectError> {
        if use_asimd {
            if let Some(primary_filter) = exact_pair_primary_cold_filter {
                aarch64_emit_start_filter_constants(
                    assembler,
                    primary_filter,
                    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                )?;
            } else if let Some(pair_filter) = exact_pair_filter {
                aarch64_emit_prefix_relation_constants(assembler, pair_filter.vector_plan)?;
            } else if let Some(vector_filter) = lazy_vector_filter {
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
            } else if complete_pair_registers.is_some() {
                aarch64_emit_start_filter_constants(
                    assembler,
                    filter,
                    AARCH64_COMPLETE_PAIR_PRIMARY_FIRST_CONSTANT,
                )?;
                let relation = complete_pair_vector.ok_or(ObjectError::InvalidModule(
                    "AArch64 persistent complete-pair registers lost their vector plan",
                ))?;
                aarch64_emit_complete_pair_relation_constants(assembler, relation)?;
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
    if !proven_exists {
        assembler.instruction(aarch64_movn_zero_x(REVERSE_MINIMUM)?)?;
    }
    if ENABLE_DEFERRED_SUFFIX_FILTER_CONSTANTS {
        emit_constants(assembler)?;
    }
    if exact_pair_primary_cold_filter.is_some() {
        assembler.instruction(aarch64_movz_w(REVERSE_RELATION_PHASE, 0)?)?;
    }
    // Unlike the ordinary DFA's optional compact/direct layout, the sidecar
    // always owns an independent exact raw-byte class map.
    aarch64_set_table_address(assembler, REVERSE_CLASS_MAP, reverse.class_map_offset)?;

    if let Some(receipt) = complete_pair_registers.filter(|receipt| receipt.batch_vectors == 4) {
        let relation = complete_pair_vector.ok_or(ObjectError::InvalidModule(
            "AArch64 persistent complete-pair batch lost its vector plan",
        ))?;
        assembler.instruction(aarch64_cmp_x_imm_lsl12(
            REVERSE_FUEL,
            COMPLETE_PAIR_BATCH_MIN_WINDOW_BYTES_LSL12,
        )?)?;
        assembler.branch_cond(AARCH64_HS, vector)?;

        // Preserve the exact pre-batch one-vector algorithm for short
        // windows. Its false-primary and false-relation edges rearm this
        // label directly, so a short call cannot drift into the batch loop.
        assembler.bind(complete_pair_short_vector)?;
        assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
        let vector_bytes = u16::from(maximum_scan_offset).checked_add(16).ok_or(
            ObjectError::ArithmeticOverflow("AArch64 complete-pair short filter width"),
        )?;
        assembler.instruction(aarch64_cmp_x_imm(12, vector_bytes)?)?;
        assembler.branch_cond(AARCH64_LO, scalar)?;
        aarch64_emit_start_filter_address(assembler, filter.scan_offset)?;
        assembler.instruction(aarch64_load_q(0, 12)?)?;
        aarch64_emit_start_filter_vector_candidates(
            assembler,
            filter,
            0,
            AARCH64_COMPLETE_PAIR_RELATION_CANDIDATES,
            AARCH64_COMPLETE_PAIR_PRIMARY_FIRST_CONSTANT,
        )?;
        aarch64_emit_candidate_any(assembler, AARCH64_COMPLETE_PAIR_RELATION_CANDIDATES)?;
        assembler.branch_cond(AARCH64_NE, complete_pair_short_primary_hit)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, AARCH64_ASIMD_VECTOR_BYTES)?)?;
        assembler.branch(complete_pair_short_vector)?;

        assembler.bind(complete_pair_short_primary_hit)?;
        aarch64_emit_complete_pair_relation_vector_test(assembler, relation, receipt)?;
        assembler.branch_cond(AARCH64_NE, complete_pair_short_hit)?;
        assembler.instruction(aarch64_add_x_imm(2, 2, AARCH64_ASIMD_VECTOR_BYTES)?)?;
        assembler.branch(complete_pair_short_vector)?;

        assembler.bind(complete_pair_short_hit)?;
        aarch64_emit_first_candidate_lane(assembler, AARCH64_COMPLETE_PAIR_RELATION_CANDIDATES)?;
        assembler.branch(relation_candidate)?;
    }

    let mut batch_first_candidates = None;
    if use_asimd {
        if let Some(primary_filter) = exact_pair_primary_cold_filter {
            let primary_vector = exact_pair_primary_vector.ok_or(ObjectError::InvalidModule(
                "AArch64 seeded exact-pair primary vector label is absent",
            ))?;
            let primary_single_vector = exact_pair_primary_single_vector.ok_or(
                ObjectError::InvalidModule(
                    "AArch64 seeded exact-pair primary single-vector label is absent",
                ),
            )?;
            let primary_scalar = exact_pair_primary_scalar.ok_or(ObjectError::InvalidModule(
                "AArch64 seeded exact-pair primary scalar label is absent",
            ))?;
            let primary_batch_hit = exact_pair_primary_batch_hit.ok_or(
                ObjectError::InvalidModule(
                    "AArch64 seeded exact-pair primary batch-hit label is absent",
                ),
            )?;
            let primary_single_hit = exact_pair_primary_single_hit.ok_or(
                ObjectError::InvalidModule(
                    "AArch64 seeded exact-pair primary single-hit label is absent",
                ),
            )?;
            let primary_candidate = exact_pair_primary_candidate.ok_or(
                ObjectError::InvalidModule(
                    "AArch64 seeded exact-pair primary candidate label is absent",
                ),
            )?;
            let relation_activate =
                exact_pair_relation_activate.ok_or(ObjectError::InvalidModule(
                    "AArch64 seeded exact-pair relation activation label is absent",
                ))?;
            let pair_filter = exact_pair_filter.ok_or(ObjectError::InvalidModule(
                "AArch64 seeded exact-pair primary phase lost its relation",
            ))?;
            assembler.bind(primary_vector)?;
            assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
            let batch_bytes = u16::from(maximum_scan_offset)
                .checked_add(AARCH64_BATCH_BYTES)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 seeded exact-pair primary width",
                ))?;
            assembler.instruction(aarch64_cmp_x_imm(12, batch_bytes)?)?;
            assembler.branch_cond(AARCH64_LO, primary_single_vector)?;
            let primary_candidates = aarch64_emit_start_filter_batch_candidates(
                assembler,
                primary_filter,
                AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
            )?;
            aarch64_emit_candidate_batch_any(assembler, primary_candidates)?;
            assembler.branch_cond(AARCH64_NE, primary_batch_hit)?;
            assembler.instruction(aarch64_add_x_imm(2, 2, AARCH64_BATCH_BYTES)?)?;
            assembler.branch(primary_vector)?;

            assembler.bind(primary_batch_hit)?;
            aarch64_emit_first_candidate_in_batch(assembler, primary_candidates)?;
            assembler.branch(primary_candidate)?;

            assembler.bind(primary_single_vector)?;
            let vector_bytes = u16::from(maximum_scan_offset)
                .checked_add(AARCH64_ASIMD_VECTOR_BYTES)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 seeded exact-pair primary tail width",
                ))?;
            assembler.instruction(aarch64_cmp_x_imm(12, vector_bytes)?)?;
            assembler.branch_cond(AARCH64_LO, primary_scalar)?;
            aarch64_emit_start_filter_address(assembler, primary_filter.scan_offset)?;
            assembler.instruction(aarch64_load_q(0, 12)?)?;
            aarch64_emit_start_filter_vector_candidates(
                assembler,
                primary_filter,
                0,
                24,
                AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
            )?;
            aarch64_emit_candidate_any(assembler, 24)?;
            assembler.branch_cond(AARCH64_NE, primary_single_hit)?;
            assembler.instruction(aarch64_add_x_imm(
                2,
                2,
                AARCH64_ASIMD_VECTOR_BYTES,
            )?)?;
            assembler.branch(primary_vector)?;

            assembler.bind(primary_single_hit)?;
            aarch64_emit_first_candidate_lane(assembler, 24)?;
            assembler.branch(primary_candidate)?;

            assembler.bind(primary_scalar)?;
            aarch64_emit_start_filter_scalar_bound(
                assembler,
                maximum_scan_offset,
                if proven_exists { no_match } else { finalize },
            )?;
            aarch64_emit_start_filter_scalar_candidate(
                assembler,
                primary_filter,
                primary_candidate,
            )?;
            assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
            assembler.branch(primary_scalar)?;

            assembler.bind(primary_candidate)?;
            aarch64_emit_exact_pair_scalar_test(assembler, pair_filter, candidate)?;
            assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
            assembler.branch(relation_activate)?;

            assembler.bind(relation_activate)?;
            assembler.instruction(aarch64_movz_w(REVERSE_RELATION_PHASE, 1)?)?;
            aarch64_emit_prefix_relation_constants(assembler, pair_filter.vector_plan)?;
            assembler.branch(vector)?;
        }
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
            let first_candidates = if let Some(pair_filter) = exact_pair_filter {
                aarch64_emit_prefix_relation_batch_candidates(
                    assembler,
                    pair_filter.vector_plan,
                )?
            } else {
                let first_register = if complete_pair_registers.is_some() {
                    AARCH64_COMPLETE_PAIR_PRIMARY_FIRST_CONSTANT
                } else if lazy_vector_filter.is_some() {
                    AARCH64_VECTOR_FILTER_FIRST_CONSTANT
                } else {
                    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT
                };
                aarch64_emit_start_filter_batch_candidates(assembler, filter, first_register)?
            };
            batch_first_candidates = Some(first_candidates);
            aarch64_emit_candidate_batch_any(assembler, first_candidates)?;
            assembler.branch_cond(
                AARCH64_NE,
                if lazy_vector_filter.is_some() || complete_pair_vector.is_some() {
                    batch_primary_hit
                } else if use_exact_asimd_lane || exact_pair_filter.is_some() {
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
        if let Some(pair_filter) = exact_pair_filter {
            aarch64_emit_prefix_relation_vector_test(assembler, pair_filter.vector_plan)?;
            assembler.branch_cond(AARCH64_NE, single_hit)?;
        } else if lazy_vector_filter.is_some() {
            aarch64_emit_start_filter_address(assembler, filter.scan_offset)?;
            assembler.instruction(aarch64_load_q(0, 12)?)?;
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
            aarch64_emit_start_filter_address(assembler, filter.scan_offset)?;
            assembler.instruction(aarch64_load_q(0, 12)?)?;
            aarch64_emit_start_filter_vector_candidates(
                assembler,
                filter,
                0,
                24,
                if complete_pair_registers.is_some() {
                    AARCH64_COMPLETE_PAIR_PRIMARY_FIRST_CONSTANT
                } else {
                    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT
                },
            )?;
            aarch64_emit_candidate_any(assembler, 24)?;
            assembler.branch_cond(
                AARCH64_NE,
                if complete_pair_vector.is_some() {
                    single_primary_hit
                } else if use_exact_asimd_lane {
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
        } else if let Some(relation) = complete_pair_vector {
            assembler.bind(batch_primary_hit)?;
            if use_asimd_batch {
                if let Some(relation_batch) = complete_pair_persistent_relation_batch {
                    // A primary-hit rejection may run a bounded number of
                    // exact-only batches at following positions. The counter
                    // is live only within that episode; ordinary primary
                    // misses execute the unchanged hot loop.
                    assembler.instruction(aarch64_movz_w(
                        REVERSE_RELATION_PHASE,
                        COMPLETE_PAIR_FALSE_PRIMARY_FOLLOW_UP_BATCHES,
                    )?)?;
                    assembler.bind(relation_batch)?;
                }
                let relation_candidates = if let Some(receipt) = complete_pair_registers {
                    aarch64_emit_complete_pair_relation_batch_candidates(
                        assembler,
                        relation,
                        receipt,
                    )?
                } else {
                    // The legacy primary four-vector load occupies V0..V3,
                    // overlapping the bounded relation-constant bank. Reload
                    // the exact relation only on a primary-hit edge.
                    aarch64_emit_prefix_relation_constants(assembler, relation)?;
                    aarch64_emit_prefix_relation_batch_candidates(assembler, relation)?
                };
                if batch_first_candidates != Some(relation_candidates) {
                    return Err(ObjectError::InvalidModule(
                        "AArch64 complete-pair relation changed its candidate bank",
                    ));
                }
                aarch64_emit_candidate_batch_any(assembler, relation_candidates)?;
                assembler.branch_cond(
                    AARCH64_NE,
                    complete_pair_persistent_batch_hit.unwrap_or(batch_hit),
                )?;
                if complete_pair_registers.is_none() {
                    // Relation masks use V16..V21 as sources and scratch.
                    // Restore the standalone primary constants before
                    // rearming the legacy scan.
                    aarch64_emit_start_filter_constants(
                        assembler,
                        filter,
                        AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                    )?;
                }
                assembler.instruction(aarch64_add_x_imm(2, 2, AARCH64_BATCH_BYTES)?)?;
                if let Some(relation_batch) = complete_pair_persistent_relation_batch {
                    // Dense first-byte decoys alternate primary+exact and
                    // exact-only batches. A sparse false primary can trigger
                    // at most two extra exact batches before the primary
                    // projection is rearmed. Recheck the full +64 bound
                    // before every overlapping final load.
                    assembler.branch_zero_w(REVERSE_RELATION_PHASE, vector)?;
                    assembler.instruction(aarch64_sub_w_imm(
                        REVERSE_RELATION_PHASE,
                        REVERSE_RELATION_PHASE,
                        1,
                    )?)?;
                    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
                    let batch_bytes = u16::from(maximum_scan_offset)
                        .checked_add(AARCH64_BATCH_BYTES)
                        .ok_or(ObjectError::ArithmeticOverflow(
                            "AArch64 complete-pair follow-up batch width",
                        ))?;
                    assembler.instruction(aarch64_cmp_x_imm(12, batch_bytes)?)?;
                    assembler.branch_cond(AARCH64_LO, vector)?;
                    assembler.branch(relation_batch)?;
                } else {
                    assembler.branch(vector)?;
                }
            } else {
                assembler.branch(scalar)?;
            }

            assembler.bind(single_primary_hit)?;
            if let Some(receipt) = complete_pair_registers {
                aarch64_emit_complete_pair_relation_vector_test(assembler, relation, receipt)?;
            } else {
                aarch64_emit_prefix_relation_constants(assembler, relation)?;
                aarch64_emit_prefix_relation_vector_test(assembler, relation)?;
            }
            assembler.branch_cond(AARCH64_NE, single_hit)?;
            if complete_pair_registers.is_none() {
                aarch64_emit_start_filter_constants(
                    assembler,
                    filter,
                    AARCH64_STANDALONE_FILTER_FIRST_CONSTANT,
                )?;
            }
            assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
            assembler.branch(vector)?;
        } else {
            assembler.bind(batch_primary_hit)?;
            assembler.branch(scalar)?;
            assembler.bind(single_primary_hit)?;
            assembler.branch(scalar)?;
        }

        if let Some(persistent_batch_hit) = complete_pair_persistent_batch_hit {
            assembler.bind(persistent_batch_hit)?;
            // The exact relation batch uses V30 for its overlapping second
            // column. Restore the lane-advance immediate only when an exact
            // relation hit will consume it; false batches keep the hot miss
            // edge free of constant rematerialization.
            assembler.instruction(aarch64_movi_16b(30, 16)?)?;
            assembler.branch(batch_hit)?;
        }

        let selected = if exact_pair_filter.is_some()
            || lazy_vector_filter.is_some()
            || suffix.scalar_filter.is_none()
        {
            candidate
        } else {
            scalar_columns
        };
        assembler.bind(batch_hit)?;
        if (use_exact_asimd_lane || exact_pair_filter.is_some())
            && let Some(first_candidates) = batch_first_candidates
        {
            aarch64_emit_first_candidate_in_batch(assembler, first_candidates)?;
            assembler.branch(if complete_pair_vector.is_some() {
                relation_candidate
            } else {
                selected
            })?;
        } else {
            assembler.branch(scalar)?;
        }
        assembler.bind(single_hit)?;
        if use_exact_asimd_lane || exact_pair_filter.is_some() {
            aarch64_emit_first_candidate_lane(assembler, 24)?;
            assembler.branch(if complete_pair_vector.is_some() {
                relation_candidate
            } else {
                selected
            })?;
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
    aarch64_emit_start_filter_scalar_bound(
        assembler,
        maximum_scan_offset,
        if proven_exists { no_match } else { finalize },
    )?;
    if let Some(pair_filter) = exact_pair_filter {
        aarch64_emit_exact_pair_scalar_test(assembler, pair_filter, candidate)?;
    } else {
        aarch64_emit_start_filter_scalar_load(assembler, filter.scan_offset)?;
        let scalar_candidate = if complete_pair_relation.is_some() {
            scalar_relation_candidate
        } else if scalar_filter.is_some() {
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
        if complete_pair_relation.is_some() {
            assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
            assembler.branch(vector)?;
        } else {
            assembler.branch(scalar)?;
        }
    }

    assembler.bind(scalar_relation_candidate)?;
    if let Some(relation) = complete_pair_relation {
        // The canonical 65,536-bit matrix independently authenticates the
        // short scalar tail. A false primary advances the incumbent suffix
        // scanner; an exact pair can safely enter the ordinary forward DFA.
        aarch64_emit_prefix_relation(assembler, relation, scalar_reject)?;
        assembler.branch(relation_candidate)?;
    }

    assembler.bind(relation_candidate)?;
    if complete_pair_relation.is_some() {
        assembler.branch(done)?;
    }

    assembler.bind(candidate)?;
    assembler.instruction(aarch64_add_x_imm(REVERSE_NEXT_BASE, 2, 1)?)?;
    if let Some(verifier) = complete_span_fill_verifier {
        let rejected = assembler.label()?;
        if verifier.candidate_backtrack != 0 {
            assembler.instruction(aarch64_cmp_x(2, 9)?)?;
            assembler.branch_cond(AARCH64_LO, rejected)?;
            assembler.instruction(aarch64_sub_x_reg(12, 2, 9)?)?;
            assembler.instruction(aarch64_cmp_x_imm(
                12,
                u16::from(verifier.candidate_backtrack),
            )?)?;
            assembler.branch_cond(AARCH64_LO, rejected)?;
            assembler.instruction(aarch64_sub_x_imm(
                2,
                2,
                u16::from(verifier.candidate_backtrack),
            )?)?;
        }
        match verifier.exact {
            NativeCompleteSpanFillExactVerifier::Short(short) => {
                aarch64_emit_exact_prefix_short(assembler, short, rejected)?;
            }
            NativeCompleteSpanFillExactVerifier::Words(words) => {
                aarch64_emit_exact_prefix_words(assembler, words, rejected)?;
            }
            NativeCompleteSpanFillExactVerifier::Block16(block) => {
                aarch64_emit_prefix_block(assembler, block, rejected)?;
            }
        }
        aarch64_emit_exact_prefix_match(
            assembler,
            verifier.full_width,
            OutputContract::Span,
            true,
            matched,
        )?;
        assembler.bind(rejected)?;
        assembler.instruction(aarch64_mov_x(2, REVERSE_NEXT_BASE)?)?;
        assembler.branch(vector)?;
    }
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
        if proven_exists {
            assembler.branch_lf_line_success(
                matched,
                NativeDirectSearchLfLineRoute::AcceptSeededReverseInsideMatchOffset,
            )?;
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
    // absolute next-row token occupies all low 31 bits. The accepting edge
    // clears its sole flag before rejoining, so W8 is raw on both inputs.
    assembler.branch_zero_w(8, reverse_done)?;
    assembler.instruction(aarch64_sub_w_imm(6, 8, 1)?)?;
    assembler.instruction(aarch64_add_x_reg(11, 5, 6)?)?;
    assembler.branch(reverse_loop)?;

    assembler.bind(record_start)?;
    if proven_exists {
        assembler.branch_lf_line_success(
            matched,
            NativeDirectSearchLfLineRoute::AcceptSeededReverseInsideMatchOffset,
        )?;
    } else {
        assembler.instruction(aarch64_and_low_31(8, 8)?)?;
        assembler.instruction(aarch64_cmp_x(REVERSE_CURSOR, REVERSE_MINIMUM)?)?;
        assembler.branch_cond(AARCH64_HS, reverse_continue)?;
        assembler.instruction(aarch64_mov_x(REVERSE_MINIMUM, REVERSE_CURSOR)?)?;
        assembler.instruction(aarch64_cmp_x(REVERSE_MINIMUM, 9)?)?;
        assembler.branch_cond(AARCH64_EQ, global_minimum)?;
        assembler.branch(reverse_continue)?;
    }

    assembler.bind(reverse_done)?;
    if !proven_exists && reverse.first_endpoint_proves_no_earlier_match {
        // The reverse trace is complete at this label. A non-sentinel minimum
        // is therefore the globally leftmost start proved by the first
        // terminal-barrier endpoint; endpoint priority remains with the
        // unchanged forward DFA.
        assembler.instruction(aarch64_add_x_imm(12, REVERSE_MINIMUM, 1)?)?;
        assembler.instruction(aarch64_cmp_x_imm(12, 0)?)?;
        assembler.branch_cond(AARCH64_NE, global_minimum)?;
    }
    assembler.instruction(aarch64_mov_x(2, REVERSE_NEXT_BASE)?)?;
    if exact_pair_primary_cold_filter.is_some() {
        let relation_activate =
            exact_pair_relation_activate.ok_or(ObjectError::InvalidModule(
                "AArch64 seeded exact-pair reverse retry lost its activation label",
            ))?;
        assembler.branch_zero_w(REVERSE_RELATION_PHASE, relation_activate)?;
    }
    assembler.branch(vector)?;

    assembler.bind(finalize)?;
    if proven_exists {
        assembler.bind(global_minimum)?;
        assembler.branch(no_match)?;
    } else {
        assembler.instruction(aarch64_add_x_imm(12, REVERSE_MINIMUM, 1)?)?;
        assembler.instruction(aarch64_cmp_x_imm(12, 0)?)?;
        assembler.branch_cond(AARCH64_EQ, no_match)?;
        assembler.bind(global_minimum)?;
        assembler.instruction(aarch64_mov_x(2, REVERSE_MINIMUM)?)?;
        assembler.branch(done)?;
    }

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
        let reverse_seed = if proves_match {
            NativeSuffixReverseSeed::AcceptBoundary
        } else {
            NativeSuffixReverseSeed::RootState(0)
        };
        let restart = if proves_match {
            NativeSuffixRestart::Synchronizing {
                non_reset: EMPTY_NATIVE_RESET_FILTER,
            }
        } else {
            NativeSuffixRestart::OriginalStart
        };
        let suffix = NativeSuffixFilter {
            filter,
            vector_filter: None,
            scalar_filter: None,
            scalar_projection_dependent: false,
            exact_pair_filter: None,
            teddy_portfolio: None,
            minimum_width: 1,
            restart,
            retry: None,
            retry_cost_rejected: false,
            reverse_seed,
        };
        let reverse = NativeSeededReverseLayout {
            class_map_offset: 0x100,
            initial_row_offset: 0x200,
            boundary_offset: u8::from(proves_match),
            initial_reaches_start: false,
            proves_match,
            first_endpoint_proves_no_earlier_match: proves_match,
            complete_pair_relation_handoff_eligible: false,
            complete_pair_relation_registers: None,
        };
        let layout = NativeDfaLayout {
            transitions: TransitionLayout::DirectByte,
            cells: NativeCellEncoding::Wide32,
            bit_slice_domain_count: None,
            forward_offset: 0,
            reverse_offset: 0,
            sparse_boundary_profile: None,
            asimd_lane_index_offset: None,
            initial_pending: false,
            initial_terminal: false,
            start_scanner_preserves_pending: false,
            has_reverse: false,
            partial: None,
            exact_span_width: None,
            exact_prefix_match_width: None,
            output: OutputContract::Exists,
            start_filter: None,
            exact_start_byte_set: None,
            exact_start_storage: None,
            suffix_filter: Some(suffix),
            mandatory_teddy: None,
            declined_redundant_root_reverse: false,
            seeded_reverse: Some(reverse),
            loop_skip: None,
            loop_skip_secondary: None,
            vector_filter: None,
            prefix_filter: None,
            prefix_relation: None,
            prefix_block: None,
            exact_prefix_words: None,
            complete_span_fill_exact_short: None,
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
            None,
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
        assert!(words.contains(&aarch64_and_low_31(8, 8).unwrap()));
        assert!(!words.contains(&aarch64_and_low_31(6, 8).unwrap()));
        assert!(words.contains(&aarch64_sub_w_imm(6, 8, 1).unwrap()));
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
            REVERSE_RELATION_PHASE,
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
        assert!(ordinary.contains(&aarch64_movn_zero_x(REVERSE_MINIMUM).unwrap()));
        assert!(!proving.contains(&aarch64_movn_zero_x(REVERSE_MINIMUM).unwrap()));
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
