//! Authenticated direct exact-finite `SelectedEnd` Teddy leaf.
//!
//! Teddy finds candidate bases and buckets. A bucket-to-source-ordinal mask
//! then drives byte-exact verification in original alternation order. False
//! fingerprints resume scanning at `base + 1`; exhausted long windows return
//! no match directly. A bounded number of failed exact verifications keeps a
//! collision-heavy window from monopolizing the verifier: the wrapper then
//! tail-enters the byte-for-byte incumbent at the still-unresolved candidate.
//! Invalid calls and windows below the fixed setup floor enter it directly.

use core::cmp::Ordering;

use super::*;

const COST_HORIZON_MULTIPLIER: usize = 16;
const EXACT_FINITE_PREFIX_MIN_INPUT_BYTES: usize =
    PARTIAL_DFA_MIN_INPUT_BYTES * COST_HORIZON_MULTIPLIER;
const EXACT_FINITE_TEDDY_GATE_COST_MULTIPLIER: u128 = 4;
const EXACT_FINITE_TEDDY_MATERIAL_GAIN_NUMERATOR: u128 = 7;
const EXACT_FINITE_TEDDY_MATERIAL_GAIN_DENOMINATOR: u128 = 8;
const EXACT_FINITE_LITERAL_BYTE_VERIFICATION_UNITS: u128 = 11;
const EXACT_FINITE_LITERAL_DISPATCH_UNITS: u128 = 8;
const EXACT_FINITE_TEDDY_RUNTIME_VERIFICATION_BUDGET: u16 = 64;
/// Hard peak for the report validator's only transient rebuild allocation.
/// Sixty-four fat slice references occupy 1 KiB on supported 64-bit hosts;
/// the extra headroom keeps this an explicit compiler resource ceiling.
const EXACT_FINITE_TEDDY_VALIDATION_SCRATCH_LIMIT_BYTES: usize = 2 * 1024;

#[derive(Clone, Copy, Debug)]
pub(super) struct ExactFiniteSelectedEndTeddySelection<'a> {
    view: NativeFiniteSelectedEndTeddyView<'a>,
    plan: MandatoryTeddyPlan,
    isa: MandatoryTeddyIsa,
    target: Target,
    selection_horizon_bytes: usize,
    gate_cost_units: u128,
    expected_verification_cost_units: u128,
    full_cost_units: u128,
    incumbent_cost_units: u128,
    root_frequency_units: u16,
    no_candidate_numerator: u128,
    probability_denominator: u128,
}

pub(super) enum ExactFiniteSelectedEndTeddyWrapOutcome {
    Selected {
        lowering: NativeLowering,
        report: ExactFiniteSelectedEndTeddyAotReport,
    },
    ResourceDeclined(NativeLowering),
}

fn root_frequency_and_cardinality(membership: [u64; 4]) -> Option<(u16, u16)> {
    let mut frequency = 0_u16;
    let mut cardinality = 0_u16;
    for byte in u8::MIN..=u8::MAX {
        let index = usize::from(byte);
        if membership[index / 64] & (1_u64 << (index % 64)) == 0 {
            continue;
        }
        cardinality = cardinality.checked_add(1)?;
        frequency = frequency
            .saturating_add(estimated_byte_frequency_units(byte))
            .min(BYTE_FREQUENCY_DENOMINATOR);
    }
    (cardinality != 0 && frequency != 0).then_some((frequency, cardinality))
}

fn candidate_probability_cmp(left: MandatoryTeddyPlan, right: MandatoryTeddyPlan) -> Ordering {
    let left_scaled = u128::from(left.candidate_frequency_upper_bound())
        .saturating_mul(u128::from(right.fingerprint_space()));
    let right_scaled = u128::from(right.candidate_frequency_upper_bound())
        .saturating_mul(u128::from(left.fingerprint_space()));
    left_scaled.cmp(&right_scaled)
}

fn complete_dfa_incumbent_cost_units(
    incumbent: ExactFiniteSelectedEndDfaBaselineReport,
    horizon: u128,
) -> Option<u128> {
    if !complete_dfa_baseline_report_has_valid_geometry(incumbent) {
        return None;
    }
    let per_byte = u128::try_from(incumbent.hot_loads_per_byte)
        .ok()?
        .checked_mul(4)?
        .checked_add(
            u128::try_from(incumbent.hot_branches_per_byte)
                .ok()?
                .checked_mul(3)?,
        )?;
    horizon.checked_mul(per_byte)
}

fn complete_dfa_baseline_report_has_valid_geometry(
    report: ExactFiniteSelectedEndDfaBaselineReport,
) -> bool {
    report.semantic_dfa_sha256 != [0; 32]
        && report.forward_states != 0
        && (1..=256).contains(&report.alphabet_classes)
        && report.transition_cells
            == report
                .forward_states
                .checked_mul(report.alphabet_classes)
                .unwrap_or(0)
        && report.minimum_native_data_bytes != 0
        && report.native_data_bytes >= report.minimum_native_data_bytes
        && report.hot_loads_per_byte != 0
        && report.hot_branches_per_byte != 0
        && !report.has_accelerator
        && report.scanner == StartAccelerator::None
}

fn worst_case_exact_verification_units<B: AsRef<[u8]>>(literals: &[B]) -> Option<u128> {
    literals.iter().try_fold(0_u128, |total, literal| {
        let bytes = u128::try_from(literal.as_ref().len()).ok()?;
        total
            .checked_add(EXACT_FINITE_LITERAL_DISPATCH_UNITS)?
            .checked_add(bytes.checked_mul(EXACT_FINITE_LITERAL_BYTE_VERIFICATION_UNITS)?)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExactFiniteSelectedEndTeddyCosts {
    gate_cost_units: u128,
    expected_verification_cost_units: u128,
    full_cost_units: u128,
    incumbent_cost_units: u128,
    root_frequency_units: u16,
    no_candidate_numerator: u128,
    probability_denominator: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecomputedExactFiniteSelectedEndTeddySelection {
    plan: MandatoryTeddyPlan,
    isa: MandatoryTeddyIsa,
    costs: ExactFiniteSelectedEndTeddyCosts,
}

fn exact_finite_selected_end_teddy_costs<B: AsRef<[u8]>>(
    literals: &[B],
    root_members: [u64; 4],
    plan: MandatoryTeddyPlan,
    isa: MandatoryTeddyIsa,
    incumbent: ExactFiniteSelectedEndDfaBaselineReport,
    selection_horizon_bytes: usize,
) -> Option<ExactFiniteSelectedEndTeddyCosts> {
    let (root_frequency_units, root_cardinality) = root_frequency_and_cardinality(root_members)?;
    let horizon = u128::try_from(selection_horizon_bytes).ok()?;
    let candidate_budget = dynamic_correlated_prefix_candidate_budget(
        horizon,
        plan.candidate_frequency_upper_bound(),
        plan.fingerprint_space(),
        plan.candidate_fingerprint_upper_bound(),
        plan.literal_count(),
    );
    let (no_candidate_numerator, probability_denominator) = candidate_budget?;
    let tier = mandatory_teddy::tier_costs(plan, isa)?;
    let block_bytes = u128::from(tier.block_bytes);
    let scan_blocks = horizon
        .checked_add(block_bytes.checked_sub(1)?)?
        .checked_div(block_bytes)?;
    let auxiliary_bytes = usize::from(isa == MandatoryTeddyIsa::Aarch64Asimd)
        .checked_mul(AARCH64_FIRST_LANE_INDEX.len())?;
    let table_bytes = tier.table_bytes.checked_add(auxiliary_bytes)?;
    let table_cache_lines = u128::try_from(table_bytes.div_ceil(64)).ok()?;
    let gate_cost_units = scan_blocks
        .checked_mul(u128::from(tier.scan_instruction_units))?
        .checked_add(table_cache_lines)?;
    let per_byte_scan_units = u128::from(tier.scan_instruction_units)
        .checked_add(block_bytes.checked_sub(1)?)?
        .checked_div(block_bytes)?
        .max(1);
    let dynamic_profitable = dynamic_correlated_prefix_is_profitable(
        gate_cost_units,
        horizon,
        no_candidate_numerator,
        probability_denominator,
        u128::from(plan.candidate_frequency_upper_bound()),
        u128::from(root_frequency_units),
        root_cardinality,
        per_byte_scan_units,
    )?;
    if !dynamic_profitable {
        return None;
    }

    let expected_candidate_numerator =
        probability_denominator.checked_sub(no_candidate_numerator)?;
    let verification_units = worst_case_exact_verification_units(literals)?;
    let expected_verification_cost_units = verification_units
        .checked_mul(expected_candidate_numerator)?
        .checked_add(probability_denominator.checked_sub(1)?)?
        .checked_div(probability_denominator)?;
    let full_cost_units = gate_cost_units
        .checked_mul(EXACT_FINITE_TEDDY_GATE_COST_MULTIPLIER)?
        .checked_add(expected_verification_cost_units)?;
    let incumbent_cost_units = complete_dfa_incumbent_cost_units(incumbent, horizon)?;
    if full_cost_units.checked_mul(EXACT_FINITE_TEDDY_MATERIAL_GAIN_DENOMINATOR)?
        > incumbent_cost_units.checked_mul(EXACT_FINITE_TEDDY_MATERIAL_GAIN_NUMERATOR)?
    {
        return None;
    }
    Some(ExactFiniteSelectedEndTeddyCosts {
        gate_cost_units,
        expected_verification_cost_units,
        full_cost_units,
        incumbent_cost_units,
        root_frequency_units,
        no_candidate_numerator,
        probability_denominator,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the validator rebuilds every selection input from literal bytes"
)]
fn recompute_exact_finite_selected_end_teddy_selection<B: AsRef<[u8]>>(
    literals: &[B],
    portfolio: MandatoryTeddyPortfolio,
    minimum_width: u32,
    root_members: [u64; 4],
    target: Target,
    incumbent: ExactFiniteSelectedEndDfaBaselineReport,
    selection_horizon_bytes: usize,
) -> Option<RecomputedExactFiniteSelectedEndTeddySelection> {
    let isa = native_mandatory_teddy_isa(target)?;
    let literal_count = u16::try_from(literals.len()).ok()?;
    let mut selected = None::<RecomputedExactFiniteSelectedEndTeddySelection>;
    for &plan in portfolio.plans() {
        if plan.bank_count() != 1
            || !(3..=4).contains(&plan.columns())
            || u32::from(plan.columns()) > minimum_width
            || plan.literal_count() != literal_count
        {
            continue;
        }
        let Some(costs) = exact_finite_selected_end_teddy_costs(
            literals,
            root_members,
            plan,
            isa,
            incumbent,
            selection_horizon_bytes,
        ) else {
            continue;
        };
        let candidate = RecomputedExactFiniteSelectedEndTeddySelection { plan, isa, costs };
        let replace = selected.is_none_or(|current| {
            candidate
                .costs
                .full_cost_units
                .cmp(&current.costs.full_cost_units)
                .then_with(|| candidate_probability_cmp(candidate.plan, current.plan))
                .then_with(|| {
                    candidate
                        .costs
                        .gate_cost_units
                        .cmp(&current.costs.gate_cost_units)
                })
                .then_with(|| current.plan.columns().cmp(&candidate.plan.columns()))
                == Ordering::Less
        });
        if replace {
            selected = Some(candidate);
        }
    }
    selected
}

/// Select solely from authenticated finite-language dimensions, the retained
/// complete semantic-DFA incumbent and target features.
pub(super) fn select_exact_finite_selected_end_teddy<'a>(
    view: NativeFiniteSelectedEndTeddyView<'a>,
    target: Target,
    incumbent: ExactFiniteSelectedEndDfaBaselineReport,
) -> Option<ExactFiniteSelectedEndTeddySelection<'a>> {
    let selection_horizon_bytes =
        PARTIAL_DFA_MIN_INPUT_BYTES.checked_mul(COST_HORIZON_MULTIPLIER)?;
    if !complete_dfa_baseline_report_has_valid_geometry(incumbent) {
        return None;
    }
    let selected = recompute_exact_finite_selected_end_teddy_selection(
        view.literals(),
        view.portfolio(),
        view.minimum_width(),
        view.root_members(),
        target,
        incumbent,
        selection_horizon_bytes,
    )?;
    Some(ExactFiniteSelectedEndTeddySelection {
        view,
        plan: selected.plan,
        isa: selected.isa,
        target,
        selection_horizon_bytes,
        gate_cost_units: selected.costs.gate_cost_units,
        expected_verification_cost_units: selected.costs.expected_verification_cost_units,
        full_cost_units: selected.costs.full_cost_units,
        incumbent_cost_units: selected.costs.incumbent_cost_units,
        root_frequency_units: selected.costs.root_frequency_units,
        no_candidate_numerator: selected.costs.no_candidate_numerator,
        probability_denominator: selected.costs.probability_denominator,
    })
}

fn report_plan_digest(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    data: &[u8],
) -> Option<[u8; 32]> {
    let table = data.get(
        usize::try_from(report.table_base).ok()?..usize::try_from(report.literal_bytes_end).ok()?,
    )?;
    let mut digest = Sha256::new();
    digest.update(report.artifact_identity);
    digest.update([match report.output {
        OutputContract::Exists => 0,
        OutputContract::SelectedEnd => 1,
        OutputContract::Span => 2,
    }]);
    digest.update(report.literal_sha256);
    digest.update(report.source_count.to_le_bytes());
    digest.update(u64::try_from(report.source_bytes).ok()?.to_le_bytes());
    digest.update(report.minimum_width.to_le_bytes());
    digest.update(report.maximum_width.to_le_bytes());
    for word in report.root_members {
        digest.update(word.to_le_bytes());
    }
    digest.update([report.columns, report.bucket_count]);
    digest.update(report.literal_count.to_le_bytes());
    digest.update(report.candidate_fingerprint_upper_bound.to_le_bytes());
    digest.update(report.candidate_frequency_upper_bound.to_le_bytes());
    digest.update(report.fingerprint_space.to_le_bytes());
    digest.update(report.plan_scan_instruction_units.to_le_bytes());
    digest.update(report.emitted_scan_instruction_units.to_le_bytes());
    digest.update(report.guaranteed_vector_bytes.to_le_bytes());
    digest.update(u64::try_from(report.gate_table_bytes).ok()?.to_le_bytes());
    digest.update([match report.selected_target_tier {
        ExactFiniteSelectedEndTeddyAotTargetTier::X86Avx2 => 0,
        ExactFiniteSelectedEndTeddyAotTargetTier::X86Avx512Bw => 1,
        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Asimd => 2,
        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve => 3,
        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve2 => 4,
    }]);
    digest.update([match report.emitted_isa {
        ExactFiniteSelectedEndTeddyAotIsa::X86Avx2 => 0,
        ExactFiniteSelectedEndTeddyAotIsa::Aarch64Asimd => 1,
        ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve => 2,
    }]);
    digest.update([match report.target.architecture {
        Architecture::X86_64 => 0,
        Architecture::Aarch64 => 1,
    }]);
    digest.update([match report.target.operating_system {
        OperatingSystem::Linux => 0,
        OperatingSystem::Macos => 1,
    }]);
    digest.update([match report.target.abi {
        CallAbi::SystemV => 0,
        CallAbi::Aapcs64 => 1,
    }]);
    digest.update(report.target.features.bits().to_le_bytes());
    let baseline = report.incumbent_complete_dfa;
    digest.update(baseline.semantic_dfa_sha256);
    digest.update(u64::try_from(baseline.forward_states).ok()?.to_le_bytes());
    digest.update(u64::try_from(baseline.alphabet_classes).ok()?.to_le_bytes());
    digest.update(u64::try_from(baseline.transition_cells).ok()?.to_le_bytes());
    digest.update(
        u64::try_from(baseline.minimum_native_data_bytes)
            .ok()?
            .to_le_bytes(),
    );
    digest.update(
        u64::try_from(baseline.native_data_bytes)
            .ok()?
            .to_le_bytes(),
    );
    digest.update(
        u64::try_from(baseline.hot_loads_per_byte)
            .ok()?
            .to_le_bytes(),
    );
    digest.update(
        u64::try_from(baseline.hot_branches_per_byte)
            .ok()?
            .to_le_bytes(),
    );
    digest.update([u8::from(baseline.has_accelerator)]);
    digest.update([start_accelerator_tag(baseline.scanner)]);
    digest.update(u64::try_from(report.input_floor_bytes).ok()?.to_le_bytes());
    digest.update(
        u64::try_from(report.selection_horizon_bytes)
            .ok()?
            .to_le_bytes(),
    );
    digest.update(report.selection_gate_cost_units.to_le_bytes());
    digest.update(
        report
            .selection_expected_verification_cost_units
            .to_le_bytes(),
    );
    digest.update(report.selection_full_cost_units.to_le_bytes());
    digest.update(report.selection_incumbent_cost_units.to_le_bytes());
    digest.update(report.selection_root_frequency_units.to_le_bytes());
    digest.update(report.selection_no_candidate_numerator.to_le_bytes());
    digest.update(report.selection_probability_denominator.to_le_bytes());
    digest.update(report.runtime_verification_budget.to_le_bytes());
    digest.update(report.table_base.to_le_bytes());
    digest.update(report.table_end.to_le_bytes());
    digest.update(report.bucket_ordinal_masks_offset.to_le_bytes());
    digest.update(report.literal_descriptors_offset.to_le_bytes());
    digest.update(report.literal_bytes_offset.to_le_bytes());
    digest.update(report.literal_bytes_end.to_le_bytes());
    digest.update(
        u64::try_from(report.incumbent_data_bytes)
            .ok()?
            .to_le_bytes(),
    );
    digest.update(report.incumbent_data_sha256);
    digest.update(report.incumbent_relocations_sha256);
    digest.update(
        u64::try_from(report.incumbent_relocation_count)
            .ok()?
            .to_le_bytes(),
    );
    digest.update(table);
    Some(digest.finalize().into())
}

pub(super) fn relocation_digest(relocations: &[ModuleRelocation]) -> Option<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(u64::try_from(relocations.len()).ok()?.to_le_bytes());
    for relocation in relocations {
        digest.update(u64::try_from(relocation.section).ok()?.to_le_bytes());
        digest.update(relocation.offset.to_le_bytes());
        digest.update([match relocation.kind {
            RelocationKind::X86PcRelative32 => 0,
            RelocationKind::X86PltRelative32 => 1,
            RelocationKind::Aarch64Page21 => 2,
            RelocationKind::Aarch64PageOff12 => 3,
            RelocationKind::Aarch64Branch26 => 4,
        }]);
        digest.update(u64::try_from(relocation.symbol).ok()?.to_le_bytes());
        digest.update(relocation.addend.to_le_bytes());
    }
    Some(digest.finalize().into())
}

const fn report_target_tier(isa: MandatoryTeddyIsa) -> ExactFiniteSelectedEndTeddyAotTargetTier {
    match isa {
        MandatoryTeddyIsa::X86Avx2 => ExactFiniteSelectedEndTeddyAotTargetTier::X86Avx2,
        MandatoryTeddyIsa::X86Avx512Bw => ExactFiniteSelectedEndTeddyAotTargetTier::X86Avx512Bw,
        MandatoryTeddyIsa::Aarch64Asimd => ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Asimd,
        MandatoryTeddyIsa::Aarch64Sve => ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve,
        MandatoryTeddyIsa::Aarch64Sve2 => ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve2,
    }
}

const fn mandatory_isa_for_target_tier(
    tier: ExactFiniteSelectedEndTeddyAotTargetTier,
) -> MandatoryTeddyIsa {
    match tier {
        ExactFiniteSelectedEndTeddyAotTargetTier::X86Avx2 => MandatoryTeddyIsa::X86Avx2,
        ExactFiniteSelectedEndTeddyAotTargetTier::X86Avx512Bw => MandatoryTeddyIsa::X86Avx512Bw,
        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Asimd => MandatoryTeddyIsa::Aarch64Asimd,
        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve => MandatoryTeddyIsa::Aarch64Sve,
        ExactFiniteSelectedEndTeddyAotTargetTier::Aarch64Sve2 => MandatoryTeddyIsa::Aarch64Sve2,
    }
}

const fn report_isa(isa: MandatoryTeddyIsa) -> ExactFiniteSelectedEndTeddyAotIsa {
    match isa {
        MandatoryTeddyIsa::X86Avx2 | MandatoryTeddyIsa::X86Avx512Bw => {
            ExactFiniteSelectedEndTeddyAotIsa::X86Avx2
        }
        MandatoryTeddyIsa::Aarch64Asimd => ExactFiniteSelectedEndTeddyAotIsa::Aarch64Asimd,
        MandatoryTeddyIsa::Aarch64Sve | MandatoryTeddyIsa::Aarch64Sve2 => {
            ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve
        }
    }
}

const fn report_scanner(isa: MandatoryTeddyIsa) -> StartAccelerator {
    match report_isa(isa) {
        ExactFiniteSelectedEndTeddyAotIsa::X86Avx2 => StartAccelerator::X86Avx2,
        ExactFiniteSelectedEndTeddyAotIsa::Aarch64Asimd => StartAccelerator::Aarch64Asimd,
        ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve => StartAccelerator::Aarch64Sve,
    }
}

fn append_aarch64_lane_index_strict(
    data: &mut Vec<u8>,
    maximum_data_bytes: usize,
) -> Result<Option<u32>, ObjectError> {
    let alignment = AARCH64_FIRST_LANE_INDEX.len();
    let aligned = data
        .len()
        .checked_add(alignment.checked_sub(1).ok_or(ObjectError::InvalidModule(
            "AArch64 exact finite SelectedEnd Teddy lane alignment",
        ))?)
        .ok_or(ObjectError::ArithmeticOverflow(
            "AArch64 exact finite SelectedEnd Teddy lane alignment",
        ))?
        & !(alignment - 1);
    let end = aligned.checked_add(AARCH64_FIRST_LANE_INDEX.len()).ok_or(
        ObjectError::ArithmeticOverflow("AArch64 exact finite SelectedEnd Teddy lane extent"),
    )?;
    if end > maximum_data_bytes || u32::try_from(aligned).is_err() {
        return Ok(None);
    }
    let additional = end
        .checked_sub(data.len())
        .ok_or(ObjectError::ArithmeticOverflow(
            "AArch64 exact finite SelectedEnd Teddy lane reservation",
        ))?;
    data.try_reserve_exact(additional)
        .map_err(|_| ObjectError::Allocation("exact finite SelectedEnd Teddy lane table"))?;
    data.resize(aligned, 0);
    data.extend_from_slice(&AARCH64_FIRST_LANE_INDEX);
    Ok(u32::try_from(aligned).ok())
}

#[derive(Clone, Copy, Debug)]
struct ExactFiniteSelectedEndTeddyDataLayout {
    teddy: NativeMandatoryTeddyLayout,
    bucket_ordinal_masks_offset: u32,
    literal_descriptors_offset: u32,
    literal_bytes_offset: u32,
    literal_bytes_end: u32,
    literal_count: u16,
}

fn exact_finite_selected_end_teddy_required_data_bytes(
    selection: ExactFiniteSelectedEndTeddySelection<'_>,
    incumbent_data_bytes: usize,
) -> Result<usize, ObjectError> {
    let tier = mandatory_teddy::tier_costs(selection.plan, selection.isa).ok_or(
        ObjectError::InvalidModule("exact finite SelectedEnd Teddy target tier costs"),
    )?;
    let alignment = match selection.target.architecture {
        Architecture::X86_64 => X86_MANDATORY_TEDDY_ALIGNMENT,
        Architecture::Aarch64 => AARCH64_MANDATORY_TEDDY_ALIGNMENT,
    };
    let table_base = incumbent_data_bytes
        .checked_add(alignment.checked_sub(1).ok_or(ObjectError::InvalidModule(
            "exact finite SelectedEnd Teddy table alignment",
        ))?)
        .ok_or(ObjectError::ArithmeticOverflow(
            "exact finite SelectedEnd Teddy table alignment",
        ))?
        & !(alignment - 1);
    let table_end =
        table_base
            .checked_add(tier.table_bytes)
            .ok_or(ObjectError::ArithmeticOverflow(
                "exact finite SelectedEnd Teddy table extent",
            ))?;
    match selection.target.architecture {
        Architecture::X86_64 => {
            let last_table_offset = table_end
                .checked_sub(X86_MANDATORY_TEDDY_NIBBLE_MASK_BYTES)
                .ok_or(ObjectError::InvalidModule(
                    "exact finite SelectedEnd Teddy x86 table extent",
                ))?;
            if i32::try_from(table_base).is_err() || i32::try_from(last_table_offset).is_err() {
                return Err(ObjectError::InvalidModule(
                    "exact finite SelectedEnd Teddy x86 table address exceeds disp32",
                ));
            }
        }
        Architecture::Aarch64 => {
            u32::try_from(table_end).map_err(|_| {
                ObjectError::InvalidModule(
                    "exact finite SelectedEnd Teddy AArch64 table address exceeds u32",
                )
            })?;
        }
    }
    let after_lane = if selection.isa == MandatoryTeddyIsa::Aarch64Asimd {
        let alignment = AARCH64_FIRST_LANE_INDEX.len();
        let lane_base = table_end
            .checked_add(alignment.checked_sub(1).ok_or(ObjectError::InvalidModule(
                "exact finite SelectedEnd Teddy lane alignment",
            ))?)
            .ok_or(ObjectError::ArithmeticOverflow(
                "exact finite SelectedEnd Teddy lane alignment",
            ))?
            & !(alignment - 1);
        u32::try_from(lane_base).map_err(|_| {
            ObjectError::InvalidModule("exact finite SelectedEnd Teddy lane address exceeds u32")
        })?;
        lane_base
            .checked_add(AARCH64_FIRST_LANE_INDEX.len())
            .ok_or(ObjectError::ArithmeticOverflow(
                "exact finite SelectedEnd Teddy lane extent",
            ))?
    } else {
        table_end
    };
    let masks = after_lane
        .checked_add(7)
        .ok_or(ObjectError::ArithmeticOverflow(
            "exact finite SelectedEnd Teddy verifier alignment",
        ))?
        & !7;
    let descriptors = masks
        .checked_add(8 * core::mem::size_of::<u64>())
        .and_then(|end| end.checked_add(selection.view.literals().len().checked_mul(8)?))
        .ok_or(ObjectError::ArithmeticOverflow(
            "exact finite SelectedEnd Teddy verifier descriptors",
        ))?;
    let end = descriptors
        .checked_add(selection.view.total_source_bytes())
        .ok_or(ObjectError::ArithmeticOverflow(
            "exact finite SelectedEnd Teddy verifier literals",
        ))?;
    for offset in [table_base, table_end, masks, descriptors, end] {
        u32::try_from(offset).map_err(|_| {
            ObjectError::InvalidModule(
                "exact finite SelectedEnd Teddy native data address exceeds u32",
            )
        })?;
    }
    Ok(end)
}

fn append_exact_verifier_data(
    data: &mut Vec<u8>,
    view: NativeFiniteSelectedEndTeddyView<'_>,
    teddy: NativeMandatoryTeddyLayout,
    maximum_data_bytes: usize,
) -> Result<Option<ExactFiniteSelectedEndTeddyDataLayout>, ObjectError> {
    let literals = view.literals();
    let assignments = mandatory_teddy::exact_plan_assignments(literals, teddy.plan).ok_or(
        ObjectError::InvalidModule(
            "exact finite SelectedEnd Teddy assignments do not authenticate",
        ),
    )?;
    if !(4..=64).contains(&literals.len())
        || assignments.as_slice().len() != literals.len()
        || teddy.plan.bank_count() != 1
        || teddy.plan.bucket_count() > 8
    {
        return Err(ObjectError::InvalidModule(
            "exact finite SelectedEnd Teddy verifier geometry",
        ));
    }

    let aligned = data
        .len()
        .checked_add(7)
        .ok_or(ObjectError::ArithmeticOverflow(
            "exact finite SelectedEnd Teddy verifier alignment",
        ))?
        & !7;
    let masks_end = aligned.checked_add(8 * core::mem::size_of::<u64>()).ok_or(
        ObjectError::ArithmeticOverflow("exact finite SelectedEnd Teddy bucket masks"),
    )?;
    let descriptors_end = literals
        .len()
        .checked_mul(8)
        .and_then(|bytes| masks_end.checked_add(bytes))
        .ok_or(ObjectError::ArithmeticOverflow(
            "exact finite SelectedEnd Teddy descriptors",
        ))?;
    let literal_bytes_end = descriptors_end
        .checked_add(view.total_source_bytes())
        .ok_or(ObjectError::ArithmeticOverflow(
            "exact finite SelectedEnd Teddy literals",
        ))?;
    if literal_bytes_end > maximum_data_bytes
        || u32::try_from(aligned).is_err()
        || u32::try_from(masks_end).is_err()
        || u32::try_from(descriptors_end).is_err()
        || u32::try_from(literal_bytes_end).is_err()
    {
        return Ok(None);
    }
    let additional =
        literal_bytes_end
            .checked_sub(data.len())
            .ok_or(ObjectError::ArithmeticOverflow(
                "exact finite SelectedEnd Teddy reservation",
            ))?;
    data.try_reserve_exact(additional)
        .map_err(|_| ObjectError::Allocation("exact finite SelectedEnd Teddy verifier data"))?;

    let mut bucket_ordinal_masks = [0_u64; 8];
    for (ordinal, &bucket) in assignments.as_slice().iter().enumerate() {
        let bucket = usize::from(bucket);
        if bucket >= usize::from(teddy.plan.bucket_count()) {
            return Err(ObjectError::InvalidModule(
                "exact finite SelectedEnd Teddy assignment escaped bucket bank",
            ));
        }
        bucket_ordinal_masks[bucket] |= 1_u64
            .checked_shl(u32::try_from(ordinal).map_err(|_| {
                ObjectError::ArithmeticOverflow("exact finite SelectedEnd Teddy source ordinal")
            })?)
            .ok_or(ObjectError::ArithmeticOverflow(
                "exact finite SelectedEnd Teddy source mask",
            ))?;
    }

    data.resize(aligned, 0);
    for mask in bucket_ordinal_masks {
        data.extend_from_slice(&mask.to_le_bytes());
    }
    let mut literal_offset = descriptors_end;
    for literal in literals {
        data.extend_from_slice(
            &u32::try_from(literal_offset)
                .map_err(|_| {
                    ObjectError::ArithmeticOverflow("exact finite SelectedEnd Teddy literal offset")
                })?
                .to_le_bytes(),
        );
        data.extend_from_slice(
            &u32::try_from(literal.len())
                .map_err(|_| {
                    ObjectError::ArithmeticOverflow("exact finite SelectedEnd Teddy literal width")
                })?
                .to_le_bytes(),
        );
        literal_offset =
            literal_offset
                .checked_add(literal.len())
                .ok_or(ObjectError::ArithmeticOverflow(
                    "exact finite SelectedEnd Teddy literal cursor",
                ))?;
    }
    for literal in literals {
        data.extend_from_slice(literal);
    }
    if data.len() != literal_bytes_end || literal_offset != literal_bytes_end {
        return Err(ObjectError::InvalidModule(
            "exact finite SelectedEnd Teddy verifier extent",
        ));
    }
    Ok(Some(ExactFiniteSelectedEndTeddyDataLayout {
        teddy,
        bucket_ordinal_masks_offset: u32::try_from(aligned).map_err(|_| {
            ObjectError::ArithmeticOverflow("exact finite SelectedEnd Teddy masks offset")
        })?,
        literal_descriptors_offset: u32::try_from(masks_end).map_err(|_| {
            ObjectError::ArithmeticOverflow("exact finite SelectedEnd Teddy descriptors offset")
        })?,
        literal_bytes_offset: u32::try_from(descriptors_end).map_err(|_| {
            ObjectError::ArithmeticOverflow("exact finite SelectedEnd Teddy literal base")
        })?,
        literal_bytes_end: u32::try_from(literal_bytes_end).map_err(|_| {
            ObjectError::ArithmeticOverflow("exact finite SelectedEnd Teddy literal end")
        })?,
        literal_count: u16::try_from(literals.len()).map_err(|_| {
            ObjectError::ArithmeticOverflow("exact finite SelectedEnd Teddy literal count")
        })?,
    }))
}

fn checked_rebase_relocations(
    relocations: Vec<ModuleRelocation>,
    original_code_bytes: usize,
    code_offset: usize,
) -> Result<Vec<ModuleRelocation>, ObjectError> {
    let mut rebased = Vec::new();
    rebased
        .try_reserve_exact(relocations.len())
        .map_err(|_| ObjectError::Allocation("exact finite SelectedEnd Teddy relocations"))?;
    for mut relocation in relocations {
        if relocation.section != TEXT_SECTION {
            return Err(ObjectError::InvalidModule(
                "exact finite SelectedEnd Teddy incumbent has a non-text relocation",
            ));
        }
        let old = usize::try_from(relocation.offset).map_err(|_| {
            ObjectError::ArithmeticOverflow("exact finite SelectedEnd Teddy incumbent relocation")
        })?;
        if old >= original_code_bytes {
            return Err(ObjectError::InvalidModule(
                "exact finite SelectedEnd Teddy incumbent relocation escaped code",
            ));
        }
        let offset = code_offset
            .checked_add(old)
            .ok_or(ObjectError::ArithmeticOverflow(
                "exact finite SelectedEnd Teddy rebased relocation",
            ))?;
        relocation.offset = u64::try_from(offset).map_err(|_| {
            ObjectError::ArithmeticOverflow("exact finite SelectedEnd Teddy rebased relocation")
        })?;
        rebased.push(relocation);
    }
    Ok(rebased)
}

fn lower_x86_wrapper(
    incumbent_code: &[u8],
    layout: ExactFiniteSelectedEndTeddyDataLayout,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>, usize), ObjectError> {
    let teddy = layout.teddy;
    if incumbent_code.is_empty()
        || layout.literal_count != teddy.plan.literal_count()
        || !matches!(
            teddy.isa,
            MandatoryTeddyIsa::X86Avx2 | MandatoryTeddyIsa::X86Avx512Bw
        )
    {
        return Err(ObjectError::InvalidModule(
            "x86 exact finite SelectedEnd Teddy wrapper has invalid inputs",
        ));
    }
    let mut assembler = X86Assembler::new();
    let vector = assembler.label()?;
    let scalar = assembler.label()?;
    let vector_candidate = assembler.label()?;
    let candidate = assembler.label()?;
    let false_candidate = assembler.label()?;
    let retry_base = assembler.label()?;
    let next_ordinal = assembler.label()?;
    let exact_loop = assembler.label()?;
    let runtime_fallback = assembler.label()?;
    let matched = assembler.label()?;
    let exhausted = assembler.label()?;
    let returned = assembler.label()?;
    let tail = assembler.label()?;

    // The wrapper performs no source read before the incumbent's own public
    // ABI has been proved valid. Invalid and short calls enter the incumbent
    // with byte-for-byte untouched public arguments.
    x86_emit_public_search_abi_validation(&mut assembler, tail)?;
    assembler.instruction(&[0x48, 0x89, 0xc8])?; // remaining = end
    assembler.instruction(&[0x48, 0x29, 0xd0])?; // remaining -= start
    let floor = u32::try_from(EXACT_FINITE_PREFIX_MIN_INPUT_BYTES).map_err(|_| {
        ObjectError::ArithmeticOverflow("x86 exact finite SelectedEnd Teddy input floor")
    })?;
    let mut compare_floor = vec![0x48, 0x3d];
    compare_floor.extend_from_slice(&floor.to_le_bytes());
    assembler.instruction(&compare_floor)?;
    assembler.branch(&[0x0f, 0x82], tail)?;

    // Preserve public arguments needed by the bounded-verification fallback,
    // plus the callee-saved counter and end/result registers used by the leaf.
    assembler.instruction(&[0x41, 0x54])?; // push r12
    assembler.instruction(&[0x53])?; // push rbx
    assembler.instruction(&[0x41, 0x55])?; // push r13
    assembler.instruction(&[0x41, 0x56])?; // push r14
    assembler.instruction(&[0x49, 0x89, 0xf4])?; // r12 = public length
    assembler.instruction(&[0x49, 0x89, 0xcd])?; // r13 = end
    assembler.instruction(&[0x4d, 0x89, 0xc6])?; // r14 = result
    let mut verification_budget = vec![0xbb]; // mov imm32, ebx
    verification_budget.extend_from_slice(
        &u32::from(EXACT_FINITE_TEDDY_RUNTIME_VERIFICATION_BUDGET).to_le_bytes(),
    );
    assembler.instruction(&verification_budget)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.instruction(&[0x49, 0x89, 0x00])?;
    assembler.instruction(&[0x49, 0x89, 0x40, 0x08])?;

    assembler.instruction(&[0x4c, 0x8d, 0x0d])?; // lea program(%rip), r9
    let program_displacement = assembler.label()?;
    assembler.bind(program_displacement)?;
    push_bytes(&mut assembler.code, &[0; 4])?;
    x86_emit_mandatory_teddy_constants(&mut assembler, teddy)?;

    assembler.bind(vector)?;
    assembler.instruction(&[0x48, 0x89, 0xc8])?;
    assembler.instruction(&[0x48, 0x29, 0xd0])?;
    let vector_bytes = u32::from(teddy.plan.columns())
        .checked_sub(1)
        .and_then(|last| last.checked_add(u32::from(teddy.vector_bytes)))
        .ok_or(ObjectError::ArithmeticOverflow(
            "x86 exact finite SelectedEnd Teddy vector bound",
        ))?;
    let mut compare_vector = vec![0x48, 0x3d];
    compare_vector.extend_from_slice(&vector_bytes.to_le_bytes());
    assembler.instruction(&compare_vector)?;
    assembler.branch(&[0x0f, 0x82], scalar)?;
    x86_emit_mandatory_teddy_avx2_candidates(&mut assembler, teddy)?;
    assembler.instruction(&[0x85, 0xc0])?;
    assembler.branch(&[0x0f, 0x85], vector_candidate)?;
    assembler.instruction(&[0x48, 0x83, 0xc2, teddy.vector_bytes])?;
    assembler.branch(&[0xe9], vector)?;

    assembler.bind(scalar)?;
    let maximum_offset = teddy
        .plan
        .columns()
        .checked_sub(1)
        .ok_or(ObjectError::InvalidModule(
            "x86 exact finite SelectedEnd Teddy has no columns",
        ))?;
    x86_emit_start_filter_scalar_bound(&mut assembler, maximum_offset, exhausted)?;
    x86_emit_mandatory_teddy_scalar_candidate(&mut assembler, teddy)?;
    assembler.branch(&[0x0f, 0x85], candidate)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], scalar)?;

    assembler.bind(vector_candidate)?;
    x86_emit_first_candidate_lane(&mut assembler, X86CandidateMask::MovemaskEax)?;
    assembler.instruction(&[0x48, 0x01, 0xc2])?;
    // Vector lanes retained only candidate truth, so recompute the exact
    // bucket identity at the selected base.
    x86_emit_mandatory_teddy_scalar_candidate(&mut assembler, teddy)?;
    assembler.branch(&[0x0f, 0x85], candidate)?;
    assembler.branch(&[0xe9], retry_base)?;

    assembler.bind(candidate)?;
    assembler.instruction(&[0x31, 0xc0])?; // source-ordinal mask = 0
    for bucket in 0..usize::from(teddy.plan.bucket_count()) {
        let absent = assembler.label()?;
        assembler.instruction(&[
            0x41,
            0xf6,
            0xc3,
            1_u8 << u32::try_from(bucket).map_err(|_| {
                ObjectError::ArithmeticOverflow("x86 exact finite SelectedEnd Teddy bucket test")
            })?,
        ])?; // test bucket bit in r11b
        assembler.branch(&[0x0f, 0x84], absent)?;
        let offset = layout
            .bucket_ordinal_masks_offset
            .checked_add(u32::try_from(bucket * 8).map_err(|_| {
                ObjectError::ArithmeticOverflow(
                    "x86 exact finite SelectedEnd Teddy bucket mask offset",
                )
            })?)
            .and_then(|offset| i32::try_from(offset).ok())
            .ok_or(ObjectError::ArithmeticOverflow(
                "x86 exact finite SelectedEnd Teddy bucket mask displacement",
            ))?;
        let mut instruction = vec![0x49, 0x0b, 0x81]; // or disp32(%r9), rax
        instruction.extend_from_slice(&offset.to_le_bytes());
        assembler.instruction(&instruction)?;
        assembler.bind(absent)?;
    }
    assembler.instruction(&[0x48, 0x85, 0xc0])?;
    assembler.branch(&[0x0f, 0x84], false_candidate)?;

    assembler.bind(next_ordinal)?;
    assembler.instruction(&[0x85, 0xdb])?; // test ebx, ebx
    assembler.branch(&[0x0f, 0x84], runtime_fallback)?;
    assembler.instruction(&[0xff, 0xcb])?; // dec ebx
    assembler.instruction(&[0x4c, 0x0f, 0xbc, 0xd0])?; // bsf rax,r10
    assembler.instruction(&[0x4c, 0x8d, 0x58, 0xff])?; // r11 = mask - 1
    assembler.instruction(&[0x4c, 0x21, 0xd8])?; // clear selected ordinal
    let descriptor = i32::try_from(layout.literal_descriptors_offset).map_err(|_| {
        ObjectError::ArithmeticOverflow(
            "x86 exact finite SelectedEnd Teddy descriptor displacement",
        )
    })?;
    let mut load_offset = vec![0x47, 0x8b, 0x9c, 0xd1];
    load_offset.extend_from_slice(&descriptor.to_le_bytes());
    assembler.instruction(&load_offset)?; // r11d = literal absolute offset
    let width_displacement = descriptor
        .checked_add(4)
        .ok_or(ObjectError::ArithmeticOverflow(
            "x86 exact finite SelectedEnd Teddy width displacement",
        ))?;
    let mut load_width = vec![0x43, 0x8b, 0x8c, 0xd1];
    load_width.extend_from_slice(&width_displacement.to_le_bytes());
    assembler.instruction(&load_width)?; // ecx = literal width
    assembler.instruction(&[0x4d, 0x01, 0xcb])?; // r11 += program base
    assembler.instruction(&[0x4c, 0x89, 0xee])?; // rsi = end
    assembler.instruction(&[0x48, 0x29, 0xd6])?; // remaining -= candidate
    assembler.instruction(&[0x48, 0x39, 0xce])?; // remaining < width?
    assembler.branch(&[0x0f, 0x82], false_candidate)?;
    assembler.instruction(&[0x41, 0x89, 0xca])?; // r10d = byte counter
    assembler.instruction(&[0x48, 0x8d, 0x34, 0x17])?; // rsi = haystack+candidate
    assembler.bind(exact_loop)?;
    assembler.instruction(&[0x44, 0x0f, 0xb6, 0x06])?; // r8d = hay byte
    assembler.instruction(&[0x45, 0x3a, 0x03])?; // cmp (r11),r8b
    assembler.branch(&[0x0f, 0x85], false_candidate)?;
    assembler.instruction(&[0x48, 0xff, 0xc6])?;
    assembler.instruction(&[0x49, 0xff, 0xc3])?;
    assembler.instruction(&[0x49, 0xff, 0xca])?;
    assembler.branch(&[0x0f, 0x85], exact_loop)?;
    assembler.branch(&[0xe9], matched)?;

    assembler.bind(false_candidate)?;
    assembler.instruction(&[0x48, 0x85, 0xc0])?;
    assembler.branch(&[0x0f, 0x85], next_ordinal)?;
    assembler.bind(retry_base)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?; // retry from base+1
    assembler.instruction(&[0x4c, 0x89, 0xe9])?; // restore public end
    assembler.branch(&[0xe9], vector)?;

    assembler.bind(runtime_fallback)?;
    // RDX still names the first candidate whose exact source-order result is
    // unresolved. Restore the other public arguments and tail-enter the
    // complete incumbent from that base.
    assembler.instruction(&[0x4c, 0x89, 0xe6])?; // rsi = public length
    assembler.instruction(&[0x4c, 0x89, 0xe9])?; // rcx = public end
    assembler.instruction(&[0x4d, 0x89, 0xf0])?; // r8 = public result
    assembler.instruction(&[0x41, 0x5e])?; // pop r14
    assembler.instruction(&[0x41, 0x5d])?; // pop r13
    assembler.instruction(&[0x5b])?; // pop rbx
    assembler.instruction(&[0x41, 0x5c])?; // pop r12
    assembler.instruction(&[0xc5, 0xf8, 0x77])?;
    assembler.branch(&[0xe9], tail)?;

    assembler.bind(matched)?;
    assembler.instruction(&[0x48, 0x8d, 0x04, 0x0a])?; // selected end
    assembler.instruction(&[0x49, 0x89, 0x06])?;
    assembler.instruction(&[0x49, 0x89, 0x46, 0x08])?;
    assembler.instruction(&[0xb8, 0x01, 0, 0, 0])?;
    assembler.branch(&[0xe9], returned)?;

    assembler.bind(exhausted)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.bind(returned)?;
    assembler.instruction(&[0x41, 0x5e])?; // pop r14
    assembler.instruction(&[0x41, 0x5d])?; // pop r13
    assembler.instruction(&[0x5b])?; // pop rbx
    assembler.instruction(&[0x41, 0x5c])?; // pop r12
    assembler.instruction(&[0xc5, 0xf8, 0x77])?;
    assembler.instruction(&[0xc3])?;

    // Keep the incumbent outside the assembler transaction so branch
    // relaxation cannot rewrite one byte of its already audited code.
    assembler.bind(tail)?;
    assembler.instruction(&[0xe9])?;
    let tail_displacement = assembler.label()?;
    assembler.bind(tail_displacement)?;
    push_bytes(&mut assembler.code, &[0; 4])?;
    let mut finished = assembler.finish_with_label_offsets()?;
    let tail_displacement = finished.label_offset(tail_displacement)?;
    let program_displacement = finished.label_offset(program_displacement)?;
    let core_offset =
        finished
            .code
            .len()
            .checked_add(15)
            .ok_or(ObjectError::ArithmeticOverflow(
                "x86 exact finite SelectedEnd Teddy core alignment",
            ))?
            & !15;
    finished
        .code
        .try_reserve_exact(
            core_offset
                .checked_sub(finished.code.len())
                .and_then(|padding| padding.checked_add(incumbent_code.len()))
                .ok_or(ObjectError::ArithmeticOverflow(
                    "x86 exact finite SelectedEnd Teddy composed code extent",
                ))?,
        )
        .map_err(|_| ObjectError::Allocation("exact finite SelectedEnd Teddy composed code"))?;
    finished.code.resize(core_offset, 0x90);
    let after = tail_displacement
        .checked_add(4)
        .ok_or(ObjectError::ArithmeticOverflow(
            "x86 exact finite SelectedEnd Teddy tail displacement",
        ))?;
    let relative = i64::try_from(core_offset)
        .map_err(|_| {
            ObjectError::ArithmeticOverflow("x86 exact finite SelectedEnd Teddy core offset")
        })?
        .checked_sub(i64::try_from(after).map_err(|_| {
            ObjectError::ArithmeticOverflow("x86 exact finite SelectedEnd Teddy tail displacement")
        })?)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(ObjectError::ArithmeticOverflow(
            "x86 exact finite SelectedEnd Teddy tail branch",
        ))?;
    finished.code[tail_displacement..after].copy_from_slice(&relative.to_le_bytes());
    finished.code.extend_from_slice(incumbent_code);
    Ok((
        finished.code,
        vec![ModuleRelocation {
            section: TEXT_SECTION,
            offset: offset_u64(
                program_displacement,
                "x86 exact finite SelectedEnd Teddy program relocation",
            )?,
            kind: RelocationKind::X86PcRelative32,
            symbol: PROGRAM_SYMBOL,
            addend: -4,
        }],
        core_offset,
    ))
}

fn aarch64_exact_orr_x(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0xaa00_0000
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_exact_and_x(destination: u8, left: u8, right: u8) -> Result<u32, ObjectError> {
    Ok(
        0x8a00_0000
            | aarch64_reg(right, 16)?
            | aarch64_reg(left, 5)?
            | aarch64_reg(destination, 0)?,
    )
}

fn aarch64_exact_rbit_x(destination: u8, source: u8) -> Result<u32, ObjectError> {
    Ok(0xdac0_0000 | aarch64_reg(source, 5)? | aarch64_reg(destination, 0)?)
}

fn aarch64_exact_clz_x(destination: u8, source: u8) -> Result<u32, ObjectError> {
    Ok(0xdac0_1000 | aarch64_reg(source, 5)? | aarch64_reg(destination, 0)?)
}

fn aarch64_exact_mov_w(destination: u8, source: u8) -> Result<u32, ObjectError> {
    Ok(0x2a00_03e0 | aarch64_reg(source, 16)? | aarch64_reg(destination, 0)?)
}

fn lower_aarch64_wrapper(
    incumbent_code: &[u8],
    layout: ExactFiniteSelectedEndTeddyDataLayout,
    lane_index_offset: Option<u32>,
) -> Result<(Vec<u8>, Vec<ModuleRelocation>, usize), ObjectError> {
    let teddy = layout.teddy;
    if incumbent_code.is_empty()
        || layout.literal_count != teddy.plan.literal_count()
        || !incumbent_code.len().is_multiple_of(4)
    {
        return Err(ObjectError::InvalidModule(
            "AArch64 exact finite SelectedEnd Teddy incumbent code alignment",
        ));
    }
    let mut assembler = Aarch64Assembler::new();
    let vector = assembler.label()?;
    let scalar = assembler.label()?;
    let vector_candidate = assembler.label()?;
    let candidate = assembler.label()?;
    let bucket_ready = assembler.label()?;
    let retry_scan = assembler.label()?;
    let retry_base = assembler.label()?;
    let ordinal_failed = assembler.label()?;
    let next_ordinal = assembler.label()?;
    let exact_loop = assembler.label()?;
    let runtime_fallback = assembler.label()?;
    let matched = assembler.label()?;
    let exhausted = assembler.label()?;
    let tail = assembler.label()?;

    aarch64_emit_public_search_abi_validation(&mut assembler, tail)?;
    assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
    aarch64_load_u32_constant(
        &mut assembler,
        11,
        u32::try_from(EXACT_FINITE_PREFIX_MIN_INPUT_BYTES).map_err(|_| {
            ObjectError::ArithmeticOverflow("AArch64 exact finite SelectedEnd Teddy input floor")
        })?,
    )?;
    assembler.instruction(aarch64_cmp_x(12, 11)?)?;
    assembler.branch_cond(AARCH64_LO, tail)?;
    assembler.instruction(aarch64_sub_x_imm(31, 31, 16)?)?;
    assembler.instruction(aarch64_store_pair_x(19, 20, 31, 0)?)?;
    assembler.instruction(aarch64_mov_x(19, 1)?)?; // preserve public length
    assembler.instruction(aarch64_movz_w(
        20,
        EXACT_FINITE_TEDDY_RUNTIME_VERIFICATION_BUDGET,
    )?)?;
    assembler.instruction(aarch64_store_x(31, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(31, 4, 8)?)?;
    let program_page = assembler.instruction(0x9000_0005)?; // adrp x5, program@PAGE
    let program_page_offset = assembler.instruction(aarch64_add_x_imm(5, 5, 0)?)?;

    match teddy.isa {
        MandatoryTeddyIsa::Aarch64Asimd => {
            aarch64_emit_mandatory_teddy_asimd_constants(&mut assembler, teddy)?;
            aarch64_emit_first_lane_constants(
                &mut assembler,
                lane_index_offset.ok_or(ObjectError::InvalidModule(
                    "AArch64 exact finite SelectedEnd Teddy ASIMD lane table is absent",
                ))?,
            )?;
            assembler.instruction(aarch64_movi_16b(26, 0x0f)?)?;
            assembler.bind(vector)?;
            assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
            let required = u16::from(teddy.plan.columns().checked_sub(1).ok_or(
                ObjectError::InvalidModule("AArch64 exact finite SelectedEnd Teddy has no columns"),
            )?)
            .checked_add(16)
            .ok_or(ObjectError::ArithmeticOverflow(
                "AArch64 exact finite SelectedEnd Teddy vector bound",
            ))?;
            assembler.instruction(aarch64_cmp_x_imm(12, required)?)?;
            assembler.branch_cond(AARCH64_LO, scalar)?;
            aarch64_emit_mandatory_teddy_asimd_candidates(&mut assembler, teddy)?;
            assembler.branch_cond(AARCH64_NE, vector_candidate)?;
            assembler.instruction(aarch64_add_x_imm(2, 2, 16)?)?;
            assembler.branch(vector)?;

            assembler.bind(scalar)?;
            let maximum_offset =
                teddy
                    .plan
                    .columns()
                    .checked_sub(1)
                    .ok_or(ObjectError::InvalidModule(
                        "AArch64 exact finite SelectedEnd Teddy has no columns",
                    ))?;
            aarch64_emit_start_filter_scalar_bound(&mut assembler, maximum_offset, exhausted)?;
            aarch64_emit_mandatory_teddy_scalar_candidate(&mut assembler, teddy)?;
            assembler.branch_cond(AARCH64_NE, bucket_ready)?;
            assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
            assembler.branch(scalar)?;

            assembler.bind(vector_candidate)?;
            aarch64_emit_first_candidate_lane(&mut assembler, 24)?;
            assembler.branch(candidate)?;
        }
        MandatoryTeddyIsa::Aarch64Sve | MandatoryTeddyIsa::Aarch64Sve2 => {
            let partial = assembler.label()?;
            aarch64_emit_mandatory_teddy_sve_constants(&mut assembler, teddy)?;
            assembler.bind(retry_scan)?;
            // Exact verification uses W6 and partial batches narrow P0. A
            // false fingerprint can cross from a full batch into the final
            // partial batch, so restore every scalable scan invariant before
            // making either decision again.
            assembler.instruction(aarch64_sve_ptrue_b())?;
            assembler.instruction(aarch64_sve_dup_b_imm(26, 0x0f)?)?;
            assembler.instruction(aarch64_sve_cntb(6)?)?;
            assembler.bind(vector)?;
            assembler.instruction(aarch64_sub_x_reg(12, 3, 2)?)?;
            assembler.instruction(aarch64_cmp_x_imm(12, u16::from(teddy.plan.columns()))?)?;
            assembler.branch_cond(AARCH64_LO, exhausted)?;
            let maximum_offset =
                teddy
                    .plan
                    .columns()
                    .checked_sub(1)
                    .ok_or(ObjectError::InvalidModule(
                        "AArch64 exact finite SelectedEnd Teddy has no columns",
                    ))?;
            assembler.instruction(aarch64_sub_x_imm(10, 3, u16::from(maximum_offset))?)?;
            assembler.instruction(aarch64_sub_x_reg(12, 10, 2)?)?;
            assembler.instruction(aarch64_cmp_x(12, 6)?)?;
            assembler.branch_cond(AARCH64_LO, partial)?;
            aarch64_emit_mandatory_teddy_sve_candidates(&mut assembler, teddy)?;
            assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
            assembler.branch_cond(AARCH64_NE, vector_candidate)?;
            assembler.instruction(aarch64_sve_addvl(2, 2, 1)?)?;
            assembler.branch(vector)?;

            assembler.bind(partial)?;
            assembler.instruction(aarch64_sve_whilelo_b(0, 2, 10)?)?;
            aarch64_emit_mandatory_teddy_sve_candidates(&mut assembler, teddy)?;
            assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
            assembler.branch_cond(AARCH64_EQ, exhausted)?;

            assembler.bind(vector_candidate)?;
            aarch64_emit_sve_first_candidate(&mut assembler, 1, candidate)?;
            assembler.bind(scalar)?;
            assembler.branch(exhausted)?;
        }
        MandatoryTeddyIsa::X86Avx2 | MandatoryTeddyIsa::X86Avx512Bw => {
            return Err(ObjectError::InvalidModule(
                "x86 Teddy reached AArch64 exact finite SelectedEnd Teddy wrapper",
            ));
        }
    }

    assembler.bind(candidate)?;
    // The SVE first-lane helper branches here directly; recover the exact
    // bucket identity that predicates intentionally discard.
    aarch64_emit_mandatory_teddy_scalar_candidate(&mut assembler, teddy)?;
    assembler.branch_cond(AARCH64_EQ, retry_base)?;
    assembler.bind(bucket_ready)?;
    assembler.instruction(aarch64_movz_w(11, 0)?)?; // source-ordinal mask
    aarch64_set_table_address(&mut assembler, 12, layout.bucket_ordinal_masks_offset)?;
    for bucket in 0..usize::from(teddy.plan.bucket_count()) {
        let absent = assembler.label()?;
        assembler.branch_bit_clear_w(
            10,
            u8::try_from(bucket).map_err(|_| {
                ObjectError::ArithmeticOverflow("AArch64 exact finite SelectedEnd Teddy bucket bit")
            })?,
            absent,
        )?;
        assembler.instruction(aarch64_load_x_imm(
            8,
            12,
            u16::try_from(bucket * 8).map_err(|_| {
                ObjectError::ArithmeticOverflow(
                    "AArch64 exact finite SelectedEnd Teddy bucket offset",
                )
            })?,
        )?)?;
        assembler.instruction(aarch64_exact_orr_x(11, 11, 8)?)?;
        assembler.bind(absent)?;
    }
    assembler.branch_zero_x(11, retry_base)?;

    assembler.bind(next_ordinal)?;
    assembler.branch_zero_x(20, runtime_fallback)?;
    assembler.instruction(aarch64_sub_w_imm(20, 20, 1)?)?;
    assembler.instruction(aarch64_exact_rbit_x(8, 11)?)?;
    assembler.instruction(aarch64_exact_clz_x(8, 8)?)?;
    assembler.instruction(aarch64_sub_x_imm(9, 11, 1)?)?;
    assembler.instruction(aarch64_exact_and_x(11, 11, 9)?)?;
    aarch64_set_table_address(&mut assembler, 12, layout.literal_descriptors_offset)?;
    assembler.instruction(aarch64_add_x_lsl(12, 12, 8, 3)?)?;
    assembler.instruction(aarch64_load_w_imm(9, 12, 0)?)?;
    assembler.instruction(aarch64_load_w_imm(15, 12, 4)?)?;
    assembler.instruction(aarch64_add_x_uxtw(14, 5, 9, 0)?)?;
    assembler.instruction(aarch64_sub_x_reg(1, 3, 2)?)?;
    assembler.instruction(aarch64_cmp_x(1, 15)?)?;
    assembler.branch_cond(AARCH64_LO, ordinal_failed)?;
    assembler.instruction(aarch64_mov_x(1, 15)?)?; // preserve selected width
    assembler.instruction(aarch64_exact_mov_w(10, 15)?)?;
    assembler.instruction(aarch64_add_x_reg(13, 0, 2)?)?;
    assembler.bind(exact_loop)?;
    assembler.instruction(aarch64_load_byte_post_imm(16, 13, 1)?)?;
    assembler.instruction(aarch64_load_byte_post_imm(17, 14, 1)?)?;
    assembler.instruction(aarch64_cmp_w(16, 17)?)?;
    assembler.branch_cond(AARCH64_NE, ordinal_failed)?;
    assembler.instruction(aarch64_sub_w_imm(10, 10, 1)?)?;
    assembler.branch_nonzero_w(10, exact_loop)?;
    assembler.branch(matched)?;

    assembler.bind(ordinal_failed)?;
    assembler.branch_nonzero_x(11, next_ordinal)?;
    assembler.bind(retry_base)?;
    assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
    match teddy.isa {
        MandatoryTeddyIsa::Aarch64Sve | MandatoryTeddyIsa::Aarch64Sve2 => {
            assembler.branch(retry_scan)?;
        }
        MandatoryTeddyIsa::Aarch64Asimd => assembler.branch(vector)?,
        MandatoryTeddyIsa::X86Avx2 | MandatoryTeddyIsa::X86Avx512Bw => {
            return Err(ObjectError::InvalidModule(
                "x86 Teddy reached AArch64 exact finite SelectedEnd Teddy retry",
            ));
        }
    }

    assembler.bind(runtime_fallback)?;
    // X2 still names the first unresolved candidate. Restore public length
    // and the callee-saved registers before tail-entering the incumbent.
    assembler.instruction(aarch64_mov_x(1, 19)?)?;
    assembler.instruction(aarch64_load_pair_x(19, 20, 31, 0)?)?;
    assembler.instruction(aarch64_add_x_imm(31, 31, 16)?)?;
    assembler.branch(tail)?;

    assembler.bind(matched)?;
    assembler.instruction(aarch64_add_x_reg(6, 2, 1)?)?;
    assembler.instruction(aarch64_store_x(6, 4, 0)?)?;
    assembler.instruction(aarch64_store_x(6, 4, 8)?)?;
    assembler.instruction(aarch64_movz_w(0, 1)?)?;
    assembler.instruction(aarch64_load_pair_x(19, 20, 31, 0)?)?;
    assembler.instruction(aarch64_add_x_imm(31, 31, 16)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(exhausted)?;
    assembler.instruction(aarch64_movz_w(0, 0)?)?;
    assembler.instruction(aarch64_load_pair_x(19, 20, 31, 0)?)?;
    assembler.instruction(aarch64_add_x_imm(31, 31, 16)?)?;
    assembler.instruction(0xd65f_03c0)?;
    assembler.bind(tail)?;
    let tail_instruction = assembler.instruction(0x1400_0000)?; // patched B core
    let mut relocation_offsets = [program_page, program_page_offset, tail_instruction];
    let mut code = assembler.finish_with_offsets(&mut relocation_offsets)?;
    let core_offset = code
        .len()
        .checked_add(15)
        .ok_or(ObjectError::ArithmeticOverflow(
            "AArch64 exact finite SelectedEnd Teddy core alignment",
        ))?
        & !15;
    let additional = core_offset
        .checked_sub(code.len())
        .and_then(|padding| padding.checked_add(incumbent_code.len()))
        .ok_or(ObjectError::ArithmeticOverflow(
            "AArch64 exact finite SelectedEnd Teddy composed code extent",
        ))?;
    code.try_reserve_exact(additional)
        .map_err(|_| ObjectError::Allocation("exact finite SelectedEnd Teddy composed code"))?;
    while code.len() < core_offset {
        code.extend_from_slice(&0xd503_201f_u32.to_le_bytes());
    }
    let branch = relocation_offsets[2];
    let delta = i64::try_from(core_offset)
        .map_err(|_| {
            ObjectError::ArithmeticOverflow("AArch64 exact finite SelectedEnd Teddy core")
        })?
        .checked_sub(i64::try_from(branch).map_err(|_| {
            ObjectError::ArithmeticOverflow("AArch64 exact finite SelectedEnd Teddy branch")
        })?)
        .ok_or(ObjectError::ArithmeticOverflow(
            "AArch64 exact finite SelectedEnd Teddy tail branch",
        ))?;
    if delta % 4 != 0 {
        return Err(ObjectError::InvalidModule(
            "AArch64 exact finite SelectedEnd Teddy tail branch alignment",
        ));
    }
    let words = delta / 4;
    if !(-(1_i64 << 25)..(1_i64 << 25)).contains(&words) {
        return Err(ObjectError::InvalidModule(
            "AArch64 exact finite SelectedEnd Teddy tail branch range",
        ));
    }
    let encoded = 0x1400_0000_u32
        | u32::try_from(words & i64::from(0x03ff_ffff)).map_err(|_| {
            ObjectError::InvalidModule(
                "AArch64 exact finite SelectedEnd Teddy tail branch encoding",
            )
        })?;
    let branch_end = branch
        .checked_add(4)
        .ok_or(ObjectError::ArithmeticOverflow(
            "AArch64 exact finite SelectedEnd Teddy tail branch extent",
        ))?;
    code.get_mut(branch..branch_end)
        .ok_or(ObjectError::InvalidModule(
            "AArch64 exact finite SelectedEnd Teddy tail branch escaped code",
        ))?
        .copy_from_slice(&encoded.to_le_bytes());
    code.extend_from_slice(incumbent_code);
    let relocations = vec![
        ModuleRelocation {
            section: TEXT_SECTION,
            offset: offset_u64(
                relocation_offsets[0],
                "AArch64 exact finite SelectedEnd Teddy ADRP relocation",
            )?,
            kind: RelocationKind::Aarch64Page21,
            symbol: PROGRAM_SYMBOL,
            addend: 0,
        },
        ModuleRelocation {
            section: TEXT_SECTION,
            offset: offset_u64(
                relocation_offsets[1],
                "AArch64 exact finite SelectedEnd Teddy ADD relocation",
            )?,
            kind: RelocationKind::Aarch64PageOff12,
            symbol: PROGRAM_SYMBOL,
            addend: 0,
        },
    ];
    Ok((code, relocations, core_offset))
}

fn report_for(
    selection: ExactFiniteSelectedEndTeddySelection<'_>,
    layout: ExactFiniteSelectedEndTeddyDataLayout,
    lowering: &NativeLowering,
    incumbent_code: &[u8],
    incumbent_code_offset: usize,
    incumbent_data: &[u8],
    incumbent_relocations_sha256: [u8; 32],
    incumbent_relocation_count: usize,
    incumbent_complete_dfa: ExactFiniteSelectedEndDfaBaselineReport,
) -> Result<ExactFiniteSelectedEndTeddyAotReport, ObjectError> {
    let teddy = layout.teddy;
    let tier = mandatory_teddy::tier_costs(selection.plan, selection.isa).ok_or(
        ObjectError::InvalidModule("exact finite SelectedEnd Teddy target tier costs"),
    )?;
    let auxiliary_table_bytes = usize::from(selection.isa == MandatoryTeddyIsa::Aarch64Asimd)
        .checked_mul(AARCH64_FIRST_LANE_INDEX.len())
        .ok_or(ObjectError::ArithmeticOverflow(
            "exact finite SelectedEnd Teddy auxiliary table bytes",
        ))?;
    let gate_table_bytes = tier.table_bytes.checked_add(auxiliary_table_bytes).ok_or(
        ObjectError::ArithmeticOverflow("exact finite SelectedEnd Teddy gate table bytes"),
    )?;
    let mut report = ExactFiniteSelectedEndTeddyAotReport {
        artifact_identity: selection.view.artifact_identity(),
        output: selection.view.output(),
        literal_sha256: selection.view.literal_digest(),
        prefix_plan_sha256: [0; 32],
        native_code_sha256: Sha256::digest(&lowering.code).into(),
        native_data_sha256: Sha256::digest(&lowering.data).into(),
        relocations_sha256: relocation_digest(&lowering.relocations).ok_or(
            ObjectError::InvalidModule("exact finite SelectedEnd Teddy relocation digest"),
        )?,
        incumbent_code_sha256: Sha256::digest(incumbent_code).into(),
        incumbent_data_sha256: Sha256::digest(incumbent_data).into(),
        incumbent_relocations_sha256,
        incumbent_complete_dfa,
        source_count: selection.view.source_count(),
        source_bytes: selection.view.total_source_bytes(),
        minimum_width: selection.view.minimum_width(),
        maximum_width: selection.view.maximum_width(),
        root_members: selection.view.root_members(),
        columns: selection.plan.columns(),
        bucket_count: selection.plan.bucket_count(),
        literal_count: selection.plan.literal_count(),
        candidate_fingerprint_upper_bound: selection.plan.candidate_fingerprint_upper_bound(),
        candidate_frequency_upper_bound: selection.plan.candidate_frequency_upper_bound(),
        fingerprint_space: selection.plan.fingerprint_space(),
        plan_scan_instruction_units: selection.plan.scan_instruction_units(),
        emitted_scan_instruction_units: tier.scan_instruction_units,
        guaranteed_vector_bytes: tier.block_bytes,
        gate_table_bytes,
        selected_target_tier: report_target_tier(selection.isa),
        emitted_isa: report_isa(selection.isa),
        target: selection.target,
        scanner: report_scanner(selection.isa),
        input_floor_bytes: EXACT_FINITE_PREFIX_MIN_INPUT_BYTES,
        selection_horizon_bytes: selection.selection_horizon_bytes,
        selection_gate_cost_units: selection.gate_cost_units,
        selection_expected_verification_cost_units: selection.expected_verification_cost_units,
        selection_full_cost_units: selection.full_cost_units,
        selection_incumbent_cost_units: selection.incumbent_cost_units,
        selection_root_frequency_units: selection.root_frequency_units,
        selection_no_candidate_numerator: selection.no_candidate_numerator,
        selection_probability_denominator: selection.probability_denominator,
        runtime_verification_budget: EXACT_FINITE_TEDDY_RUNTIME_VERIFICATION_BUDGET,
        table_base: teddy.table_base,
        table_end: teddy.table_end,
        bucket_ordinal_masks_offset: layout.bucket_ordinal_masks_offset,
        literal_descriptors_offset: layout.literal_descriptors_offset,
        literal_bytes_offset: layout.literal_bytes_offset,
        literal_bytes_end: layout.literal_bytes_end,
        native_data_bytes: lowering.data.len(),
        incumbent_code_offset,
        incumbent_code_bytes: incumbent_code.len(),
        incumbent_data_bytes: incumbent_data.len(),
        incumbent_relocation_count,
    };
    report.prefix_plan_sha256 = report_plan_digest(&report, &lowering.data).ok_or(
        ObjectError::InvalidModule("exact finite SelectedEnd Teddy plan digest"),
    )?;
    Ok(report)
}

/// Compose the selected proof with one already-lowered complete native DFA.
/// Numeric data-cap misses return that exact incumbent unchanged. Allocation
/// failures after selection are terminal under the compiler's monotonic
/// allocation policy.
pub(super) fn wrap_exact_finite_selected_end_teddy(
    selection: ExactFiniteSelectedEndTeddySelection<'_>,
    mut incumbent: NativeLowering,
    incumbent_complete_dfa: ExactFiniteSelectedEndDfaBaselineReport,
    target: Target,
    maximum_native_data_bytes: usize,
) -> Result<ExactFiniteSelectedEndTeddyWrapOutcome, ObjectError> {
    if target != selection.target
        || native_mandatory_teddy_isa(target) != Some(selection.isa)
        || !complete_dfa_baseline_report_has_valid_geometry(incumbent_complete_dfa)
        || incumbent_complete_dfa.native_data_bytes != incumbent.data.len()
        || incumbent_complete_dfa.scanner != incumbent.start_accelerator
        || incumbent.needs_runtime
        || incumbent.slow_partial_table.is_some()
        || incumbent.code.is_empty()
    {
        return Err(ObjectError::InvalidModule(
            "exact finite SelectedEnd Teddy incumbent is not a complete native DFA",
        ));
    }
    let checkpoint = incumbent.data.len();
    let required_data_bytes =
        exact_finite_selected_end_teddy_required_data_bytes(selection, checkpoint)?;
    if required_data_bytes > maximum_native_data_bytes {
        return Ok(ExactFiniteSelectedEndTeddyWrapOutcome::ResourceDeclined(
            incumbent,
        ));
    }
    let additional =
        required_data_bytes
            .checked_sub(checkpoint)
            .ok_or(ObjectError::InvalidModule(
                "exact finite SelectedEnd Teddy required data regressed",
            ))?;
    incumbent
        .data
        .try_reserve_exact(additional)
        .map_err(|_| ObjectError::Allocation("exact finite SelectedEnd Teddy native data"))?;
    let incumbent_code = core::mem::take(&mut incumbent.code);
    let incumbent_relocations = core::mem::take(&mut incumbent.relocations);
    let incumbent_relocation_count = incumbent_relocations.len();
    let incumbent_relocations_sha256 = relocation_digest(&incumbent_relocations).ok_or(
        ObjectError::InvalidModule("exact finite SelectedEnd Teddy incumbent relocation digest"),
    )?;
    let teddy = match target.architecture {
        Architecture::X86_64 => append_x86_mandatory_teddy_with_limit(
            &mut incumbent.data,
            selection.plan,
            selection.isa,
            maximum_native_data_bytes,
        )?,
        Architecture::Aarch64 => append_aarch64_mandatory_teddy_with_limit(
            &mut incumbent.data,
            selection.plan,
            selection.isa,
            maximum_native_data_bytes,
        )?,
    };
    let Some(teddy) = teddy else {
        return Err(ObjectError::InvalidModule(
            "exact finite SelectedEnd Teddy table contradicted its preflight",
        ));
    };
    let lane_index_offset = if selection.isa == MandatoryTeddyIsa::Aarch64Asimd {
        match append_aarch64_lane_index_strict(&mut incumbent.data, maximum_native_data_bytes)? {
            Some(offset) => Some(offset),
            None => {
                return Err(ObjectError::InvalidModule(
                    "exact finite SelectedEnd Teddy lane table contradicted its preflight",
                ));
            }
        }
    } else {
        None
    };
    let verifier_layout = match append_exact_verifier_data(
        &mut incumbent.data,
        selection.view,
        teddy,
        maximum_native_data_bytes,
    )? {
        Some(layout) => layout,
        None => {
            return Err(ObjectError::InvalidModule(
                "exact finite SelectedEnd Teddy verifier data contradicted its preflight",
            ));
        }
    };

    let (code, relocations, incumbent_code_offset) = match target.architecture {
        Architecture::X86_64 => {
            let (code, mut wrapper_relocations, core_offset) =
                lower_x86_wrapper(&incumbent_code, verifier_layout)?;
            let rebased = checked_rebase_relocations(
                incumbent_relocations,
                incumbent_code.len(),
                core_offset,
            )?;
            wrapper_relocations
                .try_reserve_exact(rebased.len())
                .map_err(|_| {
                    ObjectError::Allocation("exact finite SelectedEnd Teddy relocations")
                })?;
            wrapper_relocations.extend(rebased);
            (code, wrapper_relocations, core_offset)
        }
        Architecture::Aarch64 => {
            let (code, mut wrapper_relocations, core_offset) =
                lower_aarch64_wrapper(&incumbent_code, verifier_layout, lane_index_offset)?;
            let rebased = checked_rebase_relocations(
                incumbent_relocations,
                incumbent_code.len(),
                core_offset,
            )?;
            wrapper_relocations
                .try_reserve_exact(rebased.len())
                .map_err(|_| {
                    ObjectError::Allocation("exact finite SelectedEnd Teddy relocations")
                })?;
            wrapper_relocations.extend(rebased);
            (code, wrapper_relocations, core_offset)
        }
    };
    incumbent.code = code;
    incumbent.relocations = relocations;
    incumbent.start_accelerator = report_scanner(selection.isa);
    incumbent.anchored_prefix_filter_bytes = selection.plan.columns();
    let report = report_for(
        selection,
        verifier_layout,
        &incumbent,
        &incumbent_code,
        incumbent_code_offset,
        incumbent
            .data
            .get(..checkpoint)
            .ok_or(ObjectError::InvalidModule(
                "exact finite SelectedEnd Teddy incumbent data extent",
            ))?,
        incumbent_relocations_sha256,
        incumbent_relocation_count,
        incumbent_complete_dfa,
    )?;
    if !report_matches_lowering(&report, &incumbent, target)? {
        return Err(ObjectError::InvalidModule(
            "exact finite SelectedEnd Teddy wrapper disagrees with its receipt",
        ));
    }
    Ok(ExactFiniteSelectedEndTeddyWrapOutcome::Selected {
        lowering: incumbent,
        report,
    })
}

pub(super) fn report_matches_lowering(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    lowering: &NativeLowering,
    target: Target,
) -> Result<bool, ObjectError> {
    report_matches_parts(
        report,
        &lowering.code,
        &lowering.data,
        &lowering.relocations,
        lowering.needs_runtime,
        lowering.slow_partial_table.is_some(),
        lowering.start_accelerator,
        lowering.anchored_prefix_filter_bytes,
        target,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "module attachment re-authenticates every independently stored lowering component"
)]
pub(super) fn report_matches_parts(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    code: &[u8],
    data: &[u8],
    relocations: &[ModuleRelocation],
    needs_runtime: bool,
    has_slow_partial_table: bool,
    start_accelerator: StartAccelerator,
    anchored_prefix_filter_bytes: u8,
    target: Target,
) -> Result<bool, ObjectError> {
    let code_end = report
        .incumbent_code_offset
        .checked_add(report.incumbent_code_bytes);
    let incumbent = code_end
        .filter(|&end| end <= code.len())
        .and_then(|end| code.get(report.incumbent_code_offset..end));
    let incumbent_data = data.get(..report.incumbent_data_bytes);
    let incumbent_route_matches =
        complete_dfa_baseline_report_has_valid_geometry(report.incumbent_complete_dfa)
            && report.incumbent_complete_dfa.native_data_bytes == report.incumbent_data_bytes
            && incumbent_relocation_digest(
                relocations,
                report.incumbent_relocation_count,
                report.incumbent_code_offset,
                report.incumbent_code_bytes,
            )
            .is_some_and(|digest| digest == report.incumbent_relocations_sha256);
    Ok(report_costs_authenticate(report, data, target)?
        && verifier_data_authenticates(report, data)?
        && report.artifact_identity != [0; 32]
        && report.output == OutputContract::SelectedEnd
        && report.source_count >= 4
        && report.source_count <= 64
        && usize::try_from(report.minimum_width)
            .ok()
            .and_then(|width| width.checked_mul(usize::try_from(report.source_count).ok()?))
            .is_some_and(|minimum_source_bytes| report.source_bytes >= minimum_source_bytes)
        && report.minimum_width >= u32::from(report.columns)
        && report.minimum_width <= report.maximum_width
        && report.literal_sha256 != [0; 32]
        && matches!(report.columns, 3 | 4)
        && report.literal_count == u16::try_from(report.source_count).unwrap_or(0)
        && report.bucket_count == u8::try_from(report.literal_count.min(8)).unwrap_or(0)
        && report.candidate_fingerprint_upper_bound != 0
        && report.candidate_frequency_upper_bound != 0
        && report.fingerprint_space != 0
        && report.candidate_fingerprint_upper_bound <= report.fingerprint_space
        && report.candidate_frequency_upper_bound <= report.fingerprint_space
        && report.table_base < report.table_end
        && report.incumbent_data_bytes <= usize::try_from(report.table_base).unwrap_or(0)
        && report.native_data_bytes == data.len()
        && incumbent_route_matches
        && report.scanner == start_accelerator
        && anchored_prefix_filter_bytes == report.columns
        && !needs_runtime
        && !has_slow_partial_table
        && Sha256::digest(code).as_slice() == report.native_code_sha256
        && Sha256::digest(data).as_slice() == report.native_data_sha256
        && relocation_digest(relocations).is_some_and(|digest| digest == report.relocations_sha256)
        && incumbent
            .is_some_and(|code| Sha256::digest(code).as_slice() == report.incumbent_code_sha256)
        && incumbent_data
            .is_some_and(|data| Sha256::digest(data).as_slice() == report.incumbent_data_sha256))
}

fn incumbent_relocation_digest(
    relocations: &[ModuleRelocation],
    incumbent_count: usize,
    incumbent_code_offset: usize,
    incumbent_code_bytes: usize,
) -> Option<[u8; 32]> {
    let incumbent_code_end = incumbent_code_offset.checked_add(incumbent_code_bytes)?;
    let mut digest = Sha256::new();
    digest.update(u64::try_from(incumbent_count).ok()?.to_le_bytes());
    let mut actual_count = 0_usize;
    for relocation in relocations {
        let absolute_offset = usize::try_from(relocation.offset).ok()?;
        if relocation.section != TEXT_SECTION
            || absolute_offset < incumbent_code_offset
            || absolute_offset >= incumbent_code_end
        {
            continue;
        }
        actual_count = actual_count.checked_add(1)?;
        let offset = absolute_offset.checked_sub(incumbent_code_offset)?;
        digest.update(u64::try_from(relocation.section).ok()?.to_le_bytes());
        digest.update(u64::try_from(offset).ok()?.to_le_bytes());
        digest.update([match relocation.kind {
            RelocationKind::X86PcRelative32 => 0,
            RelocationKind::X86PltRelative32 => 1,
            RelocationKind::Aarch64Page21 => 2,
            RelocationKind::Aarch64PageOff12 => 3,
            RelocationKind::Aarch64Branch26 => 4,
        }]);
        digest.update(u64::try_from(relocation.symbol).ok()?.to_le_bytes());
        digest.update(relocation.addend.to_le_bytes());
    }
    (actual_count == incumbent_count).then(|| digest.finalize().into())
}

fn authenticated_literal_slices<'a>(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    data: &'a [u8],
) -> Result<Option<Vec<&'a [u8]>>, ObjectError> {
    let Ok(source_count) = usize::try_from(report.source_count) else {
        return Ok(None);
    };
    if !(4..=64).contains(&source_count) {
        return Ok(None);
    }
    let Some(reference_bytes) = source_count.checked_mul(core::mem::size_of::<&[u8]>()) else {
        return Ok(None);
    };
    if reference_bytes > EXACT_FINITE_TEDDY_VALIDATION_SCRATCH_LIMIT_BYTES {
        return Ok(None);
    }
    let mut literals = Vec::new();
    literals
        .try_reserve_exact(source_count)
        .map_err(|_| ObjectError::Allocation("exact finite SelectedEnd validation literals"))?;
    Ok(authenticated_literal_slices_with_scratch(
        report, data, literals,
    ))
}

fn authenticated_literal_slices_with_scratch<'a>(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    data: &'a [u8],
    mut literals: Vec<&'a [u8]>,
) -> Option<Vec<&'a [u8]>> {
    let Ok(source_count) = usize::try_from(report.source_count) else {
        return None;
    };
    let Ok(masks_offset) = usize::try_from(report.bucket_ordinal_masks_offset) else {
        return None;
    };
    let Ok(descriptors_offset) = usize::try_from(report.literal_descriptors_offset) else {
        return None;
    };
    let Ok(literals_offset) = usize::try_from(report.literal_bytes_offset) else {
        return None;
    };
    let Ok(literals_end) = usize::try_from(report.literal_bytes_end) else {
        return None;
    };
    if !(4..=64).contains(&source_count)
        || descriptors_offset != masks_offset.checked_add(64)?
        || literals_offset != descriptors_offset.checked_add(source_count.checked_mul(8)?)?
        || literals_end != literals_offset.checked_add(report.source_bytes)?
        || literals_end > data.len()
    {
        return None;
    }

    let mut digest = Sha256::new();
    digest.update(u64::try_from(source_count).ok()?.to_le_bytes());
    let mut cursor = literals_offset;
    let mut minimum_width = usize::MAX;
    let mut maximum_width = 0_usize;
    for ordinal in 0..source_count {
        let descriptor = descriptors_offset.checked_add(ordinal.checked_mul(8)?)?;
        let Some(offset_bytes) = data
            .get(descriptor..descriptor.checked_add(4)?)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        else {
            return None;
        };
        let Some(width_bytes) = data
            .get(descriptor.checked_add(4)?..descriptor.checked_add(8)?)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        else {
            return None;
        };
        let offset = usize::try_from(u32::from_le_bytes(offset_bytes)).ok()?;
        let width = usize::try_from(u32::from_le_bytes(width_bytes)).ok()?;
        let Some(end) = offset.checked_add(width) else {
            return None;
        };
        let Some(literal) = data.get(offset..end) else {
            return None;
        };
        if offset != cursor || width < 3 || end > literals_end {
            return None;
        }
        cursor = end;
        minimum_width = minimum_width.min(width);
        maximum_width = maximum_width.max(width);
        digest.update(u64::try_from(width).ok()?.to_le_bytes());
        digest.update(literal);
        literals.push(literal);
    }
    if cursor != literals_end
        || u32::try_from(minimum_width).ok() != Some(report.minimum_width)
        || u32::try_from(maximum_width).ok() != Some(report.maximum_width)
        || digest.finalize().as_slice() != report.literal_sha256
    {
        return None;
    }
    Some(literals)
}

fn exact_bucket_masks_authenticate<B: AsRef<[u8]>>(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    data: &[u8],
    literals: &[B],
    plan: MandatoryTeddyPlan,
) -> Option<bool> {
    let assignments = mandatory_teddy::exact_plan_assignments(literals, plan)?;
    let mut expected = [0_u64; 8];
    for (ordinal, &bucket) in assignments.as_slice().iter().enumerate() {
        let bucket = usize::from(bucket);
        if bucket >= usize::from(plan.bucket_count()) {
            return Some(false);
        }
        expected[bucket] |= 1_u64.checked_shl(u32::try_from(ordinal).ok()?)?;
    }
    let offset = usize::try_from(report.bucket_ordinal_masks_offset).ok()?;
    let bytes = data.get(offset..offset.checked_add(64)?)?;
    for (bucket, expected_mask) in expected.into_iter().enumerate() {
        let start = bucket.checked_mul(8)?;
        let actual = u64::from_le_bytes(bytes.get(start..start.checked_add(8)?)?.try_into().ok()?);
        if actual != expected_mask || (bucket >= usize::from(plan.bucket_count()) && actual != 0) {
            return Some(false);
        }
    }
    Some(true)
}

fn verifier_data_authenticates(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    data: &[u8],
) -> Result<bool, ObjectError> {
    Ok(authenticated_literal_slices(report, data)?.is_some())
}

fn exact_teddy_tables_authenticate(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    data: &[u8],
    plan: MandatoryTeddyPlan,
    isa: MandatoryTeddyIsa,
) -> Option<bool> {
    let table_base = usize::try_from(report.table_base).ok()?;
    let table_end = usize::try_from(report.table_end).ok()?;
    if report.incumbent_data_bytes > table_base
        || !data
            .get(report.incumbent_data_bytes..table_base)?
            .iter()
            .all(|&byte| byte == 0)
    {
        return Some(false);
    }
    let bank = plan.bank(0)?;
    let mut cursor = table_base;
    for column in 0..usize::from(plan.columns()) {
        let low = bank.low(column)?;
        let high = bank.high(column)?;
        match isa {
            MandatoryTeddyIsa::X86Avx2 | MandatoryTeddyIsa::X86Avx512Bw => {
                for table in [low, low, high, high] {
                    let end = cursor.checked_add(table.len())?;
                    if data.get(cursor..end)? != table {
                        return Some(false);
                    }
                    cursor = end;
                }
            }
            MandatoryTeddyIsa::Aarch64Asimd
            | MandatoryTeddyIsa::Aarch64Sve
            | MandatoryTeddyIsa::Aarch64Sve2 => {
                for table in [low, high] {
                    let end = cursor.checked_add(table.len())?;
                    if data.get(cursor..end)? != table {
                        return Some(false);
                    }
                    cursor = end;
                }
            }
        }
    }
    if matches!(
        isa,
        MandatoryTeddyIsa::X86Avx2 | MandatoryTeddyIsa::X86Avx512Bw
    ) {
        let end = cursor.checked_add(X86_MANDATORY_TEDDY_NIBBLE_MASK_BYTES)?;
        if !data.get(cursor..end)?.iter().all(|&byte| byte == 0x0f) {
            return Some(false);
        }
        cursor = end;
    }
    if cursor != table_end {
        return Some(false);
    }
    if isa == MandatoryTeddyIsa::Aarch64Asimd {
        let end = cursor.checked_add(AARCH64_FIRST_LANE_INDEX.len())?;
        if data.get(cursor..end)? != AARCH64_FIRST_LANE_INDEX.as_slice() {
            return Some(false);
        }
        cursor = end;
    }
    let masks_offset = usize::try_from(report.bucket_ordinal_masks_offset).ok()?;
    Some(
        cursor <= masks_offset
            && data
                .get(cursor..masks_offset)?
                .iter()
                .all(|&byte| byte == 0),
    )
}

fn report_costs_authenticate(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    data: &[u8],
    target: Target,
) -> Result<bool, ObjectError> {
    let selected_isa = mandatory_isa_for_target_tier(report.selected_target_tier);
    if report.target != target
        || target.validate().is_err()
        || native_mandatory_teddy_isa(target) != Some(selected_isa)
        || report.emitted_isa != report_isa(selected_isa)
        || report.scanner != report_scanner(selected_isa)
    {
        return Ok(false);
    }
    let Some(literals) = authenticated_literal_slices(report, data)? else {
        return Ok(false);
    };
    Ok((|| {
        let source_bytes = literals
            .iter()
            .try_fold(0_usize, |total, literal| total.checked_add(literal.len()))?;
        let minimum_width = literals.iter().map(|literal| literal.len()).min()?;
        let maximum_width = literals.iter().map(|literal| literal.len()).max()?;
        let mut root_members = [0_u64; 4];
        for literal in &literals {
            let byte = usize::from(*literal.first()?);
            root_members[byte / 64] |= 1_u64 << (byte % 64);
        }
        let incumbent = report.incumbent_complete_dfa;
        if !complete_dfa_baseline_report_has_valid_geometry(incumbent)
            || incumbent.native_data_bytes != report.incumbent_data_bytes
            || source_bytes != report.source_bytes
            || root_members != report.root_members
        {
            return Some(false);
        }
        let portfolio = mandatory_teddy::derive_exact_prefixes(
            &literals,
            minimum_width.min(mandatory_teddy::MAX_MANDATORY_TEDDY_COLUMNS),
        )?;
        let selected = recompute_exact_finite_selected_end_teddy_selection(
            &literals,
            portfolio,
            u32::try_from(minimum_width).ok()?,
            root_members,
            target,
            incumbent,
            EXACT_FINITE_PREFIX_MIN_INPUT_BYTES,
        )?;
        if selected.isa != selected_isa {
            return Some(false);
        }
        let plan = selected.plan;
        let tier = mandatory_teddy::tier_costs(plan, selected_isa)?;
        let auxiliary_bytes = usize::from(selected_isa == MandatoryTeddyIsa::Aarch64Asimd)
            .checked_mul(AARCH64_FIRST_LANE_INDEX.len())?;
        let expected_gate_table_bytes = tier.table_bytes.checked_add(auxiliary_bytes)?;
        let table_base = usize::try_from(report.table_base).ok()?;
        let table_end = usize::try_from(report.table_end).ok()?;
        let alignment = match selected_isa {
            MandatoryTeddyIsa::X86Avx2 | MandatoryTeddyIsa::X86Avx512Bw => {
                X86_MANDATORY_TEDDY_ALIGNMENT
            }
            MandatoryTeddyIsa::Aarch64Asimd
            | MandatoryTeddyIsa::Aarch64Sve
            | MandatoryTeddyIsa::Aarch64Sve2 => AARCH64_MANDATORY_TEDDY_ALIGNMENT,
        };
        let expected_data_end = table_end.checked_add(auxiliary_bytes)?;
        let expected_masks_offset = expected_data_end.checked_add(7)? & !7;
        if report.source_count != u32::try_from(literals.len()).ok()?
            || report.minimum_width != u32::try_from(minimum_width).ok()?
            || report.maximum_width != u32::try_from(maximum_width).ok()?
            || report.columns != plan.columns()
            || report.bucket_count != plan.bucket_count()
            || report.literal_count != plan.literal_count()
            || report.candidate_fingerprint_upper_bound != plan.candidate_fingerprint_upper_bound()
            || report.candidate_frequency_upper_bound != plan.candidate_frequency_upper_bound()
            || report.fingerprint_space != plan.fingerprint_space()
            || report.plan_scan_instruction_units != plan.scan_instruction_units()
            || report.emitted_scan_instruction_units != tier.scan_instruction_units
            || report.guaranteed_vector_bytes != tier.block_bytes
            || report.gate_table_bytes != expected_gate_table_bytes
            || !table_base.is_multiple_of(alignment)
            || table_end.checked_sub(table_base) != Some(tier.table_bytes)
            || expected_data_end > data.len()
            || usize::try_from(report.bucket_ordinal_masks_offset).ok()
                != Some(expected_masks_offset)
            || !exact_teddy_tables_authenticate(report, data, plan, selected_isa)?
            || !exact_bucket_masks_authenticate(report, data, &literals, plan)?
        {
            return Some(false);
        }
        if report.input_floor_bytes != EXACT_FINITE_PREFIX_MIN_INPUT_BYTES
            || report.selection_horizon_bytes != EXACT_FINITE_PREFIX_MIN_INPUT_BYTES
            || report.runtime_verification_budget != EXACT_FINITE_TEDDY_RUNTIME_VERIFICATION_BUDGET
        {
            return Some(false);
        }
        let costs = selected.costs;
        Some(
            report.selection_gate_cost_units == costs.gate_cost_units
                && report.selection_expected_verification_cost_units
                    == costs.expected_verification_cost_units
                && report.selection_full_cost_units == costs.full_cost_units
                && report.selection_incumbent_cost_units == costs.incumbent_cost_units
                && report.selection_root_frequency_units == costs.root_frequency_units
                && report.selection_no_candidate_numerator == costs.no_candidate_numerator
                && report.selection_probability_denominator == costs.probability_denominator
                && report_plan_digest(report, data)
                    .is_some_and(|digest| digest == report.prefix_plan_sha256),
        )
    })()
    .unwrap_or(false))
}

#[allow(
    clippy::too_many_arguments,
    reason = "aggregate composition refreshes the full-module hashes and then replays exact attachment validation"
)]
pub(super) fn refresh_report_parts(
    report: &mut ExactFiniteSelectedEndTeddyAotReport,
    code: &[u8],
    data: &[u8],
    relocations: &[ModuleRelocation],
    needs_runtime: bool,
    has_slow_partial_table: bool,
    start_accelerator: StartAccelerator,
    anchored_prefix_filter_bytes: u8,
    target: Target,
) -> Result<(), ObjectError> {
    report.native_code_sha256 = Sha256::digest(code).into();
    report.native_data_sha256 = Sha256::digest(data).into();
    report.relocations_sha256 = relocation_digest(relocations).ok_or(
        ObjectError::InvalidModule("exact finite SelectedEnd Teddy aggregate relocation digest"),
    )?;
    report.native_data_bytes = data.len();
    if !report_matches_parts(
        report,
        code,
        data,
        relocations,
        needs_runtime,
        has_slow_partial_table,
        start_accelerator,
        anchored_prefix_filter_bytes,
        target,
    )? {
        return Err(ObjectError::InvalidModule(
            "exact finite SelectedEnd Teddy aggregate composition changed its ordinary entry",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CompileMode, CompileRequest, CompiledRegex, MatchResult, OptimizationPass, SearchWindow,
        compile,
    };

    const SCANNER_FREE_BYTES: [u8; 17] = [
        0x00, 0x12, 0x3f, 0x51, 0x7e, 0x8a, 0x92, 0xa4, 0x0c, 0x18, 0x1e, 0x58, 0x5e, 0x8f, 0x98,
        0x9e, 0xaa,
    ];

    fn scanner_free_exact_finite_pattern() -> String {
        let mut pattern = String::from("(?-u:");
        for ordinal in 0_u8..17 {
            if ordinal != 0 {
                pattern.push('|');
            }
            let byte = SCANNER_FREE_BYTES[usize::from(ordinal)];
            for _ in 0..6 {
                pattern.push_str(&format!("\\x{byte:02x}"));
            }
            if ordinal == 16 {
                pattern.push_str("\\xaa");
            }
        }
        pattern.push(')');
        pattern
    }

    fn scanner_free_overlapping_pattern(long_first: bool) -> String {
        let mut pattern = scanner_free_exact_finite_pattern();
        pattern.pop();
        let short = "\\xaa\\xaa\\xaa\\xaa\\xaa\\xaa";
        if long_first {
            pattern.push('|');
            pattern.push_str(short);
        } else {
            let long = "\\xaa\\xaa\\xaa\\xaa\\xaa\\xaa\\xaa";
            let long_start = pattern.rfind(long).unwrap();
            pattern.replace_range(long_start.., short);
            pattern.push('|');
            pattern.push_str(long);
        }
        pattern.push(')');
        pattern
    }

    fn coalesced_start_exact_finite_pattern() -> String {
        let mut pattern = String::from("(?-u:");
        for ordinal in 0_u8..9 {
            if ordinal != 0 {
                pattern.push('|');
            }
            let byte = ordinal.wrapping_mul(10);
            for _ in 0..6 {
                pattern.push_str(&format!("\\x{byte:02x}"));
            }
            if ordinal == 8 {
                pattern.push_str("\\x50");
            }
        }
        pattern.push(')');
        pattern
    }

    fn dense_scanner_free_exact_finite_pattern() -> String {
        let mut pattern = String::from("(?-u:");
        for ordinal in 0_u8..64 {
            if ordinal != 0 {
                pattern.push('|');
            }
            let byte = ordinal.wrapping_mul(4);
            for _ in 0..6 + usize::from(ordinal == 63) {
                pattern.push_str(&format!("\\x{byte:02x}"));
            }
        }
        pattern.push(')');
        pattern
    }

    fn suffix_only_exact_finite_pattern() -> String {
        let mut pattern = String::from("(?-u:");
        for (ordinal, byte) in SCANNER_FREE_BYTES.into_iter().enumerate() {
            if ordinal != 0 {
                pattern.push('|');
            }
            for _ in 0..5 + usize::from(ordinal == 16) {
                pattern.push_str(&format!("\\x{byte:02x}"));
            }
            pattern.push_str("\\xff");
        }
        pattern.push(')');
        pattern
    }

    fn avx2_target() -> Target {
        Target::x86_64_linux()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .expect("valid AVX2 target")
    }

    fn compile_selected(pattern: &str, target: Target) -> CompiledRegex {
        let compiled = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        )
        .expect("compile exact finite SelectedEnd Teddy fixture");
        let report = compiled
            .receipt()
            .exact_finite_selected_end_teddy_aot
            .unwrap_or_else(|| {
                let view = compiled.program().native_finite_selected_end_teddy_view();
                let semantic = compiled.program().native_dfa_view().unwrap();
                let cost = NativeCompleteDfaCost::estimate_selected_end(&semantic)
                    .unwrap()
                    .unwrap();
                let incumbent = lower_native_dfa(semantic, target).unwrap().unwrap();
                let baseline = cost.selected_end_report(&semantic, &incumbent).unwrap();
                panic!(
                    "direct exact finite SelectedEnd Teddy route: pattern={pattern:?} engine={:?} view={} static_accelerator={} scanner={:?} baseline={} selection={}",
                    compiled.receipt().engine,
                    view.is_some(),
                    cost.has_accelerator,
                    incumbent.start_accelerator,
                    baseline.is_some(),
                    view.zip(baseline)
                        .and_then(|(view, baseline)|
                            select_exact_finite_selected_end_teddy(view, target, baseline))
                        .is_some(),
                )
            });
        assert_eq!(report.output, OutputContract::SelectedEnd);
        assert!((4..=64).contains(&report.source_count));
        assert!(report.minimum_width >= 3);
        assert!(report.bucket_count <= 8);
        assert_eq!(
            report.runtime_verification_budget,
            EXACT_FINITE_TEDDY_RUNTIME_VERIFICATION_BUDGET,
        );
        assert!(compiled.receipt().ordered_finite_language_aot.is_none());
        assert!(
            compiled
                .module()
                .ordered_finite_language_aot_report()
                .is_none(),
        );
        assert!(
            compiled
                .receipt()
                .passes
                .contains(&OptimizationPass::ExactFiniteSelectedEndTeddyLowering),
        );
        compiled
    }

    fn complete_dfa_baseline(
        compiled: &CompiledRegex,
        target: Target,
    ) -> (NativeLowering, ExactFiniteSelectedEndDfaBaselineReport) {
        let semantic = compiled
            .program()
            .native_dfa_view()
            .expect("complete SelectedEnd semantic DFA");
        let cost = NativeCompleteDfaCost::estimate_selected_end(&semantic)
            .unwrap()
            .expect("SelectedEnd baseline cost");
        let incumbent = lower_native_dfa(semantic, target)
            .unwrap()
            .expect("SelectedEnd baseline lowering");
        let report = cost
            .selected_end_report(&semantic, &incumbent)
            .unwrap()
            .expect("SelectedEnd baseline report");
        (incumbent, report)
    }

    fn unchanged_selected_end_module(compiled: &CompiledRegex, target: Target) -> CompiledModule {
        let program = compiled.program();
        CompiledModule::lower_serialized(
            program.serialize().unwrap(),
            program.native_dfa_view(),
            false,
            program.native_context_program_view(),
            program.native_bit_parallel_exists_view(),
            program.native_bit_parallel_endpoint_oracle_view(),
            program.native_partial_dfa_view(),
            program.native_dynamic_rows_view(),
            program
                .native_ordered_nfa_view()
                .map(|view| (view, usize::MAX)),
            target,
        )
        .unwrap()
    }

    fn assert_byte_identical_module(left: &CompiledModule, right: &CompiledModule) {
        assert_eq!(left.sections(), right.sections());
        assert_eq!(left.symbols(), right.symbols());
        assert_eq!(left.relocations(), right.relocations());
        assert_eq!(left.start_accelerator(), right.start_accelerator());
        assert_eq!(
            left.anchored_prefix_filter_bytes(),
            right.anchored_prefix_filter_bytes(),
        );
        assert_eq!(
            left.required_runtime_symbols().collect::<Vec<_>>(),
            right.required_runtime_symbols().collect::<Vec<_>>(),
        );
    }

    /// Exercise verifier-table invariants that require fewer than eight
    /// buckets without weakening the top-level no-accelerator admission gate.
    fn lower_level_accelerated_fixture(
        pattern: &str,
        target: Target,
    ) -> (NativeLowering, ExactFiniteSelectedEndTeddyAotReport) {
        let compiled = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        )
        .unwrap();
        let semantic = compiled.program().native_dfa_view().unwrap();
        let cost = NativeCompleteDfaCost::estimate_selected_end(&semantic)
            .unwrap()
            .unwrap();
        assert!(cost.has_accelerator);
        let mut incumbent = lower_native_dfa(semantic, target).unwrap().unwrap();
        incumbent.start_accelerator = StartAccelerator::None;
        let baseline = ExactFiniteSelectedEndDfaBaselineReport {
            semantic_dfa_sha256: native_selected_end_dfa_semantic_digest(&semantic).unwrap(),
            forward_states: semantic.dfa.forward_cells.len() / semantic.dfa.class_count,
            alphabet_classes: semantic.dfa.class_count,
            transition_cells: cost.transition_cells,
            minimum_native_data_bytes: cost.minimum_data_bytes,
            native_data_bytes: incumbent.data.len(),
            hot_loads_per_byte: cost.hot_loads_per_byte,
            hot_branches_per_byte: cost.hot_branches_per_byte,
            has_accelerator: false,
            scanner: StartAccelerator::None,
        };
        let selection = select_exact_finite_selected_end_teddy(
            compiled
                .program()
                .native_finite_selected_end_teddy_view()
                .unwrap(),
            target,
            baseline,
        )
        .unwrap();
        let ExactFiniteSelectedEndTeddyWrapOutcome::Selected { lowering, report } =
            wrap_exact_finite_selected_end_teddy(
                selection,
                incumbent,
                baseline,
                target,
                usize::MAX,
            )
            .unwrap()
        else {
            unreachable!()
        };
        (lowering, report)
    }

    #[test]
    fn selected_end_teddy_route_is_narrow_and_receipted_on_every_isa_tier() {
        let targets = [
            avx2_target(),
            Target::x86_64_linux()
                .with_features(
                    FeatureSet::of(CpuFeature::X86Avx2)
                        .with(CpuFeature::X86Avx512F)
                        .with(CpuFeature::X86Avx512Bw),
                )
                .unwrap(),
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Sve))
                .unwrap(),
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2))
                .unwrap(),
        ];
        let pattern = scanner_free_exact_finite_pattern();
        for target in targets {
            let compiled = compile_selected(&pattern, target);
            let report = compiled
                .receipt()
                .exact_finite_selected_end_teddy_aot
                .unwrap();
            assert!(!report.incumbent_complete_dfa.has_accelerator);
            assert_eq!(
                report.incumbent_complete_dfa.scanner,
                StartAccelerator::None,
            );
            assert_eq!(report.target, target);
            assert!(report.literal_descriptors_offset > report.bucket_ordinal_masks_offset);
            assert!(report.literal_bytes_end > report.literal_bytes_offset);
            assert!(
                report_matches_parts(
                    &report,
                    compiled.module().sections()[TEXT_SECTION].bytes(),
                    compiled.module().sections()[PROGRAM_SECTION].bytes(),
                    compiled.module().relocations(),
                    false,
                    false,
                    compiled.module().start_accelerator(),
                    compiled.module().anchored_prefix_filter_bytes(),
                    target,
                )
                .unwrap()
            );
        }
        for long_first in [false, true] {
            compile_selected(&scanner_free_overlapping_pattern(long_first), avx2_target());
        }

        for output in [OutputContract::Exists, OutputContract::Span] {
            let compiled = compile(
                CompileRequest::new("samwise|sam|frodo|pippin", avx2_target())
                    .mode(CompileMode::Optimizing)
                    .output(output),
            )
            .unwrap();
            assert!(
                compiled
                    .receipt()
                    .exact_finite_selected_end_teddy_aot
                    .is_none()
            );
        }
        for pattern in ["alpha|bravo|cider", "aa|bb|cc|dd"] {
            let compiled = compile(
                CompileRequest::new(pattern, avx2_target())
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            )
            .unwrap();
            assert!(
                compiled
                    .receipt()
                    .exact_finite_selected_end_teddy_aot
                    .is_none()
            );
        }
        let sixty_five_arms = (0..65)
            .map(|ordinal| format!("x{ordinal:02}"))
            .collect::<Vec<_>>()
            .join("|");
        let compiled = compile(
            CompileRequest::new(&sixty_five_arms, avx2_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        )
        .unwrap();
        assert!(
            compiled
                .receipt()
                .exact_finite_selected_end_teddy_aot
                .is_none()
        );
    }

    #[test]
    fn accelerator_classes_decline_before_semantic_incumbent_publication_changes() {
        let target = avx2_target();
        let fixtures = [
            ("exact-start", "samwise|samw|frodo|pippin".to_owned()),
            ("coalesced-start", coalesced_start_exact_finite_pattern()),
            ("suffix", suffix_only_exact_finite_pattern()),
            ("loop", "(?-u:[^Z])+Z".to_owned()),
        ];
        for (kind, pattern) in fixtures {
            let compiled = compile(
                CompileRequest::new(&pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            )
            .unwrap();
            let view = compiled.program().native_dfa_view().unwrap();
            let start = derive_start_filter(view).unwrap().is_some();
            let coalesced = derive_coalesced_initial_start_filter(view)
                .unwrap()
                .is_some();
            let suffix = derive_suffix_filter(view).unwrap().is_some();
            let loop_skip = dfa_loop_skip::select_dfa_loop_skip(&view.dfa, view.output).is_some();
            match kind {
                "exact-start" => assert!(start),
                "coalesced-start" => assert!(!start && coalesced),
                "suffix" => assert!(suffix),
                "loop" => assert!(loop_skip),
                _ => unreachable!(),
            }
            let cost = NativeCompleteDfaCost::estimate_selected_end(&view)
                .unwrap()
                .unwrap();
            assert!(cost.has_accelerator, "{kind}");
            let incumbent = lower_native_dfa(view, target).unwrap().unwrap();
            assert!(
                cost.selected_end_report(&view, &incumbent)
                    .unwrap()
                    .is_none(),
                "{kind}",
            );
            assert!(
                compiled
                    .receipt()
                    .exact_finite_selected_end_teddy_aot
                    .is_none(),
                "{kind}",
            );
            assert!(compiled.receipt().ordered_finite_language_aot.is_none());
            let unchanged = unchanged_selected_end_module(&compiled, target);
            assert_byte_identical_module(compiled.module(), &unchanged);
        }
    }

    #[test]
    fn noncompetitive_dense_selected_end_keeps_unchanged_semantic_dfa() {
        let target = avx2_target();
        let compiled = compile(
            CompileRequest::new(dense_scanner_free_exact_finite_pattern(), target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        )
        .unwrap();
        let semantic = compiled.program().native_dfa_view().unwrap();
        let cost = NativeCompleteDfaCost::estimate_selected_end(&semantic)
            .unwrap()
            .unwrap();
        assert!(!cost.has_accelerator);
        let incumbent = lower_native_dfa(semantic, target).unwrap().unwrap();
        let baseline = cost
            .selected_end_report(&semantic, &incumbent)
            .unwrap()
            .unwrap();
        assert!(
            select_exact_finite_selected_end_teddy(
                compiled
                    .program()
                    .native_finite_selected_end_teddy_view()
                    .unwrap(),
                target,
                baseline,
            )
            .is_none(),
        );
        assert!(
            compiled
                .receipt()
                .exact_finite_selected_end_teddy_aot
                .is_none(),
        );
        assert!(compiled.receipt().ordered_finite_language_aot.is_none());
        assert_byte_identical_module(
            compiled.module(),
            &unchanged_selected_end_module(&compiled, target),
        );
    }

    #[test]
    fn sve_false_candidate_retry_restores_predicate_nibble_mask_and_vl() {
        for features in [
            FeatureSet::of(CpuFeature::Aarch64Sve),
            FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2),
        ] {
            let target = Target::aarch64_linux().with_features(features).unwrap();
            let compiled = compile_selected(&scanner_free_exact_finite_pattern(), target);
            let code = compiled.module().sections()[TEXT_SECTION].bytes();
            let words = code
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            let restore = [
                aarch64_sve_ptrue_b(),
                aarch64_sve_dup_b_imm(26, 0x0f).unwrap(),
                aarch64_sve_cntb(6).unwrap(),
            ];
            let retry_target = words
                .windows(restore.len())
                .position(|window| window == restore)
                .expect("SVE retry rematerialization sequence");
            let retry_advance = aarch64_add_x_imm(2, 2, 1).unwrap();
            let branches_to_restore = words
                .iter()
                .enumerate()
                .filter(|(index, word)| {
                    if **word & 0xfc00_0000 != 0x1400_0000
                        || *index == 0
                        || words[*index - 1] != retry_advance
                    {
                        return false;
                    }
                    let immediate = (((**word & 0x03ff_ffff) as i32) << 6) >> 6;
                    isize::try_from(*index)
                        .ok()
                        .and_then(|origin| origin.checked_add(immediate as isize))
                        .and_then(|target| usize::try_from(target).ok())
                        == Some(retry_target)
                })
                .count();
            assert_eq!(branches_to_restore, 1, "target={target:?}");
            assert!(
                words
                    .iter()
                    .filter(|&&word| word == aarch64_sve_ptrue_b())
                    .count()
                    >= 2,
                "constant load and retry must each establish P0",
            );
        }
    }

    #[test]
    fn x86_verification_budget_tail_restores_public_abi() {
        let compiled = compile_selected(&scanner_free_exact_finite_pattern(), avx2_target());
        let code = compiled.module().sections()[TEXT_SECTION].bytes();
        let restore = [
            0x4c, 0x89, 0xe6, // rsi = public length
            0x4c, 0x89, 0xe9, // rcx = public end
            0x4d, 0x89, 0xf0, // r8 = public result
            0x41, 0x5e, // pop r14
            0x41, 0x5d, // pop r13
            0x5b, // pop rbx
            0x41, 0x5c, // pop r12
            0xc5, 0xf8, 0x77, // vzeroupper
        ];
        let target = code
            .windows(restore.len())
            .position(|window| window == restore)
            .expect("full ABI restore sequence");
        let long_budget_branch = code
            .windows(8)
            .enumerate()
            .filter(|(_, window)| window[..4] == [0x85, 0xdb, 0x0f, 0x84])
            .any(|(budget_test, window)| {
                let displacement = i32::from_le_bytes(
                    window[4..8]
                        .try_into()
                        .expect("complete conditional branch displacement"),
                );
                let after = isize::try_from(budget_test + 8).unwrap();
                usize::try_from(after + displacement as isize).ok() == Some(target)
            });
        let short_budget_branch = code.windows(4).enumerate().any(|(budget_test, window)| {
            if window[..3] != [0x85, 0xdb, 0x74] {
                return false;
            }
            let displacement = i8::from_le_bytes([window[3]]);
            let after = isize::try_from(budget_test + 4).unwrap();
            usize::try_from(after + isize::from(displacement)).ok() == Some(target)
        });
        assert!(
            long_budget_branch || short_budget_branch,
            "verification-budget branch targets the full ABI restore sequence",
        );
        assert!(matches!(
            code.get(target + restore.len()),
            Some(0xeb | 0xe9)
        ));
    }

    #[test]
    fn declared_native_data_cap_declines_unchanged_and_exact_boundary_selects() {
        let target = avx2_target();
        let pattern = scanner_free_exact_finite_pattern();
        let compiled = compile_selected(&pattern, target);
        let teddy_view = compiled
            .program()
            .native_finite_selected_end_teddy_view()
            .unwrap();
        let (incumbent, incumbent_report) = complete_dfa_baseline(&compiled, target);
        let selection =
            select_exact_finite_selected_end_teddy(teddy_view, target, incumbent_report).unwrap();
        let required =
            exact_finite_selected_end_teddy_required_data_bytes(selection, incumbent.data.len())
                .unwrap();
        let original_code = incumbent.code.clone();
        let original_data = incumbent.data.clone();
        let original_relocations = incumbent.relocations.clone();
        let original_scanner = incumbent.start_accelerator;
        let original_prefix = incumbent.anchored_prefix_filter_bytes;
        let ExactFiniteSelectedEndTeddyWrapOutcome::ResourceDeclined(restored) =
            wrap_exact_finite_selected_end_teddy(
                selection,
                incumbent,
                incumbent_report,
                target,
                required - 1,
            )
            .unwrap()
        else {
            panic!("one-byte-short declared ceiling must decline")
        };
        assert_eq!(restored.code, original_code);
        assert_eq!(restored.data, original_data);
        assert_eq!(restored.relocations, original_relocations);
        assert_eq!(restored.start_accelerator, original_scanner);
        assert_eq!(restored.anchored_prefix_filter_bytes, original_prefix);

        let (incumbent, incumbent_report) = complete_dfa_baseline(&compiled, target);
        let ExactFiniteSelectedEndTeddyWrapOutcome::Selected { lowering, report } =
            wrap_exact_finite_selected_end_teddy(
                selection,
                incumbent,
                incumbent_report,
                target,
                required,
            )
            .unwrap()
        else {
            panic!("exact declared ceiling must admit")
        };
        assert_eq!(lowering.data.len(), required);
        assert_eq!(report.native_data_bytes, required);

        let unchanged = unchanged_selected_end_module(&compiled, target);
        let capped = crate::compile_with_slow_aot_limits(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
            crate::SlowAotLimits {
                max_native_data_bytes: required - 1,
                ..crate::SlowAotLimits::default()
            },
        )
        .unwrap();
        assert!(
            capped
                .receipt()
                .exact_finite_selected_end_teddy_aot
                .is_none(),
        );
        assert!(capped.receipt().ordered_finite_language_aot.is_none());
        assert_byte_identical_module(capped.module(), &unchanged);
    }

    #[test]
    fn prepared_aggregate_refreshes_exact_teddy_receipt() {
        let compiled = crate::compile_with_prepared_aggregate_exports(
            CompileRequest::new(scanner_free_exact_finite_pattern(), avx2_target())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
            crate::PreparedAggregateExports::GREP_COUNT,
        )
        .unwrap();
        let receipt = compiled
            .receipt()
            .exact_finite_selected_end_teddy_aot
            .expect("aggregate receipt retains refreshed exact Teddy leaf");
        assert_eq!(
            compiled
                .module()
                .exact_finite_selected_end_teddy_aot_report(),
            Some(&receipt),
        );
        assert_ne!(receipt.native_code_sha256, receipt.incumbent_code_sha256);
        assert!(
            compiled
                .receipt()
                .passes
                .contains(&OptimizationPass::ExactFiniteSelectedEndTeddyLowering),
        );
    }

    #[test]
    fn prepared_aggregate_object_cap_restores_exact_complete_dfa_incumbent() {
        let pattern = scanner_free_exact_finite_pattern();
        let target = avx2_target();
        let exports = crate::PreparedAggregateExports::GREP_COUNT;
        let request = |max_object_bytes| {
            CompileRequest::new(&pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd)
                .limits(crate::CompileLimitsV1 {
                    max_object_bytes,
                    ..crate::CompileLimitsV1::default()
                })
        };

        let base = compile(request(usize::MAX)).expect("unbounded Teddy base object");
        let selected = crate::compile_with_prepared_aggregate_exports(
            request(usize::MAX),
            exports,
        )
        .expect("unbounded Teddy aggregate object");
        let report = selected
            .receipt()
            .exact_finite_selected_end_teddy_aot
            .expect("fixture selects the exact Teddy aggregate route");

        let serialized = selected.program().serialize().unwrap();
        let incumbent_base =
            CompiledModule::lower_with_native_data_limit_and_optional_routes(
                selected.program(),
                target,
                false,
                false,
                report.incumbent_data_bytes,
            )
            .expect("rebuild exact ordinary complete-DFA incumbent");
        assert!(
            incumbent_base
                .exact_finite_selected_end_teddy_aot_report()
                .is_none(),
        );
        assert!(incumbent_base.ordered_finite_language_aot_report().is_none());
        assert!(incumbent_base.slow_aot_report().is_none());
        assert!(incumbent_base.slow_context_aot_report().is_none());
        assert!(incumbent_base.compiler_k0_aot_report().is_none());
        assert_eq!(incumbent_base.start_accelerator(), report.incumbent_complete_dfa.scanner);
        assert_eq!(incumbent_base.sections()[1].bytes().len(), report.incumbent_data_bytes);
        assert_eq!(
            Sha256::digest(incumbent_base.sections()[0].bytes()).as_slice(),
            report.incumbent_code_sha256,
        );
        assert_eq!(
            Sha256::digest(incumbent_base.sections()[1].bytes()).as_slice(),
            report.incumbent_data_sha256,
        );
        assert_eq!(
            relocation_digest(incumbent_base.relocations()),
            Some(report.incumbent_relocations_sha256),
        );
        let incumbent = incumbent_base
            .append_prepared_aggregate_exports(
                exports,
                selected.program().artifact_identity(),
                &serialized,
            )
            .expect("append aggregate export to exact incumbent");
        let incumbent_object = crate::emit_object(
            &incumbent,
            crate::ObjectFormat::for_target(target),
            usize::MAX,
        )
        .expect("emit exact incumbent aggregate object");

        assert!(incumbent_object.len() < selected.object().len());
        assert!(base.object().len() < incumbent_object.len());
        let exact_incumbent = crate::compile_with_prepared_aggregate_exports(
            request(incumbent_object.len()),
            exports,
        )
        .expect("exact complete-DFA aggregate boundary succeeds");
        assert_eq!(exact_incumbent.module(), &incumbent);
        assert_eq!(exact_incumbent.object(), incumbent_object);
        assert!(
            exact_incumbent
                .receipt()
                .exact_finite_selected_end_teddy_aot
                .is_none(),
        );
        assert!(
            !exact_incumbent
                .receipt()
                .passes
                .contains(&OptimizationPass::ExactFiniteSelectedEndTeddyLowering),
        );

        let one_below = incumbent_object
            .len()
            .checked_sub(1)
            .expect("nonempty incumbent aggregate object");
        assert!(base.object().len() <= one_below);
        let error = crate::compile_with_prepared_aggregate_exports(
            request(one_below),
            exports,
        )
        .expect_err("Teddy and complete-DFA aggregate objects both exceed the lower cap");
        assert!(matches!(
            error,
            crate::CompileError::Object(ObjectError::Resource {
                resource: crate::CompileResource::ObjectBytes,
                limit,
                required,
            }) if limit == one_below && required == selected.object().len()
        ));
    }

    #[test]
    fn verifier_metadata_is_source_order_complete_and_mutation_rejected() {
        let target = avx2_target();
        let compiled = compile_selected(&scanner_free_exact_finite_pattern(), target);
        let report = compiled
            .receipt()
            .exact_finite_selected_end_teddy_aot
            .unwrap();
        let data = compiled.module().sections()[PROGRAM_SECTION].bytes();
        assert!(verifier_data_authenticates(&report, data).unwrap());

        let mut changed = data.to_vec();
        changed[usize::try_from(report.bucket_ordinal_masks_offset).unwrap()] ^= 1;
        let mut changed_report = report;
        changed_report.native_data_sha256 = Sha256::digest(&changed).into();
        changed_report.prefix_plan_sha256 = report_plan_digest(&changed_report, &changed).unwrap();
        assert_eq!(
            report_costs_authenticate(&changed_report, &changed, target),
            Ok(false),
        );

        let (inactive_lowering, inactive_report) =
            lower_level_accelerated_fixture("samwise|samw|frodo|pippin", target);
        let inactive_data = inactive_lowering.data.as_slice();
        assert!(inactive_report.bucket_count < 8);
        let mut changed = inactive_data.to_vec();
        let inactive_mask = usize::try_from(inactive_report.bucket_ordinal_masks_offset).unwrap()
            + usize::from(inactive_report.bucket_count) * 8;
        changed[inactive_mask] = 1;
        let mut changed_report = inactive_report;
        changed_report.native_data_sha256 = Sha256::digest(&changed).into();
        changed_report.prefix_plan_sha256 = report_plan_digest(&changed_report, &changed).unwrap();
        assert_eq!(
            report_costs_authenticate(&changed_report, &changed, target),
            Ok(false),
        );

        let mut changed = data.to_vec();
        changed[usize::try_from(report.table_base).unwrap()] ^= 1;
        let mut changed_report = report;
        changed_report.native_data_sha256 = Sha256::digest(&changed).into();
        changed_report.prefix_plan_sha256 = report_plan_digest(&changed_report, &changed).unwrap();
        assert_eq!(
            report_costs_authenticate(&changed_report, &changed, target),
            Ok(false),
        );

        let mut changed_report = report;
        changed_report.root_members[0] ^= 1 << 5;
        changed_report.prefix_plan_sha256 = report_plan_digest(&changed_report, data).unwrap();
        assert_eq!(
            report_costs_authenticate(&changed_report, data, target),
            Ok(false),
        );

        let mut changed_report = report;
        changed_report.selection_full_cost_units += 1;
        changed_report.prefix_plan_sha256 = report_plan_digest(&changed_report, data).unwrap();
        assert_eq!(
            report_costs_authenticate(&changed_report, data, target),
            Ok(false),
        );

        let mut changed = data.to_vec();
        changed[0] ^= 1;
        let mut changed_report = report;
        changed_report.incumbent_data_sha256 =
            Sha256::digest(&changed[..report.incumbent_data_bytes]).into();
        changed_report.native_data_sha256 = Sha256::digest(&changed).into();
        changed_report.prefix_plan_sha256 = report_plan_digest(&changed_report, &changed).unwrap();
        assert!(report_costs_authenticate(&changed_report, &changed, target).unwrap());
        assert!(
            !exact_finite_selected_end_dfa_lowering_authenticates(
                &compiled.program().native_dfa_view().unwrap(),
                target,
                &changed_report,
            )
            .unwrap(),
            "coherently rehashed incumbent bytes must still match the semantic DFA lowering",
        );

        let mut changed_report = report;
        changed_report.runtime_verification_budget += 1;
        changed_report.prefix_plan_sha256 = report_plan_digest(&changed_report, data).unwrap();
        assert_eq!(
            report_costs_authenticate(&changed_report, data, target),
            Ok(false),
        );

        let mut changed = data.to_vec();
        changed[usize::try_from(report.literal_descriptors_offset).unwrap()] ^= 1;
        assert!(!verifier_data_authenticates(&report, &changed).unwrap());
        let mut changed = data.to_vec();
        changed[usize::try_from(report.literal_bytes_offset).unwrap()] ^= 1;
        assert!(!verifier_data_authenticates(&report, &changed).unwrap());
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    fn linked_host_target() -> Option<Target> {
        if !std::arch::is_x86_feature_detected!("avx2") {
            return None;
        }
        let target = if cfg!(target_os = "linux") {
            Target::x86_64_linux()
        } else {
            Target::x86_64_macos()
        };
        target
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .ok()
    }

    #[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "macos")))]
    fn linked_host_target() -> Option<Target> {
        let target = if cfg!(target_os = "linux") {
            Target::aarch64_linux()
        } else {
            Target::aarch64_macos()
        };
        #[cfg(target_os = "linux")]
        let features = {
            let mut features = FeatureSet::of(CpuFeature::Aarch64Asimd);
            if std::arch::is_aarch64_feature_detected!("sve") {
                features = FeatureSet::of(CpuFeature::Aarch64Sve);
                if std::arch::is_aarch64_feature_detected!("sve2") {
                    features = features.with(CpuFeature::Aarch64Sve2);
                }
            }
            features
        };
        #[cfg(target_os = "macos")]
        let features = FeatureSet::of(CpuFeature::Aarch64Asimd);
        target.with_features(features).ok()
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    #[ignore = "links and executes the actual exact finite SelectedEnd Teddy leaf on the host ISA"]
    fn linked_host_selected_end_teddy_matches_fast_for_order_collisions_windows_and_binary_eof() {
        use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

        let Some(target) = linked_host_target() else {
            return;
        };
        let mut cases = Vec::<(String, Vec<(Vec<u8>, usize, usize)>)>::new();
        for long_first in [false, true] {
            let mut order_long = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256];
            order_long[83..90].fill(0xaa);
            let order_len = order_long.len();
            cases.push((
                scanner_free_overlapping_pattern(long_first),
                vec![
                    (order_long.clone(), 17, order_len),
                    (order_long[..128].to_vec(), 17, 128),
                    (
                        vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 64],
                        11,
                        EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 64,
                    ),
                ],
            ));
        }

        let collision_pattern = scanner_free_exact_finite_pattern();
        let collision_probe = compile_selected(&collision_pattern, target);
        let view = collision_probe
            .program()
            .native_finite_selected_end_teddy_view()
            .expect("collision exact finite view");
        let incumbent = collision_probe
            .receipt()
            .exact_finite_selected_end_teddy_aot
            .map(|report| report.incumbent_complete_dfa)
            .expect("collision complete-DFA incumbent");
        let selection = select_exact_finite_selected_end_teddy(view, target, incumbent)
            .expect("collision Teddy selection");
        let columns = usize::from(selection.plan.columns());
        let combinations = SCANNER_FREE_BYTES
            .len()
            .pow(u32::from(selection.plan.columns()));
        let mut collision = None;
        for mut ordinal in 0..combinations {
            let mut bytes = [0_u8; mandatory_teddy::MAX_MANDATORY_TEDDY_COLUMNS];
            for byte in bytes.iter_mut().take(columns) {
                *byte = SCANNER_FREE_BYTES[ordinal % SCANNER_FREE_BYTES.len()];
                ordinal /= SCANNER_FREE_BYTES.len();
            }
            let exact = view
                .literals()
                .iter()
                .any(|literal| literal[..columns] == bytes[..columns]);
            if !exact && selection.plan.candidate_buckets(&bytes[..columns]) != 0 {
                collision = Some(bytes);
                break;
            }
        }
        let collision = collision.expect("fixture has a conservative Teddy collision");
        let mut collision_long = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256];
        collision_long[64..64 + columns].copy_from_slice(&collision[..columns]);
        collision_long[192..198].fill(0);
        let mut collision_full_to_tail = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 257];
        let tail_collision = collision_full_to_tail.len() - 32;
        collision_full_to_tail[tail_collision..tail_collision + columns]
            .copy_from_slice(&collision[..columns]);
        let full_to_tail_len = collision_full_to_tail.len();
        collision_full_to_tail[full_to_tail_len - 6..].fill(0);
        let mut collision_last_base = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 71];
        let last_base = collision_last_base.len() - columns;
        collision_last_base[last_base..].copy_from_slice(&collision[..columns]);
        let collision_last_base_len = collision_last_base.len();
        let mut collision_budget_negative = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 1024];
        for candidate in 0..usize::from(EXACT_FINITE_TEDDY_RUNTIME_VERIFICATION_BUDGET) + 2 {
            let base = 64 + candidate * 8;
            collision_budget_negative[base..base + columns].copy_from_slice(&collision[..columns]);
        }
        let mut collision_budget_positive = collision_budget_negative.clone();
        let budget_match = collision_budget_positive.len() - 6;
        collision_budget_positive[budget_match..].fill(0);
        let collision_budget_len = collision_budget_negative.len();
        cases.push((
            collision_pattern,
            vec![
                (
                    collision_long,
                    19,
                    EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256,
                ),
                (collision_full_to_tail, 13, full_to_tail_len),
                (collision_last_base, 7, collision_last_base_len),
                (collision_budget_negative, 19, collision_budget_len),
                (collision_budget_positive, 19, collision_budget_len),
            ],
        ));

        let mut binary_eof = vec![0x7e; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 73];
        let binary_len = binary_eof.len();
        binary_eof[binary_len - 6..].fill(0);
        cases
            .last_mut()
            .expect("collision case")
            .1
            .push((binary_eof, 23, binary_len));

        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-finite-selected-end-teddy-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir_all(&directory).unwrap();
        let mut source = String::from("#include <stdint.h>\n#include <stddef.h>\n");
        let mut calls = String::from("int main(void){size_t r[2];uint32_t s;\n");
        let mut objects = Vec::new();
        for (artifact, (pattern, windows)) in cases.iter().enumerate() {
            let compiled = compile_selected(pattern, target);
            let reference = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Fast)
                    .output(OutputContract::SelectedEnd),
            )
            .unwrap();
            let symbol = compiled.module().entry_symbol();
            writeln!(
                source,
                "extern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);",
            )
            .unwrap();
            let object = directory.join(format!("case{artifact}.o"));
            fs::write(&object, compiled.object()).unwrap();
            objects.push(object);
            for (window_index, (haystack, start, end)) in windows.iter().enumerate() {
                let bytes = haystack
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                writeln!(
                    source,
                    "static const unsigned char h{artifact}_{window_index}[]={{{bytes}}};",
                )
                .unwrap();
                let expected = reference
                    .search(haystack, SearchWindow::new(*start, *end))
                    .unwrap();
                writeln!(
                    calls,
                    "r[0]=91;r[1]=92;s={symbol}(h{artifact}_{window_index},{},{start},{end},r);",
                    haystack.len(),
                )
                .unwrap();
                let failure = 10 + artifact * 10 + window_index;
                match expected {
                    MatchResult::SelectedEnd(Some(selected_end)) => writeln!(
                        calls,
                        "if(s!=1||r[0]!={selected_end}||r[1]!={selected_end})return {failure};",
                    ),
                    MatchResult::SelectedEnd(None) => {
                        writeln!(calls, "if(s!=0||r[0]!=0||r[1]!=0)return {failure};",)
                    }
                    _ => unreachable!(),
                }
                .unwrap();
            }
            let invalid_len = windows[0].0.len();
            writeln!(
                calls,
                "r[0]=91;r[1]=92;s={symbol}(h{artifact}_0,{invalid_len},1,0,r);if(s!=2||r[0]!=91||r[1]!=92)return {};",
                80 + artifact,
            )
            .unwrap();
        }
        calls.push_str("return 0;}\n");
        source.push_str(&calls);
        let c_path = directory.join("selected_end_teddy.c");
        let executable = directory.join("selected_end_teddy");
        fs::write(&c_path, source).unwrap();
        let compiler = if cfg!(target_os = "macos") {
            "clang"
        } else {
            "cc"
        };
        let status = Command::new(compiler)
            .arg("-O0")
            .arg(&c_path)
            .args(&objects)
            .arg("-o")
            .arg(&executable)
            .status()
            .expect("link actual SelectedEnd Teddy differential");
        assert!(status.success());
        let output = Command::new(&executable).output().unwrap();
        assert!(
            output.status.success(),
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        fs::remove_dir_all(&directory).unwrap();
    }

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    #[test]
    #[ignore = "cross-links and executes the AVX2 exact finite SelectedEnd Teddy leaf through Rosetta"]
    fn linked_rosetta_avx2_selected_end_teddy_matches_fast_after_collision_budget() {
        use std::{fs, process::Command, time::SystemTime};

        let target = Target::x86_64_macos()
            .with_features(FeatureSet::of(CpuFeature::X86Avx2))
            .unwrap();
        let pattern = scanner_free_exact_finite_pattern();
        let compiled = compile_selected(&pattern, target);
        let reference = compile(
            CompileRequest::new(&pattern, target)
                .mode(CompileMode::Fast)
                .output(OutputContract::SelectedEnd),
        )
        .unwrap();
        let view = compiled
            .program()
            .native_finite_selected_end_teddy_view()
            .unwrap();
        let incumbent = compiled
            .receipt()
            .exact_finite_selected_end_teddy_aot
            .map(|report| report.incumbent_complete_dfa)
            .unwrap();
        let selection = select_exact_finite_selected_end_teddy(view, target, incumbent).unwrap();
        let columns = usize::from(selection.plan.columns());
        let combinations = SCANNER_FREE_BYTES
            .len()
            .pow(u32::from(selection.plan.columns()));
        let mut collision = None;
        for mut ordinal in 0..combinations {
            let mut bytes = [0_u8; mandatory_teddy::MAX_MANDATORY_TEDDY_COLUMNS];
            for byte in bytes.iter_mut().take(columns) {
                *byte = SCANNER_FREE_BYTES[ordinal % SCANNER_FREE_BYTES.len()];
                ordinal /= SCANNER_FREE_BYTES.len();
            }
            let exact = view
                .literals()
                .iter()
                .any(|literal| literal[..columns] == bytes[..columns]);
            if !exact && selection.plan.candidate_buckets(&bytes[..columns]) != 0 {
                collision = Some(bytes);
                break;
            }
        }
        let collision = collision.unwrap();
        let mut haystack = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 1024];
        for candidate in 0..usize::from(EXACT_FINITE_TEDDY_RUNTIME_VERIFICATION_BUDGET) + 2 {
            let base = 64 + candidate * 8;
            haystack[base..base + columns].copy_from_slice(&collision[..columns]);
        }
        let match_base = haystack.len() - 6;
        haystack[match_base..].fill(0);
        let start = 19;
        let end = haystack.len();
        let MatchResult::SelectedEnd(Some(expected)) = reference
            .search(&haystack, SearchWindow::new(start, end))
            .unwrap()
        else {
            panic!("fixture must match after its collision")
        };

        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-finite-selected-end-teddy-rosetta-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir_all(&directory).unwrap();
        let object = directory.join("teddy.o");
        fs::write(&object, compiled.object()).unwrap();
        let c_path = directory.join("teddy.c");
        let executable = directory.join("teddy");
        let bytes = haystack
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let symbol = compiled.module().entry_symbol();
        let source = format!(
            "#include <stdint.h>\n#include <stddef.h>\n#include <unistd.h>\nextern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\nstatic const unsigned char h[]={{{bytes}}};\nint main(void){{alarm(5);size_t r[2]={{91,92}};uint32_t s={symbol}(h,{},{start},{end},r);return s==1&&r[0]=={expected}&&r[1]=={expected}?0:17;}}\n",
            haystack.len(),
        );
        fs::write(&c_path, source).unwrap();
        let status = Command::new("clang")
            .args(["-arch", "x86_64", "-O0"])
            .arg(&c_path)
            .arg(&object)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap();
        assert!(status.success());
        let output = Command::new(&executable).output().unwrap();
        assert!(output.status.success(), "status={:?}", output.status.code());
        fs::remove_dir_all(&directory).unwrap();
    }
}
