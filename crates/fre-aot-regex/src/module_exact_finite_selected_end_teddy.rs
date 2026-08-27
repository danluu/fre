//! Authenticated direct exact-finite `SelectedEnd` Teddy leaf.
//!
//! Teddy finds candidate bases and buckets. A bucket-to-source-ordinal mask
//! then drives byte-exact verification in original alternation order. After a
//! false fingerprint, the wrapper consumes the remaining candidate lanes in
//! the current vector block before advancing; exhausted long windows return no
//! match directly. A bounded number of failed exact verifications keeps a
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
const EXACT_FINITE_EXISTS_INCUMBENT_TAIL_SETUP_UNITS: u128 = 64;
const EXACT_FINITE_TEDDY_RUNTIME_VERIFICATION_BUDGET: u16 = 64;
const EXACT_FINITE_TEDDY_ASIMD_VERIFIER_BYTES: u16 = 16;
const EXACT_FINITE_TEDDY_ASIMD_OVERLAP_MIN_RESIDUE: u16 = 5;
/// Frozen before timing: the scalable Teddy miss path scans four complete
/// runtime vectors while retaining each block's bucket vector. Candidate
/// predicates are materialized only after the batch is known to contain a hit.
const EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS: u8 = 4;
const EXACT_FINITE_TEDDY_UNBATCHED_VECTORS: u8 = 1;
const _: () = assert!(
    EXACT_FINITE_PREFIX_MIN_INPUT_BYTES
        >= EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS as usize
            * AARCH64_SVE_MAX_VECTOR_BYTES as usize
            + mandatory_teddy::MAX_MANDATORY_TEDDY_COLUMNS
            - 1
);
/// P1..P4 retain a four-vector batch, so the exact leaf must not use the
/// generic first-candidate helper's P2 scratch.
const EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH: u8 = 10;
/// LASTB only accepts P0..P7 as its governing predicate. P5 is outside the
/// retained P1..P4 batch and may be rematerialized for every selected lane.
const EXACT_FINITE_TEDDY_SVE_BUCKET_SCRATCH: u8 = 5;
/// Hard peak for the report validator's only transient rebuild allocation.
/// Sixty-four fat slice references occupy 1 KiB on supported 64-bit hosts;
/// the extra headroom keeps this an explicit compiler resource ceiling.
const EXACT_FINITE_TEDDY_VALIDATION_SCRATCH_LIMIT_BYTES: usize = 2 * 1024;
const EXACT_FINITE_TEDDY_NATIVE_DATA_ALLOCATION_SITE: &str =
    "exact finite SelectedEnd Teddy native data";

#[cfg(test)]
std::thread_local! {
    static EXACT_FINITE_TEDDY_NATIVE_DATA_ALLOCATION_INJECTION: std::cell::Cell<u8> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
struct ExactFiniteTeddyNativeDataAllocationInjection;

#[cfg(test)]
impl ExactFiniteTeddyNativeDataAllocationInjection {
    fn arm() -> Self {
        EXACT_FINITE_TEDDY_NATIVE_DATA_ALLOCATION_INJECTION.with(|state| {
            assert_eq!(
                state.replace(1),
                0,
                "exact-finite Teddy native-data allocation injection was already armed",
            );
        });
        Self
    }

    fn assert_failed_once(&self) {
        EXACT_FINITE_TEDDY_NATIVE_DATA_ALLOCATION_INJECTION.with(|state| {
            assert_eq!(
                state.get(),
                2,
                "exact-finite Teddy native-data allocation injection was not consumed exactly once",
            );
        });
    }
}

#[cfg(test)]
impl Drop for ExactFiniteTeddyNativeDataAllocationInjection {
    fn drop(&mut self) {
        EXACT_FINITE_TEDDY_NATIVE_DATA_ALLOCATION_INJECTION.with(|state| state.set(0));
    }
}

fn reserve_exact_finite_teddy_native_data(
    data: &mut Vec<u8>,
    additional: usize,
) -> Result<(), ObjectError> {
    #[cfg(test)]
    {
        let inject = EXACT_FINITE_TEDDY_NATIVE_DATA_ALLOCATION_INJECTION.with(|state| {
            match state.get() {
                0 => false,
                1 => {
                    state.set(2);
                    true
                }
                2 => panic!(
                    "exact-finite Teddy native-data allocation was retried after failure"
                ),
                _ => unreachable!("invalid exact-finite Teddy allocation injection state"),
            }
        });
        if inject {
            return Err(ObjectError::Allocation(
                EXACT_FINITE_TEDDY_NATIVE_DATA_ALLOCATION_SITE,
            ));
        }
    }
    data.try_reserve_exact(additional)
        .map_err(|_| ObjectError::Allocation(EXACT_FINITE_TEDDY_NATIVE_DATA_ALLOCATION_SITE))
}

/// Common, source-authenticated literal surface consumed by the mature Teddy
/// scanner and exact verifier. Output-specific sidecars project only facts
/// rechecked at this lowering boundary.
#[derive(Clone, Copy, Debug)]
struct ExactFiniteTeddyLiteralView<'a> {
    artifact_identity: [u8; 32],
    output: OutputContract,
    literals: &'a [Vec<u8>],
    portfolio: MandatoryTeddyPortfolio,
    minimum_width: u32,
    maximum_width: u32,
    root_members: [u64; 4],
    source_count: u32,
    total_source_bytes: usize,
    literal_digest: [u8; 32],
}

const fn exact_finite_exists_teddy_source_count_is_supported(source_count: usize) -> bool {
    source_count >= 4 && source_count <= 64
}

impl<'a> ExactFiniteTeddyLiteralView<'a> {
    const fn from_selected_end(view: NativeFiniteSelectedEndTeddyView<'a>) -> Self {
        Self {
            artifact_identity: view.artifact_identity(),
            output: OutputContract::SelectedEnd,
            literals: view.literals(),
            portfolio: view.portfolio(),
            minimum_width: view.minimum_width(),
            maximum_width: view.maximum_width(),
            root_members: view.root_members(),
            source_count: view.source_count(),
            total_source_bytes: view.total_source_bytes(),
            literal_digest: view.literal_digest(),
        }
    }

    fn from_exists(
        artifact_identity: [u8; 32],
        view: NativeFiniteExistsChoiceView<'a>,
    ) -> Option<Self> {
        let literals = view.literals();
        let portfolio = view.teddy_portfolio()?;
        if artifact_identity == [0; 32]
            || !exact_finite_exists_teddy_source_count_is_supported(literals.len())
            || literals.iter().any(Vec::is_empty)
            || view.minimum_width() < 3
        {
            return None;
        }
        let total_source_bytes = literals
            .iter()
            .try_fold(0_usize, |total, literal| total.checked_add(literal.len()))?;
        let minimum_width = u32::try_from(literals.iter().map(Vec::len).min()?).ok()?;
        let maximum_width = u32::try_from(literals.iter().map(Vec::len).max()?).ok()?;
        if total_source_bytes != view.total_source_bytes()
            || minimum_width != view.minimum_width()
            || maximum_width != view.maximum_width()
        {
            return None;
        }
        let mut root_members = [0_u64; 4];
        let mut digest = Sha256::new();
        digest.update(u64::try_from(literals.len()).ok()?.to_le_bytes());
        for literal in literals {
            let byte = usize::from(*literal.first()?);
            root_members[byte / 64] |= 1_u64 << (byte % 64);
            digest.update(u64::try_from(literal.len()).ok()?.to_le_bytes());
            digest.update(literal);
        }
        Some(Self {
            artifact_identity,
            output: OutputContract::Exists,
            literals,
            portfolio,
            minimum_width,
            maximum_width,
            root_members,
            source_count: u32::try_from(literals.len()).ok()?,
            total_source_bytes,
            literal_digest: digest.finalize().into(),
        })
    }

    const fn artifact_identity(self) -> [u8; 32] {
        self.artifact_identity
    }

    const fn output(self) -> OutputContract {
        self.output
    }

    const fn literals(self) -> &'a [Vec<u8>] {
        self.literals
    }

    const fn portfolio(self) -> MandatoryTeddyPortfolio {
        self.portfolio
    }

    const fn minimum_width(self) -> u32 {
        self.minimum_width
    }

    const fn maximum_width(self) -> u32 {
        self.maximum_width
    }

    const fn root_members(self) -> [u64; 4] {
        self.root_members
    }

    const fn source_count(self) -> u32 {
        self.source_count
    }

    const fn total_source_bytes(self) -> usize {
        self.total_source_bytes
    }

    const fn literal_digest(self) -> [u8; 32] {
        self.literal_digest
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ExactFiniteSelectedEndTeddySelection<'a> {
    view: ExactFiniteTeddyLiteralView<'a>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactFiniteTeddySuccessMode {
    SelectedEnd,
    /// Preserve the verified candidate and tail-enter the exact incumbent at
    /// that base, retaining its positive result and LF-cursor authority.
    ExistsReverifyInIncumbent,
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
    selection_basis: ExactFiniteSelectedEndTeddySelectionBasisV2,
) -> Option<u128> {
    if !complete_dfa_baseline_report_has_valid_geometry(incumbent, selection_basis) {
        return None;
    }
    horizon.checked_mul(complete_dfa_incumbent_per_byte_units(incumbent)?)
}

fn complete_dfa_incumbent_per_byte_units(
    incumbent: ExactFiniteSelectedEndDfaBaselineReport,
) -> Option<u128> {
    u128::try_from(incumbent.hot_loads_per_byte)
        .ok()?
        .checked_mul(4)?
        .checked_add(
            u128::try_from(incumbent.hot_branches_per_byte)
                .ok()?
                .checked_mul(3)?,
        )
}

fn complete_dfa_baseline_report_has_valid_geometry(
    report: ExactFiniteSelectedEndDfaBaselineReport,
    selection_basis: ExactFiniteSelectedEndTeddySelectionBasisV2,
) -> bool {
    let accelerator_is_valid = match selection_basis {
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1 => {
            !report.has_accelerator && report.scanner == StartAccelerator::None
        }
        ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility => {
            report.has_accelerator == (report.scanner != StartAccelerator::None)
        }
    };
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
        && accelerator_is_valid
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
    output: OutputContract,
    root_members: [u64; 4],
    plan: MandatoryTeddyPlan,
    isa: MandatoryTeddyIsa,
    incumbent: ExactFiniteSelectedEndDfaBaselineReport,
    selection_horizon_bytes: usize,
    selection_basis: ExactFiniteSelectedEndTeddySelectionBasisV2,
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
    if !dynamic_profitable
        && selection_basis == ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1
    {
        return None;
    }

    let expected_candidate_numerator =
        probability_denominator.checked_sub(no_candidate_numerator)?;
    let verification_units = worst_case_exact_verification_units(literals)?;
    let expected_verification_cost_units = verification_units
        .checked_mul(expected_candidate_numerator)?
        .checked_add(probability_denominator.checked_sub(1)?)?
        .checked_div(probability_denominator)?;
    // Exists verifies an exact candidate and then deliberately resumes the
    // authoritative complete DFA at that base. Charge every fingerprint
    // candidate as though it were a true hit: maximum literal width times the
    // incumbent's favorable per-byte lower bound, plus a fixed tail/setup
    // charge. False candidates normally stay in Teddy, so this is a
    // result-blind conservative overcharge for unknown workloads.
    let expected_incumbent_reverify_cost_units = if output == OutputContract::Exists {
        let maximum_width = literals.iter().try_fold(0_u128, |maximum, literal| {
            Some(maximum.max(u128::try_from(literal.as_ref().len()).ok()?))
        })?;
        let per_candidate = maximum_width
            .checked_mul(complete_dfa_incumbent_per_byte_units(incumbent)?)?
            .checked_add(EXACT_FINITE_EXISTS_INCUMBENT_TAIL_SETUP_UNITS)?;
        per_candidate
            .checked_mul(expected_candidate_numerator)?
            .checked_add(probability_denominator.checked_sub(1)?)?
            .checked_div(probability_denominator)?
    } else {
        0
    };
    let full_cost_units = gate_cost_units
        .checked_mul(EXACT_FINITE_TEDDY_GATE_COST_MULTIPLIER)?
        .checked_add(expected_verification_cost_units)?
        .checked_add(expected_incumbent_reverify_cost_units)?;
    let incumbent_cost_units =
        complete_dfa_incumbent_cost_units(incumbent, horizon, selection_basis)?;
    if full_cost_units.checked_mul(EXACT_FINITE_TEDDY_MATERIAL_GAIN_DENOMINATOR)?
        > incumbent_cost_units.checked_mul(EXACT_FINITE_TEDDY_MATERIAL_GAIN_NUMERATOR)?
        && selection_basis == ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1
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
    output: OutputContract,
    portfolio: MandatoryTeddyPortfolio,
    minimum_width: u32,
    root_members: [u64; 4],
    target: Target,
    incumbent: ExactFiniteSelectedEndDfaBaselineReport,
    selection_horizon_bytes: usize,
    selection_basis: ExactFiniteSelectedEndTeddySelectionBasisV2,
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
            output,
            root_members,
            plan,
            isa,
            incumbent,
            selection_horizon_bytes,
            selection_basis,
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
    let view = ExactFiniteTeddyLiteralView::from_selected_end(view);
    let selection_horizon_bytes =
        PARTIAL_DFA_MIN_INPUT_BYTES.checked_mul(COST_HORIZON_MULTIPLIER)?;
    if !complete_dfa_baseline_report_has_valid_geometry(
        incumbent,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
    ) {
        return None;
    }
    let selected = recompute_exact_finite_selected_end_teddy_selection(
        view.literals(),
        OutputContract::SelectedEnd,
        view.portfolio(),
        view.minimum_width(),
        view.root_members(),
        target,
        incumbent,
        selection_horizon_bytes,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
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

/// Select the shared correlated scanner for an independently authenticated
/// finite `Exists` Choice. Valid two- and three-literal choices deliberately
/// decline with `None` instead of becoming module errors.
pub(super) fn exact_finite_exists_teddy_is_structurally_eligible(
    artifact_identity: [u8; 32],
    view: NativeFiniteExistsChoiceView<'_>,
    target: Target,
) -> bool {
    native_mandatory_teddy_isa(target).is_some()
        && ExactFiniteTeddyLiteralView::from_exists(artifact_identity, view).is_some()
}

pub(super) fn select_exact_finite_exists_teddy<'a>(
    artifact_identity: [u8; 32],
    view: NativeFiniteExistsChoiceView<'a>,
    target: Target,
    incumbent: ExactFiniteSelectedEndDfaBaselineReport,
) -> Option<ExactFiniteSelectedEndTeddySelection<'a>> {
    let view = ExactFiniteTeddyLiteralView::from_exists(artifact_identity, view)?;
    let selection_horizon_bytes =
        PARTIAL_DFA_MIN_INPUT_BYTES.checked_mul(COST_HORIZON_MULTIPLIER)?;
    if !complete_dfa_baseline_report_has_valid_geometry(
        incumbent,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
    ) {
        return None;
    }
    let selected = recompute_exact_finite_selected_end_teddy_selection(
        view.literals(),
        OutputContract::Exists,
        view.portfolio(),
        view.minimum_width(),
        view.root_members(),
        target,
        incumbent,
        selection_horizon_bytes,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
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

/// Select a structurally valid V2 experiment while retaining every proof,
/// target, plan-geometry and arithmetic check from the stable selector.
/// Only the two result-blind performance predicates are bypassed.
pub(super) fn select_exact_finite_selected_end_teddy_forced_v2<'a>(
    view: NativeFiniteSelectedEndTeddyView<'a>,
    target: Target,
    incumbent: ExactFiniteSelectedEndDfaBaselineReport,
) -> Option<ExactFiniteSelectedEndTeddySelection<'a>> {
    let view = ExactFiniteTeddyLiteralView::from_selected_end(view);
    let selection_horizon_bytes =
        PARTIAL_DFA_MIN_INPUT_BYTES.checked_mul(COST_HORIZON_MULTIPLIER)?;
    if !complete_dfa_baseline_report_has_valid_geometry(
        incumbent,
        ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility,
    ) {
        return None;
    }
    let selected = recompute_exact_finite_selected_end_teddy_selection(
        view.literals(),
        OutputContract::SelectedEnd,
        view.portfolio(),
        view.minimum_width(),
        view.root_members(),
        target,
        incumbent,
        selection_horizon_bytes,
        ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility,
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
    digest.update([report.batch_vectors]);
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

fn v2_route_binding_digest(report: &ExactFiniteSelectedEndTeddyAotReportV2) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"fre-exact-finite-selected-end-teddy-route-v2");
    digest.update(report.schema_version.to_le_bytes());
    digest.update([match report.requested_policy {
        crate::ExactFiniteSelectedEndTeddyPolicyV2::Disabled => 0,
        crate::ExactFiniteSelectedEndTeddyPolicyV2::Automatic => 1,
        crate::ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible => 2,
    }]);
    digest.update([match report.selection_basis {
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1 => 0,
        ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility => 1,
    }]);
    digest.update([match report.incumbent_source {
        ExactFiniteSelectedEndTeddyIncumbentSourceV2::OrdinaryPublicCompleteDfa => 0,
    }]);
    digest.update([start_accelerator_tag(report.incumbent_start_accelerator)]);
    digest.update([report.incumbent_anchored_prefix_filter_bytes]);
    digest.update([
        u8::from(report.performance_admission_bypassed),
        u8::from(report.tail_enters_exact_incumbent),
    ]);
    digest.update(report.lowering.artifact_identity);
    digest.update(report.lowering.prefix_plan_sha256);
    digest.update(report.lowering.native_code_sha256);
    digest.update(report.lowering.native_data_sha256);
    digest.update(report.lowering.relocations_sha256);
    digest.update(report.lowering.incumbent_code_sha256);
    digest.update(report.lowering.incumbent_data_sha256);
    digest.update(report.lowering.incumbent_relocations_sha256);
    digest.update(report.lowering.incumbent_complete_dfa.semantic_dfa_sha256);
    digest.finalize().into()
}

pub(crate) fn exact_finite_selected_end_teddy_report_v2(
    lowering: ExactFiniteSelectedEndTeddyAotReport,
    requested_policy: crate::ExactFiniteSelectedEndTeddyPolicyV2,
    selection_basis: ExactFiniteSelectedEndTeddySelectionBasisV2,
    incumbent_anchored_prefix_filter_bytes: u8,
) -> Result<ExactFiniteSelectedEndTeddyAotReportV2, ObjectError> {
    let valid_policy = matches!(
        (requested_policy, selection_basis),
        (
            crate::ExactFiniteSelectedEndTeddyPolicyV2::Automatic,
            ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
        ) | (
            crate::ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible,
            ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility,
        )
    );
    if !valid_policy
        || !complete_dfa_baseline_report_has_valid_geometry(
            lowering.incumbent_complete_dfa,
            selection_basis,
        )
    {
        return Err(ObjectError::InvalidModule(
            "exact finite SelectedEnd Teddy V2 policy or incumbent",
        ));
    }
    let mut report = ExactFiniteSelectedEndTeddyAotReportV2 {
        schema_version: crate::COMPILE_REQUEST_V2_SCHEMA_VERSION,
        requested_policy,
        selection_basis,
        incumbent_source: ExactFiniteSelectedEndTeddyIncumbentSourceV2::OrdinaryPublicCompleteDfa,
        incumbent_start_accelerator: lowering.incumbent_complete_dfa.scanner,
        incumbent_anchored_prefix_filter_bytes,
        performance_admission_bypassed: selection_basis
            == ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility,
        tail_enters_exact_incumbent: true,
        route_binding_sha256: [0; 32],
        lowering,
    };
    report.route_binding_sha256 = v2_route_binding_digest(&report);
    Ok(report)
}

fn report_v2_metadata_authenticates(report: &ExactFiniteSelectedEndTeddyAotReportV2) -> bool {
    report.schema_version == crate::COMPILE_REQUEST_V2_SCHEMA_VERSION
        && report.incumbent_source
            == ExactFiniteSelectedEndTeddyIncumbentSourceV2::OrdinaryPublicCompleteDfa
        && report.incumbent_start_accelerator == report.lowering.incumbent_complete_dfa.scanner
        && report.performance_admission_bypassed
            == (report.selection_basis
                == ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility)
        && report.tail_enters_exact_incumbent
        && matches!(
            (report.requested_policy, report.selection_basis),
            (
                crate::ExactFiniteSelectedEndTeddyPolicyV2::Automatic,
                ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
            ) | (
                crate::ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible,
                ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility,
            )
        )
        && report.route_binding_sha256 == v2_route_binding_digest(report)
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

const fn report_batch_vectors(isa: MandatoryTeddyIsa) -> u8 {
    match isa {
        MandatoryTeddyIsa::Aarch64Sve | MandatoryTeddyIsa::Aarch64Sve2 => {
            EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS
        }
        MandatoryTeddyIsa::X86Avx2
        | MandatoryTeddyIsa::X86Avx512Bw
        | MandatoryTeddyIsa::Aarch64Asimd => EXACT_FINITE_TEDDY_UNBATCHED_VECTORS,
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

struct ExactFiniteTeddyWrapperEmission {
    code: Vec<u8>,
    relocations: Vec<ModuleRelocation>,
    incumbent_code_offset: usize,
    trusted_core_offset: usize,
    tail_branch_offset: usize,
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
    view: ExactFiniteTeddyLiteralView<'_>,
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
    success_mode: ExactFiniteTeddySuccessMode,
) -> Result<ExactFiniteTeddyWrapperEmission, ObjectError> {
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
    let scalar_candidate = assembler.label()?;
    let candidate = assembler.label()?;
    let false_candidate = assembler.label()?;
    let retry_retained = assembler.label()?;
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
    // plus the callee-saved counter and result register used by the leaf. R12
    // and R13 retain one vector block's base and candidate mask, so public
    // length/end move to RBP/R15 for the lifetime of the wrapper.
    assembler.instruction(&[0x41, 0x54])?; // push r12
    assembler.instruction(&[0x53])?; // push rbx
    assembler.instruction(&[0x41, 0x55])?; // push r13
    assembler.instruction(&[0x41, 0x56])?; // push r14
    assembler.instruction(&[0x41, 0x57])?; // push r15
    assembler.instruction(&[0x55])?; // push rbp
    assembler.instruction(&[0x48, 0x89, 0xf5])?; // rbp = public length
    assembler.instruction(&[0x49, 0x89, 0xcf])?; // r15 = public end
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
    assembler.branch(&[0x0f, 0x85], scalar_candidate)?;
    assembler.instruction(&[0x48, 0xff, 0xc2])?;
    assembler.branch(&[0xe9], scalar)?;

    assembler.bind(vector_candidate)?;
    x86_emit_retain_candidate_mask(&mut assembler, X86CandidateMask::MovemaskEax)?;
    x86_emit_first_retained_candidate(&mut assembler)?;
    // Vector lanes retained only candidate truth, so recompute the exact
    // bucket identity at the selected base.
    x86_emit_mandatory_teddy_scalar_candidate(&mut assembler, teddy)?;
    assembler.branch(&[0x0f, 0x85], candidate)?;
    assembler.branch(&[0xe9], retry_retained)?;

    assembler.bind(scalar_candidate)?;
    // Give a scalar-tail candidate the same retained-mask contract. Encoding
    // it as lane 31 makes an exhausted synthetic block advance to base + 1.
    assembler.instruction(&[0x4c, 0x8d, 0x62, 0xe1])?; // r12 = candidate - 31
    assembler.instruction(&[0x41, 0xbd, 0, 0, 0, 0x80])?; // r13d = 1 << 31

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
    assembler.instruction(&[0x4c, 0x89, 0xfe])?; // rsi = end
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
    assembler.bind(retry_retained)?;
    x86_emit_clear_first_retained_candidate(&mut assembler)?;
    let retained_candidate = assembler.label()?;
    assembler.branch(&[0x0f, 0x85], retained_candidate)?;
    x86_emit_advance_retained_block(&mut assembler, teddy.vector_bytes)?;
    assembler.instruction(&[0x4c, 0x89, 0xf9])?; // restore public end
    assembler.branch(&[0xe9], vector)?;

    assembler.bind(retained_candidate)?;
    x86_emit_first_retained_candidate(&mut assembler)?;
    x86_emit_mandatory_teddy_scalar_candidate(&mut assembler, teddy)?;
    assembler.branch(&[0x0f, 0x85], candidate)?;
    assembler.branch(&[0xe9], retry_retained)?;

    assembler.bind(runtime_fallback)?;
    // RDX still names the first candidate whose exact source-order result is
    // unresolved. Restore the other public arguments and tail-enter the
    // complete incumbent from that base.
    assembler.instruction(&[0x48, 0x89, 0xee])?; // rsi = public length
    assembler.instruction(&[0x4c, 0x89, 0xf9])?; // rcx = public end
    assembler.instruction(&[0x4d, 0x89, 0xf0])?; // r8 = public result
    assembler.instruction(&[0x5d])?; // pop rbp
    assembler.instruction(&[0x41, 0x5f])?; // pop r15
    assembler.instruction(&[0x41, 0x5e])?; // pop r14
    assembler.instruction(&[0x41, 0x5d])?; // pop r13
    assembler.instruction(&[0x5b])?; // pop rbx
    assembler.instruction(&[0x41, 0x5c])?; // pop r12
    assembler.instruction(&[0xc5, 0xf8, 0x77])?;
    assembler.branch(&[0xe9], tail)?;

    assembler.bind(matched)?;
    match success_mode {
        ExactFiniteTeddySuccessMode::SelectedEnd => {
            assembler.instruction(&[0x48, 0x8d, 0x04, 0x0a])?; // selected end
            assembler.instruction(&[0x49, 0x89, 0x06])?;
            assembler.instruction(&[0x49, 0x89, 0x46, 0x08])?;
            assembler.instruction(&[0xb8, 0x01, 0, 0, 0])?;
            assembler.branch(&[0xe9], returned)?;
        }
        ExactFiniteTeddySuccessMode::ExistsReverifyInIncumbent => {
            // RDX still names the byte-exact candidate base.
            assembler.branch(&[0xe9], runtime_fallback)?;
        }
    }

    assembler.bind(exhausted)?;
    assembler.instruction(&[0x31, 0xc0])?;
    assembler.bind(returned)?;
    assembler.instruction(&[0x5d])?; // pop rbp
    assembler.instruction(&[0x41, 0x5f])?; // pop r15
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
    let tail_branch_offset = tail_displacement
        .checked_sub(1)
        .ok_or(ObjectError::InvalidModule(
            "x86 exact finite Exists Teddy tail opcode is absent",
        ))?;
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
    Ok(ExactFiniteTeddyWrapperEmission {
        code: finished.code,
        relocations: vec![ModuleRelocation {
            section: TEXT_SECTION,
            offset: offset_u64(
                program_displacement,
                "x86 exact finite SelectedEnd Teddy program relocation",
            )?,
            kind: RelocationKind::X86PcRelative32,
            symbol: PROGRAM_SYMBOL,
            addend: -4,
        }],
        incumbent_code_offset: core_offset,
        trusted_core_offset: 0,
        tail_branch_offset,
    })
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

fn aarch64_exact_load_q_post_imm(
    destination: u8,
    base: u8,
    byte_offset: i16,
) -> Result<u32, ObjectError> {
    if !(-256..=255).contains(&byte_offset) {
        return Err(ObjectError::InvalidModule("AArch64 LDR Q post-index"));
    }
    Ok(0x3cc0_0400
        | (u32::try_from(i32::from(byte_offset) & 0x01ff)
            .map_err(|_| ObjectError::InvalidModule("AArch64 LDR Q post-index"))?
            << 12)
        | aarch64_reg(base, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_exact_load_q_unscaled_imm(
    destination: u8,
    base: u8,
    byte_offset: i16,
) -> Result<u32, ObjectError> {
    if !(-256..=255).contains(&byte_offset) {
        return Err(ObjectError::InvalidModule("AArch64 LDUR Q offset"));
    }
    Ok(0x3cc0_0000
        | (u32::try_from(i32::from(byte_offset) & 0x01ff)
            .map_err(|_| ObjectError::InvalidModule("AArch64 LDUR Q offset"))?
            << 12)
        | aarch64_reg(base, 5)?
        | aarch64_reg(destination, 0)?)
}

fn aarch64_emit_exact_teddy_sve_first_candidate(
    assembler: &mut Aarch64Assembler,
    candidates: u8,
    buckets: u8,
    bucket_ready: Aarch64Label,
) -> Result<(), ObjectError> {
    // BRKA and BRKB expose independent inclusive/exclusive prefixes from the
    // same retained candidates. LASTB can recover the bucket while INCP
    // advances the scalar base, avoiding a predicate -> GPR -> predicate
    // dependency through ADD/WHILELO.
    assembler.instruction(aarch64_sve_brka_p0(
        EXACT_FINITE_TEDDY_SVE_BUCKET_SCRATCH,
        candidates,
    )?)?;
    assembler.instruction(aarch64_sve_brkb_p0(
        EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH,
        candidates,
    )?)?;
    assembler.instruction(aarch64_sve_lastb_w(
        10,
        EXACT_FINITE_TEDDY_SVE_BUCKET_SCRATCH,
        buckets,
    )?)?;
    assembler.instruction(aarch64_sve_incp_b(
        2,
        EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH,
    )?)?;
    assembler.branch(bucket_ready)?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the two vector routes share exact bounds and three explicit CFG exits"
)]
fn aarch64_emit_exact_teddy_sve_batch_route(
    assembler: &mut Aarch64Assembler,
    teddy: &NativeMandatoryTeddyLayout,
    vector: Aarch64Label,
    single: Aarch64Label,
    batch_candidate: Aarch64Label,
    single_prefix: bool,
) -> Result<(), ObjectError> {
    assembler.bind(vector)?;
    // Retry setup retains the last base with a complete four-vector batch in
    // X9. The steady-state miss loop needs only this unsigned cursor test;
    // X10 separately retains the exclusive end of all valid candidate bases.
    assembler.instruction(aarch64_cmp_x(2, 9)?)?;
    assembler.branch_cond(AARCH64_HI, single)?;
    aarch64_emit_mandatory_teddy_sve_batch4_candidates(
        assembler,
        teddy,
        vector,
        single_prefix,
    )?;
    aarch64_emit_mandatory_teddy_sve_batch4_any(assembler)?;
    assembler.branch_cond(AARCH64_NE, batch_candidate)?;
    assembler.instruction(aarch64_sve_addvl(
        2,
        2,
        EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS,
    )?)?;
    assembler.branch(vector)?;
    Ok(())
}

fn lower_aarch64_wrapper(
    incumbent_code: &[u8],
    layout: ExactFiniteSelectedEndTeddyDataLayout,
    lane_index_offset: Option<u32>,
    selection_basis: ExactFiniteSelectedEndTeddySelectionBasisV2,
    use_asimd_exact_verifier: bool,
    success_mode: ExactFiniteTeddySuccessMode,
) -> Result<ExactFiniteTeddyWrapperEmission, ObjectError> {
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
    let scalar_candidate = assembler.label()?;
    let candidate = assembler.label()?;
    let bucket_ready = assembler.label()?;
    let retry_scan = assembler.label()?;
    let retry_retained = assembler.label()?;
    let ordinal_failed = assembler.label()?;
    let next_ordinal = assembler.label()?;
    let runtime_fallback = assembler.label()?;
    let matched = assembler.label()?;
    let scalar_residue_loop = if use_asimd_exact_verifier {
        Some(assembler.label()?)
    } else {
        None
    };
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
    assembler.instruction(aarch64_sub_x_imm(31, 31, 32)?)?;
    assembler.instruction(aarch64_store_pair_x(19, 20, 31, 0)?)?;
    assembler.instruction(aarch64_store_x(21, 31, 16)?)?;
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
            aarch64_emit_mandatory_teddy_asimd_candidates(
                &mut assembler,
                teddy,
                vector,
                None,
            )?;
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
            assembler.branch_cond(AARCH64_NE, scalar_candidate)?;
            assembler.instruction(aarch64_add_x_imm(2, 2, 1)?)?;
            assembler.branch(scalar)?;

            assembler.bind(vector_candidate)?;
            assembler.instruction(aarch64_mov_x(21, 2)?)?; // retained block base
            aarch64_emit_first_retained_candidate_lane(&mut assembler, 24, 21)?;
            assembler.branch(candidate)?;

            assembler.bind(scalar_candidate)?;
            // Encode one scalar-tail candidate as retained lane 15, so an
            // exhausted synthetic block advances to candidate + 1.
            assembler.instruction(aarch64_sub_x_imm(21, 2, 15)?)?;
            assembler.instruction(aarch64_cmeq_16b(24, 29, 26)?)?;
            assembler.branch(bucket_ready)?;
        }
        MandatoryTeddyIsa::Aarch64Sve | MandatoryTeddyIsa::Aarch64Sve2 => {
            let single = assembler.label()?;
            let partial = assembler.label()?;
            let single_candidate = assembler.label()?;
            let batch_candidate = assembler.label()?;
            let batch_plan = aarch64_mandatory_teddy_column_plan(&teddy.plan)?;
            let single_prefix_vector = if selection_basis
                == ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility
                && batch_plan.single_prefix_max_vector_bytes.is_some()
            {
                Some(assembler.label()?)
            } else {
                None
            };
            let batch_hits = [
                assembler.label()?,
                assembler.label()?,
                assembler.label()?,
                assembler.label()?,
            ];
            aarch64_emit_mandatory_teddy_sve_constants(&mut assembler, teddy)?;
            assembler.bind(retry_scan)?;
            // Exact verification uses W6, retry bookkeeping changes P1/P10,
            // and partial batches narrow P0. Restore every scalable scan
            // invariant before entering the four-vector/single/tail decision.
            assembler.instruction(aarch64_sve_ptrue_b())?;
            assembler.instruction(aarch64_sve_dup_b_imm(26, 0x0f)?)?;
            assembler.instruction(aarch64_sve_cntb(6)?)?;
            let maximum_offset = teddy
                .plan
                .columns()
                .checked_sub(1)
                .ok_or(ObjectError::InvalidModule(
                    "AArch64 exact finite SelectedEnd Teddy has no columns",
                ))?;
            // X10 is the exclusive candidate-base end. X9 is the last base
            // from which four complete runtime vectors can be read. Exact
            // verification may clobber both, so every retry rematerializes
            // them together with the predicate and vector-length invariants.
            assembler.instruction(aarch64_sub_x_imm(10, 3, u16::from(maximum_offset))?)?;
            let backward_batch_vectors = i8::try_from(EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS)
                .ok()
                .and_then(i8::checked_neg)
                .ok_or(ObjectError::ArithmeticOverflow(
                    "AArch64 exact finite SelectedEnd Teddy batch frontier",
                ))?;
            assembler.instruction(aarch64_sve_addvl_signed(
                9,
                10,
                backward_batch_vectors,
            )?)?;
            if let (Some(single_prefix_vector), Some(maximum_vector_bytes)) = (
                single_prefix_vector,
                batch_plan.single_prefix_max_vector_bytes,
            ) {
                // CNTB is invariant for the process. Dispatch once per exact
                // retry so wider implementations retain the established loop
                // with no per-batch profitability branch.
                assembler.instruction(aarch64_cmp_x_imm(6, maximum_vector_bytes)?)?;
                assembler.branch_cond(AARCH64_LS, single_prefix_vector)?;
            }

            // Four runtime vectors are 4 * CNTB. Keep Z24/Z25/Z27/Z28 live so
            // a hit never reloads its block and exact rejection can continue
            // into later candidate blocks without rescanning them.
            aarch64_emit_exact_teddy_sve_batch_route(
                &mut assembler,
                &teddy,
                vector,
                single,
                batch_candidate,
                false,
            )?;
            if let Some(single_prefix_vector) = single_prefix_vector {
                aarch64_emit_exact_teddy_sve_batch_route(
                    &mut assembler,
                    &teddy,
                    single_prefix_vector,
                    single,
                    batch_candidate,
                    true,
                )?;
            }

            assembler.bind(batch_candidate)?;
            // The miss path needed only an existential reduction. Materialize
            // durable P1..P4 masks now that the retained bucket vectors are
            // known to contain at least one candidate.
            aarch64_emit_mandatory_teddy_sve_batch4_predicates(&mut assembler)?;
            for (block, &hit) in batch_hits.iter().enumerate() {
                let predicate = u8::try_from(block)
                    .ok()
                    .and_then(|block| block.checked_add(1))
                    .ok_or(ObjectError::ArithmeticOverflow(
                        "AArch64 exact finite SelectedEnd Teddy batch hit predicate",
                    ))?;
                assembler.instruction(aarch64_sve_ptest_p0(predicate)?)?;
                assembler.branch_cond(AARCH64_NE, hit)?;
            }
            // The reduction proved a hit. Recomputing through the one-vector
            // path is a safe progress fallback if a future emitter violates
            // the retained-predicate invariant.
            assembler.branch(single)?;
            for (block, &hit) in batch_hits.iter().enumerate() {
                assembler.bind(hit)?;
                let block = u8::try_from(block).map_err(|_| {
                    ObjectError::ArithmeticOverflow(
                        "AArch64 exact finite SelectedEnd Teddy batch hit block",
                    )
                })?;
                if block == 0 {
                    assembler.instruction(aarch64_mov_x(21, 2)?)?;
                } else {
                    assembler.instruction(aarch64_sve_addvl(21, 2, block)?)?;
                }
                assembler.instruction(aarch64_movz_w(7, u16::from(block + 1))?)?;
                let predicate = block + 1;
                if predicate != 1 {
                    assembler.instruction(aarch64_sve_orr_b(1, predicate, predicate)?)?;
                }
                let buckets = AARCH64_MANDATORY_TEDDY_SVE_BATCH_BUCKET_REGISTERS
                    [usize::from(block)];
                assembler.instruction(aarch64_sve_and_z(6, buckets, buckets)?)?;
                assembler.instruction(aarch64_mov_x(2, 21)?)?;
                aarch64_emit_exact_teddy_sve_first_candidate(
                    &mut assembler,
                    1,
                    6,
                    bucket_ready,
                )?;
            }

            assembler.bind(single)?;
            // The batch frontier deliberately permits the cursor to reach the
            // exclusive candidate end. Reject that terminal state before the
            // existing one-vector/partial split subtracts candidate bases.
            assembler.instruction(aarch64_cmp_x(2, 10)?)?;
            assembler.branch_cond(AARCH64_HS, exhausted)?;
            assembler.instruction(aarch64_sub_x_reg(12, 10, 2)?)?;
            assembler.instruction(aarch64_cmp_x(12, 6)?)?;
            assembler.branch_cond(AARCH64_LO, partial)?;
            aarch64_emit_mandatory_teddy_sve_candidates(&mut assembler, teddy)?;
            assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
            assembler.branch_cond(AARCH64_NE, single_candidate)?;
            assembler.instruction(aarch64_sve_addvl(2, 2, 1)?)?;
            assembler.branch(vector)?;

            assembler.bind(partial)?;
            assembler.instruction(aarch64_sve_whilelo_b(0, 2, 10)?)?;
            aarch64_emit_mandatory_teddy_sve_candidates(&mut assembler, teddy)?;
            assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
            assembler.branch_cond(AARCH64_EQ, exhausted)?;

            assembler.bind(single_candidate)?;
            assembler.instruction(aarch64_mov_x(21, 2)?)?; // retained block base
            // Four means no retained later-batch predicate follows this
            // standalone full vector or predicated final partial vector.
            assembler.instruction(aarch64_movz_w(
                7,
                u16::from(EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS),
            )?)?;
            aarch64_emit_exact_teddy_sve_first_candidate(
                &mut assembler,
                1,
                6,
                bucket_ready,
            )?;
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
    // ASIMD vector candidates reach this shared replay. Its scalar tail and
    // the SVE route already have an exact bucket and enter `bucket_ready`.
    aarch64_emit_mandatory_teddy_scalar_candidate(&mut assembler, teddy)?;
    assembler.branch_cond(AARCH64_EQ, retry_retained)?;
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
    assembler.branch_zero_x(11, retry_retained)?;

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
    if use_asimd_exact_verifier {
        let wide_exact_loop = assembler.label()?;
        let vector_byte_offset = i16::try_from(EXACT_FINITE_TEDDY_ASIMD_VERIFIER_BYTES)
            .map_err(|_| ObjectError::ArithmeticOverflow("AArch64 exact verifier vector width"))?;
        // Every selected literal is at least one complete ASIMD vector. Keep
        // the public width/result registers and Teddy's retained state live;
        // V0/V1 and W16/W17 are leaf-local scratch. An exact multiple branches
        // directly to `matched`. Residues below the discovery-selected
        // crossover retain the incumbent scalar verifier; residues at or
        // above it reach the overlapping final vector verifier below.
        assembler.bind(wide_exact_loop)?;
        assembler.instruction(aarch64_exact_load_q_post_imm(0, 13, vector_byte_offset)?)?;
        assembler.instruction(aarch64_exact_load_q_post_imm(1, 14, vector_byte_offset)?)?;
        assembler.instruction(aarch64_eor_16b(0, 0, 1)?)?;
        assembler.instruction(aarch64_umaxv_16b(0, 0)?)?;
        assembler.instruction(aarch64_umov_b0(16, 0)?)?;
        assembler.branch_nonzero_w(16, ordinal_failed)?;
        assembler.instruction(aarch64_sub_w_imm(
            10,
            10,
            EXACT_FINITE_TEDDY_ASIMD_VERIFIER_BYTES,
        )?)?;
        assembler.branch_zero_w(10, matched)?;
        assembler.instruction(aarch64_cmp_w_imm(
            10,
            EXACT_FINITE_TEDDY_ASIMD_VERIFIER_BYTES,
        )?)?;
        assembler.branch_cond(AARCH64_HS, wide_exact_loop)?;
        assembler.instruction(aarch64_cmp_w_imm(
            10,
            EXACT_FINITE_TEDDY_ASIMD_OVERLAP_MIN_RESIDUE,
        )?)?;
        assembler.branch_cond(
            AARCH64_LO,
            scalar_residue_loop.ok_or(ObjectError::InvalidModule(
                "AArch64 exact verifier scalar residue loop label",
            ))?,
        )?;

        // X13/X14 now point just past the last complete vector and W10 is a
        // five-through-fifteen-byte residue. Advance both pointers to their
        // proved ends, then compare the final sixteen bytes with an overlapping
        // unscaled load. The selected width already proved both windows in
        // bounds, and every selected literal is at least sixteen bytes, so
        // neither -16 address can precede its source. This removes the larger
        // residues' byte-at-a-time loop without touching retained Teddy vector
        // or predicate state.
        assembler.instruction(aarch64_add_x_uxtw(13, 13, 10, 0)?)?;
        assembler.instruction(aarch64_add_x_uxtw(14, 14, 10, 0)?)?;
        assembler.instruction(aarch64_exact_load_q_unscaled_imm(
            0,
            13,
            -vector_byte_offset,
        )?)?;
        assembler.instruction(aarch64_exact_load_q_unscaled_imm(
            1,
            14,
            -vector_byte_offset,
        )?)?;
        assembler.instruction(aarch64_eor_16b(0, 0, 1)?)?;
        assembler.instruction(aarch64_umaxv_16b(0, 0)?)?;
        assembler.instruction(aarch64_umov_b0(16, 0)?)?;
        // A mismatch falls through directly into `ordinal_failed`; only the
        // success edge needs a branch. The fixed overlap block replaces the
        // scalar residue loop in a wide module.
        assembler.branch_zero_w(16, matched)?;
    } else {
        let exact_loop = assembler.label()?;
        assembler.bind(exact_loop)?;
        assembler.instruction(aarch64_load_byte_post_imm(16, 13, 1)?)?;
        assembler.instruction(aarch64_load_byte_post_imm(17, 14, 1)?)?;
        assembler.instruction(aarch64_cmp_w(16, 17)?)?;
        assembler.branch_cond(AARCH64_NE, ordinal_failed)?;
        assembler.instruction(aarch64_sub_w_imm(10, 10, 1)?)?;
        assembler.branch_nonzero_w(10, exact_loop)?;
        assembler.branch(matched)?;
    }

    assembler.bind(ordinal_failed)?;
    assembler.branch_nonzero_x(11, next_ordinal)?;
    assembler.bind(retry_retained)?;
    match teddy.isa {
        MandatoryTeddyIsa::Aarch64Sve | MandatoryTeddyIsa::Aarch64Sve2 => {
            // Consume every candidate lane through the rejected base while
            // retaining the active full/partial predicate. P1..P4 and P0
            // survive scalar exact verification; P10 is dedicated scratch so
            // later blocks from a hit-bearing four-vector batch remain live.
            assembler.instruction(aarch64_add_x_imm(12, 2, 1)?)?;
            assembler.instruction(aarch64_sve_whilelo_b(
                EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH,
                21,
                12,
            )?)?;
            assembler.instruction(aarch64_sve_not_b(
                EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH,
                EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH,
            )?)?;
            assembler.instruction(aarch64_sve_and_b(
                1,
                1,
                EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH,
            )?)?;
            assembler.instruction(aarch64_sve_ptest_p0(1)?)?;
            let retained_candidate = assembler.label()?;
            assembler.branch_cond(AARCH64_NE, retained_candidate)?;

            // W7 names the next retained batch block. Standalone full/partial
            // scans and a hit in block four use the sentinel value four.
            let next_batch_1 = assembler.label()?;
            let next_batch_2 = assembler.label()?;
            let next_batch_3 = assembler.label()?;
            let select_batch_1 = assembler.label()?;
            let select_batch_2 = assembler.label()?;
            let select_batch_3 = assembler.label()?;
            let block_exhausted = assembler.label()?;
            assembler.instruction(aarch64_cmp_w_imm(7, 1)?)?;
            assembler.branch_cond(AARCH64_EQ, next_batch_1)?;
            assembler.instruction(aarch64_cmp_w_imm(7, 2)?)?;
            assembler.branch_cond(AARCH64_EQ, next_batch_2)?;
            assembler.instruction(aarch64_cmp_w_imm(7, 3)?)?;
            assembler.branch_cond(AARCH64_EQ, next_batch_3)?;
            assembler.branch(block_exhausted)?;

            assembler.bind(next_batch_1)?;
            assembler.instruction(aarch64_sve_addvl(21, 21, 1)?)?;
            assembler.instruction(aarch64_movz_w(7, 2)?)?;
            assembler.instruction(aarch64_sve_ptest_p0(2)?)?;
            assembler.branch_cond(AARCH64_NE, select_batch_1)?;
            assembler.bind(next_batch_2)?;
            assembler.instruction(aarch64_sve_addvl(21, 21, 1)?)?;
            assembler.instruction(aarch64_movz_w(7, 3)?)?;
            assembler.instruction(aarch64_sve_ptest_p0(3)?)?;
            assembler.branch_cond(AARCH64_NE, select_batch_2)?;
            assembler.bind(next_batch_3)?;
            assembler.instruction(aarch64_sve_addvl(21, 21, 1)?)?;
            assembler.instruction(aarch64_movz_w(
                7,
                u16::from(EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS),
            )?)?;
            assembler.instruction(aarch64_sve_ptest_p0(4)?)?;
            assembler.branch_cond(AARCH64_NE, select_batch_3)?;

            assembler.bind(block_exhausted)?;
            // A final partial P0 has no later candidate block. Advancing it
            // by a full VL could move X2 beyond the public end and make the
            // retry loop's unsigned remaining calculation underflow.
            assembler.instruction(aarch64_sve_cntp_b(12, 0, 0)?)?;
            assembler.instruction(aarch64_sve_cntb(10)?)?;
            assembler.instruction(aarch64_cmp_x(12, 10)?)?;
            assembler.branch_cond(AARCH64_LO, exhausted)?;
            assembler.instruction(aarch64_sve_addvl(2, 21, 1)?)?;
            assembler.branch(retry_scan)?;

            for (label, predicate) in [
                (select_batch_1, 2_u8),
                (select_batch_2, 3_u8),
                (select_batch_3, 4_u8),
            ] {
                assembler.bind(label)?;
                assembler.instruction(aarch64_sve_orr_b(1, predicate, predicate)?)?;
                let block = usize::from(predicate.checked_sub(1).ok_or(
                    ObjectError::ArithmeticOverflow(
                        "AArch64 exact finite SelectedEnd Teddy batch bucket",
                    ),
                )?);
                let buckets = AARCH64_MANDATORY_TEDDY_SVE_BATCH_BUCKET_REGISTERS[block];
                assembler.instruction(aarch64_sve_and_z(6, buckets, buckets)?)?;
                assembler.instruction(aarch64_mov_x(2, 21)?)?;
                aarch64_emit_exact_teddy_sve_first_candidate(
                    &mut assembler,
                    1,
                    6,
                    bucket_ready,
                )?;
            }

            assembler.bind(retained_candidate)?;
            assembler.instruction(aarch64_mov_x(2, 21)?)?;
            aarch64_emit_exact_teddy_sve_first_candidate(
                &mut assembler,
                1,
                6,
                bucket_ready,
            )?;
        }
        MandatoryTeddyIsa::Aarch64Asimd => {
            // Keep V24 intact. Form an exact `lane >= rejected + 1` mask in
            // V28, intersect it with the retained candidates, and select the
            // next lane relative to callee-saved X21.
            assembler.instruction(aarch64_add_x_imm(12, 2, 1)?)?;
            assembler.instruction(aarch64_sub_x_reg(12, 12, 21)?)?;
            assembler.instruction(aarch64_dup_16b_from_w(28, 12)?)?;
            assembler.instruction(aarch64_cmhs_16b(28, 29, 28)?)?;
            assembler.instruction(aarch64_and_16b(28, 28, 24)?)?;
            aarch64_emit_candidate_any(&mut assembler, 28)?;
            let retained_candidate = assembler.label()?;
            assembler.branch_cond(AARCH64_NE, retained_candidate)?;
            assembler.instruction(aarch64_add_x_imm(2, 21, 16)?)?;
            assembler.branch(vector)?;
            assembler.bind(retained_candidate)?;
            aarch64_emit_first_retained_candidate_lane(&mut assembler, 28, 21)?;
            assembler.branch(candidate)?;
        }
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
    assembler.instruction(aarch64_load_x_imm(21, 31, 16)?)?;
    assembler.instruction(aarch64_load_pair_x(19, 20, 31, 0)?)?;
    assembler.instruction(aarch64_add_x_imm(31, 31, 32)?)?;
    assembler.branch(tail)?;

    if let Some(scalar_residue_loop) = scalar_residue_loop {
        assembler.bind(scalar_residue_loop)?;
        // Retain the incumbent byte verifier for residues one through four.
        // The post-indexed loop preserves its exact pointer/count evolution
        // and X11's remaining source-ordinal mask for the mismatch edge.
        assembler.instruction(aarch64_load_byte_post_imm(16, 13, 1)?)?;
        assembler.instruction(aarch64_load_byte_post_imm(17, 14, 1)?)?;
        assembler.instruction(aarch64_cmp_w(16, 17)?)?;
        assembler.branch_cond(AARCH64_NE, ordinal_failed)?;
        assembler.instruction(aarch64_sub_w_imm(10, 10, 1)?)?;
        assembler.branch_nonzero_w(10, scalar_residue_loop)?;
        assembler.branch(matched)?;
    }
    assembler.bind(matched)?;
    match success_mode {
        ExactFiniteTeddySuccessMode::SelectedEnd => {
            assembler.instruction(aarch64_add_x_reg(6, 2, 1)?)?;
            assembler.instruction(aarch64_store_x(6, 4, 0)?)?;
            assembler.instruction(aarch64_store_x(6, 4, 8)?)?;
            assembler.instruction(aarch64_movz_w(0, 1)?)?;
            assembler.instruction(aarch64_load_x_imm(21, 31, 16)?)?;
            assembler.instruction(aarch64_load_pair_x(19, 20, 31, 0)?)?;
            assembler.instruction(aarch64_add_x_imm(31, 31, 32)?)?;
            assembler.instruction(0xd65f_03c0)?;
        }
        ExactFiniteTeddySuccessMode::ExistsReverifyInIncumbent => {
            // X2 still names the byte-exact candidate base.
            assembler.branch(runtime_fallback)?;
        }
    }
    assembler.bind(exhausted)?;
    assembler.instruction(aarch64_movz_w(0, 0)?)?;
    assembler.instruction(aarch64_load_x_imm(21, 31, 16)?)?;
    assembler.instruction(aarch64_load_pair_x(19, 20, 31, 0)?)?;
    assembler.instruction(aarch64_add_x_imm(31, 31, 32)?)?;
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
    Ok(ExactFiniteTeddyWrapperEmission {
        code,
        relocations,
        incumbent_code_offset: core_offset,
        trusted_core_offset: 0,
        tail_branch_offset: branch,
    })
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
        batch_vectors: report_batch_vectors(selection.isa),
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

fn rebase_exact_finite_exists_lf_cursor(
    mut cursor: NativeDirectSearchLfLineCursor,
    incumbent_code_offset: usize,
) -> Result<NativeDirectSearchLfLineCursor, ObjectError> {
    let edge_count = usize::from(cursor.edge_count);
    let edges = cursor
        .edges
        .get_mut(..edge_count)
        .ok_or(ObjectError::InvalidModule(
            "exact finite Exists Teddy LF edge count is invalid",
        ))?;
    cursor.matched_offset = cursor
        .matched_offset
        .checked_add(incumbent_code_offset)
        .ok_or(ObjectError::ArithmeticOverflow(
            "exact finite Exists Teddy LF terminal rebase",
        ))?;
    for edge in edges {
        edge.instruction_offset = edge
            .instruction_offset
            .checked_add(incumbent_code_offset)
            .ok_or(ObjectError::ArithmeticOverflow(
                "exact finite Exists Teddy LF edge rebase",
            ))?;
    }
    Ok(cursor)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the wrapper, retained DFA, LF cursor and module identities form one private core receipt"
)]
fn compose_exact_finite_exists_teddy_trusted_core(
    incumbent_core: NativeDirectSearchTrustedCore,
    incumbent_code: &[u8],
    lowering: &NativeLowering,
    report: &ExactFiniteSelectedEndTeddyAotReport,
    trusted_core_offset: usize,
    tail_branch_offset: usize,
    incumbent_code_offset: usize,
    target: Target,
) -> Result<NativeDirectSearchTrustedCore, ObjectError> {
    if incumbent_core.output != OutputContract::Exists
        || incumbent_core.entry_contract != NativeDirectSearchEntryContract::PublicCompleteV1
        || incumbent_core.result_abi != NativeDirectSearchResultAbi::ExistsStatusOnlyV1
        || incumbent_core.landmark != NativeDirectSearchTrustedCoreLandmark::CompleteDfaV1
        || incumbent_core.success_cursor.is_some()
        || incumbent_core.code_offset >= incumbent_code.len()
        || incumbent_core.entry_code_sha256 != <[u8; 32]>::from(Sha256::digest(incumbent_code))
        || report.output != OutputContract::Exists
        || report.incumbent_code_offset != incumbent_code_offset
        || report.incumbent_code_bytes != incumbent_code.len()
        || report.native_data_bytes != lowering.data.len()
        || report.native_data_sha256 != <[u8; 32]>::from(Sha256::digest(&lowering.data))
        || report.relocations_sha256
            != exact_finite_selected_end_relocation_digest(&lowering.relocations).ok_or(
                ObjectError::InvalidModule(
                    "exact finite Exists Teddy trusted-core relocation digest",
                ),
            )?
    {
        return Err(ObjectError::InvalidModule(
            "exact finite Exists Teddy trusted-core incumbent is inconsistent",
        ));
    }
    let incumbent_core_offset = incumbent_code_offset
        .checked_add(incumbent_core.code_offset)
        .ok_or(ObjectError::ArithmeticOverflow(
            "exact finite Exists Teddy retained core rebase",
        ))?;
    let (matching_lf_line_cursor, matching_lf_line_success_edges_sha256) = match (
        incumbent_core.matching_lf_line_cursor,
        incumbent_core.matching_lf_line_success_edges_sha256,
    ) {
        (None, None) => (None, None),
        (Some(cursor), Some(expected_digest)) => {
            if matching_lf_line_witness_success_edges_digest(
                target.architecture,
                incumbent_code,
                cursor,
            )? != expected_digest
            {
                return Err(ObjectError::InvalidModule(
                    "exact finite Exists Teddy retained LF cursor is unauthenticated",
                ));
            }
            let cursor = rebase_exact_finite_exists_lf_cursor(cursor, incumbent_code_offset)?;
            let digest = matching_lf_line_witness_success_edges_digest(
                target.architecture,
                &lowering.code,
                cursor,
            )?;
            (Some(cursor), Some(digest))
        }
        _ => {
            return Err(ObjectError::InvalidModule(
                "exact finite Exists Teddy retained LF cursor receipt is partial",
            ));
        }
    };
    let prologue = match target.architecture {
        Architecture::X86_64 => NativeDirectSearchTrustedCorePrologue::X86_64SelfFramed,
        Architecture::Aarch64 => NativeDirectSearchTrustedCorePrologue::Aarch64SelfFramed,
    };
    let core = NativeDirectSearchTrustedCore {
        code_offset: trusted_core_offset,
        output: OutputContract::Exists,
        entry_contract: NativeDirectSearchEntryContract::PublicSelfFramedV1,
        result_abi: NativeDirectSearchResultAbi::ExistsStatusOnlyV1,
        entry_code_sha256: Sha256::digest(&lowering.code).into(),
        prologue,
        landmark: NativeDirectSearchTrustedCoreLandmark::ExactFiniteExistsTeddyV1 {
            prefix_plan_sha256: report.prefix_plan_sha256,
            native_data_bytes: lowering.data.len(),
            native_data_sha256: Sha256::digest(&lowering.data).into(),
            relocations_sha256: exact_finite_selected_end_relocation_digest(&lowering.relocations)
                .ok_or(ObjectError::InvalidModule(
                    "exact finite Exists Teddy trusted-core relocations",
                ))?,
            tail_branch_offset,
            incumbent_entry_offset: incumbent_code_offset,
            incumbent_core_offset,
        },
        success_cursor: None,
        matching_lf_line_cursor,
        matching_lf_line_success_edges_sha256,
    };
    authenticate_native_direct_search_trusted_core(
        target.architecture,
        &lowering.code,
        0,
        lowering.code.len(),
        &lowering.data,
        &lowering.relocations,
        core,
        OutputContract::Exists,
    )?;
    Ok(core)
}

/// Compose the selected proof with one already-lowered complete native DFA.
/// Numeric data-cap misses return that exact incumbent unchanged. Allocation
/// failures after selection are terminal under the compiler's monotonic
/// allocation policy.
pub(super) fn wrap_exact_finite_selected_end_teddy(
    selection: ExactFiniteSelectedEndTeddySelection<'_>,
    incumbent: NativeLowering,
    incumbent_complete_dfa: ExactFiniteSelectedEndDfaBaselineReport,
    target: Target,
    maximum_native_data_bytes: usize,
) -> Result<ExactFiniteSelectedEndTeddyWrapOutcome, ObjectError> {
    wrap_exact_finite_selected_end_teddy_with_basis(
        selection,
        incumbent,
        incumbent_complete_dfa,
        target,
        maximum_native_data_bytes,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
        ExactFiniteTeddySuccessMode::SelectedEnd,
        false,
    )
}

pub(super) fn wrap_exact_finite_selected_end_teddy_forced_v2(
    selection: ExactFiniteSelectedEndTeddySelection<'_>,
    incumbent: NativeLowering,
    incumbent_complete_dfa: ExactFiniteSelectedEndDfaBaselineReport,
    target: Target,
    maximum_native_data_bytes: usize,
) -> Result<ExactFiniteSelectedEndTeddyWrapOutcome, ObjectError> {
    wrap_exact_finite_selected_end_teddy_with_basis(
        selection,
        incumbent,
        incumbent_complete_dfa,
        target,
        maximum_native_data_bytes,
        ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility,
        ExactFiniteTeddySuccessMode::SelectedEnd,
        false,
    )
}

/// Compose an `Exists` Teddy negative accelerator with the already selected
/// complete-DFA incumbent. Positive candidates tail-enter that exact lowering.
pub(super) fn wrap_exact_finite_exists_teddy(
    selection: ExactFiniteSelectedEndTeddySelection<'_>,
    incumbent: NativeLowering,
    incumbent_complete_dfa: ExactFiniteSelectedEndDfaBaselineReport,
    target: Target,
    maximum_native_data_bytes: usize,
) -> Result<ExactFiniteSelectedEndTeddyWrapOutcome, ObjectError> {
    wrap_exact_finite_selected_end_teddy_with_basis(
        selection,
        incumbent,
        incumbent_complete_dfa,
        target,
        maximum_native_data_bytes,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
        ExactFiniteTeddySuccessMode::ExistsReverifyInIncumbent,
        false,
    )
}

/// Compose the same byte-identical Exists wrapper while publishing its private
/// self-framed ordinary entry for an explicitly requested direct batch/LF
/// endpoint transaction. That entry repeats public validation and owns its
/// save/restore frame. Scalar and aggregate compilation use the coreless
/// Stage-1 wrapper above.
pub(super) fn wrap_exact_finite_exists_teddy_with_trusted_core(
    selection: ExactFiniteSelectedEndTeddySelection<'_>,
    incumbent: NativeLowering,
    incumbent_complete_dfa: ExactFiniteSelectedEndDfaBaselineReport,
    target: Target,
    maximum_native_data_bytes: usize,
) -> Result<ExactFiniteSelectedEndTeddyWrapOutcome, ObjectError> {
    wrap_exact_finite_selected_end_teddy_with_basis(
        selection,
        incumbent,
        incumbent_complete_dfa,
        target,
        maximum_native_data_bytes,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
        ExactFiniteTeddySuccessMode::ExistsReverifyInIncumbent,
        true,
    )
}

fn wrap_exact_finite_selected_end_teddy_with_basis(
    selection: ExactFiniteSelectedEndTeddySelection<'_>,
    mut incumbent: NativeLowering,
    incumbent_complete_dfa: ExactFiniteSelectedEndDfaBaselineReport,
    target: Target,
    maximum_native_data_bytes: usize,
    selection_basis: ExactFiniteSelectedEndTeddySelectionBasisV2,
    success_mode: ExactFiniteTeddySuccessMode,
    publish_exists_trusted_core: bool,
) -> Result<ExactFiniteSelectedEndTeddyWrapOutcome, ObjectError> {
    if target != selection.target
        || selection.view.output()
            != match success_mode {
                ExactFiniteTeddySuccessMode::SelectedEnd => OutputContract::SelectedEnd,
                ExactFiniteTeddySuccessMode::ExistsReverifyInIncumbent => OutputContract::Exists,
            }
        || native_mandatory_teddy_isa(target) != Some(selection.isa)
        || !complete_dfa_baseline_report_has_valid_geometry(incumbent_complete_dfa, selection_basis)
        || incumbent_complete_dfa.native_data_bytes != incumbent.data.len()
        || incumbent_complete_dfa.scanner != incumbent.start_accelerator
        || incumbent.needs_runtime
        || incumbent.slow_partial_table.is_some()
        || incumbent.code.is_empty()
        || (publish_exists_trusted_core
            && success_mode != ExactFiniteTeddySuccessMode::ExistsReverifyInIncumbent)
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
    reserve_exact_finite_teddy_native_data(&mut incumbent.data, additional)?;
    let incumbent_trusted_core = incumbent.direct_search_trusted_core.take();
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

    let wrapper = match target.architecture {
        Architecture::X86_64 => {
            let mut wrapper = lower_x86_wrapper(&incumbent_code, verifier_layout, success_mode)?;
            let rebased = checked_rebase_relocations(
                incumbent_relocations,
                incumbent_code.len(),
                wrapper.incumbent_code_offset,
            )?;
            wrapper
                .relocations
                .try_reserve_exact(rebased.len())
                .map_err(|_| {
                    ObjectError::Allocation("exact finite SelectedEnd Teddy relocations")
                })?;
            wrapper.relocations.extend(rebased);
            wrapper
        }
        Architecture::Aarch64 => {
            let use_asimd_exact_verifier = target.features.has(CpuFeature::Aarch64Asimd)
                && selection.view.minimum_width()
                    >= u32::from(EXACT_FINITE_TEDDY_ASIMD_VERIFIER_BYTES);
            let mut wrapper = lower_aarch64_wrapper(
                &incumbent_code,
                verifier_layout,
                lane_index_offset,
                selection_basis,
                use_asimd_exact_verifier,
                success_mode,
            )?;
            let rebased = checked_rebase_relocations(
                incumbent_relocations,
                incumbent_code.len(),
                wrapper.incumbent_code_offset,
            )?;
            wrapper
                .relocations
                .try_reserve_exact(rebased.len())
                .map_err(|_| {
                    ObjectError::Allocation("exact finite SelectedEnd Teddy relocations")
                })?;
            wrapper.relocations.extend(rebased);
            wrapper
        }
    };
    incumbent.code = wrapper.code;
    incumbent.relocations = wrapper.relocations;
    incumbent.start_accelerator = report_scanner(selection.isa);
    incumbent.anchored_prefix_filter_bytes = selection.plan.columns();
    let report = report_for(
        selection,
        verifier_layout,
        &incumbent,
        &incumbent_code,
        wrapper.incumbent_code_offset,
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
    if publish_exists_trusted_core {
        incumbent.direct_search_trusted_core =
            Some(compose_exact_finite_exists_teddy_trusted_core(
                incumbent_trusted_core.ok_or(ObjectError::InvalidModule(
                    "exact finite Exists Teddy endpoint incumbent has no trusted core",
                ))?,
                &incumbent_code,
                &incumbent,
                &report,
                wrapper.trusted_core_offset,
                wrapper.tail_branch_offset,
                wrapper.incumbent_code_offset,
                target,
            )?);
    } else {
        // Scalar Stage one deliberately declines additive direct/LF endpoints
        // instead of publishing an unrequested private core.
        incumbent.direct_search_trusted_core = None;
    }
    let report_matches = match (success_mode, selection_basis) {
        (
            ExactFiniteTeddySuccessMode::SelectedEnd,
            ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
        ) => report_matches_lowering(&report, &incumbent, target)?,
        (
            ExactFiniteTeddySuccessMode::SelectedEnd,
            ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility,
        ) => report_matches_lowering_with_basis(&report, &incumbent, target, selection_basis)?,
        (
            ExactFiniteTeddySuccessMode::ExistsReverifyInIncumbent,
            ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
        ) => exists_report_matches_lowering(&report, &incumbent, target)?,
        (
            ExactFiniteTeddySuccessMode::ExistsReverifyInIncumbent,
            ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility,
        ) => false,
    };
    if !report_matches {
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
    report_matches_lowering_with_basis(
        report,
        lowering,
        target,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
    )
}

fn report_matches_lowering_with_basis(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    lowering: &NativeLowering,
    target: Target,
    selection_basis: ExactFiniteSelectedEndTeddySelectionBasisV2,
) -> Result<bool, ObjectError> {
    report_matches_parts_with_basis(
        report,
        &lowering.code,
        &lowering.data,
        &lowering.relocations,
        lowering.needs_runtime,
        lowering.slow_partial_table.is_some(),
        lowering.start_accelerator,
        lowering.anchored_prefix_filter_bytes,
        target,
        selection_basis,
        OutputContract::SelectedEnd,
    )
}

pub(super) fn exists_report_matches_lowering(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    lowering: &NativeLowering,
    target: Target,
) -> Result<bool, ObjectError> {
    report_matches_parts_with_basis(
        report,
        &lowering.code,
        &lowering.data,
        &lowering.relocations,
        lowering.needs_runtime,
        lowering.slow_partial_table.is_some(),
        lowering.start_accelerator,
        lowering.anchored_prefix_filter_bytes,
        target,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
        OutputContract::Exists,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the additive boundary re-authenticates every independently stored Exists lowering component"
)]
pub(super) fn exists_report_matches_parts(
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
    report_matches_parts_with_basis(
        report,
        code,
        data,
        relocations,
        needs_runtime,
        has_slow_partial_table,
        start_accelerator,
        anchored_prefix_filter_bytes,
        target,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
        OutputContract::Exists,
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
    report_matches_parts_with_basis(
        report,
        code,
        data,
        relocations,
        needs_runtime,
        has_slow_partial_table,
        start_accelerator,
        anchored_prefix_filter_bytes,
        target,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
        OutputContract::SelectedEnd,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "V2 module attachment re-authenticates every independently stored lowering component"
)]
pub(super) fn report_v2_matches_parts(
    report: &ExactFiniteSelectedEndTeddyAotReportV2,
    code: &[u8],
    data: &[u8],
    relocations: &[ModuleRelocation],
    needs_runtime: bool,
    has_slow_partial_table: bool,
    start_accelerator: StartAccelerator,
    anchored_prefix_filter_bytes: u8,
    target: Target,
) -> Result<bool, ObjectError> {
    Ok(report_v2_metadata_authenticates(report)
        && report_matches_parts_with_basis(
            &report.lowering,
            code,
            data,
            relocations,
            needs_runtime,
            has_slow_partial_table,
            start_accelerator,
            anchored_prefix_filter_bytes,
            target,
            report.selection_basis,
            OutputContract::SelectedEnd,
        )?)
}

#[allow(
    clippy::too_many_arguments,
    reason = "module attachment re-authenticates every independently stored lowering component"
)]
fn report_matches_parts_with_basis(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    code: &[u8],
    data: &[u8],
    relocations: &[ModuleRelocation],
    needs_runtime: bool,
    has_slow_partial_table: bool,
    start_accelerator: StartAccelerator,
    anchored_prefix_filter_bytes: u8,
    target: Target,
    selection_basis: ExactFiniteSelectedEndTeddySelectionBasisV2,
    expected_output: OutputContract,
) -> Result<bool, ObjectError> {
    let code_end = report
        .incumbent_code_offset
        .checked_add(report.incumbent_code_bytes);
    let incumbent = code_end
        .filter(|&end| end <= code.len())
        .and_then(|end| code.get(report.incumbent_code_offset..end));
    let incumbent_data = data.get(..report.incumbent_data_bytes);
    let incumbent_route_matches = complete_dfa_baseline_report_has_valid_geometry(
        report.incumbent_complete_dfa,
        selection_basis,
    ) && report.incumbent_complete_dfa.native_data_bytes
        == report.incumbent_data_bytes
        && incumbent_relocation_digest(
            relocations,
            report.incumbent_relocation_count,
            report.incumbent_code_offset,
            report.incumbent_code_bytes,
        )
        .is_some_and(|digest| digest == report.incumbent_relocations_sha256);
    let costs_authenticate = match selection_basis {
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1 => {
            report_costs_authenticate(report, data, target)?
        }
        ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility => {
            report_costs_authenticate_with_basis(report, data, target, selection_basis)?
        }
    };
    Ok(
        costs_authenticate
            && verifier_data_authenticates(report, data)?
            && report.artifact_identity != [0; 32]
            && report.output == expected_output
            && matches!(expected_output, OutputContract::Exists | OutputContract::SelectedEnd)
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
            && relocation_digest(relocations)
                .is_some_and(|digest| digest == report.relocations_sha256)
            && incumbent.is_some_and(|code| {
                Sha256::digest(code).as_slice() == report.incumbent_code_sha256
            })
            && incumbent_data.is_some_and(|data| {
                Sha256::digest(data).as_slice() == report.incumbent_data_sha256
            }),
    )
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
    report_costs_authenticate_with_basis(
        report,
        data,
        target,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
    )
}

fn report_costs_authenticate_with_basis(
    report: &ExactFiniteSelectedEndTeddyAotReport,
    data: &[u8],
    target: Target,
    selection_basis: ExactFiniteSelectedEndTeddySelectionBasisV2,
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
        if !complete_dfa_baseline_report_has_valid_geometry(incumbent, selection_basis)
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
            report.output,
            portfolio,
            u32::try_from(minimum_width).ok()?,
            root_members,
            target,
            incumbent,
            EXACT_FINITE_PREFIX_MIN_INPUT_BYTES,
            selection_basis,
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
            || report.batch_vectors != report_batch_vectors(selected_isa)
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
    refresh_report_parts_with_basis(
        report,
        code,
        data,
        relocations,
        needs_runtime,
        has_slow_partial_table,
        start_accelerator,
        anchored_prefix_filter_bytes,
        target,
        ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
        OutputContract::SelectedEnd,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "aggregate composition refreshes the full-module hashes and then replays exact attachment validation"
)]
fn refresh_report_parts_with_basis(
    report: &mut ExactFiniteSelectedEndTeddyAotReport,
    code: &[u8],
    data: &[u8],
    relocations: &[ModuleRelocation],
    needs_runtime: bool,
    has_slow_partial_table: bool,
    start_accelerator: StartAccelerator,
    anchored_prefix_filter_bytes: u8,
    target: Target,
    selection_basis: ExactFiniteSelectedEndTeddySelectionBasisV2,
    expected_output: OutputContract,
) -> Result<(), ObjectError> {
    report.native_code_sha256 = Sha256::digest(code).into();
    report.native_data_sha256 = Sha256::digest(data).into();
    report.relocations_sha256 = relocation_digest(relocations).ok_or(
        ObjectError::InvalidModule("exact finite SelectedEnd Teddy aggregate relocation digest"),
    )?;
    report.native_data_bytes = data.len();
    if !report_matches_parts_with_basis(
        report,
        code,
        data,
        relocations,
        needs_runtime,
        has_slow_partial_table,
        start_accelerator,
        anchored_prefix_filter_bytes,
        target,
        selection_basis,
        expected_output,
    )? {
        return Err(ObjectError::InvalidModule(
            "exact finite SelectedEnd Teddy aggregate composition changed its ordinary entry",
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "V2 aggregate composition refreshes both lowering and route bindings"
)]
pub(super) fn refresh_report_v2_parts(
    report: &mut ExactFiniteSelectedEndTeddyAotReportV2,
    code: &[u8],
    data: &[u8],
    relocations: &[ModuleRelocation],
    needs_runtime: bool,
    has_slow_partial_table: bool,
    start_accelerator: StartAccelerator,
    anchored_prefix_filter_bytes: u8,
    target: Target,
) -> Result<(), ObjectError> {
    refresh_report_parts_with_basis(
        &mut report.lowering,
        code,
        data,
        relocations,
        needs_runtime,
        has_slow_partial_table,
        start_accelerator,
        anchored_prefix_filter_bytes,
        target,
        report.selection_basis,
        OutputContract::SelectedEnd,
    )?;
    report.route_binding_sha256 = v2_route_binding_digest(report);
    if !report_v2_matches_parts(
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
            "exact finite SelectedEnd Teddy V2 aggregate composition changed its ordinary entry",
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

    fn scanner_free_exact_finite_pattern_variant() -> String {
        let mut pattern = String::from("(?-u:");
        for ordinal in 0_u8..17 {
            if ordinal != 0 {
                pattern.push('|');
            }
            let first = SCANNER_FREE_BYTES[usize::from(ordinal)];
            pattern.push_str(&format!("\\x{first:02x}"));
            let remainder = first ^ 1;
            for _ in 1..6 {
                pattern.push_str(&format!("\\x{remainder:02x}"));
            }
            if ordinal == 16 {
                pattern.push_str("\\xab");
            }
        }
        pattern.push(')');
        pattern
    }

    /// Public, shape-derived counterexample to treating an optimal four-range
    /// cover as the actual start-scanner decision. The production coalescer's
    /// deterministic merge order leaves a 65-byte cover, while every root is
    /// valid ASCII and the stable aggregate byte-frequency weight is small.
    fn deterministic_coalescer_ascii_pattern() -> String {
        const ROOTS: [u8; 8] = [0x0b, 0x1b, 0x1c, 0x2b, 0x3c, 0x59, 0x6b, 0x7f];
        let mut pattern = String::from("(?:");
        for (ordinal, root) in ROOTS.into_iter().enumerate() {
            if ordinal != 0 {
                pattern.push('|');
            }
            for _ in 0..6 + usize::from(ordinal + 1 == ROOTS.len()) {
                pattern.push_str(&format!("\\x{root:02x}"));
            }
        }
        pattern.push(')');
        pattern
    }

    fn x86_rel32_target(code: &[u8], displacement_offset: usize) -> usize {
        let displacement = i64::from(i32::from_le_bytes(
            code[displacement_offset..displacement_offset + 4]
                .try_into()
                .expect("complete x86 rel32 displacement"),
        ));
        usize::try_from(
            i64::try_from(displacement_offset + 4).expect("x86 rel32 source") + displacement,
        )
        .expect("x86 rel32 target")
    }

    fn aarch64_direct_branch_target(code: &[u8], instruction_offset: usize) -> usize {
        let instruction = u32::from_le_bytes(
            code[instruction_offset..instruction_offset + 4]
                .try_into()
                .expect("complete AArch64 direct branch"),
        );
        assert!(matches!(instruction >> 26, 0b000101 | 0b100101));
        let immediate = i64::from(instruction & 0x03ff_ffff);
        let signed_words = (immediate << 38) >> 38;
        let source = i64::try_from(instruction_offset).expect("AArch64 branch source");
        usize::try_from(source + signed_words * 4).expect("AArch64 branch target")
    }

    fn sparse_single_prefix_literals() -> Vec<Vec<u8>> {
        SCANNER_FREE_BYTES
            .iter()
            .copied()
            .enumerate()
            .map(|(ordinal, first)| {
                let mut literal = vec![
                    first,
                    u8::try_from(ordinal % 4).unwrap(),
                    SCANNER_FREE_BYTES[(ordinal + 3) % SCANNER_FREE_BYTES.len()],
                    SCANNER_FREE_BYTES[(ordinal + 7) % SCANNER_FREE_BYTES.len()],
                    SCANNER_FREE_BYTES[(ordinal + 11) % SCANNER_FREE_BYTES.len()],
                    SCANNER_FREE_BYTES[(ordinal + 13) % SCANNER_FREE_BYTES.len()],
                ];
                if ordinal + 1 == SCANNER_FREE_BYTES.len() {
                    literal.push(0xc8);
                }
                literal
            })
            .collect()
    }

    fn sparse_single_prefix_pattern() -> String {
        let mut pattern = String::from("(?-u:");
        for (ordinal, literal) in sparse_single_prefix_literals().iter().enumerate() {
            if ordinal != 0 {
                pattern.push('|');
            }
            for byte in literal {
                pattern.push_str(&format!("\\x{byte:02x}"));
            }
        }
        pattern.push(')');
        pattern
    }

    fn sparse_single_prefix_three_column_pattern() -> String {
        let mut literals = sparse_single_prefix_literals();
        for literal in &mut literals {
            literal.truncate(3);
        }
        literals.last_mut().unwrap().push(0xc8);
        let mut pattern = String::from("(?-u:");
        for (ordinal, literal) in literals.iter().enumerate() {
            if ordinal != 0 {
                pattern.push('|');
            }
            for byte in literal {
                pattern.push_str(&format!("\\x{byte:02x}"));
            }
        }
        pattern.push(')');
        pattern
    }

    fn fourth_column_disambiguation_pattern() -> String {
        // The first three bytes deliberately have a common modeled
        // fingerprint while the fourth separates the sources. Long exact
        // verifiers make that fourth column win the unchanged forced V2 cost
        // ordering, so this fixture truly emits all eight constant tables.
        const LITERAL_BYTES: usize = 192;
        let mut pattern = String::from("(?-u:");
        for (ordinal, fourth) in SCANNER_FREE_BYTES.into_iter().enumerate() {
            if ordinal != 0 {
                pattern.push('|');
            }
            for byte in [
                0xc0 + u8::try_from(ordinal % 2).unwrap(),
                b'\n',
                0x01,
                fourth,
                u8::try_from(ordinal).unwrap(),
                0xee,
            ] {
                pattern.push_str(&format!("\\x{byte:02x}"));
            }
            for _ in 6..LITERAL_BYTES {
                pattern.push_str("\\xee");
            }
            if ordinal + 1 == SCANNER_FREE_BYTES.len() {
                pattern.push_str("\\xc8");
            }
        }
        pattern.push(')');
        pattern
    }

    fn exact_verifier_boundary_literals(minimum_width: usize) -> Vec<Vec<u8>> {
        assert!(matches!(minimum_width, 15 | 16));
        [minimum_width, 17, 31, 32, 33, 47, 48, 63]
            .into_iter()
            .enumerate()
            .map(|(ordinal, width)| {
                (0..width)
                    .map(|index| {
                        if index == 0 {
                            SCANNER_FREE_BYTES[ordinal]
                        } else {
                            let value = ordinal
                                .checked_mul(53)
                                .and_then(|value| value.checked_add(index * 29))
                                .unwrap()
                                % 251;
                            u8::try_from(value).unwrap()
                        }
                    })
                    .collect()
            })
            .collect()
    }

    fn exact_verifier_boundary_pattern(minimum_width: usize) -> String {
        let mut pattern = String::from("(?-u:");
        for (ordinal, literal) in exact_verifier_boundary_literals(minimum_width)
            .iter()
            .enumerate()
        {
            if ordinal != 0 {
                pattern.push('|');
            }
            for byte in literal {
                pattern.push_str(&format!("\\x{byte:02x}"));
            }
        }
        pattern.push(')');
        pattern
    }

    fn exact_verifier_residue_pattern(first_residue: usize) -> (String, Vec<Vec<u8>>) {
        assert!(matches!(first_residue, 0 | 8));
        let literals = (first_residue..first_residue + 8)
            .enumerate()
            .map(|(ordinal, residue)| {
                (0..16 + residue)
                    .map(|index| {
                        if index == 0 {
                            SCANNER_FREE_BYTES[ordinal]
                        } else {
                            let value = first_residue
                                .checked_mul(71)
                                .and_then(|value| value.checked_add(ordinal * 53))
                                .and_then(|value| value.checked_add(index * 29))
                                .unwrap()
                                % 251;
                            u8::try_from(value).unwrap()
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut pattern = String::from("(?-u:");
        for (ordinal, literal) in literals.iter().enumerate() {
            if ordinal != 0 {
                pattern.push('|');
            }
            for byte in literal {
                pattern.push_str(&format!("\\x{byte:02x}"));
            }
        }
        pattern.push(')');
        (pattern, literals)
    }

    fn exact_verifier_late_ordinal_pattern() -> (String, Vec<u8>) {
        let mut literals = exact_verifier_boundary_literals(16);
        literals[0] = (0_u8..17)
            .map(|index| if index < 16 { 0x42 } else { 0x11 })
            .collect();
        literals[1] = (0_u8..17)
            .map(|index| if index < 16 { 0x42 } else { 0x22 })
            .collect();
        let expected = literals[1].clone();
        let mut pattern = String::from("(?-u:");
        for (ordinal, literal) in literals.iter().enumerate() {
            if ordinal != 0 {
                pattern.push('|');
            }
            for byte in literal {
                pattern.push_str(&format!("\\x{byte:02x}"));
            }
        }
        pattern.push(')');
        (pattern, expected)
    }

    fn sve_batch_column_schedule(column: u8, initialize: bool) -> Vec<u32> {
        let mut schedule = Vec::new();
        schedule.push(aarch64_add_x_reg(12, 0, 2).unwrap());
        if column != 0 {
            schedule.push(aarch64_add_x_imm(12, 12, u16::from(column)).unwrap());
        }
        for block in 0..EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS {
            schedule.push(aarch64_sve_ld1b_vl(block, 12, block).unwrap());
        }
        for block in 0..EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS {
            schedule.push(aarch64_sve_lsr_b_by_4(4 + block, block).unwrap());
        }
        for block in 0..EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS {
            schedule.push(aarch64_sve_and_z(block, block, 26).unwrap());
        }
        let low = 16 + 2 * column;
        let high = low + 1;
        for block in 0..EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS {
            schedule.push(aarch64_sve_tbl_b(block, low, block).unwrap());
        }
        for block in 0..EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS {
            schedule.push(aarch64_sve_tbl_b(4 + block, high, 4 + block).unwrap());
        }
        if initialize {
            for (block, &buckets) in AARCH64_MANDATORY_TEDDY_SVE_BATCH_BUCKET_REGISTERS
                .iter()
                .enumerate()
            {
                let source = u8::try_from(block).unwrap();
                schedule.push(aarch64_sve_and_z(buckets, source, 4 + source).unwrap());
            }
        } else {
            for block in 0..EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS {
                schedule.push(aarch64_sve_and_z(block, block, 4 + block).unwrap());
            }
            for (block, &buckets) in AARCH64_MANDATORY_TEDDY_SVE_BATCH_BUCKET_REGISTERS
                .iter()
                .enumerate()
            {
                let source = u8::try_from(block).unwrap();
                schedule.push(aarch64_sve_and_z(buckets, buckets, source).unwrap());
            }
        }
        schedule
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

    fn compile_exists(pattern: &str, target: Target) -> CompiledRegex {
        let compiled = compile(
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .expect("compile exact finite Exists Teddy fixture");
        let report = compiled
            .module()
            .exact_finite_exists_teddy_aot_report()
            .unwrap_or_else(|| {
                let choice = compiled.program().native_finite_exists_choice_view();
                let semantic = compiled.program().native_dfa_view().unwrap();
                let cost = NativeCompleteDfaCost::estimate_exists(&semantic)
                    .unwrap()
                    .unwrap();
                let incumbent = lower_native_dfa(semantic, target).unwrap().unwrap();
                let baseline = cost.exists_report(&semantic, &incumbent).unwrap();
                panic!(
                    "direct exact finite Exists Teddy route: pattern={pattern:?} engine={:?} choice={} static_accelerator={} scanner={:?} baseline={} selection={}",
                    compiled.receipt().engine,
                    choice.is_some(),
                    cost.has_accelerator,
                    incumbent.start_accelerator,
                    baseline.is_some(),
                    choice
                        .zip(baseline)
                        .and_then(|(choice, baseline)| select_exact_finite_exists_teddy(
                            compiled.program().artifact_identity(),
                            choice,
                            target,
                            baseline,
                        ))
                        .is_some(),
                )
            });
        assert_eq!(report.output, OutputContract::Exists);
        assert!((4..=64).contains(&report.source_count));
        assert!(report.minimum_width >= 3);
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
                .exact_finite_selected_end_teddy_aot
                .is_none(),
            "the internal Exists proof must not be exposed as SelectedEnd provenance",
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

    fn complete_exists_dfa_baseline(
        compiled: &CompiledRegex,
        target: Target,
    ) -> (NativeLowering, ExactFiniteSelectedEndDfaBaselineReport) {
        let semantic = compiled
            .program()
            .native_dfa_view()
            .expect("complete Exists semantic DFA");
        let cost = NativeCompleteDfaCost::estimate_exists(&semantic)
            .unwrap()
            .expect("Exists baseline cost");
        let incumbent = lower_native_dfa(semantic, target)
            .unwrap()
            .expect("Exists baseline lowering");
        let report = cost
            .exists_report(&semantic, &incumbent)
            .unwrap()
            .expect("Exists baseline report");
        (incumbent, report)
    }

    fn wrap_exists_fixture_lowering(
        compiled: &CompiledRegex,
        target: Target,
    ) -> NativeLowering {
        let choice = compiled
            .program()
            .native_finite_exists_choice_view()
            .expect("authenticated exact finite Exists Choice");
        let (incumbent, baseline) = complete_exists_dfa_baseline(compiled, target);
        let selection = select_exact_finite_exists_teddy(
            compiled.program().artifact_identity(),
            choice,
            target,
            baseline,
        )
        .expect("profitable exact finite Exists Teddy selection");
        let ExactFiniteSelectedEndTeddyWrapOutcome::Selected { lowering, .. } =
            wrap_exact_finite_exists_teddy(selection, incumbent, baseline, target, usize::MAX)
                .expect("compose exact finite Exists Teddy fixture")
        else {
            panic!("uncapped exact finite Exists Teddy fixture must select")
        };
        lowering
    }

    fn uninstalled_exists_teddy_module(
        compiled: &CompiledRegex,
        target: Target,
    ) -> (CompiledModule, ExactFiniteExistsTeddyAotReport) {
        let program = compiled.program();
        let semantic = program.native_dfa_view().expect("complete Exists DFA");
        let choice = program
            .native_finite_exists_choice_view()
            .expect("authenticated exact finite Exists Choice");
        let cost = NativeCompleteDfaCost::estimate_exists(&semantic)
            .unwrap()
            .expect("Exists complete-DFA cost");
        let incumbent = lower_exact_finite_teddy_incumbent_with_data_limit(
            semantic,
            target,
            usize::MAX,
        )
        .unwrap()
        .expect("Exists ordinary incumbent");
        let baseline = cost
            .exists_report(&semantic, &incumbent)
            .unwrap()
            .expect("Exists complete-DFA baseline");
        let selection = select_exact_finite_exists_teddy(
            program.artifact_identity(),
            choice,
            target,
            baseline,
        )
        .expect("Exists Teddy selection");
        let ExactFiniteSelectedEndTeddyWrapOutcome::Selected { lowering, report } =
            wrap_exact_finite_exists_teddy(
                selection,
                incumbent,
                baseline,
                target,
                usize::MAX,
            )
            .unwrap()
        else {
            panic!("uncapped Exists Teddy wrapper must select")
        };
        let module = CompiledModule::lower_serialized_with_prelowered(
            program.serialize().unwrap(),
            Some(lowering),
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            program.native_context_program_view(),
            program.native_bit_parallel_exists_view(),
            program.native_bit_parallel_endpoint_oracle_view(),
            program.native_partial_dfa_view(),
            program.native_dynamic_rows_view(),
            None,
            target,
        )
        .unwrap();
        (
            module,
            ExactFiniteExistsTeddyAotReport {
                lowering: report,
                trusted_core: None,
            },
        )
    }

    fn installed_exists_teddy_module(
        compiled: &CompiledRegex,
        target: Target,
    ) -> CompiledModule {
        let (mut module, report) = uninstalled_exists_teddy_module(compiled, target);
        module
            .install_exact_finite_exists_teddy_aot_report(
                report,
                compiled.program().artifact_identity(),
                compiled.program().native_dfa_view().unwrap(),
                compiled
                    .program()
                    .native_finite_exists_choice_view()
                    .unwrap(),
            )
            .expect("install authenticated Exists Teddy fixture");
        module
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
                .map(|view| (view, usize::MAX, true)),
            target,
        )
        .unwrap()
    }

    fn unchanged_exists_module(compiled: &CompiledRegex, target: Target) -> CompiledModule {
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
                .map(|view| (view, usize::MAX, true)),
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
            assert_eq!(
                report.batch_vectors,
                if report.emitted_isa == ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve {
                    EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS
                } else {
                    EXACT_FINITE_TEDDY_UNBATCHED_VECTORS
                },
                "authenticated batch width: {target:?}",
            );
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
        for pattern in ["alpha|bravo", "alpha|bravo|cider", "aa|bb|cc|dd"] {
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
            assert!(
                compiled
                    .program()
                    .native_finite_selected_end_teddy_view()
                    .is_none(),
                "two/three literals and sub-three-byte arms are structural declines",
            );
            let disabled = crate::compile_v2(
                crate::CompileRequestV2::new(
                    CompileRequest::new(pattern, avx2_target())
                        .mode(CompileMode::Optimizing)
                        .output(OutputContract::SelectedEnd),
                )
                .exact_finite_selected_end_teddy(
                    crate::ExactFiniteSelectedEndTeddyPolicyV2::Disabled,
                ),
            )
            .expect("structural Teddy decline must preserve ordinary compilation");
            assert_byte_identical_module(compiled.module(), disabled.module());
            assert_eq!(compiled.object(), disabled.object());
            assert_eq!(compiled.receipt(), disabled.receipt());
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
    fn valid_ascii_deterministic_coalescer_shape_selects_exists_teddy() {
        let pattern = deterministic_coalescer_ascii_pattern();
        for target in [
            avx2_target(),
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
        ] {
            let compiled = compile_exists(&pattern, target);
            let report = compiled
                .module()
                .exact_finite_exists_teddy_aot_report()
                .expect("valid-ASCII shape selects direct Exists Teddy");
            assert_eq!(report.source_count, 8);
            assert_eq!(report.source_bytes, 49);
            assert_eq!((report.minimum_width, report.maximum_width), (6, 7));
            assert_ne!(report.scanner, StartAccelerator::None);
            assert!(!report.incumbent_complete_dfa.has_accelerator);
            assert_eq!(
                report.incumbent_complete_dfa.scanner,
                StartAccelerator::None,
            );
        }
    }

    #[test]
    fn exists_teddy_route_is_internal_and_declines_two_or_three_literals_byte_identically() {
        let target = avx2_target();
        let pattern = scanner_free_exact_finite_pattern();
        let compiled = compile_exists(&pattern, target);
        let report = compiled
            .module()
            .exact_finite_exists_teddy_aot_report()
            .expect("selected internal Exists Teddy proof");
        assert!(!report.incumbent_complete_dfa.has_accelerator);
        assert_eq!(report.scanner, StartAccelerator::X86Avx2);
        assert!(
            exists_report_matches_lowering(
                report,
                &wrap_exists_fixture_lowering(&compiled, target),
                target,
            )
            .unwrap(),
        );

        for source_count in [2, 3] {
            assert!(
                !exact_finite_exists_teddy_source_count_is_supported(source_count),
                "valid two/three-literal choices must decline before target lowering",
            );
        }

        for pattern in ["alpha|bravo", "alpha|bravo|cider"] {
            let compiled = compile(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Exists),
            )
            .expect("compile structurally valid small Exists Choice");
            assert!(
                compiled
                    .module()
                    .exact_finite_exists_teddy_aot_report()
                    .is_none(),
            );
            let unchanged = unchanged_exists_module(&compiled, target);
            assert_byte_identical_module(compiled.module(), &unchanged);
            let unchanged_object = crate::emit_object(
                &unchanged,
                crate::ObjectFormat::for_target(target),
                usize::MAX,
            )
            .unwrap();
            assert_eq!(compiled.object(), unchanged_object);
        }
    }

    #[test]
    fn exists_teddy_installer_rejects_swapped_program_self_signed_tail_and_stale_core() {
        let target = avx2_target();
        let compiled_a = compile_exists(&scanner_free_exact_finite_pattern(), target);
        let compiled_b = compile(
            CompileRequest::new(scanner_free_exact_finite_pattern_variant(), target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .expect("compile same-geometry alternate Exists program");

        let (mut module, report) = uninstalled_exists_teddy_module(&compiled_a, target);
        let mut wrong_artifact = compiled_a.program().artifact_identity();
        wrong_artifact[0] ^= 1;
        assert!(module
            .install_exact_finite_exists_teddy_aot_report(
                report,
                wrong_artifact,
                compiled_a.program().native_dfa_view().unwrap(),
                compiled_a
                    .program()
                    .native_finite_exists_choice_view()
                    .unwrap(),
            )
            .is_err());

        let (mut module, report) = uninstalled_exists_teddy_module(&compiled_a, target);
        module.serialized_program_identity = compiled_b.module().serialized_program_identity;
        assert!(module
            .install_exact_finite_exists_teddy_aot_report(
                report,
                compiled_a.program().artifact_identity(),
                compiled_a.program().native_dfa_view().unwrap(),
                compiled_a
                    .program()
                    .native_finite_exists_choice_view()
                    .unwrap(),
            )
            .is_err());

        let (mut module, report) = uninstalled_exists_teddy_module(&compiled_a, target);
        assert!(module
            .install_exact_finite_exists_teddy_aot_report(
                report,
                compiled_a.program().artifact_identity(),
                compiled_b.program().native_dfa_view().unwrap(),
                compiled_a
                    .program()
                    .native_finite_exists_choice_view()
                    .unwrap(),
            )
            .is_err());

        let (mut module, report) = uninstalled_exists_teddy_module(&compiled_a, target);
        assert!(module
            .install_exact_finite_exists_teddy_aot_report(
                report,
                compiled_a.program().artifact_identity(),
                compiled_a.program().native_dfa_view().unwrap(),
                compiled_b
                    .program()
                    .native_finite_exists_choice_view()
                    .unwrap(),
            )
            .is_err());

        // Forge the wrapper's final tail jump while refreshing the generic
        // whole-code hash. Deterministic Exists regeneration must still reject
        // this otherwise self-consistent record.
        let (mut module, mut report) = uninstalled_exists_teddy_module(&compiled_a, target);
        let incumbent = report.lowering.incumbent_code_offset;
        let tail = module.sections[TEXT_SECTION]
            .data
            .get(..incumbent)
            .unwrap()
            .windows(5)
            .enumerate()
            .find_map(|(offset, bytes)| {
                if bytes[0] != 0xe9 {
                    return None;
                }
                let displacement = i32::from_le_bytes(bytes[1..].try_into().ok()?);
                let target = i64::try_from(offset + 5)
                    .ok()?
                    .checked_add(i64::from(displacement))?;
                (usize::try_from(target).ok() == Some(incumbent)).then_some(offset)
            })
            .expect("x86 Exists Teddy tail jump");
        module.sections[TEXT_SECTION].data[tail + 1] ^= 1;
        report.lowering.native_code_sha256 =
            Sha256::digest(module.sections[TEXT_SECTION].bytes()).into();
        assert!(module
            .install_exact_finite_exists_teddy_aot_report(
                report,
                compiled_a.program().artifact_identity(),
                compiled_a.program().native_dfa_view().unwrap(),
                compiled_a
                    .program()
                    .native_finite_exists_choice_view()
                    .unwrap(),
            )
            .is_err());

        let (mut module, mut report) = uninstalled_exists_teddy_module(&compiled_a, target);
        report.lowering.output = OutputContract::SelectedEnd;
        assert!(module
            .install_exact_finite_exists_teddy_aot_report(
                report,
                compiled_a.program().artifact_identity(),
                compiled_a.program().native_dfa_view().unwrap(),
                compiled_a
                    .program()
                    .native_finite_exists_choice_view()
                    .unwrap(),
            )
            .is_err());

        let (mut module, report) = uninstalled_exists_teddy_module(&compiled_a, target);
        let semantic = compiled_a.program().native_dfa_view().unwrap();
        module.native_direct_search_trusted_core =
            lower_exact_finite_teddy_incumbent_with_data_limit(semantic, target, usize::MAX)
                .unwrap()
                .unwrap()
                .direct_search_trusted_core;
        assert!(module.native_direct_search_trusted_core.is_some());
        assert!(module
            .install_exact_finite_exists_teddy_aot_report(
                report,
                compiled_a.program().artifact_identity(),
                semantic,
                compiled_a
                    .program()
                    .native_finite_exists_choice_view()
                    .unwrap(),
            )
            .is_err());
    }

    #[test]
    fn exists_teddy_grep_count_authenticates_then_drops_only_its_internal_receipt() {
        let target = avx2_target();
        let pattern = scanner_free_exact_finite_pattern();
        let compiled = compile_exists(&pattern, target);
        let identity = compiled.program().artifact_identity();
        let module = installed_exists_teddy_module(&compiled, target);
        let serialized = compiled.program().serialize().unwrap();
        let report = *module
            .exact_finite_exists_teddy_aot_report()
            .expect("installed Exists Teddy report");
        module
            .authenticate_exact_finite_exists_teddy_before_additive_surface(
                identity,
                serialized.len(),
            )
            .expect("authenticate exact ordinary prefix before append");

        let mut wrong_identity = identity;
        wrong_identity[0] ^= 1;
        assert!(module
            .authenticate_exact_finite_exists_teddy_before_additive_surface(
                wrong_identity,
                serialized.len(),
            )
            .is_err());

        let mut forged_entry = module.clone();
        forged_entry.sections[TEXT_SECTION].data[report.incumbent_code_offset] ^= 1;
        assert!(forged_entry
            .authenticate_exact_finite_exists_teddy_before_additive_surface(
                identity,
                serialized.len(),
            )
            .is_err());

        let mut forged_wrapper = module.clone();
        let wrapper_prefix = report
            .incumbent_code_offset
            .checked_sub(1)
            .expect("Exists Teddy wrapper prefix byte");
        forged_wrapper.sections[TEXT_SECTION].data[wrapper_prefix] ^= 1;
        assert!(forged_wrapper
            .authenticate_exact_finite_exists_teddy_before_additive_surface(
                identity,
                serialized.len(),
            )
            .is_err());

        assert!(matches!(
            module.can_append_exact_finite_selected_end_grep_count(),
            Err(ObjectError::InvalidModule(
                "exact-finite SelectedEnd GrepCount cannot compose an Exists Teddy leaf"
            )),
        ));

        let aggregate = crate::compile_with_prepared_aggregate_exports(
            CompileRequest::new(&pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
            crate::PreparedAggregateExports::GREP_COUNT,
        )
        .expect("compile public Exists Teddy GrepCount aggregate");
        assert!(aggregate.module().prepared_grep_count_symbol().is_some());
        assert_eq!(
            aggregate.module().prepared_aggregate_strategy(),
            Some(crate::PreparedAggregateStrategy::NativeFused),
        );
        assert!(aggregate
            .module()
            .exact_finite_exists_teddy_aot_report()
            .is_none());
        assert_eq!(aggregate.module().start_accelerator(), StartAccelerator::X86Avx2);
    }

    #[test]
    fn independent_exists_endpoints_publish_the_authenticated_teddy_core() {
        let target = avx2_target();
        let pattern = scanner_free_exact_finite_pattern();
        let request = || {
            CompileRequest::new(&pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists)
        };
        let scalar = Box::new(compile(request()).expect("compile scalar Exists Teddy fixture"));
        assert!(scalar
            .module()
            .exact_finite_exists_teddy_aot_report()
            .is_some());
        assert!(scalar.module().native_direct_search_trusted_core.is_none());

        let endpoint_scope =
            direct_exists_endpoint_incumbent_scope(DirectExistsEndpointRequest::Batch);
        let ordinary =
            Box::new(compile(request()).expect("compile direct Teddy endpoint incumbent"));
        drop(endpoint_scope);
        assert!(
            ordinary
                .module()
                .exact_finite_exists_teddy_aot_report()
                .is_some()
        );
        assert!(
            ordinary
                .module()
                .native_direct_search_trusted_core
                .is_some()
        );
        assert_eq!(
            ordinary.module().start_accelerator(),
            StartAccelerator::X86Avx2
        );
        assert!(
            ordinary
                .module()
                .has_exact_finite_exists_teddy_trusted_core()
        );
        assert_eq!(ordinary.module().sections(), scalar.module().sections());
        assert_eq!(ordinary.module().symbols(), scalar.module().symbols());
        assert_eq!(
            ordinary.module().relocations(),
            scalar.module().relocations()
        );
        assert_eq!(ordinary.object(), scalar.object());

        let mut missing_report = ordinary.module().clone();
        missing_report.exact_finite_exists_leaf_report = None;
        assert!(matches!(
            missing_report.append_direct_exists_batch(OutputContract::Exists),
            Err(ObjectError::InvalidModule(
                "direct Exists Teddy core has no deterministic lowering receipt"
            ))
        ));

        let single = Box::new(compile(
            CompileRequest::new("public-single-literal", target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .expect("compile other-leaf forgery fixture"));
        let mut other_leaf = ordinary.module().clone();
        other_leaf.exact_finite_exists_leaf_report =
            single.module().exact_finite_exists_leaf_report.clone();
        assert!(matches!(
            other_leaf.append_direct_exists_batch(OutputContract::Exists),
            Err(ObjectError::InvalidModule(
                "direct Exists Teddy core has no deterministic lowering receipt"
            ))
        ));

        let mut cross_family = ordinary.module().clone();
        let mut forged_core = cross_family.native_direct_search_trusted_core.unwrap();
        forged_core.entry_contract = NativeDirectSearchEntryContract::PublicCompleteV1;
        forged_core.prologue = NativeDirectSearchTrustedCorePrologue::X86_64 {
            save_rbx: false,
            save_r12_r13: false,
            save_r14_r15: false,
        };
        cross_family.native_direct_search_trusted_core = Some(forged_core);
        let Some(ExactFiniteExistsLeafReport::Teddy(report)) =
            cross_family.exact_finite_exists_leaf_report.as_mut()
        else {
            panic!("Teddy cross-family forgery receipt");
        };
        report.trusted_core = Some(forged_core);
        assert!(matches!(
            cross_family.append_direct_exists_batch(OutputContract::Exists),
            Err(ObjectError::InvalidModule(
                "direct search trusted core contract is inconsistent"
            ))
        ));
        let identity = ordinary.program().artifact_identity();
        let expected_batch = ordinary
            .module()
            .clone()
            .append_direct_exists_batch(OutputContract::Exists)
            .expect("append expected direct Exists batch")
            .expect("authenticated Teddy core owns a direct Exists batch");
        let expected_batch_object = crate::emit_object(
            &expected_batch,
            crate::ObjectFormat::for_target(target),
            usize::MAX,
        )
        .unwrap();

        let batch = Box::new(
            crate::compile_with_independent_exists_batch(request())
                .expect("compile public independent Exists batch"),
        );
        assert_eq!(batch.module(), &expected_batch);
        assert_eq!(batch.object(), expected_batch_object);
        assert!(batch.module().direct_exists_batch_symbol().is_some());
        assert_eq!(
            batch.module().direct_exists_batch_strategy(),
            Some(DirectExistsBatchStrategy::NativeTeddyTrustedCoreV1),
        );
        assert!(
            batch
                .module()
                .exact_finite_exists_teddy_aot_report()
                .is_some()
        );
        assert_eq!(batch.program().artifact_identity(), identity);

        let endpoint_scope = direct_exists_endpoint_incumbent_scope(
            DirectExistsEndpointRequest::BatchAndMatchingLfWitness,
        );
        let witness_scope = matching_lf_line_witness_recipe_scope(true);
        let tracked =
            Box::new(compile(request()).expect("compile tracked direct endpoint incumbent"));
        drop(witness_scope);
        drop(endpoint_scope);
        assert!(
            tracked
                .module()
                .has_exact_finite_exists_teddy_trusted_core()
        );
        let expected_witness = tracked
            .module()
            .clone()
            .append_direct_exists_batch(OutputContract::Exists)
            .expect("append tracked direct Exists batch")
            .expect("tracked Teddy core owns a direct Exists batch")
            .append_direct_matching_lf_line_witness(OutputContract::Exists)
            .expect("append expected matching-LF witness")
            .expect("tracked Teddy core owns a matching-LF witness");
        let expected_witness_object = crate::emit_object(
            &expected_witness,
            crate::ObjectFormat::for_target(target),
            usize::MAX,
        )
        .unwrap();
        let witness = Box::new(
            crate::compile_with_independent_matching_lf_line_witness(request())
                .expect("compile public matching-LF-line witness"),
        );
        assert_eq!(witness.module(), &expected_witness);
        assert_eq!(witness.object(), expected_witness_object);
        assert!(witness.module().direct_exists_batch_symbol().is_some());
        assert!(
            witness
                .module()
                .direct_matching_lf_line_witness_symbol()
                .is_some()
        );
        assert_eq!(
            witness.module().direct_matching_lf_line_witness_strategy(),
            Some(MatchingLfLineWitnessStrategy::NativeTeddyTrustedCoreV1),
        );
        assert!(
            witness
                .module()
                .direct_matching_lf_line_witness_aot_report()
                .is_some_and(|report| report.exact_finite_language.is_some())
        );
        assert!(
            witness
                .module()
                .exact_finite_exists_teddy_aot_report()
                .is_some()
        );
    }

    #[test]
    fn exists_teddy_coreful_lowering_preserves_code_data_and_relocations_on_both_isas() {
        let pattern = scanner_free_exact_finite_pattern();
        for target in [
            avx2_target(),
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .expect("valid AArch64 ASIMD target"),
        ] {
            let request = || {
                CompileRequest::new(&pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Exists)
            };
            let scalar = compile(request()).expect("compile scalar Teddy control");
            let scope = direct_exists_endpoint_incumbent_scope(
                DirectExistsEndpointRequest::BatchAndMatchingLfWitness,
            );
            let recipe = matching_lf_line_witness_recipe_scope(true);
            let coreful = compile(request()).expect("compile coreful Teddy fixture");
            drop(recipe);
            drop(scope);
            assert_eq!(coreful.module().sections(), scalar.module().sections());
            assert_eq!(coreful.module().symbols(), scalar.module().symbols());
            assert_eq!(
                coreful.module().relocations(),
                scalar.module().relocations()
            );
            assert_eq!(coreful.object(), scalar.object());

            let scalar_report = scalar
                .module()
                .exact_finite_exists_teddy_aot_report()
                .expect("scalar Teddy report");
            let coreful_report = coreful
                .module()
                .exact_finite_exists_teddy_aot_report()
                .expect("coreful Teddy report");
            assert_eq!(
                coreful_report.incumbent_relocation_count,
                scalar_report.incumbent_relocation_count,
            );
            assert_eq!(
                coreful_report.incumbent_relocations_sha256,
                scalar_report.incumbent_relocations_sha256,
            );
            let core = coreful
                .module()
                .native_direct_search_trusted_core
                .expect("coreful Teddy trusted core");
            let NativeDirectSearchTrustedCoreLandmark::ExactFiniteExistsTeddyV1 {
                tail_branch_offset,
                incumbent_entry_offset,
                incumbent_core_offset,
                ..
            } = core.landmark
            else {
                panic!("coreful Teddy landmark");
            };
            assert_eq!(core.code_offset, 0);
            assert!(core.matching_lf_line_cursor.is_some_and(|cursor| {
                cursor.matched_offset >= incumbent_core_offset
                    && cursor.edges[..usize::from(cursor.edge_count)]
                        .iter()
                        .all(|edge| edge.instruction_offset >= incumbent_core_offset)
            }));

            let ordinary_text = coreful.module().sections[TEXT_SECTION].bytes();
            match target.architecture {
                Architecture::X86_64 => {
                    assert_eq!(ordinary_text[tail_branch_offset], 0xe9);
                    assert_eq!(
                        x86_rel32_target(ordinary_text, tail_branch_offset + 1),
                        incumbent_entry_offset,
                    );
                }
                Architecture::Aarch64 => assert_eq!(
                    aarch64_direct_branch_target(ordinary_text, tail_branch_offset),
                    incumbent_entry_offset,
                ),
            }

            let batch = coreful
                .module()
                .clone()
                .append_direct_exists_batch(OutputContract::Exists)
                .expect("append self-framed Teddy batch")
                .expect("self-framed Teddy batch eligibility");
            let batch_name = batch
                .direct_exists_batch_symbol()
                .expect("self-framed Teddy batch symbol");
            let batch_symbol = batch
                .symbols()
                .iter()
                .find(|symbol| symbol.name == batch_name)
                .expect("self-framed Teddy batch symbol record");
            let batch_start = usize::try_from(batch_symbol.offset).expect("batch start");
            let batch_text = batch.sections[TEXT_SECTION].bytes();
            let wrapper = match target.architecture {
                Architecture::X86_64 => lower_x86_64_direct_exists_batch(core.prologue),
                Architecture::Aarch64 => lower_aarch64_direct_exists_batch(core.prologue),
            }
            .expect("lower self-framed Teddy batch wrapper");
            match target.architecture {
                Architecture::X86_64 => {
                    assert_eq!(
                        core.prologue,
                        NativeDirectSearchTrustedCorePrologue::X86_64SelfFramed,
                    );
                    assert_eq!(
                        &wrapper.code[wrapper.trampoline_offset..wrapper.core_jump_offset + 4],
                        &[0x31, 0xc0, 0xe9, 0, 0, 0, 0],
                        "self-framed trampoline must not imitate Teddy's register frame",
                    );
                    assert_eq!(
                        x86_rel32_target(
                            batch_text,
                            batch_start + wrapper.search_call_offset,
                        ),
                        batch_start + wrapper.trampoline_offset,
                    );
                    assert_eq!(
                        x86_rel32_target(batch_text, batch_start + wrapper.core_jump_offset),
                        core.code_offset,
                    );
                }
                Architecture::Aarch64 => {
                    assert_eq!(
                        core.prologue,
                        NativeDirectSearchTrustedCorePrologue::Aarch64SelfFramed,
                    );
                    let mut expected = 0xf100_001f_u32.to_le_bytes().to_vec();
                    expected.extend_from_slice(&0x1400_0000_u32.to_le_bytes());
                    assert_eq!(
                        &wrapper.code[wrapper.trampoline_offset..wrapper.core_jump_offset + 4],
                        expected.as_slice(),
                    );
                    assert_eq!(
                        aarch64_direct_branch_target(
                            batch_text,
                            batch_start + wrapper.search_call_offset,
                        ),
                        batch_start + wrapper.trampoline_offset,
                    );
                    assert_eq!(
                        aarch64_direct_branch_target(
                            batch_text,
                            batch_start + wrapper.core_jump_offset,
                        ),
                        core.code_offset,
                    );
                }
            }
        }
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
            let disabled = crate::compile_v2(
                crate::CompileRequestV2::new(
                    CompileRequest::new(&pattern, target)
                        .mode(CompileMode::Optimizing)
                        .output(OutputContract::SelectedEnd),
                )
                .exact_finite_selected_end_teddy(
                    crate::ExactFiniteSelectedEndTeddyPolicyV2::Disabled,
                ),
            )
            .expect("accelerator Teddy decline must preserve ordinary compilation");
            assert_byte_identical_module(compiled.module(), disabled.module());
            assert_eq!(compiled.object(), disabled.object(), "{kind}");
            assert_eq!(compiled.receipt(), disabled.receipt(), "{kind}");
        }
    }

    #[test]
    fn exists_teddy_unsupported_isa_and_accelerated_incumbent_decline_byte_identically() {
        let fixtures = [
            (
                "unsupported-isa",
                Target::x86_64_linux(),
                scanner_free_exact_finite_pattern(),
            ),
            (
                "accelerated-incumbent",
                avx2_target(),
                accelerated_exact_finite_pattern().to_owned(),
            ),
        ];
        for (kind, target, pattern) in fixtures {
            let compiled = compile(
                CompileRequest::new(&pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::Exists),
            )
            .unwrap();
            assert!(
                compiled
                    .module()
                    .exact_finite_exists_teddy_aot_report()
                    .is_none(),
                "{kind}",
            );
            let unchanged = unchanged_exists_module(&compiled, target);
            assert_byte_identical_module(compiled.module(), &unchanged);
            assert_eq!(
                compiled.object(),
                crate::emit_object(
                    &unchanged,
                    crate::ObjectFormat::for_target(target),
                    usize::MAX,
                )
                .unwrap(),
                "{kind}",
            );
        }
    }

    fn accelerated_exact_finite_pattern() -> &'static str {
        "samwise|samw|frodo|pippin"
    }

    fn force_v2(pattern: &str, target: Target) -> crate::CompiledRegexV2 {
        crate::compile_v2(
            crate::CompileRequestV2::new(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            )
            .exact_finite_selected_end_teddy(
                crate::ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible,
            ),
        )
        .expect("compile forced structurally eligible Teddy V2")
    }

    #[test]
    fn v2_automatic_is_stable_v1_byte_for_byte() {
        let target = avx2_target();
        let pattern = scanner_free_exact_finite_pattern();
        let request = || {
            CompileRequest::new(&pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd)
        };
        let stable = compile(request()).unwrap();
        let v2 = crate::compile_v2(crate::CompileRequestV2::new(request())).unwrap();
        assert_eq!(v2.object(), stable.object());
        assert_eq!(v2.module(), stable.module());
        assert_eq!(v2.receipt(), stable.receipt());
        let stable_report = stable
            .receipt()
            .exact_finite_selected_end_teddy_aot
            .expect("stable fixture selects V1 Teddy");
        let supplement = v2
            .receipt_v2()
            .exact_finite_selected_end_teddy_aot
            .expect("V2 Automatic describes the same selection");
        assert_eq!(
            supplement.selection_basis,
            ExactFiniteSelectedEndTeddySelectionBasisV2::AutomaticV1,
        );
        assert!(!supplement.performance_admission_bypassed);
        assert_eq!(supplement.lowering, stable_report);

        let accelerated_request = || {
            CompileRequest::new(accelerated_exact_finite_pattern(), target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd)
        };
        let stable = compile(accelerated_request()).unwrap();
        let v2 = crate::compile_v2(crate::CompileRequestV2::new(accelerated_request())).unwrap();
        assert_eq!(v2.object(), stable.object());
        assert_eq!(v2.module(), stable.module());
        assert_eq!(v2.receipt(), stable.receipt());
        assert_eq!(
            v2.receipt_v2().exact_finite_selected_end_teddy_policy,
            crate::ExactFiniteSelectedEndTeddyPolicyV2::Automatic,
        );
        assert!(
            v2.receipt_v2()
                .exact_finite_selected_end_teddy_aot
                .is_none(),
            "Automatic must not enable the accelerated-incumbent experiment",
        );
    }

    #[test]
    fn v2_disabled_is_byte_identical_to_the_established_ordinary_module() {
        let target = avx2_target();
        let pattern = scanner_free_exact_finite_pattern();
        let stable = compile_selected(&pattern, target);
        let ordinary = unchanged_selected_end_module(&stable, target);
        let ordinary_object = crate::emit_object(
            &ordinary,
            crate::ObjectFormat::for_target(target),
            usize::MAX,
        )
        .unwrap();
        let disabled = crate::compile_v2(
            crate::CompileRequestV2::new(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            )
            .exact_finite_selected_end_teddy(crate::ExactFiniteSelectedEndTeddyPolicyV2::Disabled),
        )
        .unwrap();
        assert_byte_identical_module(disabled.module(), &ordinary);
        assert_eq!(disabled.object(), ordinary_object);
        assert!(
            disabled
                .receipt()
                .exact_finite_selected_end_teddy_aot
                .is_none(),
        );
        assert!(
            disabled
                .receipt_v2()
                .exact_finite_selected_end_teddy_aot
                .is_none(),
        );
    }

    #[test]
    fn teddy_incumbent_classifier_only_declines_authenticated_numeric_cap() {
        let limit = 31;
        assert!(
            exact_finite_teddy_incumbent_outcome(
                Err(ObjectError::Resource {
                    resource: crate::CompileResource::ProgramBytes,
                    limit,
                    required: limit + 1,
                }),
                limit,
            )
            .unwrap()
            .is_none(),
            "an exact effective-cap miss is the one recoverable outcome",
        );
        assert!(matches!(
            exact_finite_teddy_incumbent_outcome(
                Err(ObjectError::Allocation("injected Teddy incumbent seam")),
                limit,
            ),
            Err(ObjectError::Allocation(_)),
        ));
        assert!(matches!(
            exact_finite_teddy_incumbent_outcome(
                Err(ObjectError::Resource {
                    resource: crate::CompileResource::ProgramBytes,
                    limit,
                    required: limit,
                }),
                limit,
            ),
            Err(ObjectError::Resource {
                resource: crate::CompileResource::ProgramBytes,
                limit: 31,
                required: 31,
            }),
        ));
        assert!(matches!(
            exact_finite_teddy_incumbent_outcome(
                Err(ObjectError::Resource {
                    resource: crate::CompileResource::ProgramBytes,
                    limit: limit - 1,
                    required: limit,
                }),
                limit,
            ),
            Err(ObjectError::Resource {
                resource: crate::CompileResource::ProgramBytes,
                limit: 30,
                required: 31,
            }),
        ));
        assert!(matches!(
            exact_finite_teddy_incumbent_outcome(
                Err(ObjectError::InvalidModule("injected Teddy backend seam")),
                limit,
            ),
            Err(ObjectError::InvalidModule(_)),
        ));
    }

    #[test]
    fn exists_teddy_post_selection_allocation_failure_is_terminal_end_to_end() {
        let target = avx2_target();
        let pattern = scanner_free_exact_finite_pattern();
        compile_exists(&pattern, target);

        let injection = ExactFiniteTeddyNativeDataAllocationInjection::arm();
        let result = compile(
            CompileRequest::new(&pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        );
        injection.assert_failed_once();
        assert!(matches!(
            result,
            Err(crate::CompileError::Object(ObjectError::Allocation(
                EXACT_FINITE_TEDDY_NATIVE_DATA_ALLOCATION_SITE,
            ))),
        ));
    }

    #[test]
    fn exists_teddy_admission_charges_incumbent_reverify_and_retains_material_gain() {
        let target = avx2_target();
        let pattern = scanner_free_exact_finite_pattern();
        let exists = compile_exists(&pattern, target);
        let selected_end = compile_selected(&pattern, target);
        let exists = exists
            .module()
            .exact_finite_exists_teddy_aot_report()
            .unwrap();
        let selected_end = selected_end
            .module()
            .exact_finite_selected_end_teddy_aot_report()
            .unwrap();
        assert_eq!(
            exists.selection_gate_cost_units,
            selected_end.selection_gate_cost_units,
        );
        assert_eq!(
            exists.selection_expected_verification_cost_units,
            selected_end.selection_expected_verification_cost_units,
        );
        assert!(
            exists.selection_full_cost_units > selected_end.selection_full_cost_units,
            "Exists must price the authoritative incumbent replay after an exact hit",
        );
        assert!(
            exists
                .selection_full_cost_units
                .checked_mul(EXACT_FINITE_TEDDY_MATERIAL_GAIN_DENOMINATOR)
                .unwrap()
                <= exists
                    .selection_incumbent_cost_units
                    .checked_mul(EXACT_FINITE_TEDDY_MATERIAL_GAIN_NUMERATOR)
                    .unwrap(),
            "the reverify-inclusive cost must still pass the 7/8 material-gain gate",
        );
    }

    #[test]
    fn exists_teddy_tail_restores_public_abi_and_targets_incumbent_on_both_architectures() {
        let pattern = scanner_free_exact_finite_pattern();
        for target in [
            avx2_target(),
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
        ] {
            let compiled = compile_exists(&pattern, target);
            let report = compiled
                .module()
                .exact_finite_exists_teddy_aot_report()
                .unwrap();
            let code = compiled.module().sections()[TEXT_SECTION].bytes();
            let incumbent = report.incumbent_code_offset;
            assert!(incumbent > 0 && incumbent < code.len(), "{target:?}");
            match target.architecture {
                Architecture::X86_64 => {
                    let restore = [
                        0x48, 0x89, 0xee, // length <- rbp
                        0x4c, 0x89, 0xf9, // end <- r15
                        0x4d, 0x89, 0xf0, // result <- r14
                        0x5d, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x5b, 0x41, 0x5c,
                        0xc5, 0xf8, 0x77,
                    ];
                    assert!(code[..incumbent]
                        .windows(restore.len())
                        .any(|window| window == restore));
                    assert!(code[..incumbent].windows(5).enumerate().any(
                        |(offset, bytes)| {
                            if bytes[0] != 0xe9 {
                                return false;
                            }
                            let displacement =
                                i32::from_le_bytes(bytes[1..].try_into().unwrap());
                            i64::try_from(offset + 5)
                                .ok()
                                .and_then(|after| after.checked_add(i64::from(displacement)))
                                .and_then(|target| usize::try_from(target).ok())
                                == Some(incumbent)
                        }
                    ));
                }
                Architecture::Aarch64 => {
                    let words = code[..incumbent]
                        .chunks_exact(4)
                        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                        .collect::<Vec<_>>();
                    let restore = [
                        aarch64_mov_x(1, 19).unwrap(),
                        aarch64_load_x_imm(21, 31, 16).unwrap(),
                        aarch64_load_pair_x(19, 20, 31, 0).unwrap(),
                        aarch64_add_x_imm(31, 31, 32).unwrap(),
                    ];
                    assert!(words.windows(restore.len()).any(|window| window == restore));
                    assert!(words.iter().enumerate().any(|(index, &instruction)| {
                        if instruction & 0xfc00_0000 != 0x1400_0000 {
                            return false;
                        }
                        let immediate = (instruction & 0x03ff_ffff) as i32;
                        let signed_words = (immediate << 6) >> 6;
                        i64::try_from(index * 4)
                            .ok()
                            .and_then(|offset| {
                                offset.checked_add(i64::from(signed_words) * 4)
                            })
                            .and_then(|target| usize::try_from(target).ok())
                            == Some(incumbent)
                    }));
                }
            }
        }
    }

    #[test]
    fn tiny_native_data_cap_declines_before_teddy_incumbent_and_restores_full_portfolio() {
        let target = avx2_target();
        let pattern = scanner_free_exact_finite_pattern();
        let uncapped = compile_selected(&pattern, target);
        let ordinary = unchanged_selected_end_module(&uncapped, target);
        let semantic = uncapped
            .program()
            .native_dfa_view()
            .expect("complete SelectedEnd semantic DFA");
        let incumbent = lower_native_dfa(semantic, target)
            .unwrap()
            .expect("uncapped complete-DFA incumbent");
        let tiny_cap = incumbent
            .data
            .len()
            .checked_sub(1)
            .expect("complete-DFA incumbent has native data");
        assert!(
            lower_exact_finite_teddy_incumbent_with_data_limit(semantic, target, tiny_cap)
                .unwrap()
                .is_none(),
            "an over-cap DFA must not become the speculative Teddy incumbent",
        );
        let limits = crate::SlowAotLimits {
            max_native_data_bytes: tiny_cap,
            ..crate::SlowAotLimits::default()
        };
        let automatic = crate::compile_v2_with_slow_aot_limits(
            crate::CompileRequestV2::new(
                CompileRequest::new(&pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            ),
            limits,
        )
        .expect("tiny-cap Automatic must preserve the established portfolio");
        let disabled = crate::compile_v2_with_slow_aot_limits(
            crate::CompileRequestV2::new(
                CompileRequest::new(&pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            )
            .exact_finite_selected_end_teddy(crate::ExactFiniteSelectedEndTeddyPolicyV2::Disabled),
            limits,
        )
        .expect("tiny-cap Disabled must preserve the established portfolio");
        assert_byte_identical_module(automatic.module(), disabled.module());
        assert_eq!(automatic.object(), disabled.object());
        assert_eq!(automatic.receipt(), disabled.receipt());
        assert_ne!(
            automatic.module(),
            &ordinary,
            "an authenticated cap miss must not retry the ordinary DFA unbounded",
        );
        let finite_report = automatic
            .receipt()
            .ordered_finite_language_aot
            .expect("an unavailable over-cap DFA must release finite/AC rescue");
        assert!(finite_report.native_data_bytes <= tiny_cap);
        assert!(
            automatic
                .receipt_v2()
                .exact_finite_selected_end_teddy_aot
                .is_none(),
        );
    }

    #[test]
    fn v2_force_wraps_the_actual_accelerated_incumbent_on_every_target_tier() {
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
        for target in targets {
            let forced = force_v2(accelerated_exact_finite_pattern(), target);
            let ordinary = crate::compile_v2(
                crate::CompileRequestV2::new(
                    CompileRequest::new(accelerated_exact_finite_pattern(), target)
                        .mode(CompileMode::Optimizing)
                        .output(OutputContract::SelectedEnd),
                )
                .exact_finite_selected_end_teddy(
                    crate::ExactFiniteSelectedEndTeddyPolicyV2::Disabled,
                ),
            )
            .expect("compile the ordinary accelerated incumbent");
            assert!(
                forced
                    .receipt()
                    .exact_finite_selected_end_teddy_aot
                    .is_none(),
                "forced evidence must not enter V1: {target:?}",
            );
            let report = forced
                .receipt_v2()
                .exact_finite_selected_end_teddy_aot
                .unwrap_or_else(|| panic!("forced target did not select: {target:?}"));
            assert_eq!(
                report.selection_basis,
                ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility,
            );
            assert!(report.performance_admission_bypassed);
            assert_eq!(
                report.lowering.batch_vectors,
                if report.lowering.emitted_isa
                    == ExactFiniteSelectedEndTeddyAotIsa::Aarch64Sve
                {
                    EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS
                } else {
                    EXACT_FINITE_TEDDY_UNBATCHED_VECTORS
                },
                "forced authenticated batch width: {target:?}",
            );
            assert!(report.tail_enters_exact_incumbent);
            assert!(report.lowering.incumbent_complete_dfa.has_accelerator);
            assert_ne!(report.incumbent_start_accelerator, StartAccelerator::None,);
            assert_eq!(
                report.incumbent_start_accelerator,
                report.lowering.incumbent_complete_dfa.scanner,
            );
            assert_eq!(
                report.incumbent_start_accelerator,
                ordinary.module().start_accelerator(),
            );
            assert_eq!(
                report.incumbent_anchored_prefix_filter_bytes,
                ordinary.module().anchored_prefix_filter_bytes(),
            );
            let ordinary_code_sha256: [u8; 32] =
                Sha256::digest(ordinary.module().sections()[TEXT_SECTION].bytes()).into();
            let ordinary_data_sha256: [u8; 32] =
                Sha256::digest(ordinary.module().sections()[PROGRAM_SECTION].bytes()).into();
            assert_eq!(
                report.lowering.incumbent_code_sha256,
                ordinary_code_sha256,
            );
            assert_eq!(
                report.lowering.incumbent_data_sha256,
                ordinary_data_sha256,
            );
            assert_eq!(
                Some(report.lowering.incumbent_relocations_sha256),
                relocation_digest(ordinary.module().relocations()),
            );
            assert_eq!(
                forced
                    .module()
                    .exact_finite_selected_end_teddy_aot_report_v2(),
                Some(&report),
            );
        }
    }

    #[test]
    fn v2_route_binding_rejects_policy_and_incumbent_fact_tampering() {
        let authentic = force_v2(accelerated_exact_finite_pattern(), avx2_target())
            .receipt_v2()
            .exact_finite_selected_end_teddy_aot
            .expect("forced V2 selection");
        assert!(report_v2_metadata_authenticates(&authentic));

        let mut tampered = authentic;
        tampered.requested_policy = crate::ExactFiniteSelectedEndTeddyPolicyV2::Automatic;
        assert!(!report_v2_metadata_authenticates(&tampered));

        let mut tampered = authentic;
        tampered.incumbent_start_accelerator = StartAccelerator::None;
        assert!(!report_v2_metadata_authenticates(&tampered));

        let mut tampered = authentic;
        tampered.incumbent_anchored_prefix_filter_bytes ^= 1;
        assert!(!report_v2_metadata_authenticates(&tampered));

        let mut tampered = authentic;
        tampered.route_binding_sha256[0] ^= 1;
        assert!(!report_v2_metadata_authenticates(&tampered));
    }

    #[test]
    fn v2_force_data_cap_decline_restores_the_accelerated_incumbent_exactly() {
        let target = avx2_target();
        let pattern = accelerated_exact_finite_pattern();
        let forced = force_v2(pattern, target);
        let report = forced
            .receipt_v2()
            .exact_finite_selected_end_teddy_aot
            .expect("uncapped forced selection");
        let disabled = crate::compile_v2(
            crate::CompileRequestV2::new(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            )
            .exact_finite_selected_end_teddy(crate::ExactFiniteSelectedEndTeddyPolicyV2::Disabled),
        )
        .unwrap();
        let capped = crate::compile_v2_with_slow_aot_limits(
            crate::CompileRequestV2::new(
                CompileRequest::new(pattern, target)
                    .mode(CompileMode::Optimizing)
                    .output(OutputContract::SelectedEnd),
            )
            .exact_finite_selected_end_teddy(
                crate::ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible,
            ),
            crate::SlowAotLimits {
                max_native_data_bytes: report.lowering.native_data_bytes - 1,
                ..crate::SlowAotLimits::default()
            },
        )
        .unwrap();
        assert_eq!(capped.module(), disabled.module());
        assert_eq!(capped.object(), disabled.object());
        assert_eq!(capped.receipt(), disabled.receipt());
        assert!(
            capped
                .receipt_v2()
                .exact_finite_selected_end_teddy_aot
                .is_none(),
        );
    }

    #[test]
    fn v2_force_object_cap_restores_the_accelerated_incumbent_exactly() {
        let target = avx2_target();
        let pattern = accelerated_exact_finite_pattern();
        let request = |max_object_bytes| {
            CompileRequest::new(pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd)
                .limits(crate::CompileLimitsV1 {
                    max_object_bytes,
                    ..crate::CompileLimitsV1::default()
                })
        };
        let ordinary = crate::compile_v2(
            crate::CompileRequestV2::new(request(usize::MAX))
                .exact_finite_selected_end_teddy(
                    crate::ExactFiniteSelectedEndTeddyPolicyV2::Disabled,
                ),
        )
        .expect("compile the ordinary accelerated incumbent");
        let forced = crate::compile_v2(
            crate::CompileRequestV2::new(request(usize::MAX)).exact_finite_selected_end_teddy(
                crate::ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible,
            ),
        )
        .expect("compile the forced wrapper");
        assert!(ordinary.object().len() < forced.object().len());

        let capped = crate::compile_v2(
            crate::CompileRequestV2::new(request(ordinary.object().len()))
                .exact_finite_selected_end_teddy(
                    crate::ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible,
                ),
        )
        .expect("the exact ordinary object boundary must fit");
        assert_eq!(capped.module(), ordinary.module());
        assert_eq!(capped.object(), ordinary.object());
        assert_eq!(capped.receipt(), ordinary.receipt());
        assert!(
            capped
                .receipt_v2()
                .exact_finite_selected_end_teddy_aot
                .is_none(),
        );
    }

    #[test]
    fn sve_batch_and_single_prefix_code_growth_respect_the_exact_ordinary_object_cap() {
        let sparse_pattern = sparse_single_prefix_pattern();
        for features in [
            FeatureSet::of(CpuFeature::Aarch64Sve),
            FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2),
        ] {
            let target = Target::aarch64_linux().with_features(features).unwrap();
            for pattern in [accelerated_exact_finite_pattern(), sparse_pattern.as_str()] {
                let request = |max_object_bytes| {
                    CompileRequest::new(pattern, target)
                        .mode(CompileMode::Optimizing)
                        .output(OutputContract::SelectedEnd)
                        .limits(crate::CompileLimitsV1 {
                            max_object_bytes,
                            ..crate::CompileLimitsV1::default()
                        })
                };
                let ordinary = crate::compile_v2(
                    crate::CompileRequestV2::new(request(usize::MAX))
                        .exact_finite_selected_end_teddy(
                            crate::ExactFiniteSelectedEndTeddyPolicyV2::Disabled,
                        ),
                )
                .expect("compile the exact ordinary SVE incumbent");
                let forced = crate::compile_v2(
                    crate::CompileRequestV2::new(request(usize::MAX))
                        .exact_finite_selected_end_teddy(
                            crate::ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible,
                        ),
                )
                .expect("compile the four-vector SVE wrapper");
                let report = forced
                    .receipt_v2()
                    .exact_finite_selected_end_teddy_aot
                    .expect("forced SVE wrapper receipt");
                assert_eq!(
                    report.lowering.batch_vectors,
                    EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS,
                );
                assert!(report.lowering.incumbent_code_offset > 0);
                assert!(ordinary.object().len() < forced.object().len());

                let capped = crate::compile_v2(
                    crate::CompileRequestV2::new(request(ordinary.object().len()))
                        .exact_finite_selected_end_teddy(
                            crate::ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible,
                        ),
                )
                .expect("the exact ordinary SVE object boundary must fit");
                assert_eq!(capped.module(), ordinary.module());
                assert_eq!(capped.object(), ordinary.object());
                assert_eq!(capped.receipt(), ordinary.receipt());
                assert!(
                    capped
                        .receipt_v2()
                        .exact_finite_selected_end_teddy_aot
                        .is_none(),
                );
            }
        }
    }

    #[test]
    fn v2_force_never_bypasses_structural_or_output_gates() {
        let target = avx2_target();
        for (pattern, output) in [
            ("alpha|bravo|cider", OutputContract::SelectedEnd),
            ("aa|bb|cc|dd", OutputContract::SelectedEnd),
            (accelerated_exact_finite_pattern(), OutputContract::Exists),
            (accelerated_exact_finite_pattern(), OutputContract::Span),
        ] {
            let compiled = crate::compile_v2(
                crate::CompileRequestV2::new(
                    CompileRequest::new(pattern, target)
                        .mode(CompileMode::Optimizing)
                        .output(output),
                )
                .exact_finite_selected_end_teddy(
                    crate::ExactFiniteSelectedEndTeddyPolicyV2::ForceStructurallyEligible,
                ),
            )
            .unwrap();
            assert!(
                compiled
                    .receipt_v2()
                    .exact_finite_selected_end_teddy_aot
                    .is_none(),
                "force bypassed a correctness gate for {pattern:?}/{output:?}",
            );
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
    fn sve_lazy_pair_is_selective_deterministic_and_exact_at_both_depths() {
        // The first two chronological columns are deliberately common while
        // the final two are rare and distinct. With one literal per bucket,
        // the stable frequency oracle must therefore stage columns 1/2 for a
        // three-column plan and 2/3 for a four-column plan.
        let literals = (0_u8..8)
            .map(|ordinal| vec![b' ', b'\n', ordinal, ordinal.wrapping_add(16)])
            .collect::<Vec<_>>();
        let portfolio = mandatory_teddy::derive_exact_prefixes(&literals, 4)
            .expect("three/four-column slim Teddy plans");
        let mut observed_depths = [false; 5];
        for plan in portfolio
            .plans()
            .copied()
            .filter(|plan| plan.bank_count() == 1)
        {
            let columns = usize::from(plan.columns());
            let batch_plan = aarch64_mandatory_teddy_sve_batch_plan(&plan).unwrap();
            let order = batch_plan.column_order;
            let expected: &[u8] = match columns {
                3 => &[2, 1, 0],
                4 => &[2, 3, 0, 1],
                _ => panic!("unexpected slim Teddy depth {columns}"),
            };
            assert_eq!(&order[..columns], expected);
            assert_eq!(
                aarch64_mandatory_teddy_sve_column_union_frequency(
                    &plan,
                    usize::from(order[0]),
                )
                .unwrap(),
                8,
            );
            assert_eq!(batch_plan.single_prefix_max_vector_bytes, None);
            observed_depths[columns] = true;

            let bank = plan.bank(0).unwrap();
            let buckets_at = |column: usize, byte: u8| {
                bank.low(column).unwrap()[usize::from(byte & 0x0f)]
                    & bank.high(column).unwrap()[usize::from(byte >> 4)]
            };
            for first in u8::MIN..=u8::MAX {
                for second in u8::MIN..=u8::MAX {
                    let mut window = [0_u8; 4];
                    window[usize::from(order[0])] = first;
                    window[usize::from(order[1])] = second;
                    let prefix = buckets_at(usize::from(order[0]), first)
                        & buckets_at(usize::from(order[1]), second);
                    if buckets_at(usize::from(order[0]), first) == 0 {
                        assert_eq!(
                            prefix, 0,
                            "a singleton miss cannot survive the selected pair",
                        );
                    }
                    let mut reordered = prefix;
                    for (salt, &column) in order[2..columns].iter().enumerate() {
                        let byte = first
                            .wrapping_mul(u8::try_from(salt).unwrap().wrapping_add(3))
                            .wrapping_add(second)
                            .wrapping_add(u8::try_from(salt).unwrap());
                        window[usize::from(column)] = byte;
                        reordered &= buckets_at(usize::from(column), byte);
                    }
                    assert_eq!(
                        u16::from(reordered),
                        plan.candidate_buckets(&window[..columns]),
                        "reordered intersection changed a {columns}-column bucket result",
                    );
                    if prefix == 0 {
                        assert_eq!(reordered, 0, "a prefix miss cannot become a full hit");
                    }
                }
            }
        }
        assert!(observed_depths[3] && observed_depths[4]);

        let symmetric = (0_u8..8)
            .map(|ordinal| vec![ordinal; 4])
            .collect::<Vec<_>>();
        let symmetric_plan = mandatory_teddy::derive_exact_prefixes(&symmetric, 4)
            .unwrap()
            .plans()
            .copied()
            .find(|plan| plan.columns() == 4 && plan.bank_count() == 1)
            .unwrap();
        assert_eq!(
            aarch64_mandatory_teddy_sve_batch_plan(&symmetric_plan)
                .unwrap()
                .column_order,
            [0, 1, 2, 3],
            "equal pair scores must use the lexicographically first pair",
        );

        let sparse_plan = |distinct_first_bytes: u8| {
            let literals = (0_u8..8)
                .map(|ordinal| {
                    vec![
                        ordinal.wrapping_add(16),
                        ordinal % distinct_first_bytes,
                        ordinal.wrapping_add(64),
                        ordinal.wrapping_add(96),
                    ]
                })
                .collect::<Vec<_>>();
            mandatory_teddy::derive_exact_prefixes(&literals, 4)
                .unwrap()
                .plans()
                .copied()
                .find(|plan| plan.columns() == 4 && plan.bank_count() == 1)
                .unwrap()
        };
        for (distinct, frequency, maximum_vector_bytes) in [
            (1_u8, 1_u16, Some(64_u16)),
            (2, 2, Some(32)),
            (3, 3, Some(16)),
            (4, 4, Some(16)),
            (5, 5, None),
        ] {
            let plan = sparse_plan(distinct);
            let batch_plan = aarch64_mandatory_teddy_sve_batch_plan(&plan).unwrap();
            assert_eq!(batch_plan.column_order, [1, 0, 2, 3]);
            assert_eq!(
                aarch64_mandatory_teddy_sve_column_union_frequency(
                    &plan,
                    usize::from(batch_plan.column_order[0]),
                )
                .unwrap(),
                frequency,
            );
            assert_eq!(
                batch_plan.single_prefix_max_vector_bytes,
                maximum_vector_bytes,
                "expected-hit gate boundary for {distinct} exact bytes",
            );
        }

        let high_weight = (0_u8..8)
            .map(|ordinal| {
                vec![
                    0xc0_u8.wrapping_add(ordinal),
                    b'e',
                    0xc0_u8.wrapping_add((ordinal + 3) % 8),
                    0xc0_u8.wrapping_add((ordinal + 5) % 8),
                ]
            })
            .collect::<Vec<_>>();
        let high_weight_plan = mandatory_teddy::derive_exact_prefixes(&high_weight, 4)
            .unwrap()
            .plans()
            .copied()
            .find(|plan| plan.columns() == 4 && plan.bank_count() == 1)
            .unwrap();
        let high_weight_batch =
            aarch64_mandatory_teddy_sve_batch_plan(&high_weight_plan).unwrap();
        assert_eq!(
            aarch64_mandatory_teddy_sve_column_union_frequency(
                &high_weight_plan,
                usize::from(high_weight_batch.column_order[0]),
            )
            .unwrap(),
            estimated_byte_frequency_units(b'e'),
        );
        assert_eq!(high_weight_batch.single_prefix_max_vector_bytes, None);

        let colliding = (0_u8..9)
            .map(|ordinal| vec![ordinal.wrapping_mul(0x11); 4])
            .collect::<Vec<_>>();
        let colliding_plan = mandatory_teddy::derive_exact_prefixes(&colliding, 4)
            .unwrap()
            .plans()
            .copied()
            .find(|plan| {
                plan.columns() == 4
                    && plan.bank_count() == 1
                    && plan.bucket_count() == 8
            })
            .unwrap();
        let colliding_batch = aarch64_mandatory_teddy_sve_batch_plan(&colliding_plan).unwrap();
        assert_eq!(
            aarch64_mandatory_teddy_sve_column_union_frequency(
                &colliding_plan,
                usize::from(colliding_batch.column_order[0]),
            )
            .unwrap(),
            29,
            "the union model must include actual low/high nibble-table collisions",
        );

        let fat = (0_u8..9)
            .map(|ordinal| vec![ordinal; 4])
            .collect::<Vec<_>>();
        let fat_plan = mandatory_teddy::derive_exact_prefixes(&fat, 4)
            .unwrap()
            .plans()
            .copied()
            .find(|plan| plan.columns() == 4 && plan.bank_count() == 2)
            .unwrap();
        assert!(
            aarch64_mandatory_teddy_sve_batch_plan(&fat_plan).is_err(),
            "a bank-0 score must never order a two-bank plan",
        );
    }

    #[test]
    fn sve_single_prefix_codegen_is_vl_gated_and_returns_to_its_own_loop() {
        let plan_with_distinct_first_bytes = |distinct_first_bytes: u8| {
            let literals = (0_u8..8)
                .map(|ordinal| {
                    vec![
                        ordinal.wrapping_add(16),
                        ordinal % distinct_first_bytes,
                        ordinal.wrapping_add(64),
                        ordinal.wrapping_add(96),
                    ]
                })
                .collect::<Vec<_>>();
            mandatory_teddy::derive_exact_prefixes(&literals, 4)
                .unwrap()
                .plans()
                .copied()
                .find(|plan| plan.columns() == 4 && plan.bank_count() == 1)
                .unwrap()
        };
        let sparse = plan_with_distinct_first_bytes(1);
        let sparse_batch = aarch64_mandatory_teddy_sve_batch_plan(&sparse).unwrap();
        assert_eq!(sparse_batch.column_order, [1, 0, 2, 3]);
        assert_eq!(sparse_batch.single_prefix_max_vector_bytes, Some(64));

        let words_for = |plan: MandatoryTeddyPlan, single_prefix: bool| {
            let mut assembler = Aarch64Assembler::new();
            let vector = assembler.label().unwrap();
            assembler.bind(vector).unwrap();
            let teddy = NativeMandatoryTeddyLayout {
                plan,
                isa: MandatoryTeddyIsa::Aarch64Sve,
                vector_bytes: u8::try_from(AARCH64_SVE_MIN_VECTOR_BYTES).unwrap(),
                table_base: 0,
                nibble_mask_offset: u32::from(plan.columns()) * 32,
                table_end: u32::from(plan.columns()) * 32,
            };
            aarch64_emit_mandatory_teddy_sve_batch4_candidates(
                &mut assembler,
                &teddy,
                vector,
                single_prefix,
            )?;
            Ok::<_, ObjectError>(
                assembler
                    .finish()?
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>(),
            )
        };
        let existence = [
            aarch64_sve_orr_z(4, 24, 25).unwrap(),
            aarch64_sve_orr_z(5, 27, 28).unwrap(),
            aarch64_sve_orr_z(4, 4, 5).unwrap(),
            aarch64_sve_cmpne_zero_b(8, 4).unwrap(),
            aarch64_sve_ptest_p0(8).unwrap(),
        ];
        let ordinary = words_for(sparse, false).unwrap();
        let early = words_for(sparse, true).unwrap();
        assert_eq!(
            early.len(),
            ordinary.len() + 8,
            "the singleton candidate body adds one six-instruction survivor check and a two-instruction miss edge",
        );
        assert_eq!(
            ordinary
                .windows(existence.len())
                .filter(|window| *window == existence)
                .count(),
            1,
            "the ordinary route has only its two-column lazy check",
        );
        assert_eq!(
            early
                .windows(existence.len())
                .filter(|window| *window == existence)
                .count(),
            2,
            "the admitted route adds exactly one singleton check",
        );
        let first_check = early
            .windows(existence.len())
            .position(|window| window == existence)
            .unwrap();
        assert_eq!(
            &early[..first_check],
            sve_batch_column_schedule(sparse_batch.column_order[0], true),
            "the first column must use the direct retained-bucket accumulator",
        );
        for block in 0..EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS {
            assert_eq!(
                early[..first_check]
                    .iter()
                    .filter(|&&word| word == aarch64_sve_ld1b_vl(block, 12, block).unwrap())
                    .count(),
                1,
                "the singleton decision must precede block {block}'s second load",
            );
        }
        let survivor_branch = first_check + existence.len();
        assert_eq!(
            early[survivor_branch] & 0xff00_001f,
            0x5400_0000 | u32::from(AARCH64_NE),
        );
        assert_eq!(
            early[survivor_branch + 1],
            aarch64_sve_addvl(2, 2, EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS).unwrap(),
        );
        assert_eq!(early[survivor_branch + 2] & 0xfc00_0000, 0x1400_0000);
        let survivor_immediate =
            (i32::try_from((early[survivor_branch] >> 5) & 0x7_ffff).unwrap() << 13) >> 13;
        let second_column = isize::try_from(survivor_branch)
            .unwrap()
            .checked_add(isize::try_from(survivor_immediate).unwrap())
            .and_then(|index| usize::try_from(index).ok())
            .unwrap();
        assert_eq!(
            second_column,
            survivor_branch + 3,
            "the survivor edge must target the immediately following second column",
        );
        let second_schedule =
            sve_batch_column_schedule(sparse_batch.column_order[1], false);
        assert_eq!(
            early.get(second_column..second_column + second_schedule.len()),
            Some(second_schedule.as_slice()),
            "the singleton survivor must execute the selected pair's full second column",
        );
        let loop_immediate =
            (i32::try_from(early[survivor_branch + 2] & 0x03ff_ffff).unwrap() << 6) >> 6;
        assert_eq!(
            isize::try_from(survivor_branch + 2)
                .unwrap()
                .checked_add(isize::try_from(loop_immediate).unwrap()),
            Some(0),
            "a singleton miss must return to the same early-check loop",
        );

        let dense = plan_with_distinct_first_bytes(5);
        assert_eq!(
            aarch64_mandatory_teddy_sve_batch_plan(&dense)
                .unwrap()
                .single_prefix_max_vector_bytes,
            None,
        );
        assert!(
            words_for(dense, true).is_err(),
            "a non-material singleton must not be emitted accidentally",
        );
    }

    #[test]
    fn sve_batch_frontier_preserves_every_runtime_vl_boundary() {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Route {
            Exhausted,
            Single,
            Batch,
        }

        let cursor = 0x1_0000_usize;
        for columns in [3_usize, 4] {
            for vector_bytes in (AARCH64_SVE_MIN_VECTOR_BYTES
                ..=AARCH64_SVE_MAX_VECTOR_BYTES)
                .step_by(usize::from(AARCH64_SVE_MIN_VECTOR_BYTES))
            {
                let batch_bytes = usize::from(EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS)
                    .checked_mul(usize::from(vector_bytes))
                    .unwrap();
                for remaining in 0..=batch_bytes + columns + 2 {
                    let end = cursor + remaining;
                    let old = if remaining < columns {
                        Route::Exhausted
                    } else if end - (columns - 1) - cursor < batch_bytes {
                        Route::Single
                    } else {
                        Route::Batch
                    };
                    let candidate_end = end - (columns - 1);
                    let batch_frontier = candidate_end - batch_bytes;
                    let new = if cursor <= batch_frontier {
                        Route::Batch
                    } else if cursor >= candidate_end {
                        Route::Exhausted
                    } else {
                        Route::Single
                    };
                    assert_eq!(
                        new, old,
                        "columns={columns} vector_bytes={vector_bytes} remaining={remaining}",
                    );
                }
            }
        }
    }

    #[test]
    fn sve_single_prefix_wrapper_hoists_runtime_vl_dispatch() {
        let pattern = sparse_single_prefix_pattern();
        let target = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Sve))
            .unwrap();
        let automatic = crate::compile_v2(crate::CompileRequestV2::new(
            CompileRequest::new(&pattern, target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::SelectedEnd),
        ))
        .expect("compile automatic sparse-prefix fixture");
        assert!(
            automatic
                .receipt_v2()
                .exact_finite_selected_end_teddy_aot
                .is_none(),
            "the sparse singleton route must not leak into AutomaticV1",
        );

        let forced = force_v2(&pattern, target);
        let report_v2 = forced
            .receipt_v2()
            .exact_finite_selected_end_teddy_aot
            .expect("forced sparse-prefix fixture must select Teddy");
        assert_eq!(
            report_v2.selection_basis,
            ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility,
        );
        let report = report_v2.lowering;
        assert!((3..=4).contains(&report.columns));
        let maximum_vector_bytes = 16_u16;
        let words = forced.module().sections()[TEXT_SECTION].bytes()
            [..report.incumbent_code_offset]
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        let conditional_target = |index: usize| {
            let immediate =
                (i32::try_from((words[index] >> 5) & 0x7_ffff).unwrap() << 13) >> 13;
            isize::try_from(index)
                .unwrap()
                .checked_add(isize::try_from(immediate).unwrap())
                .and_then(|target| usize::try_from(target).ok())
        };
        let maximum_offset = u16::from(report.columns - 1);
        let retry_setup = [
            aarch64_sve_ptrue_b(),
            aarch64_sve_dup_b_imm(26, 0x0f).unwrap(),
            aarch64_sve_cntb(6).unwrap(),
            aarch64_sub_x_imm(10, 3, maximum_offset).unwrap(),
            aarch64_sve_addvl_signed(
                9,
                10,
                -i8::try_from(EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS).unwrap(),
            )
            .unwrap(),
            aarch64_cmp_x_imm(6, maximum_vector_bytes).unwrap(),
        ];
        let dispatch_matches = words
            .windows(retry_setup.len() + 1)
            .enumerate()
            .filter(|(_, window)| {
                window[..retry_setup.len()] == retry_setup
                    && window[retry_setup.len()] & 0xff00_001f
                        == 0x5400_0000 | u32::from(AARCH64_LS)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        assert_eq!(
            dispatch_matches.len(),
            1,
            "the runtime VL choice must be hoisted out of both batch loops",
        );
        let dispatch = dispatch_matches[0];
        let wide_route = dispatch + retry_setup.len() + 1;
        assert_eq!(
            words[wide_route],
            aarch64_cmp_x(2, 9).unwrap(),
            "the fall-through route must use the retained four-vector frontier",
        );
        assert_eq!(
            words[wide_route + 1] & 0xff00_001f,
            0x5400_0000 | u32::from(AARCH64_HI),
        );
        let immediate =
            (i32::try_from((words[dispatch + retry_setup.len()] >> 5) & 0x7_ffff).unwrap()
                << 13)
                >> 13;
        let sparse_route = isize::try_from(dispatch + retry_setup.len())
            .unwrap()
            .checked_add(isize::try_from(immediate).unwrap())
            .and_then(|index| usize::try_from(index).ok())
            .unwrap();
        assert_eq!(
            words[sparse_route],
            aarch64_cmp_x(2, 9).unwrap(),
            "the taken route must reuse the retained four-vector frontier",
        );
        assert_eq!(
            words[sparse_route + 1] & 0xff00_001f,
            0x5400_0000 | u32::from(AARCH64_HI),
        );
        let single = conditional_target(wide_route + 1).unwrap();
        assert_eq!(conditional_target(sparse_route + 1), Some(single));
        assert_eq!(words[single], aarch64_cmp_x(2, 10).unwrap());
        assert_eq!(
            words[single + 1] & 0xff00_001f,
            0x5400_0000 | u32::from(AARCH64_HS),
        );
        assert!(sparse_route > wide_route);
        let existence = [
            aarch64_sve_orr_z(4, 24, 25).unwrap(),
            aarch64_sve_orr_z(5, 27, 28).unwrap(),
            aarch64_sve_orr_z(4, 4, 5).unwrap(),
            aarch64_sve_cmpne_zero_b(8, 4).unwrap(),
            aarch64_sve_ptest_p0(8).unwrap(),
        ];
        assert_eq!(
            words
                .windows(existence.len())
                .filter(|window| *window == existence)
                .count(),
            5,
            "ordinary pair/final checks plus singleton pair/final checks",
        );
        assert_eq!(
            words[wide_route..sparse_route]
                .windows(existence.len())
                .filter(|window| *window == existence)
                .count(),
            2,
            "the wide route must retain only pair and final existence checks",
        );
        assert_eq!(
            words[sparse_route..]
                .windows(existence.len())
                .filter(|window| *window == existence)
                .count(),
            3,
            "the admitted route must add its singleton check before pair and final checks",
        );
        let unconditional_target = |index: usize| {
            let immediate = (i32::try_from(words[index] & 0x03ff_ffff).unwrap() << 6) >> 6;
            isize::try_from(index)
                .unwrap()
                .checked_add(isize::try_from(immediate).unwrap())
                .and_then(|target| usize::try_from(target).ok())
        };
        for (route, end, expected_checks) in [
            (wide_route, sparse_route, 2_usize),
            (sparse_route, words.len(), 3),
        ] {
            let checks = words[route..end]
                .windows(existence.len())
                .enumerate()
                .filter(|(_, window)| *window == existence)
                .map(|(index, _)| route + index)
                .collect::<Vec<_>>();
            assert_eq!(checks.len(), expected_checks);
            for check in checks {
                let survivor = check + existence.len();
                assert_eq!(
                    words[survivor] & 0xff00_001f,
                    0x5400_0000 | u32::from(AARCH64_NE),
                );
                assert!(
                    conditional_target(survivor).is_some_and(|target| target > survivor + 2),
                    "every survivor edge must skip its complete miss path",
                );
                assert_eq!(
                    words[survivor + 1],
                    aarch64_sve_addvl(2, 2, EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS).unwrap(),
                );
                assert_eq!(
                    unconditional_target(survivor + 2),
                    Some(route),
                    "every singleton/pair/final miss must return to its own loop",
                );
            }
        }
    }

    #[test]
    fn sve_single_prefix_forced_wrapper_covers_three_columns_and_sve2() {
        let pattern = sparse_single_prefix_three_column_pattern();
        let target = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2))
            .unwrap();
        let forced = force_v2(&pattern, target);
        let report = forced
            .receipt_v2()
            .exact_finite_selected_end_teddy_aot
            .expect("forced three-column SVE2 fixture must select Teddy");
        assert_eq!(
            report.selection_basis,
            ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility,
        );
        assert_eq!(report.lowering.columns, 3);
        let words = forced.module().sections()[TEXT_SECTION].bytes()
            [..report.lowering.incumbent_code_offset]
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        let retry_setup = [
            aarch64_sve_ptrue_b(),
            aarch64_sve_dup_b_imm(26, 0x0f).unwrap(),
            aarch64_sve_cntb(6).unwrap(),
            aarch64_sub_x_imm(10, 3, u16::from(report.lowering.columns - 1)).unwrap(),
            aarch64_sve_addvl_signed(
                9,
                10,
                -i8::try_from(EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS).unwrap(),
            )
            .unwrap(),
            aarch64_cmp_x_imm(6, 16).unwrap(),
        ];
        assert_eq!(
            words
                .windows(retry_setup.len() + 1)
                .filter(|window| {
                    window[..retry_setup.len()] == retry_setup
                        && window[retry_setup.len()] & 0xff00_001f
                            == 0x5400_0000 | u32::from(AARCH64_LS)
                })
                .count(),
            1,
            "the forced three-column SVE2 wrapper must retain one hoisted VL dispatch",
        );
        assert_eq!(
            words
                .windows(2)
                .filter(|window| {
                    window[0] == aarch64_cmp_x(2, 9).unwrap()
                        && window[1] & 0xff00_001f
                            == 0x5400_0000 | u32::from(AARCH64_HI)
                })
                .count(),
            2,
            "both SVE2 batch routes must use the shared retained frontier",
        );
        assert_eq!(
            words
                .windows(2)
                .filter(|window| {
                    window[0] == aarch64_cmp_x(2, 10).unwrap()
                        && window[1] & 0xff00_001f
                            == 0x5400_0000 | u32::from(AARCH64_HS)
                })
                .count(),
            1,
            "the common single-vector path must reject the exclusive candidate end",
        );
    }

    #[test]
    fn sve_teddy_tables_use_exact_fixed_ld1rqb_offsets_for_three_and_four_columns() {
        let three_columns = sparse_single_prefix_three_column_pattern();
        let four_columns = fourth_column_disambiguation_pattern();
        for features in [
            FeatureSet::of(CpuFeature::Aarch64Sve),
            FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2),
        ] {
            let target = Target::aarch64_linux().with_features(features).unwrap();
            for (pattern, expected_columns) in
                [(three_columns.as_str(), 3_u8), (four_columns.as_str(), 4)]
            {
                let forced = force_v2(pattern, target);
                let report = forced
                    .receipt_v2()
                    .exact_finite_selected_end_teddy_aot
                    .expect("forced SVE exact Teddy report")
                    .lowering;
                let selection = select_exact_finite_selected_end_teddy_forced_v2(
                    forced
                        .program()
                        .native_finite_selected_end_teddy_view()
                        .unwrap(),
                    target,
                    report.incumbent_complete_dfa,
                )
                .expect("structurally eligible exact Teddy selection");
                assert_eq!(selection.plan.columns(), expected_columns);

                assert_eq!(report.columns, expected_columns);
                let table_base = usize::try_from(report.table_base).unwrap();
                let table_end = usize::try_from(report.table_end).unwrap();
                assert!(table_base.is_multiple_of(16));
                assert_eq!(
                    table_end - table_base,
                    usize::from(expected_columns) * AARCH64_MANDATORY_TEDDY_TABLE_BYTES_PER_COLUMN,
                );
                let data = forced.module().sections()[1].bytes();
                let bank = selection.plan.bank(0).unwrap();
                for column in 0..usize::from(expected_columns) {
                    let low = table_base + column * AARCH64_MANDATORY_TEDDY_TABLE_BYTES_PER_COLUMN;
                    let high = low + 16;
                    assert_eq!(&data[low..high], bank.low(column).unwrap());
                    assert_eq!(&data[high..high + 16], bank.high(column).unwrap());
                }

                let table_count = expected_columns * 2;
                let loads = (0..table_count)
                    .map(|table| {
                        aarch64_sve_ld1rqb_imm(16 + table, 12, i16::from(table) * 16).unwrap()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    table_base + usize::from(table_count - 1) * 16 + 16,
                    table_end,
                );
                let words = forced.module().sections()[TEXT_SECTION].bytes()
                    [..report.incumbent_code_offset]
                    .chunks_exact(4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                    .collect::<Vec<_>>();
                assert_eq!(
                    words
                        .windows(loads.len())
                        .filter(|window| *window == loads)
                        .count(),
                    1,
                    "one contiguous fixed-offset constant schedule: {target:?}/{expected_columns}",
                );
                assert_eq!(
                    words
                        .iter()
                        .filter(|&&word| word & 0xfff0_fc00 == 0xa400_2000)
                        .count(),
                    usize::from(table_count),
                    "only the authenticated table loads use LD1RQB: {target:?}/{expected_columns}",
                );
                assert!(
                    !words.contains(&aarch64_add_x_imm(12, 12, 16).unwrap()),
                    "fixed-offset loads must retire the serial table-base update: {target:?}/{expected_columns}",
                );
            }
        }
    }

    #[test]
    fn sve_inclusive_prefix_extracts_the_exact_first_and_retried_bucket() {
        for vector_length in (16_usize..=256).step_by(16) {
            let buckets = (0..vector_length)
                .map(|lane| 1_u8 << (lane % 8))
                .collect::<Vec<_>>();
            for active_lanes in 1..=vector_length {
                for first in 0..active_lanes {
                    let last = active_lanes - 1;
                    let mut candidates = vec![false; vector_length];
                    candidates[first] = true;
                    candidates[last] = true;

                    let extract = |candidates: &[bool]| {
                        let selected = candidates[..active_lanes]
                            .iter()
                            .position(|&candidate| candidate)
                            .expect("retained candidate");
                        // BRKA includes every active lane through `selected`,
                        // so LASTB reads that lane's bucket. Independently,
                        // BRKB leaves the lanes before `selected`, allowing
                        // INCP to advance the retained base by its lane count.
                        let block_base = 37_usize;
                        let candidate = block_base + selected;
                        let inclusive_last = (0..active_lanes)
                            .take_while(|&lane| block_base + lane < candidate + 1)
                            .last()
                            .expect("inclusive candidate prefix");
                        (selected, buckets[inclusive_last])
                    };

                    assert_eq!(extract(&candidates), (first, buckets[first]));
                    if first != last {
                        candidates[first] = false;
                        assert_eq!(extract(&candidates), (last, buckets[last]));
                    }
                }
            }
        }
    }

    #[test]
    fn sve_retained_mask_exhaustion_restores_predicate_nibble_mask_and_vl() {
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
            let consume = [
                aarch64_add_x_imm(12, 2, 1).unwrap(),
                aarch64_sve_whilelo_b(EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH, 21, 12).unwrap(),
                aarch64_sve_not_b(
                    EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH,
                    EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH,
                )
                .unwrap(),
                aarch64_sve_and_b(1, 1, EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH).unwrap(),
                aarch64_sve_ptest_p0(1).unwrap(),
            ];
            assert!(
                words.windows(consume.len()).any(|window| window == consume),
                "SVE retry must consume retained P1 lanes under active P0: {target:?}",
            );
            let full_block_advance = [
                aarch64_sve_cntp_b(12, 0, 0).unwrap(),
                aarch64_sve_cntb(10).unwrap(),
                aarch64_cmp_x(12, 10).unwrap(),
            ];
            assert!(
                words.windows(full_block_advance.len() + 2).any(|window| {
                    window[..full_block_advance.len()] == full_block_advance
                        && window[full_block_advance.len()] & 0xff00_001f
                            == 0x5400_0000 | u32::from(AARCH64_LO)
                        && window[full_block_advance.len() + 1]
                            == aarch64_sve_addvl(2, 21, 1).unwrap()
                }),
                "SVE retained exhaustion must distinguish partial P0 before ADDVL: {target:?}",
            );
            let retry_advance = aarch64_sve_addvl(2, 21, 1).unwrap();
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
                "constant load and exhausted-block retry must each establish P0",
            );
            let first_retained = [
                aarch64_mov_x(2, 21).unwrap(),
                aarch64_sve_brka_p0(EXACT_FINITE_TEDDY_SVE_BUCKET_SCRATCH, 1).unwrap(),
                aarch64_sve_brkb_p0(EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH, 1).unwrap(),
                aarch64_sve_lastb_w(10, EXACT_FINITE_TEDDY_SVE_BUCKET_SCRATCH, 6).unwrap(),
                aarch64_sve_incp_b(2, EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH).unwrap(),
            ];
            assert_eq!(
                aarch64_sve_brka_p0(5, 1).unwrap(),
                0x2510_4025,
                "BRKA P5.B, P0/Z, P1.B architectural encoding",
            );
            assert!(
                words
                    .windows(first_retained.len())
                    .any(|window| window == first_retained),
                "retained P1 hits must restore the block base before the first-lane helper",
            );
        }
    }

    #[test]
    fn sve_four_vector_batch_has_ordered_retained_blocks_and_safe_exhaustion() {
        for features in [
            FeatureSet::of(CpuFeature::Aarch64Sve),
            FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2),
        ] {
            let target = Target::aarch64_linux().with_features(features).unwrap();
            let compiled = compile_selected(&scanner_free_exact_finite_pattern(), target);
            let report = compiled
                .receipt()
                .exact_finite_selected_end_teddy_aot
                .unwrap();
            assert_eq!(
                report.batch_vectors,
                EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS,
            );
            let wrapper = &compiled.module().sections()[TEXT_SECTION].bytes()
                [..report.incumbent_code_offset];
            let words = wrapper
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();

            let frontier = [
                aarch64_sve_ptrue_b(),
                aarch64_sve_dup_b_imm(26, 0x0f).unwrap(),
                aarch64_sve_cntb(6).unwrap(),
                aarch64_sub_x_imm(10, 3, u16::from(report.columns - 1)).unwrap(),
                aarch64_sve_addvl_signed(
                    9,
                    10,
                    -i8::try_from(EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS).unwrap(),
                )
                .unwrap(),
                aarch64_cmp_x(2, 9).unwrap(),
            ];
            assert_eq!(
                words
                    .windows(frontier.len() + 1)
                    .filter(|window| {
                        window[..frontier.len()] == frontier
                            && window[frontier.len()] & 0xff00_001f
                                == 0x5400_0000 | u32::from(AARCH64_HI)
                    })
                    .count(),
                1,
                "retry setup and the dense batch loop must share one exact frontier: {target:?}",
            );
            assert_eq!(
                words
                    .windows(2)
                    .filter(|window| {
                        window[0] == aarch64_cmp_x(2, 10).unwrap()
                            && window[1] & 0xff00_001f
                                == 0x5400_0000 | u32::from(AARCH64_HS)
                    })
                    .count(),
                1,
                "the common single-vector path must reject the exclusive candidate end: {target:?}",
            );
            assert!(
                !words.contains(&aarch64_cmp_x_lsl(12, 6, 2).unwrap()),
                "the old per-batch shifted runtime bound must be absent: {target:?}",
            );
            let (_, baseline) = complete_dfa_baseline(&compiled, target);
            let selection = select_exact_finite_selected_end_teddy(
                compiled
                    .program()
                    .native_finite_selected_end_teddy_view()
                    .unwrap(),
                target,
                baseline,
            )
            .expect("selected SVE Teddy plan");
            assert_eq!(selection.plan.columns(), report.columns);
            let batch_plan = aarch64_mandatory_teddy_sve_batch_plan(&selection.plan).unwrap();
            assert_eq!(
                batch_plan.single_prefix_max_vector_bytes, None,
                "the established dense fixture must retain one batch route",
            );
            let order = batch_plan.column_order;
            let predicates = AARCH64_MANDATORY_TEDDY_SVE_BATCH_BUCKET_REGISTERS
                .iter()
                .enumerate()
                .map(|(block, &buckets)| {
                    aarch64_sve_cmpne_zero_b(u8::try_from(block).unwrap() + 1, buckets)
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let existence = [
                aarch64_sve_orr_z(4, 24, 25).unwrap(),
                aarch64_sve_orr_z(5, 27, 28).unwrap(),
                aarch64_sve_orr_z(4, 4, 5).unwrap(),
                aarch64_sve_cmpne_zero_b(8, 4).unwrap(),
                aarch64_sve_ptest_p0(8).unwrap(),
            ];

            let mut prefix = sve_batch_column_schedule(order[0], true);
            prefix.extend(sve_batch_column_schedule(order[1], false));
            prefix.extend_from_slice(&existence);
            let prefix_at = words
                .windows(prefix.len())
                .position(|window| window == prefix)
                .expect("selective two-column SVE batch prefix");
            let prefix_branch = prefix_at + prefix.len();
            assert_eq!(
                words[prefix_branch] & 0xff00_001f,
                0x5400_0000 | u32::from(AARCH64_NE),
                "only a surviving two-column prefix may enter the lazy suffix",
            );
            assert_eq!(
                words[prefix_branch + 1],
                aarch64_sve_addvl(2, 2, EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS).unwrap(),
                "an empty prefix must fall through to the four-VL advance",
            );
            assert_eq!(
                words[prefix_branch + 2] & 0xfc00_0000,
                0x1400_0000,
                "the prefix-miss advance must immediately return to the vector loop",
            );

            let suffix_at = prefix_branch + 3;
            let prefix_immediate =
                (i32::try_from((words[prefix_branch] >> 5) & 0x7_ffff).unwrap() << 13) >> 13;
            assert_eq!(
                isize::try_from(prefix_branch)
                    .unwrap()
                    .checked_add(isize::try_from(prefix_immediate).unwrap())
                    .unwrap(),
                isize::try_from(suffix_at).unwrap(),
                "the prefix-hit branch must target the first lazy suffix instruction",
            );
            let mut suffix = Vec::new();
            for (index, &column) in order[2..usize::from(report.columns)].iter().enumerate() {
                suffix.extend(sve_batch_column_schedule(column, false));
                assert!(index < 2, "at most two lazy columns");
            }
            suffix.extend_from_slice(&existence);
            assert_eq!(
                words.get(suffix_at..suffix_at + suffix.len()),
                Some(suffix.as_slice()),
                "prefix hits must finish the exact column-outer schedule: {target:?}",
            );
            for block in 0..EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS {
                let load = aarch64_sve_ld1b_vl(block, 12, block).unwrap();
                assert!(
                    words.iter().filter(|&&word| word == load).count()
                        >= usize::from(report.columns),
                    "every column must load batch block {block}: {target:?}",
                );
                let buckets = AARCH64_MANDATORY_TEDDY_SVE_BATCH_BUCKET_REGISTERS
                    [usize::from(block)];
                assert!(
                    words
                        .iter()
                        .filter(|&&word| {
                            word == aarch64_sve_cmpne_zero_b(block + 1, buckets).unwrap()
                        })
                        .count()
                        >= 1,
                    "a hit must publish retained P{} exactly from its bucket vector: {target:?}",
                    block + 1,
                );
            }

            let reduction_at = suffix_at + suffix.len();
            assert_eq!(
                words[reduction_at] & 0xff00_001f,
                0x5400_0000 | u32::from(AARCH64_NE),
            );
            assert_eq!(
                words[reduction_at + 1],
                aarch64_sve_addvl(2, 2, EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS).unwrap(),
                "a complete full-miss batch advances by exactly four VLs",
            );
            assert_eq!(
                words.get(reduction_at + 3..reduction_at + 3 + predicates.len()),
                Some(predicates.as_slice()),
                "durable predicates must be materialized only on the hit edge",
            );

            let mut probe_at = reduction_at + 3 + predicates.len();
            for predicate in 1..=EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS {
                let relative = words[probe_at..]
                    .iter()
                    .position(|&word| word == aarch64_sve_ptest_p0(predicate).unwrap())
                    .unwrap_or_else(|| panic!("ordered probe P{predicate}: {target:?}"));
                probe_at += relative;
                assert_eq!(
                    words[probe_at + 1] & 0xff00_001f,
                    0x5400_0000 | u32::from(AARCH64_NE),
                    "ordered probe P{predicate} must branch to its block",
                );
                probe_at += 2;
            }

            for block in 0..EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS {
                let predicate = block + 1;
                let mut hit = Vec::new();
                hit.push(if block == 0 {
                    aarch64_mov_x(21, 2).unwrap()
                } else {
                    aarch64_sve_addvl(21, 2, block).unwrap()
                });
                hit.push(aarch64_movz_w(7, u16::from(block + 1)).unwrap());
                if predicate != 1 {
                    hit.push(aarch64_sve_orr_b(1, predicate, predicate).unwrap());
                }
                let buckets = AARCH64_MANDATORY_TEDDY_SVE_BATCH_BUCKET_REGISTERS
                    [usize::from(block)];
                hit.extend([
                    aarch64_sve_and_z(6, buckets, buckets).unwrap(),
                    aarch64_mov_x(2, 21).unwrap(),
                    aarch64_sve_brka_p0(EXACT_FINITE_TEDDY_SVE_BUCKET_SCRATCH, 1).unwrap(),
                    aarch64_sve_brkb_p0(EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH, 1).unwrap(),
                    aarch64_sve_lastb_w(10, EXACT_FINITE_TEDDY_SVE_BUCKET_SCRATCH, 6).unwrap(),
                    aarch64_sve_incp_b(2, EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH).unwrap(),
                ]);
                assert!(
                    words.windows(hit.len()).any(|window| window == hit),
                    "batch block {block} must preserve its base, mask, and next-block state: {target:?}",
                );
            }

            for (next_state, predicate) in [(2_u16, 2_u8), (3, 3), (4, 4)] {
                let exhaustion = [
                    aarch64_sve_addvl(21, 21, 1).unwrap(),
                    aarch64_movz_w(7, next_state).unwrap(),
                    aarch64_sve_ptest_p0(predicate).unwrap(),
                ];
                assert!(
                    words
                        .windows(exhaustion.len() + 1)
                        .any(|window| window[..exhaustion.len()] == exhaustion
                            && window[exhaustion.len()] & 0xff00_001f
                                == 0x5400_0000 | u32::from(AARCH64_NE)),
                    "chosen-block exhaustion must test retained P{predicate}: {target:?}",
                );
            }
        }
    }

    #[test]
    fn retained_candidate_masks_have_backend_specific_static_shapes_on_every_tier() {
        for target in [
            avx2_target(),
            Target::x86_64_linux()
                .with_features(
                    FeatureSet::of(CpuFeature::X86Avx2)
                        .with(CpuFeature::X86Avx512F)
                        .with(CpuFeature::X86Avx512Bw),
                )
                .unwrap(),
        ] {
            let compiled = compile_selected(&scanner_free_exact_finite_pattern(), target);
            let code = compiled.module().sections()[TEXT_SECTION].bytes();
            for (name, sequence) in [
                (
                    "retain and select vector candidate",
                    &[
                        0x49, 0x89, 0xd4, // r12 = vector block base
                        0x41, 0x89, 0xc5, // r13d = candidate lanes
                        0x49, 0x0f, 0xbc, 0xc5, // bsf r13, rax
                        0x49, 0x8d, 0x14, 0x04, // rdx = r12 + rax
                    ][..],
                ),
                (
                    "clear retained candidate",
                    &[
                        0x49, 0x8d, 0x45, 0xff, // rax = r13 - 1
                        0x49, 0x21, 0xc5, // r13 &= rax
                        0x4d, 0x85, 0xed, // test retained mask
                    ],
                ),
                (
                    "advance exhausted vector block",
                    &[0x49, 0x8d, 0x54, 0x24, 32], // rdx = r12 + 32
                ),
                (
                    "scalar synthetic retained lane",
                    &[
                        0x4c, 0x8d, 0x62, 0xe1, // r12 = rdx - 31
                        0x41, 0xbd, 0, 0, 0, 0x80, // r13d = 1 << 31
                    ],
                ),
            ] {
                assert!(
                    code.windows(sequence.len()).any(|window| window == sequence),
                    "{name}: {target:?}",
                );
            }
        }

        let asimd = compile_selected(
            &scanner_free_exact_finite_pattern(),
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
        );
        let words = asimd.module().sections()[TEXT_SECTION]
            .bytes()
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        let retain = [
            aarch64_mov_x(21, 2).unwrap(),
            aarch64_orr_16b(28, 24, 24).unwrap(),
            aarch64_bsl_16b(28, 29, 31).unwrap(),
            aarch64_uminv_16b(28, 28).unwrap(),
            aarch64_umov_b0(12, 28).unwrap(),
            aarch64_add_x_reg(2, 21, 12).unwrap(),
        ];
        assert!(words.windows(retain.len()).any(|window| window == retain));
        let consume = [
            aarch64_add_x_imm(12, 2, 1).unwrap(),
            aarch64_sub_x_reg(12, 12, 21).unwrap(),
            aarch64_dup_16b_from_w(28, 12).unwrap(),
            aarch64_cmhs_16b(28, 29, 28).unwrap(),
            aarch64_and_16b(28, 28, 24).unwrap(),
        ];
        assert!(words.windows(consume.len()).any(|window| window == consume));
        let scalar = [
            aarch64_sub_x_imm(21, 2, 15).unwrap(),
            aarch64_cmeq_16b(24, 29, 26).unwrap(),
        ];
        assert!(words.windows(scalar.len()).any(|window| window == scalar));
        assert!(words.contains(&aarch64_add_x_imm(2, 21, 16).unwrap()));

        for features in [
            FeatureSet::of(CpuFeature::Aarch64Sve),
            FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2),
        ] {
            let target = Target::aarch64_linux().with_features(features).unwrap();
            let compiled = compile_selected(&scanner_free_exact_finite_pattern(), target);
            let words = compiled.module().sections()[TEXT_SECTION]
                .bytes()
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            let consume = [
                aarch64_add_x_imm(12, 2, 1).unwrap(),
                aarch64_sve_whilelo_b(EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH, 21, 12).unwrap(),
                aarch64_sve_not_b(
                    EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH,
                    EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH,
                )
                .unwrap(),
                aarch64_sve_and_b(1, 1, EXACT_FINITE_TEDDY_SVE_LANE_SCRATCH).unwrap(),
                aarch64_sve_ptest_p0(1).unwrap(),
            ];
            assert!(
                words.windows(consume.len()).any(|window| window == consume),
                "consume active retained predicate: {target:?}",
            );
            assert!(words.contains(&aarch64_mov_x(21, 2).unwrap()));
            assert!(words.contains(&aarch64_sve_addvl(2, 21, 1).unwrap()));
        }
    }

    #[test]
    fn aarch64_exact_q_load_encoders_match_oracles_and_reject_invalid_inputs() {
        assert_eq!(
            aarch64_exact_load_q_post_imm(0, 13, 16).unwrap(),
            0x3cc1_05a0,
        );
        assert_eq!(
            aarch64_exact_load_q_post_imm(1, 14, 16).unwrap(),
            0x3cc1_05c1,
        );
        assert!(aarch64_exact_load_q_post_imm(0, 0, -256).is_ok());
        assert!(aarch64_exact_load_q_post_imm(31, 31, 255).is_ok());
        assert!(aarch64_exact_load_q_post_imm(0, 0, -257).is_err());
        assert!(aarch64_exact_load_q_post_imm(0, 0, 256).is_err());
        assert!(aarch64_exact_load_q_post_imm(32, 0, 16).is_err());
        assert!(aarch64_exact_load_q_post_imm(0, 32, 16).is_err());

        assert_eq!(
            aarch64_exact_load_q_unscaled_imm(0, 13, -16).unwrap(),
            0x3cdf_01a0,
        );
        assert_eq!(
            aarch64_exact_load_q_unscaled_imm(1, 14, -16).unwrap(),
            0x3cdf_01c1,
        );
        assert!(aarch64_exact_load_q_unscaled_imm(0, 0, -256).is_ok());
        assert!(aarch64_exact_load_q_unscaled_imm(31, 31, 255).is_ok());
        assert!(aarch64_exact_load_q_unscaled_imm(0, 0, -257).is_err());
        assert!(aarch64_exact_load_q_unscaled_imm(0, 0, 256).is_err());
        assert!(aarch64_exact_load_q_unscaled_imm(32, 0, -16).is_err());
        assert!(aarch64_exact_load_q_unscaled_imm(0, 32, -16).is_err());
    }

    #[test]
    fn aarch64_exact_verifier_uses_asimd_only_with_feature_and_full_vector_minimum() {
        let asimd = FeatureSet::of(CpuFeature::Aarch64Asimd);
        let sve = FeatureSet::of(CpuFeature::Aarch64Sve);
        let sve2 = sve.with(CpuFeature::Aarch64Sve2);
        let mixed_sve = asimd.with(CpuFeature::Aarch64Sve);
        let mixed = mixed_sve.with(CpuFeature::Aarch64Sve2);
        let pattern16 = exact_verifier_boundary_pattern(16);
        let pattern15 = exact_verifier_boundary_pattern(15);

        let wide_head = [
            aarch64_exact_load_q_post_imm(0, 13, 16).unwrap(),
            aarch64_exact_load_q_post_imm(1, 14, 16).unwrap(),
            aarch64_eor_16b(0, 0, 1).unwrap(),
            aarch64_umaxv_16b(0, 0).unwrap(),
            aarch64_umov_b0(16, 0).unwrap(),
        ];
        let scalar_head = [
            aarch64_load_byte_post_imm(16, 13, 1).unwrap(),
            aarch64_load_byte_post_imm(17, 14, 1).unwrap(),
            aarch64_cmp_w(16, 17).unwrap(),
        ];
        let overlap_tail = [
            aarch64_add_x_uxtw(13, 13, 10, 0).unwrap(),
            aarch64_add_x_uxtw(14, 14, 10, 0).unwrap(),
            aarch64_exact_load_q_unscaled_imm(0, 13, -16).unwrap(),
            aarch64_exact_load_q_unscaled_imm(1, 14, -16).unwrap(),
            aarch64_eor_16b(0, 0, 1).unwrap(),
            aarch64_umaxv_16b(0, 0).unwrap(),
            aarch64_umov_b0(16, 0).unwrap(),
        ];
        for features in [asimd, mixed_sve, mixed] {
            let target = Target::aarch64_linux().with_features(features).unwrap();
            let compiled = force_v2(&pattern16, target);
            let report = compiled
                .receipt_v2()
                .exact_finite_selected_end_teddy_aot
                .expect("wide exact verifier fixture");
            assert_eq!(report.lowering.minimum_width, 16);
            let words = compiled.module().sections()[TEXT_SECTION].bytes()
                [..report.lowering.incumbent_code_offset]
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            let matches = words
                .windows(wide_head.len())
                .enumerate()
                .filter(|(_, window)| *window == wide_head)
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1, "target={target:?}");
            let wide = matches[0];
            let vector_destinations = [
                u8::try_from(words[wide] & 0x1f).unwrap(),
                u8::try_from(words[wide + 1] & 0x1f).unwrap(),
                u8::try_from(words[wide + 2] & 0x1f).unwrap(),
                u8::try_from(words[wide + 3] & 0x1f).unwrap(),
            ];
            assert_eq!(vector_destinations, [0, 1, 0, 0]);
            for retained in [24, 25, 27, 28] {
                assert!(
                    !vector_destinations.contains(&retained),
                    "the exact leaf must not write retained Z/V{retained}: {target:?}",
                );
            }
            assert_eq!(
                words[wide + 5] & 0xff00_001f,
                0x3500_0010,
                "CBNZ W16 must reject a nonzero vector reduction: {target:?}",
            );
            assert_eq!(words[wide + 6], aarch64_sub_w_imm(10, 10, 16).unwrap(),);
            assert_eq!(words[wide + 7] & 0xff00_001f, 0x3400_000a);
            let exact_multiple_delta =
                (i32::try_from((words[wide + 7] >> 5) & 0x7_ffff).unwrap() << 13) >> 13;
            let exact_multiple_target =
                isize::try_from(wide + 7).unwrap() + exact_multiple_delta as isize;
            assert_eq!(words[wide + 8], aarch64_cmp_w_imm(10, 16).unwrap());
            assert_eq!(words[wide + 9] & 0xff00_001f, 0x5400_0002);
            assert_eq!(
                words[wide + 10],
                aarch64_cmp_w_imm(10, EXACT_FINITE_TEDDY_ASIMD_OVERLAP_MIN_RESIDUE)
                    .unwrap(),
                "the overlap crossover must be the discovery-selected residue: {target:?}",
            );
            assert_eq!(
                words[wide + 11] & 0xff00_001f,
                0x5400_0003,
                "B.LO must select the incumbent scalar residue loop: {target:?}",
            );
            let scalar_residue_delta =
                (i32::try_from((words[wide + 11] >> 5) & 0x7_ffff).unwrap() << 13) >> 13;
            let scalar_residue = usize::try_from(
                isize::try_from(wide + 11).unwrap() + scalar_residue_delta as isize,
            )
            .unwrap();
            assert_eq!(
                &words[wide + 12..wide + 12 + overlap_tail.len()],
                overlap_tail.as_slice(),
                "a residue at or above the crossover must compare its overlapping tail: {target:?}",
            );
            assert_eq!(
                words[wide + 19] & 0xff00_001f,
                0x3400_0010,
                "CBZ W16 must accept a zero overlapping-tail reduction: {target:?}",
            );
            let overlap_match_delta =
                (i32::try_from((words[wide + 19] >> 5) & 0x7_ffff).unwrap() << 13) >> 13;
            let overlap_match_target =
                isize::try_from(wide + 19).unwrap() + overlap_match_delta as isize;
            assert_eq!(
                exact_multiple_target, overlap_match_target,
                "a zero residue must skip the overlap tail and use its same matched edge: {target:?}",
            );
            assert_eq!(
                words[wide + 20] & 0xff00_001f,
                0xb500_000b,
                "a nonzero overlapping tail must fall through to ordinal failure: {target:?}",
            );
            assert_eq!(
                &words[scalar_residue..scalar_residue + scalar_head.len()],
                scalar_head.as_slice(),
                "residues below the crossover must retain the incumbent byte loop: {target:?}",
            );
            assert_eq!(
                words[scalar_residue + 3] & 0xff00_001f,
                0x5400_0001,
                "a scalar-residue mismatch must branch to ordinal failure: {target:?}",
            );
            let scalar_miss_delta =
                (i32::try_from((words[scalar_residue + 3] >> 5) & 0x7_ffff).unwrap() << 13) >> 13;
            assert_eq!(
                isize::try_from(scalar_residue + 3).unwrap() + scalar_miss_delta as isize,
                isize::try_from(wide + 20).unwrap(),
                "a scalar-residue mismatch must preserve the common ordered-retry edge: {target:?}",
            );
            assert_eq!(
                words[scalar_residue + 4],
                aarch64_sub_w_imm(10, 10, 1).unwrap(),
                "the incumbent scalar residue loop must decrement its remaining width: {target:?}",
            );
            assert_eq!(
                words[scalar_residue + 5] & 0xff00_001f,
                0x3500_000a,
                "CBNZ W10 must retain the incumbent scalar loop: {target:?}",
            );
            let scalar_loop_delta =
                (i32::try_from((words[scalar_residue + 5] >> 5) & 0x7_ffff).unwrap() << 13) >> 13;
            assert_eq!(
                isize::try_from(scalar_residue + 5).unwrap() + scalar_loop_delta as isize,
                isize::try_from(scalar_residue).unwrap(),
                "the scalar-residue loop must return to its first post-indexed load: {target:?}",
            );
            assert_eq!(
                isize::try_from(scalar_residue + 6).unwrap(),
                exact_multiple_target,
                "a completed scalar residue must fall through to the common matched edge: {target:?}",
            );
            // The first five exact words above are two Q loads and three
            // ASIMD operations. The loop-control and overlapping-tail words
            // asserted here likewise contain no predicate-register write; in
            // particular, retained P0..P4/P10 remain untouched.
            let loop_delta =
                (i32::try_from((words[wide + 9] >> 5) & 0x7_ffff).unwrap() << 13) >> 13;
            assert_eq!(
                isize::try_from(wide + 9).unwrap() + loop_delta as isize,
                isize::try_from(wide).unwrap(),
                "B.HS must close the vector loop: {target:?}",
            );
        }

        for (features, pattern) in [
            (sve, pattern16.as_str()),
            (sve2, pattern16.as_str()),
            (asimd, pattern15.as_str()),
            (mixed, pattern15.as_str()),
        ] {
            let target = Target::aarch64_linux().with_features(features).unwrap();
            let compiled = force_v2(pattern, target);
            let report = compiled
                .receipt_v2()
                .exact_finite_selected_end_teddy_aot
                .expect("scalar exact verifier fixture");
            let words = compiled.module().sections()[TEXT_SECTION].bytes()
                [..report.lowering.incumbent_code_offset]
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            assert!(
                !words
                    .windows(wide_head.len())
                    .any(|window| window == wide_head),
                "pure SVE/SVE2 and sub-vector minima remain scalar: {target:?}",
            );
            assert!(
                words
                    .windows(scalar_head.len())
                    .any(|window| window == scalar_head),
                "scalar verifier must remain present: {target:?}",
            );
            assert!(
                !words
                    .windows(overlap_tail.len())
                    .any(|window| window == overlap_tail),
                "pure SVE/SVE2 and sub-vector modules must remain unchanged without an overlap tail: {target:?}",
            );
        }
    }

    #[test]
    fn aarch64_asimd_selected_end_teddy_uses_authoritative_pair_miss() {
        let compiled = compile_selected(
            &scanner_free_exact_finite_pattern(),
            Target::aarch64_linux()
                .with_features(FeatureSet::of(CpuFeature::Aarch64Asimd))
                .unwrap(),
        );
        let report = compiled
            .receipt()
            .exact_finite_selected_end_teddy_aot
            .expect("exact finite SelectedEnd Teddy receipt");
        let words = compiled.module().sections()[TEXT_SECTION].bytes()
            [..report.incumbent_code_offset]
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();

        assert!(
            words.windows(5).any(|window| {
                window[0] == aarch64_umaxv_16b(7, 24).unwrap()
                    && window[1] == aarch64_umov_b0(12, 7).unwrap()
                    && window[2] & 0xff00_001f == 0x3500_000c
                    && window[3] == aarch64_add_x_imm(2, 2, 16).unwrap()
                    && window[4] & 0xfc00_0000 == 0x1400_0000
            }),
            "selected-end wrapper has no authoritative two-column miss edge",
        );
        assert!(
            words.windows(4).any(|window| {
                window
                    == [
                        aarch64_cmtst_16b(24, 24, 24).unwrap(),
                        aarch64_umaxv_16b(7, 24).unwrap(),
                        aarch64_umov_b0(12, 7).unwrap(),
                        aarch64_cmp_w_zero(12).unwrap(),
                    ]
            }),
            "selected-end wrapper does not publish its final exact lane mask",
        );
        assert!(
            words.windows(6).any(|window| {
                window
                    == [
                        aarch64_mov_x(21, 2).unwrap(),
                        aarch64_orr_16b(28, 24, 24).unwrap(),
                        aarch64_bsl_16b(28, 29, 31).unwrap(),
                        aarch64_uminv_16b(28, 28).unwrap(),
                        aarch64_umov_b0(12, 28).unwrap(),
                        aarch64_add_x_reg(2, 21, 12).unwrap(),
                    ]
            }),
            "selected-end wrapper no longer reaches exact first-lane selection",
        );
    }

    #[test]
    fn x86_verification_budget_tail_restores_public_abi() {
        let compiled = compile_selected(&scanner_free_exact_finite_pattern(), avx2_target());
        let code = compiled.module().sections()[TEXT_SECTION].bytes();
        let restore = [
            0x48, 0x89, 0xee, // rsi = public length
            0x4c, 0x89, 0xf9, // rcx = public end
            0x4d, 0x89, 0xf0, // r8 = public result
            0x5d, // pop rbp
            0x41, 0x5f, // pop r15
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
    fn aarch64_verification_budget_tail_restores_public_abi_on_every_tier() {
        for features in [
            FeatureSet::of(CpuFeature::Aarch64Asimd),
            FeatureSet::of(CpuFeature::Aarch64Sve),
            FeatureSet::of(CpuFeature::Aarch64Sve).with(CpuFeature::Aarch64Sve2),
        ] {
            let target = Target::aarch64_linux().with_features(features).unwrap();
            let compiled = compile_selected(&scanner_free_exact_finite_pattern(), target);
            let report = compiled
                .receipt()
                .exact_finite_selected_end_teddy_aot
                .expect("exact finite SelectedEnd Teddy receipt");
            let words = compiled.module().sections()[TEXT_SECTION]
                .bytes()
                .chunks_exact(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            let restore = [
                aarch64_mov_x(1, 19).unwrap(),
                aarch64_load_x_imm(21, 31, 16).unwrap(),
                aarch64_load_pair_x(19, 20, 31, 0).unwrap(),
                aarch64_add_x_imm(31, 31, 32).unwrap(),
            ];
            let restore_target = words
                .windows(restore.len())
                .position(|window| window == restore)
                .expect("public length, callee-saved registers, and stack restore sequence");
            let budget_branches = words
                .iter()
                .enumerate()
                .filter(|(_, word)| **word & 0xff00_001f == (0xb400_0000 | 20))
                .filter(|(branch, word)| {
                    let immediate = ((((**word >> 5) & 0x7_ffff) as i32) << 13) >> 13;
                    isize::try_from(*branch)
                        .ok()
                        .and_then(|origin| origin.checked_add(immediate as isize))
                        .and_then(|destination| usize::try_from(destination).ok())
                        == Some(restore_target)
                })
                .count();
            assert_eq!(
                budget_branches, 1,
                "verification-budget CBZ must target the complete ABI restore: {target:?}",
            );
            let tail = *words
                .get(restore_target + restore.len())
                .expect("restore sequence has an incumbent tail branch");
            assert_eq!(tail & 0xfc00_0000, 0x1400_0000, "target={target:?}");
            let immediate = (((tail & 0x03ff_ffff) as i32) << 6) >> 6;
            let tail_entry = isize::try_from(restore_target + restore.len())
                .unwrap()
                .checked_add(immediate as isize)
                .and_then(|destination| usize::try_from(destination).ok())
                .expect("in-section restored tail target");
            let incumbent_branch = *words
                .get(tail_entry)
                .expect("restored tail has an incumbent branch");
            assert_eq!(
                incumbent_branch & 0xfc00_0000,
                0x1400_0000,
                "target={target:?}",
            );
            let immediate = (((incumbent_branch & 0x03ff_ffff) as i32) << 6) >> 6;
            let incumbent = isize::try_from(tail_entry)
                .unwrap()
                .checked_add(immediate as isize)
                .and_then(|destination| usize::try_from(destination).ok())
                .expect("in-section incumbent target");
            assert_eq!(
                incumbent.checked_mul(4),
                Some(report.incumbent_code_offset),
                "restored tail must enter the authenticated incumbent: {target:?}",
            );
        }
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
    fn exists_declared_native_data_cap_restores_every_incumbent_field() {
        let target = avx2_target();
        let compiled = compile_exists(&scanner_free_exact_finite_pattern(), target);
        let choice = compiled
            .program()
            .native_finite_exists_choice_view()
            .unwrap();
        let (incumbent, baseline) = complete_exists_dfa_baseline(&compiled, target);
        let selection = select_exact_finite_exists_teddy(
            compiled.program().artifact_identity(),
            choice,
            target,
            baseline,
        )
        .unwrap();
        let required =
            exact_finite_selected_end_teddy_required_data_bytes(selection, incumbent.data.len())
                .unwrap();
        let original_code = incumbent.code.clone();
        let original_data = incumbent.data.clone();
        let original_relocations = incumbent.relocations.clone();
        let original_slow_partial = incumbent.slow_partial_table;
        let original_needs_runtime = incumbent.needs_runtime;
        let original_scanner = incumbent.start_accelerator;
        let original_prefix = incumbent.anchored_prefix_filter_bytes;
        let original_sync = incumbent.synchronizing_accept_reverse_lowered;
        let original_suffix = incumbent.exact_pair_suffix_lowered;
        let original_core = incumbent.direct_search_trusted_core;
        let original_span_reduce = incumbent.complete_span_reduce_source.as_deref().copied();
        let ExactFiniteSelectedEndTeddyWrapOutcome::ResourceDeclined(restored) =
            wrap_exact_finite_exists_teddy(
                selection,
                incumbent,
                baseline,
                target,
                required - 1,
            )
            .unwrap()
        else {
            panic!("one-byte-short Exists Teddy ceiling must decline")
        };
        assert_eq!(restored.code, original_code);
        assert_eq!(restored.data, original_data);
        assert_eq!(restored.relocations, original_relocations);
        assert_eq!(restored.slow_partial_table, original_slow_partial);
        assert_eq!(restored.needs_runtime, original_needs_runtime);
        assert_eq!(restored.start_accelerator, original_scanner);
        assert_eq!(restored.anchored_prefix_filter_bytes, original_prefix);
        assert_eq!(restored.synchronizing_accept_reverse_lowered, original_sync);
        assert_eq!(restored.exact_pair_suffix_lowered, original_suffix);
        assert_eq!(restored.direct_search_trusted_core, original_core);
        assert_eq!(
            restored.complete_span_reduce_source.as_deref().copied(),
            original_span_reduce,
        );

        let unchanged = unchanged_exists_module(&compiled, target);
        let capped = crate::compile_with_slow_aot_limits(
            CompileRequest::new(scanner_free_exact_finite_pattern(), target)
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
            crate::SlowAotLimits {
                max_native_data_bytes: required - 1,
                ..crate::SlowAotLimits::default()
            },
        )
        .expect("composite-only cap decline preserves ordinary Exists compilation");
        assert!(
            capped
                .module()
                .exact_finite_exists_teddy_aot_report()
                .is_none(),
        );
        assert_byte_identical_module(capped.module(), &unchanged);
        let unchanged_object = crate::emit_object(
            &unchanged,
            crate::ObjectFormat::for_target(target),
            usize::MAX,
        )
        .unwrap();
        assert_eq!(capped.object(), unchanged_object);

        let (incumbent, baseline) = complete_exists_dfa_baseline(&compiled, target);
        let ExactFiniteSelectedEndTeddyWrapOutcome::Selected { lowering, report } =
            wrap_exact_finite_exists_teddy(selection, incumbent, baseline, target, required)
                .unwrap()
        else {
            panic!("exact Exists Teddy ceiling must admit")
        };
        assert_eq!(lowering.data.len(), required);
        assert_eq!(report.native_data_bytes, required);
        assert_eq!(report.output, OutputContract::Exists);
        assert!(lowering.direct_search_trusted_core.is_none());
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

        let sve_target = Target::aarch64_linux()
            .with_features(FeatureSet::of(CpuFeature::Aarch64Sve))
            .unwrap();
        let sve_compiled = compile_selected(&scanner_free_exact_finite_pattern(), sve_target);
        let sve_report = sve_compiled
            .receipt()
            .exact_finite_selected_end_teddy_aot
            .unwrap();
        let sve_data = sve_compiled.module().sections()[PROGRAM_SECTION].bytes();
        assert_eq!(
            sve_report.batch_vectors,
            EXACT_FINITE_TEDDY_SVE_BATCH_VECTORS,
        );
        let mut changed_report = sve_report;
        changed_report.batch_vectors = EXACT_FINITE_TEDDY_UNBATCHED_VECTORS;
        changed_report.prefix_plan_sha256 =
            report_plan_digest(&changed_report, sve_data).unwrap();
        assert_eq!(
            report_costs_authenticate(&changed_report, sve_data, sve_target),
            Ok(false),
            "a coherently rehashed batch-width mutation must fail strict receipt authentication",
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
    fn linked_host_exists_teddy_smoke_covers_native_negative_and_positive() {
        use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

        let Some(target) = linked_host_target() else {
            return;
        };
        let compiler = if cfg!(target_os = "macos") {
            "clang"
        } else {
            "cc"
        };
        if Command::new(compiler).arg("--version").output().is_err() {
            return;
        }
        let compiled = compile_exists(&scanner_free_exact_finite_pattern(), target);
        let literal = compiled
            .program()
            .native_finite_exists_choice_view()
            .unwrap()
            .literals()[0]
            .clone();
        let mut positive = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 64];
        let base = positive.len() - literal.len();
        positive[base..].copy_from_slice(&literal);
        let negative = vec![0xff; positive.len()];
        let bytes = |haystack: &[u8]| {
            haystack
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        let symbol = compiled.module().entry_symbol();
        let mut source = format!(
            "#include <stdint.h>\n#include <stddef.h>\nextern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\n"
        );
        writeln!(source, "static const unsigned char n[]={{{}}};", bytes(&negative)).unwrap();
        writeln!(source, "static const unsigned char p[]={{{}}};", bytes(&positive)).unwrap();
        writeln!(source, "int main(void){{size_t r[2]={{9,10}};if({symbol}(n,sizeof(n),0,sizeof(n),r)!=0||r[0]!=0||r[1]!=0)return 1;r[0]=9;r[1]=10;if({symbol}(p,sizeof(p),0,sizeof(p),r)!=1||r[0]!=0||r[1]!=0)return 2;return 0;}}").unwrap();

        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-exists-teddy-smoke-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir_all(&directory).unwrap();
        let source_path = directory.join("smoke.c");
        let object_path = directory.join("smoke.o");
        let executable_path = directory.join("smoke");
        fs::write(&source_path, source).unwrap();
        fs::write(&object_path, compiled.object()).unwrap();
        let status = Command::new(compiler)
            .arg("-O0")
            .arg(&source_path)
            .arg(&object_path)
            .arg("-o")
            .arg(&executable_path)
            .status()
            .unwrap();
        assert!(status.success(), "host linker rejected Exists Teddy smoke");
        let status = Command::new(&executable_path).status().unwrap();
        assert!(status.success(), "native Exists Teddy smoke failed");
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        any(target_os = "linux", target_os = "macos")
    ))]
    #[test]
    #[ignore = "links and executes the actual exact finite Exists Teddy leaf on the host ISA"]
    fn linked_host_exists_teddy_matches_negative_candidates_and_incumbent_tails() {
        use std::{fmt::Write as _, fs, process::Command, time::SystemTime};

        let Some(target) = linked_host_target() else {
            return;
        };
        let pattern = scanner_free_exact_finite_pattern();
        let compiled = compile_exists(&pattern, target);
        let choice = compiled
            .program()
            .native_finite_exists_choice_view()
            .expect("linked Exists Teddy Choice");
        let report = compiled
            .module()
            .exact_finite_exists_teddy_aot_report()
            .expect("linked Exists Teddy internal proof");
        let selection = select_exact_finite_exists_teddy(
            compiled.program().artifact_identity(),
            choice,
            target,
            report.incumbent_complete_dfa,
        )
        .expect("linked Exists Teddy selection");
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
            let exact = choice
                .literals()
                .iter()
                .any(|literal| literal[..columns] == bytes[..columns]);
            if !exact && selection.plan.candidate_buckets(&bytes[..columns]) != 0 {
                collision = Some(bytes);
                break;
            }
        }
        let collision = collision.expect("linked fixture has a conservative fingerprint collision");
        let literal = choice.literals()[0].clone();

        let negative = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256];
        let mut early_positive = negative.clone();
        early_positive[32..32 + literal.len()].copy_from_slice(&literal);
        let mut logical_eof_positive = vec![0xff; negative.len() + 17];
        let logical_end = logical_eof_positive.len() - 17;
        logical_eof_positive[logical_end - literal.len()..logical_end]
            .copy_from_slice(&literal);
        let mut collision_then_positive = negative.clone();
        collision_then_positive[64..64 + columns].copy_from_slice(&collision[..columns]);
        collision_then_positive[192..192 + literal.len()].copy_from_slice(&literal);
        let mut budget_negative = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 1024];
        for candidate in 0..usize::from(EXACT_FINITE_TEDDY_RUNTIME_VERIFICATION_BUDGET) + 2 {
            let base = 64 + candidate * 8;
            budget_negative[base..base + columns].copy_from_slice(&collision[..columns]);
        }
        let mut budget_positive = budget_negative.clone();
        let budget_positive_base = budget_positive.len() - literal.len();
        budget_positive[budget_positive_base..].copy_from_slice(&literal);
        let windows = vec![
            (negative, 0, EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256),
            (
                early_positive,
                0,
                EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256,
            ),
            (logical_eof_positive, 0, logical_end),
            (
                collision_then_positive,
                0,
                EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256,
            ),
            (
                budget_negative,
                0,
                EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 1024,
            ),
            (
                budget_positive,
                0,
                EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 1024,
            ),
        ];
        let reference = compile(
            CompileRequest::new(&pattern, target)
                .mode(CompileMode::Fast)
                .output(OutputContract::Exists),
        )
        .expect("compile independent portable Exists reference");

        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-finite-exists-teddy-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir_all(&directory).expect("create Exists Teddy linker directory");
        let symbol = compiled.module().entry_symbol();
        let mut source = format!(
            "#include <stdint.h>\n#include <stddef.h>\nextern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);\nint main(void){{size_t r[2];uint32_t s;\n"
        );
        for (index, (haystack, start, end)) in windows.iter().enumerate() {
            let bytes = haystack
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",");
            writeln!(source, "static const unsigned char h{index}[]={{{bytes}}};").unwrap();
            let MatchResult::Exists(expected) = reference
                .search(haystack, SearchWindow::new(*start, *end))
                .expect("portable Exists Teddy differential")
            else {
                unreachable!()
            };
            writeln!(
                source,
                "r[0]=91;r[1]=92;s={symbol}(h{index},{},{start},{end},r);if(s!={}||r[0]!=0||r[1]!=0)return {};",
                haystack.len(),
                u8::from(expected),
                20 + index,
            )
            .unwrap();
        }
        writeln!(
            source,
            "r[0]=91;r[1]=92;s={symbol}(h0,{},1,0,r);if(s!=2||r[0]!=91||r[1]!=92)return 90;return 0;}}",
            windows[0].0.len(),
        )
        .unwrap();
        let c_path = directory.join("exists_teddy.c");
        let object = directory.join("exists_teddy.o");
        let executable = directory.join("exists_teddy");
        fs::write(&c_path, source).expect("write Exists Teddy linker harness");
        fs::write(&object, compiled.object()).expect("write Exists Teddy object");
        let compiler = if cfg!(target_os = "macos") {
            "clang"
        } else {
            "cc"
        };
        let status = Command::new(compiler)
            .arg("-O0")
            .arg(&c_path)
            .arg(&object)
            .arg("-o")
            .arg(&executable)
            .status()
            .expect("link actual Exists Teddy differential");
        assert!(status.success());
        let output = Command::new(&executable)
            .output()
            .expect("execute Exists Teddy differential");
        assert!(
            output.status.success(),
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        fs::remove_dir_all(directory).expect("remove Exists Teddy linker directory");
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
        type LinkedCase = (Target, String, Vec<(Vec<u8>, usize, usize)>, bool);
        let mut cases = Vec::<LinkedCase>::new();
        for long_first in [false, true] {
            let mut order_long = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256];
            order_long[83..90].fill(0xaa);
            let order_len = order_long.len();
            cases.push((
                target,
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
                false,
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
            target,
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
            false,
        ));

        let mut binary_eof = vec![0x7e; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 73];
        let binary_len = binary_eof.len();
        binary_eof[binary_len - 6..].fill(0);
        cases
            .last_mut()
            .expect("collision case")
            .2
            .push((binary_eof, 23, binary_len));

        let sparse_pattern = sparse_single_prefix_pattern();
        let sparse_literals = sparse_single_prefix_literals();
        let singleton_miss = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256];
        let singleton_miss_len = singleton_miss.len();
        let mut pair_miss = singleton_miss.clone();
        for base in (64..192).step_by(8) {
            pair_miss[base + 1] = 0;
        }
        let pair_miss_len = pair_miss.len();
        let mut direct_hit = singleton_miss.clone();
        direct_hit[96..96 + sparse_literals[0].len()].copy_from_slice(&sparse_literals[0]);
        let direct_hit_len = direct_hit.len();
        let mut retry_then_hit = singleton_miss.clone();
        retry_then_hit[64..68].copy_from_slice(&sparse_literals[1][..4]);
        retry_then_hit[68] = sparse_literals[1][4] ^ 0xff;
        retry_then_hit[144..144 + sparse_literals[2].len()]
            .copy_from_slice(&sparse_literals[2]);
        let retry_then_hit_len = retry_then_hit.len();
        let mut tail_hit = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 73];
        let tail_base = tail_hit.len() - sparse_literals[3].len();
        tail_hit[tail_base..].copy_from_slice(&sparse_literals[3]);
        let tail_hit_len = tail_hit.len();
        cases.push((
            target,
            sparse_pattern,
            vec![
                (singleton_miss, 17, singleton_miss_len),
                (pair_miss, 17, pair_miss_len),
                (direct_hit, 17, direct_hit_len),
                (retry_then_hit, 17, retry_then_hit_len),
                (tail_hit, 17, tail_hit_len),
            ],
            true,
        ));

        let mut guard_artifact = None;
        if target.architecture == Architecture::Aarch64 {
            let wide_target = target
                .with_features(target.features.with(CpuFeature::Aarch64Asimd))
                .expect("the host AArch64 target accepts its mandatory ASIMD feature");
            let literals = exact_verifier_boundary_literals(16);
            let mut windows = Vec::new();
            for literal in &literals {
                for residue in 0..16 {
                    let base = 64 + residue;
                    let mut haystack = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256];
                    haystack[base..base + literal.len()].copy_from_slice(literal);
                    let end = haystack.len();
                    windows.push((haystack, 7, end));
                }
                for mismatch in 0..literal.len() {
                    let base = 96 + mismatch % 16;
                    let mut haystack = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256];
                    let mut changed = literal.clone();
                    changed[mismatch] ^= 0x80;
                    haystack[base..base + changed.len()].copy_from_slice(&changed);
                    let end = haystack.len();
                    windows.push((haystack, 7, end));
                }
                let mut eof = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + literal.len() + 17];
                let base = eof.len() - literal.len();
                eof[base..].copy_from_slice(literal);
                let end = eof.len();
                windows.push((eof, 7, end));
            }
            guard_artifact = Some(cases.len());
            cases.push((
                wide_target,
                exact_verifier_boundary_pattern(16),
                windows,
                true,
            ));

            // Two eight-literal modules cover every possible width residue
            // after a complete sixteen-byte vector. Exercise a true match,
            // a mismatch at every literal byte, and a match ending at a
            // nonterminal logical end for each residue zero through fifteen.
            for first_residue in [0, 8] {
                let (pattern, literals) = exact_verifier_residue_pattern(first_residue);
                let mut windows = Vec::new();
                for literal in &literals {
                    let base = 64 + literal.len() % 16;
                    let mut haystack = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256];
                    haystack[base..base + literal.len()].copy_from_slice(literal);
                    let end = haystack.len();
                    windows.push((haystack, 7, end));

                    let logical_start = 64;
                    let mut at_start = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256];
                    at_start[logical_start..logical_start + literal.len()].copy_from_slice(literal);
                    let end = at_start.len();
                    windows.push((at_start, logical_start, end));

                    let mut before_start = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256];
                    before_start[logical_start - 1..logical_start - 1 + literal.len()]
                        .copy_from_slice(literal);
                    let end = before_start.len();
                    windows.push((before_start, logical_start, end));

                    for mismatch in 0..literal.len() {
                        let base = 96 + mismatch % 16;
                        let mut haystack = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256];
                        let mut changed = literal.clone();
                        changed[mismatch] ^= 0x80;
                        haystack[base..base + changed.len()].copy_from_slice(&changed);
                        let end = haystack.len();
                        windows.push((haystack, 7, end));
                    }

                    let mut eof =
                        vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + literal.len() + 17];
                    let end = eof.len() - 17;
                    let base = end - literal.len();
                    eof[base..end].copy_from_slice(literal);
                    windows.push((eof, 7, end));

                    let mut crossing_end =
                        vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + literal.len() + 17];
                    let end = crossing_end.len() - 17;
                    let base = end - literal.len() + 1;
                    crossing_end[base..base + literal.len()].copy_from_slice(literal);
                    windows.push((crossing_end, 7, end));

                    let mut physical_eof =
                        vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + literal.len() + 17];
                    let base = physical_eof.len() - literal.len();
                    physical_eof[base..].copy_from_slice(literal);
                    let end = physical_eof.len();
                    windows.push((physical_eof, 7, end));
                }
                cases.push((wide_target, pattern, windows, true));
            }

            // The first source matches the complete vector but fails in its
            // scalar residue; the next source then succeeds. This exercises
            // ordered retry without mutating the remaining source mask or the
            // candidate base.
            let (pattern, later_source) = exact_verifier_late_ordinal_pattern();
            let mut haystack = vec![0xff; EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256];
            let base = 97;
            haystack[base..base + later_source.len()].copy_from_slice(&later_source);
            let end = haystack.len();
            cases.push((wide_target, pattern, vec![(haystack, 7, end)], true));
        }

        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fre-aot-finite-selected-end-teddy-{}-{nonce}",
            std::process::id(),
        ));
        fs::create_dir_all(&directory).unwrap();
        let mut source = String::from(
            "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n#include <sys/mman.h>\n#include <unistd.h>\n#ifndef MAP_ANONYMOUS\n#define MAP_ANONYMOUS MAP_ANON\n#endif\n",
        );
        let mut calls = String::from("int main(void){size_t r[2];uint32_t s;\n");
        let mut objects = Vec::new();
        let mut guard_symbol = None;
        for (artifact, (case_target, pattern, windows, forced_v2)) in cases.iter().enumerate() {
            if *forced_v2
                && let Ok(expected) = std::env::var("FRE_EXPECT_SVE_VECTOR_LENGTH_BYTES")
            {
                let actual = fs::read_to_string("/proc/sys/abi/sve_default_vector_length")
                    .expect("read the requested Linux SVE vector length")
                    .trim()
                    .parse::<u16>()
                    .expect("parse the requested Linux SVE vector length");
                assert_eq!(actual, expected.parse::<u16>().unwrap());
            }
            let (symbol, object_bytes) = if *forced_v2 {
                let compiled = force_v2(pattern, *case_target);
                let report = compiled
                    .receipt_v2()
                    .exact_finite_selected_end_teddy_aot
                    .expect("forced sparse differential must select Teddy");
                assert_eq!(
                    report.selection_basis,
                    ExactFiniteSelectedEndTeddySelectionBasisV2::ForcedStructuralEligibility,
                );
                (
                    compiled.module().entry_symbol().to_owned(),
                    compiled.object().to_vec(),
                )
            } else {
                let compiled = compile_selected(pattern, *case_target);
                (
                    compiled.module().entry_symbol().to_owned(),
                    compiled.object().to_vec(),
                )
            };
            if guard_artifact == Some(artifact) {
                guard_symbol = Some(symbol.clone());
            }
            let reference = compile(
                CompileRequest::new(pattern, *case_target)
                    .mode(CompileMode::Fast)
                    .output(OutputContract::SelectedEnd),
            )
            .unwrap();
            writeln!(
                source,
                "extern uint32_t {symbol}(const unsigned char*,size_t,size_t,size_t,size_t*);",
            )
            .unwrap();
            let object = directory.join(format!("case{artifact}.o"));
            fs::write(&object, object_bytes).unwrap();
            objects.push(object);
            for (window_index, (haystack, start, end)) in windows.iter().enumerate() {
                let bytes = haystack
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                writeln!(
                    source,
                    "{}static const unsigned char h{artifact}_{window_index}[]={{{bytes}}};",
                    if guard_artifact == Some(artifact) {
                        "_Alignas(16) "
                    } else {
                        ""
                    },
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
                let failure = 1 + (10 + artifact * 10 + window_index) % 254;
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
        if let Some(symbol) = guard_symbol {
            let literals = exact_verifier_boundary_literals(16);
            for (ordinal, literal) in literals.iter().enumerate() {
                let bytes = literal
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                writeln!(
                    source,
                    "static const unsigned char guard_literal_{ordinal}[]={{{bytes}}};",
                )
                .unwrap();
            }
            let guard_len = EXACT_FINITE_PREFIX_MIN_INPUT_BYTES + 256;
            writeln!(
                calls,
                "long guard_page=sysconf(_SC_PAGESIZE);if(guard_page<=0)return 220;size_t guard_pages=({guard_len}+(size_t)guard_page-1)/(size_t)guard_page;size_t guard_map_bytes=(guard_pages+1)*(size_t)guard_page;unsigned char*guard_map=(unsigned char*)mmap(0,guard_map_bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(guard_map==MAP_FAILED)return 221;if(mprotect(guard_map+guard_pages*(size_t)guard_page,(size_t)guard_page,PROT_NONE)!=0)return 222;unsigned char*guard_hay=guard_map+guard_pages*(size_t)guard_page-{guard_len};",
            )
            .unwrap();
            for (ordinal, literal) in literals.iter().enumerate() {
                writeln!(
                    calls,
                    "memset(guard_hay,255,{guard_len});memcpy(guard_hay+{guard_len}-{},guard_literal_{ordinal},{});r[0]=91;r[1]=92;s={symbol}(guard_hay,{guard_len},0,{guard_len},r);if(s!=1||r[0]!={guard_len}||r[1]!={guard_len})return {};",
                    literal.len(),
                    literal.len(),
                    223 + ordinal,
                )
                .unwrap();
            }
            calls.push_str("if(munmap(guard_map,guard_map_bytes)!=0)return 239;\n");
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
