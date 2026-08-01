//! Target-neutral planning for scalar anchored-prefix predicates.
//!
//! The anchored-prefix analysis supplies exact byte membership columns. A
//! native candidate guard is a conjunction of those columns, so its order is
//! semantically irrelevant but materially affects rejected-candidate cost.
//! This pass selects an exact scalar representation for every column and
//! orders the conjunction by expected evaluation cost per rejected byte.
//!
//! The planner contains no ISA encodings. Target lowering supplies a small
//! instruction-cost profile; the same proof and ordering code therefore
//! serves `AArch64`, x86-64 and future backends. Byte weights are likewise an
//! explicit, stable input. They may model an offline byte distribution or use
//! uniform weights for a completely distribution-neutral decision.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "all arithmetic is bounded by 256 bytes, four ranges and u16 cost/weight units"
)]

use core::cmp::Ordering;

use crate::program::MAX_ANCHORED_PREFIX_BYTES;

/// Maximum anchored-prefix columns retained by the graph analysis.
pub(crate) const MAX_SCALAR_PREFIX_PREDICATES: usize = MAX_ANCHORED_PREFIX_BYTES;
/// More fragmented sets retain the exact 256-bit bitmap representation.
pub(crate) const MAX_SCALAR_PREFIX_RANGES: usize = 4;

/// Distribution-neutral weights for exact, deterministic planning.
#[cfg(test)]
pub(crate) const UNIFORM_PREFIX_BYTE_WEIGHTS: [u16; 256] = [1; 256];

/// Relative dynamic costs for one scalar membership test.
///
/// The common input-address and byte-load cost is separate because it cancels
/// when choosing an encoding, but not when ordering predicates. Interval
/// tests have two paths: a byte below the inclusive lower bound can advance
/// after one comparison/branch pair, while a byte at or above it also checks
/// the upper bound. `terminal_reject_units` is the final branch taken after
/// every range rejected the byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_field_names,
    reason = "the unit suffix distinguishes every cost from future counts and byte widths"
)]
pub(crate) struct ScalarPrefixPredicateCosts {
    input_load_units: u16,
    bitmap_membership_units: u16,
    singleton_units: u16,
    interval_below_units: u16,
    interval_at_or_above_units: u16,
    terminal_reject_units: u16,
}

impl ScalarPrefixPredicateCosts {
    const fn new(
        input_load_units: u16,
        bitmap_membership_units: u16,
        singleton_units: u16,
        interval_below_units: u16,
        interval_at_or_above_units: u16,
        terminal_reject_units: u16,
    ) -> Self {
        Self {
            input_load_units,
            bitmap_membership_units,
            singleton_units,
            interval_below_units,
            interval_at_or_above_units,
            terminal_reject_units,
        }
    }
}

/// `AArch64`'s current scalar lowering after the candidate-bound check.
///
/// The bitmap path needs a shift, table-address materialization, indexed load,
/// variable shift, mask, comparison and branch after the common address/load.
/// Large table offsets only make that path more expensive, so charging the
/// one-instruction address form is conservative when selecting ranges.
pub(crate) const AARCH64_SCALAR_PREFIX_COSTS: ScalarPrefixPredicateCosts =
    ScalarPrefixPredicateCosts::new(2, 7, 2, 2, 4, 1);

/// x86-64's `bt [bitmap], byte; jnc` makes a bitmap hard to beat. Keeping a
/// separate profile lets the target-neutral planner preserve that lowering.
pub(crate) const X86_64_SCALAR_PREFIX_COSTS: ScalarPrefixPredicateCosts =
    ScalarPrefixPredicateCosts::new(1, 2, 2, 2, 4, 1);

/// One exact graph-derived anchored byte column.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrefixPredicateInput {
    position: u8,
    words: [u64; 4],
}

impl PrefixPredicateInput {
    #[must_use]
    pub(crate) const fn new(position: u8, words: [u64; 4]) -> Self {
        Self { position, words }
    }
}

/// Inclusive exact byte range used by a compare-and-branch lowering.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ScalarPrefixRange {
    start: u8,
    end: u8,
}

impl ScalarPrefixRange {
    #[must_use]
    pub(crate) const fn start(self) -> u8 {
        self.start
    }

    #[must_use]
    pub(crate) const fn end(self) -> u8 {
        self.end
    }

    #[must_use]
    pub(crate) const fn is_singleton(self) -> bool {
        self.start == self.end
    }

    #[must_use]
    #[cfg(test)]
    const fn contains(self, byte: u8) -> bool {
        self.start <= byte && byte <= self.end
    }
}

/// Exact membership represented by at most four disjoint inclusive ranges.
///
/// Range order is deliberately not required to be numeric. The planner checks
/// every possible order and retains the one with minimum weighted dynamic
/// cost. Membership remains exact because each range is tested independently.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ScalarPrefixRangePlan {
    ranges: [ScalarPrefixRange; MAX_SCALAR_PREFIX_RANGES],
    range_count: u8,
}

impl ScalarPrefixRangePlan {
    #[must_use]
    pub(crate) fn ranges(&self) -> &[ScalarPrefixRange] {
        &self.ranges[..usize::from(self.range_count)]
    }

    #[must_use]
    #[cfg(test)]
    fn accepts(self, byte: u8) -> bool {
        self.ranges().iter().any(|range| range.contains(byte))
    }
}

/// Exact scalar representation selected for one prefix column.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScalarPrefixMembership {
    /// The graph-derived column is empty; lowering can branch directly to the
    /// rejected-candidate path without loading a byte.
    RejectAll,
    /// Compare against an exact, cost-minimized sequence of ranges.
    Ranges(ScalarPrefixRangePlan),
    /// Use the complete 256-bit membership bitmap.
    Bitmap256,
}

/// One planned predicate, including the proof data needed to serialize a
/// bitmap without consulting regex source text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScalarPrefixPredicatePlan {
    position: u8,
    words: [u64; 4],
    membership: ScalarPrefixMembership,
    passing_byte_count: u16,
    passing_weight: u64,
    rejected_weight: u64,
    evaluation_cost_numerator: u64,
}

const EMPTY_PREDICATE_PLAN: ScalarPrefixPredicatePlan = ScalarPrefixPredicatePlan {
    position: 0,
    words: [0; 4],
    membership: ScalarPrefixMembership::RejectAll,
    passing_byte_count: 0,
    passing_weight: 0,
    rejected_weight: 0,
    evaluation_cost_numerator: 0,
};

impl ScalarPrefixPredicatePlan {
    #[must_use]
    pub(crate) const fn position(self) -> u8 {
        self.position
    }

    #[must_use]
    pub(crate) const fn words(self) -> [u64; 4] {
        self.words
    }

    #[must_use]
    pub(crate) const fn membership(self) -> ScalarPrefixMembership {
        self.membership
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn passing_weight(self) -> u64 {
        self.passing_weight
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn evaluation_cost_numerator(self) -> u64 {
        self.evaluation_cost_numerator
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) fn accepts(self, byte: u8) -> bool {
        match self.membership {
            ScalarPrefixMembership::RejectAll => false,
            ScalarPrefixMembership::Ranges(ranges) => ranges.accepts(byte),
            ScalarPrefixMembership::Bitmap256 => mask_contains(self.words, byte),
        }
    }
}

/// Cost-ordered conjunction for all non-wildcard prefix columns supplied by
/// the caller. A column already proven by the moving candidate scanner should
/// be omitted from the input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScalarPrefixConjunctionPlan {
    predicates: [ScalarPrefixPredicatePlan; MAX_SCALAR_PREFIX_PREDICATES],
    predicate_count: u8,
    bitmap_count: u8,
    total_weight: u64,
}

impl ScalarPrefixConjunctionPlan {
    #[must_use]
    pub(crate) fn predicates(&self) -> &[ScalarPrefixPredicatePlan] {
        &self.predicates[..usize::from(self.predicate_count)]
    }

    #[must_use]
    pub(crate) const fn bitmap_count(self) -> u8 {
        self.bitmap_count
    }

    #[must_use]
    #[cfg(test)]
    pub(crate) const fn total_weight(self) -> u64 {
        self.total_weight
    }
}

/// Checked planning failures. Native compilation can map these directly to
/// its existing invalid-module/arithmetic error categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScalarPrefixPlanError {
    TooManyPredicates,
    DuplicatePosition,
    ZeroTotalByteWeight,
}

/// Select exact scalar membership forms and the minimum expected-cost
/// conjunction order under the supplied stable byte weights.
///
/// Wildcard columns are omitted. For every other column, a range lowering is
/// selected only when (1) its bitmap has at most four contiguous runs and (2)
/// its minimum cost over every range order is strictly below the bitmap cost.
/// On encoding or ordering ties the bitmap and lower byte position win,
/// respectively, making object output independent of discovery order.
pub(crate) fn plan_scalar_prefix_predicates(
    inputs: &[PrefixPredicateInput],
    costs: ScalarPrefixPredicateCosts,
    byte_weights: &[u16; 256],
) -> Result<ScalarPrefixConjunctionPlan, ScalarPrefixPlanError> {
    if inputs.len() > MAX_SCALAR_PREFIX_PREDICATES {
        return Err(ScalarPrefixPlanError::TooManyPredicates);
    }
    for (index, input) in inputs.iter().enumerate() {
        if inputs[index + 1..]
            .iter()
            .any(|other| other.position == input.position)
        {
            return Err(ScalarPrefixPlanError::DuplicatePosition);
        }
    }

    let total_weight = byte_weights.iter().map(|&weight| u64::from(weight)).sum();
    if total_weight == 0 {
        return Err(ScalarPrefixPlanError::ZeroTotalByteWeight);
    }

    let mut predicates = [EMPTY_PREDICATE_PLAN; MAX_SCALAR_PREFIX_PREDICATES];
    let mut predicate_count = 0_usize;
    let mut bitmap_count = 0_u8;
    for input in inputs.iter().copied() {
        let passing_byte_count = mask_cardinality(input.words);
        if passing_byte_count == 256 {
            continue;
        }
        let passing_weight = weighted_membership(input.words, byte_weights);
        let rejected_weight = total_weight - passing_weight;
        let (membership, evaluation_cost_numerator) = if passing_byte_count == 0 {
            (
                ScalarPrefixMembership::RejectAll,
                total_weight * u64::from(costs.terminal_reject_units),
            )
        } else if let Some(ranges) = encode_exact_ranges(input.words) {
            let (ranges, range_cost) =
                cheapest_range_order(ranges, costs, byte_weights, total_weight);
            let bitmap_cost = bitmap_cost_numerator(costs, total_weight);
            if range_cost < bitmap_cost {
                (ScalarPrefixMembership::Ranges(ranges), range_cost)
            } else {
                (ScalarPrefixMembership::Bitmap256, bitmap_cost)
            }
        } else {
            (
                ScalarPrefixMembership::Bitmap256,
                bitmap_cost_numerator(costs, total_weight),
            )
        };
        if membership == ScalarPrefixMembership::Bitmap256 {
            bitmap_count += 1;
        }
        predicates[predicate_count] = ScalarPrefixPredicatePlan {
            position: input.position,
            words: input.words,
            membership,
            passing_byte_count,
            passing_weight,
            rejected_weight,
            evaluation_cost_numerator,
        };
        predicate_count += 1;
    }

    predicates[..predicate_count].sort_unstable_by(predicate_order);
    Ok(ScalarPrefixConjunctionPlan {
        predicates,
        predicate_count: u8::try_from(predicate_count)
            .map_err(|_| ScalarPrefixPlanError::TooManyPredicates)?,
        bitmap_count,
        total_weight,
    })
}

fn predicate_order(
    left: &ScalarPrefixPredicatePlan,
    right: &ScalarPrefixPredicatePlan,
) -> Ordering {
    match (left.rejected_weight, right.rejected_weight) {
        (0, 0) => return left.position.cmp(&right.position),
        (0, _) => return Ordering::Greater,
        (_, 0) => return Ordering::Less,
        (_, _) => {}
    }
    let left_ratio = u128::from(left.evaluation_cost_numerator) * u128::from(right.rejected_weight);
    let right_ratio =
        u128::from(right.evaluation_cost_numerator) * u128::from(left.rejected_weight);
    left_ratio
        .cmp(&right_ratio)
        .then_with(|| left.position.cmp(&right.position))
}

fn bitmap_cost_numerator(costs: ScalarPrefixPredicateCosts, total_weight: u64) -> u64 {
    total_weight
        * u64::from(
            costs
                .input_load_units
                .saturating_add(costs.bitmap_membership_units),
        )
}

fn encode_exact_ranges(words: [u64; 4]) -> Option<ScalarPrefixRangePlan> {
    let mut plan = ScalarPrefixRangePlan::default();
    let mut range_count = 0_usize;
    for byte in u8::MIN..=u8::MAX {
        if !mask_contains(words, byte) {
            continue;
        }
        if let Some(last) = range_count
            .checked_sub(1)
            .and_then(|index| plan.ranges.get_mut(index))
            && last.end.checked_add(1) == Some(byte)
        {
            last.end = byte;
            continue;
        }
        if range_count == MAX_SCALAR_PREFIX_RANGES {
            return None;
        }
        plan.ranges[range_count] = ScalarPrefixRange {
            start: byte,
            end: byte,
        };
        range_count += 1;
    }
    plan.range_count = u8::try_from(range_count).ok()?;
    Some(plan)
}

fn cheapest_range_order(
    plan: ScalarPrefixRangePlan,
    costs: ScalarPrefixPredicateCosts,
    byte_weights: &[u16; 256],
    total_weight: u64,
) -> (ScalarPrefixRangePlan, u64) {
    let mut working = plan;
    let mut best = plan;
    let mut best_cost = range_cost_numerator(plan, costs, byte_weights, total_weight);
    search_range_orders(
        &mut working,
        0,
        costs,
        byte_weights,
        total_weight,
        &mut best,
        &mut best_cost,
    );
    (best, best_cost)
}

fn search_range_orders(
    working: &mut ScalarPrefixRangePlan,
    depth: usize,
    costs: ScalarPrefixPredicateCosts,
    byte_weights: &[u16; 256],
    total_weight: u64,
    best: &mut ScalarPrefixRangePlan,
    best_cost: &mut u64,
) {
    let count = usize::from(working.range_count);
    if depth == count {
        let cost = range_cost_numerator(*working, costs, byte_weights, total_weight);
        if cost < *best_cost || (cost == *best_cost && range_order(working, best) == Ordering::Less)
        {
            *best = *working;
            *best_cost = cost;
        }
        return;
    }
    for index in depth..count {
        working.ranges.swap(depth, index);
        search_range_orders(
            working,
            depth + 1,
            costs,
            byte_weights,
            total_weight,
            best,
            best_cost,
        );
        working.ranges.swap(depth, index);
    }
}

fn range_order(left: &ScalarPrefixRangePlan, right: &ScalarPrefixRangePlan) -> Ordering {
    left.ranges().cmp(right.ranges())
}

fn range_cost_numerator(
    plan: ScalarPrefixRangePlan,
    costs: ScalarPrefixPredicateCosts,
    byte_weights: &[u16; 256],
    total_weight: u64,
) -> u64 {
    let mut cost = total_weight * u64::from(costs.input_load_units);
    for byte in u8::MIN..=u8::MAX {
        cost +=
            u64::from(byte_weights[usize::from(byte)]) * range_membership_units(plan, byte, costs);
    }
    cost
}

fn range_membership_units(
    plan: ScalarPrefixRangePlan,
    byte: u8,
    costs: ScalarPrefixPredicateCosts,
) -> u64 {
    let mut units = 0_u64;
    for range in plan.ranges() {
        if range.is_singleton() {
            units += u64::from(costs.singleton_units);
            if byte == range.start {
                return units;
            }
        } else if byte < range.start {
            units += u64::from(costs.interval_below_units);
        } else {
            units += u64::from(costs.interval_at_or_above_units);
            if byte <= range.end {
                return units;
            }
        }
    }
    units + u64::from(costs.terminal_reject_units)
}

fn weighted_membership(words: [u64; 4], byte_weights: &[u16; 256]) -> u64 {
    let mut weight = 0_u64;
    for byte in u8::MIN..=u8::MAX {
        if mask_contains(words, byte) {
            weight += u64::from(byte_weights[usize::from(byte)]);
        }
    }
    weight
}

fn mask_cardinality(words: [u64; 4]) -> u16 {
    words
        .iter()
        .map(|word| u16::try_from(word.count_ones()).unwrap_or(u16::MAX))
        .sum()
}

fn mask_contains(words: [u64; 4], byte: u8) -> bool {
    let index = usize::from(byte);
    words[index / 64] & (1_u64 << (index % 64)) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words_from_predicate(mut predicate: impl FnMut(u8) -> bool) -> [u64; 4] {
        let mut words = [0_u64; 4];
        for byte in u8::MIN..=u8::MAX {
            if predicate(byte) {
                let index = usize::from(byte);
                words[index / 64] |= 1_u64 << (index % 64);
            }
        }
        words
    }

    fn one_plan(
        words: [u64; 4],
        costs: ScalarPrefixPredicateCosts,
        weights: &[u16; 256],
    ) -> ScalarPrefixPredicatePlan {
        let plan =
            plan_scalar_prefix_predicates(&[PrefixPredicateInput::new(0, words)], costs, weights)
                .expect("one valid predicate");
        *plan.predicates().first().expect("one selective predicate")
    }

    fn assert_exact(plan: ScalarPrefixPredicatePlan) {
        for byte in u8::MIN..=u8::MAX {
            assert_eq!(
                plan.accepts(byte),
                mask_contains(plan.words(), byte),
                "byte {byte} disagrees for {plan:?}"
            );
        }
    }

    #[test]
    fn every_contiguous_interval_is_exact_for_every_byte() {
        for start in u8::MIN..=u8::MAX {
            for end in start..=u8::MAX {
                if start == u8::MIN && end == u8::MAX {
                    continue;
                }
                let words = words_from_predicate(|byte| start <= byte && byte <= end);
                let plan = one_plan(
                    words,
                    AARCH64_SCALAR_PREFIX_COSTS,
                    &UNIFORM_PREFIX_BYTE_WEIGHTS,
                );
                assert_exact(plan);
                assert!(matches!(
                    plan.membership(),
                    ScalarPrefixMembership::Ranges(_)
                ));
            }
        }
    }

    #[test]
    fn every_fragment_shape_in_each_byte_block_is_exact() {
        for block in 0_u8..32 {
            let base = block * 8;
            for shape in 1_u16..=u16::from(u8::MAX) {
                let words = words_from_predicate(|byte| {
                    byte >= base
                        && byte.wrapping_sub(base) < 8
                        && shape & (1_u16 << u16::from(byte - base)) != 0
                });
                let plan = one_plan(
                    words,
                    AARCH64_SCALAR_PREFIX_COSTS,
                    &UNIFORM_PREFIX_BYTE_WEIGHTS,
                );
                assert_exact(plan);
                let runs = (0_u8..8)
                    .filter(|&bit| {
                        shape & (1_u16 << u16::from(bit)) != 0
                            && (bit == 0 || shape & (1_u16 << u16::from(bit - 1)) == 0)
                    })
                    .count();
                if runs > MAX_SCALAR_PREFIX_RANGES {
                    assert_eq!(plan.membership(), ScalarPrefixMembership::Bitmap256);
                }
            }
        }
    }

    #[test]
    fn range_order_is_globally_minimal_and_exact() {
        let words =
            words_from_predicate(|byte| matches!(byte, 1..=3 | 41..=79 | 130..=131 | 220..=250));
        let mut weights = [1_u16; 256];
        for byte in 220_u8..=250 {
            weights[usize::from(byte)] = 31;
        }
        let encoded = encode_exact_ranges(words).expect("four exact ranges");
        let total_weight = weights.iter().map(|&weight| u64::from(weight)).sum();
        let (selected, selected_cost) =
            cheapest_range_order(encoded, AARCH64_SCALAR_PREFIX_COSTS, &weights, total_weight);
        let mut working = encoded;
        let mut observed = Vec::new();
        collect_range_order_costs(
            &mut working,
            0,
            AARCH64_SCALAR_PREFIX_COSTS,
            &weights,
            total_weight,
            &mut observed,
        );
        assert_eq!(observed.len(), 24);
        assert!(observed.iter().all(|&cost| selected_cost <= cost));
        for byte in u8::MIN..=u8::MAX {
            assert_eq!(selected.accepts(byte), mask_contains(words, byte));
        }
    }

    fn collect_range_order_costs(
        working: &mut ScalarPrefixRangePlan,
        depth: usize,
        costs: ScalarPrefixPredicateCosts,
        weights: &[u16; 256],
        total_weight: u64,
        output: &mut Vec<u64>,
    ) {
        let count = usize::from(working.range_count);
        if depth == count {
            output.push(range_cost_numerator(*working, costs, weights, total_weight));
            return;
        }
        for index in depth..count {
            working.ranges.swap(depth, index);
            collect_range_order_costs(working, depth + 1, costs, weights, total_weight, output);
            working.ranges.swap(depth, index);
        }
    }

    #[test]
    fn target_costs_choose_ranges_only_when_strictly_cheaper() {
        let three_singletons = words_from_predicate(|byte| matches!(byte, b'Q' | b'x' | 0xf3));
        let aarch64 = one_plan(
            three_singletons,
            AARCH64_SCALAR_PREFIX_COSTS,
            &UNIFORM_PREFIX_BYTE_WEIGHTS,
        );
        let x86 = one_plan(
            three_singletons,
            X86_64_SCALAR_PREFIX_COSTS,
            &UNIFORM_PREFIX_BYTE_WEIGHTS,
        );
        assert!(matches!(
            aarch64.membership(),
            ScalarPrefixMembership::Ranges(_)
        ));
        assert_eq!(x86.membership(), ScalarPrefixMembership::Bitmap256);
        assert_exact(aarch64);
        assert_exact(x86);

        let five_runs = words_from_predicate(|byte| matches!(byte, 1 | 3 | 5 | 7 | 9));
        let fragmented = one_plan(
            five_runs,
            AARCH64_SCALAR_PREFIX_COSTS,
            &UNIFORM_PREFIX_BYTE_WEIGHTS,
        );
        assert_eq!(fragmented.membership(), ScalarPrefixMembership::Bitmap256);
        assert_exact(fragmented);
    }

    fn permute_inputs(
        values: &mut [PrefixPredicateInput],
        depth: usize,
        output: &mut Vec<Vec<PrefixPredicateInput>>,
    ) {
        if depth == values.len() {
            output.push(values.to_vec());
            return;
        }
        for index in depth..values.len() {
            values.swap(depth, index);
            permute_inputs(values, depth + 1, output);
            values.swap(depth, index);
        }
    }

    fn expected_conjunction_cost_numerator(
        predicates: &[ScalarPrefixPredicatePlan],
        total_weight: u64,
    ) -> u128 {
        let count = u32::try_from(predicates.len()).expect("small predicate count");
        let mut passing_product = 1_u128;
        let mut total = 0_u128;
        for (index, predicate) in predicates.iter().enumerate() {
            let remaining = count - u32::try_from(index + 1).expect("small index");
            total += passing_product
                * u128::from(predicate.evaluation_cost_numerator())
                * u128::from(total_weight).pow(remaining);
            passing_product *= u128::from(predicate.passing_weight());
        }
        total
    }

    #[test]
    fn every_input_order_has_one_stable_globally_minimal_conjunction_order() {
        let masks = [
            words_from_predicate(|byte| byte == b'Q'),
            words_from_predicate(|byte| byte.is_ascii_digit()),
            words_from_predicate(|byte| byte.is_ascii_alphabetic()),
            words_from_predicate(|byte| matches!(byte, 1 | 3 | 5 | 7 | 9)),
        ];
        let mut inputs = [
            PrefixPredicateInput::new(7, masks[0]),
            PrefixPredicateInput::new(2, masks[1]),
            PrefixPredicateInput::new(5, masks[2]),
            PrefixPredicateInput::new(1, masks[3]),
        ];
        let mut permutations = Vec::new();
        permute_inputs(&mut inputs, 0, &mut permutations);
        assert_eq!(permutations.len(), 24);

        let reference = plan_scalar_prefix_predicates(
            &permutations[0],
            AARCH64_SCALAR_PREFIX_COSTS,
            &UNIFORM_PREFIX_BYTE_WEIGHTS,
        )
        .expect("reference plan");
        let reference_positions = reference
            .predicates()
            .iter()
            .map(|predicate| predicate.position())
            .collect::<Vec<_>>();
        for permutation in &permutations {
            let plan = plan_scalar_prefix_predicates(
                permutation,
                AARCH64_SCALAR_PREFIX_COSTS,
                &UNIFORM_PREFIX_BYTE_WEIGHTS,
            )
            .expect("permuted plan");
            assert_eq!(
                plan.predicates()
                    .iter()
                    .map(|predicate| predicate.position())
                    .collect::<Vec<_>>(),
                reference_positions
            );
            for predicate in plan.predicates() {
                assert_exact(*predicate);
            }

            let selected_cost =
                expected_conjunction_cost_numerator(plan.predicates(), plan.total_weight());
            let mut planned_permutations = Vec::new();
            let mut planned_inputs = plan.predicates().to_vec();
            permute_predicate_plans(&mut planned_inputs, 0, &mut planned_permutations);
            assert!(planned_permutations.iter().all(|order| {
                selected_cost <= expected_conjunction_cost_numerator(order, plan.total_weight())
            }));
        }
    }

    fn permute_predicate_plans(
        values: &mut [ScalarPrefixPredicatePlan],
        depth: usize,
        output: &mut Vec<Vec<ScalarPrefixPredicatePlan>>,
    ) {
        if depth == values.len() {
            output.push(values.to_vec());
            return;
        }
        for index in depth..values.len() {
            values.swap(depth, index);
            permute_predicate_plans(values, depth + 1, output);
            values.swap(depth, index);
        }
    }

    #[test]
    fn conjunction_semantics_are_exhaustive_over_truth_vectors_and_orders() {
        let predicate_count = 8_usize;
        let mut order =
            (0_u8..u8::try_from(predicate_count).expect("small count")).collect::<Vec<_>>();
        let mut orders = Vec::new();
        permute_u8(&mut order, 0, &mut orders);
        assert_eq!(orders.len(), 40_320);
        for truth_bits in 0_u16..(1_u16 << predicate_count) {
            let expected = truth_bits == (1_u16 << predicate_count) - 1;
            for candidate_order in &orders {
                let observed = candidate_order
                    .iter()
                    .all(|&index| truth_bits & (1_u16 << u16::from(index)) != 0);
                assert_eq!(observed, expected);
            }
        }
    }

    fn permute_u8(values: &mut [u8], depth: usize, output: &mut Vec<Vec<u8>>) {
        if depth == values.len() {
            output.push(values.to_vec());
            return;
        }
        for index in depth..values.len() {
            values.swap(depth, index);
            permute_u8(values, depth + 1, output);
            values.swap(depth, index);
        }
    }

    #[test]
    fn wildcard_empty_and_checked_input_contracts_are_explicit() {
        let wildcard = PrefixPredicateInput::new(0, [u64::MAX; 4]);
        let empty = PrefixPredicateInput::new(1, [0; 4]);
        let plan = plan_scalar_prefix_predicates(
            &[wildcard, empty],
            AARCH64_SCALAR_PREFIX_COSTS,
            &UNIFORM_PREFIX_BYTE_WEIGHTS,
        )
        .expect("wildcard and empty plan");
        assert_eq!(plan.predicates().len(), 1);
        assert_eq!(
            plan.predicates()[0].membership(),
            ScalarPrefixMembership::RejectAll
        );
        assert_eq!(plan.bitmap_count(), 0);

        assert_eq!(
            plan_scalar_prefix_predicates(
                &[wildcard, wildcard],
                AARCH64_SCALAR_PREFIX_COSTS,
                &UNIFORM_PREFIX_BYTE_WEIGHTS,
            ),
            Err(ScalarPrefixPlanError::DuplicatePosition)
        );
        assert_eq!(
            plan_scalar_prefix_predicates(
                &[PrefixPredicateInput::new(0, [0; 4]); MAX_SCALAR_PREFIX_PREDICATES + 1],
                AARCH64_SCALAR_PREFIX_COSTS,
                &UNIFORM_PREFIX_BYTE_WEIGHTS,
            ),
            Err(ScalarPrefixPlanError::TooManyPredicates)
        );
        assert_eq!(
            plan_scalar_prefix_predicates(&[empty], AARCH64_SCALAR_PREFIX_COSTS, &[0; 256],),
            Err(ScalarPrefixPlanError::ZeroTotalByteWeight)
        );
    }
}
