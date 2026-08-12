//! Target-neutral selection for SIMD skipping inside completed DFA states.
//!
//! The determinizer exposes exact per-state self-loop masks derived from the
//! finalized transition table. This pass selects at most two non-initial loops
//! whose *exit* bytes have a compact SIMD representation.
//! Keeping two plans bounds the dispatch tax on every ordinary DFA iteration;
//! target lowering may scan a run of loop bytes with SSE2, AVX2, AVX-512BW,
//! ASIMD, SVE, or SVE2 and resume the ordinary transition loop at the first
//! exit byte.

#![allow(
    dead_code,
    reason = "the target-neutral loop plan is staged for native lowering"
)]

use crate::{
    byte_frequency::{BYTE_FREQUENCY_DENOMINATOR, estimated_byte_frequency_units},
    dfa::{NativeDfaSelfLoopSkipPlan, NativeDfaView, NativeSelfLoopAcceptance},
    program::OutputContract,
};

/// The scalar dispatcher admits a fixed, architecture-independent number of
/// graph-proven rows. Two comparisons cover another hot interior loop while
/// bounding emitted text and the miss cost for every ordinary DFA state.
pub(crate) const MAX_SELECTED_DFA_LOOP_SKIP_PLANS: usize = 2;

/// The existing byte-comparison lowerings reserve at most eight vector
/// constants. Four intervals fit that budget even when every interval needs
/// an inclusive-low and inclusive-high constant.
pub(crate) const MAX_DFA_LOOP_EXIT_RANGES: usize = 4;
/// Constants one loop probe may reserve without overlapping the x86 shared
/// candidate aggregate (`xmm/ymm5`) and range scratch (`xmm/ymm10..11`).
pub(crate) const MAX_DFA_LOOP_VECTOR_CONSTANTS: u8 = 4;

/// Exit sets broader than this have a uniform expected run shorter than four
/// bytes. Paying a state dispatch and vector probe for such a loop is not a
/// target-independent win. The limit is deliberately shared with native
/// start filtering and is based only on the completed transition graph.
const MAX_DFA_LOOP_EXIT_BYTES: u16 = 64;
/// A second row comparison is admitted only when the stable frequency model
/// also predicts a run of at least four bytes. The primary retains the older
/// cardinality-only policy for compatibility.
const MAX_SECONDARY_DFA_LOOP_EXIT_FREQUENCY_UNITS: u16 = 64;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DfaLoopExitRange {
    pub(crate) start: u8,
    pub(crate) end: u8,
}

/// One exact, graph-derived interior-loop optimization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DfaLoopSkipPlan {
    /// Semantic DFA state whose table row owns the self-loop.
    pub(crate) state: u32,
    /// Whether every skipped transition accepts at its consumed end.
    pub(crate) accepting: bool,
    exit_ranges: [DfaLoopExitRange; MAX_DFA_LOOP_EXIT_RANGES],
    exit_range_count: u8,
    /// Number of bytes that leave the selected self-loop.
    pub(crate) exit_byte_count: u16,
    /// Stable target-neutral frequency mass of the exact exit set.
    pub(crate) exit_frequency_units: u16,
    /// Number of vector constants required by a compare-based lowering.
    pub(crate) vector_constant_count: u8,
}

impl DfaLoopSkipPlan {
    #[must_use]
    pub(crate) fn ranges(&self) -> &[DfaLoopExitRange] {
        &self.exit_ranges[..usize::from(self.exit_range_count)]
    }

    #[must_use]
    pub(crate) fn exits_on(&self, byte: u8) -> bool {
        self.ranges()
            .iter()
            .any(|range| range.start <= byte && byte <= range.end)
    }

    #[must_use]
    pub(crate) fn is_exact(&self) -> bool {
        self.ranges().iter().all(|range| range.start == range.end)
    }
}

/// Select up to two profitable interior self-loops from the complete forward
/// table.
///
/// Soundness comes entirely from
/// [`NativeDfaView::visit_self_loop_skip_plans`]. The selected membership
/// contains all and only bytes whose transition returns to the same state with
/// one uniform acceptance behavior. The encoded complement therefore
/// identifies the exact byte at which target code must re-enter the ordinary
/// transition loop. Accepting loops are useful for end-selecting contracts,
/// where lowering updates the pending end after a skipped run. `Exists`
/// declines them because its ordinary first accepting transition already
/// returns. A non-accepting initial loop remains the responsibility of native
/// start-state acceleration unless the DFA is initially nullable (which
/// disables that optimization); accepting initial loops are not equivalent to
/// start filtering and remain eligible.
#[must_use]
pub(crate) fn select_dfa_loop_skips(
    view: &NativeDfaView<'_>,
    output: OutputContract,
) -> [Option<DfaLoopSkipPlan>; MAX_SELECTED_DFA_LOOP_SKIP_PLANS] {
    let mut primary = None;
    // Keep the best secondary-ranked plan for each of the best two distinct
    // states. Once the final primary is known, one of these is necessarily the
    // globally best frequency-eligible plan owned by another state.
    let mut secondary_by_state: [Option<DfaLoopSkipPlan>; 2] = [None; 2];
    let analysis = view.visit_self_loop_skip_plans(|candidate| {
        let Some(plan) = eligible_plan(candidate, view.initial_state, view.initial_pending, output)
        else {
            return;
        };
        if primary
            .is_none_or(|current| primary_selection_key(plan) < primary_selection_key(current))
        {
            primary = Some(plan);
        }
        if plan.exit_frequency_units <= MAX_SECONDARY_DFA_LOOP_EXIT_FREQUENCY_UNITS {
            consider_secondary_candidate(&mut secondary_by_state, plan);
        }
    });
    if analysis.is_none() {
        return [None; MAX_SELECTED_DFA_LOOP_SKIP_PLANS];
    }
    let Some(primary) = primary else {
        return [None; MAX_SELECTED_DFA_LOOP_SKIP_PLANS];
    };
    // A row guard cannot distinguish two acceptance subsets owned by one
    // semantic state. Preserve the incumbent primary plan byte-for-byte, then
    // spend the additional bounded dispatch slot on another state.
    let secondary = secondary_by_state
        .into_iter()
        .flatten()
        .find(|plan| plan.state != primary.state);
    [Some(primary), secondary]
}

fn eligible_plan(
    candidate: NativeDfaSelfLoopSkipPlan,
    initial_state: u32,
    initial_pending: bool,
    output: OutputContract,
) -> Option<DfaLoopSkipPlan> {
    if (candidate.state == initial_state
        && candidate.acceptance == NativeSelfLoopAcceptance::NonAccepting
        && !initial_pending)
        || (candidate.acceptance == NativeSelfLoopAcceptance::Accepting
            && output == OutputContract::Exists)
        || candidate.complement_cardinality == 0
        || candidate.complement_cardinality > MAX_DFA_LOOP_EXIT_BYTES
    {
        return None;
    }
    let plan = encode_exit_ranges(
        candidate.state,
        candidate.acceptance == NativeSelfLoopAcceptance::Accepting,
        candidate.complement.words,
        candidate.complement_cardinality,
    )?;
    (plan.vector_constant_count <= MAX_DFA_LOOP_VECTOR_CONSTANTS).then_some(plan)
}

fn consider_secondary_candidate(ranked: &mut [Option<DfaLoopSkipPlan>; 2], plan: DfaLoopSkipPlan) {
    if let Some(same_state) = ranked
        .iter()
        .position(|current| current.is_some_and(|current| current.state == plan.state))
    {
        let Some(current) = ranked[same_state] else {
            return;
        };
        if secondary_selection_key(current) <= secondary_selection_key(plan) {
            return;
        }
        ranked[same_state] = None;
        if same_state == 0 {
            ranked[0] = ranked[1];
            ranked[1] = None;
        }
    }

    if ranked[0]
        .is_none_or(|current| secondary_selection_key(plan) < secondary_selection_key(current))
    {
        ranked[1] = ranked[0];
        ranked[0] = Some(plan);
    } else if ranked[1]
        .is_none_or(|current| secondary_selection_key(plan) < secondary_selection_key(current))
    {
        ranked[1] = Some(plan);
    }
}

/// Compatibility wrapper for callers and tests that need only the best plan.
#[must_use]
pub(crate) fn select_dfa_loop_skip(
    view: &NativeDfaView<'_>,
    output: OutputContract,
) -> Option<DfaLoopSkipPlan> {
    select_dfa_loop_skips(view, output)[0]
}

/// Preserve the incumbent single-loop ranking exactly. This makes adding a
/// second dispatch slot incapable of perturbing the previously emitted loop.
const fn primary_selection_key(plan: DfaLoopSkipPlan) -> (u16, bool, u8, u32) {
    (
        plan.exit_byte_count,
        plan.accepting,
        plan.vector_constant_count,
        plan.state,
    )
}

/// Rank only the additional loop by an architecture-neutral estimate of work
/// left in its vector run. Lower stable exit-frequency mass predicts longer
/// runs; the remaining fields make object output deterministic.
const fn secondary_selection_key(plan: DfaLoopSkipPlan) -> (u16, u16, bool, u8, u32) {
    (
        plan.exit_frequency_units,
        plan.exit_byte_count,
        plan.accepting,
        plan.vector_constant_count,
        plan.state,
    )
}

fn encode_exit_ranges(
    state: u32,
    accepting: bool,
    words: [u64; 4],
    exit_byte_count: u16,
) -> Option<DfaLoopSkipPlan> {
    let mut ranges = [DfaLoopExitRange::default(); MAX_DFA_LOOP_EXIT_RANGES];
    let mut range_count = 0_usize;
    let mut exit_frequency_units = 0_u16;
    for byte in u8::MIN..=u8::MAX {
        if !mask_contains(words, byte) {
            continue;
        }
        exit_frequency_units = exit_frequency_units
            .saturating_add(estimated_byte_frequency_units(byte))
            .min(BYTE_FREQUENCY_DENOMINATOR);
        if let Some(last) = range_count
            .checked_sub(1)
            .and_then(|index| ranges.get_mut(index))
            && last.end.checked_add(1) == Some(byte)
        {
            last.end = byte;
            continue;
        }
        if range_count == MAX_DFA_LOOP_EXIT_RANGES {
            return None;
        }
        ranges[range_count] = DfaLoopExitRange {
            start: byte,
            end: byte,
        };
        range_count = range_count.checked_add(1)?;
    }
    if range_count == 0 {
        return None;
    }
    let exact = ranges[..range_count]
        .iter()
        .all(|range| range.start == range.end);
    let constant_count = if exact {
        range_count
    } else {
        range_count.checked_mul(2)?
    };
    Some(DfaLoopSkipPlan {
        state,
        accepting,
        exit_ranges: ranges,
        exit_range_count: u8::try_from(range_count).ok()?,
        exit_byte_count,
        exit_frequency_units,
        vector_constant_count: u8::try_from(constant_count).ok()?,
    })
}

fn mask_contains(words: [u64; 4], byte: u8) -> bool {
    let byte = usize::from(byte);
    words[byte / 64] & (1_u64 << (byte % 64)) != 0
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "bounded independent model and bitmap-oracle arithmetic"
)]
mod tests {
    use super::{
        DfaLoopSkipPlan, MAX_DFA_LOOP_EXIT_RANGES, MAX_DFA_LOOP_VECTOR_CONSTANTS,
        consider_secondary_candidate, eligible_plan, encode_exit_ranges, mask_contains,
        primary_selection_key, secondary_selection_key, select_dfa_loop_skip,
        select_dfa_loop_skips,
    };
    use crate::dfa::{ForwardCell, NativeDfaSelfLoopSkipPlan, NativeDfaView, forward_cell};
    use crate::{CompileMode, CompileRequest, OutputContract, Target, compile};

    const NO_STATE: u32 = u32::MAX;

    fn next_random(mut state: u64) -> u64 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }

    fn two_state_view<'a>(
        byte_classes: &'a [u8; 256],
        representatives: &'a [u8],
        cells: &'a [ForwardCell],
    ) -> NativeDfaView<'a> {
        NativeDfaView {
            initial_state: 0,
            initial_pending: false,
            initial_terminal: false,
            byte_classes,
            class_count: representatives.len(),
            class_representatives: representatives,
            forward_cells: cells,
            reverse_initial: None,
            reverse_cells: &[],
        }
    }

    fn legacy_select_dfa_loop_skips(
        view: &NativeDfaView<'_>,
        output: OutputContract,
    ) -> [Option<DfaLoopSkipPlan>; 2] {
        const LEGACY_STRUCTURAL_CAP: usize = 16;

        let mut candidates = Vec::<NativeDfaSelfLoopSkipPlan>::new();
        if view
            .visit_self_loop_skip_plans(|candidate| candidates.push(candidate))
            .is_none()
        {
            return [None; 2];
        }
        candidates.sort_by(|left, right| {
            right
                .membership_cardinality
                .cmp(&left.membership_cardinality)
                .then_with(|| left.acceptance.cmp(&right.acceptance))
                .then_with(|| left.state.cmp(&right.state))
        });
        candidates.truncate(LEGACY_STRUCTURAL_CAP);

        let eligible = candidates
            .into_iter()
            .filter_map(|candidate| {
                eligible_plan(candidate, view.initial_state, view.initial_pending, output)
            })
            .collect::<Vec<_>>();
        let mut primary = None;
        for &plan in &eligible {
            if primary
                .is_none_or(|current| primary_selection_key(plan) < primary_selection_key(current))
            {
                primary = Some(plan);
            }
        }
        let Some(primary) = primary else {
            return [None; 2];
        };
        let mut secondary = None;
        for &plan in &eligible {
            if plan.state == primary.state
                || plan.exit_frequency_units > super::MAX_SECONDARY_DFA_LOOP_EXIT_FREQUENCY_UNITS
            {
                continue;
            }
            if secondary.is_none_or(|current| {
                secondary_selection_key(plan) < secondary_selection_key(current)
            }) {
                secondary = Some(plan);
            }
        }
        [Some(primary), secondary]
    }

    fn semantic_cell(view: &NativeDfaView<'_>, state: u32, byte: u8) -> ForwardCell {
        let class = usize::from(view.byte_classes[usize::from(byte)]);
        let state = usize::try_from(state).expect("test state");
        view.forward_cells[state * view.class_count + class]
    }

    fn assert_plan_exact(view: &NativeDfaView<'_>, plan: &DfaLoopSkipPlan) {
        for byte in u8::MIN..=u8::MAX {
            let cell = semantic_cell(view, plan.state, byte);
            let semantic_exit = cell.next() != plan.state || cell.accepted() != plan.accepting;
            assert_eq!(
                plan.exits_on(byte),
                semantic_exit,
                "byte {byte} disagrees with the completed DFA row"
            );
        }
    }

    #[test]
    fn compact_nonaccepting_interior_loop_is_selected_exactly() {
        let mut classes = [0_u8; 256];
        classes[usize::from(b'Q')] = 1;
        classes[usize::from(b'Z')] = 2;
        let representatives = [0, b'Q', b'Z'];
        let cells = [
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: true,
            },
        ];
        let view = two_state_view(&classes, &representatives, &cells);
        let plan =
            select_dfa_loop_skip(&view, OutputContract::Exists).expect("interior 254-byte loop");
        assert_eq!(plan.state, 1);
        assert_eq!(plan.exit_byte_count, 2);
        assert_eq!(plan.vector_constant_count, 2);
        assert!(plan.is_exact());
        assert_eq!(
            plan.ranges()
                .iter()
                .map(|range| (range.start, range.end))
                .collect::<Vec<_>>(),
            vec![(b'Q', b'Q'), (b'Z', b'Z')]
        );
        assert_plan_exact(&view, &plan);
    }

    #[test]
    fn second_row_uses_frequency_without_perturbing_incumbent_primary() {
        let mut classes = [0_u8; 256];
        classes[usize::from(b'e')] = 1;
        classes[usize::from(b'Q')] = 2;
        classes[usize::from(b'Z')] = 3;
        let representatives = [0, b'e', b'Q', b'Z'];
        let cells = [
            forward_cell! { next: 0, accepted: false },
            forward_cell! { next: 1, accepted: false },
            forward_cell! { next: 2, accepted: false },
            forward_cell! { next: NO_STATE, accepted: false },
            forward_cell! { next: 1, accepted: false },
            forward_cell! { next: 2, accepted: false },
            forward_cell! { next: 1, accepted: false },
            forward_cell! { next: 1, accepted: false },
            forward_cell! { next: 2, accepted: false },
            forward_cell! { next: 2, accepted: false },
            forward_cell! { next: 1, accepted: false },
            forward_cell! { next: 2, accepted: false },
        ];
        let view = two_state_view(&classes, &representatives, &cells);
        let [first, second] = select_dfa_loop_skips(&view, OutputContract::Exists);
        let first = first.expect("incumbent cardinality-ranked loop");
        let second = second.expect("frequency-ranked additional loop");
        assert_eq!((first.state, second.state), (1, 2));
        assert_eq!(first.exit_byte_count, second.exit_byte_count);
        assert!(second.exit_frequency_units < first.exit_frequency_units);
        assert_plan_exact(&view, &first);
        assert_plan_exact(&view, &second);
    }

    #[test]
    fn accepting_rows_cannot_crowd_out_a_later_exists_loop() {
        let states = 17_usize;
        let mut classes = [0_u8; 256];
        classes[usize::from(b'Q')] = 1;
        let representatives = [0, b'Q'];
        let mut cells = Vec::with_capacity(states.checked_mul(2).expect("small table"));
        for state in 0..states.saturating_sub(1) {
            let state = u32::try_from(state).expect("small state");
            cells.extend([
                forward_cell! { next: state, accepted: true },
                forward_cell! { next: state, accepted: true },
            ]);
        }
        let late = u32::try_from(states.saturating_sub(1)).expect("small state");
        cells.extend([
            forward_cell! { next: late, accepted: false },
            forward_cell! { next: NO_STATE, accepted: false },
        ]);
        let view = two_state_view(&classes, &representatives, &cells);

        let plan = select_dfa_loop_skip(&view, OutputContract::Exists)
            .expect("later non-accepting row survives accepting-row crowd");
        assert_eq!(plan.state, late);
        assert_eq!(plan.exit_byte_count, 1);
        assert_eq!(
            plan.ranges(),
            &[super::DfaLoopExitRange {
                start: b'Q',
                end: b'Q'
            }]
        );
        assert_plan_exact(&view, &plan);
    }

    #[test]
    fn fragmented_rows_cannot_crowd_out_a_later_encodable_loop() {
        let states = 17_usize;
        let fragmented = [1_u8, 3, 5, 7, 9];
        let mut classes = [0_u8; 256];
        for (index, byte) in fragmented.into_iter().enumerate() {
            classes[usize::from(byte)] =
                u8::try_from(index.saturating_add(1)).expect("six test classes");
        }
        classes[20..=25].fill(6);
        let representatives = [0, 1, 3, 5, 7, 9, 20];
        let mut cells = Vec::with_capacity(states.checked_mul(7).expect("small table"));
        for state in 0..states.saturating_sub(1) {
            let state = u32::try_from(state).expect("small state");
            cells.push(forward_cell! { next: state, accepted: false });
            cells.extend((0..5).map(|_| forward_cell! { next: NO_STATE, accepted: false }));
            cells.push(forward_cell! { next: state, accepted: false });
        }
        let late = u32::try_from(states.saturating_sub(1)).expect("small state");
        cells.extend((0..6).map(|_| forward_cell! { next: late, accepted: false }));
        cells.push(forward_cell! { next: NO_STATE, accepted: false });
        let view = two_state_view(&classes, &representatives, &cells);

        let plan = select_dfa_loop_skip(&view, OutputContract::SelectedEnd)
            .expect("later compact row survives fragmented-row crowd");
        assert_eq!(plan.state, late);
        assert_eq!(plan.exit_byte_count, 6);
        assert_eq!(
            plan.ranges(),
            &[super::DfaLoopExitRange { start: 20, end: 25 }]
        );
        assert_plan_exact(&view, &plan);
    }

    #[test]
    fn secondary_leaderboard_keeps_the_best_two_distinct_states() {
        let plan = |state, frequency| DfaLoopSkipPlan {
            state,
            accepting: false,
            exit_ranges: [super::DfaLoopExitRange::default(); MAX_DFA_LOOP_EXIT_RANGES],
            exit_range_count: 1,
            exit_byte_count: 1,
            exit_frequency_units: frequency,
            vector_constant_count: 1,
        };
        let mut ranked = [None; 2];
        for candidate in [plan(1, 10), plan(2, 20), plan(1, 5), plan(3, 15)] {
            consider_secondary_candidate(&mut ranked, candidate);
        }
        assert_eq!(ranked[0].map(|candidate| candidate.state), Some(1));
        assert_eq!(
            ranked[0].map(|candidate| candidate.exit_frequency_units),
            Some(5)
        );
        assert_eq!(ranked[1].map(|candidate| candidate.state), Some(3));
        assert_eq!(
            ranked[1].map(|candidate| candidate.exit_frequency_units),
            Some(15)
        );
    }

    #[test]
    fn uncrowded_selector_is_identical_to_the_legacy_structural_prefilter() {
        let mut random = 0x243f_6a88_85a3_08d3_u64;
        for _ in 0..256 {
            random = next_random(random);
            let states = usize::try_from(random % 8 + 1).expect("small state count");
            random = next_random(random);
            let class_count = usize::try_from(random % 8 + 1).expect("small class count");
            let mut classes = [0_u8; 256];
            for (byte, class) in classes.iter_mut().enumerate() {
                *class = u8::try_from(byte % class_count).expect("at most eight classes");
            }
            let representatives = (0..class_count)
                .map(|class| u8::try_from(class).expect("at most eight classes"))
                .collect::<Vec<_>>();
            let mut cells = Vec::with_capacity(
                states
                    .checked_mul(class_count)
                    .expect("small generated table"),
            );
            for _ in 0..states {
                for _ in 0..class_count {
                    random = next_random(random);
                    let next = if random % 5 == 0 {
                        NO_STATE
                    } else {
                        u32::try_from(random % u64::try_from(states).expect("small states"))
                            .expect("small state")
                    };
                    random = next_random(random);
                    cells.push(forward_cell! {
                        next,
                        accepted: random & 1 != 0,
                    });
                }
            }
            let mut view = two_state_view(&classes, &representatives, &cells);
            random = next_random(random);
            view.initial_pending = random & 1 != 0;
            for output in [
                OutputContract::Exists,
                OutputContract::SelectedEnd,
                OutputContract::Span,
            ] {
                assert_eq!(
                    select_dfa_loop_skips(&view, output),
                    legacy_select_dfa_loop_skips(&view, output),
                    "uncrowded selection changed for {states} states and {class_count} classes"
                );
            }
        }
    }

    #[test]
    fn completed_general_compilation_exposes_interior_loop_plan() {
        let compiled = compile(
            CompileRequest::new("A(?-u:[^Z])*Z", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Exists),
        )
        .expect("general optimizing compilation");
        let view = compiled
            .program()
            .native_dfa_view()
            .expect("completed ordered DFA");
        let plan = select_dfa_loop_skip(&view.dfa, OutputContract::Exists)
            .expect("graph-derived interior loop");
        assert_eq!(plan.exit_byte_count, 1);
        assert_eq!(plan.ranges()[0].start, b'Z');
        assert_eq!(plan.ranges()[0].end, b'Z');
        assert_plan_exact(&view.dfa, &plan);

        let nullable = compile(
            CompileRequest::new("(?-u:[^Z]*)", Target::x86_64_linux())
                .mode(CompileMode::Optimizing)
                .output(OutputContract::Span),
        )
        .expect("nullable general optimizing compilation");
        let nullable_view = nullable
            .program()
            .native_dfa_view()
            .expect("nullable completed ordered DFA");
        let nullable_plan = select_dfa_loop_skip(&nullable_view.dfa, OutputContract::Span)
            .expect("accepting initial loop");
        assert!(nullable_plan.accepting);
        assert_eq!(nullable_plan.state, nullable_view.dfa.initial_state);
        assert_plan_exact(&nullable_view.dfa, &nullable_plan);
    }

    #[test]
    fn accepting_self_loop_is_selected_only_for_end_contracts() {
        let mut classes = [0_u8; 256];
        classes[usize::from(b'X')] = 1;
        let representatives = [0, b'X'];
        let cells = [
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: true,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
        ];
        let view = two_state_view(&classes, &representatives, &cells);
        assert!(select_dfa_loop_skip(&view, OutputContract::Exists).is_none());
        let selected = select_dfa_loop_skip(&view, OutputContract::SelectedEnd)
            .expect("selected-end accepting loop");
        assert!(selected.accepting);
        assert_plan_exact(&view, &selected);
        for bits in 0_u16..=255 {
            let mut haystack = [0_u8; 8];
            for (index, byte) in haystack.iter_mut().enumerate() {
                if bits & (1_u16 << index) != 0 {
                    *byte = b'X';
                }
            }
            assert_eq!(
                skipped_trace(&view, &selected, &haystack),
                baseline_trace(&view, &haystack)
            );
        }
    }

    #[test]
    fn fragmented_or_dense_exit_sets_decline() {
        let mut fragmented = [0_u64; 4];
        for byte in [1_u8, 3, 5, 7, 9] {
            fragmented[usize::from(byte) / 64] |= 1_u64 << (usize::from(byte) % 64);
        }
        assert!(encode_exit_ranges(1, false, fragmented, 5).is_none());

        let dense = [u64::MAX; 4];
        // Range encoding itself is exact; density is a separate selection
        // policy applied before it reaches target lowering.
        let encoded = encode_exit_ranges(1, false, dense, 256).expect("one dense interval");
        assert_eq!(encoded.ranges().len(), 1);
        assert_eq!(encoded.ranges()[0].start, 0);
        assert_eq!(encoded.ranges()[0].end, 255);
        assert_eq!(MAX_DFA_LOOP_EXIT_RANGES, 4);
        assert_eq!(MAX_DFA_LOOP_VECTOR_CONSTANTS, 4);

        let mut classes = [0_u8; 256];
        classes[1..=2].fill(1);
        classes[4..=5].fill(2);
        classes[7..=8].fill(3);
        let representatives = [0, 1, 4, 7];
        let cells = [
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: false,
            },
        ];
        let view = two_state_view(&classes, &representatives, &cells);
        assert!(
            select_dfa_loop_skip(&view, OutputContract::SelectedEnd).is_none(),
            "three range intervals need six constants and alias x86 scratch registers"
        );
    }

    #[test]
    fn range_encoding_matches_independent_bitmap_oracle_for_all_lanes() {
        let mut state = 0x243f_6a88_85a3_08d3_u64;
        for _ in 0..512 {
            let mut words = [0_u64; 4];
            for _ in 0..4 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let start = u8::try_from(state & 255).expect("reduced byte");
                let width = u8::try_from((state >> 8) & 15).expect("reduced width");
                let end = start.saturating_add(width);
                for byte in start..=end {
                    words[usize::from(byte) / 64] |= 1_u64 << (usize::from(byte) % 64);
                }
            }
            let count = words
                .iter()
                .map(|word| word.count_ones())
                .sum::<u32>()
                .try_into()
                .expect("bitmap cardinality");
            let Some(plan) = encode_exit_ranges(7, false, words, count) else {
                continue;
            };
            for byte in u8::MIN..=u8::MAX {
                assert_eq!(plan.exits_on(byte), mask_contains(words, byte));
            }
        }
    }

    fn baseline_trace(view: &NativeDfaView<'_>, haystack: &[u8]) -> (u32, Option<usize>) {
        let mut state = view.initial_state;
        let mut accepted = None;
        for (position, &byte) in haystack.iter().enumerate() {
            let cell = semantic_cell(view, state, byte);
            if cell.accepted() {
                accepted = position.checked_add(1);
            }
            if cell.next() == NO_STATE {
                break;
            }
            state = cell.next();
        }
        (state, accepted)
    }

    fn skipped_trace(
        view: &NativeDfaView<'_>,
        plan: &DfaLoopSkipPlan,
        haystack: &[u8],
    ) -> (u32, Option<usize>) {
        let mut state = view.initial_state;
        let mut accepted = None;
        let mut position = 0_usize;
        while position < haystack.len() {
            if state == plan.state {
                while position < haystack.len() && !plan.exits_on(haystack[position]) {
                    // This is the independent optimized transformation: it
                    // does not consult a transition cell for a skipped byte.
                    position = position.checked_add(1).expect("small trace");
                    if plan.accepting {
                        accepted = Some(position);
                    }
                }
                if position == haystack.len() {
                    break;
                }
            }
            let cell = semantic_cell(view, state, haystack[position]);
            position = position.checked_add(1).expect("small trace");
            if cell.accepted() {
                accepted = Some(position);
            }
            if cell.next() == NO_STATE {
                break;
            }
            state = cell.next();
        }
        (state, accepted)
    }

    #[test]
    fn randomized_skip_trace_matches_scalar_dfa_trace() {
        let mut classes = [0_u8; 256];
        classes[usize::from(b'A')] = 1;
        classes[usize::from(b'Q')] = 2;
        classes[usize::from(b'Z')] = 3;
        let representatives = [0, b'A', b'Q', b'Z'];
        let cells = [
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: 1,
                accepted: false,
            },
            forward_cell! {
                next: 0,
                accepted: false,
            },
            forward_cell! {
                next: NO_STATE,
                accepted: true,
            },
        ];
        let view = two_state_view(&classes, &representatives, &cells);
        let plan =
            select_dfa_loop_skip(&view, OutputContract::SelectedEnd).expect("broad state-one loop");
        assert_plan_exact(&view, &plan);

        let mut random = 0x1319_8a2e_0370_7345_u64;
        for length in 0..=257 {
            for _ in 0..32 {
                let mut haystack = vec![0_u8; length];
                for byte in &mut haystack {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    *byte = u8::try_from(random & 255).expect("reduced byte");
                }
                assert_eq!(
                    skipped_trace(&view, &plan, &haystack),
                    baseline_trace(&view, &haystack)
                );
            }
        }
    }
}
