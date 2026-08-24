//! Ordinary-only acceleration for a narrow ASCII-folded literal alternation.
//!
//! The canonical finite-language owner remains authoritative for every
//! checked, accounted, iterator, capture and session surface. This sidecar is
//! admitted only from the exact root HIR shape below and serves the two
//! unmetered convenience facades.

use core::mem::size_of;

use fre_exact_alloc::{CopyError, try_box_preserve};
use fre_kernels::{
    FoldedLiteral, FoldedLiteralTrieBuildAttempt, FoldedLiteralTrieBuildError,
    FoldedLiteralTrieBuildLimits, FoldedLiteralTriePlan, FoldedLiteralTrieScanAttemptError,
    FoldedLiteralTrieScanError, FoldedLiteralTrieScanLimits, FoldedScalarClass, LiteralSetError,
    SimdDispatchContext, Window, folded_literal_trie_build_requirements_from_dimensions,
};
use regex_syntax::hir::{Class, Hir, HirKind};

use crate::BuildError;

const BRANCHES: usize = 4;
const MIN_WIDTH: usize = 2;
const MAX_WIDTH: usize = 8;
const ASCII_CASE_RANGES: usize = 2;
const MATERIALIZED_CLASS_SLOTS: usize = BRANCHES * MAX_WIDTH;
pub(crate) const MIN_FULL_INPUT_BYTES: usize = 4_096;

#[derive(Debug)]
pub(crate) struct OrdinaryPlan {
    trie: FoldedLiteralTriePlan,
}

pub(crate) struct BuildAttempt {
    pub(crate) plan: Option<Box<OrdinaryPlan>>,
    pub(crate) planner_work: u64,
    pub(crate) storage_bytes: usize,
}

impl BuildAttempt {
    const fn declined(planner_work: u64) -> Self {
        Self {
            plan: None,
            planner_work,
            storage_bytes: 0,
        }
    }
}

impl OrdinaryPlan {
    pub(crate) const fn supports_full_input(input_bytes: usize) -> bool {
        input_bytes >= MIN_FULL_INPUT_BYTES
    }

    pub(crate) fn is_match_full_value(&self, haystack: &[u8]) -> Result<bool, LiteralSetError> {
        self.trie
            .is_match_window_value(
                haystack,
                Window::full(haystack),
                FoldedLiteralTrieScanLimits::unlimited(),
            )
            .map_err(map_scan_error)
    }

    pub(crate) fn find_full_value(
        &self,
        haystack: &[u8],
    ) -> Result<Option<(usize, usize)>, LiteralSetError> {
        self.trie
            .find_window_value(
                haystack,
                Window::full(haystack),
                FoldedLiteralTrieScanLimits::unlimited(),
            )
            .map(|candidate| candidate.map(|candidate| (candidate.start(), candidate.end())))
            .map_err(map_scan_error)
    }

    #[cfg(test)]
    pub(crate) fn branch_count(&self) -> usize {
        self.trie.build_accounting().patterns
    }
}

/// Try to construct the sidecar from an authenticated canonical HIR.
///
/// Resource refusals leave the canonical literal-set DFA unchanged. Shape or
/// semantic mismatches also decline after charging the work actually read.
/// Arithmetic or closed-receipt contradictions are internal failures.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn try_build(
    hir: &Hir,
    expected_hir_nodes: u64,
    expected_class_ranges: u64,
    initial_work: u64,
    planner_work_limit: u64,
    retained_facade_bytes: usize,
    incumbent_plan_bytes: usize,
    persistent_byte_limit: usize,
) -> Result<BuildAttempt, BuildError> {
    if initial_work > planner_work_limit {
        return Err(BuildError::InternalInvariant(
            "ASCII-folded alternation inherited planner work above its limit",
        ));
    }
    let dispatch = SimdDispatchContext::capture();
    // Reserve the complete syntax inspection before reading the HIR. Trie
    // materialization and construction are reserved separately from the exact
    // dimensions authenticated by this pass.
    let inspection_upper = expected_hir_nodes.checked_add(expected_class_ranges);
    let Some(inspection_upper) = inspection_upper else {
        return Ok(BuildAttempt::declined(initial_work));
    };
    if inspection_upper > planner_work_limit - initial_work {
        return Ok(BuildAttempt::declined(initial_work));
    }

    let mut work = initial_work;
    let mut observed_nodes = 0_u64;
    let mut observed_ranges = 0_u64;
    charge(&mut work, &mut observed_nodes, 1)?;
    let HirKind::Alternation(branch_hirs) = hir.kind() else {
        return Ok(BuildAttempt::declined(work));
    };
    if branch_hirs.len() != BRANCHES {
        return Ok(BuildAttempt::declined(work));
    }

    let mut widths = [0_usize; BRANCHES];
    let mut equivalents = [[['\0'; ASCII_CASE_RANGES]; MAX_WIDTH]; BRANCHES];
    let mut scalar_positions = 0_usize;
    let mut max_pattern_scalars = 0_usize;
    for (branch_index, branch_hir) in branch_hirs.iter().enumerate() {
        charge(&mut work, &mut observed_nodes, 1)?;
        let HirKind::Concat(positions_hir) = branch_hir.kind() else {
            return Ok(BuildAttempt::declined(work));
        };
        if !(MIN_WIDTH..=MAX_WIDTH).contains(&positions_hir.len()) {
            return Ok(BuildAttempt::declined(work));
        }
        widths[branch_index] = positions_hir.len();
        scalar_positions = scalar_positions.checked_add(positions_hir.len()).ok_or(
            BuildError::InternalInvariant(
                "ASCII-folded alternation scalar-position count overflowed",
            ),
        )?;
        max_pattern_scalars = max_pattern_scalars.max(positions_hir.len());

        for (index, position_hir) in positions_hir.iter().enumerate() {
            charge(&mut work, &mut observed_nodes, 1)?;
            let HirKind::Class(Class::Bytes(class)) = position_hir.kind() else {
                return Ok(BuildAttempt::declined(work));
            };
            let ranges = class.ranges();
            charge(
                &mut work,
                &mut observed_ranges,
                u64::try_from(ranges.len()).map_err(|_| {
                    BuildError::InternalInvariant(
                        "ASCII-folded alternation class range count does not fit u64",
                    )
                })?,
            )?;
            let [first, second] = ranges else {
                return Ok(BuildAttempt::declined(work));
            };
            if first.start() != first.end()
                || second.start() != second.end()
                || !is_ascii_opposite_case_pair(first.start(), second.start())
            {
                return Ok(BuildAttempt::declined(work));
            }
            let mut pair = [char::from(first.start()), char::from(second.start())];
            pair.sort_unstable();
            equivalents[branch_index][index] = pair;
        }
    }

    if observed_nodes != expected_hir_nodes || observed_ranges != expected_class_ranges {
        return Err(BuildError::InternalInvariant(
            "syntax summary differs from ASCII-folded alternation inspection",
        ));
    }
    let equivalent_scalars =
        scalar_positions
            .checked_mul(ASCII_CASE_RANGES)
            .ok_or(BuildError::InternalInvariant(
                "ASCII-folded alternation equivalent-scalar count overflowed",
            ))?;
    let requirements = folded_literal_trie_build_requirements_from_dimensions(
        BRANCHES,
        scalar_positions,
        equivalent_scalars,
        max_pattern_scalars,
    )
    .map_err(|_| {
        BuildError::InternalInvariant("ASCII-folded alternation trie requirements overflowed")
    })?;
    let wrapper_overhead = size_of::<OrdinaryPlan>()
        .checked_sub(size_of::<FoldedLiteralTriePlan>())
        .ok_or(BuildError::InternalInvariant(
            "ASCII-folded alternation owner is smaller than its trie",
        ))?;
    let storage_upper = requirements
        .persistent_bytes_upper_bound
        .checked_add(wrapper_overhead)
        .ok_or(BuildError::PersistentBytesOverflow)?;
    let charged_upper = retained_facade_bytes
        .checked_add(incumbent_plan_bytes)
        .and_then(|bytes| bytes.checked_add(storage_upper))
        .ok_or(BuildError::PersistentBytesOverflow)?;
    if charged_upper > persistent_byte_limit {
        return Ok(BuildAttempt::declined(work));
    }

    let materialization_work =
        u64::try_from(MATERIALIZED_CLASS_SLOTS + BRANCHES).map_err(|_| {
            BuildError::InternalInvariant(
                "ASCII-folded alternation materialization work does not fit u64",
            )
        })?;
    let trie_work_upper = u64::try_from(requirements.work_upper_bound).map_err(|_| {
        BuildError::InternalInvariant("ASCII-folded alternation trie work does not fit u64")
    })?;
    let post_inspection_upper = materialization_work
        .checked_add(trie_work_upper)
        .and_then(|work| work.checked_add(1));
    let Some(post_inspection_upper) = post_inspection_upper else {
        return Ok(BuildAttempt::declined(work));
    };
    if post_inspection_upper > planner_work_limit - work {
        return Ok(BuildAttempt::declined(work));
    }
    charge_work(&mut work, materialization_work)?;
    // Publish the same complete envelope pre-admitted above. The trie reports
    // exact completed work as well, but charging only that smaller value would
    // make this plan disappear when its published planner limit is replayed.
    charge_work(&mut work, trie_work_upper)?;

    let classes: [[FoldedScalarClass<'_>; MAX_WIDTH]; BRANCHES] = core::array::from_fn(|branch| {
        core::array::from_fn(|position| FoldedScalarClass::new(&equivalents[branch][position]))
    });
    let patterns = [
        FoldedLiteral::new(&classes[0][..widths[0]]),
        FoldedLiteral::new(&classes[1][..widths[1]]),
        FoldedLiteral::new(&classes[2][..widths[2]]),
        FoldedLiteral::new(&classes[3][..widths[3]]),
    ];
    let trie_limits = FoldedLiteralTrieBuildLimits {
        max_patterns: BRANCHES,
        max_scalar_positions: scalar_positions,
        max_equivalent_scalars: equivalent_scalars,
        max_states: requirements.states_upper_bound,
        max_transitions: requirements.transitions_upper_bound,
        max_work: requirements.work_upper_bound,
        max_persistent_bytes: requirements.persistent_bytes_upper_bound,
        max_peak_bytes: requirements.peak_bytes_upper_bound,
        max_allocations: requirements.allocations_upper_bound,
    };
    let trie = match FoldedLiteralTriePlan::build_with_dispatch(dispatch, &patterns, trie_limits) {
        Ok(FoldedLiteralTrieBuildAttempt::Admitted(trie)) => trie,
        Ok(FoldedLiteralTrieBuildAttempt::DenseFallback(_)) => {
            return Err(BuildError::InternalInvariant(
                "authenticated ASCII-folded classes lost canonical disjointness",
            ));
        }
        Err(FoldedLiteralTrieBuildError::AllocationFailed { .. }) => {
            return Ok(BuildAttempt::declined(work));
        }
        Err(FoldedLiteralTrieBuildError::Resource { .. }) => {
            return Err(BuildError::InternalInvariant(
                "pre-admitted ASCII-folded trie exceeded its resource envelope",
            ));
        }
        Err(FoldedLiteralTrieBuildError::ArithmeticOverflow { .. }) => {
            return Err(BuildError::InternalInvariant(
                "preflighted ASCII-folded trie arithmetic overflowed",
            ));
        }
        Err(FoldedLiteralTrieBuildError::Invariant { .. }) => {
            return Err(BuildError::InternalInvariant(
                "authenticated ASCII-folded trie violated a kernel invariant",
            ));
        }
        Err(_) => {
            return Err(BuildError::InternalInvariant(
                "authenticated ASCII-folded trie returned an unknown construction error",
            ));
        }
    };
    let trie_build = trie.build_accounting();
    if trie_build.patterns != BRANCHES
        || trie_build.scalar_positions != scalar_positions
        || trie_build.equivalent_scalars != equivalent_scalars
        || trie_build.root_prefilter_needles == 0
        || trie_build.root_prefilter_work_upper_bound > requirements.root_prefilter_work_upper_bound
        || trie_build.work_upper_bound > requirements.work_upper_bound
        || trie_build.work > requirements.work_upper_bound
        || trie_build.persistent_bytes > requirements.persistent_bytes_upper_bound
    {
        return Err(BuildError::InternalInvariant(
            "ASCII-folded trie publication differs from its authenticated census",
        ));
    }
    let storage_bytes = trie_build
        .persistent_bytes
        .checked_add(wrapper_overhead)
        .ok_or(BuildError::PersistentBytesOverflow)?;
    charge_work(&mut work, 1)?;
    let plan = OrdinaryPlan { trie };
    let plan = match try_box_preserve(plan) {
        Ok(plan) => plan,
        Err((CopyError::AllocationFailed, _)) => return Ok(BuildAttempt::declined(work)),
        Err((CopyError::LayoutOverflow, _)) => {
            return Err(BuildError::InternalInvariant(
                "ASCII-folded alternation owner layout overflowed",
            ));
        }
    };
    Ok(BuildAttempt {
        plan: Some(plan),
        planner_work: work,
        storage_bytes,
    })
}

#[cold]
#[inline(never)]
fn map_scan_error(error: FoldedLiteralTrieScanAttemptError) -> LiteralSetError {
    match error.source {
        FoldedLiteralTrieScanError::InvalidWindow {
            start,
            end,
            haystack_len,
        } => LiteralSetError::InvalidWindow {
            start,
            end,
            haystack_len,
        },
        FoldedLiteralTrieScanError::ArithmeticOverflow { computation } => {
            LiteralSetError::ArithmeticOverflow { computation }
        }
        FoldedLiteralTrieScanError::Resource { .. }
        | FoldedLiteralTrieScanError::Invariant { .. } => LiteralSetError::AutomatonBuild {
            detail: "ASCII-folded literal-set sidecar violated its scan contract".into(),
        },
        _ => LiteralSetError::AutomatonBuild {
            detail: "ASCII-folded literal-set sidecar returned an unknown scan error".into(),
        },
    }
}

fn charge(work: &mut u64, observed: &mut u64, additional: u64) -> Result<(), BuildError> {
    charge_work(work, additional)?;
    *observed = observed
        .checked_add(additional)
        .ok_or(BuildError::InternalInvariant(
            "ASCII-folded inspection observation overflowed",
        ))?;
    Ok(())
}

fn charge_work(work: &mut u64, additional: u64) -> Result<(), BuildError> {
    *work = work
        .checked_add(additional)
        .ok_or(BuildError::InternalInvariant(
            "ASCII-folded alternation planner work overflowed",
        ))?;
    Ok(())
}

const fn is_ascii_opposite_case_pair(first: u8, second: u8) -> bool {
    first.is_ascii_alphabetic()
        && second.is_ascii_alphabetic()
        && first.to_ascii_lowercase() == second.to_ascii_lowercase()
        && first != second
}
