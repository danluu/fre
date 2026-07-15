use core::ops::Range;

use crate::compile::CompiledCaptureRegex;
use crate::error::{add, enforce, mul};
use crate::operation::{OperationCertificate, Span, Strategy};
use crate::program::{AssertionContext, Inst, Program};
use crate::{CaptureLimits, Error, ExecutionAccounting, OperationLimits, Resource};

/// One whole match and all numbered groups in absolute byte offsets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureMatch {
    whole: Span,
    groups: Box<[Option<Span>]>,
}

impl CaptureMatch {
    /// Whole-match span (group zero).
    #[must_use]
    pub const fn span(&self) -> Span {
        self.whole
    }

    /// Number of group slots, including group zero.
    #[must_use]
    pub fn group_len(&self) -> usize {
        self.groups.len()
    }

    /// Absolute byte span for one participating group.
    #[must_use]
    pub fn group(&self, index: usize) -> Option<Span> {
        self.groups.get(index).copied().flatten()
    }

    /// Every numbered group in index order.
    #[must_use]
    pub fn groups(&self) -> &[Option<Span>] {
        &self.groups
    }
}

/// Admission facts for whole-match selection plus capture reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureOperationCertificate {
    pub whole_matches: OperationCertificate,
    pub whole_match_accounting: ExecutionAccounting,
    pub capture_slots: usize,
    /// Physical visited-vector capacity in replay cells.
    pub replay_cells: usize,
    /// Physical history-arena capacity in nodes.
    pub history_nodes_bound: usize,
    /// Physical retained capacities for match records and group arrays.
    pub output_bytes: usize,
    /// Physical visited/stack/history/offset/output capacities plus the
    /// retained whole-match output.
    pub peak_bytes: usize,
    /// Preflight upper bound enforced before replay allocation or execution.
    pub work_bound: usize,
    /// Actual replay and materialization work consumed.
    pub work: usize,
}

/// Fully admitted immutable capture sequence.
#[derive(Debug)]
pub struct AdmittedCaptures {
    certificate: CaptureOperationCertificate,
    matches: Box<[CaptureMatch]>,
}

impl AdmittedCaptures {
    #[must_use]
    pub fn as_slice(&self) -> &[CaptureMatch] {
        &self.matches
    }

    #[must_use]
    pub const fn certificate(&self) -> &CaptureOperationCertificate {
        &self.certificate
    }
}

#[derive(Clone, Copy, Debug)]
struct ReplayState {
    pc: usize,
    position: usize,
    history: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
enum CaptureAction {
    Start,
    End,
}

#[derive(Clone, Copy, Debug)]
struct HistoryNode {
    parent: Option<usize>,
    group: usize,
    position: usize,
    action: CaptureAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaptureStorageCapacities {
    visited_items: usize,
    stack_items: usize,
    history_items: usize,
    match_items: usize,
    group_slots: usize,
    offset_slots: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CaptureStorageFacts {
    output_bytes: usize,
    peak_bytes: usize,
}

fn account_physical_storage(
    capacities: CaptureStorageCapacities,
    whole_match_output_bytes: usize,
    limits: CaptureLimits,
) -> Result<CaptureStorageFacts, Error> {
    enforce(
        capacities.visited_items,
        limits.max_replay_cells,
        Resource::CaptureReplayCells,
    )?;
    let stack_limit = add(
        mul(limits.max_replay_cells, 2, Resource::CaptureReplayCells)?,
        1,
        Resource::CaptureReplayCells,
    )?;
    enforce(
        capacities.stack_items,
        stack_limit,
        Resource::CaptureReplayCells,
    )?;
    enforce(
        capacities.history_items,
        limits.max_history_nodes,
        Resource::CaptureHistoryNodes,
    )?;

    let match_output_bytes = mul(
        capacities.match_items,
        core::mem::size_of::<CaptureMatch>(),
        Resource::CaptureOutputBytes,
    )?;
    let group_output_bytes = mul(
        capacities.group_slots,
        core::mem::size_of::<Option<Span>>(),
        Resource::CaptureOutputBytes,
    )?;
    let output_bytes = add(
        match_output_bytes,
        group_output_bytes,
        Resource::CaptureOutputBytes,
    )?;
    enforce(
        output_bytes,
        limits.max_output_bytes,
        Resource::CaptureOutputBytes,
    )?;

    let visited_bytes = mul(
        capacities.visited_items,
        core::mem::size_of::<usize>(),
        Resource::PeakBytes,
    )?;
    let stack_bytes = mul(
        capacities.stack_items,
        core::mem::size_of::<ReplayState>(),
        Resource::PeakBytes,
    )?;
    let history_bytes = mul(
        capacities.history_items,
        core::mem::size_of::<HistoryNode>(),
        Resource::PeakBytes,
    )?;
    let offset_bytes = mul(
        capacities.offset_slots,
        core::mem::size_of::<(Option<usize>, Option<usize>)>(),
        Resource::PeakBytes,
    )?;
    let scratch_bytes = add(
        add(visited_bytes, stack_bytes, Resource::PeakBytes)?,
        add(history_bytes, offset_bytes, Resource::PeakBytes)?,
        Resource::PeakBytes,
    )?;
    let peak_bytes = add(
        add(scratch_bytes, output_bytes, Resource::PeakBytes)?,
        whole_match_output_bytes,
        Resource::PeakBytes,
    )?;
    enforce(peak_bytes, limits.max_peak_bytes, Resource::PeakBytes)?;
    Ok(CaptureStorageFacts {
        output_bytes,
        peak_bytes,
    })
}

impl CompiledCaptureRegex {
    /// Admit the complete Rust-compatible whole-match sequence and then
    /// reconstruct captures by prioritized exact-span replay.
    ///
    /// Capture slot, replay-cell, history, output and peak bounds are checked
    /// before any capture scratch or output allocation. The underlying
    /// whole-match operation retains its own independent admission contract.
    #[allow(
        clippy::too_many_lines,
        reason = "capture admission keeps logical preflight, physical capacities, and certificate publication in one audit unit"
    )]
    pub fn admit_captures(
        &self,
        haystack: &[u8],
        range: Range<usize>,
        strategy: Strategy,
        operation_limits: OperationLimits,
        capture_limits: CaptureLimits,
    ) -> Result<AdmittedCaptures, Error> {
        enforce(
            self.capture_slots,
            capture_limits.max_capture_slots,
            Resource::CaptureSlots,
        )?;
        let admitted =
            self.inner
                .admit_spans(haystack, range.clone(), strategy, operation_limits)?;
        let boundaries = add(
            range
                .end
                .checked_sub(range.start)
                .ok_or(Error::InvalidRange {
                    start: range.start,
                    end: range.end,
                    haystack_len: haystack.len(),
                })?,
            1,
            Resource::Boundaries,
        )?;
        let states = self.inner.program.insts.len();
        let longest_match = admitted
            .as_slice()
            .iter()
            .try_fold(0_usize, |longest, span| {
                let length = span
                    .end
                    .checked_sub(span.start)
                    .ok_or(Error::InternalInvariant("capture span end precedes start"))?;
                Ok::<usize, Error>(longest.max(length))
            })?;
        let replay_boundaries = add(longest_match, 1, Resource::CaptureReplayCells)?;
        let replay_cells = mul(states, replay_boundaries, Resource::CaptureReplayCells)?;
        let match_items = admitted.as_slice().len();
        let output_slots = mul(
            match_items,
            self.capture_slots,
            Resource::CaptureOutputBytes,
        )?;
        let stack_items = add(
            mul(replay_cells, 2, Resource::CaptureReplayCells)?,
            1,
            Resource::CaptureReplayCells,
        )?;
        let offset_slots = if match_items == 0 {
            0
        } else {
            self.capture_slots
        };
        account_physical_storage(
            CaptureStorageCapacities {
                visited_items: replay_cells,
                stack_items,
                history_items: replay_cells,
                match_items,
                group_slots: output_slots,
                offset_slots,
            },
            admitted.certificate().output_bytes,
            capture_limits,
        )?;
        let work_per_match = add(
            mul(replay_cells, 3, Resource::CaptureWork)?,
            1,
            Resource::CaptureWork,
        )?;
        let work_bound = mul(
            admitted.as_slice().len(),
            work_per_match,
            Resource::CaptureWork,
        )?;
        enforce(work_bound, capture_limits.max_work, Resource::CaptureWork)?;

        let mut visited = fre_exact_alloc::vec_with_exact_capacity(replay_cells).map_err(|_| {
            Error::AllocationFailed {
                resource: Resource::CaptureReplayCells,
                items: replay_cells,
            }
        })?;
        enforce(
            replay_cells,
            visited.capacity(),
            Resource::CaptureReplayCells,
        )?;
        visited.resize(replay_cells, usize::MAX);
        let mut stack = fre_exact_alloc::vec_with_exact_capacity(stack_items).map_err(|_| {
            Error::AllocationFailed {
                resource: Resource::CaptureReplayCells,
                items: stack_items,
            }
        })?;
        let mut history = fre_exact_alloc::vec_with_exact_capacity(replay_cells).map_err(|_| {
            Error::AllocationFailed {
                resource: Resource::CaptureHistoryNodes,
                items: replay_cells,
            }
        })?;
        let mut matches = fre_exact_alloc::vec_with_exact_capacity(match_items).map_err(|_| {
            Error::AllocationFailed {
                resource: Resource::CaptureOutputBytes,
                items: match_items,
            }
        })?;
        let mut physical_capacities = CaptureStorageCapacities {
            visited_items: visited.capacity(),
            stack_items: stack.capacity(),
            history_items: history.capacity(),
            match_items: matches.capacity(),
            group_slots: 0,
            offset_slots: 0,
        };
        let mut physical_facts = account_physical_storage(
            physical_capacities,
            admitted.certificate().output_bytes,
            capture_limits,
        )?;
        let local_len = boundaries.checked_sub(1).ok_or(Error::InternalInvariant(
            "capture boundaries omitted range start",
        ))?;
        let assertions = AssertionContext::new(haystack, range.start, local_len)?;
        let local = &haystack[range.clone()];
        let mut work = 0_usize;
        for (generation, span) in admitted.as_slice().iter().copied().enumerate() {
            let start = span
                .start
                .checked_sub(range.start)
                .ok_or(Error::InternalInvariant("capture span starts before range"))?;
            let end = span
                .end
                .checked_sub(range.start)
                .ok_or(Error::InternalInvariant("capture span ends before range"))?;
            stack.clear();
            history.clear();
            push_state(
                &mut stack,
                ReplayState {
                    pc: self.inner.program.entry,
                    position: start,
                    history: None,
                },
                capture_limits,
            )?;
            let accepted = replay_one(
                &self.inner.program,
                local,
                assertions,
                start,
                end,
                generation,
                &mut visited,
                &mut stack,
                &mut history,
                capture_limits,
                &mut work,
            )?
            .ok_or(Error::InternalInvariant(
                "capture replay could not reproduce selected whole match",
            ))?;
            let materialized = materialize_groups(
                span,
                range.start,
                self.capture_slots,
                accepted,
                &history,
                capture_limits,
                &mut work,
            )?;
            physical_capacities.group_slots = add(
                physical_capacities.group_slots,
                materialized.group_slots,
                Resource::CaptureOutputBytes,
            )?;
            physical_capacities.offset_slots = physical_capacities
                .offset_slots
                .max(materialized.offset_slots);
            physical_facts = account_physical_storage(
                physical_capacities,
                admitted.certificate().output_bytes,
                capture_limits,
            )?;
            if materialized.groups.len() != materialized.groups.capacity() {
                return Err(Error::InternalInvariant(
                    "capture groups did not fill their exact allocation",
                ));
            }
            push_within_capacity(
                &mut matches,
                CaptureMatch {
                    whole: span,
                    groups: materialized.groups.into_boxed_slice(),
                },
                Resource::CaptureOutputBytes,
            )?;
        }
        if physical_capacities.group_slots != output_slots
            || physical_capacities.offset_slots != offset_slots
        {
            return Err(Error::InternalInvariant(
                "capture output capacities differ from exact preflight",
            ));
        }
        if matches.len() != match_items || matches.len() != matches.capacity() {
            return Err(Error::InternalInvariant(
                "capture match output did not fill its exact allocation",
            ));
        }
        let certificate = CaptureOperationCertificate {
            whole_matches: admitted.certificate().clone(),
            whole_match_accounting: admitted.accounting(),
            capture_slots: self.capture_slots,
            replay_cells: physical_capacities.visited_items,
            history_nodes_bound: physical_capacities.history_items,
            output_bytes: physical_facts.output_bytes,
            peak_bytes: physical_facts.peak_bytes,
            work_bound,
            work,
        };
        Ok(AdmittedCaptures {
            certificate,
            matches: matches.into_boxed_slice(),
        })
    }
}

#[allow(
    clippy::option_option,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "capture replay keeps fixed scratch/limits explicit; the nested option distinguishes no accepting path from an accepting path with no capture history"
)]
fn replay_one(
    program: &Program,
    haystack: &[u8],
    assertions: AssertionContext<'_>,
    replay_start: usize,
    target_end: usize,
    generation: usize,
    visited: &mut [usize],
    stack: &mut Vec<ReplayState>,
    history: &mut Vec<HistoryNode>,
    limits: CaptureLimits,
    work: &mut usize,
) -> Result<Option<Option<usize>>, Error> {
    let states = program.insts.len();
    while let Some(state) = stack.pop() {
        charge(work, 1, limits.max_work)?;
        let relative = state
            .position
            .checked_sub(replay_start)
            .ok_or(Error::InternalInvariant(
                "capture replay moved before selected start",
            ))?;
        let cell = add(
            mul(relative, states, Resource::CaptureReplayCells)?,
            state.pc,
            Resource::CaptureReplayCells,
        )?;
        let marker = visited.get_mut(cell).ok_or(Error::InternalInvariant(
            "capture replay cell outside scratch",
        ))?;
        if *marker == generation {
            continue;
        }
        *marker = generation;
        match program.instruction(state.pc)? {
            Inst::Unfilled => {
                return Err(Error::InternalInvariant("unfilled capture replay state"));
            }
            Inst::Match if state.position == target_end => return Ok(Some(state.history)),
            Inst::Consume { bytes, next }
                if state.position < target_end && bytes.contains(haystack[state.position]) =>
            {
                push_state(
                    stack,
                    ReplayState {
                        pc: *next,
                        position: add(state.position, 1, Resource::Boundaries)?,
                        history: state.history,
                    },
                    limits,
                )?;
            }
            Inst::Fail | Inst::Match | Inst::Consume { .. } => {}
            Inst::Assert { assertion, next } => {
                if assertions.is_match(*assertion, state.position)? {
                    push_state(stack, ReplayState { pc: *next, ..state }, limits)?;
                }
            }
            Inst::CaptureStart { group, next } => {
                let history_index = push_history(
                    history,
                    HistoryNode {
                        parent: state.history,
                        group: *group,
                        position: state.position,
                        action: CaptureAction::Start,
                    },
                    limits,
                )?;
                push_state(
                    stack,
                    ReplayState {
                        pc: *next,
                        history: Some(history_index),
                        ..state
                    },
                    limits,
                )?;
            }
            Inst::CaptureEnd { group, next } => {
                let history_index = push_history(
                    history,
                    HistoryNode {
                        parent: state.history,
                        group: *group,
                        position: state.position,
                        action: CaptureAction::End,
                    },
                    limits,
                )?;
                push_state(
                    stack,
                    ReplayState {
                        pc: *next,
                        history: Some(history_index),
                        ..state
                    },
                    limits,
                )?;
            }
            Inst::Split {
                preferred,
                fallback,
            } => {
                // LIFO order makes the certified preferred branch run first.
                push_state(
                    stack,
                    ReplayState {
                        pc: *fallback,
                        ..state
                    },
                    limits,
                )?;
                push_state(
                    stack,
                    ReplayState {
                        pc: *preferred,
                        ..state
                    },
                    limits,
                )?;
            }
        }
    }
    Ok(None)
}

fn push_state(
    stack: &mut Vec<ReplayState>,
    state: ReplayState,
    limits: CaptureLimits,
) -> Result<(), Error> {
    let required = add(stack.len(), 1, Resource::CaptureReplayCells)?;
    let policy_bound = add(
        mul(limits.max_replay_cells, 2, Resource::CaptureReplayCells)?,
        1,
        Resource::CaptureReplayCells,
    )?;
    let bound = stack.capacity().min(policy_bound);
    enforce(required, bound, Resource::CaptureReplayCells)?;
    stack.push(state);
    Ok(())
}

fn push_history(
    history: &mut Vec<HistoryNode>,
    node: HistoryNode,
    limits: CaptureLimits,
) -> Result<usize, Error> {
    let index = history.len();
    let required = add(index, 1, Resource::CaptureHistoryNodes)?;
    enforce(
        required,
        limits.max_history_nodes,
        Resource::CaptureHistoryNodes,
    )?;
    push_within_capacity(history, node, Resource::CaptureHistoryNodes)?;
    Ok(index)
}

fn push_within_capacity<T>(values: &mut Vec<T>, value: T, resource: Resource) -> Result<(), Error> {
    let required = add(values.len(), 1, resource)?;
    enforce(required, values.capacity(), resource)?;
    values.push(value);
    Ok(())
}

struct MaterializedGroups {
    groups: Vec<Option<Span>>,
    group_slots: usize,
    offset_slots: usize,
}

fn materialize_groups(
    whole: Span,
    base: usize,
    capture_slots: usize,
    accepted: Option<usize>,
    history: &[HistoryNode],
    limits: CaptureLimits,
    work: &mut usize,
) -> Result<MaterializedGroups, Error> {
    let mut offsets = fre_exact_alloc::vec_with_exact_capacity(capture_slots).map_err(|_| {
        Error::AllocationFailed {
            resource: Resource::PeakBytes,
            items: capture_slots,
        }
    })?;
    enforce(capture_slots, offsets.capacity(), Resource::PeakBytes)?;
    let offset_slots = offsets.capacity();
    offsets.resize(capture_slots, (None, None));
    let mut cursor = accepted;
    while let Some(index) = cursor {
        charge(work, 1, limits.max_work)?;
        let node = history.get(index).ok_or(Error::InternalInvariant(
            "capture history parent outside arena",
        ))?;
        let slot = offsets.get_mut(node.group).ok_or(Error::InternalInvariant(
            "capture action group outside slots",
        ))?;
        let absolute = add(base, node.position, Resource::Boundaries)?;
        match node.action {
            CaptureAction::Start if slot.0.is_none() => slot.0 = Some(absolute),
            CaptureAction::End if slot.1.is_none() => slot.1 = Some(absolute),
            CaptureAction::Start | CaptureAction::End => {}
        }
        cursor = node.parent;
    }
    let mut groups = fre_exact_alloc::vec_with_exact_capacity(capture_slots).map_err(|_| {
        Error::AllocationFailed {
            resource: Resource::CaptureOutputBytes,
            items: capture_slots,
        }
    })?;
    let group_slots = groups.capacity();
    push_within_capacity(&mut groups, Some(whole), Resource::CaptureOutputBytes)?;
    for (start, end) in offsets.into_iter().skip(1) {
        let group = match (start, end) {
            (Some(start), Some(end)) => Some(Span { start, end }),
            (None, None) => None,
            _ => {
                return Err(Error::InternalInvariant(
                    "capture history has an unpaired start or end",
                ));
            }
        };
        push_within_capacity(&mut groups, group, Resource::CaptureOutputBytes)?;
    }
    if groups.len() != capture_slots {
        return Err(Error::InternalInvariant(
            "capture groups did not fill every semantic slot",
        ));
    }
    Ok(MaterializedGroups {
        groups,
        group_slots,
        offset_slots,
    })
}

fn charge(work: &mut usize, amount: usize, limit: usize) -> Result<(), Error> {
    let required = add(*work, amount, Resource::CaptureWork)?;
    enforce(required, limit, Resource::CaptureWork)?;
    *work = required;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CaptureStorageCapacities, account_physical_storage};
    use crate::{CaptureLimits, Error, Resource};

    #[allow(
        clippy::needless_pass_by_value,
        reason = "the assertion helper owns the temporary result so its failure diagnostic remains available"
    )]
    fn expect_resource(result: Result<super::CaptureStorageFacts, Error>, expected: Resource) {
        assert!(
            matches!(
                &result,
                Err(Error::ResourceLimit { resource, .. }) if *resource == expected
            ),
            "expected {expected:?}, got {result:?}"
        );
    }

    #[test]
    #[allow(
        clippy::arithmetic_side_effects,
        clippy::too_many_lines,
        reason = "small synthetic capacities exercise exact one-above and one-below boundaries"
    )]
    fn physical_capture_capacities_are_the_admitted_one_below_boundary() {
        let capacities = CaptureStorageCapacities {
            visited_items: 3,
            stack_items: 7,
            history_items: 3,
            match_items: 2,
            group_slots: 4,
            offset_slots: 2,
        };
        let whole_match_output_bytes = 24;
        let generous = CaptureLimits::default();
        let facts = account_physical_storage(capacities, whole_match_output_bytes, generous)
            .expect("small physical capacities must fit defaults");
        let exact = CaptureLimits {
            max_capture_slots: 2,
            max_replay_cells: capacities.visited_items,
            max_history_nodes: capacities.history_items,
            max_output_bytes: facts.output_bytes,
            max_work: usize::MAX,
            max_peak_bytes: facts.peak_bytes,
        };
        assert_eq!(
            account_physical_storage(capacities, whole_match_output_bytes, exact),
            Ok(facts)
        );

        expect_resource(
            account_physical_storage(
                CaptureStorageCapacities {
                    visited_items: capacities.visited_items + 1,
                    ..capacities
                },
                whole_match_output_bytes,
                exact,
            ),
            Resource::CaptureReplayCells,
        );
        expect_resource(
            account_physical_storage(
                CaptureStorageCapacities {
                    stack_items: capacities.stack_items + 1,
                    ..capacities
                },
                whole_match_output_bytes,
                exact,
            ),
            Resource::CaptureReplayCells,
        );
        expect_resource(
            account_physical_storage(
                CaptureStorageCapacities {
                    history_items: capacities.history_items + 1,
                    ..capacities
                },
                whole_match_output_bytes,
                exact,
            ),
            Resource::CaptureHistoryNodes,
        );
        expect_resource(
            account_physical_storage(
                CaptureStorageCapacities {
                    match_items: capacities.match_items + 1,
                    ..capacities
                },
                whole_match_output_bytes,
                exact,
            ),
            Resource::CaptureOutputBytes,
        );
        expect_resource(
            account_physical_storage(
                CaptureStorageCapacities {
                    group_slots: capacities.group_slots + 1,
                    ..capacities
                },
                whole_match_output_bytes,
                exact,
            ),
            Resource::CaptureOutputBytes,
        );
        expect_resource(
            account_physical_storage(
                CaptureStorageCapacities {
                    offset_slots: capacities.offset_slots + 1,
                    ..capacities
                },
                whole_match_output_bytes,
                exact,
            ),
            Resource::PeakBytes,
        );
        expect_resource(
            account_physical_storage(
                capacities,
                whole_match_output_bytes,
                CaptureLimits {
                    max_output_bytes: exact.max_output_bytes - 1,
                    ..exact
                },
            ),
            Resource::CaptureOutputBytes,
        );
        expect_resource(
            account_physical_storage(
                capacities,
                whole_match_output_bytes,
                CaptureLimits {
                    max_peak_bytes: exact.max_peak_bytes - 1,
                    ..exact
                },
            ),
            Resource::PeakBytes,
        );
    }
}
