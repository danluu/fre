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
    pub replay_cells: usize,
    pub history_nodes_bound: usize,
    pub output_bytes: usize,
    pub peak_bytes: usize,
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

impl CompiledCaptureRegex {
    /// Admit the complete Rust-compatible whole-match sequence and then
    /// reconstruct captures by prioritized exact-span replay.
    ///
    /// Capture slot, replay-cell, history, output and peak bounds are checked
    /// before any capture scratch or output allocation. The underlying
    /// whole-match operation retains its own independent admission contract.
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
        let admitted = self.inner.admit_spans(
            haystack,
            range.clone(),
            strategy,
            operation_limits,
        )?;
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
        enforce(
            replay_cells,
            capture_limits.max_replay_cells,
            Resource::CaptureReplayCells,
        )?;
        enforce(
            replay_cells,
            capture_limits.max_history_nodes,
            Resource::CaptureHistoryNodes,
        )?;
        let output_slots = mul(
            admitted.as_slice().len(),
            self.capture_slots,
            Resource::CaptureOutputBytes,
        )?;
        let group_output_bytes = mul(
            output_slots,
            core::mem::size_of::<Option<Span>>(),
            Resource::CaptureOutputBytes,
        )?;
        let match_output_bytes = mul(
            admitted.as_slice().len(),
            core::mem::size_of::<CaptureMatch>(),
            Resource::CaptureOutputBytes,
        )?;
        let output_bytes = add(
            group_output_bytes,
            match_output_bytes,
            Resource::CaptureOutputBytes,
        )?;
        enforce(
            output_bytes,
            capture_limits.max_output_bytes,
            Resource::CaptureOutputBytes,
        )?;
        let stack_items = add(
            mul(replay_cells, 2, Resource::CaptureReplayCells)?,
            1,
            Resource::CaptureReplayCells,
        )?;
        let visited_bytes = mul(
            replay_cells,
            core::mem::size_of::<usize>(),
            Resource::PeakBytes,
        )?;
        let stack_bytes = mul(
            stack_items,
            core::mem::size_of::<ReplayState>(),
            Resource::PeakBytes,
        )?;
        let history_bytes = mul(
            replay_cells,
            core::mem::size_of::<HistoryNode>(),
            Resource::PeakBytes,
        )?;
        let slot_scratch_bytes = mul(
            self.capture_slots,
            core::mem::size_of::<(Option<usize>, Option<usize>)>(),
            Resource::PeakBytes,
        )?;
        let scratch_bytes = add(
            add(visited_bytes, stack_bytes, Resource::PeakBytes)?,
            add(history_bytes, slot_scratch_bytes, Resource::PeakBytes)?,
            Resource::PeakBytes,
        )?;
        let peak_bytes = add(
            add(scratch_bytes, output_bytes, Resource::PeakBytes)?,
            admitted.certificate().output_bytes,
            Resource::PeakBytes,
        )?;
        enforce(
            peak_bytes,
            capture_limits.max_peak_bytes,
            Resource::PeakBytes,
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

        let mut visited = vec![usize::MAX; replay_cells].into_boxed_slice();
        let mut stack = Vec::new();
        stack
            .try_reserve_exact(stack_items)
            .map_err(|_| Error::AllocationFailed {
                resource: Resource::CaptureReplayCells,
                items: stack_items,
            })?;
        let mut history = Vec::new();
        history
            .try_reserve_exact(replay_cells)
            .map_err(|_| Error::AllocationFailed {
                resource: Resource::CaptureHistoryNodes,
                items: replay_cells,
            })?;
        let mut matches = Vec::new();
        matches
            .try_reserve_exact(admitted.as_slice().len())
            .map_err(|_| Error::AllocationFailed {
                resource: Resource::CaptureOutputBytes,
                items: admitted.as_slice().len(),
            })?;
        let local_len = boundaries
            .checked_sub(1)
            .ok_or(Error::InternalInvariant("capture boundaries omitted range start"))?;
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
            stack.push(ReplayState {
                pc: self.inner.program.entry,
                position: start,
                history: None,
            });
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
            let groups = materialize_groups(
                span,
                range.start,
                self.capture_slots,
                accepted,
                &history,
                capture_limits,
                &mut work,
            )?;
            matches.push(CaptureMatch {
                whole: span,
                groups,
            });
        }
        let certificate = CaptureOperationCertificate {
            whole_matches: admitted.certificate().clone(),
            whole_match_accounting: admitted.accounting(),
            capture_slots: self.capture_slots,
            replay_cells,
            history_nodes_bound: replay_cells,
            output_bytes,
            peak_bytes,
            work,
        };
        Ok(AdmittedCaptures {
            certificate,
            matches: matches.into_boxed_slice(),
        })
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "capture replay keeps every fixed scratch buffer and limit explicit"
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
            .ok_or(Error::InternalInvariant("capture replay moved before selected start"))?;
        let cell = add(
            mul(relative, states, Resource::CaptureReplayCells)?,
            state.pc,
            Resource::CaptureReplayCells,
        )?;
        let marker = visited
            .get_mut(cell)
            .ok_or(Error::InternalInvariant("capture replay cell outside scratch"))?;
        if *marker == generation {
            continue;
        }
        *marker = generation;
        match program.instruction(state.pc)? {
            Inst::Unfilled => {
                return Err(Error::InternalInvariant("unfilled capture replay state"));
            }
            Inst::Fail => {}
            Inst::Match if state.position == target_end => return Ok(Some(state.history)),
            Inst::Match => {}
            Inst::Consume { bytes, next }
                if state.position < target_end
                    && bytes.contains(haystack[state.position]) =>
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
            Inst::Consume { .. } => {}
            Inst::Assert { assertion, next } => {
                if assertions.is_match(*assertion, state.position)? {
                    push_state(
                        stack,
                        ReplayState {
                            pc: *next,
                            ..state
                        },
                        limits,
                    )?;
                }
            }
            Inst::CaptureStart { group, next } => {
                enforce(
                    add(history.len(), 1, Resource::CaptureHistoryNodes)?,
                    limits.max_history_nodes,
                    Resource::CaptureHistoryNodes,
                )?;
                let history_index = history.len();
                history.push(HistoryNode {
                    parent: state.history,
                    group: *group,
                    position: state.position,
                    action: CaptureAction::Start,
                });
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
                enforce(
                    add(history.len(), 1, Resource::CaptureHistoryNodes)?,
                    limits.max_history_nodes,
                    Resource::CaptureHistoryNodes,
                )?;
                let history_index = history.len();
                history.push(HistoryNode {
                    parent: state.history,
                    group: *group,
                    position: state.position,
                    action: CaptureAction::End,
                });
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

fn materialize_groups(
    whole: Span,
    base: usize,
    capture_slots: usize,
    accepted: Option<usize>,
    history: &[HistoryNode],
    limits: CaptureLimits,
    work: &mut usize,
) -> Result<Box<[Option<Span>]>, Error> {
    let mut offsets = vec![(None, None); capture_slots];
    let mut cursor = accepted;
    while let Some(index) = cursor {
        charge(work, 1, limits.max_work)?;
        let node = history
            .get(index)
            .ok_or(Error::InternalInvariant("capture history parent outside arena"))?;
        let slot = offsets
            .get_mut(node.group)
            .ok_or(Error::InternalInvariant("capture action group outside slots"))?;
        let absolute = add(base, node.position, Resource::Boundaries)?;
        match node.action {
            CaptureAction::Start if slot.0.is_none() => slot.0 = Some(absolute),
            CaptureAction::End if slot.1.is_none() => slot.1 = Some(absolute),
            CaptureAction::Start | CaptureAction::End => {}
        }
        cursor = node.parent;
    }
    let mut groups = Vec::new();
    groups
        .try_reserve_exact(capture_slots)
        .map_err(|_| Error::AllocationFailed {
            resource: Resource::CaptureOutputBytes,
            items: capture_slots,
        })?;
    groups.push(Some(whole));
    for (start, end) in offsets.into_iter().skip(1) {
        groups.push(match (start, end) {
            (Some(start), Some(end)) => Some(Span { start, end }),
            (None, None) => None,
            _ => {
                return Err(Error::InternalInvariant(
                    "capture history has an unpaired start or end",
                ));
            }
        });
    }
    Ok(groups.into_boxed_slice())
}

fn charge(work: &mut usize, amount: usize, limit: usize) -> Result<(), Error> {
    let required = add(*work, amount, Resource::CaptureWork)?;
    enforce(required, limit, Resource::CaptureWork)?;
    *work = required;
    Ok(())
}
