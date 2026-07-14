//! Checked lowering to a prioritized continuation graph.

use std::collections::VecDeque;

use crate::accounting::{checked_add, enforce};
use crate::{Ast, Error, Greed, RepeatAtom, ResourceKind};

/// Compile-time and whole-operation resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompileLimits {
    /// Maximum validated AST nodes.
    pub max_ast_nodes: usize,
    /// Maximum AST nesting depth. Lowering recursion is bounded by this value.
    pub max_ast_depth: usize,
    /// Maximum continuation-graph states.
    pub max_program_states: usize,
    /// Maximum minimum or finite repetition bound admitted for expansion.
    pub max_repeat_bound: u32,
    /// Maximum unbounded repetitions tracked by the guarded strategy.
    pub max_guard_count: usize,
    /// Maximum fully preflighted guarded recurrence configurations.
    pub max_guarded_configurations: usize,
    /// Maximum memo plus explicit guarded work-stack bytes.
    pub max_guarded_bytes: usize,
    /// Maximum original input boundaries (`haystack.len() + 1`).
    pub max_boundaries: usize,
    /// Maximum full-table cells.
    pub max_table_cells: usize,
    /// Maximum logical packed decision-log bytes.
    pub max_log_bytes: usize,
    /// Maximum actual word-rounded resident decision-log bytes.
    pub max_resident_log_bytes: usize,
    /// Maximum candidate random-access scratch bytes, excluding output/log.
    pub max_random_access_bytes: usize,
    /// Maximum bytes pre-reserved for returned spans.
    pub max_output_bytes: usize,
    /// Maximum instrumented work units per operation.
    pub max_work: usize,
    /// Maximum returned spans.
    pub max_output_matches: usize,
}

impl Default for CompileLimits {
    fn default() -> Self {
        Self {
            max_ast_nodes: 4_096,
            max_ast_depth: 64,
            max_program_states: 16_384,
            max_repeat_bound: 1_000,
            max_guard_count: 8,
            max_guarded_configurations: 8_000_000,
            max_guarded_bytes: 256 * 1_024 * 1_024,
            max_boundaries: 1_048_577,
            max_table_cells: 16_777_216,
            max_log_bytes: 64 * 1_024 * 1_024,
            max_resident_log_bytes: 64 * 1_024 * 1_024,
            max_random_access_bytes: 128 * 1_024 * 1_024,
            max_output_bytes: 64 * 1_024 * 1_024,
            max_work: 268_435_456,
            max_output_matches: 1_048_576,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Inst {
    Match,
    Byte { expected: Option<u8>, next: usize },
    AssertStart { next: usize },
    AssertEnd { next: usize },
    Split { preferred: usize, fallback: usize },
}

/// A validated prioritized continuation graph and its resource policy.
#[derive(Clone, Debug)]
pub struct CompiledRegex {
    pub(crate) insts: Vec<Inst>,
    pub(crate) entry: usize,
    pub(crate) epsilon_order: Vec<usize>,
    pub(crate) split_rank: Vec<Option<usize>>,
    pub(crate) split_count: usize,
    pub(crate) limits: CompileLimits,
}

impl CompiledRegex {
    /// Validate and compile one laboratory AST.
    pub fn new(ast: &Ast, limits: CompileLimits) -> Result<Self, Error> {
        validate_ast(ast, limits)?;
        let mut builder = Builder {
            slots: Vec::new(),
            limit: limits.max_program_states,
        };
        let accept = builder.push(Some(Inst::Match))?;
        let entry = builder.compile_node(ast, accept, 1)?;
        let insts = builder
            .slots
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::SameBoundaryCycle)?;
        let epsilon_order = epsilon_order(&insts)?;
        let mut split_count = 0_usize;
        let mut split_rank = Vec::new();
        split_rank
            .try_reserve_exact(insts.len())
            .map_err(|_| Error::AllocationFailed {
                kind: ResourceKind::ProgramStates,
            })?;
        for inst in &insts {
            if matches!(inst, Inst::Split { .. }) {
                let rank = split_count;
                split_count = checked_add(split_count, 1, ResourceKind::ProgramStates)?;
                split_rank.push(Some(rank));
            } else {
                split_rank.push(None);
            }
        }
        Ok(Self {
            insts,
            entry,
            epsilon_order,
            split_rank,
            split_count,
            limits,
        })
    }

    /// Number of compiled continuation-graph states.
    #[must_use]
    pub fn state_count(&self) -> usize {
        self.insts.len()
    }

    pub(crate) fn boundaries(&self, haystack: &[u8]) -> Result<usize, Error> {
        let boundaries = checked_add(haystack.len(), 1, ResourceKind::Boundaries)?;
        enforce(
            boundaries,
            self.limits.max_boundaries,
            ResourceKind::Boundaries,
        )?;
        Ok(boundaries)
    }

    pub(crate) fn maximum_build_work(&self, boundaries: usize) -> Result<usize, Error> {
        let per_boundary = self.insts.iter().try_fold(0_usize, |sum, inst| {
            let transitions = match inst {
                Inst::Match => 0,
                Inst::Byte { .. } | Inst::AssertStart { .. } | Inst::AssertEnd { .. } => 1,
                Inst::Split { .. } => 2,
            };
            checked_add(
                sum,
                checked_add(1, transitions, ResourceKind::Work)?,
                ResourceKind::Work,
            )
        })?;
        crate::accounting::checked_mul(per_boundary, boundaries, ResourceKind::Work)
    }
}

struct Builder {
    slots: Vec<Option<Inst>>,
    limit: usize,
}

impl Builder {
    fn push(&mut self, inst: Option<Inst>) -> Result<usize, Error> {
        let required = checked_add(self.slots.len(), 1, ResourceKind::ProgramStates)?;
        enforce(required, self.limit, ResourceKind::ProgramStates)?;
        let index = self.slots.len();
        self.slots
            .try_reserve(1)
            .map_err(|_| Error::AllocationFailed {
                kind: ResourceKind::ProgramStates,
            })?;
        self.slots.push(inst);
        Ok(index)
    }

    fn compile_node(
        &mut self,
        ast: &Ast,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        debug_assert!(depth > 0);
        let child_depth = checked_add(depth, 1, ResourceKind::AstDepth)?;
        match ast {
            Ast::Empty => Ok(continuation),
            Ast::Byte(byte) => self.push(Some(Inst::Byte {
                expected: Some(*byte),
                next: continuation,
            })),
            Ast::AnyByte => self.push(Some(Inst::Byte {
                expected: None,
                next: continuation,
            })),
            Ast::StartText => self.push(Some(Inst::AssertStart { next: continuation })),
            Ast::EndText => self.push(Some(Inst::AssertEnd { next: continuation })),
            Ast::Concat(children) => {
                let mut next = continuation;
                for child in children.iter().rev() {
                    next = self.compile_node(child, next, child_depth)?;
                }
                Ok(next)
            }
            Ast::Alt(children) => {
                let Some((last, preceding)) = children.split_last() else {
                    return Err(Error::EmptyAlternation);
                };
                let mut fallback = self.compile_node(last, continuation, child_depth)?;
                for child in preceding.iter().rev() {
                    let preferred = self.compile_node(child, continuation, child_depth)?;
                    fallback = self.push(Some(Inst::Split {
                        preferred,
                        fallback,
                    }))?;
                }
                Ok(fallback)
            }
            Ast::Repeat { body, greed } => {
                if body.is_empty() {
                    return Err(Error::EmptyRepeatBody);
                }
                let loop_entry = self.push(None)?;
                let body_entry = self.compile_repeat_body(body, loop_entry, continuation)?;
                let (preferred, fallback) = match greed {
                    Greed::Greedy => (body_entry, continuation),
                    Greed::Lazy => (continuation, body_entry),
                };
                self.slots[loop_entry] = Some(Inst::Split {
                    preferred,
                    fallback,
                });
                Ok(loop_entry)
            }
            Ast::Repetition {
                child,
                min,
                max,
                greed,
            } => self.compile_repetition(child, *min, *max, *greed, continuation, child_depth),
        }
    }

    fn compile_repetition(
        &mut self,
        child: &Ast,
        min: u32,
        max: Option<u32>,
        greed: Greed,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        let mut next = if let Some(maximum) = max {
            let optional = maximum.checked_sub(min).ok_or(Error::InvalidRepeatRange)?;
            let mut optional_entry = continuation;
            for _ in 0..optional {
                let child_entry = self.compile_node(child, optional_entry, depth)?;
                let (preferred, fallback) = match greed {
                    Greed::Greedy => (child_entry, optional_entry),
                    Greed::Lazy => (optional_entry, child_entry),
                };
                optional_entry = self.push(Some(Inst::Split {
                    preferred,
                    fallback,
                }))?;
            }
            optional_entry
        } else {
            self.compile_progress_star(child, greed, continuation, depth)?
        };
        for _ in 0..min {
            next = self.compile_node(child, next, depth)?;
        }
        Ok(next)
    }

    fn compile_progress_star(
        &mut self,
        child: &Ast,
        greed: Greed,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        let loop_entry = self.push(None)?;
        let mut fragment = Self {
            slots: Vec::new(),
            limit: self.limit,
        };
        let accept = fragment.push(Some(Inst::Match))?;
        let fragment_entry = fragment.compile_node(child, accept, depth)?;
        let fragment_insts = fragment
            .slots
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::SameBoundaryCycle)?;
        let body_entry = self.import_progress_product(
            &fragment_insts,
            fragment_entry,
            continuation,
            loop_entry,
        )?;
        let (preferred, fallback) = match greed {
            Greed::Greedy => (body_entry, continuation),
            Greed::Lazy => (continuation, body_entry),
        };
        self.slots[loop_entry] = Some(Inst::Split {
            preferred,
            fallback,
        });
        Ok(loop_entry)
    }

    fn import_progress_product(
        &mut self,
        fragment: &[Inst],
        fragment_entry: usize,
        zero_continuation: usize,
        consumed_continuation: usize,
    ) -> Result<usize, Error> {
        let mut zero_map = Vec::new();
        let mut consumed_map = Vec::new();
        zero_map
            .try_reserve_exact(fragment.len())
            .map_err(|_| Error::AllocationFailed {
                kind: ResourceKind::ProgramStates,
            })?;
        consumed_map
            .try_reserve_exact(fragment.len())
            .map_err(|_| Error::AllocationFailed {
                kind: ResourceKind::ProgramStates,
            })?;
        for inst in fragment {
            if matches!(inst, Inst::Match) {
                zero_map.push(zero_continuation);
                consumed_map.push(consumed_continuation);
            } else {
                zero_map.push(self.push(None)?);
                consumed_map.push(self.push(None)?);
            }
        }
        for (pc, inst) in fragment.iter().enumerate() {
            if matches!(inst, Inst::Match) {
                continue;
            }
            self.slots[zero_map[pc]] = Some(translate_progress_inst(
                inst,
                &zero_map,
                &consumed_map,
                false,
            ));
            self.slots[consumed_map[pc]] = Some(translate_progress_inst(
                inst,
                &zero_map,
                &consumed_map,
                true,
            ));
        }
        Ok(zero_map[fragment_entry])
    }

    fn compile_repeat_body(
        &mut self,
        body: &[RepeatAtom],
        loop_entry: usize,
        continuation: usize,
    ) -> Result<usize, Error> {
        let Some((last, preceding)) = body.split_last() else {
            return Err(Error::EmptyRepeatBody);
        };
        let mut fallback = self.compile_repeat_atom(*last, loop_entry, continuation)?;
        for atom in preceding.iter().rev() {
            let preferred = self.compile_repeat_atom(*atom, loop_entry, continuation)?;
            fallback = self.push(Some(Inst::Split {
                preferred,
                fallback,
            }))?;
        }
        Ok(fallback)
    }

    fn compile_repeat_atom(
        &mut self,
        atom: RepeatAtom,
        loop_entry: usize,
        continuation: usize,
    ) -> Result<usize, Error> {
        match atom {
            RepeatAtom::Empty => Ok(continuation),
            RepeatAtom::Byte(byte) => self.push(Some(Inst::Byte {
                expected: Some(byte),
                next: loop_entry,
            })),
            RepeatAtom::AnyByte => self.push(Some(Inst::Byte {
                expected: None,
                next: loop_entry,
            })),
            RepeatAtom::StartText => self.push(Some(Inst::AssertStart { next: continuation })),
            RepeatAtom::EndText => self.push(Some(Inst::AssertEnd { next: continuation })),
        }
    }
}

pub(crate) fn validate_ast(ast: &Ast, limits: CompileLimits) -> Result<(), Error> {
    let mut stack = vec![(ast, 1_usize)];
    let mut nodes = 0_usize;
    while let Some((node, depth)) = stack.pop() {
        nodes = checked_add(nodes, 1, ResourceKind::AstNodes)?;
        enforce(nodes, limits.max_ast_nodes, ResourceKind::AstNodes)?;
        enforce(depth, limits.max_ast_depth, ResourceKind::AstDepth)?;
        let next_depth = checked_add(depth, 1, ResourceKind::AstDepth)?;
        match node {
            Ast::Concat(children) => {
                stack.extend(children.iter().map(|child| (child, next_depth)));
            }
            Ast::Alt(children) => {
                if children.is_empty() {
                    return Err(Error::EmptyAlternation);
                }
                stack.extend(children.iter().map(|child| (child, next_depth)));
            }
            Ast::Repeat { body, .. } => {
                if body.is_empty() {
                    return Err(Error::EmptyRepeatBody);
                }
            }
            Ast::Repetition {
                child, min, max, ..
            } => {
                if max.is_some_and(|maximum| maximum < *min) {
                    return Err(Error::InvalidRepeatRange);
                }
                if *min > limits.max_repeat_bound
                    || max.is_some_and(|maximum| maximum > limits.max_repeat_bound)
                {
                    let required = usize::try_from(max.unwrap_or(*min)).unwrap_or(usize::MAX);
                    return Err(Error::ResourceLimit {
                        kind: ResourceKind::RepeatBound,
                        required,
                        limit: usize::try_from(limits.max_repeat_bound).unwrap_or(usize::MAX),
                    });
                }
                stack.push((child, next_depth));
            }
            Ast::Empty | Ast::Byte(_) | Ast::AnyByte | Ast::StartText | Ast::EndText => {}
        }
    }
    Ok(())
}

fn translate_progress_inst(
    inst: &Inst,
    zero_map: &[usize],
    consumed_map: &[usize],
    consumed: bool,
) -> Inst {
    let same_mode = if consumed { consumed_map } else { zero_map };
    match *inst {
        Inst::Match => unreachable!("match is mapped directly to a continuation"),
        Inst::Byte { expected, next } => Inst::Byte {
            expected,
            next: consumed_map[next],
        },
        Inst::AssertStart { next } => Inst::AssertStart {
            next: same_mode[next],
        },
        Inst::AssertEnd { next } => Inst::AssertEnd {
            next: same_mode[next],
        },
        Inst::Split {
            preferred,
            fallback,
        } => Inst::Split {
            preferred: same_mode[preferred],
            fallback: same_mode[fallback],
        },
    }
}

fn epsilon_order(insts: &[Inst]) -> Result<Vec<usize>, Error> {
    let mut outgoing = vec![0_usize; insts.len()];
    let mut parents = vec![Vec::new(); insts.len()];
    for (parent, inst) in insts.iter().enumerate() {
        let mut add = |child: usize| -> Result<(), Error> {
            outgoing[parent] = checked_add(outgoing[parent], 1, ResourceKind::ProgramStates)?;
            parents[child].push(parent);
            Ok(())
        };
        match *inst {
            Inst::AssertStart { next } | Inst::AssertEnd { next } => add(next)?,
            Inst::Split {
                preferred,
                fallback,
            } => {
                add(preferred)?;
                add(fallback)?;
            }
            Inst::Match | Inst::Byte { .. } => {}
        }
    }
    let mut queue = outgoing
        .iter()
        .enumerate()
        .filter_map(|(index, count)| (*count == 0).then_some(index))
        .collect::<VecDeque<_>>();
    let mut order = Vec::with_capacity(insts.len());
    while let Some(child) = queue.pop_front() {
        order.push(child);
        for &parent in &parents[child] {
            outgoing[parent] = outgoing[parent]
                .checked_sub(1)
                .ok_or(Error::SameBoundaryCycle)?;
            if outgoing[parent] == 0 {
                queue.push_back(parent);
            }
        }
    }
    if order.len() != insts.len() {
        return Err(Error::SameBoundaryCycle);
    }
    Ok(order)
}
