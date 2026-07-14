//! Explicit progress-guard recurrence used as an independent generalization.

use crate::accounting::{Accounting, RunReport, checked_add, checked_mul, enforce};
use crate::compile::{CompileLimits, validate_ast};
use crate::iterate::{collect_sequence, reserve_output};
use crate::{Ast, Error, Greed, RepeatAtom, ResourceKind};

const UNKNOWN: usize = 0;
const VISITING: usize = 1;
const FAILURE: usize = 2;
const END_BASE: usize = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
enum GuardInst {
    Match,
    Byte {
        expected: Option<u8>,
        next: usize,
    },
    AssertStart {
        next: usize,
    },
    AssertEnd {
        next: usize,
    },
    Split {
        preferred: usize,
        fallback: usize,
    },
    SaveProgress {
        guard: usize,
        next: usize,
    },
    CheckProgress {
        guard: usize,
        progressed: usize,
        empty: usize,
    },
}

/// A separately compiled recurrence with explicit per-repeat progress guards.
///
/// Unlike [`crate::CompiledRegex`], this strategy does not duplicate repeated
/// bodies into zero/progress modes. Its recurrence key contains a mixed-radix
/// vector of saved iteration-start boundaries. This admits the same general
/// capture-free grammar, but its preflighted state space is
/// `Q * U * (U + 1)^R` for `R` unbounded repetitions. It is a bounded research
/// comparison, not a production fallback.
#[derive(Clone, Debug)]
pub struct GuardedRegex {
    insts: Vec<GuardInst>,
    entry: usize,
    guard_count: usize,
    limits: CompileLimits,
}

impl GuardedRegex {
    /// Validate and compile an AST without the progress-product transform.
    pub fn new(ast: &Ast, limits: CompileLimits) -> Result<Self, Error> {
        validate_ast(ast, limits)?;
        let mut builder = GuardBuilder {
            slots: Vec::new(),
            guard_count: 0,
            limits,
        };
        let accept = builder.push(Some(GuardInst::Match))?;
        let entry = builder.compile_node(ast, accept, 1)?;
        let insts = builder
            .slots
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(Error::SameBoundaryCycle)?;
        Ok(Self {
            insts,
            entry,
            guard_count: builder.guard_count,
            limits,
        })
    }

    /// Evaluate the exact aggregate sequence with an explicit guarded-state
    /// memo table.
    ///
    /// The complete configuration table, solver stack, work bound and output
    /// capacity are checked and fallibly reserved before recurrence work. A
    /// resource failure returns no partial sequence.
    pub fn find_all_guarded_dp(&self, haystack: &[u8]) -> Result<RunReport, Error> {
        let started = std::time::Instant::now();
        let admission = self.admit(haystack)?;
        let mut accounting = Accounting {
            program_states: self.insts.len(),
            boundaries: admission.boundaries,
            table_builds: 1,
            table_cells: admission.cells,
            guarded_configurations: admission.cells,
            random_access_peak_bytes: admission.random_bytes,
            ..Accounting::default()
        };
        let (output, output_reserved_bytes) = reserve_output(admission.boundaries, self.limits)?;
        accounting.output_reserved_bytes = output_reserved_bytes;
        let mut memo = zeroed_usizes(admission.cells, ResourceKind::GuardedBytes)?;
        let mut stack = Vec::new();
        stack
            .try_reserve_exact(admission.cells)
            .map_err(|_| Error::AllocationFailed {
                kind: ResourceKind::GuardedBytes,
            })?;
        let initial_guard_code = admission
            .guard_space
            .checked_sub(1)
            .ok_or(Error::SameBoundaryCycle)?;
        let mut solver = GuardSolver {
            regex: self,
            haystack,
            admission,
            memo: &mut memo,
            stack: &mut stack,
        };
        let matches = collect_sequence(
            haystack.len(),
            self.limits,
            &mut accounting,
            output,
            |start, accounting| {
                solver.solve(
                    GuardConfig {
                        pc: self.entry,
                        position: start,
                        guard_code: initial_guard_code,
                    },
                    accounting,
                )
            },
        )?;
        accounting.elapsed = started.elapsed();
        Ok(RunReport {
            matches,
            accounting,
        })
    }

    /// Number of compiled guarded states.
    #[must_use]
    pub fn state_count(&self) -> usize {
        self.insts.len()
    }

    /// Number of independent unbounded-repeat progress registers.
    #[must_use]
    pub fn guard_count(&self) -> usize {
        self.guard_count
    }

    fn admit(&self, haystack: &[u8]) -> Result<GuardAdmission, Error> {
        let boundaries = checked_add(haystack.len(), 1, ResourceKind::Boundaries)?;
        enforce(
            boundaries,
            self.limits.max_boundaries,
            ResourceKind::Boundaries,
        )?;
        let radix = checked_add(boundaries, 1, ResourceKind::GuardedConfigurations)?;
        let guard_space =
            checked_pow(radix, self.guard_count, ResourceKind::GuardedConfigurations)?;
        let cells = checked_mul(
            checked_mul(
                self.insts.len(),
                boundaries,
                ResourceKind::GuardedConfigurations,
            )?,
            guard_space,
            ResourceKind::GuardedConfigurations,
        )?;
        enforce(
            cells,
            self.limits.max_guarded_configurations,
            ResourceKind::GuardedConfigurations,
        )?;
        let memo_bytes = checked_mul(
            cells,
            core::mem::size_of::<usize>(),
            ResourceKind::GuardedBytes,
        )?;
        let stack_bytes = checked_mul(
            cells,
            core::mem::size_of::<GuardFrame>(),
            ResourceKind::GuardedBytes,
        )?;
        let random_bytes = checked_add(memo_bytes, stack_bytes, ResourceKind::GuardedBytes)?;
        enforce(
            random_bytes,
            self.limits.max_guarded_bytes,
            ResourceKind::GuardedBytes,
        )?;
        let recurrence_work = checked_mul(cells, 3, ResourceKind::Work)?;
        let root_work = checked_mul(boundaries, 2, ResourceKind::Work)?;
        enforce(
            checked_add(recurrence_work, root_work, ResourceKind::Work)?,
            self.limits.max_work,
            ResourceKind::Work,
        )?;
        Ok(GuardAdmission {
            boundaries,
            radix,
            guard_space,
            cells,
            random_bytes,
        })
    }
}

struct GuardBuilder {
    slots: Vec<Option<GuardInst>>,
    guard_count: usize,
    limits: CompileLimits,
}

impl GuardBuilder {
    fn push(&mut self, inst: Option<GuardInst>) -> Result<usize, Error> {
        let required = checked_add(self.slots.len(), 1, ResourceKind::ProgramStates)?;
        enforce(
            required,
            self.limits.max_program_states,
            ResourceKind::ProgramStates,
        )?;
        self.slots
            .try_reserve(1)
            .map_err(|_| Error::AllocationFailed {
                kind: ResourceKind::ProgramStates,
            })?;
        let index = self.slots.len();
        self.slots.push(inst);
        Ok(index)
    }

    fn new_guard(&mut self) -> Result<usize, Error> {
        let required = checked_add(self.guard_count, 1, ResourceKind::GuardCount)?;
        enforce(
            required,
            self.limits.max_guard_count,
            ResourceKind::GuardCount,
        )?;
        let guard = self.guard_count;
        self.guard_count = required;
        Ok(guard)
    }

    fn compile_node(
        &mut self,
        ast: &Ast,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        let child_depth = checked_add(depth, 1, ResourceKind::AstDepth)?;
        match ast {
            Ast::Empty => Ok(continuation),
            Ast::Byte(byte) => self.push(Some(GuardInst::Byte {
                expected: Some(*byte),
                next: continuation,
            })),
            Ast::AnyByte => self.push(Some(GuardInst::Byte {
                expected: None,
                next: continuation,
            })),
            Ast::StartText => self.push(Some(GuardInst::AssertStart { next: continuation })),
            Ast::EndText => self.push(Some(GuardInst::AssertEnd { next: continuation })),
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
                    fallback = self.push(Some(GuardInst::Split {
                        preferred,
                        fallback,
                    }))?;
                }
                Ok(fallback)
            }
            Ast::Repeat { body, greed } => {
                self.compile_atom_star(body, *greed, continuation, child_depth)
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
            let mut entry = continuation;
            for _ in 0..optional {
                let child_entry = self.compile_node(child, entry, depth)?;
                let (preferred, fallback) = ordered(greed, child_entry, entry);
                entry = self.push(Some(GuardInst::Split {
                    preferred,
                    fallback,
                }))?;
            }
            entry
        } else {
            self.compile_general_star(child, greed, continuation, depth)?
        };
        for _ in 0..min {
            next = self.compile_node(child, next, depth)?;
        }
        Ok(next)
    }

    fn compile_general_star(
        &mut self,
        child: &Ast,
        greed: Greed,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        let guard = self.new_guard()?;
        let loop_entry = self.push(None)?;
        let check = self.push(Some(GuardInst::CheckProgress {
            guard,
            progressed: loop_entry,
            empty: continuation,
        }))?;
        let child_entry = self.compile_node(child, check, depth)?;
        let save = self.push(Some(GuardInst::SaveProgress {
            guard,
            next: child_entry,
        }))?;
        let (preferred, fallback) = ordered(greed, save, continuation);
        self.slots[loop_entry] = Some(GuardInst::Split {
            preferred,
            fallback,
        });
        Ok(loop_entry)
    }

    fn compile_atom_star(
        &mut self,
        body: &[RepeatAtom],
        greed: Greed,
        continuation: usize,
        _depth: usize,
    ) -> Result<usize, Error> {
        let Some((last, preceding)) = body.split_last() else {
            return Err(Error::EmptyRepeatBody);
        };
        let guard = self.new_guard()?;
        let loop_entry = self.push(None)?;
        let check = self.push(Some(GuardInst::CheckProgress {
            guard,
            progressed: loop_entry,
            empty: continuation,
        }))?;
        let mut body_entry = self.compile_atom(*last, check)?;
        for atom in preceding.iter().rev() {
            let preferred = self.compile_atom(*atom, check)?;
            body_entry = self.push(Some(GuardInst::Split {
                preferred,
                fallback: body_entry,
            }))?;
        }
        let save = self.push(Some(GuardInst::SaveProgress {
            guard,
            next: body_entry,
        }))?;
        let (preferred, fallback) = ordered(greed, save, continuation);
        self.slots[loop_entry] = Some(GuardInst::Split {
            preferred,
            fallback,
        });
        Ok(loop_entry)
    }

    fn compile_atom(&mut self, atom: RepeatAtom, continuation: usize) -> Result<usize, Error> {
        match atom {
            RepeatAtom::Empty => Ok(continuation),
            RepeatAtom::Byte(byte) => self.push(Some(GuardInst::Byte {
                expected: Some(byte),
                next: continuation,
            })),
            RepeatAtom::AnyByte => self.push(Some(GuardInst::Byte {
                expected: None,
                next: continuation,
            })),
            RepeatAtom::StartText => self.push(Some(GuardInst::AssertStart { next: continuation })),
            RepeatAtom::EndText => self.push(Some(GuardInst::AssertEnd { next: continuation })),
        }
    }
}

fn ordered(greed: Greed, body: usize, exit: usize) -> (usize, usize) {
    match greed {
        Greed::Greedy => (body, exit),
        Greed::Lazy => (exit, body),
    }
}

#[derive(Clone, Copy, Debug)]
struct GuardAdmission {
    boundaries: usize,
    radix: usize,
    guard_space: usize,
    cells: usize,
    random_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuardConfig {
    pc: usize,
    position: usize,
    guard_code: usize,
}

#[derive(Clone, Copy, Debug)]
struct GuardFrame {
    config: GuardConfig,
    next_child: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeShape {
    End(usize),
    Failure,
    Children(u8),
}

struct GuardSolver<'a> {
    regex: &'a GuardedRegex,
    haystack: &'a [u8],
    admission: GuardAdmission,
    memo: &'a mut [usize],
    stack: &'a mut Vec<GuardFrame>,
}

impl GuardSolver<'_> {
    fn solve(
        &mut self,
        root: GuardConfig,
        accounting: &mut Accounting,
    ) -> Result<Option<usize>, Error> {
        let root_index = self.index(root)?;
        if self.memo[root_index] == UNKNOWN {
            self.push(root, accounting)?;
        }
        while let Some(frame) = self.stack.last().copied() {
            let index = self.index(frame.config)?;
            if self.memo[index] == UNKNOWN {
                self.memo[index] = VISITING;
                accounting.charge_state(self.regex.limits.max_work)?;
            }
            match self.shape(frame.config) {
                NodeShape::End(end) => {
                    self.memo[index] = encode_end(end)?;
                    self.stack.pop();
                }
                NodeShape::Failure => {
                    self.memo[index] = FAILURE;
                    self.stack.pop();
                }
                NodeShape::Children(count) => {
                    if frame.next_child >= count {
                        self.memo[index] = FAILURE;
                        self.stack.pop();
                        continue;
                    }
                    let child = self.child(frame.config, frame.next_child)?;
                    accounting.charge_transition(self.regex.limits.max_work)?;
                    let child_index = self.index(child)?;
                    match self.memo[child_index] {
                        UNKNOWN => self.push(child, accounting)?,
                        VISITING => return Err(Error::SameBoundaryCycle),
                        FAILURE => {
                            let top = self.stack.last_mut().ok_or(Error::SameBoundaryCycle)?;
                            top.next_child = top
                                .next_child
                                .checked_add(1)
                                .ok_or(Error::SameBoundaryCycle)?;
                        }
                        selected => {
                            self.memo[index] = selected;
                            self.stack.pop();
                        }
                    }
                }
            }
        }
        decode_end(self.memo[root_index])
    }

    fn push(&mut self, config: GuardConfig, accounting: &mut Accounting) -> Result<(), Error> {
        if self.stack.len() >= self.admission.cells {
            return Err(Error::ResourceLimit {
                kind: ResourceKind::GuardedConfigurations,
                required: self.stack.len().saturating_add(1),
                limit: self.admission.cells,
            });
        }
        self.stack.push(GuardFrame {
            config,
            next_child: 0,
        });
        accounting.guarded_peak_frames = accounting.guarded_peak_frames.max(self.stack.len());
        Ok(())
    }

    fn shape(&self, config: GuardConfig) -> NodeShape {
        match self.regex.insts[config.pc] {
            GuardInst::Match => NodeShape::End(config.position),
            GuardInst::Byte { expected, .. } => {
                if config.position < self.haystack.len()
                    && expected.is_none_or(|byte| byte == self.haystack[config.position])
                {
                    NodeShape::Children(1)
                } else {
                    NodeShape::Failure
                }
            }
            GuardInst::AssertStart { .. } => {
                if config.position == 0 {
                    NodeShape::Children(1)
                } else {
                    NodeShape::Failure
                }
            }
            GuardInst::AssertEnd { .. } => {
                if config.position == self.haystack.len() {
                    NodeShape::Children(1)
                } else {
                    NodeShape::Failure
                }
            }
            GuardInst::Split { .. } => NodeShape::Children(2),
            GuardInst::SaveProgress { .. } | GuardInst::CheckProgress { .. } => {
                NodeShape::Children(1)
            }
        }
    }

    fn child(&self, config: GuardConfig, ordinal: u8) -> Result<GuardConfig, Error> {
        let mut child = config;
        match self.regex.insts[config.pc] {
            GuardInst::Match => return Err(Error::SameBoundaryCycle),
            GuardInst::Byte { next, .. } => {
                child.pc = next;
                child.position = checked_add(config.position, 1, ResourceKind::Boundaries)?;
            }
            GuardInst::AssertStart { next } | GuardInst::AssertEnd { next } => child.pc = next,
            GuardInst::Split {
                preferred,
                fallback,
            } => {
                child.pc = match ordinal {
                    0 => preferred,
                    1 => fallback,
                    _ => return Err(Error::SameBoundaryCycle),
                };
            }
            GuardInst::SaveProgress { guard, next } => {
                child.pc = next;
                child.guard_code = self.write_guard(config.guard_code, guard, config.position)?;
            }
            GuardInst::CheckProgress {
                guard,
                progressed,
                empty,
            } => {
                let saved = self.read_guard(config.guard_code, guard)?;
                if saved == self.admission.boundaries || config.position < saved {
                    return Err(Error::SameBoundaryCycle);
                }
                child.pc = if config.position > saved {
                    progressed
                } else {
                    empty
                };
            }
        }
        Ok(child)
    }

    fn read_guard(&self, code: usize, guard: usize) -> Result<usize, Error> {
        let factor = checked_pow(
            self.admission.radix,
            guard,
            ResourceKind::GuardedConfigurations,
        )?;
        code.checked_div(factor)
            .and_then(|value| value.checked_rem(self.admission.radix))
            .ok_or(Error::SameBoundaryCycle)
    }

    fn write_guard(&self, code: usize, guard: usize, position: usize) -> Result<usize, Error> {
        let factor = checked_pow(
            self.admission.radix,
            guard,
            ResourceKind::GuardedConfigurations,
        )?;
        let old = self.read_guard(code, guard)?;
        let removed = checked_mul(old, factor, ResourceKind::GuardedConfigurations)?;
        let base = code.checked_sub(removed).ok_or(Error::SameBoundaryCycle)?;
        checked_add(
            base,
            checked_mul(position, factor, ResourceKind::GuardedConfigurations)?,
            ResourceKind::GuardedConfigurations,
        )
    }

    fn index(&self, config: GuardConfig) -> Result<usize, Error> {
        if config.guard_code >= self.admission.guard_space
            || config.position >= self.admission.boundaries
            || config.pc >= self.regex.insts.len()
        {
            return Err(Error::SameBoundaryCycle);
        }
        checked_add(
            checked_mul(
                checked_add(
                    checked_mul(
                        config.guard_code,
                        self.admission.boundaries,
                        ResourceKind::GuardedConfigurations,
                    )?,
                    config.position,
                    ResourceKind::GuardedConfigurations,
                )?,
                self.regex.insts.len(),
                ResourceKind::GuardedConfigurations,
            )?,
            config.pc,
            ResourceKind::GuardedConfigurations,
        )
    }
}

fn checked_pow(base: usize, exponent: usize, kind: ResourceKind) -> Result<usize, Error> {
    let mut result = 1_usize;
    for _ in 0..exponent {
        result = checked_mul(result, base, kind)?;
    }
    Ok(result)
}

fn zeroed_usizes(length: usize, kind: ResourceKind) -> Result<Vec<usize>, Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed { kind })?;
    values.resize(length, 0);
    Ok(values)
}

fn encode_end(end: usize) -> Result<usize, Error> {
    checked_add(end, END_BASE, ResourceKind::Boundaries)
}

fn decode_end(value: usize) -> Result<Option<usize>, Error> {
    match value {
        UNKNOWN | VISITING => Err(Error::SameBoundaryCycle),
        FAILURE => Ok(None),
        selected => Ok(selected.checked_sub(END_BASE)),
    }
}
