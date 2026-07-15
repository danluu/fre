use core::mem::size_of;

use fre_automata::{EdgeKind, RawPlan, StateRole};
use regex_syntax::{
    hir::{Class, ClassUnicode, Hir, HirKind, Look},
    utf8::Utf8Sequences,
};

use crate::{
    LowerError, LowerLimits, LowerResource, LowerStats, OperationSemantics, UnsupportedFeature,
};

#[derive(Clone, Copy, Debug)]
struct Patch {
    state: u32,
    edge: usize,
}

#[derive(Debug)]
struct Fragment {
    start: u32,
    outs: Vec<Patch>,
}

#[derive(Clone, Copy, Debug)]
struct MutableEdge {
    target: Option<u32>,
    kind: EdgeKind,
    byte_start: u8,
    byte_end: u8,
}

#[derive(Debug)]
struct MutableState {
    role: StateRole,
    edges: Vec<MutableEdge>,
}

#[derive(Clone, Copy)]
enum Task<'h> {
    Visit(&'h Hir),
    FinishConcat(usize),
    FinishAlternation(usize),
    FinishRepetition {
        min: u32,
        max: Option<u32>,
        greedy: bool,
        copies: usize,
    },
}

pub(crate) fn compile(
    hir: &Hir,
    operation: OperationSemantics,
    limits: LowerLimits,
) -> Result<(RawPlan, LowerStats), LowerError> {
    if operation == OperationSemantics::CaptureSensitive {
        return Err(LowerError::Unsupported(
            UnsupportedFeature::CaptureSensitiveOperation,
        ));
    }
    Compiler::new(limits, hir.properties().explicit_captures_len()).run(hir)
}

struct Compiler<'h> {
    limits: LowerLimits,
    tasks: Vec<Task<'h>>,
    fragments: Vec<Fragment>,
    states: Vec<MutableState>,
    edges: usize,
    work: u64,
    peak_stack_items: usize,
    erased_captures: usize,
}

impl<'h> Compiler<'h> {
    // regex-syntax 0.8.11 partitions one scalar interval with a fixed-width
    // four-byte decomposition. Precharge its bounded private split stack; each
    // yielded sequence and all emitted graph work are charged separately.
    const UTF8_SCALAR_RANGE_PARTITION_WORK: u64 = 64;

    const fn new(limits: LowerLimits, erased_captures: usize) -> Self {
        Self {
            limits,
            tasks: Vec::new(),
            fragments: Vec::new(),
            states: Vec::new(),
            edges: 0,
            work: 0,
            peak_stack_items: 0,
            erased_captures,
        }
    }

    fn run(mut self, hir: &'h Hir) -> Result<(RawPlan, LowerStats), LowerError> {
        self.push_task(Task::Visit(hir))?;
        while let Some(task) = self.tasks.pop() {
            self.charge(1, "task dispatch")?;
            match task {
                Task::Visit(node) => self.visit(node)?,
                Task::FinishConcat(count) => self.finish_concat(count)?,
                Task::FinishAlternation(count) => self.finish_alternation(count)?,
                Task::FinishRepetition {
                    min,
                    max,
                    greedy,
                    copies,
                } => self.finish_repetition(min, max, greedy, copies)?,
            }
        }
        if self.fragments.len() != 1 {
            return Err(LowerError::InternalInvariant {
                detail: "postorder traversal did not produce exactly one fragment",
            });
        }
        self.charge(1, "final fragment removal")?;
        let fragment = self.fragments.pop().ok_or(LowerError::InternalInvariant {
            detail: "missing final fragment",
        })?;
        let accept = self.add_state(StateRole::Accept)?;
        self.patch_all(&fragment.outs, accept)?;
        let start = fragment.start;
        preflight_final_tables(self.states.len(), self.edges, self.limits)?;
        self.charge_final_table_writes()?;
        let stats = LowerStats {
            work: self.work,
            peak_stack_items: self.peak_stack_items,
            states: self.states.len(),
            edges: self.edges,
            erased_captures: self.erased_captures,
        };
        let raw = self.into_raw(start)?;
        Ok((raw, stats))
    }

    fn visit(&mut self, hir: &'h Hir) -> Result<(), LowerError> {
        match hir.kind() {
            HirKind::Empty => {
                let fragment = self.empty_fragment()?;
                self.push_fragment(fragment)
            }
            HirKind::Literal(literal) => {
                let fragment = self.literal_fragment(&literal.0)?;
                self.push_fragment(fragment)
            }
            HirKind::Class(Class::Bytes(class)) => {
                let ranges = class
                    .ranges()
                    .iter()
                    .map(|range| (range.start(), range.end()));
                let fragment = self.class_fragment(ranges)?;
                self.push_fragment(fragment)
            }
            HirKind::Class(Class::Unicode(class)) => {
                let fragment = self.unicode_class_fragment(class)?;
                self.push_fragment(fragment)
            }
            HirKind::Look(look) => {
                let kind = match look {
                    Look::Start => EdgeKind::AssertHaystackStart,
                    Look::End => EdgeKind::AssertHaystackEnd,
                    Look::StartLF => EdgeKind::AssertLineStartLf,
                    Look::EndLF => EdgeKind::AssertLineEndLf,
                    Look::WordAscii => EdgeKind::AssertWordAscii,
                    Look::WordAsciiNegate => EdgeKind::AssertWordAsciiNegate,
                    Look::WordStartAscii => EdgeKind::AssertWordStartAscii,
                    Look::WordEndAscii => EdgeKind::AssertWordEndAscii,
                    Look::WordStartHalfAscii => EdgeKind::AssertWordStartHalfAscii,
                    Look::WordEndHalfAscii => EdgeKind::AssertWordEndHalfAscii,
                    Look::StartCRLF
                    | Look::EndCRLF
                    | Look::WordUnicode
                    | Look::WordUnicodeNegate
                    | Look::WordStartUnicode
                    | Look::WordEndUnicode
                    | Look::WordStartHalfUnicode
                    | Look::WordEndHalfUnicode => {
                        return Err(LowerError::Unsupported(UnsupportedFeature::LookAssertion(
                            *look,
                        )));
                    }
                };
                let fragment = self.assertion_fragment(kind)?;
                self.push_fragment(fragment)
            }
            HirKind::Capture(capture) => self.push_task(Task::Visit(&capture.sub)),
            HirKind::Concat(parts) => {
                self.push_task(Task::FinishConcat(parts.len()))?;
                for part in parts.iter().rev() {
                    self.push_task(Task::Visit(part))?;
                }
                Ok(())
            }
            HirKind::Alternation(branches) => {
                self.push_task(Task::FinishAlternation(branches.len()))?;
                for branch in branches.iter().rev() {
                    self.push_task(Task::Visit(branch))?;
                }
                Ok(())
            }
            HirKind::Repetition(repetition) => {
                if repetition.max.is_none()
                    && !matches!(repetition.sub.properties().minimum_len(), Some(min) if min > 0)
                {
                    return Err(LowerError::Unsupported(
                        UnsupportedFeature::UncertifiedUnboundedRepetition,
                    ));
                }
                let copies_u32 = repetition.max.unwrap_or_else(|| repetition.min.max(1));
                let copies =
                    usize::try_from(copies_u32).map_err(|_| LowerError::ArithmeticOverflow {
                        computation: "repetition copy count conversion",
                    })?;
                self.push_task(Task::FinishRepetition {
                    min: repetition.min,
                    max: repetition.max,
                    greedy: repetition.greedy,
                    copies,
                })?;
                for _ in 0..copies {
                    self.push_task(Task::Visit(&repetition.sub))?;
                }
                Ok(())
            }
        }
    }

    fn finish_concat(&mut self, count: usize) -> Result<(), LowerError> {
        let parts = self.take_fragments(count)?;
        let fragment = self.concat_fragments(parts)?;
        self.push_fragment(fragment)
    }

    fn finish_alternation(&mut self, count: usize) -> Result<(), LowerError> {
        let branches = self.take_fragments(count)?;
        if branches.is_empty() {
            return Err(LowerError::InternalInvariant {
                detail: "HIR alternation had no branches",
            });
        }
        let fragment = self.alternation_fragment(branches)?;
        self.push_fragment(fragment)
    }

    fn alternation_fragment(&mut self, branches: Vec<Fragment>) -> Result<Fragment, LowerError> {
        let split = self.add_state(StateRole::Split)?;
        let mut outs = Vec::new();
        for branch in branches {
            self.add_edge(split, EdgeKind::Epsilon, 0, 0, Some(branch.start))?;
            self.append_patches(&mut outs, branch.outs, "alternation patch list")?;
        }
        Ok(Fragment { start: split, outs })
    }

    fn finish_repetition(
        &mut self,
        min: u32,
        max: Option<u32>,
        greedy: bool,
        copies: usize,
    ) -> Result<(), LowerError> {
        let fragments = self.take_fragments(copies)?;
        let required = usize::try_from(min).map_err(|_| LowerError::ArithmeticOverflow {
            computation: "minimum repetition conversion",
        })?;
        if required > fragments.len() {
            return Err(LowerError::InternalInvariant {
                detail: "repetition minimum exceeded scheduled copies",
            });
        }

        let mut pieces = Vec::new();
        self.charge_vector_growth(
            pieces.len(),
            pieces.capacity(),
            fragments.len(),
            "repetition piece list",
        )?;
        reserve(&mut pieces, fragments.len(), "repetition piece list")?;
        if max.is_some() {
            for (index, fragment) in fragments.into_iter().enumerate() {
                if index < required {
                    pieces.push(fragment);
                } else {
                    pieces.push(self.optional_fragment(fragment, greedy)?);
                }
            }
        } else {
            let mut fragments = fragments.into_iter();
            for _ in 0..required.saturating_sub(1) {
                pieces.push(fragments.next().ok_or(LowerError::InternalInvariant {
                    detail: "missing required unbounded-repetition fragment",
                })?);
            }
            let loop_body = fragments.next().ok_or(LowerError::InternalInvariant {
                detail: "missing unbounded-repetition body fragment",
            })?;
            if fragments.next().is_some() {
                return Err(LowerError::InternalInvariant {
                    detail: "extra unbounded-repetition fragments",
                });
            }
            pieces.push(if required == 0 {
                self.star_fragment(&loop_body, greedy)?
            } else {
                self.plus_fragment(&loop_body, greedy)?
            });
        }
        let fragment = self.concat_fragments(pieces)?;
        self.push_fragment(fragment)
    }

    fn empty_fragment(&mut self) -> Result<Fragment, LowerError> {
        let state = self.add_state(StateRole::Split)?;
        let patch = self.add_edge(state, EdgeKind::Epsilon, 0, 0, None)?;
        Ok(Fragment {
            start: state,
            outs: self.singleton_patch(patch, "empty patch list")?,
        })
    }

    fn assertion_fragment(&mut self, kind: EdgeKind) -> Result<Fragment, LowerError> {
        let state = self.add_state(StateRole::Split)?;
        let patch = self.add_edge(state, kind, 0, 0, None)?;
        Ok(Fragment {
            start: state,
            outs: self.singleton_patch(patch, "assertion patch list")?,
        })
    }

    fn literal_fragment(&mut self, bytes: &[u8]) -> Result<Fragment, LowerError> {
        let Some((&first, rest)) = bytes.split_first() else {
            return self.empty_fragment();
        };
        let start = self.add_state(StateRole::Consume)?;
        let mut last = self.add_edge(start, EdgeKind::ByteRange, first, first, None)?;
        for &byte in rest {
            let state = self.add_state(StateRole::Consume)?;
            self.patch(last, state)?;
            last = self.add_edge(state, EdgeKind::ByteRange, byte, byte, None)?;
        }
        Ok(Fragment {
            start,
            outs: self.singleton_patch(last, "literal patch list")?,
        })
    }

    fn class_fragment<I>(&mut self, ranges: I) -> Result<Fragment, LowerError>
    where
        I: IntoIterator<Item = (u8, u8)>,
    {
        let state = self.add_state(StateRole::Consume)?;
        let mut outs = Vec::new();
        for (start, end) in ranges {
            let patch = self.add_edge(state, EdgeKind::ByteRange, start, end, None)?;
            self.charge_vector_growth(outs.len(), outs.capacity(), 1, "class patch list")?;
            reserve(&mut outs, 1, "class patch list")?;
            outs.push(patch);
        }
        Ok(Fragment { start: state, outs })
    }

    fn unicode_class_fragment(&mut self, class: &ClassUnicode) -> Result<Fragment, LowerError> {
        let mut branches = Vec::new();
        for scalar_range in class.ranges() {
            self.charge(
                Self::UTF8_SCALAR_RANGE_PARTITION_WORK,
                "Unicode scalar range partition",
            )?;
            for sequence in Utf8Sequences::new(scalar_range.start(), scalar_range.end()) {
                self.charge(1, "UTF-8 sequence traversal")?;
                let mut parts = Vec::new();
                self.charge_vector_growth(
                    parts.len(),
                    parts.capacity(),
                    sequence.len(),
                    "UTF-8 sequence fragment list",
                )?;
                reserve(&mut parts, sequence.len(), "UTF-8 sequence fragment list")?;
                for range in sequence.as_slice() {
                    parts.push(self.class_fragment(core::iter::once((range.start, range.end)))?);
                }
                let branch = self.concat_fragments(parts)?;
                self.charge_vector_growth(
                    branches.len(),
                    branches.capacity(),
                    1,
                    "Unicode class branch list",
                )?;
                reserve(&mut branches, 1, "Unicode class branch list")?;
                branches.push(branch);
            }
        }
        if branches.is_empty() {
            return self.class_fragment(core::iter::empty());
        }
        self.alternation_fragment(branches)
    }

    fn optional_fragment(&mut self, child: Fragment, greedy: bool) -> Result<Fragment, LowerError> {
        let split = self.add_state(StateRole::Split)?;
        let skip;
        if greedy {
            self.add_edge(split, EdgeKind::Epsilon, 0, 0, Some(child.start))?;
            skip = self.add_edge(split, EdgeKind::Epsilon, 0, 0, None)?;
        } else {
            skip = self.add_edge(split, EdgeKind::Epsilon, 0, 0, None)?;
            self.add_edge(split, EdgeKind::Epsilon, 0, 0, Some(child.start))?;
        }
        let mut outs = child.outs;
        self.charge_vector_growth(outs.len(), outs.capacity(), 1, "optional patch list")?;
        reserve(&mut outs, 1, "optional patch list")?;
        outs.push(skip);
        Ok(Fragment { start: split, outs })
    }

    fn star_fragment(&mut self, child: &Fragment, greedy: bool) -> Result<Fragment, LowerError> {
        let split = self.add_state(StateRole::Split)?;
        let skip;
        if greedy {
            self.add_edge(split, EdgeKind::Epsilon, 0, 0, Some(child.start))?;
            skip = self.add_edge(split, EdgeKind::Epsilon, 0, 0, None)?;
        } else {
            skip = self.add_edge(split, EdgeKind::Epsilon, 0, 0, None)?;
            self.add_edge(split, EdgeKind::Epsilon, 0, 0, Some(child.start))?;
        }
        self.patch_all(&child.outs, split)?;
        Ok(Fragment {
            start: split,
            outs: self.singleton_patch(skip, "star patch list")?,
        })
    }

    fn plus_fragment(&mut self, child: &Fragment, greedy: bool) -> Result<Fragment, LowerError> {
        let split = self.add_state(StateRole::Split)?;
        let skip;
        if greedy {
            self.add_edge(split, EdgeKind::Epsilon, 0, 0, Some(child.start))?;
            skip = self.add_edge(split, EdgeKind::Epsilon, 0, 0, None)?;
        } else {
            skip = self.add_edge(split, EdgeKind::Epsilon, 0, 0, None)?;
            self.add_edge(split, EdgeKind::Epsilon, 0, 0, Some(child.start))?;
        }
        self.patch_all(&child.outs, split)?;
        Ok(Fragment {
            start: child.start,
            outs: self.singleton_patch(skip, "plus patch list")?,
        })
    }

    fn concat_fragments(&mut self, parts: Vec<Fragment>) -> Result<Fragment, LowerError> {
        if parts.is_empty() {
            return self.empty_fragment();
        }
        self.charge_usize(parts.len(), "concatenation fragment traversal")?;
        let mut parts = parts.into_iter();
        let first = parts.next().ok_or(LowerError::InternalInvariant {
            detail: "nonempty concatenation lost its first fragment",
        })?;
        let start = first.start;
        let mut outs = first.outs;
        for part in parts {
            self.patch_all(&outs, part.start)?;
            outs = part.outs;
        }
        Ok(Fragment { start, outs })
    }

    fn take_fragments(&mut self, count: usize) -> Result<Vec<Fragment>, LowerError> {
        let begin =
            self.fragments
                .len()
                .checked_sub(count)
                .ok_or(LowerError::InternalInvariant {
                    detail: "postorder fragment stack underflow",
                })?;
        self.charge_usize(count, "fragment stack split")?;
        Ok(self.fragments.split_off(begin))
    }

    fn push_task(&mut self, task: Task<'h>) -> Result<(), LowerError> {
        self.check_stack_growth(1)?;
        self.charge_vector_growth(
            self.tasks.len(),
            self.tasks.capacity(),
            1,
            "lowering task stack",
        )?;
        reserve(&mut self.tasks, 1, "lowering task stack")?;
        self.tasks.push(task);
        self.record_stack_peak()
    }

    fn push_fragment(&mut self, fragment: Fragment) -> Result<(), LowerError> {
        self.check_stack_growth(1)?;
        self.charge_vector_growth(
            self.fragments.len(),
            self.fragments.capacity(),
            1,
            "lowering fragment stack",
        )?;
        reserve(&mut self.fragments, 1, "lowering fragment stack")?;
        self.fragments.push(fragment);
        self.record_stack_peak()
    }

    fn check_stack_growth(&self, additional: usize) -> Result<(), LowerError> {
        let needed = self
            .tasks
            .len()
            .checked_add(self.fragments.len())
            .and_then(|value| value.checked_add(additional))
            .ok_or(LowerError::ArithmeticOverflow {
                computation: "explicit stack occupancy",
            })?;
        if needed > self.limits.max_stack_items {
            return Err(resource_limit(
                LowerResource::StackItems,
                needed,
                self.limits.max_stack_items,
            ));
        }
        Ok(())
    }

    fn record_stack_peak(&mut self) -> Result<(), LowerError> {
        let current = self.tasks.len().checked_add(self.fragments.len()).ok_or(
            LowerError::ArithmeticOverflow {
                computation: "explicit stack peak",
            },
        )?;
        self.peak_stack_items = self.peak_stack_items.max(current);
        Ok(())
    }

    fn charge(&mut self, amount: u64, _phase: &'static str) -> Result<(), LowerError> {
        let needed = self
            .work
            .checked_add(amount)
            .ok_or(LowerError::ArithmeticOverflow {
                computation: "lowering work counter",
            })?;
        if needed > self.limits.max_work {
            return Err(LowerError::ResourceLimit {
                resource: LowerResource::Work,
                needed,
                limit: self.limits.max_work,
            });
        }
        self.work = needed;
        Ok(())
    }

    fn charge_usize(&mut self, amount: usize, phase: &'static str) -> Result<(), LowerError> {
        let amount = u64::try_from(amount).map_err(|_| LowerError::ArithmeticOverflow {
            computation: "lowering work amount conversion",
        })?;
        self.charge(amount, phase)
    }

    fn charge_vector_growth(
        &mut self,
        len: usize,
        capacity: usize,
        additional: usize,
        phase: &'static str,
    ) -> Result<(), LowerError> {
        let needed = len
            .checked_add(additional)
            .ok_or(LowerError::ArithmeticOverflow {
                computation: "vector growth length",
            })?;
        if needed > capacity {
            self.charge_usize(len, phase)?;
        }
        self.charge_usize(additional, phase)
    }

    fn charge_final_table_writes(&mut self) -> Result<(), LowerError> {
        let state_items = self
            .states
            .len()
            .checked_mul(2)
            .and_then(|value| value.checked_add(1))
            .ok_or(LowerError::ArithmeticOverflow {
                computation: "final state table item count",
            })?;
        let edge_items = self
            .edges
            .checked_mul(4)
            .ok_or(LowerError::ArithmeticOverflow {
                computation: "final edge table item count",
            })?;
        let items = state_items
            .checked_add(edge_items)
            .ok_or(LowerError::ArithmeticOverflow {
                computation: "final table item count",
            })?;
        self.charge_usize(items, "final CSR table writes")
    }

    fn singleton_patch(
        &mut self,
        patch: Patch,
        structure: &'static str,
    ) -> Result<Vec<Patch>, LowerError> {
        let mut patches = Vec::new();
        self.charge_vector_growth(patches.len(), patches.capacity(), 1, structure)?;
        reserve(&mut patches, 1, structure)?;
        patches.push(patch);
        Ok(patches)
    }

    fn append_patches(
        &mut self,
        destination: &mut Vec<Patch>,
        mut source: Vec<Patch>,
        structure: &'static str,
    ) -> Result<(), LowerError> {
        self.charge_vector_growth(
            destination.len(),
            destination.capacity(),
            source.len(),
            structure,
        )?;
        reserve(destination, source.len(), structure)?;
        destination.append(&mut source);
        Ok(())
    }

    fn add_state(&mut self, role: StateRole) -> Result<u32, LowerError> {
        self.charge(1, "state emission")?;
        let needed = self
            .states
            .len()
            .checked_add(1)
            .ok_or(LowerError::ArithmeticOverflow {
                computation: "state count",
            })?;
        let index_limit = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
        let limit = self.limits.automata.max_states.min(index_limit);
        if needed > limit {
            return Err(resource_limit(LowerResource::States, needed, limit));
        }
        self.charge_vector_growth(
            self.states.len(),
            self.states.capacity(),
            1,
            "mutable state table",
        )?;
        reserve(&mut self.states, 1, "mutable state table")?;
        let index =
            u32::try_from(self.states.len()).map_err(|_| LowerError::ArithmeticOverflow {
                computation: "state index conversion",
            })?;
        self.states.push(MutableState {
            role,
            edges: Vec::new(),
        });
        Ok(index)
    }

    fn add_edge(
        &mut self,
        state: u32,
        kind: EdgeKind,
        byte_start: u8,
        byte_end: u8,
        target: Option<u32>,
    ) -> Result<Patch, LowerError> {
        self.charge(1, "edge emission")?;
        let needed = self
            .edges
            .checked_add(1)
            .ok_or(LowerError::ArithmeticOverflow {
                computation: "edge count",
            })?;
        let index_limit = usize::try_from(u32::MAX).unwrap_or(usize::MAX);
        let limit = self.limits.automata.max_edges.min(index_limit);
        if needed > limit {
            return Err(resource_limit(LowerResource::Edges, needed, limit));
        }
        let state_index = lower_index(state)?;
        let (source_len, source_capacity) = self
            .states
            .get(state_index)
            .map(|state| (state.edges.len(), state.edges.capacity()))
            .ok_or(LowerError::InternalInvariant {
                detail: "edge source state was absent",
            })?;
        self.charge_vector_growth(source_len, source_capacity, 1, "mutable edge table")?;
        let mutable = self
            .states
            .get_mut(state_index)
            .ok_or(LowerError::InternalInvariant {
                detail: "edge source state was absent",
            })?;
        reserve(&mut mutable.edges, 1, "mutable edge table")?;
        let edge = mutable.edges.len();
        mutable.edges.push(MutableEdge {
            target,
            kind,
            byte_start,
            byte_end,
        });
        self.edges = needed;
        Ok(Patch { state, edge })
    }

    fn patch_all(&mut self, patches: &[Patch], target: u32) -> Result<(), LowerError> {
        for &patch in patches {
            self.patch(patch, target)?;
        }
        Ok(())
    }

    fn patch(&mut self, patch: Patch, target: u32) -> Result<(), LowerError> {
        self.charge(1, "edge patch")?;
        let state_index = lower_index(patch.state)?;
        let edge = self
            .states
            .get_mut(state_index)
            .and_then(|state| state.edges.get_mut(patch.edge))
            .ok_or(LowerError::InternalInvariant {
                detail: "dangling edge patch referred to an absent edge",
            })?;
        if edge.target.replace(target).is_some() {
            return Err(LowerError::InternalInvariant {
                detail: "an edge was patched more than once",
            });
        }
        Ok(())
    }

    fn into_raw(self, start: u32) -> Result<RawPlan, LowerError> {
        let states = self.states.len();
        let edges = self.edges;
        preflight_final_tables(states, edges, self.limits)?;

        let mut roles = Vec::new();
        reserve_exact(&mut roles, states, "raw role table")?;
        let mut edge_offsets = Vec::new();
        reserve_exact(
            &mut edge_offsets,
            states.saturating_add(1),
            "raw offset table",
        )?;
        let mut edge_targets = Vec::new();
        reserve_exact(&mut edge_targets, edges, "raw edge target table")?;
        let mut edge_kinds = Vec::new();
        reserve_exact(&mut edge_kinds, edges, "raw edge kind table")?;
        let mut byte_starts = Vec::new();
        reserve_exact(&mut byte_starts, edges, "raw byte-start table")?;
        let mut byte_ends = Vec::new();
        reserve_exact(&mut byte_ends, edges, "raw byte-end table")?;

        edge_offsets.push(0);
        for state in self.states {
            roles.push(state.role);
            for edge in state.edges {
                edge_targets.push(edge.target.ok_or(LowerError::InternalInvariant {
                    detail: "unpatched edge remained at table finalization",
                })?);
                edge_kinds.push(edge.kind);
                byte_starts.push(edge.byte_start);
                byte_ends.push(edge.byte_end);
            }
            edge_offsets.push(u32::try_from(edge_targets.len()).map_err(|_| {
                LowerError::ArithmeticOverflow {
                    computation: "CSR edge offset conversion",
                }
            })?);
        }
        Ok(RawPlan {
            start,
            roles,
            edge_offsets,
            edge_targets,
            edge_kinds,
            byte_starts,
            byte_ends,
        })
    }
}

fn preflight_final_tables(
    states: usize,
    edges: usize,
    limits: LowerLimits,
) -> Result<(), LowerError> {
    let validation_work = states
        .checked_mul(2)
        .and_then(|value| {
            edges
                .checked_mul(2)
                .and_then(|tail| value.checked_add(tail))
        })
        .and_then(|value| value.checked_add(1))
        .ok_or(LowerError::ArithmeticOverflow {
            computation: "automaton validation work",
        })?;
    if validation_work > limits.automata.max_validation_work {
        return Err(resource_limit(
            LowerResource::ValidationWork,
            validation_work,
            limits.automata.max_validation_work,
        ));
    }

    let offsets = states
        .checked_add(1)
        .and_then(|count| count.checked_mul(size_of::<u32>()))
        .ok_or(LowerError::ArithmeticOverflow {
            computation: "raw offset storage",
        })?;
    let roles =
        states
            .checked_mul(size_of::<StateRole>())
            .ok_or(LowerError::ArithmeticOverflow {
                computation: "raw role storage",
            })?;
    let per_edge = size_of::<u32>()
        .checked_add(size_of::<EdgeKind>())
        .and_then(|value| {
            size_of::<u8>()
                .checked_mul(2)
                .and_then(|bytes| value.checked_add(bytes))
        })
        .ok_or(LowerError::ArithmeticOverflow {
            computation: "raw edge width",
        })?;
    let edge_storage = edges
        .checked_mul(per_edge)
        .ok_or(LowerError::ArithmeticOverflow {
            computation: "raw edge storage",
        })?;
    let storage = offsets
        .checked_add(roles)
        .and_then(|value| value.checked_add(edge_storage))
        .ok_or(LowerError::ArithmeticOverflow {
            computation: "raw table storage",
        })?;
    if storage > limits.automata.max_storage_bytes {
        return Err(resource_limit(
            LowerResource::StorageBytes,
            storage,
            limits.automata.max_storage_bytes,
        ));
    }
    Ok(())
}

fn reserve<T>(
    values: &mut Vec<T>,
    additional: usize,
    structure: &'static str,
) -> Result<(), LowerError> {
    values
        .try_reserve(additional)
        .map_err(|_| LowerError::AllocationFailed {
            structure,
            additional,
        })
}

fn reserve_exact<T>(
    values: &mut Vec<T>,
    additional: usize,
    structure: &'static str,
) -> Result<(), LowerError> {
    values
        .try_reserve_exact(additional)
        .map_err(|_| LowerError::AllocationFailed {
            structure,
            additional,
        })
}

fn resource_limit(resource: LowerResource, needed: usize, limit: usize) -> LowerError {
    LowerError::ResourceLimit {
        resource,
        needed: u64::try_from(needed).unwrap_or(u64::MAX),
        limit: u64::try_from(limit).unwrap_or(u64::MAX),
    }
}

fn lower_index(value: u32) -> Result<usize, LowerError> {
    usize::try_from(value).map_err(|_| LowerError::ArithmeticOverflow {
        computation: "lowering state index conversion",
    })
}
