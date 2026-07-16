use std::collections::VecDeque;

use regex_syntax::hir::{Class, Hir, HirKind, Repetition};
use regex_syntax::utf8::Utf8Sequences;

use crate::accounting::CompileAccounting;
use crate::error::{add, enforce, mul};
use crate::program::{Assertion, ByteSet, Inst, NO_SPLIT_RANK, Program};
use crate::{CompileLimits, Error, Resource, Unsupported};

/// Explicit semantic profile asserted by direct HIR callers.
///
/// HIR intentionally does not retain every parser option. In particular, an
/// empty HIR cannot reveal whether Unicode mode was enabled. Passing this
/// token asserts both the pinned parser configuration and the empty-match
/// boundary policy. Unicode-on callers receive literals, byte classes, Unicode
/// scalar classes lowered to canonical UTF-8 paths, every pinned look
/// assertion, and their regular composition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RustByteProfile {
    unicode: bool,
}

impl RustByteProfile {
    /// Pinned Unicode-off production profile for regex 1.12.4 /
    /// regex-syntax 0.8.11 with byte-boundary empty matches.
    pub const PINNED_1_12_4: Self = Self { unicode: false };

    /// Pinned Unicode-on Rust-bytes profile with `utf8(false)` and
    /// `utf8_empty(false)`, with scalar classes lowered to canonical UTF-8.
    /// Positive Unicode word boundaries additionally require valid UTF-8 at
    /// operation admission.
    pub const PINNED_1_12_4_UNICODE_ON_BYTE_STABLE: Self = Self { unicode: true };

    const fn identity_domain(self) -> &'static [u8] {
        if self.unicode {
            b"fre.aggregate.rust.bytes.unicode-on-utf8-scalar.v2"
        } else {
            // Preserve the pre-existing Unicode-off identities exactly.
            b"fre.aggregate.rust.bytes.unicode-off.v2"
        }
    }
}

/// Stable identity of the semantic continuation program.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PlanId(pub(crate) [u8; 16]);

impl PlanId {
    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

impl core::fmt::Display for PlanId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Validated capture-free continuation program.
#[derive(Debug)]
pub struct CompiledRegex {
    pub(crate) program: Program,
    plan_id: PlanId,
    accounting: CompileAccounting,
}

impl CompiledRegex {
    /// Compile canonical HIR for the explicit pinned byte profile.
    ///
    /// Validation first proves a depth bound. Lowering recursion is therefore
    /// bounded by `limits.max_hir_depth`; repetition expansion itself is
    /// iterative and separately limited.
    pub fn from_hir(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
    ) -> Result<Self, Error> {
        Self::compile(hir, profile, limits, CapturePolicy::Reject)
    }

    /// Compile canonical HIR for an API that exposes whole-match values only.
    ///
    /// Capture annotations are semantically transparent for whole-match spans,
    /// counts and matched-byte sums. This entry point handles them directly in
    /// the already bounded validation and lowering traversals: it neither
    /// clones the HIR nor allocates a capture-free copy. The exact number of
    /// annotations and transparent traversal steps is reported in
    /// [`CompileAccounting`]. Callers must not use this plan to implement a
    /// capture group API.
    pub fn from_hir_erasing_captures_for_whole_match(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
    ) -> Result<Self, Error> {
        Self::compile(hir, profile, limits, CapturePolicy::EraseForWholeMatch)
    }

    fn compile(
        hir: &Hir,
        profile: RustByteProfile,
        limits: CompileLimits,
        capture_policy: CapturePolicy,
    ) -> Result<Self, Error> {
        let mut budget = CompileBudget::new(limits);
        validate_hir(hir, profile, capture_policy, &mut budget)?;
        let mut builder = Builder::new(
            limits.max_program_states,
            profile,
            capture_policy,
            &mut budget,
        );
        let accept = builder.push(Inst::Match)?;
        let entry = builder.compile_node(hir, accept, 1)?;
        let insts = builder.finish()?;
        enforce(
            insts.len(),
            limits.max_program_states,
            Resource::ProgramStates,
        )?;
        let (epsilon_order, split_rank, split_count) = certify_program(&insts, &mut budget)?;
        let program_bytes = program_bytes(
            insts.capacity(),
            epsilon_order.capacity(),
            split_rank.capacity(),
        )?;
        enforce(
            program_bytes,
            limits.max_program_bytes,
            Resource::ProgramBytes,
        )?;
        budget.accounting.program_states = insts.len();
        budget.accounting.program_bytes = program_bytes;
        let program = Program {
            insts,
            entry,
            epsilon_order,
            split_rank,
            split_count,
        };
        let plan_id = plan_identity(&program, profile, &mut budget)?;
        let accounting = budget.finish();
        Ok(Self {
            program,
            plan_id,
            accounting,
        })
    }

    #[must_use]
    pub const fn plan_id(&self) -> PlanId {
        self.plan_id
    }

    #[must_use]
    pub const fn compile_accounting(&self) -> CompileAccounting {
        self.accounting
    }

    #[must_use]
    pub fn state_count(&self) -> usize {
        self.program.insts.len()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapturePolicy {
    Reject,
    EraseForWholeMatch,
}

struct CompileBudget {
    limits: CompileLimits,
    accounting: CompileAccounting,
    current_temporary_states: usize,
}

impl CompileBudget {
    const fn new(limits: CompileLimits) -> Self {
        Self {
            limits,
            accounting: CompileAccounting {
                hir_nodes: 0,
                hir_depth: 0,
                peak_hir_stack_items: 0,
                captures_erased: 0,
                capture_erasure_work: 0,
                literal_bytes: 0,
                class_ranges: 0,
                utf8_sequences: 0,
                utf8_byte_ranges: 0,
                look_assertions: 0,
                program_states: 0,
                temporary_states_peak: 0,
                program_bytes: 0,
                work: 0,
            },
            current_temporary_states: 0,
        }
    }

    fn charge(&mut self, amount: usize) -> Result<(), Error> {
        let required = add(self.accounting.work, amount, Resource::CompileWork)?;
        enforce(required, self.limits.max_work, Resource::CompileWork)?;
        self.accounting.work = required;
        Ok(())
    }

    fn acquire_state(&mut self) -> Result<(), Error> {
        let current = add(self.current_temporary_states, 1, Resource::TemporaryStates)?;
        enforce(
            current,
            self.limits.max_temporary_states,
            Resource::TemporaryStates,
        )?;
        self.current_temporary_states = current;
        self.accounting.temporary_states_peak = self.accounting.temporary_states_peak.max(current);
        self.charge(1)
    }

    fn release_states(&mut self, count: usize) -> Result<(), Error> {
        self.current_temporary_states =
            self.current_temporary_states
                .checked_sub(count)
                .ok_or(Error::InternalInvariant(
                    "temporary state accounting underflow",
                ))?;
        Ok(())
    }

    fn record_capture_erasure(&mut self, unique_annotation: bool) -> Result<(), Error> {
        self.accounting.capture_erasure_work = add(
            self.accounting.capture_erasure_work,
            1,
            Resource::CompileWork,
        )?;
        if unique_annotation {
            self.accounting.captures_erased =
                add(self.accounting.captures_erased, 1, Resource::HirNodes)?;
        }
        Ok(())
    }

    fn record_look_assertion(&mut self) -> Result<(), Error> {
        self.accounting.look_assertions =
            add(self.accounting.look_assertions, 1, Resource::LookAssertions)?;
        enforce(
            self.accounting.look_assertions,
            self.limits.max_look_assertions,
            Resource::LookAssertions,
        )
    }

    fn finish(self) -> CompileAccounting {
        self.accounting
    }
}

fn validate_hir(
    hir: &Hir,
    profile: RustByteProfile,
    capture_policy: CapturePolicy,
    budget: &mut CompileBudget,
) -> Result<(), Error> {
    let mut stack = Vec::new();
    stack
        .try_reserve_exact(1)
        .map_err(|_| Error::AllocationFailed {
            resource: Resource::HirStackItems,
            items: 1,
        })?;
    enforce(
        1,
        budget.limits.max_hir_stack_items,
        Resource::HirStackItems,
    )?;
    stack.push((hir, 1_usize));
    budget.accounting.peak_hir_stack_items = 1;
    while let Some((node, depth)) = stack.pop() {
        budget.charge(1)?;
        budget.accounting.hir_nodes = add(budget.accounting.hir_nodes, 1, Resource::HirNodes)?;
        enforce(
            budget.accounting.hir_nodes,
            budget.limits.max_hir_nodes,
            Resource::HirNodes,
        )?;
        enforce(depth, budget.limits.max_hir_depth, Resource::HirDepth)?;
        budget.accounting.hir_depth = budget.accounting.hir_depth.max(depth);
        match node.kind() {
            HirKind::Empty => {}
            HirKind::Literal(literal) => {
                budget.charge(literal.0.len())?;
                budget.accounting.literal_bytes = add(
                    budget.accounting.literal_bytes,
                    literal.0.len(),
                    Resource::LiteralBytes,
                )?;
                enforce(
                    budget.accounting.literal_bytes,
                    budget.limits.max_literal_bytes,
                    Resource::LiteralBytes,
                )?;
            }
            HirKind::Class(Class::Unicode(class)) => {
                validate_unicode_class(class, profile, budget)?;
            }
            HirKind::Class(Class::Bytes(class)) => {
                let ranges = class.ranges().len();
                budget.charge(ranges)?;
                budget.accounting.class_ranges = add(
                    budget.accounting.class_ranges,
                    ranges,
                    Resource::ClassRanges,
                )?;
                enforce(
                    budget.accounting.class_ranges,
                    budget.limits.max_class_ranges,
                    Resource::ClassRanges,
                )?;
            }
            HirKind::Look(_) => {
                budget.record_look_assertion()?;
            }
            HirKind::Capture(capture) => match capture_policy {
                CapturePolicy::Reject => return Err(Error::Unsupported(Unsupported::Capture)),
                CapturePolicy::EraseForWholeMatch => {
                    budget.record_capture_erasure(true)?;
                    push_children(&mut stack, [capture.sub.as_ref()], depth, budget)?;
                }
            },
            HirKind::Repetition(repetition) => {
                validate_repetition(repetition, budget)?;
                push_children(&mut stack, [repetition.sub.as_ref()], depth, budget)?;
            }
            HirKind::Concat(children) | HirKind::Alternation(children) => {
                if matches!(node.kind(), HirKind::Alternation(_)) && children.is_empty() {
                    return Err(Error::EmptyAlternation);
                }
                push_children(&mut stack, children.iter(), depth, budget)?;
            }
        }
    }
    Ok(())
}

fn validate_unicode_class(
    class: &regex_syntax::hir::ClassUnicode,
    profile: RustByteProfile,
    budget: &mut CompileBudget,
) -> Result<(), Error> {
    if !profile.unicode && class.ranges().iter().any(|range| !range.end().is_ascii()) {
        return Err(Error::Unsupported(Unsupported::UnicodeClass));
    }
    let ranges = class.ranges().len();
    budget.charge(ranges)?;
    budget.accounting.class_ranges = add(
        budget.accounting.class_ranges,
        ranges,
        Resource::ClassRanges,
    )?;
    enforce(
        budget.accounting.class_ranges,
        budget.limits.max_class_ranges,
        Resource::ClassRanges,
    )?;
    if profile.unicode {
        for range in class.ranges() {
            for sequence in Utf8Sequences::new(range.start(), range.end()) {
                budget.charge(1)?;
                budget.accounting.utf8_sequences =
                    add(budget.accounting.utf8_sequences, 1, Resource::Utf8Sequences)?;
                enforce(
                    budget.accounting.utf8_sequences,
                    budget.limits.max_utf8_sequences,
                    Resource::Utf8Sequences,
                )?;
                let byte_ranges = sequence.as_slice().len();
                budget.charge(byte_ranges)?;
                budget.accounting.utf8_byte_ranges = add(
                    budget.accounting.utf8_byte_ranges,
                    byte_ranges,
                    Resource::Utf8ByteRanges,
                )?;
                enforce(
                    budget.accounting.utf8_byte_ranges,
                    budget.limits.max_utf8_byte_ranges,
                    Resource::Utf8ByteRanges,
                )?;
            }
        }
    }
    Ok(())
}

fn push_children<'a>(
    stack: &mut Vec<(&'a Hir, usize)>,
    children: impl IntoIterator<Item = &'a Hir>,
    depth: usize,
    budget: &mut CompileBudget,
) -> Result<(), Error> {
    let next_depth = add(depth, 1, Resource::HirDepth)?;
    for child in children {
        let required = add(stack.len(), 1, Resource::HirStackItems)?;
        enforce(
            required,
            budget.limits.max_hir_stack_items,
            Resource::HirStackItems,
        )?;
        stack.try_reserve(1).map_err(|_| Error::AllocationFailed {
            resource: Resource::HirStackItems,
            items: 1,
        })?;
        stack.push((child, next_depth));
        budget.accounting.peak_hir_stack_items =
            budget.accounting.peak_hir_stack_items.max(stack.len());
        budget.charge(1)?;
    }
    Ok(())
}

fn validate_repetition(repetition: &Repetition, budget: &mut CompileBudget) -> Result<(), Error> {
    if repetition
        .max
        .is_some_and(|maximum| maximum < repetition.min)
    {
        return Err(Error::InvalidRepetition);
    }
    let largest = repetition.max.unwrap_or(repetition.min);
    let required = usize::try_from(largest).map_err(|_| Error::ArithmeticOverflow {
        resource: Resource::RepeatBound,
    })?;
    let limit =
        usize::try_from(budget.limits.max_repeat_bound).map_err(|_| Error::ArithmeticOverflow {
            resource: Resource::RepeatBound,
        })?;
    enforce(required, limit, Resource::RepeatBound)
}

struct Builder<'a> {
    slots: Vec<Inst>,
    state_limit: usize,
    profile: RustByteProfile,
    capture_policy: CapturePolicy,
    budget: &'a mut CompileBudget,
}

impl<'a> Builder<'a> {
    fn new(
        state_limit: usize,
        profile: RustByteProfile,
        capture_policy: CapturePolicy,
        budget: &'a mut CompileBudget,
    ) -> Self {
        Self {
            slots: Vec::new(),
            state_limit,
            profile,
            capture_policy,
            budget,
        }
    }

    fn push(&mut self, inst: Inst) -> Result<usize, Error> {
        let required = add(self.slots.len(), 1, Resource::ProgramStates)?;
        enforce(required, self.state_limit, Resource::ProgramStates)?;
        self.budget.acquire_state()?;
        self.slots
            .try_reserve(1)
            .map_err(|_| Error::AllocationFailed {
                resource: Resource::TemporaryStates,
                items: 1,
            })?;
        let index = self.slots.len();
        self.slots.push(inst);
        Ok(index)
    }

    fn finish(self) -> Result<Vec<Inst>, Error> {
        if self.slots.iter().any(|inst| matches!(inst, Inst::Unfilled)) {
            return Err(Error::InternalInvariant("unfilled compiler state"));
        }
        Ok(self.slots)
    }

    fn compile_node(
        &mut self,
        hir: &Hir,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        enforce(depth, self.budget.limits.max_hir_depth, Resource::HirDepth)?;
        self.budget.charge(1)?;
        let child_depth = add(depth, 1, Resource::HirDepth)?;
        match hir.kind() {
            HirKind::Empty => Ok(continuation),
            HirKind::Literal(literal) => {
                let mut next = continuation;
                for &byte in literal.0.iter().rev() {
                    let mut bytes = ByteSet::empty();
                    bytes.insert(byte);
                    next = self.push(Inst::Consume { bytes, next })?;
                }
                Ok(next)
            }
            HirKind::Class(Class::Bytes(class)) => {
                let mut bytes = ByteSet::empty();
                for range in class.ranges() {
                    self.budget
                        .charge(inclusive_byte_width(range.start(), range.end())?)?;
                    bytes.insert_range(range.start(), range.end());
                }
                self.push(Inst::Consume {
                    bytes,
                    next: continuation,
                })
            }
            HirKind::Class(Class::Unicode(class)) => {
                self.compile_unicode_class(class, continuation)
            }
            HirKind::Look(look) => {
                let assertion = Assertion::from_look(*look);
                self.push(Inst::Assert {
                    assertion,
                    next: continuation,
                })
            }
            HirKind::Capture(capture) => match self.capture_policy {
                CapturePolicy::Reject => Err(Error::Unsupported(Unsupported::Capture)),
                CapturePolicy::EraseForWholeMatch => {
                    self.budget.record_capture_erasure(false)?;
                    self.compile_node(capture.sub.as_ref(), continuation, child_depth)
                }
            },
            HirKind::Concat(children) => {
                let mut next = continuation;
                for child in children.iter().rev() {
                    next = self.compile_node(child, next, child_depth)?;
                }
                Ok(next)
            }
            HirKind::Alternation(children) => {
                let Some((last, preceding)) = children.split_last() else {
                    return Err(Error::EmptyAlternation);
                };
                let mut fallback = self.compile_node(last, continuation, child_depth)?;
                for child in preceding.iter().rev() {
                    let preferred = self.compile_node(child, continuation, child_depth)?;
                    fallback = self.push(Inst::Split {
                        preferred,
                        fallback,
                    })?;
                }
                Ok(fallback)
            }
            HirKind::Repetition(repetition) => {
                self.compile_repetition(repetition, continuation, child_depth)
            }
        }
    }

    fn compile_unicode_class(
        &mut self,
        class: &regex_syntax::hir::ClassUnicode,
        continuation: usize,
    ) -> Result<usize, Error> {
        if self.profile.unicode {
            let mut fallback = None;
            for range in class.ranges() {
                // These paths are disjoint. Stable source order affects only
                // plan identity, not leftmost-first selection.
                for sequence in Utf8Sequences::new(range.start(), range.end()) {
                    let mut next = continuation;
                    for byte_range in sequence.as_slice().iter().rev() {
                        self.budget
                            .charge(inclusive_byte_width(byte_range.start, byte_range.end)?)?;
                        let mut bytes = ByteSet::empty();
                        bytes.insert_range(byte_range.start, byte_range.end);
                        next = self.push(Inst::Consume { bytes, next })?;
                    }
                    fallback = Some(match fallback {
                        None => next,
                        Some(previous) => self.push(Inst::Split {
                            preferred: next,
                            fallback: previous,
                        })?,
                    });
                }
            }
            return fallback.ok_or(Error::InternalInvariant("empty Unicode scalar class"));
        }

        let mut entry = None;
        for range in class.ranges() {
            let start = u8::try_from(u32::from(range.start()))
                .map_err(|_| Error::Unsupported(Unsupported::UnicodeClass))?;
            let end = u8::try_from(u32::from(range.end()))
                .map_err(|_| Error::Unsupported(Unsupported::UnicodeClass))?;
            self.budget.charge(inclusive_byte_width(start, end)?)?;
            let mut bytes = ByteSet::empty();
            bytes.insert_range(start, end);
            let next = self.push(Inst::Consume {
                bytes,
                next: continuation,
            })?;
            entry = Some(match entry {
                None => next,
                Some(preferred) => self.push(Inst::Split {
                    preferred,
                    fallback: next,
                })?,
            });
        }
        entry.ok_or(Error::InternalInvariant("empty Unicode scalar class"))
    }

    fn compile_repetition(
        &mut self,
        repetition: &Repetition,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        let Some(maximum) = repetition.max else {
            return self.compile_unbounded(
                repetition.sub.as_ref(),
                repetition.min,
                repetition.greedy,
                continuation,
                depth,
            );
        };
        let optional = maximum
            .checked_sub(repetition.min)
            .ok_or(Error::InvalidRepetition)?;
        let mut next = continuation;
        for _ in 0..optional {
            let child_entry = self.compile_node(repetition.sub.as_ref(), next, depth)?;
            let (preferred, fallback) = if repetition.greedy {
                (child_entry, next)
            } else {
                (next, child_entry)
            };
            next = self.push(Inst::Split {
                preferred,
                fallback,
            })?;
        }
        for _ in 0..repetition.min {
            next = self.compile_node(repetition.sub.as_ref(), next, depth)?;
        }
        Ok(next)
    }

    fn compile_unbounded(
        &mut self,
        child: &Hir,
        minimum: u32,
        greedy: bool,
        continuation: usize,
        depth: usize,
    ) -> Result<usize, Error> {
        // Rust's empty-loop guard distinguishes a repetition before and after
        // it has consumed. In the initial mode, a zero-width body exits. In
        // the progressed mode, a zero-width body path fails so lower-priority
        // consuming paths are tried before the loop exit. A single loop entry
        // gets `(?:b|(?:|a))*` on `ba` wrong.
        let fail = self.push(Inst::Fail)?;
        let initial_loop = self.push(Inst::Unfilled)?;
        let progressed_loop = self.push(Inst::Unfilled)?;
        let (fragment, fragment_entry) = {
            let mut fragment_builder = Builder::new(
                self.state_limit,
                self.profile,
                self.capture_policy,
                self.budget,
            );
            let accept = fragment_builder.push(Inst::Match)?;
            let fragment_entry = fragment_builder.compile_node(child, accept, depth)?;
            (fragment_builder.finish()?, fragment_entry)
        };
        let fragment_len = fragment.len();
        let initial_body =
            self.import_progress_product(&fragment, fragment_entry, continuation, progressed_loop)?;
        let progressed_body =
            self.import_progress_product(&fragment, fragment_entry, fail, progressed_loop)?;
        self.budget.release_states(fragment_len)?;
        let (preferred, fallback) = if greedy {
            (initial_body, continuation)
        } else {
            (continuation, initial_body)
        };
        self.slots[initial_loop] = Inst::Split {
            preferred,
            fallback,
        };
        let (preferred, fallback) = if greedy {
            (progressed_body, continuation)
        } else {
            (continuation, progressed_body)
        };
        self.slots[progressed_loop] = Inst::Split {
            preferred,
            fallback,
        };
        if minimum == 0 {
            return Ok(initial_loop);
        }

        // Required iterations are finite, but their aggregate progress must
        // select the right mode for the open tail.
        let (required, required_entry) = {
            let mut fragment_builder = Builder::new(
                self.state_limit,
                self.profile,
                self.capture_policy,
                self.budget,
            );
            let accept = fragment_builder.push(Inst::Match)?;
            let mut entry = accept;
            for _ in 0..minimum {
                entry = fragment_builder.compile_node(child, entry, depth)?;
            }
            (fragment_builder.finish()?, entry)
        };
        let required_len = required.len();
        let entry =
            self.import_progress_product(&required, required_entry, initial_loop, progressed_loop)?;
        self.budget.release_states(required_len)?;
        Ok(entry)
    }

    fn import_progress_product(
        &mut self,
        fragment: &[Inst],
        fragment_entry: usize,
        zero_continuation: usize,
        consumed_continuation: usize,
    ) -> Result<usize, Error> {
        let mut zero_map = reserved_vec(fragment.len(), Resource::TemporaryStates)?;
        let mut consumed_map = reserved_vec(fragment.len(), Resource::TemporaryStates)?;
        for inst in fragment {
            if matches!(inst, Inst::Match) {
                zero_map.push(zero_continuation);
                consumed_map.push(consumed_continuation);
            } else {
                zero_map.push(self.push(Inst::Unfilled)?);
                consumed_map.push(self.push(Inst::Unfilled)?);
            }
        }
        for (pc, inst) in fragment.iter().enumerate() {
            self.budget.charge(1)?;
            if matches!(inst, Inst::Match) {
                continue;
            }
            self.slots[zero_map[pc]] = translate_progress(inst, &zero_map, &consumed_map, false)?;
            self.slots[consumed_map[pc]] =
                translate_progress(inst, &zero_map, &consumed_map, true)?;
        }
        zero_map
            .get(fragment_entry)
            .copied()
            .ok_or(Error::InternalInvariant("fragment entry outside fragment"))
    }
}

fn translate_progress(
    inst: &Inst,
    zero: &[usize],
    consumed: &[usize],
    has_consumed: bool,
) -> Result<Inst, Error> {
    let same = if has_consumed { consumed } else { zero };
    let mapped = |map: &[usize], pc: usize| {
        map.get(pc)
            .copied()
            .ok_or(Error::InternalInvariant("fragment target outside fragment"))
    };
    match inst {
        Inst::Unfilled => Err(Error::InternalInvariant("unfilled fragment state")),
        Inst::Fail => Ok(Inst::Fail),
        Inst::Match => Err(Error::InternalInvariant("translated fragment match")),
        Inst::Consume { bytes, next } => Ok(Inst::Consume {
            bytes: *bytes,
            next: mapped(consumed, *next)?,
        }),
        Inst::Assert { assertion, next } => Ok(Inst::Assert {
            assertion: *assertion,
            next: mapped(same, *next)?,
        }),
        Inst::Split {
            preferred,
            fallback,
        } => Ok(Inst::Split {
            preferred: mapped(same, *preferred)?,
            fallback: mapped(same, *fallback)?,
        }),
    }
}

type ProgramCertificate = (Vec<usize>, Vec<usize>, usize);

fn certify_program(
    insts: &[Inst],
    budget: &mut CompileBudget,
) -> Result<ProgramCertificate, Error> {
    let states = insts.len();
    let mut outgoing = zeroed_vec(states, Resource::TemporaryStates)?;
    let mut parent_counts = zeroed_vec(states, Resource::TemporaryStates)?;
    let mut edge_count = 0_usize;
    for (parent, inst) in insts.iter().enumerate() {
        for child in epsilon_targets(inst) {
            budget.charge(1)?;
            if child >= states {
                return Err(Error::InternalInvariant("epsilon target outside program"));
            }
            outgoing[parent] = add(outgoing[parent], 1, Resource::TemporaryStates)?;
            parent_counts[child] = add(parent_counts[child], 1, Resource::TemporaryStates)?;
            edge_count = add(edge_count, 1, Resource::TemporaryStates)?;
        }
    }
    let mut offsets = zeroed_vec(
        add(states, 1, Resource::TemporaryStates)?,
        Resource::TemporaryStates,
    )?;
    for index in 0..states {
        let next_index = add(index, 1, Resource::TemporaryStates)?;
        offsets[next_index] = add(
            offsets[index],
            parent_counts[index],
            Resource::TemporaryStates,
        )?;
    }
    let mut cursor = reserved_vec(states, Resource::TemporaryStates)?;
    cursor.extend_from_slice(&offsets[..states]);
    let mut parents = zeroed_vec(edge_count, Resource::TemporaryStates)?;
    for (parent, inst) in insts.iter().enumerate() {
        for child in epsilon_targets(inst) {
            let slot = cursor[child];
            parents[slot] = parent;
            cursor[child] = add(cursor[child], 1, Resource::TemporaryStates)?;
            budget.charge(1)?;
        }
    }
    let mut queue = VecDeque::new();
    queue
        .try_reserve(states)
        .map_err(|_| Error::AllocationFailed {
            resource: Resource::TemporaryStates,
            items: states,
        })?;
    for (state, count) in outgoing.iter().enumerate() {
        if *count == 0 {
            queue.push_back(state);
        }
    }
    let mut order = reserved_vec(states, Resource::TemporaryStates)?;
    while let Some(child) = queue.pop_front() {
        order.push(child);
        let next_child = add(child, 1, Resource::TemporaryStates)?;
        for &parent in &parents[offsets[child]..offsets[next_child]] {
            budget.charge(1)?;
            outgoing[parent] = outgoing[parent]
                .checked_sub(1)
                .ok_or(Error::SameBoundaryCycle)?;
            if outgoing[parent] == 0 {
                queue.push_back(parent);
            }
        }
    }
    if order.len() != states {
        return Err(Error::SameBoundaryCycle);
    }
    let mut split_rank = reserved_vec(states, Resource::TemporaryStates)?;
    let mut split_count = 0_usize;
    for inst in insts {
        budget.charge(1)?;
        if matches!(inst, Inst::Split { .. }) {
            split_rank.push(split_count);
            split_count = add(split_count, 1, Resource::ProgramStates)?;
        } else {
            split_rank.push(NO_SPLIT_RANK);
        }
    }
    Ok((order, split_rank, split_count))
}

fn epsilon_targets(inst: &Inst) -> impl Iterator<Item = usize> {
    let targets = match inst {
        Inst::Assert { next, .. } => [Some(*next), None],
        Inst::Split {
            preferred,
            fallback,
        } => [Some(*preferred), Some(*fallback)],
        Inst::Unfilled | Inst::Fail | Inst::Match | Inst::Consume { .. } => [None, None],
    };
    targets.into_iter().flatten()
}

fn program_bytes(states: usize, order: usize, ranks: usize) -> Result<usize, Error> {
    let insts = mul(states, core::mem::size_of::<Inst>(), Resource::ProgramBytes)?;
    let order = mul(order, core::mem::size_of::<usize>(), Resource::ProgramBytes)?;
    let ranks = mul(ranks, core::mem::size_of::<usize>(), Resource::ProgramBytes)?;
    add(
        add(insts, order, Resource::ProgramBytes)?,
        ranks,
        Resource::ProgramBytes,
    )
}

fn plan_identity(
    program: &Program,
    profile: RustByteProfile,
    budget: &mut CompileBudget,
) -> Result<PlanId, Error> {
    let mut first = StableHash::new(0xcbf2_9ce4_8422_2325);
    let mut second = StableHash::new(0x8422_2325_cbf2_9ce4);
    first.bytes(profile.identity_domain());
    second.bytes(profile.identity_domain());
    hash_usize(&mut first, program.entry);
    hash_usize(&mut second, program.entry);
    for inst in &program.insts {
        budget.charge(1)?;
        hash_inst(&mut first, inst);
        hash_inst(&mut second, inst);
    }
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&first.finish().to_le_bytes());
    bytes[8..].copy_from_slice(&second.finish().to_le_bytes());
    Ok(PlanId(bytes))
}

fn hash_inst(hash: &mut StableHash, inst: &Inst) {
    match inst {
        Inst::Unfilled => hash.byte(0),
        Inst::Fail => hash.byte(1),
        Inst::Match => hash.byte(2),
        Inst::Consume { bytes, next } => {
            hash.byte(3);
            for word in bytes.0 {
                hash.bytes(&word.to_le_bytes());
            }
            hash_usize(hash, *next);
        }
        Inst::Assert { assertion, next } => {
            hash.byte(4);
            hash.byte(assertion.identity_tag());
            hash_usize(hash, *next);
        }
        Inst::Split {
            preferred,
            fallback,
        } => {
            hash.byte(5);
            hash_usize(hash, *preferred);
            hash_usize(hash, *fallback);
        }
    }
}

fn hash_usize(hash: &mut StableHash, value: usize) {
    let canonical = u64::try_from(value).unwrap_or(u64::MAX);
    hash.bytes(&canonical.to_le_bytes());
}

fn inclusive_byte_width(start: u8, end: u8) -> Result<usize, Error> {
    let difference = end
        .checked_sub(start)
        .ok_or(Error::InternalInvariant("non-canonical byte class range"))?;
    add(usize::from(difference), 1, Resource::CompileWork)
}

struct StableHash(u64);

impl StableHash {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn byte(&mut self, byte: u8) {
        self.0 ^= u64::from(byte);
        self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.byte(byte);
        }
    }

    const fn finish(self) -> u64 {
        self.0
    }
}

fn reserved_vec<T>(length: usize, resource: Resource) -> Result<Vec<T>, Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|_| Error::AllocationFailed {
            resource,
            items: length,
        })?;
    Ok(values)
}

fn zeroed_vec(length: usize, resource: Resource) -> Result<Vec<usize>, Error> {
    let mut values = reserved_vec(length, resource)?;
    values.resize(length, 0);
    Ok(values)
}
