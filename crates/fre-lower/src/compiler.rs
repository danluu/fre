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

const fn assertion_edge_kind(look: Look) -> EdgeKind {
    match look {
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
        Look::WordUnicode => EdgeKind::AssertWordUnicode,
        Look::StartCRLF => EdgeKind::AssertLineStartCrlf,
        Look::EndCRLF => EdgeKind::AssertLineEndCrlf,
        Look::WordUnicodeNegate => EdgeKind::AssertWordUnicodeNegate,
        Look::WordStartUnicode => EdgeKind::AssertWordStartUnicode,
        Look::WordEndUnicode => EdgeKind::AssertWordEndUnicode,
        Look::WordStartHalfUnicode => EdgeKind::AssertWordStartHalfUnicode,
        Look::WordEndHalfUnicode => EdgeKind::AssertWordEndHalfUnicode,
    }
}

const fn nullable_initial_word_look(look: Look) -> bool {
    matches!(
        look,
        Look::WordAscii | Look::WordAsciiNegate | Look::WordUnicode
    )
}

#[derive(Clone, Copy)]
enum NullableRepetitionNormalization {
    Star { greedy: bool },
    LazyOptionalGreedyPlus,
    LazyGreedyOptionalThenStar,
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
    FinishOrderedWordLookAlternationPlus {
        look: Look,
    },
    FinishOrderedStartLookAlternationRepetition {
        look: Look,
        min: u32,
    },
    FinishOrderedEmptyAlternationRepetition {
        min: u32,
    },
    FinishLazyOptionalGreedyPlus,
    FinishLazyGreedyOptionalThenStar,
    FinishOrderedNullableAlternativeStar,
}

pub(crate) fn compile(
    hir: &Hir,
    operation: OperationSemantics,
    limits: LowerLimits,
    utf8_start_guarded: bool,
) -> Result<(RawPlan, LowerStats), LowerError> {
    if operation == OperationSemantics::CaptureSensitive {
        return Err(LowerError::Unsupported(
            UnsupportedFeature::CaptureSensitiveOperation,
        ));
    }
    Compiler::new(
        limits,
        hir.properties().explicit_captures_len(),
        utf8_start_guarded,
    )
    .run(hir)
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
    normalized_nullable_repetitions: usize,
    utf8_start_guarded: bool,
}

impl<'h> Compiler<'h> {
    // regex-syntax 0.8.11 partitions one scalar interval with a fixed-width
    // four-byte decomposition. Precharge its bounded private split stack; each
    // yielded sequence and all emitted graph work are charged separately.
    const UTF8_SCALAR_RANGE_PARTITION_WORK: u64 = 64;

    const fn new(limits: LowerLimits, erased_captures: usize, utf8_start_guarded: bool) -> Self {
        Self {
            limits,
            tasks: Vec::new(),
            fragments: Vec::new(),
            states: Vec::new(),
            edges: 0,
            work: 0,
            peak_stack_items: 0,
            erased_captures,
            normalized_nullable_repetitions: 0,
            utf8_start_guarded,
        }
    }

    fn run(mut self, hir: &'h Hir) -> Result<(RawPlan, LowerStats), LowerError> {
        let root = if let HirKind::Repetition(repetition) = hir.kind()
            && let Some(empty) =
                self.normalized_root_ordered_empty_alternation_repetition(repetition)?
        {
            self.increment_nullable_normalization_count()?;
            empty
        } else {
            hir
        };
        self.push_task(Task::Visit(root))?;
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
                Task::FinishOrderedWordLookAlternationPlus { look } => {
                    self.finish_ordered_word_look_alternation_plus(look)?;
                }
                Task::FinishOrderedStartLookAlternationRepetition { look, min } => {
                    self.finish_ordered_start_look_alternation_repetition(look, min)?;
                }
                Task::FinishOrderedEmptyAlternationRepetition { min } => {
                    self.finish_ordered_empty_alternation_repetition(min)?;
                }
                Task::FinishLazyOptionalGreedyPlus => {
                    self.finish_lazy_optional_greedy_plus()?;
                }
                Task::FinishLazyGreedyOptionalThenStar => {
                    self.finish_lazy_greedy_optional_then_star()?;
                }
                Task::FinishOrderedNullableAlternativeStar => {
                    self.finish_ordered_nullable_alternative_star()?;
                }
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
        let start = if self.utf8_start_guarded {
            let guard = self.utf8_start_guard_fragment()?;
            self.patch_all(&guard.outs, fragment.start)?;
            guard.start
        } else {
            fragment.start
        };
        let accept = self.add_state(StateRole::Accept)?;
        self.patch_all(&fragment.outs, accept)?;
        preflight_final_tables(self.states.len(), self.edges, self.limits)?;
        self.charge_final_table_writes()?;
        let stats = LowerStats {
            work: self.work,
            peak_stack_items: self.peak_stack_items,
            states: self.states.len(),
            edges: self.edges,
            erased_captures: self.erased_captures,
            normalized_nullable_repetitions: self.normalized_nullable_repetitions,
            utf8_start_guarded: self.utf8_start_guarded,
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
                let kind = assertion_edge_kind(*look);
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
            HirKind::Repetition(repetition) => self.visit_repetition(repetition),
        }
    }

    fn visit_repetition(
        &mut self,
        repetition: &'h regex_syntax::hir::Repetition,
    ) -> Result<(), LowerError> {
        if repetition.max.is_none()
            && !matches!(repetition.sub.properties().minimum_len(), Some(min) if min > 0)
        {
            if let Some((look, consuming)) =
                self.normalized_ordered_start_look_alternation_repetition(repetition)?
            {
                self.increment_nullable_normalization_count()?;
                self.push_task(Task::FinishOrderedStartLookAlternationRepetition {
                    look,
                    min: repetition.min,
                })?;
                return self.push_task(Task::Visit(consuming));
            }
            if let Some(consuming) =
                self.normalized_ordered_empty_alternation_repetition(repetition)?
            {
                self.increment_nullable_normalization_count()?;
                self.push_task(Task::FinishOrderedEmptyAlternationRepetition {
                    min: repetition.min,
                })?;
                return self.push_task(Task::Visit(consuming));
            }
            if let Some(consuming) =
                self.normalized_ordered_consuming_empty_alternation_repetition(repetition)?
            {
                return self.schedule_nullable_repetition(
                    consuming,
                    NullableRepetitionNormalization::Star { greedy: true },
                );
            }
            if let Some((look, atom)) =
                self.normalized_ordered_word_look_alternation_plus(repetition)?
            {
                self.increment_nullable_normalization_count()?;
                self.push_task(Task::FinishOrderedWordLookAlternationPlus { look })?;
                return self.push_task(Task::Visit(atom));
            }
            if let Some((star_atom, trailing_atom)) =
                self.normalized_ordered_nullable_alternative_star(repetition)?
            {
                self.increment_nullable_normalization_count()?;
                self.push_task(Task::FinishOrderedNullableAlternativeStar)?;
                self.push_task(Task::Visit(trailing_atom))?;
                return self.push_task(Task::Visit(star_atom));
            }
            if let Some((sub, normalization)) = self.normalized_nullable_repetition(repetition)? {
                return self.schedule_nullable_repetition(sub, normalization);
            }
            return Err(LowerError::Unsupported(
                UnsupportedFeature::UncertifiedUnboundedRepetition,
            ));
        }
        let copies_u32 = repetition.max.unwrap_or_else(|| repetition.min.max(1));
        let copies = usize::try_from(copies_u32).map_err(|_| LowerError::ArithmeticOverflow {
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

    fn increment_nullable_normalization_count(&mut self) -> Result<(), LowerError> {
        self.normalized_nullable_repetitions = self
            .normalized_nullable_repetitions
            .checked_add(1)
            .ok_or(LowerError::ArithmeticOverflow {
                computation: "normalized nullable repetition count",
            })?;
        Ok(())
    }

    /// Prove the capture-free, leftmost-first root-search identity
    /// `(?:empty|C)* == empty` and `(?:empty|C)+ == empty` for a positive-width
    /// branch `C`.
    ///
    /// The first alternative completes an iteration without consuming. The
    /// upstream empty-loop guard then exits the repetition without revisiting
    /// the later `C` path. This identity is intentionally restricted to the
    /// complete HIR root:
    /// upstream search priority is not compositional when a prefix or suffix
    /// surrounds the repetition. The proof also excludes a reversed
    /// alternative, lazy outer repetition, minima above one, additional
    /// alternatives and nullable sibling branches.
    fn normalized_root_ordered_empty_alternation_repetition(
        &mut self,
        outer: &'h regex_syntax::hir::Repetition,
    ) -> Result<Option<&'h Hir>, LowerError> {
        if !matches!(outer.min, 0 | 1) || outer.max.is_some() || !outer.greedy {
            return Ok(None);
        }
        let body = self.capture_free_node(&outer.sub)?;
        let HirKind::Alternation(branches) = body.kind() else {
            return Ok(None);
        };
        let [empty_branch, consuming_branch] = branches.as_slice() else {
            return Ok(None);
        };
        let empty_branch = self.capture_free_node(empty_branch)?;
        if !matches!(empty_branch.kind(), HirKind::Empty) {
            return Ok(None);
        }
        let consuming_branch = self.capture_free_node(consuming_branch)?;
        if !matches!(
            consuming_branch.properties().minimum_len(),
            Some(minimum) if minimum > 0
        ) {
            return Ok(None);
        }
        Ok(Some(empty_branch))
    }

    /// Prove the capture-free, leftmost-first identity
    /// `(?:A|C)+ == A|C+` for a word-boundary assertion `A` and a
    /// positive-width literal or class `C`.
    ///
    /// The upstream leftmost-first empty-loop guard permits `A` to win before
    /// the first consuming iteration. Once `C` consumes, an empty iteration of
    /// the same repetition is suppressed and greediness keeps selecting `C`
    /// while it can consume. The right side preserves those two ordered paths
    /// without a nullable cycle. ASCII `\b` and `\B` are admitted because their
    /// byte-boundary semantics are total. Positive Unicode `\b` is also total:
    /// K0 applies the pinned forward and reverse directional decoders at every
    /// byte position, including the pinned reverse treatment of trailing UTF-8
    /// continuation bytes. Negative Unicode boundaries and all other minima,
    /// lazy repetition, reversed alternatives, compound consumers and other
    /// look forms remain unsupported.
    fn normalized_ordered_word_look_alternation_plus(
        &mut self,
        outer: &'h regex_syntax::hir::Repetition,
    ) -> Result<Option<(Look, &'h Hir)>, LowerError> {
        if outer.min != 1 || outer.max.is_some() || !outer.greedy {
            return Ok(None);
        }
        let body = self.capture_free_node(&outer.sub)?;
        let HirKind::Alternation(branches) = body.kind() else {
            return Ok(None);
        };
        let [look_branch, consuming_branch] = branches.as_slice() else {
            return Ok(None);
        };
        let look_branch = self.capture_free_node(look_branch)?;
        let HirKind::Look(look) = look_branch.kind() else {
            return Ok(None);
        };
        if !nullable_initial_word_look(*look) {
            return Ok(None);
        }
        let consuming_branch = self.capture_free_node(consuming_branch)?;
        if !matches!(
            consuming_branch.properties().minimum_len(),
            Some(minimum) if minimum > 0
        ) || !matches!(
            consuming_branch.kind(),
            HirKind::Literal(_) | HirKind::Class(_)
        ) {
            return Ok(None);
        }
        Ok(Some((*look, consuming_branch)))
    }

    /// Prove a cycle-free implementation of greedy `(?:A|C)*` and
    /// `(?:A|C)+`, where `A` is a start assertion and every successful `C`
    /// path consumes at least one byte.
    ///
    /// The upstream empty-loop guard allows `A` as the first iteration, but
    /// suppresses that empty branch after `C` has consumed. We therefore use
    /// an initial ordered split containing `A` and `C`, and a consuming loop
    /// containing only `C` and the repetition exit. For `*`, the initial
    /// split has a final exit branch too. This retains leftmost-first priority
    /// and permits ordinary backtracking from an initially successful
    /// assertion into `C` when a following expression needs it, without
    /// introducing a nullable cycle.
    fn normalized_ordered_start_look_alternation_repetition(
        &mut self,
        outer: &'h regex_syntax::hir::Repetition,
    ) -> Result<Option<(Look, &'h Hir)>, LowerError> {
        if !matches!(outer.min, 0 | 1) || outer.max.is_some() || !outer.greedy {
            return Ok(None);
        }
        let body = self.capture_free_node(&outer.sub)?;
        let HirKind::Alternation(branches) = body.kind() else {
            return Ok(None);
        };
        let [look_branch, consuming_branch] = branches.as_slice() else {
            return Ok(None);
        };
        let look_branch = self.capture_free_node(look_branch)?;
        let HirKind::Look(look) = look_branch.kind() else {
            return Ok(None);
        };
        if !matches!(look, Look::Start | Look::StartLF | Look::StartCRLF) {
            return Ok(None);
        }
        let consuming_branch = self.capture_free_node(consuming_branch)?;
        if !matches!(
            consuming_branch.properties().minimum_len(),
            Some(minimum) if minimum > 0
        ) {
            return Ok(None);
        }
        Ok(Some((*look, consuming_branch)))
    }

    /// Prove a cycle-free implementation of greedy `(?:E|C)*` and
    /// `(?:E|C)+`, where `E` is exactly empty and every successful `C` path
    /// consumes exactly one byte.
    ///
    /// Leftmost-first execution first permits the empty branch. If a suffix
    /// rejects that path, ordinary backtracking may select `C`. After `C` has
    /// consumed, the upstream empty-loop guard suppresses `E`, leaving only
    /// another consuming iteration or the repetition exit. Encoding those as
    /// separate initial and loop splits preserves the priority without a
    /// nullable cycle. Restricting `C` to one byte is necessary when a suffix
    /// can backtrack into the repetition: a multi-byte `C` can otherwise
    /// change which start and end the suffix selects. The separate root-only
    /// proof may still erase any positive-width `C` because it has no suffix.
    fn normalized_ordered_empty_alternation_repetition(
        &mut self,
        outer: &'h regex_syntax::hir::Repetition,
    ) -> Result<Option<&'h Hir>, LowerError> {
        if !matches!(outer.min, 0 | 1) || outer.max.is_some() || !outer.greedy {
            return Ok(None);
        }
        let body = self.capture_free_node(&outer.sub)?;
        let HirKind::Alternation(branches) = body.kind() else {
            return Ok(None);
        };
        let [empty_branch, consuming_branch] = branches.as_slice() else {
            return Ok(None);
        };
        let empty_branch = self.capture_free_node(empty_branch)?;
        if !matches!(empty_branch.kind(), HirKind::Empty) {
            return Ok(None);
        }
        let consuming_branch = self.capture_free_node(consuming_branch)?;
        if !matches!(
            consuming_branch.properties().minimum_len(),
            Some(minimum) if minimum > 0
        ) || consuming_branch.properties().maximum_len() != Some(1)
        {
            return Ok(None);
        }
        Ok(Some(consuming_branch))
    }

    /// Prove the capture-free, leftmost-first identity
    /// `(?:C|empty)* == C*` and `(?:C|empty)+ == C*` for an exactly one-byte
    /// literal or class `C` under a greedy outer repetition.
    ///
    /// At each iteration the ordered consuming branch wins whenever it can.
    /// Once it cannot, the empty fallback completes that iteration and the
    /// upstream empty-loop guard exits without revisiting the body. The
    /// ordinary greedy-star exit preserves the same continuation backtracking
    /// order while removing the nullable cycle. The one-byte restriction is
    /// necessary when a suffix can force backtracking: a multi-byte consumer
    /// can otherwise change the selected match start. Lazy repetition, minima
    /// above one, additional alternatives and compound or nullable consumers
    /// remain outside this deliberately narrow proof.
    fn normalized_ordered_consuming_empty_alternation_repetition(
        &mut self,
        outer: &'h regex_syntax::hir::Repetition,
    ) -> Result<Option<&'h Hir>, LowerError> {
        if !matches!(outer.min, 0 | 1) || outer.max.is_some() || !outer.greedy {
            return Ok(None);
        }
        let body = self.capture_free_node(&outer.sub)?;
        let HirKind::Alternation(branches) = body.kind() else {
            return Ok(None);
        };
        let [consuming_branch, empty_branch] = branches.as_slice() else {
            return Ok(None);
        };
        let consuming_branch = self.capture_free_node(consuming_branch)?;
        if !Self::positive_width_atom(consuming_branch)
            || consuming_branch.properties().maximum_len() != Some(1)
        {
            return Ok(None);
        }
        let empty_branch = self.capture_free_node(empty_branch)?;
        if !matches!(empty_branch.kind(), HirKind::Empty) {
            return Ok(None);
        }
        Ok(Some(consuming_branch))
    }

    /// Prove the capture-free identity `(A*){m,} == A*` or
    /// `(A?){m,} == A*` for a positive-width atom `A`.
    ///
    /// The inner repetition must prefer its consuming branch. A lazy outer
    /// `A*` at minimum zero first tries the outer exit, then one greedy `A+`;
    /// at minimum one its mandatory greedy inner star is simply `A*`. For
    /// `A?`, the outer repetition's greed controls how many one-atom
    /// iterations are selected; a lazy outer repetition is admitted only at
    /// minimum zero or one.
    /// Capture wrappers may be erased because `compile` has already rejected
    /// capture-sensitive operations. Empty alternatives, assertions, lazy
    /// inner repetitions and compound bodies remain outside this theorem.
    fn normalized_nullable_repetition(
        &mut self,
        outer: &'h regex_syntax::hir::Repetition,
    ) -> Result<Option<(&'h Hir, NullableRepetitionNormalization)>, LowerError> {
        let nested = self.capture_free_node(&outer.sub)?;
        let HirKind::Repetition(inner) = nested.kind() else {
            return Ok(None);
        };
        if inner.min != 0 || !inner.greedy {
            return Ok(None);
        }
        let normalization = match inner.max {
            Some(1) if outer.greedy || outer.min == 0 => NullableRepetitionNormalization::Star {
                greedy: outer.greedy,
            },
            Some(1) if outer.min == 1 => {
                NullableRepetitionNormalization::LazyGreedyOptionalThenStar
            }
            None if outer.greedy => NullableRepetitionNormalization::Star { greedy: true },
            None if outer.min == 0 => NullableRepetitionNormalization::LazyOptionalGreedyPlus,
            None if outer.min == 1 => NullableRepetitionNormalization::Star { greedy: true },
            None | Some(_) => return Ok(None),
        };
        let atom = self.capture_free_node(&inner.sub)?;
        if !matches!(atom.properties().minimum_len(), Some(minimum) if minimum > 0)
            || !matches!(atom.kind(), HirKind::Literal(_) | HirKind::Class(_))
        {
            return Ok(None);
        }
        Ok(Some((atom, normalization)))
    }

    fn schedule_nullable_repetition(
        &mut self,
        sub: &'h Hir,
        normalization: NullableRepetitionNormalization,
    ) -> Result<(), LowerError> {
        self.increment_nullable_normalization_count()?;
        match normalization {
            NullableRepetitionNormalization::Star { greedy } => {
                self.push_task(Task::FinishRepetition {
                    min: 0,
                    max: None,
                    greedy,
                    copies: 1,
                })?;
            }
            NullableRepetitionNormalization::LazyOptionalGreedyPlus => {
                self.push_task(Task::FinishLazyOptionalGreedyPlus)?;
            }
            NullableRepetitionNormalization::LazyGreedyOptionalThenStar => {
                self.push_task(Task::FinishLazyGreedyOptionalThenStar)?;
                self.push_task(Task::Visit(sub))?;
            }
        }
        self.push_task(Task::Visit(sub))
    }

    /// Eliminate the nullable cycle in an ordered greedy `(?:A*|B)*`
    /// without changing its leftmost-first continuation priority.
    ///
    /// A language rewrite to `(?:A|B)*` is invalid: on `B`, the original
    /// first accepts the empty match through its preferred `A*`, while the
    /// rewrite consumes `B`. The dedicated graph emitted below retains the
    /// original reset points and continuation edge. Both consumers are kept
    /// deliberately narrow and positive-width so every cycle makes progress.
    fn normalized_ordered_nullable_alternative_star(
        &mut self,
        outer: &'h regex_syntax::hir::Repetition,
    ) -> Result<Option<(&'h Hir, &'h Hir)>, LowerError> {
        if outer.min != 0 || outer.max.is_some() || !outer.greedy {
            return Ok(None);
        }
        let nested = self.capture_free_node(&outer.sub)?;
        let HirKind::Alternation(branches) = nested.kind() else {
            return Ok(None);
        };
        let [nullable, trailing] = branches.as_slice() else {
            return Ok(None);
        };
        let nullable = self.capture_free_node(nullable)?;
        let HirKind::Repetition(inner) = nullable.kind() else {
            return Ok(None);
        };
        if inner.min != 0 || inner.max.is_some() || !inner.greedy {
            return Ok(None);
        }
        let star_atom = self.capture_free_node(&inner.sub)?;
        let trailing_atom = self.capture_free_node(trailing)?;
        if !Self::positive_width_atom(star_atom) || !Self::positive_width_atom(trailing_atom) {
            return Ok(None);
        }
        Ok(Some((star_atom, trailing_atom)))
    }

    fn positive_width_atom(hir: &Hir) -> bool {
        matches!(hir.kind(), HirKind::Literal(_) | HirKind::Class(_))
            && matches!(hir.properties().minimum_len(), Some(minimum) if minimum > 0)
    }

    fn capture_free_node(&mut self, mut hir: &'h Hir) -> Result<&'h Hir, LowerError> {
        while let HirKind::Capture(capture) = hir.kind() {
            self.charge(1, "capture-free nullable normalization")?;
            hir = &capture.sub;
        }
        Ok(hir)
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

    fn finish_ordered_word_look_alternation_plus(&mut self, look: Look) -> Result<(), LowerError> {
        let mut fragments = self.take_fragments(1)?;
        let consuming = fragments.pop().ok_or(LowerError::InternalInvariant {
            detail: "missing ordered word-look alternation consumer",
        })?;
        let consuming_plus = self.plus_fragment(&consuming, true)?;

        let asserted = self.assertion_fragment(assertion_edge_kind(look))?;
        let mut alternatives = Vec::new();
        self.charge_vector_growth(
            alternatives.len(),
            alternatives.capacity(),
            2,
            "normalized word-look alternatives",
        )?;
        reserve(&mut alternatives, 2, "normalized word-look alternatives")?;
        alternatives.push(asserted);
        alternatives.push(consuming_plus);
        let fragment = self.alternation_fragment(alternatives)?;
        self.push_fragment(fragment)
    }

    fn finish_lazy_optional_greedy_plus(&mut self) -> Result<(), LowerError> {
        let mut fragments = self.take_fragments(1)?;
        let atom = fragments.pop().ok_or(LowerError::InternalInvariant {
            detail: "missing lazy-outer greedy-star atom",
        })?;
        let greedy_plus = self.plus_fragment(&atom, true)?;
        let normalized = self.optional_fragment(greedy_plus, false)?;
        self.push_fragment(normalized)
    }

    fn finish_lazy_greedy_optional_then_star(&mut self) -> Result<(), LowerError> {
        let mut fragments = self.take_fragments(2)?;
        let star_atom = fragments.pop().ok_or(LowerError::InternalInvariant {
            detail: "missing lazy-star atom after greedy optional",
        })?;
        let optional_atom = fragments.pop().ok_or(LowerError::InternalInvariant {
            detail: "missing greedy-optional atom before lazy star",
        })?;
        let optional = self.optional_fragment(optional_atom, true)?;
        let star = self.star_fragment(&star_atom, false)?;
        fragments.push(optional);
        fragments.push(star);
        let normalized = self.concat_fragments(fragments)?;
        self.push_fragment(normalized)
    }

    fn finish_ordered_nullable_alternative_star(&mut self) -> Result<(), LowerError> {
        let mut fragments = self.take_fragments(2)?;
        let trailing = fragments.pop().ok_or(LowerError::InternalInvariant {
            detail: "missing ordered nullable-alternative trailing atom",
        })?;
        let star_atom = fragments.pop().ok_or(LowerError::InternalInvariant {
            detail: "missing ordered nullable-alternative star atom",
        })?;

        let zero = self.add_state(StateRole::Split)?;
        let progressed = self.add_state(StateRole::Split)?;
        self.add_edge(zero, EdgeKind::Epsilon, 0, 0, Some(star_atom.start))?;
        let zero_continuation = self.add_edge(zero, EdgeKind::Epsilon, 0, 0, None)?;
        self.add_edge(zero, EdgeKind::Epsilon, 0, 0, Some(trailing.start))?;
        self.add_edge(progressed, EdgeKind::Epsilon, 0, 0, Some(star_atom.start))?;
        self.add_edge(progressed, EdgeKind::Epsilon, 0, 0, Some(trailing.start))?;
        let progressed_continuation = self.add_edge(progressed, EdgeKind::Epsilon, 0, 0, None)?;
        self.patch_all(&star_atom.outs, progressed)?;
        self.patch_all(&trailing.outs, progressed)?;
        let mut outs =
            self.singleton_patch(zero_continuation, "zero-progress nullable-alternative exit")?;
        let progressed_outs = self.singleton_patch(
            progressed_continuation,
            "progressed nullable-alternative exit",
        )?;
        self.append_patches(
            &mut outs,
            progressed_outs,
            "ordered nullable-alternative exits",
        )?;
        self.push_fragment(Fragment { start: zero, outs })
    }

    fn finish_ordered_start_look_alternation_repetition(
        &mut self,
        look: Look,
        min: u32,
    ) -> Result<(), LowerError> {
        let mut fragments = self.take_fragments(1)?;
        let consuming = fragments.pop().ok_or(LowerError::InternalInvariant {
            detail: "missing ordered start-look alternation consumer",
        })?;

        let asserted = self.assertion_fragment(assertion_edge_kind(look))?;
        let loop_split = self.add_state(StateRole::Split)?;
        self.add_edge(loop_split, EdgeKind::Epsilon, 0, 0, Some(consuming.start))?;
        let exit = self.add_edge(loop_split, EdgeKind::Epsilon, 0, 0, None)?;
        self.patch_all(&consuming.outs, loop_split)?;

        let mut outs = asserted.outs;
        self.charge_vector_growth(
            outs.len(),
            outs.capacity(),
            2,
            "normalized start-look repetition exits",
        )?;
        reserve(&mut outs, 2, "normalized start-look repetition exits")?;
        outs.push(exit);

        let initial = self.add_state(StateRole::Split)?;
        self.add_edge(initial, EdgeKind::Epsilon, 0, 0, Some(asserted.start))?;
        self.add_edge(initial, EdgeKind::Epsilon, 0, 0, Some(consuming.start))?;
        match min {
            0 => {
                let initial_exit = self.add_edge(initial, EdgeKind::Epsilon, 0, 0, None)?;
                outs.push(initial_exit);
            }
            1 => {}
            _ => {
                return Err(LowerError::InternalInvariant {
                    detail: "uncertified ordered start-look repetition minimum",
                });
            }
        }
        self.push_fragment(Fragment {
            start: initial,
            outs,
        })
    }

    fn finish_ordered_empty_alternation_repetition(&mut self, min: u32) -> Result<(), LowerError> {
        let mut fragments = self.take_fragments(1)?;
        let consuming = fragments.pop().ok_or(LowerError::InternalInvariant {
            detail: "missing ordered empty-alternation consumer",
        })?;

        let loop_split = self.add_state(StateRole::Split)?;
        self.add_edge(loop_split, EdgeKind::Epsilon, 0, 0, Some(consuming.start))?;
        let loop_exit = self.add_edge(loop_split, EdgeKind::Epsilon, 0, 0, None)?;
        self.patch_all(&consuming.outs, loop_split)?;

        let initial = self.add_state(StateRole::Split)?;
        let empty_exit = self.add_edge(initial, EdgeKind::Epsilon, 0, 0, None)?;
        self.add_edge(initial, EdgeKind::Epsilon, 0, 0, Some(consuming.start))?;
        let mut outs = self.singleton_patch(empty_exit, "normalized empty repetition exits")?;
        self.charge_vector_growth(
            outs.len(),
            outs.capacity(),
            2,
            "normalized empty repetition exits",
        )?;
        reserve(&mut outs, 2, "normalized empty repetition exits")?;
        outs.push(loop_exit);
        match min {
            0 => {
                let initial_exit = self.add_edge(initial, EdgeKind::Epsilon, 0, 0, None)?;
                outs.push(initial_exit);
            }
            1 => {}
            _ => {
                return Err(LowerError::InternalInvariant {
                    detail: "uncertified ordered empty repetition minimum",
                });
            }
        }
        self.push_fragment(Fragment {
            start: initial,
            outs,
        })
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

    /// Match exactly the byte offsets that are scalar boundaries in a valid
    /// UTF-8 haystack. At such an offset, Unicode `\b` and `\B` are exhaustive
    /// and mutually exclusive. At an interior continuation-byte offset both
    /// assertions are false. The text facade separately proves its haystack is
    /// valid UTF-8 before selecting this synthesized start guard.
    fn utf8_start_guard_fragment(&mut self) -> Result<Fragment, LowerError> {
        let boundary = self.assertion_fragment(EdgeKind::AssertWordUnicode)?;
        let non_boundary = self.assertion_fragment(EdgeKind::AssertWordUnicodeNegate)?;
        let mut alternatives = Vec::new();
        self.charge_vector_growth(
            alternatives.len(),
            alternatives.capacity(),
            2,
            "UTF-8 start-guard alternatives",
        )?;
        reserve(&mut alternatives, 2, "UTF-8 start-guard alternatives")?;
        alternatives.push(boundary);
        alternatives.push(non_boundary);
        self.alternation_fragment(alternatives)
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
