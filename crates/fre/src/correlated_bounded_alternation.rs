//! Necessary-terminal acceleration for correlated bounded alternatives.
//!
//! This inspector recognizes a nonempty literal prefix followed by two or
//! more alternatives of the form `LEFT CLASS{min,max} RIGHT`. The final byte
//! of every `RIGHT` is distinct, so their union is a necessary terminal set
//! for the whole language. Runtime endpoint authentication remains the job of
//! the immutable K0 automaton; this module only supplies a candidate source
//! and exact finite width bounds.

use fre_kernels::{
    BYTE_SET_CLASSIFIER_BUILD_WORK, ByteSet256, ByteSetClassifier, DispatchPolicy,
    SimdDispatchContext,
};
use regex_syntax::hir::{Class, Hir, HirKind};

use crate::pure_byte_class_repeat::SetSeek;

const NODE_INSPECTION_WORK: u64 = 1;
const LITERAL_BYTE_WORK: u64 = 1;
const RANGE_INSPECTION_WORK: u64 = 1;
const TERMINAL_INSERTION_WORK: u64 = 1;
const ARITHMETIC_WORK: u64 = 1;
const LEAF_SELECTION_WORK: u64 = 1;
const SIZE_CLASS_STATES: usize = 4;
const MAX_BACKOFF_CALLS: u8 = 64;
const MAX_BRANCH_COUNT: usize = 8;
const TERMINAL_WORK_PASSES_PER_BRANCH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit {
        actual: u64,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow,
}

pub(crate) enum InspectionOutcome {
    Eligible(Inspection),
    Ineligible { planner_work: u64 },
}

impl InspectionOutcome {
    pub(crate) const fn planner_work(&self) -> u64 {
        match self {
            Self::Eligible(inspection) => inspection.planner_work,
            Self::Ineligible { planner_work } => *planner_work,
        }
    }
}

pub(crate) struct Inspection {
    terminal_words: [u64; 4],
    terminal_seek: SetSeek,
    minimum_match_bytes: usize,
    maximum_match_bytes: usize,
    branch_count: usize,
    planner_work: u64,
}

impl Inspection {
    pub(crate) fn build(self, dispatch: SimdDispatchContext) -> Plan {
        let terminal_seek = self.terminal_seek;
        let classifier = terminal_seek.requires_classifier().then(|| {
            dispatch
                .byte_set_classifier(
                    ByteSet256::from_words(self.terminal_words),
                    DispatchPolicy::Auto,
                )
                .expect("automatic byte-set dispatch retains a scalar fallback")
        });
        Plan {
            terminal_seek,
            classifier,
            minimum_match_bytes: self.minimum_match_bytes,
            maximum_match_bytes: self.maximum_match_bytes,
            branch_count: self.branch_count,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Plan {
    terminal_seek: SetSeek,
    classifier: Option<ByteSetClassifier>,
    minimum_match_bytes: usize,
    maximum_match_bytes: usize,
    branch_count: usize,
}

impl Plan {
    pub(crate) const fn storage_bytes() -> usize {
        core::mem::size_of::<Self>()
    }

    pub(crate) const fn minimum_match_bytes(&self) -> usize {
        self.minimum_match_bytes
    }

    pub(crate) const fn maximum_match_bytes(&self) -> usize {
        self.maximum_match_bytes
    }

    pub(crate) const fn branch_count(&self) -> usize {
        self.branch_count
    }

    pub(crate) fn seek_terminal(
        &self,
        haystack: &[u8],
        position: usize,
        end: usize,
    ) -> Option<usize> {
        self.terminal_seek.seek_unmetered(
            haystack,
            position,
            end,
            self.classifier.as_ref(),
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RouteClassState {
    window_size_class: Option<u32>,
    incumbent_transition_work: u64,
    learned: bool,
    prefer_terminal: bool,
    disabled_calls: u8,
    backoff: u8,
    terminal_epoch: u8,
    terminal_remaining: u8,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RouteState {
    classes: [RouteClassState; SIZE_CLASS_STATES],
    next_replacement: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Route {
    Bypass,
    Learn { class_index: usize },
    Terminal {
        class_index: usize,
        incumbent_transition_work: u64,
    },
}

impl RouteState {
    pub(crate) fn select(&mut self, window_bytes: usize) -> Route {
        if window_bytes == 0 {
            return Route::Bypass;
        }
        let window_size_class = usize::BITS - window_bytes.leading_zeros();
        let class_index = self.class_for(window_size_class);
        let class = &mut self.classes[class_index];
        if class.disabled_calls != 0 {
            class.disabled_calls = class.disabled_calls.saturating_sub(1);
            return Route::Bypass;
        }
        if !class.learned {
            return Route::Learn { class_index };
        }
        if class.prefer_terminal {
            Route::Terminal {
                class_index,
                incumbent_transition_work: class.incumbent_transition_work,
            }
        } else {
            // Distribution changes must be recoverable. Re-observe the
            // incumbent after a source-independent exponential call backoff.
            Route::Learn { class_index }
        }
    }

    pub(crate) fn observe_incumbent(
        &mut self,
        class_index: usize,
        window_bytes: usize,
        incumbent_work: u64,
        boundaries: usize,
        maximum_match_bytes: usize,
        branch_count: usize,
    ) {
        let class = &mut self.classes[class_index];
        class.learned = true;
        let source_pass = u64::try_from(window_bytes).unwrap_or(u64::MAX);
        let modeled_branch_work = boundaries
            .checked_mul(maximum_match_bytes)
            .and_then(|work| work.checked_mul(branch_count))
            .and_then(|work| u64::try_from(work).ok());
        let branch_pass_budget = window_bytes
            .checked_mul(branch_count)
            .and_then(|work| work.checked_mul(TERMINAL_WORK_PASSES_PER_BRANCH))
            .and_then(|work| u64::try_from(work).ok());
        class.prefer_terminal = modeled_branch_work
            .zip(branch_pass_budget)
            .is_some_and(|(modeled, _)| boundaries != 0 && modeled > source_pass);
        class.incumbent_transition_work = branch_pass_budget
            .map(|budget| incumbent_work.max(budget))
            .unwrap_or(incumbent_work);
        if class.prefer_terminal {
            class.terminal_epoch = if class.terminal_epoch == 0 {
                1
            } else {
                class
                    .terminal_epoch
                    .saturating_mul(2)
                    .min(MAX_BACKOFF_CALLS)
            };
            class.terminal_remaining = class.terminal_epoch;
            class.backoff = 0;
            class.disabled_calls = 0;
        } else {
            class.terminal_epoch = 0;
            class.terminal_remaining = 0;
            class.backoff = if class.backoff == 0 {
                1
            } else {
                class.backoff.saturating_mul(2).min(MAX_BACKOFF_CALLS)
            };
            class.disabled_calls = class.backoff;
        }
    }

    pub(crate) fn observe_terminal_success(&mut self, class_index: usize) {
        let class = &mut self.classes[class_index];
        class.terminal_remaining = class.terminal_remaining.saturating_sub(1);
        if class.terminal_remaining == 0 {
            // Stable wins grow a bounded epoch from one to 64 calls. Re-prime
            // raw K0 at every epoch boundary so a cheaper changed incumbent
            // is discovered without sacrificing stationary steady state.
            class.learned = false;
            class.incumbent_transition_work = 0;
            class.prefer_terminal = false;
        } else {
            class.prefer_terminal = true;
        }
        class.backoff = 0;
        class.disabled_calls = 0;
    }

    pub(crate) fn observe_terminal_loss(&mut self, class_index: usize) {
        let class = &mut self.classes[class_index];
        class.prefer_terminal = false;
        class.terminal_epoch = 0;
        class.terminal_remaining = 0;
        class.backoff = if class.backoff == 0 {
            1
        } else {
            class.backoff.saturating_mul(2).min(MAX_BACKOFF_CALLS)
        };
        class.disabled_calls = class.backoff;
    }

    fn class_for(&mut self, window_size_class: u32) -> usize {
        if let Some(index) = self
            .classes
            .iter()
            .position(|state| state.window_size_class == Some(window_size_class))
        {
            return index;
        }
        if let Some(index) = self
            .classes
            .iter()
            .position(|state| state.window_size_class.is_none())
        {
            self.classes[index].window_size_class = Some(window_size_class);
            return index;
        }
        let index = usize::from(self.next_replacement) % self.classes.len();
        self.next_replacement = self.next_replacement.wrapping_add(1)
            % u8::try_from(self.classes.len()).expect("size-class count fits u8");
        self.classes[index] = RouteClassState {
            window_size_class: Some(window_size_class),
            ..RouteClassState::default()
        };
        index
    }
}

#[cold]
pub(crate) fn inspect(
    hir: &Hir,
    initial_work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut work = initial_work;
    let root = peel_captures(hir, &mut work, max_planner_work)?;
    let HirKind::Concat(root_parts) = root.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    let Some((alternation, prefix_parts)) = root_parts.split_last() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    if prefix_parts.is_empty() {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    let mut prefix_bytes = 0usize;
    for part in prefix_parts {
        let Some(length) = exact_literal_len(part, &mut work, max_planner_work)? else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        prefix_bytes = checked_add_len(prefix_bytes, length, &mut work, max_planner_work)?;
    }
    if prefix_bytes == 0 {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }

    let alternation = peel_captures(alternation, &mut work, max_planner_work)?;
    let HirKind::Alternation(branches) = alternation.kind() else {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    };
    if !(2..=MAX_BRANCH_COUNT).contains(&branches.len()) {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }

    let mut terminal_words = [0u64; 4];
    let mut terminal_cardinality = 0u32;
    let mut minimum_match_bytes = usize::MAX;
    let mut maximum_match_bytes = 0usize;
    let mut has_variable_repeat = false;
    for branch in branches {
        let Some(shape) = inspect_branch(branch, &mut work, max_planner_work)? else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        if shape.minimum != shape.maximum {
            has_variable_repeat = true;
        }
        let minimum = checked_add_len(
            prefix_bytes,
            shape.minimum,
            &mut work,
            max_planner_work,
        )?;
        let maximum = checked_add_len(
            prefix_bytes,
            shape.maximum,
            &mut work,
            max_planner_work,
        )?;
        minimum_match_bytes = minimum_match_bytes.min(minimum);
        maximum_match_bytes = maximum_match_bytes.max(maximum);

        charge(
            &mut work,
            TERMINAL_INSERTION_WORK,
            max_planner_work,
        )?;
        let word = usize::from(shape.terminal >> 6);
        let bit = u32::from(shape.terminal & 63);
        let mask = 1u64 << bit;
        if terminal_words[word] & mask != 0 {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
        terminal_words[word] |= mask;
        terminal_cardinality = terminal_cardinality
            .checked_add(1)
            .ok_or(InspectionError::ArithmeticOverflow)?;
    }
    if !has_variable_repeat
        || minimum_match_bytes == 0
        || maximum_match_bytes < minimum_match_bytes
        || !(2..=255).contains(&terminal_cardinality)
    {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }
    charge(&mut work, LEAF_SELECTION_WORK, max_planner_work)?;
    let terminal_seek = SetSeek::build(terminal_words, terminal_cardinality, false);
    if terminal_seek.requires_classifier() {
        charge(
            &mut work,
            u64::try_from(BYTE_SET_CLASSIFIER_BUILD_WORK)
                .map_err(|_| InspectionError::ArithmeticOverflow)?,
            max_planner_work,
        )?;
    }
    Ok(InspectionOutcome::Eligible(Inspection {
        terminal_words,
        terminal_seek,
        minimum_match_bytes,
        maximum_match_bytes,
        branch_count: branches.len(),
        planner_work: work,
    }))
}

#[derive(Clone, Copy)]
struct BranchShape {
    minimum: usize,
    maximum: usize,
    terminal: u8,
}

fn inspect_branch(
    branch: &Hir,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<Option<BranchShape>, InspectionError> {
    let branch = peel_captures(branch, work, max_planner_work)?;
    let HirKind::Concat(parts) = branch.kind() else {
        return Ok(None);
    };
    let mut repeat = None;
    let mut left_bytes = 0usize;
    let mut right_bytes = 0usize;
    let mut terminal = None;
    for part in parts {
        let part = peel_captures(part, work, max_planner_work)?;
        match part.kind() {
            HirKind::Repetition(repetition) if repeat.is_none() => {
                if left_bytes == 0 {
                    return Ok(None);
                }
                let Some(maximum) = repetition.max else {
                    return Ok(None);
                };
                if maximum < repetition.min
                    || !is_single_byte_atom(&repetition.sub, work, max_planner_work)?
                {
                    return Ok(None);
                }
                repeat = Some((
                    usize::try_from(repetition.min)
                        .map_err(|_| InspectionError::ArithmeticOverflow)?,
                    usize::try_from(maximum)
                        .map_err(|_| InspectionError::ArithmeticOverflow)?,
                ));
            }
            HirKind::Literal(literal) if !literal.0.is_empty() => {
                charge_literal(literal.0.len(), work, max_planner_work)?;
                if repeat.is_some() {
                    right_bytes = checked_add_len(
                        right_bytes,
                        literal.0.len(),
                        work,
                        max_planner_work,
                    )?;
                    terminal = literal.0.last().copied();
                } else {
                    left_bytes = checked_add_len(
                        left_bytes,
                        literal.0.len(),
                        work,
                        max_planner_work,
                    )?;
                }
            }
            _ => return Ok(None),
        }
    }
    let Some((repeat_minimum, repeat_maximum)) = repeat else {
        return Ok(None);
    };
    let Some(terminal) = terminal else {
        return Ok(None);
    };
    if left_bytes == 0 || right_bytes == 0 {
        return Ok(None);
    }
    let fixed = checked_add_len(left_bytes, right_bytes, work, max_planner_work)?;
    let minimum = checked_add_len(fixed, repeat_minimum, work, max_planner_work)?;
    let maximum = checked_add_len(fixed, repeat_maximum, work, max_planner_work)?;
    Ok(Some(BranchShape {
        minimum,
        maximum,
        terminal,
    }))
}

fn exact_literal_len(
    hir: &Hir,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<Option<usize>, InspectionError> {
    let hir = peel_captures(hir, work, max_planner_work)?;
    let HirKind::Literal(literal) = hir.kind() else {
        return Ok(None);
    };
    if literal.0.is_empty() {
        return Ok(None);
    }
    charge_literal(literal.0.len(), work, max_planner_work)?;
    Ok(Some(literal.0.len()))
}

fn is_single_byte_atom(
    hir: &Hir,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<bool, InspectionError> {
    let hir = peel_captures(hir, work, max_planner_work)?;
    match hir.kind() {
        HirKind::Literal(literal) => {
            charge_literal(literal.0.len(), work, max_planner_work)?;
            Ok(literal.0.len() == 1)
        }
        HirKind::Class(Class::Bytes(class)) => {
            let mut nonempty = false;
            for range in class.ranges() {
                charge(work, RANGE_INSPECTION_WORK, max_planner_work)?;
                nonempty |= range.start() <= range.end();
            }
            Ok(nonempty)
        }
        _ => Ok(false),
    }
}

fn peel_captures<'h>(
    mut hir: &'h Hir,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<&'h Hir, InspectionError> {
    loop {
        charge(work, NODE_INSPECTION_WORK, max_planner_work)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = &capture.sub;
    }
}

fn charge_literal(
    bytes: usize,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<(), InspectionError> {
    let bytes = u64::try_from(bytes).map_err(|_| InspectionError::ArithmeticOverflow)?;
    charge(
        work,
        bytes
            .checked_mul(LITERAL_BYTE_WORK)
            .ok_or(InspectionError::ArithmeticOverflow)?,
        max_planner_work,
    )
}

fn checked_add_len(
    left: usize,
    right: usize,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<usize, InspectionError> {
    charge(work, ARITHMETIC_WORK, max_planner_work)?;
    left.checked_add(right)
        .ok_or(InspectionError::ArithmeticOverflow)
}

fn charge(
    work: &mut u64,
    additional: u64,
    limit: u64,
) -> Result<(), InspectionError> {
    let needed = work
        .checked_add(additional)
        .ok_or(InspectionError::ArithmeticOverflow)?;
    if needed > limit {
        return Err(InspectionError::WorkLimit {
            actual: *work,
            needed,
            limit,
        });
    }
    *work = needed;
    Ok(())
}
