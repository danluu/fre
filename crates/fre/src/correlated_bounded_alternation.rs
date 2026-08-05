//! Necessary-terminal acceleration for correlated byte-run alternatives.
//!
//! The bounded route recognizes a nonempty literal prefix followed by two or
//! more alternatives of the form `LEFT CLASS{min,max} RIGHT`; immutable K0
//! authenticates those finite-width endpoints. The exact-delimited route
//! recognizes a root alternation of `LEFT CLASS{0,} RIGHT` branches when each
//! distinct terminal is globally absent from every class and other fixed byte.
//! That stronger proof partitions the source and permits direct branch-local
//! reverse authentication without retaining haystack-dependent state.

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
const MAX_DELIMITED_LITERAL_BYTES: usize = 16;
const NO_DELIMITED_BRANCH: u8 = u8::MAX;
const CLASS_MEMBER_INSERTION_WORK: u64 = 1;
const MEMBERSHIP_PROOF_WORK: u64 = 1;

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
    mode: InspectionMode,
    planner_work: u64,
}

enum InspectionMode {
    Bounded {
        minimum_match_bytes: usize,
        maximum_match_bytes: usize,
        branch_count: usize,
    },
    Delimited(DelimitedPlan),
}

impl Inspection {
    pub(crate) const fn storage_bytes(&self) -> usize {
        core::mem::size_of::<Plan>()
            + match &self.mode {
                InspectionMode::Bounded { .. } => 0,
                InspectionMode::Delimited(_) => core::mem::size_of::<DelimitedPlan>(),
            }
    }

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
            mode: match self.mode {
                InspectionMode::Bounded {
                    minimum_match_bytes,
                    maximum_match_bytes,
                    branch_count,
                } => PlanMode::Bounded {
                    minimum_match_bytes,
                    maximum_match_bytes,
                    branch_count,
                },
                InspectionMode::Delimited(plan) => PlanMode::Delimited(Box::new(plan)),
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct DelimitedBranch {
    class_words: [u64; 4],
    left: [u8; MAX_DELIMITED_LITERAL_BYTES],
    right: [u8; MAX_DELIMITED_LITERAL_BYTES],
    left_len: u8,
    right_len: u8,
    class_tail_len: u8,
    minimum: u8,
}

impl DelimitedBranch {
    const EMPTY: Self = Self {
        class_words: [0; 4],
        left: [0; MAX_DELIMITED_LITERAL_BYTES],
        right: [0; MAX_DELIMITED_LITERAL_BYTES],
        left_len: 0,
        right_len: 0,
        class_tail_len: 0,
        minimum: 0,
    };

    fn class_contains(&self, byte: u8) -> bool {
        let word = usize::from(byte >> 6);
        let bit = u32::from(byte & 63);
        self.class_words[word] & (1_u64 << bit) != 0
    }

    fn left(&self) -> &[u8] {
        &self.left[..usize::from(self.left_len)]
    }

    fn right(&self) -> &[u8] {
        &self.right[..usize::from(self.right_len)]
    }

    fn terminal(&self) -> u8 {
        self.right[usize::from(self.right_len) - 1]
    }
}

#[derive(Debug)]
struct DelimitedPlan {
    branches: [DelimitedBranch; MAX_BRANCH_COUNT],
    terminal_to_branch: [u8; 256],
    minimum_match_bytes: usize,
    branch_count: usize,
}

#[derive(Debug)]
enum PlanMode {
    Bounded {
        minimum_match_bytes: usize,
        maximum_match_bytes: usize,
        branch_count: usize,
    },
    Delimited(Box<DelimitedPlan>),
}

#[derive(Debug)]
pub(crate) struct Plan {
    terminal_seek: SetSeek,
    classifier: Option<ByteSetClassifier>,
    mode: PlanMode,
}

impl Plan {
    pub(crate) fn storage_bytes(&self) -> usize {
        core::mem::size_of::<Self>()
            + match &self.mode {
                PlanMode::Bounded { .. } => 0,
                PlanMode::Delimited(_) => core::mem::size_of::<DelimitedPlan>(),
            }
    }

    pub(crate) fn minimum_match_bytes(&self) -> usize {
        match &self.mode {
            PlanMode::Bounded {
                minimum_match_bytes,
                ..
            } => *minimum_match_bytes,
            PlanMode::Delimited(plan) => plan.minimum_match_bytes,
        }
    }

    pub(crate) fn maximum_match_bytes(&self) -> usize {
        match &self.mode {
            PlanMode::Bounded {
                maximum_match_bytes,
                ..
            } => *maximum_match_bytes,
            PlanMode::Delimited(_) => 0,
        }
    }

    pub(crate) fn branch_count(&self) -> usize {
        match &self.mode {
            PlanMode::Bounded { branch_count, .. } => *branch_count,
            PlanMode::Delimited(plan) => plan.branch_count,
        }
    }

    pub(crate) fn is_exact_delimited(&self) -> bool {
        matches!(&self.mode, PlanMode::Delimited(_))
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

    /// Search one structurally proved union of terminal-delimited byte runs.
    ///
    /// Admission proves that every terminal byte is absent from every class
    /// and from all fixed bytes except its own final position. Consequently,
    /// each terminal partitions the source: a later match cannot begin before
    /// an already inspected terminal. The first authenticated endpoint is
    /// therefore both the selected leftmost match and the earliest endpoint.
    pub(crate) fn find_exact_delimited(
        &self,
        haystack: &[u8],
        start: usize,
        end: usize,
    ) -> Option<(usize, usize)> {
        let PlanMode::Delimited(plan) = &self.mode
        else {
            return None;
        };
        let mut position = start.checked_add(plan.minimum_match_bytes.saturating_sub(1))?;
        while position < end {
            let terminal_position = self.seek_terminal(haystack, position, end)?;
            let branch_index = usize::from(plan.terminal_to_branch[usize::from(
                haystack[terminal_position],
            )]);
            if let Some(branch) = plan.branches.get(branch_index) {
                if let Some(matched) = authenticate_delimited_branch(
                    branch,
                    haystack,
                    start,
                    terminal_position,
                ) {
                    return Some(matched);
                }
            }
            position = terminal_position.checked_add(1)?;
        }
        None
    }
}

fn authenticate_delimited_branch(
    branch: &DelimitedBranch,
    haystack: &[u8],
    window_start: usize,
    terminal_position: usize,
) -> Option<(usize, usize)> {
    let endpoint = terminal_position.checked_add(1)?;
    let right = branch.right();
    let right_start = endpoint.checked_sub(right.len())?;
    if right_start < window_start || haystack.get(right_start..endpoint)? != right {
        return None;
    }

    let mut cursor = right_start;
    while cursor > window_start && branch.class_contains(haystack[cursor - 1]) {
        cursor -= 1;
    }
    let class_bytes = right_start - cursor;
    let class_tail_len = usize::from(branch.class_tail_len);
    if class_bytes < class_tail_len.checked_add(usize::from(branch.minimum))? {
        return None;
    }
    let marker_len = branch.left().len().checked_sub(class_tail_len)?;
    let match_start = cursor.checked_sub(marker_len)?;
    if match_start < window_start {
        return None;
    }
    let left_end = match_start.checked_add(branch.left().len())?;
    if left_end > right_start || haystack.get(match_start..left_end)? != branch.left() {
        return None;
    }
    Some((match_start, endpoint))
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
    if let HirKind::Alternation(branches) = root.kind() {
        return inspect_exact_delimited_alternation(
            branches,
            work,
            max_planner_work,
        );
    }
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
        mode: InspectionMode::Bounded {
            minimum_match_bytes,
            maximum_match_bytes,
            branch_count: branches.len(),
        },
        planner_work: work,
    }))
}

fn inspect_exact_delimited_alternation(
    branches: &[Hir],
    mut work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome, InspectionError> {
    if !(2..=MAX_BRANCH_COUNT).contains(&branches.len()) {
        return Ok(InspectionOutcome::Ineligible { planner_work: work });
    }

    let mut inspected = [DelimitedBranch::EMPTY; MAX_BRANCH_COUNT];
    let mut terminal_words = [0_u64; 4];
    let mut terminal_to_branch = [NO_DELIMITED_BRANCH; 256];
    let mut minimum_match_bytes = usize::MAX;
    for (branch_index, branch) in branches.iter().enumerate() {
        let Some(branch) = inspect_exact_delimited_branch(
            branch,
            &mut work,
            max_planner_work,
        )? else {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        };
        let terminal = branch.terminal();
        charge(
            &mut work,
            TERMINAL_INSERTION_WORK,
            max_planner_work,
        )?;
        let terminal_index = usize::from(terminal);
        if terminal_to_branch[terminal_index] != NO_DELIMITED_BRANCH {
            return Ok(InspectionOutcome::Ineligible { planner_work: work });
        }
        terminal_to_branch[terminal_index] = u8::try_from(branch_index)
            .map_err(|_| InspectionError::ArithmeticOverflow)?;
        let word = usize::from(terminal >> 6);
        let bit = u32::from(terminal & 63);
        terminal_words[word] |= 1_u64 << bit;
        let minimum = checked_add_len(
            branch.left().len(),
            usize::from(branch.minimum),
            &mut work,
            max_planner_work,
        )?;
        let minimum = checked_add_len(
            minimum,
            branch.right().len(),
            &mut work,
            max_planner_work,
        )?;
        minimum_match_bytes = minimum_match_bytes.min(minimum);
        inspected[branch_index] = branch;
    }

    // A terminal is a global partition only when it cannot occur inside any
    // branch's class or fixed bytes. Its sole admitted fixed occurrence is the
    // final byte of its own right literal. This proof makes a forward terminal
    // scan complete for both leftmost starts and earliest endpoints.
    for terminal_branch in 0..branches.len() {
        let terminal = inspected[terminal_branch].terminal();
        for (branch_index, branch) in inspected[..branches.len()].iter().enumerate() {
            charge(
                &mut work,
                MEMBERSHIP_PROOF_WORK,
                max_planner_work,
            )?;
            if branch.class_contains(terminal) {
                return Ok(InspectionOutcome::Ineligible { planner_work: work });
            }
            for &byte in branch.left() {
                charge(
                    &mut work,
                    MEMBERSHIP_PROOF_WORK,
                    max_planner_work,
                )?;
                if byte == terminal {
                    return Ok(InspectionOutcome::Ineligible { planner_work: work });
                }
            }
            for (fixed_index, &byte) in branch.right().iter().enumerate() {
                charge(
                    &mut work,
                    MEMBERSHIP_PROOF_WORK,
                    max_planner_work,
                )?;
                let own_final = terminal_branch == branch_index
                    && fixed_index.checked_add(1) == Some(branch.right().len());
                if byte == terminal && !own_final {
                    return Ok(InspectionOutcome::Ineligible { planner_work: work });
                }
            }
        }
    }

    charge(&mut work, LEAF_SELECTION_WORK, max_planner_work)?;
    let terminal_cardinality = u32::try_from(branches.len())
        .map_err(|_| InspectionError::ArithmeticOverflow)?;
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
        mode: InspectionMode::Delimited(DelimitedPlan {
            branches: inspected,
            terminal_to_branch,
            minimum_match_bytes,
            branch_count: branches.len(),
        }),
        planner_work: work,
    }))
}

fn inspect_exact_delimited_branch(
    branch: &Hir,
    work: &mut u64,
    max_planner_work: u64,
) -> Result<Option<DelimitedBranch>, InspectionError> {
    let branch = peel_captures(branch, work, max_planner_work)?;
    let HirKind::Concat(parts) = branch.kind() else {
        return Ok(None);
    };
    let mut inspected = DelimitedBranch::EMPTY;
    let mut saw_repeat = false;
    for part in parts {
        let part = peel_captures(part, work, max_planner_work)?;
        match part.kind() {
            HirKind::Literal(literal) if !literal.0.is_empty() => {
                charge_literal(literal.0.len(), work, max_planner_work)?;
                let appended = if saw_repeat {
                    append_delimited_literal(
                        &mut inspected.right,
                        &mut inspected.right_len,
                        &literal.0,
                    )
                } else {
                    append_delimited_literal(
                        &mut inspected.left,
                        &mut inspected.left_len,
                        &literal.0,
                    )
                };
                if !appended {
                    return Ok(None);
                }
            }
            HirKind::Repetition(repetition) if !saw_repeat => {
                if inspected.left_len == 0
                    || repetition.max.is_some()
                    || repetition.min > 1
                    || !repetition.greedy
                {
                    return Ok(None);
                }
                let atom = peel_captures(&repetition.sub, work, max_planner_work)?;
                let HirKind::Class(Class::Bytes(class)) = atom.kind() else {
                    return Ok(None);
                };
                let mut nonempty = false;
                for range in class.ranges() {
                    charge(work, RANGE_INSPECTION_WORK, max_planner_work)?;
                    let mut byte = range.start();
                    loop {
                        charge(
                            work,
                            CLASS_MEMBER_INSERTION_WORK,
                            max_planner_work,
                        )?;
                        let word = usize::from(byte >> 6);
                        let bit = u32::from(byte & 63);
                        inspected.class_words[word] |= 1_u64 << bit;
                        nonempty = true;
                        if byte == range.end() {
                            break;
                        }
                        byte = byte
                            .checked_add(1)
                            .ok_or(InspectionError::ArithmeticOverflow)?;
                    }
                }
                if !nonempty {
                    return Ok(None);
                }
                inspected.minimum = u8::try_from(repetition.min)
                    .map_err(|_| InspectionError::ArithmeticOverflow)?;
                saw_repeat = true;
            }
            _ => return Ok(None),
        }
    }
    if !saw_repeat || inspected.right_len == 0 {
        return Ok(None);
    }

    let mut class_tail_len = 0_usize;
    for &byte in inspected.left().iter().rev() {
        charge(
            work,
            MEMBERSHIP_PROOF_WORK,
            max_planner_work,
        )?;
        if !inspected.class_contains(byte) {
            break;
        }
        class_tail_len = class_tail_len
            .checked_add(1)
            .ok_or(InspectionError::ArithmeticOverflow)?;
    }
    if class_tail_len == inspected.left().len() {
        return Ok(None);
    }
    inspected.class_tail_len = u8::try_from(class_tail_len)
        .map_err(|_| InspectionError::ArithmeticOverflow)?;
    Ok(Some(inspected))
}

fn append_delimited_literal(
    destination: &mut [u8; MAX_DELIMITED_LITERAL_BYTES],
    destination_len: &mut u8,
    source: &[u8],
) -> bool {
    let start = usize::from(*destination_len);
    let Some(end) = start.checked_add(source.len()) else {
        return false;
    };
    let Some(output) = destination.get_mut(start..end) else {
        return false;
    };
    output.copy_from_slice(source);
    let Ok(end) = u8::try_from(end) else {
        return false;
    };
    *destination_len = end;
    true
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

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{
        InspectionError, InspectionOutcome, Plan, SimdDispatchContext, inspect,
    };

    const TARGET: &str = r"(?-u:(?:ab[bc]*Z|q[de]*Y))";

    fn parse(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn exact_plan(pattern: &str) -> (Plan, u64) {
        let InspectionOutcome::Eligible(inspection) =
            inspect(&parse(pattern), 0, u64::MAX).unwrap()
        else {
            panic!("exact delimited alternation was refused: {pattern:?}");
        };
        let work = inspection.planner_work;
        let plan = inspection.build(SimdDispatchContext::capture());
        assert!(plan.is_exact_delimited());
        (plan, work)
    }

    fn inspection_storage_bytes(pattern: &str) -> usize {
        let InspectionOutcome::Eligible(inspection) =
            inspect(&parse(pattern), 0, u64::MAX).unwrap()
        else {
            panic!("exact delimited alternation was refused: {pattern:?}");
        };
        inspection.storage_bytes()
    }

    #[test]
    fn exact_delimited_alternation_authenticates_branch_local_runs() {
        let (plan, _) = exact_plan(TARGET);
        for (haystack, expected) in [
            (b"".as_slice(), None),
            (b"abZ", Some((0, 3))),
            (b"xxabbbbbZyy", Some((2, 9))),
            (b"xxqddddYyy", Some((2, 8))),
            (b"abbbbbY qddZ", None),
            (b"abbbbbY~qddY", Some((8, 12))),
            (b"Z~qY~abccZ", Some((2, 4))),
        ] {
            assert_eq!(
                plan.find_exact_delimited(haystack, 0, haystack.len()),
                expected,
                "haystack={haystack:?}",
            );
        }
        assert_eq!(
            plan.find_exact_delimited(b"xxabbbbbZyy", 3, 11),
            None,
            "a window may not reuse a delimiter before its start",
        );
    }

    #[test]
    fn one_minimum_excludes_the_left_literal_class_tail() {
        let (plan, _) = exact_plan(r"(?-u:(?:ab[bc]+Z|q[de]+Y))");
        assert_eq!(plan.find_exact_delimited(b"abZ~qY", 0, 6), None);
        assert_eq!(
            plan.find_exact_delimited(b"abZ~qdY~abbZ", 0, 12),
            Some((4, 7)),
        );
    }

    #[test]
    fn exact_delimited_admits_eight_branches_and_arbitrary_bytes() {
        let (plan, _) = exact_plan(
            r"(?-u:(?:a[bc]*Z|d[ef]*Y|g[hi]*X|j[kl]*W|m[no]*V|p[qr]*U|s[tu]*T|v[wx]*S))",
        );
        assert_eq!(plan.branch_count(), 8);

        let (plan, _) = exact_plan(
            r"(?-u:(?:\x80[\x81-\x82]*\xFE|\x90[\x91-\x92]+\xFF))",
        );
        assert_eq!(
            plan.find_exact_delimited(
                &[0_u8, 0x80, 0x81, 0x82, 0xFE, 0x90, 0x91, 0xFF],
                0,
                8,
            ),
            Some((1, 5)),
        );
    }

    #[test]
    fn planner_work_and_fixed_storage_are_exact_boundaries() {
        let hir = parse(TARGET);
        let (plan, exact_work) = exact_plan(TARGET);
        assert_eq!(
            inspection_storage_bytes(TARGET),
            plan.storage_bytes(),
        );
        assert_eq!(
            plan.storage_bytes(),
            core::mem::size_of_val(&plan) + core::mem::size_of::<super::DelimitedPlan>(),
        );

        let bounded = parse(
            r"(?-u:\x10(?:\x70[\x30\x31]{0,16}\x60|\x71[\x36\x37]{1,16}\x61))",
        );
        let InspectionOutcome::Eligible(bounded) =
            inspect(&bounded, 0, u64::MAX).unwrap()
        else {
            panic!("bounded correlated fixture was refused");
        };
        let bounded_storage_bytes = bounded.storage_bytes();
        let bounded = bounded.build(SimdDispatchContext::capture());
        assert_eq!(bounded_storage_bytes, bounded.storage_bytes());
        assert_eq!(bounded.storage_bytes(), core::mem::size_of::<Plan>());

        assert!(matches!(
            inspect(&hir, 0, exact_work).unwrap(),
            InspectionOutcome::Eligible(_),
        ));
        let error = match inspect(&hir, 0, exact_work - 1) {
            Err(error) => error,
            Ok(_) => panic!("one-below planner work unexpectedly succeeded"),
        };
        assert_eq!(
            error,
            InspectionError::WorkLimit {
                needed: exact_work,
                limit: exact_work - 1,
            },
        );
    }

    #[test]
    fn every_partition_or_shape_violation_is_refused() {
        for pattern in [
            r"(?-u:(?:ab[bc]*Z|q[de]*Z))",
            r"(?-u:(?:ab[bZ]*Z|q[de]*Y))",
            r"(?-u:(?:aYb[bc]*Z|q[de]*Y))",
            r"(?-u:(?:ab[bc]*YZ|q[de]*Y))",
            r"(?-u:(?:b[bc]*Z|q[de]*Y))",
            r"(?-u:(?:ab[bc]*?Z|q[de]*Y))",
            r"(?-u:(?:ab[bc]{0,8}Z|q[de]*Y))",
            r"(?-u:(?:ab[bc]*Z|q[de]*Y|r[fg]*X|s[hi]*W|t[jk]*V|u[lm]*U|v[no]*T|w[pq]*S|x[rs]*R))",
            r"(?-u:(?:ab[bc]*Z|q[de]*\bY))",
        ] {
            assert!(
                matches!(
                    inspect(&parse(pattern), 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. },
                ),
                "unexpected exact-delimited admission: {pattern:?}",
            );
        }
    }
}
