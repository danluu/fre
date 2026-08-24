//! Exact ordinary projections for deterministic token-loop lines.
//!
//! Construction admits byte-mode `StartLF (BRANCH | ...)+ TERMINAL EndLF`.
//! Each branch is a positive sequence of singleton-byte atoms, including
//! greedy repetitions. Branch-leading bytes are pairwise disjoint, every
//! variable-width atom is disjoint from every nullable successor through the
//! next required atom, and every branch ends in a fixed positive atom. The
//! resulting token stream has one forward parse.
//!
//! Predicate execution seeks the first potential terminal directly, then can
//! continue exactly by remaining line ends. Span execution may continue
//! through a small bounded number of later terminal candidates, in source
//! order. Exhausting that span bound or otherwise declining fails open so the
//! caller can replay canonical K0.

use core::mem::size_of;

use memchr::{memchr, memrchr};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

const MAX_BRANCHES: usize = 4;
const MAX_ATOMS: usize = 16;
const MAX_TERMINAL_BYTES: usize = 8;
const MAX_LATER_FIND_CANDIDATES: usize = 4;
const UNBOUNDED: u8 = u8::MAX;
pub(crate) const MIN_INPUT_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Atom {
    byte: u8,
    minimum: u8,
    maximum: u8,
}

impl Atom {
    const EMPTY: Self = Self {
        byte: 0,
        minimum: 0,
        maximum: 0,
    };

    const fn variable(self) -> bool {
        self.maximum == UNBOUNDED || self.maximum != self.minimum
    }

    fn maximum(self) -> Option<usize> {
        if self.maximum == UNBOUNDED {
            None
        } else {
            Some(usize::from(self.maximum))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Branch {
    start: u8,
    end: u8,
}

impl Branch {
    const EMPTY: Self = Self { start: 0, end: 0 };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    atoms: [Atom; MAX_ATOMS],
    branches: [Branch; MAX_BRANCHES],
    branch_count: u8,
    terminal: [u8; MAX_TERMINAL_BYTES],
    terminal_len: u8,
}

impl Plan {
    pub(crate) const fn storage_bytes() -> usize {
        size_of::<Self>()
    }

    /// Attempt the complete ordinary full-input predicate.
    ///
    /// `None` is a source-shape refusal, never a negative answer. The caller
    /// must replay canonical K0 in that case.
    #[inline]
    pub(crate) fn try_is_match_full(&self, haystack: &[u8]) -> Option<bool> {
        let output = if haystack.len() < MIN_INPUT_BYTES {
            None
        } else {
            let terminal_len = usize::from(self.terminal_len);
            match haystack.len().checked_sub(terminal_len) {
                None => None,
                Some(last_start) => {
                    let terminal = &self.terminal[..terminal_len];
                    match memchr(terminal[0], &haystack[..=last_start]) {
                        None => Some(false),
                        Some(candidate) => match candidate.checked_add(terminal_len) {
                            None => None,
                            Some(candidate_end) => {
                                if &haystack[candidate..candidate_end] != terminal
                                    || (candidate_end != haystack.len()
                                        && haystack[candidate_end] != b'\n')
                                {
                                    self.try_later_exists_by_line_end(haystack)
                                } else {
                                    self.try_authenticated_candidate(haystack, candidate)
                                }
                            }
                        },
                    }
                }
            }
        };
        #[cfg(test)]
        route_probe::record(output);
        output
    }

    /// Continue by candidate-bearing lines after the predicate's first
    /// terminal candidate is rejected. A line can match only when its terminal
    /// is its suffix, so each such line is authenticated at most once. Lines
    /// without the terminal lead byte are skipped in one forward scan. This
    /// never needs a candidate cap or partial work followed by canonical replay.
    #[inline(never)]
    fn try_later_exists_by_line_end(&self, haystack: &[u8]) -> Option<bool> {
        let terminal = &self.terminal[..usize::from(self.terminal_len)];
        let last_start = haystack.len().checked_sub(terminal.len())?;
        let first_candidate = memchr(terminal[0], &haystack[..=last_start])?;
        let mut line_search_start = 0_usize;
        let mut candidate = first_candidate;
        loop {
            let line_start = match memrchr(b'\n', &haystack[line_search_start..candidate]) {
                Some(relative) => line_search_start.checked_add(relative)?.checked_add(1)?,
                None => line_search_start,
            };
            let after_candidate = candidate.checked_add(1)?;
            let line_end = match memchr(b'\n', &haystack[after_candidate..]) {
                Some(relative) => after_candidate.checked_add(relative)?,
                None => haystack.len(),
            };
            if let Some(suffix_start) = line_end.checked_sub(terminal.len())
                && suffix_start > first_candidate
                && suffix_start >= line_start
                && &haystack[suffix_start..line_end] == terminal
                && self.matches_body(&haystack[line_start..suffix_start])
            {
                return Some(true);
            }
            if line_end == haystack.len() {
                return Some(false);
            }
            line_search_start = line_end.checked_add(1)?;
            let Some(relative) = memchr(terminal[0], &haystack[line_search_start..]) else {
                return Some(false);
            };
            candidate = line_search_start.checked_add(relative)?;
        }
    }

    /// Attempt the complete ordinary full-input leftmost-first span.
    ///
    /// `None` is a source-shape refusal, never a negative answer. The caller
    /// must replay canonical K0 in that case.
    #[inline(never)]
    pub(crate) fn try_find_full(&self, haystack: &[u8]) -> Option<Option<(usize, usize)>> {
        let output = if haystack.len() < MIN_INPUT_BYTES {
            None
        } else {
            let terminal_len = usize::from(self.terminal_len);
            match haystack.len().checked_sub(terminal_len) {
                None => None,
                Some(last_start) => {
                    let terminal = &self.terminal[..terminal_len];
                    match memchr(terminal[0], &haystack[..=last_start]) {
                        None => Some(None),
                        Some(candidate) => match candidate.checked_add(terminal_len) {
                            None => None,
                            Some(candidate_end) => {
                                if &haystack[candidate..candidate_end] != terminal
                                    || (candidate_end != haystack.len()
                                        && haystack[candidate_end] != b'\n')
                                {
                                    self.try_later_span_candidates(
                                        haystack, terminal, last_start, candidate,
                                    )
                                    .map(Some)
                                } else {
                                    match self.try_authenticated_span_candidate(
                                        haystack,
                                        candidate,
                                        candidate_end,
                                    ) {
                                        Some(span) => Some(Some(span)),
                                        None => self
                                            .try_later_span_candidates(
                                                haystack, terminal, last_start, candidate,
                                            )
                                            .map(Some),
                                    }
                                }
                            }
                        },
                    }
                }
            }
        };
        #[cfg(test)]
        span_route_probe::record(output);
        output
    }

    /// Continue strictly after a rejected first terminal candidate.
    ///
    /// Advancing one byte preserves overlapping multi-byte terminals. Every
    /// potential start is considered in increasing order, so a returned span
    /// is the exact leftmost valid later line. A missing candidate, arithmetic
    /// refusal, or the explicit cap declines to canonical K0.
    #[inline(never)]
    fn try_later_span_candidates(
        &self,
        haystack: &[u8],
        terminal: &[u8],
        last_start: usize,
        first_candidate: usize,
    ) -> Option<(usize, usize)> {
        let mut search_start = first_candidate.checked_add(1)?;
        for _ in 0..MAX_LATER_FIND_CANDIDATES {
            if search_start > last_start {
                return None;
            }
            let relative = memchr(terminal[0], &haystack[search_start..=last_start])?;
            let candidate = search_start.checked_add(relative)?;
            let candidate_end = candidate.checked_add(terminal.len())?;
            if &haystack[candidate..candidate_end] == terminal
                && (candidate_end == haystack.len() || haystack[candidate_end] == b'\n')
                && let Some(span) =
                    self.try_authenticated_span_candidate(haystack, candidate, candidate_end)
            {
                return Some(span);
            }
            search_start = candidate.checked_add(1)?;
        }
        None
    }

    #[inline(never)]
    fn try_authenticated_candidate(&self, haystack: &[u8], candidate: usize) -> Option<bool> {
        let line_start = memrchr(b'\n', &haystack[..candidate])
            .and_then(|delimiter| delimiter.checked_add(1))
            .unwrap_or(0);
        if self.matches_body(&haystack[line_start..candidate]) {
            Some(true)
        } else {
            self.try_later_exists_by_line_end(haystack)
        }
    }

    #[inline(never)]
    fn try_authenticated_span_candidate(
        &self,
        haystack: &[u8],
        candidate: usize,
        candidate_end: usize,
    ) -> Option<(usize, usize)> {
        let line_start = memrchr(b'\n', &haystack[..candidate])
            .and_then(|delimiter| delimiter.checked_add(1))
            .unwrap_or(0);
        self.matches_span_body(&haystack[line_start..candidate])
            .then_some((line_start, candidate_end))
    }

    fn matches_span_body(&self, body: &[u8]) -> bool {
        let mut position = 0_usize;
        let mut tokens = 0_usize;
        while position < body.len() {
            let Some(branch) = self.branch_for(body[position]) else {
                return false;
            };
            let before = position;
            let Some(after) = self.match_branch(branch, body, position) else {
                return false;
            };
            if after <= before {
                return false;
            }
            position = after;
            tokens = tokens.saturating_add(1);
        }
        tokens > 0
    }

    #[inline(always)]
    fn matches_body(&self, body: &[u8]) -> bool {
        let mut position = 0_usize;
        let mut tokens = 0_usize;
        while position < body.len() {
            let Some(branch) = self.branch_for(body[position]) else {
                return false;
            };
            let before = position;
            let Some(after) = self.match_branch(branch, body, position) else {
                return false;
            };
            if after <= before {
                return false;
            }
            position = after;
            tokens = tokens.saturating_add(1);
        }
        tokens > 0
    }

    fn branch_for(&self, byte: u8) -> Option<Branch> {
        self.branches[..usize::from(self.branch_count)]
            .iter()
            .copied()
            .find(|branch| self.atoms[usize::from(branch.start)].byte == byte)
    }

    fn match_branch(&self, branch: Branch, body: &[u8], mut position: usize) -> Option<usize> {
        for atom in &self.atoms[usize::from(branch.start)..usize::from(branch.end)] {
            let maximum = atom.maximum().unwrap_or(usize::MAX);
            let mut consumed = 0_usize;
            while consumed < maximum && position < body.len() && body[position] == atom.byte {
                consumed = consumed.checked_add(1)?;
                position = position.checked_add(1)?;
            }
            if consumed < usize::from(atom.minimum) {
                return None;
            }
        }
        Some(position)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionOutcome {
    Eligible { plan: Plan, planner_work: u64 },
    Ineligible { planner_work: u64 },
}

impl InspectionOutcome {
    pub(crate) const fn planner_work(self) -> u64 {
        match self {
            Self::Eligible { planner_work, .. } | Self::Ineligible { planner_work } => planner_work,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionError {
    WorkLimit {
        actual: u64,
        needed: u64,
        limit: u64,
    },
    ArithmeticOverflow,
}

struct Budget {
    actual: u64,
    limit: u64,
}

impl Budget {
    const fn new(actual: u64, limit: u64) -> Self {
        Self { actual, limit }
    }

    fn charge(&mut self, amount: u64) -> Result<(), InspectionError> {
        let needed = self
            .actual
            .checked_add(amount)
            .ok_or(InspectionError::ArithmeticOverflow)?;
        if needed > self.limit {
            return Err(InspectionError::WorkLimit {
                actual: self.actual,
                needed,
                limit: self.limit,
            });
        }
        self.actual = needed;
        Ok(())
    }
}

#[cold]
#[allow(
    clippy::too_many_lines,
    reason = "the bounded HIR transaction keeps grammar and determinism proofs adjacent"
)]
pub(crate) fn inspect(
    hir: &Hir,
    unicode: bool,
    case_insensitive: bool,
    line_terminator: u8,
    initial_work: u64,
    work_limit: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut budget = Budget::new(initial_work, work_limit);
    budget.charge(1)?;
    if unicode || case_insensitive || line_terminator != b'\n' {
        return ineligible(budget.actual);
    }
    let root = transparent(hir, &mut budget)?;
    let HirKind::Concat(parts) = root.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(1)?;
    let [start, repeated, terminal, end] = parts.as_slice() else {
        return ineligible(budget.actual);
    };
    if !matches!(
        transparent(start, &mut budget)?.kind(),
        HirKind::Look(Look::StartLF)
    ) || !matches!(
        transparent(end, &mut budget)?.kind(),
        HirKind::Look(Look::EndLF)
    ) {
        return ineligible(budget.actual);
    }

    let repeated = transparent(repeated, &mut budget)?;
    let HirKind::Repetition(repetition) = repeated.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(1)?;
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return ineligible(budget.actual);
    }
    let alternation = transparent(repetition.sub.as_ref(), &mut budget)?;
    let HirKind::Alternation(branch_hirs) = alternation.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(1)?;
    if !(2..=MAX_BRANCHES).contains(&branch_hirs.len()) {
        return ineligible(budget.actual);
    }

    let mut atoms = [Atom::EMPTY; MAX_ATOMS];
    let mut branches = [Branch::EMPTY; MAX_BRANCHES];
    let mut atom_count = 0_usize;
    for (branch_index, branch_hir) in branch_hirs.iter().enumerate() {
        let start = atom_count;
        if !append_branch(branch_hir, &mut atoms, &mut atom_count, &mut budget)? {
            return ineligible(budget.actual);
        }
        let end = atom_count;
        if start == end {
            return ineligible(budget.actual);
        }
        let first = atoms[start];
        let last_index = end
            .checked_sub(1)
            .ok_or(InspectionError::ArithmeticOverflow)?;
        let last = atoms[last_index];
        budget.charge(1)?;
        if first.minimum == 0 || last.minimum == 0 || last.variable() {
            return ineligible(budget.actual);
        }
        for prior in &branches[..branch_index] {
            budget.charge(1)?;
            if atoms[usize::from(prior.start)].byte == first.byte {
                return ineligible(budget.actual);
            }
        }
        branches[branch_index] = Branch {
            start: u8::try_from(start).map_err(|_| InspectionError::ArithmeticOverflow)?,
            end: u8::try_from(end).map_err(|_| InspectionError::ArithmeticOverflow)?,
        };
    }

    for branch in &branches[..branch_hirs.len()] {
        let start = usize::from(branch.start);
        let end = usize::from(branch.end);
        for index in start..end {
            budget.charge(1)?;
            let atom = atoms[index];
            if !atom.variable() {
                continue;
            }
            let mut successor = index
                .checked_add(1)
                .ok_or(InspectionError::ArithmeticOverflow)?;
            if successor == end {
                return ineligible(budget.actual);
            }
            loop {
                budget.charge(1)?;
                let next = atoms[successor];
                if atom.byte == next.byte {
                    return ineligible(budget.actual);
                }
                if next.minimum > 0 {
                    break;
                }
                successor = successor
                    .checked_add(1)
                    .ok_or(InspectionError::ArithmeticOverflow)?;
                if successor == end {
                    return ineligible(budget.actual);
                }
            }
        }
    }

    let terminal = transparent(terminal, &mut budget)?;
    let HirKind::Literal(literal) = terminal.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(1)?;
    if literal.0.is_empty() || literal.0.len() > MAX_TERMINAL_BYTES || literal.0.contains(&b'\n') {
        return ineligible(budget.actual);
    }
    budget
        .charge(u64::try_from(literal.0.len()).map_err(|_| InspectionError::ArithmeticOverflow)?)?;
    let mut terminal = [0_u8; MAX_TERMINAL_BYTES];
    terminal[..literal.0.len()].copy_from_slice(&literal.0);

    Ok(InspectionOutcome::Eligible {
        plan: Plan {
            atoms,
            branches,
            branch_count: u8::try_from(branch_hirs.len())
                .map_err(|_| InspectionError::ArithmeticOverflow)?,
            terminal,
            terminal_len: u8::try_from(literal.0.len())
                .map_err(|_| InspectionError::ArithmeticOverflow)?,
        },
        planner_work: budget.actual,
    })
}

fn append_branch(
    hir: &Hir,
    atoms: &mut [Atom; MAX_ATOMS],
    atom_count: &mut usize,
    budget: &mut Budget,
) -> Result<bool, InspectionError> {
    let hir = transparent(hir, budget)?;
    match hir.kind() {
        HirKind::Concat(parts) => {
            if parts.is_empty() {
                return Ok(false);
            }
            for part in parts {
                if !append_branch(part, atoms, atom_count, budget)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        HirKind::Literal(literal) if !literal.0.is_empty() => {
            for &byte in &literal.0 {
                budget.charge(1)?;
                if byte == b'\n'
                    || !push_atom(
                        atoms,
                        atom_count,
                        Atom {
                            byte,
                            minimum: 1,
                            maximum: 1,
                        },
                    )
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        HirKind::Class(Class::Bytes(class)) => {
            budget.charge(1)?;
            let [range] = class.ranges() else {
                return Ok(false);
            };
            if range.start() != range.end() || range.start() == b'\n' {
                return Ok(false);
            }
            Ok(push_atom(
                atoms,
                atom_count,
                Atom {
                    byte: range.start(),
                    minimum: 1,
                    maximum: 1,
                },
            ))
        }
        HirKind::Repetition(repetition) => {
            budget.charge(1)?;
            if !repetition.greedy {
                return Ok(false);
            }
            let Some(byte) = singleton_byte(repetition.sub.as_ref(), budget)? else {
                return Ok(false);
            };
            if byte == b'\n' {
                return Ok(false);
            }
            let Ok(minimum) = u8::try_from(repetition.min) else {
                return Ok(false);
            };
            if minimum == UNBOUNDED {
                return Ok(false);
            }
            let maximum = match repetition.max {
                None => UNBOUNDED,
                Some(maximum) => {
                    let Ok(maximum) = u8::try_from(maximum) else {
                        return Ok(false);
                    };
                    if maximum == UNBOUNDED || maximum < minimum || maximum == 0 {
                        return Ok(false);
                    }
                    maximum
                }
            };
            Ok(push_atom(
                atoms,
                atom_count,
                Atom {
                    byte,
                    minimum,
                    maximum,
                },
            ))
        }
        _ => Ok(false),
    }
}

fn singleton_byte(hir: &Hir, budget: &mut Budget) -> Result<Option<u8>, InspectionError> {
    let hir = transparent(hir, budget)?;
    Ok(match hir.kind() {
        HirKind::Literal(literal) => match literal.0.as_ref() {
            [byte] => Some(*byte),
            _ => None,
        },
        HirKind::Class(Class::Bytes(class)) => match class.ranges() {
            [range] if range.start() == range.end() => Some(range.start()),
            _ => None,
        },
        _ => None,
    })
}

fn push_atom(atoms: &mut [Atom; MAX_ATOMS], atom_count: &mut usize, atom: Atom) -> bool {
    let Some(slot) = atoms.get_mut(*atom_count) else {
        return false;
    };
    *slot = atom;
    *atom_count = atom_count
        .checked_add(1)
        .expect("an available fixed atom slot advances once");
    true
}

fn transparent<'a>(mut hir: &'a Hir, budget: &mut Budget) -> Result<&'a Hir, InspectionError> {
    loop {
        budget.charge(1)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = capture.sub.as_ref();
    }
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the helper preserves concise transactional early returns from the fallible inspector"
)]
fn ineligible(planner_work: u64) -> Result<InspectionOutcome, InspectionError> {
    Ok(InspectionOutcome::Ineligible { planner_work })
}

#[cfg(test)]
pub(crate) mod route_probe {
    use core::cell::Cell;

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct Counts {
        pub(crate) attempts: usize,
        pub(crate) completed: usize,
        pub(crate) declined: usize,
    }

    thread_local! {
        static COUNTS: Cell<Counts> = Cell::new(Counts::default());
    }

    pub(super) fn record(output: Option<bool>) {
        COUNTS.with(|slot| {
            let counts = slot.get();
            slot.set(Counts {
                attempts: counts.attempts.saturating_add(1),
                completed: counts
                    .completed
                    .saturating_add(usize::from(output.is_some())),
                declined: counts
                    .declined
                    .saturating_add(usize::from(output.is_none())),
            });
        });
    }

    pub(crate) fn reset() {
        COUNTS.with(|slot| slot.set(Counts::default()));
    }

    pub(crate) fn snapshot() -> Counts {
        COUNTS.with(Cell::get)
    }
}

#[cfg(test)]
pub(crate) mod span_route_probe {
    use core::cell::Cell;

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct Counts {
        pub(crate) attempts: usize,
        pub(crate) completed: usize,
        pub(crate) declined: usize,
    }

    thread_local! {
        static COUNTS: Cell<Counts> = Cell::new(Counts::default());
    }

    pub(super) fn record(output: Option<Option<(usize, usize)>>) {
        COUNTS.with(|slot| {
            let counts = slot.get();
            slot.set(Counts {
                attempts: counts.attempts.saturating_add(1),
                completed: counts
                    .completed
                    .saturating_add(usize::from(output.is_some())),
                declined: counts
                    .declined
                    .saturating_add(usize::from(output.is_none())),
            });
        });
    }

    pub(crate) fn reset() {
        COUNTS.with(|slot| slot.set(Counts::default()));
    }

    pub(crate) fn snapshot() -> Counts {
        COUNTS.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use regex_syntax::ParserBuilder;

    use super::{InspectionOutcome, inspect};
    use crate::{BuildLimits, PlanSelection, PortableBuilder, PortablePlan};

    fn parse(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn plan(pattern: &str) -> super::Plan {
        let InspectionOutcome::Eligible { plan, .. } =
            inspect(&parse(pattern), false, false, b'\n', 0, u64::MAX).unwrap()
        else {
            panic!("expected line-token eligibility for {pattern:?}");
        };
        plan
    }

    fn eligible(pattern: &str) -> bool {
        matches!(
            inspect(&parse(pattern), false, false, b'\n', 0, u64::MAX).unwrap(),
            InspectionOutcome::Eligible { .. }
        )
    }

    #[test]
    fn generic_loop_and_nearby_singleton_programs_are_structural() {
        assert!(eligible(r"(?m)^(?:ab+c|de?f)+Z$"));
        assert!(eligible(r"(?m)^(?:xy{2,4}q|rst)+END$"));
        for pattern in [
            r"(?m)^(?:ab+c|ab?f)+Z$",
            r"(?m)^(?:ab+b|de?f)+Z$",
            r"(?m)^(?:ab+|de?)+Z$",
            r"(?m)^(?:a*|def)+Z$",
            r"(?m)^(?:ab+c|de?f)*Z$",
            r"(?m)^(?:ab+c|de?f)+Z",
            r"(?m)^(?:ab+c|de?f)+Z.$",
            r"(?m)^(?:ab+\n|de?f)+Z$",
            r"(?Rm)^(?:ab+c|de?f)+Z$",
        ] {
            assert!(!eligible(pattern), "unexpectedly admitted {pattern:?}");
        }
        assert!(matches!(
            inspect(
                &parse(r"(?m)^(?:ab+c|de?f)+Z$"),
                false,
                false,
                b'|',
                0,
                u64::MAX,
            )
            .unwrap(),
            InspectionOutcome::Ineligible { .. }
        ));
    }

    #[test]
    fn rejected_candidate_continues_to_the_first_valid_later_line() {
        let pattern = r"(?m)^(?:ab+c|de?f)+Z$";
        let plan = plan(pattern);
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let mut source = vec![b'q'; 1_024];
        source.extend_from_slice(b"\nabZ\nabbbcdefZ\ndefabbbcZ\n");
        let expected = oracle
            .find(&source)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(plan.try_is_match_full(&source), Some(expected.is_some()));
        assert_eq!(plan.try_find_full(&source), Some(expected));

        let first_valid = source
            .windows(b"abbbcdefZ".len())
            .position(|window| window == b"abbbcdefZ")
            .unwrap();
        let position = first_valid + b"abbbcde".len();
        assert_eq!(source[position], b'f');
        let address = source.as_ptr();
        source[position] = b'Q';
        assert_eq!(source.as_ptr(), address);
        let expected = oracle
            .find(&source)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(plan.try_is_match_full(&source), Some(expected.is_some()));
        assert_eq!(plan.try_find_full(&source), Some(expected));
    }

    #[test]
    fn later_candidate_search_advances_one_byte_for_overlapping_terminals() {
        let pattern = r"(?m)^(?:xA|yz)+AAA$";
        let plan = plan(pattern);
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let mut source = vec![b'q'; 1_024];
        source.extend_from_slice(b"\nxAAAA\n");
        let expected = oracle
            .find(&source)
            .map(|matched| (matched.start(), matched.end()));

        assert!(expected.is_some());
        assert_eq!(plan.try_is_match_full(&source), Some(true));
        assert_eq!(plan.try_find_full(&source), Some(expected));
    }

    #[test]
    fn predicate_remains_exact_across_the_span_candidate_cap() {
        let pattern = r"(?m)^(?:ab+c|de?f)+Z$";
        let plan = plan(pattern);
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let source = |rejected_lines: usize| {
            let mut source = vec![b'q'; 1_024];
            for _ in 0..rejected_lines {
                source.extend_from_slice(b"\nabZ");
            }
            source.extend_from_slice(b"\nabbbcdefZ\n");
            source
        };

        for rejected_lines in 1..=super::MAX_LATER_FIND_CANDIDATES {
            let admitted = source(rejected_lines);
            let expected = oracle
                .find(&admitted)
                .map(|matched| (matched.start(), matched.end()));
            assert!(expected.is_some());
            assert_eq!(plan.try_is_match_full(&admitted), Some(true));
            assert_eq!(plan.try_find_full(&admitted), Some(expected));
            super::route_probe::reset();
            assert!(regex.is_match(&admitted));
            assert_eq!(
                super::route_probe::snapshot(),
                super::route_probe::Counts {
                    attempts: 1,
                    completed: 1,
                    declined: 0,
                },
            );
        }

        for rejected_lines in [
            super::MAX_LATER_FIND_CANDIDATES + 1,
            super::MAX_LATER_FIND_CANDIDATES * 8 + 1,
        ] {
            let beyond_cap = source(rejected_lines);
            let expected = oracle
                .find(&beyond_cap)
                .map(|matched| (matched.start(), matched.end()));
            assert!(expected.is_some());
            assert_eq!(plan.try_is_match_full(&beyond_cap), Some(true));
            assert_eq!(plan.try_find_full(&beyond_cap), None);
            super::route_probe::reset();
            assert!(regex.is_match(&beyond_cap));
            assert_eq!(
                super::route_probe::snapshot(),
                super::route_probe::Counts {
                    attempts: 1,
                    completed: 1,
                    declined: 0,
                },
            );
            assert_eq!(
                regex
                    .find(&beyond_cap)
                    .map(|matched| (matched.start(), matched.end())),
                expected,
            );
        }

        for rejected_lines in [
            super::MAX_LATER_FIND_CANDIDATES,
            super::MAX_LATER_FIND_CANDIDATES + 1,
            super::MAX_LATER_FIND_CANDIDATES * 8 + 1,
        ] {
            let mut rejected_only = vec![b'q'; 1_024];
            for _ in 0..rejected_lines {
                rejected_only.extend_from_slice(b"\nabZ");
            }
            rejected_only.push(b'\n');
            assert!(!oracle.is_match(&rejected_only));
            assert_eq!(plan.try_is_match_full(&rejected_only), Some(false));
            assert_eq!(plan.try_find_full(&rejected_only), None);
        }
    }

    #[test]
    fn multiline_mutations_match_the_independent_oracle() {
        let pattern = r"(?m)^(?:ab+c|de?f)+Z$";
        let plan = plan(pattern);
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let regex = PortableBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let mut original = vec![b'q'; 1_024];
        original.extend_from_slice(b"\nabZ\nabbbcdefZ\ndefabbbcZ\n");

        for position in 1_024..original.len() {
            for byte in [
                0, b'\n', b'Z', b'a', b'b', b'c', b'd', b'e', b'f', b'q', 0xFF,
            ] {
                let mut source = original.clone();
                source[position] = byte;
                let expected = oracle
                    .find(&source)
                    .map(|matched| (matched.start(), matched.end()));
                if let Some(actual) = plan.try_is_match_full(&source) {
                    assert_eq!(
                        actual,
                        expected.is_some(),
                        "predicate position={position}, byte={byte:#04X}",
                    );
                }
                let planned = plan.try_find_full(&source);
                if expected.is_some() {
                    assert_eq!(
                        planned,
                        Some(expected),
                        "position={position}, byte={byte:#04X}",
                    );
                } else if let Some(actual) = planned {
                    assert_eq!(actual, expected, "position={position}, byte={byte:#04X}",);
                }
                assert_eq!(
                    regex.is_match(&source),
                    expected.is_some(),
                    "predicate position={position}, byte={byte:#04X}",
                );
                assert_eq!(
                    regex
                        .find(&source)
                        .map(|matched| (matched.start(), matched.end())),
                    expected,
                    "position={position}, byte={byte:#04X}",
                );
            }
        }
    }

    #[test]
    fn bof_and_eof_line_without_final_terminator_is_exact() {
        let plan = plan(r"(?m)^(?:ab+c|de?f)+Z$");
        let mut source = b"abbbc".repeat(204);
        source.extend_from_slice(b"abcZ");
        assert_eq!(source.len(), 1_024);
        assert_eq!(plan.try_is_match_full(&source), Some(true));
        assert_eq!(plan.try_find_full(&source), Some(Some((0, 1_024))));

        source[0] = b'q';
        assert_eq!(plan.try_is_match_full(&source), Some(false));
        assert_eq!(plan.try_find_full(&source), None);
    }

    #[test]
    fn malformed_bytes_match_the_independent_oracle() {
        let pattern = r"(?m)^(?:\xFFa+q|\xFEb?r)+\xFD$";
        let plan = plan(pattern);
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let mut source = vec![0x80; 1_014];
        source.push(b'\n');
        source.extend_from_slice(&[0xFF, b'a', b'a', b'q', 0xFE, b'b', b'r', 0xFD]);
        source.push(b'\n');
        assert_eq!(source.len(), 1_024);
        assert!(oracle.is_match(&source));
        assert_eq!(plan.try_is_match_full(&source), Some(true));
        assert_eq!(plan.try_find_full(&source), Some(Some((1_015, 1_023))));

        assert_eq!(source[1_015], 0xFF);
        source[1_015] = 0x80;
        assert!(!oracle.is_match(&source));
        assert_eq!(plan.try_is_match_full(&source), Some(false));
        assert_eq!(plan.try_find_full(&source), None);

        let mut rejected_then_late = vec![0x80; 1_024];
        rejected_then_late.extend_from_slice(&[
            b'\n', 0xFF, b'q', 0xFD, b'\n', 0xFF, b'a', b'q', 0xFD, b'\n',
        ]);
        assert!(oracle.is_match(&rejected_then_late));
        assert_eq!(plan.try_is_match_full(&rejected_then_late), Some(true));
        let address = rejected_then_late.as_ptr();
        rejected_then_late[1_029] = 0x80;
        assert_eq!(rejected_then_late.as_ptr(), address);
        assert!(!oracle.is_match(&rejected_then_late));
        assert_eq!(plan.try_is_match_full(&rejected_then_late), Some(false));
        rejected_then_late[1_029] = 0xFF;
        assert_eq!(rejected_then_late.as_ptr(), address);
        assert!(oracle.is_match(&rejected_then_late));
        assert_eq!(plan.try_is_match_full(&rejected_then_late), Some(true));
    }

    #[test]
    fn dense_terminal_candidates_are_exact_and_short_inputs_decline() {
        let plan = plan(r"(?m)^(?:ab+c|de?f)+Z$");
        assert_eq!(plan.try_is_match_full(&vec![b'Z'; 256]), None);
        assert_eq!(plan.try_is_match_full(b"abbbcZ\n"), None);
        assert_eq!(plan.try_is_match_full(&vec![b'q'; 1_023]), None);
        assert_eq!(plan.try_is_match_full(&vec![b'Z'; 1_024]), Some(false));
        assert_eq!(plan.try_is_match_full(&vec![b'q'; 1_024]), Some(false));
        assert_eq!(plan.try_find_full(&vec![b'Z'; 256]), None);
        assert_eq!(plan.try_find_full(b"abbbcZ\n"), None);
        assert_eq!(plan.try_find_full(&vec![b'q'; 1_023]), None);
        assert_eq!(plan.try_find_full(&vec![b'Z'; 1_024]), None);
        assert_eq!(plan.try_find_full(&vec![b'q'; 1_024]), Some(None));
    }

    #[test]
    fn dense_inline_terminals_scan_each_line_once() {
        let pattern = r"(?m)^(?:Za|bc)+Z$";
        let dense_plan = plan(pattern);
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();

        let mut same_line = b"Za".repeat(512);
        same_line.push(b'Z');
        assert_eq!(same_line.len(), 1_025);
        assert!(oracle.is_match(&same_line));
        assert_eq!(dense_plan.try_is_match_full(&same_line), Some(true));

        let address = same_line.as_ptr();
        *same_line.last_mut().unwrap() = b'Q';
        assert_eq!(same_line.as_ptr(), address);
        assert!(!oracle.is_match(&same_line));
        assert_eq!(dense_plan.try_is_match_full(&same_line), Some(false));

        let mut many_rejected_lines = vec![b'q'; 1_024];
        for _ in 0..64 {
            many_rejected_lines.extend_from_slice(b"\nabZ");
        }
        many_rejected_lines.push(b'\n');
        let ordinary = plan(r"(?m)^(?:ab+c|de?f)+Z$");
        assert_eq!(
            ordinary.try_is_match_full(&many_rejected_lines),
            Some(false)
        );
    }

    #[test]
    fn first_authenticated_candidate_returns_the_leftmost_line_span() {
        let plan = plan(r"(?m)^(?:ab+c|de?f)+Z$");
        let mut source = vec![b'q'; 1_024];
        source.extend_from_slice(b"\nabbbcZ\ndefabbbcZ\n");
        assert_eq!(plan.try_find_full(&source), Some(Some((1_025, 1_031))));
    }

    #[test]
    fn multi_byte_terminal_returns_its_complete_span() {
        let pattern = r"(?m)^(?:xy{2,4}q|rst)+END$";
        let plan = plan(pattern);
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        let mut source = vec![b'q'; 1_024];
        source.extend_from_slice(b"\nxyyqrstEND\n");
        let expected = oracle
            .find(&source)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(expected, Some((1_025, 1_035)));
        assert_eq!(plan.try_is_match_full(&source), Some(true));
        assert_eq!(plan.try_find_full(&source), Some(expected));
    }

    #[test]
    fn bounded_small_language_matches_the_independent_oracle() {
        let pattern = r"(?m)^(?:ab+c|de?f)+Z$";
        let plan = plan(pattern);
        let oracle = regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .build()
            .unwrap();
        fn visit(
            plan: super::Plan,
            oracle: &regex::bytes::Regex,
            line: &mut Vec<u8>,
            depth: usize,
        ) {
            let mut source = vec![b'q'; 1_024];
            source.push(b'\n');
            source.extend_from_slice(line);
            source.push(b'\n');
            if let Some(matched) = plan.try_is_match_full(&source) {
                assert_eq!(matched, oracle.is_match(&source), "line={line:?}");
            }
            if let Some(matched) = plan.try_find_full(&source) {
                assert_eq!(
                    matched,
                    oracle
                        .find(&source)
                        .map(|matched| (matched.start(), matched.end())),
                    "line={line:?}",
                );
            }
            if depth == 6 {
                return;
            }
            for byte in [b'a', b'b', b'c', b'd', b'e', b'f', b'Z'] {
                line.push(byte);
                visit(plan, oracle, line, depth + 1);
                line.pop();
            }
        }
        visit(plan, &oracle, &mut Vec::new(), 0);
    }

    #[test]
    fn facade_publication_is_lowest_priority_and_exactly_bounded() {
        const PATTERN: &str = r"(?m)^(?:ab+c|de?f)+Z$";
        assert_eq!(core::mem::size_of::<super::Plan>(), 66);
        fn retained(regex: &crate::PortableRegex) -> bool {
            matches!(
                &regex.plan,
                PortablePlan::K0(plan) if plan.exclusive.line_token_loop().is_some()
            )
        }

        let complete = PortableBuilder::new(PATTERN)
            .unicode(false)
            .build()
            .unwrap();
        assert!(retained(&complete));
        let exact_work = complete.build_report().planner_work;
        let exact_bytes = complete.build_report().charged_persistent_bytes;

        let at_work = PortableBuilder::new(PATTERN)
            .unicode(false)
            .limits(BuildLimits {
                max_planner_work: exact_work,
                ..BuildLimits::default()
            })
            .build()
            .unwrap();
        assert!(retained(&at_work));
        let below_work = PortableBuilder::new(PATTERN)
            .unicode(false)
            .limits(BuildLimits {
                max_planner_work: exact_work - 1,
                ..BuildLimits::default()
            })
            .build()
            .unwrap();
        assert!(!retained(&below_work));

        let at_bytes = PortableBuilder::new(PATTERN)
            .unicode(false)
            .limits(BuildLimits {
                max_persistent_bytes: exact_bytes,
                ..BuildLimits::default()
            })
            .build()
            .unwrap();
        assert!(retained(&at_bytes));
        let below_bytes = PortableBuilder::new(PATTERN)
            .unicode(false)
            .limits(BuildLimits {
                max_persistent_bytes: exact_bytes - 1,
                ..BuildLimits::default()
            })
            .build()
            .unwrap();
        assert!(!retained(&below_bytes));

        let forced = PortableBuilder::new(PATTERN)
            .unicode(false)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap();
        assert!(!retained(&forced));

        let custom = PortableBuilder::new(PATTERN)
            .unicode(false)
            .line_terminator(b'|')
            .build()
            .unwrap();
        assert!(!retained(&custom));
        let crlf = PortableBuilder::new(r"(?Rm)^(?:ab+c|de?f)+Z$")
            .unicode(false)
            .build()
            .unwrap();
        assert!(!retained(&crlf));

        super::route_probe::reset();
        let dense = vec![b'Z'; 256];
        let oracle = regex::bytes::RegexBuilder::new(PATTERN)
            .unicode(false)
            .build()
            .unwrap();
        assert_eq!(complete.is_match(&dense), oracle.is_match(&dense));
        assert_eq!(
            super::route_probe::snapshot(),
            super::route_probe::Counts::default()
        );

        let admitted_dense = vec![b'Z'; 1_024];
        assert_eq!(
            complete.is_match(&admitted_dense),
            oracle.is_match(&admitted_dense)
        );
        assert_eq!(
            super::route_probe::snapshot(),
            super::route_probe::Counts {
                attempts: 1,
                completed: 1,
                declined: 0,
            },
            "an admitted dense ordinary predicate is completed by line ends",
        );
    }
}
