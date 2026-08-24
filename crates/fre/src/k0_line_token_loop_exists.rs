//! Exact ordinary projections for deterministic token loops.
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
//!
//! Construction also admits the unanchored byte language
//! `(BRANCH | ...)+ TERMINAL` under a stronger proof: every atom byte is
//! globally unique, every branch has a required fixed final atom, and the
//! one-byte terminal is outside the token alphabet. Terminal occurrences are
//! therefore barriers, and the maximal valid token suffix immediately before
//! each terminal can be decoded exactly in reverse. Scanning terminals in
//! source order yields the leftmost match without restart caps or fallback
//! after source inspection.

use memchr::{memchr, memrchr};
use regex_syntax::hir::{Class, Hir, HirKind, Look};

const MAX_BRANCHES: usize = 4;
const MAX_ATOMS: usize = 16;
const MAX_TERMINAL_BYTES: usize = 8;
const MAX_LATER_FIND_CANDIDATES: usize = 4;
const UNBOUNDED: u8 = u8::MAX;
pub(crate) const MIN_INPUT_BYTES: usize = 1_024;
pub(crate) const UNANCHORED_MIN_INPUT_BYTES: usize = 32;

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

/// Compact unanchored proof. Reusing the line plan's fixed representation
/// keeps the boxed exclusive-owner envelope and its persistent accounting
/// unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnanchoredPlan(Plan);

impl UnanchoredPlan {
    /// Attempt the complete ordinary full-input predicate. A refusal is only
    /// possible before source inspection at the measured size crossover.
    #[inline]
    pub(crate) fn try_is_match_full(&self, haystack: &[u8]) -> Option<bool> {
        let output = (haystack.len() >= UNANCHORED_MIN_INPUT_BYTES)
            .then(|| self.is_match_full_impl(haystack));
        #[cfg(test)]
        unanchored_route_probe::record_exists(output);
        output
    }

    #[inline]
    fn is_match_full_impl(&self, haystack: &[u8]) -> bool {
        let terminal = self.0.terminal[0];
        let mut search_start = 0_usize;
        while search_start < haystack.len() {
            let Some(relative) = memchr(terminal, &haystack[search_start..]) else {
                return false;
            };
            let candidate = search_start.saturating_add(relative);
            if self.0.matches_one_token_reverse(haystack, candidate) {
                return true;
            }
            search_start = candidate.saturating_add(1);
        }
        false
    }

    /// Attempt the complete ordinary full-input leftmost-first span. Once the
    /// size gate admits the source, the result is authoritative.
    #[inline]
    pub(crate) fn try_find_full(&self, haystack: &[u8]) -> Option<Option<(usize, usize)>> {
        let output =
            (haystack.len() >= UNANCHORED_MIN_INPUT_BYTES).then(|| self.find_full_impl(haystack));
        #[cfg(test)]
        unanchored_route_probe::record_span(output);
        output
    }

    #[inline]
    fn find_full_impl(&self, haystack: &[u8]) -> Option<(usize, usize)> {
        let terminal = self.0.terminal[0];
        let mut search_start = 0_usize;
        while search_start < haystack.len() {
            let relative = memchr(terminal, &haystack[search_start..])?;
            let candidate = search_start.saturating_add(relative);
            if let Some(start) = self.0.match_body_reverse(haystack, candidate) {
                return Some((start, candidate.saturating_add(1)));
            }
            // `candidate` indexes the source, so this addition is bounded by
            // `haystack.len()` and preserves a strictly forward scan.
            search_start = candidate.saturating_add(1);
        }
        None
    }
}

impl Plan {
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

    /// Return the beginning of the maximal nonempty valid token suffix ending
    /// at `end`. A failed attempt to extend the suffix is transactional: the
    /// already authenticated suffix remains a valid match body.
    fn match_body_reverse(&self, haystack: &[u8], end: usize) -> Option<usize> {
        let mut position = end;
        let mut tokens = 0_usize;
        while position > 0 {
            let Some(branch) = self.branch_for_end(haystack[position.saturating_sub(1)]) else {
                break;
            };
            let Some(before) = self.match_branch_reverse(branch, haystack, position) else {
                break;
            };
            if before >= position {
                break;
            }
            position = before;
            tokens = tokens.saturating_add(1);
        }
        (tokens > 0).then_some(position)
    }

    fn matches_one_token_reverse(&self, haystack: &[u8], end: usize) -> bool {
        end.checked_sub(1)
            .and_then(|last| self.branch_for_end(haystack[last]))
            .and_then(|branch| self.match_branch_reverse(branch, haystack, end))
            .is_some()
    }

    fn branch_for_end(&self, byte: u8) -> Option<Branch> {
        self.branches[..usize::from(self.branch_count)]
            .iter()
            .copied()
            .find(|branch| self.atoms[usize::from(branch.end).saturating_sub(1)].byte == byte)
    }

    fn match_branch_reverse(
        &self,
        branch: Branch,
        haystack: &[u8],
        mut position: usize,
    ) -> Option<usize> {
        for atom in self.atoms[usize::from(branch.start)..usize::from(branch.end)]
            .iter()
            .rev()
        {
            let maximum = atom.maximum().unwrap_or(usize::MAX);
            let mut consumed = 0_usize;
            while consumed < maximum
                && position > 0
                && haystack[position.saturating_sub(1)] == atom.byte
            {
                consumed = consumed.checked_add(1)?;
                position = position.checked_sub(1)?;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnanchoredInspectionOutcome {
    Eligible {
        plan: UnanchoredPlan,
        planner_work: u64,
    },
    Ineligible {
        planner_work: u64,
    },
}

impl UnanchoredInspectionOutcome {
    pub(crate) const fn planner_work(self) -> u64 {
        match self {
            Self::Eligible { planner_work, .. } | Self::Ineligible { planner_work } => planner_work,
        }
    }
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

/// Inspect the unanchored deterministic token-loop language
/// `(BRANCH | ...)+ TERMINAL`.
///
/// This proof intentionally authenticates the HIR instead of rejecting the
/// builder's global Unicode or case-folding options. Scoped `(?-u:...)` byte
/// programs remain eligible under default builder options, while folded or
/// Unicode atoms naturally fail the singleton-byte grammar below.
#[cold]
#[allow(
    clippy::too_many_lines,
    reason = "the bounded HIR transaction keeps grammar and reverse determinism proofs adjacent"
)]
pub(crate) fn inspect_unanchored(
    hir: &Hir,
    expected_terminal: u8,
    initial_work: u64,
    work_limit: u64,
) -> Result<UnanchoredInspectionOutcome, InspectionError> {
    let mut budget = Budget::new(initial_work, work_limit);
    budget.charge(1)?;
    let requires_utf8 = hir.properties().is_utf8();
    let root = transparent(hir, &mut budget)?;
    let HirKind::Concat(parts) = root.kind() else {
        return unanchored_ineligible(budget.actual);
    };
    budget.charge(1)?;
    let [repeated, terminal_hir] = parts.as_slice() else {
        return unanchored_ineligible(budget.actual);
    };

    let repeated = transparent(repeated, &mut budget)?;
    let HirKind::Repetition(repetition) = repeated.kind() else {
        return unanchored_ineligible(budget.actual);
    };
    budget.charge(1)?;
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return unanchored_ineligible(budget.actual);
    }
    let alternation = transparent(repetition.sub.as_ref(), &mut budget)?;
    let HirKind::Alternation(branch_hirs) = alternation.kind() else {
        return unanchored_ineligible(budget.actual);
    };
    budget.charge(1)?;
    if !(2..=MAX_BRANCHES).contains(&branch_hirs.len()) {
        return unanchored_ineligible(budget.actual);
    }

    let mut atoms = [Atom::EMPTY; MAX_ATOMS];
    let mut branches = [Branch::EMPTY; MAX_BRANCHES];
    let mut atom_count = 0_usize;
    for (branch_index, branch_hir) in branch_hirs.iter().enumerate() {
        let start = atom_count;
        if !append_branch(branch_hir, &mut atoms, &mut atom_count, &mut budget)? {
            return unanchored_ineligible(budget.actual);
        }
        let end = atom_count;
        if start == end {
            return unanchored_ineligible(budget.actual);
        }
        let first = atoms[start];
        let last_index = end
            .checked_sub(1)
            .ok_or(InspectionError::ArithmeticOverflow)?;
        let last = atoms[last_index];
        budget.charge(1)?;
        // Fixed edge atoms make every token boundary explicit in reverse.
        if first.minimum != 1 || first.maximum != 1 || last.minimum != 1 || last.maximum != 1 {
            return unanchored_ineligible(budget.actual);
        }
        branches[branch_index] = Branch {
            start: u8::try_from(start).map_err(|_| InspectionError::ArithmeticOverflow)?,
            end: u8::try_from(end).map_err(|_| InspectionError::ArithmeticOverflow)?,
        };
    }

    // A byte identifies exactly one atom position in the entire token
    // grammar. This stronger-than-necessary proof eliminates alternation,
    // nullable-successor, and adjacent-token ambiguity in the reverse parser.
    for index in 0..atom_count {
        budget.charge(1)?;
        // A scoped raw-byte HIR may contain arbitrary bytes. If the complete
        // language instead guarantees UTF-8, keep non-ASCII scalar encodings
        // out of this byte-token proof; singleton Unicode classes already
        // decline structurally in `append_branch`.
        if requires_utf8 && !atoms[index].byte.is_ascii() {
            return unanchored_ineligible(budget.actual);
        }
        for prior in 0..index {
            budget.charge(1)?;
            if atoms[prior].byte == atoms[index].byte {
                return unanchored_ineligible(budget.actual);
            }
        }
    }

    let terminal_hir = transparent(terminal_hir, &mut budget)?;
    let HirKind::Literal(literal) = terminal_hir.kind() else {
        return unanchored_ineligible(budget.actual);
    };
    budget.charge(1)?;
    let [terminal_byte] = literal.0.as_ref() else {
        return unanchored_ineligible(budget.actual);
    };
    budget.charge(1)?;
    if *terminal_byte != expected_terminal {
        return unanchored_ineligible(budget.actual);
    }
    for atom in &atoms[..atom_count] {
        budget.charge(1)?;
        if atom.byte == *terminal_byte {
            return unanchored_ineligible(budget.actual);
        }
    }

    let mut terminal = [0_u8; MAX_TERMINAL_BYTES];
    terminal[0] = *terminal_byte;
    Ok(UnanchoredInspectionOutcome::Eligible {
        plan: UnanchoredPlan(Plan {
            atoms,
            branches,
            branch_count: u8::try_from(branch_hirs.len())
                .map_err(|_| InspectionError::ArithmeticOverflow)?,
            terminal,
            terminal_len: 1,
        }),
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

#[allow(
    clippy::unnecessary_wraps,
    reason = "the helper preserves concise transactional early returns from the fallible inspector"
)]
fn unanchored_ineligible(
    planner_work: u64,
) -> Result<UnanchoredInspectionOutcome, InspectionError> {
    Ok(UnanchoredInspectionOutcome::Ineligible { planner_work })
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
pub(crate) mod unanchored_route_probe {
    use core::cell::Cell;

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) struct Counts {
        pub(crate) exists_attempts: usize,
        pub(crate) exists_completed: usize,
        pub(crate) span_attempts: usize,
        pub(crate) span_completed: usize,
    }

    thread_local! {
        static COUNTS: Cell<Counts> = Cell::new(Counts::default());
    }

    pub(super) fn record_exists(output: Option<bool>) {
        COUNTS.with(|slot| {
            let counts = slot.get();
            slot.set(Counts {
                exists_attempts: counts.exists_attempts.saturating_add(1),
                exists_completed: counts
                    .exists_completed
                    .saturating_add(usize::from(output.is_some())),
                ..counts
            });
        });
    }

    pub(super) fn record_span(output: Option<Option<(usize, usize)>>) {
        COUNTS.with(|slot| {
            let counts = slot.get();
            slot.set(Counts {
                span_attempts: counts.span_attempts.saturating_add(1),
                span_completed: counts
                    .span_completed
                    .saturating_add(usize::from(output.is_some())),
                ..counts
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

    use super::{InspectionOutcome, UnanchoredInspectionOutcome, inspect, inspect_unanchored};
    use crate::{
        BuildLimits, PlanSelection, PortableBuilder, PortableFindIterLimits, PortablePlan,
        SearchLimits, SearchSessionLimits, SearchWindow,
    };

    fn parse(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn parse_scoped_bytes(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
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

    fn unanchored_plan(pattern: &str) -> super::UnanchoredPlan {
        unanchored_plan_with_terminal(pattern, b'Z')
    }

    fn unanchored_plan_with_terminal(pattern: &str, terminal: u8) -> super::UnanchoredPlan {
        let UnanchoredInspectionOutcome::Eligible { plan, .. } =
            inspect_unanchored(&parse_scoped_bytes(pattern), terminal, 0, u64::MAX).unwrap()
        else {
            panic!("expected unanchored token-loop eligibility for {pattern:?}");
        };
        plan
    }

    fn unanchored_eligible(pattern: &str) -> bool {
        matches!(
            inspect_unanchored(&parse_scoped_bytes(pattern), b'Z', 0, u64::MAX).unwrap(),
            UnanchoredInspectionOutcome::Eligible { .. }
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

    #[test]
    fn unanchored_grammar_authenticates_scoped_byte_hir_and_strong_edges() {
        assert!(unanchored_eligible(r"(?-u:(?:ab+c|de?f)+Z)"));
        assert!(unanchored_eligible(r"(?-u:(?:xy{2,4}q|rst)+Z)"));

        for pattern in [
            r"(?-u:(?:ab+c|ae?f)+Z)",
            r"(?-u:(?:abac|def)+Z)",
            r"(?-u:(?:a+bc|def)+Z)",
            r"(?-u:(?:ab+|def)+Z)",
            r"(?-u:(?:ab?|def)+Z)",
            r"(?-u:(?:abc|def)*Z)",
            r"(?-u:(?:abc|def){1,4}Z)",
            r"(?-u:(?:abc|def)+?Z)",
            r"(?-u:(?:abc|def)+ZZ)",
            r"(?-u:Q(?:abc|def)+Z)",
            r"(?-u:(?:abc|def)+Z$)",
            r"(?i-u:(?:abc|def)+Z)",
            r"(?:λbc|def)+Z",
            r"(?-u:(?:aZc|def)+Z)",
            r"(?-u:(?:abc|def|ghi|jkl|mno)+Z)",
            r"(?-u:(?:abc)+Z)",
        ] {
            assert!(
                !unanchored_eligible(pattern),
                "unexpectedly admitted {pattern:?}",
            );
        }

        assert!(matches!(
            inspect_unanchored(
                &parse_scoped_bytes(r"(?-u:(?:ab+c|de?f)+Z)"),
                b'Q',
                0,
                u64::MAX,
            )
            .unwrap(),
            UnanchoredInspectionOutcome::Ineligible { .. }
        ));
    }

    #[test]
    fn unanchored_inspector_work_limit_closes_exactly() {
        let hir = parse_scoped_bytes(r"(?-u:(?:ab+c|de?f)+Z)");
        let UnanchoredInspectionOutcome::Eligible { planner_work, .. } =
            inspect_unanchored(&hir, b'Z', 0, u64::MAX).unwrap()
        else {
            panic!("expected eligibility");
        };
        assert!(matches!(
            inspect_unanchored(&hir, b'Z', 0, planner_work).unwrap(),
            UnanchoredInspectionOutcome::Eligible {
                planner_work: actual,
                ..
            } if actual == planner_work
        ));
        let limit = planner_work - 1;
        assert!(matches!(
            inspect_unanchored(&hir, b'Z', 0, limit),
            Err(super::InspectionError::WorkLimit {
                actual,
                needed,
                limit: observed,
            }) if limit == planner_work - 1
                && observed == limit
                && actual <= limit
                && needed > limit
        ));
    }

    #[test]
    fn unanchored_directed_candidates_return_exact_leftmost_spans() {
        const PATTERN: &str = r"(?-u:(?:ab+c|de?f)+Z)";
        let plan = unanchored_plan(PATTERN);
        let oracle = regex::bytes::Regex::new(PATTERN).unwrap();

        for tail in [
            b"abcZ".as_slice(),
            b"abbbcZ".as_slice(),
            b"dfZ".as_slice(),
            b"defZ".as_slice(),
            b"abbbcdefZ".as_slice(),
            b"qbcZ!abbbcdefZ".as_slice(),
            b"cabcZ".as_slice(),
            b"ZZZZ!defabcZ".as_slice(),
            b"qbcZ!qbcZ".as_slice(),
        ] {
            let mut source = vec![b'!'; 32];
            source.extend_from_slice(tail);
            let expected = oracle
                .find(&source)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(
                plan.try_is_match_full(&source),
                Some(expected.is_some()),
                "tail={tail:?}",
            );
            assert_eq!(plan.try_find_full(&source), Some(expected), "tail={tail:?}",);
        }

        let suffix_after_malformed_branch = b"cabcZ";
        assert_eq!(
            plan.find_full_impl(suffix_after_malformed_branch),
            Some((1, 5)),
            "a failed preceding branch retains the authenticated abc token",
        );
        assert_eq!(
            plan.find_full_impl(b"abbbcdefZ"),
            Some((0, b"abbbcdefZ".len())),
            "reverse decoding extends through every contiguous token",
        );
    }

    #[test]
    fn unanchored_bounded_language_is_exhaustively_differential() {
        const PATTERN: &str = r"(?-u:(?:ab+c|de?f)+Z)";
        let plan = unanchored_plan(PATTERN);
        let oracle = regex::bytes::Regex::new(PATTERN).unwrap();

        fn visit(
            plan: super::UnanchoredPlan,
            oracle: &regex::bytes::Regex,
            source: &mut Vec<u8>,
            depth: usize,
        ) {
            let expected = oracle
                .find(source)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(
                plan.is_match_full_impl(source),
                expected.is_some(),
                "predicate source={source:?}",
            );
            assert_eq!(plan.find_full_impl(source), expected, "source={source:?}");
            if depth == 6 {
                return;
            }
            for byte in [b'a', b'b', b'c', b'd', b'e', b'f', b'Z', b'!'] {
                source.push(byte);
                visit(plan, oracle, source, depth + 1);
                source.pop();
            }
        }

        visit(plan, &oracle, &mut Vec::new(), 0);
    }

    #[test]
    fn unanchored_raw_bytes_and_same_address_mutations_are_exact() {
        const PATTERN: &str = r"(?-u:(?:\xFFa+q|\xFEb?r)+\xFD)";
        let plan = unanchored_plan_with_terminal(PATTERN, 0xFD);
        let oracle = regex::bytes::Regex::new(PATTERN).unwrap();
        let mut source = vec![0; 32];
        source.extend_from_slice(&[0xFF, b'a', b'a', b'q', 0xFE, b'b', b'r', 0xFD]);
        let address = source.as_ptr();

        let expected = oracle
            .find(&source)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(plan.try_is_match_full(&source), Some(true));
        assert_eq!(plan.try_find_full(&source), Some(expected));

        source[39] = b'Q';
        assert_eq!(source.as_ptr(), address);
        let expected = oracle
            .find(&source)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(expected, None);
        assert_eq!(plan.try_is_match_full(&source), Some(false));
        assert_eq!(plan.try_find_full(&source), Some(expected));

        source[39] = 0xFD;
        assert_eq!(source.as_ptr(), address);
        let expected = oracle
            .find(&source)
            .map(|matched| (matched.start(), matched.end()));
        assert_eq!(plan.try_is_match_full(&source), Some(true));
        assert_eq!(plan.try_find_full(&source), Some(expected));
    }

    #[test]
    fn unanchored_publication_accounting_gate_and_force_k0_are_exact() {
        const PATTERN: &str = r"(?-u:(?:ab+c|de?f)+Z)";
        fn retained(regex: &crate::PortableRegex) -> bool {
            matches!(
                &regex.plan,
                PortablePlan::K0(plan) if plan.exclusive.unanchored_token_loop().is_some()
            )
        }

        assert_eq!(
            core::mem::size_of::<super::UnanchoredPlan>(),
            core::mem::size_of::<super::Plan>(),
        );
        assert_eq!(core::mem::size_of::<super::UnanchoredPlan>(), 66);
        assert_eq!(crate::K0LinePlan::storage_bytes(), 67);

        let complete = PortableBuilder::new(PATTERN).build().unwrap();
        assert!(
            retained(&complete),
            "scoped byte HIR survives global Unicode"
        );
        let PortablePlan::K0(complete_k0) = &complete.plan else {
            panic!("target must remain K0");
        };
        assert!(
            complete_k0.mandatory_suffix.is_none(),
            "the one-byte exact tail remains owned only by the compact sidecar",
        );
        let exact_work = complete.build_report().planner_work;
        let exact_bytes = complete.build_report().charged_persistent_bytes;

        let at_work = PortableBuilder::new(PATTERN)
            .limits(BuildLimits {
                max_planner_work: exact_work,
                ..BuildLimits::default()
            })
            .build()
            .unwrap();
        assert!(retained(&at_work));
        let below_work = PortableBuilder::new(PATTERN)
            .limits(BuildLimits {
                max_planner_work: exact_work - 1,
                ..BuildLimits::default()
            })
            .build()
            .unwrap();
        assert!(!retained(&below_work));

        let at_bytes = PortableBuilder::new(PATTERN)
            .limits(BuildLimits {
                max_persistent_bytes: exact_bytes,
                ..BuildLimits::default()
            })
            .build()
            .unwrap();
        assert!(retained(&at_bytes));
        let below_bytes = PortableBuilder::new(PATTERN)
            .limits(BuildLimits {
                max_persistent_bytes: exact_bytes - 1,
                ..BuildLimits::default()
            })
            .build()
            .unwrap();
        assert!(!retained(&below_bytes));

        let forced = PortableBuilder::new(PATTERN)
            .plan_selection(PlanSelection::ForceK0)
            .build()
            .unwrap();
        assert!(!retained(&forced));

        super::unanchored_route_probe::reset();
        let mut below = vec![b'!'; super::UNANCHORED_MIN_INPUT_BYTES - 4 - 1];
        below.extend_from_slice(b"abcZ");
        assert_eq!(below.len(), super::UNANCHORED_MIN_INPUT_BYTES - 1);
        assert!(complete.is_match(&below));
        assert_eq!(
            complete
                .find(&below)
                .map(|matched| (matched.start(), matched.end())),
            Some((below.len() - 4, below.len())),
        );
        assert_eq!(
            super::unanchored_route_probe::snapshot(),
            super::unanchored_route_probe::Counts::default(),
        );

        let mut at = vec![b'!'; super::UNANCHORED_MIN_INPUT_BYTES - 4];
        at.extend_from_slice(b"abcZ");
        assert_eq!(at.len(), super::UNANCHORED_MIN_INPUT_BYTES);
        assert!(complete.is_match(&at));
        assert_eq!(
            complete
                .find(&at)
                .map(|matched| (matched.start(), matched.end())),
            Some((at.len() - 4, at.len())),
        );
        assert_eq!(
            super::unanchored_route_probe::snapshot(),
            super::unanchored_route_probe::Counts {
                exists_attempts: 1,
                exists_completed: 1,
                span_attempts: 1,
                span_completed: 1,
            },
        );
    }

    #[test]
    fn unanchored_route_is_ordinary_only_and_rereads_same_allocation() {
        const PATTERN: &str = r"(?-u:(?:ab+c|de?f)+Z)";
        let regex = PortableBuilder::new(PATTERN).build().unwrap();
        let oracle = regex::bytes::Regex::new(PATTERN).unwrap();
        let mut source = vec![b'!'; 64];
        source.extend_from_slice(b"abbbcdefZ");
        let expected = oracle
            .find(&source)
            .map(|matched| (matched.start(), matched.end()));
        assert!(expected.is_some());

        super::unanchored_route_probe::reset();
        assert!(regex.is_match(&source));
        assert_eq!(
            regex
                .find(&source)
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        let direct = super::unanchored_route_probe::snapshot();
        assert_eq!(
            direct,
            super::unanchored_route_probe::Counts {
                exists_attempts: 1,
                exists_completed: 1,
                span_attempts: 1,
                span_completed: 1,
            },
        );

        let address = source.as_ptr();
        let terminal = source.len() - 1;
        source[terminal] = b'Q';
        assert_eq!(source.as_ptr(), address);
        assert!(!regex.is_match(&source));
        assert_eq!(regex.find(&source), None);
        source[terminal] = b'Z';
        assert_eq!(source.as_ptr(), address);
        assert!(regex.is_match(&source));
        assert_eq!(
            regex
                .find(&source)
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        let after_mutations = super::unanchored_route_probe::snapshot();
        assert_eq!(after_mutations.exists_attempts, 3);
        assert_eq!(after_mutations.exists_completed, 3);
        assert_eq!(after_mutations.span_attempts, 3);
        assert_eq!(after_mutations.span_completed, 3);

        for limits in [SearchLimits::default(), SearchLimits::unlimited()] {
            assert!(regex.is_match_value(&source, limits).unwrap());
            assert_eq!(
                regex
                    .find_value(&source, limits)
                    .unwrap()
                    .map(|matched| (matched.start(), matched.end())),
                expected,
            );
            assert!(
                regex
                    .is_match_window_value(&source, SearchWindow::full(&source), limits)
                    .unwrap(),
            );
            assert_eq!(
                regex
                    .find_window_value(&source, SearchWindow::full(&source), limits)
                    .unwrap()
                    .map(|matched| (matched.start(), matched.end())),
                expected,
            );
        }
        assert!(
            regex
                .is_match_accounted(&source, SearchLimits::unlimited())
                .unwrap()
                .0,
        );
        assert_eq!(
            regex
                .find_accounted(&source, SearchLimits::unlimited())
                .unwrap()
                .0
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );

        let mut session = regex
            .search_session(SearchSessionLimits::unlimited())
            .unwrap();
        assert!(
            session
                .is_match_window_value(
                    &source,
                    SearchWindow::full(&source),
                    SearchLimits::unlimited(),
                )
                .unwrap(),
        );
        assert_eq!(
            session
                .find_window_value(
                    &source,
                    SearchWindow::full(&source),
                    SearchLimits::unlimited(),
                )
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        let iter_match = regex
            .find_iter_value(&source, PortableFindIterLimits::unlimited())
            .unwrap()
            .next()
            .expect("one match")
            .unwrap();
        assert_eq!((iter_match.start(), iter_match.end()), expected.unwrap());
        let mut locations = regex.capture_locations();
        assert_eq!(
            regex
                .captures_read_value(&mut locations, &source, SearchLimits::unlimited(),)
                .unwrap()
                .map(|matched| (matched.start(), matched.end())),
            expected,
        );
        assert_eq!(
            super::unanchored_route_probe::snapshot(),
            after_mutations,
            "explicit, accounted, windowed, session, iterator, and capture APIs stay canonical",
        );
    }
}
