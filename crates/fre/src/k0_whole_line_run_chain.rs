//! Ordinary-only search for a deterministic unbounded whole-line byte chain.
//!
//! Construction admits exactly `START MASK1+ MASK2+ BYTE END` in byte HIR.
//! Both greedy run boundaries are deterministic: the run masks are disjoint,
//! and the second mask excludes the terminal byte. Searching for the terminal
//! first makes negative lines a single vectorized byte scan. On a candidate
//! line end, walking the second run backward and validating the remaining
//! nonempty prefix proves the selected whole-line span without K0 workspace.

use fre_automata::{K0OrdinaryExecutor, K0SpanSourceCursor, SearchError as K0SearchError};
use fre_kernels::{BYTE_SET_BLOCK_BYTES, LineDomainMode as LineMode, classify_byte_delta_16};
use memchr::{memchr, memchr2, memrchr, memrchr2};
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind, Look};

const MAX_RANGES: usize = 4;
const MAX_DIRECT_LINE_BYTES: usize = 4 * 1_024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ByteRange {
    start: u8,
    end: u8,
}

impl ByteRange {
    const fn contains(self, byte: u8) -> bool {
        self.start <= byte && byte <= self.end
    }

    const fn intersects(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ByteMask {
    ranges: [ByteRange; MAX_RANGES],
    len: u8,
}

impl ByteMask {
    const fn empty() -> Self {
        Self {
            ranges: [ByteRange { start: 0, end: 0 }; MAX_RANGES],
            len: 0,
        }
    }

    fn singleton(byte: u8) -> Self {
        let mut mask = Self::empty();
        mask.ranges[0] = ByteRange {
            start: byte,
            end: byte,
        };
        mask.len = 1;
        mask
    }

    fn push(&mut self, range: ByteRange) -> bool {
        let index = usize::from(self.len);
        let Some(slot) = self.ranges.get_mut(index) else {
            return false;
        };
        *slot = range;
        self.len = self.len.saturating_add(1);
        true
    }

    fn contains(self, byte: u8) -> bool {
        self.as_slice().iter().any(|range| range.contains(byte))
    }

    fn as_slice(&self) -> &[ByteRange] {
        &self.ranges[..usize::from(self.len)]
    }

    #[inline]
    fn contains_all(self, bytes: &[u8]) -> bool {
        let complete_len = bytes.len() - (bytes.len() % BYTE_SET_BLOCK_BYTES);
        for block in bytes[..complete_len].chunks_exact(BYTE_SET_BLOCK_BYTES) {
            let block: &[u8; BYTE_SET_BLOCK_BYTES] = block
                .try_into()
                .expect("an exact chunk has the fixed byte-classifier width");
            let mut members = 0_u16;
            for range in self.as_slice() {
                members |= classify_byte_delta_16(
                    range.start,
                    range.end.saturating_sub(range.start),
                    block,
                )
                .member_mask();
            }
            if members != u16::MAX {
                return false;
            }
        }
        bytes[complete_len..]
            .iter()
            .all(|&byte| self.contains(byte))
    }
}

/// A source-independent construction proof retained only for ordinary APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    first: ByteMask,
    second: ByteMask,
    terminal: u8,
    line_mode: LineMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Route {
    CompleteMiss,
    Direct { line_start: usize, terminal: usize },
    Canonical,
}

/// One worker-bound ordinary engine retaining canonical K0 for long lines.
#[derive(Debug)]
pub(crate) struct Engine<'a> {
    plan: &'a Plan,
    fallback: K0OrdinaryExecutor<'a>,
}

impl<'a> Engine<'a> {
    pub(crate) const fn new(plan: &'a Plan, fallback: K0OrdinaryExecutor<'a>) -> Self {
        Self { plan, fallback }
    }

    #[inline]
    pub(crate) fn is_match_at(
        &mut self,
        haystack: &[u8],
        start: usize,
    ) -> Result<bool, K0SearchError> {
        self.first_acceptance_at(haystack, start)
            .map(|end| end.is_some())
    }

    #[inline]
    pub(crate) fn first_acceptance_at(
        &mut self,
        haystack: &[u8],
        start: usize,
    ) -> Result<Option<usize>, K0SearchError> {
        match self.plan.route_at(haystack, start) {
            Route::CompleteMiss => Ok(None),
            Route::Canonical => self.fallback.first_acceptance_at(haystack, start),
            Route::Direct {
                line_start,
                terminal,
            } => Ok(self
                .plan
                .find_at_from_candidate(haystack, start, line_start, terminal)
                .map(|(_start, end)| end)),
        }
    }

    #[inline]
    pub(crate) fn find_at(
        &mut self,
        haystack: &[u8],
        start: usize,
    ) -> Result<Option<(usize, usize)>, K0SearchError> {
        match self.plan.route_at(haystack, start) {
            Route::CompleteMiss => Ok(None),
            Route::Canonical => self
                .fallback
                .selected_span_at(haystack, start)
                .map(|span| span.map(|span| (span.start(), span.end()))),
            Route::Direct {
                line_start,
                terminal,
            } => Ok(self
                .plan
                .find_at_from_candidate(haystack, start, line_start, terminal)),
        }
    }

    #[inline]
    pub(crate) fn try_visit_spans_at<E>(
        &mut self,
        haystack: &[u8],
        start: usize,
        mut visitor: impl FnMut((usize, usize)) -> Result<bool, E>,
    ) -> Result<Result<(), E>, K0SearchError> {
        match self.plan.route_at(haystack, start) {
            Route::CompleteMiss => Ok(Ok(())),
            Route::Direct { .. } => {
                let mut cursor = start;
                while let Some((matched_start, end)) = self.plan.find_at(haystack, cursor) {
                    match visitor((matched_start, end)) {
                        Ok(true) => cursor = end,
                        Ok(false) => return Ok(Ok(())),
                        Err(error) => return Ok(Err(error)),
                    }
                }
                Ok(Ok(()))
            }
            Route::Canonical => {
                let mut source = K0SpanSourceCursor::new(haystack);
                let mut cursor = start;
                loop {
                    let Some(span) = self
                        .fallback
                        .selected_span_at_source_cursor(&mut source, cursor)?
                    else {
                        return Ok(Ok(()));
                    };
                    if span.end() <= cursor {
                        return Err(K0SearchError::InternalInvariant {
                            detail: "positive whole-line span failed to advance",
                        });
                    }
                    match visitor((span.start(), span.end())) {
                        Ok(true) => cursor = span.end(),
                        Ok(false) => return Ok(Ok(())),
                        Err(error) => return Ok(Err(error)),
                    }
                }
            }
        }
    }

    #[inline]
    pub(crate) fn count_at(&mut self, haystack: &[u8], start: usize) -> Result<u64, K0SearchError> {
        match self.plan.route_at(haystack, start) {
            Route::CompleteMiss => Ok(0),
            Route::Direct { .. } => {
                let mut cursor = start;
                let mut count = 0_u64;
                while let Some((_matched_start, end)) = self.plan.find_at(haystack, cursor) {
                    count = count
                        .checked_add(1)
                        .ok_or(K0SearchError::ArithmeticOverflow {
                            computation: "whole-line run-chain match count",
                        })?;
                    cursor = end;
                }
                Ok(count)
            }
            Route::Canonical => {
                let mut cursor = start;
                let mut count = 0_u64;
                loop {
                    let Some(end) = self.fallback.selected_end_at(haystack, cursor)? else {
                        return Ok(count);
                    };
                    if end <= cursor {
                        return Err(K0SearchError::InternalInvariant {
                            detail: "positive whole-line endpoint failed to advance",
                        });
                    }
                    count = count
                        .checked_add(1)
                        .ok_or(K0SearchError::ArithmeticOverflow {
                            computation: "whole-line canonical match count",
                        })?;
                    cursor = end;
                }
            }
        }
    }
}

impl Plan {
    pub(crate) const fn minimum_input_bytes(&self) -> usize {
        3
    }

    #[inline]
    pub(crate) fn try_is_match_full(&self, haystack: &[u8]) -> Option<bool> {
        match self.route_at(haystack, 0) {
            Route::CompleteMiss => Some(false),
            Route::Canonical => None,
            Route::Direct {
                line_start,
                terminal,
            } => Some(
                self.find_at_from_candidate(haystack, 0, line_start, terminal)
                    .is_some(),
            ),
        }
    }

    #[inline]
    pub(crate) fn try_find_full(&self, haystack: &[u8]) -> Option<Option<(usize, usize)>> {
        match self.route_at(haystack, 0) {
            Route::CompleteMiss => Some(None),
            Route::Canonical => None,
            Route::Direct {
                line_start,
                terminal,
            } => Some(self.find_at_from_candidate(haystack, 0, line_start, terminal)),
        }
    }

    #[inline]
    pub(crate) fn find_at(&self, haystack: &[u8], start: usize) -> Option<(usize, usize)> {
        let mut search = start;
        loop {
            let relative = memchr(self.terminal, haystack.get(search..)?)?;
            let terminal = search.checked_add(relative)?;
            let end = terminal.checked_add(1)?;
            if self.is_line_end(haystack, end) {
                let line_start = self.line_start(haystack, terminal);
                if line_start >= start && self.matches_body(haystack, line_start, terminal) {
                    return Some((line_start, end));
                }
            }
            search = end;
        }
    }

    #[inline]
    fn find_at_from_candidate(
        &self,
        haystack: &[u8],
        start: usize,
        line_start: usize,
        terminal: usize,
    ) -> Option<(usize, usize)> {
        debug_assert!(line_start >= start);
        if self.matches_body(haystack, line_start, terminal) {
            Some((line_start, terminal + 1))
        } else {
            self.find_at(haystack, terminal + 1)
        }
    }

    #[inline]
    fn route_at(&self, haystack: &[u8], start: usize) -> Route {
        let Some(mut search) = self.first_searchable_line_start(haystack, start) else {
            return Route::CompleteMiss;
        };
        if self.first_line_exceeds_direct_limit(haystack, search) {
            return Route::Canonical;
        }
        loop {
            let Some(relative) = memchr(self.terminal, &haystack[search..]) else {
                return Route::CompleteMiss;
            };
            let terminal = search + relative;
            let end = terminal + 1;
            if self.is_line_end(haystack, end) {
                let line_start = self.line_start(haystack, terminal);
                if line_start >= start {
                    if end - line_start > MAX_DIRECT_LINE_BYTES {
                        return Route::Canonical;
                    }
                    return Route::Direct {
                        line_start,
                        terminal,
                    };
                }
            }
            search = end;
        }
    }

    #[inline]
    fn first_searchable_line_start(&self, haystack: &[u8], start: usize) -> Option<usize> {
        debug_assert!(start <= haystack.len());
        if start == 0 {
            return Some(0);
        }
        match self.line_mode {
            LineMode::Lf { terminator } => {
                if haystack[start - 1] == terminator {
                    Some(start)
                } else {
                    memchr(terminator, &haystack[start..]).map(|relative| start + relative + 1)
                }
            }
            LineMode::Crlf => {
                let previous = haystack[start - 1];
                if previous == b'\n' || (previous == b'\r' && haystack.get(start) != Some(&b'\n')) {
                    return Some(start);
                }
                let relative = memchr2(b'\r', b'\n', &haystack[start..])?;
                let delimiter = start + relative;
                Some(
                    delimiter
                        + usize::from(
                            haystack[delimiter] == b'\r'
                                && haystack.get(delimiter + 1) == Some(&b'\n'),
                        )
                        + 1,
                )
            }
        }
    }

    #[inline]
    fn first_line_exceeds_direct_limit(&self, haystack: &[u8], line_start: usize) -> bool {
        let remaining = haystack.len() - line_start;
        if remaining <= MAX_DIRECT_LINE_BYTES {
            return false;
        }
        let probe_end = line_start + MAX_DIRECT_LINE_BYTES + 1;
        let probe = &haystack[line_start..probe_end];
        match self.line_mode {
            LineMode::Lf { terminator } => memchr(terminator, probe).is_none(),
            LineMode::Crlf => memchr2(b'\r', b'\n', probe).is_none(),
        }
    }

    #[inline]
    fn matches_body(&self, haystack: &[u8], line_start: usize, terminal: usize) -> bool {
        let mut second_start = terminal;
        while second_start > line_start && self.second.contains(haystack[second_start - 1]) {
            second_start -= 1;
        }
        second_start < terminal
            && second_start > line_start
            && self.first.contains_all(&haystack[line_start..second_start])
    }

    #[inline]
    fn is_line_end(&self, haystack: &[u8], position: usize) -> bool {
        if position == haystack.len() {
            return true;
        }
        match self.line_mode {
            LineMode::Lf { terminator } => haystack[position] == terminator,
            LineMode::Crlf if haystack[position] == b'\r' => true,
            LineMode::Crlf if haystack[position] == b'\n' => {
                position == 0 || haystack[position - 1] != b'\r'
            }
            LineMode::Crlf => false,
        }
    }

    #[inline]
    fn line_start(&self, haystack: &[u8], before: usize) -> usize {
        let prefix = &haystack[..before];
        match self.line_mode {
            LineMode::Lf { terminator } => memrchr(terminator, prefix),
            LineMode::Crlf => memrchr2(b'\r', b'\n', prefix),
        }
        .map_or(0, |delimiter| delimiter + 1)
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

/// Prove the exact capture-transparent HIR accepted by [`Plan`].
#[cold]
pub(crate) fn inspect(
    hir: &Hir,
    line_terminator: u8,
    initial_work: u64,
    work_limit: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut budget = Budget::new(initial_work, work_limit);
    let root = transparent(hir, &mut budget)?;
    let HirKind::Concat(parts) = root.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(1)?;
    let [start, first, second, terminal, end] = parts.as_slice() else {
        return ineligible(budget.actual);
    };
    let Some(line_mode) = line_mode(start, end, line_terminator, &mut budget)? else {
        return ineligible(budget.actual);
    };
    let Some(first) = unbounded_positive_mask(first, &mut budget)? else {
        return ineligible(budget.actual);
    };
    let Some(second) = unbounded_positive_mask(second, &mut budget)? else {
        return ineligible(budget.actual);
    };
    let terminal = transparent(terminal, &mut budget)?;
    let HirKind::Literal(literal) = terminal.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(1)?;
    let [terminal] = literal.0.as_ref() else {
        return ineligible(budget.actual);
    };

    if !prove_disjoint(first, second, &mut budget)?
        || !prove_terminal_disjoint(second, *terminal, &mut budget)?
        || mask_admits_terminator(line_mode, first)
        || mask_admits_terminator(line_mode, second)
        || byte_is_terminator(line_mode, *terminal)
    {
        return ineligible(budget.actual);
    }
    Ok(InspectionOutcome::Eligible {
        plan: Plan {
            first,
            second,
            terminal: *terminal,
            line_mode,
        },
        planner_work: budget.actual,
    })
}

fn line_mode(
    start: &Hir,
    end: &Hir,
    line_terminator: u8,
    budget: &mut Budget,
) -> Result<Option<LineMode>, InspectionError> {
    let start = transparent(start, budget)?;
    let end = transparent(end, budget)?;
    Ok(match (start.kind(), end.kind()) {
        (HirKind::Look(Look::StartLF), HirKind::Look(Look::EndLF)) => Some(LineMode::Lf {
            terminator: line_terminator,
        }),
        (HirKind::Look(Look::StartCRLF), HirKind::Look(Look::EndCRLF)) => Some(LineMode::Crlf),
        _ => None,
    })
}

fn unbounded_positive_mask(
    hir: &Hir,
    budget: &mut Budget,
) -> Result<Option<ByteMask>, InspectionError> {
    let hir = transparent(hir, budget)?;
    let HirKind::Repetition(repetition) = hir.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    let body = transparent(repetition.sub.as_ref(), budget)?;
    match body.kind() {
        HirKind::Literal(literal) if literal.0.len() == 1 => {
            budget.charge(1)?;
            Ok(Some(ByteMask::singleton(literal.0[0])))
        }
        HirKind::Class(Class::Bytes(class)) => class_mask(class, budget),
        _ => Ok(None),
    }
}

fn class_mask(
    class: &ClassBytes,
    budget: &mut Budget,
) -> Result<Option<ByteMask>, InspectionError> {
    let mut mask = ByteMask::empty();
    for range in class.ranges() {
        budget.charge(1)?;
        let width = u64::from(range.end())
            .checked_sub(u64::from(range.start()))
            .and_then(|width| width.checked_add(1))
            .ok_or(InspectionError::ArithmeticOverflow)?;
        budget.charge(width)?;
        if !mask.push(ByteRange {
            start: range.start(),
            end: range.end(),
        }) {
            return Ok(None);
        }
    }
    Ok((mask.len > 0).then_some(mask))
}

fn prove_disjoint(
    first: ByteMask,
    second: ByteMask,
    budget: &mut Budget,
) -> Result<bool, InspectionError> {
    for &left in first.as_slice() {
        for &right in second.as_slice() {
            budget.charge(1)?;
            if left.intersects(right) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn prove_terminal_disjoint(
    mask: ByteMask,
    terminal: u8,
    budget: &mut Budget,
) -> Result<bool, InspectionError> {
    for &range in mask.as_slice() {
        budget.charge(1)?;
        if range.contains(terminal) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn mask_admits_terminator(mode: LineMode, mask: ByteMask) -> bool {
    match mode {
        LineMode::Lf { terminator } => mask.contains(terminator),
        LineMode::Crlf => mask.contains(b'\r') || mask.contains(b'\n'),
    }
}

fn byte_is_terminator(mode: LineMode, byte: u8) -> bool {
    match mode {
        LineMode::Lf { terminator } => byte == terminator,
        LineMode::Crlf => byte == b'\r' || byte == b'\n',
    }
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

fn ineligible(work: u64) -> Result<InspectionOutcome, InspectionError> {
    Ok(InspectionOutcome::Ineligible { planner_work: work })
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;
    use regex_syntax::ParserBuilder;

    use super::{InspectionOutcome, inspect};
    use crate::{
        Match, PortableBuilder, PortableFindIterError, PortableOrdinarySessionPlan, PortablePlan,
        SearchLimits, SearchWindow,
    };

    fn parse(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn plan(pattern: &str, terminator: u8) -> super::Plan {
        let InspectionOutcome::Eligible { plan, .. } =
            inspect(&parse(pattern), terminator, 0, u64::MAX).unwrap()
        else {
            panic!("whole-line run-chain proof declined {pattern:?}");
        };
        plan
    }

    #[test]
    fn inspection_is_narrow_and_semantic() {
        assert!(
            core::mem::size_of::<super::Plan>()
                <= core::mem::size_of::<crate::k0_line_token_loop_exists::Plan>(),
            "the appended line-owner variant must not enlarge K0LinePlan",
        );
        assert!(
            core::mem::size_of::<super::Engine<'static>>()
                <= core::mem::size_of::<(fre_automata::K0OrdinaryExecutor<'static>, bool,)>(),
            "the appended ordinary-session variant must fit below incumbent K0",
        );
        assert!(matches!(
            inspect(&parse(r"(?m)^(?-u:[a-z_]+[0-9]+X)$"), b'\n', 0, u64::MAX).unwrap(),
            InspectionOutcome::Eligible { .. }
        ));
        for pattern in [
            r"(?-u:[a-z_]+[0-9]+X)",
            r"(?m)^(?-u:[a-z_]*[0-9]+X)$",
            r"(?m)^(?-u:[a-z_]+[a-z0-9]+X)$",
            r"(?m)^(?-u:[a-z_]+[0-9]+[XY])$",
            r"(?m)^(?-u:[a-z_]+[0-9]+X+)$",
        ] {
            assert!(
                matches!(
                    inspect(&parse(pattern), b'\n', 0, u64::MAX).unwrap(),
                    InspectionOutcome::Ineligible { .. }
                ),
                "unexpectedly admitted {pattern:?}"
            );
        }
    }

    #[test]
    fn every_start_matches_upstream_for_lf_crlf_and_arbitrary_bytes() {
        for (pattern, source) in [
            (
                r"(?m)^(?-u:[a-z_]+[0-9]+X)$",
                b"a1X\naa22X\naX\n3X\naa22Y\nzz9X".as_slice(),
            ),
            (
                r"(?Rm)^(?-u:[a-z_]+[0-9]+X)$",
                b"a1X\r\naa22X\raX\n3X\r\naa22Y\rzz9X".as_slice(),
            ),
            (
                r"(?m)^(?-u:[\x80-\xBF]+[\xC0-\xFE]+\xFF)$",
                b"\x80\xc0\xff\n\x81\x82\xfe\xff\n\xff\n\x80\xc0\xfe".as_slice(),
            ),
        ] {
            let direct = plan(pattern, b'\n');
            let upstream = RegexBuilder::new(pattern).unicode(false).build().unwrap();
            for start in 0..=source.len() {
                let expected = upstream
                    .find_at(source, start)
                    .map(|matched| (matched.start(), matched.end()));
                assert_eq!(
                    direct.find_at(source, start),
                    expected,
                    "{pattern:?} start={start}"
                );
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct VisitorError;

    #[test]
    fn ordinary_session_preserves_ranged_visitor_count_and_reuse_semantics() {
        let pattern = r"(?m)^(?-u:[a-z_]+[0-9]+X)$";
        let source = b"bad\na1X\naa22X\naX\n3X\naa22Y\nzz9X\n";
        let regex = PortableBuilder::new(pattern).build().unwrap();
        let PortablePlan::K0(k0) = &regex.plan else {
            panic!("unbounded whole-line chain should retain canonical K0");
        };
        assert!(k0.exclusive.whole_line_run_chain().is_some());
        let upstream = RegexBuilder::new(pattern).unicode(false).build().unwrap();
        let expected_all: Vec<_> = upstream
            .find_iter(source)
            .map(|matched| (matched.start(), matched.end()))
            .collect();

        let mut ordinary = regex.ordinary_session().unwrap();
        assert!(matches!(
            ordinary.plan,
            PortableOrdinarySessionPlan::K0WholeLineRunChain { .. }
        ));
        for start in 0..=source.len() {
            let expected = upstream
                .find_at(source, start)
                .map(|matched| (matched.start(), matched.end()));
            assert_eq!(
                ordinary
                    .find_at(source, start)
                    .unwrap()
                    .map(|matched| (matched.start(), matched.end())),
                expected,
                "find start={start}",
            );
            assert_eq!(
                ordinary.first_acceptance_at(source, start).unwrap(),
                expected.map(|(_start, end)| end),
                "first acceptance start={start}",
            );
            assert_eq!(
                ordinary.is_match_at(source, start).unwrap(),
                expected.is_some(),
                "exists start={start}",
            );

            let expected_spans: Vec<_> = expected_all
                .iter()
                .copied()
                .filter(|&(matched_start, _end)| matched_start >= start)
                .collect();
            let mut actual_spans = Vec::new();
            assert_eq!(
                ordinary
                    .try_visit_spans_at(source, start, |matched| {
                        actual_spans.push((matched.start(), matched.end()));
                        Ok::<_, VisitorError>(true)
                    })
                    .unwrap(),
                Ok(()),
                "visitor start={start}",
            );
            assert_eq!(actual_spans, expected_spans, "visitor spans start={start}");
            assert_eq!(
                ordinary
                    .count_positive_width_selected_ends_at(source, start)
                    .unwrap(),
                Some(u64::try_from(expected_spans.len()).unwrap()),
                "count start={start}",
            );
        }

        let mut stopped = Vec::new();
        assert_eq!(
            ordinary
                .try_visit_spans(source, |matched| {
                    stopped.push((matched.start(), matched.end()));
                    Ok::<_, VisitorError>(false)
                })
                .unwrap(),
            Ok(()),
        );
        assert_eq!(stopped, expected_all[..1]);

        let mut visits = 0_usize;
        assert_eq!(
            ordinary
                .try_visit_spans(source, |_matched| {
                    visits += 1;
                    if visits == 2 {
                        Err(VisitorError)
                    } else {
                        Ok(true)
                    }
                })
                .unwrap(),
            Err(VisitorError),
        );
        assert_eq!(visits, 2);
        assert_eq!(
            ordinary.find_at(b"qq7X\n", 0).unwrap(),
            Some(Match { start: 0, end: 4 }),
            "a stopped or failed callback must leave the source-free session reusable",
        );

        let invalid = source.len() + 1;
        assert!(ordinary.find_at(source, invalid).is_err());
        assert!(matches!(
            ordinary
                .try_visit_spans_at(source, invalid, |_matched| { Ok::<_, VisitorError>(true) }),
            Err(PortableFindIterError::Search(_))
        ));
    }

    #[test]
    fn long_line_fallback_decides_before_callbacks_and_remains_reusable() {
        let pattern = r"(?m)^(?-u:[a-z_]+[0-9]+X)$";
        let mut source = vec![b'a'; super::MAX_DIRECT_LINE_BYTES + 17];
        source.extend_from_slice(b"123X\nnope\nb4X\n");
        let long_end = super::MAX_DIRECT_LINE_BYTES + 21;
        let direct = plan(pattern, b'\n');
        assert!(matches!(
            direct.route_at(&source, 0),
            super::Route::Canonical
        ));
        assert_eq!(direct.try_find_full(&source), None);
        assert_eq!(direct.try_is_match_full(&source), None);

        let regex = PortableBuilder::new(pattern).build().unwrap();
        let upstream = RegexBuilder::new(pattern).unicode(false).build().unwrap();
        let expected_all: Vec<_> = upstream
            .find_iter(&source)
            .map(|matched| (matched.start(), matched.end()))
            .collect();
        assert_eq!(expected_all[0], (0, long_end));
        assert_eq!(
            regex.find(&source).unwrap(),
            Match {
                start: 0,
                end: long_end,
            },
            "the full ordinary facade must decline to canonical K0 on a long line",
        );

        let mut ordinary = regex.ordinary_session().unwrap();
        for start in [0, 1, long_end - 1, long_end, source.len()] {
            let expected: Vec<_> = expected_all
                .iter()
                .copied()
                .filter(|&(matched_start, _end)| matched_start >= start)
                .collect();
            assert_eq!(
                ordinary
                    .find_at(&source, start)
                    .unwrap()
                    .map(|matched| (matched.start(), matched.end())),
                expected.first().copied(),
                "find start={start}",
            );
            let mut actual = Vec::new();
            assert_eq!(
                ordinary
                    .try_visit_spans_at(&source, start, |matched| {
                        actual.push((matched.start(), matched.end()));
                        Ok::<_, VisitorError>(true)
                    })
                    .unwrap(),
                Ok(()),
            );
            assert_eq!(actual, expected, "visitor start={start}");
            assert_eq!(
                ordinary
                    .count_positive_width_selected_ends_at(&source, start)
                    .unwrap(),
                Some(u64::try_from(expected.len()).unwrap()),
                "count start={start}",
            );
        }

        let mut stopped = Vec::new();
        assert_eq!(
            ordinary
                .try_visit_spans(&source, |matched| {
                    stopped.push((matched.start(), matched.end()));
                    Ok::<_, VisitorError>(false)
                })
                .unwrap(),
            Ok(()),
        );
        assert_eq!(stopped, expected_all[..1]);
        assert_eq!(
            ordinary
                .try_visit_spans(&source, |_matched| Err(VisitorError))
                .unwrap(),
            Err(VisitorError),
        );
        assert_eq!(
            ordinary.find_at(b"z8X\n", 0).unwrap(),
            Some(Match { start: 0, end: 3 }),
            "fallback callback exits must leave the source-free owner reusable",
        );
    }

    #[test]
    fn canonical_windows_and_custom_line_modes_remain_exact() {
        for (pattern, terminator, source) in [
            (
                r"(?m)^(?-u:[a-z_]+[0-9]+X)$",
                b'\n',
                b"a1X\naa22X\naX\n3X\nzz9X".as_slice(),
            ),
            (
                r"(?m)^(?-u:[a-z_]+[0-9]+X)$",
                b'|',
                b"a1X|aa22X|aX|3X|zz9X".as_slice(),
            ),
            (
                r"(?Rm)^(?-u:[a-z_]+[0-9]+X)$",
                b'\n',
                b"a1X\r\naa22X\raX\n3X\r\nzz9X".as_slice(),
            ),
        ] {
            let regex = PortableBuilder::new(pattern)
                .line_terminator(terminator)
                .build()
                .unwrap();
            let PortablePlan::K0(k0) = &regex.plan else {
                panic!("whole-line chain should remain K0");
            };
            assert!(k0.exclusive.whole_line_run_chain().is_some());
            let upstream = RegexBuilder::new(pattern)
                .unicode(false)
                .line_terminator(terminator)
                .build()
                .unwrap();
            let upstream_spans: Vec<_> = upstream
                .find_iter(source)
                .map(|matched| (matched.start(), matched.end()))
                .collect();
            let mut ordinary = regex.ordinary_session().unwrap();
            for start in 0..=source.len() {
                let expected = upstream_spans
                    .iter()
                    .copied()
                    .find(|&(matched_start, _end)| matched_start >= start);
                assert_eq!(
                    ordinary
                        .find_at(source, start)
                        .unwrap()
                        .map(|matched| (matched.start(), matched.end())),
                    expected,
                    "ordinary {pattern:?} terminator={terminator} start={start}",
                );
                for end in start..=source.len() {
                    let expected =
                        upstream_spans
                            .iter()
                            .copied()
                            .find(|&(matched_start, matched_end)| {
                                matched_start >= start && matched_end <= end
                            });
                    assert_eq!(
                        regex
                            .find_window_value(
                                source,
                                SearchWindow::new(start, end),
                                SearchLimits::unlimited(),
                            )
                            .unwrap()
                            .map(|matched| (matched.start(), matched.end())),
                        expected,
                        "canonical {pattern:?} terminator={terminator} window={start}..{end}",
                    );
                }
            }
        }
    }
}
