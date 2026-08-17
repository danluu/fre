//! Direct Count execution for an unbounded ASCII-class run followed by a
//! disjoint raw high-byte class and a Unicode word boundary.
//!
//! The raw terminal byte cannot be a continuation byte for a scalar begun in
//! the ASCII candidate run. It can begin a scalar that crosses the asserted
//! position, so the pinned assertion matcher supplies the exact Unicode
//! boundary semantics, including malformed UTF-8 on either side. Disjointness
//! makes each maximal left-class run the sole possible greedy match ending at
//! the following terminal byte.

use core::mem::size_of;

use regex_automata::util::look::LookMatcher;
use regex_syntax::{
    ParserBuilder,
    hir::{Class, Hir, HirKind, Look},
};

use super::{ExecutionError, RunLimits};

pub(crate) const PLAN: &str = "aggregate-terminal-byte-frontier-count-v1";

const MIN_REPEAT: u32 = 2;
const FIXED_PLANNER_WORK: usize = 64;
const PLANNER_WORK_PER_PATTERN_BYTE: usize = 32;
const FIXED_OPERATION_WORK: usize = 8;
const OPERATION_WORK_PER_HAYSTACK_BYTE: usize = 4;
const OPERATION_WORK_PER_BOUNDARY_CANDIDATE: usize = 32;
const RANDOM_READS_PER_BOUNDARY_CANDIDATE: usize = 8;
const SEQUENTIAL_READS_PER_HAYSTACK_BYTE: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ByteSet([u64; 4]);

impl ByteSet {
    const fn empty() -> Self {
        Self([0; 4])
    }

    fn insert(&mut self, byte: u8) {
        let index = usize::from(byte) >> 6;
        let bit = u32::from(byte & 63);
        self.0[index] |= 1_u64 << bit;
    }

    fn insert_range(&mut self, start: u8, end: u8) {
        for byte in start..=end {
            self.insert(byte);
        }
    }

    #[inline]
    fn contains(self, byte: u8) -> bool {
        let index = usize::from(byte) >> 6;
        let bit = u32::from(byte & 63);
        self.0[index] & (1_u64 << bit) != 0
    }

    const fn is_empty(self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }
}

#[derive(Debug)]
pub(crate) struct TerminalByteFrontierCount {
    left: ByteSet,
    terminal: ByteSet,
    minimum: usize,
    haystack_len: usize,
    max_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResourceEnvelope {
    planner_work: usize,
    hir_nodes: usize,
    hir_stack_items: usize,
    persistent_bytes: usize,
    operation_work: usize,
    random_access_bytes: usize,
    sequential_bytes: usize,
    max_count: u64,
    peak_bytes: usize,
}

impl ResourceEnvelope {
    fn new(
        pattern_bytes: usize,
        minimum: usize,
        haystack_len: usize,
    ) -> Result<Self, ExecutionError> {
        let planner_work = pattern_bytes
            .checked_mul(PLANNER_WORK_PER_PATTERN_BYTE)
            .and_then(|work| work.checked_add(FIXED_PLANNER_WORK))
            .ok_or_else(|| ExecutionError::fault("terminal-byte frontier planner work overflow"))?;
        let hir_items = pattern_bytes.checked_add(1).ok_or_else(|| {
            ExecutionError::fault("terminal-byte frontier HIR-item envelope overflow")
        })?;
        let minimum_match_bytes = minimum.checked_add(1).ok_or_else(|| {
            ExecutionError::fault("terminal-byte frontier minimum match width overflow")
        })?;
        let boundary_candidates = haystack_len / minimum_match_bytes;
        let boundary_work = boundary_candidates
            .checked_mul(OPERATION_WORK_PER_BOUNDARY_CANDIDATE)
            .ok_or_else(|| {
                ExecutionError::fault("terminal-byte frontier boundary work overflow")
            })?;
        let operation_work = haystack_len
            .checked_mul(OPERATION_WORK_PER_HAYSTACK_BYTE)
            .and_then(|work| work.checked_add(boundary_work))
            .and_then(|work| work.checked_add(FIXED_OPERATION_WORK))
            .ok_or_else(|| {
                ExecutionError::fault("terminal-byte frontier operation work overflow")
            })?;
        let random_access_bytes = boundary_candidates
            .checked_mul(RANDOM_READS_PER_BOUNDARY_CANDIDATE)
            .ok_or_else(|| {
                ExecutionError::fault("terminal-byte frontier random-access bound overflow")
            })?;
        let sequential_bytes = haystack_len
            .checked_mul(SEQUENTIAL_READS_PER_HAYSTACK_BYTE)
            .ok_or_else(|| {
                ExecutionError::fault("terminal-byte frontier sequential-read bound overflow")
            })?;
        let persistent_bytes = size_of::<TerminalByteFrontierCount>();
        Ok(Self {
            planner_work,
            hir_nodes: hir_items,
            hir_stack_items: hir_items,
            persistent_bytes,
            operation_work,
            random_access_bytes,
            sequential_bytes,
            max_count: u64::try_from(boundary_candidates).map_err(|_| {
                ExecutionError::fault("terminal-byte frontier Count bound does not fit u64")
            })?,
            peak_bytes: persistent_bytes,
        })
    }

    fn admit(
        self,
        pattern_bytes: usize,
        haystack_len: usize,
        limits: &RunLimits,
    ) -> Result<(), ExecutionError> {
        require_resource("pattern count", 1, limits.patterns_per_job)?;
        require_resource("pattern bytes", pattern_bytes, limits.pattern_bytes_per_job)?;
        require_resource("haystack bytes", haystack_len, limits.haystack_bytes)?;
        require_resource(
            "planner work",
            self.planner_work,
            limits.fre_aggregate_compile_work,
        )?;
        require_resource("HIR nodes", self.hir_nodes, limits.fre_aggregate_hir_nodes)?;
        require_resource(
            "HIR stack items",
            self.hir_stack_items,
            limits.fre_aggregate_hir_stack_items,
        )?;
        require_resource(
            "persistent bytes",
            self.persistent_bytes,
            limits.fre_aggregate_program_bytes,
        )?;
        require_resource(
            "operation work",
            self.operation_work,
            limits.fre_aggregate_operation_work,
        )?;
        require_resource(
            "random-access source bytes",
            self.random_access_bytes,
            limits.fre_aggregate_random_access_bytes,
        )?;
        require_resource(
            "sequential source bytes",
            self.sequential_bytes,
            limits.fre_aggregate_sequential_bytes,
        )?;
        require_resource(
            "operation peak bytes",
            self.peak_bytes,
            limits.fre_aggregate_peak_bytes,
        )?;
        if self.max_count > limits.reducer_steps {
            return Err(ExecutionError::unsupported(format!(
                "terminal-byte frontier reducer events require {}, limit is {}",
                self.max_count, limits.reducer_steps
            )));
        }
        Ok(())
    }
}

fn require_resource(
    resource: &'static str,
    needed: usize,
    limit: usize,
) -> Result<(), ExecutionError> {
    if needed > limit {
        return Err(ExecutionError::unsupported(format!(
            "terminal-byte frontier {resource} require {needed}, limit is {limit}"
        )));
    }
    Ok(())
}

impl TerminalByteFrontierCount {
    pub(crate) fn try_build(
        pattern: &str,
        unicode: bool,
        case_insensitive: bool,
        haystack_len: usize,
        limits: &RunLimits,
    ) -> Result<Option<Self>, ExecutionError> {
        if !unicode || case_insensitive {
            return Ok(None);
        }
        let hir = ParserBuilder::new()
            .unicode(true)
            .utf8(false)
            .case_insensitive(false)
            .build()
            .parse(pattern)
            .ok();
        let Some(hir) = hir else {
            return Ok(None);
        };
        let HirKind::Concat(parts) = transparent(&hir).kind() else {
            return Ok(None);
        };
        let [repeated, terminal, boundary] = parts.as_slice() else {
            return Ok(None);
        };
        let HirKind::Repetition(repetition) = transparent(repeated).kind() else {
            return Ok(None);
        };
        if repetition.min < MIN_REPEAT || repetition.max.is_some() || !repetition.greedy {
            return Ok(None);
        }
        let Some(left) = ascii_class(transparent(&repetition.sub)) else {
            return Ok(None);
        };
        let Some(terminal) = raw_high_byte_class(transparent(terminal)) else {
            return Ok(None);
        };
        if left.is_empty()
            || terminal.is_empty()
            || !matches!(
                transparent(boundary).kind(),
                HirKind::Look(Look::WordUnicode)
            )
        {
            return Ok(None);
        }
        let minimum = usize::try_from(repetition.min).map_err(|_| {
            ExecutionError::fault("terminal-byte frontier minimum does not fit usize")
        })?;
        let resources = ResourceEnvelope::new(pattern.len(), minimum, haystack_len)?;
        resources.admit(pattern.len(), haystack_len, limits)?;
        Ok(Some(Self {
            left,
            terminal,
            minimum,
            haystack_len,
            max_count: resources.max_count,
        }))
    }

    #[inline]
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "slice bounds prove single-byte cursor advances and checked addition protects the result"
    )]
    pub(crate) fn count(&self, haystack: &[u8]) -> Result<u64, ExecutionError> {
        if haystack.len() != self.haystack_len {
            return Err(ExecutionError::fault(
                "terminal-byte frontier haystack length changed after construction",
            ));
        }
        let mut at = 0_usize;
        let mut count = 0_u64;
        while at < haystack.len() {
            if !self.left.contains(haystack[at]) {
                at += 1;
                continue;
            }
            let start = at;
            at += 1;
            while at < haystack.len() && self.left.contains(haystack[at]) {
                at += 1;
            }
            let run_len = at - start;
            if run_len >= self.minimum
                && at < haystack.len()
                && self.terminal.contains(haystack[at])
                && LookMatcher::new()
                    .is_word_unicode(haystack, at + 1)
                    .map_err(|_| {
                        ExecutionError::fault("Unicode word-boundary tables are unavailable")
                    })?
            {
                count = count.checked_add(1).ok_or_else(|| {
                    ExecutionError::fault("terminal-byte frontier Count overflow")
                })?;
                if count > self.max_count {
                    return Err(ExecutionError::fault(
                        "terminal-byte frontier Count exceeded its source-free bound",
                    ));
                }
                at += 1;
            }
        }
        Ok(count)
    }
}

fn transparent(mut hir: &Hir) -> &Hir {
    while let HirKind::Capture(capture) = hir.kind() {
        hir = &capture.sub;
    }
    hir
}

fn ascii_class(hir: &Hir) -> Option<ByteSet> {
    let mut set = ByteSet::empty();
    match hir.kind() {
        HirKind::Class(Class::Bytes(class)) => {
            for range in class.ranges() {
                if !range.end().is_ascii() {
                    return None;
                }
                set.insert_range(range.start(), range.end());
            }
        }
        HirKind::Class(Class::Unicode(class)) => {
            for range in class.ranges() {
                let start = u32::from(range.start());
                let end = u32::from(range.end());
                if end > 0x7F {
                    return None;
                }
                set.insert_range(u8::try_from(start).ok()?, u8::try_from(end).ok()?);
            }
        }
        _ => return None,
    }
    Some(set)
}

fn raw_high_byte_class(hir: &Hir) -> Option<ByteSet> {
    let HirKind::Class(Class::Bytes(class)) = hir.kind() else {
        return None;
    };
    let mut set = ByteSet::empty();
    for range in class.ranges() {
        if range.start().is_ascii() {
            return None;
        }
        set.insert_range(range.start(), range.end());
    }
    Some(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CandidateRequest, CurrentFreAggregateCounterReceiptStatus, RunLimits, Status,
        build_current_fre_count_lifecycle_with_folded_limits,
        current_fre_rebar_aggregate_operation_lifecycle, fre_aggregate_count,
        fre_aggregate_count_with_folded_limits, unicode_folded_literal_build_limits,
    };

    const PATTERN: &str = r"[ab]{2,}(?-u:[\x80-\xFF])\b";

    #[test]
    fn exhaustive_leftmost_greedy_and_malformed_oracle() {
        let plan = default_build(PATTERN, true, false, 0).unwrap();
        let reference = regex::bytes::RegexBuilder::new(PATTERN)
            .unicode(true)
            .build()
            .unwrap();
        let alphabet = [b'a', b'b', b'c', b'_', b' ', 0x80, 0xA9, 0xC2, 0xFF];
        let mut haystack = Vec::new();
        for length in 0..=6 {
            compare_words(&plan, &reference, &alphabet, length, &mut haystack);
        }
    }

    fn compare_words(
        empty_plan: &TerminalByteFrontierCount,
        reference: &regex::bytes::Regex,
        alphabet: &[u8],
        remaining: usize,
        haystack: &mut Vec<u8>,
    ) {
        if remaining == 0 {
            let plan = TerminalByteFrontierCount {
                left: empty_plan.left,
                terminal: empty_plan.terminal,
                minimum: empty_plan.minimum,
                haystack_len: haystack.len(),
                max_count: u64::try_from(haystack.len() / (empty_plan.minimum + 1)).unwrap(),
            };
            assert_eq!(
                plan.count(haystack).unwrap(),
                u64::try_from(reference.find_iter(haystack).count()).unwrap(),
                "{haystack:?}"
            );
            return;
        }
        for &byte in alphabet {
            haystack.push(byte);
            compare_words(empty_plan, reference, alphabet, remaining - 1, haystack);
            haystack.pop();
        }
    }

    #[test]
    fn structural_refusals_leave_nearby_languages_on_the_incumbent() {
        assert!(default_build(PATTERN, false, false, 0).is_none());
        assert!(default_build(PATTERN, true, true, 0).is_none());
        assert!(default_build(r"[ab]{1,}(?-u:[\x80-\xFF])\b", true, false, 0).is_none());
        assert!(default_build(r"[ab]{2,8}(?-u:[\x80-\xFF])\b", true, false, 0).is_none());
        assert!(default_build(r"[ab]{2,}?(?-u:[\x80-\xFF])\b", true, false, 0).is_none());
        assert!(default_build(r"[a\u{100}]{2,}(?-u:[\x80-\xFF])\b", true, false, 0).is_none());
        assert!(default_build(r"[ab]{2,}[c-z]\b", true, false, 0).is_none());
        assert!(default_build(r"[ab]{2,}(?-u:[\x80-\xFF])(?-u:\b)", true, false, 0).is_none());
        assert!(default_build(r"[ab]{2,}(?-u:[\x80-\xFF])\B", true, false, 0).is_none());
    }

    fn default_build(
        pattern: &str,
        unicode: bool,
        case_insensitive: bool,
        haystack_len: usize,
    ) -> Option<TerminalByteFrontierCount> {
        TerminalByteFrontierCount::try_build(
            pattern,
            unicode,
            case_insensitive,
            haystack_len,
            &RunLimits::default(),
        )
        .unwrap()
    }

    fn exact_limits(haystack_len: usize) -> RunLimits {
        let required = ResourceEnvelope::new(PATTERN.len(), 2, haystack_len).unwrap();
        RunLimits {
            patterns_per_job: 1,
            pattern_bytes_per_job: PATTERN.len(),
            haystack_bytes: haystack_len,
            reducer_steps: required.max_count,
            fre_aggregate_compile_work: required.planner_work,
            fre_aggregate_hir_nodes: required.hir_nodes,
            fre_aggregate_hir_stack_items: required.hir_stack_items,
            fre_aggregate_program_bytes: required.persistent_bytes,
            fre_aggregate_operation_work: required.operation_work,
            fre_aggregate_random_access_bytes: required.random_access_bytes,
            fre_aggregate_sequential_bytes: required.sequential_bytes,
            fre_aggregate_peak_bytes: required.peak_bytes,
            ..RunLimits::default()
        }
    }

    #[test]
    fn exact_resource_envelope_and_one_below_refusals_are_shared() {
        let patterns = [PATTERN.to_string()];
        let haystack = b"aa\xFFx baa\x80_ bb\xC2\xA9";
        let expected = u64::try_from(
            regex::bytes::RegexBuilder::new(PATTERN)
                .unicode(true)
                .build()
                .unwrap()
                .find_iter(haystack)
                .count(),
        )
        .unwrap();
        assert_ne!(expected, 0);
        let exact = exact_limits(haystack.len());
        let exact_plan =
            TerminalByteFrontierCount::try_build(PATTERN, true, false, haystack.len(), &exact)
                .unwrap()
                .expect("the exact complete envelope must admit");
        assert_eq!(exact_plan.count(haystack).unwrap(), expected);

        for (resource, one_below) in [
            (
                "planner work",
                RunLimits {
                    fre_aggregate_compile_work: exact.fre_aggregate_compile_work - 1,
                    ..exact.clone()
                },
            ),
            (
                "persistent bytes",
                RunLimits {
                    fre_aggregate_program_bytes: exact.fre_aggregate_program_bytes - 1,
                    ..exact.clone()
                },
            ),
        ] {
            let refusal = TerminalByteFrontierCount::try_build(
                PATTERN,
                true,
                false,
                haystack.len(),
                &one_below,
            )
            .expect_err("one-below construction must refuse before publication");
            assert_eq!(refusal.status, Status::Unsupported);
            assert!(refusal.message.contains(resource));
        }

        let request = CandidateRequest {
            model: "count",
            patterns: &patterns,
            haystack,
            unicode: true,
            case_insensitive: false,
        };
        let folded = unicode_folded_literal_build_limits(&exact).unwrap();
        let raw = fre_aggregate_count_with_folded_limits(request, &exact, &exact, folded).unwrap();
        assert_eq!((raw.actual, raw.plan), (expected, PLAN));
        let retained = build_current_fre_count_lifecycle_with_folded_limits(
            &patterns,
            true,
            false,
            haystack.len(),
            &exact,
            &exact,
            folded,
        )
        .unwrap();
        assert_eq!(retained.plan(), PLAN);
        assert_eq!(retained.execute(haystack).unwrap(), expected);

        for (resource, one_below) in [
            (
                "operation work",
                RunLimits {
                    fre_aggregate_operation_work: exact.fre_aggregate_operation_work - 1,
                    ..exact.clone()
                },
            ),
            (
                "reducer events",
                RunLimits {
                    reducer_steps: exact.reducer_steps - 1,
                    ..exact.clone()
                },
            ),
        ] {
            let folded = unicode_folded_literal_build_limits(&one_below).unwrap();
            let raw_refusal =
                fre_aggregate_count_with_folded_limits(request, &one_below, &one_below, folded)
                    .expect_err("raw one-below operation must typed-refuse before scanning");
            assert_eq!(raw_refusal.status, Status::Unsupported);
            assert!(raw_refusal.message.contains(resource));

            let retained_refusal = build_current_fre_count_lifecycle_with_folded_limits(
                &patterns,
                true,
                false,
                haystack.len(),
                &one_below,
                &one_below,
                folded,
            )
            .expect_err("retained one-below operation must refuse before publication");
            assert!(retained_refusal.0.contains(resource));
        }
    }

    #[test]
    fn raw_and_retained_count_surfaces_publish_the_same_route() {
        let patterns = [PATTERN.to_string()];
        let haystack = b"aa\xFFc baaa\x80_ bb\xC2\xA9 aba\xFF ";
        let expected = regex::bytes::RegexBuilder::new(PATTERN)
            .unicode(true)
            .build()
            .unwrap()
            .find_iter(haystack)
            .count()
            .try_into()
            .unwrap();
        let raw = fre_aggregate_count(
            CandidateRequest {
                model: "count",
                patterns: &patterns,
                haystack,
                unicode: true,
                case_insensitive: false,
            },
            &RunLimits::default(),
        )
        .unwrap();
        assert_eq!((raw.actual, raw.plan), (expected, PLAN));

        let retained = current_fre_rebar_aggregate_operation_lifecycle(
            "count",
            &patterns,
            true,
            false,
            haystack.len(),
        )
        .unwrap();
        assert_eq!(retained.plan(), PLAN);
        assert_eq!(retained.execute(haystack).unwrap(), expected);
        let diagnostic = retained.execute_with_counters(haystack).unwrap();
        assert_eq!(diagnostic.value(), expected);
        assert_eq!(
            diagnostic.receipt_status(),
            &CurrentFreAggregateCounterReceiptStatus::DirectSelectedPlan
        );
        assert!(retained.execute(&haystack[..haystack.len() - 1]).is_err());
    }
}
