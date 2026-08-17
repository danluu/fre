//! Direct complete spans for two ASCII-casefolded prefix/class alternatives.
//!
//! The construction proof accepts exactly two ordered branches of the form
//! `P C+`. `P` is one to eight ASCII letters represented by canonical
//! two-singleton case-fold classes and `C` is one canonical nonempty byte
//! class under a greedy, nonempty, unbounded repetition. Captures are
//! transparent because this operation reports only whole-match spans.
//!
//! Execution merges eight monotone exact two-byte streams: four ASCII-case
//! variants for each branch's leading pair. Exact folded prefix verification
//! and greedy class extension preserve Rust regex's
//! leftmost-first branch priority and non-overlapping continuation. The plan
//! retains no source, HIR, allocation, scratch, or data-dependent workspace.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "successful preflight proves every hot-loop counter and cursor bound"
)]

use core::fmt;

use memchr::memmem;
use regex_syntax::hir::{Class, ClassBytes, Hir, HirKind};

pub const PLAN_ID: &str = "k0.casefold-prefix-class-alternation.v1";
pub const OPERATION_ID: &str = "k0.casefold-prefix-class-alternation.complete-spans.v1";
pub(crate) const ALTERNATIVES: usize = 2;
pub(crate) const MAX_PREFIX_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub plan_id: &'static str,
    pub operation_id: &'static str,
    pub alternatives: usize,
    pub candidate_streams: usize,
    pub anchor_bytes: usize,
    pub unbordered_anchor: bool,
    pub prefixes: [[u8; MAX_PREFIX_BYTES]; ALTERNATIVES],
    pub prefix_lengths: [u8; ALTERNATIVES],
    pub class_words: [[u64; 4]; ALTERNATIVES],
    pub unicode: bool,
    pub case_insensitive: bool,
    pub greedy: bool,
    pub non_overlapping: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    identity: Identity,
}

impl Plan {
    pub(crate) const fn identity(&self) -> &Identity {
        &self.identity
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_source_reads: u64,
    pub max_work: u64,
    pub max_candidate_starts: usize,
    pub max_prefix_byte_checks: usize,
    pub max_class_byte_checks: usize,
    pub max_match_events: usize,
    pub max_span_sum: u64,
}

impl Limits {
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_source_reads: u64::MAX,
            max_work: u64::MAX,
            max_candidate_starts: usize::MAX,
            max_prefix_byte_checks: usize::MAX,
            max_class_byte_checks: usize::MAX,
            max_match_events: usize::MAX,
            max_span_sum: u64::MAX,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::unlimited()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpperBounds {
    pub input_bytes: usize,
    pub source_reads: u64,
    pub work: u64,
    pub candidate_starts: usize,
    pub prefix_byte_checks: usize,
    pub class_byte_checks: usize,
    pub match_events: usize,
    pub span_sum: u64,
    pub scratch_bytes: usize,
    pub persistent_bytes: usize,
    pub peak_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Actual {
    pub source_reads: u64,
    pub work: u64,
    pub candidate_starts: usize,
    pub prefix_byte_checks: usize,
    pub class_byte_checks: usize,
    pub matches: usize,
    pub span_sum: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accounting {
    pub identity: Identity,
    pub upper_bounds: UpperBounds,
    pub actual: Actual,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VisitResult {
    pub matches: usize,
    pub span_sum: u64,
    pub accounting: Accounting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Resource {
        resource: &'static str,
        required: u64,
        limit: u64,
    },
    Overflow {
        counter: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource {
                resource,
                required,
                limit,
            } => write!(
                formatter,
                "casefold prefix/class span visitor needs {required} {resource}, limit is {limit}",
            ),
            Self::Overflow { counter } => write!(
                formatter,
                "casefold prefix/class span visitor {counter} accounting overflowed",
            ),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionOutcome {
    Eligible { plan: Plan, planner_work: u64 },
    Ineligible { planner_work: u64 },
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

#[derive(Clone, Copy)]
struct Budget {
    actual: u64,
    limit: u64,
}

impl Budget {
    const fn new(actual: u64, limit: u64) -> Result<Self, InspectionError> {
        if actual > limit {
            return Err(InspectionError::WorkLimit {
                actual: limit,
                needed: actual,
                limit,
            });
        }
        Ok(Self { actual, limit })
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

#[derive(Clone, Copy)]
struct Branch {
    prefix: [u8; MAX_PREFIX_BYTES],
    prefix_length: u8,
    class_words: [u64; 4],
}

pub(crate) fn inspect(
    hir: &Hir,
    unicode: bool,
    case_insensitive: bool,
    initial_work: u64,
    max_planner_work: u64,
) -> Result<InspectionOutcome, InspectionError> {
    let mut budget = Budget::new(initial_work, max_planner_work)?;
    budget.charge(1)?;
    if unicode || !case_insensitive {
        return ineligible(budget.actual);
    }
    let root = transparent(hir, &mut budget)?;
    let HirKind::Alternation(branches) = root.kind() else {
        return ineligible(budget.actual);
    };
    budget.charge(1)?;
    let [first, second] = branches.as_slice() else {
        return ineligible(budget.actual);
    };
    let Some(first) = inspect_branch(first, &mut budget)? else {
        return ineligible(budget.actual);
    };
    let Some(second) = inspect_branch(second, &mut budget)? else {
        return ineligible(budget.actual);
    };
    let prefixes = [first.prefix, second.prefix];
    let prefix_lengths = [first.prefix_length, second.prefix_length];
    let class_words = [first.class_words, second.class_words];
    Ok(InspectionOutcome::Eligible {
        plan: Plan {
            identity: Identity {
                plan_id: PLAN_ID,
                operation_id: OPERATION_ID,
                alternatives: ALTERNATIVES,
                candidate_streams: 8,
                anchor_bytes: 2,
                unbordered_anchor: true,
                prefixes,
                prefix_lengths,
                class_words,
                unicode,
                case_insensitive,
                greedy: true,
                non_overlapping: true,
            },
        },
        planner_work: budget.actual,
    })
}

fn ineligible(work: u64) -> Result<InspectionOutcome, InspectionError> {
    Ok(InspectionOutcome::Ineligible { planner_work: work })
}

fn inspect_branch(hir: &Hir, budget: &mut Budget) -> Result<Option<Branch>, InspectionError> {
    let branch = transparent(hir, budget)?;
    let HirKind::Concat(parts) = branch.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if !(3..=MAX_PREFIX_BYTES + 1).contains(&parts.len()) {
        return Ok(None);
    }
    let (tail, prefix_parts) = parts.split_last().expect("at least two admitted parts");
    let prefix_length =
        u8::try_from(prefix_parts.len()).expect("the admitted folded prefix fits in eight bytes");
    let mut prefix = [0_u8; MAX_PREFIX_BYTES];
    for (slot, part) in prefix.iter_mut().zip(prefix_parts) {
        let part = transparent(part, budget)?;
        let HirKind::Class(Class::Bytes(class)) = part.kind() else {
            return Ok(None);
        };
        let Some(canonical) = ascii_case_pair(class, budget)? else {
            return Ok(None);
        };
        *slot = canonical;
    }
    budget.charge(1)?;
    if prefix[0] == prefix[1] {
        return Ok(None);
    }

    let tail = transparent(tail, budget)?;
    let HirKind::Repetition(repetition) = tail.kind() else {
        return Ok(None);
    };
    budget.charge(1)?;
    if repetition.min != 1 || repetition.max.is_some() || !repetition.greedy {
        return Ok(None);
    }
    let repeated = transparent(repetition.sub.as_ref(), budget)?;
    let HirKind::Class(Class::Bytes(class)) = repeated.kind() else {
        return Ok(None);
    };
    if class.ranges().is_empty() {
        return Ok(None);
    }
    let class_words = class_words(class, budget)?;
    Ok(Some(Branch {
        prefix,
        prefix_length,
        class_words,
    }))
}

fn ascii_case_pair(class: &ClassBytes, budget: &mut Budget) -> Result<Option<u8>, InspectionError> {
    budget.charge(1)?;
    let [first, second] = class.ranges() else {
        return Ok(None);
    };
    budget.charge(2)?;
    if first.start() != first.end() || second.start() != second.end() {
        return Ok(None);
    }
    let first = first.start();
    let second = second.start();
    if !first.is_ascii_alphabetic()
        || !second.is_ascii_alphabetic()
        || first.to_ascii_lowercase() != second.to_ascii_lowercase()
        || first == second
    {
        return Ok(None);
    }
    Ok(Some(first.to_ascii_lowercase()))
}

fn class_words(class: &ClassBytes, budget: &mut Budget) -> Result<[u64; 4], InspectionError> {
    budget.charge(1)?;
    let mut words = [0_u64; 4];
    for range in class.ranges() {
        budget.charge(1)?;
        let population = u64::from(range.end())
            .checked_sub(u64::from(range.start()))
            .and_then(|width| width.checked_add(1))
            .ok_or(InspectionError::ArithmeticOverflow)?;
        budget.charge(population)?;
        for byte in range.start()..=range.end() {
            let index = usize::from(byte);
            words[index / 64] |= 1_u64 << (index % 64);
        }
    }
    Ok(words)
}

fn transparent<'hir>(
    mut hir: &'hir Hir,
    budget: &mut Budget,
) -> Result<&'hir Hir, InspectionError> {
    loop {
        budget.charge(1)?;
        let HirKind::Capture(capture) = hir.kind() else {
            return Ok(hir);
        };
        hir = capture.sub.as_ref();
    }
}

pub(crate) fn visit<F>(
    plan: Plan,
    haystack: &[u8],
    limits: Limits,
    mut visitor: F,
) -> Result<VisitResult, Error>
where
    F: FnMut(usize, usize),
{
    let upper = upper_bounds(haystack.len())?;
    enforce_usize("input bytes", upper.input_bytes, limits.max_input_bytes)?;
    enforce_u64("source reads", upper.source_reads, limits.max_source_reads)?;
    enforce_u64("work units", upper.work, limits.max_work)?;
    enforce_usize(
        "candidate starts",
        upper.candidate_starts,
        limits.max_candidate_starts,
    )?;
    enforce_usize(
        "prefix byte checks",
        upper.prefix_byte_checks,
        limits.max_prefix_byte_checks,
    )?;
    enforce_usize(
        "class byte checks",
        upper.class_byte_checks,
        limits.max_class_byte_checks,
    )?;
    enforce_usize("match events", upper.match_events, limits.max_match_events)?;
    enforce_u64("span-sum bytes", upper.span_sum, limits.max_span_sum)?;

    let identity = plan.identity();
    let needles = folded_pair_needles(identity);
    let mut streams = needles
        .each_ref()
        .map(|needle| memmem::find_iter(haystack, needle));
    let mut next: [Option<usize>; 8] = core::array::from_fn(|index| streams[index].next());
    let mut actual = Actual {
        source_reads: upper.source_reads,
        work: upper.source_reads + 64,
        ..Actual::default()
    };

    while let Some(start) = next.iter().flatten().copied().min() {
        let mut matched_end = None;
        for index in 0..8 {
            if next[index] != Some(start) {
                continue;
            }
            actual.candidate_starts += 1;
            actual.work += 1;
            if matched_end.is_none() {
                matched_end = match_branch(&plan, index / 4, haystack, start, &mut actual);
            }
            next[index] = streams[index].next();
        }
        let Some(end) = matched_end else {
            continue;
        };
        actual.matches += 1;
        actual.work += 1;
        let width = u64::try_from(end - start).expect("a usize match width always fits u64");
        actual.span_sum += width;
        visitor(start, end);
        for index in 0..8 {
            while next[index].is_some_and(|candidate| candidate < end) {
                next[index] = streams[index].next();
            }
        }
    }
    if actual.source_reads > upper.source_reads
        || actual.work > upper.work
        || actual.candidate_starts > upper.candidate_starts
        || actual.prefix_byte_checks > upper.prefix_byte_checks
        || actual.class_byte_checks > upper.class_byte_checks
        || actual.matches > upper.match_events
        || actual.span_sum > upper.span_sum
    {
        return Err(Error::Overflow {
            counter: "actual-versus-prospective closure",
        });
    }
    Ok(VisitResult {
        matches: actual.matches,
        span_sum: actual.span_sum,
        accounting: Accounting {
            identity: *identity,
            upper_bounds: upper,
            actual,
        },
    })
}

fn upper_bounds(input_bytes: usize) -> Result<UpperBounds, Error> {
    let input = u64::try_from(input_bytes).map_err(|_| Error::Overflow {
        counter: "input length",
    })?;
    let candidates = input_bytes.checked_mul(8).ok_or(Error::Overflow {
        counter: "candidate bound",
    })?;
    let prefix_checks = candidates
        .checked_mul(MAX_PREFIX_BYTES)
        .ok_or(Error::Overflow {
            counter: "prefix-check bound",
        })?;
    let class_checks = input_bytes.checked_mul(12).ok_or(Error::Overflow {
        counter: "class-check bound",
    })?;
    let source_reads = input.checked_mul(8).ok_or(Error::Overflow {
        counter: "source-read bound",
    })?;
    let work = input
        .checked_mul(96)
        .and_then(|work| work.checked_add(64))
        .ok_or(Error::Overflow {
            counter: "work bound",
        })?;
    Ok(UpperBounds {
        input_bytes,
        source_reads,
        work,
        candidate_starts: candidates,
        prefix_byte_checks: prefix_checks,
        class_byte_checks: class_checks,
        match_events: input_bytes,
        span_sum: input,
        scratch_bytes: 0,
        persistent_bytes: 0,
        peak_bytes: 0,
    })
}

fn folded_pair_needles(identity: &Identity) -> [[u8; 2]; 8] {
    let first = identity.prefixes[0];
    let second = identity.prefixes[1];
    [
        [first[0].to_ascii_uppercase(), first[1].to_ascii_uppercase()],
        [first[0].to_ascii_uppercase(), first[1]],
        [first[0], first[1].to_ascii_uppercase()],
        [first[0], first[1]],
        [
            second[0].to_ascii_uppercase(),
            second[1].to_ascii_uppercase(),
        ],
        [second[0].to_ascii_uppercase(), second[1]],
        [second[0], second[1].to_ascii_uppercase()],
        [second[0], second[1]],
    ]
}

#[inline]
fn match_branch(
    plan: &Plan,
    branch: usize,
    haystack: &[u8],
    start: usize,
    actual: &mut Actual,
) -> Option<usize> {
    let identity = plan.identity();
    let prefix_length = usize::from(identity.prefix_lengths[branch]);
    for offset in 0..prefix_length {
        let Some(&byte) = haystack.get(start + offset) else {
            return None;
        };
        actual.prefix_byte_checks += 1;
        actual.work += 1;
        if byte | 0x20 != identity.prefixes[branch][offset] {
            return None;
        }
    }
    let mut end = start + prefix_length;
    let Some(&first) = haystack.get(end) else {
        return None;
    };
    actual.class_byte_checks += 1;
    actual.work += 1;
    if !contains(&identity.class_words[branch], first) {
        return None;
    }
    end += 1;
    while let Some(&byte) = haystack.get(end) {
        actual.class_byte_checks += 1;
        actual.work += 1;
        if !contains(&identity.class_words[branch], byte) {
            break;
        }
        end += 1;
    }
    Some(end)
}

#[inline]
fn contains(words: &[u64; 4], byte: u8) -> bool {
    let index = usize::from(byte);
    words[index / 64] & (1_u64 << (index % 64)) != 0
}

fn enforce_usize(resource: &'static str, required: usize, limit: usize) -> Result<(), Error> {
    if required > limit {
        return Err(Error::Resource {
            resource,
            required: u64::try_from(required).unwrap_or(u64::MAX),
            limit: u64::try_from(limit).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

fn enforce_u64(resource: &'static str, required: u64, limit: u64) -> Result<(), Error> {
    if required > limit {
        return Err(Error::Resource {
            resource,
            required,
            limit,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use regex::bytes::RegexBuilder;
    use regex_syntax::ParserBuilder;

    use super::{Error, InspectionError, InspectionOutcome, Limits, inspect, visit};

    fn parsed(pattern: &str) -> regex_syntax::hir::Hir {
        ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .case_insensitive(true)
            .build()
            .parse(pattern)
            .unwrap()
    }

    fn plan(pattern: &str) -> super::Plan {
        let hir = parsed(pattern);
        let InspectionOutcome::Eligible { plan, .. } =
            inspect(&hir, false, true, 0, u64::MAX).unwrap()
        else {
            panic!("expected eligible plan for {pattern}");
        };
        plan
    }

    fn reference(pattern: &str, haystack: &[u8]) -> Vec<(usize, usize)> {
        RegexBuilder::new(pattern)
            .unicode(false)
            .case_insensitive(true)
            .build()
            .unwrap()
            .find_iter(haystack)
            .map(|matched| (matched.start(), matched.end()))
            .collect()
    }

    fn direct(pattern: &str, haystack: &[u8]) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        visit(
            plan(pattern),
            haystack,
            Limits::unlimited(),
            |start, end| {
                spans.push((start, end));
            },
        )
        .unwrap();
        spans
    }

    #[test]
    fn exact_target_preserves_casefold_greed_and_invalid_bytes() {
        let pattern = r"Sher[a-z]+|Hol[a-z]+";
        for haystack in [
            b"Sherlock Holmes! Holdup--Sher".as_slice(),
            b"SHERLOCK hOlMeS holdup shERx".as_slice(),
            b"\xffSherlock\x80HOLMES\xfeSher".as_slice(),
            b"sssSHERaaaaHOLzzSherHolmes".as_slice(),
        ] {
            assert_eq!(reference(pattern, haystack), direct(pattern, haystack));
        }
    }

    #[test]
    fn ordered_branches_preserve_greedy_nonoverlap() {
        let pattern = r"Ab[b]+|Cd[b-z]+";
        let haystack = b"ABBBBBZ CDQ";
        assert_eq!(reference(pattern, haystack), direct(pattern, haystack));
        assert_eq!(vec![(0, 6), (8, 11)], direct(pattern, haystack));
    }

    #[test]
    fn deterministic_small_domain_matches_rust_regex() {
        let pattern = r"Ab[xy]+|Cd[z0-2]+";
        let alphabet = [
            b'A', b'a', b'B', b'b', b'C', b'c', b'D', b'd', b'x', b'Y', b'z', b'1', 0xff,
        ];
        let mut state = 0x9e37_79b9_u32;
        for length in 0..48 {
            for _ in 0..64 {
                let mut haystack = Vec::with_capacity(length);
                for _ in 0..length {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    haystack.push(alphabet[(state as usize) % alphabet.len()]);
                }
                assert_eq!(
                    reference(pattern, &haystack),
                    direct(pattern, &haystack),
                    "haystack {haystack:?}",
                );
            }
        }
    }

    #[test]
    fn limits_refuse_before_the_first_callback() {
        let plan = plan(r"Ab[xy]+|Cd[z]+");
        let haystack = b"ABxxx CDzzz";
        let complete = visit(plan, haystack, Limits::unlimited(), |_, _| {}).unwrap();
        let mut limits = Limits::unlimited();
        limits.max_work = complete.accounting.upper_bounds.work - 1;
        let mut callbacks = 0;
        assert!(matches!(
            visit(plan, haystack, limits, |_, _| callbacks += 1),
            Err(Error::Resource {
                resource: "work units",
                ..
            })
        ));
        assert_eq!(0, callbacks);
    }

    #[test]
    fn nearby_shapes_are_rejected() {
        for pattern in [
            r"Ab[xy]+",
            r"Ab[xy]*|Cd[z]+",
            r"Ab[xy]+?|Cd[z]+",
            r"Ab[xy]{2}|Cd[z]+",
            r"Ab[xy]+|Cd[z]+|Ef[q]+",
            r"Ab[xy]+|123[z]+",
            r"Aa[xy]+|Cd[z]+",
            r"Ab[xy]+x|Cd[z]+",
        ] {
            assert!(matches!(
                inspect(&parsed(pattern), false, true, 0, u64::MAX).unwrap(),
                InspectionOutcome::Ineligible { .. }
            ));
        }
        let target = parsed(r"Ab[xy]+|Cd[z]+");
        for (unicode, case_insensitive) in [(true, true), (false, false)] {
            assert!(matches!(
                inspect(&target, unicode, case_insensitive, 0, u64::MAX).unwrap(),
                InspectionOutcome::Ineligible { .. }
            ));
        }
    }

    #[test]
    fn planner_work_is_exactly_replayable_one_below() {
        let hir = parsed(r"Sher[a-z]+|Hol[a-z]+");
        let initial = 17;
        let complete = inspect(&hir, false, true, initial, u64::MAX).unwrap();
        let work = match complete {
            InspectionOutcome::Eligible { planner_work, .. }
            | InspectionOutcome::Ineligible { planner_work } => planner_work,
        };
        assert!(work > initial);
        assert!(matches!(
            inspect(&hir, false, true, initial, work - 1),
            Err(InspectionError::WorkLimit {
                actual,
                needed,
                limit,
            }) if actual <= limit && needed > limit && limit == work - 1
        ));
    }
}
